/*
 * $Id$
 *
 * Copyright (c) 2001-2003, Raphael Manfredi
 * Copyright (c) 2000 Daniel Walker (dwalker@cats.ucsc.edu)
 *
 *----------------------------------------------------------------------
 * This file is part of gtk-gnutella.
 *
 *  gtk-gnutella is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  gtk-gnutella is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with gtk-gnutella; if not, write to the Free Software
 *  Foundation, Inc.:
 *      59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *----------------------------------------------------------------------
 */

/**
 * @ingroup core
 * @file
 *
 * Handles upload of our files to others users.
 *
 * @author Raphael Manfredi
 * @date 2001-2003
 * @author Daniel Walker (dwalker@cats.ucsc.edu)
 * @date 2000
 */

#ifndef _core_uploads_h_
#define _core_uploads_h_

#include "common.h"
#include "bsched.h"
#include "http.h"

#include "if/core/uploads.h"

struct dl_file_info;
struct gnutella_node;
struct parq_ul_queued;
struct special_upload;

/**
 * This structure is used for HTTP status printing callbacks.
 */
struct upload_http_cb {
	struct upload *u;			/**< Upload being ACK'ed */
	time_t mtime;				/**< File modification time */
};

enum upload_magic { UPLOAD_MAGIC = 0xac20f063U };	/**< Magic number */

struct upload {
	enum upload_magic magic;
    gnet_upload_t upload_handle;
	guint32 flags;					/**< Operating flags */
	upload_stage_t status;
	gint error_sent;				/**< HTTP error code sent back */
	gpointer io_opaque;				/**< Opaque I/O callback information */
	struct parq_ul_queued *parq_ul;	/**< PARQ information */

	struct gnutella_socket *socket;
	struct shared_file *sf;			/**< File we're uploading */
	struct file_object *file;		/**< uploaded file */
	struct dl_file_info *file_info;	/**< For PFSP: only set when partial file */
	struct special_upload *special;	/**< For special ops like browsing */
	const gchar *name;
	const struct sha1 *sha1;		/**< SHA1 of requested file */
	struct shared_file *thex;		/**< THEX owner we're uploading */
	struct bio_source *bio;			/**< Bandwidth-limited source */
	struct sendfile_ctx sendfile_ctx;

	gchar *request;
	struct upload_http_cb cb_parq_arg;
	struct upload_http_cb cb_sha1_arg;
	struct upload_http_cb cb_416_arg;
	struct upload_http_cb cb_status_arg;
	struct upload_http_cb cb_length_arg;
	http_extra_desc_t hev[16];
	guint hevcnt;

	gchar *buffer;
	gint bpos;
	gint bsize;
	gint buf_size;

	guint file_index;
	guint reqnum;				/**< Request number, incremented when serving */

	time_t start_date;
	time_t last_update;
	time_t last_dmesh;			/**< Time when last download mesh was sent */

	host_addr_t addr;			/**< Remote IP address */
	host_addr_t gnet_addr;		/**< Advertised remote IP address */
	guint16 gnet_port;			/**< Advertised Gnet port, for browsing */
	guint16 country;			/**< Country of origin, ISO3166 code */

	const gchar *user_agent;	/**< Remote user agent */

	filesize_t file_size;
	filesize_t skip;			/**< First byte to send, inclusive */
	filesize_t end;				/**< Last byte to send, inclusive */
	filesize_t pos;				/**< Read position in file we're sending */
	filesize_t sent;			/**< Bytes sent in this request */
	filesize_t total_requested;	/**< Total amount of bytes requested */
	filesize_t downloaded;		/**< What they claim as downloaded so far */

	gint http_major;			/**< HTTP major version */
	gint http_minor;			/**< HTTP minor version */

	gboolean keep_alive;		/**< Keep HTTP connection? */
	gboolean push;
	gboolean queue;				/**< Similar to PUSH, but for PARQ's QUEUE */
	gboolean accounted;			/**< True when upload was accounted for */
	gboolean unavailable_range;	/**< True when last request ended with 416 */
	gboolean n2r;				/**< True when they sent an N2R request */
	gboolean browse_host;		/**< True when they sent a Browse Host req. */
	gboolean from_browser;		/**< True when request likely from browser */
	gboolean head_only;
	gboolean is_followup;
	gboolean was_actively_queued;
	gboolean was_running;

	gboolean parq_status;
};

static inline void
upload_check(const struct upload * const u)
{
	g_assert(u);
	g_assert(UPLOAD_MAGIC == u->magic);
}

#define upload_vendor_str(u)	((u)->user_agent ? (u)->user_agent : "")

/**
 * Is upload special?
 */
static inline gboolean
upload_is_special(const struct upload *u)
{
	return u->browse_host || u->thex != NULL;
}

/*
 * Operating flags
 */

enum {
	UPLOAD_F_WAS_PLAIN		= 1 << 2,	/**< Prev request was for plain file  */
	UPLOAD_F_EARLY_STALL	= 1 << 1,	/**< Pre-stalling condition */
	UPLOAD_F_STALLED		= 1 << 0	/**< Stall condition present */
};

/*
 * Global Data
 */

/*
 * Global Functions
 */

gboolean upload_is_enabled(void);
void upload_timer(time_t now);
void upload_remove(struct upload *, const gchar *, ...) G_GNUC_PRINTF(2, 3);
void handle_push_request(struct gnutella_node *);
void upload_add(struct gnutella_socket *);
void upload_connect_conf(struct upload *);
void upload_init(void);
void upload_close(void);
void upload_stop_all(struct dl_file_info *, const gchar *reason);
void upload_send_giv(const host_addr_t addr, guint16 port, guint8 hops,
	guint8 ttl, guint32 file_index, const gchar *file_name,
	gboolean banning, guint32 flags);
struct upload *upload_create(struct gnutella_socket *, gboolean push);
void upload_fire_upload_info_changed(struct upload *);
void expect_http_header(struct upload *, upload_stage_t new_status);

GSList *upload_get_info_list(void);
void upload_free_info_list(GSList **sl_ptr);

struct upload *upload_alloc(void);
void upload_free(struct upload **ptr);

#endif /* _core_uploads_h_ */

/* vi: set ts=4 sw=4 cindent: */
