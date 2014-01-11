/*
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
#include "hcache.h"
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

enum upload_magic { UPLOAD_MAGIC = 0x2c20f063U };	/**< Magic number */

struct upload {
	enum upload_magic magic;
    gnet_upload_t upload_handle;
	uint32 flags;					/**< Operating flags */
	upload_stage_t status;
	int error_sent;					/**< HTTP error code sent back */
	void *io_opaque;				/**< Opaque I/O callback information */
	struct parq_ul_queued *parq_ul;	/**< PARQ information */

	struct gnutella_socket *socket;
	struct shared_file *sf;			/**< File we're uploading */
	struct file_object *file;		/**< uploaded file */
	struct dl_file_info *file_info;	/**< For PFSP: only set when partial file */
	struct special_upload *special;	/**< For special ops like browsing */
	const char *name;
	const struct sha1 *sha1;		/**< SHA1 of requested file */
	struct shared_file *thex;		/**< THEX owner we're uploading */
	struct bio_source *bio;			/**< Bandwidth-limited source */
	struct sendfile_ctx sendfile_ctx;

	char *request;
	struct upload_http_cb cb_parq_arg;
	struct upload_http_cb cb_sha1_arg;
	struct upload_http_cb cb_416_arg;
	struct upload_http_cb cb_status_arg;
	struct upload_http_cb cb_length_arg;
	http_extra_desc_t hev[16];
	uint hevcnt;

	char *buffer;
	int bpos;
	int bsize;
	int buf_size;

	uint file_index;
	uint reqnum;				/**< Request number, incremented when serving */
	uint error_count;			/**< Amount of errors on connection */

	time_t start_date;
	time_t last_update;
	time_t last_dmesh;			/**< Time when last download mesh was sent */

	host_addr_t addr;			/**< Remote IP address */
	host_addr_t gnet_addr;		/**< Advertised remote IP address */
	uint16 gnet_port;			/**< Advertised Gnet port, for browsing */
	uint16 country;				/**< Country of origin, ISO3166 code */

	const char *user_agent;		/**< Remote user agent */
	const struct guid *guid;	/**< Remote servent GUID (atom), if known */

	filesize_t file_size;
	filesize_t skip;			/**< First byte to send, inclusive */
	filesize_t end;				/**< Last byte to send, inclusive */
	filesize_t pos;				/**< Read position in file we're sending */
	filesize_t sent;			/**< Bytes sent in this request */
	filesize_t total_requested;	/**< Total amount of bytes requested */
	filesize_t downloaded;		/**< What they claim as downloaded so far */

	int http_major;				/**< HTTP major version */
	int http_minor;				/**< HTTP minor version */

	host_net_t net;				/**< IPv6-Ready: type of addresses they want */

	unsigned keep_alive:1;		/**< Keep HTTP connection? */
	unsigned push:1;
	unsigned queue:1;			/**< Similar to PUSH, but for PARQ's QUEUE */
	unsigned accounted:1;		/**< True when upload was accounted for */
	unsigned n2r:1;				/**< True when they sent an N2R request */
	unsigned browse_host:1;		/**< True when they sent a Browse Host req. */
	unsigned from_browser:1;	/**< True when request likely from browser */
	unsigned head_only:1;
	unsigned is_followup:1;
	unsigned was_actively_queued:1;
	unsigned was_running:1;
	unsigned last_was_error:1;	/**< Whether last request was an error */
	unsigned parq_status:1;
	unsigned fwalt:1;			/**< Downloader accepts firewalled locations */
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
static inline bool
upload_is_special(const struct upload *u)
{
	return u->browse_host || u->thex != NULL;
}

/*
 * Operating flags
 */

enum {
	UPLOAD_F_NORMAL_LIMIT	= 1 << 5,	/**< Normal limits */
	UPLOAD_F_STEALTH_LIMIT	= 1 << 4,	/**< Stealth limits */
	UPLOAD_F_LIMITED		= 1 << 3,	/**< Subject to limitation */
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

bool upload_is_enabled(void);
void upload_timer(time_t now);
void upload_remove(struct upload *, const char *, ...) G_GNUC_PRINTF(2, 3);
void handle_push_request(struct gnutella_node *);
void upload_add(struct gnutella_socket *);
void upload_init(void);
void upload_close(void);
void upload_stop_all(struct dl_file_info *, const char *reason);
void upload_send_giv(const host_addr_t addr, uint16 port, uint8 hops,
	uint8 ttl, uint32 file_index, const char *file_name, uint32 flags);
struct upload *upload_create(struct gnutella_socket *, bool push);
void upload_fire_upload_info_changed(struct upload *);
void expect_http_header(struct upload *, upload_stage_t new_status);

struct pslist *upload_get_info_list(void);
void upload_free_info_list(struct pslist **sl_ptr);

struct upload *upload_alloc(void);
void upload_free(struct upload **ptr);

const char *upload_host_info(const struct upload *u);

#endif /* _core_uploads_h_ */

/* vi: set ts=4 sw=4 cindent: */
