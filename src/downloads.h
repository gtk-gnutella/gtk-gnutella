/*
 * $Id$
 *
 * Copyright (c) 2001-2002, Raphael Manfredi
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

#ifndef __downloads_h__
#define __downloads_h__

#include "bsched.h"
#include "fileinfo.h"

/*
 * We keep a list of all the downloads queued per GUID+IP:port (host).  Indeed
 * some broken clients (e.g. Morpheus) share the same GUID, so we cannot
 * fully discriminate on the GUID alone.  So GUID+IP:port forms the "key",
 * the `dl_key' structure.
 *
 * Inside the `dl_server', we keep track all `download' structures and
 * other server-related information, which are shared by all downloads
 * from this host..
 *
 * Within a single server, a download can be in either runnning, waiting
 * or stopped.  An array of lists is kept, and since the download can be
 * in only one of them, it also keeps track of the proper list index.
 */

enum dl_list {
	DL_LIST_RUNNING	= 0,
	DL_LIST_WAITING = 1,
	DL_LIST_STOPPED = 2,
	DL_LIST_SZ		= 3,
};

struct dl_key {
	guchar *guid;			/* GUID of server (atom) */
	guint32 ip;				/* IP address of server */
	guint16 port;			/* Port of server */
};

struct dl_server {
	struct dl_key *key;		/* Key properties */
	GList *list[DL_LIST_SZ];	/* Download lists */
	gint count[DL_LIST_SZ];		/* Amount of downloads in list */
	gchar *vendor;			/* Remote server vendor string (atom) */
	time_t retry_after;		/* Time at which we may retry from this host */
	guint32 attrs;
};

struct download {
	gchar error_str[256];	/* Used to sprintf() error strings with vars */
	guint32 status;			/* Current status of the download */
	gpointer io_opaque;		/* Opaque I/O callback information */

	bio_source_t *bio;		/* Bandwidth-limited source */

	struct dl_server *server;	/* Remote server description */
	enum dl_list list_idx;		/* List to which download belongs in server */

	struct dl_file_info *file_info;
	guint32 record_index;	/* Index of the file on the Gnutella server */
	gchar *file_name;		/* Name of the file on the Gnutella server */

	guint32 size;			/* Total size of the file, in bytes */

	guint32 skip;			/* Number of bytes for file we had before start */
	guint32 pos;			/* Number of bytes of the file we currently have */
	guint32 range_end;		/* First byte offset AFTER the requested range */

	struct gnutella_socket *socket;
	gint file_desc;			/* FD for writing into downloaded file */
	guint32 overlap_size;	/* Size of the overlapping window on resume */

	time_t start_date;		/* Download start date */
	time_t last_update;		/* Last status update or I/O */
	time_t last_gui_update;	/* Last stats update on the GUI */
	time_t record_stamp;	/* Stamp of the query hit that launched us */

	guint32 retries;
	guint32 timeout_delay;

	const gchar *remove_msg;

	gchar *sha1;			/* Known SHA1 (binary atom), NULL if none */
	guint32 last_dmesh;		/* Time when last download mesh was sent */

	guint32 flags;

	gboolean keep_alive;	/* Keep HTTP connection? */
	gboolean visible;		/* The download is visible in the GUI */
	gboolean push;			/* Currently in push mode */
	gboolean always_push;	/* Always use the push method for this download */
};

/*
 * Download states.
 */

#define GTA_DL_QUEUED			1	/* Download queued, will start later */
#define GTA_DL_CONNECTING		2	/* We are connecting to the server */
#define GTA_DL_PUSH_SENT		3	/* Sent a push, waiting connection */
#define GTA_DL_FALLBACK			4	/* Direct request failed, using push */
#define GTA_DL_REQ_SENT			5	/* Request sent, waiting for HTTP headers */
#define GTA_DL_HEADERS			6	/* We are receiving the HTTP headers */
#define GTA_DL_RECEIVING		7	/* We are receiving the data of the file */
#define GTA_DL_COMPLETED		8	/* Download is completed */
#define GTA_DL_ERROR			9	/* Download is stopped due to error */
#define GTA_DL_ABORTED			10	/* User used the 'Abort Download' button */
#define GTA_DL_TIMEOUT_WAIT		11	/* Waiting to try connecting again */
#define GTA_DL_REMOVED			12	/* Download was removed, pending free */

/*
 * Download flags.
 */

#define DL_F_URIRES			0x00000001	/* Tried to GET "/uri-res/N2R?" */
#define DL_F_PUSH_IGN		0x00000002	/* Trying to ignore push flag */
#define DL_F_MARK			0x80000000	/* Marked in traversal */

/*
 * Server attributes.
 */

#define DLS_A_NO_URIRES		0x00000001	/* No support for "/uri-res/N2R?" */
#define DLS_A_PUSH_IGN		0x00000002	/* Ignore pushes and connect directly */
#define DLS_A_NO_KEEPALIVE	0x00000004	/* No persistent connection */
#define DLS_A_HTTP_1_1		0x00000008	/* Server supports HTTP/1.1 */

/*
 * Access macros.
 */

#define download_guid(d)		((d)->server->key->guid)
#define download_ip(d)			((d)->server->key->ip)
#define download_port(d)		((d)->server->key->port)
#define download_vendor(d)		((d)->server->vendor)

#define download_vendor_str(d) \
	((d)->server->vendor ? (d)->server->vendor : "")

#define download_path(d)		((d)->file_info->path)
#define download_outname(d)		((d)->file_info->file_name)
#define download_filesize(d)	((d)->file_info->size)
#define download_filedone(d)	((d)->file_info->done)

/*
 * State inspection macros.
 */

#define DOWNLOAD_IS_QUEUED(d)  ((d)->status == GTA_DL_QUEUED)

#define DOWNLOAD_IS_STOPPED(d)			\
	(  (d)->status == GTA_DL_ABORTED	\
	|| (d)->status == GTA_DL_ERROR		\
	|| (d)->status == GTA_DL_COMPLETED	)

#define DOWNLOAD_IS_ACTIVE(d)			\
	((d)->status == GTA_DL_RECEIVING)

#define DOWNLOAD_IS_WAITING(d)			\
	(  (d)->status == GTA_DL_STOPPED 	\
	|| (d)->status == GTA_DL_TIMEOUT_WAIT)

#define DOWNLOAD_IS_ESTABLISHING(d)		\
	(  (d)->status == GTA_DL_CONNECTING \
	|| (d)->status == GTA_DL_PUSH_SENT	\
	|| (d)->status == GTA_DL_FALLBACK	\
	|| (d)->status == GTA_DL_REQ_SENT	\
	|| (d)->status == GTA_DL_HEADERS	)

#define DOWNLOAD_IS_EXPECTING_GIV(d)	\
	(  (d)->status == GTA_DL_PUSH_SENT	\
	|| (d)->status == GTA_DL_FALLBACK	)

#define DOWNLOAD_IS_RUNNING(d)			\
	(	DOWNLOAD_IS_ACTIVE(d)			\
	||	DOWNLOAD_IS_ESTABLISHING(d)		)

#define DOWNLOAD_IS_IN_PUSH_MODE(d) (d->push)
#define DOWNLOAD_IS_VISIBLE(d)		(d->visible)

/* 
 * Global Data
 */

extern GSList *sl_unqueued;

/*
 * Global Functions
 */

void download_init(void);
void download_timer(time_t now);
void download_new(gchar *,
	guint32, guint32, guint32, guint16, gchar *, gchar *, time_t,
    gboolean, struct dl_file_info *);
void download_auto_new(gchar *,
	guint32, guint32, guint32, guint16, gchar *, gchar *, time_t,
    gboolean, struct dl_file_info *);
void download_file_info_change_all(
	struct dl_file_info *old_fi, struct dl_file_info *new_fi);
void download_queue(struct download *d, const gchar *fmt, ...);
void download_freeze_queue();
void download_thaw_queue();
gint download_queue_is_frozen();
void download_stop(struct download *, guint32, const gchar *, ...);
void download_free(struct download *);
void download_push_ack(struct gnutella_socket *);
void download_fallback_to_push(struct download *, gboolean, gboolean);
void download_pickup_queued(void);
void download_clear_stopped(gboolean, gboolean);
void download_abort(struct download *);
void download_resume(struct download *);
void download_start(struct download *, gboolean);
void download_queue_back(struct download *);
void download_send_request(struct download *);
void download_retry(struct download *);
void download_index_changed(guint32, guint16, guchar *, guint32, guint32);
void download_close(void);
gint download_remove_all_from_peer(const gchar *guid, guint32 ip, guint16 port);
gint download_remove_all_named(const gchar *name);
gint download_remove_all_with_sha1(const guchar *sha1);
void download_remove_file(struct download *d);
gboolean download_file_exists(struct download *d);
gboolean download_server_nopush(guchar *guid, guint32 ip, guint16 port);
gchar *build_url_from_download(struct download *d);

#endif /* __downloads_h__ */
