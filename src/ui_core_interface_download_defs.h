/*
 * FILL_IN_EMILES_BLANKS
 *
 * Interface definition file.  One of the files that defines structures,
 * macros, etc. as part of the gui/core interface.
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

#ifndef _ui_core_interface_download_defs_h_
#define _ui_core_interface_download_defs_h_

#include "ui_core_interface_fileinfo_defs.h"
#include "ui_core_interface_http_defs.h"
#include "ui_core_interface_bsched_defs.h"
#include "ui_core_interface_tm_defs.h"
#include "ui_core_interface_gnet_search_defs.h"

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
	DL_LIST_INVALID	= -1,
	DL_LIST_RUNNING	= 0,
	DL_LIST_WAITING = 1,
	DL_LIST_STOPPED = 2,
	DL_LIST_SZ		= 3,
};

struct vernum {
	guint major;
	guint minor;
};

struct dl_key {
	gchar *guid;			/* GUID of server (atom) */
	guint32 ip;				/* IP address of server */
	guint16 port;			/* Port of server */
};

struct dl_server {
	struct dl_key *key;			/* Key properties */
	GList *list[DL_LIST_SZ];	/* Download lists */
	guint count[DL_LIST_SZ];	/* Amount of downloads in list */
	const gchar *vendor;		/* Remote server vendor string (atom) */
	const gchar *hostname;		/* Remote hostname, if known (atom) */
	time_t retry_after;			/* Time at which we may retry from this host */
	time_t dns_lookup;			/* Last DNS lookup for hostname */
	struct vernum parq_version;	/* Supported queueing version */
	guint32 attrs;
	GSList *proxies;			/* Known push proxies (struct gnutella_host) */
	time_t proxies_stamp;		/* Time when list was last updated */
};

/*
 * Download states.
 */

typedef enum {
    GTA_DL_QUEUED           = 1,    /* Download queued, will start later */
    GTA_DL_CONNECTING       = 2,    /* We are connecting to the server */
    GTA_DL_PUSH_SENT        = 3,    /* Sent a push, waiting connection */
    GTA_DL_FALLBACK         = 4,    /* Direct request failed, using push */
    GTA_DL_REQ_SENT         = 5,    /* Request sent, waiting for HTTP headers */
    GTA_DL_HEADERS          = 6,    /* We are receiving the HTTP headers */
    GTA_DL_RECEIVING        = 7,    /* We are receiving the data of the file */
    GTA_DL_COMPLETED        = 8,    /* Download is completed */
    GTA_DL_ERROR            = 9,    /* Download is stopped due to error */
    GTA_DL_ABORTED          = 10,   /* User used the 'Abort Download' button */
    GTA_DL_TIMEOUT_WAIT     = 11,   /* Waiting to try connecting again */
    GTA_DL_REMOVED          = 12,   /* Download was removed, pending free */
    GTA_DL_VERIFY_WAIT      = 13,   /* Waiting to verify SHA1 */
    GTA_DL_VERIFYING        = 14,   /* Computing SHA1 */
    GTA_DL_VERIFIED         = 15,   /* Verify of SHA1 done */
    GTA_DL_MOVE_WAIT        = 16,   /* Waiting to be moved to "done/bad" dir */
    GTA_DL_MOVING           = 17,   /* Being moved to "done/bad" dir */
    GTA_DL_DONE             = 18,   /* All done! */
    GTA_DL_SINKING          = 19,   /* Sinking HTML reply */
    GTA_DL_ACTIVE_QUEUED    = 20,   /* Actively queued */
    GTA_DL_PASSIVE_QUEUED   = 21,   /* Passively queued */
    GTA_DL_REQ_SENDING      = 22,   /* Sending HTTP request */
} download_status_t;

typedef struct download download_t;

struct download {
    gnet_src_t src_handle;      /* Handle */

	gchar error_str[256];	/* Used to sprintf() error strings with vars */
	download_status_t status;   /* Current status of the download */
	gpointer io_opaque;		/* Opaque I/O callback information */

	bio_source_t *bio;		/* Bandwidth-limited source */

	struct dl_server *server;	/* Remote server description */
	enum dl_list list_idx;		/* List to which download belongs in server */

	struct dl_file_info *file_info;
	guint32 record_index;	/* Index of the file on the Gnutella server */
	gchar *file_name;		/* Name of the file on the Gnutella server */
	gchar *escaped_name;	/* Same as file_name, with control chars escaped */
	guint32 file_size;		/* Total size of the file, in bytes */

	guint32 size;			/* Total size of the next request, in bytes */
	guint32 skip;			/* Number of bytes for file we had before start */
	guint32 pos;			/* Number of bytes of the file we currently have */
	guint32 range_end;		/* First byte offset AFTER the requested range */

	struct gnutella_socket *socket;
	gint file_desc;			/* FD for writing into downloaded file */
	guint32 overlap_size;	/* Size of the overlapping window on resume */
	http_buffer_t *req;		/* HTTP request, when partially sent */

	time_t start_date;		/* Download start date */
	time_t last_update;		/* Last status update or I/O */
	time_t last_gui_update;	/* Last stats update on the GUI */
	time_t record_stamp;	/* Stamp of the query hit that launched us */
	time_t retry_after;		/* Time at which we may retry for this download */
	tm_t header_sent;		/* When we sent the headers, for latency measures */

	guint32 retries;
	guint32 timeout_delay;

	const gchar *remove_msg;

	gchar *sha1;			/* Known SHA1 (binary atom), NULL if none */
	gchar *uri;				/* Uri if not dealing with regular gnutella
							 * file download */
	guint32 last_dmesh;		/* Time when last download mesh was sent */

	GSList *ranges;			/* PFSP -- known list of ranges, NULL if none */
	guint32 ranges_size;	/* PFSP -- size of remotely available data */
	guint32 sinkleft;		/* Amount of data left to sink */

	guint32 flags;

	gboolean file_size_known; /* File size known? */
	gboolean keep_alive;	/* Keep HTTP connection? */
	gboolean visible;		/* The download is visible in the GUI */
	gboolean push;			/* Currently in push mode */
	gboolean always_push;	/* Always use the push method for this download */
	gboolean got_giv;		/* Whether download created from GIV reception */
	gboolean unavailable;	/* Set on Timout, Push route lost */

	struct cproxy *cproxy;	/* Push proxy being used currently */

	gpointer queue_status;	/* Queuing status */
};

/*
 * Download flags.
 */

#define DL_F_URIRES			0x00000001	/* Tried to GET "/uri-res/N2R?" */
#define DL_F_PUSH_IGN		0x00000002	/* Trying to ignore push flag */
#define DL_F_OVERLAPPED		0x00000004	/* We went through overlap checking */
#define DL_F_REPLIED		0x00000008	/* Servent replied to last request */
#define DL_F_CHUNK_CHOSEN	0x00000010	/* Retrying with specific chunk */
#define DL_F_SHRUNK_REPLY	0x00000020	/* Server sending less than we asked */
#define DL_F_SUNK_DATA		0x00000040	/* Whether we previously sunk data */
#define DL_F_ACTIVE_QUEUED	0x00000080	/* Download is actively queued */
#define DL_F_PASSIVE_QUEUED	0x00000100	/* Download is passively queued */
#define DL_F_DNS_LOOKUP		0x00000200	/* Attempted DNS lookup */
#define DL_F_SUSPENDED		0x40000000	/* Suspended, do not schedule */
#define DL_F_MARK			0x80000000	/* Marked in traversal */

/*
 * Server attributes.
 */

#define DLS_A_NO_URIRES		0x00000001	/* No support for "/uri-res/N2R?" */
#define DLS_A_PUSH_IGN		0x00000002	/* Ignore pushes and connect directly */
#define DLS_A_NO_KEEPALIVE	0x00000004	/* No persistent connection */
#define DLS_A_HTTP_1_1		0x00000008	/* Server supports HTTP/1.1 */
#define DLS_A_MINIMAL_HTTP	0x00000010	/* Use minimalist HTTP with server */
#define DLS_A_BANNING		0x00000020	/* Server might be banning us */
#define DLS_A_FAKE_G2		0x00000040	/* Fake a G2 server */
#define DLS_A_DNS_LOOKUP	0x00000080	/* Perform DNS lookup if possible */
#define DLS_A_REMOVED		0x80000000	/* Server marked for removal */

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

#define DOWNLOAD_IS_VERIFYING(d)		 \
	(  (d)->status == GTA_DL_VERIFY_WAIT \
	|| (d)->status == GTA_DL_VERIFYING	 \
	|| (d)->status == GTA_DL_VERIFIED	 )

#define DOWNLOAD_IS_MOVING(d)		 	\
	(  (d)->status == GTA_DL_MOVE_WAIT	\
	|| (d)->status == GTA_DL_MOVING		)

#define DOWNLOAD_IS_STOPPED(d)			\
	(  (d)->status == GTA_DL_ABORTED	\
	|| (d)->status == GTA_DL_ERROR		\
	|| (d)->status == GTA_DL_COMPLETED  \
	|| DOWNLOAD_IS_VERIFYING(d)         \
	|| DOWNLOAD_IS_MOVING(d)            \
	|| (d)->status == GTA_DL_DONE       )

#define DOWNLOAD_IS_ACTIVE(d)			\
	(  (d)->status == GTA_DL_RECEIVING	)

#define DOWNLOAD_IS_WAITING(d)			\
	(  (d)->status == GTA_DL_TIMEOUT_WAIT)

#define DOWNLOAD_IS_ESTABLISHING(d)		\
	(  (d)->status == GTA_DL_CONNECTING \
	|| (d)->status == GTA_DL_PUSH_SENT	\
	|| (d)->status == GTA_DL_FALLBACK	\
	|| (d)->status == GTA_DL_REQ_SENT	\
	|| (d)->status == GTA_DL_REQ_SENDING	\
	|| (d)->status == GTA_DL_ACTIVE_QUEUED	\
	|| (d)->status == GTA_DL_SINKING	\
	|| (d)->status == GTA_DL_HEADERS	)

#define DOWNLOAD_IS_EXPECTING_GIV(d)	\
	(  (d)->status == GTA_DL_PUSH_SENT	\
	|| (d)->status == GTA_DL_FALLBACK	)

#define DOWNLOAD_IS_RUNNING(d)			\
	(	DOWNLOAD_IS_ACTIVE(d)			\
	||	DOWNLOAD_IS_ESTABLISHING(d)		)

#define DOWNLOAD_IS_IN_PUSH_MODE(d) (d->push)
#define DOWNLOAD_IS_VISIBLE(d)		(d->visible)


#endif
