#ifndef __downloads_h__
#define __downloads_h__

#include "bsched.h"

struct download {
	gchar error_str[256];	/* Used to sprintf() error strings with vars */
	guint32 status;			/* Current status of the download */
	gpointer io_opaque;		/* Opaque I/O callback information */

	gchar *path;			/* Path of the created output file */
	gchar *output_name;		/* Basename of the created output file */
	bio_source_t *bio;		/* Bandwidth-limited source */

	gchar guid[16];			/* GUID of server from which we download the file */
	guint32 record_index;	/* Index of the file on the Gnutella server */
	gchar *file_name;		/* Name of the file on the Gnutella server */

	guint32 size;			/* Total size of the file, in bytes */

	guint32 skip;			/* Number of bytes for file we had before start */
	guint32 pos;			/* Number of bytes of the file we currently have */

	struct gnutella_socket *socket;
	gint file_desc;			/* FD for writing into downloaded file */
	guint32 overlap_size;	/* Size of the overlapping window on resume */

	time_t start_date;		/* Download start date */
	time_t last_update;		/* Last status update or I/O */
	time_t last_gui_update;	/* Last stats update on the GUI */

	guint32 retries;
	guint32 timeout_delay;
	guint restart_timer_id;

	const gchar *remove_msg;

	guint32 ip;
	guint16 port;

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
#define GTA_DL_STOPPED			12	/* Stopped, will restart shortly */

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

extern GSList *sl_downloads;
extern guint32 count_downloads;
extern gboolean send_pushes;

/*
 * Global Functions
 */

void download_init(void);
void download_timer(time_t now);
void download_new(gchar *,
	guint32, guint32, guint32, guint16, gchar *, gboolean);
void auto_download_new(
	gchar *, guint32, guint32, guint32, guint16, gchar *, gboolean);
void download_queue(struct download *);
void download_set_freeze(gboolean t);
gboolean download_get_freeze();
void download_stop(struct download *, guint32, const gchar *, ...);
void download_free(struct download *);
void download_push_ack(struct gnutella_socket *);
void download_fallback_to_push(struct download *, gboolean, gboolean);
void download_pickup_queued(void);
void downloads_clear_stopped(gboolean, gboolean);
void download_abort(struct download *);
void download_resume(struct download *);
void download_start(struct download *, gboolean);
void download_kill(struct download *);
void download_queue_back(struct download *);
gboolean download_send_request(struct download *);
void download_retry(struct download *);
void download_index_changed(guint32, guint16, guchar *, guint32, guint32);
void download_close(void);
void download_remove_all_from_peer(const gchar *guid);
void download_remove_all_named(const gchar *name);

#endif /* __downloads_h__ */
