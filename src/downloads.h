#ifndef __downloads_h__
#define __downloads_h__

struct download {
	gchar error_str[256];	/* Used to sprintf() error strings with vars */
	guint32 status;			/* Current status of the download */

	gchar *path;			/* Path of the created output file */
	gchar *file_name;		/*		Name of the created output file */

	gchar guid[16];			/* GUID of server from which we download the file */
	guint32 record_index;	/* Index of the file on the Gnutella server */

	guint32 size;			/* Total size of the file, in bytes */

	guint32 skip;			/* Number of bytes for file we had before start */
	guint32 pos;			/* Number of bytes of the file we currently have */

	struct gnutella_socket *socket;
	gint file_desc;

	time_t start_date;
	time_t last_update;
	guint32 retries;
	guint32 timeout_delay;
	guint restart_timer_id;

	const gchar *remove_msg;

	guint32 ip;
	guint16 port;

	gboolean visible;		/* The download is visible in the GUI */

	gboolean push;			/* Always use the push method for this download */

	gboolean ok;			/* We have got 200 OK */
};

/* 
 * Global Data
 */

extern GSList *sl_downloads;
extern guint32 count_downloads;
extern gboolean send_pushes;
extern struct download *selected_queued_download;
extern struct download *selected_active_download;

/*
 * Global Functions
 */

void download_new(gchar *, guint32, guint32, guint32, guint16, gchar *);
void download_queue(struct download *);
void download_stop(struct download *, guint32, const gchar *, ...);
void download_free(struct download *);
void download_read(gpointer, gint, GdkInputCondition);
void download_push(struct download *);
void download_fallback_to_push(struct download *, gboolean);
void download_pickup_queued(void);
void downloads_clear_stopped(gboolean, gboolean);
void download_abort(struct download *);
void download_resume(struct download *);
void download_start(struct download *, gboolean);
void download_kill(struct download *);
void download_queue_back(struct download *);
gboolean download_send_request(struct download *);
void download_retry(struct download *);
void download_close(void);

#endif /* __downloads_h__ */
