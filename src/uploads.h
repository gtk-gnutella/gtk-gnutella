#ifndef __uploads_h__
#define __uploads_h__

#include "sockets.h"

struct upload {
	guint32 status;
	struct gnutella_socket *socket;
	gint error_sent;				/* HTTP error code sent back */
	gpointer io_opaque;				/* Opaque I/O callback information */

	gint file_desc;

	gchar *buffer;
	gint bpos;
	gint bsize;
	gint buf_size;

	guint index;
	gchar *name;
	guint32 file_size;

	time_t start_date;
	time_t last_update;

	guint skip;						/* First byte to send, inclusive */
	guint end;						/* Last byte to send, inclusive */
	guint pos;
	gboolean push;
};

/*
 * Upload states.
 */

#define GTA_UL_CONNECTED		1	/* Someone has connected to us	*/
#define GTA_UL_PUSH_RECIEVED	2	/* We got a push request */
#define GTA_UL_COMPLETE			3	/* The file has been sent completely */
#define GTA_UL_SENDING			4	/* We are sending data */
#define GTA_UL_HEADERS			5	/* Receiving the HTTP request headers */

/*
 * State inspection macros.
 */

#define UPLOAD_IS_CONNECTING(u)						\
	(	(u)->status == GTA_UL_HEADERS				\
	||	(u)->status == GTA_UL_PUSH_RECIEVED	)

#define UPLOAD_IS_COMPLETE(u)	\
	((u)->status == GTA_UL_COMPLETE)

/*
 * Until we got all the HTTP headers, the entry does not appear
 * in the upload list on the GUI.
 */
#define UPLOAD_IS_VISIBLE(u) \
	((u)->status != GTA_UL_HEADERS)

/* 
 * Global Data
 */

extern GSList *uploads;
extern gint running_uploads;
extern gint registered_uploads;
extern guint32 count_uploads;

/* 
 * Global Functions
 */

void upload_timer(time_t now);
void upload_remove(struct upload *, const gchar *, ...);
void handle_push_request(struct gnutella_node *);
void upload_add(struct gnutella_socket *s);
void upload_push_conf(struct upload *u);
void upload_write(gpointer up, gint, GdkInputCondition);
void upload_close(void);

#endif /* __uploads_h__ */
