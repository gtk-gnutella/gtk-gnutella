#ifndef __uploads_h__
#define __uploads_h__

#include "sockets.h"

struct upload {
	guint32 status;

	struct gnutella_socket *socket;

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

	gint skip;
	gint pos;
	gboolean push;

};

/* 
 * Global Data
 */

extern GSList *uploads;
extern gint running_uploads;
extern guint32 count_uploads;

/* 
 * Global Functions
 */

void upload_remove(struct upload *, gchar *);
void handle_push_request(struct gnutella_node *);
struct upload *upload_add(struct gnutella_socket *s);
void upload_write(gpointer up, gint, GdkInputCondition);
void upload_close(void);

#endif /* __uploads_h__ */
