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

#ifndef __uploads_h__
#define __uploads_h__

#include <sys/types.h>		/* For off_t */

#include "bsched.h"

struct gnutella_node;

struct upload {
	guint32 status;
	struct gnutella_socket *socket;
	gint error_sent;				/* HTTP error code sent back */
	gpointer io_opaque;				/* Opaque I/O callback information */

	gint file_desc;
	bio_source_t *bio;				/* Bandwidth-limited source */

	gchar *buffer;
	gint bpos;
	gint bsize;
	gint buf_size;

	guint index;
	gchar *name;
	guint32 file_size;

	time_t start_date;
	time_t last_update;

	guint32 ip;						/* Remote IP address */
	gchar *user_agent;				/* Remote user agent */
	guint skip;						/* First byte to send, inclusive */
	guint end;						/* Last byte to send, inclusive */
	off_t pos;						/* Read position in file we're sending */

	guint32 last_dmesh;				/* Time when last download mesh was sent */
	guchar *sha1;					/* SHA1 of requested file */
	off_t total_requested;			/* Total amount of bytes requested */
	gint http_major;				/* HTTP major version */
	gint http_minor;				/* HTTP minor version */

	gboolean keep_alive;			/* Keep HTTP connection? */
	gboolean push;
	gboolean accounted;				/* True when upload was accounted for */
};

/*
 * Upload states.
 */

#define GTA_UL_PUSH_RECEIVED	1	/* We got a push request */
#define GTA_UL_COMPLETE			2	/* The file has been sent completely */
#define GTA_UL_SENDING			3	/* We are sending data */
#define GTA_UL_HEADERS			4	/* Receiving the HTTP request headers */
#define GTA_UL_WAITING			5	/* Waiting new HTTP request */

/*
 * State inspection macros.
 */

#define UPLOAD_IS_CONNECTING(u)						\
	(	(u)->status == GTA_UL_HEADERS				\
	||	(u)->status == GTA_UL_PUSH_RECEIVED			\
	||	(u)->status == GTA_UL_WAITING	)

#define UPLOAD_IS_COMPLETE(u)	\
	((u)->status == GTA_UL_COMPLETE)

#define UPLOAD_IS_SENDING(u)	\
	((u)->status == GTA_UL_SENDING)


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
void upload_init(void);
void upload_close(void);

#endif /* __uploads_h__ */
