/*
 * $Id$
 *
 * Copyright (c) 2001-2002, Raphael Manfredi
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

#ifndef __uploads_h__
#define __uploads_h__

#include <sys/types.h>		/* For off_t */

#include "bsched.h"

struct gnutella_node;

typedef struct upload {
    gnet_upload_t upload_handle;

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
} gnutella_upload_t;

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
void upload_init(void);
void upload_close(void);

#endif /* __uploads_h__ */

