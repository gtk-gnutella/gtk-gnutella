/*
 * Copyright (c) 2002, Raphael Manfredi
 *
 * HTTP routines.
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

#ifndef __http_h__
#define __http_h__

#include <glib.h>

struct gnutella_socket;


/*
 * http_send_status() additional header description:
 */

typedef enum {
	HTTP_EXTRA_LINE,
	HTTP_EXTRA_CALLBACK,
} http_extra_type_t;

/*
 * http_status_cb_t
 *
 * The callback used to generate custom headers.
 *
 * `buf' is where the callback can generate extra data.
 * `retlen' is initially filled with the room available in `buf'.
 * `arg' is user-supplied data.
 *
 * The callback is expected to fill `buf' and return the length of written
 * data into `retlen'.
 */
typedef void (*http_status_cb_t)(gchar *buf, gint *retlen, gpointer arg);

typedef struct {
	http_extra_type_t he_type;		/* Union discriminent */
	union {
		gchar *u_msg;				/* Single header line */
		struct {
			http_status_cb_t u_cb;	/* Callback to compute header field */
			gpointer u_arg;			/* Callback context argument */
		} u_cbk;
	} u;
} http_extra_desc_t;

#define he_msg	u.u_msg
#define he_cb	u.u_cbk.u_cb
#define he_arg	u.u_cbk.u_arg


/*
 * Public interface
 */

gboolean http_send_status(struct gnutella_socket *s,
	gint code, http_extra_desc_t *hev, gint hevcnt, gchar *reason, ...);

gint http_status_parse(gchar *line,
	gchar *proto, gchar **msg, gint *major, gint *minor);

#endif	/* __http_h__ */

/* vi: set ts=4: */

