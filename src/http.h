/*
 * $Id$
 *
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

#define HTTP_PORT		80		/* Registered HTTP port */

struct gnutella_socket;
struct header;

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
 * http_header_cb_t
 *
 * Callback used from asynchronous request to indicate that we got headers.
 * Indicates whether we should continue or not, given the HTTP response code.
 */
typedef gboolean (*http_header_cb_t)(
	gpointer h, struct header *header, gint code);

/*
 * http_data_cb_t
 *
 * Callback used from asynchronous request to indicate that data is available.
 */
typedef void (*http_data_cb_t)(gpointer h, gchar *data, gint len);

typedef enum {				/* Type of error reported by http_error_cb_t */
	HTTP_ASYNC_SYSERR,		/* System error, value is errno */
	HTTP_ASYNC_ERROR,		/* Internal error, value is error code */
	HTTP_ASYNC_HEADER,		/* Internal header error, value is error code */
	HTTP_ASYNC_HTTP,		/* HTTP error, value is http_error_t pointer */
} http_errtype_t;

typedef struct {
	struct header *header;	/* Parsed HTTP header */
	gint code;				/* HTTP status code */
	gchar *message;			/* HTTP status message */
} http_error_t;

/*
 * http_error_cb_t
 *
 * Callback used from asynchronous request to indicate that an error occurred.
 * The type of `val' depends on the `error'.
 */
typedef void (*http_error_cb_t)(gpointer h, http_errtype_t error, gpointer val);

/*
 * Asynchronous request error codes.
 */

#define HTTP_ASYNC_OK			0	/* OK */
#define HTTP_ASYNC_BAD_URL		1	/* Invalid HTTP URL */
#define HTTP_ASYNC_CONN_FAILED	2	/* Connection failed */
#define HTTP_ASYNC_IO_ERROR		3	/* I/O error */
#define HTTP_ASYNC_REQ2BIG		4	/* Request too big */
#define HTTP_ASYNC_HEAD2BIG		5	/* Header too big */
#define HTTP_ASYNC_CANCELLED	6	/* User cancel */
#define HTTP_ASYNC_EOF			7	/* Got EOF */
#define HTTP_ASYNC_BAD_STATUS	8	/* Unparseable HTTP status */
#define HTTP_ASYNC_NO_LOCATION	9	/* Got moved status, but no location */

extern gint http_async_errno;

/*
 * Public interface
 */

void http_timer(time_t now);

gboolean http_send_status(struct gnutella_socket *s,
	gint code, http_extra_desc_t *hev, gint hevcnt, gchar *reason, ...);

gint http_status_parse(gchar *line,
	gchar *proto, gchar **msg, gint *major, gint *minor);

gboolean http_extract_version(
	gchar *request, gint len, gint *major, gint *minor);

gboolean http_url_parse(gchar *url, guint32 *ip, guint16 *port, gchar **res);

gpointer http_async_get(
	gchar *url,
	http_header_cb_t header_ind,
	http_data_cb_t data_ind,
	http_error_cb_t error_ind);

void http_async_connected(gpointer handle);
void http_async_cancel(gpointer handle);
void http_async_error(gpointer handle, gint code);

#endif	/* __http_h__ */

/* vi: set ts=4: */

