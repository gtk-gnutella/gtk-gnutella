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

#ifndef _ui_core_interface_http_defs_h_
#define _ui_core_interface_http_defs_h_

#include "ui_core_interface_gnutella_defs.h"
#include "ui_core_interface_header_defs.h"

#define HTTP_PORT		80		/* Registered HTTP port */
#define MAX_HOSTLEN		256		/* Max length for FQDN host */

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
 * `flags' are extra flags passed by callback invoker
 *
 * The callback is expected to fill `buf' and return the length of written
 * data into `retlen'.
 */
typedef void (*http_status_cb_t)(
	gchar *buf, gint *retlen, gpointer arg, guint32 flags);

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
 * Flags used during callback invocation.
 */

#define HTTP_CBF_SMALL_REPLY	0x00000001	/* Try to emit smallest reply */
#define HTTP_CBF_BW_SATURATED	0x00000002	/* Bandwidth is saturated */
#define HTTP_CBF_BUSY_SIGNAL	0x00000004	/* Sending back a 503 "busy" */
#define HTTP_CBF_SHOW_RANGES	0x00000008	/* Show available ranges */

/*
 * http_header_cb_t
 *
 * Callback used from asynchronous request to indicate that we got headers.
 * Indicates whether we should continue or not, given the HTTP response code.
 */
typedef gboolean (*http_header_cb_t)(
	gpointer h, struct header *header, gint code, const gchar *message);

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
	const gchar *message;	/* HTTP status message */
} http_error_t;

/*
 * http_error_cb_t
 *
 * Callback used from asynchronous request to indicate that an error occurred.
 * The type of `val' depends on the `error'.
 */
typedef void (*http_error_cb_t)(gpointer h, http_errtype_t error, gpointer val);

/*
 * http_user_free_t
 *
 * Callabck to free user opaque data.
 */
typedef void (*http_user_free_t)(gpointer data);

/*
 * Asynchronous operations that the user may redefine.
 */

typedef gint (*http_op_request_t)(gpointer handle, gchar *buf, gint len,
	gchar *verb, gchar *path, gchar *host, guint16 port);

/*
 * Asynchronous request error codes.
 */

#define HTTP_ASYNC_OK				0	/* OK */
#define HTTP_ASYNC_BAD_URL			1	/* Invalid HTTP URL */
#define HTTP_ASYNC_CONN_FAILED		2	/* Connection failed */
#define HTTP_ASYNC_IO_ERROR			3	/* I/O error */
#define HTTP_ASYNC_REQ2BIG			4	/* Request too big */
#define HTTP_ASYNC_HEAD2BIG			5	/* Header too big */
#define HTTP_ASYNC_CANCELLED		6	/* User cancel */
#define HTTP_ASYNC_EOF				7	/* Got EOF */
#define HTTP_ASYNC_BAD_STATUS		8	/* Unparseable HTTP status */
#define HTTP_ASYNC_NO_LOCATION		9	/* Got moved status, but no location */
#define HTTP_ASYNC_CONN_TIMEOUT		10	/* Connection timeout */
#define HTTP_ASYNC_TIMEOUT			11	/* Data timeout */
#define HTTP_ASYNC_NESTED			12	/* Nested redirections */
#define HTTP_ASYNC_BAD_LOCATION_URI	13	/* Invalid URI in Location header */
#define HTTP_ASYNC_CLOSED			14	/* Connection was closed, all OK */
#define HTTP_ASYNC_REDIRECTED		15	/* Redirected, following disabled */

extern guint http_async_errno;

/*
 * Error codes from http_url_parse().
 */

typedef enum {
	HTTP_URL_OK = 0,					/* All OK */
	HTTP_URL_NOT_HTTP,					/* Not an http URI */
	HTTP_URL_MULTIPLE_CREDENTIALS,		/* More than one <user>:<password> */
	HTTP_URL_BAD_CREDENTIALS,			/* Truncated <user>:<password> */
	HTTP_URL_BAD_PORT_PARSING,			/* Could not parse port */
	HTTP_URL_BAD_PORT_RANGE,			/* Port value is out of range */
	HTTP_URL_HOSTNAME_UNKNOWN,			/* Could not resolve host into IP */
	HTTP_URL_MISSING_URI,				/* URL has no URI part */
} http_url_error_t;

extern http_url_error_t http_url_errno;

/*
 * HTTP range description.
 */

typedef struct http_range {
	guint32 start;
	guint32 end;						/* HTTP_OFFSET_MAX if unbounded */
} http_range_t;

#define HTTP_OFFSET_MAX	0xffffffff

/*
 * HTTP request states.
 */

typedef enum http_state {
	HTTP_AS_UNKNOWN = 0,		/* No defined state */
	HTTP_AS_CONNECTING,			/* Connecting to server */
	HTTP_AS_REQ_SENDING,		/* Sending request to server */
	HTTP_AS_REQ_SENT,			/* Request sent, waiting for reply */
	HTTP_AS_HEADERS,			/* Receiving headers */
	HTTP_AS_RECEIVING,			/* Receiving data */
	HTTP_AS_REDIRECTED,			/* Request redirected */
	HTTP_AS_REMOVED,			/* Removed, pending free */
} http_state_t;

/*
 * http_state_change_t
 *
 * Callabck to notify about state changes in HTTP request.
 */
typedef void (*http_state_change_t)(gpointer handle, http_state_t newstate);

/*
 * HTTP data buffered when it cannot be sent out immediately.
 */

typedef struct http_buffer {
	gchar *hb_arena;		/* The whole thing */
	gchar *hb_rptr;			/* Reading pointer within arena */
	gchar *hb_end;			/* First char after buffer */
	gint hb_len;			/* Total arena length */
} http_buffer_t;

#define http_buffer_base(hb)		((hb)->hb_arena)
#define http_buffer_length(hb)		((hb)->hb_len)
#define http_buffer_read_base(hb)	((hb)->hb_rptr)
#define http_buffer_unread(hb)		((hb)->hb_end - (hb)->hb_rptr)

#define http_buffer_add_read(hb,tx)	do { (hb)->hb_rptr += (tx); } while (0)


#endif
