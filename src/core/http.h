/*
 * $Id$
 *
 * Copyright (c) 2002-2003, Raphael Manfredi
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

/**
 * @ingroup core
 * @file
 *
 * HTTP routines.
 *
 * @author Raphael Manfredi
 * @date 2002-2003
 */

#ifndef _core_http_h_
#define _core_http_h_

#include "if/core/http.h"
#include "lib/host_addr.h"

#define HTTP_PORT		80		/**< Registered HTTP port */

typedef enum {
	HTTP_CONTENT_ENCODING_IDENTITY,
	HTTP_CONTENT_ENCODING_DEFLATE,
	HTTP_CONTENT_ENCODING_GZIP
} http_content_encoding_t;

/**
 * http_send_status() additional header description:
 */

typedef enum {
	HTTP_EXTRA_LINE,
	HTTP_EXTRA_CALLBACK,
	HTTP_EXTRA_BODY
} http_extra_type_t;

/**
 * The callback used to generate custom headers.
 *
 * @param `buf' is where the callback can generate extra data.
 * @param `retlen' is initially filled with the room available in `buf'.
 * @param `arg' is user-supplied data.
 * @param `flags' are extra flags passed by callback invoker
 *
 * The callback is expected to fill `buf' and return the length of written
 * data into `retlen'.
 */
typedef void (*http_status_cb_t)(
	gchar *buf, gint *retlen, gpointer arg, guint32 flags);

typedef struct {
	http_extra_type_t he_type;		/**< Union discriminent */
	union {
		gchar *u_msg;				/**< Single header line */
		struct {
			http_status_cb_t u_cb;	/**< Callback to compute header field */
			gpointer u_arg;			/**< Callback context argument */
		} u_cbk;
	} u;
} http_extra_desc_t;

#define he_msg	u.u_msg
#define he_cb	u.u_cbk.u_cb
#define he_arg	u.u_cbk.u_arg

/*
 * Flags used during callback invocation.
 */

#define HTTP_CBF_SMALL_REPLY	0x00000001	/**< Try to emit smallest reply */
#define HTTP_CBF_BW_SATURATED	0x00000002	/**< Bandwidth is saturated */
#define HTTP_CBF_BUSY_SIGNAL	0x00000004	/**< Sending back a 503 "busy" */
#define HTTP_CBF_SHOW_RANGES	0x00000008	/**< Show available ranges */

struct header;

/**
 * Callback used from asynchronous request to indicate that we got headers.
 * Indicates whether we should continue or not, given the HTTP response code.
 */
typedef gboolean (*http_header_cb_t)(
	gpointer h, struct header *header, gint code, const gchar *message);

/**
 * Callback used from asynchronous request to indicate that data is available.
 */
typedef void (*http_data_cb_t)(gpointer h, gchar *data, gint len);

typedef enum {				/**< Type of error reported by http_error_cb_t */
	HTTP_ASYNC_SYSERR,		/**< System error, value is errno */
	HTTP_ASYNC_ERROR,		/**< Internal error, value is error code */
	HTTP_ASYNC_HEADER,		/**< Internal header error, value is error code */
	HTTP_ASYNC_HTTP			/**< HTTP error, value is http_error_t pointer */
} http_errtype_t;

typedef struct {
	struct header *header;	/**< Parsed HTTP header */
	gint code;				/**< HTTP status code */
	const gchar *message;	/**< HTTP status message */
} http_error_t;

/**
 * Callback used from asynchronous request to indicate that an error occurred.
 * The type of `val' depends on the `error'.
 */

typedef void (*http_error_cb_t)(gpointer h, http_errtype_t error, gpointer val);

/**
 * Callabck to free user opaque data.
 */

typedef void (*http_user_free_t)(gpointer data);

/**
 * Asynchronous operations that the user may redefine.
 */

typedef size_t (*http_op_request_t)(gpointer handle, gchar *buf, size_t len,
	const gchar *verb, const gchar *path, const gchar *host, guint16 port);

/*
 * Asynchronous request error codes.
 */

#define HTTP_ASYNC_OK				0	/**< OK */
#define HTTP_ASYNC_BAD_URL			1	/**< Invalid HTTP URL */
#define HTTP_ASYNC_CONN_FAILED		2	/**< Connection failed */
#define HTTP_ASYNC_IO_ERROR			3	/**< I/O error */
#define HTTP_ASYNC_REQ2BIG			4	/**< Request too big */
#define HTTP_ASYNC_HEAD2BIG			5	/**< Header too big */
#define HTTP_ASYNC_CANCELLED		6	/**< User cancel */
#define HTTP_ASYNC_EOF				7	/**< Got EOF */
#define HTTP_ASYNC_BAD_STATUS		8	/**< Unparseable HTTP status */
#define HTTP_ASYNC_NO_LOCATION		9	/**< Got moved status, but no location */
#define HTTP_ASYNC_CONN_TIMEOUT		10	/**< Connection timeout */
#define HTTP_ASYNC_TIMEOUT			11	/**< Data timeout */
#define HTTP_ASYNC_NESTED			12	/**< Nested redirections */
#define HTTP_ASYNC_BAD_LOCATION_URI	13	/**< Invalid URI in Location header */
#define HTTP_ASYNC_CLOSED			14	/**< Connection was closed, all OK */
#define HTTP_ASYNC_REDIRECTED		15	/**< Redirected, following disabled */

extern guint http_async_errno;

/**
 * Error codes from http_url_parse().
 */

typedef enum {
	HTTP_URL_OK = 0,				/**< All OK */
	HTTP_URL_NOT_HTTP,				/**< Not an http URI */
	HTTP_URL_MULTIPLE_CREDENTIALS,	/**< More than one "<user>:<password>" */
	HTTP_URL_BAD_CREDENTIALS,		/**< Truncated "<user>:<password>" */
	HTTP_URL_BAD_PORT_PARSING,		/**< Could not parse port */
	HTTP_URL_BAD_PORT_RANGE,		/**< Port value is out of range */
	HTTP_URL_BAD_HOST_PART,			/**< Could not parse host */
	HTTP_URL_HOSTNAME_UNKNOWN,		/**< Could not resolve host into IP */
	HTTP_URL_MISSING_URI			/**< URL has no URI part */
} http_url_error_t;

extern http_url_error_t http_url_errno;

/**
 * Callback to notify about state changes in HTTP request.
 */

typedef void (*http_state_change_t)(gpointer handle, http_state_t newstate);

/**
 * HTTP data buffered when it cannot be sent out immediately.
 */

typedef struct http_buffer {
	gchar *hb_arena;				/**< The whole thing */
	gchar *hb_rptr;					/**< Reading pointer within arena */
	gchar *hb_end;					/**< First char after buffer */
	gint hb_len;					/**< Total arena length */
} http_buffer_t;

#define http_buffer_base(hb)		((hb)->hb_arena)
#define http_buffer_length(hb)		((hb)->hb_len)
#define http_buffer_read_base(hb)	((hb)->hb_rptr)
#define http_buffer_unread(hb)		((hb)->hb_end - (hb)->hb_rptr)

#define http_buffer_add_read(hb,tx)	do { (hb)->hb_rptr += (tx); } while (0)

/*
 * Public interface
 */

struct gnutella_socket;

void http_timer(time_t now);

gboolean http_send_status(struct gnutella_socket *s,
	gint code, gboolean keep_alive, http_extra_desc_t *hev, gint hevcnt,
	const gchar *reason, ...) G_GNUC_PRINTF(6, 7);

void http_hostname_add(
	gchar *buf, gint *retval, gpointer arg, guint32 flags);

gint http_status_parse(const gchar *line,
	const gchar *proto, const gchar **msg, guint *major, guint *minor);

gboolean http_extract_version(
	const gchar *request, size_t len, guint *major, guint *minor);

http_buffer_t *http_buffer_alloc(gchar *buf, size_t len, size_t written);
void http_buffer_free(http_buffer_t *b);

gint
http_content_range_parse(const gchar *buf,
		filesize_t *start, filesize_t *end, filesize_t *total);

filesize_t http_range_size(const GSList *list);
void http_range_free(GSList *list);
GSList *http_range_parse(const gchar *field, const gchar *value,
		filesize_t size, const gchar *vendor);
gboolean http_range_contains(GSList *ranges, filesize_t from, filesize_t to);

const gchar *http_url_strerror(http_url_error_t errnum);
gboolean http_url_parse(
	const gchar *url, guint16 *port, const gchar **host, const gchar **path);

gpointer http_async_get(
	gchar *url,
	http_header_cb_t header_ind,
	http_data_cb_t data_ind,
	http_error_cb_t error_ind);

gpointer http_async_get_addr(
	gchar *path,
	const host_addr_t,
	guint16 port,
	http_header_cb_t header_ind,
	http_data_cb_t data_ind,
	http_error_cb_t error_ind);

const gchar *http_async_strerror(guint errnum);
const gchar *http_async_info(
	gpointer handle, const gchar **req, gchar **path,
	host_addr_t *addr, guint16 *port);
void http_async_connected(gpointer handle);
void http_async_close(gpointer handle);
void http_async_cancel(gpointer handle);
void http_async_error(gpointer handle, gint code);
http_state_t http_async_state(gpointer handle);

void http_async_set_opaque(gpointer handle, gpointer data, http_user_free_t fn);
gpointer http_async_get_opaque(gpointer handle);
void http_async_log_error(gpointer handle, http_errtype_t type, gpointer v);
void http_async_log_error_dbg(
	gpointer handle, http_errtype_t type, gpointer v, guint32 dbg_level);

void http_async_on_state_change(gpointer handle, http_state_change_t fn);
void http_async_allow_redirects(gpointer handle, gboolean allow);
void http_async_set_op_request(gpointer handle, http_op_request_t op);

void http_close(void);

#endif	/* _core_http_h_ */

/* vi: set ts=4 sw=4 cindent: */
