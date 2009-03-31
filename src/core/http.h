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

#include "common.h"

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
 * http_send_status() layer description (for tracing purposes):
 */

typedef enum {
	HTTP_PUSH_PROXY,
	HTTP_UPLOAD,
	HTTP_OTHER
} http_layer_t;

/**
 * The callback used to generate custom headers.
 *
 * @param `buf' is where the callback can generate extra data.
 * @param `size' is the size of buf in bytes.
 * @param `arg' is user-supplied data.
 * @param `flags' are extra flags passed by callback invoker
 *
 * The callback is expected to fill `buf' and return the amount of bytes
 * written to buf.
 */
typedef size_t (*http_status_cb_t)(
	char *buf, size_t size, gpointer arg, guint32 flags);

typedef struct {
	http_extra_type_t he_type;		/**< Union discriminent */
	union {
		const char *u_msg;			/**< Single header line */
		struct {
			http_status_cb_t u_cb;	/**< Callback to compute header field */
			gpointer u_arg;			/**< Callback context argument */
		} u_cbk;
	} u;
} http_extra_desc_t;

#define he_msg	u.u_msg
#define he_cb	u.u_cbk.u_cb
#define he_arg	u.u_cbk.u_arg

static inline void
http_extra_callback_set(http_extra_desc_t *he,
	http_status_cb_t callback, gpointer user_arg)
{
	he->he_type = HTTP_EXTRA_CALLBACK;
	he->he_cb = callback;
	he->he_arg = user_arg;
}

static inline void
http_extra_line_set(http_extra_desc_t *he, const char *msg)
{
	he->he_type = HTTP_EXTRA_LINE;
	he->he_msg = msg;
}

static inline void
http_extra_body_set(http_extra_desc_t *he, const char *body)
{
	he->he_type = HTTP_EXTRA_BODY;
	he->he_msg = body;
}

static inline gboolean
http_extra_callback_matches(http_extra_desc_t *he,
	http_status_cb_t callback, gpointer user_arg)
{
	return he->he_type == HTTP_EXTRA_CALLBACK &&
		he->he_cb == callback &&
		he->he_arg == user_arg;
}

/*
 * Flags used during callback invocation.
 */

#define HTTP_CBF_SMALL_REPLY	(1 << 0)	/**< Try to emit smallest reply */
#define HTTP_CBF_BW_SATURATED	(1 << 1)	/**< Bandwidth is saturated */
#define HTTP_CBF_BUSY_SIGNAL	(1 << 2)	/**< Sending back a 503 "busy" */
#define HTTP_CBF_SHOW_RANGES	(1 << 3)	/**< Show available ranges */

struct header;
struct http_async;
struct gnutella_socket;

/**
 * Callback used from asynchronous request to indicate that we got headers.
 * Indicates whether we should continue or not, given the HTTP response code.
 */
typedef gboolean (*http_header_cb_t)(
	struct http_async *, struct header *, int code, const char *message);

/**
 * Callback used from asynchronous request to indicate that data is available.
 */
typedef void (*http_data_cb_t)(struct http_async *, char *data, int len);

typedef enum {				/**< Type of error reported by http_error_cb_t */
	HTTP_ASYNC_SYSERR,		/**< System error, value is errno */
	HTTP_ASYNC_ERROR,		/**< Internal error, value is error code */
	HTTP_ASYNC_HEADER,		/**< Internal header error, value is error code */
	HTTP_ASYNC_HTTP			/**< HTTP error, value is http_error_t pointer */
} http_errtype_t;

typedef struct {
	struct header *header;	/**< Parsed HTTP header */
	const char *message;	/**< HTTP status message */
	int code;				/**< HTTP status code */
} http_error_t;

/**
 * Callback used from asynchronous request to indicate that an error occurred.
 * The type of `val' depends on the `error'.
 */

typedef void (*http_error_cb_t)(
			struct http_async *, http_errtype_t error, gpointer val);

/**
 * Callback to free user opaque data.
 */

typedef void (*http_user_free_t)(gpointer data);

/**
 * Asynchronous operations that the user may redefine.
 */

typedef size_t (*http_op_request_t)(const struct http_async *,
	char *buf, size_t len, const char *verb, const char *path);

typedef void (*http_op_reqsent_t)(const struct http_async *,
	const struct gnutella_socket *s, const char *req, size_t len,
	gboolean deferred);

typedef void (*http_op_gotreply_t)(const struct http_async *,
	const struct gnutella_socket *s,
	const char *status, const struct header *header);

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

typedef void (*http_state_change_t)(struct http_async *, http_state_t newstate);

/**
 * HTTP data buffered when it cannot be sent out immediately.
 */

typedef struct http_buffer {
	char *hb_arena;				/**< The whole thing */
	char *hb_rptr;					/**< Reading pointer within arena */
	char *hb_end;					/**< First char after buffer */
	int hb_len;					/**< Total arena length */
} http_buffer_t;

#define http_buffer_base(hb)		((hb)->hb_arena)
#define http_buffer_length(hb)		((hb)->hb_len)
#define http_buffer_read_base(hb)	((hb)->hb_rptr)
#define http_buffer_unread(hb)		((hb)->hb_end - (hb)->hb_rptr)

#define http_buffer_add_read(hb,tx)	do { (hb)->hb_rptr += (tx); } while (0)

/*
 * Public interface
 */

void http_timer(time_t now);

gboolean http_send_status(http_layer_t layer, struct gnutella_socket *s,
	int code, gboolean keep_alive, http_extra_desc_t *hev, int hevcnt,
	const char *reason, ...) G_GNUC_PRINTF(7, 8);

size_t http_hostname_add(
	char *buf, size_t size, gpointer arg, guint32 flags);
size_t http_retry_after_add(
	char *buf, size_t size, gpointer arg, guint32 flags);

int http_status_parse(const char *line,
	const char *proto, const char **msg, guint *major, guint *minor);

gboolean http_extract_version(
	const char *request, size_t len, guint *major, guint *minor);

http_buffer_t *http_buffer_alloc(char *buf, size_t len, size_t written);
void http_buffer_free(http_buffer_t *b);

int
http_content_range_parse(const char *buf,
		filesize_t *start, filesize_t *end, filesize_t *total);

filesize_t http_range_size(const GSList *list);
void http_range_free(GSList *list);
GSList *http_range_parse(const char *field, const char *value,
		filesize_t size, const char *vendor);
gboolean http_range_contains(GSList *ranges, filesize_t from, filesize_t to);

const char *http_url_strerror(http_url_error_t errnum);
gboolean http_url_parse(
	const char *url, guint16 *port, const char **host, const char **path);

struct http_async *http_async_get(
	const char *url,
	http_header_cb_t header_ind,
	http_data_cb_t data_ind,
	http_error_cb_t error_ind);

struct http_async *http_async_get_addr(
	const char *path,
	const host_addr_t,
	guint16 port,
	http_header_cb_t header_ind,
	http_data_cb_t data_ind,
	http_error_cb_t error_ind);

const char *http_async_strerror(guint errnum);
const char *http_async_info(
	struct http_async *handle, const char **req, const char **path,
	host_addr_t *addr, guint16 *port);
void http_async_connected(struct http_async *handle);
void http_async_close(struct http_async *handle);
void http_async_cancel(struct http_async *handle);
void http_async_error(struct http_async *handle, int code);
http_state_t http_async_state(struct http_async *handle);

void http_async_set_opaque(struct http_async *handle,
		gpointer data, http_user_free_t fn);
gpointer http_async_get_opaque(struct http_async *handle);
void http_async_log_error(struct http_async *handle,
		http_errtype_t type, gpointer v);
void http_async_log_error_dbg(struct http_async *handle,
		http_errtype_t type, gpointer v, guint32 dbg_level);

void http_async_on_state_change(struct http_async *ha, http_state_change_t fn);
void http_async_allow_redirects(struct http_async *ha, gboolean allow);
void http_async_set_op_request(struct http_async *ha, http_op_request_t op);
void http_async_set_op_reqsent(struct http_async *ha, http_op_reqsent_t op);
void http_async_set_op_gotreply(struct http_async *ha, http_op_gotreply_t op);
const char *http_async_remote_host_port(const struct http_async *ha);

void http_close(void);

#endif	/* _core_http_h_ */

/* vi: set ts=4 sw=4 cindent: */
