/*
 * Copyright (c) 2002-2003, 2010, 2014 Raphael Manfredi
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
 * @date 2002-2003, 2010, 2014
 */

#ifndef _core_http_h_
#define _core_http_h_

#include "common.h"

#include "if/core/http.h"
#include "if/gen/http_async.h"
#include "if/gen/http_url.h"

#include "lib/host_addr.h"
#include "lib/header.h"

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
 * Type of option control operations.
 */
typedef enum {
	HTTP_CTL_ADD = 0,
	HTTP_CTL_REMOVE,
	HTTP_CTL_SET
} http_ctl_op_t;

/**
 * Available HTTP options.
 */
#define HTTP_O_READ_REPLY	(1 << 0)	/**< Read data for non-200 replies */
#define HTTP_O_REDIRECT		(1 << 1)	/**< Allow redirections */

/**
 * Free routine used to free POST data.
 *
 * @param p		the data to be freed
 * @param arg	additional argument for the free routine
 */
typedef void (*http_data_free_t)(void *p, void *arg);

/**
 * Post data.
 */
typedef struct http_post_data {
	const char *content_type;		/**< Content-Type header for data */
	char *data;						/**< The data to send */
	size_t datalen;					/**< Length of data to send */
	http_data_free_t data_free;		/**< Optional free routine for data */
	void *data_free_arg;			/**< Additional argument to free routine */
} http_post_data_t;

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
	char *buf, size_t size, void *arg, uint32 flags);

typedef struct {
	http_extra_type_t he_type;		/**< Union discriminent */
	union {
		const char *u_msg;			/**< Single header line */
		struct {
			http_status_cb_t u_cb;	/**< Callback to compute header field */
			void *u_arg;			/**< Callback context argument */
		} u_cbk;
	} u;
} http_extra_desc_t;

#define he_msg	u.u_msg
#define he_cb	u.u_cbk.u_cb
#define he_arg	u.u_cbk.u_arg

static inline void
http_extra_callback_set(http_extra_desc_t *he,
	http_status_cb_t callback, void *user_arg)
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

static inline bool
http_extra_callback_matches(http_extra_desc_t *he, http_status_cb_t callback)
{
	return he->he_type == HTTP_EXTRA_CALLBACK &&
		he->he_cb == callback;
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

typedef struct http_async http_async_t;

/**
 * Callback used from asynchronous request to indicate that we got headers.
 * Indicates whether we should continue or not, given the HTTP response code.
 */
typedef bool (*http_header_cb_t)(
	http_async_t *, struct header *, int code, const char *message);

/**
 * Callback used from asynchronous request to indicate that data is available.
 */
typedef void (*http_data_cb_t)(http_async_t *, char *data, int len);

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
			http_async_t *, http_errtype_t error, void *val);

/**
 * Callback to free user opaque data.
 */

typedef void (*http_user_free_t)(void *data);

/**
 * Asynchronous operations that the user may redefine.
 */

typedef size_t (*http_op_get_request_t)(const http_async_t *,
	char *buf, size_t len, const char *verb, const char *path);

typedef size_t (*http_op_post_request_t)(const http_async_t *,
	char *buf, size_t len, const char *verb, const char *path,
	const char *content_type, size_t content_len);

typedef void (*http_op_reqsent_t)(const http_async_t *,
	const struct gnutella_socket *s, const char *req, size_t len,
	bool deferred);

typedef void (*http_op_gotreply_t)(const http_async_t *,
	const struct gnutella_socket *s,
	const char *status, const struct header *header);

extern http_async_error_t http_async_errno;
extern http_url_error_t http_url_errno;

/**
 * Callback to notify about state changes in HTTP request.
 */

typedef void (*http_state_change_t)(http_async_t *, http_state_t newstate);

/**
 * HTTP data buffered when it cannot be sent out immediately.
 */

enum http_buffer_magic { HTTP_BUFFER_MAGIC = 0x5613d362U };

typedef struct http_buffer {
	enum http_buffer_magic magic;
	char *hb_arena;				/**< The whole thing */
	char *hb_rptr;				/**< Reading pointer within arena */
	char *hb_end;				/**< First char after buffer */
	int hb_len;					/**< Total arena length */
} http_buffer_t;

#define http_buffer_base(hb)		((hb)->hb_arena)
#define http_buffer_length(hb)		((hb)->hb_len)
#define http_buffer_read_base(hb)	((hb)->hb_rptr)
#define http_buffer_unread(hb)		((hb)->hb_end - (hb)->hb_rptr)

#define http_buffer_add_read(hb,tx)	do { (hb)->hb_rptr += (tx); } while (0)

static inline void
http_buffer_check(const http_buffer_t * const b)
{
	g_assert(b != NULL);
	g_assert(HTTP_BUFFER_MAGIC == b->magic);
}

/**
 * Callback used when http_async_wget() completes.
 *
 * @param data		the retrieved data, NULL on error, freed with hfree().
 * @param len		length of data returned (NOT the length of the data buffer)
 * @param code		HTTP status code
 * @param header	HTTP reply headers (may be NULL when data is NULL)
 * @param arg		additional user-supplied argument
 */
typedef void (*http_wget_cb_t)(
	char *data, size_t len, int code, header_t *header, void *arg);

/*
 * Public interface
 */

void http_timer(time_t now);

bool http_send_status(http_layer_t layer, struct gnutella_socket *s,
	int code, bool keep_alive, http_extra_desc_t *hev, int hevcnt,
	const char *reason, ...) G_PRINTF(7, 8);

size_t http_hostname_add(
	char *buf, size_t size, void *arg, uint32 flags);
size_t http_retry_after_add(
	char *buf, size_t size, void *arg, uint32 flags);

int http_status_parse(const char *line,
	const char *proto, const char **msg, uint *major, uint *minor);

bool http_extract_version(
	const char *request, size_t len, uint *major, uint *minor);

http_buffer_t *http_buffer_alloc(char *buf, size_t len, size_t written);
void http_buffer_free(http_buffer_t *b);

int
http_content_range_parse(const char *buf,
		filesize_t *start, filesize_t *end, filesize_t *total);

bool http_url_parse(
	const char *url, uint16 *port, const char **host, const char **path);

http_async_t *http_async_get(
	const char *url,
	http_header_cb_t header_ind,
	http_data_cb_t data_ind,
	http_error_cb_t error_ind);

http_async_t *http_async_get_addr(
	const char *path,
	const host_addr_t,
	uint16 port,
	http_header_cb_t header_ind,
	http_data_cb_t data_ind,
	http_error_cb_t error_ind);

http_async_t *http_async_post(
	const char *url,
	http_post_data_t *post_data,
	http_header_cb_t header_ind,
	http_data_cb_t data_ind,
	http_error_cb_t error_ind);

http_async_t *http_async_post_addr(
	const char *path,
	const host_addr_t addr,
	uint16 port,
	http_post_data_t *post_data,
	http_header_cb_t header_ind,
	http_data_cb_t data_ind,
	http_error_cb_t error_ind);

const char *http_async_info(
	const http_async_t *ha, const char **req, const char **path,
	host_addr_t *addr, uint16 *port);
const char *http_async_url(const http_async_t *ha);
const char *http_async_req(const http_async_t *ha);
const char *http_async_path(const http_async_t *ha);
host_addr_t http_async_addr(const http_async_t *ha);
uint16 http_async_port(const http_async_t *ha);

void http_async_close(http_async_t *handle);
void http_async_cancel(http_async_t *handle);
void http_async_cancel_null(http_async_t **handle_ptr);
void http_async_error(http_async_t *handle, int code);
http_state_t http_async_state(http_async_t *handle);

bool http_async_get_local_addr(const http_async_t *ha, host_addr_t *addrp);

void http_async_set_opaque(http_async_t *handle,
		void *data, http_user_free_t fn);
void *http_async_get_opaque(const http_async_t *handle);
bool http_async_log_error(http_async_t *handle,
		http_errtype_t type, void *v, const char *prefix);
bool http_async_log_error_dbg(http_async_t *handle,
		http_errtype_t type, void *v, const char *prefix, bool all);

void http_async_on_state_change(http_async_t *ha, http_state_change_t fn);
void http_async_set_op_get_request(http_async_t *, http_op_get_request_t);
void http_async_set_op_post_request(http_async_t *, http_op_post_request_t);
void http_async_set_op_headsent(http_async_t *ha, http_op_reqsent_t op);
void http_async_set_op_datasent(http_async_t *ha, http_op_reqsent_t op);
void http_async_set_op_gotreply(http_async_t *ha, http_op_gotreply_t op);
void http_async_option_ctl(http_async_t *ha, uint32 mask, http_ctl_op_t what);
const char *http_async_remote_host_port(const http_async_t *ha);

header_t *http_header_parse(const char *data, size_t len, int *code, char **msg,
	unsigned *major, unsigned *minor, const char **endptr);

char *http_field_starts_with(const char *buf,
	const char *token, bool sensitive);
const char *http_parameter_get(const char *field, const char *name);

http_async_t *http_async_wget(const char *url,
	size_t maxlen, http_wget_cb_t cb, void *arg);

void http_close(void);
void http_test(void);

#endif	/* _core_http_h_ */

/* vi: set ts=4 sw=4 cindent: */
