/*
 * Generated on Sat Apr  5 12:17:58 2014 by enum-msg.pl -- DO NOT EDIT
 *
 * Command: ../../../scripts/enum-msg.pl http_async.lst
 */

#ifndef _if_gen_http_async_h_
#define _if_gen_http_async_h_

/*
 * Enum count: 19
 */
typedef enum {
	HTTP_ASYNC_OK = 0,
	HTTP_ASYNC_BAD_URL,
	HTTP_ASYNC_CONN_FAILED,
	HTTP_ASYNC_IO_ERROR,
	HTTP_ASYNC_REQ2BIG,
	HTTP_ASYNC_HEAD2BIG,
	HTTP_ASYNC_CANCELLED,
	HTTP_ASYNC_EOF,
	HTTP_ASYNC_BAD_STATUS,
	HTTP_ASYNC_NO_LOCATION,
	HTTP_ASYNC_CONN_TIMEOUT,
	HTTP_ASYNC_TIMEOUT,
	HTTP_ASYNC_NESTED,
	HTTP_ASYNC_BAD_LOCATION_URI,
	HTTP_ASYNC_CLOSED,
	HTTP_ASYNC_REDIRECTED,
	HTTP_ASYNC_BAD_HEADER,
	HTTP_ASYNC_DATA2BIG,
	HTTP_ASYNC_MAN_FAILURE
} http_async_error_t;

const char *http_async_strerror(http_async_error_t x);

#endif /* _if_gen_http_async_h_ */

/* vi: set ts=4 sw=4 cindent: */
