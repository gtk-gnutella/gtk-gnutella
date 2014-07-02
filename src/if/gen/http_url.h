/*
 * Generated on Sat Apr  5 12:40:52 2014 by enum-msg.pl -- DO NOT EDIT
 *
 * Command: ../../../scripts/enum-msg.pl http_url.lst
 */

#ifndef _if_gen_http_url_h_
#define _if_gen_http_url_h_

/*
 * Enum count: 9
 */
typedef enum {
	HTTP_URL_OK = 0,
	HTTP_URL_NOT_HTTP,
	HTTP_URL_MULTIPLE_CREDENTIALS,
	HTTP_URL_BAD_CREDENTIALS,
	HTTP_URL_BAD_PORT_PARSING,
	HTTP_URL_BAD_PORT_RANGE,
	HTTP_URL_BAD_HOST_PART,
	HTTP_URL_HOSTNAME_UNKNOWN,
	HTTP_URL_MISSING_URI
} http_url_error_t;

const char *http_url_strerror(http_url_error_t x);

#endif /* _if_gen_http_url_h_ */

/* vi: set ts=4 sw=4 cindent: */
