/*
 * Generated on Sat Apr  5 13:38:59 2014 by enum-msg.pl -- DO NOT EDIT
 *
 * Command: ../../../scripts/enum-msg.pl dmesh_url.lst
 */

#ifndef _if_gen_dmesh_url_h_
#define _if_gen_dmesh_url_h_

/*
 * Enum count: 7
 */
typedef enum {
	DMESH_URL_OK = 0,
	DMESH_URL_HTTP_PARSER,
	DMESH_URL_BAD_FILE_PREFIX,
	DMESH_URL_RESERVED_INDEX,
	DMESH_URL_NO_FILENAME,
	DMESH_URL_BAD_ENCODING,
	DMESH_URL_BAD_URI_RES
} dmesh_url_error_t;

const char *dmesh_url_error_to_string(dmesh_url_error_t x);

#endif /* _if_gen_dmesh_url_h_ */

/* vi: set ts=4 sw=4 cindent: */
