/*
 * Generated on Sat Apr  5 12:17:58 2014 by enum-msg.pl -- DO NOT EDIT
 *
 * Command: ../../../scripts/enum-msg.pl http_async.lst
 */

#include "common.h"

#include "http_async.h"

#include "lib/str.h"
#include "lib/override.h"	/* Must be the last header included */

/*
 * English descriptions for http_async_error_t.
 */
static const char *http_async_error_str[] = {
	"OK",
	"Invalid HTTP URL",
	"Connection failed",
	"I/O error",
	"Request too large",
	"Header too large",
	"User cancel",
	"Got EOF",
	"Unparseable HTTP status",
	"Got moved status",
	"Connection timeout",
	"Data timeout",
	"Nested redirection",
	"Invalid URI in Location header",
	"Connection was closed",
	"Redirected",
	"Unparseable header value",
	"Data too large",
	"Mandatory request not understood",
};

/**
 * @return the English description of the enum value.
 */
const char *
http_async_strerror(http_async_error_t x)
{
	if G_UNLIKELY(UNSIGNED(x) >= G_N_ELEMENTS(http_async_error_str)) {
		str_t *s = str_private(G_STRFUNC, 80);
		str_printf(s, "Invalid http_async_error_t code: %d", (int) x);
		return str_2c(s);
	}

	return http_async_error_str[x];
}

/* vi: set ts=4 sw=4 cindent: */
