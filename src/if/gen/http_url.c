/*
 * Generated on Sat Apr  5 12:40:52 2014 by enum-msg.pl -- DO NOT EDIT
 *
 * Command: ../../../scripts/enum-msg.pl http_url.lst
 */

#include "common.h"

#include "http_url.h"

#include "lib/str.h"
#include "lib/override.h"	/* Must be the last header included */

/*
 * English descriptions for http_url_error_t.
 */
static const char *http_url_error_str[] = {
	"OK",
	"Not an http URI",
	"More than one <user>:<password>",
	"Truncated <user>:<password>",
	"Could not parse port",
	"Port value is out of range",
	"Could not parse host",
	"Could not resolve host into IP",
	"URL has no URI part",
};

/**
 * @return the English description of the enum value.
 */
const char *
http_url_strerror(http_url_error_t x)
{
	if G_UNLIKELY(UNSIGNED(x) >= G_N_ELEMENTS(http_url_error_str)) {
		str_t *s = str_private(G_STRFUNC, 80);
		str_printf(s, "Invalid http_url_error_t code: %d", (int) x);
		return str_2c(s);
	}

	return http_url_error_str[x];
}

/* vi: set ts=4 sw=4 cindent: */
