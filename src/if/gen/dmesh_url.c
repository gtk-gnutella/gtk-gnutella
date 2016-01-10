/*
 * Generated on Sat Apr  5 13:38:59 2014 by enum-msg.pl -- DO NOT EDIT
 *
 * Command: ../../../scripts/enum-msg.pl dmesh_url.lst
 */

#include "common.h"

#include "dmesh_url.h"

#include "lib/str.h"
#include "lib/override.h"	/* Must be the last header included */

/*
 * English descriptions for dmesh_url_error_t.
 */
static const char *dmesh_url_error_str[] = {
	"OK",
	"HTTP parsing error",
	"File prefix neither /uri-res nor /get",
	"Index in /get/index is reserved",
	"No filename after /get/index",
	"Bad URL encoding",
	"Malformed /uri-res/N2R?",
};

/**
 * @return the English description of the enum value.
 */
const char *
dmesh_url_error_to_string(dmesh_url_error_t x)
{
	if G_UNLIKELY(UNSIGNED(x) >= N_ITEMS(dmesh_url_error_str)) {
		str_t *s = str_private(G_STRFUNC, 80);
		str_printf(s, "Invalid dmesh_url_error_t code: %d", (int) x);
		return str_2c(s);
	}

	return dmesh_url_error_str[x];
}

/* vi: set ts=4 sw=4 cindent: */
