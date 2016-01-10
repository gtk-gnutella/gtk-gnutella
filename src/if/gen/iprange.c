/*
 * Generated on Sat Apr 19 17:20:54 2014 by enum-msg.pl -- DO NOT EDIT
 *
 * Command: ../../../scripts/enum-msg.pl iprange.lst
 */

#include "common.h"

#include "iprange.h"

#include "lib/str.h"
#include "lib/override.h"	/* Must be the last header included */

/*
 * English descriptions for iprange_err_t.
 */
static const char *iprange_error_str[] = {
	"OK",
	"Incorrect network prefix",
	"CIDR range clash",
	"Duplicate range",
	"Range is subnet of existing range",
	"Range is overlapping existing range",
};

/**
 * @return the English description of the enum value.
 */
const char *
iprange_strerror(iprange_err_t x)
{
	if G_UNLIKELY(UNSIGNED(x) >= N_ITEMS(iprange_error_str)) {
		str_t *s = str_private(G_STRFUNC, 80);
		str_printf(s, "Invalid iprange_err_t code: %d", (int) x);
		return str_2c(s);
	}

	return iprange_error_str[x];
}

/* vi: set ts=4 sw=4 cindent: */
