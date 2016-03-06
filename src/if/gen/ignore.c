/*
 * Generated on Sat Apr  5 13:52:34 2014 by enum-msg.pl -- DO NOT EDIT
 *
 * Command: ../../../scripts/enum-msg.pl ignore.lst
 */

#include "common.h"

#include "ignore.h"

#include "lib/str.h"
#include "lib/override.h"	/* Must be the last header included */

/*
 * English descriptions for ignore_val_t.
 */
static const char *ignore_val_str[] = {
	"Not ignored",
	"SHA1",
	"Name & Size",
	"Already owned",
	"Hostile IP",
	"Points to ourselves",
	"Country limit",
	"Known spam",
};

/**
 * @return the English description of the enum value.
 */
const char *
ignore_reason_to_string(ignore_val_t x)
{
	if G_UNLIKELY(UNSIGNED(x) >= N_ITEMS(ignore_val_str)) {
		str_t *s = str_private(G_STRFUNC, 80);
		str_printf(s, "Invalid ignore_val_t code: %d", (int) x);
		return str_2c(s);
	}

	return ignore_val_str[x];
}

/* vi: set ts=4 sw=4 cindent: */
