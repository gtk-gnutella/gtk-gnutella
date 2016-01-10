/*
 * Generated on Sat Apr  5 14:15:09 2014 by enum-msg.pl -- DO NOT EDIT
 *
 * Command: ../../../scripts/enum-msg.pl vxml.lst
 */

#include "common.h"

#include "vxml.h"

#include "lib/str.h"
#include "lib/override.h"	/* Must be the last header included */

/*
 * English descriptions for vxml_error_t.
 */
static const char *vxml_error_str[] = {
	"OK",
	"Unsupported byte order",
	"Unsupported character set",
	"Truncated input stream",
	"Expected a valid name start",
	"Invalid character reference",
	"Invalid Unicode character",
	"Invalid character in name",
	"Unknown entity reference",
	"Unexpected character",
	"Unexpected white space",
	"Bad character in name",
	"Invalid tag nesting",
	"Expected quote (\"'\" or '\"')",
	"Expected '>'",
	"Expected white space",
	"Expected '['",
	"Expected ']'",
	"Expected '--'",
	"Expected a DOCTYPE declaration",
	"Expected a declaration token",
	"Expected NDATA token",
	"Expected CDATA token",
	"Expected INCLUDE or IGNORE",
	"Was not expecting '<'",
	"Unexpected <?xml...?>",
	"Unexpected tag end",
	"Nested DOCTYPE declaration",
	"Invalid version number",
	"Version number out of range",
	"Unknown character encoding name",
	"Invalid character encoding name",
	"Reached illegal character byte sequence",
	"Input is unreadable in the specified encoding",
	"User-defined error",
	"Duplicate attribute",
	"Duplicate default namespace",
	"Bad character in namespace",
	"Invalid namespace redefinition",
	"Unknown namespace prefix",
	"Empty name",
	"I/O error",
	"Possible entity recursion",
};

/**
 * @return the English description of the enum value.
 */
const char *
vxml_strerror(vxml_error_t x)
{
	if G_UNLIKELY(UNSIGNED(x) >= N_ITEMS(vxml_error_str)) {
		str_t *s = str_private(G_STRFUNC, 80);
		str_printf(s, "Invalid vxml_error_t code: %d", (int) x);
		return str_2c(s);
	}

	return vxml_error_str[x];
}

/* vi: set ts=4 sw=4 cindent: */
