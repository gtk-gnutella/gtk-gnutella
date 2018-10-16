/*
 * Generated on Thu Jul 23 14:44:45 2020 by enum-msg.pl -- DO NOT EDIT
 *
 * Command: ../../../scripts/enum-msg.pl re.lst
 */

#include "common.h"

#include "re.h"

#include "lib/str.h"
#include "lib/override.h"	/* Must be the last header included */

/*
 * Symbolic descriptions for re_error_code_t.
 */
static const char *re_error_names[] = {
	"OK",
	"ERROR",
	"INCOMPLETE_ESCAPE",
	"INCOMPLETE_CHAR_CLASS",
	"INVALID_CHAR_CLASS_RANGE",
	"BAD_CHAR_CLASS_RANGE",
	"UNKNOWN_POSIX_CLASS",
	"CHAR_CLASS_CANNOT_MATCH",
	"INVALID_HEXA_DIGIT",
	"UNPARSEABLE_NUMBER",
	"NUMBER_OUT_OF_RANGE",
	"ORPHAN_REPETITION",
	"INCOMPLETE_REPEAT_RANGE",
	"INCONSISTENT_RANGE",
	"EXPECTED_CLOSING_BRACE",
	"CANNOT_ALTER_ONCE_MATCH",
	"NULL_REPETITION",
	"INCOMPLETE_GROUP",
	"GROUP_CAPTURE_NEEDED",
	"UNKNOWN_GROUP_REF",
	"UNKNOWN_GROUP_TYPE",
	"NO_REPEAT_ON_LOOK_AHEAD",
	"END_SEEN",
	"LATE_START",
};

/**
 * @return the symbolic description of the enum value.
 */
const char *
re_symbolic_error(re_error_code_t x)
{
	if G_UNLIKELY(UNSIGNED(x) >= N_ITEMS(re_error_names)) {
		str_t *s = str_private(G_STRFUNC, 80);
		str_printf(s, "Invalid re_error_code_t code: %d", (int) x);
		return str_2c(s);
	}

	return re_error_names[x];
}

/*
 * English descriptions for re_error_code_t.
 */
static const char *re_error_code_str[] = {
	"OK",
	"Generic catch-all error",
	"Incomplete escape sequence",
	"Incomplete character class definition",
	"Invalid character class range",
	"Bad character class range",
	"Unknown POSIX class name",
	"Character class cannot match anything",
	"Invalid hexadecimal digit",
	"Cannot parse number",
	"Number out of range",
	"Orphan repetition, not applicable to anything",
	"Incomplete repeat range definition",
	"Inconsistent repeat range",
	"Was expecting a '}' to close sequence",
	"Cannot alter greediness / atomicity of once match",
	"Repetition count cannot be zero",
	"Incomplete group",
	"Needs group capture when using back-references",
	"Reference to an unknown capturing group",
	"Unknown group type after leading '(?' sequence",
	"Cannot use repetitions on look-ahead assertions",
	"No character can follow a '$' end anchor",
	"Start anchor '^' can only be given at the start",
};

/**
 * @return the English description of the enum value.
 */
const char *
re_strerror(re_error_code_t x)
{
	if G_UNLIKELY(UNSIGNED(x) >= N_ITEMS(re_error_code_str)) {
		str_t *s = str_private(G_STRFUNC, 80);
		str_printf(s, "Invalid re_error_code_t code: %d", (int) x);
		return str_2c(s);
	}

	return re_error_code_str[x];
}

/* vi: set ts=4 sw=4 cindent: */
