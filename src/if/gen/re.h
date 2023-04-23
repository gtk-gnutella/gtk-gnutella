/*
 * Generated on Sun Apr 23 09:28:25 2023 by enum-msg.pl -- DO NOT EDIT
 *
 * Command: ../../../scripts/enum-msg.pl re.lst
 */

#ifndef _if_gen_re_h_
#define _if_gen_re_h_

/*
 * Enum count: 25
 */
typedef enum {
	RE_E_OK = 0,
	RE_E_ERROR,
	RE_E_INCOMPLETE_ESCAPE,
	RE_E_INCOMPLETE_CHAR_CLASS,
	RE_E_INVALID_CHAR_CLASS_RANGE,
	RE_E_BAD_CHAR_CLASS_RANGE,
	RE_E_UNKNOWN_POSIX_CLASS,
	RE_E_CHAR_CLASS_CANNOT_MATCH,
	RE_E_INVALID_HEXA_DIGIT,
	RE_E_INVALID_OCTAL_DIGIT,
	RE_E_UNPARSEABLE_NUMBER,
	RE_E_NUMBER_OUT_OF_RANGE,
	RE_E_ORPHAN_REPETITION,
	RE_E_INCOMPLETE_REPEAT_RANGE,
	RE_E_INCONSISTENT_RANGE,
	RE_E_EXPECTED_CLOSING_BRACE,
	RE_E_CANNOT_ALTER_ONCE_MATCH,
	RE_E_NULL_REPETITION,
	RE_E_INCOMPLETE_GROUP,
	RE_E_GROUP_CAPTURE_NEEDED,
	RE_E_UNKNOWN_GROUP_REF,
	RE_E_UNKNOWN_GROUP_TYPE,
	RE_E_NO_REPEAT_ON_LOOK_AHEAD,
	RE_E_END_SEEN,
	RE_E_LATE_START
} re_error_code_t;

const char *re_symbolic_error(re_error_code_t x);

const char *re_strerror(re_error_code_t x);

#endif /* _if_gen_re_h_ */

/* vi: set ts=4 sw=4 cindent: */
