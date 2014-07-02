/*
 * Generated on Sat Apr  5 13:52:34 2014 by enum-msg.pl -- DO NOT EDIT
 *
 * Command: ../../../scripts/enum-msg.pl ignore.lst
 */

#ifndef _if_gen_ignore_h_
#define _if_gen_ignore_h_

/*
 * Enum count: 8
 */
typedef enum {
	IGNORE_FALSE = 0,
	IGNORE_SHA1,
	IGNORE_NAMESIZE,
	IGNORE_LIBRARY,
	IGNORE_HOSTILE,
	IGNORE_OURSELVES,
	IGNORE_LIMIT,
	IGNORE_SPAM
} ignore_val_t;

const char *ignore_reason_to_string(ignore_val_t x);

#endif /* _if_gen_ignore_h_ */

/* vi: set ts=4 sw=4 cindent: */
