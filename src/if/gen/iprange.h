/*
 * Generated on Sat Apr 19 17:20:54 2014 by enum-msg.pl -- DO NOT EDIT
 *
 * Command: ../../../scripts/enum-msg.pl iprange.lst
 */

#ifndef _if_gen_iprange_h_
#define _if_gen_iprange_h_

/*
 * Enum count: 6
 */
typedef enum {
	IPR_ERR_OK = 0,
	IPR_ERR_BAD_PREFIX,
	IPR_ERR_RANGE_CLASH,
	IPR_ERR_RANGE_DUP,
	IPR_ERR_RANGE_SUBNET,
	IPR_ERR_RANGE_OVERLAP
} iprange_err_t;

const char *iprange_strerror(iprange_err_t x);

#endif /* _if_gen_iprange_h_ */

/* vi: set ts=4 sw=4 cindent: */
