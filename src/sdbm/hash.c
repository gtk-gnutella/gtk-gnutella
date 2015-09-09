/*
 * sdbm - ndbm work-alike hashed database library
 * based on Per-Aake Larson's Dynamic Hashing algorithms. BIT 18 (1978).
 * author: oz@nexus.yorku.ca
 * status: public domain. keep it that way.
 *
 * hashing routine
 */

#include "common.h"

#include "sdbm.h"

/*
 * polynomial conversion ignoring overflows
 * [this seems to work remarkably well, in fact better
 * then the ndbm hash function. Replace at your own risk]
 * use: 65599	nice.
 *      65587   even better. 
 */
long G_GNUC_HOT
sdbm_hash(const char *s, size_t len)
{
	unsigned long n = 0;

	/*
	 * Noting that 65599 = 2^16 + 2^6 - 1, we could rewrite:
	 *
	 *     n = (uint8) *s++ + 65599UL * n
	 *
	 * as:
	 *
	 *     n = (uint8) *s++ + (n << 16) + (n << 6) - n;
	 *
	 * which is a much faster choice of operations since multiplication
	 * takes more CPU cycles than bit shifts and additions.
	 *
	 * However gcc is already smart enough to perform this optimization
	 * by itself, even when compiling with -O0, so we keep the multiplicative
	 * expression, as in the original code, leaving this low-level rewrite
	 * business to the compiler.
	 *		--RAM, 2015-04-30
	 */

#define HASHC	n = (uint8) *s++ + 65599UL * n

	if (len > 0) {
#ifdef DUFF
		size_t loop = (len + 8 - 1) >> 3;

		switch(len & (8 - 1)) {
		case 0:	do {
			HASHC;	case 7:	HASHC;
		case 6:	HASHC;	case 5:	HASHC;
		case 4:	HASHC;	case 3:	HASHC;
		case 2:	HASHC;	case 1:	HASHC;
			} while (--loop > 0);
		}

#else
		do {
			HASHC;
		} while (--len > 0);
#endif
	}
	return n;
}
