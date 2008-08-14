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
long
sdbm_hash(const char *s, size_t len)
{
	unsigned long n = 0;

#define HASHC	n = (unsigned char) *s++ + 65599UL * n

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
