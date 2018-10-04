/*
 * sdbm - ndbm work-alike hashed database library
 *
 * Database rebuilding.
 * author: Raphael Manfredi <Raphael_Manfredi@pobox.com>
 * status: public domain.
 *
 * @ingroup sdbm
 * @file
 * @author Raphael Manfredi
 * @date 2015
 */

#include "common.h"

#include "sdbm.h"
#include "tune.h"
#include "private.h"
#include "pair.h"

#include "lib/override.h"		/* Must be the last header included */

/**
 * Check page sanity.
 */
bool
sdbm_chkpage(const char *pag)
{
	unsigned n;
	unsigned off;
	const unsigned short *ino = INO(pag);

	/*
	 * This static assertion makes sure that the leading bit of the shorts
	 * used for storing offsets will always remain clear with the current
	 * DBM page size, so that it can safely be used as a marker to flag
	 * big keys/values.
	 */

	STATIC_ASSERT(DBM_PBLKSIZ < 0x8000);

	/*
	 * number of entries should be something reasonable,
	 * and all offsets in the index should be in order.
	 * this could be made more rigorous.
	 */

	if G_UNLIKELY((n = ino[0]) > INO_MAX)
		return FALSE;

	if G_UNLIKELY(n & 0x1)
		return FALSE;		/* Always a multiple of 2 */

	if (n > 0) {
		unsigned ino_end = (n + 1) * sizeof(unsigned short);
		off = DBM_PBLKSIZ;
		for (ino++; n > 0; ino += 2) {
			unsigned short koff = poffset(ino[0]);
			unsigned short voff = poffset(ino[1]);
			if G_UNLIKELY(koff > off || voff > off || voff > koff)
				return FALSE;
			if G_UNLIKELY(koff < ino_end || voff < ino_end)
				return FALSE;
			off = voff;
			n -= 2;
		}
	}
	return TRUE;
}

/* vi: set ts=4 sw=4 cindent: */
