/*
 * $Id$
 *
 * Copyright (c) 2002-2003, Raphael Manfredi
 *
 * Consistant Overhead Byte Stuffing (COBS).
 *
 * COBS is an escaping algorithm, taking input in the [0,255] range and
 * producing output in the [1,255] range.  In other words, it escapes all
 * NUL bytes.
 *
 *----------------------------------------------------------------------
 * This file is part of gtk-gnutella.
 *
 *  gtk-gnutella is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  gtk-gnutella is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with gtk-gnutella; if not, write to the Free Software
 *  Foundation, Inc.:
 *      59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *----------------------------------------------------------------------
 */

#include "common.h"			/* Needed for -DUSE_DMALLOC and <string.h> */

#include <sys/types.h>		/* FreeBSD requires this before <sys/uio.h> */
#include <sys/uio.h>		/* For struct iovec */

#include <glib.h>

#include "cobs.h"
#include "override.h"		/* Must be the last header included */

RCSID("$Id$");

/*
 * cobs_encodev
 *
 * Encode vector `iov' of `iovcnt' elements, whose size is held in `retlen'.
 * Returns the new encoded buffer, and its length in `retlen'.
 *
 * NB: the output is a linear buffer, not a vector.
 */
gchar *cobs_encodev(struct iovec *iov, gint iovcnt, gint *retlen)
{
	gint maxsize;
	gchar *out;
	gchar *o;						/* Iterates over output */
	gchar *cp;						/* Where we'll write the code length */
	gint code;
	gint last_code = 0;
	gint len;
	gint i;
	struct iovec *xiov;

	g_assert(iov);
	g_assert(iovcnt > 0);
	g_assert(retlen);

	/*
	 * We can estimate the maximum overhead output as being (len/254 + 1)
	 * since there is at most 1 overhead byte for every 254 bytes of input.
	 * Note that when there are NUL bytes in the input, the size of the
	 * final encoded data can be smaller than that.
	 */

	len = *retlen;
	maxsize = len + (len / 254) + 1;
	o = out = g_malloc(maxsize);

	/*
	 * The following was adapted from the Listing 1, in the COBS paper.
	 */
	
	code = 0x1;
	cp = o++;

#define FINISH(x) do {			\
	*cp = last_code = (x);		\
	cp = o++;					\
	code = 0x1;					\
} while (0)

	for (i = iovcnt, xiov = iov; i--; xiov++) {
		const gchar *p = xiov->iov_base;		/* Iterates over buffer */
		const gchar *end = p + xiov->iov_len;	/* First byte off buffer */

		while (p < end) {
			const gchar c = *p++;
			if (c == 0)
				FINISH(code);
			else {
				*o++ = c;
				code++;					/* One more non-NUL byte */
				if (code == 0xff)
					FINISH(code);
			}
		}
	}

	/*
	 * If `last_code' is 0xff, then optimize: we don't need to finish.
	 * Decoder will detect this condition and know there was no need for
	 * the trailing logical NUL.
	 */

	if (last_code != 0xff)
		FINISH(code);

#undef FINISH

	g_assert(cp - out <= maxsize);	/* We did not overflow */

	*retlen = cp - out;

	return out;
}

/*
 * cobs_encode
 *
 * Encode `len' bytes starting at `buf' into new allocated buffer.
 * Returns the new encoded buffer, and its length in `retlen'.
 */
gchar *cobs_encode(gchar *buf, gint len, gint *retlen)
{
	struct iovec iov;

	iov.iov_base = buf;
	iov.iov_len = len;
	*retlen = len;

	return cobs_encodev(&iov, 1, retlen);
}

/*
 * cobs_decode_into
 *
 * Decode `len' bytes starting at `buf' into decoding buffer `out', which
 * is `outlen' bytes long.
 *
 * Returns whether the input was valid COBS encoding.
 * The length of the decoded buffer is returned in `retlen'.
 */
gboolean cobs_decode_into(
	gchar *buf, gint len, gchar *out, gint outlen, gint *retlen)
{
	const gchar *end = buf + len;		/* First byte off buffer */
	const gchar *oend = out + outlen;	/* First byte off buffer */
	gchar *p;
	gchar *o;
	gint last_code = 0;

	g_assert(len > 0);
	g_assert(outlen > 0);		/* Must be large enough */

	/*
	 * The following was adapted from the Listing 2, in the COBS paper.
	 */
	
	for (p = buf, o = out; p < end && o < oend; /* empty */) {
		gint i;
		gint code;

		last_code = code = (guchar) *p++;

		if (code == 0)
			return FALSE;			/* There cannot by any NUL */

		for (i = 1; i < code && p < end && o < oend; i++)
			*o++ = *p++;

		if (i < code)
			return FALSE;			/* Reached end of some buffer in loop */

		if (code < 0xFF) {
			if (o < oend)
				*o++ = '\0';
			else
				return FALSE;		/* Reached end of output buffer! */
		}
	}

	/*
	 * If last code was 0xFF, there is no trailing NUL to strip out.
	 */

	g_assert(last_code != 0);		/* We at least entered the loop once! */

	if (last_code != 0xFF)
		*retlen = (o - out) - 1;
	else
		*retlen = o - out;

	g_assert(*retlen <= outlen);

	return TRUE;					/* Valid COBS encoding */
}

/*
 * cobs_decode
 *
 * Decode `len' bytes starting at `buf' into new allocated buffer, unless
 * `inplace' is true in which case decoding is done inplace.
 *
 * Returns the new decoded buffer, or NULL if the input was not valid COBS
 * encoding.  The length of the decoded buffer is in `retlen'.
 */
gchar *cobs_decode(gchar *buf, gint len, gint *retlen, gboolean inplace)
{
	gchar *out;

	g_assert(len > 0);

	if (inplace)
		out = buf;
	else
		out = g_malloc(len);		/* Too large, but slightly */

	if (cobs_decode_into(buf, len, out, len, retlen))
		return out;

	if (!inplace)
		g_free(out);

	return NULL;
}

