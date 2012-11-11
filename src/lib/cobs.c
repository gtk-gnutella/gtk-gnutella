/*
 * Copyright (c) 2002-2004, Raphael Manfredi
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

/**
 * @ingroup lib
 * @file
 *
 * Consistant Overhead Byte Stuffing (COBS).
 *
 * COBS is an escaping algorithm, taking input in the [0,255] range and
 * producing output in the [1,255] range.  In other words, it escapes all
 * NUL bytes.
 *
 * @author Raphael Manfredi
 * @date 2002-2004
 */

#include "common.h"

#include "cobs.h"
#include "walloc.h"
#include "override.h"		/* Must be the last header included */

/**
 * Encode vector `iov' of `iovcnt' elements, whose size is held in `retlen'.
 *
 * @returns the new encoded buffer, and its length in `retlen'.
 *
 * @attention
 * NB: the output is a linear buffer, not a vector.
 */
char *
cobs_encodev(iovec_t *iov, int iovcnt, size_t *retlen)
{
	size_t maxsize, len;
	char *out;
	char *o;						/* Iterates over output */
	char *cp;						/* Where we'll write the code length */
	uchar code, last_code = 0;
	iovec_t *xiov;
	int i;

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
		const char *p = iovec_base(xiov);		/* Iterates over buffer */
		const char *end = &p[iovec_len(xiov)];	/* First byte off buffer */

		while (p != end) {
			const char c = *p++;
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
	 * If `last_code' is 0xff, then optimize: we don't need to finish if
	 * no data was written after we emitted it.
	 * Decoder will detect this condition and know there was no need for
	 * the trailing logical NUL.
	 */

	if (last_code != 0xff || code != 0x1)
		FINISH(code);

#undef FINISH

	g_assert((size_t) (cp - out) <= maxsize);	/* We did not overflow */

	*retlen = cp - out;

	return out;
}

/**
 * Encode `len' bytes starting at `buf' into new allocated buffer.
 *
 * @returns the new encoded buffer, and its length in `retlen'.
 */
char *
cobs_encode(char *buf, size_t len, size_t *retlen)
{
	iovec_t iov;

	iovec_set(&iov, buf, len);
	*retlen = len;

	return cobs_encodev(&iov, 1, retlen);
}

/**
 * Decode `len' bytes starting at `buf' into decoding buffer `out', which
 * is `outlen' bytes long.
 *
 * @returns whether the input was valid COBS encoding.
 * The length of the decoded buffer is returned in `retlen'.
 */
bool
cobs_decode_into(const char *buf, size_t len, char *out,
	size_t outlen, size_t *retlen)
{
	const char *end = &buf[len];		/* First byte off buffer */
	const char *oend = &out[outlen];	/* First byte off buffer */
	const char *p;
	char *o;
	uchar last_code = 0;

	g_assert(NULL != buf);
	g_assert(len > 0);
	g_assert(NULL != out);
	g_assert(outlen > 0);			/* Must be large enough */
	g_assert(NULL != retlen);

	/*
	 * The following was adapted from the Listing 2, in the COBS paper.
	 */

	for (p = buf, o = out; p != end && o != oend; /* empty */) {
		uchar code;

		last_code = code = *p++;

		if (0 == code)
			return FALSE;			/* There cannot be any NUL */

		code--;
		if (code > end - p || code > oend - o)
			return FALSE;			/* Reached end of some buffer */

		while (code-- > 0) {
			if (0 == (*o++ = *p++))
				return FALSE;		/* There must not be any NUL */
		}

		if (last_code < 0xFF) {
			if (o != oend)
				*o++ = '\0';
			else
				return FALSE;		/* Reached end of output buffer! */
		}
	}

	/*
	 * If last code was 0xFF, there is no trailing NUL to strip out.
	 */

	g_assert(last_code != 0);		/* We at least entered the loop once! */

	/* The last trailing NUL is stripped from data */
	if (0xFF != last_code)
		o--;

	*retlen = o - out;

	g_assert(*retlen <= outlen);

	return TRUE;					/* Valid COBS encoding */
}

/**
 * Check whether supplied buffer forms a valid COBS encoding.
 */
bool
cobs_is_valid(const char *buf, size_t len)
{
	const char *p, *end = &buf[len];		/* First byte off buffer */

	g_assert(NULL != buf);
	g_assert(len > 0);

	for (p = buf; p != end; /* empty */) {
		uchar code;

		if (0 == (code = *p++))
			return FALSE;			/* There cannot be any NUL */

		if (--code > end - p)
			return FALSE;			/* Not enough bytes in buffer */

		while (code-- > 0) {
			if (0 == *p++)
				return FALSE; /* There must not be any NUL */
		}
	}

	return TRUE;					/* Valid COBS encoding */
}

/**
 * Decode `len' bytes starting at `buf' into new allocated buffer, unless
 * `inplace' is true in which case decoding is done inplace.
 *
 * @returns the new decoded buffer, or NULL if the input was not valid COBS
 * encoding.  The length of the decoded buffer is in `retlen'.
 */
char *
cobs_decode(char *buf, size_t len, size_t *retlen, bool inplace)
{
	char *out;

	g_assert(NULL != buf);
	g_assert(len > 0);
	g_assert(NULL != retlen);

	if (inplace)
		out = buf;
	else
		out = g_malloc(len);		/* Too large, but slightly */

	if (cobs_decode_into(buf, len, out, len, retlen))
		return out;

	if (!inplace) {
		G_FREE_NULL(out);
	}
	return NULL;
}

/***
 *** Streaming interface.
 ***/

/**
 * Initialize an incremental COBS context, where data will be written in the
 * supplied buffer.
 *
 * @param cs		the COBS stream to initialize.
 * @param data		start of buffer where data will be written
 * @param len		length of supplied buffer
 */
void
cobs_stream_init(cobs_stream_t *cs, void *data, size_t len)
{
	g_assert(len != 0);
	g_assert(data != NULL);

	cs->magic = COBS_MAGIC;
	cs->o = cs->outbuf = data;
	cs->end = &cs->outbuf[len];
	cs->cp = cs->o++;
	cs->code = 0x1;
	cs->last_code = 0;
	cs->saw_nul = FALSE;
	cs->closed = FALSE;

	if (len < 2)
		cs->closed = TRUE;	/* Too short to write anything */

	g_assert(cobs_stream_is_valid(cs));
}

/**
 * Add data to the COBS stream.
 *
 * @return TRUE if OK, FALSE if we cannot put the data any more.
 */
bool
cobs_stream_write(cobs_stream_t *cs, void *data, size_t len)
{
	char *p = data;
	const char *end = &p[len];

	g_assert(cobs_stream_is_valid(cs));

	if (cs->closed)
		return FALSE;	/* Stream closed */

#define FINISH() do {					\
	g_assert(cs->cp < cs->end);			\
	*cs->cp = cs->last_code = cs->code;	\
	cs->cp = cs->o++;					\
	cs->code = 0x1;						\
} while (0)

	while (p != end) {
		const char c = *p++;
		if (cs->cp >= cs->end)
			return FALSE;
		if (c == 0) {
			cs->saw_nul = TRUE;
			FINISH();
		} else {
			if (cs->o >= cs->end)
				return FALSE;
			*(cs->o++) = c;
			cs->code++;				/* One more non-NUL byte */
			if (0xff == cs->code)
				FINISH();
		}
	}

#undef FINISH

	return TRUE;
}

/**
 * Close COBS stream: we have no more data to write.
 *
 * @param cs		the stream to close
 * @param saw_nul	if non-NULL, writes whether we saw a NUL in the input
 *
 * @return the final length of the stream on success, 0 on error.
 */
size_t
cobs_stream_close(cobs_stream_t *cs, bool *saw_nul)
{
	g_assert(cobs_stream_is_valid(cs));

	if (cs->closed)
		return 0;	/* Stream closed */

	/*
	 * If `last_code' is 0xff, then optimize: we don't need to finish if
	 * no data was written after we emitted that code.
	 * Decoder will detect this condition and know there was no need for
	 * the trailing logical NUL.
	 */

	if (cs->last_code == 0xff && cs->code == 0x1)
		goto closed;

	if (cs->cp >= cs->end)
		return 0;

	*cs->cp = cs->code;
	cs->cp = cs->o++;

closed:
	cs->closed = TRUE;

	if (saw_nul != NULL)
		*saw_nul = cs->saw_nul;

	return cs->cp - cs->outbuf;
}

/**
 * Empty the descriptor, making it invalid.
 */
void
cobs_stream_invalidate(cobs_stream_t *cs)
{
	ZERO(cs);
}

/**
 * Check whether the stream descriptor is valid, for assertions.
 */
bool
cobs_stream_is_valid(cobs_stream_t *cs)
{
	if (NULL == cs)
		return FALSE;

	if (cs->magic != COBS_MAGIC)
		return FALSE;

	if (NULL == cs->outbuf)
		return FALSE;

	if (NULL == cs->end || cs->end <= cs->outbuf)
		return FALSE;

	if (cs->o == NULL || cs->o < cs->outbuf || cs->o > cs->end)
		return FALSE;

	if (cs->cp == NULL || cs->cp < cs->outbuf || cs->cp > cs->end)
		return FALSE;

	if (cs->saw_nul != TRUE && cs->saw_nul != FALSE)
		return FALSE;

	if (cs->closed != TRUE && cs->closed != FALSE)
		return FALSE;

	return TRUE;
}

/* vi: set ts=4 sw=4 cindent: */
