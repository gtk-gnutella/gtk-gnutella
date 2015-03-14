/*
 * This file comes from RFC 3174. Inclusion in gtk-gnutella is:
 *
 * Copyright (c) 2002-2003, 2015 Raphael Manfredi
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
 * Secure Hashing Algorithm 1 implementation.
 *
 *  Description:
 *      This file implements the Secure Hashing Algorithm 1 as
 *      defined in FIPS PUB 180-1 published April 17, 1995.
 *
 *      The SHA-1, produces a 160-bit message digest for a given
 *      data stream.  It should take about 2**n steps to find a
 *      message with the same digest as a given message and
 *      2**(n/2) to find any two messages with the same digest,
 *      when n is the digest size in bits.  Therefore, this
 *      algorithm can serve as a means of providing a
 *      "fingerprint" for a message.
 *
 *  Portability Issues:
 *      SHA-1 is defined in terms of 32-bit "words".  This code
 *      uses <stdint.h> (included via "sha1.h" to define 32 and 8
 *      bit unsigned integer types.  If your C compiler does not
 *      support 32 bit unsigned integers, this code is not
 *      appropriate.
 *
 *  Caveats:
 *      SHA-1 is designed to work with messages less than 2^64 bits
 *      long.  Although SHA-1 allows a message digest to be generated
 *      for messages of any number of bits less than 2^64, this
 *      implementation only works with messages with a length that is
 *      a multiple of the size of an 8-bit character.
 *
 * @note
 * This file comes from RFC 3174. Inclusion in gtk-gnutella with additional
 * optimizations and adaptation to coding standards and specific library
 * routines were made by Raphael Manfredi.
 *
 * @author Raphael Manfredi
 * @date 2002-2003, 2015
 */

#include "common.h"
#include "endian.h"
#include "sha1.h"
#include "misc.h"			/* For RCSID */
#include "override.h"		/* Must be the last header included */

#define SHA1_BLEN	64		/**< Message block length */

/* Local Function Prototyptes */
static void SHA1_pad_message(SHA1_context *);
static void SHA1_process_message_block(SHA1_context *, const void *mblock);

/**
 *  SHA1_reset
 *
 *  Description:
 *      This function will initialize the SHA1_context in preparation
 *      for computing a new SHA1 message digest.
 *
 *  Parameters:
 *      context: [in/out]
 *          The context to reset.
 *
 *  Returns:
 *      sha Error Code.
 *
 */
int
SHA1_reset(SHA1_context *context)
{
	if (!context)
		return SHA_NULL;

	/*
	 * We rely on mblock[] being aligned on a 32-bit boundary, to be able
	 * to cast it to a uint32 * in SHA1_process_message_block().
	 */
	STATIC_ASSERT(0 == offsetof(struct SHA1_context, mblock) % 4);

	ZERO(context);

	context->magic     = SHA1_CONTEXT_MAGIC;

	context->ihash[0]  = 0x67452301;
	context->ihash[1]  = 0xEFCDAB89;
	context->ihash[2]  = 0x98BADCFE;
	context->ihash[3]  = 0x10325476;
	context->ihash[4]  = 0xC3D2E1F0;

	return SHA_SUCCESS;
}

/**
 *  SHA1_result
 *
 *  Description:
 *      This function will return the 160-bit message digest into the
 *      digest array  provided by the caller.
 *      NOTE: The first octet of hash is stored in the 0th element,
 *            the last octet of hash in the 19th element.
 *
 *  Parameters:
 *      context: [in/out]
 *          The context to use to calculate the SHA-1 hash.
 *      digest: [out]
 *          Where the digest is returned.
 *
 *  Returns:
 *      sha Error Code.
 */
int
SHA1_result(SHA1_context *context, struct sha1 *digest)
{
	unsigned i;

	SHA1_check(context);

	if (!context || !digest)
		return SHA_NULL;

	if (context->corrupted)
		return context->corrupted;

	if (!context->computed) {
		SHA1_pad_message(context);
		/* message may be sensitive, clear it out */
		ZERO(&context->mblock);
		context->length = 0;    /* and clear length */
		context->computed = TRUE;
	}

	for (i = 0; i < sizeof digest->data; ++i) {
		digest->data[i] = context->ihash[i>>2] >> 8 * (3 - (i & 0x03));
	}

	return SHA_SUCCESS;
}

/**
 *  SHA1_input
 *
 *  Description:
 *      This function accepts an array of octets as the next portion
 *      of the message.
 *
 *  Parameters:
 *      context: [in/out]
 *          The SHA context to update
 *      message_array: [in]
 *          An array of characters representing the next portion of
 *          the message.
 *      length: [in]
 *          The length of the message in message_array
 *
 *  Returns:
 *      sha Error Code.
 */
int
SHA1_input(SHA1_context *context, const void *data, size_t length)
{
	const uint8 *mp = data;		/* Pointer into message, viewed as byte array */

	SHA1_check(context);

	if G_UNLIKELY(0 == length)
		return SHA_SUCCESS;

	if G_UNLIKELY(NULL == context || NULL == data)
		return SHA_NULL;

	if G_UNLIKELY(context->computed) {
		context->corrupted = SHA_STATE_ERROR;
		return SHA_STATE_ERROR;
	}

	if G_UNLIKELY(context->corrupted)
		 return SHA_STATE_ERROR;

	/*
	 * Optimization: if the data block is aligned on a 32-bit boundary and
	 * is at least 64-byte long, we can avoid moving data around and feed
	 * them directly to SHA1_process_message_block(), as long as there are
	 * no pending bytes in the context.  This will likely be happening when
	 * large chunks of data are fed to the routine, e.g. when processing a file.
	 *		--RAM, 2015-03-14
	 */

	if G_UNLIKELY(0 != context->midx || 0 != pointer_to_long(mp) % 4)
		goto slowpath;

fastpath:
	for (/**/; length >= SHA1_BLEN; mp += SHA1_BLEN, length -= SHA1_BLEN) {
		context->length += 8 * SHA1_BLEN;		/* Counts bits, not bytes */

		if G_UNLIKELY(context->length < 8 * SHA1_BLEN) {
			/* Message is too long */
			context->corrupted = SHA_INPUT_TOO_LONG;
			return SHA_INPUT_TOO_LONG;
		}

		SHA1_process_message_block(context, mp);
	}

	/* FALL THROUGH */

	/*
	 * Normal slower processing (requires byte-copying to a message buffer).
	 */

slowpath:
	while (length--) {
		context->mblock[context->midx++] = *mp++;
		context->length += 8;		/* This counts bits, not bytes */

		if G_UNLIKELY(context->length < 8) {
			/* Message is too long */
			context->corrupted = SHA_INPUT_TOO_LONG;
			return SHA_INPUT_TOO_LONG;
		}

		if G_UNLIKELY(SHA1_BLEN == context->midx) {
			SHA1_process_message_block(context, context->mblock);
			if (length >= SHA1_BLEN && 0 == pointer_to_long(mp) % 4)
				goto fastpath;		/* Can use faster processing now */
		}
	}

	return SHA_SUCCESS;
}

/**
 *  SHA1_process_message_block
 *
 *  Description:
 *      This function will process the next 512 bits of the message
 *      stored in the mblock parameter.
 *
 *  Parameters:
 *      mblock: [in]
 *          Start of the next 64 message bytes to process
 *
 *  Returns:
 *      Nothing.
 *
 *  Comments:
 *      Many of the variable names in this code, especially the
 *      single character names, were used because those were the
 *      names used in the publication.
 */
static void G_GNUC_HOT
SHA1_process_message_block(SHA1_context *context, const void *mblock)
{
	const uint32 K[] = {       /* Constants defined in SHA-1 */
		0x5A827999,
		0x6ED9EBA1,
		0x8F1BBCDC,
		0xCA62C1D6
	};
	int    t;                 /* Loop counter              */
	uint32 W[80];             /* Word sequence             */
	uint32 a, b, c, d, e;     /* Word buffers              */
	uint32 *wp;               /* Pointer in word sequence  */

	/*
	 *  Initialize the first 16 words in the array W
	 */

#define INIT(x) \
	W[x] = UINT32_SWAP(*wp); wp++

	wp = (uint32 *) mblock;

	/* Unrolling this loop saves time */
	INIT(0);  INIT(1);  INIT(2);  INIT(3);
	INIT(4);  INIT(5);  INIT(6);  INIT(7);
	INIT(8);  INIT(9);  INIT(10); INIT(11);
	INIT(12); INIT(13); INIT(14); INIT(15);

#define CRUNCH \
	*wp = UINT32_ROTL(wp[-3] ^ wp[-8] ^ wp[-14] ^ wp[-16], 1)

	wp = &W[16];
	CRUNCH; wp++;		/* 16 */
	CRUNCH; wp++;		/* 17 */
	CRUNCH; wp++;		/* 18 */
	CRUNCH; wp++;		/* 19 */

	/* Fully unrolling this loop does NOT save time due to I-cache misses */
	for (t = 20; t < 80; t += 10) {
		CRUNCH; wp++;		/* t+0 */
		CRUNCH; wp++;		/* t+1 */
		CRUNCH; wp++;		/* t+2 */
		CRUNCH; wp++;		/* t+3 */
		CRUNCH; wp++;		/* t+4 */
		CRUNCH; wp++;		/* t+5 */
		CRUNCH; wp++;		/* t+6 */
		CRUNCH; wp++;		/* t+7 */
		CRUNCH; wp++;		/* t+8 */
		CRUNCH; wp++;		/* t+9 */
	}

	a = context->ihash[0];
	b = context->ihash[1];
	c = context->ihash[2];
	d = context->ihash[3];
	e = context->ihash[4];

	wp = &W[0];

#define ROTATE(k, A, B, C, D, E, mix) \
	E += UINT32_ROTL(A, 5) + mix(B, C, D) + *wp++ + K[k]; \
	B = UINT32_ROTL(B, 30);

	/*
	 * Optimizing "(B & C) | (~B & D)" into "D ^ (B & (C ^ D))" in M0
	 * Optimizing "(B & C) | (B & D)" into "B & (C | D)" in M2
	 */
#define M0(B, C, D)		(D ^ (B & (C ^ D)))
#define M1(B, C, D)		(B ^ C ^ D)
#define M2(B, C, D)		((B & (C | D)) | (C & D))
#define M3(B, C, D)		(B ^ C ^ D)

	/*
	 * Another optimization: get rid of the temporary variable to circulate
	 * the value.  Instead, we rotate the macro arguments, saving one
	 * assignment per ROTATE() macro.
	 *		--RAM, 2015-03-13
	 */

	ROTATE(0, a, b, c, d, e, M0);
	ROTATE(0, e, a, b, c, d, M0);
	ROTATE(0, d, e, a, b, c, M0);
	ROTATE(0, c, d, e, a, b, M0);
	ROTATE(0, b, c, d, e, a, M0);

	ROTATE(0, a, b, c, d, e, M0);
	ROTATE(0, e, a, b, c, d, M0);
	ROTATE(0, d, e, a, b, c, M0);
	ROTATE(0, c, d, e, a, b, M0);
	ROTATE(0, b, c, d, e, a, M0);

	ROTATE(0, a, b, c, d, e, M0);
	ROTATE(0, e, a, b, c, d, M0);
	ROTATE(0, d, e, a, b, c, M0);
	ROTATE(0, c, d, e, a, b, M0);
	ROTATE(0, b, c, d, e, a, M0);

	ROTATE(0, a, b, c, d, e, M0);
	ROTATE(0, e, a, b, c, d, M0);
	ROTATE(0, d, e, a, b, c, M0);
	ROTATE(0, c, d, e, a, b, M0);
	ROTATE(0, b, c, d, e, a, M0);

	ROTATE(1, a, b, c, d, e, M1);
	ROTATE(1, e, a, b, c, d, M1);
	ROTATE(1, d, e, a, b, c, M1);
	ROTATE(1, c, d, e, a, b, M1);
	ROTATE(1, b, c, d, e, a, M1);

	ROTATE(1, a, b, c, d, e, M1);
	ROTATE(1, e, a, b, c, d, M1);
	ROTATE(1, d, e, a, b, c, M1);
	ROTATE(1, c, d, e, a, b, M1);
	ROTATE(1, b, c, d, e, a, M1);

	ROTATE(1, a, b, c, d, e, M1);
	ROTATE(1, e, a, b, c, d, M1);
	ROTATE(1, d, e, a, b, c, M1);
	ROTATE(1, c, d, e, a, b, M1);
	ROTATE(1, b, c, d, e, a, M1);

	ROTATE(1, a, b, c, d, e, M1);
	ROTATE(1, e, a, b, c, d, M1);
	ROTATE(1, d, e, a, b, c, M1);
	ROTATE(1, c, d, e, a, b, M1);
	ROTATE(1, b, c, d, e, a, M1);

	ROTATE(2, a, b, c, d, e, M2);
	ROTATE(2, e, a, b, c, d, M2);
	ROTATE(2, d, e, a, b, c, M2);
	ROTATE(2, c, d, e, a, b, M2);
	ROTATE(2, b, c, d, e, a, M2);

	ROTATE(2, a, b, c, d, e, M2);
	ROTATE(2, e, a, b, c, d, M2);
	ROTATE(2, d, e, a, b, c, M2);
	ROTATE(2, c, d, e, a, b, M2);
	ROTATE(2, b, c, d, e, a, M2);

	ROTATE(2, a, b, c, d, e, M2);
	ROTATE(2, e, a, b, c, d, M2);
	ROTATE(2, d, e, a, b, c, M2);
	ROTATE(2, c, d, e, a, b, M2);
	ROTATE(2, b, c, d, e, a, M2);

	ROTATE(2, a, b, c, d, e, M2);
	ROTATE(2, e, a, b, c, d, M2);
	ROTATE(2, d, e, a, b, c, M2);
	ROTATE(2, c, d, e, a, b, M2);
	ROTATE(2, b, c, d, e, a, M2);

	ROTATE(3, a, b, c, d, e, M3);
	ROTATE(3, e, a, b, c, d, M3);
	ROTATE(3, d, e, a, b, c, M3);
	ROTATE(3, c, d, e, a, b, M3);
	ROTATE(3, b, c, d, e, a, M3);

	ROTATE(3, a, b, c, d, e, M3);
	ROTATE(3, e, a, b, c, d, M3);
	ROTATE(3, d, e, a, b, c, M3);
	ROTATE(3, c, d, e, a, b, M3);
	ROTATE(3, b, c, d, e, a, M3);

	ROTATE(3, a, b, c, d, e, M3);
	ROTATE(3, e, a, b, c, d, M3);
	ROTATE(3, d, e, a, b, c, M3);
	ROTATE(3, c, d, e, a, b, M3);
	ROTATE(3, b, c, d, e, a, M3);

	ROTATE(3, a, b, c, d, e, M3);
	ROTATE(3, e, a, b, c, d, M3);
	ROTATE(3, d, e, a, b, c, M3);
	ROTATE(3, c, d, e, a, b, M3);
	ROTATE(3, b, c, d, e, a, M3);

	context->ihash[0] += a;
	context->ihash[1] += b;
	context->ihash[2] += c;
	context->ihash[3] += d;
	context->ihash[4] += e;

	context->midx = 0;
}

/**
 *  SHA1_pad_message
 *
 *  Description:
 *      According to the standard, the message must be padded to an even
 *      512 bits.  The first padding bit must be a '1'.  The last 64
 *      bits represent the length of the original message.  All bits in
 *      between should be 0.  This function will pad the message
 *      according to those rules by filling the mblock array
 *      accordingly.  It will also call the ProcessMessageBlock function
 *      provided appropriately.  When it returns, it can be assumed that
 *      the message digest has been computed.
 *
 *  Parameters:
 *      context: [in/out]
 *          The context to pad
 *  Returns:
 *      Nothing.
 */
static void
SHA1_pad_message(SHA1_context *context)
{
	/*
	 *  Check to see if the current message block is too small to hold
	 *  the initial padding bits and length.  If so, we will pad the
	 *  block, process it, and then continue padding into a second block.
     */

#define SHA1_BUP	(SHA1_BLEN - 8)	/* Upper boundary before 64-bit length */

	if (context->midx >= SHA1_BUP) {
		context->mblock[context->midx++] = 0x80;
		while (context->midx < SHA1_BLEN) {
			context->mblock[context->midx++] = 0;
		}

		SHA1_process_message_block(context, context->mblock);

		while (context->midx < SHA1_BUP) {
			context->mblock[context->midx++] = 0;
		}
	} else {
		context->mblock[context->midx++] = 0x80;
		while (context->midx < SHA1_BUP) {
			context->mblock[context->midx++] = 0;
		}
	}

	/*
	 *  Store the message length as the last 8 octets
	 */

	poke_be64(&context->mblock[SHA1_BUP], context->length);
	SHA1_process_message_block(context, context->mblock);
}

/* vi: set ts=4 sw=4 cindent: */
