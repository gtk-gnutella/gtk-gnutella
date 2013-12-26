/*
 * This file comes from RFC 3174. Inclusion in gtk-gnutella is:
 *
 * Copyright (c) 2002-2003, Raphael Manfredi
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
 * This file comes from RFC 3174. Inclusion in gtk-gnutella is:
 *
 * @author Raphael Manfredi
 * @date 2002-2003
 */

#include "common.h"
#include "endian.h"
#include "sha1.h"
#include "misc.h"			/* For RCSID */
#include "override.h"		/* Must be the last header included */

/**
 *  Define the SHA1 circular left shift macro.
 */
#define SHA1CircularShift(bits,word) \
	(((word) << (bits)) | ((word) >> (32-(bits))))

/* Local Function Prototyptes */
static void SHA1PadMessage(SHA1Context *);
static void SHA1ProcessMessageBlock(SHA1Context *);

/**
 *  SHA1Reset
 *
 *  Description:
 *      This function will initialize the SHA1Context in preparation
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
SHA1Reset(SHA1Context *context)
{
	if (!context)
		return shaNull;

	context->Length                 = 0;
	context->Message_Block_Index    = 0;

	context->Intermediate_Hash[0]   = 0x67452301;
	context->Intermediate_Hash[1]   = 0xEFCDAB89;
	context->Intermediate_Hash[2]   = 0x98BADCFE;
	context->Intermediate_Hash[3]   = 0x10325476;
	context->Intermediate_Hash[4]   = 0xC3D2E1F0;

	context->Computed   = 0;
	context->Corrupted  = 0;

	return shaSuccess;
}

/**
 *  SHA1Result
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
SHA1Result(SHA1Context *context, struct sha1 *digest)
{
	unsigned i;

	if (!context || !digest)
		return shaNull;

	if (context->Corrupted)
		return context->Corrupted;

	if (!context->Computed) {
		SHA1PadMessage(context);
		/* message may be sensitive, clear it out */
		ZERO(&context->Message_Block);
		context->Length = 0;    /* and clear length */
		context->Computed = 1;
	}

	for (i = 0; i < sizeof digest->data; ++i) {
		digest->data[i] =
			context->Intermediate_Hash[i>>2] >> 8 * (3 - (i & 0x03));
	}

	return shaSuccess;
}

/**
 *  SHA1Input
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
SHA1Input(SHA1Context *context, const void *data, size_t length)
{
	const unsigned char *message_array = data;

	if (!length)
		return shaSuccess;

	if (!context || !message_array)
		return shaNull;

	if (context->Computed) {
		context->Corrupted = shaStateError;
		return shaStateError;
	}

	if (context->Corrupted)
		 return context->Corrupted;

	while (length-- && !context->Corrupted) {
		context->Message_Block[context->Message_Block_Index++] =
						(*message_array & 0xFF);

		context->Length += 8;
		if (context->Length < 8) {
			/* Message is too long */
			context->Corrupted = 1;
		}

		if (context->Message_Block_Index == 64)
			SHA1ProcessMessageBlock(context);

		message_array++;
	}

	return shaSuccess;
}

/**
 *  SHA1ProcessMessageBlock
 *
 *  Description:
 *      This function will process the next 512 bits of the message
 *      stored in the Message_Block array.
 *
 *  Parameters:
 *      None.
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
SHA1ProcessMessageBlock(SHA1Context *context)
{
	const uint32 K[] = {       /* Constants defined in SHA-1 */
		0x5A827999,
		0x6ED9EBA1,
		0x8F1BBCDC,
		0xCA62C1D6
	};
	int    t;                 /* Loop counter              */
	uint32 temp;              /* Temporary word value      */
	uint32 W[80];             /* Word sequence             */
	uint32 A, B, C, D, E;     /* Word buffers              */
	uint32 *wp;               /* Pointer in word sequence  */

	/*
	 *  Initialize the first 16 words in the array W
	 */

#define INIT(x) \
	W[x] = (context->Message_Block[(x) * 4] << 24)  | \
		(context->Message_Block[(x) * 4 + 1] << 16) | \
		(context->Message_Block[(x) * 4 +2] << 8)   | \
		(context->Message_Block[(x) * 4 +3])

	/* Unrolling this loop saves time */
	INIT(0);  INIT(1);  INIT(2);  INIT(3);
	INIT(4);  INIT(5);  INIT(6);  INIT(7);
	INIT(8);  INIT(9);  INIT(10); INIT(11);
	INIT(12); INIT(13); INIT(14); INIT(15);

#define CRUNCH \
	*wp = SHA1CircularShift(1,wp[-3] ^ wp[-8] ^ wp[-14] ^ wp[-16])

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

	A = context->Intermediate_Hash[0];
	B = context->Intermediate_Hash[1];
	C = context->Intermediate_Hash[2];
	D = context->Intermediate_Hash[3];
	E = context->Intermediate_Hash[4];

	wp = &W[0];

#define ROTATE(k, mix) \
	temp = SHA1CircularShift(5,A) + (mix) + E + *wp++ + K[k]; \
	E = D; D = C; \
	C = SHA1CircularShift(30,B); \
	B = A; A = temp

	/* Optimizing "(B & C) | (~B & D)" into "D ^ (B & (C ^ D))" */
	ROTATE(0, D ^ (B & (C ^ D)));
	ROTATE(0, D ^ (B & (C ^ D)));
	ROTATE(0, D ^ (B & (C ^ D)));
	ROTATE(0, D ^ (B & (C ^ D)));
	ROTATE(0, D ^ (B & (C ^ D)));
	ROTATE(0, D ^ (B & (C ^ D)));
	ROTATE(0, D ^ (B & (C ^ D)));
	ROTATE(0, D ^ (B & (C ^ D)));
	ROTATE(0, D ^ (B & (C ^ D)));
	ROTATE(0, D ^ (B & (C ^ D)));
	ROTATE(0, D ^ (B & (C ^ D)));
	ROTATE(0, D ^ (B & (C ^ D)));
	ROTATE(0, D ^ (B & (C ^ D)));
	ROTATE(0, D ^ (B & (C ^ D)));
	ROTATE(0, D ^ (B & (C ^ D)));
	ROTATE(0, D ^ (B & (C ^ D)));
	ROTATE(0, D ^ (B & (C ^ D)));
	ROTATE(0, D ^ (B & (C ^ D)));
	ROTATE(0, D ^ (B & (C ^ D)));
	ROTATE(0, D ^ (B & (C ^ D)));

	ROTATE(1, B ^ C ^ D);
	ROTATE(1, B ^ C ^ D);
	ROTATE(1, B ^ C ^ D);
	ROTATE(1, B ^ C ^ D);
	ROTATE(1, B ^ C ^ D);
	ROTATE(1, B ^ C ^ D);
	ROTATE(1, B ^ C ^ D);
	ROTATE(1, B ^ C ^ D);
	ROTATE(1, B ^ C ^ D);
	ROTATE(1, B ^ C ^ D);
	ROTATE(1, B ^ C ^ D);
	ROTATE(1, B ^ C ^ D);
	ROTATE(1, B ^ C ^ D);
	ROTATE(1, B ^ C ^ D);
	ROTATE(1, B ^ C ^ D);
	ROTATE(1, B ^ C ^ D);
	ROTATE(1, B ^ C ^ D);
	ROTATE(1, B ^ C ^ D);
	ROTATE(1, B ^ C ^ D);
	ROTATE(1, B ^ C ^ D);

	/* Optimizing "(B & C) | (B & D)" into "B & (C | D)" */
	ROTATE(2, (B & (C | D)) | (C & D));
	ROTATE(2, (B & (C | D)) | (C & D));
	ROTATE(2, (B & (C | D)) | (C & D));
	ROTATE(2, (B & (C | D)) | (C & D));
	ROTATE(2, (B & (C | D)) | (C & D));
	ROTATE(2, (B & (C | D)) | (C & D));
	ROTATE(2, (B & (C | D)) | (C & D));
	ROTATE(2, (B & (C | D)) | (C & D));
	ROTATE(2, (B & (C | D)) | (C & D));
	ROTATE(2, (B & (C | D)) | (C & D));
	ROTATE(2, (B & (C | D)) | (C & D));
	ROTATE(2, (B & (C | D)) | (C & D));
	ROTATE(2, (B & (C | D)) | (C & D));
	ROTATE(2, (B & (C | D)) | (C & D));
	ROTATE(2, (B & (C | D)) | (C & D));
	ROTATE(2, (B & (C | D)) | (C & D));
	ROTATE(2, (B & (C | D)) | (C & D));
	ROTATE(2, (B & (C | D)) | (C & D));
	ROTATE(2, (B & (C | D)) | (C & D));
	ROTATE(2, (B & (C | D)) | (C & D));

	ROTATE(3, B ^ C ^ D);
	ROTATE(3, B ^ C ^ D);
	ROTATE(3, B ^ C ^ D);
	ROTATE(3, B ^ C ^ D);
	ROTATE(3, B ^ C ^ D);
	ROTATE(3, B ^ C ^ D);
	ROTATE(3, B ^ C ^ D);
	ROTATE(3, B ^ C ^ D);
	ROTATE(3, B ^ C ^ D);
	ROTATE(3, B ^ C ^ D);
	ROTATE(3, B ^ C ^ D);
	ROTATE(3, B ^ C ^ D);
	ROTATE(3, B ^ C ^ D);
	ROTATE(3, B ^ C ^ D);
	ROTATE(3, B ^ C ^ D);
	ROTATE(3, B ^ C ^ D);
	ROTATE(3, B ^ C ^ D);
	ROTATE(3, B ^ C ^ D);
	ROTATE(3, B ^ C ^ D);
	ROTATE(3, B ^ C ^ D);

	context->Intermediate_Hash[0] += A;
	context->Intermediate_Hash[1] += B;
	context->Intermediate_Hash[2] += C;
	context->Intermediate_Hash[3] += D;
	context->Intermediate_Hash[4] += E;

	context->Message_Block_Index = 0;
}

/**
 *  SHA1PadMessage
 *
 *  Description:
 *      According to the standard, the message must be padded to an even
 *      512 bits.  The first padding bit must be a '1'.  The last 64
 *      bits represent the length of the original message.  All bits in
 *      between should be 0.  This function will pad the message
 *      according to those rules by filling the Message_Block array
 *      accordingly.  It will also call the ProcessMessageBlock function
 *      provided appropriately.  When it returns, it can be assumed that
 *      the message digest has been computed.
 *
 *  Parameters:
 *      context: [in/out]
 *          The context to pad
 *      ProcessMessageBlock: [in]
 *          The appropriate SHA*ProcessMessageBlock function
 *  Returns:
 *      Nothing.
 */
static void
SHA1PadMessage(SHA1Context *context)
{
	/*
	 *  Check to see if the current message block is too small to hold
	 *  the initial padding bits and length.  If so, we will pad the
	 *  block, process it, and then continue padding into a second block.
     */

	if (context->Message_Block_Index > 55) {
		context->Message_Block[context->Message_Block_Index++] = 0x80;
		while (context->Message_Block_Index < 64) {
			context->Message_Block[context->Message_Block_Index++] = 0;
		}

		SHA1ProcessMessageBlock(context);

		while (context->Message_Block_Index < 56) {
			context->Message_Block[context->Message_Block_Index++] = 0;
		}
	} else {
		context->Message_Block[context->Message_Block_Index++] = 0x80;
		while (context->Message_Block_Index < 56) {
			context->Message_Block[context->Message_Block_Index++] = 0;
		}
	}

	/*
	 *  Store the message length as the last 8 octets
	 */

	poke_be64(&context->Message_Block[56], context->Length);
	SHA1ProcessMessageBlock(context);
}

/* vi: set ts=4 sw=4 cindent: */
