/*
 * $Id$
 *
 * Copyright (c) 2003, Raphael Manfredi
 *
 * Base64 encoding/decoding.
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

#include "common.h"		/* For proper -DUSE_DMALLOC compiles */
#include <glib.h>
#include <string.h>

#include "base64.h"

RCSID("$Id$");

/*
 *                       The Base 64 Alphabet
 *
 *     Value Encoding  Value Encoding  Value Encoding  Value Encoding
 *         0 A            17 R            34 i            51 z
 *         1 B            18 S            35 j            52 0
 *         2 C            19 T            36 k            53 1
 *         3 D            20 U            37 l            54 2
 *         4 E            21 V            38 m            55 3
 *         5 F            22 W            39 n            56 4
 *         6 G            23 X            40 o            57 5
 *         7 H            24 Y            41 p            58 6
 *         8 I            25 Z            42 q            59 7
 *         9 J            26 a            43 r            60 8
 *        10 K            27 b            44 s            61 9
 *        11 L            28 c            45 t            62 +
 *        12 M            29 d            46 u            63 /
 *        13 N            30 e            47 v
 *        14 O            31 f            48 w         (pad) =
 *        15 P            32 g            49 x
 *        16 Q            33 h            50 y
 */
static gint8 values[256] = {
/*  0  1  2  3  4  5  6  7  8  9  */	/* 0123456789              */
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,		/*            -  00 ->  09 */
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,		/*            -  10 ->  19 */
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,		/*            -  20 ->  29 */
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,		/*            -  30 ->  39 */

    -1,-1,-1,62,-1,-1,-1,63,			/* ()*+'-./   -  40 ->  47 */
    52,53,54,55,56,57,58,59,60,61,		/* 0123456789 -  48 ->  57 */
    -1,-1,-1,-1,-1,-1,-1, 0, 1, 2,		/* :;<=>?@ABC -  58 ->  67 */
     3, 4, 5, 6, 7, 8, 9,10,11,12,		/* DEFGHIJKLM -  68 ->  77 */
    13,14,15,16,17,18,19,20,21,22,		/* NOPQRSTUVW -  78 ->  87 */
    23,24,25,-1,-1,-1,-1,-1,-1,26,		/* XYZ[\]^_`a -  88 ->  97 */
    27,28,29,30,31,32,33,34,35,36,		/* bcdefghijk -  98 -> 107 */
    37,38,39,40,41,42,43,44,45,46,		/* lmnopqrstu - 108 -> 117 */
    47,48,49,50,51,						/* vwxyz      - 118 -> 122 */

          -1,-1,-1,-1,-1,-1,-1,-1,		/*            - 123 -> 130 */
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,		/*            - 131 -> 140 */
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,		/*            - 141 -> 150 */
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,		/*            - 151 -> 160 */
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,		/*            - 161 -> 170 */
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,		/*            - 171 -> 180 */
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,		/*            - 181 -> 190 */
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,		/*            - 191 -> 200 */
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,		/*            - 201 -> 210 */
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,		/*            - 211 -> 220 */
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,		/*            - 221 -> 230 */
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,		/*            - 231 -> 240 */
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,		/*            - 241 -> 250 */
    -1,-1,-1,-1,-1,						/*            - 251 -> 255 */
};

static const gchar *b64_alphabet =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/*
 * encode_pad_length
 *
 * Compute the number of base64 digits and amount of padding necessary
 * to encode `len' bytes.
 *
 * Returns the number of base64 digits necessary.
 * Furthermore, if `pad' is a non-NULL pointer, it is filled with the amount
 * of padding chars that would be necessary.
 */
static gint encode_pad_length(gint len, gint *pad)
{
	gint ndigits;			/* Base64 digits necessary */
	gint npad = 0;			/* Final padding chars necessary */
	gint tcount;			/* Amount of full triplets */
	gint remainder;			/* Amount of input bytes in final triplet */

	g_assert(len > 0);

	tcount = len / 3;
	remainder = len - (tcount * 3);

	g_assert(remainder >= 0);

	switch (remainder) {
	case 0: npad = 0; break;
	case 1: npad = 2; break;
	case 2: npad = 1; break;
	default: g_assert(0);		/* Not possible */
	}

	ndigits = tcount * 4;		/* Each full triplet encoded on 4 bytes */
	if (npad != 0)
		ndigits += (4 - npad);

	if (pad)
		*pad = npad;

	return ndigits;
}

/*
 * base64_encode_exactly
 *
 * Encode `len' bytes from `buf' into `enclen' bytes starting from `encbuf'.
 * Caller must have ensured that there was EXACTLY the needed room in encbuf.
 */
static void base64_encode_exactly(const guchar *buf, gint len,
	guchar *encbuf, gint enclen)
{
	guint32 i = 0;					/* Input accumulator, 0 for trailing pad */
	guchar const *ip = buf + len;	/* Input pointer, one byte off end */
	guchar *op = encbuf + enclen;	/* Output pointer, one byte off end */

	g_assert(buf);
	g_assert(encbuf);
	g_assert(len > 0);
	g_assert(enclen >= len * 4 / 3);

	/*
	 * In the following picture, we represent how the 3 bytes of input
	 * are split into groups of 6 bits, each group being encoded as a
	 * single base64 digit.
	 *
	 * input byte       0        1        2     
	 *              +--------+--------+--------+
	 *              |01234501|23450123|45012345|
	 *              +--------+--------+--------+
	 *               <----><-----><-----><---->
	 * output digit     0     1      2      3
	 *
	 *
	 * Because of possible padding, which must be done as if the input
	 * was 0, and because the fractional part is at the end, we'll
	 * start encoding from the end.  The encoding loop is unrolled for
	 * greater performance (using the infamous Duff's device to directly
	 * switch at the proper stage within the do {} while loop).
	 */

	switch (len % 3) {
	case 0:
		do {
			g_assert(op - encbuf >= 4);
			i = *--ip;							/* Input #2 */
			*--op = b64_alphabet[i & 0x3f];		/* Ouput #3 */
			i >>= 6;							/* upper <45>, input #2 */
			/* FALLTHROUGH */
	case 2:
			i |= ((guint32) *--ip) << 2;		/* had 2 bits in `i' */
			*--op = b64_alphabet[i & 0x3f];		/* Output #2 */
			i >>= 6;							/* upper <2345>, input #1 */
			/* FALLTHROUGH */
	case 1:
			i |= ((guint32) *--ip) << 4;		/* had 4 bits in `i' */
			*--op = b64_alphabet[i & 0x3f];		/* Output #1 */
			i >>= 6;							/* upper <012345>, input #0 */
			*--op = b64_alphabet[i & 0x3f];		/* Output #0 */
			i >>= 6;							/* Holds nothing, MBZ */
			g_assert(i == 0);
			g_assert(op >= encbuf);
		} while (op > encbuf);
	}
}

/*
 * base64_encode_into
 *
 * Encode `len' bytes from `buf' into `enclen' bytes starting from `encbuf'.
 * Caller must have ensured that there was enough room in encbuf.
 */
void base64_encode_into(const guchar *buf, gint len,
	guchar *encbuf, gint enclen)
{
	gint pad;
	gint exactlen = encode_pad_length(len, &pad);

	g_assert(enclen >= (exactlen + pad));

	base64_encode_exactly(buf, len, encbuf, exactlen);
	if (pad)
		memset(encbuf + exactlen, '=', pad);
}

/*
 * base64_encode
 *
 * Encode `len' bytes starting at `buf' into new allocated buffer.
 * No trailing padding chars are emitted.
 *
 * Returns the new encoded buffer, NUL-terminated, and the added amount
 * of padding chars in `retpad' if it is a non-NULL pointer.
 */
guchar *base64_encode(const guchar *buf, gint len, gint *retpad)
{
	gint pad;
	gint enclen = encode_pad_length(len, &pad);
	gchar *encbuf = g_malloc(enclen + pad + 1);	/* Allow for trailing NUL */

	base64_encode_exactly(buf, len, encbuf, enclen);
	if (pad)
		memset(encbuf + enclen, '=', pad);
	encbuf[enclen + pad] = '\0';

	if (retpad)
		*retpad = pad;

	return encbuf;
}

/*
 * base64_decode_alphabet
 *
 * Decode `len' bytes from `buf' into `declen' bytes starting from `decbuf'.
 * Caller must have ensured that there was sufficient room in decbuf.
 * Uses the specified decoding alphabet.
 *
 * Return decoded bytes if successful, 0 if the input was not valid base64.
 */
static gint base64_decode_alphabet(const gint8 valmap[256],
	const guchar *buf, gint len, guchar *decbuf, gint declen)
{
	guint32 i = 0;					/* Input accumulator, 0 for trailing pad */
	guchar const *ip = buf + len;	/* Input pointer, one byte off end */
	gint dlen = (len >> 2) * 3;		/* Exact decoded lenth */
	guchar *op;						/* Output pointer, one byte off end */
	gint bytes;						/* Bytes decoded without padding */
	gint8 v;
	
	g_assert(buf);
	g_assert(decbuf);
	g_assert(len > 0);
	g_assert((len & 0x3) == 0);			/* `len' is a multiple of 4 bytes */
	g_assert(declen >= dlen);

	/*
	 * If the last byte of input is '=', there is padding and we need to
	 * zero the tail of the decoding buffer.
	 */

	if (buf[len-1] == '=') {
		gint pad = 0;
		gint n = 0;							/* Amount of bytes to zero */
		gint s = 0;							/* Amount of bytes to zero */

		/*
		 * Remove and count trailing input padding bytes.
		 */

		while (*--ip == '=')
			pad++;

		ip++;			/* Points one byte after real non-padding input */

		switch (pad) {
		case 1: n = 1; s = 0; break;
		case 2: n = 2; s = 1; break;
		default:
			return 0;				/* Cannot be valid base64 */
		}

		memset(decbuf + (dlen - n), 0, n);
		op = decbuf + (dlen - s);
		bytes = dlen - n;
	} else {
		op = decbuf + dlen;
		bytes = dlen;
	}

	/*
	 * In the following picture, we represent how the 4 bytes of input,
	 * each consisting of only 6 bits of information forming a base64 digit,
	 * are concatenated back into 3 bytes of binary information.
	 *
	 * input digit      0     1      2      3
	 *               <----><-----><-----><---->
	 *              +--------+--------+--------+
	 *              |01234501|23450123|45012345|
	 *              +--------+--------+--------+
	 * output byte      0        1        2     
	 *
	 * Because of possible padding, which must be done as if the input
	 * was 0, and because the fractional part is at the end, we'll
	 * start decoding from the end.  The decoding loop is unrolled for
	 * greater performance (using the infamous Duff's device to directly
	 * switch at the proper stage within the do {} while loop).
	 */

	switch ((ip - buf) % 4) {
	case 0:
		do {
			i = valmap[*--ip];				/* Input #3 */
			if (i < 0) return 0;
			/* FALLTHROUGH */
	case 3:
			v = valmap[*--ip];				/* Input #2 */
			if (v < 0) return 0;
			i |= v << 6;					/* had 6 bits */
			*--op = i & 0xff;				/* Output #2 */
			i >>= 8;						/* lower <0123> of output #1 */
			/* FALLTHROUGH */
	case 2:
			v = valmap[*--ip];				/* Input #1 */
			if (v < 0) return 0;
			i |= v << 4;					/* had 4 bits */
			*--op = i & 0xff;				/* Output #1 */
			i >>= 8;						/* lower <01> of output #0 */
			/* FALLTHROUGH */
	case 1:
			v = valmap[*--ip];				/* Input #0 */
			if (v < 0) return 0;
			i |= v << 2;					/* had 2 bits */
			*--op = i & 0xff;				/* Output #0 */
			i >>= 8;						/* Holds nothing, MBZ */
			g_assert(i == 0);
			g_assert(op >= decbuf);
		} while (op > decbuf);
	}

	return bytes;
}

/*
 * base64_decode_into
 *
 * Decode `len' bytes from `buf' into `declen' bytes starting from `decbuf'.
 * Caller must have ensured that there was sufficient room in decbuf.
 *
 * Returns the amount of bytes decoded (without trailing padding) if successful,
 * 0 if the input was not valid base64.
 */
gint base64_decode_into(const guchar *buf, gint len,
	guchar *decbuf, gint declen)
{
	return base64_decode_alphabet(values, buf, len, decbuf, declen);
}

/*
 * base64_decode
 *
 * Decode `len' bytes starting at `buf' into new allocated buffer.
 *
 * Returns the new decoded buffer, or NULL if the input was not valid base64
 * encoding.  The caller knows the length of the returned buffer: it's the
 * size of the input divided by 4 and multiplied by 3.  If `outlen' is non-NULL,
 * it is filled with the amount of bytes decoded into the buffer (without
 * trailing padding).
 */
guchar *base64_decode(const guchar *buf, gint len, gint *outlen)
{
	gint declen;
	gchar *decbuf;
	gint decoded;

	if (len == 0 || (len & 0x3))		/* Empty, or padding bytes missing */
		return NULL;

	declen = (len >> 2) * 3;
	decbuf = g_malloc(declen);

	decoded = base64_decode_into(buf, len, decbuf, declen);

	if (decoded == 0) {
		g_free(decbuf);
		return NULL;
	}

	if (outlen != NULL)
		*outlen = decoded;

	return decbuf;
}

