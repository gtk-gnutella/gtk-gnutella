/*
 * $Id$
 *
 * Copyright (c) 2001-2002, Raphael Manfredi
 *
 * Base32 encoding/decoding.
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

//#include "gnutella.h"
#include <glib.h>
#include <string.h>

#include "base32.h"

/*
 *                       The Base 32 Alphabet
 *
 *     Value Encoding  Value Encoding  Value Encoding  Value Encoding
 *         0 A             9 J            18 S            27 3
 *         1 B            10 K            19 T            28 4
 *         2 C            11 L            20 U            29 5
 *         3 D            12 M            21 V            30 6
 *         4 E            13 N            22 W            31 7
 *         5 F            14 O            23 X
 *         6 G            15 P            24 Y         (pad) =
 *         7 H            16 Q            25 Z
 *         8 I            17 R            26 2
 */
static gint8 values[256] = {
/*  0  1  2  3  4  5  6  7  8  9  */	/* 0123456789              */
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,		/*            -  00 ->  09 */
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,		/*            -  10 ->  19 */
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,		/*            -  20 ->  29 */
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,		/*            -  30 ->  39 */
    -1,-1,-1,-1,-1,-1,-1,-1,			/*            -  40 ->  47 */

    -1,-1,26,27,28,29,30,31,-1,-1,		/* 0123456789 -  48 ->  57 */
    -1,-1,-1,-1,-1,-1,-1, 0, 1, 2,		/* :;<=>?@ABC -  58 ->  67 */
     3, 4, 5, 6, 7, 8, 9,10,11,12,		/* DEFGHIJKLM -  68 ->  77 */
    13,14,15,16,17,18,19,20,21,22,		/* NOPQRSTUVW -  78 ->  87 */
    23,24,25,							/* XYZ        -  88 ->  90 */

    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,		/*            -  91 -> 100 */
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,		/*            - 101 -> 110 */
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,		/*            - 111 -> 120 */
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,		/*            - 121 -> 130 */
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

static gchar *b32_alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/*
 * Older base32 alphabet: "ABCDEFGHIJK MN PQRSTUVWXYZ  23456789"
 * We decode it only.
 */
static gint8 old_values[256] = {
/*  0  1  2  3  4  5  6  7  8  9  */	/* 0123456789              */
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,		/*            -  00 ->  09 */
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,		/*            -  10 ->  19 */
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,		/*            -  20 ->  29 */
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,		/*            -  30 ->  39 */
    -1,-1,-1,-1,-1,-1,-1,-1,			/*            -  40 ->  47 */

    -1,-1,24,25,26,27,28,29,30,31,		/* 0123456789 -  48 ->  57 */
    -1,-1,-1,-1,-1,-1,-1, 0, 1, 2,		/* :;<=>?@ABC -  58 ->  67 */
     3, 4, 5, 6, 7, 8, 9,10,-1,11,		/* DEFGHIJKLM -  68 ->  77 */
    12,-1,13,14,15,16,17,18,19,20,		/* NOPQRSTUVW -  78 ->  87 */
    21,22,23,							/* XYZ        -  88 ->  90 */

    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,		/*            -  91 -> 100 */
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,		/*            - 101 -> 110 */
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,		/*            - 111 -> 120 */
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,		/*            - 121 -> 130 */
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

/*
 * encode_pad_length
 *
 * Compute the number of base32 digits and amount of padding necessary
 * to encode `len' bytes.
 *
 * Returns the number of base32 digits necessary.
 * Furthermore, if `pad' is a non-NULL pointer, it is filled with the amount
 * of padding chars that would be necessary.
 */
static gint encode_pad_length(gint len, gint *pad)
{
	gint ndigits;			/* Base32 digits necessary */
	gint npad = 0;			/* Final padding chars necessary */
	gint qcount;			/* Amount of full quintets */
	gint remainder;			/* Amount of input bytes in final quintet */

	g_assert(len > 0);

	qcount = len / 5;
	remainder = len - (qcount * 5);

	g_assert(remainder >= 0);

	switch (remainder) {
	case 0: npad = 0; break;
	case 1: npad = 6; break;
	case 2: npad = 4; break;
	case 3: npad = 3; break;
	case 4: npad = 1; break;
	default: g_assert(0);		/* Not possible */
	}

	ndigits = qcount * 8;		/* Each full quintet encoded on 8 bytes */
	if (npad != 0)
		ndigits += (8 - npad);

	if (pad)
		*pad = npad;

	return ndigits;
}

/*
 * base32_encode_exactly
 *
 * Encode `len' bytes from `buf' into `enclen' bytes starting from `encbuf'.
 * Caller must have ensured that there was EXACTLY the needed room in encbuf.
 */
static void base32_encode_exactly(const guchar *buf, gint len,
	guchar *encbuf, gint enclen)
{
	guint32 i = 0;					/* Input accumulator, 0 for trailing pad */
	guchar const *ip = buf + len;	/* Input pointer, one byte off end */
	guchar *op = encbuf + enclen;	/* Output pointer, one byte off end */

	g_assert(buf);
	g_assert(encbuf);
	g_assert(len > 0);
	g_assert(enclen >= len * 8 / 5);

	/*
	 * In the following picture, we represent how the 5 bytes of input
	 * are split into groups of 5 bits, each group being encoded as a
	 * single base32 digit.
	 *
	 * input byte       0        1        2        3        4
	 *              +--------+--------+--------+--------+--------+
	 *              |01234012|34012340|12340123|40123401|23401234|
	 *              +--------+--------+--------+--------+--------+
	 *               <---><----><---><----><----><---><----><--->
	 * output digit    0     1    2     3     4    5     6    7
	 *
	 *
	 * Because of possible padding, which must be done as if the input
	 * was 0, and because the fractional part is at the end, we'll
	 * start encoding from the end.  The encoding loop is unrolled for
	 * greater performance (using the infamous Duff's device to directly
	 * switch at the proper stage within the do {} while loop).
	 */

	switch (len % 5) {
	case 0:
		do {
			g_assert(op - encbuf >= 8);
			i = *--ip;							/* Input #4 */
			*--op = b32_alphabet[i & 0x1f];		/* Ouput #7 */
			i >>= 5;							/* upper <234>, input #4 */
			/* FALLTHROUGH */
	case 4:
			i |= ((guint32) *--ip) << 3;		/* had 3 bits in `i' */
			*--op = b32_alphabet[i & 0x1f];		/* Output #6 */
			i >>= 5;							/* upper <401234>, input #3 */
			*--op = b32_alphabet[i & 0x1f];		/* Output #5 */
			i >>= 5;							/* upper <4>, input #3 */
			/* FALLTHROUGH */
	case 3:
			i |= ((guint32) *--ip) << 1;		/* had 1 bits in `i' */
			*--op = b32_alphabet[i & 0x1f];		/* Output #4 */
			i >>= 5;							/* upper <1234>, input #2 */
			/* FALLTHROUGH */
	case 2:
			i |= ((guint32) *--ip) << 4;		/* had 4 bits in `i' */
			*--op = b32_alphabet[i & 0x1f];		/* Output #3 */
			i >>= 5;							/* upper <3401234>, input #1 */
			*--op = b32_alphabet[i & 0x1f];		/* Output #2 */
			i >>= 5;							/* upper <34>, input #1 */
			/* FALLTHROUGH */
	case 1:
			i |= ((guint32) *--ip) << 2;		/* had 2 bits in `i' */
			*--op = b32_alphabet[i & 0x1f];		/* Output #1 */
			i >>= 5;							/* upper <01234>, input #0 */
			*--op = b32_alphabet[i & 0x1f];		/* Output #0 */
			i >>= 5;							/* Holds nothing, MBZ */
			g_assert(i == 0);
			g_assert(op >= encbuf);
		} while (op > encbuf);
	}
}

/*
 * base32_encode_into
 *
 * Encode `len' bytes from `buf' into `enclen' bytes starting from `encbuf'.
 * Caller must have ensured that there was enough room in encbuf.
 */
void base32_encode_into(const guchar *buf, gint len,
	guchar *encbuf, gint enclen)
{
	gint pad;
	gint exactlen = encode_pad_length(len, &pad);

	g_assert(enclen >= (exactlen + pad));

	base32_encode_exactly(buf, len, encbuf, exactlen);
	if (pad)
		memset(encbuf + exactlen, '=', pad);
}

/*
 * base32_encode
 *
 * Encode `len' bytes starting at `buf' into new allocated buffer.
 * No trailing padding chars are emitted.
 *
 * Returns the new encoded buffer, NUL-terminated, and the added amount
 * of padding chars in `retpad' if it is a non-NULL pointer.
 */
guchar *base32_encode(const guchar *buf, gint len, gint *retpad)
{
	gint pad;
	gint enclen = encode_pad_length(len, &pad);
	gchar *encbuf = g_malloc(enclen + pad + 1);	/* Allow for trailing NUL */

	base32_encode_exactly(buf, len, encbuf, enclen);
	if (pad)
		memset(encbuf + enclen, '=', pad);
	encbuf[enclen + pad] = '\0';

	if (retpad)
		*retpad = pad;

	return encbuf;
}

/*
 * base32_decode_alphabet
 *
 * Decode `len' bytes from `buf' into `declen' bytes starting from `decbuf'.
 * Caller must have ensured that there was sufficient room in decbuf.
 * Uses the specified decoding alphabet.
 *
 * Return TRUE if successful, FALSE if the input was not valid base32.
 */
static gboolean base32_decode_alphabet(gint8 valmap[256],
	const guchar *buf, gint len, guchar *decbuf, gint declen)
{
	guint32 i = 0;					/* Input accumulator, 0 for trailing pad */
	guchar const *ip = buf + len;	/* Input pointer, one byte off end */
	gint dlen = (len >> 3) * 5;		/* Exact decoded lenth */
	guchar *op;						/* Output pointer, one byte off end */
	gint8 v;
	
	g_assert(buf);
	g_assert(decbuf);
	g_assert(len > 0);
	g_assert((len & 0x7) == 0);			/* `len' is a multiple of 8 bytes */
	g_assert(declen >= dlen);

	/*
	 * If the last byte of input is '=', there is padding and we need to
	 * zero the tail of the decoding buffer.
	 */

	if (buf[len-1] == '=') {
		gint pad = 0;
		gint n = 0;							/* Amount of bytes to zero */

		/*
		 * Remove and count trailing input padding bytes.
		 */

		while (*--ip == '=')
			pad++;

		ip++;			/* Points one byte after real non-padding input */

		switch (pad) {
		case 1: n = 1; break;
		case 3: n = 2; break;
		case 4: n = 3; break;
		case 6: n = 4; break;
		default:
			return FALSE;			/* Cannot be valid base32 */
		}

		memset(decbuf + (dlen - n), 0, n);
		op = decbuf + (dlen - n);
	} else
		op = decbuf + dlen;

	/*
	 * In the following picture, we represent how the 8 bytes of input,
	 * each consisting of only 5 bits of information forming a base32 digit,
	 * are concatenated back into 5 bytes of binary information.
	 *
	 * input digit     0     1    2     3     4    5     6    7
	 *               <---><----><---><----><----><---><----><--->
	 *              +--------+--------+--------+--------+--------+
	 *              |01234012|34012340|12340123|40123401|23401234|
	 *              +--------+--------+--------+--------+--------+
	 * output byte      0        1        2        3        4
	 *
	 *
	 * Because of possible padding, which must be done as if the input
	 * was 0, and because the fractional part is at the end, we'll
	 * start decoding from the end.  The decoding loop is unrolled for
	 * greater performance (using the infamous Duff's device to directly
	 * switch at the proper stage within the do {} while loop).
	 */

	switch ((ip - buf) % 8) {
	case 0:
		do {
			i = valmap[*--ip];				/* Input #7 */
			if (i < 0) return FALSE;
			/* FALLTHROUGH */
	case 7:
			v = valmap[*--ip];				/* Input #6 */
			if (v < 0) return FALSE;
			i |= v << 5;					/* had 5 bits */
			*--op = i & 0xff;				/* Output #4 */
			i >>= 8;						/* lower <01> of output #3 */
			/* FALLTHROUGH */
	case 6:
			v = valmap[*--ip];				/* Input #5 */
			if (v < 0) return FALSE;
			i |= v << 2;					/* had 2 bits */
			/* FALLTHROUGH */
	case 5:
			v = valmap[*--ip];				/* Input #4 */
			if (v < 0) return FALSE;
			i |= v << 7;					/* had 7 bits */
			*--op = i & 0xff;				/* Output #3 */
			i >>= 8;						/* lower <0123> of output #2 */
			/* FALLTHROUGH */
	case 4:
			v = valmap[*--ip];				/* Input #3 */
			if (v < 0) return FALSE;
			i |= v << 4;					/* had 4 bits */
			*--op = i & 0xff;				/* Output #2 */
			i >>= 8;						/* lower <0> of output #1 */
			/* FALLTHROUGH */
	case 3:
			v = valmap[*--ip];				/* Input #2 */
			if (v < 0) return FALSE;
			i |= v << 1;					/* had 1 bit */
			/* FALLTHROUGH */
	case 2:
			v = valmap[*--ip];				/* Input #1 */
			if (v < 0) return FALSE;
			i |= v << 6;					/* had 6 bits */
			*--op = i & 0xff;				/* Output #1 */
			i >>= 8;						/* lower <012> of output #0 */
			/* FALLTHROUGH */
	case 1:
			v = valmap[*--ip];				/* Input #0 */
			if (v < 0) return FALSE;
			i |= v << 3;					/* had 3 bits */
			*--op = i & 0xff;				/* Output #0 */
			i >>= 8;						/* Holds nothing, MBZ */
			g_assert(i == 0);
			g_assert(op >= decbuf);
		} while (op > decbuf);
	}

	return TRUE;
}

/*
 * base32_decode_into
 *
 * Decode `len' bytes from `buf' into `declen' bytes starting from `decbuf'.
 * Caller must have ensured that there was sufficient room in decbuf.
 *
 * Return TRUE if successful, FALSE if the input was not valid base32.
 */
gboolean base32_decode_into(const guchar *buf, gint len,
	guchar *decbuf, gint declen)
{
	return base32_decode_alphabet(values, buf, len, decbuf, declen);
}

/*
 * base32_decode_old_into
 *
 * Decode `len' bytes from `buf' into `declen' bytes starting from `decbuf'.
 * Caller must have ensured that there was sufficient room in decbuf.
 * The "old" base32 alphabet is used for decoding.
 *
 * Return TRUE if successful, FALSE if the input was not valid base32.
 */
gboolean base32_decode_old_into(const guchar *buf, gint len,
	guchar *decbuf, gint declen)
{
	return base32_decode_alphabet(old_values, buf, len, decbuf, declen);
}

/*
 * base32_decode
 *
 * Decode `len' bytes starting at `buf' into new allocated buffer.
 *
 * Returns the new decoded buffer, or NULL if the input was not valid base32
 * encoding.  The caller knows the length of the returned buffer: it's the
 * size of the input divided by 8 and multiplied by 5.
 */
guchar *base32_decode(const guchar *buf, gint len)
{
	gint declen;
	gchar *decbuf;

	if (len & 0x7)					/* Padding bytes missing */
		return NULL;

	declen = (len >> 3) * 5;
	decbuf = g_malloc(declen);

	if (!base32_decode_into(buf, len, decbuf, declen)) {
		g_free(decbuf);
		return NULL;
	}

	return decbuf;
}

