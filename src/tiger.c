/*
 * $Id$
 *
 * This file comes from http://sourceforge.net/projects/tigertree/
 * Inclusion in gtk-gnutella is:
 *
 *   Copyright (c) 20033, Jeroen Asselman
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
 
#include "gnutella.h"

#include "tiger.h"
#include <glib.h>

RCSID("$Id$");

/*
 * The following macro denotes that an optimization 
 * for 64-bit CPUs is required. It is used only for
 * optimization of time. Otherwise it does nothing.
 */
#if !(G_MAXULONG < 0xffffffffffffffffULL)
#	define OPTIMIZE_FOR_64BIT
#endif

/*
 * NOTE that this code is NOT FULLY OPTIMIZED for any
 * machine. Assembly code might be much faster on some
 * machines, especially if the code is compiled with
 * gcc.
 */

/*
 * The number of passes of the hash function.
 * Three passes are recommended.
 * Use four passes when you need extra security.
 * Must be at least three.
 */
#define PASSES 3

guint64 table[4 * 256];

#define t1 (table)
#define t2 (table + 256)
#define t3 (table + 256 * 2)
#define t4 (table + 256 * 3)

#define save_abc \
	aa = a; \
	bb = b; \
	cc = c;

#ifdef OPTIMIZE_FOR_64BIT
	/* This is the official definition of round */
	
#	define round(a, b, c, x, mul) \
		c ^= x; \
		a -= t1[((c) >> (0 * 8)) & 0xFF] ^ t2[((c) >> (2 * 8)) & 0xFF] ^ \
			 t3[((c) >> (4 * 8)) & 0xFF] ^ t4[((c) >> (6 * 8)) & 0xFF] ; \
		b += t4[((c) >> (1 * 8)) & 0xFF] ^ t3[((c) >> (3 * 8)) & 0xFF] ^ \
			 t2[((c) >> (5 * 8)) & 0xFF] ^ t1[((c) >> (7 * 8)) & 0xFF] ; \
		b *= mul;
#else

	/*
	 * This code works faster when compiled on 32-bit machines
	 * (but works slower on Alpha)
	 */
#	define round(a,b,c,x,mul) \
		c ^= x; \
		a -= t1[(gint8) (c)] ^ \
			 t2[(gint8) (((gint32)(c)) >> (2 * 8))] ^ \
			 t3[(gint8) ((c) >> (4 * 8))] ^ \
			 t4[(gint8) (((gint32)((c) >> (4 * 8))) >> (2 * 8))] ; \
		b += t4[(gint8) (((gint32)(c)) >> (1 * 8))] ^ \
			 t3[(gint8) (((gint32)(c)) >> (3 * 8))] ^ \
			 t2[(gint8) (((gint32)((c) >> (4 * 8))) >> (1 * 8))] ^ \
			 t1[(gint8) (((gint32)((c) >> (4 * 8))) >> (3 * 8))]; \
		b *= mul;
#endif

#define pass(a, b, c, mul) \
	round(a, b, c, x0, mul) \
	round(b, c, a, x1, mul) \
	round(c, a, b, x2, mul) \
	round(a, b, c, x3, mul) \
	round(b, c, a, x4, mul) \
	round(c, a, b, x5, mul) \
	round(a, b, c, x6, mul) \
	round(b, c, a, x7, mul)

#define key_schedule \
	x0 -= x7 ^ 0xA5A5A5A5A5A5A5A5LL; \
	x1 ^= x0; \
	x2 += x1; \
	x3 -= x2 ^ ((~x1) << 19); \
	x4 ^= x3; \
	x5 += x4; \
	x6 -= x5 ^ ((~x4) >> 23); \
	x7 ^= x6; \
	x0 += x7; \
	x1 -= x0 ^ ((~x7) << 19); \
	x2 ^= x1; \
	x3 += x2; \
	x4 -= x3 ^ ((~x2) >> 23); \
	x5 ^= x4; \
	x6 += x5; \
	x7 -= x6 ^ 0x0123456789ABCDEFLL;

#define feedforward \
	a ^= aa; \
	b -= bb; \
	c += cc;

#ifdef OPTIMIZE_FOR_64BIT

	/* The loop is unrolled: works better on Alpha */
#	define compress \
		save_abc \
		pass(a, b, c, 5) \
		key_schedule \
		pass(c, a, b, 7) \
		key_schedule \
		pass(b, c, a, 9) \
		for(pass_no = 3; pass_no < PASSES; pass_no++) { \
			key_schedule \
			pass(a, b, c, 9) \
			tmpa = a; a = c; c = b; b = tmpa; \
		} \
		feedforward
#else
		
	/* loop: works better on PC and Sun (smaller cache?) */
#	define compress \
		save_abc \
		for(pass_no = 0; pass_no < PASSES; pass_no++) { \
			if(pass_no != 0) { key_schedule } \
			pass(a, b, c, (pass_no == 0 ? 5 : pass_no == 1 ? 7 : 9)); \
			tmpa = a; a = c; c = b; b = tmpa;\
		} \
		feedforward
#endif

#define tiger_compress_macro(str, state) \
{ \
	register guint64 a, b, c, tmpa; \
	guint64 aa, bb, cc; \
	register guint64 x0, x1, x2, x3, x4, x5, x6, x7; \
	long pass_no; \
\
	a = state[0]; \
	b = state[1]; \
	c = state[2]; \
\
	x0 = str[0]; x1 = str[1]; x2 = str[2]; x3 = str[3]; \
	x4 = str[4]; x5 = str[5]; x6 = str[6]; x7 = str[7]; \
\
	compress; \
\
	state[0] = a; \
	state[1] = b; \
	state[2] = c; \
}

/* The compress function is a function. Requires smaller cache?    */
void tiger_compress(guint64 *str, guint64 state[3])
{
	tiger_compress_macro(((guint64 *) str), ((guint64 *) state));
}

#ifdef OPTIMIZE_FOR_64BIT

	/*
	 * The compress function is inlined: works better on Alpha.
	 * Still leaves the function above in the code, in case some other
	 * module calls it directly.
	 */

#	define tiger_compress(str, state) \
		tiger_compress_macro(((guint64 *) str), ((guint64 *) state))
#endif

void tiger(guint64 *str, guint64 length, guint64 res[3])
{
	register guint64 i, j;
	guint64 temp64[8];
	unsigned char *temp = (unsigned char *) temp64;

	res[0] = 0x0123456789ABCDEFLL;
	res[1] = 0xFEDCBA9876543210LL;
	res[2] = 0xF096A5B4C3B2E187LL;

	for(i = length; i >= 64; i -= 64) {
#if G_BYTE_ORDER == G_BIG_ENDIAN
		for(j = 0; j < 64; j++)
			temp[j ^ 7] = ((gint8 *) str) [j];
		tiger_compress(temp64, res);
#elif G_BYTE_ORDER == G_LITTLE_ENDIAN
		tiger_compress(str, res);
#else
#error Byteorder not supported!
#endif
		str += 8;
	}

#if G_BYTE_ORDER == G_BIG_ENDIAN
	
	for(j = 0; j < i; j++)
		temp[j ^ 7] = ((gint8 *) str) [j];

	temp[j ^ 7] = 0x01;
	j++;
	
	for(; j & 7; j++)
		temp[j^7] = 0;
#elif G_BYTE_ORDER == G_LITTLE_ENDIAN
	
	for(j = 0; j < i; j++)
		temp[j] = ((gint8 *) str) [j];

	temp[j++] = 0x01;
	
	for(; j & 7; j++)
		temp[j] = 0;
#else
#error Byteorder not supported!
#endif
	
	if(j>56) {
		for(; j < 64; j++)
			temp[j] = 0;
		tiger_compress(temp64, res);
		j=0;
	}

	for(; j < 56; j++)
		temp[j] = 0;
	temp64[7] = length << 3;
	tiger_compress(temp64, res);
}
