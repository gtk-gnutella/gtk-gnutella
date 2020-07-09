/*
 * Copyright (c) 2003, Jeroen Asselman
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
 *      51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *----------------------------------------------------------------------
 */

/* (PD) 2001 The Bitzi Corporation
 * Please see file COPYING or http://bitzi.com/publicdomain
 * for more info.
 *
 * Created and released into the public domain by Eli Biham
 *
 * $Bitzi: tiger.c,v 1.4 2004/02/01 06:19:31 gojomo Exp $
 */

/**
 * @ingroup lib
 * @file
 *
 * Tiger hash.
 *
 * This file comes from http://www.cs.technion.ac.il/~biham/Reports/Tiger/
 *
 * Inclusion in gtk-gnutella is:
 *
 * @author Jeroen Asselman
 * @date 2003
 */

#include "common.h"

#include "endian.h"
#include "misc.h"
#include "base32.h"
#include "tiger.h"
#include "override.h"		/* Must be the last header included */

/* NOTE that this code is NOT FULLY OPTIMIZED for any  */
/* machine. Assembly code might be much faster on some */
/* machines, especially if the code is compiled with   */
/* gcc.                                                */

/* The number of passes of the hash function.          */
/* Three passes are recommended.                       */
/* Use four passes when you need extra security.       */
/* Must be at least three.                             */
#define PASSES 3

#include "tiger_sboxes.h"

#define U64_FROM_2xU32(hi, lo) (((uint64) (hi) << 32) | (lo))

#define t1 (tiger_sboxes)
#define t2 (&tiger_sboxes[256])
#define t3 (&tiger_sboxes[256*2])
#define t4 (&tiger_sboxes[256*3])

#define save_abc \
      aa = a; \
      bb = b; \
      cc = c;

/* This is the official definition of round */
#define round(a,b,c,x,mul) \
      c ^= x; \
      a -= t1[((c)>>(0*8))&0xFF] ^ t2[((c)>>(2*8))&0xFF] ^ \
	   t3[((c)>>(4*8))&0xFF] ^ t4[((c)>>(6*8))&0xFF] ; \
      b += t4[((c)>>(1*8))&0xFF] ^ t3[((c)>>(3*8))&0xFF] ^ \
	   t2[((c)>>(5*8))&0xFF] ^ t1[((c)>>(7*8))&0xFF] ; \
      b *= mul;

#define pass(a,b,c,mul) \
      round(a,b,c,x[0],mul) \
      round(b,c,a,x[1],mul) \
      round(c,a,b,x[2],mul) \
      round(a,b,c,x[3],mul) \
      round(b,c,a,x[4],mul) \
      round(c,a,b,x[5],mul) \
      round(a,b,c,x[6],mul) \
      round(b,c,a,x[7],mul)

#define key_schedule \
      x[0] -= x[7] ^ U64_FROM_2xU32(0xA5A5A5A5UL, 0xA5A5A5A5UL); \
      x[1] ^= x[0]; \
      x[2] += x[1]; \
      x[3] -= x[2] ^ ((~x[1])<<19); \
      x[4] ^= x[3]; \
      x[5] += x[4]; \
      x[6] -= x[5] ^ ((~x[4])>>23); \
      x[7] ^= x[6]; \
      x[0] += x[7]; \
      x[1] -= x[0] ^ ((~x[7])<<19); \
      x[2] ^= x[1]; \
      x[3] += x[2]; \
      x[4] -= x[3] ^ ((~x[2])>>23); \
      x[5] ^= x[4]; \
      x[6] += x[5]; \
      x[7] -= x[6] ^ U64_FROM_2xU32(0x01234567UL,  0x89ABCDEFUL);

#define feedforward \
      a ^= aa; \
      b -= bb; \
      c += cc;

/* The loop is unrolled: works better on Alpha */
#define compress \
      save_abc \
      pass(a,b,c,5) \
      key_schedule \
      pass(c,a,b,7) \
      key_schedule \
      pass(b,c,a,9) \
      for(pass_no=3; pass_no<PASSES; pass_no++) { \
        key_schedule \
	pass(a,b,c,9) \
	tmpa=a; a=c; c=b; b=tmpa;} \
      feedforward

#define tiger_compress_macro(str, state) \
{ \
  uint64 a, b, c, tmpa; \
  uint64 aa, bb, cc; \
  uint64 x[8]; \
  int pass_no, i; \
\
  a = state[0]; \
  b = state[1]; \
  c = state[2]; \
\
  for (i = 0; i < 8; i++) x[i] = str[i]; \
\
  compress; \
\
  state[0] = a; \
  state[1] = b; \
  state[2] = c; \
}

/* The compress function is a function. Requires smaller cache?    */
static void G_HOT
tiger_compress(const uint64 *data, uint64 state[3])
{
  tiger_compress_macro(data, state);
}

void
tiger(const void *data, uint64 length, char hash[24])
{
  uint64 i, j, res[3];
  const uint8 *data_u8 = data;
  union {
    uint64 u64[8];
    uint8 u8[64];
  } temp;

  res[0] = U64_FROM_2xU32(0x01234567UL, 0x89ABCDEFUL);
  res[1] = U64_FROM_2xU32(0xFEDCBA98UL, 0x76543210UL);
  res[2] = U64_FROM_2xU32(0xF096A5B4UL, 0xC3B2E187UL);

#if IS_BIG_ENDIAN
  for (i = length; i >= 64; i -= 64) {
    for (j = 0; j < 64; j++) {
      temp.u8[j ^ 7] = data_u8[j];
    }
    tiger_compress(temp.u64, res);
    data_u8 += 64;
  }
#else	/* !IS_BIG_ENDIAN */
  if ((ulong) data & 7) {
    for (i = length; i >= 64; i -= 64) {
      memcpy(temp.u64, data_u8, 64);
      tiger_compress(temp.u64, res);
      data_u8 += 64;
    }
  } else {
    for (i = length; i >= 64; i -= 64) {
      tiger_compress((void *) data_u8, res);
      data_u8 += 64;
    }
  }
#endif	/* IS_BIG_ENDIAN */

#if IS_BIG_ENDIAN
  for (j = 0; j < i; j++) {
    temp.u8[j ^ 7] = data_u8[j];
  }

  temp.u8[j ^ 7] = 0x01;
  j++;
  for (; j & 7; j++) {
    temp.u8[j ^ 7] = 0;
  }
#else
  for(j = 0; j < i; j++) {
    temp.u8[j] = data_u8[j];
  }

  temp.u8[j++] = 0x01;
  for (; j & 7; j++) {
    temp.u8[j] = 0;
  }
#endif	/* IS_BIG_ENDIAN */

  if (j > 56) {
    for (; j < 64; j++) {
      temp.u8[j] = 0;
    }
    tiger_compress(temp.u64, res);
    j = 0;
  }

  for (; j < 56; j++) {
    temp.u8[j] = 0;
  }
  temp.u64[7] = length << 3;
  tiger_compress(temp.u64, res);

  for (i = 0; i < 3; i++) {
    poke_le64(&hash[i * 8], res[i]);
  }
}

/* vi: set ai et sts=2 sw=2 cindent: */
/**
 * Runs some test cases to check whether the implementation of the tiger
 * hash algorithm is alright.
 */
void G_COLD
tiger_check(void)
{
	static const char zeros[1025];
    static const struct {
		const char *r;
		const char *s;
		size_t len;
	} tests[] = {
		{ "QMLU34VTTAIWJQM5RVN4RIQKRM2JWIFZQFDYY3Y", "\0" "1", 2 },
		{ "LWPNACQDBZRYXW3VHJVCJ64QBZNGHOHHHZWCLNQ", zeros, 1 },
		{ "VK54ZIEEVTWNAUI5D5RDFIL37LX2IQNSTAXFKSA", zeros, 2 },
		{ "KIU5YUNESS4RH6HAJRGHFHETZOFSMDFE52HKTVY", zeros, 8 },
		{ "Z5PUAX6MEZB6EWYXFCSLMMUMZEFIQPOEWX3BA6Q", zeros, 255 },
		{ "D6UXHPOSAGHITCD4VVRHJQ4PCKIWY2WEHPJOUWY", zeros, 1024 },
		{ "CMKDYROZKSC6VTM4I7LSMMHPAE4UG3FXPXZGGKY", zeros, sizeof zeros },
	};
	uint i;

	for (i = 0; i < N_ITEMS(tests); i++) {
		char hash[24];
		char buf[40];
		bool ok;

		ZERO(&buf);
		tiger(tests[i].s, tests[i].len, hash);
		base32_encode(ARYLEN(buf), ARYLEN(hash));
		buf[N_ITEMS(buf) - 1] = '\0';

		ok = 0 == strcmp(tests[i].r, buf);
		if (!ok) {
			g_warning("i=%u, buf=\"%s\"", i, buf);
			g_assert_not_reached();
		}
	}
}

/* vi: set ts=4 sw=4 cindent: */
