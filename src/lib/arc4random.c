/*
 * Copyright (c) 1996, David Mazieres <dm@lcs.mit.edu>.
 *
 * Adaptated for inclusion in gtk-gnutella by Raphael Manfredi.
 * Copyright (c) 2010, Raphael Manfredi
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
 * Arc4 random number generator.
 *
 * @author Raphael Manfredi
 * @date 2010
 * @author David Mazieres
 * @date 1996
 */

#include "common.h"

#ifndef HAS_ARC4RANDOM

/*
 * Arc4 random number generator for OpenBSD.
 * Copyright 1996 David Mazieres <dm@lcs.mit.edu>.
 *
 * Modification and redistribution in source and binary forms is
 * permitted provided that due credit is given to the author and the
 * OpenBSD project (for instance by leaving this copyright notice
 * intact).
 */

/*
 * This code is derived from section 17.1 of Applied Cryptography,
 * second edition, which describes a stream cipher allegedly
 * compatible with RSA Labs "RC4" cipher (the actual description of
 * which is a trade secret).  The same algorithm is used as a stream
 * cipher called "arcfour" in Tatu Ylonen's ssh package.
 *
 * Here the stream cipher has been modified always to include the time
 * when initializing the state.  That makes it impossible to
 * regenerate the same random sequence twice, so this can't be used
 * for encryption, but will generate good random numbers.
 *
 * RC4 is a registered trademark of RSA Laboratories.
 */

#include "arc4random.h"
#include "entropy.h"
#include "misc.h"		/* For sha1_t */

struct arc4_stream {
	guint8 i;
	guint8 j;
	guint8 s[256];
};

static struct arc4_stream rs;
static gboolean rs_initialized;
static gboolean rs_stired;

static inline guint8 arc4_getbyte(struct arc4_stream *);
static void arc4_stir(struct arc4_stream *);

static inline void
arc4_init(struct arc4_stream *as)
{
	int n;

	for (n = 0; n < 256; n++)
		as->s[n] = n;
	as->i = 0;
	as->j = 0;
}

static inline void
arc4_addrandom(struct arc4_stream *as, const unsigned char *dat, int datlen)
{
	int n;
	guint8 si;

	as->i--;
	for (n = 0; n < 256; n++) {
		as->i = (as->i + 1);
		si = as->s[as->i];
		as->j = (as->j + si + dat[n % datlen]);
		as->s[as->i] = as->s[as->j];
		as->s[as->j] = si;
	}
}

static inline void
arc4_check_init(void)
{
	if G_UNLIKELY(!rs_initialized) {
		arc4_init(&rs);
		rs_initialized = TRUE;
	}
}

static void
arc4_stir(struct arc4_stream *as)
{
	int n;
	sha1_t entropy;

	arc4_check_init();

	entropy_collect(&entropy);
	arc4_addrandom(as, cast_to_gpointer(&entropy), sizeof entropy);

	/*
	 * Throw away the first N bytes of output, as suggested in the
	 * paper "Weaknesses in the Key Scheduling Algorithm of RC4"
	 * by Fluher, Mantin, and Shamir.  N=1024 is based on
	 * suggestions in the paper "(Not So) Random Shuffles of RC4"
	 * by Ilya Mironov.
	 */
	for (n = 0; n < 1024; n++)
		arc4_getbyte(as);
}

static inline G_GNUC_HOT guint8
arc4_getbyte(struct arc4_stream *as)
{
	guint8 si, sj;

	as->i = (as->i + 1);
	si = as->s[as->i];
	as->j = (as->j + si);
	sj = as->s[as->j];
	as->s[as->i] = sj;
	as->s[as->j] = si;

	return (as->s[(si + sj) & 0xff]);
}

static inline G_GNUC_HOT guint32
arc4_getword(struct arc4_stream *as)
{
	guint32 val;

	val = arc4_getbyte(as) << 24;
	val |= arc4_getbyte(as) << 16;
	val |= arc4_getbyte(as) << 8;
	val |= arc4_getbyte(as);

	return (val);
}

static inline ALWAYS_INLINE void
arc4_check_stir(void)
{
	if G_UNLIKELY(!rs_stired) {
		arc4_stir(&rs);
		rs_stired = TRUE;
	}
}

/**
 * Collect random entropy and add it to the random pool.
 *
 * This routine can be optionally called to refresh the random pool.
 * It is otherwise automatically called if not done before, at the first
 * attempt to get random numbers.
 */
void
arc4random_stir(void)
{
	/* THREAD_LOCK(); */
	arc4_stir(&rs);
	/* THREAD_UNLOCK(); */
}

/**
 * Perform random initialization if not already done.
 */
G_GNUC_COLD void
arc4random_stir_once(void)
{
	arc4_check_stir();
}

/**
 * Supply additional randomness to the pool.
 *
 * @param dat		pointer to a buffer containing random data
 * @param datlen	length of the buffer
 */
void
arc4random_addrandom(const unsigned char *dat, int datlen)
{
	g_assert(dat != NULL);
	g_assert(datlen > 0);

	/* THREAD_LOCK(); */
	arc4_check_stir();
	arc4_addrandom(&rs, dat, datlen);
	/* THREAD_UNLOCK(); */
}

/**
 * @return a new 32-bit random number.
 */
G_GNUC_HOT guint32
arc4random(void)
{
	guint32 rnd;

	/* THREAD_LOCK(); */
	arc4_check_stir();
	rnd = arc4_getword(&rs);
	/* THREAD_UNLOCK(); */

	return rnd;
}

#else	/* HAS_ARC4RANDOM */

/**
 * Perform random initialization if not already done.
 *
 * @attention
 * This is a non-standard call, specific to this library.
 */
G_GNUC_COLD void
arc4random_stir_once(void)
{
	static int done;

	if G_UNLIKELY(!done) {
		arc4random_stir();
		done = TRUE;
	}
}

#endif	/* !HAS_ARC4RANDOM */

