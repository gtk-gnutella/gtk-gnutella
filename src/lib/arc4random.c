/*
 * Copyright (c) 1996, David Mazieres <dm@lcs.mit.edu>.
 *
 * Adaptated for inclusion in gtk-gnutella by Raphael Manfredi.
 * Copyright (c) 2010, 2012-2013 Raphael Manfredi
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
 * ARC4 random number generator.
 *
 * The arc4random() function uses the key stream generator employed by the
 * ARC4 cipher, which uses 256 8-bit S-Boxes.  The S-Boxes can be in about
 * 2^1700 states.
 *
 * There is no need to call arc4random_stir() before using arc4random()
 * since initialization happens auto-magically.  The initial seed is collected
 * through entropy_collect(), which supplies 160 random bits.
 *
 * The arc4random_upto64() routine has been added to David Mazieres's code
 * to provide uniformly distributed random numbers over a certain range.
 *
 * The code has also been extended to provide thread-local ARC4 streams, which
 * can generate random numbers without taking locks, resulting in a substantial
 * increased throughput.
 *
 * @author David Mazieres
 * @date 1996
 * @author Raphael Manfredi
 * @date 2010, 2012-2013
 */

#include "common.h"

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
#include "omalloc.h"
#include "once.h"
#include "pslist.h"
#include "spinlock.h"
#include "thread.h"

#define ARC4_BOXES		256

struct arc4_stream {
	uint8 i;
	uint8 j;
	uint8 initialized;
	uint8 s[ARC4_BOXES];
};

static inline uint8 arc4_getbyte(struct arc4_stream *);
static void arc4_stir(struct arc4_stream *);

static inline void
arc4_init(struct arc4_stream *as)
{
	int n;

	for (n = 0; n < ARC4_BOXES; n++)
		as->s[n] = n;
	as->i = 0;
	as->j = 0;
}

static inline void
arc4_addrandom(struct arc4_stream *as, const unsigned char *dat, int datlen)
{
	while (datlen > 0) {
		int n;

		as->i--;
		for (n = 0; n < ARC4_BOXES; n++) {
			uint8 si;
			as->i++;
			si = as->s[as->i];
			as->j += si + dat[n % datlen];
			as->s[as->i] = as->s[as->j];
			as->s[as->j] = si;
		}

		dat += ARC4_BOXES;
		datlen -= ARC4_BOXES;
	}
}

static void
arc4_stir(struct arc4_stream *as)
{
	int n;

	if G_UNLIKELY(!as->initialized) {
		arc4_init(as);
		as->initialized = TRUE;
	}

	/*
	 * Collect 1024 bytes of initial entropy: the more randomness there
	 * is in the initial state, the more random combinations we can produce
	 * after initialization.
	 */

	for (n = 0; n < 4; n++) {
		unsigned char buf[ARC4_BOXES];

		entropy_fill(buf, sizeof buf);
		arc4_addrandom(as, buf, sizeof buf);
	}

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

static inline G_GNUC_HOT uint8
arc4_getbyte(struct arc4_stream *as)
{
	uint8 si, sj;

	as->i++;
	si = as->s[as->i];
	as->j += si;
	sj = as->s[as->j];
	as->s[as->i] = sj;
	as->s[as->j] = si;

	return as->s[(si + sj) & 0xff];
}

static inline G_GNUC_HOT uint32
arc4_getword(struct arc4_stream *as)
{
	uint32 val;

	val = arc4_getbyte(as) << 24;
	val |= arc4_getbyte(as) << 16;
	val |= arc4_getbyte(as) << 8;
	val |= arc4_getbyte(as);

	return (val);
}

#ifndef HAS_ARC4RANDOM

static spinlock_t arc4_lck = SPINLOCK_INIT;

#define ARC4_LOCK		spinlock_hidden(&arc4_lck)
#define ARC4_UNLOCK		spinunlock_hidden(&arc4_lck)

static struct arc4_stream rs;
static bool rs_stired;

static inline ALWAYS_INLINE void
arc4_check_stir(void)
{
	if G_UNLIKELY(!rs_stired) {
		rs_stired = TRUE;
		arc4_stir(&rs);
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
	ARC4_LOCK;
	arc4_stir(&rs);
	ARC4_UNLOCK;
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

	ARC4_LOCK;
	arc4_check_stir();
	arc4_addrandom(&rs, dat, datlen);
	ARC4_UNLOCK;
}

/**
 * @return a new 32-bit random number.
 */
G_GNUC_HOT uint32
arc4random(void)
{
	uint32 rnd;

	ARC4_LOCK;
	arc4_check_stir();
	rnd = arc4_getword(&rs);
	ARC4_UNLOCK;

	return rnd;
}

/**
 * @return 64-bit random number.
 */
uint64
arc4random64(void)
{
	uint32 hi, lo;

	ARC4_LOCK;
	arc4_check_stir();
	hi = arc4_getword(&rs);
	lo = arc4_getword(&rs);
	ARC4_UNLOCK;

	return ((uint64) hi << 32) | (uint64) lo;
}
#else
/**
 * @return 64-bit random number.
 */
uint64
arc4random64(void)
{
	return ((uint64) arc4random() << 32) | (uint64) arc4random();
}
#endif	/* !HAS_ARC4RANDOM */

/**
 * Perform random initialization if not already done.
 *
 * @attention
 * This is a non-standard call, specific to this library.
 */
G_GNUC_COLD void
arc4random_stir_once(void)
{
	static once_flag_t done;

	once_flag_run(&done, arc4random_stir);
}

/***
 *** Thread-private ARC4 streams, to avoid locking.
 ***/

static once_flag_t arc4_key_inited;
static thread_key_t arc4_key = THREAD_KEY_INIT;

/**
 * Create the thread-local random stream key, once.
 */
static void
arc4_key_init(void)
{
	if (-1 == thread_local_key_create(&arc4_key, THREAD_LOCAL_KEEP))
		s_error("cannot initialize ARC4 random stream key: %m");
}

/**
 * Get suitable thread-local random stream.
 */
static struct arc4_stream *
arc4_stream(void)
{
	struct arc4_stream *as;

	ONCE_FLAG_RUN(arc4_key_inited, arc4_key_init);

	as = thread_local_get(arc4_key);

	if G_UNLIKELY(NULL == as) {
		/*
		 * The random stream is kept for each created thread and is never freed.
		 */

		OMALLOC0(as);
		arc4_init(as);
		arc4_stir(as);
		thread_local_set(arc4_key, as);
	}

	return as;
}

/**
 * @return a new 32-bit random number (from thread-local stream).
 */
G_GNUC_HOT uint32
arc4_rand(void)
{
	return arc4_getword(arc4_stream());
}

/**
 * @return 64-bit random number (from thread-local stream).
 */
uint64
arc4_rand64(void)
{
	struct arc4_stream *as = arc4_stream();
	uint32 hi, lo;

	hi = arc4_getword(as);
	lo = arc4_getword(as);

	return ((uint64) hi << 32) | (uint64) lo;
}

/**
 * Supply additional randomness to the thread-local pool.
 *
 * @param dat		pointer to a buffer containing random data
 * @param datlen	length of the buffer
 */
void
arc4_thread_addrandom(const unsigned char *dat, int datlen)
{
	g_assert(dat != NULL);
	g_assert(datlen > 0);

	arc4_addrandom(arc4_stream(), dat, datlen);
}

/**
 * @return a list of thread IDs using a thread-local ARC4 pool, which must
 * be freed with pslist_free().
 */
pslist_t *
arc4_users(void)
{
	ONCE_FLAG_RUN(arc4_key_inited, arc4_key_init);

	return thread_local_users(arc4_key);
}

/* vi: set ts=4 sw=4 cindent: */
