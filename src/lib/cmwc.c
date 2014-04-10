/*
 * Copyright (c) 2003 George Marsaglia (posting in sci.math)
 *
 * Adaptated and enhanced for inclusion in gtk-gnutella by Raphael Manfredi.
 * Copyright (c) 2014 Raphael Manfredi
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
 * Complimentary Multiply With Carry (CMWC) pseudo random number generator.
 *
 * This is a PRNG with a very large period (about 2**131086 - 1) with a
 * 16388-byte internal state.
 *
 * Here is what the author wrote about it in sci.math:

 * CMWC4096 "provides more than 10**39460 base-b digits in the expansion of
 * (p-1)/p, where p is the prime p = 18782 * b**4096 + 1, b = 2**32 - 1.
 * Those base-b 'digits' are returned in reverse order from a random starting
 * point determined by the random choice of the initial values in Q[4096]
 * and c".
 *
 * This PRNG with a large internal state is useful when generating permutations
 * on large arrays, since we are therefore able to cover more space in the set
 * of all possible permutations (the initial state of the PRNG governs which
 * permutation will be picked among the set of these permutations, which for
 * a set of n items is n!, a number that gets huge very quickly).
 *
 * @author George Marsaglia
 * @date 2003
 * @author Raphael Manfredi
 * @date 2014
 */

#include "common.h"

#include "cmwc.h"

#include "arc4random.h"
#include "endian.h"
#include "entropy.h"
#include "omalloc.h"
#include "once.h"
#include "random.h"
#include "spinlock.h"
#include "thread.h"
#include "walloc.h"

/**
 * The internal state of CMWC4096 is 4096 32-bit words (plus one 32-bit word,
 * the carry word, not counted here).
 */
#define CMWC_STATE_SIZE		4096

/*
 * Initial amount of random values to discard after initialization.
 */
#define CMWC_STATE_DISCARD	(4 * CMWC_STATE_SIZE)

/*
 * Internal state for the CMWC PRNG.  The user can keep multiple state
 * structures around as a way of generating multiple streams of random
 * numbers.
 */

enum cmwc_state_magic { CMWC_STATE_MAGIC = 0x10cd2a91 };

struct cmwc_state {
	enum cmwc_state_magic magic;
	uint32 Q[CMWC_STATE_SIZE];		/* Current state */
	uint32 c;						/* The 32-bit carry word */
	uint32 i;						/* Internal index within the state */
	spinlock_t lock;				/* Lock for thread-safe accesses */
};

static void
cmwc_state_check(const struct cmwc_state * const cs)
{
	g_assert(cs != NULL);
	g_assert(CMWC_STATE_MAGIC == cs->magic);
}

#define STATE_LOCK(c)	spinlock_hidden(&(c)->lock)
#define STATE_UNLOCK(c)	spinunlock_hidden(&(c)->lock)

#define CMWC_STATE_MASK	(CMWC_STATE_SIZE - 1)

/**
 * Generate a new 32-bit random number using the supplied CMWC state.
 *
 * This generator has an approximative period of 2**131086 - 1.
 *
 * (Routine adapted by RAM from code posted by George Marsaglia on sci.math)
 */
static inline uint32
cmwc_rand_internal(cmwc_state_t *cs)
{
	uint64 t;
	uint32 x;

	cs->i = (cs->i + 1) & CMWC_STATE_MASK;
	t = (uint64) 18782 * cs->Q[cs->i] + cs->c;
	cs->c = t >> 32;
	x = t + cs->c;

	if (x < cs->c) {
		x++;
		cs->c++;
	}

	return cs->Q[cs->i] = 0xfffffffeU - x;
}

/*
 * Discard the first CMWC_STATE_DISCARD values to make sure the internal
 * state is random enough.
 */
static void
cmwc_state_discard(cmwc_state_t *cs)
{
	unsigned i;

	for (i = 0; i < CMWC_STATE_DISCARD; i++) {
		(void) cmwc_rand_internal(cs);
	}
}

/**
 * Initialize the state with random values drawn from specified PRNG function.
 *
 * @param rf		random function to initialize the state
 * @param cs		the CMWC state we want to initialize
 */
static void
cmwc_seed_with(random_fn_t rf, cmwc_state_t *cs)
{
	if (NULL == rf)
		rf = entropy_random;

	random_bytes_with(rf, &cs->Q, sizeof cs->Q);
	cs->c = entropy_random();	/* Regardless of passed function */
	cs->i = CMWC_STATE_SIZE - 1;
	cmwc_state_discard(cs);
	spinlock_init(&cs->lock);
}

/**
 * Allocate a new state, initialized randomly using supplied random function.
 *
 * If the random function is NULL, the state is initialized with the strong
 * but slow entropy_random().
 *
 * @param rf		random function to initialize the state
 *
 * @return a new state that can be freed with cmwc_state_free_null().
 */
cmwc_state_t *
cmwc_state_new(random_fn_t rf)
{
	cmwc_state_t *cs;

	WALLOC0(cs);
	cs->magic = CMWC_STATE_MAGIC;

	cmwc_seed_with(rf, cs);
	return cs;
}

/**
 * Clone CMWC state, allowing replay of a random number generation sequence.
 *
 * @param cs		the CMWC state to clone
 *
 * @return a copy of the state which can be freed with cmwc_state_free_null().
 */
cmwc_state_t *
cmwc_state_clone(const cmwc_state_t *cs)
{
	cmwc_state_t *ccs, *wcs;

	cmwc_state_check(cs);

	wcs = deconstify_pointer(cs);		/* Only hidden state is changed */

	STATE_LOCK(wcs);
	ccs = WCOPY(wcs);
	STATE_UNLOCK(wcs);

	spinlock_init(&ccs->lock);			/* Was locked when cloned */

	return ccs;
}

/**
 * Free CMWC state and nullify its pointer.
 */
void
cmwc_state_free_null(cmwc_state_t **cs_ptr)
{
	cmwc_state_t *cs = *cs_ptr;

	if (cs != NULL) {
		cmwc_state_check(cs);
		spinlock_destroy(&cs->lock);
		WFREE(cs);
		*cs_ptr = NULL;
	}
}

/**
 * Distribute random 32-bit words over the state context.
 */
static void
cmwc_state_patch(cmwc_state_t *cs, const void *data, size_t len)
{
	size_t n;

	g_assert(len <= sizeof cs->Q);
	g_assert(0 == (len & 0x3));			/* Multiple of 4 */

	for (n = 0; n < G_N_ELEMENTS(cs->Q) && len != 0; n++, len -= 4) {
		cs->Q[n] ^= peek_be32(data);
		data = const_ptr_add_offset(data, 4);
	}
}

/**
 * Merge randomness to the CMWC state.
 */
static void
cmwc_state_merge_random(cmwc_state_t *cs, const void *data, size_t len)
{
	STATIC_ASSERT(0 == (0x3 & sizeof cs->Q));

	while (len >= 4) {
		size_t n = (MIN(len, sizeof cs->Q) >> 2) << 2;	/* Multiple of 4 */
		cmwc_state_patch(cs, data, n);
		data = const_ptr_add_offset(data, n);
		len -= n;
	}

	if (len < 4) {
		char buf[4];
		size_t i;

		ZERO(&buf);
		for (i = 0; i < len; i++) {
			buf[i] = ((char *) data)[i];
		}

		cmwc_state_patch(cs, buf, sizeof buf);
	}

	/*
	 * After changing the state, perform iterations whose aim it is to spread
	 * the bits we just added, in case they are not too random.
	 */

	cmwc_state_discard(cs);
}

/**
 * Generate a new 64-bit random number using the supplied CMWC state.
 */
static uint64
cmwc_rand64_internal(cmwc_state_t *cs)
{
	return ((uint64) cmwc_rand_internal(cs) << 32) | cmwc_rand_internal(cs);
}

/**
 * Generate a random number in the range 0 to 2^32-1, inclusive, working
 * from a given state vector.
 *
 * @param cs	state for the PRNG
 *
 * @return a 32-bit random number
 */
uint32
cmwc_state_rand(cmwc_state_t *cs)
{
	cmwc_state_check(cs);

	return cmwc_rand_internal(cs);
}

/**
 * Generate a random number in the range 0 to 2^64-1, inclusive, working
 * from a given state vector.
 *
 * @param cs	state for the PRNG
 *
 * @return a 64-bit random number
 */
uint64
cmwc_state_rand64(cmwc_state_t *cs)
{
	cmwc_state_check(cs);

	return cmwc_rand64_internal(cs);
}

/**
 * Add randomness to the CMWC state.
 *
 * @param cs		the CMWC state to which we add randomness
 * @param data		the start of the random data buffer
 * @param len		the amount of random bytes to process in the buffer
 */
void
cmwc_state_addrandom(cmwc_state_t *cs, const void *data, size_t len)
{
	cmwc_state_check(cs);

	cmwc_state_merge_random(cs, data, len);
}

/**
 * Generate a random number in the range 0 to 2^32-1, inclusive, working
 * from a given state vector.
 *
 * @param cs	state for the PRNG, locked before access
 *
 * @return a 32-bit random number
 */
uint32
cmwc_state_lock_rand(cmwc_state_t *cs)
{
	uint32 rn;

	cmwc_state_check(cs);

	STATE_LOCK(cs);
	rn = cmwc_rand_internal(cs);
	STATE_UNLOCK(cs);

	return rn;
}

/**
 * Generate a random number in the range 0 to 2^64-1, inclusive, working
 * from a given state vector.
 *
 * @param cs	state for the PRNG, locked before access
 *
 * @return a 64-bit random number
 */
uint64
cmwc_state_lock_rand64(cmwc_state_t *cs)
{
	uint64 rn;

	cmwc_state_check(cs);

	STATE_LOCK(cs);
	rn = cmwc_rand64_internal(cs);
	STATE_UNLOCK(cs);

	return rn;
}

/**
 * Add randomness to the CMWC state, locked.
 *
 * @param cs		the CMWC state to which we add randomness
 * @param data		the start of the random data buffer
 * @param len		the amount of random bytes to process in the buffer
 */
void
cmwc_state_lock_addrandom(cmwc_state_t *cs, const void *data, size_t len)
{
	cmwc_state_check(cs);

	STATE_LOCK(cs);
	cmwc_state_merge_random(cs, data, len);
	STATE_UNLOCK(cs);
}

static cmwc_state_t cmwc_default;
static once_flag_t cmwc_seeded;

/**
 * Seed the default state, once.
 */
static void
cmwc_default_seed(void)
{
	cmwc_default.magic = CMWC_STATE_MAGIC;
	cmwc_seed_with(NULL, &cmwc_default);
}

/**
 * Generate a random number in the range 0 to 2^32-1, inclusive.
 *
 * @return a 32-bit random number
 */
uint32
cmwc_rand(void)
{
	ONCE_FLAG_RUN(cmwc_seeded, cmwc_default_seed);

	return cmwc_state_lock_rand(&cmwc_default);
}

/**
 * Generate a random number in the range 0 to 2^64-1, inclusive.
 *
 * @return a 64-bit random number
 */
uint64
cmwc_rand64(void)
{
	ONCE_FLAG_RUN(cmwc_seeded, cmwc_default_seed);

	return cmwc_state_lock_rand64(&cmwc_default);
}

/**
 * Add randomness to the default (shared) CMWC state.
 *
 * @param cs		the CMWC state to which we add randomness
 * @param data		the start of the random data buffer
 * @param len		the amount of random bytes to process in the buffer
 */
void
cmwc_addrandom(const void *data, size_t len)
{
	ONCE_FLAG_RUN(cmwc_seeded, cmwc_default_seed);

	cmwc_state_lock_addrandom(&cmwc_default, data, len);
}

static once_flag_t cmwc_key_inited;
static thread_key_t cmwc_key = THREAD_KEY_INIT;

/**
 * Create the thread-local random pool key, once.
 */
static void
cmwc_key_init(void)
{
	if (-1 == thread_local_key_create(&cmwc_key, THREAD_LOCAL_KEEP))
		s_error("cannot initialize CMWC random pool key: %m");
}

/**
 * Get suitable thread-local random pool.
 */
static cmwc_state_t *
cmwc_pool(void)
{
	cmwc_state_t *cs;

	ONCE_FLAG_RUN(cmwc_key_inited, cmwc_key_init);

	cs = thread_local_get(cmwc_key);

	if G_UNLIKELY(NULL == cs) {
		/*
		 * The random pool is kept for each created thread, never freed.
		 */

		OMALLOC0(cs);
		cs->magic = CMWC_STATE_MAGIC;
		cmwc_seed_with(arc4random, cs);
		thread_local_set(cmwc_key, cs);
	}

	return cs;
}

/**
 * Generate a random number in the range 0 to 2^32-1, inclusive.
 *
 * This routine uses a thread-private random pool and is mostly a
 * lock-free execution path (about 25% faster than cmwc_rand() with locks)
 *
 * @return a 32-bit random number
 */
uint32
cmwc_thread_rand(void)
{
	return cmwc_rand_internal(cmwc_pool());
}

/**
 * Generate a random number in the range 0 to 2^64-1, inclusive.
 *
 * This routine uses a thread-private random pool and is mostly a
 * lock-free execution path.
 *
 * @return a 64-bit random number
 */
uint64
cmwc_thread_rand64(void)
{
	return cmwc_rand64_internal(cmwc_pool());
}

/**
 * Add randomness to the local CMWC state.
 *
 * @param cs		the CMWC state to which we add randomness
 * @param data		the start of the random data buffer
 * @param len		the amount of random bytes to process in the buffer
 */
void
cmwc_thread_addrandom(const void *data, size_t len)
{
	cmwc_state_merge_random(cmwc_pool(), data, len);
}

/**
 * @return a list of thread IDs using a thread-local CMWC pool, which must
 * be freed with pslist_free().
 */
pslist_t *
cmwc_users(void)
{
	ONCE_FLAG_RUN(cmwc_key_inited, cmwc_key_init);
	
	return thread_local_users(cmwc_key);
}

/* vi: set ts=4 sw=4 cindent: */
