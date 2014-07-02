/*
 * Copyright (c) 2006 Francois Panneton and Pierre L'Ecuyer
 *                    University of Montreal
 * Copyright (c) 2006 Makoto Matsumoto, Hiroshima University
 *
 * Adaptated and enhanced for inclusion in gtk-gnutella by Raphael Manfredi.
 * Copyright (c) 2013 Raphael Manfredi
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
 * Well-Equidistributed Long-period Linear (WELL) random number generator.
 *
 * This is adapted from the WELL1024a.c source code published by the
 * authors, with small code reformating according to our library coding style,
 * and to change the API to be consistent with the other PRNG in the library.
 *
 * Original source code written by Geoff was obtained at:
 * http://www.iro.umontreal.ca/~panneton/well/WELL1024a.c
 *
 * Translation of WELL1024a into WELL1024b is based on the article:
 * "Improved Long-Period Generators Based on Linear Recurrences Modulo 2",
 * by Francois Panneton and Pierre L'Ecuyer, published in 2006.
 *
 * @author Francois Panneton, Pierre L'Ecuyer and Makoto Matsumoto
 * @date 2006
 * @author Raphael Manfredi
 * @date 2013
 */

#include "common.h"

#include "well.h"

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
 * The internal state of WELL1024b is 1024 bits, i.e. 32 32-bit words.
 */
#define WELL_STATE_SIZE		32

/**
 * How many steps are required to escape a bad initialization of the state?
 *
 * The value chosen for WELL_STATE_DISCARD is NOT arbitrary.  It is based on
 * the study made by the WELL designers in their article, section 7, "Escaping
 * Zeroland", and was estimated for the WELL1024b algorithm based on the
 * comparisons between WELL800a and WELL19937a.
 */
#define WELL_STATE_DISCARD	128

/*
 * Internal state for the WELL PRNG.  The user can keep multiple state
 * structures around as a way of generating multiple streams of random
 * numbers.
 */

enum well_state_magic { WELL_STATE_MAGIC = 0x1e257513 };

struct well_state {
	enum well_state_magic magic;
	uint32 state[WELL_STATE_SIZE];	/* Vector holding current state */
	uint n;							/* Index in state[] */
	spinlock_t lock;				/* Lock for thread-safe accesses */
};

static void
well_state_check(const struct well_state * const ws)
{
	g_assert(ws != NULL);
	g_assert(WELL_STATE_MAGIC == ws->magic);
}

#define STATE_LOCK(w)	spinlock_hidden(&w->lock)
#define STATE_UNLOCK(w)	spinunlock_hidden(&w->lock)

/* -- section from WELL1024a.c, slightly adapted to handle a well_state_t -- */

/* ************************************************************************* */
/* Copyright:  Francois Panneton and Pierre L'Ecuyer, University of Montreal */
/*             Makoto Matsumoto, Hiroshima University                        */
/* Notice:     This code can be used freely for personal, academic,          */
/*             or non-commercial purposes. For commercial purposes,          */
/*             please contact P. L'Ecuyer at: lecuyer@iro.UMontreal.ca       */
/* ************************************************************************* */

/*
 * NOTES from RAM:
 *
 * We implement WELL1024b, not WELL1024a.
 *
 * The three m1, m2 and m3 constants (3, 24, 10) in WELL1024a are now set
 * to (22, 25, 26) for WELL1024b.
 *
 * For the matrix multiplications, WELL1024a uses the following Ti:
 *
 *   M1       M3(8)     M3(-19)    M3(-14)
 *   M3(-11)  M3(-7)    M3(-13)    M0
 *
 * Whereas for the WELL1024b algorithm, the Ti are the following:
 *
 *   M3(-21)  M3(17)    M4(a3)     M3(15)
 *   M3(-14)  M3(-21)   M1         M0
 *
 * Note the use of the more complex M4 matrix, but there is very little
 * impact on the performance due to a simple optimization, as done in
 * the optimized Mersenne Twister implementation.
 *
 * The reason we're using WELL1024b is due to the greater N1 value for that
 * algorithm (N1=475, whereas it is only 407 for WELL1024a).  See the paper!
 * Since delta is 0 for the two WELL1024 algorithms, no tempering is needed.
 *		--RAM, 2013-12-18
 */

#define R  WELL_STATE_SIZE
#define M1 22			/* m1 */
#define M2 25			/* m2 */
#define M3 26			/* m3 */
#define a3 0x8bdcb91e

/*
 * The Mi matrices are defined in table 1 of Panneton et al (2006):
 * "Improved Long-Period Generators Based on Linear Recurrences Modulo 2".
 *
 * y = Mi x, where Mi is the matrix we're defining.
 *
 * The following definitions were grabbed out of other WELL implementations
 * (from the WELL44497a.c file by the same authors) for completeness, although
 * we do not need all the definitions.
 *
 * I kept the strange MATn numbering that is not in sync with the Mi indices
 * for the corresponding matrices, so that readers can still compare the code
 * with the original published sources.  I do not know why we do not have i == n
 * in all these definitions.  Probably because they were implemented in the
 * order of increasing n, not increasing i...
 *		--RAM, 2013-12-18
 */

/* matrix M3(t) */
#define MAT0POS(t,v) (v^(v>>t))
#define MAT0NEG(t,v) (v^(v<<(-(t))))

/* matrix M1 -- y = x -- Identity */
#define MAT1(v) (v)

/* matrix M4(a) -- y = (x >> 1 ^ a) if x is odd, x >> 1 otherwise */
#define MAT2(a,v) ((v & 1U)?((v>>1)^a):(v>>1))

/* Optimized M4(a) for a = a3 (after optimized Mersenne Twister code) -- RAM */
static const uint32 a3m[] = { 0, a3 };
#define MAT2_A3(v) ((v >> 1) ^ a3m[(v) & 1U])

/* matrix M2(t) -- y = x >> t if t >= 0, x << -t otherwise */
#define MAT3POS(t,v) (v>>t)
#define MAT3NEG(t,v) (v<<(-(t)))

/* matrix M5(t,b) -- unused here */
#define MAT4POS(t,b,v) (v ^ ((v>>   t )  & b))
#define MAT4NEG(t,b,v) (v ^ ((v<<(-(t))) & b))

/* matrix M6(q,s,t,a) -- unused here */
#define MAT5(r,a,ds,dt,v) \
	((v & dt)?((((v<<r)^(v>>(W-r)))&ds)^a):(((v<<r)^(v>>(W-r)))&ds))

/* matrix M0 -- y = 0 -- not explicitly used since "x XOR 0 == x" */
#define MAT6(v) 0

#define MASK		 ((uint) R - 1)
#define m1           (R - 1)		/* -1 modulo R, NOT the "m1" parameter */

#define V0           ws->state[ ws->n           ]
#define VM1          ws->state[(ws->n+M1) & MASK]
#define VM2          ws->state[(ws->n+M2) & MASK]
#define VM3          ws->state[(ws->n+M3) & MASK]
#define VRm1         ws->state[(ws->n+m1) & MASK]
#define newV0        ws->state[(ws->n+m1) & MASK]
#define newV1        ws->state[ ws->n           ]

/**
 * Generate a new 32-bit random number using the supplied WELL state.
 *
 * This generator has a period of 2**1024 - 1 and implements WELL 1024a.
 */
static inline uint32 G_GNUC_UNUSED
well_1024a(well_state_t *ws)		/* UNUSED, for reference only */
{
	uint32 z0, z1, z2;

	z0    = VRm1;
	z1    = MAT1(V0)          ^ MAT0POS(8,   VM1);
	z2    = MAT0NEG(-19, VM2) ^ MAT0NEG(-14, VM3);
	newV1 = z1                ^ z2; 
	newV0 = MAT0NEG(-11, z0)  ^ MAT0NEG(-7,  z1)  ^ MAT0NEG(-13, z2);
	ws->n = (ws->n + m1) & MASK;

	return V0;
}

/* -- end section from WELL1024a.c -- */

/**
 * Generate a new 32-bit random number using the supplied WELL state.
 *
 * This generator has a period of 2**1024 - 1 and implements WELL 1024b.
 *
 * This routine was written by Raphael Manfredi based on the paper and the
 * above matrix definitions, heavily (!) inspired by the above well_1024a()
 * code.
 */
static inline uint32
well_rand_internal(well_state_t *ws)
{
	uint32 z0, z1, z2;

	z0    = VRm1;
	z1    = MAT0NEG(-21, V0)  ^ MAT0POS(17,  VM1);
	z2    = MAT2_A3(VM2)      ^ MAT0POS(15,  VM3);
	newV1 = z1                ^ z2; 
	newV0 = MAT0NEG(-14, z0)  ^ MAT0NEG(-21, z1)  ^ MAT1(z2);
	ws->n = (ws->n + m1) & MASK;

	return V0;
}

/*
 * Discard the first WELL_STATE_DISCARD values to make sure the internal
 * state does not have too many zeroed bits.
 */
static void
well_state_discard(well_state_t *ws)
{
	unsigned i;

	/*
	 * Guard argainst a zeroed state, since then the generator would only
	 * end up producing zeros...
	 */

	for (i = 0; i < G_N_ELEMENTS(ws->state); i++) {
		if G_LIKELY(ws->state != 0)
			goto good;
	}

	ws->state[0] = entropy_random();	/* Will never be 0, in practice */

	if (0 == ws->state[0])
		s_error("%s(): bad luck with random number generator", G_STRFUNC);

good:
	/*
	 * Discarding a "few" values is enough to ensure that the algorithm will
	 * not end-up being biased towards 0.
	 */

	for (i = 0; i < WELL_STATE_DISCARD; i++) {
		(void) well_rand_internal(ws);
	}
}

/**
 * Initialize the state with random values drawn from specified PRNG function.
 *
 * @param rf		random function to initialize the state
 * @param ws		the WELL state we want to initialize
 */
static void
well_seed_with(random_fn_t rf, well_state_t *ws)
{
	if (NULL == rf)
		rf = entropy_random;

	random_bytes_with(rf, &ws->state, sizeof ws->state);
	well_state_discard(ws);
	spinlock_init(&ws->lock);
}

/**
 * Allocate a new state, initialized randomly using supplied random function.
 *
 * If the random function is NULL, the state is initialized with the strong
 * but slow entropy_random().
 *
 * @param rf		random function to initialize the state
 *
 * @return a new state that can be freed with well_state_free_null().
 */
well_state_t *
well_state_new(random_fn_t rf)
{
	well_state_t *ws;

	WALLOC0(ws);
	ws->magic = WELL_STATE_MAGIC;

	well_seed_with(rf, ws);
	return ws;
}

/**
 * Clone WELL state, allowing replay of a random number generation sequence.
 *
 * @param ws		the WELL state to clone
 *
 * @return a copy of the state which can be freed with well_state_free_null().
 */
well_state_t *
well_state_clone(const well_state_t *ws)
{
	well_state_t *cws, *wws;

	well_state_check(ws);

	wws = deconstify_pointer(ws);		/* Only hidden state is changed */

	STATE_LOCK(wws);
	cws = WCOPY(wws);
	STATE_UNLOCK(wws);

	spinlock_init(&cws->lock);			/* Was locked when cloned */

	return cws;
}

/**
 * Free WELL state and nullify its pointer.
 */
void
well_state_free_null(well_state_t **ws_ptr)
{
	well_state_t *ws = *ws_ptr;

	if (ws != NULL) {
		well_state_check(ws);
		spinlock_destroy(&ws->lock);
		WFREE(ws);
		*ws_ptr = NULL;
	}
}

/**
 * Distribute random 32-bit words over the state context.
 */
static void
well_state_patch(well_state_t *ws, const void *data, size_t len)
{
	size_t n;

	g_assert(len <= sizeof ws->state);
	g_assert(0 == (len & 0x3));			/* Multiple of 4 */

	for (n = 0; n < G_N_ELEMENTS(ws->state) && len != 0; n++, len -= 4) {
		ws->state[n] ^= peek_be32(data);
		data = const_ptr_add_offset(data, 4);
	}
}

/**
 * Merge randomness to the WELL state.
 */
static void
well_state_merge_random(well_state_t *ws, const void *data, size_t len)
{
	STATIC_ASSERT(0 == (0x3 & sizeof ws->state));

	while (len >= 4) {
		size_t n = (MIN(len, sizeof ws->state) >> 2) << 2;	/* Multiple of 4 */
		well_state_patch(ws, data, n);
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

		well_state_patch(ws, buf, sizeof buf);
	}

	/*
	 * After changing the state, perform iterations whose aim it is to spread
	 * the bits and limit the impact of having too many bits set to 0 or 1 in
	 * the state.  It is imperative to check that we do not have ALL the
	 * entries in the state set to 0, or we would only end up producing zeroes.
	 */

	well_state_discard(ws);
}

/**
 * Generate a new 64-bit random number using the supplied WELL state.
 */
static uint64
well_rand64_internal(well_state_t *ws)
{
	return ((uint64) well_rand_internal(ws) << 32) | well_rand_internal(ws);
}

/**
 * Generate a random number in the range 0 to 2^32-1, inclusive, working
 * from a given state vector.
 *
 * @param ws	state for the PRNG
 *
 * @return a 32-bit random number
 */
uint32
well_state_rand(well_state_t *ws)
{
	well_state_check(ws);

	return well_rand_internal(ws);
}

/**
 * Generate a random number in the range 0 to 2^64-1, inclusive, working
 * from a given state vector.
 *
 * @param ws	state for the PRNG
 *
 * @return a 64-bit random number
 */
uint64
well_state_rand64(well_state_t *ws)
{
	well_state_check(ws);

	return well_rand64_internal(ws);
}

/**
 * Add randomness to the WELL state.
 *
 * @param ws		the WELL state to which we add randomness
 * @param data		the start of the random data buffer
 * @param len		the amount of random bytes to process in the buffer
 */
void
well_state_addrandom(well_state_t *ws, const void *data, size_t len)
{
	well_state_check(ws);

	well_state_merge_random(ws, data, len);
}

/**
 * Generate a random number in the range 0 to 2^32-1, inclusive, working
 * from a given state vector.
 *
 * @param ws	state for the PRNG, locked before access
 *
 * @return a 32-bit random number
 */
uint32
well_state_lock_rand(well_state_t *ws)
{
	uint32 rn;

	well_state_check(ws);

	STATE_LOCK(ws);
	rn = well_rand_internal(ws);
	STATE_UNLOCK(ws);

	return rn;
}

/**
 * Generate a random number in the range 0 to 2^64-1, inclusive, working
 * from a given state vector.
 *
 * @param ws	state for the PRNG, locked before access
 *
 * @return a 64-bit random number
 */
uint64
well_state_lock_rand64(well_state_t *ws)
{
	uint64 rn;

	well_state_check(ws);

	STATE_LOCK(ws);
	rn = well_rand64_internal(ws);
	STATE_UNLOCK(ws);

	return rn;
}

/**
 * Add randomness to the WELL state, locked.
 *
 * @param ws		the WELL state to which we add randomness
 * @param data		the start of the random data buffer
 * @param len		the amount of random bytes to process in the buffer
 */
void
well_state_lock_addrandom(well_state_t *ws, const void *data, size_t len)
{
	well_state_check(ws);

	STATE_LOCK(ws);
	well_state_merge_random(ws, data, len);
	STATE_UNLOCK(ws);
}

static well_state_t well_default;
static once_flag_t well_seeded;

/**
 * Seed the default state, once.
 */
static void
well_default_seed(void)
{
	well_default.magic = WELL_STATE_MAGIC;
	well_seed_with(NULL, &well_default);
}

/**
 * Generate a random number in the range 0 to 2^32-1, inclusive.
 *
 * @return a 32-bit random number
 */
uint32
well_rand(void)
{
	ONCE_FLAG_RUN(well_seeded, well_default_seed);

	return well_state_lock_rand(&well_default);
}

/**
 * Generate a random number in the range 0 to 2^64-1, inclusive.
 *
 * @return a 64-bit random number
 */
uint64
well_rand64(void)
{
	ONCE_FLAG_RUN(well_seeded, well_default_seed);

	return well_state_lock_rand64(&well_default);
}

/**
 * Add randomness to the default (shared) WELL state.
 *
 * @param ws		the WELL state to which we add randomness
 * @param data		the start of the random data buffer
 * @param len		the amount of random bytes to process in the buffer
 */
void
well_addrandom(const void *data, size_t len)
{
	ONCE_FLAG_RUN(well_seeded, well_default_seed);

	well_state_lock_addrandom(&well_default, data, len);
}

static once_flag_t well_key_inited;
static thread_key_t well_key = THREAD_KEY_INIT;

/**
 * Create the thread-local random pool key, once.
 */
static void
well_key_init(void)
{
	if (-1 == thread_local_key_create(&well_key, THREAD_LOCAL_KEEP))
		s_error("cannot initialize WELL random pool key: %m");
}

/**
 * Get suitable thread-local random pool.
 */
static well_state_t *
well_pool(void)
{
	well_state_t *ws;

	ONCE_FLAG_RUN(well_key_inited, well_key_init);

	ws = thread_local_get(well_key);

	if G_UNLIKELY(NULL == ws) {
		/*
		 * The random pool is kept for each created thread, never freed.
		 */

		OMALLOC0(ws);
		ws->magic = WELL_STATE_MAGIC;
		well_seed_with(arc4random, ws);
		thread_local_set(well_key, ws);
	}

	return ws;
}

/**
 * Generate a random number in the range 0 to 2^32-1, inclusive.
 *
 * This routine uses a thread-private random pool and is mostly a
 * lock-free execution path (about 25% faster than well_rand() with locks)
 *
 * @return a 32-bit random number
 */
uint32
well_thread_rand(void)
{
	return well_rand_internal(well_pool());
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
well_thread_rand64(void)
{
	return well_rand64_internal(well_pool());
}

/**
 * Add randomness to the local WELL state.
 *
 * @param ws		the WELL state to which we add randomness
 * @param data		the start of the random data buffer
 * @param len		the amount of random bytes to process in the buffer
 */
void
well_thread_addrandom(const void *data, size_t len)
{
	well_state_merge_random(well_pool(), data, len);
}

/**
 * @return a list of thread IDs using a thread-local WELL pool, which must
 * be freed with pslist_free().
 */
pslist_t *
well_users(void)
{
	ONCE_FLAG_RUN(well_key_inited, well_key_init);
	
	return thread_local_users(well_key);
}

/* vi: set ts=4 sw=4 cindent: */
