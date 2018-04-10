/*
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
 * Alea Jacta Est (AJE) -- a pseudo RNG inspired by Fortuna and Yarrow.
 *
 * This is a random number generator based on the Fortuna design, mostly,
 * but with some adjustments:
 *
 * - It uses only 23 pools instead of 32: because pool #n is only used 1/(2**n)
 *   of a time and there can be a reseed every 0.1 second, the 23rd pool will
 *   be used after (2**23)/10 seconds, or 9.7 days...  That's large enough
 *   for AJE, since we're not going to reseed at the maximum speed, so the
 *   actual time will be more than that.
 *
 * - It relies on modulo bias to distribute entropy more frequently to the
 *   3 lower pools, which are the ones used more often during reseeds.
 *
 * - It uses SHA1 instead of SHA256 to hash the entropy in each pool.
 *
 * - It does not reset the SHA1 context in pools, rather it carries forward
 *   its state.  This was a feature of Yarrow (ability to query the final
 *   hash without resetting the computation context).
 *
 * - It uses XXTEA (the Corrected Block Tiny Encryption Algorithm) instead
 *   of AES to perform the encryption.
 *
 * The high-level description of Fortuna can be read here:
 *		http://en.wikipedia.org/wiki/Fortuna_(PRNG)
 *
 * This implementation of AJE was heavily inspired by the implementation
 * of Fortuna by Marko Kreen, which appeared in libfortuna and can be found
 * there:
 *		https://github.com/waitman/libfortuna.git
 *
 * Including the SHA2 hashing routines and AES was deemed unnecessary for now
 * to have a "real" Fortuna implementation (2013-12-27).
 *
 * Using SHA1 means that we limit the entropy collected to 160 bits.  But
 * the encryption keys are only 128-bit long, therefore our AJE algorithm
 * has only a 128-bit security strength.
 *
 * When generating bytes without any re-seeding happening, the overall state
 * context is an 8-byte counter and a 16-byte key, hence the period of the
 * PRNG is bound by 2**192 - 1.
 *
 * However, when re-seeding happens, and even though the internal context is
 * finite and therefore bound to experience repetitions over the long run,
 * the ordering of these repetitions depends on external factors (the collected
 * entropy).  Therefore, the PRNG becomes non-periodic.
 *
 * This current AJE implementation with SHA1 and XXTEA passes 99.91% of the
 * FIPS 140-2 tests on the average and does not fail any of the dieharder
 * tests, hence it is a good source of randomness (as good as /dev/urandom).
 *
 *		./random-test -Al -T | rngtest -c 1000000
 *		./random-test -Al -T | dieharder -g 200 -a
 *
 * @author Raphael Manfredi
 * @date 2013
 */

#include "common.h"

#include "aje.h"

#include "entropy.h"
#include "mempcpy.h"
#include "omalloc.h"
#include "once.h"
#include "pslist.h"
#include "random.h"
#include "sha1.h"
#include "pow2.h"				/* For IS_POWER_OF_2() */
#include "spinlock.h"
#include "thread.h"
#include "tm.h"
#include "unsigned.h"
#include "xxtea.h"

#include "override.h"			/* Must be the last header included */

#define AJE_POOLS			23			/* amount of pools used */
#define AJE_RESEED_INTERVAL	100000		/* us: 0.1 seconds */

/*
 * This is the maximum amount of bytes we can serve in a large request before
 * forcefully changing the key, to avoid giving out too many bytes with the
 * same key: if our internal counter is known, that would give a golden
 * plain-text attack opportunity.
 */
#define AJE_REKEY_BYTES	(64*1024)	/* new key after that many bytes given */

/*
 * This is the minimum amount of bytes that must be first added to pool #0.
 */
#define AJE_POOL0_FILL		32

/*
 * The minimum amount of entropy bytes we attempt to give to a single pool
 * when adding external entropy.
 */
#define AJE_POOL_MIN		MAX(8, sizeof(void *))

/*
 * The maximum amount of entropy bytes we attempt to give to a single pool
 * when adding external entropy.
 */
#define AJE_POOL_MAX		48

/*
 * The length of the digest for the pool hashing routine, in bytes.
 */
#define AJE_DIGEST_LEN		SHA1_RAW_SIZE

/*
 * The length of the cipher key size, which must be at most AJE_DIGEST_LEN.
 */
#define AJE_CIPHER_KEYLEN	XXTEA_KEY_SIZE

/*
 * The length of the ciher blocks.
 */
#define AJE_CIPHER_BLOCKLEN	XXTEA_BLOCK_SIZE

/*
 * For speed, we generate a pool of random numbers and then serve them.
 */
#define AJE_RANDOM_COUNT	512

/**
 * Amount of 32-bit words in the counter.
 */
#define AJE_COUNTER_WORDS	(AJE_CIPHER_BLOCKLEN / 4)

enum aje_magic { AJE_MAGIC = 0x5351db40 };

/**
 * The AJE context.
 */
typedef struct aje_state {
	enum aje_magic magic;				/* Magic number */
	int sp;								/* Amount of numbers held in vec[] */
	uint32 counter[AJE_COUNTER_WORDS];	/* The counter we encrypt */
	uint8 key[AJE_CIPHER_KEYLEN];		/* Current key used */
	tm_t last_reseed;					/* When we last reseeded */
	SHA1_context pool[AJE_POOLS];		/* The entropy pools */
	uint32 vec[AJE_RANDOM_COUNT];		/* Generated random numbers */
	size_t pool0_bytes;					/* Bytes added to pool #0 */
	size_t reseed_count;				/* Amount of reseeds done */
	uint32 krnd;						/* Byte index in key[] */
	unsigned spread:1;					/* Whether we ran initial spreading */
	spinlock_t lock;					/* Thread-safe lock */
} aje_state_t;

static inline void
aje_check(const struct aje_state * const as)
{
	g_assert(as != NULL);
	g_assert(AJE_MAGIC == as->magic);
}

#define AJE_STATE_LOCK(a)		spinlock_hidden(&(a)->lock)
#define AJE_STATE_UNLOCK(a)		spinunlock_hidden(&(a)->lock)

/**
 * Increment counter, so that it changes without repeating itself, ever.
 */
static void
aje_counter_inc(aje_state_t *as)
{
	uint i;

	aje_check(as);

	for (i = 0; i < N_ITEMS(as->counter); i++) {
		if G_LIKELY(0 != ++as->counter[i])
			break;
	}
}

/**
 * Encrypt data.
 *
 * @param as		the AJE state
 * @param in		the data to encrypt
 * @param out		where data should be encrypted
 * @param len		amount of data to encrypt (size of both ``in'' and ``out'')
 */
static  void
aje_encrypt(const aje_state_t *as, void *in, void *out, size_t len)
{
	xxtea_encrypt((xxtea_key_t *) as->key, out, in, len);
}

/**
 * Encrypt counter, then increment it.
 * This is what the litterature calls "cipher in counter mode".
 *
 * @param as		the AJE state
 * @param dest		where encryption should be done
 * @param len		destination length
 */
static void
aje_counter_encrypt(aje_state_t *as, void *dest, size_t len)
{
	aje_check(as);
	g_assert(sizeof as->counter == len);

	aje_encrypt(as, as->counter, dest, len);
	aje_counter_inc(as);
}

/**
 * Are we allowed to reseed?
 */
static bool
aje_may_reseed(const aje_state_t *as)
{
	tm_t now;

	aje_check(as);

	/*
	 * Ensure we are always reseeding the first time we are called!
	 */

	if G_UNLIKELY(0 == as->reseed_count)
		return TRUE;

	tm_now_exact(&now);

	return tm_elapsed_us(&now, &as->last_reseed) >= AJE_RESEED_INTERVAL;
}

/**
 * Generate new encryption key from all the pools we can use.
 */
static void
aje_reseed(aje_state_t *as)
{
	uint k;
	size_t n, offset;
	SHA1_context kctx;
	sha1_t buf;

	aje_check(as);

	as->pool0_bytes = 0;		/* pool is now empty */

	/*
	 * Since both pool #0 and #1 would use only pool #0 for reseeding, we
	 * skip pool #0 in our count and go directly with n=1 initially.
	 * Hence the pre-incrementation.
	 */

	n = ++as->reseed_count;

	/*
	 * We want to use the k-th pool only 1/(2**k) of the time.
	 */

	SHA1_reset(&kctx);

	for (k = 0; k < N_ITEMS(as->pool) && n != 0; k++, n >>= 1) {
		/*
		 * The SHA1 is finalized, but the SHA1 context is kept intact so that
		 * new entropy added to the pool will add to the previous hash context.
		 */

		SHA1_intermediate(&as->pool[k], &buf);
		SHA1_INPUT(&kctx, buf);

		if (n & 1)
			break;
	}

	/*
	 * If the key is smaller than the SHA1 buffer, we can randomly offset
	 * the key start within the buffer to add more entropy.
	 */

#define AJE_EXTRABYTES	(AJE_DIGEST_LEN - AJE_CIPHER_KEYLEN)

	if (AJE_DIGEST_LEN > AJE_CIPHER_KEYLEN) {
		/*
		 * We avoid modulo bias by masking an entire set of trailing bits.
		 * Surely, that limits the amount of values ``offset'' can take by
		 * removing the upper value AJE_EXTRABYTES, but it simplifies code.
		 */

		STATIC_ASSERT(IS_POWER_OF_2(AJE_EXTRABYTES));
		g_assert(as->krnd < N_ITEMS(as->key));

		offset = as->key[as->krnd] & (AJE_EXTRABYTES - 1);
	} else {
		offset = 0;
	}

#undef AJE_EXTRABYTES

	/*
	 * Add the old key, the current counter and the previous reseed time into
	 * the mix, then generate the new encryption key.
	 */

	SHA1_INPUT(&kctx, as->key);
	SHA1_INPUT(&kctx, as->counter);
	SHA1_INPUT(&kctx, as->last_reseed);
	SHA1_result(&kctx, &buf);

	STATIC_ASSERT(sizeof as->key <= sizeof buf);
	g_assert(offset + sizeof as->key <= sizeof buf);

	memcpy(as->key, ptr_add_offset(&buf, offset), sizeof as->key);
	as->krnd = 0;

	/*
	 * Clear intermediate values from the stack.
	 */

	ZERO(&kctx);
	ZERO(&buf);

	/*
	 * Record time at which we last performed the reseed.
	 *
	 * We use the cached time, which was at least computed when we called
	 * aje_may_reseed() so we know it's recent enough.
	 */

	tm_now(&as->last_reseed);
}

/**
 * Change the encryption key.
 */
static void
aje_rekey(aje_state_t *as)
{
	uint8 buf[AJE_CIPHER_BLOCKLEN];
	uint8 key[AJE_CIPHER_KEYLEN];
	size_t i;

	aje_check(as);

	/*
	 * The new key is made out of the next encrypted counters.
	 *
	 * We need to generate the new key in a separate buffer on the stack
	 * because as->key is still needed to encrypt the counters (the key is
	 * larger than the counters).
	 *
	 * We make no assumption here at how much larger the key is compared to
	 * the counters, but it needs to be at least as large as the counters
	 * we encrypt, or the algorithm would be weakend.  Hence the static assert.
	 */

	STATIC_ASSERT(AJE_CIPHER_BLOCKLEN <= AJE_CIPHER_KEYLEN);

	for (i = 0; i < AJE_CIPHER_KEYLEN; i+= AJE_CIPHER_BLOCKLEN) {
		size_t r;		/* Remaining bytes to fill the key */

		aje_counter_encrypt(as, ARYLEN(buf));
		r = AJE_CIPHER_KEYLEN - i;
		memcpy(&key[i], buf, MIN(r, sizeof buf));
	}

	STATIC_ASSERT(sizeof as->key == sizeof key);

	/*
	 * Update the encryption key and reset the key random index.
	 */

	memcpy(as->key, ARYLEN(key));
	as->krnd = 0;

	/*
	 * Clear stack, covering our tracks.
	 */

	ZERO(&buf);
	ZERO(&key);
}

/**
 * Generate a random byte.
 */
static uint8
aje_random_byte(aje_state_t *as)
{
	uint8 b;

	aje_check(as);
	g_assert(as->krnd < N_ITEMS(as->key));

	/*
	 * Use the key bytes as our random source.
	 */

	b = as->key[as->krnd++];

	if G_UNLIKELY(as->krnd >= N_ITEMS(as->key))
		aje_rekey(as);				/* Get fresh randomness source */

	return b;
}

/**
 * Pick a random pool to update.
 */
static uint
aje_random_pool(aje_state_t *as)
{
	aje_check(as);

	/*
	 * The modulo bias is OK: it will slightly prefer lower pools.
	 */

	STATIC_ASSERT(MAX_INT_VAL(uint8) >= N_ITEMS(as->pool));

	return aje_random_byte(as) % N_ITEMS(as->pool);
}

/**
 * Pick a random amount of bytes to process, at least AJE_POOL_MIN if there
 * are enough data left, but no more than AJE_POOL_MAX bytes at a time.
 */
static size_t
aje_random_size(aje_state_t *as, size_t max)
{
	size_t n;

	aje_check(as);
	g_assert(size_is_positive(max));

	/*
	 * The modulo bias is OK: it will favor smaller sizes.
	 */

	if (max > AJE_POOL_MIN) {
		size_t upper = max - (AJE_POOL_MIN - 1);
		upper = MIN(upper, (AJE_POOL_MAX + 1 - AJE_POOL_MIN));
		n = AJE_POOL_MIN + (aje_random_byte(as) % upper);
	} else {
		n = max;
	}

	return n;
}

/**
 * Distribute some of the external entropy to pools, randomly.
 *
 * @param as		the AJE state
 * @param data		start of the external randomness
 * @param len		length of the supplied data
 *
 * @return the amount of data we distributed.
 */
static size_t
aje_distribute_entropy(aje_state_t *as, const void *data, size_t len)
{
	uint n, s;

	aje_check(as);

	/*
	 * Make sure that pool #0 is initialized, and if it already has
	 * enough data, then pick another pool randomly.
	 */

	if G_UNLIKELY(0 == as->pool0_bytes)
		n = 0;
	else if G_UNLIKELY(0 == as->reseed_count && as->pool0_bytes < AJE_POOL0_FILL)
		n = 0;
	else
		n = aje_random_pool(as);

	g_assert(n < N_ITEMS(as->pool));

	/*
	 * Hash a random portion of the data we are given into the pool.
	 */

	s = aje_random_size(as, len);

	g_assert(s <= len);

	SHA1_input(&as->pool[n], data, s);

	/*
	 * If we were updating pool #0, update the amount of entropy collected
	 * in that pool, since that is the one we use to decide whether we
	 * collected enough to allow feeding other pools.
	 */

	if G_UNLIKELY(0 == n)
		as->pool0_bytes += s;

	return s;		/* The amount of bytes we distributed */
}

/**
 * Update pools with new entropy (external randomness).
 */
static void
aje_add_entropy(aje_state_t *as, const void *data, size_t len)
{
	size_t n;
	const uint8 *p;

	aje_check(as);

	if G_UNLIKELY(NULL == data || 0 == len)
		return;

	/*
	 * Distribute the received entropy over all the pools: the amount of
	 * data and the pools are chosen randomly.
	 */

	for (p = data, n = len; n != 0; /* empty */) {
		size_t used;

		used = aje_distribute_entropy(as, p, n);

		g_assert(used <= n);

		n -= used;
		p += used;
	}
}

/**
 * Spread the initial entropy to all the pools.
 */
static void
aje_spread(aje_state_t *as)
{
	uint i;
	uint8 buf[AJE_CIPHER_BLOCKLEN];

	aje_check(as);

	/*
	 * Use next block as the new counter.
	 */

	STATIC_ASSERT(sizeof as->counter == sizeof buf);

	aje_counter_encrypt(as, ARYLEN(buf));
	memcpy(as->counter, ARYLEN(buf));

	/*
	 * Now feed entropy to the pools, excluding pool #0.
	 */

	for (i = 1; i < N_ITEMS(as->pool); i++) {
		size_t j;

		for (j = 0; j < 2; j++) {
			aje_counter_encrypt(as, ARYLEN(buf));
			SHA1_INPUT(&as->pool[i], buf);
		}
	}

	ZERO(buf);			/* Clear the stack */
	aje_rekey(as);		/* Hide the key */

	as->spread = TRUE;	/* Can only spread once */
}

/**
 * Extract random data to supplied buffer.
 *
 * @param as	the AJE state
 * @param dest	where random data are to be written
 * @param len	size of the destination buffer
 */
static void
aje_extract(aje_state_t *as, void *dest, size_t len)
{
	size_t block_nr = 0;
	uint8 buf[AJE_CIPHER_BLOCKLEN];
	void *p = dest;

	aje_check(as);

	/*
	 * Reseed if we can (and therefore should).
	 * This will always happen the first time we are called.
	 */

	if (aje_may_reseed(as))
		aje_reseed(as);

	/*
	 * Randomize things the first time we are called.
	 */

	if G_UNLIKELY(!as->spread)
		aje_spread(as);

	/*
	 * Generate the random bytes.
	 */

	while (len != 0) {
		size_t n;

		/*
		 * We must not give out too many bytes with one key to make
		 * sure there are no duplicate blocks generated.
		 */

		if G_UNLIKELY(++block_nr > AJE_REKEY_BYTES / AJE_CIPHER_BLOCKLEN) {
			aje_rekey(as);
			block_nr = 0;
		}

		aje_counter_encrypt(as, ARYLEN(buf));
		n = MIN(len, sizeof buf);
		p = mempcpy(p, buf, n);
		len -= n;
	}

	/*
	 * Change the key after each request, no matter how small.
	 */

	aje_rekey(as);
	ZERO(&buf);
}

static aje_state_t aje_state;
static once_flag_t aje_initialized;

/**
 * Initialize the state.
 */
static void
aje_init(aje_state_t *as)
{
	size_t i;
	uint8 buf[AJE_POOL0_FILL * 8];

	STATIC_ASSERT(AJE_CIPHER_KEYLEN <= AJE_DIGEST_LEN);
	STATIC_ASSERT(AJE_CIPHER_KEYLEN == sizeof(xxtea_key_t));

	ZERO(as);
	as->magic = AJE_MAGIC;

	for (i = 0; i < N_ITEMS(as->pool); i++) {
		SHA1_reset(&as->pool[i]);
	}

	spinlock_init(&as->lock);

	/*
	 * Generate a random counter and a random initial key.
	 *
	 * The first time we're calling entropy_fill(), we're really generating
	 * random values from the environment.  Once the global AJE is initialized,
	 * that call is redirected to aje_random_bytes(), meaning thread-specific
	 * AJE contexts will be seeded with randomness coming from the global AJE
	 * state.
	 */

	entropy_fill(ARYLEN(as->key));
	entropy_fill(ARYLEN(as->counter));

	/*
	 * Throw an initial amount of entropy into the pools, randomly spread.
	 *
	 * Use uninitialized stack values, then random values.
	 */

#ifndef ALLOW_UNINIT_VALUES
	ZERO(&buf);
#endif

	aje_add_entropy(as, ARYLEN(buf));

	for (i = 0; i < 8; i++) {
		entropy_fill(ARYLEN(buf));
		aje_add_entropy(as, ARYLEN(buf));

		random_bytes_with(entropy_minirand, ARYLEN(buf));
		aje_add_entropy(as, ARYLEN(buf));
	}

	/*
	 * Clear the stack.
	 */

	ZERO(&buf);
}

/**
 * Initialize the default state.
 */
static void
aje_default_init(void)
{
	aje_init(&aje_state);

	/*
	 * Now that the global AJE state has been initialized and seeded, it can
	 * become the source of entropy, meaning routines like entropy_fill()
	 * get redirected to AJE for generating random bytes.
	 */

	entropy_aje_inited();
}

/**
 * Add entropy.
 *
 * @param src		start of random data to add
 * @param len		length of data buffer
 */
void
aje_addrandom(const void *src, size_t len)
{
	ONCE_FLAG_RUN(aje_initialized, aje_default_init);

	AJE_STATE_LOCK(&aje_state);
	aje_add_entropy(&aje_state, src, len);
	AJE_STATE_UNLOCK(&aje_state);
}

/**
 * Extract random bytes into buffer.
 *
 * @param dest		start of buffer to fill
 * @param len		length of data buffer
 */
void
aje_random_bytes(void *dest, size_t len)
{
	g_assert(dest != NULL);
	g_assert(size_is_positive(len));

	ONCE_FLAG_RUN(aje_initialized, aje_default_init);

	AJE_STATE_LOCK(&aje_state);
	aje_extract(&aje_state, dest, len);
	AJE_STATE_UNLOCK(&aje_state);
}

/**
 * Refresh the vec[] pool of random numbers.
 */
static void
aje_refresh(aje_state_t *as)
{
	aje_check(as);

	aje_extract(as, ARYLEN(as->vec));
	as->sp = N_ITEMS(as->vec);
}

/**
 * Get pre-computed random number, refreshing pool if empty
 *
 * @param as		the AJE state
 *
 * @return a 32-bit random number.
 */
static uint32
aje_rand_internal(register aje_state_t *as)
{
	if G_UNLIKELY(as->sp <= 0)
		aje_refresh(as);

	return as->vec[--as->sp];
}

/**
 * Get pre-computed random number, refreshing pool if empty
 *
 * @param as		the AJE state
 *
 * @return a 64-bit random number.
 */
static uint64
aje_rand64_internal(register aje_state_t *as)
{
	register uint32 rn1, rn2;

	/*
	 * For maximum speed, we'll handle the two overflow cases
	 * together.  That will save us one test in the common case, at
	 * the expense of an extra one in the overflow case.
	 *
	 * We're reusing the same logic here as in mts_rand64_internal().
	 */

	if G_UNLIKELY(--as->sp <= 0) {
		if (as->sp < 0) {
			aje_refresh(as);
			rn1 = as->vec[--as->sp];
		} else {
			rn1 = as->vec[as->sp];
			aje_refresh(as);
		}
	} else {
		rn1 = as->vec[as->sp];
	}

	rn2 = as->vec[--as->sp];

	return ((uint64) rn1 << 32) | (uint64) rn2;
}

/**
 * Generate 32-bit random value (fast).
 */
uint32
aje_rand(void)
{
	uint32 v;

	ONCE_FLAG_RUN(aje_initialized, aje_default_init);

	AJE_STATE_LOCK(&aje_state);
	v = aje_rand_internal(&aje_state);
	AJE_STATE_UNLOCK(&aje_state);

	return v;
}

/**
 * Generate 64-bit random value (fast).
 */
uint64
aje_rand64(void)
{
	uint64 v;

	ONCE_FLAG_RUN(aje_initialized, aje_default_init);

	AJE_STATE_LOCK(&aje_state);
	v = aje_rand64_internal(&aje_state);
	AJE_STATE_UNLOCK(&aje_state);

	return v;
}

/**
 * Generate a strong 32-bit random value (slow).
 *
 * This is a strong number because it does not rely on a pre-computed buffer
 * of random values, hence it is immediately influenced by any call to
 * aje_addrandom(), and it will change the global AJE key.
 *
 * It is about 8 times slower than aje_rand() and should only be used when
 * the numbers need to be absolutely unpredictable given all the randomness
 * collected so-far.
 */
uint32
aje_rand_strong(void)
{
	uint32 v;

	aje_random_bytes(VARLEN(v));
	return v;
}

/**
 * Generate a strong 64-bit random value (slow).
 *
 * This is a strong number because it does not rely on a pre-computed buffer
 * of random values, hence it is immediately influenced by any call to
 * aje_addrandom(), and it will change the global AJE key.
 */
uint64
aje_rand64_strong(void)
{
	uint64 v;

	aje_random_bytes(VARLEN(v));
	return v;
}

static once_flag_t aje_key_inited;
static thread_key_t aje_key = THREAD_KEY_INIT;

/**
 * Create the thread-local random pool key, once.
 */
static void
aje_key_init(void)
{
	if (-1 == thread_local_key_create(&aje_key, THREAD_LOCAL_KEEP))
		s_error("cannot initialize AJE random pool key: %m");

	/*
	 * As a precaution, make sure the global AJE state is properly initialized
	 * so that the forthcoming thread-local AJE state can be filled with
	 * randomness coming from that global pool.
	 */

	ONCE_FLAG_RUN(aje_initialized, aje_default_init);
}

/**
 * Get suitable thread-local random pool.
 */
static aje_state_t *
aje_pool(void)
{
	aje_state_t *as;

	ONCE_FLAG_RUN(aje_key_inited, aje_key_init);

	as = thread_local_get(aje_key);

	if G_UNLIKELY(NULL == as) {
		/*
		 * The random pool is kept for each created thread, never freed.
		 */

		OMALLOC(as);
		aje_init(as);
		thread_local_set(aje_key, as);
	}

	return as;
}

/**
 * Generate a random number in the range 0 to 2^32-1, inclusive.
 *
 * This routine uses a thread-private random pool and is mostly a
 * lock-free execution path (about 10% faster than aje_rand() with locks
 * but no contention).
 *
 * @return a 32-bit random number
 */
uint32
aje_thread_rand(void)
{
	return aje_rand_internal(aje_pool());
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
aje_thread_rand64(void)
{
	return aje_rand64_internal(aje_pool());
}

/**
 * Add randomness to the local AJE state.
 *
 * @param as		the AJE state to which we add randomness
 * @param data		the start of the random data buffer
 * @param len		the amount of random bytes to process in the buffer
 */
void
aje_thread_addrandom(const void *data, size_t len)
{
	aje_add_entropy(aje_pool(), data, len);
}

/**
 * Extract random bytes from the local AJE state into buffer.
 *
 * @param dest		start of buffer to fill
 * @param len		length of data buffer
 */
void
aje_thread_random_bytes(void *dest, size_t len)
{
	g_assert(dest != NULL);
	g_assert(size_is_positive(len));

	aje_extract(aje_pool(), dest, len);
}

/**
 * Generate a strong 32-bit random value (slow) using the thread random pool.
 *
 * This is a strong number because it does not rely on a pre-computed buffer
 * of random values, hence it is immediately influenced by any call to
 * aje_thread_addrandom(), and it will change the local AJE key.
 */
uint32
aje_thread_rand_strong(void)
{
	uint32 v;

	aje_thread_random_bytes(VARLEN(v));
	return v;
}

/**
 * Generate a strong 64-bit random value (slow) using the thread random pool.
 *
 * This is a strong number because it does not rely on a pre-computed buffer
 * of random values, hence it is immediately influenced by any call to
 * aje_thread_addrandom(), and it will change the local AJE key.
 */
uint64
aje_thread_rand64_strong(void)
{
	uint64 v;

	aje_thread_random_bytes(VARLEN(v));
	return v;
}

/**
 * @return a list of thread IDs using a thread-local AJE pool, which must
 * be freed with pslist_free().
 */
pslist_t *
aje_users(void)
{
	ONCE_FLAG_RUN(aje_key_inited, aje_key_init);

	return thread_local_users(aje_key);
}

/* vi: set ts=4 sw=4 cindent: */
