/*
 * Copyright (c) 2001 Geoff Kuenning
 *
 * Adaptated and enhanced for inclusion in gtk-gnutella by Raphael Manfredi.
 * Copyright (c) 2012 Raphael Manfredi
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
 * Mersenne Twister Pseudo Random Number Generator.
 *
 * This is a stripped-down implementation originating from the LGPL version
 * from Geoff Kuenning, released March 18, 2001, mostly keeping the core
 * random number generation algorithm.  Additional API routines were added
 * by Raphael Manfredi.
 *
 * Original source code written by Geoff was obtained at:
 * http://www.cs.hmc.edu/~geoff/tars/mtwist-1.1.tgz
 *
 * The Mersenne Twister PRNG was originally developped by Makoto Matsumoto
 * and Takuji Nishimura circa 1997. For more information on that algorithm,
 * look here:
 * http://www.math.sci.hiroshima-u.ac.jp/~m-mat/MT/emt.html
 *
 * Notes from the manual page in Geoff package, plus additions by RAM:
 *
 * All of the PRNG functions work from a state vector, which is of type
 * mt_state_t.  The state vector stores everything that the PRNG needs to
 * generate new numbers in the proper sequence.  By using multiple state
 * vectors, programs can draw random numbers from independent sequences,
 * which is important in applications such as simulation (where each
 * independent random variable should be drawn from its own sequence to
 * avoid unintentional correlations).
 *
 * For convenience, the interface provides a built-in default state vector
 * that is used by mt_xxx() functions.  On the other hand, mts_xxx() functions
 * manage a user-supplied state.
 *
 * A new mt_state_t, possibly initialized through a supplied 32-bit random
 * function, can be created by mt_state_new() and cloned by mt_state_clone().
 * These states are disposed of by mt_state_free_null().  Cloning allows one to
 * snapshot the state to replay the random sequence later.  It requires
 * an initialized state.
 *
 * If the state is not initialized with random values (either one created via
 * mt_state_new() or for the built-in default state), it will be intialized
 * as needed the first time it is used by generating random values with the
 * arc4random() routine.
 *
 * When using user-supplied states, no lock protection occurs unless
 * mts_lock_xxx() routines are used.  This allows faster execution paths
 * with thread-private states, but the user must not call mts_xxx() with a
 * shared state if that call can happen from multiple threads.
 *
 * The mt_xxx() functions are thread-safe already, as a lock is always
 * taken before accessing the built-in default state.
 *
 * For the curious, a Mersenne number is an integer that is one less than
 * a power-of-two.  For instance 2^32 - 1 is a Mersenne number.  This
 * implementation of the Mersenne Twister has a period of 2^19937 - 1,
 * which is a Mersenne number, that also happens to be a Mersenne prime.
 *
 * The name of the Mersenne Twister comes from that, and by fortuity its
 * abbreviation, MT, represents the initials of the first names of the
 * two inventors of the algorithm.  Probably a happy coincidence...
 * 
 * @author Geoff Kuenning
 * @date 2001
 * @author Raphael Manfredi
 * @date 2012
 */

#include "common.h"

#include "mtwist.h"
#include "arc4random.h"
#include "once.h"
#include "random.h"
#include "spinlock.h"
#include "stacktrace.h"
#include "walloc.h"

/*
 * The following value is a fundamental parameter of the algorithm.
 * It was found experimentally using methods described in Matsumoto
 * and Nishimura's paper.  It is exceedingly magic; don't change it.
 */
#define MT_STATE_SIZE	624		/* Size of the MT state vector */

/*
 * Internal state for an MT PRNG.  The user can keep multiple mt_state
 * structures around as a way of generating multiple streams of random
 * numbers.
 *
 * In Matsumoto and Nishimura's original paper, the state vector was
 * processed in a forward direction.  I have reversed the state vector
 * in this implementation.  The reason for the reversal is that it
 * allows the critical path to use a test against zero instead of a
 * test against 624 to detect the need to refresh the state.  on most
 * machines, testing against zero is slightly faster.  It also means
 * that a state that has been set to all zeros will be correctly
 * detected as needing initialization; this means that setting a state
 * vector to zero (either with memset or by statically allocating it)
 * will cause the PRNG to operate properly.
 */

enum mt_state_magic { MT_STATE_MAGIC = 0x010e1872 };

struct mt_state {
	enum mt_state_magic magic;		/* Magic number (added by RAM) */
	uint32 vec[MT_STATE_SIZE];		/* Vector holding current state */
	spinlock_t lock;				/* Lock for thread-safe accesses */
	int sp;							/* Next state entry to be used */
	int initialized;				/* NZ if state was initialized */
};

static void
mt_state_check(const struct mt_state * const mts)
{
	g_assert(mts != NULL);
	g_assert(MT_STATE_MAGIC == mts->magic);
}

#define STATE_LOCK(m)	spinlock_hidden(&m->lock)
#define STATE_UNLOCK(m)	spinunlock_hidden(&m->lock)

/**
 * Initialize the state with random values drawn from specified PRNG function.
 *
 * @param rf		random function to initialize the state
 * @param mts		the MT state we want to initialize
 *
 * (function added by RAM)
 */
static void
mts_seed_with(random_fn_t rf, mt_state_t *mts)
{
	unsigned i;

	random_bytes_with(rf, &mts->vec, sizeof mts->vec);

	/*
	 * Make sure we have no value set to 0.  If any were generated, we
	 * supersede them with another non-zero random value.
	 */

	for (i = 0; i < G_N_ELEMENTS(mts->vec); i++) {
		if G_UNLIKELY(0 == mts->vec[i]) {
			uint32 v, n = 0;

			while (0 == (v = (*rf)()) && n++ < 100)
				/* empty */;

			if G_UNLIKELY(0 == v) {
				s_error("bad luck with random number generator %s()",
					stacktrace_function_name(rf));
			}

			mts->vec[i] = v;
		}
	}

	spinlock_init(&mts->lock);
	mts->initialized = TRUE;
}

/*
 * The following values are fundamental parameters of the algorithm.
 * With the exception of the two masks, all of them were found
 * experimentally using methods described in Matsumoto and Nishimura's
 * paper.  They are exceedingly magic; don't change them.
 *
 * R_OFFSET:
 * Offset into state space for the recurrence relation.  The recurrence mashes
 * together two values that are separated by this offset in the state space.
 *
 * MATRIX_A:
 * Constant vector A for the recurrence relation.  The mashed-together value
 * is multiplied by this vector to get a new value that will be stored into
 * the state space.
 */
#define R_OFFSET	397
#define MATRIX_A	0x9908b0df

/*
 * Masks for extracting the bits to be mashed together.  The widths of these
 * masks are also fundamental parameters of the algorithm, determined
 * experimentally -- but of course the masks themselves are simply bit
 * selectors.
 */
#define UPPER_MASK	0x80000000	/* Most significant w-r bits */
#define LOWER_MASK	0x7fffffff	/* Least significant r bits */

/*
 * Macro to simplify code in the generation loop.  This function
 * combines the top bit of x with the bottom 31 bits of y.
 */
#define COMBINE_BITS(x, y) \
	(((x) & UPPER_MASK) | ((y) & LOWER_MASK))

/*
 * Another generation-simplification macro.  This one does the magic
 * scrambling function.
 */
#define MATRIX_MULTIPLY(original, new)	\
	((original) ^ ((new) >> 1)			\
	  ^ matrix_decider[(new) & 0x1])

/*
 * In the recurrence relation, the new value is XORed with MATRIX_A only if
 * the lower bit is nonzero.  Since most modern machines don't like to
 * branch, it's vastly faster to handle this decision by indexing into an
 * array.  The chosen bit is used as an index into the following vector,
 * which produces either zero or MATRIX_A and thus the desired effect.
 */
static const uint32 matrix_decider[2] = { 0, MATRIX_A };

/**
 * Generate 624 more random values.
 *
 * This function is called when the state vector has been exhausted.
 * It generates another batch of pseudo-random values.  The performance of
 * this function is critical to the performance of the Mersenne Twister PRNG,
 * so it has been highly optimized.
 *
 * @param state		state for the PRNG
 */
static G_GNUC_HOT void
mts_refresh(register mt_state_t *mts)
{
	register int i;				/* Index into the state */
	register uint32 *sp;		/* Next place to get from state */
	register uint32 val1;		/* Scratch val picked up from state */
	register uint32 val2;		/* Scratch val picked up from state */

	/*
	 * Start by making sure a random seed has been set.  If not, set one.
	 *
	 * Note from RAM: we use arc4random() to initialize the state because it
	 * is the fastest way and the strongest PRNG we have available besides
	 * Mersenne Twister.
	 */

	if G_UNLIKELY(!mts->initialized)
		mts_seed_with(arc4random, mts);

	/*
	 * Now generate the new pseudo-random values by applying the
	 * recurrence relation.  We use two loops and a final
	 * 2-statement sequence so that we can handle the wraparound
	 * explicitly, rather than having to use the relatively slow
	 * modulus operator.
	 *
	 * In essence, the recurrence relation concatenates bits
	 * chosen from the current random value (last time around)
	 * with the immediately preceding one.  Then it matrix-multiplies
	 * the concatenated bits with a value R_OFFSET away and a constant
	 * matrix.  The matrix multiplication reduces to a shift and two XORs.
	 *
	 * Some comments on the optimizations are in order:
	 *
	 * Strictly speaking, none of the optimizations should be
	 * necessary.  All could conceivably be done by a really good
	 * compiler.  However, the compilers available to me aren't quite
	 * smart enough, so hand optimization needs to be done.
	 *
	 * Shawn Cokus was the first to achieve a major speedup.  In the
	 * original code, the first value given to COMBINE_BITS (in my
	 * characterization) was re-fetched from the state array, rather
	 * than being carried in a scratch variable.  Cokus noticed that
	 * the first argument to COMBINE_BITS could be saved in a register
	 * in the previous loop iteration, getting rid of the need for an
	 * expensive memory reference.
	 *
	 * Cokus also switched to using pointers to access the state
	 * array and broke the original loop into two so that he could
	 * avoid using the expensive modulus operator.  Cokus used three
	 * pointers; Richard J. Wagner noticed that the offsets between
	 * the three were constant, so that they could be collapsed into a
	 * single pointer and constant-offset accesses.  This is clearly
	 * faster on x86 architectures, and is the same cost on RISC
	 * machines.  A secondary benefit is that Cokus' version was
	 * register-starved on the x86, while Wagner's version was not.
	 *
	 * I made several smaller improvements to these observations.
	 * First, I reversed the contents of the state vector.  In the
	 * current version of the code, this change doesn't directly
	 * affect the performance of the refresh loop, but it has the nice
	 * side benefit that an all-zero state structure represents an
	 * uninitialized generator.  It also slightly speeds up the
	 * random-number routines, since they can compare the state
	 * pointer against zero instead of against a constant (this makes
	 * the biggest difference on RISC machines).
	 *
	 * Second, I returned to Matsumoto and Nishimura's original
	 * technique of using a lookup table to decide whether to xor the
	 * constant vector A (MATRIX_A in this code) with the newly
	 * computed value.  Cokus and Wagner had used the ?: operator,
	 * which requires a test and branch.  Modern machines don't like
	 * branches, so the table lookup is faster.
	 *
	 * Third, in the Cokus and Wagner versions the loop ends with a
	 * statement similar to "value1 = value2", which is necessary to
	 * carry the fetched value into the next loop iteration.  I
	 * recognized that if the loop were unrolled so that it generates
	 * two values per iteration, a bit of variable renaming would get
	 * rid of that assignment.  A nice side effect is that the
	 * overhead of loop control becomes only half as large.
	 *
	 * It is possible to improve the code's performance somewhat
	 * further.  In particular, since the second loop's loop count
	 * factors into 2*2*3*3*11, it could be unrolled yet further.
	 * That's easy to do, too: just change the "/ 2" into a division
	 * by whatever factor you choose, and then use cut-and-paste to
	 * duplicate the code in the body.  To remove a few more cycles,
	 * fix the code to decrement `sp' by the unrolling factor, and
	 * adjust the various offsets appropriately.  However, the payoff
	 * will be small.  At the moment, the x86 version of the loop is
	 * 25 instructions, of which 3 are involved in loop control
	 * (including the decrementing of `sp').  Further unrolling by
	 * a factor of 2 would thus produce only about a 6% speedup.
	 *
	 * The logical extension of the unrolling
	 * approach would be to remove the loops and create 624
	 * appropriate copies of the body.  However, I think that doing
	 * the latter is a bit excessive!
	 *
	 * I suspect that a superior optimization would be to simplify the
	 * mathematical operations involved in the recurrence relation.
	 * However, I have no idea whether such a simplification is
	 * feasible.
	 */

	sp = &mts->vec[MT_STATE_SIZE - 1];
	val1 = *sp;

	for (i = (MT_STATE_SIZE - R_OFFSET) / 2; --i >= 0; /* empty */) {
		sp -= 2;
		val2 = sp[1];
		val1 = COMBINE_BITS(val1, val2);
		sp[2] = MATRIX_MULTIPLY(sp[-R_OFFSET + 2], val1);
		val1 = sp[0];
		val2 = COMBINE_BITS(val2, val1);
		sp[1] = MATRIX_MULTIPLY(sp[-R_OFFSET + 1], val2);
	}

	val2 = *--sp;
	val1 = COMBINE_BITS(val1, val2);
	sp[1] = MATRIX_MULTIPLY(sp[-R_OFFSET + 1], val1);

	for (i = (R_OFFSET - 1) / 2; --i >= 0; /* empty */) {
		sp -= 2;
		val1 = sp[1];
		val2 = COMBINE_BITS(val2, val1);
		sp[2] = MATRIX_MULTIPLY(sp[MT_STATE_SIZE - R_OFFSET + 2], val2);
		val2 = sp[0];
		val1 = COMBINE_BITS(val1, val2);
		sp[1] = MATRIX_MULTIPLY(sp[MT_STATE_SIZE - R_OFFSET + 1], val1);
	}

	/*
	 * The final entry in the table requires the "previous" value
	 * to be gotten from the other end of the state vector, so it
	 * must be handled specially.
	 */

	val1 = COMBINE_BITS(val2, mts->vec[MT_STATE_SIZE - 1]);
	*sp = MATRIX_MULTIPLY(sp[MT_STATE_SIZE - R_OFFSET], val1);

	/*
	 * Now that refresh is complete, reset the state pointer to allow more
	 * pseudo-random values to be fetched from the state array.
	 */

	mts->sp = MT_STATE_SIZE;
}

/*
 * Tempering parameters.  These are perhaps the most magic of all the magic
 * values in the algorithm.  The values are again experimentally determined.
 * The values generated by the recurrence relation (constants above) are not
 * equidistributed in 623-space.  For some reason, the tempering process
 * produces that effect.  Don't ask me why.  Read the paper if you can
 * understand the math.  Or just trust these magic numbers.
 */
#define MT_TEMPERING_MASK_B 0x9d2c5680
#define MT_TEMPERING_MASK_C 0xefc60000
#define MT_TEMPERING_SHIFT_U(y)	(y >> 11)
#define MT_TEMPERING_SHIFT_S(y)	(y << 7)
#define MT_TEMPERING_SHIFT_T(y)	(y << 15)
#define MT_TEMPERING_SHIFT_L(y)	(y >> 18)

/*
 * Macros to do the tempering.  MT_PRE_TEMPER does all but the last step;
 * it's useful for situations where the final step can be incorporated
 * into a return statement.  MT_FINAL_TEMPER does that final step (not as
 * an assignment).
 *
 * The MT_TEMPER macro does the whole process.
 *
 * Note that both MT_PRE_TEMPER and MT_TEMPER modify their arguments.
 */
#define MT_PRE_TEMPER(value) G_STMT_START {						\
	value ^= MT_TEMPERING_SHIFT_U(value);						\
	value ^= MT_TEMPERING_SHIFT_S(value) & MT_TEMPERING_MASK_B;	\
	value ^= MT_TEMPERING_SHIFT_T(value) & MT_TEMPERING_MASK_C;	\
} G_STMT_END

#define MT_FINAL_TEMPER(value) ((value) ^ MT_TEMPERING_SHIFT_L(value))

#define MT_TEMPER(value) G_STMT_START {		\
	MT_PRE_TEMPER(value);					\
	value ^= MT_TEMPERING_SHIFT_L(value);	\
} G_STMT_END

/**
 * Generate a random number in the range 0 to 2^32-1, inclusive, working
 * from a given state vector.
 *
 * The generator is optimized for speed.  The primary optimization is that
 * the pseudo-random numbers are generated in batches of MT_STATE_SIZE.  This
 * saves the cost of a modulus operation in the critical path.
 *
 * @param mts	state for the PRNG
 *
 * @return a 32-bit random number
 */
static uint32
mts_rand_internal(register mt_state_t *mts)
{
	register uint32	rn;		/* Pseudo-random value generated */

	if G_UNLIKELY(mts->sp <= 0)
		mts_refresh(mts);

	rn = mts->vec[--mts->sp];
	MT_PRE_TEMPER(rn);
	return MT_FINAL_TEMPER(rn);
}

/*
 * Generate a random number in the range 0 to 2^64-1, inclusive, working
 * from a given state vector.
 *
 * According to Matsumoto and Nishimura, such a number can be generated by
 * simply concatenating two 32-bit pseudo-random numbers.  Who am I to argue?
 *
 * Note that there is a slight inefficiency here: if the 624-entry state is
 * recycled on the second call to mts_rand(), there will be an unnecessary
 * check to see if the state has been initialized.  The cost of that check
 * seems small (since it happens only once every 624 random numbers, and
 * never if only 64-bit numbers are being generated), so I didn't bother to
 * optimize it out.  Doing so would be messy, since it would require two
 * nearly-identical internal implementations of mts_rand().
 *
 * @param mts	state for the PRNG
 *
 * @return a 64-bit random number
 */
static uint64
mts_rand64_internal(register mt_state_t *mts)
{
	register uint32	rn1;	/* 1st pseudo-random value generated */
	register uint32	rn2;	/* 2nd pseudo-random value generated */

	/*
	 * For maximum speed, we'll handle the two overflow cases
	 * together.  That will save us one test in the common case, at
	 * the expense of an extra one in the overflow case.
	 */

	if G_UNLIKELY(--mts->sp <= 0) {
		if (mts->sp < 0) {
			mts_refresh(mts);
			rn1 = mts->vec[--mts->sp];
		} else {
			rn1 = mts->vec[mts->sp];
			mts_refresh(mts);
		}
	} else {
		rn1 = mts->vec[mts->sp];
	}

	MT_TEMPER(rn1);

	rn2 = mts->vec[--mts->sp];
	MT_PRE_TEMPER(rn2);

	return ((uint64) rn1 << 32) | (uint64) MT_FINAL_TEMPER(rn2);
}

/**
 * Generate a random number in the range 0 to 2^32-1, inclusive, working
 * from a given state vector.
 *
 * @param mts	state for the PRNG
 *
 * @return a 32-bit random number
 */
uint32
mts_rand(register mt_state_t *mts)
{
	mt_state_check(mts);

	return mts_rand_internal(mts);
}

/**
 * Generate a random number in the range 0 to 2^64-1, inclusive, working
 * from a given state vector.
 *
 * @param mts	state for the PRNG
 *
 * @return a 64-bit random number
 */
uint64
mts_rand64(register mt_state_t *mts)
{
	mt_state_check(mts);

	return mts_rand64_internal(mts);
}

/**
 * Generate a random number in the range 0 to 2^32-1, inclusive, working
 * from a given state vector.
 *
 * @param mts	state for the PRNG, locked before access
 *
 * @return a 32-bit random number
 *
 * (function added by RAM)
 */
uint32
mts_lock_rand(register mt_state_t *mts)
{
	uint32 rn;

	mt_state_check(mts);

	STATE_LOCK(mts);
	rn = mts_rand_internal(mts);
	STATE_UNLOCK(mts);

	return rn;
}

/**
 * Generate a random number in the range 0 to 2^64-1, inclusive, working
 * from a given state vector.
 *
 * @param mts	state for the PRNG, locked before access
 *
 * @return a 64-bit random number
 *
 * (function added by RAM)
 */
uint64
mts_lock_rand64(register mt_state_t *mts)
{
	uint64 rn;

	mt_state_check(mts);

	STATE_LOCK(mts);
	rn = mts_rand64_internal(mts);
	STATE_UNLOCK(mts);

	return rn;
}

/*
 * The default built-in state does not use the embedded lock in the state
 * because it needs to be statically initialized.  Therefore, we use an
 * explicit spinlock.
 */

static mt_state_t mt_default;
static spinlock_t mtwist_lck = SPINLOCK_INIT;

#define THREAD_LOCK		spinlock_hidden(&mtwist_lck)
#define THREAD_UNLOCK	spinunlock_hidden(&mtwist_lck)

/**
 * Generate a random number in the range 0 to 2^32-1, inclusive.
 *
 * @return a 32-bit random number
 */
uint32
mt_rand(void)
{
	uint32 rn;

	THREAD_LOCK;
	rn = mts_rand_internal(&mt_default);
	THREAD_UNLOCK;

	return rn;
}

/**
 * Generate a random number in the range 0 to 2^64-1, inclusive.
 *
 * @return a 64-bit random number
 */
uint64
mt_rand64(void)
{
	uint64 rn;

	THREAD_LOCK;
	rn = mts_rand64_internal(&mt_default);
	THREAD_UNLOCK;

	return rn;
}

/***
 *** The following are additional routines not present in Geoff's code.
 ***/

/**
 * Allocate a new state, initialized randomly using supplied random function.
 *
 * If the random function is NULL, the state is left zeroed and it will
 * be automatically initialized the first time it is used.
 *
 * @param rf		random function to initialize the state
 *
 * @return a new state that can be freed with mt_state_free_null().
 */
mt_state_t *
mt_state_new(random_fn_t rf)
{
	mt_state_t *mts;

	WALLOC0(mts);
	mts->magic = MT_STATE_MAGIC;

	if (rf != NULL)
		mts_seed_with(rf, mts);

	return mts;
}

/**
 * Clone state, allowing replay of a random number generation sequence.
 *
 * The state must already be initialized otherwise cloning would be useless
 * since an uninitialized state will be auto-magically initialized the first
 * time it is used, by generating random values.
 *
 * @param mts		the initialized state to clone
 *
 * @return a copy of the state which can be freed with mt_state_free_null().
 */
mt_state_t *
mt_state_clone(const mt_state_t *mts)
{
	mt_state_t *cmts, *wmts;

	mt_state_check(mts);
	g_assert(mts->initialized);

	wmts = deconstify_pointer(mts);		/* Only hidden state is changed */

	STATE_LOCK(wmts);
	cmts = WCOPY(wmts);
	STATE_UNLOCK(wmts);

	spinlock_init(&cmts->lock);			/* Was locked when cloned */

	return cmts;
}

/**
 * Free MT state and nullify its pointer.
 */
void
mt_state_free_null(mt_state_t **mts_ptr)
{
	mt_state_t *mts = *mts_ptr;

	if (mts != NULL) {
		mt_state_check(mts);
		WFREE(mts);
		*mts_ptr = NULL;
	}
}

/**
 * Initialize built-in default state, once.
 */
static void
mt_init_once(void)
{
	THREAD_LOCK;
	mts_seed_with(arc4random, &mt_default);
	THREAD_UNLOCK;
}

/**
 * Optional initialization routine that can be called to pre-initialize the
 * built-in default state.
 */
G_GNUC_COLD void
mt_init(void)
{
	static bool inited;

	once_run(&inited, mt_init_once);
}

/* vi: set ts=4 sw=4 cindent: */
