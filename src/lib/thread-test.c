/*
 * thread-test -- thread and related synchronization tools unit tests.
 *
 * Copyright (c) 2012 Raphael Manfredi <Raphael_Manfredi@pobox.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the authors nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "common.h"

#include "aq.h"
#include "atio.h"
#include "atomic.h"
#include "barrier.h"
#include "compat_poll.h"
#include "compat_sleep_ms.h"
#include "cond.h"
#include "cq.h"
#include "crash.h"
#include "dam.h"
#include "evq.h"
#include "getcpucount.h"
#include "halloc.h"
#include "hset.h"
#include "hstrfn.h"
#include "log.h"
#include "misc.h"
#include "mutex.h"
#include "once.h"
#include "parse.h"
#include "path.h"
#include "progname.h"
#include "qlock.h"
#include "random.h"
#include "rwlock.h"
#include "semaphore.h"
#include "shuffle.h"
#include "signal.h"
#include "spinlock.h"
#include "stacktrace.h"
#include "str.h"
#include "stringify.h"
#include "strtok.h"
#include "teq.h"
#include "thread.h"
#include "tm.h"
#include "tsig.h"
#include "vmea.h"
#include "waiter.h"
#include "walloc.h"
#include "xmalloc.h"
#include "zalloc.h"

#include "override.h"

#define STACK_SIZE		16384

static char allocator = 'r';		/* For -X tests, random mix by default */
static size_t allocator_bsize;		/* Block size to use (0 = random) */
static size_t allocator_fill;
static bool sleep_before_exit;
static bool async_exit, wait_threads;
static bool randomize_free;
static unsigned cond_timeout;
static long cpu_count;

static void *sleeping_thread(void *unused_arg);

static void G_NORETURN
usage(void)
{
	fprintf(stderr,
		"Usage: %s [-hejsvwxABCDEFHIKMNOPQRSUVWX]\n"
		"       [-a type] [-b size] [-c CPU]\n"
		"       [-f count] [-n count] [-r percent] [-t ms] [-T msecs]\n"
		"       [-z fn1,fn2...]\n"
		"  -a : allocator to exlusively test via -X (see below for type)\n"
		"  -b : fixed block size to use for memory tests via -X\n"
		"  -c : override amount of CPUs, driving thread count for mem tests\n"
		"  -e : use emulated semaphores\n"
		"  -f : fill amount, for -X to know how many blocks to allocate\n"
		"  -h : prints this help message\n"
		"  -j : join created threads\n"
		"  -n : amount of times to repeat tests\n"
		"  -r : let remote threads free some objects during -X tests\n"
		"  -s : let each created thread sleep for 1 second before ending\n"
		"  -t : timeout value (ms) for condition waits\n"
		"  -v : dump thread statistics at the end of the tests\n"
		"  -w : wait for created threads\n"
		"  -x : free memory allocated by -X in random order\n"
		"  -z : zap (suppress) messages from listed routines.\n"
		"  -A : use asynchronous exit callbacks\n"
		"  -B : test synchronization barriers\n"
		"  -C : test thread creation\n"
		"  -D : test synchronization dams\n"
		"  -E : test thread signals\n"
		"  -F : test thread fork\n"
		"  -H : test thread interrupts\n"
		"  -I : test inter-thread waiter signaling\n"
		"  -K : test thread cancellation\n"
		"  -M : monitors tennis match via waiters\n"
		"  -N : add broadcast noise during tennis session\n"
		"  -O : test thread stack overflow\n"
		"  -P : add direct POSIX threads along with thread creation test\n"
		"  -Q : test asynchronous queue\n"
		"  -R : test the read-write lock layer\n"
		"  -S : test semaphore layer\n"
		"  -T : test condition layer via tennis session for specified secs\n"
		"  -U : test the queuing lock layer\n"
		"  -V : test thread event queue (TEQ)\n"
		"  -W : test local event queue (EVQ)\n"
		"  -X : exercise concurrent memory allocation\n"
		"Values given as decimal, hexadecimal (0x), octal (0) or binary (0b)\n"
		"Allocators: r=random mix, h=halloc, v=vmm_alloc, w=walloc, x=xmalloc\n"
		, getprogname());
	exit(EXIT_FAILURE);
}

static hset_t *zap;

static void
zap_record(const char *value)
{
	strtok_t *s;
	const char *tok;

	zap = hset_create(HASH_KEY_STRING, 0);
	s = strtok_make_strip(value);

	while ((tok = strtok_next(s, ","))) {
		hset_insert(zap, h_strdup(tok));
	}

	strtok_free_null(&s);
}

static void
emitv(bool nl, const char *fmt, va_list args)
{
	str_t *s = str_new(512);
	iovec_t iov[2];
	int cnt = 0;

	str_vprintf(s, fmt, args);
	iovec_set(&iov[cnt++], str_2c(s), str_len(s));
	if (nl)
		iovec_set(&iov[cnt++], "\n", 1);

	/*
	 * Emit every message to stderr, since this is the same channel used
	 * by s_debug() and friends.  That way, all the output goes to the
	 * very same descriptor, atomically, avoiding garbled output.
	 */

	atio_writev(STDERR_FILENO, iov, cnt);

	str_destroy_null(&s);
}

static void G_PRINTF(1, 2)
emit(const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	emitv(TRUE, fmt, args);
	va_end(args);
}

static void G_PRINTF(2, 3)
emit_zap(const char *caller, const char *fmt, ...)
{
	va_list args;

	if (zap != NULL && hset_contains(zap, caller))
		return;		/* Zap messages from this caller */

	va_start(args, fmt);
	emitv(TRUE, fmt, args);
	va_end(args);
}

#define emitz(fmt, ...) emit_zap(G_STRFUNC, (fmt), __VA_ARGS__)
#define TESTING(func)	emit("----------- %s() -----------", (func));

static char *names[] = { "one", "two", "three", "four", "five" };

static void
exit_callback(const void *result, void *arg)
{
	char *name = arg;
	long length = pointer_to_long(result);
	emit("thread \"%s\" finished, result length is %ld", name, length);
}

static void *
compute_length(void *arg)
{
	unsigned stid = thread_small_id();
	const char *name = arg;
	char *scratch = xstrdup(name);

	emit("%s given \"%s\"", thread_id_name(stid), scratch);
	xfree(scratch);
	thread_cancel_test();
	if (sleep_before_exit)
		thread_sleep_ms(1000);
	return ulong_to_pointer(strlen(name));
}

static void
test_create_one(bool repeat, bool join)
{
	unsigned i;
	int launched[N_ITEMS(names)];

	for (i = 0; i < N_ITEMS(names); i++) {
		int r;
		int flags = 0;

		if (!join)
			flags |= THREAD_F_DETACH;

		if (async_exit)
			flags |= THREAD_F_ASYNC_EXIT;

		r = thread_create_full(compute_length, names[i], flags,
				STACK_SIZE, exit_callback, names[i]);

		launched[i] = r;

		if (-1 == r) {
			if (errno != EAGAIN || !repeat)
				s_warning("cannot create thread #%u: %m", i);
		} else {
			int j;
			if (!repeat)
				emit("thread i=%u created as %s", i, thread_id_name(r));
			if (!join) {
				j = thread_join(r, NULL);
				if (-1 != j) {
					s_warning("thread_join() worked for %s?",
						thread_id_name(r));
				} else if (errno != EINVAL) {
					s_warning("thread_join() failure on %s: %m",
						thread_id_name(r));
				} else {
					if (!repeat) {
						emit("%s cannot be joined, that's OK",
							thread_id_name(r));
					}
					if (wait_threads) {
						bool ok;
						tm_t tout;
						int error;

						tout.tv_sec = 2;
						tout.tv_usec = 0;

						ok = thread_timed_wait(r, &tout, &error);

						if (!ok) {
							s_warning("thread_wait() timed-out for %s",
								thread_id_name(r));
						} else if (error != 0) {
							errno = error;
							s_warning("thread_wait() failure on %s: %m",
								thread_id_name(r));
						}
					}
				}
			}
		}
	}

	if (!repeat && !join)
		compat_sleep_ms(200);		/* Let all the threads run */

	if (join) {
		emit("now joining the %u threads", (uint) N_ITEMS(launched));
		for (i = 0; i < N_ITEMS(launched); i++) {
			int r = launched[i];

			if (-1 == r) {
				if (!repeat)
					emit("skipping unlaunched thread i=%u", i);
			} else {
				void *result;
				int j;

				if (wait_threads && -1 == thread_wait(r)) {
					s_warning("thread_wait() failed for %s: %m",
						thread_id_name(r));
				}

				j = thread_join(r, &result);		/* Block */
				if (-1 == j) {
					s_warning("thread_join() failed for %s: %m",
						thread_id_name(r));
				} else {
					ulong length = pointer_to_ulong(result);
					if (!repeat) {
						emit("%s finished, result length is %lu",
							thread_id_name(r), length);
					}
				}
			}
		}
	}

	if (async_exit)
		cq_main_dispatch();
}

static pthread_t
posix_thread_create(process_fn_t routine, void *arg, bool joinable)
{
	int error;
	pthread_attr_t attr;
	pthread_t t;

	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr,
		joinable ? PTHREAD_CREATE_JOINABLE : PTHREAD_CREATE_DETACHED);
	pthread_attr_setstacksize(&attr, THREAD_STACK_MIN);
	error = pthread_create(&t, &attr, routine, arg);
	pthread_attr_destroy(&attr);

	if (error != 0) {
		errno = error;
		s_error("cannot create POSIX thread: %m");
	}

	return t;
}

static void *
posix_worker(void *unused_arg)
{
	unsigned stid = thread_small_id();
	char name[120];
	thread_info_t info;

	(void) unused_arg;

	thread_current_info(&info);
	thread_info_to_string_buf(&info, ARYLEN(name));

	emit("POSIX thread worker starting...");
	emit("POSIX worker: %s", name);

	for (;;) {
		void *p;

		thread_current_info(&info);

		g_assert_log(thread_small_id() == stid,
			"current STID=%u, prev=%u %s", thread_small_id(), stid,
			thread_info_to_string_buf(&info, ARYLEN(name)));

		p = xmalloc(100);
		compat_sleep_ms(100);
		xfree(p);

		thread_current_info(&info);

		g_assert_log(thread_small_id() == stid,
			"current STID=%u, prev=%u %s", thread_small_id(), stid,
			thread_info_to_string_buf(&info, ARYLEN(name)));
	}

	return NULL;
}

static void *
posix_threads(void *unused_arg)
{
	unsigned i;

	(void) unused_arg;

	emit("POSIX thread launcher starting...");

	for (i = 0; i < 6; i++) {
		(void) posix_thread_create(posix_worker, NULL, FALSE);
	}

	emit("POSIX thread launch done, mutating to worker...");

	return posix_worker(NULL);
}

static void
pexit_callback(const void *result, void *earg)
{
	unsigned stid = pointer_to_uint(earg);

	(void) result;
	emit("POSIX thread #%u exiting", stid);
}

static void *
posix_exiting_thread(void *unused_arg)
{
	unsigned stid = thread_small_id();
	void *p;

	(void) unused_arg;

	emit("POSIX thread #%u starting", stid);

	thread_atexit(pexit_callback, uint_to_pointer(stid));

	p = xmalloc(100);
	compat_sleep_ms(100);
	xfree(p);

	return NULL;
}

static void
test_create(unsigned repeat, bool join, bool posix)
{
	unsigned i;

	TESTING(G_STRFUNC);

	if (posix) {
		pthread_t foreign;

		foreign = posix_thread_create(posix_exiting_thread, NULL, TRUE);
		(void) posix_thread_create(posix_threads, NULL, FALSE);

		emit("Waiting for single foreign POSIX thread...");
		if (0 != pthread_join(foreign, NULL))
			s_error("cannot wait for foreign POSIX thread");
	}

	for (i = 0; i < repeat; i++) {
		test_create_one(repeat > 1, join);
	}
}

static void
test_cancel_one(bool repeat, bool join)
{
	unsigned i;
	int launched[N_ITEMS(names)];

	for (i = 0; i < N_ITEMS(names); i++) {
		int r;
		int flags = 0;

		if (!join)
			flags |= THREAD_F_DETACH;

		if (async_exit)
			flags |= THREAD_F_ASYNC_EXIT;

		r = thread_create_full(compute_length, names[i], flags,
				STACK_SIZE, exit_callback, names[i]);

		launched[i] = r;

		if (-1 == r) {
			if (errno != EAGAIN || !repeat)
				s_warning("cannot create thread #%u: %m", i);
		} else {
			int j;
			if (!repeat)
				emit("thread i=%u created as %s", i, thread_id_name(r));
			if (-1 == thread_cancel(r))
				s_warning("thread_cancel(%u) failed: %m", r);
			if (!join) {
				j = thread_join(r, NULL);
				if (-1 != j) {
					s_warning("thread_join() worked for %s?",
						thread_id_name(r));
				} else if (errno != EINVAL) {
					s_warning("thread_join() failure on %s: %m",
						thread_id_name(r));
				} else {
					if (!repeat) {
						emit("%s cannot be joined, that's OK",
							thread_id_name(r));
					}
				}
			}
		}
	}

	if (!repeat && !join)
		compat_sleep_ms(200);		/* Let all the threads run */

	if (join) {
		emit("now joining the %u threads", (uint) N_ITEMS(launched));
		for (i = 0; i < N_ITEMS(launched); i++) {
			int r = launched[i];

			if (-1 == r) {
				if (!repeat)
					emit("skipping unlaunched thread i=%u", i);
			} else {
				void *result;
				int j = thread_join(r, &result);		/* Block */
				if (-1 == j) {
					s_warning("thread_join() failed for %s: %m",
						thread_id_name(r));
				} else {
					long length = pointer_to_long(result);
					if (!repeat) {
						emit("%s finished, result length is %ld",
							thread_id_name(r), length);
					}
				}
			}
		}
	}

	if (async_exit)
		cq_main_dispatch();

	i = thread_create(sleeping_thread, NULL, THREAD_F_PANIC, STACK_SIZE);
	if (-1 == thread_cancel(i)) {
		s_error("cannot cancel sleeping thread: %m");
	} else {
		void *result;

		if (-1 == thread_join(i, &result))
			s_error("cannot join with sleeping thread: %m");
		g_assert(THREAD_CANCELLED == result);
	}
}

static void
test_cancel(unsigned repeat, bool join)
{
	unsigned i;

	TESTING(G_STRFUNC);

	for (i = 0; i < repeat; i++) {
		test_cancel_one(repeat > 1, join);
	}
}

static void *
test_inter_main(void *arg)
{
	waiter_t *w = waiter_refcnt_inc(arg);

	sleep(1);
	emit("signaling main thread");
	waiter_signal(w);

	compat_sleep_ms(5);
	waiter_refcnt_dec(arg);
	return NULL;
}

static void
test_inter(void)
{
	waiter_t *mw, *w;
	bool refed;

	TESTING(G_STRFUNC);

	mw = waiter_make(NULL);
	w = waiter_spawn(mw, int_to_pointer(31416));

	thread_create(test_inter_main, w, THREAD_F_DETACH | THREAD_F_PANIC, 0);

	emit("main thread waiting");
	if (!waiter_suspend(mw))
		s_error("could not suspend itself");
	emit("main thread awoken");

	refed = waiter_refcnt_dec(w);
	emit("child waiter %s referenced", refed ? "still" : "no longer");
	while (waiter_child_count(mw) != 1) {
		emit("waiting for all children in waiter to go");
		compat_sleep_ms(5);
	}
	refed = waiter_refcnt_dec(mw);
	emit("master waiter %s referenced", refed ? "still" : "no longer");
}

struct test_semaphore_arg {
	int n;			/* thread number */
	semaphore_t *s;	/* semaphore to use */
};

static void *
test_semaphore_main(void *arg)
{
	struct test_semaphore_arg *ta = arg;
	int i;
	int n = ta->n;
	semaphore_t *s = ta->s;

	xfree(ta);

	for (i = 0; i < 6; i++) {
		bool got = TRUE;
		emit("thread #%d alive, waiting for event", n);
		if (semaphore_acquire(s, 1, NULL)) {
			emit("#%d got semaphore!", n);
		} else {
			s_warning("thread #%d cannot get semaphore: %m", n);
			got = FALSE;
		}
		sleep(1);
		if (got) {
			emit("#%d releasing semaphore!", n);
			semaphore_release(s, 1);
		}
	}

	emit("thread #%d exiting!", n);
	return NULL;
}

static int
test_semaphore_thread_launch(int n, semaphore_t *s)
{
	struct test_semaphore_arg *arg;

	XMALLOC(arg);
	arg->n = n;
	arg->s = s;

	return thread_create(test_semaphore_main, arg, THREAD_F_PANIC, 0);
}

static void
test_semaphore(bool emulated)
{
	semaphore_t *s;
	tm_t timeout;
	int i;
	int r[3];

	TESTING(G_STRFUNC);

	s = semaphore_create_full(0, emulated);
	if (semaphore_acquire_try(s, 1))
		s_error("could acquire empty semaphore!");
	semaphore_release(s, 2);

	tm_fill_ms(&timeout, 1000);

	if (!semaphore_acquire(s, 1, &timeout))
		s_error("could not acquire semaphore, first time!");
	if (!semaphore_acquire(s, 1, &timeout))
		s_error("could not acquire semaphore, second time!");

	tm_fill_ms(&timeout, 500);
	emit("will wait 1/2 second...");
	if (semaphore_acquire(s, 1, &timeout))
		s_error("could acquire empty semaphore!");
	g_assert_log(EAGAIN == errno,
		"improper errno, expected EAGAIN (%d) but got %m", EAGAIN);
	emit("good, failed to acquire empty semaphore.");

	r[0] = test_semaphore_thread_launch(1, s);
	r[1] = test_semaphore_thread_launch(2, s);
	r[2] = test_semaphore_thread_launch(3, s);

	semaphore_release(s, 1);

	for (i = 0; i < 6; i++) {
		emit("main alive");
		sleep(1);
	}

	emit("main waiting for subthreads");

	for (i = 0; UNSIGNED(i) < N_ITEMS(r); i++) {
		if (-1 == thread_join(r[i], NULL))
			s_error("failed to join with %s: %m", thread_id_name(r[i]));
	}

	emit("main is done, final semaphore value is %d", semaphore_value(s));

	semaphore_destroy(&s);
}

/*
 * The tennis game is a C port of a C++ demo program posted to
 * comp.programming.threads circa 2001 to test condition waiting
 * implementations and outline bugs in them.
 *
 * When run normally without noise, no spurious wakeups should happen and
 * of course no deadlocks.
 *
 * When broadcast noise is added, there will be spurious wakeups but there
 * should be no deadlocks either.
 */

enum game_state {
	START_GAME,			/* Game starting */
	PLAYER_A,			/* Player A's turn */
	PLAYER_B,			/* Player B's turn */
	GAME_OVER,			/* Game over */
	ONE_PLAYER_GONE,
	BOTH_PLAYER_GONE,
};

static enum game_state game_state;
static mutex_t game_state_lock = MUTEX_INIT;
static cond_t game_state_change = COND_INIT;
static struct game_stats {
	int play;
	int spurious;
	int timeout;
} game_stats[2];
const char *name[] = { "A", "B" };
enum game_state other[] = { PLAYER_B, PLAYER_A };

static void
create_player(process_fn_t start, int n)
{
	g_assert(n >= 0 && n < (int) N_ITEMS(name));

	if (-1 == thread_create(start, int_to_pointer(n), THREAD_F_DETACH, 8192))
		s_error("cannot launch player %s: %m", name[n]);
}

static void *
player(void *num)
{
	int n;
	enum game_state other_player;
	const char *me;
	struct game_stats *stats;
	tm_t timeout;

	n = pointer_to_int(num);
	me = name[n];
	other_player = other[n];
	stats = &game_stats[n];

	if (cond_timeout != 0)
		tm_fill_ms(&timeout, cond_timeout);

	mutex_lock(&game_state_lock);

	while (game_state < GAME_OVER) {
		stats->play++;
		emitz("%s plays", me);

		game_state = other_player;
		cond_signal(&game_state_change, &game_state_lock);

		/* Wait until it's my turn to play again */

		do {
			if (cond_timeout != 0) {
				bool success = cond_timed_wait_clean(
					&game_state_change, &game_state_lock, &timeout);

				if (!success) {
					stats->timeout++;
					emitz("** TIMEOUT ** %s wakeup", me);
					continue;
				}
			} else {
				cond_wait_clean(&game_state_change, &game_state_lock);
			}

			if (other_player == game_state) {
				stats->spurious++;
				emitz("** SPURIOUS ** %s wakeup", me);
			}
		} while (other_player == game_state);
	}

	game_state++;
	emit("%s leaving", me);

	cond_broadcast(&game_state_change, &game_state_lock);
	mutex_unlock(&game_state_lock);

	return NULL;
}

static void
player_stats(int n)
{
	struct game_stats *stats;

	g_assert(n >= 0 && n < (int) N_ITEMS(game_stats));

	stats = &game_stats[n];

	emit("%s played %d times (%d spurious event%s, %d timeout%s)",
		name[n], stats->play, PLURAL(stats->spurious), PLURAL(stats->timeout));
}

static void
test_condition(unsigned play_time, bool emulated, bool monitor, bool noise)
{
	int i;
	game_state = START_GAME;
	waiter_t *w;
	uint notifications = 0;

	TESTING(G_STRFUNC);

	g_assert(0 == cond_waiting_count(&game_state_change));

	if (emulated)
		cond_init_full(&game_state_change, &game_state_lock, emulated);

	g_assert(0 == cond_waiting_count(&game_state_change));
	g_assert(0 == cond_pending_count(&game_state_change));
	g_assert(0 == cond_signal_count(&game_state_change));

	for (i = 0; i < (int) N_ITEMS(name); i++) {
		create_player(player, i);
	}

	if (monitor) {
		struct pollfd wfd[1];
		tm_t end, play;

		tm_now_exact(&end);
		tm_fill_ms(&play, play_time);
		tm_add(&end, &play);

		w = waiter_make(NULL);
		cond_waiter_add(&game_state_change, w);
		g_assert(2 == waiter_refcnt(w));

		if (!waiter_suspend(w))
			s_warning("cannot suspend myself");
		if (waiter_notified(w)) {
			waiter_ack(w);
			notifications++;
		} else {
			s_warning("waiter should have been notified");
		}

		wfd[0].fd = waiter_fd(w);
		wfd[0].events = POLLIN;

		for (;;) {
			tm_t now;
			int ret;

			tm_now_exact(&now);
			if (tm_elapsed_f(&end, &now) <= 0.0)
				break;

			ret = compat_poll(wfd, N_ITEMS(wfd), 1000);
			if (ret < 0) {
				s_warning("poll() failed: %m");
			} else {
				emit_zap("player", "[match still on]");
				notifications++;
				waiter_ack(w);
			}
		}

		cond_waiter_remove(&game_state_change, w);
		g_assert(1 == waiter_refcnt(w));
		waiter_refcnt_dec(w);
	} else {
		compat_sleep_ms(play_time);	/* Let them play */
	}

	if (noise) {
		emit("** Noise ON **");
		for (i = 0; i < 100000; i++) {
			mutex_lock(&game_state_lock);
			cond_broadcast(&game_state_change, &game_state_lock);
			mutex_unlock(&game_state_lock);
		}
		emit("** Noise OFF **");
	}

	mutex_lock(&game_state_lock);
	game_state = GAME_OVER;

	emit("Stopping the game...");

	cond_broadcast(&game_state_change, &game_state_lock);

	do {
		cond_wait_clean(&game_state_change, &game_state_lock);
	} while (game_state < BOTH_PLAYER_GONE);

	g_assert(0 == cond_waiting_count(&game_state_change));

	emit("Game over!");

	mutex_unlock(&game_state_lock);
	mutex_destroy(&game_state_lock);
	if (!cond_reset(&game_state_change))
		s_warning("cannot reset condition?");
	cond_destroy(&game_state_change);

	/* Must work also after destruction */

	g_assert(0 == cond_waiting_count(&game_state_change));
	g_assert(0 == cond_pending_count(&game_state_change));

	for (i = 0; i < (int) N_ITEMS(name); i++) {
		player_stats(i);
	}
	if (monitor)
		emit("main got %u notification%s", PLURAL(notifications));
}

static spinlock_t locks[] = { SPINLOCK_INIT, SPINLOCK_INIT };
static mutex_t mutexes[] = { MUTEX_INIT, MUTEX_INIT };
static rwlock_t rlocks[] = { RWLOCK_INIT, RWLOCK_INIT };
static rwlock_t wlocks[] = { RWLOCK_INIT, RWLOCK_INIT };
const char *fork_names[] = { "locker #1", "locker #2" };

static void *
fork_locker(void *arg)
{
	int n = pointer_to_int(arg);

	thread_set_name(fork_names[n]);

	emit("%s locking...", thread_name());

	spinlock(&locks[n]);
	mutex_lock(&mutexes[n]);
	rwlock_rlock(&rlocks[n]);
	rwlock_wlock(&wlocks[n]);

	emit("%s locked, sleeping for 5 secs", thread_name());

	sleep(5);

	emit("%s unlocking", thread_name());

	rwlock_wunlock(&wlocks[n]);
	rwlock_runlock(&rlocks[n]);
	mutex_unlock(&mutexes[n]);
	spinunlock(&locks[n]);

	return NULL;
}

static void *
fork_forker(void *arg)
{
	pid_t pid;
	unsigned running;
	bool safe = booleanize(pointer_to_int(arg));

	emit("%s() waiting 1 sec", G_STRFUNC);
	sleep(1);

	running = thread_count();
	emit("%s() forking with %u running thread%s, STID=%u", G_STRFUNC,
		PLURAL(running), thread_small_id());

	thread_lock_dump_all(STDOUT_FILENO);

	switch ((pid = thread_fork(safe))) {
	case -1:
		s_error("%s() cannot fork(): %m", G_STRFUNC);
	case 0:
		emit("%s() child process started as STID=%u",
			G_STRFUNC, thread_small_id());
		emit("%s() child has %u thread", G_STRFUNC, thread_count());
		thread_lock_dump_all(STDOUT_FILENO);
		exit(EXIT_SUCCESS);
	default:
		emit("%s() child forked, waiting...", G_STRFUNC);
#ifdef HAS_WAITPID
		{
			pid_t w = waitpid(pid, NULL, 0);
			if (-1 == w)
				s_error("%s() cannot wait(): %m", G_STRFUNC);
		}
#endif
		emit("%s() child terminated, exiting thread", G_STRFUNC);
	}

	return NULL;
}

static void
test_fork(bool safe)
{
	int l1, l2, fk, r;
	unsigned running;

	TESTING(G_STRFUNC);

	emit("--- testing thread_fork(%s)", bool_to_string(safe));

	running = thread_count();
	emit("starting with %u running thread%s", PLURAL(running));

	l1 = thread_create(fork_locker, int_to_pointer(0), THREAD_F_PANIC, 8192);
	l2 = thread_create(fork_locker, int_to_pointer(1), THREAD_F_PANIC, 8192);
	fk = thread_create(fork_forker, int_to_pointer(safe), THREAD_F_PANIC, 8192);

	r = thread_join(l1, NULL);
	if (-1 == r)
		s_error("first thread_join() failed: %m");
	r = thread_join(l2, NULL);
	if (-1 == r)
		s_error("second thread_join() failed: %m");
	r = thread_join(fk, NULL);
	if (-1 == r)
		s_error("final thread_join() failed: %m");

	running = thread_count();
	emit("ending with %u running thread%s", PLURAL(running));

	emit("--- test of thread_fork(%s) done!", bool_to_string(safe));
}

/* We are provoking infinite recursion on purpose here */
G_IGNORE_PUSH(-Winfinite-recursion)

static int
overflow_routine(void *arg)
{
	int x = pointer_to_int(arg);
	int c[128];

	ZERO(&c);
	c[0] = x;
	c[1] = overflow_routine(&c[1]);

	if (NULL == arg)
		return c[0] + c[1];

	return overflow_routine(c) + c[1];
}

G_IGNORE_POP

static void
overflow_handler(int unused_sig)
{
	(void) unused_sig;

	s_rawdebug("stack overflow signal properly caught!");

	s_rawinfo("signal_on_altstack(() = %s",
		bool_to_string(signal_on_altstack()));
	s_rawinfo("thread_on_altstack(() = %s",
		bool_to_string(thread_on_altstack()));

	g_assert(signal_on_altstack() == thread_on_altstack());
}

static void *
overflow_thread(void *arg)
{
	thread_signal(TSIG_OVFLOW, overflow_handler);
	thread_set_name("overflow");

	return int_to_pointer(overflow_routine(arg));
}

static void
test_overflow(void)
{
	int t, r;

	TESTING(G_STRFUNC);

	t = thread_create(overflow_thread, int_to_pointer(0), THREAD_F_PANIC, 8192);
	r = thread_join(t, NULL);
	if (-1 == r)
		s_error("%s(): thread_join() failed: %m", G_STRFUNC);
}

struct aqt_arg {
	aqueue_t *r, *a;
};

static void *
aqt_processor(void *arg)
{
	struct aqt_arg *aa = arg;
	aqueue_t *r = aq_refcnt_inc(aa->r);
	aqueue_t *a = aq_refcnt_inc(aa->a);

	s_message("%s starting", thread_name());

	for (;;) {
		void *msg = aq_remove(r);
		ulong len;

		if (NULL == msg)
			break;			/* NULL signals end of processing */

		len = strlen(msg);
		compat_sleep_ms(300 * len);		/* Think hard */
		aq_put(a, ulong_to_pointer(len));
	}

	s_message("%s exiting", thread_name());

	aq_refcnt_dec(a);
	aq_refcnt_dec(r);

	return NULL;
}

static void
test_aqueue(bool emulated)
{
	aqueue_t *r, *a;
	struct aqt_arg arg;
	int t;
	uint i;

	TESTING(G_STRFUNC);

	emit("%s() starting...", G_STRFUNC);

	arg.r = r = aq_make_full(emulated);		/* requests */
	arg.a = a = aq_make_full(emulated);		/* answers */

	t = thread_create(aqt_processor, &arg, THREAD_F_PANIC, 0);

	for (i = 0; i < N_ITEMS(names); i++) {
		ulong res;

		emit("computing length of \"%s\"", names[i]);

		aq_put(r, names[i]);
		res = pointer_to_ulong(aq_remove(a));

		emit("\t=> %lu bytes", res);
	}

	emit("sending EOF");

	aq_put(r, NULL);		/* Signals end to thread */
	if (-1 == thread_join(t, NULL))
		s_error("cannot join with processor thread: %m");

	aq_refcnt_dec(a);
	aq_refcnt_dec(r);

	emit("%s() all done.", G_STRFUNC);
}

static qlock_t qsync_plain = QLOCK_PLAIN_INIT;
static qlock_t qsync_recursive = QLOCK_RECURSIVE_INIT;

static void *
test_qthreads(void *arg)
{
	const char *tname = thread_name();
	qlock_t *q = arg;

	s_info("%s - starting concurrent qlock tests", tname);

	qlock_lock(q);
	s_info("%s - has read lock", tname);
	compat_sleep_ms(100);

	s_info("%s - rotating lock", tname);
	qlock_rotate(q);
	s_info("%s - has lock back", tname);
	compat_sleep_ms(100);

	s_info("%s - releasing lock", tname);
	qlock_unlock(q);

	return NULL;
}

static rwlock_t rwsync = RWLOCK_INIT;

static void *
test_rwthreads(void *unused_arg)
{
	const char *tname = thread_name();

	(void) unused_arg;

	s_info("%s - starting concurrent read tests", tname);
	rwlock_rlock(&rwsync);

	s_info("%s - has read lock", tname);
	compat_sleep_ms(100);
	s_info("%s - and now trying to upgrade it", tname);

	if (rwlock_upgrade(&rwsync)) {
		s_info("%s - could upgrade to write lock, pausing 1 second", tname);
		sleep(1);
		s_info("%s - downgrading back to read lock, pausing 1 second", tname);
		rwlock_downgrade(&rwsync);
		sleep(1);
		s_info("%s - releasing read lock, re-getting write lock", tname);
		rwlock_runlock(&rwsync);
		rwlock_wlock(&rwsync);
		s_info("%s - ok, got write lock back", tname);
	} else {
		s_info("%s - could not upgrade, releasing read lock", tname);
		rwlock_runlock(&rwsync);
		s_info("%s - waiting for write lock", tname);
		rwlock_wlock(&rwsync);
		s_info("%s - ok, got write lock, sleeping 1 second", tname);
		sleep(1);
	}

	s_info("%s - releasing write lock", tname);
	rwlock_wunlock(&rwsync);
	s_info("%s - exiting", tname);

	return NULL;
}

static void
test_qlock(void)
{
	int t[3];
	qlock_t qr = QLOCK_RECURSIVE_INIT, qp = QLOCK_PLAIN_INIT;
	unsigned i, j;

	s_info("%s starting, will be launching %s()", thread_name(),
		stacktrace_function_name(test_qthreads));

	/* The mono-threaded "cannot fail" sequence */

	printf("%s(): mono-threaded tests...\n", G_STRFUNC);
	fflush(stdout);

	if (!qlock_lock_try(&qr))
		s_error("cannot lock recursive lock");

	if (!qlock_lock_try(&qp))
		s_error("cannot lock plain lock");

	if (qlock_lock_try(&qp))
		s_error("can lock plain lock multiple times");

	if (!qlock_lock_try(&qr))
		s_error("cannot lock recursive lock multiple times");

	qlock_unlock(&qr);
	qlock_unlock(&qp);
	qlock_unlock(&qr);

	printf("%s(): mono-threaded tests succeded.\n", G_STRFUNC);
	fflush(stdout);

	/* Now for multi-threaded tests.... */

	for (j = 0; j < 2; j++) {
		qlock_t *qlocks[] = { &qsync_plain, &qsync_recursive };
		qlock_t *q = qlocks[j];

		printf("%s(): multi-threaded tests with %s...\n",
			G_STRFUNC, qlock_type(q));
		fflush(stdout);

		for (i = 0; i < N_ITEMS(t); i++) {
			t[i] = thread_create(test_qthreads, q, 0, 0);
			if (-1 == t[i])
				s_error("%s() cannot create thread %u: %m", G_STRFUNC, i);
		}

		for (i = 0; i < N_ITEMS(t); i++) {
			thread_join(t[i], NULL);
		}

		printf("%s(): multi-threaded tests with %s done.\n",
			G_STRFUNC, qlock_type(q));
		fflush(stdout);
	}
}

static void
test_rwlock(void)
{
	int t[9];
	rwlock_t rw = RWLOCK_INIT;
	unsigned i;

	TESTING(G_STRFUNC);

	s_info("%s starting, will be launching %s()", thread_name(),
		stacktrace_function_name(test_rwthreads));

	/* The mono-threaded "cannot fail" sequence */

	emit("%s(): mono-threaded tests...", G_STRFUNC);

	if (!rwlock_rlock_try(&rw))
		s_error("cannot read-lock");

	if (!rwlock_rlock_try(&rw))
		s_error("cannot recursively read-lock");

	rwlock_runlock(&rw);

	if (!rwlock_upgrade(&rw))
		s_error("cannot upgrade read-lock");

	if (rwlock_is_free(&rw))
		s_error("lock should not be free");

	rwlock_downgrade(&rw);
	rwlock_runlock(&rw);

	if (!rwlock_is_free(&rw))
		s_error("lock should be free");

	emit("%s(): mono-threaded tests succeded.", G_STRFUNC);

	/* Now for multi-threaded tests.... */

	emit("%s(): multi-threaded tests...", G_STRFUNC);

	for (i = 0; i < N_ITEMS(t); i++) {
		t[i] = thread_create(test_rwthreads, NULL, 0, 0);
		if (-1 == t[i])
			s_error("%s() cannot create thread %u: %m", G_STRFUNC, i);
	}

	for (i = 0; i < N_ITEMS(t); i++) {
		thread_join(t[i], NULL);
	}

	emit("%s(): multi-threaded tests done.", G_STRFUNC);
}

static bool test_signals_done;
static int test_signals_count;

#define TEST_SIGNALS_COUNT	3

static void
test_sighandler(int sig)
{
	emit("%s received signal #%d", thread_name(), sig);
}

static void
test_sigdone(int sig)
{
	emit("%s got signal #%d, will exit", thread_name(), sig);

	test_signals_done = TRUE;
}

static void
test_sigcount(int sig)
{
	emit("%s got signal #%d (count = %u)", thread_name(), sig,
		++test_signals_count);
}

static void
test_printsig(int sig)
{
	emit("%s got signal #%d", thread_name(), sig);
}

static void *
signalled_thread(void *unused_arg)
{
	tsigset_t set, oset;
	int count = 0;

	(void) unused_arg;

	thread_signal(TSIG_1, test_sighandler);
	thread_signal(TSIG_2, test_sighandler);
	thread_signal(TSIG_3, test_sigdone);
	thread_signal(TSIG_4, test_sighandler);

	tsig_emptyset(&set);
	tsig_addset(&set, TSIG_4);
	thread_sigmask(TSIG_BLOCK, &set, &oset);

	while (!test_signals_done) {
		if (!thread_pause())
			s_error("thread was not unblocked by signal");
		if (3 == count++) {
			emit("%s() will now get signal #4", G_STRFUNC);
			thread_sigmask(TSIG_SETMASK, &oset, NULL);
		}
	}

	emit("%s() exiting", G_STRFUNC);

	return NULL;
}

static void *
sleeping_thread(void *arg)
{
	barrier_t *b = arg;
	tm_t start, end;

	thread_signal(TSIG_1, test_sigcount);
	if (b != NULL)
		barrier_wait(b);

	tm_now_exact(&start);
	thread_sleep_ms(2000);
	tm_now_exact(&end);

	emit("%s() slept %u ms (expected 2000 ms)", G_STRFUNC,
		(uint) tm_elapsed_ms(&end, &start));

	while (test_signals_count < TEST_SIGNALS_COUNT) {
		emit("%s() got %d/%d signals so far", G_STRFUNC,
			test_signals_count, TEST_SIGNALS_COUNT);
		thread_pause();
	}

	if (b != NULL)
		barrier_wait(b);

	g_assert(TEST_SIGNALS_COUNT == test_signals_count);

	if (b != NULL) {
		tsigset_t nset, oset;
		tm_t timeout;

		tsig_emptyset(&nset);
		tsig_addset(&nset, TSIG_2);
		thread_sigmask(TSIG_BLOCK, &nset, &oset);
		thread_signal(TSIG_2, test_printsig);

		tm_fill_ms(&timeout, 2000);
		barrier_wait(b);

		tm_now_exact(&start);
		if (thread_timed_sigsuspend(&oset, &timeout)) {
			tm_now_exact(&end);
			emit("%s() suspended %u ms before getting signal", G_STRFUNC,
				(uint) tm_elapsed_ms(&end, &start));
		} else {
			g_assert_not_reached();
		}

		tm_fill_ms(&timeout, 1000);
		tm_now_exact(&start);
		if (thread_timed_sigsuspend(&oset, &timeout)) {
			g_assert_not_reached();
		} else {
			tm_now_exact(&end);
			emit("%s() suspended %u ms without getting signals", G_STRFUNC,
				(uint) tm_elapsed_ms(&end, &start));
		}

		tm_fill_ms(&timeout, 2000);

		barrier_wait(b);
		tm_now_exact(&start);
		if (thread_timed_sigsuspend(&oset, &timeout)) {
			tm_now_exact(&end);
			emit("%s() suspended %u ms (about 1 sec) before getting signal",
				G_STRFUNC, (uint) tm_elapsed_ms(&end, &start));
		} else {
			g_assert_not_reached();
		}

		barrier_free_null(&b);
	}

	return NULL;
}

static void
test_signals(void)
{
	barrier_t *b;
	int r, i;

	TESTING(G_STRFUNC);

	/* 60 is random constant, large enough to avoid it being already used */

	if (-1 != thread_kill(60, TSIG_0))
		s_error("thread #60 already exists?");

	r = thread_create(signalled_thread, NULL, THREAD_F_PANIC, 0);

	emit("%s() thread %s created", G_STRFUNC, thread_id_name(r));

	for (i = 0; i < 10; i++) {
		sleep(1);
		if (-1 == thread_kill(r, TSIG_0))
			s_error("thread #%d cannot be signalled: %m", r);
		if (-1 == thread_kill(r, TSIG_4))
			s_error("thread #%d cannot be signalled: %m", r);
		if (-1 == thread_kill(r, (i & 0x1) ? TSIG_2 : TSIG_1))
			s_error("thread #%d cannot be signalled: %m", r);
	}

	emit("%s() emitting each signal 100 times", G_STRFUNC);

	for (i = 0; i < 100; i++) {
		emitz("%d", i);
		if (-1 == thread_kill(r, TSIG_1))
			s_error("cannot send TSIG_1: %m");
		if (-1 == thread_kill(r, TSIG_2))
			s_error("cannot send TSIG_2: %m");
		if (-1 == thread_kill(r, TSIG_4))
			s_error("cannot send TSIG_4: %m");
	}

	emit("%s() done sending!", G_STRFUNC);

	if (-1 == thread_kill(r, TSIG_3))
		s_error("cannot send TSIG_3: %m");
	if (-1 == thread_join(r, NULL))
		s_error("cannot join: %m");

	emit("%s() now checking thread_sleep_ms()", G_STRFUNC);

	b = barrier_new(2);
	r = thread_create(sleeping_thread,
			barrier_refcnt_inc(b), THREAD_F_PANIC, 0);
	barrier_wait(b);		/* Give it time to setup */
	for (i = 0; i < TEST_SIGNALS_COUNT; i++) {
		if (-1 == thread_kill(r, TSIG_1))
			s_error("thread #%d cannot be signalled: %m", r);
		thread_sleep_ms(500);	/* Give it time to process signal */
	}
	emit("%s() all signals sent", G_STRFUNC);

	barrier_wait(b);		/* Let signalled thread process everything */

	emit("%s() now checking thread_timed_sigsuspend()", G_STRFUNC);

	barrier_wait(b);
	thread_kill(r, TSIG_2);
	barrier_wait(b);
	thread_sleep_ms(1000);
	thread_kill(r, TSIG_2);
	barrier_free_null(&b);
	thread_join(r, NULL);
}

static int counter;

struct computer_arg {
	int n;
	barrier_t *b;
};

static void *
computer_thread(void *arg)
{
	struct computer_arg *ca = arg;
	int n = ca->n;
	barrier_t *cb = ca->b;

	barrier_refcnt_inc(cb);
	g_assert(0 == counter);

	emit("%s(%d) started as %s", G_STRFUNC, n, thread_name());

	thread_signal(TSIG_1, test_sighandler);
	WFREE(ca);
	barrier_wait(cb);

	emit("%s(%d) incrementing counter=%d", G_STRFUNC, n,
		atomic_int_get(&counter));
	atomic_int_inc(&counter);

	barrier_wait(cb);

	emit("%s(%d) reincrementing counter=%d", G_STRFUNC, n,
		atomic_int_get(&counter));
	atomic_int_inc(&counter);

	barrier_wait(cb);
	barrier_free_null(&cb);

	emit("%s(%d) exiting", G_STRFUNC, n);

	return NULL;
}

static void
test_barrier_one(bool emulated)
{
	int t[2], i, n;
	barrier_t *cb;

	n = (int) N_ITEMS(t);
	cb = barrier_new_full(n + 1, emulated);
	counter = 0;

	for (i = 0; i < n; i++) {
		struct computer_arg *ca;
		WALLOC(ca);
		ca->n = i;
		ca->b = cb;
		t[i] = thread_create(computer_thread, ca,
				THREAD_F_DETACH | THREAD_F_PANIC, 0);
	}

	sleep(1);					/* Wait until threads have started */
	g_assert(0 == counter);		/* Nobody can change that before the barrier */

	barrier_wait(cb);
	emit("%s() reached barrier the first time: threads started", G_STRFUNC);

	barrier_master_wait(cb);
	emit("%s() reached barrier the second time as master", G_STRFUNC);

	for (i = 0; i < n; i++) {
		if (-1 == thread_kill(t[i], TSIG_1))
			s_error("cannot signal processor thread %u: %m", i);
	}

	g_assert(n == counter);		/* We're the master thread */
	sleep(1);					/* and we're the only thread running */
	atomic_int_inc(&counter);
	g_assert(n + 1 == counter);	/* We're the master thread */

	emit("%s() releasing threads, counter=%d", G_STRFUNC, counter);
	barrier_release(cb);

	barrier_wait(cb);
	barrier_free_null(&cb);
	emit("%s() computation done, counter=%d (expected is %d)",
		G_STRFUNC, counter, 2 * n  + 1);
	g_assert(2 * n + 1 == counter);
}

static void
test_barrier(unsigned repeat, bool emulated)
{
	unsigned i;

	TESTING(G_STRFUNC);

	for (i = 0; i < repeat; i++) {
		test_barrier_one(emulated);
	}
}

static int dam_counter;

struct dam_arg {
	int n;
	dam_t *d;
	barrier_t *b;
};

static void *
dam_thread(void *arg)
{
	struct dam_arg *da = arg;
	int n = da->n;
	dam_t *d = da->d;
	barrier_t *b= da->b;

	emit("%s(%d) started as %s", G_STRFUNC, n, thread_name());

	dam_wait(d);

	emit("%s(%d) incrementing counter=%d", G_STRFUNC, n,
		atomic_int_get(&dam_counter));
	atomic_int_inc(&dam_counter);

	dam_wait(d);

	emit("%s(%d) reincrementing counter=%d", G_STRFUNC, n,
		atomic_int_get(&dam_counter));
	atomic_int_inc(&dam_counter);

	dam_wait(d);		/* Dam disabled, will not wait */
	emit("%s(%d) last incrementing counter=%d", G_STRFUNC, n,
		atomic_int_get(&dam_counter));
	atomic_int_inc(&dam_counter);
	dam_free_null(&d);

	emit("%s(%d) waiting, counter=%d", G_STRFUNC, n,
		atomic_int_get(&dam_counter));

	barrier_wait(b);
	barrier_free_null(&b);

	emit("%s(%d) exiting", G_STRFUNC, n);

	return NULL;
}

static void
test_dam_one(bool emulated)
{
	int t[2], i, n;
	dam_t *d;
	barrier_t *b;
	uint key;

	n = (int) N_ITEMS(t);
	d = dam_new_full(&key, emulated);
	b = barrier_new_full(n + 1, emulated);
	atomic_int_set(&dam_counter, 0);

	for (i = 0; i < n; i++) {
		struct dam_arg *da;
		WALLOC(da);
		da->n = i;
		da->d = dam_refcnt_inc(d);
		da->b = barrier_refcnt_inc(b);
		t[i] = thread_create(dam_thread, da,
				THREAD_F_DETACH | THREAD_F_PANIC, 0);
	}

	thread_sleep_ms(500);
	dam_release(d, key);
	thread_sleep_ms(500);
	dam_disable(d, key);
	barrier_wait(b);
	g_assert(3 * n == atomic_int_get(&dam_counter));
	barrier_free_null(&b);
	dam_free_null(&d);
}

static void
test_dam(unsigned repeat, bool emulated)
{
	unsigned i;

	TESTING(G_STRFUNC);

	for (i = 0; i < repeat; i++) {
		test_dam_one(emulated);
	}
}

enum memory_alloc {
	MEMORY_XMALLOC	= 0,
	MEMORY_HALLOC	= 1,
	MEMORY_WALLOC	= 2,
	MEMORY_VMM		= 3,
	MEMORY_VMEA		= 4
};

struct memory {
	enum memory_alloc type;
	size_t size;
	void *p;
};

#define MEMORY_VMM_MIN			4096
#define MEMORY_VMM_MAX			16384
#define MEMORY_VMM_PROPORTION	20

#define MEMORY_MIN	8
#define MEMORY_MAX	8192

#define MEMORY_ALLOCATIONS	4096

struct exercise_results {
	size_t amount;			/* Amount of allocations / frees */
	time_delta_t alloc_us;	/* Allocation time, in microseconds */
	time_delta_t free_us;	/* Freeing time, in microseconds */
};

struct exercise_param {
	int percentage;			/* Random percentage of blocks to free remotely */
};

/*
 * This list is filled with memory objects that must be freed by a remote
 * thread, randomly.  All accesses are protected by a spinlock.
 */
static pslist_t *exercise_list;
static spinlock_t exercise_list_slk = SPINLOCK_INIT;

#define EXERCISE_LIST_LOCK		spinlock(&exercise_list_slk)
#define EXERCISE_LIST_UNLOCK	spinunlock(&exercise_list_slk)

static void
exercise_list_add(const struct memory *m)
{
	EXERCISE_LIST_LOCK;
	exercise_list = pslist_prepend_const(exercise_list, WCOPY(m));
	EXERCISE_LIST_UNLOCK;
}

static void
exercise_list_shuffle_once(void)
{
	EXERCISE_LIST_LOCK;
	exercise_list = pslist_shuffle(exercise_list);
	EXERCISE_LIST_UNLOCK;
}

static void
exercise_list_shuffle(void)
{
	static once_flag_t flag;

	once_flag_run(&flag, exercise_list_shuffle_once);
}

static bool
exercise_list_remove(struct memory *m)
{
	struct memory *mi;

	EXERCISE_LIST_LOCK;
	mi = pslist_shift(&exercise_list);
	EXERCISE_LIST_UNLOCK;

	if (NULL == mi)
		return FALSE;

	*m = *mi;		/* Struct copy */
	WFREE(mi);
	return TRUE;
}

static inline void ALWAYS_INLINE
exercise_alloc_memory(struct memory *m)
{
	switch (m->type) {
	case MEMORY_XMALLOC:
		m->p = xmalloc(m->size);
		break;
	case MEMORY_HALLOC:
		m->p = halloc(m->size);
		break;
	case MEMORY_WALLOC:
		m->p = walloc(m->size);
		break;
	case MEMORY_VMM:
		m->p = vmm_alloc(m->size);
		break;
	case MEMORY_VMEA:
		m->p = vmea_alloc(m->size);
		break;
	default:
		g_assert_not_reached();
	}
}

static inline void ALWAYS_INLINE
exercise_free_memory(const struct memory *m)
{
	switch (m->type) {
	case MEMORY_XMALLOC:
		xfree(m->p);
		break;
	case MEMORY_HALLOC:
		hfree(m->p);
		break;
	case MEMORY_WALLOC:
		wfree(m->p, m->size);
		break;
	case MEMORY_VMM:
		vmm_free(m->p, m->size);
		break;
	case MEMORY_VMEA:
		if (!vmea_free(m->p, m->size)) {
			s_error("%s(): cannot free %'zu-byte VMEA region at %p",
				G_STRFUNC, m->size, m->p);
		}
		break;
	default:
		g_assert_not_reached();
	}
}

static void *
exercise_memory(void *arg)
{
	struct memory *mem;
	size_t i, fill, filled;
	struct exercise_results *er;
	struct exercise_param *ep;
	tm_t start, end;

	ep = arg;

	WALLOC(er);

	fill = allocator_fill != 0 ? allocator_fill : MEMORY_ALLOCATIONS;

	XMALLOC_ARRAY(mem, fill);

	for (i = 0, filled = 0; i < fill; i++) {
		struct memory *m = &mem[filled];

		switch (allocator) {
		case 'r':
			if (random_value(99) < MEMORY_VMM_PROPORTION) {
				m->type = MEMORY_VMM + random_value(1);
				m->size = MEMORY_VMM_MIN +
					random_value(MEMORY_VMM_MAX - MEMORY_VMM_MIN);
			} else {
				m->type = random_value(2);
				m->size = MEMORY_MIN + random_value(MEMORY_MAX - MEMORY_MIN);
			}
			break;
		case 'e':
			m->type = MEMORY_VMEA;
			break;
		case 'h':
			m->type = MEMORY_HALLOC;
			break;
		case 'v':
			m->type = MEMORY_VMM;
			break;
		case 'w':
			m->type = MEMORY_WALLOC;
			break;
		case 'x':
			m->type = MEMORY_XMALLOC;
			break;
		default:
			g_assert_not_reached();
		}

		m->size = 0 != allocator_bsize ? allocator_bsize :
			m->type >= MEMORY_VMM ?
				MEMORY_VMM_MIN + random_value(MEMORY_VMM_MAX - MEMORY_VMM_MIN) :
				MEMORY_MIN + random_value(MEMORY_MAX - MEMORY_MIN);

		if (ep->percentage != 0 && (int) random_value(99) < ep->percentage) {
			exercise_alloc_memory(m);
			exercise_list_add(m);
		} else {
			filled++;
		}
	}

	er->amount = filled;

	tm_now_exact(&start);
	for (i = 0; i < filled; i++) {
		struct memory *m = &mem[i];
		exercise_alloc_memory(m);
	}
	tm_now_exact(&end);

	er->alloc_us = tm_elapsed_us(&end, &start);

	if (randomize_free)
		SHUFFLE_ARRAY_N(mem, filled);

	tm_now_exact(&start);
	for (i = 0; i < filled; i++) {
		struct memory *m = &mem[i];
		exercise_free_memory(m);
	}
	tm_now_exact(&end);

	er->free_us = tm_elapsed_us(&end, &start);

	XFREE_NULL(mem);

	{
		size_t remote = fill * ep->percentage / 100;
		struct memory m;

		exercise_list_shuffle();

		while (remote-- && exercise_list_remove(&m))
			exercise_free_memory(&m);
	}

	return er;
}

static void
test_memory_one(struct exercise_results *total, bool posix, int percentage)
{
	long cpus = 0 == cpu_count ? getcpucount() : cpu_count;
	int *t, i, n;
	pthread_t *p;
	struct exercise_param ep;

	n = cpus;
	ep.percentage = percentage;

	WALLOC_ARRAY(t, n);
	WALLOC_ARRAY(p, n);

	if ('r' == allocator || 'e' == allocator) {
		size_t fill = allocator_fill != 0 ? allocator_fill : MEMORY_ALLOCATIONS;
		size_t max = fill * MEMORY_VMM_MAX * n;
		vmea_reserve(max, FALSE);
	}

	for (i = 0; i < n; i++) {
		t[i] = thread_create(exercise_memory, &ep,
				THREAD_F_PANIC, THREAD_STACK_MIN);

		if (posix) {
			pthread_t pt = posix_thread_create(exercise_memory, &ep, TRUE);
			p[i] = pt;
		}
	}

	for (i = 0; i < n; i++) {
		int j;

		for (j = 0; j < 2; j++) {
			int r;
			void *e;
			struct exercise_results *er;

			switch (j) {
			case 0:
				r = thread_join(t[i], &e);
				break;
			case 1:
				if (!posix)
					goto next_thread;
				r = pthread_join(p[i], &e);
				if (r != 0) {
					errno = r;
					r = -1;
				}
				break;
			default:
				g_assert_not_reached();
			}

			if (-1 == r) {
				s_error("%s(): could not join with %s: %m",
					G_STRFUNC,
					0 == j ? thread_id_name(t[i]) : "POSIX thread");
			}

			er = e;
			total->amount += er->amount;
			total->alloc_us += er->alloc_us;
			total->free_us += er->free_us;
			WFREE(er);
		}

	next_thread:
		continue;
	}

	WFREE_ARRAY(t, n);
	WFREE_ARRAY(p, n);

	{
		struct memory m;

		while (exercise_list_remove(&m))
			exercise_free_memory(&m);
	}

	vmea_close();
}

static void
test_memory(unsigned repeat, bool posix, int percentage)
{
	long cpus = 0 == cpu_count ? getcpucount() : cpu_count;
	unsigned i;

	TESTING(G_STRFUNC);

	emit("%s() detected %ld CPU%s%s", G_STRFUNC, PLURAL(cpus),
		0 == cpu_count ? "" : " (forced by -c)");

	if (randomize_free)
		emit("%s() will free blocks in random order", G_STRFUNC);

	for (i = 0; i < repeat; i++) {
		tm_t start, end, elapsed;
		struct exercise_results total;

		ZERO(&total);

		tm_now_exact(&start);
		test_memory_one(&total, posix, percentage);
		tm_now_exact(&end);

		tm_elapsed(&elapsed, &end, &start);

		emit("%s() #%d finished! (%f secs, %.3f us/alloc, %.3f us/free)",
			G_STRFUNC, i, tm2f(&elapsed),
			total.alloc_us / (double) total.amount,
			total.free_us / (double) total.amount);
	}

	emit("%s() done!", G_STRFUNC);
}

static int teq_recv_cnt;
static int teq_sent_cnt;
static int teq_callout_cnt;
static bool teq_recv_completed;

static void *
teq_recv_rpc(void *arg)
{
	s_message("%s(): arg=%p", G_STRFUNC, arg);
	return arg;
}

static void
teq_recv_plain(void *arg)
{
	s_message("%s(): arg=%p", G_STRFUNC, arg);
	teq_recv_cnt++;
}

static void
teq_recv_done(void *arg)
{
	barrier_t *b = arg;
	s_message("%s(): arg=%p", G_STRFUNC, arg);
	barrier_wait(b);
	barrier_free_null(&b);
	s_message("%s(): done!", G_STRFUNC);
	teq_recv_completed = TRUE;
}

static void
teq_sent_plain(void *arg)
{
	s_message("%s(): arg=%p", G_STRFUNC, arg);
	atomic_int_inc(&teq_sent_cnt);
}

static void
teq_sent_callout(void *arg)
{
	waiter_t *w = arg;

	s_message("%s(): arg=%p", G_STRFUNC, arg);
	teq_callout_cnt++;
	waiter_signal(w);
	waiter_refcnt_dec(w);
}

static void *
teq_receiver(void *arg)
{
	barrier_t *b = arg;

	teq_recv_completed = FALSE;
	teq_create();
	s_message("%s(): thread event queue installed", G_STRFUNC);
	barrier_wait(b);			/* Receiver installed event queue */
	barrier_free_null(&b);
	s_message("%s(): sender created its thread event queue", G_STRFUNC);

	while (!teq_recv_completed)
		thread_sleep_ms(10);

	g_assert(4 == teq_recv_cnt);

	return NULL;
}

struct teq_sender_arg {
	int receiver;
	barrier_t *b;
};

static void *
teq_sender(void *arg)
{
	struct teq_sender_arg *sa = arg;
	waiter_t *w;
	void *result;

	teq_create();
	s_message("%s(): thread event queue installed", G_STRFUNC);
	barrier_wait(sa->b);		/* Wait for receiver to install event queue */
	s_message("%s(): receiver created its thread event queue", G_STRFUNC);

	w = waiter_make(NULL);

	result = teq_rpc(sa->receiver, teq_recv_rpc, w);
	g_assert(w == result);

	result = teq_rpc(sa->receiver, teq_recv_rpc, sa);
	g_assert(sa == result);

	teq_post(sa->receiver, teq_recv_plain, NULL);
	teq_post_ack(sa->receiver, teq_recv_plain, int_to_pointer(1),
		TEQ_AM_CALL, teq_sent_plain, int_to_pointer(2));
	teq_post_ack(sa->receiver, teq_recv_plain, int_to_pointer(3),
		TEQ_AM_EVENT, teq_sent_plain, int_to_pointer(4));
	teq_post_ack(sa->receiver, teq_recv_plain, int_to_pointer(5),
		TEQ_AM_CALLOUT, teq_sent_callout, waiter_refcnt_inc(w));

	/* Final event will unlock the barrier */
	teq_post(sa->receiver, teq_recv_done, barrier_refcnt_inc(sa->b));

	barrier_wait(sa->b);		/* Waiting for teq_recv_done() */
	s_message("%s(): receiver processed final event", G_STRFUNC);
	barrier_free_null(&sa->b);

	g_assert(2 == atomic_int_get(&teq_sent_cnt));

	waiter_suspend(w);			/* Let callout queue event come */
	waiter_refcnt_dec(w);
	g_assert(1 == teq_callout_cnt);

	return NULL;
}

static void
test_teq(unsigned repeat)
{
	TESTING(G_STRFUNC);

	while (repeat--) {
		int s, r;
		barrier_t *b;
		struct teq_sender_arg arg;

		teq_recv_cnt = teq_callout_cnt = 0;
		atomic_int_set(&teq_sent_cnt, 0);

		b = barrier_new(2);
		r = thread_create(teq_receiver, barrier_refcnt_inc(b),
				THREAD_F_PANIC, THREAD_STACK_MIN);
		arg.receiver = r;
		arg.b = b;
		s = thread_create(teq_sender, &arg, THREAD_F_PANIC, THREAD_STACK_MIN);

		thread_join(r, NULL);
		thread_join(s, NULL);
	}
}

static void
evq_event(void *arg)
{
	tm_t now;
	int id = pointer_to_int(arg);

	tm_now_exact(&now);		/* Force accurate timestamp in logging message */
	s_message("%s(%d) called in %s", G_STRFUNC, id, thread_name());
}

static void *
evq_one(void *unused_arg)
{
	evq_event_t *eve;

	(void) unused_arg;

	s_message("%s() starting", G_STRFUNC);

	eve = evq_insert(1000, evq_event, NULL);
	g_assert(eve != NULL);
	evq_cancel(&eve);
	g_assert(NULL == eve);

	eve = evq_insert(100, evq_event, int_to_pointer(2));
	g_assert(eve != NULL);
	evq_schedule(50, evq_event, int_to_pointer(1));
	thread_sleep_ms(100);
	evq_schedule(200, evq_event, int_to_pointer(3));
	evq_schedule(500, evq_event, int_to_pointer(4));

	thread_sleep_ms(1000);

	evq_cancel(&eve);

	evq_schedule(100, evq_event, NULL);
	s_message("%s() exiting -- expect discarding", G_STRFUNC);
	return NULL;
}

static void *
evq_two(void *unused_arg)
{
	(void) unused_arg;

	s_message("%s() starting", G_STRFUNC);

	evq_schedule(200, evq_event, int_to_pointer(2));
	evq_schedule(100, evq_event, int_to_pointer(1));
	evq_schedule(300, evq_event, int_to_pointer(3));

	thread_sleep_ms(1000);

	s_message("%s() exiting", G_STRFUNC);
	return NULL;
}

static void
test_evq(unsigned repeat)
{
	TESTING(G_STRFUNC);

	while (repeat--) {
		int s, r;

		r = thread_create(evq_one, NULL, THREAD_F_PANIC, THREAD_STACK_MIN);
		s = thread_create(evq_two, NULL, THREAD_F_PANIC, THREAD_STACK_MIN);

		thread_join(r, NULL);
		thread_join(s, NULL);
	}
}

#define INTERRUPTS	5	/* Amount of interrupts we're sending */

static int interrupt_count;
static int interrupt_acks;
static volatile bool interrupt_seen_2, interrupt_processed_2;

static void *
intr_process(void *arg)
{
	int n = pointer_to_int(arg);
	bool unsafe = signal_in_unsafe_handler();

	s_info("%s(): got %sinterrupt n=%d", G_STRFUNC, unsafe ? "UNSAFE " : "", n);

	atomic_int_inc(&interrupt_count);

	switch (n) {
	case 0:
	case 1:
	case 3:
		if (unsafe)
			s_carp("%s(): UNSAFE interrupt trace", G_STRFUNC);
		break;
	case 2:
		interrupt_seen_2 = TRUE;
		s_carp("%s(): showing %strace", G_STRFUNC, unsafe ? "UNSAFE " : "");
		interrupt_processed_2 = TRUE;
		atomic_mb();
		break;
	case 4:
		if (-1 == thread_cancel(thread_small_id()))
			s_warning("thread_cancel(self) failed: %m");
		break;
	}

	s_info("%s(): done with interrupt n=%d", G_STRFUNC, n);

	return arg;
}

static void *
intr_thread(void *unused)
{
	int i;

	(void) unused;

	for (i = 0; i < 20; i++) {
		s_message("%s(): sleeping for 1 sec", G_STRFUNC);
		thread_sleep_ms(1000);
	}

	s_error("%s(): something is wrong, missed an interrupt? (got %d)",
		G_STRFUNC, interrupt_count);

	return NULL;
}

static void
intr_acknowledge(void *arg, void *udata)
{
	g_assert(udata == (void *) intr_thread);
	g_assert_log(arg == int_to_pointer(1), "arg=%d", pointer_to_int(arg));

	s_message("%s(): got ack for interrupt n=%d",
		G_STRFUNC, pointer_to_int(arg));

	interrupt_acks++;
}

static void
test_interrupts(void)
{
	int i, t, err;

	TESTING(G_STRFUNC);

	t = thread_create(intr_thread, NULL,
			THREAD_F_PANIC | THREAD_F_WAIT, THREAD_STACK_DFLT);

	for (i = 0; i < INTERRUPTS; i++) {
		void *arg = NULL;
		notify_data_fn_t cb = NULL;

		/* Signalled thread needs to have seen interrupt #2 before continuing */
		if (i > 2 && !interrupt_seen_2) {
			size_t j;
			s_message("%s(): waiting for interrupt #2 to be seen", G_STRFUNC);
			/* Wait about 10 seconds */
			for (j = 0; !interrupt_seen_2 && j < 100; j++) {
				thread_sleep_ms(100);
			}
			if (!interrupt_seen_2)
				s_error("%s(): timeout waiting for interrupt #2", G_STRFUNC);
		}
		if (i > 2 && !interrupt_processed_2) {
			size_t j;
			s_message("%s(): waiting for interrupt #2 processing", G_STRFUNC);
			/* Wait about 30 seconds for the stack unwinding and formatting */
			for (j = 0; !interrupt_processed_2 && j < 300; j++) {
				thread_sleep_ms(100);
			}
			if (!interrupt_processed_2)
				s_error("%s(): timeout for interrupt #2 processing", G_STRFUNC);
			s_message("%s(): all done for interrupt #2", G_STRFUNC);
		}

		s_message("%s(): sending interrupt #%d to %s",
			G_STRFUNC, i, thread_id_name(t));

		/* Interrupt #1 will be acknowledged */
		if (1 == i) {
			arg = (void *) intr_thread;
			cb = intr_acknowledge;
		}

		err = thread_interrupt(t, intr_process, int_to_pointer(i), cb, arg);
		if (0 != err)
			break;
		thread_sleep_ms(100);	/* Space interrupts to allow races */
	}
	if (err != 0) {
		errno = err;
		s_warning("%s(): thread_interrupt() failed: %m", G_STRFUNC);
		if (-1 == thread_cancel(t))
			s_error("%s(): thread_cancel() failed: %m", G_STRFUNC);
	} else {
		tm_t start, end;
		tm_now_exact(&start);
		for (
			i = 0;
			i < 300 && INTERRUPTS != atomic_int_get(&interrupt_count);
			i++
		) {
			thread_sleep_ms(10);	/* Give it time to process interrupts */
		}
		tm_now_exact(&end);
		s_message("%s(): waited %ld ms for completion", G_STRFUNC,
			tm_elapsed_ms(&end, &start));
	}
	if (-1 == thread_join(t, NULL))
		s_warning("%s(): thread_join() failed: %m", G_STRFUNC);

	g_assert_log(INTERRUPTS == atomic_int_get(&interrupt_count),
		"interrupt_count=%d (expected %d)", interrupt_count, INTERRUPTS);
	g_assert_log(1 == interrupt_acks,
		"interrupt_acks=%d (expected 1)", interrupt_acks);
}

static unsigned
get_number(const char *arg, int opt)
{
	int error;
	uint32 val;

	val = parse_v32(arg, NULL, &error);
	if (0 == val && error != 0) {
		fprintf(stderr, "%s: invalid -%c argument \"%s\": %s\n",
			getprogname(), opt, arg, english_strerror(error));
		exit(EXIT_FAILURE);
	}

	return val;
}

int
main(int argc, char **argv)
{
	extern int optind;
	extern char *optarg;
	int c, percentage = 0;
	bool create = FALSE, join = FALSE, sem = FALSE, emulated = FALSE;
	bool play_tennis = FALSE, monitor = FALSE, noise = FALSE, posix = FALSE;
	bool inter = FALSE, forking = FALSE, aqueue = FALSE, rwlock = FALSE;
	bool signals = FALSE, barrier = FALSE, overflow = FALSE, memory = FALSE;
	bool stats = FALSE, teq = FALSE, cancel = FALSE, dam = FALSE, evq = FALSE;
	bool interrupts = FALSE, qlock = FALSE;
	unsigned repeat = 1, play_time = 0;
	const char options[] = "a:b:c:ef:hjn:r:st:vwxz:ABCDEFHIKMNOPQRST:UVWX";

	progstart(argc, argv);
	thread_set_main(TRUE);		/* We're the main thread, we can block */
	crash_init(argv[0], getprogname(), 0, NULL);

	while ((c = getopt(argc, argv, options)) != EOF) {
		switch (c) {
		case 'A':			/* use asynchronous exit callbacks */
			async_exit = TRUE;
			break;
		case 'B':			/* test synchronization barriers */
			barrier = TRUE;
			break;
		case 'C':			/* test thread creation */
			create = TRUE;
			break;
		case 'D':			/* test synchronization dams */
			dam = TRUE;
			break;
		case 'E':			/* test thread signals ("events") */
			signals = TRUE;
			break;
		case 'F':			/* test thread_fork() */
			forking = TRUE;
			break;
		case 'H':			/* test thread interrupts */
			interrupts = TRUE;
			break;
		case 'I':			/* test inter-thread signaling */
			inter = TRUE;
			break;
		case 'K':			/* test thread cancellation */
			cancel = TRUE;
			break;
		case 'M':			/* monitor tennis match */
			monitor = TRUE;
			break;
		case 'N':			/* add cond_broadcast() noise */
			noise = TRUE;
			break;
		case 'O':			/* test stack overflow */
			overflow = TRUE;
			break;
		case 'P':			/* add extra POSIX threads */
			posix = TRUE;
			break;
		case 'Q':			/* test asynchronous queue */
			aqueue = TRUE;
			break;
		case 'R':			/* test rwlock */
			rwlock = TRUE;
			break;
		case 'S':			/* test semaphore layer */
			sem = TRUE;
			break;
		case 'T':			/* test condition layer */
			play_time = get_number(optarg, c);
			play_tennis = TRUE;
			break;
		case 'U':			/* test qlock */
			qlock = TRUE;
			break;
		case 'V':			/* test thread event queue */
			teq = TRUE;
			break;
		case 'W':			/* test event queue */
			evq = TRUE;
			break;
		case 'X':			/* exercise memory allocation */
			memory = TRUE;
			break;
		case 'a':			/* choose allocator for -X tests */
			allocator = *optarg;
			break;
		case 'b':			/* set block size to use for -X tests */
			allocator_bsize = get_number(optarg, c);
			break;
		case 'c':			/* override CPU count */
			cpu_count = get_number(optarg, c);
			break;
		case 'e':			/* use emulated semaphores */
			emulated = TRUE;
			break;
		case 'f':			/* allocator fill count */
			allocator_fill = get_number(optarg, c);
			break;
		case 'j':			/* join threads */
			join = TRUE;
			break;
		case 'n':			/* repeat tests */
			repeat = get_number(optarg, c);
			break;
		case 'r':			/* ratio (percentage) of objects to free remotely */
			percentage = get_number(optarg, c);
			break;
		case 't':			/* condition wait timeout (0 = none) */
			cond_timeout = get_number(optarg, c);
			break;
		case 's':			/* threads sleep for 1 second before ending */
			sleep_before_exit = TRUE;
			break;
		case 'v':			/* dump thread statistics at the end */
			stats = TRUE;
			break;
		case 'w':			/* wait for created threads */
			wait_threads = TRUE;
			break;
		case 'x':			/* free allocated memory by -X tests randomly */
			randomize_free = TRUE;
			break;
		case 'z':			/* zap message from routines using emitz() */
			zap_record(optarg);
			break;
		case 'h':			/* show help */
		default:
			usage();
			break;
		}
	}

	if ((argc -= optind) != 0)
		usage();

	if (!atomic_ops_available())
		s_warning("Atomic memory operations not supported!");

	if (percentage < 0) {
		s_warning("Raising percentage (%d) to 0", percentage);
		percentage = 0;
	}

	if (percentage > 100) {
		s_warning("Capping percentage (%d) to 100", percentage);
		percentage = 100;
	}

	g_assert(0 == thread_by_name("main"));

	if (interrupts)
		test_interrupts();

	if (aqueue)
		test_aqueue(emulated);

	if (rwlock)
		test_rwlock();

	if (qlock)
		test_qlock();

	if (sem)
		test_semaphore(emulated);

	if (play_tennis)
		test_condition(play_time, emulated, monitor, noise);

	if (create)
		test_create(repeat, join, posix);

	if (cancel)
		test_cancel(repeat, join);

	if (inter)
		test_inter();

	if (forking) {
		test_fork(TRUE);
		test_fork(FALSE);
	}

	if (overflow)
		test_overflow();

	if (signals)
		test_signals();

	if (barrier)
		test_barrier(repeat, emulated);

	if (dam)
		test_dam(repeat, emulated);

	if (memory) {
		switch (allocator) {
		case 'r':
			break;
		case 'e':
			emit("Using vmea_alloc() for memory tests");
			break;
		case 'h':
			emit("Using halloc() for memory tests");
			break;
		case 'v':
			emit("Using vmm_alloc() for memory tests");
			break;
		case 'w':
			emit("Using walloc() for memory tests");
			break;
		case 'x':
			emit("Using xmalloc() for memory tests");
			break;
		default:
			s_warning("unknown allocator '%c', using random mix", allocator);
			allocator = 'r';
			break;
		}
		if (allocator_bsize != 0)
			emit("Using blocks of %lu byte%s", (ulong) PLURAL(allocator_bsize));
		if (posix)
			emit("Adding (discovered) POSIX threads");
		if (percentage)
			emit("Randomly free %d%% blocks in remote threads", percentage);
		test_memory(repeat, posix, percentage);
	}

	if (teq)
		test_teq(repeat);

	if (evq)
		test_evq(repeat);

	/*
	 * Print final statistics.
	 */

	if (stats) {
		thread_dump_stats_log(log_agent_stdout_get(), 0);
		if (memory) {
			switch (allocator) {
			case 'r':
				halloc_dump_stats_log(log_agent_stdout_get(), 0);
				xmalloc_dump_stats_log(log_agent_stdout_get(), 0);
				vmm_dump_stats_log(log_agent_stdout_get(), 0);
				zalloc_dump_stats_log(log_agent_stdout_get(), 0);
				break;
			case 'h':
				halloc_dump_stats_log(log_agent_stdout_get(), 0);
				break;
			case 'v':
				vmm_dump_stats_log(log_agent_stdout_get(), 0);
				break;
			case 'w':
				zalloc_dump_stats_log(log_agent_stdout_get(), 0);
				break;
			case 'x':
				xmalloc_dump_stats_log(log_agent_stdout_get(), 0);
				break;
			}
		}
	}

	exit(EXIT_SUCCESS);	/* Required to cleanup semaphores if not destroyed */
}

/* vi: set ts=4 sw=4 cindent: */
