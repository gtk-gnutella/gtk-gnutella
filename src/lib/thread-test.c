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
#include "atomic.h"
#include "barrier.h"
#include "compat_poll.h"
#include "compat_sleep_ms.h"
#include "cond.h"
#include "cq.h"
#include "dam.h"
#include "evq.h"
#include "getcpucount.h"
#include "halloc.h"
#include "log.h"
#include "misc.h"
#include "mutex.h"
#include "parse.h"
#include "path.h"
#include "random.h"
#include "rwlock.h"
#include "semaphore.h"
#include "shuffle.h"
#include "signal.h"
#include "spinlock.h"
#include "stacktrace.h"
#include "str.h"
#include "stringify.h"
#include "teq.h"
#include "thread.h"
#include "tm.h"
#include "tsig.h"
#include "waiter.h"
#include "walloc.h"
#include "xmalloc.h"

#define STACK_SIZE		16384

const char *progname;

static bool sleep_before_exit;
static bool async_exit, wait_threads;
static bool randomize_free;
static unsigned cond_timeout;
static long cpu_count;

static void *sleeping_thread(void *unused_arg);

static void G_GNUC_NORETURN
usage(void)
{
	fprintf(stderr,
		"Usage: %s [-hejsvwxABCDEFIKMNOPQRSVWX] [-c CPU] [-n count]\n"
		"       [-t ms] [-T secs]\n"
		"  -c : override amount of CPUs, driving thread count for mem tests\n"
		"  -e : use emulated semaphores\n"
		"  -h : prints this help message\n"
		"  -j : join created threads\n"
		"  -n : amount of times to repeat tests\n"
		"  -s : let each created thread sleep for 1 second before ending\n"
		"  -t : timeout value (ms) for condition waits\n"
		"  -v : dump thread statistics at the end of the tests\n"
		"  -w : wait for created threads\n"
		"  -x : free memory allocated by -X in random order\n"
		"  -A : use asynchronous exit callbacks\n"
		"  -B : test synchronization barriers\n"
		"  -C : test thread creation\n"
		"  -D : test synchronization dams\n"
		"  -E : test thread signals\n"
		"  -F : test thread fork\n"
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
		"  -V : test thread event queue (TEQ)\n"
		"  -W : test local event queue (EVQ)\n"
		"  -X : exercise concurrent memory allocation\n"
		"Values given as decimal, hexadecimal (0x), octal (0) or binary (0b)\n"
		, progname);
	exit(EXIT_FAILURE);
}

static char *names[] = { "one", "two", "three", "four", "five" };

static void
exit_callback(void *result, void *arg)
{
	char *name = arg;
	long length = pointer_to_long(result);
	printf("thread \"%s\" finished, result length is %ld\n", name, length);
	fflush(stdout);
}

static void *
compute_length(void *arg)
{
	unsigned stid = thread_small_id();
	const char *name = arg;
	char *scratch = xstrdup(name);

	printf("%s given \"%s\"\n", thread_id_name(stid), scratch);
	fflush(stdout);
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
	int launched[G_N_ELEMENTS(names)];

	for (i = 0; i < G_N_ELEMENTS(names); i++) {
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
				printf("thread i=%u created as %s\n", i, thread_id_name(r));
			if (!join) {
				j = thread_join(r, NULL);
				if (-1 != j) {
					s_warning("thread_join() worked for %s?\n",
						thread_id_name(r));
				} else if (errno != EINVAL) {
					s_warning("thread_join() failure on %s: %m",
						thread_id_name(r));
				} else {
					if (!repeat) {
						printf("%s cannot be joined, that's OK\n",
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
		printf("now joining the %u threads\n", (uint) G_N_ELEMENTS(launched));
		for (i = 0; i < G_N_ELEMENTS(launched); i++) {
			int r = launched[i];

			if (-1 == r) {
				if (!repeat)
					printf("skipping unlaunched thread i=%u\n", i);
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
						printf("%s finished, result length is %lu\n",
							thread_id_name(r), length);
					}
				}
			}
		}
	}

	if (async_exit)
		cq_dispatch();
}

static void
posix_thread_create(thread_main_t routine, void *arg)
{
	int error;
	pthread_attr_t attr;
	pthread_t t;

	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	pthread_attr_setstacksize(&attr, 32768);
	error = pthread_create(&t, &attr, routine, arg);
	pthread_attr_destroy(&attr);

	if (error != 0) {
		errno = error;
		s_error("cannot create POSIX thread: %m");
	}
}

static void *
posix_worker(void *unused_arg)
{
	unsigned stid = thread_small_id();
	char name[120];
	thread_info_t info;

	(void) unused_arg;

	thread_current_info(&info);
	thread_info_to_string_buf(&info, name, sizeof name);

	printf("POSIX thread worker starting...\n");
	printf("POSIX worker: %s\n", name);
	fflush(stdout);

	for (;;) {
		void *p;

		thread_current_info(&info);

		g_assert_log(thread_small_id() == stid,
			"current STID=%u, prev=%u %s", thread_small_id(), stid,
			thread_info_to_string_buf(&info, name, sizeof name));

		p = xmalloc(100);
		compat_sleep_ms(100);
		xfree(p);

		thread_current_info(&info);

		g_assert_log(thread_small_id() == stid,
			"current STID=%u, prev=%u %s", thread_small_id(), stid,
			thread_info_to_string_buf(&info, name, sizeof name));
	}

	return NULL;
}

static void *
posix_threads(void *unused_arg)
{
	unsigned i;

	(void) unused_arg;

	printf("POSIX thread launcher starting...\n");
	fflush(stdout);

	for (i = 0; i < 6; i++) {
		posix_thread_create(posix_worker, NULL);
	}

	printf("POSIX thread launch done, mutating to worker...\n");
	fflush(stdout);

	return posix_worker(NULL);
}

static void
test_create(unsigned repeat, bool join, bool posix)
{
	unsigned i;

	if (posix) {
		posix_thread_create(posix_threads, NULL);
	}

	for (i = 0; i < repeat; i++) {
		test_create_one(repeat > 1, join);
	}
}

static void
test_cancel_one(bool repeat, bool join)
{
	unsigned i;
	int launched[G_N_ELEMENTS(names)];

	for (i = 0; i < G_N_ELEMENTS(names); i++) {
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
				printf("thread i=%u created as %s\n", i, thread_id_name(r));
			if (-1 == thread_cancel(r))
				s_warning("thread_cancel(%u) failed: %m", r);
			if (!join) {
				j = thread_join(r, NULL);
				if (-1 != j) {
					s_warning("thread_join() worked for %s?\n",
						thread_id_name(r));
				} else if (errno != EINVAL) {
					s_warning("thread_join() failure on %s: %m",
						thread_id_name(r));
				} else {
					if (!repeat) {
						printf("%s cannot be joined, that's OK\n",
							thread_id_name(r));
					}
				}
			}
		}
	}

	if (!repeat && !join)
		compat_sleep_ms(200);		/* Let all the threads run */

	if (join) {
		printf("now joining the %u threads\n", (uint) G_N_ELEMENTS(launched));
		for (i = 0; i < G_N_ELEMENTS(launched); i++) {
			int r = launched[i];

			if (-1 == r) {
				if (!repeat)
					printf("skipping unlaunched thread i=%u\n", i);
			} else {
				void *result;
				int j = thread_join(r, &result);		/* Block */
				if (-1 == j) {
					s_warning("thread_join() failed for %s: %m",
						thread_id_name(r));
				} else {
					long length = pointer_to_long(result);
					if (!repeat) {
						printf("%s finished, result length is %ld\n",
							thread_id_name(r), length);
					}
				}
			}
		}
	}

	if (async_exit)
		cq_dispatch();

	i = thread_create(sleeping_thread, NULL, 0, STACK_SIZE);
	if (-1U == i)
		s_error("cannot create sleeping thread: %m");
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

	for (i = 0; i < repeat; i++) {
		test_cancel_one(repeat > 1, join);
	}
}

static void *
test_inter_main(void *arg)
{
	waiter_t *w = waiter_refcnt_inc(arg);

	sleep(1);
	printf("signaling main thread\n");
	fflush(stdout);
	waiter_signal(w);
	
	compat_sleep_ms(5);
	waiter_refcnt_dec(arg);
	return NULL;
}

static void
test_inter(void)
{
	int r;
	waiter_t *mw, *w;
	bool refed;

	mw = waiter_make(NULL);
	w = waiter_spawn(mw, int_to_pointer(31416));
	
	r = thread_create(test_inter_main, w, THREAD_F_DETACH, 0);
	if (-1 == r)
		s_error("could not launch thread: %m");

	printf("main thread waiting\n");
	fflush(stdout);
	if (!waiter_suspend(mw))
		s_error("could not suspend itself");
	printf("main thread awoken\n");

	refed = waiter_refcnt_dec(w);
	printf("child waiter %s referenced\n", refed ? "still" : "no longer");
	while (waiter_child_count(mw) != 1) {
		printf("waiting for all children in waiter to go\n");
		fflush(stdout);
		compat_sleep_ms(5);
	}
	refed = waiter_refcnt_dec(mw);
	printf("master waiter %s referenced\n", refed ? "still" : "no longer");
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
		printf("thread #%d alive, waiting for event\n", n);
		fflush(stdout);
		if (semaphore_acquire(s, 1, NULL)) {
			printf("#%d got semaphore!\n", n);
			fflush(stdout);
		} else {
			s_warning("thread #%d cannot get semaphore: %m", n);
			got = FALSE;
		}
		sleep(1);
		if (got) {
			printf("#%d releasing semaphore!\n", n);
			fflush(stdout);
			semaphore_release(s, 1);
		}
	}

	printf("thread #%d exiting!\n", n);
	return NULL;
}

static int
test_semaphore_thread_launch(int n, semaphore_t *s)
{
	struct test_semaphore_arg *arg;
	int r;

	XMALLOC(arg);
	arg->n = n;
	arg->s = s;
	r = thread_create(test_semaphore_main, arg, 0, 0);
	if (-1 == r)
		s_error("could not launch thread #%d: %m", n);

	return r;
}

static void
test_semaphore(bool emulated)
{
	semaphore_t *s;
	tm_t timeout;
	int i;
	int r[3];

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
	printf("will wait 1/2 second...\n");
	if (semaphore_acquire(s, 1, &timeout))
		s_error("could acquire empty semaphore!");
	g_assert_log(EAGAIN == errno,
		"improper errno, expected EAGAIN (%d) but got %m", EAGAIN);
	printf("good, failed to acquire empty semaphore.\n");

	r[0] = test_semaphore_thread_launch(1, s);
	r[1] = test_semaphore_thread_launch(2, s);
	r[2] = test_semaphore_thread_launch(3, s);

	semaphore_release(s, 1);

	for (i = 0; i < 6; i++) {
		printf("main alive\n");
		fflush(stdout);
		sleep(1);
	}

	printf("main waiting for subthreads\n");
	fflush(stdout);

	for (i = 0; UNSIGNED(i) < G_N_ELEMENTS(r); i++) {
		if (-1 == thread_join(r[i], NULL))
			s_error("failed to join with %s: %m", thread_id_name(r[i]));
	}

	printf("main is done, final semaphore value is %d\n", semaphore_value(s));

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
create_player(thread_main_t start, int n)
{
	g_assert(n >= 0 && n < (int) G_N_ELEMENTS(name));

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
		printf("%s plays\n", me);
		fflush(stdout);

		game_state = other_player;
		cond_signal(&game_state_change, &game_state_lock);

		/* Wait until it's my turn to play again */

		do {
			if (cond_timeout != 0) {
				bool success = cond_timed_wait_clean(
					&game_state_change, &game_state_lock, &timeout);

				if (!success) {
					stats->timeout++;
					printf("** TIMEOUT ** %s wakeup\n", me);
					fflush(stdout);
					continue;
				}
			} else {
				cond_wait_clean(&game_state_change, &game_state_lock);
			}

			if (other_player == game_state) {
				stats->spurious++;
				printf("** SPURIOUS ** %s wakeup\n", me);
				fflush(stdout);
			}
		} while (other_player == game_state);
	}

	game_state++;
	printf("%s leaving\n", me);
	fflush(stdout);

	cond_broadcast(&game_state_change, &game_state_lock);
	mutex_unlock(&game_state_lock);

	return NULL;
}

static void
player_stats(int n)
{
	struct game_stats *stats;

	g_assert(n >= 0 && n < (int) G_N_ELEMENTS(game_stats));

	stats = &game_stats[n];

	printf("%s played %d times (%d spurious event%s, %d timeout%s)\n",
		name[n], stats->play, stats->spurious, plural(stats->spurious),
		stats->timeout, plural(stats->timeout));
}

static void
test_condition(unsigned play_time, bool emulated, bool monitor, bool noise)
{
	int i;
	game_state = START_GAME;
	waiter_t *w;
	uint notifications = 0;

	g_assert(0 == cond_waiting_count(&game_state_change));

	if (emulated)
		cond_init_full(&game_state_change, &game_state_lock, emulated);

	g_assert(0 == cond_waiting_count(&game_state_change));
	g_assert(0 == cond_pending_count(&game_state_change));
	g_assert(0 == cond_signal_count(&game_state_change));

	for (i = 0; i < (int) G_N_ELEMENTS(name); i++) {
		create_player(player, i);
	}

	if (monitor) {
		struct pollfd wfd[1];
		tm_t end, play;

		tm_now_exact(&end);
		tm_fill_ms(&play, play_time * 1000);
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

			ret = compat_poll(wfd, G_N_ELEMENTS(wfd), 1000);
			if (ret < 0) {
				s_warning("poll() failed: %m");
			} else {
				printf("[match still on]\n");
				fflush(stdout);
				notifications++;
				waiter_ack(w);
			}
		}

		cond_waiter_remove(&game_state_change, w);
		g_assert(1 == waiter_refcnt(w));
		waiter_refcnt_dec(w);
	} else {
		sleep(play_time);	/* Let them play */
	}

	if (noise) {
		printf("** Noise ON **\n");
		for (i = 0; i < 100000; i++) {
			mutex_lock(&game_state_lock);
			cond_broadcast(&game_state_change, &game_state_lock);
			mutex_unlock(&game_state_lock);
		}
		printf("** Noise OFF **\n");
	}

	mutex_lock(&game_state_lock);
	game_state = GAME_OVER;

	printf("Stopping the game...\n");
	fflush(stdout);

	cond_broadcast(&game_state_change, &game_state_lock);

	do {
		cond_wait_clean(&game_state_change, &game_state_lock);
	} while (game_state < BOTH_PLAYER_GONE);

	g_assert(0 == cond_waiting_count(&game_state_change));

	printf("Game over!\n");

	mutex_unlock(&game_state_lock);
	mutex_destroy(&game_state_lock);
	if (!cond_reset(&game_state_change))
		s_warning("cannot reset condition?");
	cond_destroy(&game_state_change);

	/* Must work also after destruction */

	g_assert(0 == cond_waiting_count(&game_state_change));
	g_assert(0 == cond_pending_count(&game_state_change));

	for (i = 0; i < (int) G_N_ELEMENTS(name); i++) {
		player_stats(i);
	}
	if (monitor) {
		printf("main got %u notification%s\n",
			notifications, plural(notifications));
	}
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

	printf("%s locking...\n", thread_name());
	fflush(stdout);

	spinlock(&locks[n]);
	mutex_lock(&mutexes[n]);
	rwlock_rlock(&rlocks[n]);
	rwlock_wlock(&wlocks[n]);

	printf("%s locked, sleeping for 5 secs\n", thread_name());
	fflush(stdout);

	sleep(5);

	printf("%s unlocking\n", thread_name());
	fflush(stdout);

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

	printf("%s() waiting 1 sec\n", G_STRFUNC);
	fflush(stdout);
	sleep(1);

	running = thread_count();
	printf("%s() forking with %u running thread%s, STID=%u\n", G_STRFUNC,
		running, plural(running), thread_small_id());
	fflush(stdout);

	thread_lock_dump_all(STDOUT_FILENO);

	switch ((pid = thread_fork(safe))) {
	case -1:
		s_error("%s() cannot fork(): %m", G_STRFUNC);
	case 0:
		printf("%s() child process started as STID=%u\n",
			G_STRFUNC, thread_small_id());
		printf("%s() child has %u thread\n", G_STRFUNC, thread_count());
		fflush(stdout);
		thread_lock_dump_all(STDOUT_FILENO);
		exit(EXIT_SUCCESS);
	default:
		printf("%s() child forked, waiting...\n", G_STRFUNC);
		fflush(stdout);
#ifdef HAS_WAITPID
		{
			pid_t w = waitpid(pid, NULL, 0);
			if (-1 == w)
				s_error("%s() cannot wait(): %m", G_STRFUNC);
		}
#endif
		printf("%s() child terminated, exiting thread\n", G_STRFUNC);
		fflush(stdout);
	}

	return NULL;
}

static void
test_fork(bool safe)
{
	int l1, l2, fk, r;
	unsigned running;

	printf("--- testing thread_fork(%s)\n", safe ? "TRUE" : "FALSE");

	running = thread_count();
	printf("starting with %u running thread%s\n",
		running, plural(running));

	l1 = thread_create(fork_locker, int_to_pointer(0), 0, 8192);
	l2 = thread_create(fork_locker, int_to_pointer(1), 0, 8192);
	fk = thread_create(fork_forker, int_to_pointer(safe), 0, 8192);

	if (-1 == l1 || -1 == l2 || -1 == fk)
		s_error("%s() could not create threads", G_STRFUNC);

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
	printf("ending with %u running thread%s\n",
		running, plural(running));

	printf("--- test of thread_fork(%s) done!\n", safe ? "TRUE" : "FALSE");
}

static int
overflow_routine(void *arg)
{
	int x = pointer_to_int(arg);
	int c[128];

	ZERO(c);
	c[0] = x;
	c[1] = overflow_routine(&c[1]);

	if (NULL == arg)
		return c[0] + c[1];

	return overflow_routine(c) + c[1];
}

static void *
overflow_thread(void *arg)
{
	return int_to_pointer(overflow_routine(arg));
}

static void
test_overflow(void)
{
	int t, r;

	t = thread_create(overflow_thread, int_to_pointer(0), 0, 8192);
	if (-1 == t)
		s_error("%s() could not create thread", G_STRFUNC);
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

	printf("%s() starting...\n", G_STRFUNC);

	arg.r = r = aq_make_full(emulated);		/* requests */
	arg.a = a = aq_make_full(emulated);		/* answers */

	t = thread_create(aqt_processor, &arg, 0, 0);
	if (-1 == t)
		s_error("cannot create processor thread: %m");

	for (i = 0; i < G_N_ELEMENTS(names); i++) {
		ulong res;

		printf("computing length of \"%s\"\n", names[i]);
		fflush(stdout);

		aq_put(r, names[i]);
		res = pointer_to_ulong(aq_remove(a));

		printf("\t=> %lu bytes\n", res);
		fflush(stdout);
	}

	printf("sending EOF\n");
	fflush(stdout);

	aq_put(r, NULL);		/* Signals end to thread */
	if (-1 == thread_join(t, NULL))
		s_error("cannot join with processor thread: %m");

	aq_refcnt_dec(a);
	aq_refcnt_dec(r);

	printf("%s() all done.\n", G_STRFUNC);
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
test_rwlock(void)
{
	int t[9];
	rwlock_t rw = RWLOCK_INIT;
	unsigned i;

	s_info("%s starting, will be launching %s()", thread_name(),
		stacktrace_function_name(test_rwthreads));

	/* The mono-threaded "cannot fail" sequence */

	printf("%s(): mono-threaded tests...\n", G_STRFUNC);
	fflush(stdout);

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

	printf("%s(): mono-threaded tests succeded.\n", G_STRFUNC);
	fflush(stdout);

	/* Now for multi-threaded tests.... */

	printf("%s(): multi-threaded tests...\n", G_STRFUNC);
	fflush(stdout);

	for (i = 0; i < G_N_ELEMENTS(t); i++) {
		t[i] = thread_create(test_rwthreads, NULL, 0, 0);
		if (-1 == t[i])
			s_error("%s() cannot create thread %u: %m", G_STRFUNC, i);
	}

	for (i = 0; i < G_N_ELEMENTS(t); i++) {
		thread_join(t[i], NULL);
	}

	printf("%s(): multi-threaded tests done.\n", G_STRFUNC);
	fflush(stdout);
}

static bool test_signals_done;
static int test_signals_count;

#define TEST_SIGNALS_COUNT	3

static void
test_sighandler(int sig)
{
	printf("%s received signal #%d\n", thread_name(), sig);
	fflush(stdout);
}

static void
test_sigdone(int sig)
{
	printf("%s got signal #%d, will exit\n", thread_name(), sig);
	fflush(stdout);

	test_signals_done = TRUE;
}

static void
test_sigcount(int sig)
{
	printf("%s got signal #%d (count = %u)\n", thread_name(), sig,
		++test_signals_count);
	fflush(stdout);
}

static void
test_printsig(int sig)
{
	printf("%s got signal #%d\n", thread_name(), sig);
	fflush(stdout);
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
			printf("%s() will now get signal #4\n", G_STRFUNC);
			fflush(stdout);
			thread_sigmask(TSIG_SETMASK, &oset, NULL);
		}
	}

	printf("%s() exiting\n", G_STRFUNC);
	fflush(stdout);

	return NULL;
}

static void *
sleeping_thread(void *arg)
{
	barrier_t *b = arg;
	tm_t start, end;

	thread_signal(TSIG_1, test_sigcount);
	tm_now_exact(&start);
	thread_sleep_ms(2000);
	tm_now_exact(&end);

	printf("%s() slept %u ms (expected 2000 ms)\n", G_STRFUNC,
		(uint) tm_elapsed_ms(&end, &start));
	fflush(stdout);

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
			printf("%s() suspended %u ms before getting signal\n", G_STRFUNC,
				(uint) tm_elapsed_ms(&end, &start));
			fflush(stdout);
		} else {
			g_assert_not_reached();
		}

		tm_fill_ms(&timeout, 1000);
		tm_now_exact(&start);
		if (thread_timed_sigsuspend(&oset, &timeout)) {
			g_assert_not_reached();
		} else {
			tm_now_exact(&end);
			printf("%s() suspended %u ms without getting signals\n", G_STRFUNC,
				(uint) tm_elapsed_ms(&end, &start));
			fflush(stdout);
		}

		tm_fill_ms(&timeout, 2000);

		barrier_wait(b);
		tm_now_exact(&start);
		if (thread_timed_sigsuspend(&oset, &timeout)) {
			tm_now_exact(&end);
			printf("%s() suspended %u ms (about 1 sec) before getting signal\n",
				G_STRFUNC, (uint) tm_elapsed_ms(&end, &start));
			fflush(stdout);
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

	if (-1 != thread_kill(12, TSIG_0))		/* 12 is random constant */
		s_error("thread #12 already exists?");

	r = thread_create(signalled_thread, NULL, 0, 0);
	for (i = 0; i < 10; i++) {
		sleep(1);
		if (-1 == thread_kill(r, TSIG_0))
			s_error("thread #%d cannot be signalled: %m", r);
		if (-1 == thread_kill(r, TSIG_4))
			s_error("thread #%d cannot be signalled: %m", r);
		if (-1 == thread_kill(r, (i & 0x1) ? TSIG_2 : TSIG_1))
			s_error("thread #%d cannot be signalled: %m", r);
	}

	printf("%s() emitting each signal 100 times\n", G_STRFUNC);
	fflush(stdout);

	for (i = 0; i < 100; i++) {
		thread_kill(r, TSIG_1);
		thread_kill(r, TSIG_2);
		thread_kill(r, TSIG_4);
	}

	thread_kill(r, TSIG_3);
	thread_join(r, NULL);

	printf("%s() now checking thread_sleep_ms()\n", G_STRFUNC);
	fflush(stdout);

	b = barrier_new(2);
	r = thread_create(sleeping_thread, barrier_refcnt_inc(b), 0, 0);
	thread_sleep_ms(500);		/* Give it time to setup */
	for (i = 0; i < TEST_SIGNALS_COUNT; i++) {
		if (-1 == thread_kill(r, TSIG_1))
			s_error("thread #%d cannot be signalled: %m", r);
		thread_sleep_ms(500);	/* Give it time to process signal */
	}

	printf("%s() now checking thread_timed_sigsuspend()\n", G_STRFUNC);
	fflush(stdout);

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

	printf("%s(%d) started as %s\n", G_STRFUNC, n, thread_name());
	fflush(stdout);

	thread_signal(TSIG_1, test_sighandler);
	WFREE(ca);
	barrier_wait(cb);

	printf("%s(%d) incrementing counter=%d\n", G_STRFUNC, n,
		atomic_int_get(&counter));
	fflush(stdout);
	atomic_int_inc(&counter);

	barrier_wait(cb);

	printf("%s(%d) reincrementing counter=%d\n", G_STRFUNC, n,
		atomic_int_get(&counter));
	fflush(stdout);
	atomic_int_inc(&counter);

	barrier_wait(cb);
	barrier_free_null(&cb);

	printf("%s(%d) exiting\n", G_STRFUNC, n);
	fflush(stdout);

	return NULL;
}

static void
test_barrier_one(bool emulated)
{
	int t[2], i, n;
	barrier_t *cb;

	n = (int) G_N_ELEMENTS(t);
	cb = barrier_new_full(n + 1, emulated);
	counter = 0;

	for (i = 0; i < n; i++) {
		struct computer_arg *ca;
		WALLOC(ca);
		ca->n = i;
		ca->b = cb;
		t[i] = thread_create(computer_thread, ca, THREAD_F_DETACH, 0);
		if (-1 == t[i])
			s_error("cannot create processor thread %u: %m", i);
	}

	sleep(1);					/* Wait until threads have started */
	g_assert(0 == counter);		/* Nobody can change that before the barrier */

	barrier_wait(cb);
	printf("%s() reached barrier the first time: threads started\n", G_STRFUNC);
	fflush(stdout);

	barrier_master_wait(cb);
	printf("%s() reached barrier the second time as master\n", G_STRFUNC);
	fflush(stdout);

	for (i = 0; i < n; i++) {
		if (-1 == thread_kill(t[i], TSIG_1))
			s_error("cannot signal processor thread %u: %m", i);
	}

	g_assert(n == counter);		/* We're the master thread */
	sleep(1);					/* and we're the only thread running */
	atomic_int_inc(&counter);
	g_assert(n + 1 == counter);	/* We're the master thread */

	printf("%s() releasing threads, counter=%d\n", G_STRFUNC, counter);
	fflush(stdout);
	barrier_release(cb);

	barrier_wait(cb);
	barrier_free_null(&cb);
	printf("%s() computation done, counter=%d (expected is %d)\n",
		G_STRFUNC, counter, 2 * n  + 1);
	g_assert(2 * n + 1 == counter);
}

static void
test_barrier(unsigned repeat, bool emulated)
{
	unsigned i;

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

	printf("%s(%d) started as %s\n", G_STRFUNC, n, thread_name());

	dam_wait(d);

	printf("%s(%d) incrementing counter=%d\n", G_STRFUNC, n,
		atomic_int_get(&dam_counter));
	fflush(stdout);
	atomic_int_inc(&dam_counter);

	dam_wait(d);

	printf("%s(%d) reincrementing counter=%d\n", G_STRFUNC, n,
		atomic_int_get(&dam_counter));
	fflush(stdout);
	atomic_int_inc(&dam_counter);

	dam_wait(d);		/* Dam disabled, will not wait */
	printf("%s(%d) last incrementing counter=%d\n", G_STRFUNC, n,
		atomic_int_get(&dam_counter));
	fflush(stdout);
	atomic_int_inc(&dam_counter);
	dam_free_null(&d);

	printf("%s(%d) waiting, counter=%d\n", G_STRFUNC, n,
		atomic_int_get(&dam_counter));
	fflush(stdout);

	barrier_wait(b);
	barrier_free_null(&b);

	printf("%s(%d) exiting\n", G_STRFUNC, n);
	fflush(stdout);

	return NULL;
}

static void
test_dam_one(bool emulated)
{
	int t[2], i, n;
	dam_t *d;
	barrier_t *b;
	uint key;

	n = (int) G_N_ELEMENTS(t);
	d = dam_new_full(&key, emulated);
	b = barrier_new_full(n + 1, emulated);
	atomic_int_set(&dam_counter, 0);

	for (i = 0; i < n; i++) {
		struct dam_arg *da;
		WALLOC(da);
		da->n = i;
		da->d = dam_refcnt_inc(d);
		da->b = barrier_refcnt_inc(b);
		t[i] = thread_create(dam_thread, da, THREAD_F_DETACH, 0);
		if (-1 == t[i])
			s_error("cannot create dam thread %u: %m", i);
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

	for (i = 0; i < repeat; i++) {
		test_dam_one(emulated);
	}
}

enum memory_alloc {
	MEMORY_XMALLOC = 0,
	MEMORY_HALLOC = 1,
	MEMORY_WALLOC = 2,
	MEMORY_VMM = 3,
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

static void *
exercise_memory(void *arg)
{
	struct memory *mem;
	int i;

	(void) arg;

	XMALLOC_ARRAY(mem, MEMORY_ALLOCATIONS);

	for (i = 0; i < MEMORY_ALLOCATIONS; i++) {
		struct memory *m = &mem[i];

		if (random_value(99) < MEMORY_VMM_PROPORTION) {
			m->type = MEMORY_VMM;
			m->size = MEMORY_VMM_MIN +
				random_value(MEMORY_VMM_MAX - MEMORY_VMM_MIN);
		} else {
			m->type = random_value(2);
			m->size = MEMORY_MIN + random_value(MEMORY_MAX - MEMORY_MIN);
		}
	}

	for (i = 0; i < MEMORY_ALLOCATIONS; i++) {
		struct memory *m = &mem[i];

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
		default:
			g_assert_not_reached();
		}
	}

	if (randomize_free)
		shuffle(mem, MEMORY_ALLOCATIONS, sizeof mem[0]);

	for (i = 0; i < MEMORY_ALLOCATIONS; i++) {
		struct memory *m = &mem[i];

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
		default:
			g_assert_not_reached();
		}
	}

	XFREE_NULL(mem);

	return NULL;
}

static void
test_memory_one(void)
{
	long cpus = 0 == cpu_count ? getcpucount() : cpu_count;
	int *t, i, n;

	n = cpus + 1;

	WALLOC_ARRAY(t, n);

	for (i = 0; i < n; i++) {
		int r = thread_create(exercise_memory, NULL, 0, THREAD_STACK_MIN);
		if (-1 == r)
			s_error("cannot create thread: %m");
		t[i] = r;
	}

	for (i = 0; i < n; i++) {
		thread_join(t[i], NULL);
	}

	WFREE_ARRAY(t, n);
}

static void
test_memory(unsigned repeat)
{
	long cpus = 0 == cpu_count ? getcpucount() : cpu_count;
	unsigned i;

	printf("%s() detected %ld CPU%s%s\n", G_STRFUNC, cpus, plural(cpus),
		0 == cpu_count ? "" : " (forced by -c)");

	if (randomize_free)
		printf("%s() will free blocks in random order\n", G_STRFUNC);

	fflush(stdout);

	for (i = 0; i < repeat; i++) {
		tm_t start, end, elapsed;

		tm_now_exact(&start);
		test_memory_one();
		tm_now_exact(&end);

		tm_elapsed(&elapsed, &end, &start);

		printf("%s() #%d finished! (%f secs)\n", G_STRFUNC, i, tm2f(&elapsed));
		fflush(stdout);
	}

	printf("%s() done!\n", G_STRFUNC);
	fflush(stdout);
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
	while (repeat--) {
		int s, r;
		barrier_t *b;
		struct teq_sender_arg arg;

		teq_recv_cnt = teq_callout_cnt = 0;
		atomic_int_set(&teq_sent_cnt, 0);

		b = barrier_new(2);
		r = thread_create(teq_receiver, barrier_refcnt_inc(b),
			0, THREAD_STACK_MIN);
		arg.receiver = r;
		arg.b = b;
		s = thread_create(teq_sender, &arg, 0, THREAD_STACK_MIN);

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
	while (repeat--) {
		int s, r;

		r = thread_create(evq_one, NULL, 0, THREAD_STACK_MIN);
		s = thread_create(evq_two, NULL, 0, THREAD_STACK_MIN);

		thread_join(r, NULL);
		thread_join(s, NULL);
	}
}

static unsigned
get_number(const char *arg, int opt)
{
	int error;
	uint32 val;
	
	val = parse_v32(arg, NULL, &error);
	if (0 == val && error != 0) {
		fprintf(stderr, "%s: invalid -%c argument \"%s\": %s\n",
			progname, opt, arg, g_strerror(error));
		exit(EXIT_FAILURE);
	}

	return val;
}

int
main(int argc, char **argv)
{
	extern int optind;
	extern char *optarg;
	int c;
	bool create = FALSE, join = FALSE, sem = FALSE, emulated = FALSE;
	bool play_tennis = FALSE, monitor = FALSE, noise = FALSE, posix = FALSE;
	bool inter = FALSE, forking = FALSE, aqueue = FALSE, rwlock = FALSE;
	bool signals = FALSE, barrier = FALSE, overflow = FALSE, memory = FALSE;
	bool stats = FALSE, teq = FALSE, cancel = FALSE, dam = FALSE, evq = FALSE;
	unsigned repeat = 1, play_time = 0;
	const char options[] = "c:ehjn:st:vwxABCDEFIKMNOPQRST:VWX";

	mingw_early_init();
	progname = filepath_basename(argv[0]);
	thread_set_main(TRUE);		/* We're the main thread, we can block */
	stacktrace_init(argv[0], FALSE);

	misc_init();

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
		case 'V':			/* test thread event queue */
			teq = TRUE;
			break;
		case 'W':			/* test event queue */
			evq = TRUE;
			break;
		case 'X':			/* exercise memory allocation */
			memory = TRUE;
			break;
		case 'c':			/* override CPU count */
			cpu_count = get_number(optarg, c);
			break;
		case 'e':			/* use emulated semaphores */
			emulated = TRUE;
			break;
		case 'j':			/* join threads */
			join = TRUE;
			break;
		case 'n':			/* repeat tests */
			repeat = get_number(optarg, c);
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

	g_assert(0 == thread_by_name("main"));

	if (aqueue)
		test_aqueue(emulated);

	if (rwlock)
		test_rwlock();

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

	if (memory)
		test_memory(repeat);

	if (teq)
		test_teq(repeat);

	if (evq)
		test_evq(repeat);

	/*
	 * Print final statistics.
	 */

	if (stats)
		thread_dump_stats_log(log_agent_stdout_get(), 0);

	exit(EXIT_SUCCESS);	/* Required to cleanup semaphores if not destroyed */
}

