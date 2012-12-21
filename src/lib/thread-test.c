/*
 * thread-test -- thread unit tests.
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

#include "compat_sleep_ms.h"
#include "cq.h"
#include "log.h"
#include "misc.h"
#include "parse.h"
#include "path.h"
#include "str.h"
#include "thread.h"
#include "xmalloc.h"

const char *progname;

static bool sleep_before_exit;
static bool async_exit;

static void G_GNUC_NORETURN
usage(void)
{
	fprintf(stderr,
		"Usage: %s [-hjsAC] [-n count]"
		"  -h : prints this help message\n"
		"  -j : join created threads\n"
		"  -n : amount of times to repeat tests\n"
		"  -s : let each created thread sleep for 1 second before ending\n"
		"  -A : use asynchronous exit callbacks\n"
		"  -C : test thread creation\n"
		"Values given as decimal, hexadecimal (0x), octal (0) or binary (0b)\n"
		, progname);
	exit(EXIT_FAILURE);
}

static char *names[] = { "one", "two", "three", "four", "five" };

static void
exit_callback(void *result, void *arg)
{
	char *name = arg;
	ulong length = pointer_to_ulong(result);
	printf("thread \"%s\" finished, result length is %lu\n", name, length);
}

static void *
compute_length(void *arg)
{
	unsigned stid = thread_small_id();
	const char *name = arg;
	char *scratch = xstrdup(name);

	printf("thread #%u given \"%s\"\n", stid, scratch);
	xfree(scratch);
	if (sleep_before_exit)
		sleep(1);
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
				16384, exit_callback, names[i]);

		launched[i] = r;

		if (-1 == r) {
			if (errno != EAGAIN || !repeat)
				s_warning("cannot create thread #%u: %m", i);
		} else {
			int j;
			if (!repeat)
				printf("thread i=%u created as #%d\n", i, r);
			if (!join) {
				j = thread_join(r, NULL, FALSE);
				if (-1 != j) {
					s_warning("thread_join() worked for thread #%u?\n", r);
				} else if (errno != EINVAL) {
					s_warning("thread_join() failure on thread #%u: %m", r);
				} else {
					if (!repeat)
						printf("thread #%u cannot be joined, that's OK\n", r);
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
				int j = thread_join(r, &result, FALSE);		/* Block */
				if (-1 == j) {
					s_warning("thread_join() failed for thread #%u: %m", r);
				} else {
					ulong length = pointer_to_ulong(result);
					if (!repeat) {
						printf("thread #%u finished, result length is %lu\n",
							r, length);
					}
				}
			}
		}
	}

	if (async_exit)
		cq_dispatch();
}

static void
test_create(unsigned repeat, bool join)
{
	unsigned i;

	for (i = 0; i < repeat; i++) {
		test_create_one(repeat > 1, join);
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
	bool create = FALSE, join = FALSE;
	unsigned repeat = 1;

	mingw_early_init();
	progname = filepath_basename(argv[0]);
	thread_set_main(TRUE);		/* We're the main thread, we can block */

	misc_init();

	while ((c = getopt(argc, argv, "hjn:sAC")) != EOF) {
		switch (c) {
		case 'A':			/* use asynchronous exit callbacks */
			async_exit = TRUE;
			break;
		case 'C':			/* test thread creation */
			create = TRUE;
			break;
		case 'j':			/* join threads */
			join = TRUE;
			break;
		case 'n':			/* repeat tests */
			repeat = get_number(optarg, c);
			break;
		case 's':			/* threads sleep for 1 second before ending */
			sleep_before_exit = TRUE;
			break;
		case 'h':			/* show help */
		default:
			usage();
			break;
		}
	}

	if ((argc -= optind) != 0)
		usage();

	if (create)
		test_create(repeat, join);

	return 0;
}

