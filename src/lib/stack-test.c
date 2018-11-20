/*
 * stack-test -- tests the stack tracing functions.
 *
 * Copyright (c) 2018 Raphael Manfredi <Raphael_Manfredi@pobox.com>
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

#include "progname.h"
#include "stacktrace.h"
#include "str.h"

static void G_NORETURN
usage(void)
{
	fprintf(stderr,
			"Usage: %s [-h]\n"
			"  -h : prints this help message\n"
			, getprogname());
	exit(EXIT_FAILURE);
}

/*
 * Our own printf() for Windows which does not support "%zu" for instance.
 */
static void G_PRINTF(1, 2)
my_printf(const char *fmt, ...)
{
	va_list args;
	str_t *s = str_new(0);

	va_start(args, fmt);
	str_vprintf(s, fmt, args);
	va_end(args);

	puts(str_2c(s));
	str_destroy_null(&s);
}

static NO_INLINE void
test_caller(void)
{
	size_t i;

	for (i = 0; i < 3; i++) {
		const void *caller = stacktrace_caller(i);
		const char *name = stacktrace_caller_name(i);

		my_printf("%s(): caller[%zu]=%p (%s)",
			G_STRFUNC, i, caller, name);
	}
}

static NO_INLINE void
test_caller_fast(void)
{
	size_t i;

	for (i = 0; i < 3; i++) {
		const void *caller = stacktrace_caller(i);
		const void *fast = stacktrace_caller_fast(i);

		my_printf("%s(): caller[%zu]=%p (fast=%p) %s",
			G_STRFUNC, i, caller, fast,
			caller == fast ? "OK" : "DIFFERS");
	}

	for (i = 0; i < 3; i++) {
		const void *caller = stacktrace_caller_fast(i);
		const char *name = stacktrace_routine_name(caller, FALSE);

		my_printf("%s(): caller[%zu]=%p (%s)",
			G_STRFUNC, i, caller, name);
	}
}

static NO_INLINE void
test_routine_name(void)
{
	size_t i;

	for (i = 0; i < 3; i++) {
		const void *caller = stacktrace_caller(i);
		const char *name = stacktrace_routine_name(caller, FALSE);
		const char *name2 = stacktrace_caller_name(i);

		if (0 != strcmp(name, name2)) {
			s_warning("%s(): caller[%zu] differs (name=%s, name2=%s)",
				G_STRFUNC, i, name, name2);
		}

		my_printf("%s(): caller[%zu]=%p (%s)",
			G_STRFUNC, i, caller, name);
	}
}

static NO_INLINE void
test_basics(void)
{
	test_caller();
	test_caller_fast();
	test_routine_name();
	test_caller();			/* Witness effect of tail call optimization */
}

int
main(int argc, char **argv)
{
	extern int optind;
	extern char *optarg;
	int c;
	const char options[] = "h";

	progstart(argc, argv);
	stacktrace_init(argv[0], FALSE);

	while ((c = getopt(argc, argv, options)) != EOF) {
		switch (c) {
		case 'h':			/* show help */
			/* FALL THROUGH */
		default:
			usage();
			break;
		}
	}

	if (0 != (argc -= optind))
		usage();

	test_basics();

	return 0;
}

/* vi: set ts=4 sw=4 cindent: */
