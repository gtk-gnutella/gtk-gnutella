/*
 * sort-test -- sort tests and benchmarking.
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

#include "lib/random.h"
#include "lib/smsort.h"
#include "lib/str.h"
#include "lib/tm.h"
#include "lib/xmalloc.h"
#include "lib/xsort.h"

#define TEST_LOOP	100

#define ALIGN_MASK 	(MEM_ALIGNBYTES - 1)
#define align_round(x)	(((x) + ALIGN_MASK) & ~ALIGN_MASK)

extern G_GNUC_PRINTF(1, 2) void oops(char *fmt, ...);

char *progname;
size_t item_size;

static void G_GNUC_NORETURN
usage(void)
{
	fprintf(stderr,
		"Usage: %s [-ht]\n"
		"  -h : prints this help message\n"
		"  -t : time each test\n"
		, progname);
	exit(EXIT_FAILURE);
}

typedef int (*cmp_routine)(const void *a, const void *b);

static int
long_cmp(const void *a, const void *b)
{
	const long *la = a, *lb = b;

	return CMP(la, lb);
}

static int
generic_cmp(const void *a, const void *b)
{
	return memcmp(a, b, item_size);	/* Global variable */
}

static cmp_routine
get_cmp_routine(size_t isize)
{
	switch (isize) {
	case LONGSIZE:
		return long_cmp;
	default:
		item_size = isize;	/* Global variable */
		return generic_cmp;
	}
}

struct plain {
	char val[LONGSIZE];
};

struct plain_1 {
	char val[LONGSIZE];
	char buf[INTSIZE];
};

struct plain_2 {
	char val[LONGSIZE];
	char buf[INTSIZE * 2];
};

struct plain_3 {
	char val[LONGSIZE];
	char buf[INTSIZE * 3];
};

struct plain_4 {
	char val[LONGSIZE];
	char buf[INTSIZE * 4];
};

static bool
plain_less(void *m, size_t i, size_t j)
{
	struct plain *x = m;
	struct plain *a = &x[i];
	struct plain *b = &x[j];
	int c;

	c = memcmp(&a->val, &b->val, sizeof a->val);
	return c < 0;
}

static bool
plain_1_less(void *m, size_t i, size_t j)
{
	struct plain_1 *x = m;
	struct plain_1 *a = &x[i];
	struct plain_1 *b = &x[j];
	int c;

	c = memcmp(&a->val, &b->val, sizeof a->val);
	if (0 == c)
		return memcmp(&a->buf, &b->buf, sizeof a->buf) < 0;
	return c < 0;
}

static bool
plain_2_less(void *m, size_t i, size_t j)
{
	struct plain_2 *x = m;
	struct plain_2 *a = &x[i];
	struct plain_2 *b = &x[j];
	int c;

	c = memcmp(&a->val, &b->val, sizeof a->val);
	if (0 == c)
		return memcmp(&a->buf, &b->buf, sizeof a->buf) < 0;
	return c < 0;
}

static bool
plain_3_less(void *m, size_t i, size_t j)
{
	struct plain_3 *x = m;
	struct plain_3 *a = &x[i];
	struct plain_3 *b = &x[j];
	int c;

	c = memcmp(&a->val, &b->val, sizeof a->val);
	if (0 == c)
		return memcmp(&a->buf, &b->buf, sizeof a->buf) < 0;
	return c < 0;
}

static bool
plain_4_less(void *m, size_t i, size_t j)
{
	struct plain_4 *x = m;
	struct plain_4 *a = &x[i];
	struct plain_4 *b = &x[j];
	int c;

	c = memcmp(&a->val, &b->val, sizeof a->val);
	if (0 == c)
		return memcmp(&a->buf, &b->buf, sizeof a->buf) < 0;
	return c < 0;
}

static smsort_less_t
get_less_routine(size_t isize)
{
	if (sizeof(struct plain) == isize)
		return plain_less;
	else if (sizeof(struct plain_1) == isize)
		return plain_1_less;
	else if (sizeof(struct plain_2) == isize)
		return plain_2_less;
	else if (sizeof(struct plain_3) == isize)
		return plain_3_less;
	else if (sizeof(struct plain_4) == isize)
		return plain_4_less;
	else
		g_assert_not_reached();
}

static void
plain_swap(void *m, size_t i, size_t j)
{
	struct plain *x = m;
	struct plain tmp;

	tmp = x[j];
	x[j] = x[i];
	x[i] = tmp;
}

static void
plain_1_swap(void *m, size_t i, size_t j)
{
	struct plain_1 *x = m;
	struct plain_1 tmp;

	tmp = x[j];
	x[j] = x[i];
	x[i] = tmp;
}

static void
plain_2_swap(void *m, size_t i, size_t j)
{
	struct plain_2 *x = m;
	struct plain_2 tmp;

	tmp = x[j];
	x[j] = x[i];
	x[i] = tmp;
}

static void
plain_3_swap(void *m, size_t i, size_t j)
{
	struct plain_3 *x = m;
	struct plain_3 tmp;

	tmp = x[j];
	x[j] = x[i];
	x[i] = tmp;
}

static void
plain_4_swap(void *m, size_t i, size_t j)
{
	struct plain_4 *x = m;
	struct plain_4 tmp;

	tmp = x[j];
	x[j] = x[i];
	x[i] = tmp;
}

static smsort_swap_t
get_swap_routine(size_t isize)
{
	if (sizeof(struct plain) == isize)
		return plain_swap;
	else if (sizeof(struct plain_1) == isize)
		return plain_1_swap;
	else if (sizeof(struct plain_2) == isize)
		return plain_2_swap;
	else if (sizeof(struct plain_3) == isize)
		return plain_3_swap;
	else if (sizeof(struct plain_4) == isize)
		return plain_4_swap;
	else
		g_assert_not_reached();
}

static void
xsort_test(void *array, void *copy, size_t cnt, size_t isize)
{
	cmp_routine cmp = get_cmp_routine(isize);
	size_t len = cnt * isize;
	size_t i;

	for (i = 0; i < TEST_LOOP; i++) {
		memcpy(copy, array, len);
		xsort(copy, cnt, isize, cmp);
	}
}

static void
qsort_test(void *array, void *copy, size_t cnt, size_t isize)
{
	cmp_routine cmp = get_cmp_routine(isize);
	size_t len = cnt * isize;
	size_t i;

	for (i = 0; i < TEST_LOOP; i++) {
		memcpy(copy, array, len);
		qsort(copy, cnt, isize, cmp);
	}
}

static void
smsort_test(void *array, void *copy, size_t cnt, size_t isize)
{
	cmp_routine cmp = get_cmp_routine(isize);
	size_t len = cnt * isize;
	size_t i;

	for (i = 0; i < TEST_LOOP; i++) {
		memcpy(copy, array, len);
		smsort(copy, cnt, isize, cmp);
	}
}

static void
smsort2_test(void *array, void *copy, size_t cnt, size_t isize)
{
	smsort_less_t less = get_less_routine(isize);
	smsort_swap_t swap = get_swap_routine(isize);
	size_t len = cnt * isize;
	size_t i;

	for (i = 0; i < TEST_LOOP; i++) {
		memcpy(copy, array, len);
		smsort_ext(copy, 0, cnt, less, swap);
	}
}

static void
assert_is_sorted(const void *copy, size_t cnt, size_t isize)
{
	cmp_routine cmp = get_cmp_routine(isize);
	size_t i;

	for (i = 1; i < cnt; i++) {
		const char *prev = const_ptr_add_offset(copy, (i - 1) * isize);
		const char *cur = const_ptr_add_offset(copy, i * isize);

		g_assert((*cmp)(prev, cur) <= 0);
	}
}

static void
timeit(void (*f)(void *, void *, size_t, size_t),
	void *array, size_t cnt, size_t isize,
	bool chrono, const char *what, const char *algorithm)
{
	tm_t start, end;
	void *copy;

	copy = xmalloc(cnt * isize);

	tm_now_exact(&start);
	(*f)(array, copy, cnt, isize);
	tm_now_exact(&end);
	assert_is_sorted(copy, cnt, isize);
	xfree(copy);

	if (chrono) {
		double elapsed = tm_elapsed_f(&end, &start);
		printf("%7s - %s - took %g s\n", algorithm, what, elapsed);
	}
}

static void *
generate_array(size_t cnt, size_t isize)
{
	size_t len;
	void *array;
	
	len = cnt * isize;
	array = xmalloc(len);
	random_bytes(array, len);

	return array;
}

static void
perturb_sorted_array(void *array, size_t cnt, size_t isize)
{
	size_t n;
	size_t i;
	void *tmp;

	xsort(array, cnt, isize, get_cmp_routine(isize));

	n = 1 + random_value(cnt / 16);
	tmp = alloca(isize);

	for (i = 0; i < n; i++) {
		size_t a = random_value(cnt - 1);
		size_t b = random_value(cnt - 1);
		void *x = ptr_add_offset(array, a * isize);
		void *y = ptr_add_offset(array, b * isize);

		memcpy(tmp, y, isize);
		memcpy(y, x, isize);
		memcpy(x, tmp, isize);
	}
}

int
main(int argc, char **argv)
{
	extern int optind;
	extern char *optarg;
	bool tflag = 0;
	int c;
	size_t i;

	progname = argv[0];

	while ((c = getopt(argc, argv, "ht")) != EOF) {
		switch (c) {
		case 't':			/* timing report */
			tflag++;
			break;
		case 'h':			/* show help */
		default:
			usage();
			break;
		}
	}

	if ((argc -= optind) != 0)
		usage();

	for (i = 1; i <= 16; i++) {
		size_t cnt = 1U << i;
		size_t j;

		for (j = 0; j < 4; j++) {
			char buf[80];
			size_t isize = sizeof(void *) + INTSIZE * j;
			void *array;

			g_assert(isize == align_round(isize));

			str_bprintf(buf, sizeof buf, "%zu item%s of %zu bytes",
				cnt, 1 == cnt ? "" : "s", isize);

			array = generate_array(cnt, isize);
			timeit(xsort_test, array, cnt, isize, tflag, buf, "xsort");
			timeit(qsort_test, array, cnt, isize, tflag, buf, "qsort");
			timeit(smsort_test, array, cnt, isize, tflag, buf, "smooth");
			timeit(smsort2_test, array, cnt, isize, tflag, buf, "smooth2");

			str_bprintf(buf, sizeof buf, "%zu sorted item%s of %zu bytes",
				cnt, 1 == cnt ? "" : "s", isize);

			xsort(array, cnt, isize, get_cmp_routine(isize));
			timeit(xsort_test, array, cnt, isize, tflag, buf, "xsort");
			timeit(qsort_test, array, cnt, isize, tflag, buf, "qsort");
			timeit(smsort_test, array, cnt, isize, tflag, buf, "smooth");
			timeit(smsort2_test, array, cnt, isize, tflag, buf, "smooth2");

			str_bprintf(buf, sizeof buf,
				"%zu almost sorted item%s of %zu bytes",
				cnt, 1 == cnt ? "" : "s", isize);

			perturb_sorted_array(array, cnt, isize);
			timeit(xsort_test, array, cnt, isize, tflag, buf, "xsort");
			timeit(qsort_test, array, cnt, isize, tflag, buf, "qsort");
			timeit(smsort_test, array, cnt, isize, tflag, buf, "smooth");
			timeit(smsort2_test, array, cnt, isize, tflag, buf, "smooth2");

			xfree(array);
		}
	}

	return 0;
}

