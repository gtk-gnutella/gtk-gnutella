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

#include "lib/base16.h"
#include "lib/htable.h"
#include "lib/misc.h"
#include "lib/path.h"
#include "lib/rand31.h"
#include "lib/sha1.h"
#include "lib/smsort.h"
#include "lib/str.h"
#include "lib/tm.h"
#include "lib/xmalloc.h"
#include "lib/xsort.h"

#define TEST_BITS	16
#define TEST_WORDS	4

#define DUMP_BYTES	16

const char *progname;
static size_t item_size;
static bool qsort_only;
static bool degenerative;
static bool silent_mode;
static unsigned initial_seed;
static const char *current_test;
static const char *current_algorithm;

typedef void (*xsort_routine)(void *b, size_t n, size_t s, cmp_fn_t cmp);

static void G_GNUC_NORETURN
usage(void)
{
	fprintf(stderr,
		"Usage: %s [-htDQS] [-c items] [-n loops] [-s item_size]\n"
		"       [-N main-loops] [-R seed]\n"
		"  -c : sets item count to test\n"
		"  -h : prints this help message\n"
		"  -n : sets amount of loops\n"
		"  -s : sets item size to test, in bytes\n"
		"  -t : time each test\n"
		"  -D : include degenerative data sets\n"
		"  -N : run the main test loop that many times (default = 1)\n"
		"  -Q : only test our xqsort() versus libc's qsort()\n"
		"  -R : seed for repeatable random key sequence\n"
		"  -S : silent mode -- do not print anything for successful tests\n"
		, progname);
	exit(EXIT_FAILURE);
}

static void G_GNUC_NORETURN
test_abort()
{
	if (current_test != NULL)
		printf("%7s - %s - FAILED\n", current_algorithm, current_test);
	printf("use '-R %u' to reproduce problem.\n", initial_seed);
	abort();
}

typedef int (*cmp_routine)(const void *a, const void *b);

static int
long_cmp(const void *a, const void *b)
{
	const ulong *la = a, *lb = b;
	const ulong va = *la, vb = *lb;

	return CMP(va, vb);
}

static int
long_revcmp(const void *a, const void *b)
{
	const ulong *la = a, *lb = b;
	const ulong va = *la, vb = *lb;

	return CMP(vb, va);
}

static int
generic_cmp(const void *a, const void *b)
{
	return memcmp(a, b, item_size);	/* Global variable */
}

static int
generic_revcmp(const void *a, const void *b)
{
	return memcmp(b, a, item_size);	/* Global variable */
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

static cmp_routine
get_revcmp_routine(size_t isize)
{
	switch (isize) {
	case LONGSIZE:
		return long_revcmp;
	default:
		item_size = isize;	/* Global variable */
		return generic_revcmp;
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

	return long_cmp(&a->val, &b->val) < 0;
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

static bool
generic_less(void *m, size_t i, size_t j)
{
	void *a = ptr_add_offset(m, i * item_size);	/* Global variable */
	void *b = ptr_add_offset(m, j * item_size);	/* Global variable */

	return memcmp(a, b, item_size) < 0;	/* Global variable */
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
	else {
		item_size = isize;		/* Global variable */
		return generic_less;
	}
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

static void
generic_swap(void *m, size_t i, size_t j)
{
	void *a = ptr_add_offset(m, i * item_size);	/* Global variable */
	void *b = ptr_add_offset(m, j * item_size);	/* Global variable */

	SWAP(a, b, item_size);	/* Global variable */
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
		return generic_swap;
}

static void
xtest(xsort_routine f, void *array, void *copy,
	size_t cnt, size_t isize, size_t loops)
{
	cmp_routine cmp = get_cmp_routine(isize);
	size_t len = cnt * isize;

	do {
		memcpy(copy, array, len);
		(*f)(copy, cnt, isize, cmp);
	} while (--loops > 0);
}

static void
xsort_test(void *array, void *copy, size_t cnt, size_t isize, size_t loops)
{
	xtest(xsort, array, copy, cnt, isize, loops);
}

static void
xqsort_test(void *array, void *copy, size_t cnt, size_t isize, size_t loops)
{
	xtest(xqsort, array, copy, cnt, isize, loops);
}


static void
qsort_test(void *array, void *copy, size_t cnt, size_t isize, size_t loops)
{
	xtest(qsort, array, copy, cnt, isize, loops);
}

static void
smsort_test(void *array, void *copy, size_t cnt, size_t isize, size_t loops)
{
	xtest(smsort, array, copy, cnt, isize, loops);
}

static void
smsorte_test(void *array, void *copy, size_t cnt, size_t isize, size_t loops)
{
	smsort_less_t less = get_less_routine(isize);
	smsort_swap_t swap = get_swap_routine(isize);
	size_t len = cnt * isize;

	do {
		memcpy(copy, array, len);
		smsort_ext(copy, 0, cnt, less, swap);
	} while (--loops > 0);
}

static void
dump_unsorted(const void *copy, size_t cnt, size_t isize, size_t failed)
{
	size_t i;

	printf("unsorted array (at index %lu):\n", (ulong) failed);

	for (i = 0; i < cnt; i++) {
		char buf[DUMP_BYTES * 2 + 1];
		size_t n;
		const char *cur = const_ptr_add_offset(copy, i * isize);

		n = base16_encode(buf, sizeof buf - 1, cur, MIN(isize, DUMP_BYTES));
		buf[n] = '\0';
		printf("%6lu %s%s%s\n", (ulong) i, buf,
			isize > DUMP_BYTES ? "..." : "",
			i == failed ? " <-- FAILED" : "");
	}
	test_abort();
}

static void
assert_is_sorted(const void *copy, size_t cnt, size_t isize)
{
	cmp_routine cmp = get_cmp_routine(isize);
	size_t i;

	for (i = 1; i < cnt; i++) {
		const char *prev = const_ptr_add_offset(copy, (i - 1) * isize);
		const char *cur = const_ptr_add_offset(copy, i * isize);

		if ((*cmp)(prev, cur) > 0)
			dump_unsorted(copy, cnt, isize, i);
	}
}

static void
count_items(htable_t *ht, const void *array, size_t cnt, size_t isize)
{
	size_t i;

	for (i = 0; i < cnt; i++) {
		const char *cur = const_ptr_add_offset(array, i * isize);
		size_t n;

		n = pointer_to_size(htable_lookup(ht, cur));
		htable_insert(ht, cur, size_to_pointer(n + 1));
	}
}

static void
array_mismatch(const htable_t *ht, const void *key, const void *array,
	const void *copy, size_t cnt, size_t isize)
{
	size_t i;

	printf("array mismatch:\n");
	printf("original array:\n");

	for (i = 0; i < cnt; i++) {
		char buf[DUMP_BYTES * 2 + 1];
		size_t n;
		const char *cur = const_ptr_add_offset(array, i * isize);

		n = base16_encode(buf, sizeof buf - 1, cur, MIN(isize, DUMP_BYTES));
		buf[n] = '\0';
		printf("%6lu %s%s%s\n", (ulong) i, buf,
			isize > DUMP_BYTES ? "..." : "",
			0 == memcmp(key, cur, isize) ? " <-- ERROR" : "");
	}

	printf("sorted array:\n");

	for (i = 0; i < cnt; i++) {
		char buf[DUMP_BYTES * 2 + 1];
		size_t n;
		const char *cur = const_ptr_add_offset(copy, i * isize);

		n = base16_encode(buf, sizeof buf - 1, cur, MIN(isize, DUMP_BYTES));
		buf[n] = '\0';
		printf("%6lu %s%s%s\n", (ulong) i, buf,
			isize > DUMP_BYTES ? "..." : "",
			0 == memcmp(key, cur, isize) ? " <-- (ERROR)" :
			htable_contains(ht, cur) ? "" : " <-- UNKNOWN");
	}

	test_abort();
}

static void
assert_is_equivalent(const void *array, const void *copy,
	size_t cnt, size_t isize)
{
	htable_t *aht, *cht;
	htable_iter_t *iter;
	const void *key;
	void *value;

	aht = htable_create(HASH_KEY_FIXED, isize);
	cht = htable_create(HASH_KEY_FIXED, isize);

	count_items(aht, array, cnt, isize);
	count_items(cht, copy, cnt, isize);

	iter = htable_iter_new(aht);
	while (htable_iter_next(iter, &key, &value)) {
		size_t n = pointer_to_size(value);
		size_t o = pointer_to_size(htable_lookup(cht, key));
		if (n != o) {
			array_mismatch(aht, key, array, copy, cnt, isize);
		}
		htable_remove(cht, key);
	}
	htable_iter_release(&iter);

	g_assert(0 == htable_count(cht));

	htable_free_null(&aht);
	htable_free_null(&cht);
}

static double
dry_run(void *array, void *copy, size_t cnt, size_t isize, size_t loops)
{
	tm_t start, end;
	double ustart, uend;

	tm_now_exact(&start);
	tm_cputime(&ustart, NULL);
	qsort_test(array, copy, cnt, isize, loops);
	tm_cputime(&uend, NULL);
	tm_now_exact(&end);

	return ustart == uend ? tm_elapsed_f(&end, &start) : uend - ustart;
}

static size_t
calibrate(void *array, size_t cnt, size_t isize)
{
	double elapsed;
	size_t n = 1;
	void *copy;

	copy = xmalloc(cnt * isize);

	do {
		n *= 2;
		elapsed = dry_run(array, copy, cnt, isize, n);
	} while (elapsed < 0.1 && n < (1U << 31));

	xfree(copy);

	return n;
}

static void
compute_sha1(sha1_t *digest, const void *p, size_t len)
{
	SHA1Context ctx;

	SHA1Reset(&ctx);
	SHA1Input(&ctx, p, len);
	SHA1Result(&ctx, digest);
}

static void
timeit(void (*f)(void *, void *, size_t, size_t, size_t),
	size_t loops, void *array, size_t cnt, size_t isize,
	bool chrono, const char *what, const char *algorithm)
{
	tm_t start, end;
	double ustart, uend;
	void *copy;
	sha1_t before, after;

	copy = xmalloc(cnt * isize);
	compute_sha1(&before, array, cnt * isize);
	current_algorithm = algorithm;

	tm_now_exact(&start);
	tm_cputime(&ustart, NULL);
	(*f)(array, copy, cnt, isize, loops);
	tm_cputime(&uend, NULL);
	tm_now_exact(&end);
	compute_sha1(&after, array, cnt * isize);
	if (0 != memcmp(&before, &after, sizeof before))
		g_error("memory corruption on array during \"%s\" test", algorithm);
	assert_is_sorted(copy, cnt, isize);
	assert_is_equivalent(array, copy, cnt, isize);
	xfree(copy);

	if (chrono) {
		double elapsed = tm_elapsed_f(&end, &start);
		double cpu = uend - ustart;
		printf("%7s - %s - [%lu] time=%.3gs, CPU=%.3gs\n", algorithm, what,
			(ulong) loops, elapsed, cpu);
	} else if (!silent_mode) {
		printf("%7s - %s - OK\n", algorithm, what);
	}
	fflush(stdout);
}

static void *
generate_array(size_t cnt, size_t isize)
{
	size_t len;
	void *array;
	
	len = cnt * isize;
	array = xmalloc(len);
	rand31_bytes(array, len);

	return array;
}

enum degenerative {
	IDENTICAL,
	ALMOST_IDENTICAL,
	SPARSLY_IDENTICAL,
};

static const char *
degenerative_to_string(enum degenerative how)
{
	switch (how) {
	case IDENTICAL:				return "identical";
	case ALMOST_IDENTICAL:		return "almost identical";
	case SPARSLY_IDENTICAL:		return "sparsly identical";
	}

	return NULL;
}

static void *
generate_degenerative_array(size_t cnt, size_t isize, enum degenerative how)
{
	size_t len;
	void *array;
	
	len = cnt * isize;
	array = xmalloc(len);

	switch (how) {
	case IDENTICAL:
		memset(array, rand31() & 0xff, len);
		break;
	case SPARSLY_IDENTICAL:
	case ALMOST_IDENTICAL:
		memset(array, rand31() & 0xff, len);
		{
			size_t n;
			size_t i;

			if (SPARSLY_IDENTICAL == degenerative)
				n = cnt - cnt / 8;
			else
				n = 1 + rand31_value(cnt / 16);

			for (i = 0; i < n; i++) {
				size_t j = rand31_value(cnt - 1);
				void *x = ptr_add_offset(array, j * isize);
				rand31_bytes(x, isize);
			}
		}
		break;
	}

	return array;
}

static void
perturb_sorted_array(void *array, size_t cnt, size_t isize)
{
	size_t n;
	size_t i;

	xsort(array, cnt, isize, get_cmp_routine(isize));

	n = 1 + rand31_value(cnt / 16);

	for (i = 0; i < n; i++) {
		size_t a = rand31_value(cnt - 1);
		size_t b = rand31_value(cnt - 1);
		void *x = ptr_add_offset(array, a * isize);
		void *y = ptr_add_offset(array, b * isize);

		SWAP(x, y, isize);
	}
}

static void
run(void *array, size_t cnt, size_t isize, bool chrono, size_t loops,
	const char *what)
{
	if (0 == loops)
		loops = chrono ? calibrate(array, cnt, isize) : 1;

	current_test = what;

	if (!qsort_only)
		timeit(xsort_test, loops, array, cnt, isize, chrono, what, "xsort");
	timeit(xqsort_test, loops, array, cnt, isize, chrono, what, "xqsort");
	timeit(qsort_test, loops, array, cnt, isize, chrono, what, "qsort");
	if (!qsort_only) {
		timeit(smsort_test, loops, array, cnt, isize, chrono, what, "smooth");
		timeit(smsorte_test, loops, array, cnt, isize, chrono, what, "smoothe");
	}

	current_test = NULL;
}

static void
run_degenerative(enum degenerative how, size_t cnt, size_t isize,
	bool chrono, size_t loops)
{
	char buf[80];
	void *array;

	str_bprintf(buf, sizeof buf,
		"%zu %s item%s of %zu bytes",
		cnt, degenerative_to_string(how), 1 == cnt ? "" : "s", isize);

	array = generate_degenerative_array(cnt, isize, how);
	run(array, cnt, isize, chrono, loops, buf);
	xfree(array);
}

static void
test(size_t cnt, size_t isize, bool chrono, size_t loops)
{
	char buf[80];
	void *array;
	void *copy;

	str_bprintf(buf, sizeof buf, "%zu item%s of %zu bytes",
		cnt, 1 == cnt ? "" : "s", isize);

	array = generate_array(cnt, isize);
	copy = xcopy(array, cnt * isize);

	run(array, cnt, isize, chrono, loops, buf);

	str_bprintf(buf, sizeof buf, "%zu sorted item%s of %zu bytes",
		cnt, 1 == cnt ? "" : "s", isize);

	xsort(array, cnt, isize, get_cmp_routine(isize));
	run(array, cnt, isize, chrono, loops, buf);

	str_bprintf(buf, sizeof buf,
		"%zu almost sorted item%s of %zu bytes",
		cnt, 1 == cnt ? "" : "s", isize);

	perturb_sorted_array(array, cnt, isize);
	run(array, cnt, isize, chrono, loops, buf);

	str_bprintf(buf, sizeof buf,
		"%zu reverse-sorted item%s of %zu bytes",
		cnt, 1 == cnt ? "" : "s", isize);

	xsort(array, cnt, isize, get_revcmp_routine(isize));
	run(array, cnt, isize, chrono, loops, buf);

	str_bprintf(buf, sizeof buf,
		"%zu almost rev-sorted item%s of %zu bytes",
		cnt, 1 == cnt ? "" : "s", isize);

	perturb_sorted_array(array, cnt, isize);
	run(array, cnt, isize, chrono, loops, buf);

	str_bprintf(buf, sizeof buf,
		"%zu sorted 3/4-1/4 item%s of %zu bytes",
		cnt, 1 == cnt ? "" : "s", isize);

	memcpy(array, copy, cnt * isize);

	{
		size_t thresh = cnt / 4;
		size_t lower = cnt - thresh;
		void *upper = ptr_add_offset(array, lower * isize);

		xsort(array, lower, isize, get_cmp_routine(isize));
		if (thresh > 0)
			xsort(upper, thresh, isize, get_cmp_routine(isize));
	}
	run(array, cnt, isize, chrono, loops, buf);

	str_bprintf(buf, sizeof buf,
		"%zu sorted n-8 item%s of %zu bytes",
		cnt, 1 == cnt ? "" : "s", isize);

	memcpy(array, copy, cnt * isize);

	{
		size_t thresh = 8;
		size_t lower = cnt - thresh;
		void *upper = ptr_add_offset(array, lower * isize);

		if (cnt > thresh) {
			xsort(array, lower, isize, get_cmp_routine(isize));
			xsort(upper, thresh, isize, get_cmp_routine(isize));
		} else {
			xsort(array, cnt, isize, get_cmp_routine(isize));
		}
	}
	run(array, cnt, isize, chrono, loops, buf);

	xfree(array);
	xfree(copy);

	if (degenerative) {
		run_degenerative(IDENTICAL, cnt, isize, chrono, loops);
		run_degenerative(ALMOST_IDENTICAL, cnt, isize, chrono, loops);
		run_degenerative(SPARSLY_IDENTICAL, cnt, isize, chrono, loops);
	}
}

int
main(int argc, char **argv)
{
	extern int optind;
	extern char *optarg;
	bool tflag = FALSE;
	size_t count = 0;
	size_t isize = 0;
	size_t loops = 0;
	size_t main_loops = 1;
	size_t main_count = 0;
	bool multiple_loops = FALSE;
	int c;
	size_t i;
	unsigned rseed = 0;

	mingw_early_init();
	progname = filepath_basename(argv[0]);

	while ((c = getopt(argc, argv, "c:hn:s:tDN:QR:S")) != EOF) {
		switch (c) {
		case 'c':			/* amount of items to use in array */
			count = atol(optarg);
			break;
		case 't':			/* timing report */
			tflag++;
			break;
		case 'n':			/* amount of loops */
			loops = atol(optarg);
			break;
		case 's':			/* item size */
			isize = atol(optarg);
			break;
		case 'D':			/* use degenerative data sets */
			degenerative = TRUE;
			break;
		case 'N':			/* number of main loops */
			main_loops = atol(optarg);
			break;
		case 'Q':			/* only test qsort() versus xqsort() */
			qsort_only = TRUE;
			break;
		case 'R':			/* randomize in a repeatable way */
			rseed = atoi(optarg);
			break;
		case 'S':			/* silent mode */
			silent_mode = TRUE;
			break;
		case 'h':			/* show help */
		default:
			usage();
			break;
		}
	}

	if ((argc -= optind) != 0)
		usage();

	if (silent_mode && tflag) {
		fprintf(stderr, "%s: -S has little effect when -t is present\n",
			progname);
	}

	rand31_set_seed(rseed);
	multiple_loops = main_loops > 1;

	while (main_loops--) {
		initial_seed = rand31_current_seed();
		main_count++;

		if (multiple_loops) {
			printf("test loop #%lu (%lu more) with seed %u\n",
				(ulong) main_count, (ulong) main_loops, initial_seed);
		}

		for (i = 1; i <= TEST_BITS; i++) {
			bool is_last = count != 0;
			size_t cnt = count != 0 ? count : 1U << i;
			size_t j;

			for (j = 0; j < TEST_WORDS; j++) {
				bool is_last_size = isize != 0;
				size_t size = isize != 0 ? isize : sizeof(void *) + INTSIZE * j;

				test(cnt, size, tflag, loops);

				if (is_last_size)
					break;
			}

			if (is_last)
				break;
		}
	}

	return 0;
}

