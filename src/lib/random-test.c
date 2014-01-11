/*
 * random-test -- random tests and benchmarking.
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

#include "lib/aje.h"
#include "lib/arc4random.h"
#include "lib/chi2.h"
#include "lib/entropy.h"
#include "lib/misc.h"
#include "lib/mtwist.h"
#include "lib/parse.h"
#include "lib/path.h"
#include "lib/rand31.h"
#include "lib/random.h"
#include "lib/stats.h"
#include "lib/str.h"
#include "lib/stringify.h"
#include "lib/teq.h"
#include "lib/thread.h"
#include "lib/tm.h"
#include "lib/well.h"
#include "lib/xmalloc.h"

#define VALUES_REMEMBERED	128
#define MIN_PERIOD			4

const char *progname;

static void G_GNUC_PRINTF(1, 2)
warning(const char *msg, ...)
{
	va_list args;
	char buf[128];

	va_start(args, msg);
	str_vbprintf(buf, sizeof buf, msg, args);
	va_end(args);

	fprintf(stderr, "%s: WARNING: %s\n", progname, buf);
}

static void G_GNUC_NORETURN
usage(void)
{
	fprintf(stderr,
		"Usage: %s [-14eghluyABMPSTW] [-b mask] [-c items] [-m min]\n"
		"       [-p period] [-s skip] [-t amount] [-C val] [-D count]\n"
		"       [-F upper] [-R seed] [-U upper] [-X upper]\n"
		"  -1 : test entropy_rand31() instead of rand31()\n"
		"  -4 : test arc4random() instead of rand31()\n"
		"  -b : bit mask to apply on random values (focus on some bits)\n"
		"  -c : sets item count to remember, for period computation\n"
		"  -e : test entropy_random() instead of rand31()\n"
		"  -g : add entropy every second to AJE, ARC4 and WELL generators\n"
		"  -h : prints this help message\n"
		"  -l : use thread-local PRNG state context, if supported by routine\n"
		"  -m : sets minimum period to consider\n"
		"  -p : sets period for value and bit counting\n"
		"  -s : skip that amount of initial random values\n"
		"  -t : benchmark generation of specified amount of random values\n"
		"  -u : test rand31_u32() instead of rand31()\n"
		"  -A : test aje_rand(), the Fortuna-like PRNG, instead of rand31()\n"
		"  -B : count '1' occurrences of each bit\n"
		"  -C : count how many times the random value occurs (after -b)\n"
		"  -D : dump specified amount of random numbers (after -b)\n"
		"  -F : uses random floats multiplied by supplied constant\n"
		"  -M : test mt_rand(), the Mersenne Twister, instead of rand31()\n"
		"  -P : compute period through brute-force search\n"
		"  -R : seed for repeatable random key sequence\n"
		"  -S : test random_strong(), a XOR of WELL1024b and ARC4\n"
		"  -T : dieharder test mode, dumping raw random bytes to stdout\n"
		"  -U : use uniform random numbers to specified upper bound\n"
		"  -W : test well_rand(), the WELL 1024 PRNG, instead of rand31()\n"
		"  -X : perform chi-squared test of uniform random numbers\n"
		"Values given as decimal, hexadecimal (0x), octal (0) or binary (0b)\n"
		"Use -T as in: %s -4l -T | dieharder -g 200 -a\n"
		, progname, progname);
	exit(EXIT_FAILURE);
}

static unsigned
small_period(const unsigned *values, size_t count, unsigned min_period)
{
	unsigned *copy;
	unsigned n, period = 0;

	XMALLOC_ARRAY(copy, count);

	/* Check for a small period up to 1/2 the remembered buffer */

	for (n = min_period; n <= count / 2; n++) {
		unsigned i;

		for (i = 0; i < n; i++) {
			copy[i] = values[i] ^ values[n + i];
			if (copy[i] != 0)
				break;
		}
		g_assert(n + i <= count);

		if (i == n) {
			period = n;
			break;
		}
	}

	xfree(copy);
	return period;
}

static void
count_bits(random_fn_t fn, unsigned period, unsigned bits[], unsigned bcnt)
{
	unsigned n;

	memset(bits, 0, bcnt * sizeof bits[0]);

	for (n = 0; n < period; n++) {
		unsigned val = (*fn)();
		unsigned i;

		for (i = 0; i < bcnt; i++) {
			if (val & (1U << i))
				bits[i]++;
		}
		if (0 == (n & 0xfff)) {
			printf("Counting bits %u\r", n);
			fflush(stdout);
		}
	}

	printf("%-40s\n", "Finished counting bits!");
}

static unsigned
count_values(random_fn_t fn, unsigned period, unsigned mask, unsigned value)
{
	unsigned v = value & mask;
	unsigned n, cnt = 0;

	for (n = 0; n < period; n++) {
		unsigned val = (*fn)() & mask;
		if G_UNLIKELY(val == v)
			cnt++;
		if (0 == (n & 0xfff)) {
			printf("Counting %u (found %u)\r", n, cnt);
			fflush(stdout);
		}
	}

	printf("%-40s\n", "Finished counting!");

	return cnt;
}

static G_GNUC_HOT unsigned
compute_period(size_t count, random_fn_t fn, unsigned mask, unsigned min_period)
{
	size_t n;
	size_t idx;					/* Filling index */
	size_t didx = 0;			/* Duplicate index */
	unsigned *values, *window;
	unsigned period;

	XMALLOC_ARRAY(values, count);
	XMALLOC_ARRAY(window, count);

	if (min_period < MIN_PERIOD) {
		warning("Raising minimum period from %u to %u", min_period, MIN_PERIOD);
		min_period = MIN_PERIOD;
	}

	if (min_period > count / 2) {
		warning("Capping minimum period from %u to %u", min_period,
			(unsigned) count / 2);
		min_period = count / 2;
	}

	for (n = 0, idx = 0; idx < count; n++, idx++) {
		unsigned val = (*fn)() & mask;
		values[idx] = val;
		if (0 == (n & 0xfff)) {
			printf("Fill %u\r", (unsigned) n);
			fflush(stdout);
		}
	}

	if (0 != (period = small_period(values, count, min_period)))
		goto done;
		
	for (; n != 0; n++) {
		unsigned val = (*fn)() & mask;
		if G_UNLIKELY(val == values[didx]) {
			window[didx] = val;
			if G_UNLIKELY(++didx == count)
				break;
		} else if G_UNLIKELY(didx != 0) {
			size_t i;

			/*
			 * Did not match window[0..didx] with values[].
			 * Try with window[1..didx], window[2..didx], etc... to
			 * re-establish a matching start point in `didx'.
			 */

			for (i = 1; i < didx; i++) {
				size_t j = 0;

				for (j = 0; j < didx - i; j++) {
					if (window[i + j] != values[j])
						goto no_match;
				}

				if G_UNLIKELY(val == values[j]) {
					g_assert(didx - i == j);

					memmove(window, &window[i], (didx - i) * sizeof window[0]);
					didx = j + 1;

					g_assert(didx < count);
					window[didx] = val;
					break;
				}

				no_match:
					continue;
			}
		}
		if (0 == (n & 0xfff)) {
			printf("Period %u\r", (unsigned) n);
			fflush(stdout);
		}
	}

	period = 0 == n ? (unsigned) -1 : n - count + 1;

done:
	printf("%-20s\n", 0 == n ? "Looped over!" : "Done!");

	xfree(values);
	xfree(window);
	return period;
}

static void
skip_values(random_fn_t fn, unsigned skip)
{
	unsigned n = 0;

	while (n++ < skip) {
		(void) (*fn)();
		if (1 == (n & 0xff)) {
			printf("Skipping %u...\r", n);
			fflush(stdout);
		}
	}
	printf("Skipped %u initial random values\n", skip);
}

static void
dump_random(random_fn_t fn, unsigned mask, unsigned dumpcnt)
{
	unsigned n;

	for (n = dumpcnt; n != 0; n--) {
		printf("%u\n", (*fn)() & mask);
	}
}

static void
dump_raw(random_fn_t fn, unsigned mask)
{
	for (;;) {
		uint32 v[1024];
		size_t i;

		for (i = 0; i < G_N_ELEMENTS(v); i++) {
			v[i] = (*fn)() & mask;
		}
		if (-1 == write(STDOUT_FILENO, &v, sizeof v))
			break;
	}
}

static void
display_bits(unsigned bits[], unsigned nbits, unsigned period)
{
	unsigned i;
	statx_t *st = statx_make_nodata();
	double avg, sdev, tavg;
	unsigned used = nbits;

	for (i = nbits; i != 0; i--) {
		if (0 != bits[i - 1]) {
			used = i;
			break;
		}
	}

	for (i = 0; i < used; i++) {
		statx_add(st, (double) bits[i]);
	}

	avg = statx_avg(st);
	sdev = statx_sdev(st);
	tavg = period / 2.0;

	for (i = 0; i < used; i++) {
		bool odd = bits[i] < tavg - 2 *sdev || bits[i] > tavg + 2 * sdev;
		printf("Bit #%-2u was set %u times (%.8f%%)%s\n",
			i, bits[i], bits[i] * 100.0 / MAX(1, period),
			odd ? "*" : "");
	}
	printf("Period used was %u\n", period);
	printf("Average bit count is %.3f (%+.3f), sdev=%.3f, bits=%u\n",
		avg, avg - tavg, sdev, used);

	statx_free(st);
}

#define CHI_CLASS		1000	/* Wants about 1000 items per class */
#define CHI_MIN			5		/* Min amount of values per class */
#define CHI_MAX_CLASSES	20
#define CHI_CONFIDENCE	0.97
#define CHI_MAX_RETRY	3

static void
chi2_test(random_fn_t fn, unsigned max)
{
	unsigned classes;
	unsigned *values;
	unsigned n, i, expected;
	double ratio, chi2, p;
	int retried = 0;

	classes = MIN(CHI_MAX_CLASSES, max);
	XMALLOC0_ARRAY(values, classes);

	printf("Chi-squared test with uniform %u random numbers over %u classes:\n",
		max, classes);

	expected = CHI_CLASS;
	n = classes * expected;
	ratio = (double) max / classes;

retry:
	for (i = 0; i < n; i++) {
		unsigned val = random_upto(fn, max - 1);

		if (max == classes) {
			values[val]++;
		} else {
			unsigned idx = (unsigned) (val / ratio);
			values[idx]++;
		}

		if (1 == (i & 0xfff)) {
			printf("Generating %u / %u\r", i, n);
			fflush(stdout);
		}
	}

	for (i = 0; i < classes; i++) {
		if (values[i] < CHI_MIN && retried < CHI_MAX_RETRY) {
			n *= 2;
			expected *= 2;
			printf("Need to double count of random numbers, now %u "
				"(class #%u has %u)\n", n, i, values[i]);
			retried++;
			goto retry;
		}
	}

	printf("Generation of %u numbers completed\n", n);
	fflush(stdout);

	chi2 = 0.0;

	for (i = 0; i < classes; i++) {
		str_t *s;
		double o = values[i] / (double) n;
		double e = expected / (double) n;
		double d = o - e;
		size_t middle = 32;

		chi2 += d * d / e;

		s = str_new(0);
		str_printf(s, "%5u o=%.6f (%u/%u),", i, o, values[i], n);
		if (str_len(s) < middle)
			str_catf(s, "%*s", (int) (middle - str_len(s)), " ");
		str_catf(s, "e=%g (%u/%u)\n", e, expected, n);
		printf("%s", str_2c(s));
		str_destroy_null(&s);
	}

	p = chi2_upper_tail(classes - 1, chi2);
	printf("Chi2=%g, p=%g (%s)\n", chi2, p,
		p > CHI_CONFIDENCE ? "OK" : "SKEWED");

	xfree(values);
}

static void
timeit(random_fn_t fn, unsigned amount, const char *name)
{
	tm_t start, end;
	double ustart, uend;
	unsigned i;
	unsigned generated = amount;
	unsigned calls = amount;

	tm_now_exact(&start);
	tm_cputime(&ustart, NULL);
	(void) (*fn)();
	tm_cputime(&uend, NULL);
	tm_now_exact(&end);

	printf("%s() initialization took %.3gs (CPU=%.3gs)\n",	
		name, tm_elapsed_f(&end, &start), uend - ustart);

	fflush(stdout);

	tm_now_exact(&start);
	tm_cputime(&ustart, NULL);
again:
	for (i = calls; i != 0; i--) {
		(*fn)();
	}
	tm_cputime(&uend, NULL);
	if (uend - ustart < 0.05) {
		calls *= 2;
		generated += calls;
		goto again;
	}
	tm_now_exact(&end);

	{
		double elapsed = tm_elapsed_f(&end, &start);
		double cpu = uend - ustart;

		printf("Calling %s() %u times took %.3gs (CPU=%.3gs), %g numbers/s\n",	
			name, generated, elapsed, cpu, generated / elapsed);
		
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

struct uniform {
	random_fn_t rf;
	uint32 max;
} uniform;

static uint32
rand_uniform(void)
{
	return random_upto(uniform.rf, uniform.max);
}

struct fp {
	random_fn_t rf;
	uint32 max;
} fp;

static uint32
rand_fp(void)
{
	return random_double_generate(fp.rf) * fp.max;
}

static void *
add_entropy(void *p)
{
	(void) p;

	for (;;) {
		uint32 v[16];
		size_t i;

		thread_sleep_ms(500);

		for (i = 0; i < G_N_ELEMENTS(v); i++) {
			v[i] = rand31_u32();
		}

		random_add(v, sizeof v);
	}

	return NULL;
}

static void
start_generate_thread(bool verbose)
{
	int id;

	teq_create_if_none();

	id = thread_create(add_entropy, NULL, THREAD_F_DETACH, THREAD_STACK_MIN);

	if (-1 == id)
		s_error("%s(): cannot create new thread: %m", G_STRFUNC);

	if (verbose)
		printf("Started entropy generation thread for ARC4 and WELL\n");
}

int
main(int argc, char **argv)
{
	extern int optind;
	extern char *optarg;
	size_t count = VALUES_REMEMBERED;
	unsigned min_period = MIN_PERIOD;
	int c;
	unsigned period = (unsigned) -1;
	unsigned mask = (unsigned) -1;
	unsigned rseed = 0, cval = 0, skip = 0, dumpcnt = 0, benchmark = 0, chi = 0;
	bool cperiod = FALSE, countval = FALSE, countbits = FALSE, dumpraw = FALSE;
	bool generate = FALSE;
	random_fn_t fn = (random_fn_t) rand31;
	bool test_local = FALSE;
	const char *fnname = "rand31";
	const char options[] = "14b:c:eghlm:p:s:t:uABC:D:F:MPR:STU:WX:";

#define SET_RANDOM(x)	\
	fn = x;				\
	fnname = #x;

	mingw_early_init();
	progname = filepath_basename(argv[0]);
	misc_init();

	while ((c = getopt(argc, argv, options)) != EOF) {
		if (c == 'l') {
			test_local = TRUE;
			break;
		}
	}

	/*
	 * Despite what the manual says, the getopt() from the Linux libc6 2.17
	 * does not work properly when resetting optind to 1 (it skips the first
	 * argument in the second parsing).
	 *		--RAM, 2013-12-27
	 */

	optind = 0;

	while ((c = getopt(argc, argv, options)) != EOF) {
		switch (c) {
		case '1':			/* test entropy_rand31() */
			SET_RANDOM(entropy_rand31);
			break;
		case '4':			/* test arc4random() */
			if (test_local) {
				SET_RANDOM(arc4_rand);
			} else {
				SET_RANDOM(arc4random);
			}
			break;
		case 'b':			/* bitmask to apply to random values */
			mask = get_number(optarg, c);
			break;
		case 'c':			/* amount of items to remember */
			count = get_number(optarg, c);
			break;
		case 'e':
			SET_RANDOM(entropy_random);
			break;
		case 'g':			/* generate "entropy" in background thread */
			generate = TRUE;
			break;
		case 'l':			/* test thread-local (already handled before) */
			break;
		case 'm':			/* supersede defaul mininum period */
			min_period = get_number(optarg, c);
			break;
		case 'p':			/* supersede period */
			period = get_number(optarg, c);
			break;
		case 's':			/* initial amount of random values to skip */
			skip = get_number(optarg, c);
			break;
		case 't':			/* benchmark number generation */
			benchmark = get_number(optarg, c);
			break;
		case 'u':			/* check rand31_u32() instead */
			SET_RANDOM(rand31_u32);
			break;
		case 'A':			/* check aje_random() instead */
			if (test_local) {
				SET_RANDOM(aje_thread_rand);
			} else {
				SET_RANDOM(aje_rand);
			}
			break;
		case 'B':			/* count occurrences of each bit */
			countbits = TRUE;
			break;
		case 'C':			/* count amount of times value is returned */
			countval = TRUE;
			cval = get_number(optarg, c);
			break;
		case 'D':			/* dump random number */
			dumpcnt = get_number(optarg, c);
			break;
		case 'F':			/* floating-point-based random numbers */
			fp.max = get_number(optarg, c);
			break;
		case 'M':			/* check mt_rand() instead */
			if (test_local) {
				SET_RANDOM(mtp_rand);
			} else {
				SET_RANDOM(mt_rand);
			}
			break;
		case 'P':			/* compute period */
			cperiod = TRUE;
			break;
		case 'R':			/* randomize in a repeatable way */
			rseed = get_number(optarg, c);
			break;
		case 'S':			/* test random_strong() */
			SET_RANDOM(random_strong);
			break;
		case 'T':			/* dump raw numbers to stdout */
			dumpraw = TRUE;
			break;
		case 'U':			/* uniform random numbers */
			uniform.max = get_number(optarg, c);
			break;
		case 'W':			/* check well_rand() instead */
			if (test_local) {
				SET_RANDOM(well_thread_rand);
			} else {
				SET_RANDOM(well_rand);
			}
			break;
		case 'X':			/* perform chi-squared test */
			chi = get_number(optarg, c);
			break;
		case 'h':			/* show help */
		default:
			usage();
			break;
		}
	}

	if ((argc -= optind) != 0)
		usage();

	if (generate)
		start_generate_thread(!dumpraw);

	if (dumpraw) {
		dump_raw(fn, mask);
		return 0;
	}

	printf("Testing %s()\n", fnname);

	if (fp.max != 0) {
		fp.rf = fn;
		fn = rand_fp;
		printf("Using floating-point-based random numbers up to %u with %s\n",
			fp.max, fnname);
		fnname = "rand_fp";
	}

	if (uniform.max != 0) {
		uniform.rf = fn;
		fn = rand_uniform;
		printf("Using uniform random numbers up to %u with %s\n",
			uniform.max, fnname);
	}

	if (benchmark != 0)
		timeit(fn, benchmark, fnname);

	if (is_strprefix(fnname, "rand31")) {
		rand31_set_seed(rseed);
		printf("Initial random seed is %u\n", rand31_initial_seed());
	}

	if (skip != 0)
		skip_values(fn, skip);

	if (cperiod) {
		period = compute_period(count, fn, mask, min_period);
		printf("Period is %u (%u remembered values, mask=0x%x, min=%u)\n",
			period, (unsigned) count, mask, min_period);
	}

	if (countval) {
		unsigned n = count_values(fn, period, mask, cval);
		printf("Found %u occurence%s of %u (mask 0x%x) within period of %u\n",
			n, plural(n), cval & mask, mask, period);
	}

	if (countbits) {
		unsigned bits[32];
		unsigned nbits;

		nbits = G_N_ELEMENTS(bits);

		if ((random_fn_t) rand31 == fn) {
			nbits = 31;
			period &= ~(1U << 31);
		}

		g_assert(nbits <= G_N_ELEMENTS(bits));

		count_bits(fn, period, bits, nbits);
		display_bits(bits, nbits, period);
	}

	if (chi != 0)
		chi2_test(fn, chi);

	if (dumpcnt != 0)
		dump_random(fn, mask, dumpcnt);

	return 0;
}

