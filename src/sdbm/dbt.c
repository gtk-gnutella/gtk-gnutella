/*
 * dbt -- DB tests and benchmarking.
 *
 * Copyright (c) 2011 Raphael Manfredi <Raphael_Manfredi@pobox.com>
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

#include "lib/progname.h"
#include "lib/rand31.h"
#include "lib/str.h"
#include "lib/stringify.h"	/* For plural() */
#include "lib/tm.h"

#include "sdbm.h"

extern G_GNUC_PRINTF(1, 2) void oops(char *fmt, ...);

static bool progress;
static bool shrink, rebuild, thread_safe;
static bool randomize;
static unsigned rseed;
static bool unlink_db;
static bool large_keys, large_values, common_head_tail;

#define WR_DELAY	(1 << 0)
#define WR_VOLATILE	(1 << 1)
#define WR_EMPTY	(1 << 2)
#define WR_DELETING	(1 << 3)

static void G_NORETURN
usage(void)
{
	fprintf(stderr,
		"Usage: %s [-bdeiikprstvwBDEKSTUV] [-R seed] [-c pages] dbname count\n"
		"  -b : rebuild the database\n"
		"  -c : set LRU cache size\n"
		"  -d : perform delete test\n"
		"  -e : perform existence test\n"
		"  -i : perform iteration test\n"
		"  -k : use large keys\n"
		"  -p : show test progress\n"
		"  -r : perform a read test\n"
		"  -s : perform safe iteration test\n"
		"  -t : show timing results for each test\n"
		"  -v : use large values\n"
		"  -w : perform a write test\n"
		"  -B : rebuild the database before testing\n"
		"  -D : enable LRU cache write delay\n"
		"  -E : empty existing database on write test\n"
		"  -K : use large keys with common head/tail parts\n"
		"  -R : seed for repeatable random key sequence\n"
		"  -S : shrink database before testing\n"
		"  -T : make database handle thread-safe\n"
		"  -U : unlink database at the end\n"
		"  -V : consider database as volatile\n",
		getprogname());
	exit(EXIT_FAILURE);
}

static DBM *
open_db(const char *name, bool writeable, long cache, int wflags)
{
	DBM *db;
	int flags = writeable ? (O_CREAT|O_RDWR) : O_RDONLY;

	if ((shrink || rebuild) && !writeable)
		flags = O_RDWR;

	if (WR_EMPTY == (wflags & (WR_EMPTY|WR_DELETING)))
		flags |= O_TRUNC;

	db = sdbm_open(name, flags, 0777);
	if (NULL == db) {
		oops("error opening database \"%s\" in %s mode",
			name, writeable ? "writing" : "reading");
	}
	if (thread_safe)
		sdbm_thread_safe(db);
	if (cache != 0) {
		if (-1 == sdbm_set_cache(db, cache)) {
			oops("error configuring LRU cache for \"%s\"", name);
		}
	}
	/* Volatile implies deferred writes, so do this first */
	if (wflags & WR_VOLATILE) {
		if (-1 == sdbm_set_volatile(db, TRUE)) {
			oops("error enabling volatile status for \"%s\"", name);
		}
	}
	if (-1 == sdbm_set_wdelay(db, booleanize(wflags & WR_DELAY))) {
		oops("error %sabling write delay for \"%s\"",
			(wflags & WR_DELAY) ? "en" : "dis", name);
	}
	if (shrink)
		sdbm_shrink(db);
	if (rebuild) {
		tm_t start, end;
		printf("Rebuilding database...\n");
		tm_now_exact(&start);
		if (-1 == sdbm_rebuild(db)) {
			oops("error rebuilding \"%s\"", name);
		}
		tm_now_exact(&end);
		printf("Done in %.3f secs.\n", tm_elapsed_f(&end, &start));
	}
	return db;
}

static void
unlink_database(const char *name)
{
	DBM *db;

	db = open_db(name, TRUE, 0, 0);
	sdbm_unlink(db);
}

static void
show_progress(long n, long count)
{
	static int c = 0;

	printf("%c (%02ld%%)\r", "-\\|/"[c++ % 4], n * 100 / count);
	fflush(stdout);
}

static void
show_done(tm_t *done)
{
	tm_now_exact(done);
	printf("Done!   \n");
}

#define COMMON_HEAD_TAIL	4
#define LARGE_KEY_TAIL		17
#define NORMAL_KEY_LEN		16

static void
fill_key(char *buf, size_t len, long i)
{
	size_t w;
	size_t offset = 0;
	size_t avail = len;

	if (common_head_tail) {
		g_assert(len > COMMON_HEAD_TAIL);
		memset(buf, 0, COMMON_HEAD_TAIL);
		offset = COMMON_HEAD_TAIL;
		avail -= COMMON_HEAD_TAIL;
	}

	if (randomize) {
		int v = rand31_u32();
		w = str_bprintf(&buf[offset], avail, "%06d%010ld", v, i);
	} else {
		w = str_bprintf(&buf[offset], avail, "%016ld", i);
	}
	if (large_keys) {
		size_t off = len - LARGE_KEY_TAIL;
		memset(&buf[w+offset], 0, len - w);
		g_assert(avail > LARGE_KEY_TAIL + COMMON_HEAD_TAIL);
		if (common_head_tail)
			off -= COMMON_HEAD_TAIL;
		str_bprintf(&buf[off], LARGE_KEY_TAIL, "%016ld", i);
	}
}

static void
rebuild_db(const char *name, long count, long cache, int wflags, tm_t *done)
{
	DBM *db = open_db(name, TRUE, cache, wflags);
	long i;
	long cpage = 0 == cache ? 64 : cache;

	printf("Starting rebuild test (%ld time%s), cache=%ld page%s...\n",
		count, plural(count), cpage, plural(cpage));

	for (i = 0; i < count; i++) {
		if (progress && 0 == i % 50)
			show_progress(i, count);

		if (0 != sdbm_rebuild(db))
			oops("rebuild #%ld failed", i);
	}

	show_done(done);

	sdbm_close(db);
}

static void
read_db(const char *name, long count, long cache, int wflags, tm_t *done)
{
	DBM *db = open_db(name, shrink ? TRUE : FALSE, cache, wflags);
	long i;
	char buf[1024];
	datum key;
	long cpage = 0 == cache ? 64 : cache;

	printf("Starting read test (%ld item%s), cache=%ld page%s...\n",
		count, plural(count), cpage, plural(cpage));

	key.dsize = large_keys ? sizeof buf : NORMAL_KEY_LEN;
	key.dptr = buf;

	for (i = 0; i < count; i++) {
		datum val;

		if (progress && 0 == i % 500)
			show_progress(i, count);

		fill_key(buf, sizeof buf, i);
		val = sdbm_fetch(db, key);
		if (NULL == val.dptr) {
			if (sdbm_error(db))
				oops("read error at item #%ld", i);
			oops("item #%ld not found", i);
		}
	}

	show_done(done);

	sdbm_close(db);
}

static void
exist_db(const char *name, long count, long cache, int wflags, tm_t *done)
{
	DBM *db = open_db(name, shrink ? TRUE : FALSE, cache, wflags);
	long i;
	char buf[1024];
	datum key;
	long cpage = 0 == cache ? 64 : cache;

	printf("Starting existence test (%ld item%s), cache=%ld page%s...\n",
		count, plural(count), cpage, plural(cpage));

	key.dsize = large_keys ? sizeof buf : NORMAL_KEY_LEN;
	key.dptr = buf;

	for (i = 0; i < count; i++) {
		int res;

		if (progress && 0 == i % 500)
			show_progress(i, count);

		fill_key(buf, sizeof buf, i);
		res = sdbm_exists(db, key);
		if (res <= 0) {
			if (sdbm_error(db))
				oops("read error at item #%ld", i);
			oops("item #%ld not found", i);
		}
	}

	show_done(done);

	sdbm_close(db);
}

static void
write_db(const char *name, long count, long cache, int wflags, tm_t *done)
{
	DBM *db = open_db(name, TRUE, cache, wflags);
	long i;
	datum key;
	char buf[1024];
	long cpage = 0 == cache ? 64 : cache;

	printf("Starting %swrite test (%ld item%s), "
		"cache=%ld page%s, %s write...\n",
		(wflags & WR_VOLATILE) ? "volatile " : "",
		count, plural(count), cpage, plural(cpage),
		(wflags & WR_DELAY) ? "delayed" : "immediate");

	key.dsize = large_keys ? sizeof buf : NORMAL_KEY_LEN;
	key.dptr = buf;

	for (i = 0; i < count; i++) {
		datum val;
		char valbuf[1024];

		if (progress && 0 == i % 500)
			show_progress(i, count);

		fill_key(buf, sizeof buf, i);

		val.dptr = key.dptr;
		if (large_values) {
			if (large_keys) {
				val.dsize = key.dsize;
			} else {
				memset(valbuf, 0, sizeof valbuf);
				memcpy(valbuf, key.dptr, NORMAL_KEY_LEN);
				val.dsize = sizeof valbuf;
				val.dptr = valbuf;
			}
		} else {
			val.dsize = NORMAL_KEY_LEN;
		}

		if (-1 == sdbm_store(db, key, val, DBM_REPLACE))
			oops("write error at item #%ld", i);
	}

	show_done(done);

	sdbm_close(db);
}

static void
delete_db(const char *name, long count, long cache, int wflags, tm_t *done)
{
	DBM *db = open_db(name, TRUE, cache, wflags | WR_DELETING);
	long i;
	datum key;
	char buf[1024];
	long cpage = 0 == cache ? 64 : cache;

	printf("Starting %sdelete test (%ld item%s), "
		"cache=%ld page%s, %s write...\n",
		(wflags & WR_VOLATILE) ? "volatile " : "",
		count, plural(count), cpage, plural(cpage),
		(wflags & WR_DELAY) ? "delayed" : "immediate");

	key.dsize = large_keys ? sizeof buf : NORMAL_KEY_LEN;
	key.dptr = buf;

	for (i = 0; i < count; i++) {
		if (progress && 0 == i % 500)
			show_progress(i, count);

		fill_key(buf, sizeof buf, i);
		if (-1 == sdbm_delete(db, key))
			oops("delete error at item #%ld", i);
	}

	show_done(done);

	sdbm_close(db);
}

static void
iter_db(const char *name, long count, long cache, int safe, tm_t *done)
{
	DBM *db = open_db(name, (shrink || safe) ? TRUE : FALSE, cache, 0);
	long i;
	long cpage = 0 == cache ? 64 : cache;
	datum key;

	printf("Starting %siteration test (%ld item%s), cache=%ld page%s...\n",
		safe ? "safe " : "", count, plural(count), cpage, plural(cpage));

	key = safe ? sdbm_firstkey_safe(db) : sdbm_firstkey(db);

	if (sdbm_error(db))
		oops("error fetching first key");

	for (i = 0; key.dptr != NULL && i < count; i++) {
		if (progress && 0 == i % 500)
			show_progress(i, count);

		key = sdbm_nextkey(db);
		if (sdbm_error(db))
			oops("error fetching next key");
	}

	if (i != count)
		oops("iterated over %ld item%s but requested %ld", i, plural(i), count);

	show_done(done);

	sdbm_close(db);
}

static void
timeit(void (*f)(const char *, long, long, int, tm_t *),
	const char *name, long count,
	long cache, bool chrono, int wflags, const char *what)
{
	tm_t start, end, done;

	if (randomize)
		rand31_set_seed(rseed);	/* Repeatable sequence for all tests */

	tm_now_exact(&start);
	(*f)(name, count, cache, wflags, &done);
	tm_now_exact(&end);

	if (chrono) {
		double elapsed = tm_elapsed_f(&end, &start);
		double processing = tm_elapsed_f(&done, &start);
		printf("%s took %g s (%g s processing, %g s closing)\n",
			what, elapsed, processing, elapsed - processing);
	}
}

int
main(int argc, char **argv)
{
	extern int optind;
	extern char *optarg;
	bool wflag = 0, rflag = 0, iflag = 0, tflag = 0, sflag = 0;
	bool eflag = 0, dflag = 0, bflag = 0;
	int wflags = 0;
	int c;
	const char *name;
	long count;
	long cache = 0;

	progstart(argc, argv);

	while ((c = getopt(argc, argv, "bBc:dDeEikKprR:sStTUvVw")) != EOF) {
		switch (c) {
		case 'B':			/* rebuild before testing */
			rebuild++;
			break;
		case 'b':			/* rebuild database test */
			bflag++;
			break;
		case 'c':			/* cache pages */
			cache = atol(optarg);
			break;
		case 'D':			/* enable write delay */
			wflags |= WR_DELAY;
			break;
		case 'd':			/* delete test */
			dflag++;
			break;
		case 'E':			/* empty database on write tests */
			wflags |= WR_EMPTY;
			break;
		case 'e':			/* exists test */
			eflag++;
			break;
		case 'i':			/* iteration test */
			iflag++;
			break;
		case 'k':			/* large keys */
			large_keys++;
			break;
		case 'K':			/* large keys with common head and tail */
			large_keys++;
			common_head_tail++;
			break;
		case 'p':			/* show test progress */
			progress++;
			break;
		case 'r':			/* read test */
			rflag++;
			break;
		case 'R':			/* randomize keys in repeatable way */
			randomize++;
			rseed = atoi(optarg);
			break;
		case 's':			/* safe iteration */
			sflag++;
			iflag++;
			break;
		case 'S':			/* shrink database */
			shrink++;
			break;
		case 't':			/* timing report */
			tflag++;
			break;
		case 'T':			/* thread safe */
			thread_safe++;
			break;
		case 'U':			/* unlink database */
			unlink_db++;
			break;
		case 'v':			/* large values */
			large_values++;
			break;
		case 'V':			/* database is volatile */
			wflags |= WR_VOLATILE;
			break;
		case 'w':			/* write test */
			wflag++;
			break;
		default:
			usage();
			break;
		}
	}

	if ((argc -= optind) < 2)
		usage();

	name = argv[optind];
	count = atoi(argv[optind + 1]);

	if (wflag && (wflags & WR_EMPTY))
		printf("Database will be reset.\n");

	if (wflag && (wflags & WR_VOLATILE))
		printf("Volatile database, write test will not flush all values.\n");

	if (randomize)
		printf("Using random keys with seed 0x%x.\n", rseed);

	if (shrink)
		printf("Database will shrunk before each test.\n");

	if (thread_safe)
		printf("Database handle will be opened in thread-safe mode.\n");

	if (large_keys)
		printf("Will be using large keys%s.\n",
			common_head_tail ? " with zeroed first and last 4 bytes" : "");

	if (large_values)
		printf("Will be using large values.\n");

	if (cache < 0)
		oops("cache must be positive (is %ld)", cache);

	if (count < 0)
		oops("count must be positive (is %ld)", count);

	if (bflag)
		timeit(rebuild_db, name, count, cache, tflag, wflags, "rebuild test");

	if (wflag)
		timeit(write_db, name, count, cache, tflag, wflags, "write test");

	if (rflag)
		timeit(read_db, name, count, cache, tflag, 0, "read test");

	if (iflag)
		timeit(iter_db, name, count, cache, tflag, sflag, "iteration test");

	if (eflag)
		timeit(exist_db, name, count, cache, tflag, 0, "existence test");

	if (dflag)
		timeit(delete_db, name, count, cache, tflag, wflags, "delete test");

	if (unlink_db) {
		printf("Unlinking database\n");
		unlink_database(name);
	}

	return 0;
}

