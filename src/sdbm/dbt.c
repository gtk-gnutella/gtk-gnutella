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

#include "sdbm.h"

#include "lib/atomic.h"
#include "lib/log.h"
#include "lib/progname.h"
#include "lib/rand31.h"
#include "lib/random.h"
#include "lib/str.h"
#include "lib/stringify.h"	/* For plural() */
#include "lib/thread.h"
#include "lib/tm.h"

#include "lib/override.h"

extern void oops(char *fmt, ...) G_PRINTF(1, 2);

static bool progress;
static bool shrink, rebuild, thread_safe;
static bool randomize;
static unsigned rseed;
static bool unlink_db;
static bool all_keys;
static bool large_keys, large_values, common_head_tail;
static bool loose_delete;
static bool async_rebuild;
static int async_thread = -1;

#define WR_DELAY	(1 << 0)
#define WR_VOLATILE	(1 << 1)
#define WR_EMPTY	(1 << 2)
#define WR_DELETING	(1 << 3)

static void G_NORETURN
usage(void)
{
	fprintf(stderr,
		"Usage: %s [-abdeiklprstvwyABCDEKSTUVX] [-R seed] [-c pages]\n"
		"       dbname [count]\n"
		"  -a : rebuild the database asynchronously whilst testing\n"
		"  -b : rebuild the database\n"
		"  -c : set LRU cache size\n"
		"  -d : perform delete test\n"
		"  -e : perform existence test\n"
		"  -i : perform iteration test\n"
		"  -k : use large keys\n"
		"  -l : perform loose iteration test (implies -T)\n"
		"  -p : show test progress\n"
		"  -r : perform a read test\n"
		"  -s : perform safe iteration test\n"
		"  -t : show timing results for each test\n"
		"  -v : use large values\n"
		"  -w : perform a write test\n"
		"  -y : show runtime thread stats at the end\n"
		"  -A : traverse all keys when loosely iterating\n"
		"  -B : rebuild the database before testing\n"
		"  -C : count database items\n"
		"  -D : enable LRU cache write delay\n"
		"  -E : empty existing database on write test\n"
		"  -K : use large keys with common head/tail parts\n"
		"  -R : seed for repeatable random key sequence\n"
		"  -S : shrink database before testing\n"
		"  -T : make database handle thread-safe\n"
		"  -U : unlink database at the end\n"
		"  -V : consider database as volatile\n"
		"  -X : delete first \"count\" keys during -l test\n",
		getprogname());
	exit(EXIT_FAILURE);
}

static void *
rebuild_db_async(void *arg)
{
	DBM *db = arg;

	if (-1 == sdbm_rebuild_async(db))
		oops("sdbm_rebuild_async() failed");

	return db;
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

	if (async_rebuild) {
		printf("Launching asynchronous database rebuild.\n");
		sdbm_ref(db);
		async_thread = thread_create(rebuild_db_async, db, THREAD_F_PANIC, 0);
	}

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
		char valbuf[DBM_PBLKSIZ];

		if (progress && 0 == i % 500)
			show_progress(i, count);

		fill_key(buf, sizeof buf, i);

		val.dptr = key.dptr;
		if (large_values) {
			if (large_keys) {
				val.dsize = key.dsize;
			} else {
				ZERO(&valbuf);
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

	if (sdbm_is_thread_safe(db))
		sdbm_lock(db);

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

	if (sdbm_is_thread_safe(db))
		sdbm_unlock(db);

	if (i != count) {
		errno = 0;
		oops("iterated over %ld item%s but requested %ld", i, plural(i), count);
	}

	show_done(done);

	sdbm_close(db);
}

struct loose_iterator_args {
	DBM *db;
	struct sdbm_loose_stats *stats;
	long count;
};

static void
loose_cb(const datum key, const datum value, void *arg)
{
	(void) key;
	(void) value;
	(void) arg;
}

struct loose_cbr_args {
	long count;		/* Amount of items remaining to delete */
};

static bool
loose_cbr(const datum key, const datum value, void *arg)
{
	struct loose_cbr_args *v = arg;

	(void) key;
	(void) value;

	if (v->count != 0) {
		v->count--;
		return TRUE;	/* Delete key/value pair */
	}

	return FALSE;
}

static void *
loose_iterator(void *arg)
{
	struct loose_iterator_args *a = arg;
	int flags = 0;

	if (all_keys)
		flags |= DBM_F_ALLKEYS;

	if (loose_delete) {
		struct loose_cbr_args v;
		v.count = a->count;
		sdbm_loose_foreach_remove_stats(a->db, 0, loose_cbr, &v, a->stats);
	} else {
		sdbm_loose_foreach_stats(a->db, 0, loose_cb, NULL, a->stats);
	}
	sdbm_unref(&a->db);

	return NULL;
}

static void
loose_db(const char *name, long count, long cache, int safe, tm_t *done)
{
	DBM *db = open_db(name, TRUE, cache, 0);
	long cpage = 0 == cache ? 64 : cache;
	int t;
	struct loose_iterator_args args;
	struct sdbm_loose_stats stats;
	char buf[1024];
	ulong nop = 0;
	datum key;

	(void) safe;

	printf("Starting loose %siteration test (%ld item%s), "
		"cache=%ld page%s...\n",
		loose_delete ? "delete " : "",
		count, plural(count), cpage, plural(cpage));

	args.db = sdbm_ref(db);
	args.stats = &stats;
	args.count = count;

	ZERO(&stats);

	t = thread_create(loose_iterator, &args, THREAD_F_PANIC, 0);

	/*
	 * Perturb the iterating thread by doing random NOP updates.
	 */

	key.dsize = large_keys ? sizeof buf : NORMAL_KEY_LEN;
	key.dptr = buf;

	for (;;) {
		thread_info_t info;
		long i;
		datum val;

		if (-1 == thread_get_info(t, &info)) {
			if (ESRCH != errno)
				oops("%s(): cannot get thread info", G_STRFUNC);
		} else if (info.exited)
			break;

		i = random_value(count - 1);
		fill_key(buf, sizeof buf, i);

		/*
		 * fetch + store back must be atomic if we're deleting items.
		 */

		if (loose_delete)
			sdbm_lock(db);

		val = sdbm_fetch(db, key);
		if (NULL != val.dptr) {
			if (-1 == sdbm_store(db, key, val, DBM_REPLACE))
				oops("%s(): cannot rewrite key", G_STRFUNC);
			nop++;
		}

		if (loose_delete)
			sdbm_unlock(db);

		if (progress && 0 == nop % 50) {
			atomic_mb();
			show_progress(stats.items, count);
		}
	}

	if (-1 == thread_join(t, NULL))
		oops("%s(): cannot join with iterating thread", G_STRFUNC);

	show_done(done);

#define SHOW_LONG(f) printf("\t" #f " = %lu\n", (long) stats.f);

	printf("Perturbed iteration by issuing %lu concurrent NOP update%s\n",
		nop, plural(nop));
	printf("Loose iterator statistics (extract):\n");
	SHOW_LONG(pages);
	SHOW_LONG(restarted);
	SHOW_LONG(traversals);
	SHOW_LONG(locked);
	SHOW_LONG(avoided);
	SHOW_LONG(empty);
	SHOW_LONG(items);
	SHOW_LONG(big_keys);
	SHOW_LONG(big_values);

	if (loose_delete) {
		SHOW_LONG(kept);
		SHOW_LONG(deletions);
		SHOW_LONG(deletion_errors);
		SHOW_LONG(deletion_refused);
	}

#undef SHOW_LONG

	sdbm_close(db);
}

static void
count_db(const char *name, long count, long cache, int safe, tm_t *done)
{
	DBM *db = open_db(name, FALSE, 0, 0);
	long items;

	(void) cache;
	(void) count;
	(void) safe;

	printf("Counting items in \"%s\"...\n", name);
	items = sdbm_count(db);
	printf("...has %ld item%s\n", items, plural(items));

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
	bool eflag = 0, dflag = 0, bflag = 0, lflag = 0;
	bool stats = 0, count_items = 0;
	int wflags = 0;
	int c;
	const char *name;
	long count;
	long cache = 0;
	const char options[] = "aAbBc:CdDeEiklKprR:sStTUvVwXy";

	progstart(argc, argv);

	while ((c = getopt(argc, argv, options)) != EOF) {
		switch (c) {
		case 'A':			/* traverse all keys when loosely iterating */
			all_keys++;
			break;
		case 'a':			/* asynchronously rebuild database (implies -T) */
			async_rebuild++;
			thread_safe++;
			break;
		case 'B':			/* rebuild before testing */
			rebuild++;
			break;
		case 'b':			/* rebuild database test */
			bflag++;
			break;
		case 'c':			/* cache pages */
			cache = atol(optarg);
			break;
		case 'C':			/* count items */
			count_items++;
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
		case 'l':			/* loose iteration (implies -T) */
			lflag++;
			thread_safe++;
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
		case 'X':			/* loose deletion requested */
			loose_delete++;
			break;
		case 'y':			/* show thread stats */
			stats++;
			break;
		default:
			usage();
			break;
		}
	}

	if ((argc -= optind) < 1)
		usage();

	name = argv[optind];

	if (1 == argc) {
		DBM *db = sdbm_open(name, O_RDONLY, 0);
		if (NULL == db) {
			printf("No count argument and can't open \"%s\": %s\n",
				name, strerror(errno));
			return 1;
		} else {
			printf("Counting items in \"%s\"...\n", name);
			count = sdbm_count(db);
			sdbm_close(db);
			printf("(found %ld item%s)\n", count, plural(count));
		}
	} else {
		count = atoi(argv[optind + 1]);
	}

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

	if (count_items)
		timeit(count_db, name, count, cache, tflag, 0, "count test");

	if (bflag)
		timeit(rebuild_db, name, count, cache, tflag, wflags, "rebuild test");

	if (wflag)
		timeit(write_db, name, count, cache, tflag, wflags, "write test");

	if (rflag)
		timeit(read_db, name, count, cache, tflag, 0, "read test");

	if (iflag)
		timeit(iter_db, name, count, cache, tflag, sflag, "iteration test");

	if (lflag)
		timeit(loose_db, name, count, cache, tflag, sflag, "loose test");

	if (eflag)
		timeit(exist_db, name, count, cache, tflag, 0, "existence test");

	if (dflag)
		timeit(delete_db, name, count, cache, tflag, wflags, "delete test");

	if (-1 != async_thread) {
		void *result;
		DBM *db;

		printf("Waiting for asynchronous rebuild to finish...\n");
		if (-1 == thread_join(async_thread, &result))
			oops("thread_join() failed");

		db = result;
		printf("Done rebuilding SDBM \"%s\"\n", sdbm_name(db));
		sdbm_unref(&db);
	}

	if (unlink_db) {
		printf("Unlinking database\n");
		unlink_database(name);
	}

	if (stats)
		thread_dump_stats_log(log_agent_stdout_get(), 0);

	return 0;
}

/* vi: set ts=4 sw=4 cindent: */
