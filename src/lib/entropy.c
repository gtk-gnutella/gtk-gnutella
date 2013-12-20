/*
 * Copyright (c) 2008 Christian Biere
 * Copyright (c) 2008, 2012 Raphael Manfredi
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
 * Entropy collection.
 *
 * The aim is to produce random bits by probing the environment and combining
 * the information collected with a good hash function (SHA-1 here) to create
 * sufficient diffusion.
 *
 * The entropy collected here is meant to be as unique as possible, even
 * when called multiple times (with the same items being probed), so that
 * more than 160 bits of randomness can be collected.  Ensuring a good initial
 * random seed is critical when generating unique IDs, such as a servent GUID
 * or a DHT identifier.
 *
 * In order to do that, a simple pseudo-random number generation (PRNG) engine
 * is used to vary the order with which each source of "randomness" is probed.
 * An history of the collected entropy is also kept through successive merging
 * of newly collected bits with previously collected ones.
 *
 * The weakness of our simple PRNG engine is somewhat offset by having its
 * values combined with collected entropy, as soon as we have issued a first
 * batch at collecting the initial 160 bits of randomness.  What is important
 * is that our internal array shuffling be as uniformly random as possible.
 *
 * Entropy is mostly collected at the beginning to initialize some random
 * values and set the initial state of a much stronger PRNG engine: ARC4.
 * The application code should therefore rely on arc4random() and companion
 * routines from the ARC4 API to get its random numbers.
 *
 * @author Christian Biere
 * @date 2008
 * @author Raphael Manfredi
 * @date 2008, 2012
 */

#include "common.h"

#ifdef I_PWD
#include <pwd.h>				/* For getpwuid() and struct passwd */
#endif

#include "entropy.h"

#include "bigint.h"
#include "compat_misc.h"
#include "compat_usleep.h"
#include "endian.h"
#include "getgateway.h"
#include "gethomedir.h"
#include "host_addr.h"
#include "log.h"
#include "mempcpy.h"
#include "misc.h"
#include "pslist.h"
#include "rand31.h"
#include "sha1.h"
#include "shuffle.h"
#include "spinlock.h"
#include "stringify.h"
#include "thread.h"
#include "tm.h"
#include "unsigned.h"
#include "vmm.h"				/* For vmm_trap_page() */

#include "override.h"			/* Must be the last header included */

/**
 * Maximum amount of items we can randomly shuffle.
 *
 * We're using a 31-bit random number generator, so we can't safely
 * permute randomly arrays with more than 12 items: the number of
 * combinations are 12!, which is smaller than 2^31, but 13! is greater
 * so our internal state for the PRNG cannot hold enough values to possibly
 * lead to an unbiased shuffling.
 */
#define RANDOM_SHUFFLE_MAX	12		/* 12! = 479001600, less than 2^29 */

typedef void (*entropy_cb_t)(SHA1Context *ctx);

/**
 * Buffer where we keep track of previously generated randomness.
 */
static sha1_t entropy_previous;
static spinlock_t entropy_previous_slk = SPINLOCK_INIT;

#define ENTROPY_PREV_LOCK		spinlock_hidden(&entropy_previous_slk)
#define ENTROPY_PREV_UNLOCK		spinunlock_hidden(&entropy_previous_slk)

static void entropy_seed(void);

static void
sha1_feed_ulong(SHA1Context *ctx, unsigned long value)
{
	SHA1Input(ctx, &value, sizeof value);
}

static void
sha1_feed_double(SHA1Context *ctx, double value)
{
	SHA1Input(ctx, &value, sizeof value);
}

static void
sha1_feed_pointer(SHA1Context *ctx, const void *p)
{
	SHA1Input(ctx, &p, sizeof p);
}

static void
sha1_feed_string(SHA1Context *ctx, const char *s)
{
	if (s) {
		SHA1Input(ctx, s, strlen(s));
	}
}

static void
sha1_feed_stat(SHA1Context *ctx, const char *path)
{
	filestat_t buf;

	if (-1 != stat(path, &buf)) {
		SHA1Input(ctx, &buf, sizeof buf);
	} else {
		sha1_feed_string(ctx, path);
		sha1_feed_ulong(ctx, errno);
	}
}

static void
sha1_feed_fstat(SHA1Context *ctx, int fd)
{
	filestat_t buf;

	if (-1 != fstat(fd, &buf)) {
		SHA1Input(ctx, &buf, sizeof buf);
	} else {
		sha1_feed_ulong(ctx, fd);
		sha1_feed_ulong(ctx, errno);
	}
}

/**
 * Create a small but unpredictable delay in the process execution.
 */
void
entropy_delay(void)
{
	thread_yield();
}

/**
 * Add entropy from previous calls.
 */
static G_GNUC_COLD void
entropy_merge(sha1_t *digest)
{
	bigint_t older, newer;

	/*
	 * These big integers operate on the buffer space from ``digest'' and
	 * ``entropy_previous'' directly.
	 */

	ENTROPY_PREV_LOCK;

	bigint_use(&older, &entropy_previous, SHA1_RAW_SIZE);
	bigint_use(&newer, digest, SHA1_RAW_SIZE);
	bigint_add(&newer, &older);
	bigint_copy(&older, &newer);

	ENTROPY_PREV_UNLOCK;
}

/**
 * Minimal pseudo-random number generation, combining a simple PRNG with
 * past-collected entropy.
 *
 * @note
 * This routine MUST NOT be used directly by applications, as it is only
 * meant to be used in entropy_array_shuffle() for internal shuffling purposes
 * and in other parts of the entropy collection process where we need a random
 * number but have not finished collecting entropy yet.
 * It is only exported to be exercised in the random-test program.
 *
 * @return a 31-bit random number.
 */
uint32
entropy_rand31(void)
{
	static size_t offset;
	static bool seeded;
	int result;
	uint32 v, n;
	void *p;

	result = rand31();

	/*
	 * Combine with previously generated entropy to create even better
	 * randomness.  That previous entropy is refreshed each time a new
	 * entropy collection cycle is completed, by calling entropy_merge().
	 */

	ENTROPY_PREV_LOCK;

	if G_UNLIKELY(!seeded) {
		seeded = TRUE;
		entropy_seed();
	}

	/*
	 * Loop over the five 32-bit words, interpreted in a big-endian way
	 * and merge bits via XOR.
	 */

	v = peek_be32(ptr_add_offset(&entropy_previous, offset));
	result += v;
	offset = (offset + 4) % sizeof entropy_previous;

	/*
	 * Update the next entry as well, to have an ever-changing pool of
	 * randomness to alter the weak rand31().  Note that we avoid including
	 * the output of rand31() here, we just use existing entropy bits.
	 */

	p = ptr_add_offset(&entropy_previous, offset);	/* Next entry */
	n = peek_be32(p);
	poke_be32(p, (n * 101) ^ UINT32_SWAP(v));		/* 101 is prime */

	ENTROPY_PREV_UNLOCK;

	return result & RAND31_MASK;
}

/**
 * Shuffle array in-place.
 */
static void
entropy_array_shuffle(void *ary, size_t len, size_t elem_size)
{
	g_assert(ary != NULL);
	g_assert(size_is_non_negative(len));
	g_assert(size_is_positive(elem_size));

	if (len > RANDOM_SHUFFLE_MAX)
		s_carp("%s: cannot shuffle %zu items without bias", G_STRFUNC, len);

	shuffle_with(entropy_rand31, ary, len, elem_size);
}

/**
 * Collect entropy by randomly executing the callbacks given in the array.
 */
static void
entropy_array_cb_collect(SHA1Context *ctx, entropy_cb_t *ary, size_t len)
{
	size_t i;

	g_assert(ctx != NULL);
	g_assert(ary != NULL);
	g_assert(size_is_non_negative(len));

	entropy_array_shuffle(ary, len, sizeof ary[0]);

	for (i = 0; i < len; i++) {
		(*ary[i])(ctx);
	}
}

enum entropy_data {
	ENTROPY_ULONG,
	ENTROPY_STRING,
	ENTROPY_STAT,
	ENTROPY_FSTAT,
	ENTROPY_DOUBLE,
	ENTROPY_POINTER,
};

/**
 * Collect entropy by randomly feeding values from array.
 */
static void
entropy_array_data_collect(SHA1Context *ctx,
	enum entropy_data data, void *ary, size_t len, size_t elem_size)
{
	size_t i;
	void *p;

	g_assert(ctx != NULL);
	g_assert(ary != NULL);
	g_assert(size_is_non_negative(len));
	g_assert(size_is_positive(elem_size));

	entropy_array_shuffle(ary, len, elem_size);

	for (i = 0, p = ary; i < len; i++, p = ptr_add_offset(p, elem_size)) {
		switch (data) {
		case ENTROPY_ULONG:
			sha1_feed_ulong(ctx, *(unsigned long *) p);
			break;
		case ENTROPY_STRING:
			sha1_feed_string(ctx, *(char **) p);
			break;
		case ENTROPY_STAT:
			sha1_feed_stat(ctx, *(char **) p);
			break;
		case ENTROPY_FSTAT:
			sha1_feed_fstat(ctx, *(int *) p);
			break;
		case ENTROPY_DOUBLE:
			sha1_feed_double(ctx, *(double *) p);
			break;
		case ENTROPY_POINTER:
			sha1_feed_pointer(ctx, *(void **) p);
			break;
		}
	}
}

/**
 * Collect entropy by randomly feeding unsigned long values from array.
 */
static void
entropy_array_ulong_collect(SHA1Context *ctx, unsigned long *ary, size_t len)
{
	entropy_array_data_collect(ctx, ENTROPY_ULONG, ary, len, sizeof ary[0]);
}

/**
 * Collect entropy by randomly feeding strings from array.
 */
static void
entropy_array_string_collect(SHA1Context *ctx, const char **ary, size_t len)
{
	entropy_array_data_collect(ctx, ENTROPY_STRING, ary, len, sizeof ary[0]);
}

/**
 * Collect entropy by randomly feeding stat() info from paths in array.
 */
static void
entropy_array_stat_collect(SHA1Context *ctx, const char **ary, size_t len)
{
	entropy_array_data_collect(ctx, ENTROPY_STAT, ary, len, sizeof ary[0]);
}

/**
 * Collect entropy by randomly feeding fstat() info from file descriptors.
 */
static void
entropy_array_fstat_collect(SHA1Context *ctx, int *ary, size_t len)
{
	entropy_array_data_collect(ctx, ENTROPY_FSTAT, ary, len, sizeof ary[0]);
}

/**
 * Collect entropy by randomly feeding double values from array.
 */
static void
entropy_array_double_collect(SHA1Context *ctx, double *ary, size_t len)
{
	entropy_array_data_collect(ctx, ENTROPY_DOUBLE, ary, len, sizeof ary[0]);
}

/**
 * Collect entropy by randomly feeding pointers from array.
 */
static void
entropy_array_pointer_collect(SHA1Context *ctx, void **ary, size_t len)
{
	entropy_array_data_collect(ctx, ENTROPY_POINTER, ary, len, sizeof ary[0]);
}

/**
 * Collect hopefully random bytes.
 */
static void
entropy_collect_randomness(SHA1Context *ctx)
{
#ifdef MINGW32
	{
		uint8 data[128];
		if (0 == mingw_random_bytes(data, sizeof data)) {
			g_warning("unable to generate random bytes: %m");
		} else {
			SHA1Input(ctx, data, sizeof data);
		}
	}
#else	/* !MINGW32 */
	{
		filestat_t buf;
		FILE *f = NULL;
		bool is_pipe = TRUE;

		/*
		 * If we have a /dev/urandom character device, use it.
		 * Otherwise, launch ps and grab its output.
		 */

		if (-1 != stat("/dev/urandom", &buf) && S_ISCHR(buf.st_mode)) {
			f = fopen("/dev/urandom", "r");
			is_pipe = FALSE;
			SHA1Input(ctx, &buf, sizeof buf);
		} else if (-1 != access("/bin/ps", X_OK)) {
			f = popen("/bin/ps -ef", "r");
		} else if (-1 != access("/usr/bin/ps", X_OK)) {
			f = popen("/usr/bin/ps -ef", "r");
		} else if (-1 != access("/usr/ucb/ps", X_OK)) {
			f = popen("/usr/ucb/ps aux", "r");
		}

		if (f == NULL)
			g_warning("was unable to %s on your system",
				is_pipe ? "find the ps command" : "open /dev/urandom");
		else {
			/*
			 * Compute the SHA1 of the output (either ps or /dev/urandom).
			 */

			for (;;) {
				uint8 data[1024];
				size_t r, len = sizeof(data);

				if (is_pipe)
					len = MIN(128, len);	/* 128 is probably magic */

				r = fread(data, 1, len, f);
				if (r > 0)
					SHA1Input(ctx, data, r);
				if (r < len || !is_pipe)	/* Read once from /dev/urandom */
					break;
			}

			if (is_pipe)
				pclose(f);
			else
				fclose(f);
		}
	}
#endif	/* MINGW32 */
}

/**
 * Collect user ID information.
 */
static void
entropy_collect_user_id(SHA1Context *ctx)
{
	unsigned long id[2];

#ifdef HAS_GETUID
	id[0] = getuid();
	id[1] = getgid();
#else
	id[0] = entropy_rand31();
	id[1] = entropy_rand31();
#endif	/* HAS_GETUID */

	entropy_array_ulong_collect(ctx, id, G_N_ELEMENTS(id));
}

/**
 * Collect process ID information
 */
static void
entropy_collect_process_id(SHA1Context *ctx)
{
	unsigned long id[2];

#ifdef HAS_GETPPID
	id[0] = getppid();
#else
	id[0] = entropy_rand31();
#endif	/* HAS_GETPPID */
	id[1] = getpid();

	entropy_array_ulong_collect(ctx, id, G_N_ELEMENTS(id));
}

/**
 * Collect compile-time information.
 */
static void
entropy_collect_compile_time(SHA1Context *ctx)
{
	const char *str[2];

	str[0] = __DATE__;
	str[1] = __TIME__;

	entropy_array_string_collect(ctx, str, G_N_ELEMENTS(str));
}

/**
 * Collect user information.
 */
static void
entropy_collect_user(SHA1Context *ctx)
{
	const char *str[3];

	str[0] = gethomedir();

#if GLIB_CHECK_VERSION(2,6,0)
	/*
	 * These functions cannot be used with an unpatched GLib 1.2 on some
	 * systems as they trigger a bug in GLib causing a crash.  On Darwin
	 * there's still a problem before GLib 2.6 due to a bug in Darwin though.
	 */

	str[1] = g_get_user_name();
	str[2] = g_get_real_name();
	entropy_array_string_collect(ctx, str, G_N_ELEMENTS(str));
#else
	{
		char user[UINT32_DEC_BUFLEN];
		char real[UINT32_DEC_BUFLEN];

		uint32_to_string_buf(entropy_rand31(), user, sizeof user);
		uint32_to_string_buf(entropy_rand31(), real, sizeof real);
		str[1] = user;
		str[2] = real;
		entropy_array_string_collect(ctx, str, G_N_ELEMENTS(str));
	}
#endif	/* GLib >= 2.0 */
}

/**
 * Collect login information.
 */
static void
entropy_collect_login(SHA1Context *ctx)
{
#ifdef HAS_GETLOGIN
	{
		const char *name = getlogin();
		sha1_feed_string(ctx, name);
		sha1_feed_pointer(ctx, name);	/* name points to static data */
	}
#else
	sha1_feed_ulong(ctx, entropy_rand31());
#endif	/* HAS_GETLOGIN */
}

/**
 * Collect information from /etc/passwd.
 */
static void
entropy_collect_pw(SHA1Context *ctx)
{
#ifdef HAS_GETUID
	{
		const struct passwd *pp = getpwuid(getuid());

		sha1_feed_pointer(ctx, pp);	/* pp points to static data */
		if (pp != NULL) {
			SHA1Input(ctx, pp, sizeof *pp);
		} else {
			sha1_feed_ulong(ctx, errno);
		}
	}
#else
	sha1_feed_ulong(ctx, entropy_rand31());
#endif	/* HAS_GETUID */
}

/**
 * Collect information from file system.
 */
static void
entropy_collect_filesystem(SHA1Context *ctx)
{
	const char *path[RANDOM_SHUFFLE_MAX];
	size_t i;

	i = 0;
	path[i++] = gethomedir();
	path[i++] = ".";
	path[i++] = "..";
	path[i++] = "/";

	g_assert(i <= G_N_ELEMENTS(path));

	entropy_array_stat_collect(ctx, path, i);

	i = 0;

	if (is_running_on_mingw()) {
		path[i++] = "C:/";
		path[i++] = mingw_get_admin_tools_path();
		path[i++] = mingw_get_common_appdata_path();
		path[i++] = mingw_get_common_docs_path();
		path[i++] = mingw_get_cookies_path();
		path[i++] = mingw_get_fonts_path();
		path[i++] = mingw_get_history_path();

		g_assert(i <= G_N_ELEMENTS(path));

		entropy_array_stat_collect(ctx, path, i);

		i = 0;
		path[i++] = mingw_get_home_path();
		path[i++] = mingw_get_internet_cache_path();
		path[i++] = mingw_get_mypictures_path();
		path[i++] = mingw_get_personal_path();
		path[i++] = mingw_get_program_files_path();
		path[i++] = mingw_get_startup_path();
		path[i++] = mingw_get_system_path();
		path[i++] = mingw_get_windows_path();

		g_assert(i <= G_N_ELEMENTS(path));

		entropy_array_stat_collect(ctx, path, i);
	} else {
		path[i++] = "/bin";
		path[i++] = "/boot";
		path[i++] = "/dev";
		path[i++] = "/etc";
		path[i++] = "/home";
		path[i++] = "/lib";
		path[i++] = "/mnt";
		path[i++] = "/opt";

		g_assert(i <= G_N_ELEMENTS(path));

		entropy_array_stat_collect(ctx, path, i);

		i = 0;
		path[i++] = "/proc";
		path[i++] = "/root";
		path[i++] = "/sbin";
		path[i++] = "/sys";
		path[i++] = "/tmp";
		path[i++] = "/usr";
		path[i++] = "/var";

		g_assert(i <= G_N_ELEMENTS(path));

		entropy_array_stat_collect(ctx, path, i);
	}
}

/**
 * Collect entropy from standard file descriptors.
 */
static void
entropy_collect_stdio(SHA1Context *ctx)
{
	int fd[3];

	fd[0] = STDIN_FILENO;
	fd[1] = STDOUT_FILENO;
	fd[2] = STDERR_FILENO;

	entropy_array_fstat_collect(ctx, fd, G_N_ELEMENTS(fd));
}

/**
 * Collect entropy from available space on filesystem.
 */
static void
entropy_collect_free_space(SHA1Context *ctx)
{
	double fs[3];

	fs[0] = fs_free_space_pct(gethomedir());
	fs[1] = fs_free_space_pct("/");
	fs[2] = fs_free_space_pct(".");

	entropy_array_double_collect(ctx, fs, G_N_ELEMENTS(fs));
}

/**
 * Collect entropy from used CPU time.
 */
static void
entropy_collect_usage(SHA1Context *ctx)
{
#ifdef HAS_GETRUSAGE
	{
		struct rusage usage;

		if (-1 != getrusage(RUSAGE_SELF, &usage)) {
			SHA1Input(ctx, &usage, sizeof usage);
		} else {
			sha1_feed_ulong(ctx, errno);
		}
	}
#else
	sha1_feed_ulong(ctx, entropy_rand31());
#endif	/* HAS_GETRUSAGE */
}

/**
 * Collect entropy from system name.
 */
static void
entropy_collect_uname(SHA1Context *ctx)
{
#ifdef HAS_UNAME
	{
		struct utsname un;
		
		if (-1 != uname(&un)) {
			SHA1Input(ctx, &un, sizeof un);
		} else {
			sha1_feed_ulong(ctx, errno);
		}
	}
#else
	sha1_feed_ulong(ctx, entropy_rand31());
#endif	/* HAS_UNAME */
}

/**
 * Collect entropy from terminal line name.
 */
static void
entropy_collect_ttyname(SHA1Context *ctx)
{
#ifdef HAS_TTYNAME
	sha1_feed_string(ctx, ttyname(STDIN_FILENO));
#else
	sha1_feed_ulong(ctx, entropy_rand31());
#endif	/* HAS_TTYNAME */
}

/**
 * Collect entropy from amount of files we can open.
 */
static void
entropy_collect_file_amount(SHA1Context *ctx)
{
	sha1_feed_ulong(ctx, getdtablesize());
}

/**
 * Collect entropy from constant pointers.
 */
static void
entropy_collect_pointers(SHA1Context *ctx)
{
	void *ptr[6];

	ptr[0] = ctx;
	ptr[1] = cast_func_to_pointer(&entropy_collect);
	ptr[2] = cast_func_to_pointer(&entropy_collect_pointers);
	ptr[3] = cast_func_to_pointer(&exit);	/* libc */
	ptr[4] = &errno;
	ptr[5] = &ptr;

	entropy_array_pointer_collect(ctx, ptr, G_N_ELEMENTS(ptr));
}

/**
 * Collect entropy based on current CPU state.
 */
static void
entropy_collect_cpu(SHA1Context *ctx)
{
	jmp_buf env;

	/*
	 * Add local CPU state noise.
	 */

	ZERO(&env);			/* Avoid uninitialized memory reads */

	if (setjmp(env)) {
		/* We will never longjmp() back here */
		g_assert_not_reached();
	}
	SHA1Input(ctx, env, sizeof env);	/* "env" is an array */
}

/** 
 * Collect entropy from environment.
 */
static void
entropy_collect_environ(SHA1Context *ctx)
{
	extern char **environ;
	size_t i, j;
	const char *str[RANDOM_SHUFFLE_MAX];

	for (i = 0, j = 0; NULL != environ[i]; i++) {
		str[j++] = environ[i];
		if (RANDOM_SHUFFLE_MAX == j) {
			entropy_array_string_collect(ctx, str, RANDOM_SHUFFLE_MAX);
			j = 0;
		}
	}
	if (j != 0)
		entropy_array_string_collect(ctx, str, j);
	sha1_feed_ulong(ctx, i);
}

/**
 * Collect a few pseudo-random numbers.
 */
static void
entropy_collect_rand31(SHA1Context *ctx)
{
	int i;

	for (i = 0; i < 16; i++) {
		unsigned long p = entropy_rand31();
		unsigned long q = entropy_rand31();
		sha1_feed_ulong(ctx, p + q);
		sha1_feed_ulong(ctx, p - q);
	}
}

/**
 * Collect entropy from current time.
 */
static void
entropy_collect_time(SHA1Context *ctx)
{
	tm_t now;

	tm_now_exact(&now);
	SHA1Input(ctx, &now, sizeof now);
}

/**
 * Collect entropy from current thread.
 */
static void
entropy_collect_thread(SHA1Context *ctx)
{
	thread_t th = thread_current();

	SHA1Input(ctx, &th, sizeof th);
}

/**
 * Collect entropy from current IP gateway.
 */
static void
entropy_collect_gateway(SHA1Context *ctx)
{
	host_addr_t addr;

	ZERO(&addr);

	if (-1 == getgateway(&addr))
		sha1_feed_ulong(ctx, errno);

	SHA1Input(ctx, &addr, sizeof addr);
}

/**
 * Collect entropy from host.
 *
 * This uses the host's name and its IP addresses.
 */
static void
entropy_collect_host(SHA1Context *ctx)
{
	const char *name;
	pslist_t *hosts, *sl;

	name = local_hostname();
	sha1_feed_string(ctx, name);

	hosts = name_to_host_addr(name, NET_TYPE_NONE);

	PSLIST_FOREACH(hosts, sl) {
		host_addr_t *addr = sl->data;
		struct packed_host_addr packed = host_addr_pack(*addr);

		SHA1Input(ctx, &packed, packed_host_addr_size(packed));
	}

	host_addr_free_list(&hosts);
}

/**
 * Collect entropy from VMM information.
 */
static void
entropy_collect_vmm(SHA1Context *ctx)
{
	sha1_feed_pointer(ctx, vmm_trap_page());
}

/**
 * Collect entropy based on CPU time used and scheduling delays.
 */
static void
entropy_collect_timing(SHA1Context *ctx, bool slow)
{
	double v[4];
	tm_t before, after;

	tm_now_exact(&before);

	v[0] = tm_cputime(&v[1], &v[2]);

	if (slow) {
		compat_usleep_nocancel(2000);	/* 2 ms */
	} else {
		entropy_delay();			/* create small, unpredictable delay */
	}

	tm_now_exact(&after);
	v[3] = tm_elapsed_f(&after, &before);

	entropy_array_double_collect(ctx, v, G_N_ELEMENTS(v));
}

/**
 * Collect entropy and fill supplied SHA1 buffer with 160 random bits.
 *
 * @param digest			where generated random 160 bits are output
 * @param can_malloc		if FALSE, make sure we never malloc()
 * @param slow				whether we can sleep for 2 ms
 *
 * @attention
 * This is a slow operation, and the routine can even sleep for 2 ms, so it
 * must be called only when a truly random seed is required, ideally only
 * during initialization.
 */
G_GNUC_COLD void
entropy_collect_internal(sha1_t *digest, bool can_malloc, bool slow)
{
	static tm_t last;
	SHA1Context ctx;
	tm_t start, end;
	entropy_cb_t fn[RANDOM_SHUFFLE_MAX];
	size_t i;

	/*
	 * Get random entropy from the system.
	 */

	tm_now_exact(&start);

	SHA1Reset(&ctx);
	SHA1Input(&ctx, &start, sizeof start);

	if (can_malloc) {
		i = 0;
		fn[i++] = entropy_collect_randomness;
		fn[i++] = entropy_collect_user;
		fn[i++] = entropy_collect_login;
		fn[i++] = entropy_collect_pw;
		fn[i++] = entropy_collect_filesystem;
		fn[i++] = entropy_collect_free_space;
		fn[i++] = entropy_collect_ttyname;
		fn[i++] = entropy_collect_vmm;
		fn[i++] = entropy_collect_thread;
		fn[i++] = entropy_collect_gateway;
		fn[i++] = entropy_collect_host;

		g_assert(i <= G_N_ELEMENTS(fn));

		entropy_array_cb_collect(&ctx, fn, i);
	}

	i = 0;

	fn[i++] = entropy_collect_cpu;
	fn[i++] = entropy_collect_environ;
	fn[i++] = entropy_collect_user_id;
	fn[i++] = entropy_collect_process_id;
	fn[i++] = entropy_collect_compile_time;
	fn[i++] = entropy_collect_stdio;
	fn[i++] = entropy_collect_usage;
	fn[i++] = entropy_collect_uname;
	fn[i++] = entropy_collect_pointers;
	fn[i++] = entropy_collect_file_amount;
	fn[i++] = entropy_collect_rand31;
	fn[i++] = entropy_collect_time;

	g_assert(i <= G_N_ELEMENTS(fn));

	entropy_array_cb_collect(&ctx, fn, i);

	/*
	 * Finish by collecting various information that cannot be easily
	 * dispatched randomly due to parameters or conditions.
	 */

	entropy_collect_timing(&ctx, slow);

	{
		double v[2];

		v[0] = tm_elapsed_f(&start, &last);
		last = start;		/* struct copy */

		tm_now_exact(&end);
		SHA1Input(&ctx, &end, sizeof end);
		v[1] = tm_elapsed_f(&end, &start);

		entropy_array_double_collect(&ctx, v, G_N_ELEMENTS(v));
	}

	/*
	 * Done, finalize SHA1 computation into supplied digest buffer.
	 */

	SHA1Result(&ctx, digest);

	/*
	 * Merge entropy from all the previous calls to make this as unique
	 * a random bitstream as possible.
	 */

	entropy_merge(digest);
}

/**
 * Seed the ``entropy_previous'' variable, once.
 *
 * We're collecting changing and contextual data, always in the same order,
 * to be able to compute an initial 160-bit value, which is better than the
 * default zero value.
 */
static G_GNUC_COLD void
entropy_seed(void)
{
	extern char **environ;
	char garbage[64];		/* Left uninitialized on purpose */
	SHA1Context ctx;
	double cpu, usr, sys;
	size_t i;

	/*
	 * This routine must not allocate any memory because it will be called
	 * very early during initialization.
	 */

	SHA1Reset(&ctx);
	SHA1Input(&ctx, &ctx, sizeof ctx);

	sha1_feed_ulong(&ctx, time(NULL));
	sha1_feed_ulong(&ctx, getpid());
	SHA1Input(&ctx, &ctx, sizeof ctx);

	entropy_collect_cpu(&ctx);
	SHA1Input(&ctx, &ctx, sizeof ctx);

	sha1_feed_fstat(&ctx, STDIN_FILENO);
	sha1_feed_fstat(&ctx, STDOUT_FILENO);
	sha1_feed_fstat(&ctx, STDERR_FILENO);
	SHA1Input(&ctx, &ctx, sizeof ctx);

	for (i = 0; NULL != environ[i]; i++) {
		sha1_feed_string(&ctx, environ[i]);
	}
	sha1_feed_ulong(&ctx, getpid());
	SHA1Input(&ctx, &ctx, sizeof ctx);

	sha1_feed_pointer(&ctx, environ);
	sha1_feed_pointer(&ctx, &cpu);

	sha1_feed_stat(&ctx, ".");
	sha1_feed_stat(&ctx, "..");
	sha1_feed_stat(&ctx, "/");

	SHA1Input(&ctx, garbage, sizeof garbage);

	cpu = tm_cputime(&usr, &sys);
	sha1_feed_double(&ctx, cpu);
	sha1_feed_double(&ctx, usr);
	sha1_feed_double(&ctx, sys);

	SHA1Result(&ctx, &entropy_previous);
}

/**
 * Fold extra entropy bytes in place, putting result in the trailing n bytes.
 *
 * @return pointer to the start of the folded trailing n bytes in the digest.
 */
static void *
entropy_fold(sha1_t *digest, size_t n)
{
	sha1_t result;
	bigint_t h, v;

	g_assert(size_is_non_negative(n));

	if G_UNLIKELY(n >= SHA1_RAW_SIZE)
		return digest;

	bigint_use(&v, &result, SHA1_RAW_SIZE);
	bigint_use(&h, digest, SHA1_RAW_SIZE);

	bigint_zero(&v);

	while (!bigint_is_zero(&h)) {
		bigint_add(&v, &h);
		bigint_rshift_bytes(&h, n);
	}

	bigint_copy(&h, &v);

	return &digest->data[SHA1_RAW_SIZE - n];
}

/**
 * Collect entropy and fill supplied SHA1 buffer with 160 random bits.
 *
 * It should be called only when a truly random seed is required, ideally only
 * during initialization.
 *
 * @attention
 * This is a slow operation, and the routine will even sleep for 2 ms the
 * first time it is invoked.
 */
G_GNUC_COLD void
entropy_collect(sha1_t *digest)
{
	static bool done;

	misc_init();		/* Required since we have to call parse_uint32() */

	entropy_collect_internal(digest, TRUE, !done);
	done = TRUE;
}

/**
 * Collect minimal entropy, making sure no memory is allocated, and fill
 * supplied SHA1 buffer with 160 random bits.
 *
 * @attention
 * This is a slow operation, so it must be called only when a truly random
 * seed is required.
 */
G_GNUC_COLD void
entropy_minimal_collect(sha1_t *digest)
{
	entropy_collect_internal(digest, FALSE, FALSE);
}

/**
 * Random number generation based on entropy collection (without any memory
 * allocation).
 *
 * This is a strong random number generator, but it is very slow and should
 * be reserved to low-level initializations, before the ARC4 random number
 * has been properly seeded.
 *
 * @return 32-bit random number.
 */
uint32
entropy_random(void)
{
	static sha1_t digest;
	static void *p = &digest;
	static spinlock_t entropy_random_slk = SPINLOCK_INIT;
	uint32 rnd;

	/*
	 * Collect entropy again once we have exhausted reading from the pool.
	 */

	spinlock_hidden(&entropy_random_slk);

	if G_UNLIKELY(&digest == p) {
		sha1_t tmp;

		spinunlock_hidden(&entropy_random_slk);

		entropy_minimal_collect(&tmp);

		spinlock_hidden(&entropy_random_slk);

		digest = tmp;			/* struct copy */
		p = ptr_add_offset(&digest, sizeof digest);
	}

	/*
	 * Get the next 32-bit value from the pool, moving right to left.
	 */

	p = ptr_add_offset(p, -4);
	rnd = peek_be32(p);

	spinunlock_hidden(&entropy_random_slk);

	return rnd;
}

/**
 * Fill supplied buffer with random entropy bytes.
 *
 * Memory allocation may happen during this call.
 *
 * @param buffer	buffer to fill
 * @param len		buffer length, in bytes
 */
void
entropy_fill(void *buffer, size_t len)
{
	size_t complete, partial, i;
	void *p = buffer;

	g_assert(buffer != NULL);
	g_assert(size_is_non_negative(len));

	complete = len / SHA1_RAW_SIZE;
	partial = len - complete * SHA1_RAW_SIZE;

	for (i = 0; i < complete; i++) {
		sha1_t digest;

		entropy_collect(&digest);
		p = mempcpy(p, &digest, SHA1_RAW_SIZE);
	}

	if (partial != 0) {
		sha1_t digest;
		void *folded;

		entropy_collect(&digest);
		folded = entropy_fold(&digest, partial);
		p = mempcpy(p, folded, partial);
	}

	g_assert(ptr_diff(p, buffer) == len);
}

/* vi: set ts=4 sw=4 cindent: */
