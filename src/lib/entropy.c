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
 * Entropy is mostly collected at the beginning to initialize some random
 * values and set the initial state of much stronger PRNG engines: ARC4,
 * WELL, or MT.
 *
 * When AJE (Alea Jacta Est) has been initialized, all entropy retrieval is
 * transparently remapped to the global AJE state.
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

#include "aje.h"
#include "atomic.h"
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
#include "pow2.h"
#include "pslist.h"
#include "rand31.h"
#include "random.h"
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
 * We're using a PRNG with 128 bits of internal context and a period of, at
 * least, 2**125.  To ensure we can reach all the possible permutations of
 * the set, we cannot shuffle more than 33 items since 33! < 2**123 but 34!
 * is greater than the minimum period.
 */
#define RANDOM_SHUFFLE_MAX	33		/* 33! < 2**123 */

typedef void (*entropy_cb_t)(SHA1_context *ctx);

/**
 * Buffer where we keep track of previously generated randomness.
 */
static sha1_t entropy_previous;
static spinlock_t entropy_previous_slk = SPINLOCK_INIT;

#define ENTROPY_PREV_LOCK		spinlock_hidden(&entropy_previous_slk)
#define ENTROPY_PREV_UNLOCK		spinunlock_hidden(&entropy_previous_slk)

/**
 * Context for the entropy_minirand() routine.
 */
static struct entropy_minictx {
	spinlock_t lock;
	uint32 x, y, z, c;
	bool seeded;
} entropy_minictx = {
	SPINLOCK_INIT,
	0, 0, 0, 0,
	FALSE
};
#define ENTROPY_MINICTX_LOCK(c)		spinlock_hidden(&(c)->lock)
#define ENTROPY_MINICTX_UNLOCK(c)	spinunlock_hidden(&(c)->lock)

static void entropy_seed(struct entropy_minictx *c);

static void
sha1_feed_ulong(SHA1_context *ctx, unsigned long value)
{
	SHA1_input(ctx, &value, sizeof value);
}

static void
sha1_feed_double(SHA1_context *ctx, double value)
{
	SHA1_input(ctx, &value, sizeof value);
}

static void
sha1_feed_pointer(SHA1_context *ctx, const void *p)
{
	SHA1_input(ctx, &p, sizeof p);
}

static void
sha1_feed_string(SHA1_context *ctx, const char *s)
{
	if (s) {
		SHA1_input(ctx, s, strlen(s));
	}
}

static void
sha1_feed_stat(SHA1_context *ctx, const char *path)
{
	filestat_t buf;

	if (-1 != stat(path, &buf)) {
		SHA1_input(ctx, &buf, sizeof buf);
	} else {
		sha1_feed_string(ctx, path);
		sha1_feed_ulong(ctx, errno);
	}
}

static void
sha1_feed_fstat(SHA1_context *ctx, int fd)
{
	filestat_t buf;

	if (-1 != fstat(fd, &buf)) {
		SHA1_input(ctx, &buf, sizeof buf);
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

	STATIC_ASSERT(sizeof entropy_previous == SHA1_RAW_SIZE);

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
 * Minimal random number generation, to be used very early in the process
 * initialization when we cannot use entropy_minimal_collect() yet.
 *
 * @note
 * This routine MUST NOT be used directly by applications, as it is only
 * meant to be used in entropy_array_shuffle() for internal shuffling purposes
 * and in other parts of the entropy collection process where we need a random
 * number but have not finished collecting entropy yet.
 * It is only exported to be exercised in the random-test program.
 *
 * @return a 32-bit random number.
 */
uint32
entropy_minirand(void)
{
	uint64 t;
	uint32 r;
	struct entropy_minictx *ctx = &entropy_minictx;

	ENTROPY_MINICTX_LOCK(ctx);

	if G_UNLIKELY(!ctx->seeded) {
		ctx->seeded = TRUE;
		entropy_seed(ctx);
	}

	/*
	 * George Marsaglia's KISS alogorithm, posted in sci.math circa 2003.
	 * The period of this PRNG is more than 2**125, and it keeps 128 bits
	 * of context.
	 */

	ctx->x = 69069 * ctx->x + 12345;
	ctx->y ^= (ctx->y << 13);
	ctx->y ^= (ctx->y >> 17);
	ctx->y ^= (ctx->y << 5);
	t = (uint64) 698769069L * ctx->z + ctx->c;
	ctx->c = t >> 32;
	r = ctx->x + ctx->y + (ctx->z = t);

	ENTROPY_MINICTX_UNLOCK(ctx);

	return r;
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

	shuffle_with(entropy_minirand, ary, len, elem_size);
}

/**
 * Collect entropy by randomly executing the callbacks given in the array.
 */
static void
entropy_array_cb_collect(SHA1_context *ctx, entropy_cb_t *ary, size_t len)
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
entropy_array_data_collect(SHA1_context *ctx,
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
entropy_array_ulong_collect(SHA1_context *ctx, unsigned long *ary, size_t len)
{
	entropy_array_data_collect(ctx, ENTROPY_ULONG, ary, len, sizeof ary[0]);
}

/**
 * Collect entropy by randomly feeding strings from array.
 */
static void
entropy_array_string_collect(SHA1_context *ctx, const char **ary, size_t len)
{
	entropy_array_data_collect(ctx, ENTROPY_STRING, ary, len, sizeof ary[0]);
}

/**
 * Collect entropy by randomly feeding stat() info from paths in array.
 */
static void
entropy_array_stat_collect(SHA1_context *ctx, const char **ary, size_t len)
{
	entropy_array_data_collect(ctx, ENTROPY_STAT, ary, len, sizeof ary[0]);
}

/**
 * Collect entropy by randomly feeding fstat() info from file descriptors.
 */
static void
entropy_array_fstat_collect(SHA1_context *ctx, int *ary, size_t len)
{
	entropy_array_data_collect(ctx, ENTROPY_FSTAT, ary, len, sizeof ary[0]);
}

/**
 * Collect entropy by randomly feeding double values from array.
 */
static void
entropy_array_double_collect(SHA1_context *ctx, double *ary, size_t len)
{
	entropy_array_data_collect(ctx, ENTROPY_DOUBLE, ary, len, sizeof ary[0]);
}

/**
 * Collect entropy by randomly feeding pointers from array.
 */
static void
entropy_array_pointer_collect(SHA1_context *ctx, void **ary, size_t len)
{
	entropy_array_data_collect(ctx, ENTROPY_POINTER, ary, len, sizeof ary[0]);
}

/**
 * Collect hopefully random bytes.
 */
static void
entropy_collect_randomness(SHA1_context *ctx)
{
#ifdef MINGW32
	{
		uint8 data[128];
		if (0 == mingw_random_bytes(data, sizeof data)) {
			s_warning("%s(): unable to generate random bytes: %m", G_STRFUNC);
		} else {
			SHA1_input(ctx, data, sizeof data);
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
			SHA1_input(ctx, &buf, sizeof buf);
		} else if (-1 != access("/bin/ps", X_OK)) {
			f = popen("/bin/ps -ef", "r");
		} else if (-1 != access("/usr/bin/ps", X_OK)) {
			f = popen("/usr/bin/ps -ef", "r");
		} else if (-1 != access("/usr/ucb/ps", X_OK)) {
			f = popen("/usr/ucb/ps aux", "r");
		}

		if (f == NULL) {
			s_warning("%s(): was unable to %s on your system",
				G_STRFUNC,
				is_pipe ? "find the ps command" : "open /dev/urandom");
		} else {
			/*
			 * Compute the SHA1 of the output (either ps or /dev/urandom).
			 */

			for (;;) {
				uint8 data[1024];
				size_t r, len = sizeof(data);

				r = fread(data, 1, len, f);
				if (r > 0)
					SHA1_input(ctx, data, r);
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
entropy_collect_user_id(SHA1_context *ctx)
{
	unsigned long id[2];

#ifdef HAS_GETUID
	id[0] = getuid();
	id[1] = getgid();
#else
	id[0] = entropy_minirand();
	id[1] = entropy_minirand();
#endif	/* HAS_GETUID */

	entropy_array_ulong_collect(ctx, id, G_N_ELEMENTS(id));
}

/**
 * Collect process ID information
 */
static void
entropy_collect_process_id(SHA1_context *ctx)
{
	unsigned long id[2];

#ifdef HAS_GETPPID
	id[0] = getppid();
#else
	id[0] = entropy_minirand();
#endif	/* HAS_GETPPID */
	id[1] = getpid();

	entropy_array_ulong_collect(ctx, id, G_N_ELEMENTS(id));
}

/**
 * Collect compile-time information.
 */
static void
entropy_collect_compile_time(SHA1_context *ctx)
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
entropy_collect_user(SHA1_context *ctx)
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

		uint32_to_string_buf(entropy_minirand(), user, sizeof user);
		uint32_to_string_buf(entropy_minirand(), real, sizeof real);
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
entropy_collect_login(SHA1_context *ctx)
{
#ifdef HAS_GETLOGIN
	{
		const char *name = getlogin();
		sha1_feed_string(ctx, name);
		sha1_feed_pointer(ctx, name);	/* name points to static data */
	}
#else
	sha1_feed_ulong(ctx, entropy_minirand());
#endif	/* HAS_GETLOGIN */
}

/**
 * Collect information from /etc/passwd.
 */
static void
entropy_collect_pw(SHA1_context *ctx)
{
#ifdef HAS_GETUID
	{
		const struct passwd *pp = getpwuid(getuid());

		sha1_feed_pointer(ctx, pp);	/* pp points to static data */
		if (pp != NULL) {
			SHA1_input(ctx, pp, sizeof *pp);
		} else {
			sha1_feed_ulong(ctx, errno);
		}
	}
#else
	sha1_feed_ulong(ctx, entropy_minirand());
#endif	/* HAS_GETUID */
}

/**
 * Collect information from file system.
 */
static void
entropy_collect_filesystem(SHA1_context *ctx)
{
	const char *path[RANDOM_SHUFFLE_MAX];
	size_t i = 0;

	path[i++] = gethomedir();
	path[i++] = ".";
	path[i++] = "..";
	path[i++] = "/";

	if (is_running_on_mingw()) {
		path[i++] = "C:/";
		path[i++] = mingw_get_admin_tools_path();
		path[i++] = mingw_get_common_appdata_path();
		path[i++] = mingw_get_common_docs_path();
		path[i++] = mingw_get_cookies_path();
		path[i++] = mingw_get_fonts_path();
		path[i++] = mingw_get_history_path();
		path[i++] = mingw_get_home_path();
		path[i++] = mingw_get_internet_cache_path();
		path[i++] = mingw_get_mypictures_path();
		path[i++] = mingw_get_personal_path();
		path[i++] = mingw_get_program_files_path();
		path[i++] = mingw_get_startup_path();
		path[i++] = mingw_get_system_path();
		path[i++] = mingw_get_windows_path();
	} else {
		path[i++] = "/bin";
		path[i++] = "/boot";
		path[i++] = "/dev";
		path[i++] = "/etc";
		path[i++] = "/home";
		path[i++] = "/lib";
		path[i++] = "/mnt";
		path[i++] = "/opt";
		path[i++] = "/proc";
		path[i++] = "/root";
		path[i++] = "/sbin";
		path[i++] = "/sys";
		path[i++] = "/tmp";
		path[i++] = "/usr";
		path[i++] = "/var";
	}

	g_assert(i <= G_N_ELEMENTS(path));

	entropy_array_stat_collect(ctx, path, i);
}

/**
 * Collect entropy from standard file descriptors.
 */
static void
entropy_collect_stdio(SHA1_context *ctx)
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
entropy_collect_free_space(SHA1_context *ctx)
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
entropy_collect_usage(SHA1_context *ctx)
{
#ifdef HAS_GETRUSAGE
	{
		struct rusage usage;

		if (-1 != getrusage(RUSAGE_SELF, &usage)) {
			SHA1_input(ctx, &usage, sizeof usage);
		} else {
			sha1_feed_ulong(ctx, errno);
		}
	}
#else
	sha1_feed_ulong(ctx, entropy_minirand());
#endif	/* HAS_GETRUSAGE */
}

/**
 * Collect entropy from system name.
 */
static void
entropy_collect_uname(SHA1_context *ctx)
{
#ifdef HAS_UNAME
	{
		struct utsname un;
		
		if (-1 != uname(&un)) {
			SHA1_input(ctx, &un, sizeof un);
		} else {
			sha1_feed_ulong(ctx, errno);
		}
	}
#else
	sha1_feed_ulong(ctx, entropy_minirand());
#endif	/* HAS_UNAME */
}

/**
 * Collect entropy from terminal line name.
 */
static void
entropy_collect_ttyname(SHA1_context *ctx)
{
#ifdef HAS_TTYNAME
	sha1_feed_string(ctx, ttyname(STDIN_FILENO));
#else
	sha1_feed_ulong(ctx, entropy_minirand());
#endif	/* HAS_TTYNAME */
}

/**
 * Collect entropy from amount of files we can open.
 */
static void
entropy_collect_file_amount(SHA1_context *ctx)
{
	sha1_feed_ulong(ctx, getdtablesize());
}

/**
 * Collect entropy from constant pointers.
 */
static void
entropy_collect_pointers(SHA1_context *ctx)
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
entropy_collect_cpu(SHA1_context *ctx)
{
	jmp_buf env;
	ulong r[sizeof(env) / sizeof(ulong)];

	/*
	 * Add local CPU state noise.
	 */

	ZERO(&env);			/* Avoid uninitialized memory reads */

	if (setjmp(env)) {
		/* We will never longjmp() back here */
		g_assert_not_reached();
	}

	/*
	 * Can't call entropy_array_ulong_collect() here since we are also called
	 * from entropy_seed(), which is used to seed entropy_minirand().
	 * Hence we manually shuffle the registers.
	 */

	memcpy(r, env, sizeof r);
	shuffle_with(rand31_u32, r, G_N_ELEMENTS(r), sizeof r[0]);

	SHA1_input(ctx, env, sizeof env);	/* "env" is an array */
	SHA1_input(ctx, r, sizeof r);
}

/** 
 * Collect entropy from environment.
 */
static void
entropy_collect_environ(SHA1_context *ctx)
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
entropy_collect_minirand(SHA1_context *ctx)
{
	ulong rn[RANDOM_SHUFFLE_MAX];
	int i = 0;

	while (i < RANDOM_SHUFFLE_MAX) {
		rn[i++] = entropy_minirand();
	}

	entropy_array_ulong_collect(ctx, rn, G_N_ELEMENTS(rn));
}

/**
 * Collect entropy from current time.
 */
static void
entropy_collect_time(SHA1_context *ctx)
{
	tm_t now;

	tm_now_exact(&now);
	SHA1_input(ctx, &now, sizeof now);
}

/**
 * Collect entropy from current thread.
 */
static void
entropy_collect_thread(SHA1_context *ctx)
{
	thread_t th = thread_current();

	SHA1_input(ctx, &th, sizeof th);
}

/**
 * Collect entropy from current IP gateway.
 */
static void
entropy_collect_gateway(SHA1_context *ctx)
{
	host_addr_t addr;

	ZERO(&addr);

	if (-1 == getgateway(&addr))
		sha1_feed_ulong(ctx, errno);

	SHA1_input(ctx, &addr, sizeof addr);
}

/**
 * Collect entropy from host.
 *
 * This uses the host's name and its IP addresses.
 */
static void
entropy_collect_host(SHA1_context *ctx)
{
	const char *name;
	pslist_t *hosts, *sl;

	name = local_hostname();
	sha1_feed_string(ctx, name);

	hosts = name_to_host_addr(name, NET_TYPE_NONE);
	hosts = pslist_shuffle_with(entropy_minirand, hosts);

	PSLIST_FOREACH(hosts, sl) {
		host_addr_t *addr = sl->data;
		struct packed_host_addr packed = host_addr_pack(*addr);

		SHA1_input(ctx, &packed, packed_host_addr_size(packed));
	}

	host_addr_free_list(&hosts);
}

/**
 * Collect entropy from VMM information.
 */
static void
entropy_collect_vmm(SHA1_context *ctx)
{
	void *p, *q;
	void *ptr[3];

	ptr[0] = deconstify_pointer(vmm_trap_page());
	ptr[1] = p = vmm_alloc(1);
	ptr[2] = q = vmm_alloc(1);

	entropy_array_pointer_collect(ctx, ptr, G_N_ELEMENTS(ptr));

	vmm_free(p, 1);
	vmm_free(q, 1);
}

/**
 * Collect entropy based on CPU time used and scheduling delays.
 */
static void
entropy_collect_timing(SHA1_context *ctx, bool slow)
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
	SHA1_context ctx;
	tm_t start, end;
	entropy_cb_t fn[RANDOM_SHUFFLE_MAX];
	size_t i = 0;

	/*
	 * Get random entropy from the system.
	 */

	tm_now_exact(&start);

	SHA1_reset(&ctx);
	SHA1_input(&ctx, &start, sizeof start);

	if (can_malloc) {
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
	}

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
	fn[i++] = entropy_collect_minirand;
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
		SHA1_input(&ctx, &end, sizeof end);
		v[1] = tm_elapsed_f(&end, &start);

		entropy_array_double_collect(&ctx, v, G_N_ELEMENTS(v));
	}

	/*
	 * Done, finalize SHA1 computation into supplied digest buffer.
	 */

	SHA1_result(&ctx, digest);

	/*
	 * Merge entropy from all the previous calls to make this as unique
	 * a random bitstream as possible.
	 */

	entropy_merge(digest);
}

/**
 * Randomly feed the SHA1 context to itself 20% of the time.
 */
static void G_GNUC_COLD
entropy_self_feed_maybe(SHA1_context *ctx)
{
	if (random_upto(rand31_u32, 999) < 200)
		SHA1_input(ctx, ctx, sizeof *ctx);
}

/**
 * Seed the entropy_minirand() context variable, once.
 *
 * We're collecting changing and contextual data, to be able to compute an
 * initial 160-bit value, which is better than the default zero value.
 */
static void G_GNUC_COLD
entropy_seed(struct entropy_minictx *c)
{
	extern char **environ;
	char garbage[64];		/* Left uninitialized on purpose */
	const char *str[RANDOM_SHUFFLE_MAX];
	SHA1_context ctx;
	size_t i, j;
	tm_t now;

	/*
	 * This routine must not allocate any memory because it will be called
	 * very early during initialization.
	 */

#define ENTROPY_CONTEXT_FEED	entropy_self_feed_maybe(&ctx)

#define ENTROPY_SHUFFLE_FEED(a, f) G_STMT_START {				\
	size_t x;													\
	shuffle_with(rand31_u32, a, G_N_ELEMENTS(a), sizeof a[0]);	\
	for (x = 0; x < G_N_ELEMENTS(a); x++)						\
		f(&ctx, a[x]);											\
	ENTROPY_CONTEXT_FEED;										\
} G_STMT_END

	SHA1_reset(&ctx);

	tm_current_time(&now);		/* Do not use tm_now_exact(), it's too soon */
	SHA1_input(&ctx, &now, sizeof now);

	j = popcount(now.tv_usec);
	for (i = 0; i <= j; i++) {
		ENTROPY_CONTEXT_FEED;										\
	}

	{
		ulong along[2] = { time(NULL), getpid() };
		ENTROPY_SHUFFLE_FEED(along, sha1_feed_ulong);
	}

	entropy_collect_cpu(&ctx);
	ENTROPY_CONTEXT_FEED;

	{
		int afd[3] = { STDIN_FILENO, STDOUT_FILENO, STDERR_FILENO };
		ENTROPY_SHUFFLE_FEED(afd, sha1_feed_fstat);
	}

	for (i = 0, j = 0; NULL != environ[i]; i++) {
		str[j++] = environ[i];
		if (RANDOM_SHUFFLE_MAX == j) {
			ENTROPY_SHUFFLE_FEED(str, sha1_feed_string);
			j = 0;
		}
	}
	if (j != 0) {
		shuffle_with(rand31_u32, str, j, sizeof str[0]);
		for (i = 0; i < j; i++) {
			sha1_feed_string(&ctx, str[i]);
		}
	}
	ENTROPY_CONTEXT_FEED;

	{
		void *aptr[2] = { environ, &now };
		ENTROPY_SHUFFLE_FEED(aptr, sha1_feed_pointer);
	}

	{
		const char *astr[3] = { ".", "..", "/" };
		ENTROPY_SHUFFLE_FEED(astr, sha1_feed_stat);
	}

	SHA1_input(&ctx, garbage, sizeof garbage);
	ENTROPY_CONTEXT_FEED;

	entropy_delay();
	tm_current_time(&now);		/* Do not use tm_now_exact(), it's too soon */
	SHA1_input(&ctx, &now, sizeof now);

	j = popcount(now.tv_usec);
	for (i = 0; i <= j; i++) {
		ENTROPY_CONTEXT_FEED;
	}

	/* Partial SHA1 result */

	{
		SHA1_context tmp;
		struct sha1 hash;
		const void *p = &hash;
		uint32 v;

		tmp = ctx;			/* struct copy */
		SHA1_result(&tmp, &hash);
		p = peek_be32_advance(p, &v);

		tm_current_time(&now);
		j = (v & 0xff) + popcount(now.tv_usec);
		for (i = 0; i <= j; i++) {
			ENTROPY_CONTEXT_FEED;
		}

		sha1_feed_ulong(&ctx, peek_be32(p));
	}

	tm_current_time(&now);

	{
		double r = random_double_generate(rand31_u32);
		double usr, sys, cpu = tm_cputime(&usr, &sys);
		double adouble[6] = { cpu, usr, sys, r,
			now.tv_usec / 101.0, now.tv_usec / (now.tv_sec + 0.1) };
		ENTROPY_SHUFFLE_FEED(adouble, sha1_feed_double);
	}

#undef ENTROPY_SHUFFLE_FEED
#undef ENTROPY_CONTEXT_FEED

	tm_current_time(&now);
	SHA1_input(&ctx, &now, sizeof now);

	{
		struct sha1 hash;
		const void *p = &hash;
		uint32 v;

		SHA1_result(&ctx, &hash);
		p = peek_be32_advance(p, &c->c);
		p = peek_be32_advance(p, &c->x);
		p = peek_be32_advance(p, &c->z);
		p = peek_be32_advance(p, &v);
		c->y = v ^ peek_be32(p);
	}
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
 * Functions to call when entropy information is needed.
 */
struct entropy_ops {
	void (*ent_collect)(sha1_t *digest);
	void (*ent_mini_collect)(sha1_t *digest);
	uint32 (*ent_random)(void);
	void (*ent_fill)(void *buffer, size_t len);
};

static struct entropy_ops entropy_ops;

/**
 * Internal wrapper to collect 160 bits of entropy via AJE.
 */
static void
entropy_aje_collect(sha1_t *digest)
{
	aje_random_bytes(digest, sizeof digest);
}

/**
 * When AJE (Alea Jacta Est) has been initialized, we can use it as our main
 * entropy source.  Hence redirect all entropy requests to that layer.
 */
G_GNUC_COLD void
entropy_aje_inited(void)
{
	entropy_ops.ent_collect      = entropy_aje_collect;
	entropy_ops.ent_mini_collect = entropy_aje_collect;
	entropy_ops.ent_random       = aje_rand_strong;
	entropy_ops.ent_fill         = aje_random_bytes;
	atomic_mb();
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
static G_GNUC_COLD void
entropy_do_collect(sha1_t *digest)
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
static G_GNUC_COLD void
entropy_do_minimal_collect(sha1_t *digest)
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
static uint32
entropy_do_random(void)
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
static void
entropy_do_fill(void *buffer, size_t len)
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
	return entropy_ops.ent_collect(digest);
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
	return entropy_ops.ent_mini_collect(digest);
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
	return entropy_ops.ent_random();
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
	return entropy_ops.ent_fill(buffer, len);
}

static struct entropy_ops entropy_ops = {
	entropy_do_collect,			/* ent_collect */
	entropy_do_minimal_collect,	/* ent_mini_collect */
	entropy_do_random,			/* ent_random */
	entropy_do_fill,			/* ent_fill */
};

/* vi: set ts=4 sw=4 cindent: */
