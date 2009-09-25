/*
 * $Id$
 *
 * Copyright (c) 2008, Christian Biere
 * Copyright (c) 2008, Raphael Manfredi
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
 * @author Christian Biere
 * @author Raphael Manfredi
 * @date 2008
 */

#include "common.h"

RCSID("$Id$")

#include "entropy.h"
#include "compat_misc.h"
#include "compat_sleep_ms.h"
#include "eval.h"
#include "misc.h"
#include "sha1.h"
#include "tm.h"

#include "override.h"			/* Must be the last header included */

static void
sha1_feed_ulong(SHA1Context *ctx, gulong value)
{
	SHA1Input(ctx, &value, sizeof value);
}

static void
sha1_feed_double(SHA1Context *ctx, double value)
{
	SHA1Input(ctx, &value, sizeof value);
}

static void
sha1_feed_pointer(SHA1Context *ctx, gconstpointer p)
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

/**
 * Collect entropy and fill supplied SHA1 buffer with 160 random bits.
 *
 * @attention
 * This is a slow operation, and the routine even sleeps for 250 ms, so it
 * must be called only when a truly random seed is required, ideally only
 * during initialization.
 */
void
entropy_collect(struct sha1 *digest)
{
	struct stat buf;
	FILE *f = NULL;
	SHA1Context ctx;
	tm_t start, end;
	gboolean is_pipe = TRUE;
	jmp_buf env;

	/*
	 * Get random entropy from the system.
	 */

	tm_now_exact(&start);

	SHA1Reset(&ctx);
	SHA1Input(&ctx, &start, sizeof start);

	/*
	 * If we have a /dev/urandom character device, use it.
	 * Otherwise, launch ps and grab its output.
	 */

	if (-1 != stat("/dev/urandom", &buf) && S_ISCHR(buf.st_mode)) {
		f = fopen("/dev/urandom", "r");
		is_pipe = FALSE;
		SHA1Input(&ctx, &buf, sizeof buf);
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
			guint8 data[1024];
			int r;
			int len = is_pipe ? sizeof(data) : 128;

			r = fread(data, 1, len, f);
			if (r)
				SHA1Input(&ctx, data, r);
			if (r < len || !is_pipe)		/* Read once from /dev/urandom */
				break;
		}

		if (is_pipe)
			pclose(f);
		else
			fclose(f);
	}

	/*
	 * Add local CPU state noise.
	 */

	if (setjmp(env)) {
		/* We will never longjmp() back here */
		g_assert_not_reached();
	}
	SHA1Input(&ctx, env, sizeof env);

	/* Add some host/user dependent noise */
	sha1_feed_ulong(&ctx, getuid());
	sha1_feed_ulong(&ctx, getgid());
	sha1_feed_ulong(&ctx, getpid());
	sha1_feed_ulong(&ctx, getppid());
	sha1_feed_ulong(&ctx, compat_max_fd());

	sha1_feed_string(&ctx, __DATE__);
	sha1_feed_string(&ctx, __TIME__);
	sha1_feed_string(&ctx,
		"$Id$");

#if GLIB_CHECK_VERSION(2,6,0)
	/*
	 * These functions cannot be used with an unpatched GLib 1.2 on some
	 * systems as they trigger a bug in GLib causing a crash.  On Darwin
	 * there's still a problem before GLib 2.6 due to a bug in Darwin though.
	 */
	sha1_feed_string(&ctx, g_get_user_name());
	sha1_feed_string(&ctx, g_get_real_name());
#endif	/* GLib >= 2.0 */

	sha1_feed_string(&ctx, eval_subst("~"));
	if (-1 != stat(eval_subst("~"), &buf)) {
		SHA1Input(&ctx, &buf, sizeof buf);
	}
	if (-1 != stat(".", &buf)) {
		SHA1Input(&ctx, &buf, sizeof buf);
	}
	if (-1 != stat("..", &buf)) {
		SHA1Input(&ctx, &buf, sizeof buf);
	}
	if (-1 != stat("/", &buf)) {
		SHA1Input(&ctx, &buf, sizeof buf);
	}
	if (-1 != fstat(STDIN_FILENO, &buf)) {
		SHA1Input(&ctx, &buf, sizeof buf);
	}
	if (-1 != fstat(STDOUT_FILENO, &buf)) {
		SHA1Input(&ctx, &buf, sizeof buf);
	}

	sha1_feed_double(&ctx, fs_free_space_pct(eval_subst("~")));
	sha1_feed_double(&ctx, fs_free_space_pct("/"));

#ifdef HAS_UNAME
	{
		struct utsname un;
		
		if (-1 != uname(&un)) {
			SHA1Input(&ctx, &un, sizeof un);
		}
	}
#endif	/* HAS_UNAME */
	
	sha1_feed_pointer(&ctx, &ctx);
	sha1_feed_pointer(&ctx, cast_func_to_pointer(&random_init));
	sha1_feed_pointer(&ctx, sbrk(0));

	{
		extern char **environ;
		size_t i;

		for (i = 0; NULL != environ[i]; i++) {
			sha1_feed_string(&ctx, environ[i]);
		}
	}

	sha1_feed_string(&ctx, ttyname(STDIN_FILENO));

#ifdef HAS_GETRUSAGE
	{
		struct rusage usage;

		if (-1 != getrusage(RUSAGE_SELF, &usage)) {
			SHA1Input(&ctx, &usage, sizeof usage);
		}
	}
#endif	/* HAS_GETRUSAGE */

	/*
	 * Add timing entropy.
	 */

	{
		double u, s;
		tm_t before, after;

		sha1_feed_double(&ctx, tm_cputime(&u, &s));
		sha1_feed_double(&ctx, u);
		sha1_feed_double(&ctx, s);

		tm_now_exact(&before);
		compat_sleep_ms(250);	/* 250 ms */
		tm_now_exact(&after);
		sha1_feed_double(&ctx, 0.25 - tm_elapsed_f(&after, &before));
	}

	tm_now_exact(&end);
	SHA1Input(&ctx, &end, sizeof end);

	/*
	 * Done, finalize SHA1 computation into supplied digest buffer.
	 */

	SHA1Result(&ctx, digest);
}

/* vi: set ts=4 sw=4 cindent: */
