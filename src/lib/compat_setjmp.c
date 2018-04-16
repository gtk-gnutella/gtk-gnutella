/*
 * Copyright (c) 2016 Raphael Manfredi
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
 * Compatible and portable setjmp/sigsetjmp with longjmp/siglongjmp.
 *
 * Portability comes from the ability for the code to use Setjmp() and
 * Sigsetjmp() along with jmp_buf and sigjmp_buf freely and without worrying
 * about whether the feature is actually supported on the machine.
 *
 * Compatibility comes with the integration of idiosyncrasies from our
 * runtime: we monitor signal handlers so that we can determine whether we
 * are running in one of them.  Therefore, we need to track when we leave
 * a signal handler through a longjmp() or siglongjmp() call.
 *
 * As an added benefit, we can enforce that the Setjmp() buffer be not
 * reused after a longjmp() was made and that it is properly initialized
 * when given to longjmp().
 *
 * @author Raphael Manfredi
 * @date 2016
 */

#define SETJMP_SOURCE		/* Must not remap longjmp(), etc */

#include "common.h"

#include "compat_setjmp.h"

#include "log.h"
#include "signal.h"
#include "thread.h"

#include "override.h"		/* Must be the last header included */

/**
 * Prepare for a setjmp().
 *
 * @note
 * The jmp_buf type here is not the system one but the one we redefine.
 */
void
setjmp_prep(jmp_buf env, const char *file, uint line)
{
	env->stid = thread_small_id();
	env->sig_level = signal_thread_handler_level(env->stid);
	env->magic = SETJMP_MAGIC;
	env->file = file;
	env->line = line;
}

/**
 * Prepare for a sigsetjmp().
 *
 * @note
 * The sigjmp_buf type here is not the system one but the one we redefine.
 */
void
sigsetjmp_prep(sigjmp_buf env, int savesigs, const char *file, uint line)
{
	env->stid = thread_small_id();
	env->sig_level = signal_thread_handler_level(env->stid);
	env->magic = SIGSETJMP_MAGIC;
	env->file = file;
	env->line = line;

#ifndef HAS_SIGSETJMP
	env->mask_saved = booleanize(savesigs);

	if (env->mask_saved) {
		sigset_t old, zero;

		sigemptyset(&zero);
		sigprocmask(SIG_BLOCK, &zero, &old);
		env->mask = old;
	}
#else
	(void) savesigs;
#endif	/* !HAS_SIGSETJMP */
}

/**
 * Wrapper for the longjmp() call to restore the signal handler level.
 *
 * @note
 * The jmp_buf type here is not the system one but the one we redefine.
 */
void
compat_longjmp(jmp_buf env, int val, const char *file, uint line)
{
	uint stid = thread_small_id();

	g_assert_log(env->magic != SETJMP_USED_MAGIC,
		"context was taken at %s:%u and longjmp(%d) called at %s:%u in %s",
		env->file, env->line,
		env->used.arg, env->used.file, env->used.line,
		thread_safe_id_name(env->stid));

	g_assert_log(SETJMP_MAGIC == env->magic, "magic=0x%x", env->magic);
	g_assert(val != 0);

	g_assert_log(env->stid == stid,
		"%s(): env->stid=%u {%s}, stid=%u {%s}, context taken at %s:%u",
		G_STRFUNC, env->stid, thread_safe_id_name(env->stid),
		stid, thread_safe_id_name(stid), env->file, env->line);

	signal_thread_handler_level_set(stid, env->sig_level);

	env->magic = SETJMP_USED_MAGIC;
	env->used.arg = val;
	env->used.file = file;
	env->used.line = line;

	longjmp(env->buf, val);
}

/**
 * Wrapper for the siglongjmp() call to restore the signal handler level.
 *
 * @note
 * The sigjmp_buf type here is not the system one but the one we redefine.
 */
void
compat_siglongjmp(sigjmp_buf env, int val, const char *file, uint line)
{
	uint stid = thread_small_id();

	g_assert_log(env->magic != SETJMP_USED_MAGIC,
		"context was taken at %s:%u and longjmp(%d) called at %s:%u in %s",
		env->file, env->line,
		env->used.arg, env->used.file, env->used.line,
		thread_safe_id_name(env->stid));

	g_assert_log(SIGSETJMP_MAGIC == env->magic, "magic=0x%x", env->magic);
	g_assert(val != 0);

	g_assert_log(env->stid == stid,
		"%s(): env->stid=%u {%s}, stid=%u {%s}, context taken at %s:%u",
		G_STRFUNC, env->stid, thread_safe_id_name(env->stid),
		stid, thread_safe_id_name(stid), env->file, env->line);

#ifndef HAS_SIGSETJMP
	if (env->mask_saved)
		sigprocmask(SIG_SETMASK, &env->mask, NULL);
#endif	/* !HAS_SIGSETJMP */

	signal_thread_handler_level_set(stid, env->sig_level);

	env->magic = SETJMP_USED_MAGIC;
	env->used.arg = val;
	env->used.file = file;
	env->used.line = line;

	Siglongjmp(env->buf, val);		/* metaconfig symbol definition */
}

/* vi: set ts=4 sw=4 cindent: */
