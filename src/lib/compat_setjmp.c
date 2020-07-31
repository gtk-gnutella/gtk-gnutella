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
 *      51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
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

static void
setjmp_fill_ctx(struct compat_jmpbuf_ctx *x,
	enum setjmp_magic magic, const void *sp,
	const char *file, uint line, const char *routine)
{
	x->magic     = magic;
	x->stid      = thread_small_id();
	x->sig_level = signal_thread_handler_level(x->stid);
	x->sp        = &sp;
	x->routine   = routine;
	x->file      = file;
	x->line      = line;
}

/**
 * Prepare for a setjmp().
 *
 * @note
 * The jmp_buf type here is not the system one but the one we redefine.
 */
void
setjmp_prep(jmp_buf env,
	const char *file, uint line, const char *routine)
{
	int sp;

	setjmp_fill_ctx(&env->x, SETJMP_MAGIC, &sp, file, line, routine);
}

/**
 * Prepare for a sigsetjmp().
 *
 * @note
 * The sigjmp_buf type here is not the system one but the one we redefine.
 */
void
sigsetjmp_prep(sigjmp_buf env,
	int savesigs,
	const char *file, uint line, const char *routine)
{
	int sp;

	setjmp_fill_ctx(&env->x, SIGSETJMP_MAGIC, &sp, file, line, routine);

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

static void
longjmp_validate(const char *caller,
	const struct compat_jmpbuf_ctx *x,
	enum setjmp_magic magic, const void *sp, uint stid, int val,
	const char *file, uint line, const char *routine)
{
	if G_UNLIKELY(SETJMP_USED_MAGIC == x->magic) {
		s_error(
			"%s(): context was taken at %s:%u in %s() "
			"and %slongjmp(%d) already called at %s:%u in %s() within %s",
			caller, x->file, x->line, x->routine,
			SIGSETJMP_MAGIC == magic ? "sig" : "",
			x->used.arg, x->used.file, x->used.line, x->used.routine,
			thread_safe_id_name(x->stid));
	}

	g_assert_log(magic == x->magic,
		"%s(): magic=0x%x instead of 0x%x", caller, x->magic, magic);

	if G_UNLIKELY(x->stid != stid) {
		s_error(
			"%s(): x->stid=%u {%s}, stid=%u {%s}, context taken at %s:%u in %s()",
			caller, x->stid, thread_safe_id_name(x->stid),
			stid, thread_safe_id_name(stid), x->file, x->line, x->routine);
	}

	/*
	 * See whether routine where (sig)setjmp() occurred has already returned.
	 * We must still be deeper in the call stack at the time of longjmp(),
	 * or the context is completely invalid.
	 *
	 * This is imperfect of couse, we could have grown the stack since we
	 * returned and not be able to detect the situation where the context is
	 * truly gone, but it will detect some blatant mistakes.
	 */

	if G_UNLIKELY((thread_stack_ptr_cmp(sp, x->sp) > 0)) {
		s_error(
			"%s(): context, taken at %s:%u in %s(), already gone when "
			"%slongjmp(%d) is called at %s:%u in %s() within %s "
			"(SP was %p, now %p)",
			caller, x->file, x->line, x->routine,
			SIGSETJMP_MAGIC == magic ? "sig" : "",
			val, file, line, routine, thread_safe_id_name(x->stid),
			x->sp, sp);
	}
}

static void
longjmp_flag_used(struct compat_jmpbuf_ctx *x,
	int val, const char *file, uint line, const char *routine)
{
	x->magic        = SETJMP_USED_MAGIC;
	x->used.arg     = val;
	x->used.file    = file;
	x->used.line    = line;
	x->used.routine = routine;
}

/**
 * Wrapper for the longjmp() call to restore the signal handler level.
 *
 * @note
 * The jmp_buf type here is not the system one but the one we redefine.
 */
void
compat_longjmp(jmp_buf env, int val,
	const char *file, uint line, const char *routine)
{
	uint stid = thread_small_id();

	g_assert(val != 0);

	longjmp_validate(G_STRFUNC,
		&env->x, SETJMP_MAGIC, &stid, stid, val,
		file, line, routine);
	longjmp_flag_used(&env->x, val, file, line, routine);

	signal_thread_handler_level_set(stid, env->x.sig_level);

	longjmp(env->buf, val);
}

/**
 * Wrapper for the siglongjmp() call to restore the signal handler level.
 *
 * @note
 * The sigjmp_buf type here is not the system one but the one we redefine.
 */
void
compat_siglongjmp(sigjmp_buf env, int val,
	const char *file, uint line, const char *routine)
{
	uint stid = thread_small_id();

	g_assert(val != 0);

	longjmp_validate(G_STRFUNC,
		&env->x, SIGSETJMP_MAGIC, &stid, stid, val,
		file, line, routine);
	longjmp_flag_used(&env->x, val, file, line, routine);

#ifndef HAS_SIGSETJMP
	if (env->mask_saved)
		sigprocmask(SIG_SETMASK, &env->mask, NULL);
#endif	/* !HAS_SIGSETJMP */

	signal_thread_handler_level_set(stid, env->x.sig_level);

	Siglongjmp(env->buf, val);		/* metaconfig symbol definition */
}

/* vi: set ts=4 sw=4 cindent: */
