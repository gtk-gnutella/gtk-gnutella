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
 * In order to work properly with signal handlers, the code should use
 * Setjmp() and Sigsetjmp(), but can use longjmp() and siglongjmp().
 *
 * @author Raphael Manfredi
 * @date 2016
 */

#ifndef _compat_setjmp_h_
#define _compat_setjmp_h_

#include "config.h"

/*
 * Before including <setjmp.h> we need to remap the jmp_buf and sigjmp_buf
 * symbols because we are going to redefine our own types.
 *
 * If there is no sigjmp_buf defined, use the native jmp_buf.
 */

#define jmp_buf		native_jmp_buf

#ifdef HAS_SIGSETJMP
#define sigjmp_buf	native_sigjmp_buf
#else
#define native_sigjmp_buf native_jmp_buf
#endif	/* HAS_SIGSETJMP */

#include <setjmp.h>

#undef jmp_buf
#undef sigjmp_buf

/*
 * If SETJMP_SOURCE is defined, we are implementing our own Setjmp() and
 * longjmp() therefore we need access to the real calls!
 *
 * Note that, unfortunately, we cannot redefine setjmp() as a function hence
 * we need to use the capitalized Setjmp() -- and Sigsetjmp() if needed --
 * in the program.  We can remap longjmp() and siglongjmp() though.
 *
 * The reason for which we cannot wrap setjmp() in our own routine but need
 * a macro is simple: we cannot let the stack unwind when our wrapping routine
 * returns the first time and expect longjmp() to later place us at the right
 * place.  That's why the idiom for using Setjmp() is:
 *
 *    if (Setjmp(env)) {
 *        // code to run if we longjmp() is here
 *    }
 *
 * because we cannot return from the routine calling setjmp().
 */

#ifndef SETJMP_SOURCE
#undef Setjmp
#undef Sigsetjmp
#undef longjmp
#undef siglongjmp
#undef Siglongjmp

#define Setjmp(e)		(setjmp_prep((e), _WHERE_, __LINE__), setjmp((e)->buf))

#ifdef HAS_SIGSETJMP
#define Sigsetjmp(e,s)	\
	(sigsetjmp_prep((e), (s), _WHERE_, __LINE__), sigsetjmp((e)->buf, (s)))
#else
#define Sigsetjmp(e,s)	\
	(sigsetjmp_prep((e), (s), _WHERE_, __LINE__), setjmp((e)->buf))
#endif

#define longjmp(e,v)	compat_longjmp((e), (v))
#define siglongjmp(e,v)	compat_siglongjmp((e), (v))
#define Siglongjmp(e,v)	compat_siglongjmp((e), (v))
#endif	/* SETJMP_SOURCE */

/*
 * Our own jmp_buf and sigjmp_buf encapsulate the native ones to include
 * the signal handler level at the time Setjmp() or Sigsetjmp() was called.
 *
 * On Windows, since we emulate sigprocmask() and there is no native support
 * for sigsetjmp(), we have to include the necessary information to be able
 * to perform siglongjmp()  correctly.
 *
 * We put the CPU state at the start of our new structures to avoid problems
 * if these are used with setjmp() and sigsetjmp().
 */

enum setjmp_magic {
	SETJMP_MAGIC      = 0x6790e2ab,
	SIGSETJMP_MAGIC   = 0x4b539cdb,
	SETJMP_USED_MAGIC = 0x780be360
};

typedef struct compat_jmpbuf {
	native_jmp_buf buf;			/**< CPU state, must be at the start */
	sig_atomic_t sig_level;		/**< Internal signal handler level */
	enum setjmp_magic magic;	/**< Magic number */
	uint stid;					/**< Thread which saved the context */
	uint line;					/**< Line number where state was taken */
	const char *file;			/**< File name where state was taken */
} jmp_buf[1];

typedef struct compat_sigjmpbuf {
	native_sigjmp_buf buf;		/**< CPU state, must be at the start */
	sig_atomic_t sig_level;		/**< Internal signal handler level */
	enum setjmp_magic magic;	/**< Magic number */
	uint stid;					/**< Thread which saved the context */
#ifndef HAS_SIGSETJMP
	bool mask_saved;			/**< Did we save the signal mask? */
	sigset_t mask;				/**< Signal mask saved */
#endif	/* !HAS_SIGSETJMP */
	uint line;					/**< Line number where state was taken */
	const char *file;			/**< File name where state was taken */
} sigjmp_buf[1];

/*
 * Public interface.
 */

void setjmp_prep(jmp_buf env, const char *file, uint line);
void sigsetjmp_prep(sigjmp_buf env, int savesigs, const char *file, uint line);

void compat_longjmp(jmp_buf env, int val) G_NORETURN;
void compat_siglongjmp(sigjmp_buf env, int val) G_NORETURN;

#endif	/* _compat_setjmp_h_ */

/* vi: set ts=4 sw=4 cindent: */
