/*
 * Copyright (c) 2015 Raphael Manfredi
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
 * Program name management.
 *
 * This also adds getprogname() and setprogname() on systems that lack it.
 *
 * It also provides an important progstart() hook to capture the original
 * main() arguments and perform manadatory low-level initializations on
 * Windows platforms.
 *
 * @author Raphael Manfredi
 * @date 2015
 */

#include "common.h"

#include "progname.h"

#include "iovec.h"
#include "mem.h"
#include "misc.h"				/* For is_strcasesuffix() */
#include "mutex.h"
#include "once.h"
#include "path.h"
#include "product.h"
#include "strvec.h"
#include "tm.h"
#include "vmm.h"
#include "xmalloc.h"

#include "override.h"			/* Must be the last header included */

static int progname_argc;
static char **progname_argv;

extern char **environ;

static struct {
	const char *name;			/* Current program name */
	bool allocated;				/* Whether ``name'' was allocated */
	tm_t start;					/* Time when progstart() was called */
#ifndef HAS_SETPROCTITLE
	char *argstart;				/* Start of memory for setproctitle() */
	size_t arglen;				/* Length of memory for setproctitle() */
#endif
	once_flag_t duplicated;		/* Ensure duplication is done once */
	int argc;					/* Amount of entries in duplicated argv[] */
	char **argv;				/* Duplicated (read-only) argv[] */
	char **envp;				/* Duplicated (read-only) envp[] */
} progname_info;

/**
 * Save the original main() arguments and perform early initializations.
 *
 * @param argc		the argument count, originally given to main()
 * @param argv		the argument vector, originally given to main()
 */
void
progstart(int argc, char * const *argv)
{
	g_assert(argc > 0);
	g_assert(argv != NULL);

	g_return_unless(NULL == progname_argv);	/* Should be called once only! */

#ifdef MINGW32
	mingw_early_init();			/* Must be done as early as possible! */
#endif	/* MINGW32 */

	thread_main_starting();		/* We are now certain we're the main thread */

	progname_argc = argc;
	progname_argv = deconstify_pointer(argv);

	progname_info.name = filepath_basename(argv[0]);
	tm_current_time(&progname_info.start);

#ifdef TRACK_MALLOC
	/*
	 * When using TRACK_MALLOC, this needs to be done early to configure
	 * the tracking hash tables.
	 */

	malloc_init_tracking();
#endif

	/*
	 * Ensure we have a valid product name configured, otherwise use
	 * the executable basename.  A valid product name is required on
	 * Windows to initialize the path where we are going to store
	 * the logs.
	 *
	 * However, if we have to do this here (meaning there is not product
	 * registration done before calling progstart), force the usage of
	 * the current directory for the logs by flagging that the name
	 * was forced.
	 */

	if (NULL == product_name())
		product_set_forced_name(progname_info.name);

	/*
	 * Because fd_preserve() can allocate memory and we are going to call
	 * this routine the first time we call mingw_backtrace(), via calls to
	 * mem_is_valid_ptr(), we need to ensure this table is already allocated.
	 *
	 * If is also useful on UNIX systems because the first time we're going
	 * to attempt to capture a backtrace, we'll call valid_ptr() through
	 * stacktrace_unwind() and we do not want memory allocation then either.
	 *
	 * Hence call mem_is_valid_ptr() now, which, as a side effect, will
	 * allocate the memory.
	 */

	(void) mem_is_valid_ptr(NULL);

	/*
	 * On Windows, make sure there is no ugly trailing ".exe" at the end
	 * of the program name.
	 */

	if (is_running_on_mingw()) {
		const char *name = progname_info.name;
		const char *exe = is_strcasesuffix(name, (size_t) -1, ".exe");

		/*
		 * No need to take locks at this time, we're mono-threaded since
		 * progstart() needs to be one of the first application calls.
		 */

		if (exe != NULL) {
			progname_info.name = xstrndup(name, ptr_diff(exe, name));
			progname_info.allocated = TRUE;
		}
	}

#ifdef HAS_SETPROGNAME
	setprogname(progname_info.name);
#endif

	/*
	 * This is most always required anyway, so do it now.
	 */

	misc_init();
}

/**
 * Ensure progstart() was called.
 */
static void
progstart_called(const char *routine)
{
	g_assert_log(progname_info.name != NULL,
		"%s(): must not be called before progstart()", routine);
}

/**
 * When did the program start?
 */
tm_t
progstart_time(void)
{
	progstart_called(G_STRFUNC);

	return progname_info.start;
}

/**
 * Duplicate the original main() arguments + environment into read-only.
 */
static void
progstart_duplicate(void)
{
	size_t env_count, arg_count;
	size_t env_size, arg_size;
	size_t total_size, len;
	void *p, *q;
	char **argv;
	char **envp;

	env_count = strvec_count(environ);
	env_size = strvec_size(environ);
	arg_count = progname_argc;
	arg_size = strvec_size(progname_argv);

	len = total_size = (arg_count + env_count + 2) * sizeof(char *) +
		env_size + arg_size;

	p = vmm_alloc_not_leaking(total_size);
	argv = p;
	envp = ptr_add_offset(argv, (arg_count + 1) * sizeof(char *));
	q = ptr_add_offset(envp, (env_count + 1) * sizeof(char *));

	q = strvec_cpy(argv, progname_argv, arg_count, q, &len);
	q = strvec_cpy(envp, environ, env_count, q, &len);

	g_assert(ptr_diff(q, p) == total_size);

	if (-1 == mprotect(p, total_size, PROT_READ))
		s_warning("%s(): cannot protect memory as read-only: %m", G_STRFUNC);

	progname_info.argc = arg_count;
	progname_info.argv = argv;
	progname_info.envp = envp;
}

/**
 * Duplicate the original main() arguments + environment into read-only
 * memory, returning pointers to the argument vector, the environment and
 * the size of the argument vector.
 *
 * The progstart() routine must be called first to record the original
 * argument pointers and progstart_dup() must be called as soon as possible,
 * before alteration of the argument list or the passed environment.
 *
 * @param argv_ptr	where the allocated argment vector is returned
 * @param envp_ptr	where the allocated environment is returned
 *
 * @return the amount of entries in the returned argv[]
 */
int
progstart_dup(const char ***argv_ptr, const char ***envp_ptr)
{
	progstart_called(G_STRFUNC);

	ONCE_FLAG_RUN(progname_info.duplicated, progstart_duplicate);

	if (argv_ptr != NULL)
		*argv_ptr = (const char **) progname_info.argv;

	if (envp_ptr != NULL)
		*envp_ptr = (const char **) progname_info.envp;

	return progname_info.argc;
}

/**
 * Get original argument #n, NULL if out of boundaries.
 */
const char *
progstart_arg(int n)
{
	progstart_called(G_STRFUNC);
	g_assert(n >= 0);

	ONCE_FLAG_RUN(progname_info.duplicated, progstart_duplicate);

	if (n >= progname_info.argc)
		return NULL;

	return progname_info.argv[n];
}

#if !defined(HAS_GETPROGNAME) || !defined(HAS_SETPROGNAME)
static mutex_t progname_mtx = MUTEX_INIT;

/*
 * Use "fast" locks since these can be used very early in the process.
 *
 * We use mutexes and not simple locks in case there is some re-entrance
 * due to the fact that setprogname() calls some other routines that could
 * in turn need to call getprogname() for instance.
 */

#define PROGNAME_LOCK		mutex_lock_fast(&progname_mtx)
#define PROGNAME_UNLOCK		mutex_unlock_fast(&progname_mtx)
#endif

#ifndef HAS_GETPROGNAME
/**
 * @return the program name (last path component if invoked with full path).
 */
const char *
getprogname(void)
{
	const char *name;

	progstart_called(G_STRFUNC);

	/*
	 * Need to take a lock since setprogname() is not atomic.
	 */

	PROGNAME_LOCK;
	name = progname_info.name;
	PROGNAME_UNLOCK;

	return name;
}
#endif	/* !HAS_GETPROGNAME */

#ifndef HAS_SETPROGNAME
/**
 * Set program name.
 *
 * The given string is duplicated, hence it can be transient (held in a
 * buffer on the stack).
 *
 * @param progname		the program name we want to report via getprogname()
 */
void
setprogname(const char *name)
{
	char *oldname;

	progstart_called(G_STRFUNC);
	g_assert(name != NULL);

	PROGNAME_LOCK;

	/*
	 * We protect ourselves against re-entrance from the same thread into
	 * the critical section in getprogname(): since we call an allocation
	 * routine, we do not know what could happen.
	 *
	 * Therefore we don't immediately free the old name, if it was allocated.
	 * We first install the new allocated name, then we free-up the old one,
	 * outside of the critical section.
	 */

	if (progname_info.allocated)
		oldname = deconstify_char(progname_info.name);
	else
		oldname = NULL;

	progname_info.allocated = TRUE;

	/*
	 * Avoid any trailing ".exe" at the end of the name on Windows.
	 */

	if (is_running_on_mingw()) {
		const char *exe = is_strcasesuffix(name, (size_t) -1, ".exe");
		if (exe != NULL) {
			progname_info.name = xstrndup(name, ptr_diff(exe, name));
			goto done;
		}
	}

	progname_info.name = xstrdup(name);

done:
	PROGNAME_UNLOCK;

	if (oldname != NULL)
		xfree(oldname);
}
#endif	/* !HAS_SETPROGNAME */

/***
 *** Support routines for our setproctitle() implementation.
 ***/

#ifndef HAS_SETPROCTITLE
static once_flag_t progname_args_saved;

static void
progname_args_copy_strvec(char **strv)
{
	size_t i;

	for (i = 0; strv[i] != NULL; i++)
		strv[i] = xstrdup(strv[i]);
}

#ifdef HAS_SETENV
static void
progname_args_clearenv(void)
{
#ifdef HAS_CLEARENV
	clearenv();
#else
	char **env;

	env = real_malloc(sizeof *env);		/* libc needs malloc() */
	env[0] = NULL;
	environ = env;
#endif
}

static void
progname_args_copy_environ(void)
{
	char **env = environ;
	size_t i;

	progname_args_clearenv();

	for (i = 0; env[i] != NULL; i++) {
		char *eq = vstrchr(env[i], '=');
		int r;

		if (eq != NULL) {
			*eq = '\0';
			r = setenv(env[i], eq + 1, TRUE);
			*eq = '=';
			if (-1 == r) {
				s_warning("%s(): cannot insert \"%s\" into environment: %m",
					G_STRFUNC, env[i]);
				break;
			}
		}
	}
}
#else	/* !HAS_SETENV */
static void
progname_args_copy_environ(void)
{
	progname_args_copy_strvec(environ);
}
#endif	/* HAS_SETENV */

/**
 * Save original program arguments and compute the contiguous space they
 * were using, together with the original environment.
 */
static void
progname_args_save(void)
{
	size_t envc, n;
	iovec_t *iov;
	char *name;

	progstart_dup(NULL, NULL);		/* Keep original! */

	/*
	 * On platforms that have getprogname(), the string can point to the
	 * original argv[0] which we're about to supersede.  Duplicate it first.
	 */

	name = xstrdup(getprogname());
	setprogname(name);

#ifndef HAS_SETPROGNAME
	xfree(name);			/* Our implementation already duplicates */
#endif

	/*
	 * The GNU libc keeps track of the program invocation name as well,
	 * which we must duplicate before superseding argv[0].
	 */

#ifdef HAS_PROGRAM_INVOCATION_NAME
	{
		extern char *program_invocation_name;
		extern char *program_invocation_short_name;

		name = xstrdup(program_invocation_name);
		program_invocation_name = name;
		program_invocation_short_name =
			deconstify_char(filepath_basename(name));
	}
#endif	/* HAS_PROGRAM_INVOCATION_NAME */

	envc = strvec_count(environ);
	n = progname_argc + envc;

	iov = iov_alloc_n(n);
	iov_reset_n(iov, n);

	iov_init_from_string_vector(&iov[0], n,
		(char **) progname_argv, progname_argc);

	iov_init_from_string_vector(&iov[progname_argc], n - progname_argc,
		environ, envc);

	progname_info.argstart = progname_argv[0];
	progname_info.arglen = iov_contiguous_size(iov, n);

	iov_free(iov);

	/*
	 * Since setproctitle() is going to write over the space used by the
	 * original arguments and the environment, we need to duplicate these
	 * value elsewhere in memory.
	 */

	progname_args_copy_strvec((char **) progname_argv);
	progname_args_copy_environ();

	/*
	 * Scrap references to the original arguments, to make sure ps(1)
	 * cannot see them any more.
	 */

	{
		int i;

		for (i = 1; i < progname_argc; i++)
			progname_argv[i] = NULL;
	}
}

/**
 * @return the memory address where setproctitle() can start writing
 */
char *
progname_args_start(void)
{
	progstart_called(G_STRFUNC);

	ONCE_FLAG_RUN(progname_args_saved, progname_args_save);

	return progname_info.argstart;
}

/**
 * @return the length of the memory region where setproctitle() can write
 */
size_t
progname_args_size(void)
{
	progstart_called(G_STRFUNC);

	ONCE_FLAG_RUN(progname_args_saved, progname_args_save);

	return progname_info.arglen;
}
#endif	/* !HAS_SETPROCTITLE */

/* vi: set ts=4 sw=4 cindent: */
