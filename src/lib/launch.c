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
 * Process launcher.
 *
 * This is a compatibility layer: UNIX systems launch new processes by
 * the ways of fork() and exec(), whilst Windows only has spawn().
 *
 * The launch() interface gives a common API to the two systems and allows
 * us to provide a decent waitpid() emulation on Windows.
 *
 * As is traditional for this family of functions in the litterature,
 * the radix "launch" is supplemented with additional letters which give
 * a hint towards the function signature...
 *
 * The first letter is either 'l' or 'v':
 *
 * 'l' when command line arguments are passed as arguments to the routine.
 * 'v' when command line arguments are passed in a vector given to the routine.
 *
 * Then, either 'p', 'e', or both can be appended, in that order:
 *
 * 'p' is appended when the actual command needs to be located using the PATH
 * 'e' is appended when the last argument provides an environment vector.
 *
 * The real core function is usually the 've' one, others being wrappers
 * which transform their arguments into the ones expected by the 've' routine.
 *
 * @author Raphael Manfredi
 * @date 2015
 */

#include "common.h"

#include "launch.h"

#include "argv.h"

#include "override.h"		/* Must be the last header included */

/*
 * On Windows, we use mingw_launchve() and launchve() is remapped by cpp
 * to point to that routine instead, so the version compiled here is for
 * UNIX systems.
 */

#ifndef MINGW32

#ifndef HAS_VFORK
#define vfork() fork()
#endif

/**
 * Launch `path', supplying it with arguments argv[] and environment envp[].
 *
 * The argv[0] argument is the name the new process will see, but the actual
 * process to launch is located in the file `path'.
 *
 * @return -1 on failure, the PID of the child process otherwise.
 */
pid_t
launchve(const char *path, char *const argv[], char *const envp[])
{
	pid_t c;
	extern char **environ;

	g_assert(path != NULL);

	switch ((c = vfork())) {
	case -1:
		return -1;
	case 0:				/* Child process */
		execve(path, argv, NULL == envp ? environ : envp);
		_exit(EXIT_FAILURE);
	default:			/* Parent process */
		break;
	}

	return c;
}

#endif	/* !MINGW32 */

/**
 * Vectorized version of launchl() or launchle().
 *
 * It is a wrapper over launchve() to construct the argv[] array from
 * an argument list.
 */
pid_t
launchle_v(const char *path, const char *arg, va_list ap, char *const envp[])
{
	pid_t pid;
	char **argv;

	argv = argv_create(arg, ap);
	pid = launchve(path, argv, envp);
	argv_free_null(&argv);

	return pid;
}

/**
 * Vectorized version of launchl().
 *
 * It is a wrapper over launchve() to construct the argv[] array from
 * an argument list.
 */
pid_t
launchl_v(const char *path, const char *arg, va_list ap)
{
	return launchle_v(path, arg, ap, NULL);
}

/**
 * Launch `path', supplying it with arguments starting with `arg' and
 * followed by the listed additional argument strings, up to the trailing
 * NULL sentinel.
 *
 * @param path		the executable to launch
 * @param arg		what will be given as argv[0] to the new process
 *
 * @return -1 on failure, the PID of the child process otherwise.
 */
pid_t
launchl(const char *path, const char *arg, ...)
{
	pid_t pid;
	va_list ap;

	va_start(ap, arg);
	pid = launchl_v(path, arg, ap);
	va_end(ap);

	return pid;
}

/**
 * Launch `path', supplying it with arguments starting with `arg' and
 * followed by the listed additional argument strings, up to the trailing
 * NULL sentinel, followed by a last argument being the new environment.
 *
 * @param path		the executable to launch
 * @param arg		what will be given as argv[0] to the new process
 * @param ...		argument list, NULL-terminated
 * @param envp		the environment strings to setup for the new process
 *
 * @return -1 on failure, the PID of the child process otherwise.
 */
pid_t
launchle(const char *path, const char *arg, ...)
{
	pid_t pid;
	va_list ap;
	char **envp;

	va_start(ap, arg);
	while (NULL != va_arg(ap, char *))
		/* empty */;
	envp = va_arg(ap, char **);
	va_end(ap);

	va_start(ap, arg);
	pid = launchle_v(path, arg, ap, envp);
	va_end(ap);

	return pid;
}

/* vi: set ts=4 sw=4 cindent: */
