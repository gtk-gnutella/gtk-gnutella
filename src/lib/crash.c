/*
 * Copyright (c) 2006 Christian Biere <christianbiere@gmx.de>
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

/**
 * @ingroup lib
 * @file
 *
 * A simple crash handler.
 *
 * @author Christian Biere
 * @date 2006
 */

#include "common.h"

RCSID("$Id$")

#include "lib/misc.h"
#include "lib/vmm.h"

#include "lib/override.h"		/* Must be the last header included */

static struct {
	const char *pathname;	/* The file to execute. */
	const char *argv0;		/* The original argv[0]. */
	int pause_process;
} vars;

static const int signals[] = {
#ifdef SIGBUS
	SIGBUS,
#endif
#ifdef SIGTRAP
	SIGTRAP,
#endif
	SIGABRT,
	SIGFPE,
	SIGILL,
	SIGSEGV
};

static void
crash_exec(const char *pathname, const char *argv0)
{
	char pid_buf[32], *pid_ptr;
	pid_t pid;

	pid = getpid();
	pid_ptr = &pid_buf[sizeof pid_buf - 1];
	*pid_ptr = '\0';
	do {
		*--pid_ptr = (pid % 10) + '0';
		pid /= 10;
	} while (pid && pid_ptr != pid_buf);

	/* Make sure we don't exceed the system-wide file descriptor limit */
	close_file_descriptors(3);

	pid = fork();
	if (0 == pid) {
		char const *argv[8];

		argv[0] = pathname;
		argv[1] = argv0;
		argv[2] = pid_ptr;
		argv[3] = NULL;

		/* Assign stdin, stdout and stdout to /dev/null */
		if (
			close(STDIN_FILENO) ||
			close(STDOUT_FILENO) ||
			close(STDERR_FILENO) ||
			STDIN_FILENO  != open("/dev/null", O_RDONLY, 0) ||
			STDOUT_FILENO != open("/dev/null", O_WRONLY, 0) ||
			STDERR_FILENO != dup(STDOUT_FILENO) ||
			-1 == setsid() || 
			execve(argv[0], (const void *) argv, NULL)
		) {
			_exit(EXIT_FAILURE);
		}
	} else if ((pid_t) -1 != pid) {
		int status;
		waitpid(pid, &status, 0);
	}
}

static void
crash_handler(int signo)
{
	unsigned i;

	(void) signo;

	for (i = 0; i < G_N_ELEMENTS(signals); i++) {
		set_signal(signals[i], SIG_DFL);
	}
	if (vars.pathname) {
		crash_exec(vars.pathname, vars.argv0);
	}
	if (vars.pause_process) {
		sigset_t oset;

		sigprocmask(SIG_BLOCK, NULL, &oset);
		sigsuspend(&oset);
	}
	_exit(EXIT_FAILURE);
}

/**
 * Installs a simple crash handler.
 * 
 * @param pathname The pathname of the program to execute on crash.
 * @param argv0 The original argv[0] from main().
 */
void
crash_init(const char *pathname, const char *argv0, int pause_process)
{
	unsigned i;

	vars.pathname = prot_strdup(pathname);
	vars.argv0 = prot_strdup(argv0);
	vars.pause_process = pause_process;

	for (i = 0; i < G_N_ELEMENTS(signals); i++) {
		set_signal(signals[i], crash_handler);
	}
}

/* vi: set ts=4 sw=4 cindent: */
