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

static const struct {
	const char name[16];
	int signo;
} signals[] = {
#define D(x) { #x, x }
#ifdef SIGBUS
	D(SIGBUS),
#endif
#ifdef SIGTRAP
	D(SIGTRAP),
#endif
	D(SIGABRT),
	D(SIGFPE),
	D(SIGILL),
	D(SIGSEGV)
#undef D
};

#define print_str(x) \
G_STMT_START { \
	if (iov_cnt < G_N_ELEMENTS(iov)) { \
		const char *ptr = (x); \
		if (ptr) { \
			iov[iov_cnt].iov_base = (char *) ptr; \
			iov[iov_cnt].iov_len = strlen(ptr); \
			iov_cnt++; \
		} \
	} \
} G_STMT_END

static void
crash_message(const char *reason)
{
	struct iovec iov[5];
	unsigned iov_cnt = 0;
	char pid_buf[22];
	
	print_str("CRASH (pid=");
	print_str(print_number(pid_buf, sizeof pid_buf, getpid()));
	print_str(") by ");
	print_str(reason);
	print_str("\n");
	writev(STDERR_FILENO, iov, iov_cnt);
}


static void
crash_exec(const char *pathname, const char *argv0)
{
   	const char *pid_str;
	char pid_buf[22];
	pid_t pid;

	pid_str = print_number(pid_buf, sizeof pid_buf, getpid());

	/* Make sure we don't exceed the system-wide file descriptor limit */
	close_file_descriptors(3);

	pid = fork();
	switch (pid) {
	case 0:
		{
			char const *argv[8];

			argv[0] = pathname;
			argv[1] = argv0;
			argv[2] = pid_str;
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
		}
		break;
	case -1:
		break;
	default:
		{
			int status;
			waitpid(pid, &status, 0);
		}
	}
}

static void
crash_handler(int signo)
{
	const char *name = NULL;
	unsigned i;

	(void) signo;

	for (i = 0; i < G_N_ELEMENTS(signals); i++) {
		set_signal(signals[i].signo, SIG_DFL);
		if (signals[i].signo == signo) {
			name = signals[i].name;
		}
	}
	crash_message(name);
	if (vars.pathname) {
		crash_exec(vars.pathname, vars.argv0);
	}
	if (vars.pause_process) {
		sigset_t oset;

		if (sigprocmask(SIG_BLOCK, NULL, &oset) != -1) {
			sigsuspend(&oset);
		}
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
		set_signal(signals[i].signo, crash_handler);
	}
}

/* vi: set ts=4 sw=4 cindent: */
