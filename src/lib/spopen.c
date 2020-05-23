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
 *      51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *----------------------------------------------------------------------
 */

/**
 * @ingroup lib
 * @file
 *
 * Simple popen() using file descriptors and skipping the shell.
 *
 * This is a compatibility layer: UNIX systems have a full-blown popen()
 * which launches "sh -c command" in a child process whilst Windows lacks
 * both (the popen() call and the shell).
 *
 * The spopen() interface gives a common API to the two systems and allows
 * simpler management of the link, as if a pipe() had been setup -- unlike
 * popen() which uses stdio, spopen() returns a single file descriptor that
 * must be closed via spclose().
 *
 * Because the shell is bypassed, spopen() includes a mandatory fd[] argument
 * which lets the parent process setup the child stdin/stdout and stderr.
 *
 * Because the shell is bypassed, spopen() is more secure because the
 * command arguments are not interpreted and therefore do not require any
 * escaping of possible shell meta-characters.
 *
 * As is traditional for this family of functions in the litterature,
 * the radix "spopen" is supplemented with additional letters which give
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

#include "spopen.h"

#include "argv.h"
#include "exit2str.h"
#include "fd.h"
#include "file.h"
#include "halloc.h"
#include "hashtable.h"
#include "once.h"

#include "override.h"		/* Must be the last header included */

static hash_table_t *spopen_fds;	/* Maps an fd to a child PID */
static once_flag_t spopen_inited;

/**
 * Initialize the spopen layer, once.
 */
static void
spopen_init_once(void)
{
	g_assert(NULL == spopen_fds);

	spopen_fds = hash_table_new_not_leaking();
	hash_table_thread_safe(spopen_fds);
}

#ifdef MINGW32
#define STATIC
#else
#define STATIC static
#endif

/**
 * Record the association between the pipe file descriptor and the child PID,
 * so that spclose() can determine whom to wait for.
 *
 * This routine is only visible to the outside world on Windows, because we
 * want to let mingw_spopenve() see it.
 *
 * @param fd		the fd that spopen() will return to parent
 * @param pid		the process ID of the created child process
 */
STATIC void
spopen_fd_map(int fd, pid_t pid)
{
	pid_t cpid;

	g_assert_log(is_valid_fd(fd), "%s(): fd=%d", G_STRFUNC, fd);
	g_assert(pid != 0);

	ONCE_FLAG_RUN(spopen_inited, spopen_init_once);

	hash_table_lock(spopen_fds);

	/*
	 * If we already know about `fd' in our table, it means they forgot to
	 * spclose() the descriptor but actually issued close() on it.
	 */

	cpid = (ulong) hash_table_lookup(spopen_fds, int_to_pointer(fd));

	if G_UNLIKELY(cpid != 0) {
		int status;

		s_carp("%s(): fd #%d was already used by spopen() with child PID %lu",
			G_STRFUNC, fd, (ulong) cpid);

		/*
		 * Wait for this child we have lost, to avoid zombies.
		 */

		if (-1 == waitpid(cpid, &status, WNOHANG)) {
			s_warning("%s(): cannot wait() for PID %lu: %m",
				G_STRFUNC, (ulong) cpid);
		} else {
			s_info("%s(): PID %lu %s",
				G_STRFUNC, (ulong) cpid, exit2str(status));
		}
	}

	hash_table_replace(spopen_fds,
		int_to_pointer(fd),
		ulong_to_pointer((ulong) pid));

	hash_table_unlock(spopen_fds);
}

/**
 * Caller wants to wait for the child and close fd directly.
 *
 * If this was called with forget=TRUE, an spclose() is no longer possible,
 * and the pipe fd must be manually close()d.
 *
 * @param fd		the pipe fd returned any of the spopen() function family
 * @param forget	if TRUE, caller will have to close() fd himself
 *
 * @return the PID of the child process associated with fd, 0 on error.
 */
pid_t
sppid(int fd, bool forget)
{
	pid_t pid;

	if (!is_valid_fd(fd)) {
		s_carp("%s(): invalid fd #%d", G_STRFUNC, fd);
		errno = EBADF;
		return 0;
	}

	if G_UNLIKELY(NULL == spopen_fds)
		goto not_pipe;

	pid = (ulong) hash_table_lookup(spopen_fds, int_to_pointer(fd));

	if (0 == pid) {
		s_carp("%s(): fd #%d is not known to have been issued by spopen()",
			G_STRFUNC, fd);
		goto not_pipe;
	}

	if (forget)
		hash_table_remove(spopen_fds, int_to_pointer(fd));

	return pid;

not_pipe:
	errno = ECHILD;
	return 0;
}

/**
 * Close fd associated with a pipe, wait for child and return its exit status.
 *
 * @param fd	the fd obtained from one of the spopen() function family
 *
 * @return the child exit status, -1 with errno set otherwise.
 */
int
spclose(int fd)
{
	pid_t pid;
	int status;

	pid = sppid(fd, TRUE);

	if (0 == pid)
		return -1;

	/*
	 * We can close the pipe fd now.
	 */

	if (-1 == close(fd)) {
		s_carp("%s(): unexpected error closing pipe fd #%d to PID %lu: %m",
			G_STRFUNC, fd, (ulong) pid);
	}

	/*
	 * And wait for the child... indefinitely.
	 */

	if (-1 == waitpid(pid, &status, 0))
		return -1;

	return status;
}

/*
 * On Windows, we use mingw_spopenve() and spopenve() is remapped by cpp
 * to point to that routine instead, so the version compiled here is for
 * UNIX systems.
 */

#ifndef MINGW32

/**
 * Open a pipe with a new process.
 *
 * The mode string must contain either "r" or "w", depending on whether we
 * are opening a pipe to read from the child or to write into it.  Optionally,
 * the "e" letter requests that the pipe be closed on future exec().
 *
 * The fd[] array allows redirection of the child process stdin (when opening
 * a pipe for reading) or stdout (when opening a pipe for writing) via fd[0],
 * and setting a different stderr via fd[1].  To avoid redirection, use -1.
 * This is needed since we're not using a shell to parse the arguments and we
 * need to allow some basic redirections.
 *
 * When fd[i] is -1, the child's descriptor simply inherits the corresponding
 * parent descriptor (stdin in mode "r" for i=0, stdout in mode "w" for i=0,
 * and stderr for i=1).  For readability, -1 is actually symbolically defined
 * as SPOPEN_ASIS.
 *
 * When fd[i] is -2, the parent opens "/dev/null" in the proper mode and gives
 * that descriptor.  For readability, -2 is actually known as SPOPEN_DEV_NULL.
 *
 * When fd[1] (forbidden for fd[0]) is -3, stderr is a dup() of the parent's
 * stdout, the equivalent of the commonly used shell redirection "2>&1 >other"
 * (that is, stdout in the child can be pointing to another file, as defined
 * by fd[0]).  The -3 is symbolically known as SPOPEN_PARENT_STDOUT.
 *
 * When fd[1] (forbidden for fd[0]) is -4, stderr is a dup() of the defined
 * stdout, the equivalent of the commonly used shell redirection ">other 2>&1"
 * (that is, stdout and stderr in the child point to the same file, as defined
 * by fd[0]).  The -4 is symbolically known as SPOPEN_CHILD_STDOUT.
 *
 * If fd[i], for i = {0,1}, contains a valid descriptor, that descriptor is
 * given to the child process and is closed in the parent process before
 * returning.
 *
 * As a convenience, since this is the most likely scenario, a NULL fd[]
 * array is understood as meaning fd[0] = fd[1] = SPOPEN_ASIS.
 *
 * The argv[0] argument is the name the new process will see, but the actual
 * process to launch is located in the file `path'.
 *
 * @param path		the process to launch
 * @param mode		"r" for read, "w" for write, with "e" for close-on-exec
 * @param fd[]		fd[0] is what stdin/stdout must be, fd[1] is for stderr
 * @param argv[]	the argument vector for the new process
 * @param envp[]	the environment to supply to the new process
 *
 * @return -1 on failure, the fd to read from / write to the child process
 * otherwise.
 */
int
spopenve(const char *path, const char *mode, int fd[2],
	char *const argv[], char *const envp[])
{
	bool p_read = FALSE, p_write = FALSE, p_cloexec = FALSE;
	int pipefd[2];
	int pc[2];		/* pc[0] = parent's fd, pc[1] = child's fd */
	pid_t child;
	const char *p = mode;
	int c, r;
	int dfd[2];
	static int has_pipe2;	/* 0 = unknown, 1 = yes, -1 = no */

	g_assert(path != NULL);
	g_assert(mode != NULL);
	g_assert(argv != NULL);

	if (NULL == fd) {
		fd = dfd;
		fd[0] = fd[1] = SPOPEN_ASIS;
	}

	while ((c = *p++) != '\0') {
		switch (c) {
		case 'r': p_read    = TRUE; break;
		case 'w': p_write   = TRUE; break;
		case 'e': p_cloexec = TRUE; break;
		default: goto bad_arg;
		}
	}

	if (0 == (p_read ^ p_write)) {
		s_carp("%s(): cannot specify both \"r\" and \"w\", mode was \"%s\"",
			G_STRFUNC, mode);
		goto bad_arg;
	}

	if (SPOPEN_PARENT_STDOUT == fd[0] || SPOPEN_CHILD_STDOUT == fd[0]) {
		s_carp("%s(): cannot specify %d in fd[0], only meaningful for fd[1]",
			G_STRFUNC, fd[0]);
		goto bad_arg;
	}

#ifdef HAS_PIPE2
	if (p_cloexec && has_pipe2 >= 0) {
		r = pipe2(pipefd, O_CLOEXEC);
		if G_UNLIKELY(0 == has_pipe2)
			has_pipe2 = (-1 == r && ENOSYS == errno) ? -1 : 1;

		if (has_pipe2 > 0 && r < 0)
			goto pipe_failed;
	}
#endif	/* HAS_PIPE2 */

	if (!p_cloexec || has_pipe2 < 0) {
		if (-1 == pipe(pipefd))
			goto pipe_failed;
	}

	if (p_read) {
		pc[0] = pipefd[0];
		pc[1] = pipefd[1];
	} else {
		pc[0] = pipefd[1];
		pc[1] = pipefd[0];
	}

	switch ((child = fork())) {
	case -1:			/* could not fork() */
		s_carp("%s(): cannot fork(): %m", G_STRFUNC);
		close(pc[0]);
		close(pc[1]);
		goto fork_failed;
	case 0:				/* child process */
		break;
	default:			/* parent process */
		close(pc[1]);	/* That's the child's end of the pipe */
		spopen_fd_map(pc[0], child);
		goto parent_done;
	}

	/*
	 * We are now in the child process.
	 */

	close(pc[0]);		/* That's the parent's end of the pipe */

	/* Handle stderr = parent's stdout before we change child's stdout */

	if (SPOPEN_PARENT_STDOUT == fd[1]) {
		if (-1 == dup2(STDOUT_FILENO, STDERR_FILENO))
			goto child_failed;
	}

	/* Handle child's standard fd not contected to the pipe */

	switch (fd[0]) {
	case SPOPEN_ASIS:
		r = p_read ? STDIN_FILENO : STDOUT_FILENO;
		break;
	case SPOPEN_DEV_NULL:
		r = open("/dev/null", p_read ? O_RDONLY : O_WRONLY);
		if (-1 == r)
			goto child_failed;
		break;
	default:
		r = fd[0];
		break;
	}

	/* Redirect stdin / stdout */

	{
		int t = p_read ? STDIN_FILENO : STDOUT_FILENO;	/* target */

		if (t != r) {
			if (-1 == dup2(r, t))
				goto child_failed;
			close(r);
		}

		t = p_read ? STDOUT_FILENO : STDIN_FILENO;
		if (-1 == dup2(pc[1], t))
			goto child_failed;
		close(pc[1]);			/* Child's end now mapped to stdout / stdin */
	}

	/* Handle stderr redirections */

	switch (fd[1]) {
	case SPOPEN_PARENT_STDOUT:
		goto redir_done;		/* Already handled above */
	case SPOPEN_ASIS:
		goto redir_done;		/* Nothing to do */
	case SPOPEN_DEV_NULL:
		r = open("/dev/null", O_WRONLY);
		if (-1 == r)
			goto child_failed;
		break;
	case SPOPEN_CHILD_STDOUT:
		r = STDOUT_FILENO;
		break;
	default:
		r = fd[1];
		break;
	}

	/* Redirect stderr */

	if (r != STDERR_FILENO) {
		if (-1 == dup2(r, STDERR_FILENO))
			goto child_failed;
		close(r);
	}

	/* FALL THROUGH */

redir_done:

	execve(path, argv, envp);
	_exit(127);		/* 127 is traditional for child exec() failure */

	/* FALL THROUGH */

child_failed:
	_exit(126);		/* 126 is our indication that I/O setup failed */

parent_done:
	/*
	 * Close descriptors given to child for redirection: the parent
	 * process no longer needs them.
	 */
	for (c = 0; c < 2; c++) {
		if (is_valid_fd(fd[c]))
			close(fd[c]);
	}
	return pc[0];

bad_arg:
	errno = EINVAL;
	pc[0] = -1;
	goto parent_done;

pipe_failed:
	s_carp("%s(): pipe%s() failed: %m", G_STRFUNC, has_pipe2 > 0 ? "2" : "");

	/* FALL THROUGH */

fork_failed:
	pc[0] = -1;
	goto parent_done;
}

#endif	/* !MINGW32 */

/**
 * Same as spopenve() but program is located in the PATH and errno is set
 * to ENOENT if we cannot locate the program.
 */
int
spopenvpe(const char *prog, const char *mode, int fd[2],
	char *const argv[], char *const envp[])
{
	int pfd;
	char *path;

	path = file_locate_from_path(prog);

	if (NULL == path) {
		errno = ENOENT;
		return -1;
	}

	pfd = spopenve(path, mode, fd, argv, envp);
	hfree(path);

	return pfd;
}

/**
 * Vectorized version of spopenl() or spopenle().
 *
 * It is a wrapper over spopenve() to construct the argv[] array from
 * an argument list.
 *
 * @return -1 on failure, the fd to read from / write to the child process
 * otherwise.
 */
int
spopenle_v(const char *path, const char *mode, int fd[2],
	const char *arg, va_list ap, char *const envp[])
{
	int pfd;
	char **argv;

	argv = argv_create(arg, ap);
	pfd = spopenve(path, mode, fd, argv, envp);
	argv_free_null(&argv);

	return pfd;
}

/**
 * Vectorized version of spopenl().
 *
 * It is a wrapper over spopenve() to construct the argv[] array from
 * an argument list.
 *
 * @return -1 on failure, the fd to read from / write to the child process
 * otherwise.
 */
int
spopenl_v(const char *path, const char *mode, int fd[2],
	const char *arg, va_list ap)
{
	return spopenle_v(path, mode, fd, arg, ap, NULL);
}

/**
 * Launch `path', supplying it with arguments starting with `arg' and
 * followed by the listed additional argument strings, up to the trailing
 * NULL sentinel, after opening a pipe with the current process.
 *
 * See spopenve() for the semantics of the fd[] array and of the mode string.
 *
 * @param path		the executable to launch
 * @param mode		"r" for read, "w" for write, with "e" for close-on-exec
 * @param fd[]		fd[0] is what stdin/stdout must be, fd[1] is for stderr
 * @param arg		what will be given as argv[0] to the new process
 *
 * @return -1 on failure, the fd to read from / write to the child process
 * otherwise.
 */
int
spopenl(const char *path, const char *mode, int fd[2], const char *arg, ...)
{
	int pfd;
	va_list ap;

	va_start(ap, arg);
	pfd = spopenl_v(path, mode, fd, arg, ap);
	va_end(ap);

	return pfd;
}

/**
 * Launch `prog', supplying it with arguments starting with `arg' and
 * followed by the listed additional argument strings, up to the trailing
 * NULL sentinel, after opening a pipe with the current process.
 *
 * The actual program is located in the PATH, and errno is set to ENOENT if
 * we cannot locate the program.
 *
 * See spopenve() for the semantics of the fd[] array and of the mode string.
 *
 * @param path		the executable to launch
 * @param mode		"r" for read, "w" for write, with "e" for close-on-exec
 * @param fd[]		fd[0] is what stdin/stdout must be, fd[1] is for stderr
 * @param arg		what will be given as argv[0] to the new process
 *
 * @return -1 on failure, the fd to read from / write to the child process
 * otherwise.
 */
int
spopenlp(const char *prog, const char *mode, int fd[2], const char *arg, ...)
{
	int pfd;
	va_list ap;
	char *path;

	path = file_locate_from_path(prog);

	if (NULL == path) {
		errno = ENOENT;
		return -1;
	}

	va_start(ap, arg);
	pfd = spopenl_v(path, mode, fd, arg, ap);
	va_end(ap);

	hfree(path);

	return pfd;
}

/**
 * Launch `path', supplying it with arguments starting with `arg' and
 * followed by the listed additional argument strings, up to the trailing
 * NULL sentinel, followed by a last argument being the new environment,
 * after opening a pipe with the current process.
 *
 * See spopenve() for the semantics of the fd[] array and of the mode string.
 *
 * @param path		the executable to launch
 * @param mode		"r" for read, "w" for write, with "e" for close-on-exec
 * @param fd[]		fd[0] is what stdin/stdout must be, fd[1] is for stderr
 * @param arg		what will be given as argv[0] to the new process
 * @param ...		argument list, NULL-terminated
 * @param envp		the environment strings to setup for the new process
 *
 * @return -1 on failure, the fd to read from / write to the child process
 * otherwise.
 */
int
spopenle(const char *path, const char *mode, int fd[2], const char *arg, ...)
{
	int pfd;
	va_list ap;
	char **envp;

	va_start(ap, arg);
	while (NULL != va_arg(ap, char *))
		/* empty */;
	envp = va_arg(ap, char **);
	va_end(ap);

	va_start(ap, arg);
	pfd = spopenle_v(path, mode, fd, arg, ap, envp);
	va_end(ap);

	return pfd;
}

/* vi: set ts=4 sw=4 cindent: */
