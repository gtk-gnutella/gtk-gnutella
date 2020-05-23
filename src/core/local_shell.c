/*
 * Copyright (c) 2006, Christian Biere
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
 * @ingroup core
 * @file
 *
 * Local shell
 *
 * This implements an alterego of gtk-gnutella to access the local socket
 * of gtk-gnutella.
 *
 * @author Christian Biere
 * @date 2006
 */

/**
 * @note This file can also be compiled as a tiny standalone tool
 *       with no external dependencies (not even GLib):
 *
 * cc -o gtkg-shell -DLOCAL_SHELL_STANDALONE local_shell.c
 */

#ifdef LOCAL_SHELL_STANDALONE

/**
 * @bug	 As compat_poll() was outsourced the stand-alone requires poll() now.
 */
#define HAS_SOCKADDR_UN
#define HAS_POLL
#define FALSE 0
#define TRUE 1
#define is_running_on_mingw() 0
#define compat_poll poll
#define compat_connect connect
#define compat_socket socket
#define unix_read read
#define unix_write write
#define vstrlen strlen

typedef struct sockaddr_un sockaddr_unix_t;

#include <sys/types.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <pwd.h>

#define ARYLEN(x)		(x), sizeof(x)

static inline void
fd_close(int *fd_ptr)
{
	if (*fd_ptr >= 0) {
		close(*fd_ptr);
		*fd_ptr = -1;
	}
}

static inline int
is_temporary_error(int e)
{
	return EAGAIN == e || EINTR == e;
}

void
fd_set_nonblocking(int fd)
{
	int ret, flags;

	ret = fcntl(fd, F_GETFL);
	flags = ret | O_NONBLOCK;
	if (flags != ret)
		(void) fcntl(fd, F_SETFL, flags);
}

size_t
cstr_bcpy(char *dst, size_t len, const char *src)
{
	if (len != 0)
		strncpy(dst, src, len - 1);
	return strlen(src);
}


#else	/* !LOCAL_SHELL_STANDALONE */

#include "common.h"

#include "core/local_shell.h"

#include "lib/cstr.h"
#include "lib/misc.h"
#include "lib/fd.h"
#include "lib/log.h"
#include "lib/compat_poll.h"
#include "lib/compat_un.h"

#include "lib/override.h"

static inline ssize_t
unix_read(int fd, void *buf, size_t size)
{
	/*
	 * On Windows, we have to call s_read() for sockets, not read(),
	 * or it does not work since winsock descriptors are distinct
	 * from other file objects and the Windows kernel is too stupid
	 * to do the dirty work for us.
	 *		--RAM, 2011-01-05
	 */

	if (is_running_on_mingw()) {
		ssize_t ret = s_read(fd, buf, size);
		if (ret >= 0 || ENOTSOCK != errno)
			return ret;
		/* FALL THROUGH -- fd is a plain file, not a socket */
	}

	return read(fd, buf, size);
}

static inline ssize_t
unix_write(int fd, const void *buf, size_t size)
{
	/*
	 * On Windows, we have to call s_write() for sockets, not write().
	 * API fragmentation (winsocks versus other handles) at its best.
	 *		--RAM, 2011-01-05
	 */

	if (is_running_on_mingw()) {
		ssize_t ret = s_write(fd, buf, size);
		if (ret >= 0 || ENOTSOCK != errno)
			return ret;
		/* FALL THROUGH -- fd is a plain file, not a socket */
	}

	return write(fd, buf, size);
}

#undef perror
#define perror(x)	s_warning("%s: %m", (x));

#endif	/* LOCAL_SHELL_STANDALONE */

#ifdef USE_READLINE
#include <readline/readline.h>
#include <readline/history.h>
#endif

struct shell_buf {
	char *buf;		/**< Arbitrary buffer maybe static/local/dynamic */
	size_t size;	/**< Amount of bytes that buf can hold */
	size_t fill;	/**< Amount readable bytes in buf from pos */
	size_t pos;		/**< Read position in buf */
	unsigned eof:1;		/**< If set, no further read() possible due to EOF */
	unsigned hup:1;		/**< If set, no further write() possible due to HUP */
	unsigned readable:1;	/**< If set, read() should succeed */
	unsigned writable:1;	/**< If set, write() should succeed */
	unsigned shutdown:1;	/**< If set, a shutdown has been signalled */
	unsigned wrote:1;	/**< If set, last call to write() succeeded */
	unsigned server:1;	/**< If set, buffer going to server */
};

struct line_buf {
	char *buf;			/**< Dynamically allocated; use free() */
	size_t length;		/**< Length of the string in buf */
	size_t pos;			/**< Read position relative to buf */
};


/**
 * Attempts to fill the shell buffer from the given file descriptor, however,
 * the buffer is not further filled before it is completely empty.
 */
static int
read_data(int fd, struct shell_buf *sb)
{
	if (!sb) {
		return -1;
	}
	if (0 == sb->fill && sb->readable) {
		ssize_t ret;

		ret = unix_read(fd, sb->buf, sb->size);
		switch (ret) {
		case 0:
			sb->eof = 1;
			break;
		case -1:
			if (!is_temporary_error(errno)) {
				if (sb->server) {
					perror("read() from server failed");
				} else {
					perror("read() failed");
				}
				return -1;
			}
			break;
		default:
			sb->fill = ret;
		}
	}
	return 0;
}

/**
 * Attempts to fill the shell buffer using readline(), however,
 * the buffer is not further filled before it is completely empty.
 */
static int
read_data_with_readline(struct line_buf *line, struct shell_buf *sb)
#ifdef USE_READLINE
{
	if (!line || !sb) {
		return -1;
	}

	if (0 == sb->fill) {
		if (!line->buf) {
			errno = 0;
			line->buf = readline("");
			if (!line->buf && !is_temporary_error(errno)) {
				sb->eof = 1;
			}
			line->length = line->buf ? vstrlen(line->buf) : 0;
			line->pos = 0;
		}
		if (line->buf) {
			if (line->pos < line->length) {
				size_t n;

				n = line->length - line->pos;
				if (n > sb->size) {
					n = sb->size;
				}
				memcpy(sb->buf, &line->buf[line->pos], n);
				sb->fill = n;
				line->pos += n;
			}
			if (line->pos == line->length && sb->fill < sb->size) {
				sb->buf[sb->fill] = '\n';
				sb->fill++;
				free(line->buf);
				line->buf = NULL;
				line->length = 0;
				line->pos = 0;
			}
		}
	}
	return 0;
}
#else	/* !USE_READLINE */
{
	(void) line;
	(void) sb;
	return -1;
}
#endif	/* USE_READLINE */

/**
 * Attempts to flush the shell buffer to the given file descriptor.
 */
static int
write_data(int fd, struct shell_buf *sb)
{
	if (!sb) {
		return -1;
	}
	sb->wrote = 0;
	if (sb->fill > 0 && sb->writable) {
		ssize_t ret;

		ret = unix_write(fd, &sb->buf[sb->pos], sb->fill);
		switch (ret) {
		case 0:
			sb->hup = 1;
			break;
		case -1:
			if (EPIPE == errno) {
				sb->hup = 1;
			}
			if (!is_temporary_error(errno)) {
				if (sb->server) {
					perror("write() to server failed");
				} else if (!sb->hup) {
					perror("write() failed");
				}
				return -1;
			}
			break;
		default:
			sb->fill -= (size_t) ret;
			if (sb->fill > 0) {
				sb->pos += (size_t) ret;
			} else {
				sb->pos = 0;
			}
			sb->wrote = 1;
		}
	}
	return 0;
}

/**
 * Sleeps until any I/O event happens or the timeout expires.
 * @return -1 On error;
 *			0 If the timeout expired;
 *		   otherwise the amount of ready pollsets is returned.
 */
static int
wait_for_io(struct pollfd *fds, size_t n, int timeout)
{
	int ret;

	for (;;) {
		ret = compat_poll(fds, n, timeout);
		if (ret >= 0) {
			break;
		}
		if (ret < 0 && !is_temporary_error(errno)) {
			perror("compat_poll() failed");
			return -1;
		}
	}
	return ret;
}

static inline int
local_shell_mainloop(int fd)
{
	static struct shell_buf client, server;
	int tty = isatty(STDIN_FILENO);
	int interactive = tty != 0;
#ifdef USE_READLINE
	int use_readline = tty;
#else
	int use_readline = 0;
#endif	/* USE_READLINE */

#ifdef MINGW32
	if (!tty) {
		if (is_a_fifo(STDIN_FILENO)) {
			/*
			 * If stdin is a pipe, we can run with:
			 *
			 *    echo status | gtk-gnutella --shell
			 *
			 * or in interactive mode as in:
			 *
			 *	  gtk-gnutella --shell
			 *
			 * When running in an xterm and not from a Console window, stdin
			 * is indeed a pipe!
			 *
			 * To check the difference, look at whether we already have
			 * data on the pipe: chance are that if they run interactively,
			 * they will not type ahead but wait for the prompt.
			 */

			interactive = !mingw_stdin_pending(TRUE);
		}
	}
#endif	/* MINGW32 */

	{
		static char client_buf[4096], server_buf[4096];
		const char *helo = interactive ? "HELO\nINTR\n" : "HELO\n";

		server.buf = server_buf;
		server.size = sizeof server_buf;
		client.buf = client_buf;
		client.size = sizeof client_buf;
		client.server = 1;	/* Client is writing to server */

		/*
		 * Only send the empty INTR command when interactive.
		 */

		client.fill = vstrlen(helo);
		memcpy(client_buf, helo, client.fill);
	}

	for (;;) {

		if (use_readline) {
			static struct line_buf line;
			if (read_data_with_readline(&line, &client)) {
				return -1;
			}
		} else {
			if (read_data(STDIN_FILENO, &client)) {
				return -1;
			}
		}
		if (write_data(fd, &client)) {
			return -1;
		}
		if (read_data(fd, &server)) {
			return -1;
		}
		if (write_data(STDOUT_FILENO, &server)) {
			return -1;
		}

		if (server.eof && 0 == server.fill) {
			/*
			 * client.eof is not checked because if server.eof is set,
			 * we expect that the server has completely closed the
			 * connection and not merely done a shutdown(fd, SHUT_WR).
			 * The latter is only done on the client-side. Otherwise,
			 * the shell would not terminate before another write()
			 * (which should gain 0 or EPIPE) is attempted.
			 */
			if (client.fill > 0) {
				fprintf(stderr, "Server hung up unexpectedly!\n");
				return -1;
			}
			return 0;
		}
		if (client.eof && 0 == client.fill) {
			if ((server.eof && 0 == server.fill) || client.hup) {
				return 0;
			}
			if (!client.shutdown) {
				shutdown(fd, SHUT_WR);
				client.shutdown = 1;
			}
		}

		{
			struct pollfd fds[3];
			int ret;

			if (client.eof || client.fill > 0 || is_running_on_mingw()) {
				fds[0].fd = -1;
				fds[0].events = 0;
			} else {
				fds[0].fd = STDIN_FILENO;
				fds[0].events = POLLIN;
			}
			if (
				!is_running_on_mingw() &&
				((server.fill > 0 || server.wrote) && !server.hup)
			) {
				fds[1].fd = STDOUT_FILENO;
				fds[1].events = POLLOUT;
			} else {
				fds[1].fd = -1;
				fds[1].events = 0;
			}
			if (server.fill > 0 || server.eof) {
				fds[2].events = 0;
			} else {
				fds[2].events = POLLIN;
			}
			if ((client.fill > 0 || client.wrote) && !client.hup) {
				fds[2].events |= POLLOUT;
			}
			fds[2].fd = fds[2].events ? fd : -1;

			/*
			 * On Windows, don't poll forever but timeout after 150 ms
			 * so that we can handle stdin.  As soon as they hit the keyboard,
			 * we'll block on the read() though, when stdin is a console:
			 * input is line-buffered and the WIN32 calls under the read()
			 * front-end such as ReadFile() or ReadConsole() are responsible
			 * for that blocking.  It's not much a problem for the shell since
			 * in GTKG the remote server will not emit messages when waiting
			 * for the next command.
			 *
			 * Setting the console in unbuffered mode is a bad idea because
			 * in that case Windows also turns echo off.  Great feature.
			 *
			 * The 150 ms timeout means there's a slight delay when a new
			 * command is typed, but it's acceptable in practice and seems
			 * a good compromise: it is reasonably responsive whilst not
			 * wasting too much CPU doing active polling for new stdin input.
			 *		--RAM, 2011-01-05
			 */

			ret = wait_for_io(fds, 3, is_running_on_mingw() ? 150 : -1);
			if (ret < 0) {
				return -1;
			}
			client.readable = 0 != (fds[0].revents & (POLLIN  | POLLHUP));
			client.writable = 0 != (fds[2].revents & (POLLOUT | POLLHUP));

			server.readable = 0 != (fds[2].revents & (POLLIN  | POLLHUP));
			server.writable = 0 != (fds[1].revents & (POLLOUT | POLLHUP));

#ifdef MINGW32
			/*
			 * Under Windows, since we cannot poll() on stdin / stdout,
			 * we have to explicitly and actively probe stdin for more
			 * character data, when it's a tty.  For files or pipes, we
			 * assume stdin is always readable.
			 * Likewise, we assume stdout is always writable on Windows,
			 * which in practice is not going to be a problem.
			 *		--RAM, 2011-01-05
			 */

			client.readable = interactive ? mingw_stdin_pending(!tty) : TRUE;
			server.writable = TRUE;
#endif	/* MINGW32 */
		}
	}
	return 0;
}

/**
 * A simple shell to speak to the local socket of gtk-gnutella. This is
 * provided because there is not standard tool that could be used like
 * telnet for TCP. This is meant as a stand-alone program and therefore
 * does not return calls exit().
 */
void
local_shell(const char *socket_path)
#if defined(HAS_POLL) || defined(HAS_SELECT)
{
	sockaddr_unix_t addr;
	int fd;

	signal(SIGINT, SIG_DFL);

	if (!socket_path) {
		goto failure;
	}
	if (-1 == fcntl(STDIN_FILENO, F_GETFL)) {
		goto failure;
	}
	if (-1 == fcntl(STDOUT_FILENO, F_GETFL)) {
		if (STDOUT_FILENO != open("/dev/null", O_WRONLY))
			goto failure;
	}
	if (-1 == fcntl(STDERR_FILENO, F_GETFL)) {
		if (STDERR_FILENO != open("/dev/null", O_WRONLY))
			goto failure;
	}

	{
		static const sockaddr_unix_t zero_un;

		addr = zero_un;
		addr.sun_family = AF_LOCAL;
		if (vstrlen(socket_path) >= sizeof addr.sun_path) {
			fprintf(stderr, "local_shell(): pathname is too long\n");
			goto failure;
		}
		cstr_bcpy(ARYLEN(addr.sun_path), socket_path);
	}

	fd = compat_socket(PF_LOCAL, SOCK_STREAM, 0);
	if (fd < 0) {
		perror("socket(PF_LOCAL, SOCK_STREAM, 0) failed");
		goto failure;
	}
	if (0 != compat_connect(fd, (const void *) &addr, sizeof addr)) {
		perror("local_shell(): connect() failed");
		fd_close(&fd);
		goto failure;
	}

	fd_set_nonblocking(fd);

	if (0 != local_shell_mainloop(fd))
		goto failure;

	exit(EXIT_SUCCESS);
failure:
	exit(EXIT_FAILURE);
}
#else	/* !(HAS_POLL || HAS_SELECT)) */
{
	(void) socket_path;
	fprintf(stderr, "No shell for you!\n");
	exit(EXIT_FAILURE);
}
#endif	/* HAS_POLL || HAS_SELECT */

#ifdef LOCAL_SHELL_STANDALONE
static char *
path_compose(const char *dir, const char *name)
{
	size_t dir_len, name_len;
	size_t size;
	char *path;

	if (!dir || !name) {
		return NULL;
	}
	dir_len = vstrlen(dir);
	name_len = vstrlen(name);
	if (name_len >= ((size_t) -1) - 2 || dir_len >= ((size_t) -1) - name_len) {
		return NULL;
	}

	size = dir_len + name_len + 2;
	path = malloc(size);
	if (!path) {
		perror("malloc");
		exit(EXIT_FAILURE);
	}
	memcpy(path, dir, dir_len);
	path[dir_len] = '/';
	memcpy(&path[dir_len + 1], name, name_len + 1);

	return path;
}

static const char *
get_socket_path(void)
{
	const char *cfg_dir;

	cfg_dir = getenv("GTK_GNUTELLA_DIR");
	if (!cfg_dir) {
		const char *home_dir;

		home_dir = getenv("HOME");
		if (!home_dir) {
			const struct passwd *pw;

			pw = getpwent();
			if (pw) {
				home_dir = pw->pw_dir;
			}
		}
		if (!home_dir) {
			home_dir = "/";
		}
		cfg_dir = path_compose(home_dir,
					is_running_on_mingw() ? "gtk-gnutella" : ".gtk-gnutella");
	}
	if (cfg_dir) {
		return path_compose(cfg_dir, "ipc/socket");
	} else {
		return NULL;
	}
}

int
main(void)
{
	const char *path;

	path = get_socket_path();
	if (!path) {
		exit(EXIT_FAILURE);
	}
	local_shell(path);
	return 0;
}
#endif	/* LOCAL_SHELL_STANDALONE */

/* vi: set ts=4 sw=4 cindent: */
