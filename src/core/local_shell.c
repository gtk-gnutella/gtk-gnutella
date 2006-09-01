/*
 * $Id$
 *
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
 *      59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
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

#ifndef LOCAL_SHELL_STANDALONE
#include "common.h"

RCSID("$Id$");

#include "lib/misc.h"
#include "lib/socket.h"

#else

#define HAS_POLL
#include <sys/types.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <pwd.h>

static inline int
is_temporary_error(int e)
{
	return EAGAIN == e || EINTR == e;
}

void 
socket_set_nonblocking(int fd)
{
	int ret, flags;

	ret = fcntl(fd, F_GETFL);
	flags = ret | O_NONBLOCK;
	if (flags != ret)
		fcntl(fd, F_SETFL, flags);
}
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
	int eof;		/**< If set, no further I/O possible due hang up or EOF */
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
	if (0 == sb->fill) {
		ssize_t ret;

		ret = read(fd, sb->buf, sb->size);
		switch (ret) {
		case 0:
			sb->eof = 1;
			break;
		case -1:
			if (!is_temporary_error(errno)) {
				perror("read() failed");
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
			line->length = line->buf ? strlen(line->buf) : 0;
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
	if (sb->fill > 0) {
		ssize_t ret;

		ret = write(fd, &sb->buf[sb->pos], sb->fill);
		switch (ret) {
		case 0:
			break;
		case -1:
			if (!is_temporary_error(errno)) {
				perror("write() failed");
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
		ret = poll(fds, n, timeout);
		if (ret >= 0) {
			break;
		}
		if (ret < 0 && !is_temporary_error(errno)) {
			perror("poll() failed");
			return -1;
		}
	}
	return ret;
}

static int
local_shell_mainloop(int fd)
{
	static struct shell_buf input, output;
#ifdef USE_READLINE
	int use_readline = isatty(STDIN_FILENO);
#else
	int use_readline = 0;
#endif	/* USE_READLINE */

	{
		static char input_buf[4096], output_buf[4096];
		input.buf = input_buf;
		input.size = sizeof input_buf;
		output.buf = output_buf;
		output.size = sizeof output_buf;
	}

	for (;;) {

		if (use_readline) {
			static struct line_buf line;
			if (read_data_with_readline(&line, &input)) {
				return -1;
			}
		} else {
			if (read_data(STDIN_FILENO, &input)) {
				return -1;
			}
		}
		if (write_data(fd, &input)) {
			return -1;
		}
		if (read_data(fd, &output)) {
			return -1;
		}
		if (write_data(STDOUT_FILENO, &output)) {
			return -1;
		}
		if (
			(input.eof && 0 == input.fill) ||
			(output.eof && 0 == output.fill)
		   ) {
			return 0;
		}

		{
			struct pollfd fds[3];

			fds[0].fd = STDIN_FILENO;
			fds[0].events = (input.eof || input.fill > 0) ? 0 : POLLIN;

			fds[1].fd = STDOUT_FILENO;
			fds[1].events = output.fill > 0 ? POLLOUT : 0;

			fds[2].fd = fd;
			fds[2].events = 0
				| ((output.fill > 0 || output.eof) ? 0 : POLLIN)
				| (input.fill  > 0 ? POLLOUT : 0);

			if (wait_for_io(fds, 3, 1000) < 0) {
				return -1;
			}

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
#ifdef HAS_POLL
{
	struct sockaddr_un addr;
	int fd;

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
		static const struct sockaddr_un zero_un;

		addr = zero_un;
		addr.sun_family = AF_LOCAL;
		if (strlen(socket_path) >= sizeof addr.sun_path) {
			fprintf(stderr, "local_shell(): pathname is too long\n");
			goto failure;
		}
		strncpy(addr.sun_path, socket_path, sizeof addr.sun_path);
	}

	fd = socket(PF_LOCAL, SOCK_STREAM, 0);
	if (fd < 0) {
		perror("socket(PF_LOCAL, SOCK_STREAM, 0) failed");
		goto failure;
	}
	if (0 != connect(fd, (const void *) &addr, sizeof addr)) {
		perror("local_shell(): connect() failed");
		close(fd);
		fd = -1;
		goto failure;
	}

	socket_set_nonblocking(STDIN_FILENO);
	socket_set_nonblocking(STDOUT_FILENO);
	socket_set_nonblocking(fd);

	if (0 != local_shell_mainloop(fd))
		goto failure;

	exit(EXIT_FAILURE);
failure:
	exit(EXIT_SUCCESS);
}
#else	/* !HAS_POLL */
{
	fprintf(stderr, "No shell for you!\n");
	exit(EXIT_FAILURE);
}
#endif	/* HAS_POLL */

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
	dir_len = strlen(dir);
	name_len = strlen(name);
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

int
main(void)
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
		cfg_dir = path_compose(home_dir, ".gtk-gnutella");
	}
	if (!cfg_dir) {
		exit(EXIT_FAILURE);
	}
	{
		char *path;
		path = path_compose(cfg_dir, "socket");
		if (!path) {
			exit(EXIT_FAILURE);
		}
		local_shell(path);
	}
	return 0;
}
#endif	/* LOCAL_SHELL_STANDALONE */

/* vi: set ts=4 sw=4 cindent: */
