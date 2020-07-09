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
 * @author Raphael Manfredi
 * @date 2015
 */

#ifndef _spopen_h_
#define _spopen_h_

/**
 * File descriptor special dispositions in the fd[] array.
 */
#define SPOPEN_ASIS				(-1) /**< Keep same fd from parent process */
#define SPOPEN_DEV_NULL			(-2) /**< Open /dev/null */
#define SPOPEN_PARENT_STDOUT	(-3) /**< Stderr mapped to parent's stdout */
#define SPOPEN_CHILD_STDOUT		(-4) /**< Stderr mapped to child's stdout */

/*
 * Protected interface.
 */

#ifdef MINGW32
void spopen_fd_map(int fd, pid_t pid);
#endif

/*
 * Public interface.
 */

int spopenve(const char *path, const char *mode, int fd[2],
		char *const argv[], char *const envp[]);

int spopenvpe(const char *path, const char *mode, int fd[2],
		char *const argv[], char *const envp[]);

int spopenl(const char *path, const char *mode, int fd[2],
		const char *arg, ...) G_NULL_TERMINATED;
int spopenlp(const char *path, const char *mode, int fd[2],
		const char *arg, ...) G_NULL_TERMINATED;
int spopenle(const char *path, const char *mode, int fd[2],
		const char *arg, ...);

int spopenle_v(const char *path, const char *mode, int fd[2],
		const char *arg, va_list ap, char *const envp[]);
int spopenl_v(const char *path, const char *mode, int fd[2],
		const char *arg, va_list ap);

pid_t sppid(int fd, bool forget);
int spclose(int fd);

/**
 * Convenience routine to get the PID of the child on the other end of the
 * pipe without compromising the ability to later issue an spclose().
 *
 * @param fd	the pipe fd returned by any of the spopen() function family
 */
static inline pid_t
sppidof(int fd)
{
	return sppid(fd, FALSE);
}

#endif	/* _spopen_h_ */

/* vi: set ts=4 sw=4 cindent: */
