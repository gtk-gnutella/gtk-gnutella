/*
 * $Id$
 *
 * Copyright (c) 2009, Raphael Manfredi
 * Copyright (c) 2006-2008, Christian Biere
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
 * File descriptor functions.
 *
 * @author Raphael Manfredi
 * @date 2009
 * @author Christian Biere
 * @date 2006-2008
 */

#include "common.h"

RCSID("$Id$")

#include "fd.h"
#include "compat_misc.h"
#include "compat_un.h"
#include "override.h"			/* Must be the last header included */

void
set_close_on_exec(int fd)
{
#ifdef FD_CLOEXEC
	int flags;

	flags = fcntl(fd, F_GETFD);
	if (0 == (flags & FD_CLOEXEC)) {
		flags |= FD_CLOEXEC;
		fcntl(fd, F_SETFD, flags);
	}
#else
	(void) fd;
#endif	/* FD_CLOEXEC */
}

static inline gboolean
try_close_from(const int first_fd)
{
#if defined(F_CLOSEM)
	return -1 != fcntl(first_fd, F_CLOSEM);
#elif defined(HAS_CLOSEFROM)
	/* Returns nothing on Solaris; NetBSD has F_CLOSEM and closefrom()
	 * equivalent to the above. Thus prefer F_CLOSEM due to potential
	 * error. */
	closefrom(first_fd);
	return TRUE;
#else
	(void) first_fd;
	return FALSE;
#endif	/* HAS_CLOSEFROM */
}

/**
 * Closes all file descriptors greater or equal to ``first_fd''.
 */
void
close_file_descriptors(const int first_fd)
{
	int fd;

	g_return_if_fail(first_fd >= 0);

	if (try_close_from(first_fd))
		return;

	fd = getdtablesize() - 1;
	while (fd >= first_fd) {
		if (close(fd)) {
#if defined(F_MAXFD)
			fd = fcntl(0, F_MAXFD);
			continue;
#endif	/* F_MAXFD */
		}
		fd--;
	}
}

/**
 * Ensures that fd 0, 1 and 2 are opened.
 *
 * @return 0 on success, -1 on failure.
 */
int
reserve_standard_file_descriptors(void)
{
	int fd;

	if (is_running_on_mingw())
		return 0;

	/*
	 * POSIX guarantees that open() and dup() return the lowest unassigned file
	 * descriptor. Check this but don't rely on it.
	 */
	for (fd = 0; fd < 3; fd++) {
		int ret;

		if (is_open_fd(fd))
			continue;
		ret = open("/dev/null", O_RDWR, 0);
		if (-1 == ret)
			return -1;

		/* The following shouldn't happen on POSIX */
		if (fd != ret) {
			int fd2 = dup2(ret, fd);
			close(ret);
			if (fd2 != fd)
				return -1;
		}
	}
	return 0;
}

static gboolean
need_get_non_stdio_fd(void)
{
	int fd;

	if (is_running_on_mingw())
		return FALSE;

	/* Assume that STDIN_FILENO is open. */
	fd = fcntl(STDIN_FILENO, F_DUPFD, 256);
	if (fd >= 0) {
		FILE *f;

		f = fdopen(fd, "r");
		if (f) {
			fclose(f);
		} else {
			close(fd);
			return TRUE;
		}
	}
	return FALSE;
}

/**
 * If we detect that stdio cannot handle file descriptors above 255, this
 * functions tries to reassign 'fd' to a file descriptor above 255 in order to
 * reserve lower file descriptors for stdio. File descriptors below 3 or above
 * 255 are returned as-is. The original file descriptor is closed if it was
 * reassigned. On systems which do not need this workaround, the original
 * file descriptor is returned.
 *
 * @note The FD_CLOEXEC flag set will be cleared on the new file descriptor if
 *		 the file descriptor is successfully reassigned.
 *
 * @return	On success a new file descriptor above 255 is returned.
 *         	On failure or if reassigning was not necessary the original file
 *			descriptor is returned.
 */
int
get_non_stdio_fd(int fd)
{
	static gboolean initialized, needed;

	if (!initialized) {
		initialized = TRUE;
		needed = need_get_non_stdio_fd();
	}
	if (needed && fd > 2 && fd < 256) {
		int nfd, saved_errno;

		saved_errno = errno;
		nfd = fcntl(fd, F_DUPFD, 256);
		if (nfd > 0) {
			close(fd);
			compat_socket_duped(fd, nfd);
			fd = nfd;
		}
		errno = saved_errno;
	}
	return fd;
}

void
fd_set_nonblocking(int fd)
#ifdef MINGW32
{
	unsigned long nonblock = 1;

	if (ioctlsocket(fd, FIONBIO, &nonblock))
		errno = WSAGetLastError();
}
#else
{
	int ret, flags;

	ret = fcntl(fd, F_GETFL, 0);
	flags = ret | VAL_O_NONBLOCK;
	if (flags != ret)
		fcntl(fd, F_SETFL, flags);
}
#endif	/* MINGW32 */

/**
 * Closes the file and sets the descriptor to -1. Does nothing if
 * the descriptor is already -1.
 *
 * @param fd_ptr Must point to a non-negative file descriptor or -1.
 * @param clear_cache If TRUE posix_fadvise() is called with
 *		  POSIX_FADV_DONTNEED. This should only be used for regular
 *		  files.
 *
 * @return 0 on success, -1 on error.
 */
int
fd_close(int *fd_ptr, gboolean clear_cache)
{
	int ret;
	int fd;

	g_assert(fd_ptr != NULL);

	fd = *fd_ptr;
	g_assert(fd >= -1);

	if (fd < 0)
		return 0;

	if (clear_cache) {
		compat_fadvise_dontneed(fd, 0, 0);
	}

	ret = close(fd);
	*fd_ptr = -1;

	return ret;
}

/**
 * Uses fstat() or getsockopt() to determine whether the given file descriptor
 * is a socket.
 *
 * @param fd An arbitrary file descriptor.
 * @return TRUE if fd is a socket, FALSE otherwise.
 */
gboolean
is_a_socket(int fd)
#ifdef S_ISSOCK
{
	struct stat sb;

	return is_valid_fd(fd) && 0 == fstat(fd, &sb) && 0 != S_ISSOCK(sb.st_mode);
}
#else
{
	int ret, opt_val;
	socklen_t opt_len;

	if (is_valid_fd(fd))
		return FALSE;

	opt_len = sizeof(opt_val);
	ret = getsockopt(fd, SOL_SOCKET, SO_TYPE,
			cast_to_void_ptr(&opt_val), &opt_len);
	return 0 == ret;
}
#endif

/**
 * Check if a file descriptor is a FIFO.
 * @param fd An arbitrary file descriptor.
 * @return TRUE if fd is a FIFO, FALSE otherwise.
 */
gboolean
is_a_fifo(int fd)
{
	struct stat sb;

	return is_valid_fd(fd) && 0 == fstat(fd, &sb) && 0 != S_ISFIFO(sb.st_mode);
}

/**
 * Check if a file descriptor is opened and set errno to EBADF on failure.
 *
 * @param fd An arbitrary file descriptor.
 * @return TRUE if fd is opened, FALSE otherwise.
 */
gboolean
is_open_fd(int fd)
{
	return -1 != fcntl(fd, F_GETFL);
}
/* vi: set ts=4 sw=4 cindent: */
