/*
 * Copyright (c) 2009-2013 Raphael Manfredi
 * Copyright (c) 2006-2008 Christian Biere
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
 * @date 2009-2013
 * @author Christian Biere
 * @date 2006-2008
 */

#include "common.h"

#include "fd.h"

#include "compat_misc.h"
#include "compat_un.h"
#include "glib-missing.h"		/* For g_info() */
#include "hset.h"
#include "log.h"				/* For s_carp() */
#include "once.h"

#include "override.h"			/* Must be the last header included */

static hset_t *fd_sockets;
static hset_t *fd_preserved;
static once_flag_t fd_preserved_allocated;

void
fd_set_close_on_exec(int fd)
{
#ifdef FD_CLOEXEC
	int flags;

	flags = fcntl(fd, F_GETFD);
	if (0 == (flags & FD_CLOEXEC)) {
		flags |= FD_CLOEXEC;
		if (-1 == fcntl(fd, F_SETFD, flags))
			s_carp("%s(): failed for #%d: %m", G_STRFUNC, fd);
	}
#else
	(void) fd;
#endif	/* FD_CLOEXEC */
}

static inline bool
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

static inline bool
fd_is_opened(const int fd)
{
	return is_open_fd(fd) || is_a_socket(fd) || is_a_fifo(fd);
}

/**
 * Determine the file descriptor that will likely be used at next open().
 *
 * This is used at initialization time to determine the first available
 * file descriptor so that we do not try to close special files opened by
 * libraries.
 *
 * @return the first available file descriptor.
 */
int
fd_first_available(void)
{
	int fd;

	fd = open("/dev/null", O_RDWR, 0);
	if (-1 == fd)
		s_error("%s(): failed to open /dev/null: %m", G_STRFUNC);
	close(fd);

	return fd;
}

/**
 * Set iterator to close all known socket descriptors.
 */
static void
fd_socket_close(const void *data, void *udata)
{
	(void) udata;

	if (is_running_on_mingw()) {
		socket_fd_t fd = pointer_to_int(data);
		(void) s_close(fd);
	}
}

/**
 * Allocate the fd_preserved set if not done already.
 */
static void
fd_preserved_allocate(void)
{
	fd_preserved = hset_create(HASH_KEY_SELF, 0);
	hset_thread_safe(fd_preserved);
}

/**
 * Mark a file descriptor as being preserved from closing by
 * fd_close_unpreserved_from().
 */
void
fd_preserve(int fd)
{
	g_assert(!is_a_socket(fd));

	ONCE_FLAG_RUN(fd_preserved_allocated, fd_preserved_allocate);
	hset_insert(fd_preserved, int_to_pointer(fd));
}

/**
 * Closes all file descriptors greater or equal to ``first_fd'', skipping
 * preserved ones if ``preserve'' is TRUE.
 */
static void
fd_close_from_internal(const int first_fd, bool preserve)
{
	int fd;

	g_return_if_fail(first_fd >= 0);

	if (!preserve && try_close_from(first_fd))
		return;

	fd = getdtablesize() - 1;
	while (fd >= first_fd) {
		if (preserve && hset_contains(fd_preserved, int_to_pointer(fd)))
			goto next;

#ifdef HAVE_GTKOSXAPPLICATION
		/* OS X doesn't allow fds being closed not opened by us. During
		 * GUI initialisation a new kqueue fd is created for UI events. This
		 * is visible to us as a fifo which we are not allowed to close. 
		 * Set close on exec on all fifo's so we won't leak any of our other
		 * fifo's
		 *	-- JA 2011-11-28 */
		if (is_a_fifo(fd))
			fd_set_close_on_exec(fd);
		else
#endif
		/* OS X frowns upon random fds being closed --RAM 2011-11-13  */
		if (fd_is_opened(fd)) {
			if (close(fd)) {
#if defined(F_MAXFD)
				fd = fcntl(0, F_MAXFD);
				continue;
#endif	/* F_MAXFD */
			}
		}
	next:
		fd--;
	}

	/*
	 * When called with a first_fd of 3, and we are on Windows, also make
	 * sure we close all the known sockets we have.  This lets the process
	 * safely auto-restart, avoiding multiple listening sockets on the same
	 * port.
	 *		--RAM, 2015-04-05
	 */

	if (
		is_running_on_mingw() && !preserve &&
		3 == first_fd && NULL != fd_sockets
	) {
		hset_t *fds = fd_sockets;

		/*
		 * We're about to exec() another process, and we may be crashing,
		 * hence do not bother using hset_foreach_remove() to ensure minimal
		 * processing.  We also reset the fd_sockets pointer to NULL to
		 * make sure s_close() will do nothing when fd_notify_socket_closed()
		 * is called.
		 */

		fd_sockets = NULL;		/* We don't expect race conditions here */
		hset_foreach(fds, fd_socket_close, NULL);

		/* Don't bother freeing / clearing set, we're about to exec() */
	}
}

/**
 * Closes all file descriptors greater or equal to ``first_fd''.
 */
void
fd_close_from(const int first_fd)
{
	fd_close_from_internal(first_fd, FALSE);
}

/**
 * Closes all file descriptors greater or equal to ``first_fd'', skipping
 * all the ones that were marked as preserved via fd_preserve().
 */
void
fd_close_unpreserved_from(const int first_fd)
{
	fd_close_from_internal(first_fd, fd_preserved != NULL);
}

/**
 * Ensures that fd 0, 1 and 2 are opened.
 *
 * @return 0 on success, -1 on failure.
 */
int G_COLD
reserve_standard_file_descriptors(void)
{
	int fd;

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
			int fd2 = ret;
			
			ret = dup2(fd2, fd);
			close(fd2);
			if (-1 == ret || !is_open_fd(fd))
				return -1;
		}
	}
	return 0;
}

bool G_COLD
fd_need_non_stdio(void)
{
	static int needed = -1;

	if (G_UNLIKELY(needed < 0)) {
		int fd;
		/* Assume that STDIN_FILENO is open. */
		fd = fcntl(STDIN_FILENO, F_DUPFD, 256);
		if (fd >= 0) {
			FILE *f;

			f = fdopen(fd, "r");
			if (f) {
				fclose(f);
				needed = FALSE;
			} else {
				close(fd);
				needed = TRUE;
			}
		} else {
			needed = FALSE;
		}
	}
	return needed;
}

/*
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
fd_get_non_stdio(int fd)
{
	if (fd_need_non_stdio() && fd > 2 && fd < 256) {
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

	/*
	 * On Windows, files and sockets do not share the same ID space.
	 * Therefore, on that platform we use this routine as a hook to
	 * record active socket descriptors in a table.
	 *		--RAM, 2015-04-05
	 */

	if (is_running_on_mingw()) {
		/* We don't expect thread race conditions here */
		if G_UNLIKELY(NULL == fd_sockets)
			fd_sockets = hset_create(HASH_KEY_SELF, 0);

		if (is_a_socket(fd))
			hset_insert(fd_sockets, int_to_pointer(fd));
	}

	return fd;
}

void
fd_set_nonblocking(int fd)
{
	bool failed = FALSE;

#ifdef MINGW32
	{
		unsigned long nonblock = 1;

		if (ioctlsocket(fd, FIONBIO, &nonblock)) {
			errno = WSAGetLastError();
			failed = TRUE;
		}
	}
#else	/* !MINGW32 */
	{
		int ret, flags;

		ret = fcntl(fd, F_GETFL, 0);
		flags = ret | VAL_O_NONBLOCK;
		if (flags != ret) {
			if (-1 == fcntl(fd, F_SETFL, flags))
				failed = TRUE;
		}
	}
#endif	/* MINGW32 */

	if (failed)
		s_carp("%s(): failed for #%d: %m", G_STRFUNC, fd);
}

/**
 * Notifies that a socket descriptor has been closed.
 *
 * This is only required on Windows, since we need to keep track of opened
 * socket descriptors, in order to close them before exec().  Failure to
 * do so would leave listen sockets around, and because we use SO_REUSEADDR
 * to bind our listening sockets, we would have two processes listening on
 * the same socket -- a recipe for blackouts on Windows!
 */
void
fd_notify_socket_closed(socket_fd_t fd)
{
	if (!is_running_on_mingw()) {
		s_carp_once("%s(): not needed on UNIX", G_STRFUNC);
		return;
	} else {
		if G_LIKELY(fd_sockets != NULL)
			hset_remove(fd_sockets, int_to_pointer(fd));
	}
}

/**
 * Closes the file and sets the descriptor to -1. Does nothing if
 * the descriptor is already -1.
 *
 * @param fd_ptr Must point to a non-negative file descriptor or -1.
 *
 * @return 0 on success, -1 on error.
 */
int
fd_close(int *fd_ptr)
{
	int ret, fd;

	g_assert(NULL != fd_ptr);

	fd = *fd_ptr;
	g_assert(fd >= -1);

	if (fd < 0) {
		ret = 0;
	} else {
		if (fd_preserved != NULL)
			hset_remove(fd_preserved, int_to_pointer(fd));
		ret = close(fd);
		*fd_ptr = -1;
	}
	return ret;
}

/**
 * Identical to fd_close() except that it also calls posix_fadvise() with
 * POSIX_FADV_DONTNEED for the complete file to clear it from the file
 * cache. This is only be useful for regular files which we don't intend
 * to access anytime soon again.
 */
int
fd_forget_and_close(int *fd_ptr)
{
	g_assert(NULL != fd_ptr);

	if (*fd_ptr >= 0) {
		compat_fadvise_dontneed(*fd_ptr, 0, 0);
	}
	return fd_close(fd_ptr);
}

#if !defined(HAS_FSYNC) && !defined(HAS_FDATASYNC)
static void
fd_warn_no_fsync(void)
{
	static bool warned;

	if (!warned) {
		warned = TRUE;
		g_warning("no fsync(), assuming no delayed disk block allocation");
	}
}
#endif	/* !HAS_FSYNC && !HAS_FDATASYNC */

/**
 * Synchronize a file's in-core state with the storage device.
 */
int
fd_fsync(int fd)
{
	g_assert(fd >= -1);

#if defined(HAS_FSYNC)
	return fsync(fd);
#elif defined(HAS_FDATASYNC)
	return fdatasync(fd);
#else
	(void) fd;
	fd_warn_no_fsync();
	return 0;		/* Silently ignore request if no fsync() nor fdatasync() */
#endif
}

/**
 * Synchronize a file's in-core state with the storage device, but not the
 * metadata if they do not help in recovering the data blocks.
 */
int
fd_fdatasync(int fd)
{
	g_assert(fd >= -1);

#if defined(HAS_FDATASYNC)
	return fdatasync(fd);
#elif defined(HAS_FSYNC)
	return fsync(fd);
#else
	(void) fd;
	fd_warn_no_fsync();
	return 0;		/* Silently ignore request if no fdatasync() nor fsync() */
#endif
}

/**
 * Uses fstat() or getsockopt() to determine whether the given file descriptor
 * is a socket.
 *
 * @param fd An arbitrary file descriptor.
 * @return TRUE if fd is a socket, FALSE otherwise.
 */
bool
is_a_socket(int fd)
#ifdef S_ISSOCK
{
	filestat_t sb;

	return is_valid_fd(fd) && 0 == fstat(fd, &sb) && 0 != S_ISSOCK(sb.st_mode);
}
#else
{
	int ret, opt_val;
	socklen_t opt_len;

	if (!is_valid_fd(fd))
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
bool
is_a_fifo(int fd)
{
	filestat_t sb;

	return is_valid_fd(fd) && 0 == fstat(fd, &sb) && 0 != S_ISFIFO(sb.st_mode);
}

/**
 * Check if a file descriptor is opened and set errno to EBADF on failure.
 *
 * @param fd An arbitrary file descriptor.
 * @return TRUE if fd is opened, FALSE otherwise.
 */
bool
is_open_fd(int fd)
{
	return -1 != fcntl(fd, F_GETFL);
}

/**
 * Checks whether the given file descriptor is opened for write operations.
 *
 * @param fd A valid file descriptor.
 * @return TRUE if the file descriptor is opened with O_WRONLY or O_RDWR.
 */
bool
fd_is_writable(const int fd)
{
	int flags;

	g_return_val_if_fail(fd >= 0, FALSE);

	flags = fcntl(fd, F_GETFL);
	g_return_val_if_fail(-1 != flags, FALSE);

	flags &= O_ACCMODE;
	return O_WRONLY == flags || O_RDWR == flags;
}

/**
 * Checks whether the given file descriptor is opened for read operations.
 *
 * @param fd A valid file descriptor.
 * @return TRUE if the file descriptor is opened with O_RDONLY or O_RDWR.
 */
bool
fd_is_readable(const int fd)
{
	int flags;

	g_return_val_if_fail(fd >= 0, FALSE);

	flags = fcntl(fd, F_GETFL);
	g_return_val_if_fail(-1 != flags, FALSE);

	flags &= O_ACCMODE;
	return O_RDONLY == flags || O_RDWR == flags;
}

/**
 * Checks whether the given file descriptor is opened for read and write
 * operations.
 *
 * @param fd A valid file descriptor.
 * @return TRUE if the file descriptor is opened with O_RDWR.
 */
bool
fd_is_readable_and_writable(const int fd)
{
	int flags;

	g_return_val_if_fail(fd >= 0, FALSE);

	flags = fcntl(fd, F_GETFL);
	g_return_val_if_fail(-1 != flags, FALSE);

	flags &= O_ACCMODE;
	return O_RDWR == flags;
}

/**
 * Checks whether the given file descriptor is compatible with given
 * access mode. For example, if fd has access mode O_RDONLY but
 * accmode is O_WRONLY or O_RDWR FALSE is returned, because the
 * file descriptor is not writable.
 *
 * @param fd A valid file descriptor.
 * @return TRUE if the file descriptor is compatible with the access mode.
 */
bool
fd_accmode_is_valid(const int fd, const int accmode)
{
	g_return_val_if_fail(fd >= 0, FALSE);

	switch (accmode) {
	case O_RDONLY: return fd_is_readable(fd);
	case O_WRONLY: return fd_is_writable(fd);
	case O_RDWR:   return fd_is_readable_and_writable(fd);
	}
	return FALSE;
}

/* vi: set ts=4 sw=4 cindent: */
