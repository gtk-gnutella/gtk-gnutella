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
 *      59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *----------------------------------------------------------------------
 */

/**
 * @ingroup lib
 * @file
 *
 * Compatible poll() wrapper which falls back to select() if poll() is
 * missing or is known to be broken on some platform.
 *
 * @author Christian Biere
 * @date 2006
 */

#include "common.h"

#ifdef I_SYS_SELECT
#include <sys/select.h>
#endif

#include "compat_poll.h"
#include "fd.h"					/* For assertions */
#include "log.h"
#include "thread.h"

#include "override.h"			/* Must be the last header included */

/* Fallback on select() if they miss poll() */
#ifndef HAS_POLL
#ifdef HAS_SELECT
#define USE_SELECT_FOR_POLL
#endif
#endif

#if defined(__APPLE__) && defined(__MACH__)
/* poll() seems to be broken on Darwin */
#ifndef USE_SELECT_FOR_POLL
#define USE_SELECT_FOR_POLL
#endif
#endif	/* Darwin */

/**
 * Debugging option.
 */
#if 0
#define POLL_SAFETY_ASSERT	/* Enable safety_assert() */
#endif

#ifdef POLL_SAFETY_ASSERT
#define safety_assert(x)	g_assert(x)
#else
#define safety_assert(x)
#endif

#if defined(USE_SELECT_FOR_POLL) || defined(MINGW32)

static inline int
is_okay_for_select(int fd)
{
	return is_valid_fd(fd) &&
		(is_running_on_mingw() || UNSIGNED(fd) < FD_SETSIZE);
}

static inline int
emulate_poll_with_select(struct pollfd *fds, unsigned int n, int timeout)
{
	struct timeval tv;
	unsigned i;
	fd_set rfds, wfds, efds;
	int ret, max_fd = -1;

	FD_ZERO(&rfds);
	FD_ZERO(&wfds);
	FD_ZERO(&efds);

	for (i = 0; i < n; i++) {
		int fd = cast_to_fd(fds[i].fd);

		safety_assert(!is_valid_fd(fd) || is_a_socket(fd) || is_a_fifo(fd));

		if (!is_okay_for_select(fd) || i >= FD_SETSIZE) {
			fds[i].revents = POLLERR;
			continue;
		}

		max_fd = MAX(fd, max_fd);
		fds[i].revents = 0;

		if (POLLIN & fds[i].events) {
			FD_SET(socket_fd(fd), &rfds);
		}
		if (POLLOUT & fds[i].events) {
			FD_SET(socket_fd(fd), &wfds);
		}
		FD_SET(socket_fd(fd), &efds);
	}

	if (timeout >= 0) {
		tv.tv_sec = timeout / 1000;
		tv.tv_usec = (timeout % 1000) * 1000UL;
	}

	ret = select(max_fd + 1, &rfds, &wfds, &efds, timeout < 0 ? NULL : &tv);

	if (ret > 0) {

		n = MIN(n, FD_SETSIZE);	/* POLLERR is already set above */
		for (i = 0; i < n; i++) {
			int fd = cast_to_fd(fds[i].fd);

			if (!is_okay_for_select(fd))
				continue;

			if (FD_ISSET(fd, &rfds)) {
				fds[i].revents |= POLLIN;
			}
			if (FD_ISSET(fd, &wfds)) {
				fds[i].revents |= POLLOUT;
			}
			if (FD_ISSET(fd, &efds)) {
				fds[i].revents |= POLLERR;
			}
		}
	} else if (ret < 0) {
		s_warning("error during select(): %m");
	}
	return ret;
}
#endif	/* USE_SELECT_FOR_POLL || MINGW32 */

/**
 * A wrapper for poll() that falls back to select() when poll() is missing.
 */
int
compat_poll(struct pollfd *fds, unsigned int n, int timeout)
{
	int r;

	if (timeout != 0)
		thread_in_syscall_set(TRUE);

#ifdef USE_SELECT_FOR_POLL
	r = emulate_poll_with_select(fds, n, timeout);
#elif defined(MINGW32)
	/*
	 * Only Windows versions starting at Vista have WSAPoll(), but we
	 * know all Windows have select() under MinGW.
	 */
	if (mingw_has_wsapoll())
		r = mingw_poll(fds, n, timeout);
	else
		r = emulate_poll_with_select(fds, n, timeout);
#else	/* !USE_SELECT_FOR_POLL */
	r = poll(fds, n, timeout);
#endif	/* USE_SELECT_FOR_POLL */

	if (timeout != 0)
		thread_in_syscall_set(FALSE);

	return r;
}

/* vi: set ts=4 sw=4 cindent: */
