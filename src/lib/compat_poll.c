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

RCSID("$Id$")

#include "compat_poll.h"

#ifdef I_SYS_SELECT
#include <sys/select.h>
#endif

#include "lib/override.h"		/* Must be the last header included */

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
 * A wrapper for poll() that falls back to select() when poll() is missing.
 */
int
compat_poll(struct pollfd *fds, unsigned int n, int timeout)
#ifdef USE_SELECT_FOR_POLL
{
	struct timeval tv;
	unsigned i;
	fd_set rfds, wfds, efds;
	int ret, max_fd = -1;

#ifdef MINGW32
	/*
	 * Only Windows versions starting at Vista have WSAPoll(), but we
	 * know all Windows have select() under MinGW.
	 */
	if (mingw_has_wsapoll())
		return mingw_poll(fds, n, timeout);
#endif

	FD_ZERO(&rfds);
	FD_ZERO(&wfds);
	FD_ZERO(&efds);

	for (i = 0; i < n; i++) {
		int fd = fds[i].fd;

		/* XXX: Temporarily added for debug purposes! */
		g_assert(-1 == fd || is_a_socket(fd) || is_a_fifo(fd));
		/* XXX */

#ifdef MINGW32
		if (!is_a_socket(fd))
#else
		if (fd < 0 || fd >= FD_SETSIZE || i >= FD_SETSIZE)
#endif
		{
			fds[i].revents = POLLERR;
			continue;
		}
		
		max_fd = MAX(fd, max_fd);
		fds[i].revents = 0;

		if (POLLIN & fds[i].events) {
			FD_SET(fd, &rfds);
		}
		if (POLLOUT & fds[i].events) {
			FD_SET(fd, &wfds);
		}
		FD_SET(fd, &efds);
	}

	if (timeout < 0) {
		tv.tv_sec = 0;
		tv.tv_usec = 0;
	} else {
		tv.tv_sec = timeout / 1000;
		tv.tv_usec = (timeout % 1000) * 1000UL;
	}

	ret = select(max_fd + 1, &rfds, &wfds, &efds, timeout < 0 ? NULL : &tv);
	
	if (ret > 0) {

		n = MIN(n, FD_SETSIZE);	/* POLLERR is already set above */
		for (i = 0; i < n; i++) {
			int fd = fds[i].fd;

			if (fd < 0 
#ifndef MINGW32
				|| fd >= FD_SETSIZE
#endif
			) {
				continue;
			}
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
		g_warning("error during select %s", g_strerror(errno));
	}
	return ret;
}
#else	/* !USE_SELECT_FOR_POLL */
{
	return poll(fds, n, timeout);
}
#endif	/* USE_SELECT_FOR_POLL */

/* vi: set ts=4 sw=4 cindent: */
