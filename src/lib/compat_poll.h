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

#ifdef HAS_POLL
#if defined(I_POLL)
#include <poll.h>
#elif defined(I_SYS_POLL)
#include <sys/poll.h>
#endif
#else
/*
 * Poll events (requested and returned).
 */

#define POLLIN		0x0001	/* There is data to read */
#define POLLPRI		0x0002	/* There is urgent data to read */
#define POLLOUT		0x0004	/* Writing now will not block */
#define POLLERR		0x0008	/* Error condition */
#define POLLHUP		0x0010	/* Hung up */
#define POLLNVAL	0x0020	/* Invalid request: fd not open */

struct pollfd {
	socket_fd_t fd;		/**< File descriptor to poll */
	short events;		/**< Types of events poller cares about */
	short revents;		/**< Types of events that actually occurred */
};
#endif

int compat_poll(struct pollfd *fds, size_t n, int timeout);

/* vi: set ts=4 sw=4 cindent: */
