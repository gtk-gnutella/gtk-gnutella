/*
 * $Id$
 * 
 * Copyright (c) 2005, Jeroen Asselman
 *
 * ----------------------------------------------------------------------
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
 * ----------------------------------------------------------------------
 */

#include "common.h"

RCSID("$Id$")

#include "socket.h"

/**
 *  Sets a socket to non-blocking behaviour
 */
void 
socket_set_nonblocking(gint fd)
#ifdef MINGW32
{
	gulong nonblock = 1;

	ioctlsocket(fd, FIONBIO, &nonblock);
	ioctlsocket(fd, FIONBIO, &nonblock); /* Twice? */
}
#else
{
	gint ret, flags;

	ret = fcntl(fd, F_GETFL, 0);
	flags = ret | VAL_O_NONBLOCK;
	if (flags != ret)
		fcntl(fd, F_SETFL, flags);
}
#endif

/* vi: set ts=4 sw=4 cindent: */
