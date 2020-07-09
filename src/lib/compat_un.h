/*
 * Copyright (c) 2011, Raphael Manfredi
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
 * UNIX socket family emulation (aka local sockets).
 *
 * @author Raphael Manfredi
 * @date 2011
 */

#ifndef _compat_un_h_
#define _compat_un_h_

#ifdef HAS_SOCKADDR_UN

#define compat_socket		socket
#define compat_bind			bind
#define compat_listen		listen
#define compat_accept		accept
#define compat_connect		connect
#define compat_getsockname	getsockname
#define compat_socket_close	close

#define compat_accept_check(sd, e)		FALSE
#define compat_socket_duped(sd, nsd)

typedef struct sockaddr_un sockaddr_unix_t;

#else	/* !HAS_SOCKADDR_UN */

#ifndef AF_LOCAL
#define AF_LOCAL 1
#endif

#ifndef PF_LOCAL
#define PF_LOCAL AF_LOCAL
#endif

#define SUN_PATH_SZ			108		/* Traditional length is low */

/**
 * Our definition of a UNIX socket address (defining a filesystem path).
 *
 * For testing on machines equipped with "stuct sockaddr_un" already,
 * this structure is not named "sockaddr_un".  Hence, the code relies on
 * the sockaddr_unix_t typedef to be able to compile whether or not
 * HAS_SOCKADDR_UN is defined.
 */
struct compat_sockaddr_un {
	sa_family_t sun_family;		/* AF_LOCAL */
	char sun_path[SUN_PATH_SZ];
};

typedef struct compat_sockaddr_un sockaddr_unix_t;

int compat_socket(int domain, int type, int protocol);
int compat_bind(int sd, const struct sockaddr *my_addr, socklen_t addrlen);
int compat_listen(int sd, int backlog);
int compat_accept(int sd, struct sockaddr *addr, socklen_t *addrlen);
int compat_connect(int sd, const struct sockaddr *addr, socklen_t addrlen);
int compat_getsockname(int sd, struct sockaddr *addr, socklen_t *addrlen);
int compat_socket_close(int sd);

bool compat_accept_check(int sd, bool *error);
void compat_socket_duped(int sd, int nsd);

#endif	/* HAS_SOCKADDR_UN */

#endif /* _compat_un_h_ */

/* vi: set ts=4 sw=4 cindent: */
