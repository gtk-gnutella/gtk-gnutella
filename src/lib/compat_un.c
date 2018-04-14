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
 *      59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *----------------------------------------------------------------------
 */

/**
 * @ingroup lib
 * @file
 *
 * UNIX socket family emulation (aka local sockets).
 *
 * To emulate the UNIX socket family, we use INET sockets with a file as the
 * rendez-vous point (instead of a named socket entry in the filesystem).
 *
 * The special (albeit plain) file we create has the following format:
 *
 *    <?socket?>53795 s 688D96C7 F0E9D75D-2AD3C2BA-2EF88B65-6B26688A\0
 *    ^         ^     ^ ^        ^                                  ^
 *    magic     port  | |        client cookie                      NUL
 *                    | server cookie
 *                    socket type
 *
 * The leading "<?socket?>" string is just a magic string.
 * The port is the INET port on which the server is listening
 * The "s" indicates the socket type ("s" for STREAM, "d" for DGRAM)
 * The server cookie is a random 32-bit cookie
 * The client cookie is made up of 4 random 32-bit values.
 * The trailing NUL byte ensures this is a not a regular text file
 *
 * Upon creation, at "bind" time, the server creates the file, inserting
 * all the relevant information as described above.  It then listens to the
 * advertised port, on the loopback interface.
 *
 * The connection establishment protocol works thusly:
 *
 * The client, trying to "connect" to the named socket will open the file,
 * make sure it is well-formed, then initiate the connection to the specified
 * port, contacting the loopback interface.  Once the connection is established
 * it sends the 4 32-bit words forming the client cookie, in host byte-order.
 * The server validates them and if they match the ones expected, it replies
 * with the server cookie which the client can then validate.
 *
 * This protocol ensures that both the server and the client are certain that
 * they both talk on the same "local socket", that the port was not reassigned
 * to some other process, and that the remote server is not a simple "echo"
 * service but the server that created the file.
 *
 * @author Raphael Manfredi
 * @date 2011
 */

#include "common.h"

/***
 *** This entire file is compiled when there is no support for UNIX sockets.
 ***/

#ifndef HAS_SOCKADDR_UN

#include "compat_un.h"
#include "fd.h"
#include "file.h"
#include "host_addr.h"
#include "htable.h"
#include "log.h"
#include "misc.h"
#include "parse.h"
#include "random.h"
#include "str.h"
#include "stringify.h"
#include "walloc.h"

#include "override.h"       /* Must be the last header included */

#define SUN_CLT_COOKIE_LEN	4		/* # of int32 words */
#define SUN_SRV_COOKIE_LEN	1		/* idem */

#define SUN_SOCKET_MAX_LEN	63		/* maximum file length */

enum sock_un_magic { SOCK_UN_MAGIC = 0x3f0885fa };

/**
 * The local descriptor attached to the UNIX socket descriptor.
 */
struct sock_un {
	enum sock_un_magic magic;
	int refcnt;
	union {
		struct {					/* listening socket */
			uint32 client_cookie[SUN_CLT_COOKIE_LEN];
			uint32 server_cookie[SUN_CLT_COOKIE_LEN];
		} l;
		struct sock_un_accepted{	/* accepted socket */
			struct sock_un *lsun;
			char buf[16];		/* reading buffer */
			size_t pos;			/* read position in buffer */
		} a;
	} u;
	unsigned stream:1;
	unsigned datagram:1;
	unsigned bound:1;
	unsigned listening:1;
	unsigned connected:1;
	unsigned validated:1;
	char path[SUN_PATH_SZ];
};

static inline void
sock_un_check(const struct sock_un * const sun)
{
	g_assert(sun != NULL);
	g_assert(SOCK_UN_MAGIC == sun->magic);
	g_assert(sun->refcnt > 0);
}

static htable_t *un_desc;		/**< Maps a fd to a UNIX socket descriptor */

static const char SOCK_FILE_MAGIC[] = "<?socket?>";

/**
 * Create a new local descriptor.
 */
static struct sock_un *
sock_un_alloc(void)
{
	struct sock_un *sun;

	WALLOC0(sun);
	sun->magic = SOCK_UN_MAGIC;
	sun->refcnt = 1;

	return sun;
}

/**
 * Increment reference count on descriptor.
 */
static struct sock_un *
sock_un_refcnt_inc(struct sock_un *sun)
{
	sun->refcnt++;
	return sun;
}

static void sock_un_free(struct sock_un *sun);

/**
 * Free local descriptor and nullify pointer.
 */
static  void
sock_un_free_null(struct sock_un **sun_ptr)
{
	struct sock_un *sun = *sun_ptr;

	if (sun != NULL) {
		sock_un_free(sun);
		*sun_ptr = NULL;
	}
}

/**
 * Free a local descriptor.
 */
static void
sock_un_free(struct sock_un *sun)
{
	sock_un_check(sun);

	if (--sun->refcnt)
		return;

	if (sun->connected)
		sock_un_free_null(&sun->u.a.lsun);

	sun->magic = 0;
	WFREE(sun);
}

/**
 * Creates a socket.
 *
 * @return the socket descriptor, -1 on error with errno set.
 */
int
compat_socket(int domain, int type, int protocol)
{
	int sd;
	struct sock_un *sun;

	if (domain != AF_LOCAL)
		return socket(domain, type, protocol);

	/*
	 * Emulation layer for UNIX socket creation.
	 */

	sd = socket(AF_INET, type, protocol);

	if (-1 == sd)
		return -1;

	if (NULL == un_desc)
		un_desc = htable_create(HASH_KEY_SELF, 0);

	g_assert(!htable_contains(un_desc, int_to_pointer(sd)));

	sun = sock_un_alloc();

	switch (type) {
	case SOCK_STREAM:
		sun->stream = TRUE;
		break;
	case SOCK_DGRAM:
		sun->datagram = TRUE;
		break;
	default:
		g_assert_not_reached();
	}

	htable_insert(un_desc, int_to_pointer(sd), sun);

	return sd;
}

/**
 * Bind the socket.
 *
 * @return 0 on success, -1 on failure.
 */
int
compat_bind(int sd, const struct sockaddr *my_addr, socklen_t addrlen)
{
	sockaddr_unix_t *saddr = (sockaddr_unix_t *) my_addr;
	struct sock_un *sun;
	uint16 port;
	int fd;
	ssize_t rw;

	g_assert(my_addr != NULL);

	if (saddr->sun_family != AF_LOCAL || addrlen != sizeof *saddr)
		return bind(sd, my_addr, addrlen);

	/*
	 * Emulation layer for UNIX socket binding.
	 */

	if (NULL == un_desc)
		goto bad_sd;

	sun = htable_lookup(un_desc, int_to_pointer(sd));
	if (NULL == sun)
		goto bad_sd;

	sock_un_check(sun);
	g_assert(!sun->connected);

	if (sun->bound)
		goto already_bound;

	if (clamp_strlen(ARYLEN(saddr->sun_path)) >= sizeof saddr->sun_path)
		goto name_too_long;

	/*
	 * Try to bind our AF_INET socket first to the IPv4 loopback interface.
	 */

	{
		const int enable = 1;
		socket_addr_t addr;
		socklen_t len;

		setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, VARLEN(enable));

		len = socket_addr_set(&addr, ipv4_loopback, 0);
		if (-1 == bind(sd, socket_addr_get_const_sockaddr(&addr), len))
			return -1;

		if (0 != socket_addr_getsockname(&addr, sd))
			return -1;

		port = socket_addr_get_port(&addr);
	}

	/*
	 * Create the socket file (mode "rw" for user).
	 */

	{
		mode_t mask;
		int saved_errno;

		mask = umask(S_IXUSR | S_IRWXG | S_IRWXO);
		fd = file_create(saddr->sun_path, O_WRONLY, S_IRUSR | S_IWUSR);
		saved_errno = errno;
		(void) umask(mask);

		if (-1 == fd) {
			errno = saved_errno;
			return -1;
		}
	}

	/*
	 * Generate the random cookies and save the socket file path.
	 */

	random_bytes(ARYLEN(sun->u.l.client_cookie));
	random_bytes(ARYLEN(sun->u.l.server_cookie));
	clamp_strcpy(ARYLEN(sun->path), saddr->sun_path);

	/*
	 * Generate the file, using the following format.
	 *
	 *    <?socket?>53795 s 688D96C7 F0E9D75D-2AD3C2BA-2EF88B65-6B26688A\0
	 */

	/* Magic: "<?socket?>" */

	rw = write(fd, SOCK_FILE_MAGIC, CONST_STRLEN(SOCK_FILE_MAGIC));
	if ((ssize_t) -1 == rw)
		goto io_error;
	else if (rw != CONST_STRLEN(SOCK_FILE_MAGIC))
		goto partial_write;

	/* Listening port number */

	{
		const char *port_str = uint32_to_string(port);
		size_t port_len = strlen(port_str);

		rw = write(fd, port_str, port_len);
		if ((ssize_t) -1 == rw)
			goto io_error;
		else if (UNSIGNED(rw) != port_len)
			goto partial_write;
	}

	/* Socket type */

	{
		const char *type = sun->stream ? " s " : " d ";
		size_t type_len = strlen(type);

		rw = write(fd, type, type_len);
		if ((ssize_t) -1 == rw)
			goto io_error;
		else if (UNSIGNED(rw) != type_len)
			goto partial_write;
	}

	/* Server and client cookies */

	{
		str_t *str = str_new(64);
		size_t slen;

		STATIC_ASSERT(4 == SUN_CLT_COOKIE_LEN);

		str_printf(str, "%08X %08X-%08X-%08X-%08X%c",
			sun->u.l.server_cookie[0],
			sun->u.l.client_cookie[0], sun->u.l.client_cookie[1],
			sun->u.l.client_cookie[2], sun->u.l.client_cookie[3],
			'\0');

		slen = str_len(str);
		rw = write(fd, str_2c(str), slen);
		str_destroy(str);

		if ((ssize_t) -1 == rw)
			goto io_error;
		else if (UNSIGNED(rw) != slen)
			goto partial_write;
	}

	if (-1 == fd_forget_and_close(&fd))
		goto io_error;

	sun->bound = TRUE;

	return 0;				/* OK */

bad_sd:
	errno = EBADF;
	return -1;

already_bound:
	errno = EINVAL;
	return -1;

name_too_long:
	errno = ENAMETOOLONG;
	return -1;

partial_write:
	errno = EIO;			/* For lack of better option */
	/* FALL THROUGH */

io_error:
	{
		int saved_errno = errno;
		fd_close(&fd);
		errno = saved_errno;
	}
	return -1;
}

/**
 * Listen on the bound socket.
 *
 * @return 0 on success, -1 on failure with errno set.
 */
int
compat_listen(int sd, int backlog)
{
	struct sock_un *sun;

	if (NULL == un_desc)
		goto regular;

	sun = htable_lookup(un_desc, int_to_pointer(sd));
	if (NULL == sun)
		goto regular;

	sock_un_check(sun);
	g_assert(!sun->connected);

	if (!sun->bound) {
		errno = EOPNOTSUPP;
		return -1;
	}

	if (sun->listening) {
		errno = EADDRINUSE;
		return -1;
	}

	sun->listening = TRUE;

	/* FALL THROUGH */

regular:
	return listen(sd, backlog);
}

/**
 * Accept incoming connection on socket.
 *
 * @return 0 on success, -1 on failure with errno set.
 */
int
compat_accept(int sd, struct sockaddr *addr, socklen_t *addrlen)
{
	struct sockaddr_in sin4;
	socklen_t len;
	struct sock_un *sun;
	int fd;

	if (NULL == un_desc)
		goto regular;

	sun = htable_lookup(un_desc, int_to_pointer(sd));
	if (NULL == sun)
		goto regular;

	/*
	 * Emulation layer for UNIX sockets.
	 */

	sock_un_check(sun);
	g_assert(sun->listening);
	g_assert(sun->bound);
	g_assert(!sun->connected);

	fd = accept(sd, NULL, NULL);

	if (-1 == fd)
		return -1;

	/*
	 * This is an emulated UNIX socket, therefore the connection to the
	 * INET socket must be local.
	 */

	len = sizeof sin4;
	if (getsockname(fd, cast_to_pointer(&sin4), &len) != 0) {
		s_warning("getsockname(accepted emulated UNIX socket #%d) failed: %m",
			fd);
		goto bad_protocol;
	} else {
		host_addr_t ha;

		g_assert(AF_INET == sin4.sin_family);

		ha = host_addr_peek_ipv4(&sin4.sin_addr.s_addr);

		if (!host_addr_equiv(ha, ipv4_loopback)) {
			g_warning("connection on emulated UNIX listening socket #%d "
				"comes from non-local %s",
				sd, host_addr_to_string(ha));
			goto bad_protocol;
		}
	}

	/*
	 * Fill in address structure as if we had a UNIX socket connecting,
	 * instead of an INET one.
	 */

	if (addr != NULL) {
		sockaddr_unix_t *saddr = (sockaddr_unix_t *) addr;

		g_assert(addrlen != NULL);

		len = *addrlen;
		memset(addr, 0, len);

		if (UNSIGNED(len) >= sizeof saddr->sun_family)
			saddr->sun_family = AF_LOCAL;

		if (UNSIGNED(len) > sizeof saddr->sun_family) {
			clamp_strcpy(saddr->sun_path,
				len - sizeof saddr->sun_family, sun->path);
		}

		*addrlen = sizeof *saddr;	/* So they can detect truncation */
	}

	/*
	 * Remember the accepted UNIX socket.
	 */

	{
		struct sock_un *asun;

		asun = sock_un_alloc();
		clamp_strcpy(ARYLEN(asun->path), sun->path);
		asun->connected = TRUE;
		asun->u.a.lsun = sock_un_refcnt_inc(sun);

		htable_insert(un_desc, int_to_pointer(fd), asun);
	}

	/*
	 * Emulation requires cooperation from the application: the routine
	 * compat_accept_check() must be called when data is available to make
	 * sure that the client sends the proper cookie before being able to
	 * process application data.
	 */

	return fd;		/* OK, accepted socket */

regular:
	return accept(sd, addr, addrlen);

bad_protocol:
	s_close(fd);
	errno = ENOPROTOOPT;
	return -1;
}

/**
 * Parse an hexadecimal 32-bit value.
 *
 * @return TRUE on success, with value filled.
 */
static bool
sock_un_parse_cookie(const char *p, const char **endptr, uint32 *value)
{
	uint32 v;
	int error;

	v = parse_uint32(p, endptr, 16, &error);

	if (error)
		return FALSE;

	*value = v;
	return TRUE;
}

/**
 * Connect socket to specified address (blocking).
 *
 * @return 0 on success, -1 on failure with errno set.
 */
int
compat_connect(int sd, const struct sockaddr *addr, socklen_t addrlen)
{
	sockaddr_unix_t *saddr = (sockaddr_unix_t *) addr;
	struct sock_un *sun;
	int fd;
	uint16 port;
	uint32 client[SUN_CLT_COOKIE_LEN];
	uint32 server[SUN_SRV_COOKIE_LEN];
	ssize_t rw;

	g_assert(addr != NULL);

	if (saddr->sun_family != AF_LOCAL || addrlen != sizeof *saddr)
		return connect(sd, addr, addrlen);

	/*
	 * Emulation layer for UNIX sockets.
	 */

	if (NULL == un_desc)
		goto bad_sd;

	sun = htable_lookup(un_desc, int_to_pointer(sd));
	if (NULL == sun)
		goto bad_sd;

	sock_un_check(sun);
	g_assert(!sun->listening);
	g_assert(!sun->bound);

	if (sun->connected) {
		errno = EISCONN;
		return -1;
	}

	if (!sun->stream) {
		errno = EOPNOTSUPP;
		return -1;
	}

	if (clamp_strlen(ARYLEN(saddr->sun_path)) == sizeof saddr->sun_path) {
		errno = EINVAL;
		return -1;
	}

	/*
	 * Open "socket" rendez-vous file to extract the connection information.
	 */

	fd = file_open_missing(saddr->sun_path, O_RDONLY);
	if (-1 == fd)
		return -1;

	{
		char buf[SUN_SOCKET_MAX_LEN];
		const char *p;
		int error;
		const char *endptr;
		int c;
		size_t i;

		rw = read(fd, ARYLEN(buf));
		if ((ssize_t) -1 == rw)
			goto io_error;
		fd_close(&fd);

		g_assert(UNSIGNED(rw) <= sizeof buf);

		if (0 == rw || buf[rw - 1] != '\0')
			goto not_a_socket;

		/*
		 * Since buf[] is NUL-terminated, is_strprefix() is safe even if
		 * the string is shorter than the constant prefix.
		 */

		p = is_strprefix(buf, SOCK_FILE_MAGIC);
		if (NULL == p)
			goto not_a_socket;

		port = parse_uint16(p, &endptr, 10, &error);
		if (error || 0 == port)
			goto not_a_socket;

		p = endptr;
		if (*p++ != ' ')
			goto not_a_socket;

		c = *p++;

		if (sun->datagram && c != 'd')
			goto bad_prototype;
		if (sun->stream && c != 's')
			goto bad_prototype;

		if (*p++ != ' ')
			goto not_a_socket;

		if (!sock_un_parse_cookie(p, &endptr, &server[0]))
			goto not_a_socket;

		p = endptr;
		if (*p++ != ' ')
			goto not_a_socket;

		for (i = 0; i < N_ITEMS(client); i++) {
			if (!sock_un_parse_cookie(p, &endptr, &client[i]))
				goto not_a_socket;

			p = endptr;
			if (i != N_ITEMS(client) - 1 && *p++ != '-')
				goto not_a_socket;
		}

		if (*p != '\0')
			goto not_a_socket;
	}

	/*
	 * Attempt connection to the INET port we found in the "socket" file.
	 */

	{
		socket_addr_t local;
		socklen_t len;

		len = socket_addr_set(&local, ipv4_loopback, port);
		rw = connect(sd, socket_addr_get_const_sockaddr(&local), len);
	}

	if ((ssize_t) -1 == rw)
		return -1;

	/*
	 * Connection succeeded, send the client cookies to the server.
	 */

	rw = s_write(sd, ARYLEN(client));

	if (rw != sizeof client)
		return -1;

	/*
	 * Now read 4 bytes to make sure we're talking to the server.
	 *
	 * This is blocking, and if the server does not reply anything, we'll
	 * be stuck here.  Program can still be interrupted though.
	 */

	{
		uint32 value;

		if (sizeof value != s_read(sd, VARLEN(value)))
			return -1;

		if (value != server[0])
			goto refused;
	}

	/*
	 * We successfully emulated a UNIX socket connection.
	 */

	return 0;		/* OK, connected socket */

bad_sd:
	errno = EBADF;
	return -1;

io_error:
	{
		int saved_errno = errno;
		fd_close(&fd);
		errno = saved_errno;
	}
	return -1;

refused:
	errno = ECONNREFUSED;
	return -1;

not_a_socket:
	errno = EINVAL;
	return -1;

bad_prototype:
	errno = EPROTOTYPE;
	return -1;
}

/**
 * Remove UNIX descriptor from table.
 */
static void
sock_un_remove(int sd, struct sock_un *sun)
{
	htable_remove(un_desc, int_to_pointer(sd));
	sock_un_free(sun);

	if (0 == htable_count(un_desc))
		htable_free_null(&un_desc);
}

/**
 * Close a socket.
 *
 * @return 0 on success, -1 on failure with errno set.
 */
int
compat_socket_close(int sd)
{
	struct sock_un *sun;

	if (NULL == un_desc)
		goto regular;

	/*
	 * Emulation layer for UNIX sockets.
	 */

	sun = htable_lookup(un_desc, int_to_pointer(sd));
	if (NULL == sun)
		goto regular;

	sock_un_check(sun);

	if (sun->listening) {
		if (-1 == unlink(sun->path)) {
			s_warning("cannot unlink emulated UNIX socket file \"%s\": %m",
				sun->path);
		}
	}

	sock_un_remove(sd, sun);

	/* FALL THROUGH */

regular:
	return s_close(sd);
}

/**
 * Get socket name.
 *
 * @return 0 on success, -1 on failure with errno set.
 */
int
compat_getsockname(int sd, struct sockaddr *addr, socklen_t *addrlen)
{
	struct sock_un *sun;
	sockaddr_unix_t *saddr = (sockaddr_unix_t *) addr;

	if (NULL == un_desc)
		goto regular;

	sun = htable_lookup(un_desc, int_to_pointer(sd));
	if (NULL == sun)
		goto regular;

	if (*addrlen != sizeof *saddr) {
		errno = EINVAL;
		return -1;
	}

	sock_un_check(sun);
	g_assert(!sun->bound);
	g_assert(!sun->listening);

	saddr->sun_family = AF_LOCAL;
	clamp_strcpy(ARYLEN(saddr->sun_path), sun->path);

	return 0;		/* OK */

regular:
	return getsockname(sd, addr, addrlen);
}

/**
 * Is file descriptor that of an emulated UNIX socket and requiring some
 * more data to be read to grab the full client cookie?
 *
 * @return FALSE if no more data needs to be read, TRUE if either more data
 * needs to be read or there is an error and the connection MUST be closed.
 */
bool
compat_accept_check(int sd, bool *error)
{
	struct sock_un *sun;
	ssize_t rw;
	struct sock_un_accepted *suna;

	if (NULL == un_desc)
		return FALSE;

	sun = htable_lookup(un_desc, int_to_pointer(sd));
	if (NULL == sun)
		return FALSE;

	sock_un_check(sun);

	/*
	 * If we already validated cookies, nothing else to do.
	 */

	if (sun->validated)
		return FALSE;

	g_assert(!sun->listening);
	g_assert(sun->connected);
	g_assert(sun->u.a.lsun != NULL);

	/*
	 * Read the client cookie.
	 */

	suna = &sun->u.a;

	g_assert(suna->pos < sizeof suna->buf);

	rw = s_read(sd, ARYPOSLEN(suna->buf, suna->pos));

	if (rw <= 0) {
		*error = TRUE;
		return TRUE;
	}

	suna->pos += rw;

	g_assert(suna->pos <= sizeof suna->buf);
	STATIC_ASSERT(sizeof sun->u.a.buf == sizeof sun->u.l.client_cookie);

	if (sizeof suna->buf == suna->pos) {
		struct sock_un *lsun = suna->lsun;
		if (0 != memcmp(suna->buf, lsun->u.l.client_cookie, sizeof suna->buf)) {
			*error = TRUE;
			return TRUE;
		}
	} else {
		random_cpu_noise();
		*error = FALSE;
		return TRUE;
	}

	/*
	 * Client cookie matched, assure the client that we're the proper server.
	 */

	rw = s_write(sd, suna->lsun->u.l.server_cookie, sizeof(uint32));

	if (rw != sizeof(uint32)) {
		*error = TRUE;
		return TRUE;
	}

	/*
	 * We need to keep the descriptor around so that compat_getsockname()
	 * properly answers that this file descriptor is linked to an AF_LOCAL
	 * socket.
	 */

	sun->validated = TRUE;

	return FALSE;	/* Nothing else to check for, application is good to go */
}

/**
 * Informed that a file descriptor was duplicated.
 */
void
compat_socket_duped(int sd, int nsd)
{
	if (un_desc != NULL) {
		struct sock_un *sun = htable_lookup(un_desc, int_to_pointer(sd));

		if (sun != NULL) {
			g_assert(!htable_contains(un_desc, int_to_pointer(nsd)));
			htable_remove(un_desc, int_to_pointer(sd));
			htable_insert(un_desc, int_to_pointer(nsd), sun);
		}
	}
}

#endif	/* !HAS_SOCKADDR_UN */

/* vi: set ts=4 sw=4 cindent: */
