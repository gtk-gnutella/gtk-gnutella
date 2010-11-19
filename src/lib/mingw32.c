/*
 * $Id$
 *
 * Copyright (c) 2010, Jeroen Asselman
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
 * Win32 cross-compiling utility routines.
 *
 * @author Jeroen Asselman
 * @date 2010
 */

#include "common.h"
#include <mswsock.h>

RCSID("$Id$")

#include "override.h"			/* Must be the last header included */

#undef open
#undef read
#undef write

#undef getaddrinfo
#undef freeaddrinfo

#undef socket
#undef bind
#undef connect
#undef listen
#undef accept
#undef shutdown
#undef getsockopt
#undef setsockopt
#undef sendto

int 
mingw_open(const char *pathname, int flags, ...)
{
	int res;
	mode_t mode = 0;
	
	if (flags & O_CREAT)
    {
        va_list  args;

        va_start(args, flags);
        mode = (mode_t) va_arg(args, int);
        va_end(args);
    }

	res = open(pathname, flags, mode);
	errno = GetLastError();
	return res;
}

ssize_t 
mingw_read(int fd, void *buf, size_t count)
{
	ssize_t res = read(fd, buf, count);
	errno = GetLastError();
	return res;
}

ssize_t
mingw_write(int fd, const void *buf, size_t count)
{
	ssize_t res = write(fd, buf, count);
	errno = GetLastError();
	return res;
}

/*** Socket wrappers ***/
int mingw_getaddrinfo(const char *node, const char *service,
                      const struct addrinfo *hints,
                      struct addrinfo **res)
{
	int result = getaddrinfo(node, service, hints, res);
	errno = WSAGetLastError();
	return result;
}			

void mingw_freeaddrinfo(struct addrinfo *res)
{
	freeaddrinfo(res);
	errno = WSAGetLastError();
}

socket_fd_t 
mingw_socket(int domain, int type, int protocol)
{
	socket_fd_t res = socket(domain, type, protocol);
	errno = WSAGetLastError();
	return res;
}

int 
mingw_bind(socket_fd_t sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
	int res = bind(sockfd, addr, addrlen);
	errno = WSAGetLastError();
	return res;
}

socket_fd_t 
mingw_connect(socket_fd_t sockfd, const struct sockaddr *addr,
	  socklen_t addrlen)
{
	socket_fd_t res = connect(sockfd, addr, addrlen);
	errno = WSAGetLastError();
	return res;
}

int
mingw_listen(socket_fd_t sockfd, int backlog)
{
	int res = listen(sockfd, backlog);
	errno = WSAGetLastError();
	return res;
}

socket_fd_t
mingw_accept(socket_fd_t sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
	socket_fd_t res = accept(sockfd, addr, addrlen);
	errno = WSAGetLastError();
	return res;
}

int 
mingw_shutdown(socket_fd_t sockfd, int how)
{
	int res = shutdown(sockfd, how);
	errno = WSAGetLastError();
	return res;
}
int 
mingw_getsockopt(int sockfd, int level, int optname, void *optval, socklen_t *optlen)
{
	int res = getsockopt(sockfd, level, optname, optval, optlen);
	errno = WSAGetLastError();
	return res;
}

int 
mingw_setsockopt(socket_fd_t sockfd, int level, int optname, 
	  const void *optval, socklen_t optlen)
{
	int res = setsockopt(sockfd, level, optname, optval, optlen);
	errno = WSAGetLastError();
	return res;
}


ssize_t 
s_write(socket_fd_t fd, const void *buf, size_t count)
{
	ssize_t res = send(fd, buf, count, 0);
	errno = WSAGetLastError();
	return res;
}

ssize_t 
s_read(socket_fd_t fd, void *buf, size_t count)
{
	ssize_t res = recv(fd, buf, count, 0);
	errno = WSAGetLastError();
	return res;
}

int 
s_close(socket_fd_t fd)
{
	int res = closesocket(fd);
	errno = WSAGetLastError();
	return res;
}

size_t 
mingw_s_readv(socket_fd_t fd, const iovec_t *iov, int iovcnt)
{
	DWORD bytesReceived, flags = 0;
	WSARecv(fd,
		(LPWSABUF) iov, iovcnt,
		&bytesReceived, &flags,
		NULL, NULL);

	errno = WSAGetLastError();
	return bytesReceived;
}

ssize_t 
mingw_s_writev(socket_fd_t fd, const iovec_t *iov, int iovcnt)
{
	DWORD bytesSent;
	
	WSASend(fd,
		(LPWSABUF) iov, iovcnt,
		&bytesSent, 0, 
		NULL, NULL);
  
	errno = WSAGetLastError();
	return bytesSent;
};

ssize_t 
recvmsg (socket_fd_t s, struct msghdr *hdr, int flags) 
{
#if 0
	DWORD received;
	WSAMSG msg;

	msg.name = hdr->msg_name;
	msg.namelen = hdr->msg_namelen;
	msg.lpBuffers = hdr->msg_iov;
	msg.dwBufferCount = hdr->msg_iovlen;
	msg.Control.len = hdr->msg_controllen;
	msg.Control.buf = hdr->msg_control;
	msg.dwFlags = hdr->msg_flags;
	
	
	int res = WSARecvMsg(s, &msg, &received, NULL, NULL);
	errno = WSAGetLastError();
	return res;

#else
	/* WSARecvMsg is available in windows, but not in mingw */
    
	size_t i;
    WSABUF buf[hdr->msg_iovlen];
	DWORD received;
	INT ifromLen;
	DWORD dflags;
	
	if (hdr->msg_iovlen > 100)
    {
		g_debug("recvmsg: msg_iovlen to large:%d", hdr->msg_iovlen);
        errno = EINVAL;
        return -1;
    }

	
    for (i = 0; i < hdr->msg_iovlen; i++) {
		buf[i].buf = iovec_base(&hdr->msg_iov[i]),
		buf[i].len = iovec_len(&hdr->msg_iov[i]);
	}
    

    hdr->msg_controllen = 0;
    hdr->msg_flags = 0;

	ifromLen = hdr->msg_namelen;
	dflags = flags;
	
    if (WSARecvFrom (s, 
		  buf, i, &received, &dflags,
		  hdr->msg_name, &ifromLen, NULL, NULL) == 0)
	{
		g_debug("Received %d bytes with flags %d [%d]", received, flags, i); 
		return received;
	}
	
	errno = WSAGetLastError();
	
	g_debug("recvmsg: Error [%d] %s", errno, mingw_strerror(errno));
	
	return -1;
#endif
}

ssize_t mingw_sendto(socket_fd_t sockfd, const void *buf, size_t len, int flags,
	  const struct sockaddr *dest_addr, socklen_t addrlen)
{
	ssize_t res = sendto(sockfd, buf, len, flags, dest_addr, addrlen);
	errno = WSAGetLastError();
	return res;
}

/* vi: set ts=4 sw=4 cindent: */
