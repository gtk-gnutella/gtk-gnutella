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
RCSID("$Id$")

#ifdef MINGW32

#include <mswsock.h>
#include <shlobj.h>

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

const char *
mingw_gethome(void)
{
	static char path[MAX_PATH];
	int ret;

	ret = SHGetFolderPath(NULL, CSIDL_LOCAL_APPDATA , NULL, 0, path);
	
	if (E_INVALIDARG == ret) {
		g_warning("could not determine home directory");
		path[0] = '/';
		path[1] = '\0';
	} 

	return path;
}

guint64
mingw_getphysmemsize(void)
{
	MEMORYSTATUSEX memStatus;
	
	memStatus.dwLength = sizeof memStatus;

	if (!GlobalMemoryStatusEx(&memStatus)) {
		errno = GetLastError();
		return -1;
	}
	return memStatus.ullTotalPhys;
}

int 
mingw_open(const char *pathname, int flags, ...)
{
	int res;
	mode_t mode = 0;
	
	if (flags & O_CREAT) {
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

int
mingw_truncate(const char *path, off_t len)
{
	int fd, ret, saved_errno;

	fd = open(path, O_RDWR);
	if (-1 == fd)
		return -1;

	ret = ftruncate(fd, len);
	saved_errno = errno;
	close(fd);
	errno = saved_errno;

	return ret;
}

/***
 *** Socket wrappers
 ***/
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
mingw_getsockopt(socket_fd_t sockfd, int level, int optname,
	void *optval, socklen_t *optlen)
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
		g_warning("recvmsg: msg_iovlen to large:%d", hdr->msg_iovlen);
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
		return received;
	}
	
	errno = WSAGetLastError();
	
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

/***
 *** Memory allocation routines.
 ***/

void *
mingw_valloc(void *hint, size_t size)
{
	void *p;

	p = (void *) VirtualAlloc(hint, size, 
		MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		
	if (p == NULL) {
		p = (void *) VirtualAlloc(NULL, size,
			MEM_COMMIT | MEM_RESERVE,
			PAGE_READWRITE);
	}
	if (p == NULL) {
		p = MAP_FAILED;
		errno = GetLastError();
	}

	return p;
}

int
mingw_vfree(void *addr, size_t size)
{
	(void) size;

	if (0 == VirtualFree(addr, 0, MEM_RELEASE)) {
		errno = GetLastError();
		return -1;
	}

	return 0;	/* OK */
}

int
mingw_vfree_fragment(void *addr, size_t size)
{
	MEMORY_BASIC_INFORMATION inf;
	void *remain_ptr = addr;
	size_t remain_size = size;
	
	/* 
	 * FIXME: This is more a workaround to avoid leaking too much memory!
	 * There needs to be a better way!
	 * Perhaps we can create a CreateFileMapping with an InvalidFileHandle,
	 * this will create a anonymous file handle and as a size argument
	 * use the largest size allowed. 
	 * Next create a MapViewOfFile like mmap with an ANONYMOUS PAGE. 
	 * However it won't be possible to Protect a section of the page in this
	 * case.
	 *		-- JA 19/11/2010
	 */

	while (remain_size > 0) {
		if (0 == VirtualQuery(remain_ptr, &inf, sizeof inf))
			goto error;

		if (
			remain_ptr != inf.AllocationBase ||
			inf.RegionSize != remain_size
		) {
			g_debug("src: 0x%x, BaseAddress: 0x%x, AllocBase: 0x%x, "
				"Size 0x%x(0x%x)", 
				remain_ptr, inf.BaseAddress,
				inf.AllocationBase, inf.RegionSize, size);
		}
		if (inf.RegionSize == size) {
			if (0 == VirtualFree(remain_ptr, 0, MEM_RELEASE))
				goto error;
			remain_size = 0;
		} else if (inf.RegionSize < size) {
			if (0 == VirtualFree(remain_ptr, 0, MEM_RELEASE))
				goto error;
			remain_size -= inf.RegionSize;
			remain_ptr += inf.RegionSize;
		} else {
			g_warning("RegionSize is smaller then requested decommit size");
			if (0 == VirtualFree(remain_ptr, remain_size, MEM_DECOMMIT))
				goto error;
		}
	}

	return 0;		/* OK */

error:
	errno = GetLastError();
	return -1;
}

int
mingw_mprotect(void *addr, size_t len, int prot)
{
	DWORD oldProtect = 0;
	DWORD newProtect;
	BOOL res;

	switch (prot) {
	case PROT_NONE:
		newProtect = PAGE_NOACCESS;
		break;
	case PROT_READ:
		newProtect = PAGE_READONLY;
		break;
	case PROT_READ | PROT_WRITE:
		newProtect = PAGE_READWRITE;
		break;
	default:
		g_error("mingw_mprotect(): unsupported protection flags 0x%x", prot);
	}

	res = VirtualProtect((LPVOID) addr, len, newProtect, &oldProtect);
	if (!res) {
		errno = GetLastError();
		g_debug("VMM mprotect(0x%lx, %u) failed: errno=%d",
			(unsigned long) addr, (unsigned) len, errno);
		return -1;
	}

	return 0;	/* OK */
}

/***
 *** Miscellaneous.
 ***/

int
mingw_statvfs(const char *path, struct mingw_statvfs *buf)
{
	BOOL ret;
	DWORD SectorsPerCluster;
	DWORD BytesPerSector;
	DWORD NumberOfFreeClusters;
	DWORD TotalNumberOfClusters;

	ret = GetDiskFreeSpace(path,
		&SectorsPerCluster, &BytesPerSector,
		&NumberOfFreeClusters,
		&TotalNumberOfClusters);

	if (!ret) {
		errno = GetLastError();
		return -1;
	}

	buf->f_csize = SectorsPerCluster * BytesPerSector;
	buf->f_clusters = TotalNumberOfClusters;
	buf->f_cavail = NumberOfFreeClusters;

	return 0;
}

/**
 * Convert a FILETIME into a timeval.
 *
 * @param ft		the FILETIME structure to convert
 * @param tv		the struct timeval to fill in
 */
static void
mingw_filetime_to_timeval(FILETIME *ft, struct timeval *tv)
{
	ULARGE_INTEGER v;

	/*
	 * From MSDN documentation:
	 *
	 * A FILETIME Contains a 64-bit value representing the number of
	 * 100-nanosecond intervals since January 1, 1601 (UTC).
	 *
	 * All times are expressed using FILETIME data structures.
	 * Such a structure contains two 32-bit values that combine to form
	 * a 64-bit count of 100-nanosecond time units.
	 *
	 * It is not recommended that you add and subtract values from the
	 * FILETIME structure to obtain relative times. Instead, you should copy
	 * the low- and high-order parts of the file time to a ULARGE_INTEGER
	 * structure, perform 64-bit arithmetic on the QuadPart member, and copy
	 * the LowPart and HighPart members into the FILETIME structure.
	 */

	memcpy(&v, ft, sizeof *ft);
	v.QuadPart /= 10L;				/* Convert into microseconds */
	tv->tv_sec = li.QuadPart / 1000000L;
	tv->tv_usec = li.QuadPart % 1000000L;
}

int
mingw_getrusage(int who, struct rusage *usage)
{
	FILETIME CreationTime;
	FILETIME ExitTime;
	FILETIME KernelTime;
	FILETIME UserTime;

	if (who != RUSAGE_SELF) {
		errno = EINVAL;
		return -1;
	}
	if (NULL == usage) {
		errno = EACCESS;
		return -1;
	}

	if (
		0 == GetProcessTimes(GetCurrentProcess(),
			&CreationTime, &ExitTime, &KernelTime, &UserTime)
	) {
		errno = GetLastError();		/* FIXME: must map to UNIX error codes */
		return -1;
	}

	mingw_filetime_to_timeval(&UserTime, &usage->ru_utime);
	mingw_filetime_to_timeval(&KernelTime, &usage->ru_stime);

	return 0;
}

#endif	/* MINGW32 */

/* vi: set ts=4 sw=4 cindent: */
