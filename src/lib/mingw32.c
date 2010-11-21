/*
 * $Id$
 *
 * Copyright (c) 2010, Jeroen Asselman & Raphael Manfredi
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
 * @author Raphael Manfredi
 * @date 2010
 */

#include "common.h"

/*
 * This whole file is only compiled under Windows.
 */

#ifdef MINGW32

RCSID("$Id$")

#include <windows.h>
#include <mswsock.h>
#include <shlobj.h>
#include <wincrypt.h>

#include "misc.h"
#include "override.h"			/* Must be the last header included */

#undef open
#undef read
#undef write
#undef mkdir

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

#define VMM_MINSIZE (1024*1024*100)	/* At least 100 MB */
#define ALTVMM 1

extern gboolean vmm_is_debugging(guint32 level);

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

guint
mingw_getdtablesize(void)
{
	return 1024;	/* FIXME: max number of file descriptors per process */
}

int
mingw_mkdir(const char *path, mode_t mode)
{
	(void) mode;	/* FIXME: handle mode */
	return mkdir(path);
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
	if (res == -1)
		errno = GetLastError();
	return res;
}

ssize_t 
mingw_read(int fd, void *buf, size_t count)
{
	ssize_t res = read(fd, buf, count);
	if (res == -1)
		errno = GetLastError();
	return res;
}

ssize_t
mingw_write(int fd, const void *buf, size_t count)
{
	ssize_t res = write(fd, buf, count);
	if (res == -1)
		errno = GetLastError();
	return res;
}

int
mingw_truncate(const char *path, off_t len)
{
	int fd, ret, saved_errno;

	fd = open(path, O_RDWR);
	if (-1 == fd) {
		errno = GetLastError();
		return -1;
	}

	ret = ftruncate(fd, len);
	saved_errno = (ret == -1) ? GetLastError() : 0;
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
	if (result != 0)
		errno = WSAGetLastError();
	return result;
}			

void mingw_freeaddrinfo(struct addrinfo *res)
{
	freeaddrinfo(res);
}

socket_fd_t 
mingw_socket(int domain, int type, int protocol)
{
	socket_fd_t res = socket(domain, type, protocol);
	if (res == INVALID_SOCKET)
		errno = WSAGetLastError();
	return res;
}

int 
mingw_bind(socket_fd_t sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
	int res = bind(sockfd, addr, addrlen);
	if (res == -1)
		errno = WSAGetLastError();
	return res;
}

socket_fd_t 
mingw_connect(socket_fd_t sockfd, const struct sockaddr *addr,
	  socklen_t addrlen)
{
	socket_fd_t res = connect(sockfd, addr, addrlen);
	if (res == INVALID_SOCKET)
		errno = WSAGetLastError();
	return res;
}

int
mingw_listen(socket_fd_t sockfd, int backlog)
{
	int res = listen(sockfd, backlog);
	if (res == -1)
		errno = WSAGetLastError();
	return res;
}

socket_fd_t
mingw_accept(socket_fd_t sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
	socket_fd_t res = accept(sockfd, addr, addrlen);
	if (res == INVALID_SOCKET)
		errno = WSAGetLastError();
	return res;
}

int 
mingw_shutdown(socket_fd_t sockfd, int how)
{
	int res = shutdown(sockfd, how);
	if (res == -1)
		errno = WSAGetLastError();
	return res;
}

int 
mingw_getsockopt(socket_fd_t sockfd, int level, int optname,
	void *optval, socklen_t *optlen)
{
	int res = getsockopt(sockfd, level, optname, optval, optlen);
	if (res == -1)
		errno = WSAGetLastError();
	return res;
}

int 
mingw_setsockopt(socket_fd_t sockfd, int level, int optname, 
	  const void *optval, socklen_t optlen)
{
	int res = setsockopt(sockfd, level, optname, optval, optlen);
	if (res == -1)
		errno = WSAGetLastError();
	return res;
}


ssize_t 
s_write(socket_fd_t fd, const void *buf, size_t count)
{
	ssize_t res = send(fd, buf, count, 0);
	if (res == -1)
		errno = WSAGetLastError();
	return res;
}

ssize_t 
s_read(socket_fd_t fd, void *buf, size_t count)
{
	ssize_t res = recv(fd, buf, count, 0);
	if (res == -1)
		errno = WSAGetLastError();
	return res;
}

int 
s_close(socket_fd_t fd)
{
	int res = closesocket(fd);
	if (res == -1)
		errno = WSAGetLastError();
	return res;
}

size_t 
mingw_s_readv(socket_fd_t fd, const iovec_t *iov, int iovcnt)
{
	DWORD r, flags = 0;
	int res = WSARecv(fd, (LPWSABUF) iov, iovcnt, &r, &flags, NULL, NULL);

	if (res != 0)
		errno = WSAGetLastError();
	return r;
}

ssize_t 
mingw_s_writev(socket_fd_t fd, const iovec_t *iov, int iovcnt)
{
	DWORD w;
	int res = WSASend(fd, (LPWSABUF) iov, iovcnt, &w, 0, NULL, NULL);
  
	if (res != 0)
		errno = WSAGetLastError();
	return w;
};

ssize_t 
recvmsg(socket_fd_t s, struct msghdr *hdr, int flags) 
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
	if (res != 0) {
		errno = WSAGetLastError();
		return -1;
	}
	return received;

#else
	/* WSARecvMsg is available in windows, but not in mingw */
    
	size_t i;
    WSABUF buf[hdr->msg_iovlen];
	DWORD received;
	INT ifromLen;
	DWORD dflags;
	
	if (hdr->msg_iovlen > 100) {
		g_warning("recvmsg: msg_iovlen to large: %d", hdr->msg_iovlen);
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
	
    if (
		0 != WSARecvFrom(s, buf, i, &received, &dflags,
			hdr->msg_name, &ifromLen, NULL, NULL)
	) {
		errno = WSAGetLastError();
		return -1;
	}
	
	return received;
#endif
}

ssize_t mingw_sendto(socket_fd_t sockfd, const void *buf, size_t len, int flags,
	  const struct sockaddr *dest_addr, socklen_t addrlen)
{
	ssize_t res = sendto(sockfd, buf, len, flags, dest_addr, addrlen);
	if (res == -1)
		errno = WSAGetLastError();
	return res;
}

/***
 *** Memory allocation routines.
 ***/
static void *mingw_vmm_res_mem;
static size_t mingw_vmm_res_size;
static int mingw_vmm_res_nonhinted = 0;

void *
mingw_valloc(void *hint, size_t size)
{
#ifdef ALTVMM
	void *p;
	if (!hint && mingw_vmm_res_nonhinted >= 0) {
		if (!mingw_vmm_res_mem) {
				/* Determine maximum possible memory first */
				MEMORYSTATUSEX memStatus;
				SYSTEM_INFO system_info;
				GetNativeSystemInfo(&system_info);
				void *mem_later;
				
				mingw_vmm_res_size = 
					system_info.lpMaximumApplicationAddress 
					- 
					system_info.lpMinimumApplicationAddress;

				memStatus.dwLength = sizeof memStatus;					
				if (GlobalMemoryStatusEx(&memStatus)) {
					if (memStatus.ullTotalPhys < mingw_vmm_res_size)
						mingw_vmm_res_size = memStatus.ullTotalPhys;
				}
				
				/* Declare some space for feature allocs without hinting */
				mem_later = VirtualAlloc(
					NULL, VMM_MINSIZE, MEM_RESERVE, PAGE_NOACCESS);
					
				/* Try to reserve it */
				while (!mingw_vmm_res_mem && mingw_vmm_res_size > VMM_MINSIZE) {				
					mingw_vmm_res_mem = p = VirtualAlloc(
						NULL, mingw_vmm_res_size, MEM_RESERVE, PAGE_NOACCESS);
					
					if (!mingw_vmm_res_mem)
						mingw_vmm_res_size -= 
							system_info.dwAllocationGranularity;
				}
				
				VirtualFree(mem_later, 0, MEM_RELEASE);
				 
				if (!mingw_vmm_res_mem) {
					g_error("could not reserve %s of memory",
						compact_size(mingw_vmm_res_size, FALSE));
				} else if (vmm_is_debugging(0)) {
					g_debug("reserved %s of memory",
						compact_size(mingw_vmm_res_size, FALSE));
				}
		} else {
			SYSTEM_INFO system_info;

			GetSystemInfo(&system_info);
			
			if (vmm_is_debugging(0)) 
				g_debug("no hint given for %s allocation", 
					compact_size(size, FALSE));
			p = mingw_vmm_res_mem + 
				(++mingw_vmm_res_nonhinted * system_info.dwPageSize);
		}
		if (!p) {
			errno = GetLastError();
			if (vmm_is_debugging(0)) 
				g_debug("could not allocate %s of memory: %s",
					compact_size(size, FALSE), g_strerror(errno));
		}
	} else if (!hint && mingw_vmm_res_nonhinted < 0) {
		/* Non hinted request after hinted request are used. Allow usage of
		 * non VMM space */
		p = (void *) VirtualAlloc(NULL, size, 
			MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		
		if (p == NULL) {
			errno = GetLastError();
			p = MAP_FAILED;
		}
		return p;
	} else {
		/* Can't handle non-hinted allocations anymore */
		mingw_vmm_res_nonhinted = -1;
		p = hint;
	}
	
	p = (void *) VirtualAlloc(p, size, MEM_COMMIT, PAGE_READWRITE);
		
	if (p == NULL) {
		p = MAP_FAILED;
		errno = GetLastError();
	}

	return p;
#else
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
#endif
}

int
mingw_vfree(void *addr, size_t size)
{
#ifdef ALTVMM
	(void) addr;
	(void) size;
	
	/* 
	 * VMM hint should always be respected. So this function should not
	 * be reached from VMM, ever.
	 */
	
	g_assert_not_reached();
#else
	(void) size;

	if (0 == VirtualFree(addr, 0, MEM_RELEASE)) {
		errno = GetLastError();
		return -1;
	}

	return 0;	/* OK */
#endif
}

int
mingw_vfree_fragment(void *addr, size_t size)
{
#ifdef ALTVMM
	
	if (mingw_vmm_res_mem < addr &&
		mingw_vmm_res_mem + mingw_vmm_res_size > addr)
	{
		/* Allocated in non reserved space */
		if (!VirtualFree(addr, 0, MEM_DECOMMIT)) {
			errno = GetLastError();
			return -1;
		}
	} else if (!VirtualFree(addr, size, MEM_DECOMMIT)) {
		/* Allocated in reserved space */
		errno = GetLastError();
		return -1;
	}

	return 0;
#else
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
			g_warning("RegionSize is smaller then requested decommit"
				" size, leaking!");
#if 0	/* Seems to crash otherwise */
			if (0 == VirtualFree(remain_ptr, remain_size, MEM_DECOMMIT))
				goto error;
#endif
		}
	}

	return 0;		/* OK */

error:
	errno = GetLastError();
	return -1;
#endif
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
		if (vmm_is_debugging(0)) {
			g_debug("VMM mprotect(0x%lx, %u) failed: errno=%d",
				(unsigned long) addr, (unsigned) len, errno);
		}
		return -1;
	}

	return 0;	/* OK */
}

/***
 *** Random numbers.
 ***/

/**
 * Fill supplied buffer with random bytes.
 * @return amount of generated random bytes.
 */
int
mingw_random_bytes(void *buf, size_t len)
{
	HCRYPTPROV crypth = 0;

	g_assert(len <= MAX_INT_VAL(int));

	if (
		!CryptAcquireContext(&crypth, NULL, NULL, PROV_RSA_FULL,
			CRYPT_VERIFYCONTEXT | CRYPT_SILENT)
	) {
		errno = GetLastError();
		return 0;
	}

	memset(buf, 0, len);
	if (!CryptGenRandom(crypth, len, buf)) {
		errno = GetLastError();
		len = 0;
	}
	CryptReleaseContext(crypth, 0);

	return (int) len;
}

/***
 *** Miscellaneous.
 ***/

gchar strerrbuf[1024];
const gchar* mingw_strerror(gint errnum)
{	
	FormatMessage(
        FORMAT_MESSAGE_FROM_SYSTEM,
        NULL, errnum,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPTSTR) strerrbuf,
        sizeof(strerrbuf), NULL );
	
	return strerrbuf;
}

int 
mingw_rename(const char *oldpath, const char *newpath)
{
	if (!MoveFileEx(oldpath, newpath, MOVEFILE_REPLACE_EXISTING)) {
		errno = GetLastError();
		return -1;
	}

	return 0;
}

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
	tv->tv_sec = v.QuadPart / 1000000L;
	tv->tv_usec = v.QuadPart % 1000000L;
}

int
mingw_getrusage(int who, struct rusage *usage)
{
	FILETIME creation_time, exit_time, kernel_time, user_time;

	if (who != RUSAGE_SELF) {
		errno = EINVAL;
		return -1;
	}
	if (NULL == usage) {
		errno = EACCES;
		return -1;
	}

	if (
		0 == GetProcessTimes(GetCurrentProcess(),
			&creation_time, &exit_time, &kernel_time, &user_time)
	) {
		errno = GetLastError();
		return -1;
	}

	mingw_filetime_to_timeval(&user_time, &usage->ru_utime);
	mingw_filetime_to_timeval(&kernel_time, &usage->ru_stime);

	return 0;
}

const char *
mingw_getlogin(void)
{
	static char buf[128];
	static char *result;
	static gboolean inited;
	DWORD size;

	if (G_LIKELY(inited))
		return result;

	size = sizeof buf;
	result = 0 == GetUserName(buf, &size) ? NULL : buf;

	inited = TRUE;
	return result;
}

int
mingw_getpagesize(void)
{
	SYSTEM_INFO system_info;

	GetSystemInfo(&system_info);
	return system_info.dwPageSize;
}

int
mingw_uname(struct utsname *buf)
{
	SYSTEM_INFO system_info;
	OSVERSIONINFOEX osvi;
	DWORD len;
	const char *cpu;

	memset(buf, 0, sizeof *buf);

	GetNativeSystemInfo(&system_info);
	g_strlcpy(buf->sysname, "Windows", sizeof buf->sysname);

	switch (system_info.wProcessorArchitecture) {
	case PROCESSOR_ARCHITECTURE_AMD64:	cpu = "x64"; break;
	case PROCESSOR_ARCHITECTURE_IA64:	cpu = "ia64"; break;
	case PROCESSOR_ARCHITECTURE_INTEL:	cpu = "x86"; break;
	default:							cpu = "unknown"; break;
	}
	g_strlcpy(buf->machine, cpu, sizeof buf->machine);

	osvi.dwOSVersionInfoSize = sizeof osvi;
	if (GetVersionEx((OSVERSIONINFO *) &osvi)) {
		gm_snprintf(buf->release, sizeof buf->release, "%u.%u",
			osvi.dwMajorVersion, osvi.dwMinorVersion);
		gm_snprintf(buf->version, sizeof buf->version, "%u",
			osvi.dwBuildNumber);
	}

	len = sizeof buf->nodename;
	GetComputerName(buf->nodename, &len);

	return 0;
}

gboolean
mingw_process_is_alive(pid_t pid)
{
	HANDLE p;

	p = OpenProcess(SYNCHRONIZE, FALSE, pid);

	if (NULL == p)
		return FALSE;

	CloseHandle(p);
	return TRUE;
}

#endif	/* MINGW32 */

/* vi: set ts=4 sw=4 cindent: */
