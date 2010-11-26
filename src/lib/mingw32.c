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
#include <psapi.h>
#include <winnt.h>
#include <powrprof.h>

#include <glib.h>
#include <glib/gprintf.h>

#include "host_addr.h"			/* ADNS */

#include "glib-missing.h"
#include "misc.h"
#include "walloc.h"
#include "override.h"			/* Must be the last header included */

#undef stat
#undef open
#undef read
#undef write
#undef mkdir
#undef lseek

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

typedef struct processor_power_information {
  ULONG Number;
  ULONG MaxMhz;
  ULONG CurrentMhz;
  ULONG MhzLimit;
  ULONG MaxIdleState;
  ULONG CurrentIdleState;
} PROCESSOR_POWER_INFORMATION;

extern gboolean vmm_is_debugging(guint32 level);

int
mingw_fcntl(int fd, int cmd, ... /* arg */ )
{
	int res = -1;

	switch (cmd) {
		case F_SETFL:
			res = 0;
			break;
		case F_GETFL:
		{
			res = O_RDWR;
			break;
		}
		case F_SETLK:
		{
			HANDLE file =  (HANDLE)_get_osfhandle(fd);
			struct flock*  arg;
			va_list  args;
			va_start(args, cmd);
			arg = (struct flock*) va_arg(args, struct flock*);

			off_t len = arg->l_len == 0 ? 0xFFFF : arg->l_len;

			if (arg->l_type == F_WRLCK) {

				if (!LockFile(file, arg->l_start, 0, len, 0))
					errno = GetLastError();
				else
					res = 0;
			} else if (arg->l_type == F_UNLCK) {
				if (!UnlockFile(file, arg->l_start, 0, len, 0))
					errno = GetLastError();
				else
					res = 0;
			}

			va_end(args);

			break;
		}
	}

	return res;
}

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
	return _getmaxstdio();
}

int
mingw_mkdir(const char *path, mode_t mode)
{
	(void) mode;	/* FIXME: handle mode */
	return mkdir(path);
}

int
mingw_stat(const char *path, struct stat *buf)
{
	int res = stat(path, buf);
	if (res == -1)
		errno = GetLastError();
	return res;
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

off_t
mingw_lseek(int fd, off_t offset, int whence)
{
	off_t res = lseek(fd, offset, whence);
	if (res == (off_t) -1)
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
mingw_readv(int fd, iovec_t *iov, int iov_cnt)
{
    /*
     * Might want to use WriteFileGather here, however this probably has an
     * impact on the rest of the source code as well as this will be
     * unbuffered and async.
     */

    int i;
    ssize_t total_read = 0;

    for(i = 0; i< iov_cnt; i++) {
        ssize_t r = mingw_read(fd, iovec_base(&iov[i]), iovec_len(&iov[i]));
        total_read += r;

        if (r != iovec_len(&iov[i]))
            return total_read;
    }

    return total_read;
}

ssize_t
mingw_preadv(int fd, iovec_t *iov, int iov_cnt, filesize_t pos)
{
    if ((off_t) -1 == mingw_lseek(fd, pos, SEEK_SET))
		return -1;
    return mingw_readv(fd, iov, iov_cnt);
}

ssize_t
mingw_write(int fd, const void *buf, size_t count)
{
	ssize_t res = write(fd, buf, count);
	if (res == -1)
		errno = GetLastError();
	return res;
}

ssize_t
mingw_writev(int fd, const iovec_t *iov, int iov_cnt)
{
    /*
     * Might want to use WriteFileGather here, however this probably has an
     * impact on the rest of the source code as well as this will be
     * unbuffered and async.
     */

     int i;
     ssize_t total_written = 0;

     for(i = 0; i< iov_cnt; i++) {
         ssize_t w = mingw_write(fd, iovec_base(&iov[i]), iovec_len(&iov[i]));
         total_written += w;

         if (w != iovec_len(&iov[i]))
            return total_written;
     }

     return total_written;
}

ssize_t
mingw_pwritev(int fd, const iovec_t *iov, int iov_cnt, filesize_t pos)
{
	if ((off_t) -1 == mingw_lseek(fd, pos, SEEK_SET))
		return -1;
    return mingw_writev(fd, iov, iov_cnt);
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
	void *p;

	if (NULL == hint && mingw_vmm_res_nonhinted >= 0) {
		if (NULL == mingw_vmm_res_mem) {
			MEMORYSTATUSEX memStatus;
			SYSTEM_INFO system_info;
			void *mem_later;

			/* Determine maximum possible memory first */

			GetNativeSystemInfo(&system_info);

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
			while (
				NULL == mingw_vmm_res_mem && mingw_vmm_res_size > VMM_MINSIZE
			) {
				mingw_vmm_res_mem = p = VirtualAlloc(
					NULL, mingw_vmm_res_size, MEM_RESERVE, PAGE_NOACCESS);

				if (NULL == mingw_vmm_res_mem)
					mingw_vmm_res_size -= system_info.dwAllocationGranularity;
			}

			VirtualFree(mem_later, 0, MEM_RELEASE);

			if (NULL == mingw_vmm_res_mem) {
				g_error("could not reserve %s of memory",
					compact_size(mingw_vmm_res_size, FALSE));
			} else if (vmm_is_debugging(0)) {
				g_debug("reserved %s of memory",
					compact_size(mingw_vmm_res_size, FALSE));
			}
		} else {
			if (vmm_is_debugging(0))
				g_debug("no hint given for %s allocation",
					compact_size(size, FALSE));
			p = mingw_vmm_res_mem +
				(++mingw_vmm_res_nonhinted * mingw_getpagesize());
		}
		if (NULL == p) {
			errno = GetLastError();
			if (vmm_is_debugging(0))
				g_debug("could not allocate %s of memory: %s",
					compact_size(size, FALSE), g_strerror(errno));
		}
	} else if (NULL == hint && mingw_vmm_res_nonhinted < 0) {
		/*
		 * Non hinted request after hinted request are used. Allow usage of
		 * non VMM space
		 */

		p = VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

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

	p = VirtualAlloc(p, size, MEM_COMMIT, PAGE_READWRITE);

	if (p == NULL) {
		p = MAP_FAILED;
		errno = GetLastError();
	}

	return p;
}

int
mingw_vfree(void *addr, size_t size)
{
	(void) addr;
	(void) size;

	/*
	 * VMM hint should always be respected. So this function should not
	 * be reached from VMM, ever.
	 */

	g_assert_not_reached();
}

int
mingw_vfree_fragment(void *addr, size_t size)
{
	if (mingw_vmm_res_mem < addr &&
		mingw_vmm_res_mem + mingw_vmm_res_size > addr)
	{
		/* Allocated in reserved space */
		if (!VirtualFree(addr, size, MEM_DECOMMIT)) {
			errno = GetLastError();
			return -1;
		}
	} else if (!VirtualFree(addr, 0, MEM_RELEASE)) {
		/* Allocated in non-reserved space */
		errno = GetLastError();
		return -1;
	}

	return 0;
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

static char strerrbuf[1024];

const char *
mingw_strerror(gint errnum)
{
	FormatMessage(
        FORMAT_MESSAGE_FROM_SYSTEM,
        NULL, errnum,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPTSTR) strerrbuf,
        sizeof strerrbuf, NULL );

	str_chomp(strerrbuf, 0);	/* Remove final "\r\n" */
	return strerrbuf;
}

int
mingw_rename(const char *oldpath, const char *newpath)
{
	/*
	 * XXX: Try to rename a file with SetFileInformationByHandle
	 * and FILE_INFO_BY_HANDLE_CLASS
	 */

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
	static int result;
	SYSTEM_INFO system_info;

	if (G_LIKELY(result != 0))
		return result;

	GetSystemInfo(&system_info);
	return result = system_info.dwPageSize;
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
			(unsigned) osvi.dwMajorVersion, (unsigned) osvi.dwMinorVersion);
		gm_snprintf(buf->version, sizeof buf->version, "%u",
			(unsigned) osvi.dwBuildNumber);
	}

	len = sizeof buf->nodename;
	GetComputerName(buf->nodename, &len);

	return 0;
}

gboolean
mingw_process_is_alive(pid_t pid)
{
	char our_process_name[1024];
	char process_name[1024];
	HANDLE p;
	BOOL res = FALSE;

	pid_t our_pid = GetCurrentProcessId();

	/* PID might be reused */
	if (our_pid == pid)
		return FALSE;

	p = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);

	if (NULL != p) {
		GetModuleBaseName(p, NULL, process_name, sizeof process_name);
		GetModuleBaseName(GetCurrentProcess(),
			NULL, our_process_name, sizeof our_process_name);

		res = g_strcmp0(process_name, our_process_name) == 0;
		CloseHandle(p);
    }

	return res;
}

static int
mingw_cpu_count(void)
{
	static int result;
	SYSTEM_INFO system_info;

	if (G_LIKELY(result != 0))
		return result;

	GetSystemInfo(&system_info);
	return result = system_info.dwNumberOfProcessors;
}

guint64
mingw_cpufreq(enum mingw_cpufreq freq)
{
	int cpus = mingw_cpu_count();
	PROCESSOR_POWER_INFORMATION powarray[16];
	PROCESSOR_POWER_INFORMATION *p;
	size_t len;
	guint64 result = 0;

	len = cpus * sizeof *p;;
	if (UNSIGNED(cpus) <= G_N_ELEMENTS(powarray)) {
		p = powarray;
	} else {
		p = walloc(len);
	}

	if (0 == CallNtPowerInformation(ProcessorInformation, NULL, 0, p, len)) {
		switch (freq) {
		case MINGW_CPUFREQ_CURRENT:
			result = p[0].CurrentMhz * 1000000;		/* Convert to Hz */
			break;
		case MINGW_CPUFREQ_MAX:
			result = p[0].MaxMhz * 1000000;			/* Convert to Hz */
			break;
		}
	}

	if (p != powarray)
		wfree(p, len);

	return result;
}

#ifdef MINGW32_ADNS
/* Not a clean implementation yet */
/***
 *** ADNS
 ***/
#define mingw_thread_msg_quit 0x9
#define mingw_thread_msg_adns 0x100
#define mingw_thread_msg_adns_resolve 0x1000
#define mingw_thread_msg_adns_resolve_cb 0x1001

unsigned int mingw_gtkg_adns_thread_id;
DWORD mingw_gtkg_main_thread_id;


struct adns_common {
	void (*user_callback)(void);
	gpointer user_data;
	gboolean reverse;
};

struct adns_reverse_query {
	host_addr_t addr;
};

struct adns_query {
	enum net_type net;
	char hostname[MAX_HOSTLEN + 1];
};

struct adns_reply {
	char hostname[MAX_HOSTLEN + 1];
	host_addr_t addrs[10];
};

struct adns_reverse_reply {
	char hostname[MAX_HOSTLEN + 1];
	host_addr_t addr;
};

struct adns_request {
	struct adns_common common;
	union {
		struct adns_query by_addr;
		struct adns_reverse_query reverse;
	} query;
};

struct adns_response {
	struct adns_common common;
	union {
		struct adns_reply by_addr;
		struct adns_reverse_reply reverse;
	} reply;
};


gboolean
mingw_adns_send_request(const struct adns_request *req)
{
	char *hostname = strdup(req->query.by_addr.hostname);

	PostThreadMessage(mingw_gtkg_adns_thread_id,
		mingw_thread_msg_adns_resolve, (LPARAM) hostname, 0);

	return TRUE;
}

unsigned __stdcall
mingw_adns_thread_resolve(void *dummy)
{
	(void) dummy;

	MSG msg;

	while (1) {
		GetMessage(&msg, (HANDLE)-1, 0, 0);

		printf("mingw_adns: message %d\r\n", msg.message);

		if(msg.message == mingw_thread_msg_quit)
			goto exit;

		char *hostname = (char *) msg.wParam;
		struct addrinfo *results;

		getaddrinfo(hostname, NULL, NULL, &results);

		PostThreadMessage(mingw_gtkg_main_thread_id,
			mingw_thread_msg_adns_resolve_cb, (LPARAM) results, 0);
	}

exit:
	_endthreadex(0);
	return 0;
}

void
mingw_adns_init(void)
{
	/*
	 * Create ADNS thread, take care, gtkg is completely mono-threaded
	 * so it is _not_ thread safe, don't access any public functions or
	 * variables!
	 */

	mingw_gtkg_main_thread_id = GetCurrentThreadId();

	(HANDLE)_beginthreadex( NULL, 0, mingw_adns_thread_resolve, NULL, 0,
		&mingw_gtkg_adns_thread_id );
}

void
mingw_adns_close(void)
{
	/* Quit our ADNS thread */
	PostThreadMessage(mingw_gtkg_adns_thread_id, mingw_thread_msg_quit, 0, 0);
}

void
mingw_timer(void)
{
	MSG msg;

	if (PeekMessage(&msg, (HANDLE)-1, 0, 0, PM_NOREMOVE)) {
		g_debug("message waiting: %d", msg.message);

		switch (msg.message)
		{
			case mingw_thread_msg_adns_resolve_cb:
			{
				/* Need to verify the msg.wParam with IsBadReadPtr */
				struct addrinfo *results;
				results = (struct addrinfo *) msg.wParam;
				freeaddrinfo(results);
				break;
			}
		}
	}

}
#endif /* ADNS Disabled */

#endif	/* MINGW32 */

/* vi: set ts=4 sw=4 cindent: */
