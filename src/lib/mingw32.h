/*
 * Copyright (c) 2010, Jeroen Asselman & Raphael Manfredi
 *
 *----------------------------------------------------------------------
 * This file is part of gtk-gnutella.
 *
 *	gtk-gnutella is free software; you can redistribute it and/or modify
 *	it under the terms of the GNU General Public License as published by
 *	the Free Software Foundation; either version 2 of the License, or
 *	(at your option) any later version.
 *
 *	gtk-gnutella is distributed in the hope that it will be useful,
 *	but WITHOUT ANY WARRANTY; without even the implied warranty of
 *	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *	GNU General Public License for more details.
 *
 *	You should have received a copy of the GNU General Public License
 *	along with gtk-gnutella; if not, write to the Free Software
 *	Foundation, Inc.:
 *		59 Temple Place, Suite 330, Boston, MA	02111-1307	USA
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

#ifndef _mingw32_h_
#define _mingw32_h_

#ifdef MINGW32

#define FD_SETSIZE      4096

#ifndef WINVER
#define WINVER 0x0501
#endif

#include <ws2tcpip.h>

#ifdef I_WINSOCK2
#include <winsock2.h>
#endif	/* I_WINSOCK2 */

#include <sys/stat.h>
#include <glib.h>

#include "signal.h"		/* For signal_handler_t */

/*
 * Winsock to UNIX symbolic error code remapping.
 * These codes must not alias any other except for EWOULDBLOCK and ENOTSUP.
 */
#define EADDRINUSE WSAEADDRINUSE
#define EADDRNOTAVAIL WSAEADDRNOTAVAIL
#define EAFNOSUPPORT WSAEAFNOSUPPORT
#define EALREADY WSAEALREADY
#define ECANCELED WSAECANCELLED
#define ECONNABORTED WSAECONNABORTED
#define ECONNREFUSED WSAECONNREFUSED
#define ECONNRESET WSAECONNRESET
#define EDESTADDRREQ WSAEDESTADDRREQ
#define EDQUOT WSAEDQUOT
#define EHOSTDOWN WSAEHOSTDOWN
#define EHOSTUNREACH WSAEHOSTUNREACH
#define EINPROGRESS WSAEINPROGRESS
#define EISCONN WSAEISCONN
#define ELOOP WSAELOOP
#define EMSGSIZE WSAEMSGSIZE
#define ENETDOWN WSAENETDOWN
#define ENETRESET WSAENETRESET
#define ENETUNREACH WSAENETUNREACH
#define ENOBUFS WSAENOBUFS
#define ENOPROTOOPT WSAENOPROTOOPT
#define ENOTCONN WSAENOTCONN
#define ENOTSOCK WSAENOTSOCK
#define EOPNOTSUPP WSAEOPNOTSUPP
#define ENOTSUP EOPNOTSUPP	/* ENOTSUP missing in MinGW (GLibc has same bug) */
#define EPROTONOSUPPORT WSAEPROTONOSUPPORT
#define EPROTOTYPE WSAEPROTOTYPE
#define ESTALE WSAESTALE
#define ETIMEDOUT WSAETIMEDOUT

#define EOVERFLOW ERROR_ARITHMETIC_OVERFLOW	/* EOVERFLOW missing */

#define SHUT_RD	SD_RECEIVE
#define SHUT_WR	SD_SEND
#define SHUT_RDWR SD_BOTH

#define S_IXGRP	_S_IEXEC
#define S_IWGRP	_S_IWRITE
#define S_IRGRP	_S_IREAD

#define S_IRWXG _S_IREAD
#define S_IRWXO _S_IREAD

#define S_IROTH 0
#define S_IWOTH 0
#define S_ISUID 0
#define S_ISGID 0

#define MAP_PRIVATE 0	/* FIXME */

/* We-re emulating mprotect() */
#define PROT_NONE	0x0
#define PROT_READ	0x1
#define PROT_WRITE	0x2

#define O_NONBLOCK 0

/* Should fix the usage of all of the following */
#define F_DUPFD	0
#define F_GETFD	1
#define F_SETFD	2
#define F_GETFL	3
#define F_SETFL	4
#define F_GETLK	5
#define F_SETLK	6
#define F_SETLKW 7

#define F_RDLCK	0
#define F_WRLCK	1
#define F_UNLCK	2

#define S_IFLNK 0120000 /* Symbolic link */

#define signal(n, h) mingw_signal((n), (h))

#ifndef SIGBUS
#define SIGBUS	10		/* Simulated, unassigned signal number in MinGW32 */
#endif

#ifndef SIGTRAP
#define SIGTRAP	12		/* Simulated, unassigned signal number in MinGW32 */
#endif

#define getppid()		1
#define fcntl mingw_fcntl
#define ffs __builtin_ffs

#define select mingw_select
#define socket mingw_socket
#define bind mingw_bind
#define getsockopt mingw_getsockopt
#define setsockopt mingw_setsockopt
#define connect mingw_connect
#define listen mingw_listen
#define accept mingw_accept
#define shutdown mingw_shutdown
#define s_writev mingw_s_writev
#define s_readv mingw_s_readv

#define getaddrinfo mingw_getaddrinfo
#define freeaddrinfo mingw_freeaddrinfo

#define stat(path, buf) mingw_stat((path), (buf))
#define fstat(fd, buf) mingw_fstat((fd), (buf))
#define unlink(path) mingw_unlink((path))
#define open mingw_open
#define fopen mingw_fopen
#define freopen mingw_freopen
#define opendir mingw_opendir
#define readdir mingw_readdir
#define closedir mingw_closedir
#define dup2 mingw_dup2
#define lseek mingw_lseek
#define read mingw_read
#define readv mingw_readv
#define write mingw_write
#define writev mingw_writev
#define truncate mingw_truncate
#define recv mingw_recv
#define sendto mingw_sendto
#define recvfrom mingw_recvfrom

#ifdef HAS_WSARECVMSG
#define recvmsg mingw_recvmsg
ssize_t mingw_recvmsg(socket_fd_t s, struct msghdr *hdr, int flags);
#endif	/* HAS_WSARECVMSG */

#define mprotect mingw_mprotect
#define getlogin mingw_getlogin
#define getpagesize mingw_getpagesize
#undef getdtablesize
#define getdtablesize mingw_getdtablesize
#define mkdir mingw_mkdir
#define access mingw_access
#define chdir mingw_chdir
#define remove mingw_remove
#define pipe mingw_pipe
#define getrlimit mingw_getrlimit

#define abort() mingw_abort()

typedef SOCKET socket_fd_t;
typedef WSABUF iovec_t;
typedef unsigned short sa_family_t;

struct msghdr {
	void *msg_name;				/* Address to send to/receive from */
	socklen_t msg_namelen;		/* Length of address data */
	iovec_t *msg_iov;	 		/* Vector of data to send/receive into */
	size_t msg_iovlen;			/* Number of elements in the vector */
	void *msg_control;			/* Ancillary data (eg BSD filedesc passing) */
	/*
	 * This type should be socklen_t but the definition of the kernel is
	 * incompatible with this.
	 */
	size_t msg_controllen;		/* Ancillary data buffer length */
	int msg_flags;				/* Flags on received message.  */
};

typedef __int64 fileoffset_t;
typedef struct _stati64 filestat_t;

struct passwd {
	char *pw_name;                /* Username.  */
	char *pw_passwd;              /* Password.  */
#if 0
	__uid_t pw_uid;               /* User ID.  */
	__gid_t pw_gid;               /* Group ID.  */
	char *pw_gecos;               /* Real name.  */
	char *pw_dir;                 /* Home directory.  */
	char *pw_shell;               /* Shell program.  */
#endif /* 0 */
};

struct flock {
    short int l_type;	/* Type of lock: F_RDLCK, F_WRLCK, or F_UNLCK.  */
    short int l_whence;	/* Where `l_start' is relative to (like `lseek').  */
    fileoffset_t l_start;		/* Offset where the lock begins.  */
    fileoffset_t l_len;		/* Size of the locked area; zero means until EOF.  */
    pid_t l_pid;		/* Process holding the lock.  */
};

struct mingw_statvfs {
	unsigned long f_csize;		/* Cluster size, in bytes */
	unsigned long f_cavail;		/* Available clusters */
	unsigned long f_clusters;	/* Total amount of clusters */

};

#ifndef HAS_GETLOGIN
#define HAS_GETLOGIN			/* We emulate it */
#endif

/*
 * getrlimit() emulation.
 */
#ifndef HAS_GETRLIMIT
#define HAS_GETRLIMIT			/* We emulate it */
#define EMULATE_GETRLIMIT

#define RLIMIT_CORE 1
#define RLIMIT_DATA 2

typedef unsigned long rlim_t;

struct rlimit {
	rlim_t rlim_cur;
	rlim_t rlim_max;
};

int mingw_getrlimit(int resource, struct rlimit *rlim);
#endif	/* !HAS_GETRLIMIT */

/*
 * sched_yield() emulation
 */
#ifndef HAS_SCHED_YIELD
#define HAS_SCHED_YIELD			/* We emulate it */
#define EMULATE_SCHED_YIELD
#undef I_SCHED					/* Do not include <sched.h> */

/*
 * We can't define sched_yield because on MinGW, <pthread.h> forcefully
 * includes <sched.h> and it will cause sched_yield() to be declared as
 * belonging to a DLL.  But since that file inclusion occurs after our
 * remapping, mingw_sched_yield() is viewed as meaning _imp_mingw_sched_yield
 * and causes a link failure.
 *
 * Hence define it as do_sched_yield.
 */
#define do_sched_yield() mingw_sched_yield()

int mingw_sched_yield(void);
#endif	/* !HAS_SCHED_YIELD */

/*
 * getrusage() emulation.
 */
#ifndef HAS_GETRUSAGE
#define HAS_GETRUSAGE			/* We emulate it */
#define EMULATE_GETRUSAGE
#define getrusage mingw_getrusage

#define RUSAGE_SELF 0
#define RUSAGE_CHILDREN (-1)
#define RUSAGE_BOTH (-2)
#define RUSAGE_THREAD 1

struct rusage {
	struct timeval ru_utime;	/* user time used */
	struct timeval ru_stime;	/* system time used */
};

int mingw_getrusage(int who, struct rusage *usage);
#endif	/* !HAS_GETRUSAGE */

/*
 * uname() emulation.
 */
#ifndef HAS_UNAME
#define HAS_UNAME				/* We emulate it */
#define EMULATE_UNAME
#define uname mingw_uname

#define UTSNAME_LENGTH		65
#define UTSNAME_EXT_LENGTH	128

struct utsname {
	char sysname[UTSNAME_LENGTH];
	char nodename[UTSNAME_LENGTH];
	char release[UTSNAME_LENGTH];
	char version[UTSNAME_EXT_LENGTH];
	char machine[UTSNAME_LENGTH];
};

int mingw_uname(struct utsname *buf);
#endif	/* !HAS_UNAME */

/*
 * nanosleep() emulation.
 */
#ifndef HAS_NANOSLEEP
#define HAS_NANOSLEEP			/* We emulate it */
#define EMULATE_NANOSLEEP
#define nanosleep mingw_nanosleep

/* Mingw-w64 defines a timespec */
#ifndef _TIMESPEC_DEFINED
#define _TIMESPEC_DEFINED
#define HAVE_STRUCT_TIMESPEC	/* For <pthread.h> */
struct timespec {
	time_t tv_sec;				/* seconds */
	long tv_nsec;				/* nanoseconds */
};
#endif

int mingw_nanosleep(const struct timespec *req, struct timespec *rem);
#endif	/* !HAS_NANOSLEEP */

static inline void *
iovec_base(const iovec_t* iovec)
{
	return iovec->buf;
}

static inline size_t
iovec_len(const iovec_t* iovec)
{
	return iovec->len;
}

static inline void
iovec_set_base(iovec_t* iovec, const void *base)
{
	iovec->buf = (void *) base;
}

static inline void
iovec_set_len(iovec_t* iovec, size_t len)
{
	iovec->len = len;
}

static inline void
iovec_set(iovec_t* iovec, const void *base, size_t len)
{
	iovec->buf = (void *) base;
	iovec->len = len;
}

signal_handler_t mingw_signal(int signo, signal_handler_t handler);

int mingw_fcntl(int fd, int cmd, ... /* arg */ );

const char *mingw_get_admin_tools_path(void);
const char *mingw_get_common_appdata_path(void);
const char *mingw_get_common_docs_path(void);
const char *mingw_get_cookies_path(void);
const char *mingw_get_fonts_path(void);
const char *mingw_get_history_path(void);
const char *mingw_get_home_path(void);
const char *mingw_get_internet_cache_path(void);
const char *mingw_get_mypictures_path(void);
const char *mingw_get_personal_path(void);
const char *mingw_get_program_files_path(void);
const char *mingw_get_startup_path(void);
const char *mingw_get_system_path(void);
const char *mingw_get_windows_path(void);

uint64 mingw_getphysmemsize(void);
int mingw_getdtablesize(void);
const char *mingw_strerror(int errnum);
int mingw_stat(const char *pathname, filestat_t *buf);
int mingw_fstat(int fd, filestat_t *buf);
int mingw_dup2(int oldfd, int newfd);
int mingw_open(const char *pathname, int flags, ...);
int mingw_unlink(const char *pathname);
void *mingw_opendir(const char *pathname);
void *mingw_readdir(void *);
int mingw_closedir(void *);
fileoffset_t mingw_lseek(int fd, fileoffset_t offset, int whence);
int mingw_rename(const char *oldpathname, const char *newpathname);
int mingw_truncate(const char *pathname, fileoffset_t len);
int mingw_mkdir(const char *pathname, mode_t mode);
int mingw_access(const char *pathname, int mode);
int mingw_chdir(const char *pathname);
int mingw_remove(const char *pathname);
FILE *mingw_fopen(const char *pathname, const char *mode);
FILE *mingw_freopen(const char *pathname, const char *mode, FILE *file);
int mingw_pipe(int fd[2]);

ssize_t mingw_read(int fd, void *buf, size_t count);
ssize_t mingw_readv(int fd, iovec_t *iov, int iov_cnt);
ssize_t mingw_preadv(int fd, iovec_t *iov, int iov_cnt, filesize_t pos);
ssize_t mingw_write(int fd, const void *buf, size_t count);
ssize_t mingw_writev(int fd, const iovec_t *iov, int iov_cnt);
ssize_t mingw_pwritev(int fd, const iovec_t *iov, int iov_cnt, filesize_t pos);

/*
 * sbrk() emulation.
 */
#ifndef HAS_SBRK
#define HAS_SBRK			/* We emulate it */
#define EMULATE_SBRK
#define sbrk mingw_sbrk

void *mingw_sbrk(long incr);
#endif	/* !HAS_SBRK */

/*
 * gettimeofday() emulation.
 */
#ifndef HAS_GETTIMEOFDAY
#define HAS_GETTIMEOFDAY	/* We emulate it */
#define EMULATE_GETTIMEOFDAY
#define gettimeofday mingw_gettimeofday

int mingw_gettimeofday(struct timeval *tv, void *unused);
#endif	/* !HAS_GETTIMEOFDAY */

/*
 * dladdr() emulation
 */
#ifndef HAS_DLADDR
#define HAS_DLADDR			/* We emulate it */
#define EMULATE_DLADDR
#define dladdr mingw_dladdr
#define dlerror mingw_dlerror

typedef struct {
	const char *dli_fname;	/* Pathname of shared object containing address */
	void *dli_fbase;		/* Address at which shared object is loaded */
	const char *dli_sname;	/* Name of nearest symbol with lower address */
	void *dli_saddr;		/* Exact address of symbol named dli_sname */
} Dl_info;

int mingw_dladdr(void *addr, Dl_info *info);
const char *dlerror(void);
#endif	/* !HAS_DLADDR */

/*
 * Socket functions
 *
 * Under windows, socket descriptors are not the same as file descriptiors.
 * Hence the systematic use of socket_fd_t, which is typedef'ed to int on UNIX.
 *
 * The s_read(), s_write() and s_close() system calls are meant to be used
 * on socket file decriptors.  Other routines like sendto() are clearly
 * socket-specific and hence do not need to be distinguished by a prefix.
 * Naturally, s_read() is mapped to read() on UNIX.
 */

int mingw_select(int nfds, fd_set *readfds, fd_set *writefds,
	fd_set *exceptfds, struct timeval *timeout);

int mingw_getaddrinfo(const char *node, const char *service,
		const struct addrinfo *hints, struct addrinfo **res);
void mingw_freeaddrinfo(struct addrinfo *res);

socket_fd_t mingw_socket(int domain, int type, int protocol);
int mingw_bind(socket_fd_t, const struct sockaddr *addr, socklen_t addrlen);
socket_fd_t mingw_connect(socket_fd_t, const struct sockaddr *, socklen_t);
int mingw_listen(socket_fd_t sockfd, int backlog);
socket_fd_t mingw_accept(socket_fd_t, struct sockaddr *addr, socklen_t *len);
int mingw_shutdown(socket_fd_t sockfd, int how);
int mingw_getsockopt(socket_fd_t, int level, int optname, void *, socklen_t *);
int mingw_setsockopt(socket_fd_t, int, int, const void *, socklen_t optlen);
ssize_t mingw_recv(socket_fd_t fd, void *buf, size_t len, int recv_flags);
ssize_t mingw_sendto(socket_fd_t, const void *buf, size_t len, int flags,
		const struct sockaddr *dest_addr, socklen_t addrlen);
ssize_t s_write(socket_fd_t fd, const void *buf, size_t count);
ssize_t s_read(socket_fd_t fd, void *buf, size_t count);
ssize_t mingw_s_readv(socket_fd_t fd, const iovec_t *iov, int iovcnt);
ssize_t mingw_recvfrom(socket_fd_t, void *, size_t, int,
			struct sockaddr *, socklen_t *);

int s_close(socket_fd_t fd);
ssize_t mingw_s_writev(socket_fd_t fd, const iovec_t *iov, int iovcnt);

#define rename(oldpath, newpath) mingw_rename((oldpath), (newpath))
#define g_strerror(errnum) mingw_strerror(errnum)

void *mingw_valloc(void *hint, size_t size);
int mingw_vfree(void *addr, size_t size);
int mingw_vfree_fragment(void *addr, size_t size);
int mingw_mprotect(void *addr, size_t len, int prot);

int mingw_random_bytes(void *buf, size_t len);
bool mingw_process_is_alive(pid_t pid);

int mingw_statvfs(const char *pathname, struct mingw_statvfs *buf);
long mingw_cpu_count(void);
uint64 mingw_cpufreq_min(void);
uint64 mingw_cpufreq_max(void);
const char *mingw_getlogin(void);
int mingw_getpagesize(void);
int mingw_backtrace(void **buffer, int size, size_t offset);

enum mingw_cpufreq {
	MINGW_CPUFREQ_CURRENT,
	MINGW_CPUFREQ_MAX
};

uint64 mingw_cpufreq(enum mingw_cpufreq freq);

typedef struct pollfd {
  SOCKET fd;
  short  events;
  short  revents;
} WSAPOLLFD;

static inline unsigned
socket_fd(int fd)
{
	return fd;
}

bool mingw_has_wsapoll(void);
int mingw_poll(struct pollfd *fds, unsigned n, int timeout);
void mingw_early_init(void);
void mingw_vmm_post_init(void);
void mingw_init(void);
void mingw_close(void);

const char *mingw_filename_nearby(const char *file);
bool mingw_stdin_pending(bool fifo);
bool mingw_same_file_id(const char *pathname_a, const char *pathname_b);

struct tmval;	/* our own portable representation of "struct timeval" */
void mingw_current_time(struct tmval *tv);

const char *dir_entry_filename(const void *dirent);
int mingw_getgateway(uint32 *ip);

bool mingw_in_exception(void);
void G_GNUC_NORETURN mingw_abort(void);

struct adns_request;

void mingw_adns_init(void);
void mingw_adns_close(void);
bool mingw_adns_send_request(const struct adns_request *req);

char *mingw_patch_personal_path(const char *pathname);
const char *mingw_native_path(const char *pathname);

#else	/* !MINGW32 */

#define mingw_early_init();
#define mingw_vmm_post_init()
#define mingw_init()
#define mingw_close()
#define mingw_patch_personal_path(p)	(p)

#define mingw_get_admin_tools_path()	"/"
#define mingw_get_common_appdata_path()	"/"
#define mingw_get_common_docs_path()	"/"
#define mingw_get_cookies_path()		"/"
#define mingw_get_fonts_path()			"/"
#define mingw_get_history_path()		"/"
#define mingw_get_home_path()			"/"
#define mingw_get_internet_cache_path()	"/"
#define mingw_get_mypictures_path()		"/"
#define mingw_get_personal_path()		"/"
#define mingw_get_program_files_path()	"/"
#define mingw_get_startup_path()		"/"
#define mingw_get_system_path()			"/"
#define mingw_get_windows_path()		"/"

#define mingw_in_exception()		0

#endif	/* MINGW32 */
#endif /* _mingw32_h_ */

/* vi: set ts=4 sw=4 cindent: */
