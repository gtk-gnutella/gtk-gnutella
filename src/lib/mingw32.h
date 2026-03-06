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

#define MINGW_TRACEFILE_KEEP	3		/* Keep logs for that many past runs */
#define FD_SETSIZE      		4096	/* Max # of descriptors for select() */

#include <ws2tcpip.h>

#ifdef I_WINSOCK2
#include <winsock2.h>
#endif	/* I_WINSOCK2 */

#include <sys/stat.h>
#include <glib.h>

#include "signal.h"				/* For signal_handler_t */
#include "compat_gettid.h"		/* For systid_t */

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
#define ESHUTDOWN WSAESHUTDOWN

#define EOVERFLOW ERROR_ARITHMETIC_OVERFLOW	/* EOVERFLOW missing */

#define SHUT_RD	SD_RECEIVE
#define SHUT_WR	SD_SEND
#define SHUT_RDWR SD_BOTH

#define S_IXGRP	_S_IEXEC
#define S_IWGRP	_S_IWRITE
#define S_IRGRP	_S_IREAD

#define S_IRWXG _S_IREAD
#define S_IRWXO _S_IREAD

/* Unsupported on Windows, assign them an unused mode_t bit */
#define S_IROTH (1U << 31)
#define S_IWOTH (1U << 31)
#define S_IXOTH (1U << 31)
#define S_ISUID (1U << 31)
#define S_ISGID (1U << 31)
#define S_ISVTX (1U << 31)

#define MAP_PRIVATE 0	/* FIXME */

/* We-re emulating mprotect() */
#define PROT_NONE	0x0
#define PROT_READ	0x1
#define PROT_WRITE	0x2
#define PROT_GUARD	0x4		/* Windows-specific, see mingw_mprotect() */

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

#ifndef SIGEMT
#define SIGEMT 7		/* Simulated, unassigned signal number in MingGW32 */
#endif

#ifndef SIGKILL
#define SIGKILL 9		/* Unassigned signal number in MingGW32 */
#endif

#ifndef SIGBUS
#define SIGBUS	10		/* Simulated, unassigned signal number in MinGW32 */
#endif

#ifndef SIGTRAP
#define SIGTRAP	12		/* Simulated, unassigned signal number in MinGW32 */
#endif

#ifndef SIGPIPE
#define SIGPIPE	13		/* Simulated, unassigned signal number in MinGW32 */
#endif

#define fcntl mingw_fcntl
#define ffs __builtin_ffs
#define sleep mingw_sleep

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
#define socketpair mingw_socketpair

#ifndef HAS_SOCKETPAIR
#define EMULATE_SOCKETPAIR
#define HAS_SOCKETPAIR
#endif	/* !HAS_SOCKETPAIR */

#define gethostname mingw_gethostname
#define getaddrinfo mingw_getaddrinfo
#define freeaddrinfo mingw_freeaddrinfo

#undef stat
#undef fstat
#define stat(path, buf) mingw_stat((path), (buf))
#define fstat(fd, buf) mingw_fstat((fd), (buf))
#define unlink(path) mingw_unlink(path)
#define open mingw_open
#define fopen mingw_fopen
#define freopen mingw_freopen
#define opendir mingw_opendir
#define readdir mingw_readdir
#define closedir mingw_closedir
#define dup2 mingw_dup2
#define dup(f) mingw_dup(f)
#define lseek mingw_lseek
#define read mingw_read
#define readv mingw_readv
#define write mingw_write
#define writev mingw_writev
#define truncate mingw_truncate
#define ftruncate mingw_ftruncate
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
#define rmdir mingw_rmdir
#define access mingw_access
#define chdir mingw_chdir
#define remove mingw_remove
#define pipe mingw_pipe
#define getrlimit mingw_getrlimit

#define execve mingw_execve
#define launchve mingw_launchve
#define spopenve mingw_spopenve

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
    short int l_type;		/* Type of lock: F_RDLCK, F_WRLCK, or F_UNLCK */
    short int l_whence;		/* Where `l_start' is relative to (like `lseek') */
    fileoffset_t l_start;	/* Offset where the lock begins */
    fileoffset_t l_len;		/* Size of the locked area; zero means until EOF */
    pid_t l_pid;			/* Process holding the lock  */
};

/*
 * statvfs() emulation.
 */

#ifndef HAS_STATVFS
#define HAS_STATVFS				/* We emulate it */
#endif

typedef unsigned long fsblkcnt_t;
typedef unsigned long fsfilcnt_t;

#define statvfs mingw_statvfs	/* Aliases both struct and routine */

#define ST_RDONLY	(1U << 0)	/* Read-only file system */
#define ST_NOSUID	(1U << 1)	/* Setuid/setgid bits are ignored by exec() */

struct statvfs {
	unsigned long  f_bsize;		/* file system block size */
	unsigned long  f_frsize;	/* fragment size */
	fsblkcnt_t     f_blocks;	/* size of fs in f_frsize units */
	fsblkcnt_t     f_bfree;		/* # free blocks */
	fsblkcnt_t     f_bavail;	/* # free blocks for unprivileged users */
	fsfilcnt_t     f_files;		/* # inodes */
	fsfilcnt_t     f_ffree;		/* # free inodes */
	fsfilcnt_t     f_favail;	/* # free inodes for unprivileged users */
	unsigned long  f_fsid;		/* file system ID */
	unsigned long  f_flag;		/* mount flags */
	unsigned long  f_namemax;	/* maximum filename length */
};

int mingw_statvfs(const char *pathname, struct statvfs *buf);

#ifndef HAS_GETLOGIN
#define HAS_GETLOGIN			/* We emulate it */
#endif

/*
 * getuid(), geteuid(), etc... emulation.
 */
#define HAS_GETUID
#define HAS_GETEUID

typedef unsigned long uid_t;
uid_t mingw_getuid(void);
uid_t mingw_geteuid(void);

#define getuid() mingw_getuid()
#define geteuid() mingw_geteuid()

#define UID_NOBODY	((uid_t) -2)

typedef unsigned long gid_t;
gid_t mingw_getgid(void);
gid_t mingw_getegid(void);

#define getgid() mingw_getgid()
#define getegid() mingw_getegid()

#define GID_NOBODY	((gid_t) -2)

/*
 * stat() and fstat() emulation.
 */

/*
 * We have to redefine the stat structure to be able to store a meaningful
 * st_ino field: we need 64-bit at least to store our synthetized inode numbers.
 */

#define ino_t	uint64			/* Need large inode numbers on Windows */

typedef ushort nlink_t;
typedef uint32 blksize_t;
typedef uint64 blkcnt_t;

typedef struct mingw_stat {
	dev_t st_dev;
	ino_t st_ino;
	mode_t st_mode;
	nlink_t st_nlink;
	uid_t st_uid;
	gid_t st_gid;
	dev_t st_rdev;
	fileoffset_t st_size;
	blksize_t st_blksize;
	blkcnt_t st_blocks;
	time_t st_atime;
	time_t st_mtime;
	time_t st_ctime;
} filestat_t;

/*
 * getrlimit() emulation.
 */
#ifndef HAS_GETRLIMIT
#define HAS_GETRLIMIT			/* We emulate it */
#define EMULATE_GETRLIMIT

#define RLIMIT_CORE 1			/* Maximum size of core file */
#define RLIMIT_DATA 2			/* Maximum data segment size */
#define RLIMIT_AS 	3			/* Available Space (VM address space) */

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
#define RUSAGE_THREAD 1

struct rusage {
	struct timeval ru_utime;	/* user time used */
	struct timeval ru_stime;	/* system time used */
};

int mingw_getrusage(int who, struct rusage *usage);
#endif	/* !HAS_GETRUSAGE */

/*
 * fsync() emulation.
 */
#ifndef HAS_FSYNC
#define HAS_FSYNC				/* We emulate it */
#define EMULATE_FSYNC
#define fsync mingw_fsync

int mingw_fsync(int fd);
#endif	/* !HAS_FSYNC */

/*
 * getppid() emulation.
 */
#ifndef HAS_GETPPID
#define HAS_GETPPID
#define EMULATE_GETPPID
#define getppid mingw_getppid

pid_t mingw_getppid(void);
#endif	/* !HAS_GETPPID */

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

/*
 * waitpid() emulation.
 */
#ifndef HAS_WAITPID
#define HAS_WAITPID
#define EMULATE_WAITPID
#define waitpid mingw_waitpid
#define wait mingw_wait

/* waitpid() supported options */
#define WNOHANG		(1U << 0)	/* don't wait */

/* status queries -- Windows does not support signals nor core dumps */
#define WIFEXITED(s)		TRUE		/* can't know termination was forced */
#define WEXITSTATUS(s)		(s)
#define WIFSIGNALED(s)		FALSE
#define WTERMSIG(s)			0
#define WCOREDUMP(s)		FALSE
#define WIFSTOPPED(s)		FALSE
#define WIFCONTINUED(s)		FALSE
#define WSTOPSIG(s)			0

pid_t mingw_wait(int *status);
pid_t mingw_waitpid(pid_t pid, int *status, int options);
#endif	/* !HAS_WAITPID */

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

DIR *mingw_opendir(const char *pathname);
struct dirent *mingw_readdir(DIR *);
int mingw_closedir(DIR *);

uint64 mingw_getphysmemsize(void);
int mingw_getdtablesize(void);
const char *mingw_strerror(int errnum);
int mingw_stat(const char *pathname, filestat_t *buf);
int mingw_fstat(int fd, filestat_t *buf);
int mingw_dup(int fd);
int mingw_dup2(int oldfd, int newfd);
int mingw_open(const char *pathname, int flags, ...);
int mingw_unlink(const char *pathname);
fileoffset_t mingw_lseek(int fd, fileoffset_t offset, int whence);
int mingw_rename(const char *oldpathname, const char *newpathname);
int mingw_truncate(const char *pathname, fileoffset_t len);
int mingw_ftruncate(int fd, fileoffset_t len);
int mingw_mkdir(const char *pathname, mode_t mode);
int mingw_rmdir(const char *pathname);
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
 * clock_gettime() emulation.
 */
#ifndef HAS_CLOCK_GETTIME
#define HAS_CLOCK_GETTIME	/* We emulate it */
#define EMULATE_CLOCK_GETTIME
#define clock_gettime mingw_clock_gettime

int mingw_clock_gettime(int clock_id, struct timespec *tp);
#endif	/* !HAS_CLOCK_GETTIME */

/*
 * clock_getres() emulation.
 */
#ifndef HAS_CLOCK_GETRES
#define HAS_CLOCK_GETRES	/* We emulate it */
#define EMULATE_CLOCK_GETRES
#define clock_getres mingw_clock_getres

int mingw_clock_getres(int clock_id, struct timespec *res);
#endif	/* !HAS_CLOCK_GETTIME */

#ifndef CLOCK_REALTIME
#define CLOCK_REALTIME	0
#endif

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

int mingw_gethostname(char *name, size_t len);
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
int
mingw_socketpair(int domain, int type, int protocol, socket_fd_t sv[2]);

int s_close(socket_fd_t fd);
ssize_t mingw_s_writev(socket_fd_t fd, const iovec_t *iov, int iovcnt);

/*
 * Semaphore emulation.
 */

#define semget mingw_semget
#define semctl mingw_semctl
#define semop mingw_semop
#define semtimedop mingw_semtimedop

typedef int key_t;
#define IPC_PRIVATE		0			/* private resource */
#define IPC_CREAT		00001000	/* create if key is nonexistent */
#define IPC_EXCL		00002000	/* fail if key exists */
#define IPC_NOWAIT		00004000	/* return error on wait */
#define IPC_RMID		0			/* remove resource */
#define SEM_UNDO		0x1000		/* undo the operation on exit */
#define GETVAL			12			/* get semaphore value */
#define SETVAL			16			/* set semaphore value */

#define SEMMSL			64		/* Maximum amount of semaphores per set */

struct sembuf {
	ushort sem_num;				/* semaphore number in the set */
	short sem_op;				/* semaphore operation */
	short sem_flg;				/* operation flags */
};

/* metaconfig symbols that should not be defined on Windows */
#define HAS_SEMGET
#define HAS_SEMCTL
#define HAS_SEMOP
#define HAS_SEMTIMEDOP

int mingw_semget(key_t key, int nsems, int semflg);
int mingw_semctl(int semid, int semnum, int cmd, ...);
int mingw_semop(int semid, struct sembuf *sops, unsigned nsops);
int mingw_semtimedop(int semid, struct sembuf *sops, unsigned nsops,
	struct timespec *timeout);

/*
 * sigprocmask(), sigsuspend(), etc... emulation.
 */

#define HAS_SIGPROCMASK

/* sigset_t is already defined by system includes, even on Windows */

#define SIG_BLOCK	1
#define SIG_UNBLOCK	2
#define SIG_SETMASK	3

int mingw_sigprocmask(int how, const sigset_t *set, sigset_t *oldset);
int mingw_sigpending(sigset_t *set);
int mingw_sigsuspend(const sigset_t *mask);

/* The sigprocmask() macro is defined in common.h, since needed also on UNIX */

#define sigpending(s)	mingw_sigpending(s)
#define sigsuspend(m)	mingw_sigsuspend(m)

#define sigmask(s)		(1U << ((s) - 1))		/* 0 is not a signal */

static inline int
sigemptyset(sigset_t *s)
{
	*s = 0;
	return 0;
}

static inline int
sigfillset(sigset_t *s)
{
	*s = MAX_INT_VAL(sigset_t);
	return 0;
}

static inline int
sigaddset(sigset_t *s, int n)
{
	if G_UNLIKELY(n <= 0 || n >= SIGNAL_COUNT) {
		errno = EINVAL;
		return -1;
	}
	*s |= sigmask(n);
	return 0;
}

static inline int
sigdelset(sigset_t *s, int n)
{
	if G_UNLIKELY(n <= 0 || n >= SIGNAL_COUNT) {
		errno = EINVAL;
		return -1;
	}
	*s &= ~sigmask(n);
	return 0;
}

static inline int
sigismember(sigset_t *s, int n)
{
	if G_UNLIKELY(n <= 0 || n >= SIGNAL_COUNT) {
		errno = EINVAL;
		return -1;
	}
	return (*s & ~sigmask(n)) ? 1 : 0;
}

/*
 * Additional error codes we want to map.
 */

#define EIDRM			(INT_MAX - 100)	/* Identifier removed */

/*
 * Miscellaneous.
 */

#define rename(oldpath, newpath) mingw_rename((oldpath), (newpath))
#define g_strerror(errnum) mingw_strerror(errnum)

void *mingw_valloc(void *hint, size_t size);
int mingw_vfree(void *addr, size_t size);
int mingw_vfree_fragment(void *addr, size_t size);
void mingw_set_stop_vfree(bool val);

int mingw_mprotect(void *addr, size_t len, int prot);
void *mingw_memstart(const void *p);
void mingw_log_meminfo(const void *p);

int mingw_random_bytes(void *buf, size_t len);
int mingw_process_accessible(pid_t pid);

unsigned int mingw_sleep(unsigned int seconds);
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

const char *dir_entry_filename(const void *dirent);
size_t dir_entry_namelen(const void *dirent);

int mingw_getgateway(uint32 *ip);
void mingw_abort(void) G_NORETURN;
int mingw_execve(const char *filename, char *const argv[], char *const envp[]);
pid_t mingw_launchve(const char *path, char *const argv[], char *const envp[]);
int mingw_spopenve(const char *path, const char *mode, int fd[2],
		char *const argv[], char *const envp[]);

struct adns_request;

void mingw_adns_init(void);
void mingw_adns_close(void);
bool mingw_adns_send_request(const struct adns_request *req);

char *mingw_patch_personal_path(const char *pathname);
const char *mingw_native_path(const char *pathname);
const char *mingw_get_supervisor_log_path(void);
void mingw_file_rotate(const char *pathname, int keep);

systid_t mingw_gettid(void);
void mingw_gettid_reset(uint id);
int mingw_thread_kill(uint id, systid_t system_thread_id, int signo);
bool mingw_signal_check_for(uint id);

int mingw_last_error(void);

#else	/* !MINGW32 */

#define PROT_GUARD		PROT_NONE		/* Guard pages are Windows-specific */

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

#endif	/* MINGW32 */
#endif /* _mingw32_h_ */

/* vi: set ts=4 sw=4 cindent: */
