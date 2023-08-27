/*
 * Copyright (c) 2010 Jeroen Asselman & Raphael Manfredi
 * Copyright (c) 2012, 2013-2018 Raphael Manfredi
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
 * Win32 cross-compiling utility routines.
 *
 * @author Jeroen Asselman
 * @date 2010
 * @author Raphael Manfredi
 * @date 2010-2018
 */

#include "common.h"

/*
 * This whole file is only compiled under Windows.
 */

#ifdef MINGW32

#include <stdlib.h>
#include <windows.h>
#include <mswsock.h>
#include <shlobj.h>
#include <wincrypt.h>
#include <psapi.h>
#include <winnt.h>
#include <powrprof.h>
#include <conio.h>				/* For _kbhit() */
#include <imagehlp.h>			/* For backtrace() emulation */
#include <iphlpapi.h>			/* For GetBestRoute() */
#include <tlhelp32.h>			/* For CreateToolhelp32Snapshot() et al. */

#include <glib.h>
#include <glib/gprintf.h>

#include <stdio.h>
#include <wchar.h>

#define THREAD_SOURCE			/* we want hash_table_once_new_full_real() */

#include "host_addr.h"			/* ADNS */

#include "ascii.h"				/* For is_ascii_alpha() */
#include "atomic.h"
#include "buf.h"
#include "compat_pio.h"			/* For compat_pio_lock() */
#include "compat_sleep_ms.h"
#include "constants.h"
#include "cq.h"
#include "crash.h"
#include "cstr.h"
#include "debug.h"
#include "dl_util.h"
#include "dualhash.h"
#include "endian.h"
#include "fd.h"					/* For is_open_fd() */
#include "getphysmemsize.h"
#include "halloc.h"
#include "hashing.h"			/* For string_mix_hash() */
#include "hashtable.h"
#include "hset.h"
#include "hstrfn.h"
#include "iovec.h"
#include "log.h"
#include "mem.h"
#include "mempcpy.h"
#include "misc.h"
#include "mutex.h"
#include "once.h"
#include "path.h"				/* For filepath_basename() */
#include "product.h"
#include "progname.h"
#include "pslist.h"
#include "sha1.h"
#include "signal.h"
#include "spinlock.h"
#include "spopen.h"
#include "stacktrace.h"
#include "str.h"
#include "stringify.h"			/* For ULONG_DEC_BUFLEN */
#include "thread.h"
#include "unsigned.h"
#include "utf8.h"
#include "vmm.h"				/* For vmm_page_start() */
#include "vsort.h"
#include "walloc.h"
#include "win32dlp.h"
#include "xmalloc.h"

#include "override.h"			/* Must be the last header included */

#if 0
#define MINGW_SYSCALL_DEBUG		/**< Trace all Windows API call errors */
#endif
#if 0
#define MINGW_STARTUP_DEBUG		/**< Trace early startup stages */
#define MINGW_STARTUP_LOGDIR	"C:/cygwin/tmp"
#endif
#if 0
#define MINGW_BACKTRACE_DEBUG	/**< Always trace our own backtracing */
#endif

/*
 * We leave on this by default.
 *
 * It will compile the backtrace debugging code but it will be de-activated
 * until there is a crash happening (a Windows exception, not an assertion
 * failure).
 *
 * This is important until we can perfectly produce execution stacks on
 * exceptions.  Currently, assertion failres are OK, because this is
 * triggering mostly gcc-compiled code, which we more or less manage to
 * backtrace properly.  But Windows exception involve standard DLL that
 * were compiled using Windows calling conventions, and were produced
 * by a different compiler.  Our prologue analysis may not be working
 * correctly on those calls.
 *
 * So, for now, leave a trace of what happened during crashes so that we
 * can debug / improve the ability to properly backtrace routines.
 *
 * Note that the debugging logs we are leaving behind are rotated, so
 * they will eventually be deleted when no crashes occur.
 *
 * 		--RAM, 2018-10-12
 */
#if 1
#define MINGW_BACKTRACE_DEBUG_ON_CRASH
#endif

#if defined(MINGW_BACKTRACE_DEBUG_ON_CRASH) && !defined(MINGW_BACKTRACE_DEBUG)
/* MINGW_BACKTRACE_DEBUG_ON_CRASH depends on MINGW_BACKTRACE_DEBUG code! */
#define MINGW_BACKTRACE_DEBUG
#elif defined(MINGW_BACKTRACE_DEBUG_ON_CRASH) && defined(MINGW_BACKTRACE_DEBUG)
/* If they set MINGW_BACKTRACE_DEBUG earlier, always trace! */
#undef MINGW_BACKTRACE_DEBUG_ON_CRASH
#endif

#undef signal
#undef sleep

#undef stat
#undef fstat
#undef open
#undef fopen
#undef freopen
#undef read
#undef write
#undef mkdir
#undef access
#undef chdir
#undef remove
#undef lseek
#undef dup
#undef dup2
#undef fsync
#undef unlink
#undef opendir
#undef readdir
#undef closedir

#undef gethostname
#undef getaddrinfo
#undef freeaddrinfo

#undef select
#undef socket
#undef bind
#undef connect
#undef listen
#undef accept
#undef shutdown
#undef getsockopt
#undef setsockopt
#undef recv
#undef sendto
#undef socketpair

#undef abort
#undef execve
#undef statvfs

#undef _exit		/* _exit() is the real one here */

#define VMM_MINSIZE		(1024*1024*100)	/* At least 100 MiB */
#define VMM_GRANULARITY	(1024*1024*4)	/* 4 MiB during initalization */
#define WS2_LIBRARY		"ws2_32.dll"

#define TM_MILLION		1000000L
#define TM_BILLION		1000000000L

/* Offset of the UNIX Epoch compared to the Window's one, in microseconds */
#define EPOCH_OFFSET	UINT64_CONST(11644473600000000)

#ifdef MINGW_SYSCALL_DEBUG
#define mingw_syscall_debug()	1
#else
#define mingw_syscall_debug()	0
#endif

static HINSTANCE libws2_32;
static once_flag_t mingw_socket_inited;
static bool mingw_vmm_inited;
static bool mingw_early_inited;

static void mingw_stdio_reset(bool console);

typedef struct processor_power_information {
  ULONG Number;
  ULONG MaxMhz;
  ULONG CurrentMhz;
  ULONG MhzLimit;
  ULONG MaxIdleState;
  ULONG CurrentIdleState;
} PROCESSOR_POWER_INFORMATION;

extern bool vmm_is_debugging(uint32 level);

typedef int (WINAPI *WSAPoll_func_t)(WSAPOLLFD fdarray[], ULONG nfds, INT timeout);
static WSAPoll_func_t WSAPoll;

/*
 * Support for GetFileInformationByHandleEx() only comes with VISTA.
 */

static once_flag_t mingw_gfibhe_inited;
typedef BOOL (WINAPI *GetFileInformationByHandleEx_t)(HANDLE, int, LPVOID, DWORD);
static GetFileInformationByHandleEx_t GetFileInformationByHandleEx;

#define FileNameInfo 2

typedef struct _FILE_NAME_INFO {
	DWORD FileNameLength;
	WCHAR FileName[1];
} FILE_NAME_INFO;

#ifdef MINGW_STARTUP_DEBUG
static FILE *mingw_debug_lf;

static void
getlog(bool initial)
{
	char buf[128];
	char *exe;

	/*
	 * Because this is used at startup and progstart() invokes the MINGW32
	 * startup code before stripping the .exe from the tail of the program
	 * name, we have to do it here as well.
	 *
	 * Normal user code of getprogname() does not have to do that since upon
	 * return from progstart(), the returned value is correctly stripped if
	 * necessary.
	 */

	str_bprintf(ARYLEN(buf), "%s/%s", MINGW_STARTUP_LOGDIR, getprogname());
	exe = is_strcasesuffix(buf, (size_t) -1, ".exe");
	if (exe != NULL)
		*exe = '\0';
	clamp_strcat(ARYLEN(buf), "-log.txt");

	mingw_debug_lf = fopen(buf, initial ? "wb" : "ab");
}

static void
closelog(void)
{
	if (mingw_debug_lf != NULL)
		fclose(mingw_debug_lf);
	mingw_debug_lf = NULL;
}

#define STARTUP_DEBUG(...)	G_STMT_START {	\
	if (mingw_debug_lf != NULL) {			\
		FILE *lf = mingw_debug_lf;			\
		char tb[CRASH_TIME_BUFLEN];			\
		crash_time_raw(tb, sizeof tb);		\
		fputs(tb, lf);						\
		fputc(' ', lf);						\
		fprintf(lf, __VA_ARGS__);			\
		fputc('\n', lf);					\
		fflush(lf);							\
	}										\
} G_STMT_END

#else	/* !MINGW_STARTUP_DEBUG */
#define getlog(x)
#define closelog()
#define STARTUP_DEBUG(...)	{}
#endif	/* MINGW_STARTUP_DEBUG */

enum pncs_magic { PNCS_MAGIC = 0x7c0e73af };

/**
 * Path Name Conversion Structure.
 *
 * @note MAX_PATH_LEN might actually apply to MBCS only and the limit for
 * Unicode is 32768. So we could (or should?) support pathnames longer than
 * 256 characters.
 */
typedef struct pncs {
	enum pncs_magic magic;	/* To protect pncs_dup() */
	wchar_t *utf16;			/* Thread-private allocated buffer */
	size_t len;				/* Path length, in wide-chars, for pncs_dup() */
} pncs_t;

static inline void
pncs_check(const pncs_t * const p)
{
	g_assert(p != NULL);
	g_assert(PNCS_MAGIC == p->magic);
}

/**
 * Converts a NUL-terminated MBCS string to an UTF-16 string.
 * @note mbtowcs() is not async-signal safe.
 *
 * @param src The string to convert.
 * @param dest The destination buffer.
 * @param dest_size The size of the destination buffer in number of elements.
 *
 * @return -1 on failure with errno set, wide-char string length otherwize.
 */
static size_t
locale_to_wchar(const char *src, wchar_t *dest, size_t dest_size)
{
	size_t n;

	n = mbstowcs(NULL, src, 0);
	if ((size_t) -1 == n) {
		s_rawwarn("%s(): illegal character sequence found in path", G_STRFUNC);
		errno = EILSEQ;
		return (size_t) -1;
	}

	if (n < dest_size) {
		(void) mbstowcs(dest, src, dest_size);
	} else {
		s_rawwarn("%s(): wide-char path would be %zu-character long, max=%zu",
			G_STRFUNC, n, dest_size);
		errno = ENAMETOOLONG;
		return (size_t) -1;
	}

	return n;
}

/*
 * Build a native path for the underlying OS.
 *
 * When launched from a Cygwin or MinGW environment, we can face
 * paths like "/x/file" which really mean "x:/file" in Windows parlance.
 * Moreover, in Cygwin, unless configured otherwise, Windows paths are
 * prefixed with "/cygdrive/", so "x:/file" would be "/cygdrive/x/file";
 *
 * Since we're going to issue a Windows call, we need to translate
 * these paths so that Windows can locate the file properly.
 *
 * @attention
 * If they create a C:/x directory, when /x/path could be "c:/x/path" and
 * we will wrongly interpret is as X:/path.  The chance they create
 * single-letter top-level directories is small in practice.
 *
 * @return pointer to static data containing the "native" path or NULL on
 * error, with the error code returned in ``error''.
 */
static const char *
get_native_path(const char *pathname, int *error)
{
	buf_t *b, bs;
	char *p, *pathbuf;
	size_t pathsz;
	const char *npath = pathname;

	STARTUP_DEBUG("%s(): pathname=%s", G_STRFUNC, pathname);

	/*
	 * In a signal handler, don't allocate memory.
	 */

	if (signal_in_unsafe_handler()) {
		static char buf[MAX_PATH_LEN];
		b = buf_init(&bs, ARYLEN(buf));
	} else {
		b = buf_private(G_STRFUNC, MAX_PATH_LEN);
	}

	pathbuf = buf_data(b);
	pathsz = buf_size(b);

	/*
	 * Skip leading "/cygdrive/" string, up to the second "/".
	 *
	 * We can't really check whether we're running on Cygwin at run-time.
	 * Moreover, users can say "mount -c /cyg" to change the prefix from
	 * the default, so "/cygdrive/" is only a wild guess that will work
	 * with default Cygwin settings or when users say "mount -c /" to
	 * suppress the prefixing, in which case paths will look as they do on
	 * the MinGW environment.
	 */

	p = is_strcaseprefix(npath, "/cygdrive/");
	if (NULL != p)
		npath = p - 1;			/* Go back to ending "/" */

	/*
	 * Replace /x/file with x:/file.
	 *
	 * We could check that "/x" does not exist before doing this conversion,
	 * but what if we're on drive X: and there is a "X:/x" file there?
	 * Would /x/x/file be referring to X:/x/file?  What if /x/x exists?
	 *
	 * Since there is no easy way to avoid mistakes, let's keep the mangling
	 * algorithm straightforward so that error cases are also known and
	 * predictable enough.
	 */

	if (
		is_dir_separator(npath[0]) &&
		is_ascii_alpha(npath[1]) &&
		(is_dir_separator(npath[2]) || '\0' == npath[2])
	) {
		size_t plen = vstrlen(npath);

		if (pathsz <= plen) {
			s_rawwarn("%s(): path is %zu-byte long", G_STRFUNC, plen);
			s_debug("%s(): given path was \"%s\"", G_STRFUNC, pathname);
			*error = ENAMETOOLONG;
			return NULL;
		}

		clamp_strncpy(pathbuf, pathsz, npath, plen);
		pathbuf[0] = npath[1];	 /* Replace with correct drive letter */
		pathbuf[1] = ':';
		npath = pathbuf;
	}

	return npath;
}

/**
 * @return native path corresponding to the given path, as pointer to
 * static data.
 */
const char *
mingw_native_path(const char *pathname)
{
	const char *npath;		/* Native path */
	int error;

	npath = get_native_path(pathname, &error);

	return NULL == npath ? pathname : npath;
}

/**
 * Duplicate wide-char string held in the pncs_t structure.
 *
 * @return new wide-char string that must be freed via hfree().
 */
static wchar_t *
pncs_dup(const pncs_t *pncs)
{
	pncs_check(pncs);
	g_assert(size_is_positive(pncs->len));

	return hcopy(pncs->utf16, pncs->len * sizeof(wchar_t));
}

/**
 * Convert pathname to a UTF-16 representation.
 *
 * On success, the member utf16 points to the converted pathname that can be
 * used in Unicode-aware Windows calls.
 *
 * @attention
 * The converted pathname lies in a thread-private buffer, therefore it needs
 * to be perused immediately and saved away if another routine that could use
 * pncs_convert() is called.  Use pncs_dup() to return a new dynamically
 * allocated pathname.
 *
 * @return 0 on success, -1 on error with errno set.
 */
static int
pncs_convert(pncs_t *pncs, const char *pathname)
{
	const char *npath;		/* Native path */
	int error;
	const size_t buflen = MAX_PATH_LEN;
	buf_t *b, bs;
	wchar_t *pathbuf;
	size_t ret;

	/* On Windows wchar_t should always be 16-bit and use UTF-16 encoding. */
	STATIC_ASSERT(sizeof(uint16) == sizeof(wchar_t));

	ZERO(pncs);
	pncs->magic = PNCS_MAGIC;	/* In case they call pncs_dup() */

	STARTUP_DEBUG("%s(): pathname=%s", G_STRFUNC, pathname);

	/*
	 * In a signal handler, don't allocate memory.
	 */

	if (signal_in_unsafe_handler()) {
		static char buf[MAX_PATH_LEN * sizeof(wchar_t)];
		b = buf_init(&bs, ARYLEN(buf));
	} else {
		b = buf_private(G_STRFUNC, MAX_PATH_LEN * sizeof(wchar_t));
	}

	pathbuf = buf_data(b);

	if (NULL == (npath = get_native_path(pathname, &error))) {
		errno = error;
		return -1;
	}

	if (utf8_is_valid_string(npath)) {
		ret = utf8_to_utf16(npath, pathbuf, buflen);
		if (ret < buflen) {
			pncs->utf16 = pathbuf;
		} else {
			s_rawwarn("%s(): UFT-16 path would be %zu-character long, max=%zu",
				G_STRFUNC, ret, buflen);
			errno = ENAMETOOLONG;
			pncs->utf16 = NULL;
		}
	} else {
		ret = locale_to_wchar(npath, pathbuf, buflen);
		if ((size_t) -1 == ret)
			pncs->utf16 = NULL;		/* errno set by locale_to_wchar() */
	}

	if G_UNLIKELY(NULL == pncs->utf16) {
		s_debug("%s(): given path was \"%s\"", G_STRFUNC, pathname);
	} else {
		pncs->len = ret + 1;		/* +1 for trailing NUL */
	}

	return NULL != pncs->utf16 ? 0 : -1;
}

static void
mingw_socket_init(void)
{
	WSADATA wsaData;

	if (WSAStartup(MAKEWORD(2,2), &wsaData) != NO_ERROR)
		s_error("WSAStartup() failed");

	libws2_32 = LoadLibrary(WS2_LIBRARY);
    if (libws2_32 != NULL) {
        WSAPoll = (WSAPoll_func_t) GetProcAddress(libws2_32, "WSAPoll");
    }
}

static inline bool
mingw_fd_is_opened(int fd)
{
	unsigned long dummy;

	return (HANDLE) _get_osfhandle(fd) != INVALID_HANDLE_VALUE ||
		 0 == WSAHtonl((SOCKET) fd, 666, &dummy);
}

/**
 * Get last Winsock operation error code, remapping Winsocks-specific
 * errors into POSIX ones, which upper level code expects.
 */
static int
mingw_wsa_last_error(void)
{
	int error = WSAGetLastError();
	int result = error;

	/*
	 * Not all the Winsock error codes are translated here.  The ones
	 * not conflicting with other POSIX defines have already been mapped.
	 *
	 * For instance, we have:
	 *
	 *     #define ENOTSOCK WSAENOTSOCK
	 *
	 * so there is no need to catch WSAENOTSOCK here to translate it to
	 * ENOTSOCK since the remapping has already been done for that constant.
	 *
	 * So the ones that remain are those which are not really socket-specific
	 * and for which we cannot do a remapping that would conflict with other
	 * definitions in the MinGW headers.
	 */

	switch (error) {
	case WSAEWOULDBLOCK:	result = EAGAIN; break;
	case WSAEINTR:			result = EINTR;  break;
	case WSAEINVAL:			result = EINVAL; break;
	case ERROR_IO_PENDING:	result = EINTR;  break;
	}

	if (mingw_syscall_debug()) {
		s_debug("%s() failed: %s (%d)", stacktrace_caller_name(1),
			symbolic_errno(result), error);
	}

	return result;
}

/**
 * Remap Windows-specific errors into POSIX ones, also clearing the POSIX
 * range so that strerror() works.
 */
static int
mingw_win2posix(int error)
{
	static hset_t *warned;

	/*
	 * This is required when using non-POSIX routines, for instance
	 * _wmkdir() instead of mkdir(), so that regular errno procesing
	 * can occur in the code.
	 *
	 * MinGW also defines POSIX error codes up to 42, but they are
	 * conflicting with Windows error ones, so these must also be remapped.
	 *
	 * FIXME: Many errors are missing, only the first ones are handled.
	 * A warning will be emitted when we hit an un-remapped error, but this
	 * is going to be a painful iterative convergence.
	 */

	switch (error) {
	case ERROR_ALREADY_EXISTS:
	case ERROR_FILE_EXISTS:
		return EEXIST;
	case ERROR_INVALID_FUNCTION:
		return ENOSYS;
	case ERROR_FILE_NOT_FOUND:
	case ERROR_PATH_NOT_FOUND:
		return ENOENT;
	case ERROR_TOO_MANY_OPEN_FILES:
		return EMFILE;
	case ERROR_INVALID_HANDLE:
		return EBADF;
	case ERROR_NOT_ENOUGH_MEMORY:
	case ERROR_COMMITMENT_LIMIT:
	case ERROR_OUTOFMEMORY:
	case ERROR_NO_SYSTEM_RESOURCES:
		return ENOMEM;
	case ERROR_ACCESS_DENIED:
	case ERROR_INVALID_ACCESS:
	case ERROR_SHARING_VIOLATION:
	case ERROR_LOCK_VIOLATION:
		return EACCES;
	case ERROR_INVALID_DRIVE:
		return ENXIO;
	case ERROR_NOT_SAME_DEVICE:
		return EXDEV;
	case ERROR_NO_MORE_FILES:
		return ENFILE;
	case ERROR_WRITE_PROTECT:
	case ERROR_CANT_OPEN_ANONYMOUS:		/* Can't open anonymous token */
		return EPERM;
	case ERROR_NOT_SUPPORTED:
		return ENOSYS;
	case ERROR_DISK_FULL:
		return ENOSPC;
	case ERROR_BROKEN_PIPE:
	case ERROR_NO_DATA:
		return EPIPE;
	case ERROR_INVALID_NAME:		/* Invalid syntax in filename */
	case ERROR_INVALID_PARAMETER:	/* Invalid function parameter */
	case ERROR_BAD_PATHNAME:		/* Invalid pathname */
		return EINVAL;
	case ERROR_DIRECTORY:			/* "Directory name is invalid" */
		return ENOTDIR;				/* Seems the closest mapping */
	case WSAENOTSOCK:				/* For fstat() calls */
		return ENOTSOCK;
	case ERROR_INVALID_ADDRESS:
	case ERROR_INVALID_USER_BUFFER:
		return EFAULT;
	case ERROR_IO_PENDING:			/* System call "interrupted" by signal */
		return EINTR;
	/*
	 * The following remapped because their number is in the POSIX range
	 */
	case ERROR_ARENA_TRASHED:
		return EFAULT;
	case ERROR_INVALID_BLOCK:
		return EIO;
	case ERROR_BAD_ENVIRONMENT:
		return EFAULT;
	case ERROR_BAD_FORMAT:
		return EINVAL;
	case ERROR_INVALID_DATA:
		return EIO;
	case ERROR_CURRENT_DIRECTORY:
		return ENOFILE;
	case ERROR_BAD_UNIT:
	case ERROR_BAD_DEVICE:
	case ERROR_NOT_READY:		/* No disk "in" the letter drive */
		return ENODEV;
	case ERROR_BAD_COMMAND:
	case ERROR_CRC:
	case ERROR_BAD_LENGTH:
	case ERROR_SEEK:
	case ERROR_NOT_DOS_DISK:
	case ERROR_SECTOR_NOT_FOUND:
	case ERROR_GEN_FAILURE:
	case ERROR_WRONG_DISK:
	case ERROR_SHARING_BUFFER_EXCEEDED:
	case ERROR_DEVICE_REMOVED:
		return EIO;
	case ERROR_OUT_OF_PAPER:
		return ENOSPC;
	case ERROR_WRITE_FAULT:
	case ERROR_READ_FAULT:
	case ERROR_NOACCESS:		/* Invalid access to memory location */
		return EFAULT;
	case ERROR_HANDLE_EOF:
		return 0;			/* EOF must be treated as a read of 0 bytes */
	case ERROR_HANDLE_DISK_FULL:
		return ENOSPC;
	case ERROR_ENVVAR_NOT_FOUND:
		/* Got this error writing to a closed stdio fd, opened via pipe() */
		return EBADF;
	case ERROR_BAD_EXE_FORMAT:
		return ENOEXEC;
	case ERROR_NETNAME_DELETED:
		return EHOSTUNREACH;
	case ERROR_NO_TOKEN:
		return ESRCH;
	case 0:					/* Always indicates success */
		return 0;
	default:
		if (NULL == warned) {
			static spinlock_t warned_slk = SPINLOCK_INIT;

			spinlock(&warned_slk);
			if (NULL == warned) {
				warned = NOT_LEAKING(hset_create(HASH_KEY_SELF, 0));
				hset_thread_safe(warned);
			}
			spinunlock(&warned_slk);
		}
		if (warned != NULL && !hset_contains(warned, int_to_pointer(error))) {
			hset_insert(warned, int_to_pointer(error));
			s_minicarp("Windows error code %d (%s) not remapped to a POSIX one",
				error, g_strerror(error));
		}
	}

	return error;
}

/**
 * Get last Windows error, remapping Windows-specific errors into POSIX ones
 * and clearing the POSIX range so that strerror() works.
 */
int
mingw_last_error(void)
{
	int error = GetLastError();
	int result = mingw_win2posix(error);

	if (mingw_syscall_debug()) {
		s_debug("%s() failed: %s (%d)", stacktrace_caller_name(1),
			symbolic_errno(result), error);
	}

	return result;
}

unsigned int
mingw_sleep(unsigned int seconds)
{
	while (seconds != 0) {
		uint d = MIN(seconds, 1000);
		compat_sleep_ms(d * 1000);
		seconds -= d;
	}

	return 0;	/* Never interrupted by a signal here */
}

static signal_handler_t mingw_sighandler[SIGNAL_COUNT];

signal_handler_t
mingw_signal(int signo, signal_handler_t handler)
{
	signal_handler_t old;
	static spinlock_t mingw_signal_slk = SPINLOCK_INIT;

	g_assert(handler != SIG_ERR);

	if (signo <= 0 || signo >= SIGNAL_COUNT) {
		errno = EINVAL;
		return SIG_ERR;
	}

	spinlock_hidden(&mingw_signal_slk);

	old = mingw_sighandler[signo];
	mingw_sighandler[signo] = handler;

	spinunlock_hidden(&mingw_signal_slk);

	/*
	 * Don't call signal() with fake SIGBUS, SIGTRAP, SIGPIPE.
	 * We would get an error back as "unrecognized argument value".
	 */

	switch (signo) {
	case SIGSEGV:
		signal(signo, handler);
		break;
	default:
		break;
	}

	return old;
}

#define FLUSH_ERR_STR()	G_STMT_START {	\
	flush_err_str();					\
	if (log_stdout_is_distinct())		\
		flush_str(STDOUT_FILENO);		\
} G_STMT_END

/**
 * Sends a signal to specified thread.
 */

/**
 * Synthesize a fatal signal as the kernel would on an exception.
 */
static void G_COLD
mingw_sigraise(int signo, bool verbose)
{
	g_assert(signo > 0 && signo < SIGNAL_COUNT);

	if (verbose)
		s_rawwarn("%s(): raising %s", G_STRFUNC, signal_name(signo));

	if (SIG_IGN == mingw_sighandler[signo]) {
		/* Nothing */
	} else if (SIG_DFL == mingw_sighandler[signo]) {
		static bool done;
		DECLARE_STR(3);

		print_str("Got uncaught ");			/* 0 */
		print_str(signal_name(signo));		/* 1 */
		print_str(" -- crashing.\n");		/* 2 */
		FLUSH_ERR_STR();

		if (!done) {
			done = TRUE;
			crash_print_decorated_stack(STDERR_FILENO);
			if (log_stdout_is_distinct())
				crash_print_decorated_stack(STDOUT_FILENO);
		}

	} else {
		(*mingw_sighandler[signo])(signo);
	}
}

/**
 * Our own abort(), to avoid the message:
 *
 * "This application has requested the Runtime to terminate it in an
 * unusual way. Please contact the application's support team for more
 * information."
 */
void
mingw_abort(void)
{
	mingw_sigraise(SIGABRT, TRUE);
	ExitProcess(EXIT_FAILURE);
}

/***
 *** Thread signal emulation.
 ***/

static struct mingw_thread {
	HANDLE h;
	CONTEXT c;
	DWORD pc;
	uint32 sig_pending;
	uint32 sig_mask;
	uint stid;
	bool sig_suspend;
	atomic_lock_t lock;
} mingw_threads[THREAD_MAX];

/**
 * Clear cached system handle for dead thread and reset signal information.
 */
void
mingw_gettid_reset(uint id)
{
	struct mingw_thread *mt = &mingw_threads[id];

	if (NULL != mt->h) {
		mt->h = NULL;
		CloseHandle(mt->h);
	}

	mt->sig_pending = mt->sig_mask = 0;
	mt->sig_suspend = FALSE;
	mt->lock = 0;
}

/**
 * Return a system thread "ID", which needs to be cast back to a HANDLE
 * to be perused by thread-specific system calls.
 *
 * @return the system thread ID of the current thread.
 */
systid_t
mingw_gettid(void)
{
	uint id = thread_small_id();
	struct mingw_thread *mt = &mingw_threads[id];
	HANDLE p;

	if (mt->h != NULL)
		return (systid_t) mt->h;

	/*
	 * We need to duplicate (and cache) the pseudo thread handle to get a
	 * real handle that represents this thread.
	 *
	 * The mingw_gettid_reset() routine is called by the thread layer when
	 * the old thread exits and we can dispose of the thread handle.
	 */

	mt->stid = id;
	p = GetCurrentProcess();

	DuplicateHandle(p, GetCurrentThread(), p, &mt->h,
		0, FALSE, DUPLICATE_SAME_ACCESS);

	return (systid_t) mt->h;
}

/**
 * Atomically record signal in supplied memory location.
 */
static void
mingw_thread_add_sig(uint32 *dest, int signum)
{
	/*
	 * We merge the signal bit into the value atomically without having
	 * to take any lock.
	 */

	for (;;) {
		uint32 current, merged;

		atomic_mb();
		merged = current = *dest;
		merged |= tsig_mask(signum);

		if (atomic_uint_xchg_if_eq(dest, current, merged))
			break;
	}
}

/**
 * Atomically clear signal in supplied memory location.
 */
static void
mingw_thread_del_sig(uint32 *dest, int signum)
{
	/*
	 * We clear the signal bit within the value atomically without having
	 * to take any lock.
	 */

	for (;;) {
		uint32 current, cleared;

		atomic_mb();
		cleared = current = *dest;
		cleared &= ~tsig_mask(signum);

		if (atomic_uint_xchg_if_eq(dest, current, cleared))
			break;
	}
}

/**
 * Handle pending unblocked signals for the thread.
 *
 * @return TRUE if we handled any signal.
 */
static bool
mingw_sig_handle(struct mingw_thread *mt)
{
	uint32 pending;
	bool handled = FALSE;

	while (0 != (pending = ~mt->sig_mask & mt->sig_pending)) {
		int s;

		/*
		 * There is no signal #0, hence bit 0 in the pending mask represents
		 * signal #1.  That's why the loop starts with 1.
		 */

		for (s = 1; pending != 0; s++, pending >>= 1) {
			if (pending & 0x1) {
				/*
				 * Before delivering the signal, we need to block further
				 * invocations of the very same signal, restoring it
				 * afterwards.
				 *
				 * Note that the sig_mask field is only handled by the
				 * thread hence it could be modified freely.  It is being
				 * read by other threads though, so using atomic operations
				 * ensures synchronization, acting as a memory write barrier.
				 */

				mingw_thread_add_sig(&mt->sig_mask,    s);
				mingw_thread_del_sig(&mt->sig_pending, s);

				mingw_sigraise(s, FALSE);

				mingw_thread_del_sig(&mt->sig_mask,    s);

				handled = TRUE;
			}
		}
	}

	return handled;
}

/**
 * We are magically dispatched here in the context of the thread for which
 * we need to deliver signals thanks to thread context patching.
 */
static void
mingw_sig_trampoline(void)
{
	int id;
	struct mingw_thread *mt;
	CONTEXT ctx;

	id = thread_small_id();
	mt = &mingw_threads[id];

	g_assert(mt->lock);		/* Busy! */

	/*
	 * We need to take a copy of the original context on the stack since,
	 * before we return from the interruption, we're going to release the
	 * context lock in the mingw_thread structure (thereby allowing any other
	 * thread from superseding it to interrupt us again).
	 *
	 * Since we need to release the lock before resuming, we need to get the
	 * copy.  Do that now before dispatching interrupts to minimize the race
	 * condition window (see the FIXME below).
	 */

	ctx = mt->c;			/* Struct copy */
	ctx.Eip = mt->pc;		/* Restore original PC */

	/*
	 * Dispatch all the pending signals.
	 */

	mingw_sig_handle(mt);

	/*
	 * Time to resume to our original context.
	 *
	 * FIXME:
	 * We need to release the lock, because we're going to return from the
	 * interrupt.  Unfortunately, this is not an atomic operation: if an
	 * interrupt is posted between the time we exited the loop above and now,
	 * we'll miss it!  And there's no way we can retest for pending signals
	 * after restoring the context, because we'll be out of here.
	 */

	atomic_release(&mt->lock);

	/*
	 * We're cheating: we restore the context in the same thread, without
	 * stopping its execution (we would need an external thread to do that,
	 * requiring us to launch that new thread...).
	 *
	 * We're not checking the return of SetThreadContext() for a good reason:
	 * if it succeeds, it will not return!  Note the use of the pseudo handle
	 * for the current thread, and not mt->h.
	 */

	SetThreadContext(GetCurrentThread(), &ctx);
	g_assert_not_reached();
}

static int
mingw_thread_sig_deliver(struct mingw_thread *mt)
{
	DWORD cnt;
	const char *what = NULL;

	/*
	 * Check whether we have unmasked pending signals to deliver.
	 */

	atomic_mb();
	if (0 == (~mt->sig_mask & mt->sig_pending))
		return 0;		/* Queued, will be handled later */

	/*
	 * We have signals to deliver.
	 */

	if (thread_small_id() == mt->stid) {
		/*
		 * Must not go through the trampoline if signals are for the current
		 * thread: suspending ourselves would not do us much good!
		 * Handle them synchronously.
		 */
		mingw_sig_handle(mt);
		return 0;
	}

	/*
	 * Get lock protecting the mt->c thread context.
	 */

	if (!atomic_acquire(&mt->lock))
		return 0;		/* Busy with another signal dispatch */

	/*
	 * If we are within a sigsuspend(), then we can notify that we were
	 * interrupted by a signal and therefore sigsuspend() can return.
	 */

	mt->sig_suspend = FALSE;

	cnt = SuspendThread(mt->h);

	if ((DWORD) -1 == cnt) {
		what = "SuspendThread";
		errno = mingw_last_error();
		goto failed;
	}

	ZERO(&mt->c);
	mt->c.ContextFlags = CONTEXT_FULL;

	if (!GetThreadContext(mt->h, &mt->c)) {
		what = "GetThreadContext";
		errno = mingw_last_error();
		goto failed;
	}

	/*
	 * Patch the instruction pointer (aka. PC) to move execution to our
	 * signal dispatching routine.
	 */

	mt->pc = mt->c.Eip;
	mt->c.Eip = (DWORD) mingw_sig_trampoline;

	if (!SetThreadContext(mt->h, &mt->c)) {
		what = "SetThreadContext";
		errno = mingw_last_error();
		goto failed;
	}

	cnt = ResumeThread(mt->h);

	if ((DWORD) -1 == cnt) {
		what = "ResumeThread";
		errno = mingw_last_error();
		goto failed;
	}

	if (1 != cnt) {
		g_assert(cnt != 0);		/* Thread was suspended above */
		what = "ResumeThread";
		errno = EBUSY;			/* Thread already suspended from elsewhere */
		goto failed;
	}

	return 0;		/* OK, keep the lock since context is now active! */

failed:
	atomic_release(&mt->lock);
	s_warning("%s(): %s() failed: %m ", G_STRFUNC, what);
	return -1;
}

/**
 * Synchronously check for OS signals in the current thread (whose ID was
 * already computed) and deliver those which are unblocked.
 *
 * We need this routine to periodically check for signals that could be
 * missed (recorded as pending but not processed) due to an unavoidable
 * race condition in mingw_sig_trampoline().
 *
 * @param id	thread small ID
 *
 * @return TRUE if we handled any signal.
 */
bool
mingw_signal_check_for(uint id)
{
	g_assert(id < THREAD_MAX);

	return mingw_sig_handle(&mingw_threads[id]);
}

/**
 * Emulate sigprocmask(), necessary now that we support inter-thread
 * "kernel" signals (i.e. interrupts).  These are UNIX-like signals,
 * not our thread signals implemented by thread_kill() which can only
 * be delivered at specific checkpoints.
 *
 * Because these inter-thread signals can interrupt the processing at
 * random places, the application needs to be able to block delivery of
 * the signals to create critical sections.
 */
int
mingw_sigprocmask(int how, const sigset_t *set, sigset_t *oldset)
{
	int id = thread_small_id();
	struct mingw_thread *mt = &mingw_threads[id];

	if (oldset != NULL)
		*oldset = mt->sig_mask;

	switch (how) {
	case SIG_SETMASK:
		g_assert(set != NULL);
		mt->sig_mask = *set;
		atomic_mb();
		goto check;
	case SIG_BLOCK:
		g_assert(set != NULL);
		mt->sig_mask |= *set;
		break;
	case SIG_UNBLOCK:
		g_assert(set != NULL);
		mt->sig_mask &= ~*set;
		goto check;
	default:
		errno = EINVAL;
		return -1;
	}

	return 0;

check:
	/*
	 * When unblocking signals, we need to check whether there are
	 * pending signals to process now, and deliver them to the thread.
	 */

	return mingw_thread_sig_deliver(mt);
}

int
mingw_sigpending(sigset_t *set)
{
	int id = thread_small_id();
	struct mingw_thread *mt = &mingw_threads[id];

	if (set != NULL) {
		atomic_mb();
		*set = mt->sig_pending;
	}

	return 0;
}

int
mingw_sigsuspend(const sigset_t *mask)
{
	int id = thread_small_id();
	struct mingw_thread *mt = &mingw_threads[id];
	sigset_t old;

	if (NULL == mask) {
		errno = EFAULT;
		return -1;
	}

	atomic_mb();
	old = mt->sig_mask;
	mt->sig_mask = *mask;

	/*
	 * Suspend the process until delivery of a signal whose action is to
	 * invoke a signal handler or terminate the process.
	 *
	 * If the signal is caught, return after the signal handler returns,
	 * restoring the signal mask to the old value.
	 */

	mt->sig_suspend = TRUE;

	while (mt->sig_suspend) {
		Sleep(100);		/* ms */
	}

	mt->sig_mask = old;
	errno = EINTR;
	return -1;
}

/**
 * Send a signal to specified thread.
 *
 * This mimics pthread_kill() semantics on UNIX, which unfortunately is not
 * supported by the Windows implementation of pthreads.
 *
 * @param id		the thread ID (our internal small thread ID) to signal
 * @param sysid		the system thread ID (the thread HANDLE)
 * @param signo		the signal to deliver
 *
 * @return 0 if OK, -1 on error with errno set.
 */
int
mingw_thread_kill(uint id, systid_t sysid, int signo)
{
	struct mingw_thread *mt;

	STATIC_ASSERT(sizeof(uint32) * 8 >= SIGNAL_COUNT);
	g_assert(id < N_ITEMS(mingw_threads));
	g_assert(id != thread_small_id());		/* Cannot use for current thread */
	g_assert(sysid != mingw_gettid());		/* Cannot use for current thread */

	/*
	 * We have room for one context, so we just queue signals when we are
	 * busy handling signals in the thread.
	 */

	mt = &mingw_threads[id];

	g_assert(mt->stid == id);
	g_assert(mt->h == (HANDLE) sysid);

	mingw_thread_add_sig(&mt->sig_pending, signo);

	return mingw_thread_sig_deliver(mt);
}

int
mingw_fcntl(int fd, int cmd, ... /* arg */ )
{
	int res = -1;

	/* If fd isn't opened, _get_osfhandle() fails with errno set to EBADF */
	if (!mingw_fd_is_opened(fd)) {
		errno = EBADF;
		return -1;
	}

	switch (cmd) {
		case F_SETFL:
			res = 0;
			break;
		case F_GETFL:
			res = O_RDWR;
			break;
		case F_SETLK:
		{
			HANDLE file = (HANDLE) _get_osfhandle(fd);
			DWORD start_high, start_low;
			DWORD len_high, len_low;
			struct flock *arg;
			va_list args;

			va_start(args, cmd);
			arg = va_arg(args, struct flock *);
			va_end(args);

			if (arg->l_whence != SEEK_SET) {
				errno = EINVAL;
				return -1;		/* This emulation only supports SEEK_SET */
			}

			if (0 == arg->l_len) {
				/* Special, 0 means the whole file */
				len_high = MAX_INT_VAL(uint32);
				len_low = MAX_INT_VAL(uint32);
			} else {
				len_high = (uint64) arg->l_len >> 32;
				len_low = arg->l_len & MAX_INT_VAL(uint32);
			}
			start_high = (uint64) arg->l_start >> 32;
			start_low = arg->l_start & MAX_INT_VAL(uint32);

			if (arg->l_type == F_WRLCK) {
				if (!LockFile(file, start_low, start_high, len_low, len_high))
					errno = mingw_last_error();
				else
					res = 0;
			} else if (arg->l_type == F_RDLCK) {
				OVERLAPPED ov;

				ZERO(&ov);
				ov.Offset = start_low;
				ov.OffsetHigh = start_high;
				if (
					!LockFileEx(file, LOCKFILE_FAIL_IMMEDIATELY, 0,
						len_low, len_high, &ov)
				) {
					errno = mingw_last_error();
				} else
					res = 0;
			} else if (arg->l_type == F_UNLCK) {
				if (!UnlockFile(file, start_low, start_high, len_low, len_high))
					errno = mingw_last_error();
				else
					res = 0;
			}
			break;
		}
		case F_DUPFD:
		{
			va_list args;
			int min, max;
			pslist_t *opened = NULL, *l;
			int error = 0;

			va_start(args, cmd);
			min = va_arg(args, int);
			va_end(args);

			max = getdtablesize();

			if (min < 0 || min >= max) {
				errno = EINVAL;
				return -1;
			}

			/*
			 * Since we are multi-threaded, we cannot use dup2() because we
			 * cannot atomically select the new file descriptor, even if
			 * mingw_fd_is_opened() reports that the fd is currently available.
			 * So we need to call mingw_dup(), keeping file descriptors opened
			 * until we reach one above the minimum we can use.
			 *		--RAM, 2015-11-03
			 */

			for (;;) {
				res = mingw_dup(fd);
				if (-1 == res) {
					error = errno;
					break;
				}
				if (res >= min)
					break;
				opened = pslist_prepend(opened, int_to_pointer(res));
			}

			PSLIST_FOREACH(opened, l) {
				int d = pointer_to_int(l->data);
				close(d);
			}
			pslist_free_null(&opened);

			if (0 == error)
				return res;

			errno = error;
			break;
		}
		default:
			res = -1;
			errno = ENOSYS;
			break;
	}

	return res;
}

#ifdef EMULATE_FSYNC
/**
 * Synchronize the file's in-core data with the storage device by making sure
 * all the kernel-buffered data is written.
 */
int
mingw_fsync(int fd)
{
	HANDLE h = (HANDLE) _get_osfhandle(fd);

	if G_UNLIKELY(INVALID_HANDLE_VALUE == h) {
		errno = EBADF;
		return -1;
	}

	if (!FlushFileBuffers(h)) {
		errno = mingw_last_error();
		return -1;
	}

	return 0;
}
#endif	/* EMULATE_FSYNC */

#ifdef EMULATE_GETPPID
/**
 * Compute byte length of UTF-16 string, scanning up to specified max amount
 * of characters (ignoring surrogates, i.e. they are counted as two chars since
 * they use two 16-bit slots).
 *
 * @param s			start of UTF-16 string
 * @param maxchars	maximum amout of UTF-16 entries
 *
 * @return byte length of string, not counting trailing NUL.
 */
static size_t
wchar_clamp_bytelen(const wchar_t *s, size_t maxchars)
{
	uint16 *p = (uint16 *) s;
	size_t c = 0;

	while (*p != 0 && c < maxchars) {
		p++;
		c++;
	}

	return ptr_diff(p, s);
}

/**
 * Find process entry matching the given PID.
 *
 * If we cannot find the PID, `error' is filled with the an error code if
 * it is not NULL.
 *
 * @param pid	the PID we're looking for
 * @param pe	the process entry we can fill-in
 * @param error	if not NULL, set with value of errno if we can't find the PID
 *
 * @return TRUE if found, FALSE if not found with error filled-in.
 */
static bool
mingw_find_process_entry(pid_t pid, PROCESSENTRY32W *pe, int *error)
{
	HANDLE h;
	bool ok, found = FALSE;

	ZERO(pe);
	pe->dwSize = sizeof(*pe);
	if (error != NULL)
		*error = 0;

	h = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (INVALID_HANDLE_VALUE == h) {
		if (error != NULL)
			*error = mingw_last_error();
		return FALSE;
	}

	for (ok = Process32FirstW(h, pe); ok; ok = Process32NextW(h, pe)) {
		if ((pid_t) pe->th32ProcessID == pid) {
			found = TRUE;
			break;
		}
	}

	if (!found && error != NULL)
		*error = mingw_last_error();

	CloseHandle(h);

	return found;
}

/**
 * Compute SHA1 digest of given process entry.
 */
static void
mingw_sha1_process_entry(PROCESSENTRY32W *pe, sha1_t *digest)
{
	size_t n = N_ITEMS(pe->szExeFile);
	SHA1_context c;

	SHA1_reset(&c);
	SHA1_INPUT(&c, pe->th32ProcessID);
	SHA1_INPUT(&c, pe->th32ParentProcessID);
	SHA1_input(&c, pe->szExeFile, wchar_clamp_bytelen(pe->szExeFile, n));
	SHA1_result(&c, digest);
}

/**
 * Get the ID of the parent process.
 *
 * @note
 * This is unreliable, prone to race conditions, as the kernel could immediately
 * reuse the ID of a dead process and does not actively maintain a process tree
 * as on UNIX.  The only way to make it more reliable is to compute our parent
 * PID very early at startup, hoping the PID we find is the same process that
 * launched us and not another process which took its place (very unlikely).
 *
 * @return the ID of the parent process, 1 meaning our parent died already.
 */
pid_t
mingw_getppid(void)
{
	static pid_t parent_pid = (pid_t) -1;
	static sha1_t parent_digest;
	static spinlock_t mingw_getppid_slk = SPINLOCK_INIT;
	sha1_t digest;
	pid_t ppid;
	PROCESSENTRY32W pe;

	if ((pid_t) 1 == parent_pid)
		return 1;					/* Known to be orphan */

	ppid = parent_pid;

	if ((pid_t) -1 == ppid && mingw_find_process_entry(getpid(), &pe, NULL))
		ppid = pe.th32ParentProcessID;

	if ((pid_t) -1 == ppid)
		return 1;					/* Can't find ourselves, assume orphaned */

	/*
	 * The first time we find a parent PID, make sure it exists and if it
	 * does, compute the SHA1 of its process information.  We will use this
	 * on further invocations to ensure we still have the same parent, in case
	 * the PID of our parent was reused.
	 */

	if ((pid_t) -1 == parent_pid) {
		if (-1 == mingw_process_accessible(ppid)) {
			ppid = 1;				/* Parent died or runs under another UID */
		} else {
			if (mingw_find_process_entry(ppid, &pe, NULL)) {
				mingw_sha1_process_entry(&pe, &digest);
			} else {
				ppid = 1;			/* Parent cannot be found */
			}
		}

		/*
		 * Record initial information, return parent PID.
		 */

		spinlock_hidden(&mingw_getppid_slk);

		if ((pid_t) -1 == parent_pid) {
			parent_pid = ppid;
			if (ppid != (pid_t) 1)
				parent_digest = digest;		/* struct copy */
		}

		spinunlock_hidden(&mingw_getppid_slk);

		return ppid;
	}

	/*
	 * Not the first time, verify that the known parent PID is still
	 * referring to the same process.
	 */

	g_assert(ppid != (pid_t) 1);

	if (mingw_find_process_entry(ppid, &pe, NULL)) {
		mingw_sha1_process_entry(&pe, &digest);
	} else {
		if (0 == mingw_process_accessible(ppid)) {
			static bool warned;

			if (!warned) {
				warned = TRUE;
				s_miniwarn("%s(): assuming PID=%lu is still our parent",
					G_STRFUNC, (ulong) ppid);
			}
			return ppid;
		}
		ppid = 1;			/* Parent cannot be found */
	}

	spinlock(&mingw_getppid_slk);

	if (
		parent_pid != ppid ||
		0 != memcmp(&parent_digest, &digest, SHA1_RAW_SIZE)
	)
		parent_pid = ppid = 1;

	spinunlock(&mingw_getppid_slk);

	return ppid;
}
#endif	/* EMULATE_GETPPID */

/**
 * Count amount of backslashes that lead to a double quote '"' or to the end
 * of the string.
 *
 * @return the amount of backslashes to escape.
 */
static size_t
mingw_backslashes_to_quote_or_end(const char *str)
{
	const char *p = str;
	char c;
	size_t backslashes = 0;

	g_assert(*str == '\\');

	while ('\0' != (c = *p++)) {
		if ('\\' == c)
			backslashes++;
		else if ('"' == c)
			break;
		else
			return 0;	/* No need to escape all these backslashes */
	}

	return backslashes;
}

/**
 * Computes the memory necessary to include the string into quotes and escape
 * embedded quotes, provided there are embedded spaces or backslashes leading
 * to a quote or at the end of the string.
 *
 * @param str		the string where we want to protect embedded spaces / quotes
 *
 * @return 0 if no escaping is necessary (no embedded spaces or quotes), the
 * size of the buffer required to hold the escaped string otherwise (including
 * the trailing NUL).
 */
static size_t
mingw_quotedlen(const char *str)
{
	const char *p = str;
	char c;
	size_t spaces = 0, quotes = 0, backslashes = 0;

	g_assert(str != NULL);

	while ('\0' != (c = *p++)) {
		if (' ' == c)
			spaces++;
		else if ('"' == c)
			quotes++;
		else if ('\\' == c) {
			size_t e = mingw_backslashes_to_quote_or_end(p - 1);

			if (e != 0) {
				backslashes += e;
				p += e - 1;
			}
		}
	}

	/*
	 * If there are spaces, we need 2 surrounding quotes, plus 1 extra
	 * character per quote present (to escape them with a preceding "\")
	 * and similarily for any backslash present before a quote.
	 *
	 * Any quote or backslash present needs also to be preserved.
	 */

	if (0 == spaces && 0 == quotes && 0 == backslashes)
		return 0;		/* No escaping required */

	return 2 + quotes + backslashes + ptr_diff(p, str);
}

/**
 * Escape string into supplied buffer: two surrounding quotes are added, and
 * each embedded quote or backslash is escaped.
 *
 * @param str		the string to escape
 * @param dest		destination buffer
 * @param len		length available in buffer
 *
 * @return a pointer to the next character following the escaped string.
 */
static char *
mingw_quotestr(const char *str, char *dest, size_t len)
{
	char *end = ptr_add_offset(dest, len);
	const char *p = str;
	char *q;

	g_assert(str != NULL);
	g_assert(dest != NULL);
	g_assert(size_is_positive(len));

	dest[0] = '"';			/* Opening quote */
	q = &dest[1];

	while (q < end) {
		char c = *p++;

		if ('"' == c) {
			*q++ = '\\';	/* Escape following quote or backslash */
			if (q >= end)
				break;
			*q++ = c;
		} else if ('\\' == c) {
			size_t e = mingw_backslashes_to_quote_or_end(p - 1);

			if (0 == e) {
				*q++ = c;	/* No need to escape that backslash */
			} else {
				p += e - 1;	/* Skip all remaining backslashes in input */
				/* Escape all the backslashes we've seen */
				do {
					*q++ = '\\';
					if (q >= end)
						break;
					*q++ = '\\';
					if (q >= end)
						break;
				} while (--e);
			}
		} else if ('\0' == c) {
			*q++ = '"';		/* Close opening quote */
			if (q >= end)
				break;
			*q++ = c;		/* Final NUL */
			break;
		} else {
			*q++ = c;
		}
	}

	dest[len - 1] = '\0';	/* In case we jumped out of the loop above */

	return q;
}

/**
 * Convert known valid UTF-8 string to UTF-16.
 *
 * @return newly allocated string via halloc().
 */
static wchar_t *
wchar_utf16_convert(const char *s)
{
	size_t len;
	wchar_t *ws;

	len = 1 + utf8_to_utf16(s, NULL, 0);	/* +1 for final NULL */
	ws = halloc(len * 2);					/* Each character is 2 bytes */
	utf8_to_utf16(s, ws, len);

	return ws;
}

/**
 * Convert multi-byte string to wide-char string.
 *
 * @return newly allocated string via halloc(), NULL on error with errno set.
 */
static wchar_t *
wchar_mbs_convert(const char *s)
{
	size_t len;
	wchar_t *ws;

	len = 1 + mbstowcs(NULL, s, 0);			/* +1 for final 0x00 */
	if ((size_t) -1 == len) {
		errno = EILSEQ;
		return NULL;
	}
	ws = halloc(len * 2);
	mbstowcs(ws, s, len);

	return ws;
}

/**
 * Convert string to a wchar version.
 *
 * If the input string is UTF-8, it is converted into UTF-16.
 * If the input string is not UTF-8, it is interpreted as a local string
 * and converted to a wide-char string.
 *
 * @param s		the string to convert
 * @param uc	if non-NULL, filled with TRUE if output is Unicode in UTF-16
 *
 * @return newly allocated string via halloc(), NULL if we cannot convert it.
 */
static wchar_t *
wchar_convert(const char *s, bool *uc)
{
	wchar_t *ws;

	if (utf8_is_valid_string(s)) {
		ws = wchar_utf16_convert(s);
		if (uc != NULL)
			*uc = TRUE;
	} else {
		ws = wchar_mbs_convert(s);
		if (uc != NULL)
			*uc = FALSE;
	}

	return ws;
}

/**
 * Compare two items in a string vector.
 */
static int
strptr_cmp(const void *a, const void *b)
{
	const char * const *pa = a, * const *pb = b;

	return strcmp(*pa, *pb);
}

/**
 * The mingw_launched table is a dual-hash containing Windows process handles
 * as keys and PID as values, for all the processes created via launchve().
 */
static dualhash_t *mingw_launched;		/* Launched processes */
static once_flag_t mingw_launch_inited;

/**
 * Initialize the launched process table, once.
 */
static void
mingw_launch_init_once(void)
{
	mingw_launched = dualhash_new(NULL, pointer_eq, NULL, pointer_eq);
	dualhash_thread_safe(mingw_launched);
}

/*
 * Create escaped command-line string from argv[].
 *
 * Just like mingw_execve(), we need to properly enclose in double-quotes
 * all the arguments with embedded spaces or the constructed argv[] array
 * will not be correct.  Fortunately, we're not in an emergency situation
 * here so we can freely allocate memory.
 *
 * The reason we have to do all this work is that the underlying interface
 * that creates a new process, the CreateProcess() system call,  takes
 * a single command-line string that it must then parse to reconstruct
 * the argv[] array.  Whereas on UNIX systems, execve() already takes the
 * argv[] array and does not need to do any parsing!
 *
 * @param argv		the user-supplied argument vector for command
 *
 * @return allocated command string with proper argument quoting / escaping.
 */
static char *
mingw_command_line(char * const argv[])
{
	char **a;
	size_t i, n;
	char *cmd;

	for (i = 0; NULL != argv[i]; i++)
		/* empty */;

	n = i + 1;		/* Amount of entries in argv[] array + final NULL */
	HALLOC0_ARRAY(a, n);

	/*
	 * We're going to only allocate the strings we need to quote, reusing
	 * the ones given on entry otherwise.  This slightly complicates the
	 * freeing logic later on.
	 */

	for (i = 0; NULL != argv[i]; i++) {
		size_t qlen = mingw_quotedlen(argv[i]);

		if (0 == qlen) {
			a[i] = argv[i];		/* Reuse original string */
		} else {
			a[i] = halloc(qlen);
			mingw_quotestr(argv[i], a[i], qlen);
		}
	}

	g_assert(i == n - 1);

	a[i] = NULL;

	/*
	 * Build the command line string using the quoted arguments, then
	 * free all the strings we had to quote and our temporary vector.
	 */

	cmd = h_strjoinv(" ", a);

	for (i = 0; NULL != argv[i]; i++) {
		if (argv[i] != a[i])
			hfree(a[i]);
	}

	HFREE_NULL(a);

	return cmd;
}

/*
 * Build the environment buffer.
 *
 * Even when there is no supplied environment, we need to parse the
 * process environment to be able to determine whether it uses wide chars.
 *
 * @param envp		the optional user-supplied environment
 * @param flags		CreateProcess() flags updated for UTF-16 environment
 *
 * @return allocated environment buffer, NULL if given NULL initially.
 */
static char *
mingw_environment_block(char * const envp[], int *flags)
{
	if (envp != NULL) {
		size_t i, cnt, acnt = 0;
		const char *mandatory[] = { "PATH", "SYSTEMROOT" };
		bool has_mandatory[N_ITEMS(mandatory)];
		char *added[N_ITEMS(mandatory)];
		char **e;
		char *env;

		/*
		 * Compute size of user-supplied environment.
		 *
		 * The Windows runtime also requires that at least two environment
		 * variables be positionned or the child process will not startup
		 * properly.  These are PATH and SYSTEMROOT, which we are going to
		 * propagate from the process environment, unless superseded.
		 */

		ZERO(&has_mandatory);

		for (i = 0; NULL != envp[i]; i++) {
			size_t j;

			for (j = 0; j < N_ITEMS(mandatory); j++) {
				const char *p;

				if (has_mandatory[j])
					continue;				/* Variable already set */

				p = is_strprefix(envp[i], mandatory[j]);
				if (p != NULL && '=' == *p) {
					has_mandatory[j] = TRUE;
					break;
				}
			}
		}

		cnt = i;	/* Amount of variables in envp[] vector */

		/*
		 * If user-supplied environment does not list a mandatory variable,
		 * then propagate it from the environment of the current process.
		 */

		for (i = 0; i < N_ITEMS(mandatory); i++) {
			if (!has_mandatory[i]) {
				const char *v = getenv(mandatory[i]);

				if (NULL == v) {
					s_minicarp("%s(): missing mandatory \"%s\" in environment",
						G_STRFUNC, mandatory[i]);
				} else {
					added[acnt++] = h_strconcat(mandatory[i], "=", v, NULL_PTR);
				}
			}
		}

		g_assert(acnt <= N_ITEMS(added));

		/*
		 * Windows requires that environment variables be sorted.
		 *
		 * Moreover, unlike UNIX, the environment variables are
		 * case-insensitive.
		 */

		HALLOC_ARRAY(e, acnt + cnt + 2);	/* +2 for final "" and NULL */

		for (i = 0; i < cnt; i++) {
			e[i] = envp[i];
		}
		for (i = 0; i < acnt; i++) {
			e[cnt + i] = added[i];
		}

		vsort(e, cnt + acnt, sizeof e[0], strptr_cmp);
		e[cnt + acnt] = "";				/* Ensures final NUL emitted in env */
		e[cnt + acnt + 1] = NULL;		/* End of array for h_strjoinv() */

		env = h_strnjoinv("\0", 1, e);

		HFREE_NULL(e);
		for (i = 0; i < acnt; i++) {
			HFREE_NULL(added[i]);
		}

		return env;
	} else {
		extern char **environ;
		bool uc = FALSE;

		/* Need to check the process environment to position Unicode flag */

		if (environ[0] != NULL) {
			char *p = environ[0];
			char *q = vstrchr(p, '=');

			/*
			 * If there is a NUL byte before '=' or the '=' sign is indeed
			 * followed by a NUL, then we can safely assume this is UTF-16
			 * since and ANSI version would have bytes and no NUL before the
			 * end of the string.
			 */

			if (NULL == q || '\0' == q[1])
				uc = TRUE;		/* Little-endian UTF-16 for '=' */
		}

		if (uc)
			*flags |= CREATE_UNICODE_ENVIRONMENT;

		return NULL;
	}
}

/*
 * Record the handle of the child process and its pid, making sure we do not
 * close the process handle to be able to wait on the child later.
 *
 * @return the PID of the child process.
 */
static pid_t
mingw_record_child(PROCESS_INFORMATION *pi)
{
	HANDLE old;
	dualhash_t *dh;
	pid_t pid = pi->dwProcessId;

	once_flag_run(&mingw_launch_inited, mingw_launch_init_once);

	/* The main thread handle we can close as we don't need it */
	CloseHandle(pi->hThread);

	dh = mingw_launched;

	dualhash_lock(dh);

	old = dualhash_lookup_value(dh, uint_to_pointer(pid));

	if (old != NULL) {
		s_warning("%s(): had already an unwaited-for child bearing PID=%lu",
			G_STRFUNC, (ulong) pid);
		CloseHandle(old);
		dualhash_remove_value(dh, uint_to_pointer(pid));
	}

	/* Paranoid! */

	if (dualhash_contains_key(dh, pi->hProcess)) {
		pid_t opid = pointer_to_ulong(dualhash_lookup_key(dh, pi->hProcess));
		s_warning("%s(): duplicate handle %p, was for child PID %lu",
			G_STRFUNC, pi->hProcess, (ulong) opid);
		dualhash_remove_key(dh, pi->hProcess);
	}

	dualhash_insert_key(dh, pi->hProcess, uint_to_pointer(pid));

	dualhash_unlock(dh);

	return pid;
}

/**
 * Create a new process.
 *
 * This is a low-level routine on which mingw_launchve() and mingw_execve()
 * rely to perform their work.
 *
 * @param path		the path ot the command
 * @param argv		the argument vector
 * @param envp		the environment vector (can be NULL)
 * @param pi		where the new process information will be stored
 * @param suspended	whether to create the new process in a suspended state
 *
 * @return 0 if OK, -1 on error with errno set.
 */
static int
mingw_create_process(const char *path, char *const argv[], char *const envp[],
	PROCESS_INFORMATION *pi, bool suspended)
{
	STARTUPINFOW si;
	pncs_t pncs;
	int res, error = 0;
	char *file = deconstify_pointer(path), *cmd, *env = NULL;
	wchar_t *cmd_utf16 = NULL;
	const char exe[] = ".exe";
	int32 flags = 0;
	int ret = -1;

	g_assert(path != NULL);
	g_assert(argv != NULL);

	ZERO(pi);
	ZERO(&si);
	si.cb = sizeof si;

	if (suspended)
		flags |= CREATE_SUSPENDED;

	/*
	 * Add trailing ".exe" extension to the path if missing.
	 */

	if (!is_strcasesuffix(path, (size_t) -1, exe))
		file = h_strconcat(path, exe, NULL_PTR);

	/*
	 * Convert the command line string into a big happy UTF-16 string.
	 */

	cmd = mingw_command_line(argv);

	if (NULL == (cmd_utf16 = wchar_convert(cmd, NULL))) {
		error = EILSEQ;
		goto done;
	}

	HFREE_NULL(cmd);

	/*
	 * Create environment block or check current process for UTF-16,
	 * updating flags as necessary.
	 */

	env = mingw_environment_block(envp, &flags);

	/*
	 * Transform path to UTF-16.
	 * We use pncs_convert() to benefit from its path normalization.
	 */

	if (pncs_convert(&pncs, file)) {
		error = errno;
		goto done;
	}

	/*
	 * Now create the process!
	 */

	res = CreateProcessW(
		pncs.utf16,			/* lpApplicationName */
		cmd_utf16,			/* lpCommandLine */
		NULL,				/* lpProcessAttributes */
		NULL,				/* lpThreadAttributes */
		FALSE,				/* bInheritHandles */
		flags,				/* dwCreationFlags */
		env,				/* lpEnvironment */
		NULL,				/* lpCurrentDirectory */
		&si,				/* lpStartupInfo */
		pi					/* lpProcessInformation */
	);

	if (0 == res)
		error = mingw_last_error();
	else
		ret = 0;	/* Success! */

	/* FALL THROUGH */

done:
	HFREE_NULL(cmd);
	HFREE_NULL(cmd_utf16);
	HFREE_NULL(env);
	if (file != path)
		HFREE_NULL(file);

	if (error != 0)
		errno = error;

	return ret;
}

/**
 * Wrapper for execve().
 */
int
mingw_execve(const char *filename, char *const argv[], char *const envp[])
{
	PROCESS_INFORMATION pi;

	g_assert(filename != NULL);
	g_assert(argv != NULL);

	_flushall();

	/*
	 * We create the child in a suspended state so that we may close our
	 * stdout and stderr properly before the child starts its execution.
	 */

	if (-1 == mingw_create_process(filename, argv, envp, &pi, TRUE))
		return (pid_t) -1;		/* errno is already set */

	/*
	 * Before exiting, cleanup our resources as we would in do__exit().
	 */

	signal_perform_cleanup();
	mingw_stdio_reset(FALSE);

	/*
	 * We have cleaned-up, there are no more resources we hold that could
	 * prevent the new process from running, so resume it.
	 */

	ResumeThread(pi.hThread);		/* Pray it works... */

	/*
	 * We have to use _exit() to skip all the atexit() cleanups.
	 */

	_exit(0);		/* This is the real one, not the do__exit() call */
}

/**
 * The Windows version of our launchve() routine.
 * On UNIX, this is a simple matter of vfork() + execve()...
 *
 * The created child handle is stored along with the PID of the process
 * in a dualhash, so that we can implement wait() later on.
 *
 * @return -1 on failure, the PID of the child process otherwise.
 */
pid_t
mingw_launchve(const char *path, char *const argv[], char *const envp[])
{
	PROCESS_INFORMATION pi;

	g_assert(path != NULL);
	g_assert(argv != NULL);

	if (-1 == mingw_create_process(path, argv, envp, &pi, FALSE))
		return (pid_t) -1;		/* errno is already set */

	/*
	 * Good, process was created.
	 */

	return mingw_record_child(&pi);
}

/**
 * Create an inheritable duplicate handle given file descriptor, closing
 * and resetting the given fd if `closing' is TRUE.
 */
static HANDLE
mingw_inheritable_handle(int *fd_ptr, bool closing)
{
	int fd = *fd_ptr;
	HANDLE h, i, p;
	bool ok;

	g_assert(is_valid_fd(fd));

	/*
	 * DuplicateHandle() cannot be used with Winsock handles!
	 *
	 * See: https://msdn.microsoft.com/en-us/
	 *			library/windows/desktop/ms740522(v=vs.85).aspx
	 */

	g_return_val_unless(!is_a_socket(fd), (HANDLE) 0);

	p = GetCurrentProcess();
	h = (HANDLE) _get_osfhandle(fd);
	ok = DuplicateHandle(p, h, p, &i, 0, TRUE, DUPLICATE_SAME_ACCESS);
	if (closing)
		fd_close(fd_ptr);

	if (!ok) {
		errno = mingw_last_error();
		s_carp("%s(): cannot make fd #%d inheritable: %m", G_STRFUNC, fd);
		return (HANDLE) 0;
	}

	return i;
}

/**
 * The Windows version of our spopenve() routine.
 *
 * @return -1 on failure, the parent's pipe end to the child process otherwise.
 */
int
mingw_spopenve(const char *path, const char *mode, int fd[2],
	char *const argv[], char *const envp[])
{
	PROCESS_INFORMATION pi;
	STARTUPINFOW si;
	pncs_t pncs;
	int res, pfd = -1, error = 0;
	char *file = deconstify_pointer(path), *cmd = NULL, *env = NULL;
	wchar_t *cmd_utf16 = NULL;
	const char exe[] = ".exe";
	int32 flags = 0;
	bool p_read = FALSE, p_write = FALSE, p_cloexec = FALSE;
	pid_t pid;
	int pipefd[2];
	int pc[2];		/* pc[0] = parent's fd, pc[1] = child's fd */
	const char *p = mode;
	int c, r;
	HANDLE child_end = (HANDLE) 0;
	int dfd[2];

	g_assert(path != NULL);
	g_assert(mode != NULL);
	g_assert(argv != NULL);

	ZERO(&pi);
	ZERO(&si);
	si.cb = sizeof si;

	/* -- much of this leading code is identical to the UNIX version -- */

	if (NULL == fd) {
		fd = dfd;
		fd[0] = fd[1] = SPOPEN_ASIS;
	}

	pc[0] = pc[1] = -1;

	while ((c = *p++) != '\0') {
		switch (c) {
		case 'r': p_read    = TRUE; break;
		case 'w': p_write   = TRUE; break;
		case 'e': p_cloexec = TRUE; break;
		default: goto bad_arg;
		}
	}

	if (0 == (p_read ^ p_write)) {
		s_carp("%s(): cannot specify both \"r\" and \"w\", mode was \"%s\"",
			G_STRFUNC, mode);
		goto bad_arg;
	}

	if (SPOPEN_PARENT_STDOUT == fd[0] || SPOPEN_CHILD_STDOUT == fd[0]) {
		s_carp("%s(): cannot specify %d in fd[0], only meaningful for fd[1]",
			G_STRFUNC, fd[0]);
		goto bad_arg;
	}

	if (p_cloexec) {
		s_carp_once("%s(): ignoring \"e\" since no close-on-exec support",
			G_STRFUNC);
	}

	if (-1 == mingw_pipe(pipefd))
		goto pipe_failed;

	if (p_read) {
		pc[0] = pipefd[0];
		pc[1] = pipefd[1];
	} else {
		pc[0] = pipefd[1];
		pc[1] = pipefd[0];
	}

	/* -- now for the Windows specific part, similar to mingw_launchve() -- */

	/*
	 * Add trailing ".exe" extension to the path if missing.
	 */

	if (!is_strcasesuffix(path, (size_t) -1, exe))
		file = h_strconcat(path, exe, NULL_PTR);

	/*
	 * Convert the command line string into a big happy UTF-16 string.
	 */

	cmd = mingw_command_line(argv);

	if (NULL == (cmd_utf16 = wchar_convert(cmd, NULL))) {
		error = EILSEQ;
		goto done;
	}

	HFREE_NULL(cmd);

	/*
	 * Create environment block or check current process for UTF-16,
	 * updating flags as necessary.
	 */

	env = mingw_environment_block(envp, &flags);

	/*
	 * Setup appropriate child handles for stdin, stdout, stderr.
	 */

	child_end = mingw_inheritable_handle(&pc[1], TRUE);
	if ((HANDLE) 0 == child_end)
		goto pipe_failed;

	si.dwFlags |= STARTF_USESTDHANDLES;

	if (p_read) {
		si.hStdOutput = child_end;
	} else {
		si.hStdInput = child_end;
	}

	child_end = (HANDLE) 0;		/* copied to `si' now */

	/* Handle child's standard fd not contected to the pipe */

	switch (fd[0]) {
	case SPOPEN_ASIS:
		r = p_read ? STDIN_FILENO : STDOUT_FILENO;
	case SPOPEN_DEV_NULL:
		r = mingw_open("/dev/null", p_read ? O_RDONLY : O_WRONLY);
		if (-1 == r)
			goto pipe_failed;
		break;
	default:
		r = fd[0];
		break;
	}

	/* Redirect stdout / stdin for the child process */

	{
		HANDLE h = mingw_inheritable_handle(&r, FALSE);

		/*
		 * We only have to close(r) if fd[0] was a special negative SPOPEN_*
		 * value: otherwise, the trailing cleanup code closes all the valid
		 * descriptors in fd[].
		 */

		if (SPOPEN_DEV_NULL == fd[0])
			close(r);

		if ((HANDLE) 0 == h)
			goto pipe_failed;

		if (p_read) {
			si.hStdInput = h;
		} else {
			si.hStdOutput = h;
		}
	}

	/* Handle stderr redirections */

	switch (fd[1]) {
	case SPOPEN_ASIS:
		r = STDERR_FILENO;
		break;
	case SPOPEN_PARENT_STDOUT:
		r = STDOUT_FILENO;
		break;
	case SPOPEN_DEV_NULL:
		r = mingw_open("/dev/null", p_read ? O_RDONLY : O_WRONLY);
		if (-1 == r)
			goto pipe_failed;
		break;
	case SPOPEN_CHILD_STDOUT:
		{
			HANDLE h, i, t;
			bool ok;

			t = GetCurrentProcess();
			h = si.hStdOutput;
			ok = DuplicateHandle(t, h, t, &i, 0, TRUE, DUPLICATE_SAME_ACCESS);

			if (!ok) {
				error = mingw_last_error();
				s_carp("%s(): cannot duplicate stdout handle: %m", G_STRFUNC);
				goto pipe_failed;
			}

			si.hStdError = i;
			r = -1;		/* Nothing to do below, we already dup()ed stdout */
		}
		break;
	default:
		r = fd[1];
		break;
	}

	if (is_valid_fd(r)) {
		si.hStdError = mingw_inheritable_handle(&r, FALSE);
		if (SPOPEN_DEV_NULL == fd[1])
			close(r);
		if ((HANDLE) 0 == si.hStdError)
			goto pipe_failed;
	}

	/*
	 * Transform path to UTF-16.
	 * We use pncs_convert() to benefit from its path normalization.
	 */

	if (pncs_convert(&pncs, file)) {
		error = errno;
		goto done;
	}

	/*
	 * Now create the process, inheriting standard handles we just configured.
	 */

	res = CreateProcessW(
		pncs.utf16,			/* lpApplicationName */
		cmd_utf16,			/* lpCommandLine */
		NULL,				/* lpProcessAttributes */
		NULL,				/* lpThreadAttributes */
		TRUE,				/* bInheritHandles */
		flags,				/* dwCreationFlags */
		env,				/* lpEnvironment */
		NULL,				/* lpCurrentDirectory */
		&si,				/* lpStartupInfo */
		&pi					/* lpProcessInformation */
	);

	if (0 == res) {
		error = mingw_last_error();
		goto done;
	}

	/*
	 * Good, process was created.
	 */

	pid = mingw_record_child(&pi);	/* So they can waitpid() on child */
	pfd = pc[0];
	spopen_fd_map(pfd, pid);		/* So they can spclose() on pfd */

	goto done;

bad_arg:
	error = EINVAL;
	goto done;

pipe_failed:
	error = errno;
	/* FALL THROUGH */

done:
	HFREE_NULL(cmd);
	HFREE_NULL(cmd_utf16);
	HFREE_NULL(env);
	if (file != path)
		HFREE_NULL(file);

	for (c = 0; c < 2; c++) {
		if (is_valid_fd(fd[c]))
			close(fd[c]);
	}
	if (is_valid_fd(pc[1]))				close(pc[1]);
	if ((HANDLE) 0 != si.hStdInput)		CloseHandle(si.hStdInput);
	if ((HANDLE) 0 != si.hStdOutput)	CloseHandle(si.hStdOutput);
	if ((HANDLE) 0 != si.hStdError)		CloseHandle(si.hStdError);

	if (error != 0) {
		if (is_valid_fd(pc[0]))
			close(pc[0]);
		errno = error;
	}
	return pfd;
}

static FILETIME mingw_child_kern_time, mingw_child_user_time;
static spinlock_t mingw_child_time_slk = SPINLOCK_INIT;

#ifdef EMULATE_WAITPID
pid_t
mingw_wait(int *status)
{
	return mingw_waitpid(-1, status, 0);
}

/**
 * Add filetime from `item' into `sum'.
 */
static void
mingw_filetime_add(FILETIME *sum, FILETIME *item)
{
	DWORD old = sum->dwLowDateTime;

	sum->dwLowDateTime  += item->dwLowDateTime;
	sum->dwHighDateTime += item->dwHighDateTime;

	if (sum->dwLowDateTime < old)
		sum->dwHighDateTime++;		/* Propagate carry bit */
}

static void
mingw_child_account(FILETIME *kernel, FILETIME *user)
{
	spinlock(&mingw_child_time_slk);

	mingw_filetime_add(&mingw_child_kern_time, kernel);
	mingw_filetime_add(&mingw_child_user_time, user);

	spinunlock(&mingw_child_time_slk);
}

struct mingw_child_args {
	HANDLE *hv;			/* Handle vector */
	size_t count;		/* Amount of items in vector */
	size_t pos;			/* Next position to fill in vector */
};

static void
mingw_child_add(const void *key, void *value, void *data)
{
	struct mingw_child_args *arg = data;
	HANDLE *h = deconstify_pointer(key);

	g_assert(arg->pos < arg->count);
	(void) value;

	arg->hv[arg->pos++] = h;
}

pid_t
mingw_waitpid(pid_t pid, int *status, int options)
{
	dualhash_t *dh = mingw_launched;
	int ms;
	ulong res;
	HANDLE proc = NULL;
	pid_t exiting_pid;

	if (NULL == dh || 0 == dualhash_count(dh))
		goto no_child;

	ms = (options & WNOHANG) ? 0 : INFINITE;

	if (pid > 0) {
		HANDLE h = dualhash_lookup_value(dh, ulong_to_pointer(pid));

		if (NULL == h)
			goto no_child;

		thread_in_syscall_set(TRUE);
		res = WaitForSingleObject(h, ms);
		thread_in_syscall_set(FALSE);

		switch (res) {
		case WAIT_TIMEOUT:
			return 0;
		case WAIT_ABANDONED:
			s_warning("%s(): got WAIT_ABANDONED while waiting for PID %lu?",
				G_STRFUNC, (ulong) pid);
			errno = EINTR;	/* Such a weird state: handle is for a process! */
			return -1;
		case WAIT_OBJECT_0:
			proc = h;		/* This process has exited */
			break;
		case WAIT_FAILED:
		default:
			errno = mingw_last_error();
			return -1;
		}
	} else {
		HANDLE *hv;
		size_t count;
		struct mingw_child_args arg;

		dualhash_lock(dh);

		count = dualhash_count(dh);
		HALLOC0_ARRAY(hv, count);

		arg.hv = hv;
		arg.count = count;
		arg.pos = 0;

		dualhash_foreach(dh, mingw_child_add, &arg);
		dualhash_unlock(dh);

		thread_in_syscall_set(TRUE);
		res = WaitForMultipleObjects(count, hv, FALSE, ms);
		thread_in_syscall_set(FALSE);

		if (res < WAIT_ABANDONED_0)
			proc = hv[res - WAIT_OBJECT_0];		/* This process has exited */

		HFREE_NULL(hv);

		if (proc != NULL) {
			goto child_exited;
		} else if (WAIT_TIMEOUT == res) {
			return 0;
		} else {
			if (WAIT_FAILED == UNSIGNED(res)) {
				errno = mingw_last_error();
			} else {
				s_warning("%s(): got WAIT_ABANDONED while waiting for children",
					G_STRFUNC);
				errno = EINTR;
			}
			return -1;
		}
	}

child_exited:

	g_assert(proc != NULL);		/* This process has exited */

	dualhash_lock(dh);

	exiting_pid = pointer_to_ulong(dualhash_lookup_key(dh, proc));
	dualhash_remove_key(dh, proc);

	dualhash_unlock(dh);

	g_soft_assert_log(0 != exiting_pid,
		"%s(): handle %p is no longer associated to any PID?",
		G_STRFUNC, proc);

	/*
	 * Grab the exit status, regardless of whether our caller wants it.
	 */

	{
		DWORD code;
		if (!GetExitCodeProcess(proc, &code)) {
			errno = mingw_last_error();
			s_warning("%s(): could not get exit status of PID %lu: %m",
				G_STRFUNC, (ulong) exiting_pid);
			code = 0;
		}
		if (status != NULL)
			*status = code;
	}

	/*
	 * Get child resource usage, for getrusage(RUSAGE_CHILDREN) calls.
	 */

	{
		FILETIME creation_time, exit_time, kernel_time, user_time;

		if (
			!GetProcessTimes(proc,
				&creation_time, &exit_time, &kernel_time, &user_time)
		) {
			errno = mingw_last_error();
			s_warning("%s(): could not get resource usage for PID %lu: %m",
				G_STRFUNC, (ulong) exiting_pid);
		} else {
			mingw_child_account(&kernel_time, &user_time);
		}
	}

	CloseHandle(proc);
	return exiting_pid;

no_child:
	errno = ECHILD;
	return -1;
}
#endif	/* EMULATE_WAITPID */

/**
 * Is WSAPoll() supported?
 */
bool
mingw_has_wsapoll(void)
{
	ONCE_FLAG_RUN(mingw_socket_inited, mingw_socket_init);

	/*
	 * Since there is no binding in MinGW for WSAPoll(), we use the dynamic
	 * linker to fetch the routine address in the library.
	 * Currently, Configure cannot statically determine whether the
	 * feature exists...
	 *		--RAM, 2010-12-14
	 */

	return WSAPoll != NULL;
}

/**
 * Drop-in replacement for poll(), provided WSAPoll() exists.
 *
 * Use mingw_has_wsapoll() to check for WSAPoll() availability at runtime.
 */
int
mingw_poll(struct pollfd *fds, unsigned int nfds, int timeout)
{
	int res;

	ONCE_FLAG_RUN(mingw_socket_inited, mingw_socket_init);

	if (NULL == WSAPoll) {
		errno = WSAEOPNOTSUPP;
		return -1;
	}

	res = WSAPoll(fds, nfds, timeout);

	if (SOCKET_ERROR == res)
		errno = mingw_wsa_last_error();

	return res;
}

/**
 * Get special folder path as a UTF-8 string.
 *
 * @param which		which special folder to get (CSIDL code)
 * @param what		English description of ``which'', for error logging.
 *
 * @return read-only constant string.
 */
static const char *
get_special(int which, char *what)
{
	static spinlock_t special_slk = SPINLOCK_INIT;
	static wchar_t pathname[MAX_PATH];
	static char utf8_path[MAX_PATH];
	int ret;
	const char *result;

	spinlock_hidden(&special_slk);		/* Protect access to static vars */

	ret = SHGetFolderPathW(NULL, which, NULL, 0, pathname);

	if (E_INVALIDARG != ret) {
		size_t conv = utf16_to_utf8(pathname, ARYLEN(utf8_path));
		if (conv > sizeof utf8_path) {
			s_warning("cannot convert %s path from UTF-16 to UTF-8", what);
			ret = E_INVALIDARG;
		}
	}

	if (E_INVALIDARG == ret) {
		s_carp("%s: could not get the %s directory", G_STRFUNC, what);
		/* ASCII is valid UTF-8 */
		cstr_bcpy(ARYLEN(utf8_path), G_DIR_SEPARATOR_S);
	}

	result = constant_str(utf8_path);

	spinunlock_hidden(&special_slk);

	return result;
}

const char *
mingw_get_home_path(void)
{
	static const char *result;

	if G_UNLIKELY(NULL == result)
		result = get_special(CSIDL_LOCAL_APPDATA, "home");

	return result;
}

const char *
mingw_get_personal_path(void)
{
	static const char *result;

	if G_UNLIKELY(NULL == result)
		result = get_special(CSIDL_PERSONAL, "My Documents");

	return result;
}

const char *
mingw_get_common_docs_path(void)
{
	static const char *result;

	if G_UNLIKELY(NULL == result)
		result = get_special(CSIDL_COMMON_DOCUMENTS, "Common Documents");

	return result;
}

const char *
mingw_get_common_appdata_path(void)
{
	static const char *result;

	if G_UNLIKELY(NULL == result)
		result = get_special(CSIDL_COMMON_APPDATA, "Common Application Data");

	return result;
}

const char *
mingw_get_admin_tools_path(void)
{
	static const char *result;

	if G_UNLIKELY(NULL == result)
		result = get_special(CSIDL_ADMINTOOLS, "Admin Tools");

	return result;
}

const char *
mingw_get_windows_path(void)
{
	static const char *result;

	if G_UNLIKELY(NULL == result)
		result = get_special(CSIDL_WINDOWS, "Windows");

	return result;
}

const char *
mingw_get_system_path(void)
{
	static const char *result;

	if G_UNLIKELY(NULL == result)
		result = get_special(CSIDL_SYSTEM, "system");

	return result;
}

const char *
mingw_get_internet_cache_path(void)
{
	static const char *result;

	if G_UNLIKELY(NULL == result)
		result = get_special(CSIDL_INTERNET_CACHE, "Internet Cache");

	return result;
}

const char *
mingw_get_mypictures_path(void)
{
	static const char *result;

	if G_UNLIKELY(NULL == result)
		result = get_special(CSIDL_MYPICTURES, "My Pictures");

	return result;
}

const char *
mingw_get_program_files_path(void)
{
	static const char *result;

	if G_UNLIKELY(NULL == result)
		result = get_special(CSIDL_PROGRAM_FILES, "Program Files");

	return result;
}

const char *
mingw_get_fonts_path(void)
{
	static const char *result;

	if G_UNLIKELY(NULL == result)
		result = get_special(CSIDL_FONTS, "Font");

	return result;
}

const char *
mingw_get_startup_path(void)
{
	static const char *result;

	if G_UNLIKELY(NULL == result)
		result = get_special(CSIDL_STARTUP, "Startup");

	return result;
}

const char *
mingw_get_history_path(void)
{
	static const char *result;

	if G_UNLIKELY(NULL == result)
		result = get_special(CSIDL_HISTORY, "History");

	return result;
}

const char *
mingw_get_cookies_path(void)
{
	static const char *result;

	if G_UNLIKELY(NULL == result)
		result = get_special(CSIDL_COOKIES, "Cookies");

	return result;
}

/**
 * Build path to file as "<personal_dir>\gtk-gnutella\file" without allocating
 * any memory.  If the resulting path is too long, use "/file" instead.
 * If the directory "<personal_dir>\gtk-gnutella" doest not exist yet, it
 * is created.  If the directory "<personal_dir>" does not exist, use "/file".
 *
 * @param file		name of file
 * @param dest		destination for result path
 * @param size		size of dest
 *
 * @return the address of the dest parameter.
 */
static const char *
mingw_build_personal_path(const char *file, char *dest, size_t size)
{
	const char *personal;

	/*
	 * If we have a forced name, we're not a "registered" product
	 * that is meant to leave traces on the system, but we're a test
	 * program most probably.  Use the current directory for logging.
	 * 		--RAM, 2018-10-11
	 */

	if (product_has_forced_name()) {
		cstr_bcpy(dest, size, ".");
		goto local_dir;
	}

	personal = mingw_get_personal_path();
	cstr_bcpy(dest, size, personal);

	STARTUP_DEBUG("%s(): #1 dest=%s", G_STRFUNC, dest);

	if (path_does_not_exist(personal))
		goto fallback;

	clamp_strcat(dest, size, G_DIR_SEPARATOR_S);
	clamp_strcat(dest, size, product_name());

	STARTUP_DEBUG("%s(): #2 dest=%s", G_STRFUNC, dest);

	if (path_does_not_exist(dest))
		mingw_mkdir(dest, S_IRUSR | S_IWUSR | S_IXUSR);

	/* FALL THROUGH */

local_dir:
	clamp_strcat(dest, size, G_DIR_SEPARATOR_S);
	clamp_strcat(dest, size, file);

	if (0 != strcmp(filepath_basename(dest), file))
		goto fallback;

	STARTUP_DEBUG("%s(): returning dest=%s", G_STRFUNC, dest);

	return dest;

fallback:
	cstr_bcpy(dest, size, G_DIR_SEPARATOR_S);
	clamp_strcat(dest, size, file);
	STARTUP_DEBUG("%s(): returning fallback dest=%s", G_STRFUNC, dest);
	return dest;
}

/**
 * Return default stdout logfile when launched from the GUI.
 * Directories leading to the dirname of the result are created as needed.
 */
static const char *
mingw_getstdout_path(void)
{
	static char pathname[MAX_PATH];
	char buf[128];

	str_bprintf(ARYLEN(buf), "%s.stdout", product_nickname());

	return mingw_build_personal_path(buf, ARYLEN(pathname));
}

/**
 * Return default stderr logfile when launched from the GUI.
 * Directories leading to the dirname of the result are created as needed.
 */
static const char *
mingw_getstderr_path(void)
{
	static char pathname[MAX_PATH];
	char buf[128];

	str_bprintf(ARYLEN(buf), "%s.stderr", product_nickname());

	return mingw_build_personal_path(buf, ARYLEN(pathname));
}

/**
 * Return default supervisor logfile when launched from the GUI.
 * Directories leading to the dirname of the result are created as needed.
 */
const char *
mingw_get_supervisor_log_path(void)
{
	static char pathname[MAX_PATH];
	char buf[128];

	str_bprintf(ARYLEN(buf), "%s.super", product_nickname());

	return mingw_build_personal_path(buf, ARYLEN(pathname));
}

/**
 * Patch directory by replacing the leading "home" with the "personal"
 * directory if the supplied pathname does not exist.  If it exists, we have
 * to assume the original path was used, or created explicitely by the user
 * to be used, and we're not going to supersede it.
 *
 * @return the argument if nothing needs to be patched, a patched string
 * otherwise which needs to be freed via hfree().
 */
char *
mingw_patch_personal_path(const char *pathname)
{
	const char *home = mingw_get_home_path();
	const char *p;

	p = is_strprefix(pathname, home);
	if (p != NULL && !is_directory(pathname)) {
		char *patched;
		if (is_strsuffix(pathname, -1, "gtk-gnutella-downloads/complete")) {
			/*
			 * Put the gtk-gnutella-downloads/complete into the downloads folder
			 * as this is where the user would expect completed downloads to be
			 * be placed
			 * 	-- JA 29/7/2011
			 */
			patched = h_strdup(
				g_get_user_special_dir(G_USER_DIRECTORY_DOWNLOAD));
		} else {
			/*
			 * Put everything else under "My Documents/gtk-gnutella", were
			 * we should already find stdout and stderr files created when
			 * running from the GUI.
			 */

			patched = h_strconcat(mingw_get_personal_path(),
				G_DIR_SEPARATOR_S, product_name(), p, NULL_PTR);
		}
		s_debug("patched \"%s\" into \"%s\"", pathname, patched);
		return patched;
	} else {
		return deconstify_char(pathname);	/* No need to patch anything */
	}
}

uint64
mingw_getphysmemsize(void)
{
	MEMORYSTATUSEX memStatus;

	memStatus.dwLength = sizeof memStatus;

	if (!GlobalMemoryStatusEx(&memStatus)) {
		errno = mingw_last_error();
		return -1;
	}
	return memStatus.ullTotalPhys;
}

int
mingw_getdtablesize(void)
{
	/*
	 * Traditionally, on Windows, the stdio layer can only fopen() 512 files,
	 * but the low-level I/O layer on top of which it is built can open()
	 * up to 2048 files.
	 *
	 * An application can use _setmaxstdio() to increase the amount of files
	 * we can fopen(), up to the maximum of 2048.
	 *
	 * See: https://msdn.microsoft.com/en-us/library/6e3b887c(v=vs.140).aspx
	 *
	 * For our purpose here, we're attempting to return a number that
	 * quantifies how many "file descriptors" we can have, knowing that we
	 * do not count sockets in the mix, whereas the UNIX version of
	 * getdtablesize() does include sockets since they are identified as
	 * file descriptors.
	 *
	 * Hence calling _getmaxstdio() is meaningless.  We know there are going
	 * to be sockets used, but we do not know exactly how many compared to
	 * files, since that is application-specific.
	 *
	 * Therefore, hardwire 2048, which is a known C runtime maximum and does
	 * not represent the maximum number of Windows HANDLE we can open, which
	 * is far larger, but represents the maximum amount of files we're going
	 * to be able to manage with file descriptors: the size of the table
	 * mapping a fd to its HANDLE.
	 *
	 *		--RAM, 2016-02-21
	 */

	return 2048;
}

int
mingw_mkdir(const char *pathname, mode_t mode)
{
	int res;
	pncs_t pncs;

	(void) mode; 	/* FIXME: handle mode */

	if (pncs_convert(&pncs, pathname))
		return -1;

	res = _wmkdir(pncs.utf16);
	if (-1 == res)
		errno = mingw_last_error();

	return res;
}

int
mingw_rmdir(const char *pathname)
{
	int res;
	pncs_t pncs;

	if (pncs_convert(&pncs, pathname))
		return -1;

	res = _wrmdir(pncs.utf16);
	if (-1 == res)
		errno = mingw_last_error();

	return res;
}

int
mingw_access(const char *pathname, int mode)
{
	int res;
	pncs_t pncs;

	if (pncs_convert(&pncs, pathname))
		return -1;

	res = _waccess(pncs.utf16, mode);
	if (-1 == res)
		errno = mingw_last_error();

	return res;
}

int
mingw_chdir(const char *pathname)
{
	int res;
	pncs_t pncs;

	if (pncs_convert(&pncs, pathname))
		return -1;

	res = _wchdir(pncs.utf16);
	if (-1 == res)
		errno = mingw_last_error();

	return res;
}

int
mingw_remove(const char *pathname)
{
	int res;
	pncs_t pncs;

	if (pncs_convert(&pncs, pathname))
		return -1;

	res = _wremove(pncs.utf16);
	if (-1 == res)
		errno = mingw_last_error();

	return res;
}

int
mingw_pipe(int fd[2])
{
	int res;

	/*
	 * We force O_NOINHERIT on the pipe handles because if a pipe is created
	 * and passed to children processes, the side of the pipe that remains
	 * in the parent process must not be seen by the child.
	 *
	 * Failure to specify this flag causes spopen() to mis-behave on Windows
	 * when fd[0] is given a pipe end, for instance.  So the policy must be
	 * that hanldes cannot be inherited and those that we want to pass to
	 * a child process are explicly duplicated via mingw_inheritable_handle().
	 *		--RAM, 2015-11-04.
	 */

	/* Buffer size of 8192 is arbitrary */
	res = _pipe(fd, 8192, O_BINARY | O_NOINHERIT);
	if (-1 == res)
		errno = mingw_last_error();

	return res;
}

static void
mingw_copy_stat_struct(const struct _stati64 *nbuf, filestat_t *buf)
{
#define C(x)	buf->st_ ## x = nbuf->st_ ## x

	C(dev);
	C(ino);
	C(mode);
	C(nlink);
	C(uid);
	C(gid);
	C(rdev);
	C(size);
	C(atime);
	C(mtime);
	C(ctime);

	/*
	 * Fake these on Windows.
	 *
	 * These are not even present in the _stati64 structure, but some C code
	 * may depend on these fields being set properly, so compute some meaningful
	 * values.
	 */

	buf->st_blksize = 131072;				/* magic "random" number */
	buf->st_blocks = nbuf->st_size >> 9;	/* # of 512B blocks allocated */
	if (nbuf->st_size & ((1 << 9) - 1))		/* partial trailing block? */
		buf->st_blocks++;

#undef C
}

/**
 * Initialize the GetFileInformationByHandleEx pointer, once, by probing
 * the kernel libraray.
 *
 * Indeed, the GetFileInformationByHandleEx() routine is only available
 * starting with VISTA, which comes between XP and WIN7.
 */
static void
mingw_gfibhe_init(void)
{
	HMODULE kernel32 = LoadLibrary("kernel32.dll");

	if (kernel32 != NULL) {
		GetFileInformationByHandleEx = (GetFileInformationByHandleEx_t)
			GetProcAddress(kernel32, "GetFileInformationByHandleEx");
	}
}

static bool
mingw_fix_statbuf(HANDLE h,
	const struct _stati64 *nbuf, bool is_fstat,
	filestat_t *buf)
{
	BY_HANDLE_FILE_INFORMATION fi;
	bool ok;
	DWORD type = GetFileType(h);

	mingw_copy_stat_struct(nbuf, buf);

	/*
	 * We only know how to fix the buffer for disk files and pipes.
	 */

	if G_UNLIKELY(FILE_TYPE_PIPE == type) {
		DWORD pending;

		if (PeekNamedPipe(h, NULL, 0, NULL, &pending, NULL))
			buf->st_size = pending;

		/* Silenetly ignore errors on PeekNamedPipe() */

		return TRUE;
	}

	if (FILE_TYPE_DISK != type)
		return TRUE;

	ok = 0 != GetFileInformationByHandle(h, &fi);

	if (ok) {
		buf->st_dev = (uint) fi.dwVolumeSerialNumber;
		buf->st_ino = UINT64_VALUE(fi.nFileIndexHigh, fi.nFileIndexLow);

		/*
		 * This computation sometimes yields the wrong results: for a file
		 * on a remote SMB share with 2 links, it sometimes gives back 2,
		 * but sometimes it returns 1.
		 *
		 * Hence disabling it, as we disabled the code further below that
		 * attempts to correct it for fstat() calls.
		 * 		--RAM, 2018-05-13
		 */

#if 0
		buf->st_nlink = MIN(fi.nNumberOfLinks, MAX_UINT_VALUE(buf->st_nlink));
#endif
	}

	/*
	 * Always clear the trailing bits in mode that cannot be set on Windows
	 * (the 6 trailing bits corresponding to "other" permissions) and that we
	 * cannot check for.
	 *
	 * Our runtime remaps S_IxGRP to S_IxUSR and S_IxOTH tests are meaningless.
	 * Hence it does not make sense to keep these trailing bits.
	 */

	buf->st_mode &= ~0x3f;

	/*
	 * If coming from fstat(), then we need to query for the underlying
	 * file name to check whether it is an executable, in order to restore
	 * the executable bits in the mode.
	 *
	 * Unfortunately, GetFileInformationByHandleEx() is not available on XP:
	 * it starts with VISTA, hence the contorsions below since we are compiling
	 * on Windows XP and therefore do not have the right compile-time support.
	 */

	if (is_fstat && S_ISREG(buf->st_mode)) {
		ONCE_FLAG_RUN(mingw_gfibhe_inited, mingw_gfibhe_init);

		if (GetFileInformationByHandleEx != NULL) {
			size_t len = MAX_PATH_LEN * sizeof(wchar_t) + sizeof(FILE_NAME_INFO);
			void *b = walloc0(len);
			FILE_NAME_INFO *fni = NULL;

			if (GetFileInformationByHandleEx(h, FileNameInfo, b, len))
				fni = b;

			/*
			 * Look for an "executable" extension in the file name.
			 */

			if (fni != NULL) {
				size_t len8;		/* UTF-8 length */
				char *n8;			/* UTF-8 file name */

				/* Convert back the UTF-16 into UTF-8 */

				len8 = 1 + utf16_to_utf8(fni->FileName, NULL, 0);
				n8 = walloc(len8);
				(void) utf16_to_utf8(fni->FileName, n8, len8);

				/* Assume case-independance for extensions */

				if (
					is_strcasesuffix(n8, len8 - 1, ".exe") ||
					is_strcasesuffix(n8, len8 - 1, ".bat") ||
					is_strcasesuffix(n8, len8 - 1, ".com") ||
					is_strcasesuffix(n8, len8 - 1, ".cmd")
				)
					buf->st_mode |= S_IXUSR;

				wfree(n8, len8);
			}

			/*
			 * Compute the proper number of links by stat()-ing the file.
			 *
			 * FIXME:
			 * Unfortunately, this is unreliable and can return a
			 * different value from time to time when dealing with
			 * files on a remote volume shared by SMB.
			 * This is disturbing...
			 *
			 * On Windows, regardless of NTFS supporting links, it seems
			 * that the st_nlink value is unreliable.
			 *
			 * Therefore, disabling this code for now.
			 * 		--RAM, 2018-05-13
			 */

#if 0	/* Disabled because results are unreliable */
			if (fni != NULL) {
				HANDLE dh;

				dh = CreateFileW(fni->FileName, FILE_READ_ATTRIBUTES,
						FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE,
						NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);

				if (
					INVALID_HANDLE_VALUE != dh &&
					GetFileInformationByHandle(dh, &fi)
				) {
					buf->st_nlink =
						MIN(fi.nNumberOfLinks, MAX_UINT_VALUE(buf->st_nlink));
				}

				CloseHandle(dh);
			}
#endif	/* Disabled because results are unreliable */

			wfree(b, len);
		}
	}

	return ok;
}

static bool
mingw_fix_fstat(HANDLE h, const struct _stati64 *nbuf, filestat_t *buf)
{
	return mingw_fix_statbuf(h, nbuf, TRUE, buf);
}

/*
 * Attempt to fix the stat() buffer by post-processing the returned information
 * from the MinGW runtime.
 *
 * @return 0 if OK, -1 on error with errno set, 1 if we could not fix the
 * status but otherwise should not report any error to the user.
 */
static int
mingw_fix_stat(const wchar_t *pathname,
	const struct _stati64 *nbuf, filestat_t *buf)
{
	HANDLE h;
	bool ok;

	/*
	 * The given pathname is expected to already be UTF-16.
	 *
	 * We need FILE_FLAG_BACKUP_SEMANTICS to be able to obtain a handle
	 * on a directory.
	 */

	h = CreateFileW(pathname, FILE_READ_ATTRIBUTES,
			FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE,
			NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);

	if (INVALID_HANDLE_VALUE == h) {
		int error = GetLastError();

		/*
		 * Trap ERROR_NOT_READY errors, for instance when attempting
		 * to stat "D:/" and it is a CDROM device holding nothing.
		 */

		if (ERROR_NOT_READY == error) {
			errno = ENODEV;
			return -1;
		}

		/*
		 * Let them know the error code before failing, so that we may
		 * diagnose what to do: ignore, fix, etc...
		 */

		s_warning("%s(): got Windows error code %d", G_STRFUNC, error);
		return 1;	/* Don't let the stat() call fail, but complain loudly */
	}

	ok = mingw_fix_statbuf(h, nbuf, FALSE, buf);
	CloseHandle(h);

	return ok ? 0 : 1;
}

int
mingw_stat(const char *pathname, filestat_t *buf)
{
	pncs_t pncs;
	int res;
	size_t len;
	const char exe[] = ".exe";
	struct _stati64 nbuf;

	if (pncs_convert(&pncs, pathname))
		return -1;

	res = _wstati64(pncs.utf16, &nbuf);
	if (-1 == res) {
		errno = mingw_last_error();

		/*
		 * If there is a trailing '/' in the pathname, this will perturb
		 * stat() and we'll get ENOENT.  Likewise for a trailing "/." so
		 * if "/usr" exists, "/usr/" and "/usr/." will fail, but "/usr/.."
		 * will work.  On UNIX, the first two are strictly equivalent.
		 *		--RAM, 2015-04-19
		 */

		if (ENOENT == errno) {
			const char *p;
		   
			len = vstrlen(pathname);
			p = &pathname[len - 1];

			if (len <= 1)
				goto nofix;		/* A simple "/" would have worked */

			if ('/' == *p)
				len--;
			else if ('.' == *p && '/' == p[-1])
				len -= 2;
			else
				goto exefix;	/* See whether we try to stat() an executable */

			/*
			 * In a signal handler, don't allocate memory.
			 */

			if (signal_in_unsafe_handler()) {
				static char path[MAX_PATH_LEN];

				clamp_strncpy(ARYLEN(path), pathname, len);
				if (0 == pncs_convert(&pncs, path))
					res = _wstati64(pncs.utf16, &nbuf);
			} else {
				char *fixed;

				fixed = h_strndup(pathname, len);
				if (0 == pncs_convert(&pncs, fixed))
					res = _wstati64(pncs.utf16, &nbuf);
				hfree(fixed);
			}
		}
	}

	/* FALL THROUGH */

nofix:
	/*
	 * Unfortunately, the MinGW runtime does not fill-in any useful information
	 * for st_dev and st_ino, so we use Windows calls to supply the missing
	 * information in a consistent way.
	 * 		--RAM, 2018-05-12
	 */

	if (-1 != res) {
		int fix = mingw_fix_stat(pncs.utf16, &nbuf, buf);

		switch (fix) {
		case 0:		/* OK */
		default:
			break;
		case 1:		/* Could not fix */
			s_carp("%s(): cannot fix information correctly for \"%s\"",
				G_STRFUNC, pathname);
			break;
		case -1:	/* Report error, errno was set */
			res = -1;
			break;
		}
	}

	return res;

exefix:
	/*
	 * Maybe the are stat()ing "foo" but "foo.exe" exists?
	 *
	 * In which case we want to transparently succeed by stat()ing the
	 * executable instead!
	 * 		--RAM, 2018-05-12
	 */

	if (is_strsuffix(pathname, len, exe))
		goto nofix;		/* Already had the trailing .exe in path */

	/*
	 * In a signal handler, don't allocate memory.
	 */

	if (signal_in_unsafe_handler()) {
		static char path[MAX_PATH_LEN];

		clamp_strncpy(ARYLEN(path), pathname, len);
		clamp_strcat(ARYLEN(path), exe);
		if (0 == pncs_convert(&pncs, path))
			res = _wstati64(pncs.utf16, &nbuf);
	} else {
		char *fixed;

		fixed = h_strconcat(pathname, exe, NULL);
		if (0 == pncs_convert(&pncs, fixed))
			res = _wstati64(pncs.utf16, &nbuf);
		hfree(fixed);
	}

	goto nofix;
}

int
mingw_fstat(int fd, filestat_t *buf)
{
	int res;
	struct _stati64 nbuf;

	res = _fstati64(fd, &nbuf);
	if (-1 == res)
		errno = mingw_last_error();

	/*
	 * Unfortunately, the MinGW runtime does not fill-in any useful information
	 * for st_dev and st_ino, so we use Windows calls to supply the missing
	 * information in a consistent way.
	 * 		--RAM, 2018-05-12
	 */

	if (-1 != res && !mingw_fix_fstat((HANDLE) _get_osfhandle(fd), &nbuf, buf)) {
		s_carp("%s(): cannot fix information correctly for fd #%d",
			G_STRFUNC, fd);
	}

	return res;
}

int
mingw_unlink(const char *pathname)
{
	pncs_t pncs;
	int res;

	if (pncs_convert(&pncs, pathname))
		return -1;

	res = _wunlink(pncs.utf16);
	if (-1 == res)
		errno = mingw_last_error();

	return res;
}

int
mingw_dup(int fd)
{
	int res = _dup(fd);
	if (-1 == res)
		errno = mingw_last_error();
	return res;
}

int
mingw_dup2(int oldfd, int newfd)
{
	int res;

	if (oldfd == newfd) {
		/* Windows does not like dup2(fd, fd) */
		if (is_open_fd(oldfd))
			res = newfd;
		else
			res = -1;
	} else {
		res = dup2(oldfd, newfd);
		if (-1 == res)
			errno = mingw_last_error();
		else
			res = newfd;	/* Windows's dup2() returns 0 on success */
	}
	return res;
}

int
mingw_open(const char *pathname, int flags, ...)
{
	int res;
	mode_t mode = 0;
	pncs_t pncs;

	flags |= O_BINARY;
	if (flags & O_CREAT) {
        va_list  args;

        va_start(args, flags);
        mode = (mode_t) va_arg(args, int);
        va_end(args);
    }

	if (0 == strcmp(pathname, "/dev/null"))
		pathname = "NUL";

	if (pncs_convert(&pncs, pathname))
		return -1;

	res = _wopen(pncs.utf16, flags, mode);
	if (-1 == res)
		errno = mingw_last_error();

	return res;
}

DIR *
mingw_opendir(const char *pathname)
{
	_WDIR *res;
	pncs_t pncs;

	if (pncs_convert(&pncs, pathname))
		return NULL;

	res = _wopendir(pncs.utf16);
	if (NULL == res)
		errno = mingw_last_error();

	return (DIR *) res;
}

struct dirent *
mingw_readdir(DIR *dir)
{
	struct _wdirent *res;
	int saved_errno = errno;

	/*
	 * Do not perturb errno in this routine unless it changes.
	 * The MinGW runtime implementation of _wreaddir() will make sure
	 * errno is left untouched when we end up reaching the end of the
	 * directory.
	 *		--RAM, 2015-04-19
	 */

	res = _wreaddir((_WDIR *) dir);
	if (NULL == res) {
		if (errno != saved_errno)
			errno = mingw_last_error();
		return NULL;
	}
	return (struct dirent *) res;
}

int
mingw_closedir(DIR *dir)
{
	int res = _wclosedir((_WDIR *) dir);
	if (-1 == res)
		errno = mingw_last_error();
	return 0;
}

/**
 * @note The returned UTF-8 string becomes invalid after the next
 *		 call to dir_entry_filename().
 */
const char *
dir_entry_filename(const void *dirent)
{
	const struct _wdirent *wdirent = dirent;

	g_assert(dirent != NULL);

	return h_private(G_STRFUNC, utf16_to_utf8_string(wdirent->d_name));
}

/**
 * @return the byte length of the directory entry filename, converted to UTF-8.
 */
size_t
dir_entry_namelen(const void *dirent)
{
	const struct _wdirent *wdirent = dirent;

	g_assert(dirent != NULL);

	return utf16_to_utf8(wdirent->d_name, NULL, 0);
}

fileoffset_t
mingw_lseek(int fd, fileoffset_t offset, int whence)
{
	fileoffset_t res = _lseeki64(fd, offset, whence);
	if ((fileoffset_t) -1 == res)
		errno = mingw_last_error();
	return res;
}

ssize_t
mingw_read(int fd, void *buf, size_t count)
{
	ssize_t res;

	res = read(fd, buf, MIN(count, UINT_MAX));
	g_assert(-1 == res || (res >= 0 && UNSIGNED(res) <= count));

	if (-1 == res)
		errno = mingw_last_error();
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
    ssize_t total_read = 0, r = -1;

	for (i = 0; i < iov_cnt; i++) {
		r = mingw_read(fd, iovec_base(&iov[i]), iovec_len(&iov[i]));

		if (-1 == r)
			break;

		g_assert(r >= (ssize_t)0);
		g_assert(r <= (ssize_t)iovec_len(&iov[i]));

		total_read += r;

		if (UNSIGNED(r) != iovec_len(&iov[i]))
			break;
	}

    return total_read > 0 ? total_read : r;
}

ssize_t
mingw_write(int fd, const void *buf, size_t count)
{
	HANDLE h = (HANDLE) _get_osfhandle(fd);
	DWORD written;

	/*
	 * Apparently, on Win 7 (but not on XP and I do not know what
	 * happens on later version after 7), the C runtime causes write()
	 * to return ENOTSOCK on ERROR_NOACCESS, which should really
	 * be translated to EFAULT.  Experiments calling WriteFile()
	 * directly show that it is write() which incorrectly remaps the
	 * error code, not WriteFile() that returns a different code.
	 *
	 * Hence we now provide our own implementation on top of the Windows
	 * API, without calling write(), to ensure proper errno setting.
	 *		--RAM, 2016-02-16
	 */

	if G_UNLIKELY(INVALID_HANDLE_VALUE == h) {
		errno = EBADF;
		return -1;
	}

	if (!WriteFile(h, buf, MIN(count, UINT_MAX), &written, NULL)) {
		errno = mingw_last_error();
		written = (ssize_t) -1;

		if G_UNLIKELY(EPIPE == errno) {
			/*
			 * If we get EPIPE back, see whether there is a signal handler
			 * installed for SIGPIPE and raise the signal if there is.
			 * When there is no signal handler (still set to SIG_DFL),
			 * SIGPIPE is fatal -- this is done to mimic UNIX semantics.
			 *		--RAM, 2015-11-13
			 */

			if (SIG_DFL == mingw_sighandler[SIGPIPE]) {
				s_error("%s(): write to fd #%d caused SIGPIPE",
					G_STRFUNC, fd);
			} else if (SIG_IGN != mingw_sighandler[SIGPIPE]) {
				mingw_sigraise(SIGPIPE, FALSE);
			}
		}
	}

	return written;
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
	ssize_t total_written = 0, w = -1;
	char gather[1024];
	size_t nw;

	/*
	 * Because logging routines expect the writev() call to be atomic,
	 * and since logging message are usually small, we gather the
	 * string in memory first if it fits our small buffer.
	 */

	nw = iov_calculate_size(iov, iov_cnt);
	if (nw <= sizeof gather) {
		char *p = gather;

		for (i = 0; i < iov_cnt; i++) {
			size_t n = iovec_len(&iov[i]);

			p = mempcpy(p, iovec_base(&iov[i]), n);
		}
		g_assert(ptr_diff(p, gather) <= sizeof gather);

		w = mingw_write(fd, gather, nw);
	} else {
		for (i = 0; i < iov_cnt; i++) {
			w = mingw_write(fd, iovec_base(&iov[i]), iovec_len(&iov[i]));

			if (-1 == w)
				break;

			total_written += w;

			if (UNSIGNED(w) != iovec_len(&iov[i]))
				break;
		}
	}

	return total_written > 0 ? total_written : w;
}

int
mingw_truncate(const char *pathname, fileoffset_t len)
{
	int fd;

	fd = mingw_open(pathname, O_RDWR);
	if (-1 == fd)
		return -1;

	if (-1 == mingw_ftruncate(fd, len)) {
		int saved_errno = errno;
		fd_close(&fd);
		errno = saved_errno;
		return -1;
	}

	fd_close(&fd);
	return 0;
}

int
mingw_ftruncate(int fd, fileoffset_t len)
{
	fileoffset_t offset, current;

	if (-1 == fd) {
		errno = EBADF;
		return -1;
	}

	/*
	 * This emulation is NOT atomic and any concurrent thread trying to
	 * pread() or pwrite() on that file could get an inconsistent result
	 * due to the file offset changing underneath.
	 *
	 * Because we know that no call below can enter the compat_pio.c logic,
	 * we use the same locks as the compatibility routines to ensure we
	 * are at least consistent with our own emulations.
	 *
	 * Of course, concurrent threads accessing the file being ftruncate()-ed
	 * without using compat_pread(), compat_pwrite() or their vectorized
	 * friends to perform their I/Os would face a multi-threaded design bug!
	 */

	compat_pio_lock(fd);

	current = mingw_lseek(fd, 0, SEEK_CUR);
	if ((fileoffset_t) -1 == current)
		goto failed;

	if (current != len) {
		offset = mingw_lseek(fd, len, SEEK_SET);
		if ((fileoffset_t) -1 == offset || offset != len)
			goto failed;
	} else {
		offset = len;
	}

	if (!SetEndOfFile((HANDLE) _get_osfhandle(fd))) {
		int saved_errno = mingw_last_error();
		if (offset != current)
			(void) mingw_lseek(fd, current, SEEK_SET);
		errno = saved_errno;
		goto failed;
	}

	/*
	 * Note that this can reset the offset beyond the truncation point.
	 * But ftruncate() must not change the file offset to preserve the
	 * POSIX semantics.
	 *
	 * We used to warn when current > len but we no longer do because
	 * this does not indicate an application bug.  No harm will come if
	 * one issues a write() after truncation, if that is what they want.
	 * 		--RAM, 2018-10-08
	 */

	if (offset != current)
		(void) mingw_lseek(fd, current, SEEK_SET);

	compat_pio_unlock(fd);

	return 0;

failed:
	compat_pio_unlock(fd);
	return -1;
}

/***
 *** Socket wrappers
 ***/

int
mingw_select(int nfds, fd_set *readfds, fd_set *writefds,
	fd_set *exceptfds, struct timeval *timeout)
{
	int res;

	ONCE_FLAG_RUN(mingw_socket_inited, mingw_socket_init);

	res = select(nfds, readfds, writefds, exceptfds, timeout);

	if (res < 0)
		errno = mingw_wsa_last_error();

	return res;
}

int
mingw_gethostname(char *name, size_t len)
{
	int result;

	/* Initialize the socket layer */
	ONCE_FLAG_RUN(mingw_socket_inited, mingw_socket_init);

	result = gethostname(name, len);

	if (result != 0)
		errno = mingw_wsa_last_error();
	return result;
}

int
mingw_getaddrinfo(const char *node, const char *service,
	const struct addrinfo *hints, struct addrinfo **res)
{
	int result;

	/* Initialize the socket layer */
	ONCE_FLAG_RUN(mingw_socket_inited, mingw_socket_init);

	result = getaddrinfo(node, service, hints, res);

	if (result != 0)
		errno = mingw_wsa_last_error();
	return result;
}

void
mingw_freeaddrinfo(struct addrinfo *res)
{
	freeaddrinfo(res);
}

socket_fd_t
mingw_socket(int domain, int type, int protocol)
{
	socket_fd_t res;

	/* Initialize the socket layer */
	ONCE_FLAG_RUN(mingw_socket_inited, mingw_socket_init);

	/*
	 * Use WSASocket() to avoid creating "overlapped" sockets (i.e. sockets
	 * that can support asynchronous I/O).  This normally allows sockets to be
	 * use in read() and write() calls, transparently, as if they were files
	 * but it does not seem to work in the local_shell() code.
	 *
	 * It could however save on some system resources (avoiding creating and
	 * maintaining data structures that we won't be using anyway).
	 *		--RAM, 2011-01-11
	 */

	res = WSASocket(domain, type, protocol, NULL, 0, 0);
	if (INVALID_SOCKET == res)
		errno = mingw_wsa_last_error();
	return res;
}

int
mingw_bind(socket_fd_t sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
	int res;

	/* Initialize the socket layer */
	ONCE_FLAG_RUN(mingw_socket_inited, mingw_socket_init);

	res = bind(sockfd, addr, addrlen);
	if (-1 == res)
		errno = mingw_wsa_last_error();
	return res;
}

socket_fd_t
mingw_connect(socket_fd_t sockfd, const struct sockaddr *addr,
	  socklen_t addrlen)
{
	socket_fd_t res;

	/* Initialize the socket layer */
	ONCE_FLAG_RUN(mingw_socket_inited, mingw_socket_init);

	res = connect(sockfd, addr, addrlen);
	if (INVALID_SOCKET == res) {
		errno = mingw_wsa_last_error();
		/*
		 * We need to remap WSAEWOULDBLOCK, which is translated into EAGAIN
		 * by mingw_wsa_last_error() -- to accomodate send() and other I/O
		 * operations -- to the expected EINPROGRESS for connect() operations.
		 *
		 * On modern UNIX systems, EAGAIN is used to signal that no more
		 * local ports can be auto-assigned for this connection endpoint.
		 * Thereby, returning EAGAIN would send the wrong message.
		 *		--RAM, 2015-04-04.
		 */

		if (EAGAIN == errno)
			errno = EINPROGRESS;
	}
	return res;
}

int
mingw_listen(socket_fd_t sockfd, int backlog)
{
	int res;

	/* Initialize the socket layer */
	ONCE_FLAG_RUN(mingw_socket_inited, mingw_socket_init);

	res = listen(sockfd, backlog);
	if (-1 == res)
		errno = mingw_wsa_last_error();
	return res;
}

socket_fd_t
mingw_accept(socket_fd_t sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
	socket_fd_t res;

	/* Initialize the socket layer */
	ONCE_FLAG_RUN(mingw_socket_inited, mingw_socket_init);

	res = accept(sockfd, addr, addrlen);
	if (INVALID_SOCKET == res)
		errno = mingw_wsa_last_error();
	return res;
}

int
mingw_shutdown(socket_fd_t sockfd, int how)
{
	int res;

	/* Initialize the socket layer */
	ONCE_FLAG_RUN(mingw_socket_inited, mingw_socket_init);

	res = shutdown(sockfd, how);
	if (-1 == res)
		errno = mingw_wsa_last_error();
	return res;
}

#ifdef EMULATE_SOCKETPAIR
static int
socketpair(int domain, int type, int protocol, socket_fd_t sv[2])
{
	socket_fd_t as = INVALID_SOCKET, cs = INVALID_SOCKET, ls = INVALID_SOCKET;
	struct sockaddr_in laddr, caddr;
	socklen_t laddrlen, caddrlen;
	int r;

	if (AF_UNIX != domain) {
		errno = EAFNOSUPPORT;
		return -1;
	}

	if (NULL == sv) {
		errno = EINVAL;
		return -1;
	}

	g_assert_log(SOCK_STREAM == type,
		"%s() only emulates SOCK_STREAM pairs", G_STRFUNC);

	ZERO(&laddr);
	ZERO(&caddr);

	ls = socket(AF_INET, type, protocol);
	if (INVALID_SOCKET == ls) {
		errno = mingw_wsa_last_error();
		return -1;
	}

	laddr.sin_family = AF_INET;
	laddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	laddr.sin_port = 0;

	/*
	 * We're starting a succession of system calls.
	 */

	thread_in_syscall_set(TRUE);

	r = bind(ls, (struct sockaddr *) VARLEN(laddr));
	if (-1 == r)
		goto failed;
	r = listen(ls, 1);
	if (-1 == r)
		goto failed;

	cs = socket(AF_INET, type, protocol);
	if (INVALID_SOCKET == cs)
		goto failed;

	/*
	 * Where do we connect to (the kernel chooses the port)?
	 */

	laddrlen = sizeof laddr;
	r = getsockname(ls, (struct sockaddr *) &laddr, &laddrlen);
	if (-1 == r || laddrlen != sizeof laddr)
		goto failed;

	/*
	 * The following won't block because the listening socket has a backlog
	 * of 1 and the connection will happen "immediately".
	 */

	r = connect(cs, (struct sockaddr *) VARLEN(laddr));
	if (-1 == r)
		goto failed;

	/*
	 * Now that we have a half-opened connection on the listening socket
	 * we can accept without blocking.
	 */

	caddrlen = sizeof caddr;
	as = accept(ls, (struct sockaddr *) &caddr, &caddrlen);
	if (INVALID_SOCKET == as || caddrlen != sizeof caddr)
		goto failed;

	s_close(ls);
	ls = -1;

	/*
	 * Check that the two sockets are indeed connected to each other.
	 */

	r = getsockname(as, (struct sockaddr *) &caddr, &caddrlen);
	if (-1 == r || caddrlen != sizeof caddr)
		goto failed;

	g_assert(caddr.sin_addr.s_addr == laddr.sin_addr.s_addr);
	g_assert(caddr.sin_port == laddr.sin_port);

	sv[0] = cs;
	sv[1] = as;

	thread_in_syscall_set(FALSE);

	return 0;

failed:
	thread_in_syscall_set(FALSE);

	errno = mingw_wsa_last_error();
	if (INVALID_SOCKET != ls)
		s_close(ls);
	if (INVALID_SOCKET != as)
		s_close(as);
	if (INVALID_SOCKET != cs)
		s_close(cs);

	return -1;
}
#endif	/* EMULATE_SOCKETPAIR */

int
mingw_socketpair(int domain, int type, int protocol, socket_fd_t sv[2])
{
	int res;

	/* Initialize the socket layer */
	ONCE_FLAG_RUN(mingw_socket_inited, mingw_socket_init);

	res = socketpair(domain, type, protocol, sv);
#ifndef EMULATE_SOCKETPAIR
	if (-1 == res)
		errno = mingw_wsa_last_error();
#endif
	return res;
}

int
mingw_getsockopt(socket_fd_t sockfd, int level, int optname,
	void *optval, socklen_t *optlen)
{
	int res;

	/* Initialize the socket layer */
	ONCE_FLAG_RUN(mingw_socket_inited, mingw_socket_init);

	res = getsockopt(sockfd, level, optname, optval, optlen);
	if (-1 == res)
		errno = mingw_wsa_last_error();
	return res;
}

int
mingw_setsockopt(socket_fd_t sockfd, int level, int optname,
	  const void *optval, socklen_t optlen)
{
	int res;

	/* Initialize the socket layer */
	ONCE_FLAG_RUN(mingw_socket_inited, mingw_socket_init);

	res = setsockopt(sockfd, level, optname, optval, optlen);
	if (-1 == res)
		errno = mingw_wsa_last_error();
	return res;
}


ssize_t
s_write(socket_fd_t fd, const void *buf, size_t count)
{
	ssize_t res;

	count = MIN(count, UNSIGNED(INT_MAX));
	res = send(fd, buf, count, 0);
	if (-1 == res)
		errno = mingw_wsa_last_error();
	return res;
}

ssize_t
s_read(socket_fd_t fd, void *buf, size_t count)
{
	ssize_t res;

	count = MIN(count, UNSIGNED(INT_MAX));
	res = recv(fd, buf, count, 0);
	if (-1 == res)
		errno = mingw_wsa_last_error();
	return res;
}

int
s_close(socket_fd_t fd)
{
	int res = closesocket(fd);
	if (-1 == res)
		errno = mingw_wsa_last_error();
	fd_notify_socket_closed(fd);
	return res;
}

ssize_t
mingw_recv(socket_fd_t fd, void *buf, size_t len, int recv_flags)
{
	DWORD r, flags = recv_flags;
	iovec_t iov;
	int res;

	iovec_set(&iov, buf, len);

	res = WSARecv(fd, (LPWSABUF) &iov, 1, &r, &flags, NULL, NULL);

	if (res != 0) {
		errno = mingw_wsa_last_error();
		return (ssize_t) -1;
	}
	return (ssize_t) r;
}

ssize_t
mingw_s_readv(socket_fd_t fd, const iovec_t *iov, int iovcnt)
{
	DWORD r, flags = 0;
	int res = WSARecv(fd, (LPWSABUF) iov, iovcnt, &r, &flags, NULL, NULL);

	if (res != 0) {
		errno = mingw_wsa_last_error();
		return (ssize_t) -1;
	}
	return (ssize_t) r;
}

ssize_t
mingw_s_writev(socket_fd_t fd, const iovec_t *iov, int iovcnt)
{
	DWORD w;
	int res = WSASend(fd, (LPWSABUF) iov, iovcnt, &w, 0, NULL, NULL);

	if (res != 0) {
		errno = mingw_wsa_last_error();
		return (ssize_t) -1;
	}
	return (ssize_t) w;
};

#if HAS_WSARECVMSG
/* FIXME: WSARecvMsg is not included in MingW yet */
ssize_t
mingw_recvmsg(socket_fd_t s, struct msghdr *hdr, int flags)
{
	DWORD received;
	WSAMSG msg;
	int res;

	msg.name = hdr->msg_name;
	msg.namelen = hdr->msg_namelen;
	msg.lpBuffers = hdr->msg_iov;
	msg.dwBufferCount = hdr->msg_iovlen;
	msg.Control.len = hdr->msg_controllen;
	msg.Control.buf = hdr->msg_control;
	msg.dwFlags = hdr->msg_flags;

	res = WSARecvMsg(s, &msg, &received, NULL, NULL);
	if (res != 0) {
		errno = mingw_wsa_last_error();
		return -1;
	}
	return received;
}
#endif	/* HAS_WSARECVMSG */

ssize_t
mingw_recvfrom(socket_fd_t s, void *data, size_t len, int flags,
	struct sockaddr *src_addr, socklen_t *addrlen)
{
	DWORD received, dflags = flags;
	WSABUF buf;
	INT ifromLen = *addrlen;
	int res;

	len = MIN(len, UNSIGNED(INT_MAX));
	buf.buf = data;
	buf.len = len;
	res = WSARecvFrom(s, &buf, 1, &received, &dflags,
			src_addr, &ifromLen, NULL, NULL);
	if (0 != res) {
		errno = mingw_wsa_last_error();
		return -1;
	}
	*addrlen = ifromLen;
	/* Not sure about behaviour on truncation */
	g_return_val_if_fail(received <= len, len);
	return received;
}

ssize_t
mingw_sendto(socket_fd_t sockfd, const void *buf, size_t len, int flags,
	  const struct sockaddr *dest_addr, socklen_t addrlen)
{
	ssize_t res;

	len = MIN(len, UNSIGNED(INT_MAX));
	res = sendto(sockfd, buf, len, flags, dest_addr, addrlen);
	if (-1 == res)
		errno = mingw_wsa_last_error();
	return res;
}

/***
 *** Memory allocation routines.
 ***/

static struct {
	void *reserved;			/* Reserved memory */
	void *base;				/* Next available base for reserved memory */
	const void *heap_break;	/* Initial heap break */
	size_t consumed;		/* Consumed space in reserved memory */
	size_t size;			/* Size for hinted allocation */
	size_t later;			/* Size of "later" memory we did not reserve */
	size_t physical;		/* Physical RAM available */
	size_t available;		/* Virtual memory initially available */
	size_t allocated;		/* Memory we allocated */
	size_t baseline;		/* Committed memory at VMM init time */
	bool stop_vfree;		/* VMM no longer freeing allocated memory */
	int hinted;
} mingw_vmm;

/**
 * Called with TRUE when the VMM layer is shutting down, no longer freeing
 * the memory it allocates.
 */
void
mingw_set_stop_vfree(bool val)
{
	mingw_vmm.stop_vfree = val;
}

/**
 * @return the amount of memory (in bytes) already committed by the process.
 */
static size_t
mingw_mem_committed(void)
{
	PROCESS_MEMORY_COUNTERS c;

	if (GetProcessMemoryInfo(GetCurrentProcess(), VARLEN(c)))
		return c.PagefileUsage;

	errno = mingw_last_error();

	s_warning_once_per(LOG_PERIOD_MINUTE,
		"%s(): cannot compute process memory usage: %m", G_STRFUNC);

	/* At least that is known */
	return mingw_vmm.allocated + mingw_vmm.baseline;
}

/**
 * Initialize the VM region we're going to manage through the VMM layer.
 */
static void
mingw_vmm_init(void)
{
	SYSTEM_INFO system_info;
	void *mem_later;
	size_t mem_latersize;
	size_t mem_size;
	size_t mem_available;
	size_t granularity;

	mingw_vmm.baseline = mingw_mem_committed();

	/*
	 * Determine maximum possible memory first
	 *
	 * Don't use GetNativeSystemInfo(), rely on GetSsystemInfo()
	 * so that we get proper results for the 32-bit environment
	 * if running under WOW64.
	 */

	GetSystemInfo(&system_info);

	granularity = round_pagesize(system_info.dwAllocationGranularity);
	granularity = MAX(granularity, VMM_GRANULARITY);	/* Speed up init */

	mingw_vmm.size =
		system_info.lpMaximumApplicationAddress
		-
		system_info.lpMinimumApplicationAddress;

	mingw_vmm.physical = getphysmemsize();
	mingw_vmm.heap_break = vmm_page_start(mingw_sbrk(0));

	/*
	 * Declare some space for future allocations without hinting.
	 * We initially reserve about 80% of the virtual address space,
	 * with VMM_MINSIZE at least but we make sure we have also room
	 * available for non-VMM allocations.
	 */

	mem_size = mingw_vmm.size;		/* For the VMM space, theoretical max */
	mem_latersize = mem_size;		/* For non-hinted allocation */

reserve_less:
	mem_latersize *= 0.9;
	mem_latersize = MAX(mem_latersize, VMM_MINSIZE);
	mingw_vmm.later = mem_latersize;
	mem_later = VirtualAlloc(NULL,
		mem_latersize, MEM_RESERVE, PAGE_NOACCESS);

	if (NULL == mem_later) {
		if (VMM_MINSIZE == mem_latersize) {
			errno = mingw_last_error();
			s_error("could not reserve %s of memory: %m",
				compact_size(mem_latersize, FALSE));
		} else {
			goto reserve_less;
		}
	}

	/*
	 * Try to reserve the remaining virtual space, asking for as
	 * much as we can and reducing the requested size by the
	 * system's granularity until we get a success status.
	 */

	mingw_vmm.size = round_pagesize(mem_size - mem_latersize);

	while (
		NULL == mingw_vmm.reserved && mingw_vmm.size > VMM_MINSIZE
	) {
		mingw_vmm.reserved = VirtualAlloc(
			NULL, mingw_vmm.size, MEM_RESERVE, PAGE_NOACCESS);

		if (NULL == mingw_vmm.reserved)
			mingw_vmm.size -= granularity;
	}

	VirtualFree(mem_later, 0, MEM_RELEASE);

	mem_available = mem_latersize + mingw_vmm.size;
	mingw_vmm.available = mem_available;

	/*
	 * We are trying to balance reserved space within the total available space,
	 * and we can directly compute the value X of the "mem_latersize" we want,
	 * satisfying:
	 *
	 *		available = X + size
	 *		size = 80% * available
	 *
	 * This trivially solves to: X = 20% * available.  The assumption
	 * made here is that the total memory size we computed above as
	 * "mem_available" is going to be constant.
	 *		--RAM, 2015-11-04
	 */

	mem_latersize = 0.2 * mem_available;
	mingw_vmm.later = mem_latersize;
	mingw_vmm.size = mem_available - mem_latersize;

	/*
	 * Now that we know how much we can reserve for the VMM layer,
	 * free everything and redo the VMM reservation so that we let
	 * the kernel pick the highest possible address space, so as to
	 * leave optimal growing space for the other allocators.
	 *		--RAM, 2015-10-16
	 */

	VirtualFree(mingw_vmm.reserved, 0, MEM_RELEASE);

	mingw_vmm.reserved = VirtualAlloc(
		NULL, mingw_vmm.size, MEM_RESERVE, PAGE_NOACCESS);

	if (NULL == mingw_vmm.reserved) {
		s_error("could not reserve %s of memory: %m",
				compact_size(mingw_vmm.size, FALSE));
	}

	mingw_vmm.base = mingw_vmm.reserved;
	mingw_vmm_inited = TRUE;
}

void *
mingw_valloc(void *hint, size_t size)
{
	void *p = NULL;

	if G_UNLIKELY(NULL == hint) {
		if (mingw_vmm.hinted >= 0) {
			static spinlock_t valloc_slk = SPINLOCK_INIT;

			spinlock(&valloc_slk);

			if G_UNLIKELY(NULL == mingw_vmm.reserved)
				mingw_vmm_init();

			if (vmm_is_debugging(0)) {
				s_debug("no hint given for %s allocation #%d",
					compact_size(size, FALSE), mingw_vmm.hinted);
			}

			mingw_vmm.hinted++;
			if G_UNLIKELY(mingw_vmm.consumed + size > mingw_vmm.size) {
				spinunlock(&valloc_slk);
				/* We don't want a stacktrace, use s_minilog() directly */
				s_minilog(G_LOG_LEVEL_CRITICAL,
					"%s(): out of reserved memory for %zu bytes",
					G_STRFUNC, size);
				goto failed;
			}
			p = mingw_vmm.base;
			mingw_vmm.base = ptr_add_offset(mingw_vmm.base, size);
			mingw_vmm.consumed += size;
			spinunlock(&valloc_slk);
		} else {
			/*
			 * Non-hinted request after hinted requests have been used.
			 * Allow usage of non-reserved space.
			 */

			p = VirtualAlloc(NULL, size,
					MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

			if (p == NULL) {
				/* We don't want a stacktrace, use s_minilog() directly */
				errno = mingw_last_error();
				s_minilog(G_LOG_LEVEL_CRITICAL,
					"%s(): cannot allocate %'zu bytes: %m", G_STRFUNC, size);
				goto failed;
			}

			/*
			 * Warn them, since this VM region space will never be released
			 * to the system: the memory will be decomitted when the region
			 * is freed, but the space will be taken, fragmenting the VM space.
			 *		--RAM, 2015-04-06
			 *
			 * When the VMM layer stops freeing memory, it uses NULL hints,
			 * at which point we don't want to warn about non-hinted memory
			 * allocations since we're shutting down!
			 *		--RAM, 2015-04-07
			 *
			 * During crashes, the VMM layer always requests NULL hints.
			 *		--RAM, 2015-10-24
			 *
			 * During pmap extensions, the VMM layer also requests NULL hints.
			 *		--RAM, 2015-11-08
			 */

			if (
				!mingw_vmm.stop_vfree &&
				!vmm_is_extending() &&
				!vmm_is_crashing()
			) {
				s_minicarp("%s(): non-hinted allocation of %'zu bytes at %p",
					G_STRFUNC, size, p);
			}

			goto allocated;
		}
	} else {
		if G_UNLIKELY(mingw_vmm.hinted >= 0) {
			mingw_vmm.hinted = -1;	/* Can now handle non-hinted allocs */
			atomic_mb();
		}
		p = hint;
	}

	p = VirtualAlloc(p, size, MEM_COMMIT, PAGE_READWRITE);

	if (p == NULL) {
		/* We don't want a stacktrace, use s_minilog() directly */
		errno = mingw_last_error();
		s_minilog(G_LOG_LEVEL_CRITICAL,
			"%s(): failed to commit %'zu bytes at %p: %m",
			G_STRFUNC, size, hint);

		/*
		 * If errno is EFAULT and the hint was not NULL, then it means we have
		 * selected an address that lies too close to the end of the initially
		 * reserved memory segment, and it cannot be fully committed by the
		 * kernel.
		 *		--RAM, 2015-04-06
		 */

		if (hint != NULL && EFAULT == errno) {
			/*
			 * In order to allow the process to continue, we're going to try
			 * to allocate memory outside our reserved region.  If we can,
			 * we request a clean application restart.  Otherwise, we'll let
			 * our caller handle the situation since there is nothing else
			 * we can do from down here.
			 *		--RAM, 2015-04-06
			 */

			p = VirtualAlloc(NULL, size,
					MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

			if (p != NULL) {
				crash_restart("%s(): had to allocate %'zu bytes "
					"outside reserved region at %p", G_STRFUNC, size, p);
				goto allocated;
			}

			/* FALL THROUGH, p is still NULL */
		}

		goto failed;
	}

	/* FALL THROUGH */

allocated:
	mingw_vmm.allocated += size;
	return p;

failed:
	errno = ENOMEM;		/* Expected errno value from VMM layer */
	return MAP_FAILED;
}

int
mingw_vfree(void *addr, size_t size)
{
	(void) addr;
	(void) size;

	/*
	 * VMM hint should always be respected. So this function should not
	 * be reached from VMM, except when we are out-of-memory and
	 * mingw_valloc() tried to allocate outside the reserved region.
	 *
	 * Since we also tell the VMM layer on Windows to avoid testing to see
	 * whether we're hitting "foreign" regions, this routine still can never
	 * be called.
	 */

	s_error("%s(): should not be called on Windows", G_STRFUNC);
}

int
mingw_vfree_fragment(void *addr, size_t size)
{
	void *end = ptr_add_offset(mingw_vmm.reserved, mingw_vmm.size);

	g_assert_log(mingw_vmm.allocated >= size,
		"%s(): attempt to free unallocated memory (%'zu bytes at %p): "
			"has total of %'zu allocated bytes",
		G_STRFUNC, size, addr, mingw_vmm.allocated);

	mingw_vmm.allocated -= size;

	if (ptr_cmp(mingw_vmm.reserved, addr) <= 0 && ptr_cmp(end, addr) > 0) {
		/* Allocated in reserved space */
		if (!VirtualFree(addr, size, MEM_DECOMMIT)) {
			errno = mingw_last_error();
			return -1;
		}
	} else {
		/*
		 * Now  that we have emergency allocations, we can no longer use
		 * MEM_RELEASE, even if the region is not in the (initially)
		 * non-reserved space.  The reason is that we would have to
		 * use:
		 *
		 *		VirtualFree(addr, 0, MEM_RELEASE)
		 *
		 * (i.e. pass 0 as the size parameter) and that would decommit
		 * and release the *whole range* starting at addr.  But because of
		 * the way the VMM layer works and keeps track of allocated regions,
		 * they can be coalesced and we cannot ensure we're not going to
		 * start freeing region A, that happens to be adjacent to region B,
		 * and passing the start of region A would release region B as well!
		 *
		 * To avoid this, memory allocated outside the reserved region is
		 * never released, only decommitted.
		 */

		/* Allocated in non-reserved space */
		if (!VirtualFree(addr, size, MEM_DECOMMIT)) {
			errno = mingw_last_error();
			return -1;
		}
	}

	return 0;
}

int
mingw_mprotect(void *addr, size_t len, int prot)
{
	DWORD oldProtect = 0;
	DWORD newProtect;
	BOOL res;

	/*
	 * The PROT_GUARD is specific to Windows and is convenient to create
	 * red-pages in stacks to detect overflows: given Windows does not
	 * support an alternate signal stack, there is no way we could easily
	 * detect a stack overflow without it and still be able to process it.
	 *
	 * A guard page will simply be protected as PROT_NONE but read-write
	 * access will be restored after the first fault on it, which generates
	 * an exception of type EXCEPTION_GUARD_PAGE.
	 *
	 *		--RAM, 2015-11-09
	 */

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
	case PROT_GUARD:
		newProtect = PAGE_READWRITE | PAGE_GUARD;
		break;
	default:
		s_critical("%s(): unsupported protection flags 0x%x", G_STRFUNC, prot);
		res = EINVAL;
		return -1;
	}

	res = VirtualProtect((LPVOID) addr, len, newProtect, &oldProtect);
	if (!res) {
		errno = mingw_last_error();
		if (vmm_is_debugging(0)) {
			s_debug("VMM mprotect(%p, %zu) failed: errno=%m", addr, len);
		}
		return -1;
	}

	return 0;	/* OK */
}

/**
 * Log memory information about the memory region to which an address belongs.
 *
 * This is only useful when debugging problems on Windows at the lowest
 * possible level.
 *
 * @param p		the address for which we want information
 */
void
mingw_log_meminfo(const void *p)
{
	MEMORY_BASIC_INFORMATION mbi;
	size_t res;

	ZERO(&mbi);

	res = VirtualQuery(p, VARLEN(mbi));
	if (0 == res) {
		errno = mingw_last_error();
		s_rawwarn("VirtualQuery() failed for %p: %m", p);
	} else {
		s_rawdebug("VirtualQuery(%p):", p);
		s_rawdebug("\tBaseAddress: %p", mbi.BaseAddress);
		s_rawdebug("\tAllocationBase: %p", mbi.AllocationBase);
		s_rawdebug("\tRegionSize: %'lu", mbi.RegionSize);
		s_rawdebug("\tAllocationProtect: 0x%lx", mbi.AllocationProtect);
	}
}

/**
 * Compute the allocation start of a memory region.
 *
 * @param p		a pointer in the region for which we want the start
 *
 * @return the start of the allocated region, NULL if we cannot figure it out.
 */
void *
mingw_memstart(const void *p)
{
	MEMORY_BASIC_INFORMATION mbi;
	size_t res;
	void *base = NULL;

	ZERO(&mbi);

	res = VirtualQuery(p, VARLEN(mbi));
	if (0 == res) {
		errno = mingw_last_error();
		s_rawwarn("%s(): VirtualQuery() failed for %p: %m", G_STRFUNC, p);
	} else {
		base = mbi.AllocationBase;
	}

	return base;
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
		errno = mingw_last_error();
		return 0;
	}

	memset(buf, 0, len);
	if (!CryptGenRandom(crypth, len, buf)) {
		errno = mingw_last_error();
		len = 0;
	}
	CryptReleaseContext(crypth, 0);

	return (int) len;
}

/***
 *** Miscellaneous.
 ***/

const char *
mingw_strerror(int errnum)
{
	const char *msg;
	buf_t *b;
	char *p;

	/*
	 * We have one global "errno" but conflicting ranges for errors: the
	 * POSIX ones defined in MinGW overlap with some of the Windows error
	 * codes.
	 *
	 * Because our code is POSIX, we strive to remap these conflicting codes
	 * to POSIX values and naturally provide our own strerror() for the
	 * POSIX errors.
	 */

	msg = english_strerror(errnum);
	if (msg != NULL)
		return msg;

	b = buf_private(G_STRFUNC, 1024);
	p = buf_data(b);

	FormatMessage(
        FORMAT_MESSAGE_FROM_SYSTEM,
        NULL, errnum,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPTSTR) p, buf_size(b), NULL);

	strchomp(p, 0);		/* Remove final "\r\n" */
	return p;
}

int
mingw_rename(const char *oldpathname, const char *newpathname)
{
	pncs_t pncs;
	int res;
	wchar_t *old_utf16;

	if (pncs_convert(&pncs, oldpathname))
		return -1;

	old_utf16 = pncs_dup(&pncs);	/* pncs_convert() returns static data */

	if (pncs_convert(&pncs, newpathname)) {
		res = -1;
		goto done;		/* errno already set */
	}

	/*
	 * FIXME: Try to rename a file with SetFileInformationByHandle
	 * and FILE_INFO_BY_HANDLE_CLASS
	 */

	if (MoveFileExW(old_utf16, pncs.utf16, MOVEFILE_REPLACE_EXISTING)) {
		res = 0;
	} else {
		errno = mingw_last_error();
		res = -1;
	}

done:
	hfree(old_utf16);
	return res;
}

FILE *
mingw_fopen(const char *pathname, const char *mode)
{
	pncs_t wpathname;
	char bin_mode[14];
	wchar_t wmode[32];
	FILE *res;

	if (NULL == vstrchr(mode, 'b')) {
		int l = clamp_strcpy(ARYLEN(bin_mode) - 2, mode);
		bin_mode[l++] = 'b';
		bin_mode[l] = '\0';
		mode = bin_mode;
	}

	if (pncs_convert(&wpathname, pathname))
		return NULL;

	if (
		!is_ascii_string(mode) ||
		utf8_to_utf16(mode, wmode, N_ITEMS(wmode)) >=
			N_ITEMS(wmode)
	) {
		errno = EINVAL;
		return NULL;
	}

	res = _wfopen(wpathname.utf16, wmode);
	if (NULL == res)
		errno = mingw_last_error();

	return res;
}

/**
 * Special version of freopen() to be used when re-opening files for writing.
 *
 * Blindly using freopen() opens the file with exclusive access, which
 * prevents opening the file to inspect it whilst the program runs.
 *
 * So we use a different strategy by going deeper into the Windows API to
 * open the file with shared access, and then we just change the file
 * descriptor of the file structure to use our new descriptor.
 *
 * @param wpathname		the wpathname.utf16 is the wide-char pathname
 * @param flags			O_XXX read/write/trunc/append flags
 * @param file			the existing FILE we want to redirect to wpathname
 *
 * @return TRUE on success.
 */
static bool
mingw_write_redirect(pncs_t wpathname, int flags, FILE *file)
{
	HANDLE h;
	int fd, r;
	DWORD mode = 0;

	/* Assert they are flags, not values we cannot combine */
	STATIC_ASSERT(3 == (O_RDWR | O_WRONLY | O_RDONLY));

	if (flags & (O_RDWR | O_WRONLY))
		mode |= GENERIC_WRITE;

	if (flags & (O_RDWR | O_RDONLY))
		mode |= GENERIC_READ;

	if (flags & O_APPEND)
		mode |= FILE_APPEND_DATA;

	h = CreateFileW(wpathname.utf16, mode,
			FILE_SHARE_READ | FILE_SHARE_WRITE,
			NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

	if (INVALID_HANDLE_VALUE == h)
		return FALSE;

	if (flags & O_TRUNC)
		SetEndOfFile(h);

	/*
	 * According to MSDN, the only flags interesting here are O_APPEND and
	 * O_RDONLY.  Limit to those then.
	 */

	fd = _open_osfhandle((intptr_t) h, flags & (O_APPEND | O_RDONLY));
	if (-1 == fd) {
		CloseHandle(h);
		return FALSE;
	}

	r = mingw_dup2(fd, fileno(file));	/* replaces old fd in `file' */
	close(fd);

	if (-1 == r) {
		/* Should already be taken care of by close(fd) if dup2() failed */
		CloseHandle(h);
		return FALSE;
	}

	return TRUE;
}

FILE *
mingw_freopen(const char *pathname, const char *mode, FILE *file)
{
	pncs_t wpathname;
	char bin_mode[14];
	wchar_t wmode[32];
	int flags = 0;
	FILE *res;

	if (pncs_convert(&wpathname, pathname))
		return NULL;

	if (NULL == vstrchr(mode, 'b')) {
		int l = clamp_strcpy(ARYLEN(bin_mode) - 2, mode);
		bin_mode[l++] = 'b';
		bin_mode[l] = '\0';
		mode = bin_mode;
	}

	if (
		!is_ascii_string(mode) ||
		utf8_to_utf16(mode, wmode, N_ITEMS(wmode)) >=
			N_ITEMS(wmode)
	) {
		errno = EINVAL;
		return NULL;
	}

	/*
	 * Analyze the reopen flags to determine how the file will be
	 * written to, in case we have to handle it manually.
	 */

	if (NULL != vstrchr(mode, 'a')) {
		if (NULL != vstrstr(mode, "a+"))
			flags |= O_RDWR | O_APPEND;
		else
			flags |= O_WRONLY | O_APPEND;
	}

	if (NULL != vstrchr(mode, 'w')) {
		if (NULL != vstrstr(mode, "w+"))
			flags |= O_RDWR | O_TRUNC;
		else
			flags |= O_WRONLY | O_TRUNC;
	}

	if (NULL != vstrchr(mode, 'r')) {
		if (NULL != vstrstr(mode, "r+"))
			flags |= O_RDWR;
		else
			flags |= O_RDONLY;
	}

	/*
	 * Handle re-opening for writing specially to avoid exclusive access
	 * preventing concurrent reads.
	 */

	if (flags & (O_WRONLY | O_RDWR)) {
		/* Writing to file, use special version */
		if (mingw_write_redirect(wpathname, flags, file)) {
			res = file;
		} else {
			errno = mingw_last_error();
			res = NULL;
		}
	} else {
		/* No writing, let the default Windows behaviour apply */
		res = _wfreopen(wpathname.utf16, wmode, file);
		if (NULL == res)
			errno = mingw_last_error();
	}

	return res;
}

int
mingw_statvfs(const char *pathname, struct mingw_statvfs *buf)
{
	BOOL ret;
	DWORD SectorsPerCluster;
	DWORD BytesPerSector;
	DWORD NumberOfFreeClusters;
	DWORD TotalNumberOfClusters;
	DWORD MaxComponentLength;
	DWORD FileSystemFlags;
	wchar_t vname[256];
	wchar_t mountp[MAX_PATH_LEN];
	pncs_t pncs;
	const wchar_t *root;
	char volume[256];

	if (pncs_convert(&pncs, pathname))
		return -1;

	ret = GetDiskFreeSpaceW(pncs.utf16,
		&SectorsPerCluster, &BytesPerSector,
		&NumberOfFreeClusters,
		&TotalNumberOfClusters);

	if (!ret) {
		errno = mingw_last_error();
		return -1;
	}

	ZERO(buf);

	buf->f_bsize = SectorsPerCluster * BytesPerSector;
	buf->f_frsize = buf->f_bsize;
	buf->f_blocks = TotalNumberOfClusters;
	buf->f_bfree = NumberOfFreeClusters;
	buf->f_bavail = NumberOfFreeClusters;
	buf->f_namemax = FILENAME_MAX;		/* From <stdio.h> */

	ZERO(&mountp);

	ret = GetVolumePathNameW(pncs.utf16, mountp, N_ITEMS(mountp));
	root = ret ? mountp : pncs.utf16;

	ZERO(&vname);

	ret = GetVolumeInformationW(root,
		vname, N_ITEMS(vname),		/* VolumeName{Buffer,Size} */
		NULL,							/* VolumeSerialNumber */
		&MaxComponentLength,			/* MaximumComponentLength */
		&FileSystemFlags,				/* FileSystemFlags */
		NULL, 0);						/* FileSystemName{Buffer,Size} */

	if (ret) {
		if (FileSystemFlags & FILE_READ_ONLY_VOLUME)
			buf->f_flag |= ST_RDONLY;
		buf->f_namemax = MaxComponentLength;

		/*
		 * All we want is a stable file system ID, so we hash the volume name.
		 */

		utf16_to_utf8(vname, volume, N_ITEMS(volume));
		volume[N_ITEMS(volume) - 1] = '\0';
		buf->f_fsid = string_mix_hash(volume);
	}

	return 0;
}

#ifdef EMULATE_GETRLIMIT
/**
 * Get process resource limits.
 */
int
mingw_getrlimit(int resource, struct rlimit *rlim)
{
	switch (resource) {
	case RLIMIT_CORE:
		ZERO(rlim);
		break;
	case RLIMIT_DATA:
		if G_LIKELY(mingw_vmm_inited) {
			/*
			 * Assume the data segment (heap) will grow up to the start
			 * of the reserved region we have, since now that region is
			 * put at the lowest possible address.  This only approximates
			 * the truth.
			 *		--RAM, 2015-10-16
			 */
			rlim->rlim_max = ptr_diff(mingw_vmm.reserved, mingw_vmm.heap_break);
			rlim->rlim_cur = ptr_diff(mingw_vmm.reserved, mingw_sbrk(0));
			break;
		}
		/* FALL THROUGH */
	case RLIMIT_AS:
		{
			SYSTEM_INFO system_info;

			GetSystemInfo(&system_info);
			rlim->rlim_max =
				system_info.lpMaximumApplicationAddress
				-
				system_info.lpMinimumApplicationAddress;
			rlim->rlim_cur = rlim->rlim_max -
				size_saturate_sub(mingw_mem_committed(), mingw_vmm.baseline);
		}
		break;
	default:
		errno = ENOTSUP;
		return -1;
	}

	return 0;
}
#endif /* EMULATE_GETRLIMIT */

#ifdef EMULATE_SCHED_YIELD
/**
 * Cause the calling thread to relinquish the CPU.
 */
int
mingw_sched_yield(void)
{
	Sleep(0);
	return 0;
}
#endif	/* EMULATE_SCHED_YIELD */

#ifdef EMULATE_GETRUSAGE
/**
 * Convert a FILETIME into a timeval.
 *
 * @param ft		the FILETIME structure to convert
 * @param tv		the struct timeval to fill in
 * @param offset	offset to substract to the FILETIME value
 */
static void
mingw_filetime_to_timeval(const FILETIME *ft, struct timeval *tv, uint64 offset)
{
	uint64 v;

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

	v = UINT64_VALUE(ft->dwHighDateTime, ft->dwLowDateTime) / 10;
	v -= offset;
	tv->tv_usec = v % TM_MILLION;
	v /= TM_MILLION;
	/* If time_t is a 32-bit integer, there could be an overflow */
	tv->tv_sec = MIN(v, UNSIGNED(MAX_INT_VAL(time_t)));
}

int
mingw_getrusage(int who, struct rusage *usage)
{
	if (NULL == usage) {
		errno = EACCES;
		return -1;
	}

	ZERO(usage);

	switch (who) {
	case RUSAGE_SELF:
		{
			FILETIME creation_time, exit_time, kernel_time, user_time;

			if (
				0 == GetProcessTimes(GetCurrentProcess(),
					&creation_time, &exit_time, &kernel_time, &user_time)
			) {
				errno = mingw_last_error();
				return -1;
			}

			mingw_filetime_to_timeval(&user_time, &usage->ru_utime, 0);
			mingw_filetime_to_timeval(&kernel_time, &usage->ru_stime, 0);
		}
		break;
	case RUSAGE_CHILDREN:
		spinlock(&mingw_child_time_slk);

		mingw_filetime_to_timeval(&mingw_child_user_time, &usage->ru_utime, 0);
		mingw_filetime_to_timeval(&mingw_child_kern_time, &usage->ru_stime, 0);

		spinunlock(&mingw_child_time_slk);
		break;
	case RUSAGE_THREAD:
		errno = ENOSYS;
		return -1;
	default:
		errno = EINVAL;
		return -1;
	}

	return 0;
}
#endif	/* EMULATE_GETRUSAGE */

const char *
mingw_getlogin(void)
{
	static char buf[128];
	static char *result;
	static bool inited;
	DWORD size;

	if (G_LIKELY(inited))
		return result;

	size = sizeof buf;
	result = 0 == GetUserName(buf, &size) ? NULL : buf;

	inited = TRUE;
	return result;
}

/**
 * Extract SID (Security IDentifier) from the specified token.
 *
 * The extracted SID is stored in ``sid_ptr'' and must be xfree()'ed
 * by the caller when it is done with it.
 *
 * @param token		the token handle
 * @param which		the information class we want from the token
 * @param sid_ptr	where allocated SID will be stored
 *
 * @return TRUE if ok and we allocated a new SID, FALSE otherwise.
 */
static bool
mingw_token_sid(HANDLE token, TOKEN_INFORMATION_CLASS which, SID **sid_ptr)
{
	DWORD len, needed = 0;
	void *data = NULL;
	SID *tsid, *sid = NULL;

	if (NULL == token || INVALID_HANDLE_VALUE == token)
		return FALSE;

	GetTokenInformation(token, which, NULL, 0, &needed);
	if (0 == needed)
		return FALSE;

	len = needed;
	data = xmalloc0(len);

	if (!GetTokenInformation(token, which, data, len, &needed) || needed > len)
		goto failed;

	switch (which) {
	case TokenUser:
		{
			TOKEN_USER *u = data;
			tsid = u->User.Sid;
		}
		break;
	case TokenPrimaryGroup:
		{
			TOKEN_PRIMARY_GROUP *g = data;
			tsid = g->PrimaryGroup;
		}
		break;
	default:
		s_rawwarn("%s(): unexpected token class %d", G_STRFUNC, which);
		goto failed;
	}

	len = GetLengthSid(tsid);
	sid = xmalloc(len);
	if (!CopySid(len, sid, tsid) || !IsValidSid(sid))
		goto failed;

	xfree(data);
	*sid_ptr = sid;		/* Caller will need to xfree() this once done */

	return TRUE;

failed:
	XFREE_NULL(sid);
	XFREE_NULL(data);
	return FALSE;
}

/**
 * Extract the last relative identifier (RID) authority from a SID and free
 * that SID.
 */
static ulong
mingw_token_sid_last_rid_free(SID *sid)
{
	ulong rid, *rp;
	uint8 n, *np;

	g_assert(IsValidSid(sid));

	/*
	 * From MSDN:
	 *
	 * Standardized string notation for SIDs, making it simpler to visualize
	 * their components:
	 *
	 *     S-R-I-X#
	 *
	 * In this notation, the literal character "S" identifies the following
	 * series of digits as a SID, R is the revision level, I is the
	 * identifier-authority value, and X# is one or more subauthority values.
	 *
	 * For instance, a SID string could be: "S-1-5-32-544", meaning:
	 *
	 * - A revision level of 1
	 * - An identifier-authority value of 5 (SECURITY_NT_AUTHORITY)
	 * - A first subauthority value of 32 (SECURITY_BUILTIN_DOMAIN_RID)
	 * - A second subauthority value of 544 (DOMAIN_ALIAS_RID_ADMINS)
	 *
	 * A SID must contain a top-level authority and at least one relative
	 * identifier (RID) value.
	 */

	np = GetSidSubAuthorityCount(sid);
	n = *np;
	rp = GetSidSubAuthority(sid, n - 1);
	rid = *rp;
	xfree(sid);

	return rid;
}

static uid_t
mingw_token_uid(HANDLE token)
{
	SID *sid = NULL;
	bool ok;

	ok = mingw_token_sid(token, TokenUser, &sid);
	if (!ok)
		return UID_NOBODY;

	return (uid_t) mingw_token_sid_last_rid_free(sid);
}

static gid_t
mingw_token_gid(HANDLE token)
{
	SID *sid = NULL;
	bool ok;

	ok = mingw_token_sid(token, TokenPrimaryGroup, &sid);
	if (!ok)
		return GID_NOBODY;

	return (gid_t) mingw_token_sid_last_rid_free(sid);
}

/**
 * Get the effective security token, which must get closed by caller when done.
 */
static HANDLE
mingw_get_effective_token(void)
{
	HANDLE t = GetCurrentThread();
	HANDLE token = NULL;
	const int flags = TOKEN_READ | TOKEN_QUERY_SOURCE;
	bool ok;

	ok = OpenThreadToken(t, flags, FALSE, &token);
	if (!ok) {
		if (ERROR_NO_TOKEN != GetLastError())
			goto failed;
		ok = OpenThreadToken(t, flags, TRUE, &token);
	}
	if (!ok) {
		if (ERROR_NO_TOKEN != GetLastError())
			goto failed;
		ok = OpenProcessToken(GetCurrentProcess(), flags, &token);
	}
	if (!ok)
		goto failed;

	return token;

failed:
	errno = mingw_last_error();
	s_rawwarn("%s(): can't open thread/process token:  %m", G_STRFUNC);
	return NULL;
}

/**
 * Get the process security token, which must get closed by caller when done.
 */
static HANDLE
mingw_get_token(void)
{
	HANDLE p = GetCurrentProcess();
	HANDLE token = NULL;
	bool ok;

	ok = OpenProcessToken(p, TOKEN_READ | TOKEN_QUERY_SOURCE, &token);
	if (!ok) {
		errno = mingw_last_error();
		s_rawwarn("%s(): can't open process token: %m", G_STRFUNC);
		return NULL;
	}

	return token;
}

uid_t
mingw_getuid(void)
{
	HANDLE token;
	uid_t id;

	token = mingw_get_token();
	if (NULL == token)
		return UID_NOBODY;

	id = mingw_token_uid(token);
	CloseHandle(token);

	return id;
}

uid_t
mingw_geteuid(void)
{
	HANDLE token;
	uid_t id;

	token = mingw_get_effective_token();
	if (NULL == token)
		return UID_NOBODY;

	id = mingw_token_uid(token);
	CloseHandle(token);

	return id;
}

gid_t
mingw_getgid(void)
{
	HANDLE token;
	gid_t id;

	token = mingw_get_token();
	if (NULL == token)
		return GID_NOBODY;

	id = mingw_token_gid(token);
	CloseHandle(token);

	return id;
}

gid_t
mingw_getegid(void)
{
	HANDLE token;
	uid_t id;

	token = mingw_get_effective_token();
	if (NULL == token)
		return GID_NOBODY;

	id = mingw_token_gid(token);
	CloseHandle(token);

	return id;
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

/**
 * Compute the system processor architecture, once.
 */
static int
mingw_proc_arch(void)
{
	static SYSTEM_INFO system_info;
	static bool done;

	if (done)
		return system_info.wProcessorArchitecture;

	done = TRUE;
	GetNativeSystemInfo(&system_info);
	return system_info.wProcessorArchitecture;
}


#ifdef EMULATE_UNAME
int
mingw_uname(struct utsname *buf)
{
	OSVERSIONINFO osvi;
	DWORD len;
	const char *cpu;

	ZERO(buf);

	cstr_bcpy(ARYLEN(buf->sysname), "Windows");

	switch (mingw_proc_arch()) {
	case PROCESSOR_ARCHITECTURE_AMD64:	cpu = "x64"; break;
	case PROCESSOR_ARCHITECTURE_IA64:	cpu = "ia64"; break;
	case PROCESSOR_ARCHITECTURE_INTEL:	cpu = "x86"; break;
	default:							cpu = "unknown"; break;
	}
	cstr_bcpy(ARYLEN(buf->machine), cpu);

	osvi.dwOSVersionInfoSize = sizeof osvi;
	if (GetVersionEx(&osvi)) {
		str_bprintf(ARYLEN(buf->release), "%u.%u",
			(unsigned) osvi.dwMajorVersion, (unsigned) osvi.dwMinorVersion);
		str_bprintf(ARYLEN(buf->version), "%u %s",
			(unsigned) osvi.dwBuildNumber, osvi.szCSDVersion);
	}

	len = sizeof buf->nodename;
	GetComputerName(buf->nodename, &len);

	return 0;
}
#endif	/* EMULATE_UNAME */

#ifdef EMULATE_NANOSLEEP
int
mingw_nanosleep(const struct timespec *req, struct timespec *rem)
{
	static struct thread_timer {
		HANDLE timer;
		atomic_lock_t lock;
	} thread_timer[THREAD_MAX];
	static uint idx;
	uint i;
	struct thread_timer *tt;
	HANDLE t;
	LARGE_INTEGER dueTime;
	uint64 value;
	ulong r;

	/*
	 * There's no residual time, there cannot be early terminations.
	 */

	if (NULL != rem) {
		rem->tv_sec = 0;
		rem->tv_nsec = 0;
	}

	if (0 == req->tv_sec && 0 == req->tv_nsec)
		return 0;

	if (req->tv_sec < 0 || req->tv_nsec < 0 || req->tv_nsec > 999999999L) {
		errno = EINVAL;
		return -1;
	}

	/*
	 * On UNIX, nanosleep() is a system call but it is not on Windows.
	 * Therefore we need to clear the "in syscall" state for now, until
	 * we are ready to block, waiting for the timer to expire.
	 */

	thread_in_syscall_reset();

	/*
	 * We need one timer per thread, but since nanosleep() is called by
	 * spinlock_loop() indirectly through compat_sleep_ms(), we have to
	 * manage this expectation specially.
	 *
	 * Since a given thread can only wait once at a time, we have a rotating
	 * array of existing timers, one per thread at most and we rotate
	 * atomically each time.
	 *
	 * Each timer is locked using a low-level lock (since we cannot recurse
	 * into the spinlock code).
	 */

	for (i = 0; i < 1000; i++) {
		uint j, k;
		for (k = 0, j = atomic_uint_inc(&idx); k < THREAD_MAX; k++, j++) {
			tt = &thread_timer[j % THREAD_MAX];
			if (atomic_acquire(&tt->lock))
				goto found;
		}
	}

	s_minierror("%s() unable to get a timer", G_STRFUNC);

found:

	t = tt->timer;

	if (G_UNLIKELY(NULL == t)) {
		t = CreateWaitableTimer(NULL, TRUE, NULL);

		if (NULL == t) {
			atomic_release(&tt->lock);
			s_carp("unable to create waitable timer, ignoring nanosleep()");
			errno = ENOMEM;		/* System problem anyway */
			return -1;
		}

		tt->timer = t;
	}

	/*
	 * For Windows, the time specification unit is 100 nsec.
	 * We therefore round up the amount of nanoseconds to the nearest value.
	 * Negative values indicate relative time.
	 */

	value = uint64_saturate_add(
				uint64_saturate_mult(req->tv_sec, TM_MILLION * 10UL),
				(req->tv_nsec + 99) / 100);
	dueTime.QuadPart = -MIN(value, MAX_INT_VAL(int64));

	if (0 == SetWaitableTimer(t, &dueTime, 0, NULL, NULL, FALSE)) {
		atomic_release(&tt->lock);
		errno = mingw_last_error();
		s_carp("could not set timer, unable to nanosleep(): %m");
		return -1;
	}

	thread_in_syscall_set(TRUE);
	r = WaitForSingleObject(t, INFINITE);
	thread_in_syscall_set(FALSE);

	if (WAIT_OBJECT_0 != r) {
		atomic_release(&tt->lock);
		errno = mingw_last_error();
		s_carp("timer returned an unexpected value, nanosleep() failed: %m");
		errno = EINTR;
		return -1;
	}

	atomic_release(&tt->lock);
	return 0;
}
#endif

/*
 * Check whether a given PID could be sent a signal with kill(pid, 0), would
 * Windows support such a system call.

 * @return 0 on success, -1 on failure.
 *
 * If it returns -1, errno is set to indicate why process PID cannot be
 * queried: ESRCH when process does not exist, EPERM when it exists but cannot
 * be accessed by the user.
 */
int
mingw_process_accessible(pid_t pid)
{
	HANDLE p;
	int res = -1;

	p = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
	if (NULL == p) {
		errno = mingw_last_error();
		/*
		 * Remap our POSIX error codes to that of what kill(pid, 0)
		 * would return on UNIX.  We skip EINVAL, since that is only
		 * used by kill() when an invalid signal is passed, which is
		 * irrelevant here!
		 */
		if (EINVAL == errno)		/* When PID does not exist */
			errno = ESRCH;			/* we want ESRCH to be returned */
		else if (EACCES == errno)	/* When process cannot be queried */
			errno = EPERM;			/* we want EPERM to be returned */
		else {
			s_carp_once("%s(): unexpected error: %m", G_STRFUNC);
			errno = EPERM;			/* Assume process exists */
		}
	} else {
		/*
		 * Make sure Windows returns a handle to the PID we asked -- it has
		 * a tendency to sometimes open a process that bear a PID that is
		 * slightly less to the one requested when the requested PID does
		 * not exist!
		 */

		if (GetProcessId(p) == UNSIGNED(pid))
			res = 0;
		else
			errno = ESRCH;

		/*
		 * Also make sure the process is still running and is not in a
		 * zombie state.
		 */

		if (0 == res) {
			DWORD code;

			if (GetExitCodeProcess(p, &code) && STILL_ACTIVE != code) {
				res = -1;
				errno = ESRCH;		/* Process is a zombie */
			}
		}

		CloseHandle(p);
	}

	return res;
}

long
mingw_cpu_count(void)
{
	static long result;
	SYSTEM_INFO system_info;

	if G_UNLIKELY(0 == result) {
		GetSystemInfo(&system_info);
		result = system_info.dwNumberOfProcessors;
		g_assert(result > 0);
	}
	return result;
}

uint64
mingw_cpufreq(enum mingw_cpufreq freq)
{
	unsigned long cpus = mingw_cpu_count();
	PROCESSOR_POWER_INFORMATION *p, powarray[16];
	size_t len;
	uint64 result = 0;

	len = size_saturate_mult(cpus, sizeof *p);
	if (cpus <= N_ITEMS(powarray)) {
		p = powarray;
	} else {
		p = walloc(len);
	}

	if (0 == CallNtPowerInformation(ProcessorInformation, NULL, 0, p, len)) {
		/* FIXME: In case of mulitple CPUs (or cores?) they can likely
		 *		  have different values especially for the current freq
		 */
		switch (freq) {
		case MINGW_CPUFREQ_CURRENT:
			/* Convert to Hz */
			result = uint64_saturate_mult(p[0].CurrentMhz, TM_MILLION);
			break;
		case MINGW_CPUFREQ_MAX:
			/* Convert to Hz */
			result = uint64_saturate_mult(p[0].MaxMhz, TM_MILLION);
			break;
		}
	}

	if (p != powarray)
		wfree(p, len);

	return result;
}

/**
 * Get special folder path.
 *
 * @note
 * Our caller handles the caching so that it is guaranteed that we will be
 * called just once per folder type.
 */
static const char *
mingw_get_folder_basepath(enum special_folder folder)
{
	const char *special_path = NULL;

	switch (folder) {
	case PRIVLIB_PATH:
		special_path = mingw_filename_nearby(
			"share" G_DIR_SEPARATOR_S PACKAGE);
		goto done;
	case NLS_PATH:
		special_path = mingw_filename_nearby(
			"share" G_DIR_SEPARATOR_S "locale");
		goto done;
	case SPECIAL_FOLDER_COUNT:
		g_assert_not_reached();
	}

	s_carp("%s() needs implementation for foldertype %d", G_STRFUNC, folder);

done:
	return special_path;
}

/**
 * Build pathname of file located nearby our executable.
 *
 * @return pointer to static data.
 */
const char *
mingw_filename_nearby(const char *filename)
{
	buf_t *b = buf_private(G_STRFUNC, MAX_PATH_LEN);
	char *pathname = buf_data(b);
	static size_t offset;
	static spinlock_t nearby_slk = SPINLOCK_INIT;

	spinlock_hidden(&nearby_slk);	/* Protect access to static vars */

	if ('\0' == pathname[0]) {
		static wchar_t wpathname[MAX_PATH_LEN];
		bool error = FALSE;
		size_t pathsz = buf_size(b);

		if (0 == GetModuleFileNameW(NULL, ARYLEN(wpathname))) {
			error = TRUE;
			errno = mingw_last_error();
			s_warning("cannot locate my executable: %m");
		} else {
			size_t conv = utf16_to_utf8(wpathname, pathname, pathsz);
			if (conv > pathsz) {
				error = TRUE;
				s_carp("%s: cannot convert UTF-16 path into UTF-8", G_STRFUNC);
			}
		}

		if (error)
			cstr_bcpy(pathname, buf_size(b), G_DIR_SEPARATOR_S);

		offset = filepath_basename(pathname) - pathname;
	}

	clamp_strcpy(&pathname[offset], buf_size(b) - offset, filename);

	spinunlock_hidden(&nearby_slk);

	return pathname;
}

/**
 * Check whether there is pending data for us to read on a pipe.
 */
static bool
mingw_fifo_pending(int fd)
{
	HANDLE h = (HANDLE) _get_osfhandle(fd);
	DWORD pending;

	if (INVALID_HANDLE_VALUE == h)
		return FALSE;

	if (0 == PeekNamedPipe(h, NULL, 0, NULL, &pending, NULL)) {
		errno = mingw_last_error();
		if (EPIPE == errno)
			return TRUE;		/* Let them read EOF */
		s_warning("peek failed for fd #%d: %m", fd);
		return FALSE;
	}

	return pending != 0;
}

/**
 * Check whether there is pending data for us to read on a tty / fifo stdin.
 */
bool
mingw_stdin_pending(bool fifo)
{
	return fifo ? mingw_fifo_pending(STDIN_FILENO) : booleanize(_kbhit());
}

/**
 * Compute default gateway address.
 *
 * @param ip		where IPv4 gateway address is to be written
 *
 * @return 0 on success, -1 on failure with errno set.
 */
int
mingw_getgateway(uint32 *ip)
{
	MIB_IPFORWARDROW ipf;

	ZERO(&ipf);
	if (GetBestRoute(0, 0, &ipf) != NO_ERROR) {
		errno = mingw_last_error();
		return -1;
	}

	*ip = ntohl(ipf.dwForwardNextHop);
	return 0;
}

#ifdef EMULATE_GETTIMEOFDAY
/**
 * Get the current system time.
 *
 * @param tv	the structure to fill with the current time.
 * @param tz	(unused) normally a "struct timezone"
 */
int
mingw_gettimeofday(struct timeval *tv, void *tz)
{
	FILETIME ft;

	(void) tz;	/* We don't handle the timezone */

	GetSystemTimeAsFileTime(&ft);

	/*
	 * MSDN says that FILETIME contains a 64-bit value representing the number
	 * of 100-nanosecond intervals since January 1, 1601 (UTC).
	 *
	 * This is exactly 11644473600000000 usecs before the UNIX Epoch.
	 */

	mingw_filetime_to_timeval(&ft, tv, EPOCH_OFFSET);

	return 0;
}
#endif	/* EMULATE_GETTIMEOFDAY */

#ifdef EMULATE_CLOCK_GETTIME
/**
 * Retrieve the time of the specified clock.
 *
 * @note
 * Only the CLOCK_REALTIME clock is supported.
 *
 * @param clock_id		the ID of the clock to fetch
 * @param tp			where the clock time should be written to
 *
 * @return 0 if OK, -1 on error with errno set.
 */
int
mingw_clock_gettime(int clock_id, struct timespec *tp)
{
	LARGE_INTEGER t;
	static bool inited;
	static LARGE_INTEGER start;
	static LARGE_INTEGER freq;
	static tm_nano_t origin;

	if G_UNLIKELY(clock_id != CLOCK_REALTIME) {
		errno = EINVAL;
		return -1;
	}

	if G_UNLIKELY(!inited) {
		static spinlock_t clock_gettime_slk = SPINLOCK_INIT;

		spinlock_hidden(&clock_gettime_slk);

		if (!inited) {
			struct timeval tm;

			gettimeofday(&tm, NULL);
			origin.tv_sec = tm.tv_sec;
			origin.tv_nsec = tm.tv_usec * 1000;
			QueryPerformanceCounter(&start);
			QueryPerformanceFrequency(&freq);
			inited = TRUE;
		}

		spinunlock_hidden(&clock_gettime_slk);
	}

	if (!QueryPerformanceCounter(&t)) {
		errno = EINVAL;
		return -1;
	} else {
		uint64 nanoseconds;		/* Elapsed nanoseconds since start */
		tm_nano_t result;

		t.QuadPart -= start.QuadPart;
		nanoseconds = t.QuadPart * (uint64) TM_BILLION / freq.QuadPart;
		result.tv_sec  = nanoseconds / TM_BILLION;
		result.tv_nsec = nanoseconds % TM_BILLION;
		tm_precise_add(&result, &origin);
		tm_nano_to_timespec(tp, &result);
	}

	return 0;
}
#endif	/* EMULATE_CLOCK_GETTIME */

#ifdef EMULATE_CLOCK_GETRES
/**
 * Retrieve the resolution of the specified clock.
 *
 * @note
 * Only the CLOCK_REALTIME clock is supported.
 *
 * @param clock_id		the ID of the clock to fetch
 * @param res			where the clock resolution should be written to
 *
 * @return 0 if OK, -1 on error with errno set.
 */
int
mingw_clock_getres(int clock_id, struct timespec *res)
{
	LARGE_INTEGER freq;
	ulong nanosecs;

	if G_UNLIKELY(clock_id != CLOCK_REALTIME) {
		errno = EINVAL;
		return -1;
	}

	if (!QueryPerformanceFrequency(&freq)) {
		errno = EINVAL;
		return -1;
	}

	nanosecs = (uint64) TM_BILLION / freq.QuadPart;
	if (0 == nanosecs)
		nanosecs = 1;

	res->tv_sec  = nanosecs / TM_BILLION;
	res->tv_nsec = nanosecs % TM_BILLION;

	return 0;
}
#endif	/* EMULATE_CLOCK_GETRES */

static hash_table_t *semaphores;	/* semaphore sets by ID */
static int next_semid;				/* next ID we create */
static spinlock_t sem_slk = SPINLOCK_INIT;

/**
 * A semaphore set.
 */
struct semset {
	int count;					/* amount of semaphores */
	int refcnt;					/* amount of users in a sem*() call */
	int semid;					/* semaphore set internal ID */
	HANDLE *handle;				/* semaphore handles */
	int *token;					/* tokens per semaphore */
	spinlock_t lock;			/* thread-safe lock */
	uint destroyed:1;			/* signals the semaphore was destroyed */
};

static hash_table_t *
sem_table(void)
{
	if G_UNLIKELY(NULL == semaphores) {
		static spinlock_t semaphores_slk = SPINLOCK_INIT;

		spinlock(&semaphores_slk);
		if (NULL == semaphores) {
			semaphores = hash_table_once_new_full_real(NULL, NULL);
			hash_table_thread_safe(semaphores);
		}
		spinunlock(&semaphores_slk);
	}

	return semaphores;
}

static void
semset_destroy(struct semset *s)
{
	int i;

	g_assert(spinlock_is_held(&s->lock));
	g_assert(0 == s->refcnt);

	spinlock_destroy(&s->lock);

	for (i = 0; i < s->count; i++) {
		if (s->handle[i] != NULL) {
			if (0 == CloseHandle(s->handle[i])) {
				errno = mingw_last_error();
				s_minicarp("%s(%d, IPC_RMID) cannot close handle "
					"for semaphore #%d: %m", G_STRFUNC, s->semid, i);
				/* Ignore error */
			}
		}
	}

	WFREE_ARRAY(s->handle, s->count);
	WFREE_ARRAY(s->token, s->count);
	WFREE(s);
}

/* Must be a macro for proper spinlock source tracking */
#define SEMSET_LOCK(s,y) G_STMT_START {	\
	spinlock_swap(&(s)->lock, (y));		\
	atomic_int_inc(&(s)->refcnt);		\
} G_STMT_END

static void
SEMSET_UNLOCK(struct semset *s)
{
	g_assert(spinlock_is_held(&s->lock));

	/*
	 * Because we release the spinlock on the set before issuing a system call,
	 * we need to reference count the users of the semaphore set and defer
	 * cleanup of the structure until after the last user is gone.
	 */

	if (1 == atomic_int_dec(&s->refcnt)) {
		if G_UNLIKELY(s->destroyed) {
			semset_destroy(s);
			return;
		}
	}

	spinunlock(&s->lock);
}

int
mingw_semget(key_t key, int nsems, int semflg)
{
	int id;
	struct semset *s;
	bool ok;

	g_assert_log(IPC_PRIVATE == key,
		"%s() only supports IPC_PRIVATE keys", G_STRFUNC);

	if (nsems < 0 || nsems > SEMMSL) {
		errno = EINVAL;
		return -1;
	}

	if (0 == (semflg & IPC_CREAT)) {
		errno = ENOENT;			/* since we only support IPC_PRIVATE */
		return -1;
	}

	id = next_semid++;
	WALLOC0(s);
	s->count = nsems;
	s->semid = id;
	WALLOC0_ARRAY(s->handle, nsems);
	WALLOC0_ARRAY(s->token, nsems);
	spinlock_init(&s->lock);

	ok = hash_table_insert(sem_table(), int_to_pointer(id), s);
	g_assert(ok);

	return id;
}

int
mingw_semctl(int semid, int semnum, int cmd, ...)
{
	hash_table_t *sems = sem_table();
	struct semset *s;
	va_list args;
	int value, result = 0;

	spinlock(&sem_slk);

	s = hash_table_lookup(sems, int_to_pointer(semid));
	if (NULL == s) {
		spinunlock(&sem_slk);
		errno = EIDRM;
		return -1;
	}

	/*
	 * This critical section crossing ensures that nobody can free up the
	 * semaphore set until we SEMSET_UNLOCK() it.  The reference count is
	 * increased by SEMSET_LOCK().
	 */

	SEMSET_LOCK(s, &sem_slk);
	spinunlock(&sem_slk);

	if (s->destroyed) {
		errno = EIDRM;
		result = -1;
		goto done;
	}

	switch (cmd) {
	case IPC_RMID:
		/* The semnum argument is ignored, hence not validated */
		s->destroyed = TRUE; /* Defer destruction until last user is gone */
		hash_table_remove(sems, int_to_pointer(semid));
		break;

	case GETVAL:
		if (semnum < 0 || semnum >= s->count) {
			errno = ERANGE;
			result = -1;
			break;
		}

		if (NULL == s->handle[semnum]) {
			result = 0;
		} else {
			result = s->token[semnum];
		}
		break;

	case SETVAL:
		if (semnum < 0 || semnum >= s->count) {
			errno = ERANGE;
			result = -1;
			break;
		}

		/*
		 * The SETVAL command is our signal that the semaphore is initialized.
		 * Any previous existing handle is just closed.
		 */

		if (s->handle[semnum] != NULL) {
			HANDLE h = s->handle[semnum];
			BOOL r;

			spinunlock(&s->lock);
			r = CloseHandle(h);
			spinlock(&s->lock);
			if (s->destroyed) {
				errno = EIDRM;
				result = -1;
				break;
			} else if (0 == r) {
				errno = mingw_last_error();
				s_minicarp("%s(%d, SETVAL) cannot close semaphore #%d: %m",
					G_STRFUNC, s->semid, semnum);
				/* Ignore error */
			}
			s->handle[semnum] = NULL;
		}

		va_start(args, cmd);
		value = va_arg(args, int);
		va_end(args);

		/*
		 * We release the lock but we do not call SEMSET_UNLOCK(), hence the
		 * reference count is not altered and this prevents any physical
		 * destruction of the object.
		 *
		 * However, once we release the lock we open the door for concurrent
		 * destruction of the semaphore set so we need to recheck for that
		 * condition once we re-enter the critical section.
		 */

		spinunlock(&s->lock);
		s->handle[semnum] = CreateSemaphore(NULL, value, INT_MAX, NULL);
		spinlock(&s->lock);

		if G_UNLIKELY(s->destroyed) {
			errno = EIDRM;
			result = -1;
		} else if (NULL == s->handle[semnum]) {
			errno = mingw_last_error();
			result = -1;
		}

		if G_UNLIKELY(-1 == result) {
			/* Warn loudly since we use semaphores for inter-thread synchro */
			s_minicarp("%s(%d, SETVAL) cannot create new semaphore #%d: %m",
				G_STRFUNC, s->semid, semnum);
		} else {
			s->token[semnum] = value;
		}
		break;

	default:
		s_error("%s() only supports the GETVAL, SETVAL and IPC_RMID commands",
			G_STRFUNC);
	}

done:
	SEMSET_UNLOCK(s);
	return result;
}

int
mingw_semop(int semid, struct sembuf *sops, unsigned nsops)
{
	return mingw_semtimedop(semid, sops, nsops, NULL);
}

int
mingw_semtimedop(int semid, struct sembuf *sops,
	unsigned nsops, struct timespec *timeout)
{
	DWORD ms;
	struct semset *s;
	int result = 0;
	HANDLE h;

	g_assert_log(1 == nsops,
		"%s() only supports operations on one semaphore at a time", G_STRFUNC);

	spinlock(&sem_slk);

	s = hash_table_lookup(sem_table(), int_to_pointer(semid));
	if (NULL == s) {
		spinunlock(&sem_slk);
		errno = EIDRM;
		return -1;
	}

	/*
	 * This is the same critical handling as in mingw_semctl().
	 */

	SEMSET_LOCK(s, &sem_slk);
	spinunlock(&sem_slk);

	if (s->destroyed) {
		errno = EIDRM;
		result = -1;
		goto done;
	}

	if (NULL == sops) {
		errno = EFAULT;
		result = -1;
		goto done;
	}

	g_assert_log(0 != sops->sem_op,
		"%s() does not support waiting for semaphores which reach zero",
		G_STRFUNC);

	g_assert_log(0 == (sops->sem_flg & SEM_UNDO),
		"%s() does not support SEM_UNDO", G_STRFUNC);

	if (sops->sem_num >= s->count) {
		errno = EFBIG;
		result = -1;
		goto done;
	}

	h = s->handle[sops->sem_num];

	if (NULL == h) {
		s_minicarp("%s(%d) called on un-initialized semaphore #%d",
			G_STRFUNC, s->semid, sops->sem_num);
		errno = EIDRM;
		result = -1;
		goto done;
	}

	if (sops->sem_op > 0) {
		BOOL r;

		/*
		 * We release the spinlock before calling ReleaseSemaphore() even if
		 * that call cannot block because we don't want to keep a lock across
		 * a system call.  This opens a window for failure if another thread
		 * comes in and destroys the semaphore, but in that case our handle
		 * would become invalid.  We trap that to transform EBADF into EIDRM.
		 *
		 * We update the token count before the system call to prevent a race
		 * condition with the waiting side which could be awoken before we
		 * re-grab the lock.
		 */

		s->token[sops->sem_num] += sops->sem_op;

		/* See comment in mingw_semctl() about the following sequence */

		spinunlock(&s->lock);
		r = ReleaseSemaphore(h, sops->sem_op, NULL);
		spinlock(&s->lock);

		if G_UNLIKELY(s->destroyed) {
			errno = EIDRM;
			result = -1;
		} else if (0 == r) {
			errno = mingw_last_error();
			if (EBADF == errno)
				errno = EIDRM;
			result = -1;
		}
		if G_UNLIKELY(-1 == result) {
			/* Fail loudly since semaphores are used for inter-thread synchro */
			s_minicarp("%s(%d, +%d) failed on semaphore #%d: %m",
				G_STRFUNC, s->semid, sops->sem_op, sops->sem_num);
		}
	} else {
		DWORD w;

		/*
		 * Acquiring semaphores is the tricky part because Windows does not
		 * support atomic acquisition of more than one token.
		 *
		 * Fortunately, we should only need increments of 1.
		 *		--RAM, 2012-12-27
		 */

		g_assert_log(-1 == sops->sem_op,
			"%s(): sorry, Windows does not support getting %d tokens at a time",
			G_STRFUNC, -sops->sem_op);

		if (sops->sem_flg & IPC_NOWAIT)
			ms = 0;
		else if (timeout != NULL)
			ms = timeout->tv_nsec / TM_MILLION + timeout->tv_sec * 1000;
		else
			ms = INFINITE;

		/* See comment in mingw_semctl() about the following sequence */

		spinunlock(&s->lock);
		thread_in_syscall_set(TRUE);
		w = WaitForSingleObject(h, ms);
		thread_in_syscall_set(FALSE);
		spinlock(&s->lock);

		if G_UNLIKELY(s->destroyed) {
			errno = EIDRM;
			result = -1;
			goto done;
		}

		switch (w) {
		case WAIT_OBJECT_0:
			s->token[sops->sem_num]--;
			g_assert(s->token[sops->sem_num] >= 0);
			break;
		case WAIT_TIMEOUT:
			errno = EAGAIN;
			result = -1;
			break;
		case WAIT_ABANDONED:	/* Should not happen for a semaphore */
		default:
			errno = mingw_last_error();
			s_minicarp("%s(%d): acquisition of semaphore failed: %m",
				G_STRFUNC, s->semid);
			result = -1;
			break;
		}
	}

	/* FALL THROUGH */
done:
	SEMSET_UNLOCK(s);
	return result;
}

void mingw_vmm_post_init(void)
{
	void *cur_break = mingw_sbrk(0);

	s_info("VMM process has %s of virtual space",
		compact_size(mingw_vmm.available, FALSE));
	s_info("VMM reserved %s of virtual space at [%p, %p[",
		compact_size(mingw_vmm.size, FALSE),
		mingw_vmm.reserved,
		ptr_add_offset(mingw_vmm.reserved, mingw_vmm.size));
	s_info("VMM left %s of virtual space unreserved",
		compact_size(mingw_vmm.later, FALSE));
	s_info("VMM had %s already committed at startup",
		compact_size(mingw_vmm.baseline, FALSE));
	s_info("VMM will be using %s of VM space at most",
		compact_size(mingw_vmm.size + mingw_vmm.baseline, FALSE));

	/*
	 * On Windows, VM address space grows up, but starts far enough from
	 * the default process heap.  So vmm_reserved > heap_break.
	 */

	s_info("VMM initial break at %p, leaving %s for the heap (%'zu bytes used)",
		mingw_vmm.heap_break,
		compact_size(ptr_diff(mingw_vmm.reserved, mingw_vmm.heap_break), FALSE),
		ptr_diff(cur_break, mingw_vmm.heap_break));
}

void
mingw_init(void)
{
	ONCE_FLAG_RUN(mingw_socket_inited, mingw_socket_init);
}

#ifdef MINGW_BACKTRACE_DEBUG
#define BACKTRACE_DEBUG(lvl, ...)	\
	if ((lvl) & mingw_backtrace_flags) mingw_debug_log(__VA_ARGS__)
#define BACKTRACE_ENTRY 									\
G_STMT_START {												\
	if (mingw_backtrace_debug())							\
		mingw_debug_entering(G_STRFUNC);					\
} G_STMT_END
#define BACKTRACE_RETURN_VOID								\
G_STMT_START {												\
	if (mingw_backtrace_debug())							\
		mingw_debug_leaving(G_STRFUNC, G_STRLOC, "%s", "");	\
	return;													\
} G_STMT_END
#define BACKTRACE_RETURN(fmt, val)							\
G_STMT_START {												\
	if (mingw_backtrace_debug())							\
		mingw_debug_leaving(G_STRFUNC, G_STRLOC, (fmt), (val));	\
	return val;												\
} G_STMT_END
#define BACKTRACE_LOG_LOCK		mutex_lock(&mingw_debuglog.lock)
#define BACKTRACE_LOG_UNLOCK	mutex_unlock(&mingw_debuglog.lock)
#define mingw_backtrace_debug()	(mingw_backtrace_flags != 0)
#define mingw_debug_file		mingw_debuglog.lf
#else	/* !MINGW_BACKTRACE_DEBUG */
#define BACKTRACE_DEBUG(...)
#define BACKTRACE_ENTRY
#define BACKTRACE_RETURN_VOID		return
#define BACKTRACE_RETURN(fmt, val)	return val
#define BACKTRACE_LOG_LOCK
#define BACKTRACE_LOG_UNLOCK
#define mingw_backtrace_debug()	0
#define mingw_debug_log(...)
#define mingw_debug_file		stderr
#endif	/* MINGW_BACKTRACE_DEBUG */

#define MINGW_SP_INSPECT			3
#define MINGW_MAX_ROUTINE_LENGTH	0x2000
#define MINGW_FORWARD_SCAN			32
#define MINGW_SP_ALIGN				4
#define MINGW_SP_MASK				(MINGW_SP_ALIGN - 1)
#define MINGW_EMPTY_STACKFRAME		((void *) 1)

/* Debug flags for BACKTRACE_DEBUG */
#define BACK_F_NAME			(1 << 0)
#define BACK_F_PROLOGUE		(1 << 1)
#define BACK_F_RA			(1 << 2)
#define BACK_F_DRIVER		(1 << 3)
#define BACK_F_OTHER		(1 << 4)
#define BACK_F_DUMP			(1 << 5)
#define BACK_F_RESULT		(1 << 6)
#define BACK_F_PC			(1 << 7)

#define BACK_F_ALL \
	(BACK_F_NAME | BACK_F_PROLOGUE | BACK_F_RA | BACK_F_DRIVER | \
		BACK_F_OTHER | BACK_F_DUMP | BACK_F_RESULT | BACK_F_PC)

/* Now that we have a separate logfile for backtracing, be more verbose */
#if 0
#define MINGW_BACKTRACE_FLAGS	(BACK_F_DRIVER | BACK_F_RESULT | BACK_F_NAME)
#else
#define MINGW_BACKTRACE_FLAGS	BACK_F_ALL
#endif

/*
 * When MINGW_BACKTRACE_DEBUG_ON_CRASH is set, we turn off the debugging
 * initially, and only turn it on when an exception is raised.
 */
#ifdef MINGW_BACKTRACE_DEBUG_ON_CRASH
#define MINGW_BACKTRACE_FLAGS_INIT	0	/* No debug initially */
#else
#define MINGW_BACKTRACE_FLAGS_INIT	MINGW_BACKTRACE_FLAGS
#endif

static uint32 mingw_backtrace_flags = MINGW_BACKTRACE_FLAGS_INIT;

static inline void
mingw_activate_backtrace_debug(void)
{
	/* This has no effect if not compiled with MINGW_BACKTRACE_DEBUG */
	mingw_backtrace_flags = MINGW_BACKTRACE_FLAGS;
}

static inline bool
valid_ptr(const void * const p)
{
	ulong v = pointer_to_ulong(p);
	return v > 0x1000 && v < 0xfffff000 && mem_is_valid_ptr(p);
}

static inline bool
valid_stack_ptr(const void * const p, const void *top)
{
	ulong v = pointer_to_ulong(p);

	return 0 == (v & MINGW_SP_MASK) && vmm_is_stack_pointer(p, top);
}

/*
 * x86 leading instruction opcodes
 */
#define OPCODE_RET_NEAR		0xc3
#define OPCODE_RET_FAR		0xcb
#define OPCODE_RET_NEAR_POP	0xc2	/* Plus pop immediate 16-bit amount */
#define OPCODE_RET_FAR_POP	0xca	/* Plus pop immediate 16-bit amount */
#define OPCODE_LEAVE		0xc9	/* Set ESP to EBP, then pop EBP */
#define OPCODE_NOP			0x90
#define OPCODE_CALL_NEAR	0xe8	/* Call near, relative 16 or 32 bits */
#define OPCODE_CALL_FAR		0x9a	/* Call far, absolute 16 or 32 bits */
#define OPCODE_CALL_IND		0xff	/* Call indirect near/far */
#define OPCODE_PUSH_EAX		0x50
#define OPCODE_PUSH_ECX		0x51
#define OPCODE_PUSH_EDX		0x52
#define OPCODE_PUSH_EBX		0x53
#define OPCODE_PUSH_ESP		0x54
#define OPCODE_PUSH_EBP		0x55
#define OPCODE_PUSH_ESI		0x56
#define OPCODE_PUSH_EDI		0x57
#define OPCODE_SUB_1		0x29	/* Substraction between registers */
#define OPCODE_SUB_2		0x81	/* Need further probing for real opcode */
#define OPCODE_SUB_3		0x83	/* Need further probing for real opcode */
#define OPCODE_MOV_REG		0x89	/* Move one register to R/M word */
#define OPCODE_MOV_REGI		0x8b	/* Move R/M word to register */
#define OPCODE_MOV_IMM_EAX	0xb8	/* Move immediate value to register EAX */
#define OPCODE_MOV_IMM_ECX	0xb9
#define OPCODE_MOV_IMM_EDX	0xba
#define OPCODE_MOV_IMM_EBX	0xbb
#define OPCODE_MOV_IMM_ESP	0xbc
#define OPCODE_MOV_IMM_EBP	0xbd
#define OPCODE_MOV_IMM_ESI	0xbe
#define OPCODE_MOV_IMM_EDI	0xbf
#define OPCODE_JMP_SHORT	0xeb	/* Followed by signed byte */
#define OPCODE_JMP_LONG		0xe9	/* Followed by signed 32-bit value */
#define OPCODE_LEA			0x8d
#define OPCODE_XOR_1		0x31	/* Between registers if mod=3 */
#define OPCODE_XOR_2		0x33	/* Complex XOR involving memory */
#define OPCODE_NONE_1		0x26	/* Not a valid opcode */
#define OPCODE_NONE_2		0x2e
#define OPCODE_NONE_3		0x36
#define OPCODE_NONE_4		0x3E
#define OPCODE_NONE_5		0x64
#define OPCODE_NONE_6		0x65
#define OPCODE_NONE_7		0x66
#define OPCODE_NONE_8		0x67

/*
 * x86 follow-up instruction parsing
 */
#define OPMODE_MODE_MASK	0xc0	/* Mask to get a instruction mode code */
#define OPMODE_OPCODE		0x38	/* Mask to extract extra opcode info */
#define OPMODE_REG_SRC_MASK	0x38	/* Mask to extract source register */
#define OPMODE_REG_DST_MASK	0x07	/* Mask to extract destination register */
#define OPMODE_RM_MASK		0x07	/* Mask to extract R/M part */
#define OPMODE_ADD			0		/* Extra opcode indicating an ADD after 0x83 */
#define OPMODE_SUB			5		/* Extra opcode indicating a SUB after 0x83 */
#define OPMODE_ADD_ESP		0xc4	/* Byte after leading opcode for ADD ESP */
#define OPMODE_SUB_ESP		0xec	/* Byte after leading opcode for SUB ESP */
#define OPMODE_REG_ESP_EBP	0xe5	/* Byte after MOV_REG to move ESP to EBP */
#define OPMODE_REG_EBP_ESP	0xec	/* Byte after MOV_REGI to move ESP to EBP */

/*
 * x86 register numbers, as encoded in instructions.
 */
#define OPREG_EAX			0
#define OPREG_ECX			1
#define OPREG_EDX			2
#define OPREG_EBX			3
#define OPREG_ESP			4
#define OPREG_EBP			5
#define OPREG_ESI			6
#define OPREG_EDI			7

/*
 * The MOD-REG-R/M byte specifies instruction operands and their
 * addressing mode.  It is architected as:
 *
 *      7 6  5 4 3  2 1 0
 *    +----+------+------+
 *    |MOD |  REG |  R/M |
 *    +----+------+------+
 *
 * MOD:
 * 00   register indirect mode with no displacement (R/M = 100b) or
 *      displacement only (R/M = 101b)
 * 01   1-byte signed displacement follows
 * 10   4-byte signed displacement follows
 * 11   register addressing mode
 *
 * REG  encodes the register (0-7) as listed above (0=EAX, 7=EDI)
 *      for 2-operand instructions.
 */

static inline uint8
mingw_op_mod_code(uint8 mbyte)
{
	return (mbyte & OPMODE_MODE_MASK) >> 6;
}

static inline uint8
mingw_op_src_register(uint8 mbyte)
{
	return (mbyte & OPMODE_REG_SRC_MASK) >> 3;
}

static inline uint8
mingw_op_dst_register(uint8 mbyte)
{
	return mbyte & OPMODE_REG_DST_MASK;
}

static inline uint8
mingw_op_extra(uint8 mbyte)
{
	return (mbyte & OPMODE_OPCODE) >> 3;
}

static inline uint8
mingw_op_rm_code(uint8 mbyte)
{
	return mbyte & OPMODE_RM_MASK;
}

#define MINGW_TEXT_OFFSET	0x1000	/* Text offset after mapping base */

#define MINGW_ROUTINE_ALIGN	4
#define MINGW_ROUTINE_MASK	(MINGW_ROUTINE_ALIGN - 1)

#define mingw_routine_align(x) ulong_to_pointer( \
	(pointer_to_ulong(x) + MINGW_ROUTINE_MASK) & ~MINGW_ROUTINE_MASK)

/**
 * Expected unwinding stack frame, if present and maintained by routines.
 *
 * As the stack grows down on Windows, this structure reflects the initial
 * PUSH of EIP on the stack by the CALL instruction, followed by the PUSH
 * of the EBP register upon routine entry.
 */
struct stackframe {
	struct stackframe *next;
	void *ret;
};

#ifdef MINGW_BACKTRACE_DEBUG
static struct mingw_debuglog {
	int level[THREAD_MAX];	/* Indent level, per thread */
	FILE *lf;				/* Logfile */
	bool rotated;			/* Did we rotate the old debug logfiles? */
	mutex_t lock;			/* Protect concurrent writes */
} mingw_debuglog = {
	.lock = MUTEX_INIT,
};

/**
 * Return default logfile for backtracing debug.
 */
static const char *
mingw_getbacktrace_path(void)
{
	static char pathname[MAX_PATH];
	char buf[128];

	str_bprintf(ARYLEN(buf), "%s.backtrace.log", product_nickname());

	return mingw_build_personal_path(buf, ARYLEN(pathname));
}

/**
 * Emit log to debuglog.
 */
static void
mingw_debug_logv(const char *fmt, va_list args)
{
	FILE *lf;
	char time_buf[CRASH_TIME_BUFLEN];
	char logstr[512];
	int i;
	uint stid = thread_small_id();

	/*
	 * Until mingw_early_init() has completed, minimal service!
	 * Indeed, we are still in the early initializations, and we
	 * do not want to recurse into that path by allocating
	 * memory via halloc() for instance.
	 */

	if (!mingw_debuglog.rotated && mingw_early_inited) {
		BACKTRACE_LOG_LOCK;
		if (!mingw_debuglog.rotated) {
			const char *path = mingw_getbacktrace_path();
			if (mingw_debuglog.lf != NULL) {
				fclose(mingw_debuglog.lf);
				mingw_debuglog.lf = NULL;
			}
			mingw_debuglog.rotated = TRUE;
			mingw_file_rotate(path, MINGW_TRACEFILE_KEEP);
		}
		BACKTRACE_LOG_UNLOCK;
	}

	/*
	 * Open logfile the first time.
	 */

	if G_UNLIKELY(NULL == mingw_debuglog.lf) {
		BACKTRACE_LOG_LOCK;
		if (NULL == mingw_debuglog.lf) {
			const char *path = mingw_getbacktrace_path();
			mingw_debuglog.lf = fopen(path, "ab");
			if (NULL == mingw_debuglog.lf && mingw_early_inited)
				s_warning("%s(): cannot open %s", G_STRFUNC, path);
		}
		BACKTRACE_LOG_UNLOCK;
	}

	crash_time_raw(ARYLEN(time_buf));
	log_vbprintf(ARYLEN(logstr), fmt, args);

	BACKTRACE_LOG_LOCK;

	lf = mingw_debuglog.lf;
	if G_UNLIKELY(NULL == lf)
		goto done;

	fprintf(lf, "%s: [%d] ", time_buf, stid);

	for (i = 0; i < mingw_debuglog.level[stid]; i++) {
		fputs("| ", lf);
	}

	fputs(logstr, lf);
	fputc('\n', lf);
	fflush(lf);

done:
	BACKTRACE_LOG_UNLOCK;
}

static void G_PRINTF(1, 2)
mingw_debug_log(const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	mingw_debug_logv(fmt, args);
	va_end(args);
}

/**
 * Log routine entry.
 */
static void
mingw_debug_entering(const char *routine)
{
	uint stid = thread_small_id();

	mingw_debug_log("+> %s()", routine);
	mingw_debuglog.level[stid]++;
}

static void G_PRINTF(3, 4)
mingw_debug_leaving(const char *routine, const char *loc, const char *fmt, ...)
{
	char result[128];
	va_list args;
	uint stid = thread_small_id();

	if (mingw_debuglog.level[stid] > 0) {
		mingw_debuglog.level[stid]--;
	} else {
		mingw_debug_log(
			"WARNING: indent level was 0 when leaving %s()", routine);
	}

	va_start(args, fmt);
	log_vbprintf(ARYLEN(result), fmt, args);
	if (result[0] != '\0')
		mingw_debug_log("+< %s() = %s at %s", routine, result, loc);
	else
		mingw_debug_log("+< %s() at %s", routine, loc);
	va_end(args);
}

/**
 * @return opcode leading mnemonic string.
 */
static const char *
mingw_opcode_name(uint8 opcode)
{
	switch (opcode) {
	case OPCODE_LEAVE:
		return "LEAVE";
	case OPCODE_RET_NEAR:
	case OPCODE_RET_FAR:
	case OPCODE_RET_NEAR_POP:
	case OPCODE_RET_FAR_POP:
		return "RET";
	case OPCODE_NOP:
		return "NOP";
	case OPCODE_CALL_NEAR:
	case OPCODE_CALL_FAR:
	case OPCODE_CALL_IND:
		return "CALL";
	case OPCODE_PUSH_EAX:
	case OPCODE_PUSH_EBX:
	case OPCODE_PUSH_ECX:
	case OPCODE_PUSH_EDX:
	case OPCODE_PUSH_ESP:
	case OPCODE_PUSH_EBP:
	case OPCODE_PUSH_ESI:
	case OPCODE_PUSH_EDI:
		return "PUSH";
	case OPCODE_MOV_REG:		/* Used by gcc in "mov %esp,%ebp" */
	case OPCODE_MOV_REGI:		/* Used by MS compiler in "mov %esp,%ebp" */
	case OPCODE_MOV_IMM_EAX:
	case OPCODE_MOV_IMM_EBX:
	case OPCODE_MOV_IMM_ECX:
	case OPCODE_MOV_IMM_EDX:
	case OPCODE_MOV_IMM_ESP:
	case OPCODE_MOV_IMM_EBP:
	case OPCODE_MOV_IMM_ESI:
	case OPCODE_MOV_IMM_EDI:
		return "MOV";
	case OPCODE_JMP_SHORT:
	case OPCODE_JMP_LONG:
		return "JMP";
	case OPCODE_LEA:
		return "LEA";
	case OPCODE_XOR_1:
	case OPCODE_XOR_2:
		return "XOR";
	case OPCODE_NONE_1:
	case OPCODE_NONE_2:
	case OPCODE_NONE_3:
	case OPCODE_NONE_4:
	case OPCODE_NONE_5:
	case OPCODE_NONE_6:
	case OPCODE_NONE_7:
	case OPCODE_NONE_8:
	default:
		return "?";
	}
}
#endif /* MINGW_BACKTRACE_DEBUG */

/**
 * Wraps stacktrace_routine_name() to fake it until we performed the early init.
 */
static const char *
mingw_routine_name(const void *pc)
{
	static char buf[POINTER_BUFLEN];

	if G_UNLIKELY(!mingw_early_inited) {
		str_bprintf(ARYLEN(buf), "%p", pc);
		return buf;
	}

	return stacktrace_routine_name(pc, TRUE);
}

/**
 * Computes the length taken by the versatile LEA instruction.
 *
 * @param op		pointer to the LEA opcode
 */
static unsigned
mingw_opcode_lea_length(const uint8 *op)
{
	uint8 mode, reg;

	g_assert(OPCODE_LEA == *op);

	mode = mingw_op_mod_code(op[1]);
	reg = mingw_op_dst_register(op[1]);

	switch (mode) {
	case 0:
		/*
		 * ``reg'' encodes the following:
		 *
		 * 4 = [sib] (32-bit SIB Byte follows)
		 * 5 = disp32
		 * others = register
		 */

		if (4 == reg) {
			return 3;
		} if (5 == reg) {
			return 6;
		} else {
			return 2;
		}
		g_assert_not_reached();
	case 1:
		/*
		 * ``reg'' encodes the following:
		 *
		 * 4 = [sib] + disp8
		 * others = register + disp8
		 */

		if (4 == reg) {
			return 4;
		} else {
			return 3;
		}
		g_assert_not_reached();
	case 2:
		/*
		 * ``reg'' encodes the following:
		 *
		 * 4 = [sib] + disp32
		 * others = register + disp32
		 */
		if (4 == reg) {
			return 7;
		} else {
			return 6;
		}
		g_assert_not_reached();
	case 3:
		return 2;
	default:
		break;
	}

	g_assert_not_reached();
	return 0;
}

/**
 * Is the SUB opcode pointed at by ``op'' targetting ESP?
 *
 * FIXME: !!HACK ALERT!!
 * 	Instead of just passing "op", we're passing *op as `ov' to the routine.
 * 	why? because when, at the caller level, *op=0x81, it sometimes reads as 0x0
 * 	here, causing the fall to the "code not reached" section. incredible!
 *		--RAM, 2018-10-13
 */
static bool
mingw_opcode_is_sub_esp(const uint8 *op, uint8 ov)
{
	uint8 mbyte = op[1];

	BACKTRACE_ENTRY;
	BACKTRACE_DEBUG(BACK_F_OTHER,
		"%s: at %p, op=0x%x, ov=%x, next=0x%x", G_STRFUNC, op, op[0], ov, mbyte);

	switch (ov) {			/* See !!HACK ALERT!! above */
	case OPCODE_SUB_1:
		BACKTRACE_RETURN("%d", OPREG_ESP == mingw_op_dst_register(mbyte));
	case OPCODE_SUB_2:
	case OPCODE_SUB_3:
		{
			uint8 code = mingw_op_src_register(mbyte);
			uint8 mode = mingw_op_mod_code(mbyte);
			int32 value;

			if (mode != 3)
				BACKTRACE_RETURN("%d", FALSE);	/* Not targetting a register */
			if (OPREG_ESP != mingw_op_dst_register(mbyte))
				BACKTRACE_RETURN("%d", FALSE);	/* Not targetting ESP */

			/*
			 * The immediate value that follows is a 32-bit for SUB_2 and
			 * 8-bit for SUB_3.  These are signed.
			 */

			if (OPCODE_SUB_3 == ov) {
				int8 v = op[2];
				value = v;
				BACKTRACE_DEBUG(BACK_F_OTHER,
					"%s: read byte at %p = 0x%x as %d -> %d",
					G_STRFUNC, &op[2], op[2], v, value);
			} else {
				value = peek_le32(&op[2]);
			}

			BACKTRACE_DEBUG(BACK_F_OTHER,
				"%s: at %p, subvalue=%d for op=0x%x (code=%u %s)",
				G_STRFUNC, op, value, op[0], code,
				OPMODE_SUB == code ? "SUB" :
				OPMODE_ADD == code ? "ADD" :
				"???");

			if (OPMODE_SUB == code)
				BACKTRACE_RETURN("%d", value >= 0);

			if (OPMODE_ADD == code)
				BACKTRACE_RETURN("%d", value < 0);

			BACKTRACE_RETURN("%d", FALSE);
		}
	}

	g_assert_not_reached();
}

/**
 * Scan forward looking for one of the SUB instructions that can substract
 * a value from the ESP register.
 *
 * This can be one of (Intel notation):
 *
 * 		SUB ESP, <value>		; short stack reserve
 * 		SUB ESP, EAX			; large stack reserve
 *
 * @param start		initial program counter
 * @param max		absolute maximum PC value
 * @param at_start	known to be at the starting point of the routine
 * @param has_frame	set to TRUE if we saw a frame linking at the beginning
 * @param savings	indicates leading register savings done by the routine
 *
 * @return pointer to the start of the SUB instruction, NULL if we can't
 * find it, meaning the starting point was probably not the start of
 * a routine, MINGW_EMPTY_STACKFRAME if there is no SUB instruction.
 */
static const void *
mingw_find_esp_subtract(const void *start, const void *max, bool at_start,
	bool *has_frame, size_t *savings)
{
	const void *maxscan;
	const uint8 *p = start;
	const uint8 *first_opcode = p;
	bool saved_ebp = FALSE, mov_immediate_eax = FALSE;
	size_t pushes = 0, calls = 0;

	BACKTRACE_ENTRY;

	maxscan = const_ptr_add_offset(start, MINGW_FORWARD_SCAN);
	if (ptr_cmp(maxscan, max) > 0)
		maxscan = max;

	if (mingw_backtrace_debug() && (BACK_F_DUMP & MINGW_BACKTRACE_FLAGS)) {
		BACKTRACE_LOG_LOCK;
		mingw_debug_log("%s: next %zu bytes after pc=%p%s",
			G_STRFUNC, 1 + ptr_diff(maxscan, p),
			p, at_start ? " (known start)" : "");
		dump_hex(mingw_debug_file, "", p, 1 + ptr_diff(maxscan, p));
		BACKTRACE_LOG_UNLOCK;
	}

	for (p = start; ptr_cmp(p, maxscan) <= 0; p++) {
		const void *window;
		uint8 op;
		unsigned fill = 0;

		if (!valid_ptr(p))
			BACKTRACE_RETURN("%p", NULL);

		switch ((op = *p)) {
		case OPCODE_NONE_1:
		case OPCODE_NONE_2:
		case OPCODE_NONE_3:
		case OPCODE_NONE_4:
		case OPCODE_NONE_5:
		case OPCODE_NONE_6:
		case OPCODE_NONE_7:
		case OPCODE_NONE_8:
		case OPCODE_NOP:
			fill = 1;
			goto filler;
		case OPCODE_LEA:
			/*
			 * Need to decode further to know how many bytes are taken
			 * by this versatile instruction.
			 */
			fill = mingw_opcode_lea_length(p);
			goto filler;
		case OPCODE_PUSH_EBP:
			/*
			 * The frame pointer is saved if the routine begins with (Intel
			 * notation):
			 *
			 *	PUSH EBP
			 *  MOV  EBP, ESP
			 *
			 * to create the frame pointer link.
			 *
			 * When using the Windows call API, the EBP register is saved
			 * immediately at entry, but more registers can be saved as well
			 * before the ESP is altered (so the EBP value immediately follows
			 * the return PC pushed on the stack by the CALL instruction,
			 * establishing the "stackframe" structure).
			 */
			first_opcode = p + 1;	/* Expects the MOV operation to follow */
			if (0 == pushes)
				saved_ebp = TRUE;	/* EBP was the first to be pushed */
			/* FALL THROUGH */
		case OPCODE_PUSH_EAX:
		case OPCODE_PUSH_EBX:
		case OPCODE_PUSH_ECX:
		case OPCODE_PUSH_EDX:
		case OPCODE_PUSH_ESP:
		case OPCODE_PUSH_ESI:
		case OPCODE_PUSH_EDI:
			pushes++;
			break;
		case OPCODE_MOV_IMM_EAX:
			mov_immediate_eax = TRUE;
			/* FALL THROUGH */
		case OPCODE_MOV_IMM_EBX:
		case OPCODE_MOV_IMM_ECX:
		case OPCODE_MOV_IMM_EDX:
		case OPCODE_MOV_IMM_ESP:
		case OPCODE_MOV_IMM_EBP:
		case OPCODE_MOV_IMM_ESI:
		case OPCODE_MOV_IMM_EDI:
			p += 4;				/* Skip immediate value */
			break;
		case OPCODE_MOV_REG:
			/*
			 * This is the MOV variant used by gcc.
			 *
			 *            REG ESP EBP
			 * MOD byte is 11 100 101
			 *
			 * This performs a "mov %esp,%ebp" i.e. it sets ESP with the
			 * value of EBP.
			 */
			if (OPMODE_REG_ESP_EBP == p[1])
				saved_ebp = saved_ebp || p == first_opcode;
			p += 1;				/* Skip mod byte */
			break;
		case OPCODE_MOV_REGI:
			/*
			 * This is the MOV variant used by Microsoft compilers.
			 *
			 *            REG EBP ESP
			 * MOD byte is 11 101 100
			 *
			 * Encoding is inverted in mod byte, hence "REGI" for inverted.
			 * However since the semantics of this opcode is inverted,
			 * this performs a "mov %esp,%ebp", i.e. it sets ESP with the
			 * value of EBP.
			 */
			if (OPMODE_REG_EBP_ESP == p[1])
				saved_ebp = saved_ebp || p == first_opcode;
			p += 1;				/* Skip mod byte */
			break;
		case OPCODE_CALL_NEAR:
			/*
			 * Stackframe link created, no stack adjustment
			 *
			 * If this is the first CALL instruction and we have seen
			 * a "MOV EAX, val" (move immediate value into EAX), then
			 * we need to continue a little bit because this is the
			 * pattern generated by gcc for large stack frames:
			 *
			 *    movl    $65564, %eax
			 *    call    ___chkstk_ms
			 *    subl    %eax, %esp
			 *
			 * If we have not seen this pattern or this is the second
			 * CALL we see, assume there is no stack pointer adjustment
			 * when we saw a leading "PUSH EBB" instruction already.
			 */
			calls++;
			if (saved_ebp && !(1 == calls && mov_immediate_eax))
				BACKTRACE_RETURN("%p", MINGW_EMPTY_STACKFRAME);
			p += 4;				/* Skip offset */
			break;
		case OPCODE_XOR_1:
			if (OPMODE_MODE_MASK == (OPMODE_MODE_MASK & p[1])) {
				/* XOR between registers, same register to zero it */
				uint8 operands = p[1];
				uint8 reg1 = mingw_op_src_register(operands);
				uint8 reg2 = mingw_op_dst_register(operands);
				if (reg1 == reg2) {
					p += 1;
					break;
				}
			}
			/* XOR REG, REG is the only instruction we allow in the prologue */
			BACKTRACE_RETURN("%p", NULL);
		case OPCODE_SUB_1:
		case OPCODE_SUB_2:
		case OPCODE_SUB_3:
			if (mingw_opcode_is_sub_esp(p, op)) {
				*has_frame = saved_ebp;
				*savings = pushes;
				BACKTRACE_RETURN("%p", p);
			}
			switch (*p) {
			case OPCODE_SUB_1:
				p += 1;
				break;
			case OPCODE_SUB_2:
				p += 5;
				break;
			case OPCODE_SUB_3:
				p += 2;
				break;
			}
			break;
		default:
			/*
			 * If we're not on an aligned routine starting point, assume
			 * this is part of a filling instruction and ignore, provided
			 * we haven't seen any PUSH yet.
			 */
			if (0 == pushes && !at_start && p != mingw_routine_align(p)) {
				fill = 1;
				goto filler;
			}
			BACKTRACE_RETURN("%p", NULL);
		}

		continue;

	filler:
		/*
		 * Handle "filling" instructions between last RET / JMP and
		 * the next routine  Move the scanning window forward to avoid
		 * counting filling instructions.
		 */

		BACKTRACE_DEBUG(BACK_F_OTHER,
			"%s: ignoring %s filler (%u byte%s) at %p", G_STRFUNC,
			mingw_opcode_name(op), PLURAL(fill), p);

		first_opcode = p + fill;
		p += (fill - 1);
		window = const_ptr_add_offset(maxscan, fill);
		if (ptr_cmp(window, max) <= 0)
			maxscan = window;
	}

	BACKTRACE_RETURN("%p", NULL);
}

static int mingw_inspect_stack(const void *sp, int words, const void *start);

/**
 * Parse beginning of routine to know how many registers are saved, whether
 * there is a leading frame being formed, and how large the stack is.
 *
 * @param pc			starting point
 * @param max			maximum PC we accept to scan forward
 * @param sp			known stack pointer
 * @param at_start		known to be at the starting point of the routine
 * @param has_frame		set to TRUE if we saw a frame linking at the beginning
 * @param savings		indicates leading register savings done by the routine
 * @param offset		computed stack offsetting
 *
 * @return TRUE if ``pc'' pointed to a recognized function prologue.
 */
static bool
mingw_analyze_prologue(const void *pc, const void *max, const void *sp,
	bool at_start, bool *has_frame, size_t *savings, unsigned *offset)
{
	const uint8 *sub;
	int32 subvalue;

	BACKTRACE_ENTRY;
	BACKTRACE_DEBUG(BACK_F_PROLOGUE,
		"starting at PC=%p, max=%p%s, at_start=%s",
		pc, max, ptr_cmp(pc, max) >= 0 ? " (already over!)" : "",
		bool_to_string(at_start));

	if (ptr_cmp(pc, max) >= 0)
		BACKTRACE_RETURN("%d", FALSE);

	sub = mingw_find_esp_subtract(pc, max, at_start, has_frame, savings);

	if (MINGW_EMPTY_STACKFRAME == sub) {
		BACKTRACE_DEBUG(BACK_F_PROLOGUE,
			"%s: no SUB operation at pc=%p, %s frame",
			G_STRFUNC, pc, *has_frame ? "with" : "no");
		*offset = 0;
		BACKTRACE_RETURN("%d", TRUE);
	} else if (sub != NULL) {
		uint8 op;

		BACKTRACE_DEBUG(BACK_F_PROLOGUE,
			"%s: found SUB operation at "
			"pc=%p, opcode=0x%x, mod=0x%x, %s frame",
			G_STRFUNC, sub, sub[0], sub[1], *has_frame ? "with" : "no");

		switch (*sub) {
		case OPCODE_SUB_1:
			/*
			 * This is the pattern used by gcc for large stacks.
			 *
			 * (Note this uses AT&T syntax, not the Intel one, so
			 * order is source, destination as opposed to the regular
			 * Intel convention)
			 *
			 *    movl    $65564, %eax
			 *    call    ___chkstk_ms
			 *    subl    %eax, %esp
			 *
			 * We found the last instruction, we need to move back 10
			 * bytes to reach the MOV instruction
			 */

			op = *(sub - 10);
			if (op != OPCODE_MOV_IMM_EAX)
				BACKTRACE_RETURN("%d", FALSE);

			subvalue = peek_le32(sub - 9);	/* Read immediate offset of MOVL */
			goto check_offset;
		case OPCODE_SUB_2:
			/* subl    $220, %esp */
			if (OPMODE_SUB_ESP == sub[1])
				subvalue = peek_le32(sub + 2);
			else if (OPMODE_ADD_ESP == sub[1])
				subvalue = -peek_le32(sub + 2);
			else
				g_assert_not_reached();
			goto check_offset;
		case OPCODE_SUB_3:
			/* subl    $28, %esp */
			{
				int8 val = peek_u8(&sub[2]);

				if (OPMODE_SUB_ESP == sub[1])
					subvalue = val;
				else if (OPMODE_ADD_ESP == sub[1])
					subvalue = -val;
				else
					g_assert_not_reached();
			}
			goto check_offset;
		}
		g_assert_not_reached();
	}

	/*
	 * Maybe this routine does not need to adjust the stack pointer if
	 * it has no local variables.  Inspect the stack to see if there is
	 * a return address that fits and use the computed offset.
	 *
	 * We are only retaining positive offsets for now: since the stack
	 * grows down, a negative offset would mean the stack pointer is
	 * not right.
	 */

	BACKTRACE_DEBUG(BACK_F_PROLOGUE,
		"%s: no SUB found, analyzing stack (%s frame)",
		G_STRFUNC, *has_frame ? "has" : "no");

	{
		int calloff = mingw_inspect_stack(sp, MINGW_SP_INSPECT, pc);

		if (calloff == INT_MAX) {
			BACKTRACE_DEBUG(BACK_F_PROLOGUE | BACK_F_PC,
				"%s: no valid PC candidate on the stack", G_STRFUNC);
		} else if (calloff < 0) {
			BACKTRACE_DEBUG(BACK_F_PROLOGUE | BACK_F_PC,
				"%s: ignoring negative offset %d", G_STRFUNC, calloff);
		} else {
			BACKTRACE_DEBUG(BACK_F_PROLOGUE | BACK_F_PC,
				"%s: using offset %d", G_STRFUNC, calloff);
			*offset = calloff * sizeof(int32);
			BACKTRACE_RETURN("%d", TRUE);
		}

		/* FALL THROUGH */
	}

	BACKTRACE_RETURN("%d", FALSE);

check_offset:

	*offset = subvalue;

	BACKTRACE_DEBUG(BACK_F_PROLOGUE,
		"%s: offset is %u at pc=%p, opcode=0x%x, mod=0x%x, subvalue=%d",
		G_STRFUNC, *offset, sub, sub[0], sub[1], subvalue);

	/*
	 * Offsets must be a multiple of 4.  Otherwise, we're not parsing
	 * the opcodes correctly, or rather they are not what we think
	 * they are (random garbage due to wrong location, for instance).
	 */

	if (0 == (*offset & 3))
		BACKTRACE_RETURN("%d", TRUE);

	BACKTRACE_DEBUG(BACK_F_PROLOGUE,
		"%s: offset was %u, not a multiple of 4 bytes, "
		"pc=%p, opcode=0x%x, mod=0x%x",
		G_STRFUNC, *offset, sub, sub[0], sub[1]);

	BACKTRACE_RETURN("%d", FALSE);
}

/**
 * Check whether there is a call instruction before the given PC address.
 *
 * @param pc		supposed returned address
 * @param target	call target, if we can determine it (otherwise set to NULL)
 *
 * @return TRUE if we found a call instruction, with `target' set if possible.
 */
static bool
mingw_has_call_before(const void *pc, void **target)
{
	const uint8 *p;

	BACKTRACE_ENTRY;

	if (target != NULL)
		*target = NULL;		/* Assume we can't determine target */

	if (!valid_ptr(pc))
		BACKTRACE_RETURN("%d", FALSE);

	/*
	 * The only possible call at this offset is an indirect register
	 * call, like "call *%eax", which would be coded "FF D0" or
	 * "call *(%edx)" which would be coded "FF 12"..
	 */

	p = const_ptr_add_offset(pc, -2);
	if (!valid_ptr(p))
		BACKTRACE_RETURN("%d", FALSE);

	if (OPCODE_CALL_IND == peek_u8(p)) {
		uint8 nb = peek_u8(p+ 1);	/* Necessarily valid pointer */
		uint8 mod = mingw_op_mod_code(nb);

		/*
		 * Since FF is a versatile prefix, we need to look at the REG
		 * in the MOD-REG-R/M byte that follows and see a 2 there
		 * (the CALL instruction is FF/2).  Since we are only at -2
		 * this cannot be a far call (FF/3): we would need more bytes
		 * between FF and the supposed return address!
		 */

		if (2 == mingw_op_extra(nb) && (0 == mod || 3 == mod)) {
			BACKTRACE_DEBUG(BACK_F_PC, "indirect near call found at -2");
			BACKTRACE_RETURN("%d", TRUE);
		}
		/* FALL THROUGH */
	}

	/*
	 * Here the only possible call is an indirect register call with an
	 * offset, such as "call *0x28(%eax)" which would be coded "FF 50 28".
	 */

	p--;
	if (!valid_ptr(p))
		BACKTRACE_RETURN("%d", FALSE);

	if (OPCODE_CALL_IND == peek_u8(p)) {
		uint8 nb = peek_u8(p+ 1);	/* Necessarily valid pointer */
		uint8 mod = mingw_op_mod_code(nb);

		/*
		 * Same logic as above, we need to validate this is an FF/2
		 * instruction.
		 */
		if (2 == mingw_op_extra(nb) && 1 == mod) {
			BACKTRACE_DEBUG(BACK_F_PC, "indirect near call found at -3");
			BACKTRACE_RETURN("%d", TRUE);
		}
		/* FALL THROUGH */
	}

	/*
	 * Move back 1 byte for a register indirect FF/3 call, followed by
	 * 2 bytes.
	 */

	p--;
	if (!valid_ptr(p))
		BACKTRACE_RETURN("%d", FALSE);

	if (OPCODE_CALL_IND == peek_u8(p)) {
		uint8 nb = peek_u8(p+ 1);	/* Necessarily valid pointer */

		if (3 == mingw_op_extra(nb)) {
			/* Don't know how to disassemble those, really, accept as-is */
			BACKTRACE_DEBUG(BACK_F_PC, "indirect far call found at -4");
			BACKTRACE_RETURN("%d", TRUE);
		}
	}

	/*
	 * Move back 1 byte for a near-call with immediate 32-bit signed
	 * offset, such as "E8 28 43 FD FF"
	 */

	p--;
	if (!valid_ptr(p))
		BACKTRACE_RETURN("%d", FALSE);

	if (OPCODE_CALL_NEAR == peek_u8(p)) {
		int offset = peek_le32(p + 1);
		void *dest = deconstify_pointer(const_ptr_add_offset(pc, offset));
		if (target != NULL)
			*target = dest;
		BACKTRACE_DEBUG(BACK_F_PC,
			"immediate near call found at -5, offset %d relative to PC=%p"
			" -> %p (%s)",
			offset, pc, dest, mingw_routine_name(dest));
		BACKTRACE_RETURN("%d", TRUE);
	}

	/*
	 * Move back 1 byte for a far FF/2 call.
	 */

	p--;
	if (!valid_ptr(p))
		BACKTRACE_RETURN("%d", FALSE);

	if (OPCODE_CALL_IND == peek_u8(p)) {
		uint8 nb = peek_u8(p+ 1);	/* Necessarily valid pointer */
		uint8 mod = mingw_op_mod_code(nb);
		uint8 rm = mingw_op_rm_code(nb);
		uint32 *loc = ulong_to_pointer(peek_le32(p + 2));

		if (2 == mingw_op_extra(nb) && 0 == mod && 5 == rm) {
			BACKTRACE_DEBUG(BACK_F_PC,
				"indirect far call found at -6 in %p", loc);
			/* Only dereference if aligned and readable */
			if (0 == (pointer_to_ulong(loc) & 0x3) && valid_ptr(loc)) {
				void *dest = ulong_to_pointer(*loc);
				if (target != NULL)
					*target = dest;
				BACKTRACE_DEBUG(BACK_F_PC,
					"call destination stored in %p is %p (%s)",
					loc, dest, mingw_routine_name(dest));
			}
			BACKTRACE_RETURN("%d", TRUE);
		}
		/* FALL THROUGH */
	}

	BACKTRACE_DEBUG(BACK_F_PC,
		"no CALL found in previous 6 bytes %02x %02x %02x %02x %02x %02x from %p",
		peek_u8(p), peek_u8(p + 1), peek_u8(p+2),
		peek_u8(p + 3), peek_u8(p + 4), peek_u8(p + 5), pc);

	BACKTRACE_RETURN("%d", FALSE);
}

/**
 * Inspect `words' 32-bit words before and after the given stack pointer.
 *
 * @param sp		the stack pointer
 * @param words		how many words to scan around sp
 * @param start		known routine start
 *
 * @return the best offset that yields a call, INT_MAX if no call found.
 */
static int
mingw_inspect_stack(const void *sp, int words, const void *start)
{
	int i;
	int match = INT_MAX;

	BACKTRACE_ENTRY;

	BACKTRACE_DEBUG(BACK_F_PC, "inspecting %d word%s around SP=%p",
		PLURAL(words), sp);

	for (i = 0; i < 2 * words + 1; i++) {
		int off;
		const void *p;

		if (0 == i)
			off = 0;			/* First attempt: at the supplied SP */
		else if (i <= words)	/* -1, -2, ... -words */
			off = -i;
		else
			off = i - words;	/* 1, 2, ... words */

		p = const_ptr_add_offset(sp, off * sizeof(int32));

		if (valid_ptr(p)) {
			void *target;
			const void *v = ulong_to_pointer(peek_le32(p));
			bool has_call = mingw_has_call_before(v, &target);
			if (has_call && target != NULL) {
				BACKTRACE_DEBUG(BACK_F_PC,
					"SP[%d] = %p (%s) has CALL to %p (our %sstart is %p)",
					off, v, mingw_routine_name(v), target,
					target == start ? "*matching* " : "", start);
				if (target == start)
					match = off;		/* Always record perfect match! */
			} else {
				BACKTRACE_DEBUG(BACK_F_PC,
					"SP[%d] = %p (%s)%s",
					off, v, mingw_routine_name(v),
					has_call ? " has CALL" : "");
				if (has_call && INT_MAX == match)
					match = off;		/* Record first match */
			}
		} else {
			BACKTRACE_DEBUG(BACK_F_PC,
				"SP[%d] is an invalid pointer (%p)?", off, p);
		}
	}

	BACKTRACE_RETURN("%d", match);
}

/**
 * Intuit return address given current PC and SP.
 *
 * Uses black magic: disassembles the code on the fly knowing the gcc
 * initial function patterns to look for the instruction that alters the SP.
 *
 * @attention
 * This is not perfect and based on heuristics.  Changes in the compiler
 * generation pattern may break this routine.  Moreover, backtracing through
 * a routine using alloca() will not work because the initial stack reserve is
 * later altered, so the stack pointer in any routine that it calls will be
 * perturbed and will not allow correct reading of the return address.
 *
 * @param next_pc		where next PC is written
 * @param next_sp		where next SP is written
 * @param next_sf		where next SF is written, NULL if none seen
 *
 * @return TRUE if we were able to recognize the start of the routine and
 * compute the proper stack offset, FALSE otherwise.
 */
static bool
mingw_get_return_address(const void **next_pc, const void **next_sp,
	const void **next_sf)
{
	const void *pc = *next_pc;
	const void *sp = *next_sp;
	const void *start = NULL;
	const uint8 *p;
	unsigned offset = 0;
	bool has_frame = FALSE;
	size_t savings = 0;

	BACKTRACE_ENTRY;
	BACKTRACE_DEBUG(BACK_F_RA, "%s: pc=%p, sp=%p", G_STRFUNC, pc, sp);

	/*
	 * If we can determine the start of the routine, get there first.
	 *
	 * We substract 1 because when the return address is pushed, it is
	 * after the previous instruction (a CALL or a JMP) and when calling
	 * a non-returning routine, the pc will lie outside the routine and
	 * will point to the next routine in the code.
	 */

	p = stacktrace_routine_start(pc - 1);

	if (p != NULL && valid_ptr(p)) {
		BACKTRACE_DEBUG(BACK_F_NAME | BACK_F_RA,
			"%s: known routine start for pc=%p is %p (%s)",
			G_STRFUNC, pc, p, mingw_routine_name(p));

		if (
			mingw_analyze_prologue(p, pc, sp, TRUE, &has_frame, &savings, &offset)
		) {
			start = p;
			goto found_offset;
		}

		BACKTRACE_DEBUG(BACK_F_RA,
			"%s: %p does not seem to be a valid prologue, scanning",
			G_STRFUNC, p);
	} else {
		BACKTRACE_DEBUG(BACK_F_NAME | BACK_F_RA,
			"%s: pc=%p falls in %s from %s", G_STRFUNC, pc,
			mingw_routine_name(pc), dl_util_get_path(pc));
	}

	BACKTRACE_DEBUG(BACK_F_RA,
		"%s: scanning backwards from %p to find prologue",
		G_STRFUNC, pc);

	/*
	 * Scan backwards to find a previous RET / JMP / NOP / LEA instruction,
	 * that could mark the end of a previous routine.
	 *
	 * We also look for a "push %ebp; mov %esp,%ebp" sequence that would
	 * definitely indicate the start of a routine.
	 */

	for (p = pc; ptr_diff(pc, p) < MINGW_MAX_ROUTINE_LENGTH; /* empty */) {
		uint8 op, pop;
		const uint8 *next = p;

		if (!valid_ptr(p) || !valid_ptr(p - 1))
			BACKTRACE_RETURN("%d", FALSE);

		/*
		 * Because this is a CISC processor, single-byte opcodes could actually
		 * be part of a longer 2-byte instruction.  A likely candidate we want
		 * to avoid is a MOV between registers, where the second byte would
		 * encode the registers.
		 */

		pop = *(p - 1);
		if (OPCODE_MOV_REG == pop || OPCODE_MOV_REGI == pop) {
			BACKTRACE_DEBUG(BACK_F_RA,
				"%s: skipping %s operation at pc=%p, opcode=0x%x (after a MOV)",
				G_STRFUNC, mingw_opcode_name(*p), p, *p);
			goto next;
		}

		switch ((op = *p)) {
		case OPCODE_PUSH_EBP:
			/*
			 * To maximize chances of this being a valid routine start,
			 * we look for at least 3 bytes (including the PUSH we just
			 * scanned).
			 */
			switch (p[1]) {
			case OPCODE_MOV_REG:
				if (OPMODE_REG_ESP_EBP == p[2]) {
					BACKTRACE_DEBUG(BACK_F_RA,
						"%s: found PUSH EBP; MOV EBP,ESP sequence at pc=%p",
						G_STRFUNC, p);
					goto analyze;
				}
				break;
			case OPCODE_MOV_REGI:
				if (OPMODE_REG_EBP_ESP == p[2]) {
					BACKTRACE_DEBUG(BACK_F_RA,
						"%s: found PUSH EBP; MOV EBP,ESP sequence at pc=%p",
						G_STRFUNC, p);
					goto analyze;
				}
				break;
			/* Only look for callee-saved registers */
			case OPCODE_PUSH_EBX:
			case OPCODE_PUSH_ESI:
			case OPCODE_PUSH_EDI:
				/* Only look for callee-saved registers */
				if (p[2] >= OPCODE_PUSH_EBX && p[2] <= OPCODE_PUSH_EDI) {
					BACKTRACE_DEBUG(BACK_F_RA,
						"%s: found PUSH EBP; PUSH; PUSH sequence at pc=%p",
						G_STRFUNC, p);
					goto analyze;
				}
				switch (p[2]) {
				case OPCODE_SUB_1:
				case OPCODE_SUB_2:
				case OPCODE_SUB_3:
					if (mingw_opcode_is_sub_esp(&p[2], p[2])) {
						BACKTRACE_DEBUG(BACK_F_RA,
							"%s: found PUSH EBP; PUSH; SUB ESP sequence at pc=%p",
							G_STRFUNC, p);
						goto analyze;
					}
				}
				break;
			}
			goto next;
		case OPCODE_LEA:
			next = p + mingw_opcode_lea_length(p);
			break;
		case OPCODE_NOP:
		case OPCODE_RET_NEAR:
		case OPCODE_RET_FAR:
			next = p + 1;
			break;
		case OPCODE_RET_NEAR_POP:
		case OPCODE_RET_FAR_POP:
			next = p + 3;	/* Skip next immediate 16-bit offset */
			break;
		case OPCODE_JMP_SHORT:
			next = p + 2;	/* Skip 8-bit offset */
			break;
		case OPCODE_JMP_LONG:
			next = p + 5;	/* Skip 32-bit target */
			break;
		default:
			goto next;
		}

		BACKTRACE_DEBUG(BACK_F_RA,
			"%s: found %s operation at pc=%p, opcode=0x%x",
			G_STRFUNC, mingw_opcode_name(op), p, op);

	analyze:
		/*
		 * Could have found a byte that is part of a longer opcode, since
		 * the x86 has variable-length instructions.
		 *
		 * Scan forward for a SUB instruction targetting the ESP register.
		 */

		if (
			mingw_analyze_prologue(next, pc, sp, FALSE,
				&has_frame, &savings, &offset)
		) {
			start = next;
			goto found_offset;
		}

	next:
		p--;
	}

	BACKTRACE_RETURN("%d", FALSE);

found_offset:
	g_assert(0 == (offset & 3));	/* Multiple of 4 */

	BACKTRACE_DEBUG(BACK_F_RA, "%s: offset = %u, %zu leading push%s",
		G_STRFUNC, offset, PLURAL_ES(savings));

	/*
	 * We found that the current routine decreased the stack pointer by
	 * ``offset'' bytes upon entry.  It is expected to increase the stack
	 * pointer by the same amount before returning, at which time it will
	 * pop from the stack the return address.
	 *
	 * This is what we're computing now, to find out the return address
	 * that is on the stack.
	 *
	 * Once it pops the return address, the processor will also increase the
	 * stack pointer by 4 bytes, so this will be the value of ESP upon return.
	 *
	 * Moreover, if we have seen a "PUSH EBP; MOV EBP, ESP" sequence at the
	 * beginning, then the stack frame pointer was maintained by the callee.
	 * In AT&T syntax (which reverses the order of arguments compared to the
	 * Intel notation, becoming source, destination) used by gas, that would be:
	 *
	 *     pushl   %ebp
	 *     movl    %esp, %ebp           ; frame linking now established
	 *     subl    $56, %esp            ; reserve 56 bytes on the stack
	 */

	offset += 4 * savings;
	sp = const_ptr_add_offset(sp, offset);

	/*
	 * Look around SP to find a next PC that makes sense, i.e. a place which
	 * was preceded by a call.
	 *
	 * If we don't find any, calloff will be INT_MAX.  If all went well and
	 * we figured the initial SP displacement at the beginning of the routine,
	 * we should get a calloff of 0, meaning: the current SP pointer holds
	 * a return address that is indeed preceded by a CALL, making it a valid
	 * return address.
	 * 		--RAM, 2018-10-11
	 */

	{
		int calloff = mingw_inspect_stack(sp, MINGW_SP_INSPECT, start);

		if (INT_MAX != calloff && 0 != calloff) {
			int off = calloff * sizeof(int32);
			BACKTRACE_DEBUG(BACK_F_PC | BACK_F_RA,
				"adjusting SP by %+d bytes to get a probable return address",
				off);
			sp = const_ptr_add_offset(sp, off);
		}
	}

	if (has_frame) {
		const void *sf, *fp;
		g_assert(savings >= 1);
		sf = const_ptr_add_offset(sp, -4);

		if (!valid_ptr(sf)) {
			BACKTRACE_DEBUG(BACK_F_RA,
				"%s: invalid stack frame location %p", G_STRFUNC, sf);
			*next_sf = NULL;
			goto next_pc;
		}

		fp = ulong_to_pointer(peek_le32(sf));
		if (ptr_cmp(fp, sp) <= 0) {
			BACKTRACE_DEBUG(BACK_F_RA,
				"%s: inconsistent fp %p (\"above\" sp %p)", G_STRFUNC, fp, sp);
			has_frame = FALSE;
		} else if (!vmm_is_stack_pointer(fp, sf)) {
			BACKTRACE_DEBUG(BACK_F_RA,
				"%s: invalid fp %p (not a stack pointer)", G_STRFUNC, fp);
			has_frame = FALSE;
		}
		*next_sf = has_frame ? fp : NULL;
	} else {
		*next_sf = NULL;
	}

next_pc:
	if (NULL == *next_sf)
		has_frame = FALSE;

	if (!valid_ptr(sp)) {
		BACKTRACE_DEBUG(BACK_F_PC | BACK_F_RA,
			"%s: invalid SP %p (bad pointer)", G_STRFUNC, sp);
		BACKTRACE_RETURN("%d", FALSE);
	}

	*next_pc = ulong_to_pointer(peek_le32(sp));	/* Pushed return address */

	if (!valid_ptr(*next_pc)) {
		BACKTRACE_DEBUG(BACK_F_PC | BACK_F_RA,
			"%s: invalid PC %p on stack (not a valid pointer)",
			G_STRFUNC, *next_pc);
		BACKTRACE_RETURN("%d", FALSE);
	}

	if (!mingw_has_call_before(*next_pc, NULL)) {
		BACKTRACE_DEBUG(BACK_F_PC | BACK_F_RA,
			"%s: invalid SP %p: no CALL before SP[0] = %p",
			G_STRFUNC, sp, *next_pc);
		BACKTRACE_RETURN("%d", FALSE);
	}

	*next_sp = const_ptr_add_offset(sp, 4);	/* After popping return address */

	BACKTRACE_DEBUG(BACK_F_PC | BACK_F_RA,
		"%s: next PC=%p (%s), next SP=%p (after popping PC)",
		G_STRFUNC, *next_pc, mingw_routine_name(*next_pc), *next_sp);

	if (
		mingw_backtrace_debug() &&
		(BACK_F_RA & MINGW_BACKTRACE_FLAGS) &&
		has_frame
	) {
		const struct stackframe *sf = *next_sf;
		(void) sf;		/* Suppress warning if not debugging */
		mingw_debug_log("%s: next frame at %p "
			"(contains next=%p, ra=%p), computed ra=%p",
			G_STRFUNC, sf, sf->next, sf->ret, *next_pc);
	}

	BACKTRACE_RETURN("%d", TRUE);
}

/**
 * Unwind the stack, using the saved context to gather the initial program
 * counter, stack pointer and stack frame pointer.
 *
 * @param buffer	where function addresses are written to
 * @param size		amount of entries in supplied buffer
 * @param c			saved CPU context
 * @param offset	topmost frames to skip
 */
static int
mingw_stack_unwind(void **buffer, int size, CONTEXT *c, int skip)
{
	int i = 0;
	const struct stackframe *sf;
	const void *sp, *pc, *top, *prev_sp;

	BACKTRACE_ENTRY;

	/*
	 * We used to rely on StackWalk() here, but we no longer do because
	 * it did not work well and failed to provide useful stacktraces.
	 *
	 * Neither does blind following of frame pointers because some routines
	 * simply do not bother to maintain the frame pointers, especially
	 * those known by gcc as being non-returning routines such as
	 * assertion_abort(). Plain stack frame following could not unwind
	 * past that.
	 *
	 * Since it is critical on Windows to obtain a somewhat meaningful
	 * stack frame to be able to debug anything, given the absence of
	 * core dumps (for post-mortem analysis) and of fork() (for launching
	 * a debugger to obtain the stack trace), extraordinary measures were
	 * called for...
	 *
	 * Therefore, we now perform our own unwinding which does not rely on
	 * plain stack frame pointer following but rather (minimally)
	 * disassembles the routine prologues to find out how many stack
	 * space is used by each routine, so that we can find where the
	 * caller pushed the return address on the stack.
	 *
	 * When the start of a routine is not known, the code attempts to
	 * guess where it may be by scanning backwards until it finds what
	 * is probably the end of the previous routine.  Since the x86 is a
	 * CISC machine with a variable-length instruction set, this operation
	 * cannot be entirely fool-proof, since the opcodes used for RET or
	 * JMP instructions could well be actually parts of immediate operands
	 * given to some other instruction.
	 *
	 * Hence there is logic to determine whether the initial starting point
	 * is actually a valid routine prologue, relying on what we know gcc
	 * can use before it adjusts the stack pointer.
	 *
	 * Despite being a hack because it is based on known routine generation
	 * patterns from gcc, it works surprisingly well and, in any case, is
	 * far more useful than the original code that used StackWalk(), or
	 * the simple gcc unwinding which merely follows frame pointers.
	 *		--RAM, 2012-03-19
	 */

	sf = ulong_to_pointer(c->Ebp);
	sp = ulong_to_pointer(c->Esp);
	pc = ulong_to_pointer(c->Eip);

	BACKTRACE_DEBUG(BACK_F_DRIVER,
		"%s: pc=%p, sf=%p, sp=%p [skip %d] (current SP=%p)",
		G_STRFUNC, pc, sf, sp, skip, &i);

	if (0 == skip--) {
		BACKTRACE_DEBUG(BACK_F_RESULT,
			"%s: pushing %p (%s) at i=%d upon entry",
			G_STRFUNC, pc, mingw_routine_name(pc), i);
		buffer[i++] = deconstify_pointer(pc);
	} else {
		BACKTRACE_DEBUG(BACK_F_RESULT,
			"%s: skipping %p (%s); %d more to skip upon entry",
			G_STRFUNC, pc, mingw_routine_name(pc), skip);
	}

	if (!valid_stack_ptr(sp, sp))
		BACKTRACE_RETURN("%d", i);

	prev_sp = top = sp;
	BACKTRACE_DEBUG(BACK_F_DRIVER, "%s: stack top is %p", G_STRFUNC, top);

	while (i < size) {
		const void *next = NULL;

		BACKTRACE_DEBUG(BACK_F_DRIVER,
			"%s: i=%d, sp=%p, sf=%p, pc=%p", G_STRFUNC, i, sp, sf, pc);

		if (!valid_ptr(pc)) {
			BACKTRACE_DEBUG(BACK_F_DRIVER, "%s: invalid PC, stop!", G_STRFUNC);
			break;
		}

		if (!valid_stack_ptr(sp, top)) {
			BACKTRACE_DEBUG(BACK_F_DRIVER, "%s: invalid SP, stop!", G_STRFUNC);
			break;
		}

		if (sf != NULL && !valid_stack_ptr(sf, top)) {
			BACKTRACE_DEBUG(BACK_F_DRIVER,
				"%s: clearing sf=%p (top of stack is %p)", G_STRFUNC, sf, top);
			sf = NULL;
		} else if (sf != NULL && ptr_cmp(sf, sp) <= 0) {
			BACKTRACE_DEBUG(BACK_F_DRIVER,
				"%s: clearing sf=%p (\"above\" sp=%p)", G_STRFUNC, sf, sp);
			sf = NULL;
		}

		if (!mingw_get_return_address(&pc, &sp, &next)) {
			if (sf != NULL) {
				BACKTRACE_DEBUG(BACK_F_DRIVER,
					"%s: trying to follow sf=%p", G_STRFUNC, sf);

				next = sf->next;
				if (!valid_ptr(sf->ret)) {
					BACKTRACE_DEBUG(BACK_F_DRIVER,
						"%s: invalid PC=%p in frame", G_STRFUNC, sf->ret);
					break;
				}

				pc = sf->ret;
				sp = &sf[1];	/* After popping returned value */

				/*
				 * When debugging, spot PC in frames that are definitely
				 * invalid due to lack of CALL instruction preceding them!
				 */

				if (mingw_backtrace_debug()) {
					void *target;

					BACKTRACE_DEBUG(BACK_F_DRIVER | BACK_F_PC,
						"%s: candidate PC=%p", G_STRFUNC, pc);

					if (!mingw_has_call_before(pc, &target)) {
						BACKTRACE_DEBUG(BACK_F_DRIVER | BACK_F_PC,
							"%s: WARNING: no CALL found before PC=%p",
							G_STRFUNC, pc);
					} else {
						BACKTRACE_DEBUG(BACK_F_DRIVER | BACK_F_PC,
							"%s: has CALL before PC=%p, target=%p (%s)",
							G_STRFUNC, pc, target, NULL == target ?
								"unknown target" : mingw_routine_name(target));
					}
				}

				BACKTRACE_DEBUG(BACK_F_DRIVER,
					"%s: following frame: next sf=%p, pc=%p, rebuilt sp=%p",
					G_STRFUNC, next, pc, sp);

				if (
						next != NULL &&
						(!valid_stack_ptr(next, top) || ptr_cmp(next, sf) <= 0)
				) {
					BACKTRACE_DEBUG(BACK_F_DRIVER,
						"%s: clearing inconsistent next sf=%p", G_STRFUNC, next);
					next = NULL;
				}
			} else {
				BACKTRACE_DEBUG(BACK_F_DRIVER, "%s: out of frames", G_STRFUNC);
				break;
			}
		} else {
			int d;

			BACKTRACE_DEBUG(BACK_F_DRIVER,
				"%s: intuited next pc=%p, sp=%p, rebuilt sf=%p [old sf=%p]",
				G_STRFUNC, pc, sp, next, sf);

			/*
			 * Leave frame pointer intact if the stack pointer is still
			 * smaller than the last frame pointer: it means the routine
			 * that we backtraced through did not save a frame pointer, so
			 * it would have been invisible if we had followed the frame
			 * pointer.
			 */

			d = (NULL == sf) ? 0 : ptr_cmp(sp, sf);

			if (d < 0) {
				BACKTRACE_DEBUG(BACK_F_DRIVER,
					"%s: keeping old sf=%p, since sp=%p", G_STRFUNC, sf, sp);
				next = sf;
			} else if (d > 0) {
				if (sp == &sf[1]) {
					BACKTRACE_DEBUG(BACK_F_DRIVER,
						"%s: reached sf=%p at sp=%p, next sf=%p, current ra=%p",
						G_STRFUNC, sf, sp, sf->next, sf->ret);
					if (NULL == next && valid_stack_ptr(sf->next, top))
						next = sf->next;
				}
			}
		}

		if (skip-- <= 0) {
			/*
			 * Detect loops, since we can now adjust the SP negatively.
			 */

			if (
				i > 0 && deconstify_pointer(pc) == buffer[i-1] &&
				ptr_cmp(prev_sp, sp) >= 0
			) {
				BACKTRACE_DEBUG(BACK_F_RESULT,
					"%s: stuck at %p (%s) at i=%d: previous SP=%p, current SP=%p",
					G_STRFUNC, pc, mingw_routine_name(pc), i, prev_sp, sp);
				break;
			}

			BACKTRACE_DEBUG(BACK_F_RESULT,
				"%s: pushing %p (%s) at i=%d",
				G_STRFUNC, pc, mingw_routine_name(pc), i);
			buffer[i++] = deconstify_pointer(pc);
		} else {
			BACKTRACE_DEBUG(BACK_F_RESULT,
				"%s: skipping %p (%s); %d more to skip",
				G_STRFUNC, pc, mingw_routine_name(pc), skip);
		}

		sf = next;
		prev_sp = sp;
	}

	if (mingw_backtrace_debug()) {
		int j;

		BACKTRACE_DEBUG(BACK_F_RESULT,
			"stack returned has %d element%s:", PLURAL(i));

		for (j = 0; j < i; j++) {
			BACKTRACE_DEBUG(BACK_F_RESULT,
				"#%d: %p (%s)", j, buffer[j], mingw_routine_name(buffer[j]));
		}
	}

	BACKTRACE_RETURN("%d", i);
}

/**
 * Fill supplied buffer with current stack, skipping the topmost frames.
 *
 * @param buffer	where function addresses are written to
 * @param size		amount of entries in supplied buffer
 * @param offset	topmost frames to skip
 *
 * @return amount of entries written into buffer[].
 */
int
mingw_backtrace(void **buffer, int size, size_t offset)
{
	CONTEXT c;
	HANDLE thread;

	thread = GetCurrentThread();

	ZERO(&c);
	c.ContextFlags = CONTEXT_FULL;

	/*
	 * We'd need RtlCaptureContext() but it's not avaialable through MinGW.
	 *
	 * Although MSDN says the context will be corrupted, we're not doing
	 * context-switching here.  What's important is that the stack addresses
	 * be filled, and experience shows they are properly filled in.
	 */

	GetThreadContext(thread, &c);

	return mingw_stack_unwind(buffer, size, &c, offset);
}

#ifdef EMULATE_DLADDR
static int mingw_dl_error;

/**
 * Return a human readable string describing the most recent error
 * that occurred.
 *
 * It returns NULL if no errors have occurred since initialization
 * or since it was last called.
 */
const char *
mingw_dlerror(void)
{
	int e = mingw_dl_error;

	if (0 == e)
		return NULL;

	mingw_dl_error = 0;

	return g_strerror(e);
}

/**
 * Emulates linux's dladdr() routine.
 *
 * Given a function pointer, try to resolve name and file where it is located.
 *
 * If no symbol matching addr could be found, then dli_sname and dli_saddr are
 * set to NULL.
 *
 * @param addr		pointer within function
 * @param info		where results are returned
 *
 * @return 0 on error, non-zero on success.
 */
int
mingw_dladdr(void *addr, Dl_info *info)
{
	static uint64 loaded_library_count;
	static bool initialized;
	static bool reload_symbols;
	static wchar_t wpath[MAX_PATH_LEN];
	static char buffer[sizeof(IMAGEHLP_SYMBOL) + 256];
	static mutex_t dladdr_lk = MUTEX_INIT;
	static spinlock_t dladdr_slk = SPINLOCK_INIT;
	buf_t *b = buf_private(G_STRFUNC, MAX_PATH_LEN);
	char *path = buf_data(b);
	size_t pathsz = buf_size(b);
	buf_t *name = buf_private("mingw_dladdr:name", 255);
	uint64 current_loaded_library_count;
	int error = 0;
	HANDLE process = NULL;
	IMAGEHLP_SYMBOL *symbol = (IMAGEHLP_SYMBOL *) buffer;
	DWORD disp = 0;

	/*
	 * When we detect we have a changed loaded_library_count, we need to
	 * reload the symbols.
	 */

	current_loaded_library_count = win32dlp_loaded_library_count();

	spinlock_hidden(&dladdr_slk);	/* Protect access to static vars */
	if (current_loaded_library_count != loaded_library_count) {
		loaded_library_count = current_loaded_library_count;
		reload_symbols = TRUE;
	}
	spinunlock_hidden(&dladdr_slk);

	/*
	 * When called during a crash, do not attempt to refresh the symbols via
	 * a SymCleanup() / SymInitialize(): use the symbols we already have.
	 *
	 * However, if we never initialized them, then do so regardless of whether
	 * we are crashing.
	 */

	if (!initialized || (reload_symbols && !signal_in_exception())) {
		static bool first_init;
		static spinlock_t dladdr_first_slk = SPINLOCK_INIT;
		bool is_first = FALSE;

		spinlock_hidden(&dladdr_first_slk);
		if (!first_init) {
			is_first = TRUE;
			first_init = TRUE;
		}
		spinunlock_hidden(&dladdr_first_slk);

		if (is_first) {
			mutex_lock_fast(&dladdr_lk);
		} else {
			if (!mutex_trylock_fast(&dladdr_lk))
				goto skip_init;
		}

		process = GetCurrentProcess();

		if (initialized)
			SymCleanup(process);

		if (!SymInitialize(process, NULL, TRUE)) {
			error = mingw_dl_error = GetLastError();
			s_warning("%s(): SymInitialize() failed: error = %d (%s)",
				G_STRFUNC, mingw_dl_error, g_strerror(error));
		} else {
			spinlock_hidden(&dladdr_slk);
			initialized = TRUE;
			reload_symbols = FALSE;
			spinunlock_hidden(&dladdr_slk);
		}

		mutex_unlock_fast(&dladdr_lk);
	}

skip_init:
	ZERO(info);

	if (0 != error)
		return 0;		/* Signals error */

	if (NULL == addr)
		return 1;		/* OK */

	if (NULL == process)
		process = GetCurrentProcess();

	info->dli_fbase = ulong_to_pointer(
		SymGetModuleBase(process, pointer_to_ulong(addr)));

	if (NULL == info->dli_fbase) {
		mingw_dl_error = GetLastError();
		return 0;		/* Unknown, error */
	}

	/*
	 * A spinlock is OK to protect the critical section below because we're
	 * not expecting any recursion: the routines we call out should not
	 * allocate memory nor create assertion failures (which would definitely
	 * create recursion to dump the stack!).
	 *
	 * Note that path or symbol name information are returned in a private
	 * buffer so that two threads can concurrently request dladdr() and yet
	 * be able to get their own results back.
	 */

	spinlock_hidden(&dladdr_slk);	/* Protect access to static vars */

	if (GetModuleFileNameW((HINSTANCE) info->dli_fbase, ARYLEN(wpath))) {
		size_t conv = utf16_to_utf8(wpath, path, pathsz);
		if (conv <= pathsz)
			info->dli_fname = path;		/* Thread-private buffer */
	}

	symbol->SizeOfStruct = sizeof buffer;
	symbol->MaxNameLength = buf_size(name);

	/*
	 * The SymGetSymFromAddr() is mono-threaded, as explained on MSDN,
	 * but we're running under spinlock protection.
	 */

	if (SymGetSymFromAddr(process, pointer_to_ulong(addr), &disp, symbol)) {
		cstr_bcpy(buf_data(name), buf_size(name), symbol->Name);
		info->dli_sname = buf_data(name);	/* Thread-private buffer */
		info->dli_saddr = ptr_add_offset(addr, -disp);
	}

	spinunlock_hidden(&dladdr_slk);	/* Protect access to static vars */

	/*
	 * Windows offsets the actual loading of the text by MINGW_TEXT_OFFSET
	 * bytes, as determined empirically.
	 */

	info->dli_fbase = ptr_add_offset(info->dli_fbase, MINGW_TEXT_OFFSET);

	return 1;			/* OK */
}
#endif	/* EMULATE_DLADDR */

/**
 * Convert exception code to string.
 */
static const char * G_COLD
mingw_exception_to_string(int code)
{
	switch (code) {
	case EXCEPTION_BREAKPOINT:				return "Breakpoint";
	case EXCEPTION_SINGLE_STEP:				return "Single step";
	case EXCEPTION_STACK_OVERFLOW:			return "Stack overflow";
	case EXCEPTION_ACCESS_VIOLATION:		return "Access violation";
	case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:	return "Array bounds exceeded";
	case EXCEPTION_IN_PAGE_ERROR:			return "Paging error";
	case EXCEPTION_DATATYPE_MISALIGNMENT:	return "Bus error";
	case EXCEPTION_FLT_DENORMAL_OPERAND:	return "Float denormal operand";
	case EXCEPTION_FLT_DIVIDE_BY_ZERO:		return "Float divide by zero";
	case EXCEPTION_FLT_INEXACT_RESULT:		return "Float inexact result";
	case EXCEPTION_FLT_INVALID_OPERATION:	return "Float invalid operation";
	case EXCEPTION_FLT_OVERFLOW:			return "Float overflow";
	case EXCEPTION_FLT_STACK_CHECK:			return "Float stack check";
	case EXCEPTION_FLT_UNDERFLOW:			return "Float underflow";
	case EXCEPTION_INT_DIVIDE_BY_ZERO:		return "Integer divide by zero";
	case EXCEPTION_INT_OVERFLOW:			return "Integer overflow";
	case EXCEPTION_ILLEGAL_INSTRUCTION:		return "Illegal instruction";
	case EXCEPTION_PRIV_INSTRUCTION:		return "Privileged instruction";
	case EXCEPTION_NONCONTINUABLE_EXCEPTION:return "Continued after exception";
	case EXCEPTION_INVALID_DISPOSITION:		return "Invalid disposition";
	case EXCEPTION_GUARD_PAGE:				return "Guard page hit";
	default:								return "Unknown exception";
	}
}

/*
 * Format an error message to propagate into the crash log.
 */
static void G_COLD
mingw_crash_record(int code, const void *pc,
	const char *routine, const char *file)
{
	char data[256];
	str_t s;

	str_new_buffer(&s, ARYLEN(data), 0);
	str_printf(&s, "%s at PC=%p", mingw_exception_to_string(code), pc);

	if (routine != NULL)
		str_catf(&s, " (%s)", routine);

	if (file != NULL)
		str_catf(&s, " from %s", file);

	crash_set_error(str_2c(&s));
}

/**
 * Log reported exception.
 */
static void G_COLD
mingw_exception_log(int stid, uint code,
	const void *pc, const void *sp, const struct stackframe *sf)
{
	/* All variables declared static to avoid taking up stack space */
	STATIC_DECLARE_STR(15);
	static char time_buf[CRASH_TIME_BUFLEN];
	static char buf[ULONG_DEC_BUFLEN];
	static char pc_buf[POINTER_BUFLEN];
	static char caller_buf[POINTER_BUFLEN];
	static const char *s, *name, *file = NULL;
	static const void *caller_pc = NULL;

	crash_time_raw(ARYLEN(time_buf));
	name = stacktrace_routine_name_light(pc, NULL);

	if (!stacktrace_pc_within_our_text(pc) && EXCEPTION_STACK_OVERFLOW != code)
		file = dl_util_get_path(pc);

	/*
	 * If we did not get a valid name and file, then the PC is garbage.
	 * Try to intuit our caller from the stackframe pointer given.
	 */

	if (NULL == name && NULL == file) {
		if (valid_stack_ptr(sf, sf) && valid_ptr(sf->ret)) {
			caller_pc = sf->ret;

			/*
			 * Look at the stackframe return address.
			 */

			if (stacktrace_pc_within_our_text(caller_pc)) {
				name = stacktrace_routine_name_light(caller_pc, NULL);
			} else if (EXCEPTION_STACK_OVERFLOW != code) {
				file = dl_util_get_path(caller_pc);
			}

			if (NULL == name && NULL == file)
				caller_pc = NULL;
		}

		/*
		 * Perhaps the caller PC is just on the stack, in case they
		 * de-referenced an invalid function pointer?
		 */

		if (NULL == caller_pc && valid_stack_ptr(sp, sp)) {
			/* Grab the pushed return address at the top of the stack */
			caller_pc = ulong_to_pointer(peek_le32(sp));

			if (stacktrace_pc_within_our_text(caller_pc)) {
				name = stacktrace_routine_name_light(caller_pc, NULL);
			} else if (EXCEPTION_STACK_OVERFLOW != code) {
				file = dl_util_get_path(caller_pc);
			}

			if (NULL == name && NULL == file)
				caller_pc = NULL;
		}
	}

	print_str(time_buf);								/* 0 */
	print_str(" (CRITICAL-");							/* 1 */
	if (stid < 0)
		stid += 256;
	s = PRINT_NUMBER(buf, stid);
	print_str(s);										/* 2 */
	print_str("): received exception at PC=");			/* 3 */
	pointer_to_string_buf(pc, ARYLEN(pc_buf));
	print_str(pc_buf);									/* 4 */
	if (caller_pc != NULL) {
		pointer_to_string_buf(caller_pc, ARYLEN(caller_buf));
		print_str(" probably called from PC=");			/* 5 */
		print_str(caller_buf);							/* 6 */
	}
	if (name != NULL) {
		print_str(" (");								/* 7 */
		print_str(name);								/* 8 */
		print_str(")");									/* 9 */
	}
	if (file != NULL) {
		print_str(" from ");							/* 10 */
		print_str(file);								/* 11 */
	}
	print_str(": ");									/* 12 */
	print_str(mingw_exception_to_string(code));			/* 13 */
	print_str("\n");									/* 14 */

	FLUSH_ERR_STR();

	switch (code) {
	case EXCEPTION_STACK_OVERFLOW:
	case EXCEPTION_GUARD_PAGE:
		break;
	default:
		mingw_crash_record(code, pc, name, file);
	}
}

/**
 * Log extra information on memory faults.
 */
static void G_COLD
mingw_memory_fault_log(int stid, const EXCEPTION_RECORD *er)
{
	DECLARE_STR(8);
	char time_buf[CRASH_TIME_BUFLEN];
	char buf[ULONG_DEC_BUFLEN];
	const char *s, *prot = "unknown";
	const void *va = NULL;

	if (er->NumberParameters >= 2) {
		switch (er->ExceptionInformation[0]) {
		case 0:		prot = "read"; break;
		case 1:		prot = "write"; break;
		case 8:		prot = "execute"; break;
		}
		va = ulong_to_pointer(er->ExceptionInformation[1]);
	}

	crash_time(ARYLEN(time_buf));

	print_str(time_buf);				/* 0 */
	print_str(" (CRITICAL-");			/* 1 */
	if (stid < 0)
		stid += 256;
	s = PRINT_NUMBER(buf, stid);
	print_str(s);						/* 2 */
	print_str("): memory fault (");		/* 3 */
	print_str(prot);					/* 4 */
	print_str(") at VA=");				/* 5 */
	print_str(pointer_to_string(va));	/* 6 */
	print_str("\n");					/* 7 */

	FLUSH_ERR_STR();

	/*
	 * Format an additional error message to propagate into the crash log.
	 */

	{
		char data[80];

		str_bprintf(ARYLEN(data), "; %s fault at VA=%p", prot, va);
		crash_append_error(data);
	}
}

static void *mingw_stack[STACKTRACE_DEPTH_MAX];
static uint8 mingw_excpt[THREAD_MAX];

/**
 * Our default exception handler.
 */
static LONG WINAPI G_COLD
mingw_exception(EXCEPTION_POINTERS *ei)
{
	EXCEPTION_RECORD *er, *en;
	int stid, signo = 0;
	const void *sp, *pc;
	const struct stackframe *sf;

	signal_crashing();
	mingw_activate_backtrace_debug();

	er = ei->ExceptionRecord;
	sp = ulong_to_pointer(ei->ContextRecord->Esp);
	pc = ulong_to_pointer(ei->ContextRecord->Eip);
	sf = ulong_to_pointer(ei->ContextRecord->Ebp);

	stid = thread_safe_small_id_sp(sp);		/* Should be safe to execute */
	if (stid >= 0 && stid < THREAD_MAX)
		mingw_excpt[stid]++;

	/*
	 * Immediately disable interrupt procesing for the faulty thread if we
	 * are facing a stack overflow: handling them would require more stack
	 * space.
	 *
	 * The only operating-system signal we allow is for abort purposes.
	 */

	if (EXCEPTION_STACK_OVERFLOW == er->ExceptionCode) {
		if (stid >= 0 && stid < THREAD_MAX)
			mingw_threads[stid].sig_mask = ~tsig_mask(SIGABRT);
	}

	s_rawwarn("%s in thread #%d (%s) at PC=%p, saved pc=%p, sp=%p, current sp=%p "
		"[depth=%u, count=%d]",
		mingw_exception_to_string(er->ExceptionCode),
		stid, thread_safe_id_name(stid), er->ExceptionAddress,
		pc, sp, thread_sp(),
		(stid >= 0 && stid < THREAD_MAX) ? mingw_excpt[stid] : 0,
		signal_in_exception());

	if (EXCEPTION_STACK_OVERFLOW == er->ExceptionCode)
		s_rawwarn("stack used: %'zu bytes", thread_id_stack_used(stid, sp));

	/*
	 * Dump nested exception records, if any.
	 */

	for (en = er->ExceptionRecord; en; en = en->ExceptionRecord) {
		s_rawwarn("caused by %s at PC=%p",
			mingw_exception_to_string(en->ExceptionCode),
			en->ExceptionAddress);
	}

	mingw_exception_log(stid, er->ExceptionCode, pc, sp, sf);

	switch (er->ExceptionCode) {
	case EXCEPTION_BREAKPOINT:
	case EXCEPTION_SINGLE_STEP:
		signo = SIGTRAP;
		break;
	case EXCEPTION_GUARD_PAGE:
	case EXCEPTION_STACK_OVERFLOW:
		signal_uncrashing();				/* In case we thread_exit() */
		thread_stack_check_overflow(sp);
		signal_crashing();
		signo = SIGSEGV;
		break;
	case EXCEPTION_ACCESS_VIOLATION:
	case EXCEPTION_IN_PAGE_ERROR:
		mingw_memory_fault_log(stid, er);
		/* FALL THROUGH */
	case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:
		signo = SIGSEGV;
		break;
	case EXCEPTION_DATATYPE_MISALIGNMENT:
		signo = SIGBUS;
		break;
	case EXCEPTION_FLT_DENORMAL_OPERAND:
	case EXCEPTION_FLT_DIVIDE_BY_ZERO:
	case EXCEPTION_FLT_INEXACT_RESULT:
	case EXCEPTION_FLT_INVALID_OPERATION:
	case EXCEPTION_FLT_OVERFLOW:
	case EXCEPTION_FLT_STACK_CHECK:
	case EXCEPTION_FLT_UNDERFLOW:
	case EXCEPTION_INT_DIVIDE_BY_ZERO:
	case EXCEPTION_INT_OVERFLOW:
		signo = SIGFPE;
		break;
	case EXCEPTION_ILLEGAL_INSTRUCTION:
	case EXCEPTION_PRIV_INSTRUCTION:
		signo = SIGILL;
		break;
	case EXCEPTION_NONCONTINUABLE_EXCEPTION:
	case EXCEPTION_INVALID_DISPOSITION:
		s_rawwarn("got fatal exception -- crashing.");
		break;
	default:
		s_rawwarn("got unknown exception #%lu -- crashing.", er->ExceptionCode);
		break;
	}

	/*
	 * Core dumps are not a standard Windows feature, so when we terminate
	 * it will be too late to collect information.  Attempt to trace the
	 * stack the process was in at the time of the exception.
	 *
	 * The mingw_stack[] array is in the BSS, not on the stack to minimize
	 * the runtime requirement in the exception routine.
	 *
	 * Because the current stack is apparently a dedicated exception stack,
	 * we have to get a stacktrace from the saved stack context at the
	 * time the exception occurred.  When calling mingw_sigraise(), the
	 * default crash handler will print the exception stack (the current one)
	 * which will prove rather useless.
	 *
	 * We only attempt to unwind the stack when we're hitting the first
	 * exception: recursive calls are not interesting.
	 */

	if (
		EXCEPTION_STACK_OVERFLOW != er->ExceptionCode &&
		(
			(stid >= 0 && stid < THREAD_MAX && 1 == mingw_excpt[stid]) ||
			1 == signal_in_exception()
		)
	) {
		int count;

		count = mingw_stack_unwind(
			mingw_stack, N_ITEMS(mingw_stack), ei->ContextRecord, 0);

		stacktrace_stack_safe_print(STDERR_FILENO, stid, mingw_stack, count);
		if (log_stdout_is_distinct())
			stacktrace_stack_safe_print(STDOUT_FILENO, stid, mingw_stack, count);

		crash_save_stackframe(stid, mingw_stack, count);
	} else if (signal_in_exception() > 5) {
		DECLARE_STR(1);

		print_str("Too many exceptions in a row -- raising SIGBART.\n");
		FLUSH_ERR_STR();
		signo = SIGABRT;
	}

	/*
	 * Synthesize signal, as the UNIX kernel would for these exceptions.
	 */

	if (signo != 0)
		mingw_sigraise(signo, TRUE);

	signal_uncrashing();
	if (stid >= 0 && stid < THREAD_MAX)
		mingw_excpt[stid]--;

	return EXCEPTION_CONTINUE_SEARCH;
}

static inline void WINAPI
mingw_invalid_parameter(const wchar_t * expression,
	const wchar_t * function, const wchar_t * file, unsigned int line,
   uintptr_t pReserved)
{
	(void) expression;
	(void) function;
	(void) pReserved;

	wprintf(L"mingw: Invalid parameter in %s %s:%d\r\n", function, file, line);
}

#ifdef EMULATE_SBRK
static void *current_break;

/**
 * @return the initial break value, as defined by the first memory address
 * where HeapAlloc() allocates memory from.
 */
static void *
mingw_get_break(void)
{
	void *p;
	HANDLE h = GetProcessHeap();

	/*
	 * We try to allocate a large amount of memory (1 MiB) to avoid the call
	 * from returning a "fragment" in the heap, and force the allocator to
	 * get more core, thereby knowing the upper limit.
	 */

	p = HeapAlloc(h, 0, 1024 * 1024);

	if G_UNLIKELY(NULL == p)
		p = HeapAlloc(h, 0, 4096);		/* A page, at least */

	if (NULL == p) {
		errno = ENOMEM;
		return (void *) -1;
	}

	HeapFree(h, 0, p);
	return p;
}

/**
 * Add/remove specified amount of new core.
 *
 * The aim here is not to be able to do a malloc() but rather to mimic
 * what can be achieved on UNIX systems with sbrk().
 *
 * @return the prior break position.
 */
void *
mingw_sbrk(long incr)
{
	void *p;
	void *end;

	if (0 == incr) {
		p = mingw_get_break();
		if G_UNLIKELY(p != (void *) -1)
			current_break = p;
		return current_break;
	} else if (incr > 0) {
		p = HeapAlloc(GetProcessHeap(), 0, incr);

		if (NULL == p) {
			errno = ENOMEM;
			return (void *) -1;
		}

		end = ptr_add_offset(p, incr);

		if (ptr_cmp(end, current_break) > 0)
			current_break = end;

		return p;
	} else if (incr < 0) {

		/*
		 * Don't release memory.  We have no idea how HeapAlloc() and
		 * HeapFree() work, and if they are like malloc(), then HeapFree()
		 * will frown upon a request for releasing core coming from coalesced
		 * blocks.
		 *
		 * That's OK, since sbrk() is only used in gtk-gnutella by xmalloc()
		 * to be able to allocate memory at startup time until the VMM layer
		 * is up.  The unfreed memory won't be lost.
		 *
		 * On Windows, the C runtime should not depend on malloc() however,
		 * so very little memory, if any, should be allocated on the heap
		 * before the VMM layer can be brought up.
		 */

		/* No memory was released, but fake a successful break decrease */
		return ptr_add_offset(current_break, -incr);
	}

	g_assert_not_reached();
}
#endif 	/* EMULATE_SBRK */

static char mingw_stdout_buf[1024];		/* Used as stdout buffer */

static void G_COLD
mingw_stdio_reset(bool console)
{
	/*
	 * A note on setvbuf():
	 *
	 * Setting _IONBF on Windows for output is a really bad idea because
	 * this results in a write for every character emitted.
	 *
	 * Setting _IOLBF on output for "binary" I/O is not working as expected
	 * because of the lack of "\r\n" termination.  It will require explicit
	 * fflush() calls in the logging layer.
	 */

	if (console) {
		int tty;

		tty = isatty(STDIN_FILENO);
		STARTUP_DEBUG("stdin is%s a tty", tty ? "" : "n't");
		if (tty) {
			fclose(stdin);
			close(STDIN_FILENO);
			freopen("CONIN$", "rb", stdin);
		} else {
			setmode(fileno(stdin), O_BINARY);
			STARTUP_DEBUG("forced stdin (fd=%d) to binary mode",
				fileno(stdout));
		}
		setvbuf(stdin, NULL, _IONBF, 0);	/* stdin must be unbuffered */
		tty = isatty(STDOUT_FILENO);
		STARTUP_DEBUG("stdout is%s a tty", tty ? "" : "n't");
		if (tty) {
			fclose(stdout);
			close(STDOUT_FILENO);
			freopen("CONOUT$", "w", stdout);	/* Not "wb" */
			/* stdout to a terminal is line-buffered */
			setvbuf(stdout, mingw_stdout_buf, _IOLBF, sizeof mingw_stdout_buf);
			STARTUP_DEBUG("forced stdout (fd=%d) to buffered "
				"(%lu bytes) binary mode",
				fileno(stdout), (ulong) sizeof mingw_stdout_buf);
		} else {
			setmode(fileno(stdout), O_BINARY);
			STARTUP_DEBUG("forced stdout (fd=%d) to binary mode",
				fileno(stdout));
		}
		tty = isatty(STDERR_FILENO);
		STARTUP_DEBUG("stderr is%s a tty", tty ? "" : "n't");
		if (tty) {
			fclose(stderr);
			close(STDERR_FILENO);
			freopen("CONOUT$", "w", stderr);	/* Not "wb" */
			setvbuf(stderr, NULL, _IOLBF, 0);
		} else {
			setmode(fileno(stderr), O_BINARY);
			STARTUP_DEBUG("forced stderr (fd=%d) to binary mode",
				fileno(stderr));
		}
	} else {
		fclose(stdin);
		fclose(stdout);
		fclose(stderr);
		close(STDIN_FILENO);
		close(STDOUT_FILENO);
		close(STDERR_FILENO);
		STARTUP_DEBUG("stdio fully reset");

		freopen("NUL", "rb", stdin);
		STARTUP_DEBUG("stdin reopened from NUL");

		freopen("NUL", "wb", stdout);
		STARTUP_DEBUG("stdout reopened to NUL");

		freopen("NUL", "wb", stderr);
		STARTUP_DEBUG("stderr reopened to NUL");
	}
}

/**
 * Rotate pathname at startup time, renaming existing paths with a .0, .1, .2
 * extension, etc..., up to the maximum specified.
 */
void G_COLD
mingw_file_rotate(const char *pathname, int keep)
{
	static char npath[MAX_PATH_LEN];	/* Avoid using too much stack space */
	int i, len;
	const char *dot;

	/*
	 * Figure out the extension of the pathname, so that we can progate
	 * it during renaming.
	 *
	 * For instance, "x.stdout" will become "x.0.stdout".
	 *
	 * This allows Windows to properly open the ".stdout" files once we
	 * have registered how such an extension should be opened.
	 */

	dot = vstrrchr(pathname, '.');
	len = NULL == dot ? (int) vstrlen(pathname) : dot - pathname;
	g_assert(len >= 0);

	if (NULL == dot)
		dot = &pathname[len];	/* Points to trailing NUL -> empty string */

	if (keep > 0) {
		str_bprintf(ARYLEN(npath), "%.*s.%d%s", len, pathname, keep - 1, dot);
		if (-1 != mingw_unlink(npath))
			STARTUP_DEBUG("removed file \"%s\"", npath);
	}

	for (i = keep - 1; i > 0; i--) {
		static char opath[MAX_PATH_LEN];
		str_bprintf(ARYLEN(opath), "%.*s.%d%s", len, pathname, i - 1, dot);
		str_bprintf(ARYLEN(npath), "%.*s.%d%s", len, pathname, i, dot);
		if (-1 != mingw_rename(opath, npath))
			STARTUP_DEBUG("file \"%s\" renamed as \"%s\"", opath, npath);
	}

	str_bprintf(ARYLEN(npath), "%.*s.0%s", len, pathname, dot);

	if (-1 != mingw_rename(pathname, npath))
		STARTUP_DEBUG("file \"%s\" renamed as \"%s\"", pathname, npath);

	/*
	 * Temporary: up to 1.1.14, we were renaming file without processing
	 * the extension, by simply appending a ".digit" to the file names.
	 * Clean those up if they exist!
	 *
	 * FIXME:
	 * This code will be safe to delete after 1.1.15 is released.
	 */

	for (i = 0; i < keep; i++) {
		str_bprintf(ARYLEN(npath), "%s.%d", pathname, keep);
		if (-1 != mingw_unlink(npath))
			STARTUP_DEBUG("removed obsolete file \"%s\"", npath);
	}
}

void G_COLD
mingw_early_init(void)
{
	int console_err;

	getlog(TRUE);

	STARTUP_DEBUG("starting PID %d", getpid());
	STARTUP_DEBUG("logging on fd=%d", fileno(mingw_debug_lf));

#if __MSVCRT_VERSION__ >= 0x800
	STARTUP_DEBUG("configured invalid parameter handler");
	_set_invalid_parameter_handler(mingw_invalid_parameter);
#endif

	/* Disable any Windows pop-up on crash or file access error */
	SetErrorMode(SEM_NOOPENFILEERRORBOX | SEM_FAILCRITICALERRORS |
		SEM_NOGPFAULTERRORBOX);
	STARTUP_DEBUG("disabled Windows crash pop-up");

	/* Trap all unhandled exceptions */
	SetUnhandledExceptionFilter(mingw_exception);
	STARTUP_DEBUG("configured exception handler");

	STARTUP_DEBUG("initializing virtual memory...");
	mingw_vmm_init();
	STARTUP_DEBUG("done!");

	_fcloseall();
	getlog(FALSE);

	STARTUP_DEBUG("attempting AttachConsole()...");

	if (AttachConsole(ATTACH_PARENT_PROCESS)) {
		STARTUP_DEBUG("AttachConsole() succeeded");
		mingw_stdio_reset(TRUE);
	} else {
		console_err = GetLastError();

		STARTUP_DEBUG("AttachConsole() failed, error = %d", console_err);

		switch (console_err) {
		case ERROR_INVALID_HANDLE:
		case ERROR_GEN_FAILURE:
			/* We had no console, and we got no console. */
			mingw_stdio_reset(FALSE);
			{
				const char *pathname;

				/*
				 * The stdout/stderr files which are created when GTKG is
				 * not launched from a console are auto-rotated on startup.
				 * However, if restarting automatically after a crash, we may
				 * not be able to perform the renaming (you know, Windows
				 * usually refuses to rename an opened file).
				 *
				 * Therefore, it is probably safest to always open stdout and
				 * stderr for appending.
				 */

				pathname = mingw_getstdout_path();
				STARTUP_DEBUG("stdout file will be %s", pathname);
				mingw_file_rotate(pathname, MINGW_TRACEFILE_KEEP);
				STARTUP_DEBUG("stdout files rotated");
				if (NULL != mingw_freopen(pathname, "ab", stdout)) {
					log_set(LOG_STDOUT, pathname);
					STARTUP_DEBUG("stdout (unbuffered) reopened");
				} else {
					STARTUP_DEBUG("could not reopen stdout");
				}

				pathname = mingw_getstderr_path();
				STARTUP_DEBUG("stderr file will be %s", pathname);
				mingw_file_rotate(pathname, MINGW_TRACEFILE_KEEP);
				STARTUP_DEBUG("stderr files rotated");
				if (NULL != mingw_freopen(pathname, "ab", stderr)) {
					log_set(LOG_STDERR, pathname);
					STARTUP_DEBUG("stderr (unbuffered) reopened");
				} else {
					STARTUP_DEBUG("could not reopen stderr");
				}
			}
			break;
		case ERROR_ACCESS_DENIED:
			/* Ignore, we already have a console */
			STARTUP_DEBUG("AttachConsole() denied");
			break;
		default:
			STARTUP_DEBUG("AttachConsole() has unhandled error");
			break;
		}
	}

	/*
	 * Compute our parent PID immediately to avoid races later on, should
	 * its PID slot be reused at the time they call getppid().
	 */

#ifdef EMULATE_GETPPID
	(void) mingw_getppid();
#endif	/* EMULATE_GETPPID */

	set_folder_basepath_func(mingw_get_folder_basepath);
	win32dlp_init(mingw_vmm.reserved, mingw_vmm.size);

	closelog();
	mingw_early_inited = TRUE;
}

void
mingw_close(void)
{
	if (libws2_32 != NULL) {
		FreeLibrary(libws2_32);

		libws2_32 = NULL;
		WSAPoll = NULL;
	}

	if (mingw_launched != NULL) {
		size_t cnt = dualhash_count(mingw_launched);

		if (0 != cnt) {
			s_warning("%s(): still has %zu child process%s unwaited for",
				G_STRFUNC, PLURAL_ES(cnt));
		}
	}
}

#endif	/* MINGW32 */

/* vi: set ts=4 sw=4 cindent: */
