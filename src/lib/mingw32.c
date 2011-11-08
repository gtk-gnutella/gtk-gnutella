/*
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

#include <glib.h>
#include <glib/gprintf.h>

#include <stdio.h>
#include <wchar.h>

#include "host_addr.h"			/* ADNS */
#include "adns.h"

#include "ascii.h"				/* For is_ascii_alpha() */
#include "cq.h"
#include "crash.h"
#include "debug.h"
#include "fd.h"					/* For is_open_fd() */
#include "glib-missing.h"
#include "gtk-gnutella.h"		/* For GTA_PRODUCT_NAME */
#include "halloc.h"
#include "iovec.h"
#include "log.h"
#include "misc.h"
#include "path.h"				/* For filepath_basename() */
#include "stacktrace.h"
#include "str.h"
#include "stringify.h"			/* For ULONG_DEC_BUFLEN */
#include "unsigned.h"
#include "utf8.h"
#include "walloc.h"

#include "override.h"			/* Must be the last header included */

#if 0
#define MINGW_SYSCALL_DEBUG		/**< Trace all Windows API call errors */
#endif
#if 0
#define MINGW_STARTUP_DEBUG		/**< Trace early startup stages */
#endif

#undef signal

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
#undef dup2
#undef unlink
#undef opendir
#undef readdir
#undef closedir

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
#undef sendto

#undef abort

#define VMM_MINSIZE (1024*1024*100)	/* At least 100 MiB */

#define WS2_LIBRARY "ws2_32.dll"

#ifdef MINGW_SYSCALL_DEBUG
#define mingw_syscall_debug()	1
#else
#define mingw_syscall_debug()	0
#endif

static HINSTANCE libws2_32;

typedef struct processor_power_information {
  ULONG Number;
  ULONG MaxMhz;
  ULONG CurrentMhz;
  ULONG MhzLimit;
  ULONG MaxIdleState;
  ULONG CurrentIdleState;
} PROCESSOR_POWER_INFORMATION;

extern gboolean vmm_is_debugging(guint32 level);

typedef int (*WSAPoll_func_t)(WSAPOLLFD fdarray[], ULONG nfds, INT timeout);
WSAPoll_func_t WSAPoll = NULL;

/**
 * Path Name Conversion Structure.
 *
 * @note MAX_PATH_LEN might actually apply to MBCS only and the limit for
 * Unicode is 32768. So we could (or should?) support pathnames longer than
 * 256 characters.
 */
typedef struct pncs {
	wchar_t *utf16;
	wchar_t buf[MAX_PATH_LEN];
} pncs_t;

/**
 * Converts a NUL-terminated MBCS string to an UTF-16 string.
 * @note mbtowcs() is not async-signal safe.
 *
 * @param src The string to convert.
 * @param dest The destination buffer.
 * @param dest_size The size of the destination buffer in number of elements.
 *
 * @return NULL on failure with errno set, dest on success.
 */
static wchar_t *
locale_to_wchar(const char *src, wchar_t *dest, size_t dest_size)
{
	size_t n;

	n = mbstowcs(NULL, src, 0);
	if ((size_t) -1 == n)
		return NULL;

	if (n < dest_size) {
		(void) mbstowcs(dest, src, dest_size);
	} else {
		dest = NULL;
		errno = ENAMETOOLONG;
	}
	return dest;
}

/*
 * Convert pathname to a UTF-16 representation.
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
 * On success, the member utf16 points to the converted pathname that can be
 * used in Unicode-aware Windows calls.
 *
 * @return 0 on success, -1 on error with errno set.
 */
static int
pncs_convert(pncs_t *pncs, const char *pathname)
{
	char pathname_buf[MAX_PATH_LEN];
	char *p;

	/* On Windows wchar_t should always be 16-bit and use UTF-16 encoding. */
	STATIC_ASSERT(sizeof(guint16) == sizeof(wchar_t));

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

	p = is_strcaseprefix(pathname, "/cygdrive/");
	if (NULL != p)
		pathname = p - 1;			/* Go back to ending "/" */

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
		is_dir_separator(pathname[0]) &&
		is_ascii_alpha(pathname[1]) &&
		(is_dir_separator(pathname[2]) || '\0' == pathname[2])
	) {
		size_t plen = strlen(pathname);

		if (sizeof pathname_buf <= plen) {
			errno = ENAMETOOLONG;
			return -1;
		}

		clamp_strncpy(pathname_buf, sizeof pathname_buf, pathname, plen);
		pathname_buf[0] = pathname[1]; /* Replace with correct drive letter */
		pathname_buf[1] = ':';
		pathname = pathname_buf;
	}

	if (utf8_is_valid_string(pathname)) {
		size_t ret;

		ret = utf8_to_utf16(pathname, pncs->buf, G_N_ELEMENTS(pncs->buf));
		if (ret < G_N_ELEMENTS(pncs->buf)) {
			pncs->utf16 = pncs->buf;
		} else {
			errno = ENAMETOOLONG;
			pncs->utf16 = NULL;
		}
	} else {
		pncs->utf16 = locale_to_wchar(pathname,
						pncs->buf, G_N_ELEMENTS(pncs->buf));
	}

	return NULL != pncs->utf16 ? 0 : -1;
}

static inline gboolean
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

	switch (error) {
	case WSAEWOULDBLOCK:	result = EAGAIN; break;
	case WSAEINTR:			result = EINTR; break;
	}

	if (mingw_syscall_debug()) {
		g_debug("%s() failed: %s (%d)", stacktrace_caller_name(1),
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
	static GHashTable *warned;

	if (NULL == warned) {
		warned = NOT_LEAKING(g_hash_table_new(NULL, NULL));
	}

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
		return ENOFILE;
	case ERROR_PATH_NOT_FOUND:
		return ENOENT;
	case ERROR_TOO_MANY_OPEN_FILES:
		return EMFILE;
	case ERROR_ACCESS_DENIED:
		return EPERM;
	case ERROR_INVALID_HANDLE:
		return EBADF;
	case ERROR_NOT_ENOUGH_MEMORY:
		return ENOMEM;
	case ERROR_INVALID_ACCESS:
		return EPERM;
	case ERROR_OUTOFMEMORY:
		return ENOMEM;
	case ERROR_INVALID_DRIVE:
		return ENXIO;
	case ERROR_NOT_SAME_DEVICE:
		return EXDEV;
	case ERROR_NO_MORE_FILES:
		return ENFILE;
	case ERROR_WRITE_PROTECT:
		return EPERM;
	case ERROR_NOT_SUPPORTED:
		return ENOSYS;
	case ERROR_DISK_FULL:
		return ENOSPC;
	case ERROR_BROKEN_PIPE:
		return EPIPE;
	case ERROR_INVALID_NAME:		/* Invalid syntax in filename */
		return EINVAL;
	/* The following remapped because their number is in the POSIX range */
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
		return ENODEV;
	case ERROR_NOT_READY:
	case ERROR_BAD_COMMAND:
	case ERROR_CRC:
	case ERROR_BAD_LENGTH:
	case ERROR_SEEK:
	case ERROR_NOT_DOS_DISK:
	case ERROR_SECTOR_NOT_FOUND:
		return EIO;
	case ERROR_OUT_OF_PAPER:
		return ENOSPC;
	case ERROR_WRITE_FAULT:
	case ERROR_READ_FAULT:
		return EFAULT;
	case ERROR_GEN_FAILURE:
	case ERROR_SHARING_VIOLATION:
	case ERROR_LOCK_VIOLATION:
	case ERROR_WRONG_DISK:
	case ERROR_SHARING_BUFFER_EXCEEDED:
		return EIO;
	case ERROR_HANDLE_EOF:
		return 0;			/* EOF must be treated as a read of 0 bytes */
	case ERROR_HANDLE_DISK_FULL:
		return ENOSPC;
	default:
		if (!gm_hash_table_contains(warned, int_to_pointer(error))) {
			g_warning("Windows error code %d (%s) not remapped to a POSIX one",
				error, g_strerror(error));
			g_hash_table_insert(warned, int_to_pointer(error), NULL);
		}
	}

	return error;
}

/**
 * Get last Windows error, remapping Windows-specific errors into POSIX ones
 * and clearing the POSIX range so that strerror() works.
 */
static int
mingw_last_error(void)
{
	int error = GetLastError();
	int result = mingw_win2posix(error);

	if (mingw_syscall_debug()) {
		g_debug("%s() failed: %s (%d)", stacktrace_caller_name(1),
			symbolic_errno(result), error);
	}

	return result;
}

static signal_handler_t mingw_sighandler[SIGNAL_COUNT];

signal_handler_t
mingw_signal(int signo, signal_handler_t handler)
{
	signal_handler_t res;

	g_assert(handler != SIG_ERR);

	if (signo <= 0 || signo >= SIGNAL_COUNT) {
		errno = EINVAL;
		return SIG_ERR;
	}

	/*
	 * Don't call signal() with SIGBUS or SIGTRAP: since we're faking them,
	 * we'll get an error back as "unrecognized argument value".
	 */

	switch (signo) {
	case SIGBUS:
	case SIGTRAP:
		res = mingw_sighandler[signo];
		mingw_sighandler[signo] = handler;
		break;
	default:
		res = signal(signo, handler);
		if (SIG_ERR != res) {
			mingw_sighandler[signo] = handler;
		}
		break;
	}

	return res;
}

/**
 * Synthesize a fatal signal as the kernel would on an exception.
 */
static G_GNUC_COLD void
mingw_sigraise(int signo)
{
	g_assert(signo > 0 && signo < SIGNAL_COUNT);

	if (SIG_IGN == mingw_sighandler[signo]) {
		/* Nothing */
	} else if (SIG_DFL == mingw_sighandler[signo]) {
		DECLARE_STR(3);

		print_str("Got uncaught ");			/* 0 */
		print_str(signal_name(signo));		/* 1 */
		print_str(" -- crashing.\n");		/* 2 */
		flush_err_str();
		if (log_stdout_is_distinct())
			flush_str(STDOUT_FILENO);
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
	mingw_sigraise(SIGABRT);
	ExitProcess(EXIT_FAILURE);
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
				len_high = MAX_INT_VAL(guint32);
				len_low = MAX_INT_VAL(guint32);
			} else {
				len_high = (guint64) arg->l_len >> 32;
				len_low = arg->l_len & MAX_INT_VAL(guint32);
			}
			start_high = (guint64) arg->l_start >> 32;
			start_low = arg->l_start & MAX_INT_VAL(guint32);

			if (arg->l_type == F_WRLCK) {
				if (!LockFile(file, start_low, start_high, len_low, len_high))
					errno = mingw_last_error();
				else
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
			int i;

			va_start(args, cmd);
			min = va_arg(args, int);
			va_end(args);

			max = getdtablesize();

			if (min < 0 || min >= max) {
				errno = EINVAL;
				return -1;
			}

			for (i = min; i < max; i++) {
				if (mingw_fd_is_opened(i))
					continue;
				return mingw_dup2(fd, i);
			}
			errno = EMFILE;
			break;
		}
		default:
			res = -1;
			errno = EINVAL;
			break;
	}

	return res;
}

/**
 * Is WSAPoll() supported?
 */
gboolean
mingw_has_wsapoll(void)
{
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

	if (NULL == WSAPoll) {
		errno = WSAEOPNOTSUPP;
		return -1;
	}
	res = WSAPoll(fds, nfds, timeout);
	if (SOCKET_ERROR == res)
		errno = mingw_wsa_last_error();
	return res;
}

const char *
mingw_gethome(void)
{
	static char pathname[MAX_PATH];

	if ('\0' == pathname[0]) {
		int ret;

		/* FIXME: Unicode */
		ret = SHGetFolderPath(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, pathname);

		if (E_INVALIDARG == ret) {
			g_warning("could not determine home directory");
			g_strlcpy(pathname, "/", sizeof pathname);
		}
	}

	return pathname;
}

const char *
mingw_getpersonal(void)
{
	static char pathname[MAX_PATH];

	if ('\0' == pathname[0]) {
		int ret;

		/* FIXME: Unicode */
		ret = SHGetFolderPath(NULL, CSIDL_PERSONAL, NULL, 0, pathname);

		if (E_INVALIDARG == ret) {
			g_warning("could not determine personal document directory");
			g_strlcpy(pathname, "/", sizeof pathname);
		}
	}

	return pathname;
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
	const char *personal = mingw_getpersonal();

	g_strlcpy(dest, personal, size);

	if (path_does_not_exist(personal))
		goto fallback;

	clamp_strcat(dest, size, G_DIR_SEPARATOR_S);
	clamp_strcat(dest, size, GTA_PRODUCT_NAME);

	/*
	 * Can't use mingw_mkdir() as we can't allocate memory here.
	 * Use raw mkdir() but this won't work if there are non-ASCII chars
	 * in the path.
	 */

	if (path_does_not_exist(dest))
		mkdir(dest);

	clamp_strcat(dest, size, G_DIR_SEPARATOR_S);
	clamp_strcat(dest, size, file);

	if (0 != strcmp(filepath_basename(dest), file))
		goto fallback;

	return dest;

fallback:
	g_strlcpy(dest, G_DIR_SEPARATOR_S, size);
	clamp_strcat(dest, size, file);
	return dest;
}

/**
 * Return default stdout logfile when launched from the GUI.
 * Directories leading to the dirname of the result are created as needed.
 * This routine does not allocate any memory.
 */
static const char *
mingw_getstdout_path(void)
{
	static char pathname[MAX_PATH];

	return mingw_build_personal_path("gtkg.stdout", pathname, sizeof pathname);
}

/**
 * Return default stderr logfile when launched from the GUI.
 * Directories leading to the dirname of the result are created as needed.
 * This routine does not allocate any memory.
 */
static const char *
mingw_getstderr_path(void)
{
	static char pathname[MAX_PATH];

	return mingw_build_personal_path("gtkg.stderr", pathname, sizeof pathname);
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
	const char *home = mingw_gethome();
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

			patched = h_strconcat(mingw_getpersonal(),
				G_DIR_SEPARATOR_S, GTA_PRODUCT_NAME, p, (void *) 0);
		}
		s_debug("patched \"%s\" into \"%s\"", pathname, patched);
		return patched;
	} else {
		return deconstify_char(pathname);	/* No need to patch anything */
	}
}

guint64
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
	return _getmaxstdio();
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
	/* Buffer size of 8192 is arbitrary */
	return _pipe(fd, 8192, _O_BINARY);
}

int
mingw_stat(const char *pathname, filestat_t *buf)
{
	pncs_t pncs;
	int res;
   
	if (pncs_convert(&pncs, pathname))
		return -1;

	res = _wstati64(pncs.utf16, buf);
	if (-1 == res)
		errno = mingw_last_error();

	return res;
}

int
mingw_fstat(int fd, filestat_t *buf)
{
	int res;
   
	res = _fstati64(fd, buf);
	if (-1 == res)
		errno = mingw_last_error();

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

	if (pncs_convert(&pncs, pathname))
		return -1;

	res = _wopen(pncs.utf16, flags, mode);
	if (-1 == res)
		errno = mingw_last_error();

	return res;
}

void *
mingw_opendir(const char *pathname)
{
	_WDIR *res;
	pncs_t pncs;

	if (pncs_convert(&pncs, pathname))
		return NULL;

	res = _wopendir(pncs.utf16);
	if (NULL == res)
		errno = mingw_last_error();

	return res;
}

void *
mingw_readdir(void *dir)
{
	struct _wdirent *res;

	res = _wreaddir(dir);
	if (NULL == res) {
		errno = mingw_last_error();
		return NULL;
	}
	return res;
}

int
mingw_closedir(void *dir)
{
	int res = _wclosedir(dir);
	if (-1 == res)
		errno = mingw_last_error();
	return 0;
}

/**
 * @note The returned UTF-8 string becomes invalid after the next
 *		 call to dir_entry_filename().
 *		 In order to avoid a memory leak, you may pass NULL as
 *		 parameter to free the memory.
 */
const char *
dir_entry_filename(const void *dirent)
{
	const struct _wdirent *wdirent = dirent;
	static char *filename;

	HFREE_NULL(filename);
	if (NULL != wdirent) {
		filename = utf16_to_utf8_string(wdirent->d_name);
	}
	return filename;
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
	ssize_t res = write(fd, buf, MIN(count, UINT_MAX));
	if (-1 == res)
		errno = mingw_last_error();
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

			memcpy(p, iovec_base(&iov[i]), n);
			p += n;
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
	fileoffset_t offset;

	fd = mingw_open(pathname, O_RDWR);
	if (-1 == fd)
		return -1;

	offset = mingw_lseek(fd, len, SEEK_SET);
	if ((fileoffset_t)-1 == offset || offset != len) {
		int saved_errno = errno;
		fd_close(&fd);
		errno = saved_errno;
		return -1;
	}
	if (!SetEndOfFile((HANDLE) _get_osfhandle(fd))) {
		int saved_errno = mingw_last_error();
		fd_close(&fd);
		errno = saved_errno;
		return -1;
	}
	fd_close(&fd);
	return 0;
}

/***
 *** Socket wrappers
 ***/
 
int 
mingw_select(int nfds, fd_set *readfds, fd_set *writefds,
	fd_set *exceptfds, struct timeval *timeout)
{
	int res = select(nfds, readfds, writefds, exceptfds, timeout);
	
	if (res < 0)
		errno = mingw_wsa_last_error();
		
	return res;
}

int
mingw_getaddrinfo(const char *node, const char *service,
	const struct addrinfo *hints, struct addrinfo **res)
{
	int result = getaddrinfo(node, service, hints, res);
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
	int res = bind(sockfd, addr, addrlen);
	if (-1 == res)
		errno = mingw_wsa_last_error();
	return res;
}

socket_fd_t
mingw_connect(socket_fd_t sockfd, const struct sockaddr *addr,
	  socklen_t addrlen)
{
	socket_fd_t res = connect(sockfd, addr, addrlen);
	if (INVALID_SOCKET == res)
		errno = mingw_wsa_last_error();
	return res;
}

int
mingw_listen(socket_fd_t sockfd, int backlog)
{
	int res = listen(sockfd, backlog);
	if (-1 == res)
		errno = mingw_wsa_last_error();
	return res;
}

socket_fd_t
mingw_accept(socket_fd_t sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
	socket_fd_t res = accept(sockfd, addr, addrlen);
	if (INVALID_SOCKET == res)
		errno = mingw_wsa_last_error();
	return res;
}

int
mingw_shutdown(socket_fd_t sockfd, int how)
{

	int res = shutdown(sockfd, how);
	if (-1 == res)
		errno = mingw_wsa_last_error();
	return res;
}

int
mingw_getsockopt(socket_fd_t sockfd, int level, int optname,
	void *optval, socklen_t *optlen)
{
	int res = getsockopt(sockfd, level, optname, optval, optlen);
	if (-1 == res)
		errno = mingw_wsa_last_error();
	return res;
}

int
mingw_setsockopt(socket_fd_t sockfd, int level, int optname,
	  const void *optval, socklen_t optlen)
{
	int res = setsockopt(sockfd, level, optname, optval, optlen);
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
	return res;
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

static void *mingw_vmm_res_mem;
static size_t mingw_vmm_res_size;
static int mingw_vmm_res_nonhinted = 0;

void *
mingw_valloc(void *hint, size_t size)
{
	void *p = NULL;

	if (NULL == hint && mingw_vmm_res_nonhinted >= 0) {
		if G_UNLIKELY(NULL == mingw_vmm_res_mem) {
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
			size_t n;

			if (vmm_is_debugging(0))
				g_debug("no hint given for %s allocation",
					compact_size(size, FALSE));

			n = mingw_getpagesize();
			n = size_saturate_mult(n, ++mingw_vmm_res_nonhinted);
			p = ptr_add_offset(mingw_vmm_res_mem, n);
		}
		if (NULL == p) {
			errno = mingw_last_error();
			if (vmm_is_debugging(0))
				s_debug("could not allocate %s of memory: %m",
					compact_size(size, FALSE));
		}
	} else if (NULL == hint && mingw_vmm_res_nonhinted < 0) {
		/*
		 * Non hinted request after hinted request are used. Allow usage of
		 * non VMM space
		 */

		p = VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

		if (p == NULL) {
			errno = mingw_last_error();
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
		errno = mingw_last_error();
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
	if (ptr_cmp(mingw_vmm_res_mem, addr) < 0 &&
		ptr_cmp(ptr_add_offset(mingw_vmm_res_mem, mingw_vmm_res_size), addr) > 0)
	{
		/* Allocated in reserved space */
		if (!VirtualFree(addr, size, MEM_DECOMMIT)) {
			errno = mingw_last_error();
			return -1;
		}
	} else if (!VirtualFree(addr, 0, MEM_RELEASE)) {
		/* Allocated in non-reserved space */
		errno = mingw_last_error();
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
		g_carp("mingw_mprotect(): unsupported protection flags 0x%x", prot);
		res = EINVAL;
		return -1;
	}

	res = VirtualProtect((LPVOID) addr, len, newProtect, &oldProtect);
	if (!res) {
		errno = mingw_last_error();
		if (vmm_is_debugging(0)) {
			g_debug("VMM mprotect(%p, %lu) failed: errno=%d (%s)",
				addr, (unsigned long) len, errno,
				symbolic_errno(errno));
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

static const char *
mingw_posix_strerror(int errnum)
{
	switch (errnum) {
	case EPERM:		return "Operation not permitted";
	case ENOFILE:	return "No such file or directory";
	/* ENOENT is a duplicate for ENOFILE */
	case ESRCH:		return "No such process";
	case EINTR:		return "Interrupted function call";
	case EIO:		return "Input/output error";
	case ENXIO:		return "No such device or address";
	case E2BIG:		return "Arg list too long";
	case ENOEXEC:	return "Exec format error";
	case EBADF:		return "Bad file descriptor";
	case ECHILD:	return "No child process";
	case EAGAIN:	return "Resource temporarily unavailable";
	case ENOMEM:	return "Not enough memory space";
	case EACCES:	return "Permission denied";
	case EFAULT:	return "Bad address";
	case EBUSY:		return "Device busy";
	case EEXIST:	return "File already exists";
	case EXDEV:		return "Improper link";
	case ENODEV:	return "No such device";
	case ENOTDIR:	return "Not a directory";
	case EISDIR:	return "Is a directory";
	case EINVAL:	return "Invalid argument";
	case ENFILE:	return "Too many open files in system";
	case EMFILE:	return "Too many open files in the process";
	case ENOTTY:	return "Not a tty";
	case EFBIG:		return "File too large";
	case ENOSPC:	return "No space left on device";
	case ESPIPE:	return "Invalid seek on pipe";
	case EROFS:		return "Read-only file system";
	case EMLINK:	return "Too many links";
	case EPIPE:		return "Broken pipe";
	case EDOM:		return "Domain error";		/* Math */
	case ERANGE:	return "Result out of range";
	case EDEADLK:	return "Resource deadlock avoided";
	case ENAMETOOLONG:	return "Filename too long";
	case ENOLCK:	return "No locks available";
	case ENOSYS:	return "Function not implemented";
	case ENOTEMPTY:	return "Directory not empty";
	case EILSEQ:	return "Illegal byte sequence";
	case EOVERFLOW:	return "Value too large to be stored in data type";
	default:		return NULL;
	}

	g_assert_not_reached();
}

const char *
mingw_strerror(int errnum)
{
	const char *msg;
	static char strerrbuf[1024];

	/*
	 * We have one global "errno" but conflicting ranges for errors: the
	 * POSIX ones defined in MinGW overlap with some of the Windows error
	 * codes.
	 *
	 * Because our code is POSIX, we strive to remap these conflicting codes
	 * to POSIX values and naturally provide our own strerror() for the
	 * POSIX errors.
	 */

	msg = mingw_posix_strerror(errnum);
	if (msg != NULL)
		return msg;

	FormatMessage(
        FORMAT_MESSAGE_FROM_SYSTEM,
        NULL, errnum,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPTSTR) strerrbuf,
        sizeof strerrbuf, NULL );

	strchomp(strerrbuf, 0);		/* Remove final "\r\n" */
	return strerrbuf;
}

int
mingw_rename(const char *oldpathname, const char *newpathname)
{
	pncs_t old, new;
	int res;

	if (pncs_convert(&old, oldpathname))
		return -1;

	if (pncs_convert(&new, newpathname))
		return -1;

	/*
	 * FIXME: Try to rename a file with SetFileInformationByHandle
	 * and FILE_INFO_BY_HANDLE_CLASS
	 */

	if (MoveFileExW(old.utf16, new.utf16, MOVEFILE_REPLACE_EXISTING)) {
		res = 0;
	} else {
		errno = mingw_last_error();
		res = -1;
	}

	return res;
}

FILE *
mingw_fopen(const char *pathname, const char *mode)
{
	pncs_t wpathname;
	wchar_t wmode[32];
	FILE *res;

	if (pncs_convert(&wpathname, pathname))
		return NULL;

	if (
		!is_ascii_string(mode) ||
		utf8_to_utf16(mode, wmode, G_N_ELEMENTS(wmode)) >= G_N_ELEMENTS(wmode)
	) {
		errno = EINVAL;
		return NULL;
	}

	res = _wfopen(wpathname.utf16, wmode);
	if (NULL == res)
		errno = mingw_last_error();

	return res;
}

FILE *
mingw_freopen(const char *pathname, const char *mode, FILE *file)
{
	pncs_t wpathname;
	wchar_t wmode[32];
	FILE *res;

	if (pncs_convert(&wpathname, pathname))
		return NULL;

	if (
		!is_ascii_string(mode) ||
		utf8_to_utf16(mode, wmode, G_N_ELEMENTS(wmode)) >= G_N_ELEMENTS(wmode)
	) {
		errno = EINVAL;
		return NULL;
	}

	res = _wfreopen(wpathname.utf16, wmode, file);
	if (NULL == res)
		errno = mingw_last_error();
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
	pncs_t pncs;

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

	buf->f_csize = SectorsPerCluster * BytesPerSector;
	buf->f_clusters = TotalNumberOfClusters;
	buf->f_cavail = NumberOfFreeClusters;

	return 0;
}

#ifdef EMULATE_GETRUSAGE
/**
 * Convert a FILETIME into a timeval.
 *
 * @param ft		the FILETIME structure to convert
 * @param tv		the struct timeval to fill in
 */
static void
mingw_filetime_to_timeval(const FILETIME *ft, struct timeval *tv)
{
	guint64 v;

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

	v = (ft->dwLowDateTime | ((ft->dwHighDateTime + (guint64) 0) << 32)) / 10;
	tv->tv_usec = v % 1000000UL;
	v /= 1000000UL;
	/* If time_t is a 32-bit integer, there could be an overflow */
	tv->tv_sec = MIN(v, UNSIGNED(MAX_INT_VAL(time_t)));
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
		errno = mingw_last_error();
		return -1;
	}

	mingw_filetime_to_timeval(&user_time, &usage->ru_utime);
	mingw_filetime_to_timeval(&kernel_time, &usage->ru_stime);

	return 0;
}
#endif	/* EMULATE_GETRUSAGE */

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

/**
 * Compute the system processor architecture, once.
 */
static int
mingw_proc_arch(void)
{
	static SYSTEM_INFO system_info;
	static gboolean done;

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
	OSVERSIONINFOEX osvi;
	DWORD len;
	const char *cpu;

	ZERO(buf);

	g_strlcpy(buf->sysname, "Windows", sizeof buf->sysname);

	switch (mingw_proc_arch()) {
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
#endif	/* EMULATE_UNAME */

#ifdef EMULATE_NANOSLEEP
int
mingw_nanosleep(const struct timespec *req, struct timespec *rem)
{
	static HANDLE t = NULL;
	LARGE_INTEGER dueTime;
	guint64 value;

	/*
	 * There's no residual time, there cannot be early terminations.
	 */

	if (NULL != rem) {
		rem->tv_sec = 0;
		rem->tv_nsec = 0;
	}

	if (G_UNLIKELY(NULL == t)) {
		t = CreateWaitableTimer(NULL, TRUE, NULL);

		if (NULL == t)
			g_carp("unable to create waitable timer, ignoring nanosleep()");

		errno = ENOMEM;		/* System problem anyway */
		return -1;
	}

	if (req->tv_sec < 0 || req->tv_nsec < 0 || req->tv_nsec > 999999999L) {
		errno = EINVAL;
		return -1;
	}

	if (0 == req->tv_sec && 0 == req->tv_nsec)
		return 0;

	/*
	 * For Windows, the time specification unit is 100 nsec.
	 * We therefore round up the amount of nanoseconds to the nearest value.
	 * Negative values indicate relative time.
	 */

	value = guint64_saturate_add(
				guint64_saturate_mult(req->tv_sec, 10000000UL),
				(req->tv_nsec + 99) / 100);
	dueTime.QuadPart = -MIN(value, MAX_INT_VAL(gint64));

	if (0 == SetWaitableTimer(t, &dueTime, 0, NULL, NULL, FALSE)) {
		errno = mingw_last_error();
		s_carp("could not set timer, unable to nanosleep(): %m");
		return -1;
	}

	if (WaitForSingleObject(t, INFINITE) != WAIT_OBJECT_0) {
		g_warning("timer returned an unexpected value, nanosleep() failed");
		errno = EINTR;
		return -1;
	}

	return 0;
}
#endif

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

static unsigned long
mingw_cpu_count(void)
{
	static unsigned long result;
	SYSTEM_INFO system_info;

	if (G_UNLIKELY(result == 0)) {
		GetSystemInfo(&system_info);
		result = system_info.dwNumberOfProcessors;
		g_assert(result > 0);
	}
	return result;
}

guint64
mingw_cpufreq(enum mingw_cpufreq freq)
{
	unsigned long cpus = mingw_cpu_count();
	PROCESSOR_POWER_INFORMATION *p, powarray[16];
	size_t len;
	guint64 result = 0;

	len = size_saturate_mult(cpus, sizeof *p);
	if (cpus <= G_N_ELEMENTS(powarray)) {
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
			result = guint64_saturate_mult(p[0].CurrentMhz, 1000000UL);
			break;
		case MINGW_CPUFREQ_MAX:
			/* Convert to Hz */
			result = guint64_saturate_mult(p[0].MaxMhz, 1000000UL);
			break;
		}
	}

	if (p != powarray)
		wfree(p, len);

	return result;
}

/***
 *** ADNS
 ***
 *** Functions ending with _thread are executed in the context of the ADNS
 *** thread, others are executed in the context of the main thread.
 ***
 *** All logging within the thread must use the t_xxx() logging routines
 *** with the ``altc'' parameter in order to be thread-safe.
 ***/

static logthread_t *altc;		/* ADNS logging thread context */
 
static GAsyncQueue *mingw_gtkg_main_async_queue;
static GAsyncQueue *mingw_gtkg_adns_async_queue;
static volatile gboolean mingw_adns_thread_run;

struct async_data {
	void *user_data;
	
	void *thread_return_data;
	void *thread_arg_data;
	
	void (*thread_func)(struct async_data *);
	void (*callback_func)(struct async_data *);
};

struct arg_data {
	const struct sockaddr *sa;
	union {
		struct sockaddr_in sa_inet4;
		struct sockaddr_in6 sa_inet6;
	} u;
	char hostname[NI_MAXHOST];
	char servinfo[NI_MAXSERV];
};

struct adns_common {
	void (*user_callback)(void);
	void * user_data;
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

/* ADNS getaddrinfo */
/**
 * ADNS getaddrinfo on ADNS thread.
 */
static void
mingw_adns_getaddrinfo_thread(struct async_data *ad)
{
	struct addrinfo *results;
	const char *hostname = ad->thread_arg_data;
	
	if (common_dbg > 1) {
		t_debug(altc, "ADNS resolving '%s'", hostname);
	}	
	getaddrinfo(hostname, NULL, NULL, &results);

	if (common_dbg > 1) {
		t_debug(altc, "ADNS got result for '%s' @%p", hostname, results);
	}
	ad->thread_return_data = results;	
}

/**
 * ADNS getaddrinfo callback function.
 */
static void
mingw_adns_getaddrinfo_cb(struct async_data *ad)
{
	struct addrinfo *results;
	struct adns_request *req;
	struct addrinfo *response;
	host_addr_t addrs[10];
	unsigned i;

	if (common_dbg > 2)
		g_debug("mingw_adns_getaddrinfo_cb");
		
	g_assert(ad);
	g_assert(ad->user_data);
	g_assert(ad->thread_arg_data);
	
	results = ad->thread_return_data;
	req = ad->user_data;
	response = ad->thread_return_data;
	
	for (i = 0; i < G_N_ELEMENTS(addrs); i++) {
		if (NULL == response)
			break;

		addrs[i] = addrinfo_to_addr(response);						
		if (common_dbg) {	
			g_debug("ADNS got %s for hostname %s",
				host_addr_to_string(addrs[i]),
				(const char *) ad->thread_arg_data);
		}
		response = response->ai_next;
	}
	
	{
		adns_callback_t func = (adns_callback_t) req->common.user_callback;
		g_assert(NULL != func);
		if (common_dbg) {
			g_debug("ADNS performing user-callback to %p with %u results", 
				req->common.user_data, i);
		}
		func(addrs, i, req->common.user_data);		
	}
	
	if (NULL != ad->thread_return_data) {
		freeaddrinfo(ad->thread_return_data);
		ad->thread_return_data = NULL;
	}
	HFREE_NULL(ad->thread_arg_data);
	WFREE(ad);
	HFREE_NULL(req);
}

/**
 * ADNS getaddrinfo. Retrieves DNS info by hostname. Returns multiple 
 * @see host_addr_t in the callbackfunction.
 *
 * Performs a hostname lookup on the ADNS thread. Thread function is set to 
 * @see mingw_adns_getaddrinfo_thread, which will call the 
 * @see mingw_adns_getaddrinfo_cb function on completion. The 
 * mingw_adns_getaddrinfo_cb is responsible for performing the user callback.
 * 
 * @param req The adns request, where:
 *		- req->query.by_addr.hostname the hostname to lookup.
 *		- req->common.user_callback, a @see adns_callback_t callback function 
 *		  pointer. Raised on completion.
 */
static void 
mingw_adns_getaddrinfo(const struct adns_request *req)
{
	struct async_data *ad;
	
	if (common_dbg > 2) {
		g_debug("%s", G_STRFUNC);
	}	
	g_assert(req);
	g_assert(req->common.user_callback);
	
	WALLOC0(ad);
	ad->thread_func = mingw_adns_getaddrinfo_thread;
	ad->callback_func = mingw_adns_getaddrinfo_cb;	
	ad->user_data = hcopy(req, sizeof *req);
	ad->thread_arg_data = h_strdup(req->query.by_addr.hostname);	
	
	g_async_queue_push(mingw_gtkg_adns_async_queue, ad);
}

/* ADNS Get name info */
/**
 * ADNS getnameinfo on ADNS thread.
 */
static void
mingw_adns_getnameinfo_thread(struct async_data *ad)
{
	struct arg_data *arg_data = ad->thread_arg_data;
	
	getnameinfo(arg_data->sa, sizeof arg_data->u,
		arg_data->hostname, sizeof arg_data->hostname,
		arg_data->servinfo, sizeof arg_data->servinfo, 
		NI_NUMERICSERV);

	t_debug(altc, "ADNS resolved to %s", arg_data->hostname);
}

/**
 * ADNS getnameinfo callback function.
 */
static void
mingw_adns_getnameinfo_cb(struct async_data *ad)
{
	struct adns_request *req = ad->user_data;
	struct arg_data *arg_data = ad->thread_arg_data;

	if (common_dbg) {	
		g_debug("ADNS resolved to %s", arg_data->hostname);
	}
	
	{
		adns_reverse_callback_t func =
			(adns_reverse_callback_t) req->common.user_callback;
		g_debug("ADNS getnameinfo performing user-callback to %p with %s", 
			req->common.user_data, arg_data->hostname);
		func(arg_data->hostname, req->common.user_data);
	}
	
	HFREE_NULL(req);
	WFREE(arg_data);
}

/**
 * ADNS getnameinfo. Retrieves DNS info by ip address. Returns the hostname in 
 * the callbackfunction.
 *
 * Performs a reverse hostname lookup on the ADNS thread. Thread function is 
 * set to @see mingw_adns_getnameinfo_thread, which will call the 
 * @see mingw_adns_getnameinfo_cb function on completion. The 
 * mingw_adns_getnameinfo_cb is responsible for performing the user callback.
 * 
 * @param req The adns request, where:
 *		- req->query.reverse.addr.net == @see NET_TYPE_IPV6 or
 *		  @see NET_TYPE_IPV4
 *		- req->query.addr.addr.ipv6 the ipv6 address if NET_TYPE_IPV6
 *		- req->query.addr.addr.ipv4 the ipv4 address if NET_TYPE_IPV4
 *		- req->common.user_callback, a @see adns_callback_t callback function 
 *		  pointer. Raised on completion.
 */
static void
mingw_adns_getnameinfo(const struct adns_request *req)
{
	const struct adns_reverse_query *query = &req->query.reverse;
	struct async_data *ad;
	struct arg_data *arg_data;

	WALLOC0(ad);
	WALLOC(arg_data);
	ad->thread_func = mingw_adns_getnameinfo_thread;
	ad->callback_func = mingw_adns_getnameinfo_cb;	
	ad->user_data = hcopy(req, sizeof *req);
	ad->thread_arg_data = arg_data;
	
	switch (query->addr.net) {
		struct sockaddr_in *inet4;
		struct sockaddr_in6 *inet6;
	case NET_TYPE_IPV6:
		inet6 = &arg_data->u.sa_inet6;
		inet6->sin6_family = AF_INET6;
		memcpy(inet6->sin6_addr.s6_addr, query->addr.addr.ipv6, 16);
		arg_data->sa = (const struct sockaddr *) inet6;
		break;
	case NET_TYPE_IPV4:
		inet4 = &arg_data->u.sa_inet4;
		inet4->sin_family = AF_INET;	
		inet4->sin_addr.s_addr = htonl(query->addr.addr.ipv4);
		arg_data->sa = (const struct sockaddr *) inet4;
		break;
	case NET_TYPE_LOCAL:
	case NET_TYPE_NONE:
		g_assert_not_reached();
		break;
	}	

	g_async_queue_push(mingw_gtkg_adns_async_queue, ad);
}

/* ADNS Main thread */

static void *
mingw_adns_thread(void *unused_data)
{
	GAsyncQueue *read_queue, *result_queue;
	
	/* On ADNS thread */
	(void) unused_data;

	read_queue = g_async_queue_ref(mingw_gtkg_adns_async_queue);
	result_queue = g_async_queue_ref(mingw_gtkg_main_async_queue);
	mingw_adns_thread_run = TRUE;
	
	while (mingw_adns_thread_run) {
		struct async_data *ad = g_async_queue_pop(read_queue);	

		if (NULL == ad)
			break;

		ad->thread_func(ad);
		g_async_queue_push(result_queue, ad);			
	}

	if (common_dbg) {
		t_message(altc, "adns thread exit");
	}

	/*
	 * FIXME: The calls below cause a:
	 *
	 *    assertion `g_atomic_int_get (&queue->ref_count) > 0' failed
	 *
	 * I'm wondering whether they are needed since the main thread does
	 * it and the queue could be disposed of by g_async_queue_pop() directly,
	 * given it can detect the queue became orphan....
	 */

#if 0
	g_async_queue_unref(mingw_gtkg_adns_async_queue);
	g_async_queue_unref(mingw_gtkg_main_async_queue);
#endif

	g_thread_exit(NULL);
	return NULL;
}

/**
 * Shutdown the ADNS thread.
 */
static void
mingw_adns_stop_thread(struct async_data *unused_data)
{
	(void) unused_data;
	mingw_adns_thread_run = FALSE;
}

static gboolean
mingw_adns_timer(void *unused_arg)
{
	struct async_data *ad = g_async_queue_try_pop(mingw_gtkg_main_async_queue);

	(void) unused_arg;
	
	if (NULL != ad) {
		if (common_dbg) {
			g_debug("performing callback to func @%p", ad->callback_func);
		}
		ad->callback_func(ad);
	} 

	return TRUE;		/* Keep calling */
}

gboolean
mingw_adns_send_request(const struct adns_request *req)
{
	if (req->common.reverse) {
		mingw_adns_getnameinfo(req);
	} else {
		mingw_adns_getaddrinfo(req);
	}
	return TRUE;
}

void
mingw_adns_init(void)
{
	altc = log_thread_alloc();		/* Thread-private logging context */

	/* Be extremely careful in the ADNS thread!
	 * gtk-gnutella was designed as mono-threaded application so its regular
	 * routines are NOT thread-safe.  Do NOT access any public functions or
	 * modify global variables from the ADNS thread! Dynamic memory
	 * allocation is absolutely forbidden.
 	 */
	g_thread_init(NULL);
	mingw_gtkg_main_async_queue = g_async_queue_new();
	mingw_gtkg_adns_async_queue = g_async_queue_new();

	g_thread_create(mingw_adns_thread, NULL, FALSE, NULL);
	cq_periodic_main_add(1000, mingw_adns_timer, NULL);
}

void
mingw_adns_close(void)
{
	/* Quit our ADNS thread */
	struct async_data *ad;

	WALLOC0(ad);
	ad->thread_func = mingw_adns_stop_thread;

	g_async_queue_push(mingw_gtkg_adns_async_queue, ad);

	g_async_queue_unref(mingw_gtkg_adns_async_queue);
	g_async_queue_unref(mingw_gtkg_main_async_queue);
}

/*** End of ADNS section ***/

/**
 * Build pathname of file located nearby our executable.
 *
 * @return pointer to static data.
 */
const char *
mingw_filename_nearby(const char *filename)
{
	static char pathname[MAX_PATH_LEN];
	static size_t offset;

	/**
	 * FIXME: Unicode
	 */
	if ('\0' == pathname[0]) {
		if (0 == GetModuleFileName(NULL, pathname, sizeof pathname)) {
			static gboolean done;
			if (!done) {
				done = TRUE;
				errno = mingw_last_error();
				s_warning("cannot locate my executable: %m");
			}
		}
		offset = filepath_basename(pathname) - pathname;
	}
	clamp_strcpy(&pathname[offset], sizeof pathname - offset, filename);

	return pathname;
}

/**
 * Check whether there is pending data for us to read on a pipe.
 */
static gboolean
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
gboolean
mingw_stdin_pending(gboolean fifo)
{
	return fifo ? mingw_fifo_pending(STDIN_FILENO) : _kbhit();
}

/**
 * Get file ID.
 *
 * @return TRUE on success.
 */
static gboolean
mingw_get_file_id(const char *pathname, guint64 *id)
{
	HANDLE h;
	BY_HANDLE_FILE_INFORMATION fi;
	gboolean ok;
	pncs_t pncs;

	if (pncs_convert(&pncs, pathname))
		return FALSE;

	h = CreateFileW(pncs.utf16, 0,
			FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE,
			NULL, OPEN_EXISTING, 0, NULL);

	if (INVALID_HANDLE_VALUE == h)
		return FALSE;

	ok = 0 != GetFileInformationByHandle(h, &fi);
	CloseHandle(h);

	if (!ok)
		return FALSE;

	*id = (guint64) fi.nFileIndexHigh << 32 | (guint64) fi.nFileIndexLow;

	return TRUE;
}

/**
 * Are the two files sharing the same file ID?
 */
gboolean
mingw_same_file_id(const char *pathname_a, const char *pathname_b)
{
	guint64 ia, ib;

	if (!mingw_get_file_id(pathname_a, &ia))
		return FALSE;

	if (!mingw_get_file_id(pathname_b, &ib))
		return FALSE;

	return ia == ib;
}

/**
 * Compute default gateway address.
 *
 * @param ip		where IPv4 gateway address is to be written
 *
 * @return 0 on success, -1 on failure with errno set.
 */
int
mingw_getgateway(guint32 *ip)
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

void
mingw_init(void)
{
	WSADATA wsaData;
	
	if (WSAStartup(MAKEWORD(2,2), &wsaData) != NO_ERROR)
		g_error("WSAStartup() failed");
		
	libws2_32 = LoadLibrary(WS2_LIBRARY);
    if (libws2_32 != NULL) {
        WSAPoll = (WSAPoll_func_t) GetProcAddress(libws2_32, "WSAPoll");
    }
}

static int
mingw_stack_fill(void **buffer, int size, CONTEXT *c, int skip)
{
	STACKFRAME s;
	DWORD image;
	HANDLE proc, thread;
	int i;

	proc = GetCurrentProcess();
	thread = GetCurrentThread();

	ZERO(&s);

	/*
	 * We're MINGW32, so even on a 64-bit processor we're going to run
	 * in 32-bit mode, using WOW64 support (if running on a 64-bit Windows).
	 *
	 * FIXME: How is this going to behave on AMD64?  There's no definition
	 * of a context for this machine, and I can't test it.
	 *		--RAM, 2011-01-12
	 */

	image = IMAGE_FILE_MACHINE_I386;
	s.AddrPC.Offset = c->Eip;
	s.AddrPC.Mode = AddrModeFlat;
	s.AddrStack.Offset = c->Esp;
	s.AddrStack.Mode = AddrModeFlat;
	s.AddrFrame.Offset = c->Ebp;
	s.AddrFrame.Mode = AddrModeFlat;

	i = 0;

	while (
		i < size &&
		StackWalk(image, proc, thread, &s, &c, NULL, NULL, NULL, NULL)
	) {
		if (0 == s.AddrPC.Offset)
			break;

		if (skip-- > 0)
			continue;

		buffer[i++] = ulong_to_pointer(s.AddrPC.Offset);
	}

	return i;
}

int
mingw_backtrace(void **buffer, int size)
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

	/*
	 * Experience shows we have to skip the first 2 frames to get a
	 * correct stack frame.
	 */

	return mingw_stack_fill(buffer, size, &c, 2);
}

/**
 * Convert exception code to string.
 */
static G_GNUC_COLD const char *
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
	default:								return "Unknown exception";
	}
}

/**
 * Log reported exception.
 */
static G_GNUC_COLD void
mingw_exception_log(int code, const void *pc)
{
	DECLARE_STR(9);
	char time_buf[18];
	const char *name;

	crash_time(time_buf, sizeof time_buf);
	name = stacktrace_routine_name(pc, TRUE);
	if (is_strprefix(name, "0x"))
		name = NULL;

	print_str(time_buf);										/* 0 */
	print_str(" (CRITICAL): received exception at PC=0x");		/* 1 */
	print_str(pointer_to_string(pc));							/* 2 */
	if (name != NULL) {
		print_str(" (");										/* 3 */
		print_str(name);										/* 4 */
		print_str(")");											/* 5 */
	}
	print_str(": ");											/* 6 */
	print_str(mingw_exception_to_string(code));					/* 7 */
	print_str("\n");											/* 8 */

	flush_err_str();
	if (log_stdout_is_distinct())
		flush_str(STDOUT_FILENO);

	/*
	 * Format an error message to propagate into the crash log.
	 */

	{
		char data[128];

		str_bprintf(data, sizeof data, "%s at PC=%p%s%s%s",
			mingw_exception_to_string(code), pc,
			NULL == name ? "" : " (",
			NULL == name ? "" : name,
			NULL == name ? "" : ")");
		crash_set_error(data);
	}
}

/**
 * Log extra information on memory faults.
 */
static G_GNUC_COLD void
mingw_memory_fault_log(const EXCEPTION_RECORD *er)
{
	DECLARE_STR(6);
	char time_buf[18];
	const char *prot = "unknown";
	const void *va = NULL;

	if (er->NumberParameters >= 2) {
		switch (er->ExceptionInformation[0]) {
		case 0:		prot = "read"; break;
		case 1:		prot = "write"; break;
		case 8:		prot = "execute"; break;
		}
		va = ulong_to_pointer(er->ExceptionInformation[1]);
	}

	crash_time(time_buf, sizeof time_buf);

	print_str(time_buf);							/* 0 */
	print_str(" (CRITICAL): memory fault (");		/* 1 */
	print_str(prot);								/* 2 */
	print_str(") at VA=0x");						/* 3 */
	print_str(pointer_to_string(va));				/* 4 */
	print_str("\n");								/* 5 */

	flush_err_str();
	if (log_stdout_is_distinct())
		flush_str(STDOUT_FILENO);

	/*
	 * Format an additional error message to propagate into the crash log.
	 */

	{
		char data[80];

		str_bprintf(data, sizeof data, "; %s fault at VA=%p", prot, va);
		crash_append_error(data);
	}
}

static volatile sig_atomic_t in_exception_handler;
static void *mingw_stack[STACKTRACE_DEPTH_MAX];

int
mingw_in_exception(void)
{
	return in_exception_handler;
}

/**
 * Our default exception handler.
 */
static G_GNUC_COLD LONG WINAPI
mingw_exception(EXCEPTION_POINTERS *ei)
{
	EXCEPTION_RECORD *er;
	int signo = 0;

	in_exception_handler = 1;	/* Will never be reset, we're crashing */
	er = ei->ExceptionRecord;

	/*
	 * Don't use too much stack if we're facing a stack overflow.
	 * We'll emit a short message below in that case.
	 *
	 * However, apparently the exceptions are delivered on a distinct stack.
	 * It may be very samll, for all we know, so still be cautious.
	 */

	if (EXCEPTION_STACK_OVERFLOW != er->ExceptionCode)
		mingw_exception_log(er->ExceptionCode, er->ExceptionAddress);

	switch (er->ExceptionCode) {
	case EXCEPTION_BREAKPOINT:
	case EXCEPTION_SINGLE_STEP:
		signo = SIGTRAP;
		break;
	case EXCEPTION_STACK_OVERFLOW:
		/*
		 * With a stack overflow, we may not be able to continue very
		 * far, so log the fact as soon as possible.
		 */
		{
			DECLARE_STR(1);

			print_str("Got stack overflow -- crashing.\n");
			flush_err_str();
			if (log_stdout_is_distinct())
				flush_str(STDOUT_FILENO);
		}
		signo = SIGSEGV;
		break;
	case EXCEPTION_ACCESS_VIOLATION:
	case EXCEPTION_IN_PAGE_ERROR:
		mingw_memory_fault_log(er);
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
		{
			DECLARE_STR(1);

			print_str("Got fatal exception -- crashing.\n");
			flush_err_str();
			if (log_stdout_is_distinct())
				flush_str(STDOUT_FILENO);
		}
		break;
	default:
		{
			char buf[ULONG_DEC_BUFLEN];
			const char *s;
			DECLARE_STR(3);

			s = print_number(buf, sizeof buf, er->ExceptionCode);
			print_str("Got unknown exception #");		/* 0 */
			print_str(s);								/* 1 */
			print_str(" -- crashing.\n");				/* 2 */
			flush_err_str();
			if (log_stdout_is_distinct())
				flush_str(STDOUT_FILENO);
		}
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
	 */

	{
		int count = mingw_stack_fill(mingw_stack, G_N_ELEMENTS(mingw_stack),
						ei->ContextRecord, 0);

		stacktrace_stack_safe_print(STDERR_FILENO, mingw_stack, count);
		if (log_stdout_is_distinct())
			stacktrace_stack_safe_print(STDOUT_FILENO, mingw_stack, count);

		crash_save_stackframe(mingw_stack, count);
	}

	/*
	 * Synthesize signal, as the UNIX kernel would for these exceptions.
	 */

	if (signo != 0)
		mingw_sigraise(signo);

	return EXCEPTION_CONTINUE_SEARCH;
}

void mingw_invalid_parameter(const wchar_t * expression,
	const wchar_t * function, const wchar_t * file, unsigned int line,
   uintptr_t pReserved) 
{
	(void) expression;
	(void) function;
	(void) pReserved;
	
	wprintf(L"mingw: Invalid parameter in %s %s:%d\r\n", function, file, line);
}

#ifdef EMULATE_SBRK
static void *initial_break;
static void *current_break;

/**
 * @return the initial break value, as defined by the first memory address
 * where HeapAlloc() allocates memory from.
 */
static void *
mingw_get_break(void)
{
	void *p;

	p = HeapAlloc(GetProcessHeap(), HEAP_NO_SERIALIZE, 1);

	if (NULL == p) {
		errno = ENOMEM;
		return (void *) -1;
	}

	HeapFree(GetProcessHeap(), HEAP_NO_SERIALIZE, p);
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
		if G_UNLIKELY(NULL == initial_break) {
			initial_break = current_break = p;
		}
		return p;
	} else if (incr > 0) {
		p = HeapAlloc(GetProcessHeap(), HEAP_NO_SERIALIZE, incr);

		if (NULL == p) {
			errno = ENOMEM;
			return (void *) -1;
		}

		end = ptr_add_offset(p, incr);

		if G_UNLIKELY(NULL == initial_break)
			initial_break = current_break = p;

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

static void
mingw_stdio_reset(void)
{
	fclose(stdin);
	fclose(stdout);
	fclose(stderr);
	close(STDIN_FILENO);
	close(STDOUT_FILENO);
	close(STDERR_FILENO);
}

#ifdef MINGW_STARTUP_DEBUG
static FILE *
getlog(gboolean initial)
{
	return fopen("gtkg-log.txt", initial ? "wb" : "ab");
}

#define STARTUP_DEBUG(...)	G_STMT_START {	\
	if (lf != NULL) {						\
		fprintf(lf, __VA_ARGS__);			\
		fputc('\n', lf);					\
	}										\
} G_STMT_END

#else	/* !MINGW_STARTUP_DEBUG */
#define getlog(x)	NULL
#define STARTUP_DEBUG(...)
#endif	/* MINGW_STARTUP_DEBUG */

G_GNUC_COLD void
mingw_early_init(void)
{
	int console_err;
	FILE *lf = getlog(TRUE);

	STARTUP_DEBUG("starting");

#if __MSVCRT_VERSION__ >= 0x800
	_set_invalid_parameter_handler(mingw_invalid_parameter);
#endif

	/* Disable any Windows pop-up on crash or file access error */
	SetErrorMode(SEM_NOOPENFILEERRORBOX | SEM_FAILCRITICALERRORS |
		SEM_NOGPFAULTERRORBOX);

	/* Trap all unhandled exceptions */
	SetUnhandledExceptionFilter(mingw_exception);

	_fcloseall();

	lf = getlog(FALSE);
	STARTUP_DEBUG("attempting AttachConsole()...");

	if (AttachConsole(ATTACH_PARENT_PROCESS)) {
		int tty = isatty(STDIN_FILENO);
		STARTUP_DEBUG("AttachConsole() succeeded (stdin is%s a tty)",
			tty ? "" : "n't");
		if (tty) {
			mingw_stdio_reset();
			freopen("CONIN$", "rb", stdin);
			freopen("CONOUT$", "wb", stdout);
			freopen("CONOUT$", "wb", stderr);
			STARTUP_DEBUG("stdio reset");
		} else {
			STARTUP_DEBUG("stdio not reset");
		}
	} else {
		console_err = GetLastError();

		STARTUP_DEBUG("AttachConsole() failed, error = %d", console_err);
		STARTUP_DEBUG("stdin is%s a tty", isatty(STDIN_FILENO) ? "" : "n't");

		switch (console_err) {
		case ERROR_INVALID_HANDLE:
		case ERROR_GEN_FAILURE:
			/* We had no console, and we got no console. */
			mingw_stdio_reset();
			freopen("NUL", "rb", stdin);
			{
				const char *pathname;

				pathname = mingw_getstdout_path();
				freopen(pathname, "wb", stdout);
				log_set(LOG_STDOUT, pathname);
				STARTUP_DEBUG("stdout sent to %s", pathname);

				pathname = mingw_getstderr_path();
				freopen(pathname, "wb", stderr);
				log_set(LOG_STDERR, pathname);
				STARTUP_DEBUG("stderr sent to %s", pathname);
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

	if (lf != NULL)
		fclose(lf);
}

void 
mingw_close(void)
{
	mingw_adns_close();
	
	if (libws2_32 != NULL) {
		FreeLibrary(libws2_32);
		
		libws2_32 = NULL;
		WSAPoll = NULL;
	}
}

#endif	/* MINGW32 */

/* vi: set ts=4 sw=4 cindent: */
