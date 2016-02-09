/*
 * Copyright (c) 2001-2003, Richard Eckart
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
 * @ingroup core
 * @file
 *
 * Common header for gtk-gnutella.
 *
 * @author Richard Eckart
 * @date 2001-2003
 */

#ifndef _common_h_
#define _common_h_

#include "config.h"

/**
 * Undefining this symbol will cause gkt-gnutella to avoid using uninitialized
 * values on the stack to collect initial entropy for random number seeds,
 * and will prevent errors about "uninitialized value usage" when running under
 * valgrind.
 *
 * By default, this symbol is defined because reading the uninitialized bytes
 * results in undefined behaviour that precisely adds uncertainety, aka entropy.
 */
#if 1
#define ALLOW_UNINIT_VALUES
#endif

#ifdef MINGW32
/*
 * Must set WINVER before including ANY include on recent MinGW installations
 * because otherwise <sdkddkver.h> is going to redefine the values improperly.
 * We want to state Windows XP support and set WINVER, deriving _WIN32_WINNT
 * from that value.
 */
#ifndef WINVER
#define WINVER 0x0501	/* Windows XP */
#endif
#endif

/*
 * Main includes
 */

#include <errno.h>

#ifdef I_STDLIB
#include <stdlib.h>
#endif

#include <stdio.h>
#include <signal.h>

#ifdef I_UNISTD
#include <unistd.h>
#endif

#ifdef I_SYS_TYPES
#include <sys/types.h>
#endif

#ifdef I_SYS_TIME
#include <sys/time.h>
#endif

#ifdef I_SYS_TIME_KERNEL
#define KERNEL
#include <sys/time.h>
#undef KERNEL
#endif

#ifdef I_SYS_SOCKET
#include <sys/socket.h>
#endif

#ifdef I_SYS_RESOURCE
#include <sys/resource.h>
#endif

#ifdef I_SYS_UN
#include <sys/un.h>
#endif

#ifdef I_SYS_STAT
#include <sys/stat.h>
#endif

#ifdef I_NETINET_IN
#include <netinet/in.h>
#endif

#ifdef MINGW32

/* Provided for convenience to reduce #ifdef hell */
#define is_running_on_mingw()	1
#define native_path(x)			mingw_native_path(x)

#else /* !MINGW32 */

/* Provided for convenience to reduce #ifdef hell */
#define is_running_on_mingw()	0
#define native_path(x)			(x)

#include <sys/uio.h>		/* For writev(), readv(), struct iovec */
#include <sys/wait.h>
#include <netinet/tcp.h>

#endif /* MINGW32 */

#ifdef I_ARPA_INET
#include <arpa/inet.h>		/* For ntohl(), htonl() */
#endif

#include <ctype.h>

#ifdef I_SYS_FILE
#include <sys/file.h>
#endif

#include <fcntl.h>

#if !defined(I_FCNTL) && !defined(I_SYS_FILE)
#include <sys/fcntl.h>		/* Fallback */
#endif

#ifdef I_STRING
#include <string.h>
#else
#include <strings.h>
#endif

#ifdef I_DIRENT
#include <dirent.h>
#endif

#ifdef I_TIME
#include <time.h>
#endif

#ifdef I_SYS_PARAM
#include <sys/param.h>
#endif

#ifdef I_INTTYPES
#include <inttypes.h>
#endif /* I_INTTYPES */

#ifdef I_SYS_UTSNAME
#include <sys/utsname.h>		/* For uname() */
#endif

#ifdef I_SYS_MMAN
#include <sys/mman.h>
#endif

#ifndef MAP_FAILED
#define MAP_FAILED ((void *) -1)
#endif	/* !MAP_FAILED */

#ifdef I_SYS_SENDFILE
#include <sys/sendfile.h>
#else	/* !I_SYS_SENDFILE */
#ifdef HAS_SENDFILE
#define USE_BSD_SENDFILE	/**< No <sys/sendfile.h>, assume BSD version */
#endif	/* HAS_SENDFILE */
#endif	/* I_SYS_SENDFILE_H */

#if defined(USE_IP_TOS) && defined(I_NETINET_IP)
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#endif

/*
 * Endianness, as determined by Configure.
 */

#if BYTEORDER == 0x1234
#define IS_LITTLE_ENDIAN	1
#define IS_BIG_ENDIAN		0
#elif BYTEORDER == 0x4321
#define IS_BIG_ENDIAN		1
#define IS_LITTLE_ENDIAN	0
#else
#error "unknown endianness"
#endif

#if IEEE754_BYTEORDER == 0x1234
#define IS_LITTLE_ENDIAN_FLOAT	1
#define IS_BIG_ENDIAN_FLOAT		0
#elif IEEE754_BYTEORDER == 0x4321
#define IS_BIG_ENDIAN_FLOAT		1
#define IS_LITTLE_ENDIAN_FLOAT	0
#else
#error "float must use IEEE 754."
#endif

/*
 * Determine how large an I/O vector the kernel can accept.
 */

#if defined(IOV_MAX)
#define MAX_IOV_COUNT	IOV_MAX			/**< POSIX */
#elif defined(MAXIOV)
#define MAX_IOV_COUNT	MAXIOV			/**< HP-UX */
#elif defined(UIO_MAXIOV)
#define MAX_IOV_COUNT	UIO_MAXIOV		/**< Linux */
#elif defined(_XOPEN_IOV_MAX)
#define MAX_IOV_COUNT	_XOPEN_IOV_MAX	/**< X/Open */
#else
#define MAX_IOV_COUNT	16				/**< Unknown, use required minimum */
#endif

/*
 * These macros determine the maximum/minimum value of the given integer type
 * "t". This works for signed as well as unsigned types. This code does
 * carefully avoid integer overflows and undefined behaviour.
 * However, it's assumed the type consists of exactly sizeof(type) * CHAR_BIT
 * bits.
 */

#define MAX_INT_VAL_STEP(t) \
	((t) 1 << (CHAR_BIT * sizeof(t) - 1 - ((t) -1 < 1)))

#define MAX_INT_VAL(t) \
	((MAX_INT_VAL_STEP(t) - 1) + MAX_INT_VAL_STEP(t))

#define MIN_INT_VAL(t) \
	((t) -MAX_INT_VAL(t) - 1)

/*
 * For pedantic lint checks, define USE_LINT. We override some definitions
 * and hide ``inline'' to prevent certain useless warnings.
 */

#ifdef USE_LINT
#define inline
#endif

#include <glib.h>
#include "types.h"

#if defined(USE_GLIB1) && !defined(GLIB_MAJOR_VERSION)
#error "Install GLib 1.2 to compile gtk-gnutella against GLib 1.2."
#endif

#if defined(USE_GLIB2) && !defined(GLIB_MAJOR_VERSION)
#error "Install GLib 2.x to compile gtk-gnutella against GLib 2.x."
#endif

typedef uint64 filesize_t; /**< Use filesize_t to hold filesizes */

#ifdef HAS_SCHED_YIELD
#define do_sched_yield()	sched_yield()	/* See lib/mingw32.h */
#endif

#include "gcc.h"			/* Must precede inclusion of mingw32.h */
#include "lib/mingw32.h"

#ifndef MINGW32

typedef struct iovec iovec_t;
typedef off_t fileoffset_t;
typedef struct stat filestat_t;

/**
 * These functions are required because under MINGW struct iovec has
 * different member names and order.
 */
static inline void *
iovec_base(const struct iovec *iov)
{
	return iov->iov_base;
}

static inline void
iovec_set_base(struct iovec *iov, const void *base)
{
	iov->iov_base = (void *) base;
}

static inline size_t
iovec_len(const struct iovec *iov)
{
	return iov->iov_len;
}

static inline void
iovec_set_len(struct iovec *iov, size_t len)
{
	iov->iov_len = len;
}

static inline void
iovec_set(struct iovec *iov, const void *base, size_t len)
{
	iov->iov_base = (void *) base;
	iov->iov_len = len;
}

/* FIXME: Get rid of these: */
typedef int socket_fd_t;
#define INVALID_SOCKET (-1)

#define socket_fd(fd)		(fd)

/*
 * The following are for file-like operations on sockets, which we need to trap
 * so that we grab the possible error condition through WSAGetLastError().
 *
 * To distinguish them from regular read() or write() on plain file descriptors,
 * we prefix them with "s_".
 */
#define s_write write
#define s_writev writev
#define s_read read
#define s_readv readv
#define s_close close
#endif /* !MINGW32 */

#if !defined(AF_LOCAL) && defined(AF_UNIX)
#define AF_LOCAL AF_UNIX
#endif	/* !AF_LOCAL && AF_UNIX */

#if !defined(PF_LOCAL) && defined(PF_UNIX)
#define PF_LOCAL PF_UNIX
#endif	/* !PF_LOCAL && PF_UNIX */

#ifdef I_STDARG
#include <stdarg.h>
#endif

#ifdef HAS_REGCOMP
#ifdef I_REGEX
#include <regex.h>
#endif
#else	/* !HAS_REGCOMP */
/* We embed regex 0.12, used as fallback */
#include "lib/regex.h"
#endif	/* HAS_REGCOMP */

#ifdef USE_GLIB2
#undef G_STRLOC			/* Want our version */
#undef G_STRFUNC		/* Version from glib uses __PRETTY_FUNCTION__ */
#endif	/* USE_GLIB2 */

/*
 * G_STRLOC is the current source location (file:line).
 * G_STRFUNC is the name of the current function, or location if unavailable.
 */

#define G_STRLOC __FILE__ ":" STRINGIFY(__LINE__)

#if defined (__STDC_VERSION__) && (__STDC_VERSION__ >= 19901L)
#define G_STRFUNC (__func__)
#elif defined(__GNUC__)
#define G_STRFUNC (__FUNCTION__)
#else
#define G_STRFUNC (G_STRLOC)
#endif

#ifdef USE_GLIB2
#include <glib-object.h>
#endif	/* USE_GLIB2 */

/*
 * Array size determination
 */
#define N_ITEMS(arr) (sizeof (arr) / sizeof ((arr)[0]))

/*
 * Portability macros.
 */

/*
 * Can only use the `args' obtained via va_start(args) ONCE.  If we need
 * to call a second vararg routine, we need to copy the original args.
 * The __va_copy macro is a GNU extension.
 *
 * Using the `args' means calling va_arg(args, TYPE) on the variable argument
 * list to process the arguments.  Passing the argument list as a va_list
 * pointer does not use the `args' and does not require any VA_COPY to be done.
 *
 * However, one must assume that passing the `args' as a va_list pointer will
 * cause the routine to use the `args', and therefore if a second call with
 * the same `args' is required, the first one should be made through a copy
 * of the `args' through VA_COPY(), and the second with the original `args'.
 *
 * After a VA_COPY(dest, src), one must call va_end(dest) to properly cleanup
 * the copied list, just like one would do after a va_start(dest).  The va_end()
 * should occur in the same routine where va_start() or VA_COPY() is done.
 */
#ifdef va_copy
#define VA_COPY(dest, src) va_copy(dest, src)
#elif defined(__va_copy)
#define VA_COPY(dest, src)	__va_copy(dest, src)
#else
#define VA_COPY(dest, src)	(dest) = (src)
#endif

/**
 * @returns the offset of the given field F within the given type T, in bytes.
 */
#ifndef offsetof
#define offsetof(T, F) ((unsigned) ((char *) &((T *)0L)->F - (char *) 0L))
#endif

/*
 * Standard file descriptor numbers
 */

#ifndef STDIN_FILENO
#define STDIN_FILENO 0
#endif /* STDIN_FILENO */

#ifndef STDOUT_FILENO
#define STDOUT_FILENO 1
#endif /* STDOUT_FILENO */

#ifndef STDERR_FILENO
#define STDERR_FILENO 2
#endif /* STDERR_FILENO */

/*
 * S_ISLNK() is in POSIX.1-1997 but not in older revisions of the standard.
 */
#ifndef S_ISLNK
#define S_ISLNK(mode) (((mode) & S_IFMT) == S_IFLNK)
#endif	/* S_ISLNK */

/*
 * Allow code to blindly say lstat() even if not defined.
 */
#ifndef HAS_LSTAT
#define lstat(_p,_b)	stat((_p),(_b))
#endif

#ifndef TIME_T_MAX
/* This assumes time_t is an integer, not a float */
#define TIME_T_MAX MAX_INT_VAL(time_t)
#endif /* TIME_T_MAX */

#ifndef OFF_T_MAX
#define OFF_T_MAX MAX_INT_VAL(fileoffset_t)
#endif /* OFF_T_MAX */

#ifndef SIZE_MAX
#define SIZE_MAX MAX_INT_VAL(size_t)
#endif

#ifndef SSIZE_MAX
#define SSIZE_MAX MAX_INT_VAL(ssize_t)
#endif

#ifndef POINTER_MAX
#ifdef UINTPTR_MAX
#define POINTER_MAX	((void *) UINTPTR_MAX)
#else
#define POINTER_MAX	((void *) MAX_INT_VAL(size_t))
#endif
#endif

/*
 * Other common macros.
 */

#define SRC_PREFIX	"src/"		/**< Common prefix to remove in filenames */

/*
 * Sources should use _WHERE_ instead of __FILE__ and call short_filename()
 * on the resulting string before perusing it to remove the common prefix
 * defined by SRC_PREFIX.
 */
#ifdef CURDIR					/* Set by makefile */
#define _WHERE_	STRINGIFY(CURDIR) "/" __FILE__
#else
#define _WHERE_	__FILE__
#endif

/*
 * PACKAGE_EXTRA_SOURCE_DIR is set to $srcdir/extra_files when not compiling an
 * official build so it's not required to install these files for testing.
 */
#ifdef OFFICIAL_BUILD
#undef PACKAGE_EXTRA_SOURCE_DIR
#else
#define PACKAGE_EXTRA_SOURCE_DIR \
	PACKAGE_SOURCE_DIR G_DIR_SEPARATOR_S "extra_files"
#endif

/**
 * CMP() returns the sign of a-b, that means <0, 0, or >0.
 *
 * This version avoids branches, which should be faster on all types of CPUs.
 *		--RAM, 2015-04-15
 */
#define CMP(a, b) (((a) > (b)) - ((a) < (b)))

/**
 * SIGN() returns the sign of an integer value.
 */
#define SIGN(x) (G_UNLIKELY((x) == 0) ? 0 : (x) > 0 ? 1 : (-1))

/**
 * Byte-wise swap two items of specified size.
 */
#define SWAP(a, b, size) G_STMT_START {		\
	register size_t __size = (size);		\
	register char *__a = (a), *__b = (b);	\
											\
	do {									\
	  char __tmp = *__a;					\
	  *__a++ = *__b;						\
	  *__b++ = __tmp;						\
	} while (--__size > 0);					\
} G_STMT_END

/**
 * STATIC_ASSERT() can be used to verify conditions at compile-time. For
 * example, it can be used to ensure that an array has a minimum or exact
 * size. This is better than a run-time assertion because the condition is
 * checked even if the code would seldomly or never reached at run-time.
 * However, this can only be used for static conditions which can be verified
 * at compile-time.
 *
 * @attention
 * N.B.: The trick is using a switch case, if the term is false
 *	 there are two cases for zero - which is invalid C. This cannot be
 *	 used outside a function.
 */
#define STATIC_ASSERT(x) \
	do { switch (0) { case ((x) ? 1 : 0): case 0: break; } } while(0)

#define MAX_HOSTLEN			256		/**< Max length for FQDN host */

/* The next two defines came from huge.h --- Emile */
#define SHA1_BASE16_SIZE 	40		/**< 160 bits in base16 representation */
#define SHA1_BASE32_SIZE 	32		/**< 160 bits in base32 representation */
#define SHA1_RAW_SIZE		20		/**< 160 bits in binary representation */

#define TTH_BASE16_SIZE 	48		/**< 192 bits in base16 representation */
#define TTH_BASE32_SIZE 	39		/**< 192 bits in base32 representation */
#define TTH_RAW_SIZE		24		/**< 192 bits in binary representation */

#define BITPRINT_BASE32_SIZE 	72	/**< 352 bits in base32 representation
									 **  includes dot between sha1 and tiger */
#define BITPRINT_BASE16_SIZE	89	/**< 352 bits in base16 + separation dot */
#define BITPRINT_RAW_SIZE		44	/**< 352 bits in binary representation */

/** Maximum bytes in filename i.e., including NUL */
#define	FILENAME_MAXBYTES 256

/* Maximum path length, in bytes */
#if defined(PATH_MAX)
#define MAX_PATH_LEN	PATH_MAX	/* POSIX, first choice */
#elif defined(MAXPATHLEN)
#define MAX_PATH_LEN	MAXPATHLEN
#elif defined(PATH_LEN)
#define MAX_PATH_LEN	PATH_LEN
#else
#define MAX_PATH_LEN	2048
#endif

/**
 * A NULL pointer, to make sure it is sized as a pointer and not as an integer.
 *
 * This should be used as sentinel at the tail of variable argument lists
 * that expect a NULL pointer to terminate the list, and not integer 0.
 *
 * Depending on how variable argument lists are handled, this can prevent
 * bugs on 64-bit machines with 32-bit integers.
 *		--RAM, 2015-10-22
 */
#define NULL_PTR	((void *) 0)

/*
 * Forbidden glib calls.
 */

#define g_snprintf	DONT_CALL_g_snprintf /**< Use gm_snprintf instead */
#define g_vsnprintf	DONT_CALL_g_vsnprintf /**< Use gm_vsnprintf instead */

/*
 * Typedefs
 */

typedef gboolean (*reclaim_fd_t)(void);

/*
 * Standard gettext macros.
 */

#ifdef ENABLE_NLS
#  include <libintl.h>
#  undef _
#  define _(String) dgettext(PACKAGE, String)
#  define Q_(String) g_strip_context ((String), gettext (String))
#  ifdef gettext_noop
#    define N_(String) gettext_noop(String)
#  else
#    define N_(String) "" String ""
#  endif
#else
#  define textdomain(String) (String)
#  define gettext(String) (String)
#  define dgettext(Domain,Message) (Message)
#  define dcgettext(Domain,Message,Type) (Message)
#  define bindtextdomain(Domain,Directory) (Domain)
#  define ngettext(Single, Plural, Number) ((Number) == 1 ? (Single) : (Plural))
#  define _(String) (String)
#  define N_(String) "" String ""
#  define Q_(String) g_strip_context ((String), (String))
#endif /* ENABLE_NLS */

static inline const char * G_FORMAT(1) G_FORMAT(2)
ngettext_(const char *msg1, const char *msg2, ulong n)
{
	return ngettext(msg1, msg2, n);
}

/**
 * Short-hand for ngettext().
 */
#define NG_(Single, Plural, Number) ngettext_((Single), (Plural), (Number))

/**
 * Composes a 32-bit native endian integer from four characters (bytes) given
 * in big endian byte order.
 */
#define FOURCC_NATIVE(a,b,c,d) ( \
	((uint32) (uchar) ((a) & 0xffU) << 24) | \
	((uint32) (uchar) ((b) & 0xffU) << 16) | \
	((uint32) (uchar) ((c) & 0xffU) << 8)  | \
	((uint32) (uchar) ((d) & 0xffU)))

/**
 * Zero memory used by structure pointed at.
 */
#define ZERO(x)		memset((x), 0, sizeof *(x))

/**
 * Generate argument list for the address of `x' and its size, so that we can
 * process the content of that variable.
 *
 * The aim is to prevent typos and make sure the two arguments are in sync.
 */
#define VARLEN(x)		&(x), sizeof(x)

/**
 * Generate argument list for the address pointed at by `x' and its size, so
 * that we can process the structure content, pointed at by that variable.
 *
 * The aim is to prevent typos and make sure the two arguments are in sync.
 */
#define PTRLEN(x)		(x), sizeof *(x)

/*
 * Support for alloca().
 */

#if HAS_GCC(3, 0)
#ifndef alloca
#define alloca(size)	__builtin_alloca(size)
#endif
#else	/* !HAS_GCC(3, 0) */
#ifdef I_ALLOCA
#include <alloca.h>
#endif
#ifndef alloca
#define EMULATE_ALLOCA
#include "lib/alloca.h"
#endif	/* alloca */
#endif	/* HAS_GCC(3, 0) */

/**
 * Let the program use sigprocmask() but remap it to pthread_sigmask()
 * to ensure that we manipulate the thread's signal mask only.
 *
 * On linux, sigprocmask() always manipulates the thread's signal mask, but
 * this is not guaranteed by POSIX.
 *
 * On Windows, we are implementing our own sigprocmask() which will correctly
 * manipulate the thread's signal mask.
 */
#ifdef MINGW32
#define sigprocmask(h,s,o)	mingw_sigprocmask((h), (s), (o))
#elif defined(HAS_SIGPROCMASK) && defined(I_PTHREAD)
#define sigprocmask(h,s,o)	pthread_sigmask((h), (s), (o))
#endif

/*
 * Common inclusions, likely to be needed by most files.
 */

#include "casts.h"
#include "lib/compat_setjmp.h"
#include "lib/fast_assert.h"
#include "lib/exit.h"		/* Transparent exit() trapping */
#include "lib/glog.h"

#endif /* _common_h_ */

/* vi: set ts=4 sw=4 cindent: */
