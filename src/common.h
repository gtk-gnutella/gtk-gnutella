/*
 * $Id$
 *
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

/*
 * Constants
 */

#define GTA_PRODUCT_NAME "gtk-gnutella"	/**< Normally "gtk-gnutella" */
#define GTA_VERSION 0				/**< major version */
#define GTA_SUBVERSION 96			/**< minor version */
#define GTA_PATCHLEVEL 7			/**< patch level or teeny version */
#define GTA_REVISION "unstable"		/**< unstable, beta, stable */
#define GTA_REVCHAR "u"				/**< (u)nstable, (b)eta, none -> stable */
#define GTA_RELEASE "2009-09-27"	/**< ISO 8601 format YYYY-MM-DD */
#define GTA_WEBSITE "http://gtk-gnutella.sourceforge.net/"

#if defined(USE_GTK1)
#define GTA_INTERFACE "GTK1"
#elif defined(USE_GTK2)
#define GTA_INTERFACE "GTK2"
#elif defined(USE_TOPLESS)
#define GTA_INTERFACE "Topless"
#else
#error "Expected Gtk+ 1.2, Gtk+ 2.x or headless as user-interface."
#endif

#ifndef HAS_LIBXML2
#error "You need libxml2 (http://www.xmlsoft.org/) to compile gtk-gnutella"
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

#ifdef MINGW32
#include <ws2tcpip.h>
#include <winsock.h>
#define ECONNRESET WSAECONNRESET
#define ECONNREFUSED WSAECONNREFUSED
#define ECONNABORTED WSAECONNABORTED
#define ENETUNREACH WSAENETUNREACH
#define EHOSTUNREACH WSAEHOSTUNREACH
#define ETIMEDOUT WSAETIMEDOUT
#define EINPROGRESS WSAEINPROGRESS
#define ENOTCONN WSAENOTCONN
#define ENOBUFS WSAENOBUFS
#define EADDRNOTAVAIL WSAEADDRNOTAVAIL
#define ENETRESET WSAENETRESET
#define ENETDOWN WSAENETDOWN
#define EHOSTDOWN WSAEHOSTDOWN
#define ENOPROTOOPT WSAENOPROTOOPT
#define EPROTONOSUPPORT WSAEPROTONOSUPPORT

#define SHUT_RD   SD_RECEIVE
#define SHUT_WR   SD_SEND
#define SHUT_RDWR SD_BOTH

#define S_IXGRP  _S_IEXEC
#define S_IWGRP  _S_IWRITE
#define S_IRGRP  _S_IREAD

#define S_IRWXG _S_IREAD
#define S_IRWXO _S_IREAD

#endif /* !MINGW32 */

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

#ifdef MINGW32
struct iovec 
{
	char  *iov_base;
	int  iov_len; 
};

struct passwd
{
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

#else /* !MINGW32 */

#include <sys/uio.h>		/* For writev(), readv(), struct iovec */
#include <sys/wait.h>

#ifdef I_NETINET_IN
#include <netinet/in.h>
#endif

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

#include <setjmp.h>

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
#else
/*
 * Proper mmap() support for memory-mapped files requires ISO C functions like
 * sigsetjmp().
 */
#if defined(HAS_MMAP) && defined(HAS_SIGSETJMP)
#define USE_MMAP 1
#endif	/* ISO C */

#endif	/* HAS_SENDFILE */
#endif	/* I_SYS_SENDFILE_H */

#if defined(USE_IP_TOS) && defined(I_NETINET_IP)
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#endif

#if defined(HAS_POLL)
#include <poll.h>
#endif	/* HAS_POLL */

#if !defined(AF_LOCAL) && defined(AF_UNIX)
#define AF_LOCAL AF_UNIX
#endif	/* !AF_LOCAL && AF_UNIX */

#if !defined(PF_LOCAL) && defined(PF_UNIX)
#define PF_LOCAL PF_UNIX
#endif	/* !PF_LOCAL && PF_UNIX */

/* For pedantic lint checks, define USE_LINT. We override some definitions
 * and hide ``inline'' to prevent certain useless warnings. */
#ifdef USE_LINT
#undef G_GNUC_INTERNAL
#define G_GNUC_INTERNAL
#undef G_INLINE_FUNC
#define G_INLINE_FUNC
#define inline
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

#include <glib.h>

#if defined(USE_GLIB1) && !defined(GLIB_MAJOR_VERSION)
#error "Install GLib 1.2 to compile gtk-gnutella against GLib 1.2."
#endif

#if defined(USE_GLIB2) && !defined(GLIB_MAJOR_VERSION)
#error "Install GLib 2.x to compile gtk-gnutella against GLib 2.x."
#endif

#ifdef USE_LINT
#undef G_GNUC_INTERNAL
#define G_GNUC_INTERNAL
#undef G_INLINE_FUNC
#define G_INLINE_FUNC
#define inline
#endif

typedef guint64 filesize_t; /**< Use filesize_t to hold filesizes */

#ifdef I_STDARG
#include <stdarg.h>
#endif

#ifdef I_REGEX
#include <regex.h>
#endif

#ifdef USE_GLIB1
typedef void (*GCallback) (void);
#define G_STRLOC __FILE__ ":" STRINGIFY(__LINE__)
#endif
#ifdef USE_GLIB2
#include <glib-object.h>
#endif

/*
 * Array size determination
 */
#ifndef G_N_ELEMENTS
#define G_N_ELEMENTS(arr) (sizeof (arr) / sizeof ((arr)[0]))
#endif

/*
 * Portability macros.
 */

/*
 * Can only use the `args' obtained via va_start(args) ONCE.  If we need
 * to call another vararg routine, we need to copy the original args.
 * The __va_copy macro is a GNU extension.
 */
#ifdef va_copy
#define VA_COPY(dest, src) va_copy(dest, src)
#elif defined(__va_copy)
#define VA_COPY(dest, src)	__va_copy(dest, src)
#else
#define VA_COPY(dest, src)	(dest) = (src)
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

#ifndef TIME_T_MAX
/* This assumes time_t is an integer, not a float */
#define TIME_T_MAX MAX_INT_VAL(time_t)
#endif /* TIME_T_MAX */

#ifndef OFF_T_MAX
#define OFF_T_MAX MAX_INT_VAL(off_t)
#endif /* OFF_T_MAX */

#ifndef SIZE_MAX
#define SIZE_MAX MAX_INT_VAL(size_t)
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
 * Calls g_free() and sets the pointer to NULL afterwards. You should use
 * this instead of a bare g_free() to prevent double-free bugs and dangling
 * pointers.
 */
#define G_FREE_NULL(p)	\
G_STMT_START {			\
	if (p) {			\
		g_free(p);		\
		p = NULL;		\
	}					\
} G_STMT_END

#if defined(__GNUC__) && defined(__GNUC_MINOR__)

/** HAVE_GCC allows conditionalization depending on the version of gcc
 *  being used to compile the source.
 *
 *  Check each version at "http://gcc.gnu.org/onlinedocs/" for
 *  support.  Specific functionality may also be broken in some
 *  compiler revisions, so it is useful to conditionalize on the
 *  version.
 */
#define HAVE_GCC(major, minor) \
	((__GNUC__ > (major)) || \
	 (__GNUC__ == (major) && __GNUC_MINOR__ >= (minor)))
#else
#define HAVE_GCC(major, minor) 0
#endif

/*
 * If functions have this attribute GCC warns if it one of the specified
 * parameters is NULL. This macro takes a list of parameter indices. The
 * list must be embraced with parentheses for compatibility with C89
 * compilers. Example:
 *
 * void my_memcpy(void *dst, const void *src, size_t n) NON_NULL_PARAM((1, 2));
 */
#if defined(HASATTRIBUTE) && HAVE_GCC(3, 3) 
#define NON_NULL_PARAM(x) __attribute__((__nonnull__ x))
#else /* GCC < 3.3 */
#define NON_NULL_PARAM(x)
#endif

/**
 * This is the same G_GNUC_FORMAT() but for function pointers. Older versions
 * of GCC do not allow function attributes for function pointers.
 */
#if defined(HASATTRIBUTE) && HAVE_GCC(3, 0)
#define PRINTF_FUNC_PTR(x, y) __attribute__((format(__printf__, (x), (y))))
#else /* GCC < 3.0 */
#define PRINTF_FUNC_PTR(x, y)
#endif

/* Functions using this attribute cause a warning if the returned
 * value is not used. */
#if defined(HASATTRIBUTE) && HAVE_GCC(3, 4)
#define WARN_UNUSED_RESULT __attribute__((__warn_unused_result__))
#else /* GCC < 3.4 */
#define WARN_UNUSED_RESULT
#endif

/* Instructs the compiler to emit code for this function even if it is
 * or seems to be unused. */
#if defined(HASATTRIBUTE) && HAVE_GCC(3, 1)
#define KEEP_FUNCTION __attribute__((__used__))
#else /* GCC < 3.1 || !GCC */
#define KEEP_FUNCTION
#endif

/* The antidote for WARN_UNUSED_RESULT. This attribute is sometimes
 * misused for functions that return a result which SHOULD NOT be
 * ignored in contrast to MUST NOT. Unfortunately, a simple "(void)"
 * does not suppress this warning.
 */
#define IGNORE_RESULT(x) \
	G_STMT_START { switch (0 != (x)) { default: ; } }  G_STMT_END

/* Functions using this attribute cause a warning if the variable
 * argument list does not contain a NULL pointer. */
#ifndef G_GNUC_NULL_TERMINATED
#if defined(HASATTRIBUTE) && HAVE_GCC(4, 0)
#define G_GNUC_NULL_TERMINATED __attribute__((__sentinel__))
#else	/* GCC < 4 */
#define G_GNUC_NULL_TERMINATED
#endif	/* GCC >= 4 */
#endif	/* G_GNUC_NULL_TERMINATED */

/* Define G_LIKELY() and G_UNLIKELY() so that they are available when
 * using GLib 1.2 as well. These allow optimization by static branch
 * prediction with GCC. */
#ifndef G_LIKELY
#if HAVE_GCC(3, 4)	/* Just a guess, a Configure check would be better */
#define G_LIKELY(x)		(__builtin_expect(x, 1))
#define G_UNLIKELY(x)	(__builtin_expect(x, 0))
#else /* !GCC >= 3.4 */
#define G_LIKELY(x)		(x)
#define G_UNLIKELY(x)	(x)
#endif /* GCC >= 3.4 */
#endif /* !G_LIKELY */

#ifndef G_GNUC_MALLOC
#if defined(HASATTRIBUTE) && HAVE_GCC(3, 0)
#define G_GNUC_MALLOC __attribute__((__malloc__))
#else
#define G_GNUC_MALLOC
#endif	/* GCC >= 3.0 */
#endif	/* G_GNUC_MALLOC */

#if defined(HASATTRIBUTE) && HAVE_GCC(3, 1)
#define ALWAYS_INLINE __attribute__((__always_inline__))
#else
#define ALWAYS_INLINE
#endif	/* GCC >= 3.1 */

#if defined(HASATTRIBUTE) && defined(HAS_REGPARM)
#define REGPARM(n)	__attribute__((__regparm__((n))))
#else
#define REGPARM(n)
#endif	/* HAS_REGPARM */

/**
 * CMP() returns the sign of a-b, that means -1, 0, or 1.
 */
#define CMP(a, b) ((a) == (b) ? 0 : (a) > (b) ? 1 : (-1))

/**
 * SIGN() returns the sign of an integer value.
 */
#define SIGN(x) ((x) == 0 ? 0 : (x) > 0 ? 1 : (-1))


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

#if defined(GTA_PATCHLEVEL) && (GTA_PATCHLEVEL != 0)
#define GTA_VERSION_NUMBER \
	STRINGIFY(GTA_VERSION) "." \
	STRINGIFY(GTA_SUBVERSION) "." \
	STRINGIFY(GTA_PATCHLEVEL) GTA_REVCHAR
#else
#define GTA_VERSION_NUMBER \
	STRINGIFY(GTA_VERSION) "." STRINGIFY(GTA_SUBVERSION) GTA_REVCHAR
#endif

#define GTA_PORT			6346	/**< Default "standard" port */
#define MAX_HOSTLEN			256		/**< Max length for FQDN host */
#define GTA_BUILD					"$Revision$"

/* The next two defines came from huge.h --- Emile */
#define SHA1_BASE16_SIZE 	40		/**< 160 bits in base16 representation */
#define SHA1_BASE32_SIZE 	32		/**< 160 bits in base32 representation */
#define SHA1_RAW_SIZE		20		/**< 160 bits in binary representation */

#define TTH_BASE32_SIZE 	39		/**< 160 bits in base32 representation */
#define TTH_RAW_SIZE		24		/**< 160 bits in binary representation */

#define BITPRINT_BASE32_SIZE 	72	/**< 352 bits in base32 representation
									 **  includes dot between sha1 and tiger */
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

static inline const gchar *
ngettext_(const gchar *msg1, const gchar *msg2, gulong n)
G_GNUC_FORMAT(1) G_GNUC_FORMAT(2);

static inline const gchar *
ngettext_(const gchar *msg1, const gchar *msg2, gulong n)
{
	return ngettext(msg1, msg2, n);
}

/**
 * Short-hand for ngettext().
 */
#define NG_(Single, Plural, Number) ngettext_((Single), (Plural), (Number))

/**
 * Stores a RCS ID tag inside the object file. Every .c source file should
 * use this macro once as `RCSID("<dollar>Id$")' on top. The ID tag is
 * automagically updated each time the file is committed to the CVS repository.
 * The RCS IDs can be looked up from the compiled binary with e.g. `what',
 * `ident' or `strings'. See also rcs(1) and ident(1).
 */
#define RCSID(x) \
static KEEP_FUNCTION inline const char *	\
get_rcsid_string(void)	\
{	\
	static const char rcsid[] = "@(#) " x;	\
	return rcsid;	\
}

/**
 * Composes a 32-bit native endian integer from four characters (bytes) given
 * in big endian byte order.
 */
#define FOURCC_NATIVE(a,b,c,d) ( \
	((guint32) (unsigned char) ((a) & 0xffU) << 24) | \
	((guint32) (unsigned char) ((b) & 0xffU) << 16) | \
	((guint32) (unsigned char) ((c) & 0xffU) << 8)  | \
	((guint32) (unsigned char) ((d) & 0xffU)))

#include "casts.h"

#endif /* _common_h_ */

/* vi: set ts=4 sw=4 cindent: */
