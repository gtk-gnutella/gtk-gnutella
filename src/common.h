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

#ifndef _common_h_
#define _common_h_

#include "config.h"

/*
 * Main includes
 */

#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>

#ifdef I_SYS_TIME
#include <sys/time.h>
#endif
#ifdef I_SYS_TIME_KERNEL
#define KERNEL
#include <sys/time.h>
#undef KERNEL
#endif

#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/uio.h>		/* writev(), readv(), struct iovec */
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>		/* For ntohl(), htonl() */
#include <ctype.h>
#include <fcntl.h>
#include <string.h>
#include <dirent.h>

#ifdef I_TIME
#include <time.h>
#endif

#ifdef I_SYS_PARAM
#include <sys/param.h>
#endif
#ifdef I_SYS_SYSCTL
#include <sys/sysctl.h>
#endif

#ifdef I_INTTYPES
#include <inttypes.h>
#endif /* I_INTTYPES */

#ifdef I_SYS_SENDFILE
#include <sys/sendfile.h>
#else	/* !I_SYS_SENDFILE */
#ifdef HAS_SENDFILE
#define USE_BSD_SENDFILE	/* No <sys/sendfile.h>, assume BSD version */
#endif
#endif	/* I_SYS_SENDFILE_H */

#if defined(USE_IP_TOS) && defined(I_NETINET_IP)
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#endif

/*
 * Macro to print signed 64-bit integers
 */
#ifndef PRId64
/* Compiler doesn't support ISO C99  *sigh* */
#ifdef G_GINT64_FORMAT
/* GLib 2.x */
#define PRId64 G_GINT64_FORMAT
#elif G_MAXLONG > 0x7fffffff
/* Assume long is a 64-bit integer */
#define PRId64 "ld"
#elif G_MAXLONG == 0x7fffffff
/* long is 32-bit integer => assume long long is a 64-bit integer */
#define PRId64 "lld"
#else
#error Cannot determine sequence to print signed 64-bit integers
#endif /* !G_GUINT64_FORMAT */
#endif /* !PRId64 */

/*
 * Macro to print unsigned 64-bit integers
 */
#ifndef PRIu64
/* Compiler doesn't support ISO C99  *sigh* */
#ifdef G_GUINT64_FORMAT
/* GLib 2.x */
#define PRIu64 G_GUINT64_FORMAT
#elif G_MAXLONG > 0x7fffffff
/* Assume long is a 64-bit integer */
#define PRIu64 "lu"
#elif G_MAXLONG == 0x7fffffff
/* long is 32-bit integer => assume long long is a 64-bit integer */
#define PRIu64 "llu"
#else
#error Cannot determine sequence to print unsigned 64-bit integers
#endif /* !G_GUINT64_FORMAT */
#endif /* !PRIu64 */

#include <stdarg.h>
#include <regex.h>

#include <glib.h>
#include <zlib.h>

#ifdef USE_GLIB1
typedef void (*GCallback) (void);
#endif
#ifdef USE_GLIB2
#include <glib-object.h>
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
 * Other common macros.
 */

#define SRC_PREFIX	"src/"		/* Common prefix to remove in filenames */

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

#define G_FREE_NULL(p)		\
do {				\
	if (p) {		\
		g_free(p);	\
		p = NULL;	\
	}			\
} while (0)

/* The RCS IDs can be looked up from the compiled binary with e.g. `what'  */
#ifdef __GNUC__
#define RCSID(x) \
	static const char rcsid[] __attribute__((__unused__)) = "@(#) " x
#else
#define RCSID(x) static const char rcsid[] = "@(#) " x
#endif

/* CMP() returns sign of a-b */
#define CMP(a, b) ((a) == (b) ? 0 : (a) > (b) ? 1 : (-1))

/*
 * Constants
 */

#define GTA_VERSION 0
#define GTA_SUBVERSION 95
#define GTA_PATCHLEVEL 0
#define GTA_REVISION "unstable"
#define GTA_REVCHAR "u"
#define GTA_RELEASE "2004-09-04"	/* ISO format YYYY-MM-DD */
#define GTA_WEBSITE "http://gtk-gnutella.sourceforge.net/"

#if defined(USE_GTK1)
#define GTA_INTERFACE "GTK1"
#elif defined(USE_GTK2)
#define GTA_INTERFACE "GTK2"
#else
#define GTA_INTERFACE "X11"
#endif

#define xstr(x) STRINGIFY(x)  

#if defined(GTA_PATCHLEVEL) && (GTA_PATCHLEVEL != 0)
#define GTA_VERSION_NUMBER \
	xstr(GTA_VERSION) "." xstr(GTA_SUBVERSION) "." xstr(GTA_PATCHLEVEL) \
		GTA_REVCHAR
#else
#define GTA_VERSION_NUMBER \
	xstr(GTA_VERSION) "." xstr(GTA_SUBVERSION) GTA_REVCHAR
#endif

#define GTA_PORT		6346	/* Default "standard" port */
#define MAX_HOSTLEN		256		/* Max length for FQDN host */

/* The next two defines came from huge.h --- Emile */
#define SHA1_BASE32_SIZE 	32		/* 160 bits in base32 representation */
#define SHA1_RAW_SIZE		20		/* 160 bits in binary representation */


/*
 * Forbidden glib calls.
 */

#define g_snprintf	DONT_CALL_g_snprintf
#define g_vsnprintf	DONT_CALL_g_vsnprintf

/*
 * Typedefs
 */

typedef gboolean (*reclaim_fd_t)(void);

/*
 * Variables
 */
extern guint32 common_dbg;

/*
 * Standard gettext macros.
 */

#ifdef ENABLE_NLS
#  include <libintl.h>
#  undef _
#  define _(String) dgettext(PACKAGE, String)
#  ifdef gettext_noop
#    define N_(String) gettext_noop(String)
#  else
#    define N_(String) (String)
#  endif
#else
#  define textdomain(String) (String)
#  define gettext(String) (String)
#  define dgettext(Domain,Message) (Message)
#  define dcgettext(Domain,Message,Type) (Message)
#  define bindtextdomain(Domain,Directory) (Domain)
#  define _(String) (String)
#  define N_(String) (String)
#endif /* ENABLE_NLS */

#endif /* _common_h_ */

/* vi: set ts=4 sw=4 cindent: */
