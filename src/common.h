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
#include <time.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/uio.h>		/* writev(), readv(), struct iovec */
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <string.h>
#include <dirent.h>


#include "ui_core_interface_common_defs.h"


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


#include "atoms.h"
#include "base32.h"
#include "bg.h"
#include "cobs.h"
#include "cq.h"
#include "event.h"
#include "fuzzy.h"
#include "getdate.h"
#include "getline.h"
#include "glib-missing.h"
#include "guid.h"
#include "hashlist.h"
#include "idtable.h"
#include "inputevt.h"
#include "listener.h"
#include "matching.h"
#include "misc.h"
#include "namesize.h"
#include "sha1.h"
#include "url.h"
#include "utf8.h"
#include "vendors.h"
#include "walloc.h"
#include "zalloc.h"
#include "zlib_util.h"

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

#define G_FREE_NULL(p)		\
do {				\
	if (p) {		\
		g_free(p);	\
		p = NULL;	\
	}			\
} while (0)

/*
 * Constants
 */

#define GTA_VERSION 0
#define GTA_SUBVERSION 95
#define GTA_PATCHLEVEL 0
#define GTA_REVISION "unstable"
#define GTA_REVCHAR "u"
#define GTA_RELEASE "2004-08-13"	/* ISO format YYYY-MM-DD */
#define GTA_WEBSITE "http://gtk-gnutella.sourceforge.net/"

#if defined(USE_GTK1)
#define GTA_INTERFACE "GTK1"
#elif defined(USE_GTK2)
#define GTA_INTERFACE "GTK2"
#else
#define GTA_INTERFACE "X11"
#endif

#define GTA_PORT		6346	/* Default "standard" port */

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
 * Functions
 */

/* main.c */
void gtk_gnutella_exit(gint); 

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
