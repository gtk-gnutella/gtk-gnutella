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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <sys/time.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <glib.h>
#include <stdarg.h>
#include <regex.h>

#ifndef USE_GTK2
typedef void (*GCallback) (void);
#else
#include <glib-object.h>
#endif

#include "cq.h"
#include "url.h"
#include "vendors.h"
#include "misc.h"
#include "base32.h"
#include "zalloc.h"
#include "walloc.h"
#include "atoms.h"
#include "listener.h"
#include "fuzzy.h"
#include "matching.h"
#include "getdate.h"
#include "sha1.h"
#include "idtable.h"
#include "getline.h"
#include "namesize.h"
#include "utf8.h"
#include "zlib_util.h"
#include "cobs.h"
#include "bg.h"
#include "guid.h"
#include "file.h"
#include "inputevt.h"
#include "glib-missing.h"
#include "event.h"
#include "hashlist.h"

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

#define G_FREE_NULL(p) \
do { \
	if (p != NULL) \
		g_free(p); \
	p = NULL; \
} while (0)

/*
 * Constants
 */

#define GTA_VERSION 0
#define GTA_SUBVERSION 94
#define GTA_PATCHLEVEL 0
#define GTA_REVISION "unstable"
#define GTA_REVCHAR "u"
#define GTA_RELEASE "2004-05-24"	/* ISO format YYYY-MM-DD */
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
