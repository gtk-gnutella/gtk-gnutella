/*
 * Copyright (c) 2001-2002, Richard Eckart
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

#ifndef __common_h__
#define __common_h__

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

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
#include "regex.h"
#include "sha1.h"
#include "idtable.h"
#include "bg.h"

#include "../config.h"

/*
 * Portability macros.
 */

/*
 * Can only use the `args' obtained via va_start(args) ONCE.  If we need
 * to call another vararg routine, we need to copy the original args.
 * The __va_copy macro is a GNU extension.
 */
#ifdef __va_copy
#define VA_COPY(dest, src)	__va_copy(dest, src)
#else
#define VA_COPY(dest, src)	dest = src
#endif

/*
 * Constants
 */

#define GTA_VERSION 0
#define GTA_SUBVERSION 92
#define GTA_REVISION "unstable"
#define GTA_REVCHAR "u"
#define GTA_INTERFACE "X11"
#define GTA_RELEASE "06/11/2002"
#define GTA_WEBSITE "http://gtk-gnutella.sourceforge.net/"

/*
 * Functions
 */

/* main.c */
void gtk_gnutella_exit(gint); 


#endif /* __common_h__ */
