/*
 * $Id$
 *
 * Copyright (c) 2002, Raphael Manfredi
 *
 * Version management.
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

#ifndef _version_h_
#define _version_h_

#include <glib.h>

/*
 * A decompiled version descriptor.
 * In our comments below, we are assuming a value of "0.90.3b2".
 */
typedef struct version {
	guint major;				/* Major version number (0) */
	guint minor;				/* Minor version number (90) */
	guint patchlevel;			/* Patch level (3) */
	guchar tag;					/* Code letter after version number (b) */
	guint taglevel;				/* Value after code letter (2) */
	time_t timestamp;
} version_t;

/*
 * Banning periods for our versions.
 */

#define VERSION_ANCIENT_WARN	(86400*365)		/* 1 year */
#define VERSION_ANCIENT_BAN		(86400*365)		/* 1 year */

#define VERSION_UNSTABLE_WARN	(86400*60)		/* 2 months - 60 days */
#define VERSION_UNSTABLE_BAN	(86400*90)		/* 3 months - 90 days */

/*
 * Public interface.
 */

void version_init(void);
void version_close(void);
void version_ancient_warn(void);
gboolean version_check(guchar *str, gchar *token);
gboolean version_is_too_old(gchar *vendor);
gint version_cmp(version_t *a, version_t *b);
gboolean version_fill(gchar *version, version_t *vs);

gchar *version_str(version_t *ver);

extern gchar *version_string;
extern gchar *version_number;

#endif	/* _version_h_ */

/* vi: set ts=4: */

