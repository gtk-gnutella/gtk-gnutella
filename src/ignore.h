/*
 * $Id$
 *
 * Copyright (c) 2002, Raphael Manfredi
 *
 * Management of download ignoring list.
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

#ifndef _ignore_h_
#define _ignore_h_

#include <glib.h>

void ignore_init(void);
void ignore_close(void);

enum ignore_val {
	IGNORE_FALSE = 0,		/* Do not ignore */
	IGNORE_SHA1 = 1,		/* Ignore because of SHA1 */
	IGNORE_NAMESIZE = 2,	/* Ignore because of Name & Size */
	IGNORE_LIBRARY = 3,		/* Ignore because SHA1 present in library */
	IGNORE_HOSTILE = 4,		/* Ignore because IP address is hostile */
};

void ignore_timer(time_t now);
enum ignore_val ignore_is_requested(
	gchar *file, guint32 size, gchar *sha1);

void ignore_add_filesize(gchar *file, guint32 size);
void ignore_add_sha1(const gchar *file, const gchar *sha1);

#endif	/* _ignore_h_ */

/* vi: set ts=4: */

