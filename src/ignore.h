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

#ifndef __ignore_h__
#define __ignore_h__

#include <glib.h>

void ignore_init(void);
void ignore_close(void);

enum ignore_val {
	IGNORE_FALSE = 0,		/* Do not ignore */
	IGNORE_SHA1 = 1,		/* Ignore because of SHA1 */
	IGNORE_NAMESIZE = 2,	/* Ignore because of Name & Size */
	IGNORE_LIBRARY = 3,		/* Ignore because SHA1 present in library */
};

void ignore_timer(time_t now);
void ignore_add(guchar *file, guint32 size, guchar *sha1);
enum ignore_val ignore_is_requested(guchar *file, guint32 size, guchar *sha1);

#endif	/* __ignore_h__ */

/* vi: set ts=4: */

