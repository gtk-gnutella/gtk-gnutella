/*
 * $Id$
 *
 * Copyright (c) 2002, Raphael Manfredi
 *
 * Explicit-width block allocator, based on zalloc().
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

#ifndef __walloc_h__
#define __walloc_h__

#include <glib.h>

/*
 * Under USE_DMALLOC control, those routines are remapped to malloc/free.
 */

#ifdef USE_DMALLOC

#define walloc(s)			g_malloc(s)
#define wfree(p,s)			g_free(p)
#define wrealloc(p,o,n)		g_realloc((p), (n));

#else	/* !USE_DMALLOC */

gpointer walloc(gint size);
void wfree(gpointer ptr, gint size);
gpointer wrealloc(gpointer old, gint old_size, gint new_size);

#endif	/* USE_DMALLOC */

void wdestroy(void);

#endif /* __walloc_h__ */

