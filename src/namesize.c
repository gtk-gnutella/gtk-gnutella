/*
 * $Id$
 *
 * Copyright (c) 2002, Raphael Manfredi
 *
 * Handling of the (name, size) tuples.
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

#include "common.h"			/* For safe compilation under USE_DMALLOC */
#include "namesize.h"

RCSID("$Id$");

/*
 * namesize_hash
 *
 * Hash a `namesize_t' key.
 */
guint namesize_hash(gconstpointer key)
{
	namesize_t *k = (namesize_t *) key;
	guint32 hash;

	hash = g_str_hash(k->name);
	hash ^= k->size;

	return hash;
}

/*
 * namesize_eq
 *
 * Compare two `namesize_t' keys.
 */
gint namesize_eq(gconstpointer a, gconstpointer b)
{
	namesize_t *ka = (namesize_t *) a;
	namesize_t *kb = (namesize_t *) b;

	return ka->size == kb->size && 0 == strcmp(ka->name, kb->name);
}

/*
 * namesize_make
 *
 * Create a new namesize structure.
 */
namesize_t *namesize_make(guchar *name, guint32 size)
{
	namesize_t *ns;

	ns = walloc(sizeof(*ns));
	ns->name = atom_str_get(name);
	ns->size = size;

	return ns;
}

/*
 * namesize_free
 *
 * Free a namesize structure.
 */
void namesize_free(namesize_t *ns)
{
	atom_str_free(ns->name);
	wfree(ns, sizeof(*ns));
}

