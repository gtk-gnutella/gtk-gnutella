/*
 * Copyright (c) 2002-2003, Raphael Manfredi
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
 * Handling of the (name, size) tuples.
 *
 * @author Raphael Manfredi
 * @date 2002-2003
 */

#include "common.h"			/* For safe compilation under USE_DMALLOC */

#include "namesize.h"

#include "lib/atoms.h"
#include "lib/hashing.h"
#include "lib/walloc.h"

#include "lib/override.h"	/* Must be the last header included */

/**
 * Hash a `namesize_t' key.
 */
uint
namesize_hash(const void *key)
{
	const namesize_t *k = key;
	uint32 hash;

	hash = string_mix_hash(k->name);
	hash ^= integer_hash_fast(k->size);

	return hash;
}

/**
 * Compare two `namesize_t' keys.
 */
int
namesize_eq(const void *a, const void *b)
{
	const namesize_t *ka = a, *kb = b;

	return ka->size == kb->size && 0 == strcmp(ka->name, kb->name);
}

/**
 * Create a new namesize structure.
 */
namesize_t *
namesize_make(const char *name, filesize_t size)
{
	namesize_t *ns;

	WALLOC(ns);
	ns->name = atom_str_get(name);
	ns->size = size;

	return ns;
}

/**
 * Free a namesize structure.
 */
void
namesize_free(namesize_t *ns)
{
	atom_str_free_null(&ns->name);
	WFREE(ns);
}

/* vi: set ts=4 sw=4 cindent: */
