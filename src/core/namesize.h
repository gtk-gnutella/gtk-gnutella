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

#ifndef _core_namesize_h_
#define _core_namesize_h_

#include "common.h"

/**
 * The (name, size) tuple.
 */

typedef struct namesize {
	const char *name;	/**< Filename (atom) */
	filesize_t size;	/**< File size */
} namesize_t;

/*
 * Public interface.
 */

uint namesize_hash(const void *key);
int namesize_eq(const void *a, const void *b);

namesize_t *namesize_make(const char *name, filesize_t size);
void namesize_free(namesize_t *ns);

#endif	/* _core_namesize_h_ */

/* vi: set ts=4 sw=4 cindent: */

