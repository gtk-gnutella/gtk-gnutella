/*
 * $Id$
 *
 * Copyright (c) 2002, Raphael Manfredi
 *
 * Atom management.
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

#ifndef __atoms_h__
#define __atoms_h__

#include <glib.h>

/*
 * Atom types.
 */

#define ATOM_STRING		0		/* Strings */
#define ATOM_GUID		1		/* GUIDs (binary, 16 bytes) */
#define ATOM_SHA1		2		/* SHA1 (binary, 20 bytes) */

/*
 * Convenience macros.
 */

#define atom_str_get(k)		atom_get(ATOM_STRING, k)
#define atom_str_free(k)	atom_free(ATOM_STRING, k)

#define atom_guid_get(k)	atom_get(ATOM_GUID, k)
#define atom_guid_free(k)	atom_free(ATOM_GUID, k)

#define atom_sha1_get(k)	atom_get(ATOM_SHA1, k)
#define atom_sha1_free(k)	atom_free(ATOM_SHA1, k)

/*
 * Public interface.
 */

void atoms_init(void);
void atoms_close(void);

gpointer atom_get(gint type, gconstpointer key);
void atom_free(gint type, gconstpointer key);

#endif	/* __atoms_h__ */

/* vi: set ts=4: */

