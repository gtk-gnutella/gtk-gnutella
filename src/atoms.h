/*
 * $Id$
 *
 * Copyright (c) 2002-2003, Raphael Manfredi
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

#ifndef _atoms_h_
#define _atoms_h_

#include <glib.h>

/*
 * Atom types.
 */

#define ATOM_STRING		0		/* Strings */
#define ATOM_GUID		1		/* GUIDs (binary, 16 bytes) */
#define ATOM_SHA1		2		/* SHA1 (binary, 20 bytes) */
#define ATOM_INT		3		/* integers (binary, 4 bytes) */

/*
 * Convenience macros.
 */

#ifdef TRACK_ATOMS

#define atom_str_get(k)		atom_get_track(ATOM_STRING, (k), __FILE__, __LINE__)
#define atom_str_free(k)	atom_free_track(ATOM_STRING, (k), __FILE__, __LINE__)

#define atom_guid_get(k)	atom_get_track(ATOM_GUID, (k), __FILE__, __LINE__)
#define atom_guid_free(k)	atom_free_track(ATOM_GUID, (k), __FILE__, __LINE__)

#define atom_sha1_get(k)	atom_get_track(ATOM_SHA1, (k), __FILE__, __LINE__)
#define atom_sha1_free(k)	atom_free_track(ATOM_SHA1, (k), __FILE__, __LINE__)

#define atom_int_get(k)		atom_get_track(ATOM_INT, (k), __FILE__, __LINE__)
#define atom_int_free(k)	atom_free_track(ATOM_INT, (k), __FILE__, __LINE__)

#ifndef ATOMS_SOURCE
#define atom_get(t,k)		atom_get_track(t, (k), __FILE__, __LINE__)
#define atom_free(t,k)		atom_free_track(t, (k), __FILE__, __LINE__)
#endif

#else	/* !TRACK_ATOMS */

#define atom_str_get(k)		atom_get(ATOM_STRING, k)
#define atom_str_free(k)	atom_free(ATOM_STRING, k)

#define atom_guid_get(k)	atom_get(ATOM_GUID, k)
#define atom_guid_free(k)	atom_free(ATOM_GUID, k)

#define atom_sha1_get(k)	atom_get(ATOM_SHA1, k)
#define atom_sha1_free(k)	atom_free(ATOM_SHA1, k)

#define atom_int_get(k)		atom_get(ATOM_INT, k)
#define atom_int_free(k)	atom_free(ATOM_INT, k)

#endif	/* TRACK_ATOMS */

/*
 * Public interface.
 */

void atoms_init(void);
void atoms_close(void);


#ifdef TRACK_ATOMS
gpointer atom_get_track(gint type, gconstpointer key, gchar *file, gint line);
void atom_free_track(gint type, gconstpointer key, gchar *file, gint line);
#endif

#if !defined(TRACK_ATOMS) || defined(ATOMS_SOURCE)
gpointer atom_get(gint type, gconstpointer key);
void atom_free(gint type, gconstpointer key);
#endif

#endif	/* _atoms_h_ */

/* vi: set ts=4: */

