/*
 * $Id$
 *
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
 * @ingroup lib
 * @file
 *
 * Atom management.
 *
 * @author Raphael Manfredi
 * @date 2002-2003
 */

#ifndef _atoms_h_
#define _atoms_h_

#include <glib.h>

/*
 * Atom types.
 */

#define ATOM_STRING		0		/**< Strings */
#define ATOM_GUID		1		/**< GUIDs (binary, 16 bytes) */
#define ATOM_SHA1		2		/**< SHA1 (binary, 20 bytes) */
#define ATOM_UINT64		3		/**< integers (binary, 8 bytes) */

/*
 * Convenience macros.
 */

#ifdef TRACK_ATOMS

#define atom_str_get(k)		atom_get_track(ATOM_STRING, (k), _WHERE_, __LINE__)
#define atom_str_free(k)	atom_free_track(ATOM_STRING, (k), _WHERE_, __LINE__)

#define atom_guid_get(k)	atom_get_track(ATOM_GUID, (k), _WHERE_, __LINE__)
#define atom_guid_free(k)	atom_free_track(ATOM_GUID, (k), _WHERE_, __LINE__)

#define atom_sha1_get(k)	atom_get_track(ATOM_SHA1, (k), _WHERE_, __LINE__)
#define atom_sha1_free(k)	atom_free_track(ATOM_SHA1, (k), _WHERE_, __LINE__)

#define atom_uint64_get(k)	atom_get_track(ATOM_UINT64, (k), _WHERE_, __LINE__)
#define atom_uint64_free(k)	atom_free_track(ATOM_UINT64, (k), _WHERE_, __LINE__)

#ifndef ATOMS_SOURCE
#define atom_get(t,k)		atom_get_track(t, (k), _WHERE_, __LINE__)
#define atom_free(t,k)		atom_free_track(t, (k), _WHERE_, __LINE__)
#endif

#else	/* !TRACK_ATOMS */

#define atom_str_get(k)		atom_get(ATOM_STRING, k)
#define atom_str_free(k)	atom_free(ATOM_STRING, k)

#define atom_guid_get(k)	atom_get(ATOM_GUID, k)
#define atom_guid_free(k)	atom_free(ATOM_GUID, k)

#define atom_sha1_get(k)	atom_get(ATOM_SHA1, k)
#define atom_sha1_free(k)	atom_free(ATOM_SHA1, k)

#define atom_uint64_get(k)	atom_get(ATOM_UINT64, k)
#define atom_uint64_free(k)	atom_free(ATOM_UINT64, k)

#endif	/* TRACK_ATOMS */

/*
 * Public interface.
 */

void atoms_init(void);
void atoms_close(void);

/*
 * Hash functions and equality checks
 */
guint uint64_hash(gconstpointer key);
gint uint64_eq(gconstpointer a, gconstpointer b);
guint sha1_hash(gconstpointer key);
gint sha1_eq(gconstpointer a, gconstpointer b);
guint guid_hash(gconstpointer key);
gint guid_eq(gconstpointer a, gconstpointer b);
guint uint64_hash(gconstpointer key);
gint uint64_eq(gconstpointer a, gconstpointer b);
guint binary_hash(const guchar *key, guint len);

#ifdef TRACK_ATOMS
gpointer atom_get_track(gint type, gconstpointer key, gchar *file, gint line);
void atom_free_track(gint type, gconstpointer key, gchar *file, gint line);
#endif

#if !defined(TRACK_ATOMS) || defined(ATOMS_SOURCE)
gpointer atom_get(gint type, gconstpointer key);
void atom_free(gint type, gconstpointer key);
#endif

#endif	/* _atoms_h_ */

/* vi: set ts=4 sw=4 cindent: */

