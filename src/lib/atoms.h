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

enum atom_type {
	ATOM_STRING,	/**< Strings */
	ATOM_GUID,		/**< GUIDs (binary, 16 bytes) */
	ATOM_SHA1,		/**< SHA1 (binary, 20 bytes) */
	ATOM_UINT64,	/**< integers (binary, 8 bytes) */
	ATOM_FILESIZE,	/**< filesize_t (binary) */

	NUM_ATOM_TYPES
};

#if !defined(TRACK_ATOMS) || defined(ATOMS_SOURCE)
gpointer atom_get(enum atom_type type, gconstpointer key);
void atom_free(enum atom_type type, gconstpointer key);
#endif

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

#define atom_filesize_get(k) \
	atom_get_track(ATOM_FILESIZE, (k), _WHERE_, __LINE__)
#define atom_filesize_free(k) \
	atom_free_track(ATOM_FILESIZE, (k), _WHERE_, __LINE__)

#ifndef ATOMS_SOURCE
#define atom_get(t,k)		atom_get_track(t, (k), _WHERE_, __LINE__)
#define atom_free(t,k)		atom_free_track(t, (k), _WHERE_, __LINE__)
#endif

#else	/* !TRACK_ATOMS */

static inline gchar *
atom_str_get(const gchar *k)
{
	return atom_get(ATOM_STRING, k);
}

static inline void
atom_str_free(const gchar *k)
{
	return atom_free(ATOM_STRING, k);
}

static inline gchar *
atom_guid_get(const gchar *k)
{
	return atom_get(ATOM_GUID, k);
}

static inline void
atom_guid_free(const gchar *k)
{
	return atom_free(ATOM_GUID, k);
}

static inline gchar *
atom_sha1_get(const gchar *k)
{
	return atom_get(ATOM_SHA1, k);
}

static inline void
atom_sha1_free(const gchar *k)
{
	return atom_free(ATOM_SHA1, k);
}

static inline guint64 *
atom_uint64_get(const guint64 *k)
{
	return atom_get(ATOM_UINT64, k);
}

static inline void
atom_uint64_free(const guint64 *k)
{
	return atom_free(ATOM_UINT64, k);
}

static inline filesize_t *
atom_filesize_get(const filesize_t *k)
{
	return atom_get(ATOM_FILESIZE, k);
}

static inline void
atom_filesize_free(const filesize_t *k)
{
	return atom_free(ATOM_FILESIZE, k);
}

#endif	/* TRACK_ATOMS */

/*
 * Public interface.
 */

void atoms_init(void);
void atoms_close(void);

/*
 * Hash functions and equality checks
 */
guint filesize_hash(gconstpointer key);
gint filesize_eq(gconstpointer a, gconstpointer b);
guint sha1_hash(gconstpointer key);
gint sha1_eq(gconstpointer a, gconstpointer b);
guint guid_hash(gconstpointer key);
gint guid_eq(gconstpointer a, gconstpointer b);
guint uint64_hash(gconstpointer key);
gint uint64_eq(gconstpointer a, gconstpointer b);
guint binary_hash(const guchar *key, guint len);

#ifdef TRACK_ATOMS
gpointer atom_get_track(enum atom_type, gconstpointer key,
			gchar *file, gint line);
void atom_free_track(enum atom_type, gconstpointer key, gchar *file, gint line);
#endif

static inline void
atom_str_free_null(gchar **k_ptr)
{
	if (*k_ptr) {
		atom_free(ATOM_STRING, *k_ptr);
		*k_ptr = NULL;
	}
}

static inline void
atom_sha1_free_null(gchar **k_ptr)
{
	if (*k_ptr) {
		atom_free(ATOM_SHA1, *k_ptr);
		*k_ptr = NULL;
	}
}

static inline void
atom_filesize_free_null(filesize_t **k_ptr)
{
	if (*k_ptr) {
		atom_free(ATOM_FILESIZE, *k_ptr);
		*k_ptr = NULL;
	}
}

static inline void
atom_guid_free_null(gchar **k_ptr)
{
	if (*k_ptr) {
		atom_free(ATOM_GUID, *k_ptr);
		*k_ptr = NULL;
	}
}


#endif	/* _atoms_h_ */

/* vi: set ts=4 sw=4 cindent: */

