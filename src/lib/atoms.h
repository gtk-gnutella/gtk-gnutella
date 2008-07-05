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

#include "common.h"

/*
 * Atom types.
 */

enum atom_type {
	ATOM_STRING,	/**< Strings */
	ATOM_GUID,		/**< GUIDs (binary, 16 bytes) */
	ATOM_SHA1,		/**< SHA1 (binary, 20 bytes) */
	ATOM_TTH,		/**< TTH (binary, 24 bytes) */
	ATOM_UINT64,	/**< unsigned 64-bit integers (binary, 8 bytes) */
	ATOM_FILESIZE,	/**< filesize_t (binary) */
	ATOM_UINT32,	/**< unsigned 32-bit integers (binary, 4 bytes) */

	NUM_ATOM_TYPES
};

#if !defined(TRACK_ATOMS) || defined(ATOMS_SOURCE)
gconstpointer atom_get(enum atom_type type, gconstpointer key);
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

#define atom_tth_get(k)	atom_get_track(ATOM_TTH, (k), _WHERE_, __LINE__)
#define atom_tth_free(k)	atom_free_track(ATOM_TTH, (k), _WHERE_, __LINE__)

#define atom_uint64_get(k)	atom_get_track(ATOM_UINT64, (k), _WHERE_, __LINE__)
#define atom_uint64_free(k)	atom_free_track(ATOM_UINT64, (k), _WHERE_, __LINE__)

#define atom_uint32_get(k)	atom_get_track(ATOM_UINT32, (k), _WHERE_, __LINE__)
#define atom_uint32_free(k)	atom_free_track(ATOM_UINT32, (k), _WHERE_, __LINE__)

#define atom_filesize_get(k) \
	atom_get_track(ATOM_FILESIZE, (k), _WHERE_, __LINE__)
#define atom_filesize_free(k) \
	atom_free_track(ATOM_FILESIZE, (k), _WHERE_, __LINE__)

#ifndef ATOMS_SOURCE
#define atom_get(t,k)		atom_get_track(t, (k), _WHERE_, __LINE__)
#define atom_free(t,k)		atom_free_track(t, (k), _WHERE_, __LINE__)
#endif

#else	/* !TRACK_ATOMS */

static inline const gchar *
atom_str_get(const gchar *k)
{
	return atom_get(ATOM_STRING, k);
}

static inline void
atom_str_free(const gchar *k)
{
	return atom_free(ATOM_STRING, k);
}

static inline const gchar *
atom_guid_get(const gchar *k)
{
	return atom_get(ATOM_GUID, k);
}

static inline void
atom_guid_free(const gchar *k)
{
	return atom_free(ATOM_GUID, k);
}

static inline const struct sha1 *
atom_sha1_get(const struct sha1 *k)
{
	return atom_get(ATOM_SHA1, k);
}

static inline void
atom_sha1_free(const struct sha1 *k)
{
	return atom_free(ATOM_SHA1, k);
}

static inline const struct tth *
atom_tth_get(const struct tth *k)
{
	return atom_get(ATOM_TTH, k);
}

static inline void
atom_tth_free(const struct tth *k)
{
	return atom_free(ATOM_TTH, k);
}

static inline const guint64 *
atom_uint64_get(const guint64 *k)
{
	return atom_get(ATOM_UINT64, k);
}

static inline void
atom_uint64_free(const guint64 *k)
{
	return atom_free(ATOM_UINT64, k);
}

static inline const filesize_t *
atom_filesize_get(const filesize_t *k)
{
	return atom_get(ATOM_FILESIZE, k);
}

static inline void
atom_filesize_free(const filesize_t *k)
{
	return atom_free(ATOM_FILESIZE, k);
}

static inline const guint32 *
atom_uint32_get(const guint32 *k)
{
	return atom_get(ATOM_UINT32, k);
}

static inline void
atom_uint32_free(const guint32 *k)
{
	return atom_free(ATOM_UINT32, k);
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
guint tth_hash(gconstpointer key);
gint tth_eq(gconstpointer a, gconstpointer b);
guint guid_hash(gconstpointer key);
gint guid_eq(gconstpointer a, gconstpointer b);
guint uint64_hash(gconstpointer key);
gint uint64_eq(gconstpointer a, gconstpointer b);
guint binary_hash(const guchar *key, guint len);
guint uint32_hash(gconstpointer key);
gint uint32_eq(gconstpointer a, gconstpointer b);

#ifdef TRACK_ATOMS
gconstpointer atom_get_track(enum atom_type, gconstpointer key,
			gchar *file, gint line);
void atom_free_track(enum atom_type, gconstpointer key, gchar *file, gint line);
#endif


/**
 * These functions dereference the given atom and nullify the pointer.
 * The atom may also point to NULL, so the caller does not have to
 * check this.
 */
#define GENERATE_ATOM_FREE_NULL(name, type) \
static inline void \
atom_ ## name ## _free_null(const type *k_ptr) \
{ \
	if (*k_ptr) { \
		atom_ ## name ## _free(*k_ptr); \
		*k_ptr = NULL; \
	} \
}

struct sha1;
struct tth;

GENERATE_ATOM_FREE_NULL(filesize, filesize_t *)
GENERATE_ATOM_FREE_NULL(guid, gchar *)
GENERATE_ATOM_FREE_NULL(sha1, struct sha1 *)
GENERATE_ATOM_FREE_NULL(str, gchar *)
GENERATE_ATOM_FREE_NULL(tth, struct tth *)
GENERATE_ATOM_FREE_NULL(uint64, guint64 *)
GENERATE_ATOM_FREE_NULL(uint32, guint32 *)
#undef GENERATE_ATOM_FREE_NULL

/**
 * These functions set an atom to a new value. The old atom is dereferenced.
 * This prevents one issue: "value" might actually be the current atom. If
 * it has a reference count of 1, dereferencing would free "value" as well
 * and we end up with a corrupt atom.
 */
#define GENERATE_ATOM_CHANGE(name, type) \
static inline void \
atom_ ## name ## _change(const type *atom_ptr, const type value) \
{ \
	const void *atom = value ? atom_ ## name ## _get(value) : NULL; \
	atom_ ## name ## _free_null(atom_ptr); \
	*atom_ptr = atom; \
}

GENERATE_ATOM_CHANGE(filesize, filesize_t *)
GENERATE_ATOM_CHANGE(guid, gchar *)
GENERATE_ATOM_CHANGE(sha1, struct sha1 *)
GENERATE_ATOM_CHANGE(str, gchar *)
GENERATE_ATOM_CHANGE(tth, struct tth *)
GENERATE_ATOM_CHANGE(uint64, guint64 *)
GENERATE_ATOM_CHANGE(uint32, guint32 *)
#undef GENERATE_ATOM_CHANGE

#endif	/* _atoms_h_ */

/* vi: set ts=4 sw=4 cindent: */

