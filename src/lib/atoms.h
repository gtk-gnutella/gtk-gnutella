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
#include "gnet_host.h"		/* For gnet_host_t */

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
	ATOM_HOST,		/**< gnet_host_t "IP:port" (binary) */

	NUM_ATOM_TYPES
};

#if !defined(TRACK_ATOMS) || defined(ATOMS_SOURCE)
const void *atom_get(enum atom_type type, const void *key);
void atom_free(enum atom_type type, const void *key);
#endif

bool atom_exists(enum atom_type type, const void *key);

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

#define atom_tth_get(k)		atom_get_track(ATOM_TTH, (k), _WHERE_, __LINE__)
#define atom_tth_free(k)	atom_free_track(ATOM_TTH, (k), _WHERE_, __LINE__)

#define atom_uint64_get(k)	atom_get_track(ATOM_UINT64, (k), _WHERE_, __LINE__)
#define atom_uint64_free(k)	atom_free_track(ATOM_UINT64, (k), _WHERE_, __LINE__)

#define atom_uint32_get(k)	atom_get_track(ATOM_UINT32, (k), _WHERE_, __LINE__)
#define atom_uint32_free(k)	atom_free_track(ATOM_UINT32, (k), _WHERE_, __LINE__)

#define atom_host_get(k)	atom_get_track(ATOM_HOST, (k), _WHERE_, __LINE__)
#define atom_host_free(k)	atom_free_track(ATOM_HOST, (k), _WHERE_, __LINE__)

#define atom_filesize_get(k) \
	atom_get_track(ATOM_FILESIZE, (k), _WHERE_, __LINE__)
#define atom_filesize_free(k) \
	atom_free_track(ATOM_FILESIZE, (k), _WHERE_, __LINE__)

#ifndef ATOMS_SOURCE
#define atom_get(t,k)		atom_get_track(t, (k), _WHERE_, __LINE__)
#define atom_free(t,k)		atom_free_track(t, (k), _WHERE_, __LINE__)
#endif

#else	/* !TRACK_ATOMS */

static inline const char *
atom_str_get(const char *k)
{
	return atom_get(ATOM_STRING, k);
}

static inline void
atom_str_free(const char *k)
{
	atom_free(ATOM_STRING, k);
}

static inline const struct guid *
atom_guid_get(const struct guid *k)
{
	return atom_get(ATOM_GUID, k);
}

static inline void
atom_guid_free(const struct guid *k)
{
	atom_free(ATOM_GUID, k);
}

static inline const struct sha1 *
atom_sha1_get(const struct sha1 *k)
{
	return atom_get(ATOM_SHA1, k);
}

static inline void
atom_sha1_free(const struct sha1 *k)
{
	atom_free(ATOM_SHA1, k);
}

static inline const struct tth *
atom_tth_get(const struct tth *k)
{
	return atom_get(ATOM_TTH, k);
}

static inline void
atom_tth_free(const struct tth *k)
{
	atom_free(ATOM_TTH, k);
}

static inline const uint64 *
atom_uint64_get(const uint64 *k)
{
	return atom_get(ATOM_UINT64, k);
}

static inline void
atom_uint64_free(const uint64 *k)
{
	atom_free(ATOM_UINT64, k);
}

static inline const filesize_t *
atom_filesize_get(const filesize_t *k)
{
	return atom_get(ATOM_FILESIZE, k);
}

static inline void
atom_filesize_free(const filesize_t *k)
{
	atom_free(ATOM_FILESIZE, k);
}

static inline const uint32 *
atom_uint32_get(const uint32 *k)
{
	return atom_get(ATOM_UINT32, k);
}

static inline void
atom_uint32_free(const uint32 *k)
{
	atom_free(ATOM_UINT32, k);
}

static inline const gnet_host_t *
atom_host_get(const gnet_host_t *k)
{
	return atom_get(ATOM_HOST, k);
}

static inline void
atom_host_free(const gnet_host_t *k)
{
	atom_free(ATOM_HOST, k);
}

#endif	/* TRACK_ATOMS */

/*
 * Public interface.
 */

void atoms_init(void);
void atoms_close(void);

static inline bool
atom_is_str(const char *k)
{
	return atom_exists(ATOM_STRING, k);
}

static inline bool
atom_is_guid(const struct guid *k)
{
	return atom_exists(ATOM_GUID, k);
}

static inline bool
atom_is_sha1(const struct sha1 *k)
{
	return atom_exists(ATOM_SHA1, k);
}

static inline bool
atom_is_tth(const struct tth *k)
{
	return atom_exists(ATOM_TTH, k);
}

static inline bool
atom_is_uint64(const uint64 *k)
{
	return atom_exists(ATOM_UINT64, k);
}

static inline bool
atom_is_filesize(const filesize_t *k)
{
	return atom_exists(ATOM_FILESIZE, k);
}

static inline bool
atom_is_uint32(const uint32 *k)
{
	return atom_exists(ATOM_UINT32, k);
}

static inline bool
atom_is_host(const gnet_host_t *k)
{
	return atom_exists(ATOM_HOST, k);
}

/*
 * Hash functions and equality checks
 */
uint filesize_hash(const void *key) G_GNUC_PURE;
int filesize_eq(const void *a, const void *b) G_GNUC_PURE;
uint sha1_hash(const void *key) G_GNUC_PURE;
int sha1_eq(const void *a, const void *b) G_GNUC_PURE;
uint tth_hash(const void *key) G_GNUC_PURE;
int tth_eq(const void *a, const void *b) G_GNUC_PURE;
uint guid_hash(const void *key) G_GNUC_PURE;
int guid_eq(const void *a, const void *b) G_GNUC_PURE;
uint uint64_hash(const void *key) G_GNUC_CONST;
int uint64_eq(const void *a, const void *b) G_GNUC_PURE;
uint uint64_mem_hash(const void *key) G_GNUC_PURE;
int uint64_mem_eq(const void *a, const void *b) G_GNUC_PURE;
uint uint32_hash(const void *key) G_GNUC_PURE;
int uint32_eq(const void *a, const void *b) G_GNUC_PURE;

#ifdef TRACK_ATOMS
const void *atom_get_track(enum atom_type, const void *key,
			char *file, int line);
void atom_free_track(enum atom_type, const void *key, char *file, int line);
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
GENERATE_ATOM_FREE_NULL(guid, struct guid *)
GENERATE_ATOM_FREE_NULL(sha1, struct sha1 *)
GENERATE_ATOM_FREE_NULL(str, char *)
GENERATE_ATOM_FREE_NULL(tth, struct tth *)
GENERATE_ATOM_FREE_NULL(uint64, uint64 *)
GENERATE_ATOM_FREE_NULL(uint32, uint32 *)
GENERATE_ATOM_FREE_NULL(host, gnet_host_t *)
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
GENERATE_ATOM_CHANGE(guid, struct guid *)
GENERATE_ATOM_CHANGE(sha1, struct sha1 *)
GENERATE_ATOM_CHANGE(str, char *)
GENERATE_ATOM_CHANGE(tth, struct tth *)
GENERATE_ATOM_CHANGE(uint64, uint64 *)
GENERATE_ATOM_CHANGE(uint32, uint32 *)
#undef GENERATE_ATOM_CHANGE

#endif	/* _atoms_h_ */

/* vi: set ts=4 sw=4 cindent: */

