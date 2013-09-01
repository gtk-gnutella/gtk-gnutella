/*
 * Copyright (c) 2012, Raphael Manfredi
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
 * Definitions common for hash tables and hash sets.
 *
 * @author Raphael Manfredi
 * @date 2012
 */

#ifndef _hash_h_
#define _hash_h_

enum hash_key_type {
	HASH_KEY_SELF,		/* Self-representing value */
	HASH_KEY_STRING,	/* Strings, NUL-terminated buffer of variable length */
	HASH_KEY_FIXED,		/* Fixed-length buffer keys */
	HASH_KEY_ANY,		/* General key */
	HASH_KEY_ANY_DATA,	/* General key, hashed and compared with data */

	HASH_KEY_MAXTYPE
};

struct hash;

/*
 * The following definitions are only visible within the library.
 */

#if defined(HTABLE_SOURCE) || defined(HSET_SOURCE) || defined(HASH_SOURCE)

enum hmagic {
	HTABLE_MAGIC	= 0x7e62fd45,
	HSET_MAGIC		= 0x7e6295b9,
	HEVSET_MAGIC	= 0x7e622c20,
	HIKSET_MAGIC	= 0x7e626feb
};

#define HASH_MAGIC_SHIFT		16		/* How many trailing unique bits */
#define HASH_MAGIC_COMMON		0x7e62	/* Common leading magic for all types */

#define HASH_MIN_BITS			1
#define HASH_MIN_SIZE			(1U << HASH_MIN_BITS)

/**
 * The key set structure.
 */
struct hkeys {
	enum hash_key_type type;	/* Type of keys */
	size_t size;				/* Size of table (power of 2) */
	size_t items;				/* Number of items held */
	size_t tombs;				/* Amount of deleted items (tombstones) */
	const void **keys;			/* Array of keys */
	unsigned *hashes;			/* Array of hashed keys */
	union {
		struct {
			hash_fn_t hash;			/* Primary key hashing function */
			hash_fn_t hash2;		/* Secondary key hashing function */
		} h;
		struct {
			hash_data_fn_t hash;	/* Single key hashing function */
			void *data;				/* Extra parameter for hashing function */
		} hd;
	} uh;
	union {
		eq_fn_t eq;				/* Key equality test */
		eq_data_fn_t eq_data;	/* Key equality test with extra data */
		size_t keysize;			/* Fixed-length of keys */
	} uk;
	unsigned bits:6;			/* log2(size) -- large enough to hold 63 */
	unsigned resize:1;			/* Too many hops, rebuild or resize */
	unsigned has_values:1;		/* Whether keys have associated values */
	unsigned raw_memory:1;		/* Don't use walloc(), use VMM and xpmalloc() */
};

#define HASH(x)		((struct hash *) (x))

/*
 * Type of item in given position (hashes[] from key set).
 */

#define HASH_FREE	0			/* Nothing there */
#define HASH_TOMB	1			/* Item deleted */
#define HASH_REAL	2			/* First real hash value */

#define HASH_IS_FREE(x)			(HASH_FREE == (x))
#define HASH_IS_TOMB(x)			(HASH_TOMB == (x))
#define HASH_IS_REAL(x)			((x) >= HASH_REAL)

/**
 * Redefined routines in each heir.
 *
 * These operations are defined for polymorphic dispatching from routines
 * that are defined in the ancestor, not for all the operations that can
 * happen on a hash table.
 */
struct hash_ops {
	void (*set_values)(struct hash *h, const void **p);
	const void **(*get_values)(const struct hash *h);
	void (*hash_free)(struct hash *h);
};

/**
 * Common hash attributes.
 *
 * This is the ancestor of our little hierarchy here, which has two heirs:
 * a hash table and a hash set.
 */
#define HASH_COMMON_ATTRIBUTES \
	enum hmagic magic;			/* Magic number */	\
	size_t refcnt;				/* Iterator reference count */ \
	size_t stamp;				/* Modification stamp */ \
	struct hkeys kset;			/* Set of keys */	\
	const struct hash_ops *ops;	/* Polymorphism */

/**
 * A hash table or hash set header.
 */
struct hash {
	HASH_COMMON_ATTRIBUTES
};

/*
 * Protected interface.
 */

/*
 * Routines with a keyset parameter only handle keys.
 */

void hash_keyhash_setup(struct hkeys *hk,
	enum hash_key_type ktype, size_t keysize);
void hash_keyhash_any_setup(struct hkeys *hk,
	hash_fn_t primary, hash_fn_t secondary, eq_fn_t eq);
void hash_keyhash_data_setup(struct hkeys *hk,
	hash_data_fn_t hash, void *data, eq_data_fn_t eq);
bool hash_keyset_erect_tombstone(struct hkeys *hk, size_t idx);

/*
 * Routines with a hash parameter also handle values, if any, when resizing.
 */

void hash_arena_allocate(struct hash *h, size_t bits);
void hash_arena_free(struct hash *h);
bool hash_resize_as_needed(struct hash *h);
size_t hash_insert_key(struct hash *h, const void *key);
size_t hash_lookup_key(struct hash *h, const void *key);
bool hash_delete_key(struct hash *h, const void *key);

void hash_refcnt_inc(const struct hash *h);
void hash_refcnt_dec(const struct hash *h);

#endif	/* HTABLE_SOURCE || HSET_SOURCE || HASH_SOURCE */

/*
 * Public polymorphic interface.
 */

void hash_foreach(const struct hash *h, data_fn_t fn, void *data);
void hash_clear(struct hash *h);
size_t hash_count(const struct hash *h);
void hash_free(struct hash *h);

#endif /* _hash_h_ */

/* vi: set ts=4 sw=4 cindent: */
