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
 * Hash sets with embedded keys within values.
 *
 * @author Raphael Manfredi
 * @date 2012
 */

#ifndef _hevset_h_
#define _hevset_h_

#include "hash.h"

struct hevset;
typedef struct hevset hevset_t;

struct hevset_iter;
typedef struct hevset_iter hevset_iter_t;

/**
 * Cast set to a polmorphic hash const.
 */
static inline ALWAYS_INLINE const struct hash *
hevset_cast_to_const_hash(const struct hevset *hx)
{
	return (const struct hash *) hx;
}

/**
 * Cast set to a polmorphic hash.
 */
static inline ALWAYS_INLINE struct hash *
hevset_cast_to_hash(const struct hevset *hx)
{
	return (struct hash *) hx;
}

/**
 * Cast pointer to set to a pointer to a polmorphic hash.
 */
static inline ALWAYS_INLINE struct hash **
hevset_ptr_cast_to_hash(struct hevset * const *hx)
{
	return (struct hash **) hx;
}

/*
 * Public interface.
 */

hevset_t *hevset_create(size_t offset, enum hash_key_type ktype, size_t ksize);
hevset_t *hevset_create_real(size_t offset,
	enum hash_key_type ktype, size_t keysize);
hevset_t *hevset_create_any(size_t offset, hash_fn_t primary,
	hash_fn_t secondary, eq_fn_t eq);
hevset_t *hevset_create_any_real(size_t offset, hash_fn_t primary,
	hash_fn_t secondary, eq_fn_t eq);
void hevset_free_null(hevset_t **);
void hevset_clear(hevset_t *);
void hevset_thread_safe(hevset_t *);
void hevset_lock(hevset_t *);
void hevset_unlock(hevset_t *);

bool hevset_contains(const hevset_t *, const void *key);
void hevset_insert_key(hevset_t *ht, const void *key);
void hevset_insert(hevset_t *, const void *value);
void *hevset_lookup(const hevset_t *, const void *key);
bool hevset_lookup_extended(const hevset_t *, const void *key, void **valptr);
void *hevset_random(const hevset_t *ht);
bool hevset_remove(hevset_t *, const void *key);
size_t hevset_count(const hevset_t *);
void hevset_foreach(const hevset_t *, data_fn_t fn, void *data);
size_t hevset_foreach_remove(hevset_t *, data_rm_fn_t, void *);

hevset_iter_t *hevset_iter_new(const hevset_t *);
void hevset_iter_release(hevset_iter_t **);
bool hevset_iter_next(hevset_iter_t *, void **kp);
void hevset_iter_remove(hevset_iter_t *);

#endif /* _hevset_h_ */

/* vi: set ts=4 sw=4 cindent: */
