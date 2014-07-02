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
 * Hash sets with internal key pointers within values.
 *
 * @author Raphael Manfredi
 * @date 2012
 */

#ifndef _hikset_h_
#define _hikset_h_

#include "hash.h"

struct hikset;
typedef struct hikset hikset_t;

struct hikset_iter;
typedef struct hikset_iter hikset_iter_t;

/**
 * Cast set to a polmorphic hash const.
 */
static inline ALWAYS_INLINE const struct hash *
hikset_cast_to_const_hash(const struct hikset *hx)
{
	return (const struct hash *) hx;
}

/**
 * Cast set to a polmorphic hash.
 */
static inline ALWAYS_INLINE struct hash *
hikset_cast_to_hash(const struct hikset *hx)
{
	return (struct hash *) hx;
}

/**
 * Cast pointer to set to a pointer to a polmorphic hash.
 */
static inline ALWAYS_INLINE struct hash **
hikset_ptr_cast_to_hash(struct hikset * const *hx)
{
	return (struct hash **) hx;
}

/*
 * Public interface.
 */

hikset_t *hikset_create(size_t offset, enum hash_key_type ktype, size_t ksize);
hikset_t *hikset_create_real(size_t offset,
	enum hash_key_type ktype, size_t keysize);
hikset_t *hikset_create_any(size_t offset, hash_fn_t primary, eq_fn_t eq);
hikset_t *hikset_create_any_real(size_t offset, hash_fn_t primary, eq_fn_t eq);
void hikset_free_null(hikset_t **);
void hikset_clear(hikset_t *);
void hikset_thread_safe(hikset_t *);
void hikset_lock(hikset_t *);
void hikset_unlock(hikset_t *);

bool hikset_contains(const hikset_t *, const void *key);
void hikset_insert_key(hikset_t *hik, const void *keyptr);
void hikset_insert(hikset_t *, const void *value);
void *hikset_lookup(const hikset_t *, const void *key);
bool hikset_lookup_extended(const hikset_t *, const void *key, void **valptr);
void *hikset_random(const hikset_t *);
bool hikset_remove(hikset_t *, const void *key);
size_t hikset_count(const hikset_t *);
void hikset_foreach(const hikset_t *, data_fn_t fn, void *data);
size_t hikset_foreach_remove(hikset_t *, data_rm_fn_t, void *);

hikset_iter_t *hikset_iter_new(const hikset_t *);
void hikset_iter_release(hikset_iter_t **);
bool hikset_iter_next(hikset_iter_t *, void **kp);
void hikset_iter_remove(hikset_iter_t *);

#endif /* _hikset_h_ */

/* vi: set ts=4 sw=4 cindent: */
