/*
 * Copyright (c) 2008, Raphael Manfredi
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
 *      51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *----------------------------------------------------------------------
 */

#ifndef _if_dht_kuid_h_
#define _if_dht_kuid_h_

#include "common.h"

#define KUID_RAW_SIZE		20
#define KUID_RAW_BITSIZE	(KUID_RAW_SIZE * 8)
#define KUID_HEX_SIZE		(2 * KUID_RAW_SIZE)
#define KUID_HEX_BUFLEN		(KUID_HEX_SIZE + 1)

typedef struct kuid {
	uchar v[KUID_RAW_SIZE];
} kuid_t;

/**
 * Copy other KUID into destination.
 */
static inline void
kuid_copy(kuid_t *dest, const kuid_t *other)
{
	memmove(dest->v, other->v, KUID_RAW_SIZE);
}

/*
 * Public interface.
 */

unsigned kuid_hash(const void *key);
bool kuid_eq(const void *k1, const void *k2);

const char *kuid_to_string(const kuid_t *kuid);
const char *kuid_to_hex_string(const kuid_t *kuid);
const char *kuid_to_hex_string2(const kuid_t *kuid);

kuid_t *kuid_get_atom(const kuid_t *id);
void kuid_atom_free(const kuid_t *k);
static inline void
kuid_atom_free_null(struct kuid **k_ptr)
{
	if (*k_ptr) {
		kuid_atom_free(*k_ptr);
		*k_ptr = NULL;
	}
}
static inline void
kuid_atom_change(struct kuid **atom_ptr, const struct kuid *value)
{
	void *atom = value ? kuid_get_atom(value) : NULL;
	kuid_atom_free_null(atom_ptr);
	*atom_ptr = atom;
}

#endif /* _if_dht_kuid_h */

/* vi: set ts=4 sw=4 cindent: */

