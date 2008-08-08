/*
 * $Id$
 *
 * Copyright (c) 2006-2008, Raphael Manfredi
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
 * @ingroup dht
 * @file
 *
 * Kademlia Unique ID (KUID) manager.
 *
 * @author Raphael Manfredi
 * @date 2006-2008
 */

#ifndef _dht_kuid_h_
#define _dht_kuid_h_

#include "common.h"

#define KUID_RAW_SIZE		20
#define KUID_RAW_BITSIZE	(KUID_RAW_SIZE * 8)

typedef struct kuid {
	guchar v[KUID_RAW_SIZE];
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

void kuid_init(void);
void kuid_random_fill(kuid_t *kuid);
void kuid_from_buf(kuid_t *dest, const gchar *id);
int kuid_cmp3(const kuid_t *target, const kuid_t *kuid1, const kuid_t *kuid2);
int kuid_cmp(const kuid_t *kuid1, const kuid_t *kuid2);
gboolean kuid_eq(const kuid_t *k1, const kuid_t *k2);
const gchar *kuid_to_string(const kuid_t *kuid);
const gchar *kuid_to_hex_string(const kuid_t *kuid);
const gchar *kuid_to_hex_string2(const kuid_t *kuid);
gboolean kuid_match_nth(const kuid_t *k1, const kuid_t *k2, int bits);
void kuid_random_within(kuid_t *dest, const kuid_t *prefix, int bits);
void kuid_flip_nth_leading_bit(kuid_t *res, int n);

kuid_t *kuid_get_atom(const kuid_t *id);
void kuid_atom_free(const kuid_t *k);

void kuid_zero(kuid_t *res);
void kuid_set32(kuid_t *res, guint32 val);
void kuid_set_nth_bit(kuid_t *res, int n);
gboolean kuid_add(kuid_t *res, const kuid_t *other);
gboolean kuid_lshift(kuid_t *res);
void kuid_rshift(kuid_t *res);
double kuid_to_double(const kuid_t *value);

#endif /* _dht_kuid_h_ */

/* vi: set ts=4 sw=4 cindent: */
