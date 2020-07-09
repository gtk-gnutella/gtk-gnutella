/*
 * Copyright (c) 2006-2009, Raphael Manfredi
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

/**
 * @ingroup dht
 * @file
 *
 * Kademlia Unique IDs (KUID) and KUID-based integer arithmetic.
 *
 * @author Raphael Manfredi
 * @date 2006-2009
 */

#ifndef _dht_kuid_h_
#define _dht_kuid_h_

#include "if/dht/kuid.h"

/*
 * Public interface.
 */

void kuid_random_fill(kuid_t *kuid);
void kuid_from_buf(kuid_t *dest, const char *id);
bool kuid_is_blank(const kuid_t *kuid) G_PURE;
int kuid_cmp3(const kuid_t *target, const kuid_t *kuid1, const kuid_t *kuid2)
	G_PURE;
int kuid_cmp(const kuid_t *kuid1, const kuid_t *kuid2) G_PURE;
void kuid_xor_distance(kuid_t *res, const kuid_t *k1, const kuid_t *k2);
bool kuid_match_nth(const kuid_t *k1, const kuid_t *k2, int bits)
	G_PURE;
size_t kuid_common_prefix(const kuid_t *k1, const kuid_t *k2) G_PURE;
void kuid_random_within(kuid_t *dest, const kuid_t *prefix, int bits);
void kuid_flip_nth_leading_bit(kuid_t *res, int n);
void kuid_zero(kuid_t *res);

/**
 * Return leading KUID byte.
 */
static inline uint8
kuid_leading_u8(const kuid_t *k)
{
	return k->v[0];
}

#endif /* _dht_kuid_h_ */

/* vi: set ts=4 sw=4 cindent: */
