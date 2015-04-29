/*
 * Copyright (c) 2011, Raphael Manfredi
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
 * Numeric IDs.
 *
 * @author Raphael Manfredi
 * @date 2011
 */

#include "common.h"

#include "nid.h"
#include "atoms.h"
#include "hashing.h"
#include "stringify.h"

#include "override.h"			/* Must be the last header included */

static struct nid nid_counter;

/**
 * Hash code for a numeric ID.
 */
unsigned
nid_hash(const void *key)
{
	const struct nid *p = key;
	uint64 v = nid_value(p);
#if LONGSIZE <= 4
	return integer_hash_fast(v ^ (v >> 32));
#else
	/* uint64 and ulong are identical types */
	return integer_hash_fast(v);
#endif
}

/**
 * Second hash code for a numeric ID.
 */
unsigned
nid_hash2(const void *key)
{
	const struct nid *p = key;
	uint64 v = nid_value(p);
#if LONGSIZE <= 4
	return integer_hash2(v ^ (v >> 32));
#else
	/* uint64 and ulong are identical types */
	return integer_hash2(v);
#endif
}

/**
 * Are two numeric IDs holding the same value?
 */
bool
nid_equal(const void *p, const void *q)
{
	uint64 a = nid_value(p), b = nid_value(q);
	return a == b;
}

/**
 * Stringify numeric ID to static buffer.
 */
const char *
nid_to_string(const struct nid *nid)
{
	static char buf[UINT64_DEC_BUFLEN];
	uint64_to_string_buf(nid_value(nid), buf, sizeof buf);
	return buf;
}

/**
 * Stringify numeric ID to static buffer.
 */
const char *
nid_to_string2(const struct nid *nid)
{
	static char buf[UINT64_DEC_BUFLEN];
	uint64_to_string_buf(nid_value(nid), buf, sizeof buf);
	return buf;
}

/**
 * Increase reference count on a numeric ID.
 */
struct nid *
nid_ref(const struct nid *nid)
{
	return (struct nid *) atom_uint64_get(&nid->value);
}

/**
 * Decrease reference count on a numeric ID.
 */
void
nid_unref(const struct nid *nid)
{
	g_assert(nid != NULL);

	atom_uint64_free(&nid->value);
}

/**
 * Return new unique numeric ID, reference-counted.
 */
struct nid *
nid_new(void)
{
	nid_counter.value++;
	g_assert(nid_counter.value != 0);	/* Game over */
	return nid_ref(&nid_counter);
}

/**
 * Return next numeric ID from supplied counter, reference-counted.
 */
struct nid *
nid_new_counter(struct nid *counter)
{
	counter->value++;
	g_assert(counter->value != 0);	/* Game over */
	return nid_ref(counter);
}

/**
 * Return new unique numeric ID, by value.
 */
struct nid
nid_new_value(void)
{
	nid_counter.value++;
	g_assert(nid_counter.value != 0);	/* Game over */
	return nid_counter;					/* Struct copy */
}

/**
 * Return next unique numeric ID from supplied counter, by value.
 */
struct nid
nid_new_counter_value(struct nid *counter)
{
	counter->value++;
	g_assert(counter->value != 0);	/* Game over */
	return *counter;				/* Struct copy */
}

/* vi: set ts=4 sw=4 cindent: */
