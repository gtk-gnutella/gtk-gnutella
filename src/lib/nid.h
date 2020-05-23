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
 *      51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
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

#ifndef _nid_h_
#define _nid_h_

/*
 * A unique numerical ID that will never overflow, hopefully.
 */
struct nid {
	uint64 value;
};

/*
 * Public interface.
 */

unsigned nid_hash(const void *key);
unsigned nid_hash2(const void *key);
bool nid_equal(const void *p, const void *q);
const char *nid_to_string(const struct nid *nid);
const char *nid_to_string2(const struct nid *nid);
struct nid *nid_ref(const struct nid *nid);
void nid_unref(const struct nid *nid);
struct nid *nid_new(void);
struct nid *nid_new_counter(struct nid *counter);
struct nid nid_new_value(void);
struct nid nid_new_counter_value(struct nid *counter);

static inline uint64
nid_value(const struct nid *nid)
{
	return nid->value;
}

#endif /* _nid_h_ */

/* vi: set ts=4 sw=4 cindent: */
