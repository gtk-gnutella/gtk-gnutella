/*
 * Copyright (c) 2008-2012, Raphael Manfredi
 * Copyright (c) 2003-2008, Christian Biere
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
 * Hashing functions.
 *
 * @author Raphael Manfredi
 * @date 2008-2012
 * @author Christian Biere
 * @date 2003-2008
 */

#include "common.h"

#include "hashing.h"
#include "endian.h"

#include "override.h"			/* Must be the last header included */

/**
 * Hashing of pointers.
 *
 * The identity function makes a poor hash for pointers.
 */
unsigned
pointer_hash_func(const void *p)
{
	unsigned long v = pointer_to_ulong(p);
	return (((guint64) 0x4F1BBCDCUL * v) >> 32) ^ v;
}

/**
 * Hash `len' bytes starting from `data'.
 */
G_GNUC_HOT unsigned
binary_hash(const void *data, size_t len)
{
	const unsigned char *key = data;
	size_t i, remain, t4;
	guint32 hash;

	remain = len & 0x3;
	t4 = len & ~0x3U;

	g_assert(remain + t4 == len);
	g_assert(remain <= 3);

	hash = len;
	for (i = 0; i < t4; i += 4) {
		static const guint32 x[] = {
			0xb0994420, 0x01fa96e3, 0x05066d0e, 0x50c3c22a,
			0xec99f01f, 0xc0eaa79d, 0x157d4257, 0xde2b8419
		};
		hash ^= peek_le32(&key[i]);
		hash += x[(i >> 2) & 0x7];
		hash = (hash << 24) ^ (hash >> 8);
	}

	for (i = 0; i < remain; i++) {
		hash += key[t4 + i];
		hash ^= key[t4 + i] << (i * 8);
		hash = (hash << 24) ^ (hash >> 8);
	}

	return pointer_hash_func(ulong_to_pointer(hash));
}

/* vi: set ts=4 sw=4 cindent: */
