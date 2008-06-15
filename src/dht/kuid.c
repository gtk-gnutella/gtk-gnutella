/*
 * $Id$
 *
 * Copyright (c) 2006, Raphael Manfredi
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
 * Kademlia Unique IDs (KUID).
 *
 * @author Raphael Manfredi
 * @date 2006
 */

#include "common.h"

RCSID("$Id$")

#include "kuid.h"

#include "lib/atoms.h"
#include "lib/misc.h"
#include "lib/override.h"		/* Must be the last header included */

/**
 * Initialize KUID management.
 */
void
kuid_init(void)
{
}

/**
 * Generate a new random KUID within given `kuid'.
 */
void
kuid_random_fill(kuid_t *kuid)
{
	random_bytes(kuid->v, KUID_RAW_SIZE);
}

/**
 * Compare three KUID with the XOR distance, to determine whether `kuid1' is
 * closer to `target' than `kuid2'.
 *
 * @param target	the target KUID we want to get the closest to
 * @param kuid1		KUID #1
 * @param kuid2		KUID #2
 *
 * @return -1 if KUID #1 is closer to target that KUID #2, +1 if KUID #1 is
 * farther away from target than KUID #2, and 0 if both are equidistant.
 */
gint
kuid_cmp(const kuid_t *target, const kuid_t *kuid1, const kuid_t *kuid2)
{
	gint i;

	for (i = 0; i < KUID_RAW_SIZE; i++) {
		guint d1 = kuid1->v[i] ^ target->v[i];
		guint d2 = kuid2->v[i] ^ target->v[i];

		if (d1 < d2)
			return -1;
		else if (d2 < d1)
			return +1;
	}

	return 0;
}

/**
 * Convert a KUID to a base32 string.
 *
 * @return pointer to static data.
 */
const gchar *
kuid_to_string(const kuid_t *kuid)
{
	static gchar buf[SHA1_BASE32_SIZE + 1];

	return sha1_to_base32_buf(cast_to_gconstpointer(&kuid->v), buf, sizeof buf);
}

kuid_t *
kuid_get_atom(const kuid_t *k)
{
	return (kuid_t *) atom_sha1_get((const struct sha1 *) k);
}

void
kuid_atom_free(const kuid_t *k)
{
	atom_sha1_free((const struct sha1 *) k);
}

/* vi: set ts=4 sw=4 cindent: */
