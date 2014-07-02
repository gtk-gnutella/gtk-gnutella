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
 * Constant value management.
 *
 * Constants are atomic values that do not need to be reference-counted because
 * their lifetime is that of the program.
 *
 * Like atoms, they are allocated only once in memory and all constants with
 * the same value bear the same address.
 *
 * Unlike atoms however, they are enforced read-only values.
 *
 * @author Raphael Manfredi
 * @date 2012
 */

#include "common.h"

#include "constants.h"
#include "hashing.h"
#include "hashtable.h"
#include "omalloc.h"
#include "spinlock.h"

#include "override.h"			/* Must be the last header included */

static hash_table_t *constant_strings;

/**
 * @return a constant read-only string.
 */
const char *
constant_str(const char *s)
{
	static spinlock_t constant_slk = SPINLOCK_INIT;
	const char *v;

	if G_UNLIKELY(NULL == constant_strings) {
		spinlock(&constant_slk);
		if (NULL == constant_strings) {
			constant_strings =
				hash_table_new_full_not_leaking(string_mix_hash, string_eq);
			hash_table_thread_safe(constant_strings);
		}
		spinunlock(&constant_slk);
	}

	v = hash_table_lookup(constant_strings, s);

	if G_UNLIKELY(NULL == v) {
		hash_table_lock(constant_strings);
		v = hash_table_lookup(constant_strings, s);
		if G_LIKELY(NULL == v) {
			v = ostrdup_readonly(s);
			hash_table_insert(constant_strings, v, v);
		}
		hash_table_unlock(constant_strings);
	}

	return v;
}

/* vi: set ts=4 sw=4 cindent: */
