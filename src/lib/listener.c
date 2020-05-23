/*
 * Copyright (c) 2013 Raphael Manfredi
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
 * Event listening interface.
 *
 * @author Raphael Manfredi
 * @date 2013
 */

#include "common.h"

#include "listener.h"
#include "hashing.h"
#include "pow2.h"
#include "spinlock.h"

#include "override.h"			/* Must be the last header included */

/*
 * To avoid too much lock contention between separate event names, we use an
 * array of spinlocks to create the critical sections.  The actual spinlock
 * to use is obtained by hashing the signal name and then indexing within
 * that array.
 */
static spinlock_t listener_access[] = {
	SPINLOCK_INIT, SPINLOCK_INIT, SPINLOCK_INIT, SPINLOCK_INIT,	/* 4 */
	SPINLOCK_INIT, SPINLOCK_INIT, SPINLOCK_INIT, SPINLOCK_INIT,	/* 8 */
	SPINLOCK_INIT, SPINLOCK_INIT, SPINLOCK_INIT, SPINLOCK_INIT,	/* 12 */
	SPINLOCK_INIT, SPINLOCK_INIT, SPINLOCK_INIT, SPINLOCK_INIT,	/* 16 */
	SPINLOCK_INIT, SPINLOCK_INIT, SPINLOCK_INIT, SPINLOCK_INIT,	/* 20 */
	SPINLOCK_INIT, SPINLOCK_INIT, SPINLOCK_INIT, SPINLOCK_INIT,	/* 24 */
	SPINLOCK_INIT, SPINLOCK_INIT, SPINLOCK_INIT, SPINLOCK_INIT,	/* 28 */
	SPINLOCK_INIT, SPINLOCK_INIT, SPINLOCK_INIT, SPINLOCK_INIT,	/* 32 */
};

#define LISTENER_HASH_MASK	(N_ITEMS(listener_access) - 1)

/*
 * Get spinlock to use based on the signal name.
 */
spinlock_t *
listener_get_lock(const char *name)
{
	STATIC_ASSERT(IS_POWER_OF_2(LISTENER_HASH_MASK + 1));

	return &listener_access[string_mix_hash(name) & LISTENER_HASH_MASK];
}

/* vi: set ts=4 sw=4 cindent: */
