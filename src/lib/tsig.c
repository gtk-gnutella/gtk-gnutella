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
 * Thread signal set operations.
 */

#include "common.h"

#include "tsig.h"

#include "override.h"			/* Must be the last header included */

/**
 * Add signal to set.
 *
 * @return 0 if OK, -1 on error with errno set.
 */
int
tsig_addset(tsigset_t *set, int signum)
{
	g_assert(set != NULL);

	if G_UNLIKELY(signum <= 0 || signum >= TSIG_COUNT) {
		errno = EINVAL;
		return -1;
	}

	*set |= tsig_mask(signum);
	return 0;
}

/**
 * Remove signal from set.
 *
 * @return 0 if OK, -1 on error with errno set.
 */
int
tsig_delset(tsigset_t *set, int signum)
{
	g_assert(set != NULL);

	if G_UNLIKELY(signum <= 0 || signum >= TSIG_COUNT) {
		errno = EINVAL;
		return -1;
	}

	*set &= ~tsig_mask(signum);
	return 0;
}

/**
 * Is signal part of the set?
 *
 * @return TRUE if signal is in the set.
 */
bool
tsig_ismember(const tsigset_t *set, int signum)
{
	g_assert(set != NULL);

	if G_UNLIKELY(signum <= 0 || signum >= TSIG_COUNT)
		return FALSE;

	return booleanize(*set & tsig_mask(signum));
}

/* vi: set ts=4 sw=4 cindent: */
