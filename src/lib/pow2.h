/*
 * $Id$
 *
 * Copyright (c) 2001-2009, Raphael Manfredi
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
 * Power of 2 management.
 *
 * @author Raphael Manfredi
 * @date 2001-2009
 */

#ifndef _pow2_h_
#define _pow2_h_

#define IS_POWER_OF_2(x) ((x) && 0 == ((x) & ((x) - 1)))

guint32 next_pow2(guint32 n);

/**
 * Checks whether the given value is a power of 2.
 *
 * @param value a 32-bit integer
 * @return TRUE if ``value'' is a power of 2. Otherwise FALSE.
 */
static inline G_GNUC_CONST gboolean
is_pow2(guint32 value)
#ifdef HAS_BUILTIN_POPCOUNT
{
	return 1 == __builtin_popcount(value);
}
#else /* !HAS_BUILTIN_POPCOUNT */
{
	return IS_POWER_OF_2(value);
}
#endif /* HAS_BUILTIN_POPCOUNT */

#endif /* _pow2_h_ */

/* vi: set ts=4 sw=4 cindent: */
