/*
 * $Id$
 *
 * Copyright (c) 2003, Jeroen Asselman
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
 * Tiger hash.
 *
 * @author Jeroen Asselman
 * @date 2003
 */

#ifndef _tiger_h_
#define _tiger_h_

#include <glib.h>

void tiger_init(void);
void tiger(gconstpointer data, guint64 length, guint64 res[3]);

/* This only used internally by tiger and tigertree */
static inline void
tiger_fix_endian(guint64 res[3])
#if G_BYTE_ORDER == G_LITTLE_ENDIAN
{
	(void) res;
}
#else /* !little-endian */
{
	res[0] = guint64_to_LE(res[0]);
	res[1] = guint64_to_LE(res[1]);
	res[2] = guint64_to_LE(res[2]);
}
#endif /* little-endian */

#endif /* _tiger_h_ */
/* vi: set ts=4 sw=4 cindent: */

