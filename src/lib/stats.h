/*
 * $Id$
 *
 * Copyright (c) 2004, Raphael Manfredi
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
 * Statistics routines.
 *
 * @author Raphael Manfredi
 * @date 2004
 */

#ifndef _stats_h_
#define _stats_h_

#include "common.h"

/*
 * One dimension statistics.
 */

gpointer statx_make(void);
void statx_free(gpointer ox);
void statx_clear(gpointer ox);
void statx_add(gpointer ox, gdouble val);
void statx_remove(gpointer ox, gdouble val);
gint statx_n(gpointer ox);
gdouble statx_avg(gpointer ox);
gdouble statx_sdev(gpointer ox);
gdouble statx_var(gpointer ox);
gdouble *statx_data(gpointer ox);

#endif /* _stats_h_ */

/* vi: set ts=4: */
