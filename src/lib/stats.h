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

struct statx;

struct statx *statx_make(void);
void statx_free(struct statx *);
void statx_clear(struct statx *);
void statx_add(struct statx *, double);
void statx_remove(struct statx *, double);
void statx_remove_oldest(struct statx *);
int statx_n(struct statx *);
double statx_avg(struct statx *);
double statx_sdev(struct statx *);
double statx_var(struct statx *);
double *statx_data(struct statx *);

#endif /* _stats_h_ */

/* vi: set ts=4: */
