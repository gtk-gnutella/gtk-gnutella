/*
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

typedef struct statx statx_t;

statx_t *statx_make(void);
statx_t *statx_make_nodata(void);
void statx_free(statx_t *);
void statx_clear(statx_t *);
void statx_add(statx_t *, double);
void statx_remove(statx_t *, double);
void statx_remove_oldest(statx_t *);
int statx_n(const statx_t *);
double statx_avg(const statx_t *);
double statx_sdev(const statx_t *);
double statx_var(const statx_t *);
double statx_stderr(const statx_t *);
double *statx_data(const statx_t *);

#endif /* _stats_h_ */

/* vi: set ts=4 sw=4 cindent: */
