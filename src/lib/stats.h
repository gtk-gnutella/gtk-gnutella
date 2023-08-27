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
 *      51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
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

struct statistics;

typedef struct statistics statx_t;

statx_t *statx_make(void);
statx_t *statx_make_nodata(void);
void statx_free(statx_t *);
void statx_free_null(statx_t **);
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

void statx_foreach(const statx_t *sx, double_data_fn_t cb, void *udata);
size_t statx_foreach_remove(statx_t *sx, double_data_rm_fn_t cb, void *udata);

size_t statx_remove_outliers(statx_t *sx, double range);

#endif /* _stats_h_ */

/* vi: set ts=4 sw=4 cindent: */
