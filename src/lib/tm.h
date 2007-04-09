/*
 * $Id$
 *
 * Copyright (c) 2003-2005, Raphael Manfredi
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
 * Time manipulation and caching routines.
 *
 * @author Raphael Manfredi
 * @date 2003-2005
 */

#ifndef _tm_h_
#define _tm_h_

#include "common.h"

/**
 * tm_zero
 *
 * Returns true if time is zero.
 */
#define tm_zero(t)	((t)->tv_sec == 0 && (t)->tv_usec == 0)

/**
 * tm2f
 *
 * Convert timeval description into floating point representatiion.
 */
#define tm2f(t)		((double) (t)->tv_sec + (t)->tv_usec / 1000000.0)

/**
 * tm2ms
 *
 * Convert timeval description into milliseconds.
 */
#define tm2ms(t)	((t)->tv_sec * 1000 + (t)->tv_usec / 1000)

/**
 * tm2us
 *
 * Convert timeval description into microseconds.
 */
#define tm2us(t)	((t)->tv_sec * 1000000 + (t)->tv_usec)

typedef GTimeVal tm_t;

void f2tm(double t, tm_t *tm);
void tm_elapsed(tm_t *elapsed, const tm_t *t1, const tm_t *t0);
void tm_sub(tm_t *tm, const tm_t *dec);
void tm_add(tm_t *tm, const tm_t *inc);
int tm_cmp(const tm_t *a, const tm_t *b);

void tm_now(tm_t *tm);
void tm_now_exact(tm_t *tm);
time_t tm_time(void);
time_t tm_time_exact(void);
gdouble tm_cputime(gdouble *user, gdouble *sys);

guint tm_hash(gconstpointer key);
gint tm_equal(gconstpointer a, gconstpointer b);

#endif /* _tm_h_ */
