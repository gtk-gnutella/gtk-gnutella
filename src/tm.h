/*
 * $Id$
 *
 * Copyright (c) 2003, Raphael Manfredi
 *
 * Time manipulation routines.
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

#ifndef _tm_h_
#define _tm_h_

#include "config.h"

#ifdef I_TIME
#include <time.h>				/* For struct timeval */
#endif
#ifdef I_SYS_TIME
#include <sys/time.h>			/* For struct timeval */
#endif
#ifdef I_SYS_TIME_KERNEL
#define KERNEL
#include <sys/time.h>			/* For struct timeval */
#undef KERNEL
#endif

/*
 * tm_zero
 *
 * Returns true if time is zero.
 */
#define tm_zero(t)	((t)->tv_sec == 0 && (t)->tv_usec == 0)

/*
 * tm2f
 *
 * Convert timeval description into floating point representatiion.
 */
#define tm2f(t)		((double) (t)->tv_sec + (t)->tv_usec / 1000000.0)

/*
 * tm2ms
 *
 * Convert timeval description into milliseconds.
 */
#define tm2ms(t)	((t)->tv_sec * 1000 + (t)->tv_usec / 1000)

typedef struct timeval tm_t;

void f2tm(double t, struct timeval *tm);
void tm_elapsed(tm_t *elapsed, tm_t *last, tm_t *old);
void tm_sub(tm_t *tm, tm_t *dec);
void tm_add(tm_t *tm, tm_t *inc);
int tm_cmp(tm_t *a, tm_t *b);
void tm_now(tm_t *tm);

#endif

