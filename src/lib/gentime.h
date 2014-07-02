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
 *      59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *----------------------------------------------------------------------
 */

/**
 * @ingroup lib
 * @file
 *
 * Generation Timestamp functions.
 *
 * A generation timestamp is a timestamp that can be compared to another
 * generation timestamp by taking into account any clock adjustments that
 * can have been performed between the two, provided there are not too many
 * generations between the two stamps.
 *
 * The aim of generation timestamps is to provide safe timeout computatations
 * in critical code such as spinlocks.
 *
 * @author Raphael Manfredi
 * @date 2013
 */

#ifndef _gentime_h_
#define _gentime_h_

#include "timestamp.h"

/*
 * A generation timestamp.
 */
typedef struct gentime {
	unsigned generation;		/* The generation number */
	time_t stamp;				/* The associated timestamp */
} gentime_t;

#define GENTIME_ZERO	{ 0, 0 }

/*
 * Public interface.
 */

gentime_t gentime_now(void);
gentime_t gentime_now_exact(void);
gentime_t gentime_from(time_t stamp);
time_delta_t gentime_diff(const gentime_t t1, const gentime_t t0);

void gentime_init(void);
void gentime_close(void);

static inline bool ALWAYS_INLINE
gentime_is_zero(const gentime_t gt)
{
	return 0 == gt.stamp;
}

/**
 * Extract the time from a generation time.
 */
static inline time_t ALWAYS_INLINE
gentime_time(const gentime_t gt)
{
	return gt.stamp;
}

#endif /* _gentime_h_ */

/* vi: set ts=4 sw=4 cindent: */
