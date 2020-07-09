/*
 * Copyright (c) 2009, Raphael Manfredi
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
 * @ingroup dht
 * @file
 *
 * Stable node recording.
 *
 * @author Raphael Manfredi
 * @date 2009
 */

#ifndef _dht_stable_h_
#define _dht_stable h_

#include "lib/tm.h"
#include "if/dht/knode.h"
#include "if/dht/lookup.h"

/*
 * Public interface.
 */

void stable_init(void);
void stable_close(void);

double stable_alive_probability(time_delta_t t, time_delta_t d);
double stable_still_alive_probability(time_t first_seen, time_t last_seen);

void stable_record_activity(const knode_t *kn);
void stable_replace(const knode_t *kn, const knode_t *rn);

#endif /* _dht_stable_h_ */

/* vi: set ts=4 sw=4 cindent: */
