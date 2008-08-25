/*
 * $Id$
 *
 * Copyright (c) 2008, Raphael Manfredi
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
 * @ingroup dht
 * @file
 *
 * Local values management.
 *
 * @author Raphael Manfredi
 * @date 2008
 */

#ifndef _dht_values_h_
#define _dht_values_h_

#include "if/dht/value.h"

/*
 * Public interface.
 */

void values_init(void);
void values_close(void);

size_t values_count(void);

guint16 values_store(const knode_t *kn, const dht_value_t *v, gboolean token);
dht_value_t *values_get(guint64 dbkey, dht_value_type_t type);
void values_reclaim_expired(void);
gboolean values_has_expired(guint64 dbkey, time_t now, time_t *expire);

#endif /* _dht_values_h_ */

/* vi: set ts=4 sw=4 cindent: */
