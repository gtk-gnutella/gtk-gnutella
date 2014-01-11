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
 *      59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *----------------------------------------------------------------------
 */

/**
 * @ingroup dht
 * @file
 *
 * Kademlia value publishing.
 *
 * @author Raphael Manfredi
 * @date 2009
 */

#ifndef _dht_publish_h_
#define _dht_publish_h_

#include "if/dht/publish.h"

#include "values.h"
#include "lookup.h"

/*
 * Public interface.
 */

void publish_init(void);
void publish_close(bool exiting);

struct pslist;

publish_t *publish_cache(const kuid_t *key,
	lookup_rc_t *target, dht_value_t **vvec, int vcnt);
publish_t *publish_offload(const knode_t *kn, struct pslist *keys);

#endif	/* _dht_publish_h_ */

/* vi: set ts=4 sw=4 cindent: */
