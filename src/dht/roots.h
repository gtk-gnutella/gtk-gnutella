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
 * Lookup / publish root node caching.
 *
 * @author Raphael Manfredi
 * @date 2009
 */

#ifndef _dht_roots_h_
#define _dht_roots h_

#include "lib/patricia.h"
#include "knode.h"
#include "kuid.h"

/*
 * Public interface.
 */

void roots_init(void);
void roots_close(void);

void roots_record(patricia_t *nodes, const kuid_t *kuid);
int roots_fill_closest(const kuid_t *id,
	knode_t **kvec, int kcnt, patricia_t *known);

#endif /* _dht_roots_h_ */

/* vi: set ts=4 sw=4 cindent: */
