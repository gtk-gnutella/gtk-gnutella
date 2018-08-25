/*
 * Copyright (c) 2007, Christian Biere
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

#ifndef _tth_cache_h_
#define _tth_cache_h_

#include "common.h"

#include "lib/misc.h"

void tth_cache_init(void);
void tth_cache_insert(const struct tth *tth, const struct tth *leaves, int n);
size_t tth_cache_lookup(const struct tth *tth, filesize_t filesize);
size_t tth_cache_get_tree(const struct tth *tth, filesize_t filesize,
		const struct tth **tree);
size_t tth_cache_get_nleaves(const struct tth *tth);
void tth_cache_remove(const struct tth *tth);
void tth_cache_close(void);

void tth_cache_cleanup(void);

#endif /* _tth_cache_h_ */

/* vi: set ts=4 sw=4 cindent: */
