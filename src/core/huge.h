/*
 * Copyright (c) 2002-2003, Ch. Tronche & Raphael Manfredi
 *
 * Started by Ch. Tronche (http://tronche.com/) 28/04/2002
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
 * @ingroup core
 * @file
 *
 * HUGE support (Hash/URN Gnutella Extension).
 *
 * @author Raphael Manfredi
 * @date 2002-2003
 * @author Ch. Tronche (http://tronche.com/)
 * @date 2002-04-28
 */

#ifndef _core_huge_h_
#define _core_huge_h_

#include "common.h"

struct gnutella_node;
struct gnutella_host;
struct shared_file;
struct header;
struct sha1;

void huge_init(void);		/**< Call this function at the beginning */
void huge_close(void);		/**< Call this when servent is shutdown */

/*
 * Set the sha1_digest field in a newly created shared_file.
 * If value is found in the cache, it is used, else it is computed and
 * the computed value is saved in the cache.
 */

struct tth;

void request_sha1(struct shared_file *);
bool sha1_is_cached(const struct shared_file *sf);
bool huge_update_hashes(struct shared_file *sf,
	const struct sha1 *sha1, const struct tth *tth);

bool huge_improbable_sha1(const char *buf, size_t len);
bool huge_sha1_extract32(const char *buf, size_t len, struct sha1 *sha1,
	const struct gnutella_node *n);
bool huge_tth_extract32(const char *buf, size_t len, struct tth *tth,
	const struct gnutella_node *n);
void huge_collect_locations(
	const struct sha1 *sha1, const struct header *header,
	const struct gnutella_host *origin);
bool huge_cached_is_uptodate(const char *path, filesize_t size, time_t mtime);

void huge_sha1_cache_prune(void);

#endif	/* _core_huge_h_ */

/*
 * Emacs stuff:
 * Local Variables: ***
 * c-indentation-style: "bsd" ***
 * fill-column: 80 ***
 * tab-width: 4 ***
 * indent-tabs-mode: nil ***
 * End: ***
 */
/* vi: set ts=4 sw=4 cindent: */
