/*
 * Copyright (c) 2005, Raphael Manfredi
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
 * @ingroup core
 * @file
 *
 * Handles the client-side of the Browse Host function.
 *
 * @author Raphael Manfredi
 * @date 2005
 */

#ifndef _core_bh_download_h_
#define _core_bh_download_h_

#include "common.h"

#include "search.h"

/**
 * Flags for browse_host_dl_open().
 */
#define BH_DL_INFLATE	(1 << 0)	/**< Inflate input */
#define BH_DL_GUNZIP	(1 << 1)	/**< gunzip input */
#define BH_DL_CHUNKED	(1 << 2)	/**< Getting chunked data */
#define BH_DL_G2		(1 << 3)	/**< Expecting G2 query hits */

/*
 * Public interface.
 */

struct browse_ctx;
struct bio_source;

struct browse_ctx *browse_host_dl_create(
	void *owner, gnet_host_t *host, gnet_search_t sh);
void browse_host_dl_free(struct browse_ctx **ptr);
bool browse_host_dl_for_search(struct browse_ctx *bc, gnet_search_t sh);
void browse_host_dl_write(struct browse_ctx *bc, char *data, size_t len);
bool browse_host_dl_receive(
	struct browse_ctx *bc, gnet_host_t *host, struct wrap_io *wio,
	const char *vendor, uint32 flags);
struct bio_source *browse_host_io_source(struct browse_ctx *bc);
void browse_host_dl_close(struct browse_ctx *bc);
void browse_host_dl_search_closed(struct browse_ctx *bc, gnet_search_t sh);

#endif /* _core_bh_download_h_ */

/* vi: set ts=4 sw=4 cindent: */
