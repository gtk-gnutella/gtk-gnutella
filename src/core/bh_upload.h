/*
 * Copyright (c) 2005, Christian Biere & Raphael Manfredi
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
 * Handles the server-side of the Browse Host function.
 *
 * @author Christian Biere
 * @author Raphael Manfredi
 * @date 2005
 */

#ifndef _core_bh_upload_h_
#define _core_bh_upload_h_

#include "common.h"

#include "special_upload.h"

/**
 * The version of the Browse-Host protocol we support.
 */
#define BH_VERSION_MAJOR	1
#define BH_VERSION_MINOR	0

/**
 * Flags for browse_host_open().
 */

enum {
	BH_F_G2		 = 1 << 5,		/**< Use G2 query hits */
	BH_F_QHITS	 = 1 << 4,		/**< Emit query hits */
	BH_F_HTML	 = 1 << 3,		/**< Emit HTML data */
	BH_F_CHUNKED = 1 << 2,		/**< Emit chunked data */
	BH_F_GZIP	 = 1 << 1,		/**< gzip output */
	BH_F_DEFLATE = 1 << 0		/**< Deflate output */
};

struct gnutella_host;
struct tx_deflate_cb;
struct tx_link_cb;
struct wrap_io;

struct special_upload *browse_host_open(
	void *owner,
	struct gnutella_host *host,
	special_upload_writable_t writable,
	const struct tx_deflate_cb *deflate_cb,
	const struct tx_link_cb *link_cb,
	struct wrap_io *wio,
	int flags);

#endif /* _core_bh_upload_h_ */

/* vi: set ts=4 sw=4 cindent: */
