/*
 * $Id$
 *
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
 *      59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
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

#include "tx.h"
#include "tx_link.h"
#include "tx_deflate.h"

#include "if/core/hosts.h"
#include "if/core/wrap.h"

/**
 * The version of the Browse-Host protocol we support.
 */
#define BH_VERSION_MAJOR	1
#define BH_VERSION_MINOR	0

/**
 * Flags for browse_host_open().
 */
#define BH_DEFLATE	(1 << 0)		/**< Deflate output */
#define BH_GZIP		(1 << 1)		/**< gzip output */
#define BH_CHUNKED	(1 << 2)		/**< Emit chunked data */
#define BH_HTML		(1 << 3)		/**< Emit HTML data */
#define BH_QHITS	(1 << 4)		/**< Emit Gnutella query hits */

struct gnutella_socket;
struct bio_source;

typedef void (*bh_closed_t)(gpointer arg);
typedef void (*bh_writable_t)(gpointer arg);

struct special_ctx {
	txdrv_t *tx;
	ssize_t (*read)(gpointer ctx, gpointer dest, size_t size);
	ssize_t (*write)(gpointer ctx, gconstpointer data, size_t size);
	void (*flush)(gpointer ctx, bh_closed_t cb, gpointer arg);
	void (*close)(gpointer ctx, gboolean fully_served);
};

struct special_ctx *browse_host_open(
	gpointer owner, gnet_host_t *host,
	bh_writable_t writable,
	const struct tx_deflate_cb *deflate_cb,
	const struct tx_link_cb *link_cb,
	wrap_io_t *wio,
	gint flags);

#endif /* _core_bh_upload_h_ */

/* vi: set ts=4 sw=4 cindent: */
