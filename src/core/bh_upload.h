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
 * Flags for browse_host_open().
 */
#define BH_DEFLATE	0x00000001		/**< Deflate output */
#define BH_CHUNKED	0x00000002		/**< Emit chunked data */
#define BH_HTML		0x00000004		/**< Emit HTML data */
#define BH_QHITS	0x00000008		/**< Emit Gnutella query hits */

struct gnutella_socket;
struct bio_source;

typedef void (*bh_closed_t)(gpointer arg);
typedef void (*bh_writable_t)(gpointer arg);

struct special_ctx {
	txdrv_t *tx;
	ssize_t (*read)(gpointer ctx, gpointer dest, size_t size);
	ssize_t (*write)(gpointer ctx, gpointer data, size_t size);
	void (*flush)(gpointer ctx, bh_closed_t cb, gpointer arg);
	void (*close)(gpointer ctx);
};

struct special_ctx *browse_host_open(
	gpointer owner, gnet_host_t *host,
	bh_writable_t writable,
	struct tx_deflate_cb *deflate_cb,
	struct tx_link_cb *link_cb,
	wrap_io_t *wio,
	gint flags);

#endif /* _core_bh_upload_h_ */

/* vi: set ts=4 sw=4 cindent: */
