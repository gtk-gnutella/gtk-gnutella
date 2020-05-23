/*
 * Copyright (c) 2007, Christian Biere & Raphael Manfredi
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
 * Handles the server-side of the THEX data transfers.
 *
 * @author Christian Biere
 * @author Raphael Manfredi
 * @date 2005
 */

#ifndef _core_thex_upload_h_
#define _core_thex_upload_h_

#include "common.h"

#include "special_upload.h"

/**
 * Flags for thex_upload_open().
 */
enum {
	/* Must be the same value as BH_F_CHUNKED */
	THEX_UPLOAD_F_CHUNKED = 1 << 2		/**< Emit chunked data */
};

/* THEX data is hardly compressible, thus don't bother. */

struct gnutella_host;
struct tx_link_cb;
struct wrap_io;

size_t thex_upload_get_content_length(const struct shared_file *sf);

struct special_upload *thex_upload_open(
	void *owner,
	const struct gnutella_host *host,
	const struct shared_file *sf,
	special_upload_writable_t writable,
	const struct tx_link_cb *link_cb,
	struct wrap_io *wio,
	int flags);

#endif /* _core_thex_upload_h_ */

/* vi: set ts=4 sw=4 cindent: */
