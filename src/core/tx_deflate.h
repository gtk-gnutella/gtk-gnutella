/*
 * Copyright (c) 2002-2003, Raphael Manfredi
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
 * Network driver -- compressing layer.
 *
 * @author Raphael Manfredi
 * @date 2002-2003
 */

#ifndef _core_tx_deflate_h_
#define _core_tx_deflate_h_

#include "common.h"

#include "tx.h"
#include "lib/cq.h"

const struct txdrv_ops *tx_deflate_get_ops(void);

/**
 * Callbacks used by the deflating layer.
 */
struct tx_deflate_cb {
	void (*add_tx_deflated)(void *owner, int amount);
	void (*shutdown)(void *owner, const char *reason, ...);
	void (*flow_control)(void *owner, size_t amount);
};

/**
 * Arguments to be passed when the layer is instantiated.
 */
struct tx_deflate_args {
	const struct tx_deflate_cb *cb;	/**< Callbacks */
	cqueue_t *cq;				/**< Callout queue to use */
	size_t buffer_size;			/**< Internal buffer size to use */
	size_t buffer_flush;		/**< Flush after that many bytes */
	bool nagle;					/**< Whether to use Nagle or not */
	bool gzip;					/**< Whether to use gzip encapsulation */
	bool reduced;				/**< Whether to use reduced compression */
};

#endif	/* _core_tx_deflate_h_ */

/* vi: set ts=4 sw=4 cindent: */
