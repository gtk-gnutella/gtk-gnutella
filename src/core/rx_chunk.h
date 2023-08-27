/*
 * Copyright (c) 2005, Christian Biere
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
 * Network RX -- multiplexed dechunking stage.
 *
 * @author Christian Biere
 * @date 2005
 */

#ifndef _core_rx_chunk_h_
#define _core_rx_chunk_h_

#include "common.h"

#include "rx.h"

const struct rxdrv_ops* rx_chunk_get_ops(void);

/**
 * Callbacks used by the inflating layer.
 */
struct rx_chunk_cb {
	void (*chunk_error)(void *owner,
			const char *reason, ...) G_PRINTF_PTR(2, 3);
	void (*chunk_end)(void *owner);
};

/**
 * Arguments to be passed when the layer is instantiated.
 */
struct rx_chunk_args {
	const struct rx_chunk_cb *cb;		/**< Callbacks */
};

#endif	/* _core_rx_chunk_h_ */

/* vi: set ts=4 sw=4 cindent: */

