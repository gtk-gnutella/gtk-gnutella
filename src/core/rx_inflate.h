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
 * Network RX -- multiplexed decompressing stage.
 *
 * @author Raphael Manfredi
 * @date 2002-2003
 */

#ifndef _core_rx_inflate_h_
#define _core_rx_inflate_h_

#include "common.h"

#include "rx.h"

const struct rxdrv_ops* rx_inflate_get_ops(void);

/**
 * Callbacks used by the inflating layer.
 */
struct rx_inflate_cb {
	void (*add_rx_inflated)(void *owner, int amount);
	void (*inflate_error)(void *owner,
			const char *reason, ...) G_PRINTF_PTR(2, 3);
};

/**
 * Arguments to be passed when the layer is instantiated.
 */
struct rx_inflate_args {
	const struct rx_inflate_cb *cb;		/**< Callbacks */
};

#endif	/* _core_rx_inflate_h_ */

/* vi: set ts=4 sw=4 cindent: */

