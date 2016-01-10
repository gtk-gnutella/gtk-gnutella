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
 * Network driver -- link layer.
 *
 * @author Raphael Manfredi
 * @date 2002-2003
 */

#ifndef _core_rx_link_h_
#define _core_rx_link_h_

#include "common.h"

#include "rx.h"
#include "if/core/bsched.h"

const struct rxdrv_ops *rx_link_get_ops(void);

/**
 * Callbacks used by the link layer.
 */
struct rx_link_cb {
	void (*add_rx_given)(void *owner, ssize_t amount);
	void (*read_error)(void *owner,
			const char *reason, ...) G_PRINTF_PTR(2, 3);
	void (*got_eof)(void *owner);
};

/**
 * Arguments to be passed when the layer is instantiated.
 */
struct rx_link_args {
	const struct rx_link_cb *cb;	/**< Callbacks */
	struct wrap_io *wio;			/**< I/O wrapping routines */
	bsched_bws_t bws;				/**< Bandwidth scheduler to use */
};

#endif	/* _core_rx_link_h_ */

/* vi: set ts=4 sw=4 cindent: */

