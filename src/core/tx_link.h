/*
 * $Id$
 *
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

#ifndef _core_tx_link_h_
#define _core_tx_link_h_

#include "tx.h"

const struct txdrv_ops *tx_link_get_ops(void);

/**
 * Callbacks used by the link layer.
 */
struct tx_link_cb {
	void (*add_tx_written)(gpointer owner, gint amount);
	void (*eof_remove)(gpointer owner, const gchar *reason, ...);
	void (*eof_shutdown)(gpointer owner, const gchar *reason, ...);
	void (*unflushq)(gpointer owner);
};

/**
 * Arguments to be passed when the layer is intantiated.
 */
struct tx_link_args {
	const struct tx_link_cb *cb;	/**< Callbacks */
	struct bsched *bs;				/**< Bandwidth scheduler to use */
	struct wrap_io *wio;			/**< I/O wrapping routines */
};

#endif	/* _core_tx_link_h_ */

/* vi: set ts=4 sw=4 cindent: */

