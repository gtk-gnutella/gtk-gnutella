/*
 * $Id$
 *
 * Copyright (c) 2002-2003, Raphael Manfredi
 *
 * Network driver.
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

#ifndef _rx_h_
#define _rx_h_

#include <stdarg.h>
#include <glib.h>

#include "pmsg.h"
#include "ui_core_interface_rx_defs.h"

/*
 * Public interface
 */

rxdrv_t *rx_make(
	struct gnutella_node *n,
	struct rxdrv_ops *ops,
	rx_data_t data_ind,
	gpointer args);
rxdrv_t *rx_make_under(rxdrv_t *urx, struct rxdrv_ops *ops, gpointer args);
void rx_free(rxdrv_t *d);
void rx_recv(rxdrv_t *rx, pmsg_t *mb);
void rx_enable(rxdrv_t *rx);
void rx_disable(rxdrv_t *rx);
rxdrv_t *rx_bottom(rxdrv_t *rx);
struct bio_source *rx_bio_source(rxdrv_t *rx);

#endif	/* _rx_h_ */

/* vi: set ts=4: */
