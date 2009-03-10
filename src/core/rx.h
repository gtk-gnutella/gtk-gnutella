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
 * Network driver.
 *
 * @author Raphael Manfredi
 * @date 2002-2003
 */

#ifndef _core_rx_h_
#define _core_rx_h_

#include "common.h" 

#include "lib/pmsg.h"
#include "if/core/hosts.h"

struct rxdriver;
struct gnutella_node;

typedef gboolean (*rx_data_t)(struct rxdriver *, pmsg_t *mb);

/**
 * A network driver.
 */

typedef struct rxdriver {
	gpointer owner;					/**< Owner of the RX stack */
	gnet_host_t host;				/**< Host information (ip, port) */
	const struct rxdrv_ops *ops;	/**< Dynamically dispatched operations */
	struct rxdriver *upper;			/**< Layer above, NULL if none */
	struct rxdriver *lower;			/**< Layer underneath, NULL if none */
	int flags;						/**< Driver flags */
	rx_data_t data_ind;				/**< Data indication routine */
	gpointer opaque;				/**< Used by heirs to store specific info */
} rxdrv_t;

#define rx_owner(r)	((r)->owner)

/*
 * Driver flags.
 */

/**
 * Operations defined on all drivers.
 */

struct rxdrv_ops {
	gpointer (*init)(rxdrv_t *tx, gconstpointer args);
	void (*destroy)(rxdrv_t *tx);
	gboolean (*recv)(rxdrv_t *tx, pmsg_t *mb);
	void (*enable)(rxdrv_t *tx);
	void (*disable)(rxdrv_t *tx);
	struct bio_source *(*bio_source)(rxdrv_t *tx);
};

/*
 * Public interface
 */

rxdrv_t *rx_make(gpointer owner, gnet_host_t *host,
	const struct rxdrv_ops *ops, gpointer args);

rxdrv_t *rx_make_above(rxdrv_t *lrx, const struct rxdrv_ops *ops,
	gconstpointer args);

void rx_set_data_ind(rxdrv_t *rx, rx_data_t data_ind);
rx_data_t rx_replace_data_ind(rxdrv_t *rx, rx_data_t data_ind);
void rx_free(rxdrv_t *d);
void rx_collect(void);
gboolean rx_recv(rxdrv_t *rx, pmsg_t *mb);
void rx_enable(rxdrv_t *rx);
void rx_disable(rxdrv_t *rx);
rxdrv_t *rx_bottom(rxdrv_t *rx);
struct bio_source *rx_bio_source(rxdrv_t *rx);
struct bio_source *rx_no_source(rxdrv_t *rx);

#endif	/* _core_rx_h_ */

/* vi: set ts=4 sw=4 cindent: */
