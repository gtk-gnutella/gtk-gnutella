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

#ifndef _tx_h_
#define _tx_h_

#include <glib.h>

struct txdrv_ops;
struct iovec;
struct bio_source;

typedef void (*tx_service_t)(gpointer obj);

/*
 * A network driver
 *
 */
typedef struct txdriver {
	struct gnutella_node *node;		/* Node to which this driver belongs */
	struct txdrv_ops *ops;			/* Dynamically dispatched operations */
	gint flags;						/* Driver flags */
	tx_service_t srv_routine;		/* Service routine of upper TX layer */
	gpointer srv_arg;				/* Service routine argument */
	gpointer opaque;				/* Used by heirs to store specific info */
} txdrv_t;

/*
 * Driver flags.
 */

#define TX_SERVICE		0x00000001	/* Servicing of upper layer needed */

/*
 * Operations defined on all drivers.
 */

struct txdrv_ops {
	gpointer (*init)(txdrv_t *tx, gpointer args);
	void (*destroy)(txdrv_t *tx);
	gint (*write)(txdrv_t *tx, gpointer data, gint len);
	gint (*writev)(txdrv_t *tx, struct iovec *iov, gint iovcnt);
	void (*enable)(txdrv_t *tx);
	void (*disable)(txdrv_t *tx);
	gint (*pending)(txdrv_t *tx);
	struct bio_source *(*bio_source)(txdrv_t *tx);
};

/*
 * Public interface
 */

txdrv_t *tx_make(struct gnutella_node *n, struct txdrv_ops *ops, gpointer args);
void tx_free(txdrv_t *d);
gint tx_write(txdrv_t *tx, gpointer data, gint len);
gint tx_writev(txdrv_t *tx, struct iovec *iov, gint iovcnt);
void tx_srv_register(txdrv_t *d, tx_service_t srv_fn, gpointer srv_arg);
void tx_srv_enable(txdrv_t *tx);
void tx_srv_disable(txdrv_t *tx);
gint tx_pending(txdrv_t *tx);
struct bio_source *tx_bio_source(txdrv_t *tx);

#endif	/* _tx_h_ */

/* vi: set ts=4: */

