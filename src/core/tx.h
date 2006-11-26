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

#ifndef _core_tx_h_
#define _core_tx_h_

#include "common.h"

#include "if/core/hosts.h"

struct txdrv_ops;
struct iovec;
struct bio_source;
struct gnutella_node;

typedef void (*tx_service_t)(gpointer obj);

/**
 * A network driver.
 */

typedef struct txdriver {
	gpointer owner;					/**< Object owning the stack */
	gnet_host_t host;				/**< Host information (ip, port) */
	const struct txdrv_ops *ops;	/**< Dynamically dispatched operations */
	struct txdriver *upper;			/**< Layer above, NULL if none */
	struct txdriver *lower;			/**< Layer underneath, NULL if none */
	gint flags;						/**< Driver flags */
	tx_service_t srv_routine;		/**< Service routine of upper TX layer */
	gpointer srv_arg;				/**< Service routine argument */
	gpointer opaque;				/**< Used by heirs to store specific info */
} txdrv_t;

/*
 * Driver flags.
 */

#define TX_SERVICE		0x00000001	/**< Servicing of upper layer needed */
#define TX_ERROR		0x00000002	/**< Fatal error detected */
#define TX_DOWN			0x00000004	/**< No further writes allowed */
#define TX_CLOSING		0x00000008	/**< Closing, no further writes allowed */
#define TX_EAGER		0x00000010	/**< Always service the queue */

/**
 * Operations defined on all drivers.
 */

typedef void (*tx_closed_t)(txdrv_t *tx, gpointer arg);

struct txdrv_ops {
	gpointer (*init)(txdrv_t *tx, gpointer args);
	void (*destroy)(txdrv_t *tx);
	ssize_t (*write)(txdrv_t *tx, gconstpointer data, size_t len);
	ssize_t (*writev)(txdrv_t *tx, struct iovec *iov, gint iovcnt);
	ssize_t (*sendto)(txdrv_t *tx, const gnet_host_t *to,
							gconstpointer data, size_t len);
	void (*enable)(txdrv_t *tx);
	void (*disable)(txdrv_t *tx);
	size_t (*pending)(txdrv_t *tx);
	void (*flush)(txdrv_t *tx);
	void (*shutdown)(txdrv_t *tx);
	void (*close)(txdrv_t *tx, tx_closed_t cb, gpointer arg);
	struct bio_source *(*bio_source)(txdrv_t *tx);
};

/*
 * Public interface
 */

txdrv_t *tx_make(gpointer owner, gnet_host_t *host,
	const struct txdrv_ops *ops, gpointer args);
txdrv_t *tx_make_above(txdrv_t *ltx, const struct txdrv_ops *ops,
	gpointer args);

void tx_free(txdrv_t *tx);
void tx_collect(void);
ssize_t tx_write(txdrv_t *tx, gconstpointer data, size_t len);
ssize_t tx_writev(txdrv_t *tx, struct iovec *iov, gint iovcnt);
ssize_t tx_sendto(txdrv_t *tx, const gnet_host_t *to,
					gconstpointer data, size_t len);
void tx_srv_register(txdrv_t *d, tx_service_t srv_fn, gpointer srv_arg);
void tx_srv_enable(txdrv_t *tx);
void tx_srv_disable(txdrv_t *tx);
size_t tx_pending(txdrv_t *tx);
struct bio_source *tx_bio_source(txdrv_t *tx);
ssize_t tx_no_write(txdrv_t *tx, gconstpointer data, size_t len);
ssize_t tx_no_writev(txdrv_t *tx, struct iovec *iov, gint iovcnt);
ssize_t tx_no_sendto(txdrv_t *tx, const gnet_host_t *to,
			gconstpointer data, size_t len);
void tx_flush(txdrv_t *tx);
void tx_shutdown(txdrv_t *tx);
void tx_close(txdrv_t *d, tx_closed_t cb, gpointer arg);
void tx_close_noop(txdrv_t *tx, tx_closed_t cb, gpointer arg);
gboolean tx_has_error(txdrv_t *tx);
void tx_eager_mode(txdrv_t *tx, gboolean on);

struct bio_source *tx_no_source(txdrv_t *tx);

#endif	/* _core_tx_h_ */

/* vi: set ts=4 sw=4 cindent: */

