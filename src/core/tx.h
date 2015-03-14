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
 * Network driver.
 *
 * @author Raphael Manfredi
 * @date 2002-2003
 */

#ifndef _core_tx_h_
#define _core_tx_h_

#include "common.h"

#include "lib/gnet_host.h"
#include "lib/pmsg.h"

struct txdrv_ops;
struct bio_source;
struct gnutella_node;

typedef void (*tx_service_t)(void *obj);

enum txdrv_magic { TXDRV_MAGIC = 0x5189ae4d };

/**
 * A network driver.
 */
typedef struct txdriver {
	enum txdrv_magic magic;			/**< Magic number */
	void *owner;					/**< Object owning the stack */
	gnet_host_t host;				/**< Host information (ip, port) */
	const struct txdrv_ops *ops;	/**< Dynamically dispatched operations */
	struct txdriver *upper;			/**< Layer above, NULL if none */
	struct txdriver *lower;			/**< Layer underneath, NULL if none */
	int flags;						/**< Driver flags */
	tx_service_t srv_routine;		/**< Service routine of upper TX layer */
	void *srv_arg;					/**< Service routine argument */
	void *opaque;					/**< Used by heirs to store specific info */
} txdrv_t;

static inline void
tx_check(const txdrv_t *tx)
{
	g_assert(tx != NULL);
	g_assert(TXDRV_MAGIC == tx->magic);
}

/*
 * Driver flags.
 */

#define TX_SERVICE		(1 << 0)	/**< Servicing of upper layer needed */
#define TX_ERROR		(1 << 1)	/**< Fatal error detected */
#define TX_DOWN			(1 << 2)	/**< No further writes allowed */
#define TX_CLOSING		(1 << 3)	/**< Closing, no further writes allowed */
#define TX_EAGER		(1 << 4)	/**< Always service the queue */
#define TX_WR_FAULT		(1 << 5)	/**< Ignore writes + loudly carp */
#define TX_WR_WARNED	(1 << 6)	/**< Has warned after a write fault */

/**
 * Operations defined on all drivers.
 */

typedef void (*tx_closed_t)(txdrv_t *tx, void *arg);

struct txdrv_ops {
	const char *name;
	void *(*init)(txdrv_t *tx, void *args);
	void (*destroy)(txdrv_t *tx);
	ssize_t (*write)(txdrv_t *tx, const void *data, size_t len);
	ssize_t (*writev)(txdrv_t *tx, iovec_t *iov, int iovcnt);
	ssize_t (*sendto)(txdrv_t *tx, pmsg_t *mb, const gnet_host_t *to);
	void (*enable)(txdrv_t *tx);
	void (*disable)(txdrv_t *tx);
	size_t (*pending)(txdrv_t *tx);
	void (*flush)(txdrv_t *tx);
	void (*shutdown)(txdrv_t *tx);
	void (*close)(txdrv_t *tx, tx_closed_t cb, void *arg);
	struct bio_source *(*bio_source)(txdrv_t *tx);
};

/*
 * Public interface
 */

txdrv_t *tx_make(void *owner, const gnet_host_t *host,
	const struct txdrv_ops *ops, void *args);
txdrv_t *tx_make_above(txdrv_t *ltx, const struct txdrv_ops *ops, void *args);

void tx_free(txdrv_t *tx);
void tx_collect(void);
ssize_t tx_write(txdrv_t *tx, const void *data, size_t len);
ssize_t tx_writev(txdrv_t *tx, iovec_t *iov, int iovcnt);
ssize_t tx_sendto(txdrv_t *tx, pmsg_t *mb, const gnet_host_t *to);
void tx_srv_register(txdrv_t *d, tx_service_t srv_fn, void *srv_arg);
void tx_srv_enable(txdrv_t *tx);
void tx_srv_disable(txdrv_t *tx);
size_t tx_pending(txdrv_t *tx);
struct bio_source *tx_bio_source(txdrv_t *tx);
ssize_t tx_no_write(txdrv_t *tx, const void *data, size_t len);
ssize_t tx_no_writev(txdrv_t *tx, iovec_t *iov, int iovcnt);
ssize_t tx_no_sendto(txdrv_t *tx, pmsg_t *mb, const gnet_host_t *to);
void tx_flush(txdrv_t *tx);
void tx_error(txdrv_t *tx);
void tx_shutdown(txdrv_t *tx);
void tx_close(txdrv_t *d, tx_closed_t cb, void *arg);
void tx_close_noop(txdrv_t *tx, tx_closed_t cb, void *arg);
bool tx_has_error(const txdrv_t *tx);
const char *tx_error_layer_name(const txdrv_t *tx);
void tx_eager_mode(txdrv_t *tx, bool on);

struct bio_source *tx_no_source(txdrv_t *tx);

void tx_debug_set_addrs(const char *s);
bool tx_debug_host(const gnet_host_t *h);

#endif	/* _core_tx_h_ */

/* vi: set ts=4 sw=4 cindent: */

