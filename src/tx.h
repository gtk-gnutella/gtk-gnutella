/*
 * Copyright (c) 2002, Raphael Manfredi
 *
 * Network driver.
 */

#ifndef __tx_h__
#define __tx_h__

#include <glib.h>

struct txdrv_ops;
struct iovec;

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

#endif	/* __tx_h__ */

/* vi: set ts=4: */

