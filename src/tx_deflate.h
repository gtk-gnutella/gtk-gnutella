/*
 * Copyright (c) 2002, Raphael Manfredi
 *
 * Network driver -- compressing layer.
 */

#ifndef __tx_deflate_h__
#define __tx_deflate_h__

#include "tx.h"
#include "cq.h"

struct txdrv_ops tx_deflate_ops;

/*
 * Arguments to be passed when the layer is intantiated.
 */
struct tx_deflate_args {
	txdrv_t *nd;				/* Network driver underneath us (link) */
	cqueue_t *cq;				/* Callout queue to use */
};

#endif	/* __tx_deflate_h__ */

/* vi: set ts=4: */

