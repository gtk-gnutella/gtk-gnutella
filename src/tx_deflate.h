/*
 * $Id$
 *
 * Copyright (c) 2002, Raphael Manfredi
 *
 * Network driver -- compressing layer.
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

#ifndef _tx_deflate_h_
#define _tx_deflate_h_

#include "gnutella.h"

#include "tx.h"

struct txdrv_ops tx_deflate_ops;

/*
 * Arguments to be passed when the layer is intantiated.
 */
struct tx_deflate_args {
	txdrv_t *nd;				/* Network driver underneath us (link) */
	cqueue_t *cq;				/* Callout queue to use */
};

#endif	/* _tx_deflate_h_ */

/* vi: set ts=4: */

