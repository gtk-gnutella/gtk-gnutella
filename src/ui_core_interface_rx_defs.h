/*
 * FILL_IN_EMILES_BLANKS
 *
 * Interface definition file.  One of the files that defines structures,
 * macros, etc. as part of the gui/core interface.
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

#ifndef _ui_core_interface_rx_defs_h_
#define _ui_core_interface_rx_defs_h_

#include "ui_core_interface_pmsg_defs.h"
#include "ui_core_interface_bsched_defs.h"

struct rxdriver;
	
typedef void (*rx_data_t)(struct rxdriver *, pmsg_t *mb);

/*
 * A network driver
 *
 */
typedef struct rxdriver {
	struct gnutella_node *node;		/* Node to which this driver belongs */
	struct rxdrv_ops *ops;			/* Dynamically dispatched operations */
	struct rxdriver *upper;			/* Layer above, NULL if none */
	struct rxdriver *lower;			/* Layer underneath, NULL if none */
	gint flags;						/* Driver flags */
	rx_data_t data_ind;				/* Data indication routine */
	gpointer opaque;				/* Used by heirs to store specific info */
} rxdrv_t;

#define rx_node(r)	((r)->node)

/*
 * Driver flags.
 */

/*
 * Operations defined on all drivers.
 */

struct rxdrv_ops {
	gpointer (*init)(rxdrv_t *tx, gpointer args);
	void (*destroy)(rxdrv_t *tx);
	void (*recv)(rxdrv_t *tx, pmsg_t *mb);
	void (*enable)(rxdrv_t *tx);
	void (*disable)(rxdrv_t *tx);
	struct bio_source *(*bio_source)(rxdrv_t *tx);
};



#endif
