/*
 * $Id$
 *
 * Copyright (c) 2002-2003, Raphael Manfredi
 *
 * Message queues.
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

#ifndef _mq_h_
#define _mq_h_

#include <glib.h>

#include "pmsg.h"
#include "gnutella.h"
#include "ui_core_interface_mq_defs.h"

extern gint tx_pending(struct txdriver *tx);

/*
 * Public interface
 */

struct txdriver;

mqueue_t *mq_make(gint maxsize, struct gnutella_node *n, struct txdriver *nd);
void mq_free(mqueue_t *q);
void mq_putq(mqueue_t *q, pmsg_t *mb);
void mq_clear(mqueue_t *q);
void mq_shutdown(mqueue_t *q);

#endif	/* _mq_h_ */

/* vi: set ts=4: */
