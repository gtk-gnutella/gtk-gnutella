/*
 * Copyright (c) 2002, Raphael Manfredi
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

#ifndef __mq_h__
#define __mq_h__

#include <glib.h>

#include "pmsg.h"

/*
 * A message queue.
 *
 * The queue itself is a two-way list, whose head is kept in `qhead' and the
 * tail in `qtail', since a GList does not keep that information and we
 * don't want to traverse the list each time.  Manual bookkeeping required.
 *
 * Flow control is triggered when the size reaches the high watermark,
 * and remains in effect until we reach the low watermark, thereby providing
 * the necessary hysteresis.
 *
 * The `qlink' field is used during flow-control.  It contains a sorted (by
 * priority) array of all the items in the list.  It is dynamically allocated
 * and freed as needed.
 */
typedef struct mqueue {
	struct gnutella_node *node;		/* Node to which this queue belongs */
	struct txdriver *tx_drv;		/* Network TX driver */
	GList *qhead;			/* The queue head, new messages are prepended */
	GList *qtail;			/* The queue tail, oldest message to send first */
	GList **qlink;			/* Sorted array of (GList *) entries, or NULL */
	gint qlink_count;		/* Amount of entries in `qlink' */
	gint maxsize;			/* Maximum size of this queue (total queued) */
	gint count;				/* Amount of messages queued */
	gint hiwat;				/* High watermark */
	gint lowat;				/* Low watermark */
	gint size;				/* Current amount of bytes queued */
	gint flags;				/* Status flags */
} mqueue_t;

/*
 * Queue flags.
 */

#define MQ_FLOWC		0x00000001	/* In flow control */
#define MQ_DISCARD		0x00000002	/* No writing, discard message */

#define mq_is_flow_controlled(q)	((q)->flags & MQ_FLOWC)
#define mq_maxsize(q)				((q)->maxsize)
#define mq_size(q)					((q)->size)
#define mq_count(q)					((q)->count)
#define mq_pending(q)				((q)->size + tx_pending((q)->tx_drv))

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

#endif	/* __mq_h__ */

/* vi: set ts=4: */
