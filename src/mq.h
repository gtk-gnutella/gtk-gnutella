/*
 * Copyright (c) 2002, Raphael Manfredi
 *
 * Message queues.
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
 */
typedef struct mqueue {
	struct gnutella_node *node;		/* Node to which this queue belongs */
	GList *qhead;			/* The queue head, new messages are prepended */
	GList *qtail;			/* The queue tail, oldest message to send first */
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

#define MQ_FLOWC	0x00000001		/* In flow control */

#define mq_is_flow_controlled(q)	((q)->flags & MQ_FLOWC)

/*
 * Public interface
 */

mqueue_t *mq_make(gint maxsize, struct gnutella_node *n);
void mq_free(mqueue_t *q);
void mq_service(mqueue_t *q);
void mq_putq(mqueue_t *q, pmsg_t *mb);

#endif	/* __mq_h__ */

/* vi: set ts=4: */
