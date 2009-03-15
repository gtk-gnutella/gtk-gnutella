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
 * Message queues.
 *
 * @author Raphael Manfredi
 * @date 2002-2003
 */

#ifndef _core_mq_h_
#define _core_mq_h_

#include "common.h"

#include "gnutella.h"
#include "tx.h"

#include "lib/cq.h"
#include "lib/pmsg.h"
#include "lib/slist.h"

typedef struct mqueue mqueue_t;

/**
 * Operations defined on all mq types.
 */

struct mq_ops {
	void (*putq)(mqueue_t *q, pmsg_t *mb);
};

struct mq_cops {
	void (*puthere)(mqueue_t *q, pmsg_t *mb, int msize);
	void (*qlink_remove)(mqueue_t *q, GList *l);
	GList *(*rmlink_prev)(mqueue_t *q, GList *l, int size);
	void (*update_flowc)(mqueue_t *q);
};

enum mq_magic {
	MQ_MAGIC = 0x33990ee
};

/**
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
 *
 * The `header' is used to hold the function/hops/TTL of a reference message
 * to be used as a comparison point when speeding up dropping in flow-control.
 */
struct mqueue {
	enum mq_magic magic;	/**< Magic number */
	gnutella_header_t header;	/**< Comparison point during flow control */
	struct gnutella_node *node;		/**< Node to which this queue belongs */
	const struct mq_ops *ops;		/**< Polymorphic operations */
	const struct mq_cops *cops;		/**< Common operations */
	txdrv_t *tx_drv;				/**< Network TX stack driver */
	GList *qhead, *qtail, **qlink;
	slist_t *qwait;			/**< Waiting queue during putq recursions */
	cevent_t *swift_ev;		/**< Callout queue event in "swift" mode */
	int swift_elapsed;		/**< Scheduled elapsed time, in ms */
	int qlink_count;		/**< Amount of entries in `qlink' */
	int maxsize;			/**< Maximum size of this queue (total queued) */
	int count;				/**< Amount of messages queued */
	int hiwat;				/**< High watermark */
	int lowat;				/**< Low watermark */
	int size;				/**< Current amount of bytes queued */
	int flags;				/**< Status flags */
	int last_written;		/**< Amount last written by service routine */
	int flowc_written;		/**< Amount written during flow control */
	int last_size;			/**< Queue size at last "swift" event callback */
    int putq_entered;		/**< For recursion checks in mq_putq() */
};

/*
 * Queue flags.
 */

enum {
	MQ_CLEAR	= (1 << 4),	/**< Running mq_clear() */
	MQ_WARNZONE	= (1 << 3),	/**< Between hiwat and lowat */
	MQ_SWIFT	= (1 << 2),	/**< Swift mode, dropping more traffic */
	MQ_DISCARD	= (1 << 1),	/**< No writing, discard message */
	MQ_FLOWC	= (1 << 0)	/**< In flow control */
};

gboolean mq_is_flow_controlled(const struct mqueue *q);
gboolean mq_is_swift_controlled(const struct mqueue *q);
gboolean mq_would_flow_control(const struct mqueue *q, size_t additional);
int mq_maxsize(const struct mqueue *q);
int mq_size(const struct mqueue *q);
int mq_lowat(const struct mqueue *q);
int mq_hiwat(const struct mqueue *q);
int mq_count(const struct mqueue *q);
int mq_pending(const struct mqueue *q);
struct bio_source *mq_bio(const struct mqueue *q);
struct gnutella_node *mq_node(const struct mqueue *q);

/*
 * Public interface
 */

void mq_putq(mqueue_t *q, pmsg_t *mb);
void mq_free(mqueue_t *q);
void mq_clear(mqueue_t *q);
void mq_discard(mqueue_t *q);
void mq_shutdown(mqueue_t *q);
void mq_fill_ops(struct mq_ops *ops);

const struct mq_cops *mq_get_cops(void);
const char *mq_info(const mqueue_t *q);

/*
 * Message queue assertions.
 */

#define MQ_DEBUG
#ifdef MQ_DEBUG
void mq_check_track(mqueue_t *q, int offset, const char *where, int line);

#define mq_check(x,y)	mq_check_track((x), (y), _WHERE_, __LINE__)
#else
#define mq_check(x,y)
#endif

#endif	/* _core_mq_h_ */

/* vi: set ts=4: */
