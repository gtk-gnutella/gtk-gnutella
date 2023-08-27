/*
 * Copyright (c) 2002-2003, 2014 Raphael Manfredi
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
 *      51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *----------------------------------------------------------------------
 */

/**
 * @ingroup core
 * @file
 *
 * Message queues.
 *
 * @author Raphael Manfredi
 * @date 2002-2003, 2014
 */

#ifndef _core_mq_h_
#define _core_mq_h_

#include "common.h"

#include "gnutella.h"
#include "tx.h"

#include "if/core/mq.h"

#include "lib/cq.h"
#include "lib/plist.h"
#include "lib/pmsg.h"
#include "lib/slist.h"

typedef struct mqueue mqueue_t;

struct mq_ops;

/**
 * When invoked from the message queue, this callback must return a vector
 * of "message headers" that are going to be compared against when the queue
 * is in "swift mode" to determine which messages to prune.
 *
 * The messages need not be full message, but must be long enough to allow
 * the ``msg_headcmp'' callback to compare two messages against each other.
 *
 * These messages being templates, they are expected to be generated once only
 * and then the same vector can be returned.  This is why there is no provision
 * for a free routine.
 *
 * @param initial		whether queue is just entering swift mode
 * @param vcnt			where the amount of entries in the vector is written
 *
 * @return the base of the vector of messages, NULL if none.
 */
typedef iovec_t *(*mq_msgtmp_t)(bool initial, size_t *vcnt);

/**
 * Traffic accounting callback, invoked each time a message has been sent
 * by the message queue or flow-controlled.
 *
 * @param node			the node to which message is sent
 * @param mb			the full message being accounted for
 */
typedef void (*mq_msgcount_t)(void *node, const pmsg_t *mb);

/**
 * Logging regarding a particular message.
 *
 * @param mb			the message being logged
 * @param fmt			formatting string, followed by arguments to format
 */
typedef void (*mq_msglog_t)(const pmsg_t *mb, const char *fmt, ...)
	G_PRINTF(2, 3);

/**
 * User-supplied parameters, which are callbacks necessary for the message
 * queue operations but which are dependent on the messages being enqueued.
 */
struct mq_uops {
	cmp_fn_t msg_cmp;			/**< Message (priority) comparison routine */
	cmp_fn_t msg_headcmp;		/**< Only compare message "headers" */
	mq_msgtmp_t msg_templates;	/**< Get message templates for "swift" mode */
	mq_msgcount_t msg_sent;		/**< Message sent */
	mq_msgcount_t msg_flowc;	/**< Message dropped by flow-control */
	mq_msgcount_t msg_queued;	/**< Message queued */
	mq_msglog_t msg_log;		/**< Message logging for dropped messages */
};

#ifdef MQ_INTERNAL

/*
 * The declarations in this section are only visible to the various files
 * implementing the message queue.
 */

/**
 * Operations defined on all mq types.
 */

struct mq_ops {
	void (*putq)(mqueue_t *q, pmsg_t *mb);
	bool (*flushed)(const mqueue_t *q);
};

struct mq_cops {
	void (*puthere)(mqueue_t *q, pmsg_t *mb, int msize);
	void (*qlink_remove)(mqueue_t *q, plist_t *l);
	plist_t *(*rmlink_prev)(mqueue_t *q, plist_t *l, int size);
	void (*update_flowc)(mqueue_t *q);
};

enum mq_magic {
	MQ_MAGIC = 0x33990ee
};

/**
 * A message queue.
 *
 * The queue itself is a two-way list, whose head is kept in `qhead' and the
 * tail in `qtail', since a plist_t does not keep that information and we
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
	struct gnutella_node *node;		/**< Node to which this queue belongs */
	const struct mq_ops *ops;		/**< Polymorphic operations */
	const struct mq_cops *cops;		/**< Common operations */
	const struct mq_uops *uops;		/**< User-defined operations */
	txdrv_t *tx_drv;				/**< Network TX stack driver */
	plist_t *qhead, *qtail, **qlink;
	slist_t *qwait;			/**< Waiting queue during putq recursions */
	cevent_t *swift_ev;		/**< Callout queue event in "swift" mode */
	const uint32 *debug;	/**< Debug config variable for this queue */
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

static inline void
mq_check_consistency(const struct mqueue * const q)
{
	g_assert(q != NULL);
	g_assert(MQ_MAGIC == q->magic);
}

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

/*
 * Message queue assertions.
 */

#if 0
#define MQ_DEBUG			/**< Activates mq_check() assertions */
#endif

#ifdef MQ_DEBUG
void mq_check_track(mqueue_t *q, int offset, const char *where, int line);

#define mq_check(x,y)	mq_check_track((x), (y), _WHERE_, __LINE__)
#else
#define mq_check(x,y)
#endif

#endif /* MQ_INTERNAL */

mq_status_t mq_status(const mqueue_t *q) G_PURE;
bool mq_is_flow_controlled(const mqueue_t *q) G_PURE;
bool mq_is_swift_controlled(const mqueue_t *q) G_PURE;
bool mq_would_flow_control(const mqueue_t *q, size_t) G_PURE;
bool mq_above_low_watermark(const mqueue_t *q) G_PURE;
uint32 mq_debug(const mqueue_t *q) G_PURE;
int mq_maxsize(const mqueue_t *q) G_PURE;
int mq_size(const mqueue_t *q) G_PURE;
int mq_lowat(const mqueue_t *q) G_PURE;
int mq_hiwat(const mqueue_t *q) G_PURE;
int mq_count(const mqueue_t *q) G_PURE;
int mq_pending(const mqueue_t *q);
int mq_tx_pending(const mqueue_t *q);
struct bio_source *mq_bio(const mqueue_t *q);
struct gnutella_node *mq_node(const mqueue_t *q) G_PURE;

/*
 * Public interface
 */

void mq_putq(mqueue_t *q, pmsg_t *mb);
void mq_free(mqueue_t *q);
void mq_clear(mqueue_t *q);
void mq_flush(mqueue_t *q);
void mq_discard(mqueue_t *q);
void mq_shutdown(mqueue_t *q);
void mq_fill_ops(struct mq_ops *ops);

const struct mq_cops *mq_get_cops(void) G_CONST;
const char *mq_info(const mqueue_t *q);

#endif	/* _core_mq_h_ */

/* vi: set ts=4 sw=4 cindent: */
