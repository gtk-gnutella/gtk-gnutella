/* -*- mode: cc-mode; tab-width:4; -*-
 *
 * Copyright (c) 2002, Alex Bennee <alex@bennee.com> & Raphael Manfredi
 */

#ifndef __sq_h__
#define __sq_h__

#include <sys/time.h> 	/* for time_t */
#include <glib.h>	 	/* for glib types */

#include "pmsg.h"

struct gnutella_node;

/*
 * A search queue.
 *
 * There is one search queue per node, placed above the message queue.
 * It is only fed by the queries sent by ourselves.  Its purpose is to
 * delay queries to avoid flooding a single connection.
 */
typedef struct search_queue {
	GList *searches;			/* A pointer to the GList */
	struct gnutella_node *node;	/* Node owning this search queue */
	time_t last_sent;    		/* Time last msg was sent */
	gint count;					/* Count of number in queue */
	/* stats */
	gint n_sent;				/* Number of searches sent */
	gint n_dropped;				/* Number dropped due to flow control */
} squeue_t;

#define sq_count(q)			((q)->count)
#define sq_sent(q)			((q)->n_sent)

/*
 * Public interfaces
 */

squeue_t *sq_make(struct gnutella_node *node);
void sq_clear(squeue_t *sq);
void sq_free(squeue_t *sq);
void sq_putq(squeue_t *sq, pmsg_t *mb);
void sq_process(squeue_t *sq, time_t now);

#endif /* __sq_h__ */

