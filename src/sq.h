/* -*- mode: cc-mode; tab-width:4; -*-
 *
 * $Id$
 *
 * Copyright (c) 2002, Alex Bennee <alex@bennee.com> & Raphael Manfredi
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

#ifndef _sq_h_
#define _sq_h_

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
void sq_putq(squeue_t *sq, gnet_search_t sh, pmsg_t *mb);
void sq_process(squeue_t *sq, time_t now);
void sq_search_closed(squeue_t *sq, gnet_search_t sh);

#endif /* _sq_h_ */

