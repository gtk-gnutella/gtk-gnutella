/* -*- mode: cc-mode; tab-width:4; -*-
 *
 * Copyright (c) 2002-2003, Alex Bennee <alex@bennee.com> & Raphael Manfredi
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
 * Search queue.
 *
 * @author Alex Bennee <alex@bennee.com>
 * @author Raphael Manfredi
 * @date 2002-2003
 */

#ifndef _core_sq_h_
#define _core_sq_h_

#include "common.h"
#include "qrp.h"

#include "lib/plist.h"
#include "lib/pmsg.h"

#include "if/core/search.h"

struct hset;

/**
 * A search queue.
 *
 * There is one search queue per node, placed above the message queue.
 * It is only fed by the queries sent by ourselves.  Its purpose is to
 * delay queries to avoid flooding a single connection.
 */
typedef struct search_queue {
	plist_t *searches;			/**< List of smsg_t objects */
	struct hset *handles;		/**< Keeps track of search handles in queue */
	struct gnutella_node *node;	/**< Node owning this search queue, or NULL */
	time_t last_sent;    		/**< Time last msg was sent */
	uint count;					/**< Count of number in queue */
	/* stats */
	int n_sent;					/**< Number of searches sent */
	int n_dropped;				/**< Number dropped due to flow control */
} squeue_t;

#define sq_count(q)			((q)->count)
#define sq_sent(q)			((q)->n_sent)

/*
 * Public interfaces
 */

void sq_init(void);
void sq_close(void);

squeue_t *sq_global_queue(void);

squeue_t *sq_make(struct gnutella_node *node);
void sq_clear(squeue_t *sq);
void sq_free(squeue_t *sq);
void sq_putq(squeue_t *sq, gnet_search_t sh, pmsg_t *mb);
void sq_process(squeue_t *sq, time_t now);
void sq_search_closed(squeue_t *sq, gnet_search_t sh);
void sq_global_putq(gnet_search_t sh, pmsg_t *mb, query_hashvec_t *qhv);
void sq_set_peermode(node_peer_t mode);

#endif /* _core_sq_h_ */

/* vi: set ts=4 sw=4 cindent: */
