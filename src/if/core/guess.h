/*
 * Copyright (c) 2012  Raphael Manfredi
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

#ifndef _if_core_guess_h_
#define _if_core_guess_h_

#include "common.h"

#include "search.h"		/* For gnet_search_t */

/**
 * Parallelism modes.
 */
enum guess_mode {
	GUESS_QUERY_BOUNDED,		/**< Bounded parallelism */
	GUESS_QUERY_LOOSE			/**< Loose parallelism */
};

/**
 * Structure describing a newly created GUESS query.
 */
struct guess_query {
	size_t max_ultra;		/**< Max amount of ultrapeers queried */
	enum guess_mode mode;	/**< Current query mode */
};

/**
 * Structure holding the core GUESS stats for a running query.
 */
struct guess_stats {
	size_t pool;			/**< Pool size (unqueried hosts) */
	size_t queried_ultra;	/**< Ultra nodes queried */
	size_t queried_g2;		/**< G2 nodes queried */
	size_t acks;			/**< Query acknowledgments */
	size_t reached;			/**< Amount of ultras & G2 hubs reached by query */
	size_t results;			/**< Results received */
	size_t kept;			/**< Results kept */
	size_t hops;			/**< Iterating hops */
	size_t rpc_pending;		/**< RPCs pending */
	size_t bw_out_query;	/**< Spent outgoing querying bandwidth */
	size_t bw_out_qk;		/**< Estimated outgoing query key bandwidth */
	enum guess_mode mode;	/**< Current query mode */
	uint pool_load:1;		/**< Pending pool loading */
	uint end_starving:1;	/**< Will end as soon as it is starving */
};

/**
 * GUESS callbacks
 */

typedef void (*guess_event_listener_t)(gnet_search_t,
	const struct guess_query *query);
typedef void (*guess_stats_listener_t)(gnet_search_t,
	const struct guess_stats *stats);

/*
 * GUESS public interface, visible only from the bridge.
 */

#ifdef CORE_SOURCES

void guess_event_listener_add(guess_event_listener_t);
void guess_event_listener_remove(guess_event_listener_t);

void guess_stats_listener_add(guess_stats_listener_t);
void guess_stats_listener_remove(guess_stats_listener_t);

#endif /* CORE_SOURCES */
#endif /* _if_core_guess_h_ */

/* vi: set ts=4 sw=4 cindent: */
