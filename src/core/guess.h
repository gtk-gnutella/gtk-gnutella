/*
 * Copyright (c) 2011, Raphael Manfredi
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
 * Gnutella UDP Extension for Scalable Searches (GUESS) client-side.
 *
 * @author Raphael Manfredi
 * @date 2011
 */

#ifndef _core_guess_h_
#define _core_guess_h_

#include "common.h"
#include "hcache.h"		/* For host_net_t */

#include "lib/gnet_host.h"

#include "if/gnet_property_priv.h"
#include "if/core/search.h"

/**
 * GUESS query completion callback.
 */
typedef void (*guess_query_cb_t)(void *data);

struct guess;
typedef struct guess guess_t;

/*
 * Public interface.
 */

struct gnutella_node;

void guess_init(void);
void guess_close(void);

guess_t *guess_create(gnet_search_t sh,
	const struct guid *muid, const char *query, unsigned mtype,
	guess_query_cb_t cb, void *arg);
void guess_cancel(guess_t **gq_ptr, bool callback);
void guess_end_when_starving(guess_t *gq);
bool guess_is_search_muid(const guid_t *muid);
void guess_got_results(const guid_t *muid, uint32 hits);
void guess_kept_results(const guid_t *muid, uint32 kept);
bool guess_rpc_handle(struct gnutella_node *n);
void guess_introduction_ping(const struct gnutella_node *n,
	const char *buf, uint16 len);
void guess_add_hub(host_addr_t addr, uint16 port);
bool guess_already_queried(const guess_t *gq,
	const host_addr_t addr, uint16 port);
void guess_invalidate_keys(void);

struct g2_tree;
struct guid;

bool guess_late_qa(const struct gnutella_node *n,
	const struct g2_tree *t, const struct guid *muid);

int guess_fill_caught_array(host_net_t net,
	bool add_02, gnet_host_t *hosts, int hcount);

/**
 * Is GUESS querying enabled?
 */
static inline bool
guess_query_enabled(void)
{
	return GNET_PROPERTY(enable_udp) && GNET_PROPERTY(enable_guess) &&
		GNET_PROPERTY(enable_guess_client) &&
		GNET_PROPERTY(listen_port) != 0 && GNET_PROPERTY(recv_solicited_udp);
}

#endif /* _core_guess_h_ */

