/*
 * $Id$
 *
 * Copyright (c) 2001-2003, Raphael Manfredi
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
 * Search handling (core side).
 *
 * @author Raphael Manfredi
 * @date 2001-2003
 */

#ifndef _core_search_h_
#define _core_search_h_

#include "common.h"

#include "nodes.h"
#include "gnutella.h"
#include "lib/sectoken.h"

/*
 * Query flags used in queries (big-endian); formerly used as "speed" indicator.
 */

#define QUERY_F_MARK		0x8000	/**< Field is special: not a speed */
#define QUERY_F_FIREWALLED	0x4000	/**< Issuing servent is firewalled */
#define QUERY_F_XML			0x2000	/**< Supports XML in result set */
#define QUERY_F_LEAF_GUIDED	0x1000	/**< Leaf-guided query */
#define QUERY_F_GGEP_H		0x0800	/**< Recipient understands GGEP "H" */
#define QUERY_F_OOB_REPLY	0x0400	/**< Out-of-band reply possible */
#define QUERY_F_FW_TO_FW	0x0200	/**< Can do fw to fw transfers */
/**
 * NOTE: At this point all of the bits are exhausted. 0x0001 is not available
 * 		 because the next 9 bits are not available for flags.
 */

#define QUERY_FW2FW_FILE_INDEX	0x7FFFFFFD	/**< Magic index for fw-fw reqs */

/*
 * The version of GUESS we support.
 *
 * LimeWire defined 0.1 but we support 0.2 because OOB queries are both sent
 * (when running as a client) and accepted (as a server).  Also we implement
 * anti cache-poisoning features to limit malicious nodes in the cache.
 * Finally, gtk-gnutella understands the combination of PK & SCP in pings as
 * a requesst for query keys plus a set of GUESS ultrapeers to be sent back
 * packed in "IPP".
 */

#define SEARCH_GUESS_MAJOR 0
#define SEARCH_GUESS_MINOR 2

/**
 * Amount of (kept) search results we're aiming for when querying.
 */
#define SEARCH_MAX_RESULTS	150

struct download;
struct guid;
struct nid;

/*
 * Global Functions
 */

void search_init(void);
void search_shutdown(void);

gboolean search_results(gnutella_node_t *n, int *results);
gboolean search_query_allowed(gnet_search_t sh);
void search_starting(gnet_search_t sh);
void search_notify_sent(gnet_search_t sh, const struct nid *node_id);
void search_query_sent(gnet_search_t sh);
gboolean search_get_kept_results(const struct guid *muid, guint32 *kept);
gboolean search_running_guess(const struct guid *muid);
guint32 search_get_kept_results_by_handle(gnet_search_t sh);
void search_oob_pending_results(gnutella_node_t *n, const struct guid *muid,
	int hits, gboolean udp_firewalled, gboolean secure);

void search_dissociate_browse(gnet_search_t sh, struct download *d);
void search_browse_results(gnutella_node_t *n, gnet_search_t sh);

gboolean search_request_preprocess(struct gnutella_node *n);
void search_request(struct gnutella_node *n, struct query_hashvec *qhv);
size_t compact_query(char *search);
void search_compact(struct gnutella_node *n);
void query_strip_oob_flag(const struct gnutella_node *n, char *data);
void query_set_oob_flag(const struct gnutella_node *n, char *data);

void record_query_string(const struct guid *muid, const char *query);
const char *map_muid_to_query_string(const struct guid *muid);

void search_query_key_generate(sectoken_t *tok, host_addr_t addr, guint16 port);

gnutella_msg_search_t *build_guess_search_msg(const struct guid *muid,
	const char *query, guint32 *size, const void *query_key, guint8 length);

const char *lazy_safe_search(const char *search);

#endif /* _core_search_h_ */

/* vi: set ts=4 sw=4 cindent: */
