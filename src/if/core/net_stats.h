/*
 * $Id$
 *
 * Copyright (c) 2001-2003, Raphael Manfredi, Richard Eckart
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

#ifndef _if_core_net_stats_h_
#define _if_core_net_stats_h_

#include "common.h"

/***
 *** General statistics
 ***/

enum {
	MSG_UNKNOWN = 0,
	MSG_INIT,
	MSG_INIT_RESPONSE,
	MSG_BYE,
	MSG_QRP,
	MSG_HSEP,
	MSG_RUDP,
	MSG_VENDOR,
	MSG_STANDARD,
	MSG_PUSH_REQUEST,
	MSG_SEARCH,
	MSG_SEARCH_RESULTS,
	MSG_DHT,
	MSG_TOTAL,     /**< always counted (for all the above types) */
	
	MSG_TYPE_COUNT /**< number of known message types */
};

typedef enum msg_drop_reason {
	MSG_DROP_BAD_SIZE = 0,
	MSG_DROP_TOO_SMALL,
	MSG_DROP_TOO_LARGE,
	MSG_DROP_WAY_TOO_LARGE,
	MSG_DROP_UNKNOWN_TYPE,
	MSG_DROP_UNEXPECTED,
	MSG_DROP_TTL0,
	MSG_DROP_IMPROPER_HOPS_TTL,
	MSG_DROP_MAX_TTL_EXCEEDED,
	MSG_DROP_THROTTLE,
	MSG_DROP_PONG_UNUSABLE,
	MSG_DROP_HARD_TTL_LIMIT,
	MSG_DROP_MAX_HOP_COUNT,
	MSG_DROP_ROUTE_LOST,
	MSG_DROP_NO_ROUTE,
	MSG_DROP_DUPLICATE,
	MSG_DROP_BANNED,
	MSG_DROP_SHUTDOWN,
	MSG_DROP_FLOW_CONTROL,
	MSG_DROP_QUERY_NO_NUL,
	MSG_DROP_QUERY_TOO_SHORT,
	MSG_DROP_QUERY_OVERHEAD,
	MSG_DROP_BAD_URN,
	MSG_DROP_MALFORMED_SHA1,
	MSG_DROP_MALFORMED_UTF_8,
	MSG_DROP_BAD_RESULT,
	MSG_DROP_BAD_RETURN_ADDRESS,
	MSG_DROP_HOSTILE_IP,
	MSG_DROP_SPAM,
	MSG_DROP_EVIL,
	MSG_DROP_INFLATE_ERROR,
	MSG_DROP_UNKNOWN_HEADER_FLAGS,
	MSG_DROP_OWN_RESULT,
	MSG_DROP_ANCIENT_QUERY,
	MSG_DROP_BLANK_SERVENT_ID,
	MSG_DROP_DHT_INVALID_TOKEN,
	MSG_DROP_DHT_TOO_MANY_STORE,
	MSG_DROP_DHT_UNPARSEABLE,
	
	MSG_DROP_REASON_COUNT /**< number of known reasons to drop a message */
} msg_drop_reason_t;

typedef enum {
	GNR_ROUTING_ERRORS = 0,
	GNR_LOCAL_SEARCHES,
	GNR_LOCAL_HITS,
	GNR_LOCAL_QUERY_HITS,
	GNR_OOB_PROXIED_QUERY_HITS,
	GNR_OOB_QUERIES,
	GNR_OOB_QUERIES_STRIPPED,
	GNR_DUPS_WITH_HIGHER_TTL,
	GNR_QUERY_OOB_PROXIED_DUPS,
	GNR_OOB_HITS_FOR_PROXIED_QUERIES,
	GNR_OOB_HITS_WITH_ALIEN_IP,
	GNR_UNCLAIMED_OOB_HITS,
	GNR_PARTIALLY_CLAIMED_OOB_HITS,
	GNR_SPURIOUS_OOB_HIT_CLAIM,
	GNR_UNREQUESTED_OOB_HITS,
	GNR_QUERY_COMPACT_COUNT,
	GNR_QUERY_COMPACT_SIZE,
	GNR_QUERY_UTF8,
	GNR_QUERY_SHA1,
	GNR_BROADCASTED_PUSHES,
	GNR_PUSH_PROXY_RELAYED,
	GNR_PUSH_PROXY_BROADCASTED,
	GNR_PUSH_PROXY_FAILED,
	GNR_LOCAL_DYN_QUERIES,
	GNR_LEAF_DYN_QUERIES,
	GNR_OOB_PROXIED_QUERIES,
	GNR_DYN_QUERIES_COMPLETED_FULL,
	GNR_DYN_QUERIES_COMPLETED_PARTIAL,
	GNR_DYN_QUERIES_COMPLETED_ZERO,
	GNR_DYN_QUERIES_LINGER_EXTRA,
	GNR_DYN_QUERIES_LINGER_RESULTS,
	GNR_DYN_QUERIES_LINGER_COMPLETED,
	GNR_GTKG_TOTAL_QUERIES,
	GNR_GTKG_REQUERIES,
	GNR_QUERIES_WITH_GGEP_H,
	GNR_GIV_CALLBACKS,
	GNR_QUEUE_CALLBACKS,
	GNR_UDP_BOGUS_SOURCE_IP,
	GNR_UDP_ALIEN_MESSAGE,
	GNR_UDP_UNPROCESSED_MESSAGE,
	GNR_UDP_TX_COMPRESSED,
	GNR_UDP_RX_COMPRESSED,
	GNR_UDP_LARGER_HENCE_NOT_COMPRESSED,
	GNR_ATTEMPTED_RESOURCE_SWITCHING,
	GNR_SUCCESSFUL_RESOURCE_SWITCHING,
	GNR_SUCCESSFUL_PLAIN_RESOURCE_SWITCHING,
	GNR_QUEUED_AFTER_SWITCHING,
	GNR_IGNORED_DATA,
	GNR_IGNORING_AFTER_MISMATCH,
	GNR_IGNORING_TO_PRESERVE_CONNECTION,
	GNR_IGNORING_DURING_AGGRESSIVE_SWARMING,
	GNR_IGNORING_REFUSED,
	GNR_CLIENT_RESOURCE_SWITCHING,
	GNR_CLIENT_PLAIN_RESOURCE_SWITCHING,
	GNR_PARQ_SLOT_RESOURCE_SWITCHING,
	GNR_SEEDING_OF_ORPHAN,
	GNR_DHT_KEYS_HELD,
	GNR_DHT_VALUES_HELD,
	GNR_DHT_FETCH_LOCAL_HITS,
	GNR_DHT_STALE_REPLICATION,
	GNR_DHT_REPLICATION,
	GNR_DHT_REPUBLISH,
	GNR_DHT_ALT_LOC_LOOKUPS,
	GNR_DHT_PUSH_PROXY_LOOKUPS,
	GNR_DHT_SUCCESSFUL_ALT_LOC_LOOKUPS,
	GNR_DHT_SUCCESSFUL_PUSH_PROXY_LOOKUPS,
	GNR_DHT_SEEDING_OF_ORPHAN,
	
	GNR_TYPE_COUNT /* number of general stats */
} gnr_stats_t;

#define STATS_FLOWC_COLUMNS 10	/**< Type, 0..7, 8+ */
#define STATS_RECV_COLUMNS 10	/**< -"- */

typedef struct gnet_stat {
	guint64 drop_reason[MSG_DROP_REASON_COUNT][MSG_TYPE_COUNT];

	struct {
		guint64 received[MSG_TYPE_COUNT];
		guint64 expired[MSG_TYPE_COUNT];
		guint64 dropped[MSG_TYPE_COUNT];
		guint64 queued[MSG_TYPE_COUNT];
		guint64 relayed[MSG_TYPE_COUNT];
		guint64 gen_queued[MSG_TYPE_COUNT];
		guint64 generated[MSG_TYPE_COUNT];
		guint64 received_hops[STATS_RECV_COLUMNS][MSG_TYPE_COUNT];
		guint64 received_ttl[STATS_RECV_COLUMNS][MSG_TYPE_COUNT];
		guint64 flowc_hops[STATS_FLOWC_COLUMNS][MSG_TYPE_COUNT];
		guint64 flowc_ttl[STATS_FLOWC_COLUMNS][MSG_TYPE_COUNT];
	} pkg, byte;

	guint64 general[GNR_TYPE_COUNT];
} gnet_stats_t;

typedef enum {
	BW_GNET_IN,
	BW_GNET_OUT,
	BW_HTTP_IN,
	BW_HTTP_OUT,
	BW_LEAF_IN,
	BW_LEAF_OUT,
	BW_GNET_UDP_IN,
	BW_GNET_UDP_OUT
} gnet_bw_source;

typedef struct gnet_bw_stats {
	gboolean enabled;
	guint32  current;
	guint32  average;
	guint32  limit;
} gnet_bw_stats_t;

/***
 *** General statistics
 ***/

#ifdef CORE_SOURCES

void gnet_stats_get(gnet_stats_t *stats);
void gnet_stats_tcp_get(gnet_stats_t *stats);
void gnet_stats_udp_get(gnet_stats_t *stats);
void gnet_get_bw_stats(gnet_bw_source type, gnet_bw_stats_t *stats);
const char *gnet_stats_drop_reason_to_string(msg_drop_reason_t reason);
const char *gnet_stats_general_to_string(gnr_stats_t type);

#endif /* CORE_SOURCES */

#endif /* _if_core_net_stats_h_ */
/* vi: set ts=4 sw=4 cindent: */
