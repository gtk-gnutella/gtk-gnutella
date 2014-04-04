/*
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

#include "if/gen/gnr_stats.h"
#include "if/gen/msg_drop.h"

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
	MSG_DHT_PING,
	MSG_DHT_PONG,
	MSG_DHT_STORE,
	MSG_DHT_STORE_ACK,
	MSG_DHT_FIND_NODE,
	MSG_DHT_FOUND_NODE,
	MSG_DHT_FIND_VALUE,
	MSG_DHT_VALUE,
	/* Not including CRAWLA -- not expected as we don't send requests */
	MSG_G2_CRAWLR,
	MSG_G2_HAW,
	MSG_G2_KHL,
	MSG_G2_KHLR,
	MSG_G2_KHLA,
	MSG_G2_LNI,
	MSG_G2_PI,
	MSG_G2_PO,
	MSG_G2_PUSH,
	MSG_G2_QKA,
	MSG_G2_QKR,
	MSG_G2_Q2,
	MSG_G2_QA,
	MSG_G2_QH2,
	MSG_G2_QHT,
	MSG_G2_UPROC,
	MSG_G2_UPROD,

	MSG_TOTAL,     /**< always counted (for all the above types) */
	
	MSG_TYPE_COUNT /**< number of known message types */
};

#define MSG_DHT_BASE	0xd0		/* Base in lookup table for DHT messages */
#define MSG_G2_BASE		0x05		/* Base in lookup table for G2 messages */

#define STATS_FLOWC_COLUMNS 10	/**< Type, 0..7, 8+ */
#define STATS_RECV_COLUMNS 10	/**< -"- */

typedef struct gnet_stat {
	uint64 drop_reason[MSG_DROP_REASON_COUNT][MSG_TYPE_COUNT];

	struct {
		uint64 received[MSG_TYPE_COUNT];
		uint64 expired[MSG_TYPE_COUNT];
		uint64 dropped[MSG_TYPE_COUNT];
		uint64 queued[MSG_TYPE_COUNT];
		uint64 relayed[MSG_TYPE_COUNT];
		uint64 gen_queued[MSG_TYPE_COUNT];
		uint64 generated[MSG_TYPE_COUNT];
		uint64 received_hops[STATS_RECV_COLUMNS][MSG_TYPE_COUNT];
		uint64 received_ttl[STATS_RECV_COLUMNS][MSG_TYPE_COUNT];
		uint64 flowc_hops[STATS_FLOWC_COLUMNS][MSG_TYPE_COUNT];
		uint64 flowc_ttl[STATS_FLOWC_COLUMNS][MSG_TYPE_COUNT];
	} pkg, byte;

	uint64 general[GNR_TYPE_COUNT];
} gnet_stats_t;

typedef enum {
	BW_GNET_IN,
	BW_GNET_OUT,
	BW_HTTP_IN,
	BW_HTTP_OUT,
	BW_LEAF_IN,
	BW_LEAF_OUT,
	BW_GNET_UDP_IN,
	BW_GNET_UDP_OUT,
	BW_DHT_IN,
	BW_DHT_OUT
} gnet_bw_source;

typedef struct gnet_bw_stats {
	bool enabled;
	uint32  current;
	uint32  average;
	uint32  limit;
} gnet_bw_stats_t;

/***
 *** General statistics
 ***/

#ifdef CORE_SOURCES

void gnet_stats_get(gnet_stats_t *stats);
void gnet_stats_tcp_get(gnet_stats_t *stats);
void gnet_stats_udp_get(gnet_stats_t *stats);
void gnet_get_bw_stats(gnet_bw_source type, gnet_bw_stats_t *stats);

#endif /* CORE_SOURCES */

#endif /* _if_core_net_stats_h_ */

/* vi: set ts=4 sw=4 cindent: */
