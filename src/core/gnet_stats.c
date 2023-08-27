/*
 * Copyright (c) 2001-2003, Richard Eckart
 * Copyright (c) 2008-2014, Raphael Manfredi
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
 * Collection of Gnutella / DHT statistics.
 *
 * @author Richard Eckart
 * @date 2001-2003
 * @author Raphael Manfredi
 * @date 2008-2014
 */

#include "common.h"

#include "gnet_stats.h"
#include "gmsg.h"

#include "g2/msg.h"

#include "if/dht/kademlia.h"
#include "if/gnet_property_priv.h"

#include "lib/entropy.h"
#include "lib/event.h"
#include "lib/random.h"
#include "lib/sha1.h"
#include "lib/spinlock.h"
#include "lib/thread.h"
#include "lib/tm.h"

#include "lib/override.h"		/* Must be the last header included */

static uint8 stats_lut[256];

static gnet_stats_t gnet_stats;
static gnet_stats_t gnet_tcp_stats;
static gnet_stats_t gnet_udp_stats;

/*
 * Thread-safe locks.
 *
 * The general stats accounting code is protected because there is no guarantee
 * the routines updating these stats will always be called from the main thread.
 *
 * However, the routines updating the traffic statistics are NOT protected
 * because they are always called from the main thread, the one where the
 * I/O event loop is installed.  An assertion verifies this assumption.
 */
static spinlock_t gnet_stats_slk = SPINLOCK_INIT;

#define GNET_STATS_LOCK		spinlock_hidden(&gnet_stats_slk)
#define GNET_STATS_UNLOCK	spinunlock_hidden(&gnet_stats_slk)

/***
 *** Public functions
 ***/

void G_COLD
gnet_stats_init(void)
{
	uint i;

	/* Guarantees that our little hack below can succeed */
	STATIC_ASSERT(
		UNSIGNED(KDA_MSG_MAX_ID + MSG_DHT_BASE) < N_ITEMS(stats_lut));
	STATIC_ASSERT(
		UNSIGNED(MSG_G2_BASE + G2_MSG_MAX) < GTA_MSG_QRP);

	for (i = 0; i < N_ITEMS(stats_lut); i++) {
		uchar m = MSG_UNKNOWN;

		/*
		 * To keep the look-up table small enough, we cheat a little
		 * bit to be able to stuff both Gnutella and Kademlia messages.
		 *
		 * We use the fact that the space from 0xd0 and onwards is unused
		 * by Gnutella to stuff the DHT messages there.  And 0xd0 starts
		 * with a 'D', so it's not a total hack.
		 *		--RAM, 2010-11-01.
		 *
		 * We play the same trick for G2 messages, only we insert them
		 * in the 0x05 .. 0x2f space, which is unused by Gnutella.
		 *		--RAM, 2014-01-07.
		 */

		if (i > MSG_DHT_BASE) {
			switch ((enum kda_msg) (i - MSG_DHT_BASE)) {
			case KDA_MSG_PING_REQUEST:		m = MSG_DHT_PING; break;
			case KDA_MSG_PING_RESPONSE:		m = MSG_DHT_PONG; break;
			case KDA_MSG_STORE_REQUEST:		m = MSG_DHT_STORE; break;
			case KDA_MSG_STORE_RESPONSE:	m = MSG_DHT_STORE_ACK; break;
			case KDA_MSG_FIND_NODE_REQUEST:	m = MSG_DHT_FIND_NODE; break;
			case KDA_MSG_FIND_NODE_RESPONSE:m = MSG_DHT_FOUND_NODE; break;
			case KDA_MSG_FIND_VALUE_REQUEST:	m = MSG_DHT_FIND_VALUE; break;
			case KDA_MSG_FIND_VALUE_RESPONSE:	m = MSG_DHT_VALUE; break;
			case KDA_MSG_STATS_REQUEST:
			case KDA_MSG_STATS_RESPONSE:
				/* deprecated, not supported */
				break;
			}
		} else if (i > MSG_G2_BASE && i < GTA_MSG_QRP) {
			switch ((enum g2_msg) (i - MSG_G2_BASE)) {
			case G2_MSG_CRAWLR:			m = MSG_G2_CRAWLR; break;
			case G2_MSG_HAW:			m = MSG_G2_HAW; break;
			case G2_MSG_KHL:			m = MSG_G2_KHL; break;
			case G2_MSG_KHLR:			m = MSG_G2_KHLR; break;
			case G2_MSG_KHLA:			m = MSG_G2_KHLA; break;
			case G2_MSG_LNI:			m = MSG_G2_LNI; break;
			case G2_MSG_PI:				m = MSG_G2_PI; break;
			case G2_MSG_PO:				m = MSG_G2_PO; break;
			case G2_MSG_PUSH:			m = MSG_G2_PUSH; break;
			case G2_MSG_QKA:			m = MSG_G2_QKA; break;
			case G2_MSG_QKR:			m = MSG_G2_QKR; break;
			case G2_MSG_Q2:				m = MSG_G2_Q2; break;
			case G2_MSG_QA:				m = MSG_G2_QA; break;
			case G2_MSG_QH2:			m = MSG_G2_QH2; break;
			case G2_MSG_QHT:			m = MSG_G2_QHT; break;
			case G2_MSG_UPROC:			m = MSG_G2_UPROC; break;
			case G2_MSG_UPROD:			m = MSG_G2_UPROD; break;
			case G2_MSG_MAX:
				break;
			case G2_MSG_CRAWLA:
				/* This message is skipped, since we don't expect it */
				g_assert_not_reached();
			}
		} else {
			switch ((enum gta_msg) i) {
			case GTA_MSG_INIT:           m = MSG_INIT; break;
			case GTA_MSG_INIT_RESPONSE:  m = MSG_INIT_RESPONSE; break;
			case GTA_MSG_SEARCH:         m = MSG_SEARCH; break;
			case GTA_MSG_SEARCH_RESULTS: m = MSG_SEARCH_RESULTS; break;
			case GTA_MSG_PUSH_REQUEST:   m = MSG_PUSH_REQUEST; break;
			case GTA_MSG_RUDP:			 m = MSG_RUDP; break;
			case GTA_MSG_VENDOR:		 m = MSG_VENDOR; break;
			case GTA_MSG_STANDARD:		 m = MSG_STANDARD; break;
			case GTA_MSG_QRP:            m = MSG_QRP; break;
			case GTA_MSG_HSEP_DATA:		 m = MSG_HSEP; break;
			case GTA_MSG_BYE:      		 m = MSG_BYE; break;
			case GTA_MSG_DHT:            m = MSG_DHT; break;
			case GTA_MSG_G2_SEARCH:	/* Not a real message */
				break;
			}
		}
		stats_lut[i] = m;
	}

	/* gnet_stats_count_received_payload() relies on this for G2 messages */
	g_assert(MSG_UNKNOWN == stats_lut[N_ITEMS(stats_lut) - 1]);

#undef CASE

    ZERO(&gnet_stats);
    ZERO(&gnet_udp_stats);
}

/**
 * Generate a SHA1 digest of the supplied statistics.
 */
static void
gnet_stats_digest(sha1_t *digest, gnet_stats_t *stats)
{
	uint32 n = entropy_nonce();

	stats->general[GNR_STATS_DIGEST]++;		/* Ensure ever-changing SHA1 */
	SHA1_COMPUTE_NONCE(*stats, &n, digest);
}

/**
 * Generate a SHA1 digest of the current TCP statistics.
 *
 * This is meant for dynamic entropy collection.
 */
void
gnet_stats_tcp_digest(sha1_t *digest)
{
	gnet_stats_inc_general(GNR_STATS_TCP_DIGEST);
	gnet_stats_digest(digest, &gnet_tcp_stats);
}

/**
 * Generate a SHA1 digest of the current UDP statistics.
 *
 * This is meant for dynamic entropy collection.
 */
void
gnet_stats_udp_digest(sha1_t *digest)
{
	gnet_stats_inc_general(GNR_STATS_UDP_DIGEST);
	gnet_stats_digest(digest, &gnet_udp_stats);
}

/**
 * Generate a SHA1 digest of the current general statistics.
 *
 * This is meant for dynamic entropy collection.
 */
void
gnet_stats_general_digest(sha1_t *digest)
{
	uint32 n = entropy_nonce();

	gnet_stats_inc_general(GNR_STATS_DIGEST);
	SHA1_COMPUTE_NONCE(gnet_stats.general, &n, digest);
}

/**
 * Use unpredictable events to collect random data.
 */
static void
gnet_stats_randomness(const gnutella_node_t *n, uint8 type, uint32 val)
{
	entropy_harvest_small(
		VARLEN(n->addr), VARLEN(n->port), VARLEN(type), VARLEN(val), NULL);
}

static void
gnet_stats_count_received_header_internal(gnutella_node_t *n,
	size_t header_size, uint t, uint8 ttl, uint8 hops)
{
	gnet_stats_t *stats = NODE_USES_UDP(n) ? &gnet_udp_stats : &gnet_tcp_stats;
	uint i;

    n->received++;

    gnet_stats.pkg.received[MSG_TOTAL]++;
    gnet_stats.pkg.received[t]++;
    gnet_stats.byte.received[MSG_TOTAL] += header_size;
    gnet_stats.byte.received[t] += header_size;

    stats->pkg.received[MSG_TOTAL]++;
    stats->pkg.received[t]++;
    stats->byte.received[MSG_TOTAL] += header_size;
    stats->byte.received[t] += header_size;

	i = MIN(ttl, STATS_RECV_COLUMNS - 1);
    stats->pkg.received_ttl[i][MSG_TOTAL]++;
    stats->pkg.received_ttl[i][t]++;

	i = MIN(hops, STATS_RECV_COLUMNS - 1);
    stats->pkg.received_hops[i][MSG_TOTAL]++;
    stats->pkg.received_hops[i][t]++;
}

/**
 * Called when Gnutella header has been read.
 */
void
gnet_stats_count_received_header(gnutella_node_t *n)
{
	uint t = stats_lut[gnutella_header_get_function(&n->header)];
	uint8 ttl, hops;

	g_assert(thread_is_main());
	g_assert(!NODE_TALKS_G2(n));

	ttl = gnutella_header_get_ttl(&n->header);
	hops = gnutella_header_get_hops(&n->header);

	gnet_stats_count_received_header_internal(n, GTA_HEADER_SIZE, t, ttl, hops);
}

/**
 * Called to transform Gnutella header counting into Kademlia header counting.
 *
 * @param n		the node receiving the message
 * @param kt
 */
static void
gnet_stats_count_kademlia_header(const gnutella_node_t *n, uint kt)
{
	uint t = stats_lut[gnutella_header_get_function(&n->header)];
	uint i;
	gnet_stats_t *stats;

	g_assert(thread_is_main());
	g_assert(!NODE_TALKS_G2(n));

	stats = NODE_USES_UDP(n) ? &gnet_udp_stats : &gnet_tcp_stats;

    gnet_stats.pkg.received[t]--;
    gnet_stats.pkg.received[kt]++;
    gnet_stats.byte.received[t] -= GTA_HEADER_SIZE;
    gnet_stats.byte.received[kt] += GTA_HEADER_SIZE;

    stats->pkg.received[t]--;
    stats->pkg.received[kt]++;
    stats->byte.received[t] -= GTA_HEADER_SIZE;
    stats->byte.received[kt] += GTA_HEADER_SIZE;

	i = MIN(gnutella_header_get_ttl(&n->header), STATS_RECV_COLUMNS - 1);
    stats->pkg.received_ttl[i][MSG_TOTAL]--;
    stats->pkg.received_ttl[i][t]--;

	i = MIN(gnutella_header_get_hops(&n->header), STATS_RECV_COLUMNS - 1);
    stats->pkg.received_hops[i][MSG_TOTAL]--;
    stats->pkg.received_hops[i][t]--;

	/* DHT messages have no hops nor ttl, use 0 */

    stats->pkg.received_ttl[0][MSG_TOTAL]++;
    stats->pkg.received_ttl[0][kt]++;
    stats->pkg.received_hops[0][MSG_TOTAL]++;
    stats->pkg.received_hops[0][kt]++;
}

/**
 * Called when Gnutella payload has been read, or when a G2 messsage is read.
 *
 * The actual payload size (effectively read) is expected to be found
 * in n->size for Gnutella messages and G2 messages.
 *
 * @param n			the node from which message was received
 * @param payload	start of Gnutella payload, or head of G2 frame
 */
void
gnet_stats_count_received_payload(const gnutella_node_t *n, const void *payload)
{
	uint8 f;
	uint t;
	uint i;
	gnet_stats_t *stats;
    uint32 size;
	uint8 hops, ttl;

	g_assert(thread_is_main());

	stats = NODE_USES_UDP(n) ? &gnet_udp_stats : &gnet_tcp_stats;
	size = n->size;

	/*
	 * Size is NOT read in the Gnutella header but in n->size, which
	 * reflects how much data we have in the payload, as opposed to the
	 * size in the header which may be wrong, or have highest bits set
	 * because they indicate flags.
	 *
	 * In particular, broken DHT messages often come with an invalid size in
	 * the header.
	 *		--RAM, 2010-10-30
	 */

	if (NODE_TALKS_G2(n)) {
		f = g2_msg_type(payload, size);
		if (f != G2_MSG_MAX) {
			f += MSG_G2_BASE;
		} else {
			f = N_ITEMS(stats_lut) - 1;	/* Last, holds MSG_UNKNOWN */
		}
		ttl = 1;
		hops = NODE_USES_UDP(n) ? 0 : 1;
		t = stats_lut[f];
		/*
		 * No header for G2, so count header reception now with a size of zero.
		 * This is required to update the other packet reception statistics.
		 */
		gnet_stats_count_received_header_internal(
			deconstify_pointer(n),
			0, t, ttl, hops);
	} else {
		f = gnutella_header_get_function(&n->header);
		hops = gnutella_header_get_hops(&n->header);
		ttl = gnutella_header_get_ttl(&n->header);
		t = stats_lut[f];
	}

	gnet_stats_randomness(n, f, size);

	/*
	 * If we're dealing with a Kademlia message, we need to do two things:
	 *
	 * We counted the Gnutella header for the GTA_MSG_DHT message, but we
	 * now need to undo that and count it as a Kademlia message.
	 *
	 * To access the proper entry in the array, we need to offset the
	 * Kademlia OpCode from the header with MSG_DHT_BASE to get the entry
	 * in the statistics that are associated with that particular message.
	 *		--RAM, 2010-11-01
	 */

	if (GTA_MSG_DHT == f && size + GTA_HEADER_SIZE >= KDA_HEADER_SIZE) {
		uint8 opcode = peek_u8(payload);	/* Kademlia Opcode */

		if (UNSIGNED(opcode + MSG_DHT_BASE) < N_ITEMS(stats_lut)) {
			t = stats_lut[opcode + MSG_DHT_BASE];
			gnet_stats_count_kademlia_header(n, t);
		}
	}

	g_assert(t < MSG_TOTAL);

    gnet_stats.byte.received[MSG_TOTAL] += size;
    gnet_stats.byte.received[t] += size;

    stats->byte.received[MSG_TOTAL] += size;
    stats->byte.received[t] += size;

	i = MIN(ttl, STATS_RECV_COLUMNS - 1);
    stats->byte.received_ttl[i][MSG_TOTAL] += size;
    stats->byte.received_ttl[i][t] += size;

	i = MIN(hops, STATS_RECV_COLUMNS - 1);
    stats->byte.received_hops[i][MSG_TOTAL] += size;
    stats->byte.received_hops[i][t] += size;
}

static void
gnet_stats_count_queued_internal(const gnutella_node_t *n,
	uint t, uint8 hops, uint32 size, gnet_stats_t *stats)
{
	uint64 *stats_pkg;
	uint64 *stats_byte;

	g_assert(t < MSG_TOTAL);

	gnet_stats_randomness(n, t & 0xff, size);

	stats_pkg = hops ? gnet_stats.pkg.queued : gnet_stats.pkg.gen_queued;
	stats_byte = hops ? gnet_stats.byte.queued : gnet_stats.byte.gen_queued;

    stats_pkg[MSG_TOTAL]++;
    stats_pkg[t]++;
    stats_byte[MSG_TOTAL] += size;
    stats_byte[t] += size;

	stats_pkg = hops ? stats->pkg.queued : stats->pkg.gen_queued;
	stats_byte = hops ? stats->byte.queued : stats->byte.gen_queued;

    stats_pkg[MSG_TOTAL]++;
    stats_pkg[t]++;
    stats_byte[MSG_TOTAL] += size;
    stats_byte[t] += size;
}

void
gnet_stats_count_queued(const gnutella_node_t *n,
	uint8 type, const void *base, uint32 size)
{
	uint t = stats_lut[type];
	gnet_stats_t *stats;
	uint8 hops;

	g_assert(t != MSG_UNKNOWN);
	g_assert(thread_is_main());
	g_assert(!NODE_TALKS_G2(n));

	stats = NODE_USES_UDP(n) ? &gnet_udp_stats : &gnet_tcp_stats;

	/*
	 * Adjust for Kademlia messages.
	 */

	if (GTA_MSG_DHT == type && size >= KDA_HEADER_SIZE) {
		uint8 opcode = kademlia_header_get_function(base);

		if (UNSIGNED(opcode + MSG_DHT_BASE) < N_ITEMS(stats_lut)) {
			t = stats_lut[opcode + MSG_DHT_BASE];
		}
		hops = 0;
	} else {
		hops = gnutella_header_get_hops(base);
	}

	gnet_stats_count_queued_internal(n, t, hops, size, stats);
}

void
gnet_stats_g2_count_queued(const gnutella_node_t *n,
	const void *base, size_t len)
{
	gnet_stats_t *stats;
	uint t;
	uint8 f;

	g_assert(thread_is_main());
	g_assert(NODE_TALKS_G2(n));

	stats = NODE_USES_UDP(n) ? &gnet_udp_stats : &gnet_tcp_stats;

	f = g2_msg_type(base, len);

	if (f != G2_MSG_MAX) {
		f += MSG_G2_BASE;
	} else {
		f = N_ITEMS(stats_lut) - 1;	/* Last, holds MSG_UNKNOWN */
	}

	t = stats_lut[f];

	/* Leaf mode => hops = 0 */
	gnet_stats_count_queued_internal(n, t, 0, len, stats);
}

static void
gnet_stats_count_sent_internal(const gnutella_node_t *n,
	uint t, uint8 hops, uint32 size, gnet_stats_t *stats)
{
	uint64 *stats_pkg;
	uint64 *stats_byte;

	g_assert(t < MSG_TOTAL);

	gnet_stats_randomness(n, t & 0xff, size);

	stats_pkg = hops ? gnet_stats.pkg.relayed : gnet_stats.pkg.generated;
	stats_byte = hops ? gnet_stats.byte.relayed : gnet_stats.byte.generated;

    stats_pkg[MSG_TOTAL]++;
    stats_pkg[t]++;
    stats_byte[MSG_TOTAL] += size;
    stats_byte[t] += size;

	stats_pkg = hops ? stats->pkg.relayed : stats->pkg.generated;
	stats_byte = hops ? stats->byte.relayed : stats->byte.generated;

    stats_pkg[MSG_TOTAL]++;
    stats_pkg[t]++;
    stats_byte[MSG_TOTAL] += size;
    stats_byte[t] += size;
}

void
gnet_stats_count_sent(const gnutella_node_t *n,
	uint8 type, const void *base, uint32 size)
{
	uint t = stats_lut[type];
	gnet_stats_t *stats;
	uint8 hops;

	g_assert(t != MSG_UNKNOWN);
	g_assert(thread_is_main());
	g_assert(!NODE_TALKS_G2(n));

	stats = NODE_USES_UDP(n) ? &gnet_udp_stats : &gnet_tcp_stats;

	/*
	 * Adjust for Kademlia messages.
	 */

	if (GTA_MSG_DHT == type && size >= KDA_HEADER_SIZE) {
		uint8 opcode = kademlia_header_get_function(base);

		if (UNSIGNED(opcode + MSG_DHT_BASE) < N_ITEMS(stats_lut)) {
			t = stats_lut[opcode + MSG_DHT_BASE];
		}
		hops = 0;
	} else {
		hops = gnutella_header_get_hops(base);
	}

	gnet_stats_count_sent_internal(n, t, hops, size, stats);
}

void
gnet_stats_g2_count_sent(const gnutella_node_t *n,
	enum g2_msg type, uint32 size)
{
	uint t;
	gnet_stats_t *stats;

	g_assert(thread_is_main());
	g_assert((uint) type < UNSIGNED(G2_MSG_MAX));
	g_assert(NODE_TALKS_G2(n));

	stats = NODE_USES_UDP(n) ? &gnet_udp_stats : &gnet_tcp_stats;

	t = stats_lut[MSG_G2_BASE + type];

	g_assert(t != MSG_UNKNOWN);

	/* Leaf mode => hops = 0 */
	gnet_stats_count_sent_internal(n, t, 0, size, stats);
}

void
gnet_stats_count_expired(const gnutella_node_t *n)
{
    uint32 size = n->size + sizeof(n->header);
	uint t = stats_lut[gnutella_header_get_function(&n->header)];
	gnet_stats_t *stats;

	g_assert(thread_is_main());
	g_assert(!NODE_TALKS_G2(n));

	stats = NODE_USES_UDP(n) ? &gnet_udp_stats : &gnet_tcp_stats;

    gnet_stats.pkg.expired[MSG_TOTAL]++;
    gnet_stats.pkg.expired[t]++;
    gnet_stats.byte.expired[MSG_TOTAL] += size;
    gnet_stats.byte.expired[t] += size;

    stats->pkg.expired[MSG_TOTAL]++;
    stats->pkg.expired[t]++;
    stats->byte.expired[MSG_TOTAL] += size;
    stats->byte.expired[t] += size;
}

#define DROP_STATS(gs,t,s) do {							\
    if (												\
        (reason == MSG_DROP_ROUTE_LOST) ||				\
        (reason == MSG_DROP_NO_ROUTE)					\
    )													\
        gnet_stats.general[GNR_ROUTING_ERRORS]++;		\
														\
    gnet_stats.drop_reason[reason][MSG_TOTAL]++;		\
    gnet_stats.drop_reason[reason][t]++;				\
    gnet_stats.pkg.dropped[MSG_TOTAL]++;				\
    gnet_stats.pkg.dropped[t]++;						\
    gnet_stats.byte.dropped[MSG_TOTAL] += (s);			\
    gnet_stats.byte.dropped[t] += (s);					\
	gs->drop_reason[reason][MSG_TOTAL]++;				\
	gs->drop_reason[reason][t]++;						\
    gs->pkg.dropped[MSG_TOTAL]++;						\
    gs->pkg.dropped[t]++;								\
    gs->byte.dropped[MSG_TOTAL] += (s);					\
    gs->byte.dropped[t] += (s);							\
} while (0)

void
gnet_stats_count_dropped(gnutella_node_t *n, msg_drop_reason_t reason)
{
	uint32 size;
	uint type;
	gnet_stats_t *stats;

	g_assert(UNSIGNED(reason) < MSG_DROP_REASON_COUNT);
	g_assert(thread_is_main());

	stats = NODE_USES_UDP(n) ? &gnet_udp_stats : &gnet_tcp_stats;

	if (NODE_TALKS_G2(n)) {
		int f = g2_msg_type(n->data, n->size);
		if (f != G2_MSG_MAX) {
			f += MSG_G2_BASE;
		} else {
			f = N_ITEMS(stats_lut) - 1;	/* Last, holds MSG_UNKNOWN */
		}
		type = stats_lut[f];
		size = n->size;
	} else {
		type = stats_lut[gnutella_header_get_function(&n->header)];
		size = n->size + sizeof(n->header);
	}

	entropy_harvest_small(
		VARLEN(n->addr), VARLEN(n->port), VARLEN(reason), VARLEN(type),
		VARLEN(size), NULL);

	DROP_STATS(stats, type, size);
	node_inc_rxdrop(n);

	switch (reason) {
	case MSG_DROP_HOSTILE_IP: n->n_hostile++; break;
	case MSG_DROP_SPAM: n->n_spam++; break;
	case MSG_DROP_EVIL: n->n_evil++; break;
	default: ;
	}

	if (NODE_TALKS_G2(n)) {
		if (GNET_PROPERTY(log_dropped_g2)) {
			g2_msg_log_dropped_data(n->data, n->size,
				"from %s: %s", node_infostr(n),
				gnet_stats_drop_reason_to_string(reason));
		}
	} else {
		if (GNET_PROPERTY(log_dropped_gnutella)) {
			gmsg_log_split_dropped(&n->header, n->data, n->size,
				"from %s: %s", node_infostr(n),
				gnet_stats_drop_reason_to_string(reason));
		}
	}
}

/**
 * Account for dropped Kademlia message of specified opcode from node ``n''.
 */
void
gnet_dht_stats_count_dropped(gnutella_node_t *n, kda_msg_t opcode,
	msg_drop_reason_t reason)
{
	uint32 size;
	uint type;
	gnet_stats_t *stats;

	g_assert(UNSIGNED(reason) < MSG_DROP_REASON_COUNT);
	g_assert(opcode <= KDA_MSG_MAX_ID);
	g_assert(UNSIGNED(opcode + MSG_DHT_BASE) < N_ITEMS(stats_lut));
	g_assert(thread_is_main());

    size = n->size + sizeof(n->header);
	type = stats_lut[opcode + MSG_DHT_BASE];
	stats = NODE_USES_UDP(n) ? &gnet_udp_stats : &gnet_tcp_stats;

	entropy_harvest_small(
		VARLEN(n->addr), VARLEN(n->port), VARLEN(reason), VARLEN(type),
		VARLEN(size), NULL);

	DROP_STATS(stats, type, size);
	node_inc_rxdrop(n);
}

/**
 * Update the general stats counter by given signed delta.
 */
void
gnet_stats_count_general(gnr_stats_t type, int delta)
{
	size_t i = type;

	g_assert(i < GNR_TYPE_COUNT);

	GNET_STATS_LOCK;
    gnet_stats.general[i] += delta;
	GNET_STATS_UNLOCK;
}

/**
 * Increment the general stats counter by 1.
 */
void
gnet_stats_inc_general(gnr_stats_t type)
{
	size_t i = type;

	g_assert(i < GNR_TYPE_COUNT);

	GNET_STATS_LOCK;
    gnet_stats.general[i]++;
	GNET_STATS_UNLOCK;
}

/**
 * Decrement the general stats counter by 1.
 */
void
gnet_stats_dec_general(gnr_stats_t type)
{
	size_t i = type;

	g_assert(i < GNR_TYPE_COUNT);

	GNET_STATS_LOCK;
    gnet_stats.general[i]--;
	GNET_STATS_UNLOCK;
}

/**
 * Update the general stats counter to keep the maximum value.
 */
void
gnet_stats_max_general(gnr_stats_t type, uint64 value)
{
	size_t i = type;

	g_assert(i < GNR_TYPE_COUNT);

	GNET_STATS_LOCK;
	if (value > gnet_stats.general[i])
		gnet_stats.general[i] = value;
	GNET_STATS_UNLOCK;
}

/**
 * Set the general stats counter to the given value.
 */
void
gnet_stats_set_general(gnr_stats_t type, uint64 value)
{
	size_t i = type;

	g_assert(i < GNR_TYPE_COUNT);

	GNET_STATS_LOCK;
    gnet_stats.general[i] = value;
	GNET_STATS_UNLOCK;
}

/**
 * Get the general stats counter.
 */
uint64
gnet_stats_get_general(gnr_stats_t type)
{
	size_t i = type;
	uint64 value;

	g_assert(i < GNR_TYPE_COUNT);

	GNET_STATS_LOCK;
	value = gnet_stats.general[i];
	GNET_STATS_UNLOCK;

	return value;
}

void
gnet_stats_count_dropped_nosize(
	const gnutella_node_t *n, msg_drop_reason_t reason)
{
	uint type;
	gnet_stats_t *stats;

	g_assert(UNSIGNED(reason) < MSG_DROP_REASON_COUNT);
	g_assert(thread_is_main());
	g_assert(!NODE_TALKS_G2(n));

	type = stats_lut[gnutella_header_get_function(&n->header)];
	stats = NODE_USES_UDP(n) ? &gnet_udp_stats : &gnet_tcp_stats;

	entropy_harvest_small(VARLEN(n->addr), VARLEN(n->port), NULL);

	/* Data part of message not read */
	DROP_STATS(stats, type, sizeof(n->header));

	if (GNET_PROPERTY(log_dropped_gnutella))
		gmsg_log_split_dropped(&n->header, n->data, 0,
			"from %s: %s", node_infostr(n),
			gnet_stats_drop_reason_to_string(reason));
}

static void
gnet_stats_flowc_internal(uint t,
	uint8 function, uint8 ttl, uint8 hops, size_t size)
{
	uint i;

	g_assert(t < MSG_TOTAL);

	i = MIN(hops, STATS_FLOWC_COLUMNS - 1);
	gnet_stats.pkg.flowc_hops[i][t]++;
	gnet_stats.pkg.flowc_hops[i][MSG_TOTAL]++;
	gnet_stats.byte.flowc_hops[i][t] += size;
	gnet_stats.byte.flowc_hops[i][MSG_TOTAL] += size;

	i = MIN(ttl, STATS_FLOWC_COLUMNS - 1);

	/* Cannot send a message with TTL=0 (DHT messages are not Gnutella) */
	g_assert(function == GTA_MSG_DHT || i != 0);

	gnet_stats.pkg.flowc_ttl[i][t]++;
	gnet_stats.pkg.flowc_ttl[i][MSG_TOTAL]++;
	gnet_stats.byte.flowc_ttl[i][t] += size;
	gnet_stats.byte.flowc_ttl[i][MSG_TOTAL] += size;

	entropy_harvest_small(VARLEN(t), VARLEN(function), VARLEN(size), NULL);
}

void
gnet_stats_count_flowc(const void *head, bool head_only)
{
	uint t;
	uint16 size = gmsg_size(head) + GTA_HEADER_SIZE;
	uint8 function = gnutella_header_get_function(head);
	uint8 ttl = gnutella_header_get_ttl(head);
	uint8 hops = gnutella_header_get_hops(head);

	g_assert(thread_is_main());

	if (GNET_PROPERTY(node_debug) > 3)
		g_debug("FLOWC function=%d ttl=%d hops=%d", function, ttl, hops);

	/*
	 * Adjust for Kademlia messages.
	 */

	if (GTA_MSG_DHT == function && size >= KDA_HEADER_SIZE && !head_only) {
		uint8 opcode = kademlia_header_get_function(head);

		if (UNSIGNED(opcode + MSG_DHT_BASE) < N_ITEMS(stats_lut)) {
			t = stats_lut[opcode + MSG_DHT_BASE];
		} else {
			t = stats_lut[function];		/* Invalid opcode? */
		}
		hops = 0;
		ttl = 0;
	} else {
		t = stats_lut[function];
	}

	gnet_stats_flowc_internal(t, function, ttl, hops, size);
}

void
gnet_stats_g2_count_flowc(const gnutella_node_t *n,
	const void *base, size_t len)
{
	uint t;
	uint8 f, ttl, hops;

	g_assert(thread_is_main());

	f = g2_msg_type(base, len);

	if (GNET_PROPERTY(node_debug) > 3)
		g_debug("FLOWC G2 %s", g2_msg_type_name(f));

	if (f != G2_MSG_MAX) {
		f += MSG_G2_BASE;
	} else {
		f = N_ITEMS(stats_lut) - 1;	/* Last, holds MSG_UNKNOWN */
	}

	ttl = NODE_USES_UDP(n) ? 1 : 2;		/* Purely made up, but cannot be 0 */
	hops = 0;		/* Locally generated, this is TX flowc */

	t = stats_lut[f];

	gnet_stats_flowc_internal(t, f, ttl, hops, len);
}

/***
 *** Public functions (gnet.h)
 ***/

void
gnet_stats_get(gnet_stats_t *s)
{
    g_assert(s != NULL);

	GNET_STATS_LOCK;
    *s = gnet_stats;
	GNET_STATS_UNLOCK;
}

void
gnet_stats_tcp_get(gnet_stats_t *s)
{
    g_assert(s != NULL);
	g_assert(thread_is_main());

    *s = gnet_tcp_stats;
}

void
gnet_stats_udp_get(gnet_stats_t *s)
{
    g_assert(s != NULL);
	g_assert(thread_is_main());

    *s = gnet_udp_stats;
}

/* vi: set ts=4 sw=4 cindent: */
