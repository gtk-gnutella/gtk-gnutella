/*
 * $Id$
 *
 * Copyright (c) 2001-2003, Richard Eckart
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

#include "gnet_stats.h"
#include "gmsg.h"
#include "override.h"		/* Must be the last header included */

RCSID("$Id$");

static guint8 stats_lut[256];

static gnet_stats_t gnet_stats;

static gchar *msg_drop_reason[MSG_DROP_REASON_COUNT] = {
	"Bad size",							/* MSG_DROP_BAD_SIZE */
	"Too small",						/* MSG_DROP_TOO_SMALL */
	"Too large",						/* MSG_DROP_TOO_LARGE */
	"Way too large",					/* MSG_DROP_WAY_TOO_LARGE */
	"Unknown message type",				/* MSG_DROP_UNKNOWN_TYPE */
	"Unexpected message",				/* MSG_DROP_UNEXPECTED */
	"Message sent with TTL = 0",		/* MSG_DROP_TTL0 */
	"Improper hops/ttl combination"		/* MSG_DROP_IMPROPER_HOPS_TTL */
	"Max TTL exceeded",					/* MSG_DROP_MAX_TTL_EXCEEDED */
	"Message throttle",					/* MSG_DROP_THROTTLE */
	"Unusable Pong",					/* MSG_DROP_PONG_UNUSABLE */
	"Hard TTL limit reached",			/* MSG_DROP_HARD_TTL_LIMIT */
	"Max hop count reached",			/* MSG_DROP_MAX_HOP_COUNT */
	"Unrequested reply",				/* MSG_DROP_UNREQUESTED_REPLY */
	"Route lost",						/* MSG_DROP_ROUTE_LOST */
	"No route",							/* MSG_DROP_NO_ROUTE */
	"Duplicate message",				/* MSG_DROP_DUPLICATE */
	"Message to banned GUID",			/* MSG_DROP_BANNED */
	"Node shutting down",				/* MSG_DROP_SHUTDOWN */
	"TX flow control",					/* MSG_DROP_FLOW_CONTROL */
	"Query text had no trailing NUL",	/* MSG_DROP_QUERY_NO_NUL */
	"Query text too short",				/* MSG_DROP_QUERY_TOO_SHORT */
	"Query had unnecessary overhead",	/* MSG_DROP_QUERY_OVERHEAD */
	"Message with malformed SHA1",		/* MSG_DROP_MALFORMED_SHA1 */
	"Message with malformed UTF-8",		/* MSG_DROP_MALFORMED_UTF_8 */
	"Malformed Query Hit",				/* MSG_DROP_BAD_RESULT */
	"Hostile IP address",				/* MSG_DROP_HOSTILE_IP */
};

/***
 *** Public functions
 ***/

void gnet_stats_init(void)
{
    memset(stats_lut, MSG_UNKNOWN, sizeof(stats_lut));
    stats_lut[GTA_MSG_INIT] = MSG_INIT;
    stats_lut[GTA_MSG_INIT_RESPONSE]= MSG_INIT_RESPONSE;
    stats_lut[GTA_MSG_BYE] = MSG_BYE;
    stats_lut[GTA_MSG_QRP] = MSG_QRP;
    stats_lut[GTA_MSG_VENDOR] = MSG_VENDOR;
    stats_lut[GTA_MSG_STANDARD] = MSG_STANDARD;
    stats_lut[GTA_MSG_PUSH_REQUEST] = MSG_PUSH_REQUEST;
    stats_lut[GTA_MSG_SEARCH] = MSG_SEARCH;
    stats_lut[GTA_MSG_SEARCH_RESULTS] = MSG_SEARCH_RESULTS;

    memset(&gnet_stats, 0, sizeof(gnet_stats));
}

/*
 * gnet_stats_count_received_header
 *
 * Called when Gnutella header has been read.
 */
void gnet_stats_count_received_header(gnutella_node_t *n)
{
	guint t = stats_lut[n->header.function];
	guint i;

    n->received++;

    gnet_stats.pkg.received[MSG_TOTAL]++;
    gnet_stats.pkg.received[t]++;
    gnet_stats.byte.received[MSG_TOTAL] += sizeof(n->header);
    gnet_stats.byte.received[t] += sizeof(n->header);

	i = MIN(n->header.ttl, STATS_RECV_COLUMNS-1);
    gnet_stats.pkg.received_ttl[i][MSG_TOTAL]++;
    gnet_stats.pkg.received_ttl[i][t]++;

	i = MIN(n->header.hops, STATS_RECV_COLUMNS-1);
    gnet_stats.pkg.received_hops[i][MSG_TOTAL]++;
    gnet_stats.pkg.received_hops[i][t]++;
}

/*
 * gnet_stats_count_received_payload
 *
 * Called when Gnutella payload has been read.
 */
void gnet_stats_count_received_payload(gnutella_node_t *n)
{
    guint32 size = n->size;
	guint t = stats_lut[n->header.function];
	guint i;

    gnet_stats.byte.received[MSG_TOTAL] += size;
    gnet_stats.byte.received[t] += size;

	i = MIN(n->header.ttl, STATS_RECV_COLUMNS-1);
    gnet_stats.byte.received_ttl[i][MSG_TOTAL] += size;
    gnet_stats.byte.received_ttl[i][t] += size;

	i = MIN(n->header.hops, STATS_RECV_COLUMNS-1);
    gnet_stats.byte.received_hops[i][MSG_TOTAL] += size;
    gnet_stats.byte.received_hops[i][t] += size;
}

void gnet_stats_count_sent(
	gnutella_node_t *n, guint8 type, guint8 hops, guint32 size)
{
	guint64 *stats_pkg;
	guint64 *stats_byte;
	guint t = stats_lut[type];

	stats_pkg = hops ? gnet_stats.pkg.relayed : gnet_stats.pkg.generated;
	stats_byte = hops ? gnet_stats.byte.relayed : gnet_stats.byte.generated;

    stats_pkg[MSG_TOTAL]++;
    stats_pkg[t]++;
    stats_byte[MSG_TOTAL] += size;
    stats_byte[t] += size;
}

void gnet_stats_count_expired(gnutella_node_t *n)
{
    guint32 size = n->size + sizeof(n->header);
	guint t = stats_lut[n->header.function];

    gnet_stats.pkg.expired[MSG_TOTAL]++;
    gnet_stats.pkg.expired[t]++;
    gnet_stats.byte.expired[MSG_TOTAL] += size;
    gnet_stats.byte.expired[t] += size;
}

#define DROP_STATS(t,s) do {							\
    if (												\
        (reason == MSG_DROP_ROUTE_LOST) ||				\
        (reason == MSG_DROP_DUPLICATE) ||				\
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
} while (0)

void gnet_stats_count_dropped(gnutella_node_t *n, msg_drop_reason_t reason)
{
	guint32 size;
	guint type;
	g_assert(reason >= 0 && reason < MSG_DROP_REASON_COUNT);

    size = n->size + sizeof(n->header);
	type = stats_lut[n->header.function];

	DROP_STATS(type, size);

	if (dbg > 4)
		gmsg_log_dropped(&n->header, "from %s <%s>: %s",
			node_ip(n), node_vendor(n), msg_drop_reason[reason]);
}

void gnet_stats_count_general(gnutella_node_t *n, gnr_stats_t type, guint32 x)
{
	/* XXX - parameter `n' is unused, remove? */

	g_assert(type >= 0 && type < GNR_TYPE_COUNT);

    gnet_stats.general[type] += x;
}

void gnet_stats_count_dropped_nosize(
	gnutella_node_t *n, msg_drop_reason_t reason)
{
	guint type;
	g_assert(reason >= 0 && reason < MSG_DROP_REASON_COUNT);

	type = stats_lut[n->header.function];

	DROP_STATS(type, sizeof(n->header));	/* Data part of message not read */

	if (dbg > 4)
		gmsg_log_dropped(&n->header, "from %s <%s>: %s",
			node_ip(n), node_vendor(n), msg_drop_reason[reason]);
}

void gnet_stats_count_flowc(gpointer head)
{
    struct gnutella_header *h = (struct gnutella_header *) head;
	guint t;
	guint i;
	guint32 size;

	READ_GUINT32_LE(h->size, size);
#if 0
	g_message("FLOWC function=%d ttl=%d hops=%d", h->function, h->ttl, h->hops);
#endif

	t = stats_lut[h->function];

	i = MIN(h->hops, STATS_FLOWC_COLUMNS-1);
	gnet_stats.pkg.flowc_hops[i][t]++;
	gnet_stats.pkg.flowc_hops[i][MSG_TOTAL]++;
	gnet_stats.byte.flowc_hops[i][t] += size;
	gnet_stats.byte.flowc_hops[i][MSG_TOTAL] += size;

	i = MIN(h->ttl, STATS_FLOWC_COLUMNS-1);

	g_assert(i != 0);			/* Cannot send a message with TTL=0 */

	gnet_stats.pkg.flowc_ttl[i][t]++;
	gnet_stats.pkg.flowc_ttl[i][MSG_TOTAL]++;
	gnet_stats.byte.flowc_ttl[i][t] += size;
	gnet_stats.byte.flowc_ttl[i][MSG_TOTAL] += size;
}

/***
 *** Public functions (gnet.h)
 ***/

void gnet_stats_get(gnet_stats_t *s)
{
    g_assert(s != NULL);
    memcpy(s, &gnet_stats, sizeof(*s));
}

