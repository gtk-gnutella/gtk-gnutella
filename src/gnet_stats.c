/*
 * $Id$
 *
 * Copyright (c) 2001-2002, Richard Eckart
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

static guint8 stats_lut[256];

static gnet_stats_t gnet_stats;

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
    n->received++;

    gnet_stats.pkg.received[MSG_TOTAL]++;
    gnet_stats.pkg.received[stats_lut[n->header.function]]++;
    gnet_stats.byte.received[MSG_TOTAL] += sizeof(n->header);
    gnet_stats.byte.received[stats_lut[n->header.function]] +=
		sizeof(n->header);
}

/*
 * gnet_stats_count_received_payload
 *
 * Called when Gnutella payload has been read.
 */
void gnet_stats_count_received_payload(gnutella_node_t *n)
{
    guint32 size = n->size;

    gnet_stats.byte.received[MSG_TOTAL] += size;
    gnet_stats.byte.received[stats_lut[n->header.function]] += size;
}

void gnet_stats_count_sent(
	gnutella_node_t *n, guint8 type, guint8 hops, guint32 size)
{
	guint32 *stats_pkg;
	guint32 *stats_byte;

	stats_pkg = hops ? gnet_stats.pkg.relayed : gnet_stats.pkg.generated;
	stats_byte = hops ? gnet_stats.byte.relayed : gnet_stats.byte.generated;

    stats_pkg[MSG_TOTAL]++;
    stats_pkg[stats_lut[type]]++;
    stats_byte[MSG_TOTAL] += size;
    stats_byte[stats_lut[type]] += size;
}

void gnet_stats_count_expired(gnutella_node_t *n)
{
    guint32 size = n->size + sizeof(n->header);

    gnet_stats.pkg.expired[MSG_TOTAL]++;
    gnet_stats.pkg.expired[stats_lut[n->header.function]]++;
    gnet_stats.byte.expired[MSG_TOTAL] += size;
    gnet_stats.byte.expired[stats_lut[n->header.function]] += size;
}

#define DROP_STATS(s) do {											\
    if (															\
        (reason == MSG_DROP_ROUTE_LOST) ||							\
        (reason == MSG_DROP_DUPLICATE) ||							\
        (reason == MSG_DROP_NO_ROUTE)								\
    )																\
        gnet_stats.general[GNR_ROUTING_ERRORS]++;					\
																	\
    gnet_stats.drop_reason[reason][MSG_TOTAL]++;					\
    gnet_stats.drop_reason[reason][stats_lut[n->header.function]]++;\
    gnet_stats.pkg.dropped[MSG_TOTAL]++;							\
    gnet_stats.pkg.dropped[stats_lut[n->header.function]]++;		\
    gnet_stats.byte.dropped[MSG_TOTAL] += (s);						\
    gnet_stats.byte.dropped[stats_lut[n->header.function]] += (s);	\
} while (0)

void gnet_stats_count_dropped(gnutella_node_t *n, msg_drop_reason_t reason)
{
    guint32 size = n->size + sizeof(n->header);

	DROP_STATS(size);
}

void gnet_stats_count_general(gnutella_node_t *n, gint type, guint32 amount)
{
    gnet_stats.general[type] += amount;
}

void gnet_stats_count_dropped_nosize(
	gnutella_node_t *n, msg_drop_reason_t reason)
{
	DROP_STATS(sizeof(n->header));
}

void gnet_stats_count_flowc(gpointer head)
{
    struct gnutella_header *h = (struct gnutella_header *) head;
	guint t;
	guint i;
	guint32 size;

	READ_GUINT32_LE(h->size, size);
//	g_message("FLOWC function=%d ttl=%d hops=%d", h->function, h->ttl, h->hops);

	switch (h->function) {
		case GTA_MSG_INIT:
			t = MSG_INIT;
			break;
		case GTA_MSG_INIT_RESPONSE:
			t = MSG_INIT_RESPONSE;
			break;
		case GTA_MSG_BYE:
			t = MSG_BYE;
			break;
		case GTA_MSG_QRP:
			t = MSG_QRP;
			break;
		case GTA_MSG_VENDOR:
			t = MSG_VENDOR;
			break;
		case GTA_MSG_STANDARD:
			t = MSG_STANDARD;
			break;
		case GTA_MSG_PUSH_REQUEST:
			t = MSG_PUSH_REQUEST;
			break;
		case GTA_MSG_SEARCH:
			t = MSG_SEARCH;
			break;
		case GTA_MSG_SEARCH_RESULTS:
			t = MSG_SEARCH_RESULTS;
			break;	

		default:
			t = MSG_UNKNOWN;
	}

	i = MIN(h->hops, STATS_FLOWC_COLUMNS);
	gnet_stats.pkg.flowc_hops[i][t]++;
	gnet_stats.pkg.flowc_hops[i][MSG_TOTAL]++;
	gnet_stats.byte.flowc_hops[i][t] += size;
	gnet_stats.byte.flowc_hops[i][MSG_TOTAL] += size;

	i = MIN(h->ttl, STATS_FLOWC_COLUMNS);
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

