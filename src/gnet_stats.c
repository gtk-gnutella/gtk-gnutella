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

static guint32 stats_pkg_recv[MSG_TYPE_COUNT];
static guint32 stats_pkg_sent[MSG_TYPE_COUNT];
static guint32 stats_pkg_expd[MSG_TYPE_COUNT];
static guint32 stats_pkg_drop[MSG_TYPE_COUNT];

static guint32 stats_byte_recv[MSG_TYPE_COUNT];
static guint32 stats_byte_sent[MSG_TYPE_COUNT];
static guint32 stats_byte_expd[MSG_TYPE_COUNT];
static guint32 stats_byte_drop[MSG_TYPE_COUNT];

static guint32 stats_drop_reason[MSG_DROP_REASON_COUNT][MSG_TYPE_COUNT];

static guint32 routing_errors = 0;
static guint32 local_searches = 0;
static guint32 local_hits = 0;

/***
 *** Public functions
 ***/

void gnet_stats_init(void)
{
    memset(stats_lut, MSG_UNKNOWN, sizeof(guint8)*sizeof(stats_lut));
    stats_lut[GTA_MSG_INIT] = MSG_INIT;
    stats_lut[GTA_MSG_INIT_RESPONSE]= MSG_INIT_RESPONSE;
    stats_lut[GTA_MSG_BYE] = MSG_BYE;
    stats_lut[GTA_MSG_QRP] = MSG_QRP;
    stats_lut[GTA_MSG_VENDOR] = MSG_VENDOR;
    stats_lut[GTA_MSG_STANDARD] = MSG_STANDARD;
    stats_lut[GTA_MSG_PUSH_REQUEST] = MSG_PUSH_REQUEST;
    stats_lut[GTA_MSG_SEARCH] = MSG_SEARCH;
    stats_lut[GTA_MSG_SEARCH_RESULTS] = MSG_SEARCH_RESULTS;

    memset(stats_pkg_recv, 0, sizeof(guint32)*sizeof(stats_pkg_recv));
    memset(stats_pkg_sent, 0, sizeof(guint32)*sizeof(stats_pkg_sent));
    memset(stats_pkg_expd, 0, sizeof(guint32)*sizeof(stats_pkg_expd));
    memset(stats_pkg_drop, 0, sizeof(guint32)*sizeof(stats_pkg_drop));

    memset(stats_byte_recv, 0, sizeof(guint32)*sizeof(stats_byte_recv));
    memset(stats_byte_sent, 0, sizeof(guint32)*sizeof(stats_byte_sent));
    memset(stats_byte_expd, 0, sizeof(guint32)*sizeof(stats_byte_expd));
    memset(stats_byte_drop, 0, sizeof(guint32)*sizeof(stats_byte_drop));

    memset(stats_drop_reason, 0, 
        sizeof(guint32)*MSG_DROP_REASON_COUNT*MSG_TYPE_COUNT);

}

void gnet_stats_count_received(gnutella_node_t *n)
{
    guint32 size;

    n->received++;
    READ_GUINT32_LE(n->header.size, size);
    size += sizeof(n->header);

    stats_pkg_recv[MSG_TOTAL]++;
    stats_pkg_recv[stats_lut[n->header.function]]++;
    stats_byte_recv[MSG_TOTAL] += size;
    stats_byte_recv[stats_lut[n->header.function]] += size;
}

void gnet_stats_count_sent(gnutella_node_t *n)
{
    guint32 size;

    READ_GUINT32_LE(n->header.size, size);
    size += sizeof(n->header);

    stats_pkg_sent[MSG_TOTAL]++;
    stats_pkg_sent[stats_lut[n->header.function]]++;
    stats_byte_sent[MSG_TOTAL] += size;
    stats_byte_sent[stats_lut[n->header.function]] += size;
}

void gnet_stats_count_sent_ext(gnutella_node_t *n, guint8 type, guint32 size)
{
	guint32 msgsize;

    msgsize = size + sizeof(n->header);	/* Parameter is payload size only */

    stats_pkg_sent[MSG_TOTAL]++;
    stats_pkg_sent[stats_lut[type]]++;
    stats_byte_sent[MSG_TOTAL] += msgsize;
    stats_byte_sent[stats_lut[n->header.function]] += msgsize;
}

void gnet_stats_count_expired(gnutella_node_t *n)
{
    guint32 size;

    READ_GUINT32_LE(n->header.size, size);
    size += sizeof(n->header);

    stats_pkg_expd[MSG_TOTAL]++;
    stats_pkg_expd[stats_lut[n->header.function]]++;
    stats_byte_expd[MSG_TOTAL] += size;
    stats_byte_expd[stats_lut[n->header.function]] += size;
}

void gnet_stats_count_dropped(gnutella_node_t *n, msg_drop_reason_t reason)
{
    guint32 size;

    READ_GUINT32_LE(n->header.size, size);
    size += sizeof(n->header);

    if (
        (reason == MSG_DROP_ROUTE_LOST) ||
        (reason == MSG_DROP_DUPLICATE) ||
        (reason == MSG_DROP_NO_ROUTE)
    )
        routing_errors ++;

    stats_drop_reason[reason][MSG_TOTAL]++;
    stats_drop_reason[reason][stats_lut[n->header.function]]++;
    stats_pkg_drop[MSG_TOTAL]++;
    stats_pkg_drop[stats_lut[n->header.function]]++;
    stats_byte_drop[MSG_TOTAL] += size;
    stats_byte_drop[stats_lut[n->header.function]] += size;
}

void gnet_stats_count_local_search(gnutella_node_t *n)
{
    local_searches++;
}

void gnet_stats_count_local_hit(gnutella_node_t *n, guint32 hits)
{
    local_hits += hits;
}

/***
 *** Public functions (gnet.h)
 ***/

void gnet_stats_get(gnet_stats_t *s)
{
    g_assert(s != NULL);

    memcpy(s->pkg.recieved, stats_pkg_recv, sizeof(guint32)*MSG_TYPE_COUNT);
    memcpy(s->pkg.sent, stats_pkg_sent, sizeof(guint32)*MSG_TYPE_COUNT);
    memcpy(s->pkg.expired, stats_pkg_expd, sizeof(guint32)*MSG_TYPE_COUNT);
    memcpy(s->pkg.dropped, stats_pkg_drop, sizeof(guint32)*MSG_TYPE_COUNT);

    memcpy(s->byte.recieved, stats_byte_recv, sizeof(guint32)*MSG_TYPE_COUNT);
    memcpy(s->byte.sent, stats_byte_sent, sizeof(guint32)*MSG_TYPE_COUNT);
    memcpy(s->byte.expired, stats_byte_expd, sizeof(guint32)*MSG_TYPE_COUNT);
    memcpy(s->byte.dropped, stats_byte_drop, sizeof(guint32)*MSG_TYPE_COUNT);

    memcpy(s->drop_reason, stats_drop_reason, 
        sizeof(guint32)*MSG_DROP_REASON_COUNT*MSG_TYPE_COUNT);

    s->routing_errors = routing_errors;
    s->local_searches = local_searches;
    s->local_hits     = local_hits;
}
