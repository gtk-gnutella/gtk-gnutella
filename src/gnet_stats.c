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

static guint32 stats_recv[MSG_TYPE_COUNT];
static guint32 stats_sent[MSG_TYPE_COUNT];
static guint32 stats_expd[MSG_TYPE_COUNT];
static guint32 stats_drop[MSG_TYPE_COUNT];

static guint32 stats_drop_reason[MSG_DROP_REASON_COUNT];

static guint32 routing_errors = 0;
static guint32 local_searches = 0;

static guint32 msg_recv_total = 0;
static guint32 msg_sent_total = 0;
static guint32 msg_expired_total = 0;
static guint32 msg_dropped_total = 0;

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

    memset(stats_recv, 0, sizeof(guint32)*sizeof(stats_recv));
    memset(stats_sent, 0, sizeof(guint32)*sizeof(stats_sent));
    memset(stats_expd, 0, sizeof(guint32)*sizeof(stats_expd));
    memset(stats_drop, 0, sizeof(guint32)*sizeof(stats_drop));
    memset(stats_drop_reason, 0, sizeof(guint32)*sizeof(stats_drop_reason));

}

void gnet_stats_count_recieved(gnutella_node_t *n)
{
    n->received++;
    msg_recv_total++;

    stats_recv[stats_lut[n->header.function]]++;
}

void gnet_stats_count_sent(gnutella_node_t *n)
{
    msg_sent_total++;

    stats_sent[stats_lut[n->header.function]]++;
}

void gnet_stats_count_expired(gnutella_node_t *n)
{
    msg_expired_total++;

    stats_expd[stats_lut[n->header.function]]++;
}

void gnet_stats_count_dropped(gnutella_node_t *n, msg_drop_reason_t reason)
{
    msg_dropped_total++;

    if (
        (reason == MSG_DROP_ROUTE_LOST) ||
        (reason == MSG_DROP_DUPLICATE) ||
        (reason == MSG_DROP_NO_ROUTE)
    )
        routing_errors ++;

    stats_drop_reason[reason]++;
    stats_drop[stats_lut[n->header.function]]++;
}

void gnet_stats_count_local_search(gnutella_node_t *n)
{
    local_searches++;
}

/***
 *** Public functions (gnet.h)
 ***/

void gnet_stats_get(gnet_stats_t *s)
{
    g_assert(s != NULL);

    memcpy(s->recieved, stats_recv, sizeof(guint32)*MSG_TYPE_COUNT);
    memcpy(s->sent, stats_sent, sizeof(guint32)*MSG_TYPE_COUNT);
    memcpy(s->expired, stats_expd, sizeof(guint32)*MSG_TYPE_COUNT);
    memcpy(s->dropped, stats_drop, sizeof(guint32)*MSG_TYPE_COUNT);

    memcpy(s->drop_reason, stats_drop_reason, 
        sizeof(guint32)*MSG_DROP_REASON_COUNT);

    s->dropped_total  = msg_dropped_total;
    s->sent_total     = msg_sent_total;
    s->recieved_total = msg_recv_total;
    s->expired_total  = msg_expired_total;

    s->routing_errors = routing_errors;
    s->local_searches = local_searches;
}
