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

#include "config.h"

#include "gnet.h"		/* XXX for MSG_TYPE_COUNT et al. */
#include "gnet_stats_gui_common.h"

RCSID("$Id$");

const gchar *msg_type_str[MSG_TYPE_COUNT] = {
    "Unknown",
    "Ping",
    "Pong",
    "Bye",
    "QRP",
    "Vendor Spec.",
    "Vendor Std.",
    "Push",
    "Query",
    "Query Hit",
    "Total"
};

const gchar *msg_drop_str[MSG_DROP_REASON_COUNT] = {
    "Bad size",
    "Too small",
    "Too large",
	"Way too large",
    "Unknown message type",
    "Unexpected message",
    "Message sent with TTL = 0",
    "Max TTL exceeded",
    "Ping throttle",
	"Unusable Pong",
    "Hard TTL limit reached",
    "Max hop count reached",
    "Unrequested reply",
    "Route lost",
    "No route",
    "Duplicate message",
    "Message to banned GUID",
    "Node shutting down",
    "Flow control",
    "Query text had no trailing NUL",
    "Query text too short",
    "Query had unnecessary overhead",
    "Message with malformed SHA1",
    "Message with malformed UTF-8",
    "Malformed Query Hit",
	"Hostile IP address",
};

const gchar *general_type_str[GNR_TYPE_COUNT] = {
    "Routing errors",
    "Searches to local DB",
    "Hits on local DB",
    "Compacted queries",
    "Bytes saved by compacting",
    "UTF8 queries",
    "SHA1 queries",
    "Broadcasted push messages",
};

