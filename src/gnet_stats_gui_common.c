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

#include "gnet_stats_gui_common.h"
#include "override.h"		/* Must be the last header included */

RCSID("$Id$");

/*
 * msg_type_str
 *
 * Gets the string associated with the message type.
 */
const gchar *msg_type_str(int value)
{
	switch (value) {
		case 0: return _("Unknown");
		case 1: return _("Ping");
		case 2: return _("Pong");
		case 3: return _("Bye");
		case 4: return _("QRP");
		case 5: return _("Vendor Spec.");
		case 6: return _("Vendor Std.");
		case 7: return _("Push");
		case 8: return _("Query");
		case 9: return _("Query Hit");
		case 10: return _("Total");
		default: 
			g_warning("Requested general_type_str %d is invalid", value);
			return "";
	}
}

int msg_type_str_size(void)
{
	return MSG_TYPE_COUNT;
}

/*
 * msg_drop_str
 *
 * Gets the string associated with the drop reason.
 */
const gchar *msg_drop_str(int value)
{
	switch (value) {
		case 0: return _("Bad size");
		case 1: return _("Too small");
		case 2: return _("Too large");
		case 3: return _("Way too large");
		case 4: return _("Unknown message type");
		case 5: return _("Unexpected message");
		case 6: return _("Message sent with TTL = 0");
		case 7: return _("Improper hops/TTL combination");
		case 8: return _("Max TTL exceeded");
		case 9: return _("Message throttle");
		case 10: return _("Unusable Pong");
		case 11: return _("Hard TTL limit reached");
		case 12: return _("Max hop count reached");
		case 13: return _("Unrequested reply");
		case 14: return _("Route lost");
		case 15: return _("No route");
		case 16: return _("Duplicate message");
		case 17: return _("Message to banned GUID");
		case 18: return _("Node shutting down");
		case 19: return _("Flow control");
		case 20: return _("Query text had no trailing NUL");
		case 21: return _("Query text too short");
		case 22: return _("Query had unnecessary overhead");
		case 23: return _("Message with malformed SHA1");
		case 24: return _("Message with malformed UTF-8");
		case 25: return _("Malformed Query Hit");
		case 26: return _("Hostile IP address");
		default: 
			g_warning("Requested general_type_str %d is invalid", value);
			return "";
	}
}

/*
 * general_type_str
 *
 * Gets the string associated with the general message
 */
const gchar *general_type_str(int value)
{
	switch (value) {
		case 0: return _("Routing errors");
		case 1: return _("Searches to local DB");
		case 2: return _("Hits on local DB");
		case 3: return _("Compacted queries");
		case 4: return _("Bytes saved by compacting");
		case 5: return _("UTF8 queries");
		case 6: return _("SHA1 queries");
		case 7: return _("Broadcasted push messages");
		case 8: return _("Push proxy relayed messages");
		case 9: return _("Push proxy broadcasted messages");
		case 10: return _("Push proxy lookup failures");
		default: 
			g_warning("Requested general_type_str %d is invalid", value);
			return "";
	}
}

/*
 * horizon_stat_str
 *
 * Returns the cell contents for the horizon stats table.
 * NB: The static buffers for each column are disjunct.
 */
const gchar *horizon_stat_str(hsep_triple *table, gint row,
	c_horizon_t column)
{
    switch (column) {
    case c_horizon_hops:
		{
    		static gchar buf[21];

			gm_snprintf(buf, sizeof(buf), "%u", row);
           	return buf;
		}
    case c_horizon_nodes:
		{
    		static gchar buf[21];

			gm_snprintf(buf, sizeof(buf), "%llu", table[row][HSEP_IDX_NODES]);
           	return buf;
		}
    case c_horizon_files:
		{
    		static gchar buf[21];

			gm_snprintf(buf, sizeof(buf), "%llu", table[row][HSEP_IDX_FILES]);
           	return buf;
		}
    case c_horizon_size:
		{
   			static gchar buf[21];

			/* Make a copy because concurrent usage of short_kb_size64()
		 	 * could be hard to discover. */
			g_strlcpy(buf, short_kb_size64(table[row][HSEP_IDX_KIB]),
				sizeof buf);
			return buf;
		}
    case num_c_horizon:
		g_assert_not_reached();
    }

    return NULL;
}

/* vi: set ts=4: */
