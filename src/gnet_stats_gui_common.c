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
};

int msg_type_str_size()
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
		case 7: return _("Max TTL exceeded");
		case 8: return _("Ping throttle");
		case 9: return _("Unusable Pong");
		case 10: return _("Hard TTL limit reached");
		case 11: return _("Max hop count reached");
		case 12: return _("Unrequested reply");
		case 13: return _("Route lost");
		case 14: return _("No route");
		case 15: return _("Duplicate message");
		case 16: return _("Message to banned GUID");
		case 17: return _("Node shutting down");
		case 18: return _("Flow control");
		case 19: return _("Query text had no trailing NUL");
		case 20: return _("Query text too short");
		case 21: return _("Query had unnecessary overhead");
		case 22: return _("Message with malformed SHA1");
		case 23: return _("Message with malformed UTF-8");
		case 24: return _("Malformed Query Hit");
		case 25: return _("Hostile IP address");
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
		default: 
			g_warning("Requested general_type_str %d is invalid", value);
			return "";
	}
}
