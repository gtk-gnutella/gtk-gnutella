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
#include "nodes.h"
#include "override.h"		/* Must be the last header included */

RCSID("$Id$");

/*
 * msg_type_str
 *
 * Gets the string associated with the message type.
 */
const gchar *msg_type_str(int value)
{
	static const char * const strs[] = {
		N_("Unknown"),
		N_("Ping"),
		N_("Pong"),
		N_("Bye"),
		N_("QRP"),
		N_("Vendor Spec."),
		N_("Vendor Std."),
		N_("Push"),
		N_("Query"),
		N_("Query Hit"),
		N_("Total"),
	};

	if ((guint) value >= G_N_ELEMENTS(strs)) {
		g_warning("Requested general_type_str %d is invalid", value);
		return "";
	}

	return _(strs[value]);
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
	static const char * const strs[] = {
		N_("Bad size"),
		N_("Too small"),
		N_("Too large"),
		N_("Way too large"),
		N_("Unknown message type"),
		N_("Unexpected message"),
		N_("Message sent with TTL = 0"),
		N_("Improper hops/TTL combination"),
		N_("Max TTL exceeded"),
		N_("Message throttle"),
		N_("Unusable Pong"),
		N_("Hard TTL limit reached"),
		N_("Max hop count reached"),
		N_("Route lost"),
		N_("No route"),
		N_("Duplicate message"),
		N_("Message to banned GUID"),
		N_("Node shutting down"),
		N_("Flow control"),
		N_("Query text had no trailing NUL"),
		N_("Query text too short"),
		N_("Query had unnecessary overhead"),
		N_("Message with malformed SHA1"),
		N_("Message with malformed UTF-8"),
		N_("Malformed Query Hit"),
		N_("Hostile IP address"),
	};
	
	if ((guint) value >= G_N_ELEMENTS(strs)) {
		g_warning("Requested general_type_str %d is invalid", value);
		return "";
	}

	return _(strs[value]);
}

/*
 * general_type_str
 *
 * Gets the string associated with the general message
 */
const gchar *general_type_str(int value)
{
	static const char * const strs[] = {
		N_("Routing errors"),
		N_("Searches to local DB"),
		N_("Hits on local DB"),
		N_("Compacted queries"),
		N_("Bytes saved by compacting"),
		N_("UTF8 queries"),
		N_("SHA1 queries"),
		N_("Broadcasted push messages"),
		N_("Push proxy relayed messages"),
		N_("Push proxy broadcasted messages"),
		N_("Push proxy lookup failures"),
		N_("Locally generated dynamic queries"),
		N_("Leaf-generated dynamic queries"),
		N_("Fully completed dynamic queries"),
		N_("Partially completed dynamic queries"),
		N_("Dynamic queries ended with no results"),
		N_("Fully completed dynamic queries getting late results"),
		N_("Dynamic queries with partial late results"),
		N_("Dynamic queries completed by late results"),
	};
	
	if ((guint) value >= G_N_ELEMENTS(strs)) {
		g_warning("Requested general_type_str %d is invalid", value);
		return "";
	}

	return _(strs[value]);
}

/*
 * horizon_stat_str
 *
 * Returns the cell contents for the horizon stats table.
 * NB: The static buffers for each column are disjunct.
 */
const gchar *horizon_stat_str(hsep_triple *table, hsep_triple *other, gint row,
	c_horizon_t column)
{
    switch (column) {
    case c_horizon_hops:
		{
    		static gchar buf[21];

			gm_snprintf(buf, sizeof(buf), "%d", row);
           	return buf;
		}
    case c_horizon_nodes:
		{
    		static gchar buf[21];

			gm_snprintf(buf, sizeof(buf), "%" PRIu64,
			    table[row][HSEP_IDX_NODES] + other[0][HSEP_IDX_NODES]);
           	return buf;
		}
    case c_horizon_files:
		{
    		static gchar buf[21];

			gm_snprintf(buf, sizeof(buf), "%" PRIu64,
			    table[row][HSEP_IDX_FILES] + other[0][HSEP_IDX_FILES]);
           	return buf;
		}
    case c_horizon_size:
		{
   			static gchar buf[21];

			/* Make a copy because concurrent usage of short_kb_size64()
		 	 * could be hard to discover. */
			g_strlcpy(buf, short_kb_size64(table[row][HSEP_IDX_KIB] +
			    other[0][HSEP_IDX_KIB]), sizeof buf);
			return buf;
		}
    case num_c_horizon:
		g_assert_not_reached();
    }

    return NULL;
}

/*
 * gnet_stats_gui_horizon_update
 *
 * Updates the horizon statistics in the statusbar.
 * This is an event-driven callback called from the HSEP code
 * using the event listener framework. In addition to taking into account
 * the HSEP information, the number of established non-HSEP nodes and
 * their library size (if provided) are added to the values displayed.
 */

void gnet_stats_gui_horizon_update(hsep_triple *table, guint32 triples)
{
	const guint32 hops = 4U;      /* must be <= HSEP_N_MAX */
	gchar s[64];
	guint64 val;
	hsep_triple other;

	if (triples <= hops)     /* should not happen */
	    return;
	g_assert((gint32) triples > 0);

	hsep_get_non_hsep_triple(&other);

	/*
	 * Update the 3 labels in the statusbar with the horizon values for a
	 * distance of 'hops' hops.
	 */

	val = table[hops][HSEP_IDX_NODES] + other[HSEP_IDX_NODES];
	gm_snprintf(s, sizeof(s),
	            "%" PRIu64 " %s", val, val == 1 ? _("node") : _("nodes"));
	gtk_label_set_text(GTK_LABEL(lookup_widget(main_window,
	                   "label_statusbar_horizon_node_count")), s);

	val = table[hops][HSEP_IDX_FILES] + other[HSEP_IDX_FILES];
	gm_snprintf(s, sizeof(s), "%" PRIu64 " %s",
	            val, val == 1 ? _("file") : _("files"));
	gtk_label_set_text(GTK_LABEL(lookup_widget(main_window,
	                   "label_statusbar_horizon_file_count")), s);

	val = table[hops][HSEP_IDX_KIB] + other[HSEP_IDX_KIB];
	gm_snprintf(s, sizeof(s), "%s", short_kb_size64(val));
	gtk_label_set_text(GTK_LABEL(lookup_widget(main_window,
	                   "label_statusbar_horizon_kb_count")), s);
}

/* vi: set ts=4 sw=4 cindent: */
