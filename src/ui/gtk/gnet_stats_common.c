/*
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

#include "gui.h"

#include "gtk/notebooks.h"

#include "gnet_stats_common.h"
#include "settings.h"

#include "if/core/net_stats.h"
#include "if/bridge/ui2c.h"

#include "lib/str.h"
#include "lib/stringify.h"

#include "lib/override.h"		/* Must be the last header included */

/**
 * Gets the string associated with the message type.
 */
const gchar *
msg_type_str(gint value)
{
	g_return_val_if_fail(UNSIGNED(value) < MSG_TYPE_COUNT, "");
	return _(guc_gnet_msg_type_description(value));
}

gint
msg_type_str_size(void)
{
	return MSG_TYPE_COUNT;
}

/**
 * Gets the string associated with the drop reason.
 */
const gchar *
msg_drop_str(gint value)
{
	g_return_val_if_fail(UNSIGNED(value) < MSG_DROP_REASON_COUNT, "");
	return _(guc_gnet_stats_drop_reason_to_string(value));
}

/**
 * Gets the string associated with the general statistic.
 */
const gchar *
general_type_str(gint value)
{
	g_return_val_if_fail(UNSIGNED(value) < GNR_TYPE_COUNT, "");
	return _(guc_gnet_stats_general_description(value));
}

/**
 * @returns the cell contents for the horizon stats table.
 *
 * @warning
 * NB: The static buffers for each column are disjunct.
 */
const gchar *
horizon_stat_str(gint row, c_horizon_t column)
{
    switch (column) {
    case c_horizon_hops:
		{
    		static gchar buf[UINT64_DEC_BUFLEN];

			str_bprintf(ARYLEN(buf), "%d", row);
           	return buf;
		}
    case c_horizon_nodes:
		{
           	return guc_hsep_get_static_str(row, HSEP_IDX_NODES);
		}
    case c_horizon_files:
		{
           	return guc_hsep_get_static_str(row, HSEP_IDX_FILES);
		}
    case c_horizon_size:
		{
           	return guc_hsep_get_static_str(row, HSEP_IDX_KIB);
		}
    case num_c_horizon:
		g_assert_not_reached();
    }

    return NULL;
}

/**
 * Updates the horizon statistics in the statusbar.
 *
 * This is an event-driven callback called from the HSEP code
 * using the event listener framework. In addition to taking into account
 * the HSEP information, the number of established non-HSEP nodes and
 * their library size (if provided) are added to the values displayed.
 */
void
gnet_stats_gui_horizon_update(hsep_triple *table, guint32 triples)
{
	const guint32 hops = 4U;      /* must be <= HSEP_N_MAX */
	guint64 val;
	hsep_triple other;

	if (triples <= hops)     /* should not happen */
	    return;
	g_assert((gint32) triples > 0);

	guc_hsep_get_non_hsep_triple(&other);

	/*
	 * Update the 3 labels in the statusbar with the horizon values for a
	 * distance of 'hops' hops.
	 */

	val = table[hops][HSEP_IDX_NODES] + other[HSEP_IDX_NODES];
	gtk_label_printf(GTK_LABEL(
			gui_main_window_lookup("label_statusbar_horizon_node_count")),
		"%s %s", uint64_to_string(val), NG_("node", "nodes", val));

	val = table[hops][HSEP_IDX_FILES] + other[HSEP_IDX_FILES];
	gtk_label_printf(GTK_LABEL(
			gui_main_window_lookup("label_statusbar_horizon_file_count")),
		"%s %s", uint64_to_string(val), NG_("file", "files", val));

	val = table[hops][HSEP_IDX_KIB] + other[HSEP_IDX_KIB];
	gtk_label_printf(GTK_LABEL(
			gui_main_window_lookup("label_statusbar_horizon_kb_count")),
		"%s", short_kb_size(val, show_metric_units()));
}

/**
 * Stringify value of the general stats to buffer.
 *
 * @param dst		destination buffer
 * @param size		length of destination buffer
 * @param stats		the statistics array
 * @param idx		the index within the general statistics of value to format
 */
void
gnet_stats_gui_general_to_string_buf(char *dst, size_t size,
	const gnet_stats_t *stats, int idx)
{
	const uint64 value = stats->general[idx];

	if (0 == value)
		g_strlcpy(dst, "-", size);
	else {
		switch (idx) {
		case GNR_QUERY_COMPACT_SIZE:
		case GNR_IGNORED_DATA:
		case GNR_SUNK_DATA:
		case GNR_UDP_READ_AHEAD_BYTES_SUM:
		case GNR_UDP_READ_AHEAD_BYTES_MAX:
		case GNR_RUDP_TX_BYTES:
		case GNR_RUDP_RX_BYTES:
			g_strlcpy(dst, compact_size(value, show_metric_units()), size);
			break;
		case GNR_UDP_READ_AHEAD_DELAY_MAX:
			g_strlcpy(dst, compact_time(value), size);
			break;
		default:
			uint64_to_string_buf(value, dst, size);
		}
	}
}

static gboolean
gnet_stats_gui_is_visible(void)
{
	return main_gui_window_visible() &&
		nb_main_page_stats == main_gui_notebook_get_page();
}

void
gnet_stats_gui_timer(time_t now)
{
	static time_t last_update;

	if (last_update != now && gnet_stats_gui_is_visible()) {
		last_update = now;
		gnet_stats_gui_update_display(now);
	}
}

/* vi: set ts=4 sw=4 cindent: */
