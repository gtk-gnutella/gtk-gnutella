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

#include "common.h"

RCSID("$Id$")

#include "gtk/gui.h"
#include "gtk/gnet_stats.h"
#include "gtk/notebooks.h"
#include "gtk/settings.h"

#include "if/core/hsep.h"
#include "if/core/gnutella.h"
#include "if/gui_property.h"
#include "if/gui_property_priv.h"
#include "if/bridge/ui2c.h"

#include "lib/glib-missing.h"
#include "lib/tm.h"
#include "lib/override.h"		/* Must be the last header included */

/***
 *** Callbacks
 ***/
void
on_clist_gnet_stats_msg_resize_column(GtkCList *unused_clist, gint column,
	gint width, gpointer unused_udata)
{
    static gboolean lock = FALSE;
    guint32 buf = width;

	(void) unused_clist;
	(void) unused_udata;

    if (lock)
        return;

    lock = TRUE;

    /* remember the width for storing it to the config file later */
    gui_prop_set_guint32(PROP_GNET_STATS_MSG_COL_WIDTHS, &buf, column, 1);

    lock = FALSE;
}


void
on_clist_gnet_stats_fc_ttl_resize_column(GtkCList *unused_clist,
	gint unused_column, gint width, gpointer unused_udata)
{
    static gboolean lock = FALSE;
    guint32 buf[9];
    guint n;

	(void) unused_clist;
	(void) unused_column;
	(void) unused_udata;

    if (lock)
        return;

    lock = TRUE;

    /* remember the width for storing it to the config file later */
    for (n = 0; n < G_N_ELEMENTS(buf); n ++)
        buf[n] = width;

    gui_prop_set_guint32(PROP_GNET_STATS_FC_TTL_COL_WIDTHS,
		buf, 1, G_N_ELEMENTS(buf));

    lock = FALSE;
}

void
on_clist_gnet_stats_fc_hops_resize_column(GtkCList *unused_clist,
	gint unused_column, gint width, gpointer unused_udata)
{
    static gboolean lock = FALSE;
    guint32 buf[9];
    guint n;

	(void) unused_clist;
	(void) unused_column;
	(void) unused_udata;

    if (lock)
        return;

    lock = TRUE;

    /* remember the width for storing it to the config file later */
    for (n = 0; n < G_N_ELEMENTS(buf); n ++)
        buf[n] = width;

    gui_prop_set_guint32(PROP_GNET_STATS_FC_HOPS_COL_WIDTHS,
		buf, 1, G_N_ELEMENTS(buf));

    lock = FALSE;
}

void
on_clist_gnet_stats_horizon_resize_column(GtkCList *unused_clist,
	gint column, gint width, gpointer unused_udata)
{
    static gboolean lock = FALSE;
    guint32 buf = width;

	(void) unused_clist;
	(void) unused_udata;

    if (lock)
        return;

    lock = TRUE;

    /* remember the width for storing it to the config file later */
    gui_prop_set_guint32(PROP_GNET_STATS_HORIZON_COL_WIDTHS, &buf, column, 1);

    lock = FALSE;
}

void
on_clist_gnet_stats_drop_reasons_resize_column(GtkCList *unused_clist,
	gint column, gint width, gpointer unused_udata)
{
    guint32 buf = width;

	(void) unused_clist;
	(void) unused_udata;

    /* remember the width for storing it to the config file later */
    gui_prop_set_guint32(PROP_GNET_STATS_DROP_REASONS_COL_WIDTHS,
        &buf, column, 1);
}

void
on_clist_gnet_stats_general_resize_column(GtkCList *unused_clist, gint column,
	gint width, gpointer unused_udata)
{
    guint32 buf = width;

	(void) unused_clist;
	(void) unused_udata;

    /* remember the width for storing it to the config file later */
    gui_prop_set_guint32(PROP_GNET_STATS_GENERAL_COL_WIDTHS,
        &buf, column, 1);
}

/***
 *** Private functions
 ***/

const gchar *
pkt_stat_str(const guint64 *val_tbl, gint type)
{
    static gchar strbuf[UINT64_DEC_BUFLEN];

    if (val_tbl[type] == 0)
        return GUI_PROPERTY(gnet_stats_perc) ? "-  " : "-";

    if (GUI_PROPERTY(gnet_stats_perc))
        gm_snprintf(strbuf, sizeof strbuf, "%.2f%%",
            (gfloat) val_tbl[type] / val_tbl[MSG_TOTAL] * 100.0);
    else
        uint64_to_string_buf(val_tbl[type], strbuf, sizeof strbuf);

    return strbuf;
}


const gchar *
byte_stat_str(const guint64 *val_tbl, const guint64 *nb_packets, gint type)
{
    static gchar strbuf[UINT64_DEC_BUFLEN];
	guint64 size = val_tbl[type];

    if (val_tbl[type] == 0)
        return GUI_PROPERTY(gnet_stats_perc) ? "-  " : "-";

	if (!GUI_PROPERTY(gnet_stats_with_headers))
		size -= nb_packets[type] * GTA_HEADER_SIZE;

    if (GUI_PROPERTY(gnet_stats_perc)) {
		guint64 total_size = val_tbl[MSG_TOTAL];
		if (!GUI_PROPERTY(gnet_stats_with_headers))
			size -= nb_packets[MSG_TOTAL] * GTA_HEADER_SIZE;
        gm_snprintf(strbuf, sizeof strbuf, "%.2f%%",
            (gfloat) size / total_size * 100.0);
        return strbuf;
    } else
        return compact_size(size, show_metric_units());
}

const gchar *
drop_stat_str(const gnet_stats_t *stats, gint reason)
{
    static gchar strbuf[UINT64_DEC_BUFLEN];
    guint32 total = stats->pkg.dropped[MSG_TOTAL];
	guint i = GUI_PROPERTY(gnet_stats_drop_reasons_type);

    if (stats->drop_reason[reason][i] == 0)
        return GUI_PROPERTY(gnet_stats_perc) ? "-  " : "-";

    if (GUI_PROPERTY(gnet_stats_perc))
        gm_snprintf(strbuf, sizeof strbuf, "%.2f%%",
            (gfloat) stats->drop_reason[reason][i] / total * 100);
    else
        uint64_to_string_buf(stats->drop_reason[reason][i],
			strbuf, sizeof strbuf);

    return strbuf;
}

const gchar *
general_stat_str(const gnet_stats_t *stats, gint type)
{
    static gchar strbuf[UINT64_DEC_BUFLEN];

    if (stats->general[type] == 0)
        return "-";

    if (type == GNR_QUERY_COMPACT_SIZE) {
        return compact_size(stats->general[type], show_metric_units());
    } else {
        uint64_to_string_buf(stats->general[type], strbuf, sizeof strbuf);
        return strbuf;
    }
}

const gchar *
flowc_stat_str_pkg(const guint64 *val_tbl, gint type)
{
    static gchar strbuf[UINT64_DEC_BUFLEN];

    if (val_tbl[type] == 0)
        return GUI_PROPERTY(gnet_stats_perc) ? "-  " : "-";

	if (GUI_PROPERTY(gnet_stats_perc)) {
		gm_snprintf(strbuf, sizeof strbuf, "%.2f%%",
            (gfloat) val_tbl[type] / val_tbl[MSG_TOTAL] * 100.0);
    } else {
       	uint64_to_string_buf(val_tbl[type], strbuf, sizeof strbuf);
    }

    return strbuf;
}

const gchar *
flowc_stat_str_byte(const guint64 *val_tbl, gint type)
{
    static gchar strbuf[UINT64_DEC_BUFLEN];

    if (val_tbl[type] == 0)
        return GUI_PROPERTY(gnet_stats_perc) ? "-  " : "-";

	if (GUI_PROPERTY(gnet_stats_perc)) {
		gm_snprintf(strbuf, sizeof strbuf, "%.2f%%",
            (gfloat) val_tbl[type] / val_tbl[MSG_TOTAL] * 100.0);
    } else {
       	return compact_size(val_tbl[type], show_metric_units());
    }

    return strbuf;
}

/***
 *** Public functions
 ***/

void
gnet_stats_gui_init(void)
{
    GtkCList *clist_stats_msg;
    GtkCList *clist_stats_fc_ttl;
    GtkCList *clist_stats_fc_hops;
    GtkCList *clist_general;
    GtkCList *clist_reason;
    GtkCList *clist_horizon;
    gchar *titles[10];
    guint n;

    for (n = 0; n < G_N_ELEMENTS(titles); n ++)
        titles[n] = "-";

    clist_stats_msg = GTK_CLIST(
        gui_main_window_lookup("clist_gnet_stats_msg"));
    clist_stats_fc_ttl = GTK_CLIST(
        gui_main_window_lookup("clist_gnet_stats_fc_ttl"));
    clist_stats_fc_hops = GTK_CLIST(
        gui_main_window_lookup("clist_gnet_stats_fc_hops"));
    clist_reason = GTK_CLIST(
        gui_main_window_lookup("clist_gnet_stats_drop_reasons"));
    clist_general = GTK_CLIST(
        gui_main_window_lookup("clist_gnet_stats_general"));
    clist_horizon = GTK_CLIST(
        gui_main_window_lookup("clist_gnet_stats_horizon"));

    /*
     * Set column justification for numeric columns to GTK_JUSTIFY_RIGHT.
     */
    gtk_clist_set_column_justification(
        clist_general, 1, GTK_JUSTIFY_RIGHT);
    gtk_clist_set_column_justification(
        clist_reason, 1, GTK_JUSTIFY_RIGHT);

    for (n = 0; n < 4; n ++) {
        gtk_clist_set_column_justification(
            clist_horizon, n, GTK_JUSTIFY_RIGHT);
    }

    for (n = 1; n < num_c_gs; n ++) {
        gtk_clist_set_column_justification(
            clist_stats_msg, n, GTK_JUSTIFY_RIGHT);
    }

    for (n = 1; n < 10; n ++) {
        gtk_clist_set_column_justification(
            clist_stats_fc_ttl, n, GTK_JUSTIFY_RIGHT);
        gtk_clist_set_column_justification(
            clist_stats_fc_hops, n, GTK_JUSTIFY_RIGHT);
    }


    /*
     * Stats can't be sorted: make column headers insensitive.
     */
	gtk_clist_column_titles_passive(clist_stats_msg);
	gtk_clist_column_titles_passive(clist_stats_fc_ttl);
	gtk_clist_column_titles_passive(clist_stats_fc_hops);
	gtk_clist_column_titles_passive(clist_reason);
	gtk_clist_column_titles_passive(clist_general);
	gtk_clist_column_titles_passive(clist_horizon);

    /*
     * Initialize stats tables.
     */
    for (n = 0; n < MSG_TYPE_COUNT; n ++) {
        gint row;

        titles[0] = (gchar *) msg_type_str(n);

        row = gtk_clist_append(clist_stats_msg, titles);
        gtk_clist_set_selectable(clist_stats_msg, row, FALSE);
        row = gtk_clist_append(clist_stats_fc_ttl, titles);
        gtk_clist_set_selectable(clist_stats_fc_ttl, row, FALSE);
        row = gtk_clist_append(clist_stats_fc_hops, titles);
        gtk_clist_set_selectable(clist_stats_fc_hops, row, FALSE);
    }

    for (n = 0; n < MSG_DROP_REASON_COUNT; n ++) {
        gint row;
        titles[0] = (gchar *) msg_drop_str(n);
        row = gtk_clist_append(clist_reason, titles);
        gtk_clist_set_selectable(clist_reason, row, FALSE);
    }

    for (n = 0; n < GNR_TYPE_COUNT; n ++) {
        gint row;
        titles[0] = (gchar *) general_type_str(n);
        row = gtk_clist_append(clist_general, titles);
        gtk_clist_set_selectable(clist_general, row, FALSE);
    }

    for (n = 0; n < HSEP_N_MAX; n ++) {
        gint row;
        titles[0] = (gchar *) horizon_stat_str(n + 1, 0);
        row = gtk_clist_append(clist_horizon, titles);
        gtk_clist_set_selectable(clist_horizon, row, FALSE);
    }

    guc_hsep_add_global_table_listener(
		(GCallback) gnet_stats_gui_horizon_update, FREQ_UPDATES, 0);
}

void
gnet_stats_gui_shutdown(void)
{
	guc_hsep_remove_global_table_listener(
	    (GCallback) gnet_stats_gui_horizon_update);
}

void
gnet_stats_gui_update(time_t now)
{
	static time_t last_update = 0;
    GtkCList *clist_stats_msg;
    GtkCList *clist_reason;
    GtkCList *clist_general;
    GtkCList *clist_horizon;
    GtkCList *clist_stats_fc_ttl;
    GtkCList *clist_stats_fc_hops;
    gint n;
    gnet_stats_t stats;
    gnet_stats_t mstats;
	static time_t last_horizon_update = 0;
	gint global_table_size;
	gnet_stats_t *xstats = NULL;

    gint current_page;

	if (last_update == now)
		return;
	last_update = now;
    current_page = gtk_notebook_get_current_page(
        GTK_NOTEBOOK(gui_main_window_lookup("notebook_main")));

    if (current_page != nb_main_page_gnet_stats)
        return;

    guc_gnet_stats_get(&stats);

    clist_stats_msg = GTK_CLIST(
        gui_main_window_lookup("clist_gnet_stats_msg"));
    clist_reason = GTK_CLIST(
        gui_main_window_lookup("clist_gnet_stats_drop_reasons"));
    clist_general = GTK_CLIST(
        gui_main_window_lookup("clist_gnet_stats_general"));
    clist_horizon = GTK_CLIST(
        gui_main_window_lookup("clist_gnet_stats_horizon"));
    clist_stats_fc_ttl = GTK_CLIST(
        gui_main_window_lookup("clist_gnet_stats_fc_ttl"));
    clist_stats_fc_hops = GTK_CLIST(
        gui_main_window_lookup("clist_gnet_stats_fc_hops"));

    gtk_clist_freeze(clist_reason);
    gtk_clist_freeze(clist_general);
    gtk_clist_freeze(clist_stats_msg);
    gtk_clist_freeze(clist_stats_fc_ttl);
    gtk_clist_freeze(clist_stats_fc_hops);

	switch (GUI_PROPERTY(gnet_stats_source)) {
	case GNET_STATS_FULL:
		xstats = &stats;
		break;
	case GNET_STATS_TCP_ONLY:
		guc_gnet_stats_tcp_get(&mstats);
		xstats = &mstats;
		break;
	case GNET_STATS_UDP_ONLY:
		guc_gnet_stats_udp_get(&mstats);
		xstats = &mstats;
		break;
	default:
		g_assert_not_reached();
	}

    for (n = 0; n < MSG_TYPE_COUNT; n ++) {
        int m;

        gtk_clist_set_text(clist_stats_msg, n, c_gs_received,
            GUI_PROPERTY(gnet_stats_bytes) ?
                byte_stat_str(xstats->byte.received, xstats->pkg.received, n) :
                pkt_stat_str(xstats->pkg.received, n));
        gtk_clist_set_text(clist_stats_msg, n, c_gs_gen_queued,
            GUI_PROPERTY(gnet_stats_bytes) ?
                byte_stat_str(xstats->byte.gen_queued,
					xstats->pkg.gen_queued, n) :
                pkt_stat_str(xstats->pkg.gen_queued, n));
        gtk_clist_set_text(clist_stats_msg, n, c_gs_generated,
            GUI_PROPERTY(gnet_stats_bytes) ?
                byte_stat_str(xstats->byte.generated,
					xstats->pkg.generated, n) :
                pkt_stat_str(xstats->pkg.generated, n));
        gtk_clist_set_text(clist_stats_msg, n, c_gs_dropped,
            GUI_PROPERTY(gnet_stats_bytes) ?
                byte_stat_str(xstats->byte.dropped, xstats->pkg.dropped, n) :
                pkt_stat_str(xstats->pkg.dropped, n));
        gtk_clist_set_text(clist_stats_msg, n, c_gs_expired,
            GUI_PROPERTY(gnet_stats_bytes) ?
                byte_stat_str(xstats->byte.expired, xstats->pkg.expired, n) :
                pkt_stat_str(xstats->pkg.expired, n));
        gtk_clist_set_text(clist_stats_msg, n, c_gs_queued,
            GUI_PROPERTY(gnet_stats_bytes) ?
                byte_stat_str(xstats->byte.queued, xstats->pkg.queued, n) :
                pkt_stat_str(xstats->pkg.queued, n));
        gtk_clist_set_text(clist_stats_msg, n, c_gs_relayed,
            GUI_PROPERTY(gnet_stats_bytes) ?
                byte_stat_str(xstats->byte.relayed, xstats->pkg.relayed, n) :
                pkt_stat_str(xstats->pkg.relayed, n));

        for (m = 0; m < 9; m ++)
            gtk_clist_set_text(clist_stats_fc_ttl, n, m+1,
                GUI_PROPERTY(gnet_stats_bytes) ?
                    flowc_stat_str_byte(stats.byte.flowc_ttl[m], n) :
                    flowc_stat_str_pkg(stats.pkg.flowc_ttl[m], n));

        for (m = 0; m < 9; m ++)
            gtk_clist_set_text(clist_stats_fc_hops, n, m+1,
                GUI_PROPERTY(gnet_stats_bytes) ?
                    flowc_stat_str_byte(stats.byte.flowc_hops[m], n) :
                    flowc_stat_str_pkg(stats.pkg.flowc_hops[m], n));
    }

    for (n = 0; n < MSG_DROP_REASON_COUNT; n ++)
        gtk_clist_set_text(clist_reason, n, 1, drop_stat_str(&stats, n));

    for (n = 0; n < GNR_TYPE_COUNT; n ++)
        gtk_clist_set_text(clist_general, n, 1, general_stat_str(&stats, n));

	/*
	 * Update horizon statistics table, but only if the values have changed.
	 *		-- TNT 09/06/2004
	 *
	 * Changed this check to update the table every 2 seconds, because not
	 * only the HSEP table but also the PONG-based library sizes of direct
	 * non-HSEP neighbors may have changed.
	 *		-- TNT 14/06/2004
	 */

	if (delta_time(now, last_horizon_update) >= 2) {

		gtk_clist_freeze(clist_horizon);

		global_table_size = guc_hsep_get_table_size();

		for (n = 0; n < global_table_size; n ++) {
			/*
			 * Note that we output hsep_table[1..global_table_size]
			 *		-- TNT 02/06/2004
			 */
			gtk_clist_set_text(clist_horizon, n, 1,
			    horizon_stat_str(n + 1, 1));
			gtk_clist_set_text(clist_horizon, n, 2,
			    horizon_stat_str(n + 1, 2));
			gtk_clist_set_text(clist_horizon, n, 3,
			    horizon_stat_str(n + 1, 3));
		}
		last_horizon_update = now;
		gtk_clist_thaw(clist_horizon);
	}

    gtk_clist_thaw(clist_reason);
    gtk_clist_thaw(clist_general);
    gtk_clist_thaw(clist_stats_msg);
    gtk_clist_thaw(clist_stats_fc_ttl);
    gtk_clist_thaw(clist_stats_fc_hops);
}

/* vi: set ts=4 sw=4 cindent: */
