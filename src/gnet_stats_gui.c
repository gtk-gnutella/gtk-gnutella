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

#ifdef USE_GTK1

#include "gnet_stats_gui.h"
#include "override.h"		/* Must be the last header included */

RCSID("$Id$");

static gint selected_type = MSG_TOTAL;

/***
 *** Callbacks
 ***/
void on_clist_gnet_stats_msg_resize_column(
    GtkCList *clist, gint column, gint width, gpointer user_data)
{
    static gboolean lock = FALSE;
    guint32 buf = width;

    if (lock)
        return;

    lock = TRUE;

    /* remember the width for storing it to the config file later */
    gui_prop_set_guint32(PROP_GNET_STATS_MSG_COL_WIDTHS, &buf, column, 1);

    lock = FALSE;
}


void on_clist_gnet_stats_fc_ttl_resize_column(
    GtkCList *clist, gint column, gint width, gpointer user_data)
{
    static gboolean lock = FALSE;
    guint32 buf[9];
    guint n;

    if (lock)
        return;

    lock = TRUE;

    /* remember the width for storing it to the config file later */
    for (n = 0; n < G_N_ELEMENTS(buf); n ++)
        buf[n] = width;

    gui_prop_set_guint32(PROP_GNET_STATS_FC_TTL_COL_WIDTHS, buf, 1, 9);

    lock = FALSE;
}

void on_clist_gnet_stats_fc_hops_resize_column(
    GtkCList *clist, gint column, gint width, gpointer user_data)
{
    static gboolean lock = FALSE;
    guint32 buf[9];
    guint n;

    if (lock)
        return;

    lock = TRUE;

    /* remember the width for storing it to the config file later */
    for (n = 0; n < G_N_ELEMENTS(buf); n ++)
        buf[n] = width;

    gui_prop_set_guint32(PROP_GNET_STATS_FC_HOPS_COL_WIDTHS, buf, 1, 9);

    lock = FALSE;
}

void on_clist_gnet_stats_drop_reasons_resize_column(
    GtkCList *clist, gint column, gint width, gpointer user_data)
{
    guint32 buf = width;

    /* remember the width for storing it to the config file later */
    gui_prop_set_guint32(PROP_GNET_STATS_DROP_REASONS_COL_WIDTHS, 
        &buf, column, 1);
}

void on_clist_gnet_stats_general_resize_column(
    GtkCList *clist, gint column, gint width, gpointer user_data)
{
    guint32 buf = width;

    /* remember the width for storing it to the config file later */
    gui_prop_set_guint32(PROP_GNET_STATS_GENERAL_COL_WIDTHS, 
        &buf, column, 1);
}

static void on_gnet_stats_type_selected(GtkItem *i, gpointer data)
{
    selected_type = GPOINTER_TO_INT(data);
    gnet_stats_gui_update(time(NULL));
}


/***
 *** Private functions
 ***/
gchar *pkt_stat_str(
    guint32 *val_tbl, gint type)
{
    static gchar strbuf[20];

    if (val_tbl[type] == 0)
        return gnet_stats_perc ? "-  " : "-";

    if (gnet_stats_perc)
        gm_snprintf(strbuf, sizeof(strbuf), "%.2f%%", 
            (float)val_tbl[type]/val_tbl[MSG_TOTAL]*100.0);
    else
        gm_snprintf(strbuf, sizeof(strbuf), "%u", val_tbl[type]);

    return strbuf;
}


gchar *byte_stat_str(
    guint32 *val_tbl, gint type)
{
    static gchar strbuf[20];

    if (val_tbl[type] == 0)
        return gnet_stats_perc ? "-  " : "-";

    if (gnet_stats_perc) {
        gm_snprintf(strbuf, sizeof(strbuf), "%.2f%%", 
            (float)val_tbl[type]/val_tbl[MSG_TOTAL]*100.0);
        return strbuf;
    } else
        return compact_size(val_tbl[type]);
}

gchar *drop_stat_str(gnet_stats_t *stats, gint reason)
{
    static gchar strbuf[20];
    guint32 total = stats->pkg.dropped[MSG_TOTAL];

    if (stats->drop_reason[reason][selected_type] == 0)
        return gnet_stats_drop_perc ? "-  " : "-";

    if (gnet_stats_drop_perc)
        gm_snprintf(strbuf, sizeof(strbuf), "%.2f%%", 
            (float)stats->drop_reason[reason][selected_type]/total*100);
    else
        gm_snprintf(strbuf, sizeof(strbuf), "%u", 
            stats->drop_reason[reason][selected_type]);

    return strbuf;
}

gchar *general_stat_str(gnet_stats_t *stats, gint type)
{
    static gchar strbuf[20];

    if (stats->general[type] == 0)
        return "-";

    if (type == GNR_QUERY_COMPACT_SIZE) {
        return compact_size(stats->general[type]);
    } else {
        gm_snprintf(strbuf, sizeof(strbuf), "%u", stats->general[type]);
        return strbuf;
    }
}

gchar *flowc_stat_str_pkg(guint32 *val_tbl, gint type)
{
    static gchar strbuf[20];

    if (val_tbl[type] == 0)
        return gnet_stats_perc ? "-  " : "-";

	if (gnet_stats_perc) {
		gm_snprintf(strbuf, sizeof(strbuf), "%.2f%%", 
            (float)val_tbl[type]/val_tbl[MSG_TOTAL]*100.0);
    } else {
       	gm_snprintf(strbuf, sizeof(strbuf), "%u", val_tbl[type]);
    }

    return strbuf;
}

gchar *flowc_stat_str_byte(guint32 *val_tbl, gint type)
{
    static gchar strbuf[20];

    if (val_tbl[type] == 0)
        return gnet_stats_perc ? "-  " : "-";

	if (gnet_stats_perc) {
		gm_snprintf(strbuf, sizeof(strbuf), "%.2f%%", 
            (float)val_tbl[type]/val_tbl[MSG_TOTAL]*100.0);
    } else {
       	return compact_size(val_tbl[type]);
    }

    return strbuf;
}

/***
 *** Public functions
 ***/

void gnet_stats_gui_init(void)
{
    GtkCList *clist_stats_msg;
    GtkCList *clist_stats_fc_ttl;
    GtkCList *clist_stats_fc_hops;
    GtkCList *clist_general;
    GtkCList *clist_reason;
    GtkCombo *combo_types;
    gchar *titles[10];
    gint n;

    for (n = 0; n < G_N_ELEMENTS(titles); n ++)
        titles[n] = "-";

    clist_stats_msg = GTK_CLIST(
        lookup_widget(main_window, "clist_gnet_stats_msg"));
    clist_stats_fc_ttl = GTK_CLIST(
        lookup_widget(main_window, "clist_gnet_stats_fc_ttl"));
    clist_stats_fc_hops = GTK_CLIST(
        lookup_widget(main_window, "clist_gnet_stats_fc_hops"));
    clist_reason = GTK_CLIST(
        lookup_widget(main_window, "clist_gnet_stats_drop_reasons"));
    clist_general = GTK_CLIST(
        lookup_widget(main_window, "clist_gnet_stats_general"));
    combo_types = GTK_COMBO(
        lookup_widget(main_window, "combo_gnet_stats_type"));

    /*
     * Set column justification for numeric columns to GTK_JUSTIFY_RIGHT.
     */
    gtk_clist_set_column_justification(
        clist_general, 1, GTK_JUSTIFY_RIGHT);
    gtk_clist_set_column_justification(
        clist_reason, 1, GTK_JUSTIFY_RIGHT);

    for (n = 1; n < 6; n ++) {
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

    /*
     * Initialize stats tables.
     */
    for (n = 0; n < MSG_TYPE_COUNT; n ++) {
        GtkWidget *list_item;
        GList *l;
        gint row;

        titles[0] = (gchar *) msg_type_str(n);

        row = gtk_clist_append(clist_stats_msg, titles);
        gtk_clist_set_selectable(clist_stats_msg, row, FALSE);
        row = gtk_clist_append(clist_stats_fc_ttl, titles);
        gtk_clist_set_selectable(clist_stats_fc_ttl, row, FALSE);
        row = gtk_clist_append(clist_stats_fc_hops, titles);
        gtk_clist_set_selectable(clist_stats_fc_hops, row, FALSE);

        list_item = gtk_list_item_new_with_label(msg_type_str(n));

        gtk_widget_show(list_item);

        gtk_signal_connect(
            GTK_OBJECT(list_item), "select",
            GTK_SIGNAL_FUNC(on_gnet_stats_type_selected),
            GINT_TO_POINTER(n));

        l = g_list_prepend(NULL, (gpointer) list_item);
        gtk_list_append_items(GTK_LIST(GTK_COMBO(combo_types)->list), l);

        if (n == MSG_TOTAL)
            gtk_list_select_child(
                GTK_LIST(GTK_COMBO(combo_types)->list), list_item);
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
}

void gnet_stats_gui_shutdown(void)
{
	/* Nothing for now */
}

void gnet_stats_gui_update(time_t now)
{
	static time_t last_update = 0;
    GtkCList *clist_stats_msg;
    GtkCList *clist_reason;
    GtkCList *clist_general;
    GtkCList *clist_stats_fc_ttl;
    GtkCList *clist_stats_fc_hops;
    gint n;
    gnet_stats_t stats;

    gint current_page;

	if (last_update == now)
		return;
	last_update = now;
    current_page = gtk_notebook_get_current_page(
        GTK_NOTEBOOK(lookup_widget(main_window, "notebook_main")));

    if (current_page != nb_main_page_gnet_stats)
        return;

    gnet_stats_get(&stats);

    clist_stats_msg = GTK_CLIST(
        lookup_widget(main_window, "clist_gnet_stats_msg"));
    clist_reason = GTK_CLIST(
        lookup_widget(main_window, "clist_gnet_stats_drop_reasons"));
    clist_general = GTK_CLIST(
        lookup_widget(main_window, "clist_gnet_stats_general"));
    clist_stats_fc_ttl = GTK_CLIST(
        lookup_widget(main_window, "clist_gnet_stats_fc_ttl"));
    clist_stats_fc_hops = GTK_CLIST(
        lookup_widget(main_window, "clist_gnet_stats_fc_hops"));

    gtk_clist_freeze(clist_reason);
    gtk_clist_freeze(clist_general);
    gtk_clist_freeze(clist_stats_msg);
    gtk_clist_freeze(clist_stats_fc_ttl);
    gtk_clist_freeze(clist_stats_fc_hops);

    for (n = 0; n < MSG_TYPE_COUNT; n ++) {
        int m;

        gtk_clist_set_text(clist_stats_msg, n, c_gs_received, 
            gnet_stats_bytes ? 
                byte_stat_str(stats.byte.received, n) : 
                pkt_stat_str(stats.pkg.received, n));
        gtk_clist_set_text(clist_stats_msg, n, c_gs_generated, 
            gnet_stats_bytes ? 
                byte_stat_str(stats.byte.generated, n) : 
                pkt_stat_str(stats.pkg.generated, n));
        gtk_clist_set_text(clist_stats_msg, n, c_gs_dropped, 
            gnet_stats_bytes ? 
                byte_stat_str(stats.byte.dropped, n) : 
                pkt_stat_str(stats.pkg.dropped, n));
        gtk_clist_set_text(clist_stats_msg, n, c_gs_expired, 
            gnet_stats_bytes ? 
                byte_stat_str(stats.byte.expired, n) : 
                pkt_stat_str(stats.pkg.expired, n));
        gtk_clist_set_text(clist_stats_msg, n, c_gs_relayed, 
            gnet_stats_bytes ? 
                byte_stat_str(stats.byte.relayed, n) : 
                pkt_stat_str(stats.pkg.relayed, n));

        for (m = 0; m < 9; m ++)
            gtk_clist_set_text(clist_stats_fc_ttl, n, m+1,
                gnet_stats_bytes ? 
                    flowc_stat_str_byte(stats.byte.flowc_ttl[m], n) :
                    flowc_stat_str_pkg(stats.pkg.flowc_ttl[m], n));

        for (m = 0; m < 9; m ++)
            gtk_clist_set_text(clist_stats_fc_hops, n, m+1,
                gnet_stats_bytes ? 
                    flowc_stat_str_byte(stats.byte.flowc_hops[m], n) :
                    flowc_stat_str_pkg(stats.pkg.flowc_hops[m], n));
    }

    for (n = 0; n < MSG_DROP_REASON_COUNT; n ++)
        gtk_clist_set_text(clist_reason, n, 1, drop_stat_str(&stats, n));

    for (n = 0; n < GNR_TYPE_COUNT; n ++)
        gtk_clist_set_text(clist_general, n, 1, general_stat_str(&stats, n));

    gtk_clist_thaw(clist_reason);
    gtk_clist_thaw(clist_general);
    gtk_clist_thaw(clist_stats_msg);
    gtk_clist_thaw(clist_stats_fc_ttl);
    gtk_clist_thaw(clist_stats_fc_hops);
}

#endif	/* USE_GTK1 */
