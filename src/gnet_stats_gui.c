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

#include "gnet_stats_gui.h"

gchar *msg_type_str[MSG_TYPE_COUNT] = {
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

gchar *msg_drop_str[MSG_DROP_REASON_COUNT] = {
    "Bad size",
    "Too small",
    "Too large",
	"Way too large",
    "Unknown message type",
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
    "Malformed SHA1 Query",
    "Malformed UTF-8 Query",
    "Malformed Query Hit",
    "Query hit had bad SHA1"
};

gchar *general_type_str[GNR_TYPE_COUNT] = {
    "Routing errors",
    "Searches to local DB",
    "Hits on local DB",
    "Compacted queries",
    "Bytes saved by compacting",
    "UTF8 queries",
    "SHA1 queries"
};

static gint selected_type = MSG_TOTAL;

/***
 *** Callbacks
 ***/
void on_clist_gnet_stats_pkg_resize_column(
    GtkCList *clist, gint column, gint width, gpointer user_data)
{
    static gboolean lock = FALSE;
    guint32 buf = width;

    if (lock)
        return;

    lock = TRUE;

    /* remember the width for storing it to the config file later */
    gui_prop_set_guint32(PROP_GNET_STATS_PKG_COL_WIDTHS, &buf, column, 1);
    gtk_clist_set_column_width(
        GTK_CLIST(lookup_widget(main_window, "clist_gnet_stats_byte")),
        column, width);

    lock = FALSE;
}

void on_clist_gnet_stats_byte_resize_column(
    GtkCList *clist, gint column, gint width, gpointer user_data)
{
    static gboolean lock = FALSE;
    guint32 buf = width;

    if (lock)
        return;

    lock = TRUE;

    /* remember the width for storing it to the config file later */
    gui_prop_set_guint32(PROP_GNET_STATS_BYTE_COL_WIDTHS, &buf, column, 1);
    gtk_clist_set_column_width(
        GTK_CLIST(lookup_widget(main_window, "clist_gnet_stats_pkg")),
        column, width);

    lock = FALSE;
}

void on_clist_gnet_stats_fc_resize_column(
    GtkCList *clist, gint column, gint width, gpointer user_data)
{
    static gboolean lock = FALSE;
    guint32 buf = width;
    guint n;

    if (lock)
        return;

    lock = TRUE;

    /* remember the width for storing it to the config file later */
    for (n = 1; n < 10; n ++) {
        gui_prop_set_guint32(PROP_GNET_STATS_FC_COL_WIDTHS, &buf, n, 1);
        gtk_clist_set_column_width(
            GTK_CLIST(lookup_widget(main_window, "clist_gnet_stats_fc")),
            n, width);
    }

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
    gnet_stats_gui_update();
}


/***
 *** Private functions
 ***/
G_INLINE_FUNC gchar *pkt_stat_str(
    guint32 *val_tbl, gint type)
{
    static gchar strbuf[20];

    if (val_tbl[type] == 0)
        return gnet_stats_pkg_perc ? "-  " : "-";

    if (gnet_stats_pkg_perc)
        g_snprintf(strbuf, sizeof(strbuf), "%.2f%%", 
            (float)val_tbl[type]/val_tbl[MSG_TOTAL]*100.0);
    else
        g_snprintf(strbuf, sizeof(strbuf), "%u", val_tbl[type]);

    return strbuf;
}


G_INLINE_FUNC gchar *byte_stat_str(
    guint32 *val_tbl, gint type)
{
    static gchar strbuf[20];

    if (val_tbl[type] == 0)
        return gnet_stats_byte_perc ? "-  " : "-";

    if (gnet_stats_byte_perc) {
        g_snprintf(strbuf, sizeof(strbuf), "%.2f%%", 
            (float)val_tbl[type]/val_tbl[MSG_TOTAL]*100.0);
        return strbuf;
    } else
        return compact_size(val_tbl[type]);
}

G_INLINE_FUNC gchar *drop_stat_str(gnet_stats_t *stats, gint reason)
{
    static gchar strbuf[20];
    guint32 total = stats->pkg.dropped[MSG_TOTAL];

    if (stats->drop_reason[reason][selected_type] == 0)
        return gnet_stats_drop_perc ? "-  " : "-";

    if (gnet_stats_drop_perc)
        g_snprintf(strbuf, sizeof(strbuf), "%.2f%%", 
            (float)stats->drop_reason[reason][selected_type]/total*100);
    else
        g_snprintf(strbuf, sizeof(strbuf), "%u", 
            stats->drop_reason[reason][selected_type]);

    return strbuf;
}

G_INLINE_FUNC gchar *general_stat_str(gnet_stats_t *stats, gint type)
{
    static gchar strbuf[20];

    if (stats->general[type] == 0)
        return "-";

    if (type == GNR_QUERY_COMPACT_SIZE) {
        return compact_size(stats->general[type]);
    } else {
        g_snprintf(strbuf, sizeof(strbuf), "%u", stats->general[type]);
        return strbuf;
    }
}

G_INLINE_FUNC gchar *flowc_stat_str(
    guint32 *val_tbl, gint type)
{
    static gchar strbuf[20];

    if (val_tbl[type] == 0)
        return gnet_stats_fc_perc ? "-  " : "-";

	if (gnet_stats_drop_perc) {
		g_snprintf(strbuf, sizeof(strbuf), "%.2f%%", 
            (float)val_tbl[type]/val_tbl[MSG_TOTAL]*100.0);
    } else {
       	g_snprintf(strbuf, sizeof(strbuf), "%u", val_tbl[type]);
    }

    return strbuf;
}

/***
 *** Public functions
 ***/

void gnet_stats_gui_init(void)
{
    GtkCList *clist_stats_pkg;
    GtkCList *clist_stats_byte;
    GtkCList *clist_stats_fc;
    GtkCList *clist_general;
    GtkCList *clist_reason;
    GtkCombo *combo_types;
    gchar *titles[10];
    gint n;

    for (n = 0; n < G_N_ELEMENTS(titles); n ++)
        titles[n] = "-";

    clist_stats_pkg = GTK_CLIST(
        lookup_widget(main_window, "clist_gnet_stats_pkg"));
    clist_stats_byte = GTK_CLIST(
        lookup_widget(main_window, "clist_gnet_stats_byte"));
    clist_stats_fc = GTK_CLIST(
        lookup_widget(main_window, "clist_gnet_stats_fc"));
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
        clist_stats_pkg, c_gs_relayed, GTK_JUSTIFY_RIGHT);
    gtk_clist_set_column_justification(
        clist_stats_pkg, c_gs_generated, GTK_JUSTIFY_RIGHT);
    gtk_clist_set_column_justification(
        clist_stats_pkg, c_gs_dropped, GTK_JUSTIFY_RIGHT);
    gtk_clist_set_column_justification(
        clist_stats_pkg, c_gs_expired, GTK_JUSTIFY_RIGHT);
    gtk_clist_set_column_justification(
        clist_stats_pkg, c_gs_received, GTK_JUSTIFY_RIGHT);
    gtk_clist_set_column_justification(
        clist_stats_byte, c_gs_generated, GTK_JUSTIFY_RIGHT);
    gtk_clist_set_column_justification(
        clist_stats_byte, c_gs_dropped, GTK_JUSTIFY_RIGHT);
    gtk_clist_set_column_justification(
        clist_stats_byte, c_gs_expired, GTK_JUSTIFY_RIGHT);
    gtk_clist_set_column_justification(
        clist_stats_byte, c_gs_received, GTK_JUSTIFY_RIGHT);
    gtk_clist_set_column_justification(
        clist_stats_byte, c_gs_relayed, GTK_JUSTIFY_RIGHT);
    gtk_clist_set_column_justification(
        clist_general, 1, GTK_JUSTIFY_RIGHT);
    gtk_clist_set_column_justification(
        clist_reason, 1, GTK_JUSTIFY_RIGHT);

    for (n = 1; n < 10; n ++)
        gtk_clist_set_column_justification(
            clist_stats_fc, n, GTK_JUSTIFY_RIGHT);


    /*
     * Stats can't be sorted: make column headers insensitive.
     */
	gtk_clist_column_titles_passive(clist_stats_pkg);
	gtk_clist_column_titles_passive(clist_stats_byte);
	gtk_clist_column_titles_passive(clist_stats_fc);
	gtk_clist_column_titles_passive(clist_reason);
	gtk_clist_column_titles_passive(clist_general);

    /*
     * Initialize stats tables.
     */
    for (n = 0; n < MSG_TYPE_COUNT; n ++) {
        GtkWidget *list_item;
        GList *l;
        gint row;

        titles[0] = msg_type_str[n];

        row = gtk_clist_append(clist_stats_pkg, titles);
        gtk_clist_set_selectable(clist_stats_pkg, row, FALSE);
        row = gtk_clist_append(clist_stats_byte, titles);
        gtk_clist_set_selectable(clist_stats_byte, row, FALSE);
        row = gtk_clist_append(clist_stats_fc, titles);
        gtk_clist_set_selectable(clist_stats_fc, row, FALSE);

        list_item = gtk_list_item_new_with_label(msg_type_str[n]);

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
        titles[0] = msg_drop_str[n];
        row = gtk_clist_append(clist_reason, titles);
        gtk_clist_set_selectable(clist_reason, row, FALSE);
    }

    for (n = 0; n < GNR_TYPE_COUNT; n ++) {
        gint row;
        titles[0] = general_type_str[n];
        row = gtk_clist_append(clist_general, titles);
        gtk_clist_set_selectable(clist_general, row, FALSE);
    }
}

void gnet_stats_gui_update(void)
{
    GtkCList *clist_stats_pkg;
    GtkCList *clist_stats_byte;
    GtkCList *clist_reason;
    GtkCList *clist_general;
    GtkCList *clist_stats_fc;
    gint n;
    gnet_stats_t stats;

    gint current_page;

    current_page = gtk_notebook_get_current_page(
        GTK_NOTEBOOK(lookup_widget(main_window, "notebook_main")));

    if (current_page != nb_main_page_gnet_stats)
        return;

    gnet_stats_get(&stats);

    clist_stats_pkg = GTK_CLIST(
        lookup_widget(main_window, "clist_gnet_stats_pkg"));
    clist_stats_byte = GTK_CLIST(
        lookup_widget(main_window, "clist_gnet_stats_byte"));
    clist_reason = GTK_CLIST(
        lookup_widget(main_window, "clist_gnet_stats_drop_reasons"));
    clist_general = GTK_CLIST(
        lookup_widget(main_window, "clist_gnet_stats_general"));
    clist_stats_fc = GTK_CLIST(
        lookup_widget(main_window, "clist_gnet_stats_fc"));

    gtk_clist_freeze(clist_reason);
    gtk_clist_freeze(clist_general);
    gtk_clist_freeze(clist_stats_byte);
    gtk_clist_freeze(clist_stats_pkg);
    gtk_clist_freeze(clist_stats_fc);

    for (n = 0; n < MSG_TYPE_COUNT; n ++) {
        int m;

        gtk_clist_set_text(clist_stats_pkg, n, c_gs_received, 
            pkt_stat_str(stats.pkg.received, n));
        gtk_clist_set_text(clist_stats_pkg, n, c_gs_generated, 
            pkt_stat_str(stats.pkg.generated, n));
        gtk_clist_set_text(clist_stats_pkg, n, c_gs_dropped,
            pkt_stat_str(stats.pkg.dropped, n));
        gtk_clist_set_text(clist_stats_pkg, n, c_gs_expired,
            pkt_stat_str(stats.pkg.expired, n));
        gtk_clist_set_text(clist_stats_pkg, n, c_gs_relayed,
            pkt_stat_str(stats.pkg.relayed, n));

        gtk_clist_set_text(clist_stats_byte, n, c_gs_received, 
            byte_stat_str(stats.byte.received, n));
        gtk_clist_set_text(clist_stats_byte, n, c_gs_generated,
            byte_stat_str(stats.byte.generated, n));
        gtk_clist_set_text(clist_stats_byte, n, c_gs_dropped,
            byte_stat_str(stats.byte.dropped, n));
        gtk_clist_set_text(clist_stats_byte, n, c_gs_expired,
            byte_stat_str(stats.byte.expired, n));
        gtk_clist_set_text(clist_stats_byte, n, c_gs_relayed,
            byte_stat_str(stats.byte.relayed, n));

        for (m = 1; m < 10; m ++)
            gtk_clist_set_text(clist_stats_fc, n, m,
                flowc_stat_str(stats.byte.flowc_ttl[m], n));

    }

    for (n = 0; n < MSG_DROP_REASON_COUNT; n ++)
        gtk_clist_set_text(clist_reason, n, 1, drop_stat_str(&stats, n));

    for (n = 0; n < GNR_TYPE_COUNT; n ++)
        gtk_clist_set_text(clist_general, n, 1, general_stat_str(&stats, n));

    gtk_clist_thaw(clist_reason);
    gtk_clist_thaw(clist_general);
    gtk_clist_thaw(clist_stats_byte);
    gtk_clist_thaw(clist_stats_pkg);
    gtk_clist_thaw(clist_stats_fc);
}
