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
static gint selected_flowc = 0;

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

static void on_gnet_stats_flowc_selected(GtkItem *i, gpointer data)
{
    selected_flowc = GPOINTER_TO_INT(data);
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
        return (selected_flowc & 1) ? "-" : "- ";

	if (selected_flowc & 1) {
		
		if (selected_flowc < 4)  
        	g_snprintf(strbuf, sizeof(strbuf), "%u", val_tbl[type]);
		else
    		return compact_size(val_tbl[type]);
	}
    else
		g_snprintf(strbuf, sizeof(strbuf), "%.2f%%", 
            (float)val_tbl[type]/val_tbl[MSG_TOTAL]*100.0);

    return strbuf;
}

/***
 *** Public functions
 ***/

void gnet_stats_gui_init(void)
{
    GtkCList *clist_stats_pkg;
    GtkCList *clist_stats_byte;
    GtkCList *clist_general;
    GtkCList *clist_reason;
    GtkCombo *combo_types;
    GtkCombo *combo_flowc;
    GtkTreeView *treeview_flowc;
    GtkTreeModel *model;
	GtkTreeIter iter;
    gchar *titles[6];
    gint n;

    titles[1] = titles[2] = titles[3] = titles[4] = titles[5] = "-";

    clist_stats_pkg = GTK_CLIST(
        lookup_widget(main_window, "clist_gnet_stats_pkg"));
    clist_stats_byte = GTK_CLIST(
        lookup_widget(main_window, "clist_gnet_stats_byte"));
    clist_reason = GTK_CLIST(
        lookup_widget(main_window, "clist_gnet_stats_drop_reasons"));
    clist_general = GTK_CLIST(
        lookup_widget(main_window, "clist_gnet_stats_general"));
    combo_types = GTK_COMBO(
        lookup_widget(main_window, "combo_gnet_stats_type"));
    combo_flowc = GTK_COMBO(
        lookup_widget(main_window, "combo_gnet_stats_flowc"));
    treeview_flowc = GTK_TREE_VIEW(
        lookup_widget(main_window, "treeview_gnet_stats_flowc"));

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

	model = GTK_TREE_MODEL(
		gtk_list_store_new(STATS_FLOWC_COLUMNS,
			G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING,
			G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING,
			G_TYPE_STRING, G_TYPE_STRING));
    gtk_tree_view_set_model(treeview_flowc, model);

	for (n = 0; n < STATS_FLOWC_COLUMNS; n++) {
    	GtkCellRenderer *renderer;
    	GtkTreeViewColumn *column;
    	gchar buf[16];

		renderer = gtk_cell_renderer_text_new();
		g_snprintf(buf, sizeof(buf), "%d%c", n-1,
				(n+1) < STATS_FLOWC_COLUMNS ? ' ' : '+');
		column = gtk_tree_view_column_new_with_attributes(
			n == 0 ? "Type" : buf, renderer, "text", n, NULL);
		gtk_tree_view_column_set_fixed_width(column, n == 0 ? 100 : 50);
		gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_FIXED);
		gtk_tree_view_column_set_resizable(column, TRUE);
		gtk_tree_view_append_column(treeview_flowc, column);
	}

	for (n = 0; n < MSG_TYPE_COUNT; n++) {
		gtk_list_store_append(GTK_LIST_STORE(model), &iter);
		gtk_list_store_set(GTK_LIST_STORE(model), &iter,
			0, msg_type_str[n],
			1, "-",
			2, "-",
			3, "-",
			4, "-",
			5, "-",
			6, "-",
			7, "-",
			8, "-",
			9, "-",
			-1);
	}

    /*
     * Stats can't be sorted: make column headers insensitive.
     */
	gtk_clist_column_titles_passive(clist_stats_pkg);
	gtk_clist_column_titles_passive(clist_stats_byte);
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

    for (n = 0; n < 8; n ++) {
        GtkWidget *list_item;
        GList *l;
		static gchar *labels[8] = {
							"by TTL (packets, percent)",
							"by TTL (packets, absolute)", 
							"by hops (packets, percent)",
							"by hops (packets, absolute)",
							"by TTL (bytes, percent)",
							"by TTL (bytes, absolute)", 
							"by hops (bytes, percent)",
							"by hops (bytes, absolute)"};

        list_item = gtk_list_item_new_with_label(labels[n]);

        gtk_widget_show(list_item);

        gtk_signal_connect(
            GTK_OBJECT(list_item), "select",
            GTK_SIGNAL_FUNC(on_gnet_stats_flowc_selected),
            GINT_TO_POINTER(n));

        l = g_list_prepend(NULL, (gpointer) list_item);
        gtk_list_append_items(GTK_LIST(GTK_COMBO(combo_flowc)->list), l);

        if (n == 7)
            gtk_list_select_child(
                GTK_LIST(GTK_COMBO(combo_flowc)->list), list_item);
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
    GtkTreeView *treeview_flowc;
    GtkListStore *store;
    GtkTreeIter iter;
    gint n;
    gnet_stats_t stats;
	static gboolean lock = FALSE;
	gchar *str[MSG_TYPE_COUNT];

    gint current_page;

	if (lock)
		return;

	lock = TRUE;

    current_page = gtk_notebook_get_current_page(
        GTK_NOTEBOOK(lookup_widget(main_window, "notebook_main")));

    if (current_page != nb_main_page_gnet_stats) {
		lock = FALSE;
        return;
	}

    gnet_stats_get(&stats);

    clist_stats_pkg = GTK_CLIST(
        lookup_widget(main_window, "clist_gnet_stats_pkg"));
    clist_stats_byte = GTK_CLIST(
        lookup_widget(main_window, "clist_gnet_stats_byte"));
    clist_reason = GTK_CLIST(
        lookup_widget(main_window, "clist_gnet_stats_drop_reasons"));
    clist_general = GTK_CLIST(
        lookup_widget(main_window, "clist_gnet_stats_general"));
    treeview_flowc = GTK_TREE_VIEW(
        lookup_widget(main_window, "treeview_gnet_stats_flowc"));

	store = GTK_LIST_STORE(gtk_tree_view_get_model(treeview_flowc));

    gtk_clist_freeze(clist_reason);
    gtk_clist_freeze(clist_general);
    gtk_clist_freeze(clist_stats_byte);
    gtk_clist_freeze(clist_stats_pkg);

    for (n = 0; n < MSG_TYPE_COUNT; n ++) {
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
    }

	gtk_tree_model_get_iter_first(GTK_TREE_MODEL(store), &iter);

	for (n = 0; n < MSG_TYPE_COUNT; n++) {
		gint i;
		guint32 *p;

		for (i = 0; i < STATS_FLOWC_COLUMNS; i++) {
			switch (selected_flowc) {
				case 0: /* FALL THROUGH */
				case 1:
					p = stats.pkg.flowc_ttl[i];
					break;
				case 2: /* FALL THROUGH */
				case 3:
					p = stats.pkg.flowc_hops[i];
					break;
				case 4: /* FALL THROUGH */
				case 5:
					p = stats.byte.flowc_ttl[i];
					break;
				case 6: /* FALL THROUGH */
				case 7:
					p = stats.byte.flowc_hops[i];
				break;
			
				default:
					g_assert_not_reached();
			}

			str[i] = g_strdup(flowc_stat_str(p, n));
		}

		gtk_list_store_set(store, &iter,
			0, msg_type_str[n],
			1, str[0],
			2, str[1],
			3, str[2],
			4, str[3],
			5, str[4],
			6, str[5],
			7, str[6],
			8, str[7],
			9, str[8],
			-1);
#if 0		
		g_message("%-12s %-4s %-4s %-4s %-4s %-4s %-4s %-4s",
			msg_type_str[n],
			str[0], str[1], str[2], str[3], str[4], str[5], str[6]);
#endif

		gtk_tree_model_iter_next(GTK_TREE_MODEL(store), &iter);
		for (i = 0; i < STATS_FLOWC_COLUMNS; i++)
			G_FREE_NULL(str[i]);
	}

#if 0
	g_message(" ");
#endif

    for (n = 0; n < MSG_DROP_REASON_COUNT; n ++)
        gtk_clist_set_text(clist_reason, n, 1, drop_stat_str(&stats, n));


    for (n = 0; n < GNR_TYPE_COUNT; n ++)
        gtk_clist_set_text(clist_general, n, 1, general_stat_str(&stats, n));

    gtk_clist_thaw(clist_reason);
    gtk_clist_thaw(clist_general);
    gtk_clist_thaw(clist_stats_byte);
    gtk_clist_thaw(clist_stats_pkg);

	lock = FALSE;
}
