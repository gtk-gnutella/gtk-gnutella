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
    "bad size",
    "too small",
    "too large",
    "unknown message type",
    "ttl = 0",
    "ping throttle",
    "hard ttl limit reached",
    "max hop count reached",
    "unrequested reply",
    "route lost",
    "no route",
    "duplicate message",
    "msg from banned host",
    "node shutting down",
    "flow control",
    "query too long",
    "query too short",
    "multiple SHA1",
    "misformed SHA1 query",
    "max ttl exceeded",
    "malformed query hit",
    "query hit has double NUL",
    "query hit had bad SHA1"
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

void on_clist_gnet_stats_drop_reasons_resize_column(
    GtkCList *clist, gint column, gint width, gpointer user_data)
{
    guint32 buf = width;

    /* remember the width for storing it to the config file later */
    gui_prop_set_guint32(PROP_GNET_STATS_DROP_REASONS_COL_WIDTHS, 
        &buf, column, 1);
}

static void on_gnet_stats_type_selected(GtkItem *i, gpointer data)
{
    printf( "selected type: %d\n", (gint) data);

    selected_type = (gint) data;
    gnet_stats_gui_update();
}



/***
 *** Public functions
 ***/

void gnet_stats_gui_init(void)
{
    GtkCList *clist_stats_pkg;
    GtkCList *clist_stats_byte;
    GtkCList *clist_reason;
    GtkCombo *combo_types;
    gchar *titles[5];
    gint n;

    titles[1] = titles[2] = titles[3] = titles[4] = "-";

    clist_stats_pkg = GTK_CLIST(
        lookup_widget(main_window, "clist_gnet_stats_pkg"));
    clist_stats_byte = GTK_CLIST(
        lookup_widget(main_window, "clist_gnet_stats_byte"));
    clist_reason = GTK_CLIST(
        lookup_widget(main_window, "clist_gnet_stats_drop_reasons"));
    combo_types = GTK_COMBO(
        lookup_widget(main_window, "combo_gnet_stats_type"));

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
            (gpointer) n);

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
}

void gnet_stats_gui_update(void)
{
    GtkCList *clist_stats_pkg;
    GtkCList *clist_stats_byte;
    GtkCList *clist_reason;
    gint n;
    gchar strbuf[10];
 
    gnet_stats_t stats;

    gnet_stats_get(&stats);

    gtk_label_printf(
        GTK_LABEL(lookup_widget(main_window, "label_routing_errors")),
        "%u", stats.routing_errors);
    gtk_label_printf(
        GTK_LABEL(lookup_widget(main_window, "label_local_searches")),
        "%u", stats.local_searches);
    gtk_label_printf(
        GTK_LABEL(lookup_widget(main_window, "label_local_hits")),
        "%u", stats.local_hits);

    clist_stats_pkg = GTK_CLIST(
        lookup_widget(main_window, "clist_gnet_stats_pkg"));
    clist_stats_byte = GTK_CLIST(
        lookup_widget(main_window, "clist_gnet_stats_byte"));
    clist_reason = GTK_CLIST(
        lookup_widget(main_window, "clist_gnet_stats_drop_reasons"));

    for (n = 0; n < MSG_TYPE_COUNT; n ++) {
        g_snprintf(strbuf, sizeof(strbuf), "%u", stats.pkg.recieved[n]);
        gtk_clist_set_text(clist_stats_pkg, n, c_gs_recieved, strbuf);
        g_snprintf(strbuf, sizeof(strbuf), "%u", stats.pkg.sent[n]);
        gtk_clist_set_text(clist_stats_pkg, n, c_gs_sent, strbuf);
        g_snprintf(strbuf, sizeof(strbuf), "%u", stats.pkg.dropped[n]);
        gtk_clist_set_text(clist_stats_pkg, n, c_gs_dropped, strbuf);
        g_snprintf(strbuf, sizeof(strbuf), "%u", stats.pkg.expired[n]);
        gtk_clist_set_text(clist_stats_pkg, n, c_gs_expired, strbuf);

        gtk_clist_set_text(clist_stats_byte, n, c_gs_recieved, 
            compact_size(stats.byte.recieved[n]));
        gtk_clist_set_text(clist_stats_byte, n, c_gs_sent,
            compact_size(stats.byte.sent[n]));
        gtk_clist_set_text(clist_stats_byte, n, c_gs_dropped,
            compact_size(stats.byte.dropped[n]));
        gtk_clist_set_text(clist_stats_byte, n, c_gs_expired,
            compact_size(stats.byte.expired[n]));
    }

    for (n = 0; n < MSG_DROP_REASON_COUNT; n ++) {
        g_snprintf(strbuf, sizeof(strbuf), "%u", 
            stats.drop_reason[n][selected_type]);
        gtk_clist_set_text(clist_reason, n, 1, strbuf);
    }
}
