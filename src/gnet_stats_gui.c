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
    "unknown type",
    "init",
    "init response",
    "bye",
    "QRP",
    "vendor",
    "standard vendor",
    "push request",
    "search",
    "search results"
};

gchar *msg_drop_str[MSG_DROP_REASON_COUNT] = {
    "bad size: init message",
    "bad size: init response",
    "bad size: bye message",
    "bad size: push request",
    "search too small",
    "search too large",
    "result too large",
    "unknown message type",
    "ttl = 0",
    "ping throttle",
    "hard ttl limit reached",
    "max hop count reached",
    "unrequested reply",
    "route lost",
    "no route",
    "duplicate",
    "msg from banned host",
    "node shutting down",
    "flow control",
    "query too long",
    "query too short",
    "multiple SHA1",
    "misformed SHA1 query",
    "max ttl exceeded",
    "result too small",
    "result has double NUL",
    "malformed result",
    "result had bad SHA1"
};

/***
 *** Callbacks
 ***/
void on_clist_gnet_stats_resize_column(
    GtkCList *clist, gint column, gint width, gpointer user_data)
{
    guint32 buf = width;

    /* remember the width for storing it to the config file later */
    gui_prop_set_guint32(PROP_GNET_STATS_COL_WIDTHS, &buf, column, 1);
}

void on_clist_gnet_stats_drop_reasons_resize_column(
    GtkCList *clist, gint column, gint width, gpointer user_data)
{
    guint32 buf = width;

    /* remember the width for storing it to the config file later */
    gui_prop_set_guint32(PROP_GNET_STATS_DROP_REASONS_COL_WIDTHS, 
        &buf, column, 1);
}



/***
 *** Public functions
 ***/

void gnet_stats_gui_init(void)
{
    GtkCList *clist_stats;
    GtkCList *clist_reason;
    gchar *titles[5];
    gint n;

    titles[1] = titles[2] = titles[3] = titles[4] = "-";

    clist_stats = GTK_CLIST(
        lookup_widget(main_window, "clist_gnet_stats"));
    clist_reason = GTK_CLIST(
        lookup_widget(main_window, "clist_gnet_stats_drop_reasons"));

    for (n = 0; n < MSG_TYPE_COUNT; n ++) {
        gint row;
        titles[0] = msg_type_str[n];
        row = gtk_clist_append(clist_stats, titles);
        gtk_clist_set_selectable(clist_stats, row, FALSE);
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
    GtkCList *clist_stats;

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
        GTK_LABEL(lookup_widget(main_window, "label_msg_dropped_total")),
        "%u", stats.dropped_total);
    gtk_label_printf(
        GTK_LABEL(lookup_widget(main_window, "label_msg_sent_total")),
        "%u", stats.sent_total);
    gtk_label_printf(
        GTK_LABEL(lookup_widget(main_window, "label_msg_recv_total")),
        "%u", stats.recieved_total);
    gtk_label_printf(
        GTK_LABEL(lookup_widget(main_window, "label_msg_expired_total")),
        "%u", stats.expired_total);


    clist_stats = GTK_CLIST(
        lookup_widget(main_window, "clist_gnet_stats"));
    clist_reason = GTK_CLIST(
        lookup_widget(main_window, "clist_gnet_stats_drop_reasons"));

    for (n = 0; n < MSG_TYPE_COUNT; n ++) {
        g_snprintf(strbuf, sizeof(strbuf), "%u", stats.recieved[n]);
        gtk_clist_set_text(clist_stats, n, c_gs_recieved, strbuf);
        g_snprintf(strbuf, sizeof(strbuf), "%u", stats.sent[n]);
        gtk_clist_set_text(clist_stats, n, c_gs_sent, strbuf);
        g_snprintf(strbuf, sizeof(strbuf), "%u", stats.dropped[n]);
        gtk_clist_set_text(clist_stats, n, c_gs_dropped, strbuf);
        g_snprintf(strbuf, sizeof(strbuf), "%u", stats.expired[n]);
        gtk_clist_set_text(clist_stats, n, c_gs_expired, strbuf);
    }

    for (n = 0; n < MSG_DROP_REASON_COUNT; n ++) {
        g_snprintf(strbuf, sizeof(strbuf), "%u", stats.drop_reason[n]);
        gtk_clist_set_text(clist_reason, n, 1, strbuf);
    }
}
