/*
 * $Id$
 *
 * Copyright (c) 2001-2002, Raphael Manfredi, Richard Eckart
 *
 * GUI filtering functions.
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

#include "gnutella.h"
#include "gnet.h"
#include "nodes_cb.h"
#include "gui.h"
#include "gtk-missing.h"
#include "misc.h"
#include "settings_gui.h"

#include "gui_property_priv.h"

/*
 * nodes_ctrl_connect_by_name:
 *
 * Try to connect to the node given by the addr string in the form
 * [ip]:[port]. Port may be omitted.
 */
static void nodes_cb_connect_by_name(const gchar *addr) 
{
    guint32 port = 6346;
    gchar *e;
    gchar *seek;

    g_assert(addr != NULL);
    
    e = g_strdup(addr);
	g_strstrip(e);

	seek = e;

	while (*seek && *seek != ':' && *seek != ' ')
		seek++;

	if (*seek) {
		*seek++ = 0;
		while (*seek && (*seek == ':' || *seek == ' '))
			seek++;
		if (*seek)
			port = atol(seek);
	}

	if (port < 1 || port > 65535) {
        // FIXME: have notice in statusbar instead
		printf("Bad host !\n");
        gdk_beep();
    } else {
		guint32 ip = host_to_ip(e);
		if (ip) {
            node_add(ip, port);
        }
	}

    g_free(e);
}

void on_clist_nodes_select_row
    (GtkCList *clist, gint row, gint col, GdkEvent *event, gpointer user_data)
{
    on_clist_nodes_unselect_row(clist, row, col, event, user_data);
}

void on_clist_nodes_unselect_row
    (GtkCList *clist, gint row, gint col, GdkEvent *event, gpointer user_data)
{
    gboolean sensitive = (gboolean) clist->selection;
	gtk_widget_set_sensitive
        (lookup_widget(main_window, "button_nodes_remove"), sensitive);
    gtk_widget_set_sensitive
        (lookup_widget(popup_nodes, "popup_nodes_remove"), sensitive);
}

void on_clist_nodes_resize_column
    (GtkCList *clist, gint column, gint width, gpointer user_data)
{
    nodes_col_widths[column] = width;
}

gboolean on_clist_nodes_button_press_event
    (GtkWidget * widget, GdkEventButton * event, gpointer user_data)
{
    gint row;
    gint col;
    GtkCList *clist_nodes = GTK_CLIST
        (lookup_widget(main_window, "clist_nodes"));

    if (event->button != 3)
		return FALSE;

    if (clist_nodes->selection == NULL)
        return FALSE;

    if (!gtk_clist_get_selection_info
            (clist_nodes, event->x, event->y, &row, &col))
		return FALSE;

    gtk_menu_popup(
        GTK_MENU(popup_nodes), NULL, NULL, NULL, NULL, 
        event->button, event->time);

	return TRUE;
}

static void remove_selected_nodes(void)
{
    GList *node_list = NULL;
    
    node_list = clist_collect_data(main_window, "clist_nodes", FALSE, FALSE);
    node_remove_nodes_by_handle(node_list);
    g_list_free(node_list);
}

static void add_node(void)
{
    gchar *addr;
    GtkEditable *editable = GTK_EDITABLE
        (lookup_widget(main_window, "entry_host"));

    addr = gtk_editable_get_chars(editable, 0, -1);

    nodes_cb_connect_by_name(addr);

    g_free(addr);

    gtk_entry_set_text(GTK_ENTRY(editable), "");
}

void on_popup_nodes_remove_activate(GtkMenuItem *menuitem, gpointer user_data)
{
    remove_selected_nodes();
}

void on_button_nodes_remove_clicked(GtkButton *button, gpointer user_data)
{
    remove_selected_nodes();
}

void on_button_nodes_add_clicked(GtkButton * button, gpointer user_data)
{
    add_node();
}

void on_entry_host_activate(GtkEditable * editable, gpointer user_data)
{
    add_node();
}

void on_entry_host_changed(GtkEditable * editable, gpointer user_data)
{
	gchar *e = gtk_editable_get_chars(editable, 0, -1);
	g_strstrip(e);

	gtk_widget_set_sensitive(
        lookup_widget(main_window, "button_nodes_add"),
        is_string_ip(e));

	g_free(e);
}
