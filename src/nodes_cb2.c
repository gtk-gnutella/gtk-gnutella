/*
 * $Id$
 *
 * Copyright (c) 2001-2003, Raphael Manfredi, Richard Eckart
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

#include "gui.h"

#include "adns.h"
#include "nodes_cb2.h"
#include "settings_gui.h"
#include "statusbar_gui.h"

RCSID("$Id$");

static void add_node_helper(guint32 ip, gpointer port)
{
	node_add(ip, GPOINTER_TO_UINT(port));
}

/*
 * nodes_cb_connect_by_name:
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
        statusbar_gui_warning(15, "Port must be between 1 and 65535");
    } else {
		adns_resolve(e, add_node_helper, GUINT_TO_POINTER((guint) port));
	}

    g_free(e);
}

static void add_node(void)
{
    gchar *addr;
    GtkEditable *editable = GTK_EDITABLE
        (lookup_widget(main_window, "entry_host"));

    addr = gtk_editable_get_chars(editable, 0, -1);
    nodes_cb_connect_by_name(addr);
    G_FREE_NULL(addr);
    gtk_entry_set_text(GTK_ENTRY(editable), "");
}

void on_button_nodes_remove_clicked(GtkButton *button, gpointer user_data)
{
	nodes_gui_remove_selected();
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
    gchar *p;
	gchar *e = gtk_editable_get_chars(editable, 0, -1);
	g_strstrip(e);

    /* Strip away port, if any. */
    if((p = strchr(e, ':')) != NULL)
        *p = '\0';
    
	gtk_widget_set_sensitive(
        lookup_widget(main_window, "button_nodes_add"),
        is_string_ip(e));

	g_free(e);
}
