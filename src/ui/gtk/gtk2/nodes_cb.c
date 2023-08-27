/*
 * Copyright (c) 2001-2003, Raphael Manfredi, Richard Eckart
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
 *      51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *----------------------------------------------------------------------
 */

/**
 * @ingroup gtk
 * @file
 *
 * GUI filtering functions.
 *
 * @author Raphael Manfredi
 * @author Richard Eckart
 * @date 2001-2003
 */

#include "gtk/gui.h"

#include "nodes_cb.h"
#include "gtk/gtkcolumnchooser.h"
#include "gtk/nodes_common.h"

#include "if/bridge/ui2c.h"

#include "lib/iso3166.h"
#include "lib/override.h"		/* Must be the last header included */

static void
add_node(void)
{
    GtkEditable *editable;
    gchar *addr;

    editable = GTK_EDITABLE(gui_main_window_lookup("entry_host"));
    addr = STRTRACK(gtk_editable_get_chars(editable, 0, -1));
    nodes_gui_common_connect_by_name(addr);
    G_FREE_NULL(addr);
    gtk_entry_set_text(GTK_ENTRY(editable), "");
}

void
on_button_nodes_disconnect_clicked(GtkButton *unused_button,
	gpointer unused_udata)
{
	(void) unused_button;
	(void) unused_udata;
	nodes_gui_remove_selected();
}

void
on_popup_nodes_disconnect_activate(GtkItem *unused_item, gpointer unused_udata)
{
	(void) unused_item;
	(void) unused_udata;
	nodes_gui_remove_selected();
}

void
on_popup_nodes_reverse_lookup_activate(GtkItem *unused_item,
		gpointer unused_udata)
{
	(void) unused_item;
	(void) unused_udata;
	nodes_gui_reverse_lookup_selected();
}

void
on_button_nodes_add_clicked(GtkButton *unused_button, gpointer unused_udata)
{
	(void) unused_button;
	(void) unused_udata;
    add_node();
}

void
on_entry_host_activate(GtkEditable *unused_editable, gpointer unused_udata)
{
	(void) unused_editable;
	(void) unused_udata;
    add_node();
}

void
on_entry_host_changed(GtkEditable *editable, gpointer unused_udata)
{
	gchar *e;

	(void) unused_udata;
	e = STRTRACK(gtk_editable_get_chars(editable, 0, -1));
	g_strstrip(e);
	gtk_widget_set_sensitive(gui_main_window_lookup("button_nodes_add"),
        e[0] != '\0');
	G_FREE_NULL(e);
}

/**
 * Creates and pops up the column chooser for ``treeview_nodes''
 */
gboolean
on_popup_nodes_config_cols_activate(GtkItem *unused_menuitem,
	gpointer unused_udata)
{
    GtkWidget *cc;

	(void) unused_menuitem;
	(void) unused_udata;
    cc = gtk_column_chooser_new(gui_main_window_lookup("treeview_nodes"));
    gtk_menu_popup(GTK_MENU(cc), NULL, NULL, NULL, NULL, 1,
		gtk_get_current_event_time());

    /* GtkColumnChooser takes care of cleaning up itself */
	return TRUE;
}

/**
 * Initiates a browse host request to the currently selected host.
 */
void
on_popup_nodes_browse_host_activate(GtkMenuItem *unused_menuitem,
	gpointer unused_udata)
{
	(void) unused_menuitem;
	(void) unused_udata;

	nodes_gui_browse_selected();
}

/* vi: set ts=4 sw=4 cindent: */
