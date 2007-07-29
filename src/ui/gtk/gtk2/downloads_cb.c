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

#include "gtk/gui.h"

RCSID("$Id$")

#include "downloads_cb.h"
#include "gtk/downloads.h"
#include "gtk/downloads_common.h"
#include "gtk/statusbar.h"
#include "gtk/gtkcolumnchooser.h"
#include "gtk/columns.h"
#include "gtk/search_common.h"

#include "if/gnet_property.h"
#include "if/gui_property_priv.h"
#include "if/bridge/ui2c.h"
#include "if/core/sockets.h"

#include "lib/override.h"		/* Must be the last header included */

void fi_gui_select_by_regex(const gchar *regex);
GSList *fi_gui_sources_select(gboolean unselect);
GSList *fi_gui_files_select(gboolean unselect);
GSList *fi_gui_sources_of_selected_files(gboolean unselect);
GtkTreeView *fi_gui_current_treeview(void);

/***
 *** Popup menu: downloads
 ***/

static void
push_activate(void)
{
	GSList *sl, *selected;
	gboolean send_pushes, firewalled;

   	gnet_prop_get_boolean_val(PROP_SEND_PUSHES, &send_pushes);
   	gnet_prop_get_boolean_val(PROP_IS_FIREWALLED, &firewalled);

   	if (firewalled || !send_pushes)
       	return;

	selected = fi_gui_sources_select(TRUE);
	if (!selected)
		return;

	for (sl = selected; sl; sl = g_slist_next(sl)) {
		struct download *d = sl->data;
		guc_download_fallback_to_push(d, FALSE, TRUE);
	}
	g_slist_free(selected);
}


/**
 * Causes all selected active downloads to fall back to push.
 */
void
on_popup_sources_push_activate(GtkMenuItem *unused_menuitem,
	gpointer unused_udata)
{
	(void) unused_menuitem;
	(void) unused_udata;

	push_activate();
}

/**
 * Initiates a browse host request to the currently selected host.
 */
void
on_popup_sources_browse_host_activate(GtkMenuItem *unused_menuitem,
	gpointer unused_udata)
{
	GSList *sl, *selected;

	(void) unused_menuitem;
	(void) unused_udata;

   	selected = fi_gui_sources_select(TRUE);
	if (!selected)
		return;

	for (sl = selected; sl; sl = g_slist_next(sl)) {
		const struct download *d = sl->data;
   		search_gui_new_browse_host(
			download_hostname(d), download_addr(d), download_port(d),
			download_guid(d), NULL, 0);
	}
	g_slist_free(selected);
}

/**
 * For all selected active downloads, remove all downloads with
 * the same host.
 */
void
on_popup_sources_forget_activate(GtkMenuItem *unused_menuitem,
	gpointer unused_udata)
{
	GSList *sl, *selected;
    guint removed = 0;

	(void) unused_menuitem;
	(void) unused_udata;

	selected = fi_gui_sources_select(TRUE);
	if (!selected)
		return;

   	for (sl = selected; sl; sl = g_slist_next(sl)) {
		struct download *d = sl->data;
		removed += guc_download_remove_all_from_peer(download_guid(d),
						download_addr(d), download_port(d), FALSE);
	}
	g_slist_free(selected);

    statusbar_gui_message(15,
		NG_("Forgot %u download", "Forgot %u downloads", removed),
		removed);
}

static void
copy_selection_to_clipboard(void)
{
	GSList *selected;

   	selected = fi_gui_sources_select(TRUE);
	if (selected) {
		struct download *d = selected->data;
		gchar *url;

		gtk_clipboard_clear(gtk_clipboard_get(GDK_SELECTION_PRIMARY));
		gtk_clipboard_clear(gtk_clipboard_get(GDK_SELECTION_CLIPBOARD));

       	url = guc_download_build_url(d);
		if (url) {
			gtk_clipboard_set_text(gtk_clipboard_get(GDK_SELECTION_PRIMARY),
					url, -1);
			gtk_clipboard_set_text(gtk_clipboard_get(GDK_SELECTION_CLIPBOARD),
					url, -1);
		}
		G_FREE_NULL(url);
	}
	g_slist_free(selected);
}

/**
 * For selected download, copy URL to clipboard.
 */
void
on_popup_sources_copy_url_activate(GtkMenuItem *unused_menuitem,
	gpointer unused_udata)
{
	(void) unused_menuitem;
	(void) unused_udata;

	copy_selection_to_clipboard();
}


/**
 * For all selected active downloads connect to host.
 */
void
on_popup_sources_connect_activate(GtkMenuItem *unused_menuitem,
	gpointer unused_udata)
{
	GSList *sl, *selected;

	(void) unused_menuitem;
	(void) unused_udata;

   	selected = fi_gui_sources_select(TRUE);
	if (!selected)
		return;

	for (sl = selected; sl; sl = g_slist_next(sl)) {
		const struct download *d = sl->data;
   		guc_node_add(download_addr(d), download_port(d), SOCK_F_FORCE);
   	}
	g_slist_free(selected);
}

/**
 * For all selected downloads, activate them.
 */
void
on_popup_downloads_start_now_activate(GtkMenuItem *unused_menuitem,
	gpointer unused_udata)
{
	GSList *sl, *selected;

	(void) unused_menuitem;
	(void) unused_udata;

   	selected = fi_gui_sources_of_selected_files(TRUE);
	if (!selected)
		return;

	for (sl = selected; sl; sl = g_slist_next(sl)) {
		struct download *d = sl->data;
		guc_download_start(d, TRUE);
   	}
	g_slist_free(selected);
}

/**
 * For all selected downloads, activate them.
 */
void
on_popup_sources_start_now_activate(GtkMenuItem *unused_menuitem,
	gpointer unused_udata)
{
	GSList *sl, *selected;

	(void) unused_menuitem;
	(void) unused_udata;

   	selected = fi_gui_sources_select(TRUE);
	if (!selected)
		return;

	for (sl = selected; sl; sl = g_slist_next(sl)) {
		struct download *d = sl->data;
		guc_download_start(d, TRUE);
   	}
	g_slist_free(selected);
}

/**
 * For all selected downloads, activate them.
 */
void
on_popup_downloads_pause_activate(GtkMenuItem *unused_menuitem,
	gpointer unused_udata)
{
	GSList *sl, *selected;

	(void) unused_menuitem;
	(void) unused_udata;

   	selected = fi_gui_sources_of_selected_files(TRUE);
	if (!selected)
		return;

	for (sl = selected; sl; sl = g_slist_next(sl)) {
		struct download *d = sl->data;
		guc_download_pause(d);
   	}
	g_slist_free(selected);
}

/**
 * For all selected downloads, activate them.
 */
void
on_popup_sources_pause_activate(GtkMenuItem *unused_menuitem,
	gpointer unused_udata)
{
	GSList *sl, *selected;

	(void) unused_menuitem;
	(void) unused_udata;

   	selected = fi_gui_sources_select(TRUE);
	if (!selected)
		return;

	for (sl = selected; sl; sl = g_slist_next(sl)) {
		struct download *d = sl->data;
		guc_download_pause(d);
   	}
	g_slist_free(selected);
}

/**
 * For all selected downloads, resume them.
 */
void
on_popup_downloads_resume_activate(GtkMenuItem *unused_menuitem,
	gpointer unused_udata)
{
	GSList *sl, *selected;

	(void) unused_menuitem;
	(void) unused_udata;

   	selected = fi_gui_sources_of_selected_files(TRUE);
	if (!selected)
		return;

	for (sl = selected; sl; sl = g_slist_next(sl)) {
		struct download *d = sl->data;
		guc_download_resume(d);
   	}
	g_slist_free(selected);
}

/**
 * For all selected downloads, resume them.
 */
void
on_popup_sources_resume_activate(GtkMenuItem *unused_menuitem,
	gpointer unused_udata)
{
	GSList *sl, *selected;

	(void) unused_menuitem;
	(void) unused_udata;

   	selected = fi_gui_sources_select(TRUE);
	if (!selected)
		return;

	for (sl = selected; sl; sl = g_slist_next(sl)) {
		struct download *d = sl->data;
		guc_download_resume(d);
   	}
	g_slist_free(selected);
}

/**
 * For all selected downloads, queue them.
 */
void
on_popup_downloads_queue_activate(GtkMenuItem *unused_menuitem,
	gpointer unused_udata)
{
	GSList *sl, *selected;

	(void) unused_menuitem;
	(void) unused_udata;

   	selected = fi_gui_sources_of_selected_files(TRUE);
	if (!selected)
		return;

	for (sl = selected; sl; sl = g_slist_next(sl)) {
		struct download *d = sl->data;
		guc_download_requeue(d);
   	}
	g_slist_free(selected);
}

/**
 * For all selected downloads, queue them.
 */
void
on_popup_sources_queue_activate(GtkMenuItem *unused_menuitem,
	gpointer unused_udata)
{
	GSList *sl, *selected;

	(void) unused_menuitem;
	(void) unused_udata;

   	selected = fi_gui_sources_select(TRUE);
	if (!selected)
		return;

	for (sl = selected; sl; sl = g_slist_next(sl)) {
		struct download *d = sl->data;
		guc_download_requeue(d);
   	}
	g_slist_free(selected);
}

/**
 * For all selected downloads, queue them.
 */
void
on_popup_downloads_abort_activate(GtkMenuItem *unused_menuitem,
	gpointer unused_udata)
{
	(void) unused_menuitem;
	(void) unused_udata;

	guc_fi_purge_by_handle_list(fi_gui_files_select(TRUE));
}

/***
 *** downloads pane
 ***/


void
on_popup_downloads_config_cols_activate(GtkMenuItem *unused_menuitem,
	gpointer unused_udata)
{
    GtkWidget *cc;

	(void) unused_menuitem;
	(void) unused_udata;

    cc = gtk_column_chooser_new(GTK_WIDGET(fi_gui_current_treeview()));
    gtk_menu_popup(GTK_MENU(cc), NULL, NULL, NULL, NULL, 1, 0);
}

void
on_popup_sources_config_cols_activate(GtkMenuItem *unused_menuitem,
	gpointer unused_udata)
{
    GtkWidget *widget, *cc;

	(void) unused_menuitem;
	(void) unused_udata;

	widget = gui_main_window_lookup("treeview_download_sources");
    cc = gtk_column_chooser_new(GTK_WIDGET(widget));
    gtk_menu_popup(GTK_MENU(cc), NULL, NULL, NULL, NULL, 1, 0);
}

/***
 *** Queued downloads
 ***/


/**
 * Select all downloads that match given regex in editable.
 */
void
on_entry_regex_activate(GtkEditable *editable, gpointer unused_udata)
{
    gchar *regex;

	(void) unused_udata;

    regex = STRTRACK(gtk_editable_get_chars(GTK_EDITABLE(editable), 0, -1));
	g_return_if_fail(regex != NULL);

	fi_gui_select_by_regex(regex);
	G_FREE_NULL(regex);
}


/**
 * When the right mouse button is clicked on the active downloads
 * treeview, show the popup with the context menu.
 */
gboolean
on_treeview_downloads_button_press_event(GtkWidget *widget,
	GdkEventButton *event, gpointer unused_udata)
{
	(void) unused_udata;

	if (event->button != 3)
		return FALSE;

	if (NULL == gtk_tree_view_get_selection(GTK_TREE_VIEW(widget)))
		return FALSE;

    gtk_menu_popup(GTK_MENU(gui_popup_downloads()), NULL, NULL, NULL, NULL,
        event->button, event->time);

	return TRUE;
}

/**
 * When the right mouse button is clicked on the active downloads
 * treeview, show the popup with the context menu.
 */
gboolean
on_treeview_sources_button_press_event(GtkWidget *widget,
	GdkEventButton *event, gpointer unused_udata)
{
	(void) unused_udata;

	if (event->button != 3)
		return FALSE;

	if (NULL == gtk_tree_view_get_selection(GTK_TREE_VIEW(widget)))
		return FALSE;

    gtk_menu_popup(GTK_MENU(gui_popup_sources()), NULL, NULL, NULL, NULL,
        event->button, event->time);

	return TRUE;
}

/* vi: set ts=4 sw=4 cindent: */
