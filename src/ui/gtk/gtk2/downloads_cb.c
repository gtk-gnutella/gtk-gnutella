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

GSList *fi_gui_download_select(gboolean unselect);
void fi_gui_select_by_regex(const gchar *regex);

/***
 *** Popup menu: downloads
 ***/

/**
 * Informs the user about the number of removed downloads.
 *
 * @param removed amount of removed downloads.
 */
static void
show_removed(guint removed)
{
    statusbar_gui_message(15,
		NG_("Removed %u download", "Removed %u downloads", removed),
		removed);
}

static void
push_activate(void)
{
	GSList *sl, *selected;
	gboolean send_pushes, firewalled;

   	gnet_prop_get_boolean_val(PROP_SEND_PUSHES, &send_pushes);
   	gnet_prop_get_boolean_val(PROP_IS_FIREWALLED, &firewalled);

   	if (firewalled || !send_pushes)
       	return;

	selected = fi_gui_download_select(TRUE);
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
on_popup_downloads_push_activate(GtkMenuItem *unused_menuitem,
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
on_popup_downloads_browse_host_activate(GtkMenuItem *unused_menuitem,
	gpointer unused_udata)
{
	GSList *sl, *selected;

	(void) unused_menuitem;
	(void) unused_udata;

   	selected = fi_gui_download_select(TRUE);
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
 * the same name.
 */
void
on_popup_downloads_abort_named_activate(GtkMenuItem *unused_menuitem,
	gpointer unused_udata)
{
	GSList *sl, *selected;
    guint removed = 0;

	(void) unused_menuitem;
	(void) unused_udata;

	selected = fi_gui_download_select(TRUE);
	if (!selected)
		return;

   	for (sl = selected; sl; sl = g_slist_next(sl)) {
		struct download *d = sl->data;
		removed += guc_download_remove_all_named(d->file_name);
	}
	g_slist_free(selected);

	show_removed(removed);
}


/**
 * For all selected active downloads, remove all downloads with
 * the same host.
 */
/* XXX: routing misnamed: we're "forgetting" here, not "aborting" */
void
on_popup_downloads_abort_host_activate(GtkMenuItem *unused_menuitem,
	gpointer unused_udata)
{
	GSList *sl, *selected;
    guint removed = 0;

	(void) unused_menuitem;
	(void) unused_udata;

	selected = fi_gui_download_select(TRUE);
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


/**
 * For all selected active downloads, remove all downloads with
 * the same sha1.
 */
void
on_popup_downloads_abort_sha1_activate(GtkMenuItem *unused_menuitem,
	gpointer unused_udata)
{
	GSList *sl, *selected;
    guint removed = 0;

	(void) unused_menuitem;
	(void) unused_udata;

	selected = fi_gui_download_select(TRUE);
	if (!selected)
		return;

   	for (sl = selected; sl; sl = g_slist_next(sl)) {
		struct download *d = sl->data;

		if (d->file_info->sha1)
			removed += guc_download_remove_all_with_sha1(d->file_info->sha1);
	}
	g_slist_free(selected);

    show_removed(removed);
}


/**
 * For all selected active downloads, remove file.
 */
void on_popup_downloads_remove_file_activate(GtkMenuItem *unused_menuitem,
     gpointer unused_udata)
{
	GSList *sl, *selected;

	(void) unused_menuitem;
	(void) unused_udata;

	selected = fi_gui_download_select(TRUE);
	if (!selected)
		return;

	/*
	 * We request a reset of the fileinfo to prevent discarding
	 * should we relaunch: non-reset fileinfos are discarded if the file
	 * is missing.
	 *		--RAM, 04/01/2003.
	 */

   	for (sl = selected; sl; sl = g_slist_next(sl)) {
		struct download *d = sl->data;

    	if (d->status != GTA_DL_ERROR && d->status != GTA_DL_ABORTED)
			continue;

		if (guc_download_file_exists(d))
			guc_download_remove_file(d, TRUE);
	}
	g_slist_free(selected);
}

static void
copy_selection_to_clipboard(void)
{
	GSList *sl, *selected;

   	selected = fi_gui_download_select(TRUE);
	if (!selected)
		return;

	for (sl = selected; sl; sl = g_slist_next(sl)) {
		struct download *d = sl->data;
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
on_popup_downloads_copy_url_activate(GtkMenuItem *unused_menuitem,
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
on_popup_downloads_connect_activate(GtkMenuItem *unused_menuitem,
	gpointer unused_udata)
{
	GSList *sl, *selected;

	(void) unused_menuitem;
	(void) unused_udata;

   	selected = fi_gui_download_select(TRUE);
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

   	selected = fi_gui_download_select(TRUE);
	if (!selected)
		return;

	for (sl = selected; sl; sl = g_slist_next(sl)) {
		struct download *d = sl->data;
		guc_download_start(d, TRUE);
   	}
	g_slist_free(selected);
}

/**
 * For all selected downloads, remove them.
 */
void
on_popup_downloads_remove_activate(GtkMenuItem *unused_menuitem,
	gpointer unused_udata)
{
	GSList *sl, *selected;

	(void) unused_menuitem;
	(void) unused_udata;

   	selected = fi_gui_download_select(TRUE);
	if (!selected)
		return;

	for (sl = selected; sl; sl = g_slist_next(sl)) {
		struct download *d = sl->data;
		guc_download_remove_file(d, TRUE);
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

   	selected = fi_gui_download_select(TRUE);
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

   	selected = fi_gui_download_select(TRUE);
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
	GSList *sl, *selected;

	(void) unused_menuitem;
	(void) unused_udata;

   	selected = fi_gui_download_select(TRUE);
	if (!selected)
		return;

	for (sl = selected; sl; sl = g_slist_next(sl)) {
		struct download *d = sl->data;
		guc_download_abort(d);
   	}
	g_slist_free(selected);
}


/***
 *** downloads pane
 ***/


/**
 * For all selected active downloads, forget them.
 */
void
on_button_downloads_abort_clicked(GtkButton *unused_button,
	gpointer unused_udata)
{
	GSList *selected, *sl;

	(void) unused_button;
	(void) unused_udata;

   	selected = fi_gui_download_select(TRUE);
	if (!selected)
		return;

	for (sl = selected; sl; sl = g_slist_next(sl)) {
		struct download *d = sl->data;
		guc_download_abort(d);
	}
	g_slist_free(selected);
}



/**
 * For all selected active downloads, resume.
 */
void
on_button_downloads_resume_clicked(GtkButton *unused_button,
	gpointer unused_udata)
{
   	GSList *sl, *selected;

	(void) unused_button;
	(void) unused_udata;

   	selected = fi_gui_download_select(TRUE);
	if (!selected)
		return;

	for (sl = selected; sl; sl = g_slist_next(sl)) {
		struct download *d = sl->data;
     	guc_download_resume(d);
	}
	g_slist_free(selected);

	gui_update_download_abort_resume();
	gui_update_download_clear();
}

void
on_popup_downloads_config_cols_activate(GtkMenuItem *unused_menuitem,
	gpointer unused_udata)
{
    GtkWidget *cc;

	(void) unused_menuitem;
	(void) unused_udata;

    cc = gtk_column_chooser_new(
			GTK_WIDGET(gui_main_window_lookup("treeview_downloads")));
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

void
on_treeview_downloads_select_row(GtkTreeView *tree_view,
	gpointer unused_udata)
{
	GtkTreeSelection *selection;
   	GSList *selected;
    gboolean activate;

	(void) unused_udata;

	/* The user selects a row(s) in the downloads treeview
	 * we unselect all rows in the downloads tree view
	 */
	tree_view = GTK_TREE_VIEW(gui_main_window_lookup("treeview_downloads"));
	selection = gtk_tree_view_get_selection(tree_view);
	gtk_tree_selection_unselect_all(selection);

   	selected = fi_gui_download_select(FALSE);
	activate = NULL != selected && g_slist_next(selected) == NULL;
	g_slist_free(selected);
	selected = NULL;

    gtk_widget_set_sensitive(
		gui_popup_downloads_lookup("popup_downloads_copy_url"), activate);
   	gtk_widget_set_sensitive(
		gui_popup_downloads_lookup("popup_downloads_connect"), activate);

	/* Takes care of other widgets */
	gui_update_download_abort_resume();
}

void
on_popup_downloads_expand_all_activate(GtkMenuItem *unused_menuitem,
	gpointer unused_udata)
{
	(void) unused_menuitem;
	(void) unused_udata;

	downloads_gui_expand_all();
}

void
on_popup_downloads_collapse_all_activate(GtkMenuItem *unused_menuitem,
	gpointer unused_udata)
{
	(void) unused_menuitem;
	(void) unused_udata;

	downloads_gui_collapse_all();
}

/* vi: set ts=4 sw=4 cindent: */
