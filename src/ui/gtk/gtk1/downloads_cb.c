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

#include "gtk/downloads.h"
#include "gtk/downloads_common.h"
#include "gtk/statusbar.h"
#include "gtk/gtk-missing.h"
#include "gtk/search.h"
#include "downloads_cb.h"

#include "if/bridge/ui2c.h"
#include "if/core/sockets.h"
#include "if/gui_property_priv.h"

#include "lib/override.h"	/* Must be the last header included */

static gchar *selected_url = NULL;
static gboolean refresh_on_release = FALSE;

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

/***
 *** Downloads pane
 ***/
void
on_ctree_downloads_tree_select_row(GtkCTree *ctree, GList *node,
	gint unused_column, gpointer unused_udata)
{
	gboolean activate = FALSE;
	struct download *d;
    GList *selection;

	(void) unused_column;
	(void) unused_udata;

	gui_update_download_abort_resume();

	d = gtk_ctree_node_get_row_data(ctree, GTK_CTREE_NODE(node));
	if (DL_GUI_IS_HEADER == d)
		return;

    selection = GTK_CLIST(ctree)->selection;

    activate = (selection != NULL) &&
        (selection->next == NULL) &&
        (!GTK_CTREE_NODE_HAS_CHILDREN(selection->data));

    gtk_widget_set_sensitive
        (lookup_widget(popup_downloads, "popup_downloads_copy_url"), activate);
    gtk_widget_set_sensitive
        (lookup_widget(popup_downloads, "popup_downloads_connect"), activate);
}



void
on_ctree_downloads_tree_unselect_row(GtkCTree *ctree, GList *node,
	gint column, gpointer user_data)
{
	/* Update the popup visibility */
    on_ctree_downloads_tree_select_row(ctree, node, column, user_data);
}

void
on_ctree_downloads_resize_column(GtkCList *unused_clist,
	gint column, gint width, gpointer unused_udata)
{
	(void) unused_clist;
	(void) unused_udata;
	*(gint *) &dl_active_col_widths[column] = width;
}

gboolean
on_ctree_downloads_button_press_event(GtkWidget *widget,
	GdkEventButton *event, gpointer unused_udata)
{
	gint row;
    gint col;
    GList *selection;

	(void) unused_udata;

	refresh_on_release = event->button == 1;

	if (event->button != 3)
		return FALSE;

    selection = GTK_CLIST(widget)->selection;

	/* If no items are selected */
    if (selection == NULL) {
	    gtk_widget_set_sensitive
	        (lookup_widget(popup_downloads, "popup_downloads_abort"),
			FALSE);
	    gtk_widget_set_sensitive
	        (lookup_widget(popup_downloads, "popup_downloads_abort_named"),
			FALSE);
	    gtk_widget_set_sensitive
	        (lookup_widget(popup_downloads, "popup_downloads_abort_sha1"),
			FALSE);
	    gtk_widget_set_sensitive
	        (lookup_widget(popup_downloads, "popup_downloads_abort_host"),
			FALSE);
	    gtk_widget_set_sensitive
	        (lookup_widget(popup_downloads, "popup_downloads_remove_file"),
			FALSE);
	    gtk_widget_set_sensitive
	        (lookup_widget(popup_downloads, "popup_downloads_resume"),
			FALSE);
	    gtk_widget_set_sensitive
	        (lookup_widget(popup_downloads, "popup_downloads_queue"),
			FALSE);
	    gtk_widget_set_sensitive
	        (lookup_widget(popup_downloads, "popup_downloads_push"),
			FALSE);
	    gtk_widget_set_sensitive
 	        (lookup_widget(popup_downloads, "popup_downloads_copy_url"),
			FALSE);
	    gtk_widget_set_sensitive
	        (lookup_widget(popup_downloads, "popup_downloads_connect"),
			FALSE);
	} else if (GTK_CTREE_NODE_HAS_CHILDREN(selection->data)) {
	    gtk_widget_set_sensitive
 	        (lookup_widget(popup_downloads, "popup_downloads_copy_url"),
			FALSE);
	    gtk_widget_set_sensitive
	        (lookup_widget(popup_downloads, "popup_downloads_connect"),
			FALSE);
    }

	if (!gtk_clist_get_selection_info
		(GTK_CLIST(widget), event->x, event->y, &row, &col))
		return FALSE;

    gtk_menu_popup(
        GTK_MENU(popup_downloads), NULL, NULL, NULL, NULL,
        event->button, event->time);

	return TRUE;
}

gboolean
on_ctree_downloads_button_release_event(GtkWidget *unused_widget,
	GdkEventButton *unused_event, gpointer unused_data)
{
	(void) unused_widget;
	(void) unused_event;
	(void) unused_data;

	if (refresh_on_release)
		downloads_update_active_pane();

	return FALSE;
}

/***
 *** Popup menu: downloads
 ***/

/**
 *	All selected downloads fallback to push
 */
void
on_popup_downloads_push_activate(GtkMenuItem *unused_menuitem,
	gpointer unused_udata)
{
   	struct download *d;
    GList *node_list;
    GList *data_list;
    GList *l;
    GtkCTree *ctree_downloads = GTK_CTREE
        (lookup_widget(main_window, "ctree_downloads"));
    GtkCTree *ctree_downloads_queue = GTK_CTREE
        (lookup_widget(main_window, "ctree_downloads_queue"));

	(void) unused_menuitem;
	(void) unused_udata;
    gtk_clist_freeze(GTK_CLIST(ctree_downloads_queue));
    gtk_clist_freeze(GTK_CLIST(ctree_downloads));
	node_list = g_list_copy(GTK_CLIST(ctree_downloads)->selection);
	data_list = downloads_gui_collect_ctree_data(ctree_downloads,
		node_list, TRUE, TRUE);

	for (l = data_list; NULL != l; l = g_list_next(l)) {
		d = (struct download *) l->data;

        if (!d) {
			g_warning("on_popup_downloads_push_activate(): "
				"row has NULL data");
		    continue;
        }
     	guc_download_fallback_to_push(d, FALSE, TRUE);
	}

    gtk_clist_thaw(GTK_CLIST(ctree_downloads_queue));
    gtk_clist_thaw(GTK_CLIST(ctree_downloads));
	g_list_free(data_list);
	g_list_free(node_list);
}

/**
 * Initiate a "browse host" on the selection in the given tree
 */
static void
browse_host_selected(GtkCTree *ctree)
{
    struct download *d;
    GList *node_list;
    GList *data_list;
    GList *l;

	node_list = g_list_copy(GTK_CLIST(ctree)->selection);
	data_list = downloads_gui_collect_ctree_data(ctree, node_list, TRUE, TRUE);

	for (l = data_list; NULL != l; l = g_list_next(l)) {
		d = l->data;

		if (!d) {
			g_warning("on_popup_downloads_browse_host_activate():"
                " row has NULL data");
			continue;
		}

		search_gui_new_browse_host(
			download_hostname(d), download_addr(d), download_port(d),
			download_guid(d), NULL, 0);
	}

	g_list_free(data_list);
	g_list_free(node_list);
}

/**
 * Initiates a browse host request to the currently selected host.
 */
void
on_popup_downloads_browse_host_activate(GtkMenuItem *unused_menuitem,
	gpointer unused_udata)
{
    GtkCTree *ctree_downloads = GTK_CTREE
        (lookup_widget(main_window, "ctree_downloads"));

	(void) unused_menuitem;
	(void) unused_udata;

	browse_host_selected(ctree_downloads);
}

/**
 * Initiates a browse host request to the currently selected host.
 */
void
on_popup_queue_browse_host_activate(GtkMenuItem *unused_menuitem,
	gpointer unused_udata)
{
    GtkCTree *ctree_downloads_queue = GTK_CTREE
        (lookup_widget(main_window, "ctree_downloads_queue"));

	(void) unused_menuitem;
	(void) unused_udata;

	browse_host_selected(ctree_downloads_queue);
}

/**
 *	Abort all downloads with names identical to any of the selected downloads
 */
void
on_popup_downloads_abort_named_activate(GtkMenuItem *unused_menuitem,
	gpointer unused_udata)
{
   	struct download *d;
    GList *node_list;
    GList *data_list;
    GList *l;
    GtkCTree *ctree_downloads = GTK_CTREE
        (lookup_widget(main_window, "ctree_downloads"));
    GtkCTree *ctree_downloads_queue = GTK_CTREE
        (lookup_widget(main_window, "ctree_downloads_queue"));
    guint removed = 0;

	(void) unused_menuitem;
	(void) unused_udata;
    gtk_clist_freeze(GTK_CLIST(ctree_downloads));
    gtk_clist_freeze(GTK_CLIST(ctree_downloads_queue));
	node_list = g_list_copy(GTK_CLIST(ctree_downloads)->selection);
	data_list = downloads_gui_collect_ctree_data(ctree_downloads,
		node_list, TRUE, FALSE);

	for (l = data_list; NULL != l; l = g_list_next(l)) {
		d = (struct download *) l->data;

		if (!d) {
			g_warning("on_popup_downloads_abort_named_activate():"
                " row has NULL data");
			continue;
		}
		removed += guc_download_remove_all_named(d->file_name);
	}

	g_list_free(data_list);
	g_list_free(node_list);
    gtk_clist_thaw(GTK_CLIST(ctree_downloads_queue));
    gtk_clist_thaw(GTK_CLIST(ctree_downloads));

    show_removed(removed);
}


/**
 *	Abort all downloads with hosts identical to any of the selected downloads
 */
void
on_popup_downloads_abort_host_activate(GtkMenuItem *unused_menuitem,
	gpointer unused_udata)
{
	/* XXX routing misnamed: we're "forgetting" here, not "aborting" */
    struct download *d;
    GList *node_list;
    GList *data_list;
    GList *l;
    GtkCTree *ctree_downloads = GTK_CTREE
        (lookup_widget(main_window, "ctree_downloads"));
    GtkCTree *ctree_downloads_queue = GTK_CTREE
        (lookup_widget(main_window, "ctree_downloads_queue"));
    guint removed = 0;

	(void) unused_menuitem;
	(void) unused_udata;
	gtk_clist_freeze(GTK_CLIST(ctree_downloads));
    gtk_clist_freeze(GTK_CLIST(ctree_downloads_queue));
	node_list = g_list_copy(GTK_CLIST(ctree_downloads)->selection);
	data_list = downloads_gui_collect_ctree_data(ctree_downloads,
		node_list, TRUE, TRUE);

	for (l = data_list; NULL != l; l = g_list_next(l)) {
		d = (struct download *) l->data;

		if (!d) {
			g_warning("on_popup_downloads_abort_host_activate():"
                " row has NULL data");
			continue;
		}
		removed += guc_download_remove_all_from_peer(
			download_guid(d), download_addr(d),
			download_port(d), FALSE);
	}

	g_list_free(data_list);
	g_list_free(node_list);
    gtk_clist_thaw(GTK_CLIST(ctree_downloads_queue));
    gtk_clist_thaw(GTK_CLIST(ctree_downloads));

    statusbar_gui_message(15,
		NG_("Forgot %u download", "Forgot %u downloads", removed),
		removed);
}



/**
 *	Abort all downloads with sha1s identical to any of the selected downloads
 */
void
on_popup_downloads_abort_sha1_activate(GtkMenuItem *unused_menuitem,
	gpointer unused_udata)
{
   	struct download *d;
    GList *node_list;
    GList *data_list;
    GList *l;
    GtkCTree *ctree_downloads = GTK_CTREE
        (lookup_widget(main_window, "ctree_downloads"));
    GtkCTree *ctree_downloads_queue = GTK_CTREE
        (lookup_widget(main_window, "ctree_downloads_queue"));
    guint removed = 0;

	(void) unused_menuitem;
	(void) unused_udata;
    gtk_clist_freeze(GTK_CLIST(ctree_downloads));
    gtk_clist_freeze(GTK_CLIST(ctree_downloads_queue));
	node_list = g_list_copy(GTK_CLIST(ctree_downloads)->selection);
	data_list = downloads_gui_collect_ctree_data(ctree_downloads,
		node_list, TRUE, FALSE);

	for (l = data_list; NULL != l; l = g_list_next(l)) {
		d = (struct download *) l->data;

		if (!d) {
			g_warning("on_popup_downloads_abort_sha1_activate():"
                " row has NULL data");
			continue;
		}

        if (d->file_info->sha1 != NULL)
            removed += guc_download_remove_all_with_sha1(d->file_info->sha1);
	}

	g_list_free(data_list);
	g_list_free(node_list);
    gtk_clist_thaw(GTK_CLIST(ctree_downloads_queue));
    gtk_clist_thaw(GTK_CLIST(ctree_downloads));

    show_removed(removed);
}


/**
 *	Remove all downloads selected
 */
void
on_popup_downloads_remove_file_activate(GtkMenuItem *unused_menuitem,
	gpointer unused_udata)
{
	struct download *d;
    GList *node_list;
    GList *data_list;
    GList *l;
    GtkCTree *ctree_downloads = GTK_CTREE
        (lookup_widget(main_window, "ctree_downloads"));

	(void) unused_menuitem;
	(void) unused_udata;
    gtk_clist_freeze(GTK_CLIST(ctree_downloads));

	node_list = g_list_copy(GTK_CLIST(ctree_downloads)->selection);
	data_list = downloads_gui_collect_ctree_data(ctree_downloads,
		node_list, TRUE, FALSE);

	for (l = data_list; NULL != l; l = g_list_next(l)) {
		d = (struct download *) l->data;

		if (DL_GUI_IS_HEADER == d)
			continue;

		if (!d) {
			g_warning("on_popup_downloads_remove_file_activate():"
                " row has NULL data");
			continue;
		}

		/*
		 * We request a resetting of the fileinfo to prevent discarding
		 * should we relaunch: non-reset fileinfos are discarded if the file
		 * is missing.
		 *		--RAM, 04/01/2003.
		 */

        if (
			(d->status == GTA_DL_ERROR || d->status == GTA_DL_ABORTED) &&
            guc_download_file_exists(d)
		)
           	guc_download_remove_file(d, TRUE);
	}

    gtk_clist_thaw(GTK_CLIST(ctree_downloads));

	g_list_free(data_list);
	g_list_free(node_list);
}


/**
 *	Move all selected downloads back to queue
 */
void
on_popup_downloads_queue_activate(GtkMenuItem *unused_menuitem,
	gpointer unused_udata)
{
   	struct download *d;
    GList *node_list;
    GList *data_list;
    GList *l;
    GtkCTree *ctree_downloads = GTK_CTREE
        (lookup_widget(main_window, "ctree_downloads"));
    GtkCTree *ctree_downloads_queue = GTK_CTREE
        (lookup_widget(main_window, "ctree_downloads_queue"));

	(void) unused_menuitem;
	(void) unused_udata;
    gtk_clist_freeze(GTK_CLIST(ctree_downloads));
    gtk_clist_freeze(GTK_CLIST(ctree_downloads_queue));
	node_list = g_list_copy(GTK_CLIST(ctree_downloads)->selection);
	data_list = downloads_gui_collect_ctree_data(ctree_downloads,
		node_list, TRUE, TRUE);

	for (l = data_list; NULL != l; l = g_list_next(l)) {
		d = (struct download *) l->data;

        if (!d) {
            g_warning("on_popup_downloads_queue_activate(): "
				"row has NULL data");
            continue;
        }
        guc_download_requeue(d);
	}

    gtk_clist_thaw(GTK_CLIST(ctree_downloads_queue));
    gtk_clist_thaw(GTK_CLIST(ctree_downloads));

	g_list_free(data_list);
	g_list_free(node_list);
}

void
on_popup_downloads_copy_url_activate(GtkMenuItem *unused_menuitem,
	gpointer unused_udata)
{
   	struct download * d = NULL;
    GtkCTree *ctree_downloads = GTK_CTREE
        (lookup_widget(main_window, "ctree_downloads"));
    GList *l = GTK_CLIST(ctree_downloads)->selection;

	(void) unused_menuitem;
	(void) unused_udata;
    g_return_if_fail(l);

    if (GTK_CTREE_NODE_HAS_CHILDREN(l->data))
        return;

    /*
     * note that we set the popup dialog as owner, because we can
     * connect the selection_* signals to that using glade.
     *      --BLUE, 24/04/2002
     */
    if (gtk_selection_owner_set(GTK_WIDGET(popup_downloads),
                                GDK_SELECTION_PRIMARY,
                                GDK_CURRENT_TIME)){
       	d = (struct download *)
            gtk_ctree_node_get_row_data(ctree_downloads, l->data);

        if (!d) {
           	g_warning("on_popup_downloads_copy_url(): row has NULL data");
		    return;
        }

        /*
         * if "copy url" is done repeatedly, we have to make sure the
         * memory of the previous selection is freed, because we may not
         * recieve a "selection_clear" signal.
         *      --BLUE, 24/04/2002
         */
        if (selected_url != NULL) {
            G_FREE_NULL(selected_url);
        }

        selected_url = guc_download_build_url(d);
    }
}


void
on_popup_downloads_connect_activate(GtkMenuItem *unused_menuitem,
	gpointer unused_udata)
{
	struct download *d;
   	GtkCTree *ctree_downloads = GTK_CTREE
		(lookup_widget(main_window, "ctree_downloads"));
    GList *l = GTK_CLIST(ctree_downloads)->selection;

	(void) unused_menuitem;
	(void) unused_udata;
    g_return_if_fail(l);

    if (GTK_CTREE_NODE_HAS_CHILDREN(l->data))
        return;

   	d = (struct download *)
    	gtk_ctree_node_get_row_data(ctree_downloads, l->data);

	if (!d) {
   		g_warning("on_popup_downloads_connect_activate():"
       	    "row has NULL data");
		return;
	}

    gtk_ctree_unselect(ctree_downloads, l->data);
    guc_node_add(download_addr(d), download_port(d), SOCK_F_FORCE);
}

/***
 *** popup-queue
 ***/

void
on_popup_queue_start_now_activate(GtkMenuItem *unused_menuitem,
	gpointer unused_udata)
{
   	struct download *d;
    GList *node_list;
    GList *data_list;
    GList *l;
    GtkCTree *ctree_downloads_queue = GTK_CTREE
        (lookup_widget(main_window, "ctree_downloads_queue"));

	(void) unused_menuitem;
	(void) unused_udata;
    gtk_clist_freeze(GTK_CLIST(ctree_downloads_queue));

	node_list = g_list_copy(GTK_CLIST(ctree_downloads_queue)->selection);
	data_list = downloads_gui_collect_ctree_data(ctree_downloads_queue,
		node_list, TRUE, TRUE);

	for (l = data_list; NULL != l; l = g_list_next(l)) {
		d = (struct download *) l->data;

        if (!d) {
            g_warning(
				"on_popup_queue_start_now_activate(): row has NULL data");
            continue;
        }
		if (d->status == GTA_DL_QUEUED)
			guc_download_start(d, TRUE);
	}

    gtk_clist_thaw(GTK_CLIST(ctree_downloads_queue));

	g_list_free(data_list);
	g_list_free(node_list);
}

void
on_popup_queue_abort_activate(GtkMenuItem *unused_menuitem,
	gpointer unused_udata)
{
	struct download *d;
    GList *node_list;
    GList *data_list;
    GList *l;
    GtkCTree *ctree_downloads_queue = GTK_CTREE
        (lookup_widget(main_window, "ctree_downloads_queue"));

	(void) unused_menuitem;
	(void) unused_udata;
    gtk_clist_freeze(GTK_CLIST(ctree_downloads_queue));

	/* Remove for all selected active downloads */
	node_list = g_list_copy(GTK_CLIST(ctree_downloads_queue)->selection);
	data_list = downloads_gui_collect_ctree_data(ctree_downloads_queue,
		node_list, TRUE, TRUE);

	for (l = data_list; NULL != l; l = g_list_next(l)) {
		d = (struct download *) l->data;

        if (!d) {
			g_warning(
				"on_popup_downloads_queue_remove(): row has NULL data");
		    continue;
        }
		if (d->status == GTA_DL_QUEUED)
			guc_download_remove(d);
	}

    gtk_clist_thaw(GTK_CLIST(ctree_downloads_queue));

	g_list_free(data_list);
	g_list_free(node_list);
}


void
on_popup_queue_abort_named_activate(GtkMenuItem *unused_menuitem,
	gpointer unused_udata)
{
   	struct download *d;
    GList *node_list;
    GList *data_list;
    GList *l;
    GtkCTree *ctree_downloads = GTK_CTREE
        (lookup_widget(main_window, "ctree_downloads"));
    GtkCTree *ctree_downloads_queue = GTK_CTREE
        (lookup_widget(main_window, "ctree_downloads_queue"));
    guint removed = 0;

	(void) unused_menuitem;
	(void) unused_udata;
    gtk_clist_freeze(GTK_CLIST(ctree_downloads));
    gtk_clist_freeze(GTK_CLIST(ctree_downloads_queue));
	node_list = g_list_copy(GTK_CLIST(ctree_downloads_queue)->selection);
	data_list = downloads_gui_collect_ctree_data(ctree_downloads_queue,
		node_list, TRUE, FALSE);

	for (l = data_list; NULL != l; l = g_list_next(l)) {
		d = (struct download *) l->data;

		if (!d) {
			g_warning("on_popup_queue_abort_named_activate(): "
				"row has NULL data");
			continue;
		}
		removed += guc_download_remove_all_named(d->file_name);
	}

	g_list_free(data_list);
	g_list_free(node_list);
    gtk_clist_thaw(GTK_CLIST(ctree_downloads_queue));
    gtk_clist_thaw(GTK_CLIST(ctree_downloads));

	show_removed(removed);
}

void
on_popup_queue_abort_host_activate(GtkMenuItem *unused_menuitem,
	gpointer unused_udata)
{
   	struct download *d;
    GList *node_list;
    GList *data_list;
    GList *l;
    GtkCTree *ctree_downloads = GTK_CTREE
        (lookup_widget(main_window, "ctree_downloads"));
    GtkCTree *ctree_downloads_queue = GTK_CTREE
        (lookup_widget(main_window, "ctree_downloads_queue"));
    guint removed = 0;

	(void) unused_menuitem;
	(void) unused_udata;
    gtk_clist_freeze(GTK_CLIST(ctree_downloads));
    gtk_clist_freeze(GTK_CLIST(ctree_downloads_queue));
	node_list = g_list_copy(GTK_CLIST(ctree_downloads_queue)->selection);
	data_list = downloads_gui_collect_ctree_data(ctree_downloads_queue,
		node_list, TRUE, TRUE);

	for (l = data_list; NULL != l; l = g_list_next(l)) {
		d = (struct download *) l->data;

		if (!d) {
			g_warning("on_popup_queue_abort_host_activate(): "
				"row has NULL data");
			continue;
		}
		removed += guc_download_remove_all_from_peer(
			download_guid(d), download_addr(d), download_port(d), FALSE);
	}

	g_list_free(data_list);
	g_list_free(node_list);
    gtk_clist_thaw(GTK_CLIST(ctree_downloads_queue));
    gtk_clist_thaw(GTK_CLIST(ctree_downloads));

    show_removed(removed);
}

void
on_popup_queue_abort_sha1_activate(GtkMenuItem *unused_menuitem,
	gpointer unused_udata)
{
   	struct download *d;
    GList *node_list;
    GList *data_list;
    GList *l;
    GtkCTree *ctree_downloads = GTK_CTREE
        (lookup_widget(main_window, "ctree_downloads"));
    GtkCTree *ctree_downloads_queue = GTK_CTREE
        (lookup_widget(main_window, "ctree_downloads_queue"));
    guint removed = 0;

	(void) unused_menuitem;
	(void) unused_udata;
    gtk_clist_freeze(GTK_CLIST(ctree_downloads));
    gtk_clist_freeze(GTK_CLIST(ctree_downloads_queue));
	node_list = g_list_copy(GTK_CLIST(ctree_downloads_queue)->selection);
	data_list = downloads_gui_collect_ctree_data(ctree_downloads_queue,
		node_list, TRUE, FALSE);

	for (l = data_list; NULL != l; l = g_list_next(l)) {
		d = (struct download *) l->data;

		if (!d) {
			g_warning("on_popup_queue_abort_sha1_activate(): "
				"row has NULL data");
			continue;
		}

        if (d->file_info->sha1 != NULL)
            removed += guc_download_remove_all_with_sha1
				(d->file_info->sha1);
	}

	g_list_free(data_list);
	g_list_free(node_list);
    gtk_clist_thaw(GTK_CLIST(ctree_downloads_queue));
    gtk_clist_thaw(GTK_CLIST(ctree_downloads));

    show_removed(removed);
}

void
on_popup_queue_copy_url_activate(GtkMenuItem *unused_menuitem,
	gpointer unused_udata)
{
    /* FIXME: This is more or less copy/paste from the downloads_copy_url
     * handler. There should be a more general function to call which
     * takes the string to copy as an arguments and handles the rest.
     *      --BLUE, 24/05/2002
     */

   	struct download * d = NULL;
    GtkCTree *ctree_downloads_queue = GTK_CTREE
        (lookup_widget(main_window, "ctree_downloads_queue"));
    GList *l = GTK_CLIST(ctree_downloads_queue)->selection;

	(void) unused_menuitem;
	(void) unused_udata;
    g_return_if_fail(l);

    if (GTK_CTREE_NODE_HAS_CHILDREN(l->data))
        return;

    /*
     * note that we set the popup dialog as owner, because we can
     * connect the selection_* signals to that using glade.
     *      --BLUE, 24/04/2002
     */
    if (gtk_selection_owner_set(GTK_WIDGET(popup_downloads),
                                GDK_SELECTION_PRIMARY,
                                GDK_CURRENT_TIME)){
       	d = (struct download *) gtk_ctree_node_get_row_data
				(ctree_downloads_queue, l->data);

        if (!d) {
           	g_warning("on_popup_queue_copy_url(): row has NULL data");
		    return;
        }

        /*
         * if "copy url" is done repeatedly, we have to make sure the
         * memory of the previous selection is freed, because we may not
         * recieve a "selection_clear" signal.
         *      --BLUE, 24/04/2002
         */
        if (selected_url != NULL) {
            G_FREE_NULL(selected_url);
        }

        selected_url = guc_download_build_url(d);
    }
}

void
on_popup_queue_connect_activate(GtkMenuItem *unused_menuitem,
	gpointer unused_udata)
{
    struct download * d = NULL;
    GtkCTree *ctree_downloads_queue = GTK_CTREE
        (lookup_widget(main_window, "ctree_downloads_queue"));
    GList *l = GTK_CLIST(ctree_downloads_queue)->selection;

	(void) unused_menuitem;
	(void) unused_udata;
    g_return_if_fail(l);

    if (GTK_CTREE_NODE_HAS_CHILDREN(l->data))
        return;

   	d = gtk_ctree_node_get_row_data(ctree_downloads_queue, l->data);

    if (!d) {
    	g_warning("on_popup_queue_connect_activate(): row %d has NULL data",
            GPOINTER_TO_INT(l->data));
	    return;
    }

    gtk_ctree_unselect(ctree_downloads_queue, l->data);
    guc_node_add(download_addr(d), download_port(d), SOCK_F_FORCE);
}

gboolean
on_ctree_downloads_queue_button_release_event(GtkWidget *unused_widget,
	GdkEventButton *unused_event, gpointer unused_data)
{
	(void) unused_widget;
	(void) unused_event;
	(void) unused_data;

	if (refresh_on_release)
		downloads_update_queue_pane();

	return FALSE;
}

/***
 *** downloads pane
 ***/


/**
 *	For all selected active downloads, forget them.  This doubles as the
 *	callback for the abort option on the popup menu.
 */
void
on_button_downloads_abort_clicked(GtkButton *unused_button,
	gpointer unused_udata)
{
   	struct download *d;
    GList *node_list;
    GList *data_list;
    GList *l;
    GtkCTree *ctree_downloads = GTK_CTREE
        (lookup_widget(main_window, "ctree_downloads"));

	(void) unused_button;
	(void) unused_udata;
    gtk_clist_freeze(GTK_CLIST(ctree_downloads));
	node_list = g_list_copy(GTK_CLIST(ctree_downloads)->selection);
	data_list = downloads_gui_collect_ctree_data(ctree_downloads,
		node_list, TRUE, TRUE);

	for (l = data_list; NULL != l; l = g_list_next(l)) {
		d = (struct download *) l->data;

		if (!d) {
			g_warning("on_button_downloads_abort_clicked(): "
				"row has NULL data");
			continue;
		}

		guc_download_abort(d);
	}

	g_list_free(data_list);
	g_list_free(node_list);
    gtk_clist_thaw(GTK_CLIST(ctree_downloads));
}


void
on_button_downloads_resume_clicked(GtkButton *unused_button,
	gpointer unused_udata)
{
   	struct download *d;
    GList *node_list;
    GList *data_list;
    GList *l;
    GtkCTree *ctree_downloads = GTK_CTREE
        (lookup_widget(main_window, "ctree_downloads"));

	(void) unused_button;
	(void) unused_udata;
    gtk_clist_freeze(GTK_CLIST(ctree_downloads));
	node_list = g_list_copy(GTK_CLIST(ctree_downloads)->selection);
	data_list = downloads_gui_collect_ctree_data(ctree_downloads,
		node_list, TRUE, TRUE);

	for (l = data_list; NULL != l; l = g_list_next(l)) {
		d = (struct download *) l->data;

        if (!d) {
            g_warning("on_button_downloads_resume_clicked(): "
				"row has NULL data");
            continue;
        }
        guc_download_resume(d);
	}

	g_list_free(data_list);
	g_list_free(node_list);
    gtk_clist_thaw(GTK_CLIST(ctree_downloads));

	gui_update_download_abort_resume();
	gui_update_download_clear();
}

/***
 *** Queued downloads
 ***/

void
on_ctree_downloads_queue_tree_select_row(GtkCTree *ctree, GList *node,
	gint unused_column, gpointer unused_udata)
{
    gboolean only_one = FALSE;
    gboolean one_or_more = (GTK_CLIST(ctree)->selection != NULL);
	struct download *d;

	(void) unused_column;
	(void) unused_udata;
	d = gtk_ctree_node_get_row_data(ctree, GTK_CTREE_NODE(node));

	/* If it's a header, there is more than one */
	if (DL_GUI_IS_HEADER != d) {
	    only_one = ((GTK_CLIST(ctree)->selection != NULL) &&
    	    (GTK_CLIST(ctree)->selection->next == NULL));
	}

    gtk_widget_set_sensitive
        (lookup_widget(popup_queue, "popup_queue_copy_url"), only_one);
    gtk_widget_set_sensitive
        (lookup_widget(popup_queue, "popup_queue_connect"), only_one);
	gui_update_download_abort_resume();

	gtk_widget_set_sensitive
        (lookup_widget(popup_queue, "popup_queue_abort"), one_or_more);
	gtk_widget_set_sensitive
        (lookup_widget(popup_queue, "popup_queue_abort_named"), one_or_more);
	gtk_widget_set_sensitive
        (lookup_widget(popup_queue, "popup_queue_abort_host"), one_or_more);
    gtk_widget_set_sensitive
        (lookup_widget(popup_queue, "popup_queue_abort_sha1"), one_or_more);
}

void
on_ctree_downloads_queue_tree_unselect_row(GtkCTree *ctree,
	GList *node, gint column, gpointer user_data)
{
	/* Update popups */
    on_ctree_downloads_queue_tree_select_row(ctree, node, column, user_data);
}

void
on_entry_queue_regex_activate(GtkEditable *editable, gpointer unused_udata)
{
	GtkCTree *ctree_downloads_queue;
	GtkCTreeNode *node;
	GtkCTreeNode *child, *parent;
	GtkCTreeRow *row;
	struct download *d, *dtemp;
	gboolean child_selected, node_expanded;
    gint i;
  	gint n;
    gint m = 0;
    gint  err;
    gchar * regex;
	regex_t re;

	(void) unused_udata;
    regex = STRTRACK(gtk_editable_get_chars(GTK_EDITABLE(editable), 0, -1));
	g_return_if_fail(regex != NULL);

    err = regcomp(&re,
                  regex,
                  REG_EXTENDED|REG_NOSUB|(queue_regex_case ? 0 : REG_ICASE));

   	if (err) {
        char buf[1024];
		regerror(err, &re, buf, sizeof buf);
        statusbar_gui_warning(15, "on_entry_queue_regex_activate: "
			"regex error %s", buf);

	} else {
		gint rows;

        ctree_downloads_queue = GTK_CTREE
            (lookup_widget(main_window, "ctree_downloads_queue"));

		gtk_ctree_unselect_recursive(ctree_downloads_queue, NULL);
	    gtk_clist_freeze(GTK_CLIST(ctree_downloads_queue));

		/* Traverse the entire downloads_queue */
		i = 0;
		for (
			node = GTK_CTREE_NODE(GTK_CLIST(ctree_downloads_queue)->row_list);
			NULL != node;
			node = GTK_CTREE_NODE_NEXT (node), i++
		) {

			d = (struct download *) gtk_ctree_node_get_row_data
				(ctree_downloads_queue, node);

			if (!d) {
                g_warning("on_entry_queue_regex_activate: "
					"row %d has NULL data", i);
                continue;
            }

			if (DL_GUI_IS_HEADER == d) {
				/* A header node.  We expand it and check all of the children
				 * If one of the children get selected keep node expanded,
				 * if it was initially collapsed, collapse it again
				 */
				child_selected = FALSE;
				node_expanded = FALSE;

				parent = GTK_CTREE_NODE(node);
				row = GTK_CTREE_ROW(parent);
				child = row->children;

				if (NULL != child) {
					node_expanded =
						gtk_ctree_is_viewable(ctree_downloads_queue, child);
				}

				gtk_ctree_expand(ctree_downloads_queue, parent);

				for (
					/* NOTHING */;
					NULL != child;
					row = GTK_CTREE_ROW(child), child = row->sibling
				) {

					dtemp = gtk_ctree_node_get_row_data
						(ctree_downloads_queue, child);

					if ((n = regexec(&re, dtemp->file_name, 0, NULL, 0)) == 0 ||
						(n = regexec(&re, download_outname(dtemp), 0, NULL, 0))
						== 0) {
						gtk_ctree_select(ctree_downloads_queue, child);
						child_selected = TRUE;
						m ++;
					}

		            if (n == REG_ESPACE)
        		        g_warning("on_entry_queue_regex_activate: "
						"regexp memory overflow");
				}

				if (!child_selected && !node_expanded)
					gtk_ctree_collapse(ctree_downloads_queue, parent);

				continue;
			}

			/* Not a header entry */
            if (
				(n = regexec(&re, d->file_name, 0, NULL, 0)) == 0 ||
				(n = regexec(&re, download_outname(d), 0, NULL, 0)) == 0
			) {
                gtk_ctree_select(ctree_downloads_queue, node);
                m ++;
			}

            if (n == REG_ESPACE)
                g_warning("on_entry_queue_regex_activate: "
					"regexp memory overflow");
        }
	    gtk_clist_thaw(GTK_CLIST(ctree_downloads_queue));

		rows = GTK_CLIST(ctree_downloads_queue)->rows;
        statusbar_gui_message(15,
			NG_("Selected %u of %u queued download matching \"%s\".",
				"Selected %u of %u queued downloads matching \"%s\".", rows),
            m, rows, regex);

		regfree(&re);
    }

    G_FREE_NULL(regex);
}

gboolean
on_ctree_downloads_queue_button_press_event(GtkWidget *widget,
	GdkEventButton *event, gpointer unused_udata)
{
	gint row;
    gint col;
    GtkCTree *ctree_downloads_queue = GTK_CTREE(widget);
    GList *selection;

	(void) unused_udata;

	refresh_on_release = event->button == 1;

	if (event->button != 3)
		return FALSE;

    selection = GTK_CLIST(widget)->selection;

	/* If no items are selected */
    if (selection == NULL) {
	    gtk_widget_set_sensitive
	        (lookup_widget(popup_queue, "popup_queue_start_now"), FALSE);
	    gtk_widget_set_sensitive
	        (lookup_widget(popup_queue, "popup_queue_abort"), FALSE);
	    gtk_widget_set_sensitive
	        (lookup_widget(popup_queue, "popup_queue_abort_named"), FALSE);
	    gtk_widget_set_sensitive
	        (lookup_widget(popup_queue, "popup_queue_abort_host"), FALSE);
	    gtk_widget_set_sensitive
	        (lookup_widget(popup_queue, "popup_queue_abort_sha1"), FALSE);
	    gtk_widget_set_sensitive
	        (lookup_widget(popup_queue, "popup_queue_copy_url"), FALSE);
	    gtk_widget_set_sensitive
	        (lookup_widget(popup_queue, "popup_queue_connect"), FALSE);
	} else if (GTK_CTREE_NODE_HAS_CHILDREN(selection->data)) {
	    gtk_widget_set_sensitive
	        (lookup_widget(popup_queue, "popup_queue_copy_url"), FALSE);
	    gtk_widget_set_sensitive
	        (lookup_widget(popup_queue, "popup_queue_connect"), FALSE);
    }

	if (
		!gtk_clist_get_selection_info(GTK_CLIST(ctree_downloads_queue),
			event->x, event->y, &row, &col)
	) {
		return FALSE;
	}

	gtk_menu_popup(GTK_MENU(popup_queue), NULL, NULL, NULL, NULL,
                  event->button, event->time);

	return TRUE;
}

void
on_ctree_downloads_queue_resize_column(GtkCList *unused_clist,
	gint column, gint width, gpointer unused_udata)
{
	(void) unused_clist;
	(void) unused_udata;
	*(gint *) &dl_queued_col_widths[column] = width;
}

void
on_ctree_downloads_queue_drag_begin(GtkWidget *unused_widget,
	GdkDragContext *unused_drag_context, gpointer unused_udata)
{
	(void) unused_widget;
	(void) unused_drag_context;
	(void) unused_udata;
    guc_download_freeze_queue();
}

void
on_ctree_downloads_queue_drag_end(GtkWidget *unused_widget,
	GdkDragContext *unused_drag_context, gpointer unused_udata)
{
	(void) unused_widget;
	(void) unused_drag_context;
	(void) unused_udata;
    guc_download_thaw_queue();
}

/**
 * Expands all parent nodes.
 */
void
on_popup_downloads_expand_all_activate(GtkMenuItem *unused_menuitem,
	gpointer unused_udata)
{
	GtkCTree *ctree_downloads = GTK_CTREE
		(lookup_widget(main_window, "ctree_downloads"));

	(void) unused_menuitem;
	(void) unused_udata;

    downloads_gui_expand_all(ctree_downloads);
}

/**
 * Collapses all parent nodes.
 */
void
on_popup_downloads_collapse_all_activate(GtkMenuItem *unused_menuitem,
	gpointer unused_udata)
{
	GtkCTree *ctree_downloads = GTK_CTREE
		(lookup_widget(main_window, "ctree_downloads"));

	(void) unused_menuitem;
	(void) unused_udata;
    downloads_gui_collapse_all(ctree_downloads);
}

/**
 * Expands all parent nodes.
 */
void
on_popup_queue_expand_all_activate(GtkMenuItem *unused_menuitem,
	gpointer unused_udata)
{
	GtkCTree *ctree_downloads_queue = GTK_CTREE
		(lookup_widget(main_window, "ctree_downloads_queue"));

	(void) unused_menuitem;
	(void) unused_udata;
    downloads_gui_expand_all(ctree_downloads_queue);
}


/**
 * Collapses all parent nodes.
 */
void
on_popup_queue_collapse_all_activate(GtkMenuItem *unused_menuitem,
	gpointer unused_udata)
{
	GtkCTree *ctree_downloads_queue = GTK_CTREE
		(lookup_widget(main_window, "ctree_downloads_queue"));

	(void) unused_menuitem;
	(void) unused_udata;
    downloads_gui_collapse_all(ctree_downloads_queue);
}

/**
 * Make the current selected URL the selection data.
 */
void
on_popup_downloads_selection_get(GtkWidget *unused_widget,
	GtkSelectionData *data, guint unused_info,
	guint unused_eventtime, gpointer unused_udata)
{
	(void) unused_widget;
	(void) unused_info;
	(void) unused_udata;
	(void) unused_eventtime;
    g_return_if_fail(selected_url);

    gtk_selection_data_set(data, GDK_SELECTION_TYPE_STRING,
		8 /* CHAR_BIT */, (guchar *) selected_url, strlen(selected_url));
}


/**
 * Frees the string holding current selected URL if any.
 */
gint
on_popup_downloads_selection_clear_event(GtkWidget *unused_widget,
	GdkEventSelection *unused_event)
{
	(void) unused_widget;
	(void) unused_event;
    if (selected_url != NULL) {
        G_FREE_NULL(selected_url);
    }
    return TRUE;
}

/* vi: set ts=4 sw=4 cindent: */
