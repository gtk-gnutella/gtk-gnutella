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

RCSID("$Id$");

#include "downloads_cb.h"
#include "gtk/downloads.h"
#include "gtk/downloads_common.h"
#include "gtk/statusbar.h"
#include "gtk/gtkcolumnchooser.h"
#include "gtk/columns.h"

#include "if/gnet_property.h"
#include "if/gui_property_priv.h"
#include "if/bridge/ui2c.h"
#include "if/core/sockets.h"

#include "lib/override.h"		/* Must be the last header included */

typedef enum {
	/* Active download stuff goes here */
	DL_ACTION_ABORT,
	DL_ACTION_ABORT_HOST,
	DL_ACTION_ABORT_NAMED,
	DL_ACTION_ABORT_SHA1,
	DL_ACTION_CONNECT,
	DL_ACTION_COPY_URL,
	DL_ACTION_PUSH,
	DL_ACTION_QUEUE,
	DL_ACTION_REMOVE_FILE,
	DL_ACTION_RESUME,
	DL_ACTION_SELECT,

	/* Queued stuff goes here */
	DL_ACTION_QUEUED_ABORT,
	DL_ACTION_QUEUED_ABORT_NAMED,
	DL_ACTION_QUEUED_ABORT_HOST,
	DL_ACTION_QUEUED_ABORT_SHA1,
	DL_ACTION_QUEUED_CONNECT,
	DL_ACTION_QUEUED_COPY_URL,
	DL_ACTION_QUEUED_START,
	DL_ACTION_QUEUED_PUSH,

	NUM_DL_ACTION
} dl_action_type_t;

typedef struct {
	dl_action_type_t action;
	GSList *sl;
} dl_action_t;

/***
 *** Popup menu: downloads
 ***/

static void
dl_action(GtkTreeModel *model, GtkTreePath *unused_path,
	GtkTreeIter *iter, gpointer data)
{
	dl_action_t *ctx = data;
	struct download *d = NULL;
	gint column = -1;

	(void) unused_path;

	switch (ctx->action) {
	/* Active download stuff goes here */
	case DL_ACTION_ABORT:
	case DL_ACTION_ABORT_HOST:
	case DL_ACTION_ABORT_NAMED:
	case DL_ACTION_CONNECT:
	case DL_ACTION_COPY_URL:
	case DL_ACTION_PUSH:
	case DL_ACTION_QUEUE:
	case DL_ACTION_REMOVE_FILE:
	case DL_ACTION_RESUME:
	case DL_ACTION_SELECT:
	/* Queued stuff goes here */
	case DL_ACTION_QUEUED_ABORT_HOST:
	case DL_ACTION_QUEUED_ABORT_NAMED:
	case DL_ACTION_QUEUED_CONNECT:
	case DL_ACTION_QUEUED_COPY_URL:
	case DL_ACTION_QUEUED_PUSH:

		switch (ctx->action) {
		/* Active download stuff goes here */
		case DL_ACTION_PUSH:
		case DL_ACTION_ABORT_HOST:
		case DL_ACTION_ABORT_NAMED:
		case DL_ACTION_REMOVE_FILE:
		case DL_ACTION_QUEUE:
		case DL_ACTION_CONNECT:
		case DL_ACTION_COPY_URL:
		case DL_ACTION_ABORT:
		case DL_ACTION_RESUME:
		case DL_ACTION_SELECT:
			column = c_dl_record;
			break;

		/* Queued stuff goes here */
		case DL_ACTION_QUEUED_ABORT:
		case DL_ACTION_QUEUED_ABORT_HOST:
		case DL_ACTION_QUEUED_ABORT_NAMED:
		case DL_ACTION_QUEUED_CONNECT:
		case DL_ACTION_QUEUED_COPY_URL:
		case DL_ACTION_QUEUED_START:
		case DL_ACTION_QUEUED_PUSH:
			column = c_queue_record;
			break;

		case DL_ACTION_ABORT_SHA1:
		case DL_ACTION_QUEUED_ABORT_SHA1:
		case NUM_DL_ACTION:
			g_assert_not_reached();
		}

		gtk_tree_model_get(model, iter, column, &d, (-1));
		if (!d) {
			g_warning("popup_dl_action(): row has NULL data");
			return;
		}
		if (DL_GUI_IS_HEADER == d)
			return;


		ctx->sl = g_slist_prepend(ctx->sl, d);
		return;

	case DL_ACTION_ABORT_SHA1:
	case DL_ACTION_QUEUED_ABORT_SHA1:

		switch (ctx->action) {
		/* Active download stuff goes here */
		case DL_ACTION_ABORT_SHA1:
			column = c_dl_record;
			break;

		/* Queued stuff goes here */
		case DL_ACTION_QUEUED_ABORT_SHA1:
			column = c_queue_record;
			break;

		case DL_ACTION_PUSH:
		case DL_ACTION_ABORT_HOST:
		case DL_ACTION_ABORT_NAMED:
		case DL_ACTION_REMOVE_FILE:
		case DL_ACTION_QUEUE:
		case DL_ACTION_CONNECT:
		case DL_ACTION_COPY_URL:
		case DL_ACTION_ABORT:
		case DL_ACTION_RESUME:
		case DL_ACTION_SELECT:
		case DL_ACTION_QUEUED_ABORT:
		case DL_ACTION_QUEUED_ABORT_HOST:
		case DL_ACTION_QUEUED_ABORT_NAMED:
		case DL_ACTION_QUEUED_CONNECT:
		case DL_ACTION_QUEUED_COPY_URL:
		case DL_ACTION_QUEUED_START:
		case DL_ACTION_QUEUED_PUSH:
		case NUM_DL_ACTION:
			g_assert_not_reached();
		}

		gtk_tree_model_get(model, iter, column, &d, (-1));
		if (!d) {
			g_warning("popup_dl_action(): row has NULL data");
			return;
		}
		if (DL_GUI_IS_HEADER == d) {
			/* This is a header. All children have the same SHA1
		 	* so we just grab the next one.
		 	*/
			GtkTreeIter child;

			if (gtk_tree_model_iter_nth_child(model, &child, iter, 0))
				gtk_tree_model_get(model, &child, column, &d, (-1));
		}
		/* XXX: Should child nodes be added to the list at all? */
		ctx->sl = g_slist_prepend(ctx->sl, d);
		return;

	case DL_ACTION_QUEUED_START:
	case DL_ACTION_QUEUED_ABORT:

		gtk_tree_model_get(model, iter, c_queue_record, &d, (-1));
   		if (!d) {
			g_warning("popup_dl_action(): row has NULL data");
			return;
		}
		if (DL_GUI_IS_HEADER == d)
			return;
		if (d->status == GTA_DL_QUEUED)
			ctx->sl = g_slist_prepend(ctx->sl, d);

		return;

	case NUM_DL_ACTION:
		g_assert_not_reached();
	}

	g_assert_not_reached();
}

static GSList *
dl_action_select(const gchar *treeview_name, dl_action_type_t action)
{
	GtkTreeView *tree_view;
	GtkTreeSelection *selection;
	dl_action_t ctx;

	ctx.action = action;
	ctx.sl = NULL;

	g_assert((gint) action >= 0 && action <= NUM_DL_ACTION);
 	g_assert(treeview_name && treeview_name[0] != '\0');

	tree_view = GTK_TREE_VIEW(lookup_widget(main_window, treeview_name));
	selection = gtk_tree_view_get_selection(tree_view);
	gtk_tree_selection_selected_foreach(selection, dl_action, &ctx);
	if (action != DL_ACTION_SELECT)
		gtk_tree_selection_unselect_all(selection);

	return ctx.sl;
}

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
push_activate(gboolean active)
{
	GSList *sl, *selected;
	gboolean send_pushes, firewalled;

   	gnet_prop_get_boolean_val(PROP_SEND_PUSHES, &send_pushes);
   	gnet_prop_get_boolean_val(PROP_IS_FIREWALLED, &firewalled);

   	if (firewalled || !send_pushes)
       	return;

	selected = dl_action_select(
					active ? "treeview_downloads" : "treeview_downloads_queue",
					active ? DL_ACTION_PUSH : DL_ACTION_QUEUED_PUSH);
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

	push_activate(TRUE);
}

/**
 * Initiates a browse host request to the currently selected host.
 */
void
on_popup_downloads_browse_host_activate(GtkMenuItem *unused_menuitem,
	gpointer unused_udata)
{
	(void) unused_menuitem;
	(void) unused_udata;

	/* FIXME: Implement this */	
}

/**
 * Initiates a browse host request to the currently selected host.
 */
void
on_popup_queue_browse_host_activate(GtkMenuItem *unused_menuitem,
	gpointer unused_udata)
{
	(void) unused_menuitem;
	(void) unused_udata;

	/* FIXME: Implement this */	
}


/**
 * Causes all selected queued downloads to fall back to push.
 */
void
on_popup_queue_push_activate(GtkMenuItem *unused_menuitem,
	gpointer unused_udata)
{
	(void) unused_menuitem;
	(void) unused_udata;

	push_activate(FALSE);
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

	selected = dl_action_select("treeview_downloads", DL_ACTION_ABORT_NAMED);
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

	selected = dl_action_select("treeview_downloads", DL_ACTION_ABORT_HOST);
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

	selected = dl_action_select("treeview_downloads", DL_ACTION_ABORT_SHA1);
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

	selected = dl_action_select("treeview_downloads", DL_ACTION_REMOVE_FILE);
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


/**
 * For all selected active downloads, send back to queue.
 */
void
on_popup_downloads_queue_activate(GtkMenuItem *unused_menuitem,
	gpointer unused_udata)
{
	GSList *sl, *selected;

	(void) unused_menuitem;
	(void) unused_udata;

	selected = dl_action_select("treeview_downloads", DL_ACTION_QUEUE);
	if (!selected)
		return;

	for (sl = selected; sl; sl = g_slist_next(sl)) {
		struct download *d = sl->data;
		guc_download_requeue(d);
   	}
	g_slist_free(selected);
}


static void
copy_selection_to_clipboard(const gchar *treeview_name,
	dl_action_type_t action)
{
	GSList *sl, *selected;

   	selected = dl_action_select(treeview_name, action);
	if (!selected)
		return;

	for (sl = selected; sl; sl = g_slist_next(sl)) {
		struct download *d = sl->data;
		const gchar *url;

       	url = guc_build_url_from_download(d);
		gtk_clipboard_clear(gtk_clipboard_get(GDK_SELECTION_PRIMARY));
		gtk_clipboard_set_text(gtk_clipboard_get(GDK_SELECTION_PRIMARY),
			url, -1);
		gtk_clipboard_clear(gtk_clipboard_get(GDK_SELECTION_CLIPBOARD));
		gtk_clipboard_set_text(gtk_clipboard_get(GDK_SELECTION_CLIPBOARD),
			url, -1);
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

	copy_selection_to_clipboard("treeview_downloads", DL_ACTION_COPY_URL);
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

   	selected = dl_action_select("treeview_downloads", DL_ACTION_CONNECT);
	if (!selected)
		return;

	for (sl = selected; sl; sl = g_slist_next(sl)) {
		const struct download *d = sl->data;
   		guc_node_add(download_addr(d), download_port(d), CONNECT_F_FORCE);
   	}
	g_slist_free(selected);
}



/***
 *** popup-queue
 ***/


/**
 * For all selected queued downloads, activate them.
 */
void
on_popup_queue_start_now_activate(GtkMenuItem *unused_menuitem,
	gpointer unused_udata)
{
	GSList *sl, *selected;

	(void) unused_menuitem;
	(void) unused_udata;

   	selected = dl_action_select("treeview_downloads_queue",
					DL_ACTION_QUEUED_START);
	if (!selected)
		return;

	for (sl = selected; sl; sl = g_slist_next(sl)) {
		struct download *d = sl->data;
		guc_download_start(d, TRUE);
   	}
	g_slist_free(selected);
}


/**
 * For all selected queued downloads, forget them.
 */
void
on_popup_queue_abort_activate(GtkMenuItem *unused_menuitem,
	gpointer unused_udata)
{
	GSList *sl, *selected;

	(void) unused_menuitem;
	(void) unused_udata;

   	selected = dl_action_select("treeview_downloads_queue",
					DL_ACTION_QUEUED_ABORT);
	if (!selected)
		return;

	for (sl = selected; sl; sl = g_slist_next(sl)) {
		struct download *d = sl->data;
		guc_download_remove(d);
   	}
	g_slist_free(selected);
}


/**
 * For all selected queued downloads, remove all downloads with
 * same name.
 */
void
on_popup_queue_abort_named_activate(GtkMenuItem *unused_menuitem,
	gpointer unused_udata)
{
	GSList *sl, *selected;
    guint removed = 0;

	(void) unused_menuitem;
	(void) unused_udata;

   	selected = dl_action_select("treeview_downloads_queue",
					DL_ACTION_QUEUED_ABORT_NAMED);
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
 * For all selected queued downloads, remove all downloads with
 * same host.
 */
void
on_popup_queue_abort_host_activate(GtkMenuItem *unused_menuitem,
	gpointer unused_udata)
{
	GSList *sl, *selected;
    guint removed = 0;

	(void) unused_menuitem;
	(void) unused_udata;

   	selected = dl_action_select("treeview_downloads_queue",
					DL_ACTION_QUEUED_ABORT_HOST);
	if (!selected)
		return;

	for (sl = selected; sl; sl = g_slist_next(sl)) {
		struct download *d = sl->data;
		removed += guc_download_remove_all_from_peer(
				download_guid(d), download_addr(d), download_port(d), FALSE);
	}
	g_slist_free(selected);

    show_removed(removed);
}



/**
 * For all selected queued downloads, remove all downloads with
 * same sha1.
 */
void
on_popup_queue_abort_sha1_activate(GtkMenuItem *unused_menuitem,
	gpointer unused_udata)
{
	GSList *sl, *selected;
    guint removed = 0;

	(void) unused_menuitem;
	(void) unused_udata;

   	selected = dl_action_select("treeview_downloads_queue",
					DL_ACTION_QUEUED_ABORT_SHA1);
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
 * For all selected queued download, copy url to clipboard.
 */
void
on_popup_queue_copy_url_activate(GtkMenuItem *unused_menuitem,
	gpointer unused_udata)
{
	(void) unused_menuitem;
	(void) unused_udata;

	copy_selection_to_clipboard("treeview_downloads_queue",
		DL_ACTION_QUEUED_COPY_URL);
}


/**
 * For all selected queued download, connect to host.
 */
void
on_popup_queue_connect_activate(GtkMenuItem *unused_menuitem,
	gpointer unused_udata)
{
	GSList *selected;
	const GSList *sl;

	(void) unused_menuitem;
	(void) unused_udata;

   	selected = dl_action_select("treeview_downloads_queue",
					DL_ACTION_QUEUED_CONNECT);
	if (!selected)
		return;

	for (sl = selected; sl; sl = g_slist_next(sl)) {
		const struct download *d = sl->data;
    	guc_node_add(download_addr(d), download_port(d), CONNECT_F_FORCE);
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

   	selected = dl_action_select("treeview_downloads", DL_ACTION_ABORT);
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

   	selected = dl_action_select("treeview_downloads", DL_ACTION_RESUME);
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
			GTK_WIDGET(lookup_widget(main_window, "treeview_downloads")));
    gtk_menu_popup(GTK_MENU(cc), NULL, NULL, NULL, NULL, 1, 0);
}



/***
 *** Queued downloads
 ***/


/**
 * Select all queued downloads that match given regex in editable.
 */
void
on_entry_queue_regex_activate(GtkEditable *editable, gpointer unused_udata)
{
  	gint n;
    gint m = 0;
	gint total_nodes;
    gint  err;
    gchar * regex;
	struct download *d;
	regex_t re;
	GtkTreeIter iter;
	GtkTreeView *tree_view;
	GtkTreeModel *model;
	GtkTreeSelection *selection;

	(void) unused_udata;

    regex = STRTRACK(gtk_editable_get_chars(GTK_EDITABLE(editable), 0, -1));

	g_return_if_fail(regex != NULL);

    err = regcomp(&re,
                  regex,
                  REG_EXTENDED|REG_NOSUB|(queue_regex_case ? 0 : REG_ICASE));

   	if (err) {
        char buf[1024];

		regerror(err, &re, buf, sizeof buf);
        statusbar_gui_warning(15,
			"on_entry_queue_regex_activate: regex error %s", buf);
    } else {

		tree_view = GTK_TREE_VIEW
			(lookup_widget(main_window, "treeview_downloads_queue"));
		model = gtk_tree_view_get_model(tree_view);

		if (NULL != model) {

			selection = gtk_tree_view_get_selection(tree_view);
			gtk_tree_selection_unselect_all(selection);

			if (!gtk_tree_model_get_iter_first(model, &iter))
				return; /* tree is empty */

			for (
				total_nodes = 0;
				gtk_tree_model_iter_next(model, &iter);
				total_nodes++
			) {

				gtk_tree_model_get(model, &iter, c_queue_record, &d, (-1));

				if (DL_GUI_IS_HEADER == d)
					continue;

				if (!d) {
	                g_warning("on_entry_queue_regex_activate: "
						"row has NULL data");
    	            continue;
        	    }

	            if (
					(n = regexec(&re, d->file_name, 0, NULL, 0)) == 0 ||
					(n = regexec(&re, download_outname(d), 0, NULL, 0)) == 0
				) {
					gtk_tree_selection_select_iter(selection, &iter);
					m ++;
				}

    	        if (n == REG_ESPACE)
        	        g_warning("on_entry_queue_regex_activate: "
						"regexp memory overflow");
        	}

			statusbar_gui_message(15,
				NG_("Selected %u of %u queued download matching \"%s\".",
					"Selected %u of %u queued downloads matching \"%s\".",
					total_nodes),
				m, total_nodes, regex);

			regfree(&re);
	    }
	}

	g_free(regex);
    gtk_entry_set_text(GTK_ENTRY(editable), "");
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

    gtk_menu_popup(
        GTK_MENU(popup_downloads), NULL, NULL, NULL, NULL,
        event->button, event->time);

	return TRUE;
}


/**
 * When the right mouse button is clicked on the queued downloads
 * treeview, show the popup with the context menu.
 */
gboolean
on_treeview_downloads_queue_button_press_event(GtkWidget *widget,
	GdkEventButton *event, gpointer unused_udata)
{
	(void) unused_udata;

	if (event->button != 3)
		return FALSE;


	if (NULL == gtk_tree_view_get_selection(GTK_TREE_VIEW(widget)))
		return FALSE;

    gtk_menu_popup(
        GTK_MENU(popup_queue), NULL, NULL, NULL, NULL,
        event->button, event->time);

	return TRUE;
}


void on_treeview_downloads_select_row(GtkTreeView *tree_view,
	gpointer unused_udata)
{
	GtkTreeSelection *selection;
   	GSList *selected;
    gboolean activate;

	(void) unused_udata;

	/* The user selects a row(s) in the downloads treeview
	 * we unselect all rows in the downloads_queue tree view
	 */
	tree_view = GTK_TREE_VIEW
		(lookup_widget(main_window, "treeview_downloads_queue"));
	selection = gtk_tree_view_get_selection(tree_view);
	gtk_tree_selection_unselect_all(selection);

   	selected = dl_action_select("treeview_downloads", DL_ACTION_SELECT);
	activate = NULL != selected && g_slist_next(selected) == NULL;
	g_slist_free(selected);
	selected = NULL;

    gtk_widget_set_sensitive(lookup_widget(popup_downloads,
			"popup_downloads_copy_url"), activate);
   	gtk_widget_set_sensitive(lookup_widget(popup_downloads,
			"popup_downloads_connect"), activate);

	/* Takes care of other widgets */
	gui_update_download_abort_resume();
}


typedef struct {
	guint		count;
	gboolean	is_header;
} queue_select_help_t;

static void queue_select_row_helper(GtkTreeModel *model,
	GtkTreePath *unused_path, GtkTreeIter *iter, gpointer data)
{
	queue_select_help_t *q = data;
	download_t *d;

	(void) unused_path;

	gtk_tree_model_get(model, iter, c_queue_record, &d, (-1));
	q->is_header |= DL_GUI_IS_HEADER == d;
	q->count++;
}

void
on_treeview_downloads_queue_select_row(GtkTreeView *unused_tv,
	gpointer unused_udata)
{
	GtkTreeSelection *selection;
	queue_select_help_t q = { 0 /* count */, FALSE /* is_header */ };

	(void) unused_tv;
	(void) unused_udata;

	/* The user selects a row(s) in the downloads_queue treeview
	 * we unselect all rows in the downloads tree view
	 */
	selection = gtk_tree_view_get_selection(
		GTK_TREE_VIEW(lookup_widget(main_window, "treeview_downloads")));
	gtk_tree_selection_unselect_all(selection);

	selection = gtk_tree_view_get_selection(
		GTK_TREE_VIEW(lookup_widget(main_window, "treeview_downloads_queue")));
	gtk_tree_selection_selected_foreach(selection, queue_select_row_helper, &q);

	gtk_widget_set_sensitive(
		lookup_widget(popup_queue, "popup_queue_copy_url"),
		!q.is_header && q.count == 1);
	gtk_widget_set_sensitive(
		lookup_widget(popup_queue, "popup_queue_connect"),
		!q.is_header && q.count == 1);
	gui_update_download_abort_resume();

	gtk_widget_set_sensitive(
		lookup_widget(popup_queue, "popup_queue_abort"), !q.is_header);
	gtk_widget_set_sensitive(
		lookup_widget(popup_queue, "popup_queue_abort_named"), !q.is_header);
	gtk_widget_set_sensitive(
		lookup_widget(popup_queue, "popup_queue_abort_host"), !q.is_header);
    gtk_widget_set_sensitive(
		lookup_widget(popup_queue, "popup_queue_abort_sha1"), q.count > 0);

	if (q.is_header)
		gtk_widget_set_sensitive(
			lookup_widget(popup_queue, "popup_queue_start_now"), FALSE);
}


/**
 * on_popup_downloads_expand_all_activate
 */
void on_popup_downloads_expand_all_activate(GtkMenuItem *unused_menuitem,
	gpointer unused_udata)
{
	GtkTreeView *tree_view = GTK_TREE_VIEW
		(lookup_widget(main_window, "treeview_downloads"));

	(void) unused_menuitem;
	(void) unused_udata;

	downloads_gui_expand_all(tree_view);
}


void on_popup_downloads_collapse_all_activate(GtkMenuItem *unused_menuitem,
	gpointer unused_udata)
{
	GtkTreeView *tree_view = GTK_TREE_VIEW
		(lookup_widget(main_window, "treeview_downloads"));

	(void) unused_menuitem;
	(void) unused_udata;

	downloads_gui_collapse_all(tree_view);
}


void
on_popup_queue_expand_all_activate(GtkMenuItem *unused_menuitem,
	gpointer unused_udata)
{
	GtkTreeView *tree_view = GTK_TREE_VIEW
		(lookup_widget(main_window, "treeview_downloads_queue"));

	(void) unused_menuitem;
	(void) unused_udata;

	downloads_gui_expand_all(tree_view);
}

void
on_popup_queue_collapse_all_activate(GtkMenuItem *unused_menuitem,
	gpointer unused_udata)
{
	GtkTreeView *tree_view = GTK_TREE_VIEW
		(lookup_widget(main_window, "treeview_downloads_queue"));

	(void) unused_menuitem;
	(void) unused_udata;

	downloads_gui_collapse_all(tree_view);
}

void
on_popup_queue_config_cols_activate(GtkMenuItem *unused_menuitem,
	gpointer unused_udata)
{
    GtkWidget *cc;

	(void) unused_menuitem;
	(void) unused_udata;

    cc = gtk_column_chooser_new(
			GTK_WIDGET(lookup_widget(main_window, "treeview_downloads_queue")));
    gtk_menu_popup(GTK_MENU(cc), NULL, NULL, NULL, NULL, 1, 0);
}

/* vi: set ts=4 sw=4 cindent: */
