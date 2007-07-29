/*
 * $Id$
 *
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
 *      59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *----------------------------------------------------------------------
 */

#include "gtk/gui.h"

RCSID("$Id$")

#if !GTK_CHECK_VERSION(2,5,0)
#include "pbarcellrenderer.h"
#endif

#include "downloads_cb.h"

#include "gtk/downloads.h"
#include "gtk/downloads_common.h"
#include "gtk/statusbar.h"
#include "gtk/columns.h"
#include "gtk/notebooks.h"
#include "gtk/gtk-missing.h"
#include "gtk/misc.h"
#include "gtk/settings.h"

#include "if/core/downloads.h"
#include "if/gui_property.h"
#include "if/bridge/ui2c.h"

#include "lib/glib-missing.h"
#include "lib/utf8.h"
#include "lib/tm.h"
#include "lib/walloc.h"
#include "lib/override.h"		/* Must be the last header included */

void fi_gui_add_download(struct download *d);
void fi_gui_remove_download(struct download *d);
void fi_gui_download_set_status(struct download *d, const gchar *s);
GtkTreeView *fi_gui_current_treeview(void);

/***
 *** Private
 ***/
 
/***
 *** Public interface
 ***/
 
/**
 *	Initalize the download gui.
 */
void
downloads_gui_init(void)
{
}

/**
 * Shutdown procedures.
 */
void
downloads_gui_shutdown(void)
{
}

/**
 *	Add a download to either the active or queued download treeview depending
 *	on the download's flags.  This function handles grouping new downloads
 * 	appropriately and creation of parent/child nodes.
 */
void
download_gui_add(download_t *d)
{
	download_check(d);
	
	fi_gui_add_download(d);
	d->visible = TRUE;
}


/**
 *	Remove a download from the GUI.
 */
void
download_gui_remove(download_t *d)
{
	download_check(d);
	
	fi_gui_remove_download(d);
	d->visible = FALSE;
}

/**
 *	Update the gui to reflect the current state of the given download
 */
void
gui_update_download(download_t *d, gboolean force)
{
	time_t now;

	download_check(d);

	now = tm_time();
    if (force || 0 != delta_time(now, d->last_gui_update)) {
		d->last_gui_update = now;
		fi_gui_download_set_status(d, downloads_gui_status_string(d));
	}
}

/**
 *	Determines if abort/resume buttons should be sensitive or not
 *  Determines if the queue and abort options should be available in the
 *	treeview popups.
 */
void
gui_update_download_abort_resume(void)
{
}


/**
 * Periodically called to update downloads display.
 */
void
downloads_gui_update_display(time_t unused_now)
{
	(void) unused_now;

	/* Nothing needed for GTK2 */
}

void
downloads_gui_clear_details(void)
{
    gtk_list_store_clear(GTK_LIST_STORE(gtk_tree_view_get_model(
		GTK_TREE_VIEW(gui_main_window_lookup("treeview_download_details")))));
}

void
downloads_gui_append_detail(const gchar *title, const gchar *value)
{
	GtkTreeModel *model;
	GtkTreeIter iter;

    model = gtk_tree_view_get_model(GTK_TREE_VIEW(
				gui_main_window_lookup("treeview_download_details")));

	gtk_list_store_append(GTK_LIST_STORE(model), &iter);
	gtk_list_store_set(GTK_LIST_STORE(model), &iter, 0, title, 1, value, (-1));
}

/* vi: set ts=4 sw=4 cindent: */
