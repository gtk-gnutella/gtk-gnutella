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

#include "downloads_cb.h"

#include "gtk/columns.h"
#include "gtk/downloads.h"
#include "gtk/downloads_common.h"
#include "gtk/misc.h"
#include "gtk/notebooks.h"
#include "gtk/settings.h"
#include "gtk/statusbar.h"

#include "if/core/pproxy.h"
#include "if/core/bsched.h"
#include "if/bridge/ui2c.h"

#include "lib/atoms.h"
#include "lib/glib-missing.h"
#include "lib/tm.h"
#include "lib/utf8.h"
#include "lib/override.h"	/* Must be the last header included */

/**
 * Initialize local data structures.
 */
void
downloads_gui_init(void)
{
}

/**
 * Cleanup local data structures.
 */
void
downloads_gui_shutdown(void)
{
}

/**
 *	Adds a download to the gui.  All parenting (grouping) is done here
 */
void
download_gui_add(struct download *d)
{
	download_check(d);
	
	fi_gui_add_download(d);
	d->visible = TRUE;
}

void
gui_update_download(struct download *d, gboolean force)
{
	time_t now;

	download_check(d);

	now = tm_time();
    if (force || 0 != delta_time(now, d->last_gui_update)) {
		d->last_gui_update = now;
		fi_gui_download_set_status(d);
	}
}


void
gui_update_download_abort_resume(void)
{
}

/**
 * Remove a download from the GUI.
 */
void
download_gui_remove(struct download *d)
{
	download_check(d);

	fi_gui_remove_download(d);
	d->visible = FALSE;
}

/**
 *	Collapse all nodes in given, tree either downloads or downloads_queue
 */
void
downloads_gui_expand_all(GtkCTree *ctree)
{
	(void) ctree;
}


/**
 *	Collapse all nodes in given, tree either downloads or downloads_queue
 */
void
downloads_gui_collapse_all(GtkCTree *ctree)
{
	(void) ctree;
}

/**
 * Update "active" pane if needed.
 */
void
downloads_update_active_pane(void)
{
}

/**
 * Update "queue" pane if needed.
 */
void
downloads_update_queue_pane(void)
{
}

/**
 * Periodically called to update downloads display.
 */
void
downloads_gui_update_display(time_t unused_now)
{
	(void) unused_now;
}

void
downloads_gui_clear_details(void)
{
	GtkCList *clist;

	clist = GTK_CLIST(gui_main_window_lookup("clist_download_details"));
	g_return_if_fail(clist);

    gtk_clist_clear(clist);
}

void
downloads_gui_append_detail(const gchar *name, const gchar *value)
{
 	const gchar *titles[2];
	GtkCList *clist;

	clist = GTK_CLIST(gui_main_window_lookup("clist_download_details"));
	g_return_if_fail(clist);

	titles[0] = name;
	titles[1] = EMPTY_STRING(value);
    gtk_clist_append(clist, (gchar **) titles);
}

/* vi: set ts=4 sw=4 cindent: */
