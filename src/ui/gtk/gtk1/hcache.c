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

#include "gtk/hcache.h"
#include "gtk/notebooks.h"
#include "gtk/columns.h"

#include "if/gui_property.h"
#include "if/bridge/ui2c.h"

#include "lib/glib-missing.h"
#include "lib/override.h"	/* Must be the last header included */

/***
 *** Callbacks
 ***/
void
on_clist_hcache_resize_column(GtkCList *unused_clist, gint column, gint width,
	gpointer unused_udata)
{
    static gboolean lock = FALSE;
    guint32 buf = width;

	(void) unused_clist;
	(void) unused_udata;

    if (lock)
        return;

    lock = TRUE;

    /** remember the width for storing it to the config file later */
    gui_prop_set_guint32(PROP_HCACHE_COL_WIDTHS, &buf, column, 1);

    lock = FALSE;
}

/***
 *** Private functions
 ***/
static gchar *
guint_to_str(guint32 i)
{
    static gchar strbuf[UINT32_DEC_BUFLEN];

    gm_snprintf(strbuf, sizeof(strbuf), "%u", i);
    return strbuf;
}



/***
 *** Public functions
 ***/

void
hcache_gui_init(void)
{
    GtkCList *clist_hcache;
    const gchar *titles[5];
    guint n;

    for (n = 0; n < G_N_ELEMENTS(titles); n ++)
        titles[n] = "-";

    clist_hcache = GTK_CLIST(lookup_widget(main_window, "clist_hcache"));

    /*
     * Stats can't be sorted: make column headers insensitive.
     */
	gtk_clist_column_titles_passive(clist_hcache);

    /*
     * Initialize stats tables.
     */
    for (n = 0; n < HCACHE_MAX; n ++) {
        gint row;

		if (n == HCACHE_NONE)
			continue;

        titles[0] = get_hcache_name(n);

	/* Override const */
        row = gtk_clist_append(clist_hcache, (gchar **) titles);
        gtk_clist_set_selectable(clist_hcache, row, FALSE);
    }

    for (n = 1; n < 4; n ++) {
        gtk_clist_set_column_justification(
            clist_hcache, n, GTK_JUSTIFY_RIGHT);
    }
}

void
hcache_gui_shutdown(void)
{
	/* Nothing for now */
}

void
hcache_gui_update(time_t now)
{
	static time_t last_update = 0;
    GtkCList *clist_hcache;
    gint n;
    hcache_stats_t stats[HCACHE_MAX];

    gint current_page;

	if (last_update == now)
		return;
	last_update = now;
    current_page = gtk_notebook_get_current_page(
        GTK_NOTEBOOK(lookup_widget(main_window, "notebook_main")));

    if (current_page != nb_main_page_hostcache)
        return;

    guc_hcache_get_stats(stats);

    clist_hcache = GTK_CLIST(
        lookup_widget(main_window, "clist_hcache"));

    gtk_clist_freeze(clist_hcache);

    for (n = 0; n < HCACHE_MAX; n ++) {
		if (n == HCACHE_NONE)
			continue;

        gtk_clist_set_text( clist_hcache, n,
            c_hcs_host_count, guint_to_str(stats[n].host_count));

        gtk_clist_set_text( clist_hcache, n,
            c_hcs_hits, guint_to_str(stats[n].hits));

        gtk_clist_set_text( clist_hcache, n,
            c_hcs_misses, guint_to_str(stats[n].misses));
    }

    gtk_clist_thaw(clist_hcache);
}

/* vi: set ts=4 sw=4 cindent: */
