/*
 * $Id$
 *
 * Copyright (c) 2003, Richard Eckart
 *
 * Displaying of file information in the gui.
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

RCSID("$Id$");

enum {
    C_FI_FILENAME = 0,
    C_FI_SIZE,
    C_FI_DONE,
    C_FI_SOURCES,
    C_FI_STATUS,
    C_FI_COLUMNS
};

void on_clist_fileinfo_resize_column(
    GtkCList *clist, gint column, gint width, gpointer user_data)
{
    file_info_col_widths[column] = width;
}

static void fi_gui_append_row(
    GtkCList *cl, gnet_fi_t fih, gchar **titles, guint len)
{
    gint row;
    gint n;

    for (n = 0; n < len; n ++) {
        if (titles[n] == NULL)
            titles[n] = "";
    }

    row = gtk_clist_append(cl, titles);
    gtk_clist_set_row_data(cl, row, GUINT_TO_POINTER(fih));
}

static void fi_gui_update_row(
    GtkCList *cl, gint row, gchar **titles, guint len)
{
    gint n;

    for (n = 0; n < len; n ++) {
        if (titles[n] != NULL)
            gtk_clist_set_text(cl, row, n, titles[n]);
    }
}

/*
 * fi_gui_fill_info:
 *
 * Fill in the cell data. Calling this will always break the data
 * it filled in last time!
 */
static void fi_gui_fill_info(
    gnet_fi_t fih, gchar *titles[C_FI_COLUMNS])
{
    static gnet_fi_info_t *fi = NULL;

    /* Clear info from last call. We keep this around so we don't
     * have to strdup entries from it when passing them to the 
     * outside through titles[]. */
    if (fi != NULL) {
        fi_free_info(fi);
    }
        
    /* Fetch new info */
    fi = fi_get_info(fih);
    g_assert(fi != NULL);

    titles[C_FI_FILENAME] = fi->file_name;
}

static void fi_gui_fill_status(
    gnet_fi_t fih, gchar *titles[C_FI_COLUMNS])
{
    gnet_fi_status_t s;
    static gchar fi_sources[16];
    static gchar fi_done[SIZE_FIELD_MAX+10];
    static gchar fi_size[SIZE_FIELD_MAX];

    fi_get_status(fih, &s);

    gm_snprintf(fi_sources, sizeof(fi_sources), 
        s.recv_last_rate ? "%u/%u (%u) (%.1f k/s)" : "%u/%u (%u)",
        s.recvcount, s.lifecount, s.refcount,
        s.recv_last_rate / 1024.0);
    titles[C_FI_SOURCES] = fi_sources;

    if (s.done) {
        gm_snprintf(fi_done, sizeof(fi_done), "%s (%.1f%%)", 
            short_size(s.done), ((float) s.done / s.size)*100.0);
        titles[C_FI_DONE] = fi_done;
    } else {
        titles[C_FI_DONE] = "-";
    }
        
    gm_snprintf(fi_size, sizeof(fi_size), "%s", short_size(s.size));
    titles[C_FI_SIZE]    = fi_size;

    if (s.lifecount) {
        titles[C_FI_STATUS]  = s.recvcount ? "Downloading" : "Waiting";
    } else {
        titles[C_FI_STATUS]  = "No sources";
    }
}

static void fi_gui_update(gnet_fi_t fih, gboolean full)
{
    GtkCList *clist;
	gchar    *titles[C_FI_COLUMNS];
    gint      row;

    clist = GTK_CLIST(lookup_widget(main_window, "clist_fileinfo"));

    row = gtk_clist_find_row_from_data(clist, GUINT_TO_POINTER(fih));

    if (row == -1) {
        g_warning("fi_gui_remove: no matching row found");
        return;
    }

    memset(titles, 0, sizeof(titles));
    if (full)
        fi_gui_fill_info(fih, titles);
    fi_gui_fill_status(fih, titles);

    fi_gui_update_row(clist, row, titles, G_N_ELEMENTS(titles));
}

static void fi_gui_fi_added(gnet_fi_t fih)
{
    GtkCList       *clist;
	gchar          *titles[C_FI_COLUMNS];

    clist = GTK_CLIST(lookup_widget(main_window, "clist_fileinfo"));

    memset(titles, 0, sizeof(titles));
    fi_gui_fill_info(fih, titles);
    fi_gui_fill_status(fih, titles);

    fi_gui_append_row(clist, fih, titles, G_N_ELEMENTS(titles));
}

static void fi_gui_fi_removed(gnet_fi_t fih)
{
    GtkCList *clist;
    gint row;

    clist = GTK_CLIST(lookup_widget(main_window, "clist_fileinfo"));

    row = gtk_clist_find_row_from_data(clist, GUINT_TO_POINTER(fih));

    if (row == -1) {
        g_warning("fi_gui_remove: no matching row found");
        return;
    }

    gtk_clist_remove(clist, row);
}

static void fi_gui_fi_status_changed(gnet_fi_t fih)
{
    fi_gui_update(fih, FALSE);
}

void fi_gui_init() 
{
    fi_add_fi_added_listener(fi_gui_fi_added);
    fi_add_fi_removed_listener(fi_gui_fi_removed);
    fi_add_fi_status_changed_listener(fi_gui_fi_status_changed);
}

void fi_gui_shutdown()
{
    fi_remove_fi_removed_listener(fi_gui_fi_removed);
    fi_remove_fi_added_listener(fi_gui_fi_added);
    fi_remove_fi_status_changed_listener(fi_gui_fi_status_changed);
}

/*
 * fi_gui_update_display
 *
 * Update all the fileinfo at the same time.
 */

// FIXME: we should remember for every node when it was last
//        updated and only refresh every node at most once every
//        second. This information should be kept in a struct pointed
//        to by the row user_data and should be automatically freed
//        when removing the row (see upload stats code).

void fi_gui_update_display(time_t now)
{
    static time_t last_update = 0;
	GtkCList *clist;
	GList *l;
	gint row = 0;

    if (last_update == now)
        return;

    last_update = now;

    clist = GTK_CLIST(lookup_widget(main_window, "clist_fileinfo"));
    gtk_clist_freeze(clist);

	for (l = clist->row_list, row = 0; l; l = l->next, row++) {
        gchar *titles[C_FI_COLUMNS];
		gnet_fi_t fih = (gnet_fi_t) GPOINTER_TO_UINT(
            ((GtkCListRow *) l->data)->data);

        memset(titles, 0, sizeof(titles));
        fi_gui_fill_status(fih, titles);
        fi_gui_update_row(clist, row, titles, G_N_ELEMENTS(titles));
    }
    gtk_clist_thaw(clist);
}

