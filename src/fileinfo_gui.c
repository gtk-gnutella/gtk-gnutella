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
#include "fileinfo.h"

#ifdef USE_GTK1

RCSID("$Id$");

static gnet_fi_t last_shown = 0;
static gboolean  last_shown_valid = FALSE;

void on_clist_fileinfo_resize_column(
    GtkCList *clist, gint column, gint width, gpointer user_data)
{
    file_info_col_widths[column] = width;
}

static void fi_gui_set_details(gnet_fi_t fih)
{
    gnet_fi_info_t *fi = NULL;
    gnet_fi_status_t fis;
    gchar **aliases;
    guint n;
    GtkCList *cl_aliases;

    fi = fi_get_info(fih);
    g_assert(fi != NULL);

    fi_get_status(fih, &fis);
    aliases = fi_get_aliases(fih);

    cl_aliases = GTK_CLIST(lookup_widget(main_window, "clist_fi_aliases"));

    gtk_label_set_text(
        GTK_LABEL(lookup_widget(main_window, "label_fi_filename")),
        fi->file_name);
    gtk_label_printf(
        GTK_LABEL(lookup_widget(main_window, "label_fi_size")),
        "%s (%u bytes)", short_size(fis.size), fis.size);

    gtk_clist_freeze(cl_aliases);
    gtk_clist_clear(cl_aliases);
    for(n = 0; aliases[n] != NULL; n++)
        gtk_clist_append(cl_aliases, &aliases[n]);
    gtk_clist_thaw(cl_aliases);
    
    g_strfreev(aliases);
    fi_free_info(fi);

    last_shown = fih;
    last_shown_valid = TRUE;

    gtk_widget_set_sensitive(lookup_widget(main_window, "button_fi_purge"),
        TRUE);
}

static void fi_gui_clear_details()
{
    last_shown_valid = FALSE;

    gtk_label_set_text(
        GTK_LABEL(lookup_widget(main_window, "label_fi_filename")),
        "");
    gtk_label_set_text(
        GTK_LABEL(lookup_widget(main_window, "label_fi_size")),
        "");
    gtk_clist_clear(
        GTK_CLIST(lookup_widget(main_window, "clist_fi_aliases")));
    gtk_widget_set_sensitive(lookup_widget(main_window, "button_fi_purge"),
        FALSE);
}

void on_clist_fileinfo_select_row(GtkCList *clist, gint row, gint column,
    GdkEvent *event, gpointer user_data)
{
    gnet_fi_t fih;
    
    fih = GPOINTER_TO_UINT(gtk_clist_get_row_data(clist, row));

    fi_gui_set_details(fih);
}

void on_clist_fileinfo_unselect_row(GtkCList *clist, gint row, gint column,
    GdkEvent *event, gpointer user_data)
{ 
    if (clist->selection == NULL)
        fi_gui_clear_details();
}

void on_button_fi_purge_clicked(GtkButton *button, gpointer user_data)
{
    if (last_shown_valid)
        fi_purge(last_shown);
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

static gnet_fi_info_t *last_fi = NULL;

/*
 * fi_gui_fill_info:
 *
 * Fill in the cell data. Calling this will always break the data
 * it filled in last time!
 */
static void fi_gui_fill_info(
    gnet_fi_t fih, gchar *titles[c_fi_num])
{
    /* Clear info from last call. We keep this around so we don't
     * have to strdup entries from it when passing them to the 
     * outside through titles[]. */

    if (last_fi != NULL)
        fi_free_info(last_fi);
        
    /* Fetch new info */
    last_fi = fi_get_info(fih);
    g_assert(last_fi != NULL);

    titles[c_fi_filename] = last_fi->file_name;
}

static void fi_gui_fill_status(
    gnet_fi_t fih, gchar *titles[c_fi_num])
{
    gnet_fi_status_t s;
    static gchar fi_sources[32];
    static gchar fi_status[256];
    static gchar fi_done[SIZE_FIELD_MAX+10];
    static gchar fi_size[SIZE_FIELD_MAX];

    fi_get_status(fih, &s);

    gm_snprintf(fi_sources, sizeof(fi_sources), "%d/%d (%d)",
        s.recvcount, s.lifecount, s.refcount);
    titles[c_fi_sources] = fi_sources;

    if (s.done) {
        gm_snprintf(fi_done, sizeof(fi_done), "%s (%.1f%%)", 
            short_size(s.done), ((float) s.done / s.size)*100.0);
        titles[c_fi_done] = fi_done;
    } else {
        titles[c_fi_done] = "-";
    }
        
    gm_snprintf(fi_size, sizeof(fi_size), "%s", short_size(s.size));
    titles[c_fi_size]    = fi_size;

    if (s.recvcount) {
        gm_snprintf(fi_status, sizeof(fi_status), 
            "Downloading (%.1f k/s)", s.recv_last_rate / 1024.0);
        titles[c_fi_status] = fi_status;
    } else if (s.done == s.size){
        titles[c_fi_status] = "Finished";
    } else {
        titles[c_fi_status] = s.lifecount ? "Waiting" : "No sources";
    }
}

static void fi_gui_update(gnet_fi_t fih, gboolean full)
{
    GtkCList *clist;
	gchar    *titles[c_fi_num];
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
	gchar          *titles[c_fi_num];

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

void fi_gui_init(void) 
{
    fi_add_listener((GCallback)fi_gui_fi_added, 
        EV_FI_ADDED, FREQ_SECS, 0);
    fi_add_listener((GCallback)fi_gui_fi_removed, 
        EV_FI_REMOVED, FREQ_SECS, 0);
    fi_add_listener((GCallback)fi_gui_fi_status_changed, 
        EV_FI_STATUS_CHANGED, FREQ_SECS, 2);

    gtk_clist_set_column_justification(
        GTK_CLIST(lookup_widget(main_window, "clist_fileinfo")),
        c_fi_size, GTK_JUSTIFY_RIGHT);
}

void fi_gui_shutdown(void)
{
    fi_remove_listener((GCallback)fi_gui_fi_removed, EV_FI_REMOVED);
    fi_remove_listener((GCallback)fi_gui_fi_added, EV_FI_ADDED);
    fi_remove_listener((GCallback)fi_gui_fi_status_changed, EV_FI_STATUS_CHANGED);
    if (last_fi != NULL)
        fi_free_info(last_fi);
}

/*
 * fi_gui_update_display
 *
 * Update all the fileinfo at the same time.
 */

/* FIXME: we should remember for every node when it was last
 *        updated and only refresh every node at most once every
 *        second. This information should be kept in a struct pointed
 *        to by the row user_data and should be automatically freed
 *        when removing the row (see upload stats code).
 */
/*
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
        gchar *titles[c_fi_num];
		gnet_fi_t fih = (gnet_fi_t) GPOINTER_TO_UINT(
            ((GtkCListRow *) l->data)->data);

        memset(titles, 0, sizeof(titles));
        fi_gui_fill_status(fih, titles);
        fi_gui_update_row(clist, row, titles, G_N_ELEMENTS(titles));
    }
    gtk_clist_thaw(clist);
}
*/

#endif	/* USE_GTK1 */
