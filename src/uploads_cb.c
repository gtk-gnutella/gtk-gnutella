/*
 * $Id$
 *
 * Copyright (c) 2001-2002, Richard Eckart
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

#include "uploads_cb.h"
#include "uploads_gui.h"
#include "upload_stats.h" // FIXME: remove this dependency

/***
 *** Private functions
 ***/

/*
 * kill_upload:
 *
 * Suited for use as a GFunc in a g_list_for_each.
 */
static void kill_upload(upload_row_data_t *d, gpointer user_data)
{
    if (d->valid)
        upload_kill(d->handle);
}

/***
 *** Public functions
 ***/

void on_clist_uploads_select_row(GtkCList *clist, 
    gint row, gint column, GdkEvent *event, gpointer user_data)
{
    GtkWidget *button;

    button = lookup_widget(main_window, "button_uploads_kill");

    gtk_widget_set_sensitive(button, clist->selection != NULL);
}

void on_clist_uploads_unselect_row(GtkCList * clist, 
    gint row, gint column, GdkEvent * event, gpointer user_data)
{
    GtkWidget *button;

    button = lookup_widget(main_window, "button_uploads_kill");

    gtk_widget_set_sensitive(button, clist->selection != NULL);
}

void on_clist_uploads_resize_column(GtkCList * clist, 
    gint column, gint width, gpointer user_data)
{
    // FIXME: use properties
	uploads_col_widths[column] = width;
}

void on_button_uploads_kill_clicked(GtkButton *button, gpointer user_data)
{
    GSList *sl = NULL;
    GtkCList *clist;

    clist = GTK_CLIST(lookup_widget(main_window, "clist_uploads"));

    gtk_clist_freeze(clist);

    sl = clist_collect_data(clist, FALSE, NULL);
    g_slist_foreach(sl, (GFunc) kill_upload, NULL);
    g_slist_free(sl);

    gtk_clist_thaw(clist);
}

void on_button_uploads_clear_completed_clicked(
    GtkButton *button, gpointer user_data)
{
    uploads_gui_clear_completed();
}

/* uploads popup menu */

gboolean on_clist_uploads_button_press_event
    (GtkWidget *widget, GdkEventButton *event, gpointer user_data)
{
	gint row;
    gint col;
    GtkCList *clist_uploads = GTK_CLIST
        (lookup_widget(main_window, "clist_uploads"));

    if (event->button != 3)
		return FALSE;

    if (GTK_CLIST(clist_uploads)->selection == NULL)
        return FALSE;

	if (!gtk_clist_get_selection_info
		(GTK_CLIST(clist_uploads), event->x, event->y, &row, &col))
		return FALSE;

    gtk_menu_popup(GTK_MENU(popup_uploads), NULL, NULL, NULL, NULL, 
                  event->button, event->time);

	return TRUE;
}

void on_popup_uploads_title_activate (GtkMenuItem *menuitem, gpointer user_data) 
{
	// FIXME
}



/***
 *** Upload Stats pane
 ***/

gint compare_ul_size(GtkCList *clist, gconstpointer ptr1,
						 gconstpointer ptr2)
{
	guint32 s1 = ((struct ul_stats *) ((GtkCListRow *) ptr1)->data)->size;
	guint32 s2 = ((struct ul_stats *) ((GtkCListRow *) ptr2)->data)->size;

	return (s1 == s2) ? 0 : (s1 > s2) ? 1 : -1;
}

/*
 * first by complete, then by attempts
 */
gint compare_ul_complete(GtkCList *clist,
	gconstpointer ptr1, gconstpointer ptr2)
{
	guint32 a1 = ((struct ul_stats *) ((GtkCListRow *) ptr1)->data)->attempts;
	guint32 a2 = ((struct ul_stats *) ((GtkCListRow *) ptr2)->data)->attempts;
	guint32 c1 = ((struct ul_stats *) ((GtkCListRow *) ptr1)->data)->complete;
	guint32 c2 = ((struct ul_stats *) ((GtkCListRow *) ptr2)->data)->complete;

	return (c1 != c2) ? ((c1 > c2) ? 1 : -1) : 
		(a1 == a2) ? 0 : (a1 > a2) ? 1 : -1;
}

/*
 * first by normalized, then by complete
 */
gint compare_ul_norm(GtkCList *clist, gconstpointer ptr1,
						 gconstpointer ptr2)
{
	gfloat n1 = ((struct ul_stats *) ((GtkCListRow *) ptr1)->data)->norm;
	gfloat n2 = ((struct ul_stats *) ((GtkCListRow *) ptr2)->data)->norm;

	return (n1 != n2) ? ((n1 > n2) ? 1 : -1) : 
		compare_ul_complete(clist, ptr1, ptr2);
}

/*
 * first by attempts, then by complete
 */
gint compare_ul_attempts(GtkCList *clist, gconstpointer ptr1,
						 gconstpointer ptr2)
{
	guint32 a1 = ((struct ul_stats *) ((GtkCListRow *) ptr1)->data)->attempts;
	guint32 a2 = ((struct ul_stats *) ((GtkCListRow *) ptr2)->data)->attempts;
	guint32 c1 = ((struct ul_stats *) ((GtkCListRow *) ptr1)->data)->complete;
	guint32 c2 = ((struct ul_stats *) ((GtkCListRow *) ptr2)->data)->complete;

	return (a1 != a2) ? ((a1 > a2) ? 1 : -1) : 
		(c1 == c2) ? 0 : (c1 > c2) ? 1 : -1;
}

void on_clist_ul_stats_click_column
    (GtkCList *clist, gint column, gpointer user_data)
{
	static gint ul_sort_column = 2;
	static gint ul_sort_order = GTK_SORT_DESCENDING;

	switch (column) {
	case c_us_filename:
		gtk_clist_set_compare_func(clist, NULL);
		break;
	case c_us_size:
		gtk_clist_set_compare_func(clist, compare_ul_size);
		break;
	case c_us_attempts:
		gtk_clist_set_compare_func(clist, compare_ul_attempts);
		break;
	case c_us_complete:
		gtk_clist_set_compare_func(clist, compare_ul_complete);
		break;
	case c_us_norm:
		gtk_clist_set_compare_func(clist, compare_ul_norm);
		break;
	default:
		g_assert_not_reached();
	}

	if (column == ul_sort_column) {
		ul_sort_order = (ul_sort_order == GTK_SORT_DESCENDING) ? 
			GTK_SORT_ASCENDING : GTK_SORT_DESCENDING;
	} else {
		ul_sort_column = column;
	}
	gtk_clist_set_sort_type(clist, ul_sort_order);
	gtk_clist_set_sort_column(clist, column);
	gtk_clist_sort(clist);
}

void on_clist_ul_stats_resize_column(GtkCList *clist, 
    gint column, gint width, gpointer user_data)
{
    // FIXME: use properties
	ul_stats_col_widths[column] = width;
}

void on_button_ul_stats_clear_all_clicked(GtkButton *button, gpointer data)
{
	upload_stats_clear_all();
}

void on_button_ul_stats_clear_deleted_clicked(GtkButton * button, gpointer user_data)
{
	upload_stats_prune_nonexistent();
}
