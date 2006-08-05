/*
 * $Id$
 *
 * Copyright (c) 2003, Raphael Manfredi
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

/**
 * @ingroup gtk
 * @file
 *
 * Handles common GUI operations for upload stats.
 *
 * @author Raphael Manfredi
 * @date 2003
 * @author Richard Eckart
 * @date 2001-2003
 */

#include "gui.h"

RCSID("$Id$")

#include "upload_stats_cb.h"
#include "upload_stats.h"
#include "gtkcolumnchooser.h"
#include "columns.h"

#include "if/bridge/ui2c.h"
#include "if/gui_property_priv.h"

#include "lib/override.h"		/* Must be the last header included */


/***
 *** Upload Stats pane
 ***/

void
on_button_ul_stats_clear_all_clicked(GtkButton *unused_button,
	gpointer unused_data)
{
	(void) unused_button;
	(void) unused_data;
	guc_upload_stats_clear_all();
}

void
on_button_ul_stats_clear_deleted_clicked(GtkButton *unused_button,
	gpointer unused_data)
{
	(void) unused_button;
	(void) unused_data;
	guc_upload_stats_prune_nonexistent();
}


#ifdef USE_GTK1
static gint
compare_ul_size(GtkCList *unused_clist, gconstpointer ptr1, gconstpointer ptr2)
{
	guint32 s1;
	guint32 s2;

	(void) unused_clist;
	s1 = ((const struct ul_stats *) ((const GtkCListRow *) ptr1)->data)->size;
	s2 = ((const struct ul_stats *) ((const GtkCListRow *) ptr2)->data)->size;

	return (s1 == s2) ? 0 : (s1 > s2) ? 1 : -1;
}

/**
 * First by complete, then by attempts.
 */
static gint
compare_ul_complete(GtkCList *unused_clist,
	gconstpointer ptr1, gconstpointer ptr2)
{
	guint32 a1 = ((const struct ul_stats *)
		((const GtkCListRow *) ptr1)->data)->attempts;
	guint32 a2 = ((const struct ul_stats *)
		((const GtkCListRow *) ptr2)->data)->attempts;
	guint32 c1 = ((const struct ul_stats *)
		((const GtkCListRow *) ptr1)->data)->complete;
	guint32 c2 = ((const struct ul_stats *)
		((const GtkCListRow *) ptr2)->data)->complete;

	(void) unused_clist;
	return (c1 != c2) ? ((c1 > c2) ? 1 : -1) :
		(a1 == a2) ? 0 : (a1 > a2) ? 1 : -1;
}

/**
 * First by normalized, then by complete.
 */
gint
compare_ul_norm(GtkCList *clist, gconstpointer ptr1, gconstpointer ptr2)
{
	gfloat n1;
	gfloat n2;

	n1 = ((const struct ul_stats *) ((const GtkCListRow *) ptr1)->data)->norm;
	n2 = ((const struct ul_stats *) ((const GtkCListRow *) ptr2)->data)->norm;

	return (n1 != n2) ? ((n1 > n2) ? 1 : -1) :
		compare_ul_complete(clist, ptr1, ptr2);
}

/**
 * First by attempts, then by complete.
 */
static gint
compare_ul_attempts(GtkCList *unused_clist,
	gconstpointer ptr1, gconstpointer ptr2)
{
	guint32 a1 = ((const struct ul_stats *)
		((const GtkCListRow *) ptr1)->data)->attempts;
	guint32 a2 = ((const struct ul_stats *)
		((const GtkCListRow *) ptr2)->data)->attempts;
	guint32 c1 = ((const struct ul_stats *)
		((const GtkCListRow *) ptr1)->data)->complete;
	guint32 c2 = ((const struct ul_stats *)
		((const GtkCListRow *) ptr2)->data)->complete;

	(void) unused_clist;
	return (a1 != a2) ? ((a1 > a2) ? 1 : -1) :
		(c1 == c2) ? 0 : (c1 > c2) ? 1 : -1;
}

void
on_clist_ul_stats_click_column(GtkCList *clist, gint column,
	gpointer unused_udata)
{
	static gint ul_sort_column = 2;
	static gint ul_sort_order = GTK_SORT_DESCENDING;

	(void) unused_udata;
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

void
on_clist_ul_stats_resize_column(GtkCList *unused_clist,
	gint column, gint width, gpointer unused_udata)
{
	(void) unused_clist;
	(void) unused_udata;
    /* FIXME: use properties */
	*(gint *) &ul_stats_col_widths[column] = width;
}

#endif /* USE_GTK1 */

#ifdef USE_GTK2
void
on_popup_upload_stats_config_cols_activate(GtkMenuItem *unused_menuitem,
	gpointer unused_udata)
{
    GtkWidget *cc;

	(void) unused_menuitem;
	(void) unused_udata;
    cc = gtk_column_chooser_new(
			lookup_widget(main_window, "treeview_ul_stats"));
    gtk_menu_popup(GTK_MENU(cc), NULL, NULL, NULL, NULL, 0, GDK_CURRENT_TIME);
}
#endif /* USE_GTK2 */

/* vi: set ts=4 sw=4: */
