/*
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
 *      51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
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
	void *unused_data)
{
	(void) unused_button;
	(void) unused_data;
	guc_upload_stats_clear_all();
}

void
on_button_ul_stats_clear_deleted_clicked(GtkButton *unused_button,
	void *unused_data)
{
	(void) unused_button;
	(void) unused_data;
	guc_upload_stats_prune_nonexistent();
}


#ifdef USE_GTK1
static int
compare_ul_size(GtkCList *unused_clist, const void * ptr1, const void * ptr2)
{
	const GtkCListRow *r1 = ptr1, *r2 = ptr2;
	const struct ul_stats *us1 = r1->data, *us2 = r2->data;
	(void) unused_clist;
	return CMP(us1->size, us2->size);
}

static int compare_ul_attempts(GtkCList *, const void *, const void *);

/**
 * First by complete, then by attempts.
 */
static int
compare_ul_complete(GtkCList *unused_clist,
	const void * ptr1, const void * ptr2)
{
	const GtkCListRow *r1 = ptr1, *r2 = ptr2;
	const struct ul_stats *us1 = r1->data, *us2 = r2->data;
	int ret;
	(void) unused_clist;
	ret = CMP(us1->complete, us2->complete);
	/* Avoid double recursion through compare_ul_attempts() -- inline it here */
	return ret ? ret : CMP(us1->attempts, us2->attempts);
}

/**
 * First by normalized, then by complete.
 */
int
compare_ul_norm(GtkCList *clist, const void * ptr1, const void * ptr2)
{
	const GtkCListRow *r1 = ptr1, *r2 = ptr2;
	const struct ul_stats *us1 = r1->data, *us2 = r2->data;
	int ret;
	double delta = us1->norm - us2->norm;
	if (ABS(delta) < 1e-56)
		ret = 0;
	else
		ret = us1->norm < us2->norm ? -1 : +1;
	return ret ? ret : compare_ul_complete(clist, ptr1, ptr2);
}

/**
 * First by attempts, then by complete.
 */
static int
compare_ul_attempts(GtkCList *clist, const void * ptr1, const void * ptr2)
{
	const GtkCListRow *r1 = ptr1, *r2 = ptr2;
	const struct ul_stats *us1 = r1->data, *us2 = r2->data;
	int ret;
	ret = CMP(us1->attempts, us2->attempts);
	return ret ? ret : compare_ul_complete(clist, ptr1, ptr2);
}

static int
compare_ul_rtime(GtkCList *unused_clist, const void * ptr1, const void * ptr2)
{
	const GtkCListRow *r1 = ptr1, *r2 = ptr2;
	const struct ul_stats *us1 = r1->data, *us2 = r2->data;
	(void) unused_clist;
	return CMP(us1->rtime, us2->rtime);
}

static int
compare_ul_dtime(GtkCList *unused_clist, const void * ptr1, const void * ptr2)
{
	const GtkCListRow *r1 = ptr1, *r2 = ptr2;
	const struct ul_stats *us1 = r1->data, *us2 = r2->data;
	(void) unused_clist;
	return CMP(us1->dtime, us2->dtime);
}

void
on_clist_ul_stats_click_column(GtkCList *clist, int column, void *unused_udata)
{
	static int ul_sort_column = 2;
	static int ul_sort_order = GTK_SORT_DESCENDING;

	g_return_if_fail(column >= 0);
	g_return_if_fail(column < c_us_num);

	(void) unused_udata;
	switch ((enum c_us) column) {
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
	case c_us_rtime:
		gtk_clist_set_compare_func(clist, compare_ul_rtime);
		break;
	case c_us_dtime:
		gtk_clist_set_compare_func(clist, compare_ul_dtime);
		break;
	case c_us_num:
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

#endif /* USE_GTK1 */

#ifdef USE_GTK2
void
on_popup_upload_stats_config_cols_activate(GtkMenuItem *unused_menuitem,
	void *unused_udata)
{
    GtkWidget *cc;

	(void) unused_menuitem;
	(void) unused_udata;

    cc = gtk_column_chooser_new(gui_main_window_lookup("treeview_ul_stats"));
    gtk_menu_popup(GTK_MENU(cc), NULL, NULL, NULL, NULL, 0,
		gtk_get_current_event_time());
}
#endif /* USE_GTK2 */

/* vi: set ts=4 sw=4: */
