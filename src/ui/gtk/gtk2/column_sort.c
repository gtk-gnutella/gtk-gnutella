/*
 * Copyright (c) 2001-2003 Raphael Manfredi, Richard Eckart
 * Copyright (c) 2014 Raphael Manfredi
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
 * GTK2 tri-state column sorting
 *
 * Here we enforce a tri-state sorting. Normally, GTK+ would only
 * switch between ascending and descending but never switch back
 * to the unsorted state.
 *
 *		+--> sort ascending -> sort descending -> unsorted -+
 *		|                                                   |
 *		+-----------------------<---------------------------+
 *
 * @author Raphael Manfredi
 * @author Richard Eckart
 * @date 2001-2003
 *
 * @author Raphael Manfredi
 * @date 2014
 */

#include "gtk/gui.h"

#include "column_sort.h"

/**
 * Manage the tri-state sorting status on the column.
 *
 * @param column		the clicked column in the tree-view
 * @param ctx			the sorting context we are managing
 */
void
column_sort_tristate(GtkTreeViewColumn *column, struct sorting_context *ctx)
{
#if GTK_CHECK_VERSION(2,6,0)
	GtkTreeModel *model;
	GtkTreeSortable *sortable;
	int sort_col;

	model = gtk_tree_view_get_model(GTK_TREE_VIEW(column->tree_view));
	sortable = GTK_TREE_SORTABLE(model);
	gtk_tree_sortable_get_sort_column_id(sortable, &sort_col, NULL);

	/* If the user switched to another sort column, reset the sort order */
	if (ctx->s_column != sort_col) {
		ctx->s_order = SORT_NONE;
	}

	ctx->s_column = sort_col;

	/* Tri-state permutation of the sorting order */

	switch (ctx->s_order) {
	case SORT_NONE:
	case SORT_NO_COL:
		ctx->s_order = SORT_ASC;
		break;
	case SORT_ASC:
		ctx->s_order = SORT_DESC;
		break;
	case SORT_DESC:
		ctx->s_order = SORT_NONE;
		break;
	}

	/* Enforce sorting order */

	switch (ctx->s_order) {
	case SORT_NONE:
		ctx->s_column = GTK_TREE_SORTABLE_UNSORTED_SORT_COLUMN_ID;
		/* FALL THROUGH */
	case SORT_DESC:
		gtk_tree_sortable_set_sort_column_id(sortable,
			ctx->s_column, GTK_SORT_DESCENDING);
		break;
	case SORT_ASC:
		gtk_tree_sortable_set_sort_column_id(sortable,
			ctx->s_column, GTK_SORT_ASCENDING);
		break;
	case SORT_NO_COL:
		g_assert_not_reached();
	}
#endif	/* GTK+ >= 2.6.0 */
}

/**
 * Convenience routine to plug a callback on the column to handle clicks.
 *
 * The callback should perform the necessary context extraction and then
 * should end-up calling column_sort_tristate().
 *
 * @param column		the column for which we want to handle header clicks
 * @param cb			the GTK callback to invoke
 * @param udata			the parameter to pass to the GTK callback
 */
void
column_sort_tristate_register(GtkTreeViewColumn *column,
	column_tristate_cb_t cb, void *udata)
{
#if GTK_CHECK_VERSION(2,6,0)
	gui_signal_connect_after(column, "clicked", cb, udata);
#endif	/* GTK+ >= 2.6.0 */
}

/* vi: set ts=4 sw=4 cindent: */
