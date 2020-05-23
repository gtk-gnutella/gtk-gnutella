/*
 * Copyright (c) 2001-2004, Raphael Manfredi, Richard Eckart
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

#ifndef _gtk_misc_h_
#define _gtk_misc_h_

#include "gui.h"

#include "clipboard.h"

#include "if/ui/gtk/misc.h"

#include "lib/prop.h"

void gui_general_timer(time_t now);
void gui_update_traffic_stats(void);
void gui_update_stats_frames(void);
void gui_fix_coords(guint32 *coord);
void gui_save_window(GtkWidget *widget, property_t prop);
void gui_restore_window(GtkWidget *widget, property_t prop);
gint gui_parse_geometry_spec(const gchar *spec, guint32 coord[4]);
void gui_shrink_widget_named(const char *name);

#ifdef USE_GTK2
void gui_merge_window_as_tab(GtkWidget *toplvl, GtkWidget *notebook,
	GtkWidget *window);
gboolean tree_find_iter_by_data(GtkTreeModel *model, guint column,
	gconstpointer data, GtkTreeIter *iter);
void tree_view_save_widths(GtkTreeView *treeview, property_t prop);
void tree_view_save_visibility(GtkTreeView *treeview, property_t prop);
void tree_view_restore_visibility(GtkTreeView *treeview, property_t prop);
void tree_view_restore_widths(GtkTreeView *treeview, property_t prop);
#endif /* USE_GTK2 */

#ifdef USE_GTK1
void clist_save_visibility(GtkCList *clist, property_t prop);
void clist_save_widths(GtkCList *clist, property_t prop);
void clist_restore_visibility(GtkCList *clist, property_t prop);
void clist_restore_widths(GtkCList *clist, property_t prop);
#endif /* USE_GTK1 */

void paned_save_position(GtkPaned *paned, property_t prop);
void paned_restore_position(GtkPaned *paned, property_t prop);

typedef GtkMenu *(*widget_popup_menu_cb)(void);
void widget_add_popup_menu(GtkWidget *, widget_popup_menu_cb);

void gui_parent_widths_saveto(const void *parent, property_t prop);
void gui_parent_forget(const void *parent);
void gui_column_map(const void *column, const void *parent);
void gui_column_resized(void *column);

void misc_gui_early_init(void);
void misc_gui_shutdown(void);

#endif /* _gtk_misc_h_ */

/* vi: set ts=4 sw=4 cindent: */
