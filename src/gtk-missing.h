/*
 * $Id$
 *
 * Copyright (c) 2002, Richard Eckart
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

#ifndef _gtk_missing_h_
#define _gtk_missing_h_

#include <gtk/gtk.h>

#ifndef USE_GTK2
#define gtk_progress_bar_set_text(pb, t) \
    gtk_progress_set_format_string(GTK_PROGRESS(pb), t)
#define gtk_progress_bar_set_fraction(pb, t) \
    gtk_progress_set_percentage(GTK_PROGRESS(pb), t)
gint gtk_paned_get_position(GtkPaned *paned);
#endif

#ifndef USE_GTK2
#define gtk_spin_button_get_value(w) \
    _gtk_spin_button_get_value(w)
#endif

void gtk_clist_set_column_name(GtkCList * clist, gint col, gchar * t);
gint gtk_main_flush(void);
void option_menu_select_item_by_data(GtkWidget *m, gpointer *d);
gpointer option_menu_get_selected_data(GtkWidget *m);
GtkWidget *menu_new_item_with_data(GtkMenu *m, gchar *l, gpointer d );
GtkWidget *radiobutton_get_active_in_group(GtkRadioButton *rb);
void gtk_entry_printf(GtkEntry *entry, const gchar * format, ...);
void gtk_label_printf(GtkLabel *label, const gchar * format, ...);
void gtk_mass_widget_set_sensitive(GtkWidget *tl, gchar *list[], gboolean b);
GSList *clist_collect_data(GtkCList *clist, gboolean allow_null, 
    GCompareFunc cfn);
#ifdef USE_GTK2
GSList *tree_selection_collect_data(GtkTreeSelection *tsel,
    gboolean allow_null, GCompareFunc cfn);
#endif
gdouble _gtk_spin_button_get_value(GtkSpinButton *);
guint32 gtk_editable_get_value_as_uint(GtkEditable *editable);
void gtk_combo_init_choices(
    GtkCombo* combo, GtkSignalFunc func, prop_def_t *def, gpointer user_data);


#endif	/* _gtk_missing_h_ */
