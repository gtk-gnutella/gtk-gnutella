/*
 * Copyright (c) 2002, Richard Eckart
 *
 * Functions that should be in gtk-1.2 but are not.
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

#include "gnutella.h"

#include "gtk-missing.h"

/*
 * gtk_paned_get_position:
 *
 * Get position of divider in a GtkPaned. (in GTK2)
 */
gint gtk_paned_get_position(GtkPaned *paned)
{
    g_return_val_if_fail(paned != NULL, -1);
    g_return_val_if_fail(GTK_IS_PANED (paned), -1);

    return paned->child1_size;
}

/*
 * gtk_clist_set_column_name:
 *
 * Set the internal name of the column without changing the
 * column header widget. (Copy paste internal column_title_new
 * from gtkclist.c)
 * BEWARE: EVIL HACK
 */
void gtk_clist_set_column_name(GtkCList * clist, gint col, gchar * t)
{
    if (col < 0 || col >= clist->columns)
        return;

    if (clist->column[col].title)
        g_free(clist->column[col].title);

    clist->column[col].title = g_strdup(t);
}


/*
 * gtk_main_flush:
 *
 * Process all pending gtk events (i.e. draw now!)
 * Returns TRUE if gtk_main_quit has been called 
 * for the innermost mainloop. Aborts flush if
 * gtk_main_quit has been called.
 */
gint gtk_main_flush() 
{
    gint val = FALSE;

    while (!val && gtk_events_pending())
        val = gtk_main_iteration_do(FALSE);

    return val;
}



/*
 * Select the menu item which has given data attached to it.
 */
void option_menu_select_item_by_data(GtkWidget *m, gpointer *d)
{
    GList *l;
    gint n = 0;
    GtkWidget *menu;

    g_assert(m != NULL);
    g_assert(GTK_IS_OPTION_MENU(m));

    menu = GTK_WIDGET(gtk_option_menu_get_menu(GTK_OPTION_MENU(m)));

    for (l = GTK_MENU_SHELL(menu)->children; l != NULL; l = l->next) {
        if (l->data != NULL) {
            if (gtk_object_get_user_data((GtkObject *)l->data) == d) {
                gtk_option_menu_set_history(GTK_OPTION_MENU(m), n); 
                break;
            }
        }

        n ++;
    }

    if (l == NULL)
        g_warning("option_menu_select_item_by_data: no item with data %p", d);
}



/*
 * Add a new menu item to the GtkMenu m, with the label l and
 * the data d.
 */
GtkWidget *menu_new_item_with_data(GtkMenu * m, gchar * l, gpointer d )
{
    GtkWidget *w;                                                     
                         
    g_assert(l != NULL);
                                                 
    w = gtk_menu_item_new_with_label(l);                              
    gtk_object_set_user_data((GtkObject *)w, (gpointer)d);            
    gtk_widget_show(w);                                               
    gtk_menu_append(m, w);    
    return w;
}


/*
 * Fetches the data set associated with the selected menu item in 
 * the GtkOptionMenu m.
 */
gpointer option_menu_get_selected_data(GtkWidget *m)
{
    g_assert(GTK_IS_OPTION_MENU(m));

    return gtk_object_get_user_data                                    
        ((GtkObject *)gtk_menu_get_active(                            
            GTK_MENU(gtk_option_menu_get_menu(GTK_OPTION_MENU(m)))));
}
