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

#include <gtk/gtkcheckmenuitem.h>

#include "gtkcolumnchooser.h"
#include "misc.h"				/* For RCSID */

RCSID("$Id$");

#if (GTK_MAJOR_VERSION >= 2) 
#define signal_connect g_signal_connect
#else
#define signal_connect gtk_signal_connect
#endif

static GtkWidgetClass * parent_class = NULL;

static void gtk_column_chooser_deactivate(GtkMenuShell *menu_shell);
static gint gtk_column_chooser_button_press(GtkWidget * widget,
                                            GdkEventButton *event);

static void on_popup_hide(GtkWidget * widget, gpointer user_data)
{
    /* 
     * We remove the last reference to the widget and cause it
     * to be destroyed and finalized.
     */
#if (GTK_MAJOR_VERSION >= 2) 
    gtk_object_sink(GTK_OBJECT(widget));
#else
    gtk_object_unref(GTK_OBJECT(widget));
#endif
}

static gpointer gtk_column_chooser_get_column(
	GtkColumnChooser * cc, GtkWidget * widget)
{
    g_assert(widget != NULL);
    g_assert(cc != NULL);

    return g_hash_table_lookup(cc->col_map, widget);
}

static void on_column_popup_toggled(
	GtkCheckMenuItem * checkmenuitem, gpointer user_data)
{
    GtkColumnChooser * cc;

    g_assert(user_data != NULL);
    g_assert(GTK_IS_COLUMN_CHOOSER(user_data));

    cc = GTK_COLUMN_CHOOSER(user_data);

#if (GTK_MAJOR_VERSION >= 2) 
    gtk_tree_view_column_set_visible(
		(GtkTreeViewColumn *) gtk_column_chooser_get_column(cc,
									GTK_WIDGET(checkmenuitem)),
		checkmenuitem->active);
#else
    gtk_clist_set_column_visibility(GTK_CLIST(cc->widget),
         GPOINTER_TO_INT(
			gtk_column_chooser_get_column(cc, GTK_WIDGET(checkmenuitem))),
         checkmenuitem->active);
#endif
}

static void on_column_popup_activate(
	GtkCheckMenuItem * checkmenuitem, gpointer user_data)
{
    g_assert(user_data != NULL);
    g_assert(GTK_IS_COLUMN_CHOOSER(user_data));

    gtk_menu_popdown(GTK_MENU(user_data));
}

GtkWidget * gtk_column_chooser_new(GtkWidget *widget)
{
    GtkColumnChooser * cc;
    GtkMenu * menu;
    GtkWidget * menuitem;
#if (GTK_MAJOR_VERSION >= 2) 
	GtkTreeViewColumn *col;
#endif
	gint i;

    g_assert(NULL != widget);

    cc = gtk_type_new(GTK_TYPE_COLUMN_CHOOSER);
    cc->widget = widget;

    menu = GTK_MENU(cc);

#if (GTK_MAJOR_VERSION >= 2) 
	for (
		i = 0;
		(col = gtk_tree_view_get_column(GTK_TREE_VIEW(widget), i));
		i++
	) {
        menuitem = gtk_check_menu_item_new_with_label(
			gtk_tree_view_column_get_title(col));
        gtk_check_menu_item_set_active(GTK_CHECK_MENU_ITEM(menuitem),
			gtk_tree_view_column_get_visible(col));
    
#else
    for(i = 0; i < GTK_CLIST(widget)->columns; i ++) {
        gchar * title = gtk_clist_get_column_title(GTK_CLIST(widget), i);

        menuitem = gtk_check_menu_item_new_with_label(title);
        gtk_check_menu_item_set_active(GTK_CHECK_MENU_ITEM(menuitem),
			GTK_CLIST(widget)->column[i].visible);
#endif


        /* 
         * Set the GtkColumnChooser instance as user_data, so
         * on_column_popup_toggled knows which instance it
         * has to call to get data from.
         */
        signal_connect(GTK_OBJECT(menuitem), "toggled",
			GTK_SIGNAL_FUNC(on_column_popup_toggled), (gpointer) cc);

#if (GTK_MAJOR_VERSION >= 2) 
		if (0 == i)
			gtk_widget_set_sensitive(menuitem, FALSE); 
#endif
        gtk_widget_show(menuitem);
        gtk_menu_append(menu, menuitem);

        /* map the menu item to the corresponding column */
#if (GTK_MAJOR_VERSION >= 2) 
        g_hash_table_insert(cc->col_map, menuitem, col);
#else
        g_hash_table_insert(cc->col_map, menuitem, GINT_TO_POINTER(i));
#endif
    }

    /* 
     * Add separator and "Done" button.
     */
    menuitem = gtk_menu_item_new();
    gtk_widget_show(menuitem);
    gtk_menu_append(menu, menuitem);

    menuitem = gtk_menu_item_new_with_label("Done");
    
    /* 
     * Set the GtkColumnChooser instance as user_data, so
     * on_column_popup_pressed knows which instance it
     * has to call to get data from.
     */
    signal_connect(GTK_OBJECT(menuitem), "activate",
		GTK_SIGNAL_FUNC(on_column_popup_activate), (gpointer) cc);

    gtk_widget_show(menuitem);
    gtk_menu_append(menu, menuitem);

    /*
     * Connect to the hide signal so we can destroy the menu when is
     * is hidden. That relieves us of the need of keeping track of
     * the menu in the main application. Since the menu has a
     * grab when it's displayed, the application has not much
     * to say anyway.
     */
    signal_connect(GTK_OBJECT(cc), "hide",
		GTK_SIGNAL_FUNC(on_popup_hide), NULL);

    return GTK_WIDGET(cc);
}

static void gtk_column_chooser_finalize(GtkObject * object)
{
    GtkColumnChooser * cc;

    g_assert(object != NULL);
    g_assert(GTK_IS_COLUMN_CHOOSER(object));

    cc = GTK_COLUMN_CHOOSER(object);
    g_hash_table_destroy(cc->col_map);
#if (GTK_MAJOR_VERSION >= 2) 
	G_OBJECT_CLASS(parent_class)->finalize(G_OBJECT(object));
#else
	GTK_OBJECT_CLASS(parent_class)->finalize(object);
#endif
}

static void gtk_column_chooser_init(GtkColumnChooser * cc)
{
    g_assert(cc != NULL);

    cc->widget = NULL;
    cc->col_map = g_hash_table_new((GHashFunc) NULL, (GCompareFunc) NULL);
    cc->closed = FALSE;
}

static void gtk_column_chooser_class_init(GtkColumnChooserClass * klass)
{
    GtkObjectClass * object_class;
    GtkWidgetClass * widget_class;
    GtkMenuShellClass * menu_shell_class;

    g_assert(klass != NULL);

    parent_class = gtk_type_class(GTK_TYPE_MENU);

#if (GTK_MAJOR_VERSION >= 2) 
    object_class = GTK_OBJECT_CLASS(G_OBJECT_CLASS(klass));
#else
    object_class = GTK_OBJECT_CLASS(klass);
#endif
    widget_class = GTK_WIDGET_CLASS(klass);
    menu_shell_class = GTK_MENU_SHELL_CLASS(klass);

    widget_class->button_press_event = gtk_column_chooser_button_press;
    menu_shell_class->deactivate = gtk_column_chooser_deactivate;
#if (GTK_MAJOR_VERSION >= 2) 
	G_OBJECT_CLASS(object_class)->finalize =
		(gpointer) gtk_column_chooser_finalize;
#else
	object_class->finalize = gtk_column_chooser_finalize;
#endif
}

GtkType gtk_column_chooser_get_type()
{
    static guint cct_type = 0;   

    if (!cct_type) {
        GtkTypeInfo cct_info = {
            "GtkColumnChooser",
            sizeof (GtkColumnChooser),
            sizeof (GtkColumnChooserClass),
            (GtkClassInitFunc) gtk_column_chooser_class_init,
            (GtkObjectInitFunc) gtk_column_chooser_init,
            NULL,
            NULL,
            (GtkClassInitFunc) NULL
        };       
        cct_type = gtk_type_unique(GTK_TYPE_MENU, &cct_info);
    }   

    return cct_type;
}

static void gtk_column_chooser_deactivate(GtkMenuShell *menu_shell)
{
    g_assert(menu_shell != NULL);
    g_assert(GTK_IS_COLUMN_CHOOSER(menu_shell));

    if (GTK_COLUMN_CHOOSER(menu_shell)->closed)
        GTK_MENU_SHELL_CLASS(parent_class)->deactivate(menu_shell);
}

static gint gtk_column_chooser_button_press(
	GtkWidget * widget, GdkEventButton *event)
{
    g_return_val_if_fail(widget != NULL, FALSE);
    g_return_val_if_fail(GTK_IS_COLUMN_CHOOSER(widget), FALSE);
    g_return_val_if_fail(event != NULL, FALSE);


    /*
     * If a click outside the choose has taken place, close it.
     */
    if (event->type == GDK_BUTTON_PRESS) {
        if ((event->x < 0) || (event->x >= widget->allocation.width) ||
            (event->y < 0) || (event->y >= widget->allocation.height))

            /* 
             * We accept that the window should be closed and let
             * GtkMenuShell do the actual work of closing and freeing.
             */
            GTK_COLUMN_CHOOSER(widget)->closed = TRUE;
    }

    return GTK_WIDGET_CLASS(parent_class)->button_press_event(widget,event);
}
