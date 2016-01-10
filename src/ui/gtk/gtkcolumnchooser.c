/*
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

#include "gui.h"

#include <gtk/gtkcheckmenuitem.h>

#include "gtkcolumnchooser.h"
#include "lib/htable.h"
#include "lib/override.h"				/* Must be the last header included */

static GtkWidgetClass *parent_class;

static void gtk_column_chooser_deactivate(GtkMenuShell *menu_shell);
static gint gtk_column_chooser_button_press(GtkWidget * widget,
                                            GdkEventButton *event);

static void
on_popup_hide(GtkWidget *widget, gpointer unused_udata)
{
	(void) unused_udata;

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

static gpointer
gtk_column_chooser_get_column(GtkColumnChooser *cc, GtkWidget *widget)
{
    g_return_val_if_fail(widget != NULL, NULL);
	g_return_val_if_fail(cc != NULL, NULL);

    return htable_lookup(cc->col_map, widget);
}

static void
on_column_popup_toggled(GtkCheckMenuItem *checkmenuitem, gpointer user_data)
{
    GtkColumnChooser * cc;

    g_return_if_fail(user_data != NULL);
    g_return_if_fail(GTK_IS_COLUMN_CHOOSER(user_data));

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

static void
on_column_popup_activate(GtkCheckMenuItem *unused_checkmenuitem,
	gpointer user_data)
{
    g_return_if_fail(user_data != NULL);
    g_return_if_fail(GTK_IS_COLUMN_CHOOSER(user_data));
	(void) unused_checkmenuitem;

    gtk_menu_popdown(GTK_MENU(user_data));
}

static gboolean
has_nth_column(GtkWidget *widget, gint i)
{
#if (GTK_MAJOR_VERSION >= 2)
	return NULL != gtk_tree_view_get_column(GTK_TREE_VIEW(widget), i);
#else
	return i < GTK_CLIST(widget)->columns;
#endif /* Gtk+ >= 2.0 */
}

static gpointer
get_nth_column(GtkWidget *widget, gint i, GtkWidget **menuitem_ptr)
#if (GTK_MAJOR_VERSION >= 2)
{
	GtkWidget *menuitem = NULL;
	GtkTreeViewColumn *col;

	g_assert(menuitem_ptr);
	*menuitem_ptr = NULL;

	g_return_val_if_fail(widget != NULL, NULL);
	g_return_val_if_fail(i >= 0, NULL);

	col = gtk_tree_view_get_column(GTK_TREE_VIEW(widget), i);
	if (col) {
		const gchar *title;
		gboolean visible;

		title = gtk_tree_view_column_get_title(col);
		visible = gtk_tree_view_column_get_visible(col);
		menuitem = gtk_check_menu_item_new_with_label(title);
		gtk_check_menu_item_set_active(GTK_CHECK_MENU_ITEM(menuitem), visible);
	}
	*menuitem_ptr = menuitem;

	return col;
}
#else
{
	GtkWidget *menuitem = NULL;

	g_assert(menuitem_ptr);
	*menuitem_ptr = NULL;

	g_return_val_if_fail(widget != NULL, NULL);
	g_return_val_if_fail(i >= 0, NULL);

	if (i < GTK_CLIST(widget)->columns) {
		gchar *title;
		gboolean visible;

		title = gtk_clist_get_column_title(GTK_CLIST(widget), i);
		menuitem = gtk_check_menu_item_new_with_label(title);
		visible = GTK_CLIST(widget)->column[i].visible;
		gtk_check_menu_item_set_active(GTK_CHECK_MENU_ITEM(menuitem), visible);
	}
	*menuitem_ptr = menuitem;

	return GINT_TO_POINTER(i);
}
#endif /* Gtk+ >= 2.0 */

GtkWidget *
gtk_column_chooser_new(GtkWidget *widget)
{
    GtkColumnChooser *cc;
    GtkWidget *menuitem;
    GtkMenu *menu;
	gint i;

	g_return_val_if_fail(widget != NULL, NULL);

    cc = gtk_type_new(GTK_TYPE_COLUMN_CHOOSER);
    cc->widget = widget;
    menu = GTK_MENU(cc);

	for (i = 0; has_nth_column(widget, i); i++) {
		gpointer p;

		p = get_nth_column(widget, i, &menuitem);

        /*
         * Set the GtkColumnChooser instance as user_data, so
         * on_column_popup_toggled knows which instance it
         * has to call to get data from.
         */
        gui_signal_connect(menuitem, "toggled", on_column_popup_toggled, cc);

        gtk_widget_show(menuitem);
        gtk_menu_append(menu, menuitem);

        /* map the menu item to the corresponding column */
        htable_insert(cc->col_map, menuitem, p);
    }

    /*
     * Add separator and "Done" button.
     */
    menuitem = gtk_menu_item_new();
    gtk_widget_show(menuitem);
    gtk_menu_append(menu, menuitem);

    menuitem = gtk_menu_item_new_with_label(_("Done"));

    /*
     * Set the GtkColumnChooser instance as user_data, so
     * on_column_popup_pressed knows which instance it
     * has to call to get data from.
     */
    gui_signal_connect(menuitem, "activate", on_column_popup_activate, cc);

    gtk_widget_show(menuitem);
    gtk_menu_append(menu, menuitem);

    /*
     * Connect to the hide signal so we can destroy the menu when is
     * is hidden. That relieves us of the need of keeping track of
     * the menu in the main application. Since the menu has a
     * grab when it's displayed, the application has not much
     * to say anyway.
     */
    gui_signal_connect(cc, "hide", on_popup_hide, NULL);

    return GTK_WIDGET(cc);
}

#if GTK_CHECK_VERSION(2, 0, 0)
static void
gtk_column_chooser_init(GTypeInstance *instance, gpointer unused_g_class)
{
    GtkColumnChooser *cc;

	g_return_if_fail(instance != NULL);
	(void) unused_g_class;

	cc = (GtkColumnChooser *) instance;
    cc->widget = NULL;
    cc->col_map = htable_create(HASH_KEY_SELF, 0);
    cc->closed = FALSE;
}

static void
gtk_column_chooser_finalize(GObject *object)
{
    GtkColumnChooser *cc;

	g_return_if_fail(object != NULL);
    g_return_if_fail(GTK_IS_COLUMN_CHOOSER(object));

    cc = GTK_COLUMN_CHOOSER(object);
    htable_free_null(&cc->col_map);
	G_OBJECT_CLASS(parent_class)->finalize(G_OBJECT(object));
}

static void
gtk_column_chooser_class_init(gpointer g_class, gpointer unused_class_data)
{
    GObjectClass *object_class;
    GtkWidgetClass *widget_class;
    GtkMenuShellClass *menu_shell_class;

	(void) unused_class_data;
    g_return_if_fail(g_class != NULL);

    parent_class = gtk_type_class(GTK_TYPE_MENU);
    object_class = G_OBJECT_CLASS(g_class);
    widget_class = GTK_WIDGET_CLASS(g_class);
    menu_shell_class = GTK_MENU_SHELL_CLASS(g_class);
    widget_class->button_press_event = gtk_column_chooser_button_press;
    menu_shell_class->deactivate = gtk_column_chooser_deactivate;
	object_class->finalize = gtk_column_chooser_finalize;
}

GType
gtk_column_chooser_get_type(void)
{
    static GType cct_type;

    if (!cct_type) {
        static GTypeInfo type_info_zero;
        GTypeInfo cct_info;

		cct_info = type_info_zero;
		cct_info.class_size = sizeof(GtkColumnChooserClass);
		cct_info.class_init = gtk_column_chooser_class_init;
		cct_info.instance_size = sizeof (GtkColumnChooser);
		cct_info.instance_init = gtk_column_chooser_init;
        cct_type = g_type_register_static(GTK_TYPE_MENU,
					"GtkColumnChooser", &cct_info, 0);
    }

    return cct_type;
}

#else

static void
gtk_column_chooser_init(GtkColumnChooser *cc)
{
	g_return_if_fail(cc != NULL);

    cc->widget = NULL;
    cc->col_map = htable_create(HASH_KEY_SELF, 0);
    cc->closed = FALSE;
}

static void
gtk_column_chooser_finalize(GtkObject *object)
{
    GtkColumnChooser *cc;

	g_return_if_fail(object != NULL);
	g_return_if_fail(GTK_IS_COLUMN_CHOOSER(object));

    cc = GTK_COLUMN_CHOOSER(object);
    htable_free_null(&cc->col_map);
	GTK_OBJECT_CLASS(parent_class)->finalize(object);
}

static void
gtk_column_chooser_class_init(GtkColumnChooserClass *klass)
{
    GtkObjectClass * object_class;
    GtkWidgetClass * widget_class;
    GtkMenuShellClass * menu_shell_class;

	g_return_if_fail(klass != NULL);

    parent_class = gtk_type_class(GTK_TYPE_MENU);
    object_class = GTK_OBJECT_CLASS(klass);
    widget_class = GTK_WIDGET_CLASS(klass);
    menu_shell_class = GTK_MENU_SHELL_CLASS(klass);
    widget_class->button_press_event = gtk_column_chooser_button_press;
    menu_shell_class->deactivate = gtk_column_chooser_deactivate;
	object_class->finalize = gtk_column_chooser_finalize;
}

GtkType
gtk_column_chooser_get_type(void)
{
    static GtkType cct_type;

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
#endif

static void
gtk_column_chooser_deactivate(GtkMenuShell *menu_shell)
{
	g_return_if_fail(menu_shell != NULL);
	g_return_if_fail(GTK_IS_COLUMN_CHOOSER(menu_shell));

    if (GTK_COLUMN_CHOOSER(menu_shell)->closed)
        GTK_MENU_SHELL_CLASS(parent_class)->deactivate(menu_shell);
}

static gint
gtk_column_chooser_button_press(GtkWidget * widget, GdkEventButton *event)
{
    g_return_val_if_fail(widget != NULL, FALSE);
    g_return_val_if_fail(event != NULL, FALSE);
    g_return_val_if_fail(GTK_IS_COLUMN_CHOOSER(widget), FALSE);


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

/* vi: set ts=4 sw=4 cindent: */
