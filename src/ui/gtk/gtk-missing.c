/*
 * Copyright (c) 2002-2003, Richard Eckart
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
 * Missing functions in the GTK+.
 *
 * Functions that should be in GTK+ 1.2 or GTK+ 2.x but are not.
 *
 * @author Richard Eckart
 * @date 2002-2003
 */

#include "gui.h"

#include "columns.h"

#ifdef USE_GTK1
/* For gtk_window_iconify() */
#include <gdk/gdkx.h>
#include <X11/Xlib.h>
#endif

#include "if/gui_property.h"
#include "if/gui_property_priv.h"

#include "lib/glib-missing.h"
#include "lib/misc.h"
#include "lib/str.h"
#include "lib/walloc.h"

#include "lib/override.h"		/* Must be the last header included */

/**
 * @fn gtk_paned_get_position(GtkPaned *paned)
 *
 * Get position of divider in a GtkPaned. (in GTK2)
 */
#ifndef USE_GTK2
gint
gtk_paned_get_position(GtkPaned *paned)
{
    g_return_val_if_fail(paned != NULL, -1);
    g_return_val_if_fail(GTK_IS_PANED (paned), -1);

    return paned->child1_size;
}
#endif

#ifdef USE_GTK1
/**
 * Set the internal name of the column without changing the
 * column header widget. (Copy paste internal column_title_new
 * from gtkclist.c)
 *
 * @warning EVIL HACK
 */
void
gtk_clist_set_column_name(GtkCList *clist, int col, const char *title)
{
    if (col >= 0 && col < clist->columns) {
		if (
			NULL == title ||
			NULL == clist->column[col].title ||
			0 != strcmp(clist->column[col].title, title)
		) {
			G_FREE_NULL(clist->column[col].title);
			clist->column[col].title = NOT_LEAKING(g_strdup(title));
		}
	}
}

void
clist_sync_rows(GtkCList *clist, void (*func)(int, void *))
{
	GList *iter;
	int i;

	g_return_if_fail(clist);
	g_return_if_fail(func);

	i = 0;
	for (iter = clist->row_list; NULL != iter; iter = g_list_next(iter), i++) {
		GtkCListRow *row;

		row = iter->data;
		(*func)(i, row->data);
	}
}

char *
clist_copy_text(GtkCList *clist, int row, int column)
{
	char *text;

	g_return_val_if_fail(clist, NULL);

	if (
		row < 0 ||
		column < 0 ||
		!gtk_clist_get_text(GTK_CLIST(clist), row, column, &text)
	) {
		text = NULL;
	}
	return g_strdup(text);
}

static int
clist_get_focus_row(GtkCList *clist)
{
	g_return_val_if_fail(clist, -1);

	if (
		GTK_WIDGET_HAS_FOCUS(GTK_WIDGET(clist))
		&& clist->focus_row >= 0
		&& clist->focus_row < clist->rows
	) {
		return clist->focus_row;
	}
	return -1;
}

static gboolean
clist_row_is_selected(GtkCList *clist, int row)
{
	const GList *node;

	g_return_val_if_fail(clist, FALSE);
	g_return_val_if_fail(row >= 0, FALSE);
	g_return_val_if_fail(row < clist->rows, FALSE);

	node = g_list_nth(clist->row_list, row);
	g_return_val_if_fail(node, FALSE);

	return GTK_STATE_SELECTED == GTK_CLIST_ROW(node)->state;
}

int
clist_get_cursor_row(GtkCList *clist)
{
	int row;

	g_return_val_if_fail(clist, -1);

	row = clist_get_focus_row(clist);
	return row >= 0 && clist_row_is_selected(clist, row) ? row : -1;
}
#endif /* USE_GTK1 */

#define GTK_ITERATION_MAX	100		/* Don't spend too much time in GUI */

/**
 * Process all pending gtk events (id est draw now!).
 *
 * @returns TRUE if gtk_main_quit has been called
 * for the innermost mainloop. Aborts flush if
 * gtk_main_quit has been called.
 */
gint
gtk_main_flush(void)
{
    gint val = FALSE;
	gint i = 0;

    while (gtk_events_pending() && i++ < GTK_ITERATION_MAX) {
        val = gtk_main_iteration_do(FALSE);
		if (val)
			break;
	}

	if (i > GTK_ITERATION_MAX && !val) {
		if (GUI_PROPERTY(gui_debug)) {
			g_warning("%s(): too much work", G_STRFUNC);
		}
	}

    return val;
}

/**
 * Select the menu item which has given data attached to it.
 */
void
option_menu_select_item_by_data(GtkOptionMenu *option_menu, gconstpointer data)
{
    GList *iter;
    gint i;

    g_assert(option_menu);
    g_assert(GTK_IS_OPTION_MENU(option_menu));

    iter = GTK_MENU_SHELL(gtk_option_menu_get_menu(option_menu))->children;
    for (i = 0; iter != NULL; iter = g_list_next(iter), i++) {
        if (iter->data && gtk_object_get_user_data(iter->data) == data) {
			gtk_option_menu_set_history(option_menu, i);
			return;
        }
    }

	g_warning("%s(): no item with data %p", G_STRFUNC, data);
}



/**
 * Add a new menu item to the GtkMenu "menu" with the label "label_text" and
 * the data "data".
 */
GtkWidget *
menu_new_item_with_data(GtkMenu *menu, const gchar *label_text, gpointer data)
{
    GtkWidget *widget;

    g_assert(menu);
    g_assert(label_text);

    widget = gtk_menu_item_new_with_label(label_text);
    gtk_object_set_user_data(GTK_OBJECT(widget), data);
    gtk_widget_show(widget);
    gtk_menu_append(menu, widget);
    return widget;
}


/**
 * Fetches the data set associated with the selected menu item in
 * the GtkOptionMenu m.
 */
gpointer
option_menu_get_selected_data(GtkOptionMenu *option_menu)
{
    GtkWidget *menu;

    g_assert(GTK_IS_OPTION_MENU(option_menu));

    menu = gtk_menu_get_active(GTK_MENU(gtk_option_menu_get_menu(option_menu)));
    return menu ? gtk_object_get_user_data(GTK_OBJECT(menu)) : NULL;
}

/**
 * Given a radio button it returns a pointer to the active radio
 * button in the group the given button is in.
 *
 * @returns NULL if there is no active button.
 */
GtkWidget *
radiobutton_get_active_in_group(GtkRadioButton *rb)
{
    GSList *i;

    g_assert(rb != NULL);

    for (i = gtk_radio_button_group(rb); i != NULL; i = g_slist_next(i)) {
        GtkToggleButton *tb = GTK_TOGGLE_BUTTON(i->data);

        if (gtk_toggle_button_get_active(tb))
            return GTK_WIDGET(tb);
    }

    return NULL;
}


/**
 * printf into a gtk_entry.
 */
void
gtk_entry_printf(GtkEntry *entry, const gchar *format, ...)
{
    static gchar buf[1024];
    va_list args;

    g_assert(entry != NULL);

    va_start(args, format);

    if (format != NULL)
        str_vbprintf(ARYLEN(buf), format, args);
    else
        buf[0] = '\0';

    gtk_entry_set_text(entry, buf);

    va_end(args);
}

/**
 * printf into a GtkLabel.
 */
void gtk_label_printf(GtkLabel *label, const gchar *format, ...)
{
    static gchar buf[1024];
    va_list args;

    g_assert(label != NULL);

    va_start(args, format);

    if (format != NULL)
        str_vbprintf(ARYLEN(buf), format, args);
    else
        buf[0] = '\0';

    gtk_label_set_text(label, buf);

    va_end(args);
}


#ifdef USE_GTK1
const char *
gtk_label_get_text(GtkLabel *label)
{
	const char *text = NULL;

	g_return_val_if_fail(label, NULL);
	gtk_label_get(GTK_LABEL(label), (char **) &text);
	return text;
}
#endif	/* USE_GTK1 */

/**
 * Takes an array of strings which are supposed to be widgets names found with
 * the given top-level widget. Sets all to the given sentitivity state.
 */
void
gtk_mass_widget_set_sensitive(GtkWidget *toplevel,
	const gchar * const list[], guint n, gboolean b)
{
    guint i;

    g_assert(toplevel != NULL);

    for (i = 0; i < n; i++)
        gtk_widget_set_sensitive(lookup_widget(toplevel, list[i]), b);
}

/**
 * Fetch data from the selection of a clist. Returns a GSList containing
 * the user_data pointers from the selected rows. If allow_null is TRUE,
 * the returned list may contain NULL pointers. If cfn != NULL, it will
 * be used to determine whether two entries are equal and drop all duplicate
 * items from the result list. Using cfn will significantly increase runtime.
 */
GSList *
clist_collect_data(GtkCList *clist, gboolean allow_null, GCompareFunc cfn)
{
    GSList *result_list = NULL;
    GList *l;
    GSList *sl;
    GSList *to_unselect = NULL;

    g_assert(clist != NULL);

    /*
     * Collect the data of the selected rows.
     */
    for (l = clist->selection; l != NULL; l = g_list_next(l)) {
        gpointer data;
        gint row;

        row = GPOINTER_TO_INT(l->data);
        data = gtk_clist_get_row_data(clist, row);

        if ((data != NULL) || allow_null) {
            if (cfn != NULL) {
                if (g_slist_find_custom(result_list, data, cfn) != NULL) {
                    if (GUI_PROPERTY(gui_debug) >= 3) {
                        const gchar *name =
                            gtk_widget_get_name(GTK_WIDGET(clist));
                        printf("%s has duplicate data: %p\n",
                            (name != NULL) ? name : "<UNKNOWN>", data);
                    }
                    to_unselect =
						g_slist_prepend(to_unselect, GINT_TO_POINTER(row));
                    continue;
                }
            }
            result_list = g_slist_prepend(result_list, data);
            to_unselect = g_slist_prepend(to_unselect, GINT_TO_POINTER(row));
        } else {
            if (GUI_PROPERTY(gui_debug) >= 3) {
                const gchar *name = gtk_widget_get_name(GTK_WIDGET(clist));
                printf("%s contains NULL data in row %d\n",
                    (name != NULL) ? name : "<UNKNOWN>", row);
            }
        }
    }

    /*
     * Unselect the rows from which data has been sucessfully gathered.
     */
    for (sl = to_unselect; sl != NULL; sl = g_slist_next(sl))
        gtk_clist_unselect_row(clist, GPOINTER_TO_INT(sl->data), 0);

    g_slist_free(to_unselect);

    return result_list;
}


#ifdef USE_GTK2

/**
 * @return a pointer to a newly allocated GtkTreeIter. Must be freed
 * with w_tree_iter_free().
 */
GtkTreeIter *
w_tree_iter_new(void)
{
	GtkTreeIter *iter;

	WALLOC(iter);
	return iter;
}

/**
 * Same as gtk_tree_iter_copy() but uses walloc(). Use w_tree_iter_free()
 * to free the returned GtkTreeIter.
 */
GtkTreeIter *
w_tree_iter_copy(GtkTreeIter *iter)
{
	GtkTreeIter *copy;

	WALLOC(copy);
	*copy = *iter;		/* Struct copy */
	return copy;
}

/**
 * Use this to free a GtkTreeIter returned by w_tree_iter_copy().
 */
void
w_tree_iter_free(GtkTreeIter *iter)
{
	WFREE(iter);
}

/**
 * For use as GDestroyNotify function.
 */
void
ht_w_tree_iter_free(gpointer p)
{
	GtkTreeIter *iter = p;
	WFREE(iter);
}


typedef struct collect_data_struct {
    GSList *results;
    GSList *to_unselect;
	GCompareFunc cfn;
	tree_selection_get_data_func gdf;
	GtkTreeView *tv;
	const gchar *name; /* name of the treeview widget (for debugging) */
	guint column;
} collect_data_struct_t;

static inline void
tree_selection_collect_data_record(GtkTreeModel *model, GtkTreeIter *iter,
		collect_data_struct_t *cdata, gboolean unselect)
{
	gpointer data;

	g_assert(NULL != cdata);
	g_assert(NULL != iter);

	data = cdata->gdf(model, iter);

	if (unselect) {
		cdata->to_unselect = g_slist_prepend(cdata->to_unselect,
								w_tree_iter_copy(iter));
	}

	if (NULL != cdata->cfn &&
		NULL != g_slist_find_custom(cdata->results, data, cdata->cfn)) {
		if (GUI_PROPERTY(gui_debug) >= 3)
			g_warning("%s has duplicate data: %p", cdata->name, data);
		return;
	}
	cdata->results = g_slist_prepend(cdata->results, data);
}

static void
tree_selection_collect_data_helper(GtkTreeModel *model,
	GtkTreePath *path, GtkTreeIter *iter, gpointer user_data)
{
	collect_data_struct_t *cdata = user_data;

	/* Collect the data of the parent row */
	tree_selection_collect_data_record(model, iter, cdata, TRUE);

	/* If the row is not expanded and there are any children, collect their
	 * data as well. This is not recursive and descends only one level */

	if (
			gtk_tree_model_iter_has_child(model, iter) &&
			!gtk_tree_view_row_expanded(cdata->tv, path)
	) {
		GtkTreeIter child;
		gint i = 0;

		while (gtk_tree_model_iter_nth_child(model, &child, iter, i)) {
			tree_selection_collect_data_record(model, &child, cdata, FALSE);
			i++;
		}
	}
}

static void
tree_selection_unselect_helper(gpointer data, gpointer user_data)
{
	GtkTreeSelection *s = user_data;
	GtkTreeIter *iter = data;

	gtk_tree_selection_unselect_iter(s, iter);
	w_tree_iter_free(iter);
}

/**
 * Fetch data from the selection of a treeview. Returns a GSList containing
 * the user_data pointers from the selected rows. If cfn != NULL, it will
 * be used to determine whether two entries are equal and drop all duplicate
 * items from the result list. Using cfn will significantly increase runtime.
 */
GSList *
tree_selection_collect_data(GtkTreeSelection *selection,
	tree_selection_get_data_func gdf, GCompareFunc cfn)
{
	collect_data_struct_t cdata;

    g_assert(NULL != selection);

	cdata.results = NULL;
	cdata.to_unselect = NULL;
	cdata.cfn = cfn;
	cdata.gdf = gdf;
	cdata.tv = gtk_tree_selection_get_tree_view(selection);
	if (GUI_PROPERTY(gui_debug) >= 3) {
		cdata.name = gtk_widget_get_name(
			GTK_WIDGET(gtk_tree_selection_get_tree_view(selection)));
		if (NULL == cdata.name)
			cdata.name = "<UNKNOWN>";
	} else
		cdata.name = NULL;

    /*
     * Browse selected rows and gather data.
     */
	gtk_tree_selection_selected_foreach(selection,
		tree_selection_collect_data_helper, &cdata);

    /*
     * Now unselect the rows from which we got data.
     */
	g_slist_foreach(cdata.to_unselect,
		tree_selection_unselect_helper, selection);

    /*
     * Cleanup before exit.
     */
    gm_slist_free_null(&cdata.to_unselect);

    return cdata.results;
}

struct tree_view_motion {
	tree_view_motion_callback cb;
	GtkTreeView *tv;
	guint signal_id;
	guint timeout_id;
	guint x, y;
	gboolean ready;
};

static gboolean
on_tree_view_motion_notify(GtkWidget *widget,
	GdkEventMotion *event, gpointer udata)
{
	tree_view_motion_t *tvm;

	g_assert(widget != NULL);
	g_assert(event != NULL);

	tvm = udata;
	g_assert(tvm != NULL);
	g_assert(tvm->cb != NULL);

#if 0
	{
		gchar type[32];
#define EVENT_TYPE(x) case x: str_bprintf(type, sizeof type, "%s", #x); break;
		switch (event->type) {
		EVENT_TYPE(GDK_NOTHING)
		EVENT_TYPE(GDK_DESTROY)
		EVENT_TYPE(GDK_EXPOSE)
		EVENT_TYPE(GDK_MOTION_NOTIFY)
		EVENT_TYPE(GDK_BUTTON_PRESS)
		EVENT_TYPE(GDK_2BUTTON_PRESS)
		EVENT_TYPE(GDK_3BUTTON_PRESS)
		EVENT_TYPE(GDK_BUTTON_RELEASE)
		EVENT_TYPE(GDK_KEY_PRESS)
		EVENT_TYPE(GDK_KEY_RELEASE)
		EVENT_TYPE(GDK_ENTER_NOTIFY)
		EVENT_TYPE(GDK_LEAVE_NOTIFY)
		EVENT_TYPE(GDK_FOCUS_CHANGE)
		EVENT_TYPE(GDK_CONFIGURE)
		EVENT_TYPE(GDK_MAP)
		EVENT_TYPE(GDK_UNMAP)
		EVENT_TYPE(GDK_PROPERTY_NOTIFY)
		EVENT_TYPE(GDK_SELECTION_CLEAR)
		EVENT_TYPE(GDK_SELECTION_REQUEST)
		EVENT_TYPE(GDK_SELECTION_NOTIFY)
		EVENT_TYPE(GDK_PROXIMITY_IN)
		EVENT_TYPE(GDK_PROXIMITY_OUT)
		EVENT_TYPE(GDK_DRAG_ENTER)
		EVENT_TYPE(GDK_DRAG_LEAVE)
		EVENT_TYPE(GDK_DRAG_MOTION)
		EVENT_TYPE(GDK_DRAG_STATUS)
		EVENT_TYPE(GDK_DROP_START)
		EVENT_TYPE(GDK_DROP_FINISHED)
		EVENT_TYPE(GDK_CLIENT_EVENT)
		EVENT_TYPE(GDK_VISIBILITY_NOTIFY)
		EVENT_TYPE(GDK_NO_EXPOSE)
		EVENT_TYPE(GDK_SCROLL)
		EVENT_TYPE(GDK_WINDOW_STATE)
		EVENT_TYPE(GDK_SETTING)
		default:
			str_bprintf(type, sizeof type, "%ld", (ulong) event->type);
		}
#undef EVENT_TYPE

		if (GUI_PROPERTY(gui_debug) {
			g_debug("on_tree_view_motion_notify(): "
				"type=%s, x=%d, y=%d, axes=%p, x_root=%d, y_root=%d",
					type,
					(gint) event->x, (gint) event->y, event->axes,
					(gint) event->x_root, (gint) event->y_root);
		}
	}
#endif /* 0 */

	tvm->x = event->x;
	tvm->y = event->y;
	tvm->ready = TRUE;
	return FALSE;
}

static gboolean
tree_view_motion_timeout(gpointer data)
{
	tree_view_motion_t *tvm = data;

	g_assert(tvm != NULL);
	g_assert(tvm->tv != NULL);
	g_assert(tvm->cb != NULL);

	if (tvm->ready && GTK_WIDGET_REALIZED(GTK_WIDGET(tvm->tv))) {
		GtkTreePath *path = NULL;

		tvm->ready = FALSE;
		gtk_tree_view_get_path_at_pos(tvm->tv, tvm->x, tvm->y, &path,
			NULL, NULL, NULL);
		tvm->cb(tvm->tv, path);
		if (path)
			gtk_tree_path_free(path);
	}

	return TRUE;
}

/**
 * Registers the callback for the motion-notify-event. Only the last event
 * seen during any interval will invoke the callback.
 *
 * @param tv The GtkTreeView.
 * @param cb The callback.
 * @param interval The interval in milliseconds.
 */
tree_view_motion_t *
tree_view_motion_set_callback(GtkTreeView *tv,
	tree_view_motion_callback cb, guint interval)
{
	tree_view_motion_t *tvm;

	g_return_val_if_fail(tv, NULL);
	g_return_val_if_fail(cb, NULL);

	WALLOC(tvm);
	tvm->ready = FALSE;
	tvm->tv = GTK_TREE_VIEW(g_object_ref(tv));
	tvm->cb = cb;
	tvm->timeout_id = g_timeout_add(interval, tree_view_motion_timeout, tvm);
	tvm->signal_id = gui_signal_connect(tv,
						"motion-notify-event", on_tree_view_motion_notify, tvm);
	return tvm;
}

void
tree_view_motion_clear_callback(tree_view_motion_t **ptr)
{
	if (*ptr) {
		tree_view_motion_t *tvm = *ptr;

		g_signal_handler_disconnect(tvm->tv, tvm->signal_id);
		g_source_remove(tvm->timeout_id);
		g_object_unref(tvm->tv);
		tvm->tv = NULL;
		WFREE_TYPE_NULL(tvm);
		*ptr = NULL;
	}
}

void
tree_view_set_fixed_height_mode(GtkTreeView *tv, gboolean fixed)
{
	g_return_if_fail(tv);

#if GTK_CHECK_VERSION(2, 4, 0)
    g_object_set(GTK_TREE_VIEW(tv), "fixed_height_mode", fixed, NULL_PTR);
#endif /* GTK+ >= 2.4.0 */
}

void
tree_model_iter_changed(GtkTreeModel *model, GtkTreeIter *iter)
{
	GtkTreePath *path;

	path = gtk_tree_model_get_path(model, iter);
	gtk_tree_model_row_changed(model, path, iter);
	gtk_tree_path_free(path);
}

void
list_store_set_pointer(GtkListStore *store, GtkTreeIter *iter,
	int column, void *data)
{
	static const GValue zero_value;
	GValue value = zero_value;

	g_value_init(&value, G_TYPE_POINTER);
	g_value_set_pointer(&value, data);
	gtk_list_store_set_value(store, iter, column, &value);
}

void
list_store_append_pointer(GtkListStore *store, GtkTreeIter *iter,
	int column, void *data)
#if GTK_CHECK_VERSION(2,6,0)
{
	static const GValue zero_value;
	GValue value = zero_value;
	const int row = INT_MAX;

	g_value_init(&value, G_TYPE_POINTER);
	g_value_set_pointer(&value, data);
	gtk_list_store_insert_with_valuesv(store, iter, row, &column, &value, 1);
}
#else	/* Gtk+ < 2.6 */
{
	gtk_list_store_append(store, iter);
	list_store_set_pointer(store, iter, column, data);
}
#endif	/* Gtk+ >= 2.6 */

#endif /* USE_GTK2 */

gdouble
_gtk_spin_button_get_value(GtkSpinButton *spinbutton)
{
    gchar *e;
    gdouble result;

    e = STRTRACK(gtk_editable_get_chars(GTK_EDITABLE(spinbutton), 0, -1));
    g_strstrip(e);
    result = g_strtod(e, NULL);
    G_FREE_NULL(e);
    return result;
}

guint32
gtk_editable_get_value_as_uint32(GtkEditable *editable)
{
    gchar *e;
    guint32 result;

    e = STRTRACK(gtk_editable_get_chars(GTK_EDITABLE(editable), 0, -1));
    g_strstrip(e);
    result = strtol(e, NULL, 10);
    G_FREE_NULL(e);
    return result;
}

/**
 * Adds alist of GtkItems to the given GtkCombo. Each GtkItem has the
 * choice number set as user_data.
 */
void
widget_init_choices(GtkWidget *widget, GtkSignalFunc func,
		prop_def_t *def, gpointer user_data)
{
    guint32 original;

    g_assert(def != NULL);
    g_assert(widget != NULL);
    g_assert(GTK_IS_COMBO(widget) || GTK_IS_OPTION_MENU(widget));
    g_assert(def->type == PROP_TYPE_MULTICHOICE);
    g_assert(def->data.guint32.choices != NULL);

    original = *def->data.guint32.value;

	if (GTK_IS_COMBO(widget)) {
		GtkCombo *combo = GTK_COMBO(widget);
		const gchar *title;
    	guint i;

		for (i = 0; (title = def->data.guint32.choices[i].title) != NULL; i++) {
			GtkWidget *list_item;
			GList *l;

			list_item = gtk_list_item_new_with_label(_(title));

			gtk_object_set_user_data(GTK_OBJECT(list_item),
					GINT_TO_POINTER(def->data.guint32.choices[i].value));

			gtk_widget_show(list_item);

			gui_signal_connect_after(list_item, "select", func, user_data);

			l = g_list_prepend(NULL, list_item);
			gtk_list_append_items(GTK_LIST(combo->list), l);

			if (def->data.guint32.choices[i].value == original)
				gtk_list_select_child(GTK_LIST(combo->list), list_item);
		}
	} else if (GTK_IS_OPTION_MENU(widget)) {
		GtkOptionMenu *option_menu = GTK_OPTION_MENU(widget);
		GtkMenu *menu;
		const gchar *title;
		guint i;

		menu = GTK_MENU(gtk_menu_new());
		for (i = 0; (title = def->data.guint32.choices[i].title) != NULL; i++) {
			GtkWidget *item;

			item = gtk_menu_item_new_with_label(_(title));
			gtk_widget_show(item);
			gtk_object_set_user_data(GTK_OBJECT(item),
				GUINT_TO_POINTER(def->data.guint32.choices[i].value));
			gtk_menu_shell_append(GTK_MENU_SHELL(menu), item);
			gui_signal_connect_after(item, "activate", func, user_data);
		}
		gtk_option_menu_set_menu(option_menu, GTK_WIDGET(menu));
	}
}

#ifdef USE_GTK1
/**
 * Functions like gtk_ctree_unlink for *Top level parent nodes only*. O(1)
 */
static void
gtk_ctree_fast_unlink (GtkCTree *ctree, GtkCTreeNode *node)
{
	GtkCList *clist;
	gint rows;
	gint level;
	gint visible;
	GtkCTreeNode *work;
	GtkCTreeNode *prev;
	GtkCTreeRow *prev_row;
	GtkCTreeNode *sibling;
	GList *list;

	g_assert(NULL == GTK_CTREE_ROW(node)->parent); /* Not a child node */

	clist = GTK_CLIST(ctree);
 	visible = gtk_ctree_is_viewable(ctree, node);

	/* clist->row_list_end unlinked ? */
	if (visible && (
            GTK_CTREE_NODE_NEXT(node) == NULL || (
                GTK_CTREE_ROW(node)->children &&
                gtk_ctree_is_ancestor(
                    ctree, node, GTK_CTREE_NODE(clist->row_list_end))
            )
        ))
		clist->row_list_end = (GList *) (GTK_CTREE_NODE_PREV(node));

	/* update list */
	rows = 0;
	level = GTK_CTREE_ROW(node)->level;
	work = GTK_CTREE_NODE_NEXT(node);

	/* Counts children of node */
	while (work && GTK_CTREE_ROW(work)->level > level) {
		work = GTK_CTREE_NODE_NEXT(work);
		rows++;
    }

	/* Subtract removed node and children from row count */
	if (visible) {
		clist->rows -= (rows + 1);
	}

	if (work) {
		list = (GList *)GTK_CTREE_NODE_PREV(work);
		list->next = NULL;
		list = (GList *)work;
		list->prev = (GList *)GTK_CTREE_NODE_PREV(node);
	}

	prev = GTK_CTREE_NODE_PREV(node);

	if (prev && GTK_CTREE_NODE_NEXT(prev) == node) {
		list = (GList *)GTK_CTREE_NODE_PREV(node);
		list->next = (GList *)work;
    }

	if (clist->row_list == (GList *)node)
		clist->row_list = (GList *) (GTK_CTREE_ROW(node)->sibling);
	else {
		/* We need to hook the previous node up to the node's sibling */
		if (prev) {

			prev_row = GTK_CTREE_ROW(prev);
			while (NULL != prev_row->parent) {
				prev = GTK_CTREE_NODE_PREV(prev);
				prev_row = GTK_CTREE_ROW(prev);
			}
			sibling = prev;
			g_assert(GTK_CTREE_ROW(sibling)->sibling == node);

			GTK_CTREE_ROW(sibling)->sibling = GTK_CTREE_ROW(node)->sibling;
		}
	}
}


/**
 * Functions like gtk_ctree_link for *Top level parent nodes only*.  This is
 * optimized for data being linked at the beginning of the tree.
 * O(1) if linking to beginning, O(n) otherwise.
 */
static void
gtk_ctree_fast_link(GtkCTree *ctree, GtkCTreeNode *node, GtkCTreeNode *sibling)
{
	GtkCList *clist;
	GList *list_end;
	GList *list;
	GList *work;
	gint rows = 1;

	g_assert(NULL == GTK_CTREE_ROW(node)->parent); /* Not a child node */

	clist = GTK_CLIST (ctree);

	/* Counts node and children */
	for (list_end = (GList *)node; list_end->next; list_end = list_end->next)
    	rows++;

	GTK_CTREE_ROW(node)->parent = NULL;
	GTK_CTREE_ROW(node)->sibling = sibling;

	clist->rows += rows;
	work = clist->row_list;

	/* O(1) if adding to top of list */
	if (sibling) {
		if (work != (GList *)sibling) {
			/* Searches from beginning of list until it finds sibling */
			while (GTK_CTREE_ROW(work)->sibling != sibling) {
				work = (GList *)(GTK_CTREE_ROW(work)->sibling);
            }
			GTK_CTREE_ROW(work)->sibling = node;
		}

		if (sibling == GTK_CTREE_NODE(clist->row_list)) {
			clist->row_list = (GList *) node;
        }

		if (GTK_CTREE_NODE_PREV(sibling) &&
			GTK_CTREE_NODE_NEXT(GTK_CTREE_NODE_PREV(sibling)) == sibling) {
			list = (GList *)GTK_CTREE_NODE_PREV(sibling);
			list->next = (GList *)node;
		}

		list = (GList *)node;
		list->prev = (GList *)GTK_CTREE_NODE_PREV(sibling);
		list_end->next = (GList *)sibling;
		list = (GList *)sibling;
		list->prev = list_end;

	} else {

		if (work) {

			/* Look from beginning of list/parent all the way to the end. */
			while (GTK_CTREE_ROW(work)->sibling)
				work = (GList *)(GTK_CTREE_ROW(work)->sibling);
			GTK_CTREE_ROW(work)->sibling = node;

			/* find last child of sibling */
			work = (GList *) gtk_ctree_last(ctree, GTK_CTREE_NODE(work));

			list_end->next = work->next;

			if (work->next)
				list = work->next->prev = list_end;
			work->next = (GList *)node;
			list = (GList *)node;
			list->prev = work;

		} else {
			clist->row_list = (GList *)node;
			list = (GList *)node;
			list->prev = NULL;
			list_end->next = NULL;
		}
	}

	if (
		clist->row_list_end == NULL ||
		clist->row_list_end->next == (GList *) node
	) {
		clist->row_list_end = list_end;
    }
}


/**
 * Functions like gtk_ctree_move for *Top level parent nodes only*.  This is
 * optimized for data being moved to the beginning of the tree and assumes
 * ctree != NULL and node != NULL.  O(1) as opposed to gtk's which is O(n).
 */
void
gtk_ctree_fast_move(GtkCTree *ctree, GtkCTreeNode *node,
		GtkCTreeNode *new_sibling)
{
	GtkCList *clist;
	GtkCTreeNode *work;

	g_assert(NULL == GTK_CTREE_ROW(node)->parent); /* Not a child node */

	clist = GTK_CLIST (ctree);

	/* return if it's already the right place */
	if (new_sibling == GTK_CTREE_ROW(node)->sibling || new_sibling == node) {
		return;
	}

	work = NULL;
	if (gtk_ctree_is_viewable (ctree, node))
    	work = GTK_CTREE_NODE(g_list_nth (clist->row_list, clist->focus_row));

	gtk_ctree_fast_unlink(ctree, node);
	gtk_ctree_fast_link(ctree, node, new_sibling);

	if (!work) {
		return;
	}

	while (work && !gtk_ctree_is_viewable(ctree, work))
		work = GTK_CTREE_ROW(work)->parent;

	clist->focus_row = g_list_position(clist->row_list, (GList *)work);
	clist->undo_anchor = clist->focus_row;
}

/**
 * @returns number of children under parent node in the given ctree
 */
gint
gtk_ctree_count_node_children(GtkCTree *unused_ctree, GtkCTreeNode *parent)
{
	GtkCTreeRow *current_row;
	GtkCTreeNode *current_node;
	gint num_children = 0;

	(void) unused_ctree;
	current_row = GTK_CTREE_ROW(parent);
	current_node = current_row->children;

	for (; NULL != current_node; current_node = current_row->sibling) {
		current_row = GTK_CTREE_ROW(current_node);
		num_children++;
	}

	return num_children;
}
#endif /* USE_GTK1 */

/**
 * Adjust the width of one widget based on the font information of another
 * widget.
 *
 * Currently this function sets the width of the target widget so it can
 * accomodate a string of the given length which contains only digits.
 *
 * @param extra additional number of pixels to add
 */
#ifdef USE_GTK1
void
gtk_widget_fix_width(GtkWidget *w, GtkWidget *l, guint chars, guint extra)
{
    GtkStyle *style;
    GdkFont *font;
    gint c;
    gint max_width = 0;

    style = gtk_widget_get_style(l);
    font = style->font;

    for (c = 1; c < 256; c ++) {
        gint width;

        if (isdigit(c)) {
            width = gdk_char_width(font, c);
            if (max_width < width) {
                max_width = width;
            }
        }
    }

    max_width = max_width * chars + extra;

    gtk_widget_set_usize(w, max_width, -1);
}
#endif

#ifdef USE_GTK2
void
gtk_widget_fix_width(GtkWidget *w, GtkWidget *l, guint chars, guint extra)
{
    gint max_width;
    PangoContext *pctx;
    PangoFontDescription *pfd;
    PangoFontMetrics *pfm;
    PangoLanguage * plang;

    pctx = gtk_widget_get_pango_context(l);
    pfd = pango_context_get_font_description(pctx);
    plang = pango_context_get_language(pctx);
    pfm = pango_context_get_metrics(pctx, pfd, plang);

    max_width = PANGO_PIXELS((gint)
		(pango_font_metrics_get_approximate_digit_width(pfm) * chars + extra));

	max_width *= 1.2;	/* The above still allocates less than it should */
    gtk_widget_set_size_request(w, max_width, -1);

    pango_font_metrics_unref(pfm);
}

#endif

#ifdef USE_GTK1
void
gtk_progress_bar_set_text(GtkProgressBar *pb, const gchar *text)
{
	const gchar *p = text;
	gchar buf[1024], *q = buf, c;

	/* Replace '%' with %% */
	for (p = text; (c = *p) != '\0'; p++) {
		/* We need room for %% plus \0, truncation is OK */
		if (&buf[sizeof buf] - q < 3)
			break;

		if (c == '%')
			*q++ = c;
		*q++ = c;
	}
	*q = '\0';

	gtk_progress_set_format_string(GTK_PROGRESS(pb), buf);
}

void
gtk_window_iconify(GtkWindow *window)
{
	GtkWidget *widget;

	g_return_if_fail(GTK_IS_WINDOW(window));

	widget = GTK_WIDGET(window);
	if (widget != NULL && widget->window != NULL) {
		XIconifyWindow(GDK_DISPLAY(), GDK_WINDOW_XWINDOW(widget->window),
			((_XPrivDisplay) GDK_DISPLAY())->default_screen);
	}
}
#endif


#if !GTK_CHECK_VERSION(2, 4, 0)
GtkWidget *
gtk_paned_get_child1(GtkPaned *paned)
{
	g_return_val_if_fail(paned != NULL, NULL);
	return paned->child1;
}

GtkWidget *
gtk_paned_get_child2(GtkPaned *paned)
{
	g_return_val_if_fail(paned != NULL, NULL);
	return paned->child2;
}
#endif

void
statusbar_set_shadow_type(GtkStatusbar *sb, GtkShadowType shadow)
{
	g_return_if_fail(sb);
	(void) shadow;

#if !GTK_CHECK_VERSION(2,0,0)
	gtk_frame_set_shadow_type(GTK_FRAME(sb->frame), shadow);
#endif	/* Gtk+ 1.2 */
}

/**
 * @return TRUE if the runtime Gtk+ version is the given version or newer.
 */
gboolean
check_gtk_version(unsigned major, unsigned minor, unsigned micro)
{
	if (gtk_major_version != major)
		return gtk_major_version > major;
	if (gtk_minor_version != minor)
		return gtk_minor_version > minor;
	if (gtk_micro_version != micro)
		return gtk_micro_version > micro;
	return TRUE;
}

/* vi: set ts=4 sw=4 cindent: */
