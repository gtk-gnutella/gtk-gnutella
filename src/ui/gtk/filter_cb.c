/*
 * Copyright (c) 2001-2003, Raphael Manfredi, Richard Eckart
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
 * GUI filtering functions.
 *
 * @author Raphael Manfredi
 * @date 2001-2003
 */

#include "gui.h"

#include "filter_core.h"
#include "filter_cb.h"
#include "filter.h"

#include "if/gui_property_priv.h"

#include "lib/glib-missing.h"
#include "lib/utf8.h"
#include "lib/override.h"		/* Must be the last header included */

/*
 * Common code between Gtk+ 1.2 and Gtk+ 2.x first
 */

/**
 * Private variables.
 */
static rule_t *rule_clipboard;

/**
 * Private functions.
 */

static void
clear_clipboard(void)
{
    if (rule_clipboard != NULL) {
        filter_free_rule(rule_clipboard);
        rule_clipboard = NULL;
    }
}

/**
 * Public functions.
 */

void
filter_cb_close(void)
{
    clear_clipboard();
}

/**
 * Change the active stats of the current work_filter to what
 * the togglebutton indicates.
 */
void
on_checkbutton_filter_enabled_toggled(GtkToggleButton *togglebutton,
	gpointer unused_udata)
{
   	(void) unused_udata;

    if (work_filter == NULL)
        return;

    filter_set_enabled(work_filter, gtk_toggle_button_get_active(togglebutton));
}

void
on_popup_filter_rule_paste_activate(GtkMenuItem *unused_menuitem,
	gpointer unused_udata)
{
    rule_t *r;

	(void) unused_menuitem;
	(void) unused_udata;

    if (work_filter == NULL || rule_clipboard == NULL)
        return;

    /*
     * If the target is no longer valid, free the rule and
     * clear the clipboard.
     */
    if (!filter_is_valid_in_session(rule_clipboard->target)) {
        clear_clipboard();
        return;
    }

    /*
     * Since a rule may not be added to two filters, we copy again here.
     * We want to keep the original copy in the clipboard since we may
     * want to paste it elsewhere.
     * The filter takes ownership of the added rule.
     */
    r = filter_duplicate_rule(rule_clipboard);

    filter_append_rule_to_session(work_filter, r);
}

gboolean
on_entry_filter_size_focus_out_event(GtkEditable *editable,
	gpointer unused_udata)
{
	(void) unused_udata;

	(void) filter_update_size(GTK_ENTRY(editable));
	return FALSE;
}

gboolean
on_entry_filter_size_key_press_event(GtkWidget *widget, GdkEventKey *event,
	gpointer unused_udata)
{

  (void) unused_udata;

  if (GDK_Return == event->keyval) {
  	(void) filter_update_size(GTK_ENTRY(widget));
  }
  return FALSE;
}

void
on_button_filter_reset_clicked(GtkButton *unused_button, gpointer unused_udata)
{
	(void) unused_button;
	(void) unused_udata;

    if (work_filter != NULL)
        filter_reset_stats(work_filter);
}

gboolean
on_dlg_filters_delete_event(GtkWidget *unused_widget, gpointer unused_udata)
{
	(void) unused_widget;
	(void) unused_udata;
    filter_close_dialog(FALSE);

    return TRUE;
}

void
on_button_filter_ok_clicked(GtkButton *unused_button, gpointer unused_udata)
{
	(void) unused_button;
	(void) unused_udata;

    filter_close_dialog(TRUE);
}

void
on_button_filter_cancel_clicked(GtkButton *unused_button, gpointer unused_udata)
{
    gint page = gtk_notebook_get_current_page
        (GTK_NOTEBOOK
            (gui_filter_dialog_lookup("notebook_filter_detail")));

	(void) unused_button;
	(void) unused_udata;

    if (page == nb_filt_page_buttons) {
        filter_close_dialog(FALSE);
        return;
    }
    filter_gui_edit_rule(NULL);
}

void
on_button_filter_apply_clicked(GtkButton *unused_button, gpointer unused_udata)
{
	(void) unused_button;
	(void) unused_udata;

    filter_apply_changes();
    filter_gui_edit_rule(NULL);
}

void
on_button_filter_revert_clicked(GtkButton *unused_button, gpointer unused_udata)
{
	(void) unused_button;
	(void) unused_udata;

    filter_revert_changes();
    filter_gui_edit_rule(NULL);
}

void
on_button_filter_abort_rule_clicked(GtkButton *unused_button,
	gpointer unused_udata)
{
	(void) unused_button;
	(void) unused_udata;

    gtk_notebook_set_current_page(
        GTK_NOTEBOOK(gui_filter_dialog_lookup("notebook_filter_detail")),
        nb_filt_page_buttons);
}

void
on_button_filter_remove_clicked(GtkButton *unused_button, gpointer unused_udata)
{
	(void) unused_button;
	(void) unused_udata;

    if (work_filter != NULL)
        filter_remove_from_session(work_filter);
}

void
on_entry_filter_new_activate(GtkEditable *editable, gpointer unused_udata)
{
    gchar *name = STRTRACK(gtk_editable_get_chars(editable, 0, -1));
	const gchar *nfc;
    filter_t *filter;

	(void) unused_udata;

    g_strstrip(name);
	nfc = lazy_ui_string_to_utf8(name);
    if (nfc[0] != '\0' && filter_find_by_name_in_session(nfc) == NULL) {
        filter = filter_new(nfc);
        filter_add_to_session(filter);
        gtk_entry_set_text(GTK_ENTRY(editable), "");
        filter_set(filter);
    } else
        gdk_beep();
	G_FREE_NULL(name);
}

void
on_button_filter_create_clicked(GtkButton *unused_button, gpointer unused_udata)
{
	(void) unused_button;
	(void) unused_udata;

    /*
     * Delegate to on_entry_filter_new_activate.
     */
    on_entry_filter_new_activate(
		GTK_EDITABLE(gui_filter_dialog_lookup("entry_filter_new")),
		NULL);
}


/*
 * Gtk+ 1.2 specific code
 */

#ifdef USE_GTK1
void
on_ctree_filter_filters_tree_select_row(GtkCTree *ctree, GList *node,
	gint unused_column, gpointer unused_udata)
{
    static gboolean lock = FALSE;
    filter_t *filter;

	(void) unused_column;
   	(void) unused_udata;

    if (lock)
        return;
    lock = TRUE;

    filter = gtk_ctree_node_get_row_data(GTK_CTREE(ctree),
				GTK_CTREE_NODE(node));
    filter_set(filter);

    lock = FALSE;
}

void
on_button_filter_reset_all_clicked(GtkButton *unused_button,
	gpointer unused_udata)
{
	gint row;
	GtkCTree *ctree;
	GtkCList *clist;

	(void) unused_button;
	(void) unused_udata;

	if (gui_filter_dialog() == NULL)
		return;

	ctree = GTK_CTREE(gui_filter_dialog_lookup("ctree_filter_filters"));
	clist = GTK_CLIST(ctree);

	for (row = 0; row < clist->rows; row++) {
		filter_t *filter;
		GtkCTreeNode *node;

		node = gtk_ctree_node_nth(ctree, row);
		filter = gtk_ctree_node_get_row_data(ctree, node);
		if (filter == NULL)
			continue;

		filter_reset_stats(filter);
	}
}

void
on_clist_filter_rules_select_row(GtkCList *clist, gint row,
	gint unused_column, GdkEvent *unused_event, gpointer unused_udata)
{
    rule_t *r;

	(void) unused_column;
	(void) unused_event;
	(void) unused_udata;

    r = gtk_clist_get_row_data(clist, row);
    g_assert(r != NULL);

    filter_gui_edit_rule(r);
}

void
on_clist_filter_rules_unselect_row(GtkCList *clist, gint unused_row,
	gint unused_column, GdkEvent *unused_event, gpointer unused_udata)
{
	(void) unused_row;
	(void) unused_column;
	(void) unused_event;
	(void) unused_udata;

    if (clist->selection == NULL)
        filter_gui_edit_rule(NULL);
}

void
on_clist_filter_rules_drag_end(GtkWidget *unused_widget,
    GdkDragContext *unused_drag_context, gpointer unused_udata)
{
	(void) unused_widget;
	(void) unused_drag_context;
	(void) unused_udata;

    filter_adapt_order();
}

void
on_button_filter_add_rule_text_clicked(GtkButton *unused_button,
	gpointer unused_udata)
{
	(void) unused_button;
	(void) unused_udata;

    gtk_clist_unselect_all
        (GTK_CLIST(gui_filter_dialog_lookup("clist_filter_rules")));
    filter_gui_edit_text_rule(NULL);
}

void
on_button_filter_add_rule_ip_clicked(GtkButton *unused_button,
	gpointer unused_udata)
{
	(void) unused_button;
	(void) unused_udata;

    gtk_clist_unselect_all
        (GTK_CLIST(gui_filter_dialog_lookup("clist_filter_rules")));
    filter_gui_edit_ip_rule(NULL);
}

void
on_button_filter_add_rule_size_clicked(GtkButton *unused_button,
	gpointer unused_udata)
{
	(void) unused_button;
	(void) unused_udata;

    gtk_clist_unselect_all
        (GTK_CLIST(gui_filter_dialog_lookup("clist_filter_rules")));
    filter_gui_edit_size_rule(NULL);
}

void
on_button_filter_add_rule_jump_clicked(GtkButton *unused_button,
	gpointer unused_udata)
{
	(void) unused_button;
	(void) unused_udata;

    gtk_clist_unselect_all
        (GTK_CLIST(gui_filter_dialog_lookup("clist_filter_rules")));
    filter_gui_edit_jump_rule(NULL);
}

void
on_button_filter_add_rule_flag_clicked(GtkButton *unused_button,
	gpointer unused_udata)
{
	(void) unused_button;
	(void) unused_udata;

    gtk_clist_unselect_all
        (GTK_CLIST(gui_filter_dialog_lookup("clist_filter_rules")));
    filter_gui_edit_flag_rule(NULL);
}

void
on_button_filter_add_rule_state_clicked(GtkButton *unused_button,
	gpointer unused_udata)
{
	(void) unused_button;
	(void) unused_udata;

    gtk_clist_unselect_all
        (GTK_CLIST(gui_filter_dialog_lookup("clist_filter_rules")));
    filter_gui_edit_state_rule(NULL);
}

void
on_button_filter_add_rule_clicked(GtkButton *unused_button,
	gpointer unused_udata)
{
    gint page = gtk_notebook_get_current_page
        (GTK_NOTEBOOK(gui_filter_dialog_lookup("notebook_filter_detail")));
    GtkCList *clist_filter_rules = GTK_CLIST
        (gui_filter_dialog_lookup("clist_filter_rules"));
    rule_t *r = NULL;

	(void) unused_button;
	(void) unused_udata;

    switch (page) {
    case nb_filt_page_text:
    case nb_filt_page_ip:
    case nb_filt_page_size:
    case nb_filt_page_jump:
    case nb_filt_page_flag:
    case nb_filt_page_state:
        r = filter_gui_get_rule();
        break;
    case nb_filt_page_sha1:
        /*
         * SHA1 rules are not changeable yet (maybe never).
         * So we just return here.
         */
        filter_gui_edit_rule(NULL);
        return;
    case nb_filt_page_buttons:
    default:
        g_error("on_button_filter_on_clicked: invalid page %d", page);
    }

    /*
     *if a row is selected, we change the filter there
     *else we add a new filter to the end of the list
     */

    if (clist_filter_rules->selection != NULL) {
        GList *l = clist_filter_rules->selection;
        rule_t *oldrule;

        /* modify row */
        oldrule = gtk_clist_get_row_data(clist_filter_rules,
					GPOINTER_TO_INT(l->data));
        g_assert(oldrule != NULL);

        filter_replace_rule_in_session(work_filter, oldrule, r);
    } else {
        filter_append_rule_to_session(work_filter, r);
    }

    filter_gui_edit_rule(NULL);
}
void
on_button_filter_clear_clicked(GtkButton *unused_button, gpointer unused_udata)
{
    GtkCList *clist = GTK_CLIST
        (gui_filter_dialog_lookup("clist_filter_rules"));

	(void) unused_button;
	(void) unused_udata;

    gtk_clist_freeze(clist);

    while (clist->rows != 0) {
        filter_remove_rule_from_session(work_filter,
			gtk_clist_get_row_data(clist, 0));
    }

    gtk_clist_thaw(clist);
    gtk_notebook_set_current_page(
        GTK_NOTEBOOK(gui_filter_dialog_lookup("notebook_filter_detail")),
        nb_filt_page_buttons);
}

void
on_button_filter_remove_rule_clicked(GtkButton *unused_button,
	gpointer unused_udata)
{
    GtkCList *clist = GTK_CLIST
        (gui_filter_dialog_lookup("clist_filter_rules"));
    rule_t *r;

	(void) unused_button;
	(void) unused_udata;

    if (!clist->selection)
        return;

    r = gtk_clist_get_row_data(clist, GPOINTER_TO_INT(clist->selection->data));

    filter_remove_rule_from_session(work_filter, r);

    gtk_notebook_set_current_page(
        GTK_NOTEBOOK(gui_filter_dialog_lookup("notebook_filter_detail")),
        nb_filt_page_buttons);
}
void
on_button_filter_reset_rule_clicked(GtkButton *unused_button,
	gpointer unused_udata)
{
    rule_t *rule;
    GtkCList *clist_filter_rules = GTK_CLIST
        (gui_filter_dialog_lookup("clist_filter_rules"));

	(void) unused_button;
	(void) unused_udata;

    if (clist_filter_rules->selection == NULL)
        return;

    rule = gtk_clist_get_row_data (clist_filter_rules,
				GPOINTER_TO_INT(clist_filter_rules->selection->data));

    filter_rule_reset_stats(rule);
}

void
on_button_filter_reset_all_rules_clicked(GtkButton *unused_button,
	gpointer unused_udata)
{
    gint row;
    GtkCList *clist_filter_rules = GTK_CLIST
        (gui_filter_dialog_lookup("clist_filter_rules"));

	(void) unused_button;
	(void) unused_udata;

    for (row = 0; row < clist_filter_rules->rows; row ++) {
        rule_t *rule;

        rule = gtk_clist_get_row_data(clist_filter_rules, row);

        if (rule == NULL)
            continue;

        filter_rule_reset_stats(rule);
    }
}

gboolean
on_clist_filter_rules_button_press_event(GtkWidget *unused_widget,
		GdkEventButton *event, gpointer unused_udata)
{
    gboolean sensitive;
    GtkCList *clist_filter_rules = GTK_CLIST
        (gui_filter_dialog_lookup("clist_filter_rules"));

	(void) unused_widget;
	(void) unused_udata;

    if (event->button != 3)
		return FALSE;

    /*
     * If the target is no longer valid, free the rule and
     * clear the clipboard.
     */
    if (
		rule_clipboard != NULL &&
        !filter_is_valid_in_session(rule_clipboard->target)
	) {
        clear_clipboard();
        return TRUE;
    }

    sensitive = clist_filter_rules->selection != NULL && work_filter != NULL;

    gtk_widget_set_sensitive(
        gui_popup_filter_rule_lookup("popup_filter_rule_copy"),
        sensitive);
    gtk_widget_set_sensitive(
        gui_popup_filter_rule_lookup("popup_filter_rule_paste"),
        rule_clipboard != NULL);

    gtk_menu_popup(GTK_MENU(gui_popup_filter_rule()), NULL, NULL, NULL, NULL,
        event->button, event->time);

	return TRUE;
}

void
on_popup_filter_rule_copy_activate(GtkMenuItem *unused_menuitem,
	gpointer unused_udata)
{
    GtkCList *clist_filter_rules = GTK_CLIST
        (gui_filter_dialog_lookup("clist_filter_rules"));

	(void) unused_menuitem;
	(void) unused_udata;

    clear_clipboard();

    if (clist_filter_rules->selection != NULL) {
        rule_t *r;
        gint row;

        row = GPOINTER_TO_INT(clist_filter_rules->selection->data);

        r = gtk_clist_get_row_data(clist_filter_rules, row);
        g_assert(r != NULL);

        rule_clipboard = filter_duplicate_rule(r);
    }
}
#endif /* USE_GTK1 */


/*
 * Gtk+ 2.x specific code
 */

#ifdef USE_GTK2
gboolean
on_treeview_filter_rules_button_press_event(GtkWidget *widget,
		GdkEventButton *event, gpointer unused_udata)
{
    gboolean sensitive;

	(void) unused_udata;

    if (event->button != 3)
		return FALSE;

    /*
     * If the target is no longer valid, free the rule and
     * clear the clipboard.
     */
    if (
		rule_clipboard != NULL &&
        !filter_is_valid_in_session(rule_clipboard->target)
	) {
        clear_clipboard();
        return TRUE;
    }

	{
		GtkTreePath *path;

		gtk_tree_view_get_cursor(GTK_TREE_VIEW(widget), &path, NULL);
    	sensitive = path != NULL && work_filter != NULL;
		gtk_tree_path_free(path);
		path = NULL;
	}

    gtk_widget_set_sensitive(
        gui_popup_filter_rule_lookup("popup_filter_rule_copy"),
        sensitive);
    gtk_widget_set_sensitive(
        gui_popup_filter_rule_lookup("popup_filter_rule_paste"),
        rule_clipboard != NULL);

    gtk_menu_popup(GTK_MENU(gui_popup_filter_rule()), NULL, NULL, NULL, NULL,
        event->button, event->time);

	return TRUE;
}

void
on_treeview_filter_filters_select_row(GtkTreeView *tv,
	gpointer unused_udata)
{
	GtkTreePath *path;

	(void) unused_udata;

	gtk_tree_view_get_cursor(tv, &path, NULL);
	if (path) {
		GtkTreeIter iter;
		GtkTreeModel *model;
		gpointer p;

		model = gtk_tree_view_get_model(tv);
		if (!gtk_tree_model_get_iter(model, &iter, path)) {
			g_assert_not_reached();
			return;
		}
		gtk_tree_path_free(path);
		path = NULL;

    	gtk_tree_model_get(model, &iter, 0, &p, (-1));
    	filter_set(p);
	}
}

static gboolean
filter_reset_all_helper(GtkTreeModel *model, GtkTreePath *unused_path,
	GtkTreeIter *iter, gpointer unused_udata)
{
	gpointer p;

	(void) unused_path;
	(void) unused_udata;

   	gtk_tree_model_get(model, iter, 0, &p, (-1));
	if (p) {
		filter_t *filter = p;
        filter_reset_stats(filter);
	}

	return FALSE; /* continue traversal */
}

void
on_button_filter_reset_all_clicked(GtkButton *unused_button,
	gpointer unused_udata)
{
	(void) unused_button;
	(void) unused_udata;

	if (gui_filter_dialog() == NULL)
		return;

	gtk_tree_model_foreach(gtk_tree_view_get_model(GTK_TREE_VIEW(
		gui_filter_dialog_lookup("treeview_filter_filters"))),
		filter_reset_all_helper,
		NULL);
}

void
on_treeview_filter_rules_select_row(GtkTreeView *tv, gpointer unused_udata)
{
	GtkTreePath *path;

	(void) unused_udata;

   	gtk_tree_view_get_cursor(tv, &path, NULL);
	if (path) {
		GtkTreeIter iter;
		GtkTreeModel *model;
		gpointer p;

		model = gtk_tree_view_get_model(tv);
		if (!gtk_tree_model_get_iter(model, &iter, path)) {
			g_assert_not_reached();
			return;
		}
		gtk_tree_path_free(path);
		path = NULL;

    	gtk_tree_model_get(model, &iter, 0, &p, (-1));
 		filter_gui_edit_rule(p);
	}
}

void
on_button_filter_add_rule_text_clicked(GtkButton *unused_button,
	gpointer unused_udata)
{
	(void) unused_button;
	(void) unused_udata;

	gtk_tree_selection_unselect_all(gtk_tree_view_get_selection(
		GTK_TREE_VIEW(gui_filter_dialog_lookup("treeview_filter_rules"))));

	filter_gui_edit_text_rule(NULL);
}

void
on_button_filter_add_rule_ip_clicked(GtkButton *unused_button,
	gpointer unused_udata)
{
	(void) unused_button;
	(void) unused_udata;

	gtk_tree_selection_unselect_all(gtk_tree_view_get_selection(
		GTK_TREE_VIEW(gui_filter_dialog_lookup("treeview_filter_rules"))));

    filter_gui_edit_ip_rule(NULL);
}

void
on_button_filter_add_rule_size_clicked(GtkButton *unused_button,
	gpointer unused_udata)
{
	(void) unused_button;
	(void) unused_udata;

	gtk_tree_selection_unselect_all(gtk_tree_view_get_selection(
		GTK_TREE_VIEW(gui_filter_dialog_lookup("treeview_filter_rules"))));

	filter_gui_edit_size_rule(NULL);
}

void
on_button_filter_add_rule_jump_clicked(GtkButton *unused_button,
	gpointer unused_udata)
{
	(void) unused_button;
	(void) unused_udata;

	gtk_tree_selection_unselect_all(gtk_tree_view_get_selection(
		GTK_TREE_VIEW(gui_filter_dialog_lookup("treeview_filter_rules"))));

    filter_gui_edit_jump_rule(NULL);
}

void
on_button_filter_add_rule_flag_clicked(GtkButton *unused_button,
	gpointer unused_udata)
{
	(void) unused_button;
	(void) unused_udata;

	gtk_tree_selection_unselect_all(gtk_tree_view_get_selection(
		GTK_TREE_VIEW(gui_filter_dialog_lookup("treeview_filter_rules"))));

    filter_gui_edit_flag_rule(NULL);
}

void
on_button_filter_add_rule_state_clicked(GtkButton *unused_button,
	gpointer unused_udata)
{
	(void) unused_button;
	(void) unused_udata;

	gtk_tree_selection_unselect_all(gtk_tree_view_get_selection(
		GTK_TREE_VIEW(gui_filter_dialog_lookup("treeview_filter_rules"))));

	filter_gui_edit_state_rule(NULL);
}

void
on_button_filter_add_rule_clicked(GtkButton *unused_button,
	gpointer unused_udata)
{
	GtkTreeView *tv;
	GtkTreePath *path;
    rule_t *r = NULL;
	gint page;

	(void) unused_button;
	(void) unused_udata;

	tv = GTK_TREE_VIEW(gui_filter_dialog_lookup("treeview_filter_rules"));
    page = gtk_notebook_get_current_page(GTK_NOTEBOOK(
				gui_filter_dialog_lookup("notebook_filter_detail")));

    switch (page) {
    case nb_filt_page_text:
    case nb_filt_page_ip:
    case nb_filt_page_size:
    case nb_filt_page_jump:
    case nb_filt_page_flag:
    case nb_filt_page_state:
        r = filter_gui_get_rule();
        break;
    case nb_filt_page_sha1:
        /*
         * SHA1 rules are not changeable yet (maybe never).
         * So we just return here.
         */
        filter_gui_edit_rule(NULL);
        return;
    case nb_filt_page_buttons:
    default:
        g_error("on_button_filter_on_clicked: invalid page %d", page);
    }

    /*
     *if a row is selected, we change the filter there
     *else we add a new filter to the end of the list
     */

   	gtk_tree_view_get_cursor(tv, &path, NULL);
    if (path) {
		GtkTreeModel *model;
   		GtkTreeIter iter;
		gpointer p;

		model = gtk_tree_view_get_model(tv);
		if (!gtk_tree_model_get_iter(model, &iter, path)) {
			g_assert_not_reached();
			return;
		}
		gtk_tree_path_free(path);
		path = NULL;

		gtk_tree_model_get(model, &iter, 0, &p, (-1));
        g_assert(p != NULL);

        filter_replace_rule_in_session(work_filter, p, r);
    } else {
        filter_append_rule_to_session(work_filter, r);
    }

    filter_gui_edit_rule(NULL);
}

static gboolean
filter_clear_helper(GtkTreeModel *model, GtkTreePath *unused_path,
	GtkTreeIter *iter, gpointer slist_ptr)
{
	GSList **sl_ptr = slist_ptr;
	gpointer p;

	(void) unused_path;

	gtk_tree_model_get(model, iter, 0, &p, (-1));
	*sl_ptr = g_slist_prepend(*sl_ptr, p);

	return FALSE; /* continue traversal */
}

void
on_button_filter_clear_clicked(GtkButton *unused_button, gpointer unused_udata)
{
	GSList *sl, *sl_rules = NULL;

	(void) unused_button;
	(void) unused_udata;

	gtk_tree_model_foreach(
		gtk_tree_view_get_model(GTK_TREE_VIEW(
			gui_filter_dialog_lookup("treeview_filter_rules"))),
		filter_clear_helper,
		&sl_rules);

	for (sl = sl_rules; sl != NULL; sl = g_slist_next(sl))
		filter_remove_rule_from_session(work_filter, sl->data);
	gm_slist_free_null(&sl_rules);

    gtk_notebook_set_current_page(
        GTK_NOTEBOOK(gui_filter_dialog_lookup("notebook_filter_detail")),
        nb_filt_page_buttons);
}

void
on_button_filter_remove_rule_clicked(GtkButton *unused_button,
	gpointer unused_udata)
{
	GtkTreeView *tv;
	GtkTreePath *path;

	(void) unused_button;
	(void) unused_udata;

    tv = GTK_TREE_VIEW(gui_filter_dialog_lookup("treeview_filter_rules"));
	gtk_tree_view_get_cursor(tv, &path, NULL);
    if (path) {
		GtkTreeModel *model;
   		GtkTreeIter iter;
		gpointer p;

		model = gtk_tree_view_get_model(tv);
		if (!gtk_tree_model_get_iter(model, &iter, path)) {
			g_assert_not_reached();
			return;
		}
		gtk_tree_path_free(path);
		path = NULL;

		gtk_tree_model_get(model, &iter, 0, &p, (-1));
    	filter_remove_rule_from_session(work_filter, p);

    	gtk_notebook_set_current_page(
          GTK_NOTEBOOK(gui_filter_dialog_lookup("notebook_filter_detail")),
          nb_filt_page_buttons);
	}
}

void
on_button_filter_reset_rule_clicked(GtkButton *unused_button,
	gpointer unused_udata)
{
	GtkTreeView *tv;
	GtkTreePath *path;

	(void) unused_button;
	(void) unused_udata;

    tv = GTK_TREE_VIEW(gui_filter_dialog_lookup("treeview_filter_rules"));
	gtk_tree_view_get_cursor(tv, &path, NULL);
    if (path) {
		GtkTreeModel *model;
		GtkTreeIter iter;
		gpointer p;

		model = gtk_tree_view_get_model(tv);
		if (!gtk_tree_model_get_iter(model, &iter, path)) {
			g_assert_not_reached();
			return;
		}
		gtk_tree_path_free(path);
		path = NULL;

		gtk_tree_model_get(model, &iter, 0, &p, (-1));
    	filter_rule_reset_stats(p);
	}
}

static gboolean
filter_reset_all_rules_helper(GtkTreeModel *model, GtkTreePath *unused_path,
	GtkTreeIter *iter, gpointer unused_udata)
{
	gpointer p;

	(void) unused_path;
	(void) unused_udata;

   	gtk_tree_model_get(model, iter, 0, &p, (-1));
	if (p) {
        rule_t *rule = p;
        filter_rule_reset_stats(rule);
	}

	return FALSE; /* continue traversal */
}

void
on_button_filter_reset_all_rules_clicked(GtkButton *unused_button,
	gpointer unused_udata)
{
	(void) unused_button;
	(void) unused_udata;

	gtk_tree_model_foreach(
		gtk_tree_view_get_model(GTK_TREE_VIEW(
			gui_filter_dialog_lookup("treeview_filter_rules"))),
		filter_reset_all_rules_helper,
		NULL);
}

void
on_popup_filter_rule_copy_activate(GtkMenuItem *unused_menuitem,
	gpointer unused_udata)
{
    GtkTreeView *tv;
	GtkTreePath *path;

	(void) unused_menuitem;
	(void) unused_udata;

    clear_clipboard();

   	tv = GTK_TREE_VIEW(gui_filter_dialog_lookup("treeview_filter_rules"));
	gtk_tree_view_get_cursor(tv, &path, NULL);
	if (path) {
		GtkTreeModel *model;
		GtkTreeIter iter;
		gpointer p;

		model = gtk_tree_view_get_model(tv);
		if (!gtk_tree_model_get_iter(model, &iter, path)) {
			g_assert_not_reached();
			return;
		}
		gtk_tree_path_free(path);
		path = NULL;

		gtk_tree_model_get(model, &iter, 0, &p, (-1));
        g_assert(p != NULL);
        rule_clipboard = filter_duplicate_rule(p);
    }
}
#endif /* USE_GTK2 */

/* vi: set ts=4 sw=4 cindent: */
