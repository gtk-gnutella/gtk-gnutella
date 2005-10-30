/*
 * $Id$
 *
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
 *      59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *----------------------------------------------------------------------
 */

/**
 * @ingroup gtk
 * @file
 *
 * GUI filtering functions.
 *
 * @author Raphael Manfredi
 * @author Richard Eckart
 * @date 2001-2003
 */

#include "gui.h"

RCSID("$Id$");

#include "filter.h"
#include "gtk-missing.h"

#include "gtk/misc.h"

#ifdef USE_GTK1
#include "gtk/gtk1/interface-glade.h"
#endif
#ifdef USE_GTK2
#include "gtk/gtk2/interface-glade.h"
#endif

#include "if/gui_property.h"
#include "if/gui_property_priv.h"

#include "lib/glib-missing.h"
#include "lib/utf8.h"
#include "lib/override.h"		/* Must be the last header included */

#define DEFAULT_TARGET (filter_get_drop_target())

/*
 * Public variables
 */
GtkWidget *filter_dialog = NULL;
GtkWidget *popup_filter_rule = NULL;

/*
 * Private variables
 */
static const gchar * const rule_text_type_labels[] = {
    N_("starts with"),
    N_("contains the words"),
    N_("ends with"),
    N_("contains the substring"),
    N_("matches regex"),
    N_("is exactly")
};

static GtkCTreeNode *fl_node_global = NULL;
static GtkCTreeNode *fl_node_bound = NULL;
static GtkCTreeNode *fl_node_free = NULL;
static GtkCTreeNode *fl_node_builtin = NULL;



/*
 * Private functions prototypes
 */
static rule_t *filter_gui_get_text_rule(void);
static rule_t *filter_gui_get_ip_rule(void);
static rule_t *filter_gui_get_size_rule(void);
static rule_t *filter_gui_get_jump_rule(void);
static rule_t *filter_gui_get_flag_rule(void);
static rule_t *filter_gui_get_state_rule(void);
static GtkCTreeNode *getFilterRoot(filter_t *f);



/**
 * Fetch the proper root node for a given filter in the filter tree.
 */
static GtkCTreeNode *
getFilterRoot(filter_t *f)
{
    if (filter_is_global(f)) {
        return fl_node_global;
    } else if (filter_is_bound(f)) {
        return fl_node_bound;
    } else if (filter_is_builtin(f)) {
        return fl_node_builtin;
    } else {
        return fl_node_free;
    }
}

/**
 * Initialize the contents of the dialog editor and some
 * internal variables like the roots in the filter list etc.
 */
void
filter_gui_init(void)
{
    GtkMenu *m;
    gint i;
    GtkCList *clist_filter_rules;
    GtkCTree *ctree_filter_filters;

    if (filter_dialog == NULL)
        return;

    clist_filter_rules = GTK_CLIST
        (lookup_widget(filter_dialog, "clist_filter_rules"));
    ctree_filter_filters = GTK_CTREE
        (lookup_widget(filter_dialog, "ctree_filter_filters"));

    gtk_notebook_set_show_tabs(
        GTK_NOTEBOOK(lookup_widget(filter_dialog, "notebook_filter_detail")),
        FALSE);

    gtk_clist_set_reorderable(clist_filter_rules, TRUE);
    for (i = 0; i < 4; i++)
        gtk_clist_set_column_width(GTK_CLIST(clist_filter_rules), i,
            filter_rules_col_widths[i]);

    for (i = 0; i < 3; i++)
        gtk_clist_set_column_width(GTK_CLIST(ctree_filter_filters), i,
            filter_filters_col_widths[i]);

    m = GTK_MENU(gtk_menu_new());
    menu_new_item_with_data(
        m, _(rule_text_type_labels[RULE_TEXT_PREFIX]),
        GUINT_TO_POINTER(RULE_TEXT_PREFIX));
    menu_new_item_with_data(
        m, _(rule_text_type_labels[RULE_TEXT_WORDS]),
        GUINT_TO_POINTER(RULE_TEXT_WORDS));
    menu_new_item_with_data(
        m, _(rule_text_type_labels[RULE_TEXT_SUFFIX]),
        GUINT_TO_POINTER(RULE_TEXT_SUFFIX));
    menu_new_item_with_data(
        m, _(rule_text_type_labels[RULE_TEXT_SUBSTR]),
        GUINT_TO_POINTER(RULE_TEXT_SUBSTR));
    menu_new_item_with_data(
        m, _(rule_text_type_labels[RULE_TEXT_REGEXP]),
        GUINT_TO_POINTER(RULE_TEXT_REGEXP));
    menu_new_item_with_data(
        m, _(rule_text_type_labels[RULE_TEXT_EXACT]),
        GUINT_TO_POINTER(RULE_TEXT_EXACT));

    gtk_option_menu_set_menu(
        GTK_OPTION_MENU
            (lookup_widget(filter_dialog, "optionmenu_filter_text_type")),
        GTK_WIDGET(m));

    /*
     * The user_data set here is later relevant for filter_gui_get_flag_rule()
     */
    gtk_object_set_user_data(
        GTK_OBJECT(lookup_widget
            (filter_dialog, "radiobutton_filter_flag_stable_set")),
		GUINT_TO_POINTER(RULE_FLAG_SET));
    gtk_object_set_user_data(
        GTK_OBJECT(lookup_widget
            (filter_dialog, "radiobutton_filter_flag_stable_unset")),
        GUINT_TO_POINTER(RULE_FLAG_UNSET));
    gtk_object_set_user_data(
        GTK_OBJECT(lookup_widget
            (filter_dialog, "radiobutton_filter_flag_stable_ignore")),
        GUINT_TO_POINTER(RULE_FLAG_IGNORE));

    gtk_object_set_user_data(
        GTK_OBJECT(lookup_widget
            (filter_dialog, "radiobutton_filter_flag_busy_set")),
        GUINT_TO_POINTER(RULE_FLAG_SET));
    gtk_object_set_user_data(
        GTK_OBJECT(lookup_widget
            (filter_dialog, "radiobutton_filter_flag_busy_unset")),
        GUINT_TO_POINTER(RULE_FLAG_UNSET));
    gtk_object_set_user_data(
        GTK_OBJECT(lookup_widget
            (filter_dialog, "radiobutton_filter_flag_busy_ignore")),
        GUINT_TO_POINTER(RULE_FLAG_IGNORE));

    gtk_object_set_user_data(
        GTK_OBJECT(lookup_widget
            (filter_dialog, "radiobutton_filter_flag_push_set")),
        GUINT_TO_POINTER(RULE_FLAG_SET));
    gtk_object_set_user_data(
        GTK_OBJECT(lookup_widget
            (filter_dialog, "radiobutton_filter_flag_push_unset")),
        GUINT_TO_POINTER(RULE_FLAG_UNSET));
    gtk_object_set_user_data(
        GTK_OBJECT(lookup_widget
            (filter_dialog, "radiobutton_filter_flag_push_ignore")),
        GUINT_TO_POINTER(RULE_FLAG_IGNORE));

    /*
     * The user_data set here is later relevant for filter_gui_get_state_rule()
     */
    gtk_object_set_user_data(
        GTK_OBJECT(lookup_widget
            (filter_dialog, "radiobutton_filter_state_display_do")),
        GUINT_TO_POINTER(FILTER_PROP_STATE_DO));
    gtk_object_set_user_data(
        GTK_OBJECT(lookup_widget
        (filter_dialog, "radiobutton_filter_state_display_dont")),
        GUINT_TO_POINTER(FILTER_PROP_STATE_DONT));
    gtk_object_set_user_data(
        GTK_OBJECT(lookup_widget
            (filter_dialog, "radiobutton_filter_state_display_ignore")),
        GUINT_TO_POINTER(FILTER_PROP_STATE_IGNORE));
    gtk_object_set_user_data(
        GTK_OBJECT(lookup_widget
            (filter_dialog, "radiobutton_filter_state_display_undef")),
        GUINT_TO_POINTER(FILTER_PROP_STATE_UNKNOWN));

    gtk_object_set_user_data(
        GTK_OBJECT(lookup_widget
            (filter_dialog, "radiobutton_filter_state_download_do")),
        GUINT_TO_POINTER(FILTER_PROP_STATE_DO));
    gtk_object_set_user_data(
        GTK_OBJECT(lookup_widget
            (filter_dialog, "radiobutton_filter_state_download_dont")),
        GUINT_TO_POINTER(FILTER_PROP_STATE_DONT));
    gtk_object_set_user_data(
        GTK_OBJECT(lookup_widget
            (filter_dialog, "radiobutton_filter_state_download_ignore")),
        GUINT_TO_POINTER(FILTER_PROP_STATE_IGNORE));
    gtk_object_set_user_data(
        GTK_OBJECT(lookup_widget
            (filter_dialog, "radiobutton_filter_state_download_undef")),
        GUINT_TO_POINTER(FILTER_PROP_STATE_UNKNOWN));

}

/**
 * Show the dialog on screen and set position.
 */
void
filter_gui_show_dialog(void)
{
    guint32 coord[4] = { 0, 0, 0, 0 };

    if (filter_dialog == NULL)
        return;

    gui_prop_get_guint32(PROP_FILTER_DLG_COORDS, coord, 0, 4);
	gui_fix_coords(coord);

    if (coord[2] != 0 && coord[3] != 0)
        gtk_window_set_default_size(GTK_WINDOW(filter_dialog),
	    coord[2], coord[3]);

    gtk_paned_set_position(
        GTK_PANED(lookup_widget(filter_dialog, "hpaned_filter_main")),
        filter_main_divider_pos);

    gtk_widget_show(filter_dialog);
    gdk_window_raise(filter_dialog->window);
}



/**
 * Remove all entries from the filter tree.
 */
void
filter_gui_filter_clear_list(void)
{
    gchar *titles[3];
    GdkColor *bg_color;
    GtkCTree *ctree_filter_filters;

    if (filter_dialog == NULL)
        return;

    ctree_filter_filters = GTK_CTREE
        (lookup_widget(filter_dialog, "ctree_filter_filters"));

    bg_color = &(gtk_widget_get_style(GTK_WIDGET(ctree_filter_filters))
        ->bg[GTK_STATE_ACTIVE]);

    if (fl_node_global != NULL)
        gtk_ctree_remove_node(GTK_CTREE(ctree_filter_filters), fl_node_global);
    if (fl_node_bound != NULL)
        gtk_ctree_remove_node(GTK_CTREE(ctree_filter_filters), fl_node_bound);
    if (fl_node_free != NULL)
        gtk_ctree_remove_node(GTK_CTREE(ctree_filter_filters), fl_node_free);
    if (fl_node_builtin != NULL)
        gtk_ctree_remove_node(GTK_CTREE(ctree_filter_filters), fl_node_builtin);


    titles[0] = _("Builtin targets (not editable)");
    titles[1] = "";
    titles[2] = "";
    fl_node_builtin = gtk_ctree_insert_node(
        GTK_CTREE(ctree_filter_filters), NULL, NULL,
        titles, 0, NULL, NULL, NULL, NULL, FALSE, TRUE);

    titles[0] = _("Global filters");
    fl_node_global = gtk_ctree_insert_node(
        GTK_CTREE(ctree_filter_filters), NULL, NULL,
        titles, 0, NULL, NULL, NULL, NULL, FALSE, TRUE);

    titles[0] = _("Search filters");
    fl_node_bound = gtk_ctree_insert_node(
        GTK_CTREE(ctree_filter_filters), NULL, NULL,
        titles, 0, NULL, NULL, NULL, NULL, FALSE, TRUE);

    titles[0] = _("Free filters");
    fl_node_free = gtk_ctree_insert_node(
        GTK_CTREE(ctree_filter_filters), NULL, NULL,
        titles, 0, NULL, NULL, NULL, NULL, FALSE, TRUE);

    gtk_ctree_node_set_selectable
        (GTK_CTREE(ctree_filter_filters), fl_node_builtin, FALSE);
    gtk_ctree_node_set_selectable
        (GTK_CTREE(ctree_filter_filters), fl_node_global, FALSE);
    gtk_ctree_node_set_selectable
        (GTK_CTREE(ctree_filter_filters), fl_node_bound, FALSE);
    gtk_ctree_node_set_selectable
        (GTK_CTREE(ctree_filter_filters), fl_node_free, FALSE);

    gtk_ctree_node_set_background(GTK_CTREE(ctree_filter_filters),
        fl_node_builtin, bg_color);
    gtk_ctree_node_set_background(GTK_CTREE(ctree_filter_filters),
        fl_node_global, bg_color);
    gtk_ctree_node_set_background(GTK_CTREE(ctree_filter_filters),
        fl_node_bound, bg_color);
    gtk_ctree_node_set_background(GTK_CTREE(ctree_filter_filters),
        fl_node_free, bg_color);
}



/**
 * Adds a filter to the filter list in the dialog. If the filter has a
 * shadow, shadow->current should be set as ruleset. If ruleset is NULL,
 * default to filter->ruleset.
 */
void
filter_gui_filter_add(filter_t *f, GList *ruleset)
{
    const gchar *titles[3];
    GtkCTreeNode *node;
    GtkCTreeNode *parent;
    guint count;
    GtkCTree *ctree_filter_filters;
	gchar buf[G_N_ELEMENTS(titles)][256];

    g_assert(f != NULL);

    if (filter_dialog == NULL)
        return;

    ctree_filter_filters = GTK_CTREE
        (lookup_widget(filter_dialog, "ctree_filter_filters"));

    if (ruleset == NULL)
        ruleset = f->ruleset;

    titles[0] = lazy_utf8_to_ui_string(f->name);
    gm_snprintf(buf[1], sizeof buf[1], "%d", g_list_length(ruleset));
    titles[1] = buf[1];
    count = f->match_count + f->fail_count;
    if (count != 0) {
        if (filter_is_builtin(f)) {
            gm_snprintf(buf[2], sizeof buf[2], "%d", f->match_count);
        } else {
            gm_snprintf(buf[2], sizeof buf[2], "%d/%d (%d%%)",
                f->match_count, count,
				(gint)(f->match_count / (count * 100.0)));
        }
        titles[2] = buf[2];
    } else {
        titles[2] = "...";
    }

    parent = getFilterRoot(f);

    node = gtk_ctree_insert_node(
        GTK_CTREE(ctree_filter_filters), parent, NULL,
		deconstify_gpointer(titles),
		0, NULL, NULL, NULL, NULL, TRUE, TRUE);
    gtk_ctree_node_set_row_data(GTK_CTREE(ctree_filter_filters), node, f);

    if (parent == fl_node_builtin)
        gtk_ctree_node_set_selectable(GTK_CTREE(ctree_filter_filters),
			node, FALSE);

}



/**
 * Update the rule count of a filter in the filter table.
 */
void
filter_gui_update_rule_count(filter_t *f, GList *ruleset)
{
    GtkCTreeNode *parent;
    GtkCTreeNode *node;
    GtkCTree *ctree_filter_filters;

    g_assert(f != NULL);

    if (filter_dialog == NULL)
        return;

    ctree_filter_filters = GTK_CTREE
        (lookup_widget(filter_dialog, "ctree_filter_filters"));

    parent = getFilterRoot(f);
    node = gtk_ctree_find_by_row_data(ctree_filter_filters, parent, f);

    if (node != NULL) {
		gchar buf[32];
		
        gm_snprintf(buf, sizeof buf, "%d", g_list_length(ruleset));
        gtk_ctree_node_set_text(GTK_CTREE(ctree_filter_filters),
			node, 1, buf);
    }
}



/**
 * Removes a filter from the list in the dialog.
 */
void
filter_gui_filter_remove(filter_t *f)
{
    GtkCTreeNode *parent;
    GtkCTreeNode *node;
    GtkCTree *ctree_filter_filters;

    g_assert(f != NULL);

    if (filter_dialog == NULL)
        return;

    ctree_filter_filters = GTK_CTREE
        (lookup_widget(filter_dialog, "ctree_filter_filters"));

    parent = getFilterRoot(f);
    node = gtk_ctree_find_by_row_data(ctree_filter_filters, parent, f);
    if (node != NULL)
        gtk_ctree_remove_node(ctree_filter_filters, node);
}



/**
 * Don't use this directly. Better use filter_set from filter.c.
 * Tell the gui to set itself up to work on the given filter.
 * The information about removeable/active state and ruleset are not
 * taken from the filter!
 *
 * @note
 * This does not rebuild the target combos.
 */
void
filter_gui_filter_set(filter_t *f, gboolean removable,
	gboolean active, GList *ruleset)
{
    static const gchar * const widgets[] = {
		"checkbutton_filter_enabled",
		"button_filter_reset",
		"button_filter_add_rule_text",
		"button_filter_add_rule_ip",
		"button_filter_add_rule_size",
		"button_filter_add_rule_jump",
		"button_filter_add_rule_flag",
		"button_filter_add_rule_state",
		"clist_filter_rules",
		"entry_filter_name",
    };
    GtkCTree *ctree_filter_filters;

    if (filter_dialog == NULL)
        return;

    ctree_filter_filters = GTK_CTREE
        (lookup_widget(filter_dialog, "ctree_filter_filters"));

    filter_gui_edit_rule(NULL);

    work_filter = f;

    if (f != NULL) {
        GtkCTreeNode *node;

        gtk_mass_widget_set_sensitive(filter_dialog,
			widgets, G_N_ELEMENTS(widgets), TRUE);

        gtk_widget_set_sensitive
            (lookup_widget(filter_dialog, "button_filter_remove"), removable);
        gtk_toggle_button_set_active(
            GTK_TOGGLE_BUTTON
                (lookup_widget(filter_dialog, "checkbutton_filter_enabled")),
            active);
        gtk_entry_set_text(
            GTK_ENTRY(lookup_widget(filter_dialog, "entry_filter_name")),
            lazy_utf8_to_ui_string(f->name));

        filter_gui_filter_set_enabled(f, active);

        if (gui_debug >= 5)
            printf("showing ruleset for filter: %s\n", f->name);
        filter_gui_set_ruleset(ruleset);

        node = gtk_ctree_find_by_row_data(
            GTK_CTREE(ctree_filter_filters),
            getFilterRoot(f), f);
        if (node != NULL) {
            gtk_ctree_select(ctree_filter_filters, node);
        } else {
            g_warning("work_filter is not available in filter tree");
            gtk_clist_unselect_all(GTK_CLIST(ctree_filter_filters));
        }
    } else {
        gtk_entry_set_text(
            GTK_ENTRY(lookup_widget(filter_dialog, "entry_filter_name")),
            "");
        filter_gui_set_ruleset(NULL);
        filter_gui_filter_set_enabled(NULL, FALSE);

        gtk_clist_unselect_all(GTK_CLIST(ctree_filter_filters));

        gtk_widget_set_sensitive
            (lookup_widget(filter_dialog, "button_filter_remove"), FALSE);
        gtk_mass_widget_set_sensitive(filter_dialog,
			widgets, G_N_ELEMENTS(widgets), FALSE);
    }
}



/**
 * Tell the gui a given filter is enabled/disabled. If the filter given
 * is NULL, then the widget will be set insensitive and inactive.
 */
void
filter_gui_filter_set_enabled(filter_t *f, gboolean active)
{
    GtkCTreeNode *node;
    GtkCTreeNode *parent;
    GdkColor *color;
    GtkToggleButton *checkbutton_filter_enabled;
    GtkCTree *ctree_filter_filters;

    if (filter_dialog == NULL)
        return;

    checkbutton_filter_enabled = GTK_TOGGLE_BUTTON
        (lookup_widget(filter_dialog, "checkbutton_filter_enabled"));

    gtk_widget_set_sensitive(GTK_WIDGET(checkbutton_filter_enabled),
        f != NULL);

    if (f == NULL) {
        gtk_toggle_button_set_active(checkbutton_filter_enabled, FALSE);
        return;
    }

    ctree_filter_filters = GTK_CTREE
        (lookup_widget(filter_dialog, "ctree_filter_filters"));

    if (f == work_filter)
        gtk_toggle_button_set_active(checkbutton_filter_enabled, active);

    parent = getFilterRoot(f);

    node = gtk_ctree_find_by_row_data(ctree_filter_filters, parent, f);

    color = active ? NULL :
        &(gtk_widget_get_style(GTK_WIDGET(ctree_filter_filters))
            ->bg[GTK_STATE_INSENSITIVE]);

    gtk_ctree_node_set_foreground(ctree_filter_filters, node, color);
}



/**
 * Update the filter list with the current stats data from the filters.
 */
void
filter_gui_update_filter_stats(void)
{
    GtkCTree *ctree_filter_filters;
    gint row;

    if (filter_dialog == NULL)
        return;

    ctree_filter_filters = GTK_CTREE
        (lookup_widget(filter_dialog, "ctree_filter_filters"));

    gtk_clist_freeze(GTK_CLIST(ctree_filter_filters));

    for (row = 0; row < GTK_CLIST(ctree_filter_filters)->rows; row ++) {
        gchar *title;
        filter_t *filter;
        GtkCTreeNode *node;
		gchar buf[256];

        node = gtk_ctree_node_nth(GTK_CTREE(ctree_filter_filters), row);
        filter = gtk_ctree_node_get_row_data
            (GTK_CTREE(ctree_filter_filters), node);

        if (filter == NULL)
            continue;

        if (filter_is_shadowed(filter)) {
            title = _("new");
        } else {
			guint n;
			
            n = filter->match_count + filter->fail_count;
            if (n != 0) {
                if (filter_is_builtin(filter)) {
                    gm_snprintf(buf, sizeof buf, "%d", filter->match_count);
                } else {
                    gm_snprintf(buf, sizeof buf, "%d/%d (%d%%)",
                        filter->match_count, n,
                        (gint)(filter->match_count / (n * 100.0)));
                }
                title = buf;
            } else {
                title = _("none yet");
            }
        }

        gtk_ctree_node_set_text(GTK_CTREE(ctree_filter_filters),
			node, 2, title);
    }

    gtk_clist_thaw(GTK_CLIST(ctree_filter_filters));
}



/**
 * Update the rules list with the current stats data from the rules.
 */
void
filter_gui_update_rule_stats(void)
{
    GtkCList *clist_filter_rules;
    gint row;

    if (filter_dialog == NULL || work_filter == NULL)
        return;

    clist_filter_rules = GTK_CLIST(lookup_widget(filter_dialog,
													"clist_filter_rules"));

    gtk_clist_freeze(GTK_CLIST(clist_filter_rules));

    for (row = 0; row < GTK_CLIST(clist_filter_rules)->rows; row++) {
        gchar *title;
        rule_t *rule;
		gchar buf[256];
        gint n;

        rule = gtk_clist_get_row_data(GTK_CLIST(clist_filter_rules), row);

        if (rule == NULL)
            continue;

        if (RULE_IS_SHADOWED(rule)) {
            title = _("new");
        } else {
            n = rule->match_count + rule->fail_count;
            if (n != 0) {
                gm_snprintf(buf, sizeof buf, "%d/%d (%d%%)",
                    rule->match_count, n,
                    (gint)(rule->match_count / (n * 100.0)));
                title = buf;
            } else {
                title = _("none yet");
            }
        }

        gtk_clist_set_text(GTK_CLIST(clist_filter_rules), row, 3, title);
    }

    gtk_clist_thaw(GTK_CLIST(clist_filter_rules));
}



void
filter_gui_rebuild_target_combos(GList *filters)
{
    static const struct {
		const gchar *name;
	} opt_menus[] = {
		{ "optionmenu_filter_text_target"  },
		{ "optionmenu_filter_ip_target"    },
		{ "optionmenu_filter_size_target"  },
		{ "optionmenu_filter_jump_target"  },
		{ "optionmenu_filter_sha1_target"  },
		{ "optionmenu_filter_flag_target"  },
		{ "optionmenu_filter_state_target" },
	};
    GtkWidget *optionmenu_search_filter;
    GtkMenu *m;
    GList *l_iter;
    GList *buf = NULL;
    gpointer bufptr;

    /*
     * Prepare a list of unbound filters and also leave
     * out the global and builtin filters.
     */
    for (l_iter = filters; l_iter != NULL; l_iter = g_list_next(l_iter)) {
        filter_t *filter = l_iter->data;

        if (!filter_is_bound(filter) && !filter_is_global(filter))
            buf = g_list_append(buf, filter);
    }

    /*
     * These can only be updated if there is a dialog.
     */
    if (filter_dialog != NULL) {
    	guint i;

        for (i = 0; i < G_N_ELEMENTS(opt_menus); i++) {
            m = GTK_MENU(gtk_menu_new());

            for (l_iter = buf; l_iter != NULL; l_iter = g_list_next(l_iter)) {
                filter_t *filter = l_iter->data;
                if (filter != work_filter) {
					const gchar *s = lazy_utf8_to_ui_string(filter->name);
                    menu_new_item_with_data(m, deconstify_gchar(s), filter);
				}
            }

            gtk_option_menu_set_menu(
               GTK_OPTION_MENU(lookup_widget(filter_dialog, opt_menus[i].name)),
               GTK_WIDGET(m));
        }
    }

    /*
     * The following is in the main window and should always be
     * updateable.
     */
    optionmenu_search_filter = lookup_widget
        (main_window, "optionmenu_search_filter");

    bufptr = option_menu_get_selected_data(optionmenu_search_filter);

    m = GTK_MENU(gtk_menu_new());

    menu_new_item_with_data(m, _("no default filter"), NULL);
    for (l_iter = buf; l_iter != NULL; l_iter = g_list_next(l_iter)) {
        filter_t *filter = l_iter->data;
        /*
         * This is no need to create a query which should not
         * display anything, also we can't advertise a filter
         * as target that does not really exist yet.
         */
        if (!filter_is_builtin(filter) && !filter_is_shadowed(filter)) {
			const gchar *s = lazy_utf8_to_ui_string(filter->name);
            menu_new_item_with_data(m, deconstify_gchar(s), filter);
		}
    }

    gtk_option_menu_set_menu(GTK_OPTION_MENU(optionmenu_search_filter),
		GTK_WIDGET(m));

    option_menu_select_item_by_data(optionmenu_search_filter, bufptr);

    g_list_free(buf);
}



/**
 * Load the given rule into the detail view.
 */
void
filter_gui_edit_rule(rule_t *r)
{
    if (filter_dialog == NULL)
        return;

    if (r != NULL) {
        switch (r->type) {
        case RULE_TEXT:
            filter_gui_edit_text_rule(r);
            break;
        case RULE_IP:
            filter_gui_edit_ip_rule(r);
            break;
        case RULE_SIZE:
            filter_gui_edit_size_rule(r);
            break;
        case RULE_JUMP:
            filter_gui_edit_jump_rule(r);
            break;
        case RULE_SHA1:
            filter_gui_edit_sha1_rule(r);
            break;
        case RULE_FLAG:
            filter_gui_edit_flag_rule(r);
            break;
        case RULE_STATE:
            filter_gui_edit_state_rule(r);
            break;
        default:
            g_error("Unknown rule type: %d", r->type);
        }
    } else {
        gtk_notebook_set_page(
            GTK_NOTEBOOK
                (lookup_widget(filter_dialog, "notebook_filter_detail")),
            nb_filt_page_buttons);
        gtk_clist_unselect_all
            (GTK_CLIST(lookup_widget(filter_dialog, "clist_filter_rules")));
    }
}



/**
 * Load a ip rule into the rule edtior or clear it if the rule is NULL.
 */
void
filter_gui_edit_ip_rule(rule_t *r)
{
    gchar *ip       = NULL;
    gchar *mask     = NULL;
    gpointer target = DEFAULT_TARGET;
    gboolean invert = FALSE;
    gboolean active = TRUE;
    gboolean soft   = FALSE;

    g_assert(r == NULL || r->type == RULE_IP);

    if (filter_dialog == NULL)
        return;

    if (r != NULL) {
        ip     = g_strdup(ip_to_string(r->u.ip.addr));
        mask   = g_strdup(ip_to_string(r->u.ip.mask));
        target = r->target;
        invert = RULE_IS_NEGATED(r);
        active = RULE_IS_ACTIVE(r);
        soft   = RULE_IS_SOFT(r);
    } else {
		ip = g_strdup("");
		mask = g_strdup("255.255.255.255");
	}

    gtk_entry_set_text(
        GTK_ENTRY(lookup_widget(filter_dialog, "entry_filter_ip_address")),
        ip);
    gtk_entry_set_text(
        GTK_ENTRY(lookup_widget(filter_dialog, "entry_filter_ip_mask")),
        mask);
    option_menu_select_item_by_data(
        lookup_widget(filter_dialog, "optionmenu_filter_ip_target"),
        target);
    gtk_toggle_button_set_active(
        GTK_TOGGLE_BUTTON(lookup_widget
            (filter_dialog, "checkbutton_filter_ip_invert_cond")),
        invert);
    gtk_toggle_button_set_active(
        GTK_TOGGLE_BUTTON
            (lookup_widget(filter_dialog, "checkbutton_filter_ip_active")),
        active);
    gtk_toggle_button_set_active(
        GTK_TOGGLE_BUTTON
            (lookup_widget(filter_dialog, "checkbutton_filter_ip_soft")),
        soft);

   	G_FREE_NULL(ip);
   	G_FREE_NULL(mask);

    gtk_notebook_set_page(
        GTK_NOTEBOOK(lookup_widget(filter_dialog, "notebook_filter_detail")),
        nb_filt_page_ip);
}



/**
 * Load a sha1 rule into the rule edtior or clear it if the rule is NULL.
 */
void
filter_gui_edit_sha1_rule(rule_t *r)
{
    gchar *hash     = "";
    gchar *origfile = "";
    gpointer target = DEFAULT_TARGET;
    gboolean invert = FALSE;
    gboolean active = TRUE;
    gboolean soft   = FALSE;

    g_assert((r == NULL) ||(r->type == RULE_SHA1));

    if (filter_dialog == NULL)
        return;

    if (r != NULL) {
        hash = r->u.sha1.hash != NULL ?
            sha1_base32(r->u.sha1.hash) : _("[no hash]");
        origfile = r->u.sha1.filename;
        target = r->target;
        invert = RULE_IS_NEGATED(r);
        active = RULE_IS_ACTIVE(r);
        soft   = RULE_IS_SOFT(r);
    }

    gtk_entry_set_text(
        GTK_ENTRY(lookup_widget(filter_dialog, "entry_filter_sha1_hash")),
        hash);
    gtk_entry_set_text(
        GTK_ENTRY(lookup_widget(filter_dialog, "entry_filter_sha1_origfile")),
        lazy_utf8_to_ui_string(origfile));
    option_menu_select_item_by_data(
        lookup_widget(filter_dialog, "optionmenu_filter_sha1_target"),
        target);
    gtk_toggle_button_set_active(
        GTK_TOGGLE_BUTTON(lookup_widget
            (filter_dialog, "checkbutton_filter_sha1_invert_cond")),
        invert);
    gtk_toggle_button_set_active(
        GTK_TOGGLE_BUTTON
            (lookup_widget(filter_dialog, "checkbutton_filter_sha1_active")),
        active);
    gtk_toggle_button_set_active(
        GTK_TOGGLE_BUTTON
            (lookup_widget(filter_dialog, "checkbutton_filter_sha1_soft")),
        soft);

    gtk_notebook_set_page(
        GTK_NOTEBOOK
            (lookup_widget(filter_dialog, "notebook_filter_detail")),
        nb_filt_page_sha1);
}



/**
 * Load a ip rule into the rule edtior or clear it if the rule is NULL.
 */

void
filter_gui_edit_text_rule(rule_t *r)
{
    gchar *pattern  = "";
    guint type      = RULE_TEXT_WORDS;
    gboolean tcase  = FALSE;
    gpointer target = DEFAULT_TARGET;
    gboolean invert = FALSE;
    gboolean active = TRUE;
    gboolean soft   = FALSE;

    g_assert((r == NULL) || (r->type == RULE_TEXT));

    if (filter_dialog == NULL)
        return;

    if (r != NULL) {
        pattern = r->u.text.match;
        type    = r->u.text.type;
        tcase   = r->u.text.case_sensitive;
        target  = r->target;
        invert  = RULE_IS_NEGATED(r);
        active  = RULE_IS_ACTIVE(r);
        soft    = RULE_IS_SOFT(r);
    }

    gtk_entry_set_text(
        GTK_ENTRY(lookup_widget(filter_dialog, "entry_filter_text_pattern")),
        lazy_utf8_to_ui_string(pattern));
    gtk_toggle_button_set_active(
        GTK_TOGGLE_BUTTON
            (lookup_widget(filter_dialog, "checkbutton_filter_text_case")),
        tcase);
    gtk_option_menu_set_history(
        GTK_OPTION_MENU
            (lookup_widget(filter_dialog, "optionmenu_filter_text_type")),
        type);
    option_menu_select_item_by_data(
        lookup_widget(filter_dialog, "optionmenu_filter_text_target"),
        target);
    gtk_toggle_button_set_active(
        GTK_TOGGLE_BUTTON(lookup_widget
            (filter_dialog, "checkbutton_filter_text_invert_cond")),
        invert);
    gtk_toggle_button_set_active(
        GTK_TOGGLE_BUTTON
            (lookup_widget(filter_dialog, "checkbutton_filter_text_active")),
        active);
    gtk_toggle_button_set_active(
        GTK_TOGGLE_BUTTON
            (lookup_widget(filter_dialog, "checkbutton_filter_text_soft")),
        soft);

    gtk_notebook_set_page(
        GTK_NOTEBOOK
            (lookup_widget(filter_dialog, "notebook_filter_detail")),
        nb_filt_page_text);
}



/**
 * Load a ip rule into the rule edtior or clear it if the rule is NULL.
 */
void
filter_gui_edit_size_rule(rule_t *r)
{
    filesize_t min     = 0;
    filesize_t max     = 0;
    gpointer target = DEFAULT_TARGET;
    gboolean invert = FALSE;
    gboolean active = TRUE;
    gboolean soft   = FALSE;

    g_assert((r == NULL) || (r->type == RULE_SIZE));

    if (filter_dialog == NULL)
        return;

    if (r != NULL) {
        min    = r->u.size.lower;
        max    = r->u.size.upper;
        target = r->target;
        invert = RULE_IS_NEGATED(r);
        active = RULE_IS_ACTIVE(r);
        soft   = RULE_IS_SOFT(r);
    }

    gtk_entry_printf(
        GTK_ENTRY(lookup_widget(filter_dialog, "entry_filter_size_min")),
		"%s", uint64_to_string(min));
    gtk_entry_printf(
        GTK_ENTRY(lookup_widget(filter_dialog, "entry_filter_size_max")),
		"%s", uint64_to_string(max));
    option_menu_select_item_by_data(
        lookup_widget(filter_dialog, "optionmenu_filter_size_target"),
        target);
    gtk_toggle_button_set_active(
        GTK_TOGGLE_BUTTON(lookup_widget
            (filter_dialog, "checkbutton_filter_size_invert_cond")),
        invert);
    gtk_toggle_button_set_active(
        GTK_TOGGLE_BUTTON
            (lookup_widget(filter_dialog, "checkbutton_filter_size_active")),
        active);
    gtk_toggle_button_set_active(
        GTK_TOGGLE_BUTTON
            (lookup_widget(filter_dialog, "checkbutton_filter_size_soft")),
        soft);

    gtk_notebook_set_page(
        GTK_NOTEBOOK
            (lookup_widget(filter_dialog, "notebook_filter_detail")),
        nb_filt_page_size);
}



/**
 * Load a ip rule into the rule edtior or clear it if the rule is NULL.
 */
void
filter_gui_edit_jump_rule(rule_t *r)
{
    gpointer target = DEFAULT_TARGET;
    gboolean active = TRUE;

    g_assert((r == NULL) || (r->type == RULE_JUMP));

    if (filter_dialog == NULL)
        return;

    if (r != NULL) {
        target = r->target;
        active = RULE_IS_ACTIVE(r);
    }

    option_menu_select_item_by_data(
        lookup_widget(filter_dialog, "optionmenu_filter_jump_target"),
        target);
    gtk_toggle_button_set_active(
        GTK_TOGGLE_BUTTON
            (lookup_widget(filter_dialog, "checkbutton_filter_jump_active")),
        active);

    gtk_notebook_set_page(
        GTK_NOTEBOOK
            (lookup_widget(filter_dialog, "notebook_filter_detail")),
        nb_filt_page_jump);
}



/**
 * Load a flag rule into the rule edtior or clear it if the rule is NULL.
 */
void
filter_gui_edit_flag_rule(rule_t *r)
{
    guint stable    = RULE_FLAG_IGNORE;
    guint busy      = RULE_FLAG_IGNORE;
    guint push      = RULE_FLAG_IGNORE;
    gpointer target = DEFAULT_TARGET;
    gboolean active = TRUE;
    gboolean soft   = FALSE;
    gchar *widget   = NULL;

    g_assert((r == NULL) || (r->type == RULE_FLAG));

    if (filter_dialog == NULL)
        return;

    if (r != NULL) {
        stable = r->u.flag.stable;
        busy   = r->u.flag.busy;
        push   = r->u.flag.push;
        active = RULE_IS_ACTIVE(r);
        soft   = RULE_IS_SOFT(r);
    }

    switch (stable) {
    case RULE_FLAG_SET:
        widget = "radiobutton_filter_flag_stable_set";
        break;
    case RULE_FLAG_UNSET:
        widget = "radiobutton_filter_flag_stable_unset";
        break;
    case RULE_FLAG_IGNORE:
        widget = "radiobutton_filter_flag_stable_ignore";
        break;
    default:
        g_assert_not_reached();
    }
    gtk_toggle_button_set_active
        (GTK_TOGGLE_BUTTON(lookup_widget(filter_dialog, widget)), TRUE);

    switch (busy) {
    case RULE_FLAG_SET:
        widget = "radiobutton_filter_flag_busy_set";
        break;
    case RULE_FLAG_UNSET:
        widget = "radiobutton_filter_flag_busy_unset";
        break;
    case RULE_FLAG_IGNORE:
        widget = "radiobutton_filter_flag_busy_ignore";
        break;
    default:
        g_assert_not_reached();
    }
    gtk_toggle_button_set_active
        (GTK_TOGGLE_BUTTON(lookup_widget(filter_dialog, widget)), TRUE);

    switch (push) {
    case RULE_FLAG_SET:
        widget = "radiobutton_filter_flag_push_set";
        break;
    case RULE_FLAG_UNSET:
        widget = "radiobutton_filter_flag_push_unset";
        break;
    case RULE_FLAG_IGNORE:
        widget = "radiobutton_filter_flag_push_ignore";
        break;
    default:
        g_assert_not_reached();
    }
    gtk_toggle_button_set_active
        (GTK_TOGGLE_BUTTON(lookup_widget(filter_dialog, widget)), TRUE);

    option_menu_select_item_by_data(
        lookup_widget(filter_dialog, "optionmenu_filter_flag_target"),
        target);
    gtk_toggle_button_set_active(
        GTK_TOGGLE_BUTTON
            (lookup_widget(filter_dialog, "checkbutton_filter_flag_active")),
        active);
    gtk_toggle_button_set_active(
        GTK_TOGGLE_BUTTON
            (lookup_widget(filter_dialog, "checkbutton_filter_flag_soft")),
        soft);

    gtk_notebook_set_page(
        GTK_NOTEBOOK
            (lookup_widget(filter_dialog, "notebook_filter_detail")),
        nb_filt_page_flag);
}




/**
 * Load a state rule into the rule edtior or clear it if the rule is NULL.
 */
void
filter_gui_edit_state_rule(rule_t *r)
{
    guint display   = FILTER_PROP_STATE_IGNORE;
    guint download  = FILTER_PROP_STATE_IGNORE;
    gpointer target = DEFAULT_TARGET;
    gboolean active = TRUE;
    gboolean soft   = FALSE;
    gboolean invert = FALSE;
    gchar *widget   = NULL;

    g_assert((r == NULL) || (r->type == RULE_STATE));

    if (filter_dialog == NULL)
        return;

    if (r != NULL) {
        display  = r->u.state.display;
        download = r->u.state.download;
        target   = r->target;
        invert   = RULE_IS_NEGATED(r);
        active   = RULE_IS_ACTIVE(r);
        soft     = RULE_IS_SOFT(r);
    }

    switch (display) {
    case FILTER_PROP_STATE_UNKNOWN:
         widget = "radiobutton_filter_state_display_undef";
         break;
    case FILTER_PROP_STATE_DO:
         widget = "radiobutton_filter_state_display_do";
         break;
    case FILTER_PROP_STATE_DONT:
         widget = "radiobutton_filter_state_display_dont";
         break;
    case FILTER_PROP_STATE_IGNORE:
         widget = "radiobutton_filter_state_display_ignore";
         break;
    default:
         g_error("filter_gui_edit_state_rule: unknown property: %d", display);
    }
    gtk_toggle_button_set_active
        (GTK_TOGGLE_BUTTON(lookup_widget(filter_dialog, widget)), TRUE);

    switch (download) {
    case FILTER_PROP_STATE_UNKNOWN:
         widget = "radiobutton_filter_state_download_undef";
         break;
    case FILTER_PROP_STATE_DO:
         widget = "radiobutton_filter_state_download_do";
         break;
    case FILTER_PROP_STATE_DONT:
         widget = "radiobutton_filter_state_download_dont";
         break;
    case FILTER_PROP_STATE_IGNORE:
         widget = "radiobutton_filter_state_download_ignore";
         break;
    default:
         g_error("filter_gui_edit_state_rule: unknown property: %d", download);
    }
    gtk_toggle_button_set_active
        (GTK_TOGGLE_BUTTON(lookup_widget(filter_dialog, widget)), TRUE);

    option_menu_select_item_by_data(
        lookup_widget(filter_dialog, "optionmenu_filter_state_target"),
        target);
    gtk_toggle_button_set_active(
        GTK_TOGGLE_BUTTON(lookup_widget
            (filter_dialog, "checkbutton_filter_state_invert_cond")),
        invert);
    gtk_toggle_button_set_active(
        GTK_TOGGLE_BUTTON
            (lookup_widget(filter_dialog, "checkbutton_filter_state_active")),
        active);
    gtk_toggle_button_set_active(
        GTK_TOGGLE_BUTTON
            (lookup_widget(filter_dialog, "checkbutton_filter_state_soft")),
        soft);

    gtk_notebook_set_page(
        GTK_NOTEBOOK
            (lookup_widget(filter_dialog, "notebook_filter_detail")),
        nb_filt_page_state);
}



/**
 * Display the given ruleset in the table.
 */
void
filter_gui_set_ruleset(GList *ruleset)
{
    GList *l_iter;
    gint count = 0;
    GdkColor *color;
    GtkCList *clist_filter_rules;

    if (filter_dialog == NULL)
        return;

    clist_filter_rules = GTK_CLIST
        (lookup_widget(filter_dialog, "clist_filter_rules"));

    gtk_clist_freeze(clist_filter_rules);
    gtk_clist_clear(clist_filter_rules);

    color = &(gtk_widget_get_style(GTK_WIDGET(clist_filter_rules))
                ->bg[GTK_STATE_INSENSITIVE]);

    gtk_widget_set_sensitive(
        GTK_WIDGET
            (lookup_widget(filter_dialog, "button_filter_reset_all_rules")),
        ruleset != NULL);

    for (l_iter = ruleset; l_iter != NULL; l_iter = g_list_next(l_iter)) {
        rule_t *r = l_iter->data;
        const gchar *titles[4];
        gint row;

        g_assert(r != NULL);
        count++;
        titles[0] = RULE_IS_NEGATED(r) ? "X" : "";
        titles[1] = filter_rule_condition_to_string(r);
        titles[2] = lazy_utf8_to_ui_string(r->target->name);
        titles[3] = "...";

        row = gtk_clist_append(clist_filter_rules, deconstify_gpointer(titles));
        if (!RULE_IS_ACTIVE(r))
             gtk_clist_set_foreground(clist_filter_rules, row, color);
        gtk_clist_set_row_data(clist_filter_rules, row, r);
    }
    gtk_clist_thaw(clist_filter_rules);

    gtk_widget_set_sensitive(
        lookup_widget(filter_dialog, "button_filter_clear"),
        count != 0);

    if (gui_debug >= 5)
        g_message("updated %d items\n", count);
}



/**
 * Fetch the rule which is currently edited.
 *
 * @returns a completely new rule_t item in new memory.
 */
rule_t *
filter_gui_get_rule(void)
{
    gint page;
    rule_t *r;

    g_return_val_if_fail(filter_dialog != NULL, NULL);

    page = gtk_notebook_get_current_page
        (GTK_NOTEBOOK
            (lookup_widget(filter_dialog, "notebook_filter_detail")));

    switch (page) {
    case nb_filt_page_buttons:
        r = NULL;
        break;
    case nb_filt_page_text:
        r = filter_gui_get_text_rule();
        break;
    case nb_filt_page_ip:
        r = filter_gui_get_ip_rule();
        break;
    case nb_filt_page_size:
        r = filter_gui_get_size_rule();
        break;
    case nb_filt_page_jump:
        r = filter_gui_get_jump_rule();
        break;
    case nb_filt_page_flag:
        r = filter_gui_get_flag_rule();
        break;
    case nb_filt_page_state:
        r = filter_gui_get_state_rule();
        break;
    default:
        g_assert_not_reached();
        r = NULL;
    };

    if ((r != NULL) && (gui_debug >= 5))
        printf("got rule: %s\n", filter_rule_to_gchar(r));

    return r;
}



/**
 * Extract information about a text rule.
 *
 * @warning NEVER CALL DIRECTLY!!! Use filter_gui_get_rule().
 */
static rule_t *
filter_gui_get_text_rule(void)
{
  	rule_t *r;
    gchar *match;
    gint type;
    gboolean case_sensitive;
    filter_t *target;
    gboolean negate;
    gboolean active;
    gboolean soft;
    guint16 flags;

    g_return_val_if_fail(filter_dialog != NULL, NULL);

	type = (enum rule_text_type)
        GPOINTER_TO_UINT(option_menu_get_selected_data
            (lookup_widget(filter_dialog, "optionmenu_filter_text_type")));

	match = STRTRACK(gtk_editable_get_chars(
        GTK_EDITABLE
            (lookup_widget(filter_dialog, "entry_filter_text_pattern")),
        0, -1));

	case_sensitive = gtk_toggle_button_get_active(
        GTK_TOGGLE_BUTTON
            (lookup_widget(filter_dialog, "checkbutton_filter_text_case")));

	negate = gtk_toggle_button_get_active(
        GTK_TOGGLE_BUTTON
            (lookup_widget
                (filter_dialog, "checkbutton_filter_text_invert_cond")));

	active = gtk_toggle_button_get_active(
        GTK_TOGGLE_BUTTON
            (lookup_widget(filter_dialog, "checkbutton_filter_text_active")));

   	soft = gtk_toggle_button_get_active(
        GTK_TOGGLE_BUTTON
            (lookup_widget(filter_dialog, "checkbutton_filter_text_soft")));

    target = option_menu_get_selected_data(lookup_widget(filter_dialog,
				"optionmenu_filter_text_target"));

    flags =
        (negate ? RULE_FLAG_NEGATE : 0) |
        (active ? RULE_FLAG_ACTIVE : 0) |
        (soft   ? RULE_FLAG_SOFT   : 0);

    r = filter_new_text_rule(match, type, case_sensitive, target, flags);

    G_FREE_NULL(match);

    return r;
}



/**
 * Extract information about a ip rule.
 *
 * @warning NEVER CALL DIRECTLY!!! Use filter_gui_get_rule().
 */
static rule_t *
filter_gui_get_ip_rule(void)
{
    gchar *s;
    guint32 addr;
    guint32 mask;
    filter_t *target;
    gboolean negate;
    gboolean active;
    gboolean soft;
    guint16 flags;

    g_return_val_if_fail(filter_dialog != NULL, NULL);

	s = STRTRACK(gtk_editable_get_chars(
        GTK_EDITABLE
            (lookup_widget(filter_dialog, "entry_filter_ip_address")),
        0, -1));
	addr = ntohl(inet_addr(s));
	G_FREE_NULL(s);

	s = STRTRACK(gtk_editable_get_chars(
        GTK_EDITABLE
            (lookup_widget(filter_dialog, "entry_filter_ip_mask")),
        0, -1));
	mask = ntohl(inet_addr(s));
	G_FREE_NULL(s);

   	negate = gtk_toggle_button_get_active(
        GTK_TOGGLE_BUTTON
            (lookup_widget
                (filter_dialog, "checkbutton_filter_ip_invert_cond")));

	active = gtk_toggle_button_get_active(
        GTK_TOGGLE_BUTTON
            (lookup_widget(filter_dialog, "checkbutton_filter_ip_active")));

   	soft = gtk_toggle_button_get_active(
        GTK_TOGGLE_BUTTON
            (lookup_widget(filter_dialog, "checkbutton_filter_ip_soft")));

    target = option_menu_get_selected_data(lookup_widget(filter_dialog,
					"optionmenu_filter_ip_target"));

    flags =
        (negate ? RULE_FLAG_NEGATE : 0) |
        (active ? RULE_FLAG_ACTIVE : 0) |
        (soft   ? RULE_FLAG_SOFT   : 0);

    return filter_new_ip_rule(addr, mask, target, flags);
}

guint64
filter_update_size(GtkEntry *entry)
{
	const gchar *text = gtk_entry_get_text(entry);
	gchar buf[32];
	guint64 size = 0;
	gint error = 0;
    const gchar *endptr, *p;

	p = skip_ascii_blanks(text);
	size = parse_uint64(p, &endptr, 10, &error);
	p = skip_ascii_blanks(endptr);

	if (!error && *p != '\0') {
		static const char *suffixes[] = {
			"KB",
			"KiB",
			"MB",
			"MiB",
			"GB",
			"GiB",
			"TB",
			"TiB",
			"PB",
			"PiB",
			"EB",
			"EiB",
		};
		guint64 m10 = 1, m2 = 1;
		guint i;

		error = EINVAL;

		for (i = 0; i < G_N_ELEMENTS(suffixes); i++) {
			gboolean base2 = 0 != (i & 1);
			const gchar *q;

			if (base2) {
				m2 *= 1024;
			} else {
				m10 *= 1000;
			}
			q = is_strcaseprefix(p, suffixes[i]);
			if (NULL != q) {
				guint64 v, mp = base2 ? m2 : m10;

				v = size * mp;
				if ((size == 0 || v > size) && size == v / mp) {
					size = v;
					error = 0;
					p = q;
				} else {
					error = ERANGE;
				}
				break;
			}
		}

		p = skip_ascii_blanks(p);
		if (!error && *p != '\0')
			error = EINVAL;
	}

	if (error) {
		size = 0;
	}

	uint64_to_string_buf(size, buf, sizeof buf);
	if (0 != strcmp(buf, text)) {
		gtk_entry_set_text(entry, buf);
	}

	return size;
}

/**
 * Extract information about a size rule.
 *
 * @warning NEVER CALL DIRECTLY!!! Use filter_gui_get_rule().
 */
static rule_t *
filter_gui_get_size_rule(void)
{
    filesize_t lower;
    filesize_t upper;
    filter_t *target;
    gboolean negate;
    gboolean active;
    gboolean soft;
    guint16 flags;

    if (filter_dialog == NULL)
        return NULL;

    lower = filter_update_size(
		GTK_ENTRY(lookup_widget(filter_dialog, "entry_filter_size_min")));

    upper = filter_update_size(
		GTK_ENTRY(lookup_widget(filter_dialog, "entry_filter_size_max")));

	negate = gtk_toggle_button_get_active(
        GTK_TOGGLE_BUTTON
            (lookup_widget
                (filter_dialog, "checkbutton_filter_size_invert_cond")));

	active = gtk_toggle_button_get_active(
        GTK_TOGGLE_BUTTON
            (lookup_widget(filter_dialog, "checkbutton_filter_size_active")));

   	soft = gtk_toggle_button_get_active(
        GTK_TOGGLE_BUTTON
            (lookup_widget(filter_dialog, "checkbutton_filter_size_soft")));

    target = option_menu_get_selected_data(lookup_widget(filter_dialog,
					"optionmenu_filter_size_target"));

    flags =
        (negate ? RULE_FLAG_NEGATE : 0) |
        (active ? RULE_FLAG_ACTIVE : 0) |
        (soft   ? RULE_FLAG_SOFT   : 0);

	if (!upper && lower > 0) {
		/* Special fixup for "minimum size" filters */
		upper = lower - 1;
		lower = 0;
		flags |= RULE_FLAG_NEGATE;
	}

	return filter_new_size_rule(lower, upper, target, flags);
}



/**
 * Extract information about a size rule.
 *
 * @warning NEVER CALL DIRECTLY!!! Use filter_gui_get_rule().
 */
static rule_t *
filter_gui_get_jump_rule(void)
{
    filter_t *target;
    gboolean active;
    guint16 flags;

    if (filter_dialog == NULL)
        return NULL;

	active = gtk_toggle_button_get_active(
        GTK_TOGGLE_BUTTON
            (lookup_widget(filter_dialog, "checkbutton_filter_jump_active")));

    target = option_menu_get_selected_data(lookup_widget(filter_dialog,
					"optionmenu_filter_jump_target"));

    flags = (active ? RULE_FLAG_ACTIVE : 0);

    return filter_new_jump_rule(target, flags);
}



/**
 * Extract information about a flag rule.
 *
 * @warning NEVER CALL DIRECTLY!!! Use filter_gui_get_rule().
 */
static rule_t *
filter_gui_get_flag_rule(void)
{
    filter_t *target;
    enum rule_flag_action stable = 2;
    enum rule_flag_action busy = 2;
    enum rule_flag_action push = 2;
    gboolean active;
    gboolean soft;
    guint16 flags;
    GtkWidget *act;

    if (filter_dialog == NULL)
        return NULL;

    target = option_menu_get_selected_data(lookup_widget(filter_dialog,
					"optionmenu_filter_flag_target"));

    act = radiobutton_get_active_in_group
        (GTK_RADIO_BUTTON(lookup_widget
            (filter_dialog, "radiobutton_filter_flag_stable_set")));
    stable = (enum rule_flag_action)
        GPOINTER_TO_UINT(gtk_object_get_user_data(GTK_OBJECT(act)));

    act = radiobutton_get_active_in_group
        (GTK_RADIO_BUTTON(lookup_widget
            (filter_dialog, "radiobutton_filter_flag_busy_set")));
    busy = (enum rule_flag_action)
        GPOINTER_TO_UINT(gtk_object_get_user_data(GTK_OBJECT(act)));

    act = radiobutton_get_active_in_group
        (GTK_RADIO_BUTTON(lookup_widget
            (filter_dialog, "radiobutton_filter_flag_push_set")));
    push = (enum rule_flag_action)
        GPOINTER_TO_UINT(gtk_object_get_user_data(GTK_OBJECT(act)));

    active = gtk_toggle_button_get_active
        (GTK_TOGGLE_BUTTON
            (lookup_widget(filter_dialog, "checkbutton_filter_flag_active")));

    soft = gtk_toggle_button_get_active
        (GTK_TOGGLE_BUTTON
            (lookup_widget(filter_dialog, "checkbutton_filter_flag_soft")));

    flags = (active ? RULE_FLAG_ACTIVE : 0) |
            (soft   ? RULE_FLAG_SOFT   : 0);

    return filter_new_flag_rule(stable, busy, push, target, flags);
}



/**
 * Extract information about a state rule.
 *
 * @warning NEVER CALL DIRECTLY!!! Use filter_gui_get_rule().
 */
static rule_t *
filter_gui_get_state_rule(void)
{
    filter_t *target;
    enum filter_prop_state display  = FILTER_PROP_STATE_IGNORE;
    enum filter_prop_state download = FILTER_PROP_STATE_IGNORE;
    gboolean active;
    gboolean soft;
    gboolean negate;
    guint16 flags;
    GtkWidget *act;

    if (filter_dialog == NULL)
        return NULL;

    target = option_menu_get_selected_data(lookup_widget(filter_dialog,
					"optionmenu_filter_state_target"));

    act = radiobutton_get_active_in_group
        (GTK_RADIO_BUTTON(lookup_widget
            (filter_dialog, "radiobutton_filter_state_display_do")));
    display = (enum filter_prop_state)
        GPOINTER_TO_UINT(gtk_object_get_user_data(GTK_OBJECT(act)));

    act = radiobutton_get_active_in_group
        (GTK_RADIO_BUTTON(lookup_widget
            (filter_dialog, "radiobutton_filter_state_download_do")));
    download = (enum filter_prop_state)
        GPOINTER_TO_UINT(gtk_object_get_user_data(GTK_OBJECT(act)));

    active = gtk_toggle_button_get_active
        (GTK_TOGGLE_BUTTON(lookup_widget
            (filter_dialog, "checkbutton_filter_state_active")));

    soft = gtk_toggle_button_get_active
        (GTK_TOGGLE_BUTTON(lookup_widget
            (filter_dialog, "checkbutton_filter_state_soft")));

    negate = gtk_toggle_button_get_active
        (GTK_TOGGLE_BUTTON(lookup_widget
            (filter_dialog, "checkbutton_filter_state_invert_cond")));

    flags = (active ? RULE_FLAG_ACTIVE : 0) |
            (soft   ? RULE_FLAG_SOFT   : 0) |
            (negate ? RULE_FLAG_NEGATE : 0);

    return filter_new_state_rule(display, download, target, flags);
}

void
filter_gui_freeze_rules(void)
{
    if (filter_dialog == NULL)
        return;

    gtk_clist_freeze
        (GTK_CLIST(lookup_widget(filter_dialog, "clist_filter_rules")));
}

void
filter_gui_thaw_rules(void)
{
    if (filter_dialog == NULL)
        return;

    gtk_clist_thaw
        (GTK_CLIST(lookup_widget(filter_dialog, "clist_filter_rules")));
}

void
filter_gui_freeze_filters(void)
{
    if (filter_dialog == NULL)
        return;

    gtk_clist_freeze
        (GTK_CLIST(lookup_widget(filter_dialog, "ctree_filter_filters")));
}

void
filter_gui_thaw_filters(void)
{
    if (filter_dialog == NULL)
        return;

    gtk_clist_thaw
        (GTK_CLIST(lookup_widget(filter_dialog, "ctree_filter_filters")));
}

#ifdef USE_GTK2

/**
 * Handles filter dialog UI joining.
 *
 * Creates all dependent "tab" windows and merges them into
 * the rules notebook.
 *
 */
GtkWidget *
filter_gui_create_dlg_filters(void)
{
	GtkWidget *dialog;
    GtkWidget *notebook;
    GtkWidget *tab_window[nb_filt_page_num];
    gint i ;

    /*
     * First create the filter dialog without the tab contents.
     */

    dialog = create_dlg_filters();
    notebook = lookup_widget(dialog, "notebook_filter_detail");

    /*
     * Then create all the tabs in their own window.
     */
	tab_window[nb_filt_page_buttons] = create_dlg_filters_add_tab();
	tab_window[nb_filt_page_text] = create_dlg_filters_text_tab();
	tab_window[nb_filt_page_ip] = create_dlg_filters_ip_tab();
	tab_window[nb_filt_page_size] = create_dlg_filters_size_tab();
	tab_window[nb_filt_page_jump] = create_dlg_filters_jump_tab();
	tab_window[nb_filt_page_sha1] = create_dlg_filters_sha1_tab();
	tab_window[nb_filt_page_flag] = create_dlg_filters_flags_tab();
	tab_window[nb_filt_page_state] = create_dlg_filters_state_tab();

    /*
     * Merge the UI and destroy the source windows.
     */
    for (i = 0; i < nb_filt_page_num; i++) {
        GtkWidget *w = tab_window[i];
        gui_merge_window_as_tab(dialog, notebook, w);
        gtk_object_destroy(GTK_OBJECT(w));
    }

    /*
     * Get rid of the first (dummy) notebook tab.
     * (My glade seems to require a tab to be defined in the notebook
     * as a placeholder, or it creates _two_ unlabeled tabs at runtime).
     */
    gtk_container_remove(GTK_CONTAINER(notebook),
        gtk_notebook_get_nth_page(GTK_NOTEBOOK(notebook), 0));

	return dialog;
}
#endif	/* USE_GTK2 */

/* vi: set ts=4 sw=4 cindent: */
