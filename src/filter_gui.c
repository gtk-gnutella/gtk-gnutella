/*
 * Copyright (c) 2001-2002, Raphael Manfredi, Richard Eckart
 *
 * GUI filtering functions.
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

/*
 * For ntohl and inet_addr
 */
#include <netinet/in.h> 
#include <arpa/inet.h>


#include "gnutella.h"
#include "filter_gui.h"
#include "misc.h"
#include "interface.h"
#include "gtk-missing.h"


#define DEFAULT_TARGET (filter_get_drop_target())   


/*
 * Public variables
 */
GtkWidget *filter_dialog = NULL;



/*
 * Private variables
 */
static gchar * rule_text_type_labels[] = {
    "starts with",
    "contains the words",
    "ends with",
    "contains the substring",
    "matches regex",
    "is exactly"
};

static gchar fg_tmp[1024];
static GtkCTreeNode *fl_node_global = NULL;
static GtkCTreeNode *fl_node_bound = NULL;
static GtkCTreeNode *fl_node_free = NULL;



/*
 * Private functions prototypes
 */
static rule_t *filter_gui_get_text_rule();
static rule_t *filter_gui_get_ip_rule();
static rule_t *filter_gui_get_size_rule();
static rule_t *filter_gui_get_jump_rule();
static rule_t *filter_gui_get_flag_rule();
static GtkCTreeNode *getFilterRoot(filter_t *f);



/*
 * getFilterRoot:
 *
 * Fetch the proper root node for a given filter in the filter tree.
 */
static GtkCTreeNode *getFilterRoot(filter_t *f)
{
    if (filter_is_global(f)) {
          return fl_node_global;
    } else if (filter_is_bound(f)) {
          return fl_node_bound;
    } else {
          return fl_node_free;
    }
}

/*
 * filter_gui_init:
 *
 * Initialize the contents of the dialog editor and some 
 * internal variables like the roots in the filter list etc.
 */
void filter_gui_init(void)
{
    GtkMenu *m;
    gint i;

    gtk_notebook_set_show_tabs
        (GTK_NOTEBOOK(notebook_filter_detail), FALSE);

    gtk_clist_set_reorderable(GTK_CLIST(clist_filter_rules), TRUE);
    for (i = 0; i < 4; i++)
        gtk_clist_set_column_width(GTK_CLIST(clist_filter_rules), i,
            filter_table_col_widths[i]);

    for (i = 0; i < 3; i++)
        gtk_clist_set_column_width(GTK_CLIST(ctree_filter_filters), i,
            filter_filters_col_widths[i]);

    m = GTK_MENU(gtk_menu_new());
    menu_new_item_with_data(
        m, rule_text_type_labels[RULE_TEXT_PREFIX], 
        (gpointer) RULE_TEXT_PREFIX);
    menu_new_item_with_data(
        m, rule_text_type_labels[RULE_TEXT_WORDS], 
        (gpointer) RULE_TEXT_WORDS);
    menu_new_item_with_data(
        m, rule_text_type_labels[RULE_TEXT_SUFFIX], 
        (gpointer)RULE_TEXT_SUFFIX);
    menu_new_item_with_data(
        m, rule_text_type_labels[RULE_TEXT_SUBSTR], 
        (gpointer) RULE_TEXT_SUBSTR);
    menu_new_item_with_data(
        m, rule_text_type_labels[RULE_TEXT_REGEXP], 
        (gpointer) RULE_TEXT_REGEXP);
    menu_new_item_with_data(
        m, rule_text_type_labels[RULE_TEXT_EXACT], 
        (gpointer) RULE_TEXT_EXACT);

    gtk_option_menu_set_menu
        (GTK_OPTION_MENU(optionmenu_filter_text_type), GTK_WIDGET(m));

    m = GTK_MENU(gtk_menu_new());
        menu_new_item_with_data(m, "display", 
        (gpointer) FILTER_PROP_STATE_DO);
    menu_new_item_with_data(m, "don't display", 
        (gpointer) FILTER_PROP_STATE_DONT);
    gtk_option_menu_set_menu
        (GTK_OPTION_MENU(optionmenu_filter_default_policy), GTK_WIDGET(m));
}



/*
 * filter_gui_show_dialog:
 *
 * Show the dialog on screen and set position.
 */
void filter_gui_show_dialog(void)
{
  	gtk_window_set_default_size(GTK_WINDOW(filter_dialog), 
        flt_dlg_w, flt_dlg_h);

    gtk_paned_set_position(GTK_PANED(hpaned_filter_main),
                           filter_main_divider_pos);    

    gtk_widget_show(filter_dialog);
    gdk_window_raise(filter_dialog->window);
}



/*
 * filter_gui_filter_clear_list:
 *
 * Remove all entries from the filter tree.
 */
void filter_gui_filter_clear_list(void)
{
    gchar *titles[3];

    if (fl_node_global != NULL)
        gtk_ctree_remove_node(GTK_CTREE(ctree_filter_filters),
            fl_node_global);
    if (fl_node_bound != NULL)
        gtk_ctree_remove_node(GTK_CTREE(ctree_filter_filters),
            fl_node_bound);
    if (fl_node_free != NULL)
        gtk_ctree_remove_node(GTK_CTREE(ctree_filter_filters),
            fl_node_free);

    titles[0] = "Global filters";
    titles[1] = "";
    titles[2] = "";
    fl_node_global = gtk_ctree_insert_node(
        GTK_CTREE(ctree_filter_filters), NULL, NULL,
        titles, 0, NULL, NULL, NULL, NULL, FALSE, TRUE);
            
    titles[0] = "Search filters";
    fl_node_bound = gtk_ctree_insert_node(
        GTK_CTREE(ctree_filter_filters), NULL, NULL,
        titles, 0, NULL, NULL, NULL, NULL, FALSE, TRUE);

    titles[0] = "Free filters";
    fl_node_free = gtk_ctree_insert_node(
        GTK_CTREE(ctree_filter_filters), NULL, NULL,
        titles, 0, NULL, NULL, NULL, NULL, FALSE, TRUE);
}



/*
 * filter_gui_filter_add:
 *
 * Adds a filter to the filter list in the dialog. If the filter has a
 * shadow, shadow->current should be set as ruleset. If ruleset is NULL,
 * default to filter->ruleset.
 */
void filter_gui_filter_add(filter_t *f, GList *ruleset)
{
    g_assert(f != NULL);

    if (ruleset == NULL)
        ruleset = f->ruleset;

    if (filter_dialog != NULL) {
        gchar *titles[3];
        GtkCTreeNode *node;
        GtkCTreeNode *parent;
        guint buf;
            
        titles[0] = f->name;
        g_snprintf(fg_tmp, sizeof(fg_tmp), "%d", g_list_length(ruleset));
        titles[1] = g_strdup(fg_tmp);
        buf = f->match_count+f->fail_count;
        if (buf != 0) {
            g_snprintf(fg_tmp, sizeof(fg_tmp), "%d/%d (%d%%)",
                f->match_count, buf, 
                (gint)((float)f->match_count/buf*100));
            titles[2] = fg_tmp;
        } else {
            titles[2] = "...";
        }

        parent = getFilterRoot(f);

        node = gtk_ctree_insert_node(
            GTK_CTREE(ctree_filter_filters), parent, NULL, titles,
            0, NULL, NULL, NULL, NULL, TRUE, TRUE);
        gtk_ctree_node_set_row_data
            (GTK_CTREE(ctree_filter_filters), node, (gpointer) f);
    
        g_free(titles[1]);
    }
}



/*
 * filter_gui_update_rule_count:
 *
 * Update the rule count of a filter in the filter table.
 */
void filter_gui_update_rule_count(filter_t *f, GList *ruleset)
{
    g_assert(f != NULL);

    if (filter_dialog != NULL) {
        GtkCTreeNode *parent;
        GtkCTreeNode *node;
        
        parent = getFilterRoot(f);
        node = gtk_ctree_find_by_row_data
            (GTK_CTREE(ctree_filter_filters), parent, f);

        if (node != NULL) {
            g_snprintf(fg_tmp, sizeof(fg_tmp), "%d", g_list_length(ruleset));
            gtk_ctree_node_set_text(GTK_CTREE(ctree_filter_filters), node,
                1, fg_tmp);
        }
    }
}



/*
 * filter_gui_filter_remove:
 *
 * Removes a filter from the list in the dialog.
 */
void filter_gui_filter_remove(filter_t *f)
{
    g_assert(f != NULL);

    if (filter_dialog != NULL) {
        GtkCTreeNode *parent;
        GtkCTreeNode *node;
        
        parent = getFilterRoot(f);
        node = gtk_ctree_find_by_row_data
            (GTK_CTREE(ctree_filter_filters), parent, f);
        if (node != NULL)
            gtk_ctree_remove_node(GTK_CTREE(ctree_filter_filters), node);
    }
}



/*
 * filter_gui_set_filter:
 *
 * Don't use this directly. Better use filter_set from filter.c.
 * Tell the gui to set itself up to work on the given filter.
 * The information about removeable/active state and ruleset are not
 * taken from the filter!
 * Note: this does not rebuild the target combos.
 */
void filter_gui_filter_set
    (filter_t *f, gboolean removable, gboolean active, GList *ruleset)
{
    if (filter_dialog == NULL)
        return;

    filter_gui_edit_rule(NULL);

    work_filter = f;

    if (f != NULL) {
        gtk_widget_set_sensitive(checkbutton_filter_enabled, TRUE);
        gtk_widget_set_sensitive(button_filter_reset, TRUE);
        gtk_widget_set_sensitive(button_filter_add_rule_text, TRUE);
        gtk_widget_set_sensitive(button_filter_add_rule_ip, TRUE);
        gtk_widget_set_sensitive(button_filter_add_rule_size, TRUE);
        gtk_widget_set_sensitive(button_filter_add_rule_jump, TRUE);
        gtk_widget_set_sensitive(button_filter_add_rule_flag, TRUE);
        gtk_widget_set_sensitive(button_filter_remove, removable);
        gtk_toggle_button_set_active(
            GTK_TOGGLE_BUTTON(checkbutton_filter_enabled),
            active);
        gtk_entry_set_text(GTK_ENTRY(entry_filter_name), f->name);

        filter_gui_filter_set_enabled(f, active);

        if (dbg >= 5)
            printf("showing ruleset for filter: %s\n", f->name);
        filter_gui_set_ruleset(ruleset);
    } else {
        gtk_entry_set_text(GTK_ENTRY(entry_filter_name), "");
        filter_gui_set_ruleset(NULL);
        filter_gui_filter_set_enabled(NULL, FALSE);

        gtk_widget_set_sensitive(checkbutton_filter_enabled, FALSE);
        gtk_widget_set_sensitive(button_filter_reset, FALSE);
        gtk_widget_set_sensitive(button_filter_add_rule_text, FALSE);
        gtk_widget_set_sensitive(button_filter_add_rule_ip, FALSE);
        gtk_widget_set_sensitive(button_filter_add_rule_size, FALSE);
        gtk_widget_set_sensitive(button_filter_add_rule_jump, FALSE);
        gtk_widget_set_sensitive(button_filter_add_rule_flag, FALSE);
        gtk_widget_set_sensitive(button_filter_remove, FALSE);
        gtk_toggle_button_set_active(
            GTK_TOGGLE_BUTTON(checkbutton_filter_enabled), FALSE);
    }
}



/*
 * filter_gui_filter_set_enabled:
 *
 * Tell the gui a given filter is enabled/disabled. If the filter given
 * is NULL, then the widget will be set insensitive and inactive.
 */
void filter_gui_filter_set_enabled(filter_t *f, gboolean active)
{
    GtkCTreeNode *node;
    GtkCTreeNode *parent;
    GdkColor *color;

    if (filter_dialog == NULL)
        return;

    gtk_widget_set_sensitive(GTK_WIDGET(checkbutton_filter_enabled),
        f != NULL);

    if (f == NULL) {
        gtk_toggle_button_set_active
            (GTK_TOGGLE_BUTTON(checkbutton_filter_enabled), FALSE);
        return;
    }

    if (f == work_filter)
        gtk_toggle_button_set_active
            (GTK_TOGGLE_BUTTON(checkbutton_filter_enabled), active);

    parent = getFilterRoot(f);

    node = gtk_ctree_find_by_row_data
        (GTK_CTREE(ctree_filter_filters), parent, f);


    color = active ? NULL : 
        &(gtk_widget_get_style(GTK_WIDGET(ctree_filter_filters))
            ->bg[GTK_STATE_INSENSITIVE]);

    gtk_ctree_node_set_foreground(GTK_CTREE(ctree_filter_filters),
        node, color);
}



/*
 * filter_gui_update_filters_stats:
 *
 * Update the filter list with the current stats data from the filters
 */
void filter_gui_update_filter_stats(void)
{
    gint row;

    if (filter_dialog == NULL)
        return;

    gtk_clist_freeze(GTK_CLIST(ctree_filter_filters));

    for (row = 0; row < GTK_CLIST(ctree_filter_filters)->rows; row ++) {
        gchar *title;
        filter_t *filter;
        GtkCTreeNode *node;
        gint buf;
    
        node = gtk_ctree_node_nth(GTK_CTREE(ctree_filter_filters), row);
        filter = gtk_ctree_node_get_row_data
            (GTK_CTREE(ctree_filter_filters), node);

        if (filter == NULL)
            continue;

        if (filter_is_shadowed(filter)) {
            title = "new";
        } else {
            buf = filter->match_count+filter->fail_count;
            if (buf != 0) {
                g_snprintf(fg_tmp, sizeof(fg_tmp), "%d/%d (%d%%)",
                    filter->match_count, buf, 
                    (gint)((float)filter->match_count/buf*100));
                title = fg_tmp;
            } else {
                title = "none yet";
            }
        }

        gtk_ctree_node_set_text(
            GTK_CTREE(ctree_filter_filters), node, 2, title);
    }

    gtk_clist_thaw(GTK_CLIST(ctree_filter_filters));
}



/*
 * filter_gui_update_rules_stats:
 *
 * Update the rules list with the current stats data from the rules
 */
void filter_gui_update_rule_stats(void)
{
    gint row;

    if ((filter_dialog == NULL) || (work_filter == NULL))
        return;

    gtk_clist_freeze(GTK_CLIST(clist_filter_rules));
        
    for (row = 0; row < GTK_CLIST(clist_filter_rules)->rows; row ++) {
        gchar *title;
        rule_t *rule;
        gint buf;
    
        rule = (rule_t *) gtk_clist_get_row_data
            (GTK_CLIST(clist_filter_rules), row);

        if (rule == NULL)
            continue;

        if (RULE_IS_SHADOWED(rule)) {
            title = "new";
        } else {
            buf = rule->match_count+rule->fail_count;
            if (buf != 0) {
                g_snprintf(fg_tmp, sizeof(fg_tmp), "%d/%d (%d%%)",
                    rule->match_count, buf, 
                    (gint)((float)rule->match_count/buf*100));
                title = fg_tmp;
            } else {
                title = "none yet";
            }
        }

        gtk_clist_set_text(GTK_CLIST(clist_filter_rules), row, 3, title);
    }

    gtk_clist_thaw(GTK_CLIST(clist_filter_rules));
}



void filter_gui_rebuild_target_combos(GList *filters)
{
    GtkMenu *m;
    GList *l;
    GList *buf = NULL;
    GtkWidget *opt_menus[] = {
        optionmenu_filter_text_target,
        optionmenu_filter_ip_target,
        optionmenu_filter_size_target,
        optionmenu_filter_jump_target,
        optionmenu_filter_sha1_target,
        optionmenu_filter_flag_target,
        NULL };
    gpointer bufptr;
    gint i;
    
    /*
     * Prepare a list of unbound filters and also leave
     * out the global and builtin filters.
     */
    for (l = filters; l != NULL; l = l->next) {
        filter_t *filter = (filter_t *)l->data;

        if (!filter_is_bound(filter) && !filter_is_global(filter))
            buf = g_list_append(buf, filter);
    }

    /*
     * These can only be updated if there is a dialog.
     */
    if (filter_dialog != NULL) {
        for (i = 0; opt_menus[i] != NULL; i ++) {
            m = GTK_MENU(gtk_menu_new());
    
            for (l = buf; l != NULL; l = l->next) {
                filter_t *filter = (filter_t *)l->data;
                if (filter != work_filter)
                    menu_new_item_with_data(m, filter->name, filter);
            }
    
            gtk_option_menu_set_menu
                (GTK_OPTION_MENU(opt_menus[i]), GTK_WIDGET(m));
        }
    }

    /*
     * The following is in the main window and should always be
     * updateable.
     */
    bufptr = option_menu_get_selected_data(optionmenu_search_filter);

    m = GTK_MENU(gtk_menu_new());

    menu_new_item_with_data(m, "no default filter", NULL);
    for (l = buf; l != NULL; l = l->next) {
        filter_t *filter = (filter_t *)l->data;
        /*
         * This is no need to create a query which should not
         * display anything, also we can't advertise a filter
         * as target that does not really exist yet.
         */
        if (!filter_is_builtin(filter) && !filter_is_shadowed(filter))
            menu_new_item_with_data(m, filter->name, filter);
    }

    gtk_option_menu_set_menu
        (GTK_OPTION_MENU(optionmenu_search_filter), GTK_WIDGET(m));

    option_menu_select_item_by_data(optionmenu_search_filter, bufptr);

    g_list_free(buf);
}



/*
 * filter_gui_set_default_policy:
 *
 * Display the given filter as default policy in the gui.
 */
void filter_gui_set_default_policy(gint pol)
{
    option_menu_select_item_by_data(
        optionmenu_filter_default_policy, 
        (gpointer) pol);
}



/*
 * filter_gui_edit_rule:
 *
 * Load the given rule into the detail view.
 */
void filter_gui_edit_rule(rule_t *r)
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
        default:
            g_error("Unknown rule type: %d", r->type);
        }
    } else {
        gtk_notebook_set_page(
            GTK_NOTEBOOK(notebook_filter_detail),
            nb_filt_page_buttons);
        gtk_clist_unselect_all(GTK_CLIST(clist_filter_rules));
    }
}



/*
 * filter_gui_edit_ip_rule:
 *
 * Load a ip rule into the rule edtior or clear it if the rule is NULL.
 */
void filter_gui_edit_ip_rule(rule_t *r)
{
    g_assert((r == NULL) ||(r->type == RULE_IP));

    if (filter_dialog == NULL)
        return;

    if (r == NULL) {
        gtk_entry_set_text(GTK_ENTRY(entry_filter_ip_address), "");
        gtk_entry_set_text(GTK_ENTRY(entry_filter_ip_mask), "255.255.255.255");
        option_menu_select_item_by_data(optionmenu_filter_ip_target,
            (gpointer) DEFAULT_TARGET);
        gtk_toggle_button_set_active
            (GTK_TOGGLE_BUTTON(checkbutton_filter_ip_invert_cond), FALSE);
        gtk_toggle_button_set_active
            (GTK_TOGGLE_BUTTON(checkbutton_filter_ip_active), TRUE);
        gtk_toggle_button_set_active
            (GTK_TOGGLE_BUTTON(checkbutton_filter_ip_soft), FALSE);
    } else {
        gtk_entry_set_text(
            GTK_ENTRY(entry_filter_ip_address), 
            ip_to_gchar(r->u.ip.addr));
        gtk_entry_set_text(
            GTK_ENTRY(entry_filter_ip_mask),
            ip_to_gchar(r->u.ip.mask));
        option_menu_select_item_by_data(optionmenu_filter_ip_target,
            (gpointer) r->target);
        gtk_toggle_button_set_active
            (GTK_TOGGLE_BUTTON(checkbutton_filter_ip_invert_cond),
            RULE_IS_NEGATED(r));
        gtk_toggle_button_set_active
            (GTK_TOGGLE_BUTTON(checkbutton_filter_ip_active),
            RULE_IS_ACTIVE(r));
        gtk_toggle_button_set_active
            (GTK_TOGGLE_BUTTON(checkbutton_filter_ip_soft),
            RULE_IS_SOFT(r));
    }

    gtk_notebook_set_page(
        GTK_NOTEBOOK(notebook_filter_detail),
        nb_filt_page_ip);
}



/*
 * filter_gui_edit_sha1_rule:
 *
 * Load a sha1 rule into the rule edtior or clear it if the rule is NULL.
 */
void filter_gui_edit_sha1_rule(rule_t *r)
{
    g_assert((r == NULL) ||(r->type == RULE_SHA1));

    if (filter_dialog == NULL)
        return;

    if (r == NULL) {
        gtk_entry_set_text(GTK_ENTRY(entry_filter_sha1_hash), "");
        gtk_entry_set_text(GTK_ENTRY(entry_filter_sha1_origfile), "");
        option_menu_select_item_by_data(optionmenu_filter_sha1_target,
            (gpointer) DEFAULT_TARGET);
        gtk_toggle_button_set_active
            (GTK_TOGGLE_BUTTON(checkbutton_filter_sha1_invert_cond), FALSE);
        gtk_toggle_button_set_active
            (GTK_TOGGLE_BUTTON(checkbutton_filter_sha1_active), TRUE);
        gtk_toggle_button_set_active
            (GTK_TOGGLE_BUTTON(checkbutton_filter_sha1_soft), FALSE);
    } else {
        gchar *hash_str;

        hash_str = (r->u.sha1.hash != NULL) ? 
            sha1_base32(r->u.sha1.hash) : "";

        gtk_entry_set_text(GTK_ENTRY(entry_filter_sha1_hash), hash_str);
        gtk_entry_set_text
            (GTK_ENTRY(entry_filter_sha1_origfile), r->u.sha1.filename);
        option_menu_select_item_by_data(optionmenu_filter_sha1_target,
            (gpointer) r->target);
        gtk_toggle_button_set_active
            (GTK_TOGGLE_BUTTON(checkbutton_filter_sha1_invert_cond),
            RULE_IS_NEGATED(r));
        gtk_toggle_button_set_active
            (GTK_TOGGLE_BUTTON(checkbutton_filter_sha1_active),
            RULE_IS_ACTIVE(r));
        gtk_toggle_button_set_active
            (GTK_TOGGLE_BUTTON(checkbutton_filter_sha1_soft),
            RULE_IS_SOFT(r));
    }

    gtk_notebook_set_page(
        GTK_NOTEBOOK(notebook_filter_detail),
        nb_filt_page_sha1);
}



/*
 * filter_gui_edit_text_rule:
 *
 * Load a ip rule into the rule edtior or clear it if the rule is NULL.
 */

void filter_gui_edit_text_rule(rule_t *r) 
{
    g_assert((r == NULL) || (r->type == RULE_TEXT));

    if (filter_dialog == NULL)
        return;

    if (r == NULL) {
        gtk_entry_set_text(
            GTK_ENTRY(entry_filter_text_pattern),
            "");
        gtk_toggle_button_set_active(
            GTK_TOGGLE_BUTTON(checkbutton_filter_text_case),
            FALSE);
        gtk_option_menu_set_history(
            GTK_OPTION_MENU(optionmenu_filter_text_type),
            RULE_TEXT_WORDS);
        option_menu_select_item_by_data(optionmenu_filter_text_target,
            (gpointer) DEFAULT_TARGET);
        gtk_toggle_button_set_active
            (GTK_TOGGLE_BUTTON(checkbutton_filter_text_invert_cond), FALSE);
        gtk_toggle_button_set_active
            (GTK_TOGGLE_BUTTON(checkbutton_filter_text_active), TRUE);
        gtk_toggle_button_set_active
            (GTK_TOGGLE_BUTTON(checkbutton_filter_text_soft), FALSE);
    } else {
        gtk_entry_set_text(
            GTK_ENTRY(entry_filter_text_pattern),
            r->u.text.match);
        gtk_toggle_button_set_active(
            GTK_TOGGLE_BUTTON(checkbutton_filter_text_case),
            r->u.text.case_sensitive);
        gtk_option_menu_set_history(
            GTK_OPTION_MENU(optionmenu_filter_text_type),
            r->u.text.type);
        option_menu_select_item_by_data(optionmenu_filter_text_target,
            (gpointer) r->target);
        gtk_toggle_button_set_active
            (GTK_TOGGLE_BUTTON(checkbutton_filter_text_invert_cond),
            RULE_IS_NEGATED(r));
        gtk_toggle_button_set_active
            (GTK_TOGGLE_BUTTON(checkbutton_filter_text_active),
            RULE_IS_ACTIVE(r));
        gtk_toggle_button_set_active
            (GTK_TOGGLE_BUTTON(checkbutton_filter_text_soft),
            RULE_IS_SOFT(r));
    }

    gtk_notebook_set_page(
        GTK_NOTEBOOK(notebook_filter_detail),
         nb_filt_page_text);
}



/*
 * filter_gui_edit_size_rule:
 *
 * Load a ip rule into the rule edtior or clear it if the rule is NULL.
 */
void filter_gui_edit_size_rule(rule_t *r)
{
    g_assert((r == NULL) || (r->type == RULE_SIZE));

    if (filter_dialog == NULL)
        return;

    if (r == NULL) {
        gtk_spin_button_set_value(
            GTK_SPIN_BUTTON(spinbutton_filter_size_min), 
            0);
        gtk_spin_button_set_value(
            GTK_SPIN_BUTTON(spinbutton_filter_size_max),
            0);
        option_menu_select_item_by_data(optionmenu_filter_size_target,
            (gpointer) DEFAULT_TARGET);
        gtk_toggle_button_set_active
            (GTK_TOGGLE_BUTTON(checkbutton_filter_size_invert_cond), FALSE);
        gtk_toggle_button_set_active
            (GTK_TOGGLE_BUTTON(checkbutton_filter_size_active), TRUE);
        gtk_toggle_button_set_active
            (GTK_TOGGLE_BUTTON(checkbutton_filter_size_soft), FALSE);
    } else {
        gtk_spin_button_set_value(
            GTK_SPIN_BUTTON(spinbutton_filter_size_min), 
            r->u.size.lower);
        gtk_spin_button_set_value(
            GTK_SPIN_BUTTON(spinbutton_filter_size_max),
            r->u.size.upper);
        option_menu_select_item_by_data(optionmenu_filter_size_target,
            (gpointer) r->target);
        gtk_toggle_button_set_active
            (GTK_TOGGLE_BUTTON(checkbutton_filter_size_invert_cond),
            RULE_IS_NEGATED(r));
        gtk_toggle_button_set_active
            (GTK_TOGGLE_BUTTON(checkbutton_filter_size_active),
            RULE_IS_ACTIVE(r));
        gtk_toggle_button_set_active
            (GTK_TOGGLE_BUTTON(checkbutton_filter_size_soft),
            RULE_IS_SOFT(r));
    }

    gtk_notebook_set_page(
        GTK_NOTEBOOK(notebook_filter_detail),
        nb_filt_page_size);
}



/*
 * filter_gui_edit_jump_rule:
 *
 * Load a ip rule into the rule edtior or clear it if the rule is NULL.
 */


void filter_gui_edit_jump_rule(rule_t *r)
{
    g_assert((r == NULL) || (r->type == RULE_JUMP));

    if (filter_dialog == NULL)
        return;

    if (r == NULL) {
        option_menu_select_item_by_data(optionmenu_filter_jump_target,
            (gpointer) DEFAULT_TARGET);
        gtk_toggle_button_set_active
            (GTK_TOGGLE_BUTTON(checkbutton_filter_jump_active), TRUE);
   } else {
        option_menu_select_item_by_data(optionmenu_filter_jump_target,
            (gpointer) r->target);
        gtk_toggle_button_set_active
            (GTK_TOGGLE_BUTTON(checkbutton_filter_jump_active),
            RULE_IS_ACTIVE(r));
    }

    gtk_notebook_set_page(
        GTK_NOTEBOOK(notebook_filter_detail),
        nb_filt_page_jump);
}



/*
 * filter_gui_edit_flag_rule:
 *
 * Load a flag rule into the rule edtior or clear it if the rule is NULL.
 */


void filter_gui_edit_flag_rule(rule_t *r)
{
    g_assert((r == NULL) || (r->type == RULE_FLAG));

    if (filter_dialog == NULL)
        return;

    if (r == NULL) {
        gtk_toggle_button_set_active
            (GTK_TOGGLE_BUTTON(radiobutton_filter_flag_stable_ignore), TRUE);
        gtk_toggle_button_set_active
            (GTK_TOGGLE_BUTTON(radiobutton_filter_flag_busy_ignore), TRUE);
        gtk_toggle_button_set_active
            (GTK_TOGGLE_BUTTON(radiobutton_filter_flag_push_ignore), TRUE);
        option_menu_select_item_by_data(optionmenu_filter_flag_target,
            (gpointer) DEFAULT_TARGET);
        gtk_toggle_button_set_active
            (GTK_TOGGLE_BUTTON(checkbutton_filter_flag_active), TRUE);
        gtk_toggle_button_set_active
            (GTK_TOGGLE_BUTTON(checkbutton_filter_flag_soft), FALSE);
   } else {
        GtkWidget *tb = NULL;

        switch (r->u.flag.stable) {
        case RULE_FLAG_SET:
            tb = radiobutton_filter_flag_stable_set;
            break;
        case RULE_FLAG_UNSET:
            tb = radiobutton_filter_flag_stable_unset;
            break;
        case RULE_FLAG_IGNORE:
            tb = radiobutton_filter_flag_stable_ignore;
            break;
        default:
            g_assert_not_reached();
        }
        gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(tb), TRUE);

        switch (r->u.flag.busy) {
        case RULE_FLAG_SET:
            tb = radiobutton_filter_flag_busy_set;
            break;
        case RULE_FLAG_UNSET:
            tb = radiobutton_filter_flag_busy_unset;
            break;
        case RULE_FLAG_IGNORE:
            tb = radiobutton_filter_flag_busy_ignore;
            break;
        default:
            g_assert_not_reached();
        }
        gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(tb), TRUE);

        switch (r->u.flag.push) {
        case RULE_FLAG_SET:
            tb = radiobutton_filter_flag_push_set;
            break;
        case RULE_FLAG_UNSET:
            tb = radiobutton_filter_flag_push_unset;
            break;
        case RULE_FLAG_IGNORE:
            tb = radiobutton_filter_flag_push_ignore;
            break;
        default:
            g_assert_not_reached();
        }
        gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(tb), TRUE);

        option_menu_select_item_by_data(optionmenu_filter_jump_target,
            (gpointer) r->target);
        gtk_toggle_button_set_active
            (GTK_TOGGLE_BUTTON(checkbutton_filter_flag_active),
            RULE_IS_ACTIVE(r));
        gtk_toggle_button_set_active
            (GTK_TOGGLE_BUTTON(checkbutton_filter_flag_soft),
            RULE_IS_SOFT(r));
    }

    gtk_notebook_set_page
        (GTK_NOTEBOOK(notebook_filter_detail), nb_filt_page_flag);
}



/*
 * filter_gui_set_ruleset:
 *
 * Display the given ruleset in the table.
 */
void filter_gui_set_ruleset(GList *ruleset)
{
    GList *l;
    gint count = 0;
    GdkColor *color;

    if (filter_dialog == NULL)
        return;

    gtk_clist_freeze(GTK_CLIST(clist_filter_rules));
    gtk_clist_clear(GTK_CLIST(clist_filter_rules));

    color = &(gtk_widget_get_style(GTK_WIDGET(clist_filter_rules))
                ->bg[GTK_STATE_INSENSITIVE]);

    gtk_widget_set_sensitive
        (GTK_WIDGET(button_filter_reset_all_rules), ruleset != NULL);
        
    for (l = ruleset; l != NULL; l = l->next) {
        rule_t *r = (rule_t *)l->data;
        gchar *titles[4];
        gint row;

        g_assert(r != NULL);
        count ++;
        titles[0] = RULE_IS_NEGATED(r) ? "X" : "";
        titles[1] = filter_rule_condition_to_gchar(r);
        titles[2] = r->target->name;
        titles[3] = "...";
        
        row = gtk_clist_append(GTK_CLIST(clist_filter_rules), titles);
        if (!RULE_IS_ACTIVE(r))
             gtk_clist_set_foreground(GTK_CLIST(clist_filter_rules), row,
                color);
        gtk_clist_set_row_data
            (GTK_CLIST(clist_filter_rules), row, (gpointer) r);
    }
    gtk_clist_thaw(GTK_CLIST(clist_filter_rules));

    gtk_widget_set_sensitive(button_filter_clear, count != 0);

    if (dbg >= 5)
        printf("updated %d items\n", count);
}



/*
 * filter_gui_get_rule:
 *
 * Fetch the rule which is currently edited. This
 * returns a completely new rule_t item in new memory.
 */
rule_t *filter_gui_get_rule() 
{
    gint page;
    rule_t *r;

    g_return_val_if_fail(filter_dialog != NULL, NULL);

    page = gtk_notebook_get_current_page
        (GTK_NOTEBOOK(notebook_filter_detail));

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
    default:
        g_assert_not_reached();
        r = NULL;
    };

    if ((r != NULL) && (dbg >= 5))
        printf("got rule: %s\n", filter_rule_to_gchar(r));

    return r;
}



/* 
 * filter_gui_get_text_rule:
 *
 * Extract information about a text rule.
 * NEVER CALL DIRECTLY!!! Use filter_gui_get_rule().
 */
static rule_t *filter_gui_get_text_rule()
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
        option_menu_get_selected_data(optionmenu_filter_text_type);

	match = gtk_editable_get_chars
        (GTK_EDITABLE(entry_filter_text_pattern), 0, -1);

	case_sensitive = gtk_toggle_button_get_active
        (GTK_TOGGLE_BUTTON(checkbutton_filter_text_case));

	negate = gtk_toggle_button_get_active
        (GTK_TOGGLE_BUTTON(checkbutton_filter_text_invert_cond));

	active = gtk_toggle_button_get_active
        (GTK_TOGGLE_BUTTON(checkbutton_filter_text_active));

   	soft = gtk_toggle_button_get_active
        (GTK_TOGGLE_BUTTON(checkbutton_filter_text_soft));

    target = (filter_t *)option_menu_get_selected_data
        (optionmenu_filter_text_target);

    flags =
        (negate ? RULE_FLAG_NEGATE : 0) |
        (active ? RULE_FLAG_ACTIVE : 0) |
        (soft   ? RULE_FLAG_SOFT   : 0);

    r = filter_new_text_rule(match, type, case_sensitive, target, flags);

    g_free(match);
    
    return r;
}



/* 
 * filter_gui_get_ip_rule:
 *
 * Extract information about a ip rule.
 * NEVER CALL DIRECTLY!!! Use filter_gui_get_rule().
 */
static rule_t *filter_gui_get_ip_rule()
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

	s = gtk_editable_get_chars(GTK_EDITABLE(entry_filter_ip_address), 0, -1);
	addr = ntohl(inet_addr(s));
	g_free(s);

	s = gtk_editable_get_chars(GTK_EDITABLE(entry_filter_ip_mask), 0, -1);
	mask = ntohl(inet_addr(s));
	g_free(s);

    negate = gtk_toggle_button_get_active
        (GTK_TOGGLE_BUTTON(checkbutton_filter_ip_invert_cond));

    active = gtk_toggle_button_get_active
        (GTK_TOGGLE_BUTTON(checkbutton_filter_ip_active));

    soft = gtk_toggle_button_get_active
        (GTK_TOGGLE_BUTTON(checkbutton_filter_ip_soft));

    target = (filter_t *)option_menu_get_selected_data
        (optionmenu_filter_ip_target);

    flags =
        (negate ? RULE_FLAG_NEGATE : 0) |
        (active ? RULE_FLAG_ACTIVE : 0) |
        (soft   ? RULE_FLAG_SOFT   : 0);

    return filter_new_ip_rule(addr, mask, target, flags);
}



/* 
 * filter_gui_get_size_rule:
 *
 * Extract information about a size rule.
 * NEVER CALL DIRECTLY!!! Use filter_gui_get_rule().
 */
static rule_t *filter_gui_get_size_rule()
{
    size_t lower;
    size_t upper;
    filter_t *target;
    gboolean negate;
    gboolean active;
    gboolean soft;
    guint16 flags;

    if (filter_dialog == NULL)
        return NULL;

    lower = gtk_spin_button_get_value_as_int
        (GTK_SPIN_BUTTON(spinbutton_filter_size_min));

    upper = gtk_spin_button_get_value_as_int
        (GTK_SPIN_BUTTON(spinbutton_filter_size_max));

    negate = gtk_toggle_button_get_active
        (GTK_TOGGLE_BUTTON(checkbutton_filter_size_invert_cond));

    active = gtk_toggle_button_get_active
        (GTK_TOGGLE_BUTTON(checkbutton_filter_size_active));

    soft = gtk_toggle_button_get_active
        (GTK_TOGGLE_BUTTON(checkbutton_filter_size_soft));

    target = (filter_t *)option_menu_get_selected_data
        (optionmenu_filter_size_target);

    flags =
        (negate ? RULE_FLAG_NEGATE : 0) |
        (active ? RULE_FLAG_ACTIVE : 0) |
        (soft   ? RULE_FLAG_SOFT   : 0);

   return filter_new_size_rule(lower, upper, target, flags);
}



/* 
 * filter_gui_get_jump_rule:
 *
 * Extract information about a size rule.
 * NEVER CALL DIRECTLY!!! Use filter_gui_get_rule().
 */
static rule_t *filter_gui_get_jump_rule()
{
    filter_t *target;
    gboolean active;
    guint16 flags;

    if (filter_dialog == NULL)
        return NULL;

    target = (filter_t *)option_menu_get_selected_data
        (optionmenu_filter_jump_target);

    active = gtk_toggle_button_get_active
        (GTK_TOGGLE_BUTTON(checkbutton_filter_jump_active));

    flags = (active ? RULE_FLAG_ACTIVE : 0);

    return filter_new_jump_rule(target, flags);
}



/* 
 * filter_gui_get_flag_rule:
 *
 * Extract information about a flag rule.
 * NEVER CALL DIRECTLY!!! Use filter_gui_get_rule().
 */
static rule_t *filter_gui_get_flag_rule()
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

    target = (filter_t *)option_menu_get_selected_data
        (optionmenu_filter_flag_target);

    act = radiobutton_get_active_in_group
        (GTK_RADIO_BUTTON(radiobutton_filter_flag_stable_set));
    if (act == radiobutton_filter_flag_stable_set)
        stable = RULE_FLAG_SET;
    else if (act == radiobutton_filter_flag_stable_unset)
        stable = RULE_FLAG_UNSET;
    else if (act == radiobutton_filter_flag_stable_ignore)
        stable = RULE_FLAG_IGNORE;
    else
        g_error("Unknown radiobutton for stable flag");

    act = radiobutton_get_active_in_group
        (GTK_RADIO_BUTTON(radiobutton_filter_flag_busy_set));
    if (act == radiobutton_filter_flag_busy_set)
        busy = RULE_FLAG_SET;
    else if (act == radiobutton_filter_flag_busy_unset)
        busy = RULE_FLAG_UNSET;
    else if (act == radiobutton_filter_flag_busy_ignore)
        busy = RULE_FLAG_IGNORE;
    else
        g_error("Unknown radiobutton for busy flag");

    act = radiobutton_get_active_in_group
        (GTK_RADIO_BUTTON(radiobutton_filter_flag_push_set));
    if (act == radiobutton_filter_flag_push_set)
        push = RULE_FLAG_SET;
    else if (act == radiobutton_filter_flag_push_unset)
        push = RULE_FLAG_UNSET;
    else if (act == radiobutton_filter_flag_push_ignore)
        push = RULE_FLAG_IGNORE;
    else
        g_error("Unknown radiobutton for push flag");

    active = gtk_toggle_button_get_active
        (GTK_TOGGLE_BUTTON(checkbutton_filter_flag_active));

    soft = gtk_toggle_button_get_active
        (GTK_TOGGLE_BUTTON(checkbutton_filter_flag_soft));

    flags = (active ? RULE_FLAG_ACTIVE : 0) |
            (soft   ? RULE_FLAG_SOFT   : 0);

    return filter_new_flag_rule(stable, busy, push, target, flags);
}
