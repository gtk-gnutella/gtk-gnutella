/*
 * Copyright (c) 2001-2002, Raphael Manfredi, Richard Eckart
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

#ifndef __filter_gui_h__
#define __filter_gui_h__

#include "filter.h"
#include "gui.h"

/*
extern GtkWidget *button_filter_add_rule_flag;
extern GtkWidget *button_filter_add_rule_ip;
extern GtkWidget *button_filter_add_rule_jump;
extern GtkWidget *button_filter_add_rule_size;
extern GtkWidget *button_filter_add_rule_state;
extern GtkWidget *button_filter_add_rule_text;
extern GtkWidget *button_filter_clear;
extern GtkWidget *button_filter_remove;
extern GtkWidget *button_filter_reset;
extern GtkWidget *button_filter_reset_all_rules;
extern GtkWidget *checkbutton_filter_enabled;
extern GtkWidget *checkbutton_filter_ip_active;
extern GtkWidget *checkbutton_filter_ip_invert_cond;
extern GtkWidget *checkbutton_filter_ip_soft;
extern GtkWidget *checkbutton_filter_sha1_active;
extern GtkWidget *checkbutton_filter_sha1_invert_cond;
extern GtkWidget *checkbutton_filter_sha1_soft;
extern GtkWidget *checkbutton_filter_size_active;
extern GtkWidget *checkbutton_filter_size_invert_cond;
extern GtkWidget *checkbutton_filter_size_soft;
extern GtkWidget *checkbutton_filter_text_active;
extern GtkWidget *checkbutton_filter_text_invert_cond;
extern GtkWidget *checkbutton_filter_text_soft;
extern GtkWidget *clist_filter_rules;
extern GtkWidget *ctree_filter_filters;
extern GtkWidget *entry_filter_ip_mask;
extern GtkWidget *entry_filter_ip_address;
extern GtkWidget *entry_filter_name;
extern GtkWidget *entry_filter_new;
extern GtkWidget *entry_filter_sha1_hash;
extern GtkWidget *entry_filter_sha1_origfile;
extern GtkWidget *entry_filter_text_pattern;
extern GtkWidget *hpaned_filter_main;
extern GtkWidget *notebook_filter_detail;
extern GtkWidget *optionmenu_filter_default_policy;
extern GtkWidget *optionmenu_filter_flag_target;
extern GtkWidget *optionmenu_filter_ip_target;
extern GtkWidget *optionmenu_filter_jump_target;
extern GtkWidget *optionmenu_filter_sha1_target;
extern GtkWidget *optionmenu_filter_size_target;
extern GtkWidget *optionmenu_filter_state_target;
extern GtkWidget *optionmenu_filter_text_target;
extern GtkWidget *optionmenu_filter_text_type;
extern GtkWidget *optionmenu_search_filter;
extern GtkWidget *popup_filter_rule;
extern GtkWidget *popup_filter_rule_copy;
extern GtkWidget *popup_filter_rule_paste;
extern GtkWidget *radiobutton_filter_flag_busy_ignore;
extern GtkWidget *radiobutton_filter_flag_busy_set;
extern GtkWidget *radiobutton_filter_flag_busy_unset;
extern GtkWidget *radiobutton_filter_flag_push_ignore;
extern GtkWidget *radiobutton_filter_flag_push_set;
extern GtkWidget *radiobutton_filter_flag_push_unset;
extern GtkWidget *radiobutton_filter_flag_stable_ignore;
extern GtkWidget *radiobutton_filter_flag_stable_set;
extern GtkWidget *radiobutton_filter_flag_stable_unset;
extern GtkWidget *spinbutton_filter_size_max;
extern GtkWidget *spinbutton_filter_size_min;
extern GtkWidget *checkbutton_filter_text_case;
extern GtkWidget *checkbutton_filter_jump_active;
extern GtkWidget *checkbutton_filter_flag_active;
extern GtkWidget *checkbutton_filter_flag_soft;
extern GtkWidget *radiobutton_filter_state_display_ignore;
extern GtkWidget *radiobutton_filter_state_display_undef;
extern GtkWidget *radiobutton_filter_state_display_do;
extern GtkWidget *radiobutton_filter_state_display_dont;
extern GtkWidget *radiobutton_filter_state_download_ignore;
extern GtkWidget *radiobutton_filter_state_download_undef;
extern GtkWidget *radiobutton_filter_state_download_do;
extern GtkWidget *radiobutton_filter_state_download_dont;
extern GtkWidget *checkbutton_filter_state_active;
extern GtkWidget *checkbutton_filter_state_soft;
extern GtkWidget *checkbutton_filter_state_invert_cond;
*/


/*
 * Notebook tabs in the filter detail notebook.
 */
enum {
    nb_filt_page_buttons = 0,
    nb_filt_page_text,
    nb_filt_page_ip,
    nb_filt_page_size,
    nb_filt_page_jump,
    nb_filt_page_sha1,
    nb_filt_page_flag,
    nb_filt_page_state
};

extern GtkWidget *filter_dialog;
extern GtkWidget *popup_filter_rule;

void filter_gui_edit_ip_rule(rule_t *);
void filter_gui_edit_jump_rule(rule_t *);
void filter_gui_edit_rule(rule_t *);
void filter_gui_edit_size_rule(rule_t *);
void filter_gui_edit_text_rule(rule_t *);
void filter_gui_edit_sha1_rule(rule_t *);
void filter_gui_edit_flag_rule(rule_t *);
void filter_gui_edit_state_rule(rule_t *);
void filter_gui_filter_add(filter_t *f, GList *ruleset);
void filter_gui_filter_clear_list(void);
void filter_gui_filter_remove(filter_t *f);
void filter_gui_filter_set_enabled(filter_t *f, gboolean active);
void filter_gui_filter_set(filter_t *, gboolean, gboolean, GList *);
void filter_gui_init(void);
void filter_gui_rebuild_target_combos(GList *filters);
void filter_gui_set_default_policy(gint);
void filter_gui_set_ruleset(GList *ruleset);
void filter_gui_update_filter_stats(void);
void filter_gui_update_rule_stats(void);
void filter_gui_show_dialog(void);
rule_t *filter_gui_get_rule();
void filter_gui_update_rule_count(filter_t *f, GList *ruleset);
void filter_gui_freeze_rules();
void filter_gui_thaw_rules();
void filter_gui_freeze_filters();
void filter_gui_thaw_filters();

#endif /* __filter_gui_h__ */
