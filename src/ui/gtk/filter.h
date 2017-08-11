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
 *      59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *----------------------------------------------------------------------
 */

#ifndef _gtk_filter_h_
#define _gtk_filter_h_

#include "gui.h"
#include "filter_core.h"

/**
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
    nb_filt_page_state,

    nb_filt_page_num
};

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
void filter_gui_shutdown(void);
void filter_gui_rebuild_target_combos(GList *filters);
void filter_gui_set_ruleset(GList *ruleset);
void filter_gui_show_dialog(void);
rule_t *filter_gui_get_rule(void);
void filter_gui_update_rule_count(filter_t *f, GList *ruleset);
guint64 filter_update_size(GtkEntry *entry);

#ifdef USE_GTK1
#define filter_gui_create_dlg_filters() create_dlg_filters()

void filter_gui_freeze_rules(void);
void filter_gui_thaw_rules(void);
void filter_gui_freeze_filters(void);
void filter_gui_thaw_filters(void);
#endif /* USE_GTK1 */

#ifdef USE_GTK2
GtkWidget *filter_gui_create_dlg_filters(void);
#define filter_gui_freeze_rules()
#define filter_gui_thaw_rules()
#define filter_gui_freeze_filters()
#define filter_gui_thaw_filters()
#endif

#endif /* _gtk_filter_h_ */

/* vi: set ts=4 sw=4 cindent: */
