/*
 * $Id$
 *
 * Copyright (c) 2001-2002, Raphael Manfredi
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

#ifndef __callbacks_h__
#define __callbacks_h__

#include "gui.h"

#ifdef USE_GTK2
#include "filter_cb.h"
#include "nodes_cb2.h"
#include "settings_cb.h"
#include "search_cb.h"
#include "main_cb.h"
#include "monitor_cb.h"
#include "uploads_cb.h"
#include "downloads_cb.h"
#include "gnet_stats_gui.h"
#else
#include "filter_cb.h"
#include "nodes_cb.h"
#include "settings_cb.h"
#include "search_cb.h"
#include "main_cb.h"
#include "monitor_cb.h"
#include "uploads_cb.h"
#include "downloads_cb.h"
#include "gnet_stats_gui.h"
#endif

gboolean on_entry_search_reissue_timeout_focus_out_event (GtkWidget *widget, GdkEventFocus *event, gpointer user_data);
void on_button_extra_config_clicked (GtkButton *button, gpointer user_data); 
void on_ctree_menu_tree_select_row (GtkCTree *clist, GList *node, gint column, gpointer user_data);


 
/***
 *** sidebar
 ***/
gboolean on_progressbar_bws_in_button_press_event(GtkWidget *widget, GdkEventButton *event, gpointer user_data);
gboolean on_progressbar_bws_out_button_press_event(GtkWidget *widget, GdkEventButton *event, gpointer user_data);
gboolean on_progressbar_bws_gin_button_press_event(GtkWidget *widget, GdkEventButton *event, gpointer user_data);
gboolean on_progressbar_bws_gout_button_press_event(GtkWidget *widget, GdkEventButton *event, gpointer user_data);



/***
 *** gnutellaNet panel
 ***/
void on_button_host_catcher_clear_clicked (GtkButton *button, gpointer user_data);



/***
 *** config panel
 ***/
gboolean on_entry_config_maxttl_focus_out_event (GtkWidget *widget, GdkEventFocus *event, gpointer user_data); 
gboolean on_entry_config_myttl_focus_out_event (GtkWidget *widget, GdkEventFocus *event, gpointer user_data);
gboolean on_entry_config_netmask_focus_out_event(GtkWidget * widget, GdkEventFocus * event, gpointer user_data);
gboolean on_entry_config_search_items_focus_out_event (GtkWidget *widget, GdkEventFocus *event, gpointer user_data);
gboolean on_entry_config_speed_focus_out_event (GtkWidget *widget, GdkEventFocus *event, gpointer user_data);
void on_button_config_add_dir_clicked (GtkButton *button, gpointer user_data); 
void on_button_config_move_path_clicked (GtkButton *button, gpointer user_data); 
void on_button_config_rescan_dir_clicked (GtkButton *button, gpointer user_data); 
void on_button_config_save_path_clicked (GtkButton *button, gpointer user_data);
void on_entry_config_maxttl_activate (GtkEditable *editable, gpointer user_data); 
void on_entry_config_maxttl_changed (GtkEditable *editable, gpointer user_data);
void on_entry_config_myttl_activate (GtkEditable *editable, gpointer user_data);
void on_entry_config_myttl_changed (GtkEditable *editable, gpointer user_data);
void on_entry_config_netmask_activate(GtkEditable * editable, gpointer user_data);
void on_entry_config_search_items_activate (GtkEditable *editable, gpointer user_data);
void on_entry_config_speed_activate (GtkEditable *editable, gpointer user_data);
void on_radio_config_http_toggled (GtkToggleButton *togglebutton, gpointer user_data);
void on_radio_config_socksv4_toggled (GtkToggleButton *togglebutton, gpointer user_data);
void on_radio_config_socksv5_toggled (GtkToggleButton *togglebutton, gpointer user_data);



/*** 
 *** search stats
 ***/
void on_button_search_stats_reset_clicked(GtkButton * button, gpointer user_data);
void on_clist_search_stats_resize_column(GtkCList * clist, gint column, gint width, gpointer user_data);



/***
 *** search list (sidebar)
 ***/
void on_clist_search_resize_column(GtkCList * clist, gint column, gint width, gpointer user_data);



// FIXME: temporaily relocated
gint compare_ul_norm(GtkCList *clist, gconstpointer ptr1, gconstpointer ptr2);


#endif	/* __callbacks_h__ */
 
