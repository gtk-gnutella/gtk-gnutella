/*
 * Copyright (c) 2001-2003, Raphael Manfredi
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

#ifndef _callbacks_h_
#define _callbacks_h_

#include "gtk/gui.h"

#include "gtk/downloads.h"
#include "gtk/fileinfo.h"
#include "gtk/filter_cb.h"
#include "gtk/gnet_stats.h"
#include "gtk/hcache.h"
#include "gtk/main_cb.h"
#include "gtk/monitor_cb.h"
#include "gtk/settings_cb.h"
#include "gtk/upload_stats_cb.h"
#include "gtk/uploads_cb.h"
#include "gtk/visual_progress.h"

#ifdef USE_GTK1
#include "gtk/gtk1/nodes_cb.h"
#endif
#ifdef USE_GTK2
#include "gtk/gtk2/nodes_cb.h"
#endif

void on_button_extra_config_clicked(GtkButton *, gpointer user_data);

/***
 *** sidebar
 ***/

gboolean on_progressbar_bws_in_button_press_event(GtkWidget *,
		GdkEventButton *event, gpointer user_data);
gboolean on_progressbar_bws_out_button_press_event(GtkWidget *,
		GdkEventButton *event, gpointer user_data);
gboolean on_progressbar_bws_gin_button_press_event(GtkWidget *,
		GdkEventButton *event, gpointer user_data);
gboolean on_progressbar_bws_gout_button_press_event(GtkWidget *,
		GdkEventButton *event, gpointer user_data);
gboolean on_progressbar_bws_lin_button_press_event(GtkWidget *,
		GdkEventButton *event, gpointer user_data);
gboolean on_progressbar_bws_lout_button_press_event(GtkWidget *,
		GdkEventButton *event, gpointer user_data);
gboolean on_progressbar_bws_dht_in_button_press_event(GtkWidget *,
		GdkEventButton *event, gpointer user_data);
gboolean on_progressbar_bws_dht_out_button_press_event(GtkWidget *,
		GdkEventButton *event, gpointer user_data);

/***
 *** hostcache panel
 ***/
void on_button_host_catcher_clear_clicked(GtkButton *, gpointer user_data);
void on_button_ultra_catcher_clear_clicked(GtkButton *, gpointer user_data);
void on_button_hostcache_clear_bad_clicked(GtkButton *, gpointer user_data);

/***
 *** config panel
 ***/

gboolean on_entry_config_maxttl_focus_out_event(GtkWidget *,
		GdkEventFocus *, gpointer user_data);
gboolean on_entry_config_myttl_focus_out_event(GtkWidget *,
		GdkEventFocus *, gpointer user_data);
gboolean on_entry_config_netmask_focus_out_event(GtkWidget *,
		GdkEventFocus *, gpointer user_data);
gboolean on_entry_config_search_items_focus_out_event(GtkWidget *,
		GdkEventFocus *, gpointer user_data);
gboolean on_entry_config_speed_focus_out_event(GtkWidget *,
		GdkEventFocus *, gpointer user_data);

void on_button_downloads_clear_completed_clicked(GtkButton *, gpointer);
void on_button_config_add_dir_clicked(GtkButton *, gpointer user_data);
void on_button_config_move_path_clicked(GtkButton *, gpointer user_data);
void on_button_config_rescan_dir_clicked(GtkButton *, gpointer user_data);
void on_button_config_save_path_clicked(GtkButton *, gpointer user_data);
void on_button_config_bad_path_clicked(GtkButton *, gpointer user_data);
void on_entry_config_maxttl_activate(GtkEditable *, gpointer user_data);
void on_entry_config_maxttl_changed(GtkEditable *, gpointer user_data);
void on_entry_config_myttl_activate(GtkEditable *, gpointer user_data);
void on_entry_config_myttl_changed(GtkEditable *, gpointer user_data);
void on_entry_config_netmask_activate(GtkEditable *, gpointer user_data);
void on_entry_config_search_items_activate(GtkEditable *, gpointer user_data);
void on_entry_config_speed_activate(GtkEditable *, gpointer user_data);

/***
 *** search stats
 ***/

void on_button_search_stats_reset_clicked(GtkButton *, gpointer user_data);

void on_menu_faq_activate(GtkMenuItem *, gpointer user_data);
gboolean on_dlg_faq_delete_event(GtkWidget *, GdkEvent *, gpointer user_data);

void on_menu_glossary_activate(GtkMenuItem *, gpointer user_data);
gboolean on_dlg_glossary_delete_event(GtkWidget *, GdkEvent *, gpointer udata);

#endif	/* _callbacks_h_ */

/* vi: set ts=4 sw=4 cindent: */
