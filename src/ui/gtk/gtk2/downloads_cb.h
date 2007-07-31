/*
 * $Id$
 *
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

#ifndef _gtk2_downloads_cb_h_
#define _gtk2_downloads_cb_h_

#include "gtk/gui.h"

void fi_gui_files_configure_columns(void);
void fi_gui_purge_selected_files(void);
void fi_gui_select_by_regex(const gchar *regex);
GSList *fi_gui_sources_select(gboolean unselect);
GSList *fi_gui_files_select(gboolean unselect);
GSList *fi_gui_sources_of_selected_files(gboolean unselect);


gboolean on_treeview_downloads_button_press_event(GtkWidget *,
			GdkEventButton *, gpointer user_data);
gboolean on_treeview_sources_button_press_event(GtkWidget *,
			GdkEventButton *, gpointer user_data);

/***
 *** downloads panel
 ***/

/* active downloads */
void on_button_downloads_clear_stopped_clicked(GtkButton *, gpointer user_data);

void on_entry_regex_activate(GtkEditable *, gpointer user_data);

void on_popup_sources_browse_host_activate(GtkMenuItem *, gpointer user_data);
void on_popup_sources_config_cols_activate(GtkMenuItem *, gpointer user_data);
void on_popup_sources_connect_activate(GtkMenuItem *, gpointer user_data);
void on_popup_sources_copy_url_activate(GtkMenuItem *, gpointer user_data);
void on_popup_sources_forget_activate(GtkMenuItem *, gpointer udata);
void on_popup_sources_pause_activate(GtkMenuItem *, gpointer user_data);
void on_popup_sources_push_activate(GtkMenuItem *, gpointer user_data);
void on_popup_sources_queue_activate(GtkMenuItem *, gpointer user_data);
void on_popup_sources_resume_activate(GtkMenuItem *, gpointer user_data);
void on_popup_sources_start_now_activate(GtkMenuItem *, gpointer udata);

#endif /* _gtk2_downloads_cb_h_ */
/* vi: set ts=4 sw=4 cindent: */
