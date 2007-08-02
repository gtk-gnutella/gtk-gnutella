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

#ifndef _gtk_downloads_common_h_
#define _gtk_downloads_common_h_

#include "if/ui/gtk/downloads.h"
#include "lib/misc.h"

#define IO_STALLED	60 /**< If nothing exchanged after that many secs */

void on_button_downloads_clear_stopped_clicked(
	GtkButton *button, gpointer user_data);
void on_togglebutton_queue_freeze_toggled(
	GtkToggleButton *togglebutton, gpointer user_data);

const gchar *download_progress_to_string(const struct download *d);
const gchar *source_progress_to_string(const struct download *d);
const gchar *downloads_gui_status_string(const struct download *d);
const gchar *downloads_gui_range_string(const struct download *d);

void downloads_gui_clear_details(void);
void downloads_gui_set_details(const gchar *filename, filesize_t filesize,
	const struct sha1 *sha1, const struct tth *tth);
void downloads_gui_append_detail(const gchar *title, const gchar *value);

void downloads_gui_update_popup_downloads(void);

void fi_gui_files_configure_columns(void);
void fi_gui_purge_selected_files(void);
void fi_gui_select_by_regex(const gchar *regex);
GSList *fi_gui_sources_select(gboolean unselect);
GSList *fi_gui_files_select(gboolean unselect);
GSList *fi_gui_sources_of_selected_files(gboolean unselect);
enum nb_downloads_page fi_gui_get_current_page(void);

void fi_gui_add_download(struct download *);
void fi_gui_remove_download(struct download *);
void fi_gui_download_set_status(struct download *);

void on_entry_downloads_regex_activate(GtkEditable *, gpointer user_data);

/***
 *** popup-downloads
 ***/

void on_popup_downloads_abort_activate(GtkMenuItem *, gpointer user_data);
void on_popup_downloads_browse_host_activate(GtkMenuItem *, gpointer user_data);
void on_popup_downloads_config_cols_activate(GtkMenuItem *, gpointer user_data);
void on_popup_downloads_connect_activate(GtkMenuItem *, gpointer user_data);
void on_popup_downloads_copy_magnet_activate(GtkMenuItem *, gpointer udata);
void on_popup_downloads_forget_activate(GtkMenuItem *, gpointer user_data);
void on_popup_downloads_pause_activate(GtkMenuItem *, gpointer user_data);
void on_popup_downloads_queue_activate(GtkMenuItem *, gpointer user_data);
void on_popup_downloads_resume_activate(GtkMenuItem *, gpointer user_data);
void on_popup_downloads_start_now_activate(GtkMenuItem *, gpointer user_data);

/***
 *** popup-sources
 ***/

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

gboolean on_download_files_button_press_event(GtkWidget *,
		GdkEventButton *, gpointer user_udata);
gboolean on_download_sources_button_press_event(GtkWidget *,
		GdkEventButton *, gpointer user_udata);

#endif /* _gtk_downloads_common_h_ */
