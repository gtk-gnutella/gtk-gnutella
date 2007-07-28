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


/***
 *** popup-downloads
 ***/

void on_popup_downloads_push_activate(
	GtkMenuItem *menuitem, gpointer user_data);
void on_popup_downloads_abort_named_activate(
	GtkMenuItem *menuitem, gpointer user_data);
void on_popup_downloads_abort_host_activate(
	GtkMenuItem *menuitem, gpointer user_data);
void on_popup_downloads_abort_sha1_activate(
	GtkMenuItem *menuitem, gpointer user_data);
void on_popup_downloads_remove_activate(
	GtkMenuItem *menuitem, gpointer user_data);
void on_popup_downloads_search_again_activate(
	GtkMenuItem *menuitem, gpointer user_data);
void on_popup_downloads_queue_activate(
	GtkMenuItem *menuitem, gpointer user_data);
void on_popup_downloads_copy_url_activate(
	GtkMenuItem *menuitem, gpointer user_data);
void on_popup_downloads_connect_activate(
	GtkMenuItem *menuitem, gpointer user_data);
void on_popup_downloads_browse_host_activate(GtkMenuItem *unused_menuitem,
	gpointer unused_udata);
void on_popup_downloads_resume_activate(
	GtkMenuItem *menuitem, gpointer user_data);
void on_popup_downloads_start_now_activate(
	GtkMenuItem *menuitem, gpointer user_data);
void on_popup_downloads_pause_activate(
	GtkMenuItem *menuitem, gpointer user_data);
void on_popup_downloads_push_activate(
	GtkMenuItem *menuitem, gpointer user_data);
void on_popup_downloads_abort_host_activate(
	GtkMenuItem * menuitem, gpointer user_data);
void on_popup_downloads_abort_named_activate(
	GtkMenuItem * menuitem, gpointer user_data);
void on_popup_downloads_abort_sha1_activate(
	GtkMenuItem * menuitem, gpointer user_data);
void on_popup_downloads_abort_activate(GtkMenuItem * menuitem,
	gpointer user_data);
void on_popup_downloads_expand_all_activate(
	GtkMenuItem *menuitem, gpointer user_data);
void on_popup_downloads_collapse_all_activate(
	GtkMenuItem *menuitem, gpointer user_data);
void on_popup_downloads_copy_magnet_activate(
	GtkMenuItem *unused_menuitem, gpointer unused_udata);
void on_popup_downloads_config_cols_activate(GtkMenuItem *menuitem,
	gpointer user_data);

#endif /* _gtk_downloads_common_h_ */
