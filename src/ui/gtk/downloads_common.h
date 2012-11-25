/*
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
#include "if/bridge/ui2c.h"

#include "lib/misc.h"

/**
 * Notebook tabs in the downloads page.
 */
enum nb_downloads_page {
	nb_downloads_page_active,
	nb_downloads_page_queued,
	nb_downloads_page_paused,
	nb_downloads_page_incomplete,
	nb_downloads_page_orphaned,
	nb_downloads_page_finished,
	nb_downloads_page_seeding,
	nb_downloads_page_all,

	nb_downloads_page_num
};

/* Widget signal callbacks */

void on_entry_downloads_filter_regex_activate(GtkEditable *, void *user_data);
void on_checkbutton_downloads_filter_regex_case_toggled(GtkToggleButton *,
		void *user_data);
void on_checkbutton_downloads_filter_regex_invert_toggled(GtkToggleButton *,
		void *user_data);

void on_entry_downloads_select_regex_activate(GtkEditable *, void *user_data);
void on_checkbutton_downloads_select_regex_case_toggled(GtkToggleButton *,
		void *user_data);
void on_checkbutton_downloads_select_regex_invert_toggled(GtkToggleButton *,
		void *user_data);

void on_button_downloads_clear_stopped_clicked(GtkButton *, void *user_data);
void on_togglebutton_queue_freeze_toggled(GtkToggleButton *, void *user_data);

/***
 *** popup-downloads
 ***/

void on_popup_downloads_abort_activate(GtkMenuItem *, void *user_data);
void on_popup_downloads_browse_host_activate(GtkMenuItem *, void *user_data);
void on_popup_downloads_config_cols_activate(GtkMenuItem *, void *user_data);
void on_popup_downloads_connect_activate(GtkMenuItem *, void *user_data);
void on_popup_downloads_copy_magnet_activate(GtkMenuItem *, void *udata);
void on_popup_downloads_forget_activate(GtkMenuItem *, void *user_data);
void on_popup_downloads_pause_activate(GtkMenuItem *, void *user_data);
void on_popup_downloads_queue_activate(GtkMenuItem *, void *user_data);
void on_popup_downloads_resume_activate(GtkMenuItem *, void *user_data);
void on_popup_downloads_start_now_activate(GtkMenuItem *, void *user_data);

/***
 *** popup-sources
 ***/

void on_popup_sources_browse_host_activate(GtkMenuItem *, void *user_data);
void on_popup_sources_config_cols_activate(GtkMenuItem *, void *user_data);
void on_popup_sources_connect_activate(GtkMenuItem *, void *user_data);
void on_popup_sources_copy_url_activate(GtkMenuItem *, void *user_data);
void on_popup_sources_forget_activate(GtkMenuItem *, void *udata);
void on_popup_sources_pause_activate(GtkMenuItem *, void *user_data);
void on_popup_sources_push_activate(GtkMenuItem *, void *user_data);
void on_popup_sources_queue_activate(GtkMenuItem *, void *user_data);
void on_popup_sources_resume_activate(GtkMenuItem *, void *user_data);
void on_popup_sources_start_now_activate(GtkMenuItem *, void *udata);

gboolean on_files_button_press_event(GtkWidget *, GdkEventButton *, void *);
gboolean on_files_key_press_event(GtkWidget *, GdkEventKey *, void *);
gboolean on_sources_button_press_event(GtkWidget *, GdkEventButton *, void *);
gboolean on_sources_key_press_event(GtkWidget *, GdkEventKey *, void *);
gboolean on_details_key_press_event(GtkWidget *, GdkEventKey *, void *);

/**
 * Common functions available to the interface
 */

struct fileinfo_data;

void fi_gui_common_init(void);
void fi_gui_common_shutdown(void);

const char *fi_gui_file_column_text(const struct fileinfo_data *, int column);
const char *fi_gui_source_column_text(const struct download *, int column);

void fi_gui_fi_status_changed(gnet_fi_t handle);
void fi_gui_files_cursor_update(void);
gboolean fi_gui_filter_active(void);

int fileinfo_data_cmp(const struct fileinfo_data *,
	const struct fileinfo_data *, int column);

void fi_gui_file_set_user_data(struct fileinfo_data *, void *user_data);
void *fi_gui_file_get_user_data(const struct fileinfo_data *);

const char *fi_gui_file_get_filename(const struct fileinfo_data *);
unsigned fi_gui_file_get_progress(const struct fileinfo_data *);
char *fi_gui_file_get_magnet(const struct fileinfo_data *);

gboolean fi_gui_rename(const char *filename);

unsigned fi_gui_source_get_progress(const struct download *);

const char *fi_gui_files_column_title(int column);
gboolean fi_gui_files_column_justify_right(int column);

GtkMenu *fi_gui_sources_get_popup_menu(void);

/**
 * Interface which must be implemented by Gtk+ 1.2 and Gtk+ 2.x
 */

void fi_gui_file_invalidate(struct fileinfo_data *);
void fi_gui_file_show(struct fileinfo_data *);
void fi_gui_file_hide(struct fileinfo_data *);
void fi_gui_file_select(struct fileinfo_data *);

void fi_gui_files_freeze(void);
void fi_gui_files_thaw(void);
void fi_gui_files_unselect_all(void);
void fi_gui_files_filter_changed(void);

void fi_gui_show_aliases(const char * const *aliases);
void fi_gui_clear_aliases(void);
void fi_gui_clear_sources(void);
void fi_gui_clear_details(void);

void fi_gui_source_show(struct download *);
void fi_gui_source_update(struct download *);
void fi_gui_source_hide(struct download *);

GtkWidget *fi_gui_sources_widget(void);

GtkWidget *fi_gui_files_widget(void);
GtkWidget *fi_gui_files_widget_new(void);
void fi_gui_files_widget_destroy(void);

char *fi_gui_get_detail_at_cursor(void);
struct fileinfo_data *fi_gui_get_file_at_cursor(void);
struct download *fi_gui_get_source_at_cursor(void);

typedef int (*fi_gui_files_foreach_cb)(struct fileinfo_data *, void *user_data);
void fi_gui_files_foreach(fi_gui_files_foreach_cb func, void *user_data);

enum fi_gui_detail {
	FI_GUI_DETAIL_UNSPECIFIED,
	FI_GUI_DETAIL_FILENAME,
	FI_GUI_DETAIL_SIZE,
	FI_GUI_DETAIL_CREATED,
	FI_GUI_DETAIL_MODIFIED,
	FI_GUI_DETAIL_SHA1,
	FI_GUI_DETAIL_BITPRINT,
	FI_GUI_DETAIL_TIGERTREE,
	FI_GUI_DETAIL_BITZI
};

void fi_gui_append_detail(enum fi_gui_detail, const char *title, const char *value);

GSList *fi_gui_get_selected_files(gboolean unselect);
GSList *fi_gui_get_selected_sources(gboolean unselect);

#endif /* _gtk_downloads_common_h_ */
/* vi: set ts=4 sw=4 cindent: */
