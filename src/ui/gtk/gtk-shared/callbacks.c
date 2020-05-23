/*
 * Copyright (c) 2001-2003, Raphael Manfredi & Richard Eckart
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
 *      51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *----------------------------------------------------------------------
 */

#include "common.h"

#include "gtk/gui.h"
#include "gtk/misc.h"
#include "gtk/search.h"
#include "gtk/search_stats.h"
#include "gtk/statusbar.h"

#include "if/bridge/ui2c.h"
#include "if/gui_property.h"
#include "if/gui_property_priv.h"

#include "lib/override.h"		/* Must be the last header included */

/*
 * Create a function for the focus out signal and make it call
 * the callback for the activate signal.
 */
#define FOCUS_TO_ACTIVATE(a)                                    \
    gboolean CAT3(on_,a,_focus_out_event) (GtkWidget *widget,	\
			GdkEventFocus *unused_event, gpointer unused_udata)	\
    {                                                           \
        (void) unused_event;                                    \
        (void) unused_udata;                                    \
        CAT3(on_,a,_activate)(GTK_EDITABLE(widget), NULL);      \
        return FALSE;                                           \
    }




/***
 *** Left panel
 ***/

gboolean
on_progressbar_bws_in_button_press_event(GtkWidget *unused_widget,
		GdkEventButton *unused_event, gpointer unused_udata)
{
    gboolean val;

	(void) unused_widget;
	(void) unused_event;
	(void) unused_udata;
    gui_prop_get_boolean_val(PROP_PROGRESSBAR_BWS_IN_AVG, &val);
    gui_prop_set_boolean_val(PROP_PROGRESSBAR_BWS_IN_AVG, !val);
	return TRUE;
}

gboolean
on_progressbar_bws_out_button_press_event(GtkWidget *unused_widget,
	GdkEventButton *unused_event, gpointer unused_udata)
{
    gboolean val;

	(void) unused_widget;
	(void) unused_event;
	(void) unused_udata;
    gui_prop_get_boolean_val(PROP_PROGRESSBAR_BWS_OUT_AVG, &val);
    gui_prop_set_boolean_val(PROP_PROGRESSBAR_BWS_OUT_AVG, !val);
	return TRUE;
}

gboolean
on_progressbar_bws_gin_button_press_event(GtkWidget *unused_widget,
	GdkEventButton *unused_event, gpointer unused_udata)
{
    gboolean val;

	(void) unused_widget;
	(void) unused_event;
	(void) unused_udata;
    gui_prop_get_boolean_val(PROP_PROGRESSBAR_BWS_GIN_AVG, &val);
    gui_prop_set_boolean_val(PROP_PROGRESSBAR_BWS_GIN_AVG, !val);
	return TRUE;
}

gboolean
on_progressbar_bws_gout_button_press_event(GtkWidget *unused_widget,
	GdkEventButton *unused_event, gpointer unused_udata)
{
    gboolean val;

	(void) unused_widget;
	(void) unused_event;
	(void) unused_udata;
    gui_prop_get_boolean_val(PROP_PROGRESSBAR_BWS_GOUT_AVG, &val);
    gui_prop_set_boolean_val(PROP_PROGRESSBAR_BWS_GOUT_AVG, !val);
	return TRUE;
}

gboolean
on_progressbar_bws_lin_button_press_event(GtkWidget *unused_widget,
	GdkEventButton *unused_event, gpointer unused_udata)
{
    gboolean val;

	(void) unused_widget;
	(void) unused_event;
	(void) unused_udata;
    gui_prop_get_boolean_val(PROP_PROGRESSBAR_BWS_GLIN_AVG, &val);
    gui_prop_set_boolean_val(PROP_PROGRESSBAR_BWS_GLIN_AVG, !val);
	return TRUE;
}

gboolean
on_progressbar_bws_lout_button_press_event(GtkWidget *unused_widget,
		GdkEventButton *unused_event, gpointer unused_udata)
{
    gboolean val;

	(void) unused_widget;
	(void) unused_event;
	(void) unused_udata;
    gui_prop_get_boolean_val(PROP_PROGRESSBAR_BWS_GLOUT_AVG, &val);
    gui_prop_set_boolean_val(PROP_PROGRESSBAR_BWS_GLOUT_AVG, !val);
	return TRUE;
}

gboolean
on_progressbar_bws_dht_in_button_press_event(GtkWidget *unused_widget,
		GdkEventButton *unused_event, gpointer unused_udata)
{
    gboolean val;

	(void) unused_widget;
	(void) unused_event;
	(void) unused_udata;
    gui_prop_get_boolean_val(PROP_PROGRESSBAR_BWS_DHT_IN_AVG, &val);
    gui_prop_set_boolean_val(PROP_PROGRESSBAR_BWS_DHT_IN_AVG, !val);
	return TRUE;
}


gboolean
on_progressbar_bws_dht_out_button_press_event(GtkWidget *unused_widget,
		GdkEventButton *unused_event, gpointer unused_udata)
{
    gboolean val;

	(void) unused_widget;
	(void) unused_event;
	(void) unused_udata;
    gui_prop_get_boolean_val(PROP_PROGRESSBAR_BWS_DHT_OUT_AVG, &val);
    gui_prop_set_boolean_val(PROP_PROGRESSBAR_BWS_DHT_OUT_AVG, !val);
	return TRUE;
}

/***
 *** GnutellaNet pane
 ***/

/* minimum connections up */

void
on_button_host_catcher_clear_clicked(GtkButton *unused_button,
	gpointer unused_udata)
{
	(void) unused_button;
	(void) unused_udata;
	guc_hcache_clear_host_type(HOST_ANY);
}

void
on_button_ultra_catcher_clear_clicked(GtkButton *unused_button,
	gpointer unused_udata)
{
	(void) unused_button;
	(void) unused_udata;
	guc_hcache_clear_host_type(HOST_ULTRA);
}

void
on_button_hostcache_clear_bad_clicked(GtkButton *unused_button,
	gpointer unused_udata)
{
	(void) unused_button;
	(void) unused_udata;
    guc_hcache_clear(HCACHE_TIMEOUT);
    guc_hcache_clear(HCACHE_BUSY);
    guc_hcache_clear(HCACHE_UNSTABLE);
	/* Do not clear HCACHE_ALIEN -- we want to keep knowledge of these */
}

/***
 *** Search Stats
 ***/

void
on_button_search_stats_reset_clicked(GtkButton *unused_button,
	gpointer unused_data)
{
	(void) unused_button;
	(void) unused_data;
	search_stats_gui_reset();
}

/***
 *** Config pane
 ***/

/**
 * We use a single dialog for all directory selections.
 * This is simpler and avoids having several opened popup dialogs.
 * If the dialog is already in use, it is destroyed and re-created, so
 * the window is also automagically (re-)raised.
 */
static GtkWidget *directory_chooser;

static gboolean
on_directory_chooser_delete_event(GtkWidget *widget,
	GdkEvent *unused_event, void *unused_udata)
{
	(void) unused_event;
	(void) unused_udata;

	gtk_widget_destroy(widget);
	directory_chooser = NULL;
	return TRUE;
}

#if GTK_CHECK_VERSION(2,6,0)

enum dir_choice {
	DIR_CHOICE_SHARED,
	DIR_CHOICE_COMPLETE,
	DIR_CHOICE_INCOMPLETE,
	DIR_CHOICE_CORRUPT
};

static gboolean
on_directory_chooser_destroy_event(GtkWidget *unused_widget,
	GdkEvent *unused_event, void *unused_udata)
{
	(void) unused_widget;
	(void) unused_event;
	(void) unused_udata;

	directory_chooser = NULL;
	return TRUE;
}

static void
directory_chooser_handle_result(enum dir_choice dir_choice,
	const char *pathname)
{
	g_return_if_fail(NULL != pathname);
	g_return_if_fail(is_absolute_path(pathname));
	g_return_if_fail(is_directory(pathname));

	switch (dir_choice) {
	case DIR_CHOICE_SHARED:
		guc_shared_dir_add(pathname);
		return;
	case DIR_CHOICE_COMPLETE:
		gnet_prop_set_string(PROP_MOVE_FILE_PATH, pathname);
		return;
	case DIR_CHOICE_INCOMPLETE:
		gnet_prop_set_string(PROP_SAVE_FILE_PATH, pathname);
		return;
	case DIR_CHOICE_CORRUPT:
		gnet_prop_set_string(PROP_BAD_FILE_PATH, pathname);
		return;
	}
	g_assert_not_reached();
}

void
on_directory_chooser_response(GtkDialog *dialog, int response_id,
	void *user_data)
{
	if (GTK_RESPONSE_ACCEPT == response_id) {
		enum dir_choice dir_choice = pointer_to_uint(user_data);
		char *pathname;

		pathname = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(dialog));
		directory_chooser_handle_result(dir_choice, pathname);
		G_FREE_NULL(pathname);
	}
	gtk_widget_destroy(GTK_WIDGET(dialog));
	directory_chooser = NULL;
}

static void
directory_chooser_show(enum dir_choice dir_choice, const char *title,
	const char *current_directory)
{
	GtkWidget *widget;
	GtkFileFilter *filter;

	if (directory_chooser) {
		gtk_widget_destroy(directory_chooser);
		directory_chooser = NULL;
	}

	widget = gtk_file_chooser_dialog_new(title,
				GTK_WINDOW(gui_main_window()),
				GTK_FILE_CHOOSER_ACTION_SELECT_FOLDER,
				GTK_STOCK_CANCEL, GTK_RESPONSE_CANCEL,
				GTK_STOCK_OPEN, GTK_RESPONSE_ACCEPT,
				NULL_PTR);
	g_return_if_fail(NULL != widget);
	directory_chooser = widget;

	filter = gtk_file_filter_new();
	gtk_file_filter_add_mime_type(filter, "inode/directory");


	gtk_file_chooser_set_local_only(GTK_FILE_CHOOSER(widget), TRUE);
	gtk_file_chooser_set_filter(GTK_FILE_CHOOSER(widget),
		filter);	/* Display only directories */

	if (NULL != current_directory) {
		gtk_file_chooser_set_current_folder(GTK_FILE_CHOOSER(widget),
			current_directory);
	}

	gui_signal_connect(widget, "destroy-event",
		on_directory_chooser_destroy_event, NULL);
	gui_signal_connect(widget, "delete-event",
		on_directory_chooser_delete_event, NULL);
	gui_signal_connect(widget, "response",
		on_directory_chooser_response, uint_to_pointer(dir_choice));

	gtk_widget_show(widget);
}

void
on_button_config_add_dir_clicked(GtkButton *unused_button, void *unused_udata)
{
	(void) unused_button;
	(void) unused_udata;

	directory_chooser_show(DIR_CHOICE_SHARED,
		_("Please choose a directory to share"),
		NULL);
}

void
on_button_config_move_path_clicked(GtkButton *unused_button, void *unused_udata)
{
	char *directory = gnet_prop_get_string(PROP_MOVE_FILE_PATH, NULL, 0);

	(void) unused_button;
	(void) unused_udata;

	directory_chooser_show(DIR_CHOICE_COMPLETE,
		_("Please choose where to move files after successful download"),
		directory);
	G_FREE_NULL(directory);
}

void
on_button_config_save_path_clicked(GtkButton *unused_button, void *unused_udata)
{
	char *directory = gnet_prop_get_string(PROP_SAVE_FILE_PATH, NULL, 0);

	(void) unused_button;
	(void) unused_udata;

	directory_chooser_show(DIR_CHOICE_INCOMPLETE,
		_("Please choose where to store files while downloading"),
		directory);
	G_FREE_NULL(directory);
}

void
on_button_config_bad_path_clicked(GtkButton *unused_button, void *unused_udata)
{
	char *directory = gnet_prop_get_string(PROP_BAD_FILE_PATH, NULL, 0);

	(void) unused_button;
	(void) unused_udata;

	directory_chooser_show(DIR_CHOICE_CORRUPT,
		_("Please choose where to move corrupted files"),
		directory);
	G_FREE_NULL(directory);
}
#else	/* Gtk+ < 2.6.0 */

/* While downloading, store files to */

void
button_fs_save_path_clicked(GtkButton *unused_button, gpointer user_data)
{
	(void) unused_button;

	if (user_data) {
        const char *name = gtk_file_selection_get_filename(
			GTK_FILE_SELECTION(directory_chooser));

		if (is_directory(name)) {
            gnet_prop_set_string(PROP_SAVE_FILE_PATH, name);
		}
	}

	gtk_widget_destroy(directory_chooser);
	directory_chooser = NULL;
}

void
on_button_config_save_path_clicked(GtkButton *unused_button,
	gpointer unused_udata)
{
	(void) unused_button;
	(void) unused_udata;

	if (directory_chooser) {
		gtk_widget_destroy(directory_chooser);
		directory_chooser = NULL;
	}

	directory_chooser = gtk_file_selection_new(
				_("Please choose where to store files while downloading"));

	gui_signal_connect(
		GTK_FILE_SELECTION(directory_chooser)->ok_button,
		"clicked", button_fs_save_path_clicked, GINT_TO_POINTER(1));
	gui_signal_connect(
		GTK_FILE_SELECTION(directory_chooser)->cancel_button,
		"clicked", button_fs_save_path_clicked, NULL);
	gui_signal_connect(directory_chooser,
		"delete_event", on_directory_chooser_delete_event, NULL);

	gtk_widget_show(directory_chooser);
}

/* Move downloaded files to */

void
button_fs_move_path_clicked(GtkButton *unused_button, gpointer user_data)
{
	(void) unused_button;

	if (user_data) {
		const char *name = gtk_file_selection_get_filename(
			GTK_FILE_SELECTION(directory_chooser));

		if (is_directory(name)) {
            gnet_prop_set_string(PROP_MOVE_FILE_PATH, name);
        }
	}

	gtk_widget_destroy(directory_chooser);
	directory_chooser = NULL;
}

void
on_button_config_move_path_clicked(GtkButton *unused_button,
	gpointer unused_udata)
{
	(void) unused_button;
	(void) unused_udata;

	if (directory_chooser) {
		gtk_widget_destroy(directory_chooser);
		directory_chooser = NULL;
	}

	directory_chooser = gtk_file_selection_new(
			_("Please choose where to move files after successful download"));

	gui_signal_connect(
		GTK_FILE_SELECTION(directory_chooser)->ok_button,
		"clicked", button_fs_move_path_clicked, GINT_TO_POINTER(1));
	gui_signal_connect(
		GTK_FILE_SELECTION(directory_chooser)->cancel_button,
		"clicked", button_fs_move_path_clicked, NULL);
	gui_signal_connect(directory_chooser,
		"delete_event", on_directory_chooser_delete_event, NULL);

	gtk_widget_show(directory_chooser);
}

/* Move bad files to */

static GtkWidget *directory_chooser;

void
button_fs_bad_path_clicked(GtkButton *unused_button, gpointer user_data)
{
	(void) unused_button;

	if (user_data) {
		const char *name = gtk_file_selection_get_filename(
			GTK_FILE_SELECTION(directory_chooser));

		if (is_directory(name)) {
            gnet_prop_set_string(PROP_BAD_FILE_PATH, name);
        }
	}

	gtk_widget_destroy(directory_chooser);
	directory_chooser = NULL;
}

void
on_button_config_bad_path_clicked(GtkButton *unused_button,
	gpointer unused_udata)
{
	(void) unused_button;
	(void) unused_udata;

	if (directory_chooser) {
		gtk_widget_destroy(directory_chooser);
		directory_chooser = NULL;
	}

	directory_chooser = gtk_file_selection_new(
				_("Please choose where to move corrupted files"));

	gui_signal_connect(GTK_FILE_SELECTION(directory_chooser)->ok_button,
		"clicked", button_fs_bad_path_clicked, GINT_TO_POINTER(1));
	gui_signal_connect(GTK_FILE_SELECTION(directory_chooser)->cancel_button,
		"clicked", button_fs_bad_path_clicked, NULL);
	gui_signal_connect(directory_chooser,
		"delete_event", on_directory_chooser_delete_event, NULL);

	gtk_widget_show(directory_chooser);
}

/* Local File DB Managment */

void
button_fs_add_dir_clicked(GtkButton *unused_button, gpointer user_data)
{
	(void) unused_button;

	if (user_data) {
        const char *name = gtk_file_selection_get_filename(
			GTK_FILE_SELECTION(directory_chooser));

		if (is_directory(name)) {
			guc_shared_dir_add(name);
		} else {
			g_warning("%s(): ignoring non-directory \"%s\"", G_STRFUNC, name);
		}
	}

	gtk_widget_destroy(directory_chooser);
	directory_chooser = NULL;
}

void
on_button_config_add_dir_clicked(GtkButton *unused_button,
	gpointer unused_udata)
{
	(void) unused_button;
	(void) unused_udata;

	if (directory_chooser) {
		gtk_widget_destroy(directory_chooser);
		directory_chooser = NULL;
	}

	directory_chooser = gtk_file_selection_new(
			_("Please choose a directory to share"));

	gui_signal_connect(
		GTK_FILE_SELECTION(directory_chooser)->ok_button,
		"clicked", button_fs_add_dir_clicked, GINT_TO_POINTER(1));
	gui_signal_connect(GTK_FILE_SELECTION(directory_chooser)->cancel_button,
		"clicked", button_fs_add_dir_clicked, NULL);
	gui_signal_connect(directory_chooser,
		"delete_event", on_directory_chooser_delete_event, NULL);

	gtk_widget_show(directory_chooser);
}
#endif	/* Gtk+ >= 2.6.0 */

void
on_button_config_rescan_dir_clicked(GtkButton *unused_button,
	gpointer unused_udata)
{
	(void) unused_button;
	(void) unused_udata;

	guc_share_scan();
}

void
on_entry_config_netmask_activate(GtkEditable *editable, gpointer unused_data)
{
    gchar *buf;

	(void) unused_data;
    buf = STRTRACK(gtk_editable_get_chars(editable, 0, -1));
    gnet_prop_set_string(PROP_LOCAL_NETMASKS_STRING, buf);
    G_FREE_NULL(buf);
}
FOCUS_TO_ACTIVATE(entry_config_netmask)

/* vi: set ts=4 sw=4 cindent: */
