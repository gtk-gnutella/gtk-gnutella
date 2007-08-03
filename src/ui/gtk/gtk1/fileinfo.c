/*
 * $Id$
 *
 * Copyright (c) 2003, Richard Eckart
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

/**
 * @ingroup gtk
 * @file
 *
 * Displaying of file information in the GUI.
 *
 * @author Richard Eckart
 * @date 2003
 */

#include "gtk/gui.h"

RCSID("$Id$")

#include "downloads_cb.h"

#include "gtk/columns.h"
#include "gtk/downloads_common.h"
#include "gtk/drag.h"
#include "gtk/filter.h"
#include "gtk/gtk-missing.h"
#include "gtk/gtkcolumnchooser.h"
#include "gtk/misc.h"
#include "gtk/settings.h"
#include "gtk/statusbar.h"

#include "if/gui_property.h"
#include "if/gui_property_priv.h"

#include "lib/atoms.h"
#include "lib/cq.h"
#include "lib/glib-missing.h"
#include "lib/hashlist.h"
#include "lib/url.h"
#include "lib/utf8.h"

#include "lib/override.h"		/* Must be the last header included */

static GtkCList *clist_download_files;
static GtkCList *clist_download_sources;
static GtkCList *clist_download_aliases;
static GtkCList *clist_download_details;

static GHashTable *file_rows;		/* row -> struct fileinfo_data */
static GHashTable *source_rows;		/* row -> struct download */
static GHashTable *fi_sources;		/* struct download -> row */

static int download_files_selected_row = -1;
static int download_sources_selected_row = -1;
static int download_aliases_selected_row = -1;
static int download_details_selected_row = -1;

static cevent_t *row_selected_ev;

#define ROW_SELECT_TIMEOUT	150 /* milliseconds */

static inline void
fileinfo_data_set_row(struct fileinfo_data *file, int row)
{
	fi_gui_file_set_user_data(file, GINT_TO_POINTER(row));
}

static inline int
fileinfo_data_get_row(const struct fileinfo_data *file)
{
	return GPOINTER_TO_INT(fi_gui_file_get_user_data(file));
}

static void
render_files(const struct fileinfo_data *file, int row, int column)
{
	const char *text;

	g_return_if_fail(file);
	g_return_if_fail(row >= 0);

	text = fi_gui_file_column_text(file, column);
	gtk_clist_set_text(clist_download_files, row, column, EMPTY_STRING(text));
}

static void
on_clist_download_files_row_moved(int dst, void *user_data)
{
	struct fileinfo_data *file = user_data;
	int src = fileinfo_data_get_row(file);

	if (src != dst) {
		fileinfo_data_set_row(file, dst);
		g_hash_table_insert(file_rows, GINT_TO_POINTER(dst), file);
	}
}

static char * 
download_details_get_text(GtkWidget *widget)
{
	return clist_copy_text(GTK_CLIST(widget), download_details_selected_row, 1);
}

static char * 
download_aliases_get_text(GtkWidget *widget)
{
	return clist_copy_text(GTK_CLIST(widget), download_aliases_selected_row, 0);
}

void
fi_gui_file_invalidate(struct fileinfo_data *file)
{
	fileinfo_data_set_row(file, -1);
}

static void
on_clist_download_files_row_removed(void *data)
{
	struct fileinfo_data *file = data;

	g_hash_table_remove(file_rows,
		GINT_TO_POINTER(fileinfo_data_get_row(file)));
	fi_gui_file_invalidate(file);
	clist_sync_rows(clist_download_files, on_clist_download_files_row_moved);
}

void
fi_gui_file_show(struct fileinfo_data *file)
{
	GtkCList *clist = clist_download_files;
	unsigned i;
	int row;

	g_return_if_fail(clist);
	gtk_clist_freeze(clist);

	row = fileinfo_data_get_row(file);
	if (row < 0) {
		const char *titles[c_fi_num];

		for (i = 0; i < G_N_ELEMENTS(titles); i++) {
			titles[i] = "";
		}
		row = gtk_clist_append(clist_download_files, (char **) &titles);
		fileinfo_data_set_row(file, row);
		g_hash_table_insert(file_rows, GINT_TO_POINTER(row), file);
	}
	gtk_clist_set_row_data_full(clist, row, file,
		on_clist_download_files_row_removed);
	for (i = 0; i < c_fi_num; i++) {
		render_files(file, row, i);
	}
	gtk_clist_thaw(clist);
}

void
fi_gui_file_hide(struct fileinfo_data *file)
{
	int row = fileinfo_data_get_row(file);

	if (row >= 0) {
		if (clist_download_files) {
			gtk_clist_remove(clist_download_files, row);
		}
		fi_gui_file_invalidate(file);
	}
}

static inline struct fileinfo_data *
get_fileinfo_data(int row)
{
	struct fileinfo_data *file;

	file = g_hash_table_lookup(file_rows, GINT_TO_POINTER(row));
	g_assert(file);
	g_assert(row == fileinfo_data_get_row(file));

#if 1
	{
		struct fileinfo_data *x;

		/* NOTE: gtk_clist_get_row_data() is O(n)
		 * Keep it enabled until it has been tested more.
		 */
		x = gtk_clist_get_row_data(clist_download_files, row);
   		g_assert(x == file);
	}
#endif

	return file;
}

static inline struct download *
get_source(int row)
{
	struct download *d;

	d = g_hash_table_lookup(source_rows, GINT_TO_POINTER(row));
	g_assert(GPOINTER_TO_INT(g_hash_table_lookup(fi_sources, d)) == row);

#if 1
	{
		struct download *x;

		/* NOTE: gtk_clist_get_row_data() is O(n)
		 * Keep it enabled until it has been tested more.
		 */
		x = gtk_clist_get_row_data(clist_download_sources, row);
   		g_assert(x == d);
	}
#endif

	download_check(d);
	return d;
}

static void
render_sources(struct download *d, int row, int column)
{
	g_return_if_fail(d);
	g_return_if_fail(row >= 0);

	gtk_clist_set_text(clist_download_sources, row, column,
		fi_gui_source_column_text(d, column));
}

void
fi_gui_clear_aliases(void)
{
   	gtk_clist_clear(clist_download_aliases);
}

void
fi_gui_clear_sources(void)
{
   	gtk_clist_clear(clist_download_sources);
}


void
fi_gui_show_aliases(const char * const *aliases)
{
	GtkCList *clist;
	size_t i;

	g_return_if_fail(aliases);

	clist = clist_download_aliases;
	g_return_if_fail(clist);

    gtk_clist_freeze(clist);
    gtk_clist_clear(clist);

	for (i = 0; NULL != aliases[i]; i++) {
		const char *titles[1];

		titles[0] = lazy_filename_to_ui_string(aliases[i]);
        gtk_clist_append(clist, (char **) &titles);
	}
    gtk_clist_thaw(clist);
}

static void
on_clist_download_sources_row_moved(int dst, void *user_data)
{
	struct download *d = user_data;
	int src;

	download_check(d);
	src = GPOINTER_TO_INT(g_hash_table_lookup(fi_sources, d));
	if (src != dst) {
		g_hash_table_insert(fi_sources, d, GINT_TO_POINTER(dst));
		g_hash_table_insert(source_rows, GINT_TO_POINTER(dst), d);
	}
}

static void
on_clist_download_sources_row_removed(void *data)
{
	download_check(data);
	g_hash_table_remove(fi_sources, data);
	clist_sync_rows(clist_download_sources,
		on_clist_download_sources_row_moved);
}

void
fi_gui_source_add(struct download *key)
{
	const char *titles[c_fi_sources];
	GtkCList *clist;
	unsigned i;
	int row;

	clist = clist_download_sources;
	g_return_if_fail(clist);
	g_return_if_fail(
		!g_hash_table_lookup_extended(fi_sources, key, NULL, NULL));

	for (i = 0; i < G_N_ELEMENTS(titles); i++) {
		titles[i] = "";
	}
	row = gtk_clist_append(clist, (char **) titles);
	g_return_if_fail(row >= 0);

	g_hash_table_insert(fi_sources, key, GINT_TO_POINTER(row));
	g_hash_table_insert(source_rows, GINT_TO_POINTER(row), key);
	gtk_clist_set_row_data_full(clist, row, key,
		on_clist_download_sources_row_removed);
	for (i = 0; i < c_fi_sources; i++) {
		render_sources(key, row, i);
	}
}

void
fi_gui_source_remove(struct download *key)
{
	void *value;

	g_return_if_fail(clist_download_sources);

	if (g_hash_table_lookup_extended(fi_sources, key, NULL, &value)) {
		int row = GPOINTER_TO_INT(value);

		gtk_clist_remove(clist_download_sources, row);
	}
}

static GSList *
fi_gui_collect_selected(GtkCList *clist,
	void (*func)(GtkCList *clist, int row, void *user_data),
	gboolean unselect)
{
	const GList *iter;
	GSList *list;

	g_return_val_if_fail(clist, NULL);
	g_return_val_if_fail(func, NULL);

	gtk_clist_freeze(clist);
	list = NULL;
	for (iter = clist->selection; NULL != iter; iter = g_list_next(iter)) {
		int row = GPOINTER_TO_INT(iter->data);
		(*func)(clist, row, &list);
	}
	if (unselect) {
		gtk_clist_unselect_all(clist);
	}
	gtk_clist_thaw(clist);
	return list;
}


static void
fi_gui_sources_select_helper(GtkCList *clist, int row, void *user_data)
{
	GSList **sources_ptr = user_data;

	g_return_if_fail(clist);
	g_return_if_fail(row >= 0);

	*sources_ptr = g_slist_prepend(*sources_ptr, get_source(row));
}

static void
fi_gui_files_select_helper(GtkCList *unused_clist, int row, void *user_data)
{
	GSList **files_ptr = user_data;
	struct fileinfo_data *file;

	(void) unused_clist;

	file = get_fileinfo_data(row);
	*files_ptr = g_slist_prepend(*files_ptr, GUINT_TO_POINTER(file));
}

static void
fi_gui_sources_of_selected_files_helper(GtkCList *unused_clist,
	int row, void *user_data)
{
	GSList **files_ptr = user_data;
	struct fileinfo_data *file;

	(void) unused_clist;

	file = get_fileinfo_data(row);
	*files_ptr = g_slist_concat(fi_gui_file_get_sources(file), *files_ptr);
}

GSList *
fi_gui_sources_select(gboolean unselect)
{
	return fi_gui_collect_selected(clist_download_sources,
			fi_gui_sources_select_helper,
			unselect);
}

GSList *
fi_gui_files_select(gboolean unselect)
{
	return fi_gui_collect_selected(clist_download_files,
			fi_gui_files_select_helper,
			unselect);
}

GSList *
fi_gui_sources_of_selected_files(gboolean unselect)
{
	return fi_gui_collect_selected(clist_download_files,
			fi_gui_sources_of_selected_files_helper,
			unselect);
}

void
fi_gui_source_update(struct download *d)
{
	void *value;

	download_check(d);

	if (g_hash_table_lookup_extended(fi_sources, d, NULL, &value)) {
		int i, row = GPOINTER_TO_INT(value);

		for (i = 0; i < c_fi_sources; i++) {
			render_sources(d, row, i);
		}
	}
}

void
fi_gui_update_display(time_t unused_now)
{
	(void) unused_now;

	if (!main_gui_window_visible())
		return;

	g_return_if_fail(clist_download_files);
	if (!GTK_WIDGET_DRAWABLE(GTK_WIDGET(clist_download_files)))
		return;

	gtk_clist_freeze(clist_download_files);
	fi_gui_file_process_updates();
	gtk_clist_thaw(clist_download_files);
}

char *
fi_gui_get_detail_at_cursor(void)
{
	return download_details_get_text(GTK_WIDGET(clist_download_details));
}

struct download *
fi_gui_get_source_at_cursor(void)
{
	int row = download_sources_selected_row;
	return row < 0 ? NULL : get_source(row);
}

struct fileinfo_data *
fi_gui_get_file_at_cursor(void)
{
	int row = download_files_selected_row;
	return row < 0 ? NULL : get_fileinfo_data(row);
}

static void
row_selected_expire(cqueue_t *unused_cq, gpointer unused_udata)
{
	struct fileinfo_data *file;

	(void) unused_cq;
	(void) unused_udata;

	row_selected_ev = NULL;

	fi_gui_clear_details();
	file = fi_gui_get_file_at_cursor();
	if (file) {
		fi_gui_set_details(file);
	}
}

static void
row_selected_changed(int row)
{
	download_files_selected_row = row;
	if (row_selected_ev) {
		cq_resched(callout_queue, row_selected_ev, ROW_SELECT_TIMEOUT);
	} else {
		row_selected_ev = cq_insert(callout_queue, ROW_SELECT_TIMEOUT,
							row_selected_expire, NULL);
	}
}

static void
on_clist_download_files_select_row(GtkCList *unused_clist,
	int row, int unused_column, GdkEvent *unused_event, void *unused_udata)
{
	(void) unused_clist;
	(void) unused_column;
	(void) unused_event;
	(void) unused_udata;

	row_selected_changed(row);
}

static void
on_clist_download_files_unselect_row(GtkCList *unused_clist,
	int row, int unused_column,
	GdkEvent *unused_event, void *unused_udata)
{
	(void) unused_clist;
	(void) unused_column;
	(void) unused_event;
	(void) unused_udata;

	if (
		download_files_selected_row >= 0 &&
		download_files_selected_row == row
	) {
		row_selected_changed(-1);
	}
}

static int
fileinfo_data_cmp_func(GtkCList *clist, const void *p, const void *q)
{
	const GtkCListRow *a = p, *b = q;

	return fileinfo_data_cmp(a->data, b->data, clist->sort_column);
}

static void
on_clist_download_files_click_column(GtkCList *clist, int column,
	void *unused_udata)
{
	GtkSortType order;

	g_return_if_fail(UNSIGNED(column < c_fi_num));
	(void) unused_udata;

    gtk_clist_freeze(clist);
	if (
		column != clist->sort_column ||
		GTK_SORT_ASCENDING != clist->sort_type
	) {
		order = GTK_SORT_ASCENDING;
	} else {
		order = GTK_SORT_DESCENDING;
	}
	gtk_clist_set_sort_column(clist, column);
	gtk_clist_set_sort_type(clist, order);
	gtk_clist_sort(clist);
	clist_sync_rows(clist, on_clist_download_files_row_moved);
    gtk_clist_thaw(clist);
}

static char *
download_files_get_file_url(GtkWidget *unused_widget)
{
	struct fileinfo_data *file;

	(void) unused_widget;

	file = fi_gui_get_file_at_cursor();
	return file ? fi_gui_file_get_file_url(file) : NULL;
}

static void
clist_download_files_init(void)
{
	static const struct {
		const int id;
		const char * const title;
		gboolean justify_right;
	} columns[] = {
		{ c_fi_filename, N_("Filename"), 	FALSE },
    	{ c_fi_size,	 N_("Size"),	 	TRUE },
    	{ c_fi_progress, N_("Progress"), 	TRUE },
    	{ c_fi_rx, 		 N_("RX"), 			TRUE },
    	{ c_fi_done,	 N_("Downloaded"), 	TRUE },
    	{ c_fi_uploaded, N_("Uploaded"), 	TRUE },
    	{ c_fi_sources,  N_("Sources"),  	FALSE },
    	{ c_fi_status,   N_("Status"),	 	FALSE }
	};
	GtkCList *clist;
	unsigned i;

	STATIC_ASSERT(FILEINFO_VISIBLE_COLUMNS == G_N_ELEMENTS(columns));
	STATIC_ASSERT(c_fi_num == G_N_ELEMENTS(columns));

	clist = GTK_CLIST(gtk_clist_new(G_N_ELEMENTS(columns)));
	clist_download_files = clist;

	gtk_clist_set_shadow_type(clist, GTK_SHADOW_IN);
	gtk_clist_set_selection_mode(clist, GTK_SELECTION_EXTENDED);
	gtk_clist_column_titles_show(clist);
	gtk_clist_set_compare_func(clist, fileinfo_data_cmp_func);
	gtk_clist_set_sort_column(clist, 0);
	gtk_clist_set_sort_type(clist, GTK_SORT_ASCENDING);

	for (i = 0; i < G_N_ELEMENTS(columns); i++) {
		GtkWidget *label;
		int column;

		column = columns[i].id;
		gtk_clist_set_column_justification(clist, column,
			columns[i].justify_right ? GTK_JUSTIFY_RIGHT : GTK_JUSTIFY_LEFT);
		label = gtk_label_new(_(columns[i].title));
    	gtk_widget_show(label);
    	gtk_misc_set_alignment(GTK_MISC(label), 0.0, 0.5);
		gtk_clist_set_column_widget(clist, column, label);
    	gtk_clist_set_column_name(clist, column,
			gtk_label_get_text(GTK_LABEL(label)));
	}

	clist_restore_visibility(clist, PROP_FILE_INFO_COL_VISIBLE);
	clist_restore_widths(clist, PROP_FILE_INFO_COL_WIDTHS);

	gui_signal_connect(clist, "click-column",
		on_clist_download_files_click_column, NULL);
	gui_signal_connect(clist, "select-row",
		on_clist_download_files_select_row, NULL);
	gui_signal_connect(clist, "unselect-row",
		on_clist_download_files_unselect_row, NULL);

	gui_signal_connect(clist, "key-press-event",
		on_files_key_press_event, NULL);
	gui_signal_connect(clist, "button-press-event",
		on_files_button_press_event, NULL);

	drag_attach(GTK_WIDGET(clist), download_files_get_file_url);

    gtk_clist_freeze(clist_download_files);
	fi_gui_files_visualize();
    gtk_clist_thaw(clist_download_files);
}

GtkWidget *
fi_gui_files_widget_new(void)
{
	clist_download_files_init();
	return GTK_WIDGET(clist_download_files);
}

void
fi_gui_files_widget_destroy(void)
{
	if (clist_download_files) {
		clist_save_visibility(clist_download_files,
			PROP_FILE_INFO_COL_VISIBLE);
		clist_save_widths(clist_download_files,
			PROP_FILE_INFO_COL_WIDTHS);
		gtk_widget_destroy(GTK_WIDGET(clist_download_files));
		clist_download_files = NULL;
	}
}

void
fi_gui_init(void)
{
	fi_gui_common_init();

	file_rows = g_hash_table_new(NULL, NULL);
	source_rows = g_hash_table_new(NULL, NULL);
	fi_sources = g_hash_table_new(NULL, NULL);

	clist_download_aliases = GTK_CLIST(
		gui_main_window_lookup("clist_download_aliases"));
	clist_download_details = GTK_CLIST(
		gui_main_window_lookup("clist_download_details"));
	clist_download_sources = GTK_CLIST(
		gui_main_window_lookup("clist_download_sources"));

	{
		GtkCList *clist;
		
		clist = GTK_CLIST(gui_main_window_lookup("clist_download_details"));
		gtk_clist_set_selection_mode(clist, GTK_SELECTION_EXTENDED);
		clist_watch_cursor(clist, &download_details_selected_row);
		gui_signal_connect(clist, "key-press-event",
			on_details_key_press_event, NULL);

		clipboard_attach(GTK_WIDGET(clist));
		drag_attach(GTK_WIDGET(clist), download_details_get_text);
	}

	{
		GtkCList *clist = clist_download_aliases;

		drag_attach(GTK_WIDGET(clist), download_aliases_get_text);
		clist_watch_cursor(clist, &download_aliases_selected_row);
	}

	{
		GtkCList *clist;
		unsigned i;

		clist = GTK_CLIST(gui_main_window_lookup("clist_download_sources"));
		clist_download_sources = clist;

		clist_restore_widths(clist, PROP_SOURCES_COL_WIDTHS);
		gtk_clist_column_titles_passive(clist);
		for (i = 0; i < c_src_num; i++) {
			const char *title;
			GtkLabel *label;

			label = GTK_LABEL(gtk_clist_get_column_widget(clist, i));
			title = gtk_label_get_text(label);
			gtk_clist_set_column_name(clist, i, EMPTY_STRING(title));
		}

		clist_watch_cursor(clist, &download_sources_selected_row);
		gui_signal_connect(clist, "button-press-event",
			on_sources_button_press_event, NULL);
	}
}

void
fi_gui_shutdown(void)
{
	cq_cancel(callout_queue, &row_selected_ev);

	clist_save_visibility(clist_download_files, PROP_FILE_INFO_COL_VISIBLE);
	clist_save_widths(clist_download_files, PROP_FILE_INFO_COL_WIDTHS);
	clist_save_widths(clist_download_sources, PROP_SOURCES_COL_WIDTHS);

	fi_gui_common_shutdown();

	if (clist_download_files) {
		gtk_widget_destroy(GTK_WIDGET(clist_download_files));
		clist_download_files = NULL;
	}
	if (clist_download_aliases) {
		gtk_widget_destroy(GTK_WIDGET(clist_download_aliases));
		clist_download_aliases = NULL;
	}
	if (clist_download_sources) {
		gtk_widget_destroy(GTK_WIDGET(clist_download_sources));
		clist_download_sources = NULL;
	}

	g_hash_table_destroy(fi_sources);
	fi_sources = NULL;

	g_hash_table_destroy(file_rows);
	file_rows = NULL;
	g_hash_table_destroy(source_rows);
	source_rows = NULL;
}

void
fi_gui_files_unselect_all(void)
{
	GtkCList *clist = clist_download_files;

	g_return_if_fail(clist);
	gtk_clist_unselect_all(clist);
}

void
fi_gui_file_select(struct fileinfo_data *file)
{
	GtkCList *clist = clist_download_files;
	int row;

	g_return_if_fail(file);
	g_return_if_fail(clist);
	
   	row = fileinfo_data_get_row(file);
	g_return_if_fail(row >= 0);

	gtk_clist_select_row(clist, row, 0);
}

void
fi_gui_files_foreach(fi_gui_files_foreach_cb func, void *user_data)
{
	GtkCList *clist = clist_download_files;
	int row;

	g_return_if_fail(func);
	g_return_if_fail(clist);
	
	gtk_clist_freeze(clist);
    for (row = 0; row < clist->rows; row++) {
		(*func)(get_fileinfo_data(row), user_data);
	}
	gtk_clist_thaw(clist);
}

void
fi_gui_files_configure_columns(void)
{
    GtkWidget *cc;

	g_return_if_fail(clist_download_files);

    cc = gtk_column_chooser_new(GTK_WIDGET(clist_download_files));
    gtk_menu_popup(GTK_MENU(cc), NULL, NULL, NULL, NULL, 1,
		gtk_get_current_event_time());
}

void
fi_gui_files_freeze(void)
{
	g_return_if_fail(clist_download_files);
	gtk_clist_freeze(clist_download_files);
}

void
fi_gui_files_thaw(void)
{
	g_return_if_fail(clist_download_files);
	gtk_clist_thaw(clist_download_files);
}

/* vi: set ts=4 sw=4 cindent: */
