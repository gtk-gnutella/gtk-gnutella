/*
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

#include "gtk/columns.h"
#include "gtk/downloads_common.h"
#include "gtk/drag.h"
#include "gtk/misc.h"

#include "if/gui_property.h"

#include "lib/cq.h"
#include "lib/htable.h"
#include "lib/utf8.h"

#include "lib/override.h"		/* Must be the last header included */

/*
 * Define this macro to enable consistency checks for the row cache.
 * This will affect performance negatively O(1) -> O(n).
 */
#undef FILEINFO_C_ROW_CACHE_REGRESSION

static GtkCList *clist_download_files;
static GtkCList *clist_download_sources;
static GtkCList *clist_download_aliases;
static GtkCList *clist_download_details;

static htable_t *file_rows;		/* row -> struct fileinfo_data */
static htable_t *source_rows;	/* row -> struct download */
static htable_t *fi_sources;	/* struct download -> row */

static cevent_t *cursor_ev;

#define ROW_SELECT_TIMEOUT	150 /* milliseconds */

static inline void
fileinfo_data_set_row(struct fileinfo_data *file, int row)
{
	fi_gui_file_set_user_data(file, int_to_pointer(row));
}

static inline int
fileinfo_data_get_row(const struct fileinfo_data *file)
{
	return pointer_to_int(fi_gui_file_get_user_data(file));
}

static inline struct fileinfo_data *
get_fileinfo_data(int row)
{
	struct fileinfo_data *file;

	file = htable_lookup(file_rows, int_to_pointer(row));
	g_assert(file);
	g_assert(row == fileinfo_data_get_row(file));

#ifdef FILEINFO_C_ROW_CACHE_REGRESSION
	{
		struct fileinfo_data *x;

		/* NOTE: gtk_clist_get_row_data() is O(n)
		 * Keep it enabled until it has been tested more.
		 */
		x = gtk_clist_get_row_data(clist_download_files, row);
   		g_assert(x == file);
	}
#endif	/* FILEINFO_C_ROW_CACHE_REGRESSION */

	return file;
}

struct fileinfo_data *
fi_gui_get_file_at_cursor(void)
{
	int row = clist_get_cursor_row(clist_download_files);
	return row < 0 ? NULL : get_fileinfo_data(row);
}

static void
cursor_expire(cqueue_t *unused_cq, gpointer unused_udata)
{
	(void) unused_cq;
	(void) unused_udata;

	cursor_ev = NULL;
	fi_gui_files_cursor_update();
}

static void
cursor_update(void)
{
	if (cursor_ev) {
		cq_resched(cursor_ev, ROW_SELECT_TIMEOUT);
	} else {
		cursor_ev = cq_main_insert(ROW_SELECT_TIMEOUT, cursor_expire, NULL);
	}
}

static void
on_clist_select_row(GtkCList *unused_clist,
	int unused_row, int unused_column,
	GdkEvent *unused_event, void *unused_udata)
{
	(void) unused_clist;
	(void) unused_row;
	(void) unused_column;
	(void) unused_event;
	(void) unused_udata;

	cursor_update();
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
		htable_insert(file_rows, int_to_pointer(dst), file);
	}
}

static char *
download_details_get_text(GtkWidget *widget)
{
	GtkCList *clist;
	int row;
	
	clist = GTK_CLIST(widget);
	row = clist_get_cursor_row(clist);
	return clist_copy_text(clist, row, 1);
}

static char *
download_aliases_get_text(GtkWidget *widget)
{
	GtkCList *clist;
	int row;
	
	clist = GTK_CLIST(widget);
	row = clist_get_cursor_row(clist);
	return clist_copy_text(clist, row, 0);
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
	int row = fileinfo_data_get_row(file);

	htable_remove(file_rows, int_to_pointer(row));
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
		htable_insert(file_rows, int_to_pointer(row), file);
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

static inline struct download *
get_source(int row)
{
	struct download *d;

	d = htable_lookup(source_rows, int_to_pointer(row));
	g_assert(pointer_to_int(htable_lookup(fi_sources, d)) == row);

#ifdef FILEINFO_C_ROW_CACHE_REGRESSION
	{
		struct download *x;

		/* NOTE: gtk_clist_get_row_data() is O(n)
		 * Keep it enabled until it has been tested more.
		 */
		x = gtk_clist_get_row_data(clist_download_sources, row);
   		g_assert(x == d);
	}
#endif	/* FILEINFO_C_ROW_CACHE_REGRESSION */

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
	src = pointer_to_int(htable_lookup(fi_sources, d));
	if (src != dst) {
		htable_insert(fi_sources, d, int_to_pointer(dst));
		htable_insert(source_rows, int_to_pointer(dst), d);
	}
}

static void
on_clist_download_sources_row_removed(void *data)
{
	download_check(data);
	htable_remove(fi_sources, data);
	clist_sync_rows(clist_download_sources,
		on_clist_download_sources_row_moved);
}

void
fi_gui_source_show(struct download *key)
{
	const char *titles[c_src_num];
	GtkCList *clist;
	unsigned i;
	int row;

	clist = clist_download_sources;
	g_return_if_fail(clist);
	g_return_if_fail(!htable_contains(fi_sources, key));

	for (i = 0; i < G_N_ELEMENTS(titles); i++) {
		titles[i] = "";
	}
	row = gtk_clist_append(clist, (char **) titles);
	g_return_if_fail(row >= 0);

	htable_insert(fi_sources, key, int_to_pointer(row));
	htable_insert(source_rows, int_to_pointer(row), key);
	gtk_clist_set_row_data_full(clist, row, key,
		on_clist_download_sources_row_removed);
	for (i = 0; i < G_N_ELEMENTS(titles); i++) {
		render_sources(key, row, i);
	}
}

void
fi_gui_source_hide(struct download *key)
{
	void *value;

	g_return_if_fail(clist_download_sources);

	if (htable_lookup_extended(fi_sources, key, NULL, &value)) {
		int row = pointer_to_int(value);

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
		int row = pointer_to_int(iter->data);
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
	*files_ptr = g_slist_prepend(*files_ptr, file);
}

GSList *
fi_gui_get_selected_sources(gboolean unselect)
{
	return fi_gui_collect_selected(clist_download_sources,
			fi_gui_sources_select_helper,
			unselect);
}

GSList *
fi_gui_get_selected_files(gboolean unselect)
{
	return fi_gui_collect_selected(clist_download_files,
			fi_gui_files_select_helper,
			unselect);
}

void
fi_gui_source_update(struct download *d)
{
	void *value;

	download_check(d);

	if (htable_lookup_extended(fi_sources, d, NULL, &value)) {
		int i, row = pointer_to_int(value);

		for (i = 0; i < c_src_num; i++) {
			render_sources(d, row, i);
		}
	}
}

char *
fi_gui_get_detail_at_cursor(void)
{
	return download_details_get_text(GTK_WIDGET(clist_download_details));
}

struct download *
fi_gui_get_source_at_cursor(void)
{
	int row = clist_get_cursor_row(clist_download_sources);
	return row < 0 ? NULL : get_source(row);
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

static void
clist_download_files_init(void)
{
	GtkCList *clist;
	unsigned i;

	STATIC_ASSERT(c_fi_num == FILEINFO_VISIBLE_COLUMNS);

	clist = GTK_CLIST(gtk_clist_new(c_fi_num));
	clist_download_files = clist;

	gtk_clist_set_shadow_type(clist, GTK_SHADOW_IN);
	gtk_clist_set_selection_mode(clist, GTK_SELECTION_EXTENDED);
	gtk_clist_column_titles_show(clist);
	gtk_clist_set_compare_func(clist, fileinfo_data_cmp_func);
	gtk_clist_set_sort_column(clist, 0);
	gtk_clist_set_sort_type(clist, GTK_SORT_ASCENDING);

	for (i = 0; i < c_fi_num; i++) {
		GtkWidget *label;

		gtk_clist_set_column_justification(clist, i,
			fi_gui_files_column_justify_right(i)
				? GTK_JUSTIFY_RIGHT
				: GTK_JUSTIFY_LEFT);

		label = gtk_label_new(fi_gui_files_column_title(i));
    	gtk_widget_show(label);
    	gtk_misc_set_alignment(GTK_MISC(label), 0.0, 0.5);
		gtk_clist_set_column_widget(clist, i, label);
    	gtk_clist_set_column_name(clist, i,
			gtk_label_get_text(GTK_LABEL(label)));
	}

	clist_restore_visibility(clist, PROP_FILE_INFO_COL_VISIBLE);
	clist_restore_widths(clist, PROP_FILE_INFO_COL_WIDTHS);

	gui_signal_connect(clist,
		"click-column", on_clist_download_files_click_column, NULL);
	gui_signal_connect(clist, "select-row", on_clist_select_row, NULL);
}

void
fi_gui_files_filter_changed(void)
{
	GtkCList *clist = clist_download_files;

	g_return_if_fail(clist);
	gtk_clist_set_column_title(clist, c_fi_filename,
		fi_gui_files_column_title(c_fi_filename));
}

GtkWidget *
fi_gui_sources_widget(void)
{
	return GTK_WIDGET(clist_download_sources);
}

GtkWidget *
fi_gui_files_widget(void)
{
	return GTK_WIDGET(clist_download_files);
}

GtkWidget *
fi_gui_files_widget_new(void)
{
	clist_download_files_init();
	return fi_gui_files_widget();
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
	file_rows = htable_create(HASH_KEY_SELF, 0);
	source_rows = htable_create(HASH_KEY_SELF, 0);
	fi_sources = htable_create(HASH_KEY_SELF, 0);

	clist_download_aliases = GTK_CLIST(
		gui_main_window_lookup("clist_download_aliases"));
	clist_download_details = GTK_CLIST(
		gui_main_window_lookup("clist_download_details"));
	clist_download_sources = GTK_CLIST(
		gui_main_window_lookup("clist_download_sources"));

	{
		GtkCList *clist = clist_download_details;

		gtk_clist_set_selection_mode(clist, GTK_SELECTION_EXTENDED);
		gtk_clist_set_column_auto_resize(clist, 0, TRUE);
		gui_signal_connect(clist,
			"key-press-event", on_details_key_press_event, NULL);

		clipboard_attach(GTK_WIDGET(clist));
		drag_attach_text(GTK_WIDGET(clist), download_details_get_text);
	}

	{
		GtkCList *clist = clist_download_aliases;

		drag_attach_text(GTK_WIDGET(clist), download_aliases_get_text);
	}

	{
		GtkCList *clist = clist_download_sources;
		unsigned i;

		clist_restore_widths(clist, PROP_SOURCES_COL_WIDTHS);
		gtk_clist_column_titles_passive(clist);
		for (i = 0; i < c_src_num; i++) {
			const char *title;
			GtkLabel *label;

			label = GTK_LABEL(gtk_clist_get_column_widget(clist, i));
			title = gtk_label_get_text(label);
			gtk_clist_set_column_name(clist, i, EMPTY_STRING(title));
		}
		widget_add_popup_menu(GTK_WIDGET(clist), fi_gui_sources_get_popup_menu);	
	}
	fi_gui_common_init();
}

void
fi_gui_shutdown(void)
{
	cq_cancel(&cursor_ev);

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

	htable_free_null(&fi_sources);
	htable_free_null(&file_rows);
	htable_free_null(&source_rows);
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
fi_gui_files_freeze(void)
{
	gtk_clist_freeze(clist_download_details);
	gtk_clist_freeze(clist_download_files);
	gtk_clist_freeze(clist_download_sources);
}

void
fi_gui_files_thaw(void)
{
	gtk_clist_thaw(clist_download_details);
	gtk_clist_thaw(clist_download_files);
	gtk_clist_thaw(clist_download_sources);
}

void
fi_gui_clear_details(void)
{
	GtkCList *clist = clist_download_details;

	g_return_if_fail(clist);
    gtk_clist_clear(clist);
}

void
fi_gui_append_detail(const enum fi_gui_detail unused_id,
	const gchar *name, const gchar *value)
{
	GtkCList *clist = clist_download_details;
 	const gchar *titles[2];

	(void) unused_id;
	g_return_if_fail(clist);
	titles[0] = name;
	titles[1] = EMPTY_STRING(value);
    gtk_clist_append(clist, (gchar **) titles);
}

/* vi: set ts=4 sw=4 cindent: */
