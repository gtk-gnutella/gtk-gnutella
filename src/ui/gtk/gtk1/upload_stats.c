/*
 * Copyright (c) 2001-2003, Richard Eckart
 * Copyright (c) 2002, Michael Tesch
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
 * Keep track of which files we send away, and how often.
 *
 * Statistics are kept by _FILENAME_ and file size, not by actual path,
 * so two files with the same name and size will be counted in the same
 * bin. I dont see this as a limitation because the user wouldn't be able
 * to differentiate the files anyway.
 *
 * This could be extended to keep the entire path to each file and
 * optionally show the entire path, but..
 *
 * The 'upload_history' file has the following format:
 *
 *		- "<url-escaped filename> <file size> <attempts> <completions>"
 *
 * @todo
 * TODO: Add a check to make sure that all of the files still exist(?)
 *       grey them out if they dont, optionally remove them from the stats
 *       list (when 'Clear Non-existant Files' is clicked).
 *
 * @author Raphael Manfredi
 * @date 2001-2004
 * @author Michael Tesch
 * @date 2002
 *
 * Released with gtk-gnutella & its license
 */

#include "common.h"

#include "gtk/gui.h"

#include "if/ui/gtk/upload_stats.h"

#include "gtk/columns.h"
#include "gtk/misc.h"
#include "gtk/settings.h"
#include "gtk/upload_stats.h"
#include "gtk/upload_stats_cb.h"

#include "lib/str.h"
#include "lib/stringify.h"
#include "lib/timestamp.h"
#include "lib/utf8.h"

#include "lib/override.h"		/* Must be the last header included */

static GtkCList *
clist_ul_stats(void)
{
	static GtkCList *clist;

	if (!clist) {
		clist = GTK_CLIST(gui_main_window_lookup("clist_ul_stats"));
	}
	return clist;
}

static inline void
ul_stats_set_user_data(struct ul_stats *us, void *user_data)
{
	us->user_data = user_data;
}

static inline void *
ul_stats_get_user_data(const struct ul_stats *us)
{
	return us->user_data;
}

static inline void
ul_stats_set_row(struct ul_stats *us, int row)
{
	ul_stats_set_user_data(us, int_to_pointer(row));
}

static inline int
ul_stats_get_row(const struct ul_stats *us)
{
	return pointer_to_int(ul_stats_get_user_data(us));
}

static void
ul_stats_invalidate(struct ul_stats *us)
{
	ul_stats_set_row(us, -1);
}

static void
on_clist_ul_stats_row_moved(int dst, void *user_data)
{
	struct ul_stats *us = user_data;
	int src = ul_stats_get_row(us);

	if (src != dst) {
		ul_stats_set_row(us, dst);
	}
}

static void
on_clist_ul_stats_row_removed(void *data)
{
	struct ul_stats *us = data;

	ul_stats_invalidate(us);
	clist_sync_rows(clist_ul_stats(), on_clist_ul_stats_row_moved);
}

/* Public functions */
G_GNUC_COLD void
upload_stats_gui_init(void)
{
	enum c_us i;

	for (i = 0; i < c_us_num; i++) {
		gboolean justify_left = FALSE;

		switch (i) {
		case c_us_filename: justify_left = TRUE; break;
		case c_us_size:		justify_left = FALSE; break;
		case c_us_attempts: justify_left = FALSE; break;
		case c_us_complete: justify_left = FALSE; break;
		case c_us_norm:		justify_left = FALSE; break;
		case c_us_rtime:	justify_left = TRUE; break;
		case c_us_dtime:	justify_left = TRUE; break;
		case c_us_num:		g_assert_not_reached();
		}
		gtk_clist_set_column_justification(clist_ul_stats(), i,
			justify_left ? GTK_JUSTIFY_LEFT : GTK_JUSTIFY_RIGHT);
	}
	clist_restore_widths(clist_ul_stats(), PROP_UL_STATS_COL_WIDTHS);
    gtk_clist_set_compare_func(clist_ul_stats(), compare_ul_norm);
}

void
upload_stats_gui_shutdown(void)
{
	clist_save_widths(clist_ul_stats(), PROP_UL_STATS_COL_WIDTHS);
}

void
upload_stats_gui_add(struct ul_stats *us)
{
	GtkCList *clist = clist_ul_stats();
	const gchar *rowdata[c_us_num];
	enum c_us i;
	int row;
	char size_tmp[16];
	char attempts_tmp[16];
	char complete_tmp[16];
	char norm_tmp[16];
	char rtime_tmp[64];
	char dtime_tmp[64];

	g_strlcpy(size_tmp, short_size(us->size, show_metric_units()),
		sizeof size_tmp);
	str_bprintf(attempts_tmp, sizeof attempts_tmp, "%u", us->attempts);
	str_bprintf(complete_tmp, sizeof complete_tmp, "%u", us->complete);
	str_bprintf(norm_tmp, sizeof norm_tmp, "%.3f", us->norm);
	if (us->rtime) {
		timestamp_to_string_buf(us->rtime, rtime_tmp, sizeof rtime_tmp);
	} else {
		rtime_tmp[0] = '\0';
	}
	if (us->dtime) {
		timestamp_to_string_buf(us->dtime, dtime_tmp, sizeof dtime_tmp);
	} else {
		dtime_tmp[0] = '\0';
	}

	for (i = 0; i < c_us_num; i++)
	switch (i) {
	case c_us_filename:
		rowdata[i] = lazy_utf8_to_ui_string(us->filename);
		break;
	case c_us_size: 	rowdata[i] = size_tmp; break;
	case c_us_attempts: rowdata[i] = attempts_tmp; break;
	case c_us_complete: rowdata[i] = complete_tmp; break;
	case c_us_norm: 	rowdata[i] = norm_tmp; break;
	case c_us_rtime: 	rowdata[i] = rtime_tmp; break;
	case c_us_dtime: 	rowdata[i] = dtime_tmp; break;
	case c_us_num:		g_assert_not_reached();
	}

    row = gtk_clist_append(clist, deconstify_gpointer(rowdata));
	g_return_if_fail(row >= 0);

	ul_stats_set_row(us, row);
	gtk_clist_set_row_data_full(clist, row, us, on_clist_ul_stats_row_removed);

    /* FIXME: should use auto_sort? */
	if (0 == clist->freeze_count) {
		gtk_clist_sort(clist);
		clist_sync_rows(clist, on_clist_ul_stats_row_moved);
	}
}


/**
 * Called when the filename of a row of the upload stats should be updated
 */
void
upload_stats_gui_update_name(struct ul_stats *us)
{
	GtkCList *clist = clist_ul_stats();
	int row;

	/* find this file in the clist_ul_stats */
	row = ul_stats_get_row(us);
	g_return_if_fail(row >= 0);

	gtk_clist_set_text(clist, row, c_us_filename,
		lazy_utf8_to_ui_string(us->filename));

	/* FIXME: use auto-sort? */
	if (0 == clist->freeze_count) {
		gtk_clist_sort(clist);
		clist_sync_rows(clist, on_clist_ul_stats_row_moved);
	}
}


/**
 * Called when a row of the upload stats should be updated
 */
void
upload_stats_gui_update_model(struct ul_stats *us)
{
	GtkCList *clist = clist_ul_stats();
	enum c_us i;
	int row;

	row = ul_stats_get_row(us);
	g_return_if_fail(row >= 0);

	for (i = 0; i < c_us_num; i++) {
		const char *text = NULL;
		char tmpstr[16];

		switch (i) {
		case c_us_filename:
		case c_us_size:
			/* Never updated, only initialized */
			continue;
		case c_us_attempts:
			text = uint64_to_string(us->attempts);
			break;
		case c_us_complete:
			text = uint64_to_string(us->complete);
			break;
		case c_us_norm:
			str_bprintf(tmpstr, sizeof tmpstr, "%.3f", us->norm);
			text = tmpstr;
			break;
		case c_us_rtime:
			text = us->rtime ? timestamp_to_string(us->rtime) : "";
			break;
		case c_us_dtime:
			text = us->dtime ? timestamp_to_string(us->dtime) : "";
			break;
		case c_us_num:
			text = NULL;
			g_assert_not_reached();
		}
		gtk_clist_set_text(clist, row, i, text);
	}

	/* FIXME: use auto-sort? */
	if (0 == clist->freeze_count) {
		gtk_clist_sort(clist);
		clist_sync_rows(clist, on_clist_ul_stats_row_moved);
	}
}

void
upload_stats_gui_clear_model(void)
{
	gtk_clist_clear(clist_ul_stats());
}

void
upload_stats_gui_freeze(void)
{
	gtk_clist_freeze(clist_ul_stats());
}

void
upload_stats_gui_thaw(void)
{
	GtkCList *clist = clist_ul_stats();

	g_return_if_fail(clist);
	gtk_clist_thaw(clist);
	if (0 == clist->freeze_count) {
		gtk_clist_sort(clist);
		clist_sync_rows(clist, on_clist_ul_stats_row_moved);
	}
}

/* vi: set ts=4 sw=4 cindent: */
