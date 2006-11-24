/*
 * $Id$
 *
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

#include "gtk/gui.h"

RCSID("$Id$")

#include "gtk/upload_stats.h"
#include "gtk/columns.h"
#include "gtk/settings.h"

#include "lib/misc.h"
#include "lib/glib-missing.h"
#include "lib/override.h"		/* Must be the last header included */

/* Private variables */
static gint ul_rows = 0;

/* Private functions */

static GtkCList *
clist_ul_stats(void)
{
	return GTK_CLIST(gui_main_window_lookup("clist_ul_stats"));
}

/**
 * This is me, dreaming of gtk 2.0...
 */
static gint
ul_find_row_by_upload(const gchar *name, guint64 size, struct ul_stats **s)
{
    GtkCList *clist = clist_ul_stats();
	gint i;

	/* go through the clist_ul_stats, looking for the file...
	 * blame gtk/glib, not me...
	 */
	for (i = 0; i < ul_rows; i++) {
		gchar *filename;
		struct ul_stats *us;

		us = gtk_clist_get_row_data(clist, i);

		if (us->size != size)
			continue;

		gtk_clist_get_text(clist, i, c_us_filename, &filename);

		if (0 == strcmp(filename, name)) {
			*s = us;
			return i;
		}
	}
	return -1;
}

/* Public functions */
void
upload_stats_gui_init(void)
{
}

void
upload_stats_gui_shutdown(void)
{
}

void
upload_stats_gui_add(struct ul_stats *s)
{
	GtkCList *clist = clist_ul_stats();
	const gchar *rowdata[5];
	gint row;
	gchar size_tmp[16];
	gchar attempts_tmp[16];
	gchar complete_tmp[16];
	gchar norm_tmp[16];

	g_strlcpy(size_tmp, short_size(s->size, show_metric_units()),
		sizeof size_tmp);
	gm_snprintf(attempts_tmp, sizeof attempts_tmp, "%u", s->attempts);
	gm_snprintf(complete_tmp, sizeof complete_tmp, "%u", s->complete);
	gm_snprintf(norm_tmp, sizeof norm_tmp, "%.3f", s->norm);

	rowdata[c_us_filename] = s->filename;
	rowdata[c_us_size] = size_tmp;
	rowdata[c_us_attempts] = attempts_tmp;
	rowdata[c_us_complete] = complete_tmp;
	rowdata[c_us_norm] = norm_tmp;

    row = gtk_clist_insert(clist, 0, deconstify_gpointer(rowdata));
	ul_rows++;

	gtk_clist_set_row_data_full(clist, row, s, NULL);

    /* FIXME: should use auto_sort? */
	gtk_clist_sort(clist);
}


/**
 * Called when a row of the upload stats should be updated
 */
void
upload_stats_gui_update(const gchar *name, guint64 size)
{
	GtkCList *clist = clist_ul_stats();
	gint row;
	struct ul_stats *s;
	static gchar tmpstr[16];

	/* find this file in the clist_ul_stats */
	row = ul_find_row_by_upload(name, size, &s);
	if (-1 == row) {
		g_assert_not_reached();
		return;
	}

	/* set attempt cell contents */
	gm_snprintf(tmpstr, sizeof(tmpstr), "%d", s->attempts);
	gtk_clist_set_text(clist, row, c_us_attempts, tmpstr);
	gm_snprintf(tmpstr, sizeof(tmpstr), "%d", s->complete);
	gtk_clist_set_text(clist, row, c_us_complete, tmpstr);
	s->norm = (gfloat) s->bytes_sent / (gfloat) s->size;
	gm_snprintf(tmpstr, sizeof(tmpstr), "%.3f", s->norm);
	gtk_clist_set_text(clist, row, c_us_norm, tmpstr);

	/* FIXME: use auto-sort? */
	gtk_clist_sort(clist);
}

void
upload_stats_gui_clear_all(void)
{
	gtk_clist_clear(clist_ul_stats());
	ul_rows = 0;
}

/* vi: set ts=4 sw=4 cindent: */
