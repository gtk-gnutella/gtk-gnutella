/*
 * $Id$
 *
 * Copyright (c) 2001-2002, Raphael Manfredi
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
 *
 * upload_stats.c - keep track of which files we send away, and how often.
 *
 *		Statistics are kept by _FILENAME_ and file size, 
 *		not by actual path, so two files with the same
 *		name and size will be counted in the same bin.  
 *		I dont see this as a limitation because the
 *		user wouldn't be able to differentiate the files anyway.
 *		This could be extended to keep the entire path to 
 *		each file and optionally show the entire path, but..
 *		
 *		the 'upload_history' file has the following format:
 *		<url-escaped filename> <file size> <attempts> <completions>
 *
 *		TODO: add a check to make sure that all of the files still exist(?)
 *			grey them out if they dont, optionally remove them from the 
 *			stats list (when 'Clear Non-existant Files' is clicked)
 *
 *		(C) 2002 Michael Tesch, released with gtk-gnutella & its license
 */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif
#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <errno.h>
#include <time.h>		/* For ctime() */

#include "gnutella.h"
#include "upload_stats_gui.h"
#include "misc.h"
#include "upload_stats.h"
#include "url.h"

struct ul_stats {
	guint32 size;
	guint32 attempts;
	guint32 complete;
	guint64 bytes_sent;
	gfloat norm;		/* bytes sent / file size */
};

static gint ul_rows = 0;
static gboolean dirty = FALSE;
static gchar *stats_file = NULL;

gint compare_ul_size(GtkCList *clist, gconstpointer ptr1,
						 gconstpointer ptr2)
{
	guint32 s1 = ((struct ul_stats *) ((GtkCListRow *) ptr1)->data)->size;
	guint32 s2 = ((struct ul_stats *) ((GtkCListRow *) ptr2)->data)->size;

	return (s1 == s2) ? 0 : (s1 > s2) ? 1 : -1;
}
/*
 * first by normalized, then by complete
 */
gint compare_ul_norm(GtkCList *clist, gconstpointer ptr1,
						 gconstpointer ptr2)
{
	gfloat n1 = ((struct ul_stats *) ((GtkCListRow *) ptr1)->data)->norm;
	gfloat n2 = ((struct ul_stats *) ((GtkCListRow *) ptr2)->data)->norm;

	return (n1 != n2) ? ((n1 > n2) ? 1 : -1) : 
		compare_ul_complete(clist, ptr1, ptr2);
}

/*
 * first by attempts, then by complete
 */
gint compare_ul_attempts(GtkCList *clist, gconstpointer ptr1,
						 gconstpointer ptr2)
{
	guint32 a1 = ((struct ul_stats *) ((GtkCListRow *) ptr1)->data)->attempts;
	guint32 a2 = ((struct ul_stats *) ((GtkCListRow *) ptr2)->data)->attempts;
	guint32 c1 = ((struct ul_stats *) ((GtkCListRow *) ptr1)->data)->complete;
	guint32 c2 = ((struct ul_stats *) ((GtkCListRow *) ptr2)->data)->complete;

	return (a1 != a2) ? ((a1 > a2) ? 1 : -1) : 
		(c1 == c2) ? 0 : (c1 > c2) ? 1 : -1;
}

/*
 * first by complete, then by attempts
 */
gint compare_ul_complete(GtkCList *clist,
	gconstpointer ptr1, gconstpointer ptr2)
{
	guint32 a1 = ((struct ul_stats *) ((GtkCListRow *) ptr1)->data)->attempts;
	guint32 a2 = ((struct ul_stats *) ((GtkCListRow *) ptr2)->data)->attempts;
	guint32 c1 = ((struct ul_stats *) ((GtkCListRow *) ptr1)->data)->complete;
	guint32 c2 = ((struct ul_stats *) ((GtkCListRow *) ptr2)->data)->complete;

	return (c1 != c2) ? ((c1 > c2) ? 1 : -1) : 
		(a1 == a2) ? 0 : (a1 > a2) ? 1 : -1;
}

static void ul_stats_add_row(gchar *filename,
	guint32 size, guint32 attempts, guint32 complete, guint64 ul_bytes)
{
	gchar *rowdata[5];
	gint row;
	struct ul_stats *stat;
	gchar size_tmp[16];
	gchar attempts_tmp[16];
	gchar complete_tmp[16];
	gchar norm_tmp[16];
	gfloat norm = (float) ul_bytes / (float) size;
    GtkCList *clist = GTK_CLIST(lookup_widget(main_window, "clist_ul_stats"));

	g_snprintf(size_tmp, sizeof(size_tmp), "%s", short_size(size));
	g_snprintf(attempts_tmp, sizeof(attempts_tmp), "%u", attempts);
	g_snprintf(complete_tmp, sizeof(complete_tmp), "%u", complete);
	g_snprintf(norm_tmp, sizeof(norm_tmp), "%.3f", norm);

	rowdata[UL_STATS_FILE_IDX] = filename;
	rowdata[UL_STATS_SIZE_IDX] = size_tmp;
	rowdata[UL_STATS_ATTEMPTS_IDX] = attempts_tmp;
	rowdata[UL_STATS_COMPLETE_IDX] = complete_tmp;
	rowdata[UL_STATS_NORM_IDX] = norm_tmp;

    row = gtk_clist_insert(clist, 0, rowdata);
	ul_rows++;

	stat = g_malloc(sizeof(struct ul_stats));
	stat->size = size;
	stat->attempts = attempts;
	stat->complete = complete;
	stat->norm = norm;
	stat->bytes_sent = ul_bytes;

	gtk_clist_set_row_data_full(clist, row, stat, g_free);

    // FIXME: should use auto_sort?
	gtk_clist_sort(clist);
}

void ul_stats_load_history(const gchar *ul_history_file_name)
{
	FILE *ul_stats_file;
	gchar line[FILENAME_MAX + 64];
	gint lineno = 0;
	struct stat buf;

	stats_file = g_strdup(ul_history_file_name);

	if (-1 == stat(ul_history_file_name, &buf))
		goto done;

	/* open file for reading */
	ul_stats_file = fopen(ul_history_file_name, "r");

	if (!ul_stats_file) {
		g_warning("Unable to open file %s (%s)\n", ul_history_file_name,
				  g_strerror(errno));
		goto done;
	}

	/* parse, insert names into ul_stats_clist */
	while (fgets(line, sizeof(line), ul_stats_file)) {
		guint32 size, attempt, complete;
		guint32 ulbytes_high, ulbytes_low;	/* Portability reasons */
		guint64 ulbytes;
		gchar *name_end;

		lineno++;
		if (line[0] == '#' || line[0] == '\n')
			continue;

		name_end = strchr(line, '\t');
		if (name_end == NULL)
			goto corrupted;
		*name_end++ = '\0';		/* line is now the URL-escaped file name */

		/*
		 * The following is temporary code to assist migration of the
		 * existing upload stats for the users of 0.85 unstable.  It will
		 * be removed in the future.
		 *		--RAM, 21/03/2002
		 */

		if (
			5 == sscanf(name_end, "%u\t%u\t%u\t%u\t%u\n",
				&size, &attempt, &complete, &ulbytes_high, &ulbytes_low)
		)
			ulbytes = (((guint64) ulbytes_high) << 32) | ulbytes_low;
		else if (
			3 == sscanf(name_end, "%u\t%u\t%u\n", &size, &attempt, &complete)
		)
			ulbytes = size * complete;		// fake reasonable count
		else
			goto corrupted;

		ul_stats_add_row(url_unescape(line, TRUE),
			size, attempt, complete, ulbytes);

		continue;

	corrupted:
		g_warning("upload statistics file corrupted at line %d.\n", lineno);
	}

	/* close file */
	fclose(ul_stats_file);

done:
	/* default - set the clist to be sorted by the normalized column */
    {
        GtkCList *clist = 
            GTK_CLIST(lookup_widget(main_window, "clist_ul_stats"));

        gtk_clist_set_compare_func(clist, compare_ul_norm);
        gtk_clist_set_sort_column(clist, UL_STATS_NORM_IDX);
        gtk_clist_set_sort_type(clist, GTK_SORT_DESCENDING);

        // FIXME: should use auto-sort?
        gtk_clist_sort(clist);
    }
}

/*
 * ul_stats_dump_history
 *
 * Save upload statistics to file.
 * When `cleanup' is TRUE, we release the memory used by the statistics.
 * Otherwise, we just save the data, but keep the data structure intact.
 */
void ul_stats_dump_history(const gchar *ul_history_file_name, gboolean cleanup)
{
	gchar *file;
	FILE *out;
	gint i;
	time_t now = time((time_t *) NULL);
    GtkWidget *clist_ul_stats;

    clist_ul_stats = lookup_widget(main_window, "clist_ul_stats");

	/* open file for writing */
	out = fopen(ul_history_file_name, "w");

	if (!out) {
		g_warning("Unable to write to file %s (%s)\n", ul_history_file_name,
				  g_strerror(errno));
		return;
	}

	fputs("# THIS FILE IS AUTOMATICALLY GENERATED -- DO NOT EDIT\n", out);
	fprintf(out, "#\n# Upload statistics saved on %s#\n\n", ctime(&now));
	fputs("#\n# Format is:\n", out);
	fputs("#    File basename <TAB> size <TAB> attempts <TAB> completed\n", out);
	fputs("#        <TAB>bytes_sent-high <TABbytes_sent-low\n", out);
	fputs("#\n\n", out);

	if (cleanup)
		gtk_clist_freeze(GTK_CLIST(clist_ul_stats));

	/* for each line in ul_stats_clist, write out to hist file */
	for (i = 0; i < ul_rows; i++) {
		gchar *escaped;
		struct ul_stats *stat;
		gint row = cleanup ? 0 : i;

		stat = gtk_clist_get_row_data(GTK_CLIST(clist_ul_stats), row);

		gtk_clist_get_text(GTK_CLIST(clist_ul_stats), row,
			UL_STATS_FILE_IDX, &file);

		escaped = url_escape_cntrl(file);
		fprintf(out, "%s\t%u\t%u\t%u\t%u\t%u\n", escaped,
			stat->size, stat->attempts, stat->complete,
				(guint32) (stat->bytes_sent >> 32),
				(guint32) stat->bytes_sent);

		if (escaped != file)		/* File had escaped chars */
			g_free(escaped);

		if (cleanup)
			gtk_clist_remove(GTK_CLIST(clist_ul_stats), 0);
	}

	/* close file */
	fclose(out);

	if (cleanup && stats_file)
		g_free(stats_file);
}

/*
 * ul_flush_stats_if_dirty
 *
 * Called on a periodic basis to flush the statistics to disk if changed
 * since last call.
 */
void ul_flush_stats_if_dirty(void)
{
	if (!dirty)
		return;

	dirty = FALSE;

	if (stats_file)
		ul_stats_dump_history(stats_file, FALSE);
	else {
		g_warning("can't save upload statistics: no file name recorded");
		return;
	}
}

/*
 * this is me, dreaming of gtk 2.0...
 */
static int ul_find_row_by_upload(
	const struct upload *u, struct ul_stats **s)
{
	int i;
    GtkCList *clist = 
        GTK_CLIST(lookup_widget(main_window, "clist_ul_stats"));

	/* go through the clist_ul_stats, looking for the file...
	 * blame gtk/glib, not me...
	 */
	for (i = 0; i < ul_rows; i++) {
		gchar *filename;
		struct ul_stats *us;

		us = gtk_clist_get_row_data(clist, i);

		if (us->size != u->file_size)
			continue;

		gtk_clist_get_text(clist, i,
			UL_STATS_FILE_IDX, &filename);

		if (g_str_equal(filename, u->name)) {
			*s = us;
			return i;
		}
	}
	return -1;
}

/*
 * Called when an upload starts
 */
void ul_stats_file_begin(const struct upload *u)
{
	gint row;
	struct ul_stats *stat;

	/* find this file in the ul_stats_clist */
	row = ul_find_row_by_upload(u, &stat);

	/* increment the attempted counter */
	if (-1 == row)
		ul_stats_add_row(u->name, u->file_size, 1, 0, 0);
	else {
		gchar attempts_tmp[16];
        GtkCList *clist = 
            GTK_CLIST(lookup_widget(main_window, "clist_ul_stats"));

		stat->attempts++;

		/* set attempt cell contents */
		g_snprintf(attempts_tmp, sizeof(attempts_tmp), "%d", stat->attempts);
		gtk_clist_set_text(clist, row, UL_STATS_ATTEMPTS_IDX, attempts_tmp);
        
        // FIXME: use auto-sort?
		gtk_clist_sort(clist);
	}

	dirty = TRUE;		/* Request asynchronous save of stats */
}

/*
 * ul_stats_file_add
 *
 * Add `comp' to the current completed count, and update the amount of
 * bytes transferred.  Note that `comp' can be zero.
 *
 * If the row does not exist (race condition: deleted since upload started),
 * recreate one.
 */
static void ul_stats_file_add(const struct upload *u, gint comp, gint sent)
{
	gint row;
	struct ul_stats *stat;

	g_assert(comp >= 0);

	/* find this file in the ul_stats_clist */
	row = ul_find_row_by_upload(u, &stat);

	/* increment the completed counter */
	if (-1 == row) {
		/* uh oh, row has since been deleted, add it: 1 attempt */
		ul_stats_add_row(u->name, u->file_size, 1, comp, sent);
	} else {
		gchar complete_tmp[16];
		gchar norm_tmp[16];
        GtkCList *clist =
            GTK_CLIST(lookup_widget(main_window, "clist_ul_stats"));

		/* update complete counter */
		stat->complete += comp;
		g_snprintf(complete_tmp, sizeof(complete_tmp), "%d", 
			stat->complete);
		gtk_clist_set_text(clist, row, UL_STATS_COMPLETE_IDX, complete_tmp);

		/* update normalized upload counter */
		stat->bytes_sent += sent;
		stat->norm = (float) stat->bytes_sent / (float) stat->size;

		g_snprintf(norm_tmp, sizeof(complete_tmp), "%.3f", stat->norm);
		gtk_clist_set_text(clist, row, UL_STATS_NORM_IDX, norm_tmp);

        // FIXME: use auto-sort?
		gtk_clist_sort(clist);
	}

	dirty = TRUE;		/* Request asynchronous save of stats */
}

/*
 * ul_stats_file_aborted
 *
 * Called when an upload is aborted, to update the amount of bytes transferred.
 */
void ul_stats_file_aborted(const struct upload *u)
{
	if (u->pos > u->skip)
		ul_stats_file_add(u, 0, u->pos - u->skip);
}

/*
 * ul_stats_file_complete
 *
 * Called when an upload completes
 */
void ul_stats_file_complete(const struct upload *u)
{
	ul_stats_file_add(u, 1, u->end - u->skip + 1);
}

void ul_stats_prune_nonexistant()
{
	/* for each row, get the filename, check if filename is ? */
}

void ul_stats_clear_all()
{
    GtkCList *clist =
        GTK_CLIST(lookup_widget(main_window, "clist_ul_stats"));

	gtk_clist_clear(clist);
	ul_rows = 0;
	dirty = TRUE;
}

