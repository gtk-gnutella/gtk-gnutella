/*
 * upload_stats.c - keep track of which files we send away, and how often.
 *
 *		all of the data storage is done using the clist_ul_stats,
 *		created by glade.  statistics are kept by _FILENAME_ not by
 *		actual path, so two files with the same name will be counted
 *		in the same bin.  i dont see this as a limitation because the
 *		user wouldn't be able to differentiate the files anyway.  this
 *		could be extended to keep the entire path to each file and 
 *		optionally show the entire path, but who really cares?
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

#include "gnutella.h"
#include "interface.h"
#include "misc.h"
#include "upload_stats.h"
#include "url.h"

struct ul_stats {
	guint32 size;
	guint32 attempts;
	guint32 complete;
};

static gint ul_rows = 0;

gint compare_ul_size(GtkCList *clist, gconstpointer ptr1,
						 gconstpointer ptr2)
{
	guint32 s1 = ((struct ul_stats *) ((GtkCListRow *) ptr1)->data)->size;
	guint32 s2 = ((struct ul_stats *) ((GtkCListRow *) ptr2)->data)->size;

	return (s1 == s2) ? 0 : (s1 > s2) ? 1 : -1;
}
gint compare_ul_attempts(GtkCList *clist, gconstpointer ptr1,
						 gconstpointer ptr2)
{
	guint32 s1 = ((struct ul_stats *) ((GtkCListRow *) ptr1)->data)->attempts;
	guint32 s2 = ((struct ul_stats *) ((GtkCListRow *) ptr2)->data)->attempts;

	return (s1 == s2) ? 0 : (s1 > s2) ? 1 : -1;
}

gint compare_ul_complete(GtkCList *clist,
	gconstpointer ptr1, gconstpointer ptr2)
{
	guint32 s1 = ((struct ul_stats *) ((GtkCListRow *) ptr1)->data)->complete;
	guint32 s2 = ((struct ul_stats *) ((GtkCListRow *) ptr2)->data)->complete;

	return (s1 == s2) ? 0 : (s1 > s2) ? 1 : -1;
}

static void ul_stats_add_row(gchar *filename,
	guint32 size, guint32 attempts, guint32 complete)
{
	gchar *rowdata[4];
	gint row;
	struct ul_stats *stat;
	gchar size_tmp[16];
	gchar attempts_tmp[16];
	gchar complete_tmp[16];

	g_snprintf(size_tmp, sizeof(size_tmp), "%s", short_size(size));
	g_snprintf(attempts_tmp, sizeof(attempts_tmp), "%u", attempts);
	g_snprintf(complete_tmp, sizeof(complete_tmp), "%u", complete);

	rowdata[UL_STATS_FILE_IDX] = filename;
	rowdata[UL_STATS_SIZE_IDX] = size_tmp;
	rowdata[UL_STATS_ATTEMPTS_IDX] = attempts_tmp;
	rowdata[UL_STATS_COMPLETE_IDX] = complete_tmp;

	row = gtk_clist_insert(GTK_CLIST(clist_ul_stats), 0, rowdata);
	ul_rows++;

	stat = g_malloc(sizeof(struct ul_stats));
	stat->size = size;
	stat->attempts = attempts;
	stat->complete = complete;

	gtk_clist_set_row_data_full(GTK_CLIST(clist_ul_stats), row, stat, g_free);
	gtk_clist_sort(GTK_CLIST(clist_ul_stats));
}

void ul_stats_load_history(const gchar *ul_history_file_name)
{
	FILE *ul_stats_file;
	gchar line[FILENAME_MAX + 64];
	gint lineno = 0;
	struct stat buf;

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
		gchar **parts;

		lineno++;
		if (line[0] == '#')
			continue;

		parts = g_strsplit(line, "\t", 4);
		if (!parts || !parts[0] || !parts[1] || !parts[2] || !parts[3]) {
			g_warning("History file corrupted at line %d.\n", lineno);
			continue;
		}

		ul_stats_add_row(url_unescape(parts[0], TRUE),
			atoi(parts[1]), atoi(parts[2]), atoi(parts[3]));

		g_strfreev(parts);
	}

	/* close file */
	fclose(ul_stats_file);

done:
	/* default - set the clist to be sorted by the completed column */
	gtk_clist_set_compare_func(GTK_CLIST(clist_ul_stats), compare_ul_complete);
	gtk_clist_set_sort_column(GTK_CLIST(clist_ul_stats), UL_STATS_COMPLETE_IDX);
	gtk_clist_set_sort_type(GTK_CLIST(clist_ul_stats), GTK_SORT_DESCENDING);
	gtk_clist_sort(GTK_CLIST(clist_ul_stats));
}

void ul_stats_dump_history(const gchar *ul_history_file_name)
{
	gchar *file;
	FILE *ul_stats_file;

	/* open file for writing */
	ul_stats_file = fopen(ul_history_file_name, "w");

	if (!ul_stats_file) {
		g_warning("Unable to write to file %s (%s)\n", ul_history_file_name,
				  g_strerror(errno));
		return;
	}

	/* for each line in ul_stats_clist, write out to hist file */
	while (ul_rows-- > 0) {
		gchar *escaped;
		struct ul_stats *stat;

		stat = gtk_clist_get_row_data(GTK_CLIST(clist_ul_stats), 0);

		gtk_clist_get_text(GTK_CLIST(clist_ul_stats), 0,
			UL_STATS_FILE_IDX, &file);

		escaped = url_escape_cntrl(file);
		fprintf(ul_stats_file, "%s\t%u\t%u\t%u\n", escaped,
			stat->size, stat->attempts, stat->complete);

		if (escaped != file)		/* File had escaped chars */
			g_free(escaped);

		gtk_clist_remove(GTK_CLIST(clist_ul_stats), 0);
	}

	/* close file */
	fclose(ul_stats_file);
}

/*
 * this is me, dreaming of gtk 2.0...
 */
static int ul_find_row_by_name(gchar *name)
{
	int i;

	/* go through the clist_ul_stats, looking for the file...
	 * blame gtk/glib, not me...
	 */
	for (i = 0; i < ul_rows; i++) {
		gchar *filename;

		gtk_clist_get_text(GTK_CLIST(clist_ul_stats), i,
			UL_STATS_FILE_IDX, &filename);

		if (g_str_equal(filename, name))
			return i;
	}
	return -1;
}

/*
 * Called when an upload starts
 */
void ul_stats_file_begin(const struct upload *u)
{
	gint row;

	/* find this file in the ul_stats_clist */
	row = ul_find_row_by_name(u->name);

	/* increment the attempted counter */
	if (-1 == row)
		ul_stats_add_row(u->name, u->file_size, 1, 0);		/* add the row */
	else {
		gchar attempts_tmp[16];
		struct ul_stats *stat;

		stat = gtk_clist_get_row_data(GTK_CLIST(clist_ul_stats), row);
		stat->attempts++;

		/* set attempt cell contents */
		g_snprintf(attempts_tmp, sizeof(attempts_tmp), "%d", stat->attempts);
		gtk_clist_set_text(GTK_CLIST(clist_ul_stats), row,
			UL_STATS_ATTEMPTS_IDX, attempts_tmp);
		gtk_clist_sort(GTK_CLIST(clist_ul_stats));
	}
}

/*
 * Called when an upload completes
 */
void ul_stats_file_complete(const struct upload *u)
{
	gint row;


	/* find this file in the ul_stats_clist */
	row = ul_find_row_by_name(u->name);

	/* increment the completed counter */
	if (-1 == row) {
		/* uh oh, row has since been deleted, add it: 1 attempt, 1 success */
		ul_stats_add_row(u->name, u->file_size, 1, 1);
	} else {
		gchar complete_tmp[16];
		struct ul_stats *stat;

		stat = gtk_clist_get_row_data(GTK_CLIST(clist_ul_stats), row);
		stat->complete++;

		/* set complete cell contents */
		g_snprintf(complete_tmp, sizeof(complete_tmp), "%d", stat->complete);
		gtk_clist_set_text(GTK_CLIST(clist_ul_stats), row,
			UL_STATS_COMPLETE_IDX, complete_tmp);
		gtk_clist_sort(GTK_CLIST(clist_ul_stats));
	}
}

void ul_stats_prune_nonexistant()
{
	/* for each row, get the filename, check if filename is ? */
}

void ul_stats_clear_all()
{
	gtk_clist_clear(GTK_CLIST(clist_ul_stats));
}

