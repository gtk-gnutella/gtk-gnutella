/*
 * $Id$
 *
 * Copyright (c) 2001-2003, Raphael Manfredi
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
 * @ingroup core
 * @file
 *
 * Keep track of which files we send away, and how often.
 *
 * Statistics are kept by _FILENAME_ and file size, not by actual path,
 * so two files with the same name and size will be counted in the same
 * bin. I don't see this as a limitation because the user wouldn't be able
 * to differentiate the files anyway. This could be extended to keep the
 * entire path to each file and optionally show the entire path, but..
 *
 * The 'upload_history' file has the following format:
 *
 *	- "<url-escaped filename> <file size> <attempts> <completions>"
 *
 * @todo
 * TODO: Add a check to make sure that all of the files still exist(?)
 *       grey them out if they dont, optionally remove them from the
 *       stats list (when 'Clear Non-existent Files' is clicked).
 *
 * @author Michael Tesch
 * @date 2002
 * @author Raphael Manfredi
 * @date 2001-2003
 * @version 1.6
 */

#include "common.h"

RCSID("$Id$")

#include "upload_stats.h"

#include "if/bridge/c2ui.h"

#include "lib/atoms.h"
#include "lib/file.h"
#include "lib/tm.h"
#include "lib/url.h"
#include "lib/override.h"		/* Must be the last header included */

static gboolean dirty = FALSE;
static gchar *stats_file = NULL;
static GList *upload_stats_list = NULL;

static void
upload_stats_add(const gchar *filename,
	filesize_t size, guint32 attempts, guint32 complete, guint64 ul_bytes)
{
	struct ul_stats *stat;

	stat = g_malloc0(sizeof(struct ul_stats));
	stat->filename = atom_str_get(filename);
	stat->size = size;
	stat->attempts = attempts;
	stat->complete = complete;
	stat->norm = size > 0 ? (gfloat) ul_bytes / (gfloat) size : 0;
	stat->bytes_sent = ul_bytes;

	/* FIXME: This is unnecessarily O(n) instead of O(1). Use a
	 *		  hashtable instead.
	 */
	upload_stats_list = g_list_append(upload_stats_list, stat);
	gcu_upload_stats_gui_add(stat);
}

void
upload_stats_load_history(const gchar *ul_history_file_name)
{
	FILE *upload_stats_file;
	gchar line[FILENAME_MAX + 64];
	gint lineno = 0;

	stats_file = g_strdup(ul_history_file_name);

	/* open file for reading */
	upload_stats_file = file_fopen_missing(ul_history_file_name, "r");

	if (upload_stats_file == NULL)
		goto done;

	/* parse, insert names into ul_stats_clist */
	while (fgets(line, sizeof(line), upload_stats_file)) {
		gulong attempt, complete;
		gulong ulbytes_high, ulbytes_low;	/* Portability reasons */
		guint64 ulbytes;
		filesize_t size;
		gchar *name_end;
		size_t i;

		lineno++;
		if (line[0] == '#' || line[0] == '\n')
			continue;

		name_end = strchr(line, '\t');
		if (NULL == name_end)
			goto corrupted;
		*name_end++ = '\0';		/* line is now the URL-escaped file name */

		/* The line below is for retarded compilers only */
		size = attempt = complete = ulbytes_high = ulbytes_low = 0;

		for (i = 0; i < 5; i++) {
			guint64 v;
			gint error;
			const gchar *endptr;

			name_end = skip_ascii_spaces(name_end);
			v = parse_uint64(name_end, &endptr, 10, &error);
			name_end = deconstify_gchar(endptr);
			if (error || !is_ascii_space(*endptr))
				goto corrupted;

			switch (i) {
			case 0: size = v; break;
			case 1: attempt = v; break;
			case 2: complete = v; break;
			case 3: ulbytes_high = v; break;
			case 4: ulbytes_low = v; break;
			default:
				g_assert_not_reached();
				goto corrupted;
			}
		}

		ulbytes = (((guint64) ulbytes_high) << 32) | ulbytes_low;

		/* URL-unescape in-place */
		if (!url_unescape(line, TRUE))
			goto corrupted;

		upload_stats_add(line, size, attempt, complete, ulbytes);

		continue;

	corrupted:
		g_warning("upload statistics file corrupted at line %d.\n", lineno);
	}

	/* close file */
	fclose(upload_stats_file);

done:
	return;
}

/**
 * Save upload statistics to file.
 */
static void
upload_stats_dump_history(const gchar *ul_history_file_name)
{
	FILE *out;
	time_t now = tm_time();
	GList *list;

	/* open file for writing */
	out = file_fopen(ul_history_file_name, "w");

	if (NULL == out)
		return;

	fprintf(out,
		"# THIS FILE IS AUTOMATICALLY GENERATED -- DO NOT EDIT\n"
		"#\n"
		"# Upload statistics saved on %s"
		"#\n"
		"\n"
		"#\n"
		"# Format is:\n"
		"#    File basename <TAB> size <TAB> attempts <TAB> completed\n"
		"#        <TAB>bytes_sent-high <TAB> bytes_sent-low\n"
		"#\n"
		"\n",
		ctime(&now));

	/* for each element in uploads_stats_list, write out to hist file */
	for (list = upload_stats_list; NULL != list; list = g_list_next(list)) {
		gchar *escaped;
		struct ul_stats *stat;

		stat = list->data;
		g_assert(NULL != stat);
		escaped = url_escape_cntrl(stat->filename);
		fprintf(out, "%s\t%s\t%u\t%u\t%u\t%u\n", escaped,
			uint64_to_string(stat->size), stat->attempts, stat->complete,
				(guint32) (stat->bytes_sent >> 32),
				(guint32) stat->bytes_sent);

		if (escaped != stat->filename)		/* File had escaped chars */
			G_FREE_NULL(escaped);
	}

	/* close file */
	fclose(out);
}

/**
 * Called on a periodic basis to flush the statistics to disk if changed
 * since last call.
 */
void
upload_stats_flush_if_dirty(void)
{
	if (!dirty)
		return;

	dirty = FALSE;

	if (NULL != stats_file)
		upload_stats_dump_history(stats_file);
	else
		g_warning("can't save upload statistics: no file name recorded");
}

static struct ul_stats *
upload_stats_find(const gchar *name, guint64 size)
{
    GList *list;

	/* FIXME: Use a hashtable and the SHA-1 instead. */
	for (list = upload_stats_list; NULL != list; list = g_list_next(list)) {
		struct ul_stats *s;

		s = list->data;
		if (size == s->size && 0 == strcmp(name, s->filename))
			return s;
	}

	return NULL;
}

/**
 * Called when an upload starts.
 */
void
upload_stats_file_begin(const struct upload *u)
{
	struct ul_stats *stat;

	/* find this file in the ul_stats_clist */
	stat = upload_stats_find(u->name, u->file_size);

	/* increment the attempted counter */
	if (NULL == stat)
		upload_stats_add(u->name, u->file_size, 1, 0, 0);
	else {
		stat->attempts++;
		gcu_upload_stats_gui_update(u->name, u->file_size);
	}

	dirty = TRUE;		/* Request asynchronous save of stats */
}

/**
 * Add `comp' to the current completed count, and update the amount of
 * bytes transferred.  Note that `comp' can be zero.
 *
 * If the row does not exist (race condition: deleted since upload started),
 * recreate one.
 */
static void
upload_stats_file_add(const gchar *name, filesize_t size,
	gint comp, guint64 sent)
{
	struct ul_stats *stat;

	g_assert(comp >= 0);

	/* find this file in the ul_stats_clist */
	stat = upload_stats_find(name, size);

	/* increment the completed counter */
	if (NULL == stat) {
		/* uh oh, row has since been deleted, add it: 1 attempt */
		upload_stats_add(name, size, 1, comp, sent);
	} else {
		stat->bytes_sent += sent;
		stat->norm = (gfloat) stat->bytes_sent / (gfloat) stat->size;
		stat->complete += comp;
		gcu_upload_stats_gui_update(name, size);
	}

	dirty = TRUE;		/* Request asynchronous save of stats */
}

/**
 * Called when an upload is aborted, to update the amount of bytes transferred.
 */
void
upload_stats_file_aborted(const struct upload *u)
{
	if (u->pos > u->skip) {
		upload_stats_file_add(u->name, u->file_size, 0, u->pos - u->skip);
		gcu_upload_stats_gui_update(u->name, u->file_size);
	}
}

/**
 * Called when an upload completes.
 */
void
upload_stats_file_complete(const struct upload *u)
{
	upload_stats_file_add(u->name, u->file_size, 1, u->end - u->skip + 1);
}

void
upload_stats_prune_nonexistent(void)
{
	/* XXX */
	/* for each row, get the filename, check if filename is ? */
	g_warning("upload_stats_prune_nonexistent: not implemented!");
}

/**
 * Clear all the upload stats data structure.
 */
static void
upload_stats_free_all(void)
{
    GList *list;

	for (list = upload_stats_list; NULL != list; list = g_list_next(list)) {
		struct ul_stats *stat = list->data;

		atom_str_free_null(&stat->filename);
		G_FREE_NULL(list->data);
	}

	g_list_free(upload_stats_list);
	upload_stats_list = NULL;
	dirty = TRUE;
}

/**
 * Like upload_stats_free_all() but also clears the GUI.
 */
void
upload_stats_clear_all(void)
{
	gcu_upload_stats_gui_clear_all();
	upload_stats_free_all();
}

/**
 * Called at shutdown time.
 */
void
upload_stats_close(void)
{
	upload_stats_dump_history(stats_file);
	upload_stats_free_all();
	G_FREE_NULL(stats_file);
}

/* vi: set ts=4 sw=4 cindent: */
