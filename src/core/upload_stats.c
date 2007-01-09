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
#include "share.h"

#include "if/bridge/c2ui.h"

#include "lib/atoms.h"
#include "lib/file.h"
#include "lib/hashlist.h"
#include "lib/tm.h"
#include "lib/url.h"
#include "lib/walloc.h"

#include "lib/override.h"		/* Must be the last header included */

static gboolean dirty = FALSE;
static gchar *stats_file;
static hash_list_t *upload_stats_list;

static gboolean 
ul_stats_eq(gconstpointer p, gconstpointer q)
{
	const struct ul_stats *a = p, *b = q;
  
	/* filename is an atom */
	return a->filename == b->filename && b->size == b->size;
}

static guint
ul_stats_hash(gconstpointer p)
{
	const struct ul_stats *s = p;
  
	return ((size_t) s->filename >> 3) ^ s->size;
}

static struct ul_stats *
upload_stats_find(const gchar *name, guint64 size)
{
	struct ul_stats *s = NULL;

	if (upload_stats_list) {
		static const struct ul_stats zero_stats;
		struct ul_stats key;
		gconstpointer orig_key;

		key = zero_stats;
		key.filename = atom_str_get(name);
		key.size = size;

		if (hash_list_contains(upload_stats_list, &key, &orig_key)) {
			s = deconstify_gpointer(orig_key);
		}
		atom_str_free_null(&key.filename);
	}
	return s;
}

static void
upload_stats_add(const gchar *filename,
	filesize_t size, guint32 attempts, guint32 complete, guint64 ul_bytes)
{
	static const struct ul_stats zero_stats;
	struct ul_stats *s;

	s = walloc(sizeof *s);
	*s = zero_stats;
	s->filename = atom_str_get(filename);
	s->size = size;
	s->attempts = attempts;
	s->complete = complete;
	s->norm = size > 0 ? (gfloat) ul_bytes / (gfloat) size : 0;
	s->bytes_sent = ul_bytes;

	if (!upload_stats_list) {
		upload_stats_list = hash_list_new(ul_stats_hash, ul_stats_eq);
	}
	hash_list_append(upload_stats_list, s);
	gcu_upload_stats_gui_add(s);
}

void
upload_stats_load_history(const gchar *ul_history_file_name)
{
	FILE *upload_stats_file;
	gchar line[FILENAME_MAX + 64];
	guint lineno = 0;

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

		if (upload_stats_find(line, size)) {
			g_warning("upload_stats_load_history():"
				" Ignoring line %u due to duplicate file.", lineno);
		} else {
			upload_stats_add(line, size, attempt, complete, ulbytes);
		}

		continue;

	corrupted:
		g_warning("upload statistics file corrupted at line %d.\n", lineno);
	}

	/* close file */
	fclose(upload_stats_file);

done:
	return;
}

static void
upload_stats_dump_item(gpointer p, gpointer user_data)
{
	FILE *out = user_data;
	struct ul_stats *s = p;
	gchar *escaped;

	g_assert(NULL != s);

	escaped = url_escape_cntrl(s->filename);
	fprintf(out, "%s\t%s\t%u\t%u\t%lu\t%lu\n", escaped,
		uint64_to_string(s->size), s->attempts, s->complete,
			(gulong) (s->bytes_sent >> 32),
			(gulong) (s->bytes_sent & 0xffffffff));

	if (escaped != s->filename) {		/* File had escaped chars */
		G_FREE_NULL(escaped);
	}
}

/**
 * Save upload statistics to file.
 */
static void
upload_stats_dump_history(const gchar *ul_history_file_name)
{
	FILE *out;
	time_t now = tm_time();

	g_return_if_fail(ul_history_file_name);

	/* open file for writing */
	out = file_fopen(ul_history_file_name, "w");
	if (NULL == out) {
		return;
	}

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

	/*
	 * Don't check this sooner so that the file is cleared, if the user
	 * cleared the history.
	 */
	if (upload_stats_list) {
		/* for each element in uploads_stats_list, write out to hist file */
		hash_list_foreach(upload_stats_list, upload_stats_dump_item, out);
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

/**
 * Called when an upload starts.
 */
void
upload_stats_file_begin(const struct shared_file *sf)
{
	struct ul_stats *s;
	const gchar *name;
	filesize_t size;

	g_return_if_fail(sf);
	name = shared_file_name_nfc(sf);
	size = shared_file_size(sf);

	/* find this file in the ul_stats_clist */
	s = upload_stats_find(name, size);

	/* increment the attempted counter */
	if (NULL == s) {
		upload_stats_add(name, size, 1, 0, 0);
	} else {
		s->attempts++;
		gcu_upload_stats_gui_update(name, size);
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
	struct ul_stats *s;

	g_assert(comp >= 0);

	/* find this file in the ul_stats_clist */
	s = upload_stats_find(name, size);

	/* increment the completed counter */
	if (NULL == s) {
		/* uh oh, row has since been deleted, add it: 1 attempt */
		upload_stats_add(name, size, 1, comp, sent);
	} else {
		s->bytes_sent += sent;
		s->norm = (gfloat) s->bytes_sent / (gfloat) s->size;
		s->complete += comp;
		gcu_upload_stats_gui_update(name, size);
	}

	dirty = TRUE;		/* Request asynchronous save of stats */
}

/**
 * Called when an upload is aborted, to update the amount of bytes transferred.
 */
void
upload_stats_file_aborted(const struct shared_file *sf, filesize_t done)
{
	g_return_if_fail(sf);

	if (done > 0) {
		const gchar *name = shared_file_name_nfc(sf);
		filesize_t size = shared_file_size(sf);

		upload_stats_file_add(name, size, 0, done);
		gcu_upload_stats_gui_update(name, size);
	}
}

/**
 * Called when an upload completes.
 */
void
upload_stats_file_complete(const struct shared_file *sf, filesize_t done)
{
	const gchar *name = shared_file_name_nfc(sf);
	filesize_t size = shared_file_size(sf);

	g_return_if_fail(sf);

	name = shared_file_name_nfc(sf);
	size = shared_file_size(sf);
	upload_stats_file_add(name, size, 1, done);
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
	if (upload_stats_list) {
		struct ul_stats *s;

		while (NULL != (s = hash_list_head(upload_stats_list))) {
			hash_list_remove(upload_stats_list, s);
			atom_str_free_null(&s->filename);
			wfree(s, sizeof *s);
		}
		hash_list_free(&upload_stats_list);
	}
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
	if (stats_file) {
		upload_stats_dump_history(stats_file);
	}
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
