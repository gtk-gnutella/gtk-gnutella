/*
 * $Id$
 *
 * Copyright (c) 2007, Christian Biere
 * Copyright (c) 2004, Raphael Manfredi
 * Copyright (c) 2003, Markus Goetz
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
 * SHA-1 based spam filtering.
 *
 * @author Markus Goetz
 * @date 2003
 * @author Raphael Manfredi
 * @date 2004
 * @author Christian Biere
 * @date 2007
 */

#include "common.h"

RCSID("$Id$")

#include "spam.h"
#include "settings.h"

#include "lib/atoms.h"
#include "lib/file.h"
#include "lib/misc.h"
#include "lib/glib-missing.h"
#include "lib/sorted_array.h"
#include "lib/watcher.h"

#include "if/gnet_property.h"
#include "if/gnet_property_priv.h"
#include "if/bridge/c2ui.h"

#include "lib/override.h"		/* Must be the last header included */

static const gchar spam_sha1_file[] = "spam_sha1.txt";
static const gchar spam_sha1_what[] = "Spam SHA-1 database";

struct spam_lut {
	struct sorted_array *tab;
};

static struct spam_lut spam_lut;

static inline int
sha1_cmp_func(const void *a, const void *b)
{
	return sha1_cmp(a, b);
}

void
spam_sha1_add(const struct sha1 *sha1)
{
	g_return_if_fail(sha1);
	if (NULL == spam_lut.tab) {
		spam_lut.tab = sorted_array_new(sizeof *sha1, sha1_cmp_func);
	}
	sorted_array_add(spam_lut.tab, sha1);
}

static int
sha1_collision(const void *a, const void *b)
{
	(void) a;
	g_warning("spam_sha1_sync(): Removing duplicate SHA-1 %s",
		sha1_base32(b));
	return 1;
}

void
spam_sha1_sync(void)
{
	if (spam_lut.tab) {
		sorted_array_sync(spam_lut.tab, sha1_collision);
	}
}

/**
 * Load spam database from the supplied FILE.
 *
 * The current file format is as follows:
 *
 * # Comment
 * <SHA1 #1>
 * <SHA1 #2>
 * etc...
 *
 * @returns the amount of entries loaded or -1 on failure.
 */
static gulong
spam_sha1_load(FILE *f)
{
	gchar line[1024];
	guint line_no = 0;
	gulong item_count = 0;

	g_assert(f);

	while (fgets(line, sizeof line, f)) {
		const struct sha1 *sha1;
		gchar *nl;

		line_no++;

		nl = strchr(line, '\n');
		if (!nl) {
			/*
			 * If the line is too long or unterminated the file is either
			 * corrupt or was manually edited without respecting the
			 * exact format. If we continued, we would read from the
			 * middle of a line which could be the filename or ID.
			 */
			g_warning("spam_sha1_load(): "
				"line too long or missing newline in line %u",
				line_no);
			break;
		}
		*nl = '\0';

		/* Skip comments and empty lines */
		if (*line == '#' || *line == '\0')
			continue;

		if (strlen(line) < SHA1_BASE32_SIZE) {
			g_warning("spam_sha1_load(): SHA-1 has wrong length in line %u.",
				line_no);
			continue;
		}

		/*
		 * Allow trailing data for forwards compatability but ensure
		 * the leading SHA-1 is separated from the trailing data.
		 */
		if (is_ascii_alnum(line[SHA1_BASE32_SIZE])) {
			g_warning("spam_sha1_load(): Bad SHA-1 in line %u.",
				line_no);
			continue;
		}
		
		sha1 = base32_sha1(line);
		if (NULL == sha1) {
			g_warning("spam_sha1_load(): Could not parse SHA-1 in line %u.",
				line_no);
			continue;
		}
		spam_sha1_add(sha1);
		item_count++;
	}

	spam_sha1_sync();

	return item_count;
}

/**
 * Watcher callback, invoked when the file from which we read the spam 
 * changed.
 */
static void
spam_sha1_changed(const gchar *filename, gpointer unused_udata)
{
	FILE *f;

	(void) unused_udata;

	f = file_fopen(filename, "r");
	if (f) {
		gchar buf[80];
		gulong count;

		spam_sha1_close();
		count = spam_sha1_load(f);
		fclose(f);

		gm_snprintf(buf, sizeof(buf), "Reloaded %lu spam SHA-1 items.", count);
		gcu_statusbar_message(buf);
	}
}

static void
spam_sha1_retrieve_from_file(FILE *f, const gchar *path, const gchar *filename)
{
	gchar *pathname;

	g_assert(f);
	g_assert(path);
	g_assert(filename);

	pathname = make_pathname(path, filename);
	watcher_register(pathname, spam_sha1_changed, NULL);
	G_FREE_NULL(pathname);
	spam_sha1_load(f);
}

/**
 * Loads the spam.txt into memory.
 *
 * The selected file will then be monitored and a reloading will occur
 * shortly after a modification.
 */
static void
spam_sha1_retrieve(void)
{
	static file_path_t fp[3];
	guint num_fp = G_N_ELEMENTS(fp) - 1;
	FILE *f;
	gint idx;
	
	file_path_set(&fp[0], settings_config_dir(), spam_sha1_file);
	file_path_set(&fp[1], PRIVLIB_EXP, spam_sha1_file);

#ifndef OFFICIAL_BUILD
	file_path_set(&fp[2], PACKAGE_EXTRA_SOURCE_DIR, spam_sha1_file);
	num_fp++;
#endif	/* !OFFICIAL_BUILD */

	f = file_config_open_read_norename_chosen(spam_sha1_what, fp, num_fp, &idx);
	if (f) {
		spam_sha1_retrieve_from_file(f, fp[idx].dir, fp[idx].name);
		fclose(f);
	}
}

/**
 * Called on startup. Loads the spam.txt into memory.
 */
void
spam_sha1_init(void)
{
	spam_sha1_retrieve();
}

/**
 * Frees all entries in the spam database.
 */
void
spam_sha1_close(void)
{
	sorted_array_free(&spam_lut.tab);
}

/**
 * Check the given SHA-1 against the spam database.
 *
 * @param sha1 the SHA-1 to check.
 * @returns TRUE if found, and FALSE if not.
 */
gboolean
spam_sha1_check(const struct sha1 *sha1)
{
	g_return_val_if_fail(sha1, FALSE);
	return spam_lut.tab && NULL != sorted_array_lookup(spam_lut.tab, sha1);
}

/* vi: set ts=4 sw=4 cindent: */
