/*
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
 *      51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
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

#include "spam.h"

#include "settings.h"

#include "lib/ascii.h"
#include "lib/atoms.h"
#include "lib/dbmw.h"
#include "lib/file.h"
#include "lib/halloc.h"
#include "lib/path.h"
#include "lib/sorted_array.h"
#include "lib/str.h"
#include "lib/watcher.h"

#include "if/gnet_property.h"
#include "if/gnet_property_priv.h"
#include "if/bridge/c2ui.h"
#include "if/core/settings.h"

#include "lib/override.h"		/* Must be the last header included */

#define SPAM_DB_LOAD_CACHESIZE	32768	/* Large to do it mostly in RAM */
#define SPAM_DB_RUN_CACHESIZE	128		/* During operations, less demanding */
#define SPAM_DBMW_CACHESIZE		1024	/* DB wrapper cache size */

static const char spam_sha1_file[] = "spam_sha1.txt";
static const char spam_sha1_what[] = "Spam SHA-1 database";
static char db_spambase[] = "spam_sha1";

enum spam_state {
	SPAM_UNINITIALIZED = 0,
	SPAM_LOADING = 1,
	SPAM_LOADED
};

struct sha1_lut {
	struct sorted_array *tab;
	enum spam_state state;
	union {
		dbmw_t *dw;
		dbmap_t *dm;
	} d;
};

static struct sha1_lut sha1_lut;

static inline G_PURE int
sha1_cmp_func(const void *a, const void *b)
{
	return sha1_cmp(a, b);
}

/**
 * Initialize SPAM lookup up table.
 */
static void
spam_lut_create(void)
{
	if (GNET_PROPERTY(spam_lut_in_memory)) {
		sha1_lut.tab = sorted_array_new(sizeof(struct sha1), sha1_cmp_func);
	} else {
		dbmap_t *dm;
		char *path;

		path = make_pathname(settings_gnet_db_dir(), db_spambase);
		dm = dbmap_create_sdbm(SHA1_RAW_SIZE, NULL, spam_sha1_what, path,
			O_CREAT | O_TRUNC | O_RDWR, S_IRUSR | S_IWUSR);
		HFREE_NULL(path);

		if (NULL == dm) {
			if (GNET_PROPERTY(spam_debug))
				g_warning("unable to create SDBM database for %s: %m",
					db_spambase);
			sha1_lut.tab = sorted_array_new(sizeof(struct sha1), sha1_cmp_func);
		} else {
			/*
			 * During loading we use the dbmap directly, not the wrapper
			 * since we don't care about that high-level cache layer which
			 * is going to slow us down needlessly.
			 */

			dbmap_set_volatile(dm, TRUE);
			dbmap_set_cachesize(dm, SPAM_DB_LOAD_CACHESIZE);
			sha1_lut.d.dm = dm;
		}
	}
}

void
spam_sha1_add(const struct sha1 *sha1)
{
	g_assert(sha1_lut.state != SPAM_UNINITIALIZED);
	g_return_if_fail(sha1);

	if (sha1_lut.tab)
		sorted_array_add(sha1_lut.tab, sha1);
	else {
		if (SPAM_LOADING == sha1_lut.state) {
			dbmap_datum_t val = { NULL, 0 };
			dbmap_insert(sha1_lut.d.dm, sha1, val);
		} else {
			dbmw_write(sha1_lut.d.dw, sha1, NULL, 0);
		}
	}
}

static int
sha1_collision(const void *a, const void *b)
{
	(void) a;
	g_warning("spam_sha1_sync(): removing duplicate SHA-1 %s", sha1_base32(b));
	return 1;
}

void
spam_sha1_sync(void)
{
	if (sha1_lut.tab) {
		sorted_array_sync(sha1_lut.tab, sha1_collision);
	} else if (SPAM_LOADING == sha1_lut.state) {
		dbmap_t *dm = sha1_lut.d.dm;

		/*
		 * Now that loading is finished, we can wrap the dbmap to use some
		 * amount of high-level caching, and therefore reduce the amount
		 * of low-level caching done.
		 */

		dbmap_set_cachesize(dm, SPAM_DB_RUN_CACHESIZE);
		sha1_lut.d.dw = dbmw_create(dm, spam_sha1_what,
			0, 0,
			NULL, NULL, NULL,
			SPAM_DBMW_CACHESIZE, sha1_hash, sha1_eq);
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
static ulong G_COLD
spam_sha1_load(FILE *f)
{
	char line[1024];
	uint line_no = 0;
	ulong item_count = 0;

	g_assert(f);

	spam_lut_create();
	sha1_lut.state = SPAM_LOADING;

	while (fgets(line, sizeof(line), f)) {
		const struct sha1 *sha1;
		size_t len;

		line_no++;

		if (!file_line_chomp_tail(ARYLEN(line), &len)) {
			/*
			 * If the line is too long or unterminated the file is either
			 * corrupt or was manually edited without respecting the
			 * exact format. If we continued, we would read from the
			 * middle of a line which could be the filename or ID.
			 */
			g_warning("%s(): line %u too long or missing newline",
				G_STRFUNC, line_no);
			break;
		}

		/* Skip comments and empty lines */
		if (file_line_is_skipable(line))
			continue;

		if (len < SHA1_BASE32_SIZE) {
			g_warning("%s(): SHA-1 has wrong length %zu in line %u.",
				G_STRFUNC, len, line_no);
			continue;
		}

		/*
		 * Allow trailing data for forwards compatability but ensure
		 * the leading SHA-1 is separated from the trailing data.
		 */
		if (is_ascii_alnum(line[SHA1_BASE32_SIZE])) {
			g_warning("%s(): bad SHA-1 in line %u.", G_STRFUNC, line_no);
			continue;
		}

		sha1 = base32_sha1(line);
		if (NULL == sha1) {
			g_warning("%s(): could not parse SHA-1 in line %u.",
				G_STRFUNC, line_no);
			continue;
		}
		spam_sha1_add(sha1);
		item_count++;
	}

	spam_sha1_sync();
	sha1_lut.state = SPAM_LOADED;

	if (GNET_PROPERTY(spam_debug))
		g_debug("loaded %lu SPAM SHA-1 keys", item_count);

	return item_count;
}

/**
 * Watcher callback, invoked when the file from which we read the spam
 * changed.
 */
static void
spam_sha1_changed(const char *filename, void *unused_udata)
{
	FILE *f;

	(void) unused_udata;

	f = file_fopen(filename, "r");
	if (f) {
		char buf[80];
		ulong count;

		spam_sha1_close();
		count = spam_sha1_load(f);
		fclose(f);

		str_bprintf(ARYLEN(buf), "Reloaded %lu spam SHA-1 items.", count);
		gcu_statusbar_message(buf);
	}
}

static void
spam_sha1_retrieve_from_file(FILE *f, const char *path, const char *filename)
{
	char *pathname;

	g_assert(f);
	g_assert(path);
	g_assert(filename);

	pathname = make_pathname(path, filename);
	watcher_register(pathname, spam_sha1_changed, NULL);
	HFREE_NULL(pathname);
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
	file_path_t fp[4];
	FILE *f;
	int idx;
	unsigned length;

	length = settings_file_path_load(fp, spam_sha1_file, SFP_DFLT);

	g_assert(length <= N_ITEMS(fp));

	f = file_config_open_read_norename_chosen(spam_sha1_what, fp, length, &idx);
	if (f != NULL) {
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
	sorted_array_free(&sha1_lut.tab);
	if (sha1_lut.d.dw) {
		dbmw_destroy(sha1_lut.d.dw, TRUE);
		sha1_lut.d.dw = NULL;
	}

	sha1_lut.state = SPAM_UNINITIALIZED;
}

/**
 * Check the given SHA-1 against the spam database.
 *
 * @param sha1 the SHA-1 to check.
 * @returns TRUE if found, and FALSE if not.
 */
bool
spam_sha1_check(const struct sha1 *sha1)
{
	g_return_val_if_fail(sha1, FALSE);
	if (sha1_lut.tab)
		return NULL != sorted_array_lookup(sha1_lut.tab, sha1);

	if (sha1_lut.d.dw)
		return dbmw_exists(sha1_lut.d.dw, sha1);

	return FALSE;
}

/* vi: set ts=4 sw=4 cindent: */
