/*
 * $Id: hostiles.c 10580 2006-03-14 22:58:17Z cbiere $
 *
 * Copyright (c) 2006, Christian Biere
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
 * @date 2006
 */

#include "common.h"

RCSID("$Id: hostiles.c 10580 2006-03-14 22:58:17Z cbiere $");

#include "spam.h"
#include "settings.h"
#include "nodes.h"

#include "lib/atoms.h"
#include "lib/bit_array.h"
#include "lib/file.h"
#include "lib/getdate.h"
#include "lib/misc.h"
#include "lib/glib-missing.h"
#include "lib/walloc.h"
#include "lib/watcher.h"

#include "if/gnet_property.h"
#include "if/gnet_property_priv.h"
#include "if/bridge/c2ui.h"

#include "lib/override.h"		/* Must be the last header included */

static const gchar spam_file[] = "spam.txt";
static const gchar spam_what[] = "Spam database";

static GHashTable *spam_ht;

typedef enum {
	SPAM_TAG_UNKNOWN = 0,
	SPAM_TAG_ADDED,
	SPAM_TAG_END,
	SPAM_TAG_SHA1,

	NUM_SPAM_TAGS
} spam_tag_t;

static const struct spam_tag {
	spam_tag_t	tag;
	const gchar *str;
} spam_tag_map[] = {
	/* Must be sorted alphabetically for dichotomic search */

#define SPAM_TAG(x) { CAT2(SPAM_TAG_,x), STRINGIFY(x) }
	SPAM_TAG(ADDED),
	SPAM_TAG(END),
	SPAM_TAG(SHA1),

	/* Above line intentionally left blank (for "!}sort" on vi) */
#undef SPAM_TAG
};


static spam_tag_t
spam_string_to_tag(const gchar *s)
{
	STATIC_ASSERT(G_N_ELEMENTS(spam_tag_map) == (NUM_SPAM_TAGS - 1));

#define GET_ITEM(i) (spam_tag_map[(i)].str)
#define FOUND(i) G_STMT_START { \
	return spam_tag_map[(i)].tag; \
	/* NOTREACHED */ \
} G_STMT_END

	/* Perform a binary search to find ``s'' */
	BINARY_SEARCH(const gchar *, s, G_N_ELEMENTS(spam_tag_map), strcmp,
		GET_ITEM, FOUND);

#undef FOUND
#undef GET_ITEM
	return SPAM_TAG_UNKNOWN;
}

typedef struct {
	gchar sha1[SHA1_RAW_SIZE];
	time_t added;
} spam_item_t;

/**
 * Load spam database from the supplied FILE.
 *
 * The current file format is as follows:
 *
 * # Comment
 * SHA1 <SHA-1>
 * ADDED <date>
 * END
 *
 * @returns the amount of entries loaded.
 */
static gint
spam_load(FILE *f)
{
	static const spam_item_t zero_item;
	spam_item_t item;
	gchar line[1024];
	guint line_no = 0;
	bit_array_t tag_used[BIT_ARRAY_SIZE(NUM_SPAM_TAGS)];
	gboolean done = FALSE;

	g_assert(f);

	/* Reset state */
	done = FALSE;
	item = zero_item;
	bit_array_clear_range(tag_used, 0, (guint) NUM_SPAM_TAGS - 1);

	spam_ht = g_hash_table_new(sha1_hash, sha1_eq);

	while (fgets(line, sizeof line, f)) {
		const gchar *tag_name, *value;
		gchar *sp, *nl;
		gboolean damaged;
		spam_tag_t tag;

		line_no++;

		damaged = FALSE;
		nl = strchr(line, '\n');
		if (!nl) {
			/*
			 * If the line is too long or unterminated the file is either
			 * corrupt or was manually edited without respecting the
			 * exact format. If we continued, we would read from the
			 * middle of a line which could be the filename or ID.
			 */
			g_warning("spam_load(): "
				"line too long or missing newline in line %u",
				line_no);
			break;
		}
		*nl = '\0';

		/* Skip comments and empty lines */
		if (*line == '#' || *line == '\0')
			continue;

		sp = strchr(line, ' ');
		if (sp) {
			*sp = '\0';
			value = &sp[1];
		} else {
			value = strchr(line, '\0');
		}
		tag_name = line;

		tag = spam_string_to_tag(tag_name);
		g_assert((gint) tag >= 0 && tag < NUM_SPAM_TAGS);
		if (SPAM_TAG_UNKNOWN != tag && !bit_array_flip(tag_used, tag)) {
			g_warning("spam_load(): duplicate tag \"%s\" in entry in line %u",
				tag_name, line_no);
			break;
		}
		
		switch (tag) {
		case SPAM_TAG_ADDED:
			{
				time_t t;
				
				t = date2time(value, tm_time());
				if ((time_t) -1 != t) {
					item.added = t;
				} else {
					damaged |= TRUE;
				}
			}
			break;
			
		case SPAM_TAG_SHA1:
			{
				if (strlen(value) != SHA1_BASE32_SIZE) {
					damaged = TRUE;
					g_warning("spam_load(): SHA-1 has wrong length.");
				} else {
					const gchar *raw;

					raw = base32_sha1(value);
					if (!raw)
						damaged = TRUE;
					else
						memcpy(item.sha1, raw, sizeof item.sha1);
				}
			}
			break;

		case SPAM_TAG_END:
			if (!bit_array_get(tag_used, SPAM_TAG_SHA1)) {
				g_warning("spam_load(): missing SHA1 tag");
				damaged = TRUE;
			}
			if (!bit_array_get(tag_used, SPAM_TAG_ADDED)) {
				g_warning("spam_load(): missing ADDED tag");
				damaged = TRUE;
			}
			done = TRUE;
			break;

		case SPAM_TAG_UNKNOWN:
			/* Ignore */
			break;
			
		case NUM_SPAM_TAGS:
			g_assert_not_reached();
			break;
		}

		if (damaged) {
			g_warning("Damaged spam entry in line %u: "
				"tag_name=\"%s\", value=\"%s\"",
				line_no, tag_name, value);
			break;
		}

		if (done) {
			if (g_hash_table_lookup(spam_ht, &item.sha1)) {
				g_warning("Ignoring duplicate spam item around line %u",
					line_no);
			} else {
				spam_item_t *spam;

				spam = wcopy(&item, sizeof item);
				g_hash_table_insert(spam_ht, &spam->sha1, spam);
			}
			
			/* Reset state */
			done = FALSE;
			item = zero_item;
			bit_array_clear_range(tag_used, 0, (guint) NUM_SPAM_TAGS - 1);
		}
	}

	return g_hash_table_size(spam_ht);
}

/**
 * Watcher callback, invoked when the file from which we read the spam 
 * changed.
 */
static void
spam_changed(const gchar *filename, gpointer unused_udata)
{
	FILE *f;
	gchar buf[80];
	guint count;

	(void) unused_udata;

	f = file_fopen(filename, "r");
	if (f == NULL)
		return;

	spam_close();
	count = spam_load(f);
	fclose(f);

	gm_snprintf(buf, sizeof(buf), "Reloaded %u spam items.", count);
	gcu_statusbar_message(buf);
}

static void
spam_retrieve_from_file(FILE *f, const gchar *path, const gchar *filename)
{
	gchar *pathname;

	g_assert(f);
	g_assert(path);
	g_assert(filename);

	pathname = make_pathname(path, filename);
	watcher_register(pathname, spam_changed, NULL);
	G_FREE_NULL(pathname);
	spam_load(f);
}

/**
 * Loads the spam.txt into memory.
 *
 * The selected file will then be monitored and a reloading will occur
 * shortly after a modification.
 */
static void
spam_retrieve(void)
{
	FILE *f;
	gint idx;
	file_path_t fp[1];

	file_path_set(&fp[0], settings_config_dir(), spam_file);
	f = file_config_open_read_norename_chosen(spam_what,
			fp, G_N_ELEMENTS(fp), &idx);

	if (f) {
		spam_retrieve_from_file(f, fp[idx].dir, fp[idx].name);
		fclose(f);
	}
}

/**
 * Called on startup. Loads the spam.txt into memory.
 */
void
spam_init(void)
{
	spam_retrieve();
}

static void
spam_item_free(gpointer unused_key, gpointer value, gpointer unused_x)
{
	spam_item_t *item = value;
	
	(void) unused_key;
	(void) unused_x;

	wfree(item, sizeof *item);
}

/**
 * Frees all entries in the spam database.
 */
void
spam_close(void)
{
	if (spam_ht) {
		g_hash_table_foreach(spam_ht, spam_item_free, NULL);
		g_hash_table_destroy(spam_ht);
		spam_ht = NULL;
	}
}

/**
 * Check the given SHA-1 against the spam database.
 *
 * @param sha1 the SHA-1 to check.
 * @returns TRUE if found, and FALSE if not.
 */
gboolean
spam_check(const char *sha1)
{
	gboolean found;

	g_assert(sha1);

	if (spam_ht) {
		found = NULL != g_hash_table_lookup(spam_ht, sha1);
	} else {
		found = FALSE;
	}
	return found;
}

/* vi: set ts=4 sw=4 cindent: */
