/*
 * $Id$
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

RCSID("$Id$")

#include "spam.h"
#include "settings.h"
#include "nodes.h"

#include "lib/halloc.h"
#include "lib/atoms.h"
#include "lib/bit_array.h"
#include "lib/file.h"
#include "lib/getdate.h"
#include "lib/halloc.h"
#include "lib/glib-missing.h"
#include "lib/parse.h"
#include "lib/path.h"
#include "lib/walloc.h"
#include "lib/watcher.h"
#include "lib/utf8.h"

#include "if/gnet_property.h"
#include "if/gnet_property_priv.h"
#include "if/bridge/c2ui.h"

#include "lib/override.h"		/* Must be the last header included */

static const char spam_text_file[] = "spam.txt";
static const char spam_what[] = "Spam database";

/****** BEGIN IDEAS ONLY ******/

/*
 * The following hash tables function in pairs, which are "rotated" on a
 * regular basis, the currently active table becoming the old one and the
 * old one being cleared.  This provides a way to store temporary information
 * that will naturally fade out if unused.
 */

/*
 * These tables keep track of the association between a GUID and the
 * last known IP:port of the servent.  If more than one association is found,
 * then we most probably face a spamming entity using the same GUID accross
 * a range of different IP addresses..
 */

/*
 * These tables keep track of the association between an IP:port and a servent
 * GUID.  If more than one association is found, then we most probably face a
 * spamming entity using random GUIDs.
 */

/*
 * These tables keep track of the amount of query hits we have seen from a given
 * GUID and IP:port for a given query MUID, and the total amount of entries
 * that these hits contained.
 */

/*
 * These tables keep track of all the different ports we see behind a given
 * IP address.  Too many ports are likely to indicate a spamming origin.
 */

/*
 * These tables keep track of all the various vendor codes we see originating
 * from a given IP:port.
 */

/*
 * These tables keep track of the amount of query hits originating from a /24
 * network for a given MUID for one pair, and the various /24 networks that
 * have replied to a given MUID in another pair.
 */

/****** END IDEAS ONLY ******/

/* NOTE: This is disabled because SQLite does not seem worth the overhead
 *       here for now as spam.txt isn't horribly large. With a slow disk
 *		 or NFS, for example, the performance hit may be noticable.
 */
#if 0
#ifdef HAS_SQLITE
#define USE_SQLITE 1
#endif /* HAS_SQLITE */
#endif

struct spam_lut {
	GSList *sl_names;	/* List of g_malloc()ed regex_t items */
};

static struct spam_lut spam_lut;

typedef enum {
	SPAM_TAG_UNKNOWN = 0,
	SPAM_TAG_ADDED,
	SPAM_TAG_END,
	SPAM_TAG_NAME,
	SPAM_TAG_SHA1,
	SPAM_TAG_SIZE,

	NUM_SPAM_TAGS
} spam_tag_t;

static const struct spam_tag {
	spam_tag_t	tag;
	const char *str;
} spam_tag_map[] = {
	/* Must be sorted alphabetically for dichotomic search */

#define SPAM_TAG(x) { CAT2(SPAM_TAG_,x), #x }
	SPAM_TAG(ADDED),
	SPAM_TAG(END),
	SPAM_TAG(NAME),
	SPAM_TAG(SHA1),
	SPAM_TAG(SIZE),

	/* Above line intentionally left blank (for "!}sort" on vi) */
#undef SPAM_TAG
};


static spam_tag_t
spam_string_to_tag(const char *s)
{
	STATIC_ASSERT(G_N_ELEMENTS(spam_tag_map) == NUM_SPAM_TAGS - 1U);

#define GET_ITEM(i) (spam_tag_map[(i)].str)
#define FOUND(i) G_STMT_START { \
	return spam_tag_map[(i)].tag; \
	/* NOTREACHED */ \
} G_STMT_END

	/* Perform a binary search to find ``s'' */
	BINARY_SEARCH(const char *, s, G_N_ELEMENTS(spam_tag_map), strcmp,
		GET_ITEM, FOUND);

#undef FOUND
#undef GET_ITEM
	return SPAM_TAG_UNKNOWN;
}

struct namesize_item {
	regex_t		pattern;
	filesize_t	min_size;
	filesize_t	max_size;
};

static gboolean 
spam_add_name_and_size(const char *name,
	filesize_t min_size, filesize_t max_size)
{
	struct namesize_item *item;
	int error;

	g_return_val_if_fail(name, TRUE);
	g_return_val_if_fail(min_size <= max_size, TRUE);

	item = walloc(sizeof *item);
	error = regcomp(&item->pattern, name, REG_EXTENDED | REG_NOSUB);
	if (error) {
		char buf[1024];

		regerror(error, &item->pattern, buf, sizeof buf);
		g_warning("spam_add_name_and_size(): regcomp() failed: %s", buf);
		regfree(&item->pattern);
		wfree(item, sizeof *item);
		return TRUE;
	} else {
		item->min_size = min_size;
		item->max_size = max_size;
		spam_lut.sl_names = g_slist_prepend(spam_lut.sl_names, item);
		return FALSE;
	}
}

struct spam_item {
	struct sha1 sha1;
	char		*name;
	filesize_t  min_size;
	filesize_t  max_size;
	gboolean	done;
	gboolean	damaged;
};

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
 * @returns the amount of entries loaded or -1 on failure.
 */
static gulong
spam_load(FILE *f)
{
	static const struct spam_item zero_item;
	struct spam_item item;
	char line[1024];
	guint line_no = 0;
	bit_array_t tag_used[BIT_ARRAY_SIZE(NUM_SPAM_TAGS)];
	gulong item_count = 0;

	g_assert(f);

	/* Reset state */
	item = zero_item;
	bit_array_clear_range(tag_used, 0, NUM_SPAM_TAGS - 1U);

	while (fgets(line, sizeof line, f)) {
		const char *tag_name, *value;
		char *sp, *nl;
		spam_tag_t tag;

		line_no++;

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
		g_assert(UNSIGNED(tag) < UNSIGNED(NUM_SPAM_TAGS));

		if (SPAM_TAG_UNKNOWN != tag && !bit_array_flip(tag_used, tag)) {
			g_warning("spam_load(): duplicate tag \"%s\" in entry in line %u",
				tag_name, line_no);
			continue;
		}
		
		switch (tag) {
		case SPAM_TAG_ADDED:
			{
				time_t t;
				
				t = date2time(value, tm_time());
				if ((time_t) -1 == t) {
					item.damaged = TRUE;
				}
			}
			break;
			
		case SPAM_TAG_SHA1:
			{
				if (strlen(value) != SHA1_BASE32_SIZE) {
					item.damaged = TRUE;
					g_warning("spam_load(): SHA-1 has wrong length.");
				} else {
					const struct sha1 *raw;

					raw = base32_sha1(value);
					if (raw)
						item.sha1 = *raw;
					else
						item.damaged = TRUE;
				}
			}
			break;

		case SPAM_TAG_NAME:
			{
				if ('\0' == value[0]) {
					item.damaged = TRUE;
					g_warning("spam_load(): Missing filename pattern.");
				} else if (!utf8_is_valid_string(value)) {
					item.damaged = TRUE;
					g_warning("spam_load(): Filename pattern is not UTF-8.");
				} else {
					item.name = h_strdup(value);
				}
			}
			break;

		case SPAM_TAG_SIZE:
			{
				const char *endptr;
				guint64 u;
				int error;
					
				u = parse_uint64(value, &endptr, 10, &error);
				if (error) {
					item.damaged = TRUE;
					g_warning("spam_load(): Cannot parse SIZE: %s", value);
				} else {
					item.min_size = u;
					item.max_size = u;

					if ('-' == endptr[0]) {
						u = parse_uint64(&endptr[1], &endptr, 10, &error);
						if (error) {
							item.damaged = TRUE;
							g_warning("spam_load(): Cannot parse SIZE: %s",
								value);
						}
						if (u < item.min_size) {
							item.damaged = TRUE;
							g_warning("spam_load(): "
								"Maximum size below minimum size");
						} else {
							item.max_size = u;
						}
					}
				}
			}
			break;

		case SPAM_TAG_END:
			if (
				!bit_array_get(tag_used, SPAM_TAG_SHA1) &&
				!bit_array_get(tag_used, SPAM_TAG_NAME)
			) {
				g_warning("spam_load(): missing SHA1 or NAME tag");
				item.damaged = TRUE;
			}
			if (!bit_array_get(tag_used, SPAM_TAG_ADDED)) {
				g_warning("spam_load(): missing ADDED tag");
				item.damaged = TRUE;
			}
			item.done = TRUE;
			break;

		case SPAM_TAG_UNKNOWN:
			/* Ignore */
			break;
			
		case NUM_SPAM_TAGS:
			g_assert_not_reached();
			break;
		}

		if (item.done && !item.damaged) {
			if (bit_array_get(tag_used, SPAM_TAG_SHA1)) {
				spam_sha1_add(&item.sha1);
				item_count++;
			}
			if (bit_array_get(tag_used, SPAM_TAG_NAME)) {
				if (!bit_array_get(tag_used, SPAM_TAG_SIZE)) {
					item.min_size = 0;
					item.max_size = MAX_INT_VAL(filesize_t);
				}
				if (
					spam_add_name_and_size(item.name,
						item.min_size, item.max_size)
				) {
					item.damaged = TRUE;	
				} else {
					item_count++;
				}
			}
		}

		if (item.damaged) {
			g_warning("Damaged spam entry in line %u: "
				"tag_name=\"%s\", value=\"%s\"",
				line_no, tag_name, value);
		}

		if (item.done) {
			/* Reset state */
			HFREE_NULL(item.name);
			item = zero_item;
			bit_array_clear_range(tag_used, 0, NUM_SPAM_TAGS - 1U);
		}
	}

	spam_sha1_sync();

	return item_count;
}

/**
 * Watcher callback, invoked when the file from which we read the spam 
 * changed.
 */
static void
spam_changed(const char *filename, gpointer unused_udata)
{
	FILE *f;

	(void) unused_udata;

	f = file_fopen(filename, "r");
	if (f) {
		char buf[80];
		gulong count;

		spam_close();
		count = spam_load(f);
		fclose(f);

		gm_snprintf(buf, sizeof(buf), "Reloaded %lu spam items.", count);
		gcu_statusbar_message(buf);
	}
}

static void
spam_retrieve_from_file(FILE *f, const char *path, const char *filename)
{
	char *pathname;

	g_assert(f);
	g_assert(path);
	g_assert(filename);

	pathname = make_pathname(path, filename);
	watcher_register(pathname, spam_changed, NULL);
	HFREE_NULL(pathname);
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
	static file_path_t fp[3];
	guint num_fp = G_N_ELEMENTS(fp) - 1;
	FILE *f;
	int idx;
	
	file_path_set(&fp[0], settings_config_dir(), spam_text_file);
	file_path_set(&fp[1], PRIVLIB_EXP, spam_text_file);

#ifndef OFFICIAL_BUILD
	file_path_set(&fp[2], PACKAGE_EXTRA_SOURCE_DIR, spam_text_file);
	num_fp++;
#endif	/* !OFFICIAL_BUILD */

	f = file_config_open_read_norename_chosen(spam_what, fp, num_fp, &idx);
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
	spam_sha1_init();
	spam_retrieve();
}

/**
 * Frees all entries in the spam database.
 */
void
spam_close(void)
{
	GSList *sl;

	for (sl = spam_lut.sl_names; NULL != sl; sl = g_slist_next(sl)) {
		struct namesize_item *item = sl->data;

		g_assert(item);
		regfree(&item->pattern);
		wfree(item, sizeof *item);
	}
	g_slist_free(spam_lut.sl_names);
	spam_lut.sl_names = NULL;
	spam_sha1_close();
}

/**
 * Check the given filename against the spam database.
 *
 * @param filename the filename to check.
 * @returns TRUE if found, and FALSE if not.
 */
gboolean
spam_check_filename_and_size(const char *filename, filesize_t size)
{
	const GSList *sl;

	g_return_val_if_fail(filename, FALSE);

	for (sl = spam_lut.sl_names; NULL != sl; sl = g_slist_next(sl)) {
		const struct namesize_item *item = sl->data;

		g_assert(item);
		if (
			size >= item->min_size &&
			size <= item->max_size &&
			0 == regexec(&item->pattern, filename, 0, NULL, 0)
		) {
			return TRUE;
		}
	}
	return FALSE;
}

/* vi: set ts=4 sw=4 cindent: */
