/*
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

#include "spam.h"
#include "settings.h"
#include "nodes.h"

#include "lib/atoms.h"
#include "lib/bit_array.h"
#include "lib/file.h"
#include "lib/getdate.h"
#include "lib/halloc.h"
#include "lib/halloc.h"
#include "lib/parse.h"
#include "lib/path.h"
#include "lib/pslist.h"
#include "lib/str.h"
#include "lib/tokenizer.h"
#include "lib/utf8.h"
#include "lib/walloc.h"
#include "lib/watcher.h"

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

struct spam_lut {
	pslist_t *sl_names;	/* List of struct namesize_item */
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

static const tokenizer_t spam_tags[] = {
	/* Must be sorted alphabetically for dichotomic search */

#define SPAM_TAG(x) { #x, CAT2(SPAM_TAG_,x) }
	SPAM_TAG(ADDED),
	SPAM_TAG(END),
	SPAM_TAG(NAME),
	SPAM_TAG(SHA1),
	SPAM_TAG(SIZE),

	/* Above line intentionally left blank (for "!}sort" on vi) */
#undef SPAM_TAG
};

static inline spam_tag_t
spam_string_to_tag(const char *s)
{
	return TOKENIZE(s, spam_tags);
}

struct namesize_item {
	regex_t		pattern;
	filesize_t	min_size;
	filesize_t	max_size;
};

static bool
spam_add_name_and_size(const char *name,
	filesize_t min_size, filesize_t max_size)
{
	struct namesize_item *item;
	int error;

	g_return_val_if_fail(name, TRUE);
	g_return_val_if_fail(min_size <= max_size, TRUE);

	WALLOC(item);
	error = regcomp(&item->pattern, name, REG_EXTENDED | REG_NOSUB);
	if (error) {
		char buf[1024];

		regerror(error, &item->pattern, buf, sizeof buf);
		g_warning("%s(): regcomp() failed: %s", G_STRFUNC, buf);
		regfree(&item->pattern);
		WFREE(item);
		return TRUE;
	} else {
		item->min_size = min_size;
		item->max_size = max_size;
		spam_lut.sl_names = pslist_prepend(spam_lut.sl_names, item);
		return FALSE;
	}
}

struct spam_item {
	struct sha1 sha1;
	char		*name;
	filesize_t  min_size;
	filesize_t  max_size;
	bool	done;
	bool	damaged;
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
static ulong G_COLD
spam_load(FILE *f)
{
	static const struct spam_item zero_item;
	struct spam_item item;
	char line[1024];
	uint line_no = 0;
	bit_array_t tag_used[BIT_ARRAY_SIZE(NUM_SPAM_TAGS)];
	ulong item_count = 0;

	g_assert(f);

	/* Reset state */
	item = zero_item;
	bit_array_init(tag_used, NUM_SPAM_TAGS);

	while (fgets(line, sizeof line, f)) {
		const char *tag_name, *value;
		char *sp;
		spam_tag_t tag;

		line_no++;

		if (!file_line_chomp_tail(line, sizeof line, NULL)) {
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
			g_warning("%s(): duplicate tag \"%s\" in entry in line %u",
				G_STRFUNC, tag_name, line_no);
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
					g_warning("%s(): SHA-1 has wrong length.", G_STRFUNC);
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
					g_warning("%s(): missing filename pattern.", G_STRFUNC);
				} else if (!utf8_is_valid_string(value)) {
					item.damaged = TRUE;
					g_warning("%s(): filename pattern is not UTF-8.",
						G_STRFUNC);
				} else {
					item.name = h_strdup(value);
				}
			}
			break;

		case SPAM_TAG_SIZE:
			{
				const char *endptr;
				uint64 u;
				int error;

				u = parse_uint64(value, &endptr, 10, &error);
				if (error) {
					item.damaged = TRUE;
					g_warning("%s(): cannot parse SIZE: %s", G_STRFUNC, value);
				} else {
					item.min_size = u;
					item.max_size = u;

					if ('-' == endptr[0]) {
						u = parse_uint64(&endptr[1], &endptr, 10, &error);
						if (error) {
							item.damaged = TRUE;
							g_warning("%s(): cannot parse SIZE: %s",
								G_STRFUNC, value);
						}
						if (u < item.min_size) {
							item.damaged = TRUE;
							g_warning("%s(): maximum size below minimum size",
								G_STRFUNC);
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
				g_warning("%s(): missing SHA1 or NAME tag", G_STRFUNC);
				item.damaged = TRUE;
			}
			if (!bit_array_get(tag_used, SPAM_TAG_ADDED)) {
				g_warning("%s(): missing ADDED tag", G_STRFUNC);
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
			g_warning("%s(): damaged spam entry in line %u: "
				"tag_name=\"%s\", value=\"%s\"",
				G_STRFUNC, line_no, tag_name, value);
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
spam_changed(const char *filename, void *unused_udata)
{
	FILE *f;

	(void) unused_udata;

	f = file_fopen(filename, "r");
	if (f) {
		char buf[80];
		ulong count;

		spam_close();
		count = spam_load(f);
		fclose(f);

		str_bprintf(buf, sizeof(buf), "Reloaded %lu spam items.", count);
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
	file_path_t fp[4];
	FILE *f;
	int idx;
	unsigned length;

	length = settings_file_path_load(fp, spam_text_file, SFP_DFLT);

	g_assert(length <= G_N_ELEMENTS(fp));

	f = file_config_open_read_norename_chosen(spam_what, fp, length, &idx);
	if (f != NULL) {
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
	TOKENIZE_CHECK_SORTED(spam_tags);

	spam_sha1_init();
	spam_retrieve();
}

/**
 * Frees all entries in the spam database.
 */
void
spam_close(void)
{
	pslist_t *sl;

	PSLIST_FOREACH(spam_lut.sl_names, sl) {
		struct namesize_item *item = sl->data;

		g_assert(item);
		regfree(&item->pattern);
		WFREE(item);
	}
	pslist_free_null(&spam_lut.sl_names);
	spam_sha1_close();
}

/**
 * Check the given filename against the spam database.
 *
 * @param filename the filename to check.
 * @returns TRUE if found, and FALSE if not.
 */
bool
spam_check_filename_size(const char *filename, filesize_t size)
{
	const pslist_t *sl;

	g_return_val_if_fail(filename, FALSE);

	PSLIST_FOREACH(spam_lut.sl_names, sl) {
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
