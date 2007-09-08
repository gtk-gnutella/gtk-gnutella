/*
 * $Id$
 *
 * Copyright (c) 2006, Christian Biere
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
 * Address caching of TLS-capable hosts.
 *
 * @author Christian Biere
 * @date 2006
 */

#include "common.h"

RCSID("$Id$")

#include "lib/bit_array.h"
#include "lib/file.h"
#include "lib/getdate.h"
#include "lib/hashlist.h"
#include "lib/walloc.h"

#include "lib/endian.h"
#include "lib/host_addr.h"

#include "hosts.h"
#include "settings.h"
#include "tls_cache.h"

#include "if/gnet_property_priv.h"

#include "lib/override.h"		/* Must be the last header included */

static gboolean
tls_cache_item_expired(time_t seen, time_t now)
{
	time_delta_t d = delta_time(now, seen);
	return d < 0 || d > (time_delta_t) GNET_PROPERTY(tls_cache_max_time);
}

static hash_list_t *tls_hosts;

typedef enum {
	TLS_CACHE_TAG_UNKNOWN = 0,

	TLS_CACHE_TAG_END,
	TLS_CACHE_TAG_HOST,
	TLS_CACHE_TAG_SEEN,

	NUM_TLS_CACHE_TAGS
} tls_cache_tag_t;

static const struct tls_cache_tag {
	tls_cache_tag_t	tag;
	const char *str;
} tls_cache_tag_map[] = {
	/* Must be sorted alphabetically for dichotomic search */

#define TLS_CACHE_TAG(x) { CAT2(TLS_CACHE_TAG_,x), #x }
	TLS_CACHE_TAG(END),
	TLS_CACHE_TAG(HOST),
	TLS_CACHE_TAG(SEEN),

	/* Above line intentionally left blank (for "!}sort" on vi) */
#undef TLS_CACHE_TAG
};

static tls_cache_tag_t
tls_cache_string_to_tag(const char *s)
{
	STATIC_ASSERT(G_N_ELEMENTS(tls_cache_tag_map) == (NUM_TLS_CACHE_TAGS - 1));

#define GET_ITEM(i) (tls_cache_tag_map[(i)].str)
#define FOUND(i) G_STMT_START { \
	return tls_cache_tag_map[(i)].tag; \
	/* NOTREACHED */ \
} G_STMT_END

	/* Perform a binary search to find ``s'' */
	BINARY_SEARCH(const char *, s, G_N_ELEMENTS(tls_cache_tag_map), strcmp,
		GET_ITEM, FOUND);

#undef FOUND
#undef GET_ITEM
	return TLS_CACHE_TAG_UNKNOWN;
}

struct tls_cache_item {
	gnet_host_t host;
	time_t seen;
};

static void
tls_cache_dump(FILE *f)
{
	hash_list_iter_t *iter;

	g_return_if_fail(f);
	g_return_if_fail(tls_hosts);

	iter = hash_list_iterator(tls_hosts);
	while (hash_list_iter_has_next(iter)) {
		const struct tls_cache_item *item;
		
		item = hash_list_iter_next(iter);
		fprintf(f, "HOST %s\nSEEN %s\nEND\n\n",
			gnet_host_to_string(&item->host), timestamp_to_string(item->seen));
	}
	hash_list_iter_release(&iter);
}

static file_path_t *
tls_cache_file_path(void)
{
	static file_path_t fp;
	static gboolean initialized;

	if (!initialized) {
		initialized = TRUE;
		file_path_set(&fp, g_strdup(settings_config_dir()), "tls_cache");
	}
	return &fp;
}

static void
tls_cache_store(void)
{
	FILE *f;

	f = file_config_open_write("TLS cache", tls_cache_file_path());
	if (f) {
		tls_cache_dump(f);
		file_config_close(f, tls_cache_file_path());
	}
}

static void
tls_cache_store_periodically(time_t now)
{
	static time_t last_stored;

	if (!last_stored || delta_time(now, last_stored) > 600) {
		tls_cache_store();
		last_stored = tm_time();	/* Ignore failure */
	}
}


static void
tls_cache_remove_oldest(void)
{
	struct tls_cache_item *item;
	
	item = hash_list_head(tls_hosts);
	if (item) {
		hash_list_remove(tls_hosts, item);
		wfree(item, sizeof *item);
	}
}

void
tls_cache_insert_intern(const struct tls_cache_item *item)
{
	gconstpointer key;
	int removed;

	g_return_if_fail(item);

	key = hash_list_remove(tls_hosts, item);
	if (key) {
		struct tls_cache_item *item_ptr = deconstify_gpointer(key);

		/* We'll move the host to the end of the list */
		if (GNET_PROPERTY(tls_debug)) {
			g_message("Refreshing TLS host %s",
				gnet_host_to_string(&item->host));
		}
		item_ptr->seen = item->seen;
	} else {
		if (GNET_PROPERTY(tls_debug)) {
			g_message("Adding TLS host %s", gnet_host_to_string(&item->host));
		}
		key = wcopy(item, sizeof *item);
	}
	hash_list_append(tls_hosts, key);

	/* Remove the oldest host once we hit a reasonable limit */
	removed = 0;
	while (hash_list_length(tls_hosts) > GNET_PROPERTY(tls_cache_max_hosts)) {
		tls_cache_remove_oldest();

		/* If the limit was lowered drastically avoid doing too much work */
		if (++removed >= 512)
			break;
	}
	
	item = hash_list_head(tls_hosts);
	if (item && tls_cache_item_expired(item->seen, tm_time())) {
		tls_cache_remove_oldest();
	}
}

void
tls_cache_insert(const host_addr_t addr, guint16 port)
{
	struct tls_cache_item item;
	time_t now;

	g_return_if_fail(is_host_addr(addr));
	g_return_if_fail(0 != port);

	now = tm_time();
	gnet_host_set(&item.host, addr, port);
	item.seen = now;
	tls_cache_insert_intern(&item);
	tls_cache_store_periodically(now);
}

struct tls_cache_item *
tls_cache_lookup_intern(const host_addr_t addr, guint16 port)
{
	if (host_addr_initialized(addr) && is_host_addr(addr) && 0 != port) {
		struct tls_cache_item item;
		gconstpointer key;

		gnet_host_set(&item.host, addr, port);
		if (hash_list_contains(tls_hosts, &item, &key)) {
			struct tls_cache_item *item_ptr = deconstify_gpointer(key);
			
			if (!tls_cache_item_expired(item_ptr->seen, tm_time()))
				return item_ptr;

			hash_list_remove(tls_hosts, item_ptr);
			wfree(item_ptr, sizeof *item_ptr);
		}
	}
	return NULL;
}

/**
 * @return TRUE if addr:port is currently in the cache.
 */
gboolean
tls_cache_lookup(const host_addr_t addr, guint16 port)
{
	return NULL != tls_cache_lookup_intern(addr, port);
}

/*
 * @return If the addr:port is not found, zero is returned. Otherwise, the
 *         timestamp the time of the last refresh is returned.
 */
time_t
tls_cache_get_timestamp(const host_addr_t addr, guint16 port)
{
	const struct tls_cache_item *item;

	item = tls_cache_lookup_intern(addr, port);
	return item ? item->seen : 0;
}

static guint
tls_cache_item_hash(gconstpointer key)
{
	const struct tls_cache_item *item = key;
	return host_hash(&item->host);
}

static gint
tls_cache_item_eq(gconstpointer v1, gconstpointer v2)
{
	const struct tls_cache_item *a = v1, *b = v2;
	return host_eq(&a->host,& b->host);
}

static void
tls_cache_parse(FILE *f)
{
	bit_array_t tag_used[BIT_ARRAY_SIZE(NUM_TLS_CACHE_TAGS)];
	static const struct tls_cache_item zero_item;
	struct tls_cache_item item;
	char line[1024];
	guint line_no = 0;
	gboolean done = FALSE;

	g_return_if_fail(f);

	/* Reset state */
	done = FALSE;
	item = zero_item;
	bit_array_clear_range(tag_used, 0, (guint) NUM_TLS_CACHE_TAGS - 1);

	while (fgets(line, sizeof line, f)) {
		const char *tag_name, *value;
		gchar *sp, *nl;
		gboolean damaged;
		tls_cache_tag_t tag;

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
			g_warning("tls_cache_parse(): "
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

		tag = tls_cache_string_to_tag(tag_name);
		g_assert((gint) tag >= 0 && tag < NUM_TLS_CACHE_TAGS);
		if (TLS_CACHE_TAG_UNKNOWN != tag && !bit_array_flip(tag_used, tag)) {
			g_warning(
				"tls_cache_load(): duplicate tag \"%s\" in entry in line %u",
				tag_name, line_no);
			break;
		}
		
		switch (tag) {
		case TLS_CACHE_TAG_HOST:
			{
				host_addr_t addr;
				guint16 port;

				if (string_to_host_addr_port(value, NULL, &addr, &port)) {
					gnet_host_set(&item.host, addr, port);
				} else {
					damaged = TRUE;
				}
			}
			break;

		case TLS_CACHE_TAG_SEEN:
			item.seen = date2time(value, tm_time());
			if ((time_t) -1 == item.seen) {
				damaged = TRUE;
			}
			break;
			
		case TLS_CACHE_TAG_END:
			if (!bit_array_get(tag_used, TLS_CACHE_TAG_HOST)) {
				g_warning("tls_cache_load(): missing HOST tag");
				damaged = TRUE;
			}
			if (!bit_array_get(tag_used, TLS_CACHE_TAG_SEEN)) {
				g_warning("tls_cache_load(): missing SEEN tag");
				damaged = TRUE;
			}
			done = TRUE;
			break;

		case TLS_CACHE_TAG_UNKNOWN:
			/* Ignore */
			break;
			
		case NUM_TLS_CACHE_TAGS:
			g_assert_not_reached();
			break;
		}

		if (damaged) {
			g_warning("Damaged TLS cache entry in line %u: "
				"tag_name=\"%s\", value=\"%s\"",
				line_no, tag_name, value);
			break;
		}

		if (done) {
			if (
				tls_cache_lookup(gnet_host_get_addr(&item.host),
					gnet_host_get_port(&item.host))
			) {
				g_warning(
					"Ignoring duplicate TLS cache item around line %u (%s)",
				   	line_no, gnet_host_to_string(&item.host));
			} else if (!tls_cache_item_expired(item.seen, tm_time())) {
				tls_cache_insert_intern(&item);
			}
			
			/* Reset state */
			done = FALSE;
			item = zero_item;
			bit_array_clear_range(tag_used, 0, NUM_TLS_CACHE_TAGS - 1U);
		}
	}
}

static void
tls_cache_load(void)
{
	FILE *f;

	f = file_config_open_read("TLS cache", tls_cache_file_path(), 1);
	if (f) {
		guint n;
		
		tls_cache_parse(f);
		n = hash_list_length(tls_hosts);
		if (GNET_PROPERTY(tls_debug)) {
			g_message("Loaded %u items from the TLS cache", n);
		}
		fclose(f);
	}
}

void
tls_cache_init(void)
{
	g_return_if_fail(!tls_hosts);

	tls_hosts = hash_list_new(tls_cache_item_hash, tls_cache_item_eq);
	tls_cache_load();
}

void
tls_cache_close(void)
{
	if (tls_hosts) {
		tls_cache_store();
		while (hash_list_length(tls_hosts) > 0) {
			tls_cache_remove_oldest();
		}
		hash_list_free(&tls_hosts);
	}
}

/* vi: set ts=4 sw=4 cindent: */
