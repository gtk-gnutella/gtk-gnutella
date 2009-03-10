/*
 * $Id$
 *
 * Copyright (c) 2007, Raphael Manfredi
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
 * Address caching of G2-only hosts.
 *
 * The so-called "G2" is actually another search protocol proposed as an
 * alternative to Gnutella and which has diverged from it.  We don't care
 * about whether this search protocol is better or worse than Gnutella.
 * What's important is that servents supporting "G2" and Gnutella servents
 * share the same filespace.
 *
 * However, for stupid political reasons on the part of "G2" proponents,
 * the "G2" servents do not always allow sharing of their files with Gnutella,
 * whereas most Gnutella servents, and GTKG for sure, will fully allow "G2"
 * hosts from using the Gnutella extensions to HTTP to download files.
 *
 * The purpose of this cache is to store the addresses of known G2-only hosts
 * so that we can prevent the propagation of their addresses in the download
 * mesh.  Note that there is no problem if these G2 hosts also allow connection
 * from Gnutella servents, thereby extending the sharing space nicely.  But
 * hosts which explicitly forbid sharing with Gnutella servents must not have
 * their addresses propagated in the Gnutella mesh.
 *
 * @author Raphael Manfredi
 * @date 2006-2007
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
#include "g2_cache.h"

#include "if/gnet_property_priv.h"

#include "lib/override.h"		/* Must be the last header included */

static gboolean
g2_cache_item_expired(time_t seen, time_t now)
{
	time_delta_t d = delta_time(now, seen);
	return d < 0 || d > (time_delta_t) GNET_PROPERTY(g2_cache_max_time);
}

static hash_list_t *g2_hosts;

typedef enum {
	G2_CACHE_TAG_UNKNOWN = 0,

	G2_CACHE_TAG_END,
	G2_CACHE_TAG_HOST,
	G2_CACHE_TAG_SEEN,

	NUM_G2_CACHE_TAGS
} g2_cache_tag_t;

static const struct g2_cache_tag {
	g2_cache_tag_t	tag;
	const char *str;
} g2_cache_tag_map[] = {
	/* Must be sorted alphabetically for dichotomic search */

#define G2_CACHE_TAG(x) { CAT2(G2_CACHE_TAG_,x), #x }
	G2_CACHE_TAG(END),
	G2_CACHE_TAG(HOST),
	G2_CACHE_TAG(SEEN),

	/* Above line intentionally left blank (for "!}sort" on vi) */
#undef G2_CACHE_TAG
};

static g2_cache_tag_t
g2_cache_string_to_tag(const char *s)
{
	STATIC_ASSERT(G_N_ELEMENTS(g2_cache_tag_map) == (NUM_G2_CACHE_TAGS - 1));

#define GET_ITEM(i) (g2_cache_tag_map[(i)].str)
#define FOUND(i) G_STMT_START { \
	return g2_cache_tag_map[(i)].tag; \
	/* NOTREACHED */ \
} G_STMT_END

	/* Perform a binary search to find ``s'' */
	BINARY_SEARCH(const char *, s, G_N_ELEMENTS(g2_cache_tag_map), strcmp,
		GET_ITEM, FOUND);

#undef FOUND
#undef GET_ITEM
	return G2_CACHE_TAG_UNKNOWN;
}

struct g2_cache_item {
	gnet_host_t host;
	time_t seen;
};

static void
g2_cache_dump(FILE *f)
{
	hash_list_iter_t *iter;

	g_return_if_fail(f);
	g_return_if_fail(g2_hosts);

	iter = hash_list_iterator(g2_hosts);
	while (hash_list_iter_has_next(iter)) {
		const struct g2_cache_item *item;
		
		item = hash_list_iter_next(iter);
		fprintf(f, "HOST %s\nSEEN %s\nEND\n\n",
			gnet_host_to_string(&item->host), timestamp_to_string(item->seen));
	}
	hash_list_iter_release(&iter);
}

static file_path_t *
g2_cache_file_path(void)
{
	static file_path_t fp;
	static gboolean initialized;

	if (!initialized) {
		initialized = TRUE;
		file_path_set(&fp, g_strdup(settings_config_dir()), "g2_cache");
	}
	return &fp;
}

static void
g2_cache_store(void)
{
	FILE *f;

	f = file_config_open_write("G2 cache", g2_cache_file_path());
	if (f) {
		g2_cache_dump(f);
		file_config_close(f, g2_cache_file_path());
	}
}

static void
g2_cache_store_periodically(time_t now)
{
	static time_t last_stored;

	if (!last_stored || delta_time(now, last_stored) > 600) {
		g2_cache_store();
		last_stored = tm_time();	/* Ignore failure */
	}
}


static void
g2_cache_remove_oldest(void)
{
	struct g2_cache_item *item;
	
	item = hash_list_head(g2_hosts);
	if (item) {
		hash_list_remove(g2_hosts, item);
		wfree(item, sizeof *item);
	}
}

static void
g2_cache_insert_intern(const struct g2_cache_item *item)
{
	gconstpointer key;
	int removed;

	g_return_if_fail(item);

	key = hash_list_remove(g2_hosts, item);
	if (key) {
		struct g2_cache_item *item_ptr = deconstify_gpointer(key);

		/* We'll move the host to the end of the list */
		if (GNET_PROPERTY(g2_debug)) {
			g_message("Refreshing G2 host %s",
				gnet_host_to_string(&item->host));
		}
		item_ptr->seen = item->seen;
	} else {
		if (GNET_PROPERTY(g2_debug)) {
			g_message("Adding G2 host %s", gnet_host_to_string(&item->host));
		}
		key = wcopy(item, sizeof *item);
	}
	hash_list_append(g2_hosts, key);

	/* Remove the oldest host once we hit a reasonable limit */
	removed = 0;
	while (hash_list_length(g2_hosts) > GNET_PROPERTY(g2_cache_max_hosts)) {
		g2_cache_remove_oldest();

		/* If the limit was lowered drastically avoid doing too much work */
		if (++removed >= 512)
			break;
	}
	
	item = hash_list_head(g2_hosts);
	if (item && g2_cache_item_expired(item->seen, tm_time())) {
		g2_cache_remove_oldest();
	}
}

void
g2_cache_insert(const host_addr_t addr, guint16 port)
{
	struct g2_cache_item item;
	time_t now;

	g_return_if_fail(is_host_addr(addr));
	g_return_if_fail(0 != port);

	now = tm_time();
	gnet_host_set(&item.host, addr, port);
	item.seen = now;
	g2_cache_insert_intern(&item);
	g2_cache_store_periodically(now);
}

static struct g2_cache_item *
g2_cache_lookup_intern(const host_addr_t addr, guint16 port)
{
	if (host_addr_initialized(addr) && is_host_addr(addr) && 0 != port) {
		struct g2_cache_item item;
		gconstpointer key;

		gnet_host_set(&item.host, addr, port);
		if (hash_list_contains(g2_hosts, &item, &key)) {
			struct g2_cache_item *item_ptr = deconstify_gpointer(key);
			
			if (!g2_cache_item_expired(item_ptr->seen, tm_time()))
				return item_ptr;

			hash_list_remove(g2_hosts, item_ptr);
			wfree(item_ptr, sizeof *item_ptr);
		}
	}
	return NULL;
}

/**
 * @return TRUE if addr:port is currently in the cache.
 */
gboolean
g2_cache_lookup(const host_addr_t addr, guint16 port)
{
	return NULL != g2_cache_lookup_intern(addr, port);
}

/*
 * @return If the addr:port is not found, zero is returned. Otherwise, the
 *         timestamp the time of the last refresh is returned.
 */
time_t
g2_cache_get_timestamp(const host_addr_t addr, guint16 port)
{
	const struct g2_cache_item *item;

	item = g2_cache_lookup_intern(addr, port);
	return item ? item->seen : 0;
}

static guint
g2_cache_item_hash(gconstpointer key)
{
	const struct g2_cache_item *item = key;
	return host_hash(&item->host);
}

static int
g2_cache_item_eq(gconstpointer v1, gconstpointer v2)
{
	const struct g2_cache_item *a = v1, *b = v2;
	return host_eq(&a->host,& b->host);
}

static void
g2_cache_parse(FILE *f)
{
	bit_array_t tag_used[BIT_ARRAY_SIZE(NUM_G2_CACHE_TAGS)];
	static const struct g2_cache_item zero_item;
	struct g2_cache_item item;
	char line[1024];
	guint line_no = 0;
	gboolean done = FALSE;

	g_return_if_fail(f);

	/* Reset state */
	done = FALSE;
	item = zero_item;
	bit_array_clear_range(tag_used, 0, (guint) NUM_G2_CACHE_TAGS - 1);

	while (fgets(line, sizeof line, f)) {
		const char *tag_name, *value;
		char *sp, *nl;
		gboolean damaged;
		g2_cache_tag_t tag;

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
			g_warning("g2_cache_parse(): "
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

		tag = g2_cache_string_to_tag(tag_name);
		g_assert((int) tag >= 0 && tag < NUM_G2_CACHE_TAGS);
		if (G2_CACHE_TAG_UNKNOWN != tag && !bit_array_flip(tag_used, tag)) {
			g_warning(
				"g2_cache_load(): duplicate tag \"%s\" in entry in line %u",
				tag_name, line_no);
			break;
		}
		
		switch (tag) {
		case G2_CACHE_TAG_HOST:
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

		case G2_CACHE_TAG_SEEN:
			item.seen = date2time(value, tm_time());
			if ((time_t) -1 == item.seen) {
				damaged = TRUE;
			}
			break;
			
		case G2_CACHE_TAG_END:
			if (!bit_array_get(tag_used, G2_CACHE_TAG_HOST)) {
				g_warning("g2_cache_load(): missing HOST tag");
				damaged = TRUE;
			}
			if (!bit_array_get(tag_used, G2_CACHE_TAG_SEEN)) {
				g_warning("g2_cache_load(): missing SEEN tag");
				damaged = TRUE;
			}
			done = TRUE;
			break;

		case G2_CACHE_TAG_UNKNOWN:
			/* Ignore */
			break;
			
		case NUM_G2_CACHE_TAGS:
			g_assert_not_reached();
			break;
		}

		if (damaged) {
			g_warning("Damaged G2 cache entry in line %u: "
				"tag_name=\"%s\", value=\"%s\"",
				line_no, tag_name, value);
			break;
		}

		if (done) {
			if (
				g2_cache_lookup(gnet_host_get_addr(&item.host),
					gnet_host_get_port(&item.host))
			) {
				g_warning(
					"Ignoring duplicate G2 cache item around line %u (%s)",
				   	line_no, gnet_host_to_string(&item.host));
			} else if (!g2_cache_item_expired(item.seen, tm_time())) {
				g2_cache_insert_intern(&item);
			}
			
			/* Reset state */
			done = FALSE;
			item = zero_item;
			bit_array_clear_range(tag_used, 0, NUM_G2_CACHE_TAGS - 1U);
		}
	}
}

static void
g2_cache_load(void)
{
	FILE *f;

	f = file_config_open_read("G2 cache", g2_cache_file_path(), 1);
	if (f) {
		guint n;
		
		g2_cache_parse(f);
		n = hash_list_length(g2_hosts);
		if (GNET_PROPERTY(g2_debug)) {
			g_message("Loaded %u items from the G2 cache", n);
		}
		fclose(f);
	}
}

void
g2_cache_init(void)
{
	g_return_if_fail(!g2_hosts);

	g2_hosts = hash_list_new(g2_cache_item_hash, g2_cache_item_eq);
	g2_cache_load();
}

void
g2_cache_close(void)
{
	if (g2_hosts) {
		g2_cache_store();
		while (hash_list_length(g2_hosts) > 0) {
			g2_cache_remove_oldest();
		}
		hash_list_free(&g2_hosts);
	}
}

/* vi: set ts=4 sw=4 cindent: */
