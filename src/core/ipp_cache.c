/*
 * $Id$
 *
 * Copyright (c) 2007-2009, Raphael Manfredi
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
 * Caching of hosts by IP:port.
 *
 * @author Raphael Manfredi
 * @date 2007-2009
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
#include "ipp_cache.h"

#include "if/gnet_property_priv.h"

#include "lib/override.h"		/* Must be the last header included */

#define IPP_CACHE_PERIOD	600		/**< Store cache every 10 minutes */
#define IPP_CACHE_REMOVE	512		/**< Do not remove more items in purge */

/**
 * An IP:port cache instance.
 */
struct ipp_cache {
	file_path_t fp;					/**< Path to cache file on disk */
	const gchar *name;				/**< Cache name */
	const gchar *item_name;			/**< Cache item name */
	time_delta_t max_cache_time;	/**< Amount of time data can stay cached */
	size_t max_cache_size;			/**< Max amount od items to cache */
	hash_list_t *hosts;				/**< The caching structure */
	time_t last_stored;				/**< Last time cache was persisted */
	guint32 debug;					/**< Debug level for this cache */
};

/**
 * The data stored in a cache entry.
 */
struct ipp_cache_item {
	gnet_host_t host;				/**< The IPP:port */
	time_t seen;					/**< Last time we saw this entry */
};

/**
 * The various IP:port caches we know about.
 */
static ipp_cache_t *caches[IPP_CACHE_COUNT];

static guint
ipp_cache_item_hash(gconstpointer key)
{
	const struct ipp_cache_item *item = key;
	return host_hash(&item->host);
}

static int
ipp_cache_item_eq(gconstpointer v1, gconstpointer v2)
{
	const struct ipp_cache_item *a = v1, *b = v2;
	return host_eq(&a->host,& b->host);
}

/**
 * Create an IP:port cache instance.
 */
static ipp_cache_t *
ipp_cache_alloc(
	const gchar *name, const gchar *item_name, const gchar *file_name,
	time_delta_t max_cache_time, size_t max_cache_size,
	guint32 debug)
{
	ipp_cache_t *ic;

	ic = walloc(sizeof *ic);
	ic->name = name;
	ic->item_name = item_name;
	ic->max_cache_time = max_cache_time;
	ic->max_cache_size = max_cache_size;
	ic->hosts = hash_list_new(ipp_cache_item_hash, ipp_cache_item_eq);
	ic->debug = debug;
	ic->last_stored = 0;

	file_path_set(&ic->fp, g_strdup(settings_config_dir()), file_name);

	return ic;
}

/**
 * Has a cached entry expired?
 */
static gboolean
ipp_cache_item_expired(const ipp_cache_t *ic, time_t seen, time_t now)
{
	time_delta_t d = delta_time(now, seen);
	return d < 0 || d > ic->max_cache_time;
}

/**
 * Tags used when serializing.
 */
typedef enum {
	IPP_CACHE_TAG_UNKNOWN = 0,

	IPP_CACHE_TAG_END,
	IPP_CACHE_TAG_HOST,
	IPP_CACHE_TAG_SEEN,

	NUM_IPP_CACHE_TAGS
} ipp_cache_tag_t;

static const struct ipp_cache_tag {
	ipp_cache_tag_t	tag;
	const char *str;
} ipp_cache_tag_map[] = {
	/* Must be sorted alphabetically for dichotomic search */

#define IPP_CACHE_TAG(x) { CAT2(IPP_CACHE_TAG_,x), #x }
	IPP_CACHE_TAG(END),
	IPP_CACHE_TAG(HOST),
	IPP_CACHE_TAG(SEEN),

	/* Above line intentionally left blank (for "!}sort" on vi) */
#undef IPP_CACHE_TAG
};

/**
 * Convert a string representation of a serializing tag to its token number.
 */
static ipp_cache_tag_t
ipp_cache_string_to_tag(const char *s)
{
	STATIC_ASSERT(G_N_ELEMENTS(ipp_cache_tag_map) == (NUM_IPP_CACHE_TAGS - 1));

#define GET_ITEM(i) (ipp_cache_tag_map[(i)].str)
#define FOUND(i) G_STMT_START { \
	return ipp_cache_tag_map[(i)].tag; \
	/* NOTREACHED */ \
} G_STMT_END

	/* Perform a binary search to find ``s'' */
	BINARY_SEARCH(const char *, s, G_N_ELEMENTS(ipp_cache_tag_map), strcmp,
		GET_ITEM, FOUND);

#undef FOUND
#undef GET_ITEM
	return IPP_CACHE_TAG_UNKNOWN;
}

/**
 * Dump cache to specified file descriptor.
 */
static void
ipp_cache_dump(ipp_cache_t *ic, FILE *f)
{
	hash_list_iter_t *iter;

	g_return_if_fail(ic);
	g_return_if_fail(f);

	iter = hash_list_iterator(ic->hosts);
	while (hash_list_iter_has_next(iter)) {
		const struct ipp_cache_item *item;
		
		item = hash_list_iter_next(iter);
		fprintf(f, "HOST %s\nSEEN %s\nEND\n\n",
			gnet_host_to_string(&item->host), timestamp_to_string(item->seen));
	}
	hash_list_iter_release(&iter);
}

/**
 * Store the cached data to disk.
 */
static void
ipp_cache_store(ipp_cache_t *ic)
{
	FILE *f;

	f = file_config_open_write(ic->name, &ic->fp);
	if (f) {
		ipp_cache_dump(ic, f);
		file_config_close(f, &ic->fp);
	}
}

/**
 * Attempt to store cache periodically.
 */
static void
ipp_cache_store_periodically(ipp_cache_t *ic, time_t now)
{
	if (
		!ic->last_stored ||
		delta_time(now, ic->last_stored) > IPP_CACHE_PERIOD
	) {
		ipp_cache_store(ic);
		ic->last_stored = tm_time();	/* Ignore failure */
	}
}


/**
 * Remove oldest cache entry.
 */
static void
ipp_cache_remove_oldest(ipp_cache_t *ic)
{
	struct ipp_cache_item *item;
	
	item = hash_list_head(ic->hosts);
	if (item) {
		hash_list_remove(ic->hosts, item);
		wfree(item, sizeof *item);
	}
}

/**
 * Physically insert item in cache.
 */
static void
ipp_cache_insert_intern(ipp_cache_t *ic, const struct ipp_cache_item *item)
{
	gconstpointer key;
	int removed;

	g_return_if_fail(item);

	key = hash_list_remove(ic->hosts, item);
	if (key) {
		struct ipp_cache_item *item_ptr = deconstify_gpointer(key);

		/* We'll move the host to the end of the list */
		if (ic->debug) {
			g_message("refreshing %s host %s",
				ic->item_name, gnet_host_to_string(&item->host));
		}
		item_ptr->seen = item->seen;
	} else {
		if (ic->debug) {
			g_message("adding %s host %s",
				ic->item_name, gnet_host_to_string(&item->host));
		}
		key = wcopy(item, sizeof *item);
	}
	hash_list_append(ic->hosts, key);

	/* Remove the oldest host once we hit a reasonable limit */
	removed = 0;
	while (hash_list_length(ic->hosts) > ic->max_cache_size) {
		ipp_cache_remove_oldest(ic);

		/* If the limit was lowered drastically avoid doing too much work */
		if (++removed >= IPP_CACHE_REMOVE)
			break;
	}
	
	item = hash_list_head(ic->hosts);
	if (item && ipp_cache_item_expired(ic, item->seen, tm_time())) {
		ipp_cache_remove_oldest(ic);
	}
}

/**
 * Translate a cache ID into a cache structure.
 */
static inline ipp_cache_t *
get_cache(enum ipp_cache_id cid)
{
	g_assert(cid < IPP_CACHE_COUNT);
	g_assert(caches[cid] != NULL);

	return caches[cid];
}

/**
 * Insert host in specified cache.
 */
void
ipp_cache_insert(enum ipp_cache_id cid, const host_addr_t addr, guint16 port)
{
	ipp_cache_t *ic = get_cache(cid);
	struct ipp_cache_item item;
	time_t now;

	g_return_if_fail(caches[cid]);
	g_return_if_fail(is_host_addr(addr));
	g_return_if_fail(0 != port);

	now = tm_time();
	gnet_host_set(&item.host, addr, port);
	item.seen = now;
	ipp_cache_insert_intern(ic, &item);
	ipp_cache_store_periodically(ic, now);
}

/**
 * Physical cache lookup.
 */
static struct ipp_cache_item *
ipp_cache_lookup_intern(const ipp_cache_t *ic,
	const host_addr_t addr, guint16 port)
{
	g_assert(ic);

	if (host_addr_initialized(addr) && is_host_addr(addr) && 0 != port) {
		struct ipp_cache_item item;
		gconstpointer key;

		gnet_host_set(&item.host, addr, port);
		if (hash_list_contains(ic->hosts, &item, &key)) {
			struct ipp_cache_item *item_ptr = deconstify_gpointer(key);
			
			if (!ipp_cache_item_expired(ic, item_ptr->seen, tm_time()))
				return item_ptr;

			hash_list_remove(ic->hosts, item_ptr);
			wfree(item_ptr, sizeof *item_ptr);
		}
	}
	return NULL;
}

/**
 * @return TRUE if addr:port is currently in the cache.
 */
gboolean
ipp_cache_lookup(enum ipp_cache_id cid, const host_addr_t addr, guint16 port)
{
	ipp_cache_t *ic = get_cache(cid);
	return NULL != ipp_cache_lookup_intern(ic, addr, port);
}

/*
 * @return If the addr:port is not found, zero is returned. Otherwise, the
 *         timestamp the time of the last refresh is returned.
 */
time_t
ipp_cache_get_timestamp(enum ipp_cache_id cid,
	const host_addr_t addr, guint16 port)
{
	const struct ipp_cache_item *item;
	ipp_cache_t *ic = get_cache(cid);

	item = ipp_cache_lookup_intern(ic, addr, port);
	return item ? item->seen : 0;
}

/**
 * Parse persisted cache.
 */
static void
ipp_cache_parse(ipp_cache_t *ic, FILE *f)
{
	bit_array_t tag_used[BIT_ARRAY_SIZE(NUM_IPP_CACHE_TAGS)];
	static const struct ipp_cache_item zero_item;
	struct ipp_cache_item item;
	char line[1024];
	guint line_no = 0;
	gboolean done = FALSE;

	g_return_if_fail(f);

	/* Reset state */
	done = FALSE;
	item = zero_item;
	bit_array_clear_range(tag_used, 0, (guint) NUM_IPP_CACHE_TAGS - 1);

	while (fgets(line, sizeof line, f)) {
		const char *tag_name, *value;
		char *sp, *nl;
		gboolean damaged;
		ipp_cache_tag_t tag;

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
			g_warning("ipp_cache_parse(\"%s\"): "
				"line too long or missing newline in line %u",
				ic->name, line_no);
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

		tag = ipp_cache_string_to_tag(tag_name);
		g_assert((int) tag >= 0 && tag < NUM_IPP_CACHE_TAGS);
		if (IPP_CACHE_TAG_UNKNOWN != tag && !bit_array_flip(tag_used, tag)) {
			g_warning(
				"ipp_cache_load(\"%s\"): "
				"duplicate tag \"%s\" in entry in line %u",
				ic->name, tag_name, line_no);
			break;
		}
		
		switch (tag) {
		case IPP_CACHE_TAG_HOST:
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

		case IPP_CACHE_TAG_SEEN:
			item.seen = date2time(value, tm_time());
			if ((time_t) -1 == item.seen) {
				damaged = TRUE;
			}
			break;
			
		case IPP_CACHE_TAG_END:
			if (!bit_array_get(tag_used, IPP_CACHE_TAG_HOST)) {
				g_warning("ipp_cache_load(): missing HOST tag");
				damaged = TRUE;
			}
			if (!bit_array_get(tag_used, IPP_CACHE_TAG_SEEN)) {
				g_warning("ipp_cache_load(): missing SEEN tag");
				damaged = TRUE;
			}
			done = TRUE;
			break;

		case IPP_CACHE_TAG_UNKNOWN:
			/* Ignore */
			break;
			
		case NUM_IPP_CACHE_TAGS:
			g_assert_not_reached();
			break;
		}

		if (damaged) {
			g_warning("damaged %s cache entry in line %u: "
				"tag_name=\"%s\", value=\"%s\"",
				ic->item_name, line_no, tag_name, value);
			break;
		}

		if (done) {
			if (
				ipp_cache_lookup_intern(ic, gnet_host_get_addr(&item.host),
					gnet_host_get_port(&item.host))
			) {
				g_warning(
					"ignoring duplicate %s cache item around line %u (%s)",
				   	ic->item_name, line_no, gnet_host_to_string(&item.host));
			} else if (!ipp_cache_item_expired(ic, item.seen, tm_time())) {
				ipp_cache_insert_intern(ic, &item);
			}
			
			/* Reset state */
			done = FALSE;
			item = zero_item;
			bit_array_clear_range(tag_used, 0, NUM_IPP_CACHE_TAGS - 1U);
		}
	}
}

/**
 * Retrieve cache from disk file.
 */
static void
ipp_cache_load(ipp_cache_t *ic)
{
	FILE *f;

	f = file_config_open_read(ic->name, &ic->fp, 1);
	if (f) {
		guint n;
		
		ipp_cache_parse(ic, f);
		n = hash_list_length(ic->hosts);
		if (ic->debug) {
			g_message("loaded %u items from the %s cache", n, ic->item_name);
		}
		fclose(f);
	}
}

/**
 * Destroy an IP:port cache instance.
 */
static void
ipp_cache_free(ipp_cache_t *ic)
{
	g_assert(ic);

	if (ic->hosts) {
		while (hash_list_length(ic->hosts) > 0) {
			ipp_cache_remove_oldest(ic);
		}
		hash_list_free(&ic->hosts);
	}

	g_free(deconstify_gpointer(ic->fp.dir));
	wfree(ic, sizeof *ic);
}

/**
 * Invalidate cache, destroying its structure.
 */
static void
ipp_cache_invalidate(enum ipp_cache_id cid)
{
	ipp_cache_t *ic;

	g_assert(cid < IPP_CACHE_COUNT);

	ic = caches[cid];
	ipp_cache_store(ic);
	ipp_cache_free(ic);
	caches[cid] = NULL;
}

/**
 * Initialize IP:port caches.
 */
void
ipp_cache_init(void)
{
	ipp_cache_t *ic;

	ic = ipp_cache_alloc("TLS cache", "TLS", "tls_cache",
		GNET_PROPERTY(tls_cache_max_time), GNET_PROPERTY(tls_cache_max_hosts),
		GNET_PROPERTY(tls_debug));

	caches[IPP_CACHE_TLS] = ic;
	ipp_cache_load(ic);

	/*
	 * Address caching of G2-only hosts.
	 *
	 * The so-called "G2" is actually another search protocol proposed as an
	 * alternative to Gnutella and which has diverged from it.  We don't care
	 * about whether this search protocol is better or worse than Gnutella.
	 * What's important is that servents supporting "G2" and Gnutella servents
	 * share the same filespace.
	 *
	 * However, for stupid political reasons on the part of "G2" proponents,
	 * the "G2" servents do not always allow sharing of their files with
	 * Gnutella, whereas most Gnutella servents, and GTKG for sure, will fully
	 * allow "G2" hosts to the Gnutella extensions to HTTP to download files.
	 *
	 * The purpose of this cache is to store the addresses of known G2-only
	 * hosts so that we can prevent the propagation of their addresses in the
	 * download mesh.  Note that there is no problem if these G2 hosts also
	 * allow connection from Gnutella servents, thereby extending the sharing
	 * space nicely.  But hosts which explicitly forbid sharing with Gnutella
	 * servents must not have their addresses propagated in the Gnutella mesh.
	 */

	ic = ipp_cache_alloc("G2 cache", "G2", "g2_cache",
		GNET_PROPERTY(g2_cache_max_time), GNET_PROPERTY(g2_cache_max_hosts),
		GNET_PROPERTY(g2_debug));

	caches[IPP_CACHE_G2] = ic;
	ipp_cache_load(ic);
}

/**
 * Invalidate all IP:port caches.
 */
void
ipp_cache_close(void)
{
	ipp_cache_invalidate(IPP_CACHE_TLS);
	ipp_cache_invalidate(IPP_CACHE_G2);
}

/* vi: set ts=4 sw=4 cindent: */
