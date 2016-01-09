/*
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
 * Caching of hosts by IP:port to be able to make "existence" checks, i.e.
 * determine whether a particular IP:port belongs to the cache and when
 * it was added.
 *
 * This is generic code handling entries formatted as:
 *
 *   HOST 10.19.182.13:1033
 *   SEEN 2010-10-27 14:25:06
 *   END
 *
 * and which are added through ipp_cache_insert(), and removed through
 * ipp_cache_remove().  Lookups are made via ipp_cache_lookup().
 *
 * Convenient wrappers are provided for each of the caches we manage here.
 * For instance, tls_cache_lookup() can be used to operate on the TLS cache.
 *
 * Each cache is configured to hold a maximum amount of entries, along with
 * a maximum lifetime for the data so that old-enough entries can be
 * expired.
 *
 * @author Raphael Manfredi
 * @date 2007-2009
 * @author Christian Biere
 * @date 2006
 */

#include "common.h"

#include "ipp_cache.h"

#include "hosts.h"
#include "settings.h"

#include "lib/bit_array.h"
#include "lib/endian.h"
#include "lib/file.h"
#include "lib/getdate.h"
#include "lib/hashlist.h"
#include "lib/host_addr.h"
#include "lib/timestamp.h"
#include "lib/tokenizer.h"
#include "lib/walloc.h"

#include "if/gnet_property_priv.h"

#include "lib/override.h"		/* Must be the last header included */

#define IPP_CACHE_PERIOD	600		/**< Store cache every 10 minutes */
#define IPP_CACHE_REMOVE	512		/**< Do not remove more items in purge */

/**
 * An IP:port cache instance.
 */
struct ipp_cache {
	file_path_t fp;					/**< Path to cache file on disk */
	const char *name;				/**< Cache name */
	const char *item_name;			/**< Cache item name */
	const char *description;		/**< Cache description for comments */
	const uint32 *max_cache_time;	/**< Amount of time data can stay cached */
	const uint32 *max_cache_size;	/**< Max amount od items to cache */
	hash_list_t *hosts;				/**< The caching structure */
	time_t last_stored;				/**< Last time cache was persisted */
	const uint32 *debug;			/**< Debug level for this cache */
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

static uint
ipp_cache_item_hash(const void *key)
{
	const struct ipp_cache_item *item = key;
	return gnet_host_hash(&item->host);
}

static int
ipp_cache_item_eq(const void *v1, const void *v2)
{
	const struct ipp_cache_item *a = v1, *b = v2;
	return gnet_host_equal(&a->host,& b->host);
}

/**
 * Create an IP:port cache instance.
 */
static ipp_cache_t *
ipp_cache_alloc(
	const char *name, const char *item_name, const char *file_name,
	const char *description,
	const uint32 *max_cache_time, const uint32 *max_cache_size,
	const uint32 *debug)
{
	ipp_cache_t *ic;

	WALLOC(ic);
	ic->name = name;
	ic->item_name = item_name;
	ic->description = description;
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
static bool
ipp_cache_item_expired(const ipp_cache_t *ic, time_t seen, time_t now)
{
	time_delta_t d = delta_time(now, seen);
	return d < 0 || d > (time_delta_t) *ic->max_cache_time;
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

static const tokenizer_t ipp_cache_tags[] = {
	/* Must be sorted alphabetically for dichotomic search */

#define IPP_CACHE_TAG(x) { #x, CAT2(IPP_CACHE_TAG_,x) }
	IPP_CACHE_TAG(END),
	IPP_CACHE_TAG(HOST),
	IPP_CACHE_TAG(SEEN),

	/* Above line intentionally left blank (for "!}sort" on vi) */
#undef IPP_CACHE_TAG
};

/**
 * Convert a string representation of a serializing tag to its token number.
 */
static inline ipp_cache_tag_t
ipp_cache_string_to_tag(const char *s)
{
	return TOKENIZE(s, ipp_cache_tags);
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

	file_config_preamble(f, ic->description);

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
		WFREE(item);
	}
}

/**
 * Physically insert item in cache.
 */
static void
ipp_cache_insert_intern(ipp_cache_t *ic, const struct ipp_cache_item *item)
{
	const void *key;
	int removed;
	size_t max_size;

	g_return_if_fail(item);

	key = hash_list_remove(ic->hosts, item);
	if (key) {
		struct ipp_cache_item *item_ptr = deconstify_pointer(key);

		/* We'll move the host to the end of the list */
		if (*ic->debug > 3) {
			g_debug("refreshing %s host %s",
				ic->item_name, gnet_host_to_string(&item->host));
		}
		item_ptr->seen = item->seen;
	} else {
		if (*ic->debug > 3) {
			g_debug("adding %s host %s",
				ic->item_name, gnet_host_to_string(&item->host));
		}
		key = wcopy(item, sizeof *item);
	}
	hash_list_append(ic->hosts, key);

	/* Remove the oldest host once we hit a reasonable limit */
	removed = 0;
	max_size = (size_t) *ic->max_cache_size;
	while (hash_list_length(ic->hosts) > max_size) {
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
ipp_cache_insert(enum ipp_cache_id cid, const host_addr_t addr, uint16 port)
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
	const host_addr_t addr, uint16 port)
{
	g_assert(ic);

	if (host_addr_initialized(addr) && is_host_addr(addr) && 0 != port) {
		struct ipp_cache_item item;
		const void *key;

		gnet_host_set(&item.host, addr, port);
		if (hash_list_find(ic->hosts, &item, &key)) {
			struct ipp_cache_item *item_ptr = deconstify_pointer(key);
			
			if (!ipp_cache_item_expired(ic, item_ptr->seen, tm_time()))
				return item_ptr;

			hash_list_remove(ic->hosts, item_ptr);
			WFREE(item_ptr);
		}
	}
	return NULL;
}

/**
 * @return TRUE if addr:port is currently in the cache.
 */
bool
ipp_cache_lookup(enum ipp_cache_id cid, const host_addr_t addr, uint16 port)
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
	const host_addr_t addr, uint16 port)
{
	const struct ipp_cache_item *item;
	ipp_cache_t *ic = get_cache(cid);

	item = ipp_cache_lookup_intern(ic, addr, port);
	return item ? item->seen : 0;
}

/**
 * Physical cache removal of an entry (if found).
 *
 * @return whether entry was found and deleted.
 */
static bool
ipp_cache_remove_intern(const ipp_cache_t *ic,
	const host_addr_t addr, uint16 port)
{
	g_assert(ic);

	if (host_addr_initialized(addr) && is_host_addr(addr) && 0 != port) {
		struct ipp_cache_item item;
		const void *key;

		gnet_host_set(&item.host, addr, port);
		if (hash_list_find(ic->hosts, &item, &key)) {
			struct ipp_cache_item *item_ptr = deconstify_pointer(key);
			
			hash_list_remove(ic->hosts, item_ptr);
			WFREE(item_ptr);
			return TRUE;
		}
	}
	return FALSE;
}

/**
 * Remove IP:port tuple from cache.
 *
 * @return TRUE if found and removed.
 */
bool
ipp_cache_remove(enum ipp_cache_id cid, const host_addr_t addr, uint16 port)
{
	ipp_cache_t *ic = get_cache(cid);
	return ipp_cache_remove_intern(ic, addr, port);
}

/**
 * Parse persisted cache.
 */
static void G_COLD
ipp_cache_parse(ipp_cache_t *ic, FILE *f)
{
	bit_array_t tag_used[BIT_ARRAY_SIZE(NUM_IPP_CACHE_TAGS)];
	static const struct ipp_cache_item zero_item;
	struct ipp_cache_item item;
	char line[1024];
	uint line_no = 0;
	bool done = FALSE;

	g_return_if_fail(f);

	/* Reset state */
	done = FALSE;
	item = zero_item;
	bit_array_init(tag_used, NUM_IPP_CACHE_TAGS);
	bit_array_clear_range(tag_used, 0, NUM_IPP_CACHE_TAGS - 1U);

	while (fgets(line, sizeof line, f)) {
		const char *tag_name, *value;
		char *sp;
		bool damaged;
		ipp_cache_tag_t tag;

		line_no++;

		damaged = FALSE;
		if (!file_line_chomp_tail(line, sizeof line, NULL)) {
			/*
			 * If the line is too long or unterminated the file is either
			 * corrupt or was manually edited without respecting the
			 * exact format. If we continued, we would read from the
			 * middle of a line which could be the filename or ID.
			 */
			g_warning("%s(\"%s\"): line %u too long or missing newline",
				G_STRFUNC, ic->name, line_no);
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

		tag = ipp_cache_string_to_tag(tag_name);
		g_assert(UNSIGNED(tag) < NUM_IPP_CACHE_TAGS);
		if (IPP_CACHE_TAG_UNKNOWN != tag && !bit_array_flip(tag_used, tag)) {
			g_warning(
				"%s(\"%s\"): duplicate tag \"%s\" in entry in line %u",
				G_STRFUNC, ic->name, tag_name, line_no);
			break;
		}
		
		switch (tag) {
		case IPP_CACHE_TAG_HOST:
			{
				host_addr_t addr;
				uint16 port;

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
				g_warning("%s(): missing HOST tag", G_STRFUNC);
				damaged = TRUE;
			}
			if (!bit_array_get(tag_used, IPP_CACHE_TAG_SEEN)) {
				g_warning("%s(): missing SEEN tag", G_STRFUNC);
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
			g_warning("%s(): damaged %s cache entry in line %u: "
				"tag_name=\"%s\", value=\"%s\"",
				G_STRFUNC, ic->item_name, line_no, tag_name, value);
			break;
		}

		if (done) {
			if (
				ipp_cache_lookup_intern(ic, gnet_host_get_addr(&item.host),
					gnet_host_get_port(&item.host))
			) {
				g_warning("%s(): ignoring duplicate %s cache item around "
					"line %u (%s)",
					G_STRFUNC, ic->item_name, line_no,
					gnet_host_to_string(&item.host));
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
 * Clear content of the cache.
 */
static void
ipp_cache_clear(ipp_cache_t *ic)
{
	if (ic && ic->hosts) {
		while (hash_list_length(ic->hosts) > 0) {
			ipp_cache_remove_oldest(ic);
		}
	}
}

/**
 * Retrieve cache from disk file.
 */
static void G_COLD
ipp_cache_load(ipp_cache_t *ic)
{
	FILE *f;

	f = file_config_open_read(ic->name, &ic->fp, 1);
	if (f) {
		uint n;
		
		ipp_cache_clear(ic);
		ipp_cache_parse(ic, f);
		n = hash_list_length(ic->hosts);
		if (*ic->debug > 3) {
			g_debug("loaded %u items from the %s cache", n, ic->item_name);
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

	ipp_cache_clear(ic);
	hash_list_free(&ic->hosts);
	g_free(deconstify_pointer(ic->fp.dir));
	ic->fp.dir = NULL;	/* Don't use G_FREE_NULL b/c of lvalue cast */
	WFREE(ic);
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
 *
 * This must happen before settings_init() is called to create the data
 * structures, as some callbacks may insert data in the caches.  Later on,
 * the caches can be loaded when we know the properties are all initialized.
 */
void G_COLD
ipp_cache_init(void)
{
	TOKENIZE_CHECK_SORTED(ipp_cache_tags);

	caches[IPP_CACHE_TLS] = ipp_cache_alloc(
		"TLS cache", "TLS", "tls_cache", "TLS-capable hosts",
		GNET_PROPERTY_PTR(tls_cache_max_time),
		GNET_PROPERTY_PTR(tls_cache_max_hosts),
		GNET_PROPERTY_PTR(tls_debug));

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
	 * allow "G2" hosts to download files.
	 *
	 * The purpose of this cache is to store the addresses of known G2-only
	 * hosts so that we can prevent the propagation of their addresses in the
	 * download mesh.  Note that there is no problem if these G2 hosts also
	 * allow connection from Gnutella servents, thereby extending the sharing
	 * space nicely.  But hosts which explicitly forbid sharing with Gnutella
	 * servents must not have their addresses propagated in the Gnutella mesh.
	 */

	caches[IPP_CACHE_G2] = ipp_cache_alloc(
		"G2 cache", "G2", "g2_cache", "Identified G2 servents",
		GNET_PROPERTY_PTR(g2_cache_max_time),
		GNET_PROPERTY_PTR(g2_cache_max_hosts),
		GNET_PROPERTY_PTR(g2_debug));

	/*
	 * The local address cache is remembering the recent IP:port combinations
	 * for this host that were routable.
	 *
	 * The purpose is to be able to spot alternate locations for files that
	 * point to older instances of ourselves, and which therefore should not
	 * be addedd to the mesh nor propagated further.
	 */

	caches[IPP_CACHE_LOCAL_ADDR] = ipp_cache_alloc(
		"Recent IP:port", "local IP:port", "local_addr",
		"Recent local IP:port",
		GNET_PROPERTY_PTR(local_addr_cache_max_time),
		GNET_PROPERTY_PTR(local_addr_cache_max_hosts),
		GNET_PROPERTY_PTR(local_addr_debug));

	/* Post-condition: all caches initialized */
	{
		size_t i;

		for (i = 0; i < IPP_CACHE_COUNT; i++) {
			g_assert(NULL != get_cache(i));
		}
	}
}

/**
 * Retrieve all the caches.
 *
 * Must be called only after settings_init() has been invoked, to make sure
 * all the properties are initialized.
 */
void
ipp_cache_load_all(void)
{
	ipp_cache_load(get_cache(IPP_CACHE_TLS));
	ipp_cache_load(get_cache(IPP_CACHE_G2));
	ipp_cache_load(get_cache(IPP_CACHE_LOCAL_ADDR));
}

/**
 * Save all the caches.
 */
void
ipp_cache_save_all(void)
{
	ipp_cache_store(get_cache(IPP_CACHE_TLS));
	ipp_cache_store(get_cache(IPP_CACHE_G2));
	ipp_cache_store(get_cache(IPP_CACHE_LOCAL_ADDR));
}

/**
 * Invalidate all IP:port caches.
 */
void
ipp_cache_close(void)
{
	ipp_cache_invalidate(IPP_CACHE_TLS);
	ipp_cache_invalidate(IPP_CACHE_G2);
	ipp_cache_invalidate(IPP_CACHE_LOCAL_ADDR);
}

/* vi: set ts=4 sw=4 cindent: */
