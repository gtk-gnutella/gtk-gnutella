/*
 * $Id$
 *
 * Copyright (c) 2002-2003, Raphael Manfredi, Richard Eckart
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
 * @file
 *
 * Host cache management.
 *
 * TODO: 
 *  - finer grained stats: 
 *      hits/misses while adding, 
 *      hits/misses while bad checking
 *      how many hosts were tried to connect to?
 *  - display stats about gwcache usage:
 *      how often
 *      how many hosts got
 *  - move unstable servant code from nodes.c to hcache.c
 *  - make sure hosts we are currently connected too are also saved
 *    to disk on exit!
 *  - save more metadata if we can make use of it.
 */

#include "gnutella.h"

#include <stdlib.h>

#include "hosts.h"
#include "hcache.h"
#include "pcache.h"
#include "nodes.h"

#include "settings.h"
#include "override.h"		/* Must be the last header included */

RCSID("$Id$");

#define MIN_RESERVE_SIZE	1024	/* we'd like that many pongs in reserve */

/**
 * An entry within the hostcache.
 *
 * We don't really store the IP/port, as those are stored in the key of
 * hash table recording all known hosts.  Rather, we store "metadata" about
 * the host.
 */
typedef struct hostcache_entry {
    hcache_type_t type;        /**< Hostcache which contains this host */
    time_t        time_added;  /**< Time when entry was added */
#if 0
	guint32       avg_uptime;  /**< Reported average uptime (seconds) */
	gchar *       vendor;	   /**< Latest known vendor name (atom) */
#endif
} hostcache_entry_t;

/** No metadata for host */
#define NO_METADATA			GINT_TO_POINTER(1)	

/**
 * A hostcache table.
 */
typedef struct hostcache {
	gchar *         name;		        /**< Name of the cache */
	hcache_type_t   type;				/**< Cache type */

    gboolean        ip_only;            /**< Use IP only, port always 0 */
    GList *         hostlist;           /**< Host list: IP/Port  */

    guint           hits;               /**< Hits to the cache */
    guint           misses;             /**< Misses to the cache */

    guint           host_count;			/**< Amount of hosts in cache */
	gnet_property_t reading;			/**< Property to signal reading */
    gnet_property_t hosts_in_catcher;   /**< Property to update host count */
    gint            mass_update;        /**< If a mass update is in progess */
} hostcache_t;

static hostcache_t *caches[HCACHE_MAX];

/**
 * Names of the host caches. 
 *
 * @note has to be in the same order as in the hcache_type_t definition
 *       in gnet_nodes.h.
 */
static const gchar * const names[HCACHE_MAX] = { 
    N_("fresh regular"), 
    N_("valid regular"),
    N_("fresh ultra"),
    N_("valid ultra"),
    N_("timeout"),
    N_("busy"),
    N_("unstable")
};

static const gchar * const host_type_names[HOST_MAX] = { 
    N_("any"), 
    N_("ultra"),
};


static gpointer bg_reader[HCACHE_MAX];

enum {
    HCACHE_ALREADY_CONNECTED,
    HCACHE_INVALID_HOST,
    HCACHE_LOCAL_INSTANCE,
    HCACHE_STATS_MAX
};

static guint stats[HCACHE_STATS_MAX];

/**
 * Initiate mass update of host cache. While mass updates are in
 * progress, the hosts_in_catcher property will not be updated.
 */
static void start_mass_update(hostcache_t *hc)
{
    hc->mass_update++;
}

/**
 * End mass update of host cache. If a hostcache has already been freed
 * when this function is called, it will not tigger a property update
 * for that hostcache and all of it's group (ANY, ULTRA, BAD).
 */
static void stop_mass_update(hostcache_t *hc)
{
    g_assert(hc->mass_update > 0);
    hc->mass_update--;

    if (hc->mass_update == 0) {
        switch (hc->type) {
        case HCACHE_FRESH_ANY:
        case HCACHE_VALID_ANY: {
            gnet_prop_set_guint32_val(hc->hosts_in_catcher,
                caches[HCACHE_FRESH_ANY]->host_count +
                caches[HCACHE_VALID_ANY]->host_count);
            break;
        }
        case HCACHE_FRESH_ULTRA:
        case HCACHE_VALID_ULTRA:
            gnet_prop_set_guint32_val(hc->hosts_in_catcher,
                caches[HCACHE_FRESH_ULTRA]->host_count +
                caches[HCACHE_VALID_ULTRA]->host_count);
            break;
        case HCACHE_TIMEOUT:
        case HCACHE_UNSTABLE:
        case HCACHE_BUSY:
            gnet_prop_set_guint32_val(hc->hosts_in_catcher,
                caches[HCACHE_TIMEOUT]->host_count +
                caches[HCACHE_UNSTABLE]->host_count +
                caches[HCACHE_BUSY]->host_count);
            break;
        default:
            g_error("stop_mass_update: unknown cache type: %d", hc->type);
        }
    }
}

/**
 * Hashtable: IP/Port -> Metadata
 */
static GHashTable * ht_known_hosts = NULL;	

static void hcache_update_low_on_pongs(void)
{
    host_low_on_pongs = (guint) ( 
            caches[HCACHE_FRESH_ANY]->host_count +
            caches[HCACHE_VALID_ANY]->host_count 
        ) < (max_hosts_cached >> 3);
}

/***
 *** Metadata allocation.
 ***/

static hostcache_entry_t *hce_alloc(void)
{
	return walloc0(sizeof(struct hostcache_entry));
}

static void hce_free(struct hostcache_entry *hce)
{
	g_assert(hce && hce != NO_METADATA);
	wfree(hce, sizeof(*hce));
}

/**
 * Output contents information about a hostcache.
 */
static void hcache_dump_info(struct hostcache *hc, gchar *what)
{
    g_message("[%s|%s] %u (%u) hosts (%u hits, %u misses)",
        hc->name, what, hc->host_count,
        g_list_length(hc->hostlist), 
        hc->hits, hc->misses);
}

/***
 *** Hostcache access.
 ***/

/**
 * Check whether we already have the host.
 */
gboolean hcache_ht_has(guint32 ip, guint16 port)
{
	gnet_host_t host;

	host.ip = ip;
	host.port = port;

	return g_hash_table_lookup(ht_known_hosts, &host) != NULL;
}

/**
 * Add host to the hash table host cache. 
 * Also creates a metadata struct unless the host was added to HL_CAUGHT 
 * in which case we can not know anything about the host. Yet we can not 
 * assert that HL_CAUGHT never contains a host with metadata because when 
 * HL_CAUGHT becomes empty, move all hosts from HL_VALID to HL_CAUGHT. We 
 * can however assert that any host which does not have metadata is in 
 * HL_CAUGHT.
 *
 * @return Pointer to metadata struct for the added host or NO_METADATA
 *         if no metadata was added.
 */
static hostcache_entry_t *hcache_ht_add(hcache_type_t type, gnet_host_t *host)
{
    hostcache_entry_t *hce;

    hce = hce_alloc();
    hce->type = type;
    hce->time_added = time((time_t *) NULL);

	g_hash_table_insert(ht_known_hosts, host, hce);

    return hce;
}

/**
 * Remove host from the hash table host cache.
 */
static void hcache_ht_remove(gnet_host_t *host)
{
	union {
		hostcache_entry_t *hce;
		gpointer ptr;
	} entry;
	gpointer key;
	gboolean found;

	found = g_hash_table_lookup_extended(ht_known_hosts,
		(gconstpointer) host, &key, &entry.ptr);

	if (!found) {
		g_warning("hcache_ht_remove: attempt to remove unknown host: %s",
				  ip_port_to_gchar(host->ip, host->port));
		return;
	}

	g_hash_table_remove(ht_known_hosts, host);

	if (entry.hce != NO_METADATA)
		hce_free(entry.hce);
}

/**
 * Get metadata for host.
 *
 * @return NULL if host was not found, NO_METADATA if no metadata was stored
 *         or a pointer to a hostcache_entry struct which hold the metadata.
 */
static hostcache_entry_t *hcache_get_metadata(gnet_host_t *host)
{
    return g_hash_table_lookup(ht_known_hosts, (gconstpointer) host);
}

/**
 * Returns TRUE if the host is in one of the "bad hosts" caches.
 */
gboolean hcache_node_is_bad(guint32 ip)
{
    hostcache_entry_t *hce;
    gnet_host_t h;

    h.ip = ip;
    h.port = 0;
    hce = hcache_get_metadata(&h);

    if ((hce == NULL) || (hce == NO_METADATA))
        return FALSE;

    caches[hce->type]->hits ++;

    switch (hce->type) {
    case HCACHE_FRESH_ANY:
    case HCACHE_VALID_ANY:
    case HCACHE_FRESH_ULTRA:
    case HCACHE_VALID_ULTRA:
        return FALSE;
    default:
        return TRUE;
    }
}

/**
 * Move entries from one hostcache to another. This only works if the
 * target hostcache is empty.
 */
static void hcache_move_entries(hostcache_t *to, hostcache_t *from)
{
    GList *l;

    g_assert(to->hostlist == NULL);
    g_assert(to->host_count == 0);

    to->hostlist = from->hostlist;
    to->host_count = from->host_count;
    from->hostlist = NULL;
    from->host_count = 0;

    /* 
     * Make sure that after switching hce->list points to the new
     * list HL_CAUGHT 
     */        
    for (l = to->hostlist; NULL != l; l = g_list_next(l)) {
        hostcache_entry_t *hce;
    
        hce = hcache_get_metadata((gnet_host_t *)l->data);
        if (hce == NULL || hce == NO_METADATA)
            continue;
        hce->type = to->type;
    }
}

/**
 * Make sure that if we have some host available in HCACHE_FRESH_ANY
 * and HCACHE_FRESH_ULTRA.
 *
 * If one of the both is empty, all hosts from HCACHE_VALID_XXX 
 * are moved to HCACHE_VALID_XXX. When caught on other hcaches then
 * FRESH_ANY and FRESH_ULTRA nothing happens.
 *
 * @return TRUE if host are available in hc after the call.
 */
static gboolean hcache_require_caught(hostcache_t *hc) 
{
    g_assert(NULL != hc);

    switch(hc->type) {
    case HCACHE_FRESH_ANY:
    case HCACHE_VALID_ANY:
        if (caches[HCACHE_FRESH_ANY]->host_count == 0) {
            hcache_move_entries(
                caches[HCACHE_FRESH_ANY], caches[HCACHE_VALID_ANY]);
        }
        return caches[HCACHE_FRESH_ANY]->host_count != 0;
    case HCACHE_FRESH_ULTRA:
    case HCACHE_VALID_ULTRA:
        if (caches[HCACHE_FRESH_ULTRA]->host_count == 0) {
            hcache_move_entries(
                caches[hc->type], caches[HCACHE_VALID_ULTRA]);
        }
        return caches[HCACHE_FRESH_ULTRA]->host_count != 0;
    default:
        return hc->host_count != 0;
    }
}

/**
 * Remove a host from a hostcache using a pointer to an item in the hostcaches
 * hostlist.
 */
static void hcache_unlink_host(hostcache_t *hc, GList *l)
{
	gnet_host_t *h;
   
	h = (gnet_host_t *) l->data;
	hc->hostlist = g_list_remove_link(hc->hostlist, l);
	g_list_free_1(l);

	g_assert(hc->host_count > 0);
	hc->host_count--;

    if (hc->mass_update == 0) {
        guint32 cur;
        gnet_prop_get_guint32_val(hc->hosts_in_catcher, &cur);
        gnet_prop_set_guint32_val(hc->hosts_in_catcher, cur - 1);
    }

	hcache_ht_remove(h);

	wfree(h, sizeof(*h));

    hcache_require_caught(hc);
}

/**
 * Convert host cache type to string.
 */
const gchar *hcache_type_to_gchar(hcache_type_t type)
{
	g_assert((guint) type < HCACHE_MAX);

	return _(names[type]);
}

/**
 * Convert host type to string.
 */
const gchar *host_type_to_gchar(hcache_type_t type)
{
	g_assert((guint) type < HOST_MAX);

	return _(host_type_names[type]);
}


/**
 * @return the number of slots which can be added to the given type.
 *
 * @note Several types share common pools. Adding a host of one type
 *       may affect the number of slots left on other types.
 */
static gint32 hcache_slots_left(hcache_type_t type)
{
    g_assert((guint) type < HCACHE_MAX);

    switch (type) {
    case HCACHE_FRESH_ANY:
    case HCACHE_VALID_ANY:
        return max_hosts_cached - 
            caches[HCACHE_FRESH_ANY]->host_count -
            caches[HCACHE_VALID_ANY]->host_count;
    case HCACHE_FRESH_ULTRA:
    case HCACHE_VALID_ULTRA:
        return max_ultra_hosts_cached - 
            caches[HCACHE_FRESH_ULTRA]->host_count -
            caches[HCACHE_VALID_ULTRA]->host_count;
    default:
        return max_bad_hosts_cached - caches[type]->host_count;
    }
}

/**
 * Register a host.
 *
 * If a host is already on the known hosts hashtable, it will not be
 * registered. Otherwise it will be added to the hashtable of known hosts
 * and added to one of the host lists as indicated by the "list" parameter.
 * Sanity checks are only applied when the host is added to HL_CAUGHT, since
 * when a host is added to any of the other lists it must have been in
 * HL_CAUGHT or in the pong-cache before.
 *
 * @return TRUE when IP/port passed sanity checks, regardless of whether it
 *         was added to the cache. (See above)
 */
gboolean hcache_add(
    hcache_type_t type, guint32 ip, guint16 port, gchar *what)
{
	gnet_host_t *host;
	hostcache_t *hc;

	g_assert((guint) type < HCACHE_MAX);

	if (ip == listen_ip() && port == listen_port) {
        stats[HCACHE_LOCAL_INSTANCE] ++;
		return FALSE;
    }

	if (node_host_is_connected(ip, port)) {
        stats[HCACHE_ALREADY_CONNECTED] ++;
		return FALSE;			/* Connected to that host? */
    }

	hc = caches[type];
    g_assert(hc->type == type);

    if (!ip_is_valid(ip) && (!hc->ip_only || !port_is_valid(port))) {
        stats[HCACHE_INVALID_HOST] ++;
		return FALSE;			/* Is host valid? */
    }

    /* Do nothing if host is already known */
	if (hcache_ht_has(ip, port)) {
        hostcache_entry_t *hce;
        gnet_host_t h;

        h.ip = ip;
        h.port = port;

        hce = hcache_get_metadata(&h);
        g_assert(hce != NULL);

        hc->hits++;

		return TRUE;
    }

	/* Okay, we got a new host */
	host = (gnet_host_t *) walloc(sizeof(*host));

	host->ip   = ip;
	host->port = port;

	hcache_ht_add(type, host);

    switch (type) {
    case HCACHE_FRESH_ANY:
    case HCACHE_FRESH_ULTRA:
        // FIXME: using g_list_append here is potentially slow
        hc->hostlist = g_list_append(hc->hostlist, host);
        break;

    case HCACHE_VALID_ANY:
    case HCACHE_VALID_ULTRA:
        /*
         * We prepend to the list instead of appending because the day
         * we switch it as HCACHE_FRESH_XXX, we'll start reading from there,
         * in effect using the most recent hosts we know about.
         */

        hc->hostlist = g_list_prepend(hc->hostlist, host);
        break;

    case HCACHE_UNSTABLE:
        if (!node_monitor_unstable_ip) {
            break;
        }
        /* no break! */
    default:
        /*
         * We use g_list_prepend here because it is faster then g_list_append.
         * In hcache_expire depends on the fact that new entries are
         * added to the beginning of the list 
         */
        hc->hostlist = g_list_prepend(hc->hostlist, host);
        break;
    }

    hc->misses ++;
	hc->host_count++;

    if (hc->mass_update == 0) {
        guint32 cur;
        gnet_prop_get_guint32_val(hc->hosts_in_catcher, &cur);
        gnet_prop_set_guint32_val(hc->hosts_in_catcher, cur + 1);
    }

    hcache_prune(hc->type);
    hcache_update_low_on_pongs();

    if (dbg > 8)
        printf("Added %s %s (%s)\n", what, ip_port_to_gchar(ip, port),
            ((type == HCACHE_FRESH_ANY) || (type == HCACHE_VALID_ANY)) ? 
                (host_low_on_pongs ? "LOW" : "OK") : "");

	return TRUE;
}

/**
 * Add a caught (fresh) host to the right list depending on the host type.
 */
gboolean hcache_add_caught(
    host_type_t type, guint32 ip, guint16 port, gchar *what)
{
    switch (type) {
    case HOST_ANY:
    	return hcache_add(HCACHE_FRESH_ANY, ip, port, what);
    case HOST_ULTRA:
    	return hcache_add(HCACHE_FRESH_ULTRA, ip, port, what);
    case HOST_MAX:
		g_assert_not_reached();
    }

    g_error("hcache_add_caught: unknown host type: %d", type);
    return FALSE;
}

/**
 * Add a valid host to the right list depending on the host type.
 */
gboolean hcache_add_valid(
    host_type_t type, guint32 ip, guint16 port, gchar *what)
{
    switch (type) {
    case HOST_ANY:
    	return hcache_add(HCACHE_VALID_ANY, ip, port, what);
    case HOST_ULTRA:
    	return hcache_add(HCACHE_VALID_ULTRA, ip, port, what);
    case HOST_MAX:
		g_assert_not_reached();
    }

    g_error("hcache_add_valid: unknown host type: %d", type);
    return FALSE;
}

/**
 * Remove host from cache.
 *
 * After removing hcache_require_caught is called.
 */
static void hcache_remove(gnet_host_t *h)
{
    hostcache_entry_t *hce;
    hostcache_t *hc;
    gpointer found;
    
    hce = hcache_get_metadata(h);

    if (hce == NULL)
        return; /* Host is not in hashtable */

    hc = caches[hce->type];

    found = g_list_find_custom(hc->hostlist, h, host_cmp);
    g_assert(
        (hc->host_count > 0) &&
        (hc->hostlist != NULL) && 
        (NULL != found)
    );

	hc->hostlist = g_list_remove(hc->hostlist, h);

	g_assert(hc->host_count > 0);
	hc->host_count--;

    if (hc->mass_update == 0) {
        guint32 cur;
        gnet_prop_get_guint32_val(hc->hosts_in_catcher, &cur);
        gnet_prop_set_guint32_val(hc->hosts_in_catcher, cur - 1);
    }

	hcache_ht_remove(h);

    hcache_require_caught(hc);

	wfree(h, sizeof(*h));
}

/**
 * Do we have less that our mimumum amount of hosts in the cache?
 */
gboolean hcache_is_low(host_type_t type)
{
    switch (type) {
    case HOST_ANY:
        return (caches[HCACHE_FRESH_ANY]->host_count +
            caches[HCACHE_VALID_ANY]->host_count) < MIN_RESERVE_SIZE;
    case HOST_ULTRA:
        return (caches[HCACHE_FRESH_ULTRA]->host_count +
            caches[HCACHE_VALID_ULTRA]->host_count) < MIN_RESERVE_SIZE;
    case HOST_MAX:
		g_assert_not_reached();
    }
    g_error("hcache_is_low: unknown host type: %d", type);
    return FALSE; /* Only here to make -Wall happy */
}

/**
 * Remove all entries from hostcache.
 */
static void hcache_remove_all(hostcache_t *hc)
{
    // FIXME: may be possible to do this faster

    if (hc->host_count == 0)
        return;

    start_mass_update(hc);

    while (NULL != hc->hostlist) {
        hcache_remove((gnet_host_t *) hc->hostlist->data);
    }

    g_assert(hc->hostlist == NULL);
    g_assert(hc->host_count == 0);

    stop_mass_update(hc);
}

/**
 * Clear the whole host cache for a host type and the pong cache of 
 * the same type. Use this to clear the "ultra" and "any" host caches.
 */
void hcache_clear_host_type(host_type_t type)
{
	gboolean valid = FALSE;

    switch (type) {
    case HOST_ANY:
        hcache_remove_all(caches[HCACHE_FRESH_ANY]);
        hcache_remove_all(caches[HCACHE_VALID_ANY]);
		valid = TRUE;
        break;
    case HOST_ULTRA:
        hcache_remove_all(caches[HCACHE_FRESH_ULTRA]);
        hcache_remove_all(caches[HCACHE_VALID_ULTRA]);
		valid = TRUE;
        break;
    case HOST_MAX:
		g_assert_not_reached();
    }

	if (!valid)
        g_error("hcache_clear_host_type: unknown host type: %d", type);

	pcache_clear_recent(type);
}

/**
 * Clear the whole host cache but does not clear the pong caches. Use
 * this to clear the "bad" host caches.
 */
void hcache_clear(hcache_type_t type)
{
    g_assert((guint) type < HCACHE_MAX);

    hcache_remove_all(caches[type]);
}

/**
 * Returns the amount of hosts in the cache.
 */
gint hcache_size(host_type_t type)
{
    switch (type) {
    case HOST_ANY:
        return (caches[HCACHE_FRESH_ANY]->host_count +
            caches[HCACHE_VALID_ANY]->host_count);
    case HOST_ULTRA:
        return (caches[HCACHE_FRESH_ULTRA]->host_count +
            caches[HCACHE_VALID_ULTRA]->host_count);
    case HOST_MAX:
		g_assert_not_reached();
    }
    g_error("hcache_is_low: unknown host type: %d", type);
    return -1; /* Only here to make -Wall happy */
}

/**
 * Expire hosts from a single hostlist in a hostcache. Also removes
 * it from the host hashtable.
 *
 * @return total number of expired entries
 */
static guint32 hcache_expire_cache(hostcache_t *hc)
{
    time_t now = time((time_t *) NULL);
    gint32 secs_to_keep = 60 * 30; /* 30 minutes */
    guint32 expire_count = 0;
    GList *l;

    /* Prune all the expired ones from the list until the list is empty
     * or we find one which is not expired, in which case we know that
     * all the following are also not expired, because the list is
     * sorted by time_added */
    l = g_list_last(hc->hostlist);
    while (NULL != l) {
        GList *cur = l;
        hostcache_entry_t *hce;
        gnet_host_t *h = l->data;

        l = g_list_previous(l);
    
        hce = hcache_get_metadata(h);

        g_assert((hce != NULL) && (hce != NO_METADATA)); 

        if (delta_time(now, hce->time_added) > secs_to_keep) {
            hcache_unlink_host(hc, cur);
            expire_count ++;
        } else {
            /* Found one which has not expired. Stopping */
            break;
        }
    }

    return expire_count;
}


/**
 * Expire hosts from the HL_BUSY, HL_TIMEOUT and HL_UNSTABLE lists
 * and remove them from the hosts hashtable too.
 *
 * @return total number of expired entries
 */
guint32 hcache_expire_all(void)
{
    guint32 expire_count = 0;

    expire_count += hcache_expire_cache(caches[HCACHE_TIMEOUT]);
    expire_count += hcache_expire_cache(caches[HCACHE_BUSY]);
    expire_count += hcache_expire_cache(caches[HCACHE_UNSTABLE]);

    return expire_count;
}

/**
 * Remove hosts that exceed our maximum.
 *
 * This can be called on HCACHE_FRESH_ANY and on HCACHE_FRESH_ULTRA.
 * Calling this on any other cache will tigger an assertion.
 *
 * If too many hosts are in the cache, then it will prune the HCACHE_FRESH_XXX
 * list. Only after HCACHE_FRESH_XXX is empty HCACHE_VALID_XXX will be moved
 * to HCACHE_FRESH_XXX and then it is purged.
 */
void hcache_prune(hcache_type_t type) 
{
	hostcache_t *hc;
    gint extra;

    g_assert((guint) type < HCACHE_MAX);

    switch (type) {
    case HCACHE_VALID_ANY:
        hc = caches[HCACHE_FRESH_ANY];
        break;
    case HCACHE_VALID_ULTRA:
        hc = caches[HCACHE_FRESH_ULTRA];
        break;
    default:
        hc = caches[type];
    }

    extra = -hcache_slots_left(hc->type);

    if (extra <= 0)
        return;

    start_mass_update(hc);
    
    hcache_require_caught(hc);
	while (extra > 0) {
		if (hc->hostlist == NULL) {
			g_warning("BUG: asked to remove hosts, "
                "but hostcache list is empty: %s", hc->name);
			break;
		}
		hcache_remove(hc->hostlist->data);
        extra --;
	}

    stop_mass_update(hc);
}

/**
 * Fill `hosts', an array of `hcount' hosts already allocated with at most
 * `hcount' hosts from out caught list, without removing those hosts from
 * the list.
 *
 * @return amount of hosts filled
 */
gint hcache_fill_caught_array(
	host_type_t type, gnet_host_t *hosts, gint hcount)
{
	GList *l;
	gint i;
	hostcache_t *hc = NULL;
	GHashTable *seen_host = g_hash_table_new(host_hash, host_eq);

    switch (type) {
    case HOST_ANY:
        hc = caches[HCACHE_FRESH_ANY];
        break;
    case HOST_ULTRA:
        hc = caches[HCACHE_FRESH_ULTRA];
        break;
    case HOST_MAX:
		g_assert_not_reached();
    }

	if (!hc)
        g_error("hcache_get_caught: unknown host type: %d", type);

	/*
	 * First try to fill from our recent pongs, as they are more fresh
	 * and therefore more likely to be connectible.
	 */

	for (i = 0; i < hcount; i++) {
		gnet_host_t host;

		if (!pcache_get_recent(type, &host.ip, &host.port))
			break;

		if (g_hash_table_lookup(seen_host, &host))
			break;

		hosts[i] = host;		/* struct copy */

		g_hash_table_insert(seen_host, &hosts[i], (gpointer) 0x1);
	}

	if (i == hcount)
		goto done;

	/*
	 * Not enough fresh pongs, get some from our reserve.
	 */

	for (
        l = g_list_last(hc->hostlist); 
        (i < hcount) && (l != NULL); 
        i++, l = g_list_previous(l)
    ) {
		gnet_host_t *h = (gnet_host_t *) l->data;

		if (g_hash_table_lookup(seen_host, h))
			continue;

		hosts[i] = *h;			/* struct copy */

		g_hash_table_insert(seen_host, &hosts[i], (gpointer) 0x1);
	}

done:
	g_hash_table_destroy(seen_host);	/* Keys point directly into vector */

	return i;				/* Amount of hosts we filled */
}

/**
 * Finds a host in either the pong_cache or the host_cache that is in 
 * one of the local networks. 
 *
 * @return TRUE if host is found
 */
gboolean hcache_find_nearby(host_type_t type, guint32 *ip, guint16 *port)
{
	gnet_host_t *h;
	static int alternate = 0;
	guint32 first_ip;
	guint16 first_port;
	gboolean got_recent;
	GList *l;
	hostcache_t *hc = NULL;
	gboolean reading;
    gboolean result = FALSE;

    switch (type) {
    case HOST_ANY:
        hc = caches[HCACHE_FRESH_ANY];
		break;
    case HOST_ULTRA:
        hc = caches[HCACHE_FRESH_ULTRA];
		break;
    case HOST_MAX:
		g_assert_not_reached();
    }

	if (!hc)	
        g_error("hcache_get_caught: unknown host type: %d", type);

    gnet_prop_get_boolean_val(hc->reading, &reading);

	if (alternate++ & 1) {
		/* Iterate through all recent pongs */
		for (
			*ip = 0,
				got_recent = pcache_get_recent(type, &first_ip, &first_port);
			got_recent && (*ip != first_ip || *port != first_port); 
			got_recent = pcache_get_recent(type, ip, port)
		) {
			if (host_is_nearby(*ip))
				return TRUE;
		}
	}

	/* iterate through whole list */
	for (
		l = reading ? hc->hostlist :
			g_list_last(hc->hostlist);
		NULL != l; 
        l = g_list_previous(l)
	) {

		h = (gnet_host_t *) l->data;
		if (host_is_nearby(h->ip)) {
            *ip = h->ip;
            *port = h->port;
            
            hcache_unlink_host(hc, l);
            result = TRUE;
			break;
		}

	}

	return result;

}

/**
 * Get host IP/port information from our caught host list, or from the
 * recent pong cache, in alternance.
 */
void hcache_get_caught(host_type_t type, guint32 *ip, guint16 *port)
{
	static guint alternate = 0;
	GList *l;
	hostcache_t *hc = NULL;
	gboolean reading;
	extern guint32 number_local_networks;
	gnet_host_t *h;

    switch(type) {
    case HOST_ANY:
        hc = caches[HCACHE_FRESH_ANY];
        break;
    case HOST_ULTRA:
        hc = caches[HCACHE_FRESH_ULTRA];
        break;
    case HOST_MAX:
		g_assert_not_reached();
    }

	if (!hc)
        g_error("hcache_get_caught: unknown host type: %d", type);

    gnet_prop_get_boolean_val(hc->reading, &reading);

    g_assert(hcache_require_caught(hc));

    hcache_update_low_on_pongs();

	/* 
	 * First, try to find a local host 
	 */

	if (
		use_netmasks && number_local_networks &&
		hcache_find_nearby(type, ip, port)
	)
		return;

	/*
	 * Try the recent pong cache when `alternate' is odd.
	 */

	if (alternate++ & 0x1 && pcache_get_recent(type, ip, port))
		return;

	/*
	 * If we're done reading from the host file, get latest host, at the
	 * tail of the list.  Otherwise, get the first host in that list.
	 */

	l = reading ?
		hc->hostlist : 
        g_list_last(hc->hostlist);

	h = (gnet_host_t *) l->data;
	*ip = h->ip;
	*port = h->port;
    hcache_unlink_host(hc, l);
}

/***
 *** Hostcache management.
 ***/

/**
 * Allocate hostcache of type `type'.
 *
 * The `incache' property is what needs to be updated so that the GUI can
 * display the proper amount of hosts we currently hold.
 *
 * The `maxhosts' variable is the pointer to the variable giving the maximum
 * amount of hosts we can store.
 *
 * The `reading' variable is the property to update to signal whether we're
 * reading the persisted file.
 */
static hostcache_t *hcache_alloc(hcache_type_t type, 
    gnet_property_t reading, gnet_property_t catcher, gchar *name)
{
	struct hostcache *hc;

	g_assert((guint) type < HCACHE_MAX);

	hc = g_malloc0(sizeof(*hc));

	hc->name = name;
	hc->type = type;
	hc->reading = reading;
    hc->hosts_in_catcher = catcher;
    hc->ip_only = FALSE;

	return hc;
}

/**
 * Dispose of the hostcache.
 */
static void hcache_free(hostcache_t *hc)
{
    g_assert(hc != NULL);
    g_assert(hc->host_count == 0);
    g_assert(hc->hostlist == NULL);

	G_FREE_NULL(hc);
}

/***
 *** Hosts text files
 ***/

/*
 * Host reading context.
 */

#define READ_MAGIC		0x3d00003d
#define HOST_READ_CNT	20			/* Amount of hosts to read each tick */

struct read_ctx {
	gint magic;						/* Magic number */
	FILE *fd;						/* File descriptor to read from */
	hostcache_t *hc;			/* Hostcache to fill */
};

/**
 * Dispose of the read context.
 */
static void read_ctx_free(gpointer u)
{
	struct read_ctx *rctx = (struct read_ctx *) u;

	g_assert(rctx->magic == READ_MAGIC);

	if (rctx->fd != NULL)
		fclose(rctx->fd);

	wfree(rctx, sizeof(*rctx));
}

/**
 * Read is finished.
 */
static void read_done(hostcache_t *hc)
{
    /*
     * Order is important so the GUI can update properly. First we say
     * that loading has finished, then we tell the GUI the number of
     * hosts in the catcher.
     *      -- Richard, 6/8/2002
     */
    
    gnet_prop_set_boolean_val(hc->reading, FALSE);
}

/**
 * One reading step.
 */
static bgret_t read_step(gpointer h, gpointer u, gint ticks)
{
	struct read_ctx *rctx = (struct read_ctx *) u;
	hostcache_t *hc;
	gint max_read;
	gint count;
	gint i;
	static gchar h_tmp[1024];


	g_assert(rctx->magic == READ_MAGIC);
	g_assert(rctx->fd);

	hc = rctx->hc;

	max_read = hcache_slots_left(hc->type);
	count = ticks * HOST_READ_CNT;
	count = MIN(max_read, count);

	if (dbg > 9)
		printf("read_step(%s): ticks=%d, count=%d\n", hc->name, ticks, count);

	for (i = 0; i < count; i++) {
		if (fgets(h_tmp, sizeof(h_tmp) - 1, rctx->fd)) { /* NUL appended */
			guint32 ip;
			guint16 port;

			if (gchar_to_ip_port(h_tmp, &ip, &port)) {
                hcache_add(hc->type, ip, port, "on-disk cache");
			}
		} else
			goto done;
	}

	if (count < max_read)
		return BGR_MORE;		/* Host cache not full, need to read more */

	/* Fall through */

done:
	fclose(rctx->fd);
	rctx->fd = NULL;

	read_done(hc);

	return BGR_DONE;
}

/**
 * Invoked when the task is completed.
 */
static void bg_reader_done(
	gpointer h, gpointer ctx, bgstatus_t status, gpointer arg)
{
	struct read_ctx *rctx = (struct read_ctx *) ctx;
	hostcache_t *hc;

	g_assert(rctx->magic == READ_MAGIC);

	hc = rctx->hc;
	bg_reader[hc->type] = NULL;
}

/**
 * Loads caught hosts from text file.
 */
static void hcache_retrieve(hostcache_t *hc, gchar *filename)
{
	struct read_ctx *rctx;
	FILE *fd;
	bgstep_cb_t step = read_step;

    {
		file_path_t fp;
		
		file_path_set(&fp, settings_config_dir(), filename);
		fd = file_config_open_read("hosts", &fp, 1);
	}

	if (!fd)
		return;

	rctx = walloc(sizeof(*rctx));
	rctx->magic = READ_MAGIC;
	rctx->fd = fd;
	rctx->hc = hc;

    gnet_prop_set_boolean_val(hc->reading, TRUE);

	bg_reader[hc->type] = bg_task_create(
		hc->type == HCACHE_FRESH_ANY ? "Hostcache reading" : "Ultracache reading",
		&step, 1, rctx, read_ctx_free, bg_reader_done, NULL);
}

/**
 * Persist hostcache to disk.
 */
static void hcache_store(hcache_type_t type, gchar *filename, gboolean append)
{
	hostcache_t *hc;
	FILE *f;
	GList *l;
	file_path_t fp;
    guint count = 0;

	g_assert((guint) type < HCACHE_MAX);
	g_assert(caches[type] != NULL);

	hc = caches[type];

	fp.dir = settings_config_dir();
	fp.name = filename;

	f = append ?
        file_config_open_append(filename, &fp) :
        file_config_open_write(filename, &fp);

	if (!f)
		return;

	for (l = hc->hostlist; l; l = g_list_next(l)) {
		fprintf(f, "%s\n",
				ip_port_to_gchar(((gnet_host_t *) l->data)->ip,
								 ((gnet_host_t *) l->data)->port));
        count ++;
    }

	file_config_close(f, &fp);
}

/**
 * Get statistical information about the caches.
 *
 * @param stats must point to an hcache_stats_t[HCACHE_MAX] array.
 */
void hcache_get_stats(hcache_stats_t *stats)
{
    guint n;

    for (n = 0; n < HCACHE_MAX; n ++) {
        stats[n].host_count = caches[n]->host_count;
        stats[n].hits       = caches[n]->hits;
        stats[n].misses     = caches[n]->misses;
        stats[n].reading    = FALSE;
    }
}

/**
 * Host cache timer.
 */
void hcache_timer(void)
{
    guint i;

    hcache_expire_all();

    if (dbg >= 15) {
        hcache_dump_info(caches[HCACHE_FRESH_ANY],   "timer");    
        hcache_dump_info(caches[HCACHE_VALID_ANY],   "timer");    

        hcache_dump_info(caches[HCACHE_FRESH_ULTRA], "timer");    
        hcache_dump_info(caches[HCACHE_VALID_ULTRA], "timer");    

        hcache_dump_info(caches[HCACHE_TIMEOUT],  "timer");    
        hcache_dump_info(caches[HCACHE_BUSY],     "timer");    
        hcache_dump_info(caches[HCACHE_UNSTABLE], "timer");    

        g_message("Hcache global: local %u   alrdy connected %u   invalid %u",
            stats[HCACHE_LOCAL_INSTANCE], stats[HCACHE_ALREADY_CONNECTED],
            stats[HCACHE_INVALID_HOST]);
    }
}

/**
 * Initialize host caches.
 */
void hcache_init(void)
{
    memset(bg_reader, 0, sizeof(bg_reader));
    memset(stats, 0, sizeof(stats));

	ht_known_hosts = g_hash_table_new(host_hash, host_eq);

    caches[HCACHE_FRESH_ANY] = hcache_alloc(
        HCACHE_FRESH_ANY, PROP_READING_HOSTFILE,
        PROP_HOSTS_IN_CATCHER,
        "hosts.fresh.any");

    caches[HCACHE_FRESH_ULTRA] = hcache_alloc(
        HCACHE_FRESH_ULTRA, PROP_READING_ULTRAFILE,
        PROP_HOSTS_IN_ULTRA_CATCHER,
        "hosts.fresh.ultra");

    caches[HCACHE_VALID_ANY] = hcache_alloc(
        HCACHE_VALID_ANY, PROP_READING_HOSTFILE, 
        PROP_HOSTS_IN_CATCHER,
        "hosts.valid.any");

    caches[HCACHE_VALID_ULTRA] = hcache_alloc(
        HCACHE_VALID_ULTRA, PROP_READING_ULTRAFILE, 
        PROP_HOSTS_IN_ULTRA_CATCHER,
        "hosts.valid.ultra");

    caches[HCACHE_TIMEOUT] = hcache_alloc(
        HCACHE_TIMEOUT, PROP_READING_HOSTFILE, 
        PROP_HOSTS_IN_BAD_CATCHER,
        "hosts.timeout");
    caches[HCACHE_TIMEOUT]->ip_only = TRUE;

    caches[HCACHE_BUSY] = hcache_alloc(
        HCACHE_BUSY, PROP_READING_HOSTFILE,
        PROP_HOSTS_IN_BAD_CATCHER,
        "hosts.busy");
    caches[HCACHE_BUSY]->ip_only = TRUE;

    caches[HCACHE_UNSTABLE] = hcache_alloc(
        HCACHE_UNSTABLE, PROP_READING_HOSTFILE,
        PROP_HOSTS_IN_BAD_CATCHER,
        "hosts.unstable");
    caches[HCACHE_UNSTABLE]->ip_only = TRUE;
}

/**
 * Load hostcache data from disk.
 */
void hcache_retrieve_all(void) {
	hcache_retrieve(caches[HCACHE_FRESH_ANY], "hosts");
	hcache_retrieve(caches[HCACHE_FRESH_ULTRA], "ultras");
}

/**
 * Shutdown host caches.
 */
void hcache_shutdown(void)
{
	gboolean reading;

	/*
	 * Write "valid" hosts first.  Next time we are launched, we'll first
	 * start reading from the head first.  And once the whole cache has
	 * been read in memory, we'll begin using the tail of the list, i.e.
	 * possibly older hosts, which will help ensure we don't always connect
	 * to the same set of hosts.
	 */

	/* Save the caught hosts */

	gnet_prop_get_boolean_val(PROP_READING_HOSTFILE, &reading);

	if (reading)
		g_warning("exit() while still reading the hosts file, "
			"caught hosts not saved!");
	else {
		hcache_store(HCACHE_VALID_ANY, "hosts", FALSE);
		hcache_store(HCACHE_FRESH_ANY, "hosts", TRUE);
    }

	/* Save the caught ultra hosts */

	gnet_prop_get_boolean_val(PROP_READING_ULTRAFILE, &reading);

	if (reading)
		g_warning("exit() while still reading the ultrahosts file, "
			"caught hosts not saved !");
	else {
		hcache_store(HCACHE_VALID_ULTRA, "ultras", FALSE);
		hcache_store(HCACHE_FRESH_ULTRA, "ultras", TRUE);
    }
}

/**
 * Destroy all host caches.
 */
void hcache_close(void)
{
	static const hcache_type_t types[] = { 
        HCACHE_FRESH_ANY, 
        HCACHE_FRESH_ULTRA,
        HCACHE_VALID_ANY,
        HCACHE_VALID_ULTRA,
        HCACHE_TIMEOUT,
        HCACHE_BUSY,
        HCACHE_UNSTABLE
    };
	guint i;

    /*
     * First we stop all background processes and remove all hosts, 
     * only then we free the hcaches. This is important because 
     * hcache_require_caught will crash if we free certain hostcaches.
     */
	for (i = 0; i < G_N_ELEMENTS(types); i++) {
		hcache_type_t type = types[i];

		if (bg_reader[type] != NULL)
			bg_task_cancel(bg_reader[type]);

        hcache_remove_all(caches[type]);
	}

	for (i = 0; i < G_N_ELEMENTS(types); i++) {
		hcache_type_t type = types[i];

		hcache_free(caches[type]);
        caches[type] = NULL;
	}

    g_assert(g_hash_table_size(ht_known_hosts) == 0);

	g_hash_table_destroy(ht_known_hosts);
    ht_known_hosts = NULL;
}

/* vi: set ts=4: */

