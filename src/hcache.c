/*
 * $Id$
 *
 * Copyright (c) 2002, Raphael Manfredi
 *
 * Host cache management.
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

#include "gnutella.h"

#include <stdlib.h>

#include "hosts.h"
#include "hcache.h"
#include "pcache.h"

#include "settings.h"

#define MIN_RESERVE_SIZE	1024	/* we'd like that many pongs in reserve */

/*
 * A hostcache table.
 */
struct hostcache {
	gchar *name;						/* Cache name, for debugging */
	gchar *filename;					/* Filename where cache is persisted */
	hcache_type_t type;					/* Cache type */
	GList *sl_caught_hosts;				/* Reserve list */
	GList *sl_valid_hosts;				/* Validated hosts */
	GHashTable *ht_known_hosts;			/* All known hosts */
    gint host_count;					/* Amount of hosts in cache */
	gnet_property_t hosts_in_catcher;	/* Property to update */
	gnet_property_t reading;			/* Property to signal reading */
	guint32 *max_hosts;					/* Maximum amount of hosts */
	gint mass_operation;
};

/*
 * An entry within the hostcache.
 *
 * We don't really store the IP/port, as those are stored in the key of
 * hash table recording all known hosts.  Rather, we store "metadata" about
 * the host.
 */
struct hostcache_entry {
	gint refcount;				/* Can be shared among the caches */
	guint32 avg_uptime;			/* Reported average uptime (seconds) */
	gchar *vendor;				/* Latest known vendor name (atom) */
};

#define NO_METADATA			((gpointer) 0x1)	/* No metadata for host */

static struct hostcache *caches[HCACHE_MAX];
static gchar *files[HCACHE_MAX] = { "hosts", "ultras" };
static gchar *names[HCACHE_MAX] = { "regular", "ultra" };

gchar h_tmp[1024];

static void hcache_remove_all(struct hostcache *hc);

/*
 * hcache_type_to_gchar
 *
 * Convert host cache type to string.
 */
gchar *hcache_type_to_gchar(hcache_type_t type)
{
	g_assert(type >= 0 && type < HCACHE_MAX);

	return names[type];
}

/***
 *** Metadata allocation.
 ***/

static struct hostcache_entry *hce_alloc()
{
	return walloc0(sizeof(struct hostcache_entry));
}

static void hce_free(struct hostcache_entry *hce)
{
	g_assert(hce && hce != NO_METADATA);
	g_assert(hce->refcount > 0);

	if (1 == hce->refcount--)
		wfree(hce, sizeof(*hce));
}

/***
 *** Prevent frequent GUI updates whithin a massive update operation.
 ***/

static void start_mass_update(struct hostcache *hc)
{
    hc->mass_operation++;
}

static void end_mass_update(struct hostcache *hc) 
{
    g_assert(hc->mass_operation > 0);

    hc->mass_operation--;

    if (hc->mass_operation == 0)
        gnet_prop_set_guint32_val(hc->hosts_in_catcher, hc->host_count);
}

/***
 *** Host hashing.
 ***/

static guint host_hash(gconstpointer key)
{
	struct gnutella_host *host = (struct gnutella_host *) key;

	return (guint) (host->ip ^ ((host->port << 16) | host->port));
}

static gint host_eq(gconstpointer v1, gconstpointer v2)
{
	struct gnutella_host *h1 = (struct gnutella_host *) v1;
	struct gnutella_host *h2 = (struct gnutella_host *) v2;

	return h1->ip == h2->ip && h1->port == h2->port;
}

/***
 *** Hostcache management.
 ***/

/*
 * hcache_alloc
 *
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
static void hcache_alloc(
	hcache_type_t type,
	gnet_property_t incache, gnet_property_t reading, guint32 *maxhosts)
{
	struct hostcache *hc;

	g_assert(type >= 0 && type < HCACHE_MAX);
	g_assert(caches[type] == NULL);

	hc = g_malloc0(sizeof(*hc));

	hc->name = names[type];
	hc->filename = files[type];
	hc->type = type;
	hc->ht_known_hosts = g_hash_table_new(host_hash, host_eq);
	hc->hosts_in_catcher = incache;
	hc->max_hosts = maxhosts;
	hc->reading = reading;

	caches[type] = hc;
}

/*
 * hcache_free
 *
 * Dispose of the hostcache.
 */
static void hcache_free(hcache_type_t type)
{
	struct hostcache *hc;

	g_assert(type >= 0 && type < HCACHE_MAX);
	g_assert(caches[type] != NULL);

	hc = caches[type];

	hcache_remove_all(hc);
	g_hash_table_destroy(hc->ht_known_hosts);
	g_free(hc);

	caches[type] = NULL;
}

/***
 *** Hostcache access.
 ***/

/*
 * hcache_ht_has
 *
 * Check whether we already have the host.
 */
static gboolean hcache_ht_has(struct hostcache *hc, guint32 ip, guint16 port)
{
	struct gnutella_host host;

	host.ip = ip;
	host.port = port;

	return g_hash_table_lookup(hc->ht_known_hosts, &host) != NULL;
}

/*
 * hcache_ht_add
 *
 * Add host to the hash table host cache.
 */
static void hcache_ht_add(struct hostcache *hc, struct gnutella_host *host)
{
	if (g_hash_table_lookup(hc->ht_known_hosts, (gconstpointer) host)) {
		g_error("attempt to add existing %s to hostcache list (%s nodes)",
				  ip_port_to_gchar(host->ip, host->port), hc->name);
		return;
	}

	g_hash_table_insert(hc->ht_known_hosts, host, NO_METADATA);
	hc->host_count++;

    if (!hc->mass_operation || (hc->host_count & 0x3ff) == 0)
        gnet_prop_set_guint32_val(hc->hosts_in_catcher, hc->host_count);
}

/*
 * hcache_ht_remove
 *
 * Remove host from the hash table host cache.
 */
static void hcache_ht_remove(struct hostcache *hc, struct gnutella_host *host)
{
	struct hostcache_entry *hce;
	gpointer key;
	gboolean found;

	found = g_hash_table_lookup_extended(hc->ht_known_hosts,
		(gconstpointer) host, &key, (gpointer *) &hce);

	if (!found) {
		g_warning("attempt to remove missing %s from hostcache list (%s nodes)",
				  ip_port_to_gchar(host->ip, host->port), hc->name);
		return;
	}

	g_hash_table_remove(hc->ht_known_hosts, host);
	hc->host_count--;

	g_assert(hc->host_count >= 0);

	if (hce != NO_METADATA)
		hce_free(hce);

    if (!hc->mass_operation || (hc->host_count & 0x3ff) == 0)
        gnet_prop_set_guint32_val(hc->hosts_in_catcher, hc->host_count);
}


/*
 * hcache_save_valid
 *
 * Save host to the validated server list
 *
 * We put in this list all the Gnet nodes to which we were able to connect
 * and transmit at list one packet (indicating a successful handshake).
 */
void hcache_save_valid(hcache_type_t type, guint32 ip, guint16 port)
{
	struct gnutella_host *host;
	struct hostcache *hc;

	g_assert(type >= 0 && type < HCACHE_MAX);

	if (!host_is_valid(ip, port))
		return;

	hc = caches[type];

	if (hcache_ht_has(hc, ip, port))
		return;

	host = (struct gnutella_host *) walloc(sizeof(*host));

	host->ip = ip;
	host->port = port;

	hcache_ht_add(hc, host);

	/*
	 * We prepend to the list instead of appending because the day
	 * we switch it as `sl_caught_hosts', we'll start reading from there,
	 * in effect using the most recent hosts we know about.
	 */

	hc->sl_valid_hosts = g_list_prepend(hc->sl_valid_hosts, host);
}

/*
 * hcache_add
 *
 * Add host to cache.
 *
 * Returns true when IP/port passed sanity checks, regardless of whether it
 * was added to the cache.
 */
gboolean hcache_add(hcache_type_t type, guint32 ip, guint16 port, gchar *what)
{
	struct hostcache *hc;
	struct gnutella_host *host;

	g_assert(type >= 0 && type < HCACHE_MAX);

	if (!host_is_valid(ip, port))
		return FALSE;			/* Is host valid? */

	hc = caches[type];

	if (hcache_ht_has(hc, ip, port))
		return TRUE;			/* We have it, so IP:port are valid */

	/* Okay, we got a new host */

	host = (struct gnutella_host *) walloc(sizeof(*host));

	host->port = port;
	host->ip = ip;

	hcache_ht_add(hc, host);
	hc->sl_caught_hosts = g_list_append(hc->sl_caught_hosts, host);

	if (type == HCACHE_ANY)
		host_low_on_pongs = (hc->host_count < (max_hosts_cached >> 3));

	if (dbg > 8)
		printf("added %s %s (%s)\n", what, ip_port_to_gchar(ip, port),
			type == HCACHE_ANY ? (host_low_on_pongs ? "LOW" : "OK") : "");

	return TRUE;
}

/*
 * hcache_remove
 */
static void hcache_remove(struct hostcache *hc, struct gnutella_host *h)
{
	hc->sl_caught_hosts = g_list_remove(hc->sl_caught_hosts, h);
	hcache_ht_remove(hc, h);

	if (!hc->sl_caught_hosts) {
		hc->sl_caught_hosts = hc->sl_valid_hosts;
		hc->sl_valid_hosts = NULL;
	}

	wfree(h, sizeof(*h));
}

/*
 * hcache_is_low
 *
 * Do we have less that our mimumum amount of hosts in the cache?
 */
gboolean hcache_is_low(hcache_type_t type)
{
	g_assert(type >= 0 && type < HCACHE_MAX);
	g_assert(caches[type] != NULL);

	return caches[type]->host_count < MIN_RESERVE_SIZE;
}

/*
 * hcache_remove_all
 *
 * Remove all entries from hostcache.
 */
static void hcache_remove_all(struct hostcache *hc)
{
    start_mass_update(hc);

	/*
	 * Note that hcache_remove() will switch to `sl_valid_hosts' when the
	 * `sl_caugh_hosts' list becomes empty.
	 */

	while (hc->sl_caught_hosts)
		hcache_remove(hc, (struct gnutella_host *) hc->sl_caught_hosts->data);

    end_mass_update(hc);
}

/*
 * hcache_clear
 *
 * Clear the whole host cache.
 */
void hcache_clear(hcache_type_t type)
{
	struct hostcache *hc;

	g_assert(type >= 0 && type < HCACHE_MAX);
	g_assert(caches[type] != NULL);

	hc = caches[type];

	hcache_remove_all(hc);
	pcache_clear_recent(type);
}

/*
 * hcache_size
 *
 * Returns the amount of hosts in the cache.
 */
gint hcache_size(hcache_type_t type)
{
	g_assert(type >= 0 && type < HCACHE_MAX);
	g_assert(caches[type]);

	return caches[type]->host_count;
}

/*
 * hcache_prune
 *
 * Remove hosts that exceed our maximum.
 */
void hcache_prune(hcache_type_t type) 
{
	struct hostcache *hc;
    gint extra;

	g_assert(type >= 0 && type < HCACHE_MAX);

	hc = caches[type];

	/*
	 * Because the `ht_known_hosts' table records the hosts in the
	 * `sl_caught_hosts' list as well as those in the `sl_valid_hosts' list,
	 * it is possible that during the while loop, we reach the end of the
	 * `sl_caught_hosts' list.  At that point, we switch.
	 */

    extra = hc->host_count - *hc->max_hosts;

	while (extra-- > 0) {
		if (hc->sl_caught_hosts == NULL) {
			hc->sl_caught_hosts = hc->sl_valid_hosts;
			hc->sl_valid_hosts = NULL;
		}
		if (hc->sl_caught_hosts == NULL) {
			g_warning("BUG: asked to remove hosts, but hostcache list empty");
			break;
		}
		hcache_remove(hc, g_list_first(hc->sl_caught_hosts)->data);
	}
}

/*
 * hcache_fill_caught_array
 *
 * Fill `hosts', an array of `hcount' hosts already allocated with at most
 * `hcount' hosts from out caught list, without removing those hosts from
 * the list.
 *
 * Returns the amount of hosts filled.
 */
gint hcache_fill_caught_array(
	hcache_type_t type, struct gnutella_host *hosts, gint hcount)
{
	GList *l;
	gint i;
	struct hostcache *hc;

	g_assert(type >= 0 && type < HCACHE_MAX);

	/*
	 * First try to fill from our recent pongs, as they are more fresh
	 * and therefore more likely to be connectible.
	 */

	for (i = 0; i < hcount; i++) {
		guint32 ip;
		guint16 port;

		if (!pcache_get_recent(type, &ip, &port))
			break;

		hosts[i].ip = ip;
		hosts[i].port = port;
	}

	if (i == hcount)
		return hcount;

	/*
	 * Not enough fresh pongs, get some from our reserve.
	 */

	hc = caches[type];

	for (l = g_list_last(hc->sl_caught_hosts); i < hcount; i++, l = l->prev) {
		struct gnutella_host *h;

		if (!l)
			return i;			/* Amount of hosts we filled */
		
		h = (struct gnutella_host *) l->data;
		hosts[i] = *h;			/* struct copy */
	}

	return hcount;				/* We  filled all the slots */
}

/* 
 * hcache_find_nearby
 * 
 * Finds a host in either the pong_cache or the host_cache that is in 
 * one of the local networks. 
 *
 * returns true if host is found
 */
gboolean hcache_find_nearby(hcache_type_t type, guint32 *ip, guint16 *port)
{
	struct gnutella_host *h;
	static int alternate = 0;
	guint32 first_ip;
	guint16 first_port;
	gboolean got_recent;
	GList *link;
	struct hostcache *hc;
	gboolean reading;

	g_assert(type >= 0 && type < HCACHE_MAX);

	hc = caches[type];
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
		link = reading ?  g_list_first(hc->sl_caught_hosts) :
			g_list_last(hc->sl_caught_hosts);
		link; link = link->prev
	) {

		h = (struct gnutella_host *) link->data;
		if (host_is_nearby(h->ip)) {

			hc->sl_caught_hosts = g_list_remove_link(hc->sl_caught_hosts, link);
			g_list_free_1(link);
			hcache_ht_remove(hc, h);

			*ip = h->ip;
			*port = h->port;
			wfree(h, sizeof(*h));

			if (!hc->sl_caught_hosts) {
				hc->sl_caught_hosts = hc->sl_valid_hosts;
				hc->sl_valid_hosts = NULL;
			}
			return TRUE;
		}

	}

	return FALSE;

}

/*
 * hcache_get_caught
 *
 * Get host IP/port information from our caught host list, or from the
 * recent pont cache, in alternance.
 */
void hcache_get_caught(hcache_type_t type, guint32 *ip, guint16 *port)
{
	static guint alternate = 0;
	struct gnutella_host *h;
	GList *link;
	struct hostcache *hc;
	gboolean reading;
	extern guint32 number_local_networks;

	g_assert(type >= 0 && type < HCACHE_MAX);

	hc = caches[type];
    gnet_prop_get_boolean_val(hc->reading, &reading);

	g_assert(hc->sl_caught_hosts);		/* Must not call if no host in list */


	if (type == HCACHE_ANY)
		host_low_on_pongs = (hc->host_count < (max_hosts_cached >> 3));

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

	link = reading ?
		g_list_first(hc->sl_caught_hosts) : g_list_last(hc->sl_caught_hosts);

	h = (struct gnutella_host *) link->data;
	hc->sl_caught_hosts = g_list_remove_link(hc->sl_caught_hosts, link);
	g_list_free_1(link);
	hcache_ht_remove(hc, h);

	*ip = h->ip;
	*port = h->port;
	wfree(h, sizeof(*h));

	if (!hc->sl_caught_hosts) {
		hc->sl_caught_hosts = hc->sl_valid_hosts;
		hc->sl_valid_hosts = NULL;
	}
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
	struct hostcache *hc;			/* Hostcache to fill */
};

/*
 * read_ctx_free
 *
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

/*
 * read_done
 *
 * Read is finished.
 */
static void read_done(struct hostcache *hc)
{
    /*
     * Order is important so the GUI can update properly. First we say
     * that loading has finished, then we tell the GUI the number of
     * hosts in the catcher.
     *      -- Richard, 6/8/2002
     */
    
    gnet_prop_set_boolean_val(hc->reading, FALSE);
    end_mass_update(hc);
}

/*
 * read_step
 *
 * One reading step.
 */
static bgret_t read_step(gpointer h, gpointer u, gint ticks)
{
	struct read_ctx *rctx = (struct read_ctx *) u;
	struct hostcache *hc;
	gint max_read;
	gint count;
	gint i;

	g_assert(rctx->magic == READ_MAGIC);
	g_assert(rctx->fd);

	hc = rctx->hc;

	max_read = *hc->max_hosts - hc->host_count;
	count = ticks * HOST_READ_CNT;
	count = MIN(max_read, count);

	for (i = 0; i < count; i++) {
		if (fgets(h_tmp, sizeof(h_tmp) - 1, rctx->fd)) { /* NUL appended */
			guint32 ip;
			gint16 port;

			if (gchar_to_ip_port(h_tmp, &ip, &port))
				host_add(ip, port, FALSE);
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

/* 
 * hcache_retrieve
 *
 * Loads caught hosts from text file.
 */
void hcache_retrieve(hcache_type_t type)
{
	struct hostcache *hc;
	struct read_ctx *rctx;
	FILE *fd;
	bgstep_cb_t step = read_step;

	g_assert(type >= 0 && type < HCACHE_MAX);
	g_assert(caches[type] != NULL);

	hc = caches[type];

	{
		file_path_t fp = { config_dir, hc->filename };
		fd = file_config_open_read("hosts", &fp, 1);
	}

	if (!fd)
		return;

	rctx = walloc(sizeof(*rctx));
	rctx->magic = READ_MAGIC;
	rctx->fd = fd;
	rctx->hc = hc;

    start_mass_update(hc);
    gnet_prop_set_boolean_val(hc->reading, TRUE);

	bg_task_create(
		type == HCACHE_ANY ? "Hostcache reading" : "Ultracache reading",
		&step, 1, rctx, read_ctx_free, NULL, NULL);
}

/*
 * hcache_store
 *
 * Persist hostcache to disk.
 */
void hcache_store(hcache_type_t type)
{
	struct hostcache *hc;
	FILE *f;
	GList *l;
	file_path_t fp;

	g_assert(type >= 0 && type < HCACHE_MAX);
	g_assert(caches[type] != NULL);

	hc = caches[type];

	fp.dir = config_dir;
	fp.name = hc->filename;

	f = file_config_open_write("hosts", &fp);

	if (!f)
		return;

	/*
	 * Write "valid" hosts first.  Next time we are launched, we'll first
	 * start reading from the head first.  And once the whole cache has
	 * been read in memory, we'll begin using the tail of the list, i.e.
	 * possibly older hosts, which will help ensure we don't always connect
	 * to the same set of hosts.
	 */

	for (l = hc->sl_valid_hosts; l; l = l->next)
		fprintf(f, "%s\n",
				ip_port_to_gchar(((struct gnutella_host *) l->data)->ip,
								 ((struct gnutella_host *) l->data)->port));

	for (l = hc->sl_caught_hosts; l; l = l->next)
		fprintf(f, "%s\n",
				ip_port_to_gchar(((struct gnutella_host *) l->data)->ip,
								 ((struct gnutella_host *) l->data)->port));

	file_config_close(f, &fp);
}

/*
 * hcache_init
 *
 * Initialize host caches.
 */
void hcache_init(void)
{
	hcache_alloc(HCACHE_ANY,
		PROP_HOSTS_IN_CATCHER, PROP_READING_HOSTFILE, &max_hosts_cached);

	hcache_alloc(HCACHE_ULTRA,
		PROP_HOSTS_IN_ULTRA_CATCHER, PROP_READING_ULTRAFILE,
		&max_ultra_hosts_cached);
}

/*
 * hcache_close
 *
 * Shutdown host caches.
 */
void hcache_close(void)
{
	hcache_free(HCACHE_ANY);
	hcache_free(HCACHE_ULTRA);
}

/* vi: set ts=4: */

