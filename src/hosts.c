/*
 * $Id$
 *
 * Copyright (c) 2001-2002, Raphael Manfredi
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
#include <fcntl.h>
#include <sys/types.h>
#include <string.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include "sockets.h"
#include "hosts.h"
#include "nodes.h"
#include "share.h" /* For files_scanned and kbytes_scanned. */
#include "routing.h"
#include "gmsg.h"
#include "pcache.h"
#include "whitelist.h"
#include "gwcache.h"

#include "settings.h"

GList *sl_caught_hosts = NULL;				/* Reserve list */
static GList *sl_valid_hosts = NULL;		/* Validated hosts */
static GHashTable *ht_known_hosts = NULL;	/* All known hosts */

gboolean host_low_on_pongs = FALSE;			/* True when less than 12% full */

gchar h_tmp[4096];

gint hosts_idle_func = 0;

#define HOST_READ_CNT		20	/* Amount of hosts to read each idle tick */
#define HOST_CATCHER_DELAY	10	/* Delay between connections to same host */
#define MIN_RESERVE_SIZE	1024	/* we'd like that many pongs in reserve */

static gboolean in_shutdown = FALSE;
static gint mass_operation  = 0;

static void start_mass_update(void)
{
    mass_operation ++;
}

static void end_mass_update(void) 
{
    guint32 val = hosts_in_catcher;

    g_assert(mass_operation > 0);

    mass_operation --;

    if (mass_operation == 0)
        gnet_prop_set_guint32(PROP_HOSTS_IN_CATCHER, &val, 0, 1);
}

/***
 *** Host timer.
 ***/

/*
 * auto_connect
 *
 * Round-robin selection of a host catcher, and addition to the list of
 * nodes, if not already connected to it.
 */
static void auto_connect(void)
{
	static gchar *host_catcher[] = {
		"connect1.gnutellanet.com",
		"connect2.gnutellanet.com",
		"public.bearshare.net",
		"connect3.gnutellanet.com",
		"gnet2.ath.cx",
		"connect1.bearshare.net",
		"gnutella-again.hostscache.com",	/* Multiple IPs, oh well */
	};
	static struct host_catcher {
		time_t tried;
		guint32 ip;
	} *host_tried = NULL;
	static guint host_idx = 0;
	guint32 ip = 0;
	guint16 port = 6346;
	gint host_count = sizeof(host_catcher) / sizeof(host_catcher[0]);
	gint i;
	time_t now = time((time_t *) NULL);
	extern gboolean node_connected(guint32, guint16, gboolean);

	/*
	 * Try to fill hosts from web host cache, asynchronously.
	 */

	gwc_get_hosts();

	/*
	 * To avoid hammering the host caches, we don't allow connections to
	 * each of them that are not at least HOST_CATCHER_DELAY seconds apart.
	 * The `host_tried' array keeps track of our last attempts.
	 *		--RAM, 30/12/2001
	 *
	 * To avoid continuous (blocking) DNS lookups when we are low on hosts,
	 * cache the IP of each host catcher.  We assume those are fairly stable
	 * hosts and that their IP will never change during the course of our
	 * running time.
	 *		--RAM, 14/01/2002
	 */

	if (host_tried == NULL)
		host_tried = g_malloc0(sizeof(struct host_catcher) * host_count);

	for (i = 0; i < host_count; i++, host_idx++) {
		if (host_idx >= host_count)
			host_idx = 0;

		ip = host_tried[host_idx].ip;
		if (ip == 0)
			ip = host_tried[host_idx].ip = host_to_ip(host_catcher[host_idx]);

		if (
			ip != 0 &&
			!node_connected(ip, port, FALSE) &&
			(now - host_tried[host_idx].tried) >= HOST_CATCHER_DELAY
		) {
			node_add(ip, port);
			host_tried[host_idx].tried = now;
			return;
		}
	}
}

/*
 * host_timer
 *
 * Periodic host heartbeat timer.
 */
void host_timer(void)
{
	static gint called = 0;
    int count = node_count();
	int nodes_missing = up_connections - count;
	guint32 ip;
	guint16 port;

	if (in_shutdown)
		return;

	/*
	 * If we are not connected to the Internet, apparently, make sure to
	 * connect to at most one host, to avoid using all our hostcache.
	 * Also, we don't connect each time we are called.
	 */

	if (!is_inet_connected && nodes_missing) {
		if (0 == (called++ & 0xf))		/* Once every 16 attempts */
			nodes_missing = 1;
		else
			nodes_missing = 0;			/* Don't connect this run */
	}

    if (count < max_connections) {
        nodes_missing -= whitelist_connect();
    }
    
	/*
	 * If we are under the number of connections wanted, we add hosts
	 * to the connection list
	 */

	if (nodes_missing > 0) {
        if (!stop_host_get) {
            if (sl_caught_hosts != NULL) {
                while (nodes_missing-- > 0 && sl_caught_hosts) {
					host_get_caught(&ip, &port);
					node_add(ip, port);
				}
			} else
				auto_connect();
		}
	}
	else if (use_netmasks) {
		/* Try to find better hosts */
		if (find_nearby_host(&ip, &port) && node_remove_non_nearby())
			node_add(ip, port); 
	}
}

/***
 *** Host hash table handling.
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

static gboolean host_ht_add(struct gnutella_host *host)
{
	/* Add host to the ht_known_hosts table */

	if (g_hash_table_lookup(ht_known_hosts, (gconstpointer) host)) {
		g_warning("Attempt to add %s twice to caught host list",
				  ip_port_to_gchar(host->ip, host->port));
		return FALSE;
	}

    if (!mass_operation) {
        guint32 val = hosts_in_catcher+1;

        gnet_prop_set_guint32(PROP_HOSTS_IN_CATCHER, &val, 0, 1);
    } else
        hosts_in_catcher ++;

	g_hash_table_insert(ht_known_hosts, host, (gpointer) 1);

	return TRUE;
}

static void host_ht_remove(struct gnutella_host *host)
{
	/* Remove host from the ht_known_hosts table */

	if (!g_hash_table_lookup(ht_known_hosts, (gconstpointer) host)) {
		g_warning("Attempt to remove missing %s from caught host list",
				  ip_port_to_gchar(host->ip, host->port));
		return;
	}

    if (!mass_operation) {
        guint32 val = hosts_in_catcher-1;

        gnet_prop_set_guint32(PROP_HOSTS_IN_CATCHER, &val, 0, 1);
    } else
        hosts_in_catcher --;

	g_hash_table_remove(ht_known_hosts, host);
}

/*
 * host_save_valid
 *
 * Save host to the validated server list
 *
 * We put in this list all the Gnet nodes to which we were able to connect
 * and transmit at list one packet (indicating a successful handshake).
 */
void host_save_valid(guint32 ip, guint16 port)
{
	struct gnutella_host *host;

	/*
	 * This routing must be called only when the node has been removed
	 * from `sl_nodes' or find_host() will report we have the node.
	 */

	if (!check_valid_host(ip, port))
		return;

	if (find_host(ip, port))
		return;						/* Already have it, from a pong? */

	host = (struct gnutella_host *) g_malloc0(sizeof(struct gnutella_host));

	host->ip = ip;
	host->port = port;

	/*
	 * We prepend to the list instead of appending because the day
	 * we switch it as `sl_caught_hosts', we'll start reading from there,
	 * in effect using the most recent hosts we know about.
	 */

	if (host_ht_add(host))
		sl_valid_hosts = g_list_prepend(sl_valid_hosts, host);
	else
		g_free(host);
}

/***
 *** Hosts
 ***/

void host_init(void)
{
	ht_known_hosts = g_hash_table_new(host_hash, host_eq);
	pcache_init();
}

gboolean find_host(guint32 ip, guint16 port)
{
	GSList *l;
	struct gnutella_host lhost = { ip, port };

	/* Check our local ip */

	if (ip == listen_ip())
		return TRUE;

	/* Check the nodes -- this is a small list, OK to traverse */

	for (l = sl_nodes; l; l = l->next) {
		struct gnutella_node *node = (struct gnutella_node *) l->data;
		if (NODE_IS_REMOVING(node))
			continue;
		if (!node->gnet_ip)
			continue;
		if (node->gnet_ip == ip && node->gnet_port == port)
			return TRUE;
	}

	/* Check the hosts -- large list, use hash table --RAM */

	return g_hash_table_lookup(ht_known_hosts, &lhost) ? TRUE : FALSE;
}

void host_remove(struct gnutella_host *h)
{
	sl_caught_hosts = g_list_remove(sl_caught_hosts, h);
	host_ht_remove(h);

	if (!sl_caught_hosts) {
		sl_caught_hosts = sl_valid_hosts;
		sl_valid_hosts = NULL;
	}

	g_free(h);
}

gboolean check_valid_host(guint32 ip, guint16 port)
{
	if (!ip || !port)
		return FALSE;			/* IP == 0 || Port == 0 */

	if (is_private_ip(ip)) 
		return FALSE;

	if (ip == (guint32) 0x01020304 || ip == (guint32) 0x01010101)
		return FALSE;			/* IP == 1.2.3.4 || IP == 1.1.1.1 */
	if ((ip & (guint32) 0xF0000000) == (guint32) 0xE0000000)
		return FALSE;			/* IP == 224..239.0.0 / 8 (multicast) */
	if ((ip & (guint32) 0xFF000000) == (guint32) 0x00000000)
		return FALSE;			/* IP == 0.0.0.0 / 8 */
	if ((ip & (guint32) 0xFF000000) == (guint32) 0x7F000000)
		return FALSE;			/* IP == 127.0.0.0 / 8 */
	if ((ip & (guint32) 0xFFFFFF00) == (guint32) 0xFFFFFF00)
		return FALSE;			/* IP == 255.255.255.0 / 24 */

	return TRUE;
}

/*
 * add_host_to_cache
 *
 * Common processing for host_add() and host_add_semi_pong().
 * Returns true when IP/port passed sanity checks.
 */
static gboolean add_host_to_cache(guint32 ip, guint16 port, gchar *type)
{
	struct gnutella_host *host;

	if (!check_valid_host(ip, port))
		return FALSE;			/* Is host valid? */

	if (find_host(ip, port))
		return FALSE;			/* Do we have this host? */

	/* Okay, we got a new host */

	host = (struct gnutella_host *) g_malloc0(sizeof(struct gnutella_host));

	host->port = port;
	host->ip = ip;

	if (host_ht_add(host))
		sl_caught_hosts = g_list_append(sl_caught_hosts, host);
	else
		g_free(host);

	if (!sl_caught_hosts) {
		sl_caught_hosts = sl_valid_hosts;
		sl_valid_hosts = NULL;
	}

	host_low_on_pongs = (hosts_in_catcher < (max_hosts_cached >> 3));

	if (dbg > 8)
		printf("added %s %s (%s)\n", type, ip_port_to_gchar(ip, port),
			host_low_on_pongs ? "LOW" : "OK");

	return TRUE;
}

/* 
 * host_cache_is_empty
 *
 * Test whether the host cache is (practically) empty
 */
gboolean host_cache_is_empty(void)
{
	return g_hash_table_size(ht_known_hosts) < MIN_RESERVE_SIZE;
}

/*
 * host_cache_size
 *
 * Amount of entries in cache.
 */
gint host_cache_size(void)
{
	return g_hash_table_size(ht_known_hosts);
}

/*
 * host_add
 *
 * Add a new host to our pong reserve.
 * When `connect' is true, attempt to connect if we are low in Gnet links.
 */
void host_add(guint32 ip, guint16 port, gboolean connect)
{
	if (ip == listen_ip() && port == listen_port)
		return;

	if (!add_host_to_cache(ip, port, "pong"))
		return;

	/*
	 * If we are under the number of connections wanted, we add this host
	 * to the connection list.
	 *
	 * Note: we're not using `node_count()' for the comparison with
	 * `up_connections' but connected_nodes().	The node_add() routine also
	 * compare `node_count' with `max_connections' to ensure we don't
	 * launch too many connections, but comparing here as well may help
	 * avoid useless call to connected_nodes() and/or node_add().
	 *				--RAM, 20/09/2001
	 */


	if (connect) {
		if (node_count() < max_connections) {
			if (connected_nodes() < up_connections) {
				node_add(ip, port);
			}
		}
		else {
			/* If we are above the max connections, delete a non-nearby 
			 * connection before adding this better one
			 */
			if (use_netmasks && host_is_nearby(ip) && node_remove_non_nearby())
				node_add(ip, port);
		}

	}
	/*
	 * Prune cache if we reached our limit.
	 *
	 * Because the `ht_known_hosts' table records the hosts in the
	 * `sl_caught_hosts' list as well as those in the `sl_valid_hosts' list,
	 * it is possible that during the while loop, we reach the end of the
	 * `sl_valid_hosts'.  At that point, we switch.
	 */

    host_prune_cache();
}

/*
 * host_prune_cache
 *
 * Remove hosts that exceed max_hosts_cached.
 */
void host_prune_cache() 
{
    gint extra;

    extra = g_hash_table_size(ht_known_hosts) - max_hosts_cached;
	while (extra-- > 0) {
		if (sl_caught_hosts == NULL) {
			sl_caught_hosts = sl_valid_hosts;
			sl_valid_hosts = NULL;
		}
		if (sl_caught_hosts == NULL) {
			g_warning("BUG: asked to remove hosts, but hostcache list empty");
			break;
		}
		host_remove(g_list_first(sl_caught_hosts)->data);
	}
}

/*
 * host_add_semi_pong
 *
 * Add a new host to our pong reserve, although the information here
 * does not come from a pong but from a Query Hit packet, hence the port
 * may be unsuitable for Gnet connections.
 */
void host_add_semi_pong(guint32 ip, guint16 port)
{
	g_assert(host_low_on_pongs);	/* Only used when low on pongs */

	(void) add_host_to_cache(ip, port, "semi-pong");

	/*
	 * Don't attempt to prune cache, we know we're below the limit.
	 */
}

static FILE *hosts_r_file = (FILE *) NULL;

/*
 * host_fill_caught_array
 *
 * Fill `hosts', an array of `hcount' hosts already allocated with at most
 * `hcount' hosts from out caught list, without removing those hosts from
 * the list.
 *
 * Returns the amount of hosts filled.
 */
gint host_fill_caught_array(struct gnutella_host *hosts, gint hcount)
{
	GList *l;
	gint i;

	/*
	 * First try to fill from our recent pongs, as they are more fresh
	 * and therefore more likely to be connectible.
	 */

	for (i = 0; i < hcount; i++) {
		guint32 ip;
		guint16 port;

		if (!pcache_get_recent(&ip, &port))
			break;

		hosts[i].ip = ip;
		hosts[i].port = port;
	}

	if (i == hcount)
		return hcount;

	/*
	 * Not enough fresh pongs, get some from our reserve.
	 */

	for (l = g_list_last(sl_caught_hosts); i < hcount; i++, l = l->prev) {
		struct gnutella_host *h;

		if (!l)
			return i;			/* Amount of hosts we filled */
		
		h = (struct gnutella_host *) l->data;
		hosts[i] = *h;			/* struct copy */
	}

	return hcount;				/* We  filled all the slots */
}

/* ---------- Netmask heuristic by Mike Perry -------- */
struct network_pair
{
	struct in_addr mask;
	struct in_addr net;
};

struct network_pair *local_networks = NULL;
guint32 number_local_networks;

/*
 * free_networks()
 *
 * frees the local networks array
 */
void free_networks()
{
	if (local_networks)
		g_free(local_networks);
}

/* 
 * parse_netmaks
 *
 * Break the netmaks string and convert them into network_pair elements in 
 * the local_networks array. IP's are in network order.
 */
void parse_netmasks(gchar * str)
{
	gchar **masks = g_strsplit(str, ";", 0);
	gchar *p;
	guint32 mask_div;
	int i;

	free_networks();

	for (i = 0; masks[i]; i++)
		;

	local_networks = (struct network_pair *)g_malloc(sizeof(*local_networks)*i);
	number_local_networks = i;

	for (i = 0; masks[i]; i++) {
		/* Network is of the form ip/mask or ip/bits */
		if ((p = strchr(masks[i], '/')) && *p) {
			*p = 0;
			p++;
			if (strchr(p, '.')) {
				/* get the network address from the user */
				if (inet_aton(p, &local_networks[i].mask) == 0)
					perror("inet_nota on netmasks");
			}
			else {
				errno = 0;
				mask_div = strtol(p, NULL, 10);
				if (mask_div > 32) {
					mask_div = 32;
				}
				if (errno)
					perror("netmask_div");
				else
					*(unsigned long *)&local_networks[i].mask = 
						htonl(~((1<<(32-mask_div)) - 1));
			}
		}
		else {
			/* Assume single-host */
			inet_aton("255.255.255.255", &local_networks[i].mask);
		}
		/* get the network address from the user */
		if (inet_aton(masks[i], &local_networks[i].net) == 0)
			perror("inet_nota on netmasks");
	}

	g_strfreev(masks);
}

/* 
 * host_is_nearby
 * 
 * Returns true if the ip is inside one of the local networks  
 */
gboolean host_is_nearby(guint32 ip)
{
	int i;

	for (i = 0; i < number_local_networks; i++) {
		/* We store IP's in host byte order for some reason... */
		if ((htonl(ip) & local_networks[i].mask.s_addr) == 
				(local_networks[i].net.s_addr & local_networks[i].mask.s_addr))
			return TRUE;
	}
	return FALSE;
}

/* 
 * find_nearby_host
 * 
 * Finds a host in either the pong_cache or the host_cache that is in 
 * one of the local networks. 
 *
 * returns true if host is found
 */
gboolean find_nearby_host(guint32 *ip, guint16 *port)
{
	struct gnutella_host *h;
	static int alternate = 0;
	guint32 first_ip;
	guint16 first_port;
	gboolean got_recent;
	GList *link;

	if (alternate++ & 1) {
		/* Iterate through all recent pongs */
		for (*ip = 0, got_recent = pcache_get_recent(&first_ip, &first_port);
				got_recent && (*ip != first_ip || *port != first_port); 
				got_recent = pcache_get_recent(ip, port)) {
			if (host_is_nearby(*ip))
				return TRUE;
		}
	}

	/* iterate through whole list */
	for (link = (hosts_r_file == NULL) ?
			g_list_last(sl_caught_hosts) : g_list_first(sl_caught_hosts);
			link; link = link->prev) {

		h = (struct gnutella_host *) link->data;
		if (host_is_nearby(h->ip)) {

			sl_caught_hosts = g_list_remove_link(sl_caught_hosts, link);
			g_list_free_1(link);
			host_ht_remove(h);

			*ip = h->ip;
			*port = h->port;
			g_free(h);

			if (!sl_caught_hosts) {
				sl_caught_hosts = sl_valid_hosts;
				sl_valid_hosts = NULL;
			}
			return TRUE;
		}

	}

	return FALSE;

}

/* -------------------------- */

/*
 * host_get_caught
 *
 * Get host IP/port information from our caught host list, or from the
 * recent pont cache, in alternance.
 */
void host_get_caught(guint32 *ip, guint16 *port)
{
	static guint alternate = 0;
	struct gnutella_host *h;
	GList *link;

	g_assert(sl_caught_hosts);		/* Must not call if no host in list */

	host_low_on_pongs = (hosts_in_catcher < (max_hosts_cached >> 3));

	/* 
	 * First, try to find a local host 
	 */
	if (use_netmasks && number_local_networks && find_nearby_host(ip, port))
		return;

	/*
	 * Try the recent pong cache when `alternate' is odd.
	 */

	if (alternate++ & 0x1 && pcache_get_recent(ip, port))
		return;

	/*
	 * If we're done reading from the host file, get latest host, at the
	 * tail of the list.  Otherwise, get the first host in that list.
	 */

	link = (hosts_r_file == NULL) ?
		g_list_last(sl_caught_hosts) : g_list_first(sl_caught_hosts);

	h = (struct gnutella_host *) link->data;
	sl_caught_hosts = g_list_remove_link(sl_caught_hosts, link);
	g_list_free_1(link);
	host_ht_remove(h);

	*ip = h->ip;
	*port = h->port;
	g_free(h);

	if (!sl_caught_hosts) {
		sl_caught_hosts = sl_valid_hosts;
		sl_valid_hosts = NULL;
	}
}

/***
 *** Hosts text files
 ***/

gint hosts_reading_func(gpointer data)
{
	gint max_read = max_hosts_cached - g_hash_table_size(ht_known_hosts);
	gint count = MIN(max_read, HOST_READ_CNT);
	gint i;

	for (i = 0; i < count; i++) {
		if (fgets(h_tmp, sizeof(h_tmp) - 1, hosts_r_file)) { /* NUL appended */
			guint32 ip;
			gint16 port;

			if (gchar_to_ip_port(h_tmp, &ip, &port))
				host_add(ip, port, FALSE);
		} else
			goto done;
	}

	if (count < max_read)
		return TRUE;			/* Host cache not full, need to read more */

	/* Fall through */

done:
	fclose(hosts_r_file);

	hosts_r_file = (FILE *) NULL;
	hosts_idle_func = 0;

    /*
     * Order is important so the GUI can update properly. First we say
     * that loading has finished, then we tell the GUI the number of
     * hosts in the catcher.
     *      -- Richard, 6/8/2002
     */
    {
        gboolean b = FALSE;
    
        gnet_prop_set_boolean(PROP_READING_HOSTFILE, &b, 0, 1);
    }
    end_mass_update();

	return FALSE;
}

/* 
 * hosts_read_from_file:
 *
 * Loads 'catched' hosts from a text file.
 */
void hosts_read_from_file(const gchar * path, gboolean quiet)
{
    start_mass_update();
    
	hosts_r_file = fopen(path, "r");

	if (!hosts_r_file) {
		if (!quiet)
			g_warning("Unable to open file %s (%s)\n", path,
					  g_strerror(errno));
		return;
	}

	hosts_idle_func = g_idle_add(hosts_reading_func, (gpointer) NULL);

    {
        gboolean b = TRUE;
        gnet_prop_set_boolean(PROP_READING_HOSTFILE, &b, 0, 1);
    }
}

void hosts_write_to_file(const gchar *path)
{
	/* Saves the currently catched hosts to a file */

	FILE *f;
	GList *l;
	gchar *new = g_strconcat(path, ".new", NULL);

	f = fopen(new, "w");

	if (!f) {
		g_warning("Unable to open output file %s (%s)\n", new,
				  g_strerror(errno));
		goto out;
	}

	/*
	 * Write "valid" hosts first.  Next time we are launched, we'll first
	 * start reading from the head first.  And once the whole cache has
	 * been read in memory, we'll begin using the tail of the list, i.e.
	 * possibly older hosts, which will help ensure we don't always connect
	 * to the same set of hosts.
	 */

	for (l = sl_valid_hosts; l; l = l->next)
		fprintf(f, "%s\n",
				ip_port_to_gchar(((struct gnutella_host *) l->data)->ip,
								 ((struct gnutella_host *) l->data)->port));

	for (l = sl_caught_hosts; l; l = l->next)
		fprintf(f, "%s\n",
				ip_port_to_gchar(((struct gnutella_host *) l->data)->ip,
								 ((struct gnutella_host *) l->data)->port));

	if (0 == fclose(f)) {
		if (-1 == rename(new, path))
			g_warning("could not rename %s as %s: %s",
				new, path, g_strerror(errno));
	} else
		g_warning("could not flush %s: %s", new, g_strerror(errno));

out:
	g_free(new);
}

/*
 * host_clear_cache
 *
 * Clear the whole host cache.
 */
void host_clear_cache(void)
{
    start_mass_update();

	while (sl_caught_hosts)
		host_remove((struct gnutella_host *) sl_caught_hosts->data);
	g_list_free(sl_caught_hosts);

	sl_caught_hosts = sl_valid_hosts;	/* host_remove() uses that list */
	sl_valid_hosts = NULL;

	while (sl_caught_hosts)
		host_remove((struct gnutella_host *) sl_caught_hosts->data);
	g_list_free(sl_caught_hosts);

	pcache_clear_recent();

    end_mass_update();
}

/*
 * host_shutdown
 *
 * Warn that we're shutdowning and entering a grace period, during which
 * we don't need to make any new connection.
 */
void host_shutdown(void)
{
	in_shutdown = TRUE;
}

void host_close(void)
{
	host_clear_cache();
	pcache_close();
	g_hash_table_destroy(ht_known_hosts);
	free_networks();
}

/* vi: set ts=4: */

