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

RCSID("$Id$");

gboolean host_low_on_pongs = FALSE;			/* True when less than 12% full */

static gboolean in_shutdown = FALSE;

/***
 *** Host periodic timer.
 ***/

/*
 * host_timer
 *
 * Periodic host heartbeat timer.
 */
void host_timer(void)
{
	static gint called = 0;
    gint count;
	gint nodes_missing;
	guint32 ip;
	guint16 port;
	hcache_type_t hctype;
	gint max_nodes;
	gint up_nodes;

	if (in_shutdown || !online_mode)
		return;

	count = node_count();

	if (current_peermode == NODE_P_LEAF)
		max_nodes = up_nodes = max_ultrapeers;
	else {
		max_nodes = max_connections;
		up_nodes = up_connections;
	}

	nodes_missing = up_nodes - count;

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

	if (count < max_nodes)
		nodes_missing -= whitelist_connect();
    
	/*
	 * If we are under the number of connections wanted, we add hosts
	 * to the connection list
	 */

	hctype = current_peermode == NODE_P_LEAF ? HCACHE_ULTRA : HCACHE_ANY;

	if (hcache_size(hctype) == 0)
		hctype = HCACHE_ANY;

	if (nodes_missing > 0) {
        if (!stop_host_get) {
			while (hcache_size(hctype) && nodes_missing-- > 0) {
				hcache_get_caught(hctype, &ip, &port);
				node_add(ip, port);
			}
			if (nodes_missing)
				gwc_get_hosts(); 		/* Fill hosts from web host cache */
		}
	}
	else if (use_netmasks) {
		/* Try to find better hosts */
		if (hcache_find_nearby(hctype, &ip, &port)) {
			if (node_remove_worst(TRUE))
				node_add(ip, port); 
			else
				hcache_add(hctype, ip, port, "nearby host");
		}
	}
}

/***
 *** Hosts
 ***/

void host_init(void)
{
	pcache_init();
}

/*
 * host_is_connected
 *
 * Are we directly connected to that host?
 */
static gboolean host_is_connected(guint32 ip, guint16 port)
{
	GSList *l;

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

	return FALSE;
}


/*
 * add_host_to_cache
 *
 * Common processing for host_add() and host_add_semi_pong().
 * Returns true when IP/port passed sanity checks.
 */
static gboolean add_host_to_cache(
	hcache_type_t htype, guint32 ip, guint16 port, gchar *type)
{
	if (ip == listen_ip() && port == listen_port)
		return FALSE;

	if (host_is_connected(ip, port))
		return FALSE;			/* Connected to that host? */

	if (hcache_add(htype, ip, port, type))
		return TRUE;

	return TRUE;
}

/*
 * host_add_ultra
 *
 * Add a new host to our ultra pong reserve.
 */
void host_add_ultra(guint32 ip, guint16 port)
{
	if (!add_host_to_cache(HCACHE_ULTRA, ip, port, "pong"))
		return;

    hcache_prune(HCACHE_ULTRA);
}

/*
 * host_add
 *
 * Add a new host to our pong reserve.
 * When `connect' is true, attempt to connect if we are low in Gnet links.
 */
void host_add(guint32 ip, guint16 port, gboolean connect)
{
	if (!add_host_to_cache(HCACHE_ANY, ip, port, "pong"))
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
		gint max_nodes;
		gint up_nodes;

		if (current_peermode == NODE_P_LEAF)
			max_nodes = up_nodes = max_ultrapeers;
		else {
			max_nodes = max_connections;
			up_nodes = up_connections;
		}

		if (node_count() < max_nodes) {
			if (connected_nodes() < up_nodes)
				node_add(ip, port);
		} else {
			/* If we are above the max connections, delete a non-nearby 
			 * connection before adding this better one
			 */
			if (use_netmasks && host_is_nearby(ip) && node_remove_worst(TRUE))
				node_add(ip, port);
		}

	}

    hcache_prune(HCACHE_ANY);
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

	(void) add_host_to_cache(HCACHE_ANY, ip, port, "semi-pong");

	/*
	 * Don't attempt to prune cache, we know we're below the limit.
	 */
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
 * parse_netmasks
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

    if (!masks)
        return;

	for (i = 0; masks[i]; i++);

	number_local_networks = i;

	if (i == 0) {
        g_strfreev(masks);
		return;
    }

	local_networks = (struct network_pair *)g_malloc(sizeof(*local_networks)*i);

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

/* -------------------------- */

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
	pcache_close();
	free_networks();
}

/* vi: set ts=4: */

