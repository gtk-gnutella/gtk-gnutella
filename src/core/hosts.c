/*
 * $Id$
 *
 * Copyright (c) 2001-2004, Raphael Manfredi
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
 * Host management.
 */

#include "common.h"

RCSID("$Id$");

#include "sockets.h"
#include "hosts.h"
#include "nodes.h"
#include "share.h"		/* For files_scanned and kbytes_scanned. */
#include "routing.h"
#include "gmsg.h"
#include "pcache.h"
#include "whitelist.h"
#include "gwcache.h"
#include "settings.h"
#include "bogons.h"
#include "uhc.h"

#include "if/gnet_property_priv.h"

#include "lib/endian.h"
#include "lib/override.h"		/* Must be the last header included */

gboolean host_low_on_pongs = FALSE;			/* True when less than 12% full */

static gboolean in_shutdown = FALSE;

/***
 *** Host hashing.
 ***/

/**
 * Hash function for use in g_hash_table_new.
 */
guint
host_hash(gconstpointer key)
{
	const gnet_host_t *host = (const gnet_host_t *) key;

	return (guint) (host->ip ^ ((host->port << 16) | host->port));
}

/**
 * Compare function which returns TRUE if the hosts are equal.
 *
 * @note For use in g_hash_table_new
 */
gint
host_eq(gconstpointer v1, gconstpointer v2)
{
	const gnet_host_t *h1 = (const gnet_host_t *) v1;
	const gnet_host_t *h2 = (const gnet_host_t *) v2;

	return h1->ip == h2->ip && h1->port == h2->port;
}

/**
 * Compare function which returns 0 if the hosts are equal, otherwise 1.
 *
 * @note For use in g_list_find_custom
 */
gint
host_cmp(gconstpointer v1, gconstpointer v2)
{
	return host_eq(v1, v2) ? 0 : 1;
}


/***
 *** Host periodic timer.
 ***/

/**
 * Periodic host heartbeat timer.
 */
void
host_timer(void)
{
	static gint called = 0;
    guint count;
	gint missing;
	guint32 ip;
	guint16 port;
	host_type_t htype;
	guint max_nodes;

	if (in_shutdown || !online_mode)
		return;

	max_nodes = (current_peermode == NODE_P_LEAF) ?
		max_ultrapeers : max_connections;
	count = node_count();
	missing = node_keep_missing();

	/*
	 * If we are not connected to the Internet, apparently, make sure to
	 * connect to at most one host, to avoid using all our hostcache.
	 * Also, we don't connect each time we are called.
	 */

	if (!is_inet_connected && missing) {
		if (0 == (called++ & 0xf))		/* Once every 16 attempts */
			missing = 1;
		else
			missing = 0;			/* Don't connect this run */
	}

	/*
	 * Allow more outgoing connections than the maximum amount of
	 * established Gnet connection we can maintain, but not more
	 * than quick_connect_pool_size   This is the "greedy mode".
	 */

	if (count >= quick_connect_pool_size)
		if (dbg > 10) {
			g_message("host_timer - count %d >= pool size %d",
				count, quick_connect_pool_size);
		return;
	}

	if (count < max_nodes)
		missing -= whitelist_connect();

	if (dbg > 10)
		g_message("host_timer - missing %d host%s",
			count, count == 1 ? "" : "s");

	/*
	 * If we are under the number of connections wanted, we add hosts
	 * to the connection list
	 */

	htype = (current_peermode == NODE_P_NORMAL) ?
        HOST_ANY : HOST_ULTRA;

	if (
        current_peermode == NODE_P_ULTRA &&
        node_normal_count < normal_connections &&
        node_ultra_count >= (up_connections - normal_connections)
	) {
		htype = HOST_ANY;
    }

	if (hcache_size(htype) == 0)
		htype = HOST_ANY;

    if (!stop_host_get) {
        if (missing > 0) {
            guint fan;
            guint max_pool = MAX(quick_connect_pool_size, max_nodes);
            guint to_add;

            fan = (missing * quick_connect_pool_size) / max_nodes;
            to_add = is_inet_connected ? fan : (guint) missing;

            /*
             * Make sure that we never use more connections then the
             * quick pool or the maximum number of hosts allow.
             */
            if (to_add + count > max_pool)
                to_add = max_pool - count;

            if (dbg > 10) {
                g_message("host_timer - connecting - add: %d fan:%d  miss:%d "
                     "max_hosts:%d   count:%d   extra:%d",
					 to_add, fan, missing, max_nodes, count,
					 quick_connect_pool_size);
            }

            missing = to_add;

			while (hcache_size(htype) && missing-- > 0) {
				hcache_get_caught(htype, &ip, &port);
				node_add(ip, port);
			}

			if (missing > 0 && hcache_read_finished()) {
				static gint rotate = 0;

				if (!uhc_is_waiting() && !gwc_is_waiting()) {
					if (!enable_udp || (0x3 == (rotate++ & 0x3)))
						gwc_get_hosts(); 	/* Get from web host cache */
					else
						uhc_get_hosts();	/* Get from UDP pong caches */
				} else if (dbg > 10)
					g_message("host_timer - waiting for reply from %s",
						uhc_is_waiting() ? "UDP host cache" : "web cache");
			}
		}

	} else if (use_netmasks) {
		/* Try to find better hosts */
		if (hcache_find_nearby(htype, &ip, &port)) {
			if (node_remove_worst(TRUE))
				node_add(ip, port);
			else
				hcache_add_caught(htype, ip, port, "nearby host");
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

/**
 * Check whether host is connectible, i.e. that it has a valid port and that
 * its IP address is not private not bogus.
 */
gboolean
host_is_valid(guint32 ip, guint16 port)
{
	if (!port_is_valid(port))
		return FALSE;

	if (!ip_is_valid(ip))
		return FALSE;

	if (bogons_check(ip))
		return FALSE;

	return TRUE;
}

/**
 * Add a new host to our pong reserve.
 * When `connect' is true, attempt to connect if we are low in Gnet links.
 */
void
host_add(guint32 ip, guint16 port, gboolean do_connect)
{
	if (!hcache_add_caught(HOST_ANY, ip, port, "pong"))
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


	if (do_connect) {
		if (node_keep_missing() > 0)
				node_add(ip, port);
		else {
			/* If we are above the max connections, delete a non-nearby
			 * connection before adding this better one
			 */
			if (use_netmasks && host_is_nearby(ip) && node_remove_worst(TRUE))
				node_add(ip, port);
		}

	}
}

/**
 * Add a new host to our pong reserve, although the information here
 * does not come from a pong but from a Query Hit packet, hence the port
 * may be unsuitable for Gnet connections.
 */
void
host_add_semi_pong(guint32 ip, guint16 port)
{
	g_assert(host_low_on_pongs);	/* Only used when low on pongs */

    hcache_add_caught(HOST_ANY, ip, port, "semi-pong");
}

/* ---------- Netmask heuristic by Mike Perry -------- */
struct network_pair
{
	struct in_addr mask;
	struct in_addr net;
};

struct network_pair *local_networks = NULL;
guint32 number_local_networks;

/**
 * frees the local networks array
 */
static
void free_networks(void)
{
	if (local_networks)
		G_FREE_NULL(local_networks);
}

/**
 * Break the netmaks string and convert them into network_pair elements in
 * the local_networks array. IP's are in network order.
 */
void
parse_netmasks(gchar * str)
{
	gchar **masks = g_strsplit(str, ";", 0);
	gchar *p;
	guint32 mask_div;
	int i;

	free_networks();

    if (!masks)
        return;

	for (i = 0; masks[i]; i++)
		/* just count */ ;

	number_local_networks = i;

	if (i == 0) {
        g_strfreev(masks);
		return;
    }

	local_networks =
		(struct network_pair *) g_malloc(i * sizeof(*local_networks));

	for (i = 0; masks[i]; i++) {
		/* Network is of the form ip/mask or ip/bits */
		if ((p = strchr(masks[i], '/')) && *p) {
			*p = 0;
			p++;
			if (strchr(p, '.')) {
				/* get the network address from the user */
				if (inet_aton(p, &local_networks[i].mask) == 0)
					perror("inet_aton on netmasks");
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
					WRITE_GUINT32_BE(~((1 << (32 - mask_div)) - 1),
						&local_networks[i].mask.s_addr);
			}
		}
		else {
			/* Assume single-host */
			inet_aton("255.255.255.255", &local_networks[i].mask);
		}
		/* get the network address from the user */
		if (inet_aton(masks[i], &local_networks[i].net) == 0)
			perror("inet_aton on netmasks");
	}

	g_strfreev(masks);
}

/**
 * Returns true if the ip is inside one of the local networks
 */
gboolean
host_is_nearby(guint32 ip)
{
	guint i;

	for (i = 0; i < number_local_networks; i++) {
		if ((ip & local_networks[i].mask.s_addr) ==
				(local_networks[i].net.s_addr & local_networks[i].mask.s_addr))
			return TRUE;
	}
	return FALSE;
}

/* -------------------------- */

/**
 * Signals that we're shutdowning and entering a grace period, during which
 * we don't need to make any new connection.
 */
void
host_shutdown(void)
{
	in_shutdown = TRUE;
}

void
host_close(void)
{
	pcache_close();
	free_networks();
}

/* vi: set ts=4 sw=4 cindent: */

