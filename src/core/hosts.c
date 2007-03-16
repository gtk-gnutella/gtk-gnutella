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
 * @ingroup core
 * @file
 *
 * Host management.
 *
 * @author Raphael Manfredi
 * @date 2001-2004
 */

#include "common.h"

RCSID("$Id$")

#include "sockets.h"
#include "hosts.h"
#include "nodes.h"
#include "share.h"			/* For files_scanned and kbytes_scanned. */
#include "routing.h"
#include "gmsg.h"
#include "pcache.h"
#include "whitelist.h"
#include "settings.h"
#include "bogons.h"
#include "uhc.h"

#include "if/gnet_property_priv.h"

#include "lib/endian.h"
#include "lib/glib-missing.h"
#include "lib/misc.h"
#include "lib/walloc.h"

#include "lib/override.h"	/* Must be the last header included */

gboolean host_low_on_pongs = FALSE;			/**< True when less than 12% full */

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
	const gnet_host_t *host = key;
	host_addr_t addr;
	guint16 port;

	addr = gnet_host_get_addr(host);
	port = gnet_host_get_port(host);
	return host_addr_hash(addr) ^ ((port << 16) | port);
}

/**
 * Compare function which returns TRUE if the hosts are equal.
 *
 * @note For use in g_hash_table_new.
 */
gint
host_eq(gconstpointer v1, gconstpointer v2)
{
	const gnet_host_t *h1 = v1, *h2 = v2;

	return gnet_host_get_port(h1) == gnet_host_get_port(h2) &&
		host_addr_equal(gnet_host_get_addr(h1), gnet_host_get_addr(h2));
}

/**
 * Compare function which returns 0 if the hosts are equal, otherwise 1.
 *
 * @note For use in g_list_find_custom.
 */
gint
host_cmp(gconstpointer v1, gconstpointer v2)
{
	return host_eq(v1, v2) ? 0 : 1;
}

void
gnet_host_vec_free(gnet_host_vec_t **vec_ptr)
{
	g_assert(vec_ptr != NULL);

	if (*vec_ptr) {
		gnet_host_vec_t *vec;
	
		vec = *vec_ptr;
		WFREE_NULL(vec->hvec_v4, vec->n_ipv4 * sizeof vec->hvec_v4[0]);
		WFREE_NULL(vec->hvec_v6, vec->n_ipv6 * sizeof vec->hvec_v6[0]);
		wfree(vec, sizeof *vec);
		*vec_ptr = NULL;
	}
}

gnet_host_vec_t *
gnet_host_vec_alloc(void)
{
	static const gnet_host_vec_t zero_vec;
	return wcopy(&zero_vec, sizeof zero_vec);
}

gnet_host_vec_t *
gnet_host_vec_copy(const gnet_host_vec_t *vec)
{
	gnet_host_vec_t *vec_copy;

	g_return_val_if_fail(vec, NULL);
	g_return_val_if_fail(vec->n_ipv4 + vec->n_ipv6 > 0, NULL);

	vec_copy = wcopy(vec, sizeof *vec);
	if (vec->n_ipv4 > 0) {
		vec_copy->hvec_v4 = wcopy(vec->hvec_v4,
								vec->n_ipv4 * sizeof *vec->hvec_v4);
	}
	if (vec->n_ipv6 > 0) {
		vec_copy->hvec_v6 = wcopy(vec->hvec_v6,
								vec->n_ipv6 * sizeof *vec->hvec_v6);
	}
	return vec_copy;
}

void
gnet_host_vec_add(gnet_host_vec_t *vec, host_addr_t addr, guint16 port)
{
	g_return_if_fail(vec);

	switch (host_addr_net(addr)) {
	case NET_TYPE_IPV4:
		if (vec->n_ipv4 < 255) {
			gchar *dest;
			size_t size, old_size;
			
			old_size = vec->n_ipv4 * sizeof *vec->hvec_v4;
			vec->n_ipv4++;	
			size = vec->n_ipv4 * sizeof *vec->hvec_v4;
			vec->hvec_v4 = vec->hvec_v4
								? wrealloc(vec->hvec_v4, old_size, size)
								: walloc(size);
			dest = cast_to_gpointer(&vec->hvec_v4[vec->n_ipv4 - 1]);
			poke_be32(&dest[0], host_addr_ipv4(addr));
			poke_le16(&dest[4], port);
		}
		break;
	case NET_TYPE_IPV6:
		if (vec->n_ipv6 < 255) {
			gchar *dest;
			size_t size, old_size;
			
			old_size = vec->n_ipv6 * sizeof *vec->hvec_v6;
			vec->n_ipv6++;	
			size = vec->n_ipv6 * sizeof *vec->hvec_v6;
			vec->hvec_v6 = vec->hvec_v6
								? wrealloc(vec->hvec_v6, old_size, size)
								: walloc(size);
			dest = cast_to_gpointer(&vec->hvec_v6[vec->n_ipv6 - 1]);
			memcpy(dest, host_addr_ipv6(&addr), 16);
			poke_le16(&dest[16], port);
		}
		break;
	case NET_TYPE_LOCAL:
	case NET_TYPE_NONE:
		break;
	}
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
	host_addr_t addr;
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

	if (count >= quick_connect_pool_size) {
		if (dbg > 10) {
			g_message("host_timer - count %d >= pool size %d",
				count, quick_connect_pool_size);
		}
		return;
	}

	if (count < max_nodes)
		missing -= whitelist_connect();

	if (dbg > 10 && missing > 0)
		g_message("host_timer - missing %d host%s",
			missing, missing == 1 ? "" : "s");

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
				if (hcache_get_caught(htype, &addr, &port)) {
					node_add(addr, port, 0);
				}
			}

			if (missing > 0 && hcache_read_finished()) {
				if (!uhc_is_waiting()) {
					uhc_get_hosts();	/* Get from UDP pong caches */
				} else if (bootstrap_debug > 2)
					g_message("BOOT host_timer - waiting for reply from %s",
						uhc_is_waiting() ? "UDP host cache" : "web cache");
			}
		}

	} else if (use_netmasks) {
		/* Try to find better hosts */
		if (hcache_find_nearby(htype, &addr, &port)) {
			if (node_remove_worst(TRUE))
				node_add(addr, port, 0);
			else
				hcache_add_caught(htype, addr, port, "nearby host");
		}
	}
}

/***
 *** Hosts
 ***/

void
host_init(void)
{
	pcache_init();
}

/**
 * @return the address:port of a host
 */
const gchar *
gnet_host_to_string(const struct gnutella_host *h)
{
	static gchar buf[HOST_ADDR_PORT_BUFLEN];
	host_addr_t addr;
	guint16 port;

	packed_host_unpack(h->data, &addr, &port);
	host_addr_port_to_string_buf(addr, port, buf, sizeof buf);
	return buf;
}

/**
 * Check whether host is connectible.
 *
 * i.e. that it has a valid port and that its IP address is not private
 * not bogus.
 */
gboolean
host_is_valid(const host_addr_t addr, guint16 port)
{
	if (!port_is_valid(port))
		return FALSE;

	if (!host_addr_is_routable(addr))
		return FALSE;

	if (bogons_check(addr))
		return FALSE;

	return TRUE;
}

/**
 * Add a new host to our pong reserve.
 *
 * When `connect' is true, attempt to connect if we are low in Gnet links.
 */
void
host_add(const host_addr_t addr, guint16 port, gboolean do_connect)
{
	if (!hcache_add_caught(HOST_ANY, addr, port, "pong"))
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
				node_add(addr, port, 0);
		else {
			/* If we are above the max connections, delete a non-nearby
			 * connection before adding this better one
			 */
			if (use_netmasks && host_is_nearby(addr) && node_remove_worst(TRUE))
				node_add(addr, port, 0);
		}

	}
}

/**
 * Add a new host to our pong reserve, although the information here
 * does not come from a pong but from a Query Hit packet, hence the port
 * may be unsuitable for Gnet connections.
 */
void
host_add_semi_pong(const host_addr_t addr, guint16 port)
{
	g_assert(host_low_on_pongs);	/* Only used when low on pongs */

    hcache_add_caught(HOST_ANY, addr, port, "semi-pong");
}

/* ---------- Netmask heuristic by Mike Perry -------- */
struct network_pair
{
	guint32 mask;
	guint32 net;
};

struct network_pair *local_networks = NULL;
guint32 number_local_networks;

/**
 * frees the local networks array
 */
static void
free_networks(void)
{
	G_FREE_NULL(local_networks);
}

/**
 * Break the netmaks string and convert them into network_pair elements in
 * the local_networks array. IP's are in network order.
 */
void
parse_netmasks(const gchar *str)
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

	local_networks = g_malloc(i * sizeof *local_networks);

	for (i = 0; masks[i]; i++) {
		/* Network is of the form ip/mask or ip/bits */
		if ((p = strchr(masks[i], '/')) && *p) {
			*p++ = '\0';

			if (strchr(p, '.')) {
				/* get the network address from the user */
				if (!string_to_ip_strict(p, &local_networks[i].mask, NULL))
					g_warning("parse_netmasks(): Invalid netmask: \"%s\"", p);
			}
			else {
				gint error;

				mask_div = parse_uint32(p, NULL, 10, &error);
				mask_div = MIN(32, mask_div);
				if (error)
					g_warning("parse_netmasks(): "
						"Invalid CIDR prefixlen: \"%s\"", p);
				else
					local_networks[i].mask = (guint32) -1 << (32 - mask_div);
			}
		}
		else {
			/* Assume single-host */
			local_networks[i].mask = -1; /* 255.255.255.255 */
		}
		/* get the network address from the user */
		if (!string_to_ip_strict(masks[i], &local_networks[i].net, NULL))
			g_warning("parse_netmasks(): Invalid netmask: \"%s\"", masks[i]);
	}

	g_strfreev(masks);
}

/**
 * @returns true if the address is inside one of the local networks
 */
gboolean
host_is_nearby(const host_addr_t addr)
{
	guint i;

	if (NET_TYPE_IPV4 == host_addr_net(addr)) {
		for (i = 0; i < number_local_networks; i++) {
			guint32 m_mask = local_networks[i].mask;
			guint32 m_ip = local_networks[i].net;

			if ((host_addr_ipv4(addr) & m_mask) == (m_ip & m_mask))
				return TRUE;
		}
	} else if (NET_TYPE_IPV6 == host_addr_net(addr)) {
		/* XXX: Implement this! */
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

