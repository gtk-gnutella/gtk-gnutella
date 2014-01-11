/*
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

#include "hosts.h"
#include "bogons.h"
#include "gmsg.h"
#include "hostiles.h"
#include "nodes.h"
#include "pcache.h"
#include "routing.h"
#include "settings.h"
#include "share.h"			/* For files_scanned and kbytes_scanned. */
#include "sockets.h"
#include "udp.h"
#include "uhc.h"
#include "whitelist.h"

#include "if/gnet_property_priv.h"
#include "if/dht/dht.h"		/* For dht_fill_random() */

#include "lib/aging.h"
#include "lib/endian.h"
#include "lib/glib-missing.h"
#include "lib/parse.h"
#include "lib/stringify.h"
#include "lib/tm.h"
#include "lib/walloc.h"
#include "lib/xmalloc.h"

#include "lib/override.h"	/* Must be the last header included */

#define HOST_PINGING_PERIOD		30		/**< Try pinging every 30 seconds */
#define HOST_DHT_MAX			50		/**< Get that many random hosts */
#define HOST_CONNECT_FREQ		120		/**< At most 1 connection per 2 mins */

bool host_low_on_pongs = FALSE;		/**< True when less than 12% full */

static bool in_shutdown = FALSE;
static aging_table_t *node_connects;

/*
 * Avoid nodes being stuck helplessly due to completely stale caches.
 * @return TRUE if an UHC may be contact, FALSE if it's not permissable.
 */
static bool
host_cache_allow_bypass(void)
{
	static time_t last_try;

	if (node_count() > 0)
		return FALSE;

	/* Wait at least 2 minutes after starting up */
	if (delta_time(tm_time(), GNET_PROPERTY(start_stamp)) < 2 * 60)
		return FALSE;

	/*
	 * Allow again after 12 hours, useful after unexpected network outage
	 * or downtime.
	 */

	if (last_try && delta_time(tm_time(), last_try) < 12 * 3600)
		return FALSE;

	last_try = tm_time();
	return TRUE;
}

/**
 * Attempt Gnutella host connection.
 * @return TRUE if OK, FALSE if attempt was throttled
 */
static bool
host_gnutella_connect(host_addr_t addr, uint16 port)
{
	if (aging_lookup(node_connects, &addr))
		return FALSE;

	node_add_socket(NULL, addr, port, 0);
	aging_insert(node_connects, wcopy(&addr, sizeof addr), GUINT_TO_POINTER(1));

	return TRUE;
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
    uint count;
	int missing;
	host_addr_t addr;
	uint16 port;
	host_type_t htype;
	uint max_nodes;
	bool empty_cache = FALSE;

	if (in_shutdown || !GNET_PROPERTY(online_mode))
		return;

	max_nodes = settings_is_leaf() ?
		GNET_PROPERTY(max_ultrapeers) : GNET_PROPERTY(max_connections);
	count = node_count();			/* Established + connecting */
	missing = node_keep_missing();

	if (GNET_PROPERTY(host_debug) > 1)
		g_debug("host_timer - count %u, missing %u", count, missing);

	/*
	 * If we are not connected to the Internet, apparently, make sure to
	 * connect to at most one host, to avoid using all our hostcache.
	 * Also, we don't connect each time we are called.
	 */

	if (!GNET_PROPERTY(is_inet_connected)) {
		static time_t last_try;

		if (last_try && delta_time(tm_time(), last_try) < 20)
			return;
		last_try = tm_time();

		if (GNET_PROPERTY(host_debug))
			g_debug("host_timer - not connected, trying to connect");
	}

	/*
	 * Allow more outgoing connections than the maximum amount of
	 * established Gnet connection we can maintain, but not more
	 * than quick_connect_pool_size   This is the "greedy mode".
	 */

	if (count >= GNET_PROPERTY(quick_connect_pool_size)) {
		if (GNET_PROPERTY(host_debug) > 1)
			g_debug("host_timer - count %u >= pool size %u",
				count, GNET_PROPERTY(quick_connect_pool_size));
		return;
	}

	if (count < max_nodes)
		missing -= whitelist_connect();

	/*
	 * If we are under the number of connections wanted, we add hosts
	 * to the connection list
	 */

	htype = HOST_ULTRA;

	if (
        settings_is_ultra() &&
        GNET_PROPERTY(node_normal_count) < GNET_PROPERTY(normal_connections) &&
        GNET_PROPERTY(node_ultra_count) >=
			(GNET_PROPERTY(up_connections) - GNET_PROPERTY(normal_connections))
	) {
		htype = HOST_ANY;
    }

	if (hcache_size(htype) == 0)
		htype = HOST_ANY;

	if (hcache_size(htype) == 0)
		empty_cache = TRUE;

	if (GNET_PROPERTY(host_debug) && missing > 0)
		g_debug("host_timer - missing %d host%s%s",
			missing, plural(missing), empty_cache ? " [empty caches]" : "");

    if (!GNET_PROPERTY(stop_host_get)) {
        if (missing > 0) {
			static time_t last_try;
            unsigned fan, max_pool, to_add;

            max_pool = MAX(GNET_PROPERTY(quick_connect_pool_size), max_nodes);
            fan = (missing * GNET_PROPERTY(quick_connect_pool_size))/ max_pool;
			fan = MAX(1, fan);
            to_add = GNET_PROPERTY(is_inet_connected) ? fan : (uint) missing;

			/*
			 * Every so many calls, attempt to ping all our neighbours to
			 * get fresh pongs, in case our host cache is not containing
			 * sufficiently fresh hosts and we keep getting connection failures.
			 */

			if (
				0 == last_try ||
				delta_time(tm_time(), last_try) >= HOST_PINGING_PERIOD
			) {
				ping_all_neighbours();
				last_try = tm_time();
			}

            /*
             * Make sure that we never use more connections then the
             * quick pool or the maximum number of hosts allow.
             */
            if (to_add + count > max_pool)
                to_add = max_pool - count;

            if (GNET_PROPERTY(host_debug) > 2) {
                g_debug("host_timer - connecting - "
					"add: %d fan:%d miss:%d max_hosts:%d count:%d extra:%d",
					 to_add, fan, missing, max_nodes, count,
					 GNET_PROPERTY(quick_connect_pool_size));
            }

            missing = to_add;

			if (missing > 0 && (0 == connected_nodes() || host_low_on_pongs)) {
				gnet_host_t host[HOST_DHT_MAX];
				int hcount;
				int i;

				hcount = dht_fill_random(host,
					MIN(UNSIGNED(missing), G_N_ELEMENTS(host)));

				missing -= hcount;

				for (i = 0; i < hcount; i++) {
					addr = gnet_host_get_addr(&host[i]);
					port = gnet_host_get_port(&host[i]);
					if (!hcache_node_is_bad(addr)) {
						if (GNET_PROPERTY(host_debug) > 3) {
							g_debug("host_timer - UHC pinging and connecting "
								"to DHT node at %s",
								host_addr_port_to_string(addr, port));
						}
						/* Try to use the host as an UHC before connecting */
						udp_send_ping(NULL, addr, port, TRUE);
						if (!host_gnutella_connect(addr, port)) {
							missing++;	/* Did not use entry */
						}
					} else {
						missing++;	/* Did not use entry */
					}
				}
			}

			while (hcache_size(htype) && missing-- > 0) {
				if (hcache_get_caught(htype, &addr, &port)) {
					if (!(hostiles_is_bad(addr) || hcache_node_is_bad(addr))) {
						if (!host_gnutella_connect(addr, port)) {
							missing++;	/* Did not use entry */
						}
					} else {
						missing++;	/* Did not use entry */
					}
				}
			}

			if (missing > 0 && (empty_cache || host_cache_allow_bypass())) {
				if (!uhc_is_waiting()) {
					if (GNET_PROPERTY(host_debug))
						g_debug("host_timer - querying UDP host cache");
					uhc_get_hosts();	/* Get new hosts from UHCs */
				}
			}
		}

	} else if (GNET_PROPERTY(use_netmasks)) {
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
	node_connects = aging_make(HOST_CONNECT_FREQ,
		host_addr_hash_func, host_addr_eq_func, wfree_host_addr);
}

/**
 * Check whether host's address is usable: routable and not bogus.
 */
bool
host_address_is_usable(const host_addr_t addr)
{
	if (!host_addr_is_routable(addr))
		return FALSE;

	if (bogons_check(addr))
		return FALSE;

	return TRUE;
}

/**
 * Check whether host is connectible.
 *
 * i.e. that it has a valid port and that its IP address is not private
 * nor bogus.
 */
bool
host_is_valid(const host_addr_t addr, uint16 port)
{
	if (!port_is_valid(port))
		return FALSE;

	return host_address_is_usable(addr);
}

/**
 * Add a new host to our pong reserve.
 *
 * When `connect' is true, attempt to connect if we are low in Gnet links.
 */
void
host_add(const host_addr_t addr, uint16 port, bool do_connect)
{
	if (!do_connect || !hcache_add_caught(HOST_ANY, addr, port, "pong"))
		return;

	/*
	 * If we are under the number of connections wanted, we add this host
	 * to the connection list.
	 */


	if (node_keep_missing() > 0)
		node_add(addr, port, 0);
	else if (
		GNET_PROPERTY(use_netmasks) &&
		host_is_nearby(addr) &&
		node_remove_worst(TRUE)
	) {
		/*
		 * If we are above the max connections, delete a non-nearby
		 * connection before adding this better one
		 */
		node_add(addr, port, 0);
	}
}

/**
 * Add a new host to our pong reserve, although the information here
 * does not come from a pong but from a Query Hit packet, hence the port
 * may be unsuitable for Gnet connections.
 */
void
host_add_semi_pong(const host_addr_t addr, uint16 port)
{
	g_assert(host_low_on_pongs);	/* Only used when low on pongs */

    hcache_add_caught(HOST_ANY, addr, port, "semi-pong");
}

/* ---------- Netmask heuristic by Mike Perry -------- */
struct network_pair
{
	uint32 mask;
	uint32 net;
};

struct network_pair *local_networks = NULL;
uint32 number_local_networks;

/**
 * frees the local networks array
 */
static void
free_networks(void)
{
	XFREE_NULL(local_networks);
}

/**
 * Break the netmaks string and convert them into network_pair elements in
 * the local_networks array. IP's are in network order.
 */
void
parse_netmasks(const char *str)
{
	char **masks = g_strsplit(str, ";", 0);
	char *p;
	uint32 mask_div;
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

	XMALLOC_ARRAY(local_networks, i);

	for (i = 0; masks[i]; i++) {
		/* Network is of the form ip/mask or ip/bits */
		if ((p = strchr(masks[i], '/')) && *p) {
			*p++ = '\0';

			if (strchr(p, '.')) {
				/* get the network address from the user */
				if (!string_to_ip_strict(p, &local_networks[i].mask, NULL))
					g_warning("%s(): invalid netmask: \"%s\"", G_STRFUNC, p);
			}
			else {
				int error;

				mask_div = parse_uint32(p, NULL, 10, &error);
				mask_div = MIN(32, mask_div);
				if (error)
					g_warning("%s(): invalid CIDR prefixlen: \"%s\"",
						G_STRFUNC, p);
				else
					local_networks[i].mask = (uint32) -1 << (32 - mask_div);
			}
		}
		else {
			/* Assume single-host */
			local_networks[i].mask = -1; /* 255.255.255.255 */
		}
		/* get the network address from the user */
		if (!string_to_ip_strict(masks[i], &local_networks[i].net, NULL))
			g_warning("%s(): invalid netmask: \"%s\"", G_STRFUNC, masks[i]);
	}

	g_strfreev(masks);
}

/**
 * @returns true if the address is inside one of the local networks
 */
bool
host_is_nearby(const host_addr_t addr)
{
	uint i;

	if (host_addr_is_ipv4(addr)) {
		for (i = 0; i < number_local_networks; i++) {
			uint32 m_mask = local_networks[i].mask;
			uint32 m_ip = local_networks[i].net;

			if ((host_addr_ipv4(addr) & m_mask) == (m_ip & m_mask))
				return TRUE;
		}
	} else if (host_addr_is_ipv6(addr)) {
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
	aging_destroy(&node_connects);
}

/* vi: set ts=4 sw=4 cindent: */

