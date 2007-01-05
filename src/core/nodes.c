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
 * Gnutella node management.
 *
 * @author Raphael Manfredi
 * @date 2001-2004
 */

#include "common.h"

RCSID("$Id$")

#include <zlib.h>	/* Z_DEFAULT_COMPRESSION, Z_OK */

#include "sockets.h"
#include "search.h"
#include "share.h"
#include "routing.h"
#include "hosts.h"
#include "nodes.h"
#include "gmsg.h"
#include "mq.h"
#include "mq_tcp.h"
#include "mq_udp.h"
#include "sq.h"
#include "tx.h"
#include "tx_link.h"
#include "tx_deflate.h"
#include "tx_dgram.h"
#include "rxbuf.h"
#include "rx.h"
#include "rx_link.h"
#include "rx_inflate.h"
#include "pmsg.h"
#include "pcache.h"
#include "bsched.h"
#include "http.h"
#include "version.h"
#include "alive.h"
#include "uploads.h"			/* For handle_push_request() */
#include "whitelist.h"
#include "gnet_stats.h"
#include "ban.h"
#include "hcache.h"
#include "qrp.h"
#include "vmsg.h"
#include "token.h"
#include "hostiles.h"
#include "clock.h"
#include "hsep.h"
#include "dq.h"
#include "dh.h"
#include "ioheader.h"
#include "settings.h"
#include "features.h"
#include "udp.h"
#include "tsync.h"
#include "geo_ip.h"
#include "extensions.h"
#include "bh_upload.h"
#include "tls_cache.h"

#include "lib/adns.h"
#include "lib/aging.h"
#include "lib/atoms.h"
#include "lib/cq.h"
#include "lib/dbus_util.h"
#include "lib/getdate.h"
#include "lib/hashlist.h"
#include "lib/endian.h"
#include "lib/getline.h"
#include "lib/glib-missing.h"
#include "lib/header.h"
#include "lib/idtable.h"
#include "lib/listener.h"
#include "lib/misc.h"
#include "lib/tm.h"
#include "lib/utf8.h"
#include "lib/walloc.h"
#include "lib/zlib_util.h"

#include "if/gnet_property.h"
#include "if/gnet_property_priv.h"

#include "lib/override.h"		/* Must be the last header included */

#define CONNECT_PONGS_COUNT		10	  /**< Amoung of pongs to send */
#define CONNECT_PONGS_LOW		5	  /**< Amoung of pongs sent if saturated */
#define BYE_MAX_SIZE			4096  /**< Maximum size for the Bye message */
#define NODE_SEND_BUFSIZE		4096  /**< TCP send buffer size - 4K */
#define NODE_SEND_LEAF_BUFSIZE	1024  /**< TCP send buffer size for leaves */
#define MAX_GGEP_PAYLOAD		1536  /**< In ping, pong, push */
#define MAX_HOP_COUNT			255	  /**< Architecturally defined maximum */
#define NODE_LEGACY_DEGREE		8	  /**< Older node without X-Degree */
#define NODE_LEGACY_TTL			7	  /**< Older node without X-Max-TTL */
#define NODE_USELESS_GRACE		20	  /**< No kick if condition too recent */
#define NODE_UP_USELESS_GRACE	600	  /**< No kick if condition too recent */

#define SHUTDOWN_GRACE_DELAY	120	  /**< Grace time for shutdowning nodes */
#define BYE_GRACE_DELAY			30	  /**< Bye sent, give time to propagate */
#define MAX_WEIRD_MSG			5	  /**< End link after so much weirds */
#define MAX_TX_RX_RATIO			70	  /**< Max TX/RX ratio for shortage */
#define MIN_TX_FOR_RATIO		500	  /**< TX packets before enforcing ratio */
#define ALIVE_PERIOD			20	  /**< Seconds between each alive ping */
#define ALIVE_PERIOD_LEAF		120	  /**< Idem, for leaves <-> ultrapeers */
#define ALIVE_MAX_PENDING		6	  /**< Max unanswered pings in a row */
#define ALIVE_MAX_PENDING_LEAF	4 /**< Max unanswered pings in a row (leaves) */

#define NODE_MIN_UP_CONNECTIONS	25	   /**< Min 25 peer connections for UP */
#define NODE_MIN_UPTIME			3600   /**< Minumum uptime to become an UP */
#define NODE_MIN_AVG_UPTIME		10800  /**< Average uptime to become an UP */
#define NODE_AVG_LEAF_MEM		262144 /**< Average memory used by leaf */
#define NODE_CASUAL_FD			10	   /**< # of fds we might use casually */
#define NODE_UPLOAD_QUEUE_FD	5	   /**< # of fds/upload slot we can queue */

#define NODE_TX_BUFSIZ			1024	/**< Buffer size for TX deflation */
#define NODE_TX_FLUSH			16384	/**< Flush deflator every 16K */

#define NODE_AUTO_SWITCH_MIN	1800	/**< Don't switch too often UP - leaf */
#define NODE_AUTO_SWITCH_MAX	61200	/**< Max between switches (17 hours) */
#define NODE_UP_NO_LEAF_MAX		3600	/**< Don't remain UP if no leaves */

#define NODE_TSYNC_WAIT_MS		5000	/**< Wait time after connecting (5s) */
#define NODE_TSYNC_PERIOD_MS	300000	/**< Synchronize every 5 minutes */
#define NODE_TSYNC_CHECK		15		/**< 15 secs before a timeout */

#define TCP_CRAWLER_FREQ		300		/**< once every 5 minutes */
#define UDP_CRAWLER_FREQ		120		/**< once every 2 minutes */

const gchar *start_rfc822_date = NULL;		/**< RFC822 format of start_time */

static GSList *sl_nodes = NULL;
static GSList *sl_nodes_without_broken_gtkg = NULL;
static GHashTable *nodes_by_id = NULL;
static gnutella_node_t *udp_node = NULL;
static gnutella_node_t *udp6_node = NULL;
static gnutella_node_t *browse_node = NULL;
static gchar *payload_inflate_buffer = NULL;
static gint payload_inflate_buffer_len = 0;

/* These two contain connected and connectING(!) nodes. */
static GHashTable *ht_connected_nodes   = NULL;
static guint32     connected_node_count = 0;

#define NO_METADATA		GUINT_TO_POINTER(1)	/**< No metadata for host */

static GHashTable *unstable_servent = NULL;
static GSList *unstable_servents = NULL;

static gpointer tcp_crawls = NULL;
static gpointer udp_crawls = NULL;

typedef struct node_bad_client {
	const char *vendor;
	int	errors;
} node_bad_client_t;

static int node_error_threshold = 6;	/**< This requires an average uptime of
										     1 hour for an ultrapeer */
static time_t node_error_cleanup_timer = 6 * 3600;	/**< 6 hours */

static GSList *sl_proxies = NULL;	/* Our push proxies */
static idtable_t *node_handle_map = NULL;

static inline gnutella_node_t *
node_find_by_handle(gnet_node_t n)
{
	return idtable_get_value(node_handle_map, n);
}

static inline gnet_node_t
node_request_handle(gnutella_node_t *n) 
{
    return idtable_new_id(node_handle_map, n);
}

static inline void
node_drop_handle(gnet_node_t n)
{
    idtable_free_id(node_handle_map, n);
}

static guint32 shutdown_nodes = 0;
static guint32 node_id = 0;

static gboolean allow_gnet_connections = FALSE;

GHookList node_added_hook_list;

/**
 * For use by node_added_hook_list hooks, since we can't add a parameter
 * at list invoke time.
 */
struct gnutella_node *node_added;

/**
 * Structure used for asynchronous reaction to peer mode changes.
 */
static struct {
	gboolean changed;
	node_peer_t new;
} peermode = { FALSE, NODE_P_UNKNOWN };

/**
 * Types of bad nodes for node_is_bad().
 */
enum node_bad {
	NODE_BAD_OK = 0,		/**< Node is fine */
	NODE_BAD_IP,			/**< Node has a bad (unstable) IP */
	NODE_BAD_VENDOR,		/**< Node has a bad vendor string */
	NODE_BAD_NO_VENDOR		/**< Node has no vendor string */
};

static guint connected_node_cnt = 0;
static guint compressed_node_cnt = 0;
static guint compressed_leaf_cnt = 0;
static gint pending_byes = 0;			/* Used when shutdowning servent */
static gboolean in_shutdown = FALSE;
static guint32 leaf_to_up_switch = NODE_AUTO_SWITCH_MIN;
static time_t no_leaves_connected = 0;

static const gchar no_reason[] = "<no reason>"; /* Don't translate this */

static query_hashvec_t *query_hashvec = NULL;

static void node_disable_read(struct gnutella_node *n);
static gboolean node_data_ind(rxdrv_t *rx, pmsg_t *mb);
static void node_bye_sent(struct gnutella_node *n);
static void call_node_process_handshake_ack(gpointer obj, header_t *header);
static void node_send_qrt(struct gnutella_node *n, gpointer query_table);
static void node_send_patch_step(struct gnutella_node *n);
static void node_bye_flags(guint32 mask, gint code, const gchar *message);
static void node_bye_all_but_one(struct gnutella_node *nskip,
				gint code, const gchar *message);
static void node_set_current_peermode(node_peer_t mode);
static enum node_bad node_is_bad(struct gnutella_node *n);
static gnutella_node_t *node_udp_create(enum net_type net);
static gnutella_node_t *node_browse_create(void);
static gboolean node_remove_useless_leaf(gboolean *is_gtkg);
static gboolean node_remove_useless_ultra(gboolean *is_gtkg);

/***
 *** Callbacks
 ***/

static listeners_t node_added_listeners   = NULL;
static listeners_t node_removed_listeners = NULL;
static listeners_t node_info_changed_listeners = NULL;
static listeners_t node_flags_changed_listeners = NULL;

void
node_add_node_added_listener(node_added_listener_t l)
{
    LISTENER_ADD(node_added, l);
}

void
node_remove_node_added_listener(node_added_listener_t l)
{
    LISTENER_REMOVE(node_added, l);
}

void
node_add_node_removed_listener(node_removed_listener_t l)
{
    LISTENER_ADD(node_removed, l);
}

void
node_remove_node_removed_listener(node_removed_listener_t l)
{
    LISTENER_REMOVE(node_removed, l);
}

void
node_add_node_info_changed_listener(node_info_changed_listener_t l)
{
    LISTENER_ADD(node_info_changed, l);
}

void
node_remove_node_info_changed_listener(node_info_changed_listener_t l)
{
    LISTENER_REMOVE(node_info_changed, l);
}

void
node_add_node_flags_changed_listener(node_flags_changed_listener_t l)
{
    LISTENER_ADD(node_flags_changed, l);
}

void
node_remove_node_flags_changed_listener(node_flags_changed_listener_t l)
{
    LISTENER_REMOVE(node_flags_changed, l);
}

static void
node_fire_node_added(gnutella_node_t *n)
{
    n->last_update = tm_time();
    LISTENER_EMIT(node_added, (n->node_handle));
}

static void
node_fire_node_removed(gnutella_node_t *n)
{
    n->last_update = tm_time();
    LISTENER_EMIT(node_removed, (n->node_handle));
}

static void
node_fire_node_info_changed(gnutella_node_t *n)
{
    LISTENER_EMIT(node_info_changed, (n->node_handle));
}

static void
node_fire_node_flags_changed(gnutella_node_t *n)
{
    LISTENER_EMIT(node_flags_changed, (n->node_handle));
}

/***
 *** Utilities
 ***/

/**
 * Free atom string key from hash table.
 */
static void
free_key(gpointer key, gpointer unused_val, gpointer unused_x)
{
	(void) unused_val;
	(void) unused_x;
	atom_str_free(key);
}

/**
 * Free atom string key from hash table and return TRUE.
 */
static gboolean
free_key_true(gpointer key, gpointer unused_val, gpointer unused_x)
{
	(void) unused_val;
	(void) unused_x;
	atom_str_free(key);
	return TRUE;
}

/**
 * Clear hash table whose keys are atoms and values ignored.
 */
static void
string_table_clear(GHashTable *ht)
{
	g_assert(ht != NULL);

	g_hash_table_foreach_remove(ht, free_key_true, NULL);
}

/**
 * Dispose of hash table whose keys are atoms and values ignored.
 */
static void
string_table_free(GHashTable *ht)
{
	g_assert(ht != NULL);

	g_hash_table_foreach(ht, free_key, NULL);
	g_hash_table_destroy(ht);
}

/***
 *** Time Sync operations.
 ***/

/**
 * Send "Time Sync" via UDP if we know the remote IP:port, via TCP otherwise.
 */
static void
node_tsync_udp(cqueue_t *unused_cq, gpointer obj)
{
	gnutella_node_t *n = obj;
	gnutella_node_t *udp = NULL, *tn;

	(void) unused_cq;
	g_assert(!NODE_IS_UDP(n));
	g_assert(n->attrs & NODE_A_TIME_SYNC);

	n->tsync_ev = NULL;	/* has been freed before calling this function */

	/*
	 * If we did not get replies within the reasonable time period, we
	 * marked the node with NODE_F_TSYNC_TCP to use TCP instead of UDP.
	 */

	if (
		!(n->flags & NODE_F_TSYNC_TCP) &&
		is_host_addr(n->gnet_addr)
	)
		udp = node_udp_get_addr_port(n->gnet_addr, n->gnet_port);

	tn = (udp && udp->outq) ? udp : n;
	if (!host_is_valid(tn->addr, tn->port))
		return;

	tsync_send(tn, n->id);

	/*
	 * Next sync will occur in NODE_TSYNC_PERIOD_MS milliseconds.
	 */

	n->tsync_ev =
		cq_insert(callout_queue, NODE_TSYNC_PERIOD_MS, node_tsync_udp, n);
}

/**
 * Invoked when we determined that the node supports Time Sync.
 */
void
node_can_tsync(gnutella_node_t *n)
{
	g_assert(!NODE_IS_UDP(n));

	if (n->attrs & NODE_A_TIME_SYNC)
		return;

	n->attrs |= NODE_A_TIME_SYNC;

	/*
	 * Schedule a time sync in NODE_TSYNC_WAIT_MS milliseconds.
	 */

	n->tsync_ev =
		cq_insert(callout_queue, NODE_TSYNC_WAIT_MS, node_tsync_udp, n);
}

/**
 * Sent "probe" time sync via TCP to the specified node to compute the RTT...
 */
static void
node_tsync_tcp(gnutella_node_t *n)
{
	g_assert(!NODE_IS_UDP(n));
	g_assert(n->attrs & NODE_A_TIME_SYNC);

	tsync_send(n, n->id);
}

/***
 *** Private functions
 ***/

/**
 * Check whether we already have the host.
 */
static gboolean
node_ht_connected_nodes_has(const host_addr_t addr, guint16 port)
{
	gnet_host_t  host;

	gnet_host_set(&host, addr, port);
	return NULL != g_hash_table_lookup(ht_connected_nodes, &host);
}

/**
 * Check whether we already have the host.
 */
static gnet_host_t *
node_ht_connected_nodes_find(const host_addr_t addr, guint16 port)
{
	gnet_host_t  host;
    gboolean     found;
    gpointer	 orig_host, metadata;

	gnet_host_set(&host, addr, port);
	found = g_hash_table_lookup_extended(ht_connected_nodes, &host,
				&orig_host, &metadata);

    return found ? orig_host : NULL;
}

/**
 * Add host to the hash table host cache.
 */
static void
node_ht_connected_nodes_add(const host_addr_t addr, guint16 port)
{
    gnet_host_t *host;

    if (node_ht_connected_nodes_has(addr, port))
        return;

 	host = walloc(sizeof *host);
	gnet_host_set(host, addr, port);
	g_hash_table_insert(ht_connected_nodes, host, NO_METADATA);
	connected_node_count++;
}

/**
 * Remove host from the hash table host cache.
 */
static void
node_ht_connected_nodes_remove(const host_addr_t addr, guint16 port)
{
    gnet_host_t *orig_host;

    orig_host = node_ht_connected_nodes_find(addr, port);

    if (orig_host) {
		g_hash_table_remove(ht_connected_nodes, orig_host);
		g_assert(connected_node_count > 0);
		connected_node_count--;

		wfree(orig_host, sizeof *orig_host);
	}
}

/**
 * Dumps a gnutella message (debug).
 */
static void
message_dump(const struct gnutella_node *n)
{
	printf("Node %s: ", node_addr(n));
	printf("Func 0x%.2x ", gnutella_header_get_function(&n->header));
	printf("TTL = %u ", gnutella_header_get_ttl(&n->header));
	printf("hops = %u ", gnutella_header_get_hops(&n->header));

	printf(" data = %u", (guint) gmsg_size(&n->header));

	switch (gnutella_header_get_function(&n->header)) {
	case GTA_MSG_INIT_RESPONSE:
		{
			guint32 ip, count, total;
			guint16 port;

			port = peek_le16(n->data);
			ip = peek_be32(n->data + 2);
			count = peek_le32(n->data + 6);
			total = peek_le32(n->data + 10);

			printf(" Host = %s Port = %u Count = %u Total = %u",
					ip_to_string(ip), port, count, total);
		}
		break;
	case GTA_MSG_PUSH_REQUEST:
		{
			guint32 ip, idx;
			guint16 port;

			idx = peek_le32(n->data + 16);
			ip = peek_be32(n->data + 20);
			port = peek_le16(n->data + 24);

			printf(" Index = %u Host = %s Port = %u ", idx, ip_to_string(ip),
					port);
		}
		break;
	}

	printf("\n");
}

/**
 * Check whether node is a gtk-gnutella node.
 */
static gboolean
node_is_gtkg(const struct gnutella_node *n)
{
	return n->vendor && is_strprefix(n->vendor, "gtk-gnutella/");
}

/**
 * Extract IP/port information out of the Query Hit into `ip' and `port'.
 */
static void
node_extract_host(const struct gnutella_node *n,
	host_addr_t *ha, guint16 *port)
{
	/* Read Query Hit info */

	*ha = host_addr_get_ipv4(gnutella_search_results_get_host_ip(n->data));
	*port = gnutella_search_results_get_host_port(n->data);
}

/**
 * Check the Ultrapeer requirements, returning TRUE if we can become an UP.
 */
static gboolean
can_become_ultra(time_t now)
{
	gboolean avg_servent_uptime;
	gboolean avg_ip_uptime;
	gboolean node_uptime;
	gboolean not_firewalled;
	gboolean good_udp_support;
	gboolean enough_conn;
	gboolean enough_fd;
	gboolean enough_mem;
	gboolean enough_bw;
	const gchar *ok = "** OK **";
	const gchar *no = "-- NO --";

	/* Uptime requirements */
	avg_servent_uptime = get_average_servent_uptime(now) >= NODE_MIN_AVG_UPTIME;
	avg_ip_uptime =
		get_average_ip_lifetime(now, NET_TYPE_IPV4) >= NODE_MIN_AVG_UPTIME ||
		get_average_ip_lifetime(now, NET_TYPE_IPV6) >= NODE_MIN_AVG_UPTIME;
	node_uptime = delta_time(now, start_stamp) > NODE_MIN_UPTIME;

	/* Connectivity requirements */
	not_firewalled = !is_firewalled && !is_udp_firewalled;

	/*
	 * Require proper UDP support to be enabled. An efficient UP must be
	 * able to perform OOB-proxying of queries from firewalled leaves, lest
	 * the query hits will have to be routed back on the Gnutella network.
	 *		--RAM, 2006-08-18
	 */

	good_udp_support = udp_active() &&
		host_is_valid(listen_addr(), socket_listen_port()) &&
		proxy_oob_queries;

	/*
	 * System requirements
	 *
	 * We don't count all the banned fd, since we can now steal the necessary
	 * descriptors out of the banned pool if we run short of fd.  We need to
	 * provision for possible PARQ active queuing, which is why we scale the
	 * `max_uploads' parameter.
	 *
	 * Likewise, we assume that at most 1/4th of the downloads will actually
	 * be active at one time (meaning one fd for the connection and one fd
	 * for the file being written to).  We count "max_uploads" twice because
	 * those have one also two fd (for the connection and the file).
	 */

	enough_fd = (max_leaves + max_connections
			+ max_downloads + (max_downloads / 4)
			+ (max_uploads * (1 + NODE_UPLOAD_QUEUE_FD)) + max_uploads
			+ (max_banned_fd / 10) + NODE_CASUAL_FD) < sys_nofile;
	enough_mem = (max_leaves * NODE_AVG_LEAF_MEM +
		(max_leaves + max_connections) * node_sendqueue_size)
		< 1024 / 2 * sys_physmem;

	/* Bandwidth requirements */
	enough_bw = bsched_enough_up_bandwidth() && !uploads_stalling;

	/* Connection requirements */
	enough_conn = up_connections >= NODE_MIN_UP_CONNECTIONS;

#define OK(b)	((b) ? ok : no)

	if (node_debug > 3) {
		g_message("Checking Ultrapeer criteria:");
		g_message("> Sufficient average uptime   : %s", OK(avg_servent_uptime));
		g_message("> Sufficient IP address uptime: %s", OK(avg_ip_uptime));
		g_message("> Sufficient node uptime      : %s", OK(node_uptime));
		g_message("> Node not firewalled         : %s", OK(not_firewalled));
		g_message("> Enough min peer connections : %s", OK(enough_conn));
		g_message("> Enough file descriptors     : %s", OK(enough_fd));
		g_message("> Enough physical memory      : %s", OK(enough_mem));
		g_message("> Enough available bandwidth  : %s", OK(enough_bw));
		g_message("> Good UDP support            : %s", OK(good_udp_support));
	}

#undef OK

	/*
	 * Let them see the results of our checks in the GUI.
	 */

	gnet_prop_set_boolean_val(PROP_UP_REQ_AVG_SERVENT_UPTIME,
                                                          avg_servent_uptime);
	gnet_prop_set_boolean_val(PROP_UP_REQ_AVG_IP_UPTIME,  avg_ip_uptime);
	gnet_prop_set_boolean_val(PROP_UP_REQ_NODE_UPTIME,    node_uptime);
	gnet_prop_set_boolean_val(PROP_UP_REQ_NOT_FIREWALLED, not_firewalled);
	gnet_prop_set_boolean_val(PROP_UP_REQ_ENOUGH_CONN,    enough_conn);
	gnet_prop_set_boolean_val(PROP_UP_REQ_ENOUGH_FD,      enough_fd);
	gnet_prop_set_boolean_val(PROP_UP_REQ_ENOUGH_MEM,     enough_mem);
	gnet_prop_set_boolean_val(PROP_UP_REQ_ENOUGH_BW,      enough_bw);
	gnet_prop_set_boolean_val(PROP_UP_REQ_GOOD_UDP,       good_udp_support);
	gnet_prop_set_timestamp_val(PROP_NODE_LAST_ULTRA_CHECK, now);

	return avg_servent_uptime && avg_ip_uptime && node_uptime &&
		not_firewalled && enough_fd && enough_mem && enough_bw &&
		good_udp_support &&
		!ancient_version;		/* Old versions don't become ultra nodes */
}

/**
 * Low frequency node timer.
 */
void
node_slow_timer(time_t now)
{
	time_t last_switch = node_last_ultra_leaf_switch;	/* Property */

	/*
	 * Clear `no_leaves_connected' if we have something connected, or
	 * record the first time at which we came here with no leaf connected.
	 */

	if (current_peermode == NODE_P_ULTRA) {
		if (node_leaf_count)
			no_leaves_connected = 0;
		else if (no_leaves_connected == 0)
			no_leaves_connected = now;
	} else
		no_leaves_connected = 0;

	/*
	 * If we're in "auto" mode and we're still running as a leaf node,
	 * evaluate our ability to become an ultra node.
	 *
	 * NB: we test for configured_peermode == NODE_P_ULTRA because we
	 * can switch to leaf even when the user wants to be an ultra node
	 * when we make a very bad ultra peer and it is best for the network
	 * that we be a leaf node.
	 */

	if (
		(configured_peermode == NODE_P_AUTO ||
			configured_peermode == NODE_P_ULTRA) &&
		current_peermode == NODE_P_LEAF &&
		delta_time(now, last_switch) > (time_delta_t) leaf_to_up_switch &&
		can_become_ultra(now)
	) {
		g_warning("being promoted to Ultrapeer status");
		gnet_prop_set_guint32_val(PROP_CURRENT_PEERMODE, NODE_P_ULTRA);
		gnet_prop_set_timestamp_val(PROP_NODE_LAST_ULTRA_LEAF_SWITCH, now);
		return;
	}

	/*
	 * If we're in "auto" mode and we've been promoted to an ultra node,
	 * evaluate how good we are and whether we would not be better off
	 * running as a leaf node.
	 *
	 * We double the time we'll spend as a leaf node before switching
	 * again to UP mode to avoid endless switches between UP and leaf.
	 * We limit that doubling to NODE_AUTO_SWITCH_MAX, to ensure that if
	 * we can become one, then we should do so on a regular basis.
	 */

	if (
		configured_peermode == NODE_P_AUTO &&
		current_peermode == NODE_P_ULTRA &&
		delta_time(now, last_switch) > NODE_AUTO_SWITCH_MIN &&
		!can_become_ultra(now)
	) {
		leaf_to_up_switch *= 2;
		leaf_to_up_switch = MIN(leaf_to_up_switch, NODE_AUTO_SWITCH_MAX);
		g_warning("being demoted from Ultrapeer status (for %u secs)",
			leaf_to_up_switch);
		gnet_prop_set_guint32_val(PROP_CURRENT_PEERMODE, NODE_P_LEAF);
		gnet_prop_set_timestamp_val(PROP_NODE_LAST_ULTRA_LEAF_SWITCH, now);
		return;
	}

	/*
	 * If we're running in ultra node and we are TCP-firewalled, then
	 * switch to leaf mode.
	 *
	 * We don't check whether they are firewalled if they asked to run as
	 * an ultranode here -- this will be caught by the check below when
	 * no leaf can connect.
	 */

	if (
		configured_peermode == NODE_P_AUTO &&
		current_peermode == NODE_P_ULTRA &&
		is_firewalled
	) {
		g_warning("firewalled node being demoted from Ultrapeer status");
		gnet_prop_set_guint32_val(PROP_CURRENT_PEERMODE, NODE_P_LEAF);
		gnet_prop_set_timestamp_val(PROP_NODE_LAST_ULTRA_LEAF_SWITCH, now);
		return;
	}

	/*
	 * If we're running as an ultra node (whether automaatically promoted
	 * or configured explicitly to run as such) and we have seen no leaf
	 * node connection for some time, then we're a bad node: we're taking
	 * an ultranode slot in a high outdegree network with a low TTL and
	 * are therefore harming the propagation of queries to leaf nodes,
	 * since we have none.
	 *
	 * Therefore, we'll be better off running as a leaf node.
	 */

	if (
		current_peermode == NODE_P_ULTRA &&
		no_leaves_connected != 0 &&
		delta_time(now, no_leaves_connected) > NODE_UP_NO_LEAF_MAX
	) {
		leaf_to_up_switch *= 2;
		leaf_to_up_switch = MIN(leaf_to_up_switch, NODE_AUTO_SWITCH_MAX);
		g_warning(
			"demoted from Ultrapeer status for %d secs due to missing leaves",
			leaf_to_up_switch);
		gnet_prop_set_guint32_val(PROP_CURRENT_PEERMODE, NODE_P_LEAF);
		gnet_prop_set_timestamp_val(PROP_NODE_LAST_ULTRA_LEAF_SWITCH, now);
		return;
	}
}

static inline void
node_error_cleanup(void)
{
	GSList *sl;
	GSList *to_remove = NULL;

	for (sl = unstable_servents; sl != NULL; sl = g_slist_next(sl)) {
		node_bad_client_t *bad_node = sl->data;

		g_assert(bad_node != NULL);

		if (--bad_node->errors == 0)
			to_remove = g_slist_prepend(to_remove, bad_node);
	}

	for (sl = to_remove; sl != NULL; sl = g_slist_next(sl)) {
		node_bad_client_t *bad_node = sl->data;

		g_assert(bad_node != NULL);
		g_assert(bad_node->vendor != NULL);

		if (node_debug > 1)
			g_warning("[nodes up] Unbanning client: %s", bad_node->vendor);

		g_hash_table_remove(unstable_servent, bad_node->vendor);
		unstable_servents = g_slist_remove(unstable_servents, bad_node);

		atom_str_free_null(&bad_node->vendor);
		wfree(bad_node, sizeof(*bad_node));
	}

	g_slist_free(to_remove);
}

/**
 * Periodic node heartbeat timer.
 */
void
node_timer(time_t now)
{
	const GSList *sl;

	if ((now % node_error_cleanup_timer) == 0)
		node_error_cleanup();

	/*
	 * Asynchronously react to current peermode change.
	 * See comment in node_set_current_peermode().
	 */

	if (peermode.changed) {
		peermode.changed = FALSE;
		node_set_current_peermode(peermode.new);
	}

	for (sl = sl_nodes; NULL != sl; /* empty */ ) {
		struct gnutella_node *n = sl->data;

		/*
		 * NB:	As the list `sl_nodes' might be modified, the next
		 * 		link has to be before any changes might apply!
		 */
 		sl = g_slist_next(sl);

		/*
		 * If we're sending a BYE message, check whether the whole TX
		 * stack finally flushed.
		 */

		if (n->flags & NODE_F_BYE_SENT) {
			g_assert(n->outq);
			if (mq_pending(n->outq) == 0)
				node_bye_sent(n);
		}

		/*
		 * No timeout during shutdowns, or when `stop_host_get' is set.
		 */

		if (!(in_shutdown || stop_host_get)) {
			if (n->status == GTA_NODE_REMOVING) {
				if (
					delta_time(now, n->last_update) >
						(time_delta_t) entry_removal_timeout
				) {
					node_real_remove(n);
					continue;
				}
			} else if (NODE_IS_CONNECTING(n)) {
				if (
					delta_time(now, n->last_update) >
						(time_delta_t) node_connecting_timeout
				) {
					node_remove(n, _("Timeout"));
                    hcache_add(HCACHE_TIMEOUT, n->addr, 0, "timeout");
				}
			} else if (n->status == GTA_NODE_SHUTDOWN) {
				if (delta_time(now, n->shutdown_date) > n->shutdown_delay) {
					gchar reason[1024];

					g_strlcpy(reason, n->error_str, sizeof reason);
					node_remove(n, _("Shutdown (%s)"), reason);
				}
			} else if (
				current_peermode == NODE_P_ULTRA &&
				NODE_IS_ULTRA(n)
			) {
				glong quiet = delta_time(now, n->last_tx);

				/*
				 * Ultra node connected to another ultra node.
				 *
				 * There is no longer any flow-control or activity
				 * timeout between an ultra node and a leaf, as long
				 * as they reply to eachother alive pings.
				 *		--RAM, 11/12/2003
				 */

				if (
					quiet > (glong) node_connected_timeout &&
					NODE_MQUEUE_COUNT(n)
				) {
                    hcache_add(HCACHE_TIMEOUT, n->addr, 0,
                        "activity timeout");
					node_bye_if_writable(n, 405, "Activity timeout");
				} else if (
					NODE_IN_TX_FLOW_CONTROL(n) &&
					delta_time(now, n->tx_flowc_date) >
						(time_delta_t) node_tx_flowc_timeout
				) {
                    hcache_add(HCACHE_UNSTABLE, n->addr, 0,
                        "flow-controlled too long");
					node_bye(n, 405, "Flow-controlled for too long (%d sec%s)",
						node_tx_flowc_timeout,
						node_tx_flowc_timeout == 1 ? "" : "s");
				}
			}
		}

		if (n->searchq != NULL)
			sq_process(n->searchq, now);

		/*
		 * Sanity checks for connected nodes.
		 */

		if (n->status == GTA_NODE_CONNECTED) {
			glong tx_quiet = delta_time(now, n->last_tx);
			glong rx_quiet = delta_time(now, n->last_rx);

			if (n->n_weird >= MAX_WEIRD_MSG) {

				g_message("Removing %s <%s> due to security violation",
					node_addr(n), node_vendor(n));
				node_bye_if_writable(n, 412, "Security violation");
				return;
			}

			if (
				!NODE_IS_LEAF(n) &&
				n->sent > MIN_TX_FOR_RATIO &&
				(n->received == 0 || n->sent / n->received > MAX_TX_RX_RATIO)
			) {
				node_bye_if_writable(n, 405, "Reception shortage");
				return;
			}

			/*
			 * If quiet period is nearing timeout and node supports
			 * time-sync, send them one if none is pending.
			 */

			if (
				node_connected_timeout > 2*NODE_TSYNC_CHECK &&
				MAX(tx_quiet, rx_quiet) >
					(glong) node_connected_timeout - NODE_TSYNC_CHECK &&
				(n->attrs & NODE_A_TIME_SYNC) &&
				!(n->flags & NODE_F_TSYNC_WAIT)
			) {
				node_tsync_tcp(n);
				n->flags |= NODE_F_TSYNC_WAIT;
			}

			/*
			 * Only send "alive" pings if we have not received anything
			 * for a while and if some time has elapsed since our last
			 * attempt to send such a ping.
			 *		--RAM, 01/11/2003
			 */

			if (
				NODE_IS_ESTABLISHED(n) &&
				delta_time(now, n->last_rx) > n->alive_period
			) {
				guint32 last;
				guint32 avg;
				time_delta_t period;

				/*
				 * Take the round-trip time of the ping/pongs as a base for
				 * computing the time we should space our pings.  Indeed,
				 * if the round-trip is 90s (taking an extreme example) due
				 * to queuing and TCP/IP clogging and we send pings every 20
				 * seconds, we will have sent 4 before getting a chance to see
				 * any reply back!
				 *		-RAM, 01/11/2003
				 */

				alive_get_roundtrip_ms(n->alive_pings, &avg, &last);
				last = MAX(avg, last) / 1000;	/* Convert ms to seconds */
				period = MAX(n->alive_period, (time_delta_t) last);

				if (
					delta_time(now, n->last_alive_ping) > period &&
					!alive_send_ping(n->alive_pings)
				) {
					node_bye(n, 406, "No reply to alive pings");
					return;
				}
			}

			/*
			 * Check whether we need to send more QRT patch updates.
			 */

			if (n->qrt_update != NULL)
				node_send_patch_step(n);

			/*
			 * Check RX flow control.
			 */

			if (n->rxfc != NULL) {
				struct node_rxfc_mon *rxfc = n->rxfc;

				if (
					delta_time(now, rxfc->start_half_period)
						> NODE_RX_FC_HALF_PERIOD
				) {
					time_t total;
					gdouble fc_ratio;
					guint32 max_ratio;

					/*
					 * If we're a leaf node, we allow the ultrapeer to flow
					 * control our incoming connection for 95% of the time.
					 * Being flow controlled means we're not getting that much
					 * queries, and we can't send ours, but as long as we have
					 * a non-null window to send our queries, that's fine.
					 */

					max_ratio = current_peermode == NODE_P_LEAF ? 95 :
						node_rx_flowc_ratio;

					if (rxfc->fc_start) {		/* In flow control */
						rxfc->fc_accumulator += delta_time(now, rxfc->fc_start);
						rxfc->fc_start = now;
					}

					total = rxfc->fc_accumulator + rxfc->fc_last_half;

					/* New period begins */
					rxfc->fc_last_half = rxfc->fc_accumulator;
					rxfc->fc_accumulator = 0;
					rxfc->start_half_period = now;

					fc_ratio = (gdouble) total / (2.0 * NODE_RX_FC_HALF_PERIOD);
					fc_ratio *= 100.0;

					if ((guint32) fc_ratio > max_ratio) {
						node_bye(n, 405,
							"Remotely flow-controlled too often "
							"(%.2f%% > %d%% of time)", fc_ratio, max_ratio);
						return;
					}

					/* Dispose of monitoring if we're not flow-controlled */
					if (total == 0) {
						wfree(n->rxfc, sizeof(*n->rxfc));
						n->rxfc = NULL;
					}
				}
			}
		}

		/*
		 * Rotate `qrelayed' on a regular basis into `qrelayed_old' and
		 * dispose of previous `qrelayed_old'.
		 */

		if (
			n->qrelayed != NULL &&
			delta_time(now, n->qrelayed_created) >=
				(time_delta_t) node_queries_half_life
		) {
			GHashTable *new;

			if (n->qrelayed_old != NULL) {
				new = n->qrelayed_old;
				string_table_clear(new);
			} else
				new = g_hash_table_new(g_str_hash, g_str_equal);

			n->qrelayed_old = n->qrelayed;
			n->qrelayed = new;
			n->qrelayed_created = now;
		}
	}

	sq_process(sq_global_queue(), now);
}

/**
 * Network init.
 */
void
node_init(void)
{
	time_t now = clock_loc2gmt(tm_time());

	rxbuf_init();

	g_assert(23 == sizeof(gnutella_header_t));

    node_handle_map = idtable_new(32, 32);
	header_features_add(FEATURES_CONNECTIONS, "browse",
		BH_VERSION_MAJOR, BH_VERSION_MINOR);

	g_hook_list_init(&node_added_hook_list, sizeof(GHook));
	node_added_hook_list.seq_id = 1;
	node_added = NULL;

	query_hashvec = qhvec_alloc(128);		/* Max: 128 unique words / URNs! */

	unstable_servent   = g_hash_table_new(NULL, NULL);
    ht_connected_nodes = g_hash_table_new(host_hash, host_eq);
	nodes_by_id        = g_hash_table_new(NULL, NULL);

	start_rfc822_date = atom_str_get(timestamp_rfc822_to_string(now));
	gnet_prop_set_timestamp_val(PROP_START_STAMP, now);

	udp_node = node_udp_create(NET_TYPE_IPV4);
	udp6_node = node_udp_create(NET_TYPE_IPV6);
	browse_node = node_browse_create();

	payload_inflate_buffer_len = settings_max_msg_size();
	payload_inflate_buffer = g_malloc(payload_inflate_buffer_len);

	/*
	 * Limit replies to TCP/UDP crawls from a single IP.
	 */

	tcp_crawls = aging_make(TCP_CRAWLER_FREQ,
		host_addr_hash_func, host_addr_eq_func, wfree_host_addr,
		NULL, NULL, NULL);

	udp_crawls = aging_make(UDP_CRAWLER_FREQ,
		host_addr_hash_func, host_addr_eq_func, wfree_host_addr,
		NULL, NULL, NULL);

	/*
	 * Signal we support flags in the size header via "sflag/0.1"
	 */

	header_features_add(FEATURES_CONNECTIONS, "sflag", 0, 1);
}

/**
 * Post GUI initialization.
 */
void
node_post_init(void)
{
	if (udp_active())
		node_udp_enable();
}

/**
 * Change the socket RX buffer size for all the currently connected nodes.
 */
void
node_set_socket_rx_size(gint rx_size)
{
	GSList *sl;

	g_assert(rx_size > 0);

	for (sl = sl_nodes; sl != NULL; sl = g_slist_next(sl)) {
		struct gnutella_node *n = sl->data;

		if (n->socket) {
			socket_check(n->socket);
			sock_recv_buf(n->socket, rx_size, TRUE);
		}
	}
}

/*
 * Nodes
 */

guint
connected_nodes(void)
{
	return connected_node_cnt;
}

guint
node_count(void)
{
	return connected_node_count - shutdown_nodes - node_leaf_count;
}

/**
 * Amount of node connections we would like to keep.
 *
 * @return 0 if none.
 */
guint
node_keep_missing(void)
{
	gint missing;

	switch ((node_peer_t) current_peermode) {
	case NODE_P_LEAF:
		missing = max_ultrapeers - node_ultra_count;
		return MAX(0, missing);
	case NODE_P_NORMAL:
	case NODE_P_ULTRA:
		missing = up_connections - (node_ultra_count + node_normal_count);
		return MAX(0, missing);
	case NODE_P_AUTO:
	case NODE_P_CRAWLER:
	case NODE_P_UDP:
	case NODE_P_UNKNOWN:
		break;
	}

	g_assert_not_reached();
	return 0;
}

/**
 * Amount of node connections we would like to have.
 *
 * @return 0 if none.
 */
guint
node_missing(void)
{
	gint missing;

	switch ((node_peer_t) current_peermode) {
	case NODE_P_LEAF:
		missing = max_ultrapeers - node_ultra_count;
		return MAX(0, missing);
	case NODE_P_NORMAL:
	case NODE_P_ULTRA:
		missing = max_connections - (node_ultra_count + node_normal_count);
		return MAX(0, missing);
	case NODE_P_AUTO:
	case NODE_P_CRAWLER:
	case NODE_P_UDP:
	case NODE_P_UNKNOWN:
		break;
	}

	g_assert_not_reached();
	return 0;
}

/**
 * Amount of leaves we're missing (0 if not in ultra mode).
 */
guint
node_leaves_missing(void)
{
	gint missing;

	if (current_peermode != NODE_P_ULTRA)
		return 0;

	missing = max_leaves - node_leaf_count;

	return MAX(0, missing);
}

/**
 * @return this node's outdegree, i.e. the maximum amount of peer connections
 * that we can support.
 */
guint
node_outdegree(void)
{
	switch ((node_peer_t) current_peermode) {
	case NODE_P_LEAF:
		return max_ultrapeers;
	case NODE_P_NORMAL:
	case NODE_P_ULTRA:
		return max_connections;
	case NODE_P_AUTO:
	case NODE_P_CRAWLER:
	case NODE_P_UDP:
	case NODE_P_UNKNOWN:
		break;
	}

	g_assert_not_reached();
	return 0;
}

/**
 * Parse the first handshake line to determine the protocol version.
 * The major and minor are returned in `major' and `minor' respectively.
 */
static void
get_protocol_version(const gchar *handshake, guint *major, guint *minor)
{
	const gchar *s;

	s = &handshake[GNUTELLA_HELLO_LENGTH];	
	if (0 == parse_major_minor(s, NULL, major, minor))
		return;

	if (node_debug)
		g_warning("Unable to parse version number in HELLO, assuming 0.4");
	if (node_debug > 2) {
		guint len = strlen(handshake);
		dump_hex(stderr, "First HELLO Line", handshake, MIN(len, 80));
	}

	*major = 0;
	*minor = 4;
}

/**
 * Decrement the proper node count property, depending on the peermode.
 */
static void
node_type_count_dec(struct gnutella_node *n)
{
	switch (n->peermode) {
	case NODE_P_LEAF:
		g_assert(node_leaf_count > 0);
		gnet_prop_set_guint32_val(PROP_NODE_LEAF_COUNT,
			node_leaf_count - 1);
		return;
	case NODE_P_NORMAL:
		g_assert(node_normal_count > 0);
		gnet_prop_set_guint32_val(PROP_NODE_NORMAL_COUNT,
			node_normal_count - 1);
		return;
	case NODE_P_ULTRA:
		g_assert(node_ultra_count > 0);
		gnet_prop_set_guint32_val(PROP_NODE_ULTRA_COUNT,
			node_ultra_count - 1);
		return;
	case NODE_P_AUTO:
	case NODE_P_CRAWLER:
	case NODE_P_UDP:
	case NODE_P_UNKNOWN:
		return;
	}
	g_assert_not_reached();
}

/**
 * Physically dispose of node.
 */
void
node_real_remove(gnutella_node_t *n)
{
	g_return_if_fail(n);
	g_assert(n->magic == NODE_MAGIC);

    /*
     * Tell the frontend that the node was removed.
     */
    node_fire_node_removed(n);

	sl_nodes = g_slist_remove(sl_nodes, n);
	sl_nodes_without_broken_gtkg =
		g_slist_remove(sl_nodes_without_broken_gtkg, n);
	g_hash_table_remove(nodes_by_id, GUINT_TO_POINTER(n->id));
    node_drop_handle(n->node_handle);

	/*
	 * Now that the node was removed from the list of known nodes, we
	 * can add the host to HL_VALID iff the node was marked NODE_F_VALID,
	 * meaning we identified it as a Gnutella server, even though we
	 * might not have been granted a full connection.
	 *		--RAM, 13/01/2002
	 */

	if (
		!NODE_IS_LEAF(n) &&
		is_host_addr(n->gnet_addr) &&
		(n->flags & NODE_F_VALID)
	)
		hcache_add_valid((n->attrs & NODE_A_ULTRA) ? HOST_ULTRA : HOST_ANY,
            n->gnet_addr, n->gnet_port, "save valid");

	/*
	 * The io_opaque structure is not freed by node_remove(), so that code
	 * can still peruse the headers after node_remove() has been called.
	 */

	if (n->io_opaque)				/* I/O data */
		io_free(n->io_opaque);

	/*
	 * The freeing of the vendor string is delayed, because the GUI update
	 * code reads it.  When this routine is called, the GUI line has been
	 * removed, so it's safe to do it now.
	 */

	atom_str_free_null(&n->vendor);

	/*
	 * The RX stack needs to be dismantled asynchronously, to not be freed
	 * whilst on the "data reception" interrupt path.
	 */

	if (n->rx)
		rx_free(n->rx);

	/*
	 * The TX stack is dismantled asynchronously as well to be on the
	 * safe side.
	 */

	if (n->outq)
		mq_free(n->outq);

	if (n->alive_pings)			/* Must be freed after the TX stack */
		alive_free(n->alive_pings);

	n->magic = 0;
	wfree(n, sizeof(*n));
}

/**
 * The vectorized (message-wise) version of node_remove().
 */
static G_GNUC_PRINTF(2, 0) void
node_remove_v(struct gnutella_node *n, const gchar *reason, va_list ap)
{
	g_assert(n->magic == NODE_MAGIC);
	g_assert(n->status != GTA_NODE_REMOVING);
	g_assert(!NODE_IS_UDP(n));

	if (reason && no_reason != reason) {
		gm_vsnprintf(n->error_str, sizeof n->error_str, reason, ap);
		n->remove_msg = n->error_str;
	} else if (n->status != GTA_NODE_SHUTDOWN)	/* Preserve shutdown error */
		n->remove_msg = NULL;

	if (node_debug > 3)
		g_message("Node %s <%s> removed: %s", node_addr(n), node_vendor(n),
			n->remove_msg ? n->remove_msg : "<no reason>");

	if (node_debug > 4) {
		g_message("NODE [%d.%d] %s <%s> TX=%d (drop=%d) RX=%d (drop=%d) "
			"Dup=%d Bad=%d W=%d",
			n->proto_major, n->proto_minor, node_addr(n), node_vendor(n),
			n->sent, n->tx_dropped, n->received, n->rx_dropped,
			n->n_dups, n->n_bad, n->n_weird);
		g_message("NODE \"%s%s\" %s PING (drop=%d acpt=%d spec=%d sent=%d) "
			"PONG (rcvd=%d sent=%d)",
			(n->attrs & NODE_A_PONG_CACHING) ? "new" : "old",
			(n->attrs & NODE_A_PONG_ALIEN) ? "-alien" : "",
			node_addr(n),
			n->n_ping_throttle, n->n_ping_accepted, n->n_ping_special,
			n->n_ping_sent, n->n_pong_received, n->n_pong_sent);
	}

	if (n->routing_data) {
		routing_node_remove(n);
		n->routing_data = NULL;
	}
	if (n->qrt_update) {
		qrt_update_free(n->qrt_update);
		n->qrt_update = NULL;
	}
	if (n->qrt_receive) {
		qrt_receive_free(n->qrt_receive);
		n->qrt_receive = NULL;
	}
	if (n->recv_query_table) {
		qrt_unref(n->recv_query_table);
		n->recv_query_table = NULL;

		/*
		 * I decided to NOT call qrp_leaf_changed() here even if
		 * the node was a leaf node.  Why?  Because that could cause
		 * the regeneration of the last-hop QRP table and all we could
		 * do is clear some slots in the table to get less entries.
		 * Entries that could be filled by the next leaf that will come
		 * to fill the free leaf slot.
		 *
		 * Since having less slots means we'll get less queries, but
		 * having a new table means generating a patch and therefore
		 * consuming network resources, it's not clear what the gain
		 * would be.  Better wait for the new leaf to have sent its
		 * patch to update.
		 *
		 *		--RAM, 2004-08-04
		 */
	}

	if (n->sent_query_table) {
		qrt_unref(n->sent_query_table);
		n->sent_query_table = NULL;
	}
	if (n->qrt_info) {
		WFREE_NULL(n->qrt_info, sizeof(*n->qrt_info));
	}
	if (n->rxfc) {
		WFREE_NULL(n->rxfc, sizeof(*n->rxfc));
	}
	if (n->status == GTA_NODE_CONNECTED) {		/* Already did if shutdown */
		g_assert(connected_node_cnt > 0);
		connected_node_cnt--;
        if (n->attrs & NODE_A_RX_INFLATE) {
			if (n->flags & NODE_F_LEAF) {
				g_assert(compressed_leaf_cnt > 0);
				compressed_leaf_cnt--;
			}
            g_assert(compressed_node_cnt > 0);
            compressed_node_cnt--;
        }
		node_type_count_dec(n);
	}

	if (n->status == GTA_NODE_SHUTDOWN) {
		shutdown_nodes--;
	}
	if (n->hello.ptr) {
		WFREE_NULL(n->hello.ptr, n->hello.size);
	}

	/* n->io_opaque will be freed by node_real_remove() */
	/* n->vendor will be freed by node_real_remove() */

	if (n->allocated) {
		G_FREE_NULL(n->data);
		n->allocated = 0;
	}
	if (n->searchq) {
		sq_free(n->searchq);
		n->searchq = NULL;
	}
	if (n->rx)					/* RX stack freed by node_real_remove() */
		node_disable_read(n);
	if (n->outq)				/* TX stack freed by node_real_remove() */
		mq_shutdown(n->outq);	/* Prevents any further output */

	if (n->socket) {
		socket_check(n->socket);
		g_assert(n->socket->resource.node == n);
		socket_free_null(&n->socket);
	}

	atom_guid_free_null(&n->gnet_guid);
	if (n->tsync_ev) {
		cq_cancel(callout_queue, n->tsync_ev);
		n->tsync_ev = NULL;
	}

	n->status = GTA_NODE_REMOVING;
	n->flags &= ~(NODE_F_WRITABLE|NODE_F_READABLE|NODE_F_BYE_SENT);
	n->last_update = tm_time();

    node_ht_connected_nodes_remove(n->gnet_addr, n->gnet_port);
	node_proxying_remove(n, TRUE);

	if (n->flags & NODE_F_EOF_WAIT) {
		g_assert(pending_byes > 0);
		pending_byes--;
	}

	if (is_host_addr(n->proxy_addr)) {
		sl_proxies = g_slist_remove(sl_proxies, n);
	}
	if (n->qseen != NULL) {
		string_table_free(n->qseen);
		n->qseen = NULL;
	}
	if (n->qrelayed != NULL) {
		string_table_free(n->qrelayed);
		n->qrelayed = NULL;
	}
	if (n->qrelayed_old != NULL) {
		string_table_free(n->qrelayed_old);
		n->qrelayed_old = NULL;
	}

	if (!in_shutdown) {
		if (n->attrs & NODE_A_CAN_HSEP) {
			hsep_connection_close(n);
		}
		if (NODE_IS_LEAF(n)) {
			dq_node_removed(n->id);	/* Purge dynamic queries for that node */
		}
		node_fire_node_info_changed(n);
		node_fire_node_flags_changed(n);
	}
}

/**
 * Called when node_bye() or node_shutdown() is called during the time we're
 * in shutdown mode, processing the messages we might still read from the
 * socket.
 */
static void
node_recursive_shutdown_v(
	struct gnutella_node *n,
	const gchar *where, const gchar *reason, va_list ap)
{
	gchar *fmt, *p;

	g_assert(n->status == GTA_NODE_SHUTDOWN);
	g_assert(n->error_str);
	g_assert(reason);

	/* XXX: Could n->error_str contain a format string? Rather make sure
	 *		there isn't any. */
	for (p = n->error_str; *p != '\0'; p++)
		if (*p == '%')
			*p = 'X';

	fmt = g_strdup_printf("%s (%s) [within %s]", where, reason, n->error_str);
	node_remove_v(n, fmt, ap);
	G_FREE_NULL(fmt);
}

/**
 * Removes or shuts down the given node.
 */
void
node_remove_by_handle(gnet_node_t n)
{
    gnutella_node_t *node;

	node = node_find_by_handle(n);

    g_assert(node != NULL);
	g_assert(node->magic == NODE_MAGIC);

	if (node == udp_node || node == udp6_node) {
		/* This is too obscure. */
#if 0
		gnet_prop_set_boolean_val(PROP_ENABLE_UDP, FALSE);
#endif
	} else if (NODE_IS_WRITABLE(node)) {
        node_bye(node, 201, "User manual removal");
	} else {
        node_remove(node, no_reason);
        node_real_remove(node);
    }
}

/**
 * Check whether node has been identified as having a bad IP or vendor string.
 *
 * @return NODE_BAD_OK if node is OK, the reason why the node is bad otherwise.
 *
 * @note when we're low on pongs, we never refuse a connection, so this
 * routine always returns NODE_BAD_OK.
 */
static enum
node_bad node_is_bad(struct gnutella_node *n)
{
	node_bad_client_t *bad_client = NULL;

	g_assert(n != NULL);

	if (!node_monitor_unstable_ip)
		return NODE_BAD_OK;		/* User disabled monitoring of unstable IPs */

	if (host_low_on_pongs)
		return NODE_BAD_OK;		/* Can't refuse connection */

	if (n->vendor == NULL) {
		if (node_debug)
			g_warning("no vendor name in %s node headers from %s",
				NODE_IS_LEAF(n) ? "leaf" :
				NODE_IS_ULTRA(n) ? "ultra" : "legacy",
				node_addr(n));
		return NODE_BAD_NO_VENDOR;
	}

	g_assert(n->vendor != NULL);
	g_assert(is_host_addr(n->addr));

    if (hcache_node_is_bad(n->addr)) {
		if (node_debug)
			g_warning("[nodes up] Unstable peer %s (%s)",
				host_addr_to_string(n->addr),
				n->vendor);
		return NODE_BAD_IP;
    }

	if (!node_monitor_unstable_servents)
		return NODE_BAD_OK;	/* No monitoring of unstable servents */

	bad_client = g_hash_table_lookup(unstable_servent, n->vendor);

	if (bad_client == NULL)
		return NODE_BAD_OK;

	if (bad_client->errors > node_error_threshold) {
		if (node_debug)
			g_warning("[nodes up] Banned client: %s", n->vendor);
		return NODE_BAD_VENDOR;
	}

	return NODE_BAD_OK;
}

/**
 * Gives a specific vendor a bad mark. If a vendor + version gets to many
 * marks, we won't try to connect to it anymore.
 */
void
node_mark_bad_vendor(struct gnutella_node *n)
{
	struct node_bad_client *bad_client = NULL;
	time_t now;

	if (in_shutdown)
		return;

	/*
	 * If the user doesn't want us to protect against unstable IPs, then we
	 * can stop right now. Protecting against unstable servent name will
	 * also be ignored, to prevent marking a servent as unstable while we
	 * are actually connecting to the same IP over and over again
	 */

	if (!node_monitor_unstable_ip)
		return;

	g_assert(n != NULL);
	g_assert(NET_TYPE_LOCAL == host_addr_net(n->addr) || is_host_addr(n->addr));

	/*
	 * Only mark Ultrapeers as bad nodes. Leaves aren't expected to have
	 * high uptimes
	 */

	if (!(n->attrs & NODE_A_ULTRA))
		return;

	/*
	 * Do not mark nodes as bad with which we did not connect at all, we
	 * don't know it's behaviour in this case.
	 */

	if (n->connect_date == 0)
		return;

	now = tm_time();

	/* Don't mark a node with whom we could stay a long time as being bad */
	if (
		delta_time(now, n->connect_date) >
			node_error_cleanup_timer / node_error_threshold
	) {
		if (node_debug > 1)
			g_message("[nodes up] "
				  "%s not marking as bad. Connected for: %d (min: %d)",
				host_addr_to_string(n->addr),
				(gint) delta_time(now, n->connect_date),
				(gint) (node_error_cleanup_timer / node_error_threshold));
		return;
	}

    hcache_add(HCACHE_UNSTABLE, n->addr, 0, "vendor banned");

	if (!node_monitor_unstable_servents)
		return;	/* The user doesn't want us to monitor unstable servents. */

	if (n->vendor == NULL)
		return;

	g_assert(n->vendor != NULL);

	bad_client = g_hash_table_lookup(unstable_servent, n->vendor);
	if (bad_client == NULL) {
		bad_client = walloc0(sizeof(*bad_client));
		bad_client->errors = 0;
		bad_client->vendor = atom_str_get(n->vendor);
		gm_hash_table_insert_const(unstable_servent,
			bad_client->vendor, bad_client);
		unstable_servents = g_slist_prepend(unstable_servents, bad_client);
	}

	g_assert(bad_client != NULL);

	bad_client->errors++;

	if (node_debug)
		g_warning("[nodes up] Increased error counter (%d) for client: %s",
			bad_client->errors,
			n->vendor);
}

/**
 * Make sure that the vendor of the connecting node does not already use
 * more than "unique_nodes" percent of the slots of its kind.
 *
 * @return TRUE if accepting the node would make us use more slots than
 * what the user has configured as acceptable.
 *
 * @note when low on pongs, monopoly protection is disabled to avoid the
 * host contacting the web caches just because it cannot fulfill its
 * anti-monopoly requirements.
 */
static gboolean
node_avoid_monopoly(struct gnutella_node *n)
{
	guint up_cnt = 0;
	guint leaf_cnt = 0;
	guint normal_cnt = 0;
	GSList *sl;

	g_assert((gint) unique_nodes >= 0 && unique_nodes <= 100);

	if (host_low_on_pongs)
		return FALSE;

	if (!n->vendor || (n->flags & NODE_F_CRAWLER) || unique_nodes == 100)
		return FALSE;

	for (sl = sl_nodes; sl; sl = g_slist_next(sl)) {
		struct gnutella_node *node = sl->data;

		if (node->status != GTA_NODE_CONNECTED || node->vendor == NULL)
			continue;

		/*
		 * Node vendor strings are compared up to the specified delimitor,
		 * i.e. we don't want to take the version number into account.
		 *
		 * The vendor name and the version are normally separated with a "/"
		 * but some people wrongly use " " as the separator.
		 */

		if (0 != strcasecmp_delimit(n->vendor, node->vendor, "/ 012345678"))
			continue;

		if ((node->attrs & NODE_A_ULTRA) || (node->flags & NODE_F_ULTRA))
			up_cnt++;
		else if (node->flags & NODE_F_LEAF)
			leaf_cnt++;
		else
			normal_cnt++;
	}

	/* Include current node into counter as well */
	if ((n->attrs & NODE_A_ULTRA) || (n->flags & NODE_F_ULTRA))
		up_cnt++;
	else if (n->flags & NODE_F_LEAF)
		leaf_cnt++;
	else
		normal_cnt++;

	switch ((node_peer_t) current_peermode) {
	case NODE_P_ULTRA:
		if ((n->attrs & NODE_A_ULTRA) || (n->flags & NODE_F_ULTRA)) {
			gint max = max_connections - normal_connections;
			if (max > 1 && up_cnt * 100 > max * unique_nodes)
				return TRUE;	/* Disallow */
		} else if (n->flags & NODE_F_LEAF) {
			if (max_leaves > 1 && leaf_cnt * 100 > max_leaves * unique_nodes)
				return TRUE;
		} else {
			if (
				normal_connections > 1 &&
				normal_cnt * 100 > normal_connections * unique_nodes
			)
				return TRUE;
		}
		return FALSE;
	case NODE_P_LEAF:
		if (max_ultrapeers > 1 && up_cnt * 100 > max_ultrapeers * unique_nodes)
			return TRUE;	/* Dissallow */
		return FALSE;
	case NODE_P_NORMAL:
		if (
			max_connections > 1 &&
			normal_cnt * 100 > max_connections * unique_nodes
		)
			return TRUE;
		return FALSE;
	case NODE_P_AUTO:
		return FALSE;
	case NODE_P_CRAWLER:
	case NODE_P_UDP:
	case NODE_P_UNKNOWN:
		g_assert_not_reached();
		break;
	}

	g_assert_not_reached();
	return FALSE;
}

/**
 * When we only have "reserve_gtkg_nodes" percent slots left, make sure the
 * connecting node is a GTKG node or refuse the connection.
 *
 * @return TRUE if we should reserve the slot for GTKG, i.e. refuse `n'.
 */
static gboolean
node_reserve_slot(struct gnutella_node *n)
{
	guint up_cnt = 0;		/* GTKG UPs */
	guint leaf_cnt = 0;		/* GTKG leafs */
	guint normal_cnt = 0;	/* GTKG normal nodes */
	GSList *sl;

	g_assert((gint) reserve_gtkg_nodes >= 0 && reserve_gtkg_nodes <= 100);

	if (node_is_gtkg(n))
		return FALSE;

	if (!n->vendor || (n->flags & NODE_F_CRAWLER) || !reserve_gtkg_nodes)
		return FALSE;

	for (sl = sl_nodes; sl; sl = sl->next) {
		struct gnutella_node *node = (struct gnutella_node *) sl->data;

		if (node->status != GTA_NODE_CONNECTED || node->vendor == NULL)
			continue;

		if (!node_is_gtkg(node))
			continue;

		/*
		 * Count GTKG nodes we are already connected to, by type
		 */

		if ((node->attrs & NODE_A_ULTRA) || (node->attrs & NODE_F_ULTRA))
			up_cnt++;
		else if (node->flags & NODE_F_LEAF)
			leaf_cnt++;
		else
			normal_cnt++;
	}

	/*
	 * For a given max population `max', already filled by `x' nodes out
	 * of which `y' are GTKG ones, we want to make sure that we can have
	 * "reserve_gtkg_nodes" percent of the slots (i.e. `g' percent) used
	 * by GTKG.
	 *
	 * In other words, we want to ensure that we can have "g*max/100" slots
	 * used by GTKG.  We have already `x' slots used, that leaves "max - x"
	 * ones free.  To be able to have our quota of GTKG slots, we need to
	 * reserve slots to GTKG when "max - x" <= "g*max/100 - y".  I.e.
	 * when `x' >= max - g*max/100 + y.
	 */

	switch ((node_peer_t) current_peermode) {
	case NODE_P_ULTRA:
		if ((n->attrs & NODE_A_ULTRA) || (n->flags & NODE_F_ULTRA)) {
			gint max = max_connections - normal_connections;
			gint gtkg_min = reserve_gtkg_nodes * max / 100;

			/*
			 * If we would reserve a slot to GTKG but we can get rid of
			 * a useless ultra, then do so before checking.  If we don't
			 * remove a useless GTKG node, then this will make room for
			 * the current connection.
			 */

			if (node_ultra_count >= max + up_cnt - gtkg_min) {
				gboolean is_gtkg;

				if (node_remove_useless_ultra(&is_gtkg) && is_gtkg)
					up_cnt--;
			}

			if (node_ultra_count >= max + up_cnt - gtkg_min)
				return TRUE;
		} else if (n->flags & NODE_F_LEAF) {
			gint gtkg_min = reserve_gtkg_nodes * max_leaves / 100;

			/*
			 * If we would reserve a slot to GTKG but we can get rid of
			 * a useless leaf, then do so before checking.  If we don't
			 * remove a useless GTKG node, then this will make room for
			 * the current connection.
			 */

			if (node_leaf_count >= max_leaves + leaf_cnt - gtkg_min) {
				gboolean is_gtkg;
				if (node_remove_useless_leaf(&is_gtkg) && is_gtkg)
					leaf_cnt--;
			}

			if (node_leaf_count >= max_leaves + leaf_cnt - gtkg_min)
				return TRUE;
		} else {
			gint gtkg_min = reserve_gtkg_nodes * normal_connections / 100;
			if (node_normal_count >= normal_connections + normal_cnt - gtkg_min)
				return TRUE;
		}
		return FALSE;
	case NODE_P_LEAF:
		if (max_ultrapeers > 0 ) {
			gint gtkg_min = reserve_gtkg_nodes * max_ultrapeers / 100;
			if (node_ultra_count >= max_ultrapeers + up_cnt - gtkg_min)
				return TRUE;
		}
		return FALSE;
	case NODE_P_NORMAL:
		if (max_connections > 0) {
			gint gtkg_min = reserve_gtkg_nodes * max_connections / 100;
			if (node_normal_count >= max_connections + normal_cnt - gtkg_min)
				return TRUE;
		}
		return FALSE;
	case NODE_P_AUTO:
		return FALSE;
	case NODE_P_CRAWLER:
	case NODE_P_UDP:
	case NODE_P_UNKNOWN:
		g_assert_not_reached();
		break;
	}

	g_assert_not_reached();
	return FALSE;
}

/**
 * Terminate connection with remote node, but keep structure around for a
 * while, for displaying purposes, and also to prevent the node from being
 * physically reclaimed within this stack frame.
 *
 * It will be reclaimed on the "idle" stack frame, via node_real_remove().
 */
void
node_remove(struct gnutella_node *n, const gchar *reason, ...)
{
	va_list args;

	g_assert(n);
	g_assert(n->magic == NODE_MAGIC);

	if (n->status == GTA_NODE_REMOVING)
		return;

	va_start(args, reason);
	node_remove_v(n, reason, args);
	va_end(args);
}

/**
 * The vectorized version of node_eof().
 */
static void
node_eof_v(struct gnutella_node *n, const gchar *reason, va_list args)
{
	const gchar *format;

	g_assert(n);

	/*
	 * If the Gnutella connection was established, we should have got a BYE
	 * to cleanly shutdown.
	 */

	if (n->flags & NODE_F_ESTABLISHED)
		node_mark_bad_vendor(n);

	if (n->flags & NODE_F_BYE_SENT) {
		g_assert(n->status == GTA_NODE_SHUTDOWN);
		if (node_debug > 4) {
			va_list dbargs;

			printf("EOF-style error during BYE to %s:\n (BYE) ", node_addr(n));

			VA_COPY(dbargs, args);
			vprintf(reason, dbargs);
			va_end(dbargs);

			printf("\n");
		}
	}

	/*
	 * Call node_remove_v() with supplied message unless we already sent a BYE
 	 * message, in which case we're done since the remote end most probably
	 * read it and closed the connection.
     */

	socket_eof(n->socket);

	if (n->flags & NODE_F_CLOSING)		/* Bye sent or explicit shutdown */
		format = NULL;					/* Reuse existing reason */
	else
		format = reason;

	node_remove_v(n, format, args);
}

/**
 * Got an EOF condition, or a read error, whilst reading Gnet data from node.
 *
 * Terminate connection with remote node, but keep structure around for a
 * while, for displaying purposes.
 */
void
node_eof(struct gnutella_node *n, const gchar *reason, ...)
{
	va_list args;

	g_assert(n);

	va_start(args, reason);
	node_eof_v(n, reason, args);
	va_end(args);
}

/**
 * Enter shutdown mode: prevent further writes, drop read broadcasted messages,
 * and make sure we flush the buffers at the fastest possible speed.
 */
static void
node_shutdown_mode(struct gnutella_node *n, guint32 delay)
{

	/*
	 * If node is already in shutdown node, simply update the delay.
	 */

	n->shutdown_delay = delay;

	if (n->status == GTA_NODE_SHUTDOWN)
		return;

	if (n->status == GTA_NODE_CONNECTED) {	/* Free Gnet slot */
		connected_node_cnt--;
		g_assert(connected_node_cnt <= INT_MAX);
        if (n->attrs & NODE_A_RX_INFLATE) {
			if (n->flags & NODE_F_LEAF)
				compressed_leaf_cnt--;
            compressed_node_cnt--;
            g_assert(compressed_node_cnt <= INT_MAX);
			g_assert(compressed_leaf_cnt <= INT_MAX);
        }
		node_type_count_dec(n);
 	}

	n->status = GTA_NODE_SHUTDOWN;
	n->flags &= ~(NODE_F_WRITABLE|NODE_F_READABLE);
	n->shutdown_date = tm_time();
	mq_discard(n->outq);					/* Discard any further data */
	node_flushq(n);							/* Fast queue flushing */

	shutdown_nodes++;

    node_fire_node_info_changed(n);
    node_fire_node_flags_changed(n);
}

/**
 * The vectorized version of node_shutdown().
 */
static void
node_shutdown_v(struct gnutella_node *n, const gchar *reason, va_list args)
{
	g_assert(n);

	if (n->status == GTA_NODE_SHUTDOWN) {
		node_recursive_shutdown_v(n, "Shutdown", reason, args);
		return;
	}

	n->flags |= NODE_F_CLOSING;

	if (reason) {
		gm_vsnprintf(n->error_str, sizeof n->error_str, reason, args);
		n->remove_msg = n->error_str;
	} else {
		n->remove_msg = "Unknown reason";
		n->error_str[0] = '\0';
	}

	node_shutdown_mode(n, SHUTDOWN_GRACE_DELAY);
}

/**
 * Stop sending data to node, but keep reading buffered data from it, until
 * we hit a Bye packet or EOF.  In that mode, we don't relay Queries we may
 * read, but replies and pushes are still routed back to other nodes.
 *
 * This is mostly called when a fatal write error happens, but we want to
 * see whether the node did not send us a Bye we haven't read yet.
 */
void
node_shutdown(struct gnutella_node *n, const gchar *reason, ...)
{
	va_list args;

	va_start(args, reason);
	node_shutdown_v(n, reason, args);
	va_end(args);
}

/**
 * The vectorized version of node_bye().
 */
static void
node_bye_v(struct gnutella_node *n, gint code, const gchar *reason, va_list ap)
{
	gnutella_header_t head;
	gchar reason_fmt[1024];
	size_t len;
	gint sendbuf_len;
	gchar *reason_base = &reason_fmt[2];	/* Leading 2 bytes for code */

	g_assert(n);
	g_assert(!NODE_IS_UDP(n));

	if (n->status == GTA_NODE_SHUTDOWN) {
		node_recursive_shutdown_v(n, "Bye", reason, ap);
		return;
	}

	n->flags |= NODE_F_CLOSING;

	if (reason) {
		gm_vsnprintf(n->error_str, sizeof n->error_str, reason, ap);
		n->remove_msg = n->error_str;
	} else {
		n->remove_msg = NULL;
		n->error_str[0] = '\0';
	}

	/*
	 * Discard all the queued entries, we're not going to send them.
	 * The only message that may remain is the oldest partially sent.
	 */

	if (n->searchq)
		sq_clear(n->searchq);

	mq_clear(n->outq);

	/*
	 * Build the bye message.
	 */

	len = gm_snprintf(reason_base, sizeof reason_fmt - 3,
		"%s", n->error_str);

	/* XXX Add X-Try and X-Try-Ultrapeers */

	if (code != 200) {
		len += gm_snprintf(reason_base + len, sizeof reason_fmt - len - 3,
			"\r\n"
			"Server: %s\r\n"
			"\r\n",
			version_string);
	}

	g_assert(len <= sizeof reason_fmt - 3);

	reason_base[len] = '\0';
	len += 2 + 1;		/* 2 for the leading code, 1 for the trailing NUL */

	gnutella_bye_set_code(reason_fmt, code);

	message_set_muid(&head, GTA_MSG_BYE);
	gnutella_header_set_function(&head, GTA_MSG_BYE);
	gnutella_header_set_ttl(&head, 1);
	gnutella_header_set_hops(&head, 0);
	gnutella_header_set_size(&head, len);

	/*
	 * Send the bye message, enlarging the TCP input buffer to make sure
	 * we can atomically send the message plus the remaining queued data.
	 */

	sendbuf_len = NODE_SEND_BUFSIZE + mq_size(n->outq) +
		len + sizeof(head) + 1024;		/* Slightly larger, for flow-control */

	sock_send_buf(n->socket, sendbuf_len, FALSE);
	gmsg_split_sendto_one(n, &head, reason_fmt, len + sizeof(head));

	/*
	 * Whether we sent the message or not, enter shutdown mode.
	 *
	 * We'll stay in the shutdown mode for some time, then we'll kick the node
	 * out.  But not doing it immediately gives a chance for the message to
	 * proagate AND be read by the remote node.
	 *
	 * When sending is delayed, we will periodically check for the
	 * NODE_F_BYE_SENT condition and change the shutdown delay to a much
	 * shorter period when the TX queue is emptied.
	 *
	 * In shutdown mode, we'll also preserve the existing error message for
	 * node_remove().
	 *
	 * NB: To know whether we sent it or not, we need to probe the size
	 * of the TX stack, since there is a possible compression stage that
	 * can delay sending data for a little while.  That's why we
	 * use mq_pending() and not mq_size().
	 */

	if (mq_pending(n->outq) == 0) {
		if (node_debug)
			g_message("successfully sent BYE %d \"%s\" to %s (%s)",
				code, n->error_str, node_addr(n), node_vendor(n));

			sock_tx_shutdown(n->socket);
			node_shutdown_mode(n, BYE_GRACE_DELAY);
	} else {
		if (node_debug)
			g_message("delayed sending of BYE %d \"%s\" to %s (%s)",
				code, n->error_str, node_addr(n), node_vendor(n));

		n->flags |= NODE_F_BYE_SENT;

		node_shutdown_mode(n, SHUTDOWN_GRACE_DELAY);
	}
}

/**
 * Terminate connection by sending a bye message to the remote node.  Upon
 * reception of that message, the connection will be closed by the remote
 * party.
 *
 * This is otherwise equivalent to the node_shutdown() call.
 */
void
node_bye(gnutella_node_t *n, gint code, const gchar * reason, ...)
{
	va_list args;

	va_start(args, reason);
	node_bye_v(n, code, reason, args);
	va_end(args);

}

/**
 * If node is writable, act as if node_bye() had been called.
 * Otherwise, act as if node_remove() had been called.
 */
void
node_bye_if_writable(
	struct gnutella_node *n, gint code, const gchar *reason, ...)
{
	va_list args;

	va_start(args, reason);

	if (NODE_IS_WRITABLE(n))
		node_bye_v(n, code, reason, args);
	else
		node_remove_v(n, reason, args);
}

/**
 * Is there a node connected with this IP/port?
 *
 * The port is tested only when `incoming' is FALSE, i.e. we allow
 * only one incoming connection per IP, even when there are several
 * instances, all on different ports.
 */
gboolean
node_is_connected(const host_addr_t addr, guint16 port, gboolean incoming)
{
	if (is_my_address(addr, port)) {
		return TRUE;
	}

    /*
     * If incoming is TRUE we have to do an exhaustive search because
     * we have to ignore the port. Otherwise we can use the fast
     * hashtable lookup.
     *     -- Richard, 29/04/2004
     */
    if (incoming) {
		const GSList *sl;

        for (sl = sl_nodes; sl; sl = g_slist_next(sl)) {
            const struct gnutella_node *n = sl->data;

            if (
				n->status != GTA_NODE_REMOVING &&
				n->status != GTA_NODE_SHUTDOWN &&
				n->port == port &&
				host_addr_equal(n->addr, addr)
			) {
				return TRUE;
            }
        }
        return FALSE;
    } else {
        return node_ht_connected_nodes_has(addr, port);
    }
}

/**
 * Are we directly connected to that host?
 */
gboolean
node_host_is_connected(const host_addr_t addr, guint16 port)
{
	/* Check our local address */

	if (host_addr_equal(addr, listen_addr()))
		return TRUE;
	if (host_addr_equal(addr, listen_addr6()))
		return TRUE;

    return node_ht_connected_nodes_has(addr, port);
}

/**
 * Build CONNECT_PONGS_COUNT pongs to emit as an X-Try header.
 * We stick to strict formatting rules: no line of more than 76 chars.
 *
 * @return a pointer to static data.
 *
 * @bug
 * XXX Refactoring note: there is a need for generic header formatting
 * routines, and especially the dumping routing, which could be taught
 * basic formatting and splitting so that very long lines are dumped using
 * continuations. --RAM, 10/01/2002
 */
static const gchar *
formatted_connection_pongs(const gchar *field, host_type_t htype, gint num)
{
	struct gnutella_host hosts[CONNECT_PONGS_COUNT];
	const gchar *line = "";
	gint hcount;

	g_assert(num > 0 && num <= CONNECT_PONGS_COUNT);

	hcount = hcache_fill_caught_array(htype, hosts, num);
	g_assert(hcount >= 0 && hcount <= num);

	/* The most a pong can take is "xxx.xxx.xxx.xxx:yyyyy, ", i.e. 23 */
	if (hcount) {
		gint i;
		gpointer fmt = header_fmt_make(field, ", ",
			23 /* 23 == PONG_LEN */ * CONNECT_PONGS_COUNT + 30);

		for (i = 0; i < hcount; i++) {
			header_fmt_append_value(fmt, gnet_host_to_string(&hosts[i]));
		}

		header_fmt_end(fmt);
		line = header_fmt_to_string(fmt);
		header_fmt_free(fmt);
	}

	return line;		/* Pointer to static data */
}

/**
 * qsort() callback for sorting GTKG nodes at the front.
 */
static gint
node_gtkg_cmp(const void *np1, const void *np2)
{
	gnutella_node_t *n1 = *(gnutella_node_t **) np1;
	gnutella_node_t *n2 = *(gnutella_node_t **) np2;

	if (n1->flags & NODE_F_GTKG)
		return (n2->flags & NODE_F_GTKG) ? 0 : -1;

	if (n2->flags & NODE_F_GTKG)
		return (n1->flags & NODE_F_GTKG) ? 0 : +1;

	return 0;
}

/**
 * Inflate UDP payload, updating node internal data structures to reflect
 * the new payload size..
 *
 * @return success status, FALSE meaning the message was accounted as dropped
 * already.
 */
static gboolean
node_inflate_payload(gnutella_node_t *n)
{
	gint outlen = payload_inflate_buffer_len;
	gint ret;

	g_assert(NODE_IS_UDP(n));

	gnet_stats_count_general(GNR_UDP_RX_COMPRESSED, 1);

	if (!zlib_is_valid_header(n->data, n->size)) {
		if (udp_debug)
			g_warning("UDP got %s with non-deflated payload from %s",
				gmsg_infostr_full_split(&n->header, n->data), node_addr(n));
		gnet_stats_count_dropped(n, MSG_DROP_INFLATE_ERROR);
		return FALSE;
	}

	/*
	 * Start of payload looks OK, attempt inflation.
	 */

	ret = zlib_inflate_into(n->data, n->size, payload_inflate_buffer, &outlen);
	if (ret != Z_OK) {
		if (udp_debug)
			g_warning("UDP cannot inflate %s from %s: %s",
				gmsg_infostr_full_split(&n->header, n->data), node_addr(n),
				zlib_strerror(ret));
		gnet_stats_count_dropped(n, MSG_DROP_INFLATE_ERROR);
		return FALSE;
	}

	/*
	 * Inflation worked, update the header and the data pointers.
	 */

	n->data = payload_inflate_buffer;
	gnutella_header_set_ttl(&n->header,
		gnutella_header_get_ttl(&n->header) & ~GTA_UDP_DEFLATED);
	gnutella_header_set_size(&n->header, outlen);

	if (udp_debug)
		g_message("UDP inflated %d-byte payload from %s into %s",
			n->size, node_addr(n),
			gmsg_infostr_full_split(&n->header, n->data));

	n->size = outlen;

	return TRUE;
}

/**
 * Generate the "Peers:" and "Leaves:" headers in a static buffer.
 *
 * @return ready-to-insert header chunk, with all lines ending with "\r\n".
 */
static gchar *
node_crawler_headers(struct gnutella_node *n)
{
	static gchar buf[8192];				/* 8 KB */
	gnutella_node_t **ultras = NULL;	/* Array of ultra nodes */
	gnutella_node_t **leaves = NULL;	/* Array of `leaves' */
	gint ultras_len = 0;				/* Size of `ultras' */
	gint leaves_len = 0;				/* Size of `leaves' */
	gint ux = 0;						/* Index in `ultras' */
	gint lx = 0;						/* Index in `leaves' */
	gint uw = 0;						/* Amount of ultras written */
	gint lw = 0;						/* Amount of leaves written */
	GSList *sl;
	gint maxsize;
	gint rw;
	gint count;

	if (node_ultra_count) {
		ultras_len = node_ultra_count * sizeof(gnutella_node_t *);
		ultras = walloc(ultras_len);
	}

	if (node_leaf_count) {
		leaves_len = node_leaf_count * sizeof(gnutella_node_t *);
		leaves = walloc(leaves_len);
	}

	for (sl = sl_nodes; sl; sl = g_slist_next(sl)) {
		gnutella_node_t *cn = sl->data;

		if (!NODE_IS_ESTABLISHED(cn))
			continue;

		if (!is_host_addr(cn->gnet_addr))		/* No information yet */
			continue;

		if (NODE_IS_ULTRA(cn)) {
			g_assert((guint) ux < node_ultra_count);
			ultras[ux++] = cn;
			continue;
		}

		if (NODE_IS_LEAF(cn)) {
			g_assert((guint) lx < node_leaf_count);
			leaves[lx++] = cn;
			continue;
		}
	}

	/*
	 * Put gtk-gnutella nodes at the front of the array, so that their
	 * addresses are listed first, in case we cannot list everyone.
	 */

	if (ux)
		qsort(ultras, ux, sizeof(gnutella_node_t *), node_gtkg_cmp);
	if (lx)
		qsort(leaves, lx, sizeof(gnutella_node_t *), node_gtkg_cmp);

	/*
	 * Avoid sending an incomplete trailing IP address by roughly avoiding
	 * any write if less than 32 chars are available in the buffer.
	 */

	maxsize = sizeof(buf) - 32;

	/*
	 * First, the peers.
	 */

	rw = gm_snprintf(buf, sizeof(buf), "Peers: ");

	for (count = 0; count < ux && rw < maxsize; count++) {
		struct gnutella_node *cn = ultras[count];

		if (cn == n)				/* Don't show the crawler itself */
			continue;

		if (uw > 0)
			rw += gm_snprintf(&buf[rw], sizeof(buf)-rw, ", ");

		rw += gm_snprintf(&buf[rw], sizeof(buf)-rw, "%s",
				host_addr_port_to_string(cn->gnet_addr, cn->gnet_port));

		uw++;		/* One more ultra written */
	}

	rw += gm_snprintf(&buf[rw], sizeof(buf)-rw, "\r\n");

	if (current_peermode != NODE_P_ULTRA || rw >= maxsize)
		goto cleanup;

	/*
	 * We're an ultranode, list our leaves.
	 */

	rw += gm_snprintf(&buf[rw], sizeof(buf)-rw, "Leaves: ");

	for (count = 0; count < lx && rw < maxsize; count++) {
		struct gnutella_node *cn = leaves[count];

		if (cn == n)				/* Don't show the crawler itself */
			continue;

		if (lw > 0)
			rw += gm_snprintf(&buf[rw], sizeof(buf)-rw, ", ");

		rw += gm_snprintf(&buf[rw], sizeof(buf)-rw, "%s",
				host_addr_port_to_string(cn->gnet_addr, cn->gnet_port));

		lw++;		/* One more leaf written */
	}

	rw += gm_snprintf(&buf[rw], sizeof(buf)-rw, "\r\n");

	if (node_debug) g_message(
		"TCP crawler sending %d/%d ultra%s and %d/%d lea%s to %s",
			uw, ux, uw == 1 ? "" : "s",
			lw, lx, lw == 1 ? "f" : "ves",
			node_addr(n));

	/* FALL THROUGH */

cleanup:
	if (ultras)
		wfree(ultras, ultras_len);
	if (leaves)
		wfree(leaves, leaves_len);

	return buf;
}

/**
 * Send error message to remote end, a node presumably.
 *
 * @param s		the connected socket (mandatory)
 * @param n		the node (optional, NULL if not available)
 * @param code	the error code to report
 * @param msg	the error message (printf format)
 * @param ap	variable argument pointer, arguments for the error message
 */
static void
send_error(
	struct gnutella_socket *s, struct gnutella_node *n,
	int code, const gchar *msg, va_list ap)
{
	gchar gnet_response[2048];
	gchar msg_tmp[256];
	size_t rw;
	ssize_t sent;
	gboolean saturated = bsched_saturated(BSCHED_BWS_GOUT);
	const gchar *version;
	gchar *token;
	gchar xlive[128];
	gchar xtoken[128];
	gint pongs = saturated ? CONNECT_PONGS_LOW : CONNECT_PONGS_COUNT;

	socket_check(s);
	g_assert(n == NULL || n->socket == s);

	gm_vsnprintf(msg_tmp, sizeof(msg_tmp)-1,  msg, ap);

	/*
	 * Try to limit the size of our reply if we're saturating bandwidth.
	 */

	if (saturated) {
		xlive[0] = '\0';
		version = version_short_string;
		token = socket_omit_token(s) ? NULL : tok_short_version();
	} else {
		gm_snprintf(xlive, sizeof(xlive),
			"X-Live-Since: %s\r\n", start_rfc822_date);
		version = version_string;
		token = socket_omit_token(s) ? NULL : tok_version();
	}

	if (token)
		gm_snprintf(xtoken, sizeof(xtoken), "X-Token: %s\r\n", token);
	else
		xtoken[0] = '\0';

	/*
	 * If we have a node and we know that it is NOT a gtk-gnutella node,
	 * chances are it will not care about the token and the X-Live-Since.
	 *
	 * If it is a genuine gtk-gnutella node, give it the maximum amount
	 * of pongs though, to make it easier for the node to get a connection.
	 */

	if (n != NULL && n->vendor != NULL) {
		if (n->flags & NODE_F_GTKG) {
			if (!(n->flags & NODE_F_FAKE_NAME))	/* A genuine GTKG peer */
				pongs = CONNECT_PONGS_COUNT;	/* Give it the maximum */
		} else {
			xlive[0] = '\0';
			xtoken[0] = '\0';
		}
	}

	/*
	 * Do not send them any pong on 403 and 406 errors, even if GTKG.
	 * When banning, the error code is 550 and does not warrant pongs either.
	 */

	if (code == 403 || code == 406 || code == 550)
		pongs = 0;

	/*
	 * Build the response.
	 */

	rw = gm_snprintf(gnet_response, sizeof(gnet_response),
		"GNUTELLA/0.6 %d %s\r\n"
		"User-Agent: %s\r\n"
		"Remote-IP: %s\r\n"
		"%s"		/* X-Token */
		"%s"		/* X-Live-Since */
		"%s"		/* X-Ultrapeer */
		"%s"		/* X-Try */
		"%s"		/* X-Try-Ultrapeers */
		"\r\n",
		code, msg_tmp, version, host_addr_to_string(s->addr), xtoken, xlive,
		current_peermode == NODE_P_NORMAL ? "" :
		current_peermode == NODE_P_LEAF ?
			"X-Ultrapeer: False\r\n": "X-Ultrapeer: True\r\n",
		(current_peermode == NODE_P_NORMAL && pongs) ?
			formatted_connection_pongs("X-Try", HOST_ANY, pongs) : "",
		(current_peermode != NODE_P_NORMAL && pongs) ?
			formatted_connection_pongs("X-Try-Ultrapeers", HOST_ULTRA, pongs)
			: ""
	);

	g_assert(rw < sizeof(gnet_response));

	sent = bws_write(BSCHED_BWS_GOUT, &s->wio, gnet_response, rw);
	if ((ssize_t) -1 == sent) {
		if (node_debug)
			g_warning("Unable to send back error %d (%s) to node %s: %s",
			code, msg_tmp, host_addr_to_string(s->addr), g_strerror(errno));
	} else if ((size_t) sent < rw) {
		if (node_debug) {
			g_warning("Only sent %d out of %d bytes of error %d (%s) "
				"to node %s: %s", (int) sent, (int) rw, code, msg_tmp,
				host_addr_to_string(s->addr), g_strerror(errno));
		}
	} else if (node_debug > 2) {
		g_message("----Sent error %d to node %s (%d bytes):\n%.*s----",
			code, host_addr_to_string(s->addr),
			(int) rw, (int) rw, gnet_response);
	}
}

/**
 * Send error message to remote end, a node presumably.
 *
 * @attention
 * NB: We don't need a node to call this routine, only a socket.
 */
void
send_node_error(struct gnutella_socket *s, int code, const gchar *msg, ...)
{
	va_list args;

	va_start(args, msg);
	send_error(s, NULL, code, msg, args);
	va_end(args);
}

/**
 * Send error message to remote node.
 */
static void
node_send_error(struct gnutella_node *n, int code, const gchar *msg, ...)
{
	va_list args;

	va_start(args, msg);
	send_error(n->socket, n, code, msg, args);
	va_end(args);
}

/**
 * Request that node becomes our push-proxy.
 */
static void
send_proxy_request(gnutella_node_t *n)
{
	g_assert(n->attrs & NODE_A_CAN_VENDOR);
	g_assert(is_firewalled);
	g_assert(!is_host_addr(n->proxy_addr));		/* Not proxying us yet */

	n->flags |= NODE_F_PROXY;
	vmsg_send_proxy_req(n, servent_guid); /* XXX: servent_guid is a property */
}

/**
 * Called when we were not firewalled and suddenly become firewalled.
 * Send proxy requests to our current connections.
 */
void
node_became_firewalled(void)
{
	GSList *sl;
	guint sent = 0;

	g_assert(is_firewalled);

	for (sl = sl_nodes; sl; sl = g_slist_next(sl)) {
		struct gnutella_node *n = sl->data;

		if (socket_listen_port() && sent < 10 && n->attrs & NODE_A_CAN_VENDOR) {
			vmsg_send_tcp_connect_back(n, socket_listen_port());
			sent++;

			if (node_debug)
				g_message("sent TCP connect back request to %s",
					host_addr_port_to_string(n->addr, n->port));
		}

		if (NODE_IS_LEAF(n))
			continue;

		if (!is_host_addr(n->proxy_addr) && (n->attrs & NODE_A_CAN_VENDOR))
			send_proxy_request(n);
	}
}

/**
 * Called when we were not firewalled and suddenly become UDP firewalled.
 * Send UDP connect back requests to our current connections.
 */
void
node_became_udp_firewalled(void)
{
	GSList *sl;
	guint sent = 0;

	g_assert(is_udp_firewalled);

	if (0 == socket_listen_port())
		return;

	for (sl = sl_nodes; sl; sl = g_slist_next(sl)) {
		struct gnutella_node *n = sl->data;

		if (0 == (n->attrs & NODE_A_CAN_VENDOR))
			continue;

		vmsg_send_udp_connect_back(n, socket_listen_port());
		if (node_debug)
			g_message("sent UDP connect back request to %s",
				host_addr_port_to_string(n->addr, n->port));

		if (10 == ++sent)
			break;
	}
}

/***
 *** TX deflate callbacks
 ***/

static void
node_add_tx_deflated(gpointer o, gint amount)
{
	gnutella_node_t *n = o;

	n->tx_deflated += amount;
}

static void
node_tx_shutdown(gpointer o, const gchar *reason, ...)
{
	gnutella_node_t *n = o;
	va_list args;

	va_start(args, reason);
	node_shutdown_v(n, reason, args);
	va_end(args);
}

static struct tx_deflate_cb node_tx_deflate_cb = {
	node_add_tx_deflated,		/* add_tx_deflated */
	node_tx_shutdown,			/* shutdown */
};

/***
 *** TX link callbacks
 ***/

static void
node_add_tx_written(gpointer o, gint amount)
{
	gnutella_node_t *n = o;

	n->tx_written += amount;
}

static void
node_tx_eof_remove(gpointer o, const gchar *reason, ...)
{
	gnutella_node_t *n = o;
	va_list args;

	va_start(args, reason);
	socket_eof(n->socket);
	node_remove_v(n, reason, args);
	va_end(args);
}

static void
node_tx_eof_shutdown(gpointer o, const gchar *reason, ...)
{
	gnutella_node_t *n = o;
	va_list args;

	va_start(args, reason);
	socket_eof(n->socket);
	node_shutdown_v(n, reason, args);
	va_end(args);
}

static void
node_tx_unflushq(gpointer o)
{
	gnutella_node_t *n = o;

	node_unflushq(n);
}

static struct tx_link_cb node_tx_link_cb = {
	node_add_tx_written,		/* add_tx_written */
	node_tx_eof_remove,			/* eof_remove */
	node_tx_eof_shutdown,		/* eof_shutdown */
	node_tx_unflushq,			/* unflushq */
};

/***
 *** TX datagram callbacks
 ***/

static struct tx_dgram_cb node_tx_dgram_cb = {
	node_add_tx_written,		/* add_tx_written */
};

/***
 *** RX inflate callbacks
 ***/

static void 
node_add_rx_inflated(gpointer o, gint amount)
{
	gnutella_node_t *n = o;

	n->rx_inflated += amount;
}

static void 
node_rx_inflate_error(gpointer o, const gchar *reason, ...)
{
	gnutella_node_t *n = o;
	va_list args;

	va_start(args, reason);
	node_mark_bad_vendor(n);
	node_bye_v(n, 501, reason, args);
	va_end(args);
}

static struct rx_inflate_cb node_rx_inflate_cb = {
	node_add_rx_inflated,		/* add_rx_inflated */
	node_rx_inflate_error,		/* inflate_error */
};

/***
 *** RX link callbacks
 ***/

static void
node_add_rx_given(gpointer o, ssize_t amount)
{
	gnutella_node_t *n = o;

	n->rx_given += amount;
}

static void
node_rx_read_error(gpointer o, const gchar *reason, ...)
{
	gnutella_node_t *n = o;
	va_list args;

	va_start(args, reason);
	node_eof_v(n, reason, args);
	va_end(args);
}

static void
node_rx_got_eof(gpointer o)
{
	gnutella_node_t *n = o;

	if (n->n_ping_sent <= 2 && n->n_pong_received)
		node_eof(n, NG_("Got %d connection pong", "Got %d connection pongs",
			n->n_pong_received), n->n_pong_received);
	else
		node_eof(n, "Failed (EOF)");
}

static struct rx_link_cb node_rx_link_cb = {
	node_add_rx_given,			/* add_rx_given */
	node_rx_read_error,			/* read_error */
	node_rx_got_eof,			/* got_eof */
};

/**
 * Called when we know that we're connected to the node, at the end of
 * the handshaking (both for incoming and outgoing connections).
 */
static void
node_is_now_connected(struct gnutella_node *n)
{
	struct gnutella_socket *s = n->socket;
	txdrv_t *tx;
	gboolean peermode_changed = FALSE;
	gnet_host_t host;

	socket_check(s);

	/*
	 * Temporary: if node is not a broken GTKG node, record it.
	 */

	if (!(n->attrs & NODE_A_NO_DUPS))
		sl_nodes_without_broken_gtkg =
			g_slist_prepend(sl_nodes_without_broken_gtkg, n);

	/*
	 * Cleanup hanshaking objects.
	 */

	if (n->io_opaque)				/* None for outgoing 0.4 connections */
		io_free(n->io_opaque);
	if (n->socket->getline) {
		getline_free(n->socket->getline);
		n->socket->getline = NULL;
	}

	/*
	 * Terminate crawler connection that goes through the whole 3-way
	 * handshaking protocol.
	 */

	if (n->flags & NODE_F_CRAWLER) {
		node_remove(n, _("Sent crawling info"));
		return;
	}

	/*
	 * Make sure we did not change peermode whilst performing the 3-way
	 * handshaking with this node.
	 */

	peermode_changed =
		n->start_peermode != current_peermode ||
		n->start_peermode != peermode.new;

	/*
	 * Determine correct peer mode.
	 *
	 * If we're a leaf node and we connected to an ultranode, send it
	 * our query routing table.
	 */

	n->peermode = NODE_P_NORMAL;

	if (n->flags & NODE_F_ULTRA) {
		if (current_peermode != NODE_P_NORMAL)
			n->peermode = NODE_P_ULTRA;
	} else if (n->flags & NODE_F_LEAF) {
		if (current_peermode == NODE_P_ULTRA)
			n->peermode = NODE_P_LEAF;
	} else if (n->attrs & NODE_A_ULTRA)
		n->peermode = NODE_P_ULTRA;

	/* If peermode did not change, current_peermode = leaf => node is Ultra */
	g_assert(peermode_changed ||
		current_peermode != NODE_P_LEAF || NODE_IS_ULTRA(n));

	/*
	 * Update state, and mark node as valid.
	 */

	n->status = GTA_NODE_CONNECTED;
	n->flags |= NODE_F_VALID;
	n->last_update = n->connect_date = tm_time();

	connected_node_cnt++;

	/*
	 * Count nodes by type.
	 */

	switch (n->peermode) {
	case NODE_P_LEAF:
		gnet_prop_set_guint32_val(PROP_NODE_LEAF_COUNT,
			node_leaf_count + 1);
		break;
	case NODE_P_NORMAL:
		gnet_prop_set_guint32_val(PROP_NODE_NORMAL_COUNT,
			node_normal_count + 1);
		break;
	case NODE_P_ULTRA:
		gnet_prop_set_guint32_val(PROP_NODE_ULTRA_COUNT,
			node_ultra_count + 1);
		break;
	case NODE_P_AUTO:
	case NODE_P_CRAWLER:
	case NODE_P_UDP:
	case NODE_P_UNKNOWN:
		break;
	}

	/*
	 * Determine the frequency at which we will send "alive pings", and at
	 * which we shall accept regular pings on that connection.
	 */

	n->ping_throttle = PING_REG_THROTTLE;

	switch ((node_peer_t) current_peermode) {
	case NODE_P_NORMAL:
		n->alive_period = ALIVE_PERIOD;
		break;
	case NODE_P_ULTRA:
		if (n->peermode == NODE_P_LEAF) {
			n->alive_period = ALIVE_PERIOD_LEAF;
			n->ping_throttle = PING_LEAF_THROTTLE;
		} else
			n->alive_period = ALIVE_PERIOD;
		break;
	case NODE_P_LEAF:
		n->alive_period = ALIVE_PERIOD_LEAF;
		break;
	case NODE_P_AUTO:
	case NODE_P_CRAWLER:
	case NODE_P_UDP:
	case NODE_P_UNKNOWN:
		g_error("Invalid peer mode %d", current_peermode);
		break;
	}

	/*
	 * Create the RX stack, and enable reception of data.
	 */

	gnet_host_set(&host, n->addr, n->port);

	{
		struct rx_link_args args;

		args.cb = &node_rx_link_cb;
		args.bws = n->peermode == NODE_P_LEAF
				? BSCHED_BWS_GLIN : BSCHED_BWS_GIN;
		args.wio = &n->socket->wio;

		n->rx = rx_make(n, &host, rx_link_get_ops(), &args);
	}

	if (n->attrs & NODE_A_RX_INFLATE) {
		struct rx_inflate_args args;

		if (node_debug > 4)
			g_message("receiving compressed data from node %s", node_addr(n));

		args.cb = &node_rx_inflate_cb;

		n->rx = rx_make_above(n->rx, rx_inflate_get_ops(), &args);

		if (n->flags & NODE_F_LEAF)
			compressed_leaf_cnt++;
        compressed_node_cnt++;
	}

	rx_set_data_ind(n->rx, node_data_ind);
	rx_enable(n->rx);
	n->flags |= NODE_F_READABLE;

	/*
	 * Create the TX stack, as we're going to transmit Gnet messages.
	 */

	{
		struct tx_link_args args;

		args.cb = &node_tx_link_cb;
		args.bws = n->peermode == NODE_P_LEAF
					? BSCHED_BWS_GLOUT : BSCHED_BWS_GOUT;
		args.wio = &n->socket->wio;

		tx = tx_make(n, &host, tx_link_get_ops(), &args);	/* Cannot fail */
	}

	/*
	 * If we committed on compressing traffic, install layer.
	 */

	if (n->attrs & NODE_A_TX_DEFLATE) {
		struct tx_deflate_args args;
		txdrv_t *ctx;

		if (node_debug > 4)
			g_message("sending compressed data to node %s", node_addr(n));

		args.cq = callout_queue;
		args.cb = &node_tx_deflate_cb;
		args.nagle = TRUE;
		args.gzip = FALSE;
		args.buffer_size = NODE_TX_BUFSIZ;
		args.buffer_flush = NODE_TX_FLUSH;

		ctx = tx_make_above(tx, tx_deflate_get_ops(), &args);
		if (ctx == NULL) {
			tx_free(tx);
			node_remove(n, _("Cannot setup compressing TX stack"));
			return;
		}

		tx = ctx;		/* Use compressing stack */
	}

	g_assert(tx);

	n->outq = mq_tcp_make(node_sendqueue_size, n, tx);
	n->flags |= NODE_F_WRITABLE;
	n->alive_pings = alive_make(n, n->alive_period == ALIVE_PERIOD ?
		ALIVE_MAX_PENDING : ALIVE_MAX_PENDING_LEAF);

	/*
	 * In ultra mode, we're not broadcasting queries blindly, we're using
	 * dynamic querying, so there is no need for a per-node search queue.
	 */

	if (current_peermode != NODE_P_ULTRA)
		n->searchq = sq_make(n);

	/*
	 * Terminate connection if the peermode changed during handshaking.
	 */

	if (peermode_changed) {
		node_bye(n, 504, "Switched between Leaf/Ultra during handshake");
		return;
	}

	/*
	 * Initiate QRP sending if we're a leaf node or if we're an ultra node
	 * and the remote note is an UP supporting last-hop QRP.
	 */

	if (
		current_peermode == NODE_P_LEAF ||
		(current_peermode == NODE_P_ULTRA && (n->attrs & NODE_A_UP_QRP))
	) {
		gpointer qrt = qrt_get_table();

		/*
		 * If we don't even have our first QRT computed yet, we
		 * will send it to the ultranode when node_qrt_changed()
		 * is called by the computation code.
		 */

		if (qrt)
			node_send_qrt(n, qrt);
	}

	/*
	 * Set the socket's send buffer size to a small value, to make sure we
	 * flow control early.  Use their setup for the receive buffer.
	 */

	sock_send_buf(s, NODE_IS_LEAF(n) ?
		NODE_SEND_LEAF_BUFSIZE : NODE_SEND_BUFSIZE, TRUE);

	sock_recv_buf(s, node_rx_size * 1024, TRUE);

	/*
	 * If we have an incoming connection, send an "alive" ping.
	 * Otherwise, send a "handshaking" ping.
	 */

	if (n->flags & NODE_F_INCOMING)
		alive_send_ping(n->alive_pings);
	else
		pcache_outgoing_connection(n);	/* Will send proper handshaking ping */

	/*
	 * If node supports vendor-specific messages, advertise the set we support.
	 *
	 * If we are firewalled, and remote node supports vendor-specific
	 * messages, send a connect back, to see whether we are firewalled.
	 */

	if (n->attrs & NODE_A_CAN_VENDOR) {
		vmsg_send_messages_supported(n);
		if (is_firewalled) {
			if (0 != socket_listen_port())
				vmsg_send_tcp_connect_back(n, socket_listen_port());
			if (!NODE_IS_LEAF(n))
				send_proxy_request(n);
		}
		if (udp_active()) {
			if (!recv_solicited_udp)
				udp_send_ping(n->addr, n->port);
			else if (is_udp_firewalled && 0 != socket_listen_port())
				vmsg_send_udp_connect_back(n, socket_listen_port());
		}
	}

	/*
	 * If we're an Ultranode, we're going to monitor the queries sent by
	 * our leaves and by our neighbours.
	 */

	if (current_peermode != NODE_P_LEAF) {
		if (NODE_IS_LEAF(n))
			n->qseen = g_hash_table_new(g_str_hash, g_str_equal);
		else {
			if (node_watch_similar_queries) {
				n->qrelayed = g_hash_table_new(g_str_hash, g_str_equal);
				n->qrelayed_created = tm_time();
			}
		}
	}

	/*
	 * Update the GUI.
	 */

    node_fire_node_info_changed(n);
    node_fire_node_flags_changed(n);

	node_added = n;
	g_hook_list_invoke(&node_added_hook_list, TRUE);
	node_added = NULL;
}

/**
 * Received a Bye message from remote node.
 */
static void
node_got_bye(struct gnutella_node *n)
{
	guint16 code;
	gchar *message = n->data + 2;
	guchar c;
	guint cnt;
	gchar *p;
	gboolean warned = FALSE;
	gboolean is_plain_message = TRUE;
	guint message_len = n->size - 2;

	READ_GUINT16_LE(n->data, code);

	/*
	 * Codes are supposed to be 2xx, 4xx or 5xx.
	 *
	 * But older GnucDNA wer bugged enough to forget about the code and
	 * started to emit the message right away.  Fortunately, we can
	 * detect this because the two ASCII bytes will make the code
	 * appear out of range...  We force code 901 when we detect and
	 * correct this bug.
	 *
	 *		--RAM, 2004-10-19, revised 2005-09-30
	 */

	if (code > 999) {
		guchar c1 = n->data[0];
		guchar c2 = n->data[1];

		if (is_ascii_alnum(c1) && is_ascii_alnum(c2)) {
			message = n->data;
			message_len = n->size;
			code = 901;
		}
	}

	/*
	 * The first line can end with <cr><lf>, in which case we have an RFC-822
	 * style header in the packet.  Since the packet may not be NUL terminated,
	 * perform the scan manually.
	 */

	for (cnt = 0, p = message; cnt < message_len; cnt++, p++) {
		c = *p;
		if (c == '\0') {			/* NUL marks the end of the message */
			if (node_debug && cnt != message_len - 1)
				g_warning("BYE message %u from %s <%s> has early NUL",
					code, node_addr(n), node_vendor(n));
			break;
		} else if (c == '\r') {
			if (++cnt < n->size) {
				if ((c = *(++p)) == '\n') {
					is_plain_message = FALSE;
					message_len = (p - message + 1) - 2;  /* 2 = len("\r\n") */
					break;
				} else {
					p--;			/* Undo our look-ahead */
					cnt--;
				}
			}
			continue;
		}
		if (c && c < ' ' && !warned) {
			warned = TRUE;
			if (node_debug)
				g_warning("BYE message %u from %s <%s> contains control chars",
					code, node_addr(n), node_vendor(n));
		}
	}

	if (!is_plain_message) {
		/* XXX parse header */
		if (node_debug)
			g_message("----Bye Message from %s:\n%.*s----",
				node_addr(n), (gint) n->size - 2, message);
	}

	if (node_debug)
		g_warning("%s node %s (%s) sent us BYE %d %.*s",
			node_type(n), node_addr(n), node_vendor(n),
			code, (int) MIN(120, message_len), message);

	node_remove(n, _("Got BYE %d %.*s"), code,
		(int) MIN(120, message_len), message);
}


/**
 * Whether they want to be "online" within Gnutella or not.
 */
void
node_set_online_mode(gboolean on)
{
	GSList *sl;

	if (allow_gnet_connections == on)		/* No change? */
		return;

	allow_gnet_connections = on;

	if (on)
		return;

	/*
	 * They're disallowing Gnutella connections.
	 */

	for (sl = sl_nodes; sl; sl = g_slist_next(sl)) {
		struct gnutella_node *n = sl->data;

		if (n->status == GTA_NODE_REMOVING)
			continue;

		node_bye_if_writable(n, 202, "User going offline");
	}
}

/**
 * Called from the property system when current peermode is changed.
 */
void
node_current_peermode_changed(node_peer_t mode)
{
	/*
	 * Only record the fact that it changed.
	 *
	 * We'll react by calling node_set_current_peermode() later, in the
	 * node_timer() routine, so that we do not close connections in the
	 * middle of the handshaking handling routing.
	 */

	peermode.changed = TRUE;
	peermode.new = mode;
}

/**
 * Called from the node timer when the current peermode has changed.
 *
 * We call this "asynchronously" because the current peermode can change
 * during handshaking, when we accept the guidance of the remote ultrapeer
 * to become a leaf node.
 */
static void
node_set_current_peermode(node_peer_t mode)
{
	static node_peer_t old_mode = NODE_P_UNKNOWN;
	const gchar *msg = NULL;

	if (NODE_P_UNKNOWN == old_mode)
		old_mode = configured_peermode;

	switch (mode) {
	case NODE_P_NORMAL:
		msg = "normal";
		node_bye_flags(NODE_F_LEAF, 203, "Becoming a regular node");
		if (old_mode == NODE_P_LEAF)
			node_bye_flags(NODE_F_ULTRA, 203, "Becoming a regular node");
		break;
	case NODE_P_ULTRA:
		msg = "ultra";
		if (old_mode == NODE_P_LEAF)
			node_bye_flags(NODE_F_ULTRA, 203, "Becoming an ultra node");
		break;
	case NODE_P_LEAF:
		msg = "leaf";
		if (old_mode != NODE_P_LEAF)
			node_bye_flags(0xffffffff, 203, "Becoming a leaf node");
		break;
	case NODE_P_AUTO:
	case NODE_P_CRAWLER:
	case NODE_P_UDP:
	case NODE_P_UNKNOWN:
		g_error("unhandled mode %d", mode);
		break;
	}

	g_assert(msg != NULL);
	if (node_debug > 2)
		g_message("Switching to \"%s\" peer mode", msg);

	if (old_mode != NODE_P_UNKNOWN) {	/* Not at init time */
		bsched_set_peermode(mode);		/* Adapt Gnet bandwidth */
		pcache_set_peermode(mode);		/* Adapt pong cache lifetime */
		qrp_peermode_changed();			/* Compute proper routing table */
		sq_set_peermode(mode);			/* Possibly discard the global SQ */
	}

	dbus_util_send_message(DBS_EVT_PEERMODE_CHANGE, msg);

	old_mode = mode;
}

static guint
feed_host_cache_from_string(const gchar *s, host_type_t type, const gchar *name)
{
	guint n;

    g_assert((guint) type < HOST_MAX);
	g_assert(s);

	for (n = 0; NULL != s; s = strchr(s, ',')) {
		host_addr_t addr;
		guint16 port;

		if (',' == s[0])
			s++;

		s = skip_ascii_spaces(s);
		string_to_host_addr(s, &s, &addr);
		if (!is_host_addr(addr))
			continue;

		if (':' == s[0]) {
			guint32 u;
			gint error;

			s++;
			u = parse_uint32(s, &s, 10, &error);
			port = (error || u < 1024 || u > 65535) ? 0 : u;
		} else {
			port = GTA_PORT;
		}

		if (!port)
			continue;

		hcache_add_caught(type, addr, port, name);
		n++;
	}

	return n;
}

/**
 * Extract host:port information out of a header field and add those to our
 * pong cache. If ``gnet'' is TRUE, the header names without a leading
 * "X-" are checked as variants as well.
 *
 * @param header a valid header_t.
 * @param sender the host_type_t of the sender, if unknown use HOST_ANY.
 * @param gnet should be set to TRUE if the headers come from a Gnutella
 *			handshake.
 * @param peer the peer address who sent the headers.
 *
 * @return the amount of valid peer addresses we parsed.
 *
 * The syntax we expect is:
 *
 *   <header>: <peer> ("," <peer>)*
 *
 *   peer =		<host> [":" <port>] [any except ","]*
 *   header =	"Alt" | Listen-Ip" | "Listen-Ip" |
 *				"My-Address" | "Node" | "Try" | "Try-Ultrapeers"
 *
 */
guint
feed_host_cache_from_headers(header_t *header,
	host_type_t sender, gboolean gnet, const host_addr_t peer)
{
	static const struct {
		const gchar *name;	/* Name of the header */
		gboolean sender;	/* Host type is derived from sender */
		gboolean gnet;		/* Definitely a Gnutella network header */
		host_type_t type;	/* Default type, sender will override */
	} headers[] = {
		{ "X-Alt",				FALSE,	FALSE, HOST_ANY },
		{ "X-Listen-Ip",		TRUE,	TRUE,  HOST_ANY },
		{ "X-My-Address",		TRUE,	TRUE,  HOST_ANY },
		{ "X-Node",				TRUE,	TRUE,  HOST_ANY },
		{ "X-Try",				FALSE,	TRUE,  HOST_ANY },
		{ "X-Try-Ultrapeers",	FALSE,	TRUE,  HOST_ULTRA },
	};
	guint i, n = 0;

	g_assert(header);
    g_assert((guint) sender < HOST_MAX);

	for (;;) {
		for (i = 0; i < G_N_ELEMENTS(headers); i++) {
			const gchar *val, *name, *p;
			host_type_t type;
			guint r;

			/*
			 * One cannot assume that the same port will always be used for
			 * Gnutella connections and HTTP connections.  Do not collect
			 * addresses from ambiguous headers unless we're low on pongs.
			 */

			if (!gnet && !headers[i].gnet && !host_low_on_pongs)
				continue;

			name = headers[i].name;
			if (gnet && NULL != (p = is_strprefix(name, "X-")))
				name = p;

			type = headers[i].sender ? sender : headers[i].type;
			val = header_get(header, name);
			if (!val)
				continue;

			r = feed_host_cache_from_string(val, type, name);
			n += r;

			if (node_debug > 0) {
				if (r > 0)
					g_message("peer %s sent %u pong%s in %s header",
						host_addr_to_string(peer), r, 1 == r ? "" : "s", name);
				else
					g_message("peer %s sent an unparseable %s header",
						host_addr_to_string(peer), name);
			}
		}
		if (!gnet)
			break;
		gnet = FALSE;
	}

	return n;
}

/**
 * Extract the header pongs from the header (X-Try lines).
 * The node is only given for tracing purposes.
 */
static void
extract_header_pongs(header_t *header, struct gnutella_node *n)
{
	feed_host_cache_from_headers(header,
		NODE_P_ULTRA == n->peermode ? HOST_ULTRA : HOST_ANY,
		TRUE, n->addr);
}

/**
 * Try to determine whether headers contain an indication of our own IP.
 *
 * @return 0 if none found, or the indicated IP address.
 */
static host_addr_t
extract_my_addr(header_t *header)
{
	const gchar *field;
	host_addr_t addr;

	field = header_get(header, "Remote-Ip");
	if (!field)
		field = header_get(header, "X-Remote-Ip");

	if (field)
		string_to_host_addr(field, NULL, &addr);
	else
		addr = zero_host_addr;

	return addr;
}

/**
 * Checks for a Remote-IP or X-Remote-IP header and updates our IP address if
 * the current IP address is not enforced. Note that settings_addr_changed()
 * doesn't trust a single source.
 *
 * @param peer the IPv4 address of the peer who sent the header
 * @param head a header_t holding headers sent by the peer
 */
void
node_check_remote_ip_header(const host_addr_t peer, header_t *head)
{
	host_addr_t addr;

	g_assert(head != NULL);

	/*
	 * Remote-IP -- IP address of this node as seen from remote node
	 *
	 * Modern nodes include our own IP, as they see it, in the
	 * handshake headers and reply, whether it indicates a success or not.
	 * Use it as an opportunity to automatically detect changes.
	 *		--RAM, 13/01/2002
	 */

	if (force_local_ip)
		return;

	addr = extract_my_addr(head);
	if (!is_host_addr(addr) || host_addr_equal(addr, local_ip))
		return;

	if (node_debug > 0) {
		const gchar *ua;

		ua = header_get(head, "User-Agent");
		if (!ua)
			ua = header_get(head, "Server");
		if (!ua)
			ua = "Unknown";

		{
			gchar buf[HOST_ADDR_BUFLEN];

			host_addr_to_string_buf(addr, buf, sizeof buf);
			g_message("Peer %s reported different IP address: %s (%s)\n",
				host_addr_to_string(peer), buf, ua);
		}
	}

	settings_addr_changed(addr, peer);
}


/**
 * Analyses status lines we get from incoming handshakes (final ACK) or
 * outgoing handshakes (inital REPLY, after our HELLO)
 *
 * @return TRUE if acknowledgment was OK, FALSE if an error occurred, in
 * which case the node was removed with proper status.
 *
 * If `code' is not NULL, it is filled with the returned code, or -1 if
 * we were unable to parse the status.
 */
static gboolean
analyse_status(struct gnutella_node *n, gint *code)
{
	struct gnutella_socket *s = n->socket;
	const gchar *status;
	gint ack_code;
	guint major = 0, minor = 0;
	const gchar *ack_message = "";
	gboolean ack_ok = FALSE;
	gboolean incoming = (n->flags & NODE_F_INCOMING) ? TRUE : FALSE;
	const gchar *what = incoming ? "acknowledgment" : "reply";

	socket_check(s);
	status = getline_str(s->getline);

	ack_code = http_status_parse(status, "GNUTELLA",
		&ack_message, &major, &minor);

	if (code)
		*code = ack_code;

	if (node_debug)
		g_message("%s: code=%d, message=\"%s\", proto=%u.%u",
			incoming ? "ACK" : "REPLY",
			ack_code, ack_message, major, minor);

	if (ack_code == -1) {
		if (node_debug) {
			if (incoming || 0 != strcmp(status, "GNUTELLA OK")) {
				g_warning("weird GNUTELLA %s status line from %s",
					what, host_addr_to_string(n->addr));
				dump_hex(stderr, "Status Line", status,
					MIN(getline_length(s->getline), 80));
			} else
				g_warning("node %s gave a 0.4 reply to our 0.6 HELLO, dropping",
					node_addr(n));
		}
        hcache_add(HCACHE_UNSTABLE, n->addr, 0, "bad ack_code");
	} else {
		ack_ok = TRUE;
		n->flags |= NODE_F_VALID;		/* This is a Gnutella node */
	}

	if (ack_ok && (major != n->proto_major || minor != n->proto_minor)) {
		if (node_debug) {
			if (incoming)
				g_warning("node %s handshaked at %d.%d and now acks at %d.%d, "
					"adjusting", host_addr_to_string(n->addr),
					n->proto_major, n->proto_minor, major, minor);
			else
				g_warning("node %s was sent %d.%d HELLO but supports %d.%d "
					"only, adjusting", host_addr_to_string(n->addr),
					n->proto_major, n->proto_minor, major, minor);
		}
		n->proto_major = major;
		n->proto_minor = minor;
	}

	/*
	 * Is the connection OK?
	 */

	if (!ack_ok)
		node_remove(n, _("Weird HELLO %s"), what);
	else if (ack_code < 200 || ack_code >= 300) {
		if (ack_code == 401) {
            /* Unauthorized */
            hcache_add(HCACHE_UNSTABLE, n->addr, 0, "unauthorized");
        }

        if (ack_code == 503) {
            /* Busy */
            hcache_add(HCACHE_BUSY, n->addr, 0, "ack_code 503");
        }

		node_remove(n, _("HELLO %s error %d (%s)"), what, ack_code, ack_message);
		ack_ok = FALSE;
	}
	else if (!incoming && ack_code == 204) {
		node_remove(n, _("Shielded node"));
		ack_ok = FALSE;
	}

	return ack_ok;
}

/**
 * Can node accept connection?
 *
 * If `handshaking' is true, we're still in the handshaking phase, otherwise
 * we're already connected and can send a BYE.
 *
 * @return TRUE if we can accept the connection, FALSE otherwise, with
 * the node being removed.
 */
static gboolean
node_can_accept_connection(struct gnutella_node *n, gboolean handshaking)
{
	g_assert(handshaking || n->status == GTA_NODE_CONNECTED);
	g_assert(n->attrs & (NODE_A_NO_ULTRA|NODE_A_CAN_ULTRA));

	/*
	 * Deny cleanly if they deactivated "online mode".
	 */

	if (handshaking && !allow_gnet_connections) {
		node_send_error(n, 403,
			"Gnet connections currently disabled");
		node_remove(n, _("Gnet connections disabled"));
		return FALSE;
	}

	/*
	 * Always accept crawler connections.
	 */

	if (n->flags & NODE_F_CRAWLER)
		return TRUE;

	/*
	 * If we are handshaking, we have not incremented the node counts yet.
	 * Hence we can do >= tests against the limits.
	 */

	switch ((node_peer_t) current_peermode) {
	case NODE_P_ULTRA:

		if (n->flags & NODE_F_FORCE)
			return TRUE;

		/*
		 * If we're an ultra node, we need to enforce leaf counts.
		 *
		 * We also enforce ultra node counts if we're issuing an outgoing
		 * connection, but for incoming ones, we'll try to let the other
		 * node become a leaf node, so don't enforce if we're still in the
		 * handshaking phase.
		 */

		if (n->flags & NODE_F_LEAF) {
			/*
			 * Try to preference compressed leaf nodes too
			 * 		-- JA, 08/06/2003
			 */
			if (
				prefer_compressed_gnet &&
				up_connections <= node_leaf_count - compressed_leaf_cnt &&
				!(n->attrs & NODE_A_CAN_INFLATE)
			) {
				node_send_error(n, 403,
					"Compressed connection prefered");
				node_remove(n, _("Connection not compressed"));
				return FALSE;
			}

			/*
			 * Remove leaves that do not allow queries when we are
			 * running out of slots.
			 */

			if (node_leaf_count >= max_leaves)
				(void) node_remove_useless_leaf(NULL);

			if (handshaking && node_leaf_count >= max_leaves) {
				node_send_error(n, 503,
					"Too many leaf connections (%d max)", max_leaves);
				node_remove(n, _("Too many leaves (%d max)"), max_leaves);
				return FALSE;
			}
			if (!handshaking && node_leaf_count > max_leaves) {
				node_bye(n, 503,
					"Too many leaf connections (%d max)", max_leaves);
				return FALSE;
			}
		} else if (n->attrs & NODE_A_ULTRA) {
			guint ultra_max;

			/*
			 * Try to preference compressed ultrapeer connections too
			 * 		-- JA, 08/06/2003
			 */
			if (
				prefer_compressed_gnet &&
				up_connections <= node_ultra_count -
					(compressed_node_cnt - compressed_leaf_cnt) &&
				!(n->attrs & NODE_A_CAN_INFLATE)
			) {
				node_send_error(n, 403,
					"Compressed connection prefered");
				node_remove(n, _("Connection not compressed"));
				return FALSE;
			}

			ultra_max = max_connections > normal_connections
				? max_connections - normal_connections : 0;

			if (node_ultra_count >= ultra_max)
				(void) node_remove_useless_ultra(NULL);

			if (
				handshaking &&
				node_ultra_count >= ultra_max
			) {
				node_send_error(n, 503,
					"Too many ultra connections (%d max)", ultra_max);
				node_remove(n, _("Too many ultra nodes (%d max)"), ultra_max);
				return FALSE;
			}
			if (!handshaking && node_ultra_count > ultra_max) {
				node_bye(n, 503,
					"Too many ultra connections (%d max)", ultra_max);
				return FALSE;
			}
		}

		/*
		 * Enforce preference for compression only with non-leaf nodes.
		 */

		if (handshaking) {
			guint connected = node_normal_count + node_ultra_count;

            if (
				prefer_compressed_gnet &&
				!(n->attrs & NODE_A_CAN_INFLATE) &&
				(
					((n->flags & NODE_F_INCOMING) &&
					connected >= up_connections &&
					connected > compressed_node_cnt)
					||
					(n->flags & NODE_F_LEAF)
				)
			) {
				node_send_error(n, 403,
					"Gnet connection not compressed");
				node_remove(n, _("Connection not compressed"));
				return FALSE;
			}
		}

		/*
		 * If we have already enough normal nodes, reject a normal node.
		 */

		if (
			handshaking &&
			(n->attrs & NODE_A_NO_ULTRA) &&
			node_normal_count >= normal_connections
		) {
			if (normal_connections)
				node_send_error(n, 503,
					"Too many normal nodes (%d max)", normal_connections);
			else
				node_send_error(n, 403, "Normal nodes refused");
			node_remove(n, _("Rejected normal node (%d max)"),
				normal_connections);
			return FALSE;
		}

		break;
	case NODE_P_NORMAL:
		if (n->flags & NODE_F_FORCE)
			return TRUE;

		if (handshaking) {
			guint connected = node_normal_count + node_ultra_count;
			if (
				(n->attrs & (NODE_A_CAN_ULTRA|NODE_A_ULTRA)) == NODE_A_CAN_ULTRA
			) {
				node_send_error(n, 503, "Cannot accept leaf node");
				node_remove(n, _("Rejected leaf node"));
				return FALSE;
			}
			if (connected >= max_connections) {
				node_send_error(n, 503,
					"Too many Gnet connections (%d max)", max_connections);
				node_remove(n, _("Too many nodes (%d max)"), max_connections);
				return FALSE;
			}
			if (
				prefer_compressed_gnet &&
				(n->flags & NODE_F_INCOMING) &&
				!(n->attrs & NODE_A_CAN_INFLATE) &&
				connected >= up_connections &&
				connected > compressed_node_cnt
			) {
				node_send_error(n, 403,
					"Gnet connection not compressed");
				node_remove(n, _("Connection not compressed"));
				return FALSE;
			}
		} else if (node_normal_count + node_ultra_count > max_connections) {
			node_bye(n, 503,
				"Too many Gnet connections (%d max)", max_connections);
			return FALSE;
		}
		break;
	case NODE_P_LEAF:

		/* Even forced connections are not acceptable unless
		 * the remote node is an ultrapeer. Note: There is also
		 * an assertion in node_process_handshake_header().
		 */
		if ((n->flags & NODE_F_FORCE) && (n->attrs & NODE_A_ULTRA))
			return TRUE;

		if (handshaking) {
			/*
			 * If we're a leaf node, we can only accept incoming connections
			 * from an ultra node.
			 *
			 * The Ultrapeer specs say that two leaf nodes not finding
			 * Ultrapeers could connect to each other like two normal nodes,
			 * but I don't want to support that.  It's insane.
			 *		--RAM, 11/01/2003
			 */

			if (!(n->attrs & NODE_A_ULTRA)) {
				node_send_error(n, 204,
					"Shielded leaf node (%d peers max)", max_ultrapeers);
				node_remove(n, _("Sent shielded indication"));
				return FALSE;
			}

			if (!(n->attrs & NODE_A_ULTRA)) {
				node_send_error(n, 503, "Looking for an ultra node");
				node_remove(n, _("Not an ultra node"));
				return FALSE;
			}

			if (node_ultra_count >= max_ultrapeers) {
				node_send_error(n, 503,
					"Too many ultra connections (%d max)", max_ultrapeers);
				node_remove(n, _("Too many ultra nodes (%d max)"),
					max_ultrapeers);
				return FALSE;
			}

			/*
			 * Honour the prefer compressed connection setting. Even when making
			 * outgoing connections in leaf mode
			 * 		-- JA 24/5/2003
			 */
			if (
				prefer_compressed_gnet &&
				up_connections <= node_ultra_count - compressed_node_cnt &&
				!(n->attrs & NODE_A_CAN_INFLATE)
			) {
				node_send_error(n, 403,
					"Compressed connection prefered");
				node_remove(n, _("Connection not compressed"));
				return FALSE;
			}
		} else if (node_ultra_count > max_ultrapeers) {
			node_bye(n, 503,
				"Too many ultra connections (%d max)", max_ultrapeers);
			return FALSE;
		}
		break;
	case NODE_P_AUTO:
	case NODE_P_CRAWLER:
	case NODE_P_UDP:
	case NODE_P_UNKNOWN:
		g_assert_not_reached();
		break;
	}

	/*
	 * If a specific client version has proven to be very unstable during this
	 * version, don't connect to it.
	 *		-- JA 17/7/200
	 */

	if (n->attrs & NODE_A_ULTRA) {
		const gchar *msg = "Unknown error";
		enum node_bad bad = node_is_bad(n);

		switch (bad) {
		case NODE_BAD_OK:
			break;
		case NODE_BAD_IP:
			msg = _("Unstable IP address");
			break;
		case NODE_BAD_VENDOR:
			msg = _("Servent version appears unstable");
			break;
		case NODE_BAD_NO_VENDOR:
			msg = _("No vendor string supplied");
			break;
		}

		if (NODE_BAD_OK != bad) {
			node_send_error(n, 403, "%s", msg);
			node_remove(n, _("Not connecting: %s"), msg);
			return FALSE;
		}
	}

	return TRUE;
}

/**
 * Check whether we can accept a servent supporting a foreign protocol.
 * Must be called during handshaking.
 *
 * @return TRUE if OK, FALSE if connection was denied.
 */
static gboolean
node_can_accept_protocol(struct gnutella_node *n, header_t *head)
{
	const gchar *field;

	/*
	 * Accept -- protocols supported
	 *
	 * We ban ultrapeers claiming support for "application/x-gnutella2" if
	 * we are an ultranode ourselves.
	 *
	 * Study has shown that this closed protocol is not inter-operating
	 * well with Gnutella: it is more comparable to massive leaching.
	 * See the various GDF articles written on the subject that prove this.
	 *		--RAM, 25/01/2003
	 */

	field = header_get(head, "Accept");
	if (field) {
		if (
			current_peermode != NODE_P_LEAF &&
			!(n->flags & NODE_F_LEAF) &&
			strstr(field, "application/x-gnutella2") /* XXX parse the "," */
		) {
			static const gchar msg[] = N_("Protocol not acceptable");

			node_send_error(n, 406, msg);
			node_remove(n, _(msg));
			return FALSE;
		}
	}

	return TRUE;
}

/**
 * This routine is called to process the whole 0.6+ final handshake header
 * acknowledgement we get back after welcoming an incoming node.
 */
static void
node_process_handshake_ack(struct gnutella_node *n, header_t *head)
{
	struct gnutella_socket *s = n->socket;
	gboolean ack_ok;
	const gchar *field;
	gboolean qrp_final_set = FALSE;

	socket_check(s);

	if (node_debug) {
		g_message("got final acknowledgment headers from node %s:",
			host_addr_to_string(n->addr));
		dump_hex(stdout, "Status Line", getline_str(s->getline),
			MIN(getline_length(s->getline), 80));
		g_message("------ Header Dump:");
		header_dump(head, stderr);
		g_message("------");
		fflush(stderr);
	}

	ack_ok = analyse_status(n, NULL);
	extract_header_pongs(head, n);		/* Some servents always send X-Try-* */

	if (!ack_ok)
		return;			/* s->getline will have been freed by node removal */

	/*
	 * Get rid of the acknowledgment status line.
	 */

	getline_free(s->getline);
	s->getline = NULL;

	/*
	 * Content-Encoding -- compression accepted by the remote side
	 */

	field = header_get(head, "Content-Encoding");
	if (field) {
		/* XXX needs more rigourous parsing */
		if (strstr(field, "deflate"))
			n->attrs |= NODE_A_RX_INFLATE;	/* We shall decompress input */
	}

	if (!gnet_deflate_enabled && (n->attrs & NODE_A_RX_INFLATE)) {
		g_warning("Content-Encoding \"deflate\" although disabled - from"
			   " node %s <%s>", node_addr(n), node_vendor(n));
        node_bye(n, 400, "Compression was not accepted");
		return;
	}


	/* X-Ultrapeer -- support for ultra peer mode */

	field = header_get(head, "X-Ultrapeer");
	if (field && 0 == ascii_strcasecmp(field, "false")) {
		n->attrs &= ~NODE_A_ULTRA;
		if (current_peermode == NODE_P_ULTRA) {
			n->flags |= NODE_F_LEAF;		/* Remote accepted to become leaf */
			if (node_debug) g_warning(
				"node %s <%s> accepted to become our leaf",
				node_addr(n), node_vendor(n));
		}
	}

	/*
	 * X-Query-Routing -- QRP protocol in use by remote servent (negotiated)
	 *
	 * This header is present in the 3rd handshake only when the two servents
	 * advertised different support.  This last indication is the highest
	 * version supported by the remote end, that is less or equals to ours.
	 * (If not present, it means the remote end implicitly expects us to
	 * comply with his older version.)
	 *
	 * If we don't support that version, we'll BYE the servent later.
	 */

	field = header_get(head, "X-Query-Routing");
	if (field) {
		guint major, minor;

		parse_major_minor(field, NULL, &major, &minor);
		if (major >= n->qrp_major || minor >= n->qrp_minor)
			if (node_debug) g_warning(
				"node %s <%s> now claims QRP version %u.%u, "
				"but advertised %u.%u earlier",
				node_addr(n), node_vendor(n), major, minor,
				(guint) n->qrp_major, (guint) n->qrp_minor);
		n->qrp_major = (guint8) major;
		n->qrp_minor = (guint8) minor;
		qrp_final_set = TRUE;
	}

	/*
	 * Install new node.
	 */

	g_assert(s->gdk_tag == 0);		/* Removed before callback called */

	node_is_now_connected(n);

	if (n->status != GTA_NODE_CONNECTED)	/* Something went wrong */
		return;

	/*
	 * Now that the Gnutella stack is up, BYE the node if we don't really
	 * support the right version for the necessary protocols.
	 */

	if (current_peermode != NODE_P_NORMAL) {
		/*
		 * Only BYE them if they finally declared to use a protocol we
		 * don't support yet, despite their knowing that we only support
		 * the 0.2 version.
		 */

		if (qrp_final_set && (n->qrp_major > 0 || n->qrp_minor > 2)) {
			node_bye(n, 505, "Query Routing protocol %u.%u not supported",
				(guint) n->qrp_major, (guint) n->qrp_minor);
			return;
		}
	}

	/*
	 * Make sure we do not exceed our maximum amout of connections.
	 * In particular, if the remote node did not obey our leaf guidance
	 * and we still have enough ultra nodes, BYE them.
	 */

	if (!node_can_accept_connection(n, FALSE))
		return;

	/*
	 * Since this is the third and final acknowledgement, the remote node
	 * is ready to send Gnutella data (and so are we, now that we got
	 * the final ack).  Mark the Gnutella connection as fully established,
	 * which means we'll be able to relay traffic to this node.
	 */

	n->flags |= NODE_F_ESTABLISHED;

	/*
	 * If we already have data following the final acknowledgment, feed it
	 * to to stack, from the bottom: we already read it into the socket's
	 * buffer, but we need to inject it at the bottom of the RX stack.
	 */

	if (s->pos > 0) {
		pdata_t *db;
		pmsg_t *mb;

		if (node_debug > 4)
			g_message("read %d Gnet bytes from node %s after handshake",
				(int) s->pos, node_addr(n));

		/*
		 * Prepare data buffer out of the socket's buffer.
		 */

		db = pdata_allocb_ext(s->buf, s->pos, pdata_free_nop, NULL);
		mb = pmsg_alloc(PMSG_P_DATA, db, 0, s->pos);

		/*
		 * The message is given to the RX stack, and it will be freed by
		 * the last function consuming it.
		 */

		rx_recv(rx_bottom(n->rx), mb);

		/* During rx_recv the node could be marked for removal again. In which
		 * case the socket is freed, so lets exit now.
		 *		-- JA 14/04/04
		 */
		if (NODE_IS_REMOVING(n))
			return;

		g_assert(n->socket == s);
		g_assert(s != NULL);

		/*
		 * We know that the message is synchronously delivered.  At this
		 * point, all the data have been consumed, and the socket buffer
		 * can be "emptied" my marking it holds zero data.
		 */

		s->pos = 0;

	}
}

/**
 * @return the header string that should be used to advertise our QRP version
 * in the reply to their handshake, as a pointer to static data.
 */
static const gchar *
node_query_routing_header(struct gnutella_node *n)
{
	/*
	 * We're backward compatible with 0.1, i.e. we fully support that version.
	 * If they advertised something under the level we support (0.2), then
	 * tell them we're at their version level so they are not confused.
	 *
	 * GTKG started to advertise 0.2 on 01/01/2004.
	 */

	if (n->qrp_major > 0 || n->qrp_minor >= 2)
		return "X-Query-Routing: 0.2\r\n";
	else
		return "X-Query-Routing: 0.1\r\n";	/* Only other possible level */
}

/**
 * This routine is called to process a 0.6+ handshake header.
 *
 * It is either called to process the reply to our sending a 0.6 handshake
 * (outgoing connections) or to parse the initial 0.6 headers (incoming
 * connections).
 */
static void
node_process_handshake_header(struct gnutella_node *n, header_t *head)
{
	static const gchar gtkg_vendor[] = "gtk-gnutella/";
	static const size_t gnet_response_max = 16 * 1024;
	gchar *gnet_response;
	size_t rw;
	gint sent;
	const gchar *field;
	gboolean incoming = (n->flags & NODE_F_INCOMING);
	const gchar *what = incoming ? "HELLO reply" : "HELLO acknowledgment";
	const gchar *compressing = "Content-Encoding: deflate\r\n";
	const gchar *empty = "";

	if (node_debug) {
		g_message("got %s handshaking headers from node %s:",
			incoming ? "incoming" : "outgoing",
			host_addr_to_string(n->addr));
		if (!incoming)
			dump_hex(stdout, "Status Line", getline_str(n->socket->getline),
				MIN(getline_length(n->socket->getline), 80));
		g_message("------ Header Dump:");
		header_dump(head, stderr);
		g_message("------");
		fflush(stderr);
	}

	if (in_shutdown) {
		node_send_error(n, 503, "Servent Shutdown");
		node_remove(n, _("Servent Shutdown"));
		return;			/* node_remove() has freed s->getline */
	}

	/*
	 * Handle common header fields, non servent-specific.
	 */

	/* User-Agent -- servent vendor identification */

	field = header_get(head, "User-Agent");
	if (field) {
		const gchar *token = header_get(head, "X-Token");
		if (!version_check(field, token, n->addr))
			n->flags |= NODE_F_FAKE_NAME;
        node_set_vendor(n, field);
	}

	if (NULL == field || !is_strprefix(field, gtkg_vendor)) {
		socket_disable_token(n->socket);
	}

	/*
	 * Spot remote GTKG nodes (even if faked name).
	 */

	if (n->vendor != NULL) {
		if (
			is_strprefix(n->vendor, gtkg_vendor) ||
			(*n->vendor == '!' && is_strprefix(&n->vendor[1], gtkg_vendor))
		) {
			version_t rver;

			n->flags |= NODE_F_GTKG;

			/*
			 * Look for known bugs in certain older GTKG servents:
			 */

			if (version_fill(n->vendor, &rver)) {
				/*
				 * All versions prior 0.96u of 2005-10-02 are known to be
				 * broken with respect to duplicate message handling.
				 */

				if (rver.timestamp < 1128204000)
					n->attrs |= NODE_A_NO_DUPS;

				/*
				 * Versions prior 0.96.2u of 2006-08-15 are broken when they
				 * act as UP and perform dynamic queries for leaves: they will
				 * ignore an "OOB results status" message with kept=0 and
				 * terminate the dynamic query on timeout waiting for that
				 * message.
				 */

				if (rver.timestamp < 1155592800)
					n->attrs |= NODE_A_NO_KEPT_ZERO;
			}
		}
	}

	/* Pong-Caching -- ping/pong reduction scheme */

	field = header_get(head, "Pong-Caching");
	if (field) {
		guint major, minor;

		parse_major_minor(field, NULL, &major, &minor);
		if (major != 0 && minor != 1)
			if (node_debug) g_warning(
				"node %s claims Pong-Caching version %u.%u",
				node_addr(n), major, minor);
		n->attrs |= NODE_A_PONG_CACHING;
	}

	/* X-Ultrapeer -- support for ultra peer mode */

	field = header_get(head, "X-Ultrapeer");
	if (field) {
		n->attrs |= NODE_A_CAN_ULTRA;
		if (0 == ascii_strcasecmp(field, "true"))
			n->attrs |= NODE_A_ULTRA;
		else if (0 == ascii_strcasecmp(field, "false")) {
			if (current_peermode == NODE_P_ULTRA)
				n->flags |= NODE_F_LEAF;
		}
	} else {
		/*
		 * BearShare 4.3.x decided to no longer send X-Ultrapeer on connection,
		 * but rather include the X-Ultrapeer-Needed header.  Hopefully, only
		 * their UPs will send back such a header.
		 *		--RAM, 01/11/2003
		 */

		field = header_get(head, "X-Ultrapeer-Needed");
		if (field)
			n->attrs |= NODE_A_CAN_ULTRA | NODE_A_ULTRA;
		else
			n->attrs |= NODE_A_NO_ULTRA;
	}

	/* Node -- remote node Gnet IP/port information */

	if (incoming) {
		host_addr_t addr;
		guint16 port;

		/*
		 * We parse only for incoming connections.  Even though the remote
		 * node may reply with such a header to our outgoing connections,
		 * if we reached it, we know its IP:port already!  There's no need
		 * to spend time parsing it.
		 */

		field = header_get(head, "Node");
		if (!field) field = header_get(head, "X-My-Address");
		if (!field) field = header_get(head, "Listen-Ip");

		if (field && string_to_host_addr_port(field, NULL, &addr, &port)) {
			if (n->attrs & NODE_A_ULTRA)
				pcache_pong_fake(n, addr, port);	/* Might have free slots */

			/*
			 * Since we have the node's IP:port, record it now and mark the
			 * node as valid: if the connection is terminated, the host will
			 * be recorded amongst our valid set.
			 *		--RAM, 18/03/2002.
			 */

			if (host_addr_equal(addr, n->addr)) {
                node_ht_connected_nodes_remove(n->gnet_addr, n->gnet_port);

				n->gnet_addr = addr;			/* Signals: we know the port */
				n->gnet_port = port;
				n->gnet_pong_addr = addr;		/* Cannot lie about its IP */
				n->flags |= NODE_F_VALID;

                node_ht_connected_nodes_add(n->gnet_addr, n->gnet_port);
			}
		}
	}

	/* Bye-Packet -- support for final notification */

	field = header_get(head, "Bye-Packet");
	if (field) {
		guint major, minor;

		parse_major_minor(field, NULL, &major, &minor);
		if (major != 0 || minor != 1)
			if (node_debug) g_warning(
				"node %s <%s> claims Bye-Packet version %u.%u",
				node_addr(n), node_vendor(n), major, minor);
		n->attrs |= NODE_A_BYE_PACKET;
	}

	/* Vendor-Message -- support for vendor-specific messages */

	field = header_get(head, "Vendor-Message");
	if (field) {
		guint major, minor;

		parse_major_minor(field, NULL, &major, &minor);
		if (major > 0 || (major == 0 && minor > 1))
			if (node_debug) g_warning("node %s <%s> claims Vendor-Message "
				"version %u.%u",
				node_addr(n), node_vendor(n), major, minor);

		n->attrs |= NODE_A_CAN_VENDOR;
	}

	/* Check for (X-)Remote-IP header and handle it */
	node_check_remote_ip_header(n->addr, head);

	/* X-Live-Since -- time at which the remote node started. */
	/* Uptime -- the remote host uptime.  Only used by Gnucleus. */

	field = header_get(head, "X-Live-Since");
	if (field) {
		time_t now = tm_time(), up = date2time(field, now);

		/*
		 * We'll be comparing the up_date we compute to our local timestamp
		 * for displaying the node's uptime.  Since our clock could be
		 * offset wrt GMT, we use our current clock skew to offset the remote
		 * timestamp to our local time, so that we can substract the two
		 * quantities to get "meaningful" results.
		 *		--RAM, 05/08/2003
		 */

		if ((time_t) -1 == up)
			g_warning("cannot parse X-Live-Since \"%s\" from %s (%s)",
				field, node_addr(n), node_vendor(n));
		else
			n->up_date = MIN(clock_gmt2loc(up), now);
	} else {
		field = header_get(head, "Uptime");
		if (field) {
			time_t now = tm_time();
			gint days, hours, mins;

			if (3 == sscanf(field, "%dD %dH %dM", &days, &hours, &mins))
				n->up_date = now - 86400 * days - 3600 * hours - 60 * mins;
			else if (3 == sscanf(field, "%dDD %dHH %dMM", &days, &hours, &mins))
				n->up_date = now - 86400 * days - 3600 * hours - 60 * mins;
			else
				g_warning("cannot parse Uptime \"%s\" from %s (%s)",
					field, node_addr(n), node_vendor(n));
		}
	}

	/* X-Ultrapeer -- support for ultra peer mode */

	field = header_get(head, "X-Ultrapeer");
	if (field) {
		n->attrs |= NODE_A_CAN_ULTRA;
		if (0 == ascii_strcasecmp(field, "true"))
			n->attrs |= NODE_A_ULTRA;
		else if (0 == ascii_strcasecmp(field, "false")) {
			if (current_peermode == NODE_P_ULTRA)
				n->flags |= NODE_F_LEAF;
		}
	} else {
		/*
		 * BearShare 4.3.x decided to no longer send X-Ultrapeer on connection,
		 * but rather include the X-Ultrapeer-Needed header.  Hopefully, only
		 * their UPs will send back such a header.
		 *		--RAM, 01/11/2003
		 */

		field = header_get(head, "X-Ultrapeer-Needed");
		if (field)
			n->attrs |= NODE_A_CAN_ULTRA | NODE_A_ULTRA;
		else
			n->attrs |= NODE_A_NO_ULTRA;
	}

	if (gnet_deflate_enabled) {
		/*
	 	 * Accept-Encoding -- decompression support on the remote side
	 	 */

		field = header_get(head, "Accept-Encoding");
		if (field) {
			/* XXX needs more rigourous parsing */
			if (strstr(field, "deflate")) {
				n->attrs |= NODE_A_CAN_INFLATE;
				n->attrs |= NODE_A_TX_DEFLATE;	/* We accept! */
			}
		}

		/*
	 	 * Content-Encoding -- compression accepted by the remote side
	 	 */

		field = header_get(head, "Content-Encoding");
		if (field) {
			/* XXX needs more rigourous parsing */
			if (strstr(field, "deflate"))
				n->attrs |= NODE_A_RX_INFLATE;	/* We shall decompress input */
		}
	}

	/*
	 * Crawler -- LimeWire's Gnutella crawler
	 */

	field = header_get(head, "Crawler");
	if (field) {

		n->flags |= NODE_F_CRAWLER;
        gnet_prop_set_guint32_val(PROP_CRAWLER_VISIT_COUNT,
            crawler_visit_count + 1);

		/*
		 * Make sure they're not crawling us too often.
		 */

		if (aging_lookup(tcp_crawls, &n->addr)) {
			static const gchar msg[] = N_("Too frequent crawling");

			g_warning("rejecting TCP crawler request from %s", node_addr(n));

			node_send_error(n, 403, "%s", msg);
			node_remove(n, "%s", _(msg));
			return;
		}

		aging_insert(tcp_crawls,
			wcopy(&n->addr, sizeof n->addr), GUINT_TO_POINTER(1));
	}

	/*
	 * X-Try and X-Try-Ultrapeers -- normally only sent on 503, but some
	 * servents always send such lines during the connection process.
	 */

	extract_header_pongs(head, n);

	/*
	 * Check that everything is OK so far for an outgoing connection: if
	 * they did not reply with 200, then there's no need for us to reply back.
	 */

	if (!incoming && !analyse_status(n, NULL))
		return;				/* node_remove() has freed s->getline */

	/*
	 * Vendor-specific banning.
	 *
	 * This happens at step #2 of the handshaking process for incoming
	 * connections, at at step #3 for outgoing ones.
	 */

	if (n->vendor) {
		const gchar *msg = ban_vendor(n->vendor);

		if (msg != NULL) {
			ban_record(n->socket->addr, msg);
			node_send_error(n, 403, "%s", msg);
			node_remove(n, "%s", msg);
			return;
		}
	}

	/*
	 * Enforce our connection count here.
	 *
	 * This must come after parsing of "Accept-Encoding", since we're
	 * also enforcing the preference for gnet compression.
	 */

	if (!node_can_accept_connection(n, TRUE))
		return;

	/*
	 * If we're a leaf node, we're talking to an Ultra node.
	 * (otherwise, node_can_accept_connection() would have triggered)
	 */

	if (current_peermode == NODE_P_LEAF) {
		g_assert((n->flags & NODE_F_CRAWLER) || (n->attrs & NODE_A_ULTRA));
		if (!(n->flags & NODE_F_CRAWLER))
			n->flags |= NODE_F_ULTRA;			/* This is our ultranode */
	}

	/*
	 * X-Query-Routing -- QRP protocol in use
	 */

	field = header_get(head, "X-Query-Routing");
	if (field) {
		guint major, minor;

		parse_major_minor(field, NULL, &major, &minor);
		if (major > 0 || minor > 2)
			if (node_debug) g_warning("node %s <%s> claims QRP version %u.%u",
				node_addr(n), node_vendor(n), major, minor);
		n->qrp_major = (guint8) major;
		n->qrp_minor = (guint8) minor;
	}

	/*
	 * X-Ultrapeer-Query-Routing -- last hop QRP for inter-UP traffic
	 */

	field = header_get(head, "X-Ultrapeer-Query-Routing");
	if (field) {
		guint major, minor;

		parse_major_minor(field, NULL, &major, &minor);
		if (major > 0 || minor > 1)
			if (node_debug) g_warning(
				"node %s <%s> claims Ultra QRP version %u.%u",
				node_addr(n), node_vendor(n), major, minor);
		n->uqrp_major = (guint8) major;
		n->uqrp_minor = (guint8) minor;
		if (n->attrs & NODE_A_ULTRA)
			n->attrs |= NODE_A_UP_QRP;	/* Only makes sense for ultra nodes */
	}

	/*
	 * X-Dynamic-Querying -- ability of ultra nodes to perform dynamic querying
	 */

	field = header_get(head, "X-Dynamic-Querying");
	if (field) {
		guint major, minor;

		parse_major_minor(field, NULL, &major, &minor);
		if (major > 0 || minor > 1)
			if (node_debug)
				g_warning("node %s <%s> claims dynamic querying version %u.%u",
					node_addr(n), node_vendor(n), major, minor);
		if (n->attrs & NODE_A_ULTRA)
			n->attrs |= NODE_A_DYN_QUERY;	/* Only used by ultra nodes */
	}

	/* X-Max-TTL -- max initial TTL for dynamic querying */

	field = header_get(head, "X-Max-Ttl");		/* Needs normalized case */
	if (field) {
		guint32 value;
		gint error;

		value = parse_uint32(field, NULL, 10, &error);
		if (error || value < 1 || value > 255) {
			value = max_ttl;
			if (node_debug) g_warning(
				"node %s <%s> request bad Max-TTL %s, using %u",
				node_addr(n), node_vendor(n), field, value);
		}
		n->max_ttl = MIN(max_ttl, value);
	} else if (n->attrs & NODE_A_ULTRA)
		n->max_ttl = NODE_LEGACY_TTL;

	/* X-Degree -- their enforced outdegree (# of connections) */

	field = header_get(head, "X-Degree");
	if (field) {
		guint32 value;
		gint error;

		value = parse_uint32(field, NULL, 10, &error);
		if (value < 1 || value > 200) {
			if (node_debug) g_warning(
				"node %s <%s> advertises weird degree %s",
				node_addr(n), node_vendor(n), field);
			value = max_connections;	/* Assume something reasonable! */
		}
		n->degree = value;
	} else if (n->attrs & NODE_A_ULTRA)
		n->degree = NODE_LEGACY_DEGREE;

	/*
	 * Check that remote host speaks a protocol we can accept.
	 */

	if (!node_can_accept_protocol(n,  head))
		return;

	/*
	 * Avoid one vendor occupying all our slots
	 *		-- JA, 21/11/2003
	 */

	if (node_avoid_monopoly(n)) {
		node_send_error(n, 409,
			"Vendor would exceed %d%% of our slots", unique_nodes);
		node_remove(n, _("Vendor would exceed %d%% of our slots"), unique_nodes);
		return;
	}

	/*
	 * Wether we should reserve a slot for gtk-gnutella
	 */

	if (node_reserve_slot(n)) {
		node_send_error(n, 409, "Reserved slot");
		node_remove(n, _("Reserved slot"));
		return;
	}

	/*
	 * Test for HSEP X-Features header version. According to the specs,
	 * different version of HSEP are not necessarily compatible to each
	 * other. Therefore, we test for exactly the HSEP version we support
	 * here.
	 */
	{
		guint major, minor;

 		header_get_feature("hsep", head, &major, &minor);

 		if (major == HSEP_VERSION_MAJOR && minor == HSEP_VERSION_MINOR) {
			n->attrs |= NODE_A_CAN_HSEP;
			hsep_connection_init(n);
			/* first HSEP message will be sent on next hsep_timer() call */
		}
	}

	/*
	 * Check whether remote node supports flags in the header, via a
	 * re-architected size field: 16-bit size and 16-bit flags.
	 */
	{
		guint major, minor;

 		if (header_get_feature("sflag", head, &major, &minor))
			n->attrs |= NODE_A_CAN_SFLAG;
	}

	/*
	 * For incoming connections it's not clear whether the
	 * given address is correct, it could be a proxy.
	 */
	if (0 == (NODE_F_INCOMING & n->flags)) {
		if (header_get_feature("tls", head, NULL, NULL)) {
			tls_cache_insert(n->addr, n->port);
		}
	}

	/*
	 * If we're a leaf node, only accept connections to "modern" ultra nodes.
	 * A modern ultra node supports high outdegree and dynamic querying.
	 */

	if (
		current_peermode == NODE_P_LEAF &&
		!(n->flags & NODE_F_CRAWLER) &&
		(n->degree < 2 * NODE_LEGACY_DEGREE || !(n->attrs & NODE_A_DYN_QUERY))
	) {
		static const gchar msg[] = N_("High Outdegree and Dynamic Querying Required");

		node_send_error(n, 403, "%s", msg);
		node_remove(n, "%s", _(msg));
		return;
	}

	/*
	 * If this is an outgoing connection, we're processing the remote
	 * acknowledgment to our initial handshake.
	 */

	/* Large in case Crawler info sent back */
	gnet_response = g_malloc(gnet_response_max);

	if (!incoming) {
		gboolean mode_changed = FALSE;

		/* Make sure we only receive incoming connections from crawlers */

		if (n->flags & NODE_F_CRAWLER) {
			static const gchar msg[] = N_("Cannot connect to a crawler");

			node_send_error(n, 403, msg);
			node_remove(n, _(msg));
			goto free_gnet_response;
		}

		/* X-Ultrapeer-Needed -- only defined for 2nd reply (outgoing) */

		field = header_get(head, "X-Ultrapeer-Needed");
		if (field && 0 == ascii_strcasecmp(field, "false")) {
			/*
			 * Remote ultrapeer node wants more leaves.
			 * If we are an ultrapeer without any leaves yet, accept to
			 * become a leaf node if the remote uptime of the node is
			 * greater than ours.
			 */

			if (n->attrs & NODE_A_ULTRA) {
				if (
					current_peermode == NODE_P_ULTRA &&
					configured_peermode != NODE_P_ULTRA &&
					node_leaf_count == 0 &&
					n->up_date != 0 &&
					delta_time(n->up_date, start_stamp) < 0
				) {
					g_warning("accepting request from %s <%s> to become a leaf",
						node_addr(n), node_vendor(n));

					node_bye_all_but_one(n, 203, "Becoming a leaf node");
					n->flags |= NODE_F_ULTRA;
					mode_changed = TRUE;
					gnet_prop_set_guint32_val(PROP_CURRENT_PEERMODE,
						NODE_P_LEAF);
				} else if (current_peermode != NODE_P_LEAF) {
					static const gchar msg[] = N_("Not becoming a leaf node");

					if (node_debug > 2) g_warning(
						"denying request from %s <%s> to become a leaf",
						node_addr(n), node_vendor(n));

					node_send_error(n, 403, msg);
					node_remove(n, _(msg));
					goto free_gnet_response;
				}
			}
		}
		if (field && 0 == ascii_strcasecmp(field, "true")) {
			/*
			 * Remote ultrapeer node looking for more ultrapeers.
			 * If we're a leaf node and meet the ultrapeer requirements,
			 * maybe we should start thinking about promoting ourselves?
			 */

			/* XXX */
		}

		if (field && !(n->attrs & NODE_A_ULTRA))
			g_warning("node %s <%s> is not an ultrapeer but sent the "
				"X-Ultrapeer-Needed header",
				node_addr(n), node_vendor(n));

		/*
		 * Prepare our final acknowledgment.
		 */

		g_assert(!mode_changed || current_peermode == NODE_P_LEAF);

		rw = gm_snprintf(gnet_response, gnet_response_max,
			"GNUTELLA/0.6 200 OK\r\n"
			"%s"			/* Content-Encoding */
			"%s"			/* X-Ultrapeer */
			"%s"			/* X-Query-Routing (tells version we'll use) */
			"\r\n",
			gnet_deflate_enabled && (n->attrs & NODE_A_TX_DEFLATE)
				? compressing : empty,
			mode_changed ? "X-Ultrapeer: False\r\n" : "",
			(n->qrp_major > 0 || n->qrp_minor > 2) ?
				"X-Query-Routing: 0.2\r\n" : "");
	} else {
		guint ultra_max;

		/*
		 * Welcome the incoming node.
		 */

		ultra_max = max_connections > normal_connections
			? max_connections - normal_connections : 0;

		if (n->flags & NODE_F_CRAWLER)
			rw = gm_snprintf(gnet_response, gnet_response_max,
				"GNUTELLA/0.6 200 OK\r\n"
				"User-Agent: %s\r\n"
				"%s"		/* Peers & Leaves */
				"X-Live-Since: %s\r\n"
				"\r\n",
				version_string, node_crawler_headers(n), start_rfc822_date);
		else {
			const gchar *token;
			gchar degree[100];
			
			token = socket_omit_token(n->socket) ? NULL : tok_version();

			/*
			 * Special hack for LimeWire, which really did not find anything
			 * smarter than looking for new headers to detect "modern leaves".
			 * As if it mattered for the ultra node!
			 *
			 * Oh well, emit specially tailored headers for them to consider
			 * us good enough.
			 *
			 *		--RAM, 2004-08-05
			 */

			if (current_peermode == NODE_P_ULTRA)
				gm_snprintf(degree, sizeof(degree),
					"X-Degree: %d\r\n"
					"X-Max-TTL: %d\r\n",
					(up_connections + max_connections - normal_connections) / 2,
					max_ttl);
			else if (!is_strprefix(node_vendor(n), gtkg_vendor))
				gm_snprintf(degree, sizeof(degree),
					"X-Dynamic-Querying: 0.1\r\n"
					"X-Ultrapeer-Query-Routing: 0.1\r\n"
					"X-Degree: 32\r\n"
					"X-Max-TTL: %d\r\n",
					max_ttl);
			else
				degree[0] = '\0';

			rw = gm_snprintf(gnet_response, gnet_response_max,
				"GNUTELLA/0.6 200 OK\r\n"
				"User-Agent: %s\r\n"
				"Pong-Caching: 0.1\r\n"
				"Bye-Packet: 0.1\r\n"
				"GGEP: 0.5\r\n"
				"Vendor-Message: 0.1\r\n"
				"Remote-IP: %s\r\n"
				"%s"
				"%s"		/* Content-Encoding */
				"%s"		/* X-Ultrapeer */
				"%s"		/* X-Ultrapeer-Needed */
				"%s"		/* X-Query-Routing */
				"%s"		/* X-Ultrapeer-Query-Routing */
				"%s"		/* X-Degree + X-Max-TTL */
				"%s"		/* X-Dynamic-Querying */
				"%s"		/* X-Requeries */
				"%s%s%s"	/* X-Token (optional) */
				"X-Live-Since: %s\r\n",
				version_string,
				host_addr_to_string(n->socket->addr),
				gnet_deflate_enabled ? "Accept-Encoding: deflate\r\n" : "",
				(gnet_deflate_enabled && (n->attrs & NODE_A_TX_DEFLATE))
					? compressing : empty,
				current_peermode == NODE_P_NORMAL ? "" :
				current_peermode == NODE_P_LEAF ?
					"X-Ultrapeer: False\r\n" :
					"X-Ultrapeer: True\r\n",
				current_peermode != NODE_P_ULTRA ? "" :
				node_ultra_count < ultra_max ? "X-Ultrapeer-Needed: True\r\n" :
				node_leaf_count < max_leaves ? "X-Ultrapeer-Needed: False\r\n" :
					"",
				current_peermode != NODE_P_NORMAL ?
					node_query_routing_header(n) : "",
				current_peermode == NODE_P_ULTRA ?
					"X-Ultrapeer-Query-Routing: 0.1\r\n" : "",
				degree,
				current_peermode == NODE_P_ULTRA ?
					"X-Dynamic-Querying: 0.1\r\n" : "",
				current_peermode == NODE_P_LEAF ?
	 				"X-Requeries: False\r\n" : "",
	 			token ? "X-Token: " : "",
				token ? token : "",
				token ? "\r\n" : "",
				start_rfc822_date);

			header_features_generate(FEATURES_CONNECTIONS,
				gnet_response, gnet_response_max, &rw);

			rw += gm_snprintf(&gnet_response[rw],
					gnet_response_max - rw, "\r\n");
		}
	}

	/*
	 * We might not be able to transmit the reply atomically.
	 * This should be rare, so we're not handling the case for now.
	 * Simply log it and close the connection.
	 */

	sent = bws_write(BSCHED_BWS_GOUT, &n->socket->wio, gnet_response, rw);
	if ((ssize_t) -1 == sent) {
		int errcode = errno;
		if (node_debug) g_warning("Unable to send back %s to node %s: %s",
			what, host_addr_to_string(n->addr), g_strerror(errcode));
		node_remove(n, _("Failed (Cannot send %s: %s)"),
			what, g_strerror(errcode));
		goto free_gnet_response;
	} else if ((size_t) sent < rw) {
		if (node_debug) g_warning(
			"Could only send %d out of %d bytes of %s to node %s",
			(int) sent, (int) rw, what, host_addr_to_string(n->addr));
		node_remove(n, _("Failed (Cannot send %s atomically)"), what);
		goto free_gnet_response;
	} else if (node_debug > 2) {
		g_message("----Sent OK %s to %s (%d bytes):\n%.*s----",
			what, host_addr_to_string(n->addr),
			(int) rw, (int) rw, gnet_response);
	}

	/*
	 * Now that we got all the headers, we may update the `last_update' field.
	 */

	n->last_update = tm_time();

	/*
	 * If this is an incoming connection, we need to wait for the final ack.
	 * If this is an outgoing connection, we're now connected on Gnet.
	 */

	if (n->flags & NODE_F_INCOMING) {
		/*
		 * The remote node is expected to send us an acknowledgement.
		 * The I/O callback installed is still node_header_read(), but
		 * we need to configure a different callback when the header
		 * is collected.
		 */

		n->status = GTA_NODE_WELCOME_SENT;

		io_continue_header(n->io_opaque, IO_SAVE_FIRST,
			call_node_process_handshake_ack, NULL);

		node_fire_node_flags_changed(n);
	} else
		node_is_now_connected(n);

free_gnet_response:
	G_FREE_NULL(gnet_response);
}

/***
 *** I/O header parsing callbacks.
 ***/

#define NODE(x)	((struct gnutella_node *) (x))

static void
err_line_too_long(gpointer obj)
{
	node_send_error(NODE(obj), 413, "Header line too long");
	node_remove(NODE(obj), _("Failed (Header line too long)"));
}

static void
err_header_error_tell(gpointer obj, gint error)
{
	node_send_error(NODE(obj), 413, "%s", header_strerror(error));
}

static void
err_header_error(gpointer obj, gint error)
{
	node_remove(NODE(obj), _("Failed (%s)"), header_strerror(error));
}

static void
err_input_exception(gpointer obj)
{
	struct gnutella_node *n = NODE(obj);

	node_remove(n, (n->flags & NODE_F_CRAWLER) ?
		_("Sent crawling info") : _("Failed (Input Exception)"));
}

static void
err_input_buffer_full(gpointer obj)
{
	node_remove(NODE(obj), _("Failed (Input buffer full)"));
}

static void
err_header_read_error(gpointer obj, gint error)
{
	node_remove(NODE(obj), _("Failed (Input error: %s)"), g_strerror(error));
}

static void
err_header_read_eof(gpointer obj)
{
	struct gnutella_node *n = NODE(obj);

	if (!(n->flags & NODE_F_CRAWLER))
		node_mark_bad_vendor(n);

	node_remove(n, (n->flags & NODE_F_CRAWLER) ?
		_("Sent crawling info") : _("Failed (EOF)"));
}

static void
err_header_extra_data(gpointer obj)
{
	node_remove(NODE(obj), _("Failed (Extra HELLO data)"));
}

static struct io_error node_io_error = {
	err_line_too_long,
	err_header_error_tell,
	err_header_error,
	err_input_exception,
	err_input_buffer_full,
	err_header_read_error,
	err_header_read_eof,
	err_header_extra_data,
};

static void
call_node_process_handshake_header(gpointer obj, header_t *header)
{
	node_process_handshake_header(NODE(obj), header);
}

static void
call_node_process_handshake_ack(gpointer obj, header_t *header)
{
	node_process_handshake_ack(NODE(obj), header);
}

#undef NODE

/**
 * Create a "fake" node that is used as a placeholder when processing
 * Gnutella messages received via host browsing.
 *
 * The node instance is shared but needs to be filled with the received
 * message before parsing of the Gnutella query hit can occur.
 */
static gnutella_node_t *
node_browse_create(void)
{
	gnutella_node_t *n;

	n = walloc0(sizeof *n);

	n->magic = NODE_MAGIC;
    n->node_handle = node_request_handle(n);
    n->id = node_id++;
	n->proto_major = 0;
	n->proto_minor = 6;
	n->peermode = NODE_P_LEAF;
	n->hops_flow = MAX_HOP_COUNT;
	n->last_update = n->last_tx = n->last_rx = tm_time();
	n->routing_data = NULL;
	n->status = GTA_NODE_CONNECTED;
	n->flags = NODE_F_ESTABLISHED | NODE_F_READABLE | NODE_F_VALID;
	n->up_date = start_stamp;
	n->connect_date = start_stamp;
	n->alive_pings = alive_make(n, ALIVE_MAX_PENDING);

	return n;
}

/**
 * Let the "browse host" node hold the supplied Gnutella message as if
 * coming from the host and from a servent with the supplied vendor
 * string.
 *
 * @return the shared instance, suitable for parsing the received message.
 */
gnutella_node_t *
node_browse_prepare(
	gnet_host_t *host, const gchar *vendor, gnutella_header_t *header,
	gchar *data, guint32 size)
{
	gnutella_node_t *n = browse_node;

	g_assert(n != NULL);

	n->addr = gnet_host_get_addr(host);
	n->port = gnet_host_get_port(host);
	n->vendor = deconstify_gchar(vendor);
	n->country = gip_country(n->addr);

	n->size = size;
	memcpy(n->header, header, sizeof n->header);
	n->data = data;

	return n;
}

/**
 * Cleanup the "browse host" node.
 */
void
node_browse_cleanup(gnutella_node_t *n)
{
	g_assert(n == browse_node);

	n->vendor = NULL;
	n->data = NULL;
}

/**
 * Create a "fake" node that is used as a placeholder when processing
 * Gnutella messages received from UDP.
 */
static gnutella_node_t *
node_udp_create(enum net_type net)
{
	gnutella_node_t *n;
	gboolean is_ipv4 = FALSE;

	switch (net) {
	case NET_TYPE_IPV4:
		is_ipv4 = TRUE;
		break;
	case NET_TYPE_IPV6:
		is_ipv4 = FALSE;
		break;
	case NET_TYPE_LOCAL:
	case NET_TYPE_NONE:
		return NULL;
	}
	
	n = walloc0(sizeof *n);

	n->magic = NODE_MAGIC;
	n->addr = is_ipv4 ? listen_addr() : listen_addr6();
    n->node_handle = node_request_handle(n);
    n->id = node_id++;
	n->port = listen_port;
	n->proto_major = 0;
	n->proto_minor = 6;
	n->peermode = NODE_P_UDP;
	n->hops_flow = MAX_HOP_COUNT;
	n->last_update = n->last_tx = n->last_rx = tm_time();
	n->routing_data = NULL;
	{
		gchar buf[256];

		concat_strings(buf, sizeof buf,
			_("Pseudo UDP node"), " ", is_ipv4 ? "(IPv4)" : "(IPv6)",
			(void *) 0);
		n->vendor = atom_str_get(buf);
	}
	n->status = GTA_NODE_CONNECTED;
	n->flags = NODE_F_ESTABLISHED |
		NODE_F_READABLE | NODE_F_WRITABLE | NODE_F_VALID;
	n->up_date = start_stamp;
	n->connect_date = start_stamp;
	n->alive_pings = alive_make(n, ALIVE_MAX_PENDING);
	n->country = gip_country(n->addr);

	return n;
}

/**
 * Enable UDP transmission via pseudo node.
 */
static void
node_udp_enable_by_net(enum net_type net)
{
	struct gnutella_socket *s = NULL;
	gnutella_node_t *n = NULL;
	txdrv_t *tx;
	struct tx_dgram_args args;
	gnet_host_t host;

	switch (net) {
	case NET_TYPE_IPV4:
		n = udp_node;
		s = s_udp_listen;
		break;
	case NET_TYPE_IPV6:
		n = udp6_node;
		s = s_udp_listen6;
		break;
	case NET_TYPE_LOCAL:
	case NET_TYPE_NONE:
		g_assert_not_reached();
	}

	g_assert(n != NULL);
	g_assert(s != NULL);

#if 0
	g_assert(NULL == n->socket);
#endif

	socket_check(s);
	n->socket = s;

	args.cb = &node_tx_dgram_cb;
	args.bws = BSCHED_BWS_GOUT_UDP;
	args.wio = &n->socket->wio;

	gnet_host_set(&host, n->addr, n->port);

	if (n->outq) {
		mq_free(n->outq);
		n->outq = NULL;
	}
	tx = tx_make(n, &host, tx_dgram_get_ops(), &args);	/* Cannot fail */
	n->outq = mq_udp_make(node_sendqueue_size, n, tx);
	
    node_fire_node_added(n);
    node_fire_node_flags_changed(n);
}

/**
 * Disable UDP transmission via pseudo node.
 */
static void
node_udp_disable_by_net(enum net_type net)
{
	gnutella_node_t *n = NULL;

	switch (net) {
	case NET_TYPE_IPV4:
		n = udp_node;
		break;
	case NET_TYPE_IPV6:
		n = udp6_node;
		break;
	case NET_TYPE_LOCAL:
	case NET_TYPE_NONE:
		g_assert_not_reached();
	}

	g_assert(n != NULL);
	if (n->socket) {
		socket_check(n->socket);
		node_fire_node_removed(n);
	}
	if (n->outq) {
		mq_free(n->outq);
		n->outq = NULL;
	}
	n->socket = NULL;
}

void
node_udp_enable(void)
{
	if (s_udp_listen)
		node_udp_enable_by_net(NET_TYPE_IPV4);
	if (s_udp_listen6)
		node_udp_enable_by_net(NET_TYPE_IPV6);
}

void
node_udp_disable(void)
{
	/*
	 * Because the pseudo UDP nodes reference the UDP sockets,
	 * we have to disable these first.
	 */

	if (udp_node && udp_node->socket) {
		node_udp_disable_by_net(NET_TYPE_IPV4);
		socket_free_null(&s_udp_listen);
	}
	if (udp6_node && udp6_node->socket) {
		node_udp_disable_by_net(NET_TYPE_IPV6);
		socket_free_null(&s_udp_listen6);
	}
}

/**
 * Get "fake" node after reception of a datagram and return its address.
 */
static gnutella_node_t *
node_udp_get(struct gnutella_socket *s)
{
	gnutella_node_t *n = NULL;
	gnutella_header_t *head;

	socket_check(s);

	switch (s->net) {
	case NET_TYPE_IPV4:
		n = udp_node;
		break;
	case NET_TYPE_IPV6:
		n = udp6_node;
		break;
	case NET_TYPE_LOCAL:
	case NET_TYPE_NONE:
		g_assert_not_reached();
	}
	g_assert(n != NULL);
	g_assert(n->socket == s);		/* Only one UDP socket */

	head = cast_to_gpointer(s->buf);
	n->size = gmsg_size(head);

	memcpy(n->header, head, sizeof n->header);
	n->data = &s->buf[GTA_HEADER_SIZE];

	n->addr = s->addr;
	n->port = s->port;

	n->attrs = 0;

	return n;
}

/**
 * Get the message queue attached to the UDP node.
 *
 * @return the UDP message queue, or NULL if UDP has been disabled.
 */
mqueue_t *
node_udp_get_outq(enum net_type net)
{
	switch (net) {
	case NET_TYPE_IPV4: return udp_node ? udp_node->outq : NULL;
	case NET_TYPE_IPV6: return udp6_node ? udp6_node->outq : NULL;
	case NET_TYPE_LOCAL:
	case NET_TYPE_NONE:
		break;
	}
	return NULL;
}

/**
 * Get "fake" node for UDP transmission.
 */
gnutella_node_t *
node_udp_get_addr_port(const host_addr_t addr, guint16 port)
{
	gnutella_node_t *n = NULL;

	if (udp_active()) {
		switch (host_addr_net(addr)) {
		case NET_TYPE_IPV4:
			n = udp_node;
			break;
		case NET_TYPE_IPV6:
			n = udp6_node;
			break;
		case NET_TYPE_LOCAL:
		case NET_TYPE_NONE:
			g_assert_not_reached();
			break;
		}
		g_return_val_if_fail(n, NULL);

		n->addr = addr;
		n->port = port;
	}
	return n;
}

/**
 * Add new node.
 */
void
node_add(const host_addr_t addr, guint16 port, guint32 flags)
{
	if (!is_host_addr(addr) || !port)
		return;

	if (
		!(SOCK_F_FORCE & flags) &&
		(hostiles_check(addr) || hcache_node_is_bad(addr))
	)
		return;

   	node_add_socket(NULL, addr, port, flags);
}

struct node_add_by_name_data {
	guint32 flags;
	guint16 port;	
};

/**
 * Called when we got a reply from the ADNS process.
 *
 * @todo TODO: All resolved addresses should be attempted.
 */
static void
node_add_by_name_helper(const host_addr_t *addrs, size_t n, gpointer user_data)
{
	struct node_add_by_name_data *data = user_data;

	g_assert(addrs);
	g_assert(data);
	g_assert(data->port);

	if (n > 0) {
		size_t i = random_raw() % n;
		node_add(addrs[i], data->port, data->flags);
	}
	wfree(data, sizeof *data);
}

/**
 * Add new node by hostname.
 */
void
node_add_by_name(const gchar *host, guint16 port, guint32 flags)
{
	struct node_add_by_name_data *data;
	
	g_assert(host);

	if (!port)
		return;

	data = walloc(sizeof *data);
	data->port = port;
	data->flags = flags;

	if (
		!adns_resolve(host, settings_dns_net(), &node_add_by_name_helper, data)
	) {
		/*	node_add_by_name_helper() was already invoked! */
		if (node_debug > 0)
			g_warning("node_add_by_name: "
				"adns_resolve() failed in synchronous mode");
		return;
	}
}


/**
 * Add new node, to which we possibly have an existing connection if
 * the socket is not NULL (incoming connection).
 */
void
node_add_socket(struct gnutella_socket *s, const host_addr_t addr,
	guint16 port, guint32 flags)
{
	struct gnutella_node *n;
	gboolean incoming = FALSE, already_connected = FALSE;
	guint major = 0, minor = 0;
	gboolean forced = 0 != (SOCK_F_FORCE & flags);

	g_assert(s == NULL || s->resource.node == NULL);

	/*
	 * During shutdown, don't accept any new connection.
	 */

	if (in_shutdown) {
		socket_free_null(&s);
		return;
	}

	/*
	 * If they wish to be temporarily off Gnet, don't initiate connections.
	 */

	if (s == NULL && !allow_gnet_connections)
		return;

	/*
	 * Compute the protocol version from the first handshake line, if
	 * we got a socket (meaning an inbound connection).  It is important
	 * to figure out early because we have to deny the connection cleanly
	 * for 0.6 clients and onwards.
	 */

	if (s) {
		get_protocol_version(getline_str(s->getline), &major, &minor);
		getline_free(s->getline);
		s->getline = NULL;
	}

	if (!forced && !allow_private_network_connection && is_private_addr(addr)) {
		if (s) {
			if (major > 0 || minor > 4)
				send_node_error(s, 404, "Denied access from private IP");
			socket_free_null(&s);
		}
		return;
	}

	if (s && major == 0 && minor < 6) {
		socket_free_null(&s);
		return;
	}

	/*
	 * Check whether we have already a connection to this node.
	 */

	incoming = s != NULL;
	already_connected = node_is_connected(addr, port, incoming);

	if (!incoming && already_connected)
		return;

	/*
	 * Too many GnutellaNet connections?
     *
     * In leaf-mode we only respect max_ultrapeers, in normal-mode
     * node_ultra_count is always 0, and in ultra_mode we can only
     * have outgoing connections to ultra and normal peers, so we do not
     * respect any leaf maximum.
     * -- Richard, 28 Mar 2003
	 */

    if (
		(current_peermode == NODE_P_LEAF &&
		 	node_ultra_count >= max_ultrapeers) ||
		(current_peermode != NODE_P_LEAF &&
			node_ultra_count + node_normal_count >= max_connections)
	) {
        if (!already_connected) {
			if (forced || whitelist_check(addr)) {
				/* Incoming whitelisted IP, and we're full. Remove one node. */
				(void) node_remove_worst(FALSE);
			} else if (use_netmasks && host_is_nearby(addr)) {
				 /* We are preferring local hosts, remove a non-local node */
				(void) node_remove_worst(TRUE);
			}
		}
	}

	/*
	 * Create new node.
	 */

	n = walloc0(sizeof *n);
	n->magic = NODE_MAGIC;
    n->node_handle = node_request_handle(n);

    n->id = node_id++;
	n->addr = addr;
	n->port = port;
	n->proto_major = major;
	n->proto_minor = minor;
	n->peermode = NODE_P_UNKNOWN;		/* Until end of handshaking */
	n->start_peermode = (node_peer_t) current_peermode;
	n->hops_flow = MAX_HOP_COUNT;
	n->last_update = n->last_tx = n->last_rx = tm_time();
	n->country = gip_country(addr);

	n->hello.ptr = NULL;
    n->hello.size =	0;
    n->hello.pos = 0;
    n->hello.len = 0;

	n->routing_data = NULL;
	n->flags = NODE_F_HDSK_PING | (forced ? NODE_F_FORCE : 0);

	if (s) {					/* This is an incoming control connection */
		n->socket = s;
		s->resource.node = n;
		s->type = SOCK_TYPE_CONTROL;
		n->status = (major > 0 || minor > 4) ?
			GTA_NODE_RECEIVING_HELLO : GTA_NODE_WELCOME_SENT;

		socket_tos_default(s);	/* Set proper Type of Service */

		/*
		 * For incoming connections, we don't know the listening IP:port
		 * Gnet information.  We mark the node with the NODE_F_INCOMING
		 * flag so that we send it an "alive" ping to get that information
		 * as soon as we have handshaked.
		 *
		 *		--RAM, 02/02/2001
		 *
		 * As of today, we'll no longer be flagging incoming 0.6 connections
		 * as Ponging.  Checking for maximum connections will be done
		 * during the handshaking.
		 *
		 *		--RAM, 17/01/2003
		 */

		if (socket_uses_tls(s))
			n->flags |= NODE_F_TLS;

		n->flags |= NODE_F_INCOMING;
	} else {
		/* We have to create an outgoing control connection for the node */

		s = socket_connect(addr, port, SOCK_TYPE_CONTROL, flags);

		if (s) {
			n->status = GTA_NODE_CONNECTING;
			s->resource.node = n;
			n->socket = s;
			n->gnet_addr = addr;
			n->gnet_port = port;
			n->proto_major = 0;
			n->proto_minor = 6;				/* Handshake at 0.6 intially */
		} else {
			n->status = GTA_NODE_REMOVING;
			n->remove_msg = "Connection failed";

			/*
			 * If we are out of file descriptors, don't drop the node from
			 * the hostcache: mark it valid.
			 */

			if (errno == EMFILE || errno == ENFILE)
				n->flags |= NODE_F_VALID;
		}

	}

    node_fire_node_added(n);
    node_fire_node_flags_changed(n);

	/*
	 * Insert node in lists, before checking `already_connected', since
	 * we need everything installed to call node_remove(): we want to
	 * leave a trail in the GUI.
	 */

	sl_nodes = g_slist_prepend(sl_nodes, n);
	g_hash_table_insert(nodes_by_id, GUINT_TO_POINTER(n->id), n);

	if (n->status != GTA_NODE_REMOVING)
        node_ht_connected_nodes_add(n->gnet_addr, n->gnet_port);

	if (already_connected) {
		if (incoming && (n->proto_major > 0 || n->proto_minor > 4))
			node_send_error(n, 409, "Already connected");
		node_remove(n, _("Already connected"));
		return;
	}

	if (incoming) {				/* Welcome the incoming node */
		/*
		 * We need to read the remote headers then send ours before we can
		 * operate any data transfer (3-way handshaking).
		 */

		io_get_header(n, &n->io_opaque, BSCHED_BWS_GIN, s,
			IO_3_WAY|IO_HEAD_ONLY, call_node_process_handshake_header, NULL,
			&node_io_error);
	}

    node_fire_node_info_changed(n);
}

/**
 * Check that current message has an extra payload made of GGEP only,
 * and whose total size is not exceeding `maxsize'.
 *
 * @param `n'		no brief description.
 * @param `maxsize'	no brief description.
 * @param `regsize' value is the normal payload length of the message
 *					(e.g. 0 for a ping).
 *
 * @return TRUE if there is a GGEP extension block, and only that after
 *		   the regular payload, with a size no greater than `maxsize'.
 *
 * @note parsed extensions are left in the node's `extensions' structure.
 */
static gboolean
node_check_ggep(struct gnutella_node *n, gint maxsize, gint regsize)
{
	gchar *start;
	gint len;
	gint i;

	g_assert(n->size > (guint32) regsize);	/* "fat" message */

	len = n->size - regsize;				/* Extension length */

	if (len > maxsize) {
		g_warning("%s has %d extra bytes !", gmsg_infostr(&n->header), len);
		return FALSE;
	}

	start = n->data + regsize;
	n->extcount = ext_parse(start, len, n->extvec, MAX_EXTVEC);

	/*
	 * Assume that if we have MAX_EXTVEC, it's just plain garbage.
	 */

	if (n->extcount == MAX_EXTVEC) {
		g_warning("%s has %d extensions!",
			gmsg_infostr(&n->header), n->extcount);
		if (node_debug)
			ext_dump(stderr, n->extvec, n->extcount, "> ", "\n", TRUE);
		return FALSE;
	}

	/*
	 * Ensure we have only GGEP extensions in there.
	 */

	for (i = 0; i < n->extcount; i++) {
		if (n->extvec[i].ext_type != EXT_GGEP) {
			if (node_debug) {
				g_warning("%s has non-GGEP extensions!",
					gmsg_infostr(&n->header));
				ext_dump(stderr, n->extvec, n->extcount, "> ", "\n", TRUE);
			}
			return FALSE;
		}
	}

	if (node_debug > 3) {
		g_message("%s has GGEP extensions:", gmsg_infostr(&n->header));
		ext_dump(stderr, n->extvec, n->extcount, "> ", "\n", TRUE);
	}

	return TRUE;
}

enum dump_header_flags {                                                        
	DH_F_UDP  = (1 << 0),
	DH_F_TCP  = (1 << 1),
	DH_F_IPV4 = (1 << 2),
	DH_F_IPV6 = (1 << 3),

	NUM_DH_F
};

struct dump_header {
/*
 * This is the logic layout:
 *
 *	uint8_t flags;
 *	uint8_t addr[16];
 *	uint8_t port[2];
 */
	uint8_t data[19];
};

static void
dump_header_set(struct dump_header *dh, const struct gnutella_node *node)
{
	memset(dh, 0, sizeof dh);

	dh->data[0] = NODE_IS_UDP(node) ? DH_F_UDP : DH_F_TCP;
	switch (host_addr_net(node->addr)) {
	case NET_TYPE_IPV4:
		{
			guint32 ip;
			
			dh->data[0] |= DH_F_IPV4;
			ip = host_addr_ipv4(node->addr);
			poke_be32(&dh->data[1], ip);
		}
		break;
	case NET_TYPE_IPV6:
		dh->data[0] |= DH_F_IPV6;
		memcpy(&dh->data[1], host_addr_ipv6(&node->addr), 16);
		break;
	case NET_TYPE_LOCAL:
	case NET_TYPE_NONE:
		break;
	}
	poke_be16(&dh->data[17], node->port);
}

static void
node_dump_packet(const struct gnutella_node *node)
{
	static FILE *f;
	
	if (dump_received_gnutella_packets) {
		if (!f) {
			gchar *pathname;

			pathname = make_pathname(settings_config_dir(), "packets_rx.dump");
			f = fopen(pathname, "a");
			G_FREE_NULL(pathname);
		}
		if (f) {
			struct dump_header dh;

			dump_header_set(&dh, node);
			fwrite(dh.data, sizeof dh.data, 1, f);
			fwrite(node->header, sizeof node->header, 1, f);
			fwrite(node->data, node->size, 1, f);
		}
	} else if (f) {
		fclose(f);
		f = NULL;
	}
}

/**
 * Processing of messages.
 *
 * @attention
 * NB: callers of this routine must not use the node structure upon return,
 * since we may invalidate that node during the processing.
 */
static void
node_parse(struct gnutella_node *node)
{
	struct gnutella_node *n;
	gboolean drop = FALSE;
	gboolean has_ggep = FALSE;
	size_t regular_size = (size_t) -1;		/* -1 signals: regular size */
	struct route_dest dest;
	query_hashvec_t *qhv = NULL;
	gint results = 0;						/* # of results in query hits */

	g_return_if_fail(node);
	g_assert(NODE_IS_CONNECTED(node));

	dest.type = ROUTE_NONE;
	n = node;

	node_dump_packet(node);

	/*
	 * If we're expecting a handshaking ping, check whether we got one.
	 * An handshaking ping is normally sent after a connection is made,
	 * and it comes with hops=0.
	 *
	 * We use the handshaking ping to determine, based on the GUID format,
	 * whether the remote node is capable of limiting ping/pongs or not.
	 * Note that for outgoing connections, we'll use the first ping we see
	 * with hops=0 to determine that ability: the GUID[8] byte will be 0xff
	 * and GUID[15] will be >= 1.
	 *
	 *		--RAM, 02/01/2002
	 *
	 * The only time where the handshaking ping was necessary was for
	 * "ponging" incoming connections, which we no longer support.
	 * Those were opened solely to send back connection pongs, but we need
	 * the initial ping to know the GUID to use as message ID when replying...
	 *
	 * XXX delete the code snippet below? --RAM, 03/08/2003
	 */

	if (n->flags & NODE_F_HDSK_PING) {
		if (
			gnutella_header_get_function(&n->header) == GTA_MSG_INIT &&
			gnutella_header_get_hops(&n->header) == 0
		) {
			const gchar *muid = gnutella_header_get_muid(&n->header);
			
			if ((guint8) muid[8] == 0xff && (guint8) muid[15] >= 1)
				n->attrs |= NODE_A_PONG_CACHING;
			n->flags &= ~NODE_F_HDSK_PING;		/* Clear indication */
		}
	}

	/*
	 * If node is a leaf, it MUST send its messages with hops = 0.
	 */

	if (NODE_IS_LEAF(n) && gnutella_header_get_hops(&n->header) > 0) {
		node_bye_if_writable(n, 414, "Leaf node relayed %s",
			gmsg_name(gnutella_header_get_function(&n->header)));
		return;
	}

	/* First some simple checks */

	switch (gnutella_header_get_function(&n->header)) {
	case GTA_MSG_INIT:
        if (n->size)
			regular_size = 0;		/* Will check further below */
		break;
	case GTA_MSG_INIT_RESPONSE:
        if (n->size != sizeof(gnutella_init_response_t))
			regular_size = sizeof(gnutella_init_response_t);
		break;
	case GTA_MSG_BYE:
		if (
			gnutella_header_get_hops(&n->header) != 0 ||
			gnutella_header_get_ttl(&n->header) > 1
		) {
			n->n_bad++;
			drop = TRUE;
			if (node_debug)
				gmsg_log_bad(n, "expected hops=0 and TTL<=1");
            gnet_stats_count_dropped(n, MSG_DROP_IMPROPER_HOPS_TTL);
		}
		break;
	case GTA_MSG_PUSH_REQUEST:
        if (n->size != sizeof(gnutella_push_request_t))
			regular_size = sizeof(gnutella_push_request_t);
		break;
	case GTA_MSG_SEARCH:
		if (n->size <= 3) {	/* At least speed(2) + NUL(1) */
			drop = TRUE;
            gnet_stats_count_dropped(n, MSG_DROP_TOO_SMALL);
        }
		else if (n->size > search_queries_forward_size) {
			drop = TRUE;
            gnet_stats_count_dropped(n, MSG_DROP_TOO_LARGE);
        }

		/*
		 * TODO
		 * Just like we refuse to process queries that are "too short",
		 * and would therefore match too many things, we should probably
		 * refuse to forward those on the network.	Less careful servents
		 * would reply, and then we'll have more messages to process.
		 *				-- RAM, 09/09/2001
		 */
		break;
	case GTA_MSG_SEARCH_RESULTS:
        if (n->size > search_answers_forward_size) {
            drop = TRUE;
            gnet_stats_count_dropped(n, MSG_DROP_TOO_LARGE);
        }
		if (n->size < GUID_RAW_SIZE) {
			n->n_bad++;
            drop = TRUE;
            gnet_stats_count_dropped(n, MSG_DROP_TOO_SMALL);
		}
		break;

	case GTA_MSG_VENDOR:
	case GTA_MSG_STANDARD:
		/*
		 * Vendor messages are never routed, so they should be sent with
		 * hops=0 and TTL=1.  When they come from UDP however, they can
		 * carry OOB reply indication, so we do not drop them if their
		 * hops/ttl are not setup correctly.
		 *		--RAM, 2006-08-29
		 */
		if (!NODE_IS_UDP(n)) {
			if (
				gnutella_header_get_hops(&n->header) != 0 ||
				gnutella_header_get_ttl(&n->header) > 1
			) {
				n->n_bad++;
				drop = TRUE;
				if (node_debug)
					gmsg_log_bad(n, "expected hops=0 and TTL<=1");
				gnet_stats_count_dropped(n, MSG_DROP_IMPROPER_HOPS_TTL);
			} else {
				/* In case no Vendor-Message was seen in handshake */
				n->attrs |= NODE_A_CAN_VENDOR;
			}
		}
		break;

	case GTA_MSG_QRP:			/* Leaf -> Ultrapeer, never routed */
		if (
			gnutella_header_get_hops(&n->header) != 0 ||
			gnutella_header_get_ttl(&n->header) > 1
		) {
			n->n_bad++;
			drop = TRUE;
			if (node_debug)
				gmsg_log_bad(n, "expected hops=0 and TTL<=1");
            gnet_stats_count_dropped(n, MSG_DROP_IMPROPER_HOPS_TTL);
		} else if (
			current_peermode != NODE_P_ULTRA ||
			!(
				n->peermode == NODE_P_LEAF ||
				(n->peermode == NODE_P_ULTRA && (n->attrs & NODE_A_UP_QRP))
			)
		) {
			drop = TRUE;
			n->n_bad++;
			if (node_debug)
				gmsg_log_bad(n, "unexpected QRP message");
			gnet_stats_count_dropped(n, MSG_DROP_UNEXPECTED);
		}
		break;
	case GTA_MSG_HSEP_DATA:     /* never routed */
		if (
			gnutella_header_get_hops(&n->header) != 0 ||
			gnutella_header_get_ttl(&n->header) > 1
		) {
			n->n_bad++;
			drop = TRUE;
			if (node_debug)
				gmsg_log_bad(n, "expected hops=0 and TTL<=1");
			gnet_stats_count_dropped(n, MSG_DROP_IMPROPER_HOPS_TTL);
		} else if (!(n->attrs & NODE_A_CAN_HSEP)) {
			drop = TRUE;
			n->n_bad++;
			if (node_debug)
				gmsg_log_bad(n, "unexpected HSEP message");
			gnet_stats_count_dropped(n, MSG_DROP_UNEXPECTED);
		}
		break;
	case GTA_MSG_RUDP:
		break;
	default:					/* Unknown message type - we drop it */
		drop = TRUE;
		n->n_bad++;
		if (node_debug)
			gmsg_log_bad(n, "unknown message type");
        gnet_stats_count_dropped(n, MSG_DROP_UNKNOWN_TYPE);
		break;
	}

	/*
	 * If message has not a regular size, check for a valid GGEP extension.
	 * NB: message must be at least as big as the regular size, or it's
	 * clearly a bad message.
	 */

	if (regular_size != (size_t) -1) {
		g_assert(n->size != regular_size);

		has_ggep = FALSE;

		if (n->size > regular_size)
			has_ggep = node_check_ggep(n, MAX_GGEP_PAYLOAD, regular_size);

		if (!has_ggep) {
			drop = TRUE;
			gnet_stats_count_dropped(n, MSG_DROP_BAD_SIZE);
		}
	}

	/*
	 * If message is dropped, stop right here.
	 */

	if (drop) {
		if (gnutella_header_get_ttl(&n->header) == 0)
			node_sent_ttl0(n);
		goto reset_header;
	}

	/*
	 * If the message has header flags, and since those are not defined yet,
	 * we cannot interpret the message correctly.  We may route some of them
	 * however, if we don't need to interpret the payload to do that.
	 *
	 * Indeed, as the meaning of header flags is not defined yet, we cannot
	 * know where the payload of the message will really start: some flags
	 * may indicate extra header information for instance (options) that would
	 * shift the payload start further.
	 *
	 *		--RAM, 2006-08-27
	 */

	if (n->header_flags)
		goto route_only;

	/*
	 * With the ping/pong reducing scheme, we no longer pass ping/pongs
	 * to the route_message() routine, and don't even have to store
	 * routing information from pings to be able to route pongs back, which
	 * saves routing entry for useful things...
	 *		--RAM, 02/01/2002
	 */

	switch (gnutella_header_get_function(&n->header)) {
	case GTA_MSG_BYE:				/* Good bye! */
		node_got_bye(n);
		return;
	case GTA_MSG_INIT:				/* Ping */
		pcache_ping_received(n);
		goto reset_header;
		/* NOTREACHED */
	case GTA_MSG_INIT_RESPONSE:		/* Pong */
		pcache_pong_received(n);
		goto reset_header;
		/* NOTREACHED */
	case GTA_MSG_VENDOR:			/* Vendor-specific, experimental */
	case GTA_MSG_STANDARD:			/* Vendor-specific, standard */
		vmsg_handle(n);
		goto reset_header;
		/* NOTREACHED */
	case GTA_MSG_QRP:				/* Query Routing table propagation */
		if (n->qrt_receive == NULL) {
			n->qrt_receive = qrt_receive_create(n, n->recv_query_table);
			node_fire_node_flags_changed(n);
		}
		if (n->qrt_receive != NULL) {
			gboolean done;
			if (!qrt_receive_next(n->qrt_receive, &done))
				return;				/* Node BYE-ed */
			if (done) {
				qrt_receive_free(n->qrt_receive);
				n->qrt_receive = NULL;
				node_fire_node_flags_changed(n);
			}
		}
		goto reset_header;
	case GTA_MSG_SEARCH_RESULTS:	/* "semi-pongs" */
		if (host_low_on_pongs) {
			host_addr_t addr;
			guint16 port;

			node_extract_host(n, &addr, &port);
			host_add_semi_pong(addr, port);
		}
		break;
	case GTA_MSG_HSEP_DATA:
		hsep_process_msg(n, tm_time());
		goto reset_header;
	case GTA_MSG_RUDP:
		/* Not ready for prime time */
#if 0
		rudp_handle_packet(n->addr, n->port,
			n->socket->buf, n->size + GTA_HEADER_SIZE);
#endif
		return;
	default:
		break;
	}

	/* Compute route (destination) then handle the message if required */

route_only:
	if (route_message(&n, &dest)) {		/* We have to handle the message */
		g_assert(n);
		switch (gnutella_header_get_function(&n->header)) {
		case GTA_MSG_PUSH_REQUEST:
			/* Only handle if no unknown header flags */
			if (0 == n->header_flags)
				handle_push_request(n);
			break;
		case GTA_MSG_SEARCH:
			/* Only handle if no unknown header flags */
			if (0 != n->header_flags)
				break;

            /*
             * search_request() takes care of telling the stats that
             * the message was dropped.
			 *
			 * When running as an UP, we'll forward the search to our leaves
			 * even if its TTL expired here.
             */

			if (current_peermode == NODE_P_ULTRA) {
				qhv = query_hashvec;
				qhvec_reset(qhv);
			}

			drop = search_request(n, qhv);
			break;

		case GTA_MSG_SEARCH_RESULTS:
            /*
             * search_results takes care of telling the stats that
             * the message was dropped.
             */

			/* Only handle if no unknown header flags */
			if (0 == n->header_flags)
				drop = search_results(n, &results);
			break;

		default:
			/*
			 * Normally we'll come here only when we have unknown header
			 * flags in the message and we skipped processing above, going
			 * directly to the route_only tag.
			 *
			 * Therefore, if we come here and we don't have flags, something
			 * is wrong.
			 */
			if (node_debug && !n->header_flags)
				message_dump(n);
			break;
		}
	}

	if (!n)
		goto clean_dest;	/* The node has been removed during processing */

	if (drop)
		goto dropped;

	if (qhv != NULL && NODE_IS_LEAF(n)) {
		g_assert(current_peermode == NODE_P_ULTRA);

		/*
		 * For leaf nodes, undo decrement of TTL: act as if we were
		 * sending the search.  When the results arrives, we'll forward
		 * it to the leaf even if its TTL is zero when it reaches us
		 * (handled by route_message() directly).
		 *
		 * We used to decrement the hop count as well here, but that is
		 * bad because neighbouring GTKG ultra nodes will see a query
		 * with hops=1 and will therefore check the address in OOB queries.
		 * If the query comes from the leaf and is not OOB-proxied, then
		 * a neighbouring UP may drop the OOB flag, assuming the return
		 * address is not matching that of the node.
		 *		--RAM, 2006-08-20
		 */

		gnutella_header_set_ttl(&n->header,
			gnutella_header_get_ttl(&n->header) + 1);

		/*
		 * A leaf-originated query needs to be handled via the dynamic
		 * query mechanism.
		 */

		dq_launch_net(n, qhv);

	} else if (current_peermode != NODE_P_LEAF) {
		/*
		 * Propagate message, if needed
		 */

		g_assert(regular_size == (size_t) -1 || has_ggep);

		switch (gnutella_header_get_function(&n->header)) {
		case GTA_MSG_SEARCH:
			/*
			 * Route it to the appropriate leaves, and if TTL=1,
			 * to UPs that support last-hop QRP and to all other
			 * non-QRP awware UPs.
			 *
			 * (if running as ultra mode, in which case qhv is not NULL).
			 */

			if (qhv != NULL)
				qrt_route_query(n, qhv);

			/*
			 * If normal node, or if the TTL is not 1, broadcast (to
			 * non-leaf nodes).
			 *
			 * There's no need to test for GGEP here, as searches are
			 * variable-length messages and the GGEP check is only for
			 * fixed-sized message enriched with trailing GGEP extensions.
			 */

			if (
				current_peermode == NODE_P_NORMAL ||
				gnutella_header_get_ttl(&n->header) > 1
			)
				gmsg_sendto_route(n, &dest);
			break;

		case GTA_MSG_SEARCH_RESULTS:
			/*
			 * Special handling for query hits.
			 *
			 * We don't want to blindly forward hits to the node, because
			 * for popular queries, the send queue could become clogged.
			 * Therefore, we control how many hits we deliver per query
			 * to be able to intelligently throttle common hits and let
			 * the rarest hit room to be sent, instead of having the flow
			 * control algorithm blindly choose.
			 *
			 *		--RAM, 2004-08-06
			 */

			switch (dest.type) {
			case ROUTE_NONE:
				break;
			case ROUTE_ONE:
				g_assert(results > 0);		/* Or message would be dropped */
				dh_route(n, dest.ur.u_node, results);
				break;
			default:
				g_error("invalid destination for query hit: %d", dest.type);
			}
			break;

		default:
			gmsg_sendto_route(n, &dest);
			break;
		}
	}

dropped:
	/* gnet_stats_count_dropped() already counted dropped packet */

reset_header:
	n->have_header = FALSE;
	n->pos = 0;
	ext_reset(n->extvec, n->extcount);
	n->extcount = 0;

clean_dest:
	if (dest.type == ROUTE_MULTI)
		g_slist_free(dest.ur.u_nodes);
}

static void
node_drain_hello(gpointer data, gint source, inputevt_cond_t cond)
{
	struct gnutella_node *n = data;

	socket_check(n->socket);
	g_assert(n->socket->file_desc == source);
	g_assert(n->hello.ptr != NULL);
	g_assert(n->hello.size > 0);
	g_assert(n->hello.len < n->hello.size);
	g_assert(n->hello.pos < n->hello.size);
	g_assert(n->hello.pos + n->hello.len < n->hello.size);

	if (cond & INPUT_EVENT_EXCEPTION) {
		gint error;
		socklen_t error_len = sizeof error;

		getsockopt(source, SOL_SOCKET, SO_ERROR, &error, &error_len);
		node_remove(n, _("Write error during HELLO: %s"), g_strerror(error));
		return;
	}

	node_init_outgoing(n);
}

/**
 * Process incoming Gnutella datagram.
 */
void
node_udp_process(struct gnutella_socket *s)
{
	gnutella_node_t *n = node_udp_get(s);
	gboolean drop_hostile = TRUE;

	/*
	 * The node_parse() routine was written to process incoming Gnutella
	 * messages from TCP-connected nodes, whose connection can be broken.
	 * To reuse as much of the logic as possible, we reuse the same routine
	 * on a fake node target.
	 *
	 * At strategic places where it is important to know whether the message
	 * comes from UDP or not (e.g. for queries which are not meant to be
	 * routed), the NODE_IS_UDP() predicate is used.
	 *
	 * We enclose the node_parse() call between assertions to make sure
	 * that we never attempt to remove the fake UDP node!
	 *
	 *		--RAM, 2004-08-16
	 */

	g_assert(n->status == GTA_NODE_CONNECTED && NODE_IS_READABLE(n));

	node_add_rx_given(n, n->size + GTA_HEADER_SIZE);

	/*
	 * A little code duplication from node_read(), which we don't call
	 * when receiving UDP traffic since the whole datagram has alrady
	 * been read atomically.
	 */

	switch (gnutella_header_get_function(&n->header)) {
	case GTA_MSG_SEARCH:
		node_inc_rx_query(n);
		break;
	case GTA_MSG_SEARCH_RESULTS:
		node_inc_rx_qhit(n);
		drop_hostile = FALSE;	/* Filter later so that we can peek at them */
		break;
	case GTA_MSG_VENDOR:
	case GTA_MSG_STANDARD:
		/*
		 * Check for UDP compression support, marking host if we can send
		 * UDP compressed replies. --RAM, 2006-08-13
		 */

		if (gnutella_header_get_ttl(&n->header) & GTA_UDP_CAN_INFLATE)
			n->attrs |= NODE_A_CAN_INFLATE;
		break;
	default:
		break;
	}

	/*
	 * Discard incoming datagrams from registered hostile IP addresses.
	 */

	if (drop_hostile && hostiles_check(n->addr)) {
		if (udp_debug)
			g_warning("UDP got %s from hostile %s -- dropped",
				gmsg_infostr_full(s->buf), node_addr(n));
		gnet_stats_count_dropped(n, MSG_DROP_HOSTILE_IP);
		return;
	}

	/*
	 * If payload is deflated, inflate it before processing.
	 */

	if (
		(gnutella_header_get_ttl(&n->header) & GTA_UDP_DEFLATED) &&
		!node_inflate_payload(n)
	)
		return;

	g_assert(!(gnutella_header_get_ttl(&n->header) & GTA_UDP_DEFLATED));

	if (oob_proxy_debug > 1) {
		if (GTA_MSG_SEARCH_RESULTS == gnutella_header_get_function(&n->header))
			printf("QUERY OOB results for %s from %s\n",
				guid_hex_str(gnutella_header_get_muid(&n->header)),
				node_addr(n));
	}

	node_parse(n);

	g_assert(n->status == GTA_NODE_CONNECTED && NODE_IS_READABLE(n));
}

/**
 * Called when asynchronous connection to an outgoing node is established.
 */
void
node_init_outgoing(struct gnutella_node *n)
{
	struct gnutella_socket *s = n->socket;
	ssize_t sent;
	gchar degree[100];

	socket_check(s);

	/*
	 * Special hack for LimeWire, which insists on the presence of dynamic
	 * querying headers and high outdegree to consider a leaf "good".
	 * They should fix their clueless code instead of forcing everyone to
	 * emit garbage.
	 *
	 * Oh well, contend them with totally bogus (fixed) headers.
	 *
	 *		--RAM, 2004-08-05
	 */

	if (!n->hello.ptr) {
		host_addr_t my_addr, my_addr_v6;
		guint16 my_port;

		g_assert(0 == s->gdk_tag);

		n->hello.pos = 0;
		n->hello.len = 0;
		n->hello.ptr = walloc((n->hello.size = MAX_LINE_SIZE));
		if (!n->hello.ptr) {
			node_remove(n, _("Out of memory"));
			return;
		}

		if (current_peermode == NODE_P_ULTRA)
			gm_snprintf(degree, sizeof(degree),
				"X-Degree: %d\r\n"
				"X-Max-TTL: %d\r\n",
				(up_connections + max_connections - normal_connections) / 2,
				max_ttl);
		else
			gm_snprintf(degree, sizeof(degree),
				"X-Dynamic-Querying: 0.1\r\n"
				"X-Ultrapeer-Query-Routing: 0.1\r\n"
				"X-Degree: 32\r\n"
				"X-Max-TTL: 4\r\n");

		my_addr = listen_addr();
		my_addr_v6 = listen_addr6();
		my_port = socket_listen_port();
		
		n->hello.len = gm_snprintf(n->hello.ptr, n->hello.size,
			"%s%d.%d\r\n"
			"Node: %s%s%s\r\n"
			"Remote-IP: %s\r\n"
			"User-Agent: %s\r\n"
			"Pong-Caching: 0.1\r\n"
			"Bye-Packet: 0.1\r\n"
			"GGEP: 0.5\r\n"
			"Vendor-Message: 0.1\r\n"
			"%s"		/* "Accept-Encoding: deflate */
			"X-Token: %s\r\n"
			"X-Live-Since: %s\r\n"
			"%s"		/* X-Ultrapeer */
			"%s"		/* X-Query-Routing */
			"%s"		/* X-Ultrapeer-Query-Routing */
			"%s"		/* X-Degree + X-Max-TTL */
			"%s"		/* X-Dynamic-Querying */
			"%s",		/* X-Requeries */
			GNUTELLA_HELLO,
			n->proto_major, n->proto_minor,
			is_host_addr(my_addr)
			 ? host_addr_port_to_string(my_addr, my_port) : "",
			(is_host_addr(my_addr) && is_host_addr(my_addr_v6))
			 ? ", " : "",
			is_host_addr(my_addr_v6)
			 ? host_addr_port_to_string(my_addr_v6, my_port) : "",
			host_addr_to_string(n->addr),
			version_string,
			gnet_deflate_enabled ? "Accept-Encoding: deflate\r\n" : "",
			tok_version(),
			start_rfc822_date,
			current_peermode == NODE_P_NORMAL ? "" :
				current_peermode == NODE_P_LEAF ?
				"X-Ultrapeer: False\r\n": "X-Ultrapeer: True\r\n",
			current_peermode != NODE_P_NORMAL ? "X-Query-Routing: 0.2\r\n" : "",
			current_peermode == NODE_P_ULTRA ?
				"X-Ultrapeer-Query-Routing: 0.1\r\n" : "",
			degree,
			current_peermode == NODE_P_ULTRA ?
				"X-Dynamic-Querying: 0.1\r\n" : "",
			current_peermode == NODE_P_LEAF ?
				"X-Requeries: False\r\n" : ""
		);

		header_features_generate(FEATURES_CONNECTIONS,
			n->hello.ptr, n->hello.size, &n->hello.len);

		n->hello.len += gm_snprintf(&n->hello.ptr[n->hello.len],
							n->hello.size - n->hello.len, "\r\n");

		g_assert(n->hello.len < n->hello.size);

		/*
		 * We don't retry a connection from 0.6 to 0.4 if we fail to write the
		 * initial HELLO.
		 */

		if (socket_uses_tls(n->socket))
			n->flags |= NODE_F_TLS;

	} else {
		socket_evt_clear(s);
	}

	g_assert(n->hello.ptr != NULL);
	g_assert(n->hello.pos < n->hello.size);
	g_assert(n->hello.len > 0);

	sent = bws_write(BSCHED_BWS_GOUT, &n->socket->wio,
				&n->hello.ptr[n->hello.pos], n->hello.len);

	switch (sent) {
	case (ssize_t) -1:
		g_message("bws_write() failed: %s", g_strerror(errno));
		if (!is_temporary_error(errno)) {
			node_remove(n, _("Write error during HELLO: %s"),
				g_strerror(errno));
			return;
		}
		break;

	case 0:
		node_remove(n, _("Connection reset during HELLO"));
		return;

	default:
		g_assert(sent > 0);
		g_assert((size_t) sent <= n->hello.len);
		n->hello.pos += sent;
		n->hello.len -= sent;
	}

	if (n->hello.len > 0 && !s->gdk_tag) {
		g_assert(!s->gdk_tag);
		socket_evt_set(n->socket, INPUT_EVENT_WX, node_drain_hello, n);
		return;
	}

	n->status = GTA_NODE_HELLO_SENT;
	n->last_update = tm_time();
	node_fire_node_info_changed(n);

	if (node_debug > 2) {
		gint len = strlen(n->hello.ptr);

		g_message("----Sent HELLO request to %s (%d bytes):\n%.*s----",
			host_addr_to_string(n->addr), len, len, n->hello.ptr);
	}

	wfree(n->hello.ptr, n->hello.size);
	n->hello.ptr = NULL;

	/*
	 * Setup I/O callback to read the reply to our HELLO.
	 * Prepare parsing of the expected 0.6 reply.
	 */

	io_get_header(n, &n->io_opaque, BSCHED_BWS_GIN, s,
		IO_SAVE_FIRST|IO_HEAD_ONLY, call_node_process_handshake_header, NULL,
		&node_io_error);

	g_assert(s->gdk_tag != 0);		/* Leave with an I/O callback set */
}

/**
 * Called by queue when it's not empty and it went through the service routine
 * and yet has more data enqueued.
 */
void
node_flushq(struct gnutella_node *n)
{
	/*
	 * Put the connection in TCP_NODELAY mode to accelerate flushing of the
	 * kernel buffers by turning off the Nagle algorithm.
	 */

	if (n->flags & NODE_F_NODELAY)		/* Already done */
		return;

	sock_nodelay(n->socket, TRUE);
	n->flags |= NODE_F_NODELAY;
}

/**
 * Called by queue to disable the flush mode.
 */
void
node_unflushq(struct gnutella_node *n)
{
	if (!(n->flags & NODE_F_NODELAY))		/* Already done */
		return;

	sock_nodelay(n->socket, FALSE);
	n->flags &= ~NODE_F_NODELAY;
}

/**
 * Called when the queue service routine is switched ON/OFF.
 */
void
node_tx_service(struct gnutella_node *n, gboolean unused_on)
{
	(void) unused_on;
    node_fire_node_flags_changed(n);
}

/**
 * Called by message queue when the node enters the warn zone.
 */
void
node_tx_enter_warnzone(struct gnutella_node *n)
{
    node_fire_node_flags_changed(n);
}

/**
 * Called by message queue when the node leaves the warn zone.
 */
void
node_tx_leave_warnzone(struct gnutella_node *n)
{
    node_fire_node_flags_changed(n);
}

/**
 * Called by message queue when the node enters TX flow control.
 */
void
node_tx_enter_flowc(struct gnutella_node *n)
{
	n->tx_flowc_date = tm_time();

	if ((n->attrs & NODE_A_CAN_VENDOR) && !NODE_IS_UDP(n))
		vmsg_send_hops_flow(n, 0);			/* Disable all query traffic */

    node_fire_node_flags_changed(n);
}

/**
 * Called by message queue when the node leaves TX flow control.
 */
void
node_tx_leave_flowc(struct gnutella_node *n)
{
	if (node_debug > 4) {
		gint spent = delta_time(tm_time(), n->tx_flowc_date);

		g_message("node %s spent %d second%s in TX FLOWC",
			node_addr(n), spent, spent == 1 ? "" : "s");
	}

	if ((n->attrs & NODE_A_CAN_VENDOR) && !NODE_IS_UDP(n))
		vmsg_send_hops_flow(n, 255);		/* Re-enable query traffic */

    node_fire_node_flags_changed(n);
}

/**
 * Called by message queue when swift mode changes.
 */
void
node_tx_swift_changed(struct gnutella_node *n)
{
    node_fire_node_flags_changed(n);
}

/**
 * Disable reading callback.
 */
static void
node_disable_read(struct gnutella_node *n)
{
	g_assert(n->rx);

	if (n->flags & NODE_F_NOREAD)
		return;						/* Already disabled */

	n->flags |= NODE_F_NOREAD;
	rx_disable(n->rx);

    node_fire_node_flags_changed(n);
}

/**
 * Called when the Bye message has been successfully sent.
 */
static void
node_bye_sent(struct gnutella_node *n)
{
	if (node_debug)
		g_message("finally sent BYE \"%s\" to %s (%s)",
			n->error_str, node_addr(n), node_vendor(n));

	/*
	 * Shutdown the node.
	 */

	n->flags &= ~NODE_F_BYE_SENT;

	sock_tx_shutdown(n->socket);
	node_shutdown_mode(n, BYE_GRACE_DELAY);
}

/**
 * Read data from the message buffer we just received.
 *
 * @return TRUE whilst we think there is more data to read in the buffer.
 */
static gboolean
node_read(struct gnutella_node *n, pmsg_t *mb)
{
	gint r;

	if (!n->have_header) {		/* We haven't got the header yet */
		gchar *w = (gchar *) &n->header;
		gboolean kick = FALSE;

		r = pmsg_read(mb, &w[n->pos], GTA_HEADER_SIZE - n->pos);
		n->pos += r;
		node_add_rx_read(n, r);

		if (n->pos < GTA_HEADER_SIZE)
			return FALSE;

		/* Okay, we have read the full header */

		n->have_header = TRUE;

		/*
		 * Enforce architectural limit: messages can only be 64K.
		 */

		switch (gmsg_size_valid(&n->header, &n->size)) {
		case GMSG_VALID:
			n->header_flags = 0;
			break;
		case GMSG_VALID_MARKED:
			/*
			 * Node sent message with the flag mark, but without any flag
			 * set -- it is safe to clear that mark, provided the node who
			 * sent us this message supports the newly architected size field.
			 */

			if (NODE_CAN_SFLAG(n)) {
				/* Reset flag mark */
				gnutella_header_set_size(&n->header, n->size);
				n->header_flags = 0;
			} else
				goto bad_size;
			break;
		case GMSG_VALID_NO_PROCESS:
			/*
			 * Nodes must indicate that they support size flags before
			 * sending us messages with such flags.
			 */

			if (!NODE_CAN_SFLAG(n))
				goto bad_size;
			n->header_flags = gmsg_flags(&n->header);
			break;
		case GMSG_INVALID:
			goto bad_size;
		}

        gnet_stats_count_received_header(n);

		switch (gnutella_header_get_function(&n->header)) {
		case GTA_MSG_SEARCH:
			node_inc_rx_query(n);
			break;
		case GTA_MSG_SEARCH_RESULTS:
			node_inc_rx_qhit(n);
			break;
		default:
			break;
		}

		/* If the message haven't got any data, we process it now */

		if (!n->size) {
			node_parse(n);
			return TRUE;		/* There may be more to come */
		}

		/* Check whether the message is not too big */

		switch (gnutella_header_get_function(&n->header)) {
		case GTA_MSG_BYE:
			if (n->size > BYE_MAX_SIZE) {
				gnet_stats_count_dropped_nosize(n, MSG_DROP_WAY_TOO_LARGE);
				node_remove(n, _("Kicked: %s message too big (%d bytes)"),
					gmsg_name(gnutella_header_get_function(&n->header)),
					n->size);
				return FALSE;
			}
			break;

		case GTA_MSG_SEARCH:
			if (n->size > search_queries_kick_size)
				kick = TRUE;
			break;

		case GTA_MSG_SEARCH_RESULTS:
			if (n->size > search_answers_kick_size)
				kick = TRUE;
			break;

		default:
			if (n->size > other_messages_kick_size)
				kick = TRUE;
			break;
		}

		if (kick) {
			/*
			 * We can't read any more data from this node, as we are
			 * desynchronized: the large payload will stay unread.
			 */

			gnet_stats_count_dropped_nosize(n, MSG_DROP_WAY_TOO_LARGE);
			node_disable_read(n);
			node_bye(n, 400, "Too large %s message (%u bytes)",
				gmsg_name(gnutella_header_get_function(&n->header)), n->size);
			return FALSE;
		}

		/* Okay */

		n->pos = 0;

		if (n->size > n->allocated) {
			/*
			 * We need to grow the allocated data buffer
			 * Since could change dynamically one day, so compute it.
			 */

			guint32 maxsize = settings_max_msg_size();

			if (maxsize < n->size) {
				g_warning("BUG got %u byte %s message, should have kicked node",
					n->size,
					gmsg_name(gnutella_header_get_function(&n->header)));
				gnet_stats_count_dropped_nosize(n, MSG_DROP_WAY_TOO_LARGE);
				node_disable_read(n);
				node_bye(n, 400, "Too large %s message (%d bytes)",
					gmsg_name(gnutella_header_get_function(&n->header)),
					n->size);
				return FALSE;
			}

			if (n->allocated)
				n->data = g_realloc(n->data, maxsize);
			else
				n->data = g_malloc(maxsize);
			n->allocated = maxsize;
		}

		/* FALL THROUGH */
	}

	/* Reading of the message data */

	r = pmsg_read(mb, n->data + n->pos, n->size - n->pos);

	n->pos += r;
	node_add_rx_read(n, r);

	g_assert(n->pos <= n->size);

	if (n->pos < n->size)
		return FALSE;

	gnet_stats_count_received_payload(n);

	node_parse(n);

	return TRUE;		/* There may be more data */

bad_size:
	gnet_stats_count_dropped_nosize(n, MSG_DROP_WAY_TOO_LARGE);
	node_remove(n, _("Kicked: %s message too big (>= 64KiB limit)"),
		gmsg_name(gnutella_header_get_function(&n->header)));
	return FALSE;
}

/**
 * RX data indication callback used to give us some new Gnet traffic in a
 * low-level message structure (which can contain several Gnet messages).
 *
 * @return FALSE if an error occurred.
 */
static gboolean 
node_data_ind(rxdrv_t *rx, pmsg_t *mb)
{
	struct gnutella_node *n = rx_owner(rx);

	g_assert(mb);
	g_assert(NODE_IS_CONNECTED(n));

	/*
	 * Since node_read() can shutdown the node, we must explicitly check
	 * the the GTA_NODE_CONNECTED status and can't use NODE_IS_CONNECTED().
	 * Likewise, processing of messages can cause the node to become
	 * unreadable, so we need to check that as well.
	 *
	 * The node_read() routine will return FALSE when it detects that the
	 * message buffer is empty.
	 */

	n->last_update = n->last_rx = tm_time();
	n->flags |= NODE_F_ESTABLISHED;		/* Since we've got Gnutella data */

	while (n->status == GTA_NODE_CONNECTED && NODE_IS_READABLE(n)) {
		if (!node_read(n, mb))
			break;
	}

	pmsg_free(mb);
	return n->status == GTA_NODE_CONNECTED;
}

/**
 * Called when a node sends a message with TTL=0.
 *
 * @return TRUE if node was removed (due to a duplicate bye, probably),
 * FALSE otherwise.
 */
void
node_sent_ttl0(struct gnutella_node *n)
{
	g_assert(gnutella_header_get_ttl(&n->header) == 0);

	/*
	 * Ignore if we're a leaf node -- we'll even handle the message.
	 */

	if (current_peermode == NODE_P_LEAF)
		return;

	gnet_stats_count_dropped(n, MSG_DROP_TTL0);

	n->n_bad++;

	if (node_debug)
		gmsg_log_bad(n, "message received with TTL=0");
}

/**
 * Send a BYE message to all the nodes matching the specified flags.
 */
static void
node_bye_flags(guint32 mask, gint code, const gchar *message)
{
	GSList *sl;

	for (sl = sl_nodes; sl; sl = g_slist_next(sl)) {
		struct gnutella_node *n = sl->data;

		if (n->status == GTA_NODE_REMOVING || n->status == GTA_NODE_SHUTDOWN)
			continue;

		if (n->flags & mask)
			node_bye_if_writable(n, code, "%s", message);
	}
}

/**
 * Send a BYE message to all the nodes but the one supplied as argument.
 */
static void
node_bye_all_but_one(struct gnutella_node *nskip,
	gint code, const gchar *message)
{
	GSList *sl;

	for (sl = sl_nodes; sl; sl = g_slist_next(sl)) {
		struct gnutella_node *n = sl->data;

		if (n->status == GTA_NODE_REMOVING || n->status == GTA_NODE_SHUTDOWN)
			continue;

		if (n != nskip)
			node_bye_if_writable(n, code, "%s", message);
	}
}

/**
 * Send a BYE message to all the nodes.
 */
void
node_bye_all(void)
{
	GSList *sl;

	g_assert(!in_shutdown);		/* Meant to be called once */

	in_shutdown = TRUE;

	/*
	 * Shutdowning the application, clear the UDP queue: we don't want
	 * to have any transmission scheduled now as we're going to close
	 * the UDP socket very shortly...
	 */

	if (udp_node && udp_node->outq) {
		mq_clear(udp_node->outq);
	}
	if (udp6_node && udp6_node->outq) {
		mq_clear(udp6_node->outq);
	}

	host_shutdown();

	for (sl = sl_nodes; sl; sl = g_slist_next(sl)) {
		struct gnutella_node *n = sl->data;

		/*
		 * Record the NODE_F_EOF_WAIT condition, so that when waiting for
		 * all byes to come through, we can monitor which connections were
		 * closed, and exit immediately when we have no more pending byes.
		 *		--RAM, 17/05/2002
		 */

		if (NODE_IS_WRITABLE(n)) {
			n->flags |= NODE_F_EOF_WAIT;
			pending_byes++;
			node_bye(n, 200, "Servent shutdown");
		}

		/*
		 * We're no longer interested by receiving and parsing traffic.
		 */

		if (NODE_IS_READABLE(n))
			node_disable_read(n);
	}
}

/**
 * @return true whilst there are some connections with a pending BYE.
 */
gboolean
node_bye_pending(void)
{
	g_assert(in_shutdown);		/* Cannot be called before node_bye_all() */

	return pending_byes > 0;
}

/**
 * Try to spot a "useless" leaf node.
 *
 * i.e. one that is either not sharing anything or which is preventing us
 * from sending queries via hops-flow. We remove the ones flow-controlling
 * for the greatest amount of time, or which are not sharing anything, based
 * on the QRP.
 *
 * @param is_gtkg	if non-NULL, returns whether the node removed is a GTKG
 *
 * @return TRUE if we were able to remove one connection.
 */
static gboolean
node_remove_useless_leaf(gboolean *is_gtkg)
{
    GSList *sl;
	struct gnutella_node *worst = NULL;
	gint greatest = 0;
	time_t now = (time_t) -1;

    for (sl = sl_nodes; sl; sl = g_slist_next(sl)) {
		struct gnutella_node *n = sl->data;
		time_t target = (time_t) -1;
		gint diff;

		if (!NODE_IS_ESTABLISHED(n))
			continue;

		if (!NODE_IS_LEAF(n))
			continue;

        /* Don't kick whitelisted nodes. */
        if (whitelist_check(n->addr))
            continue;

		/*
		 * Our targets are non-sharing leaves, or leaves preventing
		 * any querying via hops-flow.
		 */

		if (n->gnet_files_count == 0)
			target = n->connect_date;

		if (n->leaf_flowc_start != 0)
			target = n->leaf_flowc_start;

		if ((time_t) -1 == target)
			continue;

		if ((time_t) -1 == now)
			now = tm_time();

		diff = delta_time(now, target);

		if (diff < NODE_USELESS_GRACE)
			continue;

		if (diff > greatest) {
			greatest = diff;
			worst = n;
		}
	}

	if (worst == NULL)
		return FALSE;

	if (is_gtkg != NULL)
		*is_gtkg = node_is_gtkg(worst);

	node_bye_if_writable(worst, 202, "Making room for another leaf");

	return TRUE;
}

/**
 * Try to spot a "useless" ultra node.
 *
 * i.e. one that is either not having leaves or is firewalled, or which
 * does not support inter-UP QRP tables.
 *
 * @param is_gtkg	if non-NULL, returns whether the node removed is a GTKG
 *
 * @return TRUE if we were able to remove one connection.
 */
static gboolean
node_remove_useless_ultra(gboolean *is_gtkg)
{
    GSList *sl;
	struct gnutella_node *worst = NULL;
	gint greatest = 0;
	time_t now = (time_t) -1;

	/*
	 * Only operate when we're an ultra node ourselves.
	 */

	if (current_peermode != NODE_P_ULTRA)
		return FALSE;

    for (sl = sl_nodes; sl; sl = g_slist_next(sl)) {
		struct gnutella_node *n = sl->data;
		time_t target = (time_t) -1;
		gint diff;

		if (!NODE_IS_ESTABLISHED(n))
			continue;

		if (!NODE_IS_ULTRA(n))
			continue;

        /* Don't kick whitelisted nodes. */
        if (whitelist_check(n->addr))
            continue;

		/*
		 * Our targets are firewalled nodes, nodes which do not support
		 * the inter-QRP table, nodes which have no leaves (as detected
		 * by the fact that they do not send QRP updates on a regular
		 * basis).
		 */

		if (n->flags & NODE_F_PROXIED)		/* Firewalled node */
			target = n->connect_date;

		if (n->qrt_receive == NULL && n->recv_query_table == NULL)
			target = n->connect_date;

		if (n->qrt_info && n->qrt_info->generation == 0)
			target = n->connect_date;

		if ((time_t) -1 == target)
			continue;

		if ((time_t) -1 == now)
			now = tm_time();

		diff = delta_time(now, target);

		if (diff < NODE_UP_USELESS_GRACE)
			continue;

		if (diff > greatest) {
			greatest = diff;
			worst = n;
		}
	}

	if (worst == NULL)
		return FALSE;

	if (is_gtkg != NULL)
		*is_gtkg = node_is_gtkg(worst);

	node_bye_if_writable(worst, 202, "Making room for another ultra node");

	return TRUE;
}


/**
 * Removes the node with the worst stats, considering the number of
 * weird, bad and duplicate packets.
 *
 * If `non_local' is TRUE, we're removing this node because it is not
 * a local node, and we're having a connection from the local LAN.
 * Otherwise, we're just removing a bad node (the BYE code is different).
 */
gboolean
node_remove_worst(gboolean non_local)
{
    GSList *sl;
    GSList *m = NULL;
    struct gnutella_node *n;
    int worst = 0, score, num = 0;

    /* Make list of "worst" based on number of "weird" packets. */
    for (sl = sl_nodes; sl; sl = g_slist_next(sl)) {
        n = sl->data;
        if (n->status != GTA_NODE_CONNECTED)
            continue;

        /* Don't kick whitelisted nodes. */
        if (!non_local && whitelist_check(n->addr))
            continue;

		/* Don't kick nearby hosts if making room for a local node */
		if (non_local && host_is_nearby(n->addr))
			continue;

        score = n->n_weird * 100 + n->n_bad * 10 + n->n_dups;

        if (score > worst) {
            worst = score;
            num = 0;
            if (m) {
                g_slist_free(m);
                m = NULL;
            }
        }
        if (score == worst) {
            m = g_slist_prepend(m, n);
            num++;
        }
    }
    if (m) {
		m = g_slist_reverse(m);
        n = g_slist_nth_data(m, random_value(num - 1));
        g_slist_free(m);
		if (non_local)
			node_bye_if_writable(n, 202, "Local Node Preferred");
		else {
			node_bye_if_writable(n, 202, "Making Room for Another Node");
		}
        return TRUE;
    }

    return FALSE;
}

/**
 * Initiate sending of the query routing table.
 */
static void
node_send_qrt(struct gnutella_node *n, gpointer query_table)
{
	g_assert(current_peermode != NODE_P_NORMAL);
	g_assert(NODE_IS_ULTRA(n));
	g_assert(query_table != NULL);
	g_assert(n->qrt_update == NULL);

	n->qrt_update = qrt_update_create(n, n->sent_query_table);

	if (n->sent_query_table)
		qrt_unref(n->sent_query_table);

	n->sent_query_table = qrt_ref(query_table);
	node_send_patch_step(n);

	node_fire_node_flags_changed(n);
}

/**
 * Incrementally send the routing table patch to our Ultrapeer.
 */
static void
node_send_patch_step(struct gnutella_node *n)
{
	gboolean ok;

	g_assert(NODE_IS_ULTRA(n));
	g_assert(n->qrt_update);

	if (qrt_update_send_next(n->qrt_update))
		return;

	/*
	 * Finished sending.
	 */

	ok = qrt_update_was_ok(n->qrt_update);

	if (node_debug > 2)
		g_message("QRP %spatch sending to %s done (%s)",
			(n->flags & NODE_F_STALE_QRP) ? "stale " : "",
			node_addr(n), ok ? "OK" : "FAILED");

	if (!ok) {
		qrt_unref(n->sent_query_table);
		n->sent_query_table = NULL;			/* Table was not successfuly sent */
	} else
		n->flags |= NODE_F_QRP_SENT;

	qrt_update_free(n->qrt_update);
	n->qrt_update = NULL;

	node_fire_node_flags_changed(n);

	/*
	 * If node was sending a stale QRP patch, we need to send an update.
	 */

	if (n->flags & NODE_F_STALE_QRP) {
		gpointer qrt = qrt_get_table();		/* Latest routing table */
		n->flags &= ~NODE_F_STALE_QRP;		/* Clear flag */
		g_assert(qrt != NULL);				/* Must have a valid table now */
		node_send_qrt(n, qrt);
	}
}

/**
 * Invoked when remote sends us a RESET message, making the existing
 * routing table obsolete.
 */
void
node_qrt_discard(struct gnutella_node *n)
{
	g_assert(n->peermode == NODE_P_LEAF || n->peermode == NODE_P_ULTRA);

	if (n->recv_query_table != NULL) {
		qrt_unref(n->recv_query_table);
		n->recv_query_table = NULL;
	}
	if (n->qrt_info != NULL) {
		wfree(n->qrt_info, sizeof(*n->qrt_info));
		n->qrt_info = NULL;
	}

    node_fire_node_flags_changed(n);
}

/**
 * Invoked for ultra nodes to install new Query Routing Table.
 */
void
node_qrt_install(struct gnutella_node *n, gpointer query_table)
{
	g_assert(NODE_IS_LEAF(n) || NODE_IS_ULTRA(n));
	g_assert(n->recv_query_table == NULL);
	g_assert(n->qrt_info == NULL);

	n->recv_query_table = qrt_ref(query_table);
	n->qrt_info = walloc(sizeof(*n->qrt_info));
	qrt_get_info(query_table, n->qrt_info);

    node_fire_node_flags_changed(n);
}

/**
 * Invoked for ultra nodes when the Query Routing Table of remote node
 * was fully patched (i.e. we got a new generation).
 */
void
node_qrt_patched(struct gnutella_node *n, gpointer query_table)
{
	g_assert(NODE_IS_LEAF(n) || NODE_IS_ULTRA(n));
	g_assert(n->recv_query_table == query_table);
	g_assert(n->qrt_info != NULL);

	qrt_get_info(query_table, n->qrt_info);
}

/**
 * Invoked for nodes when our Query Routing Table changed.
 */
void
node_qrt_changed(gpointer query_table)
{
	struct gnutella_node *n;
	GSList *sl;

	/*
	 * If we're in normal mode, do nothing.
	 *
	 * We have work to do when we're both a leaf and an ultra node, since
	 * both can sent QRT to their peers (leaf nodes send QRT to their
	 * ultranodes, and ultranodes send QRT to peer ultranodes supporting
	 * the inter-UP QRP for last-hop queries).
	 */

	if (current_peermode == NODE_P_NORMAL)
		return;

	/*
	 * Abort sending of any patch to ultranodes, but only if we're a leaf
	 * node.  If we're running as UP, then we'll continue to send our
	 * UP QRP patch to remote UPs, even if it is slightly obsolete.  The
	 * node will be marked with NODE_F_STALE_QRP so we do not forget the
	 * patch was stale.
	 */

	if (current_peermode == NODE_P_LEAF) {
		for (sl = sl_nodes; sl; sl = g_slist_next(sl)) {
			n = sl->data;
			if (n->qrt_update != NULL) {
				qrt_update_free(n->qrt_update);
				n->qrt_update = NULL;
				qrt_unref(n->sent_query_table);
				n->sent_query_table = NULL;		/* Sending did not complete */
			}
		}
	}

	/*
	 * Start sending of patch wrt to the previous table to all ultranodes.
	 * (n->sent_query_table holds the last query table we successfully sent)
	 */

    for (sl = sl_nodes; sl; sl = g_slist_next(sl)) {
        n = sl->data;

		if (!NODE_IS_WRITABLE(n) || !NODE_IS_ULTRA(n))
			continue;

		if (current_peermode == NODE_P_ULTRA && !(n->attrs & NODE_A_UP_QRP))
			continue;

		/*
		 * If we see a node that is still busy sending the old patch, mark
		 * is as holding an obsolete QRP.  It will get the latest patch as
		 * soon as this one completes.
		 */

		if (n->qrt_update != NULL) {
			n->flags |= NODE_F_STALE_QRP;
			continue;
		}

		node_send_qrt(n, query_table);
	}
}

/**
 * Final cleanup when application terminates.
 */
void
node_close(void)
{
	GSList *sl;

	g_assert(in_shutdown);

	/*
	 * Clean up memory used for determining unstable ips / servents
	 */
	for (sl = unstable_servents; sl != NULL; sl = g_slist_next(sl)) {
		node_bad_client_t *bad_node = sl->data;

		g_hash_table_remove(unstable_servent, bad_node->vendor);
		atom_str_free_null(&bad_node->vendor);
		wfree(bad_node, sizeof(*bad_node));
	}
	g_slist_free(unstable_servents);
	unstable_servents = NULL;


	g_hash_table_destroy(unstable_servent);
	unstable_servent = NULL;

	/* Clean up node info */
	while (sl_nodes) {
		struct gnutella_node *n = sl_nodes->data;

		g_assert(n);
		g_assert(n->magic == NODE_MAGIC);

		node_remove(n, no_reason);
		node_real_remove(n);
		n = NULL;
	}

	{
		gnutella_node_t *special_nodes[] = { udp_node, udp6_node, browse_node };
		guint i;

		for (i = 0; i < G_N_ELEMENTS(special_nodes); i++) {
			gnutella_node_t *n;

			n = special_nodes[i];
			if (n) {
				if (n->outq) {
					mq_free(n->outq);
					n->outq = NULL;
				}
				if (n->alive_pings) {
					alive_free(n->alive_pings);
					n->alive_pings = NULL;
				}
				node_real_remove(n);
			}
		}
		udp_node = NULL;
		udp6_node = NULL;
		browse_node = NULL;
	}

	G_FREE_NULL(payload_inflate_buffer);

	g_slist_free(sl_nodes_without_broken_gtkg);
	g_slist_free(sl_proxies);
    g_hash_table_destroy(ht_connected_nodes);
    ht_connected_nodes = NULL;

    g_assert(idtable_ids(node_handle_map) == 0);

	g_hash_table_destroy(nodes_by_id);
    idtable_destroy(node_handle_map);
    node_handle_map = NULL;
	qhvec_free(query_hashvec);

	aging_destroy(tcp_crawls);
	aging_destroy(udp_crawls);

	rxbuf_close();
}

inline void
node_add_sent(gnutella_node_t *n, gint x)
{
   	n->last_update = n->last_tx = tm_time();
	n->sent += x;
}

inline void
node_add_txdrop(gnutella_node_t *n, gint x)
{
	n->last_update = tm_time();
	n->tx_dropped += x;
}

inline void
node_add_rxdrop(gnutella_node_t *n, gint x)
{
   	n->last_update = tm_time();
	n->rx_dropped += x;
}

/**
 * Record vendor name (user-agent string).
 *
 * @param n The gnutella node.
 * @param vendor The payload of the User-Agent header; the assumed character
 *				 encoding is ISO-8859-1.
 */
void
node_set_vendor(gnutella_node_t *n, const gchar *vendor)
{
	gchar *wbuf = NULL;
	size_t size = 0;

	if (n->flags & NODE_F_FAKE_NAME) {
		size = w_concat_strings(&wbuf, "!", vendor, (void *) 0);
	} else {
		static const char full[] = "Morpheus";
		gboolean fix;

		/*
		 * Morpheus names its servents as "morph350" or "morph461" and
		 * this perturbs the anti-monopoly features by making them appear
		 * as all different whereas they are really incarnations of the
		 * same servent.  Normalize their name.
		 */
		
		fix = is_strcaseprefix(vendor, "morph") &&
				0 != strcmp_delimit(vendor, full, " /");
		if (fix)
			size = w_concat_strings(&wbuf, full, " (", vendor, ")", (void *) 0);
	}

	n->vendor = atom_str_get(lazy_iso8859_1_to_utf8(wbuf ? wbuf : vendor));
	if (wbuf) {
		wfree(wbuf, size);
		wbuf = NULL;
	}

    node_fire_node_info_changed(n);
}

/**
 * Called when a vendor-specific "hops-flow" message was received to tell
 * us to update the hops-flow counter for the connection: no query whose
 * hop count is greater or equal to the specified `hops' should be sent
 * to that node.
 */
void
node_set_hops_flow(gnutella_node_t *n, guint8 hops)
{
	struct node_rxfc_mon *rxfc;

	n->hops_flow = hops;

	/*
	 * There is no monitoring of flow control when the remote node is
	 * a leaf node: it is permitted for the leaf to send us an hops-flow
	 * to disable all query sending if it is not sharing anything.
	 *
	 * We're recording the time at which the flow-control happens though.
	 * When we're running out of leaf slots, we may want to close connections
	 * to leaves under flow-control for a long time, since they are not
	 * searchable.  We consider that hops <= 1 is very restrictive.
	 */

	if (n->peermode == NODE_P_LEAF) {
		n->leaf_flowc_start = hops <= 1 ? tm_time() : 0;
		goto fire;
	}

	/*
	 * If we're starting flow control (hops < GTA_NORMAL_TTL), make sure
	 * to create the monitoring structure if absent.
	 */

	if (hops < GTA_NORMAL_TTL && n->rxfc == NULL) {
		n->rxfc = walloc0(sizeof(*n->rxfc));
		n->rxfc->start_half_period = tm_time();
	}

	g_assert(n->rxfc != NULL || hops >= GTA_NORMAL_TTL);

	rxfc = n->rxfc;

	if (rxfc == NULL)
		goto fire;

	if (hops < GTA_NORMAL_TTL) {
		/* Entering hops-flow control */
		if (rxfc->fc_start == 0)		/* Not previously under flow control */
			rxfc->fc_start = tm_time();
	} else if (rxfc->fc_start != 0)	{	/* We were under flow control */
		/* Leaving hops-flow control */
		rxfc->fc_accumulator += tm_time() - rxfc->fc_start;
		rxfc->fc_start = 0;
	}

fire:
    node_fire_node_flags_changed(n);
}

/**
 * Fetches information about a given node.
 *
 * The returned information must be freed manually by the caller using
 * the node_free_info call.
 *
 * O(1):
 * Since the gnet_node_t is actually a pointer to the gnutella_node
 * struct, this call is O(1). It would be safer to have gnet_node be
 * an index in a list or a number, but depending on the underlying
 * container structure of sl_nodes, that would have O(log(n)) (balanced
 * tree) or O(n) (list) runtime.
 */
gnet_node_info_t *
node_get_info(const gnet_node_t n)
{
    gnet_node_info_t *info;

	info = walloc(sizeof *info);
	node_fill_info(n, info);
    return info;
}

/**
 * Clear dynamically allocated information from the info structure.
 */
void
node_clear_info(gnet_node_info_t *info)
{
	atom_str_free_null(&info->vendor);
}

/**
 * Frees the gnet_node_info_t data returned by node_get_info.
 */
void
node_free_info(gnet_node_info_t *info)
{
	node_clear_info(info);
    wfree(info, sizeof *info);
}

/**
 * Fill in supplied info structure.
 */
void
node_fill_info(const gnet_node_t n, gnet_node_info_t *info)
{
    gnutella_node_t  *node = node_find_by_handle(n);

    info->node_handle = n;

    info->proto_major = node->proto_major;
    info->proto_minor = node->proto_minor;
    info->vendor = node->vendor ? atom_str_get(node->vendor) : NULL;
    info->country = node->country;
    info->vcode = node->vcode;

    info->addr = node->addr;
    info->port = node->port;

	info->is_pseudo = node == udp_node || node == udp6_node;

	if (info->is_pseudo) {
    	info->addr = node == udp_node ? listen_addr() : listen_addr6();
    	info->port = listen_port;
		info->gnet_addr = info->addr;
		info->gnet_port = info->port;
	} else if (host_addr_initialized(node->gnet_addr)) {
		info->gnet_addr = node->gnet_addr;
		info->gnet_port = node->gnet_port;
	} else {
		info->gnet_addr = zero_host_addr;
		info->gnet_port = 0;
	}

	if (node->gnet_guid != NULL)
		memcpy(info->gnet_guid, node->gnet_guid, GUID_RAW_SIZE);
	else
		memcpy(info->gnet_guid, blank_guid, GUID_RAW_SIZE);
}

/**
 * Fill in supplied flags structure.
 */
void
node_fill_flags(const gnet_node_t n, gnet_node_flags_t *flags)
{
	gnutella_node_t *node = node_find_by_handle(n);

	flags->peermode = node->peermode;
	if (node->peermode == NODE_P_UNKNOWN) {
		if (node->flags & NODE_F_CRAWLER)
			flags->peermode = NODE_P_CRAWLER;
		else if (node->attrs & NODE_A_ULTRA)
			flags->peermode = NODE_P_ULTRA;
		else if (node->attrs & NODE_A_CAN_ULTRA)
			flags->peermode = NODE_P_LEAF;
		else if (node->attrs & NODE_A_NO_ULTRA)
			flags->peermode = NODE_P_NORMAL;
	}

	flags->incoming = node->flags & NODE_F_INCOMING;
	flags->writable = NODE_IS_WRITABLE(node);
	flags->readable = NODE_IS_READABLE(node);
    flags->tx_compressed = NODE_TX_COMPRESSED(node);
    flags->mqueue_empty  = 0 == NODE_MQUEUE_COUNT(node);
    flags->mqueue_above_lowat  = NODE_MQUEUE_ABOVE_LOWAT(node);
    flags->in_tx_flow_control = NODE_IN_TX_FLOW_CONTROL(node);
    flags->in_tx_swift_control = NODE_IN_TX_SWIFT_CONTROL(node);
    flags->rx_compressed = NODE_RX_COMPRESSED(node);
	flags->hops_flow = node->hops_flow;

	flags->is_push_proxied = (node->flags & NODE_F_PROXIED) ? TRUE : FALSE;
	flags->is_proxying = is_host_addr(node->proxy_addr);
	flags->tls = (node->flags & NODE_F_TLS) != 0;

	flags->qrt_state = QRT_S_NONE;
	flags->uqrt_state = QRT_S_NONE;

	if (node->peermode == NODE_P_LEAF) {
		/* Remote leaf connected to us, ultranode */
		if (node->qrt_receive != NULL)
			flags->qrt_state = node->recv_query_table != NULL ?
				QRT_S_PATCHING : QRT_S_RECEIVING;
		else if (node->recv_query_table != NULL)
			flags->qrt_state = QRT_S_RECEIVED;
	} else if (node->peermode == NODE_P_ULTRA) {
		if (current_peermode == NODE_P_ULTRA) {
			/* Remote ultranode connected to us, ultranode */
			if (node->qrt_receive != NULL)
				flags->qrt_state = node->recv_query_table != NULL ?
					QRT_S_PATCHING : QRT_S_RECEIVING;
			else if (node->recv_query_table != NULL)
				flags->qrt_state = QRT_S_RECEIVED;
			if (node->qrt_update != NULL)
				flags->uqrt_state = (node->flags & NODE_F_QRP_SENT) ?
					QRT_S_PATCHING : QRT_S_SENDING;
			else if (node->sent_query_table != NULL)
				flags->uqrt_state = QRT_S_SENT;
		} else {
			/* Ultranode connected to us, leaf node */
			if (node->qrt_update != NULL)
				flags->qrt_state = (node->flags & NODE_F_QRP_SENT) ?
					QRT_S_PATCHING : QRT_S_SENDING;
			else if (node->sent_query_table != NULL)
				flags->qrt_state = QRT_S_SENT;
		}
	}
}

/**
 * Fetch node status for the GUI display.
 */
void
node_get_status(const gnet_node_t n, gnet_node_status_t *status)
{
    const gnutella_node_t  *node = node_find_by_handle(n);

    g_assert(status != NULL);

    status->status     = node->status;

	status->connect_date = node->connect_date;
	status->up_date      = node->up_date;

	if (is_host_addr(node->gnet_pong_addr)) {
		/* Got a pong from this node, library info should be accurate */
		status->gnet_files_count  = node->gnet_files_count;
		status->gnet_kbytes_count = node->gnet_kbytes_count;
		status->gnet_info_known = TRUE;
	} else
		status->gnet_info_known = FALSE;

    status->sent       = node->sent;
    status->received   = node->received;
    status->tx_dropped = node->tx_dropped;
    status->rx_dropped = node->rx_dropped;
    status->n_bad      = node->n_bad;
    status->n_dups     = node->n_dups;
    status->n_hard_ttl = node->n_hard_ttl;
    status->n_weird    = node->n_weird;
    status->n_hostile  = node->n_hostile;
    status->n_spam     = node->n_spam;
    status->n_evil     = node->n_evil;

    status->squeue_sent         = NODE_SQUEUE_SENT(node);
    status->squeue_count        = NODE_SQUEUE_COUNT(node);
    status->mqueue_count        = NODE_MQUEUE_COUNT(node);
    status->mqueue_percent_used = NODE_MQUEUE_PERCENT_USED(node);
    status->in_tx_flow_control  = NODE_IN_TX_FLOW_CONTROL(node);
    status->in_tx_swift_control = NODE_IN_TX_SWIFT_CONTROL(node);

    status->tx_given    = node->tx_given;
    status->tx_deflated = node->tx_deflated;
    status->tx_written  = node->tx_written;
    status->tx_compressed = NODE_TX_COMPRESSED(node);
    status->tx_compression_ratio = NODE_TX_COMPRESSION_RATIO(node);
	status->tx_bps = node->outq ? bio_bps(mq_bio(node->outq)) : 0;

    status->rx_given    = node->rx_given;
    status->rx_inflated = node->rx_inflated;
    status->rx_read     = node->rx_read;
    status->rx_compressed = NODE_RX_COMPRESSED(node);
    status->rx_compression_ratio = NODE_RX_COMPRESSION_RATIO(node);

	status->tcp_rtt = node->tcp_rtt;
	status->udp_rtt = node->udp_rtt;

	/*
	 * The UDP node has no RX stack: we direcly receive datagrams from
	 * the socket layer, and they are meant to be one Gntuella message.
	 * Therefore, the actual traffic is given by the bws.gin_udp scheduler.
	 */

	if (NODE_IS_UDP(node))
		status->rx_bps = bsched_bps(BSCHED_BWS_GIN_UDP);
	else {
		bio_source_t *bio = node->rx ? rx_bio_source(node->rx) : NULL;
		status->rx_bps = bio ? bio_bps(bio) : 0;
	}

	status->qrp_efficiency =
		(gfloat) node->qrp_matches / (gfloat) MAX(1, node->qrp_queries);
	status->has_qrp = current_peermode == NODE_P_LEAF &&
		node_ultra_received_qrp(node);

	if (node->qrt_info != NULL) {
		qrt_info_t *qi = node->qrt_info;
		status->qrt_slots = qi->slots;
		status->qrt_generation = qi->generation;
		status->qrt_fill_ratio = qi->fill_ratio;
		status->qrt_pass_throw = qi->pass_throw;
	} else
		status->qrt_slots = 0;

	status->rx_queries = node->rx_queries;
	status->tx_queries = node->tx_queries;
	status->rx_qhits   = node->rx_qhits;
	status->tx_qhits   = node->tx_qhits;

	if (node->shutdown_delay) {
		gint d = delta_time(tm_time(), node->shutdown_date);

   		status->shutdown_remain = (gint) node->shutdown_delay > d
			? node->shutdown_delay - d : 0;
	} else {
		status->shutdown_remain = 0;
	}

    if (node->error_str != NULL)
        g_strlcpy(status->message, node->error_str, sizeof(status->message));
    else if (node->remove_msg != NULL)
        g_strlcpy(status->message, node->remove_msg, sizeof(status->message));
    else
        status->message[0] = '\0';

	if (node->alive_pings != NULL && node->status == GTA_NODE_CONNECTED)
		alive_get_roundtrip_ms(node->alive_pings,
			&status->rt_avg, &status->rt_last);
}

/**
 * Disconnect from the given list of node handles. The list may not contain
 * NULL elements or duplicate elements.
 */
void
node_remove_nodes_by_handle(GSList *node_list)
{
    GSList *sl;

    for (sl = node_list; sl != NULL; sl = g_slist_next(sl))
        node_remove_by_handle((gnet_node_t) GPOINTER_TO_UINT(sl->data));
}

/***
 *** Public functions
 ***/

/**
 * @return the address:port of a node
 */
const gchar *
node_addr(const gnutella_node_t *n)
{
	static gchar buf[HOST_ADDR_PORT_BUFLEN];

	g_assert(n);
	host_addr_port_to_string_buf(n->addr, n->port, buf, sizeof buf);
	return buf;
}

/**
 * @return the address:port of a node
 */
const gchar *
node_addr2(const gnutella_node_t *n)
{
	static gchar buf[HOST_ADDR_PORT_BUFLEN];

	g_assert(n);
	host_addr_port_to_string_buf(n->addr, n->port, buf, sizeof buf);
	return buf;
}

/**
 * @return the advertised Gnutella ip:port of a node if known, otherwise
 * just the IP address..
 */
const gchar *
node_gnet_addr(const gnutella_node_t *n)
{
	static gchar buf[HOST_ADDR_PORT_BUFLEN];

	g_assert(n);

	if (is_host_addr(n->gnet_addr))
		host_addr_port_to_string_buf(n->gnet_addr, n->gnet_port,
			buf, sizeof buf);
	else
		host_addr_to_string_buf(n->addr, buf, sizeof buf);

	return buf;
}

/**
 * Connect back to node on specified port and emit a "\n\n" sequence.
 *
 * This is called when a "Connect Back" vendor-specific message (BEAR/7v1)
 * is received.  This scheme is used by servents to detect whether they
 * are firewalled.
 */
void
node_connect_back(const gnutella_node_t *n, guint16 port)
{
	struct gnutella_socket *s;

	/*
	 * Attempt asynchronous connection.
	 *
	 * When connection is established, node_connected_back() will be called
	 * from the socket layer.
	 */

	s = socket_connect(n->addr, port, SOCK_TYPE_CONNBACK, SOCK_F_TLS);

	if (s == NULL)
		return;

	/*
	 * There is no specific resource attached to the socket.
	 */
}

/**
 * Callback invoked from the socket layer when we are finally connected.
 */
void
node_connected_back(struct gnutella_socket *s)
{
	static gchar msg[] = "\n\n";

	if (node_debug > 4)
		g_message("connected back to %s",
			host_addr_port_to_string(s->addr, s->port));

	(void) bws_write(BSCHED_BWS_OUT, &s->wio, msg, sizeof msg - 1);

	socket_free_null(&s);
}

/**
 * Remove push proxy indication for the node, i.e. we're no longer acting
 * as its push-proxy from now on.  If `discard' is true, get rid of the
 * GUID and route information.
 */
void
node_proxying_remove(gnutella_node_t *n, gboolean discard)
{
	n->flags &= ~NODE_F_PROXIED;

	if (n->guid && discard) {
		route_proxy_remove(n->guid);
		atom_guid_free_null(&n->guid);
	}

	node_fire_node_flags_changed(n);
}

/**
 * Record that node wants us to be his push proxy.
 *
 * @return TRUE if we can act as this node's proxy.
 */
gboolean
node_proxying_add(gnutella_node_t *n, const gchar *guid)
{
	/*
	 * If we're firewalled, we can't accept.
	 */

	if (is_firewalled) {
		if (node_debug) g_warning(
			"denying push-proxyfication for %s <%s>: firewalled",
			node_addr(n), node_vendor(n));
		return FALSE;
	}

	/*
	 * If our IP is not reacheable, deny as well.
	 */

	if (
		!host_is_valid(listen_addr(), socket_listen_port()) &&
		!host_is_valid(listen_addr6(), socket_listen_port())
	) {
		if (node_debug) g_warning(
			"denying push-proxyfication for %s <%s>: "
			"current IPs %s/%s are invalid",
			node_addr(n), node_vendor(n),
			host_addr_port_to_string(listen_addr(), socket_listen_port()),
			host_addr_port_to_string(listen_addr6(), socket_listen_port()));
		return FALSE;
	}

	/*
	 * Did we already get a proxyfication request for the node?
	 * Maybe he did not get our ACK and is retrying?
	 *
	 * NB: we must handle the fact that a node could have sent us a
	 * "Push-Proxy Cancel" message, and then later a "Push-Proxy Request".
	 * So we can have a GUID recorded already, but NODE_F_PROXIED cleared.
	 */

	if (n->guid != NULL) {
		gchar old[33];

		if (n->flags & NODE_F_PROXIED)
			if (node_debug) g_warning(
				"spurious push-proxyfication request from %s <%s>",
				node_addr(n), node_vendor(n));

		if (!guid_eq(guid, n->guid)) {
			strncpy(old, guid_hex_str(n->guid), sizeof(old));

			if (node_debug) g_warning(
				"new GUID %s for node %s <%s> (was %s)",
				guid_hex_str(guid), node_addr(n), node_vendor(n), old);

			route_proxy_remove(n->guid);
			atom_guid_free_null(&n->guid);
		}
	}

	n->flags |= NODE_F_PROXIED;

	if (n->guid != NULL)
		return TRUE;				/* Route already recorded */

	n->guid = atom_guid_get(guid);
	if (route_proxy_add(n->guid, n)) {
		node_fire_node_flags_changed(n);
		return TRUE;
	}

	if (node_debug) g_warning(
		"push-proxyfication failed for %s <%s>: conflicting GUID %s",
		node_addr(n), node_vendor(n), guid_hex_str(guid));

	atom_guid_free_null(&n->guid);
	n->flags &= ~NODE_F_PROXIED;

	return FALSE;
}

/**
 * Add node to our list of push-proxies.
 */
void
node_proxy_add(gnutella_node_t *n, const host_addr_t addr, guint16 port)
{
	if (!(n->flags & NODE_F_PROXY)) {
		g_warning("got spurious push-proxy ack from %s <%s>",
			node_addr(n), node_vendor(n));
		return;
	}

	n->flags &= ~NODE_F_PROXY;

	if (!is_firewalled) {
		g_warning("ignoring push-proxy ack from %s <%s>: no longer firewalled",
			node_addr(n), node_vendor(n));
		return;
	}

	/*
	 * Paranoid sanity checks.
	 */

	if (
		node_debug &&
		is_host_addr(n->gnet_addr) &&
		(!host_addr_equal(addr, n->gnet_addr) || port != n->gnet_port)
	)
		g_warning("push-proxy address %s from %s <%s> does not match "
			"its advertised node address %s:%u",
			host_addr_port_to_string(addr, port), node_addr(n), node_vendor(n),
			host_addr_to_string(n->gnet_addr), n->gnet_port);

	if (!host_addr_equal(addr, n->addr)) {
		g_warning("push-proxy address %s from %s <%s> not on same host",
			host_addr_port_to_string(addr, port),
			node_addr(n), node_vendor(n));
		if (is_host_addr(n->gnet_addr) && host_addr_equal(addr, n->gnet_addr))
			g_warning("however address %s matches the advertised node address",
				host_addr_port_to_string(addr, port));
	}

	n->proxy_addr = addr;
	n->proxy_port = port;

	sl_proxies = g_slist_prepend(sl_proxies, n);
}

/**
 * Cancel all our known push-proxies.
 */
void
node_proxy_cancel_all(void)
{
	GSList *sl;

	for (sl = sl_proxies; sl; sl = g_slist_next(sl)) {
		gnutella_node_t *n = sl->data;

		vmsg_send_proxy_cancel(n);
		n->proxy_addr = zero_host_addr;
		n->proxy_port = 0;
	}

	g_slist_free(sl_proxies);
	sl_proxies = NULL;
}

/**
 * HTTP status callback.
 *
 * If we are still firewalled and have push-proxies, let the downloader
 * know about them via the X-Push-Proxy header.
 */
void
node_http_proxies_add(gchar *buf, gint *retval,
		gpointer unused_arg, guint32 unused_flags)
{
	gint rw = 0;
	gint length = *retval;		/* Space available, starting at `buf' */

	(void) unused_arg;
	(void) unused_flags;

	if (is_firewalled && sl_proxies != NULL) {
		gpointer fmt = header_fmt_make("X-Push-Proxy", ", ", 0);
		GSList *sl;
		gint len;

		for (sl = sl_proxies; sl; sl = g_slist_next(sl)) {
			struct gnutella_node *n = sl->data;
			const gchar *str;

			/* Must be non-null if it's our proxy */
			g_assert(is_host_addr(n->proxy_addr));

			str = host_addr_port_to_string(n->proxy_addr, n->proxy_port);
			header_fmt_append_value(fmt, str);
		}

		header_fmt_end(fmt);
		len = header_fmt_length(fmt);

		if (len < length) {
			strncpy(buf, header_fmt_string(fmt), length);
			rw += len;
		}

		header_fmt_free(fmt);
	}

	*retval = rw;			/* Tell them how much we wrote into `buf' */
}

/**
 * @return list of our push-proxies.
 */
GSList *
node_push_proxies(void)
{
	return sl_proxies;
}

/**
 * @return list of all nodes.
 */
const GSList *
node_all_nodes(void)
{
	return (const GSList *) sl_nodes;
}

/**
 * @return list of all nodes without any broken GTKG (those nodes that must
 * not be forwarded any duplicate message, even with a higher TTL than
 * previously sent).
 */
const GSList *
node_all_but_broken_gtkg(void)
{
	return (const GSList *) sl_nodes_without_broken_gtkg;
}


/**
 * @return writable node given its ID, or NULL if we can't reach that node.
 */
gnutella_node_t *
node_active_by_id(guint32 id)
{
	gnutella_node_t *n;

	n = g_hash_table_lookup(nodes_by_id, GUINT_TO_POINTER(id));
	if (n == NULL || !NODE_IS_WRITABLE(n))
		return NULL;

	return n;
}

/**
 * Set leaf-guidance support indication from give node ID.
 */
void
node_set_leaf_guidance(guint32 id, gboolean supported)
{
	gnutella_node_t *n;

	n = node_active_by_id(id);
	if (n != NULL) {
		if (supported)
			n->attrs |= NODE_A_GUIDANCE;		/* Record support */
		else
			n->attrs &= ~NODE_A_GUIDANCE;		/* Clears support */
	}
}

/***
 *** UDP Crawling
 ***/

/**
 * qsort() callback for sorting nodes by user-agent.
 */
static gint
node_ua_cmp(const void *np1, const void *np2)
{
	const gnutella_node_t *n1 = *(const gnutella_node_t **) np1;
	const gnutella_node_t *n2 = *(const gnutella_node_t **) np2;

	/*
	 * Put gtk-gnutella nodes at the beginning of the array.
	 */

	if (n1->flags & NODE_F_GTKG)
		return (n2->flags & NODE_F_GTKG) ? strcmp(n1->vendor, n2->vendor) : -1;

	if (n2->flags & NODE_F_GTKG)
		return (n1->flags & NODE_F_GTKG) ? strcmp(n1->vendor, n2->vendor) : +1;

	/*
	 * Nodes without user-agent are put at the end of the array.
	 */

	if (n1->vendor == NULL)
		return (n2->vendor == NULL) ? 0 : +1;

	if (n2->vendor == NULL)
		return (n1->vendor == NULL) ? 0 : -1;

	return strcmp(n1->vendor, n2->vendor);
}

/**
 * Append user-agent string to the string holding them, each value being
 * separated from the previous with NODE_CR_SEPARATOR.
 *
 * The LimeWire crawler expects a very simple escaping whereby every
 * separator found in the vendor string is preceded by NODE_CR_ESCAPE_CHAR.
 * We further escape the escape character with itself, if found.
 */
static void
node_crawl_append_vendor(GString *ua, const gchar *vendor)
{
	const gchar *p = vendor;
	gchar c;

	while ((c = *p++)) {
		if (c == NODE_CR_ESCAPE_CHAR) {
			g_string_append_c(ua, NODE_CR_ESCAPE_CHAR);
			g_string_append_c(ua, NODE_CR_ESCAPE_CHAR);
		} else if (c == NODE_CR_SEPARATOR) {
			g_string_append_c(ua, NODE_CR_ESCAPE_CHAR);
			g_string_append_c(ua, c);
		} else
			g_string_append_c(ua, c);
	}

	g_string_append_c(ua, NODE_CR_SEPARATOR);
}

/**
 * Fill message with the selected crawling information.
 *
 * @param mb		the message into which we're writing
 * @param ary		the node array
 * @param start		the starting index in the array
 * @param len		the array length
 * @param want		the amount of entries they want
 * @param features	the selected features to insert
 * @param now		current time, for connection time computation
 * @param ua		the concatenated user-agent string
 * @param gtkg		if TRUE only Gtk-Gnutella nodes are added,
 *					otherwise only nodes of other vendors are added.
 *
 * @return the amount of entries successfully written
 */
static gint
node_crawl_fill(pmsg_t *mb,
	gnutella_node_t **ary, gint start, gint len, gint want,
	guint8 features, time_t now, GString *ua, gboolean gtkg)
{
	gint i, j;
	gint written = 0;

	g_assert(ary != NULL);
	g_assert(want > 0);
	g_assert(len > 0);
	g_assert(start < len);

	for (i = start, j = 0; written < want && j < len; j++) {
		host_addr_t ha;
		gnutella_node_t *n = ary[i];
		gchar addr[6];

		if (!gtkg != !(n->flags & NODE_F_GTKG))
			goto next;

		/*
		 * Add node's address (IP:port).
		 */

		if (!host_addr_convert(n->gnet_addr, &ha, NET_TYPE_IPV4))
			goto next;

		poke_be32(&addr[0], host_addr_ipv4(ha));
		poke_le16(&addr[4], n->gnet_port);

		if (sizeof addr != pmsg_write(mb, addr, sizeof addr))
			break;

		/*
		 * If they want the connection time, report it in minutes on
		 * a two-byte value, emitted in little-endian.
		 */

		if (features & NODE_CR_CONNECTION) {
			glong connected = delta_time(now, n->connect_date);
			guint32 minutes = connected > 0 ? connected / 60 : 0;
			gchar value[2];

			minutes = MIN(minutes, 0xffffU);
			WRITE_GUINT16_LE(minutes, value);

			if (sizeof value != pmsg_write(mb, value, sizeof value))
				break;
		}

		/*
		 * If they want the user-agent of the nodes, append the node's
		 * vendor to the `ua' string, or "" if unknown.
		 */

		if (features & NODE_CR_USER_AGENT)
			node_crawl_append_vendor(ua, n->vendor ? n->vendor : "");

		written++;			/* Completely written */
	next:
		i++;
		if (i == len)		/* Wrap around index */
			i = 0;
	}

	return written;
}

/**
 * Received an UDP crawler ping, requesting information about `ucnt' ultra
 * nodes and `lcnt' leaves.  Processing is further customized with some
 * `features', a set of flags.
 */
void
node_crawl(gnutella_node_t *n, gint ucnt, gint lcnt, guint8 features)
{
	gnutella_node_t **ultras = NULL;	/* Array  of ultra nodes		*/
	gnutella_node_t **leaves = NULL;	/* Array  of `leaves'			*/
	gint ultras_len = 0;				/* Size   of `ultras'			*/
	gint leaves_len = 0;				/* Size   of `leaves'			*/
	gint ux = 0;						/* Index  in `ultras'			*/
	gint lx = 0;						/* Index  in `leaves'			*/
	gint ui;							/* Iterating index in `ultras'	*/
	gint li;							/* Iterating index in `leaves'	*/
	gint un;							/* Amount of `ultras' to send	*/
	gint ln;							/* Amount of `leaves' to send	*/
	GSList *sl;
	gboolean crawlable_only = (features & NODE_CR_CRAWLABLE) ? TRUE : FALSE;
	gboolean wants_ua = (features & NODE_CR_USER_AGENT) ? TRUE : FALSE;
	pmsg_t *mb = NULL;
	pdata_t *db;
	guchar *payload;					/* Start of constructed payload */
	GString *agents = NULL;				/* The string holding user-agents */
	time_t now;

	g_assert(NODE_IS_UDP(n));
	g_assert(ucnt >= 0 && ucnt <= 255);
	g_assert(lcnt >= 0 && lcnt <= 255);

	gnet_prop_set_guint32_val(PROP_UDP_CRAWLER_VISIT_COUNT,
		udp_crawler_visit_count + 1);

	/*
	 * Make sure they're not crawling us too often.
	 */

	if (aging_lookup(udp_crawls, &n->addr)) {
		g_warning("rejecting UDP crawler request from %s", node_addr(n));
		return;
	}

	aging_insert(udp_crawls,
		wcopy(&n->addr, sizeof n->addr), GUINT_TO_POINTER(1));

	/*
	 * Build an array of candidate nodes.
	 */

	if (ucnt && node_ultra_count) {
		ultras_len = node_ultra_count * sizeof(gnutella_node_t *);
		ultras = walloc(ultras_len);
	}

	if (lcnt && node_leaf_count) {
		leaves_len = node_leaf_count * sizeof(gnutella_node_t *);
		leaves = walloc(leaves_len);
	}

	for (sl = sl_nodes; sl; sl = g_slist_next(sl)) {
		gnutella_node_t *cn = sl->data;

		if (!NODE_IS_ESTABLISHED(cn))
			continue;

		if (!is_host_addr(cn->gnet_addr))	/* No information about node yet */
			continue;

		if (crawlable_only && !(cn->attrs & NODE_A_CRAWLABLE))
			continue;

		if (ucnt && NODE_IS_ULTRA(cn)) {
			g_assert((guint) ux < node_ultra_count);
			ultras[ux++] = cn;
			continue;
		}

		if (lcnt && NODE_IS_LEAF(cn)) {
			g_assert((guint) lx < node_leaf_count);
			leaves[lx++] = cn;
			continue;
		}
	}

	if (ux + lx == 0)		/* Nothing selected */
		goto cleanup;

	/*
	 * If they want user-agent strings, sort the arrays by user-agent string,
	 * so that data can be better compressed.
	 */

	if (wants_ua) {
		if (ux)
			qsort(ultras, ux, sizeof(gnutella_node_t *), node_ua_cmp);
		if (lx)
			qsort(leaves, lx, sizeof(gnutella_node_t *), node_ua_cmp);
	}

	/*
	 * If we have more items than they really want, trim down by randomizing
	 * the index in the array at which we'll start iterating.
	 */

	ui = (ux <= ucnt) ? 0 : ucnt ? random_value(ucnt - 1) : 0;
	li = (lx <= lcnt) ? 0 : lcnt ? random_value(lcnt - 1) : 0;

	/*
	 * Construct the payload of the reply in a message buffer.
	 * We indicate that the first 3 bytes are already "written", since
	 * they will be inserted manually.
	 */

	db = rxbuf_new();
	mb = pmsg_alloc(PMSG_P_DATA, db, 0, 3);		/* 3 bytes of header */
	payload = (guchar *) pmsg_start(mb);

	/*
	 * The first 3 bytes of the payload are:
	 *
	 *	1- # of ultra node returned.
	 *	2- # of leaf nodes returned.
	 *  3- the features we retained.
	 */

	features &= ~NODE_CR_LOCALE;	/* XXX no support for locales yet */

	un = MIN(ux, ucnt);
	ln = MIN(lx, lcnt);

	payload[0] = un;
	payload[1] = ln;
	payload[2] = features;

	g_assert(pmsg_size(mb) == 3);

	/*
	 * We start looping over the ultra nodes, then continue with the leaf
	 * nodes.  For each entry, we write the IP:port, followed by one or all
	 * of the following: connection time in minutes, language info.
	 */

	now = tm_time();

	if (features & NODE_CR_USER_AGENT)
		agents = g_string_sized_new((un + ln) * 15);

	/*
	 * Insert GTKG nodes first, and if there is room, non-GTKG nodes starting
	 * from the selected random place if we have to put less than we have.
	 */

	if (un) {
		gint w;
		w = node_crawl_fill(mb, ultras, 0, ux, un, features, now, agents, TRUE);
		if (w < un)
			w += node_crawl_fill(
				mb, ultras, ui, ux, un - w, features, now, agents, FALSE);
		ui = w;
	}

	if (ln) {
		gint w;
		w = node_crawl_fill(mb, leaves, 0, lx, ln, features, now, agents, TRUE);
		if (w < ln)
			w += node_crawl_fill(
				mb, leaves, li, lx, ln - w, features, now, agents, FALSE);
		li = w;
	}

	if (ui != un) {
		g_assert(ui < un);
		payload[0] = ui;
		g_warning("crawler pong can only hold %d ultras out of selected %d",
			ui, un);
	}

	if (li != ln) {
		g_assert(li < ln);
		payload[1] = li;
		g_warning("crawler pong can only hold %d leaves out of selected %d",
			li, ln);
	}

	if (ui + li == 0) {
		g_warning("crawler pong ended up having nothing to send back");
		goto cleanup;
	}

	/*
	 * If they want user-agents, compress the string we have.
	 */

	if (features & NODE_CR_USER_AGENT) {
		zlib_deflater_t *zd;
		gint ret;

		g_assert(agents->len > 0);

		/*
		 * Append our own vendor string to the list.
		 */

		node_crawl_append_vendor(agents, version_string);

		zd = zlib_deflater_make(
			agents->str,
			agents->len - 1,			/* Drop trailing separator */
			Z_DEFAULT_COMPRESSION);

		ret = zlib_deflate(zd, agents->len - 1);	/* Compress the whole */

		if (ret != 0) {
			if (ret == -1)
				g_warning("crawler user-agent compression failed");
			else
				g_warning("crawler user-agent compression did not terminate?");

			payload[2] &= ~NODE_CR_USER_AGENT;		/* Don't include it then */
		} else {
			gchar *dpayload = zlib_deflater_out(zd);
			gint dlen = zlib_deflater_outlen(zd);
			gint remains;

			if (node_debug) g_message(
				"crawler compressed %d bytes user-agent string into %d",
				(gint) (agents->len - 1), dlen);

			/*
			 * If we have room to include it, do so.
			 */

			remains = pdata_len(db) - pmsg_size(mb);
			if (remains < dlen)
				g_warning("crawler cannot include %d bytes user-agent: "
					"only %d bytes left in buffer", dlen, remains);
			else {
				pmsg_write(mb, dpayload, dlen);
				g_assert((size_t) dlen ==
					pmsg_size(mb) - pdata_len(db) + remains);
			}
		}

		zlib_deflater_free(zd, TRUE);
	}

	if (node_debug) g_message(
		"UDP crawler sending data for %u/%u ultras and %u/%u leaves: %d bytes, "
		"features=0x%x to %s",
		payload[0], ux, payload[1], lx, pmsg_size(mb), payload[2],
		node_addr(n));

	vmsg_send_udp_crawler_pong(n, mb);

	/* FALL THROUGH */

cleanup:
	if (mb)
		pmsg_free(mb);
	if (ultras)
		wfree(ultras, ultras_len);
	if (leaves)
		wfree(leaves, leaves_len);
	if (agents)
		g_string_free(agents, TRUE);
}

/**
 * This has to be called once the UDP socket (e.g., due to a changed port
 * number) was changed because some internal references have to be updated.
 */
void
node_update_udp_socket(void)
{
	node_udp_disable();
	if ((udp_node || udp6_node) && udp_active())
		node_udp_enable();
}

/**
 * Display a summary of the node flags.
 *
 * The stuff in the Flags column means:
 *
 *  - 012345678AB (offset)
 *  - NIrwqxZPFhE
 *  - ^^^^^^^^^^^
 *  - ||||||||||+ E indicates a TLS encrypted connection
 *  - |||||||||+  hops flow triggerd (h), or total query flow control (f)
 *  - ||||||||+   flow control (F), or pending data in queue (d)
 *  - |||||||+    indicates whether we're a push proxy (P) / node is proxy (p)
 *  - ||||||+     indicates whether RX, TX or both (Z) are compressed
 *  - |||||+      indicates whether we sent our last-hop QRT to remote UP
 *  - ||||+       indicates whether we sent/received a QRT, or send/receive one
 *  - |||+        indicates whether node is writable
 *  - ||+         indicates whether node is readable
 *  - |+          indicates connection type (Incoming, Outgoing, Ponging)
 *  - +           indicates peer mode (Normal, Ultra, Leaf)
 */
const gchar *
node_flags_to_string(const gnet_node_flags_t *flags)
{
	static gchar status[] = "NIrwqTRPFhE";

	switch (flags->peermode) {
	case NODE_P_UNKNOWN:	status[0] = '-'; break;
	case NODE_P_ULTRA:		status[0] = 'U'; break;
	case NODE_P_NORMAL:		status[0] = 'N'; break;
	case NODE_P_LEAF:		status[0] = 'L'; break;
	case NODE_P_CRAWLER:	status[0] = 'C'; break;
	case NODE_P_UDP:		status[0] = 'P'; break;
	default:				g_assert_not_reached(); break;
	}

	status[1] = flags->incoming ? 'I' : 'O';
	status[2] = flags->readable ? 'r' : '-';
	status[3] = flags->writable ? 'w' : '-';

	switch (flags->qrt_state) {
	case QRT_S_SENT: case QRT_S_RECEIVED:		status[4] = 'Q'; break;
	case QRT_S_SENDING: case QRT_S_RECEIVING:	status[4] = 'q'; break;
	case QRT_S_PATCHING:						status[4] = 'p'; break;
	default:									status[4] = '-';
	}

	switch (flags->uqrt_state) {
	case QRT_S_SENT:		status[5] = 'X'; break;
	case QRT_S_SENDING:		status[5] = 'x'; break;
	case QRT_S_PATCHING:	status[5] = 'p'; break;
	default:				status[5] = '-';
	}

	status[6] =
		flags->tx_compressed && flags->rx_compressed ? 'Z' :
		flags->tx_compressed ? 'T' :
		flags->rx_compressed ? 'R' : '-';

	if (flags->is_push_proxied)  status[7] = 'P';
	else if (flags->is_proxying) status[7] = 'p';
	else status[7] = '-';

	if (flags->in_tx_swift_control) status[8]     = 'S';
	else if (flags->in_tx_flow_control) status[8] = 'F';
	else if (flags->mqueue_above_lowat) status[8] = 'D';
	else if (!flags->mqueue_empty) status[8]      = 'd';
	else status[8]                                = '-';

	if (flags->hops_flow == 0)
		status[9] = 'f';
	else if (flags->hops_flow < GTA_NORMAL_TTL)
		status[9] = 'h';
	else
		status[9] = '-';

	status[10] = flags->tls ? 'E' : '-';

	status[sizeof(status) - 1] = '\0';
	return status;
}

/**
 * Disconnects all connected nodes which are considered hostile. This
 * is mainly for disconnecting nodes after hostiles.txt has been reloaded.
 */
void
node_kill_hostiles(void)
{
	GSList *sl, *to_remove = NULL;

	for (sl = sl_nodes; sl != NULL; sl = g_slist_next(sl)) {
		struct gnutella_node *n = sl->data;

		if (0 == (NODE_F_FORCE & n->flags) && hostiles_check(n->addr)) {
			to_remove = g_slist_prepend(to_remove, n);
		}
	}

	for (sl = to_remove; sl != NULL; sl = g_slist_next(sl)) {
		struct gnutella_node *n = sl->data;

        node_remove(n, no_reason);
	}
	g_slist_free(to_remove);
}

const gchar *
node_peermode_to_string(node_peer_t m)
{
	switch (m) {
	case NODE_P_LEAF:
		return _("Leaf");
	case NODE_P_ULTRA:
		return _("Ultrapeer");
	case NODE_P_NORMAL:
		return _("Legacy");
	case NODE_P_CRAWLER:
		return _("Crawler");
	case NODE_P_UDP:
		return _("UDP");
	case NODE_P_AUTO:
	case NODE_P_UNKNOWN:
		break;
	}

	return _("Unknown");
}

/* vi: set ts=4 sw=4 cindent: */
