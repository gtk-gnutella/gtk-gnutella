/*
 * $Id$
 *
 * Copyright (c) 2001-2003, Raphael Manfredi
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

#include <fcntl.h>
#include <sys/types.h>
#include <string.h>

#include "sockets.h"
#include "search.h"
#include "share.h"
#include "routing.h"
#include "hosts.h"
#include "nodes.h"
#include "header.h"
#include "gmsg.h"
#include "mq.h"
#include "sq.h"
#include "tx.h"
#include "tx_link.h"
#include "tx_deflate.h"
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
#include "uploads.h" /* for handle_push_request() */
#include "whitelist.h"
#include "gnet_stats.h"
#include "ioheader.h"
#include "ban.h"
#include "hcache.h"
#include "qrp.h"
#include "vmsg.h"
#include "token.h"
#include "hostiles.h"
#include "clock.h"

#include "settings.h"

RCSID("$Id$");

#define CONNECT_PONGS_COUNT		10		/* Amoung of pongs to send */
#define BYE_MAX_SIZE			4096	/* Maximum size for the Bye message */
#define NODE_SEND_BUFSIZE		4096	/* TCP send buffer size - 4K */
#define NODE_SEND_LEAF_BUFSIZE	256		/* TCP send buffer size for leaves */
#define NODE_RECV_BUFSIZE		114688	/* TCP receive buffer size - 112K */
#define MAX_GGEP_PAYLOAD		1024	/* In ping, pong, push */
#define MAX_MSG_SIZE			65536	/* Absolute maximum message length */
#define MAX_HOP_COUNT			255		/* Architecturally defined maximum */

#define NODE_ERRMSG_TIMEOUT		5	/* Time to leave erorr messages displayed */
#define SHUTDOWN_GRACE_DELAY	120	/* Grace period for shutdowning nodes */
#define BYE_GRACE_DELAY			30	/* Bye sent, give time to propagate */
#define MAX_WEIRD_MSG			5	/* Close connection after so much weirds */
#define MAX_TX_RX_RATIO			50	/* Max TX/RX ratio */
#define MIN_TX_FOR_RATIO		500	/* TX packets before enforcing ratio */
#define ALIVE_PERIOD			20	/* Seconds between each alive ping */
#define ALIVE_PERIOD_LEAF		120	/* Idem, for leaf nodes <-> ultrapeers */
#define ALIVE_MAX_PENDING		4	/* Max unanswered pings in a row */

#define NODE_MIN_UPTIME			3600	/* Minumum uptime to become an UP */
#define NODE_MIN_AVG_UPTIME		10800	/* Average uptime to become an UP */
#define NODE_AVG_LEAF_MEM		262144	/* Average memory used by leaf */
#define NODE_CASUAL_FD			10		/* # of fds we might use casually */
#define NODE_AUTO_SWITCH_MIN	1800	/* Don't switch too often UP <-> leaf */

#define QRELAYED_HALF_LIFE		5	/* Rotate `qrelayed' every 5 seconds */

static GSList *sl_nodes = NULL;

static GHashTable *unstable_ip = NULL;
static GSList *unstable_ips = NULL;

typedef struct node_bad_ip {
	guint32 ip;
	time_t time_added;
} node_bad_ip_t;

static GHashTable *unstable_servent = NULL;
static GSList *unstable_servents = NULL;

typedef struct node_bad_client {
	int	errors;
	char *vendor;
} node_bad_client_t;

static int node_error_threshold = 12;	/* This requires an average uptime of
										 * 2 hours for an ultrapeer */
static time_t node_error_cleanup_timer = 24 * 60 * 60;	/* 1 day */

static GSList *sl_proxies = NULL;	/* Our push proxies */
static idtable_t *node_handle_map = NULL;

#define node_find_by_handle(n) \
    (gnutella_node_t *) idtable_get_value(node_handle_map, n)

#define node_request_handle(n) \
    idtable_new_id(node_handle_map, n)

#define node_drop_handle(n) \
    idtable_free_id(node_handle_map, n);


static guint32 nodes_in_list = 0;
static guint32 shutdown_nodes = 0;
static guint32 node_id = 0;

static gboolean allow_gnet_connections = FALSE;

static const gchar gnutella_welcome[] = "GNUTELLA OK\n\n";
#define GNUTELLA_WELCOME_LENGTH (sizeof(gnutella_welcome) - 1)

GHookList node_added_hook_list;
/*
 * For use by node_added_hook_list hooks, since we can't add a parameter
 * at list invoke time.
 */
struct gnutella_node *node_added;

/*
 * Structure used for asynchronous reaction to peer mode changes.
 */
static struct {
	gboolean changed;
	node_peer_t new;
} peermode = { FALSE, NODE_P_UNKNOWN };

/*
 * Types of bad nodes for node_is_bad().
 */
enum node_bad {
	NODE_BAD_OK = 0,		/* Node is fine */
	NODE_BAD_IP,			/* Node has a bad (unstable) IP */
	NODE_BAD_VENDOR,		/* Node has a bad vendor string */
	NODE_BAD_NO_VENDOR,		/* Node has no vendor string */
};

static gint32 connected_node_cnt = 0;
static gint32 compressed_node_cnt = 0;
static gint32 compressed_leaf_cnt = 0;
static gint pending_byes = 0;			/* Used when shutdowning servent */
static gboolean in_shutdown = FALSE;

static query_hashvec_t *query_hashvec = NULL;

static void node_read_connecting(
	gpointer data, gint source, inputevt_cond_t cond);
static void node_disable_read(struct gnutella_node *n);
static void node_data_ind(rxdrv_t *rx, pmsg_t *mb);
static void node_bye_sent(struct gnutella_node *n);
static void call_node_process_handshake_ack(gpointer obj, header_t *header);
static void node_send_qrt(struct gnutella_node *n, gpointer query_table);
static void node_send_patch_step(struct gnutella_node *n);
static void node_bye_flags(guint32 mask, gint code, gchar *message);
static void node_bye_all_but_one(
	struct gnutella_node *nskip, gint code, gchar *message);
static void node_set_current_peermode(node_peer_t mode);
static gboolean node_ip_is_bad(guint32 ip);
static enum node_bad node_is_bad(struct gnutella_node *n);

extern gint guid_eq(gconstpointer a, gconstpointer b);

/***
 *** Callbacks
 ***/

static listeners_t node_added_listeners   = NULL;
static listeners_t node_removed_listeners = NULL;
static listeners_t node_info_changed_listeners = NULL;
static listeners_t node_flags_changed_listeners = NULL;

void node_add_node_added_listener(node_added_listener_t l)
{
    LISTENER_ADD(node_added, (gpointer) l);
}

void node_remove_node_added_listener(node_added_listener_t l)
{
    LISTENER_REMOVE(node_added, (gpointer) l);
}

void node_add_node_removed_listener(node_removed_listener_t l)
{
    LISTENER_ADD(node_removed, (gpointer) l);
}

void node_remove_node_removed_listener(node_removed_listener_t l)
{
    LISTENER_REMOVE(node_removed, (gpointer) l);
}

void node_add_node_info_changed_listener(node_info_changed_listener_t l)
{
    LISTENER_ADD(node_info_changed, (gpointer) l);
}

void node_remove_node_info_changed_listener(node_info_changed_listener_t l)
{
    LISTENER_REMOVE(node_info_changed, (gpointer) l);
}

void node_add_node_flags_changed_listener(node_flags_changed_listener_t l)
{
    LISTENER_ADD(node_flags_changed, (gpointer) l);
}

void node_remove_node_flags_changed_listener(node_flags_changed_listener_t l)
{
    LISTENER_REMOVE(node_flags_changed, (gpointer) l);
}

static void node_fire_node_added(
    gnutella_node_t *n, const gchar *type)
{
    n->last_update = time((time_t *)NULL);
    LISTENER_EMIT(node_added, n->node_handle, type);
}

static void node_fire_node_removed(gnutella_node_t *n)
{
    n->last_update = time((time_t *)NULL);
    LISTENER_EMIT(node_removed, n->node_handle);
}

static void node_fire_node_info_changed
    (gnutella_node_t *n)
{
    LISTENER_EMIT(node_info_changed, n->node_handle);
}

static void node_fire_node_flags_changed
    (gnutella_node_t *n)
{
    LISTENER_EMIT(node_flags_changed, n->node_handle);
}

/***
 *** Utilities
 ***/

/*
 * free_key
 *
 * Free atom string key from hash table.
 */
static void free_key(gpointer key, gpointer val, gpointer x)
{
	atom_str_free(key);
}

/*
 * free_key_true
 *
 * Free atom string key from hash table and return TRUE.
 */
static gboolean free_key_true(gpointer key, gpointer val, gpointer x)
{
	atom_str_free(key);
	return TRUE;
}

/*
 * string_table_clear
 *
 * Clear hash table whose keys are atoms and values ignored.
 */
static void string_table_clear(GHashTable *ht)
{
	g_assert(ht != NULL);

	g_hash_table_foreach_remove(ht, free_key_true, NULL);
}

/*
 * string_table_free
 *
 * Dispose of hash table whose keys are atoms and values ignored.
 */
static void string_table_free(GHashTable *ht)
{
	g_assert(ht != NULL);

	g_hash_table_foreach(ht, free_key, NULL);
	g_hash_table_destroy(ht);
}

/***
 *** Private functions
 ***/

/* 
 * message_dump:
 *
 * Dumps a gnutella message (debug) 
 */
static void message_dump(const struct gnutella_node *n)
{
	gint32 size, ip, idx, count, total;
	gint16 port, speed;

	printf("Node %s: ", node_ip(n));
	printf("Func 0x%.2x ", n->header.function);
	printf("TTL = %d ", n->header.ttl);
	printf("hops = %d ", n->header.hops);

	READ_GUINT32_LE(n->header.size, size);

	printf(" data = %u", size);

	if (n->header.function == GTA_MSG_SEARCH) {
		READ_GUINT16_LE(n->data, speed);
		printf(" Speed = %d Query = '%s'", speed, n->data + 2);
	} else if (n->header.function == GTA_MSG_INIT_RESPONSE) {
		READ_GUINT16_LE(n->data, port);
		READ_GUINT32_BE(n->data + 2, ip);
		READ_GUINT32_LE(n->data + 6, count);
		READ_GUINT32_LE(n->data + 10, total);

		printf(" Host = %s Port = %d Count = %d Total = %d",
			   ip_to_gchar(ip), port, count, total);
	} else if (n->header.function == GTA_MSG_PUSH_REQUEST) {
		READ_GUINT32_LE(n->data + 16, idx);
		READ_GUINT32_BE(n->data + 20, ip);
		READ_GUINT32_LE(n->data + 24, port);

		printf(" Index = %d Host = %s Port = %d ", idx, ip_to_gchar(ip),
			   port);
	}

	printf("\n");
}

/*
 * node_extract_host
 *
 * Extract IP/port information out of the Query Hit into `ip' and `port'.
 */
static void node_extract_host(
	const struct gnutella_node *n, guint32 *ip, guint16 *port)
{
	guint32 hip;
	guint16 hport;
	const struct gnutella_search_results *r =
		(const struct gnutella_search_results *) n->data;

	/* Read Query Hit info */

	READ_GUINT32_BE(r->host_ip, hip);		/* IP address */
	READ_GUINT16_LE(r->host_port, hport);	/* Port */

	*ip = hip;
	*port = hport;
}

/*
 * can_become_ultra
 *
 * Check the Ultrapeer requirements, returning TRUE if we can become an UP.
 */
static gboolean can_become_ultra(time_t now)
{
	gboolean avg_servent_uptime;
	gboolean avg_ip_uptime;
	gboolean node_uptime;
	gboolean not_firewalled;
	gboolean enough_fd;
	gboolean enough_mem;
	gboolean enough_bw;
	gchar *ok = "** OK **";
	gchar *no = "-- NO --";

	/* Uptime requirements */
	avg_servent_uptime = average_servent_uptime >= NODE_MIN_AVG_UPTIME;
	avg_ip_uptime = average_ip_uptime >= NODE_MIN_AVG_UPTIME;
	node_uptime = now - start_stamp > NODE_MIN_UPTIME;

	/* Connectivity requirements */
	not_firewalled = !is_firewalled;

	/* System requirements */
	enough_fd = (max_leaves + max_connections + max_uploads + max_downloads
			+ max_banned_fd + NODE_CASUAL_FD) < sys_nofile;
	enough_mem = (max_leaves * NODE_AVG_LEAF_MEM) < 1024 / 2 * sys_physmem;

	/* Bandwidth requirements */
	enough_bw = bsched_enough_up_bandwidth();

#define OK(b)	((b) ? ok : no)

	if (dbg > 3) {
		printf("Checking Ultrapeer criteria:\n");
		printf(" * Sufficient average uptime   : %s\n", OK(avg_servent_uptime));
		printf(" * Sufficient IP address uptime: %s\n", OK(avg_ip_uptime));
		printf(" * Sufficient node uptime      : %s\n", OK(node_uptime));
		printf(" * Node not firewalled         : %s\n", OK(not_firewalled));
		printf(" * Enough file descriptors     : %s\n", OK(enough_fd));
		printf(" * Enough physical memory      : %s\n", OK(enough_mem));
		printf(" * Enough available bandwidth  : %s\n", OK(enough_bw));
	}

#undef OK

	return avg_servent_uptime && avg_ip_uptime && node_uptime &&
		not_firewalled && enough_fd && enough_mem && enough_bw;
}

/*
 * node_slow_timer
 *
 * Low frequency node timer.
 */
void node_slow_timer(time_t now)
{
	static time_t last_switch = 0;
	GSList *sl;
	GSList *to_remove = NULL;
	
	for (sl = unstable_ips; sl != NULL; sl = g_slist_next(sl)) {
		node_bad_ip_t *bad_ip = (node_bad_ip_t *) sl->data;
		
		if (bad_ip->time_added + node_error_cleanup_timer < now) {
			to_remove = g_slist_prepend(to_remove, bad_ip);
		} else
			break; /* Should be sorted by time. */
	}

	for (sl = to_remove; sl != NULL; sl = g_slist_next(sl)) {
		node_bad_ip_t *bad_ip = (node_bad_ip_t *) sl->data;		
	
		g_hash_table_remove(unstable_ip, GUINT_TO_POINTER(bad_ip->ip));
		unstable_ips = g_slist_remove(unstable_ips, bad_ip);
		
		wfree(bad_ip, sizeof(*bad_ip));
	}
	g_slist_free(to_remove);
	to_remove = NULL;
	
	/*
	 * If we're in "auto" mode and we're still running as a leaf node,
	 * evaluate our ability to become an ultra node.
	 */

	if (
		configured_peermode == NODE_P_AUTO &&
		current_peermode == NODE_P_LEAF &&
		now - last_switch > NODE_AUTO_SWITCH_MIN &&
		can_become_ultra(now)
	) {
		g_warning("being promoted to Ultrapeer status");
		gnet_prop_set_guint32_val(PROP_CURRENT_PEERMODE, NODE_P_ULTRA);
		last_switch = now;
	}

	/*
	 * If we're in "auto" mode and we've been promoted to an ultra node,
	 * evaluate how good we are and whether we would not be better off
	 * running as a leaf node.
	 */

	if (
		configured_peermode == NODE_P_AUTO &&
		current_peermode == NODE_P_ULTRA &&
		now - last_switch > NODE_AUTO_SWITCH_MIN &&
		!can_become_ultra(now)
	) {
		g_warning("being demoted from Ultrapeer status");
		gnet_prop_set_guint32_val(PROP_CURRENT_PEERMODE, NODE_P_LEAF);
		last_switch = now;
	}
}

static inline void node_error_cleanup(void)
{
	GSList *sl;
	GSList *to_remove = NULL;

	for (sl = unstable_servents; sl != NULL; sl = g_slist_next(sl)) {
		node_bad_client_t *bad_node = (node_bad_client_t *) sl->data;

		g_assert(bad_node != NULL);

		if (--bad_node->errors == 0)
			to_remove = g_slist_prepend(to_remove, bad_node);
	}
		
	for (sl = to_remove; sl != NULL; sl = g_slist_next(sl)) {
		node_bad_client_t *bad_node = (node_bad_client_t *) sl->data;
				
		g_assert(bad_node != NULL);
		g_assert(bad_node->vendor != NULL);
			
		if (dbg > 1)
			g_warning("[nodes up] Unbanning client: %s", bad_node->vendor);
			
		g_hash_table_remove(unstable_servent, bad_node->vendor);
		unstable_servents = g_slist_remove(unstable_servents, bad_node);
			
		atom_str_free(bad_node->vendor);
		wfree(bad_node, sizeof(*bad_node));
	}
		
	g_slist_free(to_remove);
}

/*
 * node_timer
 *
 * Periodic node heartbeat timer.
 */
void node_timer(time_t now)
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
		struct gnutella_node *n = (struct gnutella_node *) sl->data;

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
				if (now - n->last_update > NODE_ERRMSG_TIMEOUT) {
					node_real_remove(n);
					continue;
				}
			} else if (NODE_IS_CONNECTING(n) || n->received == 0) {
				if (now - n->last_update > node_connecting_timeout)
					node_remove(n, "Timeout");
			} else if (n->status == GTA_NODE_SHUTDOWN) {
				if (now - n->shutdown_date > n->shutdown_delay) {
					gchar *reason = g_strdup(n->error_str);
					node_remove(n, "Shutdown (%s)", reason);
					g_free(reason);
				}
			} else if (
				!NODE_IS_LEAF(n) &&
				now - n->last_update > node_connected_timeout
			) {
				node_mark_bad(n);
				node_bye_if_writable(n, 405, "Activity timeout");
			} else if (
				!NODE_IS_LEAF(n) &&
				NODE_IN_TX_FLOW_CONTROL(n) &&
				now - n->tx_flowc_date > node_tx_flowc_timeout
			)
				node_bye(n, 405, "Flow-controlled for too long (%d sec%s)",
					node_tx_flowc_timeout,
					node_tx_flowc_timeout == 1 ? "" : "s");
		}

		if (n->searchq != NULL)
			sq_process(n->searchq, now);

		/*
		 * Sanity checks for connected nodes.
		 */

		if (n->status == GTA_NODE_CONNECTED) {
			if (n->n_weird >= MAX_WEIRD_MSG) {
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
			 * Only send "alive" pings if we have not received anything
			 * for a while and if some time has elapsed since our last
			 * attempt to send such a ping.
			 *		--RAM, 01/11/2003
			 */

			if (NODE_IS_ESTABLISHED(n) && now - n->last_rx > n->alive_period) {
				guint32 last;
				guint32 avg;
				guint32 period;

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
				period = MAX(n->alive_period, last);

				if (
					now - n->last_alive_ping > period &&
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

				if (now - rxfc->start_half_period > NODE_RX_FC_HALF_PERIOD) {
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
						rxfc->fc_accumulator += now - rxfc->fc_start;
						rxfc->fc_start = now;
					}

					total = rxfc->fc_accumulator + rxfc->fc_last_half;

					/* New period begins */
					rxfc->fc_last_half = rxfc->fc_accumulator;
					rxfc->fc_accumulator = 0;
					rxfc->start_half_period = now;

					fc_ratio = (gdouble) total / (2.0 * NODE_RX_FC_HALF_PERIOD);
					fc_ratio *= 100.0;

					if ((gint) fc_ratio > max_ratio) {
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
			now - n->qrelayed_created >= QRELAYED_HALF_LIFE
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
}

/*
 * node_init
 *
 * Network init
 */
void node_init(void)
{
	rxbuf_init();

	g_assert(sizeof(struct gnutella_header) == 23);

    node_handle_map = idtable_new(32, 32);

	g_hook_list_init(&node_added_hook_list, sizeof(GHook));
	node_added_hook_list.seq_id = 1;
	node_added = NULL;

	query_hashvec = qhvec_alloc(128);		/* Max: 128 unique words / URNs! */
	
	unstable_servent = g_hash_table_new(NULL, NULL);
	unstable_ip = g_hash_table_new(NULL, NULL);
}

/*
 * Nodes
 */

gint32 connected_nodes(void)
{
	return connected_node_cnt;
}

gint32 node_count(void)
{
	return nodes_in_list - shutdown_nodes - node_leaf_count;
}

/*
 * node_keep_missing
 *
 * Amount of node connections we would like to keep.
 * Returns 0 if none.
 */
gint node_keep_missing(void)
{
	gint missing;

	switch (current_peermode) {
	case NODE_P_LEAF:
		missing = max_ultrapeers - node_ultra_count;
		return MAX(0, missing);
	case NODE_P_NORMAL:
	case NODE_P_ULTRA:
		missing = up_connections - (node_ultra_count + node_normal_count);
		return MAX(0, missing);
	default:
		g_assert_not_reached();
	}

	return 0;
}

/*
 * node_missing
 *
 * Amount of node connections we would like to have.
 * Returns 0 if none.
 */
gint node_missing(void)
{
	gint missing;

	switch (current_peermode) {
	case NODE_P_LEAF:
		missing = max_ultrapeers - node_ultra_count;
		return MAX(0, missing);
	case NODE_P_NORMAL:
	case NODE_P_ULTRA:
		missing = max_connections - (node_ultra_count + node_normal_count);
		return MAX(0, missing);
	default:
		g_assert_not_reached();
	}

	return 0;
}

/*
 * node_outdegree
 *
 * Returns this node's outdegree, i.e. the maximum amount of peer connections
 * that we can support.
 */
gint node_outdegree(void)
{
	switch (current_peermode) {
	case NODE_P_LEAF:
		return max_ultrapeers;
	case NODE_P_NORMAL:
	case NODE_P_ULTRA:
		return max_connections;
	default:
		g_assert_not_reached();
	}

	return 0;
}

/*
 * get_protocol_version
 *
 * Parse the first handshake line to determine the protocol version.
 * The major and minor are returned in `major' and `minor' respectively.
 */
static void get_protocol_version(gchar *handshake, gint *major, gint *minor)
{
	if (sscanf(&handshake[GNUTELLA_HELLO_LENGTH], "%d.%d", major, minor))
		return;

	if (dbg)
		g_warning("Unable to parse version number in HELLO, assuming 0.4");
	if (dbg > 2) {
		guint len = strlen(handshake);
		dump_hex(stderr, "First HELLO Line", handshake, MIN(len, 80));
	}

	*major = 0;
	*minor = 4;
}

/*
 * node_type_count_dec
 *
 * Decrement the proper node count property, depending on the peermode.
 */
static void node_type_count_dec(struct gnutella_node *n)
{
	switch (n->peermode) {
	case NODE_P_LEAF:
		g_assert(node_leaf_count > 0);
		gnet_prop_set_guint32_val(PROP_NODE_LEAF_COUNT,
			node_leaf_count - 1);
		break;
	case NODE_P_NORMAL:
		g_assert(node_normal_count > 0);
		gnet_prop_set_guint32_val(PROP_NODE_NORMAL_COUNT,
			node_normal_count - 1);
		break;
	case NODE_P_ULTRA:
		g_assert(node_ultra_count > 0);
		gnet_prop_set_guint32_val(PROP_NODE_ULTRA_COUNT,
			node_ultra_count - 1);
		break;
	default:
		break;
	}
}

/*
 * node_real_remove
 *
 * Physically dispose of node.
 */
void node_real_remove(gnutella_node_t *node)
{
	g_return_if_fail(node);

    /*
     * Tell the frontend that the node was removed.
     */
    node_fire_node_removed(node);

	sl_nodes = g_slist_remove(sl_nodes, node);
    node_drop_handle(node->node_handle);

	/*
	 * Now that the node was removed from the list of known nodes, we
	 * can call host_save_valid() iff the node was marked NODE_F_VALID,
	 * meaning we identified it as a Gnutella server, even though we
	 * might not have been granted a full connection.
	 *		--RAM, 13/01/2002
	 */

	if (!NODE_IS_LEAF(node) && node->gnet_ip && (node->flags & NODE_F_VALID))
		hcache_save_valid(
			(node->attrs & NODE_A_ULTRA) ? HCACHE_ULTRA : HCACHE_ANY,
			node->gnet_ip, node->gnet_port);

	/*
	 * The io_opaque structure is not freed by node_remove(), so that code
	 * can still peruse the headers after node_remove() has been called.
	 */

	if (node->io_opaque)				/* I/O data */
		io_free(node->io_opaque);

	/*
	 * The freeing of the vendor string is delayed, because the GUI update
	 * code reads it.  When this routine is called, the GUI line has been
	 * removed, so it's safe to do it now.
	 */

	if (node->vendor)
		atom_str_free(node->vendor);

	/*
	 * The RX stack needs to be dismantled asynchronously, to not be freed
	 * whilst on the "data reception" interrupt path.
	 */

	if (node->rx)
		rx_free(node->rx);

	wfree(node, sizeof(*node));
}

/*
 * node_remove_v
 *
 * The vectorized (message-wise) version of node_remove().
 */
static void node_remove_v(
	struct gnutella_node *n, const gchar *reason, va_list ap)
{
	g_assert(n->status != GTA_NODE_REMOVING);

	if (reason) {
		gm_vsnprintf(n->error_str, sizeof(n->error_str), reason, ap);
		n->error_str[sizeof(n->error_str) - 1] = '\0';	/* May be truncated */
		n->remove_msg = n->error_str;
	} else if (n->status != GTA_NODE_SHUTDOWN)	/* Preserve shutdown error */
		n->remove_msg = NULL;

	if (dbg > 3)
		printf("Node %s <%s> removed: %s\n", node_ip(n), node_vendor(n),
			n->remove_msg ? n->remove_msg : "<no reason>");

	if (dbg > 4) {
		printf("NODE [%d.%d] %s <%s> TX=%d (drop=%d) RX=%d (drop=%d) "
			"Dup=%d Bad=%d W=%d\n",
			n->proto_major, n->proto_minor, node_ip(n), node_vendor(n),
			n->sent, n->tx_dropped, n->received, n->rx_dropped,
			n->n_dups, n->n_bad, n->n_weird);
		printf("NODE \"%s%s\" %s PING (drop=%d acpt=%d spec=%d sent=%d) "
			"PONG (rcvd=%d sent=%d)\n",
			(n->attrs & NODE_A_PONG_CACHING) ? "new" : "old",
			(n->attrs & NODE_A_PONG_ALIEN) ? "-alien" : "",
			node_ip(n),
			n->n_ping_throttle, n->n_ping_accepted, n->n_ping_special,
			n->n_ping_sent, n->n_pong_received, n->n_pong_sent);
	}

	if (n->routing_data)
		routing_node_remove(n);

	if (n->qrt_update) {
		qrt_update_free(n->qrt_update);
		n->qrt_update = NULL;
	}

	if (n->qrt_receive) {
		qrt_receive_free(n->qrt_receive);
		n->qrt_receive = NULL;
	}

	if (n->query_table) {
		qrt_unref(n->query_table);
		n->query_table = NULL;
	}

	if (n->qrt_info) {
		wfree(n->qrt_info, sizeof(*n->qrt_info));
		n->qrt_info = NULL;
	}

	if (n->rxfc)
		wfree(n->rxfc, sizeof(*n->rxfc));

	if (n->status == GTA_NODE_CONNECTED) {		/* Already did if shutdown */
		connected_node_cnt--;
		g_assert(connected_node_cnt >= 0);
        if (n->attrs & NODE_A_RX_INFLATE) {
			if (n->flags & NODE_F_LEAF)
				compressed_leaf_cnt--;
            compressed_node_cnt--;
            g_assert(compressed_node_cnt >= 0);
			g_assert(compressed_leaf_cnt >= 0);
        }
		node_type_count_dec(n);
	}

	if (n->status == GTA_NODE_SHUTDOWN)
		shutdown_nodes--;

	if (n->socket) {
		g_assert(n->socket->resource.node == n);
		socket_free(n->socket);
		n->socket = NULL;
	}

	/* n->io_opaque will be freed by node_real_remove() */
	/* n->vendor will be freed by node_real_remove() */

	if (n->allocated) {
		g_free(n->data);
		n->allocated = 0;
	}
	if (n->outq) {
		mq_free(n->outq);
		n->outq = NULL;
	}
	if (n->searchq) {
		sq_free(n->searchq);
		n->searchq = NULL;
	}
	if (n->rx)					/* RX stack freed by node_real_remove() */
		node_disable_read(n);
	if (n->gnet_guid) {
		atom_guid_free(n->gnet_guid);
		n->gnet_guid = NULL;
	}
	if (n->alive_pings) {
		alive_free(n->alive_pings);
		n->alive_pings = NULL;
	}
	if (n->guid) {
		route_proxy_remove(n->guid);
		atom_guid_free(n->guid);
		n->guid = NULL;
	}

	n->status = GTA_NODE_REMOVING;
	n->flags &= ~(NODE_F_WRITABLE|NODE_F_READABLE|NODE_F_BYE_SENT);
	n->last_update = time((time_t *) NULL);

	nodes_in_list--;
	if (n->flags & NODE_F_EOF_WAIT)
		pending_byes--;

	if (n->proxy_ip != 0)
		sl_proxies = g_slist_remove(sl_proxies, n);

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

    node_fire_node_info_changed(n);
    node_fire_node_flags_changed(n);
}

/*
 * node_recursive_shutdown_v
 *
 * Called when node_bye() or node_shutdown() is called during the time we're
 * in shutdown mode, processing the messages we might still read from the
 * socket.
 */
static void node_recursive_shutdown_v(
	struct gnutella_node *n, gchar *where, const gchar *reason, va_list ap)
{
	gchar *fmt;

	g_assert(n->status == GTA_NODE_SHUTDOWN);
	g_assert(n->error_str);
	g_assert(reason);

	fmt = g_strdup_printf("%s (%s) [within %s]", where, reason, n->error_str);
	node_remove_v(n, fmt, ap);
	g_free(fmt);
}

/*
 * node_remove_by_handle:
 *
 * Removes or shut's down the given node.
 */
void node_remove_by_handle(gnet_node_t n)
{
    gnutella_node_t *node;

	node = node_find_by_handle(n);

    g_assert(node != NULL);

    if (NODE_IS_WRITABLE(node)) {
        node_bye(node, 201, "User manual removal");
    } else {
        node_remove(node, NULL);
        node_real_remove(node);
    }
}

/*
 * ip_is_bad
 *
 * True when a certain IP has proven to be unstable
 */
static gboolean node_ip_is_bad(guint32 ip) {
	node_bad_ip_t *bad_ip = NULL;
	
	g_assert(ip != 0);
	
	if (!node_monitor_unstable_ip)
		/* User disabled monitoring of unstable IPs. */
		return FALSE;
	
	bad_ip = g_hash_table_lookup(unstable_ip, GUINT_TO_POINTER(ip));
	
	if (bad_ip != NULL) {
		if (dbg)
			g_warning("[nodes up] Unstable ip %s", ip_to_gchar(ip));
		return TRUE;
	}
		
	return FALSE;
}

/*
 * node_is_bad
 *
 * Check whether node has been identified as having a bad IP or vendor string.
 * Returns NODE_BAD_OK if node is OK, the reason why the node is bad otherwise.
 */
static enum node_bad node_is_bad(struct gnutella_node *n)
{
	node_bad_client_t *bad_client = NULL;
	node_bad_ip_t *bad_ip = NULL;
	
	g_assert(n != NULL);
	
	if (!node_monitor_unstable_ip)
		/* User disabled monitoring of unstable IPs. */
		return FALSE;

	if (n->vendor == NULL) {
		if (dbg)
			g_warning("[nodes up] Got no vendor name!");
		return NODE_BAD_NO_VENDOR;
	}
	
	g_assert(n->vendor != NULL);
	g_assert(n->ip != 0);
	
	bad_ip = g_hash_table_lookup(unstable_ip, GUINT_TO_POINTER(n->ip));
	if (bad_ip != NULL) {
		if (dbg)
			g_warning("[nodes up] Unstable ip %s (%s)", 
				ip_to_gchar(n->ip),
				n->vendor);
		return NODE_BAD_IP;
	} else {
		if (!node_monitor_unstable_servents)
			/* User doesn't want us to monitor unstable servents */
			return FALSE;
		
		bad_client = g_hash_table_lookup(unstable_servent, n->vendor);
	
		if (bad_client == NULL)
			return NODE_BAD_OK;
	
		if (bad_client->errors > node_error_threshold) {
			if (dbg)
				g_warning("[nodes up] Banned client: %s", n->vendor);
			return NODE_BAD_VENDOR;
		}
	}
	return NODE_BAD_OK;
}

/*
 * node_mark_bad_ip
 *
 * Record that the node's IP is bad and that connection should no longer
 * be attempted towards that IP.
 */
static void node_mark_bad_ip(struct gnutella_node *n)
{
	struct node_bad_ip *bad_ip = NULL;

	if (in_shutdown || !node_monitor_unstable_ip)
		return;

	g_assert(n != NULL);
	g_assert(n->ip != 0);

	bad_ip = g_hash_table_lookup(unstable_ip, GUINT_TO_POINTER(n->ip));
	if (bad_ip == NULL) {
		bad_ip = walloc0(sizeof(*bad_ip));
		bad_ip->ip = n->ip;
		bad_ip->time_added = time(NULL);
		
		g_hash_table_insert(unstable_ip, GUINT_TO_POINTER(n->ip), bad_ip);
		unstable_ips = g_slist_prepend(unstable_ips, bad_ip);

		if (dbg)
			g_warning("[nodes up] Marked ip %s (%s) as a bad host",
				ip_to_gchar(n->ip), node_vendor(n));
	}	
}

/*
 * node_mark_bad
 *
 * Gives a specific vendor a bad mark. If a vendor + version gets to many
 * marks, we won't try to connect to it anymore.
 */
void node_mark_bad(struct gnutella_node *n)
{
	struct node_bad_client *bad_client = NULL;
	time_t now;
	
	if (in_shutdown)
		return;
	
	if (!node_monitor_unstable_ip)
		/*
		 * If the user doesn't want us to protect against unstable IPs, then we
		 * can stop right now. Protecting against unstable servent name will 
		 * also be ignored, to prevent marking a servent as unstable while we
		 * are actually connecting to the same IP over and over again
		 */
		return;
	
	g_assert(n != NULL);
	g_assert(n->ip != 0);
	
	if (!(n->attrs & NODE_A_ULTRA))
		/*
		 * Only mark Ultrapeers as bad nodes. Leaves aren't expected to have
		 * high uptimes
		 */
		return;
	

	if (n->connect_date == 0)
		/*
		 * Do not mark nodes as bad with which we did not connect at all, we 
		 * don't know it's behaviour in this case.
		 */
		return;

	now = time((time_t *) NULL);

	/* Don't mark a node as bad with whom we could stay a long time */
	if (
		now - n->connect_date >
			node_error_cleanup_timer / node_error_threshold
	) {
		if (dbg > 1)
			printf("[nodes up] "
				  "%s not marking as bad. Connected for: %d (min: %d)\r\n",
				ip_to_gchar(n->ip),
				(gint) (now - n->connect_date), 
				(gint) (node_error_cleanup_timer / node_error_threshold));
		return;
	}
	
	node_mark_bad_ip(n);

	if (!node_monitor_unstable_servents)
		/* The user doesn't want us to monitor unstable servents. */
		return;
	
	if (n->vendor == NULL)
		return;
	
	g_assert(n->vendor != NULL);
	
	bad_client = g_hash_table_lookup(unstable_servent, n->vendor);
	if (bad_client == NULL) {
		bad_client = walloc0(sizeof(*bad_client));
		bad_client->errors = 0;
		bad_client->vendor = atom_str_get(n->vendor);
		g_hash_table_insert(unstable_servent, bad_client->vendor, bad_client);
		unstable_servents = g_slist_prepend(unstable_servents, bad_client);
	}

	g_assert(bad_client != NULL);

	bad_client->errors++;

	if (dbg)
		g_warning("[nodes up] Increased error counter (%d) for client: %s",
			bad_client->errors,
			n->vendor);
}

/*
 * node_avoid_monopoly
 *
 * Make sure that the vendor of the connecting node does not already use
 * more than "unique_nodes" percent of the slots of its kind.
 *
 * Returns TRUE if accepting the node would make the uses more slot that
 */
static gboolean node_avoid_monopoly(struct gnutella_node *n)
{
	guint up_cnt = 0;
	guint leaf_cnt = 0;
	guint normal_cnt = 0;
	GSList *sl;

	if (n->vendor == NULL || (n->flags & NODE_F_CRAWLER))
		return FALSE;

	for (sl = sl_nodes; sl; sl = sl->next) {
		struct gnutella_node *node = (struct gnutella_node *) sl->data;
		
		if (node->status != GTA_NODE_CONNECTED || node->vendor == NULL)
			continue;

		/*
		 * Node vendor strings are compared up to the specified delimitor,
		 * i.e. we don't want to take the version number into account.
		 *
		 * The vendor name and the version are normally separated with a "/"
		 * but some people wrongly use " " as the separator.
		 */

		if (0 != strcmp_delimit(n->vendor, node->vendor, "/ "))
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
			
	switch (current_peermode) {
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
		break;
	case NODE_P_LEAF:
		if (max_ultrapeers > 1 && up_cnt * 100 > max_ultrapeers * unique_nodes)
			return TRUE;	/* Dissallow */
		break;
	case NODE_P_NORMAL:
		if (
			max_connections > 1 &&
			normal_cnt * 100 > max_connections * unique_nodes
		)
			return TRUE;
		break;
	default:
		break;
	}
	
	return FALSE;
}

/*
 * node_reserve_slot
 *
 * When we only have "reserve_gtkg_nodes" percent slots left, make sure the
 * connecting node is a GTKG node or refuse the connection.
 *
 * Returns TRUE if we should reserve the slot for GTKG, i.e. refuse `n'.
 */
static gboolean node_reserve_slot(struct gnutella_node *n)
{
	guint up_cnt = 0;		/* GTKG UPs */
	guint leaf_cnt = 0;		/* GTKG leafs */
	guint normal_cnt = 0;	/* GTKG normal nodes */
	GSList *sl;
	gchar *gtkg_vendor = "gtk-gnutella";
	
	if (n->vendor == NULL || (n->flags & NODE_F_CRAWLER))
		return FALSE;
	
	if (0 == strcmp_delimit(gtkg_vendor, n->vendor, "/ "))
		return FALSE;

	for (sl = sl_nodes; sl; sl = sl->next) {
		struct gnutella_node *node = (struct gnutella_node *) sl->data;

		if (node->status != GTA_NODE_CONNECTED || node->vendor == NULL)
			continue;

		if (0 != strcmp_delimit(node->vendor, gtkg_vendor, "/ "))
			continue;

		if ((node->attrs & NODE_A_ULTRA) || (node->attrs & NODE_F_ULTRA))
			up_cnt++;
		else if (node->flags & NODE_F_LEAF)
			leaf_cnt++;
		else
			normal_cnt++;
	}	

	/*
	 * For a given max polulation `max', already filled by `x' nodes out
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
	
	switch (current_peermode) {
	case NODE_P_ULTRA:
		if ((n->attrs & NODE_A_ULTRA) || (n->flags & NODE_F_ULTRA)) {
			gint max = max_connections - normal_connections;
			gint gtkg_min = reserve_gtkg_nodes * max / 100;
			if (node_ultra_count >= max + up_cnt - gtkg_min)
				return TRUE;
		} else if (n->flags & NODE_F_LEAF) {
			gint gtkg_min = reserve_gtkg_nodes * max_leaves / 100;
			if (node_leaf_count >= max_leaves + leaf_cnt - gtkg_min)
				return TRUE;
		} else {
			gint gtkg_min = reserve_gtkg_nodes * normal_connections / 100;
			if (node_normal_count >= normal_connections + normal_cnt - gtkg_min)
				return TRUE;
		}
		break;
	case NODE_P_LEAF:
		if (max_ultrapeers > 0 ) {
			gint gtkg_min = reserve_gtkg_nodes * max_ultrapeers / 100;
			if (node_ultra_count >= max_ultrapeers + up_cnt - gtkg_min)
				return TRUE;
		}
		break;
	case NODE_P_NORMAL:
		if (max_connections > 0) {
			gint gtkg_min = reserve_gtkg_nodes * max_connections / 100;
			if (node_normal_count >= max_connections + normal_cnt - gtkg_min)
				return TRUE;
		}
		break;
	default:
		break;
	}
	
	return FALSE;
}

/*
 * node_remove
 *
 * Terminate connection with remote node, but keep structure around for a
 * while, for displaying purposes, and also to prevent the node from being
 * physically reclaimed within this stack frame.
 *
 * It will be reclaimed on the "idle" stack frame, via node_real_remove().
 */
void node_remove(struct gnutella_node *n, const gchar *reason, ...)
{
	va_list args;

	g_assert(n);

	if (n->status == GTA_NODE_REMOVING)
		return;
	
	va_start(args, reason);
	node_remove_v(n, reason, args);
	va_end(args);
}

/*
 * node_eof
 *
 * Got an EOF condition, or a read error, whilst reading Gnet data from node.
 *
 * Terminate connection with remote node, but keep structure around for a
 * while, for displaying purposes.
 */
void node_eof(struct gnutella_node *n, const gchar *reason, ...)
{
	va_list args;

	g_assert(n);

	/*
	 * If the Gnutella connection was established, we should have got a BYE
	 * to cleanly shutdown.
	 */

	if (n->flags & NODE_F_ESTABLISHED)
		node_mark_bad(n);

	va_start(args, reason);

	if (n->flags & NODE_F_BYE_SENT) {
		g_assert(n->status == GTA_NODE_SHUTDOWN);
		if (dbg > 4) {
			va_list dbargs;

			printf("EOF-style error during BYE to %s:\n (BYE) ", node_ip(n));

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

	if (n->flags & NODE_F_CLOSING)			/* Bye sent or explicit shutdown */
		node_remove_v(n, NULL, args);		/* Reuse existing reason */
	else
		node_remove_v(n, reason, args);

	va_end(args);
}

/*
 * node_shutdown_mode
 *
 * Enter shutdown mode: prevent further writes, drop read broadcasted messages,
 * and make sure we flush the buffers at the fastest possible speed.
 */
static void node_shutdown_mode(struct gnutella_node *n, guint32 delay)
{

	/*
	 * If node is already in shutdown node, simply update the delay.
	 */

	n->shutdown_delay = delay;

	if (n->status == GTA_NODE_SHUTDOWN)
		return;

	if (n->status == GTA_NODE_CONNECTED) {	/* Free Gnet slot */
		connected_node_cnt--;
		g_assert(connected_node_cnt >= 0);
        if (n->attrs & NODE_A_RX_INFLATE) {
			if (n->flags & NODE_F_LEAF)
				compressed_leaf_cnt--;
            compressed_node_cnt--;
            g_assert(compressed_node_cnt >= 0);
			g_assert(compressed_leaf_cnt >= 0);
        }
		node_type_count_dec(n);
 	}

	n->status = GTA_NODE_SHUTDOWN;
	n->flags &= ~(NODE_F_WRITABLE|NODE_F_READABLE);
	n->shutdown_date = time((time_t) NULL);
	mq_shutdown(n->outq);
	node_flushq(n);							/* Fast queue flushing */

	shutdown_nodes++;

    node_fire_node_info_changed(n);
    node_fire_node_flags_changed(n);
}

/*
 * node_shutdown
 *
 * Stop sending data to node, but keep reading buffered data from it, until
 * we hit a Bye packet or EOF.  In that mode, we don't relay Queries we may
 * read, but replies and pushes are still routed back to other nodes.
 *
 * This is mostly called when a fatal write error happens, but we want to
 * see whether the node did not send us a Bye we haven't read yet.
 */
void node_shutdown(struct gnutella_node *n, const gchar *reason, ...)
{
	va_list args;

	g_assert(n);

	va_start(args, reason);

	if (n->status == GTA_NODE_SHUTDOWN) {
		node_recursive_shutdown_v(n, "Shutdown", reason, args);
		goto end;
	}

	n->flags |= NODE_F_CLOSING;

	if (reason) {
		gm_vsnprintf(n->error_str, sizeof(n->error_str), reason, args);
		n->error_str[sizeof(n->error_str) - 1] = '\0';	/* May be truncated */
		n->remove_msg = n->error_str;
	} else {
		n->remove_msg = "Unknown reason";
		n->error_str[0] = '\0';
	}

	node_shutdown_mode(n, SHUTDOWN_GRACE_DELAY);

end:
	va_end(args);
}

/*
 * node_bye_v
 *
 * The vectorized version of node_bye().
 */
static void node_bye_v(
	struct gnutella_node *n, gint code, const gchar *reason, va_list ap)
{
	struct gnutella_header head;
	gchar reason_fmt[1024];
	struct gnutella_bye *payload = (struct gnutella_bye *) reason_fmt;
	gint len;
	gint sendbuf_len;
	gchar *reason_base = &reason_fmt[2];	/* Leading 2 bytes for code */

	g_assert(n);

	if (n->status == GTA_NODE_SHUTDOWN) {
		node_recursive_shutdown_v(n, "Bye", reason, ap);
		return;
	}

	n->flags |= NODE_F_CLOSING;

	if (reason) {
		gm_vsnprintf(n->error_str, sizeof(n->error_str), reason, ap);
		n->error_str[sizeof(n->error_str) - 1] = '\0';	/* May be truncated */
		n->remove_msg = n->error_str;
	} else {
		n->remove_msg = NULL;
		n->error_str[0] = '\0';
	}

	/*
	 * Discard all the queued entries, we're not going to send them.
	 * The only message that may remain is the oldest partially sent.
	 */

	sq_clear(n->searchq);
	mq_clear(n->outq);

	/*
	 * Build the bye message.
	 */

	len = gm_snprintf(reason_base, sizeof(reason_fmt) - 3,
		"%s", n->error_str);

	/* XXX Add X-Try and X-Try-Ultrapeers */

	if (code != 200) {
		len += gm_snprintf(reason_base + len, sizeof(reason_fmt) - len - 3,
			"\r\n"
			"Server: %s\r\n"
			"\r\n",
			version_string);
	}

	g_assert(len <= sizeof(reason_fmt) - 3);

	reason_base[len] = '\0';
	len += 2 + 1;		/* 2 for the leading code, 1 for the trailing NUL */

	WRITE_GUINT16_LE(code, payload->code);

	message_set_muid(&head, GTA_MSG_BYE);
	head.function = GTA_MSG_BYE;
	head.ttl = 1;
	head.hops = 0;
	WRITE_GUINT32_LE(len, head.size);

	/*
	 * Send the bye message, enlarging the TCP input buffer to make sure
	 * can atomically send the message plus the remaining queued data.
	 */

	sendbuf_len = NODE_SEND_BUFSIZE + mq_size(n->outq) +
		len + sizeof(head) + 1024;		/* Slightly larger, for flow-control */

	sock_send_buf(n->socket, sendbuf_len, FALSE);
	gmsg_split_sendto_one(n, &head, payload, len + sizeof(head));

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
		if (dbg > 4)
			printf("successfully sent BYE \"%s\" to %s\n",
				n->error_str, node_ip(n));

			sock_tx_shutdown(n->socket);
			node_shutdown_mode(n, BYE_GRACE_DELAY);
	} else {
		if (dbg > 4)
			printf("delayed sending of BYE \"%s\" to %s\n",
				n->error_str, node_ip(n));

		n->flags |= NODE_F_BYE_SENT;

		node_shutdown_mode(n, SHUTDOWN_GRACE_DELAY);
	}
}

/*
 * node_bye
 *
 * Terminate connection by sending a bye message to the remote node.  Upon
 * reception of that message, the connection will be closed by the remote
 * party.
 *
 * This is otherwise equivalent to the node_shutdown() call.
 */

void node_bye(gnutella_node_t *n, gint code, const gchar * reason, ...)
{
	va_list args;

	va_start(args, reason);
	node_bye_v(n, code, reason, args);
	va_end(args);

}

/*
 * node_bye_if_writable
 *
 * If node is writable, act as if node_bye() had been called.
 * Otherwise, act as if node_remove() had been called.
 */
void node_bye_if_writable(
	struct gnutella_node *n, gint code, const gchar *reason, ...)
{
	va_list args;

	va_start(args, reason);

	if (NODE_IS_WRITABLE(n))
		node_bye_v(n, code, reason, args);
	else
		node_remove_v(n, reason, args);
}

/*
 * node_is_connected
 *
 * Is there a node connected with this IP/port?
 *
 * The port is tested only when `incoming' is FALSE, i.e. we allow
 * only one incoming connection per IP, even when there are several
 * instances, all on different ports.
 */
gboolean node_is_connected(guint32 ip, guint16 port, gboolean incoming)
{
	const GSList *sl;

	if (ip == listen_ip() && port == listen_port)	/* yourself */
		return TRUE;

	for (sl = sl_nodes; sl; sl = g_slist_next(sl)) {
		struct gnutella_node *n = (struct gnutella_node *) sl->data;
		if (n->status == GTA_NODE_REMOVING || n->status == GTA_NODE_SHUTDOWN)
			continue;
		if (n->ip == ip) {
			if (incoming)
				return TRUE;	/* Only one per host */
			if (n->port == port)
				return TRUE;
		}
	}
	return FALSE;
}

/*
 * node_host_is_connected
 *
 * Are we directly connected to that host?
 */
gboolean node_host_is_connected(guint32 ip, guint16 port)
{
	const GSList *sl;

	/* Check our local ip */

	if (ip == listen_ip())
		return TRUE;

	/* Check the nodes -- this is a small list, OK to traverse */

	for (sl = sl_nodes; sl; sl = g_slist_next(sl)) {
		struct gnutella_node *node = (struct gnutella_node *) sl->data;
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
 * formatted_connection_pongs
 *
 * Build CONNECT_PONGS_COUNT pongs to emit as an X-Try header.
 * We stick to strict formatting rules: no line of more than 76 chars.
 *
 * Returns a pointer to static data.
 *
 * XXX Refactoring note: there is a need for generic header formatting
 * routines, and especially the dumping routing, which could be taught
 * basic formatting and splitting so that very long lines are dumped using
 * continuations. --RAM, 10/01/2002
 */
static gchar *formatted_connection_pongs(gchar *field, hcache_type_t htype)
{
	struct gnutella_host hosts[CONNECT_PONGS_COUNT];
	gint hcount;
	gchar *line = "";

	hcount = hcache_fill_caught_array(htype, hosts, CONNECT_PONGS_COUNT);
	g_assert(hcount >= 0 && hcount <= CONNECT_PONGS_COUNT);

/* The most a pong can take is "xxx.xxx.xxx.xxx:yyyyy, ", i.e. 23 */
#define PONG_LEN 23
#define LINE_LENGTH	72

	if (hcount) {
		gint i;
		gpointer fmt = header_fmt_make(field,
			PONG_LEN * CONNECT_PONGS_COUNT + 30);

		for (i = 0; i < hcount; i++) {
			gchar *ipstr = ip_port_to_gchar(hosts[i].ip, hosts[i].port);
			header_fmt_append(fmt, ipstr, ", ");
		}

		header_fmt_end(fmt);
		line = header_fmt_to_gchar(fmt);
		header_fmt_free(fmt);
	}

#undef PONG_LEN
#undef LINE_LENGTH

	return line;		/* Pointer to static data */
}

/*
 * node_crawler_headers
 *
 * Generate the "Peers:" and "Leaves:" headers in a static buffer.
 * Returns ready-to-insert header chunk, with all lines ending with "\r\n".
 */
static gchar *node_crawler_headers(struct gnutella_node *n)
{
	static gchar buf[1536];		/* 1.5 KB */
	GSList *sl;
	gint maxsize;
	gint rw;
	gint count;

	/*
	 * Avoid sending an incomplete trailing IP address by roughly avoiding
	 * any write if less than 32 chars are available in the buffer.
	 */

	maxsize = sizeof(buf) - 32;

	/*
	 * First, the peers.
	 */

	rw = gm_snprintf(buf, sizeof(buf), "Peers: ");

	for (count = 0, sl = sl_nodes; sl && rw < maxsize; sl = g_slist_next(sl)) {
		struct gnutella_node *cn = (struct gnutella_node *) sl->data;

		if (cn == n)				/* Don't show the crawler itself */
			continue;

		if (!NODE_IS_WRITABLE(cn))	/* No longer (or not yet) connected */
			continue;

		if (NODE_IS_LEAF(cn))
			continue;

		if (cn->gnet_ip == 0)		/* No information yet */
			continue;

		if (count > 0)
			rw += gm_snprintf(&buf[rw], sizeof(buf)-rw, ", ");

		rw += gm_snprintf(&buf[rw], sizeof(buf)-rw, "%s",
			ip_port_to_gchar(cn->gnet_ip, cn->gnet_port));

		count++;
	}

	rw += gm_snprintf(&buf[rw], sizeof(buf)-rw, "\r\n");

	if (current_peermode != NODE_P_ULTRA || rw >= maxsize)
		return buf;

	/*
	 * We're an ultranode, list our leaves.
	 */

	rw += gm_snprintf(&buf[rw], sizeof(buf)-rw, "Leaves: ");

	for (count = 0, sl = sl_nodes; sl && rw < maxsize; sl = g_slist_next(sl)) {
		struct gnutella_node *cn = (struct gnutella_node *) sl->data;

		if (cn == n)				/* Don't show the crawler itself */
			continue;

		if (!NODE_IS_WRITABLE(cn))	/* No longer (or not yet) connected */
			continue;

		if (!NODE_IS_LEAF(cn))
			continue;

		if (cn->gnet_ip == 0)		/* No information yet */
			continue;

		if (count > 0)
			rw += gm_snprintf(&buf[rw], sizeof(buf)-rw, ", ");

		rw += gm_snprintf(&buf[rw], sizeof(buf)-rw, "%s",
			ip_port_to_gchar(cn->gnet_ip, cn->gnet_port));

		count++;
	}

	rw += gm_snprintf(&buf[rw], sizeof(buf)-rw, "\r\n");

	return buf;
}

/*
 * send_node_error
 *
 * Send error message to remote end, a node presumably.
 * NB: We don't need a node to call this routine, only a socket.
 */
void send_node_error(
	struct gnutella_socket *s, int code, const gchar *msg, ...)
{
	gchar gnet_response[2048];
	gchar msg_tmp[256];
	gint rw;
	gint sent;
	va_list args;

	va_start(args, msg);
	gm_vsnprintf(msg_tmp, sizeof(msg_tmp)-1,  msg, args);
	va_end(args);

	/*
	 * When sending a 503 (Busy) error to a node, send some hosts from
	 * our cache list as well.  Likewise on 403 (Non-compressed, rejected).
	 * If we're not a regular node, send out X-Try-Ultrapeers for 204 as well.
	 */

	rw = gm_snprintf(gnet_response, sizeof(gnet_response),
		"GNUTELLA/0.6 %d %s\r\n"
		"User-Agent: %s\r\n"
		"Remote-IP: %s\r\n"
		"X-Token: %s\r\n"
		"X-Live-Since: %s\r\n"
		"%s"		/* X-Ultrapeer */
		"%s",		/* X-Try */
		code, msg_tmp, version_string, ip_to_gchar(s->ip),
		tok_version(), start_rfc822_date,
		current_peermode == NODE_P_NORMAL ? "" :
		current_peermode == NODE_P_LEAF ?
			"X-Ultrapeer: False\r\n": "X-Ultrapeer: True\r\n",
		(current_peermode == NODE_P_NORMAL && (code == 503 || code == 403)) ?
			formatted_connection_pongs("X-Try", HCACHE_ANY) : "");

	header_features_generate(&xfeatures.connections,
		gnet_response, sizeof(gnet_response), &rw);

	rw += gm_snprintf(&gnet_response[rw], sizeof(gnet_response)-rw,
		"%s"		/* X-Try-Ultrapeers */
		"\r\n",
		(current_peermode != NODE_P_NORMAL &&
				(code == 503 || code == 403 || code == 204)) ?
			formatted_connection_pongs("X-Try-Ultrapeers", HCACHE_ULTRA) : "");

	g_assert(rw < sizeof(gnet_response));

	if (-1 == (sent = bws_write(bws.gout, s->file_desc, gnet_response, rw))) {
		if (dbg) g_warning("Unable to send back error %d (%s) to node %s: %s",
			code, msg_tmp, ip_to_gchar(s->ip), g_strerror(errno));
	} else if (sent < rw) {
		if (dbg) g_warning("Only sent %d out of %d bytes of error %d (%s) "
			"to node %s: %s",
			sent, rw, code, msg_tmp, ip_to_gchar(s->ip), g_strerror(errno));
	} else if (dbg > 2) {
		printf("----Sent error %d to node %s (%d bytes):\n%.*s----\n",
			code, ip_to_gchar(s->ip), rw, rw, gnet_response);
		fflush(stdout);
	}
}

/*
 * send_proxy_request
 *
 * Request that node becomes our push-proxy.
 */
static void send_proxy_request(gnutella_node_t *n)
{
	g_assert(n->attrs & NODE_A_CAN_VENDOR);
	g_assert(is_firewalled);
	g_assert(n->proxy_ip == 0);		/* Not proxying us yet */

	n->flags |= NODE_F_PROXY;
	vmsg_send_proxy_req(n, guid);
}

/*
 * node_became_firewalled
 *
 * Called when we were not firewalled and suddenly become firewalled.
 * Send proxy requests to our current connections.
 */
void node_became_firewalled(void)
{
	GSList *sl;

	g_assert(is_firewalled);

	for (sl = sl_nodes; sl; sl = g_slist_next(sl)) {
		struct gnutella_node * n = (struct gnutella_node *) sl->data;

		if (NODE_IS_LEAF(n))
			continue;

		if (n->proxy_ip == 0 && (n->attrs & NODE_A_CAN_VENDOR))
			send_proxy_request(n);
	}
}

/*
 * node_is_now_connected
 *
 * Called when we know that we're connected to the node, at the end of
 * the handshaking (both for incoming and outgoing connections).
 */
static void node_is_now_connected(struct gnutella_node *n)
{
	struct gnutella_socket *s = n->socket;
	txdrv_t *tx;
	gboolean peermode_changed = FALSE;

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
	 * Terminate crawler connection.
	 */

	if (n->flags & NODE_F_CRAWLER) {
		node_remove(n, "Sent crawling info");
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
	n->last_update = n->connect_date = time((time_t *) NULL);

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
	default:
		break;
	}
	
	/*
	 * Determine the frequency at which we will send "alive pings", and at
	 * which we shall accept regular pings on that connection.
	 */

	n->ping_throttle = PING_REG_THROTTLE;

	switch (current_peermode) {
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
	default:
		g_error("unknown peer mode %d", current_peermode);
		break;
	}

	/*
	 * Create the RX stack, and enable reception of data.
	 */

	if (n->attrs & NODE_A_RX_INFLATE) {
		rxdrv_t *rx;

		if (dbg > 4)
			printf("Receiving compressed data from node %s\n", node_ip(n));

		n->rx = rx_make(n, &rx_inflate_ops, node_data_ind, 0);
		rx = rx_make_under(n->rx, &rx_link_ops, 0);
		g_assert(rx);			/* Cannot fail */
		if (n->flags & NODE_F_LEAF)
			compressed_leaf_cnt++;
        compressed_node_cnt++;
	} else
		n->rx = rx_make(n, &rx_link_ops, node_data_ind, 0);

	rx_enable(n->rx);
	n->flags |= NODE_F_READABLE;

	/*
	 * Create the TX stack, as we're going to tranmit Gnet messages.
	 */

	tx = tx_make(n, &tx_link_ops, 0);		/* Cannot fail */

	/*
	 * If we committed on compressing traffic, install layer.
	 */

	if (n->attrs & NODE_A_TX_DEFLATE) {
		struct tx_deflate_args args;
		txdrv_t *ctx;
		extern cqueue_t *callout_queue;

		if (dbg > 4)
			printf("Sending compressed data to node %s\n", node_ip(n));

		args.nd = tx;
		args.cq = callout_queue;

		ctx = tx_make(n, &tx_deflate_ops, &args);
		if (ctx == NULL) {
			tx_free(tx);
			node_remove(n, "Cannot setup compressing TX stack");
			return;
		}

		tx = ctx;		/* Use compressing stack */
	}

	g_assert(tx);

	n->outq = mq_make(node_sendqueue_size, n, tx);
	n->searchq = sq_make(n);
	n->alive_pings = alive_make(n, ALIVE_MAX_PENDING);
	n->flags |= NODE_F_WRITABLE;

	/*
	 * Terminate connection if the peermode changed during handshaking.
	 */

	if (peermode_changed) {
		node_bye(n, 504, "Switched between Leaf/Ultra during handshake");
		return;
	}

	if (current_peermode == NODE_P_LEAF) {
		gpointer qrt = qrt_get_table();

		/*
		 * If we don't even have our first QRT computed yet, we
		 * will send it to our ultranode when node_qrt_changed()
		 * is called by the computation code.
		 */

		if (qrt)
			node_send_qrt(n, qrt);
	}

	/*
	 * Set the socket's send buffer size to a small value, to make sure we
	 * flow control early.  Increase the receive buffer to allow a larger
	 * reception window (assuming an original default 8K buffer size).
	 */

	sock_send_buf(s, NODE_IS_LEAF(n) ?
		NODE_SEND_LEAF_BUFSIZE : NODE_SEND_BUFSIZE, TRUE);

	sock_recv_buf(s, NODE_RECV_BUFSIZE, FALSE);

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
			vmsg_send_connect_back(n, listen_port);
			if (!NODE_IS_LEAF(n))
				send_proxy_request(n);
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
			n->qrelayed = g_hash_table_new(g_str_hash, g_str_equal);
			n->qrelayed_created = time(NULL);
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

	/*
	 * TODO Update the search button if there is the search entry
	 * is not empty.
	 */
}

/*
 * node_got_bye
 *
 * Received a Bye message from remote node.
 */
static void node_got_bye(struct gnutella_node *n)
{
	guint16 code;
	gchar *message = n->data + 2; 
	guchar c;
	gint cnt;
	gchar *p;
	gboolean warned = FALSE;
	gboolean is_plain_message = TRUE;
	gint message_len = n->size - 2;

	READ_GUINT16_LE(n->data, code);

	/*
	 * The first line can end with <cr><lf>, in which case we have an RFC-822
	 * style header in the packet.  Since the packet may not be NUL terminated,
	 * perform the scan manually.
	 */

	for (cnt = 0, p = message; cnt < message_len; cnt++, p++) {
		c = *p;
		if (c == '\0') {			/* NUL marks the end of the message */
			if (dbg && cnt != message_len - 1)
				g_warning("Bye message %u from %s <%s> has early NUL",
					code, node_ip(n), node_vendor(n));
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
			if (dbg)
				g_warning("Bye message %u from %s <%s> contains control chars",
					code, node_ip(n), node_vendor(n));
		}
	}

	if (!is_plain_message) {
		/* XXX parse header */
		if (dbg)
			printf("----Bye Message from %s:\n%.*s----\n",
				node_ip(n), (gint) n->size - 2, message);
	}

	if (dbg)
		g_warning("node %s (%s) sent us BYE %d %.*s",
			node_ip(n), node_vendor(n), code, MIN(80, message_len), message);

	node_remove(n, "Got BYE %d %.*s", code, MIN(80, message_len), message);
}

/*
 * node_set_online_mode
 *
 * Whether they want to be "online" within Gnutella or not.
 */
void node_set_online_mode(gboolean on)
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

/*
 * node_current_peermode_changed
 *
 * Called from the property system when current peermode is changed.
 */
void node_current_peermode_changed(node_peer_t mode)
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

/*
 * node_set_current_peermode
 *
 * Called from the node timer when the current peermode has changed.
 *
 * We call this "asynchronously" because the current peermode can change
 * during handshaking, when we accept the guidance of the remote ultrapeer
 * to become a leaf node.
 */
static void node_set_current_peermode(node_peer_t mode)
{
	const gchar *msg = NULL;
	static node_peer_t old_mode = NODE_P_UNKNOWN;

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
		node_bye_flags(0xffffffff, 203, "Becoming a leaf node");
		break;
	default:
		g_error("unhandled mode %d", mode);
		break;
	}

	if (dbg > 2)
		printf("Switching to \"%s\" peer mode\n", msg);

	if (old_mode != NODE_P_UNKNOWN) {	/* Not at init time */
		bsched_set_peermode(mode);		/* Adapt Gnet bandwidth */
		pcache_set_peermode(mode);		/* Adapt pong cache lifetime */
	}

	old_mode = mode;
}

/*
 * extract_field_pongs
 *
 * Extract host:port information out of a header field and add those to our
 * pong cache.
 *
 * Returns the amount of valid pongs we parsed.
 *
 * The syntax we expect is:
 *
 *   X-Try: host1:port1, host2:port2; host3:port3
 *
 * i.e. we're very flexible about the separators which can be "," or ";".
 */
static gint extract_field_pongs(gchar *field, hcache_type_t type)
{
	const gchar *tok;
	gint pong = 0;

	for (tok = strtok(field, ",;"); tok; tok = strtok(NULL, ",;")) {
		guint16 port;
		guint32 ip;

		if (gchar_to_ip_port(tok, &ip, &port)) {
			if (type == HCACHE_ULTRA)
				host_add_ultra(ip, port);
			else
				host_add(ip, port, FALSE);
			pong++;
		}
	}

	return pong;
}

/*
 * extract_header_pongs
 *
 * Extract the header pongs from the header (X-Try lines).
 * The node is only given for tracing purposes.
 */
static void extract_header_pongs(header_t *header, struct gnutella_node *n)
{
	gchar *field;
	gint pong;

	/*
	 * The X-Try line refers to regular nodes.
     * (Also allow a plain Try: header, for when it is standardized)
	 */

	field = header_get(header, "X-Try");
	if (!field) field = header_get(header, "Try");

	if (field) {
		pong = extract_field_pongs(field, HCACHE_ANY);
		if (dbg > 4)
			printf("Node %s sent us %d pong%s in header\n",
				node_ip(n), pong, pong == 1 ? "" : "s");
		if (pong == 0 && dbg)
			g_warning("Node %s sent us unparseable X-Try: %s\n",
				node_ip(n), field);
	}

	/*
	 * The X-Try-Ultrapeers line refers to ultra-nodes.
	 * For now, we don't handle ultranodes, so store that as regular pongs.
     * (Also allow a plain Try-Ultrapeers: header, for when it is standardized)
	 */

	field = header_get(header, "X-Try-Ultrapeers");
	if (!field) field = header_get(header, "Try-Ultrapeers");

	if (field) {
		pong = extract_field_pongs(field, HCACHE_ULTRA);
		if (dbg > 4)
			printf("Node %s sent us %d ultranode pong%s in header\n",
				node_ip(n), pong, pong == 1 ? "" : "s");
		if (pong == 0 && dbg)
			g_warning("Node %s sent us unparseable X-Try-Ultrapeers: %s\n",
				node_ip(n), field);
	}
}

/*
 * extract_my_ip
 *
 * Try to determine whether headers contain an indication of our own IP.
 * Return 0 if none found, or the indicated IP address.
 */
static guint32 extract_my_ip(header_t *header)
{
	const gchar *field;

	field = header_get(header, "Remote-Ip");

	if (!field)
		return 0;

	return gchar_to_ip(field);
}

/*
 * analyse_status
 *
 * Analyses status lines we get from incoming handshakes (final ACK) or
 * outgoing handshakes (inital REPLY, after our HELLO)
 *
 * Returns TRUE if acknowledgment was OK, FALSE if an error occurred, in
 * which case the node was removed with proper status.
 *
 * If `code' is not NULL, it is filled with the returned code, or -1 if
 * we were unable to parse the status.
 */
static gboolean analyse_status(struct gnutella_node *n, gint *code)
{
	struct gnutella_socket *s = n->socket;
	gchar *status;
	gint ack_code;
	gint major = 0, minor = 0;
	const gchar *ack_message = "";
	gboolean ack_ok = FALSE;
	gboolean incoming = (n->flags & NODE_F_INCOMING) ? TRUE : FALSE;
	const gchar *what = incoming ? "acknowledgment" : "reply";

	status = getline_str(s->getline);

	ack_code = http_status_parse(status, "GNUTELLA",
		&ack_message, &major, &minor);

	if (code)
		*code = ack_code;

	if (dbg) {
		printf("%s: code=%d, message=\"%s\", proto=%d.%d\n",
			incoming ? "ACK" : "REPLY",
			ack_code, ack_message, major, minor);
		fflush(stdout);
	}
	if (ack_code == -1) {
		if (dbg) {
			if (incoming || 0 != strcmp(status, "GNUTELLA OK")) {
				g_warning("weird GNUTELLA %s status line from %s",
					what, ip_to_gchar(n->ip));
				dump_hex(stderr, "Status Line", status,
					MIN(getline_length(s->getline), 80));
			} else
				g_warning("node %s gave a 0.4 reply to our 0.6 HELLO, dropping",
					node_ip(n));
		}
		node_mark_bad_ip(n);
	} else {
		ack_ok = TRUE;
		n->flags |= NODE_F_VALID;		/* This is a Gnutella node */
	}

	if (ack_ok && (major != n->proto_major || minor != n->proto_minor)) {
		if (dbg) {
			if (incoming)
				g_warning("node %s handshaked at %d.%d and now acks at %d.%d, "
					"adjusting", ip_to_gchar(n->ip),
					n->proto_major, n->proto_minor, major, minor);
			else
				g_warning("node %s was sent %d.%d HELLO but supports %d.%d "
					"only, adjusting", ip_to_gchar(n->ip),
					n->proto_major, n->proto_minor, major, minor);
		}
		n->proto_major = major;
		n->proto_minor = minor;
	}

	/*
	 * Is the connection OK?
	 */

	if (!ack_ok)
		node_remove(n, "Weird HELLO %s", what);
	else if (ack_code < 200 || ack_code >= 300) {
		if (ack_code == 401)		/* Unauthorized */
			node_mark_bad_ip(n);
		node_remove(n, "HELLO %s error %d (%s)", what, ack_code, ack_message);
		ack_ok = FALSE;
	}
	else if (!incoming && ack_code == 204) {
		node_remove(n, "Shielded node");
		ack_ok = FALSE;
	}

	return ack_ok;
}

/*
 * node_can_accept_connection
 *
 * Can node accept connection?
 *
 * If `handshaking' is true, we're still in the handshaking phase, otherwise
 * we're already connected and can send a BYE.
 *
 * Returns TRUE if we can accept the connection, FALSE otherwise, with
 * the node being removed.
 */
static gboolean node_can_accept_connection(
	struct gnutella_node *n, gboolean handshaking)
{
	enum node_bad bad;

	g_assert(handshaking || n->status == GTA_NODE_CONNECTED);
	g_assert(n->attrs & (NODE_A_NO_ULTRA|NODE_A_CAN_ULTRA));

	/*
	 * Deny cleanly if they deactivated "online mode".
	 */

	if (handshaking && !allow_gnet_connections) {
		send_node_error(n->socket, 403,
			"Gnet connections currently disabled");
		node_remove(n, "Gnet connections disabled");
		return FALSE;
	}

	/*
	 * Always accept crawler connections.
	 */

	if (n->flags & NODE_F_CRAWLER)
		return TRUE;

	/*
	 * If a specific client version has proven to be very unstable during this
	 * version, don't connect to it.
	 *		-- JA 17/7/200
	 */

	if ((n->attrs & NODE_A_ULTRA) && (bad = node_is_bad(n)) != NODE_BAD_OK) {
		gchar *msg = NULL;

		switch (bad) {
		case NODE_BAD_OK:
			g_error("logic error");
			break;
		case NODE_BAD_IP:
			msg = "Unstable IP address";
			break;
		case NODE_BAD_VENDOR:
			msg = "Servent version appears unstable";
			break;
		case NODE_BAD_NO_VENDOR:
			msg = "No vendor string supplied";
			break;
		}

		send_node_error(n->socket, 403, msg);
		node_remove(n, "Not connecting: %s", msg);
		return FALSE;
	}
	
	/*
	 * If we are handshaking, we have not incremented the node counts yet.
	 * Hence we can do >= tests against the limits.
	 */

	switch (current_peermode) {
	case NODE_P_ULTRA:
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
				send_node_error(n->socket, 403,
					"Compressed connection prefered");
				node_remove(n, "Connection not compressed");
				return FALSE;
			}

			if (handshaking && node_leaf_count >= max_leaves) {
				send_node_error(n->socket, 503,
					"Too many leaf connections (%d max)", max_leaves);
				node_remove(n, "Too many leaves (%d max)", max_leaves);
				return FALSE;
			}
			if (!handshaking && node_leaf_count > max_leaves) {
				node_bye(n, 503,
					"Too many leaf connections (%d max)", max_leaves);
				return FALSE;
			}
		} else if (n->attrs & NODE_A_ULTRA) {
			gint ultra_max;

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
				send_node_error(n->socket, 403,
					"Compressed connection prefered");
				node_remove(n, "Connection not compressed");
				return FALSE;
			}
			
			ultra_max = max_connections - normal_connections;
			ultra_max = MAX(ultra_max, 0);

			if (
				handshaking &&
				node_ultra_count >= ultra_max &&
				!(n->flags & NODE_F_INCOMING)
			) {
				send_node_error(n->socket, 503,
					"Too many ultra connections (%d max)", ultra_max);
				node_remove(n, "Too many ultra nodes (%d max)", ultra_max);
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
			gint connected = node_normal_count + node_ultra_count;

            if (
				prefer_compressed_gnet &&
				!(n->attrs & NODE_A_CAN_INFLATE) &&
				(((n->flags & NODE_F_INCOMING) && 
				connected >= up_connections &&
				connected - compressed_node_cnt > 0) ||
                (n->flags & NODE_F_LEAF))
			) {
				send_node_error(n->socket, 403,
					"Gnet connection not compressed");
				node_remove(n, "Connection not compressed");
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
				send_node_error(n->socket, 503,
					"Too many normal nodes (%d max)", normal_connections);
			else
				send_node_error(n->socket, 403, "Normal nodes refused");
			node_remove(n, "Rejected normal node (%d max)", normal_connections);
			return FALSE;
		}

		break;
	case NODE_P_NORMAL:
		if (handshaking) {
			gint connected = node_normal_count + node_ultra_count;
			if (
				(n->attrs & (NODE_A_CAN_ULTRA|NODE_A_ULTRA)) == NODE_A_CAN_ULTRA
			) {
				send_node_error(n->socket, 503, "Cannot accept leaf node");
				node_remove(n, "Rejected leaf node");
				return FALSE;
			}
			if (connected >= max_connections) {
				send_node_error(n->socket, 503,
					"Too many Gnet connections (%d max)", max_connections);
				node_remove(n, "Too many nodes (%d max)", max_connections);
				return FALSE;
			}
			if (
				prefer_compressed_gnet &&
				(n->flags & NODE_F_INCOMING) && 
				!(n->attrs & NODE_A_CAN_INFLATE) &&
				connected >= up_connections &&
				connected - compressed_node_cnt > 0
			) {
				send_node_error(n->socket, 403,
					"Gnet connection not compressed");
				node_remove(n, "Connection not compressed");
				return FALSE;
			}
		} else if (node_normal_count + node_ultra_count > max_connections) {
			node_bye(n, 503,
				"Too many Gnet connections (%d max)", max_connections);
			return FALSE;
		}
		break;
	case NODE_P_LEAF:
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
				send_node_error(n->socket, 204,
					"Shielded leaf node (%d peers max)", max_ultrapeers);
				node_remove(n, "Sent shielded indication");
				return FALSE;
			}

			if (!(n->attrs & NODE_A_ULTRA)) {
				send_node_error(n->socket, 503, "Looking for an ultra node");
				node_remove(n, "Not an ultra node");
				return FALSE;
			}
			if (node_ultra_count >= max_ultrapeers) {
				send_node_error(n->socket, 503,
					"Too many ultra connections (%d max)", max_ultrapeers);
				node_remove(n, "Too many ultra nodes (%d max)", max_ultrapeers);
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
				send_node_error(n->socket, 403,
					"Compressed connection prefered");
				node_remove(n, "Connection not compressed");
				return FALSE;
			}
		} else if (node_ultra_count > max_ultrapeers) {
			node_bye(n, 503,
				"Too many ultra connections (%d max)", max_ultrapeers);
			return FALSE;
		}
		break;
	default:
		g_assert_not_reached();
	}

	return TRUE;
}

/*
 * node_can_accept_protocol
 *
 * Check whether we can accept a servent supporting a foreign protocol.
 * Must be called during handshaking.
 *
 * Returns TRUE if OK, FALSE if connection was denied.
 */
static gboolean node_can_accept_protocol(
	struct gnutella_node *n, header_t *head)
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
			gchar *msg = "Protocol not acceptable";

			send_node_error(n->socket, 406, msg);
			node_remove(n, msg);
			return FALSE;
		}
	}

	return TRUE;
}

/*
 * node_process_handshake_ack
 *
 * This routine is called to process the whole 0.6+ final handshake header
 * acknowledgement we get back after welcoming an incoming node.
 */
static void node_process_handshake_ack(struct gnutella_node *n, header_t *head)
{
	struct gnutella_socket *s = n->socket;
	gboolean ack_ok;
	const gchar *field;
	gboolean qrp_final_set = FALSE;

	if (dbg) {
		printf("Got final acknowledgment headers from node %s:\n",
			ip_to_gchar(n->ip));
		dump_hex(stdout, "Status Line", getline_str(s->getline),
			MIN(getline_length(s->getline), 80));
		printf("------ Header Dump:\n");
		header_dump(head, stdout);
		printf("\n------\n");
		fflush(stdout);
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
		if (strstr(field, "deflate"))	/* XXX needs more rigourous parsing */
			n->attrs |= NODE_A_RX_INFLATE;	/* We shall decompress input */
	}

	/* X-Ultrapeer -- support for ultra peer mode */

	field = header_get(head, "X-Ultrapeer");
	if (field && 0 == strcasecmp(field, "false")) {
		n->attrs &= ~NODE_A_ULTRA;
		if (current_peermode == NODE_P_ULTRA) {
			n->flags |= NODE_F_LEAF;		/* Remote accepted to become leaf */
			if (dbg) g_warning("node %s <%s> accepted to become our leaf",
				node_ip(n), node_vendor(n));
		}
	}

	/*
	 * X-Query-Routing -- QRP protocol in use by remote servent (negotiated)
	 *
	 * This header is present in the 3rd handshake only when the two servents
	 * advertised different support.  This last indication is the highest
	 * version supported by the remote end, that is less or equals to ours.
	 *
	 * If we don't support that version, we'll BYE the servent later.
	 */

	field = header_get(head, "X-Query-Routing");
	if (field) {
		guint major, minor;
		sscanf(field, "%u.%u", &major, &minor);
		if (major >= n->qrp_major || minor >= n->qrp_minor)
			if (dbg) g_warning("node %s <%s> now claims QRP version %u.%u, "
				"but advertised %u.%u earlier",
				node_ip(n), node_vendor(n), major, minor,
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
		 * the 0.1 version.
		 */

		if (qrp_final_set && (n->qrp_major > 0 || n->qrp_minor > 1)) {
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

		if (dbg > 4)
			printf("read %d Gnet bytes from node %s after handshake\n",
				s->pos, node_ip(n));

		/*
		 * Prepare data buffer out of the socket's buffer.
		 */

		db = pdata_allocb_ext(s->buffer, s->pos, pdata_free_nop, NULL);
		mb = pmsg_alloc(PMSG_P_DATA, db, 0, s->pos);

		/*
		 * The message is given to the RX stack, and it will be freed by
		 * the last function consuming it.
		 */

		rx_recv(rx_bottom(n->rx), mb);

		/* 
		 * We know that the message is synchronously delivered.  At this
		 * point, all the data have been consumed, and the socket buffer
		 * can be "emptied" my marking it holds zero data.
		 */

		s->pos = 0;

	}
}

/*
 * node_process_handshake_header
 *
 * This routine is called to process a 0.6+ handshake header
 * It is either called to process the reply to our sending a 0.6 handshake
 * (outgoing connections) or to parse the initial 0.6 headers (incoming
 * connections).
 */
static void node_process_handshake_header(
	struct gnutella_node *n, header_t *head)
{
	gchar gnet_response[2048];
	gint rw;
	gint sent;
	const gchar *field;
	gboolean incoming = (n->flags & NODE_F_INCOMING);
	const gchar *what = incoming ? "HELLO reply" : "HELLO acknowledgment";
	const gchar *compressing = "Content-Encoding: deflate\r\n";
	const gchar *empty = "";

	if (dbg) {
		printf("Got %s handshaking headers from node %s:\n",
			incoming ? "incoming" : "outgoing",
			ip_to_gchar(n->ip));
		if (!incoming)
			dump_hex(stdout, "Status Line", getline_str(n->socket->getline),
				MIN(getline_length(n->socket->getline), 80));
		printf("------ Header Dump:\n");
		header_dump(head, stdout);
		printf("\n------\n");
		fflush(stdout);
	}

	if (in_shutdown) {
		send_node_error(n->socket, 503, "Servent Shutdown");
		node_remove(n, "Servent Shutdown");
		return;					/* node_remove() has freed s->getline */
	}

	/*
	 * Handle common header fields, non servent-specific.
	 */

	/* User-Agent -- servent vendor identification */

	field = header_get(head, "User-Agent");
	if (field) {
		const gchar *token = header_get(head, "X-Token");
		if (!version_check(field, token, n->ip))
			n->flags |= NODE_F_FAKE_NAME;
        node_set_vendor(n, field);
	}
	
	/* Pong-Caching -- ping/pong reduction scheme */

	field = header_get(head, "Pong-Caching");
	if (field) {
		guint major, minor;
		sscanf(field, "%u.%u", &major, &minor);
		if (major > 0 || minor > 1)
			if (dbg) g_warning("node %s claims Pong-Caching version %u.%u",
				node_ip(n), major, minor);
		n->attrs |= NODE_A_PONG_CACHING;
	}

	/* Node -- remote node Gnet IP/port information */

	if (incoming) {
		guint32 ip;
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

		if (field && gchar_to_ip_port(field, &ip, &port)) {
			pcache_pong_fake(n, ip, port);		/* Might have free slots */

			/*
			 * Since we have the node's IP:port, record it now and mark the
			 * node as valid: if the connection is terminated, the host will
			 * be recorded amongst our valid set.
			 *		--RAM, 18/03/2002.
			 */

			if (ip == n->ip) {
				n->gnet_ip = ip;				/* Signals: we know the port */
				n->gnet_port = port;
				n->gnet_pong_ip = ip;			/* Cannot lie about its IP */
				n->flags |= NODE_F_VALID;
			}
		}
	}

	/* Bye-Packet -- support for final notification */

	field = header_get(head, "Bye-Packet");
	if (field) {
		guint major, minor;
		sscanf(field, "%u.%u", &major, &minor);
		if (major > 0 || minor > 1)
			if (dbg) g_warning("node %s <%s> claims Bye-Packet version %u.%u",
				node_ip(n), node_vendor(n), major, minor);
		n->attrs |= NODE_A_BYE_PACKET;
	}

	/* GGEP -- support for big pings, pongs and pushes */

	field = header_get(head, "Ggep");
	if (field) {
		guint major, minor;
		sscanf(field, "%u.%u", &major, &minor);
		if (major > 0 || (major == 0 && minor >= 5))
			n->attrs |= NODE_A_CAN_GGEP;
	}

	/* Vendor-Message -- support for vendor-specific messages */

	field = header_get(head, "Vendor-Message");

	if (field) {
		guint major, minor;
		sscanf(field, "%u.%u", &major, &minor);
		if (major > 0 || (major == 0 && minor > 1))
			if (dbg) g_warning("node %s <%s> claims Vendor-Message "
				"version %u.%u",
				node_ip(n), node_vendor(n), major, minor);

		n->attrs |= NODE_A_CAN_VENDOR;
	}

	/*
	 * Remote-IP -- IP address of this node as seen from remote node
	 *
	 * Modern nodes include our own IP, as they see it, in the
	 * handshake headers and reply, whether it indicates a success or not.
	 * Use it as an opportunity to automatically detect changes.
	 *		--RAM, 13/01/2002
	 */

	if (!force_local_ip) {
		guint32 ip = extract_my_ip(head);
		if (ip && ip != local_ip)
            settings_ip_changed(ip);
	}

	/* X-Live-Since -- time at which the remote node started. */
	/* Uptime -- the remote host uptime.  Only used by Gnucleus. */

	field = header_get(head, "X-Live-Since");
	if (field) {
		time_t now = time(NULL);
		time_t up = date2time(field, &now);

		/*
		 * We'll be comparing the up_date we compute to our local timestamp
		 * for displaying the node's uptime.  Since our clock could be
		 * offset wrt GMT, we use our current clock skew to offset the remote
		 * timestamp to our local time, so that we can substract the two
		 * quantities to get "meaningful" results.
		 *		--RAM, 05/08/2003
		 */

		if (up == -1)
			g_warning("cannot parse X-Live-Since \"%s\" from %s (%s)",
				field, node_ip(n), node_vendor(n));
		else 
			n->up_date = MIN(clock_gmt2loc(up), now);
	} else {
		field = header_get(head, "Uptime");
		if (field) {
			time_t now = time(NULL);
			gint days, hours, mins;

			if (3 == sscanf(field, "%dD %dH %dM", &days, &hours, &mins))
				n->up_date = now - 86400 * days - 3600 * hours - 60 * mins;
			else if (3 == sscanf(field, "%dDD %dHH %dMM", &days, &hours, &mins))
				n->up_date = now - 86400 * days - 3600 * hours - 60 * mins;
			else
				g_warning("cannot parse Uptime \"%s\" from %s (%s)",
					field, node_ip(n), node_vendor(n));
		}
	}

	/* X-Ultrapeer -- support for ultra peer mode */

	field = header_get(head, "X-Ultrapeer");
	if (field) {
		n->attrs |= NODE_A_CAN_ULTRA;
		if (0 == strcasecmp(field, "true"))
			n->attrs |= NODE_A_ULTRA;
		else if (0 == strcasecmp(field, "false")) {
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

	/*
	 * Accept-Encoding -- decompression support on the remote side
	 */

	field = header_get(head, "Accept-Encoding");
	if (field) {
		if (strstr(field, "deflate")) {	/* XXX needs more rigourous parsing */
			n->attrs |= NODE_A_CAN_INFLATE;
			n->attrs |= NODE_A_TX_DEFLATE;	/* We accept! */
		}
	}

	/*
	 * Content-Encoding -- compression accepted by the remote side
	 */

	field = header_get(head, "Content-Encoding");
	if (field) {
		if (strstr(field, "deflate"))	/* XXX needs more rigourous parsing */
			n->attrs |= NODE_A_RX_INFLATE;	/* We shall decompress input */
	}

	/*
	 * Crawler -- LimeWire's Gnutella crawler
	 */

	field = header_get(head, "Crawler");
	if (field) {
		n->flags |= NODE_F_CRAWLER;
        gnet_prop_set_guint32_val(PROP_CRAWLER_VISIT_COUNT,
            crawler_visit_count + 1);
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
			ban_record(n->socket->ip, msg);
			send_node_error(n->socket, 403, msg);
			node_remove(n, msg);
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
		sscanf(field, "%u.%u", &major, &minor);
		if (major > 0 || minor > 1)
			if (dbg) g_warning("node %s <%s> claims QRP version %u.%u",
				node_ip(n), node_vendor(n), major, minor);
		n->qrp_major = (guint8) major;
		n->qrp_minor = (guint8) minor;
	}

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
		send_node_error(n->socket, 403,
			"Vendor code already has %d%% of our slots", unique_nodes);
		node_remove(n, "Vendor already has %d%% of our slots", unique_nodes);
		return;
	}
	
	/*
	 * Wether we should reserve a slot for gtk-gnutella
	 */

	if (node_reserve_slot(n)) {
		send_node_error(n->socket, 403, "Reserved slot");
		node_remove(n, "Reserved slot");
		return;
	}

	/*
	 * If this is an outgoing connection, we're processing the remote
	 * acknowledgment to our initial handshake.
	 */

	if (!incoming) {
		gboolean mode_changed = FALSE;

		/* Make sure we only receive incoming connections from crawlers */

		if (n->flags & NODE_F_CRAWLER) {
			gchar *msg = "Cannot connect to a crawler";

			send_node_error(n->socket, 403, msg);
			node_remove(n, msg);
			return;
		}

		/* X-Ultrapeer-Needed -- only defined for 2nd reply (outgoing) */

		field = header_get(head, "X-Ultrapeer-Needed");
		if (field && 0 == strcasecmp(field, "false")) {
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
					n->up_date != 0 && n->up_date < start_stamp
				) {
					g_warning("accepting request from %s <%s> to become a leaf",
						node_ip(n), node_vendor(n));

					node_bye_all_but_one(n, 203, "Becoming a leaf node");
					n->flags |= NODE_F_ULTRA;
					mode_changed = TRUE;
					gnet_prop_set_guint32_val(PROP_CURRENT_PEERMODE,
						NODE_P_LEAF);
				} else if (current_peermode != NODE_P_LEAF) {
					gchar *msg = "Not becoming a leaf node";

					if (dbg > 2) g_warning(
						"denying request from %s <%s> to become a leaf",
						node_ip(n), node_vendor(n));

					send_node_error(n->socket, 403, msg);
					node_remove(n, msg);
					return;
				}
			}
		}
		if (field && 0 == strcasecmp(field, "true")) {
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
				node_ip(n), node_vendor(n));

		/*
		 * Prepare our final acknowledgment.
		 */

		g_assert(!mode_changed || current_peermode == NODE_P_LEAF);

		rw = gm_snprintf(gnet_response, sizeof(gnet_response),
			"GNUTELLA/0.6 200 OK\r\n"
			"%s"			/* Content-Encoding */
			"%s"			/* X-Ultrapeer */
			"%s"			/* X-Query-Routing (tells version we'll use) */
			"\r\n",
			(n->attrs & NODE_A_TX_DEFLATE) ? compressing : empty,
			mode_changed ? "X-Ultrapeer: False\r\n" : "",
			(n->qrp_major > 0 || n->qrp_minor > 1) ?
				"X-Query-Routing: 0.1\r\n" : "");
	 	
		g_assert(rw < sizeof(gnet_response));
	} else {
		gint ultra_max;

		/*
		 * Welcome the incoming node.
		 */

		ultra_max = max_connections - normal_connections;
		ultra_max = MAX(ultra_max, 0);

		if (n->flags & NODE_F_CRAWLER)
			rw = gm_snprintf(gnet_response, sizeof(gnet_response),
				"GNUTELLA/0.6 200 OK\r\n"
				"User-Agent: %s\r\n"
				"%s"		/* Peers & Leaves */
				"X-Live-Since: %s\r\n"
				"\r\n",
				version_string, node_crawler_headers(n), start_rfc822_date);
		else {
			rw = gm_snprintf(gnet_response, sizeof(gnet_response),
				"GNUTELLA/0.6 200 OK\r\n"
				"User-Agent: %s\r\n"
				"Pong-Caching: 0.1\r\n"
				"Bye-Packet: 0.1\r\n"
				"GGEP: 0.5\r\n"
				"Vendor-Message: 0.1\r\n"
				"Remote-IP: %s\r\n"
				"Accept-Encoding: deflate\r\n"
				"%s"		/* Content-Encoding */
				"%s"		/* X-Ultrapeer */
				"%s"		/* X-Ultrapeer-Needed */
				"%s"		/* X-Query-Routing */
				"X-Token: %s\r\n"
				"X-Live-Since: %s\r\n"
				"\r\n",
				version_string, ip_to_gchar(n->socket->ip),
				(n->attrs & NODE_A_TX_DEFLATE) ? compressing : empty,
				current_peermode == NODE_P_NORMAL ? "" :
				current_peermode == NODE_P_LEAF ?
					"X-Ultrapeer: False\r\n" :
					"X-Ultrapeer: True\r\n",
				current_peermode != NODE_P_ULTRA ? "" :
				node_ultra_count < ultra_max ? "X-Ultrapeer-Needed: True\r\n" :
				node_leaf_count < max_leaves ? "X-Ultrapeer-Needed: False\r\n" :
					"",
				current_peermode != NODE_P_NORMAL ?
					"X-Query-Routing: 0.1\r\n" : "",
				tok_version(), start_rfc822_date);
				
			header_features_generate(&xfeatures.connections,
				gnet_response, sizeof(gnet_response), &rw);
		}
		g_assert(rw < sizeof(gnet_response));
	}

	/*
	 * We might not be able to transmit the reply atomically.
	 * This should be rare, so we're not handling the case for now.
	 * Simply log it and close the connection.
	 */

	sent = bws_write(bws.gout, n->socket->file_desc, gnet_response, rw);
	if (sent == -1) {
		int errcode = errno;
		if (dbg) g_warning("Unable to send back %s to node %s: %s",
			what, ip_to_gchar(n->ip), g_strerror(errcode));
		node_remove(n, "Failed (Cannot send %s: %s)",
			what, g_strerror(errcode));
		return;
	} else if (sent < rw) {
		if (dbg) g_warning(
			"Could only send %d out of %d bytes of %s to node %s",
			sent, rw, what, ip_to_gchar(n->ip));
		node_remove(n, "Failed (Cannot send %s atomically)", what);
		return;
	} else if (dbg > 2) {
		printf("----Sent OK %s to %s (%d bytes):\n%.*s----\n",
			what, ip_to_gchar(n->ip), rw, rw, gnet_response);
		fflush(stdout);
	}

	/*
	 * Now that we got all the headers, we may update the `last_update' field.
	 */

	n->last_update = time((time_t *) 0);

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
}

/***
 *** I/O header parsing callbacks.
 ***/

#define NODE(x)	((struct gnutella_node *) (x))

static void err_line_too_long(gpointer obj)
{
	send_node_error(NODE(obj)->socket, 413, "Header line too long");
	node_remove(NODE(obj), "Failed (Header line too long)");
}

static void err_header_error_tell(gpointer obj, gint error)
{
	send_node_error(NODE(obj)->socket, 413, header_strerror(error));
}

static void err_header_error(gpointer obj, gint error)
{
	node_remove(NODE(obj), "Failed (%s)", header_strerror(error));
}

static void err_input_exception(gpointer obj)
{
	node_remove(NODE(obj), "Failed (Input Exception)");
}

static void err_input_buffer_full(gpointer obj)
{
	node_remove(NODE(obj), "Failed (Input buffer full)");
}

static void err_header_read_error(gpointer obj, gint error)
{
	node_remove(NODE(obj), "Failed (Input error: %s)", g_strerror(error));
}

static void err_header_read_eof(gpointer obj)
{
	struct gnutella_node *n = NODE(obj);

	if (!(n->flags & NODE_F_CRAWLER))
		node_mark_bad(n);

	node_remove(n, (n->flags & NODE_F_CRAWLER) ?
		"Sent crawling info" : "Failed (EOF)");
}

static void err_header_extra_data(gpointer obj)
{
	node_remove(NODE(obj), "Failed (Extra HELLO data)");
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

static void call_node_process_handshake_header(gpointer obj, header_t *header)
{
	node_process_handshake_header(NODE(obj), header);
}

static void call_node_process_handshake_ack(gpointer obj, header_t *header)
{
	node_process_handshake_ack(NODE(obj), header);
}

#undef NODE

void node_add(guint32 ip, guint16 port)
{
	if (!ip || !port || hostiles_check(ip) || node_ip_is_bad(ip))
		return;
	
   	node_add_socket(NULL, ip, port);
}

void node_add_socket(struct gnutella_socket *s, guint32 ip, guint16 port)
{
	struct gnutella_node *n;
    gchar *connection_type;
	gboolean incoming = FALSE, already_connected = FALSE;
	gint major = 0, minor = 0;

	g_assert(s == NULL || s->resource.node == NULL);

	/*
	 * During shutdown, don't accept any new connection.
	 */

	if (in_shutdown) {
		if (s)
			socket_free(s);
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

	if (!allow_private_network_connection && is_private_ip(ip)) {
		if (s) {
			if (major > 0 || minor > 4)
				send_node_error(s, 404, "Denied access from private IP");
			socket_free(s);
		}
		return;
	}

	if (s && major == 0 && minor < 6) {
		socket_free(s);
		return;
	}

	/*
	 * Check whether we have already a connection to this node.
	 */

	incoming = s != NULL;
	already_connected = node_is_connected(ip, port, incoming);

	if (!incoming && already_connected)
		return;

	/*
	 * Too many gnutellaNet connections?
     *
     * In leaf-mode we only respect max_ultrapeers, in normal-mode
     * node_ultra_count is always 0, and in ultra_mode we can only
     * have outgoing connections to ultra and normal peers, so we do not
     * respect any leaf maximum.
     * -- Richard, 28 Mar 2003
	 */

    if (
		(current_peermode == NODE_P_LEAF && node_ultra_count >= max_ultrapeers)
		||
		(current_peermode != NODE_P_LEAF &&
			node_ultra_count + node_normal_count >= max_connections)
	) {
        if (!s)
            return;
        if (!already_connected) {
			if (whitelist_check(ip)) {
				/* Incoming whitelisted IP, and we're full. Remove one node. */
				(void) node_remove_worst(FALSE);
			} else if (use_netmasks && host_is_nearby(ip)) {
				 /* We are preferring local hosts, remove a non-local node */
				(void) node_remove_worst(TRUE);
			}
		}
	}

	/*
	 * Create new node.
	 */

	n = (struct gnutella_node *) walloc0(sizeof(struct gnutella_node));
    n->node_handle = node_request_handle(n);
    
    n->id = node_id++;
	n->ip = ip;
	n->port = port;
	n->proto_major = major;
	n->proto_minor = minor;
	n->peermode = NODE_P_UNKNOWN;		/* Until end of handshaking */
	n->start_peermode = (node_peer_t) current_peermode;
	n->hops_flow = MAX_HOP_COUNT;
	n->last_update = time(NULL);

	n->routing_data = NULL;
	n->flags = NODE_F_HDSK_PING;

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

		n->flags |= NODE_F_INCOMING;
		connection_type = "Incoming";
	} else {
		/* We have to create an outgoing control connection for the node */

		s = socket_connect(ip, port, SOCK_TYPE_CONTROL);

		if (s) {
			n->status = GTA_NODE_CONNECTING;
			s->resource.node = n;
			n->socket = s;
			n->gnet_ip = ip;
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

		connection_type = "Outgoing";
	}

    node_fire_node_added(n, connection_type);
    node_fire_node_flags_changed(n);

	/*
	 * Insert node in lists, before checking `already_connected', since
	 * we need everything installed to call node_remove(): we want to
	 * leave a trail in the GUI.
	 */

	sl_nodes = g_slist_prepend(sl_nodes, n);
	if (n->status != GTA_NODE_REMOVING)
		nodes_in_list++;

	if (already_connected) {
		if (incoming && (n->proto_major > 0 || n->proto_minor > 4))
			send_node_error(s, 404, "Already connected");
		node_remove(n, "Already connected");
		return;
	}

	if (incoming) {				/* Welcome the incoming node */
		/*
		 * We need to read the remote headers then send ours before we can
		 * operate any data transfer (3-way handshaking).
		 */

		io_get_header(n, &n->io_opaque, bws.gin, s, IO_3_WAY|IO_HEAD_ONLY,
			call_node_process_handshake_header, NULL, &node_io_error);
	}

    node_fire_node_info_changed(n);
}

/*
 * node_parse
 *
 * Processing of messages.
 *
 * NB: callers of this routine must not use the node structure upon return,
 * since we may invalidate that node during the processing.
 */
static void node_parse(struct gnutella_node *node)
{
	static struct gnutella_node *n;
	gboolean drop = FALSE;
	gboolean has_ggep = FALSE;
	gint regular_size = -1;			/* -1 signals: regular size */
	struct route_dest dest;
	query_hashvec_t *qhv = NULL;

	g_return_if_fail(node);
	g_assert(NODE_IS_CONNECTED(node));

	dest.type = ROUTE_NONE;
	n = node;

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
	 * The only time where the handshaking ping wass necessary wass for
	 * "ponging" incoming connections, which we no longer support.
	 * Those were opened solely to send back connection pongs, but we need
	 * the initial ping to know the GUID to use as message ID when replying...
	 *
	 * XXX delete the code snippet below? --RAM, 03/08/2003
	 */

	if (n->flags & NODE_F_HDSK_PING) {
		if (n->header.function == GTA_MSG_INIT && n->header.hops == 0) {
			if (n->header.muid[8] == '\xff' && (guchar) n->header.muid[15] >= 1)
				n->attrs |= NODE_A_PONG_CACHING;
			n->flags &= ~NODE_F_HDSK_PING;		/* Clear indication */
		}
	}

	/*
	 * If node is a leaf, it MUST send its messages with hops = 0.
	 */

	if (NODE_IS_LEAF(n) && n->header.hops > 0) {
		node_bye_if_writable(n, 414, "Leaf node relayed %s",
			gmsg_name(n->header.function));
		return;
	}

	/* First some simple checks */

	switch (n->header.function) {
	case GTA_MSG_INIT:
        if (n->size)
			regular_size = 0;		/* Will check further below */
		break;
	case GTA_MSG_INIT_RESPONSE:
        if (n->size != sizeof(struct gnutella_init_response))
			regular_size = sizeof(struct gnutella_init_response);
		break;
	case GTA_MSG_BYE:
		if (n->header.hops != 0 || n->header.ttl != 1) {
			if (dbg)
				gmsg_log_bad(n, "bye message with improper hops/ttl");
			n->n_bad++;
			drop = TRUE;
            gnet_stats_count_dropped(n, MSG_DROP_BAD_SIZE);
		}
		break;
	case GTA_MSG_PUSH_REQUEST:
        if (n->size != sizeof(struct gnutella_push_request))
			regular_size = sizeof(struct gnutella_push_request);
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
		break;

	case GTA_MSG_VENDOR:
	case GTA_MSG_STANDARD:
		if (n->header.hops != 0 || n->header.ttl != 1) {
			if (dbg)
				gmsg_log_bad(n, "vendor message with improper hops/ttl");
			n->n_bad++;
			drop = TRUE;
            gnet_stats_count_dropped(n, MSG_DROP_BAD_SIZE);
		} else if (n->size > MAX_MSG_SIZE) {
            drop = TRUE;
            gnet_stats_count_dropped(n, MSG_DROP_TOO_LARGE);
		} else {
			/* In case no Vendor-Message was seen in handshake */
			n->attrs |= NODE_A_CAN_VENDOR;
		}
		break;

	case GTA_MSG_QRP:			/* Leaf -> Ultrapeer, never routed */
		if (
			current_peermode != NODE_P_ULTRA ||
			n->peermode != NODE_P_LEAF
		) {
			drop = TRUE;
			gnet_stats_count_dropped(n, MSG_DROP_UNEXPECTED);
			if (dbg)
				gmsg_log_bad(n, "unexpected QRP message");
			n->n_bad++;
		}
		break;
	default:					/* Unknown message type - we drop it */
		drop = TRUE;
        gnet_stats_count_dropped(n, MSG_DROP_UNKNOWN_TYPE);
		if (dbg)
			gmsg_log_bad(n, "unknown message type");
		n->n_bad++;
		break;
	}

	/*
	 * If message has not a regular size, check for a valid GGEP extension.
	 * NB: message must be at least as big as the regular size, or it's
	 * clearly a bad message.
	 */

	if (regular_size != -1) {
		g_assert(n->size != regular_size);

		has_ggep = FALSE;

		if (n->size > regular_size)
			has_ggep = gmsg_check_ggep(n, MAX_GGEP_PAYLOAD, regular_size);

		if (!has_ggep) {
			drop = TRUE;
			gnet_stats_count_dropped(n, MSG_DROP_BAD_SIZE);
		}
	}

	/*
	 * If message is dropped, stop right here.
	 */

	if (drop) {
		if (dbg > 3)
			gmsg_log_dropped(&n->header, "from %s", node_ip(n));

		if (n->header.ttl == 0) {
			if (node_sent_ttl0(n))
				return;				/* Node was kicked out */
		} else {
			n->rx_dropped++;
		}
		goto reset_header;
	}

	/*
	 * With the ping/pong reducing scheme, we no longer pass ping/pongs
	 * to the route_message() routine, and don't even have to store
	 * routing information from pings to be able to route pongs back, which
	 * saves routing entry for useful things...
	 *		--RAM, 02/01/2002
	 */

	switch (n->header.function) {
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
			n->qrt_receive = qrt_receive_create(n, n->query_table);
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
			guint32 ip;
			guint16 port;

			node_extract_host(n, &ip, &port);
			host_add_semi_pong(ip, port);
		}
		break;
	default:
		break;
	}

	/* Compute route (destination) then handle the message if required */

	if (route_message(&n, &dest)) {		/* We have to handle the message */
		g_assert(n);
		switch (n->header.function) {
		case GTA_MSG_PUSH_REQUEST:
			handle_push_request(n);
			break;
		case GTA_MSG_SEARCH:
            /*
             * search_request takes care of telling the stats that
             * the message was dropped.
             */

			if (current_peermode == NODE_P_ULTRA && dest.type != ROUTE_NONE) {
				qhv = query_hashvec;
				qhvec_reset(qhv);
			} else
				qhv = NULL;

			drop = search_request(n, qhv);

			/*
			 * If node is a leaf, undo decrement of TTL: act as if we were
			 * sending the search.  When the results arrives, we'll forward
			 * it to the leaf even if its TTL is zero when it reaches us
			 * (handled by route_message() directly).
			 */
			if (NODE_IS_LEAF(n)) {
				n->header.ttl++;
				n->header.hops--;
			}
			break;
		case GTA_MSG_SEARCH_RESULTS:
            /*
             * search_results takes care of telling the stats that
             * the message was dropped.
             */
			drop = search_results(n);
			break;
		default:
			message_dump(n);
			break;
		}
	}

	if (!n)
		goto clean_dest;	/* The node has been removed during processing */

	if (!drop) {
		if (current_peermode != NODE_P_LEAF) {
			/*
			 * Propagate message, if needed
			 */

			g_assert(regular_size == -1 || has_ggep);

			if (has_ggep)
				gmsg_sendto_route_ggep(n, &dest, regular_size);
			else
				gmsg_sendto_route(n, &dest);

			/*
			 * If message was a query, route it to the appropriate leaves.
			 */

			if (
				current_peermode == NODE_P_ULTRA &&
				n->header.function == GTA_MSG_SEARCH &&
				qhv != NULL
			)
				qrt_route_query(n, qhv);
		}
	} else {
		if (dbg > 3)
			gmsg_log_dropped(&n->header, "from %s", node_ip(n));

		n->rx_dropped++;
	}

reset_header:
	n->have_header = FALSE;
	n->pos = 0;

clean_dest:
	if (dest.type == ROUTE_MULTI)
		g_slist_free(dest.ur.u_nodes);
}

/*
 * node_init_outgoing
 *
 * Called when asynchronous connection to an outgoing node is established.
 */
void node_init_outgoing(struct gnutella_node *n)
{
	struct gnutella_socket *s = n->socket;
	gchar buf[MAX_LINE_SIZE];
	gint len;
	gint sent;
	gboolean old_handshake = FALSE;

	g_assert(s->gdk_tag == 0);

	if (n->proto_major == 0 && n->proto_minor == 4) {
		old_handshake = TRUE;
		len = gm_snprintf(buf, sizeof(buf), "%s0.4\n\n", GNUTELLA_HELLO);
	} else
		len = gm_snprintf(buf, sizeof(buf),
			"%s%d.%d\r\n"
			"Node: %s\r\n"
			"Remote-IP: %s\r\n"
			"User-Agent: %s\r\n"
			"Pong-Caching: 0.1\r\n"
			"Bye-Packet: 0.1\r\n"
			"GGEP: 0.5\r\n"
			"Vendor-Message: 0.1\r\n"
			"Accept-Encoding: deflate\r\n"
			"X-Token: %s\r\n"
			"X-Live-Since: %s\r\n"
			"%s"		/* X-Ultrapeer */
			"%s"		/* X-Query-Routing */
			"\r\n",
			GNUTELLA_HELLO,
			n->proto_major, n->proto_minor,
			ip_port_to_gchar(listen_ip(), listen_port),
			ip_to_gchar(n->ip),
			version_string, tok_version(), start_rfc822_date,
			current_peermode == NODE_P_NORMAL ? "" :
			current_peermode == NODE_P_LEAF ?
				"X-Ultrapeer: False\r\n": "X-Ultrapeer: True\r\n",
			current_peermode != NODE_P_NORMAL ? "X-Query-Routing: 0.1\r\n" : ""
		);

	header_features_generate(&xfeatures.connections, buf, sizeof(buf), &len);

	g_assert(len < sizeof(buf));

	/*
	 * We don't retry a connection from 0.6 to 0.4 if we fail to write the
	 * initial HELLO.
	 */

	if (-1 == (sent = bws_write(bws.gout, n->socket->file_desc, buf, len))) {
		node_remove(n, "Write error during HELLO: %s", g_strerror(errno));
		return;
	} else if (sent < len) {
		node_remove(n, "Partial write during HELLO");
		return;
	} else {
		n->status = GTA_NODE_HELLO_SENT;
		n->last_update = time((time_t *)NULL);
        node_fire_node_info_changed(n);

		if (dbg > 2) {
			printf("----Sent HELLO request to %s (%d bytes):\n%.*s----\n",
				ip_to_gchar(n->ip), len, len, buf);
			fflush(stdout);
		}
	}

	/*
	 * Setup I/O callback to read the reply to our HELLO.
	 */

	if (old_handshake) {
		s->gdk_tag = inputevt_add(s->file_desc,
			INPUT_EVENT_READ | INPUT_EVENT_EXCEPTION,
			node_read_connecting, (gpointer) n);
	} else {
		/*
		 * Prepare parsing of the expected 0.6 reply.
		 */

		io_get_header(n, &n->io_opaque, bws.gin, s, IO_SAVE_FIRST|IO_HEAD_ONLY,
			call_node_process_handshake_header, NULL, &node_io_error);
	}

	g_assert(s->gdk_tag != 0);		/* Leave with an I/O callback set */
}

#include <sys/time.h>
#include <unistd.h>

/*
 * node_flushq
 *
 * Called by queue when it's not empty and it went through the service routine
 * and yet has more data enqueued.
 */
void node_flushq(struct gnutella_node *n)
{
	/*
	 * Put the connection in TCP_NODELAY mode to accelerate flushing of the
	 * kernel buffers by truning off the Nagle algorithm.
	 */

	if (n->flags & NODE_F_NODELAY)		/* Already done */
		return;

	sock_nodelay(n->socket, TRUE);
	n->flags |= NODE_F_NODELAY;
}

/*
 * node_tx_service
 *
 * Called when the queue service routine is switched ON/OFF.
 */
void node_tx_service(struct gnutella_node *n, gboolean on)
{
    node_fire_node_flags_changed(n);
}

/*
 * node_tx_enter_flowc
 *
 * Called by message queue when the node enters TX flow control.
 */
void node_tx_enter_flowc(struct gnutella_node *n)
{
	n->tx_flowc_date = time((time_t *) NULL);

	if (n->attrs & NODE_A_CAN_VENDOR)
		vmsg_send_hops_flow(n, 0);			/* Disable all query traffic */

    node_fire_node_flags_changed(n);
}

/*
 * node_tx_leave_flowc
 *
 * Called by message queue when the node leaves TX flow control.
 */
void node_tx_leave_flowc(struct gnutella_node *n)
{
	if (dbg > 4) {
		gint spent = time((time_t *) NULL) - n->tx_flowc_date;

		printf("node %s spent %d second%s in TX FLOWC\n",
			node_ip(n), spent, spent == 1 ? "" : "s");
	}

	if (n->attrs & NODE_A_CAN_VENDOR)
		vmsg_send_hops_flow(n, 255);		/* Re-enable query traffic */

    node_fire_node_flags_changed(n);
}

/*
 * node_disable_read
 *
 * Disable reading callback.
 */
static void node_disable_read(struct gnutella_node *n)
{
	g_assert(n->rx);

	if (n->flags & NODE_F_NOREAD)
		return;						/* Already disabled */

	n->flags |= NODE_F_NOREAD;
	rx_disable(n->rx);

    node_fire_node_flags_changed(n);
}

/*
 * node_bye_sent
 *
 * Called when the Bye message has been successfully sent.
 */
static void node_bye_sent(struct gnutella_node *n)
{
	if (dbg > 4)
		printf("finally sent BYE \"%s\" to %s\n", n->error_str, node_ip(n));

	/*
	 * Shutdown the node.
	 */

	n->flags &= ~NODE_F_BYE_SENT;

	sock_tx_shutdown(n->socket);
	node_shutdown_mode(n, BYE_GRACE_DELAY);
}

/*
 * node_read
 *
 * Read data from the message buffer we just received.
 * Returns TRUE whilst we think there is more data to read in the buffer.
 */
static gboolean node_read(struct gnutella_node *n, pmsg_t *mb)
{
	gint r;

	if (!n->have_header) {		/* We haven't got the header yet */
		gchar *w = (gchar *) &n->header;
		gboolean kick = FALSE;

		r = pmsg_read(mb, w + n->pos, sizeof(struct gnutella_header) - n->pos);
		n->pos += r;
		node_add_rx_read(n, r);

		if (n->pos < sizeof(struct gnutella_header))
			return FALSE;

		/* Okay, we have read the full header */

		n->have_header = TRUE;

		READ_GUINT32_LE(n->header.size, n->size);

        gnet_stats_count_received_header(n);
		switch (n->header.function) {
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

		switch (n->header.function) {
		case GTA_MSG_BYE:
			if (n->size > BYE_MAX_SIZE) {
				gnet_stats_count_dropped_nosize(n, MSG_DROP_WAY_TOO_LARGE);
				node_remove(n, "Kicked: %s message too big (%d bytes)",
							gmsg_name(n->header.function), n->size);
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
				gmsg_name(n->header.function), n->size);
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
				g_warning("got %u byte %s message, should have kicked node\n",
					n->size, gmsg_name(n->header.function));
				gnet_stats_count_dropped_nosize(n, MSG_DROP_WAY_TOO_LARGE);
				node_disable_read(n);
				node_bye(n, 400, "Too large %s message (%d bytes)",
					gmsg_name(n->header.function), n->size);
				return FALSE;
			}

			if (n->allocated)
				n->data = g_realloc(n->data, maxsize);
			else
				n->data = g_malloc0(maxsize);
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
}

/*
 * node_data_ind
 *
 * RX data indication callback used to give us some new Gnet traffic in a
 * low-level message structure (which can contain several Gnet messages).
 */
static void node_data_ind(rxdrv_t *rx, pmsg_t *mb)
{
	struct gnutella_node *n = rx_node(rx);

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

	n->last_rx = time(NULL);
	n->flags |= NODE_F_ESTABLISHED;		/* Since we've got Gnutella data */

	while (n->status == GTA_NODE_CONNECTED && NODE_IS_READABLE(n)) {
		if (!node_read(n, mb))
			break;
	}

	pmsg_free(mb);
}

/*
 * node_read_connecting
 *
 * Reads an outgoing connecting CONTROL node handshaking at the 0.4 level.
 */
static void node_read_connecting(
	gpointer data, gint source, inputevt_cond_t cond)
{
	struct gnutella_node *n = (struct gnutella_node *) data;
	struct gnutella_socket *s = n->socket;
	gint r;

	g_assert(n->proto_major == 0 && n->proto_minor == 4);

	if (cond & INPUT_EVENT_EXCEPTION) {
		socket_eof(s);
		node_remove(n, "Failed (Input Exception)");
		return;
	}

	r = bws_read(bws.gin, s->file_desc, s->buffer + s->pos,
		GNUTELLA_WELCOME_LENGTH - s->pos);

	if (!r) {
		socket_eof(s);
		node_remove(n, "Failed (EOF)");
		return;
	} else if (r < 0 && errno == EAGAIN)
		return;
	else if (r < 0) {
		socket_eof(s);
		node_remove(n, "Read error in HELLO: %s", g_strerror(errno));
		return;
	}

	s->pos += r;

	if (s->pos < GNUTELLA_WELCOME_LENGTH)
		return;					/* We haven't read enough bytes yet */

#define TRACE_LIMIT		256

	if (strcmp(s->buffer, gnutella_welcome) != 0) {
		/*
		 * The node does not seem to be a valid gnutella server !?
		 *
		 * Try to read a little more data, so that we log more than just
		 * the length of the expected welcome.
		 */

		if (s->pos < TRACE_LIMIT) {
			gint more = TRACE_LIMIT - s->pos;
			r = bws_read(bws.gin, s->file_desc, s->buffer + s->pos, more);
			if (r > 0)
				s->pos += r;
		}

		if (dbg) {
			g_warning("node %s replied to our 0.4 HELLO strangely", node_ip(n));
			dump_hex(stderr, "HELLO Reply",
				s->buffer, MIN(s->pos, TRACE_LIMIT));
		}
		node_remove(n, "Failed (Not a Gnutella server?)");
		return;
	}

#undef TRACE_LIMIT

	/*
	 * When the peer mode is set to NODE_P_LEAF, we normally don't try
	 * to downgrade the handshaking to 0.4.  However, to avoid any race
	 * condition, redo the testing now.
	 */

	if (current_peermode == NODE_P_LEAF) {
		node_remove(n, "Old 0.4 client cannot be an ultra node");
		return;
	}

	/*
	 * Okay, we are now really connected to a Gnutella node at the 0.4 level.
	 */

	s->pos = 0;

	g_source_remove(s->gdk_tag);
	s->gdk_tag = 0;

	node_is_now_connected(n);
}

/*
 * node_sent_ttl0
 *
 * Called when a node sends a message with TTL=0
 * Returns TRUE if node was removed (due to a duplicate bye, probably),
 * FALSE otherwise.
 */
gboolean node_sent_ttl0(struct gnutella_node *n)
{
	g_assert(n->header.ttl == 0);

	gnet_stats_count_dropped(n, MSG_DROP_TTL0);

	/*
	 * Don't disconnect if we're a leaf node.
	 * Some broken Ultrapeers out there do forward TTL=0 messages to their
	 * leaves.  The harm is limited, since leaves don't forward messages.
	 *		--RAM, 12/01/2003
	 */

	if (
		current_peermode != NODE_P_LEAF &&
		connected_nodes() > MAX(2, up_connections)
	) {
		node_bye(n, 408, "%s %s message with TTL=0",
			n->header.hops ? "Relayed" : "Sent",
			gmsg_name(n->header.function));
		return n->status == GTA_NODE_REMOVING;
	}

	n->rx_dropped++;
	n->n_bad++;

	if (dbg)
		gmsg_log_bad(n, "message received with TTL=0");

	return FALSE;
}

/*
 * node_bye_flags
 *
 * Send a BYE message to all the nodes matching the specified flags.
 */
static void node_bye_flags(guint32 mask, gint code, gchar *message)
{
	GSList *sl;

	for (sl = sl_nodes; sl; sl = g_slist_next(sl)) {
		struct gnutella_node *n = sl->data;

		if (n->status == GTA_NODE_REMOVING || n->status == GTA_NODE_SHUTDOWN)
			continue;

		if (n->flags & mask)
			node_bye_if_writable(n, code, message);
	}
}

/*
 * node_bye_all_but_one
 *
 * Send a BYE message to all the nodes but the one supplied as argument.
 */
static void node_bye_all_but_one(
	struct gnutella_node *nskip, gint code, gchar *message)
{
	GSList *sl;

	for (sl = sl_nodes; sl; sl = g_slist_next(sl)) {
		struct gnutella_node *n = sl->data;

		if (n->status == GTA_NODE_REMOVING || n->status == GTA_NODE_SHUTDOWN)
			continue;

		if (n != nskip)
			node_bye_if_writable(n, code, message);
	}
}

/*
 * node_bye_all
 *
 * Send a BYE message to all the nodes.
 */
void node_bye_all(void)
{
	GSList *sl;
	
	g_assert(!in_shutdown);		/* Meant to be called once */

	in_shutdown = TRUE;
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
	}
}

/*
 * node_bye_pending
 *
 * Returns true whilst there are some connections with a pending BYE.
 */
gboolean node_bye_pending(void)
{
	g_assert(in_shutdown);		/* Cannot be called before node_bye_all() */

	return pending_byes > 0;
}

/*
 * node_remove_worst
 *
 * Removes the node with the worst stats, considering the
 * number of weird, bad and duplicate packets.
 *
 * If `non_local' is TRUE, we're removing this node because it is not
 * a local node, and we're having a connection from the local LAN.
 * Otherwise, we're just removing a bad node (the BYE code is different).
 */
gboolean node_remove_worst(gboolean non_local)
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
        if (!non_local && whitelist_check(n->ip))
            continue;

		/* Don't kick nearby hosts if making room for a local node */
		if (non_local && host_is_nearby(n->ip))
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
            m = g_slist_append(m, n);
            num++;
        }
    }
    if (m) {
        n = g_slist_nth_data(m, random_value(num - 1));
        g_slist_free(m);
		if (non_local)
			node_bye_if_writable(n, 202, "Local Node Preferred");
		else {
			if (worst)
				node_bye_if_writable(n, 409, "Too Many Errors");
			else
				node_bye_if_writable(n, 202, "Making Room for Another Node");
		}
        return TRUE;
    }

    return FALSE;
}

/*
 * node_send_qrt
 *
 * Initiate sending of the query routing table.
 */
static void node_send_qrt(struct gnutella_node *n, gpointer query_table)
{
	g_assert(current_peermode == NODE_P_LEAF);
	g_assert(NODE_IS_ULTRA(n));
	g_assert(query_table != NULL);
	g_assert(n->qrt_update == NULL);

	n->qrt_update = qrt_update_create(n, n->query_table);

	if (n->query_table)
		qrt_unref(n->query_table);

	n->query_table = qrt_ref(query_table);
	node_send_patch_step(n);

	node_fire_node_flags_changed(n);
}

/*
 * node_send_patch_step
 *
 * Incrementally send the routing table patch to our Ultrapeer.
 */
static void node_send_patch_step(struct gnutella_node *n)
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

	if (dbg > 2)
		printf("QRP patch sending to %s done (%s)\n",
			node_ip(n), ok ? "OK" : "FAILED");

	if (!ok) {
		qrt_unref(n->query_table);
		n->query_table = NULL;			/* Table was not successfuly sent */
	}

	qrt_update_free(n->qrt_update);
	n->qrt_update = NULL;

	node_fire_node_flags_changed(n);
}

/*
 * node_qrt_discard
 *
 * Invoked when a leaf sends us a RESET message, making the existing
 * routing table obsolete.
 */
void node_qrt_discard(struct gnutella_node *n)
{
	g_assert(n->peermode == NODE_P_LEAF);

	if (n->query_table != NULL) {
		qrt_unref(n->query_table);
		n->query_table = NULL;
	}

    node_fire_node_flags_changed(n);
}

/*
 * node_qrt_install
 *
 * Invoked for ultra nodes to install new Query Routing Table.
 */
void node_qrt_install(struct gnutella_node *n, gpointer query_table)
{
	g_assert(NODE_IS_LEAF(n));
	g_assert(n->query_table == NULL);

	n->query_table = qrt_ref(query_table);
	n->qrt_info = walloc(sizeof(*n->qrt_info));
	qrt_get_info(query_table, n->qrt_info);

    node_fire_node_flags_changed(n);
}

/*
 * node_qrt_patched
 *
 * Invoked for ultra nodes when the Query Routing Table of a leaf was
 * fully patched (i.e. we got a new generation).
 */
void node_qrt_patched(struct gnutella_node *n, gpointer query_table)
{
	g_assert(NODE_IS_LEAF(n));
	g_assert(n->query_table == query_table);
	g_assert(n->qrt_info != NULL);

	qrt_get_info(query_table, n->qrt_info);
}

/*
 * node_qrt_changed
 *
 * Invoked for leaf nodes when our Query Routing Table changed.
 */
void node_qrt_changed(gpointer query_table)
{
	struct gnutella_node *n;
	GSList *sl;

	/*
	 * If we're not a leaf node, do nothing.
	 */

	if (current_peermode != NODE_P_LEAF)
		return;

	/*
	 * Abort sending of any patch to ultranodes.
	 */

    for (sl = sl_nodes; sl; sl = g_slist_next(sl)) {
        n = sl->data;
		if (n->qrt_update != NULL) {
			qrt_update_free(n->qrt_update);
			n->qrt_update = NULL;
			qrt_unref(n->query_table);
			n->query_table = NULL;		/* Sending did not complete */
		}
	}

	/*
	 * Start sending of patch wrt to the previous table to all ultranodes.
	 * (n->query_table holds the last query table we successfully sent)
	 */

    for (sl = sl_nodes; sl; sl = g_slist_next(sl)) {
        n = sl->data;

		if (!NODE_IS_WRITABLE(n) || !NODE_IS_ULTRA(n))
			continue;

		node_send_qrt(n, query_table);
	}
}

void node_close(void)
{
	GSList *sl;
	
	/*
	 * Clean up memory used for determining unstable ips / servents
	 */
	for (sl = unstable_servents; sl != NULL; sl = g_slist_next(sl)) {
		node_bad_client_t *bad_node = (node_bad_client_t *) sl->data;
			
		g_hash_table_remove(unstable_servent, bad_node->vendor);
		atom_str_free(bad_node->vendor);
		wfree(bad_node, sizeof(*bad_node));
	}
	g_slist_free(unstable_servents);
	unstable_servents = NULL;
		
	for (sl = unstable_ips; sl != NULL; sl = g_slist_next(sl)) {
		node_bad_ip_t *bad_ip = (node_bad_ip_t *) sl->data;

		g_hash_table_remove(unstable_ip, GUINT_TO_POINTER(bad_ip->ip));
		wfree(bad_ip, sizeof(*bad_ip));
	}
	g_slist_free(unstable_ips);
	unstable_ips = NULL;

	g_hash_table_destroy(unstable_servent);
	unstable_servent = NULL;
	g_hash_table_destroy(unstable_ip);
	unstable_ip = NULL;
	
	/* Clean up node info */
	while (sl_nodes) {
		struct gnutella_node *n = sl_nodes->data;
		if (n->socket) {
			if (n->socket->getline)
				getline_free(n->socket->getline);
			g_free(n->socket);
		}
		if (n->outq)
			mq_free(n->outq);
		if (n->searchq)
			sq_free(n->searchq);
		if (n->allocated)
			g_free(n->data);
		if (n->gnet_guid)
			atom_guid_free(n->gnet_guid);
		if (n->alive_pings)
			alive_free(n->alive_pings);
		if (n->routing_data)
			routing_node_remove(n);
		if (n->qrt_update)
			qrt_update_free(n->qrt_update);
		if (n->qrt_receive)
			qrt_receive_free(n->qrt_receive);
		if (n->query_table)
			qrt_unref(n->query_table);
		if (n->qrt_info)
			wfree(n->qrt_info, sizeof(*n->qrt_info));
		if (n->rxfc)
			wfree(n->rxfc, sizeof(*n->rxfc));
		if (n->guid) {
			route_proxy_remove(n->guid);
			atom_guid_free(n->guid);
		}
		if (n->qseen != NULL)
			string_table_free(n->qseen);
		if (n->qrelayed != NULL)
			string_table_free(n->qrelayed);
		if (n->qrelayed_old != NULL)
			string_table_free(n->qrelayed_old);
		node_real_remove(n);
	}

	g_slist_free(sl_nodes);
	g_slist_free(sl_proxies);

    g_assert(idtable_ids(node_handle_map) == 0);

    idtable_destroy(node_handle_map);
    node_handle_map = NULL;
	qhvec_free(query_hashvec);

	rxbuf_close();
}

inline void node_add_sent(gnutella_node_t *n, gint x)
{
    n->last_update = time((time_t *)NULL);
	n->sent += x; 
}

inline void node_add_txdrop(gnutella_node_t *n, gint x)
{
    n->last_update = time((time_t *)NULL);
	n->tx_dropped += x;
}

inline void node_add_rxdrop(gnutella_node_t *n, gint x)
{
    n->last_update = time((time_t *)NULL);
	n->rx_dropped += x; 
}

void node_set_vendor(gnutella_node_t *n, const gchar *vendor)
{
	if (n->flags & NODE_F_FAKE_NAME) {
		gchar *name = g_strdup_printf("!%s", vendor);
		n->vendor = atom_str_get(name);
		g_free(name);
	} else
		n->vendor = atom_str_get(vendor);

    node_fire_node_info_changed(n);
}

/*
 * node_set_hops_flow
 *
 * Called when a vendor-specific "hops-flow" message was received to tell
 * us to update the hops-flow counter for the connection: no query whose
 * hop count is greater or equal to the specified `hops' should be sent
 * to that node.
 */
void node_set_hops_flow(gnutella_node_t *n, guint8 hops)
{
	struct node_rxfc_mon *rxfc;

	n->hops_flow = hops;

	/*
	 * There is no monitoring of flow control when the remote node is
	 * a leaf node: it is permitted for the leaf to send us an hops-flow
	 * to disable all query sending if it is not sharing anything.
	 */

	if (n->peermode == NODE_P_LEAF)
		goto fire;

	/*
	 * If we're starting flow control (hops < GTA_NORMAL_TTL), make sure
	 * to create the monitoring structure if absent.
	 */

	if (hops < GTA_NORMAL_TTL && n->rxfc == NULL) {
		n->rxfc = walloc0(sizeof(*n->rxfc));
		n->rxfc->start_half_period = time(NULL);
	}

	g_assert(n->rxfc != NULL || hops >= GTA_NORMAL_TTL);

	rxfc = n->rxfc;

	if (rxfc == NULL)
		goto fire;

	if (hops < GTA_NORMAL_TTL) {
		/* Entering hops-flow control */
		if (rxfc->fc_start == 0)		/* Not previously under flow control */
			rxfc->fc_start = time(NULL);
	} else if (rxfc->fc_start != 0)	{	/* We were under flow control */
		/* Leaving hops-flow control */
		rxfc->fc_accumulator += time(NULL) - rxfc->fc_start;
		rxfc->fc_start = 0;
	}

fire:
    node_fire_node_flags_changed(n);
}

/*
 * node_get_info:
 *
 * Fetches information about a given node. The returned information must
 * be freed manually by the caller using the node_free_info call.
 *
 * O(1):
 * Since the gnet_node_t is actually a pointer to the gnutella_node
 * struct, this call is O(1). It would be safer to have gnet_node be
 * an index in a list or a number, but depending on the underlying
 * container structure of sl_nodes, that would have O(log(n)) (balanced tree)
 * or O(n) (list) runtime.
 */
gnet_node_info_t *node_get_info(const gnet_node_t n)
{
    gnet_node_info_t *info = g_new(gnet_node_info_t, 1);

	node_fill_info(n, info);
    return info;
}

/*
 * node_clear_info
 *
 * Clear dynamically allocated information from the info structure.
 */
void node_clear_info(gnet_node_info_t *info)
{
	if (info->vendor)
		atom_str_free(info->vendor);
}

/*
 * node_free_info:
 *
 * Frees the gnet_node_info_t data returned by node_get_info.
 */
void node_free_info(gnet_node_info_t *info)
{
	node_clear_info(info);
    g_free(info);
}

/*
 * node_fill_info
 *
 * Fill in supplied info structure.
 */
void node_fill_info(const gnet_node_t n, gnet_node_info_t *info)
{
    gnutella_node_t  *node = node_find_by_handle(n); 

    info->node_handle = n;

    info->proto_major = node->proto_major;
    info->proto_minor = node->proto_minor;
    info->vendor = node->vendor ? atom_str_get(node->vendor) : NULL;
    memcpy(info->vcode, node->vcode, 4);

    info->ip   = node->ip;
    info->port = node->port;
}

/*
 * node_fill_flags
 *
 * Fill in supplied flags structure.
 */
void node_fill_flags(const gnet_node_t n, gnet_node_flags_t *flags)
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
    flags->in_tx_flow_control  = NODE_IN_TX_FLOW_CONTROL(node);
    flags->rx_compressed = NODE_RX_COMPRESSED(node);
	flags->hops_flow = node->hops_flow;

	flags->is_push_proxied = node->guid != 0;
	flags->is_proxying = node->proxy_ip != 0;

	flags->qrt_state = QRT_S_NONE;
	if (node->peermode == NODE_P_LEAF) {
		if (node->qrt_receive != NULL) {
			flags->qrt_state = node->query_table != NULL ?
				QRT_S_PATCHING : QRT_S_RECEIVING;
		} else if (node->query_table != NULL)
			flags->qrt_state = QRT_S_RECEIVED;
	} else if (node->peermode == NODE_P_ULTRA) {
		if (node->qrt_update != NULL)
			flags->qrt_state = QRT_S_SENDING;
		else if (node->query_table != NULL)
			flags->qrt_state = QRT_S_SENT;
	}
}

void node_get_status(const gnet_node_t n, gnet_node_status_t *status)
{
    gnutella_node_t  *node = node_find_by_handle(n); 
    time_t now = time((time_t *) NULL);
	bio_source_t *bio;

    g_assert(status != NULL);

    status->status     = node->status;

	status->connect_date = node->connect_date;
	status->up_date      = node->up_date;

    status->sent       = node->sent;
    status->received   = node->received;
    status->tx_dropped = node->tx_dropped;
    status->rx_dropped = node->rx_dropped;
    status->n_bad      = node->n_bad;
    status->n_dups     = node->n_dups;
    status->n_hard_ttl = node->n_hard_ttl;
    status->n_weird    = node->n_weird;

    status->squeue_sent         = NODE_SQUEUE_SENT(node);
    status->squeue_count        = NODE_SQUEUE_COUNT(node);
    status->mqueue_count        = NODE_MQUEUE_COUNT(node);
    status->mqueue_percent_used = NODE_MQUEUE_PERCENT_USED(node);
    status->in_tx_flow_control  = NODE_IN_TX_FLOW_CONTROL(node);

    status->tx_given    = node->tx_given;
    status->tx_deflated = node->tx_deflated;
    status->tx_written  = node->tx_written;
    status->tx_compressed = NODE_TX_COMPRESSED(node);
    status->tx_compression_ratio = NODE_TX_COMPRESSION_RATIO(node);
	status->tx_bps = node->outq ? bio_bps(mq_bio(node->outq)) / 1024.0 : 0.0;

    status->rx_given    = node->rx_given;
    status->rx_inflated = node->rx_inflated;
    status->rx_read     = node->rx_read;
    status->rx_compressed = NODE_RX_COMPRESSED(node);
    status->rx_compression_ratio = NODE_RX_COMPRESSION_RATIO(node);

	bio = node->rx ? rx_bio_source(node->rx) : NULL;
	status->rx_bps = bio ? bio_bps(bio) / 1024.0 : 0.0;

	status->qrp_efficiency =
		(gfloat) node->qrp_matches / (gfloat) MAX(1, node->qrp_queries);
	status->has_qrp = node_ultra_received_qrp(node);

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

    status->shutdown_remain = 
        node->shutdown_delay - (now - node->shutdown_date);
    if (status->shutdown_remain < 0)
        status->shutdown_remain = 0;

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

/*
 * node_remove_nodes_by_handle:
 *
 * Disconnect from the given list of node handles. The list may not contain
 * NULL elements or duplicate elements.
 */
void node_remove_nodes_by_handle(GSList *node_list)
{
    GSList *sl;

    for (sl = node_list; sl != NULL; sl = g_slist_next(sl))
        node_remove_by_handle((gnet_node_t) GPOINTER_TO_UINT(sl->data));
}

/***
 *** Public functions
 ***/

/* 
 * node_ip
 *
 * Returns the ip:port of a node 
 */
/* FIXME: should be called node_ip_to_gchar */
gchar *node_ip(const gnutella_node_t *n)
{
	/* Same as ip_port_to_gchar(), but need another static buffer to be able
	   to use both in same printf() line */

	static gchar a[32];
	struct in_addr ia;
	ia.s_addr = htonl(n->ip);
	gm_snprintf(a, sizeof(a), "%s:%u", inet_ntoa(ia), n->port);
	return a;
}

/*
 * node_connect_back
 *
 * Connect back to node on specified port and emit a "\n\n" sequence.
 *
 * This is called when a "Connect Back" vendor-specific message (BEAR/7v1)
 * is received.  This scheme is used by servents to detect whether they
 * are firewalled.
 */
void node_connect_back(const gnutella_node_t *n, guint16 port)
{
	struct gnutella_socket *s;

	/*
	 * Attempt asynchronous connection.
	 *
	 * When connection is established, node_connected_back() will be called
	 * from the socket layer.
	 */

	s = socket_connect(n->ip, port, SOCK_TYPE_CONNBACK);

	if (s == NULL)
		return;

	/*
	 * There is no specific resource attached to the socket.
	 */
}

/*
 * node_connected_back
 *
 * Callback invoked from the socket layer when we are finally connected.
 */
void node_connected_back(struct gnutella_socket *s)
{
	if (dbg > 4)
		printf("Connected back to %s\n", ip_port_to_gchar(s->ip, s->port));

	(void) bws_write(bws.out, s->file_desc, "\n\n", 2);
	socket_free(s);
}

/*
 * node_proxying_add
 *
 * Record that node wants us to be his push proxy.
 * Returns TRUE if we can act as this node's proxy.
 */
gboolean node_proxying_add(gnutella_node_t *n, gchar *guid)
{
	/*
	 * If we're firewalled, we can't accept.
	 */

	if (is_firewalled) {
		g_warning("denying push-proxyfication for %s <%s>: firewalled",
			node_ip(n), node_vendor(n));
		return FALSE;
	}

	/*
	 * If our IP is not reacheable, deny as well.
	 */

	if (!host_is_valid(listen_ip(), listen_port)) {
		g_warning("denying push-proxyfication for %s <%s>: "
			"current IP %s is invalid",
			node_ip(n), node_vendor(n),
			ip_port_to_gchar(listen_ip(), listen_port));
		return FALSE;
	}

	/*
	 * Did we already get a proxyfication request for the node?
	 * Maybe he did not get our ACK and is retrying?
	 */

	if (n->guid != NULL) {
		gchar old[33];

		g_warning("spurious push-proxyfication request from %s <%s>",
			node_ip(n), node_vendor(n));

		if (guid_eq(guid, n->guid))		/* Already recorded with this GUID */
			return TRUE;

		strncpy(old, guid_hex_str(n->guid), sizeof(old));

		g_warning("new GUID %s for node %s <%s> (was %s)",
			guid_hex_str(guid), node_ip(n), node_vendor(n), old);

		route_proxy_remove(n->guid);
		atom_guid_free(n->guid);
		n->guid = NULL;
	}

	n->guid = atom_guid_get(guid);
	if (route_proxy_add(n->guid, n))
		return TRUE;

	g_warning("push-proxyfication failed for %s <%s>: conflicting GUID %s",
		node_ip(n), node_vendor(n), guid_hex_str(guid));

	atom_guid_free(n->guid);
	n->guid = NULL;

	return FALSE;
}

/*
 * node_proxy_add
 *
 * Add node to our list of push-proxies.
 */
void node_proxy_add(gnutella_node_t *n, guint32 ip, guint16 port)
{
	if (!(n->flags & NODE_F_PROXY)) {
		g_warning("got spurious push-proxy ack from %s <%s>",
			node_ip(n), node_vendor(n));
		return;
	}

	n->flags &= ~NODE_F_PROXY;

	if (!is_firewalled) {
		g_warning("ignoring push-proxy ack from %s <%s>: no longer firewalled",
			node_ip(n), node_vendor(n));
		return;
	}

	/*
	 * Paranoid sanity checks.
	 */

	if (dbg && n->gnet_ip != 0 && (ip != n->gnet_ip || port != n->gnet_port))
		g_warning("push-proxy address %s from %s <%s> does not match "
			"its advertised node address %s:%u",
			ip_port_to_gchar(ip, port), node_ip(n), node_vendor(n),
			ip_to_gchar(n->gnet_ip), n->gnet_port);

	if (ip != n->ip) {
		g_warning("push-proxy address %s from %s <%s> not on same host",
			ip_port_to_gchar(ip, port),
			node_ip(n), node_vendor(n));
		if (n->gnet_ip != 0 && ip == n->gnet_ip)
			g_warning("however address %s matches the advertised node address",
				ip_port_to_gchar(ip, port));
	}

	n->proxy_ip = ip;
	n->proxy_port = port;

	sl_proxies = g_slist_prepend(sl_proxies, n);
}

/*
 * node_http_proxies_add
 *
 * HTTP status callback.
 *
 * If we are still firewalled and have push-proxies, let the downloader
 * know about them via the X-Push-Proxies header.
 */
void node_http_proxies_add(
	gchar *buf, gint *retval, gpointer arg, guint32 flags)
{
	gint rw = 0;
	gint length = *retval;		/* Space available, starting at `buf' */

	if (is_firewalled && sl_proxies != NULL) {
		gpointer fmt = header_fmt_make("X-Push-Proxies", 0);
		GSList *sl;
		gint len;

		for (sl = sl_proxies; sl; sl = g_slist_next(sl)) {
			struct gnutella_node *n = (struct gnutella_node *) sl->data;
			gchar *ipstr;

			g_assert(n->proxy_ip);		/* Must be non-null if it's our proxy */

			ipstr = ip_port_to_gchar(n->proxy_ip, n->proxy_port);
			header_fmt_append(fmt, ipstr, ", ");
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

/*
 * node_push_proxies
 *
 * Returns list of our push-proxies.
 */
GSList *node_push_proxies(void)
{
	return sl_proxies;
}

/*
 * node_all_nodes
 *
 * Returns list of all nodes.
 */
const GSList *node_all_nodes(void)
{
	return (const GSList *) sl_nodes;
}

/* vi: set ts=4: */
