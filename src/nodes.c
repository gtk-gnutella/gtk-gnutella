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

#include <fcntl.h>
#include <sys/types.h>
#include <string.h>
#include <ctype.h>		/* For isspace() */

#include <netinet/in.h>
#include <arpa/inet.h>

#include <assert.h>

#include "sockets.h"
#include "search.h"
#include "share.h"
#include "routing.h"
#include "hosts.h"
#include "nodes.h"
#include "getline.h"
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

#include "settings.h"

#define CONNECT_PONGS_COUNT		10		/* Amoung of pongs to send */
#define BYE_MAX_SIZE			4096	/* Maximum size for the Bye message */
#define NODE_SEND_BUFSIZE		4096	/* TCP send buffer size - 4K */
#define NODE_RECV_BUFSIZE		114688	/* TCP receive buffer size - 112K */

#define NODE_ERRMSG_TIMEOUT		5	/* Time to leave erorr messages displayed */
#define SHUTDOWN_GRACE_DELAY	120	/* Grace period for shutdowning nodes */
#define BYE_GRACE_DELAY			30	/* Bye sent, give time to propagate */
#define MAX_WEIRD_MSG			5	/* Close connection after so much weirds */
#define MAX_TX_RX_RATIO			50	/* Max TX/RX ratio */
#define MIN_TX_FOR_RATIO		500	/* TX packets before enforcing ratio */
#define ALIVE_FREQUENCY			10	/* Seconds between each alive ping */
#define ALIVE_MAX_PENDING		4	/* Max unanswered pings in a row */

GSList *sl_nodes = (GSList *) NULL;

static idtable_t *node_handle_map = NULL;

#define node_find_by_handle(n) \
    (gnutella_node_t *) idtable_get_value(node_handle_map, n)

#define node_request_handle(n) \
    idtable_new_id(node_handle_map, n)

#define node_drop_handle(n) \
    idtable_free_id(node_handle_map, n);


static guint32 nodes_in_list = 0;
static guint32 ponging_nodes = 0;
static guint32 shutdown_nodes = 0;
static guint32 node_id = 0;

const gchar *gnutella_hello = "GNUTELLA CONNECT/";
guint32 gnutella_hello_length = 0;

static const gchar *gnutella_welcome = "GNUTELLA OK\n\n";
static guint32 gnutella_welcome_length = 0;

GHookList node_added_hook_list;
/*
 * For use by node_added_hook_list hooks, since we can't add a parameter
 * at list invoke time.
 */
struct gnutella_node *node_added;

static gint32 connected_node_cnt = 0;
static gint pending_byes = 0;			/* Used when shutdowning servent */
static gboolean in_shutdown = FALSE;
static gboolean no_gnutella_04 = FALSE;

static void node_read_connecting(
	gpointer data, gint source, GdkInputCondition cond);
static void node_disable_read(struct gnutella_node *n);
static void node_data_ind(rxdrv_t *rx, pmsg_t *mb);
static void node_bye_sent(struct gnutella_node *n);
static void call_node_process_handshake_ack(gpointer obj, header_t *header);

/***
 *** Callbacks
 ***/

static listeners_t node_added_listeners   = NULL;
static listeners_t node_removed_listeners = NULL;
static listeners_t node_info_changed_listeners = NULL;

void node_add_node_added_listener(node_added_listener_t l)
{
    LISTENER_ADD(node_added, l);
}

void node_remove_node_added_listener(node_added_listener_t l)
{
    LISTENER_REMOVE(node_added, l);
}

void node_add_node_removed_listener(node_removed_listener_t l)
{
    LISTENER_ADD(node_removed, l);
}

void node_remove_node_removed_listener(node_removed_listener_t l)
{
    LISTENER_REMOVE(node_removed, l);
}

void node_add_node_info_changed_listener(node_info_changed_listener_t l)
{
    LISTENER_ADD(node_info_changed, l);
}

void node_remove_node_info_changed_listener(node_info_changed_listener_t l)
{
    LISTENER_REMOVE(node_info_changed, l);
}

static void node_fire_node_added(
    gnutella_node_t *n, const gchar *type)
{
    n->last_update = time((time_t *)NULL);
    LISTENER_EMIT(node_added, n->node_handle, type, 
        connected_nodes(), node_count());;
}

static void node_fire_node_removed(gnutella_node_t *n)
{
    n->last_update = time((time_t *)NULL);
    LISTENER_EMIT(node_removed, n->node_handle, 
        connected_nodes(), node_count());
}

static void node_fire_node_info_changed
    (gnutella_node_t *n)
{
    LISTENER_EMIT(node_info_changed, n->node_handle);
}

/***
 *** Private functions
 ***/

/* 
 * message_dump:
 *
 * Dumps a gnutella message (debug) 
 */
void message_dump(struct gnutella_node *n)
{
	gint32 size, ip, index, count, total;
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
		READ_GUINT32_BE(n->data + 20, ip);
		READ_GUINT32_LE(n->data + 16, index);
		READ_GUINT32_LE(n->data + 24, port);

		printf(" Index = %d Host = %s Port = %d ", index, ip_to_gchar(ip),
			   port);
	}

	printf("\n");
}

/*
 * node_extract_host
 *
 * Extract IP/port information out of the Query Hit into `ip' and `port'.
 */
void node_extract_host(struct gnutella_node *n, guint32 *ip, guint16 *port)
{
	guint32 hip;
	guint16 hport;
	struct gnutella_search_results *r =
		(struct gnutella_search_results *) n->data;

	/* Read Query Hit info */

	READ_GUINT32_BE(r->host_ip, hip);		/* IP address */
	READ_GUINT16_LE(r->host_port, hport);	/* Port */

	*ip = hip;
	*port = hport;
}

/*
 * node_timer
 *
 * Periodic node heartbeat timer.
 */
void node_timer(time_t now)
{
	GSList *l = sl_nodes;

	while (l) {
		struct gnutella_node *n = (struct gnutella_node *) l->data;
		l = l->next;

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
			} else if (now - n->last_update > node_connected_timeout) {
				node_bye_if_writable(n, 405, "Activity timeout");
			} else if (
				NODE_IN_TX_FLOW_CONTROL(n) &&
				now - n->tx_flowc_date > node_tx_flowc_timeout
			)
				node_bye(n, 405, "Transmit timeout");
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
				n->sent > MIN_TX_FOR_RATIO &&
				(n->received == 0 || n->sent / n->received > MAX_TX_RX_RATIO)
			) {
				node_bye_if_writable(n, 405, "Reception shortage");
				return;
			}

			if (NODE_IS_WRITABLE(n)) {
				if (
					now - n->last_alive_ping > ALIVE_FREQUENCY &&
					!alive_send_ping(n->alive_pings)
				) {
					node_bye(n, 406, "No reply to alive pings");
					return;
				}
			}
		}
	}
}

/*
 * Network init
 */
void network_init(void)
{
	rxbuf_init();

    node_handle_map = idtable_new(32, 32);

	gnutella_welcome_length = strlen(gnutella_welcome);
	gnutella_hello_length = strlen(gnutella_hello);
	g_hook_list_init(&node_added_hook_list, sizeof(GHook));
	node_added_hook_list.seq_id = 1;
	node_added = NULL;
	no_gnutella_04 = time(NULL) >= 1057010400;	/* Tue Jul  1 00:00:00 2003 */
}

/*
 * Nodes
 */

gboolean on_the_net(void)
{
	return connected_node_cnt > 0 ? TRUE : FALSE;
}

gint32 connected_nodes(void)
{
	return connected_node_cnt;
}

gint32 node_count(void)
{
	return nodes_in_list - ponging_nodes - shutdown_nodes;
}

/*
 * get_protocol_version
 *
 * Parse the first handshake line to determine the protocol version.
 * The major and minor are returned in `major' and `minor' respectively.
 */
static void get_protocol_version(guchar *handshake, gint *major, gint *minor)
{
	if (sscanf(&handshake[gnutella_hello_length], "%d.%d", major, minor))
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

	if (node->gnet_ip && (node->flags & NODE_F_VALID))
		host_save_valid(node->gnet_ip, node->gnet_port);

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

	g_free(node);
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
		g_vsnprintf(n->error_str, sizeof(n->error_str), reason, ap);
		n->error_str[sizeof(n->error_str) - 1] = '\0';	/* May be truncated */
		n->remove_msg = n->error_str;
	} else if (n->status != GTA_NODE_SHUTDOWN)	/* Preserve shutdown error */
		n->remove_msg = NULL;

	if (dbg > 3)
		printf("Node %s <%s> removed: %s\n", node_ip(n),
			n->vendor ? n->vendor : "????",
			n->remove_msg ? n->remove_msg : "<no reason>");

	if (dbg > 4) {
		printf("NODE [%d.%d] %s <%s> TX=%d (drop=%d) RX=%d (drop=%d) "
			"Dup=%d Bad=%d W=%d\n",
			n->proto_major, n->proto_minor, node_ip(n),
			n->vendor ? n->vendor : "????",
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

	if (NODE_IS_CONNECTED(n)) {
		if (n->routing_data)
			routing_node_remove(n);
	}

	if (n->status == GTA_NODE_CONNECTED) {		/* Already did if shutdown */
		connected_node_cnt--;
		g_assert(connected_node_cnt >= 0);
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

	n->status = GTA_NODE_REMOVING;
	n->flags &= ~(NODE_F_WRITABLE|NODE_F_READABLE|NODE_F_BYE_SENT);
	n->last_update = time((time_t *) NULL);

	nodes_in_list--;
	if (n->flags & NODE_F_TMP)
		ponging_nodes--;

	if (n->flags & NODE_F_EOF_WAIT)
		pending_byes--;

    node_fire_node_info_changed(n);
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
    gnutella_node_t *node = node_find_by_handle(n);

    g_assert(node != NULL);

    if (NODE_IS_WRITABLE(node)) {
        node_bye(node, 201, "User manual removal");
    } else {
        node_remove(node, NULL);
        node_real_remove(node);
    }
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

	va_start(args, reason);

	if (n->flags & NODE_F_BYE_SENT) {
		g_assert(n->status == GTA_NODE_SHUTDOWN);
		if (dbg > 4) {
			printf("EOF-style error during BYE to %s:\n (BYE) ", node_ip(n));
			vprintf(reason, args);
			printf("\n");
		}
	}

	/*
	 * Call node_remove_v() with supplied message unless we already sent a BYE
 	 * message, in which case we're done since the remote end most probably
	 * read it and closed the connection.
     */

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
	}

	n->status = GTA_NODE_SHUTDOWN;
	n->flags &= ~(NODE_F_WRITABLE|NODE_F_READABLE);
	n->shutdown_date = time((time_t) NULL);
	mq_shutdown(n->outq);
	node_flushq(n);							/* Fast queue flushing */

	shutdown_nodes++;

    node_fire_node_info_changed(n);
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
		g_vsnprintf(n->error_str, sizeof(n->error_str), reason, args);
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

	g_assert(n);

	if (n->status == GTA_NODE_SHUTDOWN) {
		node_recursive_shutdown_v(n, "Bye", reason, ap);
		return;
	}

	/*
	 * A "ponging" node is not expected to be sent traffic besides the initial
	 * connection pongs.  Therefore, don't even try to send the Bye message,
	 * there is no send queue.  Since a ponging node is a 0.4 client, it won't
	 * understand our Bye message anyway.
	 */

	if (NODE_IS_PONGING_ONLY(n)) {
		node_remove_v(n, reason, ap);
		return;
	}

	n->flags |= NODE_F_CLOSING;

	if (reason) {
		g_vsnprintf(n->error_str, sizeof(n->error_str), reason, ap);
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

	len = 2 + g_snprintf(&reason_fmt[2], sizeof(reason_fmt) - 2,
		"%s\r\n"
		"Server: %s\r\n"
		"\r\n",
		n->error_str, version_string);

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
	gmsg_split_sendto_one(n,
		(guchar *) &head, (guchar *) payload, len + sizeof(head));

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

gboolean node_connected(guint32 ip, guint16 port, gboolean incoming)
{
	/*
	 * Is there a node connected with this IP/port?
	 *
	 * The port is tested only when `incoming' is FALSE, i.e. we allow
	 * only one incoming connection per IP, even when there are several
	 * instances, all on different ports.
	 */

	GSList *l;

	if (ip == listen_ip() && port == listen_port)	/* yourself */
		return TRUE;

	for (l = sl_nodes; l; l = l->next) {
		struct gnutella_node *n = (struct gnutella_node *) l->data;
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
 * send_welcome
 *
 * Send the 0.4 welcoming string, and return true if OK.
 * On error, the node is removed if given, or the connection closed.
 */
static gboolean send_welcome(
	struct gnutella_socket *s, struct gnutella_node *n)
{
	gint sent;

	g_assert(s);
	g_assert(n);
	g_assert(n->socket == s);

	if (
		-1 == (sent = bws_write(bws.gout, s->file_desc,
			(gpointer) gnutella_welcome, gnutella_welcome_length))
	) {
		node_remove(n, "Write of 0.4 HELLO acknowledge failed: %s",
			g_strerror(errno));
		return FALSE;
	}
	else if (sent < gnutella_welcome_length) {
		if (dbg)
			g_warning("wrote only %d out of %d bytes of HELLO ack to %s",
				sent, gnutella_welcome_length, ip_to_gchar(s->ip));
		node_remove(n, "Partial write of 0.4 HELLO acknowledge");
		return FALSE;
	}

	return TRUE;
}

/*
 * send_connection_pongs
 *
 * Send CONNECT_PONGS_COUNT pongs to the remote node with proper message ID,
 * then disconnect.
 */
static void send_connection_pongs(struct gnutella_node *n, guchar *muid)
{
	struct gnutella_host hosts[CONNECT_PONGS_COUNT];
	struct gnutella_socket *s = n->socket;
	gint hcount;
	gint pongs = 0;		/* Pongs we sent */

	hcount = host_fill_caught_array(hosts, CONNECT_PONGS_COUNT);
	g_assert(hcount >= 0 && hcount <= CONNECT_PONGS_COUNT);

	if (hcount) {
		gint i;

		sock_cork(s, TRUE);

		for (i = 0; i < hcount; i++) {
			struct gnutella_msg_init_response *pong;
			gint sent;

			pong = build_pong_msg(0, 1, muid, hosts[i].ip, hosts[i].port, 0, 0);

			/*
			 * Send pong, aborting on error or partial write.
			 */

			sent = bws_write(bws.gout, s->file_desc, pong, sizeof(*pong));
			if (sent != sizeof(*pong))
				break;

			n->n_pong_sent++;
			pongs++;
		}
	}

	node_remove(n, "Sent %d connection pong%s", pongs, pongs == 1 ? "" : "s");
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
static gchar *formatted_connection_pongs(gchar *field)
{
	static gchar fmt_line[MAX_LINE_SIZE];
	struct gnutella_host hosts[CONNECT_PONGS_COUNT];
	gint hcount;

	hcount = host_fill_caught_array(hosts, CONNECT_PONGS_COUNT);
	g_assert(hcount >= 0 && hcount <= CONNECT_PONGS_COUNT);

	/*
	 * XXX temporary implementation, until I find the time to write the
	 * XXX generic formatting routines in "header.c" --RAM.
	 */

/* The most a pong can take is "xxx.xxx.xxx.xxx:yyyyy, ", i.e. 23 */
#define PONG_LEN 23
#define LINE_LENGTH	72

	if (hcount) {
		GString *line = g_string_sized_new(PONG_LEN * CONNECT_PONGS_COUNT + 30);
		gint i;
		gint curlen;
		gboolean is_first = TRUE;

		g_string_append(line, field);
		g_string_append(line, ": ");
		curlen = line->len;

		for (i = 0; i < hcount; i++) {
			gchar *ipstr = ip_port_to_gchar(hosts[i].ip, hosts[i].port);
			gint plen = strlen(ipstr);
			
			if (curlen + plen + 2 > LINE_LENGTH) {	/* 2 for ", " */
				g_string_append(line, ",\r\n    ");
				curlen = 4;
			} else if (!is_first) {
				g_string_append(line, ", ");
				curlen += 2;
			}
			is_first = FALSE;
			g_string_append(line, ipstr);
			curlen += plen;
		}
		g_string_append(line, "\r\n");

		strncpy(fmt_line, line->str, sizeof(fmt_line)-1);
		fmt_line[sizeof(fmt_line)-1] = '\0';
		g_string_free(line, TRUE);
	} else
		fmt_line[0] = '\0';		/* Nothing */

#undef PONG_LEN
#undef LINE_LENGTH

	return fmt_line;		/* Pointer to static data */
}

/*
 * send_node_error
 *
 * Send error message to remote end, a node presumably.
 * NB: We don't need a node to call this routine, only a socket.
 */
void send_node_error(struct gnutella_socket *s, int code, guchar *msg, ...)
{
	gchar gnet_response[2048];
	gchar msg_tmp[256];
	gint rw;
	gint sent;
	va_list args;

	va_start(args, msg);
	g_vsnprintf(msg_tmp, sizeof(msg_tmp)-1,  msg, args);
	va_end(args);

	/*
	 * When sending a 503 (Busy) error to a node, send some hosts from
	 * our cache list as well.
	 */

	rw = g_snprintf(gnet_response, sizeof(gnet_response),
		"GNUTELLA/0.6 %d %s\r\n"
		"User-Agent: %s\r\n"
		"Remote-IP: %s\r\n"
		"X-Live-Since: %s\r\n"
		"%s"
		"\r\n",
		code, msg_tmp, version_string, ip_to_gchar(s->ip), start_rfc822_date,
		code == 503 ? formatted_connection_pongs("X-Try") : "");

	g_assert(rw < sizeof(gnet_response));

	if (-1 == (sent = bws_write(bws.gout, s->file_desc, gnet_response, rw))) {
		if (dbg) g_warning("Unable to send back error %d (%s) to node %s: %s",
			code, msg_tmp, ip_to_gchar(s->ip), g_strerror(errno));
	} else if (sent < rw) {
		if (dbg) g_warning("Only sent %d out of %d bytes of error %d (%s) "
			"to node %s: %s",
			sent, rw, code, msg_tmp, ip_to_gchar(s->ip), g_strerror(errno));
	} else if (dbg > 2) {
		printf("----Sent error %d to node %s:\n%.*s----\n",
			code, ip_to_gchar(s->ip), rw, gnet_response);
		fflush(stdout);
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

	/*
	 * Create RX stack, and enable reception of data.
	 */

	if (n->attrs & NODE_A_RX_INFLATE) {
		rxdrv_t *rx;

		if (dbg > 4)
			printf("Receiving compressed data from node %s\n", node_ip(n));

		n->rx = rx_make(n, &rx_inflate_ops, node_data_ind, 0);
		rx = rx_make_under(n->rx, &rx_link_ops, 0);
		g_assert(rx);			/* Cannot fail */
	} else
		n->rx = rx_make(n, &rx_link_ops, node_data_ind, 0);

	rx_enable(n->rx);

	/*
	 * Update state, and mark node as valid.
	 */

	if (n->io_opaque)				/* None for outgoing 0.4 connections */
		io_free(n->io_opaque);
	if (n->socket->getline) {
		getline_free(n->socket->getline);
		n->socket->getline = NULL;
	}

	n->status = GTA_NODE_CONNECTED;
	n->flags |= NODE_F_VALID | NODE_F_READABLE;
	n->last_update = n->connect_date = time((time_t *) NULL);
	connected_node_cnt++;

	if (!NODE_IS_PONGING_ONLY(n)) {
		txdrv_t *tx = tx_make(n, &tx_link_ops, 0);		/* Cannot fail */

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
	}

	/*
	 * Set the socket's send buffer size to a small value, to make sure we
	 * flow control early.  Increase the receive buffer to allow a larger
	 * reception window (assuming an original default 8K buffer size).
	 */

	sock_send_buf(s, NODE_SEND_BUFSIZE, TRUE);
	sock_recv_buf(s, NODE_RECV_BUFSIZE, FALSE);

	/*
	 * If we have an incoming connection, send an "alive" ping.
	 * Otherwise, send a "handshaking" ping.
	 */

	if (n->flags & NODE_F_INCOMING)
		alive_send_ping(n->alive_pings);
	else if (!NODE_IS_PONGING_ONLY(n))
		pcache_outgoing_connection(n);	/* Will send proper handshaking ping */

	/*
	 * Update the GUI.
	 */
    node_fire_node_info_changed(n);

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
	gint c;
	gint cnt;
	gchar *p;
	gboolean warned = FALSE;
	gboolean is_plain_message = TRUE;
	gint message_len = n->size - 2;

	READ_GUINT16_LE(n->data, code);

	/*
	 * The first line can end with <cr><lf>, in which case we have an RFC-822
	 * style header in the packet.  Since the packet is not NUL terminated,
	 * perform the scan manually.
	 */

	for (cnt = 0, p = message; cnt < n->size; cnt++, p++) {
		c = *p;
		if (c == '\r') {
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
			if (dbg) g_warning(
				"Bye message from %s contains control characters", node_ip(n));
		}
	}

	if (!is_plain_message) {
		// XXX parse header
		if (dbg)
			printf("----Bye Message from %s:\n%.*s----\n",
				node_ip(n), (gint) n->size - 2, message);
	}

	node_remove(n, "Got BYE %d %.*s", code, MIN(80, message_len), message);
}

/*
 * downgrade_handshaking
 *
 * For an outgoing *removed* node, retry the outgoing connection using
 * a 0.4 handshaking this time.
 */
static void downgrade_handshaking(struct gnutella_node *n)
{
	struct gnutella_socket *s;

	g_assert(n->status == GTA_NODE_REMOVING);
	g_assert(!(n->flags & NODE_F_INCOMING));
	g_assert(n->socket == NULL);

	if (dbg > 4)
		printf("handshaking with %s failed, retrying at 0.4\n",
			node_ip(n));

	if (n->io_opaque)				/* I/O data */
		io_free(n->io_opaque);

	s = socket_connect(n->ip, n->port, SOCK_TYPE_CONTROL);
	n->flags &= ~NODE_F_RETRY_04;

	if (s) {
		n->status = GTA_NODE_CONNECTING;
		s->resource.node = n;
		n->socket = s;
		n->proto_major = 0;
		n->proto_minor = 4;
		nodes_in_list++;
	} else
		n->remove_msg = "Re-connection failed";

    node_fire_node_info_changed(n);
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
static gint extract_field_pongs(guchar *field)
{
	guchar *tok;
	gint pong = 0;

	for (tok = strtok(field, ",;"); tok; tok = strtok(NULL, ",;")) {
		guint16 port;
		guint32 ip;

		if (gchar_to_ip_port(tok, &ip, &port)) {
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
		pong = extract_field_pongs(field);
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
		pong = extract_field_pongs(field);
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
	gchar *field;

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
	gchar *ack_message = "";
	gboolean ack_ok = FALSE;
	gboolean incoming = (n->flags & NODE_F_INCOMING) ? TRUE : FALSE;
	gchar *what = incoming ? "acknowledgment" : "reply";

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
		n->flags &= ~NODE_F_RETRY_04;	/* If outgoing, don't retry */
		node_remove(n, "HELLO %s error %d (%s)", what, ack_code, ack_message);
		ack_ok = FALSE;
	}
	else if (!incoming && ack_code == 204) {
		n->flags &= ~NODE_F_RETRY_04;	/* Don't retry */
		node_remove(n, "Shielded node");
		ack_ok = FALSE;
	}

	return ack_ok;
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
	gchar *field;

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
		if (strstr(field, "deflate"))		// XXX needs more rigourous parsing
			n->attrs |= NODE_A_RX_INFLATE;	/* We shall decompress input */
	}

	/*
	 * Install new node.
	 */

	g_assert(s->gdk_tag == 0);		/* Removed before callback called */

	node_is_now_connected(n);

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
	gchar gnet_response[1024];
	gint rw;
	gint sent;
	gchar *field;
	gboolean incoming = (n->flags & (NODE_F_INCOMING|NODE_F_TMP));
	gchar *what = incoming ? "HELLO reply" : "HELLO acknowledgment";
	gchar *compressing = "Content-Encoding: deflate\r\n";
	gchar *empty = "";

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
		version_check(field);
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
			if (dbg) g_warning("node %s claims Bye-Packet version %u.%u",
				node_ip(n), major, minor);
		n->attrs |= NODE_A_BYE_PACKET;
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

	/*
	 * Accept-Encoding -- decompression support on the remote side
	 */

	field = header_get(head, "Accept-Encoding");
	if (field) {
		if (strstr(field, "deflate")) {		// XXX needs more rigourous parsing
			n->attrs |= NODE_A_CAN_INFLATE;
			n->attrs |= NODE_A_TX_DEFLATE;	/* We accept! */
		}
	}

	/*
	 * Content-Encoding -- compression accepted by the remote side
	 */

	field = header_get(head, "Content-Encoding");
	if (field) {
		if (strstr(field, "deflate"))		// XXX needs more rigourous parsing
			n->attrs |= NODE_A_RX_INFLATE;	/* We shall decompress input */
	}

	/*
	 * If the connection is flagged as being temporary, it's time to deny
	 * it with a 503 error code.
	 */

	if (n->flags & NODE_F_TMP) {
		g_assert(incoming);
		send_node_error(n->socket, 503,
			"Too many Gnet connections (%d max)", max_connections);
		node_remove(n, "Sent busy indication");
		return;					/* node_remove() has freed s->getline */
	}

	/*
	 * If this is an outgoing connection, we're processing the remote
	 * acknowledgment to our initial handshake.
	 */

	if (!incoming) {
		if (!analyse_status(n, NULL)) {
			/*
			 * If we have the "retry at 0.4" flag set, re-initiate the
			 * connection at the 0.4 level.
			 *
			 * If the flag is not set, we got a valid 0.6 reply, but the
			 * connection was denied.  Check the header nonetheless for
			 * possible pongs.
			 */

			if (n->flags & NODE_F_RETRY_04)
				downgrade_handshaking(n);
			else
				extract_header_pongs(head, n);

			return;				/* node_remove() has freed s->getline */
		}

		/*
		 * Prepare our final acknowledgment.
		 */

		rw = g_snprintf(gnet_response, sizeof(gnet_response),
			"GNUTELLA/0.6 200 OK\r\n"
			"%s"
			"\r\n",
			(n->attrs & NODE_A_TX_DEFLATE) ? compressing : empty);
	 	
		g_assert(rw < sizeof(gnet_response));
	} else {
		/*
		 * Welcome the incoming node.
		 */

		rw = g_snprintf(gnet_response, sizeof(gnet_response),
			"GNUTELLA/0.6 200 OK\r\n"
			"User-Agent: %s\r\n"
			"Pong-Caching: 0.1\r\n"
			"Bye-Packet: 0.1\r\n"
			"Remote-IP: %s\r\n"
			"Accept-Encoding: deflate\r\n"
			"%s"
			"X-Live-Since: %s\r\n"
			"\r\n",
			version_string, ip_to_gchar(n->socket->ip),
			(n->attrs & NODE_A_TX_DEFLATE) ? compressing : empty,
			start_rfc822_date);

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
		printf("----Sent OK %s to %s:\n%.*s----\n",
			what, ip_to_gchar(n->ip), rw, gnet_response);
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

static void maybe_downgrade_handshaking(struct gnutella_node *n)
{
	/*
	 * For an outgoing connection, the remote end probably did not
	 * like our 0.6 handshake and closed the connection.  Retry at 0.4.
	 */

	if ((n->flags & (NODE_F_INCOMING|NODE_F_RETRY_04)) == NODE_F_RETRY_04)
		downgrade_handshaking(n);
}

static void err_input_exception(gpointer obj)
{
	node_remove(NODE(obj), "Failed (Input Exception)");
	maybe_downgrade_handshaking(NODE(obj));
}

static void err_input_buffer_full(gpointer obj)
{
	node_remove(NODE(obj), "Failed (Input buffer full)");
}

static void err_header_read_error(gpointer obj, gint error)
{
	node_remove(NODE(obj), "Failed (Input error: %s)", g_strerror(error));
	maybe_downgrade_handshaking(NODE(obj));
}

static void err_header_read_eof(gpointer obj)
{
	node_remove(NODE(obj), "Failed (EOF)");
	maybe_downgrade_handshaking(NODE(obj));
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

static void call_node_04_connected(gpointer obj, header_t *header)
{
	struct gnutella_node *n = NODE(obj);

	/*
	 * If it is a 0.4 handshake, we're done: we have already welcomed the
	 * node, and came here just to read the trailing "\n".  We're now
	 * ready to process incoming data.
	 */

	g_assert(n->proto_major == 0 && n->proto_minor == 4);
	g_assert(n->flags & (NODE_F_INCOMING|NODE_F_TMP));

	node_is_now_connected(n);
}

#undef NODE

void node_add(guint32 ip, guint16 port)
{
    node_add_socket(NULL, ip, port);
}

void node_add_socket(struct gnutella_socket *s, guint32 ip, guint16 port)
{
	struct gnutella_node *n;
    gchar *connection_type;
	gboolean incoming = FALSE, already_connected = FALSE;
	gint major = 0, minor = 0;
	gboolean ponging_only = FALSE;

	/*
	 * During shutdown, don't accept any new connection.
	 */

	if (in_shutdown) {
		if (s)
			socket_destroy(s);
		return;
	}

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

#ifdef NO_RFC1918
	/*
	 * This needs to be a runtime option.  I could see a need for someone
	 * to want to run gnutella behind a firewall over on a private network.
	 */
	if (is_private_ip(ip)) {
		if (s) {
			if (major > 0 || minor > 4)
				send_node_error(s, 404, "Denied access from private IP");
			socket_destroy(s);
		}
		return;
	}
#endif

	if (s && no_gnutella_04 && major == 0 && minor < 6) {
		socket_destroy(s);
		return;
	}

	/*
	 * Check wether we have already a connection to this node.
	 */

	incoming = s != NULL;
	already_connected = node_connected(ip, port, incoming);

	/*
	 * If we are preferring local hosts, try to remove a non-local host
	 * if the new host is a local one.
	 *		-- Mike Perry's netmask hack, 17/04/2002
	 */

	if (
		use_netmasks &&
		!already_connected &&
		node_count() >= max_connections &&
		host_is_nearby(ip)
	)
		node_remove_non_nearby();

	/* Too many gnutellaNet connections */
    if (node_count() >= max_connections) {
        if (!s)
            return;
        if (whitelist_check(ip)) {
            /* Incoming whitelisted IP, and we're full.
             * Remove another node. */
            node_remove_worst();
        } else if (!already_connected)
            ponging_only = TRUE;	/* Will only send connection pongs */
	}

	/*
	 * Create new node.
	 */

	n = (struct gnutella_node *) g_malloc0(sizeof(struct gnutella_node));
    n->node_handle = node_request_handle(n);
    
    n->id = node_id++;
	n->ip = ip;
	n->port = port;
	n->proto_major = major;
	n->proto_minor = minor;

	n->routing_data = NULL;
	n->flags = NODE_F_HDSK_PING;

	if (s) {					/* This is an incoming control connection */
		n->socket = s;
		s->resource.node = n;
		s->type = SOCK_TYPE_CONTROL;
		n->status = (major > 0 || minor > 4) ?
			GTA_NODE_RECEIVING_HELLO : GTA_NODE_WELCOME_SENT;

		/*
		 * We need to create a temporary connection, flagging it a "ponging"
		 * because we have to read the initial GUID of the handshaking ping
		 * to reply, lest the remote host might drop the pongs.
		 *
		 * For incoming connections, we don't know the listening IP:port
		 * Gnet information.  We mark the nod with the NODE_F_INCOMING
		 * flag so that we send it an "alive" ping to get that information
		 * as soon as we have handshaked.
		 *
		 *		--RAM, 02/02/2001
		 *
		 * For 0.6 connections, flagging as Ponging means we're going to
		 * parse the initial headers, in case there is a Node: header, but
		 * we'll deny the connection.  This allows us to grab the node's
		 * address in our pong cache, given that this nodes actively seeks
		 * a connection, so it may very well accept incoming.
		 *
		 *		--RAM, 18/03/2002
		 */

		if (ponging_only) {
			n->flags |= NODE_F_TMP;
			connection_type = "Ponging";
		} else {
			n->flags |= NODE_F_INCOMING;
			connection_type = "Incoming";
		}
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

	/*
	 * Insert node in lists, before checking `already_connected', since
	 * we need everything installed to call node_remove(): we want to
	 * leave a trail in the GUI.
	 */

	sl_nodes = g_slist_prepend(sl_nodes, n);
	if (n->status != GTA_NODE_REMOVING)
		nodes_in_list++;
	if (n->flags & NODE_F_TMP)
		ponging_nodes++;

	if (already_connected) {
		if (incoming && (n->proto_major > 0 || n->proto_minor > 4))
			send_node_error(s, 404, "Already connected");
		node_remove(n, "Already connected");
		return;
	}

	if (incoming) {				/* Welcome the incoming node */
		if (n->proto_major == 0 && n->proto_minor == 4) {
			/*
			 * Remote node uses the 0.4 protocol, welcome it.
			 */

			if (!send_welcome(s, n))
				return;

			/*
			 * There's no more handshaking to perform, we're ready to
			 * read node data.
			 *
			 * However, our implementation of the first line reading only
			 * read until the first "\n" of the hello.  Therefore, we need
			 * to enter the node_header_read() callback, which will simply
			 * get an empty line, marking the end of headers.
			 *
			 * That's why we're going to execute the code below which sets
			 * the callback as if we were talking to a 0.6+ node.
			 *
			 *		--RAM, 21/12/2001
			 */

			io_get_header(n, &n->io_opaque, bws.gin, s, 0,
				call_node_04_connected, NULL, &node_io_error);
		} else {
			/*
			 * Remote node is using a modern handshaking.  We need to read
			 * its headers then send ours before we can operate any
			 * data transfer.
			 */

			io_get_header(n, &n->io_opaque, bws.gin, s, IO_3_WAY|IO_HEAD_ONLY,
				call_node_process_handshake_header, NULL, &node_io_error);
		}
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
	struct route_dest dest;

	g_return_if_fail(node);
	g_assert(NODE_IS_CONNECTED(node));

	n = node;

	/*
	 * If we're expecting a hanshaking ping, check whether we got one.
	 * An hanshaking ping is normally sent after a connection is made,
	 * and it comes with hops=0.
	 *
	 * We use the handshaking ping to determine, based on the GUID format,
	 * whether the remote node is capable of limiting ping/pongs or not.
	 * Note that for outgoing connections, we'll use the first ping we see
	 * with hops=0 to determine that ability: the GUID[8] byte will be 0xff
	 * and GUID[15] will be >= 1.
	 *
	 * The only time where the handshaking ping is necessary is for "ponging"
	 * incoming connections.  Those were opened solely to send back connection
	 * pongs, but we need the initial ping to know the GUID to use as message
	 * ID when replying...
	 *
	 *		--RAM, 02/01/2002
	 */

	if (n->flags & NODE_F_HDSK_PING) {
		if (n->header.function == GTA_MSG_INIT && n->header.hops == 0) {
			if (n->flags & NODE_F_TMP) {
				send_connection_pongs(n, n->header.muid); /* Will disconnect */
				return;
			}
			if (n->header.muid[8] == 0xff && n->header.muid[15] >= 1)
				n->attrs |= NODE_A_PONG_CACHING;
			n->flags &= ~NODE_F_HDSK_PING;		/* Clear indication */
		} else if (n->flags & NODE_F_TMP) {
			node_remove(n, "Ponging connection did not send handshaking ping");
			return;
		}
	}

	/* First some simple checks */

	switch (n->header.function) {
	case GTA_MSG_INIT:
        if (n->size) {
			drop = TRUE;
			gnet_stats_count_dropped(n, MSG_DROP_BAD_SIZE);
        }
		break;
	case GTA_MSG_INIT_RESPONSE:
        if (n->size != sizeof(struct gnutella_init_response)) {
			drop = TRUE;
            gnet_stats_count_dropped(n, MSG_DROP_BAD_SIZE);
        }
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
        if (n->size != sizeof(struct gnutella_push_request)) {
			drop = TRUE;
            gnet_stats_count_dropped(n, MSG_DROP_BAD_SIZE);
        }
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

	default:					/* Unknown message type - we drop it */
		drop = TRUE;
        gnet_stats_count_dropped(n, MSG_DROP_UNKNOWN_TYPE);
		if (dbg)
			gmsg_log_bad(n, "unknown message type");
		n->n_bad++;
		break;
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
			drop = search_request(n);
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
		return;				/* The node has been removed during processing */

	if (!drop)
		gmsg_sendto_route(n, &dest);	/* Propagate message, if needed */
	else {
		if (dbg > 3)
			gmsg_log_dropped(&n->header, "from %s", node_ip(n));

		n->rx_dropped++;
	}

reset_header:
	n->have_header = FALSE;
	n->pos = 0;
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
		len = g_snprintf(buf, sizeof(buf), "%s%d.%d\n\n", gnutella_hello, 0, 4);
	} else
		len = g_snprintf(buf, sizeof(buf),
			"GNUTELLA CONNECT/%d.%d\r\n"
			"Node: %s\r\n"
			"Remote-IP: %s\r\n"
			"User-Agent: %s\r\n"
			"Pong-Caching: 0.1\r\n"
			"Bye-Packet: 0.1\r\n"
			"Accept-Encoding: deflate\r\n"
			"X-Live-Since: %s\r\n"
			"\r\n",
			n->proto_major, n->proto_minor,
			ip_port_to_gchar(listen_ip(), listen_port),
			ip_to_gchar(n->ip),
			version_string, start_rfc822_date);

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
        node_fire_node_info_changed(n);

		if (dbg > 2) {
			printf("----Sent HELLO request to %s:\n%.*s----\n",
				ip_to_gchar(n->ip), len, buf);
			fflush(stdout);
		}
	}

	/*
	 * Setup I/O callback to read the reply to our HELLO.
	 */

	if (old_handshake) {
		s->gdk_tag = gdk_input_add(s->file_desc,
			GDK_INPUT_READ | GDK_INPUT_EXCEPTION,
			node_read_connecting, (gpointer) n);
	} else {
		/*
		 * Prepare parsing of the expected 0.6 reply.
		 */

		if (!no_gnutella_04)
			n->flags |= NODE_F_RETRY_04;	/* On failure, retry at 0.4 */


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
 * node_tx_enter_flowc
 *
 * Called by message queue when the node enters TX flow control.
 */
void node_tx_enter_flowc(struct gnutella_node *n)
{
	n->tx_flowc_date = time((time_t *) NULL);
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
		guchar *w = (guchar *) &n->header;
		gboolean kick = FALSE;

		r = pmsg_read(mb, w + n->pos,
				 sizeof(struct gnutella_header) - n->pos);

		n->pos += r;
		node_add_rx_read(n, r);

		if (n->pos < sizeof(struct gnutella_header))
			return FALSE;

		/* Okay, we have read the full header */

		n->have_header = TRUE;

		READ_GUINT32_LE(n->header.size, n->size);

        gnet_stats_count_received_header(n);

		/* If the message haven't got any data, we process it now */

		if (!n->size) {
			node_parse(n);
			return TRUE;		/* There may be more to come */
		}

		/* Check wether the message is not too big */

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
				n->data = (guchar *) g_realloc(n->data, maxsize);
			else
				n->data = (guchar *) g_malloc0(maxsize);
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
	gpointer data, gint source, GdkInputCondition cond)
{
	struct gnutella_node *n = (struct gnutella_node *) data;
	struct gnutella_socket *s = n->socket;
	gint r;

	g_assert(n->proto_major == 0 && n->proto_minor == 4);

	if (cond & GDK_INPUT_EXCEPTION) {
		node_remove(n, "Failed (Input Exception)");
		return;
	}

	r = bws_read(bws.gin, s->file_desc, s->buffer + s->pos,
		gnutella_welcome_length - s->pos);

	if (!r) {
		node_remove(n, "Failed (EOF)");
		return;
	} else if (r < 0 && errno == EAGAIN)
		return;
	else if (r < 0) {
		node_remove(n, "Read error in HELLO: %s", g_strerror(errno));
		return;
	}

	s->pos += r;

	if (s->pos < gnutella_welcome_length)
		return;					/* We haven't read enough bytes yet */

#define TRACE_LIMIT		256

	if (strcmp(s->buffer, gnutella_welcome)) {
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
	 * Okay, we are now really connected to a Gnutella node at the 0.4 level.
	 */

	s->pos = 0;

	gdk_input_remove(s->gdk_tag);
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

	if (connected_nodes() > MAX(2, up_connections)) {
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
 * node_bye_all
 *
 * Send a BYE message to all the nodes.
 */
void node_bye_all(void)
{
	GSList *l;

	g_assert(!in_shutdown);		/* Meant to be called once */

	in_shutdown = TRUE;
	host_shutdown();

	for (l = sl_nodes; l; l = l->next) {
		struct gnutella_node *n = l->data;

		/*
		 * Record the NODE_F_EOF_WAIT condition, so that when waiting for
		 * all byes to come through, we can monitor which connections were
		 * closed, and exit immediately we have no pending byes.
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
 * node_remove_non_nearby
 * 
 * Remove a connected node that is not in our local netmasks (used to make
 * room for a local node)
 * 
 * returns true if we found a node to remove
 */
gboolean node_remove_non_nearby(void)
{
	GSList *l;

	/* iterate through nodes list */
	for (l = sl_nodes; l; l = l->next) {
		struct gnutella_node *n = (struct gnutella_node *) l->data;

		if (n->status == GTA_NODE_CONNECTED && !host_is_nearby(n->ip)) {
			node_bye_if_writable(n, 202, "Local node preferred");
			return TRUE;
		}
	}
	
	/* All nodes are local.. Keep them. */
	return FALSE;

}

/*
 * node_remove_worst
 *
 * Removes the node with the worst stats, considering the
 * number of weird, bad and duplicate packets.
 */
gboolean node_remove_worst(void)
{
    GSList *l;
    GSList *m = NULL;
    struct gnutella_node *n;
    int worst = 0, score, num = 0;

    /* Make list of "worst" based on number of "weird" packets. */
    for (l = sl_nodes; l; l = l->next) {
        n = l->data;
        if (n->status != GTA_NODE_CONNECTED)
            continue;
        /* Don't kick whitelisted nodes. */
        if (whitelist_check(n->ip))
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
        /* fixme: pick a random node instead of the first one. */
        n = g_slist_nth_data(m, random_value(num - 1));
        g_slist_free(m);
        node_bye_if_writable(n, 202, "Too many errors");
        return TRUE;
    }

    return FALSE;
}

/*
 * node_qrt_changed
 *
 * Invoked when our Query Routing Table changed.
 */
void node_qrt_changed(void)
{
	// XXX
	g_warning("node_qrt_changed called!");
}

void node_close(void)
{
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
		node_real_remove(n);
	}

	g_slist_free(sl_nodes);

    g_assert(idtable_ids(node_handle_map) == 0);

    idtable_destroy(node_handle_map);
    node_handle_map = NULL;

	rxbuf_close();
}

__inline__ void node_add_sent(gnutella_node_t *n, gint x)
{
    n->last_update = time((time_t *)NULL);
	n->sent += x; 
}

__inline__ void  node_add_txdrop(gnutella_node_t *n, gint x)
{
    n->last_update = time((time_t *)NULL);
	n->tx_dropped += x;
}

__inline__ void node_add_rxdrop(gnutella_node_t *n, gint x)
{
    n->last_update = time((time_t *)NULL);
	n->rx_dropped += x; 
}


__inline__ void node_set_vendor(gnutella_node_t *n, const gchar *vendor)
{
    n->vendor = atom_str_get(vendor);
    node_fire_node_info_changed(n);
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
 * containerstructure of sl_nodes, that would have O(log(n)) (balanced tree)
 * or O(n) (list) runtime.
 */
gnet_node_info_t *node_get_info(const gnet_node_t n)
{
    gnutella_node_t  *node = node_find_by_handle(n); 
    gnet_node_info_t *info = g_new(gnet_node_info_t, 1);

    info->node_handle = n;

    info->proto_major = node->proto_major;
    info->proto_minor = node->proto_minor;
    info->vendor = node->vendor ? g_strdup(node->vendor) : NULL;
    memcpy(info->vcode, node->vcode, 4);

    info->ip   = node->ip;
    info->port = node->port;

    return info;
}

/*
 * node_free_info:
 *
 * Frees the gnet_node_info_t data returned by node_get_info.
 */
void node_free_info(gnet_node_info_t *info)
{
	if (info->vendor)
        g_free(info->vendor);
    g_free(info);
}

void node_get_status(const gnet_node_t n, gnet_node_status_t *status)
{
    gnutella_node_t  *node = node_find_by_handle(n); 
    time_t now = time((time_t *) NULL);

    g_assert(status != NULL);

    status->status     = node->status;

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

    status->rx_given    = node->rx_given;
    status->rx_inflated = node->rx_inflated;
    status->rx_read     = node->rx_read;
    status->rx_compressed = NODE_RX_COMPRESSED(node);
    status->rx_compression_ratio = NODE_RX_COMPRESSION_RATIO(node);

    status->shutdown_remain = 
        node->shutdown_delay - (now - node->shutdown_date);
    if (status->shutdown_remain < 0)
        status->shutdown_remain = 0;

    if (node->error_str != NULL)
        g_snprintf(status->message, sizeof(status->message), "%s", 
            node->error_str);
    else if (node->remove_msg != NULL)
        g_snprintf(status->message, sizeof(status->message), "%s", 
            node->remove_msg);
    else
        status->message[0] = '\0';

}

/*
 * node_remove_nodes_by_handle:
 *
 * Disconnect from the given list of node hanles. The list may not contain
 * NULL elements or duplicate elements.
 */
void node_remove_nodes_by_handle(GSList *node_list)
{
    GSList *l;

    for (l = node_list; l != NULL; l = g_slist_next(l)) {
        gnet_node_t node;

        node = (gnet_node_t) l->data;

        node_remove_by_handle(node);
    }
}

/***
 *** Public functions
 ***/

/* 
 * node_ip:
 *
 * Returns the ip:port of a node 
 */
// FIXME: should be called node_ip_to_gchar
gchar *node_ip(gnutella_node_t *n)
{
	/* Same as ip_port_to_gchar(), but need another static buffer to be able
	   to use both in same printf() line */

	static gchar a[32];
	struct in_addr ia;
	ia.s_addr = g_htonl(n->ip);
	g_snprintf(a, sizeof(a), "%s:%u", inet_ntoa(ia), n->port);
	return a;
}


/* vi: set ts=4: */
