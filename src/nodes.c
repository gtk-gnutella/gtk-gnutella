/*
 * 0.6 handshaking code is Copyright (c) 2001, Raphael Manfredi.
 */

#include "gnutella.h"

#include <fcntl.h>
#include <sys/types.h>
#include <string.h>
#include <ctype.h>		/* For isspace() */

#include <netinet/in.h>
#include <arpa/inet.h>

#include <assert.h>

#include "interface.h"
#include "sockets.h"
#include "search.h"
#include "share.h"
#include "gui.h"
#include "routing.h"
#include "hosts.h"
#include "nodes.h"
#include "misc.h"
#include "getline.h"
#include "header.h"
#include "gmsg.h"
#include "mq.h"
#include "tx.h"
#include "tx_link.h"

#define CONNECT_PONGS_COUNT		10		/* Amoung of pongs to send */
#define BYE_MAX_SIZE			4096	/* Maximum size for the Bye message */
#define NODE_SEND_BUFSIZE		4096	/* TCP send buffer size - 4K */
#define NODE_RECV_BUFSIZE		114688	/* TCP receive buffer size - 112K */

#define NODE_ERRMSG_TIMEOUT		5	/* Time to leave erorr messages displayed */
#define SHUTDOWN_GRACE_DELAY	120	/* Grace period for shutdowning nodes */
#define BYE_GRACE_DELAY			20	/* Bye sent, give time to propagate */

GSList *sl_nodes = (GSList *) NULL;

static guint32 nodes_in_list = 0;
static guint32 ponging_nodes = 0;
static guint32 shutdown_nodes = 0;
static guint32 node_id = 0;

guint32 global_messages = 0;
guint32 global_searches = 0;
guint32 routing_errors = 0;
guint32 dropped_messages = 0;

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

/*
 * This structure is used to encapsulate the various arguments required
 * by the header parsing I/O callback.
 */
struct io_header {
	struct gnutella_node *node;
	header_t *header;
	getline_t *getline;
	void (*process_header)(struct io_header *);
	gint flags;
};

#define IO_EXTRA_DATA_OK	0x00000001	/* OK to have extra data after EOH */
#define IO_STATUS_LINE		0x00000002	/* First line is a status line */

static GHashTable *node_by_fd = 0;

/***
 *** Node timer.
 ***/

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

		if (!stop_host_get) {		/* No timeout if stop_host_get is set */
			if (n->status == GTA_NODE_REMOVING) {
				if (now - n->last_update > NODE_ERRMSG_TIMEOUT) {
					node_real_remove(n);
					continue;
				}
			} else if (NODE_IS_CONNECTING(n)) {
				if (now - n->last_update > node_connecting_timeout)
					node_remove(n, "Timeout");
			} else if (n->status == GTA_NODE_SHUTDOWN) {
				if (now - n->shutdown_date > n->shutdown_delay) {
					gchar *reason = g_strdup(n->error_str);
					node_remove(n, "Shutdown (%s)", reason);
					g_free(reason);
				}
			} else if (now - n->last_update > node_connected_timeout) {
				if (NODE_IS_WRITABLE(n))
					node_bye(n, 405, "Activity timeout");
				else
					node_remove(n, "Activity timeout");
			} else if (
				NODE_IN_TX_FLOW_CONTROL(n) &&
				now - n->tx_flowc_date > node_tx_flowc_timeout
			)
				node_bye(n, 405, "Transmit timeout");
		}

		gui_update_node_display(n, now);
	}
}

/*
 * Network init
 */

void network_init(void)
{
	gnutella_welcome_length = strlen(gnutella_welcome);
	gnutella_hello_length = strlen(gnutella_hello);
	g_hook_list_init(&node_added_hook_list, sizeof(GHook));
	node_added_hook_list.seq_id = 1;
	node_added = NULL;
	node_by_fd = g_hash_table_new(g_direct_hash, g_direct_equal);
}

/*
 * io_free
 *
 * Free the opaque I/O data.
 */
static void io_free(gpointer opaque)
{
	struct io_header *ih = (struct io_header *) opaque;

	g_assert(ih);
	g_assert(ih->node->io_opaque == opaque);

	ih->node->io_opaque = NULL;

	if (ih->header)
		header_free(ih->header);
	if (ih->getline)
		getline_free(ih->getline);

	g_free(ih);
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
void node_real_remove(struct gnutella_node *n)
{
	gint row;

	g_return_if_fail(n);

	row = gtk_clist_find_row_from_data(GTK_CLIST(clist_nodes), (gpointer) n);
	gtk_clist_remove(GTK_CLIST(clist_nodes), row);

	sl_nodes = g_slist_remove(sl_nodes, n);

	/*
	 * Now that the node was removed from the list of known nodes, we
	 * can call host_save_valid() iff the node was marked NODE_F_VALID,
	 * meaning we identified it as a Gnutella server, even though we
	 * might not have been granted a full connection.
	 *		--RAM, 13/01/2002
	 */

	if (n->gnet_ip && (n->flags & NODE_F_VALID))
		host_save_valid(n->gnet_ip, n->gnet_port);

	/*
	 * The io_opaque structure is not freed by node_remove(), so that code
	 * can still peruse the headers after node_remove() has been called.
	 */

	if (n->io_opaque)				/* I/O data */
		io_free(n->io_opaque);

	g_free(n);
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
		printf("NODE [%d.%d] %s <%s> TX=%d (drop=%d) RX=%d (drop=%d) Bad=%d\n",
			n->proto_major, n->proto_minor, node_ip(n),
			n->vendor ? n->vendor : "????",
			n->sent, n->tx_dropped, n->received, n->rx_dropped, n->n_bad);
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

	if (n->membuf) {
		g_assert(n->socket);
		g_free(n->membuf->data);
		g_free(n->membuf);
		n->membuf = NULL;
		g_hash_table_remove(node_by_fd, (gpointer) n->socket->file_desc);
	}
	if (n->socket) {
		g_assert(n->socket->resource.node == n);
		socket_free(n->socket);
		n->socket = NULL;
	}
	/* n->io_opaque will be freed by node_real_remove() */

	if (n->gdk_tag) {
		gdk_input_remove(n->gdk_tag);
		n->gdk_tag = 0;
	}

	if (n->allocated) {
		g_free(n->data);
		n->allocated = 0;
	}
	if (n->outq) {
		mq_free(n->outq);
		n->outq = NULL;
	}
	if (n->vendor) {
		g_free(n->vendor);
		n->vendor = NULL;
	}

	n->status = GTA_NODE_REMOVING;
	n->flags &= ~(NODE_F_WRITABLE|NODE_F_READABLE);
	n->last_update = time((time_t *) NULL);

	nodes_in_list--;
	if (n->flags & NODE_F_TMP)
		ponging_nodes--;

	gui_update_c_gnutellanet();
	gui_update_node(n, TRUE);
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
 * node_remove
 *
 * Terminate connection with remote node, but keep structure around for a
 * while, for displaying purposes, and also to prevent the node from being
 * physically reclaimed within this stack frame.
 *
 * It will be reclaimed on the "idle" stack frame, via node_real_remove().
 */
void node_remove(struct gnutella_node *n, const gchar * reason, ...)
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
static void node_eof(struct gnutella_node *n, const gchar * reason, ...)
{
	va_list args;

	g_assert(n);

	va_start(args, reason);

	/*
	 * Call node_remove_v() with supplied message unless we alrady sent a BYE
 	 * message, in which case we're done since the remote end most probably
	 * read it and closed the connection.
     */

	if (n->flags & NODE_F_BYE_SENT) {
		g_assert(n->status == GTA_NODE_SHUTDOWN);
		if (dbg > 4) {
			printf("EOF-style error during BYE to %s:\n (BYE) ", node_ip(n));
			vprintf(reason, args);
			printf("\n");
		}
		node_remove_v(n, NULL, NULL);		/* Reuse existing reason */
	} else
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

	gui_update_node(n, TRUE);
	gui_update_c_gnutellanet();
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
void node_shutdown(struct gnutella_node *n, const gchar * reason, ...)
{
	va_list args;

	g_assert(n);

	va_start(args, reason);

	if (n->status == GTA_NODE_SHUTDOWN) {
		node_recursive_shutdown_v(n, "Shutdown", reason, args);
		goto end;
	}

	if (reason) {
		g_vsnprintf(n->error_str, sizeof(n->error_str), reason, args);
		n->error_str[sizeof(n->error_str) - 1] = '\0';	/* May be truncated */
		n->remove_msg = n->error_str;
	} else {
		n->remove_msg = NULL;
		n->error_str[0] = '\0';
	}

	node_shutdown_mode(n, SHUTDOWN_GRACE_DELAY);

end:
	va_end(args);
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
void node_bye(struct gnutella_node *n, gint code, const gchar * reason, ...)
{
	struct gnutella_header head;
	gchar reason_fmt[1024];
	struct gnutella_bye *payload = (struct gnutella_bye *) reason_fmt;
	gint len;
	gint sendbuf_len;
	va_list args;

	g_assert(n);

	va_start(args, reason);

	if (n->status == GTA_NODE_SHUTDOWN) {
		node_recursive_shutdown_v(n, "Bye", reason, args);
		goto end;
	}

	/*
	 * A "ponging" node is not expected to be sent traffic besides the initial
	 * connection pongs.  Therefore, don't even try to send the Bye message,
	 * there is no send queue.  Since a ponging node is a 0.4 client, it won't
	 * understand our Bye message anyway.
	 */

	if (NODE_IS_PONGING_ONLY(n)) {
		node_remove_v(n, reason, args);
		goto end;
	}

	if (reason) {
		g_vsnprintf(n->error_str, sizeof(n->error_str), reason, args);
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

	message_set_muid(&head, FALSE);
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
	 * When sending is delayed, node_disableq() will check for the
	 * NODE_F_BYE_SENT condition and change the shutdown delay to a much
	 * shorter period.
	 *
	 * In shutdown mode, we'll also preserve the existing error message for
	 * node_remove().
	 */

	n->flags |= NODE_F_BYE_SENT;

	if (mq_size(n->outq) == 0) {
		if (dbg > 4)
			printf("successfully sent BYE \"%s\" to %s\n",
				n->error_str, node_ip(n));
		sock_tx_shutdown(n->socket);
		node_shutdown_mode(n, BYE_GRACE_DELAY);
	} else {
		if (dbg > 4)
			printf("delayed sending of BYE \"%s\" to %s\n",
				n->error_str, node_ip(n));
		node_shutdown_mode(n, SHUTDOWN_GRACE_DELAY);
	}

end:
	va_end(args);
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

	if (ip == listen_ip())
		return TRUE;
	for (l = sl_nodes; l; l = l->next) {
		struct gnutella_node *n = (struct gnutella_node *) l->data;
		if (n->status == GTA_NODE_REMOVING)
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

static gboolean have_node(struct gnutella_node *node, gboolean incoming)
{
	if (stop_host_get)			/* Useful for testing */
		return FALSE;

	if (node->status == GTA_NODE_REMOVING)
		return FALSE;

	return node_connected(node->ip, node->port, incoming);
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
		-1 == (sent = write(s->file_desc, gnutella_welcome,
			gnutella_welcome_length))
	) {
		node_remove(n, "Write of 0.4 HELLO acknowledge failed: %s",
			g_strerror(errno));
		return FALSE;
	}
	else if (sent < gnutella_welcome_length) {
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

			sent = write(s->file_desc, pong, sizeof(*pong));
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
 * Send error message to node.
 */
static void send_node_error(struct gnutella_socket *s,
	int code, guchar *msg, ...)
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

	if (-1 == (sent = write(s->file_desc, gnet_response, rw)))
		g_warning("Unable to send back error %d (%s) to node %s: %s",
			code, msg_tmp, ip_to_gchar(s->ip), g_strerror(errno));
	else if (sent < rw)
		g_warning("Only sent %d out of %d bytes of error %d (%s) "
			"to node %s: %s",
			sent, rw, code, msg_tmp, ip_to_gchar(s->ip), g_strerror(errno));
	else if (dbg > 4) {
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
	 * Install reading callback.
	 */

	g_assert(s->gdk_tag == 0);

	s->gdk_tag = gdk_input_add(s->file_desc,
		(GdkInputCondition) GDK_INPUT_READ | GDK_INPUT_EXCEPTION,
		node_read, (gpointer) n);

	/* We assume that if this is valid, it is non-zero */
	g_assert(s->gdk_tag);

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
		txdrv_t *tx = tx_make(n, &tx_link_ops, 0);

		n->outq = mq_make(node_sendqueue_size, n, tx);
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
		send_alive_ping(n);
	else if (!NODE_IS_PONGING_ONLY(n))
		pcache_outgoing_connection(n);	/* Will send proper handshaking ping */

	/*
	 * Update the GUI.
	 */

	gui_update_node(n, TRUE);
	gui_update_c_gnutellanet();		/* connected_node_cnt changed */

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
		if (c < ' ' && !warned) {
			warned = TRUE;
			g_warning("Bye message from %s contains control characters",
				node_ip(n));
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
 * membuf_read
 *
 * Reading callback installed by node_process_handshake_ack() to read from
 * a memory buffer.
 */
static gint membuf_read(gint fd, gpointer buf, gint len)
{
	struct gnutella_node *n;
	struct membuf *mbuf;
	gint available;
	gint count;

	if (dbg > 4) printf("membuf_read: fd=%d, len=%d\n", fd, len);

	n = (struct gnutella_node *) g_hash_table_lookup(node_by_fd, (gpointer) fd);
	g_assert(n);
	g_assert(n->read == membuf_read);

	mbuf = n->membuf;
	g_assert(mbuf);

	g_assert(mbuf->rptr <= mbuf->end);

	/*
	 * Sockets are set non-blocking.  If we have nothing to read, don't
	 * return 0, but -1 with errno set appropriately.
	 */

	if (mbuf->rptr == mbuf->end) {
		errno = EAGAIN;
		return -1;
	}

	available = mbuf->end - mbuf->rptr;
	count = len < available ? len : available;
	g_assert(count > 0);

	memmove(buf, mbuf->rptr, count);
	mbuf->rptr += count;

	g_assert(mbuf->rptr <= mbuf->end);

	return count;
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

	s = socket_connect(n->ip, n->port, GTA_TYPE_CONTROL);
	n->flags &= ~NODE_F_RETRY_04;

	if (s) {
		n->status = GTA_NODE_CONNECTING;
		s->resource.node = n;
		n->socket = s;
		n->proto_major = 0;
		n->proto_minor = 4;
		nodes_in_list++;
		gui_update_c_gnutellanet();
	} else
		n->remove_msg = "Re-connection failed";

	gui_update_node_proto(n);
	gui_update_node(n, TRUE);
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
		if (pong == 0)
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
		if (pong == 0)
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
	gint major, minor;
	gchar *ack_message = "";
	gboolean ack_ok = FALSE;
	gboolean incoming = (n->flags & NODE_F_INCOMING) ? TRUE : FALSE;
	gchar *what = incoming ? "acknowledgment" : "reply";

	status = getline_str(s->getline);

	ack_code = parse_status_line(status, "GNUTELLA",
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
		if (incoming || 0 != strcmp(status, "GNUTELLA OK")) {
			g_warning("weird GNUTELLA %s status line from %s",
				what, ip_to_gchar(n->ip));
			dump_hex(stderr, "Status Line", status,
				MIN(getline_length(s->getline), 80));
		} else
			g_warning("node %s gave a 0.4 reply to our 0.6 HELLO, dropping",
				node_ip(n));
	} else {
		ack_ok = TRUE;
		n->flags |= NODE_F_VALID;		/* This is a Gnutella node */
	}

	if (ack_ok && (major != n->proto_major || minor != n->proto_minor)) {
		if (incoming)
			g_warning("node %s handshaked at %d.%d and now acks at %d.%d, "
				"adjusting", ip_to_gchar(n->ip), n->proto_major, n->proto_minor,
				major, minor);
		else
			g_warning("node %s was sent %d.%d HELLO but supports %d.%d only, "
				"adjusting", ip_to_gchar(n->ip), n->proto_major, n->proto_minor,
				major, minor);
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
static void node_process_handshake_ack(struct io_header *ih)
{
	struct gnutella_node *n = ih->node;
	struct gnutella_socket *s = n->socket;
	gboolean ack_ok;

	if (dbg) {
		printf("Got final acknowledgment headers from node %s:\n",
			ip_to_gchar(n->ip));
		dump_hex(stdout, "Status Line", getline_str(s->getline),
			MIN(getline_length(s->getline), 80));
		printf("------ Header Dump:\n");
		header_dump(ih->header, stdout);
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
	 * Install new node.
	 */

	gdk_input_remove(s->gdk_tag);
	s->gdk_tag = 0;

	node_is_now_connected(n);

	/*
	 * The problem we have now is that the remote node is going to
	 * send binary data, normally processed by node_read().  However,
	 * we have probably read some of those data along with the handshaking
	 * reply.  We can't just install the callback and leave, since the
	 * callback won't be invoked until new data comes in.  And the remote
	 * node might have send us a Ping that it expects us to reply to
	 * or it will close the connection.
	 *
	 * To minimize the amount of change to make to the existing code, I
	 * came up with the following trick:
	 *
	 * . The node_read() routine will no longer call read(), the system call,
	 *   directly, but will use n->read() instead.
	 * . While there is data pending in the socket, we install our own reading
	 *   routine so that node_read() gets to read from a memory buffer through
	 *   a reading routine we provide: membuf_read().
	 * . We force all the data to be read now by calling node_read() manually.
	 *
	 * Because read() normally takes a file descriptor, we'll need to be able
	 * to convert that file descriptor back into a node structure.  That's
	 * the purpose of the `node_by_fd' hash.
	 *
	 *		--RAM, 23/12/2001
	 */

	if (s->pos > 0) {
		struct membuf *mbuf;

		/*
		 * Prepare buffer where membuf_read() will read from and copy all
		 * the pending data that we read from the socket.  Then reset the
		 * socket buffer so that it appears to be empty.
		 */

		mbuf = (struct membuf *) g_malloc(sizeof(struct membuf));
		mbuf->data = mbuf->rptr = g_malloc(s->pos);
		mbuf->end = mbuf->data + s->pos;
		n->membuf = mbuf;
		memmove(mbuf->data, s->buffer, s->pos);
		s->pos = 0;

		/*
		 * Install the membuf_read() callback.
		 */

		n->read = membuf_read;
		g_assert(0 == g_hash_table_lookup(node_by_fd, (gpointer) s->file_desc));
		g_hash_table_insert(node_by_fd, (gpointer) s->file_desc, (gpointer) n);

		/*
		 * Call node_read() until all the data have been read from the
		 * memory buffer.
		 *
		 * During processing, it is possible that the node be removed, at which
		 * point `membuf' would be cleaned up.  We therefore escape out of
		 * the loop as soon as we're not connected.
		 */

		g_assert(n->status == GTA_NODE_CONNECTED);

		while (n->status == GTA_NODE_CONNECTED && mbuf->rptr < mbuf->end)
			node_read((gpointer) n, s->file_desc, GDK_INPUT_READ);

		/*
		 * Cleanup the memory buffer data structures, if not already
		 * done by node removal.
		 */

		if (n->membuf) {
			g_hash_table_remove(node_by_fd, (gpointer) s->file_desc);
			g_free(mbuf->data);
			g_free(mbuf);
			n->membuf = 0;
		}
	}

	/*
	 * We can now read via the system call.
	 */

	n->read = (gint (*)(gint, gpointer, gint)) read;
}

/*
 * node_process_handshake_header
 *
 * This routine is called to process a 0.6+ handshake header
 * It is either called to process the reply to our sending a 0.6 handshake
 * (outgoing connections) or to parse the initial 0.6 headers (incoming
 * connections).
 */
static void node_process_handshake_header(struct io_header *ih)
{
	struct gnutella_node *n = ih->node;
	gchar gnet_response[1024];
	gint rw;
	gint sent;
	gchar *field;
	gboolean incoming = (n->flags & (NODE_F_INCOMING|NODE_F_TMP));
	gchar *what = incoming ? "HELLO reply" : "HELLO acknowledgment";

	if (dbg) {
		printf("Got %s handshaking headers from node %s:\n",
			incoming ? "incoming" : "outgoing",
			ip_to_gchar(n->ip));
		if (!incoming)
			dump_hex(stdout, "Status Line", getline_str(n->socket->getline),
				MIN(getline_length(n->socket->getline), 80));
		printf("------ Header Dump:\n");
		header_dump(ih->header, stdout);
		printf("\n------\n");
		fflush(stdout);
	}

	/*
	 * Handle common header fields, non servent-specific.
	 */

	/* User-Agent -- servent vendor identification */

	field = header_get(ih->header, "User-Agent");
	if (field) {
		n->vendor = g_strdup(field);
		gui_update_node_vendor(n);
	}

	/* Pong-Caching -- ping/pong reduction scheme */

	field = header_get(ih->header, "Pong-Caching");
	if (field) {
		guint major, minor;
		sscanf(field, "%u.%u", &major, &minor);
		if (major > 0 || minor > 1)
			g_warning("node %s claims Pong-Caching version %u.%u",
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

		field = header_get(ih->header, "Node");
		if (!field) field = header_get(ih->header, "X-My-Address");
		if (!field) field = header_get(ih->header, "Listen-Ip");

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
				n->flags |= NODE_F_VALID;
			}
		}
	}

	/* Bye-Packet -- support for final notification */

	field = header_get(ih->header, "Bye-Packet");
	if (field) {
		guint major, minor;
		sscanf(field, "%u.%u", &major, &minor);
		if (major > 0 || minor > 1)
			g_warning("node %s claims Bye-Packet version %u.%u",
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

	if (force_local_ip) {
		guint32 ip = extract_my_ip(ih->header);
		if (ip && ip != forced_local_ip)
			config_ip_changed(ip);
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
				extract_header_pongs(ih->header, n);

			return;				/* node_remove() has freed s->getline */
		}

		/*
		 * Prepare our final acknowledgment.
		 */

		rw = g_snprintf(gnet_response, sizeof(gnet_response),
			"GNUTELLA/0.6 200 OK\r\n"
			"\r\n");
		
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
			"X-Live-Since: %s\r\n"
			"\r\n",
			version_string, ip_to_gchar(n->socket->ip), start_rfc822_date);
	}

	/*
	 * We might not be able to transmit the reply atomically.
	 * This should be rare, so we're not handling the case for now.
	 * Simply log it and close the connection.
	 */

	if (-1 == (sent = write(n->socket->file_desc, gnet_response, rw))) {
		int errcode = errno;
		g_warning("Unable to send back %s to node %s: %s",
			what, ip_to_gchar(n->ip), g_strerror(errcode));
		node_remove(n, "Failed (Cannot send %s: %s)",
			what, g_strerror(errcode));
		return;
	} else if (sent < rw) {
		g_warning("Could only send %d out of %d bytes of %s to node %s",
			sent, rw, what, ip_to_gchar(n->ip));
		node_remove(n, "Failed (Cannot send %s atomically)", what);
		return;
	} else if (dbg > 4) {
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

		header_reset(ih->header);
		ih->flags |= IO_EXTRA_DATA_OK | IO_STATUS_LINE;
		ih->process_header = node_process_handshake_ack;
		return;
	} else {
		struct gnutella_socket *s = n->socket;

		gdk_input_remove(s->gdk_tag);
		s->gdk_tag = 0;

		node_is_now_connected(n);
	}
}

/*
 * node_header_parse
 *
 * This routine is called to parse the input buffer, a line at a time,
 * until EOH is reached.
 */
static void node_header_parse(struct io_header *ih)
{
	struct gnutella_node *n = ih->node;
	struct gnutella_socket *s = n->socket;
	getline_t *getline = ih->getline;
	header_t *header = ih->header;
	guint parsed;
	gint error;

	/*
	 * Read header a line at a time.  We have exacly s->pos chars to handle.
	 * NB: we're using a goto label to loop over.
	 */

nextline:
	switch (getline_read(getline, s->buffer, s->pos, &parsed)) {
	case READ_OVERFLOW:
		send_node_error(s, 413, "Header line too long");
		g_warning("node_header_parse: line too long, disconnecting from %s",
			ip_to_gchar(s->ip));
		dump_hex(stderr, "Leading Data", s->buffer, MIN(s->pos, 256));
		node_remove(n, "Failed (Header line too long)");
		return;
		/* NOTREACHED */
	case READ_DONE:
		if (s->pos != parsed)
			memmove(s->buffer, s->buffer + parsed, s->pos - parsed);
		s->pos -= parsed;
		break;
	case READ_MORE:		/* ok, but needs more data */
	default:
		g_assert(parsed == s->pos);
		s->pos = 0;
		return;
	}

	/*
	 * We come here everytime we get a full header line.
	 */

	if (ih->flags & IO_STATUS_LINE) {
		/*
		 * Save status line away in socket's "getline" object, then clear
		 * the fact that we're expecting a status line and continue to get
		 * the following header lines.
		 */

		g_assert(s->getline == 0);
		s->getline = getline_make();

		getline_copy(getline, s->getline);
		getline_reset(getline);
		ih->flags &= ~IO_STATUS_LINE;
		goto nextline;
	}

	error = header_append(header,
		getline_str(getline), getline_length(getline));

	switch (error) {
	case HEAD_OK:
		getline_reset(getline);
		goto nextline;			/* Go process other lines we may have read */
		/* NOTREACHED */
	case HEAD_EOH:				/* We reached the end of the header */
		break;
	case HEAD_TOO_LARGE:
	case HEAD_MANY_LINES:
		send_node_error(s, 413, header_strerror(error));
		/* FALL THROUGH */
	case HEAD_EOH_REACHED:
		g_warning("node_header_parse: %s, disconnecting from %s",
			header_strerror(error),  ip_to_gchar(s->ip));
		fprintf(stderr, "------ Header Dump:\n");
		header_dump(header, stderr);
		fprintf(stderr, "------\n");
		dump_hex(stderr, "Header Line", getline_str(getline),
			MIN(getline_length(getline), 128));
		node_remove(n, "Failed (%s)", header_strerror(error));
		return;
		/* NOTREACHED */
	default:					/* Error, but try to continue */
		g_warning("node_header_parse: %s, from %s",
			header_strerror(error), ip_to_gchar(s->ip));
		dump_hex(stderr, "Header Line",
			getline_str(getline), getline_length(getline));
		getline_reset(getline);
		goto nextline;			/* Go process other lines we may have read */
	}

	/*
	 * We reached the end of headers.
	 *
	 * Make sure there's no more data.  Whatever handshaking protocol is used,
	 * we have to answer before the other end can send more data.
	 */

	if (s->pos && !(ih->flags & IO_EXTRA_DATA_OK)) {
		g_warning("%s node %s sent extra bytes after HELLO",
			(n->flags & (NODE_F_INCOMING|NODE_F_TMP)) ?
				"incoming" : "outgoing",
			ip_to_gchar(s->ip));
		dump_hex(stderr, "Extra HELLO Data", s->buffer, MIN(s->pos, 256));
		fprintf(stderr, "------ HELLO Header Dump:\n");
		header_dump(ih->header, stderr);
		fprintf(stderr, "\n------\n");
		node_remove(n, "Failed (Extra HELLO data)");
		return;
	}

	/*
	 * If it is a 0.4 handshake, we're done: we have already welcomed the
	 * node, and came here just to read the trailing "\n".  We're now
	 * ready to process incoming data.
	 */

	if (n->proto_major == 0 && n->proto_minor == 4) {
		g_assert(n->flags & (NODE_F_INCOMING|NODE_F_TMP));
		gdk_input_remove(s->gdk_tag);
		s->gdk_tag = 0;
		node_is_now_connected(n);
		return;
	}

	/*
	 * We're dealing with a 0.6+ handshake.
	 *
	 * If this is our first call, we'll go to node_process_handshake_header().
	 *
	 * For incoming connections:
	 * . We need to welcome the node, and it will reply after our welcome,
	 *   so we don't free the io_header structure and the getline/header
	 *   objects yet.
	 *
	 * . If this is our second call, we'll go to node_process_handshake_ack().
	 *   This will terminate the handshaking process, and cleanup the header
	 *   parsing structure, then install the data handling callback.
	 *
	 * For outgoing connections: we simply need to parse their reply and
	 * accept/deny the connection.
	 */

	getline_reset(ih->getline);		/* Ensure it's empty, ready for reuse */
	ih->process_header(ih);
}

/*
 * node_header_read
 *
 * This routine is installed as an input callback to read the hanshaking
 * headers.
 */
static void node_header_read(
	gpointer data, gint source, GdkInputCondition cond)
{
	struct io_header *ih = (struct io_header *) data;
	struct gnutella_node *n = ih->node;
	struct gnutella_socket *s = n->socket;
	guint count;
	gint r;

	if (cond & GDK_INPUT_EXCEPTION) {
		node_remove(n, "Failed (Input Exception)");
		goto final_cleanup;
	}

	count = sizeof(s->buffer) - s->pos - 1;		/* -1 to allow trailing NUL */
	if (count <= 0) {
		g_warning("node_header_read: incoming buffer full, "
			"disconnecting from %s", ip_to_gchar(s->ip));
		dump_hex(stderr, "Leading Data", s->buffer, MIN(s->pos, 256));
		node_remove(n, "Failed (Input buffer full)");
		goto final_cleanup;
	}

	r = read(s->file_desc, s->buffer + s->pos, count);
	if (r == 0) {
		node_remove(n, "Failed (EOF)");
		goto final_cleanup;
	} else if (r < 0 && errno == EAGAIN)
		return;
	else if (r < 0) {
		node_remove(n, "Failed (Input error: %s)", g_strerror(errno));
		goto final_cleanup;
	}

	/*
	 * During the header reading phase, we don't update "n->last_update"
	 * on purpose.  The timeout is defined for the whole connection phase,
	 * i.e. until we read the end of the headers.
	 */

	s->pos += r;

	node_header_parse(ih);
	return;

final_cleanup:

	/*
	 * For an outgoing connection, the remote end probably did not
	 * like our 0.6 handshake and closed the connection.  Retry at 0.4.
	 */

	if ((n->flags & (NODE_F_INCOMING|NODE_F_RETRY_04)) == NODE_F_RETRY_04)
		downgrade_handshaking(n);
}

void node_add(struct gnutella_socket *s, guint32 ip, guint16 port)
{
	struct gnutella_node *n;
	gchar *titles[5];
	gint row;
	gboolean incoming = FALSE, already_connected = FALSE;
	gint major = 0, minor = 0;
	gboolean ponging_only = FALSE;
	gchar proto_tmp[16];

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

	/*
	 * If we are preferring local hosts, try to remove a non-local host
	 * if the new host is a local one.
	 *		-- Mike Perry's netmask hack, 17/04/2002
	 */

	if (
		use_netmasks &&
		node_count() >= max_connections &&
		host_is_nearby(ip)
	)
		node_remove_non_nearby();

#define NO_RFC1918				/* XXX */

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

	/* Too many gnutellaNet connections */
	if (node_count() >= max_connections) {
		if (!s)
			return;
		ponging_only = TRUE;	/* Will only send connection pongs */
	}

	n = (struct gnutella_node *) g_malloc0(sizeof(struct gnutella_node));

	n->id = node_id++;
	n->ip = ip;
	n->port = port;
	n->proto_major = major;
	n->proto_minor = minor;

	n->routing_data = NULL;
	n->read = (gint (*)(gint, gpointer, gint)) read;
	n->flags = NODE_F_HDSK_PING;

	if (s) {					/* This is an incoming control connection */
		n->socket = s;
		s->resource.node = n;
		s->type = GTA_TYPE_CONTROL;
		n->status = (major > 0 || minor > 4) ?
			GTA_NODE_RECEIVING_HELLO : GTA_NODE_WELCOME_SENT;

		incoming = TRUE;

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
			titles[1] = (gchar *) "Ponging";
		} else {
			n->flags |= NODE_F_INCOMING;
			titles[1] = (gchar *) "Incoming";
		}
	} else {
		/* We have to create an outgoing control connection for the node */

		s = socket_connect(ip, port, GTA_TYPE_CONTROL);

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
		}

		titles[1] = (gchar *) "Outgoing";
	}

	g_snprintf(proto_tmp, sizeof(proto_tmp), "%d.%d",
		n->proto_major, n->proto_minor);

	titles[0] = node_ip(n);
	titles[2] = (gchar *) "";
	titles[3] = proto_tmp;
	titles[4] = (gchar *) "";

	row = gtk_clist_append(GTK_CLIST(clist_nodes), titles);
	gtk_clist_set_row_data(GTK_CLIST(clist_nodes), row, (gpointer) n);

	/*
	 * Check wether we have already a connection to this node before
	 * adding the node to the list
	 */

	already_connected = have_node(n, incoming);

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
		struct io_header *ih;

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
		}

		/*
		 * Remote node is using a modern handshaking.  We need to read
		 * its headers then send ours before we can operate any
		 * data transfer.
		 */

		ih = (struct io_header *) g_malloc(sizeof(struct io_header));
		ih->node = n;
		ih->header = header_make();
		ih->getline = getline_make();
		ih->process_header = node_process_handshake_header;
		ih->flags = 0;
		n->io_opaque = (gpointer) ih;

		g_assert(s->gdk_tag == 0);

		s->gdk_tag = gdk_input_add(s->file_desc,
			(GdkInputCondition) GDK_INPUT_READ | GDK_INPUT_EXCEPTION,
			node_header_read, (gpointer) ih);

		/*
		 * There may be pending input in the socket buffer, so go handle
		 * it immediately.
		 */

		node_header_parse(ih);
	}

	gui_update_node(n, TRUE);
	gui_update_c_gnutellanet();
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
		if (n->size)
			drop = TRUE;
		break;
	case GTA_MSG_INIT_RESPONSE:
		if (n->size != sizeof(struct gnutella_init_response))
			drop = TRUE;
		break;
	case GTA_MSG_BYE:
		if (n->header.hops != 0 || n->header.ttl != 1) {
			n->n_bad++;
			drop = TRUE;
		}
		break;
	case GTA_MSG_PUSH_REQUEST:
		if (n->size != sizeof(struct gnutella_push_request))
			drop = TRUE;
		break;
	case GTA_MSG_SEARCH:
		if (n->size <= 3)	/* At least speed(2) + NUL(1) */
			drop = TRUE;
		else if (n->size > search_queries_forward_size)
			drop = TRUE;

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
		if (n->size > search_answers_forward_size)
			drop = TRUE;
		break;

	default:					/* Unknown message type - we drop it */
		drop = TRUE;
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
			dropped_messages++;
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

			search_extract_host(n, &ip, &port);
			host_add_semi_pong(ip, port);
		}
		break;
	default:
		break;
	}

	/* Compute route (destination) then handle the message if required */

	if (route_message(&n, &dest)) {		/* We have to handle the message */
		switch (n->header.function) {
		case GTA_MSG_PUSH_REQUEST:
			handle_push_request(n);
			break;
		case GTA_MSG_SEARCH:
			search_request(n);
			break;
		case GTA_MSG_SEARCH_RESULTS:
			search_results(n);
			break;
		default:
			message_dump(n);
			break;
		}
	}

	if (!n)
		return;				/* The node has been removed during processing */

	gmsg_sendto_route(n, &dest);		/* Propagate message, if needed */

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
			"X-Live-Since: %s\r\n"
			"\r\n",
			n->proto_major, n->proto_minor,
			ip_port_to_gchar(listen_ip(), listen_port),
			ip_to_gchar(n->ip),
			version_string, start_rfc822_date);

	/*
	 * We don't retry a connection from 0.6 to 0.4 if we fail to write the
	 * initial HELLO.
	 */

	if (-1 == (sent = write(n->socket->file_desc, buf, len))) {
		node_remove(n, "Write error during HELLO: %s", g_strerror(errno));
		return;
	} else if (sent < len) {
		node_remove(n, "Partial write during HELLO");
		return;
	} else {
		n->status = GTA_NODE_HELLO_SENT;
		gui_update_node(n, TRUE);

		if (dbg > 4) {
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
		struct io_header *ih;

		/*
		 * Prepare parsing of the expected 0.6 reply.
		 */

		n->flags |= NODE_F_RETRY_04;		/* On failure, retry at 0.4 */

		ih = (struct io_header *) g_malloc(sizeof(struct io_header));
		ih->node = n;
		ih->header = header_make();
		ih->getline = getline_make();
		ih->process_header = node_process_handshake_header;
		ih->flags = IO_STATUS_LINE;
		n->io_opaque = (gpointer) ih;

		g_assert(s->gdk_tag == 0);

		s->gdk_tag = gdk_input_add(s->file_desc,
			(GdkInputCondition) GDK_INPUT_READ | GDK_INPUT_EXCEPTION,
			node_header_read, (gpointer) ih);
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
	struct gnutella_socket *s = n->socket;

	g_assert(s);
	g_assert(s->gdk_tag);

	n->flags |= NODE_F_NOREAD;
	gdk_input_remove(s->gdk_tag);		/* Don't read anymore */
	s->gdk_tag = 0;
}

/*
 * node_bye_sent
 *
 * Called when the Bye message has been successfully sent.
 */
void node_bye_sent(struct gnutella_node *n)
{
	if (dbg > 4)
		printf("finally sent BYE \"%s\" to %s\n", n->error_str, node_ip(n));

	/*
	 * Shutdown the node.
	 */

	sock_tx_shutdown(n->socket);
	node_shutdown_mode(n, BYE_GRACE_DELAY);
}

/*
 * node_read
 *
 * I/O callback used to read binary Gnet traffic from a node.
 */
void node_read(gpointer data, gint source, GdkInputCondition cond)
{
	gint r;
	struct gnutella_node *n = (struct gnutella_node *) data;

	g_return_if_fail(n);
	g_assert(NODE_IS_CONNECTED(n));

	if (cond & GDK_INPUT_EXCEPTION) {
		node_eof(n, "Failed (Input Exception)");
		return;
	}

	/*
	 * It is possible to be called whilst NODE_F_NOREAD has been set, when
	 * we're reading from a memory buffer.
	 */

	if (n->flags & NODE_F_NOREAD) {
		node_eof(n, "Reading disabled");
		return;
	}

	if (!n->have_header) {		/* We haven't got the header yet */
		guchar *w = (guchar *) & n->header;
		gboolean kick = FALSE;

		r = n->read(n->socket->file_desc, w + n->pos,
				 sizeof(struct gnutella_header) - n->pos);

		if (!r) {
			if (n->n_ping_sent <= 2 && n->n_pong_received)
				node_eof(n, "Got %d connection pong%s",
					n->n_pong_received, n->n_pong_received == 1 ? "" : "s");
			else
				node_eof(n, "Failed (EOF)");
			return;
		} else if (r < 0 && errno == EAGAIN)
			return;
		else if (r < 0) {
			node_eof(n, "Read error: %s", g_strerror(errno));
			return;
		}

		n->pos += r;

		if (n->pos < sizeof(struct gnutella_header))
			return;

		/* Okay, we have read the full header */

		n->have_header = TRUE;

		n->received++;
		global_messages++;

		gui_update_node(n, FALSE);

		READ_GUINT32_LE(n->header.size, n->size);

		/* If the message haven't got any data, we process it now */

		if (!n->size) {
			node_parse(n);
			return;
		}

		/* Check wether the message is not too big */

		switch (n->header.function) {
		case GTA_MSG_BYE:
			if (n->size > BYE_MAX_SIZE) {
				node_remove(n, "Kicked: %s message too big (%d bytes)",
							gmsg_name(n->header.function), n->size);
				return;
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

			node_disable_read(n);
			node_bye(n, 400, "Too large %s message (%u bytes)",
				gmsg_name(n->header.function), n->size);
			return;
		}

		/* Okay */

		n->pos = 0;

		if (n->size > n->allocated) {
			/*
			 * We need to grow the allocated data buffer
			 * Since could change dynamically one day, so compute it.
			 */

			guint32 maxsize = config_max_msg_size();

			if (maxsize < n->size) {
				g_warning("got %u byte %s message, should have kicked node\n",
					n->size, gmsg_name(n->header.function));
				node_disable_read(n);
				node_bye(n, 400, "Too large %s message (%d bytes)",
					gmsg_name(n->header.function), n->size);
				return;
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

	r = n->read(n->socket->file_desc, n->data + n->pos, n->size - n->pos);

	if (r == 0) {
		node_eof(n, "Failed (EOF in %s message data)",
			gmsg_name(n->header.function));
		return;
	} else if (r < 0 && errno == EAGAIN)
		return;
	else if (r < 0) {
		node_eof(n, "Read error in %s message: %s",
			gmsg_name(n->header.function), g_strerror(errno));
		return;
	}

	n->pos += r;

	g_assert(n->pos <= n->size);

	if (n->pos == n->size)
		node_parse(n);
}

/*
 * node_read_connecting
 *
 * Reads an outgoing connecting CONTROL node handshaking at the 0.4 level.
 */
void node_read_connecting(gpointer data, gint source, GdkInputCondition cond)
{
	struct gnutella_node *n = (struct gnutella_node *) data;
	struct gnutella_socket *s = n->socket;
	gint r;

	g_assert(n->proto_major == 0 && n->proto_minor == 4);

	if (cond & GDK_INPUT_EXCEPTION) {
		node_remove(n, "Failed (Input Exception)");
		return;
	}

	r = read(s->file_desc, s->buffer + s->pos,
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

	if (strcmp(s->buffer, gnutella_welcome)) {
		/*
		 * The node does not seem to be a valid gnutella server !?
		 *
		 * Try to read a little more data, so that we log more than just
		 * the length of the expected welcome.
		 */

		r = read(s->file_desc, s->buffer + s->pos, sizeof(s->buffer) - s->pos);
		if (r > 0)
			s->pos += r;

		g_warning("node %s replied to our 0.4 HELLO strangely", node_ip(n));
		dump_hex(stderr, "HELLO Reply", s->buffer, MIN(s->pos, 256));
		node_remove(n, "Failed (Not a Gnutella server?)");
		return;
	}

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

	dropped_messages++;

	if (connected_nodes() > MAX(2, up_connections)) {
		node_bye(n, 408, "%s %s message with TTL=0",
			n->header.hops ? "Relayed" : "Sent",
			gmsg_name(n->header.function));
		return n->status == GTA_NODE_REMOVING;
	}

	n->rx_dropped++;
	n->n_bad++;

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

	for (l = sl_nodes; l; l = l->next) {
		struct gnutella_node *n = l->data;
		if (NODE_IS_WRITABLE(n))
			node_bye(n, 200, "Servent shutdown");
	}
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
		struct gnutella_node *n = sl_nodes->data;

		if (NODE_IS_CONNECTED(n) && !host_is_nearby(n->ip)) {
			node_remove(n, "Non Local");
			return TRUE;
		}
	}
	
	/* All nodes are local.. Keep them. */
	return FALSE;

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
		if (n->allocated)
			g_free(n->data);
		if (n->vendor)
			g_free(n->vendor);
		node_real_remove(n);
	}

	g_slist_free(sl_nodes);
	g_hash_table_destroy(node_by_fd);
}

/* vi: set ts=4: */
