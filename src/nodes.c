/*
 * 0.6 handshaking code is Copyright (c) 2001, Raphael Manfredi.
 */

#include "gnutella.h"

#include <fcntl.h>
#include <sys/types.h>
#include <string.h>

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

#define CONNECT_PONGS_COUNT		10		/* Amoung of pongs to send */

GSList *sl_nodes = (GSList *) NULL;

static guint32 nodes_in_list = 0;
static guint32 ponging_nodes = 0;
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
static gchar *msg_name[256];

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

/*
 * Network init
 */

void network_init(void)
{
	int i;

	gnutella_welcome_length = strlen(gnutella_welcome);
	gnutella_hello_length = strlen(gnutella_hello);
	g_hook_list_init(&node_added_hook_list, sizeof(GHook));
	node_added_hook_list.seq_id = 1;
	node_added = NULL;

	for (i = 0; i < 256; i++)
		msg_name[i] = "unknown";
	msg_name[GTA_MSG_INIT] = "ping";
	msg_name[GTA_MSG_INIT_RESPONSE] = "pong";
	msg_name[GTA_MSG_SEARCH] = "query";
	msg_name[GTA_MSG_SEARCH_RESULTS] = "query hit";

	node_by_fd = g_hash_table_new(g_direct_hash, g_direct_equal);
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
	return nodes_in_list - ponging_nodes;
}

static guint32 max_msg_size(void)
{
	/*
	 * Maximum message payload size we are configured to handle.
	 * Today, they are fixed at config time, but they will be set via
	 * GUI tomorrow, so the max size is not fixed in time.
	 *				--RAM, 15/09/2001
	 */

	guint32 maxsize;

	maxsize = MAX(search_queries_kick_size, search_answers_kick_size);
	maxsize = MAX(maxsize, other_messages_kick_size);

	return maxsize;
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

void node_real_remove(struct gnutella_node *n)
{
	gint row;

	g_return_if_fail(n);

	row = gtk_clist_find_row_from_data(GTK_CLIST(clist_nodes), (gpointer) n);
	gtk_clist_remove(GTK_CLIST(clist_nodes), row);

	sl_nodes = g_slist_remove(sl_nodes, n);

	g_free(n);
}

void node_remove(struct gnutella_node *n, const gchar * reason, ...)
{
	gboolean on;

	g_return_if_fail(n);

	if (n->status == GTA_NODE_REMOVING)
		return;

	if (n->status == GTA_NODE_CONNECTED) {
		routing_node_remove(n);
		connected_node_cnt--;
		g_assert(connected_node_cnt >= 0);
	}

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

	if (n->gdk_tag)
		gdk_input_remove(n->gdk_tag);
	if (n->allocated) {
		g_free(n->data);
		n->allocated = 0;
	}
	if (n->sendq) {
		g_free(n->sendq);
		n->sendq = NULL;
	}

	n->status = GTA_NODE_REMOVING;
	n->last_update = time((time_t *) NULL);

	if (reason) {
		va_list args;
		va_start(args, reason);
		g_vsnprintf(n->error_str, sizeof(n->error_str), reason, args);
		n->error_str[sizeof(n->error_str) - 1] = '\0';	/* May be truncated */
		va_end(args);
		n->remove_msg = n->error_str;
	} else
		n->remove_msg = NULL;

	if (dbg > 3)
		printf("Node %s removed: %s\n", node_ip(n),
			n->remove_msg ? n->remove_msg : "<no reason>");

	if (dbg > 4) {
		printf("NODE [%d.%d] %s TX=%d RX=%d Drop=%d Bad=%d\n",
			n->proto_major, n->proto_minor, node_ip(n),
			n->sent, n->received, n->dropped, n->n_bad);
		printf("NODE \"%s%s\" %s PING (drop=%d acpt=%d spec=%d sent=%d) "
			"PONG (rcvd=%d sent=%d)\n",
			(n->flags & NODE_F_PING_LIMIT) ? "new" : "old",
			(n->flags & NODE_F_PING_ALIEN) ? "-alien" : "",
			node_ip(n),
			n->n_ping_throttle, n->n_ping_accepted, n->n_ping_special,
			n->n_ping_sent, n->n_pong_received, n->n_pong_sent);
	}

	nodes_in_list--;
	if (n->flags & NODE_F_TMP)
		ponging_nodes--;

	gui_update_c_gnutellanet();
	gui_update_node(n, TRUE);

	on = on_the_net();

	gtk_widget_set_sensitive(button_host_catcher_get_more, on);

	if (!on)
		gtk_widget_set_sensitive(button_search, FALSE);
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

	if (ip == local_ip || (force_local_ip && ip == forced_local_ip))
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
 * send_node_error
 *
 * Send error message to node.
 */
static void send_node_error(struct gnutella_socket *s, int code, guchar *msg)
{
	gchar gnet_response[1024];
	gint rw;
	gint sent;

	// XXX if 503, add X-Try:

	rw = g_snprintf(gnet_response, sizeof(gnet_response),
		"GNUTELLA/0.6 %d %s\r\n"
		"User-Agent: %s\r\n\r\n",
		code, msg, version_string);

	if (-1 == (sent = write(s->file_desc, gnet_response, rw)))
		g_warning("Unable to send back error %d (%s) to node %s: %s",
			code, msg, ip_to_gchar(s->ip), g_strerror(errno));
	else if (sent < rw)
		g_warning("Only sent %d out of %d bytes of error %d (%s) "
			"to node %s: %s",
			sent, rw, code, msg, ip_to_gchar(s->ip), g_strerror(errno));
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
	 * Update state.
	 */

	n->status = GTA_NODE_CONNECTED;
	n->last_update = n->connect_date = time((time_t *) NULL);
	connected_node_cnt++;

	/*
	 * If we have an incoming connection, send an "alive" ping.
	 */

	if (n->flags & NODE_F_INCOMING)
		send_alive_ping(n);

	/*
	 * Update the GUI.
	 */

	gui_update_node(n, TRUE);
	gui_update_c_gnutellanet();		/* connected_node_cnt changed */
	gtk_widget_set_sensitive(button_host_catcher_get_more, TRUE);

	node_added = n;
	g_hook_list_invoke(&node_added_hook_list, TRUE);
	node_added = NULL;

	/*
	 * TODO Update the search button if there is the search entry
	 * is not empty.
	 */
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
 * node_process_handshake_ack
 *
 * This routine is called to process the whole 0.6+ handshake header
 * acknowledgement we get back after welcoming a node.
 */
static void node_process_handshake_ack(struct io_header *ih)
{
	struct gnutella_node *n = ih->node;
	struct gnutella_socket *s = n->socket;
	gchar *status;
	gint ack_code;
	gint major, minor;
	gchar *ack_message = "";
	gboolean ack_ok = FALSE;

	status = getline_str(s->getline);

	if (dbg) {
		printf("Got incoming acknowledgment headers from node %s:\n",
			ip_to_gchar(n->ip));
		dump_hex(stdout, "Status Line", status,
			MIN(getline_length(s->getline), 80));
		header_dump(ih->header, stdout);
		fflush(stdout);
	}

	ack_code = parse_status_line(status, "GNUTELLA",
		&ack_message, &major, &minor);

	if (dbg) {
		printf("ACK: code=%d, message=\"%s\", proto=%d.%d\n", ack_code,
			ack_message, major, minor);
		fflush(stdout);
	}
	if (ack_code == -1) {
		g_warning("weird GNUTELLA acknowledgment status line from %s",
			ip_to_gchar(n->ip));
		dump_hex(stderr, "Status Line", status,
			MIN(getline_length(s->getline), 80));
	} else
		ack_ok = TRUE;

	if (ack_ok && (major != n->proto_major || minor != n->proto_minor)) {
		g_warning("node %s handshaked at %d.%d and now acks at %d.%d, "
			"adjusting", ip_to_gchar(n->ip), n->proto_major, n->proto_minor,
			major, minor);
		n->proto_major = major;
		n->proto_minor = minor;
	}

	/*
	 * Is the connection OK?
	 */

	if (!ack_ok)
		node_remove(n, "Weird HELLO acknowlegment");
	else if (ack_code < 200 || ack_code >= 300) {
		node_remove(n, "HELLO error %d (%s)", ack_code, ack_message);
		ack_ok = FALSE;
	}

	/*
	 * We can now dispose of the io_header structure.
	 */

	header_free(ih->header);
	getline_free(ih->getline);
	g_free(ih);

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
		 */

		while (mbuf->rptr < mbuf->end)
			node_read((gpointer) n, s->file_desc, GDK_INPUT_READ);

		/*
		 * Cleanup the memory buffer data structures.
		 */

		g_hash_table_remove(node_by_fd, (gpointer) s->file_desc);
		g_free(mbuf->data);
		g_free(mbuf);
		n->membuf = 0;
	}

	/*
	 * We can now read via the system call.
	 */

	n->read = (gint (*)(gint, gpointer, gint)) read;
}

/*
 * node_process_handshake_header
 *
 * This routine is called to process the whole 0.6+ handshake header
 * and to either accept (welcoming the remote node) or deny the connection.
 */
static void node_process_handshake_header(struct io_header *ih)
{
	struct gnutella_node *n = ih->node;
	gchar gnet_response[1024];
	gint rw;
	gint sent;
	gchar *field;

	if (dbg) {
		printf("Got incoming handshaking headers from node %s:\n",
			ip_to_gchar(n->ip));
		header_dump(ih->header, stdout);
	}

	/*
	 * Handle common header fields.
	 */

	field = header_get(ih->header, "Pong-Caching");
	if (field) {
		guint major, minor;
		sscanf(field, "%u.%u", &major, &minor);
		if (major > 0 || minor > 1)
			g_warning("node %s claims Pong-Caching version %u.%u",
				node_ip(n), major, minor);
		n->flags |= NODE_F_PING_LIMIT;
	}

	/*
	 * Welcome the incoming node.
	 */

	rw = g_snprintf(gnet_response, sizeof(gnet_response),
		"GNUTELLA/0.6 200 OK\r\n"
		"User-Agent: %s\r\n"
		"Pong-Caching: 0.1\r\n"
		"X-Comment: This is still experimental\r\n"
		"\r\n",
		version_string);

	/*
	 * When sending a handshake reply, we might not be able to transmit the
	 * whole thing in one shot.  This should be rare, so we're not handling
	 * the case for now.  Simply log it and close the connection.
	 */

	if (-1 == (sent = write(n->socket->file_desc, gnet_response, rw))) {
		int errcode = errno;
		g_warning("Unable to send back handshake reply to node %s: %s",
			ip_to_gchar(n->ip), g_strerror(errcode));
		node_remove(n, "Failed (Cannot reply to HELLO: %s)",
			g_strerror(errcode));
		goto final_cleanup;
	} else if (sent < rw) {
		g_warning("Could only send %d out of %d bytes of reply to node %s",
			sent, rw, ip_to_gchar(n->ip));
		node_remove(n, "Failed (Cannot send HELLO reply atomically)");
		goto final_cleanup;
	} else if (dbg > 4) {
		printf("----Sent OK handshake reply to %s:\n%.*s----\n",
			ip_to_gchar(n->ip), rw, gnet_response);
		fflush(stdout);
	}

	/*
	 * Now that we got all the headers, we may update the `last_update' field.
	 */

	n->status = GTA_NODE_WELCOME_SENT;
	n->last_update = time((time_t *) 0);

	/*
	 * The remote node is expected to send us an acknowledgement.
	 * The I/O callback installed is still node_header_read(), but
	 * we need to configure a different callback when the header
	 * is collected.
	 */

	header_reset(ih->header);
	ih->flags |= IO_EXTRA_DATA_OK | IO_STATUS_LINE;
	ih->process_header = node_process_handshake_ack;
	return;

	/*
	 * When we come here, we're done with the parsing structures, we can
	 * free them.
	 */

final_cleanup:
	header_free(ih->header);
	getline_free(ih->getline);
	g_free(ih);
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
		goto final_cleanup;
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
		goto final_cleanup;
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
		g_warning("incoming node %s sent extra bytes after HELLO",
			ip_to_gchar(s->ip));
		dump_hex(stderr, "Extra HELLO Data", s->buffer, MIN(s->pos, 256));
		node_remove(n, "Failed (Extra HELLO data)");
		goto final_cleanup;
	}

	/*
	 * If it is a 0.4 handshake, we're done: we have already welcomed the
	 * node, and came here just to read the trailing "\n".  We're now
	 * ready to process incoming data.
	 */

	if (n->proto_major == 0 && n->proto_minor == 4) {
		gdk_input_remove(s->gdk_tag);
		s->gdk_tag = 0;
		node_is_now_connected(n);
		goto final_cleanup;
	}

	/*
	 * We're dealing with a 0.6+ handshake.
	 *
	 * If this is our first call, we'll go to node_process_handshake_header().
	 * We need to welcome the node, and it will reply after our welcome,
	 * so we don't free the io_header structure and the getline/header
	 * objects yet.
	 *
	 * If this is our second call, we'll go to node_process_handshake_ack().
	 * This will terminate the handshaking process, and cleanup the header
	 * parsing structure, then install the data handling callback.
	 */

	getline_reset(ih->getline);		/* Ensure it's empty, ready for reuse */
	ih->process_header(ih);
	return;

	/*
	 * When we come here, we're done with the parsing structures, we can
	 * free them.
	 */

final_cleanup:
	header_free(ih->header);
	getline_free(ih->getline);
	g_free(ih);
}


/*
 * node_header_read
 *
 * This routine is installed as an input callback to read the hanshaking
 * header.
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

	/*
	 * When we come here, we're done with the parsing structures, we can
	 * free them.
	 */

final_cleanup:
	header_free(ih->header);
	getline_free(ih->getline);
	g_free(ih);
}

void node_add(struct gnutella_socket *s, guint32 ip, guint16 port)
{
	struct gnutella_node *n;
	gchar *titles[4];
	gint row;
	gboolean incoming = FALSE, already_connected = FALSE;
	gint major = 0, minor = 0;
	gboolean ponging_only = FALSE;

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

#define NO_RFC1918				/* XXX */

#ifdef NO_RFC1918
	/* This needs to be a runtime option.  I could see a need for someone
	   * to want to run gnutella behind a firewall over on a private network. */
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
		if (major > 0 || minor > 4) {
			send_node_error(s, 503, "Too many Gnet connections");
			socket_destroy(s);
			return;
		}
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
		} else {
			n->status = GTA_NODE_REMOVING;
			n->remove_msg = "Connection failed";
		}

		titles[1] = (gchar *) "Outgoing";
	}

	titles[0] = node_ip(n);
	titles[2] = (gchar *) "";

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
void node_parse(struct gnutella_node *node)
{
	static struct gnutella_node *n;
	gboolean drop = FALSE;

	g_return_if_fail(node);

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
				pcache_ping_received(n);
				send_connection_pongs(n, n->header.muid); /* Will disconnect */
				return;
			}
			if (n->header.muid[8] == 0xff && n->header.muid[15] >= 1)
				n->flags |= NODE_F_PING_LIMIT;
			n->flags &= ~NODE_F_HDSK_PING;		/* Clear indication */
		} else if (n->flags & NODE_F_TMP) {
			if (n->header.function == GTA_MSG_INIT)
				pcache_ping_received(n);
			node_remove(n, "Ponging connection did not send handshaking ping");
			return;
		}
	}

	/* First some simple checks */

	switch (n->header.function) {
	case GTA_MSG_INIT:
		if (*n->header.size)
			drop = TRUE;
		break;
	case GTA_MSG_INIT_RESPONSE:
		if (*n->header.size != sizeof(struct gnutella_init_response))
			drop = TRUE;
		/* 
		 * TODO
		 * Don't propagate more than a fraction of pongs coming from
		 * hosts that don't share much?
		 *				--RAM, 09/09/2001
		 */
		break;
	case GTA_MSG_PUSH_REQUEST:
		if (*n->header.size != sizeof(struct gnutella_push_request))
			drop = TRUE;
		break;
	case GTA_MSG_SEARCH:
		if (!*n->header.size)
			drop = TRUE;
		else if (*n->header.size > search_queries_forward_size)
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
		if (*n->header.size > search_answers_forward_size)
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
		n->dropped++;
		dropped_messages++;
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
	case GTA_MSG_INIT:				/* Ping */
		pcache_ping_received(n);
		goto reset_header;
		/* NOTREACHED */
	case GTA_MSG_INIT_RESPONSE:		/* Pong */
		pcache_pong_received(n);
		goto reset_header;
		/* NOTREACHED */
	default:
		break;
	}

//		case GTA_MSG_INIT:
//			reply_init(n);
//			break;
//		case GTA_MSG_INIT_RESPONSE:
//			host_add(n, 0, 0, TRUE);
//			break;

	/* Route (forward) then handle the message if required */

	if (route_message(&n)) {		/* We have to handle the message */
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

reset_header:
	n->have_header = FALSE;
	n->pos = 0;
}

void node_init_outgoing(struct gnutella_node *n)
{
	gchar buf[MAX_LINE_SIZE];
	gint len;
	gint sent;

	n->proto_major = 0;
	n->proto_minor = 4;
	len = g_snprintf(buf, sizeof(buf), "%s%d.%d\n\n", gnutella_hello, 0, 4);

	if (-1 == (sent = write(n->socket->file_desc, buf, len)))
		node_remove(n, "Write error during HELLO: %s", g_strerror(errno));
	else if (sent < len)
		node_remove(n, "Partial write during HELLO");
	else {
		n->status = GTA_NODE_HELLO_SENT;
		gui_update_node(n, TRUE);
	}
}

gboolean node_enqueue(struct gnutella_node *n, gchar * data, guint32 size)
{
	/* Enqueue data for a slow node */

	g_return_val_if_fail(n, FALSE);

	assert(n->status != GTA_NODE_REMOVING);

	if (data == NULL) {
		g_warning("gtk-gnutella:node_enqueue:called with data == NULL\n");
		return (size == 0);
	}

	if (size == 0) {
		g_warning("gtk-gnutella:node_enqueue:called with size == 0\n");
		return TRUE;
	}

	if (size + n->sq_pos > node_sendqueue_size) {
		node_remove(n, "Send queue exceeded limit of %d bytes",
					node_sendqueue_size);
		return FALSE;
	}

	if (!n->gdk_tag) {
		n->gdk_tag = gdk_input_add(n->socket->file_desc,
			GDK_INPUT_WRITE | GDK_INPUT_EXCEPTION,
			node_write, (gpointer) n);

		/* We assume that if this is valid, it is non-zero */
		g_assert(n->gdk_tag);
	}

	if (!n->sendq) {
		n->sendq = (gchar *) g_malloc0(node_sendqueue_size);
		n->sq_pos = 0;
		n->end_of_last_packet = 0;
		n->end_of_packets = NULL;
	}

	memcpy(n->sendq + n->sq_pos, data, size);
	n->sq_pos += size;

	return TRUE;
}

void node_enqueue_end_of_packet(struct gnutella_node *n)
{
	assert(n);

	if (!n->sq_pos) {
		n->sent++;
		gui_update_node(n, FALSE);
	} else {
		n->end_of_packets = g_slist_append(n->end_of_packets,
			(gpointer) (n->sq_pos - n->end_of_last_packet));
		n->end_of_last_packet = n->sq_pos;
	}
}

#include <sys/time.h>
#include <unistd.h>

void node_write(gpointer data, gint source, GdkInputCondition cond)
{
	struct gnutella_node *n = (struct gnutella_node *) data;
	gint r;

	g_return_if_fail(n);

	if (cond & GDK_INPUT_EXCEPTION) {
		node_remove(n, "Write failed (Input Exceptions)");
		return;
	}

	/* We can write again on the node's socket */

	if (n->sendq && n->sq_pos) {
		r = write(n->socket->file_desc, n->sendq, n->sq_pos);

		if (r > 0) {
			/*
			 * Move the remaining data to the beginning of the buffer
			 * Thanks to Steven Wilcoxon <swilcoxon@uswest.net> who noticed
			 * this awful bug
			 */

			memmove(n->sendq, n->sendq + r, n->sq_pos - r);
			n->sq_pos -= r;
			n->end_of_last_packet -= r;

			/* count all the packets we just wrote */
			while (
				n->end_of_packets &&
				((guint32) n->end_of_packets->data <= r)
			) {
				n->sent++;
				r -= (guint32) n->end_of_packets->data;
				n->end_of_packets = g_slist_remove(n->end_of_packets,
					n->end_of_packets->data);
			}

			if (r && n->end_of_packets)
				(guint32) n->end_of_packets->data -= r;

			gui_update_node(n, FALSE);

		} else if (r == 0) {
			g_error("gtk-gnutella:node_enqueue:write returned 0?\n");
		} else if (errno == EAGAIN || errno == EINTR) {
			return;
		} else if (errno == EPIPE || errno == ENOSPC || errno == EIO
				   || errno == ECONNRESET || errno == ETIMEDOUT) {
			node_remove(n, "Write of queue failed: %s", g_strerror(errno));
			return;
		} else {
			int terr = errno;
			time_t t = time(NULL);
			g_error("%s  gtk-gnutella: node_write: "
				"write failed on fd #%d with unexpected errno: %d (%s)\n",
				 ctime(&t), n->socket->file_desc, terr, g_strerror(terr));
		}
	}

	if (!n->sq_pos) {
		gdk_input_remove(n->gdk_tag);
		n->gdk_tag = 0;
		g_assert(n->end_of_packets == NULL);
		g_assert(n->end_of_last_packet == 0);
	}
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
	g_assert(n->status == GTA_NODE_CONNECTED);

	if (cond & GDK_INPUT_EXCEPTION) {
		node_remove(n, "Failed (Input Exception)");
		return;
	}

	if (!n->have_header) {		/* We haven't got the header yet */
		guchar *w = (guchar *) & n->header;
		gboolean kick = FALSE;

		r = n->read(n->socket->file_desc, w + n->pos,
				 sizeof(struct gnutella_header) - n->pos);

		if (!r) {
			node_remove(n, "Failed (EOF)");
			return;
		} else if (r < 0 && errno == EAGAIN)
			return;
		else if (r < 0) {
			node_remove(n, "Read error: %s", g_strerror(errno));
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
			node_remove(n, "Kicked: %s message too big (%d bytes)",
						msg_name[n->header.function], n->size);
			return;
		}

		/* Okay */

		n->pos = 0;

		if (n->size > n->allocated) {
			/*
			 * We need to grow the allocated data buffer
			 */

			guint32 maxsize = max_msg_size();	/* Can change dynamically */

			if (maxsize < n->size) {
				g_warning("got %d byte %s message, should have kicked node\n",
					n->size, msg_name[n->header.function]);
				node_remove(n, "Kicked: %s message too big (%d bytes)",
					msg_name[n->header.function], n->size);
				return;
			}

			if (n->allocated)
				n->data = (guchar *) g_realloc(n->data, maxsize);
			else
				n->data = (guchar *) g_malloc0(maxsize);
			n->allocated = maxsize;
		}

		return;
	}

	/* Reading of the message data */

	r = n->read(n->socket->file_desc, n->data + n->pos, n->size - n->pos);

	if (!r) {
		node_remove(n, "Failed (EOF in %s message data)",
			msg_name[n->header.function]);
		return;
	} else if (r < 0 && errno == EAGAIN)
		return;
	else if (r < 0) {
		node_remove(n, "Read error in %s message: %s",
			msg_name[n->header.function], g_strerror(errno));
		return;
	}

	n->pos += r;

	if (n->pos >= n->size)
		node_parse(n);
}

/* Reads an outgoing connecting CONTROL node */

void node_read_connecting(gpointer data, gint source, GdkInputCondition cond)
{
	struct gnutella_node *n = (struct gnutella_node *) data;
	struct gnutella_socket *s = n->socket;
	gint r;

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
		/* The node does not seem to be a valid gnutella server !? */

		g_warning("node %s replied to our HELLO strangely", node_ip(n));
		dump_hex(stderr, "HELLO Reply", s->buffer, MIN(s->pos, 80));
		node_remove(n, "Failed (Not a Gnutella server?)");
		return;
	}

	/*
	 * Okay, we are now really connected to a gnutella node
	 */

	s->pos = 0;

	gdk_input_remove(s->gdk_tag);
	s->gdk_tag = 0;

	node_is_now_connected(n);
	pcache_outgoing_connection(n);	/* Will send proper handshaking ping */
}

void node_close(void)
{
	while (sl_nodes) {
		struct gnutella_node *n = sl_nodes->data;
		if (n->socket)
			g_free(n->socket);
		if (n->sendq)
			g_free(n->sendq);
		if (n->allocated)
			g_free(n->data);
		node_real_remove(n);
	}

	g_slist_free(sl_nodes);
	g_hash_table_destroy(node_by_fd);
}

/* vi: set ts=4: */
