
#include "gnutella.h"

#include <fcntl.h>
#include <sys/types.h>
#include <string.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <assert.h>

#include "interface.h"

GSList *sl_nodes = (GSList *) NULL;

guint32 nodes_in_list = 0;

guint32 global_messages = 0;
guint32 global_searches = 0;
guint32 routing_errors = 0;
guint32 dropped_messages = 0;

const gchar *gnutella_hello   = "GNUTELLA CONNECT/0.4\n\n";
const gchar *gnutella_welcome = "GNUTELLA OK\n\n";

GHookList node_added_hook_list;
struct gnutella_node *node_added; /* For use by node_added_hook_list hooks, since we can't add a parameter at list invoke time. */

guint32 gnutella_welcome_length = 0;

static gint32 connected_node_cnt = 0;
static gchar *msg_name[256];

/* Network init ----------------------------------- */

void network_init(void)
{
	int i;

	gnutella_welcome_length = strlen(gnutella_welcome);
	g_hook_list_init(&node_added_hook_list, sizeof(GHook));
	node_added_hook_list.seq_id = 1;
	node_added = NULL; 

	for (i = 0; i < 256; i++) msg_name[i] = "unknown";
	msg_name[GTA_MSG_INIT]                = "ping";
	msg_name[GTA_MSG_INIT_RESPONSE]       = "pong";
	msg_name[GTA_MSG_SEARCH]              = "query";
	msg_name[GTA_MSG_SEARCH_RESULTS]      = "query hit";
}

/* Nodes ------------------------------------------ */

gboolean on_the_net(void)
{
	return connected_node_cnt > 0 ? TRUE : FALSE;
}

gint32 connected_nodes(void)
{
	return connected_node_cnt;
}

static guint32 max_msg_size(void)
{
	/*
	 * Maximum message payload size we are configured to handle.
	 * Today, they are fixed at config time, but they will be set via
	 * GUI tomorrow, so the max size is not fixed in time.
	 *		--RAM, 15/09/2001
	 */

	guint32 maxsize;

	maxsize = MAX(search_queries_kick_size, search_answers_kick_size);
	maxsize = MAX(maxsize, other_messages_kick_size);

	return maxsize;
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

void node_remove(struct gnutella_node *n, const gchar *reason, ...)
{
	gboolean on;

	g_return_if_fail(n);

	if (n->status == GTA_NODE_REMOVING) return;

	if (n->status == GTA_NODE_CONNECTED) {
		routing_node_remove(n);
		connected_node_cnt--;
		g_assert(connected_node_cnt >= 0);
	}

	if (n->socket)
	{
		g_assert(n->socket->resource.node == n);
		socket_free(n->socket);
	}

	if (n->gdk_tag)		gdk_input_remove(n->gdk_tag);
	if (n->allocated)	{ g_free(n->data); n->allocated = 0; }
	if (n->sendq)		{ g_free(n->sendq); n->sendq = NULL; }

	n->status = GTA_NODE_REMOVING;
	n->last_update = time((time_t *) NULL);

	if (reason) {
		va_list args;
		va_start(args, reason);
		g_vsnprintf(n->error_str, sizeof(n->error_str), reason, args);
		n->error_str[sizeof(n->error_str)-1] = '\0';	/* May be truncated */
		va_end(args);
		n->remove_msg = n->error_str;
	} else
		n->remove_msg = NULL;

	nodes_in_list--;

	gui_update_c_gnutellanet();
	gui_update_node(n, TRUE);

	on = on_the_net();

	gtk_widget_set_sensitive(button_host_catcher_get_more, on);

	if (!on) gtk_widget_set_sensitive(button_search, FALSE);
}

gboolean have_node(guint32 ip)
{
	GSList *l;

	if (stop_host_get)		/* Useful for testing */
		return FALSE;

	if (ip == local_ip || (force_local_ip && ip == forced_local_ip)) return TRUE;
	for (l = sl_nodes; l; l = l->next) if (((struct gnutella_node *) l->data)->ip == ip) return TRUE;
	return FALSE;
}

struct gnutella_node *node_add(struct gnutella_socket *s, guint32 ip, guint16 port)
{
	struct gnutella_node *n;
	gchar *titles[4];
	gint row;
	gboolean incoming = FALSE, already_connected = FALSE;

#define NO_RFC1918	/* XXX */

#ifdef NO_RFC1918
       /* This needs to be a runtime option.  I could see a need for someone
       * to want to run gnutella behind a firewall over on a private network. */
       if (is_private_ip(ip))
       {       
	 if (s)
		 socket_destroy(s);
	 return NULL;
        }
#endif

   /* Too many gnutellaNet connections */
	if (nodes_in_list >= max_connections) {
		if (s)
			 socket_destroy(s);
		 return NULL;
	}
 
	n = (struct gnutella_node *) g_malloc0(sizeof(struct gnutella_node));

	n->ip = ip;
	n->port = port;

	if (s) /* This is an incoming control connection */
	{
		n->socket        = s;
		s->type          = GTA_TYPE_CONTROL;
		n->status        = GTA_NODE_WELCOME_SENT;
		s->resource.node = n;

		incoming = TRUE;

		titles[1] = (gchar *) "Incoming";
	}
	else /* We have to create an outgoing control connection for the node */
	{
		s = socket_connect(ip, port, GTA_TYPE_CONTROL);

		if (s)
		{
			n->status        = GTA_NODE_CONNECTING;
			s->resource.node = n;
			n->socket        = s;
		}
		else
		{
			n->status     = GTA_NODE_REMOVING;
			n->remove_msg = "Connection failed";
		}

		titles[1] = (gchar *) "Outgoing";
	}

	titles[0] = ip_port_to_gchar(n->ip, n->port);
	titles[2] = (gchar *) "";

	row = gtk_clist_append(GTK_CLIST(clist_nodes), titles);
	gtk_clist_set_row_data(GTK_CLIST(clist_nodes), row, (gpointer) n);

	/* Check wether we have already a connection to this node before adding the node to the list */

	already_connected = have_node(n->ip);

	sl_nodes = g_slist_prepend(sl_nodes, n);
	if (n->status != GTA_NODE_REMOVING)
		nodes_in_list++;

	if (already_connected)
	{
		node_remove(n, "Already connected");
		return (struct gnutella_node *) NULL;
	}

	if (incoming) /* Welcome the incoming node */
	{
		if (write(s->file_desc, gnutella_welcome, strlen(gnutella_welcome)) < 0)
		{
			node_remove(n, "Write of HELLO failed: %s", g_strerror(errno));
			return (struct gnutella_node *) NULL;
		}
	}

	gui_update_node(n, TRUE);
	gui_update_c_gnutellanet();

	return n;
}

/* Reading of messages ---------------------------------------------------------------------------- */

void node_parse(struct gnutella_node *node)
{
	static struct gnutella_node *n;
	gboolean drop = FALSE;

	g_return_if_fail(node);

	n = node;

	/* First some simple checks */

	switch (n->header.function)
	{
		case GTA_MSG_INIT:
		  if (*n->header.size) drop = TRUE;
			break;
		case GTA_MSG_INIT_RESPONSE:
			if (*n->header.size != sizeof(struct gnutella_init_response)) drop = TRUE;
			/* 
			 * TODO
			 * Don't propagate more than a fraction of pongs coming from
			 * hosts that don't share much.
			 *		--RAM, 09/09/2001
			 */
			break;
		case GTA_MSG_PUSH_REQUEST:
			if (*n->header.size != sizeof(struct gnutella_push_request)) drop = TRUE;
			break;
		case GTA_MSG_SEARCH:
			if (!*n->header.size) drop = TRUE;
			else if (*n->header.size > search_queries_forward_size) drop = TRUE;

			/*
			 * TODO
			 * Just like we refuse to process queries that are "too short",
			 * and would therefore match too many things, we should probably
			 * refuse to forward those on the network.  Less careful servents
			 * would reply, and then we'll have more messages to process.
			 *		-- RAM, 09/09/2001
			 */
			break;
		case GTA_MSG_SEARCH_RESULTS:
			if (*n->header.size > search_answers_forward_size) drop = TRUE;
			break;

		default: /* Unknown message type - we drop it */
			drop = TRUE;
			n->n_bad++;
			break;
	}

	/* Route (forward) then handle the message if required */

	if (drop)
	{
		n->dropped++;
		dropped_messages++;
	}
	else if (route_message(&n)) /* We have to handle the message */
	{
		switch(n->header.function)
		{
			case GTA_MSG_INIT:           { reply_init(n); break; }
			case GTA_MSG_INIT_RESPONSE:  { host_add(n, 0, 0, TRUE); break; }
			case GTA_MSG_PUSH_REQUEST:   { handle_push_request(n); break; }
			case GTA_MSG_SEARCH:         { search_request(n); break; }
			case GTA_MSG_SEARCH_RESULTS: { search_results(n); break; }
			default:                     { message_dump(n); }
		}
	}

	if (!n) return;	/* The node has been removed during processing */

	n->have_header = FALSE;
	n->pos = 0;
}

void node_init_outgoing(struct gnutella_node *n)
{
	if (write(n->socket->file_desc, gnutella_hello, strlen(gnutella_hello)) < 0)
	{
		node_remove(n, "Write error: %s", g_strerror(errno));
	}
	else
	{
		n->status = GTA_NODE_HELLO_SENT;
		gui_update_node(n, TRUE);
	}
}

gboolean node_enqueue(struct gnutella_node *n, gchar *data, guint32 size)
{
	/* Enqueue data for a slow node */

	g_return_val_if_fail(n, FALSE);

	assert(n->status != GTA_NODE_REMOVING);

	if(data == NULL) {
	  g_warning("gtk-gnutella:node_enqueue:called with data == NULL\n");
	  return (size == 0);
	}

	if(size == 0) {
	  g_warning("gtk-gnutella:node_enqueue:called with size == 0\n");
	  return TRUE;
	}

	if (size + n->sq_pos > node_sendqueue_size) {
		node_remove(n, "Send queue exceeded limit of %d bytes",
			node_sendqueue_size);
		return FALSE;
	}

	if (!n->gdk_tag) {
		n->gdk_tag = gdk_input_add(n->socket->file_desc, GDK_INPUT_WRITE | GDK_INPUT_EXCEPTION, node_write, (gpointer) n);

		/* We assume that if this is valid, it is non-zero */
		assert(n->gdk_tag);
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

void node_enqueue_end_of_packet(struct gnutella_node *n) {
  assert(n);

  if(!n->sq_pos) {
	n->sent++;
	gui_update_node(n, FALSE);
  } else {
	n->end_of_packets = g_slist_append(n->end_of_packets, (gpointer)(n->sq_pos - n->end_of_last_packet));
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

	if (cond & GDK_INPUT_EXCEPTION)	{ node_remove(n, "Write failed (Input Exceptions)"); return;}

	/* We can write again on the node's socket */

	if (n->sendq && n->sq_pos) {
		r = write(n->socket->file_desc, n->sendq, n->sq_pos);

		if (r > 0) {
			/* Move the remaining data to the beginning of the buffer */
			/* Thanks to Steven Wilcoxon <swilcoxon@uswest.net> who noticed this awful bug */

			memmove(n->sendq, n->sendq + r, n->sq_pos - r);
			n->sq_pos -= r;
			n->end_of_last_packet -= r;

			/* count all the packets we just wrote */
			while(n->end_of_packets  &&  ((guint32) n->end_of_packets->data <= r)) {
			  n->sent++;
			  r -= (guint32)n->end_of_packets->data;
			  n->end_of_packets = g_slist_remove(n->end_of_packets, n->end_of_packets->data);
			}

			if(r && n->end_of_packets)
			  (guint32) n->end_of_packets->data -= r;

			gui_update_node(n, FALSE);

		} else if(r == 0) {
		  g_error("gtk-gnutella:node_enqueue:write returned 0?\n");
		} else if (errno == EAGAIN || errno == EINTR) {
		  return;
		} else if (errno == EPIPE || errno == ENOSPC || errno == EIO || errno == ECONNRESET || errno == ETIMEDOUT) {
		  node_remove(n, "Write of queue failed: %s", g_strerror(errno));
		  return; 
		} else {
		  int terr = errno;
		  time_t t = time(NULL);
		  g_error("%s:gtk-gnutella:node_write: write failed with unexpected errno: %d (%s)\n", ctime(&t), terr, g_strerror(terr));
		}
	}

	if (!n->sq_pos)
	{
		gdk_input_remove(n->gdk_tag);
		n->gdk_tag = 0;
		g_assert(n->end_of_packets == NULL);
		g_assert(n->end_of_last_packet == 0);
	}
}

void node_read(gpointer data, gint source, GdkInputCondition cond)
{
	gint r;
	struct gnutella_node *n = (struct gnutella_node *) data;

	g_return_if_fail(n);

	if (cond & GDK_INPUT_EXCEPTION) { node_remove(n, "Failed (Input Exception)"); return; }

	if (n->status == GTA_NODE_WELCOME_SENT)	/* This is the first packet from this node */
	{
		n->status = GTA_NODE_CONNECTED;
		connected_node_cnt++;
		gtk_widget_set_sensitive(button_host_catcher_get_more, TRUE);

		node_added = n;
		g_hook_list_invoke(&node_added_hook_list, TRUE);
		node_added = NULL;

		/* TODO Update the search button if there is the search entry is not empty */
	}

	if (!n->have_header)	/* We haven't got the header yet */
	{
		guchar *w = (guchar *) &n->header;
		gboolean kick = FALSE;

		r = read(n->socket->file_desc, w + n->pos, sizeof(struct gnutella_header) - n->pos);

		if (!r) { node_remove(n, "Failed (EOF)"); return; }
		else if (r < 0 && errno == EAGAIN) return;
		else if (r < 0) {
			node_remove(n, "Read error: %s", g_strerror(errno));
			return;
		}

		n->pos += r;

		if (n->pos < sizeof(struct gnutella_header)) return;

		/* Okay, we have read the full header */

		n->have_header = TRUE;

		n->received++;
		global_messages++;

		gui_update_node(n, FALSE);

		READ_GUINT32_LE(n->header.size, n->size);

		/* If the message haven't got any data, we process it now */

		if (!n->size) { node_parse(n); return; }

		/* Check wether the message is not too big */

		switch (n->header.function)
		{
			case GTA_MSG_SEARCH:
				if (n->size > search_queries_kick_size) kick = TRUE; break;

			case GTA_MSG_SEARCH_RESULTS:
				if (n->size > search_answers_kick_size) kick = TRUE; break;

			default:
				if (n->size > other_messages_kick_size) kick = TRUE; break;
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

	r = read(n->socket->file_desc, n->data + n->pos, n->size - n->pos);

	if (!r) {
		node_remove(n, "Failed (EOF in %s message data)",
			msg_name[n->header.function]);
		return;
	}
	else if (r < 0 && errno == EAGAIN) return;
	else if (r < 0) {
		node_remove(n, "Read error in %s message: %s",
			msg_name[n->header.function], g_strerror(errno));
		return;
	}

	n->pos += r;

	if (n->pos >= n->size) node_parse(n);
}

/* Reads an outgoing connecting CONTROL node */

void node_read_connecting(gpointer data, gint source, GdkInputCondition cond)
{
	static struct gnutella_socket *s;
	static gint r;
	
	s = (struct gnutella_socket *) data;

	if (cond & GDK_INPUT_EXCEPTION) { node_remove(s->resource.node, "Failed (Input Exception)"); return; }

	r = read(s->file_desc, s->buffer + s->pos, gnutella_welcome_length - s->pos);

	if (!r) { node_remove(s->resource.node, "Failed (EOF)"); return; }
	else if (r < 0 && errno == EAGAIN) return;
	else if (r < 0) {
		node_remove(s->resource.node, "Read error in HELLO: %s",
			g_strerror(errno));
		return;
	}

	s->pos += r;

	if (s->pos < gnutella_welcome_length) return;	/* We haven't read enough bytes yet */

	if (strcmp(s->buffer, gnutella_welcome))
	{
		/* The node does not seem to be a valid gnutella server !? */

		g_warning("node %s replied to our HELLO with: \"%.80s\"\n",
			ip_port_to_gchar(s->ip, s->port), s->buffer);
		node_remove(s->resource.node, "Failed (Not a gnutella server ?)");
		return;
	}

	/* Okay, we are now really connected to a gnutella node */

	gdk_input_remove(s->gdk_tag);

	s->gdk_tag = gdk_input_add(s->file_desc, GDK_INPUT_READ | GDK_INPUT_EXCEPTION, node_read, (gpointer) s->resource.node);

	/* We assume that if this is valid, it is non-zero */
	assert(s->gdk_tag);

	s->pos = 0;

	s->resource.node->status = GTA_NODE_CONNECTED;
	connected_node_cnt++;

	gui_update_node(s->resource.node, TRUE);

	gtk_widget_set_sensitive(button_host_catcher_get_more, TRUE);

	send_init(s->resource.node);

	node_added = s->resource.node;
	g_hook_list_invoke(&node_added_hook_list, TRUE);
	node_added = NULL;
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
}

/* vi: set ts=3: */

