
#include "gnutella.h"

#include <fcntl.h>
#include <sys/types.h>
#include <string.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include "interface.h"

GSList *sl_nodes = (GSList *) NULL;

guint32 nodes_in_list = 0;

guint32 global_messages = 0;
guint32 global_searches = 0;
guint32 routing_errors = 0;
guint32 dropped_messages = 0;

const gchar *gnutella_hello   = "GNUTELLA CONNECT/0.4\n\n";
const gchar *gnutella_welcome = "GNUTELLA OK\n\n";

guint32 gnutella_welcome_length = 0;

/* Network init ----------------------------------------------------------------------------------- */

void network_init(void)
{
	gnutella_welcome_length = strlen(gnutella_welcome);
}

/* Nodes ------------------------------------------------------------------------------------------ */

gboolean on_the_net(void)
{
	GSList *l;

	for (l = sl_nodes; l; l = l->next)
		if (((struct gnutella_node *) l->data)->status == GTA_NODE_CONNECTED) return TRUE;

	return FALSE;
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

void node_remove(struct gnutella_node *n, const gchar *reason)
{
	gboolean on;

	g_return_if_fail(n);

	if (n->status == GTA_NODE_REMOVING) return;

	if (n->status == GTA_NODE_CONNECTED) routing_node_remove(n);

	if (n->socket)
	{
		n->socket->resource.node = (struct gnutella_node *) NULL;
		socket_destroy(n->socket);
	}

	if (n->gdk_tag) gdk_input_remove(n->gdk_tag);

	if (n->allocated) g_free(n->data);

	if (n->sendq) g_free(n->sendq);

	n->status = GTA_NODE_REMOVING;
	n->last_update = time((time_t *) NULL);

	if (reason) n->remove_msg = reason;

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
	nodes_in_list++;

	if (incoming) /* Welcome the incoming node */
	{
		if (already_connected)
		{
			node_remove(n, "Already connected");
			return (struct gnutella_node *) NULL;
		}
		else if (write(s->file_desc, gnutella_welcome, strlen(gnutella_welcome)) < 0)
		{
			node_remove(n, "Write failed");
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
			if (n->size) drop = TRUE;
			break;
		case GTA_MSG_INIT_RESPONSE:
			if (n->size != sizeof(struct gnutella_init_response)) drop = TRUE;
			break;
		case GTA_MSG_PUSH_REQUEST:
			if (n->size != sizeof(struct gnutella_push_request)) drop = TRUE;
			break;
		case GTA_MSG_SEARCH:
			if (!n->size) drop = TRUE;
			else if (n->size > search_queries_forward_size) drop = TRUE;
			break;
		case GTA_MSG_SEARCH_RESULTS:
			if (n->size > search_answers_forward_size) drop = TRUE;
			break;

		default: /* Unknown message type - we drop it */
			drop = TRUE;
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

	if (n->allocated) { g_free(n->data); n->allocated = FALSE; }

	n->data = (guchar *) NULL;
}

void node_init_outgoing(struct gnutella_node *n)
{
	if (write(n->socket->file_desc, gnutella_hello, strlen(gnutella_hello)) < 0)
	{
		node_remove(n, "Write error");
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

	if (size + n->sq_pos > node_sendqueue_size) { node_remove(n, "Send queue excedeed"); return FALSE; }

	if (!n->gdk_tag)
		n->gdk_tag = gdk_input_add(n->socket->file_desc, GDK_INPUT_WRITE, node_write, (gpointer) n);

	if (!n->sendq) n->sendq = (gchar *) g_malloc(node_sendqueue_size);

	memcpy(n->sendq + n->sq_pos, data, size);

	n->sq_pos += size;

	return TRUE;
}

void node_write(gpointer data, gint source, GdkInputCondition cond)
{
	struct gnutella_node *n = (struct gnutella_node *) data;
	gint r;

	g_return_if_fail(n);

	/* We can write again on the node's socket */

	if (n->sendq && n->sq_pos)
	{
		r = write(n->socket->file_desc, n->sendq, (n->sq_pos > 1024)? 1024 : n->sq_pos);

		if (r >= 0)
		{
			/* Move the remaining data to the beginning of the buffer */
			/* Thanks to Steven Wilcoxon <swilcoxon@uswest.net> who noticed this awful bug */

			memmove(n->sendq, n->sendq + r, n->sq_pos - r);
			n->sq_pos -= r;
		}
		else if (errno == EAGAIN) return;
		else { node_remove(n, "Write of queue failed"); return; }
	}

	if (!n->sq_pos)
	{
		if (n->sendq) { g_free(n->sendq); n->sendq = (gchar *) NULL; }
		gdk_input_remove(n->gdk_tag);
		n->gdk_tag = 0;
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
		gtk_widget_set_sensitive(button_host_catcher_get_more, TRUE);

		/* TODO Update the search button if there is the search entry is not empty */
	}

	if (!n->have_header)	/* We haven't got the header yet */
	{
		guchar *w = (guchar *) &n->header;
		gboolean kick = FALSE;

		r = read(n->socket->file_desc, w + n->pos, sizeof(struct gnutella_header) - n->pos);

		if (!r) { node_remove(n, "Failed (EOF)"); return; }
		else if (r < 0 && errno == EAGAIN) return;
		else if (r < 0) { node_remove(n, "Failed (Read Error)"); return; }

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

		if (kick) { node_remove(n, "Kicked (message too big)"); return; }

		/* Okay */

		n->pos = 0;
		
		if (n->size < sizeof(n->socket->buffer))
		{
			/* The socket buffer is large enough to handle all the packet data */
		
			n->data = n->socket->buffer;
		}
		else
		{
			/* We need to allocate the data buffer */

			n->allocated = TRUE;
			n->data = (guchar *) g_malloc(n->size);
		}

		return;
	}

	/* Reading of the message data */

	r = read(n->socket->file_desc, n->data + n->pos, n->size - n->pos);

	if (!r) { node_remove(n, "Failed (EOF in message data)"); return; }
	else if (r < 0 && errno == EAGAIN) return;
	else if (r < 0) { node_remove(n, "Failed (Read Error in message data)"); return; }

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
	else if (r < 0) { node_remove(s->resource.node, "Failed (Read Error)"); return; }

	s->pos += r;

	if (s->pos < gnutella_welcome_length) return;	/* We haven't read enough bytes yet */

	if (strcmp(s->buffer, gnutella_welcome))
	{
		/* The node does not seem to be a valid gnutella server !? */

		node_remove(s->resource.node, "Failed (Not a gnutella server ?)");
		return;
	}

	/* Okay, we are now really connected to a gnutella node */

	gdk_input_remove(s->gdk_tag);

	s->gdk_tag = gdk_input_add(s->file_desc, GDK_INPUT_READ | GDK_INPUT_EXCEPTION, node_read, (gpointer) s->resource.node);

	s->pos = 0;

	s->resource.node->status = GTA_NODE_CONNECTED;

	gui_update_node(s->resource.node, TRUE);

	gtk_widget_set_sensitive(button_host_catcher_get_more, TRUE);

	send_init(s->resource.node);
}

/* vi: set ts=3: */

