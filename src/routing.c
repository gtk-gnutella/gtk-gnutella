
/* Gnutella Network Messages routing */

#include "gnutella.h"

#include <stdarg.h>

guchar guid[16];				/* ID of our client for this session */

guint32 i_fake_node;			/* The address of this guint32 will be used to identify ourselves */
									/* as a fake node (for our own ping & searches requests) */

struct gnutella_node *fake_node;	/* Our fake node */

GList   *messages[256];				/* The messages lists */
guint32 n_messages[256];			/* Numbers of messages in the lists */
GList   *tail[256];					/* The older message in the lists */

struct message
{
	guchar muid[16];					/* Message UID */
	struct gnutella_node *node;	/* Node from where the message came */
	guint8 function;					/* Type of the message */
};

gchar *debug_msg[256];

#define MAX_MESSAGES_PER_LIST	256	/* So we can remember 256 * 256 = about 65536 messages */

/* ------------------------------------------------------------------------------------------------ */

/* Log function */

void routing_log(gchar *fmt, ...)
{
	static gchar t[4096];

	va_list va;

	va_start(va, fmt);

	g_vsnprintf(t, sizeof(t), fmt, va);

	/* XXX put the log somewhere */

	va_end(va);
}

/* Init function */

void routing_init(void)
{
	guint32 i;

	i_fake_node = 0;			/* Make sure the compiler allocate an address for this guint32 */

	fake_node = (struct gnutella_node *) &(i_fake_node);

	srand(time((time_t *) NULL));

	for (i = 0; i < 16; i++) guid[i]  = rand() % 256;

	for (i = 0; i < 256; i++) { messages[i] = NULL; n_messages[i] = 0; }

	for (i = 0; i < 256; i++) debug_msg[i] = "UNKNOWN MSG  ";

	debug_msg[GTA_MSG_INIT]                = "Ping Request";
	debug_msg[GTA_MSG_INIT_RESPONSE]       = "Ping Reply  ";
	debug_msg[GTA_MSG_SEARCH]              = "Search Req. ";
	debug_msg[GTA_MSG_SEARCH_RESULTS]      = "Search Reply";
}


/* Generate a new muid and put it in a message header */

void message_set_muid(struct gnutella_header *header)
{
	gint i;

	for (i = 0; i < 32; i += 2) (*((guint16 *) (header->muid + i))) = rand() % 65536;
}

/* Erase a node from the routing tables */

void routing_node_remove(struct gnutella_node *node)
{
	GList *l;
	guint32 i;

	for (i = 0; i < 256; i++)
		for (l = messages[i]; l; l = l->next)
			if (((struct message *) l->data)->node == node) ((struct message *) l->data)->node = NULL;
}

/* Adds a new message in the routing tables */

void message_add(guchar *muid, guint8 function, struct gnutella_node *node)
{
	static struct message *m;
	guint8 f = muid[0];

	if (!node)
	{
		node = fake_node;	/* We are the sender of the message */

		routing_log("%-21s %s %s %3d\n", "OURSELVES", debug_msg[function], md5dump(muid), my_ttl);
	}

	if (n_messages[f] >= MAX_MESSAGES_PER_LIST) /* Table is full */
	{
		GList *ct = tail[f];							/* ct is the current tail */

		tail[f] = ct->prev;							/* The new tail is the prev message */

		tail[f]->next = (GList *) NULL;			/* The tail next pointer must be NULL */
		ct->prev      = (GList *) NULL;			/* The head prev pointer must be NULL */

		ct->next = messages[f];						/* The head next pointer = current head */
		messages[f]->prev = ct;						/* Current head is no more the real head */

		messages[f] = ct;								/* The list head change */

		m = (struct message *) ct->data;			/* We'll use the oldest message memory place */
	}
	else /* Table is not full, allocate a new structure and prepend it to the table */
	{
		m = (struct message *) g_malloc(sizeof(struct message));

		n_messages[f]++;
	
		messages[f] = g_list_prepend(messages[f], (gpointer) m);
	
		if (!tail[f]) tail[f] = messages[f];	/* This is the first message in the table */
	}

	memcpy(m->muid, muid, 16);
	m->function = function;
	m->node = node;
}

/* Look for a particular message in the routing tables */

gboolean find_message(guchar *muid, guint8 function, struct gnutella_node **node)
{
	/* Returns TRUE if the message is found */
	/* Set *node to node if there is a connected node associated with the message found */

	static GList *l;

	for (l = messages[(guint8) muid[0]]; l; l = l->next)
	{
		if (!memcmp(((struct message *) l->data)->muid + 1, muid + 1, 15) && ((struct message *) l->data)->function == function)
		{
			/* We found the message */

			*node = ((struct message *) l->data)->node;	/* The node the message came from */
			return TRUE;
		}
	}

	*node = NULL;
	return FALSE; /* Message not found in the tables */
}

/* Main routing function -------------------------------------------------------------------------- */

gboolean route_message(struct gnutella_node **node)
{
	static struct gnutella_node *sender;	/* The node that sent the message */
	static struct gnutella_node *found;		/* The node found in the routing tables */
	static gboolean handle_it;

	sender = (*node);

	routing_log("%-21s ", node_ip(sender));
	routing_log("%s ", debug_msg[sender->header.function]);
	routing_log("%s ", md5dump(sender->header.muid));
	routing_log("%3d/%3d : ", sender->header.ttl, sender->header.hops);

	if (sender->header.function & 0x01) /* The message is a reply */
	{
		if (!find_message(sender->header.muid, sender->header.function & ~(0x01), &found))
		{
			/* We have never seen any request matching this reply ! */

			routing_log("[ ] no request matching the reply !\n");

			sender->dropped++;
			dropped_messages++;
			sender->n_bad++;					/* The node shouldn't have forwarded us this message */

			return FALSE;						/* We don't have to handle the message */
		}

		if (found == fake_node)				/* We are the target of the reply */
		{
			if (sender->header.function == GTA_MSG_INIT_RESPONSE) ping_stats_add(sender);
			routing_log("[H] we are the target\n");
			return TRUE;	
		}

		/* We'll handle all ping replies we receive, even if they are not destinated to us */
		handle_it = (sender->header.function == GTA_MSG_INIT_RESPONSE);

		if (handle_it) routing_log("[H] "); else routing_log("[ ] ");

		if (found)								/* We only have to forward the message the target node */
		{
			if (sender->header.ttl > max_ttl) /* TTL too large, don't forward */
			{
				routing_log("[Max TTL] ");
/*				sender->dropped++; */
/*				dropped_messages++; */
/*				return handle_it; */
			}

			if (!sender->header.ttl || !--sender->header.ttl)	/* TTL expired, message can't go further */
			{
				routing_log("[TTL expired] ");
/*				sender->dropped++; */
/*				dropped_messages++; */
/*				return handle_it; */
			}

			sender->header.hops++;

			routing_log("-> sendto_one(%s)\n", node_ip(found));

			sendto_one(found, (guchar *) &(sender->header), sender->data, sender->size + sizeof(struct gnutella_header));
		}
		else										/* The target node is no more connected to us */
		{
			routing_log("Target no more connected\n");

			routing_errors++;
			sender->dropped++;
			dropped_messages++;
		}

		return handle_it;
	}
	else /* The message is a request */
	{
		if (find_message(sender->header.muid, sender->header.function, &found))
		{
			/* This is a duplicated message */

			if (found == sender)	/* The same node has sent us a message twice ! */
			{
				routing_log("[ ] Dup message (from the same node !)\n");

				routing_errors++;

				/* That should be a really good reason to kick the offender immediately */
				/* But it will kick far too many people nowadays... */

/*				node_remove(sender, "Kicked (sent identical messages twice)"); */
/*				(*node) = NULL; */
			}
			else routing_log("[ ] duplicated\n");

			return FALSE;
		}
		else	/* Never seen this message before */
		{
			if (sender->header.ttl > max_ttl)	/* TTL too large */
			{
				routing_log("[ ] [NEW] Max TTL reached\n");
				sender->dropped++;
				dropped_messages++;
				return FALSE;
			}

			message_add(sender->header.muid, sender->header.function, sender);

			if (!sender->header.ttl || !--sender->header.ttl)	/* TTL expired, message can't go further */
			{
				routing_log("[H] [NEW] (TTL expired)\n");
				sender->dropped++;
				dropped_messages++;
			}
			else 							/* Forward it to all others nodes */
			{
				sender->header.hops++;

				routing_log("[H] [NEW] -> sento_all_but_one()\n");

				sendto_all_but_one(sender, (guchar *) &(sender->header), sender->data, sender->size + sizeof(struct gnutella_header));
			}

			return TRUE;
		}
	}

	return FALSE;
}

/* Sending of messages ---------------------------------------------------------------------------- */

/* Send a message to a specific connected node */

void sendto_one(struct gnutella_node *n, guchar *msg, guchar *data, guint32 size)
{
	g_return_if_fail(n);
	g_return_if_fail(msg);
	g_return_if_fail(size > 0);

	if (n->status != GTA_NODE_CONNECTED) return;

	if ((!data && write(n->socket->file_desc, msg, size) < 0)
	  || (data &&
	        (write(n->socket->file_desc, msg, sizeof(struct gnutella_header)) < 0
		   || write(n->socket->file_desc, data, size - sizeof(struct gnutella_header)) < 0)
		  )
		)
	{
		if (errno == EAGAIN)
		{
			if (node_enqueue(n, msg, sizeof(struct gnutella_header)) && data)
					node_enqueue(n, data, size - sizeof(struct gnutella_header));

			n->sent++;
		}
		else node_remove(n, "Write failed");
	}
	else
	{
		n->sent++;
		gui_update_node(n, FALSE);
	}
}

/* Send a message to all connected nodes but one */

void sendto_all_but_one(struct gnutella_node *o, guchar *msg, guchar *data, guint32 size)
{
	GSList *l = sl_nodes;
	struct gnutella_node *n;

	g_return_if_fail(o);
	g_return_if_fail(msg);
	g_return_if_fail(size > 0);

	while (l)
	{
		n = (struct gnutella_node *) l->data;
		l = l->next;

		if (n->status != GTA_NODE_CONNECTED || n == o) continue;

		if ((!data && write(n->socket->file_desc, msg, size) < 0)
		  || (data &&
		        (write(n->socket->file_desc, msg, sizeof(struct gnutella_header)) < 0
			   || write(n->socket->file_desc, data, size - sizeof(struct gnutella_header)) < 0)
			  )
			)
		{
			if (errno == EAGAIN)
			{
				if (node_enqueue(n, msg, sizeof(struct gnutella_header)) && data)
						node_enqueue(n, data, size - sizeof(struct gnutella_header));

				n->sent++;
			}
			else node_remove(n, "Write failed");
		}
		else
		{
			n->sent++;
			gui_update_node(n, FALSE);
		}
	}
}

/* Send a message to all connected nodes */

void sendto_all(guchar *msg, guchar *data, guint32 size)
{
	GSList *l = sl_nodes;
	struct gnutella_node *n;

	g_return_if_fail(msg);
	g_return_if_fail(size > 0);

	while (l)
	{
		n = (struct gnutella_node *) l->data;
		l = l->next;

		if (n->status != GTA_NODE_CONNECTED) continue;

		if ((!data && write(n->socket->file_desc, msg, size) < 0)
		  || (data &&
		        (write(n->socket->file_desc, msg, sizeof(struct gnutella_header)) < 0
			   || write(n->socket->file_desc, data, size - sizeof(struct gnutella_header)) < 0)
			  )
			)
		{
			if (errno == EAGAIN)
			{
				if (node_enqueue(n, msg, sizeof(struct gnutella_header)) && data)
						node_enqueue(n, data, size - sizeof(struct gnutella_header));

				n->sent++;
			}
			else node_remove(n, "Write failed");
		}
		else
		{
			n->sent++;
			gui_update_node(n, FALSE);
		}
	}
}

/* vi: set ts=3: */

