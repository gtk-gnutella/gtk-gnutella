
/* Gnutella Network Messages routing */

#include "gnutella.h"
#include "search.h" /* For search_passive. */
#include "routing.h"
#include "hosts.h"
#include "misc.h"

#include <stdarg.h>
#include <assert.h>


struct gnutella_node *fake_node;		/* Our fake node */

struct message {
	guchar muid[16];			/* Message UID */
	GSList *nodes;	            /* Nodes from where the message came */
	guint8 function;			/* Type of the message */
};

struct route_data {
	struct gnutella_node * node;
	/* used to know how many messages from this host remain in the
	   routing table */
	guint32 saved_messages; 
};

struct route_data fake_route;		/* Our fake route_data */

gchar *debug_msg[256];

#define MAX_STORED_MESSAGES 65536	/* Max messages we can remember */

GHashTable *messages_hashed; /* we hash the last MAX_STORED_MESSAGES */
/* storage for messages_hashed */
struct message message_array[MAX_STORED_MESSAGES];
guint next_message_index; /* index of the next space to use in message_array */

/*
 * Log function
 */

void routing_log(gchar * fmt, ...)
{
	static gchar t[4096];

	va_list va;

	va_start(va, fmt);

	g_vsnprintf(t, sizeof(t), fmt, va);

	/* XXX put the log somewhere */

	va_end(va);

	/*printf("%s", t); */
}

void decrement_message_counters(GSList *head);

/* just used to ensure type safety when accessing the routing_data field */
struct route_data * get_routing_data(struct gnutella_node *n)
{
	return (struct route_data *)(n->routing_data);
}

/* if a node doesn't currently have routing data attached, this
   creates and attaches some */
void init_routing_data(struct gnutella_node *node)
{
	struct route_data *route;
	
	/* wow, this node hasn't sent any messages before.
	   Allocate and link some routing data to it */
	route = (struct route_data *)g_malloc(sizeof(struct route_data));
	route->node = node;
	route->saved_messages = 0;
	node->routing_data = route;
}

gboolean node_sent_message(struct gnutella_node *n, struct message *m)
{
	GSList *l = m->nodes;
	struct route_data * route;

	
	if (n == fake_node)
		route = &fake_route;
	else
		route = get_routing_data(n);
	
	/* if we've never routed a message from this person before, it can't be
	   a duplicate */
	if (route == NULL)
		return FALSE;
	
	while (l) {
		if (((struct route_data*)l->data) == route)
			return TRUE;
		l = l->next;
	}
	return FALSE;
}

/* compares two message structures */
gint message_compare_func(gconstpointer a, gconstpointer b)
{
	if (memcmp(((struct message *)a)->muid,
		   ((struct message *)b)->muid, 16) == 0)
	{
		if (((struct message *)a)->function
			== ((struct message *)b)->function)
		{
			return TRUE;
		}
	}
	return FALSE;
}

/* hashes message structures for storage in a hash table */
guint message_hash_func(gconstpointer key)
{
	int count;
	guint hash = 0;
	
	for (count = 0; count <= 12; count += 4)
	{
		guint hashadd;
		hashadd = ((struct message *)key)->muid[count] |
			(((struct message *)key)->muid[count + 1] << 8) |
			(((struct message *)key)->muid[count + 2] << 16) |
			(((struct message *)key)->muid[count + 3] << 24);

		hash ^= hashadd;
	}

	hash ^= (guint)((struct message *)key)->function;

	return hash;
}

/* Init function */
void routing_init(void)
{
	guint32 i;

	/*
	 * Make sure it segfaults if we try to access it, but it must be
	 * distinct from NULL.
	 */
	fake_node = (struct gnutella_node *) 0x01;
	fake_route.saved_messages = 0;
	fake_route.node = fake_node;

	srand(time((time_t *) NULL));

	for (i = 0; i < 15; i++)
		guid[i] = rand() & 0xff;

	for (i = 0; i < 256; i++)
		debug_msg[i] = "UNKNOWN MSG	";

	debug_msg[GTA_MSG_INIT] = "Ping Request";
	debug_msg[GTA_MSG_INIT_RESPONSE] = "Ping Reply	";
	debug_msg[GTA_MSG_SEARCH] = "Search Req. ";
	debug_msg[GTA_MSG_SEARCH_RESULTS] = "Search Reply";

	/*
	 * We're a "modern" client, meaning we're not Gnutella 0.56.
	 * Therefore we must set our ninth byte, guid[8] to 0xff, and
	 * put the protocol version number in guid[15].	For 0.4, this
	 * means 0.
	 *				--RAM, 15/09/2001
	 */

	guid[8] = 0xff;
	guid[15] = 0;

	/* should be around for life of program, so should *never*
	   need to be deallocated */
	messages_hashed = g_hash_table_new(message_hash_func, message_compare_func);
	next_message_index = 0;
	/* clear message_array (needed since routing_node_remove() may
	   look through uninitalized messages at any point ) */
	memset(message_array, 0, sizeof(struct message) * MAX_STORED_MESSAGES);
}

/* frees the routing data associated with a message */
static void free_routing_data(gpointer key, gpointer value, gpointer udata)
{
	decrement_message_counters(((struct message *)value)->nodes);
}

void routing_close(void)
{
	g_hash_table_foreach(messages_hashed, free_routing_data, NULL);
	g_hash_table_destroy(messages_hashed);
}

void generate_new_muid(guchar * muid)
{
	static guint32 muid_cnt = 0;		/* Ensure messages we send are unique */
	gint i;

	for (i = 0; i < (16 - sizeof(muid_cnt)); i += 2)
		(*((guint16 *) (muid + i))) = (guint16) (rand() & 0xffff);

	*((guint32 *) (muid + 16 - sizeof(muid_cnt))) = muid_cnt++;
}

/* Generate a new muid and put it in a message header */

void message_set_muid(struct gnutella_header *header)
{
	generate_new_muid(header->muid);
}

void remove_one_message_reference(GSList * cur)
{
	struct route_data *rd = (struct route_data *) cur->data;

	/*
	 * Temporary fix, to try to avoid memory faults at final cleanup,
	 * until I understand the data structures and can tell what is
	 * really wrong.
	 *		--RAM, 28/12/2001
	 */

	if (!rd)
		return;

	if (rd->node != fake_node) {
		rd->saved_messages--;
			
		/* if we have no more messages from this node, and our
		   node has already died, wipe its routing data */
		if (rd->node == NULL && rd->saved_messages == 0) {
			g_free(rd);
			cur->data = NULL;	/* Mark: is freed, don't try again --RAM */
		}
	}
}

/* reduces the messages in routing table count for all nodes in list */

void decrement_message_counters(GSList *head)
{
	GSList * cur;
	
	for (cur = head; cur != NULL; cur = cur->next)
	{
		remove_one_message_reference(cur);
	}
}

/* Erase a node from the routing tables */

void routing_node_remove(struct gnutella_node *node)
{
	struct route_data * route;
	route = get_routing_data(node);

	/* shouldn't be needed, but if someone messes up, we'll get a crash
	   immediately */
	if (route)
	{
		route->node->routing_data = NULL;
		
		/* if no messages remain, we have no reason to keep the
		   route_data around any more */
		if (route->saved_messages == 0)
			g_free(route);
		else
			/* make sure that any future references to this routing
			   data know that we are not connected to a node */
		route->node = NULL;
	}
}

/* Adds a new message in the routing tables */

void message_add(guchar * muid, guint8 function,
				 struct gnutella_node *node)
{
	struct route_data *route;
		
	if (!node)
	{
		route = &fake_route;
		node = fake_node;	/* We are the sender of the message */
		
		routing_log("%-21s %s %s %3d\n", "OURSELVES", debug_msg[function], md5dump(muid), my_ttl);
	}
	else
	{
		if (node->routing_data == NULL)
		{
			init_routing_data(node);
			route = get_routing_data(node);
		}
		else route = node->routing_data;
	}
	
	/* remove the item that previously occupied our storage space, if it
	 * was in the hash table */
	if (message_array[next_message_index].nodes != NULL)
	{
		g_hash_table_remove(messages_hashed, &message_array[next_message_index]);
		decrement_message_counters(message_array[next_message_index].nodes);
		g_slist_free(message_array[next_message_index].nodes);
		message_array[next_message_index].nodes = NULL;
	}

	/* fill in that storage space */
	memcpy(message_array[next_message_index].muid, muid, 16);
	message_array[next_message_index].nodes =
		g_slist_append(message_array[next_message_index].nodes, route);
	message_array[next_message_index].function = function;

	/* insert the new message into the hash table */
	g_hash_table_insert(messages_hashed, &message_array[next_message_index],
		&message_array[next_message_index]);

	route->saved_messages++;
	
	next_message_index++;
	next_message_index %= MAX_STORED_MESSAGES;
}

/* remove references to routing data that is no longer associated with
   a node */
GSList * purge_dangling_references(GSList *head)
{
	GSList * cur = head;
	while (cur)
	{
		if (((struct route_data *)cur->data)->node == NULL)
		{
			GSList * next = cur->next;
			head = g_slist_remove(head, cur->data);
			remove_one_message_reference(cur);
			cur = next;
		}
		else
			cur = cur->next;
	}
	return head;
}

/* Look for a particular message in the routing tables */
gboolean find_message(guchar *muid, guint8 function, struct message **m)
{
	/* Returns TRUE if the message is found */
	/* Set *node to node if there is a connected node associated
	   with the message found */
	struct message dummyMessage;
	struct message * found_message;

	memcpy(dummyMessage.muid, muid, 16);
	dummyMessage.function = function;
	
	found_message = (struct message *)
		g_hash_table_lookup(messages_hashed, &dummyMessage);

	if (!found_message)
	{
		*m = NULL;
		return FALSE;
	}
	else
	{
		/* wipe out dead references to old nodes */
		found_message->nodes = purge_dangling_references(found_message->nodes);

		if (!found_message->nodes)
		{
			*m = NULL;
			return FALSE;
		}
		else
		{
			*m = found_message;
			return TRUE;
		}
	}
}

/*
 * Main routing function
 */

gboolean route_message(struct gnutella_node **node)
{
	static struct gnutella_node *sender;	/* The node that sent the message */
	struct message *m;			/* The copy of the message we've already seen */
	static gboolean handle_it;
	/*
	 * The node to have sent us this message earliest of those we're
	 * still connected to.
	 */
	struct gnutella_node *found;

	sender = (*node);

	/* if we haven't allocated routing data for this node yet, do so */
	if (sender->routing_data == NULL)
		init_routing_data(sender);

	routing_log("%-21s ", node_ip(sender));
	routing_log("%s ", debug_msg[sender->header.function]);
	routing_log("%s ", md5dump(sender->header.muid));
	routing_log("%3d/%3d : ", sender->header.ttl, sender->header.hops);

	if (sender->header.function & 0x01) {
		/* The message is a ping or search reply */
		/*
		 * We'll handle all ping replies we receive, even if they are not
		 * destinated to us
		 */
		handle_it = (sender->header.function == GTA_MSG_INIT_RESPONSE);

		/*
		 * We'll also handle all search replies if we're doing a passive
		 * search
		 */
		handle_it = handle_it
			|| (sender->header.function == GTA_MSG_SEARCH_RESULTS
				&& search_passive);
		if (!find_message
			(sender->header.muid, sender->header.function & ~(0x01), &m)) {
			/* We have never seen any request matching this reply ! */

			routing_log("[ ] no request matching the reply !\n");

			sender->dropped++;
			dropped_messages++;
			sender->n_bad++;	/* Node shouldn't have forwarded this message */

			return handle_it;	/* We don't have to handle the message */
		}

		if (node_sent_message(fake_node, m)) {
			/* We are the target of the reply */
			if (sender->header.function == GTA_MSG_INIT_RESPONSE)
				ping_stats_add(sender);
			routing_log("[H] we are the target\n");
			return TRUE;
		}

		if (handle_it)
			routing_log("[H] ");
		else
			routing_log("[ ] ");

		if (m && m->nodes) {
			/* We only have to forward the message the target node */
			/*
			 * We apply the TTL limits differently for replies.
			 *
			 * Indeed, replies are forwarded to ONE node, and are not
			 * broadcasted.	It is therefore important to make sure the
			 * reply will reach the issuing host.
			 *
			 * So we don't compare the header's TLL to `max_ttl' but to
			 * `hard_ttl_limit', and if above the limit, we don't drop
			 * the message but trim the TTL down to something acceptable.
			 *
			 *				--RAM, 15/09/2001
			 */

			if (sender->header.ttl > hard_ttl_limit) {	/* TTL too large, trim */
				routing_log("[TTL adjusted] ");
				sender->header.ttl = hard_ttl_limit + 1;
			}

			/*
			 * If node propagates messages with TTL=0, it's a danger to
			 * the network, kick him out.
			 *				-- RAM, 15/09/2001
			 */

			if (sender->header.ttl == 0) {
				routing_log("[TTL was 0] ");
				if (connected_nodes() > MAX(2, up_connections)) {
					node_remove(sender, "Kicked: sent message with TTL=0");
					(*node) = NULL;
				} else {
					sender->dropped++;
					sender->n_bad++;
				}
				dropped_messages++;
				return FALSE;	/* Don't handle, shouldn't have seen it */
			}

			if (!--sender->header.ttl) {
				/* TTL expired, message stops here */
				routing_log("[TTL expired] ");
				sender->dropped++;
				dropped_messages++;
				return handle_it;
			}

			sender->header.hops++;

			found = ((struct route_data *) m->nodes->data)->node;

			routing_log("-> sendto_one(%s)\n", node_ip(found));

			sendto_one(found, (guchar *) & (sender->header), sender->data,
					   sender->size + sizeof(struct gnutella_header));
		} else {				/* The target node is no more connected to us */

			routing_log("Target no more connected\n");

			routing_errors++;
			sender->dropped++;
			dropped_messages++;
		}

		return handle_it;
	} else {
		/* The message is a request */

		if (find_message(sender->header.muid, sender->header.function, &m)) {
			/* This is a duplicated message */

			if (node_sent_message(sender, m)) {
				/* The same node has sent us a message twice ! */
				routing_log("[ ] Dup message (from the same node !)\n");

				routing_errors++;

				/*
				 * That is a really good reason to kick the offender
				 * But do so only if killing this node would not bring
				 * us too low in node count, and if they have sent enough
				 * dups to be sure it's not bad luck in MUID generation.
				 * Finally, check the ratio of dups on received messages,
				 * because a dup once in a while is nothing.
				 *				--RAM, 08/09/2001
				 */

				/* XXX max_dup_msg & max_dup_ratio XXX ***/

				if (++(sender->n_dups) > min_dup_msg &&
					connected_nodes() > MAX(2, up_connections) &&
					sender->n_dups >
						(guint16) (min_dup_ratio / 100.0 * sender->received)
				) {
					node_remove(sender, "Kicked: sent %d dups (%.1f%% of RX)",
						sender->n_dups, sender->received ?
							100.0 * sender->n_dups / sender->received :
							0.0);
					(*node) = NULL;
				} else {
					sender->n_bad++;
					dropped_messages++;
				}
			} else {
				routing_log("[ ] duplicated\n");
				if (node_sent_message(fake_node, m)) {
					/* node sent us our own search, which may be ok if they've
					 * just connected and sent it before they read our reissue
					 * of the search, or if we've sent them  the search with a
					 * new muid. */
				} else {
					struct route_data * route;
					/* append so that we route matches to the one that sent it
					 * to us first; ie., presumably the one closest to the
					 * original sender. */
					route = get_routing_data(sender);
					m->nodes = g_slist_append(m->nodes, route);
					route->saved_messages++;
				}
			}
			return FALSE;
		} else {				/* Never seen this message before */
			
			/* Drop messages that would travel way too many nodes --RAM */
			if (sender->header.ttl + sender->header.hops > hard_ttl_limit) {
				routing_log("[ ] [NEW] Hard TTL limit reached\n");

				/*
				 * When close neighboors of that node send messages we drop
				 * that way, they may try to flood the network.	Disconnect
				 * after too many offenses, which should have given the
				 * relaying node ample time to kick the offender out,
				 * according to our standards.
				 *				--RAM, 08/09/2001
				 */

				/* XXX max_high_ttl_radius & max_high_ttl_msg XXX */

				sender->n_hard_ttl++;
				if (sender->header.hops <= max_high_ttl_radius &&
					sender->n_hard_ttl > max_high_ttl_msg) {
					node_remove(sender,
								"Kicked: relayed %d high TTL messages",
								sender->n_hard_ttl);
					(*node) = NULL;
				} else {
					sender->dropped++;
					dropped_messages++;
				}
				return FALSE;
			}

			if (sender->header.ttl > max_ttl)	/* TTL too large */
				sender->header.ttl = max_ttl;	/* Trim down */

			/*
			 * If node propagates messages with TTL=0, it's a danger to
			 * the network, kick him out.
			 *				-- RAM, 15/09/2001
			 */

			if (sender->header.ttl == 0) {
				routing_log("[ ] [NEW] TTL was 0\n");
				if (connected_nodes() > MAX(2, up_connections)) {
					node_remove(sender, "Kicked: sent message with TTL=0");
					(*node) = NULL;
				} else {
					sender->dropped++;
					sender->n_bad++;
				}
				dropped_messages++;
				return FALSE;	/* Don't handle, shouldn't have seen it */
			}

			message_add(sender->header.muid, sender->header.function,
						sender);

			sender->header.hops++;	/* Going to handle it, must be accurate */

			if (!--sender->header.ttl) {
				/* TTL expired, message stops here */
				routing_log("[H] [NEW] (TTL expired)\n");
				sender->dropped++;
				dropped_messages++;
			} else {			/* Forward it to all others nodes */

				routing_log("[H] [NEW] -> sento_all_but_one()\n");
				sendto_all_but_one(sender,
								   (guchar *) & (sender->header),
								   sender->data,
								   sender->size +
								   sizeof(struct gnutella_header));
			}

			return TRUE;
		}
	}

	return FALSE;
}

/*
 * Sending of messages
 */

/* Send a message to a specific connected node */

void sendto_one(struct gnutella_node *n, guchar * msg, guchar * data,
				guint32 size)
{
	g_return_if_fail(n);
	g_return_if_fail(msg);
	g_return_if_fail(size > 0);


	if (!NODE_IS_CONNECTED(n))
		return;

	if (!data || size == sizeof(struct gnutella_header)) {
		if (node_enqueue(n, msg, size)) {
			node_enqueue_end_of_packet(n);
		}
	} else {
		if (node_enqueue(n, msg, sizeof(struct gnutella_header))) {
			if (node_enqueue
				(n, data, size - sizeof(struct gnutella_header))) {
				node_enqueue_end_of_packet(n);
			}
		}
	}
}

/* Send a message to all connected nodes but one */

void sendto_all_but_one(struct gnutella_node *o, guchar * msg,
						guchar * data, guint32 size)
{
	GSList *l;
	struct gnutella_node *n;

	g_return_if_fail(o);
	g_return_if_fail(msg);
	g_return_if_fail(size > 0);

	for (l = sl_nodes; l; l = l->next) {
		n = (struct gnutella_node *) l->data;
		if (n != o)
			sendto_one(n, msg, data, size);
	}
}

/* Send a message to all connected nodes */

void sendto_all(guchar * msg, guchar * data, guint32 size)
{
	GSList *l;
	struct gnutella_node *n;

	g_return_if_fail(msg);
	g_return_if_fail(size > 0);

	for (l = sl_nodes; l; l = l->next) {
		n = (struct gnutella_node *) l->data;
		sendto_one(n, msg, data, size);
	}
}

/* vi: set ts=4: */
