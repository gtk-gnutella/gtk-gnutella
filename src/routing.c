
/* Gnutella Network Messages routing */

#include "gnutella.h"
#include "search.h" /* For search_passive. */
#include "routing.h"
#include "hosts.h"
#include "misc.h"
#include "gmsg.h"

#include <stdarg.h>
#include <assert.h>


struct gnutella_node *fake_node;		/* Our fake node */

struct message {
	guchar muid[16];			/* Message UID */
	GSList *nodes;	            /* route_data from where the message came */
	guint8 function;			/* Type of the message */
};

struct route_data {
	struct gnutella_node * node;
	gint32 saved_messages; 		/* # msg from this host in routing table */
};

struct route_data fake_route;		/* Our fake route_data */

gchar *debug_msg[256];

#define MAX_STORED_MESSAGES 65536	/* Max messages we can remember */

/*
 * We're using the message table to store Query hit routes for Push requests,
 * but this is a temporary solution.  As we continuously refresh those
 * routes, we must make sure they stay alive for some time after having been
 * updated.  Given that we periodically supersede the message_array[] in a
 * round-robin fashion, it is not really appropriate.
 *		--RAM, 06/01/2002
 */
#define QUERY_HIT_ROUTE_SAVE	0	/* Function used to store QHit GUIDs */

GHashTable *messages_hashed; /* we hash the last MAX_STORED_MESSAGES */
/* storage for messages_hashed */
struct message message_array[MAX_STORED_MESSAGES];
guint next_message_index; /* index of the next space to use in message_array */

static gboolean find_message(guchar *muid, guint8 function, struct message **m);

/*
 * Log function
 */

void routing_log(gchar * fmt, ...)
{
	static gchar t[4096];
	va_list va;

	va_start(va, fmt);
	g_vsnprintf(t, sizeof(t), fmt, va);
	va_end(va);

	if (dbg > 8)
		printf("%s", t);
}

static void decrement_message_counters(GSList *head);

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

	g_assert(node->routing_data == NULL);
	
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

/*
 * patch_muid_for_modern_node
 *
 * Make sure the MUID we use in initial handshaking pings are marked
 * specially to indicate we're modern nodes.
 */
static void patch_muid_for_modern_node(guchar *muid)
{
	/*
	 * We're a "modern" client, meaning we're not Gnutella 0.56.
	 * Therefore we must set our ninth byte, muid[8] to 0xff, and
	 * put the protocol version number in muid[15].	For 0.4, this
	 * means 0.
	 *				--RAM, 15/09/2001
	 */

	muid[8] = 0xff;
	muid[15] = 1;		/* Now capable of ping/pong reduction */
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
	patch_muid_for_modern_node(guid);

	for (i = 0; i < 256; i++)
		debug_msg[i] = "UNKN ";

	debug_msg[GTA_MSG_INIT]           = "Ping ";
	debug_msg[GTA_MSG_INIT_RESPONSE]  = "Pong ";
	debug_msg[GTA_MSG_SEARCH]         = "Query";
	debug_msg[GTA_MSG_SEARCH_RESULTS] = "Q-Hit";
	debug_msg[GTA_MSG_PUSH_REQUEST]   = "Push ";

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
	g_slist_free(((struct message *)value)->nodes);
	((struct message *)value)->nodes = NULL;
}

void routing_close(void)
{
	g_assert(messages_hashed);
	
	g_hash_table_foreach(messages_hashed, free_routing_data, NULL);
	g_hash_table_destroy(messages_hashed);
	messages_hashed = NULL;
}

/*
 * generate_new_muid
 *
 * Generate a new random message ID.  We will never send the same MUID twice
 * due to the use of a counter.
 *
 * If `modern' is true, then patch it to indicate we're a "modern node".
 * If `modern' is false, it probably does not matter.
 */
void generate_new_muid(guchar *muid, gboolean modern)
{
	static guint32 muid_cnt = 0;		/* Ensure messages we send are unique */
	gint i;

	/*
	 * We place our unique counter at offset 4, and it is 4 bytes long
	 * hence the tweaking with `k', and the upper bound for `i' of 12.
	 */

	for (i = 0; i < 12; i += 2) {
		gint k = (i < 4) ? i : (i + 4);
		(*((guint16 *) (muid + k))) = (guint16) (rand() & 0xffff);
	}

	*((guint32 *) (muid + 4)) = muid_cnt++;

	if (modern)
		patch_muid_for_modern_node(muid);
	else {
		if (muid[8] == 0xff)	/* To not confuse it with special GUID... */
			muid[8] = 0x00;		/* the 9th byte cannot be 0xff */
	}
}

/*
 * message_set_muid
 *
 * Generate a new muid and put it in a message header.
 */
void message_set_muid(struct gnutella_header *header, gboolean modern)
{
	generate_new_muid(header->muid, modern);
}

static void remove_one_message_reference(GSList * cur)
{
	struct route_data *rd = (struct route_data *) cur->data;

	g_assert(rd);

	if (rd->node != fake_node) {
		g_assert(rd->saved_messages > 0);
		rd->saved_messages--;
		/* if we have no more messages from this node, and our
		   node has already died, wipe its routing data */
		if (rd->node == NULL && rd->saved_messages == 0) {
			g_free(rd);
			cur->data = NULL;	/* Mark as freed, don't try again --RAM */
		}
	}
}

/* reduces the messages in routing table count for all nodes in list */

static void decrement_message_counters(GSList *head)
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

	g_assert(route);
	g_assert(route->node == node);
	route->node->routing_data = NULL;

	/* make sure that any future references to this routing
	   data know that we are not connected to a node */
	route->node = NULL;
	
	/* if no messages remain, we have no reason to keep the
	   route_data around any more */

	if (route->saved_messages == 0)
		g_free(route);
}

/* Adds a new message in the routing tables */

void message_add(guchar * muid, guint8 function,
				 struct gnutella_node *node)
{
	struct route_data *route;
	static time_t last_rotation = 0;

	if (last_rotation == 0)
		last_rotation = time((time_t) NULL);

	if (!node)
	{
		struct message *m;

		if (find_message(muid, function, &m)) {
			g_assert(m->nodes);		/* We're still there! */
			routing_log("ROUTE %-21s %s %s %3d [already sent]\n", "OURSELVES",
				debug_msg[function], guid_hex_str(muid), my_ttl);
			return;
		}

		route = &fake_route;
		node = fake_node;	/* We are the sender of the message */
		
		routing_log("ROUTE %-21s %s %s %3d\n", "OURSELVES",
			debug_msg[function], guid_hex_str(muid), my_ttl);
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

		if (dbg && next_message_index == 0) {
			time_t now = time((time_t) NULL);
			int elapsed = now - last_rotation;

			printf("Cycling through route table after %d seconds\n", elapsed);
			last_rotation = now;
		}
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
	
	if (++next_message_index >= MAX_STORED_MESSAGES)
		next_message_index = 0;
}

/* remove references to routing data that is no longer associated with
   a node */
static GSList * purge_dangling_references(GSList *head)
{
	GSList * cur = head;
	while (cur)
	{
		if (((struct route_data *)cur->data)->node == NULL)
		{
			GSList * next = cur->next;
			head = g_slist_remove_link(head, cur);
			remove_one_message_reference(cur);
			g_slist_free_1(cur);
			cur = next;
		}
		else
			cur = cur->next;
	}
	return head;
}

/*
 * find_message
 *
 * Look for a particular message in the routing tables.
 *
 * If we find the message, returns true, otherwise false.
 *
 * If none of the nodes that sent us the message are still present, then
 * m->nodes will be NULL.
 */
static gboolean find_message(guchar *muid, guint8 function, struct message **m)
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

	if (!found_message) {
		*m = NULL;
		return FALSE;		/* We don't remember about this message */
	} else {
		/* wipe out dead references to old nodes */
		found_message->nodes = purge_dangling_references(found_message->nodes);

		*m = found_message;
		return TRUE;		/* Message was seen */
	}
}
	
/*
 * forward_message
 *
 * Forwards message to one node if `target' is non-NULL, or to all nodes but
 * the sender otherwise.  If we kick the node, then *node is set to NULL.
 * The message is not physically sent yet, but the `dest' structure is filled
 * with proper routing information.
 *
 * Returns whether we should handle the message after routing.
 */
static gboolean forward_message(struct gnutella_node **node,
	struct gnutella_node *target, struct route_dest *dest)
{
	struct gnutella_node *sender = *node;

	/* Drop messages that would travel way too many nodes --RAM */
	if (sender->header.ttl + sender->header.hops > hard_ttl_limit) {
		routing_log("[ ] [NEW] hard TTL limit reached\n");

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
		sender->rx_dropped++;
		dropped_messages++;

		if (sender->header.hops <= max_high_ttl_radius &&
			sender->n_hard_ttl > max_high_ttl_msg
		) {
			node_bye(sender, 403, "Relayed %d high TTL (>%d) messages",
				sender->n_hard_ttl, max_high_ttl_msg);
			(*node) = NULL;
		}

		return FALSE;
	}

	/*
	 * If node propagates messages with TTL=0, it's a danger to
	 * the network, kick him out.
	 *				-- RAM, 15/09/2001
	 */

	if (sender->header.ttl == 0) {
		routing_log("[ ] [NEW] TTL was 0\n");
		if (node_sent_ttl0(sender))
			(*node) = NULL;
		return FALSE;	/* Don't handle, shouldn't have seen it */
	}

	routing_log("[H] [NEW] ");

	if (sender->header.ttl > max_ttl) {	/* TTL too large */
		sender->header.ttl = max_ttl;	/* Trim down */
		routing_log("(TTL trimmed down to %d) ", max_ttl);
	}


	message_add(sender->header.muid, sender->header.function, sender);

	sender->header.hops++;	/* Going to handle it, must be accurate */

	if (!--sender->header.ttl) {
		/* TTL expired, message stops here */
		routing_log("(TTL expired)\n");
		dropped_messages++;
		/* don't increase rx_dropped, we'll handle this message */
	} else {			/* Forward it to all others nodes */
		if (target) {
			routing_log("-> sendto_one(%s)\n", node_ip(target));
			dest->type = ROUTE_ONE;
			dest->node = target;
		} else {
			routing_log("-> sendto_all_but_one()\n");
			dest->type = ROUTE_ALL_BUT_ONE;
			dest->node = sender;
		}
	}

	return TRUE;
}

/*
 * route_message
 *
 * Main route computation function.
 *
 * Source of message is passed by reference as `node', because it can be
 * nullified when the node is disconnected from.
 *
 * The destination of the message is computed in `dest', but the message is
 * not physically sent.  The gmsg_sendto_route() will have to be called
 * for that.
 *
 * Returns whether the message is to be handled locally.
 */
gboolean route_message(struct gnutella_node **node, struct route_dest *dest)
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
	dest->type = ROUTE_NONE;

	/* if we haven't allocated routing data for this node yet, do so */
	if (sender->routing_data == NULL)
		init_routing_data(sender);

	routing_log("ROUTE %-21s ", node_ip(sender));
	routing_log("%s ", debug_msg[sender->header.function]);
	routing_log("%s ", guid_hex_str(sender->header.muid));
	routing_log("%3d/%3d : ", sender->header.hops, sender->header.ttl);

	/*
	 * We no longer route Pings through here.
	 * And we use the special 0 function to record routes taken by Query Hits,
	 * based on the responding servent ID.
	 */

	g_assert(sender->header.function != QUERY_HIT_ROUTE_SAVE);

	if (sender->header.function & 0x01) {
		/*
		 * We'll also handle all search replies if we're doing a passive
		 * search, or if we don't have the vendor ID yet and the hop count
		 * is 0.
		 */
		handle_it = sender->header.function == GTA_MSG_SEARCH_RESULTS &&
			(search_passive || (!sender->vendor && sender->header.hops == 0));

		/*
		 * If message is a Query Hit, we have to record we have seen a
		 * reply from the GUID held at the tail of the packet.  This
		 * information is used to later route back Push messages.
		 *		--RAM, 06/01/2002
		 */

		if (sender->header.function == GTA_MSG_SEARCH_RESULTS) {
			guchar *guid = sender->data + sender->size - 16;
			g_assert(sender->size >= 16);

			if (!find_message(guid, QUERY_HIT_ROUTE_SAVE, &m)) {
				/*
				 * We've never seen any Query Hit from that servent.
				 */

				message_add(guid, QUERY_HIT_ROUTE_SAVE, sender);
			} else if (m->nodes == NULL || !node_sent_message(sender, m)) {
				struct route_data *route;

				/*
				 * Either we have no more nodes that sent us any query hit
				 * from that GUID, or we have never received any such hit
				 * from the sender.
				 */

				route = get_routing_data(sender);
				m->nodes = g_slist_append(m->nodes, route);
				route->saved_messages++;
			}
		}

		if (!find_message
			(sender->header.muid, sender->header.function & ~(0x01), &m)) {
			/* We have never seen any request matching this reply ! */

			routing_log("[ ] no request matching the reply !\n");

			sender->rx_dropped++;
			dropped_messages++;
			sender->n_bad++;	/* Node shouldn't have forwarded this message */

			return handle_it;	/* We don't have to handle the message */
		}

		g_assert(m);		/* Or find_message() would have returned FALSE */

		/*
		 * If `m->nodes' is NULL, we have seen the request, but unfortunately
		 * none of the nodes that sent us the request is connected any more.
		 */

		if (m->nodes == NULL) {
			routing_log("[%c] route to target lost\n",
				handle_it ? 'H' : ' ');

			routing_errors++;
			sender->rx_dropped++;
			dropped_messages++;

			return handle_it;
		}

		if (node_sent_message(fake_node, m)) {
			/* We are the target of the reply */
			routing_log("[H] we are the target\n");
			return TRUE;
		}

		routing_log("[%c] ", handle_it ? 'H' : ' ');

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
			routing_log("(TTL adjusted) ");
			sender->header.ttl = hard_ttl_limit + 1;
		}

		/*
		 * If node propagates messages with TTL=0, it's a danger to
		 * the network, kick him out.
		 *				-- RAM, 15/09/2001
		 */

		if (sender->header.ttl == 0) {
			routing_log("(TTL was 0)\n");
			if (node_sent_ttl0(sender))
				(*node) = NULL;
			return FALSE;	/* Don't handle, shouldn't have seen it */
		}

		if (!--sender->header.ttl) {
			/* TTL expired, message stops here */
			routing_log("(TTL expired)\n");
			dropped_messages++;
			sender->rx_dropped++;
			return handle_it;
		}

		sender->header.hops++;

		found = ((struct route_data *) m->nodes->data)->node;

		routing_log("-> sendto_one(%s)\n", node_ip(found));

		dest->type = ROUTE_ONE;
		dest->node = found;

		return handle_it;
	} else {
		/*
		 * Message is a request.
		 */

		if (find_message(sender->header.muid, sender->header.function, &m)) {
			/*
			 * This is a duplicated message, which we're going to drop.
			 */

			dropped_messages++;
			sender->rx_dropped++;

			if (m->nodes && node_sent_message(sender, m)) {
				/* The same node has sent us a message twice ! */
				routing_log("[ ] dup message (from the same node!)\n");

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
					node_bye(sender, 401, "Sent %d dups (%.1f%% of RX)",
						sender->n_dups, sender->received ?
							100.0 * sender->n_dups / sender->received :
							0.0);
					(*node) = NULL;
				} else
					sender->n_bad++;
			} else {
				struct route_data * route;

				if (m->nodes == NULL)
					routing_log("[ ] dup message, original route lost\n");
				else
					routing_log("[ ] dup message\n");

				/* append so that we route matches to the one that sent it
				 * to us first; ie., presumably the one closest to the
				 * original sender. */

				route = get_routing_data(sender);
				m->nodes = g_slist_append(m->nodes, route);
				route->saved_messages++;
			}

			return FALSE;
		}

		/*
		 * A Push request is not broadcasted as other requests, it is routed
		 * back along the nodes that have seen Query Hits from the target
		 * servent of the Push.
		 */

		if (sender->header.function == GTA_MSG_PUSH_REQUEST) {
			/*
			 * The GUID of the target are the leading bytes of the Push
			 * message, hence we pass `sender->data' to find_message().
			 */

			g_assert(sender->size > 16);	/* Must be a valid push */

			if (
				!find_message(sender->data, QUERY_HIT_ROUTE_SAVE, &m) ||
				m->nodes == NULL
			) {
				if (0 == memcmp(guid, sender->data, 16)) {
					routing_log("[H] we are the target\n");
					return TRUE;
				}

				if (m && m->nodes == NULL)
					routing_log("[ ] route to target GUID %s gone\n",
						guid_hex_str(sender->data));
				else
					routing_log("[ ] no route to target GUID %s\n",
						guid_hex_str(sender->data));

				routing_errors++;
				dropped_messages++;
				sender->rx_dropped++;

				return FALSE;
			}

			forward_message(node,
				((struct route_data *) m->nodes->data)->node, dest);

			return FALSE;		/* We are not the target, don't handle it */
		} else {
			/*
			 * The message is a request to broadcast.
			 */

			if (!NODE_IS_READABLE(sender)) {		/* Being shutdown */
				dropped_messages++;
				sender->rx_dropped++;
				return FALSE;
			}

			/* If the node is flow-controlled on TX, then it is preferable
			 * to drop queries immediately: the traffic the replies may
			 * generate could pile up and make the queue reach its maximum
			 * size.  It is hoped that the flow control condition will not
			 * last too long.
			 *
			 * We do that here, at the lowest level, because we do not
			 * want to record the query as seen: if it comes from another
			 * route, we'll handle it.
			 *
			 *		--RAM, 02/02/2002
			 */

			if (
				sender->header.function == GTA_MSG_SEARCH &&
				NODE_IN_TX_FLOW_CONTROL(sender)
			) {
				if (dbg > 3)
					gmsg_log_dropped(&sender->header,
						"from %s, in TX flow-control", node_ip(sender));

				dropped_messages++;
				sender->rx_dropped++;

				return FALSE;
			}

			return forward_message(node, NULL, dest);		/* Broadcast */
		}
	}

	g_warning("BUG: fell through route_message");

	return FALSE;
}

/*
 * route_towards_guid
 *
 * Check whether we have a route to the given GUID, in order to send
 * pushes.
 *
 * Returns NULL if we have no such route, or the node to which we should
 * send the packet otherwise.
 */
struct gnutella_node *route_towards_guid(guchar *guid)
{
	struct message *m;

	if (!find_message(guid, QUERY_HIT_ROUTE_SAVE, &m) || m->nodes == NULL)
		return NULL;

	return ((struct route_data *) m->nodes->data)->node;
}

/* vi: set ts=4: */
