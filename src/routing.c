/*
 * $Id$
 *
 * Copyright (c) 2001-2002, Raphael Manfredi
 *
 * Gnutella Network Messages routing.
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

#include "search.h" /* For search_passive. */
#include "routing.h"
#include "hosts.h"
#include "gmsg.h"
#include "nodes.h"
#include "guid.h"
#include "gnet_stats.h"

#include <stdarg.h>

struct gnutella_node *fake_node;		/* Our fake node */

struct message {
	guchar muid[16];			/* Message UID */
	GSList *routes;	            /* route_data from where the message came */
	guint8 function;			/* Type of the message */
};

/*
 * We don't store a list of nodes in the message structure, but a list of
 * route_data: the reason is that nodes can go away, but we don't want to
 * traverse the whole routing table to reclaim all the places where they
 * were referenced.
 *
 * The route_data structure points to a node and keeps track of the amount of
 * messages that it is used to track.  When a node disappears, the `node' field
 * in the associated route_data structure is set to NULL.  Dangling references
 * are removed only when needed.
 */
struct route_data {
	struct gnutella_node *node;
	gint32 saved_messages; 		/* # msg from this host in routing table */
};

struct route_data fake_route;		/* Our fake route_data */

static gchar *debug_msg[256];

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

/*
 * Routing table data structures.
 */

struct message message_array[MAX_STORED_MESSAGES];
GHashTable *messages_hashed; 	/* we hash the last MAX_STORED_MESSAGES */
guint next_message_index;		/* next slot to use in message_array */

static gboolean find_message(guchar *muid, guint8 function, struct message **m);

/*
 * "banned" GUIDs for push routing.
 *
 * The following GUIDs are so common that it does not make sense to
 * route pushes to them (i.e. they are are NOT unique on the network!).
 */
static guchar *banned_push[] = {
	"20d262ff0e6fd6119734004005a207b1",		/* Morpheus, 29/06/2002 */
};
GHashTable *ht_banned_push = NULL;

#define BANNED_PUSH_COUNT	(sizeof(banned_push) / sizeof(banned_push[0]))

/*
 * Log function
 */

void routing_log(gchar * fmt, ...)
{
	va_list va;

	if (dbg <= 8)
		return;

	va_start(va, fmt);
	vprintf(fmt, va);
	va_end(va);
}

static void free_route_list(struct message *m);

/* just used to ensure type safety when accessing the routing_data field */
static struct route_data * get_routing_data(struct gnutella_node *n)
{
	return (struct route_data *)(n->routing_data);
}

/* if a node doesn't currently have routing data attached, this
   creates and attaches some */
void init_routing_data(struct gnutella_node *node)
{
	struct route_data *route;

	g_assert(node->routing_data == NULL);
	
	/*
	 * Wow, this node hasn't sent any messages before.
	 * Allocate and link some routing data to it
	 */

	route = (struct route_data *) g_malloc(sizeof(struct route_data));

	route->node = node;
	route->saved_messages = 0;
	node->routing_data = route;
}

static gboolean node_sent_message(struct gnutella_node *n, struct message *m)
{
	GSList *l;
	struct route_data * route;

	if (n == fake_node)
		route = &fake_route;
	else
		route = get_routing_data(n);
	
	/*
	 * If we've never routed a message from this person before,
	 * it can't be a duplicate.
	 */

	if (route == NULL)
		return FALSE;
	
	for (l = m->routes; l; l = l->next) {
		if (route == ((struct route_data *) l->data))
			return TRUE;
	}

	return FALSE;
}

/* compares two message structures */
gint message_compare_func(gconstpointer a, gconstpointer b)
{
	return
		0 == memcmp(((struct message *) a)->muid,
			((struct message *) b)->muid, 16)
		&& ((struct message *) a)->function ==
			((struct message *) b)->function;
}

/* hashes message structures for storage in a hash table */
guint message_hash_func(gconstpointer key)
{
	int count;
	guint hash = 0;
	
	for (count = 0; count <= 12; count += 4) {
		guint hashadd =
			( (struct message *) key)->muid[count]            |
			(((struct message *) key)->muid[count + 1] << 8)  |
			(((struct message *) key)->muid[count + 2] << 16) |
			(((struct message *) key)->muid[count + 3] << 24);

		hash ^= hashadd;
	}

	hash ^= (guint) ((struct message *) key)->function;

	return hash;
}

/* Init function */
void routing_init(void)
{
    guint8 guid_buf[16];
	guint32 i;
	gboolean need_guid = TRUE;
	extern guint guid_hash(gconstpointer key);		/* from atoms.c */
	extern gint guid_eq(gconstpointer a, gconstpointer b);

	/*
	 * Make sure it segfaults if we try to access it, but it must be
	 * distinct from NULL.
	 */
	fake_node = (struct gnutella_node *) 0x01;
	fake_route.saved_messages = 0;
	fake_route.node = fake_node;

	/*
	 * Initialize the banned GUID hash.
	 */

	ht_banned_push = g_hash_table_new(guid_hash, guid_eq);

	for (i = 0; i < BANNED_PUSH_COUNT; i++) {
		guchar g[16];
		guchar *hex = banned_push[i];

		g_assert(strlen(hex) == 2*sizeof(g));

		hex_to_guid(hex, g);
		g_hash_table_insert(ht_banned_push, atom_guid_get(g), (gpointer) 1);
	}

	/*
	 * Only generate a new GUID for this servent if all entries are 0.
	 * The empty initialization happens in config_init(), but it can be
	 * overridden by the GUID read from the configuration file
	 * (persistent GUID).
	 *		--RAM, 08/03/2002
	 */

    gnet_prop_get_storage(PROP_GUID, guid_buf, sizeof(guid_buf));

	for (i = 0; i < 15; i++) {
		if (guid_buf[i]) {
			need_guid = FALSE;
			break;
		}
	}

	if (!guid_is_gtkg(guid_buf, NULL, NULL, NULL))
		need_guid = TRUE;

retry:
	if (need_guid)
		guid_ping_muid(guid_buf);		/* We want a "modern" GUID */

	/*
	 * If by extraordinary, we have generated a banned GUID, retry.
	 */

	if (g_hash_table_lookup(ht_banned_push, guid_buf)) {
		need_guid = TRUE;
		goto retry;
	}

    gnet_prop_set_storage(PROP_GUID, guid_buf, sizeof(guid_buf));

	/*
	 * Initialize message type array for routing logs.
	 */

	for (i = 0; i < 256; i++)
		debug_msg[i] = "UNKN ";

	debug_msg[GTA_MSG_INIT]           = "Ping ";
	debug_msg[GTA_MSG_INIT_RESPONSE]  = "Pong ";
	debug_msg[GTA_MSG_SEARCH]         = "Query";
	debug_msg[GTA_MSG_SEARCH_RESULTS] = "Q-Hit";
	debug_msg[GTA_MSG_PUSH_REQUEST]   = "Push ";
	debug_msg[GTA_MSG_VENDOR]         = "Vndor";

	/*
	 * Should be around for life of program, so should *never*
	 * need to be deallocated
	 */

	messages_hashed = g_hash_table_new(message_hash_func, message_compare_func);
	next_message_index = 0;

	memset(message_array, 0, sizeof(message_array));
}

/*
 * message_set_muid
 *
 * Generate a new muid and put it in a message header.
 */
void message_set_muid(struct gnutella_header *header, guint8 function)
{
	switch (function) {
	case GTA_MSG_PUSH_REQUEST:
	case GTA_MSG_BYE:
		guid_random_muid(header->muid);
		break;
	case GTA_MSG_INIT:
		guid_ping_muid(header->muid);
		break;
	default:
		g_error("unexpected message type %d", function);
	}
}

/*
 * remove_one_message_reference
 *
 * The route references one less message.
 *
 * If the amount of messages referenced reaches 0 and the associated node
 * was removed, free the route structure.
 */
static void remove_one_message_reference(struct route_data *rd)
{
	g_assert(rd);

	if (rd->node != fake_node) {
		g_assert(rd != &fake_route);
		g_assert(rd->saved_messages > 0);

		rd->saved_messages--;

		/*
		 * If we have no more messages from this node, and our
		 *  node has already died, wipe its routing data
		 */

		if (rd->node == NULL && rd->saved_messages == 0)
			g_free(rd);
	} else
		g_assert(rd == &fake_route);
}

/*
 * free_route_list
 *
 * Dispose of route list in message.
 */
static void free_route_list(struct message *m)
{
	GSList *l;

	g_assert(m);
	
	for (l = m->routes; l; l = l->next)
		remove_one_message_reference((struct route_data *) l->data);

	g_slist_free(m->routes);
	m->routes = NULL;
}

/* Erase a node from the routing tables */

void routing_node_remove(struct gnutella_node *node)
{
	struct route_data *route = get_routing_data(node);

	g_assert(route);
	g_assert(route->node == node);

	route->node->routing_data = NULL;

	/*
	 * Make sure that any future references to this routing
	 * data know that we are not connected to a node.
	 */

	route->node = NULL;
	
	/*
	 * If no messages remain, we have no reason to keep the
	 * route_data around any more.
	 */

	if (route->saved_messages == 0)
		g_free(route);
}

/* Adds a new message in the routing tables */

void message_add(guchar * muid, guint8 function,
				 struct gnutella_node *node)
{
	static time_t last_rotation = 0;
	static gboolean cycled = FALSE;
	struct route_data *route;
	struct message *entry;

	if (last_rotation == 0)
		last_rotation = time((time_t) NULL);

	if (!node) {
		struct message *m;

		if (find_message(muid, function, &m)) {

			/*
			 * It is possible that we insert the message in the routing table,
			 * then it gets "garbage collected" through a cycling, and then
			 * we receive our own message back from the network, at which
			 * time it is re-inserted into the table.  Therefore, despite our
			 * re-issuing of our own (search) message, there might not
			 * actually be any entry for us.
			 *		--RAM, 21/02/2002
			 */

			if (node_sent_message(fake_node, m)) {
				routing_log("ROUTE %-21s %s %s %3d/%3d [already sent]\n",
					"OURSELVES", debug_msg[function],
					guid_hex_str(muid), 0, my_ttl);
				return;
			}

			routing_log("ROUTE %-21s %s %s %3d/%3d [forgot we sent it]\n",
					"OURSELVES", debug_msg[function],
					guid_hex_str(muid), 0, my_ttl);
		} else
			routing_log("ROUTE %-21s %s %s %3d/%3d\n", "OURSELVES",
				debug_msg[function], guid_hex_str(muid), 0, my_ttl);

		route = &fake_route;
		node = fake_node;		/* We are the sender of the message */
	} else {
		if (node->routing_data == NULL)
			init_routing_data(node);
		route = get_routing_data(node);
	}

	entry = &message_array[next_message_index];
	
	/*
	 * If we cycled through the table, remove the message at the slot we're
	 * going to supersede.
	 */

	if (cycled) {
		g_hash_table_remove(messages_hashed, entry);

		if (entry->routes != NULL)
			free_route_list(entry);

		if (dbg && next_message_index == 0) {
			time_t now = time((time_t) NULL);
			int elapsed = now - last_rotation;

			printf("Cycling through route table after %d seconds\n", elapsed);
			last_rotation = now;
		}
	}

	g_assert(entry->routes == NULL);

	/* fill in that storage space */
	memcpy(entry->muid, muid, 16);
	route->saved_messages++;
	entry->routes = g_slist_append(entry->routes, route);
	entry->function = function;

	/* insert the new message into the hash table */
	g_hash_table_insert(messages_hashed, entry, entry);

	if (++next_message_index >= MAX_STORED_MESSAGES) {
		next_message_index = 0;
		cycled = TRUE;
	}
}

/*
 * purge_dangling_references
 *
 * Remove references to routing data that is no longer associated with
 * a node, within the route list of the message.
 */
static void purge_dangling_references(struct message *m)
{
	GSList *l;

	for (l = m->routes; l; /* empty */) {
		struct route_data *rd = (struct route_data *) l->data;

		if (rd->node == NULL) {
			GSList *next = l->next;
			m->routes = g_slist_remove_link(m->routes, l);
			remove_one_message_reference(rd);
			g_slist_free_1(l);
			l = next;
		} else
			l = l->next;
	}
}

/*
 * find_message
 *
 * Look for a particular message in the routing tables.
 *
 * If we find the message, returns true, otherwise false.
 *
 * If none of the nodes that sent us the message are still present, then
 * m->routes will be NULL.
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
		purge_dangling_references(found_message);

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
        gnet_stats_count_dropped(sender, MSG_DROP_HARD_TTL_LIMIT);

		if (sender->header.hops <= max_high_ttl_radius &&
			sender->n_hard_ttl > max_high_ttl_msg
		) {
			node_bye(sender, 403, "Relayed %d high TTL (>%d) messages",
				sender->n_hard_ttl, max_high_ttl_msg);
			*node = NULL;
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
			*node = NULL;
		return FALSE;	/* Don't handle, shouldn't have seen it */
	}

	routing_log("[H] [NEW] ");

	message_add(sender->header.muid, sender->header.function, sender);

	sender->header.hops++;	/* Going to handle it, must be accurate */

	if (!--sender->header.ttl) {
		/* TTL expired, message stops here */
		routing_log("(TTL expired)\n");
        gnet_stats_count_expired(sender);
		/* don't increase rx_dropped, we'll handle this message */
	} else {			/* Forward it to all others nodes */
		if (target) {
			routing_log("-> sendto_one(%s)\n", node_ip(target));
			dest->type = ROUTE_ONE;
			dest->node = target;
		} else {
			/*
			 * This message is broadcasted, ensure its TTL is "reasonable".
			 * Trim down if excessively large.
			 */

			if (sender->header.ttl > max_ttl) {	/* TTL too large */
				sender->header.ttl = max_ttl;	/* Trim down */
				routing_log("(TTL trimmed down to %d) ", max_ttl);
			}

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

	sender = *node;
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
		 * We'll also handle all search replies.
		 */

		handle_it = sender->header.function == GTA_MSG_SEARCH_RESULTS;

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
				 * Ensure it's not a banned GUID though.
				 */

				if (!g_hash_table_lookup(ht_banned_push, guid))
					message_add(guid, QUERY_HIT_ROUTE_SAVE, sender);
			} else if (m->routes == NULL || !node_sent_message(sender, m)) {
				struct route_data *route;

				/*
				 * Either we have no more nodes that sent us any query hit
				 * from that GUID, or we have never received any such hit
				 * from the sender.
				 */

				route = get_routing_data(sender);
				m->routes = g_slist_append(m->routes, route);
				route->saved_messages++;
			}
		}

		/*
		 * Can't forward a message with 255 hops: we can't increase the
		 * counter.  This should never happen, even for a routed message
		 * due to network constraints.
		 *		--RAM, 04/07/2002
		 */

		if (sender->header.hops == 255) {
			routing_log("(max hop count reached)\n");
            gnet_stats_count_dropped(sender, MSG_DROP_MAX_HOP_COUNT);
			sender->rx_dropped++;
			sender->n_bad++;
			if (dbg)
				gmsg_log_bad(sender, "message with HOPS=255!");
			return FALSE;	/* Don't handle, something is wrong */
		}

		/*
		 * If node propagates messages with TTL=0, it's a danger to
		 * the network, kick him out.
		 *				-- RAM, 15/09/2001
		 */

		if (sender->header.ttl == 0) {
			routing_log("(TTL was 0)\n");
			if (node_sent_ttl0(sender))
				*node = NULL;
			return FALSE;	/* Don't handle, shouldn't have seen it */
		}

		if (!find_message
			(sender->header.muid, sender->header.function & ~(0x01), &m)) {
			/* We have never seen any request matching this reply ! */

			routing_log("[ ] no request matching the reply !\n");

			sender->rx_dropped++;
            gnet_stats_count_dropped(sender, MSG_DROP_UNREQUESTED_REPLY);
			sender->n_bad++;	/* Node shouldn't have forwarded this message */

			if (dbg > 2)
				gmsg_log_bad(sender, "got reply ID %s without matching request",
					guid_hex_str(sender->header.muid));

			if (handle_it) {
				sender->header.hops++;	/* Must be accurate if we handle it */
				sender->header.ttl--;
			}

			return handle_it;	/* We don't have to handle the message */
		}

		g_assert(m);		/* Or find_message() would have returned FALSE */

		/*
		 * If `m->routes' is NULL, we have seen the request, but unfortunately
		 * none of the nodes that sent us the request is connected any more.
		 */

		if (m->routes == NULL) {
			routing_log("[%c] route to target lost\n", handle_it ? 'H' : ' ');

            sender->rx_dropped++;
            gnet_stats_count_dropped(sender, MSG_DROP_ROUTE_LOST);

			if (handle_it) {
				sender->header.hops++;	/* Must be accurate if we handle it */
				sender->header.ttl--;
			}

			return handle_it;
		}

		if (node_sent_message(fake_node, m)) {
			/* We are the target of the reply */
			routing_log("[H] we are the target\n");
			sender->header.hops++;		/* Must be accurate: we handle it */
			sender->header.ttl--;
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

		sender->header.hops++;

		if (!--sender->header.ttl) {
			/* TTL expired, message stops here */
			routing_log("(TTL expired)\n");
            gnet_stats_count_expired(sender);
			sender->rx_dropped++;
			return handle_it;
		}

		found = ((struct route_data *) m->routes->data)->node;

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

            gnet_stats_count_dropped(sender, MSG_DROP_DUPLICATE);
			sender->rx_dropped++;

			if (m->routes && node_sent_message(sender, m)) {
				/* The same node has sent us a message twice ! */
				routing_log("[ ] dup message (from the same node!)\n");

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
					sender->n_dups > (guint16) 
                        (((float)min_dup_ratio) / 10000.0 * sender->received)
				) {
					node_bye(sender, 401, "Sent %d dups (%.1f%% of RX)",
						sender->n_dups, sender->received ?
							100.0 * sender->n_dups / sender->received :
							0.0);
					*node = NULL;
				} else {
					if (dbg > 2)
						gmsg_log_bad(sender, "dup message ID %s from same node",
							guid_hex_str(sender->header.muid));
				}
			} else {
				struct route_data * route;

				if (m->routes == NULL)
					routing_log("[ ] dup message, original route lost\n");
				else
					routing_log("[ ] dup message\n");

				/* append so that we route matches to the one that sent it
				 * to us first; ie., presumably the one closest to the
				 * original sender. */

				route = get_routing_data(sender);
				m->routes = g_slist_append(m->routes, route);
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
			g_assert(sender->size > 16);	/* Must be a valid push */

			/*
			 * If the GUID is banned, drop it immediately.
			 */

			if (g_hash_table_lookup(ht_banned_push, sender->data)) {
				if (dbg > 3)
					gmsg_log_dropped(&sender->header,
						"from %s, banned GUID %s",
						node_ip(sender), guid_hex_str(sender->data));

                gnet_stats_count_dropped(sender, MSG_DROP_BANNED);
				sender->rx_dropped++;

				return FALSE;
			}

			/*
			 * The GUID of the target are the leading bytes of the Push
			 * message, hence we pass `sender->data' to find_message().
			 */

			if (
				!find_message(sender->data, QUERY_HIT_ROUTE_SAVE, &m) ||
				m->routes == NULL
			) {
				if (0 == memcmp(guid, sender->data, 16)) {
					routing_log("[H] we are the target\n");
					return TRUE;
				}

				if (m && m->routes == NULL) {
					routing_log("[ ] route to target GUID %s gone\n",
						guid_hex_str(sender->data));
                    gnet_stats_count_dropped(sender, MSG_DROP_ROUTE_LOST);
                } else {
					routing_log("[ ] no route to target GUID %s\n",
						guid_hex_str(sender->data));
                    gnet_stats_count_dropped(sender, MSG_DROP_NO_ROUTE);
                }

				sender->rx_dropped++;

				return FALSE;
			}

			forward_message(node,
				((struct route_data *) m->routes->data)->node, dest);

			return FALSE;		/* We are not the target, don't handle it */
		} else {
			/*
			 * The message is a request to broadcast.
			 */

			if (!NODE_IS_READABLE(sender)) {		/* Being shutdown */
                gnet_stats_count_dropped(sender, MSG_DROP_SHUTDOWN);
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

                gnet_stats_count_dropped(sender, MSG_DROP_FLOW_CONTROL);
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

	if (g_hash_table_lookup(ht_banned_push, guid))	/* Banned for PUSH */
		return NULL;

	if (!find_message(guid, QUERY_HIT_ROUTE_SAVE, &m) || m->routes == NULL)
		return NULL;

	return ((struct route_data *) m->routes->data)->node;
}

/* frees the routing data associated with a message */
static void free_routing_data(gpointer key, gpointer value, gpointer udata)
{
	struct message *m = (struct message *) value;
	free_route_list(m);
}

/* frees the banned GUID atom keys */
static void free_banned_push(gpointer key, gpointer value, gpointer udata)
{
	guchar *g = (guchar *) key;
	atom_guid_free(g);
}

void routing_close(void)
{
	g_assert(messages_hashed);
	
	g_hash_table_foreach(messages_hashed, free_routing_data, NULL);
	g_hash_table_destroy(messages_hashed);
	messages_hashed = NULL;

	g_hash_table_foreach(ht_banned_push, free_banned_push, NULL);
	g_hash_table_destroy(ht_banned_push);
	ht_banned_push = NULL;
}

/* vi: set ts=4: */

