
/* Gnutella Network Messages routing */

#include "gnutella.h"

#include <stdarg.h>
#include <assert.h>


struct gnutella_node *fake_node;		/* Our fake node */

GList *messages[256];			/* The messages lists */
guint32 n_messages[256];		/* Numbers of messages in the lists */
GList *tail[256];				/* The older message in the lists */

struct message {
	guchar muid[16];			/* Message UID */
	GSList *nodes;				/* Nodes from which the message came */
	guint8 function;			/* Type of the message */
};

gchar *debug_msg[256];

#define MAX_MESSAGES_PER_LIST	256		/* We can remember 256 * 256 messages */

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

	//printf("%s", t);
}

gboolean node_sent_message(struct gnutella_node *n, struct message *m)
{
	GSList *l = m->nodes;

	while (l) {
		if (l->data == n)
			return TRUE;
		l = l->next;
	}
	return FALSE;
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

	srand(time((time_t *) NULL));

	for (i = 0; i < 15; i++)
		guid[i] = rand() & 0xff;

	for (i = 0; i < 256; i++) {
		messages[i] = NULL;
		n_messages[i] = 0;
	}

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

/* Erase a node from the routing tables */

void routing_node_remove(struct gnutella_node *node)
{
	GList *l;
	guint32 i;

	for (i = 0; i < 256; i++)
		for (l = messages[i]; l; l = l->next) {
			struct message *m = (struct message *) l->data;
			/* g_slist_remove won't do anything if this node isn't in the list */
			m->nodes = g_slist_remove(m->nodes, node);
		}
}

/* Adds a new message in the routing tables */

void message_add(guchar * muid, guint8 function,
				 struct gnutella_node *node)
{
	static struct message *m;
	guint8 f = muid[0];

	if (!node) {
		node = fake_node;		/* We are the sender of the message */

		routing_log("%-21s %s %s %3d\n", "OURSELVES", debug_msg[function],
					md5dump(muid), my_ttl);
	}

	if (n_messages[f] >= MAX_MESSAGES_PER_LIST) {		/* Table is full */
		GList *ct = tail[f];	/* ct is the current tail */

		tail[f] = ct->prev;		/* The new tail is the prev message */

		tail[f]->next = (GList *) NULL; /* The tail next pointer must be NULL */
		ct->prev = (GList *) NULL;		/* The head prev pointer must be NULL */

		ct->next = messages[f]; /* The head next pointer = current head */
		messages[f]->prev = ct; /* Current head is no more the real head */

		messages[f] = ct;		/* The list head change */

		/* We'll use the oldest message memory place */
		m = (struct message *) ct->data;
		g_slist_free(m->nodes);
	} else {
		/*
		 * Table is not full, allocate a new structure and prepend it to
		 * the table
		 */

		m = (struct message *) g_malloc(sizeof(struct message));

		n_messages[f]++;

		messages[f] = g_list_prepend(messages[f], (gpointer) m);

		if (!tail[f])
			tail[f] = messages[f];	/* Now the first message in the table */
	}

	memcpy(m->muid, muid, 16);
	m->function = function;
	m->nodes = g_slist_append(NULL, node);
}

/* Look for a particular message in the routing tables */

gboolean find_message(guchar * muid, guint8 function, struct message **m)
{
	/* Returns TRUE if the message is found */
	/* Set *m to message when the message is found */

	static GList *l;

	for (l = messages[(guint8) muid[0]]; l; l = l->next) {
		struct message *msg = (struct message *) l->data;
		if (
			(msg->muid[1] == muid[1]) &&
			(msg->function == function) &&
			!memcmp(msg->muid + 2, muid + 2, 14)	/* Done for [0] and [1] */
		) {
			*m = msg;			/* We found the message */
			return TRUE;
		}
	}

	*m = NULL;
	return FALSE;				/* Message not found in the tables */
}

void routing_close(void)
{
	GList *l;
	guint32 i;

	for (i = 0; i < 256; i++) {
		for (l = messages[i]; l; l = l->next) {
			struct message *m = (struct message *) l->data;
			while (m->nodes)
				m->nodes = g_slist_remove(m->nodes, m->nodes->data);
			g_free(m);
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

			found = (struct gnutella_node *) m->nodes->data;

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
					 * of the search, or if we've sent them the search with a
					 * new muid. */
				} else {
					/* append so that we route matches to the one that sent it
					 * to us first; ie., presumably the one closest to the
					 * original sender. */
					m->nodes = g_slist_append(m->nodes, sender);
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


	if (n->status != GTA_NODE_CONNECTED)
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
