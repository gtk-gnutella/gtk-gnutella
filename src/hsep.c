/*
 * Copyright (c) 2004, Thomas Schuerger & Jeroen Asselman
 *
 * Horizon size estimation protocol 0.2.
 *
 * Protocol is defined here: http://www.menden.org/gnutella/hsep.html
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

/*
 * General API information:
 *
 * - hsep_init() should be called once on startup of GtkG
 * - hsep_connection_init(node) should be called once for each
 *   newly established HSEP-capable connection
 * - hsep_connection_close(node) should be called when a HSEP-capable
 *   connection is closed
 * - hsep_timer() should be called frequently to send out
 *   HSEP messages to HSEP-capable nodes as required
 * - hsep_notify_shared(files,kibibytes) should be called whenever the 
 *   number of shared files and/or kibibytes has changed
 * - hsep_process_msg(node) should be called whenever a HSEP message
 *   is received from a HSEP-capable node
 * - hsep_reset() can be used to reset all HSEP data (not for normal use)
 *
 * To display horizon size information, use the global array hsep_global_table
 * or the per-connection array node->hsep_table. The usable array indexes are
 * between 1 (for 1 hop) and HSEP_N_MAX (for n_max hops). Note that the arrays
 * only consider other nodes (i.e. exclude what we share ourselves), so the
 * array index 0 always contains zeros. Note also that each triple represents
 * the reachable resources *within* the number of hops, not at *exactly* the
 * number of hops. To get the values for exactly the number of hops, simply
 * subtract the preceeding triple from the desired triple.
 */

/*
 * TODO: in leaf mode HSEP messages should only be sent once at connection
 * startup and after that only after hsep_notify_shared() has been called,
 * i.e. not in hsep_timer(). But we can also live without this optimization.
 */
 
/*
 * TODO: check if semaphores are required for access to global or per-node
 * HSEP tables (e.g. in multithreaded applications). If semaphores are
 * required, a semaphore-based get()-function for the global and
 * per-connection table should be implemented instead of using these arrays
 * directly and locking/unlocking has to be used to enable thread-safety
 */

#include "common.h"

#include "gmsg.h"
#include "routing.h"
#include "nodes.h"
#include "hsep.h"
#include "header.h"
#include "uploads.h"

RCSID("$Id$");

#if G_BYTE_ORDER == G_BIG_ENDIAN
#define guint64_to_LE(x)	GUINT64_SWAP_LE_BE(x)
#elif G_BYTE_ORDER == G_LITTLE_ENDIAN
#define guint64_to_LE(x)	x
#else
#error "Byte order not supported"
#endif

/* global HSEP table */
hsep_triple hsep_global_table[HSEP_N_MAX+1];

/*
 * my own HSEP triple (first value must not be changed, the other must be
 * be updated whenever the number of our shared files/kibibytes change
 * by calling hsep_notify_shared()).
 */

hsep_triple hsep_own = {1, 0, 0};

/*
 * hsep_init
 *
 * Initializes HSEP.
 */

void hsep_init(void)
{
	header_features_add(&xfeatures.connections, 
		"HSEP", HSEP_VERSION_MAJOR, HSEP_VERSION_MINOR);

	memset(hsep_global_table, 0, sizeof(hsep_global_table));
}

/*
 * hsep_reset
 * 
 * Resets all HSEP data. The global HSEP table and all connections'
 * HSEP tables are reset to zero. The number of own shared files and
 * kibibytes is untouched. This can be used to watch how quickly
 * the HSEP data converges back to the correct "static" state. As soon
 * as we have received a HSEP message from each of our peers, this state
 * should be reached. Use with care, because this reset will temporarily
 * affect all HSEP-capable nodes in the radius of N_MAX hops!
 */

void hsep_reset()
{
	int i;
	GSList *sl;

	memset(hsep_global_table, 0, sizeof(hsep_global_table));

	for (sl = (GSList *) node_all_nodes(); sl; sl = g_slist_next(sl)) {
		struct gnutella_node *n = (struct gnutella_node *) sl->data;

		/* also consider unestablished connections here */

		if (!(n->attrs & NODE_A_CAN_HSEP))
			continue;

		memset(n->hsep_table, 0, sizeof(n->hsep_table));
		memset(n->hsep_sent_table, 0, sizeof(n->hsep_sent_table));

		/* this is what we know before receiving the first message */
		
		for (i = 1; i <= HSEP_N_MAX; i++) {
			n->hsep_table[i][HSEP_IDX_NODES] = 1;
			hsep_global_table[i][HSEP_IDX_NODES]++;
		}

		/*
		 * There's no need to reset the last_sent timestamp.
		 * If we'd do this, hsep_timer() would send a message
		 * to all HSEP connections the next time it is called.
		 */
	}
}

/*
 * hsep_connection_init
 *
 * Initializes the connection's HSEP data.
 */
 
void hsep_connection_init(struct gnutella_node *n)
{
	int i;

	g_assert(n);

	printf("HSEP: Node %p initialized\n", n);
	
	memset(n->hsep_table, 0, sizeof(n->hsep_table));
	memset(n->hsep_sent_table, 0, sizeof(n->hsep_sent_table));

	/* this is what we know before receiving the first message */
		
	for (i = 1; i <= HSEP_N_MAX; i++) {
		n->hsep_table[i][HSEP_IDX_NODES] = 1;
		hsep_global_table[i][HSEP_IDX_NODES]++;
	}

	n->hsep_msgs_received = 0;
	n->hsep_triples_received = 0;
	n->hsep_last_received = 0;
	n->hsep_msgs_sent = 0;
	n->hsep_triples_sent = 0;
	n->hsep_last_sent = 0;
}

/*
 * hsep_timer
 *
 * Sends a HSEP message to all nodes where the last message
 * has been sent some time ago. This should be called frequently
 *  (e.g. every second or every few seconds).
 */

void hsep_timer()
{
	time_t now = time(NULL);
	GSList *sl;
	gboolean scanning_shared;
	
	/* update number of shared files and KiB */

	gnet_prop_get_boolean_val(PROP_LIBRARY_REBUILDING, &scanning_shared);

	if (!scanning_shared) {
		if (upload_is_enabled())
			hsep_notify_shared(files_scanned, kbytes_scanned);
		else
			hsep_notify_shared(0, 0);
	}

	for (sl = (GSList *) node_all_nodes(); sl; sl = g_slist_next(sl)) {
		struct gnutella_node *n = (struct gnutella_node *) sl->data;
		int diff;

		/* only consider established connections here */
		if (!NODE_IS_ESTABLISHED(n))
			continue;

		if (!(n->attrs & NODE_A_CAN_HSEP))
			continue;

		/* check how many seconds ago the last message was sent */
		diff = now - n->hsep_last_sent;

		/* the -900 is used to react to changes in system time */
		if (diff >= HSEP_MSG_INTERVAL || diff < -900)
			hsep_send_msg(n);
	}
}

/*
 * hsep_connection_close
 *
 * Updates the global HSEP table when a connection is about
 * to be closed. The connection's HSEP data is restored to
 * zero and the CAN_HSEP attribute is cleared.
 */

void hsep_connection_close(struct gnutella_node *n)
{
	unsigned int i;
	guint64 *globalt = (guint64 *) &hsep_global_table[1];
	guint64 *connectiont;

	g_assert(n);

	connectiont = (guint64 *) &n->hsep_table[1];
	
	printf("HSEP: Deinitializing node %p\n", n);

	for (i = 0; i < HSEP_N_MAX; i++) {
		*globalt++ -= *connectiont;
		*connectiont++ = 0;
		*globalt++ -= *connectiont;
		*connectiont++ = 0;
		*globalt++ -= *connectiont;
		*connectiont++ = 0;
	}

	/* clear CAN_HSEP attribute so that the HSEP code */
	/* will not use the node any longer */
	n->attrs &= ~NODE_A_CAN_HSEP;
	
	hsep_dump_table();
}

/*
 * hsep_process_msg
 *
 * Processes a received HSEP message by updating the
 * connection's HSEP data and the global HSEP table.
 */

void hsep_process_msg(struct gnutella_node *n)
{
	unsigned int length;
	unsigned int i, max, msgmax;
	guint64 *messaget;
	guint64 *connectiont;
	guint64 *globalt = (guint64 *) &hsep_global_table[1];

	g_assert(n);

	length = n->size;

	/* note the offset between message and local data by 1 triple */

	messaget = (guint64 *) n->data;
	connectiont = (guint64 *) &n->hsep_table[1];
	
	if (length == 0) {   /* error, at least 1 triple must be present */
		printf("HSEP: Node %p sent empty message\n", n);
		return;
	}

	if (length % 24) {   /* error, # of triples not an integer */
		printf("HSEP: Node %p sent broken message\n", n);
		return;
	}

	/* get N_MAX of peer servent (other_n_max) */
	msgmax = length / 24;

	if (NODE_IS_LEAF(n) && msgmax > 1) {
		printf("HSEP: Node %p is a leaf, but sent %u triples instead of 1\n",
			n, msgmax);
		return;
	}

	/* truncate if peer servent sent more triples than we need */
	if (msgmax > HSEP_N_MAX)
		max = HSEP_N_MAX;
	else
		max = msgmax;
	
	/*
	 * Convert message from little endian to native byte order
	 * only the part of the message we are using is converted
	 * if native byte order is little endian, do nothing
	 */

	for (i = max; i > 0; i--) {
		*messaget = guint64_to_LE(*messaget);
		messaget++;
		*messaget = guint64_to_LE(*messaget);
		messaget++;
		*messaget = guint64_to_LE(*messaget);
		messaget++;
	}

	messaget = (guint64 *) n->data;		/* Back to front */

	/* sanity check */

	if (*messaget != 1) {   /* number of nodes for 1 hop must be 1 */
		printf("HSEP: Node %p's message's #nodes for 1 hop is not 1", n);
		return;
	}

	if (!hsep_check_monotony((hsep_triple *) messaget, max)) {
		printf("HSEP: Node %p's message's monotony check failed", n);
		return;
	}

	printf("HSEP: Received %d %s from node %p (msg #%u): ", max,
	    max == 1 ? "triple" : "triples", n, n->hsep_msgs_received + 1);

	/*
	 * Update global and per-connection tables
	 */

	for (i = 0; i < max; i++) {
		printf("(%llu,%llu,%llu) ", messaget[0], messaget[1], messaget[2]);
		*globalt++ += *messaget - *connectiont;
		*connectiont++ = *messaget++;
		*globalt++ += *messaget - *connectiont;
		*connectiont++ = *messaget++;
		*globalt++ += *messaget - *connectiont;
		*connectiont++ = *messaget++;
	}

	printf("\n");

	/*
	 * If the peer servent sent less triples than we need,
	 * repeat the last triple until we have enough triples
	 */

	for (; i < HSEP_N_MAX; i++) {
		/* go back to previous triple */
		messaget -= 3;

		*globalt++ += *messaget - *connectiont;
		*connectiont++ = *messaget++;
		*globalt++ += *messaget - *connectiont;
		*connectiont++ = *messaget++;
		*globalt++ += *messaget - *connectiont;
		*connectiont++ = *messaget++;
	}

	n->hsep_msgs_received++;
	n->hsep_triples_received += msgmax;

	n->hsep_last_received = time(NULL);

	hsep_dump_table();
}

/*
 * hsep_send_msg
 *
 * Sends a HSEP message to the given node if data to send
 * has changed. Should be called about every 30-60 seconds per node.
 * Will automatically be called by hsep_timer() and
 * hsep_connection_init(). Node must be HSEP-capable.
 */

void hsep_send_msg(struct gnutella_node *n)
{
	unsigned int i;
	unsigned int msglen;
	unsigned int triples;
	unsigned int opttriples;
	guint64 *globalt = (guint64 *) hsep_global_table;
	guint64 *connectiont;
	guint64 *ownt = (guint64 *) hsep_own;
	guint64 *messaget;
	struct gnutella_msg_hsep_data *m;

	g_assert(n);

	connectiont = (guint64 *) n->hsep_table;
	
	/*
	 * If we are a leaf, we just need to send one triple,
	 * which contains our own data (this triple is expanded
	 * to the needed number of triples on the peer's side)
	 * As the 0th global and 0th connection triple are zero,
	 * it contains only our own triple
	 */

	if (current_peermode == NODE_P_LEAF)
		triples = 1;
	else
		triples = HSEP_N_MAX;

	msglen = sizeof(struct gnutella_header) + triples * 24;

	m = (struct gnutella_msg_hsep_data *) g_malloc(msglen);

	message_set_muid(&m->header, GTA_MSG_HSEP_DATA);

	m->header.function = GTA_MSG_HSEP_DATA;
	m->header.ttl = 1;
	m->header.hops = 0;

	messaget = (guint64 *) ((&m->header)+1);

	/*
	 * Collect HSEP data to send.
	 */

	for (i = 0; i < triples; i++) {
		guint64 val;
		val = *ownt++ + *globalt++ - *connectiont++;
		*messaget++ = guint64_to_LE(val);
		val = *ownt++ + *globalt++ - *connectiont++;
		*messaget++ = guint64_to_LE(val);
		val = *ownt++ + *globalt++ - *connectiont++;
		*messaget++ = guint64_to_LE(val);
		ownt -= 3;  /* back to start of own triple */
	}

	/* check if the table differs from the previously sent table */
	if (0 == memcmp((char *) ((&m->header) + 1), 
					(char *) n->hsep_sent_table, 
					triples * 24)
	) {
		G_FREE_NULL(m);
		goto charge_timer;
	}
	
	/*  
	 * Note that on big endian architectures the message data is now in
	 * the wrong byte order. Nevertheless, we can use hsep_triples_to_send()
	 * with that data.
	 */
	
	/* optimize required number of triples */
	opttriples = hsep_triples_to_send(
		(hsep_triple *) ((&m->header) + 1), triples);

	globalt = (guint64 *) hsep_global_table;
	connectiont = (guint64 *) n->hsep_table;

	printf("HSEP: Sending %d %s to node %p (msg #%u): ", opttriples,
	    opttriples == 1 ? "triple" : "triples", n, n->hsep_msgs_sent + 1);

	for (i = 0; i < opttriples; i++) {
		printf("(%llu,%llu,%llu) ", ownt[0] + globalt[0] - connectiont[0],
			ownt[1] + globalt[1] - connectiont[1],
			ownt[2] + globalt[2] - connectiont[2]);
		globalt += 3;
		connectiont += 3;
	}

	printf("\n");

	/* write message size */
	WRITE_GUINT32_LE(opttriples * 24, m->header.size);
	
	/* correct message length */
	msglen = sizeof(struct gnutella_header) + opttriples * 24;

	gmsg_sendto_one(n, (gchar *) m, msglen);

	/* store the table for later comparison */
	memcpy((char *) n->hsep_sent_table, 
		   (char *) ((&m->header) + 1),
		   triples * 24);

	G_FREE_NULL(m);

	n->hsep_msgs_sent++;
	n->hsep_triples_sent += opttriples;

	/*
	 * Set the last_sent timestamp to the current time +/- some
	 * random skew.
	 */

charge_timer:	
	n->hsep_last_sent = time(NULL) +
		(time_t) random_value(2 * HSEP_MSG_SKEW) - (time_t) HSEP_MSG_SKEW;
}

/*
 * hsep_notify_shared
 *
 * This should be called whenever the number of shared files or kibibytes
 * change. The values are checked for changes, nothing is done if nothing
 * has changed. Note that kibibytes are determined by shifting the number
 * of bytes right by 10 bits, not by dividing by 1000.
 */

void hsep_notify_shared(guint64 ownfiles, guint64 ownkibibytes)
{
	/* check for change */
	if (ownfiles != hsep_own[HSEP_IDX_FILES] ||
		ownkibibytes != hsep_own[HSEP_IDX_KIB])
	{
		printf("HSEP: Shared files changed to %llu (%llu KiB)\n",
		    ownfiles, ownkibibytes);
		
		hsep_own[HSEP_IDX_FILES] = ownfiles;
		hsep_own[HSEP_IDX_KIB] = ownkibibytes;

		/*
		 * we could send a HSEP message to all nodes now, but these changes
		 * will propagate within at most HSEP_MSG_INTERVAL seconds anyway
		 *
		 * in leaf mode we could send a message to all HSEP-capable nodes
		 * now and don't send any messages at all in hsep_timer()
		 */
	}
}

/*
 * hsep_sanity_check
 *
 * Sanity check for the global and per-connection HSEP tables.
 * This is mainly for debugging purposes.
 *
 * Performed checks:
 *
 * - own triple must be (1, *, *)
 * - global triple for 0 hops must be (0, 0, 0)
 * - per-connection triple for 0 hops must be (0, 0, 0)
 * - per-connection triple for 1 hops must be (1, *, *)
 * - per-connection triples must be monotonically increasing
 * - the sum of the nth triple of each connection must match the
 *   nth global table triple for all n
 */

void hsep_sanity_check()
{
	hsep_triple sum[HSEP_N_MAX+1];
	GSList *sl;
	guint64 *globalt;
	guint64 *sumt;
	unsigned int i;

	memset(sum, 0, sizeof(sum));

	g_assert(hsep_own[HSEP_IDX_NODES] == 1);

	/*
	 * Iterate over all HSEP-capable nodes, and for each triple position
	 * sum up all the connections' triple values
	 */

	for (sl = (GSList *) node_all_nodes() ; sl; sl = g_slist_next(sl)) {
		struct gnutella_node *n = (struct gnutella_node *) sl->data;
		guint64 *connectiont;

		/* also consider unestablished connections here */

		if (!(n->attrs & NODE_A_CAN_HSEP))
			continue;

		sumt = (guint64 *) sum;
		connectiont = (guint64 *) n->hsep_table;
  
		g_assert(connectiont[HSEP_IDX_NODES] == 0);      /* check nodes */
		g_assert(connectiont[HSEP_IDX_FILES] == 0);      /* check files */
		g_assert(connectiont[HSEP_IDX_KIB] == 0);        /* check KiB */
		g_assert(connectiont[HSEP_IDX_NODES + 3] == 1);  /* check nodes */

		/* check if values are monotonously increasing (skip first) */
		g_assert(
			hsep_check_monotony((hsep_triple *) (connectiont + 3), HSEP_N_MAX)
			);

		/* sum up the values */

		for (i = 0; i <= HSEP_N_MAX; i++) {
			*sumt++ += *connectiont++;
			*sumt++ += *connectiont++;
			*sumt++ += *connectiont++;
		}
	}

	globalt = (guint64 *) hsep_global_table;
	sumt = (guint64 *) sum;

	/* check sums */

	for (i = 0; i <= HSEP_N_MAX; i++) {
		g_assert(*globalt == *sumt);
		globalt++;
		sumt++;
		g_assert(*globalt == *sumt);
		globalt++;
		sumt++;
		g_assert(*globalt == *sumt);
		globalt++;
		sumt++;
	}
}

/*
 * hsep_dump_table
 *
 * Outputs the global HSEP table to the console.
 */

void hsep_dump_table()
{
	unsigned int i;

	printf("HSEP: Reachable nodes (1-%d hops): ", HSEP_N_MAX);

	for (i = 1; i <= HSEP_N_MAX; i++)
		printf("%llu ", hsep_global_table[i][HSEP_IDX_NODES]);

	printf("\nHSEP: Reachable files (1-%d hops): ", HSEP_N_MAX);

	for (i = 1; i <= HSEP_N_MAX; i++)
		printf("%llu ", hsep_global_table[i][HSEP_IDX_FILES]);

	printf("\nHSEP:   Reachable KiB (1-%d hops): ", HSEP_N_MAX);

	for (i = 1; i <= HSEP_N_MAX; i++)
		printf("%llu ", hsep_global_table[i][HSEP_IDX_KIB]);

	printf("\n");

	hsep_sanity_check();
}

/*
 * hsep_check_monotony
 *
 * Checks the monotony of the given triples.
 * Nothing is done if just 1 triple is given.
 * Returns 1 if monotony is ok, 0 otherwise.
 */

gboolean hsep_check_monotony(hsep_triple *table, unsigned int triples)
{
	guint64 *prev;
	guint64 *curr;
	gboolean error = FALSE;

	g_assert(table);

	if (triples < 2)  /* handle special case */
		return TRUE;
	
	prev = (guint64 *) table;
	curr = (guint64 *) &table[1];
	
	/* if any triple is not >= the previous one, error will be TRUE */

	while (!error && --triples)
		error |= (*curr++ < *prev++) || 
				  (*curr++ < *prev++) || 
				  (*curr++ < *prev++);

	return FALSE == error;
}

/*
 * hsep_triples_to_send
 *
 * Takes a list of triples and returns the optimal number of triples
 * to send in a HSEP message. The number of triples to send
 * is n_opt, defined as (triple indices counted from 0):
 *
 * n_opt := 1 + min {n | triple[n] = triple[k] for all k in [n+1,triples-1]}
 *
 * If there is no such n_opt, n_opt := triples.
 * If all triples are equal, 1 is returned, which is correct.
 *
 * NOTE: this algorithm works regardless of the byte order of the triple data,
 * because only equality tests are used.
 */

unsigned int hsep_triples_to_send(hsep_triple *table, unsigned int triples)
{
	guint64 a, b, c;
	guint64 *ptr = (guint64 *) &table[triples];

	g_assert(table);

	if (triples < 2)  /* handle special case */
		return triples;

	c = *--ptr;  /* get KiB of last triple */
	b = *--ptr;  /* get files of last triple */
	a = *--ptr;  /* get nodes of last triple */

	/*
	 * ptr now points to start of last triple
	 * We go backwards until we find a triple where at least
	 * one of its components is different from the last triple
	 */

	while (triples > 0 && *--ptr == c && *--ptr == b && *--ptr == a)
		triples--;

	return triples;
}

/**
 * hsep_get_table
 *
 * Copies the first maxtriples triples from the global HSEP table into
 * the specified buffer. If maxtriples is larger than the number of
 * triples in the table, it is truncated appropriately.
 *
 * The number of copied triples is returned.
 */

unsigned int hsep_get_table(hsep_triple *buffer, unsigned int maxtriples)
{
	unsigned int i;
	guint64 *src = (guint64 *) hsep_global_table;
	guint64 *dest = (guint64 *) buffer;

	g_assert(buffer);

	if (maxtriples > HSEP_N_MAX + 1)
		maxtriples = HSEP_N_MAX + 1;

	for (i = 0; i < maxtriples; i++)
	{
		*dest++ = *src++;
		*dest++ = *src++;
		*dest++ = *src++;
	}

	return maxtriples;
}

/**
 * hsep_get_connection_table
 *
 * Copies the first maxtriples triples from the connection's HSEP table into
 * the specified buffer. If maxtriples is larger than the number of
 * triples in the table, it is truncated appropriately.
 *
 * The number of copied triples is returned.
 */

unsigned int hsep_get_connection_table(struct gnutella_node *n,
    hsep_triple *buffer, unsigned int maxtriples)
{
	unsigned int i;
	guint64 *src;
	guint64 *dest = (guint64 *) buffer;
	
	g_assert(n);
	g_assert(buffer);

	src = (guint64 *) n->hsep_table;

	if (maxtriples > HSEP_N_MAX + 1)
		maxtriples = HSEP_N_MAX + 1;

	for (i = 0; i < maxtriples; i++) {
		*dest++ = *src++;
		*dest++ = *src++;
		*dest++ = *src++;
	}

	return maxtriples;
}

/*
 * hsep_close
 *
 * Used to shut down HSEP. Currently does nothing.
 */

void hsep_close()
{
}
