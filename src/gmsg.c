/*
 * $Id$
 *
 * Copyright (c) 2002-2003, Raphael Manfredi
 *
 * Gnutella Messages.
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

#include <stdio.h>
#include <stdarg.h>
#include <string.h>		/* For memcpy() */

#include "pmsg.h"
#include "gmsg.h"
#include "nodes.h"
#include "sq.h"
#include "mq.h"
#include "routing.h"
#include "extensions.h"

RCSID("$Id$");

#define HEADER_SIZE	sizeof(struct gnutella_header)

static const gchar *msg_name[256];
static gint msg_weight[256];		/* For gmsg_cmp() */

static void gmsg_dump(FILE *out, gpointer data, guint32 size);
static void gmsg_split_dump(FILE *out, gpointer head, gpointer data,
				guint32 size);

/*
 * gmsg_init
 *
 * Initialization of the Gnutella message structures.
 */
void gmsg_init(void)
{
	gint i;

	for (i = 0; i < 256; i++)
		msg_name[i] = "unknown";

	msg_name[GTA_MSG_INIT]				= "ping";
	msg_name[GTA_MSG_INIT_RESPONSE]		= "pong";
	msg_name[GTA_MSG_BYE]				= "bye";
	msg_name[GTA_MSG_SEARCH]			= "query";
	msg_name[GTA_MSG_SEARCH_RESULTS]	= "query hit";
	msg_name[GTA_MSG_PUSH_REQUEST]		= "push";
	msg_name[GTA_MSG_QRP]				= "QRP";
	msg_name[GTA_MSG_VENDOR]			= "vendor";

	for (i = 0; i < 256; i++)
		msg_weight[i] = 0;

	msg_weight[GTA_MSG_INIT]			= 1;
	msg_weight[GTA_MSG_SEARCH]			= 2;
	msg_weight[GTA_MSG_INIT_RESPONSE]	= 3;
	msg_weight[GTA_MSG_SEARCH_RESULTS]	= 4;
	msg_weight[GTA_MSG_PUSH_REQUEST]	= 5;
	msg_weight[GTA_MSG_QRP]				= 6;
	msg_weight[GTA_MSG_VENDOR]			= 7;	/* deemed important */
}

/*
 * gmsg_name
 *
 * Convert message function number into name.
 */
const gchar *gmsg_name(guint function)
{
	if (function > 255)
		return "invalid";

	return msg_name[function];
}

/*
 * gmsg_to_pmsg
 *
 * Construct PDU from message.
 */
static pmsg_t *gmsg_to_pmsg(gint prio, gpointer msg, guint32 size)
{
	return pmsg_new(prio, msg, size);
}

/*
 * gmsg_split_to_pmsg
 *
 * Construct PDU from header and data.
 */
static pmsg_t *gmsg_split_to_pmsg(gpointer head, gpointer data, guint32 size)
{
	pmsg_t *mb;
	gint written;

	mb = pmsg_new(0, NULL, size);
	written = pmsg_write(mb, head, HEADER_SIZE);
	written += pmsg_write(mb, data, size - HEADER_SIZE);

	g_assert(written == size);

	return mb;
}

/***
 *** Sending of Gnutella messages.
 ***
 *** To send data to a single node, we need NODE_IS_WRITABLE, indicating
 *** that the TX stack is up and operational.
 ***
 *** To relay data to a node, we need NODE_IS_ESTABLISHED, indicating that
 *** our RX stack received some Gnutella traffic (for outgoing connections)
 *** or that we got the 3rd handshake (for incoming connections).
 ***/

/*
 * gmsg_sendto_one
 *
 * Send message to one node.
 */
void gmsg_sendto_one(struct gnutella_node *n, gchar *msg, guint32 size)
{
	g_assert(((struct gnutella_header *) msg)->ttl > 0);

	if (!NODE_IS_WRITABLE(n))
		return;

	if (dbg > 5 && gmsg_hops(msg) == 0)
		gmsg_dump(stdout, msg, size);

	mq_putq(n->outq, gmsg_to_pmsg(PMSG_P_DATA, msg, size));
}

/*
 * gmsg_search_sendto_one
 *
 * Send our search message to one node.
 */
void gmsg_search_sendto_one(
	struct gnutella_node *n, gnet_search_t sh, gchar *msg, guint32 size)
{
	g_assert(((struct gnutella_header *) msg)->ttl > 0);
	g_assert(((struct gnutella_header *) msg)->hops <= hops_random_factor);

	if (!NODE_IS_WRITABLE(n))
		return;

	if (dbg > 5 && gmsg_hops(msg) == 0)
		gmsg_dump(stdout, msg, size);

	sq_putq(n->searchq, sh, gmsg_to_pmsg(PMSG_P_DATA, msg, size));
}


/*
 * gmsg_ctrl_sendto_one
 *
 * Send control message to one node.
 * A control message is inserted ahead any other queued regular data.
 */
void gmsg_ctrl_sendto_one(struct gnutella_node *n, gchar *msg, guint32 size)
{
	g_assert(((struct gnutella_header *) msg)->ttl > 0);

	if (!NODE_IS_WRITABLE(n))
		return;

	if (dbg > 6 && gmsg_hops(msg) == 0)
		gmsg_dump(stdout, msg, size);

	mq_putq(n->outq, gmsg_to_pmsg(PMSG_P_CONTROL, msg, size));
}

/*
 * gmsg_split_sendto_one
 *
 * Send message consisting of header and data to one node.
 */
void gmsg_split_sendto_one(struct gnutella_node *n,
	gpointer head, gpointer data, guint32 size)
{
	g_assert(((struct gnutella_header *) head)->ttl > 0);

	if (!NODE_IS_WRITABLE(n))
		return;

	if (dbg > 6)
		gmsg_split_dump(stdout, head, data, size);

	mq_putq(n->outq, gmsg_split_to_pmsg(head, data, size));
}

/*
 * gmsg_sendto_all
 *
 * Broadcast message to all nodes in the list.
 */
void gmsg_sendto_all(const GSList *sl, gchar *msg, guint32 size)
{
	pmsg_t *mb = gmsg_to_pmsg(PMSG_P_DATA, msg, size);

	g_assert(((struct gnutella_header *) msg)->ttl > 0);

	if (dbg > 5 && gmsg_hops(msg) == 0)
		gmsg_dump(stdout, msg, size);

	for (/* empty */; sl; sl = g_slist_next(sl)) {
		struct gnutella_node *dn = (struct gnutella_node *) sl->data;
		if (!NODE_IS_ESTABLISHED(dn))
			continue;
		mq_putq(dn->outq, pmsg_clone(mb));
	}

	pmsg_free(mb);
}

/*
 * gmsg_search_sendto_all
 *
 * Broadcast our search message to all nodes in the list.
 */
void gmsg_search_sendto_all(
	const GSList *sl, gnet_search_t sh, gchar *msg, guint32 size)
{
	pmsg_t *mb = gmsg_to_pmsg(PMSG_P_DATA, msg, size);

	g_assert(((struct gnutella_header *) msg)->ttl > 0);
	g_assert(((struct gnutella_header *) msg)->hops <= hops_random_factor);

	if (dbg > 5 && gmsg_hops(msg) == 0)
		gmsg_dump(stdout, msg, size);

	for (/* empty */; sl; sl = g_slist_next(sl)) {
		struct gnutella_node *dn = (struct gnutella_node *) sl->data;
		if (!NODE_IS_ESTABLISHED(dn))
			continue;
		sq_putq(dn->searchq, sh, pmsg_clone(mb));
	}

	pmsg_free(mb);
}

/*
 * gmsg_search_sendto_all_nonleaf
 *
 * Broadcast our search message to all non-leaf nodes in the list.
 */
void gmsg_search_sendto_all_nonleaf(
	const GSList *sl, gnet_search_t sh, gchar *msg, guint32 size)
{
	pmsg_t *mb = gmsg_to_pmsg(PMSG_P_DATA, msg, size);

	g_assert(((struct gnutella_header *) msg)->ttl > 0);
	g_assert(((struct gnutella_header *) msg)->hops <= hops_random_factor);

	if (dbg > 5 && gmsg_hops(msg) == 0)
		gmsg_dump(stdout, msg, size);

	for (/* empty */; sl; sl = g_slist_next(sl)) {
		struct gnutella_node *dn = (struct gnutella_node *) sl->data;
		if (!NODE_IS_ESTABLISHED(dn) || NODE_IS_LEAF(dn))
			continue;
		sq_putq(dn->searchq, sh, pmsg_clone(mb));
	}

	pmsg_free(mb);
}

/*
 * gmsg_split_sendto_all_but_one
 *
 * Send message consisting of header and data to all nodes in the list
 * but one node.
 *
 * We never broadcast anything to a leaf node.  Those are handled specially.
 */
void gmsg_split_sendto_all_but_one(const GSList *sl, struct gnutella_node *n,
	gpointer head, gpointer data, guint32 size)
{
	pmsg_t *mb = gmsg_split_to_pmsg(head, data, size);

	g_assert(((struct gnutella_header *) head)->ttl > 0);

	/* relayed broadcasted message, cannot be sent with hops=0 */

	for (/* empty */; sl; sl = g_slist_next(sl)) {
		struct gnutella_node *dn = (struct gnutella_node *) sl->data;
		if (dn == n)
			continue;
		if (!NODE_IS_ESTABLISHED(dn) || NODE_IS_LEAF(dn))
			continue;
		mq_putq(dn->outq, pmsg_clone(mb));
	}

	pmsg_free(mb);
}

/*
 * gmsg_split_sendto_leaves
 *
 * Send message consisting of header and data to all the leaves in the list.
 */
void gmsg_split_sendto_leaves(const GSList *sl,
	gpointer head, gpointer data, guint32 size)
{
	pmsg_t *mb = gmsg_split_to_pmsg(head, data, size);

	g_assert(((struct gnutella_header *) head)->ttl > 0);

	/* relayed broadcasted message, cannot be sent with hops=0 */

	for (/* empty */; sl; sl = g_slist_next(sl)) {
		struct gnutella_node *dn = (struct gnutella_node *) sl->data;

		if (!NODE_IS_ESTABLISHED(dn))
			continue;

		/*
		 * We have already tested that the node was being writable.
		 */

		mq_putq(dn->outq, pmsg_clone(mb));
	}

	pmsg_free(mb);
}

/*
 * gmsg_split_sendto_all_but_one_ggep
 *
 * Same as gmsg_split_sendto_all_but_one(), but the message must not be
 * forwarded as-is to nodes not supporting GGEP: it must be truncated to
 * its `regular_size' size first.
 *
 * We never broadcast anything to a leaf node.  Those are handled specially.
 */
static void gmsg_split_sendto_all_but_one_ggep(
	const GSList *sl,
	struct gnutella_node *n,
	gpointer head, gpointer data, guint32 size, gint regular_size)
{
	pmsg_t *mb = gmsg_split_to_pmsg(head, data, size);
	pmsg_t *mb_stripped = NULL;

	g_assert(((struct gnutella_header *) head)->ttl > 0);
	g_assert(size >= regular_size);

	/* relayed broadcasted message, cannot be sent with hops=0 */

	for (/* empty */; sl; sl = g_slist_next(sl)) {
		struct gnutella_node *dn = (struct gnutella_node *) sl->data;
		if (dn == n)
			continue;
		if (!NODE_IS_ESTABLISHED(dn) || NODE_IS_LEAF(dn))
			continue;
		if (NODE_CAN_GGEP(dn))
			mq_putq(dn->outq, pmsg_clone(mb));
		else {
			if (mb_stripped == NULL) {
				struct gnutella_header nhead;

				memcpy(&nhead, head, HEADER_SIZE);
				WRITE_GUINT32_LE(regular_size, nhead.size);
				mb_stripped =
					gmsg_split_to_pmsg((guchar *) &nhead, data, regular_size);
			}
			mq_putq(dn->outq, pmsg_clone(mb_stripped));
		}
	}

	pmsg_free(mb);

	if (mb_stripped != NULL)
		pmsg_free(mb_stripped);
}


/*
 * gmsg_sendto_route
 *
 * Send message held in current node according to route specification.
 */
void gmsg_sendto_route(struct gnutella_node *n, struct route_dest *rt)
{
	struct gnutella_node *rt_node = rt->ur.u_node;
	const GSList *sl;

	switch (rt->type) {
	case ROUTE_NONE:
		break;
	case ROUTE_ONE:
		gmsg_split_sendto_one(rt_node,
			(guchar *) &n->header, n->data, n->size + HEADER_SIZE);
		break;
	case ROUTE_ALL_BUT_ONE:
		g_assert(n == rt_node);
		gmsg_split_sendto_all_but_one(node_all_nodes(), rt_node,
			(guchar *) &n->header, n->data, n->size + HEADER_SIZE);
		break;
	case ROUTE_MULTI:
		for (sl = rt->ur.u_nodes; sl; sl = g_slist_next(sl)) {
			rt_node = (struct gnutella_node *) sl->data;
			gmsg_split_sendto_one(rt_node,
				(guchar *) &n->header, n->data, n->size + HEADER_SIZE);
		}
		break;
	default:
		g_error("unknown route destination: %d", rt->type);
	}
}

/*
 * sendto_ggep
 *
 * Send message from `n' to single node `sn'.  If target node cannot
 * understand extra GGEP payloads, trim message before sending.
 */
static void sendto_ggep(
	struct gnutella_node *n, struct gnutella_node *sn, gint regular_size)
{
	if (NODE_CAN_GGEP(sn))
		gmsg_split_sendto_one(sn,
			(guchar *) &n->header, n->data, n->size + HEADER_SIZE);
	else {
		WRITE_GUINT32_LE(regular_size, n->header.size);
		gmsg_split_sendto_one(sn,
			(guchar *) &n->header, n->data, regular_size + HEADER_SIZE);
		WRITE_GUINT32_LE(n->size, n->header.size);
	}
}

/*
 * gmsg_sendto_route_ggep
 *
 * Same as gmsg_sendto_route() but if the node did not claim support of GGEP
 * extensions in pings, pongs and pushes, strip the GGEP payload before
 * forwarding the message.
 */
void gmsg_sendto_route_ggep(
	struct gnutella_node *n, struct route_dest *rt, gint regular_size)
{
	struct gnutella_node *rt_node = rt->ur.u_node;
	const GSList *sl;

	g_assert(regular_size >= 0);

	switch (rt->type) {
	case ROUTE_NONE:
		break;
	case ROUTE_ONE:
		sendto_ggep(n, rt_node, regular_size);
		break;
	case ROUTE_ALL_BUT_ONE:
		g_assert(n == rt_node);
		gmsg_split_sendto_all_but_one_ggep(node_all_nodes(), rt_node,
			(guchar *) &n->header, n->data, n->size + HEADER_SIZE,
			regular_size);
		break;
	case ROUTE_MULTI:
		for (sl = rt->ur.u_nodes; sl; sl = g_slist_next(sl)) {
			rt_node = (struct gnutella_node *) sl->data;
			sendto_ggep(n, rt_node, regular_size);
		}
		break;
	default:
		g_error("unknown route destination: %d", rt->type);
	}
}

/***
 *** Miscellaneous utilities.
 ***/

/*
 * gmsg_can_drop
 *
 * Test whether the Gnutella message can be safely dropped on the connection.
 * We're given the whole PDU, not just the payload.
 *
 * Dropping of messages only happens when the connection is flow-controlled,
 * and there's not enough room in the queue.
 */
gboolean gmsg_can_drop(gpointer pdu, gint size)
{
	struct gnutella_header *head = (struct gnutella_header *) pdu;

	if (size < sizeof(struct gnutella_header))
		return TRUE;

	switch (head->function) {
	case GTA_MSG_INIT:
	case GTA_MSG_SEARCH:
	case GTA_MSG_INIT_RESPONSE:
		return TRUE;
	default:
		return FALSE;
	}
}

/*
 * gmsg_cmp
 *
 * Perform a priority comparison between two messages, given as the whole PDU.
 *
 * Return algebraic -1/0/+1 depending on relative order.
 */
gint gmsg_cmp(gpointer pdu1, gpointer pdu2)
{
	struct gnutella_header *h1 = (struct gnutella_header *) pdu1;
	struct gnutella_header *h2 = (struct gnutella_header *) pdu2;
	gint w1 = msg_weight[h1->function];
	gint w2 = msg_weight[h2->function];

	/*
	 * The more weight a message type has, the more prioritary it is.
	 */

	if (w1 != w2)
		return w1 < w2 ? -1 : +1;

	/*
	 * Same weight.
	 *
	 * Compare hops.
	 *
	 * For queries: the more hops a message has travelled, the less prioritary
	 * it is.
	 * For replies: the more hops a message has travelled, the more prioritary
	 * it is (to maximize network's usefulness, or it would have just been a
	 * waste of bandwidth).  If identical hops, favor the one that is closer
	 * to its destination (lowest TTL).
	 */

	if (h1->hops == h2->hops) {
		switch (h1->function) {
		case GTA_MSG_PUSH_REQUEST:
		case GTA_MSG_SEARCH_RESULTS:
			if (h1->ttl == h2->ttl)
				return 0;
			return h1->ttl > h2->ttl ? -1 : +1;
		default:
			return 0;
		}
	}

	switch (h1->function) {
	case GTA_MSG_INIT:
	case GTA_MSG_SEARCH:
	case GTA_MSG_QRP:
		return h1->hops > h2->hops ? -1 : +1;
	default:
		return h1->hops < h2->hops ? -1 : +1;
	}
}

/*
 * gmsg_infostr
 *
 * Returns formatted static string:
 *
 *     msg_type (payload length) [hops=x, TTL=x]
 */
gchar *gmsg_infostr(gpointer head)
{
	static gchar a[80];
	struct gnutella_header *h = (struct gnutella_header *) head;
	guint32 size;

	READ_GUINT32_LE(h->size, size);

	gm_snprintf(a, sizeof(a), "%s (%u byte%s) [hops=%d, TTL=%d]",
		gmsg_name(h->function), size, size == 1 ? "" : "s", h->hops, h->ttl);

	return a;
}

/*
 * gmsg_infostr2
 *
 * Same as gmsg_infostr(), but different static buffer.
 */
static gchar *gmsg_infostr2(gpointer head)
{
	static gchar a[80];
	struct gnutella_header *h = (struct gnutella_header *) head;
	guint32 size;

	READ_GUINT32_LE(h->size, size);

	gm_snprintf(a, sizeof(a), "%s (%u byte%s) [hops=%d, TTL=%d]",
		gmsg_name(h->function), size, size == 1 ? "" : "s", h->hops, h->ttl);

	return a;
}

/*
 * gmsg_log_dropped
 *
 * Log dropped message, and reason.
 */
void gmsg_log_dropped(gpointer head, gchar *reason, ...)
{
	fputs("DROP ", stdout);
	fputs(gmsg_infostr2(head), stdout);	/* Allows gmsg_infostr() in arglist */

	if (reason) {
		va_list args;
		va_start(args, reason);
		fputs(": ", stdout);
		vprintf(reason, args);
		va_end(args);
	}

	fputc('\n', stdout);
}

/*
 * gmsg_log_bad
 *
 * Log bad message, the node's vendor, and reason.
 */
void gmsg_log_bad(struct gnutella_node *n, gchar *reason, ...)
{
	printf("BAD <%s> ", node_vendor(n));

	/* Allows gmsg_infostr() in arglist */
	fputs(gmsg_infostr2(&n->header), stdout);

	if (reason) {
		va_list args;
		va_start(args, reason);
		fputs(": ", stdout);
		vprintf(reason, args);
		va_end(args);
	}

	fputc('\n', stdout);
}

/*
 * gmsg_dump
 *
 * Log an hexadecimal dump of the message `data', tagged with:
 *
 *     msg_type (payload length) [hops=x, TTL=x]
 *
 * to the specified file descriptor.
 */
static void gmsg_dump(FILE *out, gpointer data, guint32 size)
{
	g_assert(size >= HEADER_SIZE);

	dump_hex(out, gmsg_infostr(data),
		(gchar *) data + HEADER_SIZE, size - HEADER_SIZE);
}

/*
 * gmsg_split_dump
 *
 * Same as gmsg_dump(), but the header and the PDU data are separated.
 */
static void gmsg_split_dump(FILE *out, gpointer head, gpointer data,
	guint32 size)
{
	g_assert(size >= HEADER_SIZE);

	dump_hex(out, gmsg_infostr(head), data, size - HEADER_SIZE);
}

/*
 * gmsg_check_ggep
 *
 * Check that current message has an extra payload made of GGEP only, and
 * whose total size is not exceeding `maxsize'.  The `regsize' value is the
 * normal payload length of the message (e.g. 0 for a ping).
 *
 * Returns TRUE if there is a GGEP extension, and only that after the
 * regular payload, with a size no greater than `maxsize'.
 */
gboolean gmsg_check_ggep(struct gnutella_node *n, gint maxsize, gint regsize)
{
	extvec_t exv[MAX_EXTVEC];
	gint exvcnt;
	gchar *start;
	gint len;
	gint i;

	g_assert(n->size > regsize);

	len = n->size - regsize;				/* Extension length */

	if (len > maxsize) {
		g_warning("%s has %d extra bytes !", gmsg_infostr(&n->header), len);
		return FALSE;
	}

	start = n->data + regsize;
	exvcnt = ext_parse(start, len, exv, MAX_EXTVEC);

	/*
	 * Assume that if we have MAX_EXTVEC, it's just plain garbage.
	 */

	if (exvcnt == MAX_EXTVEC) {
		g_warning("%s has %d extensions!", gmsg_infostr(&n->header), exvcnt);
		if (dbg)
			ext_dump(stderr, exv, exvcnt, "> ", "\n", TRUE);
		return FALSE;
	}

	/*
	 * Ensure we have only GGEP extensions in there.
	 */

	for (i = 0; i < exvcnt; i++) {
		if (exv[i].ext_type != EXT_GGEP) {
			g_warning("%s has non-GGEP extensions!", gmsg_infostr(&n->header));
			if (dbg)
				ext_dump(stderr, exv, exvcnt, "> ", "\n", TRUE);
			return FALSE;
		}
	}

	if (dbg > 3) {
		printf("%s has GGEP extensions:\n", gmsg_infostr(&n->header));
		ext_dump(stdout, exv, exvcnt, "> ", "\n", TRUE);
	}

	return TRUE;
}

