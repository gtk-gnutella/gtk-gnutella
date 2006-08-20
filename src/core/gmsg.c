/*
 * $Id$
 *
 * Copyright (c) 2002-2003, Raphael Manfredi
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

/**
 * @ingroup core
 * @file
 *
 * Gnutella Messages.
 *
 * @author Raphael Manfredi
 * @date 2002-2003
 */

#include "common.h"

RCSID("$Id$")

#include "gmsg.h"
#include "pmsg.h"
#include "nodes.h"
#include "sq.h"
#include "mq.h"
#include "routing.h"
#include "vmsg.h"
#include "search.h"
#include "gnet_stats.h"

#include "if/gnet_property_priv.h"

#include "lib/endian.h"
#include "lib/glib-missing.h"
#include "lib/walloc.h"
#include "lib/zlib_util.h"
#include "lib/override.h"		/* Must be the last header included */

static const gchar *msg_name[256];
static guint8 msg_weight[256];	/**< For gmsg_cmp() */

/**
 * Ensure that the gnutella message header has the correct size,
 * a TTL greater than zero and that size is at least 23 (GTA_HEADER_SIZE).
 *
 * @param h		the gnutella message header to check.
 * @param size	the payload plus header size of the gnutella message.
 */
static inline void
gmsg_header_check(const struct gnutella_header *h, guint32 size)
{
	g_assert(h->ttl > 0);
	g_assert(size >= GTA_HEADER_SIZE);
	g_assert(peek_le32(h->size) == size - GTA_HEADER_SIZE);
}

/**
 * Log an hexadecimal dump of the message `data'.
 *
 * Tagged with:
 *
 *     msg_type (payload length) [hops=x, TTL=x]
 *
 * to the specified file descriptor.
 */
static void
gmsg_dump(FILE *out, gconstpointer data, guint32 size)
{
	g_assert(size >= GTA_HEADER_SIZE);

	dump_hex(out, gmsg_infostr_full(data),
		(gchar *) data + GTA_HEADER_SIZE, size - GTA_HEADER_SIZE);
}

/**
 * Same as gmsg_dump(), but the header and the PDU data are separated.
 */
static void
gmsg_split_dump(FILE *out, gconstpointer head, gconstpointer data,
	guint32 size)
{
	g_assert(size >= GTA_HEADER_SIZE);

	dump_hex(out, gmsg_infostr_full_split(head, data),
		data, size - GTA_HEADER_SIZE);
}

/**
 * Initialization of the Gnutella message structures.
 */
void
gmsg_init(void)
{
	gint i;

	for (i = 0; i < 256; i++) {
		const gchar *s;
		guint w;

		s = "unknown";
		w = 0;

		switch ((enum gta_msg) i) {
		case GTA_MSG_INIT:           w = 1; s = "Ping"; break;
		case GTA_MSG_INIT_RESPONSE:  w = 3; s = "Pong"; break;
		case GTA_MSG_SEARCH:         w = 2; s = "Query"; break;
		case GTA_MSG_SEARCH_RESULTS: w = 4; s = "Q-Hit"; break;
		case GTA_MSG_PUSH_REQUEST:   w = 5; s = "Push"; break;
		case GTA_MSG_RUDP:   		 		s = "RUDP"; break;
		case GTA_MSG_VENDOR:         		s = "Vndor"; break;
		case GTA_MSG_STANDARD:       		s = "Vstd"; break;
		case GTA_MSG_QRP:            w = 6; s = "QRP"; break;
		case GTA_MSG_HSEP_DATA:      		s = "HSEP"; break;
		case GTA_MSG_BYE:      		 w = 7; s = "BYE"; break;
		}
		msg_name[i] = s;
		msg_weight[i] = w;
	}
}

/**
 * Convert message function number into name.
 */
const gchar *
gmsg_name(guint function)
{
	if (function > 255)
		return "invalid";

	return msg_name[function];
}

/**
 * Construct regular PDU descriptor from message.
 *
 * Message data is copied into the new data buffer, so caller may release
 * its memory.
 */
pmsg_t *
gmsg_to_pmsg(gconstpointer msg, guint32 size)
{
	pmsg_t *mb;

	mb = pmsg_new(PMSG_P_DATA, msg, size);
	gmsg_install_presend(mb);
	return mb;
}

/**
 * Construct compressed control PDU descriptor from message, for UDP traffic.
 * The message payload is deflated only when the resulting size is smaller
 * than the raw uncompressed form.
 *
 * Message data is copied into the new data buffer, so caller may release
 * its memory.
 */
pmsg_t *
gmsg_to_deflated_pmsg(gconstpointer msg, guint32 size)
{
	guint32 plen = size - GTA_HEADER_SIZE;		/* Raw payload length */
	guint32 blen = plen + (plen >> 4) + 12;		/* 1.0625 times orginal */
	gpointer buf;								/* Compression made there */
	gconstpointer data;							/* Raw data start */
	guint32 deflated_length;					/* Length of deflated data */
	zlib_deflater_t *z;
	struct gnutella_header *header;
	pmsg_t *mb;

	/*
	 * Since there is a 2-byte header added to each deflated stream, plus
	 * a trailing 16-bit checksum, it's no use to attempt deflation if
	 * the payload has less than 5 bytes.
	 */

	if (plen <= 5)
		return gmsg_to_pmsg(msg, size);

	/*
	 * Compress payload into newly allocated buffer.
	 */

	buf = walloc(blen);
	data = (const gchar *) msg + GTA_HEADER_SIZE;
	z = zlib_deflater_make_into(data, plen, buf, blen, Z_DEFAULT_COMPRESSION);

	switch (zlib_deflate(z, plen)) {
	case -1:
		goto send_raw;
		break;
	case 0:
		break;
	case 1:
		g_error("did not deflate the whole input");
		break;
	}

	g_assert(zlib_deflater_closed(z));

	/*
	 * Check whether compressed data is smaller than the original payload.
	 */

	deflated_length = zlib_deflater_outlen(z);

	if (deflated_length >= plen) {
		gnet_stats_count_general(GNR_UDP_LARGER_HENCE_NOT_COMPRESSED, 1);
		goto send_raw;
	}

	/*
	 * OK, we gain something so we'll send this payload deflated.
	 */

	mb = gmsg_split_to_pmsg(&header, buf, deflated_length + GTA_HEADER_SIZE);

	wfree(buf, blen);
	zlib_deflater_free(z, FALSE);

	header = (struct gnutella_header *) pmsg_start(mb);

	if (udp_debug)
		g_message("UDP deflated %s into %d bytes",
			gmsg_infostr(header), deflated_length);

	header->ttl |= GTA_UDP_DEFLATED;
	poke_le32(header->size, deflated_length);

	return mb;

send_raw:
	/*
	 * Cleanup and send payload as-is (uncompressed).
	 */

	wfree(buf, blen);
	zlib_deflater_free(z, FALSE);

	return gmsg_to_pmsg(msg, size);
}

/**
 * Construct control PDU descriptor from message.
 */
pmsg_t *
gmsg_to_ctrl_pmsg(gconstpointer msg, guint32 size)
{
	pmsg_t *mb;

	mb = pmsg_new(PMSG_P_CONTROL, msg, size);
	gmsg_install_presend(mb);
	return mb;
}

/**
 * Construct extended control PDU (with free routine) from message.
 */
pmsg_t *
gmsg_to_ctrl_pmsg_extend(
	gconstpointer msg, guint32 size, pmsg_free_t free_cb, gpointer arg)
{
	pmsg_t *mb;

	mb = pmsg_new_extend(PMSG_P_CONTROL, msg, size, free_cb, arg);
	gmsg_install_presend(mb);

	return mb;
}

/**
 * Write message data into new empty message buffer.
 */
static void
write_message(pmsg_t *mb, gconstpointer head, gconstpointer data, guint32 size)
{
	gint written;

	written = pmsg_write(mb, head, GTA_HEADER_SIZE);
	written += pmsg_write(mb, data, size - GTA_HEADER_SIZE);

	g_assert((guint32) written == size);
}

/**
 * Construct PDU from header and data.
 *
 * @param head		pointer to the Gnutella header
 * @param data		pointer to the Gnutella payload
 * @param size		the total size of the message, header + payload
 */
pmsg_t *
gmsg_split_to_pmsg(gconstpointer head, gconstpointer data, guint32 size)
{
	pmsg_t *mb;

	mb = pmsg_new(PMSG_P_DATA, NULL, size);
	write_message(mb, head, data, size);
	gmsg_install_presend(mb);

	return mb;
}

/**
 * Construct extended PDU (with free routine) from header and data.
 */
pmsg_t *
gmsg_split_to_pmsg_extend(gconstpointer head, gconstpointer data,
	guint32 size, pmsg_free_t free_cb, gpointer arg)
{
	pmsg_t *mb;

	mb = pmsg_new_extend(PMSG_P_DATA, NULL, size, free_cb, arg);
	write_message(mb, head, data, size);
	gmsg_install_presend(mb);

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

/**
 * Broadcast message to all nodes in the list.
 *
 * The supplied mb is cloned for each node to which it is sent. It is up
 * to the caller to free that mb, if needed, upon return.
 */
void
gmsg_mb_sendto_all(const GSList *sl, pmsg_t *mb)
{
	gmsg_header_check(cast_to_gconstpointer(pmsg_start(mb)), pmsg_size(mb));

	if (gmsg_debug > 5 && gmsg_hops(pmsg_start(mb)) == 0)
		gmsg_dump(stdout, pmsg_start(mb), pmsg_size(mb));

	for (/* empty */; sl; sl = g_slist_next(sl)) {
		struct gnutella_node *dn = sl->data;
		if (!NODE_IS_ESTABLISHED(dn))
			continue;
		mq_putq(dn->outq, pmsg_clone(mb));
	}
}

/**
 * Send message to one node.
 *
 * The supplied mb is NOT cloned, it is up to the caller to ensure that
 * a private instance is supplied.
 */
void
gmsg_mb_sendto_one(struct gnutella_node *n, pmsg_t *mb)
{
	g_assert(!pmsg_was_sent(mb));
	gmsg_header_check(cast_to_gconstpointer(pmsg_start(mb)), pmsg_size(mb));

	if (!NODE_IS_WRITABLE(n))
		return;

	if (gmsg_debug > 5 && gmsg_hops(pmsg_start(mb)) == 0)
		gmsg_dump(stdout, pmsg_start(mb), pmsg_size(mb));

	mq_putq(n->outq, mb);
}

/**
 * Send message to one node.
 */
void
gmsg_sendto_one(struct gnutella_node *n, gconstpointer msg, guint32 size)
{
	if (!NODE_IS_WRITABLE(n))
		return;

	gmsg_header_check(msg, size);

	if (gmsg_debug > 5 && gmsg_hops(msg) == 0)
		gmsg_dump(stdout, msg, size);

	mq_putq(n->outq, gmsg_to_pmsg(msg, size));
}

/**
 * Send message to one node, stripping the GGEP part if the node cannot grok
 * GGEP extensions.
 */
void
gmsg_sendto_one_ggep(struct gnutella_node *n,
	gconstpointer msg, guint32 size, guint32 regular_size)
{
	g_assert(size >= regular_size);
	gmsg_header_check(msg, size);

	if (!NODE_IS_WRITABLE(n))
		return;

	if (gmsg_debug > 5 && gmsg_hops(msg) == 0)
		gmsg_dump(stdout, msg, size);

	if (NODE_CAN_GGEP(n)) {
		mq_putq(n->outq, gmsg_to_pmsg(msg, size));
	} else {
		const struct gnutella_header *msg_head = msg;
		struct gnutella_header head;
		pmsg_t *mb;

		/*
		 * Create a copy of message with the trailing GGEP data
		 * stripped and a corrected size field in the header
		 */

		head = *msg_head;
		WRITE_GUINT32_LE(regular_size - GTA_HEADER_SIZE, head.size);
		mb = gmsg_split_to_pmsg(&head, &msg_head[1], regular_size);
		mq_putq(n->outq, pmsg_clone(mb));
		pmsg_free(mb);
	}
}

/**
 * Send control message to one node.
 *
 * A control message is inserted ahead any other queued regular data.
 */
void
gmsg_ctrl_sendto_one(struct gnutella_node *n, gconstpointer msg, guint32 size)
{
	gmsg_header_check(msg, size);

	if (!NODE_IS_WRITABLE(n))
		return;

	if (gmsg_debug > 6 && gmsg_hops(msg) == 0)
		gmsg_dump(stdout, msg, size);

	mq_putq(n->outq, gmsg_to_ctrl_pmsg(msg, size));
}

/**
 * Send control message to one node.
 *
 * A control message is inserted ahead any other queued regular data.
 */
void
gmsg_ctrl_sendto_one_ggep(struct gnutella_node *n,
	gconstpointer msg, guint32 size, guint32 regular_size)
{
	gmsg_header_check(msg, size);

	if (!NODE_IS_WRITABLE(n))
		return;

	if (gmsg_debug > 6 && gmsg_hops(msg) == 0)
		gmsg_dump(stdout, msg, size);

	if (NODE_CAN_GGEP(n))
		mq_putq(n->outq, gmsg_to_ctrl_pmsg(msg, size));
	else
		mq_putq(n->outq, gmsg_to_ctrl_pmsg(msg, regular_size));
}

/**
 * Send our search message to one node.
 */
void
gmsg_search_sendto_one(
	struct gnutella_node *n, gnet_search_t sh, gconstpointer msg, guint32 size)
{
	gmsg_header_check(msg, size);
	g_assert(((struct gnutella_header *) msg)->hops <= hops_random_factor);

	if (!NODE_IS_WRITABLE(n))
		return;

	if (gmsg_debug > 5 && gmsg_hops(msg) == 0)
		gmsg_dump(stdout, msg, size);

	sq_putq(n->searchq, sh, gmsg_to_pmsg(msg, size));
}

/**
 * Send message consisting of header and data to one node.
 */
void
gmsg_split_sendto_one(struct gnutella_node *n,
	gconstpointer head, gconstpointer data, guint32 size)
{
	gmsg_header_check(head, size);

	if (!NODE_IS_WRITABLE(n))
		return;

	if (gmsg_debug > 6)
		gmsg_split_dump(stdout, head, data, size);

	mq_putq(n->outq, gmsg_split_to_pmsg(head, data, size));
}

/**
 * Broadcast message to all nodes in the list.
 */
void
gmsg_sendto_all(const GSList *sl, gconstpointer msg, guint32 size)
{
	pmsg_t *mb = gmsg_to_pmsg(msg, size);

	gmsg_header_check(msg, size);

	if (gmsg_debug > 5 && gmsg_hops(msg) == 0)
		gmsg_dump(stdout, msg, size);

	for (/* empty */; sl; sl = g_slist_next(sl)) {
		struct gnutella_node *dn = sl->data;
		if (!NODE_IS_ESTABLISHED(dn))
			continue;
		mq_putq(dn->outq, pmsg_clone(mb));
	}

	pmsg_free(mb);
}

/**
 * Broadcast message to all nodes in the list, sending only a stripped down
 * version without the trailing GGEP extension to nodes not advertising
 * GGEP support.
 */
void
gmsg_sendto_all_ggep(const GSList *sl,
	gconstpointer msg, guint32 size, guint32 regular_size)
{
	pmsg_t *mb = gmsg_to_pmsg(msg, size);
	pmsg_t *mb_stripped = NULL;

	gmsg_header_check(msg, size);

	if (gmsg_debug > 5 && gmsg_hops(msg) == 0)
		gmsg_dump(stdout, msg, size);

	for (/* empty */; sl; sl = g_slist_next(sl)) {
		struct gnutella_node *dn = sl->data;
		if (!NODE_IS_ESTABLISHED(dn))
			continue;
		if (NODE_CAN_GGEP(dn))
			mq_putq(dn->outq, pmsg_clone(mb));
		else {
			if (mb_stripped == NULL)
				mb_stripped = gmsg_to_pmsg(msg, regular_size);
			mq_putq(dn->outq, pmsg_clone(mb_stripped));
		}
	}

	pmsg_free(mb);
	if (mb_stripped)
		pmsg_free(mb_stripped);
}

/**
 * Broadcast our search message to all nodes in the list.
 */
void
gmsg_search_sendto_all(
	const GSList *sl, gnet_search_t sh, gconstpointer msg, guint32 size)
{
	pmsg_t *mb = gmsg_to_pmsg(msg, size);

	gmsg_header_check(msg, size);
	g_assert(((struct gnutella_header *) msg)->hops <= hops_random_factor);

	if (gmsg_debug > 5 && gmsg_hops(msg) == 0)
		gmsg_dump(stdout, msg, size);

	for (/* empty */; sl; sl = g_slist_next(sl)) {
		struct gnutella_node *dn = (struct gnutella_node *) sl->data;

		/*
		 * When switching UP -> leaf, it may happen that we try to send
		 * a search to a leaf node without any search queue.  Hence
		 * the explicit test.  --RAM, 2005-01-24
		 */

		if (!NODE_IS_ESTABLISHED(dn) || dn->searchq == NULL)
			continue;
		sq_putq(dn->searchq, sh, pmsg_clone(mb));
	}

	pmsg_free(mb);
}

/**
 * Send message consisting of header and data to all nodes in the list
 * but one node.
 *
 * We never broadcast anything to a leaf node.  Those are handled specially.
 */
void
gmsg_split_sendto_all_but_one(const GSList *sl, const struct gnutella_node *n,
	gconstpointer head, gconstpointer data, guint32 size)
{
	pmsg_t *mb = gmsg_split_to_pmsg(head, data, size);
	gboolean skip_up_with_qrp = FALSE;

	/*
	 * Special treatment for TTL=1 queries in UP mode.
	 */

	if (
		current_peermode == NODE_P_ULTRA &&
		((struct gnutella_header *) head)->function == GTA_MSG_SEARCH &&
		((struct gnutella_header *) head)->ttl == 1
	)
		skip_up_with_qrp = TRUE;

	gmsg_header_check(head, size);

	/* relayed broadcasted message, cannot be sent with hops=0 */

	for (/* empty */; sl; sl = g_slist_next(sl)) {
		struct gnutella_node *dn = sl->data;
		if (dn == n)
			continue;
		if (!NODE_IS_ESTABLISHED(dn) || NODE_IS_LEAF(dn))
			continue;
		if (skip_up_with_qrp && NODE_UP_QRP(dn))
			continue;
		mq_putq(dn->outq, pmsg_clone(mb));
	}

	pmsg_free(mb);
}

/**
 * Send message consisting of header and data to all the nodes in the list.
 */
void
gmsg_split_sendto_all(
	const GSList *sl, gconstpointer head, gconstpointer data, guint32 size)
{
	pmsg_t *mb = gmsg_split_to_pmsg(head, data, size);

	gmsg_header_check(head, size);

	/* relayed broadcasted message, cannot be sent with hops=0 */

	for (/* empty */; sl; sl = g_slist_next(sl)) {
		struct gnutella_node *dn = sl->data;

		if (!NODE_IS_ESTABLISHED(dn))
			continue;

		/*
		 * We have already tested that the node was being writable.
		 */

		mq_putq(dn->outq, pmsg_clone(mb));
	}

	pmsg_free(mb);
}

/**
 * Same as gmsg_split_sendto_all_but_one(), but the message must not be
 * forwarded as-is to nodes not supporting GGEP: it must be truncated to
 * its `regular_size' size first.
 *
 * We never broadcast anything to a leaf node.  Those are handled specially.
 * In UP mode, we never broadcast queries with TTL=1 to ultra nodes that
 * support the last-hop QRP.
 *
 * @param sl 			a list of destination nodes.
 * @param n 			the source node which will be skipped.
 * @param head 			the gnutella message header.
 * @param data 			the gnutella message payload.
 * @param size			the length of "data" plus the size of the header.
 * @param regular_size	the length of "data" excluding trailing GGEP data.
 */
static void
gmsg_split_sendto_all_but_one_ggep(
	const GSList *sl,
	const struct gnutella_node *n,
	gconstpointer head, gconstpointer data, guint32 size, guint32 regular_size)
{
	pmsg_t *mb = gmsg_split_to_pmsg(head, data, size);
	pmsg_t *mb_stripped = NULL;
	gboolean skip_up_with_qrp = FALSE;

	gmsg_header_check(head, size);
	g_assert(size >= regular_size);

	/*
	 * Special treatment for TTL=1 queries in UP mode.
	 */

	if (
		current_peermode == NODE_P_ULTRA &&
		((struct gnutella_header *) head)->function == GTA_MSG_SEARCH &&
		((struct gnutella_header *) head)->ttl == 1
	)
		skip_up_with_qrp = TRUE;

	/* relayed broadcasted message, cannot be sent with hops=0 */

	for (/* empty */; sl; sl = g_slist_next(sl)) {
		struct gnutella_node *dn = sl->data;
		if (dn == n)
			continue;
		if (!NODE_IS_ESTABLISHED(dn) || NODE_IS_LEAF(dn))
			continue;
		if (skip_up_with_qrp && NODE_UP_QRP(dn))
			continue;
		if (NODE_CAN_GGEP(dn))
			mq_putq(dn->outq, pmsg_clone(mb));
		else {
			if (mb_stripped == NULL) {
				const struct gnutella_header *h = head;
				struct gnutella_header nhead;

				nhead = *h;
				WRITE_GUINT32_LE(regular_size - GTA_HEADER_SIZE, nhead.size);
				mb_stripped = gmsg_split_to_pmsg(&nhead, data, regular_size);
			}
			mq_putq(dn->outq, pmsg_clone(mb_stripped));
		}
	}

	pmsg_free(mb);

	if (mb_stripped != NULL)
		pmsg_free(mb_stripped);
}


/**
 * Send message held in current node according to route specification.
 */
void
gmsg_sendto_route(struct gnutella_node *n, struct route_dest *rt)
{
	struct gnutella_node *rt_node = rt->ur.u_node;
	const GSList *sl;

	switch (rt->type) {
	case ROUTE_NONE:
		return;
	case ROUTE_ONE:
		gmsg_split_sendto_one(rt_node, &n->header,
				n->data, n->size + GTA_HEADER_SIZE);
		return;
	case ROUTE_ALL_BUT_ONE:
		g_assert(n == rt_node);
		gmsg_split_sendto_all_but_one(node_all_nodes(), rt_node,
			(guchar *) &n->header, n->data, n->size + GTA_HEADER_SIZE);
		return;
	case ROUTE_NO_DUPS_BUT_ONE:
		g_assert(n == rt_node);
		gmsg_split_sendto_all_but_one(node_all_but_broken_gtkg(), rt_node,
			(guchar *) &n->header, n->data, n->size + GTA_HEADER_SIZE);
		return;
	case ROUTE_MULTI:
		for (sl = rt->ur.u_nodes; sl; sl = g_slist_next(sl)) {
			rt_node = (struct gnutella_node *) sl->data;
			gmsg_split_sendto_one(rt_node,
				(guchar *) &n->header, n->data, n->size + GTA_HEADER_SIZE);
		}
		return;
	}

	g_error("unknown route destination: %d", rt->type);
}

/**
 * Send message from `n' to destination node `dn'.  If target node cannot
 * understand extra GGEP payloads, trim message before sending.
 *
 * @param n the source node.
 * @param dn the destination node.
 * @param regular_size	the size of the message including the header 
 *						and trailing GGEP data.
 */
static void
sendto_ggep(struct gnutella_node *n, struct gnutella_node *dn,
	guint32 regular_size)
{
	if (NODE_CAN_GGEP(dn)) {
		gmsg_split_sendto_one(dn, &n->header,
				n->data, n->size + GTA_HEADER_SIZE);
	} else {
		WRITE_GUINT32_LE(regular_size, n->header.size);
		gmsg_split_sendto_one(dn, &n->header,
				n->data, regular_size + GTA_HEADER_SIZE);
		WRITE_GUINT32_LE(n->size, n->header.size);
	}
}

/**
 * Same as gmsg_sendto_route() but if the node did not claim support of GGEP
 * extensions in pings, pongs and pushes, strip the GGEP payload before
 * forwarding the message.
 *
 * @param n the source node.
 * @param rt the destination route.
 * @param regular_size	the size of the message including the header 
 *						and trailing GGEP data.
 */
void
gmsg_sendto_route_ggep(struct gnutella_node *n, struct route_dest *rt,
	guint32 regular_size)
{
	struct gnutella_node *rt_node = rt->ur.u_node;
	const GSList *sl;

	g_assert(regular_size <= INT_MAX);

	switch (rt->type) {
	case ROUTE_NONE:
		return;
	case ROUTE_ONE:
		sendto_ggep(n, rt_node, regular_size);
		return;
	case ROUTE_ALL_BUT_ONE:
		g_assert(n == rt_node);
		gmsg_split_sendto_all_but_one_ggep(node_all_nodes(), rt_node,
			&n->header, n->data, n->size + GTA_HEADER_SIZE, regular_size);
		return;
	case ROUTE_NO_DUPS_BUT_ONE:
		g_assert(n == rt_node);
		gmsg_split_sendto_all_but_one_ggep(node_all_but_broken_gtkg(), rt_node,
			&n->header, n->data, n->size + GTA_HEADER_SIZE, regular_size);
		return;
	case ROUTE_MULTI:
		for (sl = rt->ur.u_nodes; sl; sl = g_slist_next(sl)) {
			rt_node = sl->data;
			sendto_ggep(n, rt_node, regular_size);
		}
		return;
	}

	g_error("unknown route destination: %d", rt->type);
}

/***
 *** Miscellaneous utilities.
 ***/

/**
 * Test whether a query can be sent.
 *
 * We look at the hops-flow, and whether there is a route for the query hits
 * if it is a non-OOB query: no need to forward the request if the reply
 * will be dropped.
 *
 * @note Queries with hops=0 are not necessarily ours, since the queries
 * from our leaves are propagated as if they were coming from ourselves.
 * Therefore, unless the OOB flag is set, we always check for an existing
 * route.
 */
static gboolean
gmsg_query_can_send(pmsg_t *mb, const mqueue_t *q)
{
	gnutella_node_t *n = mq_node(q);
	gconstpointer start = pmsg_start(mb);
	const struct gnutella_header *head = start;

	g_assert(head->function == GTA_MSG_SEARCH);

	if (!node_query_hops_ok(n, head->hops)) {
		if (gmsg_debug > 4)
			gmsg_log_dropped(start, "to node %s due to hops-flow",
				node_addr(n));
		return FALSE;
	}

	if (gmsg_is_oob_query(start))
		return TRUE;

	if (!route_exists_for_reply(start, head->function)) {
		if (gmsg_debug > 4)
			gmsg_log_dropped(start, "to node %s due to no route for hits",
				node_addr(n));
		return FALSE;
	}

	return TRUE;
}

/**
 * Install "pre-send" callback for certain types of messages.
 */
void
gmsg_install_presend(pmsg_t *mb)
{
	gconstpointer start = pmsg_start(mb);
	const struct gnutella_header *head = start;

	if (GTA_MSG_SEARCH == head->function) {
		pmsg_check_t old = pmsg_set_check(mb, gmsg_query_can_send);
		g_assert(NULL == old);
	}
}

/**
 * Test whether the Gnutella message can be safely dropped on the connection.
 * We're given the whole PDU, not just the payload.
 *
 * Dropping of messages only happens when the connection is flow-controlled,
 * and there's not enough room in the queue.
 */
gboolean
gmsg_can_drop(gconstpointer pdu, gint size)
{
	const struct gnutella_header *head = pdu;

	if ((size_t) size < sizeof(struct gnutella_header))
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

/**
 * Perform a priority comparison between two messages, given as the whole PDU.
 *
 * @return algebraic -1/0/+1 depending on relative order.
 */
gint
gmsg_cmp(gconstpointer pdu1, gconstpointer pdu2)
{
	const struct gnutella_header *h1 = pdu1, *h2 = pdu2;
	gint w1 = msg_weight[h1->function], w2 = msg_weight[h2->function];

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
			return CMP(h2->ttl, h1->ttl);
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

/**
 * @returns formatted static string:
 *
 *     msg_type (payload length) [hops=x, TTL=x]
 *
 * that can also decompile vendor messages given a pointer on the whole
 * message that contains the leading header immediately followed by the
 * payload of that message.
 */
gchar *
gmsg_infostr_full(gconstpointer message)
{
	const gchar *data = (gchar *) message + GTA_HEADER_SIZE;

	return gmsg_infostr_full_split(message, data);
}

/**
 * @returns formatted static string:
 *
 *     msg_type (payload length) [hops=x, TTL=x]
 *
 * that can also decompile vendor messages given a pointer on the header
 * and on the data of the message (which may not be consecutive in memory).
 */
gchar *
gmsg_infostr_full_split(gconstpointer head, gconstpointer data)
{
	static gchar a[160];
	const struct gnutella_header *h = (const struct gnutella_header *) head;
	guint32 size;

	READ_GUINT32_LE(h->size, size);
	size &= GTA_SIZE_MASK;

	switch (h->function) {
	case GTA_MSG_VENDOR:
	case GTA_MSG_STANDARD:
		gm_snprintf(a, sizeof(a), "%s %s (%u byte%s) %s[hops=%d, TTL=%d]",
			gmsg_name(h->function), vmsg_infostr(data, size),
			size, size == 1 ? "" : "s",
			h->ttl & GTA_UDP_DEFLATED ? "deflated " :
			h->ttl & GTA_UDP_CAN_INFLATE ? "can_inflate " : "",
			h->hops, h->ttl & ~(GTA_UDP_DEFLATED | GTA_UDP_CAN_INFLATE));
		break;
	default:
		gm_snprintf(a, sizeof(a), "%s (%u byte%s) %s[hops=%d, TTL=%d]",
			gmsg_name(h->function),
			size, size == 1 ? "" : "s",
			h->ttl & GTA_UDP_DEFLATED ? "deflated " : "",
			h->hops, h->ttl & ~GTA_UDP_DEFLATED);
		break;
	}

	return a;
}

/**
 * @returns formatted static string:
 *
 *     msg_type (payload length) [hops=x, TTL=x]
 */
gchar *
gmsg_infostr(gconstpointer head)
{
	static gchar a[80];
	const struct gnutella_header *h = head;
	guint32 size;

	READ_GUINT32_LE(h->size, size);
	size &= GTA_SIZE_MASK;

	gm_snprintf(a, sizeof(a), "%s (%u byte%s) %s[hops=%d, TTL=%d]",
		gmsg_name(h->function), size, size == 1 ? "" : "s",
		h->ttl & GTA_UDP_DEFLATED ? "deflated " : "",
		h->hops, h->ttl & ~GTA_UDP_DEFLATED);

	return a;
}

/**
 * Same as gmsg_infostr(), but different static buffer.
 */
static gchar *
gmsg_infostr2(gconstpointer head)
{
	static gchar a[80];
	const struct gnutella_header *h = head;
	guint32 size;

	READ_GUINT32_LE(h->size, size);
	size &= GTA_SIZE_MASK;

	gm_snprintf(a, sizeof(a), "%s (%u byte%s) %s[hops=%d, TTL=%d]",
		gmsg_name(h->function), size, size == 1 ? "" : "s",
		h->ttl & GTA_UDP_DEFLATED ? "deflated " : "",
		h->hops, h->ttl & ~GTA_UDP_DEFLATED);

	return a;
}

/**
 * Log dropped message, and reason.
 */
void
gmsg_log_dropped(gconstpointer head, const gchar *reason, ...)
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

/**
 * Log bad message, the node's vendor, and reason.
 */
void
gmsg_log_bad(const struct gnutella_node *n, const gchar *reason, ...)
{
	printf("BAD <%s> ", node_vendor(n));

	fputs(gmsg_infostr_full_split(&n->header, n->data), stdout);

	if (reason) {
		va_list args;
		va_start(args, reason);
		fputs(": ", stdout);
		vprintf(reason, args);
		va_end(args);
	}

	fputc('\n', stdout);
}

/**
 * Check whether query message starting at `msg' is flagged
 * for OOB hit delivery.
 */
gboolean
gmsg_is_oob_query(gconstpointer msg)
{
	const struct gnutella_header *h = msg;
	gconstpointer data = (const gchar *) msg + GTA_HEADER_SIZE;
	guint16 req_speed;

	g_assert(h->function == GTA_MSG_SEARCH);

	READ_GUINT16_LE(data, req_speed);

	return (req_speed & (QUERY_SPEED_MARK | QUERY_SPEED_OOB_REPLY)) ==
		(QUERY_SPEED_MARK | QUERY_SPEED_OOB_REPLY);
}

/**
 * Check whether query message split between header and data is flagged
 * for OOB hit delivery.
 */
gboolean
gmsg_split_is_oob_query(gconstpointer head, gconstpointer data)
{
	const struct gnutella_header *h = head;
	guint16 req_speed;

	g_assert(h->function == GTA_MSG_SEARCH);

	READ_GUINT16_LE(data, req_speed);

	return (req_speed & (QUERY_SPEED_MARK | QUERY_SPEED_OOB_REPLY)) ==
		(QUERY_SPEED_MARK | QUERY_SPEED_OOB_REPLY);
}

/* vi: set ts=4 sw=4 cindent: */
