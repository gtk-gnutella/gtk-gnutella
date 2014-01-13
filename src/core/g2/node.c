/*
 * Copyright (c) 2014 Raphael Manfredi
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
 * G2 message handling.
 *
 * @author Raphael Manfredi
 * @date 2014
 */

#include "common.h"

#include "node.h"

#include "build.h"
#include "frame.h"
#include "msg.h"
#include "tfmt.h"
#include "tree.h"

#include "core/alive.h"
#include "core/hosts.h"
#include "core/mq_tcp.h"
#include "core/mq_udp.h"
#include "core/nodes.h"

#include "if/gnet_property_priv.h"

#include "if/core/guid.h"

#include "lib/host_addr.h"
#include "lib/misc.h"			/* For dump_hex() */
#include "lib/pmsg.h"

#include "lib/override.h"		/* Must be the last header included */

/**
 * Send a message to target node.
 */
void
g2_node_send(gnutella_node_t *n, pmsg_t *mb)
{
	node_check(n);
	g_assert(NODE_TALKS_G2(n));

	if (NODE_IS_UDP(n))
		mq_udp_node_putq(n->outq, mb, n);
	else
		mq_tcp_putq(n->outq, mb, NULL);
}

/**
 * Send a pong to target node.
 */
static void
g2_node_send_pong(gnutella_node_t *n)
{
	pmsg_t *mb = g2_build_pong();

	g2_node_send(n, mb);
}

/**
 * Send a /QHT RESET to node.
 *
 * @param n			the TCP node to which we need to send the /QHT
 * @param slots		amount of slots in the table (power of 2)
 * @param inf_val	infinity value (1)
 */
void
g2_node_send_qht_reset(gnutella_node_t *n, int slots, int inf_val)
{
	pmsg_t *mb = g2_build_qht_reset(slots, inf_val);

	node_check(n);
	g_assert(!NODE_IS_UDP(n));

	g2_node_send(n, mb);
}

/**
 * Send a /QHT RESET to node.
 *
 * @param n			the TCP node to which we need to send the /QHT
 * @param seqno			the patch sequence number
 * @param seqsize		the total length of the sequence
 * @param compressed	whether patch is compressed
 * @param bits			amount of bits for each entry (1)
 * @param buf			start of patch data
 * @param len			length in byte of patch data
 */
void
g2_node_send_qht_patch(gnutella_node_t *n,
	int seqno, int seqsize, bool compressed, int bits,
	char *buf, int len)
{
	pmsg_t *mb = g2_build_qht_patch(seqno, seqsize, compressed, bits, buf, len);

	node_check(n);
	g_assert(!NODE_IS_UDP(n));

	g2_node_send(n, mb);
}

/**
 * Send a /LNI to node.
 */
void
g2_node_send_lni(gnutella_node_t *n)
{
	pmsg_t *mb = g2_build_lni();

	node_check(n);
	g_assert(!NODE_IS_UDP(n));

	g2_node_send(n, mb);
}

/**
 * Drop message received from given node.
 *
 * @param routine		routine where we're coming from (the one dropping)
 * @param n				source node of message
 * @param t				the message tree
 * @param reason		optional reason
 */
static void
g2_node_drop(const char *routine, gnutella_node_t *n, const g2_tree_t *t,
	const char *reason)
{
	if (GNET_PROPERTY(g2_debug) || GNET_PROPERTY(log_dropped_g2)) {
		g_debug("%s(): dropping %s packet from %s%s%s",
			routine, g2_tree_name(t), node_infostr(n),
			NULL == reason ? "" : ": ",
			NULL == reason ? "" : reason);
	}
	if (GNET_PROPERTY(log_dropped_g2)) {
		g2_tfmt_tree_dump(t, stderr, G2FMT_O_PAYLEN);
	}
}

/**
 * Handle reception of a /PI
 */
static void
g2_node_handle_ping(gnutella_node_t *n, const g2_tree_t *t)
{
	g2_tree_t *c;

	/*
	 * Drop pings received from UDP.
	 */

	if (NODE_IS_UDP(n)) {
		g2_node_drop(G_STRFUNC, n, t, "coming from UDP");
		return;
	}

	c = g2_tree_first_child(t);

	/*
	 * If there is no payload, it's a keep-alive ping, send back a pong.
	 */

	if (NULL == c) {
		g2_node_send_pong(n);
		return;
	}

	/*
	 * There are children.
	 *
	 * If there is a /PI/UDP present, drop the message: we're not a hub,
	 * we don't have to relay this message to its UDP target (we're only
	 * connected to hubs, and the hub which got it should only forward that
	 * message it its neighbouring hubs, not to leaves).
	 *
	 * If there is a /PI/RELAY, the ping was relayed by a hub, but it made
	 * a mistake because we are a leaf node.
	 */

	g2_node_drop(G_STRFUNC, n, t, "has children and we are a leaf");
}

/**
 * Handle reception of a /PO
 */
static void
g2_node_handle_pong(gnutella_node_t *n, const g2_tree_t *t)
{
	/*
	 * Drop pongs received from UDP.
	 */

	if (NODE_IS_UDP(n)) {
		g2_node_drop(G_STRFUNC, n, t, "coming from UDP");
		return;
	}

	/*
	 * Must be a pong received because we sent an alive ping earlier.
	 */

	alive_ack_ping(n->alive_pings, NULL);	/* No MUID on G2 */
}

/**
 * Handle reception of a /LNI
 */
static void
g2_node_handle_lni(gnutella_node_t *n, const g2_tree_t *t)
{
	g2_tree_t *c;

	/* GU -- the node's GUID */

	c = g2_tree_lookup(t, "/LNI/GU");
	if (c != NULL) {
		const void *payload;
		size_t paylen;

		payload = g2_tree_node_payload(c, &paylen);
		if (GUID_RAW_SIZE == paylen)
			node_set_guid(n, (guid_t *) payload, TRUE);
	}

	/* NA -- the node's address, with listening port */

	c = g2_tree_lookup(t, "/LNI/NA");
	if (c != NULL) {
		const char *payload;
		size_t paylen;

		payload = g2_tree_node_payload(c, &paylen);

		/*
		 * Only handle if we have the port, because otherwise we already
		 * know the remote IP address since we're connected to the node!
		 * We only handle IPv4 because G2 does not support IPv6.
		 */

		if (6 == paylen) {		/* IPv4 + port */
			host_addr_t addr;
			uint16 port;

			addr = host_addr_peek_ipv4(payload);
			port = peek_le16(&payload[4]);

			if (host_address_is_usable(addr))
				n->gnet_addr = addr;
			n->gnet_port = port;
		}
	}

	/* LS -- library statistics */

	c = g2_tree_lookup(t, "/LNI/LS");
	if (c != NULL) {
		const char *payload;
		size_t paylen;

		payload = g2_tree_node_payload(c, &paylen);

		if (paylen >= 8) {
			uint32 files = peek_le32(payload);
			uint32 kbytes = peek_le32(&payload[4]);

			n->gnet_files_count = files;
			n->gnet_kbytes_count = kbytes;
			n->flags |= NODE_F_SHARED_INFO;
		}
	}

	/* V -- vendor code */

	c = g2_tree_lookup(t, "/LNI/V");
	if (c != NULL) {
		const char *payload;
		size_t paylen;

		payload = g2_tree_node_payload(c, &paylen);

		if (paylen >= 4)
			n->vcode.u32 = peek_be32(payload);
	}
}

/**
 * Handle message coming from G2 node.
 */
void
g2_node_handle(gnutella_node_t *n)
{
	g2_tree_t *t;
	size_t plen;
	enum g2_msg type;

	node_check(n);
	g_assert(NODE_TALKS_G2(n));

	t = g2_frame_deserialize(n->data, n->size, &plen, FALSE);
	if (NULL == t) {
		g_warning("%s(): cannot deserialize %s packet from %s",
			G_STRFUNC, g2_msg_raw_name(n->data, n->size), node_infostr(n));
		if (GNET_PROPERTY(log_bad_g2) > 10)
			dump_hex(stderr, "G2 Packet", n->data, n->size);
		return;
	} else if (plen != n->size) {
		g_warning("%s(): consumed %zu bytes but %s packet from %s had %u",
			G_STRFUNC, plen, g2_msg_raw_name(n->data, n->size),
			node_infostr(n), n->size);
		if (GNET_PROPERTY(log_bad_g2) > 10)
			dump_hex(stderr, "G2 Packet", n->data, n->size);
		return;
	} else if (GNET_PROPERTY(g2_debug) > 19) {
		g_debug("%s(): received packet from %s", G_STRFUNC, node_infostr(n));
		g2_tfmt_tree_dump(t, stderr, G2FMT_O_PAYLEN);
	}

	type = g2_msg_name_type(g2_tree_name(t));

	switch (type) {
	case G2_MSG_PI:
		g2_node_handle_ping(n, t);
		break;
	case G2_MSG_PO:
		g2_node_handle_pong(n, t);
		break;
	case G2_MSG_LNI:
		g2_node_handle_lni(n, t);
		break;
	default:
		g2_node_drop(G_STRFUNC, n, t, "default");
		break;
	}

	g2_tree_free_null(&t);
}

/* vi: set ts=4 sw=4 cindent: */
