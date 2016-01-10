/*
 * Copyright (c) 2002-2003, 2014 Raphael Manfredi
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
 * @date 2002-2003, 2014
 */

#include "common.h"

#include <zlib.h>	/* Z_DEFAULT_COMPRESSION */

#include "gmsg.h"

#include "gnet_stats.h"
#include "mq_tcp.h"
#include "mq_udp.h"
#include "nodes.h"
#include "routing.h"
#include "search.h"
#include "settings.h"
#include "sq.h"
#include "vmsg.h"

#include "g2/msg.h"

#include "if/gnet_property_priv.h"
#include "if/dht/kmsg.h"
#include "if/dht/kademlia.h"

#include "lib/endian.h"
#include "lib/omalloc.h"
#include "lib/once.h"
#include "lib/pmsg.h"
#include "lib/pslist.h"
#include "lib/str.h"
#include "lib/stringify.h"
#include "lib/unsigned.h"
#include "lib/walloc.h"
#include "lib/zlib_util.h"

#include "lib/override.h"		/* Must be the last header included */

static const char *msg_name[256];
static uint8 msg_weight[256];	/**< For gmsg_cmp() */
static uint8 kmsg_weight[256];	/**< For gmsg_cmp() */

static zlib_deflater_t *gmsg_deflater;

/**
 * Ensure that the gnutella message header has the correct size,
 * a TTL greater than zero and that size is at least 23 (GTA_HEADER_SIZE).
 *
 * @param h		the gnutella message header to check.
 * @param size	the payload plus header size of the gnutella message.
 */
static inline void
gmsg_header_check(const void *msg, uint32 size)
{
	g_assert(gnutella_header_get_ttl(msg) > 0);
	g_assert(size >= GTA_HEADER_SIZE);
	g_assert(gnutella_header_get_size(msg) == size - GTA_HEADER_SIZE);
}

/**
 * Returns whether the size field is properly architected as flags and size.
 *
 * @param msg		the head of the message
 * @param size		where the message size is returned if valid
 *
 * @return GMSG_VALID if we can process the message, GMSG_INVALID if the
 * message should be dropped and the connection closed, GMSG_VALID_NO_PROCESS
 * if the message is valid but cannot be interpreted locally.
 */
gmsg_valid_t
gmsg_size_valid(const void *msg, uint16 *size)
{
	uint32 raw_size = gnutella_header_get_size(msg);
	uint16 payload_size = (uint16) (raw_size & GTA_SIZE_MASK);

	if (raw_size == payload_size)
		goto ok;

	if (raw_size & GTA_SIZE_MARKED) {
		uint32 flags = raw_size & ~GTA_SIZE_MASK;
		flags &= ~GTA_SIZE_MARKED;

		*size = payload_size;

		if (flags == 0)
			return GMSG_VALID_MARKED;

		/*
		 * We don't know how to handle flags yet -- they are undefined.
		 * However, the message IS valid and could be relayed possibly.
		 * But we cannot interpret it.
		 */

		return GMSG_VALID_NO_PROCESS;
	}

	return GMSG_INVALID;

ok:
	*size = payload_size;
	return GMSG_VALID;
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
gmsg_dump(FILE *out, const void *data, uint32 size)
{
	g_assert(size >= GTA_HEADER_SIZE);

	dump_hex(out, gmsg_infostr_full(data, size),
		(char *) data + GTA_HEADER_SIZE, size - GTA_HEADER_SIZE);
}

/**
 * Same as gmsg_dump(), but the header and the PDU data are separated.
 */
static void
gmsg_split_dump(FILE *out, const void *head, const void *data,
	uint32 size)
{
	g_assert(size >= GTA_HEADER_SIZE);

	dump_hex(out, gmsg_infostr_full_split(head, data, size - GTA_HEADER_SIZE),
		data, size - GTA_HEADER_SIZE);
}

/**
 * Initialization of the Gnutella message structures.
 */
void G_COLD
gmsg_init(void)
{
	int i;

#define VMSG_W	10		/* Special weight to flag vendor messages */

	for (i = 0; i < 256; i++) {
		const char *s = "unknown";
		uint w = 0;

		switch ((enum gta_msg) i) {
		case GTA_MSG_DHT:            w = 0;      s = "DHT"; break;
		case GTA_MSG_HSEP_DATA:      w = 0;      s = "HSEP"; break;
		case GTA_MSG_INIT:           w = 1;      s = "Ping"; break;
		case GTA_MSG_SEARCH:         w = 2;      s = "Query"; break;
		case GTA_MSG_INIT_RESPONSE:  w = 3;      s = "Pong"; break;
		case GTA_MSG_SEARCH_RESULTS: w = 4;      s = "Q-Hit"; break;
		case GTA_MSG_PUSH_REQUEST:   w = 5;      s = "Push"; break;
		case GTA_MSG_VENDOR:         w = VMSG_W; s = "Vndor"; break;
		case GTA_MSG_STANDARD:       w = VMSG_W; s = "Vstd"; break;
		case GTA_MSG_RUDP:   		 w = 6;      s = "RUDP"; break;
		case GTA_MSG_QRP:            w = 8;      s = "QRP"; break;
		case GTA_MSG_BYE:      		 w = 9;      s = "BYE"; break;
		case GTA_MSG_G2_SEARCH: /* Not a real message */ break;
		}
		msg_name[i] = s;
		msg_weight[i] = w;
	}

	/*
	 * We need to be able to compare Gnutella and Kademlia messages since
	 * they can both be found in the same UDP queue.
	 *
	 * The messages with a weight of 0 can be dropped quite safely in
	 * flow-control situations.  See also kmsg_can_drop().
	 *
	 * NB: This is defined here and not in the DHT sources to avoid a costly
	 * function call in gmsg_cmp() and also because respective weights of
	 * Gnutella and Kademlia messages must be defined with knowledge of each
	 * other.
	 */

	for (i = 0; i < 256; i++) {
		uint w = 0;

		switch ((enum kda_msg) i) {
		case KDA_MSG_PING_REQUEST:        w = 1; break;
		case KDA_MSG_PING_RESPONSE:       w = 2; break;
		case KDA_MSG_STORE_REQUEST:       w = 0; break;
		case KDA_MSG_STORE_RESPONSE:      w = 3; break;
		case KDA_MSG_FIND_NODE_REQUEST:   w = 0; break;
		case KDA_MSG_FIND_NODE_RESPONSE:  w = 0; break;
		case KDA_MSG_FIND_VALUE_REQUEST:  w = 0; break;
		case KDA_MSG_FIND_VALUE_RESPONSE: w = 7; break;
		case KDA_MSG_STATS_REQUEST:       w = 0; break;	/* UNUSED */
		case KDA_MSG_STATS_RESPONSE:      w = 0; break;	/* UNUSED */
		}
		kmsg_weight[i] = w;
	}

	gmsg_deflater = zlib_deflater_make(NULL, 0, Z_BEST_COMPRESSION);
}

/**
 * Destroy locally-allocated data.
 */
void G_COLD
gmsg_close(void)
{
	zlib_deflater_free(gmsg_deflater, TRUE);
}

/**
 * Convert message function number into name.
 */
const char *
gmsg_name(uint function)
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
gmsg_to_pmsg(const void *msg, uint32 size)
{
	pmsg_t *mb;

	mb = pmsg_new(PMSG_P_DATA, msg, size);
	gmsg_install_presend(mb);
	return mb;
}

/**
 * Construct compressed regular PDU descriptor from message, for UDP traffic.
 * The message payload is deflated only when the resulting size is smaller
 * than the raw uncompressed form.
 *
 * Message data is copied into the new data buffer, so caller may release
 * its memory.
 *
 * @param head		pointer to the Gnutella header
 * @param data		pointer to the Gnutella payload
 * @param size		the total size of the message, header + payload
 *
 * @return new message, with possibly deflated payload content.
 * The caller can tell because deflated payloads are signaled with the
 * TTL having the GTA_UDP_DEFLATED bit set.
 */
pmsg_t *
gmsg_split_to_deflated_pmsg(const void *head, const void *data, uint32 size)
{
	uint32 plen = size - GTA_HEADER_SIZE;		/* Raw payload length */
	void *buf;									/* Compression made there */
	uint32 deflated_length;						/* Length of deflated data */
	pmsg_t *mb;

	/*
	 * Since there is a 2-byte header added to each deflated stream, plus
	 * a trailing 16-bit checksum, it's no use to attempt deflation if
	 * the payload has less than 5 bytes.
	 */

	if (plen <= 5)
		goto send_raw;

	/*
	 * Compress payload into internally allocated buffer (in gmsg_deflater).
	 */

	zlib_deflater_reset(gmsg_deflater, data, plen);

	if (-1 == zlib_deflate_all(gmsg_deflater)) {
		g_carp("%s(): deflate error", G_STRFUNC);
		goto send_raw;
	}

	/*
	 * Check whether compressed data is smaller than the original payload.
	 */

	deflated_length = zlib_deflater_outlen(gmsg_deflater);
	buf = zlib_deflater_out(gmsg_deflater);

	g_assert(zlib_is_valid_header(buf, deflated_length));

	gnet_stats_inc_general(GNR_UDP_COMPRESSION_ATTEMPTS);

	if (deflated_length >= plen) {
		if (GNET_PROPERTY(udp_debug))
			g_debug("UDP not deflating %s into %d bytes",
				gmsg_infostr_full_split(head, data, size), deflated_length);

		gnet_stats_inc_general(GNR_UDP_LARGER_HENCE_NOT_COMPRESSED);
		goto send_raw;
	}

	/*
	 * OK, we gain something so we'll send this payload deflated.
	 */

	mb = gmsg_split_to_pmsg(head, buf, deflated_length + GTA_HEADER_SIZE);

	if (GNET_PROPERTY(udp_debug))
		g_debug("UDP deflated %s into %d bytes",
			gmsg_infostr_full_split(head, data, size), deflated_length);

	{
		void *header;

		header = pmsg_start(mb);
		gnutella_header_set_ttl(header,
			gnutella_header_get_ttl(header) | GTA_UDP_DEFLATED);
		gnutella_header_set_size(header, deflated_length);
	}

	return mb;

send_raw:
	/*
	 * Send payload as-is (uncompressed).
	 */

	return gmsg_split_to_pmsg(head, data, size);
}

/**
 * Construct compressed regular PDU descriptor from message, for UDP traffic.
 * The message payload is deflated only when the resulting size is smaller
 * than the raw uncompressed form.
 *
 * Message data is copied into the new data buffer, so caller may release
 * its memory.
 *
 * @param msg		pointer to the Gnutella message (payload follows header)
 * @param size		the total size of the message, header + payload
 *
 * @return new message, with possibly deflated payload content.
 * The caller can tell because deflated payloads are signaled with the
 * TTL having the GTA_UDP_DEFLATED bit set.
 */
pmsg_t *
gmsg_to_deflated_pmsg(const void *msg, uint32 size)
{
	const char *data = const_ptr_add_offset(msg, GTA_HEADER_SIZE);

	return gmsg_split_to_deflated_pmsg(msg, data, size);
}

/**
 * Construct control PDU descriptor from message.
 */
pmsg_t *
gmsg_to_ctrl_pmsg(const void *msg, uint32 size)
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
gmsg_to_ctrl_pmsg_extend(const void *msg, uint32 size,
	pmsg_free_t free_cb, void *arg)
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
write_message(pmsg_t *mb, const void *head, const void *data, uint32 size)
{
	size_t written;

	written = pmsg_write(mb, head, GTA_HEADER_SIZE);
	written += pmsg_write(mb, data, size - GTA_HEADER_SIZE);

	g_assert(written == size);
}

/**
 * Construct PDU from header and data.
 *
 * @param head		pointer to the Gnutella header
 * @param data		pointer to the Gnutella payload
 * @param size		the total size of the message, header + payload
 */
pmsg_t *
gmsg_split_to_pmsg(const void *head, const void *data, uint32 size)
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
gmsg_split_to_pmsg_extend(const void *head, const void *data,
	uint32 size, pmsg_free_t free_cb, void *arg)
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
gmsg_mb_sendto_all(const pslist_t *sl, pmsg_t *mb)
{
	gmsg_header_check(cast_to_constpointer(pmsg_start(mb)), pmsg_size(mb));

	if (GNET_PROPERTY(gmsg_debug) > 5 && gmsg_hops(pmsg_start(mb)) == 0)
		gmsg_dump(stdout, pmsg_start(mb), pmsg_size(mb));

	for (/* empty */; sl; sl = pslist_next(sl)) {
		gnutella_node_t *dn = sl->data;
		if (!NODE_IS_ESTABLISHED(dn))
			continue;
		mq_tcp_putq(dn->outq, pmsg_clone(mb), NULL);
	}
}

/**
 * Route message to one node.
 *
 * The supplied mb is NOT cloned, it is up to the caller to ensure that
 * a private instance is supplied.
 */
void
gmsg_mb_routeto_one(const gnutella_node_t *from,
	const gnutella_node_t *to, pmsg_t *mb)
{
	g_assert(!NODE_TALKS_G2(to));
	g_assert(!pmsg_was_sent(mb));
	gmsg_header_check(cast_to_constpointer(pmsg_start(mb)), pmsg_size(mb));

	if (!NODE_IS_WRITABLE(to))
		return;

	if (GNET_PROPERTY(gmsg_debug) > 5 && gmsg_hops(pmsg_start(mb)) == 0)
		gmsg_dump(stdout, pmsg_start(mb), pmsg_size(mb));

	if (NODE_IS_UDP(to)) {
		gnet_host_t host;
		gnet_host_set(&host, to->addr, to->port);
		mq_udp_putq(to->outq, mb, &host);
	} else {
		mq_tcp_putq(to->outq, mb, from);
	}
}

/**
 * Send message to one node.
 *
 * The supplied mb is NOT cloned, it is up to the caller to ensure that
 * a private instance is supplied.
 */
void
gmsg_mb_sendto_one(const gnutella_node_t *n, pmsg_t *mb)
{
	gmsg_mb_routeto_one(NULL, n, mb);
}

/**
 * Send message to one node.
 */
void
gmsg_sendto_one(gnutella_node_t *n, const void *msg, uint32 size)
{
	g_assert(!NODE_TALKS_G2(n));

	if (!NODE_IS_WRITABLE(n))
		return;

	gmsg_header_check(msg, size);

	if (GNET_PROPERTY(gmsg_debug) > 5 && gmsg_hops(msg) == 0)
		gmsg_dump(stdout, msg, size);

	/*
	 * A GUESS query generating a local hit will come here if the query is
	 * not requesting OOB hit delivery.
	 */

	if (NODE_IS_UDP(n)) {
		pmsg_t *mb;
		gnet_host_t to;

		gnet_host_set(&to, n->addr, n->port);

		if (GNET_PROPERTY(guess_server_debug) > 19) {
			g_debug("GUESS sending local hit (%s) for #%s to %s",
				NODE_CAN_SR_UDP(n) ? "reliably" :
				NODE_CAN_INFLATE(n) ? "possibly deflated" : "uncompressed",
				guid_hex_str(gnutella_header_get_muid(msg)), node_infostr(n));
		}

		if (NODE_CAN_SR_UDP(n)) {
			mb = gmsg_to_pmsg(msg, size);
			pmsg_mark_reliable(mb);
		} else {
			mb = NODE_CAN_INFLATE(n) ?
				gmsg_to_deflated_pmsg(msg, size) :
				gmsg_to_pmsg(msg, size);
		}

		mq_udp_putq(n->outq, mb, &to);
	} else {
		mq_tcp_putq(n->outq, gmsg_to_pmsg(msg, size), NULL);
	}
}

/**
 * Send control message to one node.
 *
 * A control message is inserted ahead any other queued regular data.
 */
void
gmsg_ctrl_sendto_one(gnutella_node_t *n, const void *msg, uint32 size)
{
	g_assert(!NODE_TALKS_G2(n));
	g_return_if_fail(!NODE_IS_UDP(n));

	gmsg_header_check(msg, size);

	if (!NODE_IS_WRITABLE(n))
		return;

	if (GNET_PROPERTY(gmsg_debug) > 6 && gmsg_hops(msg) == 0)
		gmsg_dump(stdout, msg, size);

	mq_tcp_putq(n->outq, gmsg_to_ctrl_pmsg(msg, size), NULL);
}

/**
 * Send our search message to one node.
 */
void
gmsg_search_sendto_one(
	gnutella_node_t *n, gnet_search_t sh, const void *msg, uint32 size)
{
	g_assert(!NODE_TALKS_G2(n));
	g_return_if_fail(!NODE_IS_UDP(n));

	gmsg_header_check(msg, size);
	g_assert(gnutella_header_get_hops(msg)<= GNET_PROPERTY(hops_random_factor));

	if (!NODE_IS_WRITABLE(n))
		return;

	if (GNET_PROPERTY(gmsg_debug) > 5 && gmsg_hops(msg) == 0)
		gmsg_dump(stdout, msg, size);

	sq_putq(n->searchq, sh, gmsg_to_pmsg(msg, size));
}

/**
 * Send message consisting of header and data to one node.
 */
static void
gmsg_split_send_from_to(gnutella_node_t *from, gnutella_node_t *to,
	const void *head, const void *data, uint32 size)
{
	g_assert(!NODE_TALKS_G2(to));
	g_return_if_fail(!NODE_IS_UDP(to));

	gmsg_header_check(head, size);

	if (!NODE_IS_WRITABLE(to))
		return;

	if (GNET_PROPERTY(gmsg_debug) > 6)
		gmsg_split_dump(stdout, head, data, size);

	mq_tcp_putq(to->outq, gmsg_split_to_pmsg(head, data, size), from);
}

/**
 * Send message consisting of header and data to one node.
 */
void
gmsg_split_sendto_one(gnutella_node_t *n,
	const void *head, const void *data, uint32 size)
{
	gmsg_split_send_from_to(NULL, n, head, data, size);
}

/**
 * Route message consisting of header and data to one node.
 */
static void
gmsg_split_routeto_one(gnutella_node_t *from, gnutella_node_t *to,
	const void *head, const void *data, uint32 size)
{
	gmsg_split_send_from_to(from, to, head, data, size);
}

/**
 * Broadcast message to all nodes in the list.
 */
void
gmsg_sendto_all(const pslist_t *sl, const void *msg, uint32 size)
{
	pmsg_t *mb = gmsg_to_pmsg(msg, size);

	gmsg_header_check(msg, size);

	if (GNET_PROPERTY(gmsg_debug) > 5 && gmsg_hops(msg) == 0)
		gmsg_dump(stdout, msg, size);

	for (/* empty */; sl; sl = pslist_next(sl)) {
		gnutella_node_t *dn = sl->data;
		if (!NODE_IS_ESTABLISHED(dn))
			continue;
		mq_tcp_putq(dn->outq, pmsg_clone(mb), NULL);
	}

	pmsg_free(mb);
}

/**
 * Broadcast our search message to all nodes in the list.
 */
void
gmsg_search_sendto_all(
	const pslist_t *sl, gnet_search_t sh, const void *msg, uint32 size)
{
	pmsg_t *mb = gmsg_to_pmsg(msg, size);

	gmsg_header_check(msg, size);
	g_assert(gnutella_header_get_hops(msg)<= GNET_PROPERTY(hops_random_factor));

	if (GNET_PROPERTY(gmsg_debug) > 5 && gmsg_hops(msg) == 0)
		gmsg_dump(stdout, msg, size);

	for (/* empty */; sl; sl = pslist_next(sl)) {
		gnutella_node_t *dn = sl->data;

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
 * Route message from ``from'' consisting of header and data to all nodes in
 * the list but one node ``n''.
 *
 * We never broadcast anything to a leaf node.  Those are handled specially.
 */
static void
gmsg_split_routeto_all_but_one(const gnutella_node_t *from,
	const pslist_t *sl, const gnutella_node_t *n,
	const void *head, const void *data, uint32 size)
{
	pmsg_t *mb = gmsg_split_to_pmsg(head, data, size);
	bool skip_up_with_qrp = FALSE;

	/*
	 * Special treatment for TTL=1 queries in UP mode.
	 */

	if (
		settings_is_ultra() &&
		gnutella_header_get_function(head) == GTA_MSG_SEARCH &&
		gnutella_header_get_ttl(head) == 1
	)
		skip_up_with_qrp = TRUE;

	gmsg_header_check(head, size);

	/* relayed broadcasted message, cannot be sent with hops=0 */

	for (/* empty */; sl; sl = pslist_next(sl)) {
		gnutella_node_t *dn = sl->data;
		if (dn == n)
			continue;
		if (!NODE_IS_ESTABLISHED(dn) || NODE_IS_LEAF(dn))
			continue;
		if (skip_up_with_qrp && NODE_UP_QRP(dn))
			continue;
		if (n->header_flags && !NODE_CAN_SFLAG(dn))
			continue;
		mq_tcp_putq(dn->outq, pmsg_clone(mb), from);
	}

	pmsg_free(mb);
}

/**
 * Route message consisting of header and data to all the nodes in the list.
 */
void
gmsg_split_routeto_all(
	const pslist_t *sl,
	const gnutella_node_t *from,
	const void *head, const void *data, uint32 size)
{
	pmsg_t *mb = gmsg_split_to_pmsg(head, data, size);

	gmsg_header_check(head, size);

	/* relayed broadcasted message, cannot be sent with hops=0 */

	for (/* empty */; sl; sl = pslist_next(sl)) {
		gnutella_node_t *dn = sl->data;

		if (!NODE_IS_ESTABLISHED(dn))
			continue;

		/*
		 * We have already tested that the node was being writable.
		 */

		mq_tcp_putq(dn->outq, pmsg_clone(mb), from);
	}

	pmsg_free(mb);
}

/**
 * Send Gnutella message held in current node according to route specification.
 */
void
gmsg_sendto_route(gnutella_node_t *n, struct route_dest *rt)
{
	gnutella_node_t *rt_node = rt->ur.u_node;
	const pslist_t *sl;

	/*
	 * If during processing (e.g. in search_request_preprocess()) after
	 * route_message() was called someone is resetting the TTL to 0,
	 * then it will cause the message to not be sent out, regardless of
	 * the computed route.
	 */

	if (0 == gnutella_header_get_ttl(&n->header))
		return;

	switch (rt->type) {
	case ROUTE_NONE:
		return;
	case ROUTE_LEAVES:
		g_assert_not_reached();
		break;
	case ROUTE_ONE:
		node_check(rt_node);

		/*
		 * Make sure the message does not accidentally cross a network boundary.
		 * This is a Gnutella message, it can only be sent to Gnutella nodes.
		 */

		if (NODE_TALKS_G2(rt_node)) {
			gnet_stats_count_dropped(n, MSG_DROP_NETWORK_CROSSING);
			return;
		}

		/*
		 * If message has size flags and the recipient cannot understand it,
		 * then too bad but we have to drop that message.  We account it
		 * as dropped because this message was meant to be routed to one
		 * recipient only.
		 */

		if (n->header_flags && !NODE_CAN_SFLAG(rt_node)) {
			gnet_stats_count_dropped(n, MSG_DROP_BAD_SIZE);
			return;
		}

		gmsg_split_routeto_one(n, rt_node, &n->header,
				n->data, n->size + GTA_HEADER_SIZE);
		return;
	case ROUTE_ALL_BUT_ONE:
		g_assert(n == rt_node);
		gmsg_split_routeto_all_but_one(n, node_all_ultranodes(), rt_node,
			&n->header, n->data, n->size + GTA_HEADER_SIZE);
		return;
	case ROUTE_MULTI:
		PSLIST_FOREACH(rt->ur.u_nodes, sl) {
			rt_node = sl->data;
			node_check(rt_node);
			if (NODE_TALKS_G2(rt_node))
				continue;
			if (n->header_flags && !NODE_CAN_SFLAG(rt_node))
				continue;
			gmsg_split_routeto_one(n, rt_node,
				&n->header, n->data, n->size + GTA_HEADER_SIZE);
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
static bool
gmsg_query_can_send(const pmsg_t *mb, const void *q)
{
	gnutella_node_t *n = mq_node(q);
	const void *msg = pmsg_start(mb);

	g_assert(GTA_MSG_SEARCH == gnutella_header_get_function(msg));

	if (!node_query_hops_ok(n, gnutella_header_get_hops(msg))) {
		if (GNET_PROPERTY(gmsg_debug) > 4)
			gmsg_log_dropped_pmsg(mb,
				"to node %s due to hops-flow", node_addr(n));
		return FALSE;
	}

	if (gmsg_is_oob_query(msg))
		return TRUE;

	if (!route_exists_for_reply(msg, gnutella_header_get_function(msg))) {
		if (GNET_PROPERTY(gmsg_debug) > 4)
			gmsg_log_dropped_pmsg(mb,
				"to node %s due to no route for hits", node_addr(n));
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
	const void *msg = pmsg_start(mb);

	if (GTA_MSG_SEARCH == gnutella_header_get_function(msg)) {
		pmsg_set_check(mb, gmsg_query_can_send);
	}
}

/**
 * Test whether the Gnutella message can be safely dropped on the connection.
 * We're given the whole PDU, not just the payload.
 *
 * Dropping of messages only happens when the connection is flow-controlled,
 * and there's not enough room in the queue.
 */
bool
gmsg_can_drop(const void *pdu, int size)
{
	if ((size_t) size < GTA_HEADER_SIZE)
		return TRUE;

	switch (gnutella_header_get_function(pdu)) {
	case GTA_MSG_INIT:
	case GTA_MSG_SEARCH:
	case GTA_MSG_INIT_RESPONSE:
		return TRUE;
	case GTA_MSG_DHT:
		return kmsg_can_drop(pdu, size);
	default:
		return FALSE;
	}
}

/**
 * Perform a priority comparison between two messages, given as whole PDUs.
 *
 * If h2_pdu is FALSE, then h2 is only a Gnutella header, not a whole PDU.
 *
 * @return algebraic -1/0/+1 depending on relative order.
 */
static int
gmsg_cmp_internal(const void *h1, const void *h2, bool h2_pdu)
{
	int w1, w2;
	uint8 f1, f2;
	uint8 hop1, hop2;

	f1 = gnutella_header_get_function(h1);
	f2 = gnutella_header_get_function(h2);

	w1 = (f1 == GTA_MSG_DHT) ?
		kmsg_weight[kademlia_header_get_function(h1)] :  msg_weight[f1];
	w2 = (f2 == GTA_MSG_DHT && h2_pdu) ?
		kmsg_weight[kademlia_header_get_function(h2)] :  msg_weight[f2];

	/*
	 * Special case for vendor messages.
	 */

	w1 = w1 == VMSG_W ?  vmsg_weight(gnutella_data(h1)) : w1;
	w2 = (w2 == VMSG_W && h2_pdu) ? vmsg_weight(gnutella_data(h2)) : w2;

	/*
	 * The more weight a message type has, the more prioritary it is.
	 */

	if (w1 != w2)
		return w1 < w2 ? -1 : +1;

	/*
	 * Same weight.
	 *
	 * DHT messages are less prioritary than Gnutella.
	 * Between 2 DHT messages, keep the shortest.
	 */

	if (f1 == GTA_MSG_DHT) {
		uint32 s1 = gnutella_header_get_size(h1);
		uint32 s2 = gnutella_header_get_size(h2);
		return f2 == GTA_MSG_DHT ?  CMP(s2, s1) : -1;
	} else if (f2 == GTA_MSG_DHT) {
		return +1;		/* Gnutella message (f1) more prioritary */
	}

	/*
	 * Same weight, both Gnutella messages.
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

	hop1 = gnutella_header_get_hops(h1);
	hop2 = gnutella_header_get_hops(h2);

	if (hop1 == hop2) {
		switch (f1) {
		case GTA_MSG_PUSH_REQUEST:
		case GTA_MSG_SEARCH_RESULTS:
			{
				uint8 t1 = gnutella_header_get_ttl(h1);
				uint8 t2 = gnutella_header_get_ttl(h2);
				int ttlc = CMP(t2, t1);
				/* If same TTL, favor the shortest message */
				if (ttlc) {
					return ttlc;
				} else {
					uint32 s1 = gnutella_header_get_size(h1);
					uint32 s2 = gnutella_header_get_size(h2);
					return CMP(s2, s1);
				}
			}
		default:
			/* Favor the shortest */
			{
				uint32 s1 = gnutella_header_get_size(h1);
				uint32 s2 = gnutella_header_get_size(h2);
				return CMP(s2, s1);
			}
		}
	} else {
		switch (f1) {
		case GTA_MSG_INIT:
		case GTA_MSG_SEARCH:
		case GTA_MSG_QRP:
			return hop1 > hop2 ? -1 : +1;
		default:
			return hop1 < hop2 ? -1 : +1;
		}
	}
}

/**
 * Perform a priority comparison between two messages, given as whole PDUs.
 *
 * @return algebraic -1/0/+1 depending on relative order.
 */
int
gmsg_cmp(const void *h1, const void *h2)
{
	return gmsg_cmp_internal(h1, h2, TRUE);
}

/**
 * Perform a priority comparison between two messages, h1 being a whole PDU
 * and h2 being only a Gnutella header, not a whole PDU.
 *
 * Caller must ensure that h1 points to the whole PDU, i.e. that the Gnutella
 * message data immediately follows the Gnutella header in memory.
 *
 * @return algebraic -1/0/+1 depending on relative order.
 */
int
gmsg_headcmp(const void *h1, const void *h2)
{
	return gmsg_cmp_internal(h1, h2, FALSE);
}

/**
 * Vector templates for message queue pruning.
 *
 * These only contain Gnutella headers with minimum fields set to ensure
 * we can use gmsg_headcmp() on them.
 */
static struct gmsg_template {
	iovec_t *vec;
	size_t cnt;
	once_flag_t done;
} gmsg_templates[2];

#define GMSG_TEMPLATE_QUERY		0
#define GMSG_TEMPLATE_QHIT		1

static void
gmsg_mq_queries(void)
{
	struct gmsg_template *t = &gmsg_templates[GMSG_TEMPLATE_QUERY];
	gnutella_header_t *header;

	/*
	 * First time the queue is in "swift" mode.
	 *
	 * Purge pending queries, since they are getting quite old.
	 * Leave our queries in for now (they have hops=0).
	 */

	OMALLOC(t->vec);
	t->cnt = 1;

	OMALLOC0(header);
	gnutella_header_set_function(header, GTA_MSG_SEARCH);
	gnutella_header_set_hops(header, 1);
	gnutella_header_set_ttl(header, GNET_PROPERTY(max_ttl));

	iovec_set(t->vec, header, sizeof *header);

	/*
	 * Whether or not this header template will let the queue make enough
	 * room is not important, for the initial checkpoint.  Indeed, since
	 * the queue is now in "swift" mode , more query messages will be dropped
	 * at the next iteration, since we'll start dropping query hits by then,
	 * and hits are more prioritary than queries.
	 */

	if (GNET_PROPERTY(gmsg_debug)) {
		g_debug("%s(): generated %zu entr%s",
			G_STRFUNC, t->cnt, plural_y(t->cnt));
	}
}

static void
gmsg_mq_qhits(void)
{
	struct gmsg_template *t = &gmsg_templates[GMSG_TEMPLATE_QHIT];
	uint8 max_ttl = GNET_PROPERTY(hard_ttl_limit);
	int ttl;

	/*
	 * We're going to drop query hits...
	 *
	 * We start with the lowest prioritary query hit: low hops count
	 * and high TTL, and we progressively increase until we can drop
	 * the amount we need to drop.
	 *
	 * Note that we will never be able to drop the partially written
	 * message at the tail of the queue, even if it is less prioritary
	 * than our comparison point.
	 */

	OMALLOC_ARRAY(t->vec, max_ttl + 1);
	t->cnt = max_ttl + 1;

	for (ttl = max_ttl; ttl >= 0; ttl--) {
		gnutella_header_t header;

		ZERO(&header);
		gnutella_header_set_function(&header, GTA_MSG_SEARCH_RESULTS);
		gnutella_header_set_hops(&header, max_ttl - ttl);
		gnutella_header_set_ttl(&header, ttl);

		iovec_set(&t->vec[max_ttl - ttl], OCOPY(&header), sizeof header);
	}

	/*
	 * Make sure gmsg_headcmp() agrees with our assumption here that the
	 * deeper we go into the array, the more prioritary the message.
	 */

	for (ttl = 0; ttl < max_ttl; ttl++) {
		const void *prev = iovec_base(&t->vec[ttl]);
		const void *next = iovec_base(&t->vec[ttl + 1]);
		g_assert_log(gmsg_headcmp(prev, next) < 0,
			"%s(): ttl=%d, prev is %s",
			G_STRFUNC, ttl, gmsg_infostr(prev));
	}

	if (GNET_PROPERTY(gmsg_debug)) {
		g_debug("%s(): generated %zu entr%s",
			G_STRFUNC, t->cnt, plural_y(t->cnt));
	}
}


/**
 * Generates vector of message templates that will be used by the message
 * queue to prioritize traffic.
 *
 * The vector contains a sorted list of Gnutella headers.  The deeper we go
 * in the vector, the more important the message is deemed to be, according
 * to gmsg_headcmp().
 *
 * These vectors are only allocated once, and then they are never freed.
 *
 * @param initial		whether queue is just entering swift mode
 * @param vcnt			where the amount of entries in the vector is written
 *
 * @return the base of the vector of messages
 */
iovec_t *
gmsg_mq_templates(bool initial, size_t *vcnt)
{
	struct gmsg_template *t;

	if (initial) {
		t = &gmsg_templates[GMSG_TEMPLATE_QUERY];
		ONCE_FLAG_RUN(t->done, gmsg_mq_queries);
	} else {
		t = &gmsg_templates[GMSG_TEMPLATE_QHIT];
		ONCE_FLAG_RUN(t->done, gmsg_mq_qhits);
	}

	if (vcnt != NULL)
		*vcnt = t->cnt;

	return t->vec;
}

/**
 * @param msg		start of message (Gnutella header), followed by data
 * @param msg_len	length of the buffer containing the header + body
 *
 * @returns formatted static string:
 *
 *     msg_type (payload length) [hops=x, TTL=x]
 *
 * that can also decompile vendor messages given a pointer on the whole
 * message that contains the leading header immediately followed by the
 * payload of that message.
 */
char *
gmsg_infostr_full(const void *msg, size_t msg_len)
{
	const char *data = const_ptr_add_offset(msg, GTA_HEADER_SIZE);
	size_t data_len = msg_len - GTA_HEADER_SIZE;

	if (msg_len < GTA_HEADER_SIZE)
		return "undecipherable (smaller than Gnutella header)";

	return gmsg_infostr_full_split(msg, data, data_len);
}

/**
 * Same a gmsg_infostr_to_buf() only we have the header and the payload.
 * If the data follows the header, then we can also decompile DHT messages.
 */
static size_t
gmsg_infostr_split_to_buf(
	const void *head, const void *data, size_t data_len,
	char *buf, size_t buf_size)
{
	uint8 function = gnutella_header_get_function(head);
	uint16 size = gmsg_size(head);

	if (
		GTA_MSG_DHT == function &&
		data_len + GTA_HEADER_SIZE >= KDA_HEADER_SIZE &&
		data == gnutella_data(head) && data_len == size
	) {
		/* Data is consecutive to header and length matches with header */
		return kmsg_infostr_to_buf(head, buf, buf_size);
	}

	return str_bprintf(buf, buf_size, "%s (%u byte%s) #%s %s[hops=%d, TTL=%d]",
		gmsg_name(function),
		size, plural(size),
		guid_hex_str(gnutella_header_get_muid(head)),
		gnutella_header_get_ttl(head) & GTA_UDP_DEFLATED ? "deflated " : "",
		gnutella_header_get_hops(head),
		gnutella_header_get_ttl(head) & ~GTA_UDP_DEFLATED);
}

/**
 * Same a gmsg_infostr() but fills the supplied buffer with the formatted
 * string and returns the amount of bytes written.
 */
static size_t
gmsg_infostr_to_buf(const void *msg, char *buf, size_t buf_size)
{
	uint8 function = gnutella_header_get_function(msg);
	uint16 size = gmsg_size(msg);

	/*
	 * We cannot assume we have more than the Gnutella header, so
	 * we can't go and probe DHT messages.
	 */

	return str_bprintf(buf, buf_size, "%s (%u byte%s) #%s %s[hops=%d, TTL=%d]",
		gmsg_name(function),
		size, plural(size),
		guid_hex_str(gnutella_header_get_muid(msg)),
		gnutella_header_get_ttl(msg) & GTA_UDP_DEFLATED ? "deflated " : "",
		gnutella_header_get_hops(msg),
		gnutella_header_get_ttl(msg) & ~GTA_UDP_DEFLATED);
}

/**
 * Same as gmsg_infostr_full_split() but fills the supplied buffer with
 * the formatted string and returns the amount of bytes written.
 */
size_t
gmsg_infostr_full_split_to_buf(const void *head, const void *data,
	size_t data_len, char *buf, size_t buf_size)
{
	size_t rw;

	g_assert(size_is_non_negative(data_len));
	g_assert(size_is_non_negative(buf_size));

	switch (gnutella_header_get_function(head)) {
	case GTA_MSG_VENDOR:
	case GTA_MSG_STANDARD:
		{
			uint16 size = data_len & GTA_SIZE_MASK;
			uint8 ttl = gnutella_header_get_ttl(head);

			rw = str_bprintf(buf, buf_size,
				"%s %s (%u byte%s) #%s %s[hops=%d, TTL=%d]",
				gmsg_name(gnutella_header_get_function(head)),
				vmsg_infostr(data, size),
				size, plural(size),
				guid_hex_str(gnutella_header_get_muid(head)),
				ttl & GTA_UDP_DEFLATED ? "deflated " :
					ttl & GTA_UDP_CAN_INFLATE ? "can_inflate " : "",
				gnutella_header_get_hops(head),
				ttl & ~(GTA_UDP_DEFLATED | GTA_UDP_CAN_INFLATE));
		}
		break;
	default:
		rw = gmsg_infostr_split_to_buf(head, data, data_len, buf, buf_size);
	}

	return rw;
}

/**
 * Same as gmsg_infostr_full() but formats to supplied buffer ``buf''
 * which is ``buf_len'' bytes long and returns the amount of bytes written.
 */
static size_t
gmsg_infostr_full_to_buf(const void *msg, size_t msg_len,
	char *buf, size_t buf_len)
{
	const char *data = (const char *) msg + GTA_HEADER_SIZE;
	size_t data_len = msg_len - GTA_HEADER_SIZE;

	return gmsg_infostr_full_split_to_buf(msg, data, data_len, buf, buf_len);
}

/**
 * Pretty-print the message information, based on the Gnutella header and
 * possibly probing the payload if necessary (for vendor or DHT messages).
 *
 * @returns formatted static string:
 *
 *     msg_type (payload length) MUID [hops=x, TTL=x]
 *
 * that can also decompile vendor messages given a pointer on the header
 * and on the data of the message (which may not be consecutive in memory).
 */
char *
gmsg_infostr_full_split(const void *head, const void *data, size_t data_len)
{
	static char buf[180];

	gmsg_infostr_full_split_to_buf(head, data, data_len, buf, sizeof buf);
	return buf;
}

/**
 * Pretty-print the message information, based solely on the Gnutella header.
 *
 * @returns formatted static string:
 *
 *     msg_type (payload length) MUID [hops=x, TTL=x]
 */
const char *
gmsg_infostr(const void *msg)
{
	static char buf[96];
	gmsg_infostr_to_buf(msg, buf, sizeof buf);
	return buf;
}

/**
 * Pretty-print the message information, based solely on the Gnutella header
 * of the message held in a gnutella node (current message received from
 * that node and being routed or processed).
 *
 * The advantage over calling gmsg_infostr(&n->header) is that the node
 * information is also printed if by chance the hop count of the message is 1
 * or 0 (for UDP messages).  Also this routine works for G2 nodes.
 *
 * @returns formatted static string:
 *
 *     msg_type (payload length) MUID [hops=x, TTL=x]
 *
 * if message is from a remote node, or
 *
 *     msg_type (payload length) MUID [hops=x, TTL=x] //IP:port <vendor>//
 *
 * if message comes from a neighbour.
 */
const char *
gmsg_node_infostr(const gnutella_node_t *n)
{
	static char buf[180];
	uint8 hops;
	size_t w;

	if (NODE_TALKS_G2(n)) {
		w = g2_msg_infostr_to_buf(n->data, n->size, buf, sizeof buf);
		hops = 1;
	} else {
		w = gmsg_infostr_to_buf(&n->header, buf, sizeof buf);
		hops = gnutella_header_get_hops(n->header);
	}

	if (hops <= 1)
		str_bprintf(&buf[w], sizeof buf - w, " //%s//", node_infostr(n));

	return buf;
}

/**
 * Log dropped message (given with separated header and data) with reason.
 */
void
gmsg_log_split_dropped(
	const void *head, const void *data, size_t data_len,
	const char *reason, ...)
{
	char rbuf[256];
	char buf[128];

	gmsg_infostr_full_split_to_buf(head, data, data_len, buf, sizeof buf);

	if (reason) {
		va_list args;
		va_start(args, reason);
		rbuf[0] = ':';
		rbuf[1] = ' ';
		str_vbprintf(&rbuf[2], sizeof rbuf - 2, reason, args);
		va_end(args);
	} else {
		rbuf[0] = '\0';
	}

	g_debug("DROP %s%s", buf, rbuf);
}

/**
 * Log dropped message with reason.
 */
void
gmsg_log_dropped(const gnutella_node_t *n, const char *reason, ...)
{
	char rbuf[256];
	char buf[128];

	if (NODE_TALKS_G2(n)) {
		g2_msg_infostr_to_buf(n->data, n->size, buf, sizeof buf);
	} else {
		gmsg_infostr_full_split_to_buf(&n->header, n->data, n->size,
			buf, sizeof buf);
	}

	if (reason) {
		va_list args;
		va_start(args, reason);
		rbuf[0] = ':';
		rbuf[1] = ' ';
		str_vbprintf(&rbuf[2], sizeof rbuf - 2, reason, args);
		va_end(args);
	} else {
		rbuf[0] = '\0';
	}

	g_debug("DROP %s%s", buf, rbuf);
}

/**
 * Log duplicate message with reason.
 */
void
gmsg_log_duplicate(const gnutella_node_t *n, const char *reason, ...)
{
	char rbuf[256];
	char buf[160];

	if (NODE_TALKS_G2(n)) {
		g2_msg_infostr_to_buf(n->data, n->size, buf, sizeof buf);
	} else {
		gmsg_infostr_full_split_to_buf(&n->header, n->data, n->size,
			buf, sizeof buf);
	}

	if (reason) {
		va_list args;
		va_start(args, reason);
		rbuf[0] = ':';
		rbuf[1] = ' ';
		str_vbprintf(&rbuf[2], sizeof rbuf - 2, reason, args);
		va_end(args);
	} else {
		rbuf[0] = '\0';
	}

	g_debug("DUP %s%s", buf, rbuf);
}

/**
 * Log dropped message (held in message block) with supplied reason.
 */
void
gmsg_log_dropped_pmsg(const pmsg_t *mb, const char *reason, ...)
{
	char rbuf[256];
	char buf[128];

	gmsg_infostr_full_to_buf(pmsg_start(mb), pmsg_written_size(mb),
		buf, sizeof buf);

	if (reason) {
		va_list args;
		va_start(args, reason);
		rbuf[0] = ':';
		rbuf[1] = ' ';
		str_vbprintf(&rbuf[2], sizeof rbuf - 2, reason, args);
		va_end(args);
	} else {
		rbuf[0] = '\0';
	}

	g_debug("DROP %s%s", buf, rbuf);
}

/**
 * Log bad message, the node's vendor, and reason.
 */
void
gmsg_log_bad(const gnutella_node_t *n, const char *reason, ...)
{
	char rbuf[256];
	char buf[128];

	if (NODE_TALKS_G2(n)) {
		g2_msg_infostr_to_buf(n->data, n->size, buf, sizeof buf);
	} else {
		gmsg_infostr_full_split_to_buf(
			&n->header, n->data, n->size, buf, sizeof buf);
	}

	if (reason) {
		va_list args;
		va_start(args, reason);
		rbuf[0] = ':';
		rbuf[1] = ' ';
		str_vbprintf(&rbuf[2], sizeof rbuf - 2, reason, args);
		va_end(args);
	} else {
		rbuf[0] = '\0';
	}

	g_debug("BAD %s %s%s", node_infostr(n), buf, rbuf);
}

/**
 * Check whether query message split between header and data is flagged
 * for OOB hit delivery.
 */
bool
gmsg_split_is_oob_query(const void *head, const void *data)
{
	const uint16 mask = QUERY_F_MARK | QUERY_F_OOB_REPLY;
	uint16 flags;

	g_assert(GTA_MSG_SEARCH == gnutella_header_get_function(head));

	flags = peek_be16(data);
	return (flags & mask) == mask;
}

/**
 * Check whether query message starting at `msg' is flagged
 * for OOB hit delivery.
 */
bool
gmsg_is_oob_query(const void *msg)
{
	const char *data = msg;
	return gmsg_split_is_oob_query(&data[0], &data[GTA_HEADER_SIZE]);
}

/* vi: set ts=4 sw=4 cindent: */
