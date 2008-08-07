/*
 * $Id$
 *
 * Copyright (c) 2008, Raphael Manfredi
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
 * @ingroup dht
 * @file
 *
 * Kademlia Messages.
 *
 * @author Raphael Manfredi
 * @date 2008
 */

#include "common.h"

RCSID("$Id$")

#include "kmsg.h"
#include "knode.h"
#include "rpc.h"
#include "routing.h"

#include "core/hosts.h"
#include "core/hostiles.h"
#include "core/udp.h"
#include "core/nodes.h"
#include "core/guid.h"
#include "core/pmsg.h"
#include "core/sockets.h"
#include "core/settings.h"

#include "if/dht/kademlia.h"

#include "if/gnet_property_priv.h"

#include "lib/bstr.h"
#include "lib/misc.h"
#include "lib/host_addr.h"
#include "lib/glib-missing.h"
#include "lib/vendors.h"

#include "lib/override.h"		/* Must be the last header included */

typedef void (*kmsg_handler_t)(knode_t *kn, struct gnutella_node *n,
	const kademlia_header_t *header,
	guint8 extlen, const void *payload, size_t len);

/**
 * A Kademlia message descriptor.
 */
struct kmsg {
	guint8 function;
	kmsg_handler_t handler;
	const char *name;
};

static const struct kmsg kmsg_map[];
static const struct kmsg *kmsg_find(guint8 function);

/**
 * Handle incoming Kademlia message.
 *
 * @param kn		the Kademlia node from which the message originated
 * @param n			UDP gnutella node from which the message came
 * @param header	the start of the kademlia header
 * @param extlen	the length of Kademlia header extension (0 if none)
 * @param payload	the start of the message payload
 * @param len		the payload length
 */
static void
kmsg_handle(knode_t *kn,
	struct gnutella_node *n,
	const kademlia_header_t *header, guint8 extlen,
	const void *payload, size_t len)
{
	guint8 function;
	const struct kmsg *km;

	if (GNET_PROPERTY(dht_debug > 3))
		g_message("DHT got %s from %s",
			kmsg_infostr(header), knode_to_string(kn));

	function = kademlia_header_get_function(header);
	km = kmsg_find(function);

	if (!km) {
		if (GNET_PROPERTY(dht_debug))
			g_message("DHT invalid message function 0x%x from %s",
				function, knode_to_string(kn));
	} else if (NULL == km->handler) {
		if (GNET_PROPERTY(dht_debug))
			g_message("DHT unhandled %s from %s",
				km->name, knode_to_string(kn));
	} else {
		km->handler(kn, n, header, extlen, payload, len);
	}
}

/**
 * Let them know we don't handle Kademlia header extensions.
 *
 * We do that everywhere instead of factoring it out in kmsg_handle()
 * to avoid warnings about unused parameters in every handler.
 */
static void
warn_no_header_extension(const knode_t *kn,
	const kademlia_header_t *header, guint8 extlen)
{
	if (extlen && GNET_PROPERTY(dht_debug)) {
		guint8 function = kademlia_header_get_function(header);
		g_warning("DHT unhandled extended header (%u byte%s) in %s from %s",
			extlen, extlen == 1 ? "" : "s", kmsg_name(function),
			knode_to_string(kn));
		dump_hex(stderr, "Kademlia extra header",
			kademlia_header_end(header), extlen);
	}
}

/**
 * Build a proper Kademlia header for our reply, filling contact information
 * for our node.
 *
 * @param header	the Kademlia header structure to fill
 * @param op		the Kademlia message function we're building
 * @param major		major version of the message
 * @param minor		minor version of the message
 * @param muid		the MUID to use
 *
 * @attention
 * The length is not filled in the Kademlia header.
 */
static void
kmsg_build_header(kademlia_header_t *header,
	guint8 op, guint8 major, guint8 minor, const guid_t *muid)
{
	kademlia_header_set_muid(header, muid);
	kademlia_header_set_dht(header, major, minor);
	kademlia_header_set_function(header, op);
	kademlia_header_set_contact_kuid(header, get_our_kuid()->v);
	kademlia_header_set_contact_vendor(header, T_GTKG);
	kademlia_header_set_contact_version(header,
		KDA_VERSION_MAJOR, KDA_VERSION_MINOR);
	kademlia_header_set_contact_addr_port(header,
		host_addr_ipv4(listen_addr()), socket_listen_port());
	kademlia_header_set_contact_instance(header, 1);	/* XXX What's this? */
	kademlia_header_set_contact_flags(header,
		KDA_MSG_F_FIREWALLED);							/* XXX for now */
	kademlia_header_set_extended_length(header, 0);

	g_assert(kademlia_header_constants_ok(header));
}

/**
 * Build a proper Kademlia header for our reply, filling contact information
 * for our node and message size information.
 *
 * The given message block must be sized exactly to the final message size.
 *
 * @param mb		the message block (Kademlia header at the start)
 * @param op		the Kademlia message function we're building
 * @param major		major version of the message
 * @param minor		minor version of the message
 * @param muid		the MUID to use
 */
static void
kmsg_build_header_pmsg(pmsg_t *mb,
	guint8 op, guint8 major, guint8 minor, const guid_t *muid)
{
	kmsg_build_header((void *) pmsg_start(mb), op, major, minor, muid);
	kademlia_header_set_size(pmsg_start(mb),
		pmsg_phys_len(mb) - KDA_HEADER_SIZE);
}

/**
 * Serialize host address in supplied message buffer.
 */
static void
serialize_addr(pmsg_t *mb, const host_addr_t addr)
{
	g_assert(pmsg_available(mb) >= 17);

	switch (host_addr_net(addr)) {
	case NET_TYPE_IPV4:
		pmsg_write_u8(mb, 4);
		pmsg_write_be32(mb, host_addr_ipv4(addr));
		break;
	case NET_TYPE_IPV6:
		pmsg_write_u8(mb, 16);
		pmsg_write(mb, host_addr_ipv6(&addr), 16);
		break;
	case NET_TYPE_LOCAL:
	case NET_TYPE_NONE:
		g_error("unexpected address for incoming DHT message: %s",
			host_addr_to_string(addr));
	}
}

/**
 * Serialize the DHT size estimate, skipping leading zeroes.
 */
static void
serialize_size_estimate(pmsg_t *mb)
{
	int i;
	const kuid_t *estimate = dht_get_size_estimate();

	g_assert(pmsg_available(mb) >= KUID_RAW_SIZE + 1);

	for (i = 0; i < KUID_RAW_SIZE; i++) {
		guint8 v = estimate->v[i];
		if (v)
			break;		/* Found non-zero byte */
	}

	pmsg_write_u8(mb, KUID_RAW_SIZE - i);
	pmsg_write(mb, &estimate->v[i], KUID_RAW_SIZE - i);
}

/**
 * Serialize a contact to message block.
 */
static void
serialize_contact(pmsg_t *mb, const knode_t *kn)
{
	pmsg_write_be32(mb, kn->vcode.u32);
	pmsg_write_u8(mb, kn->major);
	pmsg_write_u8(mb, kn->minor);
	pmsg_write(mb, kn->id->v, KUID_RAW_SIZE);
	serialize_addr(mb, kn->addr);
	pmsg_write_be16(mb, kn->port);		/* Port is big-endian in Kademlia */
}

/**
 * Serialize vector of contact to message block.
 */
static void
serialize_contact_vector(pmsg_t *mb, knode_t **kvec, size_t klen)
{
	size_t i;

	g_assert(klen < 256);

	pmsg_write_u8(mb, klen);

	for (i = 0; i < klen; i++)
		serialize_contact(mb, kvec[i]);
}

/**
 * Send a pong message back to the host who sent the ping.
 */
static void
k_send_pong(struct gnutella_node *n, const guid_t *muid)
{
	kademlia_header_t *header;
	pmsg_t *mb;

	/*
	 * Response payload:
	 *
	 * Requester's external address: [addr len] [serialized addr] [port]
	 * Estimated DHT size: [length of size] [size]
	 *
	 * The maximum payload size is therefore: 1 + 16 + 2 + 1 + 20 = 40 bytes.
	 */

	mb = pmsg_new(PMSG_P_DATA, NULL, KDA_HEADER_SIZE + 40);

	header = (kademlia_header_t *) pmsg_start(mb);
	/* Size unknown yet */
	kmsg_build_header(header, KDA_MSG_PING_RESPONSE, 0, 0, muid);

	/* Insert requester's external address */

	pmsg_seek(mb, KDA_HEADER_SIZE);		/* Start of payload */
	serialize_addr(mb, n->addr);
	pmsg_write_be16(mb, n->port);		/* Port is big-endian in Kademlia */

	/*
	 * Insert estimated DHT size as a "BigInteger": we serialize the
	 * estimated size as a KUID by skipping leading zero bytes.
	 */

	serialize_size_estimate(mb);

	kademlia_header_set_size(header, pmsg_size(mb) - KDA_HEADER_SIZE);

	/*
	 * Send the message...
	 */

	if (GNET_PROPERTY(dht_debug > 3))
		g_message("DHT sending back %s (%lu bytes) to %s",
			kmsg_infostr(header), (unsigned long) pmsg_size(mb),
			host_addr_port_to_string(n->addr, n->port));

	udp_send_mb(n, mb);
}

/**
 * Send back response to find_node(id).
 *
 * @param n			where to send the response to
 * @param kvec		base of knode vector
 * @param klen		amount of entries filled in vector
 * @param muid		MUID to use in response
 */
static void
k_send_find_node_response(
	struct gnutella_node *n,
	knode_t **kvec, size_t klen, const guid_t *muid)
{
	pmsg_t *mb;
	kademlia_header_t *header;

	/*
	 * Response payload:
	 *
	 * Security token: [length] [token]
	 * At most k contacts: [count] [Contacts]
	 *
	 * Each contact is made of: Vendor, Version, KUID, IP:port, and asssuming
	 * an IPv6 address, the maximum size is 4 + 2 + 20 + 19 = 45 bytes.
	 *
	 * The maximum payload size is therefore: 1 + 4 + 1 + 20*45 = 906 bytes.
	 */

	mb = pmsg_new(PMSG_P_DATA, NULL, KDA_HEADER_SIZE + 906);

	header = (kademlia_header_t *) pmsg_start(mb);
	kmsg_build_header(header, KDA_MSG_FIND_NODE_RESPONSE, 0, 0, muid);

	pmsg_seek(mb, KDA_HEADER_SIZE);		/* Start of payload */

	/*
	 * Write security token, which they will have to give us back
	 * if they want to store something at our node.
	 */

	pmsg_write_u8(mb, 0);		/* XXX no security token yet */

	/*
	 * Write contact vector.
	 */

	serialize_contact_vector(mb, kvec, klen);

	kademlia_header_set_size(header, pmsg_size(mb) - KDA_HEADER_SIZE);

	/*
	 * Send the message...
	 */

	if (GNET_PROPERTY(dht_debug > 3))
		g_message("DHT sending back %s (%lu bytes) with %lu contact%s to %s",
			kmsg_infostr(header), (unsigned long) pmsg_size(mb),
			(unsigned long) klen, klen == 1 ? "" : "s",
			host_addr_port_to_string(n->addr, n->port));

	udp_send_mb(n, mb);
}

/**
 * Handle ping messages.
 */
static void
k_handle_ping(knode_t *kn, struct gnutella_node *n,
	const kademlia_header_t *header, guint8 extlen,
	const void *payload, size_t len)
{
	warn_no_header_extension(kn, header, extlen);

	if (len && GNET_PROPERTY(dht_debug)) {
		g_warning("DHT unhandled PING payload (%lu byte%s) from %s",
			(unsigned long) len, len == 1 ? "" : "s", knode_to_string(kn));
		dump_hex(stderr, "Kademlia Ping payload", payload, len);
	}

	k_send_pong(n, kademlia_header_get_muid(header));
}

/**
 * Handle pong messages.
 */
static void
k_handle_pong(knode_t *kn, struct gnutella_node *n,
	const kademlia_header_t *header, guint8 extlen,
	const void *payload, size_t len)
{
	char *reason;
	bstr_t *bs;

	warn_no_header_extension(kn, header, extlen);

	if (
		!dht_rpc_answer(kademlia_header_get_muid(header), kn, n,
			KDA_MSG_PING_RESPONSE, payload, len)
	) {
		if (GNET_PROPERTY(dht_debug))
			g_warning("DHT ignoring unexpected PONG from %s",
				knode_to_string(kn));
		return;
	}

	bs = bstr_open(payload, len, GNET_PROPERTY(dht_debug) ? BSTR_F_ERROR : 0);

	/*
	 * Decompile first field: Requester's external address
	 */

	{
		host_addr_t addr;
		guint16 port;

		bstr_read_packed_ipv4_or_ipv6_addr(bs, &addr);
		bstr_read_le16(bs, &port);

		if (bstr_has_error(bs)) {
			reason = "could not decompile IP address";
			goto error;
		}

		if (
			!GNET_PROPERTY(force_local_ip) &&
			is_host_addr(addr) && !is_my_address(addr)
		) {
			if (GNET_PROPERTY(dht_debug))
				g_message(
					"DHT node %s at %s reported new IP address for us: %s",
					knode_to_string(kn),
					host_addr_port_to_string(n->addr, n->port),
					host_addr_port_to_string2(addr, port));

			settings_addr_changed(addr, n->addr);
		}
	}

	/*
	 * Decompile second field:  Estimated DHT size.
	 *
	 * Only the needed (significant) trailing bytes are transmitted, the
	 * leading zero bytes are not present.
	 */

	{
		kuid_t estimated;
		guint8 bytes;

		bstr_read_packed_array_u8(bs, KUID_RAW_SIZE, &estimated.v[0], &bytes);

		if (bstr_has_error(bs)) {
			reason = "could not decompile estimated DHT size";
			goto error;
		}

		g_assert(bytes <= KUID_RAW_SIZE);

		memmove(&estimated.v[KUID_RAW_SIZE - bytes], estimated.v, bytes);
		memset(&estimated.v[0], 0, KUID_RAW_SIZE - bytes);

		if (GNET_PROPERTY(dht_debug))
			g_message("DHT node %s estimates DHT size to %lf hosts",
				knode_to_string(kn), kuid_to_double(&estimated));

		dht_record_size_estimate(kn, &estimated);
	}

	bstr_destroy(bs);
	return;

error:
	if (GNET_PROPERTY(dht_debug))
		g_warning("DHT unhandled PONG payload (%lu byte%s) from %s: %s: %s",
			(unsigned long) len, len == 1 ? "" : "s", knode_to_string(kn),
			reason, bstr_error(bs));

	bstr_destroy(bs);
}

/**
 * Handle find_node(id) messages.
 */
static void
k_handle_find_node(knode_t *kn, struct gnutella_node *n,
	const kademlia_header_t *header, guint8 extlen,
	const void *payload, size_t len)
{
	knode_t *kvec[KDA_K];
	int cnt;
	kuid_t *id = (kuid_t *) payload;

	warn_no_header_extension(kn, header, extlen);

	if (len != KUID_RAW_SIZE && GNET_PROPERTY(dht_debug)) {
		g_warning("DHT bad FIND_NODE payload (%lu byte%s) from %s",
			(unsigned long) len, len == 1 ? "" : "s", knode_to_string(kn));
		dump_hex(stderr, "Kademlia FIND_NODE payload", payload, len);
		return;
	}

	if (GNET_PROPERTY(dht_debug > 3))
		g_message("DHT node %s looking for %s",
			knode_to_string(kn), kuid_to_hex_string(id));


	g_assert(len == KUID_RAW_SIZE);

	cnt = dht_fill_closest(id, kvec, KDA_K, FALSE, kn->id);
	k_send_find_node_response(n, kvec, cnt, kademlia_header_get_muid(header));
}

/**
 * Handle node lookup answers (FIND_NODE_RESPONSE and FIND_VALUE_RESPONSE).
 */
static void
k_handle_lookup(knode_t *kn, struct gnutella_node *n,
	const kademlia_header_t *header, guint8 extlen,
	const void *payload, size_t len)
{
	guint8 function = kademlia_header_get_function(header);

	warn_no_header_extension(kn, header, extlen);

	if (
		!dht_rpc_answer(kademlia_header_get_muid(header), kn, n,
			function, payload, len)
	) {
		if (GNET_PROPERTY(dht_debug))
			g_warning("DHT ignoring unexpected %s from %s",
				kmsg_name(function), knode_to_string(kn));
		return;
	}

	/* Nothing to do here -- everything is handled by RPC callbacks */
}

/**
 * Send message to the Kademlia node.
 */
static void
kmsg_send_mb(knode_t *kn, pmsg_t *mb)
{
	struct gnutella_node *n = node_udp_get_addr_port(kn->addr, kn->port);

	if (GNET_PROPERTY(dht_debug) > 19) {
		int len = pmsg_size(mb);
		g_message("DHT sending %s (%d bytes) to %s",
			kmsg_infostr(pmsg_start(mb)), len, knode_to_string(kn));
		dump_hex(stderr, "UDP datagram", pmsg_start(mb), len);
	}

	kn->last_sent = tm_time();
	udp_send_mb(n, mb);
}

/**
 * Send ping message to node.
 */
void
kmsg_send_ping(knode_t *kn, const guid_t *muid)
{
	pmsg_t *mb;

	mb = pmsg_new(PMSG_P_DATA, NULL, KDA_HEADER_SIZE);
	pmsg_seek(mb, KDA_HEADER_SIZE);		/* Start of payload */
	kmsg_build_header_pmsg(mb, KDA_MSG_PING_REQUEST, 0, 0, muid);
	g_assert(0 == pmsg_available(mb));
	kmsg_send_mb(kn, mb);
}

/**
 * Send find_node(id) message to node.
 *
 * @param kn		the node to whom the message should be sent
 * @param id		the ID we wish to look for
 * @param muid		the message ID to use
 * @param mfree		(optional) message free routine to use
 * @param marg		the argument to supply to the message free routine
 */
void
kmsg_send_find_node(knode_t *kn, const kuid_t *id, const guid_t *muid,
	pmsg_free_t mfree, gpointer marg)
{
	pmsg_t *mb;

	mb = mfree ?
		pmsg_new_extend(PMSG_P_DATA, NULL,
			KDA_HEADER_SIZE + KUID_RAW_SIZE, mfree, marg) :
		pmsg_new(PMSG_P_DATA, NULL, KDA_HEADER_SIZE + KUID_RAW_SIZE);

	kmsg_build_header_pmsg(mb, KDA_MSG_FIND_NODE_REQUEST, 0, 0, muid);
	pmsg_seek(mb, KDA_HEADER_SIZE);		/* Start of payload */
	pmsg_write(mb, id->v, KUID_RAW_SIZE);
	g_assert(0 == pmsg_available(mb));
	kmsg_send_mb(kn, mb);
}

/**
 * Main entry point for DHT messages received from UDP.
 *
 * The Gnutella layer that comes before has validated that the message looked
 * like a valid Gnutella one (i.e. the Gnutella header size is consistent)
 * and has already performed hostile address checks.  Traffic accounting
 * was also done, based on the message being a Gnutella one (in terms of
 * header and payload).
 *
 * Validation of the Kademlia message and its processing is now our problem.
 *
 * @param data		the head of the message (start of header)
 * @param len		total length of the message (header + data)
 * @param addr		address from which we received the datagram
 * @param port		port from which we received the datagram
 */
void kmsg_received(
	gconstpointer data, size_t len,
	host_addr_t addr, guint16 port)
{
	const kademlia_header_t *header = deconstify_gpointer(data);
	char *reason;
	guint8 major;
	guint8 minor;
	knode_t *kn;
	host_addr_t kaddr;
	guint16 kport;
	vendor_code_t vcode;
	guint8 kmajor;
	guint8 kminor;
	const char *id;
	guint8 flags;
	guint16 extended_length;
	struct gnutella_node *n;

	/*
	 * If DHT is not enabled, drop the message now.
	 */

	if (!GNET_PROPERTY(enable_dht)) {
		reason = "DHT disabled";
		goto drop;
	}

	/*
	 * Basic checks on the Kademlia header.
	 */

	if (len < KDA_HEADER_SIZE) {
		reason = "truncated header";
		goto drop;
	}

	if (!kademlia_header_constants_ok(header)) {
		reason = "bad header constants";
		goto drop;
	}

	/*
	 * We know the Gnutella layer has already validated the packet length.
	 * Therefore this should not happen, but it's a protection against
	 * something going wrong.
	 */

	if (kademlia_header_get_size(header) + KDA_HEADER_SIZE != len) {
		reason = "header size mismatch";
		goto drop;
	}

	extended_length = kademlia_header_get_extended_length(header);

	if (extended_length + (guint) KDA_HEADER_SIZE > len) {
		reason = "invalid extended header length";
		goto drop;
	}

	/*
	 * If evolutions are architected correctly, newer versions should
	 * be backward compatible with older parsing code...
	 */

	major = kademlia_header_get_major_version(header);
	minor = kademlia_header_get_minor_version(header);

	if (
		major > KDA_VERSION_MAJOR ||
		(major == KDA_VERSION_MAJOR && minor > KDA_VERSION_MINOR)
	) {
		/* ... hence just warn when debugging */
		if (GNET_PROPERTY(dht_debug))
			g_warning("DHT Kademlia message at v%u.%u -- I am only v%u.%u",
				major, minor, KDA_VERSION_MAJOR, KDA_VERSION_MINOR);
	}

	/*
	 * Get contact information.
	 */

	vcode.u32 = kademlia_header_get_contact_vendor(header);
	kmajor = kademlia_header_get_contact_major_version(header);
	kminor = kademlia_header_get_contact_minor_version(header);
	id = kademlia_header_get_contact_kuid(header);
	kaddr = host_addr_get_ipv4(kademlia_header_get_contact_addr(header));
	kport = kademlia_header_get_contact_port(header);

	/*
	 * Check contact's address.
	 */

	if (!host_is_valid(kaddr, kport)) {
		if (GNET_PROPERTY(dht_debug))
			g_warning("DHT bad contact address %s (%s v%u.%u)",
				host_addr_port_to_string(kaddr, kport),
				vendor_code_to_string(vcode.u32), kmajor, kminor);
		reason = "bad contact address";
		goto drop;
	}

	if (hostiles_check(kaddr)) {
		if (GNET_PROPERTY(dht_debug))
			g_warning("DHT hostile contact address %s (%s v%u.%u)",
				host_addr_to_string(kaddr),
				vendor_code_to_string(vcode.u32), kmajor, kminor);
		reason = "hostile contact address";
		goto drop;
	}

	flags = kademlia_header_get_contact_flags(header);

	/*
	 * See whether we already have this node in the routing table.
	 */

	kn = dht_find_node(id);

	g_assert(kn == NULL || !(kn->flags & KDA_MSG_F_FIREWALLED));

	if (NULL == kn) {
		if (GNET_PROPERTY(dht_debug))
			g_message("DHT traffic from new %s%snode %s at %s (%s v%u.%u)",
				(flags & KDA_MSG_F_FIREWALLED) ? "firewalled " : "",
				(flags & KDA_MSG_F_SHUTDOWNING) ? "shutdowning " : "",
				kuid_to_hex_string((kuid_t *) id),
				host_addr_port_to_string(kaddr, kport),
				vendor_code_to_string(vcode.u32), kmajor, kminor);

		kn = knode_new(id, flags, kaddr, kport, vcode, kmajor, kminor);
		if (!(flags & (KDA_MSG_F_FIREWALLED | KDA_MSG_F_SHUTDOWNING)))
			dht_traffic_from(kn);
	} else {
		/*
		 * Make sure the IP has not changed for the node.
		 * Otherwise, request an address verification if none is already
		 * pending for the node.
		 */

		if (!host_addr_equal(kaddr, kn->addr) || kport != kn->port) {
			if (!(kn->flags & KNODE_F_VERIFYING)) {
				knode_t *new;

				new = knode_new(id, flags, kaddr, kport, vcode, kmajor, kminor);
				dht_verify_node(kn, new);
				kn = new;				/* Speaking to new node for now */
			}
		} else {
			/* Node bears same address as before */

			knode_refcnt_inc(kn);		/* Node existed in routing table */

			if (kn->vcode.u32 != vcode.u32)
				knode_change_vendor(kn, vcode);

			if (kn->major != kmajor || kn->minor != kminor)
				knode_change_version(kn, kmajor, kminor);

			/*
			 * Flag checking.
			 */

			if (flags & KDA_MSG_F_FIREWALLED) {
				kn->flags |= KNODE_F_FIREWALLED;
				dht_remove_node(kn);
			}

			if (flags & KDA_MSG_F_SHUTDOWNING) {
				kn->flags |= KNODE_F_SHUTDOWNING;
				dht_set_node_status(kn, KNODE_PENDING);
			} else {
				kn->flags &= ~KNODE_F_SHUTDOWNING;
			}

			if (!(flags & (KDA_MSG_F_FIREWALLED | KDA_MSG_F_SHUTDOWNING)))
				dht_record_activity(kn);
		}
	}

	/*
	 * If we got the UDP message from another address than the one we
	 * have in the contact information, it is not necessarily an error.
	 * However, we keep track of that by flagging the node.
	 *
	 * We always reply to the address we had in the UDP message, but when
	 * contacting the node, we use the address in the contact information.
	 * The gnutella_node structure keeps track of the origin of the UDP message.
	 */

	if (!host_addr_equal(addr, kaddr)) {
		if (GNET_PROPERTY(dht_debug))
			g_warning("DHT contact address is %s but message came from %s",
				host_addr_port_to_string(kaddr, kport),
				host_addr_to_string(addr));

		kn->flags |= KNODE_F_FOREIGN_IP;
	}

	n = node_udp_get_addr_port(addr, port);

	kmsg_handle(kn, n, header, extended_length,
		(char *) header + extended_length + KDA_HEADER_SIZE,
		len - KDA_HEADER_SIZE - extended_length);

	knode_free(kn);		/* Will free only if not still referenced */

	return;

drop:
	if (GNET_PROPERTY(dht_debug)) {
		g_warning("DHT got invalid Kademlia packet from UDP (%s): %s",
			host_addr_port_to_string(addr, port), reason);
		if (len)
			dump_hex(stderr, "UDP datagram", data, len);
	}
}

static const struct kmsg kmsg_map[] = {
	{ 0x00,							NULL,					"invalid"		},
	{ KDA_MSG_PING_REQUEST,			k_handle_ping,			"PING"			},
	{ KDA_MSG_PING_RESPONSE,		k_handle_pong,			"PONG"			},
	{ KDA_MSG_STORE_REQUEST,		NULL,					"STORE"			},
	{ KDA_MSG_STORE_RESPONSE,		NULL,					"STORE_ACK"		},
	{ KDA_MSG_FIND_NODE_REQUEST,	k_handle_find_node,		"FIND_NODE"		},
	{ KDA_MSG_FIND_NODE_RESPONSE,	k_handle_lookup,		"FOUND_NODE"	},
	{ KDA_MSG_FIND_VALUE_REQUEST,	NULL,					"GET_VALUE"		},
	{ KDA_MSG_FIND_VALUE_RESPONSE,	k_handle_lookup,		"VALUE"			},
	{ KDA_MSG_STATS_REQUEST,		NULL,					"STATS"			},
	{ KDA_MSG_STATS_RESPONSE,		NULL,					"STATS_ACK" 	},
};

/**
 * Find message description based on function.
 */
static const struct kmsg *
kmsg_find(guint8 function)
{
	const struct kmsg *km;

	if (function == 0 || function >= G_N_ELEMENTS(kmsg_map) - 1)
		return NULL;

	km = &kmsg_map[function];

	g_assert(km->function == function);

	return km;
}

/**
 * Convert message function number into name.
 */
const char *
kmsg_name(guint function)
{
	if (function >= G_N_ELEMENTS(kmsg_map) - 1)
		return "invalid";

	return kmsg_map[function].name;
}

static size_t
kmsg_infostr_to_buf(gconstpointer msg, char *buf, size_t buf_size)
{
	guint size = kmsg_size(msg);

	return gm_snprintf(buf, buf_size, "%s%s (%u byte%s) [%s v%u.%u @%s]",
		kmsg_name(kademlia_header_get_function(msg)),
		kademlia_header_get_extended_length(msg) ? "(+)" : "",
		size, size == 1 ? "" : "s",
		vendor_code_to_string(kademlia_header_get_contact_vendor(msg)),
		kademlia_header_get_major_version(msg),
		kademlia_header_get_minor_version(msg),
		host_addr_port_to_string(
			host_addr_get_ipv4(kademlia_header_get_contact_addr(msg)),
			kademlia_header_get_contact_port(msg)));
}

/**
 * @param msg	the pointer to the Kademlia header (no need to access payload)
 *
 * @returns formatted static string containing basic information about
 * the message:
 *
 *   msg_type(+) (payload length) [vendor version]
 *
 * A "(+)" sign indicates an extended Kademlia header.
 */
const char *
kmsg_infostr(gconstpointer msg)
{
	static char buf[80];
	kmsg_infostr_to_buf(msg, buf, sizeof buf);
	return buf;
}

/**
 * Initialize Kademlia messages.
 */
void
kmsg_init(void)
{
	size_t i;

	for (i = 0; i < G_N_ELEMENTS(kmsg_map); i++) {
		const struct kmsg *entry = &kmsg_map[i];

		g_assert(entry->function == i);
	}
}

/* vi: set ts=4 sw=4 cindent: */
