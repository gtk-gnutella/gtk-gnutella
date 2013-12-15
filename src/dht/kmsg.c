/*
 * Copyright (c) 2008-2009, Raphael Manfredi
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
 * @date 2008-2009
 */

#include "common.h"

#include "kmsg.h"
#include "knode.h"
#include "rpc.h"
#include "routing.h"
#include "token.h"
#include "keys.h"
#include "values.h"

#include "core/bsched.h"
#include "core/gnet_stats.h"
#include "core/hosts.h"
#include "core/hostiles.h"
#include "core/inet.h"
#include "core/gmsg.h"
#include "core/udp.h"
#include "core/nodes.h"
#include "core/guid.h"
#include "core/sockets.h"
#include "core/settings.h"

#include "if/dht/kademlia.h"
#include "if/dht/value.h"

#include "if/gnet_property_priv.h"

#include "lib/aging.h"
#include "lib/bigint.h"
#include "lib/bstr.h"
#include "lib/host_addr.h"
#include "lib/pmsg.h"
#include "lib/pslist.h"
#include "lib/random.h"
#include "lib/sectoken.h"
#include "lib/str.h"
#include "lib/stringify.h"
#include "lib/unsigned.h"
#include "lib/vendors.h"
#include "lib/vsort.h"
#include "lib/walloc.h"

#include "lib/override.h"		/* Must be the last header included */

#define MAX_VALUE_RESPONSE_SIZE	1024	/**< Max message size for VALUE */
#define MAX_STORE_RESPONSE_SIZE	1024	/**< Max message size for STORE acks */

/**
 * The typical length of a full FIND_NODE response: 61 bytes of header
 * plus 666 bytes of payload for a total of 727 bytes.
 */
#define KMSG_FOUND_NODE_SIZE	727

/**
 * Constant length of a PONG response: 61 bytes of header + 40 bytes payload.
 */
#define KMSG_PONG_SIZE			101

/**
 * Ping throttling.
 *
 * Firewalled LimeWire nodes seem to send very frequent pings, some nodes
 * re-pinging every 10 seconds.  Under no circumstances should a node ping
 * another one so frequently: alive checks are supposed to happen every
 * 5 minutes for nodes.  Moreover, nodes should be smart and avoid pinging
 * another if they got traffic from it recently.
 *
 * We need to allow for re-pinging though, because pongs could be dropped
 * on the way back and the other host could resend its ping after some
 * timeout.
 */
#define KMSG_PING_FREQ			30		/**< 1 ping per 30 seconds per IP */

static aging_table_t *kmsg_aging_pings;

/**
 * Lookup throttling.
 *
 * Avoid abuse from nodes (passive?) who would query us too frequently.
 */
#define KMSG_FIND_FREQ			10		/**< 1 every 10 seconds */

static aging_table_t *kmsg_aging_finds;

/**
 * The aimed length for STORE messages.
 *
 * The overhead of a STORE message is variable, because the security token is
 * of variable length, and there can be several DHT values in one single
 * STORE message.
 *
 * The maximum possible length would be 652 bytes with a 512-byte long value
 * payload, and using an IPv6 address for the creator.  However, the current
 * specifications (v0.0) require the DHT value header to use an IPv4 address,
 * so the maximum message length is 640 bytes.
 *
 * In practice, we aim for 512-byte long messages (including overhead) and
 * only include 1 single DHT value if the message would end-up being longer.
 */
#define KMSG_STORE_AIMED_SIZE	512
#define KMSG_STORE_MAX_SIZE		640

typedef void (*kmsg_handler_t)(knode_t *kn, struct gnutella_node *n,
	const kademlia_header_t *header,
	uint8 extlen, const void *payload, size_t len);

/**
 * A Kademlia message descriptor.
 */
struct kmsg {
	uint8 function;
	uint8 rpc_call;
	kmsg_handler_t handler;
	const char *name;
};

static const struct kmsg *kmsg_find(uint8 function);

/**
 * Test whether the Kademlia message can be safely dropped.
 * We're given the whole PDU, not just the payload.
 *
 * Dropping of messages only happens when the connection is flow-controlled,
 * and there's not enough room in the queue.
 */
bool
kmsg_can_drop(const void *pdu, int size)
{
	if (UNSIGNED(size) < KDA_HEADER_SIZE)
		return TRUE;

	/*
	 * We can safely discard FIND_NODE, FIND_VALUE and STORE requests
	 * because we install pmsg free routines that will let us see the
	 * message was dropped and which can react properly.
	 *
	 * We can discard PING_RESPONSE (pongs) to the extent that if we are
	 * flow-controlled, we're in bad shape anyway, so the remote pinging
	 * host will see us as "no more alive" for a while.
	 *
	 * We can discard FIND_NODE_RESPONSE, with the same risk as appearing
	 * to be "stale" for the remote party.
	 *
	 * We never discard FIND_VALUE_RESPONSE, since they carry DHT values!
	 */

	switch (kademlia_header_get_function(pdu)) {
	case KDA_MSG_FIND_NODE_REQUEST:
	case KDA_MSG_FIND_VALUE_REQUEST:
	case KDA_MSG_STORE_REQUEST:
	case KDA_MSG_PING_RESPONSE:
	case KDA_MSG_FIND_NODE_RESPONSE:
		return TRUE;
	case KDA_MSG_PING_REQUEST:
		/* Drop only if no callback attached: alive pings... */
		return dht_rpc_cancel_if_no_callback(cast_to_guid_ptr_const(pdu));
	default:
		return FALSE;
	}
}

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
	const kademlia_header_t *header, uint8 extlen,
	const void *payload, size_t len)
{
	uint8 function;
	const struct kmsg *km;

	if (GNET_PROPERTY(dht_debug > 1)) {
		g_debug("DHT got %s from %s",
			kmsg_infostr(header), knode_to_string(kn));
		if (len && (GNET_PROPERTY(dht_trace) & SOCK_TRACE_IN))
			dump_hex(stderr, "UDP payload", payload, len);
		
	}

	function = kademlia_header_get_function(header);
	km = kmsg_find(function);

	/*
	 * Users can force passive mode, even if not firewalled.
	 * Enforce that no RPC call can be made on a non-active node.
	 */

	if (km->rpc_call && !dht_is_active()) {
		if (GNET_PROPERTY(dht_debug)) {
			g_debug("DHT in passive mode, ignoring %s from %s",
				km->name, knode_to_string(kn));
		}
		gnet_dht_stats_count_dropped(n, function, MSG_DROP_UNEXPECTED);
		return;
	}

	if (!km) {
		if (GNET_PROPERTY(dht_debug))
			g_message("DHT invalid message function 0x%x from %s",
				function, knode_to_string(kn));
	} else if (NULL == km->handler) {
		if (GNET_PROPERTY(dht_debug))
			g_warning("DHT unhandled %s from %s",
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
	const kademlia_header_t *header, uint8 extlen)
{
	if (extlen && GNET_PROPERTY(dht_debug)) {
		uint8 function = kademlia_header_get_function(header);
		g_warning("DHT unhandled extended header (%u byte%s) in %s from %s",
			extlen, plural(extlen), kmsg_name(function),
			knode_to_string(kn));
		if (GNET_PROPERTY(dht_debug) > 15)
			dump_hex(stderr, "Kademlia extra header",
				kademlia_header_end(header), extlen);
	}
}

/**
 * Let them know when there is unparsed data at the end of the message.
 */
static void
warn_unparsed_trailer(const knode_t *kn, const kademlia_header_t *header,
	bstr_t *bs)
{
	size_t unparsed = bstr_unread_size(bs);

	if (unparsed && GNET_PROPERTY(dht_debug)) {
		uint8 function = kademlia_header_get_function(header);
		g_warning("DHT message %s from %s "
			"has %zu byte%s of unparsed trailing data (ignored)",
			kmsg_name(function), knode_to_string(kn),
			unparsed, plural(unparsed));
		if (GNET_PROPERTY(dht_debug) > 15)
			dump_hex(stderr, "Unparsed trailing data",
				bstr_read_base(bs), unparsed);
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
	uint8 op, uint8 major, uint8 minor, const guid_t *muid)
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
		dht_is_active() ?  0 : KDA_MSG_F_FIREWALLED);
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
	uint8 op, uint8 major, uint8 minor, const guid_t *muid)
{
	kmsg_build_header((void *) pmsg_start(mb), op, major, minor, muid);
	kademlia_header_set_size(pmsg_start(mb),
		pmsg_phys_len(mb) - KDA_HEADER_SIZE);
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
		uint8 v = estimate->v[i];
		if (v)
			break;		/* Found non-zero byte */
	}

	pmsg_write_u8(mb, KUID_RAW_SIZE - i);
	pmsg_write(mb, &estimate->v[i], KUID_RAW_SIZE - i);
}

/**
 * Serialize a contact to message block.
 */
void
kmsg_serialize_contact(pmsg_t *mb, const knode_t *kn)
{
	pmsg_write_be32(mb, kn->vcode.u32);
	pmsg_write_u8(mb, kn->major);
	pmsg_write_u8(mb, kn->minor);
	pmsg_write(mb, kn->id->v, KUID_RAW_SIZE);
	pmsg_write_ipv4_or_ipv6_addr(mb, kn->addr);
	pmsg_write_be16(mb, kn->port);		/* Port is big-endian in Kademlia */
}

/**
 * Serialize vector of contact to message block.
 */
static void
serialize_contact_vector(pmsg_t *mb, knode_t **kvec, size_t klen)
{
	size_t i;

	g_assert(klen <= MAX_INT_VAL(uint8));

	pmsg_write_u8(mb, klen);

	for (i = 0; i < klen; i++)
		kmsg_serialize_contact(mb, kvec[i]);
}

/**
 * Deserialize a contact.
 *
 * @return the deserialized node, or NULL if an error occured.
 */
knode_t *
kmsg_deserialize_contact(bstr_t *bs)
{
	kuid_t kuid;
	host_addr_t addr;
	uint16 port;
	vendor_code_t vcode;
	uint8 major, minor;

	bstr_read_be32(bs, &vcode.u32);
	bstr_read_u8(bs, &major);
	bstr_read_u8(bs, &minor);
	bstr_read(bs, kuid.v, KUID_RAW_SIZE);
	bstr_read_packed_ipv4_or_ipv6_addr(bs, &addr);
	bstr_read_be16(bs, &port);		/* Port is big-endian in Kademlia */

	if (bstr_has_error(bs))
		return NULL;

	return knode_new(&kuid, 0, addr, port, vcode, major, minor);
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
	pmsg_write_ipv4_or_ipv6_addr(mb, n->addr);
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
		g_debug("DHT sending back %s (%zu bytes) to %s",
			kmsg_infostr(header), (size_t) pmsg_size(mb),
			host_addr_port_to_string(n->addr, n->port));

	udp_dht_send_mb(n, mb);
}

/**
 * Send back response to find_node(id).
 *
 * @param n			where to send the response to
 * @param kn		the node who sent the request
 * @param kvec		base of knode vector
 * @param klen		amount of entries filled in vector
 * @param muid		MUID to use in response
 */
static void
k_send_find_node_response(
	struct gnutella_node *n,
	const knode_t *kn,
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
	 *
	 * We don't use the addr/port from the gnutella_node in case they
	 * are firewalled: the port could have changed the next time they
	 * contact us, whereas addr/port given in the contact part of the
	 * header should be stable.
	 */

	{
		sectoken_t tok;

		token_generate(&tok, kn);
		pmsg_write_u8(mb, SECTOKEN_RAW_SIZE);
		pmsg_write(mb, tok.v, SECTOKEN_RAW_SIZE);
	}

	/*
	 * Write contact vector.
	 */

	serialize_contact_vector(mb, kvec, klen);

	kademlia_header_set_size(header, pmsg_size(mb) - KDA_HEADER_SIZE);

	/*
	 * Send the message...
	 */

	if (GNET_PROPERTY(dht_debug > 3))
		g_debug("DHT sending back %s (%zu bytes) with %zu contact%s to %s",
			kmsg_infostr(header), (size_t) pmsg_size(mb),
			klen, plural(klen), host_addr_port_to_string(n->addr, n->port));

	udp_dht_send_mb(n, mb);
}

/**
 * Send back response to find_value(id).
 *
 * @param n			where to send the response to
 * @param kn		the node who sent the request
 * @param vvec		base of DHT value vector
 * @param vlen		amount of entries filled in vector
 * @param load		the EMA of the # of requests / minute for the key
 * @param cached	whether key was cached in our node (outside our k-ball)
 * @param muid		MUID to use in response
 */
static void
k_send_find_value_response(
	struct gnutella_node *n,
	const knode_t *unused_kn,
	dht_value_t **vvec, size_t vlen, float load, bool cached,
	const guid_t *muid)
{
	pmsg_t *mb;
	kademlia_header_t *header;
	pmsg_offset_t value_count;
	size_t i;
	int values = 0, secondaries = 0;	/* For logging only */

	(void) unused_kn;

	g_assert(vlen <= MAX_VALUES_PER_KEY);

	/*
	 * Response payload:
	 *
	 * Request load: 32-bit float
	 * Value count: 1 byte
	 * At most MAX_VALUES_PER_KEY values (variable size): a DHT value
	 * has 61 bytes of header + the length of the data.
	 * Secondary key count: 1 byte
	 * At most MAX_VALUES_PER_KEY secondary keys (20 bytes each).
	 *
	 * We limit the total message size to MAX_VALUE_RESPONSE_SIZE and
	 * therefore need to decide at each step whether to expand the DHT
	 * value or switch to emitting secondary keys.
	 *
	 * To emit n secondary keys, we need 20n + 1 bytes of payload.
	 *
	 * The assertion below makes sure that, with our limited message size
	 * and given the maximum amount of values per key and the maximum size
	 * of a value, we can always send at least 1 expanded value and all
	 * the remaining secondary keys in a single message.
	 */

	STATIC_ASSERT(KDA_HEADER_SIZE + 61 + DHT_VALUE_MAX_LEN + 6 +
		(MAX_VALUES_PER_KEY - 1) * KUID_RAW_SIZE < MAX_VALUE_RESPONSE_SIZE);

	/*
	 * Values are sent with an "urgent" priority to make sure they get
	 * the reply quickly, even under tight outgoing bandwidth: the message
	 * will be put ahead of the message queue and sent as soon as possible
	 * by the UDP TX scheduler.
	 */

	mb = pmsg_new(PMSG_P_URGENT, NULL, MAX_VALUE_RESPONSE_SIZE);

	header = (kademlia_header_t *) pmsg_start(mb);
	kmsg_build_header(header, KDA_MSG_FIND_VALUE_RESPONSE, 0, 0, muid);

	pmsg_seek(mb, KDA_HEADER_SIZE);		/* Start of payload */
	pmsg_write_float_be(mb, load);

	value_count = pmsg_write_offset(mb);	/* We'll come back later */
	pmsg_write_u8(mb, vlen);				/* We may need to fix that */

	/*
	 * Sort values by increasing data size, so that we may expand as many
	 * as possible and emit as few secondary keys as possible: that way, the
	 * remote host will have to send less messages to retrieve the remaining
	 * keys (we expect 1 message per secondary key, normally, as they cannot
	 * know how large the values are).
	 */

	vsort(vvec, vlen, sizeof vvec[0], dht_value_cmp);

	for (i = 0; i < vlen; i++) {
		size_t secondary_size = (vlen - i) * KUID_RAW_SIZE + 1;
		dht_value_t *v = vvec[i];
		size_t value_size = DHT_VALUE_HEADER_SIZE + dht_value_length(v);

		g_assert((size_t) pmsg_available(mb) >= secondary_size);

		if (value_size + secondary_size > (size_t) pmsg_available(mb)) {
			if (GNET_PROPERTY(dht_debug) > 3)
				g_warning(
					"DHT after sending %zu DHT values, will send %zu key%s",
					i, vlen - i, plural(vlen - i));
			break;
		}

		/* That's the specs and the 61 above depends on the following... */
		g_assert(host_addr_is_ipv4(dht_value_creator(v)->addr));

		dht_value_serialize(mb, v);
		values++;

		if (GNET_PROPERTY(dht_debug) > 4)
			g_warning("DHT packed value %d/%zu: %s", values, vlen,
				dht_value_to_string(v));
	}

	/*
	 * If we had to break off above, we need to go back and fix the
	 * amount of DHT values.
	 */

	if (i < vlen) {
		size_t remain = vlen - i;
		pmsg_offset_t cur = pmsg_write_offset(mb);
		pmsg_seek(mb, value_count);
		pmsg_write_u8(mb, i);	/* Go back and patch amount of values */
		pmsg_seek(mb, cur);		/* Critical: must go back to end */

		/*
		 * Write the remaining values as secondary keys only.
		 */

		pmsg_write_u8(mb, remain);
		for (/* empty */; i < vlen; i++) {
			dht_value_t *v = vvec[i];
			pmsg_write(mb, dht_value_creator(v)->id, KUID_RAW_SIZE);
			secondaries++;

			if (GNET_PROPERTY(dht_debug) > 4)
				g_warning("DHT packed secondary key %d/%zu for %s",
					secondaries, remain, dht_value_to_string(v));
		}
	} else {
		/*
		 * We emitted all the values in expanded form, so there are no
		 * secondary keys.  Do not forget to emit the amount of secondary
		 * keys present (0).  Starting with 0.98.4, GTKG will be lenient and
		 * will correctly handle responses missing that trailing byte but
		 * other versions were not, and other vendors may choke as well.
		 *		--RAM, 2012-10-28
		 */

		pmsg_write_u8(mb, 0);
	}

	g_assert(UNSIGNED(values + secondaries) == vlen);	/* Sanity check */

	kademlia_header_set_size(header, pmsg_size(mb) - KDA_HEADER_SIZE);

	/*
	 * Update statistics.
	 */

	gnet_stats_count_general(GNR_DHT_RETURNED_EXPANDED_VALUES, values);
	gnet_stats_count_general(GNR_DHT_RETURNED_SECONDARY_KEYS, secondaries);

	if (cached) {
		gnet_stats_count_general(
			GNR_DHT_RETURNED_EXPANDED_CACHED_VALUES, values);
		gnet_stats_count_general(
			GNR_DHT_RETURNED_CACHED_SECONDARY_KEYS, secondaries);
	}

	/*
	 * Send the message...
	 */

	if (GNET_PROPERTY(dht_debug > 3))
		g_debug("DHT sending back %s (%zu bytes) with "
			"%d value%s and %d secondary key%s to %s",
			kmsg_infostr(header), (size_t) pmsg_size(mb),
			values, plural(values), secondaries, plural(secondaries),
			host_addr_port_to_string(n->addr, n->port));

	udp_dht_send_mb(n, mb);
}

/**
 * Send back response to store requests.
 *
 * @param n				where to send the response to
 * @param kn			the node who sent the request
 * @param vec			base of DHT value vector to store
 * @param vlen			amount of values in vector
 * @param valid_token	whether security token was valid
 * @param muid			MUID to use in response
 */
static void
k_send_store_response(
	struct gnutella_node *n,
	const knode_t *kn,
	dht_value_t **vec, uint8 vlen,
	bool valid_token,
	const guid_t *muid)
{
	pmsg_t *mb;
	kademlia_header_t *header;
	uint16 *status;
	int i;

	WALLOC_ARRAY(status, vlen);

	for (i = 0; i < vlen; i++)
		status[i] = values_store(kn, vec[i], valid_token);

	/*
	 * The architected store response message v0.0 is Cretinus Maximus.
	 * Limit the total size to MAX_STORE_RESPONSE_SIZE, whatever happens.
	 *
	 * We use a "control" priority to make sure the acknowledgement is
	 * received rapidly enough, even under tight outgoing bandwidth.
	 */

	mb = pmsg_new(PMSG_P_CONTROL, NULL, MAX_STORE_RESPONSE_SIZE);

	header = (kademlia_header_t *) pmsg_start(mb);
	kmsg_build_header(header, KDA_MSG_STORE_RESPONSE, 0, 0, muid);

	pmsg_seek(mb, KDA_HEADER_SIZE);		/* Start of payload */

	/*
	 * To write a status code for a value, we need:
	 *
	 * The primary key: 20 bytes
	 * The secondary key (KUID of creator): 20 bytes
	 * The status code: 4 bytes (we provide no descriptions)
	 *
	 * That's 44 bytes.  If we have less than 44 bytes left, stop
	 * sending them the status.
	 *
	 * Wouldn't it be smarter to send back only a vector of status, in
	 * the order of the values received in the STORE request and
	 * let the other side attach each status to each value?
	 *
	 * FIXME: for now, GTKG complies with the v0.0 specs, but this
	 * will need to be fixed.	--RAM, 2008-08-11
	 */

	pmsg_write_u8(mb, vlen);	/* We'll come back to patch this if needed */

	for (i = 0; i < vlen; i++) {
		if (pmsg_available(mb) < 44)
			break;

		/* Serialize status */
		pmsg_write(mb, dht_value_key(vec[i])->v, KUID_RAW_SIZE);
		pmsg_write(mb, dht_value_creator(vec[i])->id->v, KUID_RAW_SIZE);
		pmsg_write_be16(mb, status[i]);
		pmsg_write_be16(mb, 0);		/* Aren't we verbose enough already? */
	}

	if (i < vlen) {
		pmsg_offset_t cur = pmsg_write_offset(mb);
		pmsg_seek(mb, KDA_HEADER_SIZE);
		pmsg_write_u8(mb, i);	/* Go back and patch amount of results */
		pmsg_seek(mb, cur);		/* Critical: must go back to end */

		if (GNET_PROPERTY(dht_debug))
			g_warning("DHT sending back only %d out of %u STORE statuses to %s",
				i, vlen, knode_to_string(kn));
	}

	kademlia_header_set_size(header, pmsg_size(mb) - KDA_HEADER_SIZE);

	/*
	 * Send the message...
	 */

	if (GNET_PROPERTY(dht_debug > 3))
		g_debug("DHT sending back %s (%zu bytes) with %d status%s to %s",
			kmsg_infostr(header), (size_t) pmsg_size(mb),
			i, plural_es(i), host_addr_port_to_string(n->addr, n->port));

	udp_dht_send_mb(n, mb);

	/*
	 * Cleanup.
	 */

	WFREE_ARRAY(status, vlen);
}

/**
 * Handle ping messages.
 */
static void
k_handle_ping(knode_t *kn, struct gnutella_node *n,
	const kademlia_header_t *header, uint8 extlen,
	const void *payload, size_t len)
{
	const char *msg = NULL;

	warn_no_header_extension(kn, header, extlen);

	if (len && GNET_PROPERTY(dht_debug)) {
		g_warning("DHT unhandled PING payload (%zu byte%s) from %s",
			len, plural(len), knode_to_string(kn));
		dump_hex(stderr, "Kademlia Ping payload", payload, len);
	}

	/*
	 * Throttle too frequent pings from same address.
	 */

	if (aging_lookup(kmsg_aging_pings, &kn->addr))
		goto throttle;

	/*
	 * Ignore "old" PING requests: we're trying to catch up with a UDP burst.
	 */

	if (node_udp_is_old(n))
		goto old;

	/*
	 * Firewalled nodes send us PINGs when they are listing us in their
	 * routing table.  We usually try to reply to such messages unless
	 * we're short on UDP bandwidth or we're (almost) flow-controlled.
	 */

	if (kn->flags & KNODE_F_FIREWALLED) {
		if (node_dht_would_flow_control(KMSG_PONG_SIZE)) {
			msg = "flow-control threat";
			goto drop;
		} else if (bsched_saturated(BSCHED_BWS_DHT_OUT)) {
			if (random_value(100) < 90) {
				msg = "outgoing bandwidth saturated";
				goto drop;
			}
		} else if (node_dht_above_low_watermark()) {
			if (random_value(100) < 50) {
				msg = "UDP delayed";
				goto drop;
			}
		}
	}

	/*
	 * Record we're answering a PING from this node so that we can ignore
	 * further PINGs for a while...
	 */

	aging_insert(kmsg_aging_pings,
		wcopy(&kn->addr, sizeof kn->addr), GINT_TO_POINTER(1));

	k_send_pong(n, kademlia_header_get_muid(header));
	return;

old:
	if (GNET_PROPERTY(dht_debug) > 2) {
		g_debug("DHT ignoring OLD PING from %s", knode_to_string(kn));
	}
	gnet_dht_stats_count_dropped(n, KDA_MSG_PING_REQUEST, MSG_DROP_TOO_OLD);
	return;

drop:
	if (GNET_PROPERTY(dht_debug) > 2) {
		g_debug("DHT ignoring PING from %s: %s", knode_to_string(kn), msg);
	}
	gnet_dht_stats_count_dropped(n,
		KDA_MSG_PING_REQUEST, MSG_DROP_FLOW_CONTROL);
	return;

throttle:
	if (GNET_PROPERTY(dht_debug) > 2) {
		g_debug("DHT throttling PING from %s: seen %s ago",
			knode_to_string(kn),
			compact_time(aging_age(kmsg_aging_pings, &kn->addr)));
	}
	gnet_dht_stats_count_dropped(n, KDA_MSG_PING_REQUEST, MSG_DROP_THROTTLE);
}

/**
 * Handle pong messages.
 */
static void
k_handle_pong(knode_t *kn, struct gnutella_node *n,
	const kademlia_header_t *header, uint8 extlen,
	const void *payload, size_t len)
{
	char *reason;
	bstr_t *bs;

	warn_no_header_extension(kn, header, extlen);

	if (
		!dht_rpc_answer(kademlia_header_get_muid(header), kn, n,
			KDA_MSG_PING_RESPONSE, payload, len)
	) {
		if (GNET_PROPERTY(dht_debug) || GNET_PROPERTY(dht_rpc_debug)) {
			g_warning("DHT ignoring unexpected PONG #%s from %s",
				guid_to_string(kademlia_header_get_muid(header)),
				knode_to_string(kn));
		}
		return;
	}

	bs = bstr_open(payload, len, GNET_PROPERTY(dht_debug) ? BSTR_F_ERROR : 0);

	/*
	 * Decompile first field: Requester's external address
	 */

	{
		host_addr_t addr;
		uint16 port;

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
				g_debug(
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
		char buf[KUID_RAW_SIZE];
		bigint_t estimated;
		uint8 bytes;

		bstr_read_packed_array_u8(bs, KUID_RAW_SIZE, buf, &bytes);

		if (bstr_has_error(bs)) {
			reason = "could not decompile estimated DHT size";
			goto error;
		}

		g_assert(bytes <= KUID_RAW_SIZE);

		memmove(&buf[KUID_RAW_SIZE - bytes], buf, bytes);
		memset(buf, 0, KUID_RAW_SIZE - bytes);

		bigint_use(&estimated, buf, sizeof buf);

		if (GNET_PROPERTY(dht_debug)) {
			g_debug("DHT node %s estimates DHT size to %s hosts",
				knode_to_string(kn),
				uint64_to_string(bigint_to_uint64(&estimated)));
		}

		dht_record_size_estimate(kn, &estimated);
	}

	warn_unparsed_trailer(kn, header, bs);

	bstr_free(&bs);
	return;

error:
	gnet_dht_stats_count_dropped(n,
		KDA_MSG_PING_RESPONSE, MSG_DROP_DHT_UNPARSEABLE);

	if (GNET_PROPERTY(dht_debug))
		g_warning("DHT unhandled PONG payload (%zu byte%s) from %s: %s: %s",
			len, plural(len), knode_to_string(kn),
			reason, bstr_error(bs));

	bstr_free(&bs);
}

/**
 * Perform find_node(id) and send back the answer.
 *
 * @param n			the node to whom we need to send the response
 * @param kn		querying node (required to generate the security token)
 * @param id		the node ID they want to look up
 * @param header	the Kademlia header from which we can extract the MUID
 */
static void
answer_find_node(struct gnutella_node *n,
	const knode_t *kn, const kuid_t *id, const kademlia_header_t *header)
{
	knode_t *kvec[KDA_K];
	int requested = KDA_K;
	int cnt;
	const char *msg = NULL;
	bool delayed;
	bool within_kball;
	const guid_t *muid = kademlia_header_get_muid(header);

	/*
	 * Throttle too frequent lookups from same address for keys that are
	 * not deemed to be close enough from our KUID to warrant such a large
	 * lookup load.
	 */

	if (!keys_is_nearby(id)) {
		if (aging_lookup(kmsg_aging_finds, &kn->addr))
			goto throttle;

		aging_insert(kmsg_aging_finds,
			wcopy(&kn->addr, sizeof kn->addr), GINT_TO_POINTER(1));
	}

	/*
	 * Ignore "old" requests: we are trying to catch up with a UDP burst.
	 *
	 * Note that FIND_VALUE requests that get here are for keys we do not
	 * know about: we do not ignore old requests for keys we hold!
	 */

	if (node_udp_is_old(n)) {
		uint8 function = kademlia_header_get_function(header);
		if (GNET_PROPERTY(dht_debug > 2)) {
			g_debug("DHT ignoring OLD %s from %s",
				kmsg_name(function), knode_to_string(kn));
		}
		gnet_dht_stats_count_dropped(n, function, MSG_DROP_TOO_OLD);
		return;
	}

	/*
	 * If the UDP queue is flow controlled already, there's no need to
	 * bother computing the answer and generating the message since it
	 * is likely to be dropped by the queue later on.
	 */

	if (node_dht_is_flow_controlled()) {
		msg = "is flow-controlled";
		goto flow_controlled;
	}

	/*
	 * If sending the message would cause the UDP queue to flow control,
	 * then don't bother.  We assume we'll find KDA_K hosts, which is always
	 * the case in practice as long as we've been looking up our own KUID once.
	 */

	if (node_dht_would_flow_control(KMSG_FOUND_NODE_SIZE)) {
		msg = "would flow-control";
		goto flow_controlled;
	}

	/*
	 * We're going to reply differently depending on whether the key falls
	 * within our k-ball or whether we are starting to have some noticeable
	 * delays in the outgoing UDP queue.
	 */

	delayed = node_dht_above_low_watermark();
	within_kball = keys_within_kball(id);

	if (within_kball) {
		if (
			bsched_saturated(BSCHED_BWS_DHT_OUT) &&
			kuid_eq(id, get_our_kuid())
		) {
			/*
			 * If they are looking for precisely our KUID, then most probably
			 * all they want is our security token.  Since bandwidth is
			 * saturated, just give them that.
			 */

			msg = "bandwidth limited";
			goto only_token;
		}

		/*
		 * Regardless of bandwidth considerations, we need to fully reply to
		 * requests for which we could be one of the k-closest nodes otherwise
		 * the looking node would not be able to find accurately the set of
		 * k-closest nodes surrounding the looked-up key.
		 */

		goto answer;
	}

	/*
	 * If the request comes from a firewalled node, then let's be stricter.
	 *
	 * Indeed, a firewalled node will not participate to the DHT structure
	 * fully since it cannot answer FIND_NODE and STORE requests, by definition.
	 *
	 * We are an active node (since we're replying to the RPC) and therefore
	 * are paying a greater bandwidth price for the benefit of the whole
	 * network, but this should not penalize us if there are more passive than
	 * active nodes out there.
	 *
	 * So, if the request comes from a firewalled node and we are already
	 * suffering from outgoing traffic congestion, limit the number of replies
	 * to KDA_K / 2 provided the key falls in our space, KDA_K / 4 otherwise.
	 *
	 * Furthermore, if we already have enough outgoing pending traffic in
	 * the queue, drop the request.
	 */

	if (kn->flags & KNODE_F_FIREWALLED) {
		if (delayed) {
			msg = "above low watermark with passive requestor";
			goto flow_controlled;
		}
		if (bsched_saturated(BSCHED_BWS_DHT_OUT)) {
			requested = keys_is_foreign(id) ? KDA_K / 4 : KDA_K / 2;
		}
	} else if (delayed) {
		requested = keys_is_foreign(id) ? KDA_K / 2 : 3 * KDA_K / 4;
	}

	/*
	 * OK, perform the lookup and send them the answer.
	 */

answer:

	if (GNET_PROPERTY(dht_debug > 2)) {
		g_debug("DHT processing %s %s "
			"%s%s%s: giving %d node%s",
			kmsg_name(kademlia_header_get_function(header)),
			kuid_to_hex_string(id),
			delayed ? "[UDP delayed] " : "",
			within_kball ? "[in k-ball] " :
				keys_is_foreign(id) ? "[foreign] " : "",
			(kn->flags & KNODE_F_FIREWALLED) ? "[passive]" : "[active]",
			requested, plural(requested));
	}

	cnt = dht_fill_closest(id, kvec, requested, kn->id, TRUE);
	k_send_find_node_response(n, kn, kvec, cnt, muid);
	return;

flow_controlled:
	/*
	 * If they are looking for our KUID, they probably want our security token.
	 * Answer with no nodes to limit message size.
	 *
	 * Otherwise, don't bother replying.
	 */

	if (kuid_eq(id, get_our_kuid())) {
		goto only_token;
	} else {
		if (GNET_PROPERTY(dht_debug)) {
			/* This can be a FIND_NODE or a FIND_VALUE (if we don't hold it) */
			g_debug("DHT ignoring %s %s: UDP queue %s",
				kmsg_name(kademlia_header_get_function(header)),
				kuid_to_hex_string(id), msg);
		}

		gnet_dht_stats_count_dropped(n,
			kademlia_header_get_function(header),
			MSG_DROP_FLOW_CONTROL);
	}

	return;

only_token:
	/*
	 * Only send back our security token, with no nodes.
	 */

	if (GNET_PROPERTY(dht_debug)) {
		g_debug("DHT limiting %s %s (ourselves): UDP queue %s",
			kmsg_name(kademlia_header_get_function(header)),
			kuid_to_hex_string(id), msg);
	}

	k_send_find_node_response(n, kn, kvec, 0, muid);
	return;

throttle:
	if (GNET_PROPERTY(dht_debug) > 2) {
		g_debug("DHT throttling %s from %s: seen another lookup %s ago",
			kmsg_name(kademlia_header_get_function(header)),
			knode_to_string(kn),
			compact_time(aging_age(kmsg_aging_finds, &kn->addr)));
	}
	gnet_dht_stats_count_dropped(n,
		kademlia_header_get_function(header), MSG_DROP_THROTTLE);
}

/**
 * Is lookup of ID by the given node something that can be accounted for
 * as peer replication among the k-closest nodes?
 */
static inline bool
peer_replication(const knode_t *kn, const kuid_t *id)
{
	return keys_within_kball(kn->id) && keys_within_kball(id);
}

/**
 * Handle find_node(id) messages.
 */
static void
k_handle_find_node(knode_t *kn, struct gnutella_node *n,
	const kademlia_header_t *header, uint8 extlen,
	const void *payload, size_t len)
{
	kuid_t *id = (kuid_t *) payload;

	warn_no_header_extension(kn, header, extlen);

	if (len != KUID_RAW_SIZE) {
		if (GNET_PROPERTY(dht_debug)) {
			g_warning("DHT bad FIND_NODE payload (%zu byte%s) from %s",
				len, plural(len), knode_to_string(kn));
			dump_hex(stderr, "Kademlia FIND_NODE payload", payload, len);
		}
		gnet_dht_stats_count_dropped(n,
			KDA_MSG_FIND_NODE_REQUEST, MSG_DROP_DHT_UNPARSEABLE);
		return;
	}

	if (GNET_PROPERTY(dht_debug > 3))
		g_debug("DHT node %s looking for %s",
			knode_to_string(kn), kuid_to_hex_string(id));

	/*
	 * Signal that we got an unsolicited UDP message.
	 */

	inet_udp_got_unsolicited_incoming();

	g_assert(len == KUID_RAW_SIZE);

	/*
	 * If we're getting too many STORE requests for this key, do not reply
	 * to the FIND_NODE message which could cause further STORE and further
	 * negative acknowledgements, wasting bandwidth.  Just drop the request
	 * on the floor, too bad for the remote node.
	 *
	 * We're going to appear as "stale" for the remote party, but we'll
	 * reply to its pings and to other requests for less busy keys...
	 *
	 * However, we need to make sure we do not prevent Kademlia replication
	 * of values among the k-closest nodes.
	 */

	if (!peer_replication(kn, id) && keys_is_store_loaded(id)) {
		if (GNET_PROPERTY(dht_debug > 2)) {
			g_debug("DHT key %s getting too many STORE, "
				"ignoring FIND_NODE from %s",
				kuid_to_hex_string(id), knode_to_string(kn));
		}
		gnet_dht_stats_count_dropped(n,
			KDA_MSG_FIND_NODE_REQUEST, MSG_DROP_DHT_TOO_MANY_STORE);
		return;
	}

	answer_find_node(n, kn, id, header);
}

/**
 * Handle store requests.
 */
static void
k_handle_store(knode_t *kn, struct gnutella_node *n,
	const kademlia_header_t *header, uint8 extlen,
	const void *payload, size_t len)
{
	bool valid_token = FALSE;
	bstr_t *bs;
	char *reason;
	uint8 values;
	int i = 0;
	char msg[80];
	dht_value_t **vec = NULL;

	warn_no_header_extension(kn, header, extlen);

	bs = bstr_open(payload, len, GNET_PROPERTY(dht_debug) ? BSTR_F_ERROR : 0);
	
	/*
	 * Decompile first field: security token.
	 */

	{
		sectoken_t security;
		uint8 token_len;

		if (!bstr_read_u8(bs, &token_len)) {
			reason = "could not read security token length";
			goto error;
		}

		if (sizeof(security.v) == UNSIGNED(token_len))
			bstr_read(bs, security.v, sizeof(security.v));
		else
			bstr_skip(bs, token_len);

		if (bstr_has_error(bs)) {
			reason = "could not parse security token";
			goto error;
		}

		if (
			sizeof(security.v) == UNSIGNED(token_len) &&
			token_is_valid(&security, kn)
		)
			valid_token = TRUE;
	}

	if (GNET_PROPERTY(dht_debug))
		g_debug("DHT STORE %s security token from %s",
			valid_token ? "valid" : "invalid", knode_to_string(kn));

	if (!bstr_read_u8(bs, &values)) {
		reason = "could not read amount of values";
		goto error;
	}

	if (0 == values) {
		reason = "zero values";
		goto error;
	}

	/*
	 * If the security token is invalid but the the node's ID falls
	 * within our k-ball, it is one of our k-closest and we must be nicer
	 * than just ignoring it: we will decompile 1 DHT value, then send
	 * back an error stating the security token was invalid.
	 */

	if (!valid_token) {
		bool in_kball = keys_within_kball(kn->id);
		int ignored = in_kball ? values - 1 : values;

		if (ignored && GNET_PROPERTY(dht_debug))
			g_warning("DHT STORE ignoring the %u %svalue%s supplied by %s %s",
				ignored, in_kball ? "additional" : "", plural(ignored),
				in_kball ? "k-closest" : "foreigner", knode_to_string(kn));

		if (in_kball) {
			values = 1;
		} else {
			reason = "invalid security token";
			gnet_dht_stats_count_dropped(n,
				KDA_MSG_STORE_REQUEST, MSG_DROP_DHT_INVALID_TOKEN);
			goto invalid_token;
		}
	}

	/*
	 * Decompile remaining fields: values to store.
	 */

	WALLOC_ARRAY(vec, values);

	for (i = 0; i < values; i++) {
		dht_value_t *v = dht_value_deserialize(bs);

		if (NULL == v) {
			str_bprintf(msg, sizeof msg,
				"could not read value #%d/%u", i, values);
			reason = msg;
			goto error;
		}

		/*
		 * Special handling of dumb LimeWire firewalled nodes who cannot seem
		 * to be able to figure out their outgoing address and which use
		 * a private one: if we already patched the sender of the message,
		 * look whether the creator of the value is also the sender, and
		 * patch its addr:port as well.
		 *
		 * We do this at the lowest possible level so that upper layers do not
		 * need to bother.
		 */

		if (
			(kn->flags & KNODE_F_PCONTACT) &&
			kuid_eq(kn->id, dht_value_creator(v)->id)
		) {
			const knode_t *cn = dht_value_creator(v);

			if (GNET_PROPERTY(dht_storage_debug))
				g_warning(
					"DHT patching creator's IP %s:%u to match sender's %s",
					host_addr_to_string(cn->addr), cn->port,
					host_addr_port_to_string(kn->addr, kn->port));

			dht_value_patch_creator(v, kn->addr, kn->port);
		}

		vec[i] = v;
	}

	/*
	 * If token is invalid, we have adjusted the amount of values above
	 * (the node is within our k-ball or we would have aborted already).
	 * Hence avoid spurious warnings.
	 */

	if (valid_token)
		warn_unparsed_trailer(kn, header, bs);

	/*
	 * Now that we know the message is correctly formed, handle the
	 * store request.
	 */

	g_assert(i == values);

	k_send_store_response(n, kn, vec, values, valid_token,
		kademlia_header_get_muid(header));

	goto cleanup;

error:
	gnet_dht_stats_count_dropped(n,
		KDA_MSG_STORE_REQUEST, MSG_DROP_DHT_UNPARSEABLE);

	/* FALL THROUGH */

invalid_token:
	if (GNET_PROPERTY(dht_debug))
		g_warning("DHT unhandled STORE payload (%zu byte%s) from %s: %s: %s",
			len, plural(len), knode_to_string(kn),
			reason, bstr_error(bs));

	/* FALL THROUGH */

cleanup:
	if (vec) {
		int j;

		for (j = 0; j < i; j++)
			dht_value_free(vec[j], TRUE);

		WFREE_ARRAY(vec, values);
	}

	bstr_free(&bs);
}

/**
 * Handle find_value(id) requests.
 */
static void
k_handle_find_value(knode_t *kn, struct gnutella_node *n,
	const kademlia_header_t *header, uint8 extlen,
	const void *payload, size_t len)
{
	kuid_t *id = (kuid_t *) payload;
	bstr_t *bs;
	uint8 count;
	kuid_t **secondary = NULL;
	const char *reason;
	char msg[80];
	dht_value_type_t type;
	dht_value_t *vvec[MAX_VALUES_PER_KEY];
	int vcnt = 0;
	float load;
	bool cached;

	warn_no_header_extension(kn, header, extlen);

	/*
	 * Must have at least the KUID to locate, and 4 bytes at the end
	 * to hold the DHT value type.
	 */

	if (len < KUID_RAW_SIZE + 4) {
		if (GNET_PROPERTY(dht_debug)) {
			g_warning("DHT bad FIND_VALUE payload (%zu byte%s) from %s",
				len, plural(len), knode_to_string(kn));
			dump_hex(stderr, "Kademlia FIND_VALUE payload", payload, len);
		}
		gnet_dht_stats_count_dropped(n,
			KDA_MSG_FIND_VALUE_REQUEST, MSG_DROP_DHT_UNPARSEABLE);
		return;
	}

	/*
	 * Peek at the DHT value type early for logging.
	 */

	{
		const char *p = payload;
		type = peek_be32(&p[len - 4]);
	}

	if (GNET_PROPERTY(dht_debug > 3))
		g_debug("DHT FETCH node %s looking for %s value %s (%s)",
			knode_to_string(kn),
			dht_value_type_to_string(type),
			kuid_to_hex_string(id), kuid_to_string(id));

	/*
	 * If we don't hold the key, reply as we would for a FIND_NODE.
	 */

	if (!keys_exists(id)) {
		if (GNET_PROPERTY(dht_debug) || GNET_PROPERTY(dht_storage_debug))
			g_debug("DHT FETCH \"%s\" %s not found (%s)",
				dht_value_type_to_string(type),
				kuid_to_hex_string(id), kuid_to_string(id));

		answer_find_node(n, kn, id, header);
		return;
	}

	/*
	 * We hold the key, so we need to parse the payload in more
	 * details to know what exactly they are looking for.
	 */

	bs = bstr_open(payload, len, GNET_PROPERTY(dht_debug) ? BSTR_F_ERROR : 0);

	bstr_skip(bs, KUID_RAW_SIZE);	/* We know the KUID is there */

	if (!bstr_read_u8(bs, &count)) {
		reason = "could not read amount of secondary keys";
		goto error;
	}

	/*
	 * If there are secondary keys, grab them.
	 */

	if (count) {
		int i;

		WALLOC0_ARRAY(secondary, count);

		for (i = 0; i < count; i++) {
			kuid_t sec_id;

			if (!bstr_read(bs, sec_id.v, KUID_RAW_SIZE)) {
				str_bprintf(msg, sizeof msg,
					"could not read secondary key #%d/%u", i, count);
				reason = msg;
				goto error;
			}

			secondary[i] = kuid_get_atom(&sec_id);
		}
	}

	/*
	 * Final item: DHT value type, we already read it initially by peeking,
	 * we read it again to make sure the stream contains at least 4 bytes,
	 * and no more than 4 bytes...
	 */

	if (!bstr_read_be32(bs, &type)) {
		reason = "could not read DHT value type";
		goto error;
	}

	if (bstr_unread_size(bs)) {
		reason = "expected end of payload after DHT value type";
		goto error;
	}

	/*
	 * Perform the value lookup.
	 */

	vcnt = keys_get(id, type, secondary, count,
		vvec, G_N_ELEMENTS(vvec), &load, &cached);

	/*
	 * If we have no items of the requested value type, we need to act
	 * as if we were not holding the key.
	 *
	 * The reason is that due to value caching, we may have stored some
	 * cached results for a key, but only for a particular type.  There may
	 * be actual results for the type they are looking up now further down
	 * in the path, at some node closest to the key than we are.
	 *
	 * Furthermore, we need to carefully distinguish between an initial
	 * lookup, asking for a value, and secondary key fetches.  The initial
	 * lookup cannot know the secondary keys, so it cannot specify any.
	 * If a secondary key lookup was issued, and we have no value to
	 * return, we'll reply with an empty message.
	 */

	if (0 == vcnt && NULL == secondary) {
		if (GNET_PROPERTY(dht_debug) || GNET_PROPERTY(dht_storage_debug))
			g_debug("DHT FETCH \"%s\" %s not found in existing key (%s)",
				dht_value_type_to_string(type),
				kuid_to_hex_string(id), kuid_to_string(id));

		answer_find_node(n, kn, id, header);
		goto cleanup;
	}

	/*
	 * Send back the values we found (could be none for secondary keys).
	 */

	if (GNET_PROPERTY(dht_debug) || GNET_PROPERTY(dht_storage_debug))
		g_debug("DHT FETCH \"%s\" %s (%s) FOUND %d %svalue%s",
			dht_value_type_to_string(type),
			kuid_to_hex_string(id), kuid_to_string(id),
			vcnt, cached ? "cached " : "", plural(vcnt));

	k_send_find_value_response(n,
		kn, vvec, vcnt, load, cached, kademlia_header_get_muid(header));

	goto cleanup;

error:
	gnet_dht_stats_count_dropped(n,
		KDA_MSG_FIND_VALUE_REQUEST, MSG_DROP_DHT_UNPARSEABLE);

	if (GNET_PROPERTY(dht_debug))
		g_warning(
			"DHT unhandled FIND_VALUE payload (%zu byte%s) from %s: %s: %s",
			len, plural(len), knode_to_string(kn),
			reason, bstr_error(bs));

	/* FALL THROUGH */

cleanup:

	if (secondary) {
		int i;
		for (i = 0; i < count; i++) {
			if (!secondary[i])
				break;
			kuid_atom_free_null(&secondary[i]);
		}
		WFREE_ARRAY(secondary, count);
	}

	if (vcnt) {
		int i;
		for (i = 0; i < vcnt; i++)
			dht_value_free(vvec[i], TRUE);
	}

	bstr_free(&bs);
}

/**
 * Handle node RPC answers (FIND_NODE_RESPONSE, FIND_VALUE_RESPONSE and
 * STORE_RESPONSE).
 *
 * If the message is for a recognized RPC (based on the message's MUID), then
 * it will be handled by the RPC callbacks.  Otherwise, the message is ignored.
 */
static void
k_handle_rpc_reply(knode_t *kn, struct gnutella_node *n,
	const kademlia_header_t *header, uint8 extlen,
	const void *payload, size_t len)
{
	uint8 function = kademlia_header_get_function(header);

	warn_no_header_extension(kn, header, extlen);

	if (
		!dht_rpc_answer(kademlia_header_get_muid(header), kn, n,
			function, payload, len)
	) {
		if (GNET_PROPERTY(dht_debug) || GNET_PROPERTY(dht_rpc_debug)) {
			g_warning("DHT ignoring unexpected %s #%s from %s",
				kmsg_name(function),
				guid_to_string(kademlia_header_get_muid(header)),
				knode_to_string(kn));
		}
		return;
	}

	/* Nothing to do here -- everything is handled by RPC callbacks */
}

/**
 * Send message to the Kademlia node.
 */
void
kmsg_send_mb(knode_t *kn, pmsg_t *mb)
{
	struct gnutella_node *n = node_dht_get_addr_port(kn->addr, kn->port);

	knode_check(kn);

	if (NULL == n) {
		/* E.g. we're given an IPv6 node address but IPv6 support is off */
		if (GNET_PROPERTY(dht_debug)) {
			int len = pmsg_size(mb);
			g_debug("DHT discarding %s (%d bytes) to %s",
				kmsg_infostr(pmsg_start(mb)), len, knode_to_string(kn));
		}
		pmsg_free(mb);
		return;
	}

	if (GNET_PROPERTY(dht_debug) > 3) {
		int len = pmsg_size(mb);
		g_debug("DHT sending %s (%d bytes) to %s, RTT=%u",
			kmsg_infostr(pmsg_start(mb)), len, knode_to_string(kn), kn->rtt);
		if (GNET_PROPERTY(dht_trace) & SOCK_TRACE_OUT)
			dump_hex(stderr, "UDP datagram", pmsg_start(mb), len);
	}

	kn->last_sent = tm_time();
	udp_dht_send_mb(n, mb);
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
	pmsg_free_t mfree, void *marg)
{
	pmsg_t *mb;
	int msize = KDA_HEADER_SIZE + KUID_RAW_SIZE;

	mb = mfree ?
		pmsg_new_extend(PMSG_P_DATA, NULL, msize, mfree, marg) :
		pmsg_new(PMSG_P_DATA, NULL, msize);

	kmsg_build_header_pmsg(mb, KDA_MSG_FIND_NODE_REQUEST, 0, 0, muid);
	pmsg_seek(mb, KDA_HEADER_SIZE);		/* Start of payload */
	pmsg_write(mb, id->v, KUID_RAW_SIZE);
	g_assert(0 == pmsg_available(mb));
	kmsg_send_mb(kn, mb);
}

/**
 * Send find_value(id,type) message to node.
 *
 * @param kn		the node to whom the message should be sent
 * @param id		the ID we wish to look for
 * @param type		the value type we're looking for
 * @param skeys		(optional) array of secondary keys to request
 * @param scnt		amount of secondary keys suplied in `skeys'
 * @param muid		the message ID to use
 * @param mfree		(optional) message free routine to use
 * @param marg		the argument to supply to the message free routine
 */
void
kmsg_send_find_value(knode_t *kn, const kuid_t *id, dht_value_type_t type,
	kuid_t **skeys, int scnt,
	const guid_t *muid, pmsg_free_t mfree, void *marg)
{
	pmsg_t *mb;
	int msize;
	int i;

	g_assert(skeys == NULL || scnt > 0);
	g_assert(scnt >= 0 && scnt <= MAX_INT_VAL(uint8));

	/* Header + target KUID + count + array-of-sec-keys + type */
	msize = KDA_HEADER_SIZE + KUID_RAW_SIZE + 1 +
		scnt * KUID_RAW_SIZE + 4;

	mb = mfree ?
		pmsg_new_extend(PMSG_P_DATA, NULL, msize, mfree, marg) :
		pmsg_new(PMSG_P_DATA, NULL, msize);

	kmsg_build_header_pmsg(mb, KDA_MSG_FIND_VALUE_REQUEST, 0, 0, muid);
	pmsg_seek(mb, KDA_HEADER_SIZE);		/* Start of payload */
	pmsg_write(mb, id->v, KUID_RAW_SIZE);
	pmsg_write_u8(mb, scnt);

	for (i = 0; i < scnt; i++)
		pmsg_write(mb, skeys[i]->v, KUID_RAW_SIZE);

	pmsg_write_be32(mb, type);
	g_assert(0 == pmsg_available(mb));
	kmsg_send_mb(kn, mb);
}

/**
 * Patch the STORE message value count byte if we have finally put more than
 * one values in the message and adjust the Kademlia header size to match
 * that of the built buffer, since the message block can be larger than
 * the message actually serialized to it.
 */
static void
store_finalize_pmsg(pmsg_t *mb, int values_held, pmsg_offset_t value_count)
{
	uint8 function = kademlia_header_get_function(pmsg_start(mb));

	g_assert(KDA_MSG_STORE_REQUEST == function);

	/* Patch value count if more than 1 value is held in message */
	if (values_held > 1) {
		pmsg_offset_t cur = pmsg_write_offset(mb);
		pmsg_seek(mb, value_count);
		pmsg_write_u8(mb, values_held);
		pmsg_seek(mb, cur);		/* Critical: must go back to end */
	}

	/* Adjust Kademlia header size -- message block can be larger */
	kademlia_header_set_size(pmsg_start(mb),
		pmsg_written_size(mb) - KDA_HEADER_SIZE);
}

/**
 * Build store(values) messages.
 *
 * There are ``vcnt'' values to store, and we need at most 1 message per
 * value.  We try to stuff as many values per message as we can, aiming
 * to produce messages that are around KMSG_STORE_AIMED_SIZE bytes, including
 * Kademlia header overhead + DHT value header overhead.
 *
 * @param token		security token
 * @param toklen	length of security token, in bytes (can be 0)
 * @param vvec		vector of values to store
 * @param vcnt		amount of values in ``vvec''
 *
 * @return a pslist_t of message blocks (pmsg_t *), with blank MUIDs, meant
 * to be overwritten by the RPC layer.
 * It is up to the caller to free up the list and the blocks.
 */
pslist_t *
kmsg_build_store(const void *token, size_t toklen, dht_value_t **vvec, int vcnt)
{
	int i;
	pslist_t *result = NULL;
	pmsg_t *mb = NULL;
	int vheld = 0;
	pmsg_offset_t value_count = 0;

	g_assert(vvec);
	g_assert(size_is_non_negative(toklen));
	g_assert(token == NULL || size_is_positive(toklen));
	g_assert(vcnt > 0 && vcnt <= MAX_INT_VAL(uint8));

	/*
	 * Sort values by increasing size, so that we can stuff as many smaller
	 * values as possible in the first messages.
	 */

	vsort(vvec, vcnt, sizeof vvec[0], dht_value_cmp);

	for (i = 0; i < vcnt; i++) {
		dht_value_t *v = vvec[i];
		size_t value_size = DHT_VALUE_HEADER_SIZE + dht_value_length(v);

		/*
		 * If value does not fit in message, flush the current one.
		 */

		if (mb && UNSIGNED(pmsg_available(mb)) < value_size) {
			g_assert(vheld > 0 && vheld <= MAX_INT_VAL(uint8));

			store_finalize_pmsg(mb, vheld, value_count);

			result = pslist_prepend(result, mb);
			mb = NULL;
			vheld = 0;
		}

		/*
		 * If no current message, allocate one suitable for holding the
		 * current value.
		 */

		if (NULL == mb) {
			int msize;
			kademlia_header_t *header;

			/* Header + token length + security token + count + value(s) */
			msize = KDA_HEADER_SIZE + 1 + toklen + 1 + value_size;
			if (vcnt - i > 1)		/* Can hope to pack more than 1 value */
				msize = MAX(msize, KMSG_STORE_AIMED_SIZE);

			mb = pmsg_new(PMSG_P_DATA, NULL, msize);

			/*
			 * Build message header.
			 *
			 * When we stuff more than one value in the message, we cannot
			 * know what the final size is going to be a priori, so it will
			 * get patched at the end in store_finalize_pmsg().
			 */

			header = (kademlia_header_t *) pmsg_start(mb);
			kmsg_build_header(header, KDA_MSG_STORE_REQUEST, 0, 0, &blank_guid);
			pmsg_seek(mb, KDA_HEADER_SIZE);		/* Start of payload */
			pmsg_write_u8(mb, toklen);
			pmsg_write(mb, token, toklen);

			/* Assume 1 value will be held -- field patched if needed */
			value_count = pmsg_write_offset(mb);
			pmsg_write_u8(mb, 1);
		}

		/*
		 * Serialize current value at the tail of the current message.
		 */

		g_assert(UNSIGNED(pmsg_available(mb)) >= value_size);

		dht_value_serialize(mb, v);
		vheld++;
	}

	/*
	 * Flush current message.
	 */

	g_assert(mb != NULL);
	g_assert(vheld > 0 && vheld <= MAX_INT_VAL(uint8));

	store_finalize_pmsg(mb, vheld, value_count);

	return pslist_prepend(result, mb);
}

/**
 * Check whether message origin is hostile.
 *
 * If it is an RPC reply (non-NULL MUID given), force a timeout when the
 * origin if the message is now hostile (could have been dynamically set
 * as hostile after the RPC was sent).
 *
 * @param n		the source of the message
 * @param kuid	the advertised KUID of the node sending the message
 * @param muid	if non-NULL, the MUID of the RPC to cancel for hostile source
 *
 * @return TRUE if message is from an hostile source and must be ignored.
 */
static bool
kmsg_hostile_source(gnutella_node_t *n, const kuid_t *kuid, const guid_t *muid)
{
	if (node_hostile_udp(n)) {
		knode_t *kn = dht_find_node(kuid);	/* Is node in our routing table? */
		if (kn != NULL)
			dht_remove_node(kn);
		if (muid != NULL)
			dht_rpc_timeout(muid);
		return TRUE;
	}

	return FALSE;
}

/**
 * Main entry point for DHT messages received from UDP.
 *
 * The Gnutella layer that comes before has validated that the message looked
 * like a valid Gnutella one (i.e. the Gnutella header size is consistent)
 * but has NOT performed hostile address checks (because we want to timeout
 * RPCs early if we get any such messages on an RPC reply).

 * Traffic accounting was also done, based on the message being a Gnutella
 * one (in terms of header and payload).
 *
 * Validation of the Kademlia message and its processing is now our problem.
 *
 * @param data		the head of the message (start of header)
 * @param len		total length of the message (header + data)
 * @param addr		address from which we received the datagram
 * @param port		port from which we received the datagram
 * @param n			the DHT Gnutella node, for some core function calls
 */
void kmsg_received(
	const void *data, size_t len,
	host_addr_t addr, uint16 port,
	gnutella_node_t *n)
{
	const kademlia_header_t *header = deconstify_pointer(data);
	char *reason;
	uint8 major, minor;
	knode_t *kn;
	host_addr_t kaddr;
	uint16 kport;
	vendor_code_t vcode;
	uint8 kmajor, kminor;
	const kuid_t *id;
	uint8 flags;
	uint16 extended_length;
	bool weird_header = FALSE;
	bool rpc_reply = FALSE;

	g_assert(len >= GTA_HEADER_SIZE);	/* Valid Gnutella packet at least */
	g_assert(NODE_IS_DHT(n));

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

	if (extended_length + (uint) KDA_HEADER_SIZE > len) {
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
		if (GNET_PROPERTY(dht_debug) > 4)
			g_warning("DHT Kademlia message %s -- I am only v%u.%u",
				kmsg_infostr(data), KDA_VERSION_MAJOR, KDA_VERSION_MINOR);
	}

	/*
	 * Get contact information.
	 */

	vcode.u32 = kademlia_header_get_contact_vendor(header);
	kmajor = kademlia_header_get_contact_major_version(header);
	kminor = kademlia_header_get_contact_minor_version(header);
	id = (const kuid_t *) kademlia_header_get_contact_kuid(header);
	kaddr = host_addr_get_ipv4(kademlia_header_get_contact_addr(header));
	kport = kademlia_header_get_contact_port(header);
	flags = kademlia_header_get_contact_flags(header);

	/*
	 * Update statistics.
	 */

	gnet_stats_inc_general(GNR_DHT_MSG_RECEIVED);

	/* Do not check the port, it can be off for firewalled nodes */

	if (host_addr_equal(kaddr, addr))
		gnet_stats_inc_general(GNR_DHT_MSG_MATCHING_CONTACT_ADDRESS);

	/*
	 * Check contact's address on RPC replies.
	 *
	 * LimeWire nodes suffer from a bug whereby the contact is not
	 * firewalled but replies to RPC requests come back with an
	 * advertised address of 127.0.0.1.  This is annoying but hopefully
	 * fixable, at the cost of extra processing.
	 *
	 * Given the remote host is echoing back our random RPC MUID, we can
	 * be confident that the contact information was valid if we get a
	 * matching reply, since the MUID cannot be otherwise guessed.
	 */

	{
		host_addr_t raddr;
		uint16 rport;
		const guid_t *muid = kademlia_header_get_muid(header);

		if (dht_rpc_info(muid, &raddr, &rport)) {
			gnet_stats_inc_general(GNR_DHT_RPC_REPLIES_RECEIVED);

			if (kmsg_hostile_source(n, id, muid)) {
				gnet_stats_inc_general(GNR_DHT_MSG_FROM_HOSTILE_ADDRESS);
				reason = "hostile UDP source on RPC reply";
				goto drop;
			}

			rpc_reply = TRUE;

			if (kport == rport && host_addr_equal(kaddr, raddr))
				goto hostile_checked;

			if (GNET_PROPERTY(dht_debug)) {
				bool matches = port == rport && host_addr_equal(addr, raddr);
				g_warning("DHT fixing contact address for kuid=%s "
					"to %s:%u on RPC reply (%s UDP info%s%s) in %s",
					kuid_to_hex_string(id),
					host_addr_to_string(raddr), rport,
					matches ?  "matches" : "still different from",
					matches ?  "" : " ",
					matches ?  "" : host_addr_port_to_string(addr, port),
					kmsg_infostr(data));
			}

			kaddr = raddr;
			kport = rport;
			weird_header = TRUE;
			gnet_stats_inc_general(GNR_DHT_RPC_REPLIES_FIXED_CONTACT);

			goto hostile_checked;	/* Check done above */
		}
	}

	/*
	 * Check UDP origin of message for known hostile sources.
	 */

	if (kmsg_hostile_source(n, id, NULL)) {
		gnet_stats_inc_general(GNR_DHT_MSG_FROM_HOSTILE_ADDRESS);
		reason = "hostile UDP source";
		goto drop;
	}

hostile_checked:

	/*
	 * Even if they are "firewalled", drop the message if contact address
	 * is deemed hostile.  There's no reason a good firewalled host would
	 * pick this address to appear in the contact.
	 */

	if (hostiles_is_bad(kaddr)) {
		if (GNET_PROPERTY(dht_debug)) {
			hostiles_flags_t hflags = hostiles_check(kaddr);
			g_warning("DHT hostile contact address %s (%s v%u.%u): %s",
				host_addr_to_string(kaddr),
				vendor_code_to_string(vcode.u32), kmajor, kminor,
				hostiles_flags_to_string(hflags));
		}
		gnet_stats_inc_general(GNR_DHT_MSG_FROM_HOSTILE_CONTACT_ADDRESS);
		reason = "hostile contact address";
		goto drop;
	}

	/*
	 * If we got the UDP message from another address than the one we
	 * have in the contact information, it is not necessarily an error.
	 *
	 * We always reply to the address we had in the UDP message, but when
	 * contacting the node, we use the address in the contact information.
	 * The gnutella_node structure keeps track of the origin of the UDP message.
	 *
	 * If the UDP port matches the port advertised in the contact information,
	 * then it probably means the servent is unable to figure its outgoing
	 * IP address correctly.
	 */

	if (
		!(flags & KDA_MSG_F_FIREWALLED) &&
		(port != kport || !host_addr_equal(addr, kaddr))
	) {
		if (GNET_PROPERTY(dht_debug)) {
			g_warning("DHT contact address is %s "
				"but %s came from %s (%s v%u.%u) kuid=%s",
				host_addr_port_to_string(kaddr, kport),
				kmsg_name(kademlia_header_get_function(header)),
				host_addr_port_to_string2(addr, port),
				vendor_code_to_string(vcode.u32), kmajor, kminor,
				kuid_to_hex_string(id));
		}
		weird_header = TRUE;
	}

	/*
	 * If they set kport to 0, act as if they were firewalled.
	 */

	if (!(flags & KDA_MSG_F_FIREWALLED) && 0 == kport) {
		if (GNET_PROPERTY(dht_debug)) {
			g_warning("DHT contact port is zero, forcing firewalled status "
				"for %s (%s v%u.%u@%s) kuid=%s",
				host_addr_port_to_string(kaddr, kport),
				vendor_code_to_string(vcode.u32), kmajor, kminor,
				host_addr_port_to_string2(addr, port),
				kuid_to_hex_string(id));
		}
		flags |= KDA_MSG_F_FIREWALLED;
		weird_header = TRUE;
	}


	/*
	 * See whether we already have this node in the routing table.
	 */

	kn = dht_find_node(id);

	g_assert(kn == NULL || !(kn->flags & KNODE_F_FIREWALLED));

	if (NULL == kn) {
		bool patched = FALSE;

		/*
		 * We do not have this KUID in our routing table.
		 *
		 * If we are not handling an RPC reply (where we already patched
		 * the address), see whether we know this node because we did a
		 * successful RPC exchange with it recently, and make sure we have
		 * the correct contact information.
		 */

		if (!rpc_reply)
			patched = dht_fix_kuid_contact(id, &kaddr, &kport, "incoming");

		/*
		 * If the node is not already in our routing table, but its advertised
		 * contact information is wrong and it is not presenting itself as
		 * being firewalled, attempt to use the UDP address and port.
		 *
		 * Moreover, we are flagging the node with KNODE_F_PCONTACT, so
		 * any value it attempts to store will have its creator address
		 * corrected.
		 */

		if (
			!patched &&
			!(flags & KDA_MSG_F_FIREWALLED) &&
			(!host_is_valid(kaddr, kport) || !host_addr_equal(addr, kaddr))
		) {
			if (port == kport) {
				if (GNET_PROPERTY(dht_debug)) {
					g_warning("DHT fixing contact address for kuid=%s, "
						"not firewalled, replacing with UDP source %s:%u in %s",
						kuid_to_hex_string(id),
						host_addr_to_string(addr), port,
						kmsg_infostr(data));
				}
			} else {
				if (GNET_PROPERTY(dht_debug)) {
					g_warning("DHT fixing contact address for kuid=%s, "
						"not firewalled, replacing with UDP source IP %s and "
						"ignoring UDP port %u in %s",
						kuid_to_hex_string(id),
						host_addr_to_string(addr), port,
						kmsg_infostr(data));
				}
				/*
				 * kport is probably their advertised listening port, and
				 * the UDP port is different because of NAT: replying on
				 * that port would work for a while, until the NAT times out.
				 *
				 * We don't know whether kport is forwarded on the router
				 * though, but since the host did not set the "firewalled" bit
				 * we have to assume it is.
				 */
			}
			kaddr = addr;
			patched = TRUE;
			weird_header = TRUE;
		}

		if (GNET_PROPERTY(dht_debug) > 2)
			g_debug("DHT traffic from new %s%snode %s at %s (%s v%u.%u)",
				(flags & KDA_MSG_F_FIREWALLED) ? "firewalled " : "",
				(flags & KDA_MSG_F_SHUTDOWNING) ? "shutdowning " : "",
				kuid_to_hex_string(id),
				host_addr_port_to_string(kaddr, kport),
				vendor_code_to_string(vcode.u32), kmajor, kminor);

		kn = knode_new(id, flags, kaddr, kport, vcode, kmajor, kminor);

		if (patched)
			kn->flags |= KNODE_F_PCONTACT;

		if (!(flags & (KDA_MSG_F_FIREWALLED | KDA_MSG_F_SHUTDOWNING)))
			dht_traffic_from(kn);
	} else {
		/*
		 * Node is already present in our routing table.
		 *
		 * If we got an RPC reply, mark it so that we know its contact
		 * information is valid.
		 */

		if (rpc_reply)
			kn->flags |= KNODE_F_RPC;

		/*
		 * This here is again a workaround for LimeWire's bug: a good
		 * non-firewalled host that is known in our routing table with a
		 * proper address has to be identical to one bearing the same KUID
		 * with a non-routable address as long as the ports are identical.
		 *
		 * This needs to be done here before we attempt to initiate an
		 * address validation because the node's address would appear to have
		 * changed...
		 */

		if (!(flags & KDA_MSG_F_FIREWALLED)) {
			if (
				kport == kn->port &&
				host_is_valid(kn->addr, kn->port) &&
				(
					!host_is_valid(kaddr, kport) ||
					!host_addr_equal(addr, kaddr)
				)
			) {
				if (GNET_PROPERTY(dht_debug)) {
					bool matches = port == kport &&
						host_addr_equal(addr, kn->addr);
					g_warning("DHT fixing contact address for kuid=%s to %s:%u"
						" based on routing table (%s UDP info%s%s) in %s",
						kuid_to_hex_string(id),
						host_addr_to_string(kn->addr), kn->port,
						matches ? "matches" : "still different from",
						matches ? "" : " ",
						matches ? "" : host_addr_port_to_string(addr, port),
						kmsg_infostr(data));
				}
				weird_header = TRUE;
				kaddr = kn->addr;
				/* Port identical, as checked in test */
				kn->flags |= KNODE_F_PCONTACT;	/* To adapt creator later */
				kn->flags &= ~KNODE_F_FOREIGN_IP;
			} else {
				kn->flags &= ~(KNODE_F_PCONTACT | KNODE_F_FOREIGN_IP);
				if (!host_addr_equal(addr, kaddr)) {
					if (GNET_PROPERTY(dht_debug)) {
						g_warning("DHT not fixing contact address %s "
							"(%s v%u.%u) kuid=%s but keeping "
							"routing table info %s:%u (UDP came from %s) in %s",
							host_addr_port_to_string(kaddr, kport),
							vendor_code_to_string(vcode.u32), kmajor, kminor,
							kuid_to_hex_string(id),
							host_addr_to_string(kn->addr), kn->port,
							host_addr_port_to_string2(addr, port),
							kmsg_infostr(data));
					}
					kn->flags |= KNODE_F_FOREIGN_IP;
					weird_header = TRUE;
				}
			}
		}

		if (GNET_PROPERTY(dht_debug) > 2) {
			g_debug("DHT traffic from known %s %s%snode %s at %s (%s v%u.%u)",
				knode_status_to_string(kn->status),
				(flags & KDA_MSG_F_FIREWALLED) ? "firewalled " : "",
				(flags & KDA_MSG_F_SHUTDOWNING) ? "shutdowning " : "",
				kuid_to_hex_string(id),
				host_addr_port_to_string(kaddr, kport),
				vendor_code_to_string(vcode.u32), kmajor, kminor);
		}

		/*
		 * Make sure the IP has not changed for the node.
		 * Otherwise, request an address verification if none is already
		 * pending for the node.
		 */

		if (
			/* Node not firewalled, contact address changed */
			(!(flags & KDA_MSG_F_FIREWALLED) &&
				(!host_addr_equal(kaddr, kn->addr) || kport != kn->port))
			||
			/* Node firewalled, source IP address changed */
			((flags & KDA_MSG_F_FIREWALLED) &&
				!host_addr_equal(kn->addr, addr))
		) {
			if (GNET_PROPERTY(dht_debug))
				g_debug("DHT new IP for %s (now at %s) -- %s verification",
					knode_to_string(kn),
					host_addr_port_to_string(kaddr, kport),
					(kn->flags & KNODE_F_VERIFYING) ?
						"already under" : "initiating");

			if (kn->flags & KNODE_F_VERIFYING) {
				knode_refcnt_inc(kn);	/* Node existed in routing table */
			} else {
				knode_t *new;

				new = knode_new(id, flags, kaddr, kport, vcode, kmajor, kminor);
				dht_verify_node(kn, new, TRUE);
				kn = new;				/* Speaking to new node for now */
			}
		} else {
			/*
			 * Node bears same address as before or is now firewalled (but
			 * messages still come from the address we knew about -- node
			 * will be removed from table shortly).
			 */

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
	 * If host is firewalled, ignore private host address in the Kademlia
	 * header and use the addr/port from the UDP datagram.
	 */

	if ((kn->flags & KNODE_F_FIREWALLED) && !host_addr_is_routable(kaddr)) {
		if (GNET_PROPERTY(dht_debug))
			g_warning("DHT non-routable contact address in firewalled node %s "
				"replaced by UDP source %s:%u",
				host_addr_port_to_string(kaddr, kport),
				host_addr_to_string(addr), port);

		/* kaddr and kport not changed since this does not count as a fixup */

		kn->addr = addr;
		kn->port = port;
		kn->flags |= KNODE_F_PCONTACT;
		weird_header = TRUE;
	}

	/*
	 * Update contact fixup stats.
	 */

	if (
		kport != kademlia_header_get_contact_port(header) ||
		!host_addr_equal(kaddr,
			host_addr_get_ipv4(kademlia_header_get_contact_addr(header)))
	)
		gnet_stats_inc_general(GNR_DHT_MSG_FIXED_CONTACT_ADDRESS);

	/*
	 * Log weird headers when debugging.
	 */

	if (
		weird_header &&
		GNET_PROPERTY(dht_debug) && GNET_PROPERTY(log_weird_dht_headers)
	) {
		dump_hex(stderr, "DHT Header", data, extended_length + KDA_HEADER_SIZE);
	}

	/*
	 * Handle the message.
	 */

	kmsg_handle(kn, n, header, extended_length,
		ptr_add_offset(header, extended_length + KDA_HEADER_SIZE),
		len - KDA_HEADER_SIZE - extended_length);

	knode_free(kn);		/* Will free only if not still referenced */

	return;

drop:
	if (GNET_PROPERTY(dht_debug)) {
		g_warning("DHT got invalid %sKademlia packet (%zu bytes) "
			"\"%s\" from UDP (%s): %s",
			node_udp_is_old(n) ? "OLD " : "",
			len, gmsg_infostr_full(data, len),
			host_addr_port_to_string(addr, port), reason);
		if (len && GNET_PROPERTY(dht_debug) > 10)
			dump_hex(stderr, "UDP datagram", data, len);
	}
}

static const struct kmsg kmsg_map[] = {
	{ 0x00,							FALSE, NULL, /* Invalid */	"invalid"	},
	{ KDA_MSG_PING_REQUEST,			TRUE,  k_handle_ping,		"PING"		},
	{ KDA_MSG_PING_RESPONSE,		FALSE, k_handle_pong,		"PONG"		},
	{ KDA_MSG_STORE_REQUEST,		TRUE,  k_handle_store,		"STORE"		},
	{ KDA_MSG_STORE_RESPONSE,		FALSE, k_handle_rpc_reply,	"STORE_ACK"	},
	{ KDA_MSG_FIND_NODE_REQUEST,	TRUE,  k_handle_find_node,	"FIND_NODE"	},
	{ KDA_MSG_FIND_NODE_RESPONSE,	FALSE, k_handle_rpc_reply,	"FOUND_NODE"},
	{ KDA_MSG_FIND_VALUE_REQUEST,	TRUE,  k_handle_find_value,	"FIND_VALUE"},
	{ KDA_MSG_FIND_VALUE_RESPONSE,	FALSE, k_handle_rpc_reply,	"VALUE"		},
	{ KDA_MSG_STATS_REQUEST,		TRUE,  NULL, /* Obsolete */	"STATS"		},
	{ KDA_MSG_STATS_RESPONSE,		FALSE, NULL, /* Obsolete */	"STATS_ACK"	},
};

/**
 * Find message description based on function.
 */
static const struct kmsg *
kmsg_find(uint8 function)
{
	const struct kmsg *km;

	if (function == 0 || function >= G_N_ELEMENTS(kmsg_map))
		return NULL;

	km = &kmsg_map[function];

	g_assert(km->function == function);

	return km;
}

/**
 * Convert message function number into name.
 */
const char *
kmsg_name(uint function)
{
	if (function >= G_N_ELEMENTS(kmsg_map))
		return "invalid";

	return kmsg_map[function].name;
}

/**
 * Same a kmsg_infostr() but fills the supplied buffer with the formatted
 * string and returns the amount of bytes written.
 */
size_t
kmsg_infostr_to_buf(const void *msg, char *buf, size_t buf_size)
{
	uint size = kmsg_size(msg);
	uint16 extlen = kademlia_header_get_extended_length(msg);
	char host[HOST_ADDR_PORT_BUFLEN];
	char ext[UINT32_DEC_BUFLEN + 4];	/* +1 for NUL, +3 for "(+)" */

	host_addr_port_to_string_buf(
			host_addr_get_ipv4(kademlia_header_get_contact_addr(msg)),
			kademlia_header_get_contact_port(msg),
			host, sizeof host);

	if (extlen != 0) {
		str_bprintf(ext, sizeof ext, "(+%u)", extlen);
	} else {
		ext[0] = '\0';
	}

	return str_bprintf(buf, buf_size, "%s%s (%u byte%s) [%s v%u.%u @%s]",
		kmsg_name(kademlia_header_get_function(msg)),
		ext, size, plural(size),
		vendor_code_to_string(kademlia_header_get_contact_vendor(msg)),
		kademlia_header_get_major_version(msg),
		kademlia_header_get_minor_version(msg),
		host);
}

/**
 * @param msg	the pointer to the Kademlia header (no need to access payload)
 *
 * @returns formatted static string containing basic information about
 * the message:
 *
 *   msg_type(+s) (payload length) [vendor version]
 *
 * A "(+s)" sign indicates an extended Kademlia header, ``s'' being the
 * size of that extension.
 */
const char *
kmsg_infostr(const void *msg)
{
	static char buf[80];
	kmsg_infostr_to_buf(msg, buf, sizeof buf);
	return buf;
}

/**
 * Initialize Kademlia messages.
 */
G_GNUC_COLD void
kmsg_init(void)
{
	size_t i;

	g_assert(NULL == kmsg_aging_pings);
	g_assert(NULL == kmsg_aging_finds);

	for (i = 0; i < G_N_ELEMENTS(kmsg_map); i++) {
		const struct kmsg *entry = &kmsg_map[i];

		g_assert(entry->function == i);
	}

	kmsg_aging_pings = aging_make(KMSG_PING_FREQ,
		host_addr_hash_func, host_addr_eq_func, wfree_host_addr);

	kmsg_aging_finds = aging_make(KMSG_FIND_FREQ,
		host_addr_hash_func, host_addr_eq_func, wfree_host_addr);
}

/**
 * Cleanup on DHT shutdown.
 */
void
kmsg_close(void)
{
	aging_destroy(&kmsg_aging_pings);
	aging_destroy(&kmsg_aging_finds);
}

/* vi: set ts=4 sw=4 cindent: */
