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
#include "token.h"
#include "keys.h"
#include "values.h"
#include "storage.h"

#include "core/gnet_stats.h"
#include "core/hosts.h"
#include "core/hostiles.h"
#include "core/udp.h"
#include "core/nodes.h"
#include "core/guid.h"
#include "core/sockets.h"
#include "core/settings.h"

#include "if/dht/kademlia.h"
#include "if/dht/value.h"

#include "if/gnet_property_priv.h"

#include "lib/bstr.h"
#include "lib/misc.h"
#include "lib/host_addr.h"
#include "lib/glib-missing.h"
#include "lib/pmsg.h"
#include "lib/vendors.h"
#include "lib/walloc.h"

#include "lib/override.h"		/* Must be the last header included */

#define MAX_VALUE_RESPONSE_SIZE	1024	/**< Max message size for VALUE */
#define MAX_STORE_RESPONSE_SIZE	1024	/**< Max message size for STORE acks */

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

	if (GNET_PROPERTY(dht_debug > 1)) {
		g_message("DHT got %s from %s",
			kmsg_infostr(header), knode_to_string(kn));
		if (len && GNET_PROPERTY(dht_debug > 19))
			dump_hex(stderr, "UDP payload", payload, len);
		
	}

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
		guint8 function = kademlia_header_get_function(header);
		g_warning("DHT message %s from %s "
			"has %lu byte%s of unparsed trailing data (ignored)",
			kmsg_name(function), knode_to_string(kn),
			(gulong) unparsed, 1 == unparsed ? "" : "s");
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
		GNET_PROPERTY(is_udp_firewalled) ? KDA_MSG_F_FIREWALLED : 0);
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

	g_assert(klen < 256);

	pmsg_write_u8(mb, klen);

	for (i = 0; i < klen; i++)
		serialize_contact(mb, kvec[i]);
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
	guint16 port;
	vendor_code_t vcode;
	guint8 major, minor;

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
 * Deserialize a DHT value.
 *
 * @return the deserialized DHT value, or NULL if an error occurred.
 */
dht_value_t *
kmsg_deserialize_dht_value(bstr_t *bs)
{
	dht_value_t *dv;
	kuid_t id;
	knode_t *creator;
	guint8 major, minor;
	guint16 length;
	gpointer data = NULL;
	guint32 type;

	creator = kmsg_deserialize_contact(bs);
	if (!creator)
		return NULL;

	bstr_read(bs, id.v, KUID_RAW_SIZE);
	bstr_read_be32(bs, &type);
	bstr_read_u8(bs, &major);
	bstr_read_u8(bs, &minor);
	bstr_read_be16(bs, &length);

	if (bstr_has_error(bs))
		goto error;

	if (length && length <= DHT_VALUE_MAX_LEN) {
		data = walloc(length);
		bstr_read(bs, data, length);
	} else {
		bstr_skip(bs, length);
	}

	if (bstr_has_error(bs))
		goto error;

	dv = dht_value_make(creator, &id, type, major, minor, data, length);
	knode_free(creator);
	return dv;

error:
	knode_free(creator);
	if (data)
		wfree(data, length);
	return NULL;
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
		g_message("DHT sending back %s (%lu bytes) to %s",
			kmsg_infostr(header), (unsigned long) pmsg_size(mb),
			host_addr_port_to_string(n->addr, n->port));

	udp_send_mb(n, mb);
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
		token_t tok;

		token_generate(&tok, kn);
		pmsg_write_u8(mb, TOKEN_RAW_SIZE);
		pmsg_write(mb, tok.v, TOKEN_RAW_SIZE);
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
		g_message("DHT sending back %s (%lu bytes) with %lu contact%s to %s",
			kmsg_infostr(header), (unsigned long) pmsg_size(mb),
			(unsigned long) klen, klen == 1 ? "" : "s",
			host_addr_port_to_string(n->addr, n->port));

	udp_send_mb(n, mb);
}

/**
 * qsort() callback to compare two DHT values on a length basis.
 */
static gint
dht_value_cmp(const void *a, const void *b)
{
	const dht_value_t * const *pa = a;
	const dht_value_t * const *pb = b;
	const dht_value_t *va = *pa;
	const dht_value_t *vb = *pb;

	return va->length == vb->length ? 0 :
		va->length < vb->length ? -1 : +1;
}

/**
 * Send back response to find_value(id).
 *
 * @param n			where to send the response to
 * @param kn		the node who sent the request
 * @param vvec		base of DHT value vector
 * @param vlen		amount of entries filled in vector
 * @param load		the EMA of the # of requests / minute for the key
 * @param muid		MUID to use in response
 */
static void
k_send_find_value_response(
	struct gnutella_node *n,
	const knode_t *unused_kn,
	dht_value_t **vvec, size_t vlen, float load, const guid_t *muid)
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

	mb = pmsg_new(PMSG_P_DATA, NULL, MAX_VALUE_RESPONSE_SIZE);

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

	qsort(vvec, vlen, sizeof vvec[0], dht_value_cmp);

	for (i = 0; i < vlen; i++) {
		size_t secondary_size = (vlen - i) * KUID_RAW_SIZE + 1;
		dht_value_t *v = vvec[i];
		size_t value_size = 61 + v->length;	/* See assert below */

		g_assert((size_t) pmsg_available(mb) >= secondary_size);

		if (value_size + secondary_size > (size_t) pmsg_available(mb)) {
			if (GNET_PROPERTY(dht_debug) > 3)
				g_warning("DHT after sending %d DHT values, will send %d key%s",
					i, vlen - i, (1 == vlen - i) ? "" : "s");
			break;
		}

		/* That's the specs and the 61 above depends on the following... */
		g_assert(NET_TYPE_IPV4 == host_addr_net(v->creator->addr));

		/* DHT value header */
		serialize_contact(mb, v->creator);
		pmsg_write(mb, v->id, KUID_RAW_SIZE);
		pmsg_write_be32(mb, v->type);
		pmsg_write_u8(mb, v->major);
		pmsg_write_u8(mb, v->minor);
		pmsg_write_be16(mb, v->length);

		/* DHT value data */
		if (v->length)
			pmsg_write(mb, v->data, v->length);

		values++;

		if (GNET_PROPERTY(dht_debug) > 4)
			g_warning("DHT packed value %d/%lu: %s", values, (gulong) vlen,
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
			pmsg_write(mb, v->creator->id, KUID_RAW_SIZE);
			secondaries++;

			if (GNET_PROPERTY(dht_debug) > 4)
				g_warning("DHT packed secondary key %d/%lu for %s",
					secondaries, (gulong) remain,
					dht_value_to_string(v));
		}
	}

	g_assert(values + secondaries == (int) vlen);	/* Sanity check */

	kademlia_header_set_size(header, pmsg_size(mb) - KDA_HEADER_SIZE);

	/*
	 * Send the message...
	 */

	if (GNET_PROPERTY(dht_debug > 3))
		g_message("DHT sending back %s (%lu bytes) with "
			"%d value%s and %d secondary key%s to %s",
			kmsg_infostr(header), (unsigned long) pmsg_size(mb),
			values, values == 1 ? "" : "s",
			secondaries, secondaries == 1 ? "" : "s",
			host_addr_port_to_string(n->addr, n->port));

	udp_send_mb(n, mb);
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
	dht_value_t **vec, guint8 vlen,
	gboolean valid_token,
	const guid_t *muid)
{
	pmsg_t *mb;
	kademlia_header_t *header;
	guint16 *status;
	int i;

	status = walloc(vlen * sizeof(guint16));

	for (i = 0; i < vlen; i++)
		status[i] = values_store(kn, vec[i], valid_token);

	/*
	 * The architected store response message v0.0 is Cretinus Maximus.
	 * Limit the total size to MAX_STORE_RESPONSE_SIZE, whatever happens.
	 */

	mb = pmsg_new(PMSG_P_DATA, NULL, MAX_STORE_RESPONSE_SIZE);

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
		pmsg_write(mb, vec[i]->id->v, KUID_RAW_SIZE);
		pmsg_write(mb, vec[i]->creator->id->v, KUID_RAW_SIZE);
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
		g_message("DHT sending back %s (%lu bytes) with %d status%s to %s",
			kmsg_infostr(header), (unsigned long) pmsg_size(mb),
			i, i == 1 ? "" : "es",
			host_addr_port_to_string(n->addr, n->port));

	udp_send_mb(n, mb);

	/*
	 * Cleanup.
	 */

	wfree(status, vlen * sizeof(guint16));
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

	warn_unparsed_trailer(kn, header, bs);

	bstr_destroy(bs);
	return;

error:
	gnet_stats_count_dropped(n, MSG_DROP_DHT_UNPARSEABLE);
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
		gnet_stats_count_dropped(n, MSG_DROP_DHT_UNPARSEABLE);
		return;
	}

	if (GNET_PROPERTY(dht_debug > 3))
		g_message("DHT node %s looking for %s",
			knode_to_string(kn), kuid_to_hex_string(id));

	g_assert(len == KUID_RAW_SIZE);

	/*
	 * If we're getting too much STORE request for this key, do not reply
	 * to the FIND_NODE message which will cause further STORE and further
	 * negative acknowledgements, wasting bandwidth.  Just drop the request
	 * on the floor, too bad for the remote node.
	 *
	 * We're going to appear as "stale" for the remote party, but we'll
	 * reply to its pings and to other requests for less busy keys...
	 */

	if (keys_is_store_loaded(id)) {
		if (GNET_PROPERTY(dht_debug > 2))
			g_message("DHT key %s getting too many STORE, "
				"ignoring FIND_NODE from %s",
				kuid_to_hex_string(id), knode_to_string(kn));

		gnet_stats_count_dropped(n, MSG_DROP_DHT_TOO_MANY_STORE);
		return;
	}

	cnt = dht_fill_closest(id, kvec, KDA_K, kn->id, TRUE);
	k_send_find_node_response(n,
		kn, kvec, cnt, kademlia_header_get_muid(header));
}

/**
 * Handle store requests.
 */
static void
k_handle_store(knode_t *kn, struct gnutella_node *n,
	const kademlia_header_t *header, guint8 extlen,
	const void *payload, size_t len)
{
	gboolean valid_token = FALSE;
	bstr_t *bs;
	char *reason;
	guint8 values;
	int i = 0;
	char msg[80];
	dht_value_t **vec = NULL;

	warn_no_header_extension(kn, header, extlen);

	bs = bstr_open(payload, len, GNET_PROPERTY(dht_debug) ? BSTR_F_ERROR : 0);
	
	/*
	 * Decompile first field: security token.
	 */

	{
		token_t security;
		guint8 token_len;

		if (!bstr_read_u8(bs, &token_len)) {
			reason = "could not read security token length";
			goto error;
		}

		if (sizeof(security.v) == (size_t) token_len)
			bstr_read(bs, security.v, sizeof(security.v));
		else
			bstr_skip(bs, token_len);

		if (bstr_has_error(bs)) {
			reason = "could not parse security token";
			goto error;
		}

		if (
			sizeof(security.v) == (size_t) token_len &&
			token_is_valid(&security, kn)
		)
			valid_token = TRUE;
	}

	if (GNET_PROPERTY(dht_debug))
		g_message("DHT STORE %s security token from %s",
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
		gboolean in_kball = keys_within_kball(kn->id);
		int ignored = in_kball ? values - 1 : values;

		if (ignored && GNET_PROPERTY(dht_debug))
			g_warning("DHT STORE ignoring the %u %svalue%s supplied by %s %s",
				ignored, in_kball ? "additional" : "", 1 == ignored ? "" : "s",
				in_kball ? "k-closest" : "foreigner",
				knode_to_string(kn));

		if (in_kball) {
			values = 1;
		} else {
			reason = "invalid security token";
			gnet_stats_count_dropped(n, MSG_DROP_DHT_INVALID_TOKEN);
			goto invalid_token;
		}
	}

	/*
	 * Decompile remaining fields: values to store.
	 */

	vec = walloc(values * sizeof *vec);

	for (i = 0; i < values; i++) {
		dht_value_t *v = kmsg_deserialize_dht_value(bs);

		if (NULL == v) {
			gm_snprintf(msg, sizeof msg,
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

		if ((kn->flags & KNODE_F_PCONTACT) && kuid_eq(kn->id, v->creator->id)) {
			knode_t *cn = deconstify_gpointer(v->creator);

			if (GNET_PROPERTY(dht_storage_debug))
				g_warning(
					"DHT patching creator's IP %s:%u to match sender's %s",
					host_addr_to_string(cn->addr), cn->port,
					host_addr_port_to_string(kn->addr, kn->port));

			cn->addr = kn->addr;
			cn->port = kn->port;
			cn->flags |= KNODE_F_PCONTACT;
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
	gnet_stats_count_dropped(n, MSG_DROP_DHT_UNPARSEABLE);
	/* FALL THROUGH */

invalid_token:
	if (GNET_PROPERTY(dht_debug))
		g_warning("DHT unhandled STORE payload (%lu byte%s) from %s: %s: %s",
			(unsigned long) len, len == 1 ? "" : "s", knode_to_string(kn),
			reason, bstr_error(bs));

	/* FALL THROUGH */

cleanup:
	if (vec) {
		int j;

		for (j = 0; j < i; j++)
			dht_value_free(vec[j], TRUE);

		wfree(vec, values * sizeof *vec);
	}

	bstr_destroy(bs);
}

/**
 * Handle find_value(id) requests.
 */
static void
k_handle_find_value(knode_t *kn, struct gnutella_node *n,
	const kademlia_header_t *header, guint8 extlen,
	const void *payload, size_t len)
{
	kuid_t *id = (kuid_t *) payload;
	bstr_t *bs;
	guint8 count;
	kuid_t **secondary = NULL;
	const char *reason;
	char msg[80];
	dht_value_type_t type;
	dht_value_t *vvec[MAX_VALUES_PER_KEY];
	int vcnt = 0;
	float load;

	warn_no_header_extension(kn, header, extlen);

	/*
	 * Must have at least the KUID to locate, and 4 bytes at the end
	 * to hold the DHT value type.
	 */

	if (len < KUID_RAW_SIZE + 4 && GNET_PROPERTY(dht_debug)) {
		g_warning("DHT bad FIND_VALUE payload (%lu byte%s) from %s",
			(unsigned long) len, len == 1 ? "" : "s", knode_to_string(kn));
		dump_hex(stderr, "Kademlia FIND_VALUE payload", payload, len);
		gnet_stats_count_dropped(n, MSG_DROP_DHT_UNPARSEABLE);
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
		g_message("DHT FETCH node %s looking for %s value %s (%s)",
			knode_to_string(kn),
			dht_value_type_to_string(type),
			kuid_to_hex_string(id), kuid_to_string(id));

	/*
	 * If we don't hold the key, reply as we would for a FIND_NODE.
	 */

	if (!keys_exists(id)) {
		knode_t *kvec[KDA_K];
		int cnt;

		if (GNET_PROPERTY(dht_debug) || GNET_PROPERTY(dht_storage_debug))
			g_message("DHT FETCH %s not found (%s)",
				kuid_to_hex_string(id), kuid_to_string(id));

		cnt = dht_fill_closest(id, kvec, KDA_K, kn->id, TRUE);
		k_send_find_node_response(n,
			kn, kvec, cnt, kademlia_header_get_muid(header));

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

		secondary = walloc0(count * sizeof(secondary[0]));

		for (i = 0; i < count; i++) {
			kuid_t sec_id;

			if (!bstr_read(bs, sec_id.v, KUID_RAW_SIZE)) {
				gm_snprintf(msg, sizeof msg,
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
		vvec, G_N_ELEMENTS(vvec), &load);

	k_send_find_value_response(n,
		kn, vvec, vcnt, load, kademlia_header_get_muid(header));

	goto cleanup;

error:
	gnet_stats_count_dropped(n, MSG_DROP_DHT_UNPARSEABLE);
	if (GNET_PROPERTY(dht_debug))
		g_warning(
			"DHT unhandled FIND_VALUE payload (%lu byte%s) from %s: %s: %s",
			(unsigned long) len, len == 1 ? "" : "s", knode_to_string(kn),
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
		wfree(secondary, count * sizeof(secondary[0]));
	}

	if (vcnt) {
		int i;
		for (i = 0; i < vcnt; i++)
			dht_value_free(vvec[i], TRUE);
	}

	bstr_destroy(bs);
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

	knode_check(kn);

	if (GNET_PROPERTY(dht_debug) > 3) {
		int len = pmsg_size(mb);
		g_message("DHT sending %s (%d bytes) to %s, RTT=%u",
			kmsg_infostr(pmsg_start(mb)), len, knode_to_string(kn), kn->rtt);
		if (GNET_PROPERTY(dht_debug) > 19)
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
	const guid_t *muid, pmsg_free_t mfree, gpointer marg)
{
	pmsg_t *mb;
	int msize;
	int i;

	g_assert(skeys == NULL || scnt > 0);
	g_assert(scnt >= 0 && scnt < 256);

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
 * @param n			the UDP Gnutella node, for some core function calls
 */
void kmsg_received(
	gconstpointer data, size_t len,
	host_addr_t addr, guint16 port,
	struct gnutella_node *n)
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
	const kuid_t *id;
	guint8 flags;
	guint16 extended_length;

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
	id = (const kuid_t *) kademlia_header_get_contact_kuid(header);
	kaddr = host_addr_get_ipv4(kademlia_header_get_contact_addr(header));
	kport = kademlia_header_get_contact_port(header);
	flags = kademlia_header_get_contact_flags(header);

	/*
	 * Check contact's address, if host not flagged as "firewalled".
	 */

	if (!(flags & KDA_MSG_F_FIREWALLED) && !host_is_valid(kaddr, kport)) {
		if (GNET_PROPERTY(dht_debug))
			g_warning("DHT bad contact address %s (%s v%u.%u), "
				"forcing \"firewalled\" flag",
				host_addr_port_to_string(kaddr, kport),
				vendor_code_to_string(vcode.u32), kmajor, kminor);

		flags |= KDA_MSG_F_FIREWALLED;
	}

	/*
	 * Even if they are "firewalled", drop the message if contact address
	 * is deemed hostile.  There's no reason a good firewalled host would
	 * pick this address to appear in the contact.
	 */

	if (hostiles_check(kaddr)) {
		if (GNET_PROPERTY(dht_debug))
			g_warning("DHT hostile contact address %s (%s v%u.%u)",
				host_addr_to_string(kaddr),
				vendor_code_to_string(vcode.u32), kmajor, kminor);
		reason = "hostile contact address";
		goto drop;
	}

	/*
	 * See whether we already have this node in the routing table.
	 */

	kn = dht_find_node(id);

	g_assert(kn == NULL || !(kn->flags & KNODE_F_FIREWALLED));

	if (NULL == kn) {
		if (GNET_PROPERTY(dht_debug) > 2)
			g_message("DHT traffic from new %s%snode %s at %s (%s v%u.%u)",
				(flags & KDA_MSG_F_FIREWALLED) ? "firewalled " : "",
				(flags & KDA_MSG_F_SHUTDOWNING) ? "shutdowning " : "",
				kuid_to_hex_string(id),
				host_addr_port_to_string(kaddr, kport),
				vendor_code_to_string(vcode.u32), kmajor, kminor);

		kn = knode_new(id, flags, kaddr, kport, vcode, kmajor, kminor);
		if (!(flags & (KDA_MSG_F_FIREWALLED | KDA_MSG_F_SHUTDOWNING)))
			dht_traffic_from(kn);
	} else {
		if (GNET_PROPERTY(dht_debug) > 2)
			g_message("DHT traffic from known %s %s%snode %s at %s (%s v%u.%u)",
				knode_status_to_string(kn->status),
				(flags & KDA_MSG_F_FIREWALLED) ? "firewalled " : "",
				(flags & KDA_MSG_F_SHUTDOWNING) ? "shutdowning " : "",
				kuid_to_hex_string(id),
				host_addr_port_to_string(kaddr, kport),
				vendor_code_to_string(vcode.u32), kmajor, kminor);

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
				g_message("DHT new IP for %s (now at %s) -- %s verification",
					knode_to_string(kn),
					host_addr_port_to_string(kaddr, kport),
					(kn->flags & KNODE_F_VERIFYING) ?
						"already under" : "initiating");

			if (kn->flags & KNODE_F_VERIFYING) {
				knode_refcnt_inc(kn);	/* Node existed in routing table */
			} else {
				knode_t *new;

				new = knode_new(id, flags, kaddr, kport, vcode, kmajor, kminor);
				dht_verify_node(kn, new);
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
	 * If we got the UDP message from another address than the one we
	 * have in the contact information, it is not necessarily an error.
	 * However, we keep track of that by flagging the node.
	 *
	 * We always reply to the address we had in the UDP message, but when
	 * contacting the node, we use the address in the contact information.
	 * The gnutella_node structure keeps track of the origin of the UDP message.
	 */

	if (!(kn->flags & KNODE_F_FIREWALLED) && !host_addr_equal(addr, kaddr)) {
		if (GNET_PROPERTY(dht_debug))
			g_warning("DHT contact address is %s but message came from %s",
				host_addr_port_to_string(kaddr, kport),
				host_addr_to_string(addr));

		kn->flags |= KNODE_F_FOREIGN_IP;
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

		kn->addr = addr;
		kn->port = port;
		kn->flags |= KNODE_F_PCONTACT;
	}

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
	{ KDA_MSG_STORE_REQUEST,		k_handle_store,			"STORE"			},
	{ KDA_MSG_STORE_RESPONSE,		NULL,					"STORE_ACK"		},
	{ KDA_MSG_FIND_NODE_REQUEST,	k_handle_find_node,		"FIND_NODE"		},
	{ KDA_MSG_FIND_NODE_RESPONSE,	k_handle_lookup,		"FOUND_NODE"	},
	{ KDA_MSG_FIND_VALUE_REQUEST,	k_handle_find_value,	"FIND_VALUE"	},
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
	char host[HOST_ADDR_PORT_BUFLEN];

	host_addr_port_to_string_buf(
			host_addr_get_ipv4(kademlia_header_get_contact_addr(msg)),
			kademlia_header_get_contact_port(msg),
			host, sizeof host);

	return gm_snprintf(buf, buf_size, "%s%s (%u byte%s) [%s v%u.%u @%s]",
		kmsg_name(kademlia_header_get_function(msg)),
		kademlia_header_get_extended_length(msg) ? "(+)" : "",
		size, size == 1 ? "" : "s",
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
