/*
 * Copyright (c) 2003, Raphael Manfredi
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
 * Vendor-specific messages.
 *
 * @author Raphael Manfredi
 * @date 2003
 */

#include "common.h"

#include "clock.h"
#include "dmesh.h"
#include "dq.h"
#include "fileinfo.h"
#include "ggep.h"
#include "ggep_type.h"
#include "gmsg.h"
#include "gnet_stats.h"
#include "guid.h"			/* For blank_guid[] */
#include "hostiles.h"
#include "hosts.h"
#include "inet.h"
#include "mq.h"
#include "mq_udp.h"
#include "nodes.h"
#include "oob.h"
#include "routing.h"		/* For message_set_muid() */
#include "search.h"
#include "settings.h"		/* For listen_addr() */
#include "sockets.h"		/* For socket_listen_addr() */
#include "tsync.h"
#include "ipp_cache.h"
#include "udp.h"
#include "uploads.h"
#include "vmsg.h"

#include "if/gnet_property.h"
#include "if/gnet_property_priv.h"
#include "if/dht/dht.h"			/* For dht_enabled(), dht_is_active() */
#include "if/dht/kademlia.h"	/* For KDA_VERSION_* */

#include "lib/array.h"
#include "lib/atoms.h"
#include "lib/base16.h"
#include "lib/endian.h"
#include "lib/hashing.h"
#include "lib/hashlist.h"
#include "lib/hset.h"
#include "lib/mempcpy.h"
#include "lib/misc.h"			/* hexadecimal conversions */
#include "lib/nid.h"
#include "lib/patricia.h"
#include "lib/pmsg.h"
#include "lib/random.h"
#include "lib/str.h"
#include "lib/stringify.h"
#include "lib/timestamp.h"
#include "lib/tm.h"
#include "lib/urn.h"
#include "lib/vendors.h"
#include "lib/walloc.h"

#include "lib/override.h"	/* Must be the last header included */

static char v_tmp[4128];	/**< Large enough for a payload of 4 KiB */
static gnutella_header_t *v_tmp_header = (void *) v_tmp;
static gnutella_vendor_t *v_tmp_data = (void *) &v_tmp[GTA_HEADER_SIZE];

/* Available payload space minus the bytes used by headers */
#define VMSG_PAYLOAD_MAX \
	((sizeof v_tmp) - GTA_HEADER_SIZE - sizeof(gnutella_vendor_t))

static hset_t *hs_vmsg;

/*
 * Vendor message handler.
 */

struct vmsg;

typedef void (*vmsg_handler_t)(struct gnutella_node *n,
	const struct vmsg *vmsg, const char *payload, size_t size);

/**
 * Definition of vendor messages.
 */
struct vmsg {
	uint32 vendor;
	uint16 id;
	uint16 version;
	vmsg_handler_t handler;
	const char *name;
};

#define VMS_ITEM_SIZE		8		/**< Each entry is 8 bytes (4+2+2) */
#define VMS_FEATURE_SIZE	6		/**< Each entry is 6 bytes (4+2) */

enum vmsg_pmi_magic { VMSG_PMI_MAGIC = 0x1b311e93 };

/**
 * Message block information for those equipped with a free routine.
 */
struct vmsg_pmsg_info {
	enum vmsg_pmi_magic magic;
	struct nid *nid;				/**< Node ID of message target */
	vmsg_sent_t sent;				/**< User callback to invoke */
	void *arg;						/**< Additional user argument */
};

static inline void
vmsg_pmsg_info_check(const struct vmsg_pmsg_info * const pmi)
{
	g_assert(pmi != NULL);
	g_assert(VMSG_PMI_MAGIC == pmi->magic);
}

static uint
vmsg_hash_func(const void *key)
{
	const struct vmsg *vmsg = key;
	return integer_hash(vmsg->vendor) ^ port_hash(vmsg->id);
}

static uint
vmsg_hash_func2(const void *key)
{
	const struct vmsg *vmsg = key;
	return integer_hash2(vmsg->vendor) ^ port_hash2(vmsg->id);
}

static bool
vmsg_eq_func(const void *p, const void *q)
{
	const struct vmsg *a = p, *b = q;
	return a->vendor == b->vendor && a->id == b->id;
}

/**
 * Find message, given vendor code, and id.
 *
 * @param vmsg_ptr If the message is supported, the structure
 *				   will be initialized appropriately.
 * @param vc The vendor code.
 * @param id The vendor message ID.
 * @param version The vendor message version.
 * @returns whether the message is known and supported. 
 */
static bool
find_message(struct vmsg *vmsg_ptr,
	vendor_code_t vc, uint16 id, uint16 version)
{
	struct vmsg key, *value;

	key.vendor = vc.u32;
	key.id = id;

	value = hset_lookup(hs_vmsg, &key);
	if (value) {
		*vmsg_ptr = *value;
		vmsg_ptr->version = version;
		return TRUE;
	} else {
		return FALSE;
	}
}

/**
 * Decompiles vendor-message name given the data payload of the Gnutella
 * message and its size.  The leading bytes give us the identification
 * unless it's too short.
 *
 * @return vendor message name in the form "NAME/1v1 'Known name'" as
 * a static string.
 */
const char *
vmsg_infostr(const void *data, size_t size)
{
	static char msg[80];
	vendor_code_t vc;
	uint16 id;
	uint16 version;
	struct vmsg vmsg;

	if (size < sizeof vc)
		return "????";

	vc.u32 = gnutella_vendor_get_code(data);
	id = gnutella_vendor_get_selector_id(data);
	version = gnutella_vendor_get_version(data);

	if (!find_message(&vmsg, vc, id, version))
		str_bprintf(msg, sizeof msg , "%s/%uv%u",
			vendor_code_to_string(vc.u32), id, version);
	else
		str_bprintf(msg, sizeof msg, "%s/%uv%u '%s'",
			vendor_code_to_string(vc.u32), id, version, vmsg.name);

	return msg;
}

/**
 * Send reply to node (message block), via the appropriate channel.
 */
static void
vmsg_send_reply(struct gnutella_node *n, pmsg_t *mb)
{
	if (GNET_PROPERTY(vmsg_debug) > 2 || GNET_PROPERTY(log_vmsg_tx)) {
		g_debug("VMSG sending %s to %s",
			gmsg_infostr_full(pmsg_start(mb), pmsg_size(mb)), node_infostr(n));
	}

	if (NODE_IS_UDP(n))
		udp_send_mb(n, mb);
	else
		gmsg_mb_sendto_one(n, mb);
}

/**
 * Send a message to node (data + size), via the appropriate channel.
 */
static void
vmsg_send_data(struct gnutella_node *n, const void *data, uint32 size)
{
	if (NODE_IS_UDP(n))
		udp_send_msg(n, data, size);
	else
		gmsg_sendto_one(n, data, size);

	if (GNET_PROPERTY(vmsg_debug) > 2 || GNET_PROPERTY(log_vmsg_tx)) {
		g_debug("VMSG sent %s to %s",
			gmsg_infostr_full(data, size), node_infostr(n));
	}
}

/**
 * Send a control message to node (data + size), via the appropriate channel.
 */
static void
vmsg_ctrl_send_data(struct gnutella_node *n, const void *data, uint32 size)
{
	if (NODE_IS_UDP(n))
		udp_ctrl_send_msg(n, data, size);
	else
		gmsg_ctrl_sendto_one(n, data, size);

	if (GNET_PROPERTY(vmsg_debug) > 2 || GNET_PROPERTY(log_vmsg_tx)) {
		g_debug("VMSG sent %s to %s",
			gmsg_infostr_full(data, size), node_infostr(n));
	}
}

/**
 * Callback trampoline for vmsg_send_data_notify().
 *
 * Invoked when message is freed to trigger appropriate notification.
 */
static void
vmsg_pmsg_free(pmsg_t *mb, void *arg)
{
	struct vmsg_pmsg_info *pmi = arg;
	gnutella_node_t *n;

	vmsg_pmsg_info_check(pmi);
	g_assert(pmsg_is_extended(mb));

	/*
	 * Callback is invoked regardless of whether message was sent.
	 */

	n = node_by_id(pmi->nid);		/* Will be NULL if node is gone */
	(*pmi->sent)(n, pmsg_was_sent(mb), pmi->arg);

	nid_unref(pmi->nid);
	pmi->magic = 0;
	WFREE(pmi);
}

/**
 * Send a message to node (data + size), via the appropriate channel.
 *
 * @param n				destination node
 * @param prioritary	whether message is prioritary
 * @param msg			pointer to start of message
 * @param size			size of message
 * @param sent			optional: if non-NULL, callback to invoke when sent
 * @param arg			additional callback argument
 *
 * For TCP nodes we can optionally install a callback that will be
 * triggered when the message has been finally sent.
 */
static void
vmsg_send_data_notify(struct gnutella_node *n, bool prioritary,
	const void *msg, uint32 size, vmsg_sent_t sent, void *arg)
{
	g_assert(NULL == sent || !NODE_IS_UDP(n));

	if (NODE_IS_UDP(n)) {
		udp_send_msg(n, msg, size);
	} else {
		pmsg_t *mb;
		int prio = prioritary ? PMSG_P_CONTROL : PMSG_P_DATA;

		if (NULL == sent) {
			mb = pmsg_new(prio, msg, size);
		} else {
			struct vmsg_pmsg_info *pmi;

			WALLOC(pmi);
			pmi->magic = VMSG_PMI_MAGIC;
			pmi->nid = nid_ref(NODE_ID(n));
			pmi->sent = sent;
			pmi->arg = arg;

			mb = pmsg_new_extend(prio, msg, size, vmsg_pmsg_free, pmi);
		}
		gmsg_mb_sendto_one(n, mb);
	}

	if (GNET_PROPERTY(vmsg_debug) > 2 || GNET_PROPERTY(log_vmsg_tx)) {
		g_debug("VMSG sent %s to %s",
			gmsg_infostr_full(msg, size), node_infostr(n));
	}
}

/**
 * Main entry point to handle reception of vendor-specific message.
 */
void
vmsg_handle(struct gnutella_node *n)
{
	gnutella_vendor_t *v = cast_to_pointer(n->data);
	bool found;
	struct vmsg vmsg;
	vendor_code_t vc;
	uint16 id, version;
	const unsigned expected_size = sizeof *v;

	if (n->size < expected_size) {
		gnet_stats_count_dropped(n, MSG_DROP_TOO_SMALL);
		if (GNET_PROPERTY(vmsg_debug) || GNET_PROPERTY(log_bad_gnutella))
			gmsg_log_bad(n, "message has only %u bytes, needs at least %u",
				(unsigned) n->size, expected_size);
		return;
	}

	vc.u32 = gnutella_vendor_get_code(v);
	id = gnutella_vendor_get_selector_id(v);
	version = gnutella_vendor_get_version(v);

	found = find_message(&vmsg, vc, id, version);

	if (GNET_PROPERTY(vmsg_debug) > 4 || GNET_PROPERTY(log_vmsg_rx)) {
		g_debug("VMSG got %s from %s",
			gmsg_infostr_full_split(n->header, n->data, n->size),
			node_infostr(n));
	}

	/*
	 * If we can't handle the message, we count it as "unknown type", which
	 * is not completely exact because the type (vendor-specific) is known,
	 * it was only the subtype of that message which was unknown.  Still, I
	 * don't think it is ambiguous enough to warrant another drop type.
	 *		--RAM, 04/01/2003.
	 */

	if (found) {
		(*vmsg.handler)(n, &vmsg, n->data + sizeof(*v), n->size - sizeof(*v));
	} else {
		gnet_stats_count_dropped(n, MSG_DROP_UNKNOWN_TYPE);
		if (GNET_PROPERTY(vmsg_debug) || GNET_PROPERTY(log_bad_gnutella))
			gmsg_log_bad(n, "unknown vendor message");
	}
}

/**
 * Fill common message header part for all vendor-specific messages.
 * The GUID is blanked (all zero bytes), TTL is set to 1 and hops to 0.
 * Those common values can be superseded by the caller if needed.
 *
 * `size' is only the size of the payload we filled so far.
 * `maxsize' is the size of the already allocated vendor messsage.
 *
 * @returns the total size of the whole Gnutella message.
 */
static uint32
vmsg_fill_header(gnutella_header_t *header, uint32 size, uint32 maxsize)
{
	uint32 msize;

	/* Default GUID: all blank */
	gnutella_header_set_muid(header, &blank_guid);
	gnutella_header_set_function(header, GTA_MSG_VENDOR);
	gnutella_header_set_ttl(header, 1);
	gnutella_header_set_hops(header, 0);

	msize = size + sizeof(gnutella_vendor_t);

	gnutella_header_set_size(header, msize);

	msize += GTA_HEADER_SIZE;

	if (msize > maxsize)
		g_error("allocated vendor message is only %u bytes, would need %u",
			maxsize, msize);

	return msize;
}

/**
 * Indicate that we understand deflated UDP payloads.
 */
static void
vmsg_advertise_udp_compression(gnutella_header_t *header)
{
	uint8 ttl = gnutella_header_get_ttl(header);

	g_assert(0 == (ttl & GTA_UDP_CAN_INFLATE));

	gnutella_header_set_ttl(header, ttl | GTA_UDP_CAN_INFLATE);
}

/**
 * Fill leading part of the payload data, containing the common part for
 * all vendor-specific messages.
 *
 * @returns start of payload after that common part.
 */
static char *
vmsg_fill_type(gnutella_vendor_t *base,
	uint32 vendor, uint16 id, uint16 version)
{
	gnutella_vendor_set_code(base, vendor);
	gnutella_vendor_set_selector_id(base, id);
	gnutella_vendor_set_version(base, version);

	return (char *) &base[1];
}

/**
 * Report a vendor-message with bad payload to the stats.
 */
static bool
vmsg_bad_payload(struct gnutella_node *n,
	const struct vmsg *vmsg, size_t size, size_t expected)
{
	n->n_bad++;
	gnet_stats_count_dropped(n, MSG_DROP_BAD_SIZE);

	if (GNET_PROPERTY(vmsg_debug) || GNET_PROPERTY(log_bad_gnutella))
		gmsg_log_bad(n, "bad payload size %zu for %s/%uv%u (%s), "
			"expected at least %zu bytes",
			size, vendor_code_to_string(vmsg->vendor), vmsg->id,
			vmsg->version, vmsg->name, expected);

	return TRUE;	/* bad */
}

/**
 * Check that payload "size" is at least "min_size"-byte long.
 *
 * @return TRUE if size is short, FALSE if OK.
 */
#define VMSG_SHORT_SIZE(n, vmsg, size, min_size) \
	(((size) < (min_size)) \
		? vmsg_bad_payload((n), (vmsg), (size), (min_size)) \
		: FALSE)

/**
 * Ignore message coming from wrong origin, complaining loudly when debugging.
 */
static void
vmsg_ignore(const gnutella_node_t *n, const struct vmsg *vmsg)
{
	if (GNET_PROPERTY(vmsg_debug)) {
		g_warning("VMSG got %s/%uv%u \"%s\" via %s, ignoring",
			vendor_code_to_string(vmsg->vendor),
			vmsg->id, vmsg->version, vmsg->name, node_infostr(n));
	}
}

/**
 * Make sure message comes from TCP.
 *
 * @return TRUE if message is from TCP.
 */
static inline bool
vmsg_from_tcp(const gnutella_node_t *n, const struct vmsg *vmsg)
{
	if (NODE_IS_UDP(n)) {
		vmsg_ignore(n, vmsg);
		return FALSE;
	}

	return TRUE;
}

/**
 * Make sure message comes from UDP.
 *
 * @return TRUE if message is from UDP.
 */
static inline bool
vmsg_from_udp(const gnutella_node_t *n, const struct vmsg *vmsg)
{
	if (!NODE_IS_UDP(n)) {
		vmsg_ignore(n, vmsg);
		return FALSE;
	}

	return TRUE;
}

/**
 * Handle the "Features Supported" message.
 */
static void
handle_features_supported(struct gnutella_node *n,
	const struct vmsg *vmsg, const char *payload, size_t size)
{
	const char *description;
	uint16 count;
	str_t *feats;

	if (!vmsg_from_tcp(n, vmsg))
		return;

	count = peek_le16(payload);

	if (GNET_PROPERTY(vmsg_debug) > 1)
		g_debug("VMSG %s supports %u extra feature%s",
			node_infostr(n), count, plural(count));

	if (VMSG_SHORT_SIZE(n, vmsg, size, count * VMS_FEATURE_SIZE + sizeof count))
		return;

	description = &payload[2];		/* Skip count */

	/*
	 * Analyze the supported features.
	 */

	feats = str_new(count * 16);	/* Pre-size generously */

	while (count-- > 0) {
		char feature[5];
		uint16 version;

		memcpy(feature, &description[0], 4);
		feature[4] = '\0';
		version = peek_le16(&description[4]);
		description += 6;

		str_catf(feats, " %s/%u", feature, version);

		if (GNET_PROPERTY(vmsg_debug) > 2)
			g_debug("VMSG %s supports feature %s/%u",
				node_infostr(n), feature, version);

		if (0 != version && 0 == strcmp(feature, "TLS!")) {
			node_supports_tls(n);
		}

		if (0 != version && 0 == strcmp(feature, "WHAT")) {
			node_supports_whats_new(n);
		}

		if (0 != version && 0 == strcmp(feature, "QRP1")) {
			node_supports_qrp_1bit_patches(n);
		}

		/* Any of ADHT, PDHT or LDHT means DHT is supported */
		if (feature[0] && 0 == strcmp(&feature[1], "DHT")) {
			dht_mode_t mode;
			bool known = TRUE;
			switch (feature[0]) {
			case 'A': mode = DHT_MODE_ACTIVE; break;
			case 'P': mode = DHT_MODE_PASSIVE; break;
			case 'L': mode = DHT_MODE_PASSIVE_LEAF; break;
			case 'I': mode = DHT_MODE_INACTIVE; break;
			default:  known = FALSE; break;
			}
			if (known) {
				node_supports_dht(n, mode);
			}
		}
	}

	if (!NODE_IS_TRANSIENT(n))
		node_supported_feats(n, str_2c(feats), str_len(feats));

	str_destroy(feats);
}

/**
 * Handle the "Hops Flow" message.
 */
static void
handle_hops_flow(struct gnutella_node *n,
	const struct vmsg *vmsg, const char *payload, size_t size)
{
	if (vmsg->version > 1)
		return;

	if (VMSG_SHORT_SIZE(n, vmsg, size, 1))
		return;

	node_set_hops_flow(n, peek_u8(payload));
}

/**
 * Send an "Hops Flow" message to specified node.
 *
 * @param n		target node
 * @param hops	max number of hops allowed on received queries
 * @param sent	if non-NULL, will be invoked when message is sent
 * @param arg	additional callback argument
 */
void
vmsg_send_hops_flow(struct gnutella_node *n, uint8 hops,
	vmsg_sent_t sent, void *arg)
{
	uint32 paysize = sizeof hops;
	uint32 msgsize;
	char *payload;

	msgsize = vmsg_fill_header(v_tmp_header, paysize, sizeof v_tmp);
	payload = vmsg_fill_type(v_tmp_data, T_BEAR, 4, 1);

	*payload = hops;

	/*
	 * Send the message as a control message, so that it gets sent ASAP.
	 */

	vmsg_send_data_notify(n, TRUE, v_tmp, msgsize, sent, arg);
}

/**
 * Handle the "TCP Connect Back" message.
 */
static void
handle_tcp_connect_back(struct gnutella_node *n,
	const struct vmsg *vmsg, const char *payload, size_t size)
{
	uint16 port;

	if (vmsg->version > 1)
		return;

	if (VMSG_SHORT_SIZE(n, vmsg, size, 2))
		return;

	port = peek_le16(payload);
	if (port == 0) {
		if (GNET_PROPERTY(vmsg_debug)) {
			g_warning("got improper port #%d in %s from %s",
				port, vmsg->name, node_infostr(n));
		}
		return;
	}

	/* XXX forward to neighbours supporting the remote connect back message? */

	node_connect_back(n, port);
}

/**
 * Send a "TCP Connect Back" message to specified node, telling it to connect
 * back to us on the specified port.
 */
void
vmsg_send_tcp_connect_back(struct gnutella_node *n, uint16 port)
{
	uint32 paysize = sizeof port;
	uint32 msgsize;
	char *payload;

	g_return_if_fail(0 != port);

	msgsize = vmsg_fill_header(v_tmp_header, paysize, sizeof v_tmp);
	payload = vmsg_fill_type(v_tmp_data, T_BEAR, 7, 1);

	poke_le16(payload, port);

	gmsg_sendto_one(n, v_tmp, msgsize);

	if (GNET_PROPERTY(vmsg_debug) > 2 || GNET_PROPERTY(log_vmsg_tx)) {
		g_debug("VMSG sent %s for port %u to %s",
			gmsg_infostr_full(v_tmp, msgsize), port, node_infostr(n));
	}
}

/**
 * Handle the "UDP Connect Back" message.
 */
static void
handle_udp_connect_back(struct gnutella_node *n,
	const struct vmsg *vmsg, const char *payload, size_t size)
{
	const struct guid *guid;
	size_t expected_size;
	uint16 port;

	if (vmsg->version < 1 || vmsg->version > 2)
		return;

	expected_size = sizeof(port);
	if (vmsg->version < 2) {
		expected_size += GUID_RAW_SIZE;
	}
	if (VMSG_SHORT_SIZE(n, vmsg, size, expected_size))
		return;

	port = peek_le16(payload);
	if (0 == port) {
		if (GNET_PROPERTY(vmsg_debug)) {
			g_warning("got improper port #%d in %s from %s",
				port, vmsg->name, node_infostr(n));
		}
		return;
	}

	/*
	 * Version 1 included the GUID at the end of the payload.
	 * Version 2 uses the message's GUID itself to store the GUID
	 * of the PING to send back.
	 */

	if (vmsg->version == 1) {
		/* Get GUID from payload */
		guid = cast_to_guid_ptr_const(&payload[2]);
	} else {
		/* Get GUID from MUID */
		guid = gnutella_header_get_muid(&n->header);
	}

	udp_connect_back(n->addr, port, guid);
}

/**
 * Send a "UDP Connect Back" message to specified node, telling it to ping
 * us back via UDP on the specified port.
 *
 * XXX for now, we only send GTKG/7v1, although GTKG/7v2 is more compact.
 */
void
vmsg_send_udp_connect_back(struct gnutella_node *n, uint16 port)
{
	uint32 paysize = sizeof(port) + 16;
	uint32 msgsize;
	char *payload;

	g_return_if_fail(0 != port);

	msgsize = vmsg_fill_header(v_tmp_header, paysize, sizeof v_tmp);
	payload = vmsg_fill_type(v_tmp_data, T_GTKG, 7, 1);

	payload = poke_le16(payload, port);
	memcpy(payload, GNET_PROPERTY(servent_guid), GUID_RAW_SIZE);

	gmsg_sendto_one(n, v_tmp, msgsize);

	if (GNET_PROPERTY(vmsg_debug) > 2 || GNET_PROPERTY(log_vmsg_tx)) {
		g_debug("VMSG sent %s for port %u to %s",
			gmsg_infostr_full(v_tmp, msgsize), port, node_infostr(n));
	}
}

/**
 * Send a "Push Proxy Acknowledgment" message to specified node, using
 * supplied `muid' as the message ID (which is the target node's GUID).
 *
 * The version 1 of this message did not have the listening IP, only the
 * port: the recipient was supposed to gather the IP address from the
 * connected socket.
 *
 * The version 2 includes both our IP and port.
 */
static void
vmsg_send_proxy_ack(struct gnutella_node *n,
	const struct guid *muid, int version)
{
	uint32 paysize = sizeof(uint32) + sizeof(uint16);
	uint32 msgsize;
	char *payload;

	if (version == 1)
		paysize -= sizeof(uint32);		/* No IP address for v1 */

	msgsize = vmsg_fill_header(v_tmp_header, paysize, sizeof v_tmp);
	gnutella_header_set_muid(v_tmp_header, muid);
	payload = vmsg_fill_type(v_tmp_data, T_LIME, 22, version);

	if (version >= 2) {
		payload = poke_be32(payload, host_addr_ipv4(listen_addr()));
	}

	poke_le16(payload, socket_listen_port());

	/*
	 * Reply with a control message, so that the issuer knows that we can
	 * proxify pushes to it ASAP.
	 */

	vmsg_ctrl_send_data(n, v_tmp, msgsize);
}

/**
 * Handle reception of the "Push Proxy Request" message.
 */
static void
handle_proxy_req(struct gnutella_node *n,
	const struct vmsg *vmsg, const char *unused_payload, size_t unused_size)
{
	(void) unused_payload;
	(void) unused_size;

	/*
	 * This message is only meaningful from TCP.
	 */

	if (!vmsg_from_tcp(n, vmsg))
		return;

	/*
	 * Normally, a firewalled host should be a leaf node, not an UP.
	 * Warn if node is not a leaf, but accept to be the push proxy
	 * nonetheless.
	 */

	if (!NODE_IS_LEAF(n)) {
		g_warning("got %s from non-leaf node %s <%s> over %s",
			vmsg->name, node_addr(n), node_vendor(n),
			NODE_IS_UDP(n) ? "UDP" : "TCP");
	}

	/*
	 * Add proxying info for this node.  On successful completion,
	 * we'll send an acknowledgement.
	 *
	 * We always use version 2 to reply, see comment in vmsg_send_proxy_req().
	 */

	if (node_proxying_add(n, gnutella_header_get_muid(&n->header))) {
		/* MUID is the node's GUID */
		vmsg_send_proxy_ack(n, gnutella_header_get_muid(&n->header), 2);
	}
}

/**
 * Send a "Push Proxy Request" message to specified node, using supplied
 * `muid' as the message ID (which is our GUID).
 */
void
vmsg_send_proxy_req(struct gnutella_node *n, const struct guid *muid)
{
	uint32 msgsize;

	g_assert(!NODE_IS_LEAF(n));

	msgsize = vmsg_fill_header(v_tmp_header, 0, sizeof v_tmp);
	gnutella_header_set_muid(v_tmp_header, muid);

	/*
	 * LimeWire only supports version 1 of the Push Proxy Request but will
	 * send a Push Proxy Ack at version 2.  They did not think that people
	 * would be using the version of the request message to indicate the
	 * level of support for the acknowledgement.
	 *
	 * So from now on, stick to sending version 1, and always reply with
	 * version 2, regardless of what they send us, thereby mimicking their
	 * (broken) behaviour.  Nowadays, everybody should support the version 2
	 * of the acknowledgement anyway.
	 *		--RAM, 2009-10-30
	 */

	(void) vmsg_fill_type(v_tmp_data, T_LIME, 21, 1);

	vmsg_send_data(n, v_tmp, msgsize);
}

/**
 * Handle reception of the "Push Proxy Acknowledgment" message.
 *
 * Version 1 only bears the port.  The IP address must be gathered from n->addr.
 * Version 2 holds both the IP and port of our push-proxy.
 */
static void
handle_proxy_ack(struct gnutella_node *n,
	const struct vmsg *vmsg, const char *payload, size_t size)
{
	host_addr_t ha;
	uint16 port;

	if (VMSG_SHORT_SIZE(n, vmsg, size, vmsg->version < 2 ? 2 : 6))
		return;

	if (vmsg->version >= 2) {
		ha = host_addr_peek_ipv4(payload);
		payload += 4;
	} else {
		ha = n->addr;
	}

	port = peek_le16(payload);

	if (GNET_PROPERTY(vmsg_debug) > 2) {
		g_debug("VMSG got proxy ACK v%u from %s: proxy at %s",
			vmsg->version,
			node_infostr(n), host_addr_port_to_string(ha, port));
	}

	if (!host_is_valid(ha, port)) {
		g_warning("got improper address %s in %s from %s",
			host_addr_port_to_string(ha, port), vmsg->name, node_infostr(n));
		return;
	}
	if (hostiles_is_bad(ha)) {
		hostiles_flags_t flags = hostiles_check(ha);
		g_message("VMSG ignoring proxy ACK from hostile %s (%s): proxy at %s",
			node_infostr(n), hostiles_flags_to_string(flags),
			host_addr_port_to_string(ha, port));
		return;
	}

	node_proxy_add(n, ha, port);
}

/**
 * Handle reception of "Query Status Request", where the UP requests how
 * many results the search filters of the leave (ourselves) let pass through.
 */
static void
handle_qstat_req(struct gnutella_node *n, const struct vmsg *vmsg,
	const char *unused_payload, size_t unused_size)
{
	uint32 kept;
	const struct guid *muid = gnutella_header_get_muid(&n->header);

	(void) unused_payload;
	(void) unused_size;

	/*
	 * Ignore servents requesting the status of our queries via UDP.
	 * This is only supposed to happen via TCP (from our ultra peer).
	 */

	if (!vmsg_from_tcp(n, vmsg))
		return;

	if (!search_get_kept_results_by_muid(muid, &kept)) {
		/*
		 * We did not find any search for this MUID.  Either the remote
		 * side goofed, or they closed the search.
		 */

		if (GNET_PROPERTY(vmsg_debug)) {
			g_warning("VMSG could not find matching search for #%s",
				guid_hex_str(muid));
		}
		kept = 0xffffU;		/* Magic value telling them to stop the search */
	} else {
		/*
		 * If we've started running a GUESS query for this search, there's
		 * no need for our ultrapeer to continue running the dynamic query
		 * for us.
		 */

		if (search_running_guess(muid))
			kept = 0xffffU;	/* Magic value telling them to stop the search */
		else
			kept = MIN(kept, 0xfffeU);
	}

	vmsg_send_qstat_answer(n, muid, kept);
}

/**
 * Send a "Query Status Request" message to specified node, using supplied
 * `muid' as the message ID (which is the query ID).
 */
void
vmsg_send_qstat_req(struct gnutella_node *n, const struct guid *muid)
{
	uint32 msgsize;

	g_assert(!NODE_IS_UDP(n));	/* Can only be sent via TCP from UP -> leaf */

	msgsize = vmsg_fill_header(v_tmp_header, 0, sizeof v_tmp);
	gnutella_header_set_muid(v_tmp_header, muid);
	(void) vmsg_fill_type(v_tmp_data, T_BEAR, 11, 1);

	vmsg_ctrl_send_data(n, v_tmp, msgsize);	/* Send ASAP */
}

/**
 * Handle "Query Status Response" where the leave notifies us about the
 * amount of results its search filters let pass through for the specified
 * query.
 */
static void
handle_qstat_answer(struct gnutella_node *n,
	const struct vmsg *vmsg, const char *payload, size_t size)
{
	uint16 kept;

	if (VMSG_SHORT_SIZE(n, vmsg, size, 2))
		return;

	/*
	 * Let the dynamic querying side about the reply.
	 */

	kept = peek_le16(payload);
	dq_got_query_status(gnutella_header_get_muid(&n->header), NODE_ID(n), kept);
}

/**
 * Send a "Query Status Response" message to specified node.
 *
 * @param n the Gnutella node to sent the message to
 * @param muid is the query ID
 * @param hits is the number of hits our filters did not drop.
 */
void
vmsg_send_qstat_answer(struct gnutella_node *n,
	const struct guid *muid, uint16 hits)
{
	uint32 msgsize;
	uint32 paysize = sizeof(uint16);
	char *payload;

	msgsize = vmsg_fill_header(v_tmp_header, paysize, sizeof v_tmp);
	gnutella_header_set_muid(v_tmp_header, muid);
	payload = vmsg_fill_type(v_tmp_data, T_BEAR, 12, 1);

	poke_le16(payload, hits);

	gmsg_ctrl_sendto_one(n, v_tmp, msgsize);	/* Send it ASAP */

	if (GNET_PROPERTY(vmsg_debug) > 2 || GNET_PROPERTY(log_vmsg_tx)) {
		g_debug("VMSG sent %s with hits=%u to %s",
			gmsg_infostr_full(v_tmp, msgsize), hits, node_infostr(n));
	}
}

/**
 * Handle reception of "Push Proxy Cancel" request, when remote node no longer
 * wishes to have us as a push-proxy.  This is an indication that the host
 * determined it was not TCP-firewalled.
 */
static void
handle_proxy_cancel(struct gnutella_node *n, const struct vmsg *unused_vmsg,
	const char *unused_payload, size_t unused_size)
{
	(void) unused_vmsg;
	(void) unused_payload;
	(void) unused_size;

	node_proxying_remove(n);
}

/**
 * Send a "Push Proxy Cancel" message to specified node.
 */
void
vmsg_send_proxy_cancel(struct gnutella_node *n)
{
	uint32 msgsize;

	msgsize = vmsg_fill_header(v_tmp_header, 0, sizeof v_tmp);
	gnutella_header_set_muid(v_tmp_header, &blank_guid);
	(void) vmsg_fill_type(v_tmp_data, T_GTKG, 21, 1);

	vmsg_send_data(n, v_tmp, msgsize);
}

/**
 * Handle reception of an "OOB Reply Indication" message, whereby the remote
 * host informs us about the amount of query hits it has for us for a
 * given query.  The message bears the MUID of the query we sent out.
 */
static void
handle_oob_reply_ind(struct gnutella_node *n,
	const struct vmsg *vmsg, const char *payload, size_t size)
{
	bool can_recv_unsolicited = FALSE;
	size_t expected_size;
	bool secure;
	int hits;

	/*
	 * We only expect LIME/12 messages from UDP.
	 */

	if (!vmsg_from_udp(n, vmsg))
		return;

	switch (vmsg->version) {
	case 1:
		expected_size = 1;
		break;
	case 2:
	case 3:
		expected_size = 2;
		break;
	default:
		goto not_handling;
	}

	if (VMSG_SHORT_SIZE(n, vmsg, size, expected_size))
		goto not_handling;

	hits = peek_u8(payload);
	if (hits == 0) {
		if (GNET_PROPERTY(vmsg_debug)) {
			g_warning("no results advertised in %s/%uv%u from %s",
				vendor_code_to_string(vmsg->vendor),
				vmsg->id, vmsg->version, node_infostr(n));
		}
		goto not_handling;
	}

	secure = vmsg->version > 2;
	can_recv_unsolicited = vmsg->version > 1 && peek_u8(&payload[1]) & 0x1;

	search_oob_pending_results(n, gnutella_header_get_muid(&n->header),
		hits, can_recv_unsolicited, secure);
	return;

not_handling:
	if (GNET_PROPERTY(vmsg_debug)) {
		g_warning("not handling %s/%uv%u from %s",
			vendor_code_to_string(vmsg->vendor),
			vmsg->id, vmsg->version, node_infostr(n));
	}
}

/**
 * Build an "OOB Reply Indication" message.
 *
 * @param muid is the query ID.
 * @param hits is the number of hits we have to deliver for that query.
 * @param secure TRUE -> secure OOB; FALSE -> normal OOB.
 */
pmsg_t *
vmsg_build_oob_reply_ind(const struct guid *muid, uint8 hits, bool secure)
{
	uint32 msgsize;
	uint32 paysize = sizeof(uint8) + sizeof(uint8);
	char *payload;

	g_assert(muid);

	msgsize = vmsg_fill_header(v_tmp_header, paysize, sizeof v_tmp);
	gnutella_header_set_muid(v_tmp_header, muid);
	payload = vmsg_fill_type(v_tmp_data, T_LIME, 12, secure ? 3 : 2);

	payload[0] = hits;
	payload[1] = GNET_PROPERTY(is_udp_firewalled) ? 0x0 : 0x1;

	/*
	 * The "OOB Reply Indication" (LIME/12) is now sent as a control message.
	 * We want to get this out to the querying host quickly and ahead of
	 * other less prioritary UDP traffic, especially if bandwidth is tight.
	 *		--RAM, 2012-09-16
	 */

	return gmsg_to_ctrl_pmsg(v_tmp, msgsize);
}

#define MAX_OOB_TOKEN_SIZE 16

static struct array
extract_token(const char *data, size_t size, char token[MAX_OOB_TOKEN_SIZE])
{
	extvec_t exv[MAX_EXTVEC];
	int i, exvcnt;
	size_t token_size = 0;

	ext_prepare(exv, MAX_EXTVEC);
	exvcnt = ext_parse(data, size, exv, MAX_EXTVEC);

	for (i = 0; i < exvcnt; i++) {
		const extvec_t *e = &exv[i];

		if (EXT_T_GGEP_SO == e->ext_token) {
			size_t len = ext_paylen(e);

			if (len < 1) {
				if (GNET_PROPERTY(vmsg_debug))
					g_warning("empty GGEP \"SO\"");
			} else if (len > MAX_OOB_TOKEN_SIZE) {
				if (GNET_PROPERTY(vmsg_debug))
					g_warning("GGEP \"SO\" too large");
				len = MAX_OOB_TOKEN_SIZE;	/* truncate it */
			}
			if (len > 0 && len <= MAX_OOB_TOKEN_SIZE) {
				memcpy(token, ext_payload(e), MAX_OOB_TOKEN_SIZE);
				token_size = len;
			}
			break;
		}
	}
	if (exvcnt) {
		ext_reset(exv, MAX_EXTVEC);
	}	
	return token_size > 0 ? array_init(token, token_size) : zero_array;
}

/**
 * Handle reception of an "OOB Reply Ack" message, whereby the remote
 * host informs us about the amount of query hits it wants delivered
 * for the query identified by the MUID of the message.
 */
static void
handle_oob_reply_ack(struct gnutella_node *n,
	const struct vmsg *vmsg, const char *payload, size_t size)
{
	char token_data[MAX_OOB_TOKEN_SIZE];
	struct array token;
	int wanted;

	if (VMSG_SHORT_SIZE(n, vmsg, size, 1))
		return;

	/*
	 * We expect those ACKs to come back via UDP.
	 */

	if (!vmsg_from_udp(n, vmsg))
		return;

	wanted = peek_u8(&payload[0]);

	if (vmsg->version > 2 && size > 1) {
		token = extract_token(&payload[1], size - 1, token_data);
	} else {
		token = zero_array;
	}

	oob_deliver_hits(n, gnutella_header_get_muid(&n->header), wanted, &token);
}

/**
 * Node does not want us to OOB-proxy its queries.
 */
static void
handle_oob_proxy_veto(struct gnutella_node *n,
	const struct vmsg *vmsg, const char *payload, size_t size)
{
	if (!vmsg_from_tcp(n, vmsg))
		return;

	if (!NODE_IS_LEAF(n)) {
		vmsg_ignore(n, vmsg);
		return;
	}

	if (size > 0 && peek_u8(payload) < 3) {
		/* we support OOB v3 */
		n->attrs2 &= ~NODE_A2_NO_OOB_PROXY;
	} else {
		n->attrs2 |= NODE_A2_NO_OOB_PROXY;
	}

	return;
}

/**
 * Send an "OOB Reply Ack" message to specified node, informing it that
 * we want the specified amount of hits delivered for the query identified
 * by the MUID of the message we got (the "OOB Reply Indication").
 *
 * We signal that we support "deflated UDP", so that remote servent can
 * compress the query hits if necessary and if supported.
 */
void
vmsg_send_oob_reply_ack(struct gnutella_node *n,
	const struct guid *muid, uint8 want, const struct array *token)
{
	uint32 msgsize;
	uint32 paysize = sizeof(uint8);
	char *payload;

	g_assert(NODE_IS_UDP(n));
	g_assert(token);

	payload = vmsg_fill_type(v_tmp_data, T_LIME, 11, token->data ? 3 : 2);
	payload[0] = want;

	if (token->data) {
		ggep_stream_t gs;

		ggep_stream_init(&gs, &payload[paysize], sizeof v_tmp - paysize);
		ggep_stream_pack(&gs, GGEP_NAME(SO), token->data, token->size, 0);
		paysize += ggep_stream_close(&gs);
	}

	msgsize = vmsg_fill_header(v_tmp_header, paysize, sizeof v_tmp);
	vmsg_advertise_udp_compression(v_tmp_header);	/* Can deflate UDP */
	gnutella_header_set_muid(v_tmp_header, muid);

	/*
	 * The "OOB Reply ACK" message (LIME/11) is now sent as a control message.
	 * We want to get this out to the replying host quickly and ahead of
	 * other less prioritary UDP traffic, especially if bandwidth is tight,
	 * minimizing the chances of it being dropped.
	 *		--RAM, 2012-09-23
	 */

	udp_ctrl_send_msg(n, v_tmp, msgsize);

	if (
		GNET_PROPERTY(vmsg_debug) > 2 ||
		GNET_PROPERTY(secure_oob_debug) ||
		GNET_PROPERTY(log_vmsg_tx)
	) {
		char buf[17];
		if (token->data)
			bin_to_hex_buf(token->data, token->size, buf, sizeof buf);
		g_debug("VMSG sent %s to %s for %u hit%s%s%s",
			gmsg_infostr_full(v_tmp, msgsize),
			node_infostr(n), want, plural(want),
			token->data ? ", token=0x" : "", token->data ? buf : "");
	}
}

/**
 * Handle reception of a "Time Sync Request" message, indicating a request
 * from another host about time synchronization.
 */
static void
handle_time_sync_req(struct gnutella_node *n,
	const struct vmsg *vmsg, const char *unused_payload, size_t size)
{
	tm_t got;

	(void) unused_payload;

	if (VMSG_SHORT_SIZE(n, vmsg, size, 1))
		return;

	if (node_udp_is_old(n)) {
		gnet_stats_count_dropped(n, MSG_DROP_TOO_OLD);
		return;
	}

	/*
	 * We have received the message well before, but this is the first
	 * time we can timestamp it really...  We're not NTP, so the precision
	 * is not really necessary as long as we stay beneath a second, which
	 * we should.
	 */

	tm_now_exact(&got);			/* Mark when we got the message */
	got.tv_sec = clock_loc2gmt(got.tv_sec);

	tsync_got_request(n, &got);
}

/**
 * Handle reception of a "Time Sync Reply" message, holding the reply from
 * a previous time synchronization request.
 */
static void
handle_time_sync_reply(struct gnutella_node *n,
	const struct vmsg *vmsg, const char *payload, size_t size)
{
	tm_t got, sent, replied, received;
	const struct guid *muid;
	bool ntp;

	if (VMSG_SHORT_SIZE(n, vmsg, size, 9))
		return;

	tm_now_exact(&got);			/* Mark when we got (to see) the message */
	got.tv_sec = clock_loc2gmt(got.tv_sec);

	ntp = peek_u8(payload) & 0x1;

	/*
	 * Decompile send time.
	 */

	STATIC_ASSERT(sizeof(sent) >= 2 * sizeof(uint32));

	muid = gnutella_header_get_muid(&n->header);
	sent.tv_sec = peek_be32(&muid->v[0]);
	sent.tv_usec = peek_be32(&muid->v[4]);

	/*
	 * Decompile replied time.
	 */

	replied.tv_sec = peek_be32(&muid->v[8]);
	replied.tv_usec = peek_be32(&muid->v[12]);

	/*
	 * Decompile the time at which they got the message.
	 */

	received.tv_sec = peek_be32(&payload[1]);
	received.tv_usec = peek_be32(&payload[5]);

	tsync_got_reply(n, &sent, &received, &replied, &got, ntp);
}

/**
 * Callback invoked when "Time Sync Request" is about to be sent.
 * Writes current time in the first half of the MUID.
 */
static bool
vmsg_time_sync_req_stamp(const pmsg_t *mb, const void *unused_q)
{
	struct guid *muid = cast_to_guid_ptr(pmsg_start(mb));
	tm_t old, now;

	(void) unused_q;
	g_assert(pmsg_is_writable(mb));
	STATIC_ASSERT(sizeof(now) >= 2 * sizeof(uint32));

	/*
	 * Read the old timestamp.
	 */

	old.tv_sec = peek_be32(&muid->v[0]);
	old.tv_usec = peek_be32(&muid->v[4]);

	tm_now_exact(&now);
	now.tv_sec = clock_loc2gmt(now.tv_sec);

	poke_be32(&muid->v[0], now.tv_sec);
	poke_be32(&muid->v[4], now.tv_usec);

	/*
	 * Inform the tsync layer that the "T1" timestamp is not the one
	 * we registered in vmsg_send_time_sync_req().  Tagging via the
	 * timestamp is the only mean we have to update the records since we
	 * can't attach metadata to the "pre-send" callbacks, hence the need
	 * to pass both the old and the new timestamps.
	 */

	tsync_send_timestamp(&old, &now);

	return TRUE;
}

/**
 * Same as vmsg_time_sync_req_stamp() but for UDP messages.
 */
static bool
vmsg_time_sync_req_stamp_udp(const pmsg_t *mb)
{
	return vmsg_time_sync_req_stamp(mb, NULL);
}

/**
 * Send a "Time Sync Request" message, asking them to echo back their own
 * time so that we can compute our clock differences and measure round trip
 * times.  The time at which we send the message is included in the first
 * half of the MUID.
 *
 * If the node is an UDP node, its IP and port indicate to whom we shall
 * send the message.
 *
 * The `sent' parameter holds the initial "T1" timestamp markup.
 */
void
vmsg_send_time_sync_req(struct gnutella_node *n, bool ntp, tm_t *sent)
{
	uint32 msgsize;
	uint32 paysize = sizeof(uint8);
	char *payload;
	struct guid *muid;
	pmsg_t *mb;

	if (!NODE_IS_WRITABLE(n))
		return;

	msgsize = vmsg_fill_header(v_tmp_header, paysize, sizeof v_tmp);
	payload = vmsg_fill_type(v_tmp_data, T_GTKG, 9, 1);
	*payload = ntp ? 0x1 : 0x0;				/* bit0 indicates NTP */

	mb = gmsg_to_ctrl_pmsg(v_tmp, msgsize);	/* Send as quickly as possible */
	muid = cast_to_guid_ptr(pmsg_start(mb));

	/*
	 * The first 8 bytes of the MUID are used to store the time at which
	 * we send the message, and we fill that as late as possible.  We write
	 * the current time now, because we have to return it to the caller,
	 * but it will be superseded when the message is finally scheduled to
	 * be sent by the queue.
	 *
	 * For UDP destinations, we install a hook check instead of a plain check
	 * because the UDP TX scheduler can enqueue underneath the UDP message
	 * queue and we want the timestamp to be written as late as possible.
	 * Plain checks are invoked by the message queue whilst hooks are invoked
	 * at the UDP TX scheduler level.
	 *		--RAM, 2012-10-11
	 */

	if (NODE_IS_UDP(n))
		pmsg_set_hook(mb, vmsg_time_sync_req_stamp_udp);
	else
		pmsg_set_check(mb, vmsg_time_sync_req_stamp);

	poke_be32(&muid->v[0], sent->tv_sec);
	poke_be32(&muid->v[4], sent->tv_usec);

	vmsg_send_reply(n, mb);
}

/**
 * Callback invoked when "Time Sync Reply" is about to be sent.
 * Writes current time in the second half of the MUID.
 */
static bool
vmsg_time_sync_reply_stamp(const pmsg_t *mb, const void *unused_q)
{
	struct guid *muid = cast_to_guid_ptr(pmsg_start(mb));
	tm_t now;

	(void) unused_q;
	g_assert(pmsg_is_writable(mb));
	STATIC_ASSERT(sizeof(now) >= 2 * sizeof(uint32));

	tm_now_exact(&now);
	now.tv_sec = clock_loc2gmt(now.tv_sec);

	poke_be32(&muid->v[8], now.tv_sec);	/* Second half of MUID */
	poke_be32(&muid->v[12], now.tv_usec);

	return TRUE;
}

/**
 * Send a "Time Sync Reply" message to the node, including the time at
 * which we send back the message in the second half of the MUID.
 * The time in `got' is the time at which we received their request.
 */
void
vmsg_send_time_sync_reply(struct gnutella_node *n, bool ntp, tm_t *got)
{
	uint32 msgsize;
	uint32 paysize = sizeof(uint8) + 2 * sizeof(uint32);
	char *payload;
	char *muid;
	pmsg_t *mb;

	if (!NODE_IS_WRITABLE(n))
		return;

	msgsize = vmsg_fill_header(v_tmp_header, paysize, sizeof v_tmp);
	payload = vmsg_fill_type(v_tmp_data, T_GTKG, 10, 1);

	payload = poke_u8(payload, ntp ? 0x1 : 0x0);	/* bit 0 indicates NTP */

	/*
	 * Write time at which we got their message, so they can substract
	 * the processing time from the computation of the round-trip time.
	 */

	payload = poke_be32(payload, got->tv_sec);
	payload = poke_be32(payload, got->tv_usec);

	mb = gmsg_to_ctrl_pmsg(v_tmp, msgsize);	/* Send as quickly as possible */
	muid = pmsg_start(mb);					/* MUID of the reply */

	/*
	 * Propagate first half of the MUID, which is the time at which
	 * they sent us the message in their clock time, into the reply's MUID
	 *
	 * The second 8 bytes of the MUID are used to store the time at which
	 * we send the message, and we fill that as late as possible, i.e.
	 * when we are about to send the message.
	 */

	/* First half of MUID */
	memcpy(muid, gnutella_header_get_muid(&n->header), 8);

	pmsg_set_check(mb, vmsg_time_sync_reply_stamp);

	vmsg_send_reply(n, mb);
}

/**
 * Handle reception of an UDP crawler ping.
 */
static void
handle_udp_crawler_ping(struct gnutella_node *n,
	const struct vmsg *vmsg, const char *payload, size_t size)
{
	uint8 number_up;
	uint8 number_leaves;
	uint8 features;

	/*
	 * We expect those messages to come via UDP.
	 */

	if (!vmsg_from_udp(n, vmsg))
		return;

	/*
	 * The format of the message was reverse-engineered from LimeWire's code.
	 * The version 1 message is claimed to be forward compatible with future
	 * versions, meaning the first 3 bytes will remain in newer versions.
	 *
	 * The payload is made of 3 bytes:
	 *
	 *   number_up: 	the # of UP they want to know about (255 means ALL)
	 *   number_leaves: the # of leaves they want to know about (255 means ALL)
	 *	 features:		some flags defining what to return
	 *					0x1 - connection time, in minutes
	 *					0x2 - locale info (2-letter language code)
	 *					0x4 - "new" peers only (supporting this LIME/5 message)
	 *					0x8 - user agent of peers, separated by ";" and deflated
	 *
	 * Upon reception of this message, an "UDP Crawler Pong" (LIME/6v1) is built
	 * and sent back to the requester.
	 */

	if (vmsg->version == 1 && VMSG_SHORT_SIZE(n, vmsg, size, 3))
		return;

	number_up = peek_u8(&payload[0]);
	number_leaves = peek_u8(&payload[1]);
	features = peek_u8(&payload[2]) & NODE_CR_MASK;

	node_crawl(n, number_up, number_leaves, features);
}

/**
 * Send UDP crawler pong, in reply to their ping.
 * The supplied message block contains the payload to send back.
 */
void
vmsg_send_udp_crawler_pong(struct gnutella_node *n, pmsg_t *mb)
{
	uint32 msgsize;
	uint32 paysize = pmsg_size(mb);
	char *payload;

	g_assert(NODE_IS_UDP(n));

	msgsize = vmsg_fill_header(v_tmp_header, paysize, sizeof v_tmp);
	payload = vmsg_fill_type(v_tmp_data, T_LIME, 6, 1);
	/* Propagate MUID */
	gnutella_header_set_muid(v_tmp_header,
		gnutella_header_get_muid(&n->header));

	memcpy(payload, pmsg_start(mb), paysize);

	udp_send_msg(n, v_tmp, msgsize);

	if (GNET_PROPERTY(vmsg_debug) > 2 || GNET_PROPERTY(log_vmsg_tx)) {
		uint8 nup = peek_u8(&payload[0]);
		uint8 nleaves = peek_u8(&payload[1]);

		g_debug("VMSG sent %s with up=%u and leaves=%u to %s",
			gmsg_infostr_full(v_tmp, msgsize), nup, nleaves, node_infostr(n));
	}
}

/**
 * Handle reception of a Node Info Request -- GTKG/22v1
 *
 * This messsage is a request for internal Gnutella connectivity information.
 * It must be replied with an urgent GTKG/23v1 "Node Info Reply" message.
 */
static void
handle_node_info_req(struct gnutella_node *n,
	const struct vmsg *vmsg, const char *payload, size_t size)
{
	if (VMSG_SHORT_SIZE(n, vmsg, size, 4))
		return;

	if (node_udp_is_old(n)) {
		gnet_stats_count_dropped(n, MSG_DROP_TOO_OLD);
		return;
	}

	/* XXX */
	(void) payload;
}

/**
 * Send a "Node Info Reply" -- GTKG/23v1
 *
 * The message is constructed from the rnode_info_t structure which contains
 * everything we have to send back.  Since we're replying to a "Node Info Req"
 * message, we have the GUID of that message in the node's header.
 *
 * @param n		the node to which the message should be sent
 * @param ri	the node information we have to format and send back
 */
void
vmsg_send_node_info_ans(struct gnutella_node *n, const rnode_info_t *ri)
{
	uint32 msgsize;
	uint32 paysize;
	ggep_stream_t gs;
	int ggep_len;
	char *payload, *p;
	char *payload_end = &v_tmp[sizeof v_tmp];	/* First byte beyond buffer */
	uint i;

	payload = vmsg_fill_type(v_tmp_data, T_GTKG, 23, 1);
	p = payload;

	/*
	 * We'll assert at the end that we have not overflown the data segment
	 * we've been given to construct the message.
	 */

	/* General information always returned */

	for (i = 0; i < G_N_ELEMENTS(ri->vendor); i++)
		p = poke_u8(p, ri->vendor[i]);

	p = poke_u8(p, ri->mode);
	p = poke_be32(p, ri->answer_flags);
	p = poke_be32(p, ri->op_flags);
	p = poke_u8(p, G_N_ELEMENTS(ri->features));

	g_assert(ri->features_count == G_N_ELEMENTS(ri->features));

	for (i = 0; i < G_N_ELEMENTS(ri->features); i++)
		p = poke_be32(p, ri->features[i]);

	p = poke_u8(p, ri->max_ultra_up);
	p = poke_u8(p, ri->max_ultra_lf);
	p = poke_u8(p, ri->ultra_count);

	p = poke_be16(p, ri->max_leaves);
	p = poke_be16(p, ri->leaf_count);

	p = poke_u8(p, ri->ttl);
	p = poke_u8(p, ri->hard_ttl);

	p = poke_be32(p, ri->startup_time);
	p = poke_be32(p, ri->ip_change_time);

	g_assert(p - payload == 31 + 4 * ri->features_count);

	/* Conditional -- bandwidth information */

	if (ri->answer_flags & RNODE_RQ_BW_INFO) {
		p = poke_be16(p, ri->bw_flags);
		p = poke_be32(p, ri->gnet_bw_in);
		p = poke_be32(p, ri->gnet_bw_out);
		p = poke_be32(p, ri->gnet_bwl_in);
		p = poke_be32(p, ri->gnet_bwl_out);
	}

	/* Conditional -- dropped packets */

	if (ri->answer_flags & RNODE_RQ_DROP_INFO) {
		p = poke_be32(p, ri->tx_dropped);
		p = poke_be32(p, ri->rx_dropped);
	}

	/* Conditional - query hit statistics */

	if (ri->answer_flags & RNODE_RQ_QHIT_INFO) {
		p = poke_be16(p, ri->results_max);
		p = poke_be32(p, ri->file_hits);
		p = poke_be32(p, ri->qhits_tcp);
		p = poke_be32(p, ri->qhits_udp);
		p = poke_be64(p, ri->qhits_tcp_bytes);
		p = poke_be64(p, ri->qhits_udp_bytes);
	}

	/* Conditional -- CPU usage */

	if (ri->answer_flags & RNODE_RQ_CPU_INFO) {
		p = poke_be64(p, ri->cpu_usr);
		p = poke_be64(p, ri->cpu_sys);
	}

	/*
	 * GGEP blocks
	 */

	ggep_stream_init(&gs, p, payload_end - p);

	if (ri->answer_flags & RNODE_RQ_GGEP_DU) {
		char uptime[sizeof(uint64)];
		uint len;

		len = ggept_du_encode(ri->ggep_du, uptime, sizeof uptime);
		ggep_stream_pack(&gs, GGEP_NAME(DU), uptime, len, 0);
	}

	if (ri->answer_flags & RNODE_RQ_GGEP_LOC) {
		/* XXX -- NOT SUPPORTED */
	}

	if (ri->answer_flags & RNODE_RQ_GGEP_IPV6) {
		g_assert(is_host_addr(ri->ggep_ipv6));

		ggep_stream_pack(&gs, GGEP_NAME(6),
			host_addr_ipv6(&ri->ggep_ipv6), 16, 0);
	}

	if (ri->answer_flags & RNODE_RQ_GGEP_UA) {
		ggep_stream_pack(&gs, GGEP_NAME(UA), ri->ggep_ua,
			strlen(ri->ggep_ua), GGEP_W_DEFLATE);
	}

	if (ri->answer_flags & RNODE_RQ_GGEP_GGEP) {
		/* XXX */
	}

	if (ri->answer_flags & RNODE_RQ_GGEP_VMSG) {
		/* XXX */
	}

	ggep_len = ggep_stream_close(&gs);

	(void) ggep_len;	/* XXX code not finished, do we need this variable? */

	/*
	 * Now that the message has been fully generated, we know its size and
	 * can fill in the header.
	 */

	paysize = p - payload;
	msgsize = vmsg_fill_header(v_tmp_header, paysize, sizeof v_tmp);
	gnutella_header_set_muid(v_tmp_header,
		gnutella_header_get_muid(&n->header));

	/*
	 * Message is sent back over TCP as a prioritary one (put ahead of the
	 * queue, much like "alive" pongs).
	 */

	vmsg_ctrl_send_data(n, v_tmp, msgsize);
}

/**
 * Handle reception of a Node Info Reply -- GTKG/23v1
 *
 * This messsage is sent in reply to a GTKG/22v1 "Node Info Request".
 */
static void
handle_node_info_ans(struct gnutella_node *n,
	const struct vmsg *vmsg, const char *payload, size_t size)
{
	if (VMSG_SHORT_SIZE(n, vmsg, size, 20))
		return;

	/* TODO: Implement this */
	(void) payload;
}

static struct {
	size_t size;
	char data[256];
} svn_release_signature;

static bool
latest_svn_release_changed(property_t prop)
{
	char data[sizeof svn_release_signature.data], hex[sizeof data * 2 + 1];
	size_t data_length, hex_length;

	(void) prop;

	svn_release_signature.size = 0;
	if (!svn_release_notification_can_verify())
		return FALSE;

	gnet_prop_get_string(PROP_LATEST_SVN_RELEASE_SIGNATURE, hex, sizeof hex);
	hex_length = strlen(hex);
	if (hex_length > 0 && hex_length / 2 < sizeof data) {
		struct array signature;
		uint32 revision;
		time_t date;

		data_length = base16_decode(data, sizeof data, hex, hex_length);
		revision = GNET_PROPERTY(latest_svn_release_revision);
		date = GNET_PROPERTY(latest_svn_release_date);
		signature = array_init(data, data_length);

		if (svn_release_notification_verify(revision, date, &signature)) {
			g_message("VMSG SVN release notify signature is valid: r%u (%s)",
				revision, timestamp_to_string(date));

			memcpy(svn_release_signature.data, data, data_length);
			svn_release_signature.size = data_length;
		}
	}
	return FALSE;
}

static bool
svn_release_signature_is_valid(void)
{
	static bool initialized;

	if (!initialized) {
		initialized = TRUE;
		
		gnet_prop_add_prop_changed_listener(PROP_LATEST_SVN_RELEASE_REVISION,
			latest_svn_release_changed, FALSE);
		gnet_prop_add_prop_changed_listener(PROP_LATEST_SVN_RELEASE_DATE,
			latest_svn_release_changed, FALSE);
		gnet_prop_add_prop_changed_listener(PROP_LATEST_SVN_RELEASE_SIGNATURE,
			latest_svn_release_changed, TRUE);
	}
	return svn_release_signature.size > 0;
}

static void
vmsg_send_svn_release_notify(struct gnutella_node *n)
{
	uint32 msgsize;
	uint32 paysize;
	char *payload, *end;

	g_return_if_fail(!NODE_IS_UDP(n));	

	if (!(NODE_A_CAN_SVN_NOTIFY & n->attrs))
		return;

	if (!svn_release_signature_is_valid())
		return;

	if (n->svn_release_revision >= GNET_PROPERTY(latest_svn_release_revision))
		return;

	n->svn_release_revision = GNET_PROPERTY(latest_svn_release_revision);
	
	payload = vmsg_fill_type(v_tmp_data, T_GTKG, 24, 1);
	end = poke_be32(payload, GNET_PROPERTY(latest_svn_release_revision));
	end = poke_be32(end, GNET_PROPERTY(latest_svn_release_date));
	end = mempcpy(end, svn_release_signature.data, svn_release_signature.size);
	paysize = ptr_diff(end, payload);

	msgsize = vmsg_fill_header(v_tmp_header, paysize, sizeof v_tmp);
	message_set_muid(v_tmp_header, GTA_MSG_VENDOR);
	vmsg_send_data(n, v_tmp, msgsize);
}

static void
handle_svn_release_notify(struct gnutella_node *n,
	const struct vmsg *vmsg, const char *payload, size_t size)
{
	struct array signature;
	uint32 revision;
	time_t date;

	if (NODE_IS_UDP(n))
		return;
	
	if (VMSG_SHORT_SIZE(n, vmsg, size, 16))
		return;

	if (!svn_release_notification_can_verify())
		return;

	signature = array_init(&payload[8], size - 8);

	revision = peek_be32(&payload[0]);
	date = peek_be32(&payload[4]);

	if (revision <= GNET_PROPERTY(latest_svn_release_revision))
		return;

	n->svn_release_revision = revision;

	if (svn_release_notification_verify(revision, date, &signature)) {
		size_t hex_length;
		char *hex;

		hex_length = signature.size * 2;
		hex = g_malloc(hex_length + 1);
		base16_encode(hex, hex_length, signature.data, signature.size);
		hex[hex_length] = '\0';
		
		gnet_prop_set_guint32_val(PROP_LATEST_SVN_RELEASE_REVISION, revision);
		gnet_prop_set_timestamp_val(PROP_LATEST_SVN_RELEASE_DATE, date);
		gnet_prop_set_string(PROP_LATEST_SVN_RELEASE_SIGNATURE, hex);
		G_FREE_NULL(hex);
	} else {
		g_message("VMSG BAD %s v%u from %s (TTL=%u, hops=%u, size=%zu)",
			vmsg->name,
			vmsg->version,
			node_infostr(n),
			gnutella_header_get_ttl(n->header),
			gnutella_header_get_hops(n->header),
			size);
	}
}

enum {
	VMSG_HEAD_F_TLS			= 1 << 0,	/* HEAD Pong v2; TLS capable */

	VMSG_HEAD_F_RANGES		= 1 << 0,
	VMSG_HEAD_F_ALT			= 1 << 1,
	VMSG_HEAD_F_ALT_PUSH	= 1 << 2,
	VMSG_HEAD_F_RUDP		= 1 << 3,
	VMSG_HEAD_F_GGEP		= 1 << 4,
	VMSG_HEAD_F_IPV6		= 1 << 5,	/* Can understand IPv6 addresses */
	VMSG_HEAD_F_IPV6_ONLY	= 1 << 6,	/* Does not want any IPv4 address */

	VMSG_HEAD_F_MASK		= 0x1f
};

enum {
	VMSG_HEAD_CODE_NOT_FOUND	= 0,
	VMSG_HEAD_CODE_COMPLETE		= 1 << 0,
	VMSG_HEAD_CODE_PARTIAL		= 1 << 1,

	VMSG_HEAD_STATUS_FIREWALLED	 = 1 << 2,
	VMSG_HEAD_STATUS_DOWNLOADING = 1 << 3,
	
	VMSG_HEAD_CODE_MASK			= 0x03
};

/**
 * Calculates the byte value describing our queue status for a HEAD Pong.
 */
static uint8
head_pong_queue_status(void)
{
	uint32 maximum, running;

	maximum = GNET_PROPERTY(max_uploads);
	running = GNET_PROPERTY(ul_running);
	if (!upload_is_enabled()) {
		return 0x7f; /* Busy */
	} else if (running >= maximum) {
		return 0;
	} else {
		uint32 slots;
		slots = maximum - running;	
		slots = MIN(0x7eU, slots);
		return -(uint8)slots;
	}
}

static void
vmsg_send_head_pong_v1(struct gnutella_node *n, const struct sha1 *sha1,
	uint8 code, uint8 flags)
{
	uint32 msgsize;
	uint32 paysize;
	char *payload, *p;

	payload = vmsg_fill_type(v_tmp_data, T_LIME, 24, 1);
	paysize = 2;

	flags &= VMSG_HEAD_F_MASK;

	p = poke_u8(&payload[0], flags);
	p = poke_u8(&payload[1], code);

	if (VMSG_HEAD_CODE_NOT_FOUND == code) {
		flags = 0;
	} else {
		code |= GNET_PROPERTY(is_firewalled) ? VMSG_HEAD_STATUS_FIREWALLED : 0;

		p = poke_be32(p, T_GTKG);	/* Vendor code */
		p = poke_u8(p, head_pong_queue_status());		/* Queue status */

		/* Optional ranges for partial files */
		if (VMSG_HEAD_F_RANGES & flags) {
			flags &= ~VMSG_HEAD_F_RANGES;	/* Not implemented */
		}

		/* Optional firewalled alternate locations */
		if (VMSG_HEAD_F_ALT_PUSH & flags) {
			flags &= ~VMSG_HEAD_F_ALT_PUSH;	/* Not implemented */	
		}

		/* Optional alternate locations */
		if (VMSG_HEAD_F_ALT & flags) {
			gnet_host_t hvec[15];	/* 15 * 6 = 90 bytes (max) */
			int hcnt = 0;
		   	
			if (sha1) {
				hcnt = dmesh_fill_alternate(sha1, hvec, G_N_ELEMENTS(hvec));
			}
			if (hcnt > 0) {
				int i;

				/* HEAD Ping v1 is NOT IPv6-Ready (it is deprecated) */

				p = poke_be16(p, hcnt * 6);
				for (i = 0; i < hcnt; i++) {
					if (!gnet_host_is_ipv4(&hvec[i]))
						continue;
					p = poke_be32(p,
							host_addr_ipv4(gnet_host_get_addr(&hvec[i])));
					p = poke_le16(p, gnet_host_get_port(&hvec[i]));
				}
			} else {
				flags &= ~VMSG_HEAD_F_ALT;
			}
		}
	}

	poke_u8(&payload[0], flags);	/* Update flags */
	paysize = p - payload;

	if (GNET_PROPERTY(vmsg_debug) > 1) {
		g_debug("VMSG sending HEAD Pong v1 to %s (%u bytes)",
			node_infostr(n), paysize);
	}

	msgsize = vmsg_fill_header(v_tmp_header, paysize, sizeof v_tmp);
	gnutella_header_set_muid(v_tmp_header,
		gnutella_header_get_muid(&n->header));

	vmsg_send_data(n, v_tmp, msgsize);
}

static void
vmsg_send_head_pong_v2(struct gnutella_node *n, const struct sha1 *sha1,
	uint8 code, uint8 flags)
{
	ggep_stream_t gs;
	size_t ggep_len;
	uint32 msgsize;
	uint32 paysize;
	char *payload;

	payload = vmsg_fill_type(v_tmp_data, T_LIME, 24, 2);
	paysize = 0;

	ggep_stream_init(&gs, &payload[paysize],
		&v_tmp[sizeof(v_tmp)] - &payload[paysize]);

	if (VMSG_HEAD_CODE_NOT_FOUND == code) {
		if (!ggep_stream_pack(&gs, GGEP_NAME(C), &code, sizeof code, 0))
			goto failure;
	} else {
		uint8 queue;
		uint8 caps;

		code |= GNET_PROPERTY(is_firewalled) ? VMSG_HEAD_STATUS_FIREWALLED : 0;

		if (!ggep_stream_pack(&gs, GGEP_NAME(C), &code, sizeof code, 0))
			goto failure;
	
		queue = head_pong_queue_status();	
		if (!ggep_stream_pack(&gs, GGEP_NAME(Q), &queue, sizeof queue, 0))
			goto failure;

		if (!ggep_stream_pack(&gs, GGEP_NAME(V), "GTKG", 4, 0))
			goto failure;

		caps = tls_enabled() ? VMSG_HEAD_F_TLS : 0;
		if (!ggep_stream_pack(&gs, GGEP_NAME(F), &caps, sizeof caps, 0))
			goto failure;

		/* Optional alternate locations */
		if (VMSG_HEAD_F_ALT & flags) {
			if (sha1 != NULL) {
				gnet_host_t hvec[15];	/* 15 * 18 = 270 bytes (max) */
				unsigned hcnt;

				hcnt = dmesh_fill_alternate(sha1, hvec, G_N_ELEMENTS(hvec));
				if (hcnt > 0) {
					if (GGEP_OK != ggept_a_pack(&gs, hvec, hcnt))
						goto failure;
				}
			}
		}
	}

	ggep_len = ggep_stream_close(&gs);
	paysize += ggep_len;

	msgsize = vmsg_fill_header(v_tmp_header, paysize, sizeof v_tmp);
	gnutella_header_set_muid(v_tmp_header,
		gnutella_header_get_muid(&n->header));

	vmsg_send_data(n, v_tmp, msgsize);
	return;

failure:
	(void) ggep_stream_close(&gs);
}

struct head_ping_data {
	const struct sha1 *sha1;/**< The SHA-1 of the HEAD Ping request	(atom) */
	struct nid *node_id;	/**< The sender of the HEAD Ping */
	host_addr_t addr;		/**< In case of UDP, the address of the sender */
	uint16 port;			/**< In case of UDP, the port of the sender */
};

struct head_ping_source {
	struct guid muid;			/* MUST be at offset zero */
	struct head_ping_data ping;
	time_t added;				/**< Timestamp of insertion */
};

static const time_delta_t HEAD_PING_TIMEOUT	    = 30;	/**< seconds */
static const size_t		  HEAD_PING_MAX 		= 1024;	/**< amount to track */
static const int 		  HEAD_PING_PERIODIC_MS = 5000;	/**< milliseconds */

static hash_list_t *head_pings;	/**< Tracks send/forwarded HEAD Pings */
static cevent_t *head_ping_ev;	/**< Monitoring event */

static inline void
head_ping_source_free(struct head_ping_source *source)
{
	atom_sha1_free_null(&source->ping.sha1);
	nid_unref(source->ping.node_id);
	WFREE(source);
}

static void
head_ping_expire(bool forced)
{
	time_t now;

	g_return_if_fail(head_pings);

	now = tm_time();
	for (;;) {
		struct head_ping_source *source;

		source = hash_list_head(head_pings);
		if (!source) {
			break;
		}
		if (!forced) {
			if (delta_time(now, source->added) < HEAD_PING_TIMEOUT)
				break;
		}
		hash_list_remove(head_pings, source);
		head_ping_source_free(source);
	}
}

/**
 * Callout queue callback to perform periodic monitoring of the
 * registered files.
 */
static void
head_ping_timer(cqueue_t *cq, void *unused_udata)
{
	(void) unused_udata;

	/*
	 * Re-install timer for next time.
	 */

	cq_zero(cq, &head_ping_ev);

	head_ping_ev = cq_insert(cq, HEAD_PING_PERIODIC_MS, head_ping_timer, NULL);
	head_ping_expire(FALSE);
}

static struct head_ping_source * 
head_ping_register_intern(const struct guid *muid,
	const struct sha1 *sha1, const struct nid *node_id)
{
	struct head_ping_source *source;
	uint length;

	g_assert(muid);
	g_return_val_if_fail(head_pings, NULL);

	if (!node_id_self(node_id)) {
		struct gnutella_node *n = node_active_by_id(node_id);
		if (!n || (NODE_IS_UDP(n) && !host_is_valid(n->addr, n->port))) {
			return NULL;
		}
	}
	if (hash_list_contains(head_pings, muid)) {
		/* Probably a duplicate */
		return NULL;
	}

	/* random early drop */
	length = hash_list_length(head_pings);
	if (length >= HEAD_PING_MAX) {
		return NULL;
	} else if (length > (HEAD_PING_MAX / 4) * 3) {
		if (random_value(HEAD_PING_MAX - 1) < length)
			return NULL;
	}

	WALLOC(source);
	source->muid = *muid;
	source->added = tm_time();
	hash_list_append(head_pings, source);
	
	/*
	 * We don't need the SHA-1 for routing, thus only record it
 	 * for debugging purposes or if we are the origin.
	 */
	if (node_id_self(node_id) || GNET_PROPERTY(vmsg_debug)) {
		source->ping.sha1 = atom_sha1_get(sha1);
	} else {
		source->ping.sha1 = NULL;
	}
	source->ping.node_id = nid_ref(node_id);
	return source;
}

static bool
head_ping_register_own(const struct guid *muid,
	const struct sha1 *sha1, const struct gnutella_node *target)
{
	struct head_ping_source *source;

	g_return_val_if_fail(muid, FALSE);
	g_return_val_if_fail(sha1, FALSE);
	g_return_val_if_fail(target, FALSE);
	
	source = head_ping_register_intern(muid, sha1, NODE_ID_SELF);
	if (source) {
		if (NODE_IS_UDP(target)) {
			source->ping.addr = target->addr;
			source->ping.port = target->port;
		} else {
			source->ping.addr = zero_host_addr;
			source->ping.port = 0;
		}
		return TRUE;
	} else {
		return FALSE;
	}
}

static bool
head_ping_register_forwarded(const struct guid *muid,
	const struct sha1 *sha1, const struct gnutella_node *sender)
{
	struct head_ping_source *source;
	
	g_return_val_if_fail(muid, FALSE);
	g_return_val_if_fail(sha1, FALSE);
	g_return_val_if_fail(sender, FALSE);
	
	source = head_ping_register_intern(muid, sha1, NODE_ID(sender));
	if (source) {
		if (NODE_IS_UDP(sender)) {
			source->ping.addr = sender->addr;
			source->ping.port = sender->port;
		} else {
			source->ping.addr = zero_host_addr;
			source->ping.port = 0;
		}
		return TRUE;
	} else {
		return FALSE;
	}
}

static struct head_ping_source *
head_ping_is_registered(const struct guid *muid)
{
	g_assert(muid);
	g_return_val_if_fail(head_pings, FALSE);

	return hash_list_remove(head_pings, muid);
}

/**
 * Send a "HEAD Ping" -- LIME/23v2
 *
 * This message is used to gather information about an urn:sha1, such as
 * getting more alternate location, or the list of available ranges.
 *
 * @param sha1	the SHA1 we wish to know more about
 * @param addr	the host to send the Ping to.
 * @param port	the port to send the Ping to
 * @param guid	(optional) the GUID of the node to which HEAD ping must be sent
 *
 * When the optional GUID is set, it means we're sending this message to a
 * push-proxy, so it can relay the message to the leaf bearing that GUID.
 */
void
vmsg_send_head_ping(const struct sha1 *sha1, host_addr_t addr, uint16 port,
	const struct guid *guid)
{
	static const char urn_prefix[] = "urn:sha1:";
	struct gnutella_node *n;
	const struct guid *muid;
	uint32 msgsize;
	uint32 paysize;
	char *payload;
	uint8 flags = VMSG_HEAD_F_ALT;
	ggep_stream_t gs;
	size_t ggep_len;
	void *p;

	/*
	 * TODO: in order to handle VMSG_HEAD_F_RANGES, we need to be able to
	 * somehow tie a HEAD ping to a struct download.
	 *
	 * We don't send VMSG_HEAD_F_ALT_PUSH: our mesh is not propagating those.
	 */

	g_return_if_fail(sha1);
	n = node_udp_get_addr_port(addr, port);
	if (NULL == n)
		return;

	payload = vmsg_fill_type(v_tmp_data, T_LIME, 23, 2);

	p = mempcpy(&payload[1], urn_prefix, CONST_STRLEN(urn_prefix));
	p = mempcpy(p, sha1_base32(sha1), SHA1_BASE32_SIZE);
	paysize = ptr_diff(p, payload);

	/*
	 * Optional GGEP extensions.
	 */

	ggep_stream_init(&gs, &payload[paysize],
		&v_tmp[sizeof(v_tmp)] - &payload[paysize]);

	/*
	 * Add a GGEP extension "PUSH" holding the GUID, if supplied.
	 */

	if (guid != NULL) {
		(void) ggep_stream_pack(&gs, GGEP_NAME(PUSH), guid, GUID_RAW_SIZE, 0);
	}

	/*
	 * IPv6-Ready:
	 *
	 * Let them know whether we're interested in IPv6 addresses.
	 */

	if (settings_running_ipv4()) {
		if (settings_running_ipv6()) {
			/*
			 * Our primary listening address is IPv4, but when we also have
			 * IPv6, let them know that we can accept IPv6 results.
			 */

			(void) ggep_stream_pack(&gs, GGEP_NAME(I6), NULL, 0, 0);
		}
	} else if (settings_running_ipv6()) {
		uint8 b = 1;

		/*
		 * Only running IPv6, let them know we're not interested in IPv4.
		 */

		(void) ggep_stream_pack(&gs, GGEP_NAME(I6), &b, sizeof b, 0);
	}

	ggep_len = ggep_stream_close(&gs);
	paysize += ggep_len;

	if (0 != ggep_len)
		flags |= VMSG_HEAD_F_GGEP;

	poke_u8(&payload[0], flags);

	msgsize = vmsg_fill_header(v_tmp_header, paysize, sizeof v_tmp);
	message_set_muid(v_tmp_header, GTA_MSG_VENDOR);
	muid = gnutella_header_get_muid(v_tmp_header);
	
	if (head_ping_register_own(muid, sha1, n)) {
		if (GNET_PROPERTY(vmsg_debug) > 1 || GNET_PROPERTY(log_vmsg_tx)) {
			g_debug(
				"VMSG sending HEAD Ping to %s (%u bytes) for urn:sha1:%s",
					node_infostr(n), paysize, sha1_base32(sha1));
		}
		vmsg_send_data(n, v_tmp, msgsize);
	}
}

/**
 * Given a GUID, fetch the node to which we are connected that bears this GUID
 * and support HEAD pings, so that we can forward the HEAD Ping to it.
 *
 * @return the target node, or NULL if not found or not capable of handling it.
 */
static struct gnutella_node *
head_ping_target_by_guid(const struct guid *guid)
{
	struct gnutella_node *n;
		
	n = node_by_guid(guid);
	if (n) {
	   	if (!(NODE_A_CAN_HEAD & n->attrs)) {
			if (GNET_PROPERTY(vmsg_debug) > 1) {
				g_debug(
					"VMSG HEAD Ping target %s does not support HEAD pings",
					node_infostr(n));
			}
			n = NULL;
		}
	}
	return n;
}

/**
 * Handle reception of an UDP Head Ping
 */
static void
handle_head_ping(struct gnutella_node *n,
	const struct vmsg *vmsg, const char *payload, size_t size)
{
	static const char urn_prefix[] = "urn:sha1:";
	const size_t urn_length = CONST_STRLEN(urn_prefix) + SHA1_BASE32_SIZE;
	const size_t expect_size = 1 + urn_length;
	struct guid guid;
	bool has_guid = FALSE;
	struct sha1 sha1;
	uint8 flags;

	/*
	 * The format of the message was reverse-engineered from LimeWire's code.
	 *
	 * The payload is made of a single "flags" byte and an URN:
	 *
	 *	 flags:		some flags defining what to return
	 *   urn:       typically urn:sha1:<base32 sha1>
	 */

	if (VMSG_SHORT_SIZE(n, vmsg, size, expect_size))
		return;

	if (NODE_IS_UDP(n))
		inet_udp_got_unsolicited_incoming();

	flags = peek_u8(&payload[0]);
	if (
		is_strcaseprefix(&payload[1], urn_prefix) &&
		urn_get_sha1(&payload[1], &sha1)
	) {
		if (GNET_PROPERTY(vmsg_debug) > 2) {
			g_debug("VMSG HEAD Ping for %s%s",
				urn_prefix, sha1_to_string(&sha1));
		}
	} else {
		if (GNET_PROPERTY(vmsg_debug) > 2) {
			g_warning("VMSG HEAD Ping: no SHA-1");
		}
		return;
	}

	if (VMSG_HEAD_F_GGEP & flags) {
		const char *p;

		flags &= ~VMSG_HEAD_F_GGEP;

		/*
		 * The hash length can differ (bitprint or sha1) but it's
		 * ASCII not binary, so GGEP_MAGIC (0xc3) should not appear
		 * in it.
		 */
		p = memchr(&payload[1], GGEP_MAGIC, size - 1);
		if (p != NULL) {
			extvec_t exv[MAX_EXTVEC];
			int i, exvcnt;

			ext_prepare(exv, MAX_EXTVEC);
			exvcnt = ext_parse(p, &payload[size] - p, exv, MAX_EXTVEC);

			for (i = 0; i < exvcnt; i++) {
				extvec_t *e = &exv[i];

				switch (e->ext_token) {
				case EXT_T_GGEP_PUSH:
					/*
					 * LimeWire has redefined the meaning of GGEP PUSH in this
					 * context. The payload is GUID of target peer i.e., it does
					 * not contain an array of PUSH proxies as usual.
					 */
					if (ext_paylen(e) < GUID_RAW_SIZE) {
						if (GNET_PROPERTY(vmsg_debug)) {
							g_warning("VMSG HEAD Ping: GUID too short");
						}
					} else {
						memcpy(&guid, ext_payload(e), GUID_RAW_SIZE);
						has_guid = TRUE;
					}
					break;
				case EXT_T_GGEP_I6:		/* IPv6-Ready -- supports IPv6 */
					/*
					 * If payload is empty, then it simply flags that IPv6 is
					 * supported in addition to IPv4.  If non-empty (1 byte set
					 * to TRUE) it means the host supports IPv6 only, so no IPv4
					 * results should be sent back.
					 */

					flags |= VMSG_HEAD_F_IPV6;
					if (ext_paylen(e) > 0) {
						const uint8 *b = ext_payload(e);
						if (*b) {
							flags |= VMSG_HEAD_F_IPV6_ONLY;
						}
					}
					break;
				default:
					if (GNET_PROPERTY(vmsg_debug) > 1) {
						g_debug("%s has unhandled extension %s",
							gmsg_node_infostr(n), ext_to_string(e));
					}
				}
			}

			if (exvcnt) {
				ext_reset(exv, MAX_EXTVEC);
			}
		}
		if (has_guid) {
		   	if (GNET_PROPERTY(vmsg_debug) > 1) {
				g_debug("VMSG HEAD Ping #%s", guid_hex_str(&guid));
			}
		} else {
		   	if (GNET_PROPERTY(vmsg_debug) > 1) {
				g_debug("VMSG HEAD Ping: no GUID");
			}
		}
	}

	if (has_guid && !guid_eq(&guid, GNET_PROPERTY(servent_guid))) {
		struct gnutella_node *target;

		if (settings_is_leaf()) {
		   	if (GNET_PROPERTY(vmsg_debug) > 1) {
				g_debug("VMSG HEAD Ping: not forwarding as leaf");
			}
			return;
		}
		if (gnutella_header_get_hops(&n->header) > 0) {
		   	if (GNET_PROPERTY(vmsg_debug) > 1) {
				g_debug("VMSG HEAD Ping: not forwarding further (hops=%u)",
					gnutella_header_get_hops(&n->header));
			}
			return;
		}

		target = head_ping_target_by_guid(&guid);
		if (target && target != n) {
			gnutella_header_t header;
			const struct guid *muid;

			memcpy(header, n->header, GTA_HEADER_SIZE);
			gnutella_header_set_ttl(&header, 1);
			gnutella_header_set_hops(&header, 1);
			muid = gnutella_header_get_muid(header);

			if (head_ping_register_forwarded(muid, &sha1, n)) {
				if (GNET_PROPERTY(vmsg_debug) > 1) {
					g_debug("VMSG HEAD Ping: forwarding to %s",
						node_infostr(target));
				}
				gmsg_split_sendto_one(target, header, n->data,
					GTA_HEADER_SIZE + n->size);
			}
		} else {
			if (GNET_PROPERTY(vmsg_debug) > 1) {
				g_debug("VMSG HEAD Ping: no route found");
			}
		}
	} else {
		shared_file_t *sf;
		uint8 code;

		if (node_udp_is_old(n)) {
			gnet_stats_count_dropped(n, MSG_DROP_TOO_OLD);
			return;
		}

		sf = shared_file_by_sha1(&sha1);
		if (SHARE_REBUILDING == sf) {
			/*
			 * Just ignore the request because rebuilding only takes a few
			 * seconds, so the sender might want to retry in a moment.  Over
			 * HTTP we would also claim "Busy" (503) instead of "Not found"
			 * (404).
			 */
			if (GNET_PROPERTY(vmsg_debug) > 1) {
				g_debug("VMSG HEAD Ping: got it whilst rebuilding library");
			}
		} else {
			if (sf) {
				const fileinfo_t *fi;
				
				shared_file_check(sf);
				fi = shared_file_fileinfo(sf);
				if (fi) {
					if (GNET_PROPERTY(vmsg_debug) > 2) {
						g_debug("VMSG HEAD Ping: matches a partial file");
					}
					if (file_info_partial_shareable(fi)) {
						code = VMSG_HEAD_CODE_PARTIAL;
						if (fi->recvcount > 0) {
							code |= VMSG_HEAD_STATUS_DOWNLOADING;
						}
					} else {
						code = VMSG_HEAD_CODE_NOT_FOUND;
					}
				}  else {
					if (GNET_PROPERTY(vmsg_debug) > 2) {
						g_debug("VMSG HEAD Ping: matches a shared file");
					}
					code = VMSG_HEAD_CODE_COMPLETE;
				}
				shared_file_unref(&sf);
			} else {
				if (GNET_PROPERTY(vmsg_debug) > 2) {
					g_debug("VMSG HEAD Ping: unknown file");
				}
				code = VMSG_HEAD_CODE_NOT_FOUND;
			}
			if (vmsg->version == 1) {
				vmsg_send_head_pong_v1(n, &sha1, code, flags);
			} else {
				vmsg_send_head_pong_v2(n, &sha1, code, flags);
			}
		}
	}
}

/**
 * This routine tries to intuit the size of the next "block" where the
 * data following the payload has the usual variable-sized structure:
 * an initial 16-bit big-endian value indicates the size of the block,
 * followed by the actual (fix-sized) entries, whose size is known implicitly.
 * For instance, when expecting IP:port data, this would be 6 bytes.
 *
 * The idiomatic way to use this routine is to say something like:
 *
 *	len = block_length(array_init(p, endptr - p));
 *
 * where 'p' is the current pointer within the payload and `endptr' is the
 * pointer to the first byte AFTER the payload.
 *
 * @return the size in bytes of the next block within the payload.
 */
static int
block_length(const struct array array)
{
	if (array.size >= 2) {
		uint len = peek_be16(array.data);
		if (array.size >= len + 2) {
			return len;
		}
	}
	return -1;
}

static void
fetch_alt_locs(const struct sha1 *sha1, struct array array, enum net_type net)
{
	size_t ilen;

	g_return_if_fail(sha1);

	ilen = NET_TYPE_IPV4 == net ? 6 : 18;		/* IP + port */

	while (array.size >= ilen) {
		host_addr_t addr;
		uint16 port;

		if (NET_TYPE_IPV4 == net) {
			addr = host_addr_peek_ipv4(&array.data[0]);
			array.data += 4;
		} else {
			addr = host_addr_peek_ipv6(&array.data[0]);
			array.data += 16;
		}
		port = peek_le16(&array.data[0]);
		array.data += 2;
		array.size -= ilen;

		dmesh_add_alternate(sha1, addr, port);
	}
}

static void
forward_head_pong(struct gnutella_node *n,
	const struct head_ping_source *source)
{
	/*
	 * Foward pong to proper target if we are an ultrapeer and we relayed
	 * the ping (carrying a GUID) to the proper leaf node: that leaf node
	 * is replying via TCP and we then forward the pong to the original
	 * node that ping'ed us.
	 */

	if (
		!node_id_self(source->ping.node_id) &&
		gnutella_header_get_ttl(&n->header) > 0 &&
		gnutella_header_get_hops(&n->header) == 0 &&
		settings_is_ultra()
	) {
		struct gnutella_node *target;

		if (0 != source->ping.port && is_host_addr(source->ping.addr)) {
			target = node_udp_get_addr_port(source->ping.addr,
						source->ping.port);
		} else {
			target = node_active_by_id(source->ping.node_id);
		}
		if (target) {
			gnutella_header_t header;
			pmsg_t *mb;

			if (GNET_PROPERTY(vmsg_debug) > 1) {
				g_debug("VMSG HEAD Pong: forwarding to %s",
					node_infostr(target));
			}

			memcpy(header, n->header, GTA_HEADER_SIZE);
			gnutella_header_set_ttl(&header,
				gnutella_header_get_ttl(&header) - 1);
			gnutella_header_set_hops(&header,
				gnutella_header_get_hops(&header) + 1);
		
			mb = gmsg_split_to_pmsg(header, n->data, n->size + GTA_HEADER_SIZE);
			vmsg_send_reply(target, mb);	/* Forward to destination */
		}
	}
}

static void 
handle_head_pong_v1(const struct head_ping_source *source,
	const char *payload, size_t size)
{
	const char *vendor, *p, *endptr;
	uint8 flags, code;
	int8 queue;

	endptr = &payload[size];

	/*
	 * The format of the message was reverse-engineered from LimeWire's code.
	 *
	 * offset	name			description
	 * 0		Features		some flags
	 * 1		Code			response code with flags (not found,
	 *							firewalled,	downloading, complete file)
	 * 2		Vendor ID		4-letter vendor ID of sender
	 * 6		Queue Status	
	 * 7		variable data
	 *
	 * The pong may also carry alt-locs and available ranges.
	 *
	 * Since this message is NOT IPv6-Ready, servents should no longer use
	 * v1 pings and switch to v2.
	 */

	flags = peek_u8(&payload[0]);
	code = peek_u8(&payload[1]);
	queue = 0;
	vendor = "?";
	/* LimeWire sends only code and flags if the file was not found */

	p = &payload[2];
	if (endptr - p >= 4) {
		vendor = vendor_code_to_string(peek_be32(p));
		p += 4;
		if (p != endptr) {
			queue = peek_u8(p);
			p++;
		}
	}

	if (GNET_PROPERTY(vmsg_debug) > 1) {
		g_debug(
			"VMSG HEAD Pong v1 vendor=%s, %s%s, result=\"%s%s%s\", queue=%d",
			vendor,
			source->ping.sha1 ? "urn:sha1:" : "<unknown hash>",
			source->ping.sha1 ? sha1_base32(source->ping.sha1) : "",
			VMSG_HEAD_CODE_COMPLETE & code
				? "complete"
				: (VMSG_HEAD_CODE_PARTIAL | VMSG_HEAD_STATUS_DOWNLOADING) & code
					? "partial"
					: "not found",
			VMSG_HEAD_STATUS_DOWNLOADING & code ?  ", downloading" : "",
			VMSG_HEAD_STATUS_FIREWALLED & code ?  ", firewalled" : "",
			queue);
	}

	switch (code & VMSG_HEAD_CODE_MASK) {
	case VMSG_HEAD_CODE_NOT_FOUND:
		if (node_id_self(source->ping.node_id) && source->ping.port) {
			/* We only have address and port if the Ping was sent
			 * over UDP. */
			dmesh_remove_alternate(source->ping.sha1,
				source->ping.addr, source->ping.port);
		}
		return;

	case VMSG_HEAD_CODE_COMPLETE:
	case VMSG_HEAD_CODE_PARTIAL:
		if (node_id_self(source->ping.node_id) && source->ping.port) {
			/* We only have address and port if the Ping was sent
			 * over UDP. */
			dmesh_add_good_alternate(source->ping.sha1,
				source->ping.addr, source->ping.port);
		}
		break;
	}
	
	/* Optional ranges for partial files -- IGNORED FOR NOW */
	if (VMSG_HEAD_F_RANGES & flags) {
		int len;

		len = block_length(array_init(p, endptr - p));
		if (len < 0 || len % 8) {
			if (GNET_PROPERTY(vmsg_debug)) {
				g_warning("VMSG HEAD Pong carries truncated ranges");
			}
			return;
		} else {
			if (GNET_PROPERTY(vmsg_debug) > 2) {
				g_debug("VMSG HEAD Pong carries ranges (%u bytes)", len);
			}
			p += 2;
			p += len;
		}
	}

	/* Optional firewalled alternate locations -- IGNORED FOR NOW */
	if (VMSG_HEAD_F_ALT_PUSH & flags) {
		int len;
		
		len = block_length(array_init(p, endptr - p));
		if (len != 0 && (len < 23 || (len - 23) % 6)) {
			if (GNET_PROPERTY(vmsg_debug)) {
				g_warning(
					"VMSG HEAD Pong carries truncated firewalled alt-locs");
			}
			return;
		} else {
			if (GNET_PROPERTY(vmsg_debug) > 2) {
				g_debug(
					"VMSG HEAD Pong carries firewalled alt-locs (%u bytes)",
					len);
			}
			p += 2;
			p += len;
		}
	}

	/*
	 * Optional alternate locations: feed them to the mesh.
	 */

	if (VMSG_HEAD_F_ALT & flags) {
		int len;
		
		len = block_length(array_init(p, endptr - p));
		if (len < 0 || len % 6) {
			if (GNET_PROPERTY(vmsg_debug)) {
				g_warning("VMSG HEAD Pong carries truncated alt-locs");
			}
			return;
		} else {
			if (GNET_PROPERTY(vmsg_debug) > 2)
				g_debug("VMSG HEAD Pong carries %u alt-locs", len / 6);

			p += 2;				/* Skip length indication */
			if (node_id_self(source->ping.node_id) && source->ping.sha1) {
				fetch_alt_locs(source->ping.sha1,
					array_init(p, len), NET_TYPE_IPV4);
			}
			p += len;
		}
	}
}

static void
handle_head_pong_v2(const struct head_ping_source *source,
	const char *payload, size_t size)
{
	const char *vendor;
	int flags, code, queue;
	extvec_t exv[MAX_EXTVEC];
	int i, exvcnt;

	ext_prepare(exv, MAX_EXTVEC);
	exvcnt = ext_parse(payload, size, exv, MAX_EXTVEC);

	code = VMSG_HEAD_CODE_NOT_FOUND;
	flags = 0;
	queue = 0;
	vendor = "?";

	for (i = 0; i < exvcnt; i++) {
		const extvec_t *e = &exv[i];

		switch (e->ext_token) {
		case EXT_T_GGEP_C:
			if (ext_paylen(e) < 1) {
				if (GNET_PROPERTY(vmsg_debug)) {
					g_warning("GGEP \"C\" payload too short");
				}
			} else {
				code = peek_u8(ext_payload(e));
			}
			break;
		case EXT_T_GGEP_F:
			if (ext_paylen(e) < 1) {
				if (GNET_PROPERTY(vmsg_debug)) {
					g_warning("GGEP \"F\" payload too short");
				}
			} else {
				flags = peek_u8(ext_payload(e));
			}
			break;
		case EXT_T_GGEP_V:
		case EXT_T_GGEP_VC:
			if (ext_paylen(e) < 4) {
				if (GNET_PROPERTY(vmsg_debug)) {
					g_warning("GGEP \"V\" payload too short");
				}
			} else {
				vendor = vendor_code_to_string(peek_be32(ext_payload(e)));
			}
			break;
		case EXT_T_GGEP_Q:
			if (ext_paylen(e) < 1) {
				if (GNET_PROPERTY(vmsg_debug)) {
					g_warning("GGEP \"Q\" payload too short");
				}
			} else {
				queue = (int8) peek_u8(ext_payload(e));
			}
			break;
		case EXT_T_GGEP_A:
		case EXT_T_GGEP_ALT:
			if (node_id_self(source->ping.node_id) && source->ping.sha1) {
				fetch_alt_locs(source->ping.sha1,
					array_init(ext_payload(e), ext_paylen(e)), NET_TYPE_IPV4);
			}
			break;
		case EXT_T_GGEP_A6:
		case EXT_T_GGEP_ALT6:
			if (node_id_self(source->ping.node_id) && source->ping.sha1) {
				fetch_alt_locs(source->ping.sha1,
					array_init(ext_payload(e), ext_paylen(e)), NET_TYPE_IPV6);
			}
			break;
		case EXT_T_GGEP_T:			/* TLS-capability bitmap for "A" */
		case EXT_T_GGEP_ALT_TLS:	/* TLS-capability bitmap for "ALT" */
			/* FIXME: Handle this */	
			break;
		case EXT_T_GGEP_T6:			/* TLS-capability bitmap for "A6" */
		case EXT_T_GGEP_ALT6_TLS:	/* TLS-capability bitmap for "ALT6" */
			/* FIXME: Handle this */	
			break;
		default:
			if (GNET_PROPERTY(vmsg_debug)) {
				const char *name = ext_ggep_id_str(e);

				if (name[0]) {
					g_debug("VMSG HEAD Pong carries unhandled "
						"GGEP \"%s\" (%zu bytes)",
						name, (size_t) ext_paylen(e));
				} else {
					g_debug("VMSG HEAD Pong carries unknown extra payload");
				}
			}
			break;
		}
	}
	if (exvcnt) {
		ext_reset(exv, MAX_EXTVEC);
	}	

	if (GNET_PROPERTY(vmsg_debug) > 1) {
		g_debug(
			"VMSG HEAD Pong v2 vendor=%s, %s%s, result=\"%s%s%s\", queue=%d",
			vendor,
			source->ping.sha1 ? "urn:sha1:" : "<unknown hash>",
			source->ping.sha1 ? sha1_base32(source->ping.sha1) : "",
			VMSG_HEAD_CODE_COMPLETE & code
				? "complete"
				: (VMSG_HEAD_CODE_PARTIAL | VMSG_HEAD_STATUS_DOWNLOADING) & code
					? "partial"
					: "not found",
			VMSG_HEAD_STATUS_DOWNLOADING & code ?  ", downloading" : "",
			VMSG_HEAD_STATUS_FIREWALLED & code ?  ", firewalled" : "",
			queue);
	}

	switch (code & VMSG_HEAD_CODE_MASK) {
	case VMSG_HEAD_CODE_NOT_FOUND:
		if (node_id_self(source->ping.node_id) && source->ping.port) {
			/* We only have address and port if the Ping was sent
			 * over UDP. */
			dmesh_remove_alternate(source->ping.sha1,
				source->ping.addr, source->ping.port);
		}
		break;

	case VMSG_HEAD_CODE_COMPLETE:
	case VMSG_HEAD_CODE_PARTIAL:
		if (node_id_self(source->ping.node_id) && source->ping.port) {
			/* We only have address and port if the Ping was sent
			 * over UDP. */
			dmesh_add_good_alternate(source->ping.sha1,
				source->ping.addr, source->ping.port);
		}
		break;
	}

	if (
		(VMSG_HEAD_F_TLS & flags) &&
		node_id_self(source->ping.node_id) && source->ping.port
	) {
		tls_cache_insert(source->ping.addr, source->ping.port);		
	}
}

/**
 * Handle reception of an Head Pong
 */
static void
handle_head_pong(struct gnutella_node *n,
	const struct vmsg *vmsg, const char *payload, size_t size)
{
	const size_t expected_size = 2; /* v1: flags and code; v2: GGEP only */
	struct head_ping_source *source;

	if (VMSG_SHORT_SIZE(n, vmsg, size, expected_size))
		return;

	source = head_ping_is_registered(gnutella_header_get_muid(&n->header));
	if (source) {
		if (vmsg->version == 1) {
			handle_head_pong_v1(source, payload, size);
		} else {
			handle_head_pong_v2(source, payload, size);
		}
		forward_head_pong(n, source);
		head_ping_source_free(source);
	} else {
		if (GNET_PROPERTY(vmsg_debug)) {
			g_warning("VMSG HEAD Pong MUID is not registered");
		}
	}
}

#if 0 
/**
 * Send an "UDP Crawler Ping" message to specified node. -- For testing only
 */
void
vmsg_send_udp_crawler_ping(struct gnutella_node *n,
	uint8 ultras, uint8 leaves, uint8 features)
{
	uint32 paysize = sizeof(ultras) + sizeof(leaves) + sizeof(features);
	uint32 msgsize;
	char *payload;

	g_assert(NODE_IS_UDP(n));

	msgsize = vmsg_fill_header(v_tmp_header, paysize, sizeof v_tmp);
	payload = vmsg_fill_type(v_tmp_data, T_LIME, 5, 1);

	poke_u8(&payload[0], ultras);
	poke_u8(&payload[1], leaves);
	poke_u8(&payload[2], features);

	vmsg_send_data(n, v_tmp, msgsize);
}
#endif	/* 0 */

/**
 * Handle the "Messages Supported" message.
 */
static void
handle_messages_supported(struct gnutella_node *n,
	const struct vmsg *vmsg, const char *payload, size_t size)
{
	const char *description;
	uint16 count;
	str_t *msgs;
	hset_t *handlers;

	if (NODE_IS_UDP(n))			/* Don't waste time if we get this via UDP */
		return;

	/* Accept this only once */
	if (NODE_F_VMSG_SUPPORT & n->flags)
		return;
	n->flags |= NODE_F_VMSG_SUPPORT;

	count = peek_le16(payload);

	if (GNET_PROPERTY(vmsg_debug) > 1)
		g_debug("VMSG %s supports %u vendor message%s",
			node_infostr(n), count, plural(count));

	if (VMSG_SHORT_SIZE(n, vmsg, size, count * VMS_ITEM_SIZE + sizeof count))
		return;

	description = &payload[2];		/* Skip count */

	/*
	 * Analyze the supported messages.
	 */

	msgs = str_new(count * 16);		/* Pre-size generously */
	handlers = hset_create(HASH_KEY_SELF, 0);

	while (count-- > 0) {
		struct vmsg vm;
		vendor_code_t vendor;
		uint16 id, version;

		vendor.u32 = peek_be32(&description[0]);
		id = peek_le16(&description[4]);
		version = peek_le16(&description[6]);
		description += 8;

		str_catf(msgs, " %s/%dv%d",
			vendor_code_to_string(vendor.u32), id, version);

		if (!find_message(&vm, vendor, id, version)) {
			if (GNET_PROPERTY(vmsg_debug) > 1)
				g_warning("VMSG %s supports unknown %s/%dv%d",
					node_infostr(n),
					vendor_code_to_string(vendor.u32), id, version);
			continue;
		}

		if (GNET_PROPERTY(vmsg_debug) > 2)
			g_debug("VMSG ...%s/%dv%d",
				vendor_code_to_string(vendor.u32), id, version);

		hset_insert(handlers, func_to_pointer(vm.handler));
	}

#define CAN(x)	(hset_contains(handlers, func_to_pointer(x)))

	if (CAN(handle_qstat_req) || CAN(handle_qstat_answer)) {
		node_set_leaf_guidance(NODE_ID(n), TRUE);
	}

	if (CAN(handle_time_sync_req) || CAN(handle_time_sync_reply)) {
		node_can_tsync(n);				/* Time synchronization support */
	}

	if (CAN(handle_udp_crawler_ping))
		n->attrs |= NODE_A_CRAWLABLE;   /* UDP-crawling support */

	if (CAN(handle_head_ping))
		n->attrs |= NODE_A_CAN_HEAD;

	if (CAN(handle_svn_release_notify)) {
		n->attrs |= NODE_A_CAN_SVN_NOTIFY;
		vmsg_send_svn_release_notify(n);
	}

	if (CAN(handle_oob_reply_ind))
		n->attrs |= NODE_A_CAN_OOB;

	if (CAN(handle_hops_flow))
		n->attrs |= NODE_A_HOPS_FLOW;

	if (!NODE_IS_TRANSIENT(n))
		node_supported_vmsg(n, str_2c(msgs), str_len(msgs));

#undef CAN

	str_destroy(msgs);
	hset_free_null(&handlers);
}

/**
 * Known vendor-specific messages.
 */
static const struct vmsg vmsg_map[] = {
	/* This list MUST be sorted by vendor, id, version */

	{ T_0000,  0,  0, handle_messages_supported,	"Messages Supported" },
	{ T_0000, 10,  0, handle_features_supported,	"Features Supported" },
	{ T_BEAR,  4,  1, handle_hops_flow,				"Hops Flow" },
	{ T_BEAR,  7,  1, handle_tcp_connect_back,		"TCP Connect Back" },
	{ T_BEAR, 11,  1, handle_qstat_req,				"Query Status Request" },
	{ T_BEAR, 12,  1, handle_qstat_answer,			"Query Status Response" },
	{ T_GTKG,  7,  1, handle_udp_connect_back,		"UDP Connect Back" },
	{ T_GTKG,  7,  2, handle_udp_connect_back,		"UDP Connect Back" },
	{ T_GTKG,  9,  1, handle_time_sync_req,			"Time Sync Request" },
	{ T_GTKG, 10,  1, handle_time_sync_reply,		"Time Sync Reply" },
	{ T_GTKG, 21,  1, handle_proxy_cancel,			"Push-Proxy Cancel" },
	{ T_GTKG, 22,  1, handle_node_info_req,			"Node Info Request" },
	{ T_GTKG, 23,  1, handle_node_info_ans,			"Node Info Reply" },
#ifdef HAS_GNUTLS
	{ T_GTKG, 24,  1, handle_svn_release_notify,	"SVN Release Notify" },
#endif	/* HAS_GNUTLS */
	{ T_LIME,  5,  1, handle_udp_crawler_ping,		"UDP Crawler Ping" },
	{ T_LIME, 11,  2, handle_oob_reply_ack,			"OOB Reply ACK" },
	{ T_LIME, 11,  3, handle_oob_reply_ack,			"OOB Reply ACK" },
	{ T_LIME, 12,  1, handle_oob_reply_ind,			"OOB Reply Indication" },
	{ T_LIME, 12,  2, handle_oob_reply_ind,			"OOB Reply Indication" },
	{ T_LIME, 12,  3, handle_oob_reply_ind,			"OOB Reply Indication" },
	{ T_LIME, 13,  1, handle_oob_proxy_veto,		"OOB Proxy Veto" },
	{ T_LIME, 21,  1, handle_proxy_req,				"Push-Proxy Request" },
	{ T_LIME, 21,  2, handle_proxy_req,				"Push-Proxy Request" },
	{ T_LIME, 22,  1, handle_proxy_ack,				"Push-Proxy ACK" },
	{ T_LIME, 22,  2, handle_proxy_ack,				"Push-Proxy ACK" },
	{ T_LIME, 23,  1, handle_head_ping,				"HEAD Ping" },
	{ T_LIME, 23,  2, handle_head_ping,				"HEAD Ping" },
	{ T_LIME, 24,  1, handle_head_pong,				"HEAD Pong" },
	{ T_LIME, 24,  2, handle_head_pong,				"HEAD Pong" },

	/* Above line intentionally left blank (for "!}sort" in vi) */
};

/**
 * Send a "Messages Supported" message to specified node, telling it which
 * subset of the vendor messages we can understand.  We don't send information
 * about the "Messages Supported" message itself, since this one is guaranteed
 * to be always understood
 */
void
vmsg_send_messages_supported(struct gnutella_node *n)
{
	uint16 count = 0;
	uint32 paysize;
	uint32 msgsize;
	char *payload, *count_ptr;
	uint i;

	payload = vmsg_fill_type(v_tmp_data, T_0000, 0, 0);

	/*
	 * First 2 bytes is the number of entries in the vector.
	 */

	count_ptr = payload;	/* Record offset for later correction */
	payload += 2;

	/*
	 * Fill one entry per message type supported, excepted ourselves.
	 */

	for (i = 0; i < G_N_ELEMENTS(vmsg_map); i++) {
		const struct vmsg *msg = &vmsg_map[i];

		if (msg->vendor == T_0000)		/* Don't send info about ourselves */
			continue;

		payload = poke_be32(payload, msg->vendor);
		payload = poke_le16(payload, msg->id);
		payload = poke_le16(payload, msg->version);
		count++;
	}

	/* Update the size */
	poke_le16(count_ptr, count);

	paysize = count * VMS_ITEM_SIZE	+ sizeof count;
	msgsize = vmsg_fill_header(v_tmp_header, paysize, sizeof v_tmp);

	vmsg_send_data(n, v_tmp, msgsize);
}

struct vmsg_features {
	char *data;		/* Buffer where to store the message payload */
	size_t size;	/* size in bytes of the above mentioned buffer */
	size_t pos;		/* current byte position in the buffer */
};

static void
vmsg_features_reset(struct vmsg_features *vmf, char *data, size_t size)
{
	g_assert(vmf);
	g_assert(data);
	g_assert(size >= 2);

	vmf->data = data;
	vmf->size = size;
	poke_le16(&vmf->data[0], 0);
	vmf->pos = 2;
}

static size_t
vmsg_features_get_length(const struct vmsg_features *vmf)
{
	g_assert(vmf);
	g_assert(vmf->pos <= vmf->size);

	return vmf->pos;
}

static void
vmsg_features_add(struct vmsg_features *vmf, const char *name, uint16 version)
{
	uint16 num_features;
	void *p;

	g_assert(vmf);
	g_assert(vmf->pos >= 2);
	g_assert(vmf->pos <= vmf->size);
	g_return_if_fail(vmf->size - vmf->pos >= 6);
	g_return_if_fail(name);
	g_return_if_fail(4 == strlen(name));

	/*
	 * First 2 bytes is the number of entries in the vector.
	 */
	num_features = peek_le16(&vmf->data[0]) + 1;
	poke_le16(&vmf->data[0], num_features);

	p = mempcpy(&vmf->data[vmf->pos], name, 4);
	poke_le16(p, version);
	vmf->pos += 6;
}

/**
 * Tell node about which features we're currently supporting.
 */
void
vmsg_send_features_supported(struct gnutella_node *n)
{
	struct vmsg_features vmf;
	uint32 paysize;
	uint32 msgsize;
	char *payload;

	payload = vmsg_fill_type(v_tmp_data, T_0000, 10, 0);
	vmsg_features_reset(&vmf, payload, VMSG_PAYLOAD_MAX);

	vmsg_features_add(&vmf, "HSEP", 1);
	vmsg_features_add(&vmf, "WHAT", 1);
	vmsg_features_add(&vmf, "QRP1", 1);		/* 1-bit QRP patches */
	/* No support for NAT-to-NAT -- signal version as -1, not 0 */
	vmsg_features_add(&vmf, "F2FT", (uint16) -1);
	/* TCP-incoming connections: are possible if not firewalled */
	vmsg_features_add(&vmf, "TCPI", GNET_PROPERTY(is_firewalled) ? 0 : 1);
	if (tls_enabled()) {
		vmsg_features_add(&vmf, "TLS!", 1);
	}
	if (dht_enabled()) {
		/* DHT mode: ADHT = active, PDHT = passive, LDHT = leaf */
		vmsg_features_add(&vmf,
			dht_is_active() ?  "ADHT" : "PDHT",
			(KDA_VERSION_MAJOR << 8) + KDA_VERSION_MINOR);
	}

	paysize = vmsg_features_get_length(&vmf);
	msgsize = vmsg_fill_header(v_tmp_header, paysize, sizeof v_tmp);
	vmsg_send_data(n, v_tmp, msgsize);
}

/**
 * Definition of vendor message sorting weight, for gmsg_cmp().
 * Note that we don't care about the message version here.
 */
struct vmsg_weight {
	uint32 vendor;
	uint16 id;
	int weight;
};

static const struct vmsg_weight vmsg_weight_map[] = {
	{ T_0000,  0,  7 },		/* Messages Supported */
	{ T_0000, 10,  7 },		/* Features Supported */
	{ T_BEAR,  4,  8 },		/* Hops Flow */
	{ T_BEAR,  7,  3 },		/* TCP Connect Back */
	{ T_BEAR, 11,  6 },		/* Query Status Request */
	{ T_BEAR, 12,  8 },		/* Query Status Response */
	{ T_GTKG,  7,  3 },		/* UDP Connect Back */
	{ T_GTKG,  9,  1 },		/* Time Sync Request */
	{ T_GTKG, 10,  2 },		/* Time Sync Reply */
	{ T_GTKG, 21,  0 },		/* Push-Proxy Cancel */
	{ T_GTKG, 22,  0 },		/* Node Info Request */
	{ T_GTKG, 23,  0 },		/* Node Info Reply */
	{ T_GTKG, 24,  9 },		/* SVN Release Notify */
	{ T_LIME,  5,  1 },		/* UDP Crawler Ping */
	{ T_LIME, 11,  6 },		/* OOB Reply ACK */
	{ T_LIME, 12,  7 },		/* OOB Reply Indication */
	{ T_LIME, 13,  2 },		/* OOB Proxy Veto */
	{ T_LIME, 21,  8 },		/* Push-Proxy Request */
	{ T_LIME, 22,  8 },		/* Push-Proxy ACK */
	{ T_LIME, 23,  4 },		/* HEAD Ping */
	{ T_LIME, 24,  2 },		/* HEAD Pong */
};

static patricia_t *pt_weight;

#define VMSG_TYPE_LEN		6		/* 6 bytes to identify a message */
#define VMSG_TYPE_BITLEN	(VMSG_TYPE_LEN * 8)

/**
 * @return vendor message weight given beginning of vendor message payload.
 */
uint8
vmsg_weight(const void *data)
{
	void *value;

	value = patricia_lookup(pt_weight, data);

	return pointer_to_uint(value) & 0xff;
}

/**
 * Construct the PATRICIA that will be used to quickly determine the
 * weight of a vendor message by looking at the first 6 bytes of the
 * message payload.
 */
static void
vmsg_init_weight(void)
{
	size_t i;

	pt_weight = patricia_create(VMSG_TYPE_BITLEN);

	for (i = 0; i < G_N_ELEMENTS(vmsg_weight_map); i++) {
		const struct vmsg_weight *vw = &vmsg_weight_map[i];
		gnutella_vendor_t *key = walloc(VMSG_TYPE_LEN);

		gnutella_vendor_set_code(key, vw->vendor);
		gnutella_vendor_set_selector_id(key, vw->id);

		patricia_insert(pt_weight, key, uint_to_pointer(vw->weight));
	}
}

static bool
pt_weight_free(void *key, size_t keybits, void *value, void *u)
{
	(void) keybits;
	(void) value;
	(void) u;
	wfree(key, VMSG_TYPE_LEN);
	return TRUE;
}

/**
 * Cleanup the weights.
 */
static void
vmsg_close_weight(void)
{
	patricia_foreach_remove(pt_weight, pt_weight_free, NULL);
	patricia_destroy(pt_weight);
	pt_weight = NULL;
}

/**
 * Initialize vendor messages.
 */
G_GNUC_COLD void
vmsg_init(void)
{
	size_t i;
	char data[VMSG_TYPE_LEN];
	gnutella_vendor_t *weight_key = (void *) data;

	vmsg_init_weight();

	hs_vmsg = hset_create_any(vmsg_hash_func, vmsg_hash_func2, vmsg_eq_func);

	for (i = 0; i < G_N_ELEMENTS(vmsg_map); i++) {
		const void *key = &vmsg_map[i];
		hset_insert(hs_vmsg, key);

		gnutella_vendor_set_code(weight_key, vmsg_map[i].vendor);
		gnutella_vendor_set_selector_id(weight_key, vmsg_map[i].id);

		if (!patricia_contains(pt_weight, weight_key)) {
			g_error("vendor message %s/%u missing from vmsg_weight_map[]",
				vendor_code_to_string(vmsg_map[i].vendor),
				vmsg_map[i].id);
		}
	}

	head_pings = hash_list_new(guid_hash, guid_eq);
	head_ping_ev = cq_main_insert(HEAD_PING_PERIODIC_MS, head_ping_timer, NULL);
}

G_GNUC_COLD void
vmsg_close(void)
{
	vmsg_close_weight();
	head_ping_expire(TRUE);
	hash_list_free(&head_pings);
	cq_cancel(&head_ping_ev);
	hset_free_null(&hs_vmsg);
}

/* vi: set ts=4 sw=4 cindent: */
