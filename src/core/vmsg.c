/*
 * $Id$
 *
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

RCSID("$Id$")

#include "vmsg.h"
#include "nodes.h"
#include "search.h"
#include "gmsg.h"
#include "routing.h"		/* For message_set_muid() */
#include "gnet_stats.h"
#include "dq.h"
#include "udp.h"
#include "sockets.h"		/* For socket_listen_addr() */
#include "settings.h"		/* For listen_addr() */
#include "guid.h"			/* For blank_guid[] */
#include "inet.h"
#include "oob.h"
#include "mq.h"
#include "mq_udp.h"
#include "clock.h"
#include "tsync.h"
#include "hosts.h"
#include "pmsg.h"
#include "hostiles.h"
#include "ggep.h"
#include "ggep_type.h"

#include "if/gnet_property_priv.h"

#include "lib/endian.h"
#include "lib/glib-missing.h"
#include "lib/tm.h"
#include "lib/vendors.h"
#include "lib/override.h"	/* Must be the last header included */

static gchar v_tmp[4128];	/**< Large enough for a payload of 4K */
static gnutella_header_t *v_tmp_header = (void *) v_tmp;
static gnutella_vendor_t *v_tmp_data = (void *) &v_tmp[GTA_HEADER_SIZE];

/*
 * Vendor message handler.
 */

struct vmsg;

typedef void (*vmsg_handler_t)(struct gnutella_node *n,
	const struct vmsg *vmsg, gchar *payload, gint size);

/**
 * Definition of vendor messages.
 */
struct vmsg {
	guint32 vendor;
	guint16 id;
	guint16 version;
	vmsg_handler_t handler;
	const gchar *name;
};

static void handle_messages_supported(struct gnutella_node *n,
	const struct vmsg *vmsg, gchar *payload, gint size);
static void handle_features_supported(struct gnutella_node *n,
	const struct vmsg *vmsg, gchar *payload, gint size);
static void handle_hops_flow(struct gnutella_node *n,
	const struct vmsg *vmsg, gchar *payload, gint size);
static void handle_tcp_connect_back(struct gnutella_node *n,
	const struct vmsg *vmsg, gchar *payload, gint size);
static void handle_udp_connect_back(struct gnutella_node *n,
	const struct vmsg *vmsg, gchar *payload, gint size);
static void handle_proxy_req(struct gnutella_node *n,
	const struct vmsg *vmsg, gchar *payload, gint size);
static void handle_proxy_ack(struct gnutella_node *n,
	const struct vmsg *vmsg, gchar *payload, gint size);
static void handle_qstat_req(struct gnutella_node *n,
	const struct vmsg *vmsg, gchar *payload, gint size);
static void handle_qstat_answer(struct gnutella_node *n,
	const struct vmsg *vmsg, gchar *payload, gint size);
static void handle_proxy_cancel(struct gnutella_node *n,
	const struct vmsg *vmsg, gchar *payload, gint size);
static void handle_oob_reply_ind(struct gnutella_node *n,
	const struct vmsg *vmsg, gchar *payload, gint size);
static void handle_oob_reply_ack(struct gnutella_node *n,
	const struct vmsg *vmsg, gchar *payload, gint size);
static void handle_time_sync_req(struct gnutella_node *n,
	const struct vmsg *vmsg, gchar *payload, gint size);
static void handle_time_sync_reply(struct gnutella_node *n,
	const struct vmsg *vmsg, gchar *payload, gint size);
static void handle_udp_crawler_ping(struct gnutella_node *n,
	const struct vmsg *vmsg, gchar *payload, gint size);
static void handle_node_info_req(struct gnutella_node *n,
	const struct vmsg *vmsg, gchar *payload, gint size);
static void handle_node_info_ans(struct gnutella_node *n,
	const struct vmsg *vmsg, gchar *payload, gint size);

#if 0
static void handle_udp_head_ping(struct gnutella_node *n,
	const struct vmsg *vmsg, gchar *payload, gint size);
static void handle_udp_head_pong(struct gnutella_node *n,
	const struct vmsg *vmsg, gchar *payload, gint size);
#endif

/**
 * Known vendor-specific messages.
 */
static const struct vmsg vmsg_map[] = {
	/* This list MUST be sorted by vendor, id, version */

	{ T_0000, 0x0000, 0x0000, handle_messages_supported, "Messages Supported" },
	{ T_0000, 0x000a, 0x0000, handle_features_supported, "Features Supported" },
	{ T_BEAR, 0x0004, 0x0001, handle_hops_flow, "Hops Flow" },
	{ T_BEAR, 0x0007, 0x0001, handle_tcp_connect_back, "TCP Connect Back" },
	{ T_BEAR, 0x000b, 0x0001, handle_qstat_req, "Query Status Request" },
	{ T_BEAR, 0x000c, 0x0001, handle_qstat_answer, "Query Status Response" },
	{ T_GTKG, 0x0007, 0x0001, handle_udp_connect_back, "UDP Connect Back" },
	{ T_GTKG, 0x0007, 0x0002, handle_udp_connect_back, "UDP Connect Back" },
	{ T_GTKG, 0x0009, 0x0001, handle_time_sync_req, "Time Sync Request" },
	{ T_GTKG, 0x000a, 0x0001, handle_time_sync_reply, "Time Sync Reply" },
	{ T_GTKG, 0x0015, 0x0001, handle_proxy_cancel, "Push-Proxy Cancel" },
	{ T_GTKG, 0x0016, 0x0001, handle_node_info_req, "Node Info Request" },
	{ T_GTKG, 0x0017, 0x0001, handle_node_info_ans, "Node Info Reply" },
	{ T_LIME, 0x0005, 0x0001, handle_udp_crawler_ping, "UDP Crawler Ping" },
	{ T_LIME, 0x000b, 0x0002, handle_oob_reply_ack, "OOB Reply Ack" },
	{ T_LIME, 0x000c, 0x0001, handle_oob_reply_ind, "OOB Reply Indication" },
	{ T_LIME, 0x000c, 0x0002, handle_oob_reply_ind, "OOB Reply Indication" },
	{ T_LIME, 0x0015, 0x0001, handle_proxy_req, "Push-Proxy Request" },
	{ T_LIME, 0x0015, 0x0002, handle_proxy_req, "Push-Proxy Request" },
	{ T_LIME, 0x0016, 0x0001, handle_proxy_ack, "Push-Proxy Acknowledgment" },
	{ T_LIME, 0x0016, 0x0002, handle_proxy_ack, "Push-Proxy Acknowledgment" },

#if 0
	{ T_LIME, 0x0017, 0x0001, handle_udp_head_ping, "UDP Head Ping" },
	{ T_LIME, 0x0018, 0x0001, handle_udp_head_pong, "UDP Head Pong" },
#endif

	/* Above line intentionally left blank (for "!}sort" in vi) */
};

/**
 * Items in the "Messages Supported" vector.
 */
struct vms_item {
	guint32 vendor;
	guint16 selector_id;
	guint16 version;
};

#define VMS_ITEM_SIZE		8		/**< Each entry is 8 bytes (4+2+2) */

/**
 * Items in the "Features Supported" vector.
 */
struct vms_feature {
	guint32 vendor;
	guint16 version;
};

#define VMS_FEATURE_SIZE	6		/**< Each entry is 6 bytes (4+2) */

#define PAIR_CMP(x, y, a0, a1, b0, b1) \
( \
  (x = CMP(a0, a1)) \
	? x \
	: (y = CMP(b0, b1)) \
			? y \
			: 0 \
)

/**
 * Find message, given vendor code, and id, version.
 *
 * @returns handler callback if found, NULL otherwise.
 */
static const struct vmsg *
find_message(vendor_code_t vc, guint16 id, guint16 version)
{
  gint c_vendor, c_id, c_version;
  guint32 vendor = ntohl(vc.be32);

#define GET_KEY(i) (&vmsg_map[(i)])
#define FOUND(i) G_STMT_START { \
	return &vmsg_map[(i)];		\
	/* NOTREACHED */ 			\
} G_STMT_END

#define COMPARE(item, key) \
	0 != (c_vendor = VENDOR_CODE_CMP((item)->key, key)) \
		? c_vendor \
		: PAIR_CMP(c_id, c_version, (item)->id, id, (item)->version, version)

	BINARY_SEARCH(const struct vmsg *, vendor, G_N_ELEMENTS(vmsg_map), COMPARE,
		GET_KEY, FOUND);

#undef COMPARE	
#undef FOUND
#undef GET_KEY
	return NULL;		/* Not found */
}

/**
 * Decompiles vendor-message name given the data payload of the Gnutella
 * message and its size.  The leading bytes give us the identification
 * unless it's too short.
 *
 * @return vendor message name in the form "NAME/1v1 'Known name'" as
 * a static string.
 */
const gchar *
vmsg_infostr(gconstpointer data, gint size)
{
	static gchar msg[80];
	vendor_code_t vc;
	guint16 id;
	guint16 version;
	const struct vmsg *vm;

	if ((size_t) size < sizeof vc)
		return "????";

	vc.be32 = gnutella_vendor_get_code(data);
	id = gnutella_vendor_get_selector_id(data);
	version = gnutella_vendor_get_version(data);

	vm = find_message(vc, id, version);

	if (vm == NULL)
		gm_snprintf(msg, sizeof msg , "%s/%uv%u",
			vendor_code_str(ntohl(vc.be32)), id, version);
	else
		gm_snprintf(msg, sizeof msg, "%s/%uv%u '%s'",
			vendor_code_str(ntohl(vc.be32)), id, version, vm->name);

	return msg;
}

/**
 * Send reply to node, via the appropriate channel.
 */
static void
vmsg_send_reply(struct gnutella_node *n, pmsg_t *mb)
{
	if (NODE_IS_UDP(n))
		mq_udp_node_putq(n->outq, mb, n);
	else
		mq_putq(n->outq, mb);
}

/**
 * Main entry point to handle reception of vendor-specific message.
 */
void
vmsg_handle(struct gnutella_node *n)
{
	gnutella_vendor_t *v = cast_to_gpointer(n->data);
	const struct vmsg *vm;
	vendor_code_t vc;
	guint16 id, version;

	if (n->size < sizeof *v) {
		gnet_stats_count_dropped(n, MSG_DROP_TOO_SMALL);
		if (dbg || vmsg_debug)
			gmsg_log_bad(n, "message has only %d bytes, needs at least %d",
				n->size, (int) sizeof(*v));
		return;
	}

	vc.be32 = gnutella_vendor_get_code(v);
	id = gnutella_vendor_get_selector_id(v);
	version = gnutella_vendor_get_version(v);

	vm = find_message(vc, id, version);

	if (vmsg_debug > 4)
		g_message("VMSG %s \"%s\": %s/%uv%u",
			gmsg_infostr(&n->header), vm == NULL ? "UNKNOWN" : vm->name,
			vendor_code_str(ntohl(vc.be32)), id, version);

	/*
	 * If we can't handle the message, we count it as "unknown type", which
	 * is not completely exact because the type (vendor-specific) is known,
	 * it was only the subtype of that message which was unknown.  Still, I
	 * don't think it is ambiguous enough to warrant another drop type.
	 *		--RAM, 04/01/2003.
	 */

	if (vm == NULL) {
		gnet_stats_count_dropped(n, MSG_DROP_UNKNOWN_TYPE);
		if (dbg || vmsg_debug)
			gmsg_log_bad(n, "unknown vendor message");
		return;
	}

	(*vm->handler)(n, vm, n->data + sizeof(*v), n->size - sizeof(*v));
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
static guint32
vmsg_fill_header(gnutella_header_t *header, guint32 size, guint32 maxsize)
{
	guint32 msize;

	/* Default GUID: all blank */
	gnutella_header_set_muid(header, blank_guid);
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
	guint8 ttl = gnutella_header_get_ttl(header);

	g_assert(0 == (ttl & GTA_UDP_CAN_INFLATE));

	gnutella_header_set_ttl(header, ttl | GTA_UDP_CAN_INFLATE);
}

/**
 * Fill leading part of the payload data, containing the common part for
 * all vendor-specific messages.
 *
 * @returns start of payload after that common part.
 */
static gchar *
vmsg_fill_type(gnutella_vendor_t *base,
	guint32 vendor, guint16 id, guint16 version)
{
	gnutella_vendor_set_code(base, vendor);
	gnutella_vendor_set_selector_id(base, id);
	gnutella_vendor_set_version(base, version);

	return (gchar *) &base[1];
}

/**
 * Report a vendor-message with bad payload to the stats.
 */
static void
vmsg_bad_payload(
	struct gnutella_node *n, const struct vmsg *vmsg, gint size, gint expected)
{
	n->n_bad++;
	gnet_stats_count_dropped(n, MSG_DROP_BAD_SIZE);

	if (dbg || vmsg_debug)
		gmsg_log_bad(n, "Bad payload size %d for %s/%dv%d (%s), expected %d",
			size, vendor_code_str(vmsg->vendor), vmsg->id, vmsg->version,
			vmsg->name, expected);
}

/**
 * Handle the "Messages Supported" message.
 */
static void
handle_messages_supported(struct gnutella_node *n,
	const struct vmsg *vmsg, gchar *payload, gint size)
{
	guint16 count;
	gint i;
	gchar *description;
	gint expected;

	if (NODE_IS_UDP(n))			/* Don't waste time if we get this via UDP */
		return;

	count = peek_le16(payload);

	if (vmsg_debug)
		g_message("VMSG node %s <%s> supports %u vendor message%s",
			node_addr(n), node_vendor(n), count,
			count == 1 ? "" : "s");

	expected = (gint) sizeof(count) + count * VMS_ITEM_SIZE;

	if (size != expected) {
		vmsg_bad_payload(n, vmsg, size, expected);
		return;
	}

	description = payload + 2;		/* Skip count */

	/*
	 * Analyze the supported messages.
	 */

	for (i = 0; i < count; i++) {
		const struct vmsg *vm;
		vendor_code_t vendor;
		guint16 id, version;

		memcpy(&vendor.be32, &description[0], 4);
		id = peek_le16(&description[4]);
		version = peek_le16(&description[6]);
		description += 8;

		vm = find_message(vendor, id, version);

		if (vm == NULL) {
			if (vmsg_debug > 1)
				g_warning("VMSG node %s <%s> supports unknown %s/%dv%d",
					node_addr(n), node_vendor(n),
					vendor_code_str(ntohl(vendor.be32)), id, version);
			continue;
		}

		if (vmsg_debug > 2)
			g_message("VMSG ...%s/%dv%d",
				vendor_code_str(ntohl(vendor.be32)), id, version);

		/*
		 * Look for leaf-guided dynamic query support.
		 *
		 * Remote can advertise only one of the two messages needed, we
		 * can infer support for the other!.
		 */

		if (
			vm->handler == handle_qstat_req ||
			vm->handler == handle_qstat_answer
		)
			node_set_leaf_guidance(n->node_handle, TRUE);

		/*
		 * Time synchronization support.
		 */

		if (
			vm->handler == handle_time_sync_req ||
			vm->handler == handle_time_sync_reply
		)
			node_can_tsync(n);

		/*
		 * UDP-crawling support.
		 */

		if (vm->handler == handle_udp_crawler_ping)
			n->attrs |= NODE_A_CRAWLABLE;
	}
}

/**
 * Send a "Messages Supported" message to specified node, telling it which
 * subset of the vendor messages we can understand.  We don't send information
 * about the "Messages Supported" message itself, since this one is guaranteed
 * to be always understood
 */
void
vmsg_send_messages_supported(struct gnutella_node *n)
{
	guint16 count = 0;
	guint32 paysize;
	guint32 msgsize;
	gchar *payload, *count_ptr;
	guint i;

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

	gmsg_sendto_one(n, v_tmp, msgsize);
}

/**
 * Handle the "Features Supported" message.
 */
static void
handle_features_supported(struct gnutella_node *n,
	const struct vmsg *vmsg, gchar *payload, gint size)
{
	guint16 count;
	gint i;
	gchar *description;
	gint expected;

	count = peek_le16(payload);

	if (vmsg_debug)
		g_message("VMSG node %s <%s> supports %u extra feature%s",
			node_addr(n), node_vendor(n), count,
			count == 1 ? "" : "s");

	expected = (gint) sizeof(count) + count * VMS_FEATURE_SIZE;

	if (size != expected) {
		vmsg_bad_payload(n, vmsg, size, expected);
		return;
	}

	description = payload + 2;		/* Skip count */

	/*
	 * Analyze the supported features.
	 */

	for (i = 0; i < count; i++) {
		vendor_code_t vendor;
		guint16 version;

		memcpy(&vendor, &description[0], 4);
		version = peek_le16(&description[4]);
		description += 6;

		if (vmsg_debug > 1)
			g_message("VMSG node %s <%s> supports feature %s/%u",
				node_addr(n), node_vendor(n),
				vendor_code_str(ntohl(vendor.be32)), version);

		/* XXX -- look for specific features not present in handshake */
	}
}

/**
 * Handle the "Hops Flow" message.
 */
static void
handle_hops_flow(struct gnutella_node *n,
	const struct vmsg *vmsg, gchar *payload, gint size)
{
	guint8 hops;

	g_assert(vmsg->version <= 1);

	if (size != 1) {
		vmsg_bad_payload(n, vmsg, size, 1);
		return;
	}

	hops = *payload;
	node_set_hops_flow(n, hops);
}

/**
 * Send an "Hops Flow" message to specified node.
 */
void
vmsg_send_hops_flow(struct gnutella_node *n, guint8 hops)
{
	guint32 paysize = sizeof hops;
	guint32 msgsize;
	gchar *payload;

	msgsize = vmsg_fill_header(v_tmp_header, paysize, sizeof v_tmp);
	payload = vmsg_fill_type(v_tmp_data, T_BEAR, 4, 1);

	*payload = hops;

	/*
	 * Send the message as a control message, so that it gets sent ASAP.
	 */

	gmsg_ctrl_sendto_one(n, v_tmp, msgsize);
}

/**
 * Handle the "TCP Connect Back" message.
 */
static void
handle_tcp_connect_back(struct gnutella_node *n,
	const struct vmsg *vmsg, gchar *payload, gint size)
{
	guint16 port;

	g_assert(vmsg->version <= 1);

	if (size != 2) {
		vmsg_bad_payload(n, vmsg, size, 2);
		return;
	}

	port = peek_le16(payload);

	if (port == 0) {
		g_warning("got improper port #%d in %s from %s <%s>",
			port, vmsg->name, node_addr(n), node_vendor(n));
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
vmsg_send_tcp_connect_back(struct gnutella_node *n, guint16 port)
{
	guint32 paysize = sizeof port;
	guint32 msgsize;
	gchar *payload;

	g_return_if_fail(0 != port);

	msgsize = vmsg_fill_header(v_tmp_header, paysize, sizeof v_tmp);
	payload = vmsg_fill_type(v_tmp_data, T_BEAR, 7, 1);

	poke_le16(payload, port);

	gmsg_sendto_one(n, v_tmp, msgsize);
}

/**
 * Handle the \"UDP Connect Back" message.
 */
static void
handle_udp_connect_back(struct gnutella_node *n,
	const struct vmsg *vmsg, gchar *payload, gint size)
{
	guint16 port;
	gchar guid_buf[GUID_RAW_SIZE];

	g_assert(vmsg->version <= 2);

	/*
	 * Version 1 included the GUID at the end of the payload.
	 * Version 2 uses the message's GUID itself to store the GUID
	 * of the PING to send back.
	 */

	switch (vmsg->version) {
	case 1:
		if (size != 18) {
			vmsg_bad_payload(n, vmsg, size, 18);
			return;
		}
		memcpy(guid_buf, payload + 2, 16);		/* Get GUID from payload */
		break;
	case 2:
		if (size != 2) {
			vmsg_bad_payload(n, vmsg, size, 2);
			return;
		}
		/* Get GUID from MUID */
		memcpy(guid_buf, gnutella_header_get_muid(&n->header), 16);
		break;
	default:
		g_assert_not_reached();
	}

	port = peek_le16(payload);

	if (port == 0) {
		g_warning("got improper port #%d in %s from %s <%s>",
			port, vmsg->name, node_addr(n), node_vendor(n));
		return;
	}

	udp_connect_back(n->addr, port, guid_buf);
}

/**
 * Send a "UDP Connect Back" message to specified node, telling it to ping
 * us back via UDP on the specified port.
 *
 * XXX for now, we only send GTKG/7v1, although GTKG/7v2 is more compact.
 */
void
vmsg_send_udp_connect_back(struct gnutella_node *n, guint16 port)
{
	guint32 paysize = sizeof(port) + 16;
	guint32 msgsize;
	gchar *payload;

	g_return_if_fail(0 != port);

	msgsize = vmsg_fill_header(v_tmp_header, paysize, sizeof v_tmp);
	payload = vmsg_fill_type(v_tmp_data, T_GTKG, 7, 1);

	payload = poke_le16(payload, port);
	memcpy(payload, servent_guid, 16);

	gmsg_sendto_one(n, v_tmp, msgsize);
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
vmsg_send_proxy_ack(struct gnutella_node *n, const gchar *muid, gint version)
{
	guint32 paysize = sizeof(guint32) + sizeof(guint16);
	guint32 msgsize;
	gchar *payload;

	if (version == 1)
		paysize -= sizeof(guint32);		/* No IP address for v1 */

	msgsize = vmsg_fill_header(v_tmp_header, paysize, sizeof v_tmp);
	gnutella_header_set_muid(v_tmp_header, muid);
	payload = vmsg_fill_type(v_tmp_data, T_LIME, 22, version);

	if (version >= 2) {
		payload = poke_be32(payload, host_addr_ipv4(listen_addr()));
	}

	poke_le16(payload, socket_listen_port());

	/*
	 * Reply with a control message, so that the issuer knows that we can
	 * proxyfy pushes to it ASAP.
	 */

	gmsg_ctrl_sendto_one(n, v_tmp, msgsize);
}

/**
 * Handle reception of the "Push Proxy Request" message.
 */
static void
handle_proxy_req(struct gnutella_node *n,
	const struct vmsg *vmsg, gchar *unused_payload, gint size)
{
	(void) unused_payload;

	if (size != 0) {
		vmsg_bad_payload(n, vmsg, size, 0);
		return;
	}

	/*
	 * Normally, a firewalled host should be a leaf node, not an UP.
	 * Warn if node is not a leaf, but accept to be the push proxy
	 * nonetheless.
	 */

	if (!NODE_IS_LEAF(n))
		g_warning("got %s from non-leaf node %s <%s>",
			vmsg->name, node_addr(n), node_vendor(n));

	/*
	 * Add proxying info for this node.  On successful completion,
	 * we'll send an acknowledgement.
	 *
	 * We'll reply with a message at the same version as the one we got.
	 */

	if (node_proxying_add(n, gnutella_header_get_muid(&n->header))) {
		/* MUID is the node's GUID */
		vmsg_send_proxy_ack(n, gnutella_header_get_muid(&n->header),
			vmsg->version);
	}
}

/**
 * Send a "Push Proxy Request" message to specified node, using supplied
 * `muid' as the message ID (which is our GUID).
 */
void
vmsg_send_proxy_req(struct gnutella_node *n, const gchar *muid)
{
	guint32 msgsize;

	g_assert(!NODE_IS_LEAF(n));

	msgsize = vmsg_fill_header(v_tmp_header, 0, sizeof v_tmp);
	gnutella_header_set_muid(v_tmp_header, muid);
	(void) vmsg_fill_type(v_tmp_data, T_LIME, 21, 2);

	gmsg_sendto_one(n, v_tmp, msgsize);

	if (vmsg_debug > 2)
		g_warning("sent proxy REQ to %s <%s>", node_addr(n), node_vendor(n));
}

/**
 * Handle reception of the "Push Proxy Acknowledgment" message.
 *
 * Version 1 only bears the port.  The IP address must be gathered from n->addr.
 * Version 2 holds both the IP and port of our push-proxy.
 */
static void
handle_proxy_ack(struct gnutella_node *n,
	const struct vmsg *vmsg, gchar *payload, gint size)
{
	host_addr_t ha;
	guint16 port;
	gint expected_size;

	expected_size = (vmsg->version < 2) ? 2 : 6;

	if (size != expected_size) {
		vmsg_bad_payload(n, vmsg, size, expected_size);
		return;
	}

	if (vmsg->version >= 2) {
		ha = host_addr_get_ipv4(peek_be32(payload));
		payload += 4;
	} else {
		ha = n->addr;
	}

	port = peek_le16(payload);

	if (vmsg_debug > 2)
		g_message("got proxy ACK from %s <%s>: proxy at %s",
			node_addr(n), node_vendor(n), host_addr_port_to_string(ha, port));


	if (!host_is_valid(ha, port)) {
		g_warning("got improper address %s in %s from %s <%s>",
			host_addr_port_to_string(ha, port), vmsg->name,
			node_addr(n), node_vendor(n));
		return;
	}
	if (hostiles_check(ha)) {
		g_message("got proxy ACK from hostile host %s <%s>: proxy at %s",
			node_addr(n), node_vendor(n), host_addr_port_to_string(ha, port));
		return;
	}

	node_proxy_add(n, ha, port);
}

/**
 * Handle reception of "Query Status Request", where the UP requests how
 * many results the search filters of the leave (ourselves) let pass through.
 */
static void
handle_qstat_req(struct gnutella_node *n,
	const struct vmsg *vmsg, gchar *unused_payload, gint size)
{
	guint32 kept;

	(void) unused_payload;

	if (size != 0) {
		vmsg_bad_payload(n, vmsg, size, 0);
		return;
	}

	if (!search_get_kept_results(gnutella_header_get_muid(&n->header), &kept)) {
		/*
		 * We did not find any search for this MUID.  Either the remote
		 * side goofed, or they closed the search.
		 */

		g_warning("Could not find matching search");
		kept = 0xffffU;		/* Magic value telling them to stop the search */
	} else {
		kept = MIN(kept, 0xfffeU);
	}

	vmsg_send_qstat_answer(n, gnutella_header_get_muid(&n->header), kept);
}

/**
 * Send a "Query Status Request" message to specified node, using supplied
 * `muid' as the message ID (which is the query ID).
 */
void
vmsg_send_qstat_req(struct gnutella_node *n, const gchar *muid)
{
	guint32 msgsize;

	msgsize = vmsg_fill_header(v_tmp_header, 0, sizeof v_tmp);
	gnutella_header_set_muid(v_tmp_header, muid);
	(void) vmsg_fill_type(v_tmp_data, T_BEAR, 11, 1);

	gmsg_ctrl_sendto_one(n, v_tmp, msgsize);	/* Send ASAP */
}

/**
 * Handle "Query Status Response" where the leave notifies us about the
 * amount of results its search filters let pass through for the specified
 * query.
 */
static void
handle_qstat_answer(struct gnutella_node *n,
	const struct vmsg *vmsg, gchar *payload, gint size)
{
	guint16 kept;

	if (size != 2) {
		vmsg_bad_payload(n, vmsg, size, 2);
		return;
	}

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
vmsg_send_qstat_answer(struct gnutella_node *n, const gchar *muid, guint16 hits)
{
	guint32 msgsize;
	guint32 paysize = sizeof(guint16);
	gchar *payload;

	msgsize = vmsg_fill_header(v_tmp_header, paysize, sizeof v_tmp);
	gnutella_header_set_muid(v_tmp_header, muid);
	payload = vmsg_fill_type(v_tmp_data, T_BEAR, 12, 1);

	poke_le16(payload, hits);

	if (vmsg_debug > 2)
		g_message("VMSG sending %s with hits=%u to %s <%s>",
			gmsg_infostr_full(v_tmp), hits, node_addr(n), node_vendor(n));

	gmsg_ctrl_sendto_one(n, v_tmp, msgsize);	/* Send it ASAP */
}

/**
 * Handle reception of "Push Proxy Cancel" request, when remote node no longer
 * wishes to have us as a push-proxy.  This is an indication that the host
 * determined it was not TCP-firewalled.
 */
static void
handle_proxy_cancel(struct gnutella_node *n,
	const struct vmsg *vmsg, gchar *unused_payload, gint size)
{
	(void) unused_payload;

	if (size != 0) {
		vmsg_bad_payload(n, vmsg, size, 0);
		return;
	}

	/*
	 * We keep the GUID route for that node, to honour further push-proxy
	 * requests coming from past hits sent away by the proxied node.
	 * However, we clear the flag marking the node as proxied, and we know
	 * it is no longer TCP-firewalled.
	 */

	node_proxying_remove(n, FALSE);
}

/**
 * Send a "Push Proxy Cancel" message to specified node.
 */
void
vmsg_send_proxy_cancel(struct gnutella_node *n)
{
	guint32 msgsize;

	msgsize = vmsg_fill_header(v_tmp_header, 0, sizeof v_tmp);
	gnutella_header_set_muid(v_tmp_header, blank_guid);
	(void) vmsg_fill_type(v_tmp_data, T_GTKG, 21, 1);

	gmsg_sendto_one(n, v_tmp, msgsize);

	if (vmsg_debug > 2)
		g_message("sent proxy CANCEL to %s <%s>", node_addr(n), node_vendor(n));
}

/**
 * Handle reception of an "OOB Reply Indication" message, whereby the remote
 * host informs us about the amount of query hits it has for us for a
 * given query.  The message bears the MUID of the query we sent out.
 */
static void
handle_oob_reply_ind(struct gnutella_node *n,
	const struct vmsg *vmsg, gchar *payload, gint size)
{
	gint hits;
	gboolean can_recv_unsolicited = FALSE;

	if (!NODE_IS_UDP(n)) {
		/*
		 * Uh-oh, someone forwarded us a LIME/12 message.  Ignore it!
		 */

		g_warning("got %s/%uv%u from TCP via %s, ignoring",
			vendor_code_str(vmsg->vendor),
			vmsg->id, vmsg->version, node_addr(n));
		return;
	}

	switch (vmsg->version) {
	case 1:
		if (size != 1) {
			vmsg_bad_payload(n, vmsg, size, 1);
			return;
		}
		hits = *(guchar *) payload;
		break;
	case 2:
		if (size != 2) {
			vmsg_bad_payload(n, vmsg, size, 2);
			return;
		}
		hits = *(guchar *) payload;
		can_recv_unsolicited = (*(guchar *) &payload[1]) & 0x1;
		break;
	default:
		goto not_handling;
	}

	if (hits == 0) {
		g_warning("no results advertised in %s/%uv%u from %s",
			vendor_code_str(vmsg->vendor),
			vmsg->id, vmsg->version, node_addr(n));
		return;
	}

	search_oob_pending_results(n, gnutella_header_get_muid(&n->header),
		hits, can_recv_unsolicited);
	return;

not_handling:
	g_warning("not handling %s/%uv%u from %s",
		vendor_code_str(vmsg->vendor),
		vmsg->id, vmsg->version, node_addr(n));
}

/**
 * Build an "OOB Reply Indication" message.
 *
 * @param muid is the query ID
 * @param hits is the number of hits we have to deliver for that query
 */
pmsg_t *
vmsg_build_oob_reply_ind(const gchar *muid, guint8 hits)
{
	guint32 msgsize;
	guint32 paysize = sizeof(guint8) + sizeof(guint8);
	gchar *payload;

	msgsize = vmsg_fill_header(v_tmp_header, paysize, sizeof v_tmp);
	gnutella_header_set_muid(v_tmp_header, muid);
	payload = vmsg_fill_type(v_tmp_data, T_LIME, 12, 2);

	payload[0] = hits;
	payload[1] = is_udp_firewalled ? 0x0 : 0x1;

	return gmsg_to_pmsg(v_tmp, msgsize);
}

/**
 * Handle reception of an "OOB Reply Ack" message, whereby the remote
 * host informs us about the amount of query hits it wants delivered
 * for the query identified by the MUID of the message.
 */
static void
handle_oob_reply_ack(struct gnutella_node *n,
	const struct vmsg *vmsg, gchar *payload, gint size)
{
	gint wanted;

	if (size != 1) {
		vmsg_bad_payload(n, vmsg, size, 1);
		return;
	}

	/*
	 * We expect those ACKs to come back via UDP.
	 */

	if (!NODE_IS_UDP(n)) {
		g_warning("got %s/%uv%u from TCP via %s, ignoring",
			vendor_code_str(vmsg->vendor),
			vmsg->id, vmsg->version, node_addr(n));
		return;
	}

	wanted = *(guchar *) payload;
	oob_deliver_hits(n, gnutella_header_get_muid(&n->header), wanted);
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
vmsg_send_oob_reply_ack(struct gnutella_node *n, const gchar *muid, guint8 want)
{
	guint32 msgsize;
	guint32 paysize = sizeof(guint8);
	gchar *payload;

	g_assert(NODE_IS_UDP(n));

	msgsize = vmsg_fill_header(v_tmp_header, paysize, sizeof v_tmp);
	vmsg_advertise_udp_compression(v_tmp_header);	/* Can deflate UDP */
	gnutella_header_set_muid(v_tmp_header, muid);
	payload = vmsg_fill_type(v_tmp_data, T_LIME, 11, 2);

	*payload = want;

	udp_send_msg(n, v_tmp, msgsize);

	if (vmsg_debug > 2)
		g_message("sent OOB reply ACK %s to %s for %u hit%s",
			guid_hex_str(muid), node_addr(n), want, want == 1 ? "" : "s");
}

/**
 * Handle reception of a "Time Sync Request" message, indicating a request
 * from another host about time synchronization.
 */
static void
handle_time_sync_req(struct gnutella_node *n,
	const struct vmsg *vmsg, gchar *unused_payload, gint size)
{
	tm_t got;

	(void) unused_payload;

	/*
	 * We have received the message well before, but this is the first
	 * time we can timestamp it really...  We're not NTP, so the precision
	 * is not really necessary as long as we stay beneath a second, which
	 * we should.
	 */

	tm_now_exact(&got);			/* Mark when we got the message */
	got.tv_sec = clock_loc2gmt(got.tv_sec);

	if (size != 1) {
		vmsg_bad_payload(n, vmsg, size, 1);
		return;
	}

	tsync_got_request(n, &got);
}

/**
 * Handle reception of a "Time Sync Reply" message, holding the reply from
 * a previous time synchronization request.
 */
static void
handle_time_sync_reply(struct gnutella_node *n,
	const struct vmsg *vmsg, gchar *payload, gint size)
{
	gboolean ntp;
	tm_t got;
	tm_t sent;
	tm_t replied;
	tm_t received;
	const gchar *muid;
	gchar *data;

	tm_now_exact(&got);			/* Mark when we got (to see) the message */
	got.tv_sec = clock_loc2gmt(got.tv_sec);

	if (size != 9) {
		vmsg_bad_payload(n, vmsg, size, 9);
		return;
	}

	ntp = *payload & 0x1;

	/*
	 * Decompile send time.
	 */

	STATIC_ASSERT(sizeof(sent) >= 2 * sizeof(guint32));

	muid = gnutella_header_get_muid(&n->header);
	sent.tv_sec = peek_be32(&muid[0]);
	sent.tv_usec = peek_be32(&muid[4]);

	/*
	 * Decompile replied time.
	 */

	replied.tv_sec = peek_be32(&muid[8]);
	replied.tv_usec = peek_be32(&muid[12]);

	/*
	 * Decompile the time at which they got the message.
	 */

	data = payload + 1;
	received.tv_sec = peek_be32(&data[0]);
	received.tv_usec = peek_be32(&data[4]);

	tsync_got_reply(n, &sent, &received, &replied, &got, ntp);
}

/**
 * Callback invoked when "Time Sync Request" is about to be sent.
 * Writes current time in the first half of the MUID.
 */
static gboolean
vmsg_time_sync_req_stamp(pmsg_t *mb, const struct mqueue *unused_q)
{
	tm_t old;
	tm_t now;
	gchar *muid = pmsg_start(mb);

	(void) unused_q;
	g_assert(pmsg_is_writable(mb));
	STATIC_ASSERT(sizeof(now) >= 2 * sizeof(guint32));

	/*
	 * Read the old timestamp.
	 */

	old.tv_sec = peek_be32(&muid[0]);
	old.tv_usec = peek_be32(&muid[4]);

	tm_now_exact(&now);
	now.tv_sec = clock_loc2gmt(now.tv_sec);

	muid = poke_be32(muid, now.tv_sec);
	muid = poke_be32(muid, now.tv_usec);

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
vmsg_send_time_sync_req(struct gnutella_node *n, gboolean ntp, tm_t *sent)
{
	guint32 msgsize;
	guint32 paysize = sizeof(guint8);
	gchar *payload;
	gchar *muid;
	pmsg_t *mb;

	if (!NODE_IS_WRITABLE(n))
		return;

	msgsize = vmsg_fill_header(v_tmp_header, paysize, sizeof v_tmp);
	payload = vmsg_fill_type(v_tmp_data, T_GTKG, 9, 1);
	*payload = ntp ? 0x1 : 0x0;				/* bit0 indicates NTP */

	mb = gmsg_to_ctrl_pmsg(v_tmp, msgsize);	/* Send as quickly as possible */
	muid = pmsg_start(mb);

	/*
	 * The first 8 bytes of the MUID are used to store the time at which
	 * we send the message, and we fill that as late as possible.  We write
	 * the current time now, because we have to return it to the caller,
	 * but it will be superseded when the message is finally scheduled to
	 * be sent by the queue.
	 */

	pmsg_set_check(mb, vmsg_time_sync_req_stamp);

	muid = poke_be32(muid, sent->tv_sec);
	muid = poke_be32(muid, sent->tv_usec);

	vmsg_send_reply(n, mb);
}

/**
 * Callback invoked when "Time Sync Reply" is about to be sent.
 * Writes current time in the second half of the MUID.
 */
static gboolean
vmsg_time_sync_reply_stamp(pmsg_t *mb, const struct mqueue *unused_q)
{
	gchar *muid = pmsg_start(mb);
	tm_t now;

	(void) unused_q;
	g_assert(pmsg_is_writable(mb));
	STATIC_ASSERT(sizeof(now) >= 2 * sizeof(guint32));

	muid += 8;

	tm_now_exact(&now);
	now.tv_sec = clock_loc2gmt(now.tv_sec);

	muid = poke_be32(muid, now.tv_sec);	/* Second half of MUID */
	muid = poke_be32(muid, now.tv_usec);

	return TRUE;
}

/**
 * Send a "Time Sync Reply" message to the node, including the time at
 * which we send back the message in the second half of the MUID.
 * The time in `got' is the time at which we received their request.
 */
void
vmsg_send_time_sync_reply(struct gnutella_node *n, gboolean ntp, tm_t *got)
{
	guint32 msgsize;
	guint32 paysize = sizeof(guint8) + 2 * sizeof(guint32);
	gchar *payload;
	gchar *muid;
	pmsg_t *mb;

	if (!NODE_IS_WRITABLE(n))
		return;

	msgsize = vmsg_fill_header(v_tmp_header, paysize, sizeof v_tmp);
	payload = vmsg_fill_type(v_tmp_data, T_GTKG, 10, 1);

	*payload = ntp ? 0x1 : 0x0;			/* bit 0 indicates NTP */
	payload++;

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
	const struct vmsg *vmsg, gchar *payload, gint size)
{
	guint8 number_up;
	guint8 number_leaves;
	guint8 features;

	/*
	 * We expect those messages to come via UDP.
	 */

	if (!NODE_IS_UDP(n)) {
		g_warning("got %s/%uv%u from TCP via %s, ignoring",
			vendor_code_str(vmsg->vendor),
			vmsg->id, vmsg->version, node_addr(n));
		return;
	}

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

	if (vmsg->version == 1 && size != 3) {
		vmsg_bad_payload(n, vmsg, size, 3);
		return;
	}

	number_up = payload[0];
	number_leaves = payload[1];
	features = payload[2] & NODE_CR_MASK;

	node_crawl(n, number_up, number_leaves, features);
}

/**
 * Send UDP crawler pong, in reply to their ping.
 * The supplied message block contains the payload to send back.
 */
void
vmsg_send_udp_crawler_pong(struct gnutella_node *n, pmsg_t *mb)
{
	guint32 msgsize;
	guint32 paysize = pmsg_size(mb);
	gchar *payload;

	g_assert(NODE_IS_UDP(n));

	msgsize = vmsg_fill_header(v_tmp_header, paysize, sizeof v_tmp);
	payload = vmsg_fill_type(v_tmp_data, T_LIME, 6, 1);
	/* Propagate MUID */
	gnutella_header_set_muid(v_tmp_header,
		gnutella_header_get_muid(&n->header));

	memcpy(payload, pmsg_start(mb), paysize);

	if (vmsg_debug > 2) {
		guint8 nup = payload[0];
		guint8 nleaves = payload[1];

		g_message("VMSG sending %s with up=%u and leaves=%u to %s",
			gmsg_infostr_full(v_tmp), nup, nleaves, node_addr(n));
	}

	udp_send_msg(n, v_tmp, msgsize);
}

/**
 * Handle reception of a Node Info Request -- GTKG/22v1
 *
 * This messsage is a request for internal Gnutella connectivity information.
 * It must be replied with an urgent GTKG/23v1 "Node Info Reply" message.
 */
static void
handle_node_info_req(struct gnutella_node *n,
	const struct vmsg *vmsg, gchar *payload, gint size)
{
	const guint expect_size = 4;

	if ((guint) size != expect_size) {
		vmsg_bad_payload(n, vmsg, size, expect_size);
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
	guint32 msgsize;
	guint32 paysize;
	ggep_stream_t gs;
	gint ggep_len;
	gchar *payload;
	gchar *payload_end = v_tmp + sizeof v_tmp;	/* First byte beyond buffer */
	guint8 *p;
	guint i;

	payload = vmsg_fill_type(v_tmp_data, T_GTKG, 23, 1);
	p = (guint8 *) payload;

	/*
	 * We'll assert at the end that we have not overflown the data segment
	 * we've been given to construct the message.
	 */

	/* General information always returned */

	for (i = 0; i < G_N_ELEMENTS(ri->vendor); i++)
		*p++ = (guint8) ri->vendor[i];

	*p++ = (guint8) ri->mode;
	p = poke_be32(p, ri->answer_flags);
	p = poke_be32(p, ri->op_flags);
	*p++ = (guint8) G_N_ELEMENTS(ri->features);

	g_assert(ri->features_count == G_N_ELEMENTS(ri->features));

	for (i = 0; i < G_N_ELEMENTS(ri->features); i++)
		p = poke_be32(p, ri->features[i]);

	*p++ = ri->max_ultra_up;
	*p++ = ri->max_ultra_lf;
	*p++ = ri->ultra_count;

	p = poke_be16(p, ri->max_leaves);
	p = poke_be16(p, ri->leaf_count);

	*p++ = ri->ttl;
	*p++ = ri->hard_ttl;

	p = poke_be32(p, ri->startup_time);
	p = poke_be32(p, ri->ip_change_time);

	g_assert((gchar *) p - payload == 31 + 4 * ri->features_count);

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

	g_assert((gchar *) p > v_tmp && (gchar *) p < payload_end);

	/*
	 * GGEP blocks
	 */

	ggep_stream_init(&gs, p, payload_end - (gchar *) p);

	if (ri->answer_flags & RNODE_RQ_GGEP_DU) {
		gchar uptime[sizeof ri->ggep_du];
		gint len;

		len = ggept_du_encode(ri->ggep_du, uptime);
		ggep_stream_pack(&gs, GGEP_NAME(DU), uptime, len, 0);
	}

	if (ri->answer_flags & RNODE_RQ_GGEP_LOC) {
		/* XXX -- NOT SUPPORTED */
	}

	if (ri->answer_flags & RNODE_RQ_GGEP_IPV6) {
		g_assert(is_host_addr(ri->ggep_ipv6));

		ggep_stream_pack(&gs, GGEP_GTKG_NAME(IPV6),
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

	g_assert((gchar *) p + ggep_len < payload_end);

	/*
	 * Now that the message has been fully generated, we know its size and
	 * can fill in the header.
	 */

	paysize = (gchar *) p - payload;
	msgsize = vmsg_fill_header(v_tmp_header, paysize, sizeof v_tmp);
	gnutella_header_set_muid(v_tmp_header,
		gnutella_header_get_muid(&n->header));

	/*
	 * Message is sent back over TCP as a prioritary one (put ahead of the
	 * queue, much like "alive" pongs).
	 */

	if (NODE_IS_UDP(n))
		udp_send_msg(n, v_tmp, msgsize);
	else
		gmsg_ctrl_sendto_one(n, v_tmp, msgsize);
}

/**
 * Handle reception of a Node Info Reply -- GTKG/23v1
 *
 * This messsage is sent in reply to a GTKG/22v1 "Node Info Request".
 */
static void
handle_node_info_ans(struct gnutella_node *n,
	const struct vmsg *vmsg, gchar *payload, gint size)
{
	const guint min_size = 20;

	if ((guint) size < min_size) {
		vmsg_bad_payload(n, vmsg, size, min_size);
		return;
	}

	/* XXX */
	(void) payload;
}

#if 0
/**
 * Handle reception of an UDP Head Ping
 */
static void
handle_udp_head_ping(struct gnutella_node *n,
	const struct vmsg *vmsg, gchar *payload, gint size)
{
	const guint expect_size = 1 + CONST_STRLEN("urn:sha1:") + SHA1_BASE32_SIZE;
	guint8 features;

	/*
	 * We expect those messages to come via UDP.
	 */

	if (!NODE_IS_UDP(n)) {
		g_warning("got %s/%uv%u from TCP via %s, ignoring",
			vendor_code_str(vmsg->vendor),
			vmsg->id, vmsg->version, node_addr(n));
		return;
	}

	/*
	 * The format of the message was reverse-engineered from LimeWire's code.
	 *
	 * The payload is made of a single "feature" byte and an URN:
	 *
	 *	 features:		some flags defining what to return
	 *   urn:           typically urn:sha1:<base32 sha1>
	 */

	if ((guint) size != expect_size) {
		vmsg_bad_payload(n, vmsg, size, expect_size);
		return;
	}

	features = payload[0];
	/* TODO: Implement this */
}

/**
 * Handle reception of an Head Pong
 */
static void
handle_udp_head_pong(struct gnutella_node *n,
	const struct vmsg *vmsg, gchar *payload, gint size)
{
	const guint min_size = 2; /* features and code */
	guint8 features;
	guint8 code;

	/*
	 * We expect those messages to come via UDP.
	 */

	if (!NODE_IS_UDP(n)) {
		g_warning("got %s/%uv%u from TCP via %s, ignoring",
			vendor_code_str(vmsg->vendor),
			vmsg->id, vmsg->version, node_addr(n));
		return;
	}

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
	 */

	if ((guint) size != min_size) {
		vmsg_bad_payload(n, vmsg, size, min_size);
		return;
	}

	features = payload[0];
	code = payload[1];

	/* TODO: Implement this */
}
#endif


#if 0
/**
 * Send an "UDP Crawler Ping" message to specified node. -- For testing only
 */
void
vmsg_send_udp_crawler_ping(struct gnutella_node *n,
	guint8 ultras, guint8 leaves, guint8 features)
{
	guint32 paysize = sizeof(ultras) + sizeof(leaves) + sizeof(features);
	guint32 msgsize;
	gchar *payload;

	g_assert(NODE_IS_UDP(n));

	msgsize = vmsg_fill_header(v_tmp_header, paysize, sizeof v_tmp);
	payload = vmsg_fill_type(v_tmp_data, T_LIME, 5, 1);

	*payload++ = ultras;
	*payload++ = leaves;
	*payload++ = features;

	udp_send_msg(n, v_tmp, msgsize);
}
#endif

/**
 * Assert that the vmsg_map[] array is sorted.
 */
static void
vmsg_map_is_sorted(void)
{
	size_t i;
	size_t size = G_N_ELEMENTS(vmsg_map);
	gint c_vendor, c_id, c_version;

	/* Don't use BINARY_ARRAY_SORTED -- keep that macro simple */

#define COMPARE(it, o) \
	(0 != (c_vendor = VENDOR_CODE_CMP((it)->vendor, (o)->vendor)) \
		? c_vendor \
		: PAIR_CMP(c_id, c_version, \
			(it)->id, (o)->id, (it)->version, (o)->version))


	for (i = 1; i < size; i++) {
		const struct vmsg *prev = &vmsg_map[i - 1], *e = &vmsg_map[i];

		if (COMPARE(prev, e) >= 0)
			g_error("vmsg_map[] unsorted (near %s/%uv%u '%s')",
				vendor_code_str(e->vendor), e->id, e->version, e->name);
	}

#undef COMPARE
}

/**
 * Initialize vendor messages.
 */
void
vmsg_init(void)
{
	vmsg_map_is_sorted();
}

/* vi: set ts=4 sw=4 cindent: */
