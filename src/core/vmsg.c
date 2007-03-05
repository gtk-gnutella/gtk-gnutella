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
#include "pmsg.h"
#include "routing.h"		/* For message_set_muid() */
#include "search.h"
#include "settings.h"		/* For listen_addr() */
#include "sockets.h"		/* For socket_listen_addr() */
#include "tsync.h"
#include "udp.h"
#include "uploads.h"
#include "vmsg.h"

#include "if/gnet_property_priv.h"

#include "lib/array.h"
#include "lib/atoms.h"
#include "lib/endian.h"
#include "lib/glib-missing.h"
#include "lib/hashlist.h"
#include "lib/tm.h"
#include "lib/urn.h"
#include "lib/vendors.h"
#include "lib/walloc.h"

#include "lib/override.h"	/* Must be the last header included */

static gchar v_tmp[4128];	/**< Large enough for a payload of 4K */
static gnutella_header_t *v_tmp_header = (void *) v_tmp;
static gnutella_vendor_t *v_tmp_data = (void *) &v_tmp[GTA_HEADER_SIZE];

/*
 * Vendor message handler.
 */

struct vmsg;

typedef void (*vmsg_handler_t)(struct gnutella_node *n,
	const struct vmsg *vmsg, const gchar *payload, size_t size);

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

#define VMS_ITEM_SIZE		8		/**< Each entry is 8 bytes (4+2+2) */
#define VMS_FEATURE_SIZE	6		/**< Each entry is 6 bytes (4+2) */

#define PAIR_CMP(x, y, a0, a1, b0, b1) \
( \
  (x = CMP(a0, a1)) \
	? x \
	: (y = CMP(b0, b1)) \
			? y \
			: 0 \
)

static const struct vmsg *find_message(vendor_code_t vc,
							guint16 id, guint16 version);

/**
 * Decompiles vendor-message name given the data payload of the Gnutella
 * message and its size.  The leading bytes give us the identification
 * unless it's too short.
 *
 * @return vendor message name in the form "NAME/1v1 'Known name'" as
 * a static string.
 */
const gchar *
vmsg_infostr(gconstpointer data, size_t size)
{
	static gchar msg[80];
	vendor_code_t vc;
	guint16 id;
	guint16 version;
	const struct vmsg *vm;

	if (size < sizeof vc)
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
	const unsigned expected_size = sizeof *v;

	if (n->size < expected_size) {
		gnet_stats_count_dropped(n, MSG_DROP_TOO_SMALL);
		if (dbg || vmsg_debug)
			gmsg_log_bad(n, "message has only %u bytes, needs at least %u",
				(unsigned) n->size, expected_size);
		return;
	}

	vc.be32 = gnutella_vendor_get_code(v);
	id = gnutella_vendor_get_selector_id(v);
	version = gnutella_vendor_get_version(v);

	vm = find_message(vc, id, version);

	if (vmsg_debug > 4)
		g_message("VMSG %s \"%s\": %s/%uv%u from %s",
			gmsg_infostr(&n->header), vm == NULL ? "UNKNOWN" : vm->name,
			vendor_code_str(ntohl(vc.be32)), id, version,
			host_addr_port_to_string(n->addr, n->port));

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
static gboolean
vmsg_bad_payload(struct gnutella_node *n,
	const struct vmsg *vmsg, size_t size, size_t expected)
{
	n->n_bad++;
	gnet_stats_count_dropped(n, MSG_DROP_BAD_SIZE);

	if (dbg || vmsg_debug)
		gmsg_log_bad(n, "Bad payload size %lu for %s/%dv%d (%s), expected %lu",
			(gulong) size, vendor_code_str(vmsg->vendor), vmsg->id,
			vmsg->version, vmsg->name, (gulong) expected);

	return TRUE;	/* bad */
}

#define VMSG_CHECK_SIZE(n, vmsg, size, expected_size) \
	(((size) < (expected_size)) \
		? vmsg_bad_payload((n), (vmsg), (size), (expected_size)) \
		: FALSE)

/**
 * Handle the "Features Supported" message.
 */
static void
handle_features_supported(struct gnutella_node *n,
	const struct vmsg *vmsg, const gchar *payload, size_t size)
{
	const gchar *description;
	guint16 count;

	count = peek_le16(payload);

	if (vmsg_debug)
		g_message("VMSG node %s <%s> supports %u extra feature%s",
			node_addr(n), node_vendor(n), count,
			count == 1 ? "" : "s");

	if (VMSG_CHECK_SIZE(n, vmsg, size, count * VMS_FEATURE_SIZE + sizeof count))
		return;

	description = &payload[2];		/* Skip count */

	/*
	 * Analyze the supported features.
	 */

	while (count-- > 0) {
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
	const struct vmsg *vmsg, const gchar *payload, size_t size)
{
	g_assert(vmsg->version <= 1);

	if (VMSG_CHECK_SIZE(n, vmsg, size, 1))
		return;

	node_set_hops_flow(n, peek_u8(payload));
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
	const struct vmsg *vmsg, const gchar *payload, size_t size)
{
	guint16 port;

	g_assert(vmsg->version <= 1);

	if (VMSG_CHECK_SIZE(n, vmsg, size, 2))
		return;

	port = peek_le16(payload);
	if (port == 0) {
		if (vmsg_debug) {
			g_warning("got improper port #%d in %s from %s <%s>",
				port, vmsg->name, node_addr(n), node_vendor(n));
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
	const struct vmsg *vmsg, const gchar *payload, size_t size)
{
	const gchar *guid;
	size_t expected_size;
	guint16 port;

	g_assert(vmsg->version >= 1 && vmsg->version <= 2);

	expected_size = sizeof(port);
	if (vmsg->version < 2) {
		expected_size += GUID_RAW_SIZE;
	}
	if (VMSG_CHECK_SIZE(n, vmsg, size, expected_size))
		return;

	port = peek_le16(payload);
	if (0 == port) {
		if (vmsg_debug) {
			g_warning("got improper port #%d in %s from %s <%s>",
				port, vmsg->name, node_addr(n), node_vendor(n));
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
		guid = &payload[2];
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
	const struct vmsg *vmsg, const gchar *unused_payload, size_t unused_size)
{
	(void) unused_payload;
	(void) unused_size;

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
	const struct vmsg *vmsg, const gchar *payload, size_t size)
{
	host_addr_t ha;
	guint16 port;

	if (VMSG_CHECK_SIZE(n, vmsg, size, vmsg->version < 2 ? 2 : 6))
		return;

	if (vmsg->version >= 2) {
		ha = host_addr_peek_ipv4(payload);
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
handle_qstat_req(struct gnutella_node *n, const struct vmsg *unused_vmsg,
	const gchar *unused_payload, size_t unused_size)
{
	guint32 kept;

	(void) unused_vmsg;
	(void) unused_payload;
	(void) unused_size;

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
	const struct vmsg *vmsg, const gchar *payload, size_t size)
{
	guint16 kept;

	if (VMSG_CHECK_SIZE(n, vmsg, size, 2))
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
handle_proxy_cancel(struct gnutella_node *n, const struct vmsg *unused_vmsg,
	const gchar *unused_payload, size_t unused_size)
{
	(void) unused_vmsg;
	(void) unused_payload;
	(void) unused_size;

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
	const struct vmsg *vmsg, const gchar *payload, size_t size)
{
	gboolean can_recv_unsolicited = FALSE;
	size_t expected_size;
	gboolean secure;
	gint hits;

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
		expected_size = 1;
		break;
	case 2:
	case 3:
		expected_size = 2;
		break;
	default:
		goto not_handling;
	}

	if (VMSG_CHECK_SIZE(n, vmsg, size, expected_size))
		goto not_handling;

	hits = peek_u8(payload);
	if (hits == 0) {
		g_warning("no results advertised in %s/%uv%u from %s",
			vendor_code_str(vmsg->vendor),
			vmsg->id, vmsg->version, node_addr(n));
		goto not_handling;
	}

	secure = vmsg->version > 2;
	can_recv_unsolicited = vmsg->version > 1 && peek_u8(&payload[1]) & 0x1;

	search_oob_pending_results(n, gnutella_header_get_muid(&n->header),
		hits, can_recv_unsolicited, secure);
	return;

not_handling:
	g_warning("not handling %s/%uv%u from %s",
		vendor_code_str(vmsg->vendor),
		vmsg->id, vmsg->version, node_addr(n));
}

/**
 * Build an "OOB Reply Indication" message.
 *
 * @param muid is the query ID.
 * @param hits is the number of hits we have to deliver for that query.
 * @param secure TRUE -> secure OOB; FALSE -> normal OOB.
 */
pmsg_t *
vmsg_build_oob_reply_ind(const gchar *muid, guint8 hits, gboolean secure)
{
	guint32 msgsize;
	guint32 paysize = sizeof(guint8) + sizeof(guint8);
	gchar *payload;

	g_assert(muid);

	msgsize = vmsg_fill_header(v_tmp_header, paysize, sizeof v_tmp);
	gnutella_header_set_muid(v_tmp_header, muid);
	payload = vmsg_fill_type(v_tmp_data, T_LIME, 12, secure ? 3 : 2);

	payload[0] = hits;
	payload[1] = is_udp_firewalled ? 0x0 : 0x1;

	return gmsg_to_pmsg(v_tmp, msgsize);
}

#define MAX_OOB_TOKEN_SIZE 16

static struct array
extract_token(const gchar *data, size_t size, gchar token[MAX_OOB_TOKEN_SIZE])
{
	extvec_t exv[MAX_EXTVEC];
	gint i, exvcnt;
	size_t token_size = 0;

	ext_prepare(exv, MAX_EXTVEC);
	exvcnt = ext_parse(data, size, exv, MAX_EXTVEC);

	for (i = 0; i < exvcnt; i++) {
		const extvec_t *e = &exv[i];

		if (EXT_T_GGEP_SO == e->ext_token) {
			size_t len = ext_paylen(e);

			if (len < 1) {
				if (vmsg_debug)
					g_warning("Empty GGEP \"SO\"");
			} else if (len > MAX_OOB_TOKEN_SIZE) {
				if (vmsg_debug)
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
	const struct vmsg *vmsg, const gchar *payload, size_t size)
{
	gchar token_data[MAX_OOB_TOKEN_SIZE];
	struct array token;
	gint wanted;

	if (VMSG_CHECK_SIZE(n, vmsg, size, 1))
		return;

	/*
	 * We expect those ACKs to come back via UDP.
	 */

	if (!NODE_IS_UDP(n)) {
		g_warning("got %s/%uv%u from TCP via %s, ignoring",
			vendor_code_str(vmsg->vendor),
			vmsg->id, vmsg->version, node_addr(n));
		return;
	}

	wanted = peek_u8(&payload[0]);

	if (vmsg->version > 2 && size > 1) {
		token = extract_token(&payload[1], size - 1, token_data);
	} else {
		token = zero_array;
	}

	oob_deliver_hits(n, gnutella_header_get_muid(&n->header), wanted, &token);
}

static void
handle_oob_proxy_veto(struct gnutella_node *n,
	const struct vmsg *vmsg, const gchar *payload, size_t size)
{
	if (NODE_IS_UDP(n)) {
		g_warning("got %s/%uv%u from TCP via %s, ignoring",
			vendor_code_str(vmsg->vendor),
			vmsg->id, vmsg->version, node_addr(n));
		return;
	}

	if (size > 0 && peek_u8(payload) < 3) {
		/* we support OOB v3 */
		n->flags &= ~NODE_F_NO_OOB_PROXY;
	} else {
		n->flags |= NODE_F_NO_OOB_PROXY;
	}
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
	const gchar *muid, guint8 want, const struct array *token)
{
	guint32 msgsize;
	guint32 paysize = sizeof(guint8);
	gchar *payload;

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
	const struct vmsg *vmsg, const gchar *unused_payload, size_t size)
{
	tm_t got;

	(void) unused_payload;

	if (VMSG_CHECK_SIZE(n, vmsg, size, 1))
		return;

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
	const struct vmsg *vmsg, const gchar *payload, size_t size)
{
	tm_t got, sent, replied, received;
	const gchar *muid;
	gboolean ntp;

	if (VMSG_CHECK_SIZE(n, vmsg, size, 9))
		return;

	tm_now_exact(&got);			/* Mark when we got (to see) the message */
	got.tv_sec = clock_loc2gmt(got.tv_sec);

	ntp = peek_u8(payload) & 0x1;

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

	received.tv_sec = peek_be32(&payload[1]);
	received.tv_usec = peek_be32(&payload[5]);

	tsync_got_reply(n, &sent, &received, &replied, &got, ntp);
}

/**
 * Callback invoked when "Time Sync Request" is about to be sent.
 * Writes current time in the first half of the MUID.
 */
static gboolean
vmsg_time_sync_req_stamp(pmsg_t *mb, const struct mqueue *unused_q)
{
	gchar *muid = pmsg_start(mb);
	tm_t old, now;

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

	poke_be32(&muid[0], now.tv_sec);
	poke_be32(&muid[4], now.tv_usec);

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

	tm_now_exact(&now);
	now.tv_sec = clock_loc2gmt(now.tv_sec);

	poke_be32(&muid[8], now.tv_sec);	/* Second half of MUID */
	poke_be32(&muid[12], now.tv_usec);

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
	const struct vmsg *vmsg, const gchar *payload, size_t size)
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

	if (vmsg->version == 1 && VMSG_CHECK_SIZE(n, vmsg, size, 3))
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
		guint8 nup = peek_u8(&payload[0]);
		guint8 nleaves = peek_u8(&payload[1]);

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
	const struct vmsg *vmsg, const gchar *payload, size_t size)
{
	if (VMSG_CHECK_SIZE(n, vmsg, size, 4))
		return;

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
	gchar *payload, *p;
	gchar *payload_end = &v_tmp[sizeof v_tmp];	/* First byte beyond buffer */
	guint i;

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
		gchar uptime[sizeof(guint64)];
		guint len;

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
	const struct vmsg *vmsg, const gchar *payload, size_t size)
{
	if (VMSG_CHECK_SIZE(n, vmsg, size, 20))
		return;

	/* TODO: Implement this */
	(void) payload;
}

enum {
	VMSG_HEAD_F_RANGES		= 1 << 0,
	VMSG_HEAD_F_ALT			= 1 << 1,
	VMSG_HEAD_F_ALT_PUSH	= 1 << 2,
	VMSG_HEAD_F_GGEP		= 1 << 4,

	VMSG_HEAD_F_MASK		= 0x1f
};

enum {
	VMSG_HEAD_CODE_NOT_FOUND	= 0,
	VMSG_HEAD_CODE_COMPLETE		= 1 << 0,
	VMSG_HEAD_CODE_PARTIAL		= 1 << 1,
	VMSG_HEAD_CODE_FIREWALLED	= 1 << 2,
	VMSG_HEAD_CODE_DOWNLOADING	= 1 << 3,

	VMSG_HEAD_CODE_MASK			= 0x0f
};

void
vmsg_send_head_pong(struct gnutella_node *n, const struct sha1 *sha1,
	guint8 code, guint8 flags)
{
	guint32 msgsize;
	guint32 paysize;
	gchar *payload, *p;

	payload = vmsg_fill_type(v_tmp_data, T_LIME, 24, 1);
	paysize = 2;

	code &= VMSG_HEAD_CODE_MASK;
	flags &= VMSG_HEAD_F_MASK;

	p = poke_u8(&payload[0], flags);
	p = poke_u8(&payload[1], code);

	if (VMSG_HEAD_CODE_NOT_FOUND == code) {
		flags = 0;
	} else {
		guint32 slots;

		code |= is_firewalled ? VMSG_HEAD_CODE_PARTIAL : 0;

		slots = upload_is_enabled() ? max_uploads - ul_running : 0;
		slots = MIN(max_uploads, slots);
		slots = MIN(0x7eU, slots);
		if (0 == slots) {
			slots = 0x7f; /* Busy */
		}

		p = poke_be32(p, T_GTKG);	/* Vendor code */
		p = poke_u8(p, slots);		/* Queue status */

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
			gint hcnt = 0;
		   	
			if (sha1) {
				hcnt = dmesh_fill_alternate(cast_to_gchar_ptr(sha1->data),
							hvec, G_N_ELEMENTS(hvec));
			}
			if (hcnt > 0) {
				gint i;
				
				p = poke_be16(p, hcnt * 6);
				for (i = 0; i < hcnt; i++) {
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

	if (vmsg_debug) {
		g_message("Sending HEAD Pong to %s", node_addr(n));
	}

	msgsize = vmsg_fill_header(v_tmp_header, paysize, sizeof v_tmp);
	gnutella_header_set_muid(v_tmp_header,
		gnutella_header_get_muid(&n->header));
	udp_send_msg(n, v_tmp, msgsize);
}

struct head_ping_data {
	struct sha1 sha1;
	host_addr_t addr;
	guint16 port;
};

struct head_ping_source {
	gchar muid[GUID_RAW_SIZE];	/* Must be at offset zero */
	time_t added;
	struct head_ping_data data;
};

static const time_delta_t HEAD_PING_TIMEOUT	    = 30;	/**< seconds */
static const size_t		  HEAD_PING_MAX 		= 1024;	/**< amount to track */
static const gint 		  HEAD_PING_PERIODIC_MS = 5000;	/**< milliseconds */

static hash_list_t *head_pings;	/**< Tracks send/forwarded HEAD Pings */
static gpointer head_ping_ev;	/**< Monitoring event */

static inline void
head_ping_source_free(struct head_ping_source *source)
{
	wfree(source, sizeof *source);
}

static void
head_ping_expire(gboolean forced)
{
	time_t now;

	g_return_if_fail(head_pings);

	now = tm_time();
	for (;;) {
		struct head_ping_source *source;
		time_delta_t d;

		source = hash_list_head(head_pings);
		if (!source) {
			break;
		}
		if (!forced) {
			d = delta_time(now, source->added);
			if (d > 0 && d <= HEAD_PING_TIMEOUT) {
				break;
			}
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
head_ping_timer(cqueue_t *unused_cq, gpointer unused_udata)
{
	(void) unused_cq;
	(void) unused_udata;

	/*
	 * Re-install timer for next time.
	 */

	head_ping_ev = cq_insert(callout_queue, HEAD_PING_PERIODIC_MS,
					head_ping_timer, NULL);
	head_ping_expire(FALSE);
}

static gboolean
head_ping_register(const gchar *muid, struct sha1 sha1, struct gnutella_node *n)
{
	struct head_ping_source *source;
	guint length;

	g_assert(muid);
	g_return_val_if_fail(head_pings, FALSE);

	if (n) {
		if (!NODE_IS_UDP(n) || !host_is_valid(n->addr, n->port))
			return FALSE;
	}
	if (hash_list_contains(head_pings, muid, NULL)) {
		/* Probably a duplicate */
		return FALSE;
	}

	/* random early drop */
	length = hash_list_length(head_pings);
	if (length >= HEAD_PING_MAX) {
		return FALSE;
	} else if (length > (HEAD_PING_MAX / 4) * 3) {
		if ((random_raw() % HEAD_PING_MAX) < length)
			return FALSE;
	}

	source = walloc(sizeof *source);
	memcpy(source->muid, muid, GUID_RAW_SIZE);
	source->added = tm_time();
	source->data.sha1 = sha1;
	if (n) {
		source->data.addr = n->addr;
		source->data.port = n->port;
	} else {
		source->data.addr = zero_host_addr;
		source->data.port = 0;
	}
	hash_list_append(head_pings, source);
	return TRUE;
}

static gboolean
head_ping_is_registered(const gchar *muid, struct head_ping_data *data)
{
	struct head_ping_source *source;

	g_assert(muid);
	g_assert(data);
	g_return_val_if_fail(head_pings, FALSE);

	source = hash_list_remove(head_pings, muid);
	if (source) {
		*data = source->data;
		head_ping_source_free(source);
		return TRUE;
	} else {
		return FALSE;
	}
}

void
vmsg_send_head_ping(struct gnutella_node *n, const struct sha1 sha1)
{
	static const gchar prefix[] = "urn:sha1:";
	guint32 msgsize;
	guint32 paysize;
	gchar *payload;

	g_assert(NODE_IS_UDP(n));

	payload = vmsg_fill_type(v_tmp_data, T_LIME, 23, 1);

	poke_u8(&payload[0], VMSG_HEAD_F_ALT | VMSG_HEAD_F_ALT_PUSH);
	memcpy(&payload[1], prefix, CONST_STRLEN(prefix));
	memcpy(&payload[1 + CONST_STRLEN(prefix)],
		sha1_to_string(sha1), SHA1_BASE32_SIZE);
	paysize = 1 + CONST_STRLEN(prefix) + SHA1_BASE32_SIZE;

	/* TODO: We can also add a GUID in case of a firewalled peer,
	 *		 this works just a like a PUSH message then.
	 */

	msgsize = vmsg_fill_header(v_tmp_header, paysize, sizeof v_tmp);
	message_set_muid(v_tmp_header, GTA_MSG_VENDOR);
	head_ping_register(gnutella_header_get_muid(v_tmp_header), sha1, NULL);

	udp_send_msg(n, v_tmp, msgsize);
}

static gboolean
extract_guid(const gchar *data, size_t size, gchar guid[GUID_RAW_SIZE])
{
	extvec_t exv[MAX_EXTVEC];
	gint i, exvcnt;
	gboolean success = FALSE;

	ext_prepare(exv, MAX_EXTVEC);
	exvcnt = ext_parse(data, size, exv, MAX_EXTVEC);

	for (i = 0; i < exvcnt; i++) {
		const extvec_t *e = &exv[i];

		if (EXT_T_GGEP_PUSH == e->ext_token) {
			/**
			 * LimeWire has redefined the meaning of GGEP PUSH in this
			 * context. The payload is GUID of target peer i.e., it does
			 * not contain an array of PUSH proxies as usual.
			 */
			if (ext_paylen(e) < GUID_RAW_SIZE) {
				if (vmsg_debug) {
					g_warning("GUID too short in HEAD Ping");
				}
			} else {
				memcpy(guid, ext_payload(e), GUID_RAW_SIZE);
				success = TRUE;
			}
			break;
		}
	}
	if (exvcnt) {
		ext_reset(exv, MAX_EXTVEC);
	}	
	return success;
}

static struct gnutella_node *
node_by_guid(const gchar *guid)
{
	struct gnutella_node *target = NULL;
	GSList *nodes, *iter;
		
	nodes = route_towards_guid(guid);
	for (iter = nodes; NULL != iter; iter = g_slist_next(iter)) {
		struct gnutella_node *n = iter->data;

		/* Forward the packet only to a direct neighbour */
		if (n->guid && guid_eq(n->guid, guid)) {
			if (NODE_A_CAN_HEAD & n->attrs) {
				target = n;
			} else {
				if (vmsg_debug) {
					g_message(
						"HEAD Ping target %s does not support HEAD pings",
						node_addr(n));
				}
			}
			break;
		}
	}
	g_slist_free(nodes);
	return target;
}
/**
 * Handle reception of an UDP Head Ping
 */
static void
handle_udp_head_ping(struct gnutella_node *n,
	const struct vmsg *vmsg, const gchar *payload, size_t size)
{
	static const gchar prefix[] = "urn:sha1:";
	const size_t expect_size = 1 + CONST_STRLEN(prefix) + SHA1_BASE32_SIZE;
	gchar guid[GUID_RAW_SIZE];
	gboolean has_guid = FALSE;
	struct sha1 sha1;
	guint8 flags;

	/*
	 * The format of the message was reverse-engineered from LimeWire's code.
	 *
	 * The payload is made of a single "flags" byte and an URN:
	 *
	 *	 flags:		some flags defining what to return
	 *   urn:       typically urn:sha1:<base32 sha1>
	 */

	if (VMSG_CHECK_SIZE(n, vmsg, size, expect_size))
		return;

	if (vmsg_debug) {
		g_message("Got HEAD Ping from %s%s (TTL=%u, hops=%u)",
			node_addr(n),
			NODE_IS_UDP(n) ? " (UDP)" : "",
			gnutella_header_get_ttl(n->header),
			gnutella_header_get_hops(n->header));
	}

	flags = peek_u8(&payload[0]);
	if (
		size > (CONST_STRLEN(prefix) + SHA1_BASE32_SIZE) &&
		urn_get_sha1(&payload[1], cast_to_gchar_ptr(sha1.data))
	) {
		if (vmsg_debug) {
			g_warning("HEAD Ping for %s%s", prefix, sha1_to_string(sha1));
		}
	} else {
		if (vmsg_debug) {
			g_warning("No SHA-1 in HEAD Ping");
		}
		return;
	}

	if (VMSG_HEAD_F_GGEP & flags) {
		const gchar *p;

		/*
		 * The hash length can differ (bitprint or sha1) but it's
		 * ASCII not binary, so GGEP_MAGIC (0xc3) should appear in
		 * it.
		 */
		p = memchr(&payload[1], GGEP_MAGIC, size - 1);
		if (p) {
			has_guid = extract_guid(p, p - &payload[1], guid);
		}
		if (has_guid) {
		   	if (vmsg_debug) {
				g_message("HEAD Ping carries GUID %s", guid_hex_str(guid));
			}
		} else {
		   	if (vmsg_debug) {
				g_message("No GUID in HEAD Ping");
			}
		}
	}

	if (has_guid && !guid_eq(guid, servent_guid)) {
		struct gnutella_node *target;

		if (NODE_P_LEAF == current_peermode) {
		   	if (vmsg_debug) {
				g_message("Not forwarding HEAD Ping as leaf");
			}
			return;
		}
		if (gnutella_header_get_hops(&n->header) > 0) {
		   	if (vmsg_debug) {
				g_message("Not forwarding forwarded HEAD Ping");
			}
			return;
		}

		target = node_by_guid(guid);
		if (target && target != n) {
			gnutella_header_t header;
			const gchar *muid;

			memcpy(header, n->header, GTA_HEADER_SIZE);
			gnutella_header_set_ttl(&header, 1);
			gnutella_header_set_hops(&header, 1);
			muid = gnutella_header_get_muid(header);
			if (head_ping_register(muid, sha1, n)) {
				if (vmsg_debug) {
					g_message("Forwarding HEAD Ping to %s", node_addr(n));
				}
				gmsg_split_sendto_one(target, header, n->data, n->size);
			}
		} else {
			if (vmsg_debug) {
				g_message("No route found for HEAD Ping");
			}
		}
	} else {
		const struct shared_file *sf;
		guint8 code;

		sf = shared_file_by_sha1(cast_to_gchar_ptr(sha1.data));
		if (SHARE_REBUILDING == sf) {
			/*
			 * Just ignore the request because rebuilding only takes a few
			 * seconds, so the sender might want to retry in a moment.  Over
			 * HTTP we would also claim "Busy" (503) instead of "Not found"
			 * (404).
			 */
			if (vmsg_debug) {
				g_message("HEAD Ping whilst rebuilding library");
			}
		} else {
			if (sf) {
				const fileinfo_t *fi;
				
				shared_file_check(sf);
				fi = shared_file_fileinfo(sf);
				if (fi) {
					if (vmsg_debug) {
						g_message("HEAD Ping for partial file");
					}
					if (pfsp_server) {
						code = VMSG_HEAD_CODE_PARTIAL;
						if (fi->recvcount > 0) {
							code |= VMSG_HEAD_CODE_DOWNLOADING;
						}
					} else {
						code = VMSG_HEAD_CODE_NOT_FOUND;
					}
				}  else {
					if (vmsg_debug) {
						g_message("HEAD Ping for shared file");
					}
					code = VMSG_HEAD_CODE_COMPLETE;
				}
			} else {
				if (vmsg_debug) {
					g_message("HEAD Ping for unknown file");
				}
				code = VMSG_HEAD_CODE_NOT_FOUND;
			}
			vmsg_send_head_pong(n, &sha1, code, flags);
		}
	}
}

static gint
block_length(const struct array array)
{
	if (array.size >= 2) {
		guint len = peek_be16(array.data);
		if (array.size >= len + 2) {
			return len;
		}
	}
	return -1;
}

/**
 * Handle reception of an Head Pong
 */
static void
handle_udp_head_pong(struct gnutella_node *n,
	const struct vmsg *vmsg, const gchar *payload, size_t size)
{
	const size_t expected_size = 2; /* flags and code */
	const gchar *vendor, *muid, *p, *endptr;
	struct head_ping_data data;
	guint8 flags, code;
	gint8 queue;

	if (VMSG_CHECK_SIZE(n, vmsg, size, expected_size))
		return;

	if (vmsg_debug) {
		g_message("Got HEAD Pong from %s%s (TTL=%u, hops=%u)",
			node_addr(n),
			NODE_IS_UDP(n) ? " (UDP)" : "",
			gnutella_header_get_ttl(n->header),
			gnutella_header_get_hops(n->header));
	}

	muid = gnutella_header_get_muid(&n->header);
	if (!head_ping_is_registered(muid, &data)) {
		if (vmsg_debug) {
			g_warning("HEAD Pong MUID is not registered");
		}
		return;
	}

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
	 */

	flags = peek_u8(&payload[0]);
	code = peek_u8(&payload[1]) & VMSG_HEAD_CODE_MASK;
	queue = 0;
	vendor = "?";

	p = &payload[2];
	if (endptr - p >= 4) {
		vendor = vendor_code_str(peek_be32(p));
		p += 4;
		if (p != endptr) {
			queue = peek_u8(p);
			p++;
		}
	}

	if (vmsg_debug) {
		g_message(
			"HEAD Pong vendor=%s, urn:sha1:%s, result=\"%s%s%s\", queue=%d",
			vendor,
			sha1_to_string(data.sha1),
			VMSG_HEAD_CODE_COMPLETE & code
				? "complete"
				: (VMSG_HEAD_CODE_PARTIAL | VMSG_HEAD_CODE_DOWNLOADING) & code
					? "partial"
					: "not found",
			VMSG_HEAD_CODE_DOWNLOADING & code ?  ", downloading" : "",
			VMSG_HEAD_CODE_FIREWALLED & code ?  ", firewalled" : "",
			queue);
	}

	if (VMSG_HEAD_CODE_NOT_FOUND == code) {
		/* LimeWire sends only code and flags if the file was not found */
		return;
	}
	
	/* Optional ranges for partial files */
	if (VMSG_HEAD_F_RANGES & flags) {
		gint len;

		len = block_length(array_init(p, endptr - p));
		if (len < 0 || len % 8) {
			if (vmsg_debug) {
				g_warning("HEAD Pong carries truncated ranges");
			}
			return;
		} else {
			if (vmsg_debug) {
				g_message("HEAD Pong carries ranges (%u bytes)", len);
			}
			p += 2;
			p += len;
		}
	}

	/* Optional firewalled alternate locations */
	if (VMSG_HEAD_F_ALT_PUSH & flags) {
		gint len;
		
		len = block_length(array_init(p, endptr - p));
		if (len != 0 && (len < 23 || (len - 23) % 6)) {
			if (vmsg_debug) {
				g_warning("HEAD Pong carries truncated firewalled alt-locs");
			}
			return;
		} else {
			if (vmsg_debug) {
				g_message("HEAD Pong carries firewalled alt-locs (%u bytes)",
					len);
			}
			p += 2;
			p += len;
		}
	}

	/* Optional alternate locations */
	if (VMSG_HEAD_F_ALT & flags) {
		gint len;
		
		len = block_length(array_init(p, endptr - p));
		if (len < 0 || len % 6) {
			if (vmsg_debug) {
				g_warning("HEAD Pong carries truncated alt-locs");
			}
			return;
		} else {
			if (vmsg_debug) {
				g_message("HEAD Pong carries %u alt-locs", len / 6);
			}
			p += 2;
		   	p += len;
		}
	}

	if (
		NODE_P_LEAF != current_peermode &&
		gnutella_header_get_ttl(&n->header) > 0 &&
		gnutella_header_get_hops(&n->header) < max_ttl &&
		host_is_valid(data.addr, data.port)
	) {
		struct gnutella_node *udp;

		udp = node_udp_get_addr_port(data.addr, data.port);
		if (udp) {
			gnutella_header_t header;

			memcpy(header, n->header, GTA_HEADER_SIZE);
			gnutella_header_set_ttl(&header,
				gnutella_header_get_ttl(&header) - 1);
			gnutella_header_set_hops(&header,
				gnutella_header_get_hops(&header) + 1);
			gmsg_split_sendto_one(udp, header, n->data, n->size);
		}
	}
}

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

	poke_u8(&payload[0], ultras);
	poke_u8(&payload[1], leaves);
	poke_u8(&payload[2], features);

	udp_send_msg(n, v_tmp, msgsize);
}
#endif	/* 0 */

/**
 * Handle the "Messages Supported" message.
 */
static void
handle_messages_supported(struct gnutella_node *n,
	const struct vmsg *vmsg, const gchar *payload, size_t size)
{
	const gchar *description;
	guint16 count;

	if (NODE_IS_UDP(n))			/* Don't waste time if we get this via UDP */
		return;

	count = peek_le16(payload);

	if (vmsg_debug)
		g_message("VMSG node %s <%s> supports %u vendor message%s",
			node_addr(n), node_vendor(n), count,
			count == 1 ? "" : "s");

	if (VMSG_CHECK_SIZE(n, vmsg, size, count * VMS_ITEM_SIZE + sizeof count))
		return;

	description = &payload[2];		/* Skip count */

	/*
	 * Analyze the supported messages.
	 */

	while (count-- > 0) {
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

		if (vm->handler == handle_udp_head_ping)
			n->attrs |= NODE_A_CAN_HEAD;
	}
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
	{ T_LIME,  5,  1, handle_udp_crawler_ping,		"UDP Crawler Ping" },
	{ T_LIME, 11,  2, handle_oob_reply_ack,			"OOBv2 Reply ACK" },
	{ T_LIME, 11,  3, handle_oob_reply_ack,			"OOBv3 Reply ACK" },
	{ T_LIME, 12,  1, handle_oob_reply_ind,			"OOBv1 Reply Indication" },
	{ T_LIME, 12,  2, handle_oob_reply_ind,			"OOBv2 Reply Indication" },
	{ T_LIME, 12,  3, handle_oob_reply_ind,			"OOBv3 Reply Indication" },
	{ T_LIME, 13,  1, handle_oob_proxy_veto,		"OOB Proxy Veto" },
	{ T_LIME, 21,  1, handle_proxy_req,				"Push-Proxy Request" },
	{ T_LIME, 21,  2, handle_proxy_req,				"Push-Proxy Request" },
	{ T_LIME, 22,  1, handle_proxy_ack,				"Push-Proxy ACK" },
	{ T_LIME, 22,  2, handle_proxy_ack,				"Push-Proxy ACK" },

	{ T_LIME, 23,  1, handle_udp_head_ping,			"HEAD Ping" },
	{ T_LIME, 24,  1, handle_udp_head_pong,			"HEAD Pong" },

	/* Above line intentionally left blank (for "!}sort" in vi) */
};

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
 * Assert that the vmsg_map[] array is sorted.
 */
static void
vmsg_map_is_sorted(void)
{
	size_t i, size = G_N_ELEMENTS(vmsg_map);
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
 * Initialize vendor messages.
 */
void
vmsg_init(void)
{
	vmsg_map_is_sorted();
	head_pings = hash_list_new(guid_hash, guid_eq);
	head_ping_ev = cq_insert(callout_queue, HEAD_PING_PERIODIC_MS,
					head_ping_timer, NULL);
}

void
vmsg_close(void)
{
	head_ping_expire(TRUE);
	hash_list_free(&head_pings);
	cq_cancel(callout_queue, head_ping_ev);
}

/* vi: set ts=4 sw=4 cindent: */
