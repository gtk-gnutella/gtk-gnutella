/*
 * $Id$
 *
 * Copyright (c) 2003, Raphael Manfredi
 *
 * Vendor-specific messages.
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

#include "common.h"		/* For -DUSE_DMALLOC */

#include "vmsg.h"
#include "vendors.h"
#include "nodes.h"
#include "gmsg.h"
#include "routing.h"	/* For message_set_muid() */
#include "gnet_stats.h"

RCSID("$Id$");

static gchar v_tmp[256];

/*
 * Vendor message handler.
 */
typedef void (*vmsg_handler_t)(struct gnutella_node *n,
	guint16 version, guchar *payload, gint size);

/*
 * Definition of vendor messages
 */
struct vmsg_known {
	guint32 vendor;
	guint16 id;
	guint16 version;
	vmsg_handler_t handler;
	gchar *name;
};

static void handle_messages_supported(struct gnutella_node *n,
	guint16 version, guchar *payload, gint size);
static void handle_hops_flow(struct gnutella_node *n,
	guint16 version, guchar *payload, gint size);
static void handle_connect_back(struct gnutella_node *n,
	guint16 version, guchar *payload, gint size);

/*
 * Known vendor-specific messages.
 */
static struct vmsg_known vmsg_map[] = {
	/* This list MUST be sorted by vendor, id, version */

	{ T_0000, 0x0000, 0x0000, handle_messages_supported, "Messages Supported" },
	{ T_BEAR, 0x0004, 0x0001, handle_hops_flow, "Hops Flow" },
	{ T_BEAR, 0x0007, 0x0001, handle_connect_back, "Connect Back" },

	/* Above line intentionally left blank (for "!}sort" on vi) */
};

#define END(v)		(v - 1 + sizeof(v) / sizeof(v[0]))

/*
 * Items in the "Message Supported" vector.
 */
struct vms_item {
	guint32 vendor;
	guint16 selector_id;
	guint16 version;
};

#define VMS_ITEM_SIZE	8		/* Each entry is 8 bytes (4+2+2) */

/*
 * find_message
 *
 * Find message, given vendor code, and id, version.
 *
 * We don't necessarily match the version exactly: we only guarantee to
 * return a handler whose version number is greater or equal than the message
 * received.
 *
 * Returns handler callback if found, NULL otherwise.
 */
static struct vmsg_known *find_message(
	guint32 vendor, guint16 id, guint16 version)
{
	struct vmsg_known *low = vmsg_map;
	struct vmsg_known *high = END(vmsg_map);

	while (low <= high) {
		struct vmsg_known *mid = low + (high - low) / 2;
		gint c;

		c = vendor_code_cmp(mid->vendor, vendor);

		if (c == 0) {
			if (mid->id != id)
				c = mid->id < id ? -1 : +1;
		}

		if (c == 0) {
			if (mid->version < version)		/* Return match if >= */
				c = -1;
		}

		if (c == 0)
			return mid;
		else if (c < 0)
			low = mid + 1;
		else
			high = mid - 1;
	}

	return NULL;		/* Not found */
}

/*
 * vmsg_handle
 *
 * Main entry point to handle reception of vendor-specific message.
 */
void vmsg_handle(struct gnutella_node *n)
{
	struct gnutella_vendor *v = (struct gnutella_vendor *) n->data;
	guint32 vendor;
	guint16 id;
	guint16 version;
	struct vmsg_known *vm;

	READ_GUINT32_BE(v->vendor, vendor);
	READ_GUINT16_LE(v->selector_id, id);
	READ_GUINT16_LE(v->version, version);

	vm = find_message(vendor, id, version);

	if (dbg > 4)
		printf("VMSG %s \"%s\": vendor=%s, id=%u, version=%u\n",
			gmsg_infostr(&n->header), vm == NULL ? "UNKNOWN" : vm->name,
			vendor_code_str(vendor), id, version);

	/*
	 * If we can't handle the message, we count it as "unknown type", which
	 * is not completely exact because the type (vendor-specific) is known,
	 * it was only the subtype of that message which was unknown.  Still, I
	 * don't think it is ambiguous enough to warrant another drop type.
	 *		--RAM, 04/01/2003.
	 */

	if (vm == NULL) {
		gnet_stats_count_dropped(n, MSG_DROP_UNKNOWN_TYPE);
		if (dbg)
			g_warning("unknown vendor message: %s vendor=%s id=%u version=%u",
				gmsg_infostr(&n->header), vendor_code_str(vendor), id, version);
		return;
	}

	(*vm->handler)(n, version, n->data + sizeof(*v), n->size - sizeof(*v));
}

/*
 * vmsg_fill_header
 *
 * Fill common message header part for all vendor-specific messages.
 * The GUID is blanked (all zero bytes), TTL is set to 1 and hops to 0.
 * Those common values can be superseded by the caller if needed.
 */
static void vmsg_fill_header(struct gnutella_header *header, guint32 size)
{
	memset(header->muid, 0, 16);				/* Default GUID: all blank */
	header->function = GTA_MSG_VENDOR;
	header->ttl = 1;
	header->hops = 0;

	WRITE_GUINT32_LE(size, header->size);
}

/*
 * vmsg_fill_type
 *
 * Fill leading part of the payload data, containing the common part for
 * all vendor-specific messages.
 *
 * Returns start of payload after that common part.
 */
static guchar *vmsg_fill_type(
	struct gnutella_vendor *base, guint32 vendor, guint16 id, guint16 version)
{
	WRITE_GUINT32_BE(vendor, base->vendor);
	WRITE_GUINT16_LE(id, base->selector_id);
	WRITE_GUINT16_LE(version, base->version);

	return (guchar *) (base + 1);
}

/*
 * handle_messages_supported
 *
 * Handle the "Messages Supported" message.
 */
static void handle_messages_supported(struct gnutella_node *n,
	guint16 version, guchar *payload, gint size)
{
	guint16 count;

	READ_GUINT16_LE(payload, count);

	if (dbg > 2)
		printf("VMSG node %s <%s> supports %u vendor message%s\n",
			node_ip(n), node_vendor(n), count,
			count == 1 ? "" : "s");

	if (size != sizeof(count) + count * VMS_ITEM_SIZE) {
		g_warning("bad payload length in \"Messages Supported\" from %s <%s>: "
			"expected %d bytes in vector for %d item%s, got %d",
			node_ip(n), node_vendor(n),
			count * VMS_ITEM_SIZE, count, count == 1 ? "" : "s",
			size - (gint) sizeof(count));
		return;
	}

	/* XXX -- we don't need this support yet -- RAM, 30/01/2003 */
	if (dbg)
		g_warning("handle_messages_supported() not implemented yet!");
}

/*
 * vmsg_send_messages_supported
 *
 * Send a "Messages Supported" message to specified node, telling it which
 * subset of the vendor messages we can understand.  We don't send information
 * about the "Messages Supported" message itself, since this one is guarateeed
 * to be always understood
 */
void vmsg_send_messages_supported(struct gnutella_node *n)
{
	struct gnutella_msg_vendor *vms = (struct gnutella_msg_vendor *) v_tmp;
	guint16 count = G_N_ELEMENTS(vmsg_map) - 1;
	guint32 paysize = sizeof(vms->data) + sizeof(count) + count * VMS_ITEM_SIZE;
	guint32 msgsize = paysize + sizeof(vms->header);
	guchar *payload;
	gint i;

	g_assert(sizeof(v_tmp) >= msgsize);

	vmsg_fill_header(&vms->header, paysize);
	payload = vmsg_fill_type(&vms->data, T_0000, 0, 0);

	/*
	 * First 2 bytes is the number of entries in the vector.
	 */

	WRITE_GUINT16_LE(count, payload);
	payload += 2;

	/*
	 * Fill one entry per message type supported, excepted ourselves.
	 */

	for (i = 0; i < G_N_ELEMENTS(vmsg_map); i++) {
		struct vmsg_known *msg = &vmsg_map[i];

		if (msg->vendor == T_0000)		/* Don't send info about ourselves */
			continue;

		WRITE_GUINT32_BE(msg->vendor, payload);
		payload += 4;
		WRITE_GUINT16_LE(msg->id, payload);
		payload += 2;
		WRITE_GUINT16_LE(msg->version, payload);
		payload += 2;
	}

	gmsg_sendto_one(n, (guchar *) vms, msgsize);
}

/*
 * handle_hops_flow
 *
 * Handle the "Hops Flow" message.
 */
static void handle_hops_flow(struct gnutella_node *n,
	guint16 version, guchar *payload, gint size)
{
	guint8 hops;

	g_assert(version <= 1);

	if (size != 1) {
		g_warning("got improper Hops Flow (payload has %d bytes) from %s <%s>",
			size, node_ip(n), node_vendor(n));
		return;
	}

	hops = *payload;
	node_set_hops_flow(n, hops);
}

/*
 * vmsg_send_hops_flow
 *
 * Send an "Hops Flow" message to specified node.
 */
void vmsg_send_hops_flow(struct gnutella_node *n, guint8 hops)
{
	struct gnutella_msg_vendor *hflow = (struct gnutella_msg_vendor *) v_tmp;
	guint32 paysize = sizeof(hops) + sizeof(hflow->data);
	guint32 msgsize = paysize + sizeof(hflow->header);
	guchar *payload;

	g_assert(sizeof(v_tmp) >= msgsize);

	vmsg_fill_header(&hflow->header, paysize);
	payload = vmsg_fill_type(&hflow->data, T_BEAR, 4, 1);
	*payload = hops;

	/*
	 * Send the message as a control message, so that it gets sent ASAP.
	 */

	gmsg_ctrl_sendto_one(n, (guchar *) hflow, msgsize);
}

/*
 * handle_connect_back
 *
 * Handle the "Connect Back" message.
 */
static void handle_connect_back(struct gnutella_node *n,
	guint16 version, guchar *payload, gint size)
{
	guint16 port;

	g_assert(version <= 1);

	if (size != 2) {
		g_warning("got improper Connect Back (payload has %d byte%ss) "
			"from %s <%s>", size, size == 1 ? "" : "s",
			node_ip(n), node_vendor(n));
		return;
	}

	READ_GUINT16_LE(payload, port);

	if (port == 0) {
		g_warning("got improper port #%d in Connect Back from %s <%s>",
			port, node_ip(n), node_vendor(n));
		return;
	}

	node_connect_back(n, port);
}

/*
 * vmsg_send_connect_back
 *
 * Send an "Connect Back" message to specified node, telling it to connect
 * back to us on the specified port.
 */
void vmsg_send_connect_back(struct gnutella_node *n, guint16 port)
{
	struct gnutella_msg_vendor *cbak = (struct gnutella_msg_vendor *) v_tmp;
	guint32 paysize = sizeof(port) + sizeof(cbak->data);
	guint32 msgsize = paysize + sizeof(cbak->header);
	guchar *payload;

	g_assert(sizeof(v_tmp) >= msgsize);

	vmsg_fill_header(&cbak->header, paysize);
	payload = vmsg_fill_type(&cbak->data, T_BEAR, 7, 1);

	WRITE_GUINT16_LE(port, payload);

	gmsg_sendto_one(n, (guchar *) cbak, msgsize);
}

