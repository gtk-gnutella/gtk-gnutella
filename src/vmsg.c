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

#include "vmsg.h"
#include "vendors.h"
#include "nodes.h"
#include "gmsg.h"
#include "routing.h"	/* For message_set_muid() */

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

	if (vm == NULL)
		return;

	(*vm->handler)(n, version, n->data + sizeof(*v), n->size - sizeof(*v));
}

/*
 * vmsg_fill_header
 *
 * Fill common message header part for all vendor-specific messages.
 */
static void vmsg_fill_header(struct gnutella_header *header, guint32 size)
{
	message_set_muid(header, GTA_MSG_VENDOR);
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
	// XXX
	g_warning("handle_messages_supported not implemented yet!");
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
			size, node_ip(n), n->vendor == NULL ? n->vendor : "????");
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
			node_ip(n), n->vendor ? n->vendor : "????");
		return;
	}

	READ_GUINT16_LE(payload, port);

	if (port == 0) {
		g_warning("got improper port #%d in Connect Back from %s <%s>",
			port, node_ip(n), n->vendor ? n->vendor : "????");
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

	gmsg_ctrl_sendto_one(n, (guchar *) cbak, msgsize);
}

