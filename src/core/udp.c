/*
 * $Id$
 *
 * Copyright (c) 2004, Raphael Manfredi
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
 * @file
 *
 * Handling UDP datagrams.
 */

#include "common.h"

RCSID("$Id$");

#include "udp.h"
#include "gmsg.h"
#include "inet.h"
#include "nodes.h"
#include "sockets.h"
#include "bsched.h"
#include "gnet_stats.h"
#include "gnutella.h"
#include "mq_udp.h"
#include "routing.h"
#include "pcache.h"

#include "if/gnet_property_priv.h"

#include "lib/endian.h"
#include "lib/misc.h"
#include "lib/override.h"		/* Must be the last header included */

/**
 * Look whether the datagram we received is a valid Gnutella packet.
 */
static gboolean
udp_is_valid_gnet(struct gnutella_socket *s)
{
	struct gnutella_node *n = node_udp_get_ip_port(s->ip, s->port);
	struct gnutella_header *head;
	gchar *msg;
	guint32 size;				/* Payload size, from the Gnutella message */

	if (s->pos < GTA_HEADER_SIZE) {
		msg = "Too short";
		goto not;
	}

	head = (struct gnutella_header *) s->buffer;
	READ_GUINT32_LE(head->size, size);

	n->header = *head;						/* Struct copy */
	n->size = s->pos - GTA_HEADER_SIZE;		/* Payload size if Gnutella msg */

	gnet_stats_count_received_header(n);
	gnet_stats_count_received_payload(n);

	if (size + GTA_HEADER_SIZE != s->pos) {
		msg = "Size mismatch";
		goto not;
	}

	/*
	 * We only support a subset of Gnutella message from UDP.  In particular,
	 * messages like HSEP data, BYE or QRP are not expected!
	 */

	switch (head->function) {
	case GTA_MSG_INIT:
	case GTA_MSG_INIT_RESPONSE:
	case GTA_MSG_VENDOR:
	case GTA_MSG_STANDARD:
	case GTA_MSG_PUSH_REQUEST:
	case GTA_MSG_SEARCH_RESULTS:
		break;
	case GTA_MSG_SEARCH:
		msg = "Queries not yet processed from UDP";
		goto drop;			/* XXX don't handle GUESS queries for now */
	default:
		msg = "Gnutella message not processed from UDP";
		goto drop;
	}

	return TRUE;

drop:
	gnet_stats_count_dropped(n, MSG_DROP_UNEXPECTED);
	/* FALL THROUGH */

not:
	if (udp_debug) {
		g_warning("got invalid Gnutella packet from UDP: %s", msg);
		if (s->pos)
			dump_hex(stderr, "UDP datagram", s->buffer, s->pos);
	}

	return FALSE;
}

/**
 * Notification from the socket layer that we got a new datagram.
 */
void
udp_received(struct gnutella_socket *s)
{
	inet_udp_got_incoming(s->ip);
	bws_udp_count_read(s->pos);

	if (!udp_is_valid_gnet(s))
		return;

	/*
	 * Process message as if it had been received from regular Gnet by
	 * another node, only we'll use a special "pseudo UDP node" as origin.
	 */

	if (udp_debug > 19)
		printf("UDP got %s from %s\n", gmsg_infostr_full(s->buffer),
			ip_port_to_gchar(s->ip, s->port));

	node_udp_process(s);
}

/**
 * Send a reply datagram to the specified node, made of `len' bytes from `buf'.
 */
void udp_send_reply(gnutella_node_t *n, gpointer buf, gint len)
{
	g_assert(NODE_IS_UDP(n));

	mq_udp_node_putq(n->outq, gmsg_to_pmsg(buf, len), n);
}

/**
 * Send a Gnutella ping to the specified host via UDP, using the
 * specified MUID.
 */
void
udp_connect_back(guint32 ip, guint16 port, const gchar *muid)
{
	struct gnutella_msg_init *m;
	struct gnutella_node *n = node_udp_get_ip_port(ip, port);

	if (!enable_udp)
		return;

	m = build_ping_msg(muid, 1);

	mq_udp_node_putq(n->outq, gmsg_to_pmsg(m, sizeof(*m)), n);

	if (udp_debug > 19)
		printf("UDP queued connect-back PING %s to %s\n",
			guid_hex_str(muid), ip_port_to_gchar(ip, port));
}

/*
 * Send a Gnutella ping to the specified host.
 */
void
udp_send_ping(guint32 ip, guint16 port)
{
	struct gnutella_msg_init *m;
	struct gnutella_node *n = node_udp_get_ip_port(ip, port);

	if (!enable_udp)
		return;

	m = build_ping_msg(NULL, 1);

	mq_udp_node_putq(n->outq, gmsg_to_pmsg(m, sizeof(*m)), n);
}

/* vi: set ts=4: */

