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

#include "if/gnet_property_priv.h"

#include "lib/endian.h"
#include "lib/misc.h"
#include "lib/override.h"		/* Must be the last header included */

/**
 * Get a "fake" UDP node for the specified IP:port, matching NODE_IS_UDP().
 * @return pointer to static data
 */
static gnutella_node_t *
udp_fake_node(guint32 ip, guint16 port)
{
	static struct gnutella_node fake_node;
	struct gnutella_node *n;

	fake_node.peermode = NODE_P_UDP;
	fake_node.ip = ip;
	fake_node.port = ip;

	n = &fake_node;
	g_assert(NODE_IS_UDP(n));

	return n;
}

/**
 * Look whether the datagram we received is a valid Gnutella packet.
 */
static gboolean
udp_is_valid_gnet(struct gnutella_socket *s)
{
	struct gnutella_node *n = udp_fake_node(s->ip, s->port);
	struct gnutella_header *head;
	gchar *msg;
	guint32 size;

	if (s->pos < sizeof(struct gnutella_header)) {
		msg = "Too short";
		goto not;
	}

	head = (struct gnutella_header *) s->buffer;
	READ_GUINT32_LE(head->size, size);

	n->header = *head;			/* Struct copy */
	n->size = size;

	gnet_stats_count_received_header(n);
	gnet_stats_count_received_payload(n);

	if (size + sizeof(struct gnutella_header) != s->pos) {
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
		return FALSE;		/* XXX don't handle GUESS queries for now */
	default:
		msg = "Invalid Gnutella message type";
		goto not;
	}

	return TRUE;

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

	if (!udp_is_valid_gnet(s))
		return;

	if (udp_debug > 19)
		printf("UDP got %s from %s\n", gmsg_infostr_full(s->buffer),
			ip_port_to_gchar(s->ip, s->port));

	node_udp_process(s);
}

/**
 * Send a datagram to the specified IP:port, made of `len' bytes from `buf'.
 * This datagram is meant to be a complete Gnutella message.
 *
 * From a statistics bookkeeping point of view, this routine assumes the
 * message it is about to send has already been accounted for as "queued".
 * It will be counted as "sent" upon transmit success.
 *
 * @return success status.
 */
static gboolean
udp_sendto(guint32 ip, guint16 port, gpointer buf, gint len)
{
	struct sockaddr_in addr;
	gint alen = sizeof(addr);
	gint rw;
	struct gnutella_node *n = udp_fake_node(ip, port);

	if (s_udp_listen == NULL) {
		if (udp_debug)
			g_warning("can't send %d-byte datagram to %s: no UDP socket",
				len, ip_port_to_gchar(ip, port));
		return FALSE;
	}

	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(ip);
	addr.sin_port = htons(port);

	rw = sendto(s_udp_listen->file_desc, buf, len, MSG_DONTWAIT,
		(const struct sockaddr *) &addr, alen);

	if (rw == -1) {
		g_warning("can't send %d-byte datagram to %s: %s",
			len, ip_port_to_gchar(ip, port), g_strerror(errno));
		return FALSE;
	}

	/*
	 * The following should NEVER happen, since UDP preserves write
	 * boundaries: write operations are therefore necessarily atomic!
	 * Hence it's a fatal error.
	 */

	if (rw != len)
		g_error("truncated %d-byte datagram to %s down to %d bytes",
			len, ip_port_to_gchar(ip, port), rw);

	bws_udp_count_written(rw);

	gnet_stats_count_sent(n, gmsg_function(buf), gmsg_hops(buf), len);

	return TRUE;
}

/**
 * Send a reply datagram to the specified node, made of `len' bytes from `buf'.
 */
void udp_send_reply(gnutella_node_t *n, gpointer buf, gint len)
{
	g_assert(NODE_IS_UDP(n));

	gnet_stats_count_queued(n, gmsg_function(buf), gmsg_hops(buf), len);
	(void) udp_sendto(n->ip, n->port, buf, len);
}

/**
 * Send a Gnutella ping to the specified host via UDP, using the
 * specified MUID.
 */
void
udp_connect_back(guint32 ip, guint16 port, const gchar *muid)
{
	struct gnutella_msg_init m;
	gboolean ok;
	struct gnutella_node *n = udp_fake_node(ip, port);

	memcpy(m.header.muid, muid, 16);
	m.header.function = GTA_MSG_INIT;
	m.header.ttl = 1;
	m.header.hops = 0;

	WRITE_GUINT32_LE(0, m.header.size);

	gnet_stats_count_queued(n, m.header.function, m.header.hops, sizeof(m));
	ok = udp_sendto(ip, port, (gchar *) &m, sizeof(m));

	if (ok && udp_debug > 19)
		printf("UDP sent connect-back PING %s to %s\n",
			guid_hex_str(muid), ip_port_to_gchar(ip, port));
}

/* vi: set ts=4: */

