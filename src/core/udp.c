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
 * @ingroup core
 * @file
 *
 * Handling UDP datagrams.
 *
 * @author Raphael Manfredi
 * @date 2004
 */

#include "common.h"

RCSID("$Id$")

#include "bogons.h"
#include "bsched.h"
#include "gmsg.h"
#include "gnet_stats.h"
#include "gnutella.h"
#include "inet.h"
#include "mq_udp.h"
#include "nodes.h"
#include "ntp.h"
#include "pcache.h"
#include "routing.h"
#include "sockets.h"
#include "udp.h"

#include "if/gnet_property_priv.h"

#include "lib/atoms.h"
#include "lib/endian.h"
#include "lib/hashlist.h"
#include "lib/misc.h"
#include "lib/walloc.h"

#include "lib/override.h"		/* Must be the last header included */

/**
 * Look whether the datagram we received is a valid Gnutella packet.
 */
static gboolean
udp_is_valid_gnet(struct gnutella_socket *s, gboolean truncated)
{
	struct gnutella_node *n = node_udp_get_addr_port(s->addr, s->port);
	gnutella_header_t *head;
	const gchar *msg;
	guint16 size;				/**< Payload size, from the Gnutella message */

	g_return_val_if_fail(n, FALSE);

	if (s->pos < GTA_HEADER_SIZE) {
		msg = "Too short";
		goto not;
	}

	/*
	 * We have enough to account for packet reception.
	 * Note that packet could be garbage at this point.
	 */

	head = cast_to_gpointer(s->buf);
	memcpy(n->header, head, sizeof n->header);
	n->size = s->pos - GTA_HEADER_SIZE;		/* Payload size if Gnutella msg */

	gnet_stats_count_received_header(n);
	gnet_stats_count_received_payload(n);

	/*
	 * Message sizes are architecturally limited to 64K bytes.
	 *
	 * We don't ensure the leading bits are zero in the size field because
	 * this constraint we put allows us to use those bits for flags in
	 * future extensions.
	 *
	 * The downside is that we have only 3 bytes (2 bytes for the size and
	 * 1 byte for the function type) to identify a valid Gnutella packet.
	 */

	switch (gmsg_size_valid(head, &size)) {
	case GMSG_VALID:
	case GMSG_VALID_MARKED:
		break;
	case GMSG_VALID_NO_PROCESS:
		msg = "Header flags undefined for now";
		goto drop;
	case GMSG_INVALID:
		msg = "Invalid size (greater than 64 KiB without flags)";
		goto too_large;
	}

	/*
	 * If the message was truncated, then there is also going to be a
	 * size mismatch, but we want to flag truncated messages as being
	 * "too large" because this is mainly why we reject them.  They may
	 * be legitimate Gnutella packets, too bad.
	 */

	if (truncated) {
		msg = "Too large (truncated)";
		goto too_large;
	}

	if ((size_t) size + GTA_HEADER_SIZE != s->pos) {
		msg = "Size mismatch";
		goto not;
	}

	/*
	 * We only support a subset of Gnutella message from UDP.  In particular,
	 * messages like HSEP data, BYE or QRP are not expected!
	 */

	switch (gnutella_header_get_function(head)) {
	case GTA_MSG_INIT:
	case GTA_MSG_INIT_RESPONSE:
	case GTA_MSG_VENDOR:
	case GTA_MSG_STANDARD:
	case GTA_MSG_PUSH_REQUEST:
	case GTA_MSG_SEARCH_RESULTS:
	case GTA_MSG_RUDP:
		return TRUE;
	case GTA_MSG_SEARCH:
		msg = "Queries not yet processed from UDP";
		goto drop;			/* XXX don't handle GUESS queries for now */
	}
	msg = "Gnutella message not processed from UDP";

drop:
	gnet_stats_count_dropped(n, MSG_DROP_UNEXPECTED);
	gnet_stats_count_general(GNR_UDP_UNPROCESSED_MESSAGE, 1);
	goto log;

too_large:
	gnet_stats_count_dropped(n, MSG_DROP_TOO_LARGE);
	gnet_stats_count_general(GNR_UDP_UNPROCESSED_MESSAGE, 1);
	goto log;

not:
	gnet_stats_count_general(GNR_UDP_ALIEN_MESSAGE, 1);
	/* FALL THROUGH */

log:
	if (GNET_PROPERTY(udp_debug)) {
		g_warning("got invalid Gnutella packet from UDP (%s): %s",
			host_addr_port_to_string(s->addr, s->port), msg);
		if (s->pos)
			dump_hex(stderr, "UDP datagram", s->buf, s->pos);
	}

	return FALSE;
}

/**
 * Notification from the socket layer that we got a new datagram.
 *
 * If `truncated' is true, then the message was too large for the
 * socket buffer.
 */
void
udp_received(struct gnutella_socket *s, gboolean truncated)
{
	gboolean bogus = FALSE;

	/*
	 * If reply comes from the NTP port, notify that they're running NTP.
	 */

	if (NTP_PORT == s->port) {
		host_addr_t addr;
		gboolean got_reply = FALSE;
		
		if (!host_addr_convert(s->addr, &addr, NET_TYPE_IPV4))
			addr = s->addr;

		switch (host_addr_net(addr)) {
		case NET_TYPE_IPV4:
			got_reply = 0x7f000001 == host_addr_ipv4(addr); /* 127.0.0.1:123 */
			break;
		case NET_TYPE_IPV6:
			/* Only the loopback address (::1) qualifies as private */
			got_reply = is_private_addr(addr); /* [::1]:123 */
			break;
		case NET_TYPE_LOCAL:
		case NET_TYPE_NONE:
			g_assert_not_reached();
		}
		if (got_reply) {
			g_message("NTP detected at %s", host_addr_to_string(addr));
			ntp_got_reply(s);
			return;
		}
		/* FALL THROUGH -- reply did not come from localhost */
	}

	/*
	 * This must be regular Gnutella traffic then.
	 */

	inet_udp_got_incoming(s->addr);
	bws_udp_count_read(s->pos);

	/*
	 * If we get traffic from a bogus IP (unroutable), warn, for now.
	 */

	if (bogons_check(s->addr)) {
		bogus = TRUE;

		if (GNET_PROPERTY(udp_debug)) {
			g_warning("UDP %sdatagram (%d byte%s) received from bogus IP %s",
				truncated ? "truncated " : "",
				(gint) s->pos, s->pos == 1 ? "" : "s",
				host_addr_to_string(s->addr));
		}
		gnet_stats_count_general(GNR_UDP_BOGUS_SOURCE_IP, 1);
	}

	if (!udp_is_valid_gnet(s, truncated))
		return;

	/*
	 * Process message as if it had been received from regular Gnet by
	 * another node, only we'll use a special "pseudo UDP node" as origin.
	 */

	if (GNET_PROPERTY(udp_debug) > 19)
		g_message("UDP got %s from %s%s", gmsg_infostr_full(s->buf),
			bogus ? "BOGUS " : "", host_addr_port_to_string(s->addr, s->port));

	node_udp_process(s);
}

/**
 * Send a datagram to the specified node, made of `len' bytes from `buf',
 * forming a valid Gnutella message.
 */
void
udp_send_msg(const gnutella_node_t *n, gconstpointer buf, gint len)
{
	g_assert(NODE_IS_UDP(n));
	g_return_if_fail(n->outq);

	mq_udp_node_putq(n->outq, gmsg_to_pmsg(buf, len), n);
}

/**
 * Send a message to specified UDP node.
 *
 * It is up to the caller to clone the message if needed, otherwise the
 * node's queue becomes the sole owner of the message and will pmsg_free() it.
 */
void
udp_send_mb(const gnutella_node_t *n, pmsg_t *mb)
{
	g_assert(NODE_IS_UDP(n));
	g_return_if_fail(n->outq);

	mq_udp_node_putq(n->outq, mb, n);
}

/**
 * Send a Gnutella ping to the specified host via UDP, using the
 * specified MUID.
 */
void
udp_connect_back(const host_addr_t addr, guint16 port, const gchar *muid)
{
	if (udp_send_ping(muid, addr, port, FALSE)) {
		if (GNET_PROPERTY(udp_debug) > 19)
			g_message("UDP queued connect-back PING %s to %s\n",
				guid_hex_str(muid), host_addr_port_to_string(addr, port));
	}
}

struct udp_ping {
	gchar muid[GUID_RAW_SIZE];	/* MUST be at offset zero */
	time_t added;				/**< Timestamp of insertion */
};

static const time_delta_t UDP_PING_TIMEOUT	    = 30;	/**< seconds */
static const size_t		  UDP_PING_MAX 			= 1024;	/**< amount to track */
static const gint 		  UDP_PING_PERIODIC_MS	= 5000;	/**< milliseconds */

static hash_list_t *udp_pings;	/**< Tracks send/forwarded UDP Pings */
static cevent_t *udp_ping_ev;	/**< Monitoring event */

static inline void
udp_ping_free(struct udp_ping *ping)
{
	wfree(ping, sizeof *ping);
}

static void
udp_ping_expire(gboolean forced)
{
	time_t now;

	g_return_if_fail(udp_pings);

	now = tm_time();
	for (;;) {
		struct udp_ping *ping;
		time_delta_t d;

		ping = hash_list_head(udp_pings);
		if (!ping) {
			break;
		}
		if (!forced) {
			d = delta_time(now, ping->added);
			if (d > 0 && d <= UDP_PING_TIMEOUT) {
				break;
			}
		}
		hash_list_remove(udp_pings, ping);
		udp_ping_free(ping);
	}
}

/**
 * Callout queue callback to perform periodic monitoring of the
 * registered files.
 */
static void
udp_ping_timer(cqueue_t *cq, gpointer unused_udata)
{
	(void) unused_udata;

	/*
	 * Re-install timer for next time.
	 */

	udp_ping_ev = cq_insert(cq, UDP_PING_PERIODIC_MS, udp_ping_timer, NULL);
	udp_ping_expire(FALSE);
}

gboolean
udp_ping_register(const gchar *muid)
{
	static gboolean initialized;
	struct udp_ping *ping;
	guint length;

	g_assert(muid);

	if (!initialized) {
		initialized = TRUE;
		udp_pings = hash_list_new(guid_hash, guid_eq);
		udp_ping_timer(callout_queue, NULL);
	}
	g_return_val_if_fail(udp_pings, FALSE);

	if (hash_list_contains(udp_pings, muid, NULL)) {
		/* Probably a duplicate */
		return FALSE;
	}

	/* random early drop */
	length = hash_list_length(udp_pings);
	if (length >= UDP_PING_MAX) {
		return FALSE;
	} else if (length > (UDP_PING_MAX / 4) * 3) {
		if ((random_raw() % UDP_PING_MAX) < length)
			return FALSE;
	}

	ping = walloc(sizeof *ping);
	memcpy(ping->muid, muid, GUID_RAW_SIZE);
	ping->added = tm_time();
	hash_list_append(udp_pings, ping);
	return TRUE;
}

gboolean
udp_ping_is_registered(const gchar *muid)
{
	g_assert(muid);

	if (udp_pings) {
		struct udp_ping *ping;

		ping = hash_list_remove(udp_pings, muid);
		if (ping) {
			udp_ping_free(ping);
			return TRUE;
		}
	}
	return FALSE;
}

/**
 * Send a Gnutella ping to the specified host.
 */
gboolean
udp_send_ping(const gchar *muid, const host_addr_t addr, guint16 port,
	gboolean uhc_ping)
{
	struct gnutella_node *n = node_udp_get_addr_port(addr, port);

	if (n) {
		gnutella_msg_init_t *m;
		guint32 size;

		m = build_ping_msg(muid, 1, uhc_ping, &size);
		if (udp_ping_register(gnutella_header_get_muid(m))) {
			udp_send_msg(n, m, size);
			return TRUE;
		}
	}
	return FALSE;
}

/* vi: set ts=4 sw=4 cindent: */
