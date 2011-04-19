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
#include "pcache.h"
#include "routing.h"
#include "sockets.h"
#include "udp.h"

#include "if/gnet_property_priv.h"

#include "lib/aging.h"
#include "lib/atoms.h"
#include "lib/endian.h"
#include "lib/hashlist.h"
#include "lib/random.h"
#include "lib/walloc.h"

#include "lib/override.h"		/* Must be the last header included */

#define UDP_PING_FREQ	60		/**< At most 1 ping per minute to a given IP */

static aging_table_t *udp_aging_pings;

/**
 * Look whether the datagram we received is a valid Gnutella packet.
 *
 * @return NULL if not valid, the UDP node that got the message otherwise
 */
static gnutella_node_t *
udp_is_valid_gnet(struct gnutella_socket *s, gboolean dht, gboolean truncated)
{
	struct gnutella_node *n;
	gnutella_header_t *head;
	const char *msg;
	const void *payload;
	guint16 size;				/**< Payload size, from the Gnutella message */

	n = dht ? node_dht_get_addr_port(s->addr, s->port) :
		node_udp_get_addr_port(s->addr, s->port);

	/*
	 * If we can't get a proper UDP node for this address/port combination,
	 * ignore the message.
	 */

	if (NULL == n) {
		msg = "Invalid address/port combination";
		goto not;
	}

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
	payload = ptr_add_offset(s->buf, GTA_HEADER_SIZE);

	gnet_stats_count_received_header(n);
	gnet_stats_count_received_payload(n, payload);

	/*
	 * If the message was truncated, then there is also going to be a
	 * size mismatch, but we want to flag truncated messages as being
	 * "too large" because this is mainly why we reject them.  They may
	 * be legitimate Gnutella packets, too bad.
	 */

	if (truncated) {
		msg = "Truncated (too large?)";
		goto too_large;
	}

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
		goto not;		/* Probably just garbage */
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
	case GTA_MSG_DHT:
		return n;
	case GTA_MSG_SEARCH:
		if (
			NODE_P_LEAF != GNET_PROPERTY(current_peermode) &&
			GNET_PROPERTY(enable_guess)
		) {
			return n;	/* GUESS query accepted */
		}
		msg = "Query from UDP refused";
		goto drop;
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
		g_warning("got invalid Gnutella packet (%u byte%s) "
			"\"%s\" %sfrom UDP (%s): %s",
			(unsigned) s->pos, 1 == s->pos ? "" : "s",
			gmsg_infostr_full(s->buf, s->pos),
			truncated ? "(truncated) " : "",
			host_addr_port_to_string(s->addr, s->port), msg);
		if (s->pos)
			dump_hex(stderr, "UDP datagram", s->buf, s->pos);
	}

	return NULL;
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
	gnutella_node_t *n;
	gboolean bogus = FALSE;
	gboolean dht = FALSE;

	/*
	 * This must be regular Gnutella / DHT traffic.
	 */

	inet_udp_got_incoming(s->addr);

	/*
	 * Discriminate between Gnutella UDP and DHT messages, so that we
	 * can account received data with the proper bandwidth scheduler.
	 */

	if (s->pos >= GTA_HEADER_SIZE)
		dht = GTA_MSG_DHT == gnutella_header_get_function(s->buf);

	bws_udp_count_read(s->pos, dht);

	/*
	 * If we get traffic from a bogus IP (unroutable), warn, for now.
	 */

	if (bogons_check(s->addr)) {
		bogus = TRUE;

		if (GNET_PROPERTY(udp_debug)) {
			g_warning("UDP %sdatagram (%d byte%s) received from bogus IP %s",
				truncated ? "truncated " : "",
				(int) s->pos, s->pos == 1 ? "" : "s",
				host_addr_to_string(s->addr));
		}
		gnet_stats_count_general(GNR_UDP_BOGUS_SOURCE_IP, 1);
	}

	if (!(n = udp_is_valid_gnet(s, dht, truncated)))
		return;

	/*
	 * Process message as if it had been received from regular Gnet by
	 * another node, only we'll use a special "pseudo UDP node" as origin.
	 */

	if (GNET_PROPERTY(udp_debug) > 19)
		g_debug("UDP got %s from %s%s", gmsg_infostr_full(s->buf, s->pos),
			bogus ? "BOGUS " : "", host_addr_port_to_string(s->addr, s->port));

	node_udp_process(n, s);
}

/**
 * Send a datagram to the specified node, made of `len' bytes from `buf',
 * forming a valid Gnutella message.
 */
void
udp_send_msg(const gnutella_node_t *n, gconstpointer buf, int len)
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
	if (NULL == n || NULL == n->outq) {
		pmsg_free(mb);
		/* emit warnings */
		g_return_if_fail(n);
		g_return_if_fail(n->outq);
		g_assert_not_reached();
	}
	g_assert(NODE_IS_UDP(n));
	mq_udp_node_putq(n->outq, mb, n);
}

/**
 * Send a message to the DHT node through UDP.
 *
 * It is up to the caller to clone the message if needed, otherwise the
 * node's queue becomes the sole owner of the message and will pmsg_free() it.
 */
void
udp_dht_send_mb(const gnutella_node_t *n, pmsg_t *mb)
{
	if (NULL == n || NULL == n->outq) {
		pmsg_free(mb);
		/* emit warnings */
		g_return_if_fail(n);
		g_return_if_fail(n->outq);
		g_assert_not_reached();
	}
	g_assert(NODE_IS_DHT(n));
	mq_udp_node_putq(n->outq, mb, n);
}

/**
 * Send a Gnutella ping to the specified host via UDP, using the
 * specified MUID.
 */
void
udp_connect_back(const host_addr_t addr, guint16 port, const struct guid *muid)
{
	if (udp_send_ping(muid, addr, port, FALSE)) {
		if (GNET_PROPERTY(udp_debug) > 19)
			g_debug("UDP queued connect-back PING %s to %s\n",
				guid_hex_str(muid), host_addr_port_to_string(addr, port));
	}
}

/***
 *** Management of "UDP ping RPCs", whereby we register a ping event and
 *** expect a pong back within a hardwired timeout.
 ***/

struct udp_ping_cb {
	udp_ping_cb_t cb;
	void *data;
	unsigned multiple:1;
	unsigned got_reply:1;
};

struct udp_ping {
	struct guid muid;	/* MUST be at offset zero (for hashing function) */
	time_t added;		/**< Timestamp of insertion */
	struct udp_ping_cb *callback;	/**< Optional: callback description */
};

static const time_delta_t UDP_PING_TIMEOUT	   = 30;	/**< seconds */
static const size_t		  UDP_PING_MAX 		   = 1024;	/**< amount to track */
static const int 		  UDP_PING_PERIODIC_MS = 10000;	/**< milliseconds */

static hash_list_t *udp_pings;	/**< Tracks send/forwarded UDP Pings */
static cevent_t *udp_ping_ev;	/**< Monitoring event */

static inline void
udp_ping_free(struct udp_ping *ping)
{
	WFREE_NULL(ping->callback, sizeof *ping->callback);
	wfree(ping, sizeof *ping);
}

/**
 * Expire registered pings.
 *
 * @param forced	TRUE if we're shutdowning and want to cleanup
 */
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
			if (ping->callback) {
				(*ping->callback->cb)(
					ping->callback->got_reply ?
						UDP_PING_EXPIRED : UDP_PING_TIMEDOUT,
					ping->callback->data);
			}
		}
		hash_list_remove(udp_pings, ping);
		udp_ping_free(ping);
	}
}

/**
 * Callout queue callback to perform periodic monitoring of the
 * registered pings.
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

static gboolean
udp_ping_register(const struct guid *muid,
	udp_ping_cb_t cb, void *data, gboolean multiple)
{
	struct udp_ping *ping;
	guint length;

	g_assert(muid);
	g_return_val_if_fail(udp_pings, FALSE);

	if (hash_list_contains(udp_pings, muid)) {
		/* Probably a duplicate */
		return FALSE;
	}

	/* random early drop */
	length = hash_list_length(udp_pings);
	if (length >= UDP_PING_MAX) {
		return FALSE;
	} else if (length > (UDP_PING_MAX / 4) * 3) {
		if ((random_u32() % UDP_PING_MAX) < length)
			return FALSE;
	}

	ping = walloc(sizeof *ping);
	ping->muid = *muid;
	ping->added = tm_time();
	if (cb != NULL) {
		ping->callback = walloc0(sizeof *ping->callback);
		ping->callback->cb = cb;
		ping->callback->data = data;
		ping->callback->multiple = booleanize(multiple);
	} else {
		ping->callback = NULL;
	}
	hash_list_append(udp_pings, ping);
	return TRUE;
}

/**
 * Upon reception of an UDP pong, check whether we had a matching registered
 * ping bearing the given MUID.
 *
 * If there was a callback atttached to the reception of a reply, invoke it
 * before returning.
 *
 * @return TRUE if indeed this was a reply for a ping we sent.
 */
gboolean
udp_ping_is_registered(const struct guid *muid)
{
	g_assert(muid);

	if (udp_pings) {
		struct udp_ping *ping;

		ping = hash_list_remove(udp_pings, muid);
		if (ping) {
			if (ping->callback) {
				(*ping->callback->cb)(UDP_PING_REPLY, ping->callback->data);
				if (ping->callback->multiple) {
					ping->callback->got_reply = TRUE;
					ping->added = tm_time();	/* Delay expiration */
					hash_list_append(udp_pings, ping);
				} else {
					udp_ping_free(ping);
				}
			} else {
				udp_ping_free(ping);
			}
			return TRUE;
		}
	}
	return FALSE;
}

/**
 * Send a Gnutella ping message to the specified host.
 *
 * @param m			the Ping message to send
 * @param size		size of the Ping message, in bytes
 * @param addr		address to which ping should be sent
 * @param port		port number
 * @param cb		if non-NULL, callback to invoke on reply or timeout
 * @param arg		additional callback argument
 * @param multiple	whether multiple replies (Pongs) are expected
 *
 * @return TRUE if we sent the ping, FALSE it we throttled it.
 */
static gboolean
udp_send_ping_with_callback(
	gnutella_msg_init_t *m, guint32 size,
	const host_addr_t addr, guint16 port,
	udp_ping_cb_t cb, void *arg, gboolean multiple)
{
	struct gnutella_node *n = node_udp_get_addr_port(addr, port);

	if (n != NULL) {
		if (udp_ping_register(gnutella_header_get_muid(m), cb, arg, multiple)) {
			aging_insert(udp_aging_pings,
				wcopy(&addr, sizeof addr), GUINT_TO_POINTER(1));
			udp_send_msg(n, m, size);
			return TRUE;
		}
	}
	return FALSE;
}

/**
 * Send a new Gnutella ping message to the specified host.
 *
 * @param muid		the MUID to use (allocated randomly if NULL)
 * @param addr		address to which ping should be sent
 * @param port		port number
 * @param uhc_ping	if TRUE, include the "SCP" GGEP extension
 *
 * @return TRUE if we sent the ping, FALSE it we throttled it.
 */
gboolean
udp_send_ping(const struct guid *muid, const host_addr_t addr, guint16 port,
	gboolean uhc_ping)
{
	gnutella_msg_init_t *m;
	guint32 size;

	/*
	 * Don't send too frequent pings: they may throttle us anyway.
	 */

	if (aging_lookup(udp_aging_pings, &addr)) {
		if (GNET_PROPERTY(udp_debug) > 1) {
			g_warning("UDP throttling %sping to %s",
				uhc_ping ? "UHC " : "", host_addr_to_string(addr));
		}
		return FALSE;
	}

	m = build_ping_msg(muid, 1, uhc_ping, &size);
	return udp_send_ping_with_callback(m, size, addr, port, NULL, NULL, FALSE);
}

/**
 * Send given Gnutella ping message to the host, monitoring replies and
 * timeouts through specified callback.
 *
 * @param m			the Ping message to send
 * @param size		size of the Ping message, in bytes
 * @param addr		address to which ping should be sent
 * @param port		port number
 * @param cb		callback to invoke on reply or timeout
 * @param arg		additional callback argument
 * @param multiple	whether multiple replies (Pongs) are expected
 *
 * @return TRUE if we sent the ping, FALSE it we throttled it.
 */
gboolean
udp_send_ping_callback(
	gnutella_msg_init_t *m, guint32 size,
	const host_addr_t addr, guint16 port,
	udp_ping_cb_t cb, void *arg, gboolean multiple)
{
	g_assert(cb != NULL);

	return udp_send_ping_with_callback(m, size, addr, port, cb, arg, multiple);
}

/***
 *** Init / shutdown
 ***/

/**
 * UDP layer startup
 */
void
udp_init(void)
{
	/*
	 * Limit sending of UDP pings to 1 per UDP_PING_FREQ seconds.
	 */

	udp_aging_pings = aging_make(UDP_PING_FREQ,
		host_addr_hash_func, host_addr_eq_func, wfree_host_addr);

	udp_pings = hash_list_new(guid_hash, guid_eq);
	udp_ping_timer(callout_queue, NULL);
}

/**
 * Final cleanup when application terminates.
 */
void
udp_close(void)
{
	if (udp_pings) {
		udp_ping_expire(TRUE);
		hash_list_free(&udp_pings);
	}

	aging_destroy(&udp_aging_pings);
}

/* vi: set ts=4 sw=4 cindent: */
