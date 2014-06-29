/*
 * Copyright (c) 2001-2003, Raphael Manfredi
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
 * Pong caching (LimeWire's ping/pong reducing scheme).
 *
 * @author Raphael Manfredi
 * @date 2001-2003
 */

#include "common.h"

#include "pcache.h"

#include "gtk-gnutella.h"		/* For GTA_VENDOR_CODE */

#include "alive.h"
#include "extensions.h"
#include "ggep.h"
#include "ggep_type.h"
#include "gmsg.h"
#include "gnet_stats.h"
#include "guess.h"
#include "hcache.h"
#include "hostiles.h"
#include "hosts.h"
#include "inet.h"
#include "ipp_cache.h"
#include "ipv6-ready.h"
#include "nodes.h"
#include "routing.h"
#include "search.h"	/* For search_query_key_generate() */
#include "settings.h"
#include "share.h" /* For shared_files_scanned() and shared_kbytes_scanned(). */
#include "sockets.h"
#include "udp.h"
#include "uhc.h"
#include "version.h"

#include "if/gnet_property_priv.h"
#include "if/dht/kademlia.h"
#include "if/dht/dht.h"

#include "lib/aging.h"
#include "lib/atoms.h"
#include "lib/endian.h"
#include "lib/glib-missing.h"
#include "lib/gnet_host.h"
#include "lib/hashing.h"
#include "lib/hset.h"
#include "lib/nid.h"
#include "lib/plist.h"
#include "lib/pow2.h"
#include "lib/pslist.h"
#include "lib/random.h"
#include "lib/sectoken.h"
#include "lib/stringify.h"	/* For plural() */
#include "lib/tm.h"
#include "lib/walloc.h"

#include "lib/override.h"	/* Must be the last header included */

#define PCACHE_MAX_FILES	10000000	/**< Arbitrarily large file count */
#define PCACHE_UHC_MAX_IP	30			/**< Max amount of IP:port returned */
#define PCACHE_DHT_MAX_IP	10			/**< Max amount of IP:port returned */
#define PCACHE_TRANSIENT	60			/**< Once every minute */

/**
 * Basic pong information.
 */
struct pong_info {
	host_addr_t addr;				/**< Values from the pong message */
	uint32 port;
	uint32 files_count;
	uint32 kbytes_count;
};

enum ping_flag {
	PING_F_NONE			= 0,		/**< No special ping */
	PING_F_UHC			= (1 << 0),	/**< UHC ping */
	PING_F_UHC_LEAF		= (1 << 1),	/**< UHC ping, wants leaf slots */
	PING_F_UHC_ULTRA	= (1 << 2),	/**< UHC ping, wants ultra slots */
	PING_F_UHC_ANY		= (PING_F_UHC_LEAF | PING_F_UHC_ULTRA),
	PING_F_IP			= (1 << 3),	/**< GGEP IP */
	PING_F_DHTIPP		= (1 << 4),	/**< GGEP DHTIPP, wants DHT hosts */
	PING_F_QK			= (1 << 5),	/**< GGEP QK, wants GUESS Query Key */
	PING_F_GUE			= (1 << 6),	/**< GGEP GUE, wants GUESS hosts in IPP */
	PING_F_IPV6			= (1 << 7),	/**< Will accept IPv6 addresses */
	PING_F_NO_IPV4		= (1 << 8),	/**< Does not want IPv4 addresses */

	PING_LAST_ENUM_FLAG
};

static pong_meta_t local_meta;

/**
 * Compute the proper net type when requesting cached hosts, depending on the
 * ping flags (what the remote party said it wanted).
 */
static host_net_t
ping_net(enum ping_flag flags)
{
	host_net_t net;

	net = HOST_NET_IPV4;
	if (flags & PING_F_NO_IPV4)
		net = HOST_NET_IPV6;
	else if (flags & PING_F_IPV6)
		net = HOST_NET_BOTH;

	return net;
}

/***
 *** Messages
 ***/

/**
 * Sends a ping to given node.
 */
static void
send_ping(gnutella_node_t *n, uint8 ttl)
{
	gnutella_msg_init_t *m;
	uint32 size;

	node_check(n);
	g_assert(!NODE_IS_UDP(n));

	STATIC_ASSERT(GTA_HEADER_SIZE == sizeof *m);	
	m = build_ping_msg(NULL, ttl, FALSE, &size);

	if (NODE_IS_WRITABLE(n)) {
		n->n_ping_sent++;
		gmsg_sendto_one(n, m, size);
	}
}

/**
 * Build ping message, bearing given TTL and MUID.
 *
 * By construction, hops=0 for all pings.
 *
 * @param muid	the MUID to use.  If NULL, a random one will be assigned.
 * @param ttl	the TTL to use in the generated ping.
 * @param uhc	whether to generate an "UHC" ping for a host cache
 * @param size	where the size of the generated message is written.
 *
 * @return pointer to static data, and the size of the message in `size'.
 */
gnutella_msg_init_t *
build_ping_msg(const struct guid *muid, uint8 ttl, bool uhc, uint32 *size)
{
	static union {
		gnutella_msg_init_t s;
		char buf[256];
		uint64 align8;
	} msg_init;
	gnutella_msg_init_t *m = &msg_init.s;
	uint32 sz;

	g_assert(ttl);
	STATIC_ASSERT(sizeof *m <= sizeof msg_init.buf);
	STATIC_ASSERT(GTA_HEADER_SIZE == sizeof *m);

	if (muid)
		gnutella_header_set_muid(m, muid);
	else
		message_set_muid(m, GTA_MSG_INIT);

	gnutella_header_set_function(m, GTA_MSG_INIT);
	gnutella_header_set_ttl(m, ttl);
	gnutella_header_set_hops(m, 0);

	sz = 0;			/* Payload size if no extensions */

	/*
	 * If we're not sending an "alive" ping (TTL=1), then tell them we
	 * support "IPP" groupping in pongs by sending "SCP".  Also include
	 * that if we're building an UDP host cache ping.
	 */

	if (uhc || ttl > 1) {
		uchar *ggep;
		ggep_stream_t gs;
		bool ok;
		char spp;

		ggep = cast_to_pointer(&m[1]);
		ggep_stream_init(&gs, ggep, sizeof msg_init.buf - sizeof *m);
		
		spp = settings_is_leaf() ? 0 : SCP_F_ULTRA;
		spp |= tls_enabled() ? SCP_F_TLS : 0;

		/* IPv6-Ready: just request the addresses we want */

		spp |= settings_running_ipv6() ? SCP_F_IPV6 : 0;
		spp |= settings_running_ipv6_only() ? SCP_F_NO_IPV4 : 0;

		ok = ggep_stream_pack(&gs, GGEP_NAME(SCP), &spp, sizeof spp, 0);
		g_assert(ok);

		/*
		 * Add vendor code if we're building an UDP host cache ping.
		 * This allows the host cache to perform vendor clustering.
		 */

		if (uhc) {
			pong_meta_t *meta = &local_meta;

			ok = ok &&
				ggep_stream_begin(&gs, GGEP_NAME(VC), 0) &&
				ggep_stream_write(&gs, meta->vendor, sizeof meta->vendor) &&
				ggep_stream_write(&gs, &meta->version_ua, 1) &&
				ggep_stream_end(&gs);
			g_assert(ok);
		}

		/*
		 * If DHT is not seeded yet, ask for more hosts through "DHTIPP".
		 */

		if (dht_enabled() && !dht_seeded())
			ggep_stream_pack(&gs, GGEP_NAME(DHTIPP), NULL, 0, 0);

		sz += ggep_stream_close(&gs);
	}

	gnutella_header_set_size(m, sz);

	if (size)
		*size = sz + GTA_HEADER_SIZE;

	return m;
}

/**
 * Build GUESS ping message, bearing given MUID.
 *
 * By construction, hops=0 and TTL=1 for all GUESS pings.
 *
 * @param muid	the MUID to use.  If NULL, a random one will be assigned.
 * @param qk	whether to request query keys
 * @param intro	whether this is an introduction ping
 * @param scp	whether we want more GUESS hosts packed in a Ping "IPP"
 * @param size	where the size of the generated message is written.
 *
 * @return pointer to static data, and the size of the message in `size'.
 */
gnutella_msg_init_t *
build_guess_ping_msg(const struct guid *muid, bool qk, bool intro, bool scp,
	uint32 *size)
{
	static union {
		gnutella_msg_init_t s;
		char buf[256];
		uint64 align8;
	} msg_init;
	gnutella_msg_init_t *m = &msg_init.s;
	uint32 sz;
	uchar *ggep;
	ggep_stream_t gs;
	bool ok;

	g_assert(qk || intro);

	STATIC_ASSERT(sizeof *m <= sizeof msg_init.buf);
	STATIC_ASSERT(GTA_HEADER_SIZE == sizeof *m);

	if (muid)
		gnutella_header_set_muid(m, muid);
	else
		message_set_muid(m, GTA_MSG_INIT);

	gnutella_header_set_function(m, GTA_MSG_INIT);
	gnutella_header_set_ttl(m, 1);
	gnutella_header_set_hops(m, 0);

	sz = 0;			/* Payload size if no extensions */
	ggep = cast_to_pointer(&m[1]);
	ggep_stream_init(&gs, ggep, sizeof msg_init.buf - sizeof *m);

	if (scp) {
		if (qk) {
			char spp;

			/*
			 * A "QK" query with "SCP" requests more GUESS hosts packed in
			 * an "IPP" extension, not sent as separate pongs.
			 *
			 * If "SCP" is not present along "QK", then no extra hosts will
			 * be sent back, only the proper query key in a single pong.
			 */

			spp = settings_is_leaf() ? 0 : SCP_F_ULTRA;
			spp |= tls_enabled() ? SCP_F_TLS : 0;

			/* IPv6-Ready: just request the addresses we want */

			spp |= settings_running_ipv6() ? SCP_F_IPV6 : 0;
			spp |= settings_running_ipv6_only() ? SCP_F_NO_IPV4 : 0;

			ok = ggep_stream_pack(&gs, GGEP_NAME(SCP), &spp, sizeof spp, 0);
			g_assert(ok);
		} else if (!intro || !settings_is_ultra()) {
			/*
			 * An "SCP" request for more GUESS hosts, in the absence of "QK",
			 * is indicated by a "GUE" extension.  Here it's sent empty
			 * because it's not an introduction ping.
			 */

			ggep_stream_pack(&gs, GGEP_NAME(GUE), NULL, 0, 0);
		}
	}

	if (qk) {
		ggep_stream_pack(&gs, GGEP_NAME(QK), NULL, 0, 0);
	}

	/*
	 * This is the GUESS 0.2 "GUE" extension sent with introduction pings:
	 *
	 * - the first byte is the GUESS version, as usual
	 * - the next two bytes are the listening port, in little-endian.
	 *
	 * This is only sent when running in ultrapeer mode.
	 */

	if (intro && settings_is_ultra()) {
		char buf[3];
		poke_u8(&buf[0], (SEARCH_GUESS_MAJOR << 4) | SEARCH_GUESS_MINOR);
		poke_le16(&buf[1], socket_listen_port());
		ggep_stream_pack(&gs, GGEP_NAME(GUE), buf, sizeof buf, 0);
	}

	sz += ggep_stream_close(&gs);

	gnutella_header_set_size(m, sz);

	if (size)
		*size = sz + GTA_HEADER_SIZE;

	return m;
}

/**
 * Are we missing node connections?
 */
static bool
pcache_node_missing(void)
{
	if (node_missing() != 0)
		return TRUE;

	return settings_is_ultra() && node_leaves_missing() != 0;
}

/**
 * Should we answer a ping?
 */
static bool
pcache_can_answer_ping(void)
{
	/*
	 * When we (think we) are firewalled, there is a period when we can answer
	 * pings to make sure we can receive incoming connections.  This logic
	 * is held in inet_can_answer_ping(), and we must ensure we're calling it
	 * when we are flagged as firewalled, regardless of whether we miss
	 * Gnutella connections.
	 */

 	return (GNET_PROPERTY(is_firewalled) || pcache_node_missing()) &&
		inet_can_answer_ping();
}

/**
 * Build pong message.
 *
 * @return pointer to static data, and the size of the message in `size'.
 */
static gnutella_msg_init_response_t *
build_pong_msg(host_addr_t sender_addr, uint16 sender_port,
	uint8 hops, uint8 ttl, const struct guid *muid,
	struct pong_info *info, pong_meta_t *meta, enum ping_flag flags,
	uint32 *size)
{
	static union {
		gnutella_msg_init_response_t s;
		char buf[1024];
		uint64 align8;
	} msg_pong;
	gnutella_msg_init_response_t *pong = &msg_pong.s;
	ggep_stream_t gs;
	uchar *ggep;
	uint32 sz;
	uint32 ipv4;
	bool ipv6_included = FALSE;

	STATIC_ASSERT(37 == sizeof *pong);
	ggep = cast_to_pointer(&pong[1]);

	{
		gnutella_header_t *header = gnutella_msg_init_response_header(pong);

		gnutella_header_set_function(header, GTA_MSG_INIT_RESPONSE);
		gnutella_header_set_hops(header, hops);
		gnutella_header_set_ttl(header, ttl);
		gnutella_header_set_muid(header, muid);
	}

	gnutella_msg_init_response_set_host_port(pong, info->port);
	gnutella_msg_init_response_set_files_count(pong, info->files_count);
	gnutella_msg_init_response_set_kbytes_count(pong, info->kbytes_count);

	/*
	 * IPv6-Ready support: the PONG message is architected with an IPv4 address.
	 * When the address we want to send is an IPv6 one, it needs to be sent
	 * in a GGEP "6" field, the IPv4 being forced to 127.0.0.0.
	 */

	ipv4 = ipv6_ready_advertised_ipv4(info->addr);
	gnutella_msg_init_response_set_host_ip(pong, ipv4);

	sz = sizeof *pong - GTA_HEADER_SIZE;

	/*
	 * Add GGEP meta-data if we have some to propagate.
	 */

	ggep_stream_init(&gs, ggep, sizeof msg_pong.buf - sizeof *pong);

	/*
	 * IPv6-Ready support: No IPv4 address means we need to send the IPv6
	 * address in a GGEP "6" extension.
	 */

	if (ipv6_ready_has_no_ipv4(ipv4) && host_addr_is_ipv6(info->addr)) {
		ggep_stream_pack(&gs, GGEP_NAME(6),
			info->addr.addr.ipv6, sizeof info->addr.addr.ipv6, 0);
		ipv6_included = TRUE;
	}

	/*
	 * Include metadata about the host.
	 */

	if (meta != NULL) {
		if (meta->flags & PONG_META_HAS_VC) {	/* Vendor code */
			(void) (ggep_stream_begin(&gs, GGEP_NAME(VC), 0) &&
			ggep_stream_write(&gs, meta->vendor, sizeof meta->vendor) &&
			ggep_stream_write(&gs, &meta->version_ua, 1) &&
			ggep_stream_end(&gs));
		}

		if (meta->flags & PONG_META_HAS_GUE) {	/* GUESS support */
			ggep_stream_pack(&gs, GGEP_NAME(GUE),
				cast_to_pointer(&meta->guess), 1, 0);
		}

		if (meta->flags & PONG_META_HAS_UP) {	/* Ultrapeer info */
			(void) (ggep_stream_begin(&gs, GGEP_NAME(UP), 0) &&
			ggep_stream_write(&gs, &meta->version_up, 1) &&
			ggep_stream_write(&gs, &meta->leaf_slots, 1) &&
			ggep_stream_write(&gs, &meta->up_slots, 1) &&
			ggep_stream_end(&gs));
		}

		if (meta->flags & PONG_META_HAS_LOC) {	/* Locale preferencing */
			bool ok;

			ok = ggep_stream_begin(&gs, GGEP_NAME(LOC), 0) &&
				ggep_stream_write(&gs, meta->language, 2);

			if (ok && meta->country[0])
				ok = ggep_stream_write(&gs, "_", 1) &&
					ggep_stream_write(&gs, meta->country, 2);

			ok = ok && ggep_stream_end(&gs);
		}

		if (meta->flags & PONG_META_HAS_DU) {	/* Daily average uptime */
			char uptime[sizeof(uint64)];
			uint32 value = MIN(meta->daily_uptime, 86400);
			uint len;

			len = ggept_du_encode(value, uptime, sizeof uptime);
			ggep_stream_pack(&gs, GGEP_NAME(DU), uptime, len, 0);
		}

		/*
		 * Ensure we only include one GGEP "6" extension.
		 */

		if ((meta->flags & PONG_META_HAS_IPV6) && !ipv6_included) {
			ggep_stream_pack(&gs, GGEP_NAME(6),
				host_addr_ipv6(&meta->ipv6_addr), 16, 0);
		}

		if (meta->flags & PONG_META_HAS_TLS) {
			ggep_stream_pack(&gs, GGEP_NAME(TLS), NULL, 0, 0);
		}

		if (meta->flags & PONG_META_HAS_DHT) {
			(void) (ggep_stream_begin(&gs, GGEP_NAME(DHT), 0) &&
			ggep_stream_write(&gs, &meta->dht_major, 1) &&
			ggep_stream_write(&gs, &meta->dht_minor, 1) &&
			ggep_stream_write(&gs, &meta->dht_mode, 1) &&
			ggep_stream_end(&gs));
		}
	}

	/*
	 * If we're replying to an UDP node, and they sent an "SCP" in their
	 * ping, then we're acting as an UDP host cache.  Give them some
	 * fresh pongs of hosts with free slots.
	 *
	 * If there was a "GUE" extension in the ping, we behave as if
	 * there was an "SCP", only we send back GUESS hosts in the "IPP" pong
	 * extension.
	 */

	if (
		(flags & PING_F_UHC) ||
		(GNET_PROPERTY(enable_guess) && (flags & PING_F_GUE))
	) {
		/*
		 * FIXME:
		 * For this first implementation, ignore their desire.  Just
		 * fill a bunch of hosts as we would for an X-Try-Ultrapeer header.
		 */

		gnet_host_t host[PCACHE_UHC_MAX_IP];
		int hcount;
		host_net_t net = ping_net(flags);

		/*
		 * For GUESS 0.2, if there is a "QK" extension in the ping as well,
		 * or a "GUE" extension, then we send back GUESS hosts.
		 */

		if (GNET_PROPERTY(enable_guess) && (flags & (PING_F_QK | PING_F_GUE))) {
			hcount = guess_fill_caught_array(net, TRUE,
				host, PCACHE_UHC_MAX_IP);
		} else {
			hcount = node_fill_ultra(net, host, PCACHE_UHC_MAX_IP);

			/*
			 * If we are missing node connections, be sure to include
			 * ourselves in the list, replacing a random node from the
			 * returned set.
			 */

			if (pcache_can_answer_ping()) {
				uint idx = hcount != 0 ? random_value(hcount - 1) : 0;
				gnet_host_set(&host[idx],
					listen_addr_primary(), socket_listen_port());
			}
		}

		if (hcount > 0) {
			gnet_host_t evec[2];

			/*
			 * Skip hosts that have already been included in the pong
			 * info part or which correspond to the recipient of the pong.
			 */

			gnet_host_set(&evec[0], info->addr, info->port);
			gnet_host_set(&evec[1], sender_addr, sender_port);

			ggept_ipp_pack(&gs, host, hcount, evec, G_N_ELEMENTS(evec),
				flags & PING_F_IPV6, flags & PING_F_NO_IPV4);
		}
	}

	/*
	 * If they gave "DHTIPP" in their ping, send them a packed list of
	 * valid DHT contacts, in addr:port packed format, similar to "IPP".
	 *
	 * NB: The port here is little-endian, since this is a Gnutella message
	 * and not a Kademlia one.
	 */

	if (0 != (flags & PING_F_DHTIPP)) {
		gnet_host_t host[PCACHE_DHT_MAX_IP];
		int hcount;

		hcount = dht_fill_random(host, G_N_ELEMENTS(host));

		if (hcount > 0) {
			ggept_dhtipp_pack(&gs, host, hcount,
				flags & PING_F_IPV6, flags & PING_F_NO_IPV4);
		}
	}

	/*
	 * The "IP" GGEP extension in the ping requests that the IP:port
	 * of the sending host be echoed back.
	 *
	 * We echo either an IPv4:port or an IPv6:port here, and the recipient
	 * must use the size of the payload to discriminate: a 6-byte payload
	 * will indicate an IPv4:port, as opposed to a 18-byte payload for
	 * an IPv6:port.
	 */

	if (flags & PING_F_IP) {
		char ip_port[18];			/* Big enough for IPv6 + port */
		size_t len;

		/* IP + Port (not UHC IPP!)*/
		if (GNET_PROPERTY(pcache_debug) > 1 || GNET_PROPERTY(ggep_debug) > 1) {
			g_debug("adding GGEP IP to pong for %s",
				host_addr_port_to_string(sender_addr, sender_port));
		}

		host_ip_port_poke(ip_port, sender_addr, sender_port, &len);
		ggep_stream_pack(&gs, GGEP_NAME(IP), ip_port, len, 0);
	}

	/*
	 * The "QK" GGEP extension in the ping requests a GUESS Query Key.
	 */

	if ((flags & PING_F_QK) && GNET_PROPERTY(enable_guess)) {
		sectoken_t tok;

		search_query_key_generate(&tok, sender_addr, sender_port);
		ggep_stream_pack(&gs, GGEP_NAME(QK), tok.v, sizeof tok.v, 0);
	}

	sz += ggep_stream_close(&gs);

	gnutella_header_set_size(gnutella_msg_init_response_header(pong), sz);

	if (size)
		*size = sz + GTA_HEADER_SIZE;

	return pong;
}

/**
 * Send pong message back to node.
 *
 * If `control' is true, send it as a higher priority message.
 * If `uhc' is true, this is an UDP host cache reply.
 */
static void
send_pong(
	gnutella_node_t *n, bool control, enum ping_flag flags,
	uint8 hops, uint8 ttl, const struct guid *muid,
	struct pong_info *info, pong_meta_t *meta)
{
	gnutella_msg_init_response_t *r;
	uint32 size;

	g_assert(ttl >= 1);

	if (!NODE_IS_WRITABLE(n))
		return;

	/*
	 * We don't include metadata when sending the pong as a "control" message,
	 * as this means that we're replying to an "alive" check.
	 */

	r = build_pong_msg(n->addr, n->port, hops, ttl, muid, info,
			meta, flags, &size);
	n->n_pong_sent++;

	if (NODE_IS_UDP(n)) {
		if (control)
			udp_ctrl_send_msg(n, r, size);
		else
			udp_send_msg(n, r, size);
	} else if (control)
		gmsg_ctrl_sendto_one(n, r, size);
	else
		gmsg_sendto_one(n, r, size);
}

/**
 * Scan extensions in the incoming ping to determine whether this is
 * an UHC ping (mentionning "SCP" support), or whether the ping is requesting
 * DHT hosts in packed IP format (mentionning "DHTIPP").
 *
 * @return ping flags summarizing the remote request.  For instance PING_F_UHC
 * will indicate an UHC ping, and PING_F_DHTIPP will indicate a ping for
 * DHT hosts.
 */
static enum ping_flag
ping_type(const gnutella_node_t *n)
{
	int i;
	enum ping_flag flags = PING_F_NONE;
	bool has_gue = FALSE;
	bool has_scp = FALSE;

	for (i = 0; i < n->extcount; i++) {
		const extvec_t *e = &n->extvec[i];

		switch (e->ext_token) {
		case EXT_T_GGEP_SCP:
			has_scp = TRUE;

			/*
		 	 * Look whether they want leaf slots, ultra slots, or don't care.
			 * Also determine which IP addresses they want.
		 	 */

			/* Accept only the first SCP, just in case there are multiple */
			if (!(flags & PING_F_UHC) && ext_paylen(e) >= 1) {
				const uchar *payload = ext_payload(e);
				uint8 mask = payload[0];
				flags |= (mask & SCP_F_ULTRA) ?
					PING_F_UHC_ULTRA : PING_F_UHC_LEAF;
				flags |= (mask & SCP_F_IPV6) ? PING_F_IPV6 : 0;
				flags |= (mask & SCP_F_NO_IPV4) ? PING_F_NO_IPV4 : 0;
			} else if (!(flags & PING_F_UHC)) {
				/* No payload, assume they want any host */
				flags |= PING_F_UHC_ANY;
			}
			flags |= PING_F_UHC;
			break;

		case EXT_T_GGEP_IP:
			if (
				0 == (flags & PING_F_IP) &&
				NODE_IS_UDP(n) &&
				0 == gnutella_header_get_hops(&n->header) &&
				1 == gnutella_header_get_ttl(&n->header) &&
				0 == ext_paylen(e)
			) {
				/*
				 * Remote host wants to know its IP and port, as seen within
				 * the UDP datagram.  This is useful to firewalled node who
				 * want to initiate a firewalled-to-firewalled connection
				 * via RUDP and need to communicate their external (possibly
				 * NAT-ed) UDP port.
				 */
				flags |= PING_F_IP;
			}
			break;

		case EXT_T_GGEP_DHTIPP:
			/* Accept only the first DHTIPP, just in case there are multiple */
			if (ext_paylen(e) >= 1 && !(flags & PING_F_DHTIPP)) {
				const uchar *payload = ext_payload(e);
				uint8 mask = payload[0];
				flags |= (mask & SCP_F_IPV6) ? PING_F_IPV6 : 0;
				flags |= (mask & SCP_F_NO_IPV4) ? PING_F_NO_IPV4 : 0;
			}
			flags |= PING_F_DHTIPP;
			break;

		case EXT_T_GGEP_GUE:
			has_gue = TRUE;
			if (ext_paylen(e) != 0) {
				guess_introduction_ping(n, ext_payload(e), ext_paylen(e));
			}
			break;

		case EXT_T_GGEP_QK:
			if (0 == ext_paylen(e) && settings_is_ultra()) {
				flags |= PING_F_QK;
			}
			break;

		default: ;
		}

	}

	/*
	 * If they sent a "GUE" extension and no "QK" as well, then they are
	 * requesting more GUESS hosts packed in "IPP".
	 *
	 * Likewise if they sent a "QK" with "SCP".
	 */

	if ((has_gue && !(flags & PING_F_QK)) || (has_scp && (flags & PING_F_QK))) {
		flags |= PING_F_GUE;
	}

	if ((flags & PING_F_UHC) && GNET_PROPERTY(ggep_debug) > 1)
		g_debug("%s: UHC ping requesting %s hosts from %s",
			gmsg_node_infostr(n),
			(flags & PING_F_GUE) ?	"GUESS" :
			(flags & PING_F_UHC_ANY) ?	"any" :
			(flags & PING_F_UHC_ULTRA) ?	"ultra" : "leaf",
			host_addr_port_to_string(n->addr, n->port));

	return flags;
}

/**
 * Send info about us back to node, using the hopcount information present in
 * the header of the node structure to construct the TTL of the pong we
 * send.
 *
 * @param n			destination node, where to send the pong
 * @param control	if TRUE, send it as a higher priority message.
 * @param flags		description of the ping we got
 */
static void
send_personal_info(gnutella_node_t *n, bool control, enum ping_flag flags)
{
	uint32 kbytes;
	uint32 files;
	struct pong_info info;
	uint32 ip_uptime;
	uint32 avg_uptime;

	/* Replying to a ping */
	g_assert(gnutella_header_get_function(&n->header) == GTA_MSG_INIT);

	files = MIN(shared_files_scanned(), ~((uint32) 0U));

	/*
	 * Mark pong if we are an ultra node: the amount of kbytes scanned must
	 * be an exact power of two, and at minimum 8.
	 */

	kbytes = MIN(shared_kbytes_scanned(), ~((uint32) 0U));

	if (settings_is_ultra()) {
		uint32 next, prev;
		
		next = next_pow2(kbytes);
		prev = next / 2;
		/* Pick power of 2 which is closest to the actual value. */
		kbytes = (next - kbytes) < (kbytes - prev) ? next : prev;
		kbytes = MAX(8, kbytes);
	} else if (kbytes)
		kbytes |= 1;		/* Ensure not a power of two */

	/*
	 * Pongs are sent with a TTL just large enough to reach the pinging host,
	 * up to a maximum of max_ttl.	Note that we rely on the hop count being
	 * accurate.
	 *				--RAM, 15/09/2001
	 *
	 * IPv6-Ready: if running with an IPv4 address, supply it and list a
	 * possible IPv6 address in GGEP "6".  Otherwise, if running only with
	 * an IPv6 address, advertise it in GGEP "6" and set the legacy IPv4
	 * field to 127.0.0.0.
	 *				--RAM, 2011-06-16
	 */

	info.addr = listen_addr_primary();
	info.port = socket_listen_port();
	info.files_count = files;
	info.kbytes_count = kbytes;

	/*
	 * What matters for the uptime is both the actual servent uptime and the
	 * stability of the IP address.  If they have high uptimes but change IP
	 * every 12 hours, it makes no sense to advertise a high daily uptime...
	 */

	ip_uptime = delta_time(tm_time(), GNET_PROPERTY(current_ip_stamp));
	ip_uptime = MAX(ip_uptime, GNET_PROPERTY(average_ip_uptime));
	avg_uptime = get_average_servent_uptime(tm_time());
	local_meta.daily_uptime = MIN(avg_uptime, ip_uptime);

	/*
	 * Activate "UP" only if we're an ultrapeer right now.
	 */

	if (settings_is_ultra()) {
		local_meta.flags |= PONG_META_HAS_UP;
		local_meta.leaf_slots = MIN(node_leaves_missing(), 255);
		local_meta.up_slots = MIN(node_missing(), 255);

		/*
		 * Ultrapeers supporting GUESS must advertize it in their pongs.
		 */

		if (GNET_PROPERTY(enable_guess)) {
			local_meta.flags |= PONG_META_HAS_GUE;
			local_meta.guess = (SEARCH_GUESS_MAJOR << 4) | SEARCH_GUESS_MINOR;
		}
	}

	/*
	 * IPv6-Ready:
	 * We're supplying the IPv6 address when running both IPv4 and IPv6.
	 * If we're only running IPv6, the legacy IPv4 address will be 127.0.0.0.
	 */

	if (settings_running_ipv6() && !host_addr_is_ipv6(info.addr)) {
		local_meta.ipv6_addr = listen_addr6();
		local_meta.flags |= PONG_META_HAS_IPV6;
	}

	/*
	 * If the DHT is up and running in active mode, send an indication.
	 * These tagged pongs are used by hosts to bootstrap their DHT
	 * routing table and join.
	 */

	if (dht_is_active() && dht_bootstrapped()) {
		local_meta.dht_major = KDA_VERSION_MAJOR;
		local_meta.dht_minor = KDA_VERSION_MINOR;
		local_meta.dht_mode = DHT_MODE_ACTIVE;
		local_meta.flags |= PONG_META_HAS_DHT;
	}

	local_meta.flags |= tls_enabled() ? PONG_META_HAS_TLS : 0;

	send_pong(n, control, flags, 0,
		MIN(gnutella_header_get_hops(&n->header) + 1U, GNET_PROPERTY(max_ttl)),
		gnutella_header_get_muid(&n->header), &info, &local_meta);

	/* Reset flags that must be recomputed each time */
	local_meta.flags &=
		~(PONG_META_HAS_UP | PONG_META_HAS_GUE | PONG_META_HAS_DHT);
}

/**
 * Send a pong for each of our connected neighbours to specified node.
 */
static void
send_neighbouring_info(gnutella_node_t *n)
{
	const pslist_t *sl;

	/* Replying to a ping */
	g_assert(gnutella_header_get_function(&n->header) == GTA_MSG_INIT);
	/* Originates from node */
	g_assert(gnutella_header_get_hops(&n->header) == 0);
	g_assert(gnutella_header_get_ttl(&n->header) == 2);	/* "Crawler" ping */

	PSLIST_FOREACH(node_all_ultranodes(), sl) {
		gnutella_node_t *cn = sl->data;
		struct pong_info info;

		if (!NODE_IS_WRITABLE(cn))
			continue;

		if (n == cn)
			continue;

		/*
		 * If we have valid Gnet information for the node, build the pong
		 * as if it came from the neighbour, only we don't send the ping,
		 * and don't have to read back the pong and resent it.
		 *
		 * Otherwise, don't send anything back: we no longer keep routing
		 * information for pings.
		 */

		if (!is_host_addr(cn->gnet_addr))
			continue;				/* No information yet */

		info.addr = cn->gnet_addr;
		info.port = cn->gnet_port;
		info.files_count = cn->gnet_files_count;
		info.kbytes_count = cn->gnet_kbytes_count;

		send_pong(n, FALSE, PING_F_NONE,
			1, 1, gnutella_header_get_muid(&n->header),
			&info, NULL);	/* hops = 1, TTL = 1 */

		/*
		 * Since we won't see the neighbour pong, we won't be able to store
		 * it in our reserve, so do it from here.
		 */

		if (!NODE_IS_LEAF(n))
			host_add(cn->gnet_addr, cn->gnet_port, FALSE);

		/*
		 * Node can be removed should its send queue saturate.
		 */

		if (!NODE_IS_CONNECTED(n))
			return;

		/*
		 * Careful with transient nodes, their lifetime is reduced so don't
		 * waste too much banwdwidth with them.
		 *		--RAM, 2012-01-15
		 */

		if (NODE_IS_TRANSIENT(n)) {
			unsigned pcnt = NODE_TX_COMPRESSED(n) ? 10 : 2;
			if (random_value(99) < pcnt || node_above_low_watermark(n))
				break;
		}
	}
}

/**
 * Acknowledge reception of query through GUESS by sending back a pong
 * listing one other GUESS ultrapeer, or ourselves if we don't have any
 * other to propagate.
 *
 * When the query key was not good, send back a new query key in the pong.
 */
void
pcache_guess_acknowledge(gnutella_node_t *n,
	bool good_query_key, bool wants_ipp, host_net_t net)
{
	struct pong_info info;
	pong_meta_t meta;
	gnet_host_t host[2];
	int hcount;
	int flags = PING_F_NONE;

	node_check(n);
	g_assert(NODE_IS_UDP(n));

	/*
	 * We request more than one host to make sure we include an address
	 * for a host different from the one sending us the message.
	 */

	hcount = guess_fill_caught_array(net, FALSE, host, G_N_ELEMENTS(host));

	meta.guess = (SEARCH_GUESS_MAJOR << 4) | SEARCH_GUESS_MINOR;
	meta.flags = PONG_META_HAS_GUE;

	if (!good_query_key)
		flags |= PING_F_QK;		/* Will generate a new query key */

	if (wants_ipp)
		flags |= PING_F_UHC;	/* Will include more hosts in IPP */

	if (0 == hcount) {
		goto use_self_pong;
	} else {
		int i;

		for (i = 0; i < hcount; i++) {
			gnet_host_t *h = &host[i];

			info.addr = gnet_host_get_addr(h);
			info.port = gnet_host_get_port(h);

			if (info.port == n->port && host_addr_equiv(info.addr, n->addr))
				continue;	/* Don't send pong for the host contacting us */
	
			goto send_pong;
		}
	}

	/* FALL THROUGH */

use_self_pong:
	info.addr = listen_addr();
	info.port = socket_listen_port();
	info.files_count = 0;
	info.kbytes_count = 0;

	/* FALL THROUGH */

send_pong:
	/*
	 * GUESS acknowledgments are sent as "control" messages to make sure
	 * querying hosts get them quickly.
	 */

	send_pong(n, TRUE, flags,
		1, 1, gnutella_header_get_muid(&n->header),
		&info, &meta);	/* hops = 1, TTL = 1 */

	if (GNET_PROPERTY(guess_server_debug) > 10) {
		g_debug("GUESS %s query #%s from %s with %spong listing %s:%u%s",
			good_query_key ? "acknowledged" : "refused",
			guid_hex_str(gnutella_header_get_muid(&n->header)), node_infostr(n),
			good_query_key ? "" : "new query key and ",
			host_addr_to_string(info.addr), info.port,
			wants_ipp ? " plus others in \"IPP\"" : "");
	}
}

/***
 *** Ping/pong reducing scheme.
 ***/

/*
 * Data structures used:
 *
 * `pong_cache' is an array of MAX_CACHE_HOPS+1 entries.
 * Each entry is a structure holding a one-way list and a traversal pointer
 * so we may iterate over the list of cached pongs at that hop level.
 *
 * `cache_expire_time' is the time after which we will expire the whole cache
 * and ping all our connections.
 */

static time_t pcache_expire_time = 0;
static aging_table_t *udp_pings;

struct cached_pong {		/**< A cached pong */
	int refcount;			/**< How many lists reference us? */
	struct nid *node_id;	/**< The node ID from which we got that pong */
	struct nid *last_sent_id; /**< Node ID we last sent this pong to */
	struct pong_info info;	/**< Values from the pong message */
	pong_meta_t *meta;		/**< Optional meta data */
};

struct cache_line {			/**< A cache line for a given hop value */
	int hops;				/**< Hop count of this cache line */
	pslist_t *pongs;		/**< List of cached_pong */
	pslist_t *cursor;		/**< Cursor within list: last item traversed */
};

struct recent {
	hset_t *hs_recent_pongs;	/**< Recent pongs we know about */
	plist_t *recent_pongs;		/**< Recent pongs we got */
	plist_t *last_returned_pong;/**< Last returned from list */
	int recent_pong_count;		/**< # of pongs in recent list */
};

#define PONG_CACHE_SIZE		(MAX_CACHE_HOPS+1)

static struct cache_line pong_cache[PONG_CACHE_SIZE];
static struct recent recent_pongs[HOST_MAX];

#define CACHE_UP_LIFESPAN	20		/**< seconds -- ultra/normal mode */
#define CACHE_LEAF_LIFESPAN	120		/**< seconds -- leaf mode */
#define MAX_PONGS			10		/**< Max pongs returned per ping */
#define OLD_PING_PERIOD		45		/**< Pinging period for "old" clients */
#define OLD_CACHE_RATIO		20		/**< % of cached pongs from "old" clients */
#define RECENT_PING_SIZE	50		/**< remember last 50 pongs we saw */
#define MIN_UP_PING			3		/**< ping at least 3 neighbours */
#define UP_PING_RATIO		20		/**< ping 20% of UP, at random */

#define UDP_PING_FREQ		60		/**< answer to 1 ping per minute per IP */

#define cache_lifespan(m)	\
	((m) == NODE_P_LEAF ? CACHE_LEAF_LIFESPAN : CACHE_UP_LIFESPAN)

/*
 * cached_pong_hash
 * cached_pong_eq
 *
 * Callbacks for the `hs_recent_pongs' hash set.
 */

static uint
cached_pong_hash(const void *key)
{
	const struct cached_pong *cp = key;

	return host_addr_hash(cp->info.addr) ^ port_hash(cp->info.port);
}

static int
cached_pong_eq(const void *v1, const void *v2)
{
	const struct cached_pong *h1 = v1, *h2 = v2;

	return host_addr_equiv(h1->info.addr, h2->info.addr) &&
		h1->info.port == h2->info.port;
}

/**
 * Initialization.
 */
G_GNUC_COLD void
pcache_init(void)
{
	int h;
	char *lang = NULL;

	ZERO(&pong_cache);
	ZERO(&recent_pongs);

	/*
	 * We limit UDP pings to 1 every UDP_PING_FREQ seconds.
	 */

	udp_pings = aging_make(UDP_PING_FREQ,
			host_addr_hash_func, host_addr_eq_func, wfree_host_addr);

	/*
	 * The `local_meta' structure collects our meta data that we may send
	 * out in pongs for ourselves, when not replying to "alive" pings.
	 */

	local_meta.flags = PONG_META_HAS_VC | PONG_META_HAS_DU;
	memcpy(local_meta.vendor, GTA_VENDOR_CODE, 4);
	local_meta.version_ua = version_get_code();
	local_meta.version_up = 0x2;	/* X-Query-Routing: 0.2 */

	/*
	 * Until we can supersede those default settings from the GUI and
	 * enable locale preferencing from there, leave this out.
	 *		--RAM, 2004-11-14
	 */

	(void) lang;	/* Avoid warnings whilst the following is disabled */

#if 0	/* Disabled for 0.95 */
	/*
	 * Derive the locale if we can.
	 */

#define GET_LANG(x)										\
G_STMT_START {											\
	if (lang == NULL) {									\
		lang = getenv(#x);								\
		if (lang != NULL) {								\
			if (strlen(lang) >= 3 && lang[2] != '_')	\
				lang = NULL;							\
		}												\
	}													\
} G_STMT_END

	GET_LANG(LANG);
	GET_LANG(LC_CTYPE);				/* E.g. "fr_FR.iso-8859-1" */
	GET_LANG(LC_MESSAGES);
	GET_LANG(LC_ALL);

#undef GET_LANG

	if (lang != NULL) {
		int len = strlen(lang);

		if (len > 0) {
			int i;

			local_meta.flags |= PONG_META_HAS_LOC;

			if (len == 1)		/* C */
				memcpy(local_meta.language, "en", 2);
			else
				memcpy(local_meta.language, lang, 2);

			for (i = 0; i < 2; i++)
				local_meta.language[i] = ascii_tolower(local_meta.language[i]);

			if (len >= 5 && lang[2] == '_') {
				memcpy(local_meta.country, lang + 3, 2);
				for (i = 0; i < 2; i++)
					local_meta.country[i] = ascii_toupper(local_meta.country[i]);
			} else
				local_meta.country[0] = '\0';
		}

		g_info("locale set to language=\"%.2s\", country=\"%.2s\"",
			local_meta.language, local_meta.country);
	} else
		g_warning("unable to figure out locale preferences");
#endif

	for (h = 0; h < PONG_CACHE_SIZE; h++)
		pong_cache[h].hops = h;

	recent_pongs[HOST_ANY].hs_recent_pongs =
		hset_create_any(cached_pong_hash, NULL, cached_pong_eq);

	recent_pongs[HOST_ULTRA].hs_recent_pongs =
		hset_create_any(cached_pong_hash, NULL, cached_pong_eq);
}

/**
 * Free cached pong when noone references it any more.
 */
static void
free_cached_pong(struct cached_pong *cp)
{
	g_assert(cp->refcount > 0);		/* Someone was referencing it */

	if (--(cp->refcount) != 0)
		return;

	if (cp->meta != NULL)
		WFREE(cp->meta);

	nid_unref(cp->node_id);
	nid_unref(cp->last_sent_id);
	WFREE(cp);
}


/**
 * Get a recent pong from the list, updating `last_returned_pong' as we
 * go along, so that we never return twice the same pong instance.
 *
 * Fills `addr' and `port' with the pong value and return TRUE if we
 * got a pong.  Otherwise return FALSE.
 *
 * XXX This routine is no longer called anywhere.
 * XXX Need to think about whether we should just remove this pcache recent
 * XXX pong caching alltogether, or whether we need to keep it for the pong
 * XXX demultiplexing logic?
 * XXX		--RAM, 2008-03-11
 */
bool
pcache_get_recent(host_type_t type, host_addr_t *addr, uint16 *port)
{
	static host_addr_t last_addr;
	static uint16 last_port = 0;
	plist_t *l;
	struct cached_pong *cp;
	struct recent *rec;

	g_assert((uint) type < HOST_MAX);

	rec = &recent_pongs[type];

	if (!rec->recent_pongs)		/* List empty */
		return FALSE;

	/*
	 * If `last_returned_pong' is NULL, it means we reached the head
	 * of the list, so we traverse faster than we get pongs.
	 *
	 * Try with the head of the list, because maybe we have a recent pong
	 * there, but if it is the same as the last ip/port we returned, then
	 * go back to the tail of the list.
	 */

	if (rec->last_returned_pong == NULL) {
		l = plist_first(rec->recent_pongs);
		cp = l->data;

		if (
			!host_addr_equiv(cp->info.addr, last_addr) ||
			cp->info.port != last_port
		)
			goto found;

		if (plist_next(l) == NULL)		/* Head is the only item in list */
			return FALSE;
	} else {
		/* Regular case */
		l = plist_prev(rec->last_returned_pong);
		for (/* empty */ ; l; l = plist_prev(l)) {
			cp = l->data;
			if (
				!host_addr_equiv(cp->info.addr, last_addr) ||
				cp->info.port != last_port
			)
				goto found;
		}
	}

	/*
	 * Still none found, go back to the end of the list.
	 */

	for (l = plist_last(rec->recent_pongs); l; l = plist_prev(l)) {
		cp = l->data;
		if (
			!host_addr_equiv(cp->info.addr, last_addr) ||
			cp->info.port != last_port
		)
			goto found;
	}

	return FALSE;

found:
	rec->last_returned_pong = l;
	*addr =last_addr = cp->info.addr;
	*port = last_port = cp->info.port;

	if (GNET_PROPERTY(pcache_debug) > 8)
		g_debug("returning recent %s PONG %s",
			host_type_to_string(type),
			host_addr_port_to_string(cp->info.addr, cp->info.port));

	return TRUE;
}

/**
 * Add recent pong to the list, handled as a FIFO cache, if not already
 * present.
 */
static void
add_recent_pong(host_type_t type, struct cached_pong *cp)
{
	struct recent *rec;

	g_assert(UNSIGNED(type) < HOST_MAX);

	rec = &recent_pongs[type];

    if (
        !host_is_valid(cp->info.addr, cp->info.port) ||
        hset_contains(rec->hs_recent_pongs, cp) ||
        hcache_node_is_bad(cp->info.addr)
    ) {
        return;
    }

	if (rec->recent_pong_count == RECENT_PING_SIZE) {		/* Full */
		plist_t *lnk = plist_last(rec->recent_pongs);
		struct cached_pong *p = lnk->data;

		rec->recent_pongs = plist_remove_link(rec->recent_pongs, lnk);
		hset_remove(rec->hs_recent_pongs, p);

		if (lnk == rec->last_returned_pong)
			rec->last_returned_pong = plist_prev(rec->last_returned_pong);

		free_cached_pong(p);
		plist_free_1(lnk);
	} else
		rec->recent_pong_count++;

	rec->recent_pongs = plist_prepend(rec->recent_pongs, cp);
	hset_insert(rec->hs_recent_pongs, cp);
	cp->refcount++;		/* We don't refcount insertion in the hash table */
}

/**
 * Determine the pong type (any, or of the ultra kind).
 */
static host_type_t
pong_type(gnutella_init_response_t *pong)
{
	uint32 kbytes;

	kbytes = gnutella_init_response_get_kbytes_count(pong);

	/*
	 * Ultra pongs are marked by having their kbytes count be an
	 * exact power of two, and greater than 8.
	 */

	return (kbytes >= 8 && is_pow2(kbytes)) ? HOST_ULTRA : HOST_ANY;
}

/**
 * Clear the whole recent pong list.
 */
void
pcache_clear_recent(host_type_t type)
{
	plist_t *l;
	struct recent *rec;

	g_assert(UNSIGNED(type) < HOST_MAX);

	rec = &recent_pongs[type];

	PLIST_FOREACH(rec->recent_pongs, l) {
		struct cached_pong *cp = l->data;

		hset_remove(rec->hs_recent_pongs, cp);
		free_cached_pong(cp);
	}

	plist_free_null(&rec->recent_pongs);
	rec->last_returned_pong = NULL;
	rec->recent_pong_count = 0;
}

/**
 * Called when a new outgoing connection has been made.
 *
 * Here needs brief description for the following list:
 *
 * - If we need a connection, or have less than MAX_PONGS entries in our caught
 *   list, send a ping at normal TTL value.
 * - Otherwise, send a handshaking ping with TTL=1
 */
void
pcache_outgoing_connection(gnutella_node_t *n)
{
	g_assert(NODE_IS_CONNECTED(n));

	if (
		connected_nodes() < GNET_PROPERTY(up_connections) ||
		hcache_is_low(HOST_ANY)
	)
		send_ping(n, GNET_PROPERTY(my_ttl)); /* Regular ping, get fresh pongs */
	else
		send_ping(n, 1);			/* Handshaking ping */
}

/**
 * Called to attempt collecting DHT hosts for bootstrapping.
 * Ping is sent to neighbour with a TTL=2 so that "DHTIPP" is included (we're
 * not sending an UHC ping).
 */
void
pcache_collect_dht_hosts(gnutella_node_t *n)
{
	g_assert(NODE_IS_CONNECTED(n));

	send_ping(n, 2);
}

/**
 * Expire the whole cache.
 */
static void
pcache_expire(void)
{
	int i;
	int entries = 0;

	for (i = 0; i < PONG_CACHE_SIZE; i++) {
		struct cache_line *cl = &pong_cache[i];
		pslist_t *sl;

		PSLIST_FOREACH(cl->pongs, sl) {
			entries++;
			free_cached_pong(sl->data);
		}
		pslist_free_null(&cl->pongs);
		cl->cursor = NULL;
	}

	if (GNET_PROPERTY(pcache_debug) > 4)
		g_debug("Pong CACHE expired (%d entr%s, %d in reserve)",
			entries, plural_y(entries), hcache_size(HOST_ANY));
}

/**
 * Final shutdown.
 */
G_GNUC_COLD void
pcache_close(void)
{
	static host_type_t types[] = { HOST_ANY, HOST_ULTRA };
	uint i;

	pcache_expire();

	for (i = 0; i < G_N_ELEMENTS(types); i++) {
		host_type_t type = types[i];

		pcache_clear_recent(type);
		hset_free_null(&recent_pongs[type].hs_recent_pongs);
	}

	aging_destroy(&udp_pings);
}

/**
 * Send a ping to all "new" clients to which we are connected, and one to
 * older client if and only if at least OLD_PING_PERIOD seconds have
 * elapsed since our last ping, as determined by `next_ping'.
 */
void
ping_all_neighbours(void)
{
	const pslist_t *sl;
	pslist_t *may_ping = NULL;
	pslist_t *to_ping = NULL;
	int ping_cnt = 0;
	int selected = 0;
	int left;
	time_t now = tm_time();

	if (GNET_PROPERTY(pcache_debug))
		g_debug("PCACHE attempting to ping all neighbours");

	/*
	 * Because nowadays the network has a higher outdegree for ultrapeers,
	 * and because of the widespread use of X-Try-Ultrapeers headers, it is
	 * less critical to use pings as a way to collect hosts.
	 *
	 * Therefore, don't ping all neighbours but only UP_PING_RATIO percent
	 * of them, chosen at random, with at least MIN_UP_PING hosts chosen.
	 *
	 *		--RAM, 12/01/2004
	 */

	PSLIST_FOREACH(node_all_ultranodes(), sl) {
		gnutella_node_t *n = sl->data;

		if (!NODE_IS_WRITABLE(n) || NODE_IS_LEAF(n))
			continue;

		/*
		 * If node is in TX flow control, we already have problems,
		 * so don't increase them by sending more pings.
		 *		--RAM, 19/06/2003
		 */

		if (NODE_IN_TX_FLOW_CONTROL(n))
			continue;

		if ((n->attrs & NODE_A_PONG_CACHING) || now > n->next_ping) {
			may_ping = pslist_prepend(may_ping, n);
			ping_cnt++;
		}
	}

	for (sl = may_ping, left = ping_cnt; sl; sl = pslist_next(sl), left--) {
		gnutella_node_t *n = sl->data;

		if (
			ping_cnt <= MIN_UP_PING ||
			(selected < MIN_UP_PING && left <= (MIN_UP_PING - selected)) ||
			random_value(99) < UP_PING_RATIO
		) {
			to_ping = pslist_prepend(to_ping, n);
			selected++;
		}
	}

	PSLIST_FOREACH(to_ping, sl) {
		gnutella_node_t *n = sl->data;

		if (!(n->attrs & NODE_A_PONG_CACHING))
			n->next_ping = time_advance(now, OLD_PING_PERIOD);

		if (GNET_PROPERTY(pcache_debug) > 1)
			g_debug("PCACHE pinging \"%s\" %s",
				(n->attrs & NODE_A_PONG_CACHING) ? "new" : "old",
				host_addr_port_to_string(n->addr, n->port));

		send_ping(n, GNET_PROPERTY(my_ttl));
	}

	pslist_free(may_ping);
	pslist_free(to_ping);
}

/**
 * Check pong cache for expiration.
 * If expiration time is reached, flush it and ping all our neighbours.
 */
void
pcache_possibly_expired(time_t now)
{
	if (delta_time(now, pcache_expire_time) >= 0) {
		pcache_expire();
		pcache_expire_time = time_advance(now,
							cache_lifespan(GNET_PROPERTY(current_peermode)));
		ping_all_neighbours();
	}
}

/**
 * Called when peer mode is changed to recompute the pong cache lifetime.
 */
void
pcache_set_peermode(node_peer_t mode)
{
	pcache_expire_time = tm_time() + cache_lifespan(mode);
}

/**
 * Fill ping_guid[] and pong_needed[] arrays in the node from which we just
 * accepted a ping.
 *
 * When we accept a ping from a connection, we don't really relay the ping.
 * Our cache is filled by the pongs we receive back from our periodic
 * pinging of the neighbours.
 *
 * However, when we get some pongs back, we forward them back to the nodes
 * for which we have accepted a ping and which still need results, as
 * determined by pong_needed[] (index by pong hop count).  The saved GUID
 * of the ping allows us to fake the pong reply, so the sending node recognizes
 * those as being "his" pongs.
 */
static void
setup_pong_demultiplexing(gnutella_node_t *n, uint8 ttl)
{
	int remains;
	int h;

	g_assert(gnutella_header_get_function(&n->header) == GTA_MSG_INIT);

	memcpy(&n->ping_guid, gnutella_header_get_muid(&n->header), 16);
	ZERO(&n->pong_needed);
	n->pong_missing = 0;

	/*
	 * `ttl' is currently the amount of hops the ping could travel.
	 * If it's 1, it means it would have travelled on host still, and we
	 * would have got a pong back with an hop count of 0.
	 *
	 * Since our pong_needed[] array is indexed by the hop count of pongs,
	 * we need to substract one from the ttl parameter.
	 */

	if (ttl-- == 0)
		return;

	ttl = MIN(ttl, MAX_CACHE_HOPS);		/* We limit the maximum hop count */

	/*
	 * Now we're going to distribute "evenly" the MAX_PONGS we can return
	 * to this ping accross the (0..ttl) range.  We start by the beginning
	 * of the array to give more weight to high-hops pongs.
	 */

	n->pong_missing = remains = MAX_PONGS;

	for (h = 0; h <= MAX_CACHE_HOPS; h++) {
		uchar amount = (uchar) (remains / (MAX_CACHE_HOPS + 1 - h));
		n->pong_needed[h] = amount;
		remains -= amount;
		if (GNET_PROPERTY(pcache_debug) > 7)
			g_debug("pong_needed[%d] = %d, remains = %d", h, amount, remains);
	}

	g_assert(remains == 0);
}

/**
 * Internal routine for send_cached_pongs.
 *
 * Iterates on a list of cached pongs and send back any pong to node `n'
 * that did not originate from it.  Update `cursor' in the cached line
 * to be the address of the last traversed item.
 *
 * @return FALSE if we're definitely done, TRUE if we can still iterate.
 */
static bool
iterate_on_cached_line(
	gnutella_node_t *n, struct cache_line *cl, uint8 ttl,
	pslist_t *start, pslist_t *end, bool strict)
{
	int hops = cl->hops;
	pslist_t *sl;

	sl = start;
	for (; sl && sl != end && n->pong_missing; sl = pslist_next(sl)) {
		struct cached_pong *cp = sl->data;

		cl->cursor = sl;

		/*
		 * We never send a cached pong to the node from which it came along.
		 *
		 * The `last_sent_id' trick is used because we're going to iterate
		 * twice on the cache list: once to send pongs that strictly match
		 * the hop counts needed, and another time to send pongs as needed,
		 * more loosely.  The two runs are consecutive, so we're saving in
		 * each cached entry the node to which we sent it last, so we don't
		 * resend the same pong twice.
		 *
		 * We're only iterating upon reception of the intial ping from the
		 * node.  After that, we'll send pongs as we receive them, and
		 * only if they strictly match the needed TTL.
		 */

		if (nid_equal(NODE_ID(n), cp->node_id))
			continue;
		if (nid_equal(NODE_ID(n), cp->last_sent_id))
			continue;

		nid_unref(cp->last_sent_id);
		cp->last_sent_id = nid_ref(NODE_ID(n));

		/*
		 * When sending a cached pong, don't forget that its cached hop count
		 * is the one we got when we received it, i.e. hops=0 means a pong
		 * from one of our immediate neighbours.  However, we're now "routing"
		 * it, so we must increase the hop count.
		 */

		g_assert(hops < 255);		/* Because of MAX_CACHE_HOPS */

		send_pong(n, FALSE, PING_F_NONE,
			hops + 1, ttl, &n->ping_guid, &cp->info, cp->meta);

		n->pong_missing--;

		if (GNET_PROPERTY(pcache_debug) > 7)
			g_debug("iterate: sent cached pong %s (hops=%d, TTL=%d) to %s, "
				"missing=%d %s",
				host_addr_port_to_string(cp->info.addr, cp->info.port),
				hops, ttl,
				node_addr(n), n->pong_missing, strict ? "STRICT" : "loose");

		if (strict && --(n->pong_needed[hops]) == 0)
			return FALSE;

		/*
		 * Node can be removed should its send queue saturate.
		 */

		if (!NODE_IS_CONNECTED(n))
			return FALSE;
	}

	return n->pong_missing != 0;
}

/**
 * Send pongs from cache line back to node `n' if more are needed for this
 * hop count and they are not originating from the node.  When `strict'
 * is false, we send even if no pong at that hop level is needed.
 *
 * @param n			the node to which pongs are sent
 * @param cl		the cache line on which we need to iterate.
 * @param ttl		the TTL of the pongs we're generating
 * @param strict	if TRUE, don't send pongs if none needed at that hop count
 */
static void
send_cached_pongs(
	gnutella_node_t *n,
	struct cache_line *cl, uint8 ttl, bool strict)
{
	int hops = cl->hops;
	pslist_t *old = cl->cursor;

	if (strict && !n->pong_needed[hops])
		return;

	/*
	 * We start iterating after `cursor', until the end of the list, at which
	 * time we restart from the beginning until we reach `cursor', included.
	 * When we leave, `cursor' will point to the last traversed item.
	 */

	if (old) {
		if (!iterate_on_cached_line(n, cl, ttl, old->next, NULL, strict))
			return;
		(void) iterate_on_cached_line(n, cl, ttl, cl->pongs, old->next, strict);
	} else
		(void) iterate_on_cached_line(n, cl, ttl, cl->pongs, NULL, strict);
}

/**
 * Send as many cached pongs as needed to the relevant node.
 */
static void
send_demultiplexed_pongs(gnutella_node_t *n)
{
	enum ping_flag flags;
	uint h, ttl;

	/*
	 * Look whether the "ping" they sent bore the "SCP" extension, meaning
	 * we can reply using "IPP" to pack the various addresses.
	 */

	flags = ping_type(n);
	if (0 != (flags & PING_F_UHC)) {
		send_personal_info(n, FALSE, flags);
		return;
	}

	/*
	 * If TTL = 0, only us can reply, and we'll do that below in any case.
	 * We call setup_pong_demultiplexing() anyway to reset the pong_needed[]
	 * array and compute `n->pong_missing'.
	 */

	setup_pong_demultiplexing(n, gnutella_header_get_ttl(&n->header));

	if (n->pong_missing == 0)
		return;

	/*
	 * @return cached pongs if we have some and they are needed.
	 * We first try to send pongs on a per-hop basis, based on pong_needed[].
	 *
	 * NB: if we can send IPs in a single IPP extension, then we supply a
	 * vector that is filled, and we'll have to send the pong afterwards.
	 */

	ttl = gnutella_header_get_hops(&n->header) + 1U;
	ttl = MIN(ttl, GNET_PROPERTY(max_ttl));

	for (h = 0; n->pong_missing; h++) {
		struct cache_line *cl;

		if (h >= gnutella_header_get_ttl(&n->header))
			break;

		cl = &pong_cache[CACHE_HOP_IDX(h)];
		if (cl->pongs) {
			send_cached_pongs(n, cl, ttl, TRUE);
			if (!NODE_IS_CONNECTED(n))
				return;
		}
	}

	/*
	 * We then re-iterate if some pongs are still needed, sending any we
	 * did not already send.
	 */

	for (h = 0; n->pong_missing; h++) {
		struct cache_line *cl;
	   
		if (h >= gnutella_header_get_ttl(&n->header))
			break;

		cl = &pong_cache[CACHE_HOP_IDX(h)];
		if (cl->pongs) {
			send_cached_pongs(n, cl, ttl, FALSE);
			if (!NODE_IS_CONNECTED(n))
				return;
		}
	}
}

/**
 * We received a pong we cached from `n'.  Send it to all other nodes if
 * they need one at this hop count.
 */
static void
pong_all_neighbours_but_one(
	gnutella_node_t *n, struct cached_pong *cp, host_type_t ptype,
	uint8 hops, uint8 ttl)
{
	const pslist_t *sl;

	PSLIST_FOREACH(node_all_gnet_nodes(), sl) {
		gnutella_node_t *cn = sl->data;

		if (cn == n)
			continue;

		if (!NODE_IS_WRITABLE(cn))
			continue;

		/*
		 * Since we iterate twice initially at ping reception, once strictly
		 * and the other time loosly, `pong_missing' is always accurate but
		 * can be different from the sum of `pong_needed[i]', for all `i'.
		 */

		if (!cn->pong_missing)
			continue;

		if (!cn->pong_needed[hops])
			continue;

		/*
		 * If node is a leaf node, we can only send it Ultra pongs.
		 */

		if (NODE_IS_LEAF(cn) && ptype != HOST_ULTRA)
			continue;

		cn->pong_missing--;
		cn->pong_needed[hops]--;

		/*
		 * When sending a cached pong, don't forget that its cached hop count
		 * is the one we got when we received it, i.e. hops=0 means a pong
		 * from one of our immediate neighbours.  However, we're now "routing"
		 * it, so we must increase the hop count.
		 */

		g_assert(hops < 255);

		send_pong(cn, FALSE, PING_F_NONE,
			hops + 1, ttl, &cn->ping_guid, &cp->info, cp->meta);

		if (GNET_PROPERTY(pcache_debug) > 7)
			g_debug("pong_all: sent cached pong %s (hops=%d, TTL=%d) to %s "
				"missing=%d",
				host_addr_port_to_string(cp->info.addr, cp->info.port),
				hops, ttl, node_addr(cn), cn->pong_missing);
	}
}

/**
 * We received an ultra pong.
 * Send it to one randomly selected leaf, which is not already missing pongs.
 */
static void
pong_random_leaf(struct cached_pong *cp, uint8 hops, uint8 ttl)
{
	const pslist_t *sl;
	unsigned leaves;
	gnutella_node_t *leaf = NULL;

	g_assert(settings_is_ultra());

	for (sl = node_all_gnet_nodes(), leaves = 0; sl; sl = pslist_next(sl)) {
		gnutella_node_t *cn = sl->data;

		if (cn->pong_missing)	/* A job for pong_all_neighbours_but_one() */
			continue;

		if (!NODE_IS_LEAF(cn) || NODE_IS_TRANSIENT(cn))
			continue;

		if (NODE_IN_TX_FLOW_CONTROL(cn))	/* Already overwhelmed */
			continue;

		/*
		 * Randomly select one leaf.
		 *
		 * As we go along, the probability that we retain the current leaf
		 * decreases.  It is 1 for the first leaf, 1/2 for the second leaf,
		 * 1/3 for the third leaf, etc...
		 */

		leaves++;

		if (0 == random_value(leaves - 1))
			leaf = cn;
	}

	/*
	 * Send the pong to the selected leaf, if any.
	 *
	 * NB: If the leaf never sent a ping before, leaf->ping_guid will
	 * be a zero GUID.  That's OK.
	 */

	if (leaf != NULL) {
		send_pong(leaf, FALSE, PING_F_NONE, hops + 1, ttl, &leaf->ping_guid,
			&cp->info, cp->meta);

		if (GNET_PROPERTY(pcache_debug) > 7)
			g_debug("pong_random_leaf: sent pong %s (hops=%d, TTL=%d) to %s",
				host_addr_port_to_string(cp->info.addr, cp->info.port),
				hops, ttl, node_addr(leaf));
	}
}

/**
 * Extract pong meta data from the GGEP extensions, and create a meta data
 * structure to hold them if necessary.
 *
 * @return a walloc-ed pong_meta_t structure if meta data were found.
 */
static pong_meta_t *
pong_extract_metadata(gnutella_node_t *n)
{
	int i;
	pong_meta_t *meta = NULL;

#define ALLOCATE(f) do {					\
	if (meta == NULL) {						\
		WALLOC(meta);						\
		meta->flags = 0;					\
	}										\
	meta->flags |= CAT2(PONG_META_HAS_,f);	\
} while (0)

	for (i = 0; i < n->extcount; i++) {
		extvec_t *e = &n->extvec[i];
		const uchar *payload;
		uint16 paylen;

		switch (e->ext_token) {
		case EXT_T_GGEP_DU:
			/*
			 * Daily uptime.
			 * Payload is a variable-length little-endian uptime.
			 */

			{
				uint32 uptime;
				if (GGEP_OK == ggept_du_extract(e, &uptime)) {
					ALLOCATE(DU);
					meta->daily_uptime = uptime;
				}
			}
			break;
		case EXT_T_GGEP_GUE:
			/*
			 * GUESS support.
			 * Payload is optional and holds the GUESS version number encoded
			 * in one byte: the upper 4 bits are the major version, the lower
			 * 4 bits the minor.
			 */

			ALLOCATE(GUE);
			if (ext_paylen(e) > 0) {
				payload = ext_payload(e);
				meta->guess = payload[0];
			} else {
				meta->guess = 0x1;		/* No payload, assume version 0.1 */
			}
			break;
		case EXT_T_GGEP_LOC:
			/*
			 * Preferred locale.
			 * Contains a standard Locale identifier: format is
			 * 'll_[CC[_variant]]', where 'll' is a lowercase ISO639 language
			 * code, 'CC' is a uppercase ISO3166 country/region code, and
			 * 'variant' is a variant code (each subcode is 2 chars min,
			 * case is normaly not significant but should be as indicated
			 * before; the locale identifier subcodes may be longer if needed,
			 * notably for language codes; see RFC 3066). The language code
			 * part is mandatory, other parts are optional but must each be
			 * prefixed by a '_' separator.
			 */

			paylen = ext_paylen(e);

			if (paylen > 1) {
				payload = ext_payload(e);
				ALLOCATE(LOC);
				memcpy(meta->language, payload, 2);
				meta->country[0] = '\0';		/* Signals no country code */
				if (paylen > 4 && payload[2] == '_')
					memcpy(meta->country, &payload[3], 2);
			}
			break;
		case EXT_T_GGEP_UP:
			/*
			 * Ultrapeer.
			 * Payload contains the UP version number (Query-Routing version?)
			 * followed by 1-byte quantities for # of free UP slots and # of
			 * free leaf slots.
			 */

			paylen = ext_paylen(e);

			if (paylen > 2) {
				payload = ext_payload(e);
				ALLOCATE(UP);
				meta->version_up = payload[0];
				meta->leaf_slots = payload[1];
				meta->up_slots = payload[2];
			}
			break;
		case EXT_T_GGEP_VC:
			/*
			 * Vendor code.
			 * The 4-letter vendor code, followed by the User-Agent version.
			 */

			paylen = ext_paylen(e);

			if (paylen >= 4) {
				payload = ext_payload(e);
				ALLOCATE(VC);
				memcpy(meta->vendor, payload, 4);
				if (paylen >= 5)
					meta->version_ua = payload[4];
			}
			break;
		case EXT_T_GGEP_6:			/* IPv6-Ready */
		case EXT_T_GGEP_GTKG_IPV6:	/* Deprecated for 0.97 */
			if (ext_paylen(e) != 0) {
				host_addr_t addr;

				if (GGEP_OK == ggept_gtkg_ipv6_extract(e, &addr)) {
					ALLOCATE(IPV6);
					meta->ipv6_addr = addr;
				}
			}
			break;
		case EXT_T_GGEP_TLS:
			ALLOCATE(TLS);
			break;
		case EXT_T_GGEP_DHT:
			/*
			 * Host is part of the DHT.
			 * Indicates version information and operating flags.
			 */

			paylen = ext_paylen(e);

			if (paylen >= 3) {
				payload = ext_payload(e);
				ALLOCATE(DHT);
				meta->dht_major = payload[0];
				meta->dht_minor = payload[1];
				meta->dht_mode = payload[2];
			}
			break;
		case EXT_T_GGEP_IPP_TLS:
		case EXT_T_GGEP_IPP6_TLS:
			/* Silently ignored */
			break;
		default:
			if (GNET_PROPERTY(ggep_debug) > 3 && e->ext_type == EXT_GGEP) {
				paylen = ext_paylen(e);
				g_warning("%s: unhandled GGEP \"%s\" (%d byte%s)",
					gmsg_node_infostr(n), ext_ggep_id_str(e),
					paylen, plural(paylen));
			}
			break;
		}
	}

#undef ALLOCATE

	return meta;
}

/**
 * Add pong from node `n' to our cache of recent pongs.
 * @returns the cached pong object.
 */
static struct cached_pong *
record_fresh_pong(
	host_type_t type,
	gnutella_node_t *n,
	uint8 hops, host_addr_t addr, uint16 port,
	uint32 files_count, uint32 kbytes_count,
	pong_meta_t *meta)
{
	struct cache_line *cl;
	struct cached_pong *cp;
	uint8 hop;

	g_assert(UNSIGNED(type) < HOST_MAX);

	WALLOC(cp);
	cp->refcount = 1;
	cp->node_id = nid_ref(NODE_ID(n));
	cp->last_sent_id = nid_ref(NODE_ID(n));
	cp->info.addr = addr;
	cp->info.port = port;
	cp->info.files_count = files_count;
	cp->info.kbytes_count = kbytes_count;
	cp->meta = meta;

	hop = CACHE_HOP_IDX(hops);		/* Trim high values to MAX_CACHE_HOPS */
	cl = &pong_cache[hop];
	cl->pongs = pslist_append(cl->pongs, cp);
	add_recent_pong(type, cp);

	return cp;
}

/**
 * Called when an UDP ping is received.
 */
static void
pcache_udp_ping_received(gnutella_node_t *n)
{
	enum ping_flag flags;
	bool is_uhc, throttled;

	g_assert(NODE_IS_UDP(n));

	/*
	 * If we got a PING whose MUID is our node's GUID, then it's a reply
	 * to our "UDP Connect Back" message.
	 */

	if (
		guid_eq(GNET_PROPERTY(servent_guid),
			gnutella_header_get_muid(&n->header))
	) {
		if (GNET_PROPERTY(udp_debug) > 19)
			g_debug("UDP got unsolicited PING matching our GUID!");
		inet_udp_got_unsolicited_incoming();
		return;
	}

	/*
	 * Don't answer to "old" pings (we're catching up with incoming UDP
	 * traffic).
	 */

	if (node_udp_is_old(n)) {
		gnet_stats_count_dropped(n, MSG_DROP_TOO_OLD);
		return;
	}

	/*
	 * Don't answer to pings from bad nodes (includes "alien" hosts).
	 */

	if (hcache_node_is_bad(n->addr)) {
		gnet_stats_count_dropped(n, MSG_DROP_BAD_RETURN_ADDRESS);
		return;
	}

	/*
	 * Count pure UHC pings (i.e. ones without GUESS).
	 */

	flags = ping_type(n);
	is_uhc = booleanize(PING_F_UHC == ((PING_F_GUE | PING_F_UHC) & flags));
	throttled = FALSE;

	if (is_uhc)
		gnet_stats_inc_general(GNR_UDP_UHC_PINGS);

	/*
	 * Don't answer to too frequent pings from the same IP.
	 */

	if (aging_lookup(udp_pings, &n->addr)) {
        gnet_stats_count_dropped(n, MSG_DROP_THROTTLE);
		throttled = TRUE;
	} else {
		aging_insert(udp_pings,
			wcopy(&n->addr, sizeof n->addr), GUINT_TO_POINTER(1));

		/*
		 * Answers to UHC pings are sent back with a "control" priority.
		 */

		send_personal_info(n, is_uhc, flags);
		throttled = FALSE;

		if (is_uhc)
			gnet_stats_inc_general(GNR_UDP_UHC_PONGS);
	}

	if (is_uhc && GNET_PROPERTY(log_uhc_pings_rx)) {
		g_debug("UDP UHC got %s from %s%s",
			gmsg_infostr_full_split(n->header, n->data, n->size),
			node_infostr(n), throttled ? " (throttled)" : "");
	}
}

/*
 * Shall we accept the ping?.
 */
static bool
pcache_ping_accept(gnutella_node_t *n)
{
	time_t now = tm_time();

	if (now < n->ping_accept) {
		n->n_ping_throttle++;		/* Drop the ping */
        gnet_stats_count_dropped(n, MSG_DROP_THROTTLE);
		return FALSE;
	} else {
		n->n_ping_accepted++;
		n->ping_accept = now + n->ping_throttle;	/* Drop all until then */

		/*
		 * Add penalty for non TX-compressed nodes (uncompressed pong traffic
		 * can really waste bandwidth).
		 */

		if (!NODE_TX_COMPRESSED(n))
			n->ping_accept += n->ping_throttle;

		/*
		 * Throttle pings from transient nodes a little more since their
		 * connection is unlikely to stay up very long.  The more they
		 * insist the longer we'll throttle them, as a safety net.
		 */

		if (NODE_IS_TRANSIENT(n)) {
			unsigned extra = n->n_ping_throttle + PCACHE_TRANSIENT / 10;
			n->ping_accept += MIN(extra, PCACHE_TRANSIENT);
		}

		return TRUE;
	}
}

/**
 * Called when a ping is received from a node.
 *
 * Here needs brief description for the following list:
 *
 * - If current time is less than what `ping_accept' says, drop the ping.
 *   Otherwise, accept the ping and increment `ping_accept' by n->ping_throttle.
 * - If cache expired, call pcache_expire() and broadcast a new ping to all
 *   the "new" clients (i.e. those flagged NODE_A_PONG_CACHING).  For "old"
 *   clients, do so only if "next_ping" time was reached.
 * - Handle "alive" pings (TTL=1) and "crawler" pings (TTL=2) immediately,
 *   then return.
 * - Setup pong demultiplexing tables, recording the fact that  the node needs
 *   to be sent pongs as we receive them.
 * - Return a pong for us if we accept incoming connections right now.
 * - Return cached pongs, avoiding to resend a pong coming from that node ID.
 */
void
pcache_ping_received(gnutella_node_t *n)
{
	time_t now = tm_time();

	g_assert(NODE_IS_CONNECTED(n));

	if (NODE_IS_UDP(n)) {
		pcache_udp_ping_received(n);
		return;
	}

	/*
	 * Handle "alive" pings and "crawler" pings specially.
	 * Besides, we always accept them.
	 *
	 * If we get a TTL=0 ping, assume it's used to ack an "alive ping" we
	 * sent earlier.  Don't even log we got a message with TTL=0, we're
	 * getting way too many of them and nobody on the GDF seems to care.
	 * BearShare is known to do this, and they admitted it publicly like
	 * it was a good idea!
	 *		--RAM, 2004-08-09
	 */

	if (
		gnutella_header_get_hops(&n->header) == 0 &&
		gnutella_header_get_ttl(&n->header) <= 2
	) {
		uint8 ttl = gnutella_header_get_ttl(&n->header);

		n->n_ping_special++;

		/*
		 * Transient nodes are severely limited, because we don't want
		 * to waste traffic to them.
		 *		--RAM, 2012-01-15
		 */

		if (NODE_IS_TRANSIENT(n) && ttl > 1 && !pcache_ping_accept(n))
			return;

		n->n_ping_accepted++;

		if (1 == ttl)
			send_personal_info(n, TRUE, PING_F_NONE);	/* Prioritary */
		else if (2 == ttl) {
			if (settings_is_ultra())
				send_neighbouring_info(n);
		} else
			alive_ack_first(n->alive_pings,
				gnutella_header_get_muid(&n->header));
		return;
	}

	/*
	 * If we get a ping with hops != 0 from a host that claims to
	 * implement ping/pong reduction, then they are not playing
	 * by the same rules as we are.  Emit a warning.
	 *		--RAM, 03/03/2001
	 */

	if (
		gnutella_header_get_hops(&n->header) &&
		(n->attrs & (NODE_A_PONG_CACHING|NODE_A_PONG_ALIEN)) ==
			NODE_A_PONG_CACHING
	) {
		if (GNET_PROPERTY(pcache_debug))
			g_warning("%s [%d.%d] claimed ping reduction, "
				"got ping with hops=%d",
				node_infostr(n), n->proto_major, n->proto_minor,
				gnutella_header_get_hops(&n->header));
		n->attrs |= NODE_A_PONG_ALIEN;		/* Warn only once */
	}

	/*
	 * Accept the ping?.
	 */

	if (!pcache_ping_accept(n))
		return;

	/*
	 * Purge cache if needed.
	 */

	pcache_possibly_expired(now);

	if (!NODE_IS_CONNECTED(n))		/* Can be removed if send queue is full */
		return;

	/*
	 * If we can accept an incoming connection, send a reply.
	 *
	 * If we are firewalled, we nonetheless send a ping
	 * when inet_can_answer_ping() tells us we can, irrespective
	 * of whether we can accept a new node connection: the aim is
	 * to trigger an incoming connection that will prove us we're
	 * not firewalled.
	 *
	 * Finally, we always reply to the first ping we get with our
	 * personal information (reply to initial ping sent after handshake).
	 */

	if (1 == n->n_ping_accepted || pcache_can_answer_ping()) {
		send_personal_info(n, FALSE, PING_F_NONE);
		if (!NODE_IS_CONNECTED(n))	/* Can be removed if send queue is full */
			return;
	}

	if (settings_is_leaf())
		return;

	/*
	 * We continue here only for non-leaf nodes.
	 */

	send_demultiplexed_pongs(n);
}

/**
 * Called when an UDP pong is received.
 */
static void
pcache_udp_pong_received(gnutella_node_t *n)
{
	host_addr_t ipv4_addr;
	host_addr_t ipv6_addr;	/* Extracted, but value unused currently */
	bool supports_tls;
	bool supports_dht;
	gnet_host_t host;
	uint16 port;
	int i;

	g_assert(NODE_IS_UDP(n));

	switch (udp_ping_is_registered(n, &host)) {
	case UDP_PONG_UNSOLICITED:
		if (guess_rpc_handle(n))
			return;
		if (GNET_PROPERTY(bootstrap_debug) || GNET_PROPERTY(udp_debug)) {
			g_message("UDP ignoring unsolicited %s from %s",
				gmsg_infostr(n->header), node_addr(n));
		}
		/* FALL THROUGH */
	case UDP_PONG_HANDLED:
		return;
	case UDP_PONG_SOLICITED:
		break;
	}

	port = peek_le16(&n->data[0]);
	ipv4_addr = host_addr_peek_ipv4(&n->data[2]);
	ipv6_addr = zero_host_addr;
	supports_tls = FALSE;
	supports_dht = FALSE;

	if (GNET_PROPERTY(udp_debug) && port != gnet_host_get_port(&host)) {
		g_warning("UDP ping set to %s but host advertises %s in its pong",
			gnet_host_to_string(&host),
			host_addr_port_to_string(ipv4_addr, port));
	}
	
	/*
	 * We pretty much ignore pongs we get from UDP, unless they bear
	 * the GGEP "IPP" or "DHTIPP" extensions, containing a packed set
	 * of IP:port.
	 */

	for (i = 0; i < n->extcount; i++) {
		extvec_t *e = &n->extvec[i];
		uint16 paylen;
		const char *payload;

		switch (e->ext_token) {
		case EXT_T_GGEP_IPP:
		case EXT_T_GGEP_DHTIPP:
		case EXT_T_GGEP_IPP6:
		case EXT_T_GGEP_DHTIPP6:
		{
			int len;
			enum net_type nt;

			paylen = ext_paylen(e);
			payload = ext_payload(e);

			switch (e->ext_token) {
			case EXT_T_GGEP_IPP:		len = 6;	nt = NET_TYPE_IPV4; break;	
			case EXT_T_GGEP_DHTIPP:		len = 6;	nt = NET_TYPE_IPV4; break;	
			case EXT_T_GGEP_IPP6:		len = 18;	nt = NET_TYPE_IPV6; break;	
			case EXT_T_GGEP_DHTIPP6:	len = 18;	nt = NET_TYPE_IPV6; break;	
			default:
				g_assert_not_reached();
			}

			if (paylen % len) {
				if (GNET_PROPERTY(pcache_debug) || GNET_PROPERTY(ggep_debug)) {
					g_warning("%s (UDP): "
						"bad length for GGEP \"%s\" "
						"(%d byte%s, not multiple of %d)",
						gmsg_node_infostr(n), ext_ggep_id_str(e),
						paylen, plural(paylen), len);
				}
			} else {
				switch (e->ext_token) {
				case EXT_T_GGEP_IPP:
				case EXT_T_GGEP_IPP6:
					uhc_ipp_extract(n, payload, paylen, nt); 
					break;
				case EXT_T_GGEP_DHTIPP:
				case EXT_T_GGEP_DHTIPP6:
					dht_ipp_extract(n, payload, paylen, nt); 
					break;
				default:
					g_assert_not_reached();
				}
			}
			break;
		}
		case EXT_T_GGEP_6:			/* IPv6-Ready */
		case EXT_T_GGEP_GTKG_IPV6:	/* Deprecated for 0.97 */
			if (ext_paylen(e) != 0) {
				ggept_gtkg_ipv6_extract(e, &ipv6_addr);
			}
			break;
		case EXT_T_GGEP_TLS:
		case EXT_T_GGEP_GTKG_TLS:	/* Deprecated for 0.97 */
			supports_tls = TRUE;
			break;
		case EXT_T_GGEP_DHT:
			if (ext_paylen(e) >= 3) {
				uint8 mode;

				payload = ext_payload(e);
				mode = payload[2];

				/* We want to ping active DHT nodes only */
				if (mode == DHT_MODE_ACTIVE)
					supports_dht = TRUE;
			}
			break;
		case EXT_T_GGEP_UP:
		case EXT_T_GGEP_LOC:
		case EXT_T_GGEP_IPP_TLS:
		case EXT_T_GGEP_IPP6_TLS:
			/* Silently ignored */
			break;
		default:
			if (GNET_PROPERTY(ggep_debug) > 1 && e->ext_type == EXT_GGEP) {
				paylen = ext_paylen(e);
				g_warning("%s (UDP): unhandled GGEP \"%s\" (%d byte%s)",
					gmsg_node_infostr(n), ext_ggep_id_str(e),
					paylen, plural(paylen));
			}
			break;
		}
	}

	/*
	 * Since host replied to the ping, it is alive at the IP:port to which
	 * the ping was sent.
	 */

	{
		host_addr_t addr;
		uint16 hport;

		addr = gnet_host_get_addr(&host);
		hport = gnet_host_get_port(&host);

		if (!hcache_node_is_bad(addr)) {
			/* Asuume the (valid) UDP port is also a proper TCP port */
			host_add(addr, hport, TRUE);
			if (supports_tls) {
				tls_cache_insert(addr, hport);
			}
			if (supports_dht) {
				dht_bootstrap_if_needed(addr, hport);
			}
		}
	}
}

/**
 * Called when a pong is received from a node.
 *
 * Here needs brief description for the following list:
 *
 * - Record node in the main host catching list.
 * - If node is not a "new" client (i.e. flagged as NODE_A_PONG_CACHING),
 *   cache randomly OLD_CACHE_RATIO percent of those (older clients need
 *   to be able to get incoming connections as well).
 * - Cache pong in the pong.hops cache line, associated with the node ID (so we
 *   never send back this entry to the node).
 * - For all nodes but `n', propagate pong if neeed, with demultiplexing.
 */
void
pcache_pong_received(gnutella_node_t *n)
{
	uint16 port;
	uint32 files_count;
	uint32 kbytes_count;
	uint32 swapped_count;
	struct cached_pong *cp;
	host_type_t ptype;
	host_addr_t addr;
	pong_meta_t *meta;

	n->n_pong_received++;

	if (NODE_IS_UDP(n)) {
		pcache_udp_pong_received(n);
		return;
	}

	/*
	 * Decompile the pong information.
	 */

	port = peek_le16(&n->data[0]);
	addr = host_addr_peek_ipv4(&n->data[2]);
	files_count = peek_le32(&n->data[6]);
	kbytes_count = peek_le32(&n->data[10]);
	
	meta = pong_extract_metadata(n);

	/*
	 * IPv6-Ready: if there is an IPv6 address supplied in a GGEP "6" extension
	 * and the IPv4 address in the legacy pong field is 127.0.0.0 to indicate
	 * that there is no IPv4 support, force the address to be the IPv6 one.
	 *
	 * Likewise, if the host is not configured for IPv4, use the IPv6 address
	 * and discard the IPv4 address we cannot use anyway since they are only
	 * on the IPv6 network.
	 */

	if (
		meta != NULL && (meta->flags & PONG_META_HAS_IPV6) &&
		(ipv6_ready_no_ipv4_addr(addr) || !settings_use_ipv4())
	) {
		addr = meta->ipv6_addr;		/* IPv6-Ready support */
	}

	/*
	 * Sanity checks: make sure the files_count is reasonable, or try
	 * to swap it otherwise.  Then try to adjust the kbytes_count if we
	 * fixed the files_count.
	 *		--RAM, 13/07/2004
	 */

	if (files_count > PCACHE_MAX_FILES) {	/* Arbitrarily large constant */
		bool fixed = FALSE;

		swapped_count = swap_uint32(files_count);

		if (swapped_count > PCACHE_MAX_FILES) {
			if (GNET_PROPERTY(pcache_debug) && host_addr_equiv(addr, n->addr))
				g_warning("%s sent us a pong with "
					"large file count %u (0x%x), dropped",
					node_infostr(n), files_count, files_count);
			n->rx_dropped++;
			goto done;
		} else {
			if (GNET_PROPERTY(pcache_debug) && host_addr_equiv(addr, n->addr))
				g_warning("%s sent us a pong with suspect file count %u "
					"(fixed to %u)",
					node_infostr(n), files_count, swapped_count);
			files_count = swapped_count;
			fixed = TRUE;
		}
		/*
		 * Maybe the kbytes_count is correct if the files_count was?
		 */

		swapped_count = swap_uint32(kbytes_count);

		if (fixed && swapped_count < kbytes_count)
			kbytes_count = swapped_count;		/* Probably wrong as well */
	}

	/*
	 * Handle replies from our neighbours specially
	 */

	if (gnutella_header_get_hops(&n->header) == 0) {
		/*
		 * For an incoming connection, we might not know the GNet IP address
		 * of the remote node yet (we know the remote endpoint, but it could
		 * be a proxy for a firewalled node).  The information from the pong
		 * may help us fill this gap.
		 */

		if (!is_host_addr(n->gnet_addr) && (n->flags & NODE_F_INCOMING)) {
			if (host_addr_equiv(addr, n->addr)) {
				n->gnet_addr = addr;	/* Signals: we have figured it out */
				n->gnet_port = port;
			} else if (!(n->flags & NODE_F_ALIEN_IP)) {
				if (GNET_PROPERTY(pcache_debug)) g_warning(
					"%s sent us a pong for itself with alien IP %s",
					node_infostr(n), host_addr_to_string(addr));
				n->flags |= NODE_F_ALIEN_IP;	/* Probably firewalled */
			}
		}

		/*
		 * Only record library stats for the node if it is the first pong
		 * we receive from it (likely to be a reply to our handshaking ping)
		 * or if it comes from the node's IP.
		 * Indeed, LimeWire suffers from a bug where it will forward foreign
		 * pongs with hops=0 even though they are not coming from the node.
		 *		--RAM, 11/01/2004.
		 */

		if (n->n_pong_received == 1 || host_addr_equiv(addr, n->gnet_addr)) {
			n->gnet_files_count = files_count;
			n->gnet_kbytes_count = kbytes_count;
			n->flags |= NODE_F_SHARED_INFO;
		}

		/*
		 * Spot any change in the pong's IP address.  We try to avoid messages
		 * about "connection pongs" by checking whether we have sent at least
		 * 2 pings (one handshaking ping plus one another).
		 */

		if (
			is_host_addr(n->gnet_pong_addr) &&
			!host_addr_equiv(addr, n->gnet_pong_addr)
		) {
			if (GNET_PROPERTY(pcache_debug) && n->n_ping_sent > 2) {
				g_warning("%s sent us a pong for new IP %s (used %s before)",
					node_infostr(n),
					host_addr_port_to_string(addr, port),
					host_addr_to_string(n->gnet_pong_addr));
			}
		}

		n->gnet_pong_addr = addr;

		/*
		 * If it was an acknowledge for one of our alive pings, don't cache.
		 */

		if (alive_ack_ping(n->alive_pings, gnutella_header_get_muid(&n->header)))
			goto done;
	}

	/*
	 * If it's not a connectible pong, discard it.
	 */

	if (!host_is_valid(addr, port)) {
		gnet_stats_count_dropped(n, MSG_DROP_PONG_UNUSABLE);
		goto done;
	}

	/*
	 * If pong points to an hostile IP address, discard it.
	 */

	if (hostiles_is_bad(addr)) {
		gnet_stats_count_dropped(n, MSG_DROP_HOSTILE_IP);
		goto done;
	}

	/*
	 * If pong points to us, maybe we explicitly connected to ourselves
	 * (tests) or someone is trying to fool us.
	 */

	if (is_my_address_and_port(addr, port))
		goto done;

	/*
	 * Add pong to our reserve, and possibly try to connect.
	 */

	host_add(addr, port, TRUE);

	/*
	 * If we got a pong from an "old" client, cache OLD_CACHE_RATIO of
	 * its pongs, randomly.  Returning from this routine means we won't
	 * cache it.
	 */

	if (!(n->attrs & NODE_A_PONG_CACHING)) {
		unsigned ratio = random_value(100);
		if (ratio >= OLD_CACHE_RATIO) {
			if (GNET_PROPERTY(pcache_debug) > 7)
				g_debug("NOT CACHED pong %s (hops=%d, TTL=%d) from OLD %s",
					host_addr_port_to_string(addr, port),
					gnutella_header_get_hops(&n->header),
					gnutella_header_get_ttl(&n->header),
					node_addr(n));
			goto done;
		}
	}

	/*
	 * Insert pong within our cache.
	 */

	cp = record_fresh_pong(HOST_ANY, n, gnutella_header_get_hops(&n->header),
			addr, port, files_count, kbytes_count, meta);
	meta = NULL;	/* Metadata now owned by cached pong */

	ptype = pong_type(cast_to_pointer(n->data));
	if (cp->meta != NULL && (cp->meta->flags & PONG_META_HAS_UP))
		ptype = HOST_ULTRA;

	if (ptype == HOST_ULTRA)
		add_recent_pong(HOST_ULTRA, cp);

	if (cp->meta != NULL && (cp->meta->flags & PONG_META_HAS_GUE)) {
		/*
		 * If we're connected, we learnt about this GUESS host through
		 * Gnutella handshaking.  The host is valid, we don't want to
		 * smear it out from the GUESS cache.
		 */

		if (!node_is_connected(addr, port, FALSE)) {
			hcache_add_caught(HOST_GUESS, addr, port, "pong");
		}
	}

	if (GNET_PROPERTY(pcache_debug) > 6)
		g_debug("CACHED %s pong %s (hops=%d, TTL=%d) from %s %s",
			ptype == HOST_ULTRA ? "ultra" : "normal",
			host_addr_port_to_string(addr, port),
			gnutella_header_get_hops(&n->header),
			gnutella_header_get_ttl(&n->header),
			(n->attrs & NODE_A_PONG_CACHING) ? "NEW" : "OLD", node_addr(n));

	/*
	 * Demultiplex pong: send it to all the connections but the one we
	 * received it from, provided they need more pongs of this hop count.
	 */

	if (settings_is_ultra())
		pong_all_neighbours_but_one(n, cp, ptype,
			CACHE_HOP_IDX(gnutella_header_get_hops(&n->header)),
			MAX(1, gnutella_header_get_ttl(&n->header)));

	/*
	 * If we're in ultra mode, send 33% of all the ultra pongs we get
	 * to one random leaf.
	 */

	if (settings_is_ultra() && ptype == HOST_ULTRA && random_value(99) < 33)
		pong_random_leaf(cp,
			CACHE_HOP_IDX(gnutella_header_get_hops(&n->header)),
			MAX(1, gnutella_header_get_ttl(&n->header)));

	/*
	 * If host indicates DHT support for non-firewalled node, use that
	 * address for bootstrapping, if necessary.
	 */

	if (
		cp->meta != NULL && (cp->meta->flags & PONG_META_HAS_DHT) &&
		cp->meta->dht_mode == DHT_MODE_ACTIVE
	)
		dht_bootstrap_if_needed(addr, port);

done:
	if (meta != NULL) {
		WFREE(meta);
	}
}

/**
 * Fake a pong for a node from which we received an incoming connection,
 * using the supplied IP/port.
 *
 * This pong is not multiplexed to neighbours, but is used to populate our
 * cache, so we can return its address to others, assuming that if it is
 * making an incoming connection to us, it is really in need for other
 * connections as well.
 */
void
pcache_pong_fake(gnutella_node_t *n, const host_addr_t addr, uint16 port)
{
	g_assert(n->attrs & NODE_A_ULTRA);

	if (!host_is_valid(addr, port))
		return;

	host_add(addr, port, FALSE);
	(void) record_fresh_pong(HOST_ULTRA, n, 1, addr, port, 0, 0, NULL);
}

/* vi: set ts=4 sw=4 cindent: */
