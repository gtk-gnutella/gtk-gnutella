/*
 * $Id$
 *
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

RCSID("$Id$")

#include "sockets.h"
#include "hosts.h"
#include "hcache.h"
#include "pcache.h"
#include "nodes.h"
#include "share.h" /* For shared_files_scanned() and shared_kbytes_scanned(). */
#include "routing.h"
#include "gmsg.h"
#include "alive.h"
#include "inet.h"
#include "gnet_stats.h"
#include "hostiles.h"
#include "settings.h"
#include "udp.h"
#include "uhc.h"
#include "extensions.h"
#include "ggep.h"
#include "ggep_type.h"
#include "version.h"

#include "if/core/hosts.h"
#include "if/gnet_property_priv.h"

#include "lib/aging.h"
#include "lib/atoms.h"
#include "lib/endian.h"
#include "lib/tm.h"
#include "lib/walloc.h"
#include "lib/override.h"	/* Must be the last header included */

#define PCACHE_MAX_FILES	10000000	/**< Arbitrarily large file count */
#define PCACHE_UHC_MAX_IP	30			/**< Max amount of IP:port returned */

/**
 * Basic pong information.
 */
struct pong_info {
	host_addr_t addr;				/**< Values from the pong message */
	guint32 port;
	guint32 files_count;
	guint32 kbytes_count;
};

enum ping_flag {
	PING_F_NONE			= 0,		/**< No special ping */
	PING_F_UHC			= (1 << 0),	/**< UHC ping */
	PING_F_UHC_LEAF		= (1 << 1),	/**< UHC ping, wants leaf slots */
	PING_F_UHC_ULTRA	= (1 << 2),	/**< UHC ping, wants ultra slots */
	PING_F_UHC_ANY		= (PING_F_UHC_LEAF | PING_F_UHC_ULTRA),
	PING_F_IP			= (1 << 3)	/**< GGEP IP */
};

static pong_meta_t local_meta;

/***
 *** Messages
 ***/

/**
 * Sends a ping to given node, or broadcast to everyone if `n' is NULL.
 */
static void
send_ping(struct gnutella_node *n, guint8 ttl)
{
	gnutella_msg_init_t *m;
	guint32 size;

	STATIC_ASSERT(23 == sizeof *m);	
	m = build_ping_msg(NULL, ttl, FALSE, &size);

	if (n) {
		g_assert(!NODE_IS_UDP(n));

		if (NODE_IS_WRITABLE(n)) {
			n->n_ping_sent++;
			gmsg_sendto_one(n, m, size);
		}
	} else {
		const GSList *sl_nodes = node_all_nodes();
		const GSList *sl;

		/*
		 * XXX Have to loop to count pings sent.
		 * XXX Need to do that more generically, to factorize code.
		 */

		for (sl = sl_nodes; sl; sl = g_slist_next(sl)) {
			n = sl->data;
			if (!NODE_IS_WRITABLE(n))
				continue;
			n->n_ping_sent++;
		}

		gmsg_sendto_all(sl_nodes, m, size);
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
build_ping_msg(const gchar *muid, guint8 ttl, gboolean uhc, guint32 *size)
{
	static union {
		gnutella_msg_init_t s;
		gchar buf[256];
		guint64 align8;
	} msg_init;
	gnutella_msg_init_t *m = &msg_init.s;
	guint32 sz;

	g_assert(ttl);
	STATIC_ASSERT(sizeof *m <= sizeof msg_init.buf);
	STATIC_ASSERT(23 == sizeof *m);

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
		guchar *ggep;
		ggep_stream_t gs;
		gboolean ok;
		gchar spp;

		ggep = cast_to_gpointer(&m[1]);
		ggep_stream_init(&gs, ggep, sizeof msg_init.buf - sizeof *m);
		
		spp = (current_peermode == NODE_P_LEAF) ? 0x0 : 0x1;
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

		sz += ggep_stream_close(&gs);
	}

	gnutella_header_set_size(m, sz);

	if (size)
		*size = sz + GTA_HEADER_SIZE;

	return m;
}

/**
 * Build pong message.
 *
 * @return pointer to static data, and the size of the message in `size'.
 */
static gnutella_msg_init_response_t *
build_pong_msg(host_addr_t sender_addr, guint16 sender_port,
	guint8 hops, guint8 ttl, const gchar *muid,
	struct pong_info *info, pong_meta_t *meta, enum ping_flag flags,
	guint32 *size)
{
	static union {
		gnutella_msg_init_response_t s;
		gchar buf[1024];
		guint64 align8;
	} msg_pong;
	gnutella_msg_init_response_t *pong = &msg_pong.s;
	ggep_stream_t gs;
	guchar *ggep;
	guint32 sz;

	STATIC_ASSERT(37 == sizeof *pong);
	ggep = cast_to_gpointer(&pong[1]);

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

	{
		host_addr_t addr;

		host_addr_convert(info->addr, &addr, NET_TYPE_IPV4);
		gnutella_msg_init_response_set_host_ip(pong, host_addr_ipv4(addr));
	}

	sz = sizeof *pong - GTA_HEADER_SIZE;

	/*
	 * Add GGEP meta-data if we have some to propagate.
	 */

	ggep_stream_init(&gs, ggep, sizeof msg_pong.buf - sizeof *pong);

	/*
	 * First, start with metadata about our host.
	 */

	if (meta != NULL) {
		if (meta->flags & PONG_META_HAS_VC) {	/* Vendor code */
			gboolean ok;

			ok = ggep_stream_begin(&gs, GGEP_NAME(VC), 0) &&
			ggep_stream_write(&gs, meta->vendor, sizeof meta->vendor) &&
			ggep_stream_write(&gs, &meta->version_ua, 1) &&
			ggep_stream_end(&gs);
		}

		if (meta->flags & PONG_META_HAS_GUE)	/* GUESS support */
			ggep_stream_pack(&gs, GGEP_NAME(GUE),
				cast_to_gpointer(&meta->guess), 1, 0);

		if (meta->flags & PONG_META_HAS_UP) {	/* Ultrapeer info */
			gboolean ok;

			ok = ggep_stream_begin(&gs, GGEP_NAME(UP), 0) &&
			ggep_stream_write(&gs, &meta->version_up, 1) &&
			ggep_stream_write(&gs, &meta->up_slots, 1) &&
			ggep_stream_write(&gs, &meta->leaf_slots, 1) &&
			ggep_stream_end(&gs);
		}

		if (meta->flags & PONG_META_HAS_LOC) {	/* Locale preferencing */
			gboolean ok;

			ok = ggep_stream_begin(&gs, GGEP_NAME(LOC), 0) &&
				ggep_stream_write(&gs, meta->language, 2);

			if (ok && meta->country[0])
				ok = ggep_stream_write(&gs, "_", 1) &&
					ggep_stream_write(&gs, meta->country, 2);

			ok = ok && ggep_stream_end(&gs);
		}

		if (meta->flags & PONG_META_HAS_DU) {	/* Daily average uptime */
			gchar uptime[sizeof(guint64)];
			guint32 value = MIN(meta->daily_uptime, 86400);
			guint len;

			len = ggept_du_encode(value, uptime);
			ggep_stream_pack(&gs, GGEP_NAME(DU), uptime, len, 0);
		}

		if (meta->flags & PONG_META_HAS_IPV6) {
			ggep_stream_pack(&gs, GGEP_GTKG_NAME(IPV6),
				host_addr_ipv6(&meta->ipv6_addr), 16, 0);
		}

	}

	/*
	 * If we're replying to an UDP node, and they sent an "SCP" in their
	 * ping, then we're acting as an UDP host cache.  Give them some
	 * fresh pongs of hosts with free slots.
	 */

	if (0 != (flags & PING_F_UHC)) {
		/*
		 * XXX For this first implementation, ignore their desire.  Just
		 * XXX fill a bunch of hosts as we would for an X-Try-Ultrapeer header.
		 */

		gnet_host_t host[PCACHE_UHC_MAX_IP];
		gint hcount;

		hcount = hcache_fill_caught_array(HOST_ULTRA, host, PCACHE_UHC_MAX_IP);

		if (hcount > 0) {
			gint i;
			gboolean ok;

			/*
			 * The binary data that makes up IPP does not deflate well.
			 * The 180 bytes of data for 30 addresses typically end up
			 * being 175 bytes after compression.  It's not worth the
			 * pain and the CPU overhead.
			 */

			ok = ggep_stream_begin(&gs, GGEP_NAME(IPP), 0);

			for (i = 0; ok && i < hcount; i++) {
				/* @todo TODO: IPv6 */
				if (NET_TYPE_IPV4 == gnet_host_get_net(&host[i])) {
					gchar addr_buf[6];
					guint32 ip;

					ip = host_addr_ipv4(gnet_host_get_addr(&host[i]));
					poke_be32(&addr_buf[0], ip);
					poke_le16(&addr_buf[4], gnet_host_get_port(&host[i]));
					ok = ggep_stream_write(&gs, addr_buf, sizeof addr_buf);
				}
			}

			ok = ok && ggep_stream_end(&gs);
		}
	}

	if ((flags & PING_F_IP) && NET_TYPE_IPV4 == host_addr_net(sender_addr)) {
		gchar ip_port[6];

		/* Ip Port (not UHC IPP!)*/
		if (pcache_debug || ggep_debug)
			g_message("adding GGEP IP for %s",
				host_addr_port_to_string(sender_addr, sender_port));

		poke_be32(&ip_port[0], host_addr_ipv4(sender_addr));
		poke_le16(&ip_port[4], sender_port);
		ggep_stream_pack(&gs, GGEP_NAME(IP), ip_port, sizeof ip_port, 0);
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
	struct gnutella_node *n, gboolean control, enum ping_flag flags,
	guint8 hops, guint8 ttl, const gchar *muid,
	struct pong_info *info, pong_meta_t *meta)
{
	gnutella_msg_init_response_t *r;
	guint32 size;

	g_assert(ttl >= 1);

	if (!NODE_IS_WRITABLE(n))
		return;

	/*
	 * We don't include metadata when sending the pong as a "control" message,
	 * as this means that we're replying to an "alive" check.
	 */

	r = build_pong_msg(n->addr, n->port, hops, ttl, muid, info,
			control ? NULL : meta, flags, &size);
	n->n_pong_sent++;

	g_assert(!control || size == sizeof *r);	/* control => no extensions */

	if (NODE_IS_UDP(n))
		udp_send_msg(n, r, size);
	else if (control)
		gmsg_ctrl_sendto_one(n, r, sizeof *r);
	else
		gmsg_sendto_one(n, r, size);
}

/**
 * Determine whether this is an UHC ping (mentionning "SCP" support).
 *
 * @return UHC_NONE if not an UHC ping, the UHC type otherwise.
 */
static enum ping_flag
ping_type(const gnutella_node_t *n)
{
	gint i;
	enum ping_flag flags = PING_F_NONE;

	for (i = 0; i < n->extcount; i++) {
		const extvec_t *e = &n->extvec[i];
		guint16 paylen;

		switch (e->ext_token) {
		case EXT_T_GGEP_SCP:
			/*
		 	 * Look whether they want leaf slots, ultra slots, or don't care.
		 	 */

			/* Accept only the first SCP, just in case there are multiple */
			if (!(flags & PING_F_UHC)) {
				flags |= PING_F_UHC;

				paylen = ext_paylen(e);
				if (paylen >= 1) {
					const guchar *payload = ext_payload(e);
					guint8 mask = payload[0];
					flags |= (mask & 0x1) ? PING_F_UHC_ULTRA : PING_F_UHC_LEAF;
				} else {
					flags |= PING_F_UHC_ANY;
				}
			}
			break;

		case EXT_T_GGEP_IP:
			if (
				0 == (flags & PING_F_IP) &&
				NODE_IS_UDP(n) &&
				0 == gnutella_header_get_hops(&n->header) &&
				1 == gnutella_header_get_ttl(&n->header) &&
				0 == ext_paylen(e)
			) {
				flags |= PING_F_IP;
			}
			break;

		default: ;
		}

	}

	if ((flags & PING_F_UHC) && ggep_debug > 1)
		printf("%s: UHC ping requesting %s slots from %s\n",
			gmsg_infostr(&n->header),
			(flags & PING_F_UHC_ANY) ?	"unspecified" :
			(flags & PING_F_UHC_ULTRA) ?	"ultra" : "leaf",
			host_addr_port_to_string(n->addr, n->port));

	return flags;
}

/**
 * Send info about us back to node, using the hopcount information present in
 * the header of the node structure to construct the TTL of the pong we
 * send.
 *
 * If `control' is true, send it as a higher priority message.
 * If `uhc' is not UHC_NONE, we'll send IPs in a packed IPP reply.
 */
static void
send_personal_info(struct gnutella_node *n, gboolean control,
	enum ping_flag flags)
{
	guint32 kbytes;
	guint32 files;
	struct pong_info info;
	guint32 ip_uptime;
	guint32 avg_uptime;

	/* Replying to a ping */
	g_assert(gnutella_header_get_function(&n->header) == GTA_MSG_INIT);

	files = MIN(shared_files_scanned(), ~((guint32) 0U));

	/*
	 * Mark pong if we are an ultra node: the amount of kbytes scanned must
	 * be an exact power of two, and at minimum 8.
	 */

	kbytes = MIN(shared_kbytes_scanned(), ~((guint32) 0U));

	if (current_peermode == NODE_P_ULTRA) {
		guint32 next, prev;
		
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
	 */

	info.addr = listen_addr();
	info.port = socket_listen_port();
	info.files_count = files;
	info.kbytes_count = kbytes;

	/*
	 * What matters for the uptime is both the actual servent uptime and the
	 * stability of the IP address.  If they have high uptimes but change IP
	 * every 12 hours, it makes no sense to advertise a high daily uptime...
	 */

	ip_uptime = delta_time(tm_time(), current_ip_stamp);
	ip_uptime = MAX(ip_uptime, average_ip_uptime);
	avg_uptime = get_average_servent_uptime(tm_time());
	local_meta.daily_uptime = MIN(avg_uptime, ip_uptime);

	/*
	 * Activate "UP" only if we're an ultrapeer right now.
	 */

	if (current_peermode == NODE_P_ULTRA) {
		local_meta.flags |= PONG_META_HAS_UP;
		local_meta.up_slots = MIN(node_missing(), 255);
		local_meta.leaf_slots = MIN(node_leaves_missing(), 255);
	}

	if ((flags & PING_F_IP)) {
		local_meta.sender_addr = n->addr;
		local_meta.sender_port = n->port;
	}

	if (
		NET_TYPE_IPV6 == host_addr_net(listen_addr6()) &&
		is_host_addr(listen_addr6())
	) {
		local_meta.ipv6_addr = listen_addr6();
		local_meta.flags |= PONG_META_HAS_IPV6;
	}

	send_pong(n, control, flags, 0,
		MIN((guint) gnutella_header_get_hops(&n->header) + 1, max_ttl),
		gnutella_header_get_muid(&n->header), &info, &local_meta);

	/* Reset flags that must be recomputed each time */
	local_meta.flags &= ~PONG_META_HAS_UP;
}

/**
 * Send a pong for each of our connected neighbours to specified node.
 */
static void
send_neighbouring_info(struct gnutella_node *n)
{
	const GSList *sl;

	/* Replying to a ping */
	g_assert(gnutella_header_get_function(&n->header) == GTA_MSG_INIT);
	/* Originates from node */
	g_assert(gnutella_header_get_hops(&n->header) == 0);
	g_assert(gnutella_header_get_ttl(&n->header) == 2);	/* "Crawler" ping */

	for (sl = node_all_nodes(); sl; sl = g_slist_next(sl)) {
		struct gnutella_node *cn = sl->data;
		struct pong_info info;

		if (!NODE_IS_WRITABLE(cn))
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
static gpointer udp_pings = NULL;

struct cached_pong {		/**< A cached pong */
	gint refcount;			/**< How many lists reference us? */
	node_id_t node_id;		/**< The node ID from which we got that pong */
	node_id_t last_sent_id; /**< Node ID we last sent this pong to */
	struct pong_info info;	/**< Values from the pong message */
	pong_meta_t *meta;		/**< Optional meta data */
};

struct cache_line {			/**< A cache line for a given hop value */
	gint hops;				/**< Hop count of this cache line */
	GSList *pongs;			/**< List of cached_pong */
	GSList *cursor;			/**< Cursor within list: last item traversed */
};

struct recent {
	GHashTable *ht_recent_pongs;	/**< Recent pongs we know about */
	GList *recent_pongs;			/**< Recent pongs we got */
	GList *last_returned_pong;		/**< Last returned from list */
	gint recent_pong_count;			/**< # of pongs in recent list */
};

#define PONG_CACHE_SIZE		(MAX_CACHE_HOPS+1)

static struct cache_line pong_cache[PONG_CACHE_SIZE];
static struct recent recent_pongs[HOST_MAX];

#define CACHE_UP_LIFESPAN	20		/**< seconds -- ultra/normal mode */
#define CACHE_LEAF_LIFESPAN	120		/**< seconds -- leaf mode */
#define MAX_PONGS			10		/**< Max pongs returned per ping */
#define OLD_PING_PERIOD		45		/**< Pinging period for "old" clients */
#define OLD_CACHE_RATIO		20		/**< % of pongs from "old" clients we cache */
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
 * Callbacks for the `ht_recent_pongs' hash table.
 */

static guint
cached_pong_hash(gconstpointer key)
{
	const struct cached_pong *cp = key;

	return host_addr_hash(cp->info.addr) ^
		((cp->info.port << 16) | cp->info.port);
}
static gint
cached_pong_eq(gconstpointer v1, gconstpointer v2)
{
	const struct cached_pong *h1 = v1, *h2 = v2;

	return host_addr_equal(h1->info.addr, h2->info.addr) &&
		h1->info.port == h2->info.port;
}

/**
 * Initialization.
 */
void
pcache_init(void)
{
	gint h;
	gchar *lang = NULL;

	memset(pong_cache, 0, sizeof pong_cache);
	memset(recent_pongs, 0, sizeof recent_pongs);

	/*
	 * We limit UDP pings to 1 every UDP_PING_FREQ seconds.
	 */

	udp_pings = aging_make(UDP_PING_FREQ,
			host_addr_hash_func, host_addr_eq_func, wfree_host_addr,
			NULL, NULL, NULL);

	/*
	 * The `local_meta' structure collects our meta data that we may send
	 * out in pongs for ourselves, when not replying to "alive" pings.
	 */

	local_meta.flags = PONG_META_HAS_VC | PONG_META_HAS_DU;
	memcpy(local_meta.vendor, "GTKG", 4);
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
		gint len = strlen(lang);

		if (len > 0) {
			gint i;

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

		g_message("locale set to language=\"%.2s\", country=\"%.2s\"",
			local_meta.language, local_meta.country);
	} else
		g_warning("unable to figure out locale preferences");
#endif

	for (h = 0; h < PONG_CACHE_SIZE; h++)
		pong_cache[h].hops = h;

	recent_pongs[HOST_ANY].ht_recent_pongs =
		g_hash_table_new(cached_pong_hash, cached_pong_eq);

	recent_pongs[HOST_ULTRA].ht_recent_pongs =
		g_hash_table_new(cached_pong_hash, cached_pong_eq);
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

	if (cp->meta)
		wfree(cp->meta, sizeof(*cp->meta));

	node_id_unref(cp->node_id);
	node_id_unref(cp->last_sent_id);
	wfree(cp, sizeof(*cp));
}


/**
 * Get a recent pong from the list, updating `last_returned_pong' as we
 * go along, so that we never return twice the same pong instance.
 *
 * Fills `addr' and `port' with the pong value and return TRUE if we
 * got a pong.  Otherwise return FALSE.
 */
gboolean
pcache_get_recent(host_type_t type, host_addr_t *addr, guint16 *port)
{
	static host_addr_t last_addr;
	static guint16 last_port = 0;
	GList *l;
	struct cached_pong *cp;
	struct recent *rec;

	g_assert((guint) type < HOST_MAX);

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
		l = g_list_first(rec->recent_pongs);
		cp = l->data;

		if (
			!host_addr_equal(cp->info.addr, last_addr) ||
			cp->info.port != last_port
		)
			goto found;

		if (g_list_next(l) == NULL)		/* Head is the only item in list */
			return FALSE;
	} else {
		/* Regular case */
		l = g_list_previous(rec->last_returned_pong);
		for (/* empty */ ; l; l = g_list_previous(l)) {
			cp = l->data;
			if (
				!host_addr_equal(cp->info.addr, last_addr) ||
				cp->info.port != last_port
			)
				goto found;
		}
	}

	/*
	 * Still none found, go back to the end of the list.
	 */

	for (l = g_list_last(rec->recent_pongs); l; l = g_list_previous(l)) {
		cp = l->data;
		if (
			!host_addr_equal(cp->info.addr, last_addr) ||
			cp->info.port != last_port
		)
			goto found;
	}

	return FALSE;

found:
	rec->last_returned_pong = l;
	*addr =last_addr = cp->info.addr;
	*port = last_port = cp->info.port;

	if (pcache_debug > 8)
		printf("returning recent %s PONG %s\n",
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

	g_assert((gint) type >= 0 && type < HOST_MAX);

	rec = &recent_pongs[type];

    if (
        !host_is_valid(cp->info.addr, cp->info.port) ||
        (NULL != g_hash_table_lookup(
            rec->ht_recent_pongs, (gconstpointer) cp)) ||
        hcache_node_is_bad(cp->info.addr)
    ) {
        return;
    }

	if (rec->recent_pong_count == RECENT_PING_SIZE) {		/* Full */
		GList *lnk = g_list_last(rec->recent_pongs);
		struct cached_pong *p = lnk->data;

		rec->recent_pongs = g_list_remove_link(rec->recent_pongs, lnk);
		g_hash_table_remove(rec->ht_recent_pongs, p);

		if (lnk == rec->last_returned_pong)
			rec->last_returned_pong = g_list_previous(rec->last_returned_pong);

		free_cached_pong(p);
		g_list_free_1(lnk);
	} else
		rec->recent_pong_count++;

	rec->recent_pongs = g_list_prepend(rec->recent_pongs, cp);
	g_hash_table_insert(rec->ht_recent_pongs, cp, GUINT_TO_POINTER(1));
	cp->refcount++;		/* We don't refcount insertion in the hash table */
}

/**
 * Determine the pong type (any, or of the ultra kind).
 */
static host_type_t
pong_type(gnutella_init_response_t *pong)
{
	guint32 kbytes;

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
	GList *l;
	struct recent *rec;

	g_assert((gint) type >= 0 && type < HOST_MAX);

	rec = &recent_pongs[type];

	for (l = rec->recent_pongs; l; l = g_list_next(l)) {
		struct cached_pong *cp = l->data;

		g_hash_table_remove(rec->ht_recent_pongs, cp);
		free_cached_pong(cp);
	}

	g_list_free(rec->recent_pongs);
	rec->recent_pongs = NULL;
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
pcache_outgoing_connection(struct gnutella_node *n)
{
	g_assert(NODE_IS_CONNECTED(n));

	if (connected_nodes() < up_connections || hcache_is_low(HOST_ANY))
		send_ping(n, my_ttl);		/* Regular ping, get fresh pongs */
	else
		send_ping(n, 1);			/* Handshaking ping */
}

/**
 * Expire the whole cache.
 */
static void
pcache_expire(void)
{
	gint i;
	gint entries = 0;

	for (i = 0; i < PONG_CACHE_SIZE; i++) {
		struct cache_line *cl = &pong_cache[i];
		GSList *sl;

		for (sl = cl->pongs; sl; sl = g_slist_next(sl)) {
			entries++;
			free_cached_pong(sl->data);
		}
		g_slist_free(cl->pongs);

		cl->pongs = NULL;
		cl->cursor = NULL;
	}

	if (pcache_debug > 4)
		printf("Pong CACHE expired (%d entr%s, %d in reserve)\n",
			entries, entries == 1 ? "y" : "ies", hcache_size(HOST_ANY));
}

/**
 * Final shutdown.
 */
void
pcache_close(void)
{
	static host_type_t types[] = { HOST_ANY, HOST_ULTRA };
	guint i;

	pcache_expire();

	for (i = 0; i < G_N_ELEMENTS(types); i++) {
		host_type_t type = types[i];

		pcache_clear_recent(type);
		g_hash_table_destroy(recent_pongs[type].ht_recent_pongs);
	}

	aging_destroy(udp_pings);
}

/**
 * Send a ping to all "new" clients to which we are connected, and one to
 * older client if and only if at least OLD_PING_PERIOD seconds have
 * elapsed since our last ping, as determined by `next_ping'.
 */
static void
ping_all_neighbours(time_t now)
{
	const GSList *sl;
	GSList *may_ping = NULL;
	GSList *to_ping = NULL;
	gint ping_cnt = 0;
	gint selected = 0;
	gint left;

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

	for (sl = node_all_nodes(); sl; sl = g_slist_next(sl)) {
		struct gnutella_node *n = sl->data;

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
			may_ping = g_slist_prepend(may_ping, n);
			ping_cnt++;
		}
	}

	for (sl = may_ping, left = ping_cnt; sl; sl = g_slist_next(sl), left--) {
		struct gnutella_node *n = sl->data;

		if (
			ping_cnt <= MIN_UP_PING ||
			(selected < MIN_UP_PING && left <= (MIN_UP_PING - selected)) ||
			random_value(99) < UP_PING_RATIO
		) {
			to_ping = g_slist_prepend(to_ping, n);
			selected++;
		}
	}

	for (sl = to_ping; sl; sl = g_slist_next(sl)) {
		struct gnutella_node *n = sl->data;

		if (!(n->attrs & NODE_A_PONG_CACHING))
			n->next_ping = now + OLD_PING_PERIOD;

		send_ping(n, my_ttl);
	}

	g_slist_free(may_ping);
	g_slist_free(to_ping);
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
		pcache_expire_time = now + cache_lifespan(current_peermode);
		ping_all_neighbours(now);
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
setup_pong_demultiplexing(struct gnutella_node *n, guint8 ttl)
{
	gint remains;
	gint h;

	g_assert(gnutella_header_get_function(&n->header) == GTA_MSG_INIT);

	memcpy(n->ping_guid, gnutella_header_get_muid(&n->header), 16);
	memset(n->pong_needed, 0, sizeof(n->pong_needed));
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
		guchar amount = (guchar) (remains / (MAX_CACHE_HOPS + 1 - h));
		n->pong_needed[h] = amount;
		remains -= amount;
		if (pcache_debug > 7)
			printf("pong_needed[%d] = %d, remains = %d\n", h, amount, remains);
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
static gboolean
iterate_on_cached_line(
	struct gnutella_node *n, struct cache_line *cl, guint8 ttl,
	GSList *start, GSList *end, gboolean strict)
{
	gint hops = cl->hops;
	GSList *sl;

	sl = start;
	for (; sl && sl != end && n->pong_missing; sl = g_slist_next(sl)) {
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

		if (node_id_eq(NODE_ID(n), cp->node_id))
			continue;
		if (node_id_eq(NODE_ID(n), cp->last_sent_id))
			continue;

		node_id_unref(cp->last_sent_id);
		cp->last_sent_id = node_id_ref(NODE_ID(n));

		/*
		 * When sending a cached pong, don't forget that its cached hop count
		 * is the one we got when we received it, i.e. hops=0 means a pong
		 * from one of our immediate neighbours.  However, we're now "routing"
		 * it, so we must increase the hop count.
		 */

		g_assert(hops < 255);		/* Because of MAX_CACHE_HOPS */

		send_pong(n, FALSE, PING_F_NONE,
			hops + 1, ttl, n->ping_guid, &cp->info, cp->meta);

		n->pong_missing--;

		if (pcache_debug > 7)
			printf("iterate: sent cached pong %s (hops=%d, TTL=%d) to %s, "
				"missing=%d %s\n",
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
	struct gnutella_node *n,
	struct cache_line *cl, guint8 ttl, gboolean strict)
{
	gint hops = cl->hops;
	GSList *old = cl->cursor;

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
	gint h;
	guint8 ttl;
	enum ping_flag flags;

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

	ttl = MIN((guint) gnutella_header_get_hops(&n->header) + 1, max_ttl);

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
	struct gnutella_node *n, struct cached_pong *cp, host_type_t ptype,
	guint8 hops, guint8 ttl)
{
	const GSList *sl;

	for (sl = node_all_nodes(); sl; sl = g_slist_next(sl)) {
		struct gnutella_node *cn = sl->data;

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
			hops + 1, ttl, cn->ping_guid, &cp->info, cp->meta);

		if (pcache_debug > 7)
			printf("pong_all: sent cached pong %s (hops=%d, TTL=%d) to %s "
				"missing=%d\n",
				host_addr_port_to_string(cp->info.addr, cp->info.port),
				hops, ttl, node_addr(cn), cn->pong_missing);
	}
}

/**
 * We received an ultra pong.
 * Send it to one randomly selected leaf, which is not already missing pongs.
 */
static void
pong_random_leaf(struct cached_pong *cp, guint8 hops, guint8 ttl)
{
	const GSList *sl;
	gint leaves;
	struct gnutella_node *leaf = NULL;

	g_assert(current_peermode == NODE_P_ULTRA);

	for (sl = node_all_nodes(), leaves = 0; sl; sl = g_slist_next(sl)) {
		struct gnutella_node *cn = sl->data;
		gint threshold;

		if (cn->pong_missing)	/* A job for pong_all_neighbours_but_one() */
			continue;

		if (!NODE_IS_LEAF(cn))
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
		threshold = (gint) (1000.0 / leaves);

		if ((gint) random_value(999) < threshold)
			leaf = cn;
	}

	/*
	 * Send the pong to the selected leaf, if any.
	 *
	 * NB: If the leaf never sent a ping before, leaf->ping_guid will
	 * be a zero GUID.  That's OK.
	 */

	if (leaf != NULL) {
		send_pong(leaf, FALSE, PING_F_NONE, hops + 1, ttl, leaf->ping_guid,
			&cp->info, cp->meta);

		if (pcache_debug > 7)
			printf("pong_random_leaf: sent pong %s (hops=%d, TTL=%d) to %s\n",
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
pong_extract_metadata(struct gnutella_node *n)
{
	gint i;
	pong_meta_t *meta = NULL;

#define ALLOCATE(f) do {					\
	if (meta == NULL) {						\
		meta = walloc(sizeof(*meta));		\
		meta->flags = 0;					\
	}										\
	meta->flags |= CAT2(PONG_META_HAS_,f);	\
} while (0)

	for (i = 0; i < n->extcount; i++) {
		extvec_t *e = &n->extvec[i];
		const guchar *payload;
		guint16 paylen;

		switch (e->ext_token) {
		case EXT_T_GGEP_DU:
			/*
			 * Daily uptime.
			 * Payload is a variable-length little-endian uptime.
			 */

			{
				guint32 uptime;
				if (GGEP_OK == ggept_du_extract(e, &uptime)) {
					ALLOCATE(DU);
					meta->daily_uptime = uptime;
				}
			}
			break;
		case EXT_T_GGEP_GUE:
			/*
			 * GUESS support.
			 * Payload is optional and holds the GUESS version number.
			 */

			ALLOCATE(GUE);
			if (ext_paylen(e) > 0) {
				payload = ext_payload(e);
				meta->guess = payload[0];
			} else {
				meta->guess = 0x1;
			}
			break;
		case EXT_T_GGEP_LOC:
			/*
			 * Preferred locale.
			 * Contains a standard Locale identifier: format is
			 * 'll_[CC[_variant]]', where 'll' is a lowercase ISO639 language
			 * code, 'CC' is a uppercase ISO3166 country/region code, and
			 * 'variant' is a variant code (each subcode is 2 chars min,
			 * case is normaly not significant but should be as indincated
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
				meta->up_slots = payload[1];
				meta->leaf_slots = payload[2];
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
		case EXT_T_GGEP_GTKG_IPV6:
			{
				host_addr_t addr;

				if (GGEP_OK == ggept_gtkg_ipv6_extract(e, &addr)) {
					ALLOCATE(IPV6);
					meta->ipv6_addr = addr;
				}
			}
			break;
		default:
			if (ggep_debug > 1 && e->ext_type == EXT_GGEP) {
				paylen = ext_paylen(e);
				g_warning("%s: unhandled GGEP \"%s\" (%d byte%s)",
					gmsg_infostr(&n->header), ext_ggep_id_str(e),
					paylen, paylen == 1 ? "" : "s");
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
	struct gnutella_node *n,
	guint8 hops, host_addr_t addr, guint16 port,
	guint32 files_count, guint32 kbytes_count,
	gboolean get_meta)
{
	struct cache_line *cl;
	struct cached_pong *cp;
	guint8 hop;

	g_assert((gint) type >= 0 && type < HOST_MAX);

	cp = walloc(sizeof *cp);

	cp->refcount = 1;
	cp->node_id = node_id_ref(NODE_ID(n));
	cp->last_sent_id = node_id_ref(NODE_ID(n));
	cp->info.addr = addr;
	cp->info.port = port;
	cp->info.files_count = files_count;
	cp->info.kbytes_count = kbytes_count;
	cp->meta = get_meta ? pong_extract_metadata(n) : NULL;

	hop = CACHE_HOP_IDX(hops);		/* Trim high values to MAX_CACHE_HOPS */
	cl = &pong_cache[hop];
	cl->pongs = g_slist_append(cl->pongs, cp);
	add_recent_pong(type, cp);

	return cp;
}

/**
 * Called when an UDP ping is received.
 */
static void
pcache_udp_ping_received(struct gnutella_node *n)
{
	g_assert(NODE_IS_UDP(n));

	/*
	 * If we got a PING whose MUID is our node's GUID, then it's a reply
	 * to our "UDP Connect Back" message.  Ignore it, we've already
	 * noticed that we got an unsolicited UDP message.
	 */

	if (guid_eq(servent_guid, gnutella_header_get_muid(&n->header))) {
		if (udp_debug > 19)
			printf("UDP got unsolicited PING matching our GUID!\n");
		return;
	}

	/*
	 * Don't answer to too frequent pings from the same IP.
	 */

	if (aging_lookup(udp_pings, &n->addr)) {
        gnet_stats_count_dropped(n, MSG_DROP_THROTTLE);
		return;
	}

	aging_insert(udp_pings,
		wcopy(&n->addr, sizeof n->addr), GUINT_TO_POINTER(1));
	send_personal_info(n, FALSE, ping_type(n));
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
pcache_ping_received(struct gnutella_node *n)
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
	 * sent earlier.  Don't event log we got a message with TTL=0, we're
	 * getting way too many of them and nobody on the GDF seems to care.
	 * BearShare is known to do this, and they admitted it publicly like
	 * it was a good idea!
	 *
	 *		--RAM, 2004-08-09
	 */

	if (
		gnutella_header_get_hops(&n->header) == 0 &&
		gnutella_header_get_ttl(&n->header) <= 2
	) {
		n->n_ping_special++;
		n->n_ping_accepted++;

		if (gnutella_header_get_ttl(&n->header) == 1)
			send_personal_info(n, TRUE, PING_F_NONE);	/* Prioritary */
		else if (gnutella_header_get_ttl(&n->header) == 2) {
			if (current_peermode != NODE_P_LEAF)
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
		if (pcache_debug || dbg)
			g_warning("node %s (%s) [%d.%d] claimed ping reduction, "
				"got ping with hops=%d", node_addr(n),
				node_vendor(n),
				n->proto_major, n->proto_minor,
				gnutella_header_get_hops(&n->header));
		n->attrs |= NODE_A_PONG_ALIEN;		/* Warn only once */
	}

	/*
	 * Accept the ping?.
	 */

	if (now < n->ping_accept) {
		n->n_ping_throttle++;		/* Drop the ping */
        gnet_stats_count_dropped(n, MSG_DROP_THROTTLE);
		return;
	} else {
		n->n_ping_accepted++;
		n->ping_accept = now + n->ping_throttle;	/* Drop all until then */
	}

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

	if (
		n->n_ping_accepted == 1 ||
		((is_firewalled || node_missing() > 0) && inet_can_answer_ping())
	) {
		send_personal_info(n, FALSE, PING_F_NONE);
		if (!NODE_IS_CONNECTED(n))	/* Can be removed if send queue is full */
			return;
	}

	if (current_peermode == NODE_P_LEAF)
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
pcache_udp_pong_received(struct gnutella_node *n)
{
	gint i;

	g_assert(NODE_IS_UDP(n));

	/*
	 * We pretty much ignore pongs we get from UDP, unless they bear
	 * the GGEP "IPP" extension, containing a packed set of IP:port.
	 */

	for (i = 0; i < n->extcount; i++) {
		extvec_t *e = &n->extvec[i];
		guint16 paylen;
		const gchar *payload;

		switch (e->ext_token) {
		case EXT_T_GGEP_IPP:
			paylen = ext_paylen(e);
			payload = ext_payload(e);

			if (paylen % 6) {
				g_warning("%s (UDP): bad length for GGEP \"%s\" (%d byte%s)",
					gmsg_infostr(&n->header), ext_ggep_id_str(e),
					paylen, paylen == 1 ? "" : "s");
			} else
				uhc_ipp_extract(n, payload, paylen);
			break;
		default:
			if (ggep_debug > 1 && e->ext_type == EXT_GGEP) {
				paylen = ext_paylen(e);
				g_warning("%s (UDP): unhandled GGEP \"%s\" (%d byte%s)",
					gmsg_infostr(&n->header), ext_ggep_id_str(e),
					paylen, paylen == 1 ? "" : "s");
			}
			break;
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
pcache_pong_received(struct gnutella_node *n)
{
	guint16 port;
	guint32 files_count;
	guint32 kbytes_count;
	guint32 swapped_count;
	struct cached_pong *cp;
	host_type_t ptype;
	host_addr_t addr;

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
	
	/* Check for an IPv6 address */
	if (gnutella_header_get_hops(&n->header) == 0) {
		pong_meta_t *meta;
		
		meta = pong_extract_metadata(n);
		if (meta && meta->flags & PONG_META_HAS_IPV6) {
			addr = meta->ipv6_addr;
		}
		WFREE_NULL(meta, sizeof *meta);
	}

	/*
	 * Sanity checks: make sure the files_count is reasonable, or try
	 * to swap it otherwise.  Then try to adjust the kbytes_count if we
	 * fixed the files_count.
	 *		--RAM, 13/07/2004
	 */

	if (files_count > PCACHE_MAX_FILES) {	/* Arbitrarily large constant */
		gboolean fixed = FALSE;

		swapped_count = swap_guint32(files_count);

		if (swapped_count > PCACHE_MAX_FILES) {
			if (pcache_debug && host_addr_equal(addr, n->addr))
				g_warning("node %s (%s) sent us a pong with "
					"large file count %u (0x%x), dropped",
					node_addr(n), node_vendor(n), files_count, files_count);
			n->rx_dropped++;
			return;
		} else {
			if (pcache_debug && host_addr_equal(addr, n->addr)) g_warning(
				"node %s (%s) sent us a pong with suspect file count %u "
				"(fixed to %u)",
				node_addr(n), node_vendor(n), files_count, swapped_count);
			files_count = swapped_count;
			fixed = TRUE;
		}
		/*
		 * Maybe the kbytes_count is correct if the files_count was?
		 */

		swapped_count = swap_guint32(kbytes_count);

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
			if (host_addr_equal(addr, n->addr)) {
				n->gnet_addr = addr;	/* Signals: we have figured it out */
				n->gnet_port = port;
			} else if (!(n->flags & NODE_F_ALIEN_IP)) {
				if (pcache_debug) g_warning(
					"node %s (%s) sent us a pong for itself with alien IP %s",
					node_addr(n), node_vendor(n), host_addr_to_string(addr));
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

		if (n->n_pong_received == 1 || host_addr_equal(addr, n->gnet_addr)) {
			n->gnet_files_count = files_count;
			n->gnet_kbytes_count = kbytes_count;
		}

		/*
		 * Spot any change in the pong's IP address.  We try to avoid messages
		 * about "connection pongs" by checking whether we have sent at least
		 * 2 pings (one handshaking ping plus one another).
		 */

		if (
			is_host_addr(n->gnet_pong_addr) &&
			!host_addr_equal(addr, n->gnet_pong_addr)
		) {
			if (pcache_debug && n->n_ping_sent > 2) g_warning(
				"node %s (%s) sent us a pong for new IP %s (used %s before)",
				node_addr(n), node_vendor(n),
				host_addr_port_to_string(addr, port),
				host_addr_to_string(n->gnet_pong_addr));
		}

		n->gnet_pong_addr = addr;

		/*
		 * If it was an acknowledge for one of our alive pings, don't cache.
		 */

		if (alive_ack_ping(n->alive_pings,
				gnutella_header_get_muid(&n->header)))
			return;
	}

	/*
	 * If it's not a connectible pong, discard it.
	 */

	if (!host_is_valid(addr, port)) {
		gnet_stats_count_dropped(n, MSG_DROP_PONG_UNUSABLE);
		return;
	}

	/*
	 * If pong points to an hostile IP address, discard it.
	 */

	if (hostiles_check(addr)) {
		gnet_stats_count_dropped(n, MSG_DROP_HOSTILE_IP);
		return;
	}

	/*
	 * If pong points to us, maybe we explicitly connected to ourselves
	 * (tests) or someone is trying to fool us.
	 */

	if (is_my_address_and_port(addr, port))
		return;

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
		gint ratio = (gint) random_value(100);
		if (ratio >= OLD_CACHE_RATIO) {
			if (pcache_debug > 7)
				printf("NOT CACHED pong %s (hops=%d, TTL=%d) from OLD %s\n",
					host_addr_port_to_string(addr, port),
					gnutella_header_get_hops(&n->header),
					gnutella_header_get_ttl(&n->header),
					node_addr(n));
			return;
		}
	}

	/*
	 * Insert pong within our cache.
	 */

	cp = record_fresh_pong(HOST_ANY, n, gnutella_header_get_hops(&n->header),
			addr, port, files_count, kbytes_count, TRUE);

	ptype = pong_type((gpointer) n->data);
	if (cp->meta != NULL && (cp->meta->flags & PONG_META_HAS_UP))
		ptype = HOST_ULTRA;

	if (ptype == HOST_ULTRA)
		add_recent_pong(HOST_ULTRA, cp);

	if (pcache_debug > 6)
		printf("CACHED %s pong %s (hops=%d, TTL=%d) from %s %s\n",
			ptype == HOST_ULTRA ? "ultra" : "normal",
			host_addr_port_to_string(addr, port),
			gnutella_header_get_hops(&n->header),
			gnutella_header_get_ttl(&n->header),
			(n->attrs & NODE_A_PONG_CACHING) ? "NEW" : "OLD", node_addr(n));

	/*
	 * Demultiplex pong: send it to all the connections but the one we
	 * received it from, provided they need more pongs of this hop count.
	 */

	if (current_peermode != NODE_P_LEAF)
		pong_all_neighbours_but_one(n, cp, ptype,
			CACHE_HOP_IDX(gnutella_header_get_hops(&n->header)),
			MAX(1, gnutella_header_get_ttl(&n->header)));

	/*
	 * If we're in ultra mode, send 33% of all the ultra pongs we get
	 * to one random leaf.
	 */

	if (
		current_peermode == NODE_P_ULTRA &&
		ptype == HOST_ULTRA && random_value(99) < 33
	)
		pong_random_leaf(cp,
			CACHE_HOP_IDX(gnutella_header_get_hops(&n->header)),
			MAX(1, gnutella_header_get_ttl(&n->header)));
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
pcache_pong_fake(struct gnutella_node *n, const host_addr_t addr, guint16 port)
{
	g_assert(n->attrs & NODE_A_ULTRA);

	if (!host_is_valid(addr, port))
		return;

	host_add(addr, port, FALSE);
	(void) record_fresh_pong(HOST_ULTRA, n, 1, addr, port, 0, 0, FALSE);
}

/* vi: set ts=4 sw=4 cindent: */
