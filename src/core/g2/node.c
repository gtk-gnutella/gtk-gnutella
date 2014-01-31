/*
 * Copyright (c) 2014 Raphael Manfredi
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
 * G2 message handling.
 *
 * @author Raphael Manfredi
 * @date 2014
 */

#include "common.h"

#include "node.h"

#include "build.h"
#include "frame.h"
#include "msg.h"
#include "rpc.h"
#include "tfmt.h"
#include "tree.h"

#define SEARCH_SOURCES
#include "core/search.h"

#include "core/alive.h"
#include "core/gnet_stats.h"
#include "core/hcache.h"
#include "core/hostiles.h"		/* For hostiles_is_bad() */
#include "core/hosts.h"
#include "core/mq_tcp.h"
#include "core/mq_udp.h"
#include "core/nodes.h"
#include "core/routing.h"
#include "core/settings.h"		/* For is_my_address_and_port() */

#include "if/gnet_property_priv.h"

#include "if/core/guid.h"

#include "lib/aging.h"
#include "lib/ascii.h"
#include "lib/halloc.h"
#include "lib/host_addr.h"
#include "lib/misc.h"			/* For dump_hex() */
#include "lib/pmsg.h"
#include "lib/str.h"
#include "lib/stringify.h"		/* For plural() */
#include "lib/tokenizer.h"
#include "lib/utf8.h"
#include "lib/walloc.h"

#include "lib/override.h"		/* Must be the last header included */

#define G2_UDP_PING_FREQ	60		/**< answer to 1 ping per minute per IP */

enum g2_q2_child {
	G2_Q2_DN = 1,
	G2_Q2_I,
	G2_Q2_MD,
	G2_Q2_SZR,
	G2_Q2_UDP,
	G2_Q2_URN,
};

enum g2_lni_child {
	G2_LNI_GU = 1,
	G2_LNI_LS,
	G2_LNI_NA,
	G2_LNI_UP,
	G2_LNI_V,
};

static const tokenizer_t g2_q2_children[] = {
	/* Sorted array */
	{ "DN",		G2_Q2_DN },
	{ "I",		G2_Q2_I },
	{ "MD",		G2_Q2_MD },
	{ "SZR",	G2_Q2_SZR },
	{ "UDP",	G2_Q2_UDP },
	{ "URN",	G2_Q2_URN },
};

static const tokenizer_t g2_lni_children[] = {
	/* Sorted array */
	{ "GU",		G2_LNI_GU },
	{ "LS",		G2_LNI_LS },
	{ "NA",		G2_LNI_NA },
	{ "UP",		G2_LNI_UP },
	{ "V",		G2_LNI_V },
};

/**
 * The /Q2/I flags we parse and handle.
 */
#define G2_Q2_F_PFS		(1U << 0)		/**< Wants partial files */
#define G2_Q2_F_URL		(1U << 1)		/**< Wants URL */
#define G2_Q2_F_A		(1U << 2)		/**< Wants alt-locs */
#define G2_Q2_F_DN		(1U << 3)		/**< Wants distinguished name */

static const tokenizer_t g2_q2_i[] = {
	/* Sorted array */
	{ "A",		G2_Q2_F_A },
	{ "DN",		G2_Q2_F_DN },
	{ "PFS",	G2_Q2_F_PFS },
	{ "URL",	G2_Q2_F_URL },
};

/**
 * String prefix for /Q2/URN that can prefix a SHA1.
 */
static const char *g2_q2_urn[] = {
	"sha1",
	"bp",
	"bitprint",
};

/**
 * XML tags that we lexically recognize to intuit media types.
 */
static const tokenizer_t g2_q2_md[] = {
	/* Sorted array */
	{ "application",	SEARCH_WIN_TYPE | SEARCH_UNIX_TYPE },
	{ "archive",		SEARCH_WIN_TYPE | SEARCH_UNIX_TYPE },
	{ "audio",			SEARCH_AUDIO_TYPE },
	{ "book",			SEARCH_DOC_TYPE },
	{ "document",		SEARCH_DOC_TYPE },
	{ "image",			SEARCH_IMG_TYPE },
	{ "video",			SEARCH_VIDEO_TYPE },
};

static aging_table_t *g2_udp_pings;

/**
 * Send a message to target node.
 */
void
g2_node_send(const gnutella_node_t *n, pmsg_t *mb)
{
	node_check(n);
	g_assert(NODE_TALKS_G2(n));

	if (NODE_IS_UDP(n))
		mq_udp_node_putq(n->outq, mb, n);
	else
		mq_tcp_putq(n->outq, mb, NULL);
}

/**
 * Send a pong to target node.
 */
static void
g2_node_send_pong(gnutella_node_t *n)
{
	pmsg_t *mb = g2_build_pong();

	g2_node_send(n, mb);
}

/**
 * Send a /QHT RESET to node.
 *
 * @param n			the TCP node to which we need to send the /QHT
 * @param slots		amount of slots in the table (power of 2)
 * @param inf_val	infinity value (1)
 */
void
g2_node_send_qht_reset(gnutella_node_t *n, int slots, int inf_val)
{
	pmsg_t *mb = g2_build_qht_reset(slots, inf_val);

	node_check(n);
	g_assert(!NODE_IS_UDP(n));

	g2_node_send(n, mb);
}

/**
 * Send a /QHT RESET to node.
 *
 * @param n			the TCP node to which we need to send the /QHT
 * @param seqno			the patch sequence number
 * @param seqsize		the total length of the sequence
 * @param compressed	whether patch is compressed
 * @param bits			amount of bits for each entry (1)
 * @param buf			start of patch data
 * @param len			length in byte of patch data
 */
void
g2_node_send_qht_patch(gnutella_node_t *n,
	int seqno, int seqsize, bool compressed, int bits,
	char *buf, int len)
{
	pmsg_t *mb = g2_build_qht_patch(seqno, seqsize, compressed, bits, buf, len);

	node_check(n);
	g_assert(!NODE_IS_UDP(n));

	g2_node_send(n, mb);
}

/**
 * Send a /LNI to node.
 */
void
g2_node_send_lni(gnutella_node_t *n)
{
	pmsg_t *mb = g2_build_lni();

	node_check(n);
	g_assert(!NODE_IS_UDP(n));

	g2_node_send(n, mb);
}

/**
 * Drop message received from given node.
 *
 * @param routine		routine where we're coming from (the one dropping)
 * @param n				source node of message
 * @param t				the message tree
 * @param reason		optional reason
 */
static void G_GNUC_PRINTF(4, 5)
g2_node_drop(const char *routine, gnutella_node_t *n, const g2_tree_t *t,
	const char *fmt, ...)
{
	if (GNET_PROPERTY(g2_debug) || GNET_PROPERTY(log_dropped_g2)) {
		va_list args;
		char buf[256];

		va_start(args, fmt);

		if (fmt != NULL)
			str_vbprintf(buf, sizeof buf, fmt, args);
		else
			buf[0] = '\0';

		g_debug("%s(): dropping %s packet from %s%s%s",
			routine, g2_tree_name(t), node_infostr(n),
			NULL == fmt ? "" : ": ", buf);

		va_end(args);
	}

	gnet_stats_count_dropped(n, MSG_DROP_G2_UNEXPECTED);

	if (GNET_PROPERTY(log_dropped_g2)) {
		g2_tfmt_tree_dump(t, stderr, G2FMT_O_PAYLEN);
	}
}

/**
 * Handle reception of a /PI
 */
static void
g2_node_handle_ping(gnutella_node_t *n, const g2_tree_t *t)
{
	g2_tree_t *c;

	/*
	 * Throttle pings received from UDP.
	 */

	if (NODE_IS_UDP(n)) {
		if (aging_lookup(g2_udp_pings, &n->addr)) {
			gnet_stats_count_dropped(n, MSG_DROP_THROTTLE);
			return;
		}
		aging_insert(g2_udp_pings, WCOPY(&n->addr), uint_to_pointer(1));

		/* FALL THROUGH */
	}

	c = g2_tree_first_child(t);

	/*
	 * If there is no payload, it's a keep-alive ping, send back a pong.
	 */

	if (NULL == c) {
		g2_node_send_pong(n);
		return;
	}

	/*
	 * There are children.
	 *
	 * If there is a /PI/UDP present, drop the message: we're not a hub,
	 * we don't have to relay this message to its UDP target (we're only
	 * connected to hubs, and the hub which got it should only forward that
	 * message it its neighbouring hubs, not to leaves).
	 *
	 * If there is a /PI/RELAY, the ping was relayed by a hub, but it made
	 * a mistake because we are a leaf node.
	 */

	g2_node_drop(G_STRFUNC, n, t, "has children and we are a leaf");
}

/**
 * Handle reception of a /PO
 */
static void
g2_node_handle_pong(gnutella_node_t *n, const g2_tree_t *t)
{
	/*
	 * Pongs received from UDP must be RPC replies to pings.
	 */

	if (NODE_IS_UDP(n)) {
		if (!g2_rpc_answer(n, t))
			g2_node_drop(G_STRFUNC, n, t, "coming from UDP");
		return;
	}

	/*
	 * Must be a pong received because we sent an alive ping earlier.
	 */

	alive_ack_ping(n->alive_pings, NULL);	/* No MUID on G2 */
}

/**
 * Handle reception of an RPC answer (/QKA, /QA)
 */
static void
g2_node_handle_rpc_answer(gnutella_node_t *n, const g2_tree_t *t)
{
	/*
	 * /QKA received from UDP must be RPC replies to /QKR, otherwise
	 * it can be sent when a /Q2 bearing the wrong query key is received
	 * by a host.
	 *
	 * A /QA is sent back by a hub upon reception of the /Q2 message if
	 * the query key was correct.
	 */

	if (NODE_IS_UDP(n)) {
		if (!g2_rpc_answer(n, t))
			g2_node_drop(G_STRFUNC, n, t, "coming from UDP");
		return;
	}

	/*
	 * We do not expect these from TCP, since they are UDP RPC replies.
	 */

	g2_node_drop(G_STRFUNC, n, t, "coming from TCP");
}

/**
 * Parse the payload of given node to extract a node address + port.
 *
 * @param t		the tree node whose payload we wish to parse
 * @param addr	where to write the address part
 * @param port	where to write the port part
 *
 * @return TRUE if OK, FALSE if we could not extract anything.
 */
static bool NON_NULL_PARAM((2, 3))
g2_node_parse_address(const g2_tree_t *t, host_addr_t *addr, uint16 *port)
{
	const char *payload;
	size_t paylen;

	payload = g2_tree_node_payload(t, &paylen);

	/*
	 * Only handle if we have an IP:port entry.
	 * We only handle IPv4 because G2 does not support IPv6.
	 */

	if (6 == paylen) {		/* IPv4 + port */
		*addr = host_addr_peek_ipv4(payload);
		*port = peek_le16(&payload[4]);
		return TRUE;
	}

	return FALSE;		/* Unrecognized payload length */
}

/**
 * Handle reception of a /LNI
 */
static void
g2_node_handle_lni(gnutella_node_t *n, const g2_tree_t *t)
{
	g2_tree_t *c;

	/*
	 * Handle the children of /LNI.
	 */

	G2_TREE_CHILD_FOREACH(t, c) {
		enum g2_lni_child ct = TOKENIZE(g2_tree_name(c), g2_lni_children);
		const char *payload;
		size_t paylen;

		switch (ct) {
		case G2_LNI_GU:			/* the node's GUID */
			payload = g2_tree_node_payload(c, &paylen);
			if (GUID_RAW_SIZE == paylen)
				node_set_guid(n, (guid_t *) payload, TRUE);
			break;

		case G2_LNI_NA:			/* the node's address, with listening port */
			{
				host_addr_t addr;
				uint16 port;

				if (g2_node_parse_address(c, &addr, &port)) {
					if (host_address_is_usable(addr))
						n->gnet_addr = addr;
					n->gnet_port = port;
				}
			}
			break;

		case G2_LNI_LS:			/* library statistics */
			payload = g2_tree_node_payload(c, &paylen);
			if (paylen >= 8) {
				uint32 files = peek_le32(payload);
				uint32 kbytes = peek_le32(&payload[4]);

				n->gnet_files_count = files;
				n->gnet_kbytes_count = kbytes;
				n->flags |= NODE_F_SHARED_INFO;
			}
			break;

		case G2_LNI_V:			/* vendor code */
			payload = g2_tree_node_payload(c, &paylen);
			if (paylen >= 4)
				n->vcode.u32 = peek_be32(payload);
			break;

		case G2_LNI_UP:			/* uptime */
			payload = g2_tree_node_payload(c, &paylen);
			if (paylen <= 4)
				n->up_date = tm_time() - vlint_decode(payload, paylen);
			break;
		}
	}
}

/**
 * Tree message iterator to handle "NH" nodes and extract their IP:port.
 *
 */
static void
g2_node_extract_nh(void *data, void *udata)
{
	const g2_tree_t *t = data;

	(void) udata;

	if (0 == strcmp("NH", g2_tree_name(t))) {
		host_addr_t addr;
		uint16 port;

		if (
			g2_node_parse_address(t, &addr, &port) &&
			host_is_valid(addr, port)
		) {
			hcache_add_caught(HOST_G2HUB, addr, port, "/KHL/NH");
		}
	}
}

/**
 * Handle reception of a /KHL
 */
static void
g2_node_handle_khl(const g2_tree_t *t)
{
	/*
	 * Extract the neighbouring node info and insert them into our cache.
	 */

	g2_tree_child_foreach(t, g2_node_extract_nh, NULL);
}

/**
 * Extract min/max sizes from the payload of a /Q2/SZR tree node.
 *
 * @return TRUE if we successfully extracted the information.
 */
static bool NON_NULL_PARAM((2, 3))
g2_node_extract_size_request(const g2_tree_t *t, uint64 *min, uint64 *max)
{
	const char *p;
	size_t paylen;

	/*
	 * The payload can be 2 32-bit or 2 64-bit values.
	 */

	p = g2_tree_node_payload(t, &paylen);

	if (8 == paylen) {
		*min = (uint64) peek_le32(p);
		*max = (uint64) peek_le32(&p[4]);
		return TRUE;
	} else if (16 == paylen) {
		*min = peek_le64(p);
		*max = peek_le64(&p[8]);
		return TRUE;
	}

	return FALSE;
}

/**
 * Extract interest flags from the payload of a /Q2/I tree node.
 *
 * @return the consolidated flags G2_Q2_F_* requested by the payload.
 */
static uint32
g2_node_extract_interest(const g2_tree_t *t)
{
	const char *p, *q, *end;
	size_t paylen;
	uint32 flags = 0;

	p = q = g2_tree_node_payload(t, &paylen);

	if (NULL == p)
		return 0;

	end = p + paylen;

	while (q != end) {
		if ('\0' == *q++) {
			flags |= TOKENIZE(p, g2_q2_i);
			p = q;
		}
	}

	if (p != q) {
		char *r = h_strndup(p, q - p);		/* String not NUL-terminated */
		flags |= TOKENIZE(r, g2_q2_i);
		hfree(r);
	}

	return flags;
}

/**
 * Extract the URN from a /Q2/URN and populate the search request info
 * if it is a SHA1 (or bitprint, which contains a SHA1).
 */
static void
g2_node_extract_urn(const g2_tree_t *t, search_request_info_t *sri)
{
	const char *p;
	size_t paylen;
	uint i;

	/*
	 * If we have more SHA1s already than we can hold, stop.
	 */

	if (sri->exv_sha1cnt == G_N_ELEMENTS(sri->exv_sha1))
		return;

	p = g2_tree_node_payload(t, &paylen);

	if (NULL == p)
		return;

	/*
	 * We can only search by SHA1, hence we're only interested by URNs
	 * that contain a SHA1.
	 */

	if (paylen < SHA1_RAW_SIZE)
		return;		/* Cannot contain a SHA1 */

	/*
	 * Since we know there are at least SHA1_RAW_SIZE bytes in the payload,
	 * we can use clamp_memcmp() to see whether we have a known prefix.
	 */

	for (i = 0; i < G_N_ELEMENTS(g2_q2_urn); i++) {
		const char *prefix = g2_q2_urn[i];
		size_t len = strlen(prefix) + 1;	/* Wants trailing NUL as well */

		if (0 == clamp_memcmp(prefix, len, p, paylen)) {
			p += len;
			paylen -= len;

			g_assert(size_is_positive(paylen));

			if (paylen >= SHA1_RAW_SIZE) {
				uint idx = sri->exv_sha1cnt++;

				g_assert(idx < G_N_ELEMENTS(sri->exv_sha1));

				memcpy(&sri->exv_sha1[idx].sha1, p, SHA1_RAW_SIZE);
			}
			break;
		}
	}
}

/**
 * Extract the UDP IP:port from a /Q2/UDP and populate the search request info
 * if we have a valid address.
 */
static void
g2_node_extract_udp(const g2_tree_t *t, search_request_info_t *sri,
	const gnutella_node_t *n)
{
	const char *p;
	size_t paylen;

	p = g2_tree_node_payload(t, &paylen);

	/*
	 * Only handle if we have an IP:port entry.
	 * We only handle IPv4 because G2 does not support IPv6.
	 *
	 * We don't care about the presence of the query key because as G2 leaf,
	 * we only process /Q2 coming from our TCP-connected hubs, and they
	 * are in charge of validating it.  Now hubs may forward us /Q2 coming
	 * from neighbouring hubs and those won't have a query key, hence we
	 * need to handle payloads with no trailing 32-bit QK.
	 */

	if (6 == paylen || 10 == paylen) {	/* IPv4 + port (+ QK usually) */
		host_addr_t addr = host_addr_peek_ipv4(p);
		uint16 port = peek_le16(&p[4]);

		if (host_is_valid(addr, port)) {
			sri->addr = addr;
			sri->port = port;

			/*
			 * If the address is that of the node sending us the query,
			 * and it is not a UDP node, then we can deliver the hit
			 * back via the TCP connection we have, so no need to use OOB.
			 */

			if (n->port == port && host_addr_equal(addr, n->gnet_addr))
				sri->oob = NODE_IS_UDP(n);
			else
				sri->oob = TRUE;
		}
	}
}

/**
 * Intuit the media type they are searching based on the first XML tag
 * we find in the meta data string, using simplistic lexical parsing which
 * will encompass 99% of the cases.
 */
static uint32
g2_node_intuit_media_type(const char *md)
{
	const char *p = md;
	const char *start;
	int c;
	uint32 flags;

	while ('<' != (c = *p++) && c != 0)
		/* empty */;

	if (0 == c)
		return 0;		/* Did not find any tag opening */

	start = p = skip_ascii_spaces(p);

	while (0 != (c = *p)) {
		if (is_ascii_space(c) || '/' == c || '>' == c) {
			char *name;

			/* Found end of word, we got the tag name */

			name = h_strndup(start, p - start);
			flags = TOKENIZE(name, g2_q2_md);
			if (0 == flags) {
				g_warning("%s(): unknown tag \"%s\", XML string was \"%s\"",
					G_STRFUNC, name, md);
			}
			hfree(name);
			return flags;
		}
		p++;
	}

	return 0;
}

/**
 * Handle reception of a /Q2
 */
static void
g2_node_handle_q2(gnutella_node_t *n, const g2_tree_t *t)
{
	const guid_t *muid;
	size_t paylen;
	const g2_tree_t *c;
	char *dn = NULL;
	char *md = NULL;
	uint32 iflags = 0;
	search_request_info_t sri;

	node_inc_rx_query(n);

	/*
	 * As a G2 leaf, we cannot handle queries coming from UDP because we
	 * are not supposed to get any!
	 */

	if (NODE_IS_UDP(n)) {
		g2_node_drop(G_STRFUNC, n, t, "coming from UDP");
		return;
	}

	/*
	 * The MUID of the query is the payload of the root node.
	 */

	muid = g2_tree_node_payload(t, &paylen);

	if (paylen != GUID_RAW_SIZE) {
		g2_node_drop(G_STRFUNC, n, t, "missing MUID");
		return;
	}

	/*
	 * Make sure we have never seen this query already.
	 *
	 * To be able to leverage on Gnutella's routing table to detect duplicates
	 * over a certain lifespan, we are going to fake a minimal Gnutella header
	 * with a message type of GTA_MSG_G2_SEARCH, which is never actually used
	 * on the network.
	 *
	 * The TTL and hops are set to 1 and 0 initially, so that the message seems
	 * to come from a neighbouring host and cannot be forwarded.
	 *
	 * When that is done, we will be able to call route_message() and have
	 * all the necessary bookkeeping done for us.
	 */

	{
		struct route_dest dest;

		gnutella_header_set_muid(&n->header, muid);
		gnutella_header_set_function(&n->header, GTA_MSG_G2_SEARCH);
		gnutella_header_set_ttl(&n->header, 1);
		gnutella_header_set_hops(&n->header, 0);

		if (!route_message(&n, &dest))
			return;			/* Already accounted as duplicated, and logged */
	}

	/*
	 * Setup request information so that we can call search_request()
	 * to process our G2 query.
	 */

	ZERO(&sri);

	/*
	 * Handle the children of /Q2.
	 */

	G2_TREE_CHILD_FOREACH(t, c) {
		enum g2_q2_child ct = TOKENIZE(g2_tree_name(c), g2_q2_children);
		const char *payload;

		switch (ct) {
		case G2_Q2_DN:
			payload = g2_tree_node_payload(c, &paylen);
			if (payload != NULL && NULL == dn) {
				uint off = 0;
				/* Not NUL-terminated, need to h_strndup() it */
				dn = h_strndup(payload, paylen);
				if (!query_utf8_decode(dn, &off)) {
					gnet_stats_count_dropped(n, MSG_DROP_MALFORMED_UTF_8);
					goto done;		/* Drop the query */
				}
				sri.extended_query = dn + off;
				sri.search_len = paylen - off;		/* In bytes */
			}
			break;

		case G2_Q2_I:
			if (0 == iflags)
				iflags = g2_node_extract_interest(c);
			break;

		case G2_Q2_MD:
			payload = g2_tree_node_payload(c, &paylen);
			if (payload != NULL && NULL == md) {
				/* Not NUL-terminated, need to h_strndup() it */
				md = h_strndup(payload, paylen);
			}
			break;

		case G2_Q2_SZR:			/* Size limits */
			if (g2_node_extract_size_request(c, &sri.minsize, &sri.maxsize))
				sri.size_restrictions = TRUE;
			break;

		case G2_Q2_UDP:
			if (!sri.oob)
				g2_node_extract_udp(c, &sri, n);
			break;

		case G2_Q2_URN:
			g2_node_extract_urn(c, &sri);
			break;
		}
	}

	/*
	 * If there are meta-data, try to intuit which media types there are
	 * looking for.
	 *
	 * The payload is XML looking like "<audio/>" or "<video/>" but there
	 * can be attributes and we don't want to do a full XML parsing there.
	 * Hence we'll base our analysis on simple lexical parsing, which is
	 * why we call a routine to "intuit", not to "extract".
	 *
	 * Also, this is poorer than Gnutella's GGEP "M" because apparently there
	 * can be only one single type, since the XML payload must obey some
	 * kind of schema and there is an audio schema, a video schema, etc...
	 * XML was just a wrong design choice there.
	 */

	if (md != NULL)
		sri.media_types = g2_node_intuit_media_type(md);

	/*
	 * Validate the return address if OOB hit delivery is configured.
	 */

	if (sri.oob) {
		if (hostiles_is_bad(sri.addr)) {
			gnet_stats_count_dropped(n, MSG_DROP_HOSTILE_IP);
			goto done;
		}

		if (is_my_address_and_port(sri.addr, sri.port)) {
			gnet_stats_count_dropped(n, MSG_DROP_OWN_QUERY);
			goto done;
		}
	}

	/*
	 * Update statistics, as done in search_request_preprocess() for Gnutella.
	 */

	if (sri.exv_sha1cnt) {
		gnet_stats_inc_general(GNR_QUERY_G2_SHA1);

		if (NULL == dn) {
			int i;
			for (i = 0; i < sri.exv_sha1cnt; i++) {
				search_request_listener_emit(QUERY_SHA1,
					sha1_base32(&sri.exv_sha1[i].sha1), n->addr, n->port);
			}
		}
	}

	if (dn != NULL && !is_ascii_string(dn))
		gnet_stats_inc_general(GNR_QUERY_G2_UTF8);

	if (dn != NULL)
		search_request_listener_emit(QUERY_STRING, dn, n->addr, n->port);

	if (!search_is_valid(n, 0, &sri))
		goto done;

	/*
	 * Perform the query.
	 */

	sri.g2_query     = TRUE;
	sri.partials     = booleanize(iflags & G2_Q2_F_PFS);
	sri.g2_wants_url = booleanize(iflags & G2_Q2_F_URL);
	sri.g2_wants_alt = booleanize(iflags & G2_Q2_F_A);
	sri.g2_wants_dn  = booleanize(iflags & G2_Q2_F_DN);

	search_request(n, &sri, NULL);

done:

	HFREE_NULL(dn);
	HFREE_NULL(md);
}

/**
 * Handle message coming from G2 node.
 */
void
g2_node_handle(gnutella_node_t *n)
{
	g2_tree_t *t;
	size_t plen;
	enum g2_msg type;

	node_check(n);
	g_assert(NODE_TALKS_G2(n));

	t = g2_frame_deserialize(n->data, n->size, &plen, FALSE);
	if (NULL == t) {
		g_warning("%s(): cannot deserialize %s packet from %s",
			G_STRFUNC, g2_msg_raw_name(n->data, n->size), node_infostr(n));
		if (GNET_PROPERTY(log_bad_g2))
			dump_hex(stderr, "G2 Packet", n->data, n->size);
		return;
	} else if (plen != n->size) {
		g_warning("%s(): consumed %zu bytes but %s packet from %s had %u",
			G_STRFUNC, plen, g2_msg_raw_name(n->data, n->size),
			node_infostr(n), n->size);
		if (GNET_PROPERTY(log_bad_g2))
			dump_hex(stderr, "G2 Packet", n->data, n->size);
		return;
	} else if (GNET_PROPERTY(g2_debug) > 19) {
		g_debug("%s(): received packet from %s", G_STRFUNC, node_infostr(n));
		g2_tfmt_tree_dump(t, stderr, G2FMT_O_PAYLEN);
	}

	type = g2_msg_name_type(g2_tree_name(t));

	switch (type) {
	case G2_MSG_PI:
		g2_node_handle_ping(n, t);
		break;
	case G2_MSG_PO:
		g2_node_handle_pong(n, t);
		break;
	case G2_MSG_LNI:
		g2_node_handle_lni(n, t);
		break;
	case G2_MSG_KHL:
		g2_node_handle_khl(t);
		break;
	case G2_MSG_Q2:
		g2_node_handle_q2(n, t);
		break;
	case G2_MSG_QA:
	case G2_MSG_QKA:
		g2_node_handle_rpc_answer(n, t);
		break;
	default:
		g2_node_drop(G_STRFUNC, n, t, "default");
		break;
	}

	g2_tree_free_null(&t);
}

/**
 * Initialization.
 */
void G_GNUC_COLD
g2_node_init(void)
{
	/*
	 * Limit asnwering to UDP pings to 1 every G2_UDP_PING_FREQ seconds
	 */

	g2_udp_pings = aging_make(G2_UDP_PING_FREQ,
		host_addr_hash_func, host_addr_eq_func, wfree_host_addr);
}

/**
 * Shutdown.
 */
void G_GNUC_COLD
g2_node_close(void)
{
	aging_destroy(&g2_udp_pings);
}

/* vi: set ts=4 sw=4 cindent: */
