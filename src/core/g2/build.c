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
 *      51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *----------------------------------------------------------------------
 */

/**
 * @ingroup core
 * @file
 *
 * G2 message factory.
 *
 * @author Raphael Manfredi
 * @date 2014
 */

#include "common.h"
#include "gtk-gnutella.h"		/* For GTA_VENDOR_CODE */

#include "build.h"

#include "frame.h"
#include "msg.h"
#include "node.h"
#include "tfmt.h"
#include "tree.h"

#include "core/dmesh.h"
#include "core/gnet_stats.h"
#include "core/ggep_type.h"		/* For ggept_gtkgv_build() and GTKGV_MAX_LEN */
#include "core/nodes.h"
#include "core/guid.h"			/* For guid_query_muid_is_gtkg() */
#include "core/qhit.h"
#include "core/settings.h"		/* For listen_addr_primary() */
#include "core/share.h"			/* For shared_files_scanned() */
#include "core/sockets.h"		/* For socket_listen_port() */
#include "core/tls_common.h"	/* For tls_enabled() */

#include "if/core/search.h"		/* For SEARCH_* meta type flags */

#include "lib/endian.h"
#include "lib/halloc.h"
#include "lib/hset.h"
#include "lib/mempcpy.h"
#include "lib/misc.h"			/* For CONST_STRLEN() */
#include "lib/nid.h"
#include "lib/once.h"
#include "lib/pmsg.h"
#include "lib/pow2.h"
#include "lib/pslist.h"
#include "lib/sha1.h"
#include "lib/stacktrace.h"
#include "lib/stringify.h"
#include "lib/walloc.h"

#include "lib/override.h"		/* Must be the last header included */

#define G2_BUILD_QH2_THRESH		8192	/**< Flush /QH2 larger than this */
#define G2_BUILD_QH2_MAX_ALT	16		/**< Max amount of alt-locs we send */

enum g2_qht_type {
	G2_QHT_RESET = 0,
	G2_QHT_PATCH = 1,
};

const char G2_URN_SHA1[]     = "sha1";
const char G2_URN_BITPRINT[] = "bp";

static pmsg_t *build_alive_pi;		/* Single alive ping */
static once_flag_t build_alive_pi_done;

static pmsg_t *build_po;			/* Single pong */
static once_flag_t build_po_done;

enum g2_qh2_pmi_magic { G2_QH2_PMI_MAGIC = 0x79ec9986 };

/**
 * Information about the /QH2 messages we sent to the semi-reliable UDP
 * layer, which allows up to monitor their fate.
 */
struct g2_qh2_pmsg_info {
	enum g2_qh2_pmi_magic magic;
	struct nid *hub_id;				/**< ID of the hub which sent us the /Q2 */
};

static inline void
g2_qh2_pmsg_info_check(const struct g2_qh2_pmsg_info * const pmi)
{
	g_assert(pmi != NULL);
	g_assert(G2_QH2_PMI_MAGIC == pmi->magic);
}

/**
 * Create new message holding serialized tree.
 *
 * @param t			the tree to serialize
 * @param prio		priority of the message
 * @param freecb	if non-NULL, the free routine to attach to message
 * @param arg		additional argument for the free routine
 *
 * @return a message containing the serialized tree.
 */
static pmsg_t *
g2_build_pmsg_prio(const g2_tree_t *t, int prio, pmsg_free_t freecb, void *arg)
{
	size_t len;
	pmsg_t *mb;

	len = g2_frame_serialize(t, NULL, 0);
	if (NULL == freecb)
		mb = pmsg_new(prio, NULL, len);
	else
		mb = pmsg_new_extend(prio, NULL, len, freecb, arg);
	g2_frame_serialize(t, pmsg_phys_base(mb), len);
	pmsg_seek(mb, len);

	g_assert(UNSIGNED(pmsg_size(mb)) == len);

	return mb;
}

/**
 * Create new control message holding serialized tree.
 *
 * @param t		the tree to serialize
 *
 * @return a message containing the serialized tree.
 */
static inline pmsg_t *
g2_build_ctrl_pmsg(const g2_tree_t *t)
{
	return g2_build_pmsg_prio(t, PMSG_P_CONTROL, NULL, NULL);
}

/**
 * Create new message holding serialized tree.
 *
 * @param t		the tree to serialize
 *
 * @return a message containing the serialized tree.
 */
static inline pmsg_t *
g2_build_pmsg(const g2_tree_t *t)
{
	return g2_build_pmsg_prio(t, PMSG_P_DATA, NULL, NULL);
}

/**
 * Create new message holding serialized tree, with associated free routine.
 *
 * @param t			the tree to serialize
 * @param freecb	the freeing callback to invoke
 * @param arg		additional argument for the freeing callback
 *
 * @return a message containing the serialized tree.
 */
static inline pmsg_t *
g2_build_pmsg_extended(const g2_tree_t *t, pmsg_free_t freecb, void *arg)
{
	return g2_build_pmsg_prio(t, PMSG_P_DATA, freecb, arg);
}

/**
 * Create a pong message, once.
 */
static void
g2_build_pong_once(void)
{
	g2_tree_t *t;

	t = g2_tree_alloc_empty(G2_NAME(PO));
	build_po = g2_build_pmsg(t);
	g2_tree_free_null(&t);
}

/**
 * Build a pong message.
 *
 * @return a /PO message.
 */
pmsg_t *
g2_build_pong(void)
{
	ONCE_FLAG_RUN(build_po_done, g2_build_pong_once);

	return pmsg_clone(build_po);
}

/**
 * Create an alive ping message, once.
 */
static void
g2_build_alive_ping_once(void)
{
	g2_tree_t *t;

	t = g2_tree_alloc_empty(G2_NAME(PI));
	build_alive_pi = g2_build_ctrl_pmsg(t);		/* Prioritary */
	g2_tree_free_null(&t);
}

/**
 * Build an alive ping message.
 *
 * @return a /PI message.
 */
pmsg_t *
g2_build_alive_ping(void)
{
	ONCE_FLAG_RUN(build_alive_pi_done, g2_build_alive_ping_once);

	return pmsg_clone(build_alive_pi);
}

/**
 * Build a QHT RESET message.
 *
 * @param slots		amount of slots in the table (power of 2)
 * @param inf_val	infinity value (1)
 *
 * @return a /QHT message with a RESET payload.
 */
pmsg_t *
g2_build_qht_reset(int slots, int inf_val)
{
	g2_tree_t *t;
	char body[6];
	void *p = &body[0];
	pmsg_t *mb;

	g_assert(is_pow2(slots));
	g_assert(1 == inf_val);		/* Only 1-bit patches in G2 */

	p = poke_u8(p, G2_QHT_RESET);
	p = poke_le32(p, slots);
	p = poke_u8(p, inf_val);

	t = g2_tree_alloc(G2_NAME(QHT), ARYLEN(body));
	mb = g2_build_pmsg(t);
	g2_tree_free_null(&t);

	return mb;
}

/**
 * Build a QHT PATCH message.
 *
 * @param seqno			the patch sequence number
 * @param seqsize		the total length of the sequence
 * @param compressed	whether patch is compressed
 * @param bits			amount of bits for each entry (1)
 * @param buf			start of patch data
 * @param len			length in byte of patch data
 *
 * @return a /QHT message with a PATCH payload.
 */
pmsg_t *
g2_build_qht_patch(int seqno, int seqsize, bool compressed, int bits,
	char *buf, int len)
{
	g2_tree_t *t;
	char body[5];				/* The start of the payload */
	void *payload, *p;
	pmsg_t *mb;

	g_assert(1 == bits);		/* Only 1-bit patches in G2 */

	p = payload = halloc(len + sizeof body);

	p = poke_u8(p, G2_QHT_PATCH);
	p = poke_u8(p, seqno);
	p = poke_u8(p, seqsize);
	p = poke_u8(p, compressed ? 0x1 : 0x0);
	p = poke_u8(p, bits);

	memcpy(p, buf, len);

	t = g2_tree_alloc(G2_NAME(QHT), payload, len + sizeof body);
	mb = g2_build_pmsg(t);
	g2_tree_free_null(&t);
	hfree(payload);

	return mb;
}

/**
 * Add the local node GUID as a "GU" child to the root.
 */
static void
g2_build_add_guid(g2_tree_t *t)
{
	g2_tree_t *c;

	c = g2_tree_alloc_copy("GU", GNET_PROPERTY(servent_guid), GUID_RAW_SIZE);
	g2_tree_add_child(t, c);
}

/**
 * Add the vendor code as a "V" child to the root.
 */
static void
g2_build_add_vendor(g2_tree_t *t)
{
	g2_tree_t *c;

	c = g2_tree_alloc("V", GTA_VENDOR_CODE, CONST_STRLEN(GTA_VENDOR_CODE));
	g2_tree_add_child(t, c);
}

/**
 * Add child to the node, carrying an IP:port.
 *
 * @param t		the tree node where child must be added
 * @param name	the name of the child
 * @param addr	the IP address
 * @param port	the port address
 *
 * @return the added child node
 */
static g2_tree_t *
g2_build_add_host(g2_tree_t *t, const char *name, host_addr_t addr, uint16 port)
{
	struct packed_host_addr packed;
	uint alen;
	char payload[18];		/* Large enough for IPv6 as well, one day? */
	void *p;
	g2_tree_t *c;

	packed = host_addr_pack(addr);
	alen = packed_host_addr_size(packed) - 1;	/* skip network byte */

	p = mempcpy(payload, &packed.addr, alen);
	p = poke_le16(p, port);

	c = g2_tree_alloc_copy(name, payload, ptr_diff(p, payload));
	g2_tree_add_child(t, c);

	return c;
}

/**
 * Add child to the node, carrying our listening IP:port.
 *
 * @param t		the tree node where child must be added
 * @param name	the name of the child
 *
 * @return the added child node
 */
static g2_tree_t *
g2_build_add_listening_address(g2_tree_t *t, const char *name)
{
	return g2_build_add_host(t, name,
		listen_addr_primary(), socket_listen_port());
}

/**
 * Add the local node address as a "NA" child to the root.
 */
static void
g2_build_add_node_address(g2_tree_t *t)
{
	g2_build_add_listening_address(t, "NA");
}

/**
 * Add the servent update as a "UP" child to the root.
 */
static void
g2_build_add_uptime(g2_tree_t *t)
{
	time_delta_t uptime;
	char payload[8];
	int n;
	g2_tree_t *c;

	/*
	 * The uptime will typically be small, hence it is encoded as a variable
	 * length little-endian value, with trailing zeros removed.  Usually
	 * only 2 or 3 bytes will be necesssary to encode the uptime (in seconds).
	 */

	uptime = delta_time(tm_time(), GNET_PROPERTY(start_stamp));
	n = vlint_encode(uptime, payload);

	c = g2_tree_alloc_copy("UP", payload, n);	/* No trailing 0s */
	g2_tree_add_child(t, c);
}

/**
 * Generate a "FW" child in the root if the node is firewalled.
 */
static void
g2_build_add_firewalled(g2_tree_t *t)
{
	if (GNET_PROPERTY(is_firewalled) || GNET_PROPERTY(is_udp_firewalled)) {
		g2_tree_t *c = g2_tree_alloc_empty("FW");
		g2_tree_add_child(t, c);
	}
}

/**
 * Generate a "BH" child in the root if the node is browsable.
 */
static void
g2_build_add_browsable(g2_tree_t *t)
{
	if (GNET_PROPERTY(browse_host_enabled)) {
		g2_tree_t *c = g2_tree_alloc_empty("BH");
		g2_tree_add_child(t, c);
	}
}

/**
 * Generate a "TLS" child in the root if the node supports TLS connections.
 * This is a documented GTKG extension.
 */
static void
g2_build_add_tls(g2_tree_t *t)
{
	if (tls_enabled()) {
		g2_tree_t *c = g2_tree_alloc_empty("TLS");
		g2_tree_add_child(t, c);
	}
}

/**
 * Generate a "HN" child in the root to hold the DNS hostname, if defined.
 * This is a documented GTKG extension.
 */
static void
g2_build_add_hostname(g2_tree_t *t)
{
	if (
		!GNET_PROPERTY(is_firewalled) &&
		GNET_PROPERTY(give_server_hostname) &&
		!is_null_or_empty(GNET_PROPERTY(server_hostname))
	) {
		g2_tree_t *c;
		const char *hostname = GNET_PROPERTY(server_hostname);

		c = g2_tree_alloc_copy("HN", hostname, vstrlen(hostname));
		g2_tree_add_child(t, c);
	}
}

/**
 * Generate as many "NH" children to the root as we have neihbouring hubs,
 * when the node is firewalled.  They can act as "push proxies", as in Gnutella.
 */
static void
g2_build_add_neighbours(g2_tree_t *t)
{
	if (GNET_PROPERTY(is_firewalled) || GNET_PROPERTY(is_udp_firewalled)) {
		const pslist_t *sl;

		PSLIST_FOREACH(node_all_g2_nodes(), sl) {
			const gnutella_node_t *n = sl->data;

			node_check(n);
			g_assert(NODE_TALKS_G2(n));

			if (NODE_IS_ESTABLISHED(n) && node_address_known(n))
				g2_build_add_host(t, "NH", n->gnet_addr, n->gnet_port);
		}
	}
}

/**
 * Add a "gtkgV" child to propagate GTKG version information.
 */
static void
g2_build_add_gtkgv(g2_tree_t *t)
{
	char buf[GTKGV_MAX_LEN];
	size_t len;
	g2_tree_t *c;

	len = ggept_gtkgv_build(ARYLEN(buf));
	c = g2_tree_alloc_copy("gtkgV", buf, len);
	g2_tree_add_child(t, c);
}

/**
 * Build a Local Node Info message.
 *
 * @return a /LNI message.
 */
pmsg_t *
g2_build_lni(void)
{
	g2_tree_t *t;
	pmsg_t *mb;

	t = g2_tree_alloc_empty(G2_NAME(LNI));

	/* LS -- library statistics */

	{
		uint32 files, kbytes;
		char payload[8];
		void *p = payload;
		g2_tree_t *c;

		files  = MIN(shared_files_scanned(), ~((uint32) 0U));
		kbytes = MIN(shared_kbytes_scanned(), ~((uint32) 0U));

		p = poke_le32(p, files);
		p = poke_le32(p, kbytes);

		c = g2_tree_alloc_copy("LS", ARYLEN(payload));
		g2_tree_add_child(t, c);
	}

	g2_build_add_firewalled(t);		/* FW -- whether servent is firewalled */
	g2_build_add_uptime(t);			/* UP -- servent uptime */
	g2_build_add_vendor(t);			/* V  -- vendor code */
	g2_build_add_guid(t);			/* GU -- the GUID of this node */
	g2_build_add_node_address(t);	/* NA -- the IP:port of this node */
	g2_build_add_tls(t);			/* TLS -- whether TLS is supported */

	mb = g2_build_pmsg(t);
	g2_tree_free_null(&t);

	return mb;
}

/**
 * Build a PUSH request.
 *
 * @param guid	the GUID of the remote servent we're trying to reach
 *
 * @return a /PUSH message, or NULL if the listening address or port
 * are invalid.
 */
pmsg_t *
g2_build_push(const guid_t *guid)
{
	g2_tree_t *t, *c;
	pmsg_t *mb;
	char payload[18];
	size_t plen;
	host_addr_t addr = listen_addr_primary();
	uint16 port = socket_listen_port();

	if (0 == port || !is_host_addr(addr))
		return NULL;

	host_ip_port_poke(payload, addr, port, &plen);

	t = g2_tree_alloc(G2_NAME(PUSH), payload, plen);
	g2_build_add_tls(t);

	/*
	 * The /?/TO child is a generic GUID-based addressing scheme.
	 *
	 * To ensure it is the first child of the packet, we add it last since
	 * our children are pre-pended to the list of existing ones.
	 */

	c = g2_tree_alloc("TO", guid, GUID_RAW_SIZE);
	g2_tree_add_child(t, c);

	mb = g2_build_ctrl_pmsg(t);
	g2_tree_free_null(&t);

	return mb;
}

/**
 * Build a Query Key Request
 *
 * @return a /QKR message.
 */
pmsg_t *
g2_build_qkr(void)
{
	g2_tree_t *t;
	pmsg_t *mb;

	t = g2_tree_alloc_empty(G2_NAME(QKR));
	g2_build_add_listening_address(t, "RNA");

	mb = g2_build_ctrl_pmsg(t);
	g2_tree_free_null(&t);

	return mb;
}

/*
 * Build a Query.
 *
 * @param muid		the MUID to use for the search message
 * @param query		the query string
 * @param mtype		media type filtering (0 if none wanted)
 * @param query_key	the GUESS query key to use
 * @param length	length of query key
 *
 * @return a /Q2 message.
 */
pmsg_t *
g2_build_q2(const guid_t *muid, const char *query,
	unsigned mtype, const void *query_key, uint8 length)
{
	g2_tree_t *t, *c;
	pmsg_t *mb;
	static const char interest[] = "URL\0PFS\0DN\0A";

	t = g2_tree_alloc_copy(G2_NAME(Q2), PTRLEN(muid));
	c = g2_build_add_listening_address(t, "UDP");
	g2_tree_append_payload(c, query_key, length);

	c = g2_tree_alloc_copy("DN", query, vstrlen(query));
	g2_tree_add_child(t, c);

	/*
	 * Due to an important Shareaza parsing bug in versions <= 2.7.1.0,
	 * we're including the trailing NUL in the interest[] string.
	 * Otherwise, that simply blocks Shareaza in a looong parsing loop.
	 * Hence the use of "sizeof" below instead of CONST_STRLEN().
	 *		--RAM, 2014-02-28
	 */

	c = g2_tree_alloc("I", interest, sizeof interest);
	g2_tree_add_child(t, c);

	if (mtype != 0) {
		/*
		 * Don't know how we can combine these flags on G2, hence only
		 * emit for simple flags.
		 */

		c = NULL;

		if (SEARCH_AUDIO_TYPE == (mtype & SEARCH_AUDIO_TYPE)) {
			static const char audio[] = "<audio/>";
			c = g2_tree_alloc("MD", audio, CONST_STRLEN(audio));
		}
		else if (SEARCH_VIDEO_TYPE == (mtype & SEARCH_VIDEO_TYPE)) {
			static const char video[] = "<video/>";
			c = g2_tree_alloc("MD", video, CONST_STRLEN(video));
		}
		else if (SEARCH_IMG_TYPE == (mtype & SEARCH_IMG_TYPE)) {
			static const char image[] = "<image/>";
			c = g2_tree_alloc("MD", image, CONST_STRLEN(image));
		}
		else if (SEARCH_DOC_TYPE == (mtype & SEARCH_DOC_TYPE)) {
			static const char doc[] = "<document/>";
			c = g2_tree_alloc("MD", doc, CONST_STRLEN(doc));
		}
		else if (mtype & (SEARCH_WIN_TYPE | SEARCH_UNIX_TYPE)) {
			static const char archive[] = "<archive/>";
			c = g2_tree_alloc("MD", archive, CONST_STRLEN(archive));
		}

		if (c != NULL)
			g2_tree_add_child(t, c);
	}

	if (GNET_PROPERTY(is_firewalled) || GNET_PROPERTY(is_udp_firewalled)) {
		/*
		 * Shareaza uses /Q2/NAT to indicate that the querying node is
		 * firewalled.  Why didn't they choose /Q2/FW for consistency?
		 */

		c = g2_tree_alloc_empty("NAT");
		g2_tree_add_child(t, c);
	}

	g2_tree_reverse_children(t);

	mb = g2_build_pmsg(t);
	g2_tree_free_null(&t);

	return mb;
}

/**
 * Free routine for the extended message blocks we send to the UDP layer.
 */
static void
g2_qh2_pmsg_free(pmsg_t *mb, void *arg)
{
	struct g2_qh2_pmsg_info *pmi = arg;
	gnutella_node_t *n;

	g2_qh2_pmsg_info_check(pmi);
	g_assert(pmsg_is_extended(mb));

	if (pmsg_was_sent(mb))
		goto done;

	/*
	 * Message was unsent, probably because the UDP address in the /Q2 was
	 * wrong for some reason.
	 *
	 * If we're still connected to the hub which passed us this /Q2, then
	 * we can relay back the /QH2 to the hub and it will hopefully be able
	 * to deliver it back to the querying node.
	 */

	n = node_by_id(pmi->hub_id);

	if (NULL == n) {
		if (GNET_PROPERTY(g2_debug) > 1) {
			g_debug("%s(): could not send %s, relaying hub is gone, dropping.",
				G_STRFUNC, g2_msg_infostr_mb(mb));
		}
		gnet_stats_inc_general(GNR_UDP_G2_HITS_UNDELIVERED);
		goto done;
	} else {
		pmsg_t *nmb;

		if (GNET_PROPERTY(g2_debug) > 1) {
			g_debug("%s(): could not send %s, giving back to %s for relaying",
				G_STRFUNC, g2_msg_infostr_mb(mb), node_infostr(n));
		}

		nmb = pmsg_clone_plain(mb);
		pmsg_clear_reliable(nmb);

		g2_node_send(n, nmb);
		gnet_stats_inc_general(GNR_UDP_G2_HITS_REROUTED_TO_HUB);
	}

done:
	nid_unref(pmi->hub_id);
	pmi->magic = 0;
	WFREE(pmi);
}

/**
 * Structure used to control the generation of query hits (/QH2 messages)
 */
struct g2_qh2_builder {
	char payload[1 + GUID_RAW_SIZE];	/**< hops + MUID */
	const guid_t *muid;			/**< MUID of query, for logging if needed */
	const gnutella_node_t *hub;	/**< The hub that gave us the query */
	const gnutella_node_t *n;	/**< The node to which results are sent */
	hset_t *hs;					/**< Records SHA1 atoms we sent */
	g2_tree_t *t;				/**< Current message */
	g2_build_qh2_cb_t cb;		/**< (optional) Processing callback */
	void *arg;					/**< Processing callback argument */
	size_t max_size;			/**< Max query hit size we want */
	size_t common_size;			/**< Serialized size with common fields only */
	size_t current_size;		/**< Estimated current size */
	int messages;				/**< Counts flushed messages, for logging */
	uint flags;					/**< Flags for optional entries in hit */
	uint from_gtkg:1;			/**< Whether query comes from GTKG */
	uint to_udp:1;				/**< Whether results are sent via UDP */
};

/**
 * Flush current /QH2.
 *
 * Depending how the QH2 builder is configured, this either sends the message
 * to the target node or invokes a processing callback.
 */
static void
g2_build_qh2_flush(struct g2_qh2_builder *ctx)
{
	pmsg_t *mb;

	g_assert(ctx != NULL);
	g_assert(ctx->t != NULL);
	g_assert((ctx->n != NULL) ^ (ctx->cb != NULL));

	/*
	 * Restore the order of children in the root packet to be the order we
	 * used when we added the nodes, since we prepend new children.
	 */

	g2_tree_reverse_children(ctx->t);

	/*
	 * If sending over UDP, ask for reliable delivery of the query hit.
	 * To be able to monitor the fate of the message, we asssociate a free
	 * routine to it.
	 */

	if (ctx->to_udp) {
		struct g2_qh2_pmsg_info *pmi;

		WALLOC0(pmi);
		pmi->magic = G2_QH2_PMI_MAGIC;
		pmi->hub_id = nid_ref(NODE_ID(ctx->hub));
		mb = g2_build_pmsg_extended(ctx->t, g2_qh2_pmsg_free, pmi);
		pmsg_mark_reliable(mb);
	} else {
		mb = g2_build_pmsg(ctx->t);
	}

	if (GNET_PROPERTY(g2_debug) > 3) {
		g_debug("%s(): flushing the following hit for "
			"Q2 #%s to %s%s (%d bytes):",
			G_STRFUNC, guid_hex_str(ctx->muid),
			NULL == ctx->n ?
				stacktrace_function_name(ctx->cb) : node_infostr(ctx->n),
			NULL == ctx->n ? "()" : "", pmsg_size(mb));
		g2_tfmt_tree_dump(ctx->t, stderr, G2FMT_O_PAYLOAD | G2FMT_O_PAYLEN);
	}

	if (ctx->n != NULL)
		g2_node_send(ctx->n, mb);
	else
		(*ctx->cb)(mb, ctx->arg);

	ctx->messages++;
	ctx->current_size = 0;
	g2_tree_free_null(&ctx->t);
}

/**
 * Create new /QH2 and fill it with fields that do not depend on the hits
 * themselves, i.e. all the common fields we have to send in every /QH2 anyway.
 */
static void
g2_build_qh2_start(struct g2_qh2_builder *ctx)
{
	g_assert(NULL == ctx->t);

	/*
	 * The payload of the /QH2 message is one byte hop count + the MUID.
	 */

	ctx->t = g2_tree_alloc(G2_NAME(QH2), ARYLEN(ctx->payload));

	g2_build_add_node_address(ctx->t);	/* NA -- the IP:port of this node */
	g2_build_add_guid(ctx->t);			/* GU -- the GUID of this node */
	g2_build_add_vendor(ctx->t);		/* V  -- vendor code */
	g2_build_add_firewalled(ctx->t);	/* FW -- when servent is firewalled */
	g2_build_add_browsable(ctx->t);		/* BH -- when browsing is allowed */
	g2_build_add_tls(ctx->t);			/* TLS -- whether TLS is supported */
	g2_build_add_uptime(ctx->t);		/* UP -- servent uptime */
	g2_build_add_neighbours(ctx->t);	/* NH -- neighbouring hubs, if FW */
	g2_build_add_hostname(ctx->t);		/* HN -- DNS hostname, if defined */

	/*
	 * If the query comes from a GTKG node (not 100% safe, there can be some
	 * false positive, but we cannot miss any true GTKG query), propagate back
	 * detailed version information.
	 */

	if (ctx->from_gtkg)
		g2_build_add_gtkgv(ctx->t);		/* gtkgV -- GTKG version info */

	/*
	 * Compute size we have so far, once per query hit series.
	 */

	if G_UNLIKELY(0 == ctx->common_size)
		ctx->common_size = g2_frame_serialize(ctx->t, NULL, 0);

	ctx->current_size = ctx->common_size;
}

/**
 * Add file to the current query hit.
 *
 * @return TRUE if we kept the file, FALSE if we did not include it in the hit.
 */
static bool
g2_build_qh2_add(struct g2_qh2_builder *ctx, const shared_file_t *sf)
{
	const sha1_t *sha1;
	g2_tree_t *h, *c;

	shared_file_check(sf);

	/*
	 * Make sure the file is still in the library.
	 */

	if (0 == shared_file_index(sf))
		return FALSE;

	/*
	 * On G2, the H/URN child is required, meaning we need the SHA1 at least.
	 */

	if (!sha1_hash_available(sf))
		return FALSE;

	/*
	 * Do not send duplicates, as determined by the SHA1 of the resource.
	 *
	 * A user may share several files with different names but the same SHA1,
	 * and if all of them are hits, we only want to send one instance.
	 *
	 * When generating hits for host-browsing, we do not care about duplicates
	 * and ctx->hs is NULL then.
	 */

	sha1 = shared_file_sha1(sf);		/* This is an atom */

	if (ctx->hs != NULL) {
		if (hset_contains(ctx->hs, sha1))
			return FALSE;

		hset_insert(ctx->hs, sha1);
	}

	/*
	 * Create the "H" child and attach it to the current tree.
	 */

	if (NULL == ctx->t)
		g2_build_qh2_start(ctx);

	h = g2_tree_alloc_empty("H");
	g2_tree_add_child(ctx->t, h);

	/*
	 * URN -- Universal Resource Name
	 *
	 * If there is a known TTH, then we can generate a bitprint, otherwise
	 * we just convey the SHA1.
	 */

	{
		const tth_t * const tth = shared_file_tth(sf);
		char payload[SHA1_RAW_SIZE + TTH_RAW_SIZE + sizeof G2_URN_BITPRINT];
		char *p = payload;

		/* Can't use ARYLEN(x) in case mempcpy() is a macro with 3 args declared */

		if (NULL == tth) {
			p = mempcpy(p, G2_URN_SHA1, sizeof G2_URN_SHA1);
			p += clamp_memcpy(p, sizeof payload - ptr_diff(p, payload),
				sha1, SHA1_RAW_SIZE);
		} else {
			p = mempcpy(p, G2_URN_BITPRINT, sizeof G2_URN_BITPRINT);
			p += clamp_memcpy(p, sizeof payload - ptr_diff(p, payload),
				sha1, SHA1_RAW_SIZE);
			p += clamp_memcpy(p, sizeof payload - ptr_diff(p, payload),
				tth, TTH_RAW_SIZE);
		}

		g_assert(ptr_diff(p, payload) <= sizeof payload);

		c = g2_tree_alloc_copy("URN", payload, ptr_diff(p, payload));
		g2_tree_add_child(h, c);
	}

	/*
	 * URL -- empty to indicate that we share the file via uri-res.
	 */

	if (ctx->flags & QHIT_F_G2_URL) {
		uint known;
		uint16 csc;

		c = g2_tree_alloc_empty("URL");
		g2_tree_add_child(h, c);

		/*
		 * CSC -- if we know alternate sources, indicate how many in "CSC".
		 *
		 * This child is only emitted when they requested "URL".
		 */

		known = dmesh_count(sha1);
		csc = MIN(known, MAX_INT_VAL(uint16));

		if (csc != 0) {
			char payload[2];

			poke_le16(payload, csc);
			c = g2_tree_alloc_copy("CSC", ARYLEN(payload));
			g2_tree_add_child(h, c);
		}

		/*
		 * PART -- if we only have a partial file, indicate how much we have.
		 *
		 * This child is only emitted when they requested "URL".
		 */

		if (shared_file_is_partial(sf) && !shared_file_is_finished(sf)) {
			filesize_t available = shared_file_available(sf);
			char payload[8];	/* If we have to encode file size as 64-bit */
			uint32 av32;
			time_t mtime = shared_file_modification_time(sf);

			c = g2_tree_alloc_empty("PART");
			g2_tree_add_child(h, c);

			av32 = available;
			if (av32 == available) {
				/* Fits within a 32-bit quantity */
				poke_le32(payload, av32);
				g2_tree_set_payload(c, payload, sizeof av32, TRUE);
			} else {
				/* Encode as a 64-bit quantity then */
				poke_le64(payload, available);
				g2_tree_set_payload(c, ARYLEN(payload), TRUE);
			}

			/*
			 * GTKG extension: encode the last modification time of the
			 * partial file in an "MT" child.  This lets the other party
			 * determine whether the host is still able to actively complete
			 * the file.
			 */

			poke_le32(payload, (uint32) mtime);
			g2_tree_add_child(c,
				g2_tree_alloc_copy("MT", payload, sizeof(uint32)));
		}

		/*
		 * CT -- creation time of the resource (GTKG extension).
		 */

		{
			time_t create_time = shared_file_creation_time(sf);

			if ((time_t) -1 != create_time) {
				char payload[8];
				int n;

				create_time = MAX(0, create_time);
				n = vlint_encode(create_time, payload);
				g2_tree_add_child(h,
					g2_tree_alloc_copy("CT", payload, n));	/* No trailing 0s */
			}
		}
	}

	/*
	 * DN -- distinguished name.
	 *
	 * Note that the presence of DN also governs the presence of SZ if the
	 * file length does not fit a 32-bit unsigned quantity.
	 */

	if (ctx->flags & QHIT_F_G2_DN) {
		char payload[8];		/* If we have to encode file size as 64-bit */
		uint32 fs32;
		filesize_t fs = shared_file_size(sf);
		const char *name;
		const char *rp;

		c = g2_tree_alloc_empty("DN");

		fs32 = fs;
		if (fs32 == fs) {
			/* Fits within a 32-bit quantity */
			poke_le32(payload, fs32);
			g2_tree_set_payload(c, payload, sizeof fs32, TRUE);
		} else {
			/* Does not fit a 32-bit quantity, emit a SZ child */
			poke_le64(payload, fs);
			g2_tree_add_child(h, g2_tree_alloc_copy("SZ", ARYLEN(payload)));
		}

		name = shared_file_name_nfc(sf);
		g2_tree_append_payload(c, name, shared_file_name_nfc_len(sf));
		g2_tree_add_child(h, c);

		/*
		 * GTKG extension: if there is a file path, expose it as a "P" child
		 * under the DN node.
		 */

		rp = shared_file_relative_path(sf);
		if (rp != NULL) {
			g2_tree_add_child(c, g2_tree_alloc_copy("P", rp, vstrlen(rp)));
		}
	}

	/*
	 * GTKG extension: if they requested alt-locs in the /Q2/I with "A", then
	 * send them some known alt-locs in an "ALT" child.
	 *
	 * Note that these alt-locs can be for Gnutella hosts: since both Gnutella
	 * and G2 share a common HTTP-based file transfer mechanism with compatible
	 * extra headers, there is no need to handle them separately.
	 */

	if (ctx->flags & QHIT_F_G2_ALT) {
		gnet_host_t hvec[G2_BUILD_QH2_MAX_ALT];
		int hcnt = 0;

		hcnt = dmesh_fill_alternate(sha1, hvec, N_ITEMS(hvec));

		if (hcnt > 0) {
			int i;

			c = g2_tree_alloc_empty("ALT");

			for (i = 0; i < hcnt; i++) {
				host_addr_t addr;
				uint16 port;

				addr = gnet_host_get_addr(&hvec[i]);
				port = gnet_host_get_port(&hvec[i]);

				if (host_addr_is_ipv4(addr)) {
					char payload[6];

					host_ip_port_poke(payload, addr, port, NULL);
					g2_tree_append_payload(c, ARYLEN(payload));
				}
			}

			/*
			 * If the payload is still empty, then drop the "ALT" child.
			 * Otherwise, attach it to the "H" node.
			 */

			if (NULL == g2_tree_node_payload(c, NULL)) {
				g2_tree_free_null(&c);
			} else {
				g2_tree_add_child(h, c);
			}
		}
	}

	/*
	 * Update the size of the query hit we're generating.
	 */

	ctx->current_size += g2_frame_serialize(h, NULL, 0);

	return TRUE;
}

/**
 * Process the files according to the initialized /QH2 context.
 *
 * @return the amount of files processed.
 */
static int
g2_build_qh2_process(const pslist_t *files, struct g2_qh2_builder *ctx)
{
	const pslist_t *sl;
	int sent = 0;

	PSLIST_FOREACH(files, sl) {
		shared_file_t *sf = sl->data;

		if (g2_build_qh2_add(ctx, sf))
			sent++;

		if (ctx->current_size >= ctx->max_size)
			g2_build_qh2_flush(ctx);

		shared_file_unref(&sf);
	}

	if (ctx->t != NULL)					/* Still some unflushed results */
		g2_build_qh2_flush(ctx);		/* Send last packet */

	hset_free_null(&ctx->hs);

	return sent;
}

/**
 * Build and send query hits (/QH2) to specified node.
 *
 * @param h			the hub node which sent us the query
 * @param n			the node where we should send results to
 * @param files		the list of shared_file_t entries that make up results
 * @param count		the amount of results held in the list
 * @param muid		the query's MUID
 * @param flags		a set of QHIT_F_G2_* flags
 */
void
g2_build_send_qh2(const gnutella_node_t *h, gnutella_node_t *n,
	pslist_t *files, int count, const guid_t *muid, uint flags)
{
	struct g2_qh2_builder ctx;
	int sent = 0;

	ZERO(&ctx);

	if (NULL == n) {
		shared_file_slist_free_null(&files);
		goto done;		/* G2 support was disabled whilst processing */
	}

	clamp_memcpy(ARYPOSLEN(ctx.payload, 1), muid, GUID_RAW_SIZE);
	ctx.muid = muid;
	ctx.hs = hset_create(HASH_KEY_SELF, 0);
	ctx.max_size = G2_BUILD_QH2_THRESH;
	ctx.flags = flags;
	ctx.hub = h;
	ctx.n = n;
	ctx.to_udp = NODE_IS_UDP(n);

	/*
	 * Determine whether query comes from GTKG.
	 *
	 * Because G2 support was added in 2014-01, we're past 2012-10-07, date
	 * where all MUID markup in queries has been made compatible with OOB,
	 * so that our markup does not coincide with OOB markup.  In G2, the MUID
	 * is not supposed to carry OOB delivery information, but since we're using
	 * the same MUID to query Gnuella and G2, we have to expect OOB-tagged
	 * MUIDs from GTKG.
	 */

	{
		uint8 maj, min;
		bool rel;

		ctx.from_gtkg = guid_query_muid_is_gtkg(muid, TRUE, &maj, &min, &rel);
	}

	sent = g2_build_qh2_process(files, &ctx);
	pslist_free(files);

	/* FALL THROUGH */

done:
	if (GNET_PROPERTY(g2_debug) > 3) {
		g_debug("%s(): sent %d/%d hit%s in %d message%s to %s",
			G_STRFUNC, sent, count, plural(sent),
			PLURAL(ctx.messages), node_infostr(n));
	}
}

/**
 * Build and post-process /QH2 messages for specified files.
 *
 * Results are held in the `files' list.  They are packed in hits until
 * the message reaches the `max_msgsize' limit at which time the packet
 * is flushed and given the the `cb' callback for processing (sending,
 * queueing, whatever).
 *
 * The callback is invoked as
 *
 *		cb(mb, udata)
 *
 * where the serialized /QH2 message is held in `mb'.
 * The `udata' parameter is simply user-supplied data, opaque for us.
 *
 * @param files			the list of shared_file_t entries that make up results
 * @param count			the amount of results to deliver (first `count' files)
 * @param max_msgsize	the targeted maximum hit size before flushing
 * @param cb			the processor callback to invoke on each built hit
 * @param udata			argument to pass to callback
 * @param muid			the MUID to use on each generated hit
 * @param flags			a set of QHIT_F_G2_* flags
 */
void
g2_build_qh2_results(const pslist_t *files, int count, size_t max_msgsize,
	g2_build_qh2_cb_t cb, void *udata, const struct guid *muid, uint flags)
{
	struct g2_qh2_builder ctx;
	int sent;

	ZERO(&ctx);
	clamp_memcpy(ARYPOSLEN(ctx.payload, 1), muid, GUID_RAW_SIZE);
	ctx.muid = muid;
	ctx.max_size = max_msgsize;
	ctx.flags = flags;
	ctx.cb = cb;
	ctx.arg = udata;
	ctx.from_gtkg = TRUE;	/* Always include the gtkgV child */

	sent = g2_build_qh2_process(files, &ctx);

	if (GNET_PROPERTY(g2_debug) > 3) {
		g_debug("%s(): procesed %d/%d hit%s in %d message%s to %s()",
			G_STRFUNC, sent, count, plural(sent),
			PLURAL(ctx.messages), stacktrace_function_name(cb));
	}
}

/**
 * Free up global messages, at shutdown time.
 */
void
g2_build_close(void)
{
	/* Don't take locks, we're shutdowning from a single thread */
	pmsg_free_null(&build_alive_pi);
	pmsg_free_null(&build_po);
}

/* vi: set ts=4 sw=4 cindent: */
