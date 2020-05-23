/*
 * Copyright (c) 2001-2003, 2011, Raphael Manfredi
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
 * Gnutella Network Messages routing.
 *
 * @author Raphael Manfredi
 * @date 2001-2003, 2011
 */

#include "common.h"

#include "routing.h"

#include "gmsg.h"
#include "gnet_stats.h"
#include "guid.h"
#include "hostiles.h"
#include "hosts.h"
#include "nodes.h"
#include "oob_proxy.h"
#include "search.h"			/* For search_passive. */
#include "settings.h"

#include "if/gnet_property.h"
#include "if/gnet_property_priv.h"

#include "lib/aging.h"
#include "lib/atoms.h"
#include "lib/endian.h"
#include "lib/halloc.h"
#include "lib/hashing.h"
#include "lib/host_addr.h"
#include "lib/hset.h"
#include "lib/htable.h"
#include "lib/pslist.h"
#include "lib/str.h"
#include "lib/stringify.h"
#include "lib/tm.h"
#include "lib/walloc.h"

#include "lib/override.h"	/* Must be the last header included */

static gnutella_node_t *fake_node;		/**< Our fake node */

/**
 * An UDP node that sent us a message and for which we want to retain the
 * source so that replies can be routed back.
 *
 * The reason we have to create routing_udp_node is for GUESS routing: we have
 * to remember the source of queries but don't want to create a full-blown
 * gnutella_node just to record a few attributes.
 *
 * To be able to store a gnutella_node or a routing_udp_node pointer at the
 * same place without adding an union discriminent (to save space in the
 * routing table), we rely on C's structural equivalence and the presence of
 * a leading magic number field in both structures.
 */
struct routing_udp_node {
	node_magic_t magic;			/**< Magic number, MUST be the first field */
	host_addr_t addr;			/**< Remote node UDP address */
	uint16 port;				/**< Remote node UDP port */
	uint8 can_deflate;			/**< Whether servent supports UDP compression */
	uint8 sr_udp;				/**< Whether servent has semi-reliable UDP */
	struct route_data *routing_data;
};

static inline void
routing_udp_node_check(const struct routing_udp_node * const un)
{
	g_assert(un != NULL);
	g_assert(NODE_UDP_MAGIC == un->magic);
}

#define ROUTE_UDP_LIFETIME	180		/**< Keep UDP routes for 3 minutes */

/**
 * An entry in the routing table.
 *
 * Each entry is stored in the "message_array[]", to keep track of the
 * order used to create the routes, and in a hash table for quick lookup,
 * hashing being made based on the muid and the function.
 *
 * Query hit routes and push routes are precious, therefore they are
 * moved to the tail of the "message_array[]" when they get used to increase
 * their liftime.
 */
struct message {
	struct guid muid;			/**< Message UID */
	struct message **slot;		/**< Place where we're referenced from */
	pslist_t *routes;            /**< route_data from where the message came */
	pslist_t *ttls;			/**< For broadcasted messages: TTL by route */
	uint8 function;				/**< Type of the message */
	uint8 ttl;					/**< Max TTL we saw for this message */
	uint8 chunk_idx;			/**< Index of chunk holding the slot */
};

/**
 * We don't store a list of nodes in the message structure, but a list of
 * route_data: the reason is that nodes can go away, but we don't want to
 * traverse the whole routing table to reclaim all the places where they
 * were referenced.
 *
 * The route_data structure points to a node and keeps track of the amount of
 * messages that it is used to track.  When a node disappears, the `node' field
 * in the associated route_data structure is set to NULL.  Dangling references
 * are removed only when needed.
 *
 * The node is a generic pointer, which refers to either a gnutella_node or
 * a routing_udp_node.  Both structures start with a magic number and structural
 * equivalence allows us to easily know which structure it really refers to.
 */
struct route_data {
	void *node;					/**< gnutella_node or routing_udp_node */
	int32 saved_messages; 		/**< # msg from this host in routing table */
};

static struct route_data fake_route;		/**< Our fake route_data */
static const char *debug_msg[256];

/*
 * We're using the message table to store Query hit routes for Push requests,
 * but this is a temporary solution.  As we continuously refresh those
 * routes, we must make sure they stay alive for some time after having been
 * updated.  Given that we periodically supersede the message_array[] in a
 * round-robin fashion, it is not really appropriate.
 *		--RAM, 06/01/2002
 */
#define QUERY_HIT_ROUTE_SAVE	0	/**< Function used to store QHit GUIDs */

/*
 * Routing table data structures.
 *
 * This is known as the "message_array[]".  It used to be a fixed-sized
 * array, but it is no more.  Instead, we use an array of chunks that
 * are dynamically allocated as needed.  The aim is to not cycle
 * back to the beginning of the table, loosing all the routing information
 * before at least TABLE_MIN_CYCLE seconds have elapsed or we have
 * allocated more than the amount of chunks we can tolerate.
 *
 * Each chunk contains pointers to dynamically allocated message entries,
 * each pointer being called a "slot" whilst the message structure is called
 * the "entry".
 */

#define CHUNK_BITS			14 	  /**< log2 of # messages stored  in a chunk */
#define MAX_CHUNKS			64	  /**< Max # of chunks */
#define TABLE_MIN_CYCLE		3600  /**< 1 hour at least */

#define CHUNK_MESSAGES		(1 << CHUNK_BITS)
#define CHUNK_INDEX(x)		(((x) & ~(CHUNK_MESSAGES - 1)) >> CHUNK_BITS)
#define ENTRY_INDEX(x)		((x) & (CHUNK_MESSAGES - 1))

static struct {
	struct message **chunks[MAX_CHUNKS];
	int next_idx;				 /**< Next slot to use in "message_array[]" */
	int capacity;				 /**< Capacity in terms of messages */
	int count;					 /**< Amount really stored */
	unsigned nchunks;			 /**< Amount of allocated chunks */
	hset_t *messages_hashed;	 /**< All messages (key = struct message) */
	time_t last_rotation;		 /**< Last time we restarted from idx=0 */
} routing;

/**
 * "banned" GUIDs for push routing.
 *
 * The following GUIDs are so common that it does not make sense to
 * route pushes to them (i.e. they are are NOT unique on the network!).
 */
static const char * const banned_push[] = {
	"20d262ff0e6fd6119734004005a207b1",		/**< Morpheus, 29/06/2002 */
	"9c51e42153d4c94a858f8e8a8391173d",		/**< morph471 4.7.1.326 */
	"27630b632f070ca9ffc48eb06a72c700",		/**< Morpheus?, 2005-08-30 */
	"58585858585858585858585858585858",		/**< Probably an init bug! */
};
static hset_t *ht_banned_push;

/**
 * Starving GUIDs for push routing.
 *
 * Downloads which require a push route to a given GUID but have no identified
 * push route are said to be "starving" for that GUID.  They can of course
 * rely on push-proxies to contact the node, or look through the DHT.
 *
 * But still, in case we happen to see a query hit that comes from one of
 * the starving GUID, it's good to notify the download layer.
 */
static htable_t *ht_starving_guid;

/**
 * Push-proxy table.
 *
 * It maps a GUID to a node, so that we can easily send a push message
 * on behalf of a requesting node to the proper connection.
 */
static htable_t *ht_proxyfied;

/**
 * Routing logging.
 */
struct route_log {
	host_addr_t addr;			/**< Sender's IP */
	uint16 port;				/**< Sender's port */
	struct guid muid;			/**< Message ID */
	uint8 function;				/**< Message function */
	uint8 hops;					/**< Message hops */
	uint8 ttl;					/**< Message ttl */
	char extra[120];			/**< Extra text for logging */
	struct route_dest dest;		/**< Message destination */
	unsigned handle:1;			/**< Whether message will be handled */
	unsigned local:1;			/**< Whether message originated locally */
	unsigned new:1;				/**< Whether message is a new message */
	unsigned routing:1;			/**< Whether message is routed */
};

/**
 * UDP routing node table.
 *
 * This is an aging table that allows us to keep UDP routing information for
 * a while and have it expire automatically.
 */
static aging_table_t *at_udp_routes;

static bool find_message(
	const struct guid *muid, uint8 function, struct message **m);
static void free_route_list(struct message *m);

static inline bool
is_banned_push(const struct guid *guid)
{
	return hset_contains(ht_banned_push, guid) || guid_is_banned(guid);
}

struct node_magic {
	node_magic_t magic;
};

/**
 * Checks whether the generic pointer in "struct route_data" points to a
 * gnutella_node.
 */
static inline bool
route_node_is_gnutella(const void *node)
{
	g_assert(node != NULL);
	return NODE_MAGIC == ((struct node_magic *) node)->magic;
}

/**
 * Checks whether the generic pointer in "struct route_data" points to a
 * routing_udp_node.
 */
static inline bool G_UNUSED
route_node_is_udp(const void *node)
{
	g_assert(node != NULL);
	return NODE_UDP_MAGIC == ((struct node_magic *) node)->magic;
}

/**
 * Force a gnutella_node as the route destination.
 */
static gnutella_node_t *
route_node_get_gnutella(void *node)
{
	switch (((struct node_magic *) node)->magic) {
	case NODE_MAGIC:
		return node;
	case NODE_UDP_MAGIC:
		{
			struct routing_udp_node *un = node;
			return node_udp_route_get_addr_port(un->addr, un->port,
				un->can_deflate, un->sr_udp);
		}
	}
	g_assert_not_reached();
}

/**
 * Allocate a new UDP node recording the UDP route from node ``n''.
 */
static struct routing_udp_node *
route_allocate_udp(const gnutella_node_t *n)
{
	struct routing_udp_node *un;

	node_check(n);
	g_assert(NODE_IS_UDP(n));

	WALLOC0(un);
	un->magic = NODE_UDP_MAGIC;
	un->addr = n->addr;
	un->port = n->port;

	/*
	 * In some cases, the UDP route is allocated before the node can be flagged
	 * as supporting deflated traffic or semi-reliable UDP.  In particular
	 * for GUESS queries which go through route_message() before having their
	 * actual message content analyzed.
	 *
	 * This is why we have the following routines to force the behaviour later
	 * on when the message is parsed:
	 *		route_udp_mark_deflatable()
	 *		route_udp_mark_semi_reliable()
	 *
	 * We know that a given host will not have varying support for deflation
	 * or semi-reliable UDP, hence this works.  Because the UDP route will be
	 * collected when it is unused for too long, we should be immune against a
	 * new node with different characteristics reusing this IP:port.
	 *		--RAM, 2014-06-29
	 */

	/* If it can inflate, we can deflate traffic to it */
	un->can_deflate = booleanize(NODE_CAN_INFLATE(n));

	/* If query had the semi-reliable UDP flag set, then we can use it */
	un->sr_udp = booleanize(NODE_HAS_SR_UDP(n));

	return un;
}

/**
 * Free UDP node.
 */
static void
route_free_udp(struct routing_udp_node *un)
{
	routing_udp_node_check(un);

	if (un->routing_data) {
		routing_node_remove(un);
		un->routing_data = NULL;
	}
	un->magic = 0;
	WFREE(un);
}

/**
 * Hash an UDP node structure.
 */
static unsigned
route_udp_node_hash(const void *key)
{
	const struct routing_udp_node *un = key;

	return host_addr_port_hash(un->addr, un->port);
}

/**
 * Are two UDP nodes equal?
 */
static int
route_udp_node_eq(const void *n1, const void *n2)
{
	const struct routing_udp_node *un1 = n1, *un2 = n2;

	return un1->port == un2->port && host_addr_equiv(un1->addr, un2->addr);
}

/**
 * Free routine callback for the UDP route aging table.
 */
static void
route_udp_kvfree(void *key, void *unused_value)
{
	struct routing_udp_node *un = key;

	routing_udp_node_check(un);
	(void) unused_value;

	if (GNET_PROPERTY(guess_server_debug) > 4) {
		g_debug("GUESS forgetting UDP node route %s:%u",
			host_addr_to_string(un->addr), un->port);
	}

	route_free_udp(un);
}

/**
 * Fetch a minimal UDP node data structure that can be used to record
 * the route associated with a message we got from that UDP node.
 *
 * @param n			the node for which we want the UDP route data
 * @param verbose	whether debugging message should be emitted on access
 *
 * @return the UDP node route.
 */
static struct routing_udp_node *
route_fetch_udp(const gnutella_node_t *n, bool verbose)
{
	struct routing_udp_node key;
	struct routing_udp_node *un;

	node_check(n);
	g_assert(NODE_IS_UDP(n));

	/*
	 * UDP nodes are created on the fly and will stay alive for at most
	 * ROUTE_UDP_LIFETIME seconds after last usage.
	 */

	key.addr = n->addr;
	key.port = n->port;

	un = aging_lookup_revitalise(at_udp_routes, &key);

	if (un != NULL) {
		if (verbose) {
			g_debug("GUESS reusing known UDP node route %s (%s)",
				host_addr_port_to_string(n->addr, n->port),
				un->sr_udp ? "reliable" :
				un->can_deflate ? "deflatable" : "regular");
		}
	} else {
		if (verbose) {
			g_debug("GUESS creating new UDP node route %s (%s)",
				host_addr_port_to_string(n->addr, n->port),
				NODE_HAS_SR_UDP(n) ? "reliable" :
				NODE_CAN_INFLATE(n) ? "deflatable" : "regular");
		}
		un = route_allocate_udp(n);
		aging_insert(at_udp_routes, un, un);
	}

	return un;
}

/**
 * Fetch a minimal UDP node data structure that can be used to record
 * the route associated with a message we got from that UDP node.
 */
static struct routing_udp_node *
route_get_udp(const gnutella_node_t *n)
{
	return route_fetch_udp(n, GNET_PROPERTY(guess_server_debug) > 4);
}

/**
 * Flag UDP route as deflatable.
 *
 * If the route does not exist yet for that host, it is created.
 */
void
route_udp_mark_deflatable(const gnutella_node_t *n)
{
	struct routing_udp_node *un;

	node_check(n);
	g_assert(NODE_IS_UDP(n));

	un = route_fetch_udp(n, FALSE);

	if (GNET_PROPERTY(guess_server_debug) > 4 && !un->can_deflate) {
		g_debug("GUESS flagging UDP node route %s as deflatable",
			host_addr_port_to_string(n->addr, n->port));
	}

	un->can_deflate = TRUE;
}

/**
 * Flag UDP route as semi-reliable.
 *
 * If the route does not exist yet for that host, it is created.
 */
void
route_udp_mark_semi_reliable(const gnutella_node_t *n)
{
	struct routing_udp_node *un;

	node_check(n);
	g_assert(NODE_IS_UDP(n));

	un = route_fetch_udp(n, FALSE);

	if (GNET_PROPERTY(guess_server_debug) > 4 && !un->sr_udp) {
		g_debug("GUESS flagging UDP node route %s as semi-reliable",
			host_addr_port_to_string(n->addr, n->port));
	}

	un->sr_udp = TRUE;
}

/**
 * Remove starving condition for a GUID.
 */
void
route_starving_remove(const guid_t *guid)
{
 	/*
	 * The GUID atom is still referred to by the server,
	 * so don't clear anything.
	 */

	htable_remove(ht_starving_guid, guid);
}

/**
 * Add starving condition for ``guid''.
 *
 * When we learn about a new route for that GUID, the callback will be
 * triggered, with the GUID as argument.
 *
 * @attention
 * NB: assumes ``guid'' is already an atom linked somehow to ``server''.
 */
void
route_starving_add(const guid_t *guid, route_starving_cb_t cb)
{
	htable_insert(ht_starving_guid, guid, cast_func_to_pointer(cb));
}

/**
 * Invoked when we discover a new route for a given GUID.
 *
 * Check whether a GUID was recorded as starving and invoke the callback
 * if it was.
 */
static void
route_starving_check(const guid_t *guid)
{
	route_starving_cb_t cb;

	cb = cast_pointer_to_func(htable_lookup(ht_starving_guid, guid));

	if (cb != NULL)
		(*cb)(guid);
}

/**
 * Record message parameters.
 */
static void
routing_log_init(struct route_log *route_log,
	gnutella_node_t *n,
	const struct guid *muid, uint8 function, uint8 hops, uint8 ttl)
{
	if (!GNET_PROPERTY(log_gnutella_routing))
		return;

	if (n == NULL) {
		route_log->local = TRUE;
		route_log->addr = zero_host_addr;
		route_log->port = 0;
	} else {
		route_log->local = FALSE;
		route_log->addr = n->addr;
		route_log->port = n->port;
	}

	route_log->function = function;
	route_log->hops = hops;
	route_log->ttl = ttl;
	route_log->muid = *muid;

	route_log->extra[0] = '\0';
	route_log->handle = FALSE;
	route_log->new = FALSE;
	route_log->routing = FALSE;
	route_log->dest.type = ROUTE_NONE;
}

/**
 * Record message's route.
 */
static void
routing_log_set_route(struct route_log *route_log,
	struct route_dest *dest, bool handle)
{
	if (!GNET_PROPERTY(log_gnutella_routing))
		return;

	route_log->dest = *dest;		/* Struct copy */
	route_log->handle = handle;
	route_log->routing = TRUE;
}

/**
 * Mark message as being new.
 */
static void
routing_log_set_new(struct route_log *route_log)
{
	if (!GNET_PROPERTY(log_gnutella_routing))
		return;

	route_log->new = TRUE;
}

/**
 * Record extra logging information, appending to existing information.
 */
static void G_PRINTF(2, 3)
routing_log_extra(struct route_log *route_log, const char *fmt, ...)
{
	va_list args;
	char *buf;
	int buflen;
	int len;

	if (!GNET_PROPERTY(log_gnutella_routing))
		return;

	buf = route_log->extra;
	buflen = sizeof(route_log->extra);
	len = vstrlen(route_log->extra);

	/*
	 * If there was already a message recorded, append "; " before
	 * the new message.
	 */

	if (len) {
		buflen -= len;
		buf += len;

		if (buflen > 2) {
			int seplen = str_bprintf(buf, buflen, "; ");

			buflen -= seplen;
			buf += seplen;
		}
	}

	if (buflen <= 2)
		return;

	va_start(args, fmt);
	str_vbprintf(buf, buflen, fmt, args);
	va_end(args);
}

/**
 * @return string representation of message route, as pointer to static data.
 */
static char *
route_string(struct route_dest *dest,
	const host_addr_t origin_addr, bool routed)
{
	static char msg[80];

	switch (dest->type) {
	case ROUTE_NONE:
		str_bprintf(ARYLEN(msg), routed ? "stops here" : "registered");
		break;
	case ROUTE_LEAVES:
		str_bprintf(ARYLEN(msg), "all leaves");
		break;
	case ROUTE_ONE:
		str_bprintf(ARYLEN(msg), "%s %s",
			node_type(dest->ur.u_node), node_addr(dest->ur.u_node));
		break;
	case ROUTE_ALL_BUT_ONE:
		str_bprintf(ARYLEN(msg), "all %sbut %s",
			dest->duplicate ? "ultras " : "",	/* Won't be sent to leaves */
			host_addr_to_string(origin_addr));
		break;
	case ROUTE_MULTI:
		{
			int count = pslist_length(dest->ur.u_nodes);
			str_bprintf(ARYLEN(msg), "selected %u node%s",
				count, plural(count));
		}
		break;
	default:
		str_bprintf(ARYLEN(msg), "** BUG ** UNKNOWN ROUTE");
		break;
	}

	return msg;
}

/**
 * Emit route_log message.
 */
static void
routing_log_flush(struct route_log *route_log)
{
	if (!GNET_PROPERTY(log_gnutella_routing))
		return;

	g_debug("ROUTE %-21s %s %s %3d/%3d: [%c%c] %s%s-> %s",
		route_log->local ? "OURSELVES"
			: host_addr_port_to_string(route_log->addr, route_log->port),
		debug_msg[route_log->function], guid_hex_str(&route_log->muid),
		route_log->hops, route_log->ttl,
		route_log->handle ? (route_log->dest.duplicate ? 'h' : 'H') : ' ',
		route_log->new ? 'N' : ' ',
		route_log->extra, route_log->extra[0] == '\0' ? "" : " ",
		route_string(&route_log->dest, route_log->addr, route_log->routing));
}

/**
 * Mangle OOB query MUID by zeroing the parts of the MUID where the IP:port
 * are recorded.
 *
 * @return copy of mangled MUID as pointer to static data.
 */
static const struct guid *
route_mangled_oob_muid(const struct guid *muid)
{
	static struct guid mangled;

	memcpy(&mangled.v[4], &muid->v[4], 9);	/* Clear IP address (bytes 0-3) */
	mangled.v[15] = muid->v[15];			/* Clear port (bytes 13-14) */

	return &mangled;
}

/**
 * Fetch the routing_data field of the node.
 */
static struct route_data *
get_routing_data(void *n)
{
	g_assert(n != NULL);

	switch (((struct node_magic *) n)->magic) {
	case NODE_MAGIC:
		{
			gnutella_node_t *gn = n;
			struct routing_udp_node *un;

			if (!NODE_IS_UDP(gn))
				return gn->routing_data;

			/*
			 * Since we have to get at the routing data of an UDP node, we
			 * need to fetch that of the corresponding "routing_udp_node",
			 * creating it if it does not exist.
			 */

			un = route_get_udp(gn);
			return un->routing_data;
		}
	case NODE_UDP_MAGIC:
		return ((struct routing_udp_node *) n)->routing_data;
	}
	g_assert_not_reached();
}

static struct route_data **
route_data_pointer(void *node, void **route_node)
{
	g_assert(node != NULL);

	switch (((struct node_magic *) node)->magic) {
	case NODE_MAGIC:
		{
			gnutella_node_t *gn = node;
			struct routing_udp_node *un;

			if (!NODE_IS_UDP(gn)) {
				if (route_node != NULL)
					*route_node = gn;
				return &gn->routing_data;
			}

			/*
			 * There is not routing data ever created for the UDP node.
			 * We need to fetch the corresponding "routing_udp_node" instead.
			 */

			un = route_get_udp(gn);
			if (route_node != NULL)
				*route_node = un;
			return &un->routing_data;
		}
	case NODE_UDP_MAGIC:
		if (route_node != NULL)
			*route_node = node;
		return &((struct routing_udp_node *) node)->routing_data;
	}
	g_assert_not_reached();
}

/**
 * If a node doesn't currently have routing data attached, this
 * creates and attaches some.
 *
 * @return created routing data structure.
 */
static struct route_data *
init_routing_data(gnutella_node_t *node)
{
	struct route_data *route;
	struct route_data **route_ptr;
	void *route_node;

	route_ptr = route_data_pointer(node, &route_node);

	/*
	 * Wow, this node hasn't sent any messages before.
	 * Allocate and link some routing data to it
	 */

	WALLOC(route);
	route->node = route_node;
	route->saved_messages = 0;

	g_assert(NULL == *route_ptr);

	return *route_ptr = route;
}

/**
 * Make sure slot belongs to specified chunk index.
 */
static void
slot_check(struct message * const * const slot, unsigned chunk_idx)
{
	const void *chunk_base;
	const void *chunk_end;

	g_assert(uint_is_non_negative(chunk_idx));
	g_assert(chunk_idx < MAX_CHUNKS);
	g_assert(chunk_idx < routing.nchunks);

	chunk_base = routing.chunks[chunk_idx];
	chunk_end = const_ptr_add_offset(chunk_base, CHUNK_MESSAGES * sizeof *slot);

	g_assert(ptr_cmp(slot, chunk_base) >= 0);
	g_assert(ptr_cmp(slot, chunk_end) < 0);
}

/**
 * Asserts that a message entry is consistent and belongs to the correct chunk.
 */
static void
message_check(const struct message * const m, unsigned chunk_idx)
{
	g_assert(m != NULL);
	slot_check(m->slot, chunk_idx);
	g_assert(chunk_idx == m->chunk_idx);
}

/**
 * Asserts that a message entry is consistent and belongs to the correct chunk.
 *
 * The "chunk" parameter points to the old chunk address and is used to
 * properly validate the m->slot value (before our caller can update it
 * to reflect the new chunk location).
 */
static void
message_check_chunk(const struct message * const m, unsigned chunk_idx,
	struct message * const *chunk)
{
	const void *chunk_end;

	g_assert(m != NULL);
	g_assert(chunk_idx == m->chunk_idx);

	/*
	 * Expand a variant of slot_check() since routing.chunks[chunk_idx]
	 * has been re-allocated and the old chunk address is given.
	 */

	g_assert(uint_is_non_negative(chunk_idx));
	g_assert(chunk_idx < MAX_CHUNKS);
	g_assert(chunk_idx < routing.nchunks);

	chunk_end = const_ptr_add_offset(chunk, CHUNK_MESSAGES * sizeof m);

	g_assert(ptr_cmp(m->slot, chunk) >= 0);
	g_assert(ptr_cmp(m->slot, chunk_end) < 0);
}

/**
 * Clean already allocated entry.
 */
static void
clean_entry(struct message *entry)
{
	g_assert(entry != NULL);

	hset_remove(routing.messages_hashed, entry);

	if (entry->routes != NULL)
		free_route_list(entry);

	g_assert(entry->ttls == NULL);		/* Cleaned by free_route_list() */
	g_assert(entry->routes == NULL);	/* Idem */

	entry->ttl = 0;
}

/**
 * Prepare entry, cleaning any old value we can find at the referenced slot.
 * We try to avoid re-allocating something if we can.
 *
 * @return message entry to use
 */
static struct message *
prepare_entry(struct message **entryp, unsigned chunk_idx)
{
	struct message *entry = *entryp;

	STATIC_ASSERT(MAX_CHUNKS <= MAX_INT_VAL(uint8));

	g_assert(uint_is_non_negative(chunk_idx));
	g_assert(chunk_idx < MAX_CHUNKS);
	slot_check(entryp, chunk_idx);

	if (entry == NULL) {
		WALLOC0(entry);
		*entryp = entry;
		entry->slot = entryp;
		entry->chunk_idx = chunk_idx;	/* 8-bit value, must fit */
		routing.count++;
		gnet_stats_inc_general(GNR_ROUTING_TABLE_COUNT);
		goto done;
	}

	/*
	 * We cycled over the table, remove the message at the slot we're
	 * going to supersede.  We don't need to allocate anything, we'll
	 * reuse the old structure, which will be rehashed after being updated.
	 */

	clean_entry(entry);

	/*
	 * Attempt to move the object around if it can help compacting.
	 */

	{
		struct message *nentry = WMOVE(entry);

		if (nentry != entry)
			entry = *entryp = nentry;
	}

done:
	g_assert(entryp == entry->slot);
	message_check(entry, chunk_idx);

	return entry;
}

/**
 * Attempt to reallocate an already allocated chunk to see if the VMM layer
 * can relocate a fragment.
 */
static struct message **
routing_chunk_move(struct message **chunk, unsigned chunk_idx)
{
	struct message **nchunk;
	struct message **p;
	unsigned i;

	g_assert(chunk != NULL);
	g_assert(uint_is_non_negative(chunk_idx));
	g_assert(chunk_idx < MAX_CHUNKS);
	g_assert(chunk == routing.chunks[chunk_idx]);

	nchunk = hrealloc(chunk, CHUNK_MESSAGES * sizeof(struct message *));
	if (nchunk == chunk)
		return chunk;

	/*
	 * VMM layer chose to relocate the chunk, update all the entries.
	 */

	if (GNET_PROPERTY(routing_debug)) {
		g_debug("RT moving chunk #%u from %p to %p",
			chunk_idx, (void *) chunk, (void *) nchunk);
	}

	for (p = &nchunk[0], i = 0; i < CHUNK_MESSAGES; i++, p++) {
		struct message *m = *p;

		if (m != NULL) {
			message_check_chunk(m, chunk_idx, chunk);
			m->slot = p;
		}
	}

	return routing.chunks[chunk_idx] = nchunk;
}

/**
 * Try to move the chunks we have, since the lowest indices
 * (which are going to be the more permanent chunks) will be
 * better hosted in the early VM space, freeing up the upper
 * VM space for more volatile data and possibly defragmenting.
 */
static void
routing_chunk_move_attempt(void)
{
	size_t i;

	for (i = 0; i < routing.nchunks; i++) {
		routing.chunks[i] = routing_chunk_move(routing.chunks[i], i);
	}
}

/**
 * Advance slot index so that a call to get_next_slot() will return the
 * next available slot.
 */
static void
advance_slot(void)
{
	/*
	 * It's OK to go beyond the last allocated chunk (a new chunk will
	 * be allocated next time) unless we already reached the last chunk.
	 */

	routing.next_idx++;

	if (CHUNK_INDEX(routing.next_idx) >= MAX_CHUNKS)
		routing.next_idx = 0;		/* Will force cycling over next time */
}

/**
 * Clear routing table, starting with specified chunk index.
 *
 * @param idx	the index of the first chunk to clear
 */
static void
routing_clear(unsigned idx)
{
	size_t i;

	for (i = idx; i < routing.nchunks; i++) {
		struct message **rchunk = routing.chunks[i];
		size_t j;

		if (GNET_PROPERTY(routing_debug)) {
			g_debug("RT freeing chunk #%zu at %p, now holds %d / %d",
				i, (void *) rchunk, routing.count, routing.capacity);
		}

		for (j = 0; j < CHUNK_MESSAGES; j++) {
			struct message *m = rchunk[j];

			if (m != NULL) {
				message_check(m, i);
				g_assert(m->slot == &rchunk[j]);
				clean_entry(m);
				WFREE(m);
				routing.count--;
			}
		}

		routing.capacity -= CHUNK_MESSAGES;
		HFREE_NULL(routing.chunks[i]);
	}

	routing.nchunks = idx;
	gnet_stats_set_general(GNR_ROUTING_TABLE_CHUNKS, routing.nchunks);
	gnet_stats_set_general(GNR_ROUTING_TABLE_CAPACITY, routing.capacity);
	gnet_stats_set_general(GNR_ROUTING_TABLE_COUNT, routing.count);

	g_assert(uint_is_non_negative(routing.nchunks));

	/*
	 * After freeing chunks, we may be able to move around some of the
	 * remaining ones.
	 */

	routing_chunk_move_attempt();
}

/**
 * Clear the whole routing table.
 */
void
routing_clear_all(void)
{
	if (GNET_PROPERTY(routing_debug)) {
		g_debug("RT clearing whole table (holds %d / %d)",
			routing.capacity, routing.count);
	}

	routing_clear(0);
	routing.next_idx = 0;
	routing.last_rotation = tm_time();
	hset_clear(routing.messages_hashed);	/* Paranoid */
}

/**
 * Fetch next routing table slot, a pointer to a routing entry.
 *
 * When `advance' is FALSE, the slot is allocated as usual but there is
 * no increment of the slot index for next time.  This allows trial allocation
 * to see where the message will be allocated.  If the slot is kept, the
 * caller must call advance_slot().
 *
 * When `advance' is TRUE, the slot is allocated and the slot index is
 * incremented immediately.
 *
 * @param advance		whether to advance the slot index
 * @param cidx			if non-NULL, filled with the chunk index where slot is
 *
 * @return the address of the allocated slot.
 */
static struct message **
get_next_slot(bool advance, unsigned *cidx)
{
	unsigned idx;
	unsigned chunk_idx;
	struct message **chunk;
	struct message **slot = NULL;
	time_t now = tm_time();
	time_delta_t elapsed = delta_time(now, routing.last_rotation);

	idx = routing.next_idx;
	chunk_idx = CHUNK_INDEX(idx);

	g_assert(UNSIGNED(chunk_idx) < MAX_CHUNKS);

	chunk = routing.chunks[chunk_idx];

	/*
	 * If we get back here with a next index of zero and the chunk is
	 * allocated, it means we've naturally cycled over.  There is nothing
	 * to free up (or we would discard the whole table).
	 */

	if G_UNLIKELY(0 == idx && NULL != chunk) {
		if (GNET_PROPERTY(routing_debug)) {
			g_debug("RT cycled naturally over table, elapsed=%u, holds %d / %d",
				(unsigned) elapsed, routing.count, routing.capacity);
		}
		routing.last_rotation = now;	/* Just cycled over */
		elapsed = 0;
	}

	/*
	 * If we've taken more than TABLE_MIN_CYCLE seconds since the last
	 * rotation and reach the start of an allocated chunk, it means we
	 * have more chunks than we need.  Discard all remaining chunks before
	 * rotating.
	 */

	if G_UNLIKELY(elapsed > TABLE_MIN_CYCLE) {
		/*
		 * 0 != ENTRY_INDEX(idx): means we're not at the start of a chunk.
		 * chunk == NULL: means we've reached an empty chunk, nothing to free.
		 */

		if G_UNLIKELY(chunk != NULL && 0 == ENTRY_INDEX(idx)) {
			routing_clear(chunk_idx);
			chunk = NULL;
		}
	}

	if (chunk == NULL) {

		g_assert(idx >= UNSIGNED(routing.capacity));

		/*
		 * Chunk does not exist yet, determine whether we should create
		 * it or recycle the table by going back to the start.
		 */

		if (idx > 0 && elapsed > TABLE_MIN_CYCLE) {
			if (GNET_PROPERTY(routing_debug)) {
				g_debug("RT cycling over table, elapsed=%u, holds %d / %d",
					(unsigned) elapsed, routing.count, routing.capacity);
			}

			chunk_idx = 0;
			idx = routing.next_idx = 0;
			routing.last_rotation = now;
			slot = routing.chunks[0];
		} else {
			/*
			 * Allocate new chunk, expanding the capacity of the table.
			 */

			g_assert(idx == 0 || chunk_idx > 0);
			g_assert(chunk_idx == routing.nchunks);

			routing_chunk_move_attempt();		/* Compact before allocating */

			routing.nchunks++;
			routing.capacity += CHUNK_MESSAGES;
			routing.chunks[chunk_idx] =
				halloc0(CHUNK_MESSAGES * sizeof(struct message *));

			gnet_stats_inc_general(GNR_ROUTING_TABLE_CHUNKS);
			gnet_stats_count_general(GNR_ROUTING_TABLE_CAPACITY,
				CHUNK_MESSAGES);

			if (GNET_PROPERTY(routing_debug)) {
				g_debug("RT created new chunk #%d at %p, now holds %d / %d",
					chunk_idx, (void *) routing.chunks[chunk_idx],
					routing.count, routing.capacity);
			}

			slot = routing.chunks[chunk_idx];	/* First slot in new chunk */
		}
	} else {
		unsigned entry_idx = ENTRY_INDEX(idx);

		/*
		 * Each time we move to a new chunk, see whether we can move some
		 * of the existing ones around to compact the VM space.
		 */

		if (0 == entry_idx) {
			routing_chunk_move_attempt();
			chunk = routing.chunks[chunk_idx];	/* In case it moved */
		}

		/*
		 * If we went back to the first index without allocating a chunk,
		 * it means we finally cycled over the table, in a forced way,
		 * because we have already allocated the maximum amount of chunks.
		 */

		if (0 == idx && MAX_CHUNKS == routing.nchunks) {
			if (GNET_PROPERTY(routing_debug)) {
				g_warning("RT cycling over FORCED, elapsed=%u, holds %d / %d",
					(unsigned) elapsed, routing.count, routing.capacity);
			}
			routing.last_rotation = now;
		}

		slot = &chunk[entry_idx];
	}

	g_assert(slot != NULL);
	g_assert(idx == UNSIGNED(routing.next_idx));
	g_assert(idx < UNSIGNED(routing.capacity));
	g_assert(routing.nchunks <= MAX_CHUNKS);

	if (advance)
		advance_slot();

	if (cidx != NULL)
		*cidx = chunk_idx;

	slot_check(slot, chunk_idx);

	return slot;
}

/**
 * Fetch next routing table entry to be able to store routing information.
 */
static struct message *
get_next_entry(void)
{
	struct message **slot;
	unsigned chunk_idx;

	slot = get_next_slot(TRUE, &chunk_idx);
	return prepare_entry(slot, chunk_idx);
}

/**
 * When a precious route (for query hit or push) is used, revitalize the
 * entry by moving it to the end of the "message_array[]", thereby making
 * it unlikely that it expires soon.
 *
 * @return the new location of the revitalized entry
 */
static void
revitalize_entry(struct message *entry, bool force)
{
	struct message **relocated;
	struct message *prev;
	unsigned chunk_idx;

	/*
	 * Leaves don't route anything, so we usually don't revitalize their
	 * entries.  The only exception is when it makes use of the recorded
	 * PUSH routes, i.e. when it initiates a PUSH ("force" will be TRUE).
	 */

	if (!force && settings_is_leaf())
		return;

	/*
	 * Relocate at the end of the table, preventing early expiration.
	 */

	relocated = get_next_slot(FALSE, &chunk_idx);

	/*
	 * If slot is allocated in the same chunk, there's no need to revitalize
	 * since entries in the same chunk will roughly have the same lifetime.
	 */

	if (chunk_idx == entry->chunk_idx)			/* Same chunk being used */
		return;

	/*
	 * Clean and reclaim new slot content, if present.
	 */

	advance_slot();							/* Keeping the slot */
	prev = *relocated;

	if (prev != NULL) {
		message_check(prev, chunk_idx);
		g_assert(prev->slot == relocated);
		clean_entry(prev);
		WFREE(prev);
		routing.count--;
		gnet_stats_dec_general(GNR_ROUTING_TABLE_COUNT);
	}

	/*
	 * Move `entry' to this new slot.
	 */

	*relocated = entry;
	*(entry->slot) = NULL;					/* Old slot "freed" */
	entry->slot = relocated;				/* Entry now at new slot */
	entry->chunk_idx = chunk_idx;			/* Entry moved to new chunk */

	message_check(entry, chunk_idx);
}

/**
 * Did node send the message?
 */
static bool
route_node_sent_message(gnutella_node_t *n, struct message *m)
{
	struct route_data *route;
	pslist_t *sl;

	if (n == fake_node)
		route = &fake_route;
	else
		route = get_routing_data(n);

	/*
	 * If we've never routed a message from this person before,
	 * it can't be a duplicate.
	 */

	if (route == NULL)
		return FALSE;

	PSLIST_FOREACH(m->routes, sl) {
		if (route == sl->data)
			return TRUE;
	}

	return FALSE;
}

/**
 * For a broadcasted message which is known to have already been sent,
 * check whether the TTL of the message previously seen is less than the
 * one we just got.  Update the highest TTL value if needed.
 *
 * @return FALSE if the message is really a duplicate (current TTL not greater)
 * and the node should not have broadcasted this message again.
 */
static bool
route_node_ttl_higher(gnutella_node_t *n, struct message *m, uint8 ttl)
{
	pslist_t *l;
	int i;
	struct route_data *route;

	g_assert(n != fake_node);

	/*
	 * GTA_MSG_G2_SEARCH is a fake function used to process G2 queries.
	 *
	 * Since we run as a leaf node, and we fake the TTL, it does not make
	 * sense to check whether this "duplicate" query comes with a higher TTL.
	 * It's really a duplicate message.
	 */

	if (GTA_MSG_G2_SEARCH == m->function)
		return FALSE;		/* As a G2 leaf, we do not care, it's a dup */

	g_assert(m->ttls != NULL);
	g_assert(
		m->function == GTA_MSG_PUSH_REQUEST || m->function == GTA_MSG_SEARCH);

	route = get_routing_data(n);

	g_assert(route != NULL);

	for (l = m->routes, i = 0; l; l = pslist_next(l), i++) {
		if (route == l->data) {
			pslist_t *t = pslist_nth(m->ttls, i);
			uint8 old_ttl;

			g_assert(t != NULL);
			old_ttl = GPOINTER_TO_INT(t->data);
			if (old_ttl >= ttl)
				return FALSE;

			t->data = GUINT_TO_POINTER((uint) ttl);
			return TRUE;
		}
	}

	g_error("route not found -- message was supposed to be a duplicate");
	return FALSE;
}

/**
 * compares two message structures
 */
static int
message_compare_func(const void *p, const void *q)
{
	const struct message *a = p, *b = q;

	return a->function == b->function && guid_eq(&a->muid, &b->muid);
}

/**
 * Hashes message structures for storage in a hash table.
 */
static uint
message_hash_func(const void *key)
{
	const struct message *msg = key;

	return integer_hash_fast(msg->function) ^
		universal_hash(&msg->muid, GUID_RAW_SIZE);
}

/**
 * Alternate hashing of message structures for storage in a hash table.
 */
static uint
message_hash_func2(const void *key)
{
	const struct message *msg = key;

	return integer_hash2(msg->function) ^ guid_hash(&msg->muid);
}

/**
 * Reset this node's GUID.
 */
void
gnet_reset_guid(void)
{
	gnet_prop_set_storage(PROP_SERVENT_GUID, VARLEN(blank_guid));
}

/**
 * Init function.
 */
void G_COLD
routing_init(void)
{
    struct guid guid_buf;
	uint32 i;

	/*
	 * Make sure it segfaults if we try to access it, but it must be
	 * distinct from NULL.
	 */
	fake_node = deconstify_pointer(vmm_trap_page());
	fake_route.saved_messages = 0;
	fake_route.node = fake_node;

	/*
	 * Initialize the banned GUID hash.
	 */

	ht_banned_push = hset_create(HASH_KEY_FIXED, GUID_RAW_SIZE);

	for (i = 0; i < N_ITEMS(banned_push); i++) {
		struct guid guid;
		const char *hex = banned_push[i];

		g_assert(vstrlen(hex) == 2 * sizeof guid);

		(void) hex_to_guid(hex, &guid);
		hset_insert(ht_banned_push, atom_guid_get(&guid));
	}

	/*
	 * If they did not configure a sticky GUID, or if the GUID ia blank,
	 * configure a new one.
	 *
	 * In the advent of an unclean restart (i.e. after a crash), we ignore
	 * the "sticky_guid" property though since this is merely the resuming
	 * of the previously interrupted run.
	 */

	gnet_prop_get_storage(PROP_SERVENT_GUID, VARLEN(guid_buf));

	if (
		guid_is_blank(&guid_buf) ||
		(!GNET_PROPERTY(sticky_guid) && GNET_PROPERTY(clean_restart))
	) {
		do {
			guid_random_muid(&guid_buf);
			/*
			 * If by extraordinary, we have generated a banned GUID, retry.
			 */
		} while (is_banned_push(&guid_buf));

		gnet_prop_set_storage(PROP_SERVENT_GUID, VARLEN(guid_buf));
		g_assert(guid_is_gtkg(&guid_buf, NULL, NULL, NULL));
	}

	/*
	 * Initialize message type array for routing logs.
	 */

	for (i = 0; i < 256; i++) {
		const char *s;

		s = "UNKN ";
		switch ((enum gta_msg) i) {
		case GTA_MSG_INIT:           s = "Ping "; break;
		case GTA_MSG_INIT_RESPONSE:  s = "Pong "; break;
		case GTA_MSG_SEARCH:         s = "Query"; break;
		case GTA_MSG_SEARCH_RESULTS: s = "Q-Hit"; break;
		case GTA_MSG_PUSH_REQUEST:   s = "Push "; break;
		case GTA_MSG_RUDP:   		 s = "RUDP "; break;
		case GTA_MSG_VENDOR:         s = "Vndor"; break;
		case GTA_MSG_STANDARD:       s = "Vstd "; break;
		case GTA_MSG_QRP:            s = "QRP  "; break;
		case GTA_MSG_HSEP_DATA:      s = "HSEP "; break;
		case GTA_MSG_BYE:      		 s = "Bye  "; break;
		case GTA_MSG_DHT:      		 s = "DHT  "; break;
		case GTA_MSG_G2_SEARCH: 	 s = "Q2  "; break;
		}
		debug_msg[i] = s;
	}

	/*
	 * Should be around for life of program, so should *never*
	 * need to be deallocated
	 */

	routing.messages_hashed = hset_create_any(message_hash_func,
		message_hash_func2, message_compare_func);
	routing.last_rotation = tm_time();

	/*
	 * Push proxification and starving GUIDs.
	 */

	ht_proxyfied = htable_create(HASH_KEY_FIXED, GUID_RAW_SIZE);
	ht_starving_guid = htable_create(HASH_KEY_FIXED, GUID_RAW_SIZE);

	/*
	 * GUESS query hit routing.
	 */

	at_udp_routes = aging_make(ROUTE_UDP_LIFETIME,
		route_udp_node_hash, route_udp_node_eq, route_udp_kvfree);
}

/**
 * Generate a new muid and put it in a message header.
 */
void
message_set_muid(gnutella_header_t *header, uint8 function)
{
	switch (function) {
	case GTA_MSG_PUSH_REQUEST:
	case GTA_MSG_BYE:
	case GTA_MSG_QRP:
	case GTA_MSG_HSEP_DATA:
	case GTA_MSG_STANDARD:
	case GTA_MSG_VENDOR:		/* When a non-blank random GUID is needed */
		guid_random_muid(gnutella_header_muid(header));
		return;
	case GTA_MSG_INIT:
		guid_ping_muid(gnutella_header_muid(header));
		return;
	case GTA_MSG_RUDP:
		g_assert_not_reached();
	}
	g_error("unexpected message type %d", function);
}

/**
 * The route references one less message.
 *
 * If the amount of messages referenced reaches 0 and the associated node
 * was removed, free the route structure.
 */
static void
remove_one_message_reference(struct route_data *rd)
{
	g_assert(rd);

	if (rd->node != fake_node) {
		g_assert(rd != &fake_route);
		g_assert(rd->saved_messages > 0);

		rd->saved_messages--;

		/*
		 * If we have no more messages from this node, and our
		 *  node has already died, wipe its routing data
		 */

		if (rd->node == NULL && rd->saved_messages == 0)
			WFREE(rd);
	} else
		g_assert(rd == &fake_route);
}

/**
 * Dispose of route list in message.
 */
static void
free_route_list(struct message *m)
{
	pslist_t *sl;

	g_assert(m);

	PSLIST_FOREACH(m->routes, sl) {
		remove_one_message_reference(sl->data);
	}

	pslist_free_null(&m->routes);

	/*
	 * If the message was a broadcasted one, we kept track of the TTL of
	 * each message along the route.  This needs to be freed as well.
	 */

	pslist_free_null(&m->ttls);	/* Data are ints, nothing to free */
}

/**
 * Erase a node from the routing tables.
 *
 * Node can be either a gnutella_node or a routing_udp_node.
 */
void
routing_node_remove(void *node)
{
	struct route_data *route = get_routing_data(node);
	struct route_data **rptr;

	g_assert(route != NULL);
	g_assert(route->node == node);

	rptr = route_data_pointer(node, NULL);
 	*rptr = NULL;

	/*
	 * Make sure that any future references to this routing
	 * data know that we are not connected to a node.
	 */

	route->node = NULL;

	/*
	 * If no messages remain, we have no reason to keep the
	 * route_data around any more.
	 */

	if (route->saved_messages == 0)
		WFREE(route);
}

/**
 * Adds a new message in the routing tables.
 *
 * @param muid is the message MUID
 * @param function is the message type
 * @param node is the node from which we got the message, NULL if we are the
 * node emitting it.
 */
void
message_add(const struct guid *muid, uint8 function,
	gnutella_node_t *node)
{
	struct route_data *route;
	struct message *entry;
	struct message *m;
	bool found;

	found = find_message(muid, function, &m);

	if (!node) {
		struct route_log route_log;
		bool already_recorded = FALSE;

		routing_log_init(&route_log, NULL, muid, function, 0,
			GNET_PROPERTY(my_ttl));

		if (found) {
			/*
			 * It is possible that we insert the message in the routing table,
			 * then it gets "garbage collected" through a cycling, and then
			 * we receive our own message back from the network, at which
			 * time it is re-inserted into the table.  Therefore, despite our
			 * re-issuing of our own (search) message, there might not
			 * actually be any entry for us.
			 *		--RAM, 21/02/2002
			 */

			if (route_node_sent_message(fake_node, m)) {
				routing_log_extra(&route_log, "already sent");
				already_recorded = TRUE;
			} else
				routing_log_extra(&route_log, "forgot we sent it");
		}

		route = &fake_route;
		node = fake_node;		/* We are the sender of the message */

		routing_log_flush(&route_log);

		if (already_recorded)
			return;
	} else {
		route = get_routing_data(node);
		if (NULL == route)
			route = init_routing_data(node);
	}

	if (found)			/* Dup message forwarded due to higher TTL */
		entry = m;		/* Reuse existing entry */
	else {
		entry = get_next_entry();
		g_assert(entry->routes == NULL);

		/* fill in that storage space */
		entry->muid = *muid;
		entry->function = function;
	}

	g_assert(route != NULL);

	/*
	 * We have to account for the reception of a duplicate message from
	 * the same node, but with a higher TTL. Hence the test for
	 * route_node_sent_message() if the message was already seen.
	 *		--RAM, 2004-08-28
	 */

	if (!found || !route_node_sent_message(node, m)) {
		uint ttl;

		route->saved_messages++;
		entry->routes = pslist_append(entry->routes, route);

		/*
		 * If message is typically broadcasted, also record the TTL of
		 * that route, since a node is allowed to resend us a message
		 * if it comes with a higher TTL than previously seen.
		 *		--RAM, 2005-10-02
		 */

		ttl = node == fake_node
				? GNET_PROPERTY(my_ttl)
				: gnutella_header_get_ttl(&node->header);

		switch (function) {
		case GTA_MSG_PUSH_REQUEST:
		case GTA_MSG_SEARCH:
			entry->ttls = pslist_append(entry->ttls, GUINT_TO_POINTER(ttl));
			break;
		}
	}

	if (found)
		return;

	/*
	 * New message entry.
	 */

	if (node != fake_node)
		entry->ttl = gnutella_header_get_ttl(&node->header);
	else
		entry->ttl = GNET_PROPERTY(my_ttl);

	/* insert the new message into the hash table */
	hset_insert(routing.messages_hashed, entry);
}

/**
 * Remove references to routing data that is no longer associated with
 * a node, within the route list of the message.
 */
static void
purge_dangling_references(struct message *m)
{
	pslist_t *sl;
	pslist_t *t;

	for (sl = m->routes, t = m->ttls; sl; /* empty */) {
		struct route_data *rd = sl->data;

		if (rd->node == NULL) {
			pslist_t *next = pslist_next(sl);
			m->routes = pslist_remove_link(m->routes, sl);
			remove_one_message_reference(rd);
			pslist_free_1(sl);
			sl = next;

			if (t) {
				next = pslist_next(t);
				m->ttls = pslist_remove_link(m->ttls, t);
				pslist_free_1(t);
				t = next;
			}
		} else {
			sl = pslist_next(sl);
			if (t)
				t = pslist_next(t);
		}
	}
}

/**
 * Forget that node sent given message.
 *
 * @param muid is the message MUID
 * @param function is the message type
 * @param node is the node from which we got the message
 */
void
message_forget(const struct guid *muid, uint8 function, gnutella_node_t *node)
{
	bool found;
	struct message *m;
	pslist_t *sl;
	pslist_t *t;
	struct route_data *route;

	g_assert(muid != NULL);
	node_check(node);

	found = find_message(muid, function, &m);
	g_return_unless(found);
	g_assert(m != NULL);

	route = get_routing_data(node);
	g_return_unless(route != NULL);

	for (
		sl = m->routes, t = m->ttls;
		sl != NULL;
		sl = pslist_next(sl), t = pslist_next(t)
	) {
		struct route_data *rd = sl->data;

		if (route == rd) {
			m->routes = pslist_remove_link(m->routes, sl);
			if (t != NULL)
				m->ttls = pslist_remove_link(m->ttls, t);
			remove_one_message_reference(rd);
			break;
		}
	}
}

/**
 * Look for a particular message in the routing tables.
 *
 * If none of the nodes that sent us the message are still present, then
 * m->routes will be NULL.
 *
 * @return TRUE if the message is found.
 */
static bool
find_message(const struct guid *muid, uint8 function, struct message **m)
{
	struct message dummy;
	const void *orig_key;

	dummy.muid = *muid;
	dummy.function = function;

	if (hset_contains_extended(routing.messages_hashed, &dummy, &orig_key)) {
		struct message *msg = deconstify_pointer(orig_key);

		/* wipe out dead references to old nodes */
		purge_dangling_references(msg);

		*m = msg;
		return TRUE;		/* Message was seen */
	} else {
		*m = NULL;
		return FALSE;		/* We don't remember anything about this message */
	}
}

/**
 * Ensure sane hop count.
 *
 * If the hop count has reached 255, drop the message and count it as bad.
 *
 * @return TRUE if OK, FALSE if message should not be forwarded.
 */
static bool
check_hops(struct route_log *route_log, gnutella_node_t *sender)
{
	/*
	 * Can't forward a message with 255 hops: we can't increase the
	 * counter.  This should never happen, even for a routed message
	 * due to network constraints.
	 *		--RAM, 04/07/2002
	 */

	if (gnutella_header_get_hops(&sender->header) == 255) {
		routing_log_extra(route_log, "max hop count reached");
		gnet_stats_count_dropped(sender, MSG_DROP_MAX_HOP_COUNT);
		sender->n_bad++;
		if (GNET_PROPERTY(routing_debug) || GNET_PROPERTY(log_bad_gnutella))
			gmsg_log_bad(sender, "message with HOPS=255!");
		return FALSE;
	}

	return TRUE;
}

/**
 * Ensure sane TTL value.
 *
 * If the TTL value reached 0, drop the message and count it as bad.
 *
 * @return TRUE if OK, FALSE if message should not be forwarded.
 */
static bool
check_ttl(struct route_log *route_log, gnutella_node_t *sender)
{
	if (gnutella_header_get_ttl(&sender->header) == 0) {
		routing_log_extra(route_log, "TTL was 0");
		if (!NODE_IS_UDP(sender)) {		/* Be lenient if coming from UDP */
			node_sent_ttl0(sender);
			return FALSE;	/* Don't route */
		}
	}

	return TRUE;
}

/**
 * Ensure sane hops and TTL counts.
 *
 * @return TRUE if we can continue, FALSE if we should not forward the
 * message.
 */
static bool
check_hops_ttl(struct route_log *route_log, gnutella_node_t *sender)
{
	return check_hops(route_log, sender) && check_ttl(route_log, sender);
}

/**
 * Calculates the TTL that should be used when the message is forwarded.
 *
 * @returns the TTL used when forwarding the message.
 */
static int
route_max_forward_ttl(const gnutella_node_t *sender)
{
	int ttl_forward = gnutella_header_get_ttl(&sender->header);

	if (
		(uint) gnutella_header_get_hops(&sender->header) +
			gnutella_header_get_ttl(&sender->header)
				> GNET_PROPERTY(max_ttl)
	) {
		int ttl_max;

		/* Trim down */
		ttl_max = GNET_PROPERTY(max_ttl);
		ttl_max -= gnutella_header_get_hops(&sender->header);
		ttl_max = MAX(ttl_max, 1);

		ttl_forward = ttl_max;
	}

	return ttl_forward;
}

/**
 * Forwards message to one node if `target' is non-NULL, or to all nodes but
 * the sender otherwise.  If we kick the node, then *node is set to NULL.
 * The message is not physically sent yet, but the `dest' structure is filled
 * with proper routing information.
 *
 * `routes' is normally NULL unless we're forwarding a PUSH request.  In that
 * case, it must be sent to the whole list of routes we have, and `target' will
 * be NULL.
 *
 * @attention
 * NB: we're just *recording* routing information for the message into `dest',
 * we are not physically forwarding the message on the wire.
 *
 * @returns whether we should handle the message after routing.
 */
static bool
forward_message(
	struct route_log *route_log,
	gnutella_node_t **node,
	gnutella_node_t *target, struct route_dest *dest, pslist_t *routes)
{
	gnutella_node_t *sender = *node;

	g_assert(routes == NULL || target == NULL);
	g_assert(settings_is_ultra());

	/* Drop messages that would travel way too many nodes --RAM */
	if (
		(uint32) gnutella_header_get_ttl(&sender->header) +
			gnutella_header_get_hops(&sender->header)
				> GNET_PROPERTY(hard_ttl_limit)
	) {
		routing_log_extra(route_log, "hard TTL limit reached");

		/*
		 * When close neighboors of that node send messages we drop
		 * that way, they may try to flood the network.	Disconnect
		 * after too many offenses, which should have given the
		 * relaying node ample time to kick the offender out,
		 * according to our standards.
		 *		--RAM, 08/09/2001
		 *
		 * Don't kick if message is not a query, but simply a routed message.
		 *		--RAM, 2004-11-01
		 */

		sender->n_hard_ttl++;
        gnet_stats_count_dropped(sender, MSG_DROP_HARD_TTL_LIMIT);

		if (
			gnutella_header_get_function(&sender->header) == GTA_MSG_SEARCH &&
			gnutella_header_get_hops(&sender->header)
				<= GNET_PROPERTY(max_high_ttl_radius) &&
			sender->n_hard_ttl > GNET_PROPERTY(max_high_ttl_msg) &&
			!NODE_IS_UDP(sender)
		) {
			node_bye(sender, 403, "Relayed %d high TTL (>%d) messages",
				sender->n_hard_ttl, GNET_PROPERTY(max_high_ttl_msg));
			*node = NULL;
			return FALSE;
		}

		return TRUE;
	}

	if (!check_hops_ttl(route_log, sender))
		return TRUE;

	if (gnutella_header_get_ttl(&sender->header) == 1) {
		/* TTL expired, message stops here */
		routing_log_extra(route_log, "TTL expired");
		gnet_stats_count_expired(sender);
	} else {
		/*
		 * Forward message to all others nodes, or the the ones specified
		 * by the `routes' parameter if not NULL.
		 */

		if (routes != NULL) {
			pslist_t *l;
			pslist_t *nodes = NULL;
			int count = 0;

			g_assert(gnutella_header_get_function(&sender->header)
					== GTA_MSG_PUSH_REQUEST);

			PSLIST_FOREACH(routes, l) {
				struct route_data *rd = l->data;
				if (rd->node == sender)
					continue;

				nodes = pslist_prepend(nodes, rd->node);
				count++;
			}

			/*
			 * The `nodes' list will be freed by node_parse().
			 */

			if (count > 0) {
				dest->type = ROUTE_MULTI;
				dest->ur.u_nodes = nodes;

				/*
				 * If PUSH was coming from UDP and we're going to route it,
				 * make sure its TTL is reasonable, and reset its hop count
				 * to 0 as we're going to start real routing from here.
				 *		--RAM, 2012-11-02
				 */

				if (NODE_IS_UDP(sender)) {
					uint8 ttl = gnutella_header_get_ttl(&sender->header);
					uint8 hops = gnutella_header_get_hops(&sender->header);
					uint8 ttl_max;

					if (hops != 0) {
						gnutella_header_set_hops(&sender->header, 0);
						routing_log_extra(route_log, "hops %u => 0", hops);
					}
					ttl_max = MAX(ttl, GNET_PROPERTY(max_ttl));
					if (ttl < ttl_max) {
						gnutella_header_set_ttl(&sender->header, ttl_max);
						routing_log_extra(route_log, "TTL %u => %u",
							ttl, ttl_max);
					}
				}
			}

			if (count > 1)
				gnet_stats_inc_general(GNR_BROADCASTED_PUSHES);

		} else if (target != NULL) {
			dest->type = ROUTE_ONE;
			dest->ur.u_node = target;
		} else {
			/*
			 * This message is broadcasted, ensure its TTL is "reasonable".
			 * Trim down if excessively large.
			 * NB: Account for the fact that we haven't decremented it yet.
			 */

			if (
				(uint) gnutella_header_get_hops(&sender->header) +
					gnutella_header_get_ttl(&sender->header)
						> GNET_PROPERTY(max_ttl)
			) {
				int ttl_max = route_max_forward_ttl(sender);

				/* Trim down */

				gnutella_header_set_ttl(&sender->header, ttl_max);

				if (gnutella_header_get_ttl(&sender->header) == 1) {
					/* TTL expired, message stops here */
					routing_log_extra(route_log, "TTL forcefully expired");
					gnet_stats_count_expired(sender);
					return TRUE;
				} else
					routing_log_extra(route_log, "TTL trimmed down to %d ",
						gnutella_header_get_ttl(&sender->header));
			}

			dest->type = ROUTE_ALL_BUT_ONE;
			dest->ur.u_node = sender;
		}
	}

	return TRUE;
}

/**
 * Handle duplicate message.
 *
 * @param route_log	a structure recording to-be-logged information for debug
 * @param node		pointer to variable holding the sender of the message
 * @param m			the message, as already found in the routing table
 * @param oob		whether this a duplicate OOB query (spot with mangled MUID)
 *
 * @return whether we should route the message (a duplicate with a higher TTL).
 */
static bool
handle_duplicate(struct route_log *route_log, gnutella_node_t **node,
	struct message *m, bool oob)
{
	gnutella_node_t *sender = *node;
	bool forward = FALSE;
	int ttl_forward = route_max_forward_ttl(sender);

	node_check(sender);
	g_assert(m != NULL);

	/*
	 * This is a duplicated message, which we might drop.
	 *
	 * We don't drop queries/pushes that come to us with a higher TTL
	 * as we have previously seen.  In that case, we forward them but
	 * don't handle them, since this was done when we saw them the
	 * very first time.
	 *		--RAM, 2004-08-28
	 */

	if (oob)
		gnet_stats_inc_general(GNR_QUERY_OOB_PROXIED_DUPS);

	routing_log_extra(route_log, oob ? "dup OOB GUID" : "dup message");

	if (ttl_forward > m->ttl) {
		routing_log_extra(route_log, "higher TTL (%d>%u)", ttl_forward, m->ttl);

		gnet_stats_inc_general(GNR_DUPS_WITH_HIGHER_TTL);

		if (GNET_PROPERTY(log_dup_gnutella_higher_ttl)) {
			gmsg_log_duplicate(sender,
				"from %s: %shigher TTL (previous TTL was %u)",
				node_infostr(sender), oob ? "OOB, " : "", m->ttl);
		}

		m->ttl = ttl_forward;   /* Remember highest TTL */

		forward = TRUE;         /* Forward but don't handle */
	}

	if (!forward)
		gnet_stats_count_dropped(sender, MSG_DROP_DUPLICATE);

	/*
	 * Even if we decided to forward the message, we must continue
	 * to update the highest TTL seen for a given message along
	 * each route.
	 */

	if (m->routes && route_node_sent_message(sender, m)) {
		bool higher_ttl;

		/*
		 * The same node has sent us a message twice!
		 *
		 * Check whether we have a higher TTL this time, and update
		 * the highest TTL seen along this route.
		 */

		higher_ttl = route_node_ttl_higher(sender, m,
						gnutella_header_get_ttl(&sender->header));

		if (higher_ttl) {
			routing_log_extra(route_log, "same node");

			if (GNET_PROPERTY(log_dup_gnutella_higher_ttl)) {
				gmsg_log_duplicate(sender,
					"from %s: %ssame node, higher TTL (dups=%u)",
					node_infostr(sender), oob ? "OOB, " : "", sender->n_dups);
			}
		} else {
			routing_log_extra(route_log, "same node and no higher TTL");

			if (GNET_PROPERTY(log_dup_gnutella_same_node)) {
				gmsg_log_duplicate(sender,
					"from %s: %ssame node (dups=%u)",
					node_infostr(sender), oob ? "OOB, " : "", sender->n_dups);
			}
		}

		/*
		 * That is a really good reason to kick the offender
		 * But do so only if killing this node would not bring
		 * us too low in node count, and if they have sent enough
		 * dups to be sure it's not bad luck in MUID generation.
		 * Finally, check the ratio of dups on received messages,
		 * because a dup once in a while is nothing.
		 *		--RAM, 08/09/2001
		 *
		 * Don't count duplicates coming with a higher TTL, those are OK!
		 *		--RAM, 2005-10-02
		 */

		/* XXX max_dup_msg & max_dup_ratio XXX ***/

		if (
			!higher_ttl && !oob &&
			!NODE_IS_UDP(sender) &&
			sender->n_dups++ >= GNET_PROPERTY(min_dup_msg) &&
			connected_nodes() > MAX(2, GNET_PROPERTY(up_connections)) &&
			sender->n_dups >
				(uint16)(1.0 * GNET_PROPERTY(min_dup_ratio) / 10000.0
							* sender->received)
		) {
			node_mark_bad_vendor(sender);
			node_bye(sender, 401, "Sent %d dups (%.1f%% of RX)",
				sender->n_dups, sender->received ?
					100.0 * sender->n_dups / sender->received :
					0.0);
			*node = NULL;
		} else {
			if (GNET_PROPERTY(log_bad_gnutella))
				gmsg_log_bad(sender, "dup message from same node");
		}
	} else {
		if (m->routes == NULL) {
			routing_log_extra(route_log, "all routes lost");

			if (GNET_PROPERTY(log_dup_gnutella_other_node)) {
				gmsg_log_duplicate(sender,
					"from %s: %sother node, no route (dups=%u)",
					node_infostr(sender), oob ? "OOB, " : "", sender->n_dups);
			}
		} else {
			if (GNET_PROPERTY(log_gnutella_routing)) {
				unsigned count = pslist_length(m->routes);
				routing_log_extra(route_log, "%u remaining route%s",
					count, plural(count));
			}

			if (GNET_PROPERTY(log_dup_gnutella_other_node)) {
				unsigned count = pslist_length(m->routes);
				gmsg_log_duplicate(sender,
					"from %s: %sother node, %u route%s (dups=%u)",
					node_infostr(sender), oob ? "OOB, " : "",
					count, plural(count), sender->n_dups);
			}
		}
	}

	return forward;
}

/**
 * Lookup message in the routing table and check whether we have a duplicate.
 *
 * @param route_log is a structure recording to-be-logged information for debug
 * @param node is a pointer to the variable holding the node, and it can be
 * set to NULL if we removed the node.
 * @param mangled is an alternate MUID with bytes 0-3 and 13-14 zeroed
 * which should be tested for duplication as well.  Only set for OOB queries.
 * @param mp is set on output to the message if found in the routing table.
 *
 * @return whether we should route the message.  If `*mp' is not NULL, then
 * the message was a duplicate and it should not be handled locally.
 */
static bool
check_duplicate(struct route_log *route_log, gnutella_node_t **node,
	const guid_t *mangled, struct message **mp)
{
	gnutella_node_t *sender = *node;
	uint8 function = gnutella_header_get_function(&sender->header);
	const guid_t *muid = gnutella_header_get_muid(&sender->header);

	if (find_message(muid, function, mp))
		return handle_duplicate(route_log, node, *mp, FALSE);

	/*
	 * If we have a mangled MUID to test against, we have to look at whether
	 * we also have an entry for it in the routing table.  Indeed, due to
	 * OOB-proxying of queries performed by ultra nodes, the same query can
	 * be proxied from different nodes with different IP:port.
	 *
	 * The mangled MUID is the query MUID where the IP:port have been zeroed
	 * out.  If we get a match, it means we saw this OOB query under a
	 * different incarnation already.  We'll only forward it if it has a
	 * higher TTL as we saw before.
	 *
	 *		--RAM, 2004-09-19
	 */

	if (mangled != NULL && find_message(mangled, function, mp))
		return handle_duplicate(route_log, node, *mp, TRUE);

	g_assert(*mp == NULL);

	routing_log_set_new(route_log);

	if (GNET_PROPERTY(log_new_gnutella)) {
		g_debug("NEW #%s %s from %s", guid_hex_str(muid),
			gmsg_infostr_full_split(
				&sender->header, sender->data, sender->size),
				node_infostr(sender));
	}

	return TRUE;				/* Forward and handle (new message) */
}

/**
 * Route a push message.
 *
 * @return whether message should be handled
 */
static bool
route_push(struct route_log *route_log,
	gnutella_node_t **node, struct route_dest *dest)
{
	gnutella_node_t *sender = *node;
	struct message *m;
	const struct guid *guid;
	gnutella_node_t *neighbour;
	host_addr_t ip;

	/*
	 * A Push request is not broadcasted as other requests, it is routed
	 * back along the nodes that have seen Query Hits from the target
	 * servent of the Push.
	 *
	 * The GUID of the target are the leading bytes of the Push message.
	 */

	g_assert(sender->size > GUID_RAW_SIZE);	/* Must be a valid push */
	guid = cast_to_guid_ptr_const(sender->data);	/* Targetted GUID */

	if (NODE_IS_UDP(sender))
		routing_log_extra(route_log, "UDP");

	/*
	 * Is it for us?
	 */

	if (guid_eq(GNET_PROPERTY(servent_guid), guid)) {
		routing_log_extra(route_log, "we are the target");
		return TRUE;
	}

	if (settings_is_leaf())
		return FALSE;				/* Not for us, and we can't relay */

	/*
	 * If the GUID is banned, drop it immediately.
	 */

	if (is_banned_push(guid)) {
		if (GNET_PROPERTY(routing_debug) > 3) {
			gmsg_log_dropped(sender,
				"from %s, banned GUID %s",
				node_addr(sender), guid_hex_str(guid));
		}
		routing_log_extra(route_log, "to banned GUID %s", guid_hex_str(guid));
		gnet_stats_count_dropped(sender, MSG_DROP_TO_BANNED);
		return FALSE;
	}

	/*
	 * If IP address is among the hostile set, drop.
	 *
	 * FIXME: need to check for "6" for IPv6-Ready because it may not be
	 * an IPv4 target.
	 */

	ip = host_addr_peek_ipv4(&sender->data[20]);

	if (hostiles_is_bad(ip)) {
		hostiles_flags_t flags = hostiles_check(ip);
		routing_log_extra(route_log, "callback IP %s is hostile (%s)",
			host_addr_to_string(ip), hostiles_flags_to_string(flags));
		gnet_stats_count_dropped(sender, MSG_DROP_HOSTILE_IP);
		return FALSE;
	}

	/*
	 * If we find a local route (one of our neighbours), use that.
	 * Otherwise look for a route in the routing table.
	 */

	if (NULL != (neighbour = node_by_guid(guid))) {
		gnet_stats_inc_general(GNR_PUSH_RELAYED_VIA_LOCAL_ROUTE);

		/*
		 * If we got a PUSH directly through UDP, and we can relay it to
		 * a local neighbour, we were most likely the push-proxy for that node.
		 */

		if (NODE_IS_UDP(sender))
			gnet_stats_inc_general(GNR_PUSH_PROXY_UDP_RELAYED);

		routing_log_extra(route_log, "connected to target GUID %s",
				guid_hex_str(guid));

		/*
		 * Since we have a direct connection to the target, relay the message
		 * directly without using the known routes.
		 */

		forward_message(route_log, node, neighbour, dest, NULL);

	} else if (find_message(guid, QUERY_HIT_ROUTE_SAVE, &m) && m->routes) {
		gnet_stats_inc_general(GNR_PUSH_RELAYED_VIA_TABLE_ROUTE);

		/*
		 * By revitalizing the entry, we'll remember the route for
		 * at least TABLE_MIN_CYCLE secs more after seeing this PUSH.
		 */

		revitalize_entry(m, FALSE);
		forward_message(route_log, node, NULL, dest, m->routes);

	} else {
		if (m && m->routes == NULL) {
			routing_log_extra(route_log, "route to target GUID %s gone",
				guid_hex_str(guid));
			gnet_stats_count_dropped(sender, MSG_DROP_ROUTE_LOST);
		} else {
			routing_log_extra(route_log, "no route to target GUID %s",
				guid_hex_str(guid));
			gnet_stats_count_dropped(sender, MSG_DROP_NO_ROUTE);
		}

		return FALSE;
	}

	return FALSE;		/* We are not the target, don't handle it */
}

/**
 * Route a query message.
 *
 * @return whether message should be handled
 */
static bool
route_query(struct route_log *route_log,
	gnutella_node_t **node, struct route_dest *dest)
{
	gnutella_node_t *sender = *node;
	bool is_oob_query;
	bool handle_it;

	/*
	 * Leaves process all the queries and don't route them.
	 */

	if (settings_is_leaf())
		return TRUE;

	/*
	 * If the message comes from UDP, it's not going to go anywhere.
	 */

	if (NODE_IS_UDP(sender)) {
		routing_log_extra(route_log, "UDP");
		handle_it = TRUE;			/* Process it, but don't route */
		goto done;
	}

	is_oob_query = gmsg_split_is_oob_query(&sender->header, sender->data);

	/*
	 * If node is shutdown, it won't be there to get query hits back.
	 * This check is useless for OOB queries since hits may flow out-of-band.
	 */

	if (!NODE_IS_READABLE(sender) && !is_oob_query) {
		routing_log_extra(route_log, "relay shutting down");
		gnet_stats_count_dropped(sender, MSG_DROP_SHUTDOWN);
		return FALSE;
	}

	/*
	 * If the node is flow-controlled on TX, then it is preferable
	 * to drop queries immediately: the traffic the replies may
	 * generate could pile up and make the queue reach its maximum
	 * size.  It is hoped that the flow control condition will not
	 * last too long.
	 *
	 * We do that here, at the lowest level, because we do not
	 * want to record the query as seen: if it comes from another
	 * route, we'll handle it.
	 *
	 *		--RAM, 02/02/2002
	 *
	 * Let OOB queries pass through naturally, as most likely the replies
	 * generated will flow back out-of-band.
	 *
	 *		--RAM, 2004-08-29
	 */

	if (!is_oob_query && NODE_IN_TX_FLOW_CONTROL(sender)) {
		routing_log_extra(route_log, "relay in TX flow control");
		gnet_stats_count_dropped(sender, MSG_DROP_FLOW_CONTROL);
		return FALSE;
	}

	/*
	 * If query was emitted by a host not supporting dynamic querying,
	 * then this host is broadcasting.  We can't know for sure whether
	 * hops=1 queries are not coming from a leaf node connected to our
	 * neighbour.
	 *
	 * We limit the query so that hops + ttl < my_ttl, where my_ttl is our
	 * own broadcasting TTL, but we're dynamic querying and they are not.
	 */

	if (
		!(sender->attrs & NODE_A_DYN_QUERY) &&
		(uint) gnutella_header_get_ttl(&sender->header) +
			gnutella_header_get_hops(&sender->header) > GNET_PROPERTY(my_ttl)
	) {
		int ttl_max;

		/* Trim down */
		ttl_max = GNET_PROPERTY(my_ttl);
		ttl_max -= gnutella_header_get_hops(&sender->header);
		ttl_max = MAX(1, ttl_max);
		gnutella_header_set_ttl(&sender->header, ttl_max);

		routing_log_extra(route_log, "no dynamic querying, TTL forced to %u ",
			gnutella_header_get_ttl(&sender->header));
	}

	/* Broadcast */
	handle_it = forward_message(route_log, node, NULL, dest, NULL);

	/*
	 * Query needs to be forwarded to all leaves if we have to handle it
	 * and message was not a duplicate.
	 */

done:
	if (handle_it && ROUTE_NONE == dest->type && !dest->duplicate)
		dest->type = ROUTE_LEAVES;

	return handle_it;
}

/**
 * Route a query hit message.
 *
 * @return whether message should be handled
 */
static bool
route_query_hit(struct route_log *route_log,
	gnutella_node_t **node, struct route_dest *dest)
{
	gnutella_node_t *sender = *node;
	struct message *m;
	bool node_is_target = FALSE;
	gnutella_node_t *found;
	bool is_oob_proxied;
	const struct guid *origin_guid;
	const guid_t *muid = gnutella_header_get_muid(&sender->header);

	/*
	 * The last GUID_RAW_SIZE bytes of the message are the GUID of the servent
	 * which generated the query hit.
	 */

	g_assert(sender->size >= GUID_RAW_SIZE);

   	origin_guid =
		cast_to_guid_ptr_const(&sender->data[sender->size - GUID_RAW_SIZE]);

	/*
	 * We have to record we have seen a hit reply from the GUID held at
	 * the tail of the packet.  This information is used to later route
	 * back Push messages.
	 *		--RAM, 06/01/2002
	 */

	if (NODE_IS_UDP(sender)) {
		routing_log_extra(route_log, "UDP");
	} else {
		if (!find_message(origin_guid, QUERY_HIT_ROUTE_SAVE, &m)) {
			/*
			 * We've never seen any Query Hit from that servent.
			 * Ensure it's not a banned GUID though.
			 */

			if (!is_banned_push(origin_guid)) {
				message_add(origin_guid, QUERY_HIT_ROUTE_SAVE, sender);
				route_starving_check(origin_guid);
			}
		} else if (m->routes == NULL || !route_node_sent_message(sender, m)) {
			struct route_data *route;

			/*
			 * Either we have no more nodes that sent us any query hit
			 * from that GUID, or we have never received any such hit
			 * from the sender.
			 */

			route = get_routing_data(sender);
			if (NULL == route)
				route = init_routing_data(sender);

			g_assert(route != NULL);

			/*
			 * A query hit is not a broadcasted message, so there's
			 * no recording of the TTLs at which we see it.
			 */

			g_assert(m->ttls == NULL);

			m->routes = pslist_append(m->routes, route);
			route->saved_messages++;

			/*
			 * We just made use of this routing data: make it persist
			 * as long as we can by revitalizing the entry.  This will
			 * allow us to route back PUSH requests for a longer time,
			 * at least TABLE_MIN_CYCLE seconds after seeing the latest
			 * query hit flow by.
			 */

			revitalize_entry(m, FALSE);
		}
	}

	/*
	 * It's important to handle query hits for OOB-proxied queries
	 * differently: they appear to come from ourselves, but they are
	 * not destined to us, and we'll forward them to the leaf who sent
	 * the initial query, regardless of the hops/TTL value of the hit.
	 */

	is_oob_proxied = NULL != oob_proxy_muid_proxied(muid);

	if (!find_message(muid, GTA_MSG_SEARCH, &m)) {
		/* We have never seen any request matching this reply ! */

		routing_log_extra(route_log, "no request matching the reply!");

		gnet_stats_count_dropped(sender, MSG_DROP_NO_ROUTE);
		sender->n_bad++;	/* Node shouldn't have forwarded this message */

		if (GNET_PROPERTY(log_bad_gnutella))
			gmsg_log_bad(sender, "got reply without matching request%s",
				is_oob_proxied ? " (OOB-proxied)" : "");

		goto handle;
	}

	g_assert(m);		/* Or find_message() would have returned FALSE */

	/*
	 * Since this routing data is used, relocate it at the end of
	 * the "message_array[]" to augment its lifetime.
	 */

	revitalize_entry(m, FALSE);

	/*
	 * If `m->routes' is NULL, we have seen the request, but unfortunately
	 * none of the nodes that sent us the request are connected any more.
	 */

	if (m->routes == NULL)
		goto route_lost;

	if (route_node_sent_message(fake_node, m)) {
		node_is_target = TRUE;		/* We are the target of the reply */
		if (is_oob_proxied)
			gnet_stats_inc_general(GNR_OOB_PROXIED_QUERY_HITS);
		else
			gnet_stats_inc_general(GNR_LOCAL_QUERY_HITS);
		goto handle;
	}

	/*
	 * If the query hit's MUID is among the registered OOB-proxied queries,
	 * yet we did not find the message in the routing table as having been
	 * sent by ourselves, something is wrong.
	 *
	 * I ued to assert "!is_oob_proxied" at this point, but it failed once
	 * in a while, and we can recover, it's not critical.  Let's handle it
	 * then, as it's known by the OOB proxy layer.
	 */

	if (is_oob_proxied) {
		g_carp("BUG: forgot we sent OOB-proxied query #%s in routing table!",
			guid_hex_str(gnutella_header_get_muid(&sender->header)));
		node_is_target = TRUE;		/* We are the target of the reply */
		routing_log_extra(route_log, "forgot OOB-proxied MUID");
		goto handle;
	}

	/*
	 * Look for a route different from the one we received the
	 * message from.
	 * XXX should remember hops from queries and choose the lowest hop
	 * XXX route for relaying. --RAM, 2004-08-29
	 */
	{
		pslist_t *sl;
		bool skipped_transient = FALSE;

		found = NULL;
		PSLIST_FOREACH(m->routes, sl) {
			struct route_data *route = sl->data;

			g_assert(route);
			g_assert(route->node);

			if (route->node == sender)
				continue;

			if (route_node_is_gnutella(route->node)) {
				if (
					node_guid(route->node) &&
					guid_eq(node_guid(route->node), origin_guid)
				)
					continue;

				/*
				 * Don't waste bandwidth nor lose the hit: try to find a route
				 * which is not through a transient node, if we can.
				 *
				 * Otherwise, the DH layer will drop the hit later and it
				 * will be logged as a message targeted to a transient node.
				 */

				if (NULL != pslist_next(sl)) {
					gnutella_node_t *rn;

					rn = route_node_get_gnutella(route->node);
					if (NODE_IS_TRANSIENT(rn)) {
						skipped_transient = TRUE;
						continue;
					}

					/* Count non-transient route found after skipping */

					if (skipped_transient) {
						gnet_stats_inc_general(GNR_ROUTING_TRANSIENT_AVOIDED);
					}
				}
			}

			found = route_node_get_gnutella(route->node);
			break;
		}
	}

	if (found == NULL)
		goto route_lost;

	/*
	 * We don't call check_hops_ttl() but inline it here as we don't
	 * want to necessarily drop TTL=0 messages if they are going to
	 * be routed to a leaf node.
	 */

	if (!check_hops(route_log, sender))
		goto handle;	/* Don't route, something is wrong */

	(void) check_ttl(route_log, sender);	/* Just flag TTL=0, don't drop */

	/*
	 * If the TTL expired, drop the message, unless the target is a
	 * leaf node, in which case we'll forward it the reply, or we
	 * are a leaf node, in which case we won't route the message!.
	 */

	if (gnutella_header_get_ttl(&sender->header) <= 1) {
		if (NODE_IS_LEAF(found)) {
			/* TTL expired, but target is a leaf node */
			routing_log_extra(route_log, "expired TTL bumped");
			gnutella_header_set_ttl(&sender->header, 2);
		} else {
			/* TTL expired, message stops here in any case */
			if (!settings_is_leaf()) {
				routing_log_extra(route_log, "TTL expired");
				gnet_stats_count_expired(sender);
			}
			goto handle;
		}
	}

	dest->type = ROUTE_ONE;
	dest->ur.u_node = found;

	if (GNET_PROPERTY(guess_server_debug) > 10 && NODE_IS_UDP(found)) {
		g_debug("GUESS routing query hit #%s to %s",
			guid_hex_str(gnutella_header_get_muid(&sender->header)),
			node_infostr(found));
	}

	goto handle;

route_lost:
	routing_log_extra(route_log, "route to target lost");

	gnet_stats_count_dropped(sender, MSG_DROP_ROUTE_LOST);
	return FALSE;

handle:
	if (node_is_target)
		routing_log_extra(route_log, "we are the target%s",
			is_oob_proxied ? " (OOB-proxy)" : "");

	/*
	 * We apply the TTL limits differently for replies.
	 *
	 * Indeed, replies are forwarded to ONE node, and are not
	 * broadcasted.	It is therefore important to make sure the
	 * reply will reach the issuing host.
	 *
	 * So we don't compare the header's TLL to `max_ttl' but to
	 * `hard_ttl_limit', and if above the limit, we don't drop
	 * the message but trim the TTL down to something acceptable.
	 *
	 *				--RAM, 15/09/2001
	 */

	if (
		gnutella_header_get_ttl(&sender->header)
			> GNET_PROPERTY(hard_ttl_limit) + 1
	) {
		/* TTL too large */
		routing_log_extra(route_log, "TTL adjusted");
		gnutella_header_set_ttl(&sender->header,
			GNET_PROPERTY(hard_ttl_limit) + 1);
	}

	return TRUE;
}

/**
 * Main route computation function.
 *
 * Source of message is passed by reference as `node', because it can be
 * nullified when the node is disconnected from.
 *
 * The destination of the message is computed in `dest', but the message is
 * not physically sent.  The gmsg_sendto_route() will have to be called
 * for that.
 *
 * @returns whether the message is to be handled locally.
 */
bool
route_message(gnutella_node_t **node, struct route_dest *dest)
{
	bool handle_it = FALSE;
	gnutella_node_t *sender = *node;
	struct message *m;
	bool duplicate = FALSE;
	struct route_log route_log;
	const guid_t *mangled = NULL;
	const guid_t *muid = NULL;
	uint8 function;

	node_check(sender);

	function = gnutella_header_get_function(&sender->header);
	muid = gnutella_header_get_muid(&sender->header);

	/* Ensure we never get something bearing our special GUID route marker */
	g_assert(function != QUERY_HIT_ROUTE_SAVE);

	dest->type = ROUTE_NONE;
	dest->duplicate = FALSE;

	routing_log_init(&route_log, sender,
		muid, function,
		gnutella_header_get_hops(&sender->header),
		gnutella_header_get_ttl(&sender->header));

	/*
	 * For OOB queries, we have to mangle the MUID to detect duplicates
	 * when the query is proxied from different ultra nodes.
	 */

	if (
		GTA_MSG_SEARCH == function &&
		!NODE_TALKS_G2(sender) &&
		gmsg_split_is_oob_query(&sender->header, sender->data)
	) {
		mangled = route_mangled_oob_muid(muid);
		gnet_stats_inc_general(GNR_OOB_QUERIES);
		routing_log_extra(&route_log, "OOB");
	}

	/*
	 * For routed messages, we check whether we get a duplicate and
	 * whether the message should be handled locally.
	 */

	switch (function) {
	case GTA_MSG_PUSH_REQUEST:
	case GTA_MSG_SEARCH:
	case GTA_MSG_G2_SEARCH:
	{
		bool route_it = check_duplicate(&route_log, node, mangled, &m);

		dest->duplicate = duplicate = booleanize(m != NULL);

		/*
		 * If the node has been removed, we won't handle the message.
		 */

		if G_UNLIKELY(NULL == *node)
			goto done;

		/*
		 * Record the message in the routing table.
		 *
		 * If it's a duplicate, we'll record the additional route, which
		 * will enable us to find alternate routes for query hits should
		 * the original one fail due to a node disconnection.
		 *
		 * We don't record a PUSH coming from UDP, but we do record a SEARCH
		 * since we have to be able to route back hits from GUESS queries.
		 */

		if (function != GTA_MSG_PUSH_REQUEST || !NODE_IS_UDP(sender)) {
			message_add(muid, function, sender);
		}

		/*
		 * Unfortunately, to be able to detect duplicate OOB-proxied queries
		 * we need to insert two entries in the routing table for queries
		 * marked with the OOB flag: one for the original MUID, and one for
		 * the mangled MUID with the IP:port section zeroed.
		 *		--RAM, 2004-09-19
		 */

		if (mangled) {
			message_add(mangled, function, sender);
		}

		if (!route_it)
			goto done;
		break;
	}
	default:
		break;
	}

	/*
	 * Compute the route, determine if we should handle the message.
	 */

	switch (function) {
	case GTA_MSG_PUSH_REQUEST:
		handle_it = route_push(&route_log, node, dest);
		break;
	case GTA_MSG_SEARCH:
		handle_it = route_query(&route_log, node, dest);
		break;
	case GTA_MSG_SEARCH_RESULTS:
		handle_it = route_query_hit(&route_log, node, dest);
		break;
	case GTA_MSG_G2_SEARCH:
		handle_it = TRUE;		/* We're a G2 leaf node */
		break;
	default:
		/*
		 * Any other message that gets passed to route_message() must
		 * neither be routed nor handled.
		 */
		handle_it = FALSE;
		break;
	}

done:
	routing_log_set_route(&route_log, dest, handle_it);
	routing_log_flush(&route_log);

	/* Paranoid: avoid hop overflow */
	if (gnutella_header_get_hops(&sender->header) < 255) {
		/* Mark passage through our node */
		gnutella_header_set_hops(&sender->header,
			gnutella_header_get_hops(&sender->header) + 1);
	}
	if (gnutella_header_get_ttl(&sender->header) > 0)
		gnutella_header_set_ttl(&sender->header,
			gnutella_header_get_ttl(&sender->header) - 1);

	return !duplicate && handle_it;		/* Don't handle duplicates */
}

/**
 * Check whether we have a route for the reply that would be generated
 * for this request.
 *
 * @returns boolean indicating whether we have such a route.
 */
bool
route_exists_for_reply(const struct guid *muid, uint8 function)
{
	struct message *m;

	if (!find_message(muid, function & ~0x01, &m) || m->routes == NULL)
		return FALSE;

	return TRUE;
}

/**
 * Check whether GUID is routable through a PUSH request.
 *
 * @return TRUE if GUID is routable, FALSE if no PUSH could ever properly
 * reach the target node.
 */
bool
route_guid_pushable(const struct guid *guid)
{
	return !is_banned_push(guid);
}

/**
 * Check whether we have a route to the given GUID, in order to send
 * pushes.
 *
 * @returns NULL if we have no such route, or a list of  node to which we should
 * send the packet otherwise.  It is up to the caller to free that list.
 */
pslist_t *
route_towards_guid(const struct guid *guid)
{
	gnutella_node_t *node;
	struct message *m;

	if (is_banned_push(guid))
		return NULL;

	node = node_by_guid(guid);
	if (node)
		return pslist_prepend(NULL, node);

	if (find_message(guid, QUERY_HIT_ROUTE_SAVE, &m) && m->routes) {
		pslist_t *iter, *nodes = NULL;

		revitalize_entry(m, TRUE);
		PSLIST_FOREACH(m->routes, iter) {
			struct route_data *rd = iter->data;
			nodes = pslist_prepend(nodes, rd->node);
		}
		return nodes;
	}

	return NULL;
}

/**
 * Remove push-proxy entry indexed by GUID.
 */
void
route_proxy_remove(const struct guid *guid)
{
 	/*
	 * The GUID atom is still referred to by the node,
	 * so don't clear anything.
	 */

	htable_remove(ht_proxyfied, guid);
}

/**
 * Add push-proxy route to GUID `guid', which is node `n'.
 *
 * @returns TRUE on success, FALSE if there is a GUID conflict.
 *
 * @attention
 * NB: assumes `guid' is already an atom linked somehow to `n'.
 */
bool
route_proxy_add(const struct guid *guid, gnutella_node_t *n)
{
	if (htable_contains(ht_proxyfied, guid))
		return FALSE;

	htable_insert(ht_proxyfied, guid, n);
	return TRUE;
}

/**
 * Find node to which we are connected with supplied GUID and who requested
 * that we act as its push-proxy.
 *
 * @returns node address if we found it, or NULL if we aren't connected to
 * that node directly.
 */
gnutella_node_t *
route_proxy_find(const struct guid *guid)
{
	return htable_lookup(ht_proxyfied, guid);
}

/**
 * Frees the banned GUID atom keys.
 */
static void
free_banned_push(const void *key, void *unused_udata)
{
	(void) unused_udata;
	atom_guid_free(key);
}

/**
 * Destroy routing data structures.
 */
void G_COLD
routing_close(void)
{
	uint cnt;

	g_assert(routing.messages_hashed != NULL);

	hset_free_null(&routing.messages_hashed);

	for (cnt = 0; cnt < MAX_CHUNKS; cnt++) {
		struct message **chunk = routing.chunks[cnt];
		if (chunk != NULL) {
			int i;
			for (i = 0; i < CHUNK_MESSAGES; i++) {
				struct message *m = chunk[i];
				if (m != NULL) {
					message_check(m, cnt);
					free_route_list(m);
					WFREE(m);
				}
			}
			HFREE_NULL(chunk);
		}
	}

	hset_foreach(ht_banned_push, free_banned_push, NULL);
	hset_free_null(&ht_banned_push);

	cnt = htable_count(ht_proxyfied);
	if (cnt != 0) {
		g_warning("push-proxification table still holds %u node%s",
			cnt, plural(cnt));
	}

	htable_free_null(&ht_proxyfied);

	cnt = htable_count(ht_starving_guid);
	if (cnt != 0) {
		g_warning("starving GUID table still holds %u entr%s",
			cnt, plural_y(cnt));
	}

	htable_free_null(&ht_starving_guid);
	aging_destroy(&at_udp_routes);
}

/* vi: set ts=4 sw=4 cindent: */
