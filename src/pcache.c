/*
 * $Id$
 *
 * Copyright (c) 2001-2002, Raphael Manfredi
 *
 * Pong caching (LimeWire's ping/pong reducing scheme).
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

#include "gnutella.h"

#include <stdlib.h>
#include <fcntl.h>
#include <sys/types.h>
#include <string.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include "sockets.h"
#include "hosts.h"
#include "hcache.h"
#include "pcache.h"
#include "nodes.h"
#include "share.h" /* For files_scanned and kbytes_scanned. */
#include "routing.h"
#include "gmsg.h"
#include "alive.h"
#include "inet.h"
#include "gnet_stats.h"

#include "settings.h"

RCSID("$Id$");

/***
 *** Messages
 ***/

/*
 * send_ping
 *
 * Sends a ping to given node, or broadcast to everyone if `n' is NULL.
 */
static void send_ping(struct gnutella_node *n, guint8 ttl)
{
	struct gnutella_msg_init m;

	message_set_muid(&m.header, GTA_MSG_INIT);

	m.header.function = GTA_MSG_INIT;
	m.header.ttl = ttl;
	m.header.hops = 0;

	WRITE_GUINT32_LE(0, m.header.size);

	if (n) {
		if (NODE_IS_WRITABLE(n)) {
			n->n_ping_sent++;
			gmsg_sendto_one(n, (guchar *) &m, sizeof(struct gnutella_msg_init));
		}
	} else {
		GSList *l;

		/*
		 * XXX Have to loop to count pings sent.
		 * XXX Need to do that more generically, to factorize code.
		 */

		for (l = sl_nodes; l; l = l->next) {
			n = (struct gnutella_node *) l->data;
			if (!NODE_IS_WRITABLE(n))
				continue;
			n->n_ping_sent++;
		}

		gmsg_sendto_all(sl_nodes, (guchar *) &m,
			sizeof(struct gnutella_msg_init));
	}
}

/*
 * send_alive_ping
 *
 * Send ping to immediate neighbour, to check its latency and the fact
 * that it is alive, or get its Gnet sharing information (ip, port).
 * The message is sent as a "control" one, i.e. it's put ahead of the queue.
 *
 * The message ID used is copied back to `muid'.
 *
 * NB: this routine is only made visible for "alive.c".
 */
void send_alive_ping(struct gnutella_node *n, guchar *muid)
{
	struct gnutella_msg_init m;

	g_assert(NODE_IS_WRITABLE(n));
	g_assert(muid);

	message_set_muid(&m.header, GTA_MSG_INIT);
	memcpy(muid, &m.header, 16);

	m.header.function = GTA_MSG_INIT;
	m.header.ttl = 1;
	m.header.hops = 0;

	WRITE_GUINT32_LE(0, m.header.size);

	n->n_ping_sent++;
	gmsg_ctrl_sendto_one(n, (guchar *) &m, sizeof(struct gnutella_msg_init));
}

/*
 * build_pong_msg
 *
 * Build pong message, returns pointer to static data.
 */
struct gnutella_msg_init_response *build_pong_msg(
	guint8 hops, guint8 ttl, guchar *muid,
	guint32 ip, guint16 port, guint32 files, guint32 kbytes)
{
	static struct gnutella_msg_init_response pong;

	pong.header.function = GTA_MSG_INIT_RESPONSE;
	pong.header.hops = hops;
	pong.header.ttl = ttl;
	memcpy(&pong.header.muid, muid, 16);

	WRITE_GUINT16_LE(port, pong.response.host_port);
	WRITE_GUINT32_BE(ip, pong.response.host_ip);
	WRITE_GUINT32_LE(files, pong.response.files_count);
	WRITE_GUINT32_LE(kbytes, pong.response.kbytes_count);
	WRITE_GUINT32_LE(sizeof(struct gnutella_init_response), pong.header.size);

	return &pong;
}

/*
 * send_pong
 *
 * Send pong message back to node.
 * If `control' is true, send it as a higher priority message.
 */
static void send_pong(struct gnutella_node *n, gboolean control,
	guint8 hops, guint8 ttl, guchar *muid,
	guint32 ip, guint16 port, guint32 files, guint32 kbytes)
{
	struct gnutella_msg_init_response *r;

	g_assert(ttl >= 1);

	if (!NODE_IS_WRITABLE(n))
		return;

	r = build_pong_msg(hops, ttl, muid, ip, port, files, kbytes);
	n->n_pong_sent++;

	if (control)
		gmsg_ctrl_sendto_one(n, (guchar *) r, sizeof(*r));
	else
		gmsg_sendto_one(n, (guchar *) r, sizeof(*r));
}

/*
 * send_personal_info
 *
 * Send info about us back to node, using the hopcount information present in
 * the header of the node structure to construct the TTL of the pong we
 * send.
 *
 * If `control' is true, send it as a higher priority message.
 */
static void send_personal_info(struct gnutella_node *n, gboolean control)
{
	guint32 kbytes;

	g_assert(n->header.function == GTA_MSG_INIT);	/* Replying to a ping */

	if (!force_local_ip && !local_ip)
		return;		/* If we don't know yet our local IP, we can't reply */

	/*
	 * Mark pong if we are an ultra node: the amount of kbytes scanned must
	 * be an exact power of two, and at minimum 8.
	 */

	if (current_peermode == NODE_P_ULTRA) {
		if (kbytes_scanned <= 8)
			kbytes = 8;
		else
			kbytes = next_pow2(kbytes_scanned);
	} else
		kbytes = kbytes_scanned | 0x1;		/* Ensure not a power of two */

	/*
	 * Pongs are sent with a TTL just large enough to reach the pinging host,
	 * up to a maximum of max_ttl.	Note that we rely on the hop count being
	 * accurate.
	 *				--RAM, 15/09/2001
	 */

	send_pong(n, control, 0, MIN(n->header.hops + 1, max_ttl), n->header.muid,
		listen_ip(), listen_port, files_scanned, kbytes);
}

/*
 * send_neighbouring_info
 *
 * Send a pong for each of our connected neighbours to specified node.
 */
static void send_neighbouring_info(struct gnutella_node *n)
{
	GSList *l;

	g_assert(n->header.function == GTA_MSG_INIT);	/* Replying to a ping */
	g_assert(n->header.hops == 0);					/* Originates from node */
	g_assert(n->header.ttl == 2);					/* "Crawler" ping */

	for (l = sl_nodes; l; l = l->next) {
		struct gnutella_node *cn = (struct gnutella_node *) l->data;

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

		if (cn->gnet_ip == 0)
			continue;				/* No information yet */

		send_pong(n, FALSE,
			1, 1, n->header.muid,			/* hops = 1, TTL = 1 */
			cn->gnet_ip, cn->gnet_port,
			cn->gnet_files_count, cn->gnet_kbytes_count);

		/*
		 * Since we won't see the neighbour pong, we won't be able to store
		 * it in our reserve, so do it from here.
		 */

		if (!NODE_IS_LEAF(n))
			host_add(cn->gnet_ip, cn->gnet_port, FALSE);

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

struct cached_pong {		/* A cached pong */
	gint refcount;			/* How many lists reference us? */
	guint32 node_id;		/* The node ID from which we got that pong */
	guint32 last_sent_id;	/* Node ID to which we last sent this pong */
	guint32 ip;				/* Values from the pong message */
	guint32 port;
	guint32 files_count;
	guint32 kbytes_count;
};

struct cache_line {			/* A cache line for a given hop value */
	gint hops;				/* Hop count of this cache line */
	GSList *pongs;			/* List of cached_pong */
	GSList *cursor;			/* Cursor within list: last item traversed */
};

struct recent {
	GHashTable *ht_recent_pongs;	/* Recent pongs we know about */
	GList *recent_pongs;			/* Recent pongs we got */
	GList *last_returned_pong;		/* Last returned from list */
	gint recent_pong_count;			/* # of pongs in recent list */
};

#define PONG_CACHE_SIZE		(MAX_CACHE_HOPS+1)

static struct cache_line pong_cache[PONG_CACHE_SIZE];
static struct recent recent_pongs[HCACHE_MAX];

#define CACHE_LIFESPAN		5		/* seconds */
#define PING_THROTTLE		3		/* seconds */
#define MAX_PONGS			10		/* Max pongs returned per ping */
#define OLD_PING_PERIOD		45		/* Pinging period for "old" clients */
#define OLD_CACHE_RATIO		20		/* % of pongs from "old" clients we cache */
#define RECENT_PING_SIZE	50		/* remember last 50 pongs we saw */

/*
 * cached_pong_hash
 * cached_pong_eq
 *
 * Callbacks for the `ht_recent_pongs' hash table.
 */

static guint cached_pong_hash(gconstpointer key)
{
	struct cached_pong *cp = (struct cached_pong *) key;

	return (guint) (cp->ip ^ ((cp->port << 16) | cp->port));
}
static gint cached_pong_eq(gconstpointer v1, gconstpointer v2)
{
	struct cached_pong *h1 = (struct cached_pong *) v1;
	struct cached_pong *h2 = (struct cached_pong *) v2;

	return h1->ip == h2->ip && h1->port == h2->port;
}

/*
 * pcache_init
 */
void pcache_init(void)
{
	gint h;

	memset(pong_cache, 0, sizeof(pong_cache));
	memset(recent_pongs, 0, sizeof(recent_pongs));

	for (h = 0; h < PONG_CACHE_SIZE; h++)
		pong_cache[h].hops = h;

	recent_pongs[HCACHE_ANY].ht_recent_pongs =
		g_hash_table_new(cached_pong_hash, cached_pong_eq);

	recent_pongs[HCACHE_ULTRA].ht_recent_pongs =
		g_hash_table_new(cached_pong_hash, cached_pong_eq);
}

/*
 * free_cached_pong
 *
 * Free cached pong when noone references it any more.
 */
static void free_cached_pong(struct cached_pong *cp)
{
	g_assert(cp->refcount > 0);		/* Someone was referencing it */

	if (--(cp->refcount) != 0)
		return;

	wfree(cp, sizeof(*cp));
}


/*
 * pcache_get_recent
 *
 * Get a recent pong from the list, updating `last_returned_pong' as we
 * go along, so that we never return twice the same pong instance.
 *
 * Fills `ip' and `port' with the pong value and return TRUE if we
 * got a pong.  Otherwise return FALSE.
 */
gboolean pcache_get_recent(hcache_type_t type, guint32 *ip, guint16 *port)
{
	static guint32 last_ip = 0;
	static guint16 last_port = 0;
	GList *l;
	struct cached_pong *cp;
	struct recent *rec;

	g_assert(type >= 0 && type < HCACHE_MAX);

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
		cp = (struct cached_pong *) l->data;

		if (cp->ip != last_ip || cp->port != last_port)
			goto found;

		if (l->next == NULL)			/* Head is the only item in list */
			return FALSE;
	} else {
		/* Regular case */
		for (l = rec->last_returned_pong->prev; l; l = l->prev) {
			cp = (struct cached_pong *) l->data;
			if (cp->ip != last_ip || cp->port != last_port)
				goto found;
		}
	}

	/*
	 * Still none found, go back to the end of the list.
	 */

	for (l = g_list_last(rec->recent_pongs); l; l = l->prev) {
		cp = (struct cached_pong *) l->data;
		if (cp->ip != last_ip || cp->port != last_port)
			goto found;
	}

	return FALSE;

found:
	rec->last_returned_pong = l;
	*ip = last_ip = cp->ip;
	*port = last_port = cp->port;

	if (dbg > 8)
		printf("returning recent %s PONG %s\n",
			hcache_type_to_gchar(type), ip_port_to_gchar(cp->ip, cp->port));

	return TRUE;
}

/*
 * add_recent_pong
 *
 * Add recent pong to the list, handled as a FIFO cache, if not already
 * present.
 */
static void add_recent_pong(hcache_type_t type, struct cached_pong *cp)
{
	struct recent *rec;

	g_assert(type >= 0 && type < HCACHE_MAX);

	rec = &recent_pongs[type];

	if (g_hash_table_lookup(rec->ht_recent_pongs, (gconstpointer) cp))
		return;

	if (rec->recent_pong_count == RECENT_PING_SIZE) {		/* Full */
		GList *link = g_list_last(rec->recent_pongs);
		struct cached_pong *cp = (struct cached_pong *) link->data;

		rec->recent_pongs = g_list_remove_link(rec->recent_pongs, link);
		g_hash_table_remove(rec->ht_recent_pongs, cp);

		if (link == rec->last_returned_pong)
			rec->last_returned_pong = rec->last_returned_pong->prev;

		free_cached_pong(cp);
		g_list_free_1(link);
	} else
		rec->recent_pong_count++;
	
	rec->recent_pongs = g_list_prepend(rec->recent_pongs, cp);
	g_hash_table_insert(rec->ht_recent_pongs, cp, (gpointer) 1);
	cp->refcount++;		/* We don't refcount insertion in the hash table */
}

/*
 * pong_type
 *
 * Determine the pong type (any, or of the ultra kind).
 */
static hcache_type_t pong_type(struct gnutella_init_response *pong)
{
	guint32 kbytes;

	READ_GUINT32_LE(pong->kbytes_count, kbytes);

	/*
	 * Ultra pongs are marked by having their kbytes count be an
	 * exact power of two.
	 */

	return is_pow2(kbytes) ? HCACHE_ULTRA : HCACHE_ANY;
}

/*
 * pcache_clear_recent
 *
 * Clear the whole recent pong list.
 */
void pcache_clear_recent(hcache_type_t type)
{
	GList *l;
	struct recent *rec;

	g_assert(type >= 0 && type < HCACHE_MAX);

	rec = &recent_pongs[type];

	for (l = rec->recent_pongs; l; l = l->next) {
		struct cached_pong *cp = (struct cached_pong *) l->data;

		g_hash_table_remove(rec->ht_recent_pongs, cp);
		free_cached_pong(cp);
	}

	g_list_free(rec->recent_pongs);
	rec->recent_pongs = NULL;
	rec->last_returned_pong = NULL;
	rec->recent_pong_count = 0;
}

/*
 * pcache_outgoing_connection
 *
 * Called when a new outgoing connection has been made.
 *
 * + If we need a connection, or have less than MAX_PONGS entries in our caught
 *   list, send a ping at normal TTL value.
 * + Otherwise, send a handshaking ping with TTL=1
 */
void pcache_outgoing_connection(struct gnutella_node *n)
{
	g_assert(NODE_IS_CONNECTED(n));

	if (connected_nodes() < up_connections || hcache_is_low(HCACHE_ANY))
		send_ping(n, my_ttl);		/* Regular ping, get fresh pongs */
	else
		send_ping(n, 1);			/* Handshaking ping */
}

/*
 * pcache_expire
 *
 * Expire the whole cache.
 */
static void pcache_expire(void)
{
	gint i;
	gint entries = 0;

	for (i = 0; i < PONG_CACHE_SIZE; i++) {
		struct cache_line *cl = &pong_cache[i];
		GSList *l;

		for (l = cl->pongs; l; l = l->next) {
			entries++;
			free_cached_pong((struct cached_pong *) l->data);
		}
		g_slist_free(cl->pongs);

		cl->pongs = NULL;
		cl->cursor = NULL;
	}

	if (dbg > 4)
		printf("Pong CACHE expired (%d entr%s, %d in reserve)\n",
			entries, entries == 1 ? "y" : "ies", hcache_size(HCACHE_ANY));
}

/*
 * pcache_close
 *
 * Final shutdown.
 */
void pcache_close(void)
{
	static hcache_type_t types[] = { HCACHE_ANY, HCACHE_ULTRA };
	gint i;

	pcache_expire();

	for (i = 0; i < sizeof(types) / sizeof(types[0]); i++) {
		hcache_type_t type = types[i];

		pcache_clear_recent(type);
		g_hash_table_destroy(recent_pongs[type].ht_recent_pongs);
	}
}

/*
 * ping_all_neighbours
 *
 * Send a ping to all "new" clients to which we are connected, and one to
 * older client if and only if at least OLD_PING_PERIOD seconds have
 * elapsed since our last ping, as determined by `next_ping'.
 */
static void ping_all_neighbours(time_t now)
{
	GSList *l;

	for (l = sl_nodes; l; l = l->next) {
		struct gnutella_node *n = (struct gnutella_node *) l->data;

		if (!NODE_IS_WRITABLE(n) || NODE_IS_LEAF(n))
			continue;

		if (n->attrs & NODE_A_PONG_CACHING)
			send_ping(n, my_ttl);
		else if (now > n->next_ping) {
			send_ping(n, my_ttl);
			n->next_ping = now + OLD_PING_PERIOD;
		}
	}
}

/*
 * pcache_possibly_expired
 *
 * Check pong cache for expiration.
 * If expiration time is reached, flush it and ping all our neighbours.
 */
void pcache_possibly_expired(time_t now)
{
	if (now >= pcache_expire_time) {
		pcache_expire();
		pcache_expire_time = now + CACHE_LIFESPAN;
		ping_all_neighbours(now);
	}
}

/*
 * setup_pong_demultiplexing
 *
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
static void setup_pong_demultiplexing(
	struct gnutella_node *n, guchar *muid, guint8 ttl)
{
	gint remains;
	gint h;

	g_assert(n->header.function == GTA_MSG_INIT);

	memcpy(n->ping_guid, n->header.muid, 16);
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
		if (dbg > 7)
			printf("pong_needed[%d] = %d, remains = %d\n", h, amount, remains);
	}

	g_assert(remains == 0);
}

/*
 * iterate_on_cached_line
 *
 * Internal routine for send_cached_pongs.
 *
 * Iterates on a list of cached pongs and send back any pong to node `n'
 * that did not originate from it.  Update `cursor' in the cached line
 * to be the address of the last traversed item.
 *
 * Return FALSE if we're definitely done, TRUE if we can still iterate.
 */
static gboolean iterate_on_cached_line(
	struct gnutella_node *n, struct cache_line *cl, guint8 ttl,
	GSList *start, GSList *end, gboolean strict)
{
	gint hops = cl->hops;
	GSList *l;

	for (l = start; l && l != end && n->pong_missing; l = l->next) {
		struct cached_pong *cp = (struct cached_pong *) l->data;

		cl->cursor = l;

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

		if (n->id == cp->node_id)
			continue;
		if (n->id == cp->last_sent_id)
			continue;
		cp->last_sent_id = n->id;

		/*
		 * When sending a cached pong, don't forget that its cached hop count
		 * is the one we got when we received it, i.e. hops=0 means a pong
		 * from one of our immediate neighbours.  However, we're now "routing"
		 * it, so we must increase the hop count.
		 */

		g_assert(hops < 255);		/* Because of MAX_CACHE_HOPS */

		send_pong(n, FALSE, hops + 1, ttl, n->ping_guid,
			cp->ip, cp->port, cp->files_count, cp->kbytes_count);

		n->pong_missing--;

		if (dbg > 7)
			printf("iterate: sent cached pong %s (hops=%d, TTL=%d) to %s, "
				"missing=%d %s\n", ip_port_to_gchar(cp->ip, cp->port),
				hops, ttl, node_ip(n), n->pong_missing,
				strict ? "STRICT" : "loose");

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

/*
 * send_cached_pongs
 *
 * Send pongs from cache line back to node `n' if more are needed for this
 * hop count and they are not originating from the node.  When `strict'
 * is false, we send even if no pong at that hop level is needed.
 */
static void send_cached_pongs(struct gnutella_node *n,
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

/*
 * pong_all_neighbours_but_one
 *
 * We received a pong we cached from `n'.  Send it to all other nodes if
 * they need one at this hop count.
 */
static void pong_all_neighbours_but_one(
	struct gnutella_node *n, struct cached_pong *cp, guint8 hops, guint8 ttl)
{
	GSList *l;

	for (l = sl_nodes; l; l = l->next) {
		struct gnutella_node *cn = (struct gnutella_node *) l->data;

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

		cn->pong_missing--;
		cn->pong_needed[hops]--;

		/*
		 * When sending a cached pong, don't forget that its cached hop count
		 * is the one we got when we received it, i.e. hops=0 means a pong
		 * from one of our immediate neighbours.  However, we're now "routing"
		 * it, so we must increase the hop count.
		 */

		g_assert(hops < 255);

		send_pong(cn, FALSE, hops + 1, ttl, cn->ping_guid,
			cp->ip, cp->port, cp->files_count, cp->kbytes_count);

		if (dbg > 7)
			printf("pong_all: sent cached pong %s (hops=%d, TTL=%d) to %s "
				"missing=%d\n", ip_port_to_gchar(cp->ip, cp->port),
				hops, ttl, node_ip(cn), cn->pong_missing);
	}
}

/*
 * record_fresh_pong
 *
 * Add pong from node `n' to our cache of recent pongs.
 * Returns the cached pong object.
 */
static struct cached_pong *record_fresh_pong(
	hcache_type_t type,
	struct gnutella_node *n,
	guint8 hops, guint32 ip, guint16 port,
	guint32 files_count, guint32 kbytes_count)
{
	struct cache_line *cl;
	struct cached_pong *cp;
	guint8 hop;

	g_assert(type >= 0 && type < HCACHE_MAX);

	cp = (struct cached_pong *) walloc(sizeof(struct cached_pong));

	cp->refcount = 1;
	cp->node_id = n->id;
	cp->last_sent_id = n->id;
	cp->ip = ip;
	cp->port = port;
	cp->files_count = files_count;
	cp->kbytes_count = kbytes_count;

	hop = CACHE_HOP_IDX(hops);		/* Trim high values to MAX_CACHE_HOPS */
	cl = &pong_cache[hop];
	cl->pongs = g_slist_append(cl->pongs, cp);
	add_recent_pong(type, cp);

	return cp;
}

/*
 * pcache_ping_received
 *
 * Called when a ping is received from a node.
 *
 * + If current time is less than what `ping_accept' says, drop the ping.
 *   Otherwise, accept the ping and increment `ping_accept' by PING_THROTTLE.
 * + If cache expired, call pcache_expire() and broadcast a new ping to all
 *   the "new" clients (i.e. those flagged NODE_A_PONG_CACHING).  For "old"
 *   clients, do so only if "next_ping" time was reached.
 * + Handle "alive" pings (TTL=1) and "crawler" pings (TTL=2) immediately,
 *   then return.
 * + Setup pong demultiplexing tables, recording the fact that  the node needs
 *   to be sent pongs as we receive them.
 * + Return a pong for us if we accept incoming connections right now.
 * + Return cached pongs, avoiding to resend a pong coming from that node ID.
 */
void pcache_ping_received(struct gnutella_node *n)
{
	time_t now = time((time_t *) 0);
	gint h;
	guint8 ttl;

	g_assert(NODE_IS_CONNECTED(n));

	/*
	 * Handle "alive" pings and "crawler" pings specially.
	 * Besides, we always accept them.
	 */

	if (n->header.hops == 0 && n->header.ttl <= 2) {
		n->n_ping_special++;
		if (n->header.ttl == 1)
			send_personal_info(n, TRUE);	/* Control message, prioritary */
		else if (n->header.ttl == 2) {
			if (current_peermode != NODE_P_LEAF)
				send_neighbouring_info(n);
		} else
			node_sent_ttl0(n);
		return;
	}

	/*
	 * If we get a ping with hops != 0 from a host that claims to
	 * implement ping/pong reduction, then they are not playing
	 * by the same rules as we are.  Emit a warning.
	 *		--RAM, 03/03/2001
	 */

	if (
		n->header.hops &&
		(n->attrs & (NODE_A_PONG_CACHING|NODE_A_PONG_ALIEN)) ==
			NODE_A_PONG_CACHING
	) {
		if (dbg)
			g_warning("node %s (%s) [%d.%d] claimed ping reduction, "
				"got ping with hops=%d", node_ip(n),
				n->vendor ? n->vendor : "????",
				n->proto_major, n->proto_minor, n->header.hops);
		n->attrs |= NODE_A_PONG_ALIEN;		/* Warn only once */
	}

	/*
	 * Accept the ping?.
	 */

	if (now < n->ping_accept) {
		n->n_ping_throttle++;		/* Drop the ping */
		n->rx_dropped++;
        gnet_stats_count_dropped(n, MSG_DROP_PING_THROTTLE);
		return;
	} else {
		n->n_ping_accepted++;
		n->ping_accept = now + PING_THROTTLE;	/* Drop more ones until then */
	}

	/*
	 * Purge cache if needed.
	 */

	pcache_possibly_expired(now);

	if (!NODE_IS_CONNECTED(n))		/* Can be removed if send queue is full */
		return;

	/*
	 * If TTL = 0, only us can reply, and we'll do that below in any case..
	 * We call setup_pong_demultiplexing() anyway to reset the pong_needed[]
	 * array.
	 *
	 * A leaf node will not demultiplex pongs, so don't bother.
	 */

	if (current_peermode != NODE_P_LEAF)
		setup_pong_demultiplexing(n, n->header.muid, n->header.ttl);

	/*
	 * If we can accept an incoming connection, send a reply.
	 *
	 * If we are firewalled, we nonetheless send a ping
	 * when inet_can_answer_ping() tells us we can, irrespective
	 * of whether we can accept a new node connection: the aim is
	 * to trigger an incoming connection that will prove us we're
	 * not firewalled.
	 */

	if (
		(is_firewalled || node_missing() > 0) && inet_can_answer_ping()
	) {
		send_personal_info(n, FALSE);
		if (!NODE_IS_CONNECTED(n))	/* Can be removed if send queue is full */
			return;
	}

	if (current_peermode == NODE_P_LEAF)
		return;

	/*
	 * We continue here only for non-leaf nodes.
	 */

	/*
	 * Return cached pongs if we have some and they are needed.
	 * We first try to send pongs on a per-hop basis, based on pong_needed[].
	 */

	ttl = MIN(n->header.hops + 1, max_ttl);

	for (h = 0; n->pong_missing && h < n->header.ttl; h++) {
		struct cache_line *cl = &pong_cache[CACHE_HOP_IDX(h)];

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

	for (h = 0; n->pong_missing && h < n->header.ttl; h++) {
		struct cache_line *cl = &pong_cache[CACHE_HOP_IDX(h)];

		if (cl->pongs) {
			send_cached_pongs(n, cl, ttl, FALSE);
			if (!NODE_IS_CONNECTED(n))
				return;
		}
	}
}

/*
 * pcache_pong_received
 *
 * Called when a pong is received from a node.
 *
 * + Record node in the main host catching list.
 * + If node is not a "new" client (i.e. flagged as NODE_A_PONG_CACHING),
 *   cache randomly OLD_CACHE_RATIO percent of those (older clients need
 *   to be able to get incoming connections as well).
 * + Cache pong in the pong.hops cache line, associated with the node ID (so we
 *   never send back this entry to the node).
 * + For all nodes but `n', propagate pong if neeed, with demultiplexing.
 */
void pcache_pong_received(struct gnutella_node *n)
{
	guint32 ip;
	guint16 port;
	guint32 files_count;
	guint32 kbytes_count;
	struct cached_pong *cp;
	hcache_type_t ptype;

	n->n_pong_received++;

	/*
	 * Decompile the pong information.
	 */

	READ_GUINT16_LE(n->data, port);
	READ_GUINT32_BE(n->data + 2, ip);
	READ_GUINT32_LE(n->data + 6, files_count);
	READ_GUINT32_LE(n->data + 10, kbytes_count);

	/*
	 * Handle replies from our neighbours specially
	 */

	if (n->header.hops == 0) {
		if (!n->gnet_ip && (n->flags & NODE_F_INCOMING)) {
			if (ip == n->ip) {
				n->gnet_ip = ip;		/* Signals: we have figured it out */
				n->gnet_port = port;
			} else if (!(n->flags & NODE_F_ALIEN_IP)) {
				if (dbg) g_warning(
					"node %s (%s) sent us a pong for itself with alien IP %s",
					node_ip(n), n->vendor ? n->vendor : "", ip_to_gchar(ip));
				n->flags |= NODE_F_ALIEN_IP;	/* Probably firewalled */
			}
		}

		n->gnet_files_count = files_count;
		n->gnet_kbytes_count = kbytes_count;

		/*
		 * Spot any change in the pong's IP address.  We try to avoid messages
		 * about "connection pongs" by checking whether we have sent at least
		 * 2 pings (one handshaking ping plus one another).
		 */

		if (n->gnet_pong_ip && ip != n->gnet_pong_ip) {
			if (dbg && n->n_ping_sent > 2) g_warning(
				"node %s (%s) sent us a pong for new IP %s (used %s before)",
				node_ip(n), n->vendor ? n->vendor : "",
				ip_port_to_gchar(ip, port), ip_to_gchar(n->gnet_pong_ip));
		}

		n->gnet_pong_ip = ip;

		/*
		 * If it was an acknowledge for one of our alive pings, don't cache.
		 */

		if (alive_ack_ping(n->alive_pings, n->header.muid))
			return;
	}

	/*
	 * If it's not a connectible pong, discard it.
	 */

	if (!host_is_valid(ip, port)) {
		gnet_stats_count_dropped(n, MSG_DROP_PONG_UNUSABLE);
		return;
	}

	/*
	 * If pong points to us, maybe we explicitly connected to ourselves
	 * (tests) or someone is trying to fool us.
	 */

	if (ip == listen_ip() && port == listen_port)
		return;

	/*
	 * Add pong to our reserve, and possibly try to connect.
	 */

	host_add(ip, port, TRUE);

	/*
	 * If we got a pong from an "old" client, cache OLD_CACHE_RATIO of
	 * its pongs, randomly.  Returning from this routine means we won't
	 * cache it.
	 */

	if (!(n->attrs & NODE_A_PONG_CACHING)) {
		gint ratio = (gint) random_value(100);
		if (ratio >= OLD_CACHE_RATIO) {
			if (dbg > 7)
				printf("NOT CACHED pong %s (hops=%d, TTL=%d) from OLD %s\n",
					ip_port_to_gchar(ip, port), n->header.hops, n->header.ttl,
					node_ip(n));
			return;
		}
	}

	/*
	 * Insert pong within our cache.
	 */

	ptype = pong_type((struct gnutella_init_response *) n->data);

	cp = record_fresh_pong(HCACHE_ANY, n, n->header.hops, ip, port,
		files_count, kbytes_count);

	if (ptype == HCACHE_ULTRA)
		(void) record_fresh_pong(HCACHE_ULTRA, n, n->header.hops, ip, port,
			files_count, kbytes_count);

	if (dbg > 6)
		printf("CACHED %s pong %s (hops=%d, TTL=%d) from %s %s\n",
			ptype == HCACHE_ULTRA ? "ultra" : "normal",
			ip_port_to_gchar(ip, port), n->header.hops, n->header.ttl,
			(n->attrs & NODE_A_PONG_CACHING) ? "NEW" : "OLD", node_ip(n));

	/*
	 * Demultiplex pong: send it to all the connections but the one we
	 * received it from, provided they need more pongs of this hop count.
	 */

	if (current_peermode != NODE_P_LEAF)
		pong_all_neighbours_but_one(n,
			cp, CACHE_HOP_IDX(n->header.hops), MAX(1, n->header.ttl));
}

/*
 * pcache_pong_fake
 *
 * Fake a pong for a node from which we received an incoming connection,
 * using the supplied IP/port.
 *
 * This pong is not multiplexed to neighbours, but is used to populate our
 * cache, so we can return its address to others, assuming that if it is
 * making an incoming connection to us, it is really in need for other
 * connections as well.
 */
void pcache_pong_fake(struct gnutella_node *n, guint32 ip, guint16 port)
{
	if (!host_is_valid(ip, port))
		return;

	host_add(ip, port, FALSE);
	(void) record_fresh_pong(HCACHE_ANY, n, 1, ip, port, 0, 0);
}

/* vi: set ts=4: */

