/*
 * Copyright (c) 2001-2011, 2014 Raphael Manfredi
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
 * Search handling (core side).
 *
 * @author Raphael Manfredi
 * @date 2001-2011, 2014
 */

#include "common.h"

#define SEARCH_SOURCES
#include "search.h"

#include "ban.h"
#include "bogons.h"
#include "bsched.h"
#include "ctl.h"
#include "dh.h"
#include "dmesh.h"
#include "downloads.h"
#include "dq.h"
#include "extensions.h"
#include "fileinfo.h"
#include "geo_ip.h"
#include "ggep.h"
#include "ggep_type.h"
#include "gmsg.h"
#include "gnet_stats.h"
#include "guess.h"
#include "guid.h"
#include "hostiles.h"
#include "hosts.h"
#include "huge.h"
#include "ignore.h"
#include "ipv6-ready.h"
#include "nodes.h"
#include "oob.h"
#include "oob_proxy.h"
#include "pcache.h"			/* For pcache_guess_acknowledge() */
#include "qhit.h"
#include "qrp.h"
#include "routing.h"
#include "settings.h"		/* For listen_ip() */
#include "share.h"
#include "sockets.h"
#include "spam.h"
#include "sq.h"
#include "version.h"
#include "vmsg.h"

#include "g2/build.h"
#include "g2/msg.h"
#include "g2/node.h"
#include "g2/tree.h"

#include "if/gnet_property.h"
#include "if/gnet_property_priv.h"
#include "if/bridge/c2ui.h"

#include "xml/vxml.h"
#include "xml/xnode.h"
#include "xml/xfmt.h"

#include "lib/aging.h"
#include "lib/array.h"
#include "lib/ascii.h"
#include "lib/atoms.h"
#include "lib/compat_misc.h"
#include "lib/concat.h"
#include "lib/cq.h"
#include "lib/cstr.h"
#include "lib/endian.h"
#include "lib/entropy.h"
#include "lib/glib-missing.h"
#include "lib/gnet_host.h"
#include "lib/halloc.h"
#include "lib/hashing.h"
#include "lib/hashlist.h"
#include "lib/hset.h"
#include "lib/hstrfn.h"
#include "lib/htable.h"
#include "lib/idtable.h"
#include "lib/iso3166.h"
#include "lib/listener.h"
#include "lib/magnet.h"
#include "lib/mempcpy.h"
#include "lib/nid.h"
#include "lib/pow2.h"			/* For IS_POWER_OF_2() */
#include "lib/pslist.h"
#include "lib/pslist.h"
#include "lib/random.h"
#include "lib/sbool.h"
#include "lib/sectoken.h"
#include "lib/str.h"
#include "lib/stringify.h"		/* For hex_escape() */
#include "lib/tm.h"
#include "lib/tokenizer.h"
#include "lib/urn.h"
#include "lib/utf8.h"
#include "lib/vector.h"
#include "lib/vendors.h"
#include "lib/walloc.h"
#include "lib/wd.h"
#include "lib/wordvec.h"
#include "lib/wq.h"

#include "lib/override.h"		/* Must be the last header included */

#define MIN_SEARCH_TERM_BYTES 3		/* in bytes! */
#define MAX_SEARCH_TERM_BYTES 200	/* in bytes; reserve some for GGEP etc. */

/*
 * LimeWire has dropped searches with more than 30 characters (actually UTF-16
 * codepoints) for years. In late 2008, they added GGEP XQ to bypass this limit.
 */
#define MAX_SEARCH_TERM_CHARS MAX_SEARCH_TERM_BYTES	/* in characters! */
#define MAX_EXTENDED_QUERY_LEN 255	/* in bytes; long search terms (GGEP XQ) */

#define MUID_MAX			4	 /**< Max amount of MUID we keep per search */
#define SEARCH_MIN_RETRY	1800 /**< Minimum search retry timeout */

#define SEARCH_GC_PERIOD	120	 /**< Every 2 minutes */

#define HUGE_FS				0x1c /**< HUGE Field Separator */
#define DEFLATE_THRESHOLD	48	 /**< Minimum size to attempt GGEP deflate */

/*
 * GUESS security tokens.
 */
#define GUESS_KEYS				2		/**< Two keys in the set */
#define GUESS_REFRESH_PERIOD	86400	/**< 1 day */

#define SEARCH_ACTIVITY_TIMEOUT	120		/**< Delay before declaring idle */
#define ORA_KEYS				2		/**< Two keys in the set */
#define OOB_REPLY_ACK_TIMEOUT	900		/**< Timeout for OOB hit delivery */

static sectoken_gen_t *guess_stg;		/**< GUESS token generator */
static sectoken_gen_t *ora_stg;			/**< OOB request ack token generator */
static aging_table_t *ora_secure;		/**< Hosts supporting secure OOB */

enum search_ctrl_magic { SEARCH_CTRL_MAGIC = 0x0add8c06 };

/**
 * Structure for search results.
 */
typedef struct search_ctrl {
	enum search_ctrl_magic magic;	/**< Magic number */
    gnet_search_t search_handle;	/**< Search handle */
	uint32 id;						/**< Unique ID */

	/* no more "speed" field -- use marked field now --RAM, 06/07/2003 */

	const char *query;		/**< The normalized search query (atom) */
	const char *name;		/**< The original search term (atom) */
	time_t  time;			/**< Time when this search was started */
	pslist_t *muids;		/**< Message UIDs of this search */
	guess_t *guess;			/**< GUESS query running, NULL if none */
	unsigned media_type;	/**< Media type filtering (0 means none) */

	sbool passive;		/**< Is this a passive search? */
	sbool frozen;		/**< NOTE: If TRUE, the query is not issued to nodes
				  			anymore and "don't update window" */
	sbool browse;		/**< Special "browse host" search */
	sbool local;		/**< Special "local" search */
	sbool whats_new;	/**< Is this a "What's New?" query */
	sbool active;		/**< Whether to actively issue queries. */
	sbool track_sha1;	/**< Track SHA1 of files downloaded from results */

	/*
	 * Keep a record of nodes we've sent this search w/ this muid to.
	 */

	hset_t *sent_nodes;			/**< Sent node by ip:port */
	hset_t *sent_node_ids;		/**< IDs of nodes to which we sent query */

	wq_event_t *new_node_wait;	/**< Waiting for new node connections */
	watchdog_t *activity;		/**< Monitoring queries/hits activity */
	cperiodic_t *reissue_ev;	/**< re-issue timeout periodic event */
	uint reissue_timeout;		/**< timeout per search, 0 = search stopped */
	time_t create_time;			/**< Time at which this search was created */
	uint lifetime;				/**< Initial lifetime (in hours) */
	uint query_emitted;			/**< # of queries emitted since last retry */
	uint32 items;				/**< Items displayed in the GUI */
	uint32 kept_results;		/**< Results we kept for last query */
	unsigned sha1_downloaded;	/**< Amount of SHA1s being tracked */

	/*
	 * For browse-host requests.
	 */

	struct download *download;	/**< Associated download for browse-host */
} search_ctrl_t;

static inline void
search_ctrl_check(const search_ctrl_t * const sch)
{
	g_assert(sch != NULL);
	g_assert(SEARCH_CTRL_MAGIC == sch->magic);
}

/*
 * List of all searches, and of passive searches only.
 */
static pslist_t *sl_search_ctrl;		/**< All searches */
static pslist_t *sl_passive_ctrl;		/**< Only passive searches */

/*
 * Table holding all the active MUIDs for all the searches, pointing back
 * to the searches directly (i.e. it maps MUID -> search_ctrl_t).
 * The keys are not atoms but directly the MUID objects allocated and held
 * in the search's set of MUIDs.
 */
static htable_t *search_by_muid;

static idtable_t *search_handle_map;
static query_hashvec_t *query_hashvec;

/**
 * This structure is used to map the query MUIDs we relay as an ultrapeer with
 * the corresponding search string and media type filtering requested.
 *
 * We only remember a few of them (as configured by search_muid_track_amount)
 * and focus on the "most active" ones, i.e. attempt to keep alive the ones
 * we see hits for (LRU-type caching).
 */
struct query_desc {
	const guid_t *muid;		/* The query MUID (atom) */
	const char *query;		/* Query string, UTF-8 canonized (atom) */
	unsigned media_mask;	/* The requested media mask (0 if none) */
};

static hash_list_t *query_muids;	/* hashed by MUID, to manage LRU cache */
static htable_t *sha1_to_search;	/* Downloaded SHA1 -> search handle */

/**
 * The legacy "What's New?" query string.
 */
static const char WHATS_NEW_QUERY[] = "WhatIsNewXOXO";
static const char WHATS_NEW[] = "What's New?";

#define WHATS_NEW_TTL		2		/**< Low TTL for issued "What's New?" */
#define WHATS_NEW_DELAY		300		/**< One "What's New?" every 5 minutes */

static time_t search_last_whats_new;	/**< When we last sent "What's New?" */

static bool search_reissue_timeout_callback(void *data);

static uint
query_desc_hash(const void *key)
{
	const struct query_desc *qd = key;

	return guid_hash(qd->muid);
}

static bool
query_desc_eq(const void *a, const void *b)
{
	const struct query_desc * const qa = a, * const qb = b;

	return guid_eq(qa->muid, qb->muid);
}

static void
query_muid_map_init(void)
{
	query_muids = hash_list_new(query_desc_hash, query_desc_eq);
}

static inline bool
query_muid_map_head_expired(void)
{
	struct query_desc *qd = hash_list_head(query_muids);
	return qd != NULL && !route_exists_for_reply(qd->muid, GTA_MSG_SEARCH);
}

static bool
query_muid_map_remove_oldest(void)
{
	struct query_desc *qd;

	qd = hash_list_head(query_muids);
	if (qd != NULL) {
		hash_list_remove(query_muids, qd);
		atom_guid_free_null(&qd->muid);
		atom_str_free_null(&qd->query);
		WFREE(qd);
		return TRUE;
	} else {
		return FALSE;	/* Nothing else to remove */
	}
}

static void
query_muid_map_close(void)
{
	while (query_muid_map_remove_oldest())
		continue;

	hash_list_free(&query_muids);
}

static void
query_muid_map_garbage_collect(void)
{
	uint removed = 0;
	uint32 max;

	/*
	 * When not running as an Ultrapeer, there is no need for us to track
	 * queries since we're not relaying any hits and the only hits we're
	 * going to get are the ones for our own queries.
	 */

	max = settings_is_ultra() ? GNET_PROPERTY(search_muid_track_amount) : 0;

	/*
	 * We remove LRU entries if the list is too long or LRU entries for
	 * which the MUID has expired in the routing table, meaning we would
	 * not be able to route back any hits we would get bearing this MUID.
	 */

	while (
		hash_list_length(query_muids) > max ||
		query_muid_map_head_expired()
	) {
		if (!query_muid_map_remove_oldest())
			break;

		/*
		 * If search_muid_track_amount was lowered drastically, there might
		 * be thousands of items to remove. If there is too much to be
		 * removed, we abort and come back later to prevent stalling.
		 */

		if (++removed > 100)	/* arbitrary limit */
			break;
	}

	gnet_stats_set_general(GNR_QUERY_TRACKED_MUIDS,
		hash_list_length(query_muids));
}

/**
 * Associate a query message ID with the query string and the media filter.
 */
void
record_query_string(const guid_t *muid, const char *query, unsigned media_types)
{
	g_assert(muid);
	g_assert(query);

	if (GNET_PROPERTY(search_muid_track_amount) > 0) {
		const void *orig_key;
		struct query_desc qk;

		qk.muid = muid;

		if (hash_list_find(query_muids, &qk, &orig_key)) {
			/*
			 * Already know, keep the query we have, assuming the query
			 * string and media types will be identical: MUIDs for queries
			 * are supposedly unique, and if they aren't, there is nothing
			 * useful we can do about it anyway.
			 *
			 * Move the key to the tail of the list to keep this query active.
			 */

			hash_list_moveto_tail(query_muids, orig_key);
		} else {
			struct query_desc *qd;
			char *canonized;

			/*
			 * New query must be remembered and put at the tail of the list.
			 */

			WALLOC(qd);
			canonized = UNICODE_CANONIZE(query);
			qd->muid = atom_guid_get(muid);
			qd->query = atom_str_get(canonized);
			qd->media_mask = media_types;
			if (canonized != query)
				HFREE_NULL(canonized);

			hash_list_append(query_muids, qd);
		}
	}
	query_muid_map_garbage_collect();
}

/**
 * @param muid			the query MUID for which we want the query string
 * @param media_mask	where media mask is written if MUID is known
 *
 * @return the query string associated with the given message ID, or NULL
 * if we can't find any.  The ``media_mask'' is filled with the known media
 * types requested.  The query string is in UTF-8 canonic form.
 */
static const char *
map_muid_to_query_string(const guid_t *muid, unsigned *media_mask)
{
	const void *key;
	struct query_desc qk;

	g_assert(muid != NULL);
	g_assert(media_mask != NULL);

	/*
	 * Relayed MUID of queries (as an ultrapeer) are stored in the "query_muids"
	 * hash list, whereas those of our searches are kept in the search mapping
	 * table.
	 *
	 * This ensures that we are always able to reconstruct the query strings
	 * for the hits we receive out of our own queries.
	 */

	qk.muid = muid;

	if (hash_list_find(query_muids, &qk, &key)) {
		const struct query_desc *qd = key;
		g_assert(qd != NULL);

		/*
		 * Move MUID to the tail of the list so that we remember it for a
		 * longer period of time, given that we're seeing query hits.
		 */

		hash_list_moveto_tail(query_muids, qd);		/* LRU cache management */
		*media_mask = qd->media_mask;
		return qd->query;
	} else {
		search_ctrl_t *sch = htable_lookup(search_by_muid, muid);
		if (sch != NULL && sch->query != NULL) {
			*media_mask = sch->media_type;
			return sch->query;
		}
	}

	return NULL;
}

/**
 * Supply a string representation of media type mask.
 *
 * @return pointer to static string
 */
const char *
search_media_mask_to_string(unsigned mask)
{
	static char buf[80];
	str_t *str = str_new(sizeof buf);

	if (mask & SEARCH_AUDIO_TYPE)
		STR_CAT(str, "audio");
	if (mask & SEARCH_VIDEO_TYPE) {
		if (str_len(str) != 0)
			str_putc(str, '/');
		STR_CAT(str, "video");
	}
	if (mask & SEARCH_DOC_TYPE) {
		if (str_len(str) != 0)
			str_putc(str, '/');
		STR_CAT(str, "document");
	}
	if (mask & SEARCH_IMG_TYPE) {
		if (str_len(str) != 0)
			str_putc(str, '/');
		STR_CAT(str, "image");
	}
	if (mask & SEARCH_WIN_TYPE) {
		if (str_len(str) != 0)
			str_putc(str, '/');
		STR_CAT(str, "archive (win)");
	}
	if (mask & SEARCH_UNIX_TYPE) {
		if (str_len(str) != 0)
			str_putc(str, '/');
		STR_CAT(str, "archive (unix)");
	}
	if (mask & SEARCH_TORRENT_TYPE) {
		if (str_len(str) != 0)
			str_putc(str, '/');
		STR_CAT(str, "torrent");
	}

	cstr_bcpy(ARYLEN(buf), str_2c(str));
	str_destroy(str);

	return buf;
}

/**
 * Is supplied GUESS query key (within GGEP "QK" extension) valid?
 *
 * @param n		the node which sent the query
 * @param exv	the extension value
 *
 * @return TRUE if query key is valid.
 */
static bool
search_query_key_validate(const gnutella_node_t *n, const extvec_t *exv)
{
	size_t len = ext_paylen(exv);
	const char *payload;
	sectoken_t tok;

	g_assert(EXT_GGEP == exv->ext_type);
	g_assert(EXT_T_GGEP_QK == exv->ext_token);

	if (len != sizeof tok.v)
		return FALSE;

	payload = ext_payload(exv);
	memcpy(tok.v, payload, sizeof tok.v);

	return sectoken_is_valid(guess_stg, &tok, n->addr, n->port);
}

/**
 * Fills valid query key into supplied security token for the given addr:port.
 */
void
search_query_key_generate(sectoken_t *tok, host_addr_t addr, uint16 port)
{
	if (GNET_PROPERTY(guess_server_debug) > 10) {
		g_debug("GUESS generating token for %s",
			host_addr_port_to_string(addr, port));
	}

	sectoken_generate(guess_stg, tok, addr, port);
}

static inline search_ctrl_t *
search_find_by_handle(gnet_search_t n)
{
	return idtable_get_value(search_handle_map, n);
}

static inline search_ctrl_t *
search_probe_by_handle(gnet_search_t n)
{
	return idtable_probe_value(search_handle_map, n);
}

static inline gnet_search_t
search_request_handle(search_ctrl_t *sch)
{
	return idtable_new_id(search_handle_map, sch);
}

static inline void
search_drop_handle(gnet_search_t n)
{
    idtable_free_id(search_handle_map, n);
}

/***
 *** Callbacks (private and public)
 ***/

static listeners_t search_got_results_listeners;

void
search_got_results_listener_add(search_got_results_listener_t l)
{
	LISTENER_ADD(search_got_results, l);
}

void
search_got_results_listener_remove(search_got_results_listener_t l)
{
	LISTENER_REMOVE(search_got_results, l);
}

static void
search_fire_got_results(pslist_t *sch_matched,
	const guid_t *muid, const gnet_results_set_t *rs)
{
    g_assert(rs != NULL);

	LISTENER_EMIT(search_got_results, (sch_matched, muid, rs));
}

static listeners_t search_status_change_listeners;

void
search_status_change_listener_add(search_status_change_listener_t l)
{
	LISTENER_ADD(search_status_change, l);
}

void
search_status_change_listener_remove(search_status_change_listener_t l)
{
	LISTENER_REMOVE(search_status_change, l);
}

static void
search_status_changed(gnet_search_t search_handle)
{
	LISTENER_EMIT(search_status_change, (search_handle));
}

/***
 *** Management of the "sent_nodes" hash table.
 ***/

static void
search_free_sent_node(const void *key, void *unused_udata)
{
	const gnet_host_t *host = key;

	(void) unused_udata;

	atom_host_free(host);
}

static void
search_free_sent_nodes(search_ctrl_t *sch)
{
	hset_foreach(sch->sent_nodes, search_free_sent_node, NULL);
	hset_free_null(&sch->sent_nodes);
}

static void
search_reset_sent_nodes(search_ctrl_t *sch)
{
	hset_foreach(sch->sent_nodes, search_free_sent_node, NULL);
	hset_clear(sch->sent_nodes);
}

static void
search_mark_sent_to_node(search_ctrl_t *sch, const gnutella_node_t *n)
{
	gnet_host_t sd;

	gnet_host_set(&sd, n->addr, n->port);
	hset_insert(sch->sent_nodes, atom_host_get(&sd));
}

static void
search_mark_sent_to_connected_nodes(search_ctrl_t *sch)
{
	const pslist_t *sl;

	PSLIST_FOREACH(node_all_gnet_nodes(), sl) {
		gnutella_node_t *n = sl->data;

		node_check(n);

		if (NODE_IS_WRITABLE(n))
			search_mark_sent_to_node(sch, n);
	}
}

static void
search_mark_query_sent(search_ctrl_t *sch)
{
	wd_kick(sch->activity);
}

/***
 *** Management of the "sent_node_ids" hash table.
 ***/

static void
free_node_id(const void *key, void *unused_udata)
{
	const struct nid *node_id = key;

	(void) unused_udata;
	nid_unref(node_id);
}

static void
search_free_sent_node_ids(search_ctrl_t *sch)
{
	hset_foreach(sch->sent_node_ids, free_node_id, NULL);
	hset_free_null(&sch->sent_node_ids);
}

static void
search_reset_sent_node_ids(search_ctrl_t *sch)
{
	hset_foreach(sch->sent_node_ids, free_node_id, NULL);
	hset_clear(sch->sent_node_ids);
}

static void
search_mark_sent_to_node_id(search_ctrl_t *sch, const struct nid *node_id)
{
	if (!hset_contains(sch->sent_node_ids, node_id)) {
		const struct nid *key = nid_ref(node_id);
		hset_insert(sch->sent_node_ids, key);
	}
}

/**
 * @return TRUE if we already queried the given node for the given search.
 */
static bool
search_already_sent_to_node(const search_ctrl_t *sch, const gnutella_node_t *n)
{
	gnet_host_t sd;

	gnet_host_set(&sd, n->addr, n->port);
	return hset_contains(sch->sent_nodes, &sd);
}

/**
 * Free the alternate locations held within a file record.
 */
void
search_free_alt_locs(gnet_record_t *rc)
{
	gnet_host_vec_free(&rc->alt_locs);
}

/**
 * Free the push proxies held within a result set.
 */
static void
search_free_proxies(gnet_results_set_t *rs)
{
	g_assert(rs);
	gnet_host_vec_free(&rs->proxies);
}

/**
 * Free one file record.
 */
static void
search_free_record(gnet_record_t *rc)
{
	g_assert(rc);

	if (!(SR_ATOMIZED & rc->flags)) {
		if (SR_ALLOC_NAME & rc->flags) {
			char *p = deconstify_char(rc->filename);
			if (p != NULL)
				hfree(p);
		}
		rc->filename = NULL;
	}
	atom_str_free_null(&rc->filename);
	atom_str_free_null(&rc->tag);
	atom_str_free_null(&rc->xml);
	atom_str_free_null(&rc->path);
	atom_sha1_free_null(&rc->sha1);
	atom_tth_free_null(&rc->tth);
	search_free_alt_locs(rc);
	WFREE(rc);
}

static gnet_results_set_t *
search_new_r_set(void)
{
	gnet_results_set_t *rs;

	WALLOC0(rs);
	return rs;
}

/**
 * Free one results_set.
 */
static void
search_free_r_set(gnet_results_set_t *rs)
{
	pslist_t *m;

	PSLIST_FOREACH(rs->records, m) {
		search_free_record(m->data);
	}
	atom_guid_free_null(&rs->guid);
	atom_str_free_null(&rs->version);
	atom_str_free_null(&rs->hostname);
	atom_str_free_null(&rs->query);
	search_free_proxies(rs);

	pslist_free_null(&rs->records);
	WFREE(rs);
}


static gnet_record_t *
search_record_new(void)
{
	gnet_record_t *rc;

	WALLOC0(rc);
	rc->create_time = (time_t) -1;
	return rc;
}

/**
 * This checks XML data appended to search results for action URL spam. It's
 * a weak heuristic but it should be sufficient for now. Gnoozle and others
 * exploit a feature of LimeWire and sends results for faked, non-existent
 * files with bogus SHA-1s. This has been fixed in LimeWire, so there's no
 * need to invest too much into it and it can probably be removed in a couple
 * of months from now (2006-12-20).
 *
 * Extended to look for FUD based spam (2011-01-14).
 *
 * @param data The buffer to scan.
 * @param size The size of the buffer.
 * @return TRUE if spam was detected, FALSE if it looks alright.
 */
static bool
is_lime_xml_spam(const char * const data, size_t size)
{
	if (size > 0) {
		static const char schema[] = "http://www.limewire.com/schemas/";
		const char *p;

		g_assert(data);
		p = compat_memmem(data, size, schema, CONST_STRLEN(schema));
		if (p) {
			static const char action[] = " action=\"http://";
			static const char fud[] = "WWW" "." "LIMEWIRE" "LAW" "." "COM";

			p += CONST_STRLEN(schema);
			size -= p - data;

			if (compat_memmem(p, size, action, CONST_STRLEN(action)))
				return TRUE;
			if (compat_memmem(p, size, fud, CONST_STRLEN(fud)))
				return TRUE;
		}
	}
	return FALSE;
}

/**
 * Normalizes characters from an URL (partially or completely) encoded
 * string.
 * Conversion rules:
 *
 * '\' -> '/'
 * %HH -> decoded character; %00 is not treated specially.
 * % or %H, as well as all other characters are kept as-is.
 *
 * @param p A pointer to a string.
 * @param endptr A pointer to the next character; this necessary for
 *	      decoding %HH sequences as we skip 3 bytes in this case instead
 *        of one.
 * @return The normalized character.
 */
static inline char
url_normalize_char(const char *p, const char **endptr)
{
	char c;

	g_assert(p);
	g_assert(endptr);

	c = *p;
	if ('\\' == c) {
		c = '/';
	} else if ('%' == c) {
		int hi, lo;

		if G_UNLIKELY(0 == hex2int_inline('a'))
			misc_init();	/* Auto-initialization of hex2int_inline() */

		hi = hex2int_inline(p[1]);
		if (hi >= 0) {
			lo = hex2int_inline(p[2]);
			if (lo >= 0) {
				c = (hi << 4) | lo;
				p += 2;
			}
		}
	}

	*endptr = ++p;
	return c;
}

/**
 * Some clients add paths to filenames, that is they contain '/' or '\'. We
 * tolerate this but we consider "/../" and variants as evil because
 * it can be abused in combination with poorly written clients.
 */
static bool
is_evil_filename(const char *filename)
{
	const char *endptr, *p = filename;
	char win[4];
	uint i;

	g_assert(filename);

	win[0] = '/';	/* Implicit by "/get/<index>/<filename>" */

	for (i = 1; i < N_ITEMS(win); i++) {
		win[i] = url_normalize_char(p, &endptr);
		if ('\0' == *p)
			break;
		p = endptr;
	}

	for (;;) {
		if (
			'/' == win[0] && (
				0 == memcmp(win, "/", 2) ||
				0 == memcmp(win, "/.", 3) ||
				0 == memcmp(win, "/..", 4) ||
				0 == memcmp(win, "/../", 4)
			)
		) {
			return TRUE;
		}

		if ('\0' == *p)
			break;
		p = endptr;

		win[0] = win[1];
		win[1] = win[2];
		win[2] = win[3];
		win[3] = url_normalize_char(p, &endptr);
	}
	return FALSE;
}

#define RS_STATUS(x)	{ ST_ ## x, #x }

static struct {
	uint32 flag;
	const char *name;
} rs_status_flags[] = {
	RS_STATUS(SR_UDP),
	RS_STATUS(BANNED_GUID),
	RS_STATUS(MEDIA),
	RS_STATUS(ALIEN),
	RS_STATUS(GUESS),
	RS_STATUS(MORPHEUS_BOGUS),
	RS_STATUS(GOOD_TOKEN),
	RS_STATUS(BROWSE),
	RS_STATUS(LOCAL),
	RS_STATUS(FW2FW),
	RS_STATUS(HOSTILE),
	RS_STATUS(UNREQUESTED),
	RS_STATUS(EVIL),
	RS_STATUS(G2),
	RS_STATUS(UNUSED_4),
	RS_STATUS(UNUSED_3),
	RS_STATUS(UNUSED_2),
	RS_STATUS(UNUSED_1),
	RS_STATUS(SPAM),
	RS_STATUS(TLS),
	RS_STATUS(BH),
	RS_STATUS(KNOWN_VENDOR),
	RS_STATUS(PARSED_TRAILER),
	RS_STATUS(UDP),
	RS_STATUS(BOGUS),
	RS_STATUS(PUSH_PROXY),
	RS_STATUS(GGEP),
	RS_STATUS(UPLOADED),
	RS_STATUS(BUSY),
	RS_STATUS(FIREWALL),
};

#undef RS_STATUS

/**
 * Convert result set status flags into English description.
 */
static const char *
search_rs_status_to_string(const gnet_results_set_t *rs)
{
	str_t *s = str_private(G_STRFUNC, 80);
	uint i;

	str_reset(s);

	for (i = 0; i < N_ITEMS(rs_status_flags); i++) {
		if (rs->status & rs_status_flags[i].flag) {
			if (0 != str_len(s))
				STR_CAT(s, ", ");
			str_cat(s, rs_status_flags[i].name);
		}
	}

	return str_2c(s);
}

#define RC_STATUS(x)	{ SR_ ## x, #x }

static struct {
	uint32 flag;
	const char *name;
} rc_flags[] = {
	RC_STATUS(ALLOC_NAME),
	RC_STATUS(MEDIA),
	RC_STATUS(PARTIAL_HIT),
	RC_STATUS(PUSH),
	RC_STATUS(ATOMIZED),
	RC_STATUS(PARTIAL),
	RC_STATUS(OWNED),
	RC_STATUS(SHARED),
	RC_STATUS(SPAM),
	RC_STATUS(DONT_SHOW),
	RC_STATUS(IGNORED),
	RC_STATUS(DOWNLOADED),
};

#undef RC_STATUS

/**
 * Convert result record flags into English description.
 */
static const char *
search_rc_flags_to_string(const gnet_record_t *rc)
{
	str_t *s = str_private(G_STRFUNC, 80);
	uint i;

	str_reset(s);

	for (i = 0; i < N_ITEMS(rc_flags); i++) {
		if (rc->flags & rc_flags[i].flag) {
			if (0 != str_len(s))
				STR_CAT(s, ", ");
			str_cat(s, rc_flags[i].name);
		}
	}

	return str_2c(s);
}

/**
 * Log query hit.
 */
static void
search_results_log(const gnutella_node_t *n, const gnet_results_set_t *rs)
{
	char buf[128];
	str_t *s = str_new(80);

	if (n != NULL) {
		if (NODE_TALKS_G2(n)) {
			g2_msg_infostr_to_buf(n->data, n->size, ARYLEN(buf));
		} else {
			gmsg_infostr_full_split_to_buf(
				&n->header, n->data, n->size, ARYLEN(buf));
		}
	} else {
		buf[0] = '\0';
	}

	if (
		n != NULL && NODE_IS_UDP(n) &&
		!(host_addr_equiv(n->addr, rs->addr) && n->port == rs->port)
	) {
		str_printf(s, "%s UDP=%s",
			host_addr_port_to_string(rs->addr, rs->port),
			host_addr_port_to_string2(n->addr, n->port));
	} else {
		str_printf(s, "%s", host_addr_port_to_string(rs->addr, rs->port));
	}

	g_debug("SEARCH %s QHIT [%s] (%s [%s], %s) %s: %u rec%s {%s}",
		NULL == n ? "NULL" : NODE_IS_UDP(n) ? "UDP" : "TCP",
		vendor_code_to_string(rs->vcode.u32),
		str_2c(s), iso3166_country_cc(rs->country), guid_to_string(rs->guid),
		buf, PLURAL(rs->num_recs),
		search_rs_status_to_string(rs));

	str_destroy_null(&s);
}

/**
 * Log query hit records.
 */
static void
search_results_records_log(const gnutella_node_t *n,
	const gnet_results_set_t *rs)
{
	pslist_t *sl;
	uint nr = 0;
	str_t *s = str_new(80);
	char buf[128];

	if (n != NULL) {
		if (NODE_TALKS_G2(n)) {
			g2_msg_infostr_to_buf(n->data, n->size, ARYLEN(buf));
		} else {
			gmsg_infostr_full_split_to_buf(
				&n->header, n->data, n->size, ARYLEN(buf));
		}
	} else {
		buf[0] = '\0';
	}

	g_debug("SEARCH %s QHIT [%s] (%s) %u rec%s {%s}:",
		NULL == n ? "NULL" : NODE_IS_UDP(n) ? "UDP" : "TCP",
		vendor_code_to_string(rs->vcode.u32),
		host_addr_port_to_string(rs->addr, rs->port),
		PLURAL(rs->num_recs),
		search_rs_status_to_string(rs));

	PSLIST_FOREACH(rs->records, sl) {
		const gnet_record_t *rc = sl->data;
		char *f;
		size_t len;

		nr++;

		len = 1 + vstrlen(rc->filename);
		f = halloc(len);
		ascii_enforce(f, len, rc->filename);		/* Safe logging */

		if (rc->path != NULL) {
			char *p;

			len = 1 + vstrlen(rc->path);
			p = halloc(len);
			ascii_enforce(p, len, rc->path);
			str_printf(s, "name=\"%s\", path=\"%s\"", f, p);
			hfree(p);
		} else {
			str_printf(s, "name=\"%s\"", f);
		}

		HFREE_NULL(f);

		str_catf(s, ", size=%s", filesize_to_string(rc->size));

		if (rc->flags & SR_PARTIAL_HIT)
			str_catf(s, ", avail=%s", filesize_to_string(rc->available));

		if (rc->sha1 != NULL)
			str_catf(s, ", sha1=%s", sha1_base32(rc->sha1));

		if (rc->tth != NULL)
			str_catf(s, ", tth=%s", tth_base32(rc->tth));

		g_debug("SEARCH REC #%u/%u: %s {%s}",
			nr, rs->num_recs, str_2c(s), search_rc_flags_to_string(rc));
	}

	str_destroy_null(&s);
}

/**
 * Log spam reason.
 */
static void G_PRINTF(3, 4)
search_log_spam(const gnutella_node_t *n, const gnet_results_set_t *rs,
	const char *reason, ...)
{
	char rbuf[384];
	char buf[128];

	if (!GNET_PROPERTY(log_spam_query_hit))
		return;

	if (n != NULL) {
		if (NODE_TALKS_G2(n)) {
			g2_msg_infostr_to_buf(n->data, n->size, ARYLEN(buf));
		} else {
			gmsg_infostr_full_split_to_buf(
				&n->header, n->data, n->size, ARYLEN(buf));
		}
	} else {
		buf[0] = '\0';
	}

	if (reason) {
		va_list args;
		unsigned off = 0;
		va_start(args, reason);
		if (n != NULL) {
			rbuf[0] = ':';
			rbuf[1] = ' ';
			off = 2;
		}
		str_vbprintf(ARYPOSLEN(rbuf, off), reason, args);
		va_end(args);
	} else {
		rbuf[0] = '\0';
	}

	g_debug("SPAM QHIT [%s] (%s) %s %s%s",
		vendor_code_to_string(rs->vcode.u32),
		host_addr_port_to_string(rs->addr, rs->port),
		NULL == n ? "==>" : node_infostr(n), buf, rbuf);
}

static inline void
search_results_set_spam(gnet_results_set_t *rs, unsigned flag)
{
	rs->status |= ST_SPAM;		/* Indicates that set carries SPAM */
	rs->spam |= flag;
}

static void
search_results_identify_dupes(const gnutella_node_t *n, gnet_results_set_t *rs,
	hostiles_flags_t *hostile)
{
	htable_t *ht = htable_create(HASH_KEY_SELF, 0);
	pslist_t *sl;
	unsigned dups = 0;

	/*
	 * Since we fake the file indices for G2 hits, skip the file index tests!
	 */

	if (ST_G2 & rs->status)
		goto sha1_check;

	/* Look for identical file index */
	PSLIST_FOREACH(rs->records, sl) {
		gnet_record_t *rc;
		const void *key;

		rc = sl->data;
		key = ulong_to_pointer(rc->file_index);
		if (htable_contains(ht, key)) {
			search_results_set_spam(rs, SPAM_F_DUP);
			*hostile |= HSTL_DUP_INDEX;
			rc->flags |= SR_SPAM;
			dups++;
			search_log_spam(n, rs, "duplicate file index %u", rc->file_index);
		} else {
			htable_insert(ht, key, rc);
		}
	}

sha1_check:

	/* Look for identical SHA-1 */
	PSLIST_FOREACH(rs->records, sl) {
		gnet_record_t *rc;
		const void *key;

		rc = sl->data;
		key = rc->sha1;
		if (NULL == key)
			continue;

		if (htable_contains(ht, key)) {
			search_results_set_spam(rs, SPAM_F_DUP);
			*hostile |= HSTL_DUP_SHA1;
			rc->flags |= SR_SPAM;
			dups++;
			search_log_spam(n, rs, "duplicate SHA1 %s", sha1_base32(rc->sha1));
		} else {
			htable_insert(ht, key, rc);
		}
	}

	if (rs->spam & SPAM_F_DUP)
		gnet_stats_inc_general(GNR_SPAM_DUP_HITS);

	htable_free_null(&ht);

	if (dups != 0) {
		search_log_spam(n, rs, "--> %u duplicate%s over %u item%s",
			PLURAL(dups), PLURAL(rs->num_recs));
	}
}

static bool
is_odd_guid(const guid_t *guid)
{
	size_t i = N_ITEMS(guid->v);

	do {
		unsigned char c = guid->v[--i];

		if (c < 0xaaU || (c & 0x0fU) < 0x0aU)
			return FALSE;
	} while (i > 0);
	return TRUE;
}

static bool
is_lime_return_path(const extvec_t *e)
{
	const char *id = ext_ggep_id_str(e);
	const char *s;

	s = is_strprefix(id, "RP");		/* Return Path */
	if (NULL == s)
		return FALSE;

	/*
	 * "RP" followed by a letter then by digit(s).
	 *
	 * This seems to be a trail left by each relaying LimeWire which
	 * yields information about the IP:port of the servent which received
	 * the message ("RPI"), the source from which it was received ("RPS"),
	 * along with TTL ("RPT") and hops ("RPH") information.
	 *
	 * Each relaying host increments the trailing digits, so it is possible
	 * to reconstruct the full message path from this information, as long
	 * as it was relayed through LimeWire hosts.
	 *
	 * Certainly great for debugging, but what a waste and silly format (it
	 * was probably easier to hack this feature in that way, grr....).
	 */

	return s[0] != '\0' && is_ascii_digit(s[1]);
}

/**
 * Mark fake spam.
 */
static void
search_results_mark_fake_spam(gnet_results_set_t *rs, hostiles_flags_t *hostile)
{
	if (!(rs->spam & SPAM_F_FAKE)) {
		/* Count only once per result set */
		gnet_stats_inc_general(GNR_SPAM_FAKE_HITS);
		search_results_set_spam(rs, SPAM_F_FAKE);
		*hostile |= HSTL_FAKE_SPAM;
	}
}

/**
 * Mark close filename spam.
 */
static void
search_results_mark_close_filename_spam(
	const gnutella_node_t *n,
	gnet_results_set_t *rs, gnet_record_t *rc, hostiles_flags_t *hostile)
{
	search_results_mark_fake_spam(rs, hostile);

	if (GNET_PROPERTY(log_spam_query_hit)) {
		char *f;
		size_t len;

		len = 1 + vstrlen(rc->filename);
		f = halloc(len);
		ascii_enforce(f, len, rc->filename);

		search_log_spam(n, rs, "filename \"%s\" similar to query \"%s\"",
			f, rs->query);

		hfree(f);
	}

	rc->flags |= SR_SPAM;
	*hostile |= HSTL_CLOSE_FILENAME;
}

static bool
is_evil_timestamp(time_t t)
{
	switch (t) {
	case 0x45185160:
	case 0x45186D80:
	case 0x34AC60DE:
		return TRUE;
	}
	return FALSE;
}

static inline bool
search_results_from_spammer(const gnet_results_set_t *rs)
{
	/*
	 * Spam other than listed URNs/names or accidental duplicates is never
	 * sent by innocent peers,
	 */

	return 0 != (rs->spam & ~(SPAM_F_URN | SPAM_F_NAME | SPAM_F_DUP));
}

static inline bool
search_results_from_country(const gnet_results_set_t *rs, const char *cc)
{
	return 0 == strcmp(cc, iso3166_country_cc(rs->country));
}

/*
 * Is filename similar to the query string?
 *
 * @param filename		filename from search results
 * @param query			canonized UTF-8 query string
 *
 * @attention
 * The filename must be valid UTF-8, a precondition for canonization.
 */
static bool
search_filename_similar(const char *filename, const char *query)
{
	char *filename_canonic;
	bool result;
	size_t qlen = vstrlen(query);
	size_t flen;
	const char *ext;

	filename_canonic = UNICODE_CANONIZE(filename);
	flen = vstrlen(filename_canonic);
	ext = vstrrchr(filename_canonic, ' ');	/* Last word */

	result = NULL != is_strprefix(filename_canonic, query);

	if (!result && ext != NULL) {
		size_t len = ptr_diff(ext, filename_canonic);

		/* Look before the extension */

		if (len > qlen) {
			const char *base = ext - qlen;
			result = NULL != is_strprefix(base, query);
		}
	}

	/*
	 * Avoid false positives:
	 *
	 * - if the query string is small (less than 6 chars) or has only 1 word,
	 *   then it must represent at least 50% of the results to be a "hit".
	 *
	 * - otherwise, the query string must be at least 85% of the results.
	 */

	if (result) {
		double ratio = 0.85;

		if (ext != NULL)
			flen -= vstrlen(ext);		/* Remove extension chars */

		if (0 == flen)
			flen = 1;

		if (qlen <= 6 || NULL == vstrchr(query, ' '))
			ratio = 0.50;

		if (qlen / (double) flen < ratio)
			result = FALSE;				/* Not enough chars overall */
	}

	if (filename_canonic != filename)
		hfree(filename_canonic);

	return result;
}

static void
search_results_identify_spam(const gnutella_node_t *n, gnet_results_set_t *rs,
	hostiles_flags_t *hostile)
{
	const pslist_t *sl;
	uint8 has_ct = 0, has_tth = 0, has_xml = 0, expected_xml = 0;
	bool logged = FALSE;

	PSLIST_FOREACH(rs->records, sl) {
		gnet_record_t *rc = sl->data;
		unsigned n_alt;

		n_alt = rc->alt_locs ? gnet_host_vec_count(rc->alt_locs) : 0;

		if (SR_SPAM & rc->flags) {
			/*
			 * Avoid costly check if already marked as spam.
			 */
		} else if ((uint32)-1 == rc->file_index) {
			/*
			 * Some spammers get this wrong but some version of LimeWire
			 * start counting at zero despite this being a special wildcard
			 */
			rc->flags |= SR_SPAM;
			*hostile |= HSTL_BAD_FILE_INDEX;
			search_log_spam(n, rs, "file index set to -1");
			logged = TRUE;
		} else if (!rc->file_index && T_GTKG == rs->vcode.u32) {
			search_results_mark_fake_spam(rs, hostile);
			search_log_spam(n, rs, "hit with invalid file index");
			logged = TRUE;
			rc->flags |= SR_SPAM;
			*hostile |= HSTL_BAD_FILE_INDEX | HSTL_GTKG;
		} else if (
			T_GTKG == rs->vcode.u32 &&
			(
				NULL == rs->version ||
				!guid_is_gtkg(rs->guid, NULL, NULL, NULL)
			)
		) {
			search_results_mark_fake_spam(rs, hostile);
			search_log_spam(n, rs, "hit with %s",
				NULL == rs->version ? "no version indication" : "bad GUID");
			logged = TRUE;
			rc->flags |= SR_SPAM;
			*hostile |= HSTL_GTKG |
				(NULL == rs->version ?
					HSTL_NO_GTKG_VERSION : HSTL_BAD_GTKG_GUID);
		} else if (n_alt > 16 || (T_LIME == rs->vcode.u32 && n_alt > 10)) {
			search_results_mark_fake_spam(rs, hostile);
			search_log_spam(n, rs, "hit with %u alt-locs", n_alt);
			logged = TRUE;
			rc->flags |= SR_SPAM;
			*hostile |= HSTL_MANY_ALT_LOCS;
		} else if (rc->sha1 && spam_sha1_check(rc->sha1)) {
			search_log_spam(n, rs, "URN %s", sha1_base32(rc->sha1));
			logged = TRUE;
			search_results_set_spam(rs, SPAM_F_URN);
			*hostile |= HSTL_URN_SPAM;
			rc->flags |= SR_SPAM;
			gnet_stats_inc_general(GNR_SPAM_SHA1_HITS);
		} else if (
			T_LIME == rs->vcode.u32 &&
			is_evil_timestamp(rc->create_time)
		) {
			search_results_mark_fake_spam(rs, hostile);
			search_log_spam(n, rs, "evil timestamp 0x%lx",
				(unsigned long) rc->create_time);
			logged = TRUE;
			rc->flags |= SR_SPAM;
			*hostile |= HSTL_EVIL_TIMESTAMP;
		} else if (spam_check_filename_size(rc->filename, rc->size)) {
			search_log_spam(n, rs, "SPAM filename/size hit");
			logged = TRUE;
			search_results_set_spam(rs, SPAM_F_NAME);
			*hostile |= HSTL_NAME_SPAM;
			rc->flags |= SR_SPAM;
			gnet_stats_inc_general(GNR_SPAM_NAME_HITS);
		} else if (
			rc->xml &&
			is_lime_xml_spam(rc->xml, vstrlen(rc->xml))
		) {
			search_log_spam(n, rs, "LIME XML SPAM");
			logged = TRUE;
			search_results_set_spam(rs, SPAM_F_URL);
			*hostile |= HSTL_URL_SPAM;
			rc->flags |= SR_SPAM;
		} else if (is_evil_filename(rc->filename)) {
			search_log_spam(n, rs, "evil filename");
			logged = TRUE;
			rs->status |= ST_EVIL;
			*hostile |= HSTL_EVIL_FILENAME;
			rc->flags |= SR_IGNORED;
		} else if (
			T_LIME == rs->vcode.u32 &&
			!utf8_is_valid_string(rc->filename)
		) {
			/* LimeWire is a program known to generate valid UTF-8 strings */
			search_results_mark_fake_spam(rs, hostile);
			search_log_spam(n, rs, "invalid UTF-8 filename");
			logged = TRUE;
			rc->flags |= SR_SPAM;
			*hostile |= HSTL_BAD_UTF8;
		} else if (
			T_LIME == rs->vcode.u32 && rs->query != NULL &&
			0 == strcmp(rs->query, WHATS_NEW_QUERY) &&
			is_strcaseprefix(rc->filename, WHATS_NEW_QUERY)
		) {
			/* All genuine LimeWire nodes understand "What's New?" queries */
			search_results_mark_fake_spam(rs, hostile);
			search_log_spam(n, rs, "filename mimics query \"%s\"",
				WHATS_NEW_QUERY);
			logged = TRUE;
			rc->flags |= SR_SPAM;
			*hostile |= HSTL_NO_WHATS_NEW;
		}

		has_tth |= NULL != rc->tth;
		has_xml |= NULL != rc->xml;
		has_ct  |= (time_t)-1 != rc->create_time;

		/*
		 * LimeWire normally sends XML data when it's requested in the query
		 * or when the hit is delivered via UDP (OOB or direct GUESS), for
		 * AVI and MPG files, and for MP3 files.
		 *
		 * We request XML in our queries, but we can't know whether other
		 * servents will so we can only determine whether XML is indeed
		 * expected for OOB hits or for our own queries.
		 */

		if (
			T_LIME == rs->vcode.u32 && !expected_xml &&
			(
				rs->query != NULL ||						/* We queried */
				(0 == rs->hops && (ST_UDP & rs->status))	/* OOB hit */
			)
		) {
			const char *ext = vstrrchr(rc->filename, '.');

			if (
				ext++ != NULL &&			/* Skip '.' */
				(
					0 == strcasecmp(ext, "avi") ||
					0 == strcasecmp(ext, "mpg") ||
					0 == strcasecmp(ext, "mp3")
				)
			) {
				expected_xml = TRUE;
			}
		}

		/*
		 * Popular TCP-relayed spam, in reply to our queries.
		 */

		if (
			0 == (SR_SPAM & rc->flags) &&
			T_LIME == rs->vcode.u32 && rs->query != NULL &&
			0 == ((ST_UDP | ST_TLS) & rs->status)
		) {
			/*
			 * We know rc->filename is a valid UTF-8 string because otherwise
			 * the record would have been flagged as SR_SPAM above.
			 *
			 * Likewise, rs->query comes from our map recording queries, and
			 * we don't insert invalid UTF-8 encoded strings.
			 *
			 * This makes it safe for search_filename_similar() to attempt
			 * UTF-8 canonization.
			 */

			if (
				(
					2 == n_alt &&
					search_filename_similar(rc->filename, rs->query)
				) || (
					0 == ((ST_UPLOADED | ST_BH | ST_FIREWALL | ST_PUSH_PROXY)
						& rs->status) &&
					search_filename_similar(rc->filename, rs->query)
				)
			) {
				search_results_mark_close_filename_spam(n, rs, rc, hostile);
				logged = TRUE;
			}
		}

		/*
		 * Popular G2 spam.
		 */

		if (
			(ST_G2 & rs->status) && rs->query != NULL &&
			search_filename_similar(rc->filename, rs->query)
		) {
			search_results_mark_close_filename_spam(n, rs, rc, hostile);
			logged = TRUE;
		}

		/*
		 * If we already determined that these results come from a spammer,
		 * there's no need to inspect the other records.
		 */

		if (search_results_from_spammer(rs)) {
			search_log_spam(logged ? NULL : n, rs, "hit from spammer");
			goto flag_all;
		}
	}

	if (!is_vendor_acceptable(rs->vcode)) {
		/* A proper vendor code is mandatory */
		search_results_mark_fake_spam(rs, hostile);
		search_log_spam(n, rs, "improper vendor code");
		*hostile |= HSTL_BAD_VENDOR_CODE;
	} else if (expected_xml && !has_xml) {
		/**
		 * LimeWire adds XML metadata for AVI and MPG files
		 * which may be merged into the trailer for all records.
		 * Make an exception for Cabos popular in Japan.
		 */
		if (!search_results_from_country(rs, "jp")) {
			search_results_mark_fake_spam(rs, hostile);
			search_log_spam(n, rs, "was expecting XML");
			*hostile |= HSTL_MISSING_XML;
		}
	} else if (
		T_LIME == rs->vcode.u32 &&
		!has_ct &&
		(!has_xml || !search_results_from_country(rs, "jp"))
	) {
		/**
		 * If there are no timestamps, this is most-likely not from LimeWire.
		 * Cabos frequently fails to add timestamps for unknown reasons.
		 * Make an exception for Cabos popular in Japan.
		 */
		search_results_mark_fake_spam(rs, hostile);
		search_log_spam(n, rs, "no CT");
		*hostile |= HSTL_NO_CREATE_TIME;
	} else if (is_odd_guid(rs->guid)) {
		search_results_mark_fake_spam(rs, hostile);
		search_log_spam(n, rs, "odd GUID %s", guid_hex_str(rs->guid));
		*hostile |= HSTL_ODD_GUID;
	} else if (guid_is_banned(rs->guid)) {
		rs->status |= ST_BANNED_GUID;
		*hostile |= HSTL_BANNED_GUID;
		search_log_spam(n, rs, "banned GUID %s", guid_hex_str(rs->guid));
	} else if (0 == ((ST_SPAM | ST_BROWSE) & rs->status)) {
		/*
		 * Avoid costly checks if already marked as spam.
		 * Skip duplicate checks for host browsing since they may share files
		 * with hard links and different names, or even true duplicates.
		 */
		search_results_identify_dupes(n, rs, hostile);
	}

	if (search_results_from_spammer(rs)) {
		search_log_spam(NULL, rs, "hit from spammer, finally");
		goto flag_all;
	}

	return;

flag_all:
	/*
	 * Mark all records of the set as spam.
	 */

	PSLIST_FOREACH(rs->records, sl) {
		gnet_record_t *rc = sl->data;
		rc->flags |= SR_SPAM;
	}
}

/**
 * Check whether we have explicitly claimed some OOB hits.
 *
 * @param muid	the query MUID used, as seen from the query hit
 * @param addr	the address from which the results come via UDP
 * @param port	the port from which results come
 */
static bool
search_results_are_requested(const guid_t *muid,
	const host_addr_t addr, uint16 port, uint32 token)
{
	sectoken_t tok;
	gnet_host_t host;

	STATIC_ASSERT(sizeof(uint32) == sizeof tok.v);

	gnet_host_set(&host, addr, port);
	if (!aging_lookup(ora_secure, &host))
		return TRUE;		/* Host not supporting secure OOB */

	poke_be32(tok.v, token);
	return sectoken_is_valid_with_context(ora_stg,
		&tok, addr, port, muid, GUID_RAW_SIZE);
}

/**
 * Log multiple GGEP occurrences in trailer if needed.
 *
 * @param n			node from which we got the message
 * @param e			the GGEP extension
 * @param vendor	the vendor code string
 */
static void
search_log_multiple_ggep(const gnutella_node_t *n,
	const extvec_t *e, const char *vendor)
{
	g_assert(EXT_GGEP == e->ext_type);

	if (GNET_PROPERTY(search_debug) || GNET_PROPERTY(ggep_debug)) {
		if (vendor != NULL) {
			g_warning("%s from %s has multiple GGEP \"%s\" (ignoring)",
				gmsg_node_infostr(n), vendor, ext_ggep_id_str(e));
		} else {
			g_warning("%s has multiple GGEP \"%s\" (ignoring)",
				gmsg_node_infostr(n), ext_ggep_id_str(e));
		}
	}
}

/**
 * Log GGEP occurrences in trailer if needed.
 *
 * @param n			node from which we got the message
 * @param e			the GGEP extension
 * @param vendor	the vendor code string
 * @param what		adjective describing what is wrong about GGEP extension
 */
static void
search_log_ggep(const gnutella_node_t *n,
	const extvec_t *e, const char *vendor, const char *what)
{
	g_assert(EXT_GGEP == e->ext_type);

	if (GNET_PROPERTY(search_debug) > 3 || GNET_PROPERTY(ggep_debug) > 3) {
		if (vendor != NULL) {
			g_warning("%s from %s has %s GGEP \"%s\"%s",
				gmsg_node_infostr(n), vendor, what, ext_ggep_id_str(e),
				GNET_PROPERTY(ggep_debug) > 5 ? " (dumping)" : "");
		} else {
			g_warning("%s has %s GGEP \"%s\"%s",
				gmsg_node_infostr(n), what, ext_ggep_id_str(e),
				GNET_PROPERTY(ggep_debug) > 5 ? " (dumping)" : "");
		}
		if (GNET_PROPERTY(ggep_debug) > 5) {
			ext_dump(stderr, e, 1, "....", "\n", TRUE);
		}
	}
}

/**
 * Log bad GGEP occurrences in trailer if needed.
 *
 * @param n			node from which we got the message
 * @param e			the GGEP extension
 * @param vendor	the vendor code string
 */
static void
search_log_bad_ggep(const gnutella_node_t *n,
	const extvec_t *e, const char *vendor)
{
	search_log_ggep(n, e, vendor, "bad");
}

/**
 * Log unknown GGEP occurrences in trailer if needed.
 *
 * @param n			node from which we got the message
 * @param rs		the result set
 * @param e			the GGEP extension
 * @param vendor	the vendor code string
 */
static void
search_log_unknown_ggep(const gnutella_node_t *n,
	const gnet_results_set_t *rs,
	const extvec_t *e, const char *vendor)
{
	if (GNET_PROPERTY(search_debug) <= 3 && GNET_PROPERTY(ggep_debug) <= 3)
		return;

	/*
	 * Avoid logging unknown GGEP extensions for LimeWire's return-path,
	 * which we don't want to parse anyway (and since they're dynamic and
	 * not fixed, we wouldn't be able to parse them given our current
	 * zero-copy extension parsing implementation).
	 *		--RAM, 2009-11-04
	 */

	if ((T_LIME == rs->vcode.u32 || rs->hops > 0) && is_lime_return_path(e))
		return;

	search_log_ggep(n, e, vendor, "unknown");
}

/**
 * Add synthetized push-proxy to the results.
 */
static void
search_add_push_proxy(gnet_results_set_t *rs, host_addr_t addr, uint16 port)
{
	if (NULL == rs->proxies) {
		rs->proxies = gnet_host_vec_alloc();
	}
	if (!gnet_host_vec_contains(rs->proxies, addr, port)) {
		gnet_host_vec_add(rs->proxies, addr, port);
	}
}

/**
 * Build a string atom representing the GGEP version information.
 */
static const char *
search_results_version(const struct ggep_gtkgv *vi)
{
	version_ext_t ver;

	ZERO(&ver);
	ver.version.major = vi->major;
	ver.version.minor = vi->minor;
	ver.version.patchlevel = vi->patch;
	ver.version.tag = vi->revchar;
	ver.version.build = vi->build;
	if (ver.version.tag)
		ver.version.timestamp = vi->release;
	ver.commit_len = vi->commit_len;
	ver.commit = vi->commit;		/* Struct copy */
	ver.osname = vi->osname;		/* Static string */
	ver.dirty = vi->dirty;

	return atom_str_get(version_ext_str(&ver, TRUE));
}

/**
 * Compute status bits, decompile trailer info, if present.
 *
 * @return TRUE if there were errors and the packet should be dropped.
 */
static bool
search_results_handle_trailer(const gnutella_node_t *n,
	gnet_results_set_t *rs, const char *trailer, size_t trailer_size,
	hostiles_flags_t *hostile)
{
	uint8 open_size, open_parsing_size, enabler_mask, flags_mask;
	const char *vendor;
	uint32 token;
	bool has_token;
	host_addr_t ipv6_addr;
	bool has_ipv6_addr;

	if (!trailer || trailer_size < 7)
		return FALSE;

	vendor = vendor_get_name(rs->vcode);
	vendor = vendor != NULL ? vendor : "unknown vendor";
	open_size = trailer[4];
	open_parsing_size = trailer[4];
	enabler_mask = trailer[5];
	flags_mask = trailer[6];
	has_token = FALSE;
	token = 0;
	has_ipv6_addr = FALSE;

	if (open_size > trailer_size - 4) {
		if (GNET_PROPERTY(search_debug)) {
			g_warning("trailer from %s is too small (%u byte%s) "
				"for open size field", vendor,
				(unsigned) PLURAL(trailer_size));
		}
		return TRUE;
	} else if (open_size == 4) {
		open_parsing_size = 2;		/* We ignore XML data size */
	}

	if (T_NAPS == rs->vcode.u32) {
		/*
		 * NapShare has a one-byte only flag: no enabler, just setters.
		 *		--RAM, 17/12/2001
		 */
		if (open_size == 1) {
			if (enabler_mask & 0x04) rs->status |= ST_BUSY;
			if (enabler_mask & 0x01) rs->status |= ST_FIREWALL;
			rs->status |= ST_PARSED_TRAILER;
		}
	} else {
		if (open_parsing_size == 2) {
			uint8 status = enabler_mask & flags_mask;
			if (status & 0x04) rs->status |= ST_BUSY;
			if (status & 0x01) rs->status |= ST_FIREWALL;
			if (status & 0x08) rs->status |= ST_UPLOADED;
			if (status & 0x20) rs->status |= ST_GGEP;
			rs->status |= ST_PARSED_TRAILER;
		} else if (rs->status & ST_KNOWN_VENDOR) {
			if (GNET_PROPERTY(search_debug) > 1)
				g_warning("vendor %s changed # of open data bytes to %d",
						vendor, open_size);
		} else {
			if (GNET_PROPERTY(search_debug) > 1)
				g_warning("ignoring %d open data byte%s from %s",
						PLURAL(open_size), vendor);
		}
	}

	/*
	 * Parse trailer after the open data, if we have a GGEP extension.
	 */

	if (rs->status & ST_GGEP) {
		const char *priv;
		size_t privlen;
		int exvcnt = 0;
		extvec_t exv[MAX_EXTVEC];
		bool seen_ggep = FALSE;
		gnet_host_vec_t *hvec = NULL;		/* For GGEP "PUSH" */

		int i;

		if (trailer_size >= (size_t) open_size + 5) {
			priv = &trailer[5 + open_size];
			privlen = &trailer[trailer_size] - priv;
		} else {
			priv = NULL;
			privlen = 0;
		}
		if (privlen > 0) {
			ext_prepare(exv, MAX_EXTVEC);
			exvcnt = ext_parse(priv, privlen, exv, MAX_EXTVEC);
		}

		for (i = 0; i < exvcnt; i++) {
			extvec_t *e = &exv[i];
			ggept_status_t ret;

			if (e->ext_type == EXT_GGEP)
				seen_ggep = TRUE;

			switch (e->ext_token) {
			case EXT_T_GGEP_BH:
				rs->status |= ST_BH;
				break;
			case EXT_T_GGEP_FW:
				rs->status |= ST_FW2FW;
				break;
			case EXT_T_GGEP_TLS:
			case EXT_T_GGEP_GTKG_TLS:	/* Deprecated for 0.97 */
				rs->status |= ST_TLS;
				break;
			case EXT_T_GGEP_SO:
				if ((ST_UDP & rs->status) && ext_paylen(e) == sizeof token) {
					memcpy(&token, ext_payload(e), sizeof token);
					has_token = TRUE;
				}
				break;
			case EXT_T_GGEP_6:			/* IPv6-Ready */
			case EXT_T_GGEP_GTKG_IPV6:	/* Deprecated for 0.97 */
				if (has_ipv6_addr) {
					search_log_multiple_ggep(n, e, vendor);
				} else if (ext_paylen(e) != 0) {
					ret = ggept_gtkg_ipv6_extract(e, &ipv6_addr);
					if (GGEP_OK == ret) {
						has_ipv6_addr = TRUE;
						/*
						 * The extracted IPv6 address supersedes the IPv4 one
						 * when it is 127.0.0.0, per IPv6-Ready specs, or
						 * when they have not configured IPv4 support.
						 */
						if (
							ipv6_ready_no_ipv4_addr(rs->addr) ||
							!settings_use_ipv4()
						) {
							rs->addr = ipv6_addr;
						}
					} else if (ret == GGEP_INVALID) {
						search_log_bad_ggep(n, e, vendor);
					}
				}
				break;
			case EXT_T_GGEP_GTKGV1:		/* Deprecated @0.97, now uses GTKGV */
				if (NULL != rs->version) {
					search_log_multiple_ggep(n, e, vendor);
				} else {
					struct ggep_gtkgv1 vi;

					ret = ggept_gtkgv1_extract(e, &vi);
					if (ret == GGEP_OK) {
						static const version_t zero_ver;
						version_t ver = zero_ver;

						ver.major = vi.major;
						ver.minor = vi.minor;
						ver.patchlevel = vi.patch;
						ver.tag = vi.revchar;
						/* Build information valid after 2006-08-27 */
						if (vi.release >= 1156629600)
							ver.build = vi.build;
						if (ver.tag)
							ver.timestamp = vi.release;

						rs->version = atom_str_get(version_str(&ver));
					} else if (ret == GGEP_INVALID) {
						search_log_bad_ggep(n, e, vendor);
					}
				}
				break;
			case EXT_T_GGEP_GTKGV:
				if (NULL != rs->version) {
					search_log_multiple_ggep(n, e, vendor);
				} else {
					struct ggep_gtkgv vi;

					ret = ggept_gtkgv_extract(e, &vi);
					if (ret == GGEP_OK) {
						rs->version = search_results_version(&vi);
					} else if (ret == GGEP_INVALID) {
						search_log_bad_ggep(n, e, vendor);
					}
				}
				break;
			case EXT_T_GGEP_PUSH:
				if (NULL != rs->proxies && rs->proxies->n_ipv4 != 0) {
					search_log_multiple_ggep(n, e, vendor);
				} else if (settings_running_ipv4()) {
					rs->status |= ST_PUSH_PROXY;
					/* Allocates new hvec or reuses existing one */
					ret = ggept_push_extract(e, &hvec, NET_TYPE_IPV4);
					if (ret == GGEP_OK) {
						rs->proxies = hvec;
					} else {
						search_log_bad_ggep(n, e, vendor);
					}
				}
				break;
			case EXT_T_GGEP_PUSH6:
				if (NULL != rs->proxies && rs->proxies->n_ipv6 != 0) {
					search_log_multiple_ggep(n, e, vendor);
				} else if (settings_running_ipv6()) {
					rs->status |= ST_PUSH_PROXY;
					/* Allocates new hvec or reuses existing one */
					ret = ggept_push_extract(e, &hvec, NET_TYPE_IPV6);
					if (ret == GGEP_OK) {
						rs->proxies = hvec;
					} else {
						search_log_bad_ggep(n, e, vendor);
					}
				}
				break;
			case EXT_T_GGEP_HNAME:
				if (NULL != rs->hostname) {
					search_log_multiple_ggep(n, e, vendor);
				} else {
					char hostname[MAX_HOSTLEN];

					ret = ggept_hname_extract(e, ARYLEN(hostname));
					if (ret == GGEP_OK)
						rs->hostname = atom_str_get(hostname);
					else {
						search_log_bad_ggep(n, e, vendor);
					}
				}
				break;
			case EXT_T_XML:
				{
					size_t paylen = ext_paylen(e);
					gnet_record_t *rc;

					/* FIXME: Add the XML data to the next best record.
					 *		Maybe better to all? It's just an atom.
					 */
					rc = rs->records ? rs->records->data : NULL;
					if (rc && !rc->xml && paylen > 0) {
						char buf[4096];

						clamp_strncpy(ARYLEN(buf), ext_payload(e), paylen);
						if (utf8_is_valid_string(buf)) {
							rc->xml = atom_str_get(buf);
						}
					}
				}
				break;
			case EXT_T_UNKNOWN_GGEP:	/* Unknown GGEP extension */
				search_log_unknown_ggep(n, rs, e, vendor);

				/*
				 * Only LimeWire (including derivatives) is known to tag
				 * its query hits with "return path" GGEP extensions.
				 */

				if (
					T_LIME != rs->vcode.u32 && 0 == rs->hops &&
					is_lime_return_path(e)
				) {
					search_results_mark_fake_spam(rs, hostile);
				}
				break;
			default:
				break;
			}
		}

		if (exvcnt == MAX_EXTVEC) {
			if (GNET_PROPERTY(search_debug) > 0) {
				g_warning("%s from %s has %d trailer extensions!",
					gmsg_node_infostr(n), vendor, exvcnt);
			}
			if (GNET_PROPERTY(search_debug) > 2)
				ext_dump(stderr, exv, exvcnt, "> ", "\n", TRUE);
			if (GNET_PROPERTY(search_debug) > 3 && priv)
				dump_hex(stderr, "Query Hit private data", priv, privlen);
		} else if (!seen_ggep && GNET_PROPERTY(ggep_debug)) {
			g_warning("%s from %s claimed GGEP extensions in trailer, "
					"seen none",
					gmsg_node_infostr(n), vendor);
		} else if (GNET_PROPERTY(search_debug) > 2) {
			g_debug("%s from %s has %d trailer extensions:",
					gmsg_node_infostr(n), vendor, exvcnt);
			ext_dump(stderr, exv, exvcnt, "> ", "\n", TRUE);
		}

		if (exvcnt)
			ext_reset(exv, MAX_EXTVEC);
	} else {
		if (is_lime_xml_spam(trailer, trailer_size)) {
			search_results_set_spam(rs, SPAM_F_URL);
			*hostile |= HSTL_URL_SPAM;
		}
	}

	/*
	 * Check whether the results were actually requested.
	 *
	 * GUESS ultrapeers can forward hits from their leaves that they would
	 * get from TCP, so we have to check for hops=0 as well.
	 */

	if (0 == rs->hops && (ST_UDP & rs->status)) {
		const guid_t *muid = gnutella_header_get_muid(&n->header);

		if (!has_token)
			token = 0;

		if (search_results_are_requested(muid, n->addr, n->port, token)) {
			if (has_token) {
				rs->status |= ST_GOOD_TOKEN;
			}
			/* We can send PUSH requests directly, so add it as push proxy. */
			search_add_push_proxy(rs, n->addr, n->port);
		} else {
			rs->status |= ST_UNREQUESTED;
			/* Most probably fake since it came unrequested */
			search_results_set_spam(rs, SPAM_F_FAKE);
			/* Count only as unrequested, not as fake spam */
			gnet_stats_inc_general(GNR_UNREQUESTED_OOB_HITS);
			*hostile |= HSTL_OOB;

			if (
				GNET_PROPERTY(search_debug) > 1 ||
				GNET_PROPERTY(secure_oob_debug)
			) {
				char buf[9];
				bin_to_hex_buf(VARLEN(token), ARYLEN(buf));
				g_debug("OOB received unrequested %squery hit #%s "
					"from %s%s%s [%s]",
					guess_is_search_muid(muid) ? "GUESS " : "",
					guid_hex_str(muid), node_infostr(n),
					has_token ? ", wrong token=0x" : ", no token",
					has_token ? buf : "",
					vendor_code_to_string(rs->vcode.u32));
			}
		}

		/* If we have a token and did not mark hit as hostile, check source */

		if (
			((ST_GOOD_TOKEN | ST_HOSTILE) & rs->status) == ST_GOOD_TOKEN &&
			hostiles_is_bad(n->addr)
		) {
			if (GNET_PROPERTY(search_debug) > 1) {
				hostiles_flags_t flags = hostiles_check(n->addr);
				g_debug("dropping UDP query hit from secure OOB: "
					"hostile IP %s (%s)",
					host_addr_to_string(n->addr),
					hostiles_flags_to_string(flags));
			}
			rs->status |= ST_HOSTILE;
		}
	}

	/*
	 * If the peer has an IPv6 address, we can use that as push proxy, too.
	 */

	if (
		has_ipv6_addr &&
		rs->port > 0 &&
		is_host_addr(ipv6_addr) &&
		settings_running_ipv6() &&
		!hostiles_is_bad(ipv6_addr)
	) {
		search_add_push_proxy(rs, ipv6_addr, rs->port);
	}

	return FALSE;	/* no errors */
}

/**
 * Perform sanity checks on the result set once we have fully parsed it
 * successfully.
 */
static void
search_results_postprocess(const gnutella_node_t *n, gnet_results_set_t *rs,
	const guid_t *muid, hostiles_flags_t *hostile)
{
	/*
	 * Hits relayed through UDP are necessarily a response to a GUESS query.
	 */

	if (1 == rs->hops && (ST_UDP & rs->status)) {
		if (guess_is_search_muid(muid)) {
			/*
			 * The relaying ultrapeer is necessarily a push-proxy for the node.
			 */
			search_add_push_proxy(rs, n->addr, n->port);
		} else {
			search_results_mark_fake_spam(rs, hostile);
			*hostile |= HSTL_UDP_GUESS;

			if (GNET_PROPERTY(search_debug) > 1) {
				g_debug("received non-GUESS UDP query hit with hops=1 from %s",
                	node_infostr(n));
			}
		}
	}

	/*
	 * Hits sent through TCP with hops=1 (i.e. relayed by another ultrapeer)
	 * have necessarily that ultrapeer as a possible push-proxy for the
	 * remote host.
	 *
	 * NOTE: when parsing results, we decrease the hop count by 1 when not
	 * dealing with browse results to undo the effect of route_message().
	 * Hence the hop count is an indication of the number of relaying peers,
	 * not the number of hops the message went through.
	 */

	if (1 == rs->hops && !(ST_UDP & rs->status)) {
		/*
		 * The relaying node is an ultrapeer by construction, hence it
		 * cannot be firewalled and has a direct connection to the
		 * answering node => can act as a push-proxy.
		 *
		 * NOTE: we use the known Gnutella address/port, if known, and
		 * not the connected address/port which may be different for an
		 * incoming connection.
		 */

		if (host_address_is_usable(n->gnet_addr)) {
			search_add_push_proxy(rs, n->gnet_addr, n->gnet_port);
		} else {
			search_add_push_proxy(rs, n->addr, n->port);
		}
	}
}

/**
 * Decode LimeWire's encoding of the available intervals in the file, held
 * in the "PRi" extension they are using to encode the ranges as numbers.
 *
 * Numbers are taken from a binary tree starting at 1 and spanning as deep as
 * necessary to have at least enough leaves to cover all the 1 KiB blocks of
 * the file.
 *
 * @param n		the node sending us the results with partial file (for logging)
 * @param e		the GGEP "PRi" extension, for i = 1..4
 * @param size	the total file size
 *
 * @return the size encoded by the intervals of the extension `e'.
 */
static filesize_t
lime_range_decode(const gnutella_node_t *n, const extvec_t *e, filesize_t size)
{
	int i;
	size_t len;

	switch (e->ext_token) {
	case EXT_T_GGEP_PR1: i = 1; break;		/* 1-byte values */
	case EXT_T_GGEP_PR2: i = 2; break;		/* 2-byte values */
	case EXT_T_GGEP_PR3: i = 3; break;		/* 3-byte values */
	case EXT_T_GGEP_PR4: i = 4; break;		/* 4-byte values */
	default:
		g_soft_assert(FALSE);
		return 0;
	}

	if (size < 1024)
		return size;

	len = ext_paylen(e);
	if (0 != len % i) {
		search_log_bad_ggep(n, e, NULL);
		return 0;
	} else {
		const uint8 *p = ext_payload(e);
		unsigned j;
		filesize_t leaves, power, result = 0, nodemax;

		leaves = size >> 10;	/* # of leaves (1 KiB blocks) in the tree */
		if (0 != size % 1024)
			leaves++;

		/*
		 * "power" indicates the starting index of the last row of the
		 * binary tree spanned by 1:
		 *
		 *                            1
		 *                           / \
		 *                          2   3
		 *                         / \ / \
		 *              power ->  4  5 6  7  (4 leaves)
		 *                        :  : :  :
		 * file block numbers ->  0  1 2  3  (1 KiB each)
		 *
		 * "power" is the first power of 2 spanning the leaves of the tree.
		 * Here, with 4 leaves, we can represent files of at most 4 blocks
		 * of 1 KiB, i.e ranging from 0 bytes to 4 KiB.
		 *
		 * Hence, "power" is the smallest power of 2 such that leaves <= power.
		 *
		 * The maximum node ID, "nodemax" is 7, the last number before
		 * going to the next power of 2 (next row, if we had one).  However,
		 * if we have only 3 leaves, then "nodemax" is 6: we have to
		 * substract "power - leaves" to "2 * power  -1" to get the proper
		 * maximum ID.
		 */

		if (IS_POWER_OF_2(leaves)) {
			power = leaves;
		} else {
			power = (uint64) 1 << (1 + highest_bit_set64(leaves));
		}
		g_assert(leaves <= power);

		nodemax = 2 * power - 1 - (power - leaves);

		/*
		 * Decompile big-endian node numbers (total of len / i)
		 */

		for (j = 0; j < len; j += i) {
			int depth, k;
			filesize_t node;			/* The node ID in the tree */
			filesize_t start, end;		/* Block numbers in the file */

			/* Read node #j as a big-endian number over i bytes */

			for (node = 0, k = 0; k < i; k++) {
				node <<= 8;
				node |= p[j + k] & 0xff;
			}

			/*
			 * Determine the start and end indices of the blocks from the file.
			 */

			if (node < 1 || node > nodemax)
				continue;		/* Invalid node number */

			if (1 == node)
				return size;	/* 1 is the root of the tree, we're done! */

			depth = 0;
			while (node < power) {
				depth++;
				node <<= 1;
			}

			if (node > nodemax)
				continue;

			start = node - power;
			end = start + ((uint64) 1 << depth) - 1;

			/* Leaves may not cover whole depth, therefore adjust */
			end = MIN(end, nodemax - power);

			result += 1024 * (end - start + 1);
		}

		return result;
	}
	g_assert_not_reached();
}

/**
 * Cleanup the result record.
 */
static void
search_record_cleanup(gnet_record_t *rc)
{
	/*
	 * If the hit is flagged as partial, yet the remote server has 100% of
	 * the file, clear the partial indication.
	 */

	if (rc->available >= rc->size) {
		rc->available = 0;
		rc->flags &= ~SR_PARTIAL_HIT;
	}
}

/**
 * Perform address sanity check on result set and set flags accordingly.
 *
 * @param rs		the result set being constructed
 * @param n			the node from which the hit comes
 * @param browse	whether hit comes from a host browsing
 */
static void
search_validate_result_address(gnet_results_set_t *rs,
	const gnutella_node_t *n, bool browse)
{
	/*
	 * Hits coming from UDP should bear the node's address, unless the
	 * hit has a private IP because the servent did not determine its
	 * own IP address yet or is firewalled (in which case the address should
	 * be a private one).
	 */

	if (NODE_IS_UDP(n)) {
		rs->status |= ST_UDP;

		if (NODE_CAN_SR_UDP(n))
			rs->status |= ST_SR_UDP;

		if (
			0 == rs->hops &&	/* GUESS ultrapeers can relay hits over UDP */
			!host_addr_equiv(n->addr, rs->addr) &&
			host_addr_is_routable(rs->addr)
		) {
			rs->status |= ST_ALIEN;
			gnet_stats_inc_general(GNR_OOB_HITS_WITH_ALIEN_IP);
		}
	}

	/* Check for hostile IP addresses */

	if (hostiles_is_bad(rs->addr)) {
		if (GNET_PROPERTY(search_debug) > 1) {
			hostiles_flags_t flags = hostiles_check(rs->addr);
			g_debug("dropping %s %s %s by %s: hostile source at %s (%s)",
				NODE_IS_UDP(n) ? "UDP" : "TCP",
				NODE_TALKS_G2(n) ? "/QH2" : "query hit",
				NODE_IS_UDP(n) ?
					(0 == rs->hops ? "issued" : "relayed") : "relayed",
				host_addr_to_string(n->addr), host_addr_to_string2(rs->addr),
				hostiles_flags_to_string(flags));
		}
		rs->status |= ST_HOSTILE;
	}

	if (browse) {
		rs->status |= ST_BROWSE;
		if (!host_addr_is_routable(rs->addr)) {
			/*
			 * Sometimes peers report a private IP address in the results
			 * even though they're TCP connectible.
			 */
			rs->addr = n->addr;
		}
	}

	/* Check for valid IP addresses (unroutable => turn push on) */
	if (!host_addr_is_routable(rs->addr)) {
		rs->status |= ST_FIREWALL;
	} else if (rs->port == 0 || bogons_check(rs->addr)) {
        if (GNET_PROPERTY(search_debug)) {
            g_warning("%s advertising bogus IP %s",
				gmsg_node_infostr(n),
				host_addr_port_to_string(rs->addr, rs->port));
        }
		rs->status |= ST_BOGUS | ST_FIREWALL;
	}
}

/**
 * Validate that the GUID held in the hit is correct.
 *
 * @param rs		the result set being constructed
 * @param n			the node from which the hit comes
 * @param muid		the MUID of the search
 *
 * @return NULL if OK, a pointer to an error string otherwise.
 */
static const char *
search_validate_guid(gnet_results_set_t *rs,
	gnutella_node_t *n, const guid_t *muid)
{
	if (guid_eq(rs->guid, GNET_PROPERTY(servent_guid))) {
        gnet_stats_count_dropped(n, MSG_DROP_OWN_RESULT);
		if (0 == rs->hops) {
			n->n_weird++;
			if (GNET_PROPERTY(search_debug) > 1) {
				g_warning("[weird #%d] %s sending our own results with hops=0",
					 n->n_weird, node_infostr(n));
			}
		}
		return "own result";
	}

	/* Very funny */
	if (guid_eq(rs->guid, muid)) {
		gnet_stats_count_dropped(n, MSG_DROP_BAD_RESULT);
		return "bad MUID";
	}

	if (guid_eq(rs->guid, &blank_guid)) {
		gnet_stats_count_dropped(n, MSG_DROP_BLANK_SERVENT_ID);
		return "blank GUID";
	}

	return NULL;	/* OK */
}

/**
 * Finalize information in the results set.
 *
 * @param rs		the result set being constructed
 * @param muid		the MUID of the search
 * @param browse	whether we're processing a hit from a "browse host"
 */
static void
search_finalize_results(gnet_results_set_t *rs, const guid_t *muid, bool browse)
{
	{
		host_addr_t c_addr;

		/*
		 * Prefer an UDP source IP for the country computation.
		 *
		 * Have to check for hops=0 since GUESS ultrapeeers can route back
		 * query hits returned via TCP from their leaves.
		 */

		c_addr = (0 == rs->hops && (rs->status & ST_UDP)) ?
			rs->last_hop : rs->addr;
		rs->country = gip_country(c_addr);

		/*
		 * If we're not only validating (i.e. we're going to peruse this hit),
		 * and if the server is marking its hits with the Push flag, check
		 * whether it is already known to wrongly set that bit.
		 *		--RAM, 18/08/2002.
		 */

		if (
			(rs->status & ST_FIREWALL) &&
			download_server_nopush(rs->guid, rs->addr, rs->port)
		) {
			rs->status &= ~ST_FIREWALL;		/* Clear "Push" indication */
		}
	}

	{
		const char *query;
		unsigned media_mask = 0;

		query = map_muid_to_query_string(muid, &media_mask);
		rs->query = query != NULL ? atom_str_get(query) : NULL;

		/*
		 * The field rs->media is only 8 bits, but we rely on the fact that
		 * the currently architected media types all fit in one single byte.
		 * This allows us to store the media type in the results without
		 * really increasing the memory requirements (uses padding space).
		 */

		rs->media = media_mask;

		if (NULL == query && !browse && settings_is_ultra()) {
			gnet_stats_inc_general(GNR_QUERY_HIT_FOR_UNTRACKED_QUERY);
		}

		/*
		 * Morpheus ignores all non-ASCII characters in query strings
		 * which results in completely bogus results. For example, if you
		 * search for "<chinese>.txt" every filename ending with .txt will
		 * match!
		 */

		if (
			T_MRPH == rs->vcode.u32 &&
			rs->query != NULL && !is_ascii_string(rs->query)
		) {
			pslist_t *sl;

			rs->status |= ST_MORPHEUS_BOGUS;
			PSLIST_FOREACH(rs->records, sl) {
				gnet_record_t *record = sl->data;
				record->flags |= SR_DONT_SHOW | SR_IGNORED;
			}
		}

		/*
		 * If we have a non-zero media type filter for the query, then
		 * look whether at least one of the records matches.  Otherwise,
		 * it's bye-bye.
		 */

		if (query != NULL && media_mask != 0) {
			pslist_t *sl;
			size_t matching = 0;
			bool own_query = htable_contains(search_by_muid, muid);

			PSLIST_FOREACH(rs->records, sl) {
				gnet_record_t *rc = sl->data;
				unsigned mask = share_filename_media_mask(rc->filename);

				if (mask != 0 && !(mask & media_mask)) {
					/*
					 * Not matching the requested media type.
					 *
					 * Hide in the GUI, if it's for one of our queries
					 * otherwise display them as "ignored" (in passive
					 * searches).
					 */

					if (own_query)
						rc->flags |= SR_DONT_SHOW;
					rc->flags |= SR_IGNORED | SR_MEDIA;
				} else {
					matching++;
				}
			}

			if (0 == matching) {
				/* We will not forward this packet */
				rs->status |= ST_MEDIA;		/* Lacking proper media type */
			}
		}
	}
}

static void G_PRINTF(4, 5)
search_record_warn(const gnutella_node_t *n,
	const gnet_results_set_t *rs, size_t hit, const char *fmt, ...)
{
	va_list args;
	char buf[256];

	va_start(args, fmt);
	str_vbprintf(ARYLEN(buf), fmt, args);
	va_end(args);

	if (GNET_PROPERTY(qhit_bad_debug)) {
		if (node_addr_port_equal(n, rs->addr, rs->port)) {
			g_warning("hit record #%zu/%u in %s generated by %s: %s",
				 hit, rs->num_recs, gmsg_node_infostr(n),
				 vendor_code_to_string(rs->vcode.u32),
				 buf);
		} else {
			g_warning("hit record #%zu/%u in %s generated by %s at %s: %s",
				 hit, rs->num_recs, gmsg_node_infostr(n),
				 vendor_code_to_string(rs->vcode.u32),
				 host_addr_port_to_string(rs->addr, rs->port), buf);
		}
	}
}

enum g2_qh2_child {
	G2_QH2_BH = 1,
	G2_QH2_FW,
	G2_QH2_GTKGV,		/* Child is "gtkgV", this is GTKG-specific */
	G2_QH2_GU,
	G2_QH2_H,
	G2_QH2_HN,
	G2_QH2_NA,
	G2_QH2_NH,
	G2_QH2_TLS,
	G2_QH2_V
};

enum g2_qh2_h_child {
	G2_QH2_H_ALT = 1,
	G2_QH2_H_CSC,		/* unparsed (rather useless) */
	G2_QH2_H_CT,
	G2_QH2_H_DN,
	G2_QH2_H_ID,		/* unparsed */
	G2_QH2_H_PART,
	G2_QH2_H_SZ,
	G2_QH2_H_URL,
	G2_QH2_H_URN
};

static const tokenizer_t g2_qh2_children[] = {
	/* Sorted array */
	{ "BH",		G2_QH2_BH },
	{ "FW",		G2_QH2_FW },
	{ "GU",		G2_QH2_GU },
	{ "H",		G2_QH2_H },
	{ "HN",		G2_QH2_HN },
	{ "NA",		G2_QH2_NA },
	{ "NH",		G2_QH2_NH },
	{ "TLS",	G2_QH2_TLS },
	{ "V",		G2_QH2_V },
	{ "gtkgV",	G2_QH2_GTKGV },
};

static const tokenizer_t g2_qh2_h_children[] = {
	/* Sorted array */
	{ "ALT",	G2_QH2_H_ALT },
	{ "CSC",	G2_QH2_H_CSC },
	{ "CT",		G2_QH2_H_CT },
	{ "DN",		G2_QH2_H_DN },
	{ "ID",		G2_QH2_H_ID },
	{ "PART",	G2_QH2_H_PART },
	{ "SZ",		G2_QH2_H_SZ },
	{ "URL",	G2_QH2_H_URL },
	{ "URN",	G2_QH2_H_URN },
};

enum g2_qh2_urn_type {
	URN_SHA1 = 1,
	URN_TTH,
	URN_BITPRINT
};

static const tokenizer_t g2_qh2_urn[] = {
	/* Sorted array */
	{ "bitprint",		URN_BITPRINT },
	{ "bp",				URN_BITPRINT },
	{ "sha1",			URN_SHA1 },
	{ "tree:tiger/",	URN_TTH },
	{ "ttr",			URN_TTH },
};

/**
 * Parse /QH2/H to build a file record.
 *
 * @param t		the /QH2/H tree node
 * @param n		the node from which we got the hit (for logging)
 * @param rs	the result set to which record belongs (for logging)
 * @param hit	hit number within the /QH2 message
 *
 * @return a synthetized file record if OK, NULL on errors.
 */
gnet_record_t *
get_g2_results_record(const g2_tree_t *t, const gnutella_node_t *n,
	const gnet_results_set_t *rs, size_t hit, hostiles_flags_t *hostile)
{
	gnet_record_t *rc;
	const g2_tree_t *c;
	gnet_host_vec_t *hvec = NULL;
	bool has_sz = FALSE, has_url = FALSE;
	const char *badmsg = NULL;

	rc = search_record_new();
	rc->file_index = 1;			/* Not 0, not -1, otherwise does not matter */

	G2_TREE_CHILD_FOREACH(t, c) {
		enum g2_qh2_h_child ct = TOKENIZE(g2_tree_name(c), g2_qh2_h_children);
		const void *payload;
		size_t paylen;

		switch (ct) {
		case G2_QH2_H_ALT:
			payload = g2_tree_node_payload(c, &paylen);
			if (payload != NULL && 0 == paylen % 6 && NULL == hvec) {
				const char *end = const_ptr_add_offset(payload, paylen);
				const char *p = payload;

				hvec = gnet_host_vec_alloc();

				while (p < end) {
					host_addr_t addr = host_addr_peek_ipv4(p);
					uint16 port = peek_le16(&p[4]);
					gnet_host_vec_add(hvec, addr, port);
					p += 6;
				}
			} else {
				if (NULL == payload) {
					badmsg = "no ALT payload";
					goto bad;
				}
				if (hvec != NULL)
					search_record_warn(n, rs, hit, "ignoring duplicate ALT");
				if (paylen % 6 != 0) {
					search_record_warn(n, rs, hit,
						"ignoring ALT (%zu bytes)", paylen);
				}
			}
			break;

		case G2_QH2_H_CT:
			payload = g2_tree_node_payload(c, &paylen);
			if (paylen <= 8) {
				uint64 v = vlint_decode(payload, paylen);
				rc->create_time = MIN(v, TIME_T_MAX);
			}
			break;

		case G2_QH2_H_DN:
			payload = g2_tree_node_payload(c, &paylen);
			if (NULL == payload) {
				badmsg = "no DN payload";
				goto bad;
			}
			if (rc->filename != NULL) {
				badmsg = "duplicate DN payload";
				goto bad;
			}

			/*
			 * We need to probe for "SZ" because when it is present, there
			 * is no file size before the name.
			 */

			if (!has_sz)
				has_sz = NULL != g2_tree_lookup(t, "SZ");

			{
				const char *p = payload;

				if (!has_sz) {
					if (paylen < 4) {
						badmsg = "too small DN payload";
						goto bad;
					}
					rc->size = peek_le32(p);
					p += 4;
					paylen -= 4;
				}

				if (!utf8_is_valid_data(p, paylen)) {
					/*
					 * If there is a SZ record, maybe they included a 32-bit
					 * size before the name as well (broken servent, but
					 * still manageable in that case)?
					 */

					if (has_sz && paylen > 4) {
						if (utf8_is_valid_data(p + 4, paylen - 4)) {
							search_record_warn(n, rs, hit,
								"DN probably had 32-bit size despite SZ");
							p += 4;
							paylen -= 4;
							goto utf8_filename;
						}
					}

					badmsg = has_sz ?
						"DN payload not valid UTF-8" :
						"filename in DN not valid UTF-8";
					*hostile |= HSTL_NON_UTF8;
					goto bad;
				}

			utf8_filename:

				/* Must copy string since it is usually not NUL-terminated */
				rc->filename = h_strndup(p, paylen);
				rc->flags |= SR_ALLOC_NAME;

				/*
				 * Make sure the filename is not empty.
				 */

				if (0 == utf8_strlen(rc->filename)) {
					badmsg = "empty filename";
					goto bad;
				}
			}

			/*
			 * See whether we have a "P" child to indicate the shared path.
			 */

			{
				const g2_tree_t *p = g2_tree_lookup(c, "P");

				if (p != NULL) {
					char buf[1024];
					payload = g2_tree_node_payload(p, &paylen);
					clamp_strncpy(ARYLEN(buf), payload, paylen);
					rc->path = atom_str_get(buf);
				}
			}

			break;

		case G2_QH2_H_PART:
			rc->flags |= SR_PARTIAL_HIT;
			payload = g2_tree_node_payload(c, &paylen);
			if (paylen <= 8)
				rc->available = vlint_decode(payload, paylen);
			else {
				search_record_warn(n, rs, hit,
					"ignoring PART payload (%zu bytes)", paylen);
			}

			/*
			 * See whether we have a "MT" child to hold the last mtime of file.
			 */

			{
				const g2_tree_t *m = g2_tree_lookup(c, "MT");

				if (m != NULL) {
					payload = g2_tree_node_payload(m, &paylen);
					if (paylen >= 4)
						rc->mod_time = peek_le32(payload);
				}
			}

			break;

		case G2_QH2_H_SZ:
			has_sz = TRUE;
			payload = g2_tree_node_payload(c, &paylen);
			if (paylen <= 8)
				rc->size = vlint_decode(payload, paylen);
			else {
				search_record_warn(n, rs, hit,
					"ignoring SZ payload (%zu bytes)", paylen);
			}
			break;

		case G2_QH2_H_URL:
			payload = g2_tree_node_payload(c, &paylen);
			if (payload != NULL) {
				/* TODO: parse URL to see whether it points back to host */
				search_record_warn(n, rs, hit, "ignoring URL payload \"%*s\"",
					(int) paylen, (char *) payload);
			} else {
				has_url = TRUE;
			}
			break;

		case G2_QH2_H_URN:
			payload = g2_tree_node_payload(c, &paylen);
			if (NULL == payload) {
				search_record_warn(n, rs, hit, "ignoring empty URN payload");
			} else {
				char name[16];
				const void *p;
				size_t l, e = 0;
				enum g2_qh2_urn_type type;

				l = clamp_strlen(payload, paylen);
				if (l == paylen) {
					search_record_warn(n, rs, hit,
						"ignoring URN payload with no NUL (%zu bytes)", paylen);
					break;
				}
				clamp_strncpy(ARYLEN(name), payload, l);
				paylen -= l + 1;		/* Skip urn string + NUL */
				p = const_ptr_add_offset(payload, l + 1);
				type = TOKENIZE(name, g2_qh2_urn);
				if (0 == type)
					break;				/* Not the type of URN we want */

				switch (type) {
				case URN_SHA1:		e = SHA1_RAW_SIZE; break;
				case URN_BITPRINT:	e = SHA1_RAW_SIZE + TTH_RAW_SIZE; break;
				case URN_TTH:		e = TTH_RAW_SIZE; break;
				}

				if (paylen != e) {
					search_record_warn(n, rs, hit,
						"ignoring bad URN \"%s\" (%zu-byte long, expected %zu)",
						name, paylen, e);
					break;
				}

				switch (type) {
				case URN_SHA1:
				case URN_BITPRINT:
					if (NULL == rc->sha1) {
						sha1_t sha1;
						memcpy(&sha1, p, SHA1_RAW_SIZE);
						rc->sha1 = atom_sha1_get(&sha1);
					} else {
						search_record_warn(n, rs, hit, "ignoring dup SHA1");
					}
					if (URN_SHA1 == type)
						break;
					p = const_ptr_add_offset(p, SHA1_RAW_SIZE);
					/* FALL THROUGH */
				case URN_TTH:
					if (NULL == rc->tth) {
						tth_t tth;
						memcpy(&tth, p, TTH_RAW_SIZE);
						rc->tth = atom_tth_get(&tth);
					} else {
						search_record_warn(n, rs, hit, "ignoring dup TTH");
					}
					break;
				}
			}
			break;

		case G2_QH2_H_CSC:
		case G2_QH2_H_ID:
			/* Unparsed */
			break;
		}
	}

	/*
	 * The "ALT" locs are only useful if there was a SHA1 present.
	 */

	if (hvec != NULL) {
		if (NULL == rc->sha1) {
			search_record_warn(n, rs, hit, "ignoring ALT since lacking SHA1");
			gnet_host_vec_free(&hvec);
		} else {
			rc->alt_locs = hvec;
		}
	}

	/*
	 * There must be a "DN" since we're always requesting one in our queries.
	 */

	if (NULL == rc->filename) {
		badmsg = "no DN";
		goto bad;
	}

	/*
	 * There must be a "URL", indicating that the servent is sharing the
	 * file using the regular uri-res resolver, otherwise we won't know
	 * how to download the resource so drop it.
	 */

	if (!has_url) {
		badmsg = "no empty URL key, resource unusable";
		goto bad;
	}

	/*
	 * There must be a SHA1 since this is G2 and there is no file index to
	 * request the resource.
	 */

	if (NULL == rc->sha1) {
		badmsg = "no SHA1 found, resource unusable";
		goto bad;
	}

	search_record_cleanup(rc);

	return rc;

bad:
	gnet_host_vec_free(&hvec);
	search_record_warn(n, rs, hit, "skipping bad record: %s", badmsg);
	search_free_record(rc);
	return NULL;
}

/**
 * Parse /QH2 and extract the embedded records.
 *
 * @param n			the node from which we got the hit
 * @param t			the G2 message tree
 * @param browse	whether this hit comes from a browse-host request
 * @param hostile	where hostile indications are consolidated
 *
 * @return a structure describing the whole result set, or NULL if we
 * were unable to parse it properly.
 */
static gnet_results_set_t *
get_g2_results_set(gnutella_node_t *n, const g2_tree_t *t,
	bool browse, hostiles_flags_t *hostile)
{
	gnet_results_set_t *rs;
	const guid_t *muid;
	guid_t muid_buf;
	const void *payload;
	size_t paylen;
	const g2_tree_t *c;
	size_t nr = 0;
	const char *vendor = NULL;
	const char *badmsg = NULL;
	bool has_na = FALSE;

	*hostile = HSTL_CLEAN;
	muid = g2_msg_get_muid(t, &muid_buf);

	if (browse) {
		if (NULL == muid)
			muid = &blank_guid;
	} else {
		/* If we dispatch the results, we extracted the MUID before */
		g_assert(muid != NULL);
	}

	rs = search_new_r_set();
	rs->stamp = tm_time();
	rs->country = ISO3166_INVALID;

	if (browse) {
		rs->hops = 0;
	} else {
		/* Since we extracted the MUID before, there must be a "hops" byte */
		payload = g2_tree_node_payload(t, &paylen);
		g_assert(payload != NULL);
		rs->hops = *(uint8 *) payload;
	}
	gnutella_header_set_hops(&n->header, rs->hops + 1);
	rs->last_hop = n->addr;
	rs->status |= ST_G2 | ST_PARSED_TRAILER;	/* No trailer in G2 */

	/*
	 * Count the number of hits present, so that we know how many valid
	 * hits we parsed in case we have to bail out due to a malformed packet.
	 */

	G2_TREE_CHILD_FOREACH(t, c) {
		if (0 == strcmp(g2_tree_name(c), "H"))
			rs->num_recs++;
	}

	/*
	 * Parse the children.
	 */

	G2_TREE_CHILD_FOREACH(t, c) {
		enum g2_qh2_child ct = TOKENIZE(g2_tree_name(c), g2_qh2_children);

		switch (ct) {
		case G2_QH2_BH:
			rs->status |= ST_BH;
			break;

		case G2_QH2_FW:
			rs->status |= ST_FIREWALL;
			break;

		case G2_QH2_GU:
			payload = g2_tree_node_payload(c, &paylen);
			if (NULL == payload || paylen != GUID_RAW_SIZE) {
				badmsg = NULL == payload ? "no GUID" : "invalid GUID length";
				goto bad_packet;
			}
			rs->guid = atom_guid_get(cast_to_guid_ptr_const(payload));
			badmsg = search_validate_guid(rs, n, muid);
			if (badmsg != NULL)
				goto bad_packet;
			break;

		case G2_QH2_GTKGV:
			payload = g2_tree_node_payload(c, &paylen);
			if (payload != NULL && NULL == rs->version) {
				struct ggep_gtkgv vi;

				if (GGEP_OK == ggept_gtkgv_extract_data(payload, paylen, &vi))
					rs->version = search_results_version(&vi);
			}
			break;

		case G2_QH2_H:
			{
				gnet_record_t *rc;

				nr++;
				rc = get_g2_results_record(c, n, rs, nr, hostile);
				if (rc != NULL)
					rs->records = pslist_prepend(rs->records, rc);
			}
			break;

		case G2_QH2_HN:
			payload = g2_tree_node_payload(c, &paylen);
			if (payload != NULL && NULL == rs->hostname) {
				char buf[MAX_HOSTLEN];

				clamp_strncpy(ARYLEN(buf), payload, paylen);
				if (utf8_is_valid_string(buf)) {
					const char *endptr;
					host_addr_t addr;

					/*
					 * Ensure the full string qualifies as hostname and is
					 * not an IP address.
					 */

					if (
						string_to_host_or_addr(buf, &endptr, &addr) &&
						'\0' == *endptr && !is_host_addr(addr)
					) {
						rs->hostname = atom_str_get(buf);
					}
				}
			}
			break;

		case G2_QH2_NA:
			if (!g2_node_parse_address(c, &rs->addr, &rs->port)) {
				badmsg = "no valid address in \"NA\"";
				goto bad_packet;
			}
			has_na = TRUE;
			break;

		case G2_QH2_NH:
			{
				host_addr_t addr;
				uint16 port;

				if (NULL == rs->proxies) {
					rs->proxies = gnet_host_vec_alloc();
					rs->status |= ST_PUSH_PROXY;
				}

				if (g2_node_parse_address(c, &addr, &port))
					gnet_host_vec_add(rs->proxies, addr, port);
			}
			break;

		case G2_QH2_TLS:
			rs->status |= ST_TLS;
			break;

		case G2_QH2_V:
			payload = g2_tree_node_payload(c, &paylen);
			if (payload != NULL && 4 == paylen) {
				rs->vcode.u32 = peek_be32(payload);
				vendor = vendor_get_name(rs->vcode);
				if (vendor != NULL && is_vendor_known(rs->vcode)) {
					rs->status |= ST_KNOWN_VENDOR;
				}
			}
			break;
		}
	}

	/* Drop if no results in /QH2 */

	if (0 == nr) {
		badmsg = "no results";
		goto bad_packet;
	}

	/*
	 * Adjust the number of records, in case we did not include all the
	 * items in the hit.
	 */

	rs->num_recs = pslist_length(rs->records);

	if (0 == rs->num_recs) {
		badmsg = "kept none of the items";
		goto bad_packet;
	}

	/*
	 * If we did not find a "NA" child in the hit, try to intuit the address.
	 */

	if (!has_na) {
		/*
		 * If it comes from UDP, we can derive the address, and pray for the
		 * port to be the listening port.  Via TCP, with hops=0, we have the
		 * node address and listening port normally.
		 * Otherwise, reject the hit.
		 */

		if (NODE_IS_UDP(n)) {
			rs->addr = n->addr;
			rs->port = n->port;
		} else {
			if (0 != rs->hops || 0 == n->gnet_port) {
				badmsg = "no \"NA\" in TCP hit, cannot derive source";
				goto bad_packet;
			}
			rs->addr = n->gnet_addr;
			rs->port = n->gnet_port;	/* Known listening port */
		}
	}

	if (*hostile & HSTL_NON_UTF8) {
		hostiles_dynamic_add(rs->addr,
			"non UTF-8 filenames in hits", HSTL_NON_UTF8);
	}

	search_results_postprocess(n, rs, muid, hostile);

	/*
	 * Refresh push-proxies if we're downloading anything from this server.
	 *
	 * Special handling for GTKG hosts: they can return hits via G2 but they
	 * are more Gnutella than G2 really, hence we can avoid recording their
	 * connected G2 hubs as G2, and handle them as Gnutella ones: it's possible
	 * that these G2 nodes are also supporting Gnutella (and could therefore
	 * understand incoming PUSH requests via UDP), and we don't want to flag a
	 * GTKG server as being G2!
	 */

	if (rs->proxies != NULL) {
		download_got_push_proxies(rs->guid, rs->proxies,
			rs->vcode.u32 != T_GTKG);
	}

	search_validate_result_address(rs, n, browse);
	search_finalize_results(rs, muid, browse);
	search_results_identify_spam(n, rs, hostile);

	if (GNET_PROPERTY(log_query_hits))
		search_results_log(n, rs);

	return rs;

bad_packet:
	if (GNET_PROPERTY(qhit_bad_debug)) {
		g_warning(
			"BAD %s from %s (via %s) -- %zu/%u record%s parsed: %s",
			 gmsg_node_infostr(n), vendor ? vendor : "????", node_infostr(n),
			 nr, PLURAL(rs->num_recs), badmsg);
		if (GNET_PROPERTY(qhit_bad_debug) > 1)
			dump_hex(stderr, "/QH2 Data (BAD)", n->data, n->size);
	}

	search_free_r_set(rs);
	gnet_stats_count_dropped(n, MSG_DROP_BAD_RESULT);

	return NULL;				/* Forget set, comes from a bad node */
}

/**
 * Parse Query Hit and extract the embedded records, plus the optional
 * trailing Query Hit Descritor (QHD).
 *
 * @param n			the node from which we got the QHD
 * @param browse	whether this QHD comes from a browse-host request
 * @param hostile	where hostile indications are consolidated
 *
 * @return a structure describing the whole result set, or NULL if we
 * were unable to parse it properly.
 */
static gnet_results_set_t * G_HOT
get_results_set(gnutella_node_t *n, bool browse, hostiles_flags_t *hostile)
{
	gnet_results_set_t *rs;
	const char *endptr, *s, *tag;
	uint32 nr = 0;
	uint32 size, idx, taglen;
	str_t *info;
	unsigned sha1_errors = 0;
	unsigned alt_errors = 0;
	unsigned alt_without_hash = 0;
	const char *trailer = NULL;
	bool seen_ggep_h = FALSE;
	bool seen_ggep_alt = FALSE;
	bool seen_ggep_alt6 = FALSE;
	bool seen_bitprint = FALSE;
	bool multiple_sha1 = FALSE;
	bool multiple_alt = FALSE;
	bool tag_has_nul = FALSE;
	const char *vendor = NULL;
	const char *badmsg = NULL;
	const guid_t *muid = gnutella_header_get_muid(&n->header);

	*hostile = HSTL_CLEAN;

	/* We shall try to detect malformed packets as best as we can */
	if (n->size < 27) {
		/* packet too small 11 header, 16 GUID min */
		g_warning("%s(): given too small a packet (%d bytes)",
			G_STRFUNC, n->size);
        gnet_stats_count_dropped(n, MSG_DROP_TOO_SMALL);
		return NULL;
	}

	info = str_new(80);

	rs = search_new_r_set();
	rs->stamp = tm_time();
	rs->country = ISO3166_INVALID;

	rs->ttl	= gnutella_header_get_ttl(&n->header);
	rs->hops = gnutella_header_get_hops(&n->header);

	if (!browse) {
		g_assert(rs->hops > 0);
		rs->hops--; 	/* route_message() increased hop count by 1 */
	}

	/* Transfer the Query Hit info to our internal results_set struct */

	{
		const gnutella_search_results_t *r = cast_to_pointer(n->data);

		rs->num_recs = gnutella_search_results_get_num_recs(r);
		rs->addr = host_addr_get_ipv4(gnutella_search_results_get_host_ip(r));
		rs->port = gnutella_search_results_get_host_port(r);
		rs->speed = gnutella_search_results_get_host_speed(r);
		rs->last_hop = n->addr;

		/* Now come the result set, and the servent ID will close the packet */

		STATIC_ASSERT(11 == sizeof *r);
		s = cast_to_constpointer(&r[1]);	/* Start of the records */
		endptr = &s[n->size - 11 - 16];	/* End of records, less header, GUID */
	}

	/* Drop if no results in Query Hit */

	if (rs->num_recs == 0) {
        gnet_stats_count_dropped(n, MSG_DROP_BAD_RESULT);
		badmsg = "no results";
		goto bad_packet;
	}

	search_validate_result_address(rs, n, browse);

	if (GNET_PROPERTY(search_debug) > 7)
		dump_hex(stdout, "Query Hit Data", n->data, n->size);

	while (endptr - s > 10 && nr < rs->num_recs) {
		gnet_record_t *rc;
		const char *filename;

		idx = peek_le32(s);
		s += 4;					/* File Index */
		size = peek_le32(s);
		s += 4;					/* File Size */

		/* Followed by file name, and termination (double NUL) */
		filename = s;

		s = vmemchr(s, '\0', endptr - s);
		if (!s) {
			/* There cannot be two NULs: end of packet! */
			gnet_stats_count_dropped(n, MSG_DROP_BAD_RESULT);
			badmsg = "no NUL after filename";
			goto bad_packet;
        }
		s++;

		/*
		 * `s' points after the first NUL of the double NUL sequence.
		 *
		 * Between the two NULs at the end of each record, servents may put
		 * some extra information about the file (a tag), but this information
		 * may not contain any NUL.
		 */

		if (s[0]) {
			/* Not a NUL, so we're *probably* within the tag info */

			tag = s;

			/*
			 * Inspect the tag, looking for next NUL.
			 */

			/* Find second NUL */
			s = vmemchr(s, '\0', endptr - s);
			if (s) {
				/* Found second NUL */
				taglen = s - tag;
			} else {
                gnet_stats_count_dropped(n, MSG_DROP_BAD_RESULT);
				badmsg = "no second NUL to close record";
				goto bad_packet;
            }
		} else {
			tag = NULL;
			taglen = 0;
		}
		s++;				/* Skip second NUL */

		/*
		 * Okay, one more record
		 */

		nr++;

		rc = search_record_new();
		rc->file_index = idx;
		rc->size = size;
		rc->filename = filename;

		rs->records = pslist_prepend(rs->records, rc);

		/*
		 * If we have a tag, parse it for extensions.
		 */

		if (tag) {
			extvec_t exv[MAX_EXTVEC];
			int exvcnt;
			int i;
			char *endtag;
			size_t parselen;
			gnet_host_vec_t *hvec = NULL;		/* For GGEP "ALT" */
			bool has_hash = FALSE;
			bool has_unknown = FALSE;
			filesize_t available = 0;			/* For GGEP "PRU" */

			g_assert(taglen > 0);

			/*
			 * We're not only parsing the tag, we're parsing until the
			 * end of the query hit to be able to detect wrong encodings.
			 * Parsing will stop at the first NUL byte seen after a valid
			 * extension but will happily swallow NUL in a GGEP payload,
			 * which is completely invalid in a query hit of course.
			 */

			parselen = ptr_diff(endptr, tag);
			g_assert(parselen >= taglen);

			ext_prepare(exv, MAX_EXTVEC);
			exvcnt = ext_parse_nul(tag, parselen, &endtag, exv, MAX_EXTVEC);

			/*
			 * If all went well, endptr is at the end of the tag, past its
			 * NUL byte.  So the length of the data parsed is taglen + 1,
			 * to account for the NUL being swallowed by the parser.
			 *
			 * Otherwise, since we computed the end of the tag by looking
			 * for the next NUL byte, it means the servent did not use COBS
			 * in GGEP or sent garbage data.
			 */

			g_assert(ptr_cmp(endtag, tag) >= 0);

			if (ptr_diff(endtag, tag) != taglen + 1) {
				tag_has_nul = TRUE;
				if (endtag == tag || *(endtag - 1) != '\0') {
					/* Cannot continue parsing */
					ext_reset(exv, MAX_EXTVEC);
					gnet_stats_count_dropped(n, MSG_DROP_BAD_RESULT);
					badmsg = "NUL found within result tag data";
					goto bad_packet;
				}
			}

			s = endtag;		/* Resume parsing here for next record */

			/*
			 * Look for a valid SHA1 or a tag string we can display.
			 */

			str_setlen(info, 0);

			for (i = 0; i < exvcnt; i++) {
				extvec_t *e = &exv[i];
				struct sha1 sha1_digest;
				struct tth tth_digest;
				ggept_status_t ret;
				int paylen;
				const char *payload;

				switch (e->ext_token) {
				case EXT_T_URN_BITPRINT:	/* first 32 chars is the SHA1 */
					seen_bitprint = TRUE;
					paylen = ext_paylen(e);
					if (paylen >= BITPRINT_BASE32_SIZE) {
						paylen -= (SHA1_BASE32_SIZE + 1);	/* include '.' */
						paylen = MIN(paylen, TTH_BASE32_SIZE);
						payload = ext_payload(e);
						if (
							huge_tth_extract32(&payload[SHA1_BASE32_SIZE + 1],
								paylen, &tth_digest, n)
						) {
							atom_tth_change(&rc->tth, &tth_digest);
						} else {
							if (GNET_PROPERTY(search_debug) > 0) {
								g_debug("huge_tth_extract32() failed");
							}
						}
					}
					/* FALLTHROUGH */
				case EXT_T_URN_SHA1:		/* SHA1 URN, the HUGE way */
					has_hash = TRUE;
					paylen = ext_paylen(e);
					if (e->ext_token == EXT_T_URN_BITPRINT) {
						paylen = MIN(paylen, SHA1_BASE32_SIZE);
					}
					if (
						huge_sha1_extract32(ext_payload(e),
								paylen, &sha1_digest, n)
					) {
						multiple_sha1 |= NULL != rc->sha1;
						atom_sha1_change(&rc->sha1, &sha1_digest);
					} else {
						if (GNET_PROPERTY(search_debug) > 0) {
							g_debug("huge_sha1_extract32() failed");
						}
						sha1_errors++;
					}
					break;
				case EXT_T_URN_TTH:	/* TTH URN (urn:ttroot) */
					paylen = ext_paylen(e);
					paylen = MIN(paylen, TTH_BASE32_SIZE);
					if (
						huge_tth_extract32(ext_payload(e),
							paylen, &tth_digest, n)
					) {
						atom_tth_change(&rc->tth, &tth_digest);
					} else {
						if (GNET_PROPERTY(search_debug) > 0) {
							g_debug("huge_tth_extract32() failed");
						}
					}
					break;
				case EXT_T_URN_BTIH:
				case EXT_T_URN_MD5:
				case EXT_T_URN_ED2KHASH:
				case EXT_T_URN_UNKNOWN:
					/* Silently ignore unknown / unhandled URNs */
					break;
				case EXT_T_GGEP_TT:	/* TTH (binary) */
					paylen = ext_paylen(e);
					paylen = MIN(paylen, TTH_RAW_SIZE);
					if (TTH_RAW_SIZE == paylen) {
						memcpy(tth_digest.data, ext_payload(e), TTH_RAW_SIZE);
						atom_tth_change(&rc->tth, &tth_digest);
					} else {
						if (GNET_PROPERTY(search_debug) > 0) {
							g_debug("GGEP \"TTH\" has wrong size");
						}
					}
					break;
				case EXT_T_GGEP_u:		/* HUGE URN, without leading urn: */
					paylen = ext_paylen(e);
					payload = ext_payload(e);
					if (
						paylen > 9 && (
							is_strcaseprefix(payload, "sha1:") ||
							is_strcaseprefix(payload, "bitprint:")
						)
					) {
						char *buf = h_strndup(payload, paylen);

						has_hash = TRUE;
						if (urn_get_sha1_no_prefix(buf, &sha1_digest)) {
							if (huge_improbable_sha1(ARYLEN(sha1_digest.data))) {
								if (GNET_PROPERTY(search_debug) > 0) {
									g_debug("improbable SHA-1 detected");
								}
								sha1_errors++;
							} else {
								multiple_sha1 |= NULL != rc->sha1;
								atom_sha1_change(&rc->sha1, &sha1_digest);
							}
						} else {
							if (GNET_PROPERTY(search_debug) > 0) {
								g_debug("urn_get_sha1_no_prefix() failed");
							}
							sha1_errors++;
						}
						HFREE_NULL(buf);
					}
					break;
				case EXT_T_GGEP_H:			/* Expect SHA1 value only */
					ret = ggept_h_sha1_extract(e, &sha1_digest);
					if (ret == GGEP_OK) {
						has_hash = TRUE;
						if (GGEP_OK == ggept_h_tth_extract(e, &tth_digest)) {
							atom_tth_change(&rc->tth, &tth_digest);
						}
						if (huge_improbable_sha1(ARYLEN(sha1_digest.data))) {
							if (GNET_PROPERTY(search_debug) > 0) {
								g_debug("Improbable SHA-1 detected");
							}
							sha1_errors++;
						} else {
							multiple_sha1 |= NULL != rc->sha1;
							atom_sha1_change(&rc->sha1, &sha1_digest);
						}
						seen_ggep_h = TRUE;
					} else if (ret == GGEP_INVALID) {
						sha1_errors++;
						search_log_bad_ggep(n, e, NULL);
					} else {
						search_log_ggep(n, e, NULL, "SHA1-less");
					}
					break;
				case EXT_T_GGEP_ALT:		/* Alternate locations (IPv4) */
					if (hvec != NULL && hvec->n_ipv4 != 0) {
						/* Already saw one for record! */
						multiple_alt = TRUE;
						break;
					}
					/* Allocates new hvec or reuses existing one */
					ret = ggept_alt_extract(e, &hvec, NET_TYPE_IPV4);
					if (ret == GGEP_OK) {
						seen_ggep_alt = TRUE;
					} else {
						alt_errors++;
						search_log_bad_ggep(n, e, NULL);
					}
					break;
				case EXT_T_GGEP_ALT6:		/* Alternate locations (IPv6) */
					if (hvec != NULL && hvec->n_ipv6 != 0) {
						/* Already saw one for record! */
						multiple_alt = TRUE;
						break;
					}
					/* Allocates new hvec or reuses existing one */
					ret = ggept_alt_extract(e, &hvec, NET_TYPE_IPV6);
					if (ret == GGEP_OK) {
						seen_ggep_alt6 = TRUE;
					} else {
						alt_errors++;
						search_log_bad_ggep(n, e, NULL);
					}
					break;
				case EXT_T_GGEP_ALT_TLS:	/* TLS-capability bitmap for ALT */
				case EXT_T_GGEP_ALT6_TLS:	/* TLS-capability bitmap for ALT6 */
					/* FIXME: Handle this */
					break;
				case EXT_T_GGEP_LF:			/* Large File */
					{
						uint64 fs;

					   	ret = ggept_filesize_extract(e, &fs);
						if (ret == GGEP_OK) {
							rc->size = fs;
						} else {
							search_log_bad_ggep(n, e, NULL);
						}
					}
					break;
				case EXT_T_GGEP_LIME_XML:
					paylen = ext_paylen(e);
					if (!rc->xml && paylen > 0) {
						char buf[4096];

						clamp_strncpy(ARYLEN(buf), ext_payload(e), paylen);
						if (utf8_is_valid_string(buf)) {
							rc->xml = atom_str_get(buf);
						}
					}
					break;
				case EXT_T_GGEP_PATH:		/* Path */
					paylen = ext_paylen(e);
					if (!rc->path && paylen > 0) {
						char buf[1024];

						clamp_strncpy(ARYLEN(buf), ext_payload(e), paylen);
						rc->path = atom_str_get(buf);
					}
					break;
				case EXT_T_GGEP_CT:		/* Create Time */
					{
						time_t stamp;

						ret = ggept_ct_extract(e, &stamp);
						if (GGEP_OK == ret) {
							rc->create_time = stamp;
						} else {
							search_log_bad_ggep(n, e, NULL);
						}
					}
					break;
				case EXT_T_GGEP_PR0:	/* Partial results */
					rc->flags |= SR_PARTIAL_HIT;
					/* No parts of the file available yet */
					break;
				case EXT_T_GGEP_PR1:
				case EXT_T_GGEP_PR2:
				case EXT_T_GGEP_PR3:
				case EXT_T_GGEP_PR4:
					rc->flags |= SR_PARTIAL_HIT;
					rc->available += lime_range_decode(n, e, rc->size);
					break;
				case EXT_T_GGEP_PRU:
					rc->flags |= SR_PARTIAL_HIT;
					if (0 != ext_paylen(e)) {
						if (
							GGEP_OK == ggept_stamp_filesize_extract(e,
								&rc->mod_time, &available)
						) {
							/*
							 * Do not update rc->available yet, in case there
							 * are "PRi" extensions.  Since the file size is
							 * more precise in "PRU" than the one computed
							 * with "PRi" decoding, wait until we have handled
							 * all the extensions to set the one found in "PRU".
							 */
						} else {
							search_log_bad_ggep(n, e, NULL);
						}
					}
					break;
				case EXT_T_UNKNOWN_GGEP:	/* Unknown GGEP extension */
					if (
						GNET_PROPERTY(search_debug) > 3 ||
						GNET_PROPERTY(ggep_debug) > 3
					) {
						search_log_ggep(n, e, NULL, "unknown");
					}
					break;
				case EXT_T_UNKNOWN:
					has_unknown = TRUE;
					if (ext_paylen(e) && ext_has_ascii_word(e)) {
						if (str_len(info))
							STR_CAT(info, "; ");
						str_cat_len(info, ext_payload(e), ext_paylen(e));
					}
					break;
				default:
					if (GNET_PROPERTY(search_debug) > 4) {
						g_debug("%s has unhandled record extension %s",
							gmsg_node_infostr(n), ext_to_string(e));
					}
					break;
				}
			}

			/*
			 * The available size on the server (for partial results) is more
			 * precise in the "PRU" extension.  So if one was present, use it
			 * to derive the remotely available bytes.
			 */

			if (available != 0)
				rc->available = available;

			if (has_unknown) {
				if (GNET_PROPERTY(search_debug) > 2) {
					g_warning("%s hit record #%d/%d has unknown extensions!",
						gmsg_node_infostr(n), nr, rs->num_recs);
					ext_dump(stderr, exv, exvcnt, "> ", "\n", TRUE);
					dump_hex(stderr, "Query Hit Tag", tag, taglen);
				}
			} else if (exvcnt == MAX_EXTVEC) {
				if (GNET_PROPERTY(search_debug) > 2) {
					g_warning("%s hit record #%d/%d has %d extensions!",
						gmsg_node_infostr(n), nr, rs->num_recs, exvcnt);
					ext_dump(stderr, exv, exvcnt, "> ", "\n", TRUE);
					dump_hex(stderr, "Query Hit Tag", tag, taglen);
				}
			} else if (GNET_PROPERTY(search_debug) > 3) {
				g_debug("%s hit record #%d/%d has %d extensions:",
					gmsg_node_infostr(n), nr, rs->num_recs, exvcnt);
				ext_dump(stderr, exv, exvcnt, "> ", "\n", TRUE);
			}

			if (exvcnt)
				ext_reset(exv, MAX_EXTVEC);

			if (str_len(info) > 0)
				rc->tag = atom_str_get(str_2c(info));

			if (hvec != NULL) {
				if (!has_hash)
					alt_without_hash++;

				/*
				 * GGEP "ALT" is only meaningful when there is a SHA1!
				 */

				if (rc->sha1 != NULL) {
					rc->alt_locs = hvec;
				} else {
					gnet_host_vec_free(&hvec);
				}
			}
		}

		search_record_cleanup(rc);
	}

	/*
	 * If we have not reached the end of the packet, then we have a trailer.
	 * It can be of any length, but bound by the maximum query hit packet
	 * size we configured for this node.
	 *
	 * The payload of the trailer is vendor-specific, but its "header" is
	 * somehow codified:
	 *
	 *	bytes 0..3: vendor code (4 letters)
	 *	byte 4	: open data size
	 *
	 * Followed by open data (flags usually), and opaque data.
	 */

	if (s < endptr) {
		size_t trailer_len = endptr - s;	/* Trailer length, starts at `s' */

		if (trailer_len >= 5) {
			unsigned open_data_size = peek_u8(&s[4]);

			if (trailer_len - 5 >= open_data_size)
				trailer = s;
		}

		if (trailer) {
			rs->vcode.u32 = peek_be32(trailer);
			vendor = vendor_get_name(rs->vcode);
			if (vendor != NULL && is_vendor_known(rs->vcode)) {
				rs->status |= ST_KNOWN_VENDOR;
			}
		} else {
			if (GNET_PROPERTY(search_debug)) {
				g_warning(
					"UNKNOWN %zu-byte trailer at offset %zu in %s from %s "
					"(%u/%u records parsed)",
					trailer_len, s - n->data,
					gmsg_node_infostr(n),
					node_addr(n), (uint) nr, (uint) rs->num_recs);
			}
			if (GNET_PROPERTY(search_debug) > 1) {
				dump_hex(stderr, "Query Hit Data (non-empty UNKNOWN trailer?)",
					n->data, n->size);
				dump_hex(stderr, "UNKNOWN trailer part", s, trailer_len);
			}
		}
	}

	if (tag_has_nul) {
		/*
		 * So that we know who generates such a bad query hit...
		 */

		if (0 == rs->hops && !NODE_IS_UDP(n) && vendor != NULL) {
			/*
			 * These vendors are known to generate proper hits usually.
			 */

			switch (rs->vcode.u32) {
			case T_GTKG:
			case T_LIME:
				if (GNET_PROPERTY(node_debug) && NODE_IS_GENUINE(n)) {
					g_message("NODE %s is not a genuine %s: "
						"sends bad query hits",
						node_infostr(n), vendor ? vendor : "node");
				}
				n->attrs2 |= NODE_A2_NOT_GENUINE;
				break;
			}
		}
        gnet_stats_count_dropped(n, MSG_DROP_BAD_RESULT);
		badmsg = "at least one filenme tag had NUL bytes";
		goto bad_packet;
	}

	if (nr != rs->num_recs) {
        gnet_stats_count_dropped(n, MSG_DROP_BAD_RESULT);
		badmsg = "inconsistent number of records";
		goto bad_packet;
    }

	/* We now have the GUID of the node */

	rs->guid = atom_guid_get(cast_to_guid_ptr_const(endptr));

	badmsg = search_validate_guid(rs, n, muid);
	if (badmsg != NULL)
		goto bad_packet;

	if (
		trailer &&
		search_results_handle_trailer(n, rs, trailer, endptr - trailer, hostile)
	) {
        gnet_stats_count_dropped(n, MSG_DROP_BAD_RESULT);
		badmsg = "bad trailer";
		goto bad_packet;
	}

	if ((rs->status & ST_FIREWALL) && !route_guid_pushable(rs->guid)) {
        gnet_stats_count_dropped(n, MSG_DROP_FROM_BANNED);
		badmsg = "firewalled origin & banned GUID";
		goto bad_packet;
	}

	/*
	 * At this point we finished processing of the query hit, successfully.
	 */

	search_results_postprocess(n, rs, muid, hostile);

	/*
	 * Refresh push-proxies if we're downloading anything from this server.
	 */

	if (rs->proxies != NULL)
		download_got_push_proxies(rs->guid, rs->proxies, FALSE);

	/*
	 * Now that we have the vendor, warn if the message has SHA1 errors.
	 * Then drop the packet!
	 */

	if (sha1_errors) {
		if (GNET_PROPERTY(search_debug))
			g_warning("%s from %s (via %s) had %u SHA1 error%s "
				"over %u record%s",
				gmsg_node_infostr(n), vendor ? vendor : "????",
				node_infostr(n),
				PLURAL(sha1_errors), PLURAL(nr));
		gnet_stats_count_dropped(n, MSG_DROP_MALFORMED_SHA1);
		badmsg = "malformed SHA1";
		goto bad_packet;		/* Will drop this bad query hit */
	}

	/*
	 * If we have bad ALT locations, or ALT without hashes, warn but
	 * do not drop.
	 */

	if (alt_errors && GNET_PROPERTY(search_debug)) {
		g_warning("%s from %s (via %s) had %u ALT error%s over %u record%s",
			gmsg_node_infostr(n), vendor ? vendor : "????",
			node_infostr(n),
			PLURAL(alt_errors), PLURAL(nr));
	}

	if (alt_without_hash && GNET_PROPERTY(search_debug)) {
		g_warning("%s from %s (via %s) had %u ALT extension%s "
			"with no hash over %u record%s",
			gmsg_node_infostr(n), vendor ? vendor : "????",
			node_infostr(n),
			PLURAL(alt_without_hash), PLURAL(nr));
	}

	if (GNET_PROPERTY(search_debug) > 1) {
		if (seen_ggep_h && GNET_PROPERTY(search_debug) > 3)
			g_debug("%s from %s used GGEP \"H\" extension",
					gmsg_node_infostr(n), vendor ? vendor : "????");
		if (seen_ggep_alt && GNET_PROPERTY(search_debug) > 3)
			g_debug("%s from %s used GGEP \"ALT\" extension",
					gmsg_node_infostr(n), vendor ? vendor : "????");
		if (seen_ggep_alt6 && GNET_PROPERTY(search_debug) > 3)
			g_debug("%s from %s used GGEP \"ALT6\" extension",
					gmsg_node_infostr(n), vendor ? vendor : "????");
		if (seen_bitprint && GNET_PROPERTY(search_debug) > 3)
			g_debug("%s from %s used urn:bitprint",
					gmsg_node_infostr(n), vendor ? vendor : "????");
		if (multiple_sha1)
			g_warning("%s from %s had records with multiple SHA1",
					gmsg_node_infostr(n), vendor ? vendor : "????");
		if (multiple_alt)
			g_warning("%s from %s had records with multiple ALT",
					gmsg_node_infostr(n), vendor ? vendor : "????");
	}

	search_finalize_results(rs, muid, browse);
	search_results_identify_spam(n, rs, hostile);
	str_destroy_null(&info);

	if (GNET_PROPERTY(log_query_hits))
		search_results_log(n, rs);

	return rs;

	/*
	 * Come here when we encounter bad packets (NUL chars not where expected,
	 * or missing).	The whole packet is ignored.
	 *				--RAM, 09/01/2001
	 */

bad_packet:
	if (GNET_PROPERTY(qhit_bad_debug)) {
		g_warning(
			"BAD %s from %s (via %s) -- %u/%u record%s parsed: %s",
			 gmsg_node_infostr(n), vendor ? vendor : "????", node_infostr(n),
			 nr, PLURAL(rs->num_recs), badmsg);
		if (GNET_PROPERTY(qhit_bad_debug) > 1)
			dump_hex(stderr, "Query Hit Data (BAD)", n->data, n->size);
	}

	search_free_r_set(rs);
	str_destroy_null(&info);

	return NULL;				/* Forget set, comes from a bad node */
}

/**
 * Called when we get a query hit from an immediate neighbour.
 */
static void
update_neighbour_info(gnutella_node_t *n, gnet_results_set_t *rs)
{
	const char *vendor;
	uint32 old_weird = n->n_weird;

	g_assert(gnutella_header_get_hops(&n->header) == 1);

	vendor = vendor_get_name(rs->vcode);

	if (n->attrs & NODE_A_QHD_NO_VTAG) {	/* Known to have no tag */
		if (vendor) {
			n->n_weird++;
			if (GNET_PROPERTY(search_debug) > 1) g_warning("[weird #%d] "
				"%s had no tag in its query hits, now has %s in %s",
				n->n_weird, node_infostr(n), vendor, gmsg_node_infostr(n));
			n->attrs &= ~NODE_A_QHD_NO_VTAG;
		}
	} else {
		/*
		 * Use vendor tag if needed to guess servent vendor name.
		 */

		if (n->vendor == NULL && vendor)
			node_set_vendor(n, vendor);

		if (vendor == NULL)
			n->attrs |= NODE_A_QHD_NO_VTAG;	/* No vendor tag */

		if (n->vcode.u32 != T_0000 && vendor == NULL) {
			n->n_weird++;
			if (GNET_PROPERTY(search_debug) > 1) g_warning("[weird #%d] "
				"%s had tag \"%s\" in its query hits, now has none in %s",
				n->n_weird, node_infostr(n),
				vendor_code_to_string(n->vcode.u32),
				gmsg_node_infostr(n));
		}
	}

	/*
	 * Tell the node layer when we detect a firewalled node.
	 */

	if (rs->status & ST_FIREWALL && !(n->attrs & NODE_A_FIREWALLED)) {
		node_is_firewalled(n);
	}

	/*
	 * Save vendor code if present.
	 */

	if (vendor != NULL) {
		STATIC_ASSERT(sizeof n->vcode == sizeof rs->vcode);

		if (n->vcode.u32 != T_0000 && n->vcode.u32 != rs->vcode.u32) {
			char vc_old[VENDOR_CODE_BUFLEN];
			char vc_new[VENDOR_CODE_BUFLEN];

			n->n_weird++;
			vendor_code_to_string_buf(n->vcode.u32, ARYLEN(vc_old));
			vendor_code_to_string_buf(rs->vcode.u32, ARYLEN(vc_new));

			if (GNET_PROPERTY(search_debug) > 1) {
				g_warning("[weird #%d] %s moved from tag %4.4s to %4.4s in %s",
					n->n_weird, node_infostr(n),
					vc_old, vc_new, gmsg_node_infostr(n));
			}
		}

		n->vcode = rs->vcode;
	} else {
		n->vcode.u32 = T_0000;
	}

	/*
	 * Save node's GUID, extracted from the search results.
	 *
	 * If we already know the GUID of that node, this will also make
	 * sure that it is not changing.
	 */

	node_set_guid(n, rs->guid, TRUE);

	/*
	 * We don't declare any weirdness if the address in the results matches
	 * the socket's peer address.
	 *
	 * Otherwise, make sure the address is a private IP one, or that the hit
	 * has the "firewalled" bit.  Otherwise, the IP must match the one the
	 * servent thinks it has, which we know from its previous query hits
	 * with hops=0. If we never got a query hit from that servent, check
	 * against last IP we saw in pong.
	 *
	 * FIXME: The IPv4 address might dynamic and the IPv6 address might
	 *        be stable or vice-versa.
	 */

	if (
		!(rs->status & ST_FIREWALL) &&		/* Hit not marked "firewalled" */
		!host_addr_equiv(n->addr, rs->addr) &&	/* Not socket's address */
		host_addr_is_routable(n->addr) &&	/* Not LAN or loopback */
		host_addr_is_routable(rs->addr)
	) {
		if (
			(is_host_addr(n->gnet_qhit_addr) &&
				!host_addr_equiv(n->gnet_qhit_addr, rs->addr)
				) ||
			(!is_host_addr(n->gnet_qhit_addr) &&
				is_host_addr(n->gnet_pong_addr) &&
				!host_addr_equiv(n->gnet_pong_addr, rs->addr)
			)
		) {
			n->n_weird++;
			if (GNET_PROPERTY(search_debug) > 1) {
				g_warning("[weird #%d] %s advertised %s but now says "
					"hit from %s",
					n->n_weird, node_infostr(n),
					host_addr_to_string(is_host_addr(n->gnet_qhit_addr) ?
						n->gnet_qhit_addr : n->gnet_pong_addr),
					host_addr_port_to_string(rs->addr, rs->port));
			}
		}
		n->gnet_qhit_addr = rs->addr;
		rs->status |= ST_ALIEN;				/* Alien IP address detected */
	}

	if (GNET_PROPERTY(search_debug) > 3 && old_weird != n->n_weird) {
		dump_hex(stderr, NODE_TALKS_G2(n) ?
			"/QH2 data (weird)" : "Query Hit data (weird)", n->data, n->size);
	}
}

/**
 * Create a search request message for specified search.
 *
 * On success a walloc()ated message is returned. Use wfree() to release
 * the memory. The size is returned in the "size" variable, if not NULL.
 *
 * @param muid		the MUID to use for the search message
 * @param query		the query string
 * @param mtype		media type filtering (0 if none wanted)
 * @param whats_new	whether search message is of the "What's New?" type.
 * @param size		if not-NULL, written with the size of the generated message
 * @param query_key	the GUESS query key to use (if non-NULL)
 * @param length	length of query key
 * @param udp		whether message will be sent via UDP
 *
 * @return NULL if we cannot build a suitable message (bad query string
 * containing only whitespaces, for instance).
 */
static gnutella_msg_search_t *
build_search_message(const guid_t *muid, const char *query,
	unsigned mtype, bool whats_new, uint32 *size,
	const void *query_key, uint8 length, bool udp)
{
	static union {
		gnutella_msg_search_t data;
		char bytes[1024];
		uint64 align8;
	} msg;
	size_t msize;
	uint16 flags;
	bool is_sha1_search;
	struct sha1 sha1;
	ggep_stream_t gs;
	size_t glen;
	bool need_6 = FALSE;

	g_assert(NULL == query_key || 0 != length);
	g_assert(NULL != query_key || 0 == length);

	STATIC_ASSERT(25 == sizeof msg.data);
	msize = sizeof msg.data;

	{
		gnutella_header_t *header = gnutella_msg_search_header(&msg.data);
		uint8 hops;
		bool is_leaf = settings_is_leaf();

		hops = !udp && !whats_new && GNET_PROPERTY(hops_random_factor) &&
			!is_leaf ? random_value(GNET_PROPERTY(hops_random_factor)) : 0;

		gnutella_header_set_muid(header, muid);
		gnutella_header_set_function(header, GTA_MSG_SEARCH);
		gnutella_header_set_hops(header, hops);
		gnutella_header_set_ttl(header,
			whats_new ? WHATS_NEW_TTL + (is_leaf ? 1 : 0) :
			query_key != NULL ? 1 : GNET_PROPERTY(my_ttl));

		if (
			(uint32) gnutella_header_get_ttl(header) +
			   gnutella_header_get_hops(header) > GNET_PROPERTY(hard_ttl_limit)
		) {
			gnutella_header_set_ttl(header,
			  GNET_PROPERTY(hard_ttl_limit) - gnutella_header_get_hops(header));
		}
	}

	/*
	 * The search speed is no longer used by most servents as a raw indication
	 * of speed.  There is now a special marking for the speed field in the
	 * upper byte, the lower byte being kept for speed indication, but not
	 * defined yet -> use zeros (since this is a min speed).
	 *
	 * It is too soon though, as GTKG before 0.92 did honour that field.
	 * The next major version will use a tailored speed field.
	 *		--RAM, 19/01/2003
	 *
	 * Starting today (06/07/2003), we're using marked speed fields and
	 * ignore the speed they specify in the searches from the GUI. --RAM
	 *
	 * Starting 2005-08-20, we specify QUERY_F_XML because
	 * we show XML in hits within the GUI.  We don't yet parse it, but at
	 * least they can read it.
	 */

	flags = QUERY_F_MARK;			/* Indicates: special speed field */
	if (GNET_PROPERTY(is_firewalled))
		flags |= QUERY_F_FIREWALLED;
	flags |= QUERY_F_LEAF_GUIDED;	/* GTKG supports leaf-guided queries */
	flags |= QUERY_F_GGEP_H;		/* GTKG understands GGEP "H" in hits */
	flags |= QUERY_F_XML;			/* GTKG can read XML in hits */
	flags |= QUERY_F_SR_UDP;		/* GTKG supports semi-reliable UDP */

	/*
	 * We need special processing for OOB queries since the GUID has to be
	 * marked specially.  This must happen at the time we issue the search.
	 * Therefore, if we're in a position for emitting an OOB query, make sure
	 * the already chosen MUID is valid according to our current IP:port.
	 */

	if (
		udp_active() &&
		GNET_PROPERTY(send_oob_queries) &&
		!GNET_PROPERTY(is_udp_firewalled)
	) {
		host_addr_t primary = listen_addr_primary();
		uint32 ipv4 = ipv6_ready_advertised_ipv4(primary);
		host_addr_t addr;
		uint16 port;

		guid_oob_get_addr_port(muid, &addr, &port);

		/*
		 * IPv6-Ready: we only compare the trailing part of our IPv6 address
		 * here, which should be fine most of the time since we're only
		 * handling MUIDs we generate and we'll prepare for OOB-compatible
		 * MUIDs as soon as UDP is active.
		 */

		if (
			port == GNET_PROPERTY(listen_port) &&
			host_addr_ipv4(addr) == ipv4
		) {
			flags |= QUERY_F_OOB_REPLY;
			need_6 = ipv6_ready_has_no_ipv4(ipv4);
		}
	}

	gnutella_msg_search_set_flags(&msg.data, flags);

	/*
	 * Are we dealing with a URN search?
	 */

	is_sha1_search = urn_get_sha1(query, &sha1);

	{
		size_t len;

		len = vstrlen(query);
		if (len + 1 >= sizeof msg.bytes - msize) {
			g_warning("dropping too large query \"%s\"", query);
			goto error;
		}

		if (is_sha1_search) {
			msg.bytes[msize++] = '\\';
			msg.bytes[msize++] = '\0';
			memcpy(&msg.bytes[msize], query, len);
			msize += len;
		} else {
			size_t new_len;

			memcpy(&msg.bytes[msize], query, len);
			msg.bytes[msize + len] = '\0';

			new_len = compact_query(&msg.bytes[msize]);
			g_assert(new_len <= len);

			if (new_len == 0) {
				g_warning("dropping empty query \"%s\"", query);
				goto error;
			}

			if (new_len < len) {
				len = new_len;
				if (GNET_PROPERTY(search_debug) > 1)
					g_debug("compacted query \"%s\" into \"%s\"",
						query, &msg.bytes[msize]);
			}
			msize += len + 1;
		}
	}

	if (is_sha1_search) {
		/*
		 * As long as we have to use plain text hash queries instead
		 * of GGEP H, we need to add a separator between the hash
		 * and the following GGEP block.
		 */
		if (sizeof msg.bytes == msize) {
			g_warning("dropping too large query \"%s\"", query);
			goto error;
		}
		msg.bytes[msize] = HUGE_FS; /* extension separator */
		msize++;
	}

	ggep_stream_init(&gs, &msg.bytes[msize], sizeof msg.bytes - msize);

	/*
	 * If OOB hit delivery is requested, add GGEP "SO" for secure OOBv3.
	 */

	if (QUERY_F_OOB_REPLY & flags) {
		/*
		 * Indicate support for OOB v3.
		 * See doc/gnutella/out-of-band-v3
		 */

		if (
			udp_active() &&
			!GNET_PROPERTY(is_udp_firewalled) &&
			host_is_valid(listen_addr(), socket_listen_port())
		) {
			/*
			 * Since our ultrapeers might not support OOB v3 and not understand
			 * GGEP "SO" either, only add this if we're not OOB proxied.
			 *
			 * Otherwise, we won't receive OOB results: the query bearing "SO"
			 * will be understood by the servent with hits as OOBv3, and
			 * therefore it will send back a v3 indication of hits, which our
			 * ultrapeer may not understand and therefore drop!
			 *
			 * Hence avoid advertising "SO" if we are firewalled.
			 */

			if (!ggep_stream_pack(&gs, GGEP_NAME(SO), NULL, 0, 0)) {
				g_carp("could not add GGEP \"SO\" extension to query");
				goto error;
			}
		}
	}

	/*
	 * FIXME
	 *
	 * 1- SHA1 searches cannot work since SHA1s are no longer in QRTs for
	 *    all LimeWire (including derivatives) and gtk-gnutella servents.
	 * 2- We currently use HUGE instead of GGEP "H" because support for the
	 *    latter is not widespread enough.  So no need to add GGEP "H" here,
	 *    the HUGE part was included above.
	 * 3- SHA1 searches do not work anyway and have been superseded by DHT
	 *    lookups.  Remove all SHA1-search support from GTKG.
	 *
	 * 		--RAM, 2011-05-01
	 */
#if 0
	if (is_sha1_search) {
		const uint8 type = GGEP_H_SHA1;
		bool ok;

		ok = ggep_stream_begin(&gs, GGEP_NAME(H), 0) &&
			ggep_stream_write(&gs, &type, 1) &&
			ggep_stream_write(&gs, &sha1, sizeof sha1.data) &&
			ggep_stream_end(&gs);

		if (!ok) {
			g_carp("could not add GGEP \"H\" to query");
			goto error;
		}
	}
#endif

	/*
	 * If a query key buffer was supplied, then it's a GUESS query.
	 *
	 * For proper GUESS 0.2 support, we include both the "QK" extension as
	 * well as the "SCP" one to make sure we get back more GUESS hosts in
	 * a packed "IPP" extension.
	 *
	 * The "Z" extension tells them we support deflated UDP replies in case
	 * query hits have to be routed back to us.
	 */

	if (query_key != NULL) {
		bool ok;
		uint8 scp = 0;
		size_t scp_len;

		/*
		 * IPv6-Ready: tell them whether we accept IPv6 and whether we want
		 * to see IPv4 addresses at all.
		 */

		if (settings_running_ipv4_and_ipv6())
			scp = SCP_F_IPV6;
		else if (settings_running_ipv6_only())
			scp = SCP_F_IPV6 | SCP_F_NO_IPV4;

		scp_len = 0 == scp ? 0 : sizeof scp;

		ok = ggep_stream_pack(&gs, GGEP_NAME(QK), query_key, length, 0);
		ok = ok && ggep_stream_pack(&gs, GGEP_NAME(SCP), &scp, scp_len, 0);
		ok = ok && ggep_stream_pack(&gs, GGEP_NAME(Z), NULL, 0, 0);

		if (!ok) {
			g_carp("could not add GGEP \"QK\", "
				"\"SCP\" and \"Z\" to GUESS query: %s", ggep_errstr());
			goto error;
		}
	}

	/*
	 * If they want partial results returned, include the GGEP "PR" key.
	 *
	 * "What's New?" queries do not include "PR" because by definition no
	 * partial file can match this kind of query.
	 */

	if (GNET_PROPERTY(query_request_partials) && !whats_new) {
		bool ok = ggep_stream_pack(&gs, GGEP_NAME(PR), NULL, 0, 0);

		if (!ok) {
			g_carp("could not add GGEP \"PR\" to query: %s", ggep_errstr());
			/* It's OK, "PR" is not critical and can be missing */
		}
	}

	/*
	 * If media type filtering is requested for that search, add GGEP "M".
	 */

	if (mtype != 0) {
		char media_type[sizeof(uint64)];
		unsigned len;
		bool ok;

		len = ggept_m_encode(mtype, ARYLEN(media_type));
		ok = ggep_stream_pack(&gs, GGEP_NAME(M), media_type, len, 0);

		if (!ok) {
			g_carp("could not add GGEP \"M\" to query: %s", ggep_errstr());
			/* It's OK, "M" is not critical and can be missing */
		}
	}

	/*
	 * A "What's New?" query is indicated with the GGEP "WH" key holding
	 * a 1-byte payload with the value 1.
	 */

	if (whats_new) {
		uchar b = 1;		/* Feature #1 is "What's New?" */
		bool ok;

		ok = ggep_stream_pack(&gs, GGEP_NAME(WH), VARLEN(b), 0);

		if (!ok) {
			g_carp("could not add GGEP \"WH\" to query: %s", ggep_errstr());
			goto error;
		}
	}

	/*
	 * IPv6-Ready: if we're sending a query requesting OOB hit delivery
	 * to an IPv6 address, we must supply the GGEP "6" extension.
	 */

	if (need_6) {
		bool ok;
		host_addr_t primary = listen_addr_primary();
		const uint8 *data = host_addr_ipv6(&primary);

		g_assert(host_addr_is_ipv6(primary));

		ok = ggep_stream_pack(&gs, GGEP_NAME(6), data, 16, 0);

		if (!ok) {
			g_carp("could not add GGEP \"6\" to query: %s", ggep_errstr());
			goto error;
		}
	}

	/*
	 * IPv6-Ready:
	 *
	 * It's important to indicate whether remote hosts should send back
	 * IPv6 results, or whether we are not interested in IPv4 results.
	 * We can't rely on the presence of "6" to convey that meaning, since
	 * that extension is tied to OOB replies, and the OOB flag can be stripped
	 * out, or the query could be OOB-proxied by a servent running both IPv4
	 * and IPv6 and which would therefore not include "6" at all.
	 *
	 * By default, searches request IPv4-only hits.  If one wants IPv6 hits
	 * as well as IPv4 ones, an empty "I6" will do.  However if the host is
	 * only running on an IPv6 address (meaning it has no IPv4), then we only
	 * want to return IPv6 hits: a single byte payload holding a 1 signals that.
	 */

	if (settings_running_ipv4()) {
		if (settings_running_ipv6()) {
			/*
			 * Our primary listening address is IPv4, but when we also have
			 * IPv6, let them know that we can accept IPv6 results and proxies
			 * by including an empty "I6".
			 */

			if (!ggep_stream_pack(&gs, GGEP_NAME(I6), NULL, 0, 0)) {
				g_carp("could not add GGEP \"I6\" to query");
				/* It's OK, "I6" is not critical and can be missing */
			}
		}
	} else if (settings_running_ipv6()) {
		uint8 b = 1;

		/*
		 * Only running IPv6, let them know we're not interested in IPv4.
		 */

		if (!ggep_stream_pack(&gs, GGEP_NAME(I6), VARLEN(b), 0)) {
			g_carp("could not add GGEP \"I6\" to query");
			/* It's OK, "I6" is not critical and can be missing */
		}
	}

	msize += (glen = ggep_stream_close(&gs));

	/*
	 * If the GGEP block is empty and we're dealing with a SHA-1 search,
	 * remove the HUGE separator (otherwise the query will be flagged
	 * as carrying unnecessary bloat and will be dropped by GTKG.
	 */

	if (0 == glen && is_sha1_search) {
		g_assert(msize >= 1);
		g_assert(HUGE_FS == msg.bytes[msize - 1]);
		msize--;
	}

	if (msize - GTA_HEADER_SIZE > GNET_PROPERTY(search_queries_forward_size)) {
		g_warning("not sending query \"%s\": larger than max query size (%d)",
			query, GNET_PROPERTY(search_queries_forward_size));
		goto error;
	}

	gnutella_header_set_size(gnutella_msg_search_header(&msg.data),
		msize - GTA_HEADER_SIZE);

	if (GNET_PROPERTY(search_debug) > 3)
		g_debug("%squery \"%s\" message built with #%s",
			is_sha1_search ? "URN " : "", query,
			guid_hex_str(gnutella_header_get_muid(
							gnutella_msg_search_header(&msg.data))));

	message_add(gnutella_header_get_muid(gnutella_msg_search_header(&msg.data)),
		GTA_MSG_SEARCH, NULL);

	if (size != NULL)
		*size = msize;

	return wcopy(&msg.bytes, msize);

error:
	return NULL;
}

/**
 * Create a GUESS search request message for specified query string.
 *
 * On success a walloc()ated message is returned. Use wfree() to release
 * the memory. The size is returned in the "size" variable, if not NULL.
 *
 * @param muid		the MUID to use for the search message
 * @param query		the query string
 * @param mtype		media type filtering (0 if none wanted)
 * @param size		if not-NULL, written with the size of the generated message
 * @param query_key	the GUESS query key to use
 * @param length	length of query key
 *
 * @return NULL if we cannot build a suitable message (bad query string
 * containing only whitespaces, for instance).
 */
gnutella_msg_search_t *
build_guess_search_msg(const guid_t *muid, const char *query,
	unsigned mtype, uint32 *size, const void *query_key, uint8 length)
{
	return build_search_message(muid, query, mtype, FALSE, size,
		query_key, length, TRUE);
}

/**
 * Create a search request message for specified query string.
 *
 * On success a walloc()ated message is returned. Use wfree() to release
 * the memory. The size is returned in the "size" variable, if not NULL.
 *
 * @param muid		the MUID to use for the search message
 * @param query		the query string
 * @param mtype		media type filtering (0 if none wanted)
 * @param whats_new	whether search message is of the "What's New?" type.
 * @param size		if not-NULL, written with the size of the generated message
 *
 * @return NULL if we cannot build a suitable message (bad query string
 * containing only whitespaces, for instance).
 */
static gnutella_msg_search_t *
build_search_msg(const guid_t *muid, const char *query,
	unsigned mtype, bool whats_new, uint32 *size)
{
	return build_search_message(muid, query, mtype, whats_new,
		size, NULL, 0, FALSE);
}

/**
 * Create a search request message for specified search.
 *
 * On success a walloc()ated message is returned. Use wfree() to release
 * the memory. The size can be derived from the header, add GTA_HEADER_SIZE.
 *
 * @return NULL if we cannot build a suitable message (bad query string
 * containing only whitespaces, for instance).
 */
static gnutella_msg_search_t *
search_build_msg(const search_ctrl_t *sch)
{
	search_ctrl_check(sch);
	g_assert(sbool_get(sch->active));
	g_assert(!sbool_get(sch->frozen));
	g_assert(sch->muids != NULL);

	/* Use the first MUID on the list (the last one allocated) */

	return build_search_msg(sch->muids->data, sch->query,
		sch->media_type, sbool_get(sch->whats_new), NULL);
}

/**
 * Create a G2 search request message (/Q2) for specified search.
 *
 * @return NULL if we cannot build a suitable message (unsupported query type).
 */
static pmsg_t *
search_g2_build_q2(const search_ctrl_t *sch)
{
	search_ctrl_check(sch);
	g_assert(sbool_get(sch->active));
	g_assert(!sbool_get(sch->frozen));
	g_assert(sch->muids != NULL);

	if (sbool_get(sch->whats_new))
		return NULL;		/* G2 does not support "What's New?" queries */

	/*
	 * Use the first MUID on the list (the last one allocated).
	 *
	 * Because the /Q2 will be sent via TCP, there is no need to include a
	 * query key in the message.
	 */

	return g2_build_q2(sch->muids->data, sch->query, sch->media_type, NULL, 0);
}

/**
 * Fill supplied query hash vector `qhv' with relevant word/SHA1 entries for
 * the given search.
 */
static void
search_qhv_fill(search_ctrl_t *sch, query_hashvec_t *qhv)
{
	word_vec_t *wovec;
	uint i;
	uint wocnt;

	search_ctrl_check(sch);

	g_assert(sch != NULL);
	g_assert(qhv != NULL);
	g_assert(settings_is_ultra());

	qhvec_reset(qhv);

	if (is_strprefix(sch->query, "urn:sha1:")) {		/* URN search */
		qhvec_add(qhv, sch->query, QUERY_H_URN);
		return;
	} else if (sbool_get(sch->whats_new)) {
		qhvec_set_whats_new(qhv, TRUE);
		return;
	}

	wocnt = word_vec_make(sch->query, &wovec);

	for (i = 0; i < wocnt; i++) {
		if (wovec[i].len >= QRP_MIN_WORD_LENGTH)
			qhvec_add(qhv, wovec[i].word, QUERY_H_WORD);
	}

	if (wocnt != 0)
		word_vec_free(wovec, wocnt);
}

/**
 * Can we re-issue a "What's New?" search?
 */
static bool
search_whats_new_can_reissue(void)
{
	time_delta_t elapsed = delta_time(tm_time(), search_last_whats_new);

	/*
	 * A "What's New?" search is special: it gets broadcasted to all leaves
	 * that support the feature (regardless of their QRP table) and to
	 * all ultrapeers (if TTL > 1, only those supporting the feature
	 * otherwise).
	 *
	 * As such, we don't want to broadcast these queries too often on
	 * the network.
	 */

	if (search_last_whats_new != 0 && elapsed < WHATS_NEW_DELAY) {
		char buf[80];
		time_delta_t grace = WHATS_NEW_DELAY - elapsed + 1;

		str_bprintf(ARYLEN(buf),
			_("Must wait %u more seconds before resending \"What's New\""),
			(unsigned) grace);
		gcu_statusbar_warning(buf);
		return FALSE;
	} else {
		return TRUE;
	}
}

/**
 * Create and send a search request packet
 *
 * @param sch DOCUMENT THIS!
 * @param n if NULL, we're "broadcasting" an initial search.  Otherwise, this
 * is the only node to which we should send the message.
 */
static void
search_send_packet(search_ctrl_t *sch, gnutella_node_t *n)
{
	gnutella_msg_search_t *msg = NULL;
	pmsg_t *mb;
	size_t size;

	g_assert(sch != NULL);
	g_assert(sbool_get(sch->active));
	g_assert(!sbool_get(sch->frozen));

	if (NULL == (msg = search_build_msg(sch)))
		return;

	size = gnutella_header_get_size(gnutella_msg_search_header(msg));
	size += GTA_HEADER_SIZE;

	/*
	 * All the gmsg_search_xxx() routines include the search handle.
	 * In the search queue, we put entries pointing back to the search.
	 * When the search is put in the MQ, we increment a counter in the
	 * search if the target is not a leaf node.
	 *
	 * When the counter in the search reaches the node's outdegree, then we
	 * stop sending the query on the network, even though we continue to feed
	 * the SQ as usual when new connections are made.
	 *
	 * The "query emitted" counter is reset when the search retry timer expires.
	 *
	 *		--RAM, 04/04/2003
	 */

	if (n != NULL) {
		search_mark_sent_to_node(sch, n);
		if (!NODE_TALKS_G2(n))
			gmsg_search_sendto_one(n, sch->search_handle, msg, size);
		goto gnet_done;
	}

	/*
	 * If we're a leaf node, broadcast to all our ultra peers.
	 * If we're a regular node, broadcast to all peers.
	 */

	if (settings_is_leaf()) {
		if (sbool_get(sch->whats_new)) {
			if (!search_whats_new_can_reissue())
				goto gnet_done;
			search_last_whats_new = tm_time();
		} else {
			search_starting(sch->search_handle);
		}
		search_mark_sent_to_connected_nodes(sch);
		gmsg_search_sendto_all(node_all_gnet_nodes(),
			sch->search_handle, msg, size);
		goto gnet_done;
	}

	search_qhv_fill(sch, query_hashvec);

	if (sbool_get(sch->whats_new)) {
		pslist_t *nodes;

		if (!search_whats_new_can_reissue())
			goto gnet_done;

		nodes = qrt_build_query_target(
			query_hashvec, 0, WHATS_NEW_TTL, TRUE, NULL);

		if (nodes != NULL) {
			mb = gmsg_to_pmsg(msg, size);
			gmsg_mb_sendto_all(nodes, mb);
			pmsg_free_null(&mb);
			search_last_whats_new = tm_time();
		}
		pslist_free(nodes);
	} else {
		/*
		 * Enqueue search in global SQ for later dynamic querying dispatching.
		 */

		sq_global_putq(sch->search_handle,
			gmsg_to_pmsg(msg, size), qhvec_clone(query_hashvec));
	}

	/* FALL THROUGH */

gnet_done:
	WFREE_NULL(msg, size);

	/*
	 * Now handle the G2 network side.
	 */

	if (n != NULL && NODE_TALKS_G2(n)) {
		mb = search_g2_build_q2(sch);
		if (mb != NULL)
			sq_putq(n->searchq, sch->search_handle, mb);
		/* Node already marked as "having been sent to" in code above */
	}

	if (NULL == n) {
		mb = search_g2_build_q2(sch);
		if (mb != NULL) {
			const pslist_t *sl;

			PSLIST_FOREACH(node_all_g2_nodes(), sl) {
				const gnutella_node_t *n2 = sl->data;

				node_check(n2);

				if (NULL == n2->searchq)
					continue;		/* Skip non-writable node */

				search_mark_sent_to_node(sch, n2);
				sq_putq(n2->searchq, sch->search_handle, pmsg_clone(mb));
			}
			pmsg_free_null(&mb);
		}
	}
}

/**
 * Called when we connect to a new node and thus can send it our searches.
 */
static wq_status_t
search_node_added(void *search, void *node)
{
	search_ctrl_t *sch = search;
	gnutella_node_t *n = node;

	search_ctrl_check(sch);
	g_assert(sbool_get(sch->active));
	node_check(n);

	/*
	 * If we're in UP mode, we're using dynamic querying for our own queries.
	 * If it's a G2 node, we're always sending out the query.
	 */

	if (settings_is_leaf() || NODE_TALKS_G2(n)) {
		/*
		 * Send search to new node if not already done and if the search
		 * is still active.
		 */

		if (!search_already_sent_to_node(sch, n) && !sbool_get(sch->frozen)) {
			/*
			 * If a GUESS query is active, check whether we have already
			 * queried the node.  A GUESS search will skip nodes to which we
			 * are already connected via TCP, but we may have not queried that
			 * host yet.
			 */

			if (
				NULL == sch->guess ||
				!guess_already_queried(sch->guess, n->gnet_addr, n->gnet_port)
			) {
				search_send_packet(sch, n);
			}
		}
	}

	return WQ_SLEEP;		/* Keep being notified */
}

/**
 * Create a new muid and add it to the search's list of muids.
 *
 * Also record the direct mapping between this muid and the search into
 * the `search_by_muid' table.
 */
static void
search_add_new_muid(search_ctrl_t *sch, guid_t *muid)
{
	uint count;

	g_assert(!htable_contains(search_by_muid, muid));

	if (sch->muids) {		/* If this isn't the first muid -- requerying */
		search_reset_sent_nodes(sch);
		search_reset_sent_node_ids(sch);
	}

	sch->muids = pslist_prepend(sch->muids, muid);
	htable_insert(search_by_muid, muid, sch);

	/*
	 * If we got more than MUID_MAX entries in the list, chop last items.
	 */

	count = pslist_length(sch->muids);

	while (count-- > MUID_MAX) {
		pslist_t *last = pslist_last(sch->muids);
		if (sch->guess != NULL && guess_is_search_muid(last->data)) {
			/*
			 * Do not remove an active GUESS MUID or we would not be
			 * be showing the results any more.
			 *
			 * Since GUESS queries for a given search are launched one at
			 * a time, the item right before the last entry cannot be
			 * the MUID of a GUESS query, and therefore we remove that entry
			 * instead.
			 */
			g_assert(count >= 1);
			last = pslist_nth(sch->muids, count - 1);
			g_assert(!guess_is_search_muid(last->data));
		}
		htable_remove(search_by_muid, last->data);
		wfree(last->data, GUID_RAW_SIZE);
		sch->muids = pslist_remove_link(sch->muids, last);
		pslist_free_1(last);
	}
}

/**
 * Send search to all connected nodes.
 */
static void
search_send_packet_all(search_ctrl_t *sch)
{
	sch->kept_results = 0;
	search_send_packet(sch, NULL);
}

/**
 * @return whether search has expired.
 */
static bool
search_expired(const search_ctrl_t *sch)
{
	time_t ct;
	uint lt;

	search_ctrl_check(sch);

	ct = sch->create_time;			/* In local (kernel) time */
	lt = 3600U * sch->lifetime;

	/*
	 * A lifetime of zero indicates session-only searches.
	 */

	if (lt) {
		time_delta_t d;

		d = delta_time(tm_time(), ct);
		d = MAX(0, d);
		return UNSIGNED(d) >= lt;
	}
	return FALSE;
}

/**
 * Allocate a new MUID for a search.
 *
 * @param initial indicates whether this is an initial query or a requery.
 *
 * @return a new MUID that can be wfree()'d when done.
 */
static guid_t *
search_new_muid(bool initial)
{
	guid_t *muid;
	host_addr_t addr;
	uint32 ipv4;
	int i;

	WALLOC(muid);

	/*
	 * Determine whether this is going to be an OOB query, because we have
	 * to encode our IP port correctly right now, at MUID selection time.
	 *
	 * We allow them to change their mind on `send_oob_queries', as we're not
	 * testing that flag yet, but if they allow UDP, and have a valid IP,
	 * we can encode an OOB-compatible MUID.  Likewise, we ignore the
	 * `is_udp_firewalled' yet, as this can change between now and the time
	 * we emit the query.
	 *
	 * IPv6-Ready: if our primary address is IPv6, the full IPv6 address will
	 * be given via an additional GGEP "6" extension, added when we're building
	 * the query message.
	 */

	addr = listen_addr_primary();
	ipv4 = ipv6_ready_advertised_ipv4(addr);

	for (i = 0; i < 100; i++) {
		if (udp_active() && host_addr_is_routable(addr)) {
			guid_query_oob_muid(muid, host_addr_get_ipv4(ipv4),
				socket_listen_port(), initial);
		} else {
			guid_query_muid(muid, initial);
		}

		/*
		 * Make sure the search MUID is not that of an older search that we
		 * keep around or that of a recently expired GUESS query (since active
		 * GUESS queries are already held in `search_by_muid').
		 *		--RAM, 2014-02-04
		 */

		if (
			!htable_contains(search_by_muid, muid) &&
			!guess_is_search_muid(muid)
		)
			return muid;
	}

	g_error("random number generator not random enough");	/* Sorry */

	return NULL;
}

static uint32
search_max_results_for_ui(const search_ctrl_t *sch)
{
	if (sbool_get(sch->browse))
		return GNET_PROPERTY(browse_host_max_results);
	else if (sbool_get(sch->whats_new))
		return GNET_PROPERTY(whats_new_search_max_results);
	else if (sbool_get(sch->local) || sbool_get(sch->passive))
		return GNET_PROPERTY(passive_search_max_results);
	else
		return GNET_PROPERTY(search_max_results);
}

/**
 * Make sure a timer is created/removed after a search was started/stopped.
 */
static void
update_one_reissue_timeout(search_ctrl_t *sch)
{
	uint32 max_items;
	unsigned percent;
	float factor;
	uint32 tm;

	search_ctrl_check(sch);
	g_assert(sbool_get(sch->active));

	/*
	 * When a search is frozen or the reissue_timout is zero, all we need
	 * to do is to remove the timer.
	 */

	if (sbool_get(sch->frozen) || sch->reissue_timeout == 0) {
		cq_periodic_remove(&sch->reissue_ev);
		return;
	}

	/*
	 * Look at the amount of items we got for this search already.
	 * The more we have, the less often we retry to save network resources.
	 */
	max_items = search_max_results_for_ui(sch);
	max_items = MAX(1, max_items);

	percent = sch->items * 100 / max_items;
	factor = (percent < 10) ? 1.0 :
		1.0 + (percent - 10) * (percent - 10) / 550.0;

	tm = (uint32) sch->reissue_timeout;
	tm = (uint32) (MAX(tm, SEARCH_MIN_RETRY) * factor);

	/*
	 * Otherwise we also add a new timer. If the search was stopped, this
	 * will restart the search, otherwise is will simply reset the timer
	 * and set a new timer with the searches's reissue_timeout.
	 */

	if (GNET_PROPERTY(search_debug) > 2)
		g_debug("updating search \"%s\" with timeout %u.", sch->query, tm);

	if (NULL == sch->reissue_ev) {
		sch->reissue_ev = cq_periodic_main_add(
			tm * 1000, search_reissue_timeout_callback, sch);
	} else {
		cq_periodic_resched(sch->reissue_ev, tm * 1000);
	}
}

/**
 * Force a reissue of the given search. Restart reissue timer.
 */
static void
search_reissue(search_ctrl_t *sch)
{
	guid_t *muid;

	search_ctrl_check(sch);
	g_return_if_fail(!sbool_get(sch->frozen));

	if (sbool_get(sch->local)) {
		search_locally(sch->search_handle, sch->query);
		return;
	}

	g_return_if_fail(sbool_get(sch->active));

	/*
	 * If the search has expired, disable any further invocation.
	 */

	if (search_expired(sch)) {
		if (GNET_PROPERTY(search_debug))
			g_debug("expired search \"%s\" (queries broadcasted: %d)",
				sch->query, sch->query_emitted);
		sch->frozen = sbool_set(TRUE);
		wd_sleep(sch->activity);
		goto done;
	}

	if (GNET_PROPERTY(search_debug))
		g_debug("reissuing search \"%s\" (queries broadcasted: %d)",
			sch->query, sch->query_emitted);

	/*
	 * When a "broadcasting" search is issued, cancel any running
	 * backgound "iterating" search as soon as it will be starving...
	 *
	 * Otherwise, let it continue its crawl in the background, as we
	 * may explore ultrapeers that our broadcast may never be reaching.
	 */

	if (sch->guess != NULL)
		guess_end_when_starving(sch->guess);

	muid = search_new_muid(FALSE);

	sch->query_emitted = 0;
	search_add_new_muid(sch, muid);
	search_send_packet_all(sch);

done:
	update_one_reissue_timeout(sch);
}

/**
 * Called when the reissue timer for any search is triggered.
 *
 * The data given is the search to be reissued.
 */
static bool
search_reissue_timeout_callback(void *data)
{
	search_ctrl_t *sch = data;

	search_ctrl_check(sch);

	search_reissue(sch);
	search_status_changed(sch->search_handle);
	return TRUE;
}

#define CLOSED_SEARCH	0xffff

/**
 * Send an unsolicited "Query Status Response" to the specified node ID,
 * bearing the amount of kept results.  The 0xffff value is a special
 * marker to indicate the search was closed.
 */
static void
search_send_query_status(search_ctrl_t *sch,
	const struct nid *node_id, uint16 kept)
{
	gnutella_node_t *n;

	n = node_active_by_id(node_id);
	if (n == NULL)
		return;					/* Node disconnected already */

	if (GNET_PROPERTY(search_debug) > 1)
		g_debug("SCH reporting %u kept results so far for \"%s\" to %s",
			kept, sch->query, node_addr(n));

	/*
	 * We use the first MUID in the list, i.e. the last one we used
	 * for sending out queries for that search.
	 */

	vmsg_send_qstat_answer(n, sch->muids->data, kept);
}

/**
 * Send an unsolicited "Query Status Response" to the specified node ID
 * about the results we kept so far for the relevant search.
 * -- hash set iterator callback
 */
static void
search_send_status(const void *key, void *udata)
{
	const struct nid *node_id = key;
	search_ctrl_t *sch = udata;
	uint16 kept;

	/*
	 * The 0xffff value is a magic number telling them to stop the search,
	 * so we never report it here.
	 */

	kept = MIN(sch->kept_results, (CLOSED_SEARCH - 1));
	search_send_query_status(sch, node_id, kept);
}

/**
 * Update our querying ultrapeers about the results we kept so far for
 * the given search.
 */
static void
search_update_results(search_ctrl_t *sch)
{
	hset_foreach(sch->sent_node_ids, search_send_status, sch);
}

/**
 * Send an unsolicited "Query Status Response" to the specified node ID
 * informing it that the search was closed.
 * -- hash set iterator callback
 */
static void
search_send_closed(const void *key, void *udata)
{
	const struct nid *node_id = key;
	search_ctrl_t *sch = udata;

	search_send_query_status(sch, node_id, CLOSED_SEARCH);
}

/**
 * Tell our querying ultrapeers that the search is closed.
 */
static void
search_notify_closed(gnet_search_t sh)
{
	search_ctrl_t *sch = search_find_by_handle(sh);

	hset_foreach(sch->sent_node_ids, search_send_closed, sch);
}

/**
 * Signal to all search queues that search was closed.
 */
static void
search_dequeue_all_nodes(gnet_search_t sh)
{
	const pslist_t *sl;

	PSLIST_FOREACH(node_all_nodes(), sl) {
		gnutella_node_t *n = sl->data;
		squeue_t *sq;

		node_check(n);

		sq = NODE_SQUEUE(n);
		if (sq != NULL)
			sq_search_closed(sq, sh);
	}

	sq_search_closed(sq_global_queue(), sh);

	/*
	 * We're only issuing dynamic queries if we're an ultra node.
	 *
	 * Otherwise, our ultra nodes are doing the dynamic querying,
	 * and we have to notify them that it's no longer useful to
	 * continue sending queries on our behalf.
	 */

	if (settings_is_ultra())
		dq_search_closed(sh);
	else
		search_notify_closed(sh);
}

/**
 * Garbage collector -- callout queue periodic callback.
 */
static bool
search_gc(void *unused_cq)
{
	(void) unused_cq;

	query_muid_map_garbage_collect();

	return TRUE;		/* Keep calling */
}

/***
 *** Public functions
 ***/

void G_COLD
search_init(void)
{
	TOKENIZE_CHECK_SORTED(g2_qh2_children);
	TOKENIZE_CHECK_SORTED(g2_qh2_h_children);
	TOKENIZE_CHECK_SORTED(g2_qh2_urn);

	search_by_muid = htable_create(HASH_KEY_FIXED, GUID_RAW_SIZE);
	search_handle_map = idtable_new(32);
	sha1_to_search = htable_create(HASH_KEY_FIXED, SHA1_RAW_SIZE);
	/* Max: 128 unique words / URNs! */
	query_hashvec = qhvec_alloc(QRP_HVEC_MAX);
	query_muid_map_init();
	guess_stg = sectoken_gen_new(GUESS_KEYS, GUESS_REFRESH_PERIOD);
	ora_stg = sectoken_gen_new(ORA_KEYS, OOB_REPLY_ACK_TIMEOUT);
	ora_secure = aging_make(OOB_REPLY_ACK_TIMEOUT,
		gnet_host_hash, gnet_host_equal, gnet_host_free_atom2);

	cq_periodic_main_add(SEARCH_GC_PERIOD * 1000, search_gc, NULL);
}

void G_COLD
search_shutdown(void)
{
	while (sl_search_ctrl != NULL) {
		search_ctrl_t *sch = sl_search_ctrl->data;

		search_ctrl_check(sch);
		g_warning("force-closing search left over by GUI: %s", sch->query);
		search_close(sch->search_handle);
	}

	g_assert(0 == idtable_count(search_handle_map));

	htable_free_null(&search_by_muid);
	htable_free_null(&sha1_to_search);
	idtable_destroy(search_handle_map);
	search_handle_map = NULL;
	qhvec_free(query_hashvec);

	query_muid_map_close();
	sectoken_gen_free_null(&guess_stg);
	sectoken_gen_free_null(&ora_stg);
	aging_destroy(&ora_secure);
}

/**
 * Check for alternate locations in the result set, and enqueue the downloads
 * if there are any.  Then free the alternate location from the record.
 */
static void
search_check_alt_locs(gnet_results_set_t *rs, gnet_record_t *rc, fileinfo_t *fi)
{
	gnet_host_vec_t *alt = rc->alt_locs;
	unsigned i, ignored = 0;

	g_assert(alt != NULL);

	i = gnet_host_vec_count(alt);
	while (i-- > 0) {
		struct gnutella_host host;
		host_addr_t addr;
		uint16 port;

		host = gnet_host_vec_get(alt, i);
		addr = gnet_host_get_addr(&host);
		port = gnet_host_get_port(&host);
		if (host_is_valid(addr, port)) {
			download_auto_new(rc->filename,
				rc->size,
				addr,
				port,
				&blank_guid,
				NULL,	/* hostname */
				rc->sha1,
				rc->tth,
				rs->stamp,
				fi,
				NULL,	/* proxies */
				0);		/* flags */
		} else {
			ignored++;
		}
	}

	search_free_alt_locs(rc);

	if (ignored) {
		const char *vendor = vendor_get_name(rs->vcode);
		g_warning("ignored %u invalid alt-loc%s in hits from %s (%s)",
			PLURAL(ignored),
			host_addr_port_to_string(rs->addr, rs->port),
			vendor ? vendor : "????");
	}
}

static void
search_results_set_flag_records(gnet_results_set_t *rs)
{
	const pslist_t *sl;
	bool need_push = FALSE;

	if (rs->guid != NULL && !guid_is_blank(rs->guid)) {
		if ((rs->status & ST_FIREWALL) || !host_is_valid(rs->addr, rs->port)) {
			need_push = TRUE;
		}
	}

	PSLIST_FOREACH(rs->records, sl) {
		shared_file_t *sf;
		gnet_record_t *rc = sl->data;

		if (need_push) {
			rc->flags |= SR_PUSH;
		}

		if (!rc->sha1)
			continue;

		sf = shared_file_by_sha1(rc->sha1);
		if (sf && SHARE_REBUILDING != sf) {
			if (shared_file_is_finished(sf)) {
				rc->flags |= SR_SHARED;
			} else {
				rc->flags |= SR_PARTIAL;
			}
		} else {
			ignore_val_t reason;

			reason = ignore_is_requested(rc->filename, rc->size, rc->sha1);
			switch (reason) {
				case IGNORE_FALSE:
					break;
				case IGNORE_SHA1:
				case IGNORE_NAMESIZE:
				case IGNORE_LIBRARY:
					rc->flags |= SR_OWNED;
					break;
				case IGNORE_SPAM:
					rc->flags |= SR_SPAM;
					break;
				case IGNORE_OURSELVES:
				case IGNORE_HOSTILE:
				case IGNORE_LIMIT:
					/* These are for manual use and never returned */
					g_assert_not_reached();
					break;
			}
			if (IGNORE_FALSE != reason) {
				switch (GNET_PROPERTY(search_handle_ignored_files)) {
				case SEARCH_IGN_DISPLAY_AS_IS:
					break;
				case SEARCH_IGN_NO_DISPLAY:
					rc->flags |= SR_DONT_SHOW;
					break;
				default:
					rc->flags |= SR_IGNORED;
				}
			}
		}
		shared_file_unref(&sf);
	}
}

/**
 * Check a results_set for matching entries in the download queue,
 * and generate new entries if we find a match.
 */
static void
search_results_set_auto_download(gnet_results_set_t *rs)
{
	const pslist_t *sl;

	if (!GNET_PROPERTY(auto_download_identical))
		return;

	PSLIST_FOREACH(rs->records, sl) {
		gnet_record_t *rc = sl->data;
		fileinfo_t *fi;

		if (!rc->sha1)
			continue;

		fi = file_info_has_identical(rc->sha1, rc->size);
		if (fi) {
			uint32 flags = 0;

			flags |= (rs->status & ST_FIREWALL) ? SOCK_F_PUSH : 0;
			flags |= !host_is_valid(rs->addr, rs->port) ? SOCK_F_PUSH : 0;
			flags |= (rs->status & ST_TLS) ? SOCK_F_TLS : 0;

			download_auto_new(rc->filename,
				rc->size,
				rs->addr,
				rs->port,
				rs->guid,
				rs->hostname,
				rc->sha1,
				rc->tth,
				rs->stamp,
				fi,
				rs->proxies,
				flags);

			search_free_proxies(rs);
			rc->flags |= SR_DOWNLOADED;

			/*
			 * If there are alternate sources for this download in the query
			 * hit, enqueue the downloads as well, then remove the sources
			 * from the record.
			 *		--RAM, 15/07/2003.
			 */

			if (rc->alt_locs != NULL)
				search_check_alt_locs(rs, rc, fi);

			g_assert(rc->alt_locs == NULL);
		}
	}
}


/**
 * This routine is called for each Query Hit or /QH2 packet we receive out of
 * a browse-host request, since we know the target search result, and
 * we don't need to bother with forwarding that message.
 *
 * @param n			the node receiving the hit
 * @param sh		the "browse-host" search handle
 * @param t			the message tree (for G2, NULL for Gnutella)
 */
void
search_browse_results(gnutella_node_t *n, gnet_search_t sh, const g2_tree_t *t)
{
	gnet_results_set_t *rs;
	pslist_t *search = NULL;
	pslist_t *sl;
	hostiles_flags_t flags;

	if (NULL == t)
		rs = get_results_set(n, TRUE, &flags);
	else
		rs = get_g2_results_set(n, t, TRUE, &flags);

	if (rs == NULL)
		return;

	/*
	 * Dispatch the results as-is without any ignoring to the GUI, which
	 * will copy the information for its own perusal (and filtering).
	 */
	{
		search_ctrl_t *sch = search_find_by_handle(sh);

		search_ctrl_check(sch);

		if (!sbool_get(sch->frozen))
			search = pslist_prepend(search,
						uint_to_pointer(sch->search_handle));
	}

	/*
	 * We're also going to dispatch the results to all the opened passive
	 * searches, since they may have customized filters.
	 */

	if (GNET_PROPERTY(browse_copied_to_passive)) {
		uint32 max_items = GNET_PROPERTY(passive_search_max_results);

		PSLIST_FOREACH(sl_passive_ctrl, sl) {
			search_ctrl_t *sch = sl->data;

			search_ctrl_check(sch);

			if (!sbool_get(sch->frozen) && sch->items < max_items)
				search = pslist_prepend(search,
					uint_to_pointer(sch->search_handle));
		}
	}

	if (search) {
		search_results_set_flag_records(rs);
		search_results_set_auto_download(rs);
		search_fire_got_results(search, NULL, rs);
		pslist_free_null(&search);
	}

	search_free_r_set(rs);
}

/**
 * This routine is called for each hit packet (Gnutella and G2) we receive.
 *
 * @param n			the node receiving the hit
 * @param t			the message tree (for G2, NULL for Gnutella)
 * @param results	if not NULL, where amount of results in hit is written back
 *
 * @returns whether the message should be dropped, i.e. FALSE if OK.
 * If the message should not be dropped, `results' is filled with the
 * amount of results contained in the query hit.
 */
static bool
search_results_process(gnutella_node_t *n, const g2_tree_t *t, int *results)
{
	gnet_results_set_t *rs;
	pslist_t *sl;
	bool drop_it = FALSE;
	bool forward_it = TRUE;
	bool dispatch_it = TRUE;
	pslist_t *selected_searches = NULL;
	uint32 max_items;
	hostiles_flags_t flags;
	const guid_t *muid;
	guid_t muid_buf;

	g_assert(!(NULL != t) == !NODE_TALKS_G2(n));

	/*
	 * Get the MUID of the query that produced this hit.
	 */

	if (NULL == t) {
		muid = gnutella_header_get_muid(&n->header);
	} else {
		muid = g2_msg_get_muid(t, &muid_buf);
		if (NULL == muid) {
			gnet_stats_count_dropped(n, MSG_DROP_BAD_RESULT);
			return TRUE;
		}
	}

	/*
	 * We'll dispatch to non-frozen passive searches, and to the active search
	 * matching the MUID, if any and not frozen as well.
	 */

	max_items = GNET_PROPERTY(passive_search_max_results);

	PSLIST_FOREACH(sl_passive_ctrl, sl) {
		search_ctrl_t *sch = sl->data;

		search_ctrl_check(sch);

		if (!sbool_get(sch->frozen) && sch->items < max_items)
			selected_searches = pslist_prepend(selected_searches,
						uint_to_pointer(sch->search_handle));
	}

	{
		search_ctrl_t *sch;

		sch = htable_lookup(search_by_muid, muid);
		max_items = sch ? search_max_results_for_ui(sch) : 0;

		if (sch && !sbool_get(sch->frozen) && sch->items < max_items)
			selected_searches = pslist_prepend(selected_searches,
				uint_to_pointer(sch->search_handle));
	}

	/*
	 * Parse the packet.
	 *
	 * If we're not going to dispatch it to any search or auto-download files
	 * based on the SHA1, the packet is only parsed for validation.
	 */

	if (NULL == t)
		rs = get_results_set(n, FALSE, &flags);
	else
		rs = get_g2_results_set(n, t, FALSE, &flags);

	if (rs == NULL) {
        /*
         * get_results_set takes care of telling the stats that
         * the message was dropped.
         */
		drop_it = TRUE;				/* Don't forward bad packets */
		goto final_cleanup;
	}

	g_assert(rs->num_recs > 0);

	if (results != NULL)
		*results = rs->num_recs;

	/*
	 * If we're handling a message from our immediate neighbour, grab the
	 * vendor code from the QHD.  This is useful for 0.4 handshaked nodes
	 * to determine and display their vendor ID.
	 */

	if (0 == rs->hops && !NODE_IS_UDP(n))
		update_neighbour_info(n, rs);

	/*
	 * Apply country limits to determine whether we should dispatch
	 * the hits to the various selected searches.
	 */

	if (selected_searches != NULL) {
		host_addr_t c_addr = (0 == rs->hops && (rs->status & ST_UDP)) ?
			rs->last_hop : rs->addr;
		if (ctl_limit(c_addr, CTL_D_QHITS))
			dispatch_it = FALSE;
	}

	if (
		(rs->status & (ST_SPAM | ST_EVIL)) &&
		(
		 	(ST_UDP|ST_GOOD_TOKEN) == ((ST_UDP|ST_GOOD_TOKEN) & rs->status) ||
			(0 == rs->hops && !NODE_IS_UDP(n)) ||
			(ST_UDP|ST_G2) == ((ST_UDP|ST_G2) & rs->status)
		)
	) {
		host_addr_t n_addr = (0 == rs->hops) ? rs->last_hop : rs->addr;

		hostiles_dynamic_add(n_addr, "spam/evil query hits", flags);
		rs->status |= ST_HOSTILE;

		/*
		 * Record spamming hosts to avoid requesting OOB hits from them
		 * in the future.
		 */

		if (0 == rs->hops && ST_UDP == ((ST_UDP|ST_G2) & rs->status)) {
			hostiles_spam_add(rs->last_hop, rs->port);
		}
	}

	/*
	 * Let dynamic querying know about the result count, in case
	 * there is a dynamic query opened for this.
	 *
	 * Also pass the results to the dynamic query hit monitoring (DH)
	 * to be able to throttle messages if we get too many hits.
	 *
	 * NB: if the dynamic query says the user is no longer interested
	 * by the query, we won't forward the results, but we don't set
	 * `drop_it' as this is reserved for bad packets.
	 */

	if (
		rs->status &
			(ST_SPAM | ST_EVIL | ST_HOSTILE | ST_MORPHEUS_BOGUS | ST_MEDIA)
	) {
		forward_it = FALSE;
		/* It's not really dropped, just not forwarded, count it anyway. */
		if (ST_SPAM & rs->status) {
			gnet_stats_count_dropped(n, MSG_DROP_SPAM);
		} else if (ST_EVIL & rs->status) {
			gnet_stats_count_dropped(n, MSG_DROP_EVIL);
		} else if (ST_HOSTILE & rs->status) {
			gnet_stats_count_dropped(n, MSG_DROP_HOSTILE_IP);
		} else if (ST_MORPHEUS_BOGUS & rs->status) {
			gnet_stats_count_dropped(n, MSG_DROP_MORPHEUS_BOGUS);
		} else if (ST_MEDIA & rs->status) {
			gnet_stats_count_dropped(n, MSG_DROP_MEDIA);
		}
	} else {
		if (
			t != NULL ||	/* Don't forward G2 hits, don't pass them to DQ */
			!dq_got_results(gnutella_header_get_muid(&n->header),
				rs->num_recs, rs->status)
		)
			forward_it = FALSE;

		/*
		 * If we got results for an OOB-proxied query, we'll forward
		 * the hit to the proper leaf, but we don't want to route this
		 * message any further.
		 *
		 * Also, the DH layer is invoked directly from the OOB-proxy layer
		 * if the MUID is for a proxied query, using the unmangled original
		 * MUID of the query, as sent by the leaf.  Therefore, we can only
		 * call dh_got_results() when oob_proxy_got_results() returns FALSE.
		 */

		if (forward_it) {
			if (
				GNET_PROPERTY(proxy_oob_queries) &&
				oob_proxy_got_results(n, rs->num_recs)
			)
				forward_it = FALSE;
			else
				dh_got_results(gnutella_header_get_muid(&n->header),
					rs->num_recs);
		}

		/*
		 * If we're not going to dispatch the query hit, then we must act
		 * as if we had not received it in the first place, so do not attempt
		 * to collect alternate locations from it for downloading.
		 */

		if (dispatch_it) {
			/* Look for records that match entries in the download queue */
			search_results_set_auto_download(rs);
		}

		/*
		 * Look for records whose SHA1 matches files we own and add
		 * those entries to the mesh.
		 */

		if (GNET_PROPERTY(auto_feed_download_mesh))
			dmesh_check_results_set(rs);
	}

	/*
	 * Dispatch the results to the selected searches.
	 */

	if (dispatch_it && selected_searches != NULL) {
		const guid_t *guess_muid = NULL;

		/*
		 * When dealing with a GUESS search we have to pass in the GUESS
		 * query MUID so that this parameter may be passed back by the GUI
		 * once it has filtered results and we know we're being notified
		 * about kept results for a GUESS search (and which one), which in
		 * turn allows us to track the amount of meaningful results that a
		 * GUESS query generates.
		 *
		 * So this GUESS MUID we're giving to the GUID is to be construed
		 * as an opaque ID that allows us to tie our ends in the core side.
		 *
		 * This complication is only necessary because results filtering
		 * happens in the GUI and not in the core as it should (FIXME, but
		 * this is far from trivial as the whole filtering configuration
		 * must be exchanged between the core and the GUI, along with the
		 * associated statistics, for proper GUI display and editing).
		 */

		if (guess_is_search_muid(muid)) {
			rs->status |= ST_GUESS;
			guess_got_results(muid, rs->num_recs);
			guess_muid = muid;

			if (GNET_PROPERTY(guess_client_debug) > 5) {
				search_ctrl_t *sch;
				sch = htable_lookup(search_by_muid, muid);
				if (NULL == sch) {
					g_carp("%s(): GUESS search %s not found by MUID",
						G_STRFUNC, guid_to_string(muid));
				} else {
					void *data = pslist_find(selected_searches,
						uint_to_pointer(sch->search_handle));
					if (NULL == data) {
						g_carp("%s(): GUESS search %s not selected!",
							G_STRFUNC, guid_to_string(muid));
					} else {
						g_debug("GUESS delivering hit with %u record%s "
							"for \"%s\" %s",
							PLURAL(rs->num_recs),
							sch->name, guid_to_string(muid));
					}
				}
			}
		}

		search_results_set_flag_records(rs);

		if (GNET_PROPERTY(log_query_hit_records))
			search_results_records_log(n, rs);

		search_fire_got_results(selected_searches, guess_muid, rs);

		/*
		 * Record activity on each search to which we're dispatching results.
		 */

		PSLIST_FOREACH(selected_searches, sl) {
			gnet_search_t sh = pointer_to_uint(sl->data);
			search_ctrl_t *sch = search_find_by_handle(sh);

			wd_kick(sch->activity);

			if (GNET_PROPERTY(search_debug) > 1) {
				g_debug("SEARCH \"%s\" got %u record%s for %s#%s from %s",
					sch->name, PLURAL(rs->num_recs),
					(ST_GUESS & rs->status) ? "GUESS " : "",
					guid_to_string(muid), node_infostr(n));
			}
		}
	}

    search_free_r_set(rs);

final_cleanup:
	pslist_free(selected_searches);

	return drop_it || !forward_it;
}

/**
 * This routine is called for each Query Hit packet we receive.
 *
 * @returns whether the message should be dropped, i.e. FALSE if OK.
 * If the message should not be dropped, `results' is filled with the
 * amount of results contained in the query hit.
 */
bool
search_results(gnutella_node_t *n, int *results)
{
	return search_results_process(n, NULL, results);
}

/**
 * This routine is called for each /QH2 packet we receive.
 */
void
search_g2_results(gnutella_node_t *n, const g2_tree_t *t)
{
	search_results_process(n, t, NULL);
}

/**
 * Check whether we can send another query for this search.
 *
 * @returns TRUE if we can send, with the emitted counter incremented, or FALSE
 * if the query should just be ignored.
 */
bool
search_query_allowed(gnet_search_t sh)
{
    search_ctrl_t *sch = search_find_by_handle(sh);

	search_ctrl_check(sch);

	/*
	 * We allow the query to be sent once more than our outdegree.
	 *
	 * This is because "sending" here means putting the message in
	 * the message queue, not physically sending.  We might never get
	 * a chance to send that message.
	 */

	if (sch->query_emitted > node_outdegree())
		return FALSE;

	sch->query_emitted++;
	return TRUE;
}

/**
 * Notification from sq that a query for this search was sent to the
 * specified node ID.
 */
void
search_notify_sent(gnet_search_t sh, const struct nid *node_id)
{
	search_ctrl_t *sch = search_probe_by_handle(sh);

	if (NULL == sch)
		return;

	search_mark_sent_to_node_id(sch, node_id);
	search_mark_query_sent(sch);
}

static bool
search_remove_sha1_key(const void *key, void *value, void *data)
{
	const struct sha1 *sha1 = key;
	gnet_search_t sh = pointer_to_uint(value);
	search_ctrl_t *sch = data;

	if (sh == sch->search_handle) {
		g_assert(uint_is_positive(sch->sha1_downloaded));
		sch->sha1_downloaded--;
		atom_sha1_free(sha1);
		return TRUE;
	} else {
		return FALSE;
	}
}

/**
 * Forget about all the SHA1s which were downloaded by this search.
 */
static void
search_dissociate_all_sha1(search_ctrl_t *sch)
{
	if (0 == sch->sha1_downloaded)
		return;

	htable_foreach_remove(sha1_to_search, search_remove_sha1_key, sch);

	g_assert(0 == sch->sha1_downloaded);
}

struct search_sha1_context {
	gnet_search_t sh;
	pslist_t *sl;
};

/**
 * Hash table iterator to append SHA1 to list of associated SHA1s
 * for the search.
 */
static void
search_add_associated_sha1(const void *key, void *value, void *data)
{
	const struct sha1 *sha1 = key;
	gnet_search_t sh = pointer_to_uint(value);
	struct search_sha1_context *ctx = data;

	if (sh == ctx->sh) {
		ctx->sl = pslist_prepend_const(ctx->sl, sha1);
	}
}

/***
 *** Public functions.
 ***/

/**
 * Associate a SHA1 with a search.
 */
void
search_associate_sha1(gnet_search_t sh, const struct sha1 *sha1)
{
    search_ctrl_t *sch = search_probe_by_handle(sh);

	g_return_if_fail(sch);
	search_ctrl_check(sch);

	if (sbool_get(sch->track_sha1)) {
		if (!htable_contains(sha1_to_search, sha1)) {
			htable_insert(sha1_to_search, atom_sha1_get(sha1),
				uint_to_pointer(sh));
			sch->sha1_downloaded++;

			if (GNET_PROPERTY(search_debug) > 1) {
				g_debug("SEARCH \"%s\" #%u associated with urn:sha1:%s",
					lazy_safe_search(sch->query),
					(unsigned) sch->search_handle, sha1_base32(sha1));
			}
			gcu_search_gui_store_searches();
		}
	}
}

/**
 * Dissociate a SHA1 from its search.
 *
 * This is called when the corresponding file has finished downloading and
 * its SHA1 has been correctly verified.
 */
void
search_dissociate_sha1(const struct sha1 *sha1)
{
	if (htable_contains(sha1_to_search, sha1)) {
		gnet_search_t sh;
		search_ctrl_t *sch;

		sh = pointer_to_uint(htable_lookup(sha1_to_search, sha1));
		sch = search_probe_by_handle(sh);

		search_ctrl_check(sch);
		g_assert(sbool_get(sch->track_sha1));
		g_assert(uint_is_positive(sch->sha1_downloaded));

		if (GNET_PROPERTY(search_debug) > 1) {
			g_debug("SEARCH \"%s\" #%u dissociating from urn:sha1:%s, "
				"with %u more pending",
				lazy_safe_search(sch->query),
				(unsigned) sch->search_handle, sha1_base32(sha1),
				sch->sha1_downloaded - 1);
		}

		sch->sha1_downloaded--;
		htable_remove(sha1_to_search, sha1);
		atom_sha1_free(sha1);

		/*
		 * When a search has no more pending downloads, stop it.
		 */

		if (GNET_PROPERTY(search_smart_stop) && 0 == sch->sha1_downloaded) {
			search_stop(sh);

			if (GNET_PROPERTY(search_debug)) {
				g_debug("SEARCH \"%s\" stopped due to no pending download",
					lazy_safe_search(sch->query));
			}
		}

		gcu_search_gui_store_searches();
	}
}

/**
 * @return list of SHA1 associated with a given search, NULL if none.
 */
pslist_t *
search_associated_sha1(gnet_search_t sh)
{
    search_ctrl_t *sch = search_probe_by_handle(sh);
	struct search_sha1_context ctx;

	g_return_val_if_fail(sch, NULL);
	search_ctrl_check(sch);

	if (0 == sch->sha1_downloaded)
		return NULL;

	ctx.sh = sh;
	ctx.sl = NULL;

	htable_foreach(sha1_to_search, search_add_associated_sha1, &ctx);

	return ctx.sl;
}

/**
 * @return amount of SHA1s associated with a given search.
 */
unsigned
search_associated_sha1_count(gnet_search_t sh)
{
	search_ctrl_t *sch = search_probe_by_handle(sh);

	g_return_val_if_fail(sch, 0);
	search_ctrl_check(sch);

	return sch->sha1_downloaded;
}

/**
 * Remove the search from the list of searches and free all
 * associated ressources.
 */
void
search_close(gnet_search_t sh)
{
    search_ctrl_t *sch = search_probe_by_handle(sh);

	g_return_if_fail(sch);
	search_ctrl_check(sch);

	entropy_harvest_many(VARLEN(sh),
		sch->name, vstrlen(sch->name),
		VARLEN(sch->items),
		VARLEN(sch->kept_results),
		VARLEN(sch->query_emitted),
		VARLEN(sch->id),
		VARLEN(sch->media_type),
		VARLEN(sch->time),
		VARLEN(sch->create_time),
		sch->query, vstrlen(sch->query),
		NULL);

	/*
	 * This needs to be done before the handle of the search is reclaimed.
	 */

	if (sbool_get(sch->active))
		search_dequeue_all_nodes(sh);

    /*
     * We remove the search immeditaly from the list of searches,
     * because some of the following calls (may) depend on
     * "searches" holding only the remaining searches.
     * We may not free any ressources of "sch" yet, because
     * the same calls may still need them!.
     *      --BLUE 26/05/2002
     */

	sl_search_ctrl = pslist_remove(sl_search_ctrl, sch);

	if (sbool_get(sch->passive))
		sl_passive_ctrl = pslist_remove(sl_passive_ctrl, sch);

	if (sbool_get(sch->browse) && sch->download != NULL)
		download_abort_browse_host(sch->download, sh);

    search_drop_handle(sch->search_handle);

	if (sbool_get(sch->active)) {
		wq_cancel(&sch->new_node_wait);
		cq_periodic_remove(&sch->reissue_ev);

		if (sch->muids) {
			pslist_t *sl;

			PSLIST_FOREACH(sch->muids, sl) {
				htable_remove(search_by_muid, sl->data);
				wfree(sl->data, GUID_RAW_SIZE);
			}
			pslist_free_null(&sch->muids);
		}

		search_free_sent_nodes(sch);
		search_free_sent_node_ids(sch);
	}

	atom_str_free_null(&sch->query);
	atom_str_free_null(&sch->name);
	wd_free_null(&sch->activity);
	guess_cancel(&sch->guess, FALSE);
	search_dissociate_all_sha1(sch);

	sch->magic = 0;
	WFREE(sch);
}

/**
 * Indicates that the search is starting: we're emitting the query.
 */
void
search_starting(gnet_search_t sh)
{
    search_ctrl_t *sch = search_find_by_handle(sh);

	search_ctrl_check(sch);
    g_return_if_fail(sbool_get(sch->active));
    g_return_if_fail(sch->activity != NULL);

	wd_wakeup(sch->activity);
}

/**
 * Set the reissue timeout of a search.
 */
void
search_set_reissue_timeout(gnet_search_t sh, uint32 timeout)
{
    search_ctrl_t *sch = search_find_by_handle(sh);

	search_ctrl_check(sch);
    g_return_if_fail(sbool_get(sch->active));

	timeout = timeout > 0 ? MAX(SEARCH_MIN_RETRY, timeout) : 0;
	if (sch->reissue_timeout != timeout) {
		sch->reissue_timeout = timeout;
		update_one_reissue_timeout(sch);
	}
}

/**
 * Get the reissue timeout of a search.
 */
uint32
search_get_reissue_timeout(gnet_search_t sh)
{
    search_ctrl_t *sch = search_find_by_handle(sh);

	search_ctrl_check(sch);

    return sch->reissue_timeout;
}

/**
 * Get the configured media type filtering for this search.
 */
unsigned
search_get_media_type(gnet_search_t sh)
{
    search_ctrl_t *sch = search_find_by_handle(sh);

	search_ctrl_check(sch);

    return sch->media_type;
}

/**
 * Get the initial lifetime (in hours) of a search.
 */
uint
search_get_lifetime(gnet_search_t sh)
{
    search_ctrl_t *sch = search_find_by_handle(sh);

	search_ctrl_check(sch);

    return sch->lifetime;
}

/**
 * Get the create time of a search.
 */
time_t
search_get_create_time(gnet_search_t sh)
{
    search_ctrl_t *sch = search_find_by_handle(sh);

	search_ctrl_check(sch);

    return sch->create_time;
}

/**
 * Set the create time of a search.
 */
void
search_set_create_time(gnet_search_t sh, time_t t)
{
    search_ctrl_t *sch = search_find_by_handle(sh);

	search_ctrl_check(sch);

	sch->create_time = t;
}

/**
 * Callback invoked when GUESS query ends.
 */
static void
search_guess_done(void *data)
{
	search_ctrl_t *sch = data;

	search_ctrl_check(sch);
	g_return_if_fail(sch->guess != NULL);

	sch->guess = NULL;
}

/**
 * Watchdog callback when search is becoming idle.
 *
 * @return TRUE if watchdog should remain active, FALSE to put it to sleep.
 */
static bool
search_is_idle(watchdog_t *unused_wd, void *data)
{
	search_ctrl_t *sch = data;
	guid_t *muid;

	search_ctrl_check(sch);
	g_assert(!sbool_get(sch->passive));

	(void) unused_wd;

	if (GNET_PROPERTY(search_debug)) {
		g_debug("search \"%s\" now idle (kept results: %u, GUESS %s)",
			sch->query, sch->kept_results,
			!guess_query_enabled() ? "disabled" :
			sch->guess != NULL ? "running" : "idle");
	}

	if (sch->guess != NULL)
		return FALSE;			/* GUESS already active */

	if (!guess_query_enabled())
		return TRUE;

	/*
	 * If the previous query (dynamic querying most probably) already
	 * returned enough results, do not launch a GUESS query.
	 */

	if (sch->kept_results >= SEARCH_MAX_RESULTS)
		return FALSE;

	/*
	 * Launch a new GUESS query for this search.
	 */

	muid = search_new_muid(FALSE);
	search_add_new_muid(sch, muid);
	sch->kept_results = 0;
	sch->guess = guess_create(sch->search_handle, muid, sch->query,
		sch->media_type, search_guess_done, sch);

	return FALSE;
}

/**
 * Create a new suspended search and return a handle which identifies it.
 *
 * @param query				an UTF-8 encoded query string.
 * @param query				media type filtering to request in queries
 * @param create_time		search creation time
 * @param lifetime			search lifetime (in hours, 0 = "this session")
 * @param flags				option flags for the search.
 * @param reissue_timeout	delay in seconds before requerying.
 *
 * @return	SEARCH_NEW_SUCCESS on success
 *			SEARCH_NEW_TOO_LONG if too long,
 *			SEARCH_NEW_TOO_SHORT if too short,
 *			SEARCH_NEW_TOO_EARLY if too early (for "What's New"),
 *			SEARCH_NEW_INVALID_URN if the URN was unparsable.
 */
enum search_new_result
search_new(gnet_search_t *ptr, const char *query, unsigned mtype,
	time_t create_time, uint lifetime, uint32 reissue_timeout, uint32 flags)
{
	const char *endptr;
	search_ctrl_t *sch;
	char *qdup;
	int result;

	g_assert(ptr);
	g_assert(utf8_is_valid_string(query));

	/*
	 * Harvest entropy.
	 */

	entropy_harvest_many(query, strsize(query), VARLEN(mtype),
		VARLEN(lifetime), VARLEN(reissue_timeout), VARLEN(flags), NULL);

	/*
	 * Canonicalize the query we're sending.
	 */

	if (NULL != (endptr = is_strprefix(query, "urn:sha1:"))) {
		if (
			SHA1_BASE32_SIZE != vstrlen(endptr) ||
			!urn_get_sha1(query, NULL)
		) {
			g_warning("rejected invalid urn:sha1 search");
			qdup = NULL;
			result = SEARCH_NEW_INVALID_URN;
			goto failure;
		}
		qdup = h_strdup(query);
	} else if (
		!(flags &
			(
				SEARCH_F_LOCAL | SEARCH_F_BROWSE |
				SEARCH_F_PASSIVE | SEARCH_F_WHATS_NEW
			)
		)
	) {
		size_t byte_count;

		qdup = UNICODE_CANONIZE(query);
		g_assert(qdup != query);
		byte_count = compact_query(qdup);

		if (byte_count < MIN_SEARCH_TERM_BYTES) {
			if (GNET_PROPERTY(search_debug) > 1) {
				g_warning("rejected too short query string: \"%s\"", qdup);
			}
			result = SEARCH_NEW_TOO_SHORT;
			goto failure;
		} else if (
			byte_count > MAX_SEARCH_TERM_BYTES ||
			utf8_strlen(qdup) > MAX_SEARCH_TERM_CHARS
		) {
			if (GNET_PROPERTY(search_debug) > 1) {
				g_warning("rejected too long query string: \"%s\"", qdup);
			}
			result = SEARCH_NEW_TOO_LONG;
			goto failure;
		}
	} else if (flags & SEARCH_F_WHATS_NEW) {
		qdup = h_strdup(WHATS_NEW_QUERY);
		if (
			search_last_whats_new != 0 &&
			delta_time(tm_time(), search_last_whats_new) < WHATS_NEW_DELAY
		) {
			if (GNET_PROPERTY(search_debug) > 1) {
				g_warning("rejected too frequent \"What's New?\" querying");
			}
			result = SEARCH_NEW_TOO_EARLY;
			goto failure;
		}
	} else {
		qdup = h_strdup(query);
	}

	WALLOC0(sch);
	sch->magic = SEARCH_CTRL_MAGIC;
	sch->search_handle = search_request_handle(sch);

	sch->name = atom_str_get(query);
	sch->query = atom_str_get(qdup);
	sch->frozen = sbool_set(TRUE);
	sch->create_time = create_time;
	sch->lifetime = (flags & SEARCH_F_WHATS_NEW) ? 0 : lifetime;
	sch->media_type = mtype;

	/*
	 * The watchdog monitor sending of queries and reception of hits.
	 * When no activity occurs for SEARCH_ACTIVITY_TIMEOUT seconds, the
	 * callback is fired.
	 */

	sch->activity = wd_make("Gnutella search",
		SEARCH_ACTIVITY_TIMEOUT, search_is_idle, sch, FALSE);

	HFREE_NULL(qdup);

	sch->browse = sbool_set(flags & SEARCH_F_BROWSE);
	sch->local = sbool_set(flags & SEARCH_F_LOCAL);
	sch->passive = sbool_set(flags & SEARCH_F_PASSIVE);
	sch->whats_new = sbool_set(flags & SEARCH_F_WHATS_NEW);
	sch->active = sbool_set(0 == (flags &
		(SEARCH_F_BROWSE | SEARCH_F_LOCAL | SEARCH_F_PASSIVE)));

	/*
	 * The table recording SHA1 of files downloaded is used to stop the
	 * search as soon as all the files downloaded from it are completed.
	 * This applies only to searches we'll persist to disk.
	 */

	sch->track_sha1 = sbool_set(0 == (flags &
		(SEARCH_F_BROWSE | SEARCH_F_LOCAL |
			SEARCH_F_PASSIVE | SEARCH_F_WHATS_NEW)));

	if (sbool_get(sch->active)) {
		if (flags & SEARCH_F_WHATS_NEW) {
			/*
			 * A "What's New?" search is never re-issued and does not need to
			 * monitor new nodes -- it's broadcasted once to the current set of
			 * nodes, period.
			 */

			sch->reissue_timeout = 0;
		} else {
			sch->new_node_wait = wq_sleep(
				func_to_pointer(node_add), search_node_added, sch);

			if (reissue_timeout != 0 && reissue_timeout < SEARCH_MIN_RETRY)
				reissue_timeout = SEARCH_MIN_RETRY;
			sch->reissue_timeout = reissue_timeout;
		}

		sch->sent_nodes =
			hset_create_any(gnet_host_hash, NULL, gnet_host_equiv);
		sch->sent_node_ids = hset_create_any(nid_hash, nid_hash2, nid_equal);
	}

	sl_search_ctrl = pslist_prepend(sl_search_ctrl, sch);

	if (sbool_get(sch->passive))
		sl_passive_ctrl = pslist_prepend(sl_passive_ctrl, sch);

	*ptr = sch->search_handle;
	return SEARCH_NEW_SUCCESS;

failure:
	HFREE_NULL(qdup);
	*ptr = -1;
	return result;
}

/**
 * The GUI updates us on the amount of items displayed in the search.
 */
void
search_update_items(gnet_search_t sh, uint32 items)
{
    search_ctrl_t *sch = search_find_by_handle(sh);

	search_ctrl_check(sch);

	sch->items = items;
}

/**
 * The filtering side lets us know the amount of items we "kept", which
 * are either things we display to the user or entries we used for
 * auto-download.
 */
void
search_add_kept(gnet_search_t sh, const guid_t *muid, uint32 kept)
{
    search_ctrl_t *sch = search_find_by_handle(sh);

	search_ctrl_check(sch);

	sch->kept_results += kept;

	/*
	 * When dispatching hits to the GUI for GUESS queries, we supply the MUID
	 * of the query hit.  If we get a non-NULL MUID here, then it was
	 * previously determined that this was the MUID of a GUESS query.  However,
	 * this may not be the search that issued that query (could be a passive
	 * search for instance) so we only call guess_kept_results() when there
	 * is a pending GUESS query.  By construction, the MUID of a GUESS query
	 * can only be tied to one single search.
	 */

	if (sch->guess != NULL && muid != NULL)
		guess_kept_results(muid, kept);

	if (GNET_PROPERTY(search_debug) > 1)
		g_debug("SCH GUI reported %u new kept %sresults for \"%s\", has %u now",
			kept, muid != NULL ? "GUESS " : "",
			lazy_safe_search(sch->query), sch->kept_results);

	/*
	 * If we're a leaf node, notify our dynamic query managers (the ultranodes
	 * to which we're connected) about the amount of results we got so far.
	 */

	if (sbool_get(sch->active) && settings_is_leaf()) {
		search_update_results(sch);
	}
}

/**
 * Start a newly created start or resume stopped search.
 */
void
search_start(gnet_search_t sh)
{
    search_ctrl_t *sch = search_find_by_handle(sh);

	search_ctrl_check(sch);
    g_assert(sbool_get(sch->frozen));/* Coming from search_new(), or resuming */

	entropy_harvest_single(VARLEN(sh));

    sch->frozen = sbool_set(FALSE);

    if (sbool_get(sch->active)) {
		search_reissue(sch);
	}
	search_status_changed(sh);
}

/**
 * Stop search. Cancel reissue timer and don't return any results anymore.
 */
void
search_stop(gnet_search_t sh)
{
    search_ctrl_t *sch = search_find_by_handle(sh);

	search_ctrl_check(sch);

	entropy_harvest_single(VARLEN(sh));

	if (!sbool_get(sch->frozen)) {
		sch->frozen = sbool_set(TRUE);
		wd_sleep(sch->activity);
		guess_cancel(&sch->guess, FALSE);

		if (sbool_get(sch->active)) {
			update_one_reissue_timeout(sch);
		}
	}

	search_status_changed(sh);
}

/*
 * @returns TRUE if the search is not NULL, along with the amount of results
 * we kept sofar for the last requery, via "kept", or FALSE if the search
 * is NULL or it has been frozen (meaning new results must be ignored).
 */
static bool
search_get_kept_results(const search_ctrl_t *sch, uint32 *kept)
{
	if (sch == NULL)
		return FALSE;

	if (sbool_get(sch->frozen)) {
		if (GNET_PROPERTY(search_debug))
			g_debug("ignoring results because search is stopped");
		return FALSE;
	}

	if (GNET_PROPERTY(search_debug) > 1)
		g_debug("SCH reporting %u kept results for \"%s\"",
			sch->kept_results, sch->query);

	*kept = sch->kept_results;
	return TRUE;
}

/**
 * Get amount of results we displayed for the search identified by
 * its MUID.  We assume it is the last MUID we used for requerying if we
 * find a search that sent a query with the MUID.
 *
 * @returns TRUE if we found a search having sent this MUID, along with
 * the amount of results we kept sofar for the last requery, via "kept",
 * or FALSE if we did not find any search.
 */
bool
search_get_kept_results_by_muid(const guid_t *muid, uint32 *kept)
{
	search_ctrl_t *sch;

	sch = htable_lookup(search_by_muid, muid);

	g_assert(sch == NULL || sbool_get(sch->active)); /* No MUID if not active */

	return search_get_kept_results(sch, kept);
}

/**
 * Is search running a GUESS query?
 */
bool
search_running_guess(const guid_t *muid)
{
	search_ctrl_t *sch;

	sch = htable_lookup(search_by_muid, muid);

	g_assert(sch == NULL || sbool_get(sch->active)); /* No MUID if not active */

	return sch != NULL && sch->guess != NULL;
}

/**
 * @returns amount of hits kept by the search, identified by its handle
 */
uint32
search_get_kept_results_by_handle(gnet_search_t sh)
{
    search_ctrl_t *sch;

	/*
	 * Don't use search_find_by_handle() in case the search was closed
	 * after the node mode changed (ultrapeer -> leaf) and the client code
	 * (e.g. the dynamic query) was not notified..
	 */

	sch = search_probe_by_handle(sh);

	return NULL == sch ? 0 : sch->kept_results;
}

/**
 * Signals that a query was sent for this search.
 */
void
search_query_sent(gnet_search_t sh)
{
    search_ctrl_t *sch = search_probe_by_handle(sh);

	if (sch != NULL)
		search_mark_query_sent(sch);
}

/**
 * Received out-of-band indication of results for search identified by its
 * MUID, on remote node `n'.
 *
 * @param n					the remote node which has results for us.
 * @param muid				the MUID of the search.
 * @param hits				the amount of hits available (255 mean 255+ hits).
 * @param udp_firewalled	the remote host is UDP-firewalled and cannot
 *							receive unsolicited UDP traffic.
 * @param secure			whether we use OOBv3
 */
void
search_oob_pending_results(
	gnutella_node_t *n, const guid_t *muid, int hits,
	bool udp_firewalled, bool secure)
{
	search_ctrl_t *sch;
	struct array token_opaque;
	uint32 token, kept, threshold;
	unsigned ask;

	g_assert(NODE_IS_UDP(n));
	g_assert(hits > 0);

	/*
	 * If remote host promising hits is a known spammer or evil host, ignore.
	 */

	if (hostiles_spam_check(n->addr, n->port)) {
		if (GNET_PROPERTY(search_debug)) {
			g_debug("ignoring %d %sOOB hit%s for query #%s "
				"(%s is a caught spammer)",
				hits,
				guess_is_search_muid(muid) ? "GUESS " : "",
				plural(hits), guid_hex_str(muid), node_addr(n));
		}
		gnet_stats_inc_general(GNR_OOB_HITS_IGNORED_ON_SPAMMER_HIT);
		return;
	}

	/*
	 * If host is known to support secure OOB yet we get a non-secure OOB
	 * promise for hits, then something is wrong: because we always send
	 * the GGEP "SO" in queries, and force it when OOB-proxying, the remote
	 * host had to see the extension, unless the query was maliciously altered
	 * on the network or the IP:port is fake.
	 *		--RAM, 2012-10-14
	 */

	if (!secure) {
		gnet_host_t host;
		gnet_host_set(&host, n->addr, n->port);

		if (aging_lookup_revitalise(ora_secure, &host)) {
			if (GNET_PROPERTY(search_debug)) {
				g_debug("ignoring %d %sOOB unsecure hit%s for query #%s "
					"(%s supports secure OOB)",
					hits,
					guess_is_search_muid(muid) ? "GUESS " : "",
					plural(hits), guid_hex_str(muid), node_addr(n));
			}
			gnet_stats_inc_general(GNR_OOB_HITS_IGNORED_ON_UNSECURE_HIT);
			return;
		}
	}

	if (secure) {
		sectoken_t tok;

		/*
		 * The generated security token depends not only on the IP:port
		 * of the remote host, but also on the MUID of the query.
		 *
		 * Even though the token has a small lifetime due to the short
		 * period of the rotating keys in the generator, this makes sure
		 * the recipient of the token can only use it for this query, in
		 * case it received several queries from us.
		 */

		sectoken_generate_with_context(ora_stg, &tok,
			n->addr, n->port, muid, GUID_RAW_SIZE);
		token = peek_be32(tok.v);
		token_opaque = array_init(VARLEN(token));

		if (
			GNET_PROPERTY(search_debug) > 1 ||
			GNET_PROPERTY(secure_oob_debug)
		) {
			char buf[17];
			bin_to_hex_buf(token_opaque.data, token_opaque.size, ARYLEN(buf));
			g_debug("OOB secure token for %s and #%s is 0x%s",
				host_addr_port_to_string(n->addr, n->port),
				guid_hex_str(muid), buf);
		}
	} else {
		token = 0;
		token_opaque = zero_array;
	}

	/*
	 * Locate the search bearing this MUID and get the amount of results
	 * we got so far during this query.  If the search is unknown, drop
	 * indication.
	 */

	sch = htable_lookup(search_by_muid, muid);

	if (!search_get_kept_results(sch, &kept)) {

		/*
		 * Maybe it's an OOB-proxied search?
		 *
		 * Note that this is done after checking for known spammers or evil
		 * hosts to sanitize the replies for our leaves and save traffic.
		 */

		if (
			GNET_PROPERTY(proxy_oob_queries) &&
			oob_proxy_pending_results(n, muid, hits, udp_firewalled,
				&token_opaque)
		)
			goto record_secure;		/* OK, sent OOB reply ack to claim hits */

		if (GNET_PROPERTY(search_debug)) {
			g_warning("got OOB indication of %d hit%s for unknown query #%s "
				"at %s",
				PLURAL(hits), guid_hex_str(muid), node_infostr(n));
		}

		if (GNET_PROPERTY(log_bad_gnutella))
			gmsg_log_bad(n, "unexpected OOB hit indication");

		gnet_stats_count_dropped(n, MSG_DROP_UNEXPECTED);
		return;
	}

	if (GNET_PROPERTY(search_debug) > 1 || GNET_PROPERTY(udp_debug) > 1) {
		g_debug("has %d pending %s%sOOB hit%s for query #%s at %s",
			hits, secure ? "secure " : "",
			guess_is_search_muid(muid) ? "GUESS " : "",
			plural(hits), guid_hex_str(muid), node_infostr(n));
	}

	/*
	 * Skip throttling logic if we detect we have enough bandwidth.
	 */

	if (
		!bsched_saturated(BSCHED_BWS_GOUT_UDP) &&
		!bsched_saturated(BSCHED_BWS_GIN_UDP)
	)
		goto has_bandwidth;

	/*
	 * If we got more than 15% of our maximum amount of shown results,
	 * then we have a very popular query here.  We don't really need
	 * to get all the results: randomly ignore.
	 *
	 * Exception is made for "What's New?" searches of course since by
	 * definition we need to grab all the hits that come back.
	 */


	gnet_stats_inc_general(GNR_OOB_HITS_TIGHT_BANDWIDTH);

	threshold = search_max_results_for_ui(sch) * 0.15;

	if (
		!sbool_get(sch->whats_new) &&
		kept > threshold &&
		random_value(999) > (uint32) (501.0 * threshold / kept)
	) {
		if (GNET_PROPERTY(search_debug)) {
			g_debug("ignoring %d %s%sOOB hit%s for query #%s (already got %u) "
				"at %s",
				hits, secure ? "secure " : "",
				guess_is_search_muid(muid) ? "GUESS " : "",
				plural(hits), guid_hex_str(muid), kept, node_infostr(n));
		}
		gnet_stats_inc_general(GNR_OOB_HITS_THROTTLED);
		return;
	}

has_bandwidth:

	/*
	 * They have configured us to never reply to a query with more than
	 * `search_max_items' query hit entries.  So we will never ask for more
	 * results than that from remote hosts as well.  This can be construed
	 * as a way to educate users to create meaningful query strings that don't
	 * match everything, and as a flood protection as well in case the remote
	 * host is trying to send us lots of files.  In any case, don't request
	 * more than 254 hits, since 255 means getting eveything the remote has.
	 *
	 * Note that we're at the mercy of the other host there, which can choose
	 * to flood us with more than we asked for.
	 *
	 * FIXME: We currently have no protection against this, nor any way to
	 * track it, as we'll blindly accept incoming UDP hits without really
	 * knowing how much we asked for.  Tracking would allow us to identify
	 * hostile hosts for the remaining of the session.
	 */

	ask = MIN(hits, 254);
	ask = MIN(ask, GNET_PROPERTY(search_max_items));
	g_assert(ask < 255);

	/*
	 * Ok, ask them the hits then.
	 */


	gnet_stats_inc_general(GNR_OOB_HITS_CLAIMED);
	vmsg_send_oob_reply_ack(n, muid, ask, &token_opaque);

record_secure:
	if (secure) {
		gnet_host_t host;

		gnet_stats_inc_general(GNR_OOB_HITS_SECURELY_CLAIMED);
		gnet_host_set(&host, n->addr, n->port);
		if (!aging_lookup_revitalise(ora_secure, &host))
			aging_record(ora_secure, atom_host_get(&host));
	}
}

const char *
search_query(gnet_search_t sh)
{
    search_ctrl_t *sch = search_find_by_handle(sh);

	search_ctrl_check(sch);
    g_assert(sch->name != NULL);

    return sch->name;
}

bool
search_is_frozen(gnet_search_t sh)
{
    search_ctrl_t *sch = search_find_by_handle(sh);

	search_ctrl_check(sch);

    return sbool_get(sch->frozen);
}

bool
search_is_passive(gnet_search_t sh)
{
    search_ctrl_t *sch = search_find_by_handle(sh);

	search_ctrl_check(sch);

    return sbool_get(sch->passive);
}

bool
search_is_active(gnet_search_t sh)
{
    search_ctrl_t *sch = search_find_by_handle(sh);

	search_ctrl_check(sch);

    return sbool_get(sch->active);
}

bool
search_is_browse(gnet_search_t sh)
{
    search_ctrl_t *sch = search_find_by_handle(sh);

	search_ctrl_check(sch);

    return sbool_get(sch->browse);
}

bool
search_is_expired(gnet_search_t sh)
{
    search_ctrl_t *sch = search_find_by_handle(sh);

	search_ctrl_check(sch);

    return search_expired(sch);
}

bool
search_is_local(gnet_search_t sh)
{
    search_ctrl_t *sch = search_find_by_handle(sh);

	search_ctrl_check(sch);

    return sbool_get(sch->local);
}

bool
search_is_whats_new(gnet_search_t sh)
{
    search_ctrl_t *sch = search_find_by_handle(sh);

	search_ctrl_check(sch);

    return sbool_get(sch->whats_new);
}

/***
 *** Host Browsing.
 ***/

/**
 * Associate download to fill in the opened browse search.
 *
 * @param sh		no document.
 * @param hostname	the DNS name of the host, or NULL if none known.
 * @param addr		the IP address of the host to browse.
 * @param port		the port to contact.
 * @param guid		the GUID of the remote host.
 * @param push		whether a PUSH request is neeed to reach remote host.
 * @param proxies	vector holding known push-proxies.
 * @param flags		connection flags like SOCK_F_PUSH, SOCK_F_TLS, SOCK_F_G2
 *
 * @return	TRUE if we successfully initialized the download layer.
 */
bool
search_browse(gnet_search_t sh,
	const char *hostname, host_addr_t addr, uint16 port,
	const guid_t *guid, const gnet_host_vec_t *proxies, uint32 flags)
{
    search_ctrl_t *sch = search_find_by_handle(sh);

	search_ctrl_check(sch);
	g_assert(sbool_get(sch->browse));
	g_assert(!sbool_get(sch->frozen));
	g_assert(sch->download == NULL);

	entropy_harvest_many(VARLEN(sh), VARLEN(addr), VARLEN(port), NULL);

	/*
	 * Host browsing is done thusly: a non-persistent search was created and
	 * it is now associated with a special download that will know it will
	 * receive Gnutella query hits and that those hits should be given back
	 * to the special search for display.
	 */

	sch->download = download_browse_start(hostname, addr, port,
						guid, proxies, sh, flags);

	return sch->download != NULL;
}

/**
 * Notification from the download layer that a browse-host download is being
 * removed.  This closes the relationship between the given search and
 * the removed download.
 */
void
search_dissociate_browse(gnet_search_t search_handle, struct download *d)
{
    search_ctrl_t *sch = search_find_by_handle(search_handle);

	search_ctrl_check(sch);
	g_assert(sbool_get(sch->browse));
	g_assert(sch->download == d);

	sch->download = NULL;
	search_stop(sch->search_handle);
}

#define LOCAL_MAX_ALT	30		/* Max alt-locs we report for local searches */

/**
 * Add local file to a search result.
 *
 * This routine is used when searching for files locally (search string was
 * prefixed with "local:"), not when replying to a network search.
 */
static void
search_add_local_file(gnet_results_set_t *rs, shared_file_t *sf)
{
	gnet_record_t *rc;

	g_return_if_fail(rs);
	g_return_if_fail(sf);
	g_return_if_fail(SHARE_REBUILDING != sf);

	rc = search_record_new();
	if (sha1_hash_available(sf)) {
		gnet_host_t hvec[LOCAL_MAX_ALT];
		int hcnt;

		/*
		 * SHA1 is available, look at the known alternate locations we have.
		 */

		atom_sha1_change(&rc->sha1, shared_file_sha1(sf));
		atom_tth_change(&rc->tth, shared_file_tth(sf));
		hcnt = dmesh_fill_alternate(rc->sha1, hvec, N_ITEMS(hvec));

		/*
		 * Propagate them to the results so that they can see how many entries
		 * they have in the mesh for each shared file, up to a maximum of
		 * LOCAL_MAX_ALT entries.
		 */

		if (hcnt > 0) {
			vector_t vec = vector_create(VARLEN(hvec[0]), hcnt);
			rc->alt_locs = gnet_host_vec_from_vector(&vec);
		}
	}

	if (shared_file_is_partial(sf)) {
   		rc->flags |= SR_PARTIAL;
	} else {
		rc->flags |= SR_SHARED;
	}
	rc->file_index = shared_file_index(sf);
	rc->size = shared_file_size(sf);

	rc->filename = atom_str_get(shared_file_name_nfc(sf));
	rc->flags |= SR_ATOMIZED;

	if (shared_file_relative_path(sf)) {
		rc->path = atom_str_get(shared_file_relative_path(sf));
	}
	rc->tag = atom_str_get(shared_file_path(sf));

	rc->create_time = shared_file_creation_time(sf);
	rs->records = pslist_prepend(rs->records, rc);
	rs->num_recs++;
}

bool
search_locally(gnet_search_t sh, const char *query)
{
	gnet_results_set_t *rs;
    search_ctrl_t *sch;
	shared_file_t *sf;
	regex_t *re;
	int error;

    g_assert(query);

   	sch = search_find_by_handle(sh);
    g_assert(sch != NULL);
	g_assert(!sbool_get(sch->browse));
	g_assert(!sbool_get(sch->frozen));
	g_assert(sbool_get(sch->local));
	g_assert(sch->download == NULL);

	entropy_harvest_many(VARLEN(sh), query, strsize(query), NULL);

	if ('\0' == query[0]) {
		error = FALSE;
		re = NULL;
		sf = NULL;
	} else if (is_strprefix(query, "urn:sha1:")) {
		struct sha1 sha1;

		re = NULL;
		error = !urn_get_sha1(query, &sha1);
		if (error) {
			goto done;
		}
		sf = shared_file_by_sha1(&sha1);
		error = !sf || SHARE_REBUILDING == sf;
		shared_file_unref(&sf);
		if (error) {
			goto done;
		}
	} else {
		sf = NULL;
		WALLOC(re);
		error = regcomp(re, query, REG_EXTENDED | REG_NOSUB | REG_ICASE);
		if (error) {
			goto done;
		}
	}

	rs = search_new_r_set();

	rs->addr = listen_addr();
	if (!is_host_addr(rs->addr)) {
		rs->addr = listen_addr6();
	}
	rs->port = GNET_PROPERTY(listen_port);
	rs->last_hop = zero_host_addr;
	rs->country = ISO3166_INVALID;
	rs->guid = atom_guid_get(
		cast_to_guid_ptr_const(GNET_PROPERTY(servent_guid)));
	rs->vcode.u32 = T_GTKG;
    rs->status |= ST_LOCAL | ST_KNOWN_VENDOR;

	if (GNET_PROPERTY(is_firewalled))
		rs->status |= ST_FIREWALL;

	if (GNET_PROPERTY(is_firewalled) || !host_is_valid(rs->addr, rs->port)) {
		const gnet_host_t *host = node_oldest_push_proxy();

		if (host != NULL) {
			rs->proxies = gnet_host_vec_alloc();
			gnet_host_vec_add(rs->proxies,
				gnet_host_get_addr(host), gnet_host_get_port(host));
		}
	}

	if (sf) {
		search_add_local_file(rs, sf);
	} else {
		uint num_files, idx;

		num_files = MIN((uint) -1, shared_files_scanned());
		for (idx = 1; idx > 0 && idx <= num_files; idx++) {
			sf = shared_file(idx);
			if (!sf) {
				continue;
			} else if (SHARE_REBUILDING == sf) {
				break;
			} else if (re) {
				const char *name, *path;
				char *buf = NULL;
				size_t buf_size = 0;
				int ret;

				name = shared_file_name_nfc(sf);
				path = shared_file_relative_path(sf);
				if (path) {
					buf_size =
						w_concat_strings(&buf, path, "/", name, NULL_PTR);
					name = buf;
				}
				ret = regexec(re, name, 0, NULL, 0);
				WFREE_NULL(buf, buf_size);
				if (ret) {
					shared_file_unref(&sf);
					continue;
				}
			}

			if (
				0 != sch->media_type &&
				!shared_file_has_media_type(sf, sch->media_type)
			) {
				shared_file_unref(&sf);
				continue;
			}

			search_add_local_file(rs, sf);
			shared_file_unref(&sf);
		}
	}

	if (rs->records) {
		pslist_t *search;

		rs->status |= ST_PARSED_TRAILER;	/* Avoid <unparsed> in the GUI */
		search = pslist_prepend(NULL, uint_to_pointer(sch->search_handle));
		/* Dispatch browse results using a NULL MUID since it's not GUESS */
		search_fire_got_results(search, NULL, rs);
		pslist_free_null(&search);
	}
    search_free_r_set(rs);

done:
	if (re) {
		regfree(re);
		WFREE(re);
	}
	return !error;
}

/**
 * Handle magnet searches, launching Gnutella searches as appropriate.
 */
uint
search_handle_magnet(const char *url)
{
	struct magnet_resource *res;
	uint n_searches = 0;

	g_assert(url != NULL);

	entropy_harvest_single(url, vstrlen(url));

	res = magnet_parse(url, NULL);
	if (res) {
		pslist_t *sl;

		PSLIST_FOREACH(res->searches, sl) {
			const char *query;

			/* Note that SEARCH_F_LITERAL is used to prevent that these
			 * searches are parsed for magnets or other special items. */
			query = sl->data;
			g_assert(query);
			if (
				gcu_search_gui_new_search(query,
					SEARCH_F_ENABLED | SEARCH_F_LITERAL)
			) {
				n_searches++;
			}
		}
		if (res->sha1 && NULL == res->display_name) {
			char urn_buf[64];

			sha1_to_urn_string_buf(res->sha1, ARYLEN(urn_buf));
			if (
				gcu_search_gui_new_search(urn_buf,
					SEARCH_F_ENABLED | SEARCH_F_LITERAL)
			) {
				n_searches++;
			}
		}

		magnet_resource_free(&res);
	}
	return n_searches;
}

/***
 *** Callbacks
 ***/

static listeners_t search_request_listeners;

void
search_request_listener_add(search_request_listener_t l)
{
    LISTENER_ADD(search_request, l);
}

void
search_request_listener_remove(search_request_listener_t l)
{
    LISTENER_REMOVE(search_request, l);
}

void
search_request_listener_emit(
	query_type_t type, const char *query, const host_addr_t addr, uint16 port)
{
    LISTENER_EMIT(search_request, (type, query, addr, port));
}

/**
 * A query context.
 *
 * We don't want to include the same file several times in a reply (for
 * example, once because it matches an URN query and once because the file name
 * matches). So we keep track of what has been added in `shared_files'.
 */
struct query_context {
	hset_t *shared_files;
	pslist_t *files;			/**< List of shared_file_t that match */
	const search_request_info_t *sri;
	int found;
};

/**
 * Create new query context.
 */
static struct query_context *
share_query_context_make(const search_request_info_t *sri)
{
	struct query_context *ctx;

	WALLOC0(ctx);
	ctx->shared_files = hset_create(HASH_KEY_SELF, 0);
	ctx->sri = sri;

	return ctx;
}

/**
 * Get rid of the query context.
 */
static void
share_query_context_free(struct query_context *ctx)
{
	/*
	 * Don't free the `files' list, as we passed it to the query hit builder.
	 */

	hset_free_null(&ctx->shared_files);
	WFREE(ctx);
}

/**
 * Check if a given shared_file has been added to the QueryHit.
 *
 * @return TRUE if the shared_file is in the QueryHit already, FALSE otherwise
 */
static inline bool
shared_file_already_found(struct query_context *ctx, const shared_file_t *sf)
{
	return hset_contains(ctx->shared_files, sf);
}

/**
 * Add the shared_file to the set of files already added to the QueryHit.
 */
static inline void
shared_file_mark_found(struct query_context *ctx, const shared_file_t *sf)
{
	hset_insert(ctx->shared_files, sf);
}

/**
 * Apply search limits.
 *
 * @param sf	the already matched file or matching candidate
 * @param sri	the search request meta information
 *
 * @return TRUE if the match is to be kept / attempted.
 */
bool
search_apply_limits(const shared_file_t *sf, const search_request_info_t *sri)
{
	shared_file_check(sf);
	search_request_info_check(sri);

	/*
	 * If there is a media type filtering, ignore files not matching
	 * their request.
	 */

	if (
		0 != sri->media_types &&
		!shared_file_has_media_type(sf, sri->media_types)
	) {
		if (GNET_PROPERTY(query_debug) > 1 ||
			GNET_PROPERTY(matching_debug) > 1
		) {
			g_debug("MATCH ignoring %s \"%s\", not of type %s",
				shared_file_is_partial(sf) ? "partial" : "shared",
				shared_file_name_canonic(sf),
				search_media_mask_to_string(sri->media_types));
		}

		return FALSE;
	}

	/*
	 * If there is a size limit, apply it.
	 */

	if (sri->size_restrictions) {
		filesize_t size = shared_file_size(sf);

		if (size < sri->minsize || size > sri->maxsize) {
			if (GNET_PROPERTY(query_debug) > 1 ||
				GNET_PROPERTY(matching_debug) > 1
			) {
				g_debug("MATCH ignoring %s \"%s\": size=%s "
					"not within boundaries [%s, %s]",
					shared_file_is_partial(sf) ? "partial" : "shared",
					shared_file_name_canonic(sf),
					filesize_to_string(size),
					filesize_to_string2(sri->minsize),
					filesize_to_string3(sri->maxsize));
			}

			return FALSE;
		}
	}

	return TRUE;
}

/**
 * Invoked for each new match we get.
 *
 * @return TRUE if the match is kept.
 */
static bool
got_match(void *context, const void *data, bool limits)
{
	struct query_context *qctx = context;
	const shared_file_t *sf = data;
	const search_request_info_t *sri = qctx->sri;

	shared_file_check(sf);

	/*
	 * Don't insert duplicates (possible when matching both by SHA1 and name).
	 */

	if (!shared_file_already_found(qctx, sf)) {
		if (limits && !search_apply_limits(sf, sri))
			return FALSE;

		shared_file_mark_found(qctx, sf);
		qctx->files = pslist_prepend(qctx->files, shared_file_ref(sf));
		qctx->found++;
		return TRUE;
	} else {
		return FALSE;
	}
}

#define MIN_WORD_LENGTH 1		/**< For compaction */

/**
 * Remove unnecessary ballast from a query before processing it. Works in
 * place on the given string. Removed are all consecutive blocks of
 * whitespace and all words shorter then MIN_WORD_LENGTH.
 *
 * @param search	the search string to compact, modified in place.
 * @return			the length in bytes of the compacted search string.
 */
static size_t
compact_query_utf8(char *search)
{
	char *s;
	char *word = NULL, *p;
	size_t word_length = 0;	/* length in bytes, not characters */
	char *orig_search = NULL;

#define APPEND_WORD()								\
do {												\
	/* Append a space unless it's the first word */	\
	if (p != search) {								\
		if (*p != ' ')								\
			*p = ' ';								\
		p++;										\
	}												\
	if (p != word && word != NULL)					\
		memmove(p, word, word_length);				\
	p += word_length;								\
} while (0)

	if (GNET_PROPERTY(query_debug) > 14) {
		orig_search = hex_escape(search, FALSE);
		if (orig_search == search)
			orig_search = h_strdup(search);
	}

	word = is_ascii_blank(*search) ? NULL : search;
	p = s = search;
	while ('\0' != *s) {
		uint clen;

		clen = utf8_char_len(s);
		clen = MAX(1, clen);	/* In case of invalid UTF-8 */

		if (is_ascii_blank(*s)) {
			if (word_length >= MIN_WORD_LENGTH) {
				APPEND_WORD();
			}
			word_length = 0;

			s = skip_ascii_blanks(s);
			if ('\0' == *s) {
				word = NULL;
				break;
			}
			word = s;
		} else {
			word_length += clen;
			s += clen;
		}
	}

	if (word_length >= MIN_WORD_LENGTH) {
		APPEND_WORD();
	}

	if ('\0' != *p)
		*p = '\0'; /* terminate mangled query */

	if (GNET_PROPERTY(query_debug) > 14) {
		char *safe_search = hex_escape(search, FALSE);
		if (0 != strcmp(orig_search, safe_search)) {
			g_debug("original: [%s]", orig_search);
			g_debug("mangled:  [%s]", safe_search);
		}
		if (safe_search != search)
			HFREE_NULL(safe_search);
		HFREE_NULL(orig_search);
	}


	/* search does no longer contain unnecessary whitespace */
	return p - search;
}

/**
 * Determine whether the given string is UTF-8 encoded.
 * If query starts with a BOM mark, skip it and set `retoff' accordingly.
 *
 * @returns TRUE if the string is valid UTF-8, FALSE otherwise.
 */
bool
query_utf8_decode(const char *text, uint *retoff)
{
	const char *p;

	/*
	 * Look whether we're facing an UTF-8 query.
	 *
	 * If it starts with the sequence EF BB BF (BOM in UTF-8), then
	 * it is clearly UTF-8.  If we can't decode it, it is bad UTF-8.
	 */

	if (!(p = is_strprefix(text, "\xef\xbb\xbf")))
		p = text;

	if (retoff)
		*retoff = p - text;

	/* Disallow BOM followed by an empty string */
	return (p == text || '\0' != p[0]) && utf8_is_valid_string(p);
}

/**
 * Remove unnecessary ballast from a query string, in-place.
 *
 * @returns new query string length.
 */
size_t
compact_query(char *search)
{
	size_t mangled_search_len, orig_len = vstrlen(search);
	uint offset;			/* Query string start offset */

	/*
	 * Look whether we're facing an UTF-8 query.
	 */

	if (!query_utf8_decode(search, &offset))
		g_error("found invalid UTF-8 after a leading BOM");

	/*
	 * Compact the query, offsetting from the start as needed in case
	 * there is a leading BOM (our UTF-8 decoder does not allow BOM
	 * within the UTF-8 string, and rightly I think: that would be pure
	 * gratuitous bloat).
	 */

	mangled_search_len = compact_query_utf8(&search[offset]);

	g_assert(mangled_search_len <= (size_t) orig_len - offset);

	/*
	 * Get rid of BOM, if any.
	 */

	if (offset > 0)
		memmove(search, &search[offset], mangled_search_len);

	return mangled_search_len;
}

/**
 * Convert query flags into a string describing the positionned flags.
 *
 * @return pointer to static string.
 */
static const char *
search_flags_to_string(uint16 flags)
{
	static char buf[64];

	str_bprintf(ARYLEN(buf), "%s%s%s%s%s%s%s%s",
		(flags & QUERY_F_MARK) ? "MARKED" : "",
		(flags & QUERY_F_FIREWALLED) ? " FW" : "",
		(flags & QUERY_F_XML) ? " XML" : "",
		(flags & QUERY_F_LEAF_GUIDED) ? " GUIDED" : "",
		(flags & QUERY_F_GGEP_H) ? " GGEP_H" : "",
		(flags & QUERY_F_OOB_REPLY) ? " OOB" : "",
		(flags & QUERY_F_FW_TO_FW) ? " FW2FW" : "",
		(flags & QUERY_F_SR_UDP) ? " SR_UDP" : "");

	return buf;
}

/**
 * Convert search request info into a string describing the positionned flags.
 *
 * @return pointer to static string.
 */
static const char *
search_request_info_as_bits(const struct search_request_info *sri)
{
	static char buf[17];

	search_request_info_check(sri);

	buf[0]  = (sri->flags & QUERY_F_MARK) ?			'M' : '-',
	buf[1]  = (sri->flags & QUERY_F_FIREWALLED) ?	'F' : '-',
	buf[2]  = (sri->flags & QUERY_F_XML) ?			'X' : '-',
	buf[3]  = (sri->flags & QUERY_F_LEAF_GUIDED) ?	'G' : '-',
	buf[4]  = (sri->flags & QUERY_F_GGEP_H) ?		'H' : '-',
	buf[5]  = (sri->flags & QUERY_F_OOB_REPLY) ?	'O' : '-',
	buf[5]  = sri->secure_oob ?						'3' : buf[5];
	buf[6]  = (sri->flags & QUERY_F_FW_TO_FW) ?		'f' : '-',
	buf[7]  = (sri->flags & QUERY_F_SR_UDP) ?		'R' : '-',

	buf[8] = '/';

	buf[9]  = sri->g2_query ?			'2' : '-';
	buf[10] = sri->g2_wants_url ?		'U' : '-';
	buf[11] = sri->g2_wants_dn ?		'D' : '-';
	buf[12] = sri->g2_wants_alt ?		'A' : '-';
	buf[13] = sri->size_restrictions ?	'S' : '-';
	buf[14] = sri->extended_query	?	'x' : '-';
	buf[15] = sri->partials	?			'p' : '-';

	buf[16] = '\0';

	return buf;
}

/**
 * Remove the OOB delivery flag by patching the query message inplace.
 */
void
query_strip_oob_flag(gnutella_node_t *n, char *data)
{
	uint16 flags;

	flags = peek_be16(data) & ~QUERY_F_OOB_REPLY;
	poke_be16(data, flags);

	/* Strip "SO" since no OOB now */
	n->msg_flags |= NODE_M_STRIP_GE_SO | NODE_M_EXT_CLEANUP;

	gnet_stats_inc_general(GNR_OOB_QUERIES_STRIPPED);

	if (GNET_PROPERTY(query_debug) > 2 || GNET_PROPERTY(oob_proxy_debug) > 2)
		g_debug("QUERY #%s from %s: removed OOB delivery (flags = 0x%x : %s)",
			guid_hex_str(gnutella_header_get_muid(&n->header)),
			node_infostr(n), flags, search_flags_to_string(flags));
}

/**
 * Set the OOB delivery flag by patching the query message inplace.
 */
void
query_set_oob_flag(const gnutella_node_t *n, char *data)
{
	uint16 flags;

	/*
	 * This is for OOB-proxied queries, so we're turning the flag for
	 * semi-reliable UDP support because hits are going to come back
	 * to us, so we do not care about the original querying servent settings.
	 */

	flags = peek_be16(data) | QUERY_F_OOB_REPLY | QUERY_F_MARK | QUERY_F_SR_UDP;
	poke_be16(data, flags);

	if (GNET_PROPERTY(query_debug))
		g_debug("QUERY #%s from %s: set OOB delivery (flags = 0x%x : %s)",
			guid_hex_str(gnutella_header_get_muid(&n->header)),
			node_infostr(n), flags, search_flags_to_string(flags));
}

/**
 * Extract query flags for a search and apply some workarounds for
 * buggy clients.
 */
static uint16
search_request_get_flags(const gnutella_node_t *n)
{
	const uint16 mask = QUERY_F_MARK | QUERY_F_GGEP_H | QUERY_F_LEAF_GUIDED;
	uint16 flags;

	flags = peek_be16(n->data);
	if (flags & QUERY_F_MARK)
		return flags;
	if (0 == flags)
		return flags;
	/* RAZA has been buggy for years, incorrectly using little-endian */
	flags = peek_le16(n->data);
	if ((flags & mask) == mask)
		return flags;

	return QUERY_F_MARK;	/* Ignore speed and clear all flags */
}

/**
 * Allocates a new structure to hold search request (query) information,
 * so that we can reuse in search_request() the preprocessing work done
 * via search_request_preprocess().
 */
search_request_info_t *
search_request_info_alloc(void)
{
	search_request_info_t *sri;

	WALLOC0(sri);
	sri->magic = SEARCH_REQUEST_INFO_MAGIC;

	return sri;
}

/**
 * Free data structure and nullify its pointer.
 */
void
search_request_info_free_null(search_request_info_t **sri_ptr)
{
	search_request_info_t *sri = *sri_ptr;

	if (sri != NULL) {
		search_request_info_check(sri);
		atom_str_free_null(&sri->extended_query);
		sri->magic = 0;
		WFREE(sri);
		*sri_ptr = NULL;
	}
}

/**
 * Is the search string valid?
 *
 * If invalid, the message drop is accounted for.
 *
 * @attention
 * Sets sri->skip_file_search as a side effect.
 *
 * @param n		the node where query comes from
 * @param hops	the hops travelled by the query
 * @param sri	the analyzed search string so far
 *
 * @return TRUE if search can be processed.
 */
bool
search_is_valid(gnutella_node_t *n, uint8 hops, search_request_info_t *sri)
{
	/*
	 * When an URN search is present, there can be an empty search string.
	 *
	 * If requester is farther than half our TTL hops. save bandwidth when
	 * returning lots of hits from short queries, which are not specific enough.
	 * The idea here is to give some response, but not too many.
	 */

	sri->skip_file_search = sri->search_len <= 1 || (
		sri->search_len <= MIN_SEARCH_TERM_BYTES &&
		hops > (GNET_PROPERTY(max_ttl) / 2));

    if (0 == sri->exv_sha1cnt && sri->skip_file_search) {
        gnet_stats_count_dropped(n, MSG_DROP_QUERY_TOO_SHORT);
		return FALSE;					/* Drop this search message */
    }

	return TRUE;
}

/**
 * Can we issue an OOB query with results sent to the given address?
 *
 * If not, the message drop is accounted for.
 *
 * @param n		the node where query comes from
 * @param sri	the analyzed search string so far
 *
 * @return TRUE if search can be processed.
 */
bool
search_oob_is_allowed(gnutella_node_t *n, const search_request_info_t *sri)
{
	hostiles_flags_t hostile;
	msg_drop_reason_t reason = MSG_DROP_REASON_COUNT;

	node_check(n);
	g_assert(sri->oob);

	/*
	 * Verify against the hostile IP addresses...
	 */

	hostile = hostiles_check(sri->addr);

	if (hostiles_flags_are_bad(hostile))
		reason = MSG_DROP_HOSTILE_IP;
	else if (hostiles_flags_warrant_shunning(hostile))
		reason = MSG_DROP_SHUNNED_IP;

	if (reason != MSG_DROP_REASON_COUNT) {
		if (GNET_PROPERTY(search_debug)) {
			g_debug("SEARCH dropping OOB query from hostile %s (%s)",
				host_addr_to_string(sri->addr),
				hostiles_flags_to_string(hostile));
		}
		gnet_stats_count_dropped(n, reason);
		return FALSE;		/* Drop the message! */
	}

	if (is_my_address_and_port(sri->addr, sri->port)) {
		if (GNET_PROPERTY(search_debug))
			g_debug("SEARCH dropping OOB query from myself");
		gnet_stats_count_dropped(n, MSG_DROP_OWN_QUERY);
		return FALSE;
	}

	return TRUE;
}

/**
 * Preprocesses searches requests (from others nodes).
 *
 * This is called after route_message(), so TTL and hops do not hold the values
 * that were set by the sender, i.e. they have been adjusted to mark the
 * passage at our node.
 *
 * @param n		the node from which the query comes from (relay)
 * @param sri	search request information structure filled with parsed data
 * @param isdup	whether query is known to have been seen with a lower TTL
 *
 * @return TRUE if the query should be discarded, FALSE if everything was OK.
 */
bool
search_request_preprocess(gnutella_node_t *n,
	search_request_info_t *sri, bool isdup)
{
	static char stmp_1[4096];
	char *search;
	struct sha1 *last_sha1_digest = NULL;
	host_addr_t ipv6_addr;
	const guid_t *muid;
	bool will_oob;

	g_assert(GTA_MSG_SEARCH == gnutella_header_get_function(&n->header));
	g_assert(sri != NULL);

	if (GNET_PROPERTY(guess_server_debug) > 18 && NODE_IS_UDP(n)) {
		g_debug("GUESS got %s", gmsg_node_infostr(n));
	}

	muid = gnutella_header_get_muid(&n->header);
	sri->duplicate = booleanize(isdup);
	ZERO(&ipv6_addr);

	/*
	 * Make sure search request is NUL terminated... --RAM, 06/10/2001
	 *
	 * We can't simply check the last byte, because there can be extensions
	 * at the end of the query after the first NUL.  So we need to scan the
	 * string.  Note that we use this scanning opportunity to also compute
	 * the search string length.
	 *		--RAN, 21/12/2001
	 */

	search = n->data + 2;	/* skip flags */
	sri->search_len = clamp_strlen(search, n->size - 2);
	if (sri->search_len >= n->size - 2U) {
		g_assert(n->data[n->size - 1] != '\0');
		if (GNET_PROPERTY(query_debug) > 10)
			g_warning("%s had no NUL (%d byte%s)",
				gmsg_node_infostr(n),
				n->size - 2, n->size == 3 ? "" : "s");
		if (GNET_PROPERTY(query_debug) > 14)
			dump_hex(stderr, "Query Text", search, MIN(n->size - 2, 256));

		gnet_stats_count_dropped(n, MSG_DROP_QUERY_NO_NUL);
		goto drop;		/* Drop the message! */
	}

	/*
	 * Detect legacy "What's New?" queries early.
	 */

	sri->whats_new =
		CONST_STRLEN(WHATS_NEW_QUERY) == sri->search_len &&
		0 == strcasecmp(search, WHATS_NEW_QUERY);

	/*
	 * We can now use `search' safely as a C string: it embeds a NUL
	 * Don't emit empty search strings.  We include "\" in the empty set.
	 */

	if (sri->search_len > 0 && (sri->search_len != 1 || search[0] != '\\')) {
		search_request_listener_emit(QUERY_STRING,
			sri->whats_new ? WHATS_NEW : search, n->addr, n->port);
	}

	/*
	 * Special processing for the "query flags" field of queries.
	 *
	 * Unless bit 15 is set, process as a speed indicator.
	 * Otherwise if bit 15 is set:
	 *
	 * 1. If the firewall bit (bit 14) is set, the remote servent is firewalled.
	 *    Therefore, if we are also firewalled, don't reply.
	 *
	 * 2. If the XML bit (bit 13) is cleared and we support XML meta data, don't
	 *    include them in the result set [GTKG does not support XML meta data]
	 *
	 *		--RAM, 19/01/2003, updated 06/07/2003 (bit 14-13 instead of 8-9)
	 *
	 * 3. If the GGEP "H" bit (bit 11) is set, the issuer of the query will
	 *    understand the "H" extension in query hits.
	 *		--RAM, 16/07/2003
	 *
	 * Starting today (06/07/2003), we ignore the connection speed overall
	 * if it's not marked with the QUERY_F_MARK flag to indicate new
	 * interpretation. --RAM
	 */

	sri->flags = search_request_get_flags(n);
	if (0 == sri->flags) {
		gnet_stats_count_dropped(n, MSG_DROP_ANCIENT_QUERY);
		goto drop;		/* Drop the message! */
	}

	/*
	 * Don't waste resources issuing queries from transient leaves.
	 */

	if (NODE_IS_LEAF(n) && NODE_IS_TRANSIENT(n)) {
		gnet_stats_count_dropped(n, MSG_DROP_TRANSIENT);
		goto drop;		/* Drop the message! */
	}

	/*
	 * Look whether we're facing a UTF-8 query.
	 */

	if (!query_utf8_decode(search, NULL)) {
		gnet_stats_count_dropped(n, MSG_DROP_MALFORMED_UTF_8);
		goto drop;					/* Drop message! */
	}

	if (!is_ascii_string(search)) {
		gnet_stats_inc_general(GNR_QUERY_UTF8);
	}

	/*
	 * If there is extra data after the first NUL, fill the extension vector.
	 */

	if (sri->search_len + 3 != n->size) {
		extvec_t exv[MAX_EXTVEC];
		int i, exvcnt;
		size_t extra;
		bool drop_it = FALSE;
		bool valid_query_key = FALSE;
		bool seen_query_key = FALSE;
		bool wants_ipp = FALSE;
		bool has_unknown = FALSE;
		host_net_t ipp_net = HOST_NET_IPV4;

	   	extra = n->size - 3 - sri->search_len;	/* Amount of extra data */
		ext_prepare(exv, MAX_EXTVEC);
		exvcnt = ext_parse(search + sri->search_len + 1,
			extra, exv, MAX_EXTVEC);

		if (N_ITEMS(exv) == UNSIGNED(exvcnt)) {
			g_warning("%s has at least %d extensions!",
				gmsg_node_infostr(n), exvcnt);
			if (GNET_PROPERTY(query_debug) > 10)
				ext_dump(stderr, exv, exvcnt, "> ", "\n", TRUE);
			if (GNET_PROPERTY(query_debug) > 11)
				dump_hex(stderr, "Query", search, n->size - 2);
		}

		if (exvcnt && GNET_PROPERTY(query_debug) > 13) {
			g_debug("QUERY %s#%s [hops=%u, TTL=%u] with extensions: "
				"\"%s\" (%zu byte%s)",
				NODE_IS_UDP(n) ? "(GUESS) " : "",
				guid_hex_str(gnutella_header_get_muid(&n->header)),
				gnutella_header_get_hops(&n->header),
				gnutella_header_get_ttl(&n->header),
				sri->whats_new ? WHATS_NEW : lazy_safe_search(search),
				PLURAL(extra));
			ext_dump(stderr, exv, exvcnt, "> ", "\n",
				GNET_PROPERTY(query_debug) > 14);
		}

		/*
		 * If there is a SHA1 URN, validate it and extract the binary digest
		 * into sha1_digest[], and set `sha1_query' to the base32 value.
		 */

		for (i = 0; i < exvcnt; i++) {
			extvec_t *e = &exv[i];
			struct sha1 *sha1;

			switch (e->ext_token) {
			case EXT_T_OVERHEAD:
				if (GNET_PROPERTY(query_debug) > 16)
					dump_hex(stderr, "Query Packet (BAD: has overhead)",
						search, MIN(n->size - 2, 256));
				gnet_stats_count_dropped(n, MSG_DROP_QUERY_OVERHEAD);
				drop_it = TRUE;
				break;

			case EXT_T_URN_BAD:
				if (GNET_PROPERTY(query_debug) > 10) {
					dump_hex(stderr, "Query Packet has bad URN",
						search, MIN(n->size - 2, 256));
				}
				gnet_stats_count_dropped(n, MSG_DROP_BAD_URN);
				drop_it = TRUE;
				break;

			case EXT_T_GGEP_QK:			/* GUESS Query Key */
				seen_query_key = TRUE;
				if (NODE_IS_UDP(n)) {
					valid_query_key = search_query_key_validate(n, e);
				}
				break;

			case EXT_T_GGEP_SCP:		/* Wants GUESS pongs in "IPP" */
				wants_ipp = TRUE;		/* GUESS >= v0.2 */
				/* IPV6-Ready: check which addresses they want */
				if (ext_paylen(e) > 0) {
					const uint8 *payload = ext_payload(e);
					uint8 flags = payload[0];

					if (flags & SCP_F_NO_IPV4)
						ipp_net = HOST_NET_IPV6;
					else if (flags & SCP_F_IPV6)
						ipp_net = HOST_NET_BOTH;
				}
				break;

			case EXT_T_GGEP_WH:			/* Feature Query (What's New?) */
				/*
				 * Ignore payload, a variable-length little-endian integer.
				 * We only understand feature #1, aka. "What's New?".
				 */
				sri->whats_new = TRUE;
				break;

			case EXT_T_GGEP_SO:			/* Secure OOB */
				sri->secure_oob = TRUE;
				break;

			case EXT_T_GGEP_NP:			/* No OOB-proxying */
				/*
				 * We support OOB v3 (secure OOB) so there is no need to refuse
				 * OOB proxying.  If they sent us an "OOB Proxy Veto", we'll
				 * honour it, but "NP" comes from legacy servents.
				 *		--RAM, 2012-10-07
				 */
				n->msg_flags |= NODE_M_EXT_CLEANUP;	/* Strip "NP" if relayed */
				break;

			case EXT_T_GGEP_PR:			/* Partial: match on downloads */
				sri->partials = TRUE;
				break;

			case EXT_T_GGEP_M:			/* Media type they want */
				ggept_uint32_extract(e, &sri->media_types);
				break;

			case EXT_T_GGEP_XQ:			/* Extended Query */
				if (NULL != sri->extended_query) {
					search_log_multiple_ggep(n, e, NULL);
				} else {
					char buf[MAX_EXTENDED_QUERY_LEN + 1];

					switch (ggept_utf8_string_extract(e, ARYLEN(buf))) {
					case GGEP_OK:
						sri->extended_query = atom_str_get(buf);
						break;
					default:
						search_log_bad_ggep(n, e, NULL);
						break;
					}
				}
				if (
					ext_paylen(e) > DEFLATE_THRESHOLD &&
					!ext_ggep_is_deflated(e)
				) {
					/* Will attempt to compress if relaying this query */
					n->msg_flags |= NODE_M_EXT_CLEANUP;
				}
				break;


			case EXT_T_URN_EMPTY:		/* Ignored, we always send SHA1s */
			case EXT_T_XML:
				/* Will attempt cleanup if we end-up relaying this query */
				n->msg_flags |= NODE_M_EXT_CLEANUP;
				break;

			case EXT_T_GGEP_H:			/* Expect SHA1 value only */
			case EXT_T_URN_SHA1:
			case EXT_T_URN_BITPRINT:
			case EXT_T_GGEP_u:			/* We handle sha1 / bitprint only */
				sha1 = &sri->exv_sha1[sri->exv_sha1cnt].sha1;

				if (EXT_T_GGEP_H == e->ext_token) {
					int ret;

					ret = ggept_h_sha1_extract(e, sha1);
					if (GGEP_OK == ret) {
						/* Okay, but clean it up if it's a bitprint */
						if (ext_paylen(e) > 1 + SHA1_RAW_SIZE)
							n->msg_flags |= NODE_M_EXT_CLEANUP;
					} else if (GGEP_NOT_FOUND == ret) {
						search_log_ggep(n, e, NULL, "SHA1-less");
						continue;		/* Unsupported hash type */
					} else {
						search_log_bad_ggep(n, e, NULL);
						drop_it = TRUE;
						break;
					}
				} else if (EXT_T_GGEP_u == e->ext_token) {
					size_t plen = ext_paylen(e);
					const char *pload = ext_payload(e);
					const char *p;
					bool keep = FALSE;

					if (
						(p = is_bufcaseprefix(pload, plen, "sha1:")) ||
						(p = is_bufcaseprefix(pload, plen, "bitprint:"))
					) {
						size_t len;

						plen -= (p - pload);
						len = MIN(plen, SHA1_BASE32_SIZE);
						keep = huge_sha1_extract32(p, len, sha1, n);
					}
					if (!keep) {
						/* Don't propagate if it's not containing valid info */
						n->msg_flags |=
							NODE_M_EXT_CLEANUP | NODE_M_STRIP_GE_u;
						continue;
					}
				} else if (
					EXT_T_URN_SHA1 == e->ext_token ||
					EXT_T_URN_BITPRINT == e->ext_token
				) {
					size_t paylen = ext_paylen(e);

					/*
					 * It is no longer required to send "urn:sha1:" in
					 * queries because all Gnutella nodes in existence
					 * will return the SHA-1 of file hits, regardless.
					 * Therefore, request extension cleanup to remove this
					 * from the query before relaying it further.
					 *		--RAM, 2011-04-09
					 */

					if (paylen == 0) {
						n->msg_flags |= NODE_M_EXT_CLEANUP;
						continue;				/* A simple "urn:sha1:" */
					}

					/*
					 * Handle urn:bitprint: as if it were urn:sha1 by only
					 * parsing the leading SHA1 part.
					 */

					if (EXT_T_URN_BITPRINT == e->ext_token) {
						paylen = MIN(paylen, SHA1_BASE32_SIZE);
						/* Request cleanup to rewrite as urn:sha1 */
						n->msg_flags |= NODE_M_EXT_CLEANUP;
					}

					if (
						!huge_sha1_extract32(ext_payload(e), paylen, sha1, n)
					) {
						gnet_stats_count_dropped(n, MSG_DROP_MALFORMED_SHA1);
						drop_it = TRUE;
						break;
					}
				}

				sri->exv_sha1[sri->exv_sha1cnt].matched = FALSE;
				sri->exv_sha1cnt++;

				if (GNET_PROPERTY(query_debug) > 14) {
					g_debug("valid SHA1 #%d in query: %s",
						sri->exv_sha1cnt, sha1_base32(sha1));
				}

				last_sha1_digest = sha1;
				break;

			case EXT_T_GGEP_Z:			/* Compressed UDP supported */
				if (NODE_IS_UDP(n)) {
					/*
					 * Because UDP routes are created before the actual
					 * message payload is analysed, they cannot know that
					 * the host is deflatable initially (queries are not
					 * "requests" for the "Gnutella UDP Traffic Compression"
					 * specifications, hence are not bearing a flagged TTL).
					 *
					 * This is the reason why we need the GGEP "Z" extension
					 * in queries sent over GUESS, and this is also why we
					 * need to explicitly flag the UDP route as deflatable now.
					 */

					n->attrs |= NODE_A_CAN_INFLATE;
					route_udp_mark_deflatable(n);
				}
				break;

			case EXT_T_GGEP_6:			/* IPv6-Ready -- has IPv6 OOB return */
				if (
					0 != ext_paylen(e) &&
					GGEP_OK == ggept_gtkg_ipv6_extract(e, &ipv6_addr)
				) {
					/*
					 * When present, "6" indicates that the querying servent
					 * wants OOB.  The OOB flag could have been cleared by
					 * a relaying servent not IPv6-Ready who would think the
					 * IPv4 in the GUID is invalid.  Hence, force it locally
					 * (without re-installing it in the message itself).
					 */

					sri->flags |= QUERY_F_OOB_REPLY;
				}
				/*
				 * Always request cleanup in case we have to strip the OOB
				 * flag for some reason.
				 */
				n->msg_flags |= NODE_M_EXT_CLEANUP;
				break;

			case EXT_T_GGEP_I6:			/* IPv6-Ready -- supports IPv6 */
				/*
				 * If payload is empty, then it simply flags that IPv6 is
				 * supported in addition to IPv4.  If non-empty (1 byte set
				 * to TRUE) it means the host supports IPv6 only, so no IPv4
				 * results should be sent back.
				 */
				sri->ipv6 = TRUE;
				if (ext_paylen(e) > 0) {
					const uint8 *b = ext_payload(e);
					if (*b) {
						sri->ipv6_only = TRUE;
					}
				}
				break;

			case EXT_T_UNKNOWN_GGEP:
				search_log_ggep(n, e, NULL, "unknown");
				break;

			case EXT_T_URN_TTH:
			case EXT_T_URN_BTIH:
			case EXT_T_URN_ED2KHASH:
			case EXT_T_URN_MD5:
			case EXT_T_URN_UNKNOWN:
				/*
				 * Silently ignore unknown URNs like urn:ed2khash or urn:md5,
				 * and rewrite query to remove them if we have to forward.
				 */
				n->msg_flags |= NODE_M_EXT_CLEANUP;
				break;

			case EXT_T_UNKNOWN:
				if (GNET_PROPERTY(query_debug) > 14) {
					g_debug("%s has unknown extension", gmsg_node_infostr(n));
					ext_dump(stderr, e, 1, "....", "\n", TRUE);
				}
				has_unknown = TRUE;
				break;

			default:
				if (GNET_PROPERTY(query_debug) > 14) {
					g_debug("%s has unhandled extension %s",
						gmsg_node_infostr(n), ext_to_string(e));
				}
			}

			if (drop_it)
				break;
		}

		if (has_unknown && GNET_PROPERTY(query_debug)) {
			dump_hex(stderr, "Query Packet has unknown extension",
				search, MIN(n->size - 2, 256));
		}

		if (exvcnt)
			ext_reset(exv, MAX_EXTVEC);

		if (drop_it)
			goto drop;

		/*
		 * A "What's New?" query cannot bear any SHA1s, by nature.
		 */

		if (sri->whats_new && sri->exv_sha1cnt) {
			if (GNET_PROPERTY(query_debug) > 1) {
				g_debug("QUERY %s#%s [hops=%u, TTL=%u] \"%s\" "
					"has %d SHA1%s, dropping",
					NODE_IS_UDP(n) ? "(GUESS) " : "",
					guid_hex_str(gnutella_header_get_muid(&n->header)),
					gnutella_header_get_hops(&n->header),
					gnutella_header_get_ttl(&n->header),
					WHATS_NEW,
					PLURAL(sri->exv_sha1cnt));
			}
			gnet_stats_count_dropped(n, MSG_DROP_QUERY_OVERHEAD);
			goto drop;
		}

		/*
		 * Because "What's New?" queries are broadcasted broadly, we must
		 * restrict their scope to the close vincinity of the issuer.
		 * Enforce a maximum of 2 hops (plus all the leaves at destination).
		 * Remember: we have decremented the TTL and increased the hop count
		 * at this stage.
		 */

		if (
			sri->whats_new &&
			gnutella_header_get_hops(&n->header) >= 2 &&
			gnutella_header_get_ttl(&n->header) > 0
		) {
			if (GNET_PROPERTY(query_debug) > 1) {
				g_debug("QUERY %s#%s [hops=%u, TTL=%u] \"%s\" "
					"travelling too far, forcing TTL to 0",
					NODE_IS_UDP(n) ? "(GUESS) " : "",
					guid_hex_str(gnutella_header_get_muid(&n->header)),
					gnutella_header_get_hops(&n->header),
					gnutella_header_get_ttl(&n->header), WHATS_NEW);
			}
			/* Message will not be forwarded -- see gmsg_sendto_route() */
			gnutella_header_set_ttl(&n->header, 0);
		}

		if (sri->exv_sha1cnt)
			gnet_stats_inc_general(GNR_QUERY_SHA1);

		if (sri->whats_new) {
			gnet_stats_inc_general(GNR_QUERY_WHATS_NEW);

			/*
			 * Since "What's New?" queries are broadcasted, we make sure
			 * they carry as little bloat as possible.  The only GGEP
			 * extensions that make sense are "WH", "M" and "SO", all others
			 * can be safely dropped.
			 *		--RAM, 2011-05-18
			 */

			n->msg_flags |= NODE_M_EXT_CLEANUP | NODE_M_WHATS_NEW;
		}

		/*
		 * If query comes from UDP, then it's a GUESS query.
		 */

		if (NODE_IS_UDP(n)) {
			if (!seen_query_key) {
				gnet_stats_count_dropped(n, MSG_DROP_GUESS_MISSING_TOKEN);
				goto drop;
			} else if (!valid_query_key) {
				gnet_stats_count_dropped(n, MSG_DROP_GUESS_INVALID_TOKEN);
				/*
				 * Send new query key and forget we saw this message to be
				 * able to handle it again when it comes back with the
				 * proper query key this time.
				 */
				pcache_guess_acknowledge(n, FALSE, wants_ipp, ipp_net);
				message_forget(muid, GTA_MSG_SEARCH, n);
				goto drop;
			} else {
				if (wants_ipp) {
					/* This is a GUESS 0.2 query, at least */
					gnet_stats_inc_general(GNR_QUERY_GUESS_02);
				} else {
					/* This is a GUESS query from a legacy servent */
					gnet_stats_inc_general(GNR_QUERY_GUESS);
				}
				/* Send back a pong */
				pcache_guess_acknowledge(n, TRUE, wants_ipp, ipp_net);
			}

			/*
			 * GUESS queries should be sent with TTL=1 since they must
			 * not be propagated to other ultrapeeers, only local leaves.
			 */

			if (0 != gnutella_header_get_ttl(&n->header)) {
				if (GNET_PROPERTY(guess_server_debug)) {
					g_warning("GUESS node %s sent query #%s with TTL=%u, "
						"dropping",
						node_infostr(n),
						guid_hex_str(gnutella_header_get_muid(&n->header)),
						gnutella_header_get_ttl(&n->header) + 1);
				}
				/* Message will not be forwarded -- see gmsg_sendto_route() */
				gnutella_header_set_ttl(&n->header, 0);
			}

			/*
			 * Enforce sending with hops=0 since a GUESS query is not relayed.
			 */

			if (1 != gnutella_header_get_hops(&n->header)) {
				if (GNET_PROPERTY(guess_server_debug)) {
					g_warning("GUESS node %s sent query #%s with hops=%u, "
						"adjusting to 1 before forwarding",
						node_infostr(n),
						guid_hex_str(gnutella_header_get_muid(&n->header)),
						gnutella_header_get_hops(&n->header) - 1);
				}
				gnutella_header_set_hops(&n->header, 1);
			}

			/*
			 * Will strip "QK" and "SCP" extensions before forwarding to leaves.
			 */

			n->msg_flags |= NODE_M_EXT_CLEANUP | NODE_M_STRIP_GUESS;
		} else {
			/* Query relayed via TCP */
			if G_UNLIKELY(seen_query_key && GNET_PROPERTY(guess_server_debug)) {
				uint8 hops = gnutella_header_get_hops(&n->header) - 1;
				g_warning(
					"GUESS node %s %s TCP query #%s with GGEP QK (hops=%u)",
					node_infostr(n),
					0 == hops ? "sent" : "relayed",
					guid_hex_str(gnutella_header_get_muid(&n->header)), hops);
			}
		}
	}

    /*
     * Push the query string to interested ones (GUI tracing).
     */

    if (
		(0 == sri->search_len || (1 == sri->search_len && '\\' == search[0]))
		&& sri->exv_sha1cnt
    ) {
		int i;
		for (i = 0; i < sri->exv_sha1cnt; i++) {
			search_request_listener_emit(QUERY_SHA1,
				sha1_base32(&sri->exv_sha1[i].sha1), n->addr, n->port);
		}
	}

	/*
	 * When an URN search is present, there can be an empty search string.
	 */

	if (!search_is_valid(n, gnutella_header_get_hops(&n->header), sri))
		goto drop;			/* Drop this search message */

	/*
	 * When we are not a leaf node, we do two sanity checks here:
	 *
	 * 1. We keep track of all the queries sent by the node (hops = 1)
	 *    and the time by which we saw them.  If they are sent too often,
	 *    just drop the duplicates.  Since an Ultranode will send queries
	 *    from its leaves with an adjusted hop, we only do that check
	 *    for leaf nodes.
	 *
	 * 2. We keep track of all queries relayed by the node (hops >= 1)
	 *    by hops and by search text for a limited period of time.
	 *    The purpose is to sanitize the traffic if the node did not do
	 *    point #1 above for its own neighbours.  Naturally, we expire
	 *    this data more quickly.
	 *
	 * When there is a SHA1 in the query, it is the SHA1 itself that is
	 * being remembered.
	 *
	 *		--RAM, 09/12/2003
	 */

	if (sri->whats_new)
		goto skip_throttling;		/* What's New? queries are exempted */

	if (isdup)
		goto skip_throttling;		/* We already know message is a dup */

	if (gnutella_header_get_hops(&n->header) == 1 && n->qseen != NULL) {
		time_t now = tm_time();
		time_t seen = 0;
		bool found;
		const void *orig_key;
		void *orig_val;
		const void *atom;
		char *query = search;
		time_delta_t threshold = GNET_PROPERTY(node_requery_threshold);

		g_assert(NODE_IS_LEAF(n));

		if (last_sha1_digest) {
			sha1_to_urn_string_buf(last_sha1_digest, ARYLEN(stmp_1));
			query = stmp_1;
		}

		found = htable_lookup_extended(n->qseen, query, &orig_key, &orig_val);
		if (found) {
			seen = (time_t) pointer_to_int(orig_val);
			atom = orig_key;
		} else {
			atom = NULL;
		}

		if (delta_time(now, (time_t) 0) - seen < threshold) {
			if (GNET_PROPERTY(query_debug) > 10) g_warning(
				"node %s (%s) re-queried \"%s\" after %u secs",
				node_addr(n), node_vendor(n), query,
				(unsigned) delta_time(now, seen));
			gnet_stats_count_dropped(n, MSG_DROP_THROTTLE);
			goto drop;		/* Drop the message! */
		}

		if (!found)
			atom = atom_str_get(query);

		htable_insert(n->qseen, atom,
			uint_to_pointer((unsigned) delta_time(now, (time_t) 0)));
	}

	/*
	 * For point #2, there are two sets to consider: `qrelayed_old' and
	 * `qrelayed'.  Presence in any of the sets is sufficient, but we
	 * only insert in the "new" set `qrelayed'.
	 */

	if (n->qrelayed != NULL) {					/* Check #2 */
		bool found = FALSE;

		g_assert(!NODE_IS_LEAF(n));

		/*
		 * Consider both hops and TTL for dynamic querying, whereby the
		 * same query can be repeated with an increased TTL.
		 */

		if (last_sha1_digest == NULL)
			str_bprintf(ARYLEN(stmp_1), "%u/%u%s",
				gnutella_header_get_hops(&n->header),
				gnutella_header_get_ttl(&n->header), search);
		else
			str_bprintf(ARYLEN(stmp_1), "%u/%uurn:sha1:%s",
				gnutella_header_get_hops(&n->header),
				gnutella_header_get_ttl(&n->header),
				sha1_base32(last_sha1_digest));

		if (n->qrelayed_old != NULL)
			found = hset_contains(n->qrelayed_old, stmp_1);

		if (!found)
			found = hset_contains(n->qrelayed, stmp_1);

		if (found) {
			if (GNET_PROPERTY(query_debug) > 10) {
				g_warning("QUERY dropping \"%s%s\" (hops=%u, TTL=%u) "
					"already seen recently from %s",
					last_sha1_digest == NULL ? "" : "urn:sha1:",
					last_sha1_digest == NULL ? lazy_safe_search(search) :
						sha1_base32(last_sha1_digest),
					gnutella_header_get_hops(&n->header),
					gnutella_header_get_ttl(&n->header),
					node_infostr(n));
			}
			gnet_stats_count_dropped(n, MSG_DROP_THROTTLE);
			goto drop;		/* Drop the message! */
		}

		hset_insert(n->qrelayed, atom_str_get(stmp_1));
	}

skip_throttling:

	sri->oob = booleanize(sri->flags & QUERY_F_OOB_REPLY);
	sri->sr_udp = booleanize(sri->flags & QUERY_F_SR_UDP);
	sri->may_oob_proxy = booleanize(0 == (n->attrs2 & NODE_A2_NO_OOB_PROXY));

	if (sri->sr_udp && NODE_IS_UDP(n)) {
		/*
		 * Because UDP routes are created before the actual message payload
		 * is analysed, they cannot know that the host is supporting
		 * Semi-Reliable UDB initially (queries are not "requests" for
		 * the "Gnutella UDP Traffic Compression" specifications, hence are
		 * not bearing a flagged TTL).
		 */

		n->attrs2 |= NODE_A2_HAS_SR_UDP;
		route_udp_mark_semi_reliable(n);
	}

	/*
	 * IPv6-Ready: Compute the proper IPv6 reply address if we saw GGEP "6".
	 */

	if (sri->oob) {
		host_addr_t addr;
		uint16 port;

		guid_oob_get_addr_port(gnutella_header_get_muid(&n->header),
			&addr, &port);

		if (sri->ipv6_only && host_addr_is_ipv6(ipv6_addr)) {
			sri->addr = ipv6_addr;
		} else {
			sri->addr = addr;
		}
		sri->port = port;
	}

	/*
	 * If query comes from GTKG 0.91 or later, it understands GGEP "H".
	 * Otherwise, it's an old servent or one unwilling to support this new
	 * extension, so it will get its SHA1 URNs in ASCII form.
	 *		--RAM, 17/11/2002
	 */

	{
		uint8 major, minor;
		bool release;

		if (
			guid_query_muid_is_gtkg(gnutella_header_get_muid(&n->header),
				sri->oob, &major, &minor, &release)
		) {
			bool requery;

			gnet_stats_inc_general(GNR_GTKG_TOTAL_QUERIES);
			requery = guid_is_requery(gnutella_header_get_muid(&n->header));
			if (requery)
				gnet_stats_inc_general(GNR_GTKG_REQUERIES);

			if (GNET_PROPERTY(query_debug) > 3) {
				char origin[60];
				if (sri->oob) {
					str_bprintf(ARYLEN(origin), " from %s",
						host_addr_port_to_string(sri->addr, sri->port));
				}
				g_debug("GTKG %s%squery from %d.%d%s #%s%s",
					sri->oob ? "OOB " : "", requery ? "re-" : "",
					major, minor, release ? "" : "u",
					guid_hex_str(gnutella_header_get_muid(&n->header)),
					sri->oob ? origin : "");
			}
		}
	}

	if (0 != (sri->flags & QUERY_F_GGEP_H))
		gnet_stats_inc_general(GNR_QUERIES_WITH_GGEP_H);

	if (0 != (sri->flags & QUERY_F_SR_UDP))
		gnet_stats_inc_general(GNR_QUERIES_WITH_SR_UDP);

	/*
	 * If OOB reply is wanted, validate a few things.
	 *
	 * We may either drop the query, or reset the OOB flag if it's
	 * obviously misconfigured.  Then we can re-enable the OOB flag
	 * if we're allowed to perform OOB-proxying for leaf queries.
	 */

	if (sri->oob) {
		/*
		 * Verify against the hostile IP addresses...
		 */

		if (!search_oob_is_allowed(n, sri))
			goto drop;

		/*
		 * If it's a neighbouring leaf query, make sure the IP for results
		 * matches what we know about the listening IP for the node.
		 * The UDP port can be different from the TCP port, so we can't
		 * check that.
		 *
		 * IPv6-Ready: we can be connected to a leaf node via IPv6 because
		 * we only support IPv6, but the leaf has both IPv4 and IPv6 and is
		 * advertising IPv4...  Hence we must make sure the address is on
		 * the same network before testing for equality.
		 */

		if (
			(NODE_IS_LEAF(n) || NODE_IS_UDP(n)) &&
			is_host_addr(n->gnet_addr) &&
			host_addr_net(n->gnet_addr) == host_addr_net(sri->addr) &&
			!host_addr_equiv(sri->addr, n->gnet_addr)
		) {
			if (NODE_IS_UDP(n)) {
				query_strip_oob_flag(n, n->data);
				sri->oob = FALSE;
				if (GNET_PROPERTY(guess_server_debug)) {
					g_debug("QUERY (GUESS) #%s from %s: removed OOB flag "
						"(mismatching return address %s versus UDP %s)",
						guid_hex_str(gnutella_header_get_muid(&n->header)),
						node_infostr(n), host_addr_to_string(sri->addr),
						host_addr_to_string2(n->addr));
				}
			} else {
				gnet_stats_count_dropped(n, MSG_DROP_BAD_RETURN_ADDRESS);

				if (
					GNET_PROPERTY(query_debug) ||
					GNET_PROPERTY(oob_proxy_debug) > 1
				) {
					g_debug("QUERY dropped from %s: invalid OOB flag "
						"(return address mismatch: %s, node: %s)",
						node_infostr(n),
						host_addr_port_to_string(sri->addr, sri->port),
						node_gnet_addr(n));
				}
				goto drop;
			}
		}

		/*
		 * If the query contains an invalid IP:port, clear the OOB flag
		 * If it comes from a leaf node, we may then OOB-proxy it.
		 */

		if (!host_is_valid(sri->addr, sri->port)) {
			query_strip_oob_flag(n, n->data);
			sri->oob = FALSE;

			if (
				GNET_PROPERTY(query_debug) ||
				GNET_PROPERTY(oob_proxy_debug) > 1 ||
				(NODE_IS_UDP(n) && GNET_PROPERTY(guess_server_debug))
			) {
				g_debug("QUERY %s#%s from %s: removed OOB flag "
					"(invalid return address: %s)",
					NODE_IS_UDP(n) ? "(GUESS) " : "",
					guid_hex_str(gnutella_header_get_muid(&n->header)),
					node_infostr(n),
					host_addr_port_to_string(sri->addr, sri->port));
			}
		}
	} else if (1 == gnutella_header_get_hops(&n->header)) {
		/*
		 * Query comes from one of our neighbours.
		 *
		 * We can be connected to an hostile address if we reloaded a newer
		 * hostiles file but were already connected to that node, for instance.
		 */

		if (hostiles_is_bad(n->addr)) {
			gnet_stats_count_dropped(n, MSG_DROP_HOSTILE_IP);
			goto drop;		/* Drop the message! */
		}
	}

	/*
	 * If the query comes from a node farther than our TTL (i.e. the TTL we'll
	 * use to send our reply), don't bother processing it: the reply won't
	 * be able to reach the issuing node.
	 *
	 * However, note that for replies, we use our maximum configured TTL for
	 * relayed messages, so we compare to that, and not to my_ttl, which is
	 * the TTL used for "standard" packets.
	 *
	 *                              --RAM, 12/09/2001
	 *
	 * Naturally, we don't do this check for OOB queries, since the reply
	 * won't be relayed but delivered directly via UDP.
	 *
	 *                              --RAM, 2004-11-27
	 */

	will_oob = sri->oob &&
			GNET_PROPERTY(process_oob_queries) &&
			GNET_PROPERTY(recv_solicited_udp) &&
			udp_active() &&
			gnutella_header_get_hops(&n->header) > 1;

	if (
		!will_oob &&
		gnutella_header_get_hops(&n->header) > GNET_PROPERTY(max_ttl) &&
		!settings_is_leaf()
	) {
		gnet_stats_count_dropped(n, MSG_DROP_MAX_TTL_EXCEEDED);
		goto drop;  /* Drop this long-lived search */
	}

	/*
	 * Remember the query string and the media types they are looking
	 * for when running as an Ultrapeer, provided it's not an URN search.
	 */

	if (settings_is_ultra() && 0 == sri->exv_sha1cnt) {
		record_query_string(gnutella_header_get_muid(&n->header),
			search, sri->media_types);
	}

	return FALSE;

drop:
	return TRUE;
}

/**
 * Searches requests (from others nodes)
 * Basic matching. The search request is made lowercase and
 * is matched to the filenames in the library.
 *
 * If `qhv' is not NULL, it is filled with hashes of URN or query words,
 * so that we may later properly route the query among the leaf nodes.
 *
 * This routine must be called after search_request_preprocess() to actually
 * perform the querying based on the information gathered into ``sri''.
 *
 * It can therefore be used to process traditional Gnutella queries and G2
 * queries which have been decompiled and for which ``sri'' was populated.
 * A fake Gnutella header is filled, with the query MUID, fake hops and TTL
 * and a special GTA_MSG_G2_SEARCH function which indicates the G2 query,
 * plus the fact that NODE_TALKS_G2(n) will be TRUE.
 *
 * @param n			the node from which the query comes from (relay)
 * @param sri		the information gathered during the pre-processing stage
 * @param qhv		query hash vector (can be NULL) to fill for later routing
 */
void
search_request(gnutella_node_t *n,
	const search_request_info_t *sri, query_hashvec_t *qhv)
{
	const char *search;
	const guid_t *muid;
	bool qhv_filled = FALSE;
	bool oob;
	char *safe_search = NULL;
	uint8 function = gnutella_header_get_function(&n->header);

	g_assert(!NODE_TALKS_G2(n) || GTA_MSG_G2_SEARCH == function);
	g_assert(NODE_TALKS_G2(n) || GTA_MSG_SEARCH == function);
	g_assert(sri != NULL);

	muid = gnutella_header_get_muid(&n->header);
	oob = sri->oob;

	/*
	 * NOTE: search_request_preprocess() has already handled this query,
	 * filling ``sri'' with the gathered information.
	 */

	search = sri->g2_query ? "" : n->data + 2;	/* skip flags */

	if (sri->extended_query != NULL) {
		char *safe_ext = hex_escape(sri->extended_query, FALSE);

		if (GNET_PROPERTY(query_debug) > 14) {
			g_debug("QUERY %s#%s extended: original=\"%s\", extended=\"%s\"",
				NODE_TALKS_G2(n) ? "(G2) " :
					NODE_IS_UDP(n) ? "(GUESS) " : "",
				guid_hex_str(gnutella_header_get_muid(&n->header)),
				lazy_safe_search(search), safe_ext);
		}
		search = sri->extended_query;
		safe_search = safe_ext;
	} else {
		safe_search = hex_escape(search, FALSE);
		if (GNET_PROPERTY(query_debug) > 14) {
			g_debug("QUERY %s#%s \"%s\"",
				NODE_TALKS_G2(n) ? "(G2) " :
					NODE_IS_UDP(n) ? "(GUESS) " : "",
				guid_hex_str(gnutella_header_get_muid(&n->header)),
				sri->whats_new ? WHATS_NEW : safe_search);
		}
	}

	/*
	 * If this is a duplicate query (with higher TTL), we just need to relay
	 * it, and for that we need to compute the query hash vector.
	 */

	if (sri->duplicate)
		goto finish;

	/* We're going to attempt to process the query (i.e. search our library) */

	/*
	 * Check limits.
	 */

	if (oob) {
		if (ctl_limit(sri->addr, CTL_D_QUERY)) {
			if (GNET_PROPERTY(ctl_debug) > 3) {
				g_debug("CTL ignoring OOB query to be answered at %s [%s]",
					host_addr_to_string(sri->addr), gip_country_cc(sri->addr));
			}
			goto finish;
		}
	} else if (1 == gnutella_header_get_hops(&n->header)) {
		/*
		 * Query comes from one of our neighbours.
		 */

		if (ctl_limit(n->addr, CTL_D_QUERY)) {
			if (GNET_PROPERTY(ctl_debug) > 3) {
				g_debug("CTL ignoring neighbour query from %s [%s]",
					node_infostr(n), gip_country_cc(n->addr));
			}
			goto finish;
		}
	}

	/*
	 * Before handling an OOB query, make sure the remote host is actually
	 * claiming its hits on a regular basis.
	 *
	 * FIXME:
	 * Note that banning is at the IP address level, not at the IP:port level
	 * so if several servents run under the same IP, all will be penalized if
	 * one behaves badly.  For now this is acceptable -- RAM, 2012-06-10
	 *
	 * When we ignore a query, we still relay it to neighbours so that we do
	 * not penalize the network unduly should our ignoring logic be too
	 * aggresive.
	 */

	if (oob && ban_is_banned(BAN_CAT_OOB_CLAIM, sri->addr)) {
		if (GNET_PROPERTY(query_debug) > 2) {
			g_debug("QUERY OOB %s#%s \"%s\" ignored: host %s not claiming hits",
				NODE_IS_UDP(n) ? "(GUESS) " : "",
				guid_hex_str(gnutella_header_get_muid(&n->header)),
				sri->whats_new ? WHATS_NEW : safe_search,
				host_addr_to_string(sri->addr));
		}
		gnet_stats_inc_general(GNR_OOB_QUERIES_IGNORED);
		goto finish;
	}

	/*
	 * Check IP address requirements.
	 */

	if (sri->ipv6_only && !settings_running_ipv6()) {
		if (GNET_PROPERTY(query_debug) > 9) {
			g_debug("QUERY %s#%s \"%s\" ignored: wants only IPv6",
				NODE_IS_UDP(n) ? "(GUESS) " : "",
				guid_hex_str(gnutella_header_get_muid(&n->header)),
				sri->whats_new ? WHATS_NEW : safe_search);
		}
		goto finish;
	}

	/*
	 * Given we don't support FW-to-FW transfers, there's no need to reply
	 * if the request coems from a firewalled host and we are also firewalled.
	 */

	if (
		0 != (sri->flags & QUERY_F_FIREWALLED) &&
		GNET_PROPERTY(is_firewalled)
	) {
		goto finish;			/* Both servents are firewalled */
	}

	/*
	 * LimeWire hosts blindly send push-proxy requests when the startup
	 * but never learned to properly send push-proxy cancel notifications.
	 * Hence, most LimeWire leaves remain push-proxied.  Since LimeWire does
	 * not want to fix that bug but instead wants everyone to determine
	 * whether a node is proxied or not by looking at the "firewalled" flag
	 * in queries, so be it.  It's stupid though: a node may never issue any
	 * request but simply reply to remote queries.  Nevermind.
	 *		-- RAM, 2007-11-05
	 */

	if (!(sri->flags & QUERY_F_FIREWALLED) && node_guid(n) && NODE_IS_LEAF(n))
		node_proxying_remove(n);	/* This leaf node is no longer firewalled */

	if (sri->whats_new || !sri->skip_file_search || sri->exv_sha1cnt > 0) {
		struct query_context *qctx;
		uint32 max_replies;

		/*
		 * Perform search...
		 */

		if (!sri->whats_new) {
			/*
			 * Since What's New? queries are always broadcasted, they cannot
			 * be counted in QRP filterting statistics.
			 */

			if (NODE_TALKS_G2(n)) {
				if (node_hub_received_qrp(n)) {
					node_inc_qrp_query(n);
				}
				gnet_stats_inc_general(GNR_LOCAL_G2_SEARCHES);
			} else {
				if (settings_is_leaf() && node_ultra_received_qrp(n)) {
					node_inc_qrp_query(n);
				}
				gnet_stats_inc_general(GNR_LOCAL_SEARCHES);
			}
		}

		qctx = share_query_context_make(sri);
		max_replies = GNET_PROPERTY(search_max_items) == (uint32) -1
				? 255
				: GNET_PROPERTY(search_max_items);

		/*
		 * Search each SHA1.
		 */

		if (sri->exv_sha1cnt) {
			int i;

			for (i = 0; i < sri->exv_sha1cnt && max_replies > 0; i++) {
				shared_file_t *sf;

				sf = shared_file_by_sha1(&sri->exv_sha1[i].sha1);
				if (
					sf &&
					sf != SHARE_REBUILDING &&
					!shared_file_is_partial(sf)
				) {
					shared_file_check(sf);
					if (got_match(qctx, sf, TRUE))
						max_replies--;
				}
				shared_file_unref(&sf);
			}
		}

		if (sri->whats_new) {
			shared_file_t *sfv[3];	/* Limit results to 3 newest files */
			size_t cnt, i;

			cnt = GNET_PROPERTY(query_answer_whats_new)
				? share_fill_newest(sfv, N_ITEMS(sfv),
					sri->media_types,
					sri->size_restrictions, sri->minsize, sri->maxsize)
				: 0;
			for (i = 0; i < cnt; i++) {
				got_match(qctx, sfv[i], TRUE);
				shared_file_unref(&sfv[i]);
			}
			gnet_stats_count_general(GNR_LOCAL_WHATS_NEW_HITS, cnt);

		} else if (!sri->skip_file_search) {
			uint32 flags = 0;

			flags |= sri->partials ? SHARE_FM_PARTIALS : 0;
			flags |= NODE_TALKS_G2(n) ? SHARE_FM_G2 : 0;

			shared_files_match(search, sri,
				got_match, qctx, max_replies, flags, qhv);

			qhv_filled = TRUE;		/* A side effect of st_search() */
		}

		if (GNET_PROPERTY(query_trace)) {
			g_info("Q #%s %s [%c %u/%u] hit=%03d \"%s\" (%s)%s%s%s%s%s",
				guid_hex_str(gnutella_header_get_muid(&n->header)),
				search_request_info_as_bits(sri),
				NODE_IS_UDP(n) ? 'G' : NODE_IS_LEAF(n) ? 'L' : 'U',
				gnutella_header_get_hops(&n->header),
				gnutella_header_get_ttl(&n->header),
				qctx->found,
				sri->whats_new ? WHATS_NEW : lazy_safe_search(search),
				search_media_mask_to_string(sri->media_types),
				sri->skip_file_search ? " (skipped local)" : "",
				sri->exv_sha1cnt > 0 ? " (SHA1)" : "",
				sri->oob ? " <" : "",
				sri->oob ? host_addr_port_to_string(sri->addr, sri->port) : "",
				sri->oob ? ">" : "");
		}

		if (qctx->found > 0) {
			if (
				(settings_is_leaf() && node_ultra_received_qrp(n)) ||
				(NODE_TALKS_G2(n) && node_hub_received_qrp(n))
			)
				node_inc_qrp_match(n);

			if (GNET_PROPERTY(share_debug) > 3) {
				g_debug("share HIT %u file%s '%s'%s for #%s%s",
					PLURAL(qctx->found),
					sri->whats_new ? WHATS_NEW : safe_search,
					sri->skip_file_search ? " (skipped)" : "",
					guid_hex_str(gnutella_header_get_muid(&n->header)),
					NODE_TALKS_G2(n) ? " (G2)" : "");
				if (sri->exv_sha1cnt) {
					int i;
					for (i = 0; i < sri->exv_sha1cnt; i++)
						g_debug("\t%c(%32s)",
							sri->exv_sha1[i].matched ? '+' : '-',
							sha1_base32(&sri->exv_sha1[i].sha1));
				}
				g_debug("\tflags=0x%04x max-hits=%u (%s) "
					"ttl=%u hops=%u",
					(uint) sri->flags,
					(uint) (sri->flags & QUERY_F_MAX_HITS),
					search_flags_to_string(sri->flags),
					gnutella_header_get_ttl(&n->header),
					gnutella_header_get_hops(&n->header));
			}
		}

		if (GNET_PROPERTY(query_debug) > 14) {
			g_debug("QUERY #%s \"%s\" [hops=%u, TTL=%u] has %u hit%s%s%s (%s)",
					guid_hex_str(gnutella_header_get_muid(&n->header)),
					sri->whats_new ? WHATS_NEW : lazy_safe_search(search),
					gnutella_header_get_hops(&n->header),
					gnutella_header_get_ttl(&n->header),
					PLURAL(qctx->found),
					sri->skip_file_search ? " (skipped local)" : "",
					sri->exv_sha1cnt > 0 ? " (SHA1)" : "",
					search_media_mask_to_string(sri->media_types));
		}

		/*
		 * If we got a query marked for OOB results delivery, send them
		 * a reply out-of-band but only if the query's hops is > 1.  Otherwise,
		 * we have a direct link to the queryier.
		 */

		if (qctx->found) {
			bool should_oob;
			unsigned flags = 0;

			flags |= (sri->flags & QUERY_F_GGEP_H) ? QHIT_F_GGEP_H : 0;
			flags |= sri->ipv6 ? QHIT_F_IPV6 : 0;
			flags |= sri->ipv6_only ? QHIT_F_IPV6_ONLY : 0;

			should_oob = oob && !sri->g2_query &&
							GNET_PROPERTY(process_oob_queries) &&
							GNET_PROPERTY(recv_solicited_udp) &&
							udp_active() &&
							gnutella_header_get_hops(&n->header) > 1 &&
							settings_running_same_net(sri->addr);

			if (should_oob) {
				oob_got_results(n, qctx->files, qctx->found,
					sri->addr, sri->port, sri->secure_oob, sri->sr_udp, flags);
			} else if (sri->g2_query) {
				gnutella_node_t *g = n;
				if (sri->oob)
					g = node_udp_g2_get_addr_port(sri->addr, sri->port);
				flags |= sri->g2_wants_url ? QHIT_F_G2_URL : 0;
				flags |= sri->g2_wants_dn  ? QHIT_F_G2_DN  : 0;
				flags |= sri->g2_wants_alt ? QHIT_F_G2_ALT : 0;
				g2_build_send_qh2(n, g, qctx->files, qctx->found, muid, flags);
			} else {
				qhit_send_results(n, qctx->files, qctx->found, muid, flags);
			}
		}

		share_query_context_free(qctx);
	}

finish:
	/*
	 * If for some reason we did not call shared_files_match(), then
	 * we've not had an opportunity to fill the query hash vector.
	 * Regardless of whether we attempt a match locally, we need to build
	 * this vector to properly route the query (if we're an ultra node, but
	 * if we're a leaf, qhv will be NULL).
	 *		--RAM, 2009-11-11
	 */

	if (!qhv_filled && qhv != NULL) {
		if (sri->whats_new) {
			qhvec_set_whats_new(qhv, TRUE);
		} else {
			st_fill_qhv(search, qhv);
		}
	}

	if (safe_search != search)
		HFREE_NULL(safe_search);
}

/**
 * XML tree traversal callback.
 */
static void
search_xml_node_is_empty(void *node, void *data)
{
	xnode_t *xn = node;
	bool *empty = data;

	if (!*empty)
		return;

	if (xnode_is_comment(xn))
		return;

	if (xnode_is_text(xn) && vstrlen(xnode_text(xn)) > 0) {
		*empty = FALSE;
	} else if (xnode_prop_count(xn) > 0) {
		*empty = FALSE;
	}
}

/**
 * Is the XML tree "empty": no content in tags, no attributes.
 */
static bool
search_xml_tree_empty(xnode_t *root)
{
	bool empty = TRUE;

	xnode_tree_foreach(root, search_xml_node_is_empty, &empty);
	return empty;
}

/**
 * Log GGEP write failure.
 */
static void
search_log_ggep_write_failure(const char *id, uint32 flags,
	const gnutella_node_t *n, const char *caller)
{
	if (GNET_PROPERTY(query_debug)) {
		g_warning("%s(): QUERY #%s could not write %s"
			"GGEP \"%s\": %s",
			caller, guid_hex_str(gnutella_header_get_muid(&n->header)),
			(flags & GGEP_W_DEFLATE) ? "deflated " : "", id, ggep_errstr());
	}
}

/**
 * Write GGEP extension in GGEP stream for message held in the node.
 */
static void
search_ggep_write(ggep_stream_t *gs, const extvec_t *e, const char *id,
	const void *payload, size_t plen,
	const gnutella_node_t *n, const char *caller)
{
	uint32 flags;
	bool ok;
	const char *extid;

	g_assert((NULL == e) ^ (NULL == id));

	if (e != NULL) {
		flags = (plen > DEFLATE_THRESHOLD || ext_ggep_is_deflated(e)) ?
			GGEP_W_DEFLATE : 0;
		extid = ext_ggep_id_str(e);
	} else {
		flags = plen > DEFLATE_THRESHOLD ? GGEP_W_DEFLATE : 0;
		extid = id;
	}

	ok = ggep_stream_pack(gs, extid, payload, plen, flags);

	if (!ok)
		search_log_ggep_write_failure(extid, flags, n, caller);
}

/**
 * Compact search request by removing unneeded extensions, cutting on
 * needless bloat, and by removing unnecessary bloat from the query string.
 *
 * When NODE_M_ADD_GE_SO is set, we add the GGEP "SO" key to the message,
 * creating a GGEP extension if needed in order to secure OOB hit delivery
 * for OOB-proxied queries.
 *
 * Edition happens in-place: upon return we have a new valid message in the
 * node buffer, ready to be sent.
 */
void
search_compact(gnutella_node_t *n)
{
	const char *search;
	size_t search_len;
	extvec_t exv[MAX_EXTVEC];
	int i, exvcnt;
	size_t extra, newlen;
	char buffer[512];
	char *dest = buffer;
	char *p;
	const char *end = dest + sizeof buffer;
	size_t target;
	bool has_ggep = FALSE;
	char *start;

	g_assert(GTA_MSG_SEARCH == gnutella_header_get_function(&n->header));
	g_assert(n->data != NULL);

	search = n->data + 2;	/* skip flags */
	search_len = clamp_strlen(search, n->size - 2);

	g_assert(n->size >= search_len + 3);	/* 3 = 2 (flags) + 1 (NUL) */

	/*
	 * Compact query string, if requested.
	 */

	if (GNET_PROPERTY(gnet_compact_query)) {
		unsigned offset;

		/*
		 * Compact the query, offsetting from the start as needed in case
		 * there is a leading BOM (our UTF-8 decoder does not allow BOM
		 * within the UTF-8 string, and rightly I think: that would be pure
		 * gratuitous bloat).
		 */

		if (query_utf8_decode(search, &offset)) {
			size_t mangled_search_len;
			char *str = deconstify_char(search);

			mangled_search_len = compact_query_utf8(&str[offset]);

			g_assert(mangled_search_len <= search_len - offset);

			if (mangled_search_len != search_len - offset) {
				gnet_stats_inc_general(GNR_QUERY_COMPACT_COUNT);
				gnet_stats_count_general(GNR_QUERY_COMPACT_SIZE,
					search_len - offset - mangled_search_len);
				n->msg_flags |= NODE_M_COMPACTED;
			}

			/*
			 * Need to move the trailing data forward and adjust the
			 * size of the packet.
			 */

			memmove(
				&str[offset + mangled_search_len], /* new end of query string */
				&str[search_len],                  /* old end of query string */
				n->size - (search - n->data) - search_len); /* trailer len */

			n->size -= search_len - offset - mangled_search_len;
			gnutella_header_set_size(&n->header, n->size);
			search_len = mangled_search_len + offset;

			g_assert('\0' == search[search_len]);
		}
	}

	/*
	 * Now deal with extensions, if needed.
	 */

	if (!(n->msg_flags & NODE_M_EXT_CLEANUP))
		return;

	extra = n->size - 3 - search_len;		/* Amount of extra data */

	g_assert(size_is_non_negative(extra));

	if G_UNLIKELY(0 == extra && !(n->msg_flags & NODE_M_ADD_GE_SO))
		return;		/* Nothing to strip nor to add */

	ext_prepare(exv, MAX_EXTVEC);

	if G_UNLIKELY(0 == extra) {
		exvcnt = 0;
	} else {
		exvcnt = ext_parse(search + search_len + 1, extra, exv, MAX_EXTVEC);
	}

	target = extra + (extra >> 2);		/* Add 25% margin for bad compression */

	if (n->msg_flags & NODE_M_ADD_GE_SO) {
		/* Will force an "SO" extension if missing */
		target += 6;					/* Worst case (no GGEP block already) */
		has_ggep = TRUE;				/* Because we'll add "SO" */
	}

	if (target > sizeof buffer) {
		dest = halloc(target);
		end = dest + target;
	}

	/*
	 * First pass: emit all non-GGEP extensions as HUGE fields.
	 */

	p = dest;

	for (i = 0; i < exvcnt; i++) {
		extvec_t *e = &exv[i];

		switch (e->ext_type) {
		case EXT_GGEP:
			has_ggep = TRUE;
			/* FALL THROUGH */
		case EXT_NONE:
			continue;
		case EXT_XML:
			{
				vxml_parser_t *vp;
				vxml_error_t err;
				xnode_t *root;

				vp = vxml_parser_make("Query XML", VXML_O_NO_NAMESPACES);
				vxml_parser_add_data(vp, ext_payload(e), ext_paylen(e));
				err = vxml_parse_tree(vp, &root);
				if (VXML_E_OK != err) {
					if (GNET_PROPERTY(query_debug)) {
						g_warning("QUERY #%s dropping invalid XML payload: %s",
							guid_hex_str(gnutella_header_get_muid(&n->header)),
							vxml_strerror(err));
					}
				} else {
					size_t w;

					g_assert(root != NULL);

					/*
					 * Remove this useless XML bloat.
					 */

					xnode_prop_unset(root, "xsi:noNamespaceSchemaLocation");
					xnode_prop_unset(root, "xsi:nonamespaceschemalocation");

					if (!search_xml_tree_empty(root)) {
						/*
						 * Emit the XML without indentation and prologue.
						 * All XML parsers can parse without a prologue, so why
						 * send one in each and every query?
						 */

						w = xfmt_tree_to_buffer(root, p, end - p,
								XFMT_O_SKIP_BLANKS | XFMT_O_SINGLE_LINE);

						if ((size_t) -1 == w) {
							if (GNET_PROPERTY(query_debug)) {
								g_warning("%s(): QUERY #%s "
									"could not rewrite XML tree",
									G_STRFUNC,
									guid_hex_str(
										gnutella_header_get_muid(&n->header)));
							}
						} else {
							p += w;
							*p++ = HUGE_FS;
						}
					}

					xnode_tree_free_null(&root);
				}
				vxml_parser_free(vp);
			}
			g_assert(p <= end);
			break;
		case EXT_HUGE:
			{
				/*
				 * All Gnutella servents will send a SHA-1 of matched files,
				 * so there's no need for an empty "urn:" or "urn:sha1:"
				 * specification in the query.
				 */

				switch (e->ext_token) {
				case EXT_T_URN_EMPTY:
					break;					/* Don't emit empty "urn:" */
				case EXT_T_URN_BAD:
				case EXT_T_URN_UNKNOWN:
					break;					/* Don't emit, obviously! */
				case EXT_T_URN_TTH:
					break;					/* Only the TTH root, skip */
				case EXT_T_URN_SHA1:
					{
						size_t paylen = ext_paylen(e);
						if (0 == paylen)
							break;			/* Dont emit simple "urn:sha1:" */
					}
					/* FALL THROUGH */
				case EXT_T_URN_BITPRINT:
					{
						size_t paylen = ext_paylen(e);
						size_t w;

						/*
						 * We force an urn:sha1: in the queries because sending
						 * bitprints is a waste of space: legacy servents will
						 * not understand this larger URN and moreoever URN
						 * queries are deprecated and should now be done via
						 * the DHT.
						 *		--RAM, 2011-06-12
						 */

						if (
							GNET_PROPERTY(query_debug) > 2 &&
							EXT_T_URN_SHA1 != e->ext_token
						) {
							const char *prefix = ext_huge_urn_name(e);
							g_debug("QUERY #%s rewriting %s as urn:sha1",
								guid_hex_str(
									gnutella_header_get_muid(&n->header)),
								prefix);
						}

						w = cstr_bcpy(p, end - p, "urn:sha1");
						p += w;
						*p++ = ':';
						paylen = MIN(paylen, SHA1_BASE32_SIZE);
						p = mempcpy(p, ext_payload(e), paylen);
						*p++ = HUGE_FS;
					}
				default:
					break;
				}
			}
			g_assert(p <= end);
			break;
		case EXT_UNKNOWN:
			{
				size_t w;

				w = clamp_memcpy(p, end - p, ext_payload(e), ext_paylen(e));
				p += w;
				*p++ = HUGE_FS;
			}
			break;
		case EXT_TYPE_COUNT:
			g_assert_not_reached();
		}
	}

	/*
	 * If we're not going to add a GGEP extension block, the last HUGE
	 * separator we emitted is useless and must be stripped out.
	 */

	if (p != dest && !has_ggep) {
		g_assert(p > dest && p <= end);
		g_assert(HUGE_FS == *(p - 1));
		p--;		/* Remove trailing useless HUGE separator */
	}

	/*
	 * Second pass: emit GGEP extension block.
	 */

	if (has_ggep) {
		ggep_stream_t gs;
		size_t glen;
		bool has_ggep_so = FALSE;

		g_assert(p < end);

		ggep_stream_init(&gs, p, end - p);

		for (i = 0; i < exvcnt; i++) {
			extvec_t *e = &exv[i];
			bool ok;

			if (EXT_GGEP != e->ext_type)
				continue;

			switch (e->ext_token) {
			case EXT_T_GGEP_6:
				if (16 != ext_paylen(e))
					continue;	/* Strip improperly sized value */
				if (n->msg_flags & NODE_M_FINISH_IPV6)
					continue;	/* We'll emit one for our own address */
				if (QUERY_F_OOB_REPLY & search_request_get_flags(n))
					break;
				/* "6" only required for OOB replies to an IPv6 address */
				continue;
			case EXT_T_GGEP_u:
				if (n->msg_flags & (NODE_M_STRIP_GE_u | NODE_M_WHATS_NEW))
					continue;
				break;
			case EXT_T_GGEP_QK:
			case EXT_T_GGEP_SCP:
			case EXT_T_GGEP_Z:
				if (n->msg_flags & (NODE_M_STRIP_GUESS | NODE_M_WHATS_NEW))
					continue;
				break;
			case EXT_T_GGEP_SO:
				has_ggep_so = TRUE;
				if (n->msg_flags & NODE_M_STRIP_GE_SO)
					continue;
				break;
			case EXT_T_GGEP_WH:
			case EXT_T_GGEP_M:
				/* "WH", and "M" are kept with NODE_M_WHATS_NEW */
				break;
			case EXT_T_GGEP_NP:
				/* "NP" only used from leaf -> ultra to prevent OOB proxying */
				continue;	/* Strip "NP" in relayed queries */
			case EXT_T_GGEP_H:
				if (n->msg_flags & NODE_M_WHATS_NEW)
					continue;		/* Strip "H" in "what's new?" queries */
				{
					const char *payload = ext_payload(e);
					sha1_t sha1;
					ggept_status_t ret = ggept_h_sha1_extract(e, &sha1);
					const uint8 type = GGEP_H_SHA1;

					if (ret != GGEP_OK)
						continue;		/* Not a SHA1 or bitprint -- strip! */

					if (GGEP_H_SHA1 == payload[0])
						break;			/* Propagate as-is */

					/*
					 * Rewrite with only the SHA1, then continue.
					 */

					ok = ggep_stream_begin(&gs, GGEP_NAME(H), 0) &&
						ggep_stream_write(&gs, &type, 1) &&
						ggep_stream_write(&gs, sha1.data, SHA1_RAW_SIZE) &&
						ggep_stream_end(&gs);

					if (!ok)
						search_log_ggep_write_failure("H", 0, n, G_STRFUNC);
				}
				continue;		/* We rewrote it */
			default:
				if (n->msg_flags & NODE_M_WHATS_NEW)
					continue;
				/* Other GGEP extensions kept if not a "What's New?" */
				break;
			}

			search_ggep_write(&gs, e, NULL, ext_payload(e), ext_paylen(e),
				n, G_STRFUNC);
		}

		/*
		 * IPv6-Ready: if we're OOB-proxying a query and we're running on IPv6,
		 * so we must add our IPv6 listening address.
		 */

		if (n->msg_flags & NODE_M_FINISH_IPV6) {
			const host_addr_t addr6 = listen_addr6();
			const uint8 *ipv6 = host_addr_ipv6(&addr6);

			search_ggep_write(&gs, NULL, GGEP_NAME(6), ipv6, 16, n, G_STRFUNC);
		}

		/*
		 * If we have to add a GGEP "SO", do it now unless already present.
		 */

		if ((n->msg_flags & NODE_M_ADD_GE_SO) && !has_ggep_so)
			search_ggep_write(&gs, NULL, GGEP_NAME(SO), NULL, 0, n, G_STRFUNC);

		glen = ggep_stream_close(&gs);
		p += glen;
		g_assert(p <= end);
	}

	newlen = p - dest;
	g_assert(size_is_non_negative(newlen));

	ext_reset(exv, MAX_EXTVEC);

	if (newlen != extra) {
		size_t diff = extra - newlen;

		if (
			GNET_PROPERTY(query_debug) > 14 ||
			(
				(n->msg_flags & NODE_M_STRIP_GUESS) &&
				GNET_PROPERTY(guess_server_debug) > 5
			) ||
			(
				(n->msg_flags & NODE_M_ADD_GE_SO) &&
				GNET_PROPERTY(secure_oob_debug)
			)
		) {
			g_debug("QUERY %s#%s search extension part %zu -> %zu bytes%s",
				NODE_IS_UDP(n) ? "(GUESS) " : "",
				guid_hex_str(gnutella_header_get_muid(&n->header)),
				extra, newlen,
				(n->msg_flags & NODE_M_ADD_GE_SO) ?
					" (added GGEP \"SO\")" : ""
			);
		}

		/*
		 * Adjust message length.
		 *
		 * We can add extensions on the fly, not just strip them, hence
		 * we may have to grow n->data, which can move data around!
		 */

		n->size -= diff;
		gnutella_header_set_size(&n->header, n->size);
		node_grow_data(n, n->size);
		search = n->data + 2;	/* skip flags, n->data could have changed */

		if (!(n->msg_flags & NODE_M_COMPACTED) && size_is_positive(diff)) {
			gnet_stats_inc_general(GNR_QUERY_COMPACT_COUNT);
			n->msg_flags |= NODE_M_COMPACTED;
		}

		if (size_is_positive(diff))
			gnet_stats_count_general(GNR_QUERY_COMPACT_SIZE, diff);
	}

	/*
	 * Copy new bytes over and update statistics.
	 */

	start = deconstify_char(search) + search_len + 1;
	memcpy(start, dest, newlen);

	if (GNET_PROPERTY(query_debug) > 13) {
		if (newlen != 0) {
			exvcnt = ext_parse(start, newlen, exv, MAX_EXTVEC);
			g_debug("QUERY %s#%s rewritten extensions "
				"(now %zu byte%s, was %zu), payload now %u bytes",
				NODE_IS_UDP(n) ? "(GUESS) " : "",
				guid_hex_str(gnutella_header_get_muid(&n->header)),
				PLURAL(newlen), extra, n->size);
			ext_dump(stderr, exv, exvcnt, "> ", "\n",
				GNET_PROPERTY(query_debug) > 14);
			ext_reset(exv, MAX_EXTVEC);
		} else if (newlen != extra) {
			g_debug("QUERY %s#%s rewritten with no extensions",
				NODE_IS_UDP(n) ? "(GUESS) " : "",
				guid_hex_str(gnutella_header_get_muid(&n->header)));
		}
	}

	if (dest != buffer)
		HFREE_NULL(dest);
}

/**
 * Lazily produce a print-safe version of a search string.
 * The returned string MUST NOT be freed and will remain valid until
 * the next call to this routine..
 */
const char *
lazy_safe_search(const char *search)
{
	static char *previous;
	char *canonic;
	char *safe;

	g_assert(search != previous);

	HFREE_NULL(previous);

	canonic = UNICODE_CANONIZE(search);
	safe = hex_escape(canonic, FALSE);

	if (safe == search) {
		g_assert(canonic == search);
		return search;
	} else {
		if (canonic != search && safe != canonic) {
			HFREE_NULL(canonic);
		}
		return previous = NOT_LEAKING(safe);
	}
}

/* vi: set ts=4 sw=4 cindent: */
