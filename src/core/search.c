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
 * Search handling (core side).
 *
 * @author Raphael Manfredi
 * @date 2001-2003
 */

#include "common.h"

RCSID("$Id$")

#include "bogons.h"
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
#include "guid.h"
#include "hostiles.h"
#include "hosts.h"
#include "huge.h"
#include "ignore.h"
#include "nodes.h"
#include "oob.h"
#include "oob_proxy.h"
#include "qhit.h"
#include "qrp.h"
#include "routing.h"
#include "search.h"
#include "settings.h"		/* For listen_ip() */
#include "share.h"
#include "sockets.h"
#include "spam.h"
#include "sq.h"
#include "version.h"
#include "vmsg.h"

#include "if/gnet_property_priv.h"
#include "if/core/hosts.h"
#include "if/bridge/c2ui.h"

#include "lib/array.h"
#include "lib/ascii.h"
#include "lib/atoms.h"
#include "lib/endian.h"
#include "lib/glib-missing.h"
#include "lib/hashlist.h"
#include "lib/idtable.h"
#include "lib/iso3166.h"
#include "lib/listener.h"
#include "lib/magnet.h"
#include "lib/sbool.h"
#include "lib/tm.h"
#include "lib/vendors.h"
#include "lib/wordvec.h"
#include "lib/walloc.h"
#include "lib/zalloc.h"
#include "lib/utf8.h"
#include "lib/urn.h"

#include "lib/override.h"		/* Must be the last header included */

#define MIN_SEARCH_TERM_BYTES 3		/* in bytes! */
#define MAX_SEARCH_TERM_BYTES 200	/* in bytes; reserve some for GGEP etc. */

/*
 * Ignore this nonsense for release but see whether anyone complains about this
 * rather low limit for non-releases. LimeWire drops searches with more than
 * 30 characters (actually UTF-16 codepoints).
 */
#ifdef OFFICIAL_BUILD
#define MAX_SEARCH_TERM_CHARS MAX_SEARCH_TERM_BYTES	/* in characters! */
#else
#define MAX_SEARCH_TERM_CHARS 30	/* in characters! */
#endif	/* OFFICIAL_BUILD */

#define MUID_MAX			4	 /**< Max amount of MUID we keep per search */
#define SEARCH_MIN_RETRY	1800 /**< Minimum search retry timeout */

static GHashTable *muid_to_query_map;
static hash_list_t *query_muids;

static void
query_muid_map_init(void)
{
	muid_to_query_map = g_hash_table_new(pointer_hash_func, NULL);
	query_muids = hash_list_new(guid_hash, guid_eq);
}

static gboolean
query_muid_map_remove_oldest(void)
{
	const struct guid *old_muid;

	old_muid = hash_list_head(query_muids);
	if (old_muid) {
		const gchar *old_query;
		
		hash_list_remove(query_muids, old_muid);

		old_query = g_hash_table_lookup(muid_to_query_map, old_muid);
		g_hash_table_remove(muid_to_query_map, old_muid);

		atom_guid_free_null(&old_muid);
		atom_str_free_null(&old_query);
		return TRUE;
	} else {
		return FALSE;
	}
}

static void
query_muid_map_close(void)
{
	while (query_muid_map_remove_oldest())
		continue;

	g_hash_table_destroy(muid_to_query_map);
	muid_to_query_map = NULL;
	hash_list_free(&query_muids);
}

static void
query_muid_map_garbage_collect(void)
{
	guint removed = 0;
	
	while (
		hash_list_length(query_muids) > GNET_PROPERTY(search_muid_track_amount)
	) {

		if (!query_muid_map_remove_oldest())
			break;

		/* If search_muid_track_amount was lowered drastically, there might
		 * be thousands of items to remove. If there are too much to be
		 * removed, we abort and come back later to prevent stalling.
		 */
		if (++removed > 100)
			break;
	}
}

void
record_query_string(const struct guid *muid, const gchar *query)
{
	const struct guid *key;
	
	g_assert(muid);
	g_assert(query);

	if (GNET_PROPERTY(search_muid_track_amount) > 0) {
		gconstpointer orig_key;

		orig_key = hash_list_remove(query_muids, muid);
	   	if (orig_key) {
			const gchar *old_query;

			/* We'll append the new value to the list */
			key = orig_key;
			old_query = g_hash_table_lookup(muid_to_query_map, key);
			atom_str_free_null(&old_query);
			g_hash_table_remove(muid_to_query_map, old_query);
		} else {
			key = atom_guid_get(muid);
		}

		gm_hash_table_insert_const(muid_to_query_map, key, atom_str_get(query));
		hash_list_append(query_muids, key);
	}
	query_muid_map_garbage_collect();
}

const gchar *
map_muid_to_query_string(const struct guid *muid)
{
	gconstpointer orig_key;
	
	if (hash_list_contains(query_muids, muid, &orig_key)) {
		return g_hash_table_lookup(muid_to_query_map, orig_key);
	}
	return NULL;
}

static guint32 search_id;				/**< Unique search counter */
static GHashTable *searches;			/**< All alive searches */

/**
 * Structure for search results.
 */
typedef struct search_ctrl {
    gnet_search_t search_handle;	/**< Search handle */
	guint32 id;						/**< Unique ID */

	/* no more "speed" field -- use marked field now --RAM, 06/07/2003 */

	const gchar *query;	/**< The normalized search query (atom) */
	const gchar *name;	/**< The original search term (atom) */
	time_t  time;		/**< Time when this search was started */
	GSList *muids;		/**< Message UIDs of this search */

	sbool passive;	/**< Is this a passive search? */
	sbool frozen;	/**< NOTE: If TRUE, the query is not issued to nodes
				  		anymore and "don't update window" */
	sbool browse;	/**< Special "browse host" search */
	sbool local;	/**< Special "local" search */
	sbool active;	/**< Whether to actively issue queries. */

	/*
	 * Keep a record of nodes we've sent this search w/ this muid to.
	 */

	GHashTable *sent_nodes;		/**< Sent node by ip:port */
	GHashTable *sent_node_ids;	/**< IDs of nodes to which we sent query */

	GHook *new_node_hook;
	guint reissue_timeout_id;
	guint reissue_timeout;		/**< timeout per search, 0 = search stopped */
	time_t create_time;			/**< Time at which this search was created */
	guint lifetime;				/**< Initial lifetime (in hours) */
	guint query_emitted;		/**< # of queries emitted since last retry */
	guint32 items;				/**< Items displayed in the GUI */
	guint32 kept_results;		/**< Results we kept for last query */

	/*
	 * For browse-host requests.
	 */

	struct download *download;	/**< Associated download for browse-host */
} search_ctrl_t;

/*
 * List of all searches, and of passive searches only.
 */
static GSList *sl_search_ctrl;		/**< All searches */
static GSList *sl_passive_ctrl;		/**< Only passive searches */

/*
 * Table holding all the active MUIDs for all the searches, pointing back
 * to the searches directly (i.e. it maps MUID -> search_ctrl_t).
 * The keys are not atoms but directly the MUID objects allocated and held
 * in the search's set of MUIDs.
 */
static GHashTable *search_by_muid;

static zone_t *rs_zone;		/**< Allocation of results_set */
static zone_t *rc_zone;		/**< Allocation of record */

static idtable_t *search_handle_map;
static query_hashvec_t *query_hashvec;

static inline search_ctrl_t *
search_find_by_handle(gnet_search_t n)
{
	return idtable_get_value(search_handle_map, n);
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

static void search_check_results_set(gnet_results_set_t *rs);

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
search_fire_got_results(GSList *sch_matched, const gnet_results_set_t *rs)
{
    g_assert(rs != NULL);

	LISTENER_EMIT(search_got_results, (sch_matched, rs));
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

static guint
sent_node_hash_func(gconstpointer key)
{
	const gnet_host_t *sd = key;

	/* ensure that we've got sizeof(gint) bytes of deterministic data */
	return host_addr_hash(gnet_host_get_addr(sd)) ^
			(guint32) gnet_host_get_port(sd);
}

static gint
sent_node_compare(gconstpointer a, gconstpointer b)
{
	const gnet_host_t *sa = a, *sb = b;

	return gnet_host_get_port(sa) == gnet_host_get_port(sb) &&
		host_addr_equal(gnet_host_get_addr(sa), gnet_host_get_addr(sb));
}

static gboolean
search_free_sent_node(gpointer key,
	gpointer unused_value, gpointer unused_udata)
{
	gnet_host_t *node = key;

	(void) unused_value;
	(void) unused_udata;

	wfree(node, sizeof *node);
	return TRUE;
}

static void
search_free_sent_nodes(search_ctrl_t *sch)
{
	g_hash_table_foreach_remove(sch->sent_nodes, search_free_sent_node, NULL);
	g_hash_table_destroy(sch->sent_nodes);
}

static void
search_reset_sent_nodes(search_ctrl_t *sch)
{
	search_free_sent_nodes(sch);
	sch->sent_nodes = g_hash_table_new(sent_node_hash_func, sent_node_compare);
}

static void
mark_search_sent_to_node(search_ctrl_t *sch, gnutella_node_t *n)
{
	gnet_host_t *sd = walloc(sizeof *sd);
	gnet_host_set(sd, n->addr, n->port);
	g_hash_table_insert(sch->sent_nodes, sd, GUINT_TO_POINTER(1));
}

static void
mark_search_sent_to_connected_nodes(search_ctrl_t *sch)
{
	const GSList *sl;
	struct gnutella_node *n;

	for (sl = node_all_nodes(); sl; sl = g_slist_next(sl)) {
		n = sl->data;
		if (NODE_IS_WRITABLE(n))
			mark_search_sent_to_node(sch, n);
	}
}

/***
 *** Management of the "sent_node_ids" hash table.
 ***/

static gboolean
free_node_id(gpointer key, gpointer value, gpointer unused_udata)
{
	const node_id_t node_id = key;

	g_assert(key == value);
	(void) unused_udata;
	node_id_unref(node_id);
	return TRUE;
}

static void
search_free_sent_node_ids(search_ctrl_t *sch)
{
	g_hash_table_foreach_remove(sch->sent_node_ids, free_node_id, NULL);
	g_hash_table_destroy(sch->sent_node_ids);
	sch->sent_node_ids = NULL;
}

static void
search_reset_sent_node_ids(search_ctrl_t *sch)
{
	search_free_sent_node_ids(sch);
	sch->sent_node_ids = g_hash_table_new(node_id_hash, node_id_eq_func);
}

static void
mark_search_sent_to_node_id(search_ctrl_t *sch, const node_id_t node_id)
{
	if (NULL == g_hash_table_lookup(sch->sent_node_ids, node_id)) {
		const node_id_t key = node_id_ref(node_id);
		gm_hash_table_insert_const(sch->sent_node_ids, key, key);
	}
}

/**
 * @return TRUE if we already queried the given node for the given search.
 */
static gboolean
search_already_sent_to_node(const search_ctrl_t *sch, const gnutella_node_t *n)
{
	gnet_host_t sd;

	gnet_host_set(&sd, n->addr, n->port);
	return NULL != g_hash_table_lookup(sch->sent_nodes, &sd);
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
	atom_str_free_null(&rc->name);
	atom_str_free_null(&rc->tag);
	atom_str_free_null(&rc->xml);
	atom_str_free_null(&rc->path);
	atom_sha1_free_null(&rc->sha1);
	atom_tth_free_null(&rc->tth);
	search_free_alt_locs(rc);
	zfree(rc_zone, rc);
}

static gnet_results_set_t *
search_new_r_set(void)
{
	static const gnet_results_set_t zero_rs;
	gnet_results_set_t *rs;
   
	rs = zalloc(rs_zone);
	*rs = zero_rs;
	return rs;
}

/**
 * Free one results_set.
 */
static void
search_free_r_set(gnet_results_set_t *rs)
{
	GSList *m;

	for (m = rs->records; m; m = g_slist_next(m)) {
		search_free_record(m->data);
	}
	atom_guid_free_null(&rs->guid);
	atom_str_free_null(&rs->version);
	atom_str_free_null(&rs->hostname);
	atom_str_free_null(&rs->query);
	search_free_proxies(rs);

	g_slist_free(rs->records);
	zfree(rs_zone, rs);
}


static gnet_record_t *
search_record_new(void)
{
	static const gnet_record_t zero_record;
	gnet_record_t *rc;

	rc = zalloc(rc_zone);
	*rc = zero_record;
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
 * @param data The buffer to scan.
 * @param size The size of the buffer.
 * @return TRUE if spam was detected, FALSE if it looks alright.
 */
static gboolean
is_action_url_spam(const char * const data, size_t size)
{
	if (size > 0) {
		static const char schema[] = "http://www.limewire.com/schemas/";
		const char *p;

		g_assert(data);
		p = compat_memmem(data, size, schema, CONST_STRLEN(schema));
		if (p) {
			static const char action[] = " action=\"http://";

			p += CONST_STRLEN(schema);
			size -= p - data;
			if (compat_memmem(p, size, action, CONST_STRLEN(action)))
				return TRUE;
		}
	}
	return FALSE;
}

static gboolean
has_dupe_spam(const gnet_results_set_t *rs)
{
	GSList *sl;
	guint dupes = 0;

	for (sl = rs->records; NULL != sl; sl = g_slist_next(sl)) {
		gnet_record_t *r1, *r2;

		if (!g_slist_next(sl))
			break;
		r1 = sl->data;
		r2 = g_slist_next(sl)->data;
		if (
			r1->file_index == r2->file_index &&
			r1->sha1 == r2->sha1 &&
			r1->size == r2->size
		) {
			dupes++;
		}
	}

	return dupes > 4;	/* Tolerate a few dupes for now */
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
static inline gchar
url_normalize_char(const gchar *p, const gchar **endptr)
{
	gchar c;

	g_assert(p);
	g_assert(endptr);

	c = *p;
	if ('\\' == c) {
		c = '/';
	} else if ('%' == c) {
		gint hi, lo;

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
static gboolean
is_evil_filename(const gchar *filename)
{
	const gchar *endptr, *p = filename;
	gchar win[4];
	guint i;

	g_assert(filename);

	win[0] = '/';	/* Implicit by "/get/<index>/<filename>" */

	for (i = 1; i < G_N_ELEMENTS(win); i++) {
		win[i] = url_normalize_char(p, &endptr);
		if ('\0' == *p)
			break;
		p = endptr;
	}
	
	for (;;) {
		if (
			0 == memcmp(win, "/", 2) ||
			0 == memcmp(win, "/.", 3) ||
			0 == memcmp(win, "/..", 4) ||
			0 == memcmp(win, "/../", 4)
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

static hash_list_t *oob_reply_acks;
static const time_delta_t oob_reply_ack_timeout = 120;

struct ora {
	const struct guid *muid;	/* GUID atom */
	time_t sent;
	host_addr_t addr;
	guint32 token;
	guint16 port;
};

static struct ora *
ora_alloc(const struct guid *muid, const host_addr_t addr, guint16 port,
		guint32 token)
{
	struct ora *ora;

	ora = walloc(sizeof *ora);
	ora->muid = atom_guid_get(muid);
	ora->addr = addr;
	ora->port = port;
	ora->token = token;
	return ora;
}

static void
ora_free(struct ora **ora_ptr)
{
	struct ora *ora;

	ora = *ora_ptr;
	if (ora) {
		atom_guid_free_null(&ora->muid);
		wfree(ora, sizeof *ora);
		*ora_ptr = NULL;
	}
}

static guint
ora_hash(gconstpointer key)
{
	const struct ora *ora = key;

	return ora->token ^
		guid_hash(ora->muid) ^
		host_addr_hash(ora->addr) ^
		(((guint32) ora->port << 16) | ora->port);
}

static gint
ora_eq(gconstpointer v1, gconstpointer v2)
{
	const struct ora *a = v1, *b = v2;

	return a->token == b->token &&
		a->port == b->port &&
		host_addr_equal(a->addr, b->addr) &&
		guid_eq(a->muid, b->muid);
}

static struct ora *
ora_lookup(const struct guid *muid,
	const host_addr_t addr, guint16 port, guint32 token)
{
	struct ora ora;
	gconstpointer key;

	ora.muid = muid;
	ora.sent = 0;
	ora.addr = addr;
	ora.port = port;
	ora.token = token;

	if (hash_list_contains(oob_reply_acks, &ora, &key)) {
		return deconstify_gpointer(key);
	}
	return NULL;
}

static gboolean
oob_reply_acks_remove_oldest(void)
{
	struct ora *ora;

	ora = hash_list_head(oob_reply_acks);
	if (ora) {
		hash_list_remove(oob_reply_acks, ora);
		ora_free(&ora);
		return TRUE;
	}
	return FALSE;
}

static void
oob_reply_acks_garbage_collect(void)
{
	time_t now = tm_time();
	
	do {
		struct ora *ora;

		ora = hash_list_head(oob_reply_acks);
		if (!ora || delta_time(now, ora->sent) <= oob_reply_ack_timeout)
			break;
	} while (oob_reply_acks_remove_oldest());
}

static void
oob_reply_acks_init(void)
{
	oob_reply_acks = hash_list_new(ora_hash, ora_eq);
}

static void
oob_reply_acks_close(void)
{
	while (oob_reply_acks_remove_oldest()) {
		continue;
	}
	hash_list_free(&oob_reply_acks);
}

static void
oob_reply_ack_record(const struct guid *muid,
	const host_addr_t addr, guint16 port, guint32 token)
{
	struct ora *ora;
	
	g_assert(muid);

	ora = ora_lookup(muid, addr, port, token);
	if (ora) {
		/* We'll append the new value to the list */
		hash_list_remove(oob_reply_acks, ora);
	} else {
		ora = ora_alloc(muid, addr, port, token);
	}
	ora->sent = tm_time();

	hash_list_append(oob_reply_acks, ora);
	oob_reply_acks_garbage_collect();
}

/**
 * Check whether we have explicitly claimed some OOB hits.
 *
 * @param muid	the query MUID used, as seen from the query hit
 * @param addr	the address from which the results come via UDP
 * @param port	the port from which results come
 */
static gboolean
search_results_are_requested(const struct guid *muid,
	const host_addr_t addr, guint16 port, guint32 token)
{
	struct ora *ora;

	ora = ora_lookup(muid, addr, port, token);
	if (ora) {
		if (delta_time(tm_time(), ora->sent) <= oob_reply_ack_timeout)
			return TRUE;
		hash_list_remove(oob_reply_acks, ora);
	}
	return FALSE;
}

/**
 * Compute status bits, decompile trailer info, if present.
 *
 * @return TRUE if there were errors and the packet should be dropped.
 */
static gboolean
search_results_handle_trailer(const gnutella_node_t *n,
	gnet_results_set_t *rs, const gchar *trailer, size_t trailer_size)
{
	guint8 open_size, open_parsing_size, enabler_mask, flags_mask;
	const gchar *vendor;
	guint32 token;
	gboolean has_token;
	host_addr_t ipv6_addr;
	gboolean has_ipv6_addr;

	if (!trailer || trailer_size < 7)
		return FALSE;

	vendor = vendor_get_name(rs->vcode.u32);
	open_size = trailer[4];
	open_parsing_size = trailer[4];
	enabler_mask = trailer[5];
	flags_mask = trailer[6];
	has_token = FALSE;
	token = 0;
	has_ipv6_addr = FALSE;

	if (open_size > trailer_size - 4) {
		if (GNET_PROPERTY(search_debug)) {
			g_warning("Trailer is too small for open size field");
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
			guint8 status = enabler_mask & flags_mask;
			if (status & 0x04) rs->status |= ST_BUSY;
			if (status & 0x01) rs->status |= ST_FIREWALL;
			if (status & 0x08) rs->status |= ST_UPLOADED;
			if (status & 0x08) rs->status |= ST_UPLOADED;
			if (status & 0x20) rs->status |= ST_GGEP;
			rs->status |= ST_PARSED_TRAILER;
		} else if (rs->status & ST_KNOWN_VENDOR) {
			if (GNET_PROPERTY(search_debug) > 1)
				g_warning("vendor %s changed # of open data bytes to %d",
						vendor, open_size);
		} else if (vendor) {
			if (GNET_PROPERTY(search_debug) > 1)
				g_warning("ignoring %d open data byte%s from "
						"unknown vendor %s",
						open_size, open_size == 1 ? "" : "s", vendor);
		}
	}

	/*
	 * Parse trailer after the open data, if we have a GGEP extension.
	 */

	if (rs->status & ST_GGEP) {
		const gchar *priv;
		size_t privlen;
		gint exvcnt = 0;
		extvec_t exv[MAX_EXTVEC];
		gboolean seen_ggep = FALSE;
		gint i;

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
			case EXT_T_GGEP_GTKG_TLS:
				rs->status |= ST_TLS;
				break;
			case EXT_T_GGEP_SO:
				if ((ST_UDP & rs->status) && ext_paylen(e) == sizeof token) {
					memcpy(&token, ext_payload(e), sizeof token);
					has_token = TRUE;
				}
				break;
			case EXT_T_GGEP_GTKG_IPV6:
				if (has_ipv6_addr) {
					g_warning("%s has multiple GGEP \"GTKG.IPV6\" (ignoring)",
							gmsg_infostr(&n->header));
				} else {
					ret = ggept_gtkg_ipv6_extract(e, &ipv6_addr);
					if (GGEP_OK == ret) {
						has_ipv6_addr = TRUE;
					} else if (ret == GGEP_INVALID) {
						if (
							GNET_PROPERTY(search_debug) > 3 ||
							GNET_PROPERTY(ggep_debug) > 3
						) {
							g_warning("%s bad GGEP \"GTKG.IPV6\" (dumping)",
								gmsg_infostr(&n->header));
							ext_dump(stderr, e, 1, "....", "\n", TRUE);
						}
					}
				}
				break;
			case EXT_T_GGEP_GTKGV1:
				if (NULL != rs->version) {
					g_warning("%s has multiple GGEP \"GTKGV1\" (ignoring)",
							gmsg_infostr(&n->header));
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
						if (
							GNET_PROPERTY(search_debug) > 3 ||
							GNET_PROPERTY(ggep_debug) > 3
						) {
							g_warning("%s bad GGEP \"GTKGV1\" (dumping)",
									gmsg_infostr(&n->header));
							ext_dump(stderr, e, 1, "....", "\n", TRUE);
						}
					}
				}
				break;
			case EXT_T_GGEP_PUSH:
				if (NULL != rs->proxies) {
					g_warning("%s has multiple GGEP \"PUSH\" (ignoring)",
							gmsg_infostr(&n->header));
				} else {
					gnet_host_vec_t *hvec = NULL;

					rs->status |= ST_PUSH_PROXY;
					ret = ggept_push_extract(e, &hvec);
					if (ret == GGEP_OK) {
						rs->proxies = hvec;
					} else {
						if (
							GNET_PROPERTY(search_debug) > 3 ||
							GNET_PROPERTY(ggep_debug) > 3
						) {
							g_warning("%s bad GGEP \"PUSH\" (dumping)",
									gmsg_infostr(&n->header));
							ext_dump(stderr, e, 1, "....", "\n", TRUE);
						}
					}
				}
				break;
			case EXT_T_GGEP_HNAME:
				if (NULL != rs->hostname) {
					g_warning("%s has multiple GGEP \"HNAME\" (ignoring)",
							gmsg_infostr(&n->header));
				} else {
					gchar hostname[256];

					ret = ggept_hname_extract(e, hostname, sizeof(hostname));
					if (ret == GGEP_OK)
						rs->hostname = atom_str_get(hostname);
					else {
						if (
							GNET_PROPERTY(search_debug) > 3 ||
							GNET_PROPERTY(ggep_debug) > 3
						) {
							g_warning("%s bad GGEP \"HNAME\" (dumping)",
									gmsg_infostr(&n->header));
							ext_dump(stderr, e, 1, "....", "\n", TRUE);
						}
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
						size_t len;
						gchar buf[4096];

						len = MIN(paylen, sizeof buf - 1);
						memcpy(buf, ext_payload(e), len);
						buf[len] = '\0';
						if (utf8_is_valid_string(buf)) {
							rc->xml = atom_str_get(buf);
							if (is_action_url_spam(buf, len)) {
								rs->status |= ST_URL_SPAM;
							}
						}
					}
				}
				break;
			case EXT_T_UNKNOWN_GGEP:	/* Unknown GGEP extension */
				if (
					GNET_PROPERTY(search_debug) > 3 ||
					GNET_PROPERTY(ggep_debug) > 3
				) {
					g_warning("%s unknown GGEP \"%s\" in trailer (dumping)",
							gmsg_infostr(&n->header), ext_ggep_id_str(e));
					ext_dump(stderr, e, 1, "....", "\n", TRUE);
				}
				break;
			default:
				break;
			}
		}

		if (exvcnt == MAX_EXTVEC) {
			g_warning("%s from %s has %d trailer extensions!",
					gmsg_infostr(&n->header), vendor ? vendor : "????", exvcnt);
			if (GNET_PROPERTY(search_debug) > 2)
				ext_dump(stderr, exv, exvcnt, "> ", "\n", TRUE);
			if (GNET_PROPERTY(search_debug) > 3 && priv)
				dump_hex(stderr, "Query Hit private data", priv, privlen);
		} else if (!seen_ggep && GNET_PROPERTY(ggep_debug)) {
			g_warning("%s from %s claimed GGEP extensions in trailer, "
					"seen none",
					gmsg_infostr(&n->header), vendor ? vendor : "????");
		} else if (GNET_PROPERTY(search_debug) > 2) {
			g_message("%s from %s has %d trailer extensions:",
					gmsg_infostr(&n->header), vendor ? vendor : "????", exvcnt);
			ext_dump(stderr, exv, exvcnt, "> ", "\n", TRUE);
		}

		if (exvcnt)
			ext_reset(exv, MAX_EXTVEC);
	} else {
		if (is_action_url_spam(trailer, trailer_size)) {
			rs->status |= ST_URL_SPAM;
		}
	}

	/**
	 * Check whether the results were actually requested.
	 */

	if (ST_UDP & rs->status) {
		if (
			search_results_are_requested(
				gnutella_header_get_muid(&n->header), n->addr, n->port, token)
		) {
			if (has_token) {
				rs->status |= ST_GOOD_TOKEN;
			}
			/* We can send PUSH requests directly, so add it as push proxy. */
			if (NULL == rs->proxies) {
				rs->proxies = gnet_host_vec_alloc();
			}
			gnet_host_vec_add(rs->proxies, n->addr, n->port);
		} else {
			rs->status |= ST_UNREQUESTED | ST_FAKE_SPAM;
			gnet_stats_count_general(GNR_UNREQUESTED_OOB_HITS, 1);
			if (GNET_PROPERTY(search_debug)) {
				g_message("Received unrequested query hit from %s",
                	host_addr_port_to_string(n->addr, n->port));
			}
		}
	}

	/**
	 * If the peer has an IPv6 address, we can use that as push proxy, too.
	 */
	if (
		has_ipv6_addr &&
		rs->port > 0 &&
		is_host_addr(ipv6_addr) &&
		!hostiles_check(ipv6_addr)
	) {
		if (NULL == rs->proxies) {
			rs->proxies = gnet_host_vec_alloc();
		}
		gnet_host_vec_add(rs->proxies, ipv6_addr, rs->port);
	}
	return FALSE;	/* no errors */
}

/**
 * Parse Query Hit and extract the embedded records, plus the optional
 * trailing Query Hit Descritor (QHD).
 *
 * @returns a structure describing the whole result set, or NULL if we
 * were unable to parse it properly.
 */
static gnet_results_set_t *
get_results_set(gnutella_node_t *n, gboolean browse)
{
	gnet_results_set_t *rs;
	gchar *endptr, *s, *tag;
	guint32 nr = 0;
	guint32 size, idx, taglen;
	GString *info;
	unsigned sha1_errors = 0;
	unsigned alt_errors = 0;
	unsigned alt_without_hash = 0;
	gchar *trailer = NULL;
	gboolean seen_ggep_h = FALSE;
	gboolean seen_ggep_alt = FALSE;
	gboolean seen_bitprint = FALSE;
	gboolean multiple_sha1 = FALSE;
	gboolean multiple_alt = FALSE;
	const gchar *vendor = NULL;

	/* We shall try to detect malformed packets as best as we can */
	if (n->size < 27) {
		/* packet too small 11 header, 16 GUID min */
		g_warning("get_results_set(): given too small a packet (%d bytes)",
				  n->size);
        gnet_stats_count_dropped(n, MSG_DROP_TOO_SMALL);
		return NULL;
	}

	info = g_string_sized_new(80);

	rs = search_new_r_set();
	rs->stamp = tm_time();
	rs->country = ISO3166_INVALID;

	rs->ttl	= gnutella_header_get_ttl(&n->header);
	rs->hops = gnutella_header_get_hops(&n->header);
	if (!browse) {
		/*
		 * NB: route_message() increases hops by 1 for messages we handle.
		 */
		rs->hops--;
	}

	{
		const gchar *query;

		query = map_muid_to_query_string(gnutella_header_get_muid(&n->header));
		rs->query = query ? atom_str_get(query) : NULL;
	}

	/* Transfer the Query Hit info to our internal results_set struct */

	{
		const gnutella_search_results_t *r = cast_to_gpointer(n->data);

		rs->num_recs = gnutella_search_results_get_num_recs(r);
		rs->addr = host_addr_get_ipv4(gnutella_search_results_get_host_ip(r));
		rs->port = gnutella_search_results_get_host_port(r);
		rs->speed = gnutella_search_results_get_host_speed(r);
		rs->last_hop = n->addr;

		/* Now come the result set, and the servent ID will close the packet */

		STATIC_ASSERT(11 == sizeof *r);
		s = cast_to_gpointer(&r[1]);	/* Start of the records */
		endptr = &s[n->size - 11 - 16];	/* End of records, less header, GUID */
	}

	/*
	 * Hits coming from UDP should bear the node's address, unless the
	 * hit has a private IP because the servent did not determine its
	 * own IP address yet or is firewalled.
	 */

	if (NODE_IS_UDP(n)) {
		rs->status |= ST_UDP;

		if (
			!host_addr_equal(n->addr, rs->addr) &&
			!host_addr_is_routable(rs->addr)
		)
			gnet_stats_count_general(GNR_OOB_HITS_WITH_ALIEN_IP, 1);
	}

	/* Check for hostile IP addresses */

	if (hostiles_check(n->addr) || hostiles_check(rs->addr)) {
        if (GNET_PROPERTY(dbg) || GNET_PROPERTY(search_debug)) {
            g_message("dropping query hit from hostile IP %s",
                host_addr_to_string(rs->addr));
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
        if (GNET_PROPERTY(dbg) || GNET_PROPERTY(search_debug)) {
            g_warning("query hit advertising bogus IP %s",
				host_addr_port_to_string(rs->addr, rs->port));
        }
		rs->status |= ST_BOGUS | ST_FIREWALL;
	}

	/* Drop if no results in Query Hit */

	if (rs->num_recs == 0) {
        gnet_stats_count_dropped(n, MSG_DROP_BAD_RESULT);
		goto bad_packet;
	}

	if (GNET_PROPERTY(search_debug) > 7)
		dump_hex(stdout, "Query Hit Data", n->data, n->size);

	while (endptr - s > 10 && nr < rs->num_recs) {
		gnet_record_t *rc;
		gchar *filename;

		idx = peek_le32(s);
		s += 4;					/* File Index */
		size = peek_le32(s);
		s += 4;					/* File Size */

		/* Followed by file name, and termination (double NUL) */
		filename = s;

		s = memchr(s, '\0', endptr - s);
		if (!s) {
			/* There cannot be two NULs: end of packet! */
			gnet_stats_count_dropped(n, MSG_DROP_BAD_RESULT);
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

			/* Find to second NUL */
			s = memchr(s, '\0', endptr - s);
			if (s) {
				/* Found second NUL */
				taglen = s - tag;
			} else {
                gnet_stats_count_dropped(n, MSG_DROP_BAD_RESULT);
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
		rc->name = atom_str_get(filename);

		/*
		 * Some spammers get this wrong but some version of LimeWire
		 * start counting at zero despite this being a special wildcard
		 */
		if ((guint32)-1 == rc->file_index) {
			set_flags(rc->flags, SR_SPAM);
		}

		if (is_evil_filename(rc->name)) {
			if (GNET_PROPERTY(search_debug)) {
				g_message("get_results_set(): Ignoring evil filename \"%s\"",
					rc->name);
			}
			rs->status |= ST_EVIL;
			set_flags(rc->flags, SR_IGNORED);
		}

		/*
		 * If we have a tag, parse it for extensions.
		 */

		if (tag) {
			extvec_t exv[MAX_EXTVEC];
			gint exvcnt;
			gint i;
			gnet_host_vec_t *hvec = NULL;		/* For GGEP "ALT" */
			gboolean has_hash = FALSE;
			gboolean has_unknown = FALSE;

			g_assert(taglen > 0);

			ext_prepare(exv, MAX_EXTVEC);
			exvcnt = ext_parse(tag, taglen, exv, MAX_EXTVEC);

			/*
			 * Look for a valid SHA1 or a tag string we can display.
			 */

			g_string_truncate(info, 0);

			for (i = 0; i < exvcnt; i++) {
				extvec_t *e = &exv[i];
				struct sha1 sha1_digest;
				struct tth tth_digest;
				ggept_status_t ret;
				gint paylen;
				const gchar *payload;

				switch (e->ext_token) {
				case EXT_T_URN_BITPRINT:	/* first 32 chars is the SHA1 */
					seen_bitprint = TRUE;
					paylen = ext_paylen(e);
					if (paylen >= BITPRINT_BASE32_SIZE) {
						paylen = MIN(paylen, TTH_BASE32_SIZE);
						if (
							huge_tth_extract32(
								ext_payload(e) + SHA1_BASE32_SIZE + 1,
								paylen, &tth_digest, &n->header)
						) {
							atom_tth_change(&rc->tth, &tth_digest);
						} else {
							if (GNET_PROPERTY(search_debug) > 0) {
								g_message("huge_tth_extract32() failed");
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
								paylen, &sha1_digest, &n->header)
					) {
						if (spam_sha1_check(&sha1_digest)) {
							rs->status |= ST_URN_SPAM;
							set_flags(rc->flags, SR_SPAM);
						}
						multiple_sha1 |= NULL != rc->sha1;
						atom_sha1_change(&rc->sha1, &sha1_digest);
					} else {
						if (GNET_PROPERTY(search_debug) > 0) {
							g_message("huge_sha1_extract32() failed");
						}
						sha1_errors++;
					}
					break;
				case EXT_T_URN_TTH:	/* TTH URN (urn:ttroot) */
					paylen = ext_paylen(e);
					paylen = MIN(paylen, TTH_BASE32_SIZE);
					if (
						huge_tth_extract32(ext_payload(e),
							paylen, &tth_digest, &n->header)
					) {
						atom_tth_change(&rc->tth, &tth_digest);
					} else {
						if (GNET_PROPERTY(search_debug) > 0) {
							g_message("huge_tth_extract32() failed");
						}
					}
					break;
				case EXT_T_GGEP_TT:	/* TTH (binary) */
					paylen = ext_paylen(e);
					paylen = MIN(paylen, TTH_RAW_SIZE);
					if (TTH_RAW_SIZE == paylen) {
						memcpy(tth_digest.data, ext_payload(e), TTH_RAW_SIZE);
						atom_tth_change(&rc->tth, &tth_digest);
					} else {
						if (GNET_PROPERTY(search_debug) > 0) {
							g_message("GGEP \"TTH\" has wrong size");
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
						gchar *buf;

						has_hash = TRUE;

						/* Must NUL-terminate the payload first */
						buf = walloc(paylen + 1);
						memcpy(buf, payload, paylen);
						buf[paylen] = '\0';

						if (urn_get_sha1_no_prefix(buf, &sha1_digest)) {
							if (spam_sha1_check(&sha1_digest)) {
								rs->status |= ST_URN_SPAM;
								set_flags(rc->flags, SR_SPAM);
							}
							if (huge_improbable_sha1(sha1_digest.data,
									sizeof sha1_digest.data)
							) {
								if (GNET_PROPERTY(search_debug) > 0) {
									g_message("Improbable SHA-1 detected");
								}
								sha1_errors++;
							} else {
								multiple_sha1 |= NULL != rc->sha1;
								atom_sha1_change(&rc->sha1, &sha1_digest);
							}
						} else {
							if (GNET_PROPERTY(search_debug) > 0) {
								g_message("urn_get_sha1_no_prefix() failed");
							}
							sha1_errors++;
						}
						wfree(buf, paylen + 1);
					}
					break;
				case EXT_T_GGEP_H:			/* Expect SHA1 value only */
					ret = ggept_h_sha1_extract(e, &sha1_digest);
					if (ret == GGEP_OK) {
						has_hash = TRUE;
						if (GGEP_OK == ggept_h_tth_extract(e, &tth_digest)) {
							atom_tth_change(&rc->tth, &tth_digest);
						}
						if (spam_sha1_check(&sha1_digest)) {
							rs->status |= ST_URN_SPAM;
							set_flags(rc->flags, SR_SPAM);
						}
						if (huge_improbable_sha1(sha1_digest.data,
								sizeof sha1_digest.data)
						) {
							if (GNET_PROPERTY(search_debug) > 0) {
								g_message("Improbable SHA-1 detected");
							}
							sha1_errors++;
						} else {
							multiple_sha1 |= NULL != rc->sha1;
							atom_sha1_change(&rc->sha1, &sha1_digest);
						}
						seen_ggep_h = TRUE;
					} else if (ret == GGEP_INVALID) {
						sha1_errors++;
						if (
							GNET_PROPERTY(search_debug) > 3 ||
							GNET_PROPERTY(ggep_debug) > 3
						) {
							g_warning("%s bad GGEP \"H\" (dumping)",
								gmsg_infostr(&n->header));
							ext_dump(stderr, e, 1, "....", "\n", TRUE);
						}
					} else {
						if (
							GNET_PROPERTY(search_debug) > 3 ||
							GNET_PROPERTY(ggep_debug) > 3
						) {
							g_warning("%s GGEP \"H\" with no SHA1 (dumping)",
								gmsg_infostr(&n->header));
							ext_dump(stderr, e, 1, "....", "\n", TRUE);
						}
					}
					break;
				case EXT_T_GGEP_ALT:		/* Alternate locations */
					if (hvec != NULL) {		/* Already saw one for record! */
						multiple_alt = TRUE;
						break;
					}
					ret = ggept_alt_extract(e, &hvec);
					if (ret == GGEP_OK) {
						seen_ggep_alt = TRUE;
						if (gnet_host_vec_count(hvec) > 16) {
							/* Known limits: LIME: 10, GTKG: 15, BEAR: >10? */
							rs->status |= ST_ALT_SPAM;
						}
					} else {
						alt_errors++;
						if (GNET_PROPERTY(search_debug) > 3) {
							g_warning("%s bad GGEP \"ALT\" (dumping)",
								gmsg_infostr(&n->header));
							ext_dump(stderr, e, 1, "....", "\n", TRUE);
						}
					}
					break;
				case EXT_T_GGEP_ALT_TLS:	/* TLS-capability bitmap for ALT */
					/* FIXME: Handle this */	
					break;
				case EXT_T_GGEP_LF:			/* Large File */
					{
						guint64 fs;

					   	ret = ggept_filesize_extract(e, &fs);
						if (ret == GGEP_OK) {
							rc->size = fs;
						} else {
							g_warning("%s bad GGEP \"LF\" (dumping)",
								gmsg_infostr(&n->header));
							ext_dump(stderr, e, 1, "....", "\n", TRUE);
						}
					}
					break;
				case EXT_T_GGEP_LIME_XML:
					paylen = ext_paylen(e);
					if (!rc->xml && paylen > 0) {
						size_t len;
						gchar buf[4096];

						len = MIN((size_t) paylen, sizeof buf - 1);
						memcpy(buf, ext_payload(e), len);
						buf[len] = '\0';
						if (utf8_is_valid_string(buf)) {
							rc->xml = atom_str_get(buf);
							if (is_action_url_spam(buf, len)) {
								rs->status |= ST_URL_SPAM;
							}
						}
					}
					break;
				case EXT_T_GGEP_PATH:		/* Path */
					paylen = ext_paylen(e);
					if (!rc->path && paylen > 0) {
						size_t len;
						gchar buf[1024];

						len = MIN((size_t) paylen, sizeof buf - 1);
						memcpy(buf, ext_payload(e), len);
						buf[len] = '\0';
						rc->path = atom_str_get(buf);
					}
					break;
				case EXT_T_GGEP_CT:		/* Create Time */
					{
						time_t stamp;

						ret = ggept_ct_extract(e, &stamp);
						if (
							GGEP_OK == ret &&
							0x45185160 != stamp &&
							0x45186D80 != stamp
						) {
							rs->status |= ST_HAS_CT;
							rc->create_time = stamp;
						} else {
							if (
								GNET_PROPERTY(search_debug) > 3 ||
								GNET_PROPERTY(ggep_debug) > 3
							) {
								g_warning("%s bad GGEP \"CT\" (dumping)",
										gmsg_infostr(&n->header));
								ext_dump(stderr, e, 1, "....", "\n", TRUE);
							}
						}
					}
					break;
				case EXT_T_UNKNOWN_GGEP:	/* Unknown GGEP extension */
					if (
						GNET_PROPERTY(search_debug) > 3 ||
						GNET_PROPERTY(ggep_debug) > 3
					) {
						g_warning("%s unknown GGEP \"%s\" (dumping)",
							gmsg_infostr(&n->header), ext_ggep_id_str(e));
						ext_dump(stderr, e, 1, "....", "\n", TRUE);
					}
					break;
				case EXT_T_UNKNOWN:
					has_unknown = TRUE;
					if (ext_paylen(e) && ext_has_ascii_word(e)) {
						if (info->len)
							g_string_append(info, "; ");
						g_string_append_len(info,
							ext_payload(e), ext_paylen(e));
					}
					break;
				default:
					break;
				}
			}

			if (has_unknown) {
				if (GNET_PROPERTY(search_debug) > 2) {
					g_warning("%s hit record #%d/%d has unknown extensions!",
						gmsg_infostr(&n->header), nr, rs->num_recs);
					ext_dump(stderr, exv, exvcnt, "> ", "\n", TRUE);
					dump_hex(stderr, "Query Hit Tag", tag, taglen);
				}
			} else if (exvcnt == MAX_EXTVEC) {
				if (GNET_PROPERTY(search_debug) > 2) {
					g_warning("%s hit record #%d/%d has %d extensions!",
						gmsg_infostr(&n->header), nr, rs->num_recs, exvcnt);
					ext_dump(stderr, exv, exvcnt, "> ", "\n", TRUE);
					dump_hex(stderr, "Query Hit Tag", tag, taglen);
				}
			} else if (GNET_PROPERTY(search_debug) > 3) {
				g_message("%s hit record #%d/%d has %d extensions:",
					gmsg_infostr(&n->header), nr, rs->num_recs, exvcnt);
				ext_dump(stderr, exv, exvcnt, "> ", "\n", TRUE);
			}

			if (exvcnt)
				ext_reset(exv, MAX_EXTVEC);

			if (info->len)
				rc->tag = atom_str_get(info->str);

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

		/*
		 * Check the filename only if the record is not already marked as spam.
		 */
		if (
			0 == (SR_SPAM & rc->flags) &&
			spam_check_filename_and_size(rc->name, rc->size)
		) {
			rs->status |= ST_NAME_SPAM;
			set_flags(rc->flags, SR_SPAM);
		}

		rs->records = g_slist_prepend(rs->records, rc);
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
		size_t trailer_len = endptr - s;			/* Trailer length, starts at `s' */

		if (trailer_len >= 5) {
			unsigned open_data_size = peek_u8(&s[4]);

			if (trailer_len - 5 >= open_data_size)
				trailer = s;
		}

		if (trailer) {
			rs->vcode.u32 = peek_be32(trailer);
			vendor = vendor_get_name(rs->vcode.u32);
			if (vendor != NULL && is_vendor_known(rs->vcode)) {
				rs->status |= ST_KNOWN_VENDOR;
			}
		} else {
			if (GNET_PROPERTY(search_debug)) {
				g_warning(
					"UNKNOWN %lu-byte trailer at offset %lu in %s from %s "
					"(%u/%u records parsed)",
					(unsigned long) trailer_len,
					(unsigned long) (s - n->data),
					gmsg_infostr(&n->header),
					node_addr(n), (guint) nr, (guint) rs->num_recs);
			}
			if (GNET_PROPERTY(search_debug) > 1) {
				dump_hex(stderr, "Query Hit Data (non-empty UNKNOWN trailer?)",
					n->data, n->size);
				dump_hex(stderr, "UNKNOWN trailer part", s, trailer_len);
			}
		}
	}


	if (nr != rs->num_recs) {
        gnet_stats_count_dropped(n, MSG_DROP_BAD_RESULT);
		goto bad_packet;
    }

	/* We now have the GUID of the node */

	rs->guid = atom_guid_get(cast_to_guid_ptr_const(endptr));
	if (guid_eq(rs->guid, GNET_PROPERTY(servent_guid))) {
        gnet_stats_count_dropped(n, MSG_DROP_OWN_RESULT);
		goto bad_packet;		
	}

	/* Very funny */
	if (guid_eq(rs->guid, gnutella_header_get_muid(&n->header))) {
		gnet_stats_count_dropped(n, MSG_DROP_BAD_RESULT);
		goto bad_packet;		
	}

	if (guid_eq(rs->guid, &blank_guid)) {
		gnet_stats_count_dropped(n, MSG_DROP_BLANK_SERVENT_ID);
		goto bad_packet;		
	}

	if (
		trailer &&
		search_results_handle_trailer(n, rs, trailer, endptr - trailer)
	) {
        gnet_stats_count_dropped(n, MSG_DROP_BAD_RESULT);
		goto bad_packet;		
	}
	
	/*
	 * Now that we have the vendor, warn if the message has SHA1 errors.
	 * Then drop the packet!
	 */

	if (sha1_errors) {
		if (GNET_PROPERTY(search_debug)) g_warning(
				"%s from %s (via \"%s\" at %s) "
				"had %u SHA1 error%s over %u record%s",
				gmsg_infostr(&n->header), vendor ? vendor : "????",
				node_vendor(n), node_addr(n),
				sha1_errors, sha1_errors == 1 ? "" : "s",
				nr, nr == 1 ? "" : "s");
		gnet_stats_count_dropped(n, MSG_DROP_MALFORMED_SHA1);
		goto bad_packet;		/* Will drop this bad query hit */
	}

	/*
	 * If we have bad ALT locations, or ALT without hashes, warn but
	 * do not drop.
	 */

	if (alt_errors && GNET_PROPERTY(search_debug)) {
		g_warning(
				"%s from %s (via \"%s\" at %s) "
				"had %u ALT error%s over %u record%s",
				gmsg_infostr(&n->header), vendor ? vendor : "????",
				node_vendor(n), node_addr(n),
				alt_errors, alt_errors == 1 ? "" : "s",
				nr, nr == 1 ? "" : "s");
	}

	if (alt_without_hash && GNET_PROPERTY(search_debug)) {
		g_warning(
				"%s from %s (via \"%s\" at %s) "
				"had %u ALT extension%s with no hash over %u record%s",
				gmsg_infostr(&n->header), vendor ? vendor : "????",
				node_vendor(n), node_addr(n),
				alt_without_hash, alt_without_hash == 1 ? "" : "s",
				nr, nr == 1 ? "" : "s");
	}

	if (GNET_PROPERTY(search_debug) > 1) {
		if (seen_ggep_h && GNET_PROPERTY(search_debug) > 3)
			g_message("%s from %s used GGEP \"H\" extension",
					gmsg_infostr(&n->header), vendor ? vendor : "????");
		if (seen_ggep_alt && GNET_PROPERTY(search_debug) > 3)
			g_message("%s from %s used GGEP \"ALT\" extension",
					gmsg_infostr(&n->header), vendor ? vendor : "????");
		if (seen_bitprint && GNET_PROPERTY(search_debug) > 3)
			g_message("%s from %s used urn:bitprint",
					gmsg_infostr(&n->header), vendor ? vendor : "????");
		if (multiple_sha1)
			g_warning("%s from %s had records with multiple SHA1",
					gmsg_infostr(&n->header), vendor ? vendor : "????");
		if (multiple_alt)
			g_warning("%s from %s had records with multiple ALT",
					gmsg_infostr(&n->header), vendor ? vendor : "????");
	}

	{
		host_addr_t c_addr;

		g_string_free(info, TRUE);
		info = NULL;

		/*
		 * Prefer an UDP source IP for the country computation.
		 */

		c_addr = (rs->status & ST_UDP) ? rs->last_hop : rs->addr;
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

	if (
		T_0000 == rs->vcode.u32 ||
		(T_LIME == rs->vcode.u32 && !(ST_HAS_CT & rs->status))
	) {	
		/*
		 * If there are no timestamps, this is most-likely not from LimeWire.
		 * A vendor code is mandatory.
		 */
		rs->status |= ST_FAKE_SPAM;
	}

	if (has_dupe_spam(rs)) {
		rs->status |= ST_DUP_SPAM;
	}

	if ((ST_SPAM & ~(ST_URN_SPAM | ST_NAME_SPAM)) & rs->status) {
		GSList *sl;

		/*
		 * Spam other than listed URNs is never sent by innocent peers,
		 * thus mark all records of the set as spam.
		 */
		for (sl = rs->records; NULL != sl; sl = g_slist_next(sl)) {
			gnet_record_t *record = sl->data;
			set_flags(record->flags, SR_SPAM);
		}
	}

	return rs;

	/*
	 * Come here when we encounter bad packets (NUL chars not where expected,
	 * or missing).	The whole packet is ignored.
	 *				--RAM, 09/01/2001
	 */

  bad_packet:
	if (GNET_PROPERTY(search_debug) > 2) {
		g_warning(
			"BAD %s from %s (via \"%s\" at %s) -- %u/%u records parsed",
			 gmsg_infostr(&n->header), vendor ? vendor : "????",
			 node_vendor(n), node_addr(n), nr, rs->num_recs);
		if (GNET_PROPERTY(search_debug) > 1)
			dump_hex(stderr, "Query Hit Data (BAD)", n->data, n->size);
	}

	search_free_r_set(rs);
	g_string_free(info, TRUE);

	return NULL;				/* Forget set, comes from a bad node */
}

/**
 * Called when we get a query hit from an immediate neighbour.
 */
static void
update_neighbour_info(gnutella_node_t *n, gnet_results_set_t *rs)
{
	const gchar *vendor;
	guint32 old_weird = n->n_weird;

	g_assert(gnutella_header_get_hops(&n->header) == 1);

    vendor = vendor_get_name(rs->vcode.u32);

	if (n->attrs & NODE_A_QHD_NO_VTAG) {	/* Known to have no tag */
		if (vendor) {
			n->n_weird++;
			if (GNET_PROPERTY(search_debug) > 1) g_warning("[weird #%d] "
				"node %s (%s) had no tag in its query hits, now has %s in %s",
				n->n_weird,
				node_addr(n), node_vendor(n), vendor, gmsg_infostr(&n->header));
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
				"node %s (%s) had tag \"%s\" in its query hits, "
				"now has none in %s",
				n->n_weird, node_addr(n), node_vendor(n),
				vendor_code_to_string(n->vcode.u32),
				gmsg_infostr(&n->header));
		}
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
			vendor_code_to_string_buf(n->vcode.u32, vc_old, sizeof vc_old);
			vendor_code_to_string_buf(rs->vcode.u32, vc_new, sizeof vc_new);

			if (GNET_PROPERTY(search_debug) > 1) g_warning("[weird #%d] "
				"node %s (%s) moved from tag %4.4s to %4.4s in %s",
				n->n_weird, node_addr(n), node_vendor(n),
				vc_old, vc_new, gmsg_infostr(&n->header));
		}

		n->vcode = rs->vcode;
	} else {
		n->vcode.u32 = T_0000;
	}

	/*
	 * Save node's GUID.
	 */

	if (node_guid(n)) {
		if (!guid_eq(node_guid(n), rs->guid)) {
			n->n_weird++;
			if (GNET_PROPERTY(search_debug) > 1) {
				gchar guid_buf[GUID_HEX_SIZE + 1];

				guid_to_string_buf(rs->guid, guid_buf, sizeof guid_buf);
				g_warning("[weird #%d] "
					"Node %s (%s) has GUID %s but used %s in %s",
					n->n_weird, node_addr(n), node_vendor(n),
					guid_hex_str(node_guid(n)), guid_buf,
					gmsg_infostr(&n->header));
			}
		}
	} else {
		node_set_guid(n, rs->guid);
	}

	/*
	 * We don't declare any weirdness if the address in the results matches
	 * the socket's peer address.
	 *
	 * Otherwise, make sure the address is a private IP one, or that the hit
	 * has the "firewalled" bit.  Otherwise, the IP must match the one the
	 * servent thinks it has, which we know from its previous query hits
	 * with hops=0. If we never got a query hit from that servent, check
	 * against last IP we saw in pong.
	 */

	if (
		!(rs->status & ST_FIREWALL) &&		/* Hit not marked "firewalled" */
		!host_addr_equal(n->addr, rs->addr) &&	/* Not socket's address */
		host_addr_is_routable(rs->addr)
	) {
		if (
			(is_host_addr(n->gnet_qhit_addr) &&
			 	!host_addr_equal(n->gnet_qhit_addr, rs->addr)
				) ||
			(!is_host_addr(n->gnet_qhit_addr) &&
				is_host_addr(n->gnet_pong_addr) &&
				!host_addr_equal(n->gnet_pong_addr, rs->addr)
			)
		) {
			n->n_weird++;
			if (GNET_PROPERTY(search_debug) > 1) g_warning("[weird #%d] "
				"node %s (%s) advertised %s but now says Query Hits from %s",
				n->n_weird, node_addr(n), node_vendor(n),
				host_addr_to_string(is_host_addr(n->gnet_qhit_addr) ?
					n->gnet_qhit_addr : n->gnet_pong_addr),
				host_addr_port_to_string(rs->addr, rs->port));
		}
		n->gnet_qhit_addr = rs->addr;
	}

	if (GNET_PROPERTY(search_debug) > 3 && old_weird != n->n_weird)
		dump_hex(stderr, "Query Hit Data (weird)", n->data, n->size);
}

/**
 * Create a search request message for specified search.
 *
 * On success a walloc()ated message is returned. Use wfree() to release
 * the memory. The is can be derived from the header, add GTA_HEADER_SIZE.
 *
 * @returns NULL if we cannot build a suitable message (bad query string
 * containing only whitespaces, for instance).
 */
static gnutella_msg_search_t *
build_search_msg(search_ctrl_t *sch)
{
	static union {
		gnutella_msg_search_t data;
		gchar bytes[1024];
		guint64 align8;
	} msg;
	size_t size;
	guint16 flags;
	gboolean is_sha1_search;
	struct sha1 sha1;

	STATIC_ASSERT(25 == sizeof msg.data);
	size = sizeof msg.data;
	
    g_assert(sch != NULL);
    g_assert(sbool_get(sch->active));
	g_assert(!sbool_get(sch->frozen));
	g_assert(sch->muids);

	/* Use the first MUID on the list (the last one allocated) */
	{
		gnutella_header_t *header = gnutella_msg_search_header(&msg.data);
		guint8 hops;
		
		hops = GNET_PROPERTY(hops_random_factor) &&
			GNET_PROPERTY(current_peermode) != NODE_P_LEAF
			? random_value(GNET_PROPERTY(hops_random_factor))
			: 0;

		gnutella_header_set_muid(header, sch->muids->data);
		gnutella_header_set_function(header, GTA_MSG_SEARCH);
		gnutella_header_set_ttl(header, GNET_PROPERTY(my_ttl));
		gnutella_header_set_hops(header, hops);

		if (
			(guint32) gnutella_header_get_ttl(header) +
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
		host_addr_t addr;
		guint16 port;

		guid_oob_get_addr_port(
			gnutella_header_get_muid(gnutella_msg_search_header(&msg.data)),
			&addr, &port);

		if (is_my_address_and_port(addr, port))
			flags |= QUERY_F_OOB_REPLY;
	}

	gnutella_msg_search_set_flags(&msg.data, flags);
	
	/*
	 * Are we dealing with an URN search?
	 */

	is_sha1_search = urn_get_sha1(sch->query, &sha1);

	{	
		size_t len;

		len = strlen(sch->query);
		if (len + 1 >= sizeof msg.bytes - size) {
			g_warning("dropping too large query \"%s\"", sch->query);
			goto error;
		}
	
		if (is_sha1_search) {
			msg.bytes[size++] = '\\';
			msg.bytes[size++] = '\0';
			memcpy(&msg.bytes[size], sch->query, len);
			size += len;
		} else {
			size_t new_len;

			memcpy(&msg.bytes[size], sch->query, len);
			msg.bytes[size + len] = '\0';

			new_len = compact_query(&msg.bytes[size]);
			g_assert(new_len <= len);

			if (new_len == 0) {
				g_warning("dropping empty query \"%s\"", sch->query);
				goto error;
			}

			if (new_len < len) {
				len = new_len;
				if (GNET_PROPERTY(search_debug) > 1)
					g_message("compacted query \"%s\" into \"%s\"",
						sch->query, &msg.bytes[size]);
			}
			size += len + 1;
		}
	}

	if (QUERY_F_OOB_REPLY & flags) {
		ggep_stream_t gs;

		if (is_sha1_search) {
			/* As long as we have to use plain text hash queries instead
			 * of GGEP H, we need to add a separator between the hash
			 * and the following GGEP block.
			 */
			if (sizeof msg.bytes == size) {
				g_warning("dropping too large query \"%s\"", sch->query);
				goto error;
			}
			msg.bytes[size] = 0x1C; /* extension separator */
			size++;
		}

		ggep_stream_init(&gs, &msg.bytes[size], sizeof msg.bytes - size);

		/* TODO: We cannot emit empty queries with GGEP H attached because
		 *		 GTKG before 0.96.4 does not parse GGEP H in queries.
		 */
#if 0
		if (is_sha1_search) {
			const guint8 type = GGEP_H_SHA1;
			gboolean ok;

			ok = ggep_stream_begin(&gs, GGEP_NAME(H), 0) &&
				ggep_stream_write(&gs, &type, 1) &&
				ggep_stream_write(&gs, &sha1, sizeof sha1.data) &&
				ggep_stream_end(&gs);

			if (!ok) {
				g_warning("could not add GGEP \"H\" to query");
				goto error;
			}
		}
#endif

		/** 
		 * Indicate support for OOB v3.
		 * @see http://the-gdf.org/index.php?title=OutOfBandV3
		 */

		if (
			udp_active() &&
			!GNET_PROPERTY(is_udp_firewalled) &&
			host_is_valid(listen_addr(), socket_listen_port())
		) {
			/*
			 * Since our ultrapeers might not support OOB v3 and not understand
			 * GGEP "SO" either, only add this if we're not OOB proxied.
			 * Otherwise, we won't receive OOB results.
			 */
			if (!ggep_stream_pack(&gs, GGEP_NAME(SO), NULL, 0, 0)) {
				g_warning("could not add GGEP \"SO\" extension to query");
				goto error;
			}
		}

		size += ggep_stream_close(&gs);
	}

	if (size - GTA_HEADER_SIZE > GNET_PROPERTY(search_queries_forward_size)) {
		g_warning("not sending query \"%s\": larger than max query size (%d)",
			sch->query, GNET_PROPERTY(search_queries_forward_size));
		goto error;
	}

	gnutella_header_set_size(gnutella_msg_search_header(&msg.data),
		size - GTA_HEADER_SIZE);

	if (GNET_PROPERTY(search_debug) > 3)
		g_message("%squery \"%s\" message built with MUID %s",
			is_sha1_search ? "URN " : "", sch->query,
			guid_hex_str(gnutella_header_get_muid(
							gnutella_msg_search_header(&msg.data))));

	message_add(gnutella_header_get_muid(gnutella_msg_search_header(&msg.data)),
		GTA_MSG_SEARCH, NULL);

	return wcopy(&msg.bytes, size);

error:
	return NULL;
}

/**
 * Fill supplied query hash vector `qhv' with relevant word/SHA1 entries for
 * the given search.
 */
static void
search_qhv_fill(search_ctrl_t *sch, query_hashvec_t *qhv)
{
	word_vec_t *wovec;
	guint i;
	guint wocnt;

    g_assert(sch != NULL);
    g_assert(qhv != NULL);
	g_assert(GNET_PROPERTY(current_peermode) == NODE_P_ULTRA);

	qhvec_reset(qhv);

	if (is_strprefix(sch->query, "urn:sha1:")) {		/* URN search */
		qhvec_add(qhv, sch->query, QUERY_H_URN);
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
 * Create and send a search request packet
 *
 * @param sch DOCUMENT THIS!
 * @param n if NULL, we're "broadcasting" an initial search.  Otherwise, this
 * is the only node to which we should send the message.
 */
static void
search_send_packet(search_ctrl_t *sch, gnutella_node_t *n)
{
	gnutella_msg_search_t *msg;
	size_t size;

    g_assert(sch != NULL);
    g_assert(sbool_get(sch->active));
	g_assert(!sbool_get(sch->frozen));

	if (NULL == (msg = build_search_msg(sch)))
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

	if (n) {
		mark_search_sent_to_node(sch, n);
		gmsg_search_sendto_one(n, sch->search_handle, (gchar *) msg, size);
		goto cleanup;
	}

	/*
	 * If we're a leaf node, broadcast to all our ultra peers.
	 * If we're a regular node, broadcast to all peers.
	 *
	 * FIXME: Drop support for regular nodes after 0.95 --RAM, 2004-08-31.
	 */

	if (GNET_PROPERTY(current_peermode) != NODE_P_ULTRA) {
		mark_search_sent_to_connected_nodes(sch);
		gmsg_search_sendto_all(
			node_all_nodes(), sch->search_handle, (gchar *) msg, size);
		goto cleanup;
	}

	/*
	 * Enqueue search in global SQ for later dynamic querying dispatching.
	 */

	search_qhv_fill(sch, query_hashvec);
	sq_global_putq(sch->search_handle,
		gmsg_to_pmsg(msg, size), qhvec_clone(query_hashvec));

	/* FALL THROUGH */

cleanup:
	wfree(msg, size);
}

/**
 * Called when we connect to a new node and thus can send it our searches.
 *
 * @bug
 * FIXME: uses node_added which is a global variable in nodes.c. This
 * should instead be contained with the argument to this call.
 */
static void
node_added_callback(gpointer data)
{
	search_ctrl_t *sch = data;
	g_assert(node_added != NULL);
	g_assert(data != NULL);
    g_assert(sch != NULL);
    g_assert(sbool_get(sch->active));

	/*
	 * If we're in UP mode, we're using dynamic querying for our own queries.
	 */

	if (GNET_PROPERTY(current_peermode) == NODE_P_ULTRA)
		return;

	/*
	 * Send search to new node if not already done and if the search
	 * is still active.
	 */

	if (
        !search_already_sent_to_node(sch, node_added) &&
		!sbool_get(sch->frozen)
    ) {
		search_send_packet(sch, node_added);
	}
}

/**
 * Create a new muid and add it to the search's list of muids.
 *
 * Also record the direct mapping between this muid and the search into
 * the `search_by_muid' table.
 */
static void
search_add_new_muid(search_ctrl_t *sch, struct guid *muid)
{
	guint count;

	g_assert(NULL == g_hash_table_lookup(search_by_muid, muid));

	if (sch->muids) {		/* If this isn't the first muid -- requerying */
		search_reset_sent_nodes(sch);
		search_reset_sent_node_ids(sch);
	}

	sch->muids = g_slist_prepend(sch->muids, muid);
	g_hash_table_insert(search_by_muid, muid, sch);

	record_query_string(muid, sch->query);

	/*
	 * If we got more than MUID_MAX entries in the list, chop last items.
	 */

	count = g_slist_length(sch->muids);

	while (count-- > MUID_MAX) {
		GSList *last = g_slist_last(sch->muids);
		g_hash_table_remove(search_by_muid, last->data);
		wfree(last->data, GUID_RAW_SIZE);
		sch->muids = g_slist_remove_link(sch->muids, last);
		g_slist_free_1(last);
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
 * Called when the reissue timer for any search is triggered.
 *
 * The data given is the search to be reissued.
 */
static gboolean
search_reissue_timeout_callback(gpointer data)
{
	search_ctrl_t *sch = data;

	search_reissue(sch->search_handle);
	return TRUE;
}

static guint32
search_max_results_for_ui(void)
{
	return GNET_PROPERTY(search_max_results);
}

/**
 * Make sure a timer is created/removed after a search was started/stopped.
 */
static void
update_one_reissue_timeout(search_ctrl_t *sch)
{
	guint32 max_items;
	unsigned percent;
	gfloat factor;
	guint32 tm;

	g_assert(sch != NULL);
	g_assert(sbool_get(sch->active));

	if (sch->reissue_timeout_id > 0) {
		g_source_remove(sch->reissue_timeout_id);
		sch->reissue_timeout_id = 0;
	}

	/*
	 * When a search is frozen or the reissue_timout is zero, all we need
	 * to do is to remove the timer.
	 */

	if (sbool_get(sch->frozen) || sch->reissue_timeout == 0)
		return;

	/*
	 * Look at the amount of items we got for this search already.
	 * The more we have, the less often we retry to save network resources.
	 */
	max_items = search_max_results_for_ui();
	max_items = MAX(1, max_items);

	percent = sch->items * 100 / max_items;
	factor = (percent < 10) ? 1.0 :
		1.0 + (percent - 10) * (percent - 10) / 550.0;

	tm = (guint32) sch->reissue_timeout;
	tm = (guint32) (MAX(tm, SEARCH_MIN_RETRY) * factor);

	/*
	 * Otherwise we also add a new timer. If the search was stopped, this
	 * will restart the search, otherwise is will simply reset the timer
	 * and set a new timer with the searches's reissue_timeout.
	 */

	if (GNET_PROPERTY(search_debug) > 2)
		g_message("updating search \"%s\" with timeout %u.", sch->query, tm);

	sch->reissue_timeout_id = g_timeout_add(
		tm * 1000, search_reissue_timeout_callback, sch);
}

/**
 * Check whether search bearing the specified ID is still alive.
 */
static gboolean
search_alive(search_ctrl_t *sch, guint32 id)
{
	if (!g_hash_table_lookup(searches, sch))
		return FALSE;

	return sch->id == id;		/* In case it reused the same address */
}

#define CLOSED_SEARCH	0xffff

/**
 * Send an unsolicited "Query Status Response" to the specified node ID,
 * bearing the amount of kept results.  The 0xffff value is a special
 * marker to indicate the search was closed.
 */
static void
search_send_query_status(search_ctrl_t *sch,
	const node_id_t node_id, guint16 kept)
{
	struct gnutella_node *n;

	n = node_active_by_id(node_id);
	if (n == NULL)
		return;					/* Node disconnected already */

	if (GNET_PROPERTY(search_debug) > 1)
		g_message("SCH reporting %u kept results so far for \"%s\" to %s",
			kept, sch->query, node_addr(n));

	/*
	 * Workaround for older broken GTKG ultrapeers.  Remove about in 1 year,
	 * along with the NODE_A_NO_KEPT_ZERO flag..
	 *		--RAM, 2006-08-16
	 */

	if (kept == 0 && (n->attrs & NODE_A_NO_KEPT_ZERO))
		kept = 1;

	/*
	 * We use the first MUID in the list, i.e. the last one we used
	 * for sending out queries for that search.
	 */

	vmsg_send_qstat_answer(n, sch->muids->data, kept);
}


/**
 * Send an unsolicited "Query Status Response" to the specified node ID
 * about the results we kept so far for the relevant search.
 * -- hash table iterator callback
 */
static void
search_send_status(gpointer key, gpointer unused_value, gpointer udata)
{
	const node_id_t node_id = key;
	search_ctrl_t *sch = udata;
	guint16 kept;

	(void) unused_value;

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
	g_hash_table_foreach(sch->sent_node_ids, search_send_status, sch);
}

/**
 * Send an unsolicited "Query Status Response" to the specified node ID
 * informing it that the search was closed.
 * -- hash table iterator callback
 */
static void
search_send_closed(gpointer key, gpointer unused_value, gpointer udata)
{
	const node_id_t node_id = key;
	search_ctrl_t *sch = udata;

	(void) unused_value;
	search_send_query_status(sch, node_id, CLOSED_SEARCH);
}

/**
 * Tell our querying ultrapeers that the search is closed.
 */
static void
search_notify_closed(gnet_search_t sh)
{
    search_ctrl_t *sch = search_find_by_handle(sh);

	g_hash_table_foreach(sch->sent_node_ids, search_send_closed, sch);
}

/**
 * Signal to all search queues that search was closed.
 */
static void
search_dequeue_all_nodes(gnet_search_t sh)
{
	const GSList *sl;

	for (sl = node_all_nodes(); sl; sl = g_slist_next(sl)) {
		struct gnutella_node *n = (struct gnutella_node *) sl->data;
		squeue_t *sq = NODE_SQUEUE(n);

		if (sq)
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

	if (GNET_PROPERTY(current_peermode) == NODE_P_ULTRA)
		dq_search_closed(sh);
	else
		search_notify_closed(sh);
}

/***
 *** Public functions
 ***/

void
search_init(void)
{
	rs_zone = zget(sizeof(gnet_results_set_t), 1024);
	rc_zone = zget(sizeof(gnet_record_t), 1024);

	searches = g_hash_table_new(pointer_hash_func, NULL);
	search_by_muid = g_hash_table_new(guid_hash, guid_eq);
    search_handle_map = idtable_new();
	/* Max: 128 unique words / URNs! */
	query_hashvec = qhvec_alloc(QRP_HVEC_MAX);
	oob_reply_acks_init();
	query_muid_map_init();	
}

void
search_shutdown(void)
{
    while (sl_search_ctrl != NULL) {
		search_ctrl_t *sch = sl_search_ctrl->data;
		
        g_warning("force-closing search left over by GUI: %s", sch->query);
        search_close(sch->search_handle);
    }

    g_assert(idtable_ids(search_handle_map) == 0);

	g_hash_table_destroy(searches);
	searches = NULL;
	g_hash_table_destroy(search_by_muid);
	search_by_muid = NULL;
    idtable_destroy(search_handle_map);
    search_handle_map = NULL;
	qhvec_free(query_hashvec);

	zdestroy(rs_zone);
	zdestroy(rc_zone);
	rs_zone = rc_zone = NULL;

	oob_reply_acks_close();
	query_muid_map_close();
}

/**
 * This routine is called for each Query Hit packet we receive out of
 * a browse-host request, since we know the target search result, and
 * we don't need to bother with forwarding that message.
 */
void
search_browse_results(gnutella_node_t *n, gnet_search_t sh)
{
	gnet_results_set_t *rs;
	GSList *search = NULL;
	GSList *sl;

	rs = get_results_set(n, TRUE);
	if (rs == NULL)
		return;

	/*
	 * Dispatch the results as-is without any ignoring to the GUI, which
	 * will copy the information for its own perusal (and filtering).
	 */
	{
    	search_ctrl_t *sch = search_find_by_handle(sh);
		
		g_assert(sch != NULL);
		if (!sbool_get(sch->frozen))
			search = g_slist_prepend(search,
						GUINT_TO_POINTER(sch->search_handle));
	}

    /*
	 * We're also going to dispatch the results to all the opened passive
	 * searches, since they may have customized filters.
     */

	if (GNET_PROPERTY(browse_copied_to_passive)) {
		guint32 max_items = search_max_results_for_ui();

		for (sl = sl_passive_ctrl; sl != NULL; sl = g_slist_next(sl)) {
			search_ctrl_t *sch = sl->data;

			if (!sbool_get(sch->frozen) && sch->items < max_items)
				search = g_slist_prepend(search,
					GUINT_TO_POINTER(sch->search_handle));
		}
	}

	if (search) {
		search_check_results_set(rs);
		search_fire_got_results(search, rs);
		g_slist_free(search);
		search = NULL;
	}

    search_free_r_set(rs);
}

/**
 * This routine is called for each Query Hit packet we receive.
 *
 * @returns whether the message should be dropped, i.e. FALSE if OK.
 * If the message should not be dropped, `results' is filled with the
 * amount of results contained in the query hit.
 */
gboolean
search_results(gnutella_node_t *n, gint *results)
{
	gnet_results_set_t *rs;
	GSList *sl;
	gboolean drop_it = FALSE;
	gboolean forward_it = TRUE;
	GSList *selected_searches = NULL;
	guint32 max_items;

	g_assert(results != NULL);

	max_items = search_max_results_for_ui();

	/*
	 * We'll dispatch to non-frozen passive searches, and to the active search
	 * matching the MUID, if any and not frozen as well.
	 */

	for (sl = sl_passive_ctrl; sl != NULL; sl = g_slist_next(sl)) {
		search_ctrl_t *sch = sl->data;

		if (!sbool_get(sch->frozen) && sch->items < max_items)
			selected_searches = g_slist_prepend(selected_searches,
						GUINT_TO_POINTER(sch->search_handle));
	}

	{
		search_ctrl_t *sch;

		sch = g_hash_table_lookup(search_by_muid,
					gnutella_header_get_muid(&n->header));

		if (sch && !sbool_get(sch->frozen) && sch->items < max_items)
			selected_searches = g_slist_prepend(selected_searches,
				GUINT_TO_POINTER(sch->search_handle));
	}

	/*
	 * Parse the packet.
	 *
	 * If we're not going to dispatch it to any search or auto-download files
	 * based on the SHA1, the packet is only parsed for validation.
	 */

	rs = get_results_set(n, FALSE);
	if (rs == NULL) {
        /*
         * get_results_set takes care of telling the stats that
         * the message was dropped.
         */
		drop_it = TRUE;				/* Don't forward bad packets */
		goto final_cleanup;
	}

	g_assert(rs->num_recs > 0);
	*results = rs->num_recs;

	/*
	 * If we're handling a message from our immediate neighbour, grab the
	 * vendor code from the QHD.  This is useful for 0.4 handshaked nodes
	 * to determine and display their vendor ID.
	 */

	if (rs->hops == 0 && !NODE_IS_UDP(n))
		update_neighbour_info(n, rs);

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

	if (rs->status & (ST_SPAM | ST_EVIL | ST_HOSTILE)) {
		forward_it = FALSE;
		/* It's not really dropped, just not forwarded, count it anyway. */
		if (ST_SPAM & rs->status) {
			gnet_stats_count_dropped(n, MSG_DROP_SPAM);
		} else if (ST_EVIL & rs->status) {
			gnet_stats_count_dropped(n, MSG_DROP_EVIL);
		} else if (ST_HOSTILE & rs->status) {
			gnet_stats_count_dropped(n, MSG_DROP_HOSTILE_IP);
		}
	} else {
		if (
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
		 * Look for records that match entries in the download queue.
		 */

		if (GNET_PROPERTY(auto_download_identical))
			search_check_results_set(rs);

		/*
		 * Look for records whose SHA1 matches files we own and add
		 * those entries to the mesh.
		 */

		if (GNET_PROPERTY(auto_feed_download_mesh))
			dmesh_check_results_set(rs);
	}

    /*
     * Look for records that should be ignored.
     */

    if (
		selected_searches != NULL &&
		GNET_PROPERTY(search_handle_ignored_files) != SEARCH_IGN_DISPLAY_AS_IS
	) {
        for (sl = rs->records; sl != NULL; sl = g_slist_next(sl)) {
            gnet_record_t *rc = sl->data;
            enum ignore_val ival;

            ival = ignore_is_requested(rc->name, rc->size, rc->sha1);
            if (ival != IGNORE_FALSE) {
				if (
					GNET_PROPERTY(search_handle_ignored_files)
						== SEARCH_IGN_NO_DISPLAY
				)
					set_flags(rc->flags, SR_DONT_SHOW);
				else
					set_flags(rc->flags, SR_IGNORED);
			}
		}
	}

	/*
	 * Dispatch the results to the selected searches.
	 */

	if (selected_searches != NULL)
		search_fire_got_results(selected_searches, rs);

    search_free_r_set(rs);

final_cleanup:
	g_slist_free(selected_searches);

	return drop_it || !forward_it;
}

/**
 * Check whether we can send another query for this search.
 *
 * @returns TRUE if we can send, with the emitted counter incremented, or FALSE
 * if the query should just be ignored.
 */
gboolean
search_query_allowed(gnet_search_t sh)
{
    search_ctrl_t *sch = search_find_by_handle(sh);

	g_assert(sch);

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
 * @returns unique ID associated with search with given handle, and return
 * the address of the search object as well.
 */
guint32
search_get_id(gnet_search_t sh, gpointer *search)
{
    search_ctrl_t *sch = search_find_by_handle(sh);

	g_assert(sch);

	*search = sch;
	return sch->id;
}

/**
 * Notification from sq that a query for this search was sent to the
 * specified node ID.
 */
void
search_notify_sent(gpointer search, guint32 id, const node_id_t node_id)
{
	search_ctrl_t *sch = search;

	if (!search_alive(sch, id))
		return;

	mark_search_sent_to_node_id(sch, node_id);
}

/**
 * Check for alternate locations in the result set, and enqueue the downloads
 * if there are any.  Then free the alternate location from the record.
 */
static void
search_check_alt_locs(gnet_results_set_t *rs, gnet_record_t *rc, fileinfo_t *fi)
{
	gnet_host_vec_t *alt = rc->alt_locs;
	unsigned ignored = 0;
	gint i;

	g_assert(alt != NULL);

	for (i = gnet_host_vec_count(alt) - 1; i >= 0; i--) {
		struct gnutella_host host;
		host_addr_t addr;
		guint16 port;

		host = gnet_host_vec_get(alt, i);
		addr = gnet_host_get_addr(&host);
		port = gnet_host_get_port(&host);
		if (host_is_valid(addr, port)) {
			download_auto_new(rc->name,
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
    	const gchar *vendor = vendor_get_name(rs->vcode.u32);
		g_warning("ignored %u invalid alt-loc%s in hits from %s (%s)",
			ignored, ignored == 1 ? "" : "s",
			host_addr_port_to_string(rs->addr, rs->port),
			vendor ? vendor : "????");
	}
}

/**
 * Check a results_set for matching entries in the download queue,
 * and generate new entries if we find a match.
 */
static void
search_check_results_set(gnet_results_set_t *rs)
{
	GSList *sl;
	fileinfo_t *fi;

	for (sl = rs->records; sl; sl = g_slist_next(sl)) {
		gnet_record_t *rc = sl->data;

		if (rc->sha1) {
			const shared_file_t *sf = shared_file_by_sha1(rc->sha1);
			if (sf && SHARE_REBUILDING != sf) {
				if (shared_file_is_partial(sf)) {
            		set_flags(rc->flags, SR_PARTIAL);
				} else {
					set_flags(rc->flags, SR_SHARED);
				}
			} else {
				enum ignore_val reason;

				reason = ignore_is_requested(rc->name, rc->size, rc->sha1);
				switch (reason) {
				case IGNORE_FALSE:
					break;
				case IGNORE_SHA1:
				case IGNORE_NAMESIZE:
				case IGNORE_LIBRARY:
					set_flags(rc->flags, SR_OWNED);
					break;
				case IGNORE_SPAM:
					set_flags(rc->flags, SR_SPAM);
					break;
				case IGNORE_OURSELVES:
				case IGNORE_HOSTILE:
					/* These are for manual use and never returned */
					g_assert_not_reached();
					break;
				}
			}
		}

		fi = file_info_has_identical(rc->sha1, rc->size);
		if (fi) {
			guint32 flags = 0;
			
			flags |= (rs->status & ST_FIREWALL) ? SOCK_F_PUSH : 0;
			flags |= !host_is_valid(rs->addr, rs->port) ? SOCK_F_PUSH : 0;
			flags |= (rs->status & ST_TLS) ? SOCK_F_TLS : 0;
			
			download_auto_new(rc->name,
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
            set_flags(rc->flags, SR_DOWNLOADED);

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

/***
 *** Public functions.
 ***/

/**
 * Remove the search from the list of searches and free all
 * associated ressources.
 */
void
search_close(gnet_search_t sh)
{
    search_ctrl_t *sch = search_find_by_handle(sh);

	g_return_if_fail(sch);

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

	sl_search_ctrl = g_slist_remove(sl_search_ctrl, sch);

	if (sbool_get(sch->passive))
		sl_passive_ctrl = g_slist_remove(sl_passive_ctrl, sch);

	if (sbool_get(sch->browse) && sch->download != NULL)
		download_abort_browse_host(sch->download, sh);

    search_drop_handle(sch->search_handle);
	g_hash_table_remove(searches, sch);

	if (sbool_get(sch->active)) {
		g_hook_destroy_link(&node_added_hook_list, sch->new_node_hook);
		sch->new_node_hook = NULL;

		/* we could have stopped the search already, must test the ID */
		if (sch->reissue_timeout_id) {
			g_source_remove(sch->reissue_timeout_id);
			sch->reissue_timeout_id = 0;
		}

		if (sch->muids) {
			GSList *sl;

			for (sl = sch->muids; sl; sl = g_slist_next(sl)) {
				g_hash_table_remove(search_by_muid, sl->data);
				wfree(sl->data, GUID_RAW_SIZE);
			}
			g_slist_free(sch->muids);
			sch->muids = NULL;
		}

		search_free_sent_nodes(sch);
		search_free_sent_node_ids(sch);
	}

	atom_str_free_null(&sch->query);
	atom_str_free_null(&sch->name);
	wfree(sch, sizeof *sch);
}

/**
 * Allocate a new MUID for a search.
 *
 * @param initial indicates whether this is an initial query or a requery.
 *
 * @return a new MUID that can be wfree()'d when done.
 */
static struct guid * 
search_new_muid(gboolean initial)
{
	struct guid *muid;
	host_addr_t addr;
	gint i;

	muid = walloc(sizeof *muid);

	/*
	 * Determine whether this is going to be an OOB query, because we have
	 * to encode our IP port correctly right now, at MUID selection time.
	 *
	 * We allow them to change their mind on `send_oob_queries', as we're not
	 * testing that flag yet, but if they allow UDP, and have a valid IP,
	 * we can encode an OOB-compatible MUID.  Likewise, we ignore the
	 * `is_udp_firewalled' yet, as this can change between now and the time
	 * we emit the query.
	 */

	addr = listen_addr();

	for (i = 0; i < 100; i++) {
		if (
			udp_active() &&
			NET_TYPE_IPV4 == host_addr_net(addr) &&
			host_addr_is_routable(addr)
		)
			guid_query_oob_muid(muid, addr, socket_listen_port(), initial);
		else
			guid_query_muid(muid, initial);

		if (NULL == g_hash_table_lookup(search_by_muid, muid))
			return muid;
	}

	g_error("random number generator not random enough");	/* Sorry */

	return NULL;
}

/**
 * @return whether search has expired.
 */
static gboolean
search_expired(const search_ctrl_t *sch)
{
	time_t ct;
	guint lt;

	g_assert(sch);
	
	ct = sch->create_time;			/* In local (kernel) time */
	lt = 3600U * sch->lifetime;

	if (lt) {
		time_delta_t d;

		d = delta_time(tm_time(), ct);
		d = MAX(0, d);
		return UNSIGNED(d) >= lt;
	}
	return FALSE;
}

/**
 * Force a reissue of the given search. Restart reissue timer.
 */
void
search_reissue(gnet_search_t sh)
{
    search_ctrl_t *sch = search_find_by_handle(sh);
	struct guid *muid;

	g_return_if_fail(!sbool_get(sch->frozen));

	if (sbool_get(sch->local)) {
		search_locally(sh, sch->query);
		return;
	}

	g_return_if_fail(sbool_get(sch->active));

	/*
	 * If the search has expired, disable any further invocation.
	 */

	if (search_expired(sch)) {
		if (GNET_PROPERTY(search_debug))
			g_message("expired search \"%s\" (queries broadcasted: %d)",
				sch->query, sch->query_emitted);
		sch->frozen = sbool_set(TRUE);
		goto done;
	}

	if (GNET_PROPERTY(search_debug))
		g_message("reissuing search \"%s\" (queries broadcasted: %d)",
			sch->query, sch->query_emitted);

	muid = search_new_muid(FALSE);

	sch->query_emitted = 0;
	search_add_new_muid(sch, muid);
	search_send_packet_all(sch);

done:
	update_one_reissue_timeout(sch);
	search_status_changed(sch->search_handle);
}

/**
 * Set the reissue timeout of a search.
 */
void
search_set_reissue_timeout(gnet_search_t sh, guint32 timeout)
{
    search_ctrl_t *sch = search_find_by_handle(sh);

    g_assert(sch != NULL);
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
guint32
search_get_reissue_timeout(gnet_search_t sh)
{
    search_ctrl_t *sch = search_find_by_handle(sh);

    g_assert(sch != NULL);

    return sch->reissue_timeout;
}

/**
 * Get the initial lifetime (in hours) of a search.
 */
guint
search_get_lifetime(gnet_search_t sh)
{
    search_ctrl_t *sch = search_find_by_handle(sh);

    g_assert(sch != NULL);

    return sch->lifetime;
}

/**
 * Get the create time of a search.
 */
time_t
search_get_create_time(gnet_search_t sh)
{
    search_ctrl_t *sch = search_find_by_handle(sh);

    g_assert(sch != NULL);

    return sch->create_time;
}

/**
 * Set the create time of a search.
 */
void
search_set_create_time(gnet_search_t sh, time_t t)
{
    search_ctrl_t *sch = search_find_by_handle(sh);

    g_assert(sch != NULL);

	sch->create_time = t;
}

/**
 * Create a new suspended search and return a handle which identifies it.
 *
 * @param query				an UTF-8 encoded query string.
 * @param create_time		no document.
 * @param lifetime			no document.
 * @param flags				option flags for the search.
 * @param reissue_timeout	delay in seconds before requerying.
 *
 * @return	SEARCH_NEW_SUCCESS on success
 *			SEARCH_NEW_TOO_LONG if too long,
 *			SEARCH_NEW_TOO_SHORT if too short,
 *			SEARCH_NEW_INVALID_URN if the URN was unparsable.
 */
enum search_new_result
search_new(gnet_search_t *ptr, const gchar *query,
	time_t create_time, guint lifetime, guint32 reissue_timeout, flag_t flags)
{
	const gchar *endptr;
	search_ctrl_t *sch;
	gchar *qdup;
	gint result;

	g_assert(ptr);
	g_assert(utf8_is_valid_string(query));
	
	/*
	 * Canonicalize the query we're sending.
	 */

	if (NULL != (endptr = is_strprefix(query, "urn:sha1:"))) {
		if (SHA1_BASE32_SIZE != strlen(endptr) || !urn_get_sha1(query, NULL)) {
			g_warning("Rejected invalid urn:sha1 search");
			qdup = NULL;
			result = SEARCH_NEW_INVALID_URN;
			goto failure;
		}
		qdup = g_strdup(query);
	} else if (
		!(flags & (SEARCH_F_LOCAL | SEARCH_F_BROWSE | SEARCH_F_PASSIVE))
	) {
		size_t byte_count;

		qdup = UNICODE_CANONIZE(query);
		g_assert(qdup != query);
		byte_count = compact_query(qdup);

		if (byte_count < MIN_SEARCH_TERM_BYTES) {
			if (GNET_PROPERTY(search_debug) > 1) {
				g_warning("Rejected too short query string: \"%s\"", qdup);
			}
			result = SEARCH_NEW_TOO_SHORT;
			goto failure;
		} else if (
			byte_count > MAX_SEARCH_TERM_BYTES ||
			utf8_char_count(qdup) > MAX_SEARCH_TERM_CHARS
		) {
			if (GNET_PROPERTY(search_debug) > 1) {
				g_warning("Rejected too long query string: \"%s\"", qdup);
			}
			result = SEARCH_NEW_TOO_LONG;
			goto failure;
		}
	} else {
		qdup = g_strdup(query);
	}

	sch = walloc0(sizeof *sch);

	sch->search_handle = search_request_handle(sch);
	sch->id = search_id++;

	g_hash_table_insert(searches, sch, GINT_TO_POINTER(1));

	sch->name = atom_str_get(query);
	sch->query = atom_str_get(qdup);
	sch->frozen = sbool_set(TRUE);
	sch->create_time = create_time;
	sch->lifetime = lifetime;

	G_FREE_NULL(qdup);

	sch->browse = sbool_set(flags & SEARCH_F_BROWSE);
	sch->local = sbool_set(flags & SEARCH_F_LOCAL);
	sch->passive = sbool_set(flags & SEARCH_F_PASSIVE);
	sch->active = sbool_set(
			0 == (flags & (SEARCH_F_BROWSE|SEARCH_F_LOCAL|SEARCH_F_PASSIVE)));

	if (sbool_get(sch->active)) {
		sch->new_node_hook = g_hook_alloc(&node_added_hook_list);
		sch->new_node_hook->data = sch;
		sch->new_node_hook->func = node_added_callback;
		g_hook_prepend(&node_added_hook_list, sch->new_node_hook);

		if (reissue_timeout != 0 && reissue_timeout < SEARCH_MIN_RETRY)
			reissue_timeout = SEARCH_MIN_RETRY;
		sch->reissue_timeout = reissue_timeout;

		sch->sent_nodes =
			g_hash_table_new(sent_node_hash_func, sent_node_compare);
		sch->sent_node_ids = g_hash_table_new(node_id_hash, node_id_eq_func);
	}

	sl_search_ctrl = g_slist_prepend(sl_search_ctrl, sch);

	if (sbool_get(sch->passive))
		sl_passive_ctrl = g_slist_prepend(sl_passive_ctrl, sch);

	*ptr = sch->search_handle;
	return SEARCH_NEW_SUCCESS;

failure:
	G_FREE_NULL(qdup);
	*ptr = -1;
	return result;
}

/**
 * The GUI updates us on the amount of items displayed in the search.
 */
void
search_update_items(gnet_search_t sh, guint32 items)
{
    search_ctrl_t *sch = search_find_by_handle(sh);

	sch->items = items;
}

/**
 * The filtering side lets us know the amount of items we "kept", which
 * are either things we display to the user or entries we used for
 * auto-download.
 */
void
search_add_kept(gnet_search_t sh, guint32 kept)
{
    search_ctrl_t *sch = search_find_by_handle(sh);

	sch->kept_results += kept;

	if (GNET_PROPERTY(search_debug) > 1)
		g_message("SCH GUI reported %u new kept results for \"%s\", has %u now",
			kept, sch->query, sch->kept_results);

	/*
	 * If we're a leaf node, notify our dynamic query managers (the ultranodes
	 * to which we're connected) about the amount of results we got so far.
	 */

	if (
		!sbool_get(sch->active) ||
		GNET_PROPERTY(current_peermode) != NODE_P_LEAF
	)
		return;

	search_update_results(sch);
}

/**
 * Start a newly created start or resume stopped search.
 */
void
search_start(gnet_search_t sh)
{
    search_ctrl_t *sch = search_find_by_handle(sh);

    g_assert(sbool_get(sch->frozen));/* Coming from search_new(), or resuming */

    sch->frozen = sbool_set(FALSE);

    if (sbool_get(sch->active)) {
		/*
		 * If we just created the search with search_new(), there will be
		 * no message ever sent, and sch->muids will be NULL.
		 */

		if (sch->muids == NULL) {
			struct guid *muid;

			muid = search_new_muid(TRUE);
			search_add_new_muid(sch, muid);
			search_send_packet_all(sch);		/* Send initial query */
		}
        update_one_reissue_timeout(sch);
	}
	search_status_changed(sch->search_handle);
}

/**
 * Stop search. Cancel reissue timer and don't return any results anymore.
 */
void
search_stop(gnet_search_t search_handle)
{
    search_ctrl_t *sch = search_find_by_handle(search_handle);

    g_assert(sch != NULL);
    g_assert(!sbool_get(sch->frozen));

    sch->frozen = sbool_set(TRUE);

    if (sbool_get(sch->active)) {
		update_one_reissue_timeout(sch);
	}
	search_status_changed(sch->search_handle);
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
gboolean
search_get_kept_results(const struct guid *muid, guint32 *kept)
{
	search_ctrl_t *sch;

	sch = g_hash_table_lookup(search_by_muid, muid);

	g_assert(sch == NULL || sbool_get(sch->active)); /* No MUID if not active */

	if (sch == NULL)
		return FALSE;

	if (sbool_get(sch->frozen)) {
		if (GNET_PROPERTY(search_debug))
			g_message("Ignoring results because search is stopped");
		return FALSE;
	}

	if (GNET_PROPERTY(search_debug) > 1)
		g_message("SCH reporting %u kept results for \"%s\"",
			sch->kept_results, sch->query);

	*kept = sch->kept_results;
	return TRUE;
}

/**
 * @returns amount of hits kept by the search, identified by its handle
 */
guint32
search_get_kept_results_by_handle(gnet_search_t sh)
{
    search_ctrl_t *sch = search_find_by_handle(sh);

	g_assert(sch);

	return sch->kept_results;
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
 */
void
search_oob_pending_results(
	gnutella_node_t *n, const struct guid *muid, gint hits,
	gboolean udp_firewalled, gboolean secure)
{
	struct array token_opaque;
	guint32 token;
	guint32 kept;
	unsigned ask;

	g_assert(NODE_IS_UDP(n));
	g_assert(hits > 0);

	if (secure) {
		token = random_u32();
		token_opaque = array_init(&token, sizeof token);
	} else {
		token = 0;
		token_opaque = zero_array;
	}

	/*
	 * Locate the search bearing this MUID and get the amount of results
	 * we got so far during this query.  If the search is unknown, drop
	 * indication.
	 */

	if (!search_get_kept_results(muid, &kept)) {

		/*
		 * Maybe it's an OOB-proxied search?
		 */

		if (
			GNET_PROPERTY(proxy_oob_queries) &&
			oob_proxy_pending_results(n, muid, hits, udp_firewalled,
				&token_opaque)
		) {
			goto record_token;	
		}

		if (GNET_PROPERTY(search_debug))
			g_warning("got OOB indication of %d hit%s for unknown search %s",
				hits, hits == 1 ? "" : "s", guid_hex_str(muid));

		if (GNET_PROPERTY(search_debug) > 3)
			gmsg_log_bad(n, "unexpected OOB hit indication");

		gnet_stats_count_dropped(n, MSG_DROP_UNEXPECTED);
		return;
	}

	if (GNET_PROPERTY(search_debug) || GNET_PROPERTY(udp_debug))
		g_message("has %d pending OOB hit%s for search %s at %s",
			hits, hits == 1 ? "" : "s", guid_hex_str(muid), node_addr(n));

	/*
	 * If we got more than 15% of our maximum amount of shown results,
	 * then we have a very popular query here.  We don't really need
	 * to get more results, ignore.
	 */

	if (kept > search_max_results_for_ui() * 0.15) {
		if (GNET_PROPERTY(search_debug))
			g_message("ignoring %d OOB hit%s for search %s (already got %u)",
				hits, hits == 1 ? "" : "s", guid_hex_str(muid), kept);
		return;
	}

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


	vmsg_send_oob_reply_ack(n, muid, ask, &token_opaque);

record_token:
	oob_reply_ack_record(muid, n->addr, n->port, token);
}

const gchar *
search_query(gnet_search_t sh)
{
    search_ctrl_t *sch = search_find_by_handle(sh);

    g_assert(sch != NULL);
    g_assert(sch->name != NULL);

    return sch->name;
}

gboolean
search_is_frozen(gnet_search_t sh)
{
    search_ctrl_t *sch = search_find_by_handle(sh);

    g_assert(sch != NULL);

    return sbool_get(sch->frozen);
}

gboolean
search_is_passive(gnet_search_t sh)
{
    search_ctrl_t *sch = search_find_by_handle(sh);

    g_assert(sch != NULL);

    return sbool_get(sch->passive);
}

gboolean
search_is_active(gnet_search_t sh)
{
    search_ctrl_t *sch = search_find_by_handle(sh);

    g_assert(sch != NULL);

    return sbool_get(sch->active);
}

gboolean
search_is_browse(gnet_search_t sh)
{
    search_ctrl_t *sch = search_find_by_handle(sh);

    g_assert(sch != NULL);

    return sbool_get(sch->browse);
}

gboolean
search_is_expired(gnet_search_t sh)
{
    search_ctrl_t *sch = search_find_by_handle(sh);

    g_assert(sch != NULL);

    return search_expired(sch);
}

gboolean
search_is_local(gnet_search_t sh)
{
    search_ctrl_t *sch = search_find_by_handle(sh);

    g_assert(sch != NULL);

    return sbool_get(sch->local);
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
 *
 * @return	TRUE if we successfully initialized the download layer.
 */
gboolean
search_browse(gnet_search_t sh,
	const gchar *hostname, host_addr_t addr, guint16 port,
	const struct guid *guid, const gnet_host_vec_t *proxies, guint32 flags)
{
    search_ctrl_t *sch = search_find_by_handle(sh);

    g_assert(sch != NULL);
	g_assert(sbool_get(sch->browse));
	g_assert(!sbool_get(sch->frozen));
	g_assert(sch->download == NULL);

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

    g_assert(sch != NULL);
	g_assert(sbool_get(sch->browse));
	g_assert(sch->download == d);

	sch->download = NULL;
	if (!sbool_get(sch->frozen)) {
		search_stop(sch->search_handle);
		search_status_changed(sch->search_handle);
	}
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
		gint hcnt;

		/*
		 * SHA1 is available, look at the known alternate locations we have.
		 */

		atom_sha1_change(&rc->sha1, shared_file_sha1(sf));
		atom_tth_change(&rc->tth, shared_file_tth(sf));
		hcnt = dmesh_fill_alternate(rc->sha1, hvec, G_N_ELEMENTS(hvec));

		/*
		 * Propagate them to the results so that they can see how many entries
		 * they have in the mesh for each shared file, up to a maximum of
		 * LOCAL_MAX_ALT entries.
		 */

		if (hcnt) {
			rc->alt_locs = gnet_host_vec_create(hvec, hcnt);
		}
	}

	if (shared_file_is_partial(sf)) {
   		set_flags(rc->flags, SR_PARTIAL);
	} else {
		set_flags(rc->flags, SR_SHARED);
	}
	rc->file_index = shared_file_index(sf);
	rc->size = shared_file_size(sf);
	rc->name = atom_str_get(shared_file_name_nfc(sf));
	if (shared_file_relative_path(sf)) {
		rc->path = atom_str_get(shared_file_relative_path(sf));
	}
	rc->tag = atom_str_get(shared_file_path(sf));

	/* FIXME: Create time != modification time */
	rc->create_time = shared_file_modification_time(sf);
	rs->records = g_slist_prepend(rs->records, rc);
	rs->num_recs++;
}

gboolean
search_locally(gnet_search_t sh, const gchar *query)
{
	gnet_results_set_t *rs;
    search_ctrl_t *sch;
	shared_file_t *sf;
	regex_t *re;
	gint error;

    g_assert(query);

   	sch = search_find_by_handle(sh);
    g_assert(sch != NULL);
	g_assert(!sbool_get(sch->browse));
	g_assert(!sbool_get(sch->frozen));
	g_assert(sbool_get(sch->local));
	g_assert(sch->download == NULL);

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
		if (error) {
			goto done;
		}
	} else {
		sf = NULL;
		re = walloc(sizeof *re);
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
		const GSList *nodes = node_push_proxies();

		if (nodes) {
			struct gnutella_node *n = nodes->data;

			rs->proxies = gnet_host_vec_alloc();
			gnet_host_vec_add(rs->proxies, n->proxy_addr, n->proxy_port);
		}
	}

	if (sf) {
		search_add_local_file(rs, sf);
	} else {
		guint num_files, idx;

		num_files = MIN((guint) -1, shared_files_scanned());
		for (idx = 1; idx > 0 && idx <= num_files; idx++) {
			sf = shared_file(idx);
			if (!sf) {
				continue;
			} else if (SHARE_REBUILDING == sf) {
				break;
			} else if (re) {
				const gchar *name, *path;
				gchar *buf = NULL;
				size_t buf_size = 0;
				int ret;
				
				name = shared_file_name_nfc(sf);
				path = shared_file_relative_path(sf);
				if (path) {
					buf_size = w_concat_strings(&buf,
									path, "/", name, (void *) 0);
					name = buf;
				}
				ret = regexec(re, name, 0, NULL, 0);
				WFREE_NULL(buf, buf_size);
				if (ret) {
					continue;
				}
			}
			search_add_local_file(rs, sf);
		}
	}

	if (rs->records) {	
		GSList *search;
		
		rs->status |= ST_PARSED_TRAILER;	/* Avoid <unparsed> in the GUI */
		search = g_slist_prepend(NULL, GUINT_TO_POINTER(sch->search_handle));
		search_fire_got_results(search, rs);	/* Dispatch browse results */
		g_slist_free(search);
		search = NULL;
	}
    search_free_r_set(rs);

done:
	if (re) {
		regfree(re);
		wfree(re, sizeof *re);
	}
	return !error;
}

/**
 * Handle magnet searches, launching Gnutella searches as appropriate.
 */
guint
search_handle_magnet(const gchar *url)
{
	struct magnet_resource *res;
	guint n_searches = 0;

	res = magnet_parse(url, NULL);
	if (res) {
		GSList *sl;

		for (sl = res->searches; sl != NULL; sl = g_slist_next(sl)) {
			const gchar *query;

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

			sha1_to_urn_string_buf(res->sha1, urn_buf, sizeof urn_buf);
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

static void
search_request_listener_emit(
	query_type_t type, const gchar *query, const host_addr_t addr, guint16 port)
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
	GHashTable *shared_files;
	GSList *files;				/**< List of shared_file_t that match */
	gint found;
};

/**
 * Create new query context.
 */
static struct query_context *
share_query_context_make(void)
{
	struct query_context *ctx;

	ctx = walloc(sizeof *ctx);
	/* Uses direct hashing */
	ctx->shared_files = g_hash_table_new(pointer_hash_func, NULL);
	ctx->files = NULL;
	ctx->found = 0;

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

	g_hash_table_destroy(ctx->shared_files);
	wfree(ctx, sizeof *ctx);
}

/**
 * Check if a given shared_file has been added to the QueryHit.
 *
 * @return TRUE if the shared_file is in the QueryHit already, FALSE otherwise
 */
static inline gboolean
shared_file_already_found(struct query_context *ctx, const shared_file_t *sf)
{
	return NULL != g_hash_table_lookup(ctx->shared_files, sf);
}

/**
 * Add the shared_file to the set of files already added to the QueryHit.
 */
static inline void
shared_file_mark_found(struct query_context *ctx, const shared_file_t *sf)
{
	gm_hash_table_insert_const(ctx->shared_files, sf, sf);
}

/**
 * Invoked for each new match we get.
 */
static void
got_match(gpointer context, gpointer data)
{
	struct query_context *qctx = context;
	shared_file_t *sf = data;

	shared_file_check(sf);
	/* Cannot match partially downloaded files */
	g_assert(!shared_file_is_partial(sf));

	/*
	 * Don't insert duplicates (possible when matching both by SHA1 and name).
	 */

	if (!shared_file_already_found(qctx, sf)) {
		shared_file_mark_found(qctx, sf);
		qctx->files = g_slist_prepend(qctx->files, shared_file_ref(sf));
		qctx->found++;
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
compact_query_utf8(gchar *search)
{
	gchar *s;
	gchar *word = NULL, *p;
	size_t word_length = 0;	/* length in bytes, not characters */

#define APPEND_WORD()								\
do {												\
	/* Append a space unless it's the first word */	\
	if (p != search) {								\
		if (*p != ' ')								\
			*p = ' ';								\
		p++;										\
	}												\
	if (p != word)									\
		memmove(p, word, word_length);				\
	p += word_length;								\
} while (0)

	if (GNET_PROPERTY(share_debug) > 4)
		g_message("original: [%s]", search);

	word = is_ascii_blank(*search) ? NULL : search;
	p = s = search;
	while ('\0' != *s) {
		guint clen;

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

	if (GNET_PROPERTY(share_debug) > 4)
		g_message("mangled:  [%s]", search);

	/* search does no longer contain unnecessary whitespace */
	return p - search;
}

/**
 * Determine whether the given string is UTF-8 encoded.
 * If query starts with a BOM mark, skip it and set `retoff' accordingly.
 *
 * @returns TRUE if the string is valid UTF-8, FALSE otherwise.
 */
static gboolean 
query_utf8_decode(const gchar *text, guint *retoff)
{
	const gchar *p;

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
compact_query(gchar *search)
{
	size_t mangled_search_len, orig_len = strlen(search);
	guint offset;			/* Query string start offset */

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
 * Remove the OOB delivery flag by patching the query message inplace.
 */
void
query_strip_oob_flag(const gnutella_node_t *n, gchar *data)
{
	guint16 flags;

	flags = peek_be16(data) & ~QUERY_F_OOB_REPLY;
	poke_be16(data, flags);

	gnet_stats_count_general(GNR_OOB_QUERIES_STRIPPED, 1);

	if (GNET_PROPERTY(query_debug) > 2 || GNET_PROPERTY(oob_proxy_debug) > 2)
		g_message(
			"QUERY %s from node %s <%s>: removed OOB delivery (flags = 0x%x)",
			guid_hex_str(gnutella_header_get_muid(&n->header)),
				node_addr(n), node_vendor(n), flags);
}

/**
 * Set the OOB delivery flag by patching the query message inplace.
 */
void
query_set_oob_flag(const gnutella_node_t *n, gchar *data)
{
	guint16 flags;

	flags = peek_be16(data) | QUERY_F_OOB_REPLY | QUERY_F_MARK;
	poke_be16(data, flags);

	if (GNET_PROPERTY(query_debug))
		g_message(
			"QUERY %s from node %s <%s>: set OOB delivery (flags = 0x%x)",
			guid_hex_str(gnutella_header_get_muid(&n->header)),
			node_addr(n), node_vendor(n), flags);
}


/**
 * Preprocesses searches requests (from others nodes)
 *
 * @return TRUE if the query should be discarded, FALSE if everything was OK.
 */
gboolean
search_request_preprocess(struct gnutella_node *n)
{
	static const gchar qtrax2_con[] = "QTRAX2_CONNECTION";
	static gchar stmp_1[4096];
	guint16 flags;
	gchar *search;
	size_t search_len;
	gboolean skip_file_search = FALSE;
	struct {
		struct sha1 sha1;
		gboolean matched;
	} exv_sha1[MAX_EXTVEC];
	struct sha1 *last_sha1_digest = NULL;
	gint exv_sha1cnt = 0;
	guint offset = 0;			/**< Query string start offset */
	gboolean oob;		/**< Wants out-of-band query hit delivery? */

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
	search_len = clamp_strlen(search, n->size - 2);
	if (search_len >= n->size - 2U) {
		g_assert(n->data[n->size - 1] != '\0');
		if (GNET_PROPERTY(share_debug))
			g_warning("query (hops=%u, ttl=%u) had no NUL (%d byte%s)",
				gnutella_header_get_hops(&n->header),
				gnutella_header_get_ttl(&n->header),
				n->size - 2,
				n->size == 3 ? "" : "s");
		if (GNET_PROPERTY(share_debug) > 4)
			dump_hex(stderr, "Query Text", search, MIN(n->size - 2, 256));

		gnet_stats_count_dropped(n, MSG_DROP_QUERY_NO_NUL);
		goto drop;		/* Drop the message! */
	}

	/* We can now use `search' safely as a C string: it embeds a NUL */

	search_request_listener_emit(QUERY_STRING, search, n->addr, n->port);

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

	flags = peek_be16(n->data);
	if (!(flags & QUERY_F_MARK)) {
		gnet_stats_count_dropped(n, MSG_DROP_ANCIENT_QUERY);
		goto drop;		/* Drop the message! */
	}

	/*
	 * Drop the "QTRAX2_CONNECTION" queries as being "overhead".
	 */
	if (
		search_len >= CONST_STRLEN(qtrax2_con) &&
		is_strprefix(search, qtrax2_con)
	) {
		gnet_stats_count_dropped(n, MSG_DROP_QUERY_OVERHEAD);
		goto drop;		/* Drop the message! */
	}

	/*
	 * Look whether we're facing an UTF-8 query.
	 */

	if (!query_utf8_decode(search, &offset)) {
		gnet_stats_count_dropped(n, MSG_DROP_MALFORMED_UTF_8);
		goto drop;					/* Drop message! */
	}

	/*
	 * Compact query, if requested and we're going to relay that message.
	 */

	if (
		GNET_PROPERTY(gnet_compact_query) &&
		gnutella_header_get_ttl(&n->header) &&
		GNET_PROPERTY(current_peermode) != NODE_P_LEAF
	) {
		size_t mangled_search_len;

		if (!is_ascii_string(search))
			gnet_stats_count_general(GNR_QUERY_UTF8, 1);

		/*
		 * Compact the query, offsetting from the start as needed in case
		 * there is a leading BOM (our UTF-8 decoder does not allow BOM
		 * within the UTF-8 string, and rightly I think: that would be pure
		 * gratuitous bloat).
		 */

		mangled_search_len = compact_query_utf8(&search[offset]);

		g_assert(mangled_search_len <= search_len - offset);

		if (mangled_search_len != search_len - offset) {
			gnet_stats_count_general(GNR_QUERY_COMPACT_COUNT, 1);
			gnet_stats_count_general(GNR_QUERY_COMPACT_SIZE,
				search_len - offset - mangled_search_len);
		}

		/*
		 * Need to move the trailing data forward and adjust the
		 * size of the packet.
		 */

		g_memmove(
			&search[offset + mangled_search_len], /* new end of query string */
			&search[search_len],                  /* old end of query string */
			n->size - (search - n->data) - search_len); /* trailer len */

		n->size -= search_len - offset - mangled_search_len;
		gnutella_header_set_size(&n->header, n->size);
		search_len = mangled_search_len + offset;

		g_assert('\0' == search[search_len]);
	}

	/*
	 * If there is extra data after the first NUL, fill the extension vector.
	 */

	if (search_len + 3 != n->size) {
		extvec_t exv[MAX_EXTVEC];
		gint i, exvcnt;
		size_t extra;
		gboolean drop_it = FALSE;

	   	extra = n->size - 3 - search_len;		/* Amount of extra data */
		ext_prepare(exv, MAX_EXTVEC);
		exvcnt = ext_parse(search + search_len + 1, extra, exv, MAX_EXTVEC);

		if (exvcnt == MAX_EXTVEC) {
			g_warning("%s has %d extensions!",
				gmsg_infostr(&n->header), exvcnt);
			if (GNET_PROPERTY(share_debug))
				ext_dump(stderr, exv, exvcnt, "> ", "\n", TRUE);
			if (GNET_PROPERTY(share_debug) > 1)
				dump_hex(stderr, "Query", search, n->size - 2);
		}

		if (exvcnt && GNET_PROPERTY(share_debug) > 3) {
			g_message("query with extensions: %s\n", search);
			ext_dump(stderr, exv, exvcnt, "> ", "\n",
				GNET_PROPERTY(share_debug) > 4);
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
				if (GNET_PROPERTY(share_debug) > 6)
					dump_hex(stderr, "Query Packet (BAD: has overhead)",
						search, MIN(n->size - 2, 256));
				gnet_stats_count_dropped(n, MSG_DROP_QUERY_OVERHEAD);
				drop_it = TRUE;
				break;

			case EXT_T_URN_BAD:
				if (GNET_PROPERTY(share_debug)) {
					dump_hex(stderr, "Query Packet has bad URN",
						search, MIN(n->size - 2, 256));
				}
				gnet_stats_count_dropped(n, MSG_DROP_BAD_URN);
				drop_it = TRUE;
				break;

			case EXT_T_GGEP_H:			/* Expect SHA1 value only */
			case EXT_T_URN_SHA1:
				sha1 = &exv_sha1[exv_sha1cnt].sha1;

				if (EXT_T_GGEP_H == e->ext_token) {
					gint ret;
				
					ret = ggept_h_sha1_extract(e, sha1);
					if (GGEP_OK == ret) {
						/* Okay */
					} else if (GGEP_NOT_FOUND == ret) {
						if (
							GNET_PROPERTY(search_debug) > 3 ||
							GNET_PROPERTY(ggep_debug) > 3
						) {
							g_warning("%s GGEP \"H\" with no SHA1 (dumping)",
								gmsg_infostr(&n->header));
							ext_dump(stderr, e, 1, "....", "\n", TRUE);
						}
						continue;		/* Unsupported hash type */
					} else {
						if (
							GNET_PROPERTY(search_debug) > 3 ||
							GNET_PROPERTY(ggep_debug) > 3
						) {
							g_warning("%s bad GGEP \"H\" (dumping)",
								gmsg_infostr(&n->header));
							ext_dump(stderr, e, 1, "....", "\n", TRUE);
						}
						drop_it = TRUE;
						break;
					}
				} else if (EXT_T_URN_SHA1 == e->ext_token) {
					size_t paylen = ext_paylen(e);

					if (paylen == 0)
						continue;				/* A simple "urn:sha1:" */

					if (
						!huge_sha1_extract32(ext_payload(e), paylen,
							sha1, &n->header)
					) {
						gnet_stats_count_dropped(n, MSG_DROP_MALFORMED_SHA1);
						drop_it = TRUE;
						break;
					}

				}

				if (GNET_PROPERTY(share_debug) > 4) {
					g_message("valid SHA1 #%d in query: %s",
						exv_sha1cnt, sha1_base32(sha1));
				}

				exv_sha1[exv_sha1cnt].matched = FALSE;
				exv_sha1cnt++;

				last_sha1_digest = sha1;
				break;

			case EXT_T_UNKNOWN_GGEP:
				if (GNET_PROPERTY(share_debug) > 4) {
					g_message("Unknown GGEP extension in query");
				}
				break;
			case EXT_T_UNKNOWN:
				if (GNET_PROPERTY(share_debug) > 4) {
					g_message("Unknown extension in query");
				}
				break;
			default:
				if (GNET_PROPERTY(share_debug) > 4) {
					g_message("Unhandled extension in query");
				}
			}
			
			if (drop_it)
				break;
		}

		if (exv_sha1cnt)
			gnet_stats_count_general(GNR_QUERY_SHA1, 1);

		if (exvcnt)
			ext_reset(exv, MAX_EXTVEC);

		if (drop_it)
			goto drop;
	}

    /*
     * Push the query string to interested ones (GUI tracing).
     */

    if (
		(search[0] == '\0' || (search[0] == '\\' && search[1] == '\0'))
		&& exv_sha1cnt
    ) {
		gint i;
		for (i = 0; i < exv_sha1cnt; i++) {
			search_request_listener_emit(QUERY_SHA1,
				sha1_base32(&exv_sha1[i].sha1), n->addr, n->port);
		}
	}

	/*
	 * When an URN search is present, there can be an empty search string.
	 *
	 * If requester if farther than half our TTL hops. save bandwidth when
	 * returning lots of hits from short queries, which are not specific enough.
	 * The idea here is to give some response, but not too many.
	 */

	skip_file_search = search_len <= 1 || (
		search_len < 5 &&
		gnutella_header_get_hops(&n->header) > (GNET_PROPERTY(max_ttl) / 2));

    if (0 == exv_sha1cnt && skip_file_search) {
        gnet_stats_count_dropped(n, MSG_DROP_QUERY_TOO_SHORT);
		goto drop;					/* Drop this search message */
    }

	/*
	 * When we are not a leaf node, we do two sanity checks here:
	 *
	 * 1. We keep track of all the queries sent by the node (hops = 1)
	 *    and the time by which we saw them.  If they are sent too often,
	 *    just drop the duplicates.  Since an Ultranode will send queries
	 *    from its leaves with an adjusted hop, we only do that for leaf
	 *    nodes.
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

	if (gnutella_header_get_hops(&n->header) == 1 && n->qseen != NULL) {
		time_t now = tm_time();
		time_t seen = 0;
		gboolean found;
		gpointer orig_key, orig_val;
		gconstpointer atom;
		gchar *query = search;
		time_delta_t threshold = GNET_PROPERTY(node_requery_threshold);

		g_assert(NODE_IS_LEAF(n));

		if (last_sha1_digest) {
			sha1_to_urn_string_buf(last_sha1_digest, stmp_1, sizeof stmp_1);
			query = stmp_1;
		}

		found = g_hash_table_lookup_extended(n->qseen, query,
					&orig_key, &orig_val);
		if (found) {
			seen = (time_t) GPOINTER_TO_INT(orig_val);
			atom = orig_key;
		} else {
			atom = NULL;
		}

		if (delta_time(now, (time_t) 0) - seen < threshold) {
			if (GNET_PROPERTY(share_debug)) g_warning(
				"node %s (%s) re-queried \"%s\" after %u secs",
				node_addr(n), node_vendor(n), query,
				(unsigned) delta_time(now, seen));
			gnet_stats_count_dropped(n, MSG_DROP_THROTTLE);
			goto drop;		/* Drop the message! */
		}

		if (!found)
			atom = atom_str_get(query);

		gm_hash_table_insert_const(n->qseen, atom,
			GUINT_TO_POINTER((unsigned) delta_time(now, (time_t) 0)));
	}
	record_query_string(gnutella_header_get_muid(&n->header), search);

	/*
	 * For point #2, there are two tables to consider: `qrelayed_old' and
	 * `qrelayed'.  Presence in any of the tables is sufficient, but we
	 * only insert in the "new" table `qrelayed'.
	 */

	if (n->qrelayed != NULL) {					/* Check #2 */
		gpointer found = NULL;

		g_assert(!NODE_IS_LEAF(n));

		/*
		 * Consider both hops and TTL for dynamic querying, whereby the
		 * same query can be repeated with an increased TTL.
		 */

		if (last_sha1_digest == NULL)
			gm_snprintf(stmp_1, sizeof(stmp_1), "%u/%u%s",
				gnutella_header_get_hops(&n->header),
				gnutella_header_get_ttl(&n->header), search);
		else
			gm_snprintf(stmp_1, sizeof(stmp_1), "%u/%uurn:sha1:%s",
				gnutella_header_get_hops(&n->header),
				gnutella_header_get_ttl(&n->header),
				sha1_base32(last_sha1_digest));

		if (n->qrelayed_old != NULL)
			found = g_hash_table_lookup(n->qrelayed_old, stmp_1);

		if (found == NULL)
			found = g_hash_table_lookup(n->qrelayed, stmp_1);

		if (found != NULL) {
			if (GNET_PROPERTY(share_debug)) g_warning(
				"dropping query \"%s%s\" (hops=%u, TTL=%u) "
				"already seen recently from %s (%s)",
				last_sha1_digest == NULL ? "" : "urn:sha1:",
				last_sha1_digest == NULL ?
					search : sha1_base32(last_sha1_digest),
				gnutella_header_get_hops(&n->header),
				gnutella_header_get_ttl(&n->header),
				node_addr(n), node_vendor(n));
			gnet_stats_count_dropped(n, MSG_DROP_THROTTLE);
			goto drop;		/* Drop the message! */
		}

		gm_hash_table_insert_const(n->qrelayed,
			atom_str_get(stmp_1), GINT_TO_POINTER(1));
	}

	oob = 0 != (flags & QUERY_F_OOB_REPLY);

	/*
	 * If query comes from GTKG 0.91 or later, it understands GGEP "H".
	 * Otherwise, it's an old servent or one unwilling to support this new
	 * extension, so it will get its SHA1 URNs in ASCII form.
	 *		--RAM, 17/11/2002
	 */

	{
		guint8 major, minor;
		gboolean release;

		if (
			guid_query_muid_is_gtkg(gnutella_header_get_muid(&n->header),
				oob, &major, &minor, &release)
		) {
			gboolean requery;
		   
			gnet_stats_count_general(GNR_GTKG_TOTAL_QUERIES, 1);
			requery = guid_is_requery(gnutella_header_get_muid(&n->header));
			if (requery)
				gnet_stats_count_general(GNR_GTKG_REQUERIES, 1);

			if (GNET_PROPERTY(query_debug) > 3)
				g_message("GTKG %s%squery from %d.%d%s",
					oob ? "OOB " : "", requery ? "re-" : "",
					major, minor, release ? "" : "u");
		}
	}

	if (0 != (flags & QUERY_F_GGEP_H)) {
		gnet_stats_count_general(GNR_QUERIES_WITH_GGEP_H, 1);
	}

	/*
	 * If OOB reply is wanted, validate a few things.
	 *
	 * We may either drop the query, or reset the OOB flag if it's
	 * obviously misconfigured.  Then we can re-enable the OOB flag
	 * if we're allowed to perform OOB-proxying for leaf queries.
	 */

	if (oob) {
		host_addr_t addr;
		guint16 port;

		guid_oob_get_addr_port(gnutella_header_get_muid(&n->header),
			&addr, &port);

		/*
		 * Verify against the hostile IP addresses...
		 */

		if (hostiles_check(addr)) {
			gnet_stats_count_dropped(n, MSG_DROP_HOSTILE_IP);
			goto drop;		/* Drop the message! */
		}

		if (is_my_address_and_port(addr, port)) {
			gnet_stats_count_dropped(n, MSG_DROP_OWN_RESULT);
			goto drop;
		}

		/*
		 * If it's a neighbouring query, make sure the IP for results
		 * matches what we know about the listening IP for the node.
		 * The UDP port can be different from the TCP port, so we can't
		 * check that.
		 */

		if (
			gnutella_header_get_hops(&n->header) == 1 &&
			is_host_addr(n->gnet_addr) &&
			!host_addr_equal(addr, n->gnet_addr)
		) {
			gnet_stats_count_dropped(n, MSG_DROP_BAD_RETURN_ADDRESS);

			if (GNET_PROPERTY(query_debug) || GNET_PROPERTY(oob_proxy_debug))
				g_message("QUERY dropped from node %s <%s>: invalid OOB flag "
					"(return address mismatch: %s, node: %s)",
					node_addr(n), node_vendor(n),
					host_addr_port_to_string(addr, port), node_gnet_addr(n));

			goto drop;
		}

		/*
		 * If the query contains an invalid IP:port, clear the OOB flag.
		 */

		if (!host_is_valid(addr, port)) {
			query_strip_oob_flag(n, n->data);
			oob = FALSE;

			if (GNET_PROPERTY(query_debug) || GNET_PROPERTY(oob_proxy_debug))
				g_message("QUERY %s node %s <%s>: removed OOB flag "
					"(invalid return address: %s)",
					guid_hex_str(gnutella_header_get_muid(&n->header)),
					node_addr(n), node_vendor(n),
					host_addr_port_to_string(addr, port));
		}
	}

	/*
	 * If the query comes from a leaf node and has the "firewalled"
	 * bit set, chances are the leaf is UDP-firewalled as well.
	 * Clear the OOB flag.
	 * If there is a SHA1 URN, validate it and extract the binary digest
	 * into sha1_digest[], and set `sha1_query' to the base32 value.
	 */

	if (
		oob &&
		(flags & QUERY_F_FIREWALLED) &&
		NODE_IS_LEAF(n)
	) {
		query_strip_oob_flag(n, n->data);
		oob = FALSE;

		if (GNET_PROPERTY(query_debug) || GNET_PROPERTY(oob_proxy_debug)) {
			g_message("QUERY %s node %s <%s>: removed OOB flag "
				"(leaf node is TCP-firewalled)",
				guid_hex_str(gnutella_header_get_muid(&n->header)),
				node_addr(n), node_vendor(n));
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

	oob = oob &&
			GNET_PROPERTY(process_oob_queries) && 
			GNET_PROPERTY(recv_solicited_udp) && 
			udp_active() &&
			gnutella_header_get_hops(&n->header) > 1;

	if (
		!oob &&
		gnutella_header_get_hops(&n->header) > GNET_PROPERTY(max_ttl)
	) {
		gnet_stats_count_dropped(n, MSG_DROP_MAX_TTL_EXCEEDED);
		goto drop;  /* Drop this long-lived search */
	}

	return FALSE;

drop:
	return TRUE;
}

/**
 * Searches requests (from others nodes)
 * Basic matching. The search request is made lowercase and
 * is matched to the filenames in the LL.
 *
 * If `qhv' is not NULL, it is filled with hashes of URN or query words,
 * so that we may later properly route the query among the leaf nodes.
 *
 * @returns TRUE if the message should be dropped and not propagated further.
 */
gboolean
search_request(struct gnutella_node *n, query_hashvec_t *qhv)
{
	guint16 flags;
	gchar *search;
	size_t search_len;
	gboolean skip_file_search = FALSE;
	struct {
		struct sha1 sha1;
		gboolean matched;
	} exv_sha1[MAX_EXTVEC];
	gint exv_sha1cnt = 0;
	guint offset = 0;			/**< Query string start offset */
	gboolean oob = FALSE;		/**< Wants out-of-band query hit delivery? */
	gboolean secure_oob = FALSE;
	gboolean may_oob_proxy = !(n->flags & NODE_F_NO_OOB_PROXY);
	struct guid muid;

	/* NOTE: search_request_preprocess() has already handled this query. */

	flags = peek_be16(n->data);
	search = n->data + 2;	/* skip flags */
	search_len = clamp_strlen(search, n->size - 2);

	/*
	 * If there is extra data after the first NUL, fill the extension vector.
	 */

	if (search_len + 3 != n->size) {
		extvec_t exv[MAX_EXTVEC];
		gint i, exvcnt;
		size_t extra;

	   	extra = n->size - 3 - search_len;		/* Amount of extra data */
		ext_prepare(exv, MAX_EXTVEC);
		exvcnt = ext_parse(search + search_len + 1, extra, exv, MAX_EXTVEC);

		/*
		 * If there is a SHA1 URN, validate it and extract the binary digest
		 * into sha1_digest[], and set `sha1_query' to the base32 value.
		 */

		for (i = 0; i < exvcnt; i++) {
			extvec_t *e = &exv[i];
			struct sha1 *sha1;

			switch (e->ext_token) {
			case EXT_T_OVERHEAD:
			case EXT_T_URN_BAD:
				g_assert_not_reached();
				break;

			case EXT_T_GGEP_NP:
				/* This may override LIME/13v1 */
				may_oob_proxy = FALSE;
				break;

			case EXT_T_GGEP_SO:
				secure_oob = TRUE;
				break;

			case EXT_T_GGEP_H:			/* Expect SHA1 value only */
			case EXT_T_URN_SHA1:
				sha1 = &exv_sha1[exv_sha1cnt].sha1;

				if (EXT_T_GGEP_H == e->ext_token) {
					gint ret;
				
					ret = ggept_h_sha1_extract(e, sha1);
					if (GGEP_OK == ret) {
						/* Okay */
					} else if (GGEP_NOT_FOUND == ret) {
						continue;		/* Unsupported hash type */
					} else {
						g_assert_not_reached();
					}
				} else if (EXT_T_URN_SHA1 == e->ext_token) {
					size_t paylen = ext_paylen(e);

					if (paylen == 0)
						continue;				/* A simple "urn:sha1:" */

					if (
						!huge_sha1_extract32(ext_payload(e), paylen,
							sha1, &n->header)
					) {
						g_assert_not_reached();
					}

				}

				exv_sha1[exv_sha1cnt].matched = FALSE;
				exv_sha1cnt++;

				/*
				 * Add valid URN query to the list of query hashes, if we
				 * are to fill any for query routing.
				 */

				if (qhv) {
					qhvec_add(qhv, sha1_to_urn_string(sha1), QUERY_H_URN);
				}
				break;

			default:;
			}
		}

		if (exv_sha1cnt)
			gnet_stats_count_general(GNR_QUERY_SHA1, 1);

		if (exvcnt)
			ext_reset(exv, MAX_EXTVEC);
	}

    /*
     * Reorderd the checks: if we drop the packet, we won't notify any
     * listeners. We first check whether we want to drop the packet and
     * later decide whether we are eligible for answering the query:
     * 1) try top drop
     * 2) notify listeners
     * 3) bail out if not eligible for a local search
     * 4) local search
     *      --Richard, 11/09/2002
     */

	/*
	 * When an URN search is present, there can be an empty search string.
	 *
	 * If requester if farther than half our TTL hops. save bandwidth when
	 * returning lots of hits from short queries, which are not specific enough.
	 * The idea here is to give some response, but not too many.
	 */

	skip_file_search = search_len <= 1 || (
	 	search_len < 5 &&
		gnutella_header_get_hops(&n->header) > (GNET_PROPERTY(max_ttl) / 2));

	oob = 0 != (flags & QUERY_F_OOB_REPLY);

	/*
	 * If the query does not have an OOB mark, comes from a leaf node and
	 * they allow us to be an OOB-proxy, then replace the IP:port of the
	 * query with ours, so that we are the ones to get the UDP replies.
	 *
	 * Since calling oob_proxy_create() is going to mangle the query's
	 * MUID in place (alterting n->header.muid), we must save the MUID
	 * in case we have local hits to deliver: since we send those directly
	 *		--RAM, 2005-08-28
	 */

	muid = *gnutella_header_get_muid(&n->header);

	if (
		!oob &&
		may_oob_proxy &&
		udp_active() &&
		GNET_PROPERTY(proxy_oob_queries) &&
		!GNET_PROPERTY(is_udp_firewalled) &&
		NODE_IS_LEAF(n) &&
		host_is_valid(listen_addr(), socket_listen_port())
	) {
		oob_proxy_create(n);
		oob = TRUE;
		gnet_stats_count_general(GNR_OOB_PROXIED_QUERIES, 1);
	}

	/*
	 * Given we don't support FW-to-FW transfers, there's no need to reply
	 * if the request coems from a firewalled host and we are also firewalled.
	 */

	if (
		0 != (flags & QUERY_F_FIREWALLED) &&
		GNET_PROPERTY(is_firewalled)
	) {
		return FALSE;			/* Both servents are firewalled */
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

	if (!(flags & QUERY_F_FIREWALLED) && node_guid(n) && NODE_IS_LEAF(n))
		node_proxying_remove(n);	/* This leaf node is no longer firewalled */

	if (!skip_file_search || exv_sha1cnt > 0) {
		struct query_context *qctx;
		guint32 max_replies;

		/*
		 * Perform search...
		 */

		gnet_stats_count_general(GNR_LOCAL_SEARCHES, 1);
		if (
			GNET_PROPERTY(current_peermode) == NODE_P_LEAF &&
			node_ultra_received_qrp(n)
		) {
			node_inc_qrp_query(n);
		}
		qctx = share_query_context_make();
		max_replies = GNET_PROPERTY(search_max_items) == (guint32) -1
				? 255
				: GNET_PROPERTY(search_max_items);

		/*
		 * Search each SHA1.
		 */

		if (exv_sha1cnt) {
			gint i;

			for (i = 0; i < exv_sha1cnt && max_replies > 0; i++) {
				struct shared_file *sf;

				sf = shared_file_by_sha1(&exv_sha1[i].sha1);
				if (
					sf &&
					sf != SHARE_REBUILDING &&
					!shared_file_is_partial(sf)
				) {
					shared_file_check(sf);
					got_match(qctx, sf);
					max_replies--;
				}
			}
		}

		if (!skip_file_search) {
			shared_files_match(search, got_match, qctx, max_replies, qhv);
		}

		if (qctx->found > 0) {
			gnet_stats_count_general(GNR_LOCAL_HITS, qctx->found);
			if (
				GNET_PROPERTY(current_peermode) == NODE_P_LEAF &&
				node_ultra_received_qrp(n)
			)
				node_inc_qrp_match(n);

			if (GNET_PROPERTY(share_debug) > 3) {
				g_message("share HIT %u files '%s'%s ", qctx->found,
						search + offset,
						skip_file_search ? " (skipped)" : "");
				if (exv_sha1cnt) {
					gint i;
					for (i = 0; i < exv_sha1cnt; i++)
						g_message("\t%c(%32s)",
								exv_sha1[i].matched ? '+' : '-',
								sha1_base32(&exv_sha1[i].sha1));
				}
				g_message("\tflags=0x%04x ttl=%u hops=%u",
						(guint) flags,
						gnutella_header_get_ttl(&n->header),
						gnutella_header_get_hops(&n->header));
			}
		}

		if (GNET_PROPERTY(share_debug) > 3)
			g_message("QUERY %s \"%s\" has %u hit%s",
					guid_hex_str(gnutella_header_get_muid(&n->header)),
					search, qctx->found,
					qctx->found == 1 ? "" : "s");

		/*
		 * If we got a query marked for OOB results delivery, send them
		 * a reply out-of-band but only if the query's hops is > 1.  Otherwise,
		 * we have a direct link to the queryier.
		 */

		if (qctx->found) {
			gboolean ggep_h, should_oob;

			ggep_h = 0 != (flags & QUERY_F_GGEP_H);
			should_oob = oob &&
							GNET_PROPERTY(process_oob_queries) && 
							GNET_PROPERTY(recv_solicited_udp) && 
							udp_active() &&
							gnutella_header_get_hops(&n->header) > 1;

			if (should_oob) {
				oob_got_results(n, qctx->files, qctx->found,
					secure_oob, ggep_h);
			} else {
				qhit_send_results(n, qctx->files, qctx->found, &muid, ggep_h);
			}
		}

		share_query_context_free(qctx);
	}

	return FALSE;
}

/* vi: set ts=4 sw=4 cindent: */
