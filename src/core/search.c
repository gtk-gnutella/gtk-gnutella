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

#include "extensions.h"
#include "gmsg.h"
#include "huge.h"
#include "nodes.h"
#include "routing.h"
#include "downloads.h"
#include "gnet_stats.h"
#include "ignore.h"
#include "ggep.h"
#include "ggep_type.h"
#include "version.h"
#include "qrp.h"
#include "search.h"
#include "hostiles.h"
#include "dmesh.h"
#include "fileinfo.h"
#include "guid.h"
#include "dq.h"
#include "dh.h"
#include "share.h"
#include "sockets.h"
#include "vmsg.h"
#include "spam.h"
#include "sq.h"
#include "settings.h"		/* For listen_ip() */
#include "oob_proxy.h"
#include "hosts.h"
#include "bogons.h"
#include "geo_ip.h"

#include "if/gnet_property_priv.h"

#if !defined(USE_TOPLESS)
#include "if/gui_property.h"
#endif /* USE_TOPLESS */

#include "if/core/hosts.h"

#include "lib/array.h"
#include "lib/atoms.h"
#include "lib/endian.h"
#include "lib/glib-missing.h"
#include "lib/hashlist.h"
#include "lib/idtable.h"
#include "lib/listener.h"
#include "lib/misc.h"
#include "lib/sbool.h"
#include "lib/tm.h"
#include "lib/vendors.h"
#include "lib/wordvec.h"
#include "lib/walloc.h"
#include "lib/zalloc.h"
#include "lib/utf8.h"
#include "lib/urn.h"

#include "lib/override.h"		/* Must be the last header included */

#ifdef USE_GTK2
#ifndef g_hash_table_freeze
#define g_hash_table_freeze(x)	/**< The function is deprecated: does nothing */
#endif
#ifndef g_hash_table_thaw
#define g_hash_table_thaw(x)	/**< The function is deprecated: does nothing */
#endif
#endif

#define MUID_MAX			4	 /**< Max amount of MUID we keep per search */
#define SEARCH_MIN_RETRY	1800 /**< Minimum search retry timeout */

static guint32 search_id = 0;			/**< Unique search counter */
static GHashTable *searches = NULL;		/**< All alive searches */

/**
 * Structure for search results.
 */
typedef struct search_ctrl {
    gnet_search_t search_handle;	/**< Search handle */
	guint32 id;						/**< Unique ID */

	/* no more "speed" field -- use marked field now --RAM, 06/07/2003 */

	const gchar  *query;		/**< The search query (atom) */
	time_t  time;				/**< Time when this search was started */
	GSList *muids;				/**< Message UIDs of this search */

	sbool passive;	/**< Is this a passive search? */
	sbool frozen;	/**< XXX: If TRUE, the query is not issued to nodes
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
static GSList *sl_search_ctrl = NULL;		/**< All searches */
static GSList *sl_passive_ctrl = NULL;		/**< Only passive searches */

/*
 * Table holding all the active MUIDs for all the searches, pointing back
 * to the searches directly (i.e. it maps MUID -> search_ctrl_t).
 * The keys are not atoms but directly the MUID objects allocated and held
 * in the search's set of MUIDs.
 */
static GHashTable *search_by_muid = NULL;

static zone_t *rs_zone = NULL;		/**< Allocation of results_set */
static zone_t *rc_zone = NULL;		/**< Allocation of record */

static idtable_t *search_handle_map = NULL;
static query_hashvec_t *query_hashvec = NULL;

#define search_find_by_handle(n) \
    (search_ctrl_t *) idtable_get_value(search_handle_map, n)

#define search_request_handle(n) \
    idtable_new_id(search_handle_map, n)

#define search_drop_handle(n) \
    idtable_free_id(search_handle_map, n);

static void search_check_results_set(gnet_results_set_t *rs);

/***
 *** Counters
 ***/

static GHashTable *ht_sha1 = NULL;
static GHashTable *ht_host = NULL;

#if !GLIB_CHECK_VERSION(2, 0, 0)
#undef SEARCH_STATS_COUNTERS
#endif

#ifdef SEARCH_STATS_COUNTERS
static GList *top_sha1 = NULL;
static GList *top_host = NULL;

struct item_count {
	gpointer p;
	guint n;
};

static GList *
stats_update(GList *top, gpointer key, guint n)
{
	GList *l;
	struct item_count *item = NULL;
	guint last_n = 0;

	for (l = top; l != NULL; l = g_list_next(l)) {
		struct item_count *ic = l->data;

		if (ic->p == key) {
			item = ic;
			ic->n = n;
			if (last_n >= n || l == top)
				return top;

			top = g_list_delete_link(top, l);
			break;
		}
		last_n = ic->n;
	}

	if (!item) {
		if (g_list_length(top) < 25) {
			item = g_malloc(sizeof *item);
		} else if (n > last_n) {
			l = g_list_last(top);
			item = l->data;
			top = g_list_delete_link(top, l);
		} else {
			return top;
		}
		item->p = key;
		item->n = n;
	}

	for (l = top; l != NULL; l = g_list_next(l)) {
		struct item_count *ic = l->data;

		if (ic->n <= n)
			break;
	}
	top = g_list_insert_before(top, l, item);

	return top;
}

static void
free_sha1(gpointer sha1)
{
	g_assert(sha1 != NULL);
	atom_sha1_free(sha1);
}

static void
count_sha1(const gchar *sha1)
{
	static guint calls;
	gpointer key, value;
	guint n;

	if (spam_check_sha1(sha1)) {
		return;
	}

	if (!ht_sha1) {
		ht_sha1 = g_hash_table_new_full(NULL, NULL, free_sha1, NULL);
		if (top_sha1) {
			GList *l;

			g_message("SHA1 ranking:");
			for (l = top_sha1; l != NULL; l = g_list_next(l)) {
				struct item_count *ic = l->data;

				ic->p = atom_sha1_get(ic->p);
				g_hash_table_insert(ht_sha1, ic->p, GUINT_TO_POINTER(ic->n));
				g_message("%8u %s", ic->n, sha1_base32(ic->p));
			}
		}
	}

	key = atom_sha1_get(sha1);
	if (g_hash_table_lookup_extended(ht_sha1, key, NULL, &value)) {
		n = GPOINTER_TO_UINT(value) + 1;
	} else {
		n = 1;
	}

	g_hash_table_insert(ht_sha1, key, GUINT_TO_POINTER(n));
	top_sha1 = stats_update(top_sha1, key, n);
	if (++calls > 1000) {
		GList *l;

		for (l = top_sha1; l != NULL; l = g_list_next(l)) {
			struct item_count *ic = l->data;

			ic->p = atom_sha1_get(ic->p);
		}
		g_hash_table_destroy(ht_sha1);
		ht_sha1 = NULL;
		calls = 0;
	}
}

static void
count_host(host_addr_t addr)
{
	static guint calls;
	gpointer key, value;
	guint n;

	if (
		NET_TYPE_IPV4 != host_addr_net(addr) ||
		is_private_addr(addr) ||
		bogons_check(addr)
	)
		return;

	if (!ht_host) {
		ht_host = g_hash_table_new(NULL, NULL);
		if (top_host) {
			GList *l;

			g_message("Host ranking:");
			for (l = top_host; l != NULL; l = g_list_next(l)) {
				struct item_count *ic = l->data;

				g_hash_table_insert(ht_host, ic->p, GUINT_TO_POINTER(ic->n));
				g_message("%8d %s", ic->n,
					host_addr_to_string(
						host_addr_get_ipv4(GPOINTER_TO_UINT(ic->p))));
			}
		}
	}

	key = GUINT_TO_POINTER(host_addr_ipv4(addr));
	if (g_hash_table_lookup_extended(ht_host, key, NULL, &value))
		n = GPOINTER_TO_UINT(value) + 1;
	else
		n = 1;

	g_hash_table_insert(ht_host, key, GUINT_TO_POINTER(n));
	top_host = stats_update(top_host, key, n);
	if (++calls > 1000) {
		g_hash_table_destroy(ht_host);
		ht_host = NULL;
		calls = 0;
	}
}
#else
#define count_sha1(x) G_STMT_START { } G_STMT_END
#define count_host(x) G_STMT_START { } G_STMT_END 
#endif /* SEARCH_STATS_COUNTERS */

/***
 *** Callbacks (private and public)
 ***/

static listeners_t search_got_results_listeners = NULL;

void
search_add_got_results_listener(search_got_results_listener_t l)
{
	LISTENER_ADD(search_got_results, l);
}

void
search_remove_got_results_listener(search_got_results_listener_t l)
{
	LISTENER_REMOVE(search_got_results, l);
}

static void
search_fire_got_results(GSList *sch_matched, const gnet_results_set_t *rs)
{
    g_assert(rs != NULL);

	LISTENER_EMIT(search_got_results, (sch_matched, rs));
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

	g_hash_table_freeze(sch->sent_nodes);
	for (sl = node_all_nodes(); sl; sl = g_slist_next(sl)) {
		n = sl->data;
		if (NODE_IS_WRITABLE(n))
			mark_search_sent_to_node(sch, n);
	}
	g_hash_table_thaw(sch->sent_nodes);
}

/***
 *** Management of the "sent_node_ids" hash table.
 ***/

static void
search_free_sent_node_ids(search_ctrl_t *sch)
{
	g_hash_table_destroy(sch->sent_node_ids);
}

static void
search_reset_sent_node_ids(search_ctrl_t *sch)
{
	search_free_sent_node_ids(sch);
	sch->sent_node_ids = g_hash_table_new(NULL, NULL);
}

static void
mark_search_sent_to_node_id(search_ctrl_t *sch, guint32 node_id)
{
	gpointer key = GUINT_TO_POINTER(node_id);

	if (g_hash_table_lookup(sch->sent_node_ids, key))
		return;

	g_hash_table_insert(sch->sent_node_ids, key, GUINT_TO_POINTER(1));
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
is_action_url_spam(const gchar *data, size_t size)
{
	if (size > 0) {
		static const gchar schema[] = "http://www.limewire.com/schemas/";
		const gchar *p;

		g_assert(data);
		p = compat_memmem(data, size, schema, CONST_STRLEN(schema));
		if (p) {
			static const gchar action[] = " action=\"http://";
			size -= p - data - CONST_STRLEN(schema);
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
	const gchar *muid;	/* GUID atom */
	time_t sent;
	host_addr_t addr;
	guint32 token;
	guint16 port;
};

static struct ora *
ora_alloc(const gchar muid[GUID_RAW_SIZE], const host_addr_t addr, guint16 port,
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

void
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
ora_lookup(const gchar muid[GUID_RAW_SIZE],
	const host_addr_t addr, guint16 port, guint32 token)
{
	struct ora ora;
	gconstpointer key;

	ora.muid = deconstify_gchar(muid);
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
oob_reply_ack_record(const gchar muid[GUID_RAW_SIZE],
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
search_results_are_requested(const gchar muid[GUID_RAW_SIZE],
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
 * Compute status bits, decompile trailer info, if present
 */
static void
search_results_handle_trailer(const gnutella_node_t *n,
	gnet_results_set_t *rs, const gchar *trailer, size_t trailer_size)
{
	guint8 open_size, open_parsing_size, enabler_mask, flags_mask;
	const gchar *vendor;
	guint32 token;
	gboolean has_token;

	if (!trailer || trailer_size < 7)
		return;

	vendor = lookup_vendor_name(rs->vcode);
	open_size = trailer[4];
	open_parsing_size = trailer[4];
	enabler_mask = trailer[5];
	flags_mask = trailer[6];
	has_token = FALSE;
	token = 0;

	if (open_size == 4)
		open_parsing_size = 2;		/* We ignore XML data size */

	if (T_NAPS == peek_be32(&rs->vcode.be32)) {	
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
		} else if (rs->status  & ST_KNOWN_VENDOR) {
			if (search_debug > 1)
				g_warning("vendor %s changed # of open data bytes to %d",
						vendor, open_size);
		} else if (vendor) {
			if (search_debug > 1)
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
				{
					host_addr_t addr;

					ret = ggept_gtkg_ipv6_extract(e, &addr);
					if (GGEP_OK == ret) {
						if (
							NET_TYPE_IPV4 != network_protocol &&
							is_host_addr(addr) &&
							!hostiles_check(rs->addr) &&
							!hostiles_check(addr)
						) {
							rs->addr = addr;
						}
					} else if (ret == GGEP_INVALID) {
						if (search_debug > 3 || ggep_debug > 3) {
							g_warning("%s bad GGEP \"GTKG.IPV6\" (dumping)",
								gmsg_infostr(&n->header));
							ext_dump(stderr, e, 1, "....", "\n", TRUE);
						}
					}
				}
				break;
			case EXT_T_GGEP_GTKGV1:
				{
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
						if (search_debug > 3 || ggep_debug > 3) {
							g_warning("%s bad GGEP \"GTKGV1\" (dumping)",
									gmsg_infostr(&n->header));
							ext_dump(stderr, e, 1, "....", "\n", TRUE);
						}
					}
				}
				break;
			case EXT_T_GGEP_PUSH:
				if (rs->proxies != NULL) {
					g_warning("%s has multiple GGEP \"PUSH\" (ignoring)",
							gmsg_infostr(&n->header));
					break;
				}
				rs->status |= ST_PUSH_PROXY;
				{
					gnet_host_vec_t *hvec = NULL;

					ret = ggept_push_extract(e, &hvec);
					if (ret == GGEP_OK) {
						rs->proxies = hvec;
					} else {
						if (search_debug > 3 || ggep_debug > 3) {
							g_warning("%s bad GGEP \"PUSH\" (dumping)",
									gmsg_infostr(&n->header));
							ext_dump(stderr, e, 1, "....", "\n", TRUE);
						}
					}
				}
				break;
			case EXT_T_GGEP_HNAME:
				{
					gchar hostname[256];

					ret = ggept_hname_extract(e, hostname, sizeof(hostname));
					if (ret == GGEP_OK)
						rs->hostname = atom_str_get(hostname);
					else {
						if (search_debug > 3 || ggep_debug > 3) {
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
					const gchar *payload = ext_payload(e);
					gnet_record_t *rc;

					/* XXX: Add the XML data to the next best record.
					 *		Maybe better to all? It's just an atom.
					 */
					rc = rs->records ? rs->records->data : NULL; 
					if (rc && !rc->xml && paylen > 0) {
						size_t len;
						gchar buf[4096];

						len = MIN((size_t) paylen, sizeof buf - 1);
						memcpy(buf, payload, len);
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
				if (search_debug > 3 || ggep_debug > 3) {
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
			if (search_debug > 2)
				ext_dump(stderr, exv, exvcnt, "> ", "\n", TRUE);
			if (search_debug > 3 && priv)
				dump_hex(stderr, "Query Hit private data", priv, privlen);
		} else if (!seen_ggep && ggep_debug) {
			g_warning("%s from %s claimed GGEP extensions in trailer, "
					"seen none",
					gmsg_infostr(&n->header), vendor ? vendor : "????");
		} else if (search_debug > 2) {
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
			if (has_token)
				rs->status |= ST_GOOD_TOKEN;
		} else {
			rs->status |= ST_UNREQUESTED;
			gnet_stats_count_general(GNR_UNREQUESTED_OOB_HITS, 1);
			if (search_debug) {
				g_message("Received unrequested query hit from %s",
                	host_addr_port_to_string(n->addr, n->port));
			}
		}
	}

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
	gint sha1_errors = 0;
	gint alt_errors = 0;
	gint alt_without_hash = 0;
	gchar *trailer = NULL;
	gboolean seen_ggep_h = FALSE;
	gboolean seen_ggep_alt = FALSE;
	gboolean seen_bitprint = FALSE;
	gboolean multiple_sha1 = FALSE;
	gint multiple_alt = 0;
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
	rs->country = -1;
	rs->hops = gnutella_header_get_hops(&n->header);
	rs->ttl	= gnutella_header_get_ttl(&n->header);
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
			!is_private_addr(rs->addr)
		)
			gnet_stats_count_general(GNR_OOB_HITS_WITH_ALIEN_IP, 1);
	}

	count_host(rs->addr);

	/* Check for hostile IP addresses */

	if (hostiles_check(n->addr) || hostiles_check(rs->addr)) {
        if (dbg || search_debug) {
            g_message("dropping query hit from hostile IP %s",
                host_addr_to_string(rs->addr));
        }
		rs->status |= ST_HOSTILE;
	}

	if (browse) {
		rs->status |= ST_BROWSE;
		if (is_private_addr(rs->addr)) {
			/*
			 * Sometimes peers report a private IP address in the results
			 * even though they're TCP connectible.
			 *
			 * XXX: Is this correct or might n->addr be the push-proxy?
			 */
			rs->addr = n->addr;
		}
	}

	/* Check for valid IP addresses (unroutable => turn push on) */
	if (is_private_addr(rs->addr))
		rs->status |= ST_FIREWALL;
	else if (rs->port == 0 || bogons_check(rs->addr)) {
        if (dbg || search_debug) {
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

	if (search_debug > 7)
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

		if (is_evil_filename(rc->name)) {
			if (search_debug) {
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
				gchar sha1_digest[SHA1_RAW_SIZE];
				ggept_status_t ret;
				gboolean unknown = TRUE;
				gint paylen;
				const gchar *payload;

				switch (e->ext_token) {
				case EXT_T_URN_BITPRINT:	/* first 32 chars is the SHA1 */
					seen_bitprint = TRUE;
					/* FALLTHROUGH */
				case EXT_T_URN_SHA1:		/* SHA1 URN, the HUGE way */
					has_hash = TRUE;
					paylen = ext_paylen(e);
					if (e->ext_token == EXT_T_URN_BITPRINT) {
						paylen = MIN(paylen, SHA1_BASE32_SIZE);
					}
					if (
						huge_sha1_extract32(ext_payload(e),
								paylen, sha1_digest, &n->header, TRUE)
					) {
						gboolean is_spam;
						
						count_sha1(sha1_digest);
						is_spam = spam_check_sha1(sha1_digest);
						if (is_spam) {
							rs->status |= ST_URN_SPAM;
						}
						if (rc->sha1 != NULL) {
							multiple_sha1 = TRUE;
							atom_sha1_free(rc->sha1);
						}
						rc->sha1 = atom_sha1_get(sha1_digest);
						if (is_spam) {
							set_flags(rc->flags, SR_SPAM);
						}
					} else {
						if (search_debug > 0) {
							g_message("huge_sha1_extract32() failed");
						}
						sha1_errors++;
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

						if (urn_get_sha1_no_prefix(buf, sha1_digest)) {
							gboolean is_spam;
							
							count_sha1(sha1_digest);
							is_spam = spam_check_sha1(sha1_digest);
							if (is_spam) {
								rs->status |= ST_URN_SPAM;
							}

							if (
								huge_improbable_sha1(sha1_digest,
									SHA1_RAW_SIZE)
							) {
								if (search_debug > 0) {
									g_message("Improbable SHA-1 detected");
								}
								sha1_errors++;
							} else {
								if (rc->sha1 != NULL) {
									multiple_sha1 = TRUE;
									atom_sha1_free(rc->sha1);
								}
								rc->sha1 = atom_sha1_get(sha1_digest);
								if (is_spam)
									set_flags(rc->flags, SR_SPAM);
							}
						} else {
							if (search_debug > 0) {
								g_message("urn_get_sha1_no_prefix() failed");
							}
							sha1_errors++;
						}
						wfree(buf, paylen + 1);
					}
					break;
				case EXT_T_GGEP_H:			/* Expect SHA1 value only */
					ret = ggept_h_sha1_extract(e, sha1_digest, SHA1_RAW_SIZE);
					if (ret == GGEP_OK) {
						gboolean is_spam;
						
						has_hash = TRUE;
						count_sha1(sha1_digest);
						is_spam = spam_check_sha1(sha1_digest);
						if (is_spam) {
							rs->status |= ST_URN_SPAM;
						}

						if (huge_improbable_sha1(sha1_digest, SHA1_RAW_SIZE)) {
							if (search_debug > 0) {
								g_message("Improbable SHA-1 detected");
							}
							sha1_errors++;
						} else {
							if (rc->sha1 != NULL) {
								multiple_sha1 = TRUE;
								atom_sha1_free(rc->sha1);
							}
							rc->sha1 = atom_sha1_get(sha1_digest);
							if (is_spam)
								set_flags(rc->flags, SR_SPAM);
						}
						seen_ggep_h = TRUE;
					} else if (ret == GGEP_INVALID) {
						sha1_errors++;
						if (search_debug > 3 || ggep_debug > 3) {
							g_warning("%s bad GGEP \"H\" (dumping)",
								gmsg_infostr(&n->header));
							ext_dump(stderr, e, 1, "....", "\n", TRUE);
						}
					} else {
						if (search_debug > 3 || ggep_debug > 3) {
							g_warning("%s GGEP \"H\" with no SHA1 (dumping)",
								gmsg_infostr(&n->header));
							ext_dump(stderr, e, 1, "....", "\n", TRUE);
						}
					}
					break;
				case EXT_T_GGEP_ALT:		/* Alternate locations */
					if (hvec != NULL) {		/* Already saw one for record! */
						multiple_alt++;
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
						if (search_debug > 3) {
							g_warning("%s bad GGEP \"ALT\" (dumping)",
								gmsg_infostr(&n->header));
							ext_dump(stderr, e, 1, "....", "\n", TRUE);
						}
					}
					break;
				case EXT_T_GGEP_LF:			/* Large File */
					{
						guint64 fs;

					   	ret = ggept_lf_extract(e, &fs);
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
					payload = ext_payload(e);
					if (!rc->xml && paylen > 0) {
						size_t len;
						gchar buf[4096];

						len = MIN((size_t) paylen, sizeof buf - 1);
						memcpy(buf, payload, len);
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
					payload = ext_payload(e);
					if (!rc->path && paylen > 0) {
						size_t len;
						gchar buf[1024];

						len = MIN((size_t) paylen, sizeof buf - 1);
						memcpy(buf, payload, len);
						buf[len] = '\0';
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
							if (search_debug > 3 || ggep_debug > 3) {
								g_warning("%s bad GGEP \"CT\" (dumping)",
										gmsg_infostr(&n->header));
								ext_dump(stderr, e, 1, "....", "\n", TRUE);
							}
						}
					}
					break;
				case EXT_T_UNKNOWN_GGEP:	/* Unknown GGEP extension */
					if (search_debug > 3 || ggep_debug > 3) {
						g_warning("%s unknown GGEP \"%s\" (dumping)",
							gmsg_infostr(&n->header), ext_ggep_id_str(e));
						ext_dump(stderr, e, 1, "....", "\n", TRUE);
					}
					break;
				case EXT_T_GGEP_T:			/* Descriptive text */
					unknown = FALSE;		/* Disables ext_has_ascii_word() */
					/* FALLTHROUGH */
				case EXT_T_UNKNOWN:
					if (unknown) {
						has_unknown = TRUE;
					}
					if (
						ext_paylen(e) &&
						(!unknown || ext_has_ascii_word(e))
					) {
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
				if (search_debug > 2) {
					g_warning("%s hit record #%d/%d has unknown extensions!",
						gmsg_infostr(&n->header), nr, rs->num_recs);
					ext_dump(stderr, exv, exvcnt, "> ", "\n", TRUE);
					dump_hex(stderr, "Query Hit Tag", tag, taglen);
				}
			} else if (exvcnt == MAX_EXTVEC) {
				if (search_debug > 2) {
					g_warning("%s hit record #%d/%d has %d extensions!",
						gmsg_infostr(&n->header), nr, rs->num_recs, exvcnt);
					ext_dump(stderr, exv, exvcnt, "> ", "\n", TRUE);
					dump_hex(stderr, "Query Hit Tag", tag, taglen);
				}
			} else if (search_debug > 3) {
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
		if (0 == (SR_SPAM & rc->flags) && spam_check_filename(rc->name)) {
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
		guint32 tlen = endptr - s;			/* Trailer length, starts at `s' */
		guchar *x = (guchar *) s;

		if ((gint) tlen >= 5 && x[4] + 5 <= (gint) tlen)
			trailer = s;

		if (trailer) {
			memcpy(&rs->vcode.be32, trailer, 4);
			vendor = lookup_vendor_name(rs->vcode);
			if (vendor != NULL && is_vendor_known(rs->vcode)) {
				rs->status |= ST_KNOWN_VENDOR;
			}
		} else {
			if (search_debug) {
				g_warning(
					"UNKNOWN %d-byte trailer at offset %d in %s from %s "
					"(%u/%u records parsed)",
					(gint) tlen, (gint) (s - n->data), gmsg_infostr(&n->header),
					node_addr(n), (guint) nr, (guint) rs->num_recs);
			}
			if (search_debug > 1) {
				dump_hex(stderr, "Query Hit Data (non-empty UNKNOWN trailer?)",
					n->data, n->size);
				dump_hex(stderr, "UNKNOWN trailer part", s, tlen);
			}
		}
	}


	if (nr != rs->num_recs) {
        gnet_stats_count_dropped(n, MSG_DROP_BAD_RESULT);
		goto bad_packet;
    }

	/* We now have the guid of the node */

	rs->guid = atom_guid_get(endptr);

	if (trailer) {
		search_results_handle_trailer(n, rs, trailer, endptr - trailer);
	}
	
	/*
	 * Now that we have the vendor, warn if the message has SHA1 errors.
	 * Then drop the packet!
	 */

	if (sha1_errors) {
		if (search_debug) g_warning(
				"%s from %s (via \"%s\" at %s) "
				"had %d SHA1 error%s over %u record%s",
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

	if (alt_errors && search_debug) {
		g_warning(
				"%s from %s (via \"%s\" at %s) "
				"had %d ALT error%s over %u record%s",
				gmsg_infostr(&n->header), vendor ? vendor : "????",
				node_vendor(n), node_addr(n),
				alt_errors, alt_errors == 1 ? "" : "s",
				nr, nr == 1 ? "" : "s");
	}

	if (alt_without_hash && search_debug) {
		g_warning(
				"%s from %s (via \"%s\" at %s) "
				"had %d ALT extension%s with no hash over %u record%s",
				gmsg_infostr(&n->header), vendor ? vendor : "????",
				node_vendor(n), node_addr(n),
				alt_without_hash, alt_without_hash == 1 ? "" : "s",
				nr, nr == 1 ? "" : "s");
	}

	if (search_debug > 1) {
		if (seen_ggep_h && search_debug > 3)
			g_message("%s from %s used GGEP \"H\" extension",
					gmsg_infostr(&n->header), vendor ? vendor : "????");
		if (seen_ggep_alt && search_debug > 3)
			g_message("%s from %s used GGEP \"ALT\" extension",
					gmsg_infostr(&n->header), vendor ? vendor : "????");
		if (seen_bitprint && search_debug > 3)
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
	if (search_debug > 2) {
		g_warning(
			"BAD %s from %s (via \"%s\" at %s) -- %u/%u records parsed",
			 gmsg_infostr(&n->header), vendor ? vendor : "????",
			 node_vendor(n), node_addr(n), nr, rs->num_recs);
		if (search_debug > 1)
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

    vendor = lookup_vendor_name(rs->vcode);

	if (n->attrs & NODE_A_QHD_NO_VTAG) {	/* Known to have no tag */
		if (vendor) {
			n->n_weird++;
			if (search_debug > 1) g_warning("[weird #%d] "
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

		if (n->vcode.be32 != 0 && vendor == NULL) {
			const guint8 *u8 = cast_to_gconstpointer(&n->vcode.be32);

			n->n_weird++;
			if (search_debug > 1) g_warning("[weird #%d] "
				"node %s (%s) had tag %c%c%c%c in its query hits, "
				"now has none in %s",
				n->n_weird, node_addr(n), node_vendor(n),
				u8[0], u8[1], u8[2], u8[3],
				gmsg_infostr(&n->header));
		}
	}

	/*
	 * Save vendor code if present.
	 */

	if (vendor != NULL) {
		STATIC_ASSERT(sizeof n->vcode == sizeof rs->vcode);

		if (n->vcode.be32 != 0 && n->vcode.be32 != rs->vcode.be32) {
			const guint8 *n_vendor, *rs_vendor;
		   
			n_vendor = cast_to_gconstpointer(&n->vcode.be32);
			rs_vendor = cast_to_gconstpointer(&rs->vcode.be32);

			n->n_weird++;
			if (search_debug > 1) g_warning("[weird #%d] "
				"node %s (%s) moved from tag %c%c%c%c to %c%c%c%c in %s",
				n->n_weird, node_addr(n), node_vendor(n),
				n_vendor[0], n_vendor[1], n_vendor[2], n_vendor[3],
				rs_vendor[0], rs_vendor[1], rs_vendor[2], rs_vendor[3],
				gmsg_infostr(&n->header));
		}

		n->vcode = rs->vcode;
	} else
		n->vcode.be32 = 0;

	/*
	 * Save node's GUID.
	 */

	if (n->gnet_guid) {
		if (!guid_eq(n->gnet_guid, rs->guid)) {
			n->n_weird++;
			if (search_debug > 1) {
				gchar old[33];
				strncpy(old, guid_hex_str(n->gnet_guid), sizeof(old));

				g_warning("[weird #%d] "
					"node %s (%s) moved from GUID %s to %s in %s",
					n->n_weird, node_addr(n), node_vendor(n),
					old, guid_hex_str(rs->guid), gmsg_infostr(&n->header));
			}
			atom_guid_free_null(&n->gnet_guid);
		}
	}

	if (n->gnet_guid == NULL)
		n->gnet_guid = atom_guid_get(rs->guid);

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
		!host_addr_equal(n->addr, rs->addr) &&	/* Not socket's address */
		!(rs->status & ST_FIREWALL) &&		/* Hit not marked "firewalled" */
		!is_private_addr(rs->addr)			/* Address not private */
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
			if (search_debug > 1) g_warning("[weird #%d] "
				"node %s (%s) advertised %s but now says Query Hits from %s",
				n->n_weird, node_addr(n), node_vendor(n),
				host_addr_to_string(is_host_addr(n->gnet_qhit_addr) ?
					n->gnet_qhit_addr : n->gnet_pong_addr),
				host_addr_port_to_string(rs->addr, rs->port));
		}
		n->gnet_qhit_addr = rs->addr;
	}

	if (search_debug > 3 && old_weird != n->n_weird)
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
gnutella_msg_search_t *
build_search_msg(search_ctrl_t *sch)
{
	static union {
		gnutella_msg_search_t data;
		gchar bytes[1024];
		guint64 align8;
	} msg;
	ggep_stream_t gs;
	size_t size;
	guint16 speed;
	gboolean is_sha1_search;
	gchar digest[SHA1_RAW_SIZE];

	STATIC_ASSERT(25 == sizeof msg.data);
	size = sizeof msg.data;
	
    g_assert(sch != NULL);
    g_assert(sbool_get(sch->active));
	g_assert(!sbool_get(sch->frozen));
	g_assert(sch->muids);

	/* Use the first MUID on the list (the last one allocated) */
	{
		gnutella_header_t *header = gnutella_msg_search_header(&msg.data);
		
		gnutella_header_set_muid(header, sch->muids->data);
		gnutella_header_set_function(header, GTA_MSG_SEARCH);
		gnutella_header_set_ttl(header, my_ttl);
		gnutella_header_set_hops(header,
				(hops_random_factor && current_peermode != NODE_P_LEAF) ?
				random_value(hops_random_factor) : 0);

		if (
			(guint32) gnutella_header_get_ttl(header) +
				gnutella_header_get_hops(header) > hard_ttl_limit
		) {
			gnutella_header_set_ttl(header,
				hard_ttl_limit - gnutella_header_get_hops(header));
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
	 * Starting 2005-08-20, we specify QUERY_SPEED_XML because
	 * we show XML in hits within the GUI.  We don't yet parse it, but at
	 * least they can read it.
	 */

	speed = QUERY_SPEED_MARK;			/* Indicates: special speed field */
	if (is_firewalled)
		speed |= QUERY_SPEED_FIREWALLED;
	speed |= QUERY_SPEED_LEAF_GUIDED;	/* GTKG supports leaf-guided queries */
	speed |= QUERY_SPEED_GGEP_H;		/* GTKG understands GGEP "H" in hits */
	speed |= QUERY_SPEED_XML;			/* GTKG can read XML in hits */

	/*
	 * We need special processing for OOB queries since the GUID has to be
	 * marked specially.  This must happen at the time we issue the search.
	 * Therefore, if we're in a position for emitting an OOB query, make sure
	 * the already chosen MUID is valid according to our current IP:port.
	 */

	if (udp_active() && send_oob_queries && !is_udp_firewalled) {
		host_addr_t addr;
		guint16 port;

		guid_oob_get_addr_port(
			gnutella_header_get_muid(gnutella_msg_search_header(&msg.data)),
			&addr, &port);

		if (is_my_address(addr, port))
			speed |= QUERY_SPEED_OOB_REPLY;
	}

	gnutella_msg_search_set_speed(&msg.data, speed);
	
	/*
	 * Are we dealing with an URN search?
	 */

	is_sha1_search = urn_get_sha1(sch->query, digest);

	{	
		size_t len;

		len = strlen(sch->query);
		if (len >= sizeof msg.bytes - size) {
			g_warning("dropping too large query \"%s\"", sch->query);
			goto error;
		}
		memcpy(&msg.bytes[size], sch->query, len);
		msg.bytes[size + len] = '\0';
	
		if (!is_sha1_search) {
			size_t new_len;

			new_len = compact_query(&msg.bytes[size]);
			g_assert(new_len <= len);

			if (new_len == 0) {
				g_warning("dropping empty query \"%s\"", sch->query);
				goto error;
			}

			if (new_len < len) {
				len = new_len;
				if (search_debug > 1)
					g_message("compacted query \"%s\" into \"%s\"",
						sch->query, &msg.bytes[size]);
			}
		}
		size += len + 1;
	}

	ggep_stream_init(&gs, &msg.bytes[size], sizeof msg.bytes - size);

	if (is_sha1_search) {
		/* TODO: We cannot emit empty queries with GGEP H attached because
		 *		 GTKG before 0.96.4 does not parse GGEP H in queries.
		 */
#if 0
		const guint8 type = GGEP_H_SHA1;
		gboolean ok;

		ok = ggep_stream_begin(&gs, GGEP_NAME(H), 0) &&
			ggep_stream_write(&gs, &type, 1) &&
			ggep_stream_write(&gs, digest, sizeof digest) &&
			ggep_stream_end(&gs);

		if (!ok) {
			g_warning("could not add GGEP \"H\" to query");
			goto error;
		}
#endif
	}

	/** 
	 * Indicate support for OOB v3.
	 * @see http://the-gdf.org/index.php?title=OutOfBandV3
	 */
	if (!ggep_stream_pack(&gs, GGEP_NAME(SO), NULL, 0, 0)) {
			g_warning("could not add GGEP \"SO\" extension to query");
			goto error;
	}

	size += ggep_stream_close(&gs);

	if (size - GTA_HEADER_SIZE > search_queries_forward_size) {
		g_warning("not sending query \"%s\": larger than max query size (%d)",
			sch->query, search_queries_forward_size);
		goto error;
	}

	gnutella_header_set_size(gnutella_msg_search_header(&msg.data),
		size - GTA_HEADER_SIZE);

	if (search_debug > 3)
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
	g_assert(current_peermode == NODE_P_ULTRA);

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
	 * XXX Drop support for regular nodes after 0.95 --RAM, 2004-08-31.
	 */

	if (current_peermode != NODE_P_ULTRA) {
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

	if (current_peermode == NODE_P_ULTRA)
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
search_add_new_muid(search_ctrl_t *sch, gchar *muid)
{
	guint count;

	g_assert(NULL == g_hash_table_lookup(search_by_muid, muid));

	if (sch->muids) {		/* If this isn't the first muid -- requerying */
		search_reset_sent_nodes(sch);
		search_reset_sent_node_ids(sch);
	}

	sch->muids = g_slist_prepend(sch->muids, (gpointer) muid);
	g_hash_table_insert(search_by_muid, muid, sch);

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
	guint32 max_items;

#if defined(USE_TOPLESS)
	max_items = 1;
#else
	gui_prop_get_guint32_val(PROP_SEARCH_MAX_RESULTS, &max_items);
#endif
	return max_items;
}

/**
 * Make sure a timer is created/removed after a search was started/stopped.
 */
static void
update_one_reissue_timeout(search_ctrl_t *sch)
{
	guint32 max_items;
	gint percent;
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

	if (search_debug > 2)
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
search_send_query_status(search_ctrl_t *sch, guint32 node_id, guint16 kept)
{
	struct gnutella_node *n;

	n = node_active_by_id(node_id);
	if (n == NULL)
		return;					/* Node disconnected already */

	if (search_debug > 1)
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
	guint node_id = GPOINTER_TO_UINT(key);
	search_ctrl_t *sch = (search_ctrl_t *) udata;
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
	guint node_id = GPOINTER_TO_UINT(key);
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

	if (current_peermode == NODE_P_ULTRA)
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

	searches = g_hash_table_new(NULL, NULL);
	search_by_muid = g_hash_table_new(guid_hash, guid_eq);
    search_handle_map = idtable_new(32, 32);
	query_hashvec = qhvec_alloc(128);	/* Max: 128 unique words / URNs! */
	oob_reply_acks_init();
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

	if (ht_sha1) {
		g_hash_table_destroy(ht_sha1);
		ht_sha1 = NULL;
	}
	if (ht_host) {
		g_hash_table_destroy(ht_host);
		ht_host = NULL;
	}

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

	if (browse_copied_to_passive) {
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
	 *
	 * NB: route_message() increases hops by 1 for messages we handle.
	 */

	if (gnutella_header_get_hops(&n->header) == 1 && !NODE_IS_UDP(n))
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
			if (proxy_oob_queries && oob_proxy_got_results(n, rs->num_recs))
				forward_it = FALSE;
			else
				dh_got_results(gnutella_header_get_muid(&n->header),
					rs->num_recs);
		}

		/*
		 * Look for records that match entries in the download queue.
		 */

		if (auto_download_identical)
			search_check_results_set(rs);

		/*
		 * Look for records whose SHA1 matches files we own and add
		 * those entries to the mesh.
		 */

		if (auto_feed_download_mesh)
			dmesh_check_results_set(rs);
	}

    /*
     * Look for records that should be ignored.
     */

    if (
		selected_searches != NULL &&
		search_handle_ignored_files != SEARCH_IGN_DISPLAY_AS_IS
	) {
        for (sl = rs->records; sl != NULL; sl = g_slist_next(sl)) {
            gnet_record_t *rc = sl->data;
            enum ignore_val ival;

            ival = ignore_is_requested(rc->name, rc->size, rc->sha1);
            if (ival != IGNORE_FALSE) {
				if (search_handle_ignored_files == SEARCH_IGN_NO_DISPLAY)
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

	if (
		drop_it &&
		gnutella_header_get_hops(&n->header) == 1 &&
		!NODE_IS_UDP(n)
	) {
		n->n_weird++;
		if (search_debug > 1) g_warning("[weird #%d] dropped %s from %s (%s)",
			n->n_weird, gmsg_infostr(&n->header), node_addr(n), node_vendor(n));
	}

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
search_notify_sent(gpointer search, guint32 id, guint32 node_id)
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
	gint ignored = 0;
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
			download_auto_new(rc->name, rc->size, URN_INDEX, addr, port,
				blank_guid, rs->hostname, rc->sha1, rs->stamp, TRUE, fi,
				rs->proxies, (rs->status & ST_TLS) ? SOCK_F_TLS : 0);

			search_free_proxies(rs);
		} else {
			ignored++;
		}
	}

	search_free_alt_locs(rc);

	if (ignored) {
    	const gchar *vendor = lookup_vendor_name(rs->vcode);
		g_warning("ignored %d invalid alt-loc%s in hits from %s (%s)",
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

		fi = file_info_has_identical(rc->name, rc->size, rc->sha1);

		if (fi) {
			guint32 flags = 0;
			
			flags |= (rs->status & ST_FIREWALL) ? SOCK_F_PUSH : 0;
			flags |= !host_is_valid(rs->addr, rs->port) ? SOCK_F_PUSH : 0;
			flags |= (rs->status & ST_TLS) ? SOCK_F_TLS : 0;
			
			download_auto_new(rc->name, rc->size, rc->file_index,
				rs->addr, rs->port, rs->guid, rs->hostname, rc->sha1,
				rs->stamp, TRUE, fi, rs->proxies, flags);


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
	wfree(sch, sizeof *sch);
}

/**
 * Allocate a new MUID for a search.
 *
 * @param initial indicates whether this is an initial query or a requery.
 *
 * @return a new MUID that can be wfree()'d when done.
 */
static gchar *
search_new_muid(gboolean initial)
{
	gchar *muid;
	host_addr_t addr;
	gint i;

	muid = walloc(GUID_RAW_SIZE);

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
	gboolean expired;
	time_t ct;
	guint lt;

	g_assert(sch);
	
	ct = sch->create_time;			/* In local (kernel) time */
	lt = 3600 * sch->lifetime;

	if (lt) {
		gint d;

		d = delta_time(tm_time(), ct);
		d = MAX(0, d);
		expired = (guint) d >= lt;
	} else
		expired = FALSE;

	return expired;
}

/**
 * Force a reissue of the given search. Restart reissue timer.
 */
void
search_reissue(gnet_search_t sh)
{
    search_ctrl_t *sch = search_find_by_handle(sh);
	gchar *muid;

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
		if (search_debug)
			g_message("expired search \"%s\" (queries broadcasted: %d)",
				sch->query, sch->query_emitted);
		sch->frozen = sbool_set(TRUE);
		goto done;
	}

	if (search_debug)
		g_message("reissuing search \"%s\" (queries broadcasted: %d)",
			sch->query, sch->query_emitted);

	muid = search_new_muid(FALSE);

	sch->query_emitted = 0;
	search_add_new_muid(sch, muid);
	search_send_packet_all(sch);

done:
	update_one_reissue_timeout(sch);
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

    sch->reissue_timeout = timeout > 0 ? MAX(SEARCH_MIN_RETRY, timeout) : 0;
    update_one_reissue_timeout(sch);
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
 * @return	-1 if the search could not be created, a valid handle for the
 *			search otherwise.
 */
gnet_search_t
search_new(const gchar *query,
	time_t create_time, guint lifetime, guint32 reissue_timeout, flag_t flags)
{
	const gchar *endptr;
	search_ctrl_t *sch;
	gchar *qdup;

	g_assert(utf8_is_valid_string(query));
	
	/*
	 * Canonicalize the query we're sending.
	 */

	if (NULL != (endptr = is_strprefix(query, "urn:sha1:"))) {
		if (SHA1_BASE32_SIZE != strlen(endptr) || !urn_get_sha1(query, NULL)) {
			g_warning("Rejected invalid urn:sha1 search");
			return (gnet_search_t) -1;
		}
		qdup = g_strdup(query);
	} else if (!(flags & (SEARCH_F_LOCAL | SEARCH_F_BROWSE | SEARCH_F_PASSIVE))) {
		qdup = UNICODE_CANONIZE(query);
		g_assert(qdup != query);
		
		if (compact_query(qdup) < 3) {
			g_warning("Rejected too short query string: \"%s\"", qdup);
			G_FREE_NULL(qdup);
			return (gnet_search_t) -1;
		}
	} else {
		qdup = g_strdup(query);
	}

	sch = walloc0(sizeof *sch);

	sch->search_handle = search_request_handle(sch);
	sch->id = search_id++;

	g_hash_table_insert(searches, sch, GINT_TO_POINTER(1));

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
		sch->new_node_hook->func =
				cast_func_to_gpointer((func_ptr_t) node_added_callback);
		g_hook_prepend(&node_added_hook_list, sch->new_node_hook);

		if (reissue_timeout != 0 && reissue_timeout < SEARCH_MIN_RETRY)
			reissue_timeout = SEARCH_MIN_RETRY;
		sch->reissue_timeout = reissue_timeout;

		sch->sent_nodes =
			g_hash_table_new(sent_node_hash_func, sent_node_compare);
		sch->sent_node_ids = g_hash_table_new(NULL, NULL);
	}

	sl_search_ctrl = g_slist_prepend(sl_search_ctrl, sch);

	if (sbool_get(sch->passive))
		sl_passive_ctrl = g_slist_prepend(sl_passive_ctrl, sch);

	return sch->search_handle;
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

	if (search_debug > 1)
		g_message("SCH GUI reported %u new kept results for \"%s\", has %u now",
			kept, sch->query, sch->kept_results);

	/*
	 * If we're a leaf node, notify our dynamic query managers (the ultranodes
	 * to which we're connected) about the amount of results we got so far.
	 */

	if (!sbool_get(sch->active) || current_peermode != NODE_P_LEAF)
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
			gchar *muid;

			muid = search_new_muid(TRUE);
			search_add_new_muid(sch, muid);
			search_send_packet_all(sch);		/* Send initial query */
		}

        update_one_reissue_timeout(sch);
	}
}

/**
 * Stop search. Cancel reissue timer and don't return any results anymore.
 */
void
search_stop(gnet_search_t sh)
{
    search_ctrl_t *sch = search_find_by_handle(sh);

    g_assert(sch != NULL);
    g_assert(!sbool_get(sch->frozen));

    sch->frozen = sbool_set(TRUE);

    if (sbool_get(sch->active))
		update_one_reissue_timeout(sch);
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
search_get_kept_results(const gchar *muid, guint32 *kept)
{
	search_ctrl_t *sch;

	sch = g_hash_table_lookup(search_by_muid, muid);

	g_assert(sch == NULL || sbool_get(sch->active)); /* No MUID if not active */

	if (sch == NULL)
		return FALSE;

	if (sbool_get(sch->frozen)) {
		if (search_debug)
			g_message("Ignoring results because search is stopped");
		return FALSE;
	}

	if (search_debug > 1)
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
	gnutella_node_t *n, const gchar *muid, gint hits,
	gboolean udp_firewalled, gboolean secure)
{
	struct array token_opaque;
	guint32 token;
	guint32 kept;
	gint ask;

	g_assert(NODE_IS_UDP(n));
	g_assert(hits > 0);

	if (secure) {
		token = random_raw();
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
			proxy_oob_queries &&
			oob_proxy_pending_results(n, muid, hits, udp_firewalled,
				&token_opaque)
		) {
			goto record_token;	
		}

		if (search_debug)
			g_warning("got OOB indication of %d hit%s for unknown search %s",
				hits, hits == 1 ? "" : "s", guid_hex_str(muid));

		if (search_debug > 3)
			gmsg_log_bad(n, "unexpected OOB hit indication");

		gnet_stats_count_dropped(n, MSG_DROP_UNEXPECTED);

		return;
	}

	if (search_debug || udp_debug)
		g_message("has %d pending OOB hit%s for search %s at %s",
			hits, hits == 1 ? "" : "s", guid_hex_str(muid), node_addr(n));

	/*
	 * If we got more than 15% of our maximum amount of shown results,
	 * then we have a very popular query here.  We don't really need
	 * to get more results, ignore.
	 */

	if (kept > search_max_results_for_ui() * 0.15) {
		if (search_debug)
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
	 * XXX We currently have no protection against this, nor any way to
	 * XXX track it, as we'll blindly accept incoming UDP hits without really
	 * XXX knowing how much we asked for.  Tracking would allow us to identify
	 * XXX hostile hosts for the remaining of the session.
	 */

	ask = MIN(hits, 254);
	ask = MIN((guint) ask, search_max_items);
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
    g_assert(sch->query != NULL);

    return sch->query;
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
	const gchar *guid, const gnet_host_vec_t *proxies, guint32 flags)
{
    search_ctrl_t *sch = search_find_by_handle(sh);

    g_assert(sch != NULL);
	g_assert(sbool_get(sch->browse));
	g_assert(!sbool_get(sch->frozen));
	g_assert(sch->download == NULL);

	if (!port_is_valid(port))
		return FALSE;

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
search_dissociate_browse(gnet_search_t sh, struct download *d)
{
    search_ctrl_t *sch = search_find_by_handle(sh);

    g_assert(sch != NULL);
	g_assert(sbool_get(sch->browse));
	g_assert(sch->download == d);

	sch->download = NULL;

	/* XXX notify the GUI that the browse is finished */
}

static void
search_add_local_file(gnet_results_set_t *rs, shared_file_t *sf)
{
	gnet_record_t *rc;

	g_return_if_fail(rs);
	g_return_if_fail(sf);
	g_return_if_fail(SHARE_REBUILDING != sf);

	rc = search_record_new();
	rc->file_index = shared_file_index(sf);
	rc->size = shared_file_size(sf);
	rc->name = atom_str_get(shared_file_name_nfc(sf));
	if (shared_file_relative_path(sf)) {
		rc->path = atom_str_get(shared_file_relative_path(sf));
	}
	rc->tag = atom_str_get(shared_file_path(sf));
	if (sha1_hash_available(sf)) {
		rc->sha1 = atom_sha1_get(shared_file_sha1(sf));
	}
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
		gchar digest[SHA1_RAW_SIZE];

		re = NULL;
		error = !urn_get_sha1(query, digest);
		if (error) {
			goto done;
		}
		sf = shared_file_by_sha1(digest);
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
	rs->port = listen_port;
	rs->last_hop = zero_host_addr;
	rs->country = -1;
	rs->guid = atom_guid_get(servent_guid);
	poke_be32(&rs->vcode.be32, T_GTKG);
    rs->status |= ST_LOCAL | ST_KNOWN_VENDOR;

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

/* vi: set ts=4 sw=4 cindent: */
