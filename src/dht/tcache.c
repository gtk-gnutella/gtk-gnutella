/*
 * Copyright (c) 2009, Raphael Manfredi
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
 * @ingroup dht
 * @file
 *
 * Security token caching.
 *
 * Security tokens are used in the Gnutella DHT to make sure a node can
 * issue a STORE on another node only if it recently contacted that node
 * to perform a FIND_NODE operation.  In effect, this prevents someone
 * performing massive STORE operations blindly.
 *
 * Security tokens have a short lifespan and must be re-acquired often.
 * How often depends on the vendors, but it is safe to assume that the
 * minimum lifetime will be the replication period defined in Kademlia specs,
 * i.e. one hour at least.  It can be much longer, but there's no way to
 * know for sure.
 *
 * When performing node lookup operations, security tokens are collected along
 * the way, as FIND_NODE RPCs are issued to identify the k-closest nodes for
 * a given KUID.  Unfortunately, FIND_NODE operations are expensive in terms
 * of network bandwidth and delays, and we need to perform some caching to
 * speed things a little bit (well, significantly).
 *
 * For publishing operations, we can rely on the root caching to be able to
 * quickly seed the lookup shortlist.  But still we need to contact all the
 * nodes to be able to STORE to them.  Here comes the security token cache...
 *
 * Whenever a security token is collected from a node lookup, it is given
 * to the security token cache where it will remain for some time.  Whenever
 * we initiate a node lookup in order to perform a STORE, we look whether
 * we already know fresh security tokens for some of the nodes that we put in
 * the shortlist.  This gives us an indication that it is likely for the node
 * to still be alive (it freshly replied) and it can prevent a FIND_NODE to
 * be issued to that node -- that really is up to the lookup logic to decide
 * depending on the replies for FIND_NODE it gets from other contacted nodes.
 *
 * The cache is made of one single DBMW database which maps a KUID target to
 * its latest known security token.
 *
 * @author Raphael Manfredi
 * @date 2009
 */

#include "common.h"

#include "tcache.h"
#include "lookup.h"
#include "token.h"

#include "if/gnet_property_priv.h"
#include "if/dht/kuid.h"
#include "if/core/settings.h"	/* For settings_dht_db_dir() */

#include "core/gnet_stats.h"

#include "lib/atoms.h"
#include "lib/cq.h"
#include "lib/debug.h"
#include "lib/map.h"
#include "lib/dbmw.h"
#include "lib/dbstore.h"
#include "lib/misc.h"
#include "lib/tm.h"
#include "lib/stringify.h"
#include "lib/walloc.h"
#include "lib/override.h"		/* Must be the last header included */

#define TOK_DB_CACHE_SIZE	4096	/**< Cached amount of tokens */
#define TOK_MAP_CACHE_SIZE	64		/**< Amount of SDBM pages to cache */
#define TOK_LIFE			(5*3600)	/**< Cached token lifetime in seconds */

#define TCACHE_PRUNE_PERIOD	(3600 * 1000)	/**< 1 hour in ms */

static time_delta_t token_life;		/**< Lifetime of our cached tokens */
static cperiodic_t *tcache_prune_ev;

/**
 * Debugging configuration for the DBM wrapper.
 */
static dbg_config_t tcache_dbmw_dbg = {
	"DHT TCACHE ",							/* prefix */
	"DBMW",									/* type */
	0, 0,									/* level, flags */
	(stringify_fn_t) dbmw_name,				/* o2str */
	(stringify_fn_t) kuid_to_hex_string,	/* k2str */
	NULL,									/* klen2str */
	NULL,									/* v2str */
	NULL,									/* vlen2str */
};

/**
 * DBM wrapper to associate a target KUID its STORE security token.
 */
static dbmw_t *db_tokdata;
static char db_tcache_base[] = "dht_tokens";
static char db_tcache_what[] = "DHT security tokens";

/**
 * Information about a target KUID that is stored to disk.
 * The structure is serialized first, not written as-is.
 */
struct tokdata {
	time_t last_update;		/**< When we last updated the security token */
	uint8 length;			/**< Token length (0 if none) */
	void *token;			/**< Token binary data -- walloc()-ed */
};

/**
 * Debugging variables changed.
 */
void
tcache_debugging_changed(void)
{
	tcache_dbmw_dbg.level = GNET_PROPERTY(dht_tcache_debug);
	tcache_dbmw_dbg.flags = GNET_PROPERTY(dht_tcache_debug_flags);
}

/**
 * Get tokdata from database, returning NULL if not found.
 */
static struct tokdata *
get_tokdata(const kuid_t *id)
{
	struct tokdata *td;

	td = dbmw_read(db_tokdata, id, NULL);

	if (NULL == td) {
		if (dbmw_has_ioerr(db_tokdata)) {
			s_warning_once_per(LOG_PERIOD_MINUTE,
				"DBMW \"%s\" I/O error, bad things could happen...",
				dbmw_name(db_tokdata));
		}
	}

	return td;
}

/**
 * Delete known-to-be existing token data for specified KUID from database.
 */
static void
delete_tokdata(const kuid_t *id)
{
	dbmw_delete(db_tokdata, id);
	gnet_stats_dec_general(GNR_DHT_CACHED_TOKENS_HELD);

	if (GNET_PROPERTY(dht_tcache_debug) > 2)
		g_debug("DHT TCACHE security token from %s reclaimed",
			kuid_to_hex_string(id));

	if (GNET_PROPERTY(dht_tcache_debug_flags) & DBG_DSF_USR1) {
		g_debug("DHT TCACHE %s: stats=%s, count=%zu, id=%s",
			G_STRFUNC, uint64_to_string(
				gnet_stats_get_general(GNR_DHT_CACHED_TOKENS_HELD)),
			dbmw_count(db_tokdata), kuid_to_hex_string(id));
	}
}

/**
 * Serialization routine for tokdata.
 */
static void
serialize_tokdata(pmsg_t *mb, const void *data)
{
	const struct tokdata *td = data;

	pmsg_write_time(mb, td->last_update);
	pmsg_write_u8(mb, td->length);
	pmsg_write(mb, td->token, td->length);
}

/**
 * Deserialization routine for tokdata.
 */
static void
deserialize_tokdata(bstr_t *bs, void *valptr, size_t len)
{
	struct tokdata *td = valptr;

	g_assert(sizeof *td == len);

	bstr_read_time(bs, &td->last_update);
	bstr_read_u8(bs, &td->length);

	if (td->length != 0) {
		td->token = walloc(td->length);
		bstr_read(bs, td->token, td->length);
	} else {
		td->token = NULL;
	}
}

/**
 * Free routine for tokdata, to release internally allocated memory, not
 * the structure itself.
 */
static void
free_tokdata(void *valptr, size_t len)
{
	struct tokdata *td = valptr;

	g_assert(sizeof *td == len);

	WFREE_NULL(td->token, td->length);
}

/**
 * Map iterator to record security tokens in the database.
 */
static void
record_token(void *key, void *value, void *unused_u)
{
	kuid_t *id = key;
	lookup_token_t *ltok = value;
	struct tokdata td;

	(void) unused_u;

	td.last_update = ltok->retrieved;
	td.length = ltok->token->length;
	td.token = td.length ? wcopy(ltok->token->v, td.length) : NULL;

	if (GNET_PROPERTY(dht_tcache_debug) > 4 && td.token != NULL) {
		char buf[80];
		bin_to_hex_buf(td.token, td.length, buf, sizeof buf);
		g_debug("DHT TCACHE adding security token for %s: %u-byte \"%s\"",
			kuid_to_hex_string(id), td.length, buf);
	}

	/*
	 * Data is put in the DBMW cache and the dynamically allocated token
	 * will be freed via free_tokdata() when the cached entry is released.
	 */

	if (!dbmw_exists(db_tokdata, id->v))
		gnet_stats_inc_general(GNR_DHT_CACHED_TOKENS_HELD);

	dbmw_write(db_tokdata, id->v, &td, sizeof td);

	if (GNET_PROPERTY(dht_tcache_debug_flags) & DBG_DSF_USR1) {
		g_debug("DHT TCACHE %s: stats=%s, count=%zu, id=%s",
			G_STRFUNC, uint64_to_string(
				gnet_stats_get_general(GNR_DHT_CACHED_TOKENS_HELD)),
			dbmw_count(db_tokdata), kuid_to_hex_string(id));
	}
}

/**
 * Record security tokens collected during a node lookup from the supplied map.
 *
 * @param tokens	a map containing KUID => lookup_token_t
 */
void
tcache_record(map_t *tokens)
{
	map_foreach(tokens, record_token, NULL);
}

/**
 * Retrieve cached security token for a given KUID.
 *
 * @param id		the KUID for which we'd like the security token
 * @param len_ptr	where the length of the security token is written
 * @param tok_ptr	where the address of the security token is written
 * @param time_ptr	where the last update time of token is writen
 *
 * @return TRUE if we found a token, with len_ptr and tok_ptr filled with
 * the information about the length and the token pointer.  Information is
 * returned from a static memory buffer so it must be perused immediately.
 */
bool
tcache_get(const kuid_t *id,
	uint8 *len_ptr, const void **tok_ptr, time_t *time_ptr)
{
	struct tokdata *td;

	g_assert(id != NULL);

	td = get_tokdata(id);

	if (NULL == td)
		return FALSE;

	if (delta_time(tm_time(), td->last_update) > token_life) {
		delete_tokdata(id);
		return FALSE;
	}

	if (len_ptr != NULL)	*len_ptr = td->length;
	if (tok_ptr != NULL)	*tok_ptr = td->token;
	if (time_ptr != NULL)	*time_ptr = td->last_update;

	if (GNET_PROPERTY(dht_tcache_debug) > 4) {
		char buf[80];
		bin_to_hex_buf(td->token, td->length, buf, sizeof buf);
		g_debug("DHT TCACHE security token for %s is %u-byte \"%s\" (%s)",
			kuid_to_hex_string(id), td->length, buf,
			compact_time(delta_time(tm_time(), td->last_update)));
	}

	gnet_stats_inc_general(GNR_DHT_CACHED_TOKENS_HITS);

	return TRUE;
}

/**
 * Remove cached token for specified KUID.
 *
 * @return TRUE if entry existed
 */
bool
tcache_remove(const kuid_t *id)
{
	if (!dbmw_exists(db_tokdata, id))
		return FALSE;

	delete_tokdata(id);
	return TRUE;
}

/**
 * DBMW foreach iterator to remove old entries.
 * @return  TRUE if entry must be deleted.
 */
static bool
tk_prune_old(void *key, void *value, size_t u_len, void *u_data)
{
	const kuid_t *id = key;
	const struct tokdata *td = value;
	time_delta_t d;

	(void) u_len;
	(void) u_data;

	d = delta_time(tm_time(), td->last_update);

	if (GNET_PROPERTY(dht_tcache_debug) > 2 && d > token_life) {
		g_debug("DHT TCACHE security token from %s expired",
			kuid_to_hex_string(id));
	}

	if (GNET_PROPERTY(dht_tcache_debug) > 5) {
		g_debug("DHT TCACHE %s: %s id=%s",
			G_STRFUNC, d > token_life ? "prune" : "keep ",
			kuid_to_hex_string(id));
	}

	return d > token_life;
}

/**
 * Prune the database, removing expired tokens.
 */
static void
tcache_prune_old(void)
{
	size_t pruned;

	if (GNET_PROPERTY(dht_tcache_debug)) {
		g_debug("DHT TCACHE pruning expired tokens (%zu)",
			dbmw_count(db_tokdata));
	}

	pruned = dbmw_foreach_remove(db_tokdata, tk_prune_old, NULL);
	gnet_stats_set_general(GNR_DHT_CACHED_TOKENS_HELD, dbmw_count(db_tokdata));

	if (GNET_PROPERTY(dht_tcache_debug)) {
		g_debug("DHT TCACHE pruned expired tokens (%zu pruned, %zu remaining)",
			pruned, dbmw_count(db_tokdata));
	}
}

/**
 * Callout queue periodic event to expire old entries.
 */
static bool
tcache_periodic_prune(void *unused_obj)
{
	(void) unused_obj;

	tcache_prune_old();
	return TRUE;		/* Keep calling */
}

/**
 * Initialize security token caching.
 */
G_GNUC_COLD void
tcache_init(void)
{
	dbstore_kv_t kv = { KUID_RAW_SIZE, NULL, sizeof(struct tokdata),
		sizeof(struct tokdata) + MAX_INT_VAL(uint8) };
	dbstore_packing_t packing =
		{ serialize_tokdata, deserialize_tokdata, free_tokdata };

	g_assert(NULL == db_tokdata);
	g_assert(NULL == tcache_prune_ev);

	db_tokdata = dbstore_create(db_tcache_what, settings_dht_db_dir(),
		db_tcache_base, kv, packing, TOK_DB_CACHE_SIZE, kuid_hash, kuid_eq,
		GNET_PROPERTY(dht_storage_in_memory));

	dbmw_set_map_cache(db_tokdata, TOK_MAP_CACHE_SIZE);
	dbmw_set_debugging(db_tokdata, &tcache_dbmw_dbg);

	token_life = MIN(TOK_LIFE, token_lifetime());

	if (GNET_PROPERTY(dht_tcache_debug))
		g_debug("DHT cached token lifetime set to %u secs",
			(unsigned) token_life);

	tcache_prune_ev = cq_periodic_main_add(TCACHE_PRUNE_PERIOD,
		tcache_periodic_prune, NULL);
}

/**
 * Close security token caching.
 */
void
tcache_close(void)
{
	dbstore_delete(db_tokdata);
	db_tokdata = NULL;
	cq_periodic_remove(&tcache_prune_ev);
}

/* vi: set ts=4 sw=4 cindent: */
