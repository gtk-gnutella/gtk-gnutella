/*
 * $Id$
 *
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

RCSID("$Id$")

#include "tcache.h"
#include "lookup.h"
#include "storage.h"

#include "if/gnet_property_priv.h"
#include "if/dht/kuid.h"

#include "core/gnet_stats.h"

#include "lib/atoms.h"
#include "lib/map.h"
#include "lib/dbmw.h"
#include "lib/walloc.h"
#include "lib/override.h"		/* Must be the last header included */

#define TOK_DB_CACHE_SIZE	4096	/**< Cached amount of tokens */
#define TOK_MAP_CACHE_SIZE	64		/**< Amount of SDBM pages to cache */
#define TOK_LIFE	3600			/**< Cached token lifetime in seconds */

/**
 * DBM wrapper to associate a target KUID with the set of KDA_K dbkeys.
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
	guint8 length;			/**< Token length (0 if none) */
	void *token;			/**< Token binary data -- walloc()-ed */
};

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
			g_warning("DBMW \"%s\" I/O error, bad things could happen...",
				dbmw_name(db_tokdata));
		}
		return NULL;
	}

	return td;
}

/**
 * Delete rootdata from database.
 */
static void
delete_tokdata(const kuid_t *id)
{
	dbmw_delete(db_tokdata, id);

	if (GNET_PROPERTY(dht_tcache_debug) > 2)
		g_message("DHT TCACHE security token from %s reclaimed",
			kuid_to_hex_string(id));
}

/**
 * Serialization routine for tdata.
 */
static void
serialize_tokdata(pmsg_t *mb, gconstpointer data)
{
	const struct tokdata *td = data;

	pmsg_write_time(mb, td->last_update);
	pmsg_write_u8(mb, td->length);
	pmsg_write(mb, td->token, td->length);
}

/**
 * Deserialization routine for rootdata.
 */
static gboolean
deserialize_tokdata(bstr_t *bs, gpointer valptr, size_t len)
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

	if (bstr_has_error(bs))
		return FALSE;
	else if (bstr_unread_size(bs)) {
		/* Something is wrong, we're not deserializing the right data */
		g_warning("DHT deserialization of tokdata: has %lu unread bytes",
			(gulong) bstr_unread_size(bs));
		return FALSE;
	}

	return TRUE;
}

/**
 * Free routine for tokdata, to release internally allocated memory, not
 * the structure itself.
 */
static void
free_tokdata(gpointer valptr, size_t len)
{
	struct tokdata *td = valptr;

	g_assert(sizeof *td == len);

	WFREE_NULL(td->token, td->length);
}

/**
 * Map iterator to record security tokens in the database.
 */
static void
record_token(gpointer key, gpointer value, gpointer unused_u)
{
	kuid_t *id = key;
	lookup_token_t *ltok = value;
	struct tokdata td;

	(void) unused_u;

	td.last_update = ltok->retrieved;
	td.length = ltok->token->length;
	td.token = td.length ? wcopy(ltok->token->v, td.length) : NULL;

	/*
	 * Data is put in the DBMW cache and the dynamically allocated token
	 * will be freed via free_tokdata() when the cached entry is released.
	 */

	if (!dbmw_exists(db_tokdata, id->v))
		gnet_stats_count_general(GNR_DHT_CACHED_TOKENS_HELD, +1);

	dbmw_write(db_tokdata, id->v, &td, sizeof td);
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
 *
 * @return TRUE if we found a token, with len_ptr and tok_ptr filled with
 * the information about the length and the token pointer.  Information is
 * returned from a static memory buffer so it must be perused immediately.
 */
gboolean
tcache_get(const kuid_t *id, guint8 *len_ptr, const void **tok_ptr)
{
	struct tokdata *td;

	g_assert(id != NULL);

	td = get_tokdata(id);

	if (NULL == td)
		return FALSE;

	if (delta_time(tm_time(), td->last_update) > TOK_LIFE) {
		delete_tokdata(id);
		gnet_stats_count_general(GNR_DHT_CACHED_TOKENS_HELD, -1);
		return FALSE;
	}

	if (len_ptr != NULL)	*len_ptr = td->length;
	if (tok_ptr != NULL)	*tok_ptr = td->token;

	gnet_stats_count_general(GNR_DHT_CACHED_TOKENS_HITS, 1);

	return TRUE;
}

/**
 * Initialize security token caching.
 */
void
tcache_init(void)
{
	db_tokdata = storage_create(db_tcache_what, db_tcache_base,
		KUID_RAW_SIZE, sizeof(struct tokdata),
			sizeof(struct tokdata) + MAX_INT_VAL(guint8),
		serialize_tokdata, deserialize_tokdata, free_tokdata,
		TOK_DB_CACHE_SIZE, sha1_hash, sha1_eq);

	dbmw_set_map_cache(db_tokdata, TOK_MAP_CACHE_SIZE);
}

/**
 * Close security token caching.
 */
void
tcache_close(void)
{
	storage_delete(db_tokdata);
	db_tokdata = NULL;
}

/* vi: set ts=4 sw=4 cindent: */
