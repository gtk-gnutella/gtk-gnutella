/*
 * Copyright (c) 2008, Raphael Manfredi
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
 * @ingroup dht
 * @file
 *
 * Kademlia node/value lookups.
 *
 * @author Raphael Manfredi
 * @date 2008
 */

#ifndef _dht_lookup_h_
#define _dht_lookup_h_

#include "common.h"

#include "if/dht/lookup.h"

#include "knode.h"
#include "values.h"
#include "lib/sectoken.h"

/**
 * A security token, as gathered during node lookups.
 */
typedef struct lookup_token {
	time_t retrieved;			/**< Retrieval time */
	sectoken_remote_t *token;	/**< Their security token */
} lookup_token_t;

struct nlookup;
typedef struct nlookup nlookup_t;

/**
 * Lookup types.
 */
typedef enum {
	LOOKUP_NODE = 1,			/**< Node lookup */
	LOOKUP_VALUE,				/**< Value lookup */
	LOOKUP_STORE,				/**< Node lookup before s STORE */
	LOOKUP_TOKEN,				/**< Security token lookup */
	LOOKUP_REFRESH				/**< Refresh lookup */
} lookup_type_t;

/**
 * Lookup statistics.
 */
struct lookup_stats {
	double elapsed;				/**< Elapsed time in seconds */
	int msg_sent;				/**< Amount of messages sent */
	int msg_dropped;			/**< Amount of messages dropped */
	int rpc_replies;			/**< Amount of valid RPC replies */
	int bw_outgoing;			/**< Amount of outgoing bandwidth used */
	int bw_incoming;			/**< Amount of incoming bandwidth used */
};

/**
 * Node lookup callback invoked to provide statistics upon completion.
 *
 * @param kuid		the KUID that was looked for
 * @param stats		the lookup stats
 * @param arg		additional callback opaque argument
 */
typedef void (*lookup_cb_stats_t)(
	const kuid_t *kuid, const struct lookup_stats *ls, void *arg);

/**
 * Node lookup result record.
 */
typedef struct lookup_rc {
	knode_t *kn;				/**< A Kademlia node */
	void *token;				/**< The security token (NULL if none) */
	uint8 token_len;			/**< Length of security token */
} lookup_rc_t;

typedef enum {
	LOOKUP_RESULT_MAGIC = 0x5f46d447U
} lookup_rs_magic_t;

/**
 * Node lookup result set.
 *
 * NB: path can contain more than the k-closest nodes, but the first k entries
 * are the k-closest.  It can also contain less than k items, if we were
 * unable to find closer nodes.
 */
struct lookup_result {
	lookup_rs_magic_t magic;	/**< Magic number */
	int refcnt;					/**< Reference count */
	lookup_rc_t *path;			/**< Lookup path, closest node first */
	size_t path_len;			/**< Amount of entries in lookup path */
};

static inline void
lookup_result_check(const lookup_rs_t *rs)
{
	g_assert(rs != NULL);
	g_assert(LOOKUP_RESULT_MAGIC == rs->magic);
	g_assert(rs->refcnt > 0);
}

/*
 * Public interface.
 */

void lookup_init(void);
void lookup_close(bool exiting);

nlookup_t *lookup_bucket_refresh(const kuid_t *kuid, size_t bits,
	lookup_cb_err_t done, void *arg);
nlookup_t *lookup_find_value(const kuid_t *kuid, dht_value_type_t type,
	lookup_cbv_ok_t ok, lookup_cb_err_t error, void *arg);
nlookup_t *lookup_find_node(const kuid_t *kuid,
	lookup_cb_ok_t ok, lookup_cb_err_t error, void *arg);
nlookup_t *lookup_store_nodes(const kuid_t *kuid,
	lookup_cb_ok_t ok, lookup_cb_err_t error, void *arg);
nlookup_t *lookup_token(const knode_t *kn,
	lookup_cb_ok_t ok, lookup_cb_err_t error, void *arg);

void lookup_ctrl_stats(nlookup_t *nl, lookup_cb_stats_t stats);
void lookup_cancel(nlookup_t *nl, bool callback);

#endif	/* _dht_lookup_h_ */

/* vi: set ts=4 sw=4 cindent: */
