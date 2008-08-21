/*
 * $Id$
 *
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
 *      59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
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

#include "if/dht/lookup.h"

#include "knode.h"
#include "values.h"

struct nlookup;
typedef struct nlookup nlookup_t;

/**
 * Lookup types.
 */
typedef enum {
	LOOKUP_NODE = 1,			/**< Node lookup */
	LOOKUP_VALUE,				/**< Value lookup */
	LOOKUP_REFRESH,				/**< Refresh lookup */
} lookup_type_t;

/**
 * Node lookup result record.
 */
typedef struct lookup_rc {
	knode_t *kn;				/**< A Kademlia node */
	void *token;				/**< The security token (NULL if none) */
	guint8 token_len;			/**< Length of security token */
} lookup_rc_t;

/**
 * Node lookup result set.
 *
 * NB: path can contain more than the k-closest nodes, but the first k entries
 * are the k-closest.  It can also contain less than k items, if we were
 * unable to find closer nodes.
 */
typedef struct lookup_result {
	lookup_rc_t *path;			/**< Lookup path, closest node first */
	size_t path_len;			/**< Amount of entries in lookup path */
} lookup_rs_t;

/**
 * Node lookup callback invoked when OK.
 *
 * @param kuid		the KUID that was looked for
 * @param rs		the result set
 * @param arg		additional callback opaque argument
 */
typedef void (*lookup_cb_ok_t)(
	const kuid_t *kuid, const lookup_rs_t *rs, gpointer arg);

/*
 * Public interface.
 */

void lookup_init(void);
void lookup_close(void);

nlookup_t *lookup_bucket_refresh(const kuid_t *kuid,
	lookup_cb_err_t done, gpointer arg);
nlookup_t *lookup_find_value(const kuid_t *kuid, dht_value_type_t type,
	lookup_cbv_ok_t ok, lookup_cb_err_t error, gpointer arg);
nlookup_t *lookup_find_node(const kuid_t *kuid,
	lookup_cb_ok_t ok, lookup_cb_err_t error, gpointer arg);

void lookup_cancel(nlookup_t *nl, gboolean callback);
void lookup_free_results(const lookup_rs_t *rs);

#endif	/* _dht_lookup_h_ */

/* vi: set ts=4 sw=4 cindent: */
