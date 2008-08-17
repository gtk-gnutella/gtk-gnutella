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
 * Kademlia node lookups.
 *
 * @author Raphael Manfredi
 * @date 2008
 */

#ifndef _dht_lookup_h_
#define _dht_lookup_h_

#include "knode.h"
#include "values.h"

struct nlookup;
typedef struct nlookup nlookup_t;

/**
 * Lookup error codes.
 */
typedef enum {
	LOOKUP_E_OK = 0,			/**< No error */
	LOOKUP_E_CANCELLED,			/**< Lookup cancelled by user */
	LOOKUP_E_UDP_CLOGGED,		/**< Outgoing UDP traffic clogged */
	LOOKUP_E_NO_REPLY,			/**< Lack of RPC replies */
	LOOKUP_E_NOT_FOUND,			/**< Value not found */
	LOOKUP_E_EXPIRED,			/**< Lookup expired */

	LOOKUP_E_MAX				/**< Amount of error codes defined */
} lookup_error_t;

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
 * Value lookup result record.
 */
typedef struct lookup_value_rc {
	gconstpointer data;			/**< The data payload */
	size_t length;				/**< Length of value, in bytes */
	host_addr_t addr;			/**< Address of creator */
	dht_value_type_t type;		/**< Type of value */
	guint16 port;				/**< Port of creator */
	guint8 major;				/**< Major version of value */
	guint8 minor;				/**< Minor version of value */
} lookup_val_rc_t;

/**
 * Value lookup result set.
 */
typedef struct lookup_value {
	lookup_val_rc_t *records;	/**< Array of records */
	size_t count;				/**< Amount of records in array */
	float load;					/**< Reported request load on key */
} lookup_val_rs_t;

/**
 * Node lookup callback invoked when OK.
 *
 * @param kuid		the KUID that was looked for
 * @param rs		the result set
 * @param arg		additional callback opaque argument
 */
typedef void (*lookup_cb_ok_t)(
	const kuid_t *kuid, const lookup_rs_t *rs, gpointer arg);

/**
 * Value lookup callback invoked when OK.
 *
 * @param kuid		the KUID that was looked for
 * @param rs		the result set
 * @param arg		additional callback opaque argument
 */
typedef void (*lookup_cbv_ok_t)(
	const kuid_t *kuid, const lookup_val_rs_t *rs, gpointer arg);

/**
 * Lookup callback invoked on error (both for value lookups and node lookups).
 *
 * @param kuid		the KUID that was looked for
 * @param error		the error code
 * @param arg		additional callback opaque argument
 */
typedef void (*lookup_cb_err_t)(
	const kuid_t *kuid, lookup_error_t error, gpointer arg);

/*
 * Public interface.
 */

void lookup_init(void);
void lookup_close(void);

const char *lookup_strerror(lookup_error_t error);

nlookup_t *lookup_bucket_refresh(const kuid_t *kuid,
	lookup_cb_err_t done, gpointer arg);
nlookup_t *lookup_find_value(const kuid_t *kuid, dht_value_type_t type,
	lookup_cbv_ok_t ok, lookup_cb_err_t error, gpointer arg);
nlookup_t *lookup_find_node(const kuid_t *kuid,
	lookup_cb_ok_t ok, lookup_cb_err_t error, gpointer arg);

void lookup_cancel(nlookup_t *nl, gboolean callback);
void lookup_free_results(lookup_rs_t *rs);
void lookup_free_value_results(lookup_val_rs_t *rs);

#endif	/* _dht_lookup_h_ */

/* vi: set ts=4 sw=4 cindent: */
