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

#ifndef _if_dht_value_h_
#define _if_dht_value_h_

#include "common.h"

#include "kuid.h"
#include "knode.h"

#include "lib/tm.h"

/**
 * Value types.
 *
 * We use an enum so that we can dispose of the macro helper afterwards.
 */
typedef enum {
	DHT_VT_BINARY	= 0x00000000,
	DHT_VT_ALOC		= FOURCC_NATIVE('A','L','O','C'),	/**< Gnutella alt-loc */
	DHT_VT_BTAL		= FOURCC_NATIVE('B','T','A','L'),	/**< Bittorrent alt-loc */
	DHT_VT_GTKG		= FOURCC_NATIVE('G','T','K','G'),
	DHT_VT_LIME		= FOURCC_NATIVE('L','I','M','E'),
	DHT_VT_PROX		= FOURCC_NATIVE('P','R','O','X'),
	DHT_VT_TEST		= FOURCC_NATIVE('T','E','S','T'),
	DHT_VT_TEXT		= FOURCC_NATIVE('T','E','X','T'),

	DHT_VT_ANY		= FOURCC_NATIVE('*','*','*','*')
} dht_value_type_t;

#define DHT_VALUE_MAX_LEN	512		/**< Max value size */

/**
 * Value expiration time (republishing should occur before expiration).
 *
 * The 1 hour expiration time may seem low, but LimeWire uses that and
 * it probably makes sense in a highly transient environment.  However,
 * with such a low expiration time, it would have been wiser to choose
 * a KDA_K < 20.
 */
#define DHT_VALUE_EXPIRE		(4*60*60)	/**< 4 hours, default */
#define DHT_VALUE_ALOC_EXPIRE	(1*60*60)	/**< 1 hour for alt-locs */
#define DHT_VALUE_PROX_EXPIRE	(1*60*60)	/**< 1 hour for push-proxies */

/**
 * Value republishing time.
 *
 * Again, very low value chosen by the LimeWire team.
 */
#define DHT_VALUE_REPUBLISH		(30*60)		/**< 30 minutes */

/**
 * The size of the DHT value header, preceding the actual data value
 * (fixed because IP address of creator must be given as IPv4)
 */
#define DHT_VALUE_HEADER_SIZE	61

/**
 * Maximum size of a serialized DHT value.
 */
#define DHT_VALUE_MAX_SERIAL_SIZE	(DHT_VALUE_HEADER_SIZE + DHT_VALUE_MAX_LEN)

/**
 * Store status codes.
 */
#define STORE_SC_OK				1U	/**< OK */
#define STORE_SC_ERROR			2U	/**< Generic error */
#define STORE_SC_FULL			3U	/**< Node is full for this key */
#define STORE_SC_LOADED			4U	/**< Node is too loaded for this key */
#define STORE_SC_FULL_LOADED	5U	/**< Node is both loaded and full */
#define STORE_SC_TOO_LARGE		6U	/**< Value is too large */
#define STORE_SC_EXHAUSTED		7U	/**< Storage space exhausted */
#define STORE_SC_BAD_CREATOR	8U	/**< Creator is not acceptable */
#define STORE_SC_BAD_VALUE		9U	/**< Analyzed value did not validate */
#define STORE_SC_BAD_TYPE		10U	/**< Improper value type */
#define STORE_SC_QUOTA			11U /**< Storage quota for creator reached */
#define STORE_SC_DATA_MISMATCH	12U /**< Replicated data is different */
#define STORE_SC_BAD_TOKEN		13U /**< Invalid security token */
#define STORE_SC_EXPIRED		14U	/**< Value has already expired */

/**
 * A DHT value.
 */
typedef struct {
	const knode_t *creator;	/**< The creator of the value */
	kuid_t *id;				/**< The key of the value (atom) */
	dht_value_type_t type;	/**< Type of values */
	guint8 major;			/**< Value's major version */
	guint8 minor;			/**< Value's minor version */
	guint16 length;			/**< Length of value */
	gconstpointer data;		/**< The actual data value */
} dht_value_t;

/*
 * Public interface.
 */

const char *dht_store_error_to_string(guint16 errnum);

dht_value_t *dht_value_make(const knode_t *creator,
	kuid_t *primary_key, dht_value_type_t type,
	guint8 major, guint8 minor, gpointer data, guint16 length);
dht_value_t *dht_value_clone(const dht_value_t *v);
void dht_value_free(dht_value_t *v, gboolean free_data);
size_t dht_value_type_to_string_buf(guint32 type, char *buf, size_t size);
time_delta_t dht_value_lifetime(dht_value_type_t type);
const char *dht_value_type_to_string(guint32 type);
const char *dht_value_type_to_string2(guint32 type);
const char *dht_value_to_string(const dht_value_t *v);

#endif /* _if_dht_value_h */

/* vi: set ts=4 sw=4 cindent: */

