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
	DHT_VT_BTAL		= FOURCC_NATIVE('B','T','A','L'),	/**< Bittorrent */
	DHT_VT_GTKG		= FOURCC_NATIVE('G','T','K','G'),
	DHT_VT_LIME		= FOURCC_NATIVE('L','I','M','E'),
	DHT_VT_NOPE		= FOURCC_NATIVE('N','O','P','E'),	/**< Node push entry */
	DHT_VT_PROX		= FOURCC_NATIVE('P','R','O','X'),	/**< Push-proxies */
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
 *
 * A solution would be to extend the message protocol to be able to specify
 * the expiration time of published values.  Nodes would know to estimate
 * that based on their average uptime for intance, or average IP stability time.
 * However this extension must be transparent to existing nodes, which is
 * a challenge.
 */
#define DHT_VALUE_EXPIRE		(4*60*60)	/**< 4 hours, default */
#define DHT_VALUE_ALOC_EXPIRE	(1*60*60)	/**< 1 hour for alt-locs */
#define DHT_VALUE_NOPE_EXPIRE	(1*60*60)	/**< 1 hour for node push entries */
#define DHT_VALUE_PROX_EXPIRE	(1*60*60)	/**< 1 hour for push-proxies */

/**
 * Value republishing time.
 *
 * Again, very low value chosen by the LimeWire team.
 */
#define DHT_VALUE_REPUBLISH		(60*60)		/**< 1 hour */

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
#define STORE_SC_DB_IO			15U	/**< Database I/O error */

#define STORE_SC_OUT_OF_RANGE	65533U	/**< Internal: out of k-closest set */
#define STORE_SC_FIREWALLED		65534U	/**< Internal: node is firewalled */
#define STORE_SC_TIMEOUT		65535U	/**< Internal: STORE timed-out */

struct dht_value;
typedef struct dht_value dht_value_t;

/*
 * Public interface.
 */

const kuid_t *dht_value_key(const dht_value_t *v);
const knode_t *dht_value_creator(const dht_value_t *v);
uint16 dht_value_length(const dht_value_t *v);
dht_value_type_t dht_value_type(const dht_value_t *v);

const char *dht_store_error_to_string(uint16 errnum);

dht_value_t *dht_value_make(const knode_t *creator,
	const kuid_t *primary_key, dht_value_type_t type,
	uint8 major, uint8 minor, void *data, uint16 length);
dht_value_t *dht_value_clone(const dht_value_t *v);
void dht_value_free(dht_value_t *v, bool free_data);
size_t dht_value_type_to_string_buf(uint32 type, char *buf, size_t size);
time_delta_t dht_value_lifetime(dht_value_type_t type);
const char *dht_value_type_to_string(uint32 type);
const char *dht_value_type_to_string2(uint32 type);
const char *dht_value_to_string(const dht_value_t *v);

unsigned dht_value_hash(const void *key);
bool dht_value_eq(const void *v1, const void *v2);
void dht_value_dump(FILE *out, const dht_value_t *v);

#endif /* _if_dht_value_h */

/* vi: set ts=4 sw=4 cindent: */

