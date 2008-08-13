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
 * Local values management.
 *
 * @author Raphael Manfredi
 * @date 2008
 */

#ifndef _dht_values_h_
#define _dht_values_h_

#include "knode.h"
#include "kuid.h"

#define VALUE_TYPE_CODE(a,b,c,d) (	\
	((guint32) (a) << 24) | \
	((guint32) (b) << 16) | \
	((guint32) (c) << 8)  | \
	((guint32) (d)))

/**
 * Value types.
 *
 * We use an enum so that we can dispose of the macro helper afterwards.
 */
typedef enum {
	DHT_VT_BINARY	= 0x00000000,
	DHT_VT_GTKG		= VALUE_TYPE_CODE('G','T','K','G'),
	DHT_VT_LIME		= VALUE_TYPE_CODE('L','I','M','E'),
	DHT_VT_TEXT		= VALUE_TYPE_CODE('T','E','X','T'),
	DHT_VT_TEST		= VALUE_TYPE_CODE('T','E','S','T'),
	DHT_VT_ANY		= VALUE_TYPE_CODE('*','*','*','*'),
} dht_value_type_t;

#undef VALUE_TYPE_CODE

#define VALUE_MAX_LEN	512		/**< Max value size */

/**
 * A DHT value.
 */
typedef struct {
	const knode_t *creator;	/**< The creator of the value */
	const kuid_t *id;		/**< The key of the value (atom) */
	dht_value_type_t type;	/**< Type of values */
	guint8 major;			/**< Value's major version */
	guint8 minor;			/**< Value's minor version */
	guint16 length;			/**< Length of value */
	gconstpointer data;		/**< The actual data value */
} dht_value_t;

/*
 * Public interface.
 */

void values_init(void);
void values_close(void);

size_t values_count(void);

/*
 * DHT values.
 */

dht_value_t *
dht_value_make(const knode_t *creator,
	kuid_t *primary_key, dht_value_type_t type,
	guint8 major, guint8 minor, gpointer data, guint16 length);
void dht_value_free(dht_value_t *v);
size_t dht_value_type_to_string_buf(guint32 type, char *buf, size_t size);
const char *dht_value_type_to_string(guint32 type);
const char *dht_value_to_string(const dht_value_t *v);

guint16 values_store(const knode_t *kn, const dht_value_t *v, gboolean token);
dht_value_t *values_get(guint64 dbkey, dht_value_type_t type);

#endif /* _dht_values_h_ */

/* vi: set ts=4 sw=4 cindent: */
