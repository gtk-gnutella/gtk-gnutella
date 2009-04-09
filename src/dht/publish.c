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
 * Kademlia value publishing.
 *
 * @author Raphael Manfredi
 * @date 2009
 */

#include "common.h"

RCSID("$Id$")

#include "publish.h"
#include "lookup.h"
#include "knode.h"

#include "if/dht/kademlia.h"
#include "if/dht/value.h"
#include "if/gnet_property_priv.h"

#include "lib/map.h"
#include "lib/patricia.h"
#include "lib/walloc.h"
#include "lib/override.h"		/* Must be the last header included */

/**
 * Table keeping track of all the publish objects that we have created
 * and which are still running.
 */
static GHashTable *publishes;

struct publish_id {
	guint64 value;
};

typedef enum {
	PUBLISH_MAGIC = 0x647dfaf7U
} publish_magic_t;

/**
 * Publishing context.
 */
typedef struct publish {
	publish_magic_t magic;
	struct publish_id pid;		/**< Publish ID (unique to this object) */
	kuid_t *key;				/**< The STORE key */
	lookup_rs_t *result;		/**< Node lookup results */
	dht_value_t **vvec;			/**< Value vector to store */
	int vcnt;					/**< Amount of values in vvec (= size) */
} publish_t;

static inline void
publish_check(const publish_t *pb)
{
	g_assert(pb);
	g_assert(PUBLISH_MAGIC == pb->magic);
}

/**
 * Check whether the given publish object with specified publish ID is still
 * alive. This is necessary because publishes are asynchronous and an RPC reply
 * may come back after the publish was terminated...
 *
 * @return NULL if the publish ID is unknown, otherwise the publish object
 */
static inline publish_t *
publish_is_alive(struct publish_id pid)
{
	publish_t *pb;

	if (NULL == publishes)
		return NULL;

	pb = g_hash_table_lookup(publishes, &pid);

	if (pb) {
		publish_check(pb);
	}

	return pb;
}

static struct publish_id
publish_id_create(void)
{
	static struct publish_id id;

	id.value++;						/* Avoid using zero as valid ID */
	g_assert(0 != id.value);		/* Game Over! */
	return id;
}

/** 
 * Create a new publish-once request.
 *
 * This is used to cache values returned by a FIND_VALUE, to the first node
 * closest to the key that did not return the value.
 *
 * @param key		the primary key for accessing published values
 * ...etc...
 */
static inline publish_t *
publish_create(const kuid_t *key /* etc... */)
{
	publish_t *pb;

	pb = walloc0(sizeof *pb);
	pb->magic = PUBLISH_MAGIC;
	pb->pid = publish_id_create();
	pb->key = kuid_get_atom(key);

	/* XXX */

	return pb;
}

/**
 * Destroy a publish request.
 */
static void
publish_free(publish_t *pb, gboolean can_remove)
{
	publish_check(pb);

	kuid_atom_free_null(&pb->key);

	/* XXX */

	if (can_remove)
		g_hash_table_remove(publishes, &pb->pid);

	pb->magic = 0;
	wfree(pb, sizeof *pb);
}

static unsigned
publish_id_hash(const void *key)
{
	const struct publish_id *id = key;
	return (unsigned) (id->value >> 32) ^ (unsigned) id->value;
}

static int
publish_id_equal(const void *p, const void *q)
{
	const struct publish_id *a = p, *b = q;
	return a->value == b->value;
}

/**
 * Initialize Kademlia publishing.
 */
void
publish_init(void)
{
	publishes = g_hash_table_new(publish_id_hash, publish_id_equal);
}

/** 
 * Hashtable iteration callback to free the publish_t object held as the key.
 */
static void
free_publish(gpointer key, gpointer unused_value, gpointer unused_data)
{
	publish_t *pb = key;

	publish_check(pb);
	g_assert(key == &pb->pid);
	(void) unused_value;
	(void) unused_data;

	publish_free(pb, FALSE);		/* No removal whilst we iterate! */
}

/**
 * Cleanup data structures used by Kademlia publishing.
 */
void
publish_close(void)
{
	g_hash_table_foreach(publishes, free_publish, NULL);
	g_hash_table_destroy(publishes);
	publishes = NULL;
}

/* vi: set ts=4 sw=4 cindent: */
