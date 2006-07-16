/*
 * $Id$
 *
 * Copyright (c) 2006, Raphael Manfredi
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
 * Kademlia routing table.
 *
 * The Kademlia routing table is the central data structure governing all
 * the DHT operations pertaining to distribution (the 'D' of DHT).
 *
 * @author Raphael Manfredi
 * @date 2006
 */

#include "common.h"

RCSID("$Id$");

#include "routing.h"
#include "kuid.h"

#include "if/gnet_property.h"
#include "if/gnet_property_priv.h"

#include "lib/hashlist.h"
#include "lib/walloc.h"
#include "lib/override.h"		/* Must be the last header included */

/**
 * The routing table is a binary tree.  Each node holds a k-bucket containing
 * the contacts whose KUID falls within the range of the k-bucket.
 */
struct knode {
	kuid_t prefix;				/**< Node prefix of the k-bucket */
	struct knode *parent;		/**< Parent node in the tree */
	struct knode *zero;			/**< Child node for "0" prefix */
	struct knode *one;			/**< Child node for "1" prefix */
	hash_list_t *good;			/**< The good nodes */
	hash_list_t *stale;			/**< The (possibly) stale nodes */
	hash_list_t *pending;		/**< The nodes which are awaiting decision */
	time_t last_refresh;		/**< Last time bucket was refreshed */
	guchar depth;				/**< Depth in tree (meaningful bits) */
	gboolean ours;				/**< Whether our KUID falls in that bucket */
};

static struct knode *root = NULL;	/**< The root of the routing table tree. */
static kuid_t our_kuid;				/**< Our own KUID */

/**
 * Initialize routing table management.
 */
void
dht_route_init(void)
{
	gint i;
	gboolean need_kuid = TRUE;

	/*
	 * Only generate a new KUID for this servent if all entries are 0.
	 * The empty initialization happens in config_init(), but it can be
	 * overridden by the KUID read from the configuration file.
	 */

	gnet_prop_get_storage(PROP_SERVENT_KUID, our_kuid.v, sizeof our_kuid.v);

	for (i = 0; i < KUID_RAW_SIZE; i++) {
		if (our_kuid.v[i]) {
			need_kuid = FALSE;
			break;
		}
	}

	if (need_kuid) {
		if (dht_debug) g_message("generating new DHT node ID");
		kuid_random_fill(&our_kuid);
		gnet_prop_set_storage(PROP_SERVENT_KUID, our_kuid.v, sizeof our_kuid.v);
	}

	if (dht_debug)
		g_message("DHT local node ID is %s", kuid_to_string(&our_kuid));

	/*
	 * Allocate root node for the routing table.
	 */

	root = walloc0(sizeof *root);
	root->ours = TRUE;
}

/**
 * Free bucket's hashlist.
 */
static void
dht_free_node_hashlist(hash_list_t *hl)
{
	guint count;

	g_assert(hl != NULL);

	count = hash_list_length(hl);

	if (count)
		g_warning("freeing hashlist with %u items at %s", count, _WHERE_);

	hash_list_free(hl);
}

/**
 * Free bucket node.
 */
static void
dht_free_knode(struct knode *kn)
{
	if (kn->good != NULL) {
		dht_free_node_hashlist(kn->good);
		kn->good = NULL;
	}
	if (kn->stale != NULL) {
		dht_free_node_hashlist(kn->stale);
		kn->good = NULL;
	}
	if (kn->pending != NULL) {
		dht_free_node_hashlist(kn->pending);
		kn->good = NULL;
	}

	wfree(kn, sizeof *kn);
}

/**
 * Shutdown routing table at exit time.
 */
void
dht_route_close(void)
{
}


/* vi: set ts=4 sw=4 cindent: */
