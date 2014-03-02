/*
 * Copyright (c) 2001-2003, Raphael Manfredi, Richard Eckart
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

#ifndef _if_core_hcache_h_
#define _if_core_hcache_h_

#include "common.h"

/***
 *** Gnet host cache
 ***/

typedef enum {
	HCACHE_FRESH_ANY = 0, /**< Fresh hosts to which we did not
                               yet try to connect. */
    HCACHE_VALID_ANY,     /**< All the Gnet nodes to which we were able to
                               connect and transmit at least one packet
                               (indicating a successful handshake). */
	HCACHE_FRESH_ULTRA,	  /**< Fresh IPv4 ultra nodes to which we did not
                               yet try to connect. (X-Try-Ultrapeer)*/
    HCACHE_VALID_ULTRA,   /**< Valid IPv4 ultra nodes */
	HCACHE_FRESH_ULTRA6,  /**< Fresh IPv6 ultra nodes to which we did not
                               yet try to connect. (X-Try-Ultrapeer)*/
    HCACHE_VALID_ULTRA6,  /**< Valid IPv6 ultra nodes */
    HCACHE_TIMEOUT,       /**< We put in this list all the Gnet nodes which
                               gave us a timeout during connection. */
    HCACHE_BUSY,          /**< We put in this list all the Gnet nodes which
                               gave us a 503 (busy) during connection. */
    HCACHE_UNSTABLE,      /**< Unstable IPs */
    HCACHE_ALIEN,         /**< Alien networks (protected by auth challenges) */
    HCACHE_GUESS,         /**< Running GUESS IPv4 cache (MRU-managed) */
    HCACHE_GUESS_INTRO,   /**< GUESS IPv4 introduction cache (LRU-managed) */
    HCACHE_GUESS6,        /**< Running GUESS IPv6 cache (MRU-managed) */
    HCACHE_GUESS6_INTRO,  /**< GUESS IPv6 introduction cache (LRU-managed) */
	HCACHE_FRESH_G2HUB,   /**< Fresh IPv4 G2 hubs to which we did not connect */
	HCACHE_VALID_G2HUB,   /**< Valid IPv4 G2 hubs */
	HCACHE_NONE,
    HCACHE_MAX
} hcache_type_t;

typedef enum {
    HOST_ANY = 0,
    HOST_ULTRA,
    HOST_ULTRA6,
    HOST_GUESS,
    HOST_GUESS6,
    HOST_G2HUB,
    HOST_MAX
} host_type_t;

typedef enum {
    HOST_NET_IPV4,
    HOST_NET_IPV6,
    HOST_NET_BOTH,
    HOST_NET_MAX
} host_net_t;

typedef enum {
	HCACHE_CLASS_HOST,		/**< Classic Gnutella host cache */
	HCACHE_CLASS_G2,		/**< Classic G2 host cache */
	HCACHE_CLASS_GUESS		/**< GUESS-specific host cache */
} hcache_class_t;

typedef struct hcache_stats {
    int32  host_count;		/**< Number of hosts in cache */
    uint32 hits;			/**< Hits to known hosts */
    uint32 misses;			/**< Total number of misses (added hosts) */
    bool   reading;			/**< TRUE if currently reading from disk */
} hcache_stats_t;

/*
 * Public interface, visible from the bridge.
 */

#ifdef CORE_SOURCES

void hcache_clear_host_type(host_type_t type);
void hcache_clear(hcache_type_t type);
void hcache_get_stats(hcache_stats_t *stats);

#endif /* CORE_SOURCES */
#endif /* _if_core_hcache_h_ */

/* vi: set ts=4 sw=4 cindent: */
