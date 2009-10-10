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
 * @ingroup core
 * @file
 *
 * Shared file DHT publisher.
 *
 * The publisher records the SHA1 of all the files that are shared locally
 * by the Gnutella node, either full or partial.
 *
 * Periodically, it wakes up and requests DHT publishing of these files,
 * if still shared and if not too popular, to make sure that their entries
 * do not expire in the DHT.
 *
 * @author Raphael Manfredi
 * @date 2009
 */

#include "common.h"

RCSID("$Id$")

#include "publisher.h"
#include "share.h"
#include "pdht.h"
#include "dmesh.h"
#include "gnet_stats.h"
#include "fileinfo.h"

#include "if/dht/dht.h"
#include "if/dht/kademlia.h"
#include "if/dht/value.h"
#include "if/core/net_stats.h"

#include "if/gnet_property_priv.h"

#include "lib/atoms.h"
#include "lib/cq.h"
#include "lib/glib-missing.h"
#include "lib/misc.h"
#include "lib/tm.h"
#include "lib/stringify.h"
#include "lib/walloc.h"
#include "lib/override.h"		/* Must be the last header included */

#define PUBLISHER_CALLOUT	10000	/**< Heartbeat every 10 seconds */
#define PUBLISH_SAFETY		(5*60)	/**< Safety before expiration: 5 min */
#define PUBLISH_POPULAR		7200	/**< 2 hour delay for popular files */
#define PUBLISH_BUSY		600		/**< Retry after 10 minutes */
#define PUBLISH_DMESH_MAX	5		/**< File popularity by dmesh entry count */

typedef enum { PUBLISHER_MAGIC = 0x7592fb8fU } publisher_magic_t;

/**
 * A to-be-published entry.
 */
struct publisher_entry {
	publisher_magic_t magic;
	const sha1_t *sha1;			/**< SHA1 of file (atom) */
	cevent_t *publish_ev;		/**< Republish event */
	time_t last_enqueued;		/**< When file was last enqueued */
	time_t last_publish;		/**< When file was last published */
};

static inline void
publisher_check(const struct publisher_entry *pe)
{
	g_assert(pe != NULL);
	g_assert(PUBLISHER_MAGIC == pe->magic);
}

static GHashTable *publisher_sha1;	/** Known entries by SHA1 */

static void publisher_handle(struct publisher_entry *pe);

/**
 * Private callout queue used to trigger republish events.
 */
static cqueue_t *publish_cq;

/**
 * Allocate new publisher entry.
 */
static struct publisher_entry *
publisher_entry_alloc(const sha1_t *sha1)
{
	struct publisher_entry *pe;

	pe = walloc0(sizeof *pe);
	pe->magic = PUBLISHER_MAGIC;
	pe->sha1 = atom_sha1_get(sha1);

	return pe;
}

/**
 * Free publisher entry.
 */
static void
publisher_entry_free(struct publisher_entry *pe, gboolean do_remove)
{
	publisher_check(pe);

	if (do_remove)
		g_hash_table_remove(publisher_sha1, pe->sha1);

	atom_sha1_free_null(&pe->sha1);
	cq_cancel(publish_cq, &pe->publish_ev);
	wfree(pe, sizeof *pe);
}

/**
 * Callout queue callback to handle an entry.
 */
static void
handle_entry(cqueue_t *unused_cq, gpointer obj)
{
	struct publisher_entry *pe = obj;

	(void) unused_cq;
	publisher_check(pe);

	pe->publish_ev = NULL;
	publisher_handle(pe);
}

/**
 * Retry publishing after some delay.
 *
 * @param pe		the entry to publish
 * @param delay		delay in seconds
 */
static void
publisher_retry(struct publisher_entry *pe, int delay)
{
	publisher_check(pe);
	g_assert(NULL == pe->publish_ev);
	
	pe->publish_ev = cq_insert(publish_cq, delay * 1000, handle_entry, pe);
}

/**
 * Publishing callback invoked when asynchronous publication is completed,
 * or ended with an error.
 */
static void
publisher_done(gpointer arg, pdht_error_t code, unsigned roots)
{
	struct publisher_entry *pe = arg;
	int delay;
	
	publisher_check(pe);

	/*
	 * Compute retry delay.
	 */

	switch (code) {
	case PDHT_E_OK:
		/*
		 * If we were not able to publish to KDA_K nodes, decrease the
		 * delay before republishing.
		 */

		delay = DHT_VALUE_ALOC_EXPIRE * roots / KDA_K - PUBLISH_SAFETY;
		delay = MAX(delay, PUBLISH_SAFETY);
		break;
	case PDHT_E_POPULAR:
		delay = PUBLISH_POPULAR;
		break;
	case PDHT_E_NOT_SHARED:
		if (GNET_PROPERTY(publisher_debug)) {
			g_message("PUBLISHER SHA-1 %s is no longer shared",
				sha1_to_string(pe->sha1));
		}
		publisher_entry_free(pe, TRUE);
		return;
	case PDHT_E_LOOKUP_EXPIRED:
	case PDHT_E_LOOKUP:
	case PDHT_E_UDP_CLOGGED:
	case PDHT_E_PUBLISH_EXPIRED:
	case PDHT_E_PUBLISH_ERROR:
	case PDHT_E_SHA1:
	case PDHT_E_PENDING:
	case PDHT_E_CANCELLED:
	case PDHT_E_GGEP:
	case PDHT_E_NONE:
		delay = PUBLISH_BUSY;
		break;
	case PDHT_E_MAX:
		g_assert_not_reached();
	}

	if (GNET_PROPERTY(publisher_debug) > 1) {
		shared_file_t *sf = shared_file_by_sha1(pe->sha1);
		char retry[80];
		char after[80];
		const char *late = "";

		after[0] = '\0';
		if (pe->last_publish) {
			time_delta_t elapsed = delta_time(tm_time(), pe->last_publish);
			gm_snprintf(after, sizeof after,
				" after %s", compact_time(elapsed));
			if (elapsed > DHT_VALUE_ALOC_EXPIRE)
				late = "late, ";
		}

		gm_snprintf(retry, sizeof retry, "%s", compact_time(delay));

		g_message("PUBLISHER SHA-1 %s %s\"%s\" %spublished to %u node%s%s: %s"
			" (%stook %s, retry in %s)", sha1_to_string(pe->sha1),
			(sf && sf != SHARE_REBUILDING && shared_file_is_partial(sf)) ?
				"partial " : "",
			(sf && sf != SHARE_REBUILDING) ? shared_file_name_nfc(sf) : "",
			pe->last_publish ? "re" : "",
			roots, 1 == roots ? "" : "s", after, pdht_strerror(code),
			late, compact_time(delta_time(tm_time(), pe->last_enqueued)),
			retry);
	}

	/*
	 * Update stats on publishing success.
	 */

	if (PDHT_E_OK == code) {
		if (pe->last_publish && roots > 0) {
			time_delta_t elapsed = delta_time(tm_time(), pe->last_publish);

			if (elapsed > DHT_VALUE_ALOC_EXPIRE)
				gnet_stats_count_general(GNR_DHT_REPUBLISHED_LATE, +1);
		}
		if (roots > 0) {
			pe->last_publish = tm_time();
		}
	}

	publisher_retry(pe, delay);
}

/**
 * Handle a SHA-1 entry, publishing its alt-loc to the DHT if still shared.
 */
static void
publisher_handle(struct publisher_entry *pe)
{
	shared_file_t *sf;
	gboolean is_partial = FALSE;
	int alt_locs;

	publisher_check(pe);
	g_assert(NULL == pe->publish_ev);

	sf = shared_file_by_sha1(pe->sha1);

	/*
	 * Remove SHA1 if no longer shared.
	 */

	if (NULL == sf) {
		if (GNET_PROPERTY(publisher_debug)) {
			g_message("PUBLISHER SHA-1 %s is no longer shared",
				sha1_to_string(pe->sha1));
		}
		publisher_entry_free(pe, TRUE);
		return;
	}

	if (sf == SHARE_REBUILDING) {
		publisher_retry(pe, PUBLISH_BUSY);
		return;
	}

	is_partial = shared_file_is_partial(sf);

	/*
	 * If rebuilding the library or the SHA1 is not available, wait.
	 */

	if (
		!is_partial &&
		(!sha1_hash_available(sf) || !sha1_hash_is_uptodate(sf))
	) {
		publisher_retry(pe, PUBLISH_BUSY);
		return;
	}

	/*
	 * If we are dealing with a file for which we know enough alternate
	 * locations, assume it is popular and do not publish it yet.
	 *
	 * We do not publish the SHA-1 of a partial file for which we know
	 * of at least two alternate locations because the purpose of us publishing
	 * these partial SHA-1s is to attract other PFSP-aware hosts and
	 * recreate a mesh.
	 */

	alt_locs = dmesh_count(pe->sha1);

	if (alt_locs > (is_partial ? 1 : PUBLISH_DMESH_MAX)) {
		if (GNET_PROPERTY(publisher_debug)) {
			g_message("PUBLISHER SHA-1 %s %s\"%s\" has %d download mesh "
				"entr%s, skipped", sha1_to_string(pe->sha1),
				is_partial ? "partial " : "",
				shared_file_name_nfc(sf),
				alt_locs, 1 == alt_locs ? "y" : "ies");
		}
		publisher_retry(pe, PUBLISH_POPULAR);
		return;
	}

	/*
	 * If the DHT is not enabled, postpone processing.
	 */

	if (!dht_enabled()) {
		publisher_retry(pe, PUBLISH_BUSY);
		return;
	}

	/*
	 * If this is a partial file for which we have less than the minimum
	 * for PFSP sharing, or if PFSP has been disabled, skip it.
	 */

	if (shared_file_is_partial(sf)) {
		fileinfo_t *fi = shared_file_fileinfo(sf);

		if (
			!GNET_PROPERTY(pfsp_server) ||
			fi->done < GNET_PROPERTY(pfsp_minimum_filesize)
		) {
			publisher_retry(pe, PUBLISH_BUSY);
			return;
		}
	}

	/*
	 * OK, we can publish this alternate location.
	 */

	if (pe->last_publish) {
		if (GNET_PROPERTY(publisher_debug) > 2) {
			g_message("PUBLISHER SHA-1 %s re-enqueued %d secs "
				"after last publish", sha1_to_string(pe->sha1),
				(int) delta_time(tm_time(), pe->last_publish));
		}
	}

	pe->last_enqueued = tm_time();
	pdht_publish_file(sf, publisher_done, pe);
}

/**
 * Record a SHA1 for publishing.
 */
void
publisher_add(const sha1_t *sha1)
{
	struct publisher_entry *pe;

	g_assert(sha1 != NULL);

	/*
	 * If already known, ignore silently.
	 */

	if (g_hash_table_lookup(publisher_sha1, sha1))
		return;

	/*
	 * New entry will be processed immediately.
	 */

	pe = publisher_entry_alloc(sha1);
	gm_hash_table_insert_const(publisher_sha1, pe->sha1, pe);

	publisher_handle(pe);
}

/**
 * Initialize the DHT publisher.
 */
void
publisher_init(void)
{
	publish_cq = cq_submake("publisher", callout_queue, PUBLISHER_CALLOUT);
	publisher_sha1 = g_hash_table_new(sha1_hash, sha1_eq);
}

/**
 * Hash table iterator callback to free entry.
 */
static void
free_entry(gpointer key, gpointer val, gpointer data)
{
	struct publisher_entry *pe = val;

	(void) key;
	(void) data;

	publisher_entry_free(pe, FALSE);
}

/**
 * Shutdown the DHT publisher.
 */
void
publisher_close(void)
{
	g_hash_table_foreach(publisher_sha1, free_entry, NULL);
	g_hash_table_destroy(publisher_sha1);
	publisher_sha1 = NULL;

	cq_free_null(&publish_cq);
}

/* vi: set ts=4 sw=4 cindent: */
