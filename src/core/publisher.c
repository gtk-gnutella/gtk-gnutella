/*
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

#ifdef I_MATH
#include <math.h>		/* For log() */
#endif	/* I_MATH */

#include "publisher.h"
#include "share.h"
#include "pdht.h"
#include "dmesh.h"
#include "gnet_stats.h"
#include "fileinfo.h"
#include "settings.h"	/* For get_average_servent_uptime() */

#include "if/dht/dht.h"
#include "if/dht/kademlia.h"
#include "if/dht/value.h"
#include "if/core/net_stats.h"

#include "if/gnet_property_priv.h"

#include "lib/atoms.h"
#include "lib/cq.h"
#include "lib/crash.h"
#include "lib/dbmw.h"
#include "lib/dbstore.h"
#include "lib/file.h"
#include "lib/hikset.h"
#include "lib/misc.h"
#include "lib/str.h"
#include "lib/stringify.h"
#include "lib/tm.h"
#include "lib/unsigned.h"
#include "lib/walloc.h"

#include "lib/override.h"		/* Must be the last header included */

#define PUBLISHER_CALLOUT	10000	/**< Heartbeat every 10 seconds */
#define PUBLISH_SAFETY		(5*60)	/**< Safety before expiration: 5 min */
#define PUBLISH_POPULAR		10800	/**< 3 hours of delay for popular files */
#define PUBLISH_POPULAR_MAX	604800	/**< 1 week max delay for popular files */
#define PUBLISH_BUSY		600		/**< Retry after 10 minutes */
#define PUBLISH_TRANSIENT	7200	/**< less than 2 hours => transient node */
#define PUBLISH_DMESH_MAX	5		/**< File popularity by dmesh entry count */
#define PUBLISH_PARTIAL_MAX	1		/**< Partial file popularity (dmesh) */

#define PUBLISH_DB_CACHE_SIZE	128		/**< Amount of data to keep cached */
#define PUBLISH_SYNC_PERIOD		60000	/**< Flush DB every minute */
#define PUBLISH_MIN_DECIMATION	0.95	/**< Minimum acceptable decimation */
#define PUBLISH_MIN_PROBABILITY	0.99999	/**< 5 nines */

/**
 * Decimation factor to adjust the republish time depending on how many
 * nodes we published to.  Since the overall probability of all the n nodes
 * to which we published to disappearing within the hour is exponentially
 * decreasing, so is our decimation function.
 *
 * Assuming we manage to publish to n nodes out of the k-closest set,
 * the decimation is set to 1 + ln(n/k)^2, with n <= k.
 *
 * To avoid having to do a floating point division each time, we compute
 * the inverse of the decimation factor.
 */
static double inverse_decimation[KDA_K];

/**
 * The minimum amount of nodes we accept without attempting a background
 * followup STORE is the amount for which the inverse of the decimation
 * factor is greater than PUBLISH_MIN_DECIMATION.
 */
static unsigned publisher_minimum;

typedef enum { PUBLISHER_MAGIC = 0x7592fb8fU } publisher_magic_t;

/**
 * A to-be-published entry, kept in core.
 */
struct publisher_entry {
	publisher_magic_t magic;
	const sha1_t *sha1;			/**< SHA1 of file (atom) */
	cevent_t *publish_ev;		/**< Republish event */
	time_t last_enqueued;		/**< When file was last enqueued */
	time_t last_publish;		/**< When file was last published */
	time_t last_delayed;		/**< When republish event was set */
	uint8 backgrounded;			/**< Whether PDHT is continuing publishing */
};

static inline void
publisher_check(const struct publisher_entry *pe)
{
	g_assert(pe != NULL);
	g_assert(PUBLISHER_MAGIC == pe->magic);
}

static hikset_t *publisher_sha1;	/** Known entries by SHA1 */

/**
 * Private callout queue used to trigger republish events.
 */
static cqueue_t *publish_cq;

/**
 * DBM wrapper to associate a SHA1 with publish timing information.
 */
static dbmw_t *db_pubdata;
static char db_pubdata_base[] = "dht_published";
static char db_pubdata_what[] = "DHT published SHA-1 information";

#define PUBDATA_STRUCT_VERSION	0

/**
 * Publish scheduling information kept in persistent storage.
 *
 * When the ``expiration'' field is zero, it means we do not care whether
 * the data for this SHA-1 expires in the DHT.
 */
struct pubdata {
	time_t next_enqueue;		/**< When file should be enqueued again */
	time_t expiration;			/**< Expiration date of published information */
	uint8 version;				/**< Structure version */
};

static void publisher_handle(struct publisher_entry *pe);

/**
 *  Get pubdata from database.
 */
static struct pubdata *
get_pubdata(const sha1_t *sha1)
{
	struct pubdata *pd;

	pd = dbmw_read(db_pubdata, sha1, NULL);

	if (NULL == pd && dbmw_has_ioerr(db_pubdata)) {
		s_warning_once_per(LOG_PERIOD_MINUTE,
			"DBMW \"%s\" I/O error, bad things could happen...",
			dbmw_name(db_pubdata));
	}

	return pd;
}

/**
 * Delete pubdata from database.
 */
static void
delete_pubdata(const sha1_t *sha1)
{
	dbmw_delete(db_pubdata, sha1);

	if (GNET_PROPERTY(publisher_debug) > 2) {
		shared_file_t *sf = shared_file_by_sha1(sha1);
		g_debug("PUBLISHER SHA-1 %s %s\"%s\" reclaimed",
			sha1_to_string(sha1),
			(sf && sf != SHARE_REBUILDING && shared_file_is_partial(sf)) ?
				"partial " : "",
			(sf && sf != SHARE_REBUILDING) ? shared_file_name_nfc(sf) : "");
		shared_file_unref(&sf);
	}
}

/**
 * Allocate new publisher entry.
 */
static struct publisher_entry *
publisher_entry_alloc(const sha1_t *sha1)
{
	struct publisher_entry *pe;

	WALLOC0(pe);
	pe->magic = PUBLISHER_MAGIC;
	pe->sha1 = atom_sha1_get(sha1);

	return pe;
}

/**
 * Free publisher entry.
 */
static void
publisher_entry_free(struct publisher_entry *pe, bool do_remove)
{
	publisher_check(pe);

	if (do_remove) {
		hikset_remove(publisher_sha1, pe->sha1);
		delete_pubdata(pe->sha1);
	}

	if (pe->backgrounded)
		pdht_cancel_file(pe->sha1, FALSE);

	atom_sha1_free_null(&pe->sha1);
	cq_cancel(&pe->publish_ev);
	WFREE(pe);
}

/**
 * Callout queue callback to handle an entry.
 */
static void
handle_entry(cqueue_t *cq, void *obj)
{
	struct publisher_entry *pe = obj;

	publisher_check(pe);

	cq_zero(cq, &pe->publish_ev);
	publisher_handle(pe);
}

/**
 * Retry publishing after some delay.
 *
 * @param pe		the entry to publish
 * @param delay		delay in seconds
 * @param msg		if non-NULL, logging message explaining the delay
 */
static void
publisher_retry(struct publisher_entry *pe, int delay, const char *msg)
{
	struct pubdata *pd;

	publisher_check(pe);
	g_assert(NULL == pe->publish_ev);
	g_assert(delay > 0);

	pd = get_pubdata(pe->sha1);
	if (pd != NULL) {
		pd->next_enqueue = time_advance(tm_time(), UNSIGNED(delay));
		dbmw_write(db_pubdata, pe->sha1, pd, sizeof *pd);
	}

	pe->publish_ev = cq_insert(publish_cq, delay * 1000, handle_entry, pe);
	pe->last_delayed = tm_time();

	if (GNET_PROPERTY(publisher_debug) > 3) {
		shared_file_t *sf = shared_file_by_sha1(pe->sha1);
		g_debug("PUBLISHER will retry SHA-1 %s %s\"%s\" in %s: %s",
			sha1_to_string(pe->sha1),
			(sf && sf != SHARE_REBUILDING && shared_file_is_partial(sf)) ?
				"partial " : "",
			(sf && sf != SHARE_REBUILDING) ? shared_file_name_nfc(sf) : "",
			compact_time(delay), msg != NULL ? msg : "<no reason>");
		shared_file_unref(&sf);
	}
}

/**
 * Hold publishing for some delay, for data we do not want to republish
 * in the short term (data deemed to be popular).  It therefore does not
 * matter if this already published data expires in the DHT.
 */
static void
publisher_hold(struct publisher_entry *pe, int delay, const char *msg)
{
	struct pubdata *pd;

	publisher_check(pe);

	pd = get_pubdata(pe->sha1);
	if (pd != NULL) {
		pd->expiration = 0;		/* Signals: do not care any more */
		dbmw_write(db_pubdata, pe->sha1, pd, sizeof *pd);
	}

	publisher_retry(pe, delay, msg);
}

/**
 * Computes republish delay for a value.
 *
 * @param info			the information from the publishing layer
 * @param expiration	expected value expiration time
 *
 * @return republishing delay, in seconds.
 *
 * @attention
 * As a side effect, increases the count of satisfactory publishes if the
 * information from the publishing layer lead us to believe it is.  Therefore
 * this routine is not idempotent and should be called only once per callback.
 */
int
publisher_delay(const pdht_info_t *info, time_delta_t expiration)
{
	int delay;

	if (0 == info->all_roots) {
		delay = PUBLISH_SAFETY;
	} else if (
		info->all_roots >= KDA_K ||
		info->presence >= PUBLISH_MIN_PROBABILITY
	) {
		delay = expiration - PUBLISH_SAFETY;
		gnet_stats_inc_general(GNR_DHT_PUBLISHING_SATISFACTORY);
	} else {
		g_assert(uint_is_positive(info->all_roots));
		delay =
			inverse_decimation[info->all_roots - 1] * expiration;
		delay -= PUBLISH_SAFETY;
		delay = MAX(delay, PUBLISH_SAFETY);
	}

	return delay;
}

/**
 * Is publishing acceptable or should we attempt background republish?
 */
bool
publisher_is_acceptable(const pdht_info_t *info)
{
	return info->presence >= PUBLISH_MIN_PROBABILITY ||
		info->all_roots >= publisher_minimum || !info->can_bg;
}

/**
 * Publishing callback invoked when asynchronous publication is completed,
 * or ended with an error.
 *
 * @return TRUE if we accept the publishing, FALSE otherwise to get the
 * publishing layer to continue attempts to failed STORE roots and report
 * on progress using the same callback.
 */
static bool
publisher_done(void *arg, pdht_error_t code, const pdht_info_t *info)
{
	struct publisher_entry *pe = arg;
	struct pubdata *pd;
	int delay = PUBLISH_BUSY;
	bool expired = FALSE;
	bool accepted = TRUE;

	publisher_check(pe);

	pd = get_pubdata(pe->sha1);

	/*
	 * Update stats on republishing before value expiration.
	 */

	if (PDHT_E_OK == code) {
		if (pe->last_publish && info->roots > 0) {
			if (pd != NULL) {
				if (pd->expiration && delta_time(tm_time(), pd->expiration) > 0)
					expired = TRUE;
			} else {
				time_delta_t elapsed = delta_time(tm_time(), pe->last_publish);
				if (elapsed > DHT_VALUE_ALOC_EXPIRE)
					expired = TRUE;
			}
			if (expired)
				gnet_stats_inc_general(GNR_DHT_REPUBLISHED_LATE);
		}
	}

	/*
	 * Compute retry delay.
	 */

	switch (code) {
	case PDHT_E_OK:
		/*
		 * If we were not able to publish to KDA_K nodes, decrease the
		 * delay before republishing.  We use a non-linear decimation of
		 * the republish time, as a function of the number of nodes to which
		 * we could publish.
		 */

		delay = publisher_delay(info, DHT_VALUE_ALOC_EXPIRE);
		accepted = publisher_is_acceptable(info);
		break;
	case PDHT_E_POPULAR:
		/*
		 * Compute the suitable delay: the first time, we use PUBLISH_POPULAR,
		 * and then we double each time until we reach PUBLISH_POPULAR_MAX.
		 *
		 * If we already tried to publish the entry, pe->last_delayed will
		 * be non-zero.
		 */
		if (0 != pe->last_delayed) {
			time_delta_t elapsed = delta_time(tm_time(), pe->last_delayed);
			if (elapsed < PUBLISH_POPULAR) {
				delay = PUBLISH_POPULAR;
			} else if (elapsed >= PUBLISH_POPULAR_MAX / 2) {
				delay = PUBLISH_POPULAR_MAX;
			} else {
				delay = elapsed * 2;
			}
		} else {
			delay = PUBLISH_POPULAR;
		}
		break;
	case PDHT_E_NOT_SHARED:
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

	/*
	 * For a backgrounded entry publishing, we need to adjust the computed
	 * delay with the time that was elapsed
	 */

	g_assert(!pe->backgrounded == !(pe->publish_ev != NULL));

	if (pe->backgrounded) {
		time_delta_t elapsed = delta_time(tm_time(), pe->last_delayed);
		g_assert(pe->last_delayed > 0);
		cq_cancel(&pe->publish_ev);
		if (delay > elapsed) {
			delay -= elapsed;
		} else {
			delay = 1;
		}
	}

	/*
	 * Logging.
	 */

	if (GNET_PROPERTY(publisher_debug) > 1) {
		shared_file_t *sf = shared_file_by_sha1(pe->sha1);
		char retry[80];
		char after[80];
		const char *late = "";

		after[0] = '\0';
		if (pe->last_publish) {
			time_delta_t elapsed = delta_time(tm_time(), pe->last_publish);

			str_bprintf(after, sizeof after,
				" after %s", compact_time(elapsed));

			if (pd != NULL) {
				if (expired)
					late = "late, ";
			} else {
				late = "no data, ";
			}
		}

		str_bprintf(retry, sizeof retry, "%s", compact_time(delay));

		g_debug("PUBLISHER SHA-1 %s %s%s\"%s\" %spublished to %u node%s%s: %s"
			" (%stook %s, total %u node%s, proba %.3f%%, retry in %s,"
			" %s bg, path %u) [%s]",
			sha1_to_string(pe->sha1),
			pe->backgrounded ? "[bg] " : "",
			(sf && sf != SHARE_REBUILDING && shared_file_is_partial(sf)) ?
				"partial " : "",
			(sf && sf != SHARE_REBUILDING) ? shared_file_name_nfc(sf) : "",
			pe->last_publish ? "re" : "",
			info->roots, plural(info->roots),
			after, pdht_strerror(code), late,
			compact_time(delta_time(tm_time(), pe->last_enqueued)),
			info->all_roots, plural(info->all_roots),
			info->presence * 100.0, retry,
			info->can_bg ? "can" : "no", info->path_len,
			accepted ? "OK" : "INCOMPLETE");

		shared_file_unref(&sf);
	}

	/*
	 * Update last publishing time and remember expiration time.
	 */

	if (PDHT_E_OK == code && info->roots > 0) {
		pe->last_publish = tm_time();
		if (pd != NULL) {
			pd->expiration =
				time_advance(pe->last_publish, DHT_VALUE_ALOC_EXPIRE);
			dbmw_write(db_pubdata, pe->sha1, pd, sizeof *pd);
		}
	}

	/*
	 * If entry was deemed popular, we're going to delay its republishing
	 * by a larger amount of time and any data we published already about
	 * it will surely expire.  Since this is our decision, we do not want
	 * to be told that republishing, if it occurs again, was done later than
	 * required.  Hence call publisher_hold() to mark that we don't care.
	 */

	if (PDHT_E_POPULAR == code)
		publisher_hold(pe, delay, "popular entry");
	else
		publisher_retry(pe, delay, accepted ? "accepted publish" : "published");

	pe->backgrounded = !accepted;

	return accepted;
}

/**
 * Handle a SHA-1 entry, publishing its alt-loc to the DHT if still shared.
 */
static void
publisher_handle(struct publisher_entry *pe)
{
	shared_file_t *sf;
	bool is_partial = FALSE;
	int alt_locs;
	time_delta_t min_uptime;
	uint32 avg_uptime;

	publisher_check(pe);
	g_assert(NULL == pe->publish_ev);

	sf = shared_file_by_sha1(pe->sha1);

	/*
	 * Remove SHA1 if no longer shared.
	 */

	if (NULL == sf) {
		fileinfo_t *fi = file_info_by_sha1(pe->sha1);

		/*
		 * If a partial file has lees than the minimum amount of data for PFSP,
		 * shared_file_by_sha1() will return NULL, hence we need to explicitly
		 * check for existence through file_info_by_sha1() and that the file
		 * still exists.
		 */

		if (fi != NULL && file_exists(fi->pathname)) {
			/* Waiting for more data to be able to share, or PFSP re-enabled */
			publisher_retry(pe, PUBLISH_BUSY, "partial file missing");
			return;
		}

		if (GNET_PROPERTY(publisher_debug)) {
			g_debug("PUBLISHER SHA-1 %s is no longer shared",
				sha1_to_string(pe->sha1));
		}
		publisher_entry_free(pe, TRUE);
		return;
	}

	/*
	 * Wait when rebuilding the library.
	 */

	if (SHARE_REBUILDING == sf) {
		publisher_retry(pe, PUBLISH_BUSY, "library being rebuilt");
		return;
	}

	is_partial = shared_file_is_partial(sf);

	/*
	 * If the SHA1 is not available, wait.
	 */

	if (
		!is_partial &&
		(!sha1_hash_available(sf) || !sha1_hash_is_uptodate(sf))
	) {
		publisher_retry(pe, PUBLISH_BUSY, "SHA-1 of file unknown yet");
		goto done;
	}

	/*
	 * Look whether this node has a sufficient average uptime.
	 *
	 * We're stricter to publish partial files because we want to favor
	 * publishing of full files in the DHT, and the benefits of publishing
	 * partial entries come only if we're up for a long enough time.
	 *
	 * Since publishing imposes lookup traffic in the DHT, it is not efficient
	 * to have transient nodes publish file sharing information because this
	 * will likely never be useful.
	 */

	min_uptime = PUBLISH_TRANSIENT;
	if (is_partial)
		min_uptime *= 2;

	avg_uptime = get_average_servent_uptime(tm_time());

	if (avg_uptime < UNSIGNED(min_uptime)) {
		time_delta_t delay = min_uptime - avg_uptime;

		delay = MAX(delay, PUBLISH_BUSY);
		publisher_retry(pe, delay, "minimum average uptime not reached yet");
		goto done;
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
	is_partial = is_partial && !shared_file_is_finished(sf);

	if (alt_locs > (is_partial ? PUBLISH_PARTIAL_MAX : PUBLISH_DMESH_MAX)) {
		if (GNET_PROPERTY(publisher_debug)) {
			g_debug("PUBLISHER SHA-1 %s %s\"%s\" has %d download mesh "
				"entr%s, skipped", sha1_to_string(pe->sha1),
				is_partial ? "partial " : "", shared_file_name_nfc(sf),
				alt_locs, plural_y(alt_locs));
		}
		publisher_hold(pe, PUBLISH_POPULAR, "popular file");
		goto done;
	}

	/*
	 * If the DHT is not enabled, postpone processing.
	 */

	if (!dht_enabled()) {
		publisher_hold(pe, PUBLISH_BUSY, "DHT  disabled");
		goto done;
	}

	/*
	 * If this is a partial file for which we have less than the minimum
	 * for PFSP sharing, or if PFSP has been disabled, skip it.
	 */

	if (shared_file_is_partial(sf)) {
		fileinfo_t *fi = shared_file_fileinfo(sf);

		if (
			!file_info_partial_shareable(fi) ||
			fi->done < GNET_PROPERTY(pfsp_minimum_filesize)
		) {
			publisher_hold(pe, PUBLISH_BUSY, "PFSP minima not reached");
			goto done;
		}
	}

	/*
	 * Check whether it is time to process the entry, in case we're
	 * restarting quickly after a shutdown.
	 */

	if (0 == pe->last_publish) {
		struct pubdata *pd = get_pubdata(pe->sha1);

		if (pd != NULL) {
			time_t now = tm_time();
			time_delta_t enqueue = delta_time(pd->next_enqueue, now);
			time_delta_t expire = delta_time(pd->expiration, now);

			if (enqueue > 0 && (0 == pd->expiration || expire > 0)) {
				int delay = MIN(enqueue, PUBLISH_POPULAR);
				if (pd->expiration != 0)
					delay = MIN(delay, expire);

				if (GNET_PROPERTY(publisher_debug) > 1) {
					g_debug("PUBLISHER SHA-1 %s delayed by %s",
						sha1_to_string(pe->sha1), compact_time(enqueue));
				}

				publisher_retry(pe, delay, "first-time delay");
				goto done;
			}
		}
	}

	/*
	 * Cancel possible remaining backgrounded publishing.
	 */

	if (pe->backgrounded) {
		pdht_cancel_file(pe->sha1, FALSE);
		pe->backgrounded = FALSE;
	}

	/*
	 * OK, we can publish this alternate location.
	 */

	if (pe->last_publish) {
		if (GNET_PROPERTY(publisher_debug) > 2) {
			g_debug("PUBLISHER SHA-1 %s re-enqueued %d secs "
				"after last publish", sha1_to_string(pe->sha1),
				(int) delta_time(tm_time(), pe->last_publish));
		}
	}

	pe->last_enqueued = tm_time();
	pdht_publish_file(sf, publisher_done, pe);

	/* FALL THROUGH */

done:
	shared_file_unref(&sf);
}

/**
 * Record a SHA1 for publishing.
 */
void
publisher_add(const sha1_t *sha1)
{
	struct publisher_entry *pe;
	struct pubdata *pd;

	g_assert(sha1 != NULL);

	if (NULL == db_pubdata)
		return;					/* Shutdowning */

	/*
	 * If already known, ignore silently.
	 */

	if (hikset_lookup(publisher_sha1, sha1))
		return;

	/*
	 * Create persistent publishing data if none known already.
	 */

	pd = get_pubdata(sha1);
	if (NULL == pd) {
		struct pubdata new_pd;

		new_pd.next_enqueue = 0;
		new_pd.expiration = 0;

		dbmw_write(db_pubdata, sha1, &new_pd, sizeof new_pd);

		if (GNET_PROPERTY(publisher_debug) > 2) {
			g_debug("PUBLISHER allocating new SHA-1 %s",
				sha1_to_string(sha1));
		}
	} else {
		if (GNET_PROPERTY(publisher_debug) > 2) {
			time_delta_t enqueue = delta_time(pd->next_enqueue, tm_time());
			time_delta_t expires = delta_time(pd->expiration, tm_time());

			g_debug("PUBLISHER existing SHA-1 %s, next enqueue %s%s, %s%s",
				sha1_to_string(sha1),
				enqueue > 0 ? "in " : "",
				enqueue > 0 ? compact_time(enqueue) : "now",
				pd->expiration ?
					(expires > 0 ? "expires in " : "expired") : "not published",
				expires > 0 ? compact_time2(expires) : "");
		}
	}

	/*
	 * New entry will be processed immediately.
	 */

	pe = publisher_entry_alloc(sha1);
	hikset_insert_key(publisher_sha1, &pe->sha1);

	publisher_handle(pe);
}

/**
 * Wrapper over publisher_add() to let other threads call it via a TEQ event.
 */
void
publisher_add_event(void *sha1)
{
	/*
	 * The DBMW layer is not yet thread-safe as of 2013-11-05 so we need to
	 * funnel back publishing requests to the main thread.  Even when the
	 * DBMW layer is made thread-safe, it might actually be more efficient to
	 * still send back requests via TEQ to the main thread.  This will avoid
	 * setting the SDBM layer as thread-safe as well, since we don't need
	 * the locks in the main use cases.
	 *		--RAM, 2013-11-05
	 */

	publisher_add(sha1);
}

/**
 * Serialization routine for pubdata.
 */
static void
serialize_pubdata(pmsg_t *mb, const void *data)
{
	const struct pubdata *pd = data;

	pmsg_write_time(mb, pd->next_enqueue);
	pmsg_write_time(mb, pd->expiration);

	/*
	 * Because this is persistent, version the structure so that changes
	 * can be processed efficiently after an upgrade.
	 *
	 * This is done here and not at the beginning of the serialized data
	 * because I forgot to plan for it before.
	 *		--RAM, 2009-10-18
	 */

	pmsg_write_u8(mb, PUBDATA_STRUCT_VERSION);
}

/**
 * Deserialization routine for pubdata.
 */
static void
deserialize_pubdata(bstr_t *bs, void *valptr, size_t len)
{
	struct pubdata *pd = valptr;

	g_assert(sizeof *pd == len);

	bstr_read_time(bs, &pd->next_enqueue);
	bstr_read_time(bs, &pd->expiration);

	/*
	 * Temporary, until 0.96.7 is out: we cannot blindly read the version
	 * since it was lacking in previous experimental versions.  Therefore
	 * only do it if we have unread data.
	 *
	 * The test will be removed in versions after 0.96.7, when we can be
	 * certain that the new data format was serialized.
	 *		--RAM, 2009-10-18
	 */

	if (bstr_unread_size(bs))
		bstr_read_u8(bs, &pd->version);
	else
		pd->version = 0;
}

/**
 * Periodic DB synchronization.
 */
static bool
publisher_sync(void *unused_obj)
{
	(void) unused_obj;

	dbstore_sync_flush(db_pubdata);
	return TRUE;
}

/**
 * DBMW foreach iterator to remove expired DB keys.
 * @return TRUE if entry must be deleted.
 */
static bool
publisher_remove_expired(void *u_key, void *value, size_t u_len, void *u_data)
{
	const struct pubdata *pd = value;

	(void) u_key;
	(void) u_len;
	(void) u_data;

	/*
	 * Entries for which we should re-enqueue a publish request now
	 * have expired and can be deleted.
	 */

	return delta_time(tm_time(), pd->next_enqueue) >= 0;
}

/**
 * Remove expired items at startup time.
 */
static void
publisher_trim_pubdata(void)
{
	size_t count;

	if (GNET_PROPERTY(publisher_debug)) {
		count = dbmw_count(db_pubdata);
		g_debug("PUBLISHER scanning %u retrieved SHA1%s",
			(unsigned) count, plural(count));
	}

	dbmw_foreach_remove(db_pubdata, publisher_remove_expired, NULL);

	count = dbmw_count(db_pubdata);

	if (GNET_PROPERTY(publisher_debug)) {
		g_debug("PUBLISHER kept information about %u SHA1%s",
			(unsigned) count, plural(count));
	}

	if (!crash_was_restarted())
		dbstore_compact(db_pubdata);
}

/**
 * Initialize the DHT publisher.
 */
void G_COLD
publisher_init(void)
{
	size_t i;
	dbstore_kv_t kv = { SHA1_RAW_SIZE, NULL, sizeof(struct pubdata), 0 };
	dbstore_packing_t packing =
		{ serialize_pubdata, deserialize_pubdata, NULL };

	publish_cq = cq_main_submake("publisher", PUBLISHER_CALLOUT);
	publisher_sha1 = hikset_create(
		offsetof(struct publisher_entry, sha1), HASH_KEY_FIXED, SHA1_RAW_SIZE);

	db_pubdata = dbstore_open(db_pubdata_what, settings_dht_db_dir(),
		db_pubdata_base, kv, packing, PUBLISH_DB_CACHE_SIZE,
		sha1_hash, sha1_eq, GNET_PROPERTY(dht_storage_in_memory));

	cq_periodic_add(publish_cq, PUBLISH_SYNC_PERIOD, publisher_sync, NULL);

	for (i = 0; i < N_ITEMS(inverse_decimation); i++) {
		double n = i + 1.0;
		double v = log(n / KDA_K);

		inverse_decimation[i] = 1.0 / (1.0 + v * v);

		if (GNET_PROPERTY(publisher_debug) > 4) {
			g_debug("PUBLISHER inverse_decimation[%zu] = %g",
				i, inverse_decimation[i]);
		}
	}

	for (i = 0; i < N_ITEMS(inverse_decimation); i++) {
		if (inverse_decimation[i] >= PUBLISH_MIN_DECIMATION) {
			publisher_minimum = i + 1;
			break;
		}
	}

	g_assert(publisher_minimum > 0);

	if (GNET_PROPERTY(publisher_debug)) {
		g_debug("PUBLISHER minimum amount of nodes we accept: %u",
			publisher_minimum);
	}

	publisher_trim_pubdata();
}

/**
 * Hash table iterator callback to free entry.
 */
static void
free_entry(void *val, void *data)
{
	struct publisher_entry *pe = val;

	(void) data;

	publisher_entry_free(pe, FALSE);
}

/**
 * DBMW foreach iterator to remove keys otherwise unknown by the publisher.
 * @return TRUE if entry is to be deleted.
 */
static bool
publisher_remove_orphan(void *key, void *u_value, size_t u_len, void *u_data)
{
	const sha1_t *sha1 = key;

	(void) u_value;
	(void) u_len;
	(void) u_data;

	return !hikset_contains(publisher_sha1, sha1);
}

/**
 * Shutdown the DHT publisher.
 */
void G_COLD
publisher_close(void)
{
	/*
	 * Purge data we no longer know about from the persisted DB.
	 */

	dbmw_foreach_remove(db_pubdata, publisher_remove_orphan, NULL);

	/*
	 * Final cleanup.
	 */

	hikset_foreach(publisher_sha1, free_entry, NULL);
	hikset_free_null(&publisher_sha1);

	dbstore_close(db_pubdata, settings_dht_db_dir(), db_pubdata_base);
	db_pubdata = NULL;

	cq_free_null(&publish_cq);
}

/* vi: set ts=4 sw=4 cindent: */
