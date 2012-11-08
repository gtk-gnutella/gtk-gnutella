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
 * @ingroup dht
 * @file
 *
 * Stable node recording.
 *
 * The purpose here is to record the lifetime of nodes that we cache as
 * "roots", to be able to compute the probability of a published value to
 * still be present on the DHT one hour later (which is the current hardwired
 * expiration time in the LimeWire servents and chances to have that changed
 * are slim, as of 2009-10-19).
 *
 * The maths:
 *
 * The probability of presence of nodes on the network is modelled through
 * the following probability density function:
 *
 *    f(x) = 1 / (2*x^2)     for x >= 1
 *
 * with "x" being the number of hours a servent is up.  We consider that
 * there is a probability of 0.5 that a servent will not stay up for more
 * than 1 hour.  For those which do, we use f(x), and it is trivial to
 * see that the primitive of f is:
 *
 *    F(x) = -1/2x
 *
 * and that the integral of f(x) between 1 and +oo is F(+oo) - F(1) = 0.5.
 *
 * Therefore, f(x) is a suitable probability density function fox x >= 1,
 * given our hypothesis that P(x >= 1) = 0.5.
 *
 * Given the limit of F(x) is 0 when x |--> +oo, the integral of f(x) between
 * ``a'' and ``+oo'' is -F(a).
 *
 * This is used to easily compute a (theoretical) conditional probability
 * of presence of a node for "h" more hours given that it was already
 * alive for H hours (with H >= 1):
 *
 *    P(x >= (H + h))|x >= H = -F(H + h) / -F(H) = H / (H + h)
 *
 * For the [0, 1] interval, we use the following probability density:
 *
 *    f(x) = 1/2           for x in [0, 1]
 *
 * Its primitive is:
 *
 *    F(x) = x/2
 *
 * and the integral of f(x) over [0, 1] is F(1) - F(0) = 0.5
 *
 * Since f(1) = 0.5 in the two definitions we gave above, the function
 * defines a continuous probability density whose integral over [0, +oo] is 1:
 *
 *     f(x) = 1/2          for x in [0, 1]
 *     f(x) = 1 / (2*x^2)  for x >= 1
 *
 * If a node has been alive "H" hours already (H >= 1), what is the time
 * increment h (in hours) that satisfies:
 *
 *    p = P(x >= (H + h))|x >= H
 *
 * where p is a given probability of presence?  This satisfies the equation:
 *
 *    p = H / (H + h)
 *
 * and solving for h we have:
 *
 *    h = H * (1 - p) / p
 *
 * Applications:
 *
 * - for publishing operations, given the set of nodes to which the value
 *   was stored, and knowing the current stability of these nodes, compute
 *   the probability of having the published value still there before the
 *   next publishing cycle.  If too low, we can then attempt republishing
 *   sooner than the default.
 *
 * - for values we store and for which we have an original, we can determine
 *   the probability that the publisher remains alive for one more publishing
 *   period and, if high enough, increase the expiration date for the published
 *   value, so as to reserve the entry slot in the key (given we have a fixed
 *   limited amount of values per keys) to the most stable publishers.
 *
 * - for alive node checks: when a node has been up at least one hour, we
 *   can compute how much time we can wait before pinging the node again,
 *   knowing that we want to be sure that it is still likely to be up with
 *   a probability of "p" (for instance p = 95%).
 *
 * Implementation:
 *
 * We keep a table mapping a node's KUID with the set { first seen, last seen }.
 * Each time we get a STORE reply (not necessarily OK) from the node, we update
 * the "time last seen".  We don't care about IP:port changes because the node
 * remains in the DHT with the same KUID, hence it will be quickly reachable
 * again thanks to the routing table updates.  We don't consider KUID conflicts
 * a problem here given our application.
 *
 * For practical considerations, we make the above table persistent so that
 * immediate restarts can reuse the information collected from a past run.
 *
 * When no updates are seen on a given node for more than 2 * republish period,
 * we consider the node dead and reclaim its entry.
 *
 * @author Raphael Manfredi
 * @date 2009
 */

#include "common.h"

#include "stable.h"

#include "if/dht/kuid.h"
#include "if/dht/knode.h"
#include "if/dht/value.h"

#include "core/gnet_stats.h"
#include "core/settings.h"

#include "if/gnet_property_priv.h"

#include "lib/atoms.h"
#include "lib/cq.h"
#include "lib/dbmw.h"
#include "lib/dbstore.h"
#include "lib/stringify.h"
#include "lib/tm.h"
#include "lib/override.h"		/* Must be the last header included */

#define	STABLE_DB_CACHE_SIZE	4096	/**< Cached amount of stable nodes */
#define STABLE_MAP_CACHE_SIZE	64		/**< Amount of SDBM pages to cache */
#define STABLE_UPPER_THRESH		(3600 * 24 * 7 * 2)	/**< ~ 2 weeks in s */

#define STABLE_EXPIRE (2 * DHT_VALUE_REPUBLISH)	/**< 2 republish periods */
#define STABLE_PROBA  (0.3333)					/**< 33.33% */

#define STABLE_PRUNE_PERIOD	(DHT_VALUE_REPUBLISH * 1000)
#define STABLE_SYNC_PERIOD	(60 * 1000)

static cperiodic_t *stable_sync_ev;
static cperiodic_t *stable_prune_ev;

/**
 * DBM wrapper to associate a target KUID with the set timestamps.
 */
static dbmw_t *db_lifedata;
static char db_stable_base[] = "dht_stable";
static char db_stable_what[] = "DHT stable nodes";

#define LIFEDATA_STRUCT_VERSION	0

/**
 * Information about a target KUID that is stored to disk.
 * The structure is serialized first, not written as-is.
 */
struct lifedata {
	time_t first_seen;			/**< Time when we first seen the node */
	time_t last_seen;			/**< Last time we saw the node */
	uint8 version;				/**< Structure version information */
};

/**
 * Get lifedata from database, returning NULL if not found.
 */
static struct lifedata *
get_lifedata(const kuid_t *id)
{
	struct lifedata *ld;

	ld = dbmw_read(db_lifedata, id, NULL);

	if (NULL == ld && dbmw_has_ioerr(db_lifedata)) {
		g_warning("DBMW \"%s\" I/O error, bad things could happen...",
			dbmw_name(db_lifedata));
	}

	return ld;
}

/**
 * Given a node who has been alive for t seconds, return the probability
 * that it will be alive in d seconds.
 *
 * @param t		elapsed time the node has been alive
 * @param d		future delta time for which we want the probability
 *
 * @return the probability that the node will be alive in d seconds.
 */
double
stable_alive_probability(time_delta_t t, time_delta_t d)
{
	double th = t / 3600.0;
	double dh = d / 3600.0;

	if (0 == t + d || t <= 0)
		return 0.0;

	if (d <= 0)
		return 1.0;

	/*
	 * See leading file comment for an explanation.
	 *
	 * NB: this is a theoretical probability, implied by our choice for
	 * the probability density function.
	 */

	if (t >= 3600) {
		return th / (th + dh);
	} else {
		/*
		 * The area under f(x) between 1 and +oo is 0.5
		 * The area under f(x) between x and 1 is 0.5 - x/2
		 */

		if (t + d >= 3600) {
			double a1 = 1.0 / (2.0 * (th + dh));	/* From t+d to +oo */
			double a2 = 1.0 - th / 2.0;				/* From t to +oo */
			return a1 / a2;
		} else {
			double a1 = 1.0 - (th + dh) / 2.0;		/* From t+d to +oo */
			double a2 = 1.0 - th / 2.0;				/* From t to +oo */
			return a1 / a2;
		}
	}
}

/**
 * Given a node which was first seen at ``first_seen'' and last seen at
 * ``last_seen'', return probability that node still be alive now.
 *
 * @param first_seen		first time node was seen / created
 * @param last_seen			last time node was seen
 *
 * @return the probability that the node be still alive now.
 */
double
stable_still_alive_probability(time_t first_seen, time_t last_seen)
{
	time_delta_t life;
	time_delta_t elapsed;

	life = delta_time(last_seen, first_seen);
	if (life <= 0)
		return 0.0;

	elapsed = delta_time(tm_time(), last_seen);

	/*
	 * Safety precaution: regardless of the past lifetime of the node, if
	 * we have not heard from it for more than STABLE_UPPER_THRESH, then
	 * consider it dead.
	 */

	return elapsed < STABLE_UPPER_THRESH ?
		stable_alive_probability(life, elapsed) : 0.0;
}

/**
 * Record activity on the node.
 */
void
stable_record_activity(const knode_t *kn)
{
	struct lifedata *ld;
	struct lifedata new_ld;

	knode_check(kn);
	g_assert(kn->flags & KNODE_F_ALIVE);

	ld = get_lifedata(kn->id);

	if (NULL == ld) {
		ld = &new_ld;

		new_ld.version = LIFEDATA_STRUCT_VERSION;
		new_ld.first_seen = kn->first_seen;
		new_ld.last_seen = kn->last_seen;

		gnet_stats_inc_general(GNR_DHT_STABLE_NODES_HELD);
	} else {
		if (kn->last_seen <= ld->last_seen)
			return;
		ld->last_seen = kn->last_seen;
	}

	dbmw_write(db_lifedata, kn->id->v, ld, sizeof *ld);
}

/**
 * The KUID of the node has changed: remove its entry if it had one and make
 * sure we have an entry for the new KUID.
 *
 * @param kn		the old node
 * @param rn		the replacing node
 */
void
stable_replace(const knode_t *kn, const knode_t *rn)
{
	struct lifedata *ld;

	knode_check(kn);
	knode_check(rn);
	g_assert(rn->flags & KNODE_F_ALIVE);

	ld = get_lifedata(kn->id);
	if (NULL == ld)
		return;				/* Node was not recorded in the "stable" set */

	if (GNET_PROPERTY(dht_stable_debug)) {
		g_debug("DHT STABLE removing obsolete %s, now at %s",
			knode_to_string(kn), knode_to_string2(rn));
	}

	/*
	 * Remove the old node and create an entry for the new one.
	 */

	dbmw_delete(db_lifedata, kn->id->v);
	gnet_stats_dec_general(GNR_DHT_STABLE_NODES_HELD);
	stable_record_activity(rn);
}

/**
 * Estimate probability of presence for a value published to some roots in
 * a given time frame.
 *
 * @param d			how many seconds in the future?
 * @param rs		the STORE lookup path, giving root candidates
 * @param status	the array of STORE status for each entry in the path
 *
 * @return an estimated probability of presence of the value in the network.
 */
double
stable_store_presence(time_delta_t d,
	const lookup_rs_t *rs, const uint16 *status)
{
	double q = 1.0;
	size_t i;
	size_t count = lookup_result_path_length(rs);

	/*
	 * We may be called by publish callbacks invoked to clean up because
	 * the operation was cancelled.  Maybe the DHT was disabled during the
	 * operation, meaning our data structures have been cleaned up?  In that
	 * case, abort immediately.
	 *
	 * NOTE: this is not an assertion, it can happen in practice and needs to
	 * be explicitly checked for.
	 */

	if (NULL == db_lifedata)		/* DHT disabled dynamically */
		return 0.0;

	/*
	 * The probability of presence is (1 - q) where q is the probability
	 * that the value be lost by all the nodes, i.e. that all the nodes
	 * to which the value was published to be gone in "d" seconds.
	 */

	for (i = 0; i < count; i++) {
		if (status[i] == STORE_SC_OK) {
			const knode_t *kn = lookup_result_nth_node(rs, i);
			struct lifedata *ld = get_lifedata(kn->id);

			if (NULL == ld) {
				return 0.0;		/* Cannot compute a suitable probability */
			} else {
				time_delta_t alive = delta_time(ld->last_seen, ld->first_seen);
				double p = stable_alive_probability(alive, d);

				q *= (1.0 - p);	/* (1 - p) is proba this node will be gone */
			}
		}
	}

	return 1.0 - q;
}

/**
 * DBMW foreach iterator to remove old entries.
 * @return  TRUE if entry must be deleted.
 */
static bool
prune_old(void *key, void *value, size_t u_len, void *u_data)
{
	const kuid_t *id = key;
	const struct lifedata *ld = value;
	time_delta_t d;
	bool expired;
	double p;

	(void) u_len;
	(void) u_data;

	d = delta_time(tm_time(), ld->last_seen);

	if (d <= STABLE_EXPIRE) {
		expired = FALSE;
		p = 1.0;
	} else {
		p = stable_still_alive_probability(ld->first_seen, ld->last_seen);
		expired = p < STABLE_PROBA;
	}

	if (GNET_PROPERTY(dht_stable_debug) > 4) {
		g_debug("DHT STABLE node %s life=%s last_seen=%s, p=%.2f%%%s",
			kuid_to_hex_string(id),
			compact_time(delta_time(ld->last_seen, ld->first_seen)),
			compact_time2(d), p * 100.0,
			expired ? " [EXPIRED]" : "");
	}

	return expired;
}

/**
 * Prune the database, removing old entries not updated since at least
 * STABLE_EXPIRE seconds and which have less than STABLE_PROBA chance of
 * still being alive, given our probability density function.
 */
static void
stable_prune_old(void)
{
	if (GNET_PROPERTY(dht_stable_debug)) {
		g_debug("DHT STABLE pruning old stable node records (%zu)",
			dbmw_count(db_lifedata));
	}

	dbmw_foreach_remove(db_lifedata, prune_old, NULL);
	gnet_stats_set_general(GNR_DHT_STABLE_NODES_HELD, dbmw_count(db_lifedata));

	if (GNET_PROPERTY(dht_stable_debug)) {
		g_debug("DHT STABLE pruned old stable node records (%zu remaining)",
			dbmw_count(db_lifedata));
	}

	dbstore_shrink(db_lifedata);
}

/**
 * Callout queue periodic event to expire old entries.
 */
static bool
stable_periodic_prune(void *unused_obj)
{
	(void) unused_obj;

	stable_prune_old();
	return TRUE;		/* Keep calling */
}

/**
 * Callout queue periodic event to synchronize persistent DB.
 */
static bool
stable_sync(void *unused_obj)
{
	(void) unused_obj;

	dbstore_sync(db_lifedata);
	return TRUE;		/* Keep calling */
}

/**
 * Serialization routine for lifedata.
 */
static void
serialize_lifedata(pmsg_t *mb, const void *data)
{
	const struct lifedata *ld = data;

	pmsg_write_u8(mb, LIFEDATA_STRUCT_VERSION);
	pmsg_write_time(mb, ld->first_seen);
	pmsg_write_time(mb, ld->last_seen);
}

/**
 * Deserialization routine for lifedata.
 */
static void
deserialize_lifedata(bstr_t *bs, void *valptr, size_t len)
{
	struct lifedata *ld = valptr;

	g_assert(sizeof *ld == len);

	bstr_read_u8(bs, &ld->version);
	bstr_read_time(bs, &ld->first_seen);
	bstr_read_time(bs, &ld->last_seen);
}

/**
 * Initialize node stability caching.
 */
G_GNUC_COLD void
stable_init(void)
{
	dbstore_kv_t kv = { KUID_RAW_SIZE, NULL, sizeof(struct lifedata), 0 };
	dbstore_packing_t packing =
		{ serialize_lifedata, deserialize_lifedata, NULL };

	g_assert(NULL == db_lifedata);
	g_assert(NULL == stable_sync_ev);
	g_assert(NULL == stable_prune_ev);

	/* Legacy: remove after 0.97 -- RAM, 2011-05-03 */
	dbstore_move(settings_config_dir(), settings_dht_db_dir(), db_stable_base);

	db_lifedata = dbstore_open(db_stable_what, settings_dht_db_dir(),
		db_stable_base, kv, packing, STABLE_DB_CACHE_SIZE, kuid_hash, kuid_eq,
		GNET_PROPERTY(dht_storage_in_memory));

	dbmw_set_map_cache(db_lifedata, STABLE_MAP_CACHE_SIZE);
	stable_prune_old();

	stable_sync_ev = cq_periodic_main_add(STABLE_SYNC_PERIOD,
		stable_sync, NULL);

	stable_prune_ev = cq_periodic_main_add(STABLE_PRUNE_PERIOD,
		stable_periodic_prune, NULL);
}

/**
 * Close node stability caching.
 */
G_GNUC_COLD void
stable_close(void)
{
	dbstore_close(db_lifedata, settings_dht_db_dir(), db_stable_base);
	db_lifedata = NULL;
	cq_periodic_remove(&stable_sync_ev);
	cq_periodic_remove(&stable_prune_ev);
}

/* vi: set ts=4 sw=4 cindent: */
