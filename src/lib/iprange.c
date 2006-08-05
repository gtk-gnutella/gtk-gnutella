/*
 * $Id$
 *
 * Copyright (c) 2004, Raphael Manfredi
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
 * @ingroup lib
 * @file
 *
 * Needs brief description here.
 *
 * Load, parse and lookup IP addresses from a set of IP ranges defined
 * by a list of addresses in CIDR (Classless Internet Domain Routing) format.
 *
 * @author Raphael Manfredi
 * @date 2004
 */

#include "common.h"

RCSID("$Id$")

#include "iprange.h"
#include "misc.h"
#include "walloc.h"
#include "override.h"		/* Must be the last header included */

/*
 * The "database" of IP ranges is made of several data structures:
 *
 * A level-1 index, a 256-entry wide array, indexed by the first byte of the
 * IP address, which points to a either an exact entry (for CIDR networks
 * whose leading bits are /8 or less) or a level-2 index (keyed by the second
 * byte of the address) yielding to either an entry (for CIDR entries ranging
 * from 9 to 16 bits) or a list of CIDR ranges (for CIDR entries made of 17+
 * leading bits).
 *
 * WARNING: to discriminate between an exact match (yielding the value) and
 * a follow-up index, we assume that values will be pointers and that pointers
 * cannot be even.  Therefore, we mark values by setting the bit 0, making an
 * even pointer (the IPRANGE_MARK define).
 *
 * The "database" maps a single IP address to a pointer value, inserted at
 * the time the range was added to the database.
 */

#define IPRANGE_MARK	1		/**< Magic tagging of user values */

/*
 * A "database" descriptor, holding the CIDR networks and their attached value.
 */

#define IPRANGE_MAGIC	0x01b3a59e
#define IPAGESZ			256

struct iprange_db {
	guint32 magic;			/**< Magic number */
	gpointer lvl1[IPAGESZ];	/**< Level-1 index */
	/* Allocation */
	iprange_clone_t clone;	/**< Cloning callback for values */
	iprange_free_t free;	/**< Freeing callback for values */
	/* Statistics */
	gint range_count;		/**< Amount of network ranges registered */
	gint lvl2_count;		/**< Amount of level-2 pages, for stats */
	gint head_count;		/**< Amount of heads in level-2 pages, for stats */
	gint list_count;		/**< Amount of items held in lists */
};

/**
 * A CIDR network description.  Note that the network IP is already masked,
 * so to determine whether some IP falls within that network, one needs
 * to compare (IP & netmask) with the ip_masked field.
 */
struct iprange_net {
	guint32 ip_masked;	/**< The IP of the network (meaningful bits) */
	guint32 netmask;	/**< The network bit mask, selecting meaningful bits */
	gpointer value;		/**< Value held */
};

/**
 * Error code stings.
 */
static const gchar *iprange_errstr[] = {
	"OK",									/**< IPR_ERR_OK */
	"Incorrect network prefix",				/**< IPR_ERR_BAD_PREFIX */
	"CIDR range clash",						/**< IPR_ERR_RANGE_CLASH */
	"Duplicate range",						/**< IPR_ERR_RANGE_DUP */
	"Range is subnet of existing range",	/**< IPR_ERR_RANGE_SUBNET */
	"Range is overlapping existing range",	/**< IPR_ERR_RANGE_OVERLAP */
};

/**
 * @return human-readable error string for given error code.
 */
const gchar *
iprange_strerror(iprange_err_t errnum)
{
	STATIC_ASSERT(IPR_ERROR_COUNT == G_N_ELEMENTS(iprange_errstr));

	if ((gint) errnum < 0 || errnum >= G_N_ELEMENTS(iprange_errstr))
		return "Invalid error code";

	return iprange_errstr[errnum];
}

/**
 * Null free callback, when values held in database are not pointers and
 * we need to force insertion.
 */
static void
iprange_free_nop(gpointer unused_value, gpointer unused_updata)
{
	(void) unused_value;
	(void) unused_updata;
}

/**
 * Identity clone callback, when values are not pointers and not meant
 * to be freed.
 */
static gpointer
iprange_clone_nop(gpointer value)
{
	return value;
}


/**
 * Create a new IP range database.
 */
gpointer
iprange_make(iprange_free_t freecb, iprange_clone_t clonecb)
{
	struct iprange_db *idb;

	idb = walloc0(sizeof(*idb));
	idb->magic = IPRANGE_MAGIC;
	idb->free = freecb == NULL ? iprange_free_nop : freecb;
	idb->clone = clonecb == NULL ? iprange_clone_nop : clonecb;

	return idb;
}

/**
 * Free values stored in the IP range database, then destroy database.
 *
 * @param db the database
 * @param udata trailing user-supplied data, passed to freeing callback
 */
void
iprange_free_each(gpointer db, gpointer udata)
{
	struct iprange_db *idb = (struct iprange_db *) db;
	gint i;

	g_assert(db);
	g_assert(idb->magic == IPRANGE_MAGIC);

	/*
	 * Loop through the level-1 page, and then through level-2 pages,
	 * and finally to the lists anchored on the level-2 page.
	 */

	for (i = 0; i < IPAGESZ; i++) {
		gpointer *lvl2 = idb->lvl1[i];
		gint j;

		if (lvl2 == NULL)
			continue;

		if (GPOINTER_TO_UINT(lvl2) & IPRANGE_MARK) {
			gpointer value = (gchar *) lvl2 - IPRANGE_MARK;
			(*idb->free)(value, udata);
			continue;
		}

		for (j = 0; j < IPAGESZ; j++) {
			GSList *head = lvl2[j];
			GSList *l;

			if (head == NULL)
				continue;

			if (GPOINTER_TO_UINT(head) & IPRANGE_MARK) {
				gpointer value = (gchar *) head - IPRANGE_MARK;
				(*idb->free)(value, udata);
				continue;
			}

			for (l = head; l; l = g_slist_next(l)) {
				struct iprange_net *ipn = (struct iprange_net *) l->data;

				(*idb->free)(ipn->value, udata);
				wfree(ipn, sizeof(*ipn));
			}
			g_slist_free(head);
		}

		wfree(lvl2, sizeof(idb->lvl1));
	}

	wfree(idb, sizeof(*idb));
}

/**
 * Add network in the level-1 page of the database.
 */
static iprange_err_t
iprange_add_level1(
	struct iprange_db *idb,
	guint32 net, guint bits, gpointer udata, gboolean force)
{
	guint8 first;
	guint8 mask;
	guint8 max;
	gint i;
	gboolean added = FALSE;

	g_assert(bits >= 1 && bits <= 8);

	first = net >> 24;
	mask = (1 << (8 - bits)) - 1;		/* Covered range */
	max = first | mask;					/* From first/8 to max/8 included */

	g_assert(0 == (first & mask));

	/*
	 * There must not be anything recorded in the level-1 page for this
	 * network, nor for any subsequent one (e.g. if we record an hypothetic
	 * network 16.0.0.0/4, then we would fill bytes 16-31).
	 */

	for (i = first; i <= max; i++) {
		if (!force && idb->lvl1[i] != NULL)
			return IPR_ERR_RANGE_CLASH;
	}

	/*
	 * Now we know we can record this range.
	 * We mark data to signal that there is no level-2 index to consider.
	 */

	for (i = first; i <= max; i++) {
		if (force && idb->lvl1[i] != NULL)
			continue;
		if (i != first)
			udata = (*idb->clone)(udata);
		idb->lvl1[i] = (gchar *) udata + IPRANGE_MARK;
		added = TRUE;
	}

	if (added)
		idb->range_count++;

	return IPR_ERR_OK;			/* Successfully inserted */
}

/**
 * Add network in the level-2 page of the database.
 */
static iprange_err_t
iprange_add_level2(
	struct iprange_db *idb,
	guint32 net, guint bits, gpointer *lvl2, gpointer udata, gboolean force)
{
	guint8 second;
	guint8 mask;
	guint8 max;
	gint i;
	gboolean added = FALSE;

	g_assert(bits >= 9 && bits <= 16);

	second = (net & 0x00ff0000) >> 16;
	mask = (1 << (16 - bits)) - 1;		/* Covered range */
	max = second | mask;				/* From second/16 to max/16 included */

	g_assert(0 == (second & mask));

	/*
	 * There must not be anything recorded in the level-2 page for this
	 * network, nor for any subsequent one (e.g. if we record an hypothetic
	 * network 15.16.0.0/12, then we would fill bytes 16-31).
	 */

	for (i = second; i <= max; i++) {
		if (!force && lvl2[i] != NULL)
			return IPR_ERR_RANGE_CLASH;
	}

	/*
	 * Now we know we can record this range.
	 * We mark data to signal that there is no further data to consider.
	 */

	for (i = second; i <= max; i++) {
		if (force && lvl2[i] != NULL)
			continue;
		if (i != second)
			udata = (*idb->clone)(udata);
		lvl2[i] = (gchar *) udata + IPRANGE_MARK;
		added = TRUE;
	}

	if (added)
		idb->range_count++;

	return IPR_ERR_OK;			/* Successfully inserted */
}

/**
 * Add CIDR network to the database (common routine for both plain and forced
 * database insertions).
 *
 * @param db	the IP range database
 * @param net	the network prefix
 * @param bits	the amount of bits in the network prefix
 * @param udata	value associated to this IP network
 * @param force	force insertion, possibly freeing subnets already registered
 * @param cdata	extra parameter to pass to free callback, if invoked
 *
 * @return IPR_ERR_OK if successful, an error code otherwise.
 */
static iprange_err_t
iprange_add_cidr_internal(
	gpointer db, guint32 net, guint bits, gpointer udata,
	gboolean force, gpointer cdata)
{
	struct iprange_db *idb = (struct iprange_db *) db;
	guint8 first;
	guint8 second;
	guint32 netmask;
	guint32 trailmask;
	gpointer *lvl2;
	GSList *head;
	GSList *l;
	guint32 ip_masked;
	GSList *to_remove = NULL;
	struct iprange_net *ipn;

	g_assert(db);
	g_assert(idb->magic == IPRANGE_MAGIC);
	g_assert(bits >= 1 && bits <= 32);
	g_assert(0 == (GPOINTER_TO_UINT(udata) & IPRANGE_MARK));

	/*
	 * Ensure network range is properly given: trailing bits must be zero.
	 */

	trailmask = (1 << (32 - bits)) - 1;
	netmask = ~trailmask;

	if (net & trailmask)
		return IPR_ERR_BAD_PREFIX;

	g_assert(net == (net & netmask));

	/*
	 * If it is an 8-bit network or less, we'll fill only the level-1 index,
	 * and there must not be any entry yet (we expect a disjoint set of
	 * CIDR entries).
	 */

	if (bits <= 8)
		return iprange_add_level1(idb, net, bits, udata, force);

	/*
	 * If the net/8 is already registered, then we have a range clash.
	 */

	first = net >> 24;
	lvl2 = idb->lvl1[first];

	if (GPOINTER_TO_UINT(lvl2) & IPRANGE_MARK)
		return force ? IPR_ERR_OK : IPR_ERR_RANGE_CLASH;

	/*
	 * We need to create a level-2 page if none was created already.
	 */

	if (lvl2 == NULL) {
		lvl2 = idb->lvl1[first] = walloc0(sizeof(idb->lvl1));
		idb->lvl2_count++;
	}

	/*
	 * If we have 16-bit network or less, we'll fill only the level-2 index.
	 */

	if (bits <= 16)
		return iprange_add_level2(idb, net, bits, lvl2, udata, force);

	/*
	 * The level-2 page points to either a value (the pointer is tagged
	 * with the mark), the head or a list of IP/netmasks, or NULL if there
	 * is nothing registered yet.
	 */

	second = (net & 0x00ff0000) >> 16;
	head = lvl2[second];

	if (GPOINTER_TO_UINT(head) & IPRANGE_MARK)
		return force ? IPR_ERR_OK : IPR_ERR_RANGE_CLASH;

	/*
	 * Look whether we already have this network, or whether it is already
	 * contained in another network we have.
	 */

	ip_masked = net & netmask;

	g_assert(0 == (ip_masked & trailmask));

	for (l = head; l; l = g_slist_next(l)) {
		ipn = (struct iprange_net *) l->data;

		if (ip_masked == ipn->ip_masked) {
			if (netmask == ipn->netmask)
				return IPR_ERR_RANGE_DUP;
			if (netmask == (netmask & ipn->netmask)) {
				/*
				 * Existing CIDR contained in network we're adding, for
				 * instance 16.0.0/24 versus added 16.0.0/17.
				 */
				if (!force)
					return IPR_ERR_RANGE_OVERLAP;
				to_remove = g_slist_prepend(to_remove, ipn);
				continue;
			} else {
				/*
				 * It's the other way round: we're adding 16.0.0/24 and we
				 * already had 16.0.0/17.
				 */
				return IPR_ERR_RANGE_SUBNET;
			}
		}

		if ((net & ipn->netmask) == ipn->ip_masked) {
			/*
			 * We're adding 16.0.129/24 but we had 16.0.128/17.
			 */
			return IPR_ERR_RANGE_SUBNET;
		}

		if ((ipn->ip_masked & netmask) == ip_masked) {
			/*
			 * Existing CIDR fully contained in the network we're adding,
			 * but the reduction is not equal or it would have been caught
			 * above.  Paranoid test, can't see when it could happen exactly.
			 */
			if (!force)
				return IPR_ERR_RANGE_OVERLAP;
			to_remove = g_slist_prepend(to_remove, ipn);
			continue;
		}
	}

	/*
	 * We'll add a list head later, but we have to count it now since after
	 * the possible removal step, we'll be unable to know whether we had
	 * something initially or not.
	 */

	if (head == NULL)
		idb->head_count++;

	/*
	 * If we have to force entry and have duplicates to remove, do so now.
	 */

	for (l = to_remove; l; l = g_slist_next(l)) {
		ipn = (struct iprange_net *) l->data;

		g_assert(head != NULL);

		head = g_slist_remove(head, ipn);
		(*idb->free)(ipn->value, cdata);
		wfree(ipn, sizeof(*ipn));
		idb->list_count--;
		idb->range_count--;
	}
	g_slist_free(to_remove);

	g_assert(idb->list_count >= 0);

	/*
	 * Insert new network range.
	 */

	ipn = walloc(sizeof(*ipn));
	ipn->ip_masked = ip_masked;
	ipn->netmask = netmask;
	ipn->value = udata;

	lvl2[second] = g_slist_prepend(head, ipn);
	idb->list_count++;
	idb->range_count++;

	return IPR_ERR_OK;			/* Successfully inserted */
}

/**
 * Add CIDR network to the database.
 *
 * @param db	the IP range database
 * @param net	the network prefix
 * @param bits	the amount of bits in the network prefix
 * @param udata	value associated to this IP network
 *
 * @return IPR_ERR_OK if successful, an error code otherwise.
 */
iprange_err_t
iprange_add_cidr(gpointer db, guint32 net, guint bits, gpointer udata)
{
	return iprange_add_cidr_internal(db, net, bits, udata, FALSE, NULL);
}

/**
 * Add CIDR network to the database, forcing entry if new range supersedes
 * an older range.
 *
 * @param db	the IP range database
 * @param net	the network prefix
 * @param bits	the amount of bits in the network prefix
 * @param udata	value associated to this IP network
 * @param cdata	extra parameter to pass to free callback, if invoked
 *
 * @return IPR_ERR_OK if successful, an error code otherwise.
 */
iprange_err_t
iprange_add_cidr_force(
	gpointer db, guint32 net, guint bits, gpointer udata, gpointer cdata)
{
	return iprange_add_cidr_internal(db, net, bits, udata, TRUE, cdata);
}

/**
 * Retrieve value associated with an IP address, i.e. that of the range
 * containing it.
 */
gpointer
iprange_get(gpointer db, guint32 ip)
{
	struct iprange_db *idb = (struct iprange_db *) db;
	guint8 first;
	guint8 second;
	gpointer *lvl2;
	GSList *head;
	GSList *l;

	g_assert(db);
	g_assert(idb->magic == IPRANGE_MAGIC);

	first = ip >> 24;
	lvl2 = idb->lvl1[first];

	if (lvl2 == NULL)
		return NULL;		/* Not found */

	/*
	 * Held within a known /8 network?
	 */

	if (GPOINTER_TO_UINT(lvl2) & IPRANGE_MARK)
		return (gchar *) lvl2 - IPRANGE_MARK;

	/*
	 * Held within a known /16 network?
	 */

	second = (ip & 0x00ff0000) >> 16;
	head = lvl2[second];

	if (GPOINTER_TO_UINT(head) & IPRANGE_MARK)
		return (gchar *) head - IPRANGE_MARK;

	/*
	 * Look in sub-networks registered below this /16 range...
	 */

	for (l = head; l; l = g_slist_next(l)) {
		struct iprange_net *ipn = (struct iprange_net *) l->data;

		if ((ip & ipn->netmask) == ipn->ip_masked)
			return ipn->value;
	}

	return NULL;		/* Not found */
}

/**
 * Get statistics about the database.
 *
 * @param db the database
 * @param stats the supplied structure to fill
 */
void
iprange_get_stats(gpointer db, iprange_stats_t *stats)
{
	struct iprange_db *idb = (struct iprange_db *) db;

	g_assert(db);
	g_assert(idb->magic == IPRANGE_MAGIC);

	stats->count = idb->range_count;
	stats->level2 = idb->lvl2_count;
	stats->heads = idb->head_count;
	stats->enlisted = idb->list_count;
}

/* vi: set ts=4 sw=4 cindent: */
