/*
 * Copyright (c) 2002-2003, 2011, Raphael Manfredi
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
 * Globally Unique ID (GUID) manager.
 *
 * HEC generation code is courtesy of Charles Michael Heard (initially
 * written for ATM, but adapted for GTKG, with leading coset leader
 * changed).
 *
 * @author Raphael Manfredi
 * @date 2002-2003, 2011
 */

#include "common.h"

#include "guid.h"
#include "settings.h"
#include "gnet_stats.h"

#include "dht/stable.h"

#include "lib/atoms.h"
#include "lib/bstr.h"
#include "lib/cq.h"
#include "lib/dbmw.h"
#include "lib/dbstore.h"
#include "lib/endian.h"
#include "lib/entropy.h"
#include "lib/hikset.h"
#include "lib/misc.h"
#include "lib/pmsg.h"
#include "lib/product.h"
#include "lib/stringify.h"
#include "lib/tm.h"

#include "if/gnet_property_priv.h"

#include "lib/override.h"		/* Must be the last header included */

/*
 * Flags for GUID[15] tagging.
 */

#define GUID_PONG_CACHING	0x01
#define GUID_PERSISTENT		0x02

/*
 * Flags for GUID[15] query tagging.
 */

#define GUID_REQUERY		0x01	/**< Cleared means initial query */

/*
 * HEC constants.
 */

#define HEC_GENERATOR	0x107		/**< x^8 + x^2 + x + 1 */
#define HEC_GTKG_MASK	0x0c3		/**< HEC GTKG's mask */

/**
 * DBM wrapper to store dynamically collected bad GUID.
 */
static dbmw_t *db_guid;
static char db_guid_base[] = "banned_guid";
static char db_guid_what[] = "Banned GUIDs";

#define GUID_DATA_VERSION		0		/**< Serialization version number */
#define GUID_PRUNE_PERIOD		(3000 * 1000)	/**< in ms */
#define GUID_SYNC_PERIOD		(60 * 1000)		/**< 1 minute, in ms */
#define GUID_STABLE_PROBA		0.25			/**< 25% */
#define GUID_STABLE_LIFETIME	(12 * 3600)		/**< 12 hours */

/**
 * Information about a bad GUID that is stored to disk.
 * The structure is serialized first, not written as-is.
 */
struct guiddata {
	time_t create_time;		/**< When we first encountered that GUID */
	time_t last_time;		/**< Last time we had evidence of it being bad */
};

static cperiodic_t *guid_prune_ev;		/**< Bad GUID pruning */
static cperiodic_t *guid_sync_ev;		/**< Bad GUID DB sync */

const struct guid blank_guid;

static uint8 syndrome_table[256];
static uint16 gtkg_version_mark;

/**
 * Serialization routine for guiddata.
 */
static void
serialize_guiddata(pmsg_t *mb, const void *data)
{
	const struct guiddata *gd = data;

	pmsg_write_u8(mb, GUID_DATA_VERSION);
	pmsg_write_time(mb, gd->create_time);
	pmsg_write_time(mb, gd->last_time);
}

/**
 * Deserialization routine for guiddata.
 */
static void
deserialize_guiddata(bstr_t *bs, void *valptr, size_t len)
{
	struct guiddata *gd = valptr;
	uint8 version;

	g_assert(sizeof *gd == len);

	bstr_read_u8(bs, &version);
	bstr_read_time(bs, &gd->create_time);
	bstr_read_time(bs, &gd->last_time);
}

/**
 * Generate a table of HEC syndromes for all possible input bytes.
 */
static void
guid_gen_syndrome_table(void)
{
	unsigned i;
	unsigned j;

	/*
	 * The code below is wrong but cannot be fixed lightly without making all
	 * deployed GTKGs obsolete (it would break their ability to recognize
	 * a valid GTKG GUID as such).
	 *
	 * In the loop below, the code fragment:
	 *
	 *      syn <<= 1;
	 *      if (syn & 0x80)
	 *          syn ^= HEC_GENERATOR;
	 *
	 * is WRONG.  It should have been:
	 *
	 *      if (syn & 0x80)
	 *          syn = (syn << 1) ^ HEC_GENERATOR;
	 *      else
	 *          syn = (syn << 1);
	 *
	 * or rather:
	 *
	 *      syn <<= 1;
	 *      if (syn & 0x100)
	 *          syn ^= HEC_GENERATOR;
	 *
	 * which is what I originally intended to write by taking out the left
	 * shift and trying to factorize it, but my stupid mistake went uncaught
	 * until I re-read that code now, 10 years later, accidentally.
	 *
	 * So we're not really computing the CRC-8 with the intended polynomial.
	 * I'm not sure what we're actually computing, the polynomial division
	 * being incorrect since the remainders (aka syndromes) are incorrect.
	 *
	 * It does not matter much, because we're not following a standard here.
	 * We just need to keep compatible with the computation done by other
	 * GTKGs out there, which can be viewed as some kind of special hashcode.
	 *
	 * Anyway, we're calling that a HEC (Header Error Control), not a CRC...
	 *
	 *		--RAM, 2013-12-30
	 */

	for (i = 0; i < 256; i++) {
		unsigned syn = i;
		for (j = 0; j < 8; j++) {
			/* This is wrong (see long comment above) but DO NOT FIX yet! */
			syn <<= 1;
			if (syn & 0x80)
				syn ^= HEC_GENERATOR;
		}
		syndrome_table[i] = (uint8) syn;
	}
}

/**
 * Encode major/minor version into 16 bits.
 * If `rel' is true, we're a release, otherwise we're unstable or a beta.
 */
static uint16
guid_gtkg_encode_version(unsigned major, unsigned minor, bool rel)
{
	uint8 low;
	uint8 high;

	g_assert(major < 0x10);
	g_assert(minor < 0x80);

	/*
	 * Low byte of result is the minor number.
	 *
	 * The MSB is set for unstable releases, which means minor versions
	 * can grow up to 127 only.
	 */

	low = minor;

	if (!rel)
		low |= 0x80;

	/*
	 * High byte is divided into two:
	 * . the lowest quartet is the major number.
	 * . the highest quartet is a combination of major/minor.
	 */

	high = (major & 0x0f) | \
		(0xf0 & ((minor << 4) ^ (minor & 0xf0) ^ (major << 4)));

	return (high << 8) | low;
}

/*
 * Compute HEC for GUID bytes ``start'' to ``end'', inclusive.
 */
static inline uint8
calculate_hec(const struct guid *guid, int start, int end)
{
	int i;
	uint8 hec = 0;

	g_assert(start >= 0);
	g_assert(end <= 15);

	for (i = start; i <= end; i++)
		hec = syndrome_table[hec ^ peek_u8(&guid->v[i])];

	return hec ^ HEC_GTKG_MASK;
}

/**
 * Compute GUID's HEC over bytes 1..15.
 */
static uint8
guid_hec(const struct guid *guid)
{
	return calculate_hec(guid, 1, 15);
}

/**
 * Compute GUID's HEC over bytes 0..14.
 *
 * This is the old way of computing the GUID HEC, and is no longer deemed
 * appropriate because it does not work when the query is OOB proxied by
 * an ultrapeer (the IP:port field being superseded later).
 */
static uint8
guid_hec_oob_legacy(const struct guid *guid)
{
	return calculate_hec(guid, 0, 14);
}

/**
 * Compute GUID's HEC for a query, leaving out bytes 0-3 (used in OOB queries
 * to add the IP address) and bytes 13-14 (used to carry the port number in
 * OOB queries), the HEC being stored in byte 15.
 *
 * That way, even if the query is later OOB-proxied by someone, we will not
 * alter the HEC's value and preserve our ability to recognize a marked GUID.
 *
 * Note that starting 2012-10-07, this is the new way to encode MUIDs in
 * queries, even for those not initially sent out with OOB.
 */
static uint8
guid_hec_oob(const struct guid *guid)
{
	return calculate_hec(guid, 4, 12);
}

/**
 * FIXME: This is actually long deprecated by now. LimeWire does not care about
 * it anymore but some older or less maintained clients might still care. It
 * reduces the randomness of the MUIDs resp. GUID and makes them stick out too.
 *
 * Make sure the MUID we use in initial handshaking pings are marked
 * specially to indicate we're modern nodes.
 */
static void
guid_flag_modern(struct guid *muid)
{
	/*
	 * We're a "modern" client, meaning we're not Gnutella 0.56.
	 * Therefore we must set our ninth byte, muid[8] to 0xff, and
	 * put the protocol version number in muid[15].	For 0.4, this
	 * means 0.
	 *				--RAM, 15/09/2001
	 */

	muid->v[8] = (unsigned char) 0xffU;
	muid->v[15] = GUID_PONG_CACHING | GUID_PERSISTENT;
}

/**
 * Flag a GUID/MUID as being from GTKG, by patching `guid' in place.
 *
 * Bytes 2/3 become the GTKG version mark.
 * Byte 0 becomes the HEC of the remaining 15 bytes.
 */
static void
guid_flag_gtkg(struct guid *guid)
{
	poke_be16(&guid->v[2], gtkg_version_mark);
	guid->v[0] = guid_hec(guid);
}

/**
 * Flag a MUID for OOB queries as being from GTKG, by patching `guid' in place.
 *
 * Bytes 4/5 become the GTKG version mark.
 * Byte 15 becomes the HEC of the leading 15 bytes.
 */
static void
guid_flag_oob_gtkg(struct guid *muid)
{
	poke_be16(&muid->v[4], gtkg_version_mark);
	muid->v[15] = guid_hec_oob(muid);		/* guid_hec() skips leading byte */
}

/**
 * Decode major/minor and release information from the specified two
 * contiguous GUID bytes.
 *
 * @param guid is the GUID considered
 * @param start is the offset of the markup (2 or 4) in the GUID
 * @param majp is filled with the major version if it's a GTKG markup
 * @param minp is filled with the minor version if it's a GTKG markup
 * @param relp is filled with the release status if it's a GTKG markup
 *
 * @return whether we recognized a GTKG markup.
 */
static bool
guid_extract_gtkg_info(const struct guid *guid, size_t start,
	uint8 *majp, uint8 *minp, bool *relp)
{
	uint8 major;
	uint8 minor;
	bool release;
	uint16 mark;
	uint16 xmark;
	uint8 product_major;

	g_assert(start < GUID_RAW_SIZE - 1);
	major = peek_u8(&guid->v[start]) & 0x0f;
	minor = peek_u8(&guid->v[start + 1]) & 0x7f;
	release = booleanize(0 == (peek_u8(&guid->v[start + 1]) & 0x80));

	mark = guid_gtkg_encode_version(major, minor, release);
	xmark = peek_be16(&guid->v[start]);

	if (mark != xmark)
		return FALSE;

	/*
	 * Even if by extraordinary the above check matches, make sure we're
	 * not distant from more than one major version.  Since GTKG versions
	 * expire every year, and I don't foresee more than one major version
	 * release per year, this strengthens the positive check.
	 */

	product_major = product_get_major();

	if (major != product_major) {
		int8 delta = product_major - major;
		if (delta < -1 || delta > 1)
			return FALSE;
	}

	/*
	 * We've validated the GUID: the HEC is correct and the version is
	 * consistently encoded, judging by the highest 4 bits of guid.v[4].
	 */

	if (majp) *majp = major;
	if (minp) *minp = minor;
	if (relp) *relp = release;

	return TRUE;
}

/**
 * Test whether GUID is that of GTKG, and extract version major/minor, along
 * with release status provided the `majp', `minp' and `relp' are non-NULL.
 */
bool
guid_is_gtkg(const struct guid *guid,
	uint8 *majp, uint8 *minp, bool *relp)
{
	if (peek_u8(&guid->v[0]) != guid_hec(guid))
		return FALSE;

	return guid_extract_gtkg_info(guid, 2, majp, minp, relp);
}

/**
 * Test whether a GTKG MUID in a Query is marked as being a retry.
 */
bool
guid_is_requery(const struct guid *guid)
{
	return (peek_u8(&guid->v[15]) & GUID_REQUERY) ? TRUE : FALSE;
}

/**
 * Test whether a GUID is blank.
 */
bool
guid_is_blank(const struct guid *guid)
{
	size_t i;

	g_assert(guid);

	for (i = 0; i < GUID_RAW_SIZE; i++)
		if (guid->v[i])
			return FALSE;

	return TRUE;
}

/**
 * Generate a new random GUID, flagged as GTKG.
 */
void
guid_random_muid(struct guid *muid)
{
	guid_random_fill(muid);
	guid_flag_gtkg(muid);		/* Mark as being from GTKG */
}

/**
 * Generate a new random (modern) message ID for pings.
 */
void
guid_ping_muid(struct guid *muid)
{
	guid_random_fill(muid);
	guid_flag_modern(muid);
	guid_flag_gtkg(muid);		/* Mark as being from GTKG */
}

/**
 * Generate a new random message ID for queries.
 * If `initial' is false, this is a requery.
 */
void
guid_query_muid(struct guid *muid, bool initial)
{
	guid_random_fill(muid);

	/*
	 * Since 2012-10-07, we call guid_flag_oob_gtkg() instead of
	 * guid_flag_gtkg() to mark the MUID of the query, regardless of
	 * whether it is sent out as an OOB query.
	 *
	 * That way, even if it is OOB-proxied by an ultrapeer, we will
	 * be able to recognize the markup.
	 */

	guid_flag_oob_gtkg(muid);		/* Mark as being from GTKG */

	if (initial)
		muid->v[15] &= ~GUID_REQUERY;
	else
		muid->v[15] |= GUID_REQUERY;
}

/**
 * Generate a new GUID atom that is not already conflicting with any other
 * GUID recorded in the supplied hikset (hash set with values pointing to
 * the GUID key).
 *
 * @attention
 * It is up to the caller to later insert the value referencing this GUID in
 * the hikset to prevent further duplicates.  To avoid race conditions between
 * the checking of the hiset and the insertion, the hikset should be locked
 * if it is shared by multiple threads.
 *
 * @param hik		the hikset against which we need to check for duplicates
 * @param gtkg		whether to flag the GUID as being generated by GTKG.
 *
 * @return a new unique GUID atom.
 */
const guid_t *
guid_unique_atom(const hikset_t *hik, bool gtkg)
{
	int i;
	guid_t guid;

	entropy_harvest_time();

	for (i = 0; i < 100; i++) {
		guid_random_fill(&guid);
		if (gtkg)
			guid_flag_gtkg(&guid);	/* Mark as being from GTKG */

		if (NULL == hikset_lookup(hik, &guid))
			return atom_guid_get(&guid);
	}

	g_error("%s(): no luck with random number generator", G_STRFUNC);
}

/**
 * Test whether GUID is that of GTKG, and extract version major/minor, along
 * with release status provided the `majp', `minp' and `relp' are non-NULL.
 */
static bool
guid_oob_is_gtkg(const struct guid *guid,
	uint8 *majp, uint8 *minp, bool *relp)
{
	uint8 hec;

	if (!guid_extract_gtkg_info(guid, 4, majp, minp, relp))
		return FALSE;		/* Marking incorrect, no need to compute HEC */

	/*
	 * The HEC for OOB queries was made of the first 15 bytes for versions
	 * up to 0.98.4u (legacy encoding).  Starting with 0.98.4, we have a
	 * different way of encoding the HEC to preserve its integrity even in
	 * the advent of OOB-proxying.
	 *
	 * Also bit 0 of the HEC is not significant (used to mark requeries)
	 * therefore it is masked out for comparison purposes.
	 */

	hec = peek_u8(&guid->v[15]) & ~GUID_REQUERY;

	if (*majp >0 || *minp >= 99)
		return booleanize((guid_hec_oob(guid) & ~GUID_REQUERY) == hec);

	/*
	 * Transition period for servents earlier than 0.99: try the legacy marking
	 * for 0.97 and earlier. For 0.98, try the legacy marking first, then the
	 * new marking.
	 */

	if (*minp <= 97)
		return booleanize((guid_hec_oob_legacy(guid) & ~GUID_REQUERY) == hec);

	return booleanize((guid_hec_oob_legacy(guid) & ~GUID_REQUERY) == hec) ||
		booleanize((guid_hec_oob(guid) & ~GUID_REQUERY) == hec);
}

/**
 * Check whether the MUID of a query is that of GTKG.
 *
 * GTKG uses MUID tagging, but unfortunately, the bytes used to store the
 * IP and port for OOB query hit delivery conflict with the bytes used for
 * the tagging of other MUIDs.  Hence the need for a special routine, dedicated
 * to query MUID markup.
 *
 * @param guid	the MUID of the message
 * @param oob	whether the query requests OOB query hit delivery
 * @param majp	where the major release version is written, if GTKG
 * @param minp	where the minor release version is written, if GTKG
 * @param relp	where the release indicator gets written, if GTKG
 */
bool
guid_query_muid_is_gtkg(const struct guid *guid, bool oob,
	uint8 *majp, uint8 *minp, bool *relp)
{
	/*
	 * We used to encode the query MUID differently depending on whether OOB
	 * queries were used or just plain ones, but we are now always using
	 * an encoding and a tagging that ignores the bytes which can be superseded
	 * by OOB proxying.
	 *		--RAM, 2012-10-07
	 */

	if (guid_oob_is_gtkg(guid, majp, minp, relp))
		return TRUE;

	/*
	 * For legacy GTKG servents which may have encoded non-OOB queries
	 * differently.  This will only work if the query was not flagged for
	 * OOB, since then our legacy markup is superseded!
	 *		--RAM, 2012-10-07
	 */

	if (oob)
		return FALSE;

	return guid_is_gtkg(guid, majp, minp, relp);	/* Plain old markup */
}

/**
 * Generate GUID for a query with OOB results delivery.
 * If `initial' is false, this is a requery.
 *
 * Bytes 0 to 3 if the GUID are the 4 octet bytes of the IP address.
 * Bytes 13 and 14 are the little endian representation of the port.
 * Byte 15 holds an HEC with bit 0 indicating a requery.
 */
void
guid_query_oob_muid(struct guid *muid, const host_addr_t addr, uint16 port,
	bool initial)
{
	uint32 ip;

	g_assert(host_addr_is_ipv4(addr));

	guid_random_fill(muid);

	ip = host_addr_ipv4(addr);
	poke_be32(&muid->v[0], ip);
	poke_le16(&muid->v[13], port);

	guid_flag_oob_gtkg(muid);		/* Mark as being from GTKG */

	if (initial)
		muid->v[15] &= ~GUID_REQUERY;
	else
		muid->v[15] |= GUID_REQUERY;
}

/**
 * Extract the IP and port number from the GUID of queries marked for OOB
 * query hit delivery.
 *
 * Bytes 0 to 3 of the guid are the 4 octet bytes of the IP address.
 * Bytes 13 and 14 are the little endian representation of the port.
 */
void
guid_oob_get_addr_port(const struct guid *guid,
	host_addr_t *addr, uint16 *port)
{
	if (addr) {
		/*
		 * IPv6-Ready: this is always 4 bytes, even if the final address is
		 * an IPv6 one because the GGEP "6" key will supply us the IPv6
		 * address should the IPv4 one be 127.0.0.0.
		 */
		*addr = host_addr_peek_ipv4(&guid->v[0]);
	}
	if (port) {
		*port = peek_le16(&guid->v[13]);
	}
}

/**
 * Is GUID banned?
 */
bool
guid_is_banned(const struct guid *guid)
{
	return dbmw_exists(db_guid, guid);
}

/**
 * Free GUID atom -- aging table callback version.
 */
void
guid_free_atom2(void *guid, void *unused)
{
	(void) unused;
	atom_guid_free(guid);
}

/**
 * Get banned GUID data from database, returning NULL if not found.
 */
static struct guiddata *
get_guiddata(const struct guid *guid)
{
	struct guiddata *gd;

	gd = dbmw_read(db_guid, guid, NULL);

	if (NULL == gd) {
		if (dbmw_has_ioerr(db_guid)) {
			s_warning_once_per(LOG_PERIOD_MINUTE,
				"DBMW \"%s\" I/O error", dbmw_name(db_guid));
		}
	}

	return gd;
}

/**
 * Add GUID to the banned list or refresh the fact that we are still seeing
 * it as being worth banning.
 */
void
guid_add_banned(const struct guid *guid)
{
	struct guiddata *gd;
	struct guiddata new_gd;

	gd = get_guiddata(guid);

	if (NULL == gd) {
		gd = &new_gd;
		gd->create_time = gd->last_time = tm_time();
		gnet_stats_inc_general(GNR_BANNED_GUID_HELD);

		if (GNET_PROPERTY(guid_debug)) {
			g_debug("GUID banning %s", guid_hex_str(guid));
		}
	} else {
		gd->last_time = tm_time();
	}

	dbmw_write(db_guid, guid, gd, sizeof *gd);
}

/**
 * DBMW foreach iterator to remove old entries.
 * @return TRUE if entry must be deleted.
 */
static bool
guid_prune_old_entries(void *key, void *value, size_t u_len, void *u_data)
{
	const guid_t *guid = key;
	const struct guiddata *gd = value;
	time_delta_t d;
	double p = 0.0;
	bool expired;

	(void) u_len;
	(void) u_data;

	/*
	 * We reuse the statistical probability model of DHT nodes to project
	 * whether it makes sense to keep an entry.
	 */

	d = delta_time(tm_time(), gd->last_time);
	if (gd->create_time == gd->last_time) {
		expired = d > GUID_STABLE_LIFETIME;
	} else {
		p = stable_still_alive_probability(gd->create_time, gd->last_time);
		expired = p < GUID_STABLE_PROBA;
	}

	if (GNET_PROPERTY(guid_debug) > 5) {
		g_debug("GUID cached %s life=%s last_seen=%s, p=%.2f%%%s",
			guid_hex_str(guid),
			compact_time(delta_time(gd->last_time, gd->create_time)),
			compact_time2(d), p * 100.0,
			expired ? " [EXPIRED]" : "");
	}

	return expired;
}

/**
 * Prune the database of banned GUIDs, removing expired entries.
 */
static void
guid_prune_old(void)
{
	if (GNET_PROPERTY(guid_debug))
		g_debug("GUID pruning expired entries (%zu)", dbmw_count(db_guid));

	dbmw_foreach_remove(db_guid, guid_prune_old_entries, NULL);
	gnet_stats_set_general(GNR_BANNED_GUID_HELD, dbmw_count(db_guid));

	if (GNET_PROPERTY(guid_debug)) {
		g_debug("GUID pruned expired entries (%zu remaining)",
			dbmw_count(db_guid));
	}
}

/**
 * Callout queue periodic event to expire old entries.
 */
static bool
guid_periodic_prune(void *unused_obj)
{
	(void) unused_obj;

	guid_prune_old();
	return TRUE;		/* Keep calling */
}

/**
 * Callout queue periodic event to synchronize the disk image.
 */
static bool
guid_periodic_sync(void *unused_obj)
{
	(void) unused_obj;

	dbstore_sync_flush(db_guid);
	return TRUE;		/* Keep calling */
}

/**
 * Initialize GUID management.
 */
G_GNUC_COLD void
guid_init(void)
{
	dbstore_kv_t kv = {
		sizeof(guid_t), NULL, sizeof(struct guiddata),
		1 + sizeof(struct guiddata)	/* Version byte not held in structure */
	};
	dbstore_packing_t packing = {
		serialize_guiddata, deserialize_guiddata, NULL
	};
	char rev;		/* NUL means stable release */

	g_assert(NULL == db_guid);

	guid_gen_syndrome_table();

	rev = product_get_revchar();
	gtkg_version_mark =
		guid_gtkg_encode_version(product_get_major(),
			product_get_minor(), '\0' == rev);

	if (GNET_PROPERTY(node_debug))
		g_debug("GTKG version mark is 0x%x", gtkg_version_mark);

	/*
	 * Validate that guid_random_muid() correctly marks GUIDs as being GTKG's.
	 */

	{
		struct guid guid_buf;

		guid_random_muid(&guid_buf);
		g_assert(guid_is_gtkg(&guid_buf, NULL, NULL, NULL));
	}

	db_guid = dbstore_open(db_guid_what, settings_gnet_db_dir(),
		db_guid_base, kv, packing, 1,
		guid_hash, guid_eq, FALSE);

	guid_prune_old();

	guid_prune_ev = cq_periodic_main_add(
		GUID_PRUNE_PERIOD, guid_periodic_prune, NULL);
	guid_sync_ev = cq_periodic_main_add(
		GUID_SYNC_PERIOD, guid_periodic_sync, NULL);
}

/**
 * Close GUID management.
 */
G_GNUC_COLD void
guid_close(void)
{
	dbstore_close(db_guid, settings_gnet_db_dir(), db_guid_base);
	db_guid = NULL;
	cq_periodic_remove(&guid_prune_ev);
	cq_periodic_remove(&guid_sync_ev);
}

/* vi: set ts=4 sw=4 cindent: */
