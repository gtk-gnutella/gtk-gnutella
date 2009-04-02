/*
 * $Id$
 *
 * Copyright (c) 2002-2003, Raphael Manfredi
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
 * @date 2002-2003
 */

#include "common.h"

RCSID("$Id$")

#include "guid.h"
#include "lib/misc.h"
#include "lib/endian.h"

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

const struct guid blank_guid;

static guint8 syndrome_table[256];
static guint16 gtkg_version_mark;

/**
 * Generate a table of CRC-8 syndromes for all possible input bytes.
 */
static void
guid_gen_syndrome_table(void)
{
	unsigned i;
	unsigned j;

	for (i = 0; i < 256; i++) {
		unsigned syn = i;
		for (j = 0; j < 8; j++) {
			syn <<= 1;
			if (syn & 0x80)
				syn ^= HEC_GENERATOR;
		}
		syndrome_table[i] = (guint8) syn;
	}
}

/**
 * Encode major/minor version into 16 bits.
 * If `rel' is true, we're a release, otherwise we're unstable or a beta.
 */
static guint16
guid_gtkg_encode_version(unsigned major, unsigned minor, gboolean rel)
{
	guint8 low;
	guint8 high;

	g_assert(major < 0x10);
	g_assert(minor < 0x80);

	/*
	 * Low byte of result is the minor number.
	 * MSB is set for unstable releases.
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

static inline guint8
calculate_hec(const struct guid *guid, size_t offset)
{
	int i;
	guint8 hec = 0;

	for (i = 0; i < 15; i++)
		hec = syndrome_table[hec ^ peek_u8(&guid->v[i + offset])];

	return hec ^ HEC_GTKG_MASK;
}

/**
 * Compute GUID's HEC over bytes 1..15.
 */
static guint8
guid_hec(const struct guid *guid)
{
	return calculate_hec(guid, 1);
}

/**
 * Compute GUID's HEC over bytes 0..14.
 */
static guint8
guid_hec_oob(const struct guid *guid)
{
	return calculate_hec(guid, 0);
}

/**
 * Initialize GUID management.
 */
void
guid_init(void)
{
	const char *rev = GTA_REVCHAR;	/* Empty string means stable release */

	guid_gen_syndrome_table();

	gtkg_version_mark =
		guid_gtkg_encode_version(GTA_VERSION, GTA_SUBVERSION, *rev == '\0');

	if (GNET_PROPERTY(dbg))
		printf("GTKG version mark is 0x%x\n", gtkg_version_mark);

	/*
	 * Validate that guid_random_muid() correctly marks GUIDs as being GTKG's.
	 */

	{
		struct guid guid_buf;

		guid_random_muid(&guid_buf);
		g_assert(guid_is_gtkg(&guid_buf, NULL, NULL, NULL));
	}
}

/**
 * FIXME: This actually long deprecated by now. LimeWire does not care about
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
static gboolean
guid_extract_gtkg_info(const struct guid *guid, size_t start,
	guint8 *majp, guint8 *minp, gboolean *relp)
{
	guint8 major;
	guint8 minor;
	gboolean release;
	guint16 mark;
	guint16 xmark;

	g_assert(start < GUID_RAW_SIZE - 1);
	major = peek_u8(&guid->v[start]) & 0x0f;
	minor = peek_u8(&guid->v[start + 1]) & 0x7f;
	release = (peek_u8(&guid->v[start + 1]) & 0x80) ? FALSE : TRUE;

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

	if (major != GTA_VERSION) {
		if (major + 1 != GTA_VERSION || major - 1 != GTA_VERSION)
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
gboolean
guid_is_gtkg(const struct guid *guid,
	guint8 *majp, guint8 *minp, gboolean *relp)
{
	if (peek_u8(&guid->v[0]) != guid_hec(guid))
		return FALSE;

	return guid_extract_gtkg_info(guid, 2, majp, minp, relp);
}

/**
 * Test whether a GTKG MUID in a Query is marked as being a retry.
 */
gboolean
guid_is_requery(const struct guid *guid)
{
	return (peek_u8(&guid->v[15]) & GUID_REQUERY) ? TRUE : FALSE;
}

/**
 * Test whether a GUID is blank.
 */
gboolean
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
guid_query_muid(struct guid *muid, gboolean initial)
{
	guint8 v;

	guid_random_fill(muid);

	v = peek_u8(&muid->v[15]);
	if (initial)
		v &= ~GUID_REQUERY;
	else
		v |= GUID_REQUERY;
	muid->v[15] = v;
	guid_flag_gtkg(muid);		/* Mark as being from GTKG */
}

/**
 * Flag a MUID for OOB queries as being from GTKG, by patching `guid' in place.
 *
 * Bytes 4/5 become the GTKG version mark.
 * Byte 15 becomes the HEC of the leading 15 bytes.
 */
static void
guid_flag_oob_gtkg(struct guid *guid)
{
	poke_be16(&guid->v[4], gtkg_version_mark);
	guid->v[15] = guid_hec_oob(guid);		/* guid_hec() skips leading byte */
}

/**
 * Test whether GUID is that of GTKG, and extract version major/minor, along
 * with release status provided the `majp', `minp' and `relp' are non-NULL.
 */
static gboolean
guid_oob_is_gtkg(const struct guid *guid,
	guint8 *majp, guint8 *minp, gboolean *relp)
{
	/*
	 * The HEC for OOB queries is made of the first 15 bytes.  We can offset
	 * the argument to guid_hec() by 1 because that routine starts at the byte
	 * after its argument.
	 *
	 * Also bit 0 of the HEC is not significant (used to mark requeries)
	 * therefore it is masked out for comparison purposes.
	 */

	if ((peek_u8(&guid->v[15]) & ~GUID_REQUERY) != (guid_hec_oob(guid) & ~GUID_REQUERY))
		return FALSE;

	return guid_extract_gtkg_info(guid, 4, majp, minp, relp);
}

/**
 * Check whether the MUID of a query is that of GTKG.
 *
 * GTKG uses GUID tagging, but unfortunately, the bytes uses to store the
 * IP and port for OOB query hit delivery conflict with the bytes used for
 * the tagging.  Hence the need for a special routine.
 *
 * @param guid	the MUID of the message
 * @param oob	whether the query requests OOB query hit delivery
 * @param majp	where the major release version is written, if GTKG
 * @param minp	where the minor release version is written, if GTKG
 * @param relp	where the release indicator gets written, if GTKG
 */
gboolean
guid_query_muid_is_gtkg(const struct guid *guid, gboolean oob,
	guint8 *majp, guint8 *minp, gboolean *relp)
{
	gboolean is_gtkg;

	if (oob)
		return guid_oob_is_gtkg(guid, majp, minp, relp);

	/*
	 * There is an ambiguity if the query is not marked as being OOB,
	 * because GTKG can initially select an OOB-encoding of the GUID yet
	 * not emit the query with the OOB flag because it realizes the servent
	 * is UDP-firewalled, or the user changed his mind and turned off OOB
	 * queries.
	 *
	 * Therefore, try to decode as OOB first, and if it fails being recognized
	 * as a GTKG marking, use the plain old markup instead.
	 */

	is_gtkg = guid_oob_is_gtkg(guid, majp, minp, relp);

	if (is_gtkg)
		return TRUE;

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
guid_query_oob_muid(struct guid *muid, const host_addr_t addr, guint16 port,
	gboolean initial)
{
	guint32 ip;

	guid_random_fill(muid);

	ip = host_addr_ipv4(addr); /* @todo TODO: IPv6 */
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
	host_addr_t *addr, guint16 *port)
{
	if (addr) {
		*addr = host_addr_peek_ipv4(&guid->v[0]); /* @todo TODO: IPv6 */
	}
	if (port) {
		*port = peek_le16(&guid->v[13]);
	}
}

/* vi: set ts=4 sw=4 cindent: */
