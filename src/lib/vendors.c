/*
 * Copyright (c) 2001-2003, Richard Eckart
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
 * Vendor code management.
 *
 * @author Richard Eckart
 * @date 2001-2003
 */

#include "common.h"

#include "vendors.h"

#include "ascii.h"
#include "buf.h"
#include "endian.h"
#include "glib-missing.h"	/* For g_strlcpy() */
#include "misc.h"
#include "override.h"	/* Must be the last header included */

static const struct vendor {
    uint32 code;
    const char *name;
} vendor_map[] = {
	/* This array MUST be sorted, because it is searched dichotomically */

    { T_ACQL, "AcqLite" },
    { T_ACQX, "Acquisition" },
    { T_AGIO, "Adagio" },
    { T_AGNT, "Agentella" },
    { T_ARES, "Ares" },
    { T_ATOM, "AtomWire" },
    { T_AZOO, "AyZoo" },
    { T_BARE, "BearShare-v4" },
    { T_BEAR, "BearShare" },
    { T_BGNU, "brandGNU" },
    { T_COCO, "CocoGnut" },
    { T_CULT, "Cultiv8r" },
    { T_DRIP, "Driptella" },
    { T_EVIL, "Suicide" },
    { T_FEVR, "FileFever" },
    { T_FIRE, "FireFly" },
    { T_FISH, "PEERanha" },
    { T_FOXY, "Foxy" },
    { T_FSCP, "FileScope" },
    { T_FZZN, "Fuzzon" },
    { T_GDNA, "Gnucleus DNA" },
    { T_GIFT, "giFT" },
    { T_GNEW, "Gnewtellium" },
    { T_GNOT, "Gnotella" },
    { T_GNTD, "Gnet Daemon" },
    { T_GNTG, "Gnutelligentsia" },
    { T_GNUC, "Gnucleus" },
    { T_GNUM, "Gnuminous" },
    { T_GNUT, "Gnut" },
    { T_GNZL, "Gnoozle" },
    { T_GSHR, "GnuShare" },
    { T_GTKG, "gtk-gnutella" },
    { T_HSLG, "Hagelslag" },
    { T_HUIT, "Huitella" },
    { T_HYDR, "Hydranode" },
    { T_JHOP, "J-Hop" },
    { T_JOEY, "Jotella" },
    { T_KIKI, "KikiTella" },
    { T_KISS, "Kisstella" },
    { T_LIME, "LimeWire" },
    { T_LION, "LionShare" },
    { T_MACT, "Mactella" },
    { T_MESH, "iMesh" },
    { T_MIRT, "Mirtella" },
    { T_MLDK, "MLDonkey" },
    { T_MMMM, "Morpheus-v2" },
    { T_MNAP, "MyNapster" },
    { T_MOOD, "MoodAmp" },
    { T_MRPH, "Morpheus" },
    { T_MUTE, "Mutella" },
    { T_MXIE, "mxie" },
    { T_NAPS, "NapShare" },
    { T_NGET, "Gnuget" },
    { T_NOOG, "Noogtella" },
    { T_NOVA, "NovaP2P" },
    { T_OCFG, "OpenCola" },
    { T_OPRA, "Opera" },
    { T_OXID, "Oxide" },
    { T_PCST, "Peercast" },
    { T_PEER, "PeerProject" },
    { T_PHEX, "Phex" },
    { T_PWRT, "PowerTella" },
    { T_QAZA, "Quazaa" },
    { T_QAZB, "Quazaa Beta" },
    { T_QTEL, "Qtella" },
    { T_RASP, "Rasputin" },
    { T_RAZA, "Shareaza" },
    { T_RAZB, "Shareaza Beta" },
    { T_RAZL, "ShareazaLite" },
    { T_RZCA, "ShareazaPlus Alpha" },
    { T_RZCB, "ShareazaPlus Beta" },
    { T_RZCC, "ShareazaPlus" },
    { T_SHLN, "Sharelin" },
    { T_SHNB, "Shinobu" },
    { T_SNOW, "FrostWire" },
    { T_SNUT, "SwapNut" },
    { T_STRM, "Storm" },
    { T_SWAP, "Swapper" },
    { T_SWFT, "Swift" },
    { T_TFLS, "TrustyFiles" },
    { T_TOAD, "ToadNode" },
    { T_VPUT, "Vputella" },
    { T_WAST, "Waste" },
    { T_XOLO, "Xolox" },
    { T_XTLA, "Xtella" },
    { T_YAFS, "UlfsYAFS" },
    { T_ZIGA, "Ziga" },
    { T_peer, "Peeranha" },

	/* Above line intentionally left blank (for "!}sort" on vi) */
};

/**
 * Find vendor name, given vendor code.
 *
 * @returns vendor string if found, NULL otherwise.
 */
static const char * G_HOT
find_vendor(uint32 code)
{
#define GET_KEY(i)	(vendor_map[(i)].code)
#define FOUND(i)	return vendor_map[(i)].name

	BINARY_SEARCH(uint32, code, G_N_ELEMENTS(vendor_map), VENDOR_CODE_CMP,
		GET_KEY, FOUND);

#undef FOUND
#undef GET_KEY

	return NULL; /* not found */
}

/**
 * @return true is gtk-gnutella knows the given 4-byte vendor code.
 */
bool
is_vendor_known(vendor_code_t code)
{
    if (code.u32 == T_0000)
        return FALSE;

	return find_vendor(code.u32) != NULL;
}

/**
 * @return TRUE If the 4-byte vendor code is acceptable.
 */
bool
is_vendor_acceptable(vendor_code_t code)
{
	char temp[4];

	memcpy(temp, &code.u32, 4);
	return is_ascii_alnum(temp[0]) &&
		is_ascii_alnum(temp[1]) &&
		is_ascii_alnum(temp[2]) &&
		is_ascii_alnum(temp[3]);
}

/**
 * Make up a printable version of the vendor code.
 *
 * @param code A 4-letter Gnutella vendor ID in host-endian order thus
 *        after peek_be32() or ntohl().
 * @param buf  The destination buffer to hold the string.
 * @param size The size of buf in bytes.
 *
 * @return Length of the resulting string before potential truncation.
 */
size_t
vendor_code_to_string_buf(uint32 code, char *buf, size_t size)
{
    if (code == 0) {
		return g_strlcpy(buf, "null", size);
	} else {
		char temp[5];
		size_t i;

		poke_be32(&temp[0], code);

		for (i = 0; i < G_N_ELEMENTS(temp) - 1; i++) {
			if (!is_ascii_print(temp[i]))
				temp[i] = '.';
		}
		temp[4] = '\0';
		return g_strlcpy(buf, temp, size);
	}
}

/**
 * Make up a printable version of the vendor code.
 *
 * @param code A 4-letter Gnutella vendor ID in host-endian order thus
 *        after peek_be32() or ntohl().
 *
 * @return pointer to static data.
 */
const char *
vendor_code_to_string(uint32 code)
{
	buf_t *b = buf_private(G_STRFUNC, 5);
	char *p = buf_data(b);

	vendor_code_to_string_buf(code, p, buf_size(b));
	return p;
}

/**
 * Return the "human readable" name associated with the 4-byte vendor code.
 * If we can't understand the code return NULL or if the 4-byte code
 * consists only of printable characters, return the code as a string.
 */
const char *
vendor_code_get_name(uint32 code)
{
	const char *name;

    if (0 == code) {
		return NULL;
	} else if (NULL != (name = find_vendor(code))) {
		return name;
	} else {
		buf_t *b = buf_private(G_STRFUNC, 5);
		char *p = buf_data(b);
		unsigned i;

		g_assert(sizeof code == buf_size(b) - 1);
		poke_be32(p, code);

		/* Unknown type, look whether we have all printable ASCII */
		for (i = buf_size(b); i != 0; i--) {
			if (!is_ascii_alnum(p[i - 1]))
				return NULL;
		}
		buf_setc(b, 4, '\0');
		return p;
	}
}

/**
 * Make up a printable version of the vendor code.
 *
 * @param vendor	The vendor code.
 *
 * @return pointer to static data.
 */
const char *
vendor_to_string(const vendor_code_t vendor)
{
	buf_t *b = buf_private(G_STRFUNC, 5);
	char *p = buf_data(b);

	vendor_code_to_string_buf(vendor.u32, p, buf_size(b));
	return p;
}

/**
 * Make up a printable version of the vendor code.
 *
 * @param vendor 	The vendor code.
 * @param buf  		The destination buffer to hold the string.
 * @param size 		The size of buf in bytes.
 *
 * @return Length of the resulting string before potential truncation.
 */
size_t
vendor_to_string_buf(const vendor_code_t vendor, char *buf, size_t size)
{
	return vendor_code_to_string_buf(vendor.u32, buf, size);
}

/**
 * Return the "human readable" name associated with the 4-byte vendor code.
 * If we can't understand the code return NULL or if the 4-byte code
 * consists only of printable characters, return the code as a string.
 */
const char *
vendor_get_name(const vendor_code_t vendor)
{
	return vendor_code_get_name(vendor.u32);
}

/**
 * Initialize the vendor lookup.
 */
void G_COLD
vendor_init(void)
{
	BINARY_ARRAY_SORTED(vendor_map, struct vendor, code,
		VENDOR_CODE_CMP, vendor_code_to_string);
}

/* vi: set ts=4 sw=4 cindent: */
