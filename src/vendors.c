/*
 * $Id$
 *
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

#include "gnutella.h"
#include "common.h"

#include <ctype.h>

#include "override.h"		/* Must be the last header included */

RCSID("$Id$");

struct vendor {
    guint32 code;
    gchar *name;
} vendor_map[] = {
	/* This array MUST be sorted, because it is searched dichotomically */

    { T_ACQX, "Acquisition" },
    { T_ARES, "Ares" },
    { T_ATOM, "AtomWire" },
    { T_BARE, "BearShare-v4" },
    { T_BEAR, "BearShare" },
    { T_COCO, "CocoGnut" },
    { T_CULT, "Cultiv8r" },
    { T_EVIL, "Suicide" },
    { T_FEVR, "FileFever" },
    { T_FIRE, "FireFly" },
    { T_FISH, "PEERanha" },
    { T_GDNA, "Gnucleus DNA" },
    { T_GIFT, "giFT" },
    { T_GNEW, "Gnewtellium" },
    { T_GNOT, "Gnotella" },
    { T_GNTD, "Gnet Daemon" },
    { T_GNUC, "Gnucleus" },
    { T_GNUT, "Gnut" },
    { T_GTKG, "gtk-gnutella" },
    { T_HSLG, "Hagelslag" },
    { T_LIME, "LimeWire" },
    { T_MACT, "Mactella" },
    { T_MLDK, "MLDonkey" },
    { T_MMMM, "Morpheus-v2" },
    { T_MNAP, "MyNapster" },
    { T_MRPH, "Morpheus" },
    { T_MUTE, "Mutella" },
    { T_NAPS, "NapShare" },
    { T_OCFG, "OpenCola" },
    { T_OPRA, "Opera" },
    { T_PHEX, "Phex" },
    { T_QTEL, "Qtella" },
    { T_RAZA, "Shareaza" },
    { T_SHNB, "Shinobu" },
    { T_SNUT, "SwapNut" },
    { T_SWAP, "Swapper" },
    { T_SWFT, "Swift" },
    { T_TOAD, "ToadNode" },
    { T_XOLO, "Xolox" },
    { T_XTLA, "Xtella" },
    { T_ZIGA, "Ziga" }

	/* Above line intentionally left blank (for "!}sort" on vi) */
};

#define END(v)		(v - 1 + sizeof(v) / sizeof(v[0]))

/*
 * vendor_code_cmp
 *
 * Compare two codes, alphanumerically (i.e. "ACQX" < "GTKG").
 * Returns -1/0/+1 depending on comparison's sign.
 */
gint vendor_code_cmp(guint32 a, guint32 b)
{
	gint i;

	if (a == b)
		return 0;

	for (i = 0; i < 4; i++) {
		guint32 mask = 0xff << ((3 - i) << 3);		/* (3 - i) * 8 */
		guint32 ax = a & mask;
		guint32 bx = b & mask;

		if (ax == bx)
			continue;

		return ax < bx ? -1 : +1;
	}

	g_assert(0);		/* Not reached */
	return 0;			/* To shut up compiler warnings */
}

/*
 * find_vendor
 *
 * Find vendor name, given vendor code.
 * Returns vendor string if found, NULL otherwise.
 */
static gchar *find_vendor(guchar raw[4])
{
	struct vendor *low = vendor_map;
	struct vendor *high = END(vendor_map);
	guint32 code;

    READ_GUINT32_BE(raw, code);

	while (low <= high) {
		struct vendor *mid = low + (high - low) / 2;
		gint c = vendor_code_cmp(mid->code,  code);

		if (c == 0)
			return mid->name;
		else if (c < 0)
			low = mid + 1;
		else
			high = mid - 1;
	}

	return NULL;		/* Not found */
}

/*
 * is_vendor_known:
 *
 * Return true is gtk-gnutella knows the given 4-byte vendor code.
 */
gboolean is_vendor_known(guchar raw[4])
{
    if (raw[0] == '\0')
        return FALSE;

	return find_vendor(raw) != NULL;
}

/*
 * vendor_code_str
 *
 * Make up a printable version of the vendor code.
 * Returns pointer to static data.
 */
gchar *vendor_code_str(guint32 code)
{
	static gchar temp[5];
    gint i;

	WRITE_GUINT32_BE(code, temp);
	temp[4] = '\0';

	for (i = 0; i < 4; i++) {
        guchar c = temp[i];
		if (!isascii(c) || !isprint(c))
			temp[i] = '.';
	}

	return temp;
}

/*
 * lookup_vendor_name
 *
 * Return the "human readable" name associated with the 4-byte vendor code.
 * If we can't understand the code return NULL or if the 4-byte code
 * consists only of printable characters, return the code as a string.
 */
gchar *lookup_vendor_name(guchar raw[4])
{
	static gchar temp[5];
	gchar *name;
    gint i;

    if (raw[0] == '\0')
        return NULL;

	name = find_vendor(raw);
	if (name != NULL)
		return name;

	/* Unknown type, look whether we have all printable ASCII */
	for (i = 0; i < sizeof(raw); i++) {
        guchar c = raw[i];
		if (isascii(c) && isprint(c))
            temp[i] = c;
		else {
            temp[0] = '\0';
			break;
		}
	}
	temp[4] = '\0';

	return temp[0] ? temp : NULL;
}

