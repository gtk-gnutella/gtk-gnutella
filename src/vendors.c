/*
 * $Id$
 *
 * Copyright (c) 2001-2002, Richard Eckart
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

#include "vendors.h"

#include <ctype.h>

struct {
    guint32 code;
    gchar * name;
} vendor_map[] = {
    { T_ARES, "Ares" },
    { T_BEAR, "BearShare" },
    { T_COCO, "CocoGnut" },
    { T_CULT, "Cultiv8r" },
    { T_FIRE, "FireFly" },
    { T_FISH, "PEERahna" },
    { T_GNEW, "Gnewtellium" },
    { T_GNOT, "Gnotella" },
    { T_GNUC, "Gnucleus" },
    { T_GNUT, "Gnut" },
    { T_GTKG, "gtk-gnutella" },
    { T_HSLG, "Hagelslag" },
    { T_LIME, "Limewire" },
    { T_MACT, "Mactella" },
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
    { T_SNUT, "SwapNut" },
    { T_SWAP, "Swapper" },
    { T_SWFT, "Swift" },
    { T_TOAD, "ToadNode" },
    { T_XOLO, "Xolox" },
    { T_XTLA, "Xtella" },
    { T_ZIGA, "Ziga" }
};

#define READ_GUINT32_BE(a,v) { memcpy(&v, a, 4); v = GUINT32_FROM_BE(v); }


/*
 * is_vendor_known:
 *
 * Return true is gtk-gnutella knows the given 4-byte vendor code.
 */
gboolean is_vendor_known(guchar raw[4])
{
    gint n;
    guint32 code;
    READ_GUINT32_BE(raw, code);

    if (raw[0] == '0')
        return FALSE;

    for (n = 0; n < (sizeof(vendor_map)/sizeof(vendor_map[0])); n++)
        if (code == vendor_map[n].code)
            return TRUE;

    return FALSE;
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
    gint i;
    guint32 code;

    if (raw[0] == '0')
        return NULL;

    READ_GUINT32_BE(raw, code);

    for (i = 0; i < (sizeof(vendor_map)/sizeof(vendor_map[0])); i++)
        if (code == vendor_map[i].code)
            return vendor_map[i].name;

	/* Unknown type, look whether we have all printable ASCII */
	for (i = 0; i < sizeof(code); i++) {
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
