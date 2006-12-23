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

/**
 * @ingroup lib
 * @file
 *
 * Vendor code management.
 *
 * @author Richard Eckart
 * @date 2001-2003
 */

#ifndef _vendors_h_
#define _vendors_h_

#include "common.h"

/***
 *** Known gnutella vendor codes
 ***/

#define MAKE_CODE(a,b,c,d) ( \
	((guint32) (a) << 24) | \
	((guint32) (b) << 16) | \
	((guint32) (c) << 8)  | \
	((guint32) (d)))

#define T_ACQL  MAKE_CODE('A','C','Q','L')
#define T_ACQX  MAKE_CODE('A','C','Q','X')
#define T_AGNT  MAKE_CODE('A','G','N','T')
#define T_ARES  MAKE_CODE('A','R','E','S')
#define T_ATOM  MAKE_CODE('A','T','O','M')
#define T_AZOO  MAKE_CODE('A','Z','O','O')
#define T_BARE	MAKE_CODE('B','A','R','E')
#define T_BEAR	MAKE_CODE('B','E','A','R')
#define T_BGNU  MAKE_CODE('B','G','N','U')
#define T_COCO	MAKE_CODE('C','O','C','O')
#define T_CULT	MAKE_CODE('C','U','L','T')
#define T_DRIP  MAKE_CODE('D','R','I','P')
#define T_EVIL	MAKE_CODE('E','V','I','L')
#define T_FEVR	MAKE_CODE('F','E','V','R')
#define T_FIRE	MAKE_CODE('F','I','R','E')
#define T_FISH	MAKE_CODE('F','I','S','H')
#define T_FZZN  MAKE_CODE('F','Z','Z','N')
#define T_GDNA	MAKE_CODE('G','D','N','A')
#define T_GIFT  MAKE_CODE('G','I','F','T')
#define T_GNEW	MAKE_CODE('G','N','E','W')
#define T_GNOT	MAKE_CODE('G','N','O','T')
#define T_GNTD	MAKE_CODE('G','N','T','D')
#define T_GNTG  MAKE_CODE('G','N','T','G')
#define T_GNUC	MAKE_CODE('G','N','U','C')
#define T_GNUM  MAKE_CODE('G','N','U','M')
#define T_GNUT	MAKE_CODE('G','N','U','T')
#define T_GNZL	MAKE_CODE('G','N','Z','L')
#define T_GTKG	MAKE_CODE('G','T','K','G')
#define T_HSLG	MAKE_CODE('H','S','L','G')
#define T_HUIT  MAKE_CODE('H','U','I','T')
#define T_JHOP  MAKE_CODE('J','H','O','P')
#define T_JOEY  MAKE_CODE('J','O','E','Y')
#define T_KIKI  MAKE_CODE('K','I','K','I')
#define T_KISS  MAKE_CODE('K','I','S','S')
#define T_LIME	MAKE_CODE('L','I','M','E')
#define T_LION  MAKE_CODE('L','I','O','N')
#define T_MACT	MAKE_CODE('M','A','C','T')
#define T_MESH	MAKE_CODE('M','E','S','H')
#define T_MIRT  MAKE_CODE('M','I','R','T')
#define T_MLDK  MAKE_CODE('M','L','D','K')
#define T_MMMM	MAKE_CODE('M','M','M','M')
#define T_MNAP	MAKE_CODE('M','N','A','P')
#define T_MRPH	MAKE_CODE('M','R','P','H')
#define T_MUTE	MAKE_CODE('M','U','T','E')
#define T_NAPS	MAKE_CODE('N','A','P','S')
#define T_NGET  MAKE_CODE('N','G','E','T')
#define T_NOOG  MAKE_CODE('N','O','O','G')
#define T_NOVA  MAKE_CODE('N','O','V','A')
#define T_OCFG	MAKE_CODE('O','C','F','G')
#define T_OPRA	MAKE_CODE('O','P','R','A')
#define T_OXID  MAKE_CODE('O','X','I','D')
#define T_PCST  MAKE_CODE('P','C','S','T')
#define T_PHEX	MAKE_CODE('P','H','E','X')
#define T_PWRT  MAKE_CODE('P','W','R','T')
#define T_QTEL	MAKE_CODE('Q','T','E','L')
#define T_RASP  MAKE_CODE('R','A','S','P')
#define T_RAZA	MAKE_CODE('R','A','Z','A')
#define T_RAZB	MAKE_CODE('R','A','Z','B')
#define T_SHNB	MAKE_CODE('S','H','N','B')
#define T_SNOW	MAKE_CODE('S','N','O','W')
#define T_SNUT	MAKE_CODE('S','N','U','T')
#define T_STRM  MAKE_CODE('S','T','R','M')
#define T_SWAP	MAKE_CODE('S','W','A','P')
#define T_SWFT	MAKE_CODE('S','W','F','T')
#define T_TFLS	MAKE_CODE('T','F','L','S')
#define T_TOAD	MAKE_CODE('T','O','A','D')
#define T_VPUT  MAKE_CODE('V','P','U','T')
#define T_WAST  MAKE_CODE('W','A','S','T')
#define T_XOLO	MAKE_CODE('X','O','L','O')
#define T_XTLA	MAKE_CODE('X','T','L','A')
#define T_YAFS  MAKE_CODE('Y','A','F','S')
#define T_ZIGA	MAKE_CODE('Z','I','G','A')
#define T_peer  MAKE_CODE('p','e','e','r')

#define T_0000	0x00000000

/**
 * Compare two codes, alphanumerically (id est "ACQX" < "GTKG").
 *
 * Returns -1/0/+1 depending on comparison's sign.
 * Note that this comparison is case-sensitive.
 */
#define VENDOR_CODE_CMP(a, b) CMP(a, b)

typedef struct vendor_code {
	guint32 be32;	/**< Always big-endian order; for convenient '=' and '!=' */
} vendor_code_t;

const gchar *vendor_code_str(guint32 code);
const gchar *lookup_vendor_name(vendor_code_t code);
gboolean is_vendor_known(vendor_code_t code);

void vendor_init(void);

#endif /* _vendors_h_ */
/* vi: set ts=4 sw=4 cindent: */
