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

#ifndef _vendors_h_
#define _vendors_h_

#include "common.h"

/***
 *** Known gnutella vendor codes
 ***/

#define T_ACQL  FOURCC_NATIVE('A','C','Q','L')
#define T_ACQX  FOURCC_NATIVE('A','C','Q','X')
#define T_AGIO  FOURCC_NATIVE('A','G','I','O')
#define T_AGNT  FOURCC_NATIVE('A','G','N','T')
#define T_ARES  FOURCC_NATIVE('A','R','E','S')
#define T_ATOM  FOURCC_NATIVE('A','T','O','M')
#define T_AZOO  FOURCC_NATIVE('A','Z','O','O')
#define T_BARE	FOURCC_NATIVE('B','A','R','E')
#define T_BEAR	FOURCC_NATIVE('B','E','A','R')
#define T_BGNU  FOURCC_NATIVE('B','G','N','U')
#define T_COCO	FOURCC_NATIVE('C','O','C','O')
#define T_CULT	FOURCC_NATIVE('C','U','L','T')
#define T_DRIP  FOURCC_NATIVE('D','R','I','P')
#define T_EVIL	FOURCC_NATIVE('E','V','I','L')
#define T_FEVR	FOURCC_NATIVE('F','E','V','R')
#define T_FIRE	FOURCC_NATIVE('F','I','R','E')
#define T_FISH	FOURCC_NATIVE('F','I','S','H')
#define T_FOXY	FOURCC_NATIVE('F','O','X','Y')
#define T_FSCP  FOURCC_NATIVE('F','S','C','P')
#define T_FZZN  FOURCC_NATIVE('F','Z','Z','N')
#define T_GDNA	FOURCC_NATIVE('G','D','N','A')
#define T_GIFT  FOURCC_NATIVE('G','I','F','T')
#define T_GNEW	FOURCC_NATIVE('G','N','E','W')
#define T_GNOT	FOURCC_NATIVE('G','N','O','T')
#define T_GNTD	FOURCC_NATIVE('G','N','T','D')
#define T_GNTG  FOURCC_NATIVE('G','N','T','G')
#define T_GNUC	FOURCC_NATIVE('G','N','U','C')
#define T_GNUM  FOURCC_NATIVE('G','N','U','M')
#define T_GNUT	FOURCC_NATIVE('G','N','U','T')
#define T_GNZL	FOURCC_NATIVE('G','N','Z','L')
#define T_GSHR	FOURCC_NATIVE('G','S','H','R')
#define T_GTKG	FOURCC_NATIVE('G','T','K','G')
#define T_HSLG	FOURCC_NATIVE('H','S','L','G')
#define T_HUIT  FOURCC_NATIVE('H','U','I','T')
#define T_HYDR  FOURCC_NATIVE('H','Y','D','R')
#define T_JHOP  FOURCC_NATIVE('J','H','O','P')
#define T_JOEY  FOURCC_NATIVE('J','O','E','Y')
#define T_KIKI  FOURCC_NATIVE('K','I','K','I')
#define T_KISS  FOURCC_NATIVE('K','I','S','S')
#define T_LIME	FOURCC_NATIVE('L','I','M','E')
#define T_LION  FOURCC_NATIVE('L','I','O','N')
#define T_MACT	FOURCC_NATIVE('M','A','C','T')
#define T_MESH	FOURCC_NATIVE('M','E','S','H')
#define T_MIRT  FOURCC_NATIVE('M','I','R','T')
#define T_MLDK  FOURCC_NATIVE('M','L','D','K')
#define T_MMMM	FOURCC_NATIVE('M','M','M','M')
#define T_MNAP	FOURCC_NATIVE('M','N','A','P')
#define T_MOOD  FOURCC_NATIVE('M','O','O','D')
#define T_MRPH	FOURCC_NATIVE('M','R','P','H')
#define T_MUTE	FOURCC_NATIVE('M','U','T','E')
#define T_MXIE  FOURCC_NATIVE('M','X','I','E')
#define T_NAPS	FOURCC_NATIVE('N','A','P','S')
#define T_NGET  FOURCC_NATIVE('N','G','E','T')
#define T_NOOG  FOURCC_NATIVE('N','O','O','G')
#define T_NOVA  FOURCC_NATIVE('N','O','V','A')
#define T_OCFG	FOURCC_NATIVE('O','C','F','G')
#define T_OPRA	FOURCC_NATIVE('O','P','R','A')
#define T_OXID  FOURCC_NATIVE('O','X','I','D')
#define T_PCST  FOURCC_NATIVE('P','C','S','T')
#define T_PEER  FOURCC_NATIVE('P','E','E','R')
#define T_PHEX	FOURCC_NATIVE('P','H','E','X')
#define T_PWRT  FOURCC_NATIVE('P','W','R','T')
#define T_QAZA  FOURCC_NATIVE('Q','A','Z','A')
#define T_QAZB  FOURCC_NATIVE('Q','A','Z','B')
#define T_QTEL	FOURCC_NATIVE('Q','T','E','L')
#define T_RASP  FOURCC_NATIVE('R','A','S','P')
#define T_RAZA	FOURCC_NATIVE('R','A','Z','A')
#define T_RAZB	FOURCC_NATIVE('R','A','Z','B')
#define T_RAZL	FOURCC_NATIVE('R','A','Z','L')
#define T_RZCA	FOURCC_NATIVE('R','Z','C','A')
#define T_RZCB	FOURCC_NATIVE('R','Z','C','B')
#define T_RZCC	FOURCC_NATIVE('R','Z','C','C')
#define T_SHLN	FOURCC_NATIVE('S','H','L','N')
#define T_SHNB	FOURCC_NATIVE('S','H','N','B')
#define T_SNOW	FOURCC_NATIVE('S','N','O','W')
#define T_SNUT	FOURCC_NATIVE('S','N','U','T')
#define T_STRM  FOURCC_NATIVE('S','T','R','M')
#define T_SWAP	FOURCC_NATIVE('S','W','A','P')
#define T_SWFT	FOURCC_NATIVE('S','W','F','T')
#define T_TFLS	FOURCC_NATIVE('T','F','L','S')
#define T_TOAD	FOURCC_NATIVE('T','O','A','D')
#define T_VPUT  FOURCC_NATIVE('V','P','U','T')
#define T_WAST  FOURCC_NATIVE('W','A','S','T')
#define T_WSHR  FOURCC_NATIVE('W','S','H','R')
#define T_XOLO	FOURCC_NATIVE('X','O','L','O')
#define T_XTLA	FOURCC_NATIVE('X','T','L','A')
#define T_YAFS  FOURCC_NATIVE('Y','A','F','S')
#define T_ZIGA	FOURCC_NATIVE('Z','I','G','A')
#define T_peer  FOURCC_NATIVE('p','e','e','r')

#define T_0000	0x00000000

/**
 * Compare two codes, alphanumerically (id est "ACQX" < "GTKG").
 *
 * Returns -1/0/+1 depending on comparison's sign.
 * Note that this comparison is case-sensitive.
 */
#define VENDOR_CODE_CMP(a, b) CMP(a, b)

/* Buffer size required to hold a vendor code as NUL-terminated string */
#define VENDOR_CODE_BUFLEN 5

typedef struct vendor_code {
	uint32 u32;		/**< Always host-endian order */
} vendor_code_t;

/* Old stringification API */
const char *vendor_code_to_string(uint32);
size_t vendor_code_to_string_buf(uint32, char *, size_t);
const char *vendor_code_get_name(uint32);

/* New stringification API */
const char *vendor_to_string(const vendor_code_t);
size_t vendor_to_string_buf(const vendor_code_t, char *, size_t);
const char *vendor_get_name(const vendor_code_t);

bool is_vendor_known(vendor_code_t);
bool is_vendor_acceptable(vendor_code_t);

void vendor_init(void);

#endif /* _vendors_h_ */
/* vi: set ts=4 sw=4 cindent: */
