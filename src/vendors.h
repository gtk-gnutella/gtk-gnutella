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

#ifndef __vendors_h__
#define __vendors_h__

#include <glib.h>

/***
 *** Known gnutella vendor codes
 ***/

#define MAKE_CODE(a,b,c,d) ( \
	((guint32) (a) << 24) | \
	((guint32) (b) << 16) | \
	((guint32) (c) << 8)  | \
	((guint32) (d)))

#define T_ARES  MAKE_CODE('A','R','E','S')
#define T_BEAR	MAKE_CODE('B','E','A','R')
#define T_COCO	MAKE_CODE('C','O','C','O')
#define T_CULT	MAKE_CODE('C','U','L','T')
#define T_FIRE	MAKE_CODE('F','I','R','E')
#define T_FISH	MAKE_CODE('F','I','S','H')
#define T_GNEW	MAKE_CODE('G','N','E','W')
#define T_GNOT	MAKE_CODE('G','N','O','T')
#define T_GNUC	MAKE_CODE('G','N','U','C')
#define T_GNUT	MAKE_CODE('G','N','U','T')
#define T_GTKG	MAKE_CODE('G','T','K','G')
#define T_HSLG	MAKE_CODE('H','S','L','G')
#define T_LIME	MAKE_CODE('L','I','M','E')
#define T_MACT	MAKE_CODE('M','A','C','T')
#define T_MMMM	MAKE_CODE('M','M','M','M')
#define T_MNAP	MAKE_CODE('M','N','A','P')
#define T_MRPH	MAKE_CODE('M','R','P','H')
#define T_MUTE	MAKE_CODE('M','U','T','E')
#define T_NAPS	MAKE_CODE('N','A','P','S')
#define T_OCFG	MAKE_CODE('O','C','F','G')
#define T_OPRA	MAKE_CODE('O','P','R','A')
#define T_PHEX	MAKE_CODE('P','H','E','X')
#define T_QTEL	MAKE_CODE('Q','T','E','L')
#define T_RAZA	MAKE_CODE('R','A','Z','A')
#define T_SNUT	MAKE_CODE('S','N','U','T')
#define T_SWAP	MAKE_CODE('S','W','A','P')
#define T_SWFT	MAKE_CODE('S','W','F','T')
#define T_TOAD	MAKE_CODE('T','O','A','D')
#define T_XOLO	MAKE_CODE('X','O','L','O')
#define T_XTLA	MAKE_CODE('X','T','L','A')
#define T_ZIGA	MAKE_CODE('Z','I','G','A')

gchar *lookup_vendor_name(guchar code[4]);
gboolean is_vendor_known(guchar code[4]);

#endif /* __vendors_h__ */

