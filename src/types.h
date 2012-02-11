/*
 * Copyright (c) 2012 Raphael Manfredi
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
 * @file
 *
 * Portable type definitions and other conveniences.
 *
 * @author Raphael Manfredi
 * @date 2012
 */

#ifndef _types_h_
#define _types_h_

/* @note This file is only for inclusion by common.h. */

#if 0	/* Not yet */
typedef enum bool {
	BOOL_FALSE=0,
	BOOL_TRUE = 1
} bool;
#else
typedef int bool;
#endif

#if CHARSIZE == 1
typedef signed char int8;
typedef unsigned char uint8;
#else
#error "no known 8-bit type."
#endif

#if SHORTSIZE == 2
typedef short int16;
typedef unsigned short uint16;
#else
#error "no known 16-bit type."
#endif

#if INTSIZE == 4
typedef int int32;
typedef unsigned int uint32;
#else
#error "no known 32-bit type."
#endif

#if LONGSIZE == 8
typedef long int64;
typedef unsigned long uint64;
#elif defined(CAN_HANDLE_64BITS)
typedef long long int64;
typedef unsigned long long uint64;
#else
#error "no known 64-bit type."
#endif

typedef unsigned char uchar;
typedef unsigned short ushort;
typedef unsigned int uint;
typedef unsigned long ulong;

#endif /* _types_h_ */

/* vi: set ts=4 sw=4 cindent: */
