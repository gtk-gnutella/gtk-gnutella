/*
 * $Id$
 *
 * Copyright (c) 2001-2003, Raphael Manfredi
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

#ifndef _endian_h_
#define _endian_h_

/*
 * Macros
 *
 * "a" is an address, "v" is the variable to which the value is written
 * in a READ operation (i.e. its address is taken).  On a WRITE operation,
 * the value is copied from "v", which can therefore be a manifest value.
 *
 * WATCH OUT: the order of the arguments for READ and WRITE is inverted.
 */

#define READ_GUINT16_LE(a,v) G_STMT_START { \
    memcpy(&v, a, 2); v = GUINT16_FROM_LE(v); \
} G_STMT_END

#define WRITE_GUINT16_LE(v,a) G_STMT_START { \
    guint16 _v = GUINT16_TO_LE(v); memcpy(a, &_v, 2); \
} G_STMT_END

#define READ_GUINT16_BE(a,v) G_STMT_START { \
    memcpy(&v, a, 2); v = ntohs(v); \
} G_STMT_END

#define WRITE_GUINT16_BE(v,a) G_STMT_START { \
    guint16 _v = htons(v); memcpy(a, &_v, 2); \
} G_STMT_END

#define READ_GUINT32_LE(a,v) G_STMT_START { \
    memcpy(&v, a, 4); v = GUINT32_FROM_LE(v); \
} G_STMT_END

#define READ_GUINT32_BE(a,v) G_STMT_START { \
    memcpy(&v, a, 4); v = ntohl(v); \
} G_STMT_END

#define WRITE_GUINT32_LE(v,a) G_STMT_START { \
    guint32 _v = GUINT32_TO_LE(v); memcpy(a, &_v, 4); \
} G_STMT_END

#define WRITE_GUINT32_BE(v,a) G_STMT_START { \
    guint32 _v = htonl(v); memcpy(a, &_v, 4); \
} G_STMT_END

#endif /* _endian_h_ */
