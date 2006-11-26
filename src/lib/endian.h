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

#include "common.h"

#if G_BYTE_ORDER == G_BIG_ENDIAN
#define guint64_to_BE(x)	x
#define guint64_to_LE(x)	GUINT64_SWAP_LE_BE(x)
#elif G_BYTE_ORDER == G_LITTLE_ENDIAN
#define guint64_to_BE(x)	GUINT64_SWAP_LE_BE(x)
#define guint64_to_LE(x)	x
#else
#error "Byte order not supported"
#endif

/*
 * Macros
 *
 * "a" is an address, "v" is the variable to which the value is written
 * in a READ operation (i.e. its address is taken).  On a WRITE operation,
 * the value is copied from "v", which can therefore be a manifest value.
 *
 * WATCH OUT: the order of the arguments for READ and WRITE is inverted.
 */

/*
 * 16-bit
 */

#define READ_GUINT16_LE(a,v) G_STMT_START { \
	STATIC_ASSERT(2 == sizeof (v));		\
    memcpy(&v, a, 2); v = GUINT16_FROM_LE(v); \
} G_STMT_END

#define WRITE_GUINT16_LE(v,a) G_STMT_START { \
    guint16 _v = GUINT16_TO_LE(v); memcpy(a, &_v, 2); \
} G_STMT_END

#define READ_GUINT16_BE(a,v) G_STMT_START { \
	STATIC_ASSERT(2 == sizeof (v));		\
    memcpy(&v, a, 2); v = ntohs(v); \
} G_STMT_END

#define WRITE_GUINT16_BE(v,a) G_STMT_START { \
    guint16 _v = htons(v); memcpy(a, &_v, 2); \
} G_STMT_END

/*
 * 32-bit
 */

#define READ_GUINT32_LE(a,v) G_STMT_START { \
	STATIC_ASSERT(4 == sizeof (v));		\
    memcpy(&v, a, 4); v = GUINT32_FROM_LE(v); \
} G_STMT_END

#define READ_GUINT32_BE(a,v) G_STMT_START { \
	STATIC_ASSERT(4 == sizeof (v));		\
    memcpy(&v, a, 4); v = ntohl(v); \
} G_STMT_END

#define WRITE_GUINT32_LE(v,a) G_STMT_START { \
    guint32 _v = GUINT32_TO_LE(v); memcpy(a, &_v, 4); \
} G_STMT_END

#define WRITE_GUINT32_BE(v,a) G_STMT_START { \
    guint32 _v = htonl(v); memcpy(a, &_v, 4); \
} G_STMT_END

/*
 * 64-bit
 */

#define READ_GUINT64_BE(a,v) G_STMT_START { \
	STATIC_ASSERT(8 == sizeof (v));		\
    memcpy(&v, a, 8); v = guint64_to_BE(v); \
} G_STMT_END

#define READ_GUINT64_LE(a,v) G_STMT_START { \
	STATIC_ASSERT(8 == sizeof (v));		\
    memcpy(&v, a, 8); v = guint64_to_LE(v); \
} G_STMT_END

#define WRITE_GUINT64_BE(v,a) G_STMT_START { \
    guint64 _v = guint64_to_BE(v); memcpy(a, &_v, sizeof _v); \
} G_STMT_END

#define WRITE_GUINT64_LE(v,a) G_STMT_START { \
    guint64 _v = guint64_to_LE(v); memcpy(a, &_v, sizeof _v); \
} G_STMT_END

/*
 * Alternate inline functions
 */

static inline guint16
peek_be16(gconstpointer p)
{
	const guint8 *q = p;
	return q[1] | (q[0] << 8);
}

static inline guint32
peek_be32(gconstpointer p)
{
	const guint8 *q = p;
	return q[3] | (q[2] << 8) | (q[1] << 16) | (q[0] << 24);
}

static inline guint16
peek_le16(gconstpointer p)
{
	const guint8 *q = p;
	return q[0] | (q[1] << 8);
}

static inline guint32
peek_le32(gconstpointer p)
{
	const guint8 *q = p;
	return q[0] | (q[1] << 8) | (q[2] << 16) | (q[3] << 24);
}

/*
 * The poke_* functions return a pointer to the next byte after the
 * written bytes.
 */

static inline gpointer
poke_be16(gpointer p, guint16 v)
{
	guint8 *q = p;

	q[0] = v >> 8;
	q[1] = v;

	return &q[2];
}

static inline gpointer
poke_be32(gpointer p, guint32 v)
{
	guint8 *q = p;

	q[0] = v >> 24;
	q[1] = v >> 16;
	q[2] = v >> 8;
	q[3] = v;

	return &q[4];
}

static inline gpointer
poke_be64(gpointer p, guint64 v)
{
	guint8 *q = p;
	guint i;

	for (i = 0; i < 8; i++) {
		q[i ^ 7] = v;
		v >>= 8;
	}

	return &q[8];
}

static inline gpointer
poke_le16(gpointer p, guint16 v)
{
	guint8 *q = p;

	q[0] = v;
	q[1] = v >> 8;

	return &q[2];
}

static inline gpointer
poke_le32(gpointer p, guint32 v)
{
	guint8 *q = p;

	q[0] = v;
	q[1] = v >> 8;
	q[2] = v >> 16;
	q[3] = v >> 24;

	return &q[4];
}

static inline gpointer
poke_le64(gpointer p, guint64 v)
{
	guint8 *q = p;
	guint i;

	for (i = 0; i < 8; i++) {
		q[i] = v;
		v >>= 8;
	}

	return &q[8];
}

#endif /* _endian_h_ */
/* vi: set ts=4 sw=4 cindent: */
