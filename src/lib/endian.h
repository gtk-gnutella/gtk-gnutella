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

/**
 * Functions for writing and reading fixed-size integers in big-endian
 * or little-endian.
 */

static inline ALWAYS_INLINE guchar
peek_u8(gconstpointer p)
{
	const guchar *q = p;
	return q[0] & 0xff;
}

static inline guint16
peek_be16(gconstpointer p)
{
	const guchar *q = p;
	guint16 v;

#if G_BYTE_ORDER == G_BIG_ENDIAN
	memcpy(&v, q, sizeof v);
#else
	v = ((guint16) peek_u8(q) << 8) | peek_u8(&q[sizeof v / 2]);
#endif
	return v;
}

static inline guint32
peek_be32(gconstpointer p)
{
	const guchar *q = p;
	guint32 v;

#if G_BYTE_ORDER == G_BIG_ENDIAN
	memcpy(&v, q, sizeof v);
#else
	v = ((guint32) peek_be16(q) << 16) | peek_be16(&q[sizeof v / 2]);
#endif
	return v;
}

static inline guint16
peek_le16(gconstpointer p)
{
	const guchar *q = p;
	guint16 v;

#if G_BYTE_ORDER == G_LITTLE_ENDIAN
	memcpy(&v, q, sizeof v);
#else
	v = peek_u8(q) | ((guint16) peek_u8(&q[sizeof v / 2]) << 8);
#endif
	return v;
}

static inline guint32
peek_le32(gconstpointer p)
{
	const guchar *q = p;
	guint32 v;

#if G_BYTE_ORDER == G_LITTLE_ENDIAN
	memcpy(&v, q, sizeof v);
#else
	v = peek_le16(q) | ((guint32) peek_le16(&q[sizeof v / 2]) << 16);
#endif
	return v;
}

/*
 * The poke_* functions return a pointer to the next byte after the
 * written bytes.
 */

static inline ALWAYS_INLINE gpointer
poke_u8(gpointer p, guchar v)
{
	guchar *q = p;
	*q = v & 0xff;
	return &q[sizeof v];
}

static inline gpointer
poke_be16(gpointer p, guint16 v)
{
	guchar *q = p;

#if G_BYTE_ORDER == G_BIG_ENDIAN
	memcpy(q, &v, sizeof v);
#else
	poke_u8(&q[0], v >> 8);
	poke_u8(&q[sizeof v / 2], v);
#endif

	return &q[sizeof v];
}

static inline gpointer
poke_be32(gpointer p, guint32 v)
{
	guchar *q = p;

#if G_BYTE_ORDER == G_BIG_ENDIAN
	memcpy(q, &v, sizeof v);
#else
	poke_be16(&q[0], v >> 16);
	poke_be16(&q[sizeof v / 2], v);
#endif

	return &q[sizeof v];
}

static inline gpointer
poke_be64(gpointer p, guint64 v)
{
	guchar *q = p;

#if G_BYTE_ORDER == G_BIG_ENDIAN
	memcpy(q, &v, sizeof v);
#else
	poke_be32(&q[0], v >> 32);
	poke_be32(&q[sizeof v / 2], v);
#endif

	return &q[sizeof v];
}

static inline gpointer
poke_le16(gpointer p, guint16 v)
{
	guchar *q = p;

#if G_BYTE_ORDER == G_LITTLE_ENDIAN
	memcpy(q, &v, sizeof v);
#else
	poke_u8(&q[0], v);
	poke_u8(&q[sizeof v / 2], v >> 8);
#endif

	return &q[sizeof v];
}

static inline gpointer
poke_le32(gpointer p, guint32 v)
{
	guchar *q = p;

#if G_BYTE_ORDER == G_LITTLE_ENDIAN
	memcpy(q, &v, sizeof v);
#else
	poke_le16(&q[0], v);
	poke_le16(&q[sizeof v / 2], v >> 16);
#endif

	return &q[sizeof v];
}

static inline gpointer
poke_le64(gpointer p, guint64 v)
{
	guchar *q = p;

#if G_BYTE_ORDER == G_LITTLE_ENDIAN
	memcpy(q, &v, sizeof v);
#else
	poke_le32(&q[0], v);
	poke_le32(&q[sizeof v / 2], v >> 32);
#endif

	return &q[sizeof v];
}


/*
 * The list of architectures is taken from xdr_float.c of
 * SUN's XDR implementation.
 */
#if \
	defined(__alpha__) || \
	defined(__arm__) || \
	defined(__hppa__) || \
	defined(__i386__) || \
	defined(__ia64__) || \
	defined(__m68k__) || \
	defined(__mips__) || \
	defined(__ns32k__) || \
	defined(__powerpc__) || \
	defined(__sh__) || \
	defined(__sparc__) || \
	defined(__x86_64__)
#define FLOAT_USES_IEEE754
#else
#undef FLOAT_USES_IEEE754
#error "This architecture may be unsupported. float must use IEEE 754."
#endif

#ifdef FLOAT_USES_IEEE754
static inline gpointer
poke_float_be32(gpointer p, float v)
{
	guint32 tmp;

	STATIC_ASSERT(sizeof(float) == 4);

	/* XXX needs metaconfig check */
	/* XXX assumes integer byte order is float byte order (true on i386) */
	/* XXX IEC 60559/IEEE 754 floating point single-precision (32-bit) */
	memcpy(&tmp, &v, 4);
	return poke_be32(p, tmp);
}

static inline float
peek_float_be32(gconstpointer p)
{
	guint32 tmp;
	float v;

	STATIC_ASSERT(sizeof(float) == 4);

	/* XXX needs metaconfig check */
	/* XXX assumes integer byte order is float byte order (true on i386) */
	/* XXX IEC 60559/IEEE 754 floating point single-precision (32-bit) */
	tmp = peek_be32(p);
	memcpy(&v, &tmp, 4);
	return v;
}
#endif	/* FLOAT_USES_IEEE754 */

#endif /* _endian_h_ */
/* vi: set ts=4 sw=4 cindent: */
