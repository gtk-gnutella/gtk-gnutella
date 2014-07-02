/*
 * Copyright (c) 2001-2003, Raphael Manfredi
 * Copyright (c) 2006, Christian Biere
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
 * Endiannes peek/poke routines.
 *
 * @author Raphael Manfredi
 * @date 2001-2003
 * @author Christian Biere
 * @date 2006
 */

#ifndef _endian_h_
#define _endian_h_

#include "common.h"

/**
 * Functions for writing and reading fixed-size integers in big-endian
 * or little-endian.
 */

static inline ALWAYS_INLINE G_GNUC_PURE uint8
peek_u8(const void *p)
{
	const uint8 *q = p;
	return q[0];
}

static inline ALWAYS_INLINE G_GNUC_PURE uint16
peek_u16(const void *p)
{
	const unsigned char *q = p;
	uint16 v;
	memcpy(&v, q, sizeof v);
	return v;
}

static inline ALWAYS_INLINE G_GNUC_PURE uint32
peek_u32(const void *p)
{
	const unsigned char *q = p;
	uint32 v;
	memcpy(&v, q, sizeof v);
	return v;
}

static inline ALWAYS_INLINE G_GNUC_PURE uint64
peek_u64(const void *p)
{
	const unsigned char *q = p;
	uint64 v;
	memcpy(&v, q, sizeof v);
	return v;
}

static inline G_GNUC_PURE uint16
peek_be16(const void *p)
{
	const unsigned char *q = p;
	uint16 v;

#if IS_BIG_ENDIAN
	memcpy(&v, q, sizeof v);
#else
	v = ((uint16) peek_u8(q) << 8) | peek_u8(&q[sizeof v / 2]);
#endif
	return v;
}

static inline G_GNUC_PURE uint32
peek_be32(const void *p)
{
	const unsigned char *q = p;
	uint32 v;

#if IS_BIG_ENDIAN
	memcpy(&v, q, sizeof v);
#else
	v = ((uint32) peek_be16(q) << 16) | peek_be16(&q[sizeof v / 2]);
#endif
	return v;
}

static inline G_GNUC_PURE uint64
peek_be64(const void *p)
{
	const unsigned char *q = p;
	uint64 v;

#if IS_BIG_ENDIAN
	memcpy(&v, q, sizeof v);
#else
	v = ((uint64) peek_be32(q) << 32) | peek_be32(&q[sizeof v / 2]);
#endif
	return v;
}

static inline G_GNUC_PURE uint16
peek_le16(const void *p)
{
	const unsigned char *q = p;
	uint16 v;

#if IS_LITTLE_ENDIAN
	memcpy(&v, q, sizeof v);
#else
	v = peek_u8(q) | ((uint16) peek_u8(&q[sizeof v / 2]) << 8);
#endif
	return v;
}

static inline G_GNUC_PURE uint32
peek_le32(const void *p)
{
	const unsigned char *q = p;
	uint32 v;

#if IS_LITTLE_ENDIAN
	memcpy(&v, q, sizeof v);
#else
	v = peek_le16(q) | ((uint32) peek_le16(&q[sizeof v / 2]) << 16);
#endif
	return v;
}

static inline G_GNUC_PURE uint64
peek_le64(const void *p)
{
	const unsigned char *q = p;
	uint64 v;

#if IS_LITTLE_ENDIAN
	memcpy(&v, q, sizeof v);
#else
	v = (uint64) peek_le32(q) | ((uint64) peek_le32(&q[sizeof v / 2]) << 32);
#endif
	return v;
}

/*
 * The poke_* functions return a pointer to the next byte after the
 * written bytes.
 */

static inline ALWAYS_INLINE void *
poke_u8(void *p, unsigned char v)
{
	unsigned char *q = p;
	*q = v & 0xff;
	return &q[sizeof v];
}

static inline void *
poke_be16(void *p, uint16 v)
{
	unsigned char *q = p;

#if IS_BIG_ENDIAN
	memcpy(q, &v, sizeof v);
#else
	poke_u8(&q[0], v >> 8);
	poke_u8(&q[sizeof v / 2], v);
#endif

	return &q[sizeof v];
}

static inline void *
poke_be32(void *p, uint32 v)
{
	unsigned char *q = p;

#if IS_BIG_ENDIAN
	memcpy(q, &v, sizeof v);
#else
	poke_be16(&q[0], v >> 16);
	poke_be16(&q[sizeof v / 2], v);
#endif

	return &q[sizeof v];
}

static inline void *
poke_be64(void *p, uint64 v)
{
	unsigned char *q = p;

#if IS_BIG_ENDIAN
	memcpy(q, &v, sizeof v);
#else
	poke_be32(&q[0], v >> 32);
	poke_be32(&q[sizeof v / 2], v);
#endif

	return &q[sizeof v];
}

static inline void *
poke_le16(void *p, uint16 v)
{
	unsigned char *q = p;

#if IS_LITTLE_ENDIAN
	memcpy(q, &v, sizeof v);
#else
	poke_u8(&q[0], v);
	poke_u8(&q[sizeof v / 2], v >> 8);
#endif

	return &q[sizeof v];
}

static inline void *
poke_le32(void *p, uint32 v)
{
	unsigned char *q = p;

#if IS_LITTLE_ENDIAN
	memcpy(q, &v, sizeof v);
#else
	poke_le16(&q[0], v);
	poke_le16(&q[sizeof v / 2], v >> 16);
#endif

	return &q[sizeof v];
}

static inline void *
poke_le64(void *p, uint64 v)
{
	unsigned char *q = p;

#if IS_LITTLE_ENDIAN
	memcpy(q, &v, sizeof v);
#else
	poke_le32(&q[0], v);
	poke_le32(&q[sizeof v / 2], v >> 32);
#endif

	return &q[sizeof v];
}

#ifdef USE_IEEE754_FLOAT
/*
 * Handles IEC 60559/IEEE 754 floating point single-precision (32-bit).
 */

static inline void *
poke_float_be32(void *p, float v)
{
	uint32 tmp;

	STATIC_ASSERT(sizeof(float) == 4);

	memcpy(&tmp, &v, 4);
#if BYTEORDER == IEEE754_BYTEORDER
	return poke_be32(p, tmp);
#else
	return poke_le32(p, tmp);	/* Will swap the ordering */
#endif
}

static inline G_GNUC_PURE float
peek_float_be32(const void *p)
{
	uint32 tmp;
	float v;

	STATIC_ASSERT(sizeof(float) == 4);

#if BYTEORDER == IEEE754_BYTEORDER
	tmp = peek_be32(p);
#else
	tmp = peek_le32(p);			/* Will swap the ordering */
#endif
	memcpy(&v, &tmp, 4);
	return v;
}
#endif	/* USE_IEEE754_FLOAT */

/*
 * The peek_*_advance() routines return a pointer to the byte immediately
 * following the read value, and fill-in the given pointer with the read value.
 */

static inline const void *
peek_be32_advance(const void *p, uint32 *v)
{
	*v = peek_be32(p);
	return const_ptr_add_offset(p, 4);
}

static inline const void *
peek_le32_advance(const void *p, uint32 *v)
{
	*v = peek_le32(p);
	return const_ptr_add_offset(p, 4);
}

#endif /* _endian_h_ */

/* vi: set ts=4 sw=4 cindent: */
