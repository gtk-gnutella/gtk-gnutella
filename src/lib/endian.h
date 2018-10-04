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
 * Endianness peek/poke routines.
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
 * UINT32_ROTR() rotates a 32-bit value to the right by `n' bits.
 * UINT32_ROTL() rotates a 32-bit value to the left by `n' bits.
 */
#define UINT32_ROTR(x_,n_) \
	(((uint32) (x_) >> (n_)) | ((uint32) (x_) << (32 - (n_))))

#define UINT32_ROTL(x_,n_) \
	(((uint32) (x_) << (n_)) | ((uint32) (x_) >> (32 - (n_))))

/**
 * UINT32_SWAP_CONSTANT() byte-swaps a 32-bit word, preferrably a constant.
 * If the value is a variable, use UINT32_SWAP().
 */
#define UINT32_SWAP_CONSTANT(x_) \
	((UINT32_ROTR((x_), 8) & 0xff00ff00) | (UINT32_ROTL((x_), 8) & 0x00ff00ff))

/**
 * UINT64_SWAP_CONSTANT() byte-swaps a 64-bit word, preferrably a constant.
 * If the value is a variable, use UINT64_SWAP().
 */
#define UINT64_SWAP_CONSTANT(x_) \
	(UINT32_SWAP_CONSTANT((uint32) ((x_) >> 32)) | \
	 ((uint64) UINT32_SWAP_CONSTANT((uint32) (x_)) << 32))

/**
 * UINT16_SWAP() byte-swaps a 16-bit word.
 */
#define UINT16_SWAP(x_) ((uint16)((x_) >> 8) | (uint16)((x_) << 8))

/**
 * UINT32_SWAP() byte-swaps a 32-bit word.
 *
 * Avoid using glib's GUINT32_SWAP_LE_BE(): it triggers compile-time
 * warnings on a wrong __asm__ statement with glib 1.2.  This version
 * should be as efficient as the one defined by glib.
 */
#ifdef HAS_BUILTIN_BSWAP32
#define UINT32_SWAP(x_) \
	(IS_CONSTANT(x_) ? UINT32_SWAP_CONSTANT(x_) : __builtin_bswap32(x_))
#else
#define UINT32_SWAP(x_) UINT32_SWAP_CONSTANT(x_)
#endif

/**
 * UINT64_SWAP() byte-swaps a 64-bit word.
 */
#ifdef HAS_BUILTIN_BSWAP64
#define UINT64_SWAP(x_) \
	(IS_CONSTANT(x_) ? UINT64_SWAP_CONSTANT(x_) : __builtin_bswap64(x_))
#else
#define UINT64_SWAP(x_) UINT64_SWAP_CONSTANT(x_)
#endif

/**
 * ULONG_SWAP() byte-swaps an unsigned long.
 */
#if PTRSIZE == 8
#define ULONG_SWAP(w)	UINT64_SWAP(w)
#elif PTRSIZE == 4
#define ULONG_SWAP(w)	UINT32_SWAP(w)
#else
#error "unexpected pointer size"
#endif

/**
 * Functions for writing and reading fixed-size integers in big-endian
 * or little-endian.
 */

static inline ALWAYS_INLINE G_PURE uint8
peek_u8(const void *p)
{
	const uint8 *q = p;
	return q[0];
}

static inline ALWAYS_INLINE G_PURE uint16
peek_u16(const void *p)
{
	const unsigned char *q = p;
	uint16 v;
	memcpy(&v, q, sizeof v);
	return v;
}

static inline ALWAYS_INLINE G_PURE uint32
peek_u32(const void *p)
{
	const unsigned char *q = p;
	uint32 v;
	memcpy(&v, q, sizeof v);
	return v;
}

static inline ALWAYS_INLINE G_PURE uint64
peek_u64(const void *p)
{
	const unsigned char *q = p;
	uint64 v;
	memcpy(&v, q, sizeof v);
	return v;
}

static inline G_PURE uint16
peek_be16(const void *p)
{
#if IS_BIG_ENDIAN
	return peek_u16(p);
#else
	return UINT16_SWAP(peek_u16(p));
#endif
}

static inline G_PURE uint32
peek_be32(const void *p)
{
#if IS_BIG_ENDIAN
	return peek_u32(p);
#else
	return UINT32_SWAP(peek_u32(p));
#endif
}

static inline G_PURE uint64
peek_be64(const void *p)
{
#if IS_BIG_ENDIAN
	return peek_u64(p);
#else
	return UINT64_SWAP(peek_u64(p));
#endif
}

static inline G_PURE uint16
peek_le16(const void *p)
{
#if IS_LITTLE_ENDIAN
	return peek_u16(p);
#else
	return UINT16_SWAP(peek_u32(p));
#endif
}

static inline G_PURE uint32
peek_le32(const void *p)
{
#if IS_LITTLE_ENDIAN
	return peek_u32(p);
#else
	return UINT32_SWAP(peek_u32(p));
#endif
}

static inline G_PURE uint64
peek_le64(const void *p)
{
#if IS_LITTLE_ENDIAN
	return peek_u64(p);
#else
	return UINT64_SWAP(peek_u64(p));
#endif
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

static inline ALWAYS_INLINE void *
poke_u16(void *p, uint16 v)
{
	unsigned char *q = p;
	memcpy(q, &v, sizeof v);
	return &q[sizeof v];
}

static inline ALWAYS_INLINE void *
poke_u32(void *p, uint32 v)
{
	unsigned char *q = p;
	memcpy(q, &v, sizeof v);
	return &q[sizeof v];
}

static inline ALWAYS_INLINE void *
poke_u64(void *p, uint64 v)
{
	unsigned char *q = p;
	memcpy(q, &v, sizeof v);
	return &q[sizeof v];
}

static inline void *
poke_be16(void *p, uint16 v)
{
#if IS_LITTLE_ENDIAN
	v = UINT16_SWAP(v);
#endif
	return poke_u16(p, v);
}

static inline void *
poke_be32(void *p, uint32 v)
{
#if IS_LITTLE_ENDIAN
	v = UINT32_SWAP(v);
#endif
	return poke_u32(p, v);
}

static inline void *
poke_be64(void *p, uint64 v)
{
#if IS_LITTLE_ENDIAN
	v = UINT64_SWAP(v);
#endif
	return poke_u64(p, v);
}

static inline void *
poke_le16(void *p, uint16 v)
{
#if IS_BIG_ENDIAN
	v = UINT16_SWAP(v);
#endif
	return poke_u16(p, v);
}

static inline void *
poke_le32(void *p, uint32 v)
{
#if IS_BIG_ENDIAN
	v = UINT32_SWAP(v);
#endif
	return poke_u32(p, v);
}

static inline void *
poke_le64(void *p, uint64 v)
{
#if IS_BIG_ENDIAN
	v = UINT64_SWAP(v);
#endif
	return poke_u64(p, v);
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

static inline G_PURE float
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
