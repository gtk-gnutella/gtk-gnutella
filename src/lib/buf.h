/*
 * Copyright (c) 2013 Raphael Manfredi
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
 * Fix-sized buffers, for using as thread-private "static" containers.
 *
 * @author Raphael Manfredi
 * @date 2013
 */

#ifndef _buf_h_
#define _buf_h_

#include "unsigned.h"		/* For size_is_positive()) */

/*
 * The buffer structure is public to allow static buffer objects.
 */

#define BUF_MAGIC_MASK		0xffffff00		/* Leading 24 bits set */
#define BUF_MAGIC_VAL		0x00e72800		/* Leading 24 bits significant */

#define BUF_MAGIC_EMBMASK	0xfffffff0		/* Leading 28 bits set */
#define BUF_MAGIC_EMBVAL	0x00e72860		/* Leading 28 bits set */

enum buf_magic {
	BUF_MAGIC          = BUF_MAGIC_VAL + 0xc4,
	BUF_MAGIC_STATIC   = BUF_MAGIC_VAL + 0xf1,
	BUF_MAGIC_EMBEDDED = BUF_MAGIC_VAL + 0x6b,
	BUF_MAGIC_PRIVATE  = BUF_MAGIC_VAL + 0x68
};

/*
 * A fix-sized buffer description.
 */
typedef struct buf {
	enum buf_magic b_magic;
	size_t b_size;			/**< Available data size (NOT total size) */
	union {
		char bu_edata[1];	/**< Where data start (embedded data) */
		char *bu_data;		/**< Data pointer */
	} b_u;
} buf_t;

static inline void
buf_check(const struct buf * const b)
{
	g_assert(b != NULL);
	g_assert(BUF_MAGIC_VAL == (b->b_magic & BUF_MAGIC_MASK));
}

/**
 * Initialize buffer structure with pre-allocated data arena.
 *
 * This allows using formtting routines without having to pass both
 * the buffer and its size separately, thereby limiting the potential
 * for mistakes.
 *
 * @param b			the buffer structure to initialize
 * @param arena		the data arena start
 * @param size		the size of the supplied arena, in bytes
 *
 * @return its parameter b, as a convenience.
 */
static inline buf_t *
buf_init(buf_t *b, void *arena, size_t size)
{
	g_assert(arena != NULL);
	g_assert(size_is_positive(size));
	b->b_magic = BUF_MAGIC_STATIC;
	b->b_size = size;
	b->b_u.bu_data = arena;

	return b;
}

/**
 * @return the physical size of the data buffer.
 */
static inline size_t
buf_size(const buf_t *b)
{
	buf_check(b);
	return b->b_size;
}

/**
 * Does buffer have embedded data?
 */
static inline bool
buf_is_embedded(const buf_t *b)
{
	return b != NULL && BUF_MAGIC_EMBVAL == (BUF_MAGIC_EMBMASK & b->b_magic);
}

/**
 * @return the physical data buffer.
 */
static inline void *
buf_data(const buf_t *b)
{
	buf_check(b);
	return buf_is_embedded(b) ? (char *) b->b_u.bu_edata : b->b_u.bu_data;
}

/*
 * Public interface.
 */

buf_t *buf_new(size_t size);
buf_t *buf_new_embedded(size_t size);
buf_t *buf_private(const void *key, size_t size);
void buf_free_null(buf_t **b_ptr);

buf_t *buf_grow(buf_t *b, size_t total);
buf_t *buf_resize(buf_t *b, size_t size);
buf_t *buf_private_resize(const void *key, size_t size);

void buf_setc(buf_t *b, size_t i, char c);
char buf_getc(const buf_t *b, size_t i);
size_t buf_copyin(buf_t *b, const void *src, size_t len);

size_t buf_printf(buf_t *b, const char *fmt, ...) G_PRINTF(2, 3);
size_t buf_vprintf(buf_t *b, const char *fmt, va_list args);
size_t buf_catf(buf_t *b, const char *fmt, ...) G_PRINTF(2, 3);
size_t buf_vcatf(buf_t *b, const char *fmt, va_list args);

#endif /* _buf_h_ */

/* vi: set ts=4 sw=4 cindent: */
