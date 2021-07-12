/*
 * Copyright (c) 2013, 2015 Raphael Manfredi
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
 *      51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *----------------------------------------------------------------------
 */

/**
 * @ingroup lib
 * @file
 *
 * Fix-sized buffers, for using as thread-private "static" containers.
 *
 * These buffers are expected to be relatively short, hence they are allocated
 * via xmalloc() to benefit from the thread-private allocation pools.
 *
 * @author Raphael Manfredi
 * @date 2013, 2015
 */

#include "common.h"

#include "buf.h"

#include "misc.h"			/* For clamp_memcpy() */
#include "str.h"
#include "thread.h"
#include "unsigned.h"		/* For size_is_positive() */
#include "walloc.h"
#include "xmalloc.h"

#include "override.h"		/* Must be the last header included */

#define BUF_DATA_OFFSET		offsetof(struct buf, b_u.bu_data)

/*
 * Hysteresis for buffer growth.
 *
 * Once the block becomes larger than BUF_HYST_SIZE, it is grown in multiple
 * amounts of BUF_HYST_SIZE to avoid endless reallocations each time we wish
 * to add a few bytes.
 */
#define BUF_HYST_SHIFT	10
#define BUF_HYST_SIZE	(1U << BUF_HYST_SHIFT)
#define BUF_HYST_MASK	(BUF_HYST_SIZE - 1)

/**
 * Round supplied value up with a BUF_HYST_SIZE granularity.
 */
static inline size_t G_PURE
buf_hyst_round(size_t n)
{
	return (n + BUF_HYST_MASK) & ~BUF_HYST_MASK;
}

/**
 * Allocate a new buffer of the specified size.
 */
buf_t *
buf_new(size_t size)
{
	buf_t *b;

	g_assert(size_is_positive(size));	/* Size cannot be 0 either */

	WALLOC0(b);
	b->b_magic = BUF_MAGIC;
	b->b_size = size;
	b->b_u.bu_data = xmalloc(size);

	return b;
}

/**
 * Allocate a new embedded buffer of the specified size.
 * The data part of the embedded buffer is zeroed.
 */
buf_t *
buf_new_embedded(size_t size)
{
	buf_t *b;

	g_assert(size_is_positive(size));	/* Size cannot be 0 either */

	b = xmalloc0(BUF_DATA_OFFSET + size);
	b->b_magic = BUF_MAGIC_EMBEDDED;
	b->b_size = size;

	return b;
}

/**
 * Free buffer.
 */
static void
buf_free(buf_t *b)
{
	buf_check(b);
	g_assert_log(b->b_magic != BUF_MAGIC_PRIVATE,
		"%s(): attempting to free thread-private buffer %p",
		G_STRFUNC, b);
	g_assert_log(b->b_magic != BUF_MAGIC_STATIC,
		"%s(): attempting to free buffer %p wrapping arena %p",
		G_STRFUNC, b, buf_data(b));

	if (buf_is_embedded(b)) {
		b->b_magic = 0;
		xfree(b);
	} else {
		XFREE_NULL(b->b_u.bu_data);
		b->b_magic = 0;
		WFREE(b);
	}
}

/**
 * Free buffer and nullify its pointer.
 */
void
buf_free_null(buf_t **b_ptr)
{
	buf_t *b = *b_ptr;

	if (b != NULL) {
		buf_free(b);
		*b_ptr = NULL;
	}
}

/**
 * Reclaim a thread-private buffer when the thread is exiting.
 */
static void
buf_private_reclaim(void *data, void *unused)
{
	buf_t *b = data;

	(void) unused;

	buf_check(b);
	g_assert(BUF_MAGIC_PRIVATE == b->b_magic);

	b->b_magic = BUF_MAGIC_EMBEDDED;
	buf_free(b);
}


/**
 * Get a thread-private buffer attached to the specified key.
 *
 * If the buffer already existed in the thread for this key, it is returned,
 * and the size parameter is ignored.
 *
 * Otherwise, a new buffer is created, zeroed, and attached to the key.
 *
 * A typical usage of this routine is to make a routine returning static
 * data thread-safe:
 *
 *   const char *
 *   routine(int arg)
 *   {
 *       buf_t *b = buf_private(G_STRFUNC, 10);
 *       char *p = buf_data(b);     // the "static" buffer, on the heap
 *       size_t n;
 *
 *       n = transfer_to_buffer(arg, p); // returns amount of chars
 *       g_assert(n < buf_size(b)); // allow trailing NUL
 *       return p;	                // the private copy for this thread
 *   }
 *
 * @param key		the key to use to identify this string
 * @param size		length of the data buffer
 *
 * @note
 * The buffer will be reclaimed automatically when the thread exits and its
 * pointer should not be given to foreign threads but used solely in the
 * context of the thread.  This applies to the buffer object and its data.
 *
 * @return a buffer object dedicated to the calling thread, which is zeroed
 * initially.
 */
buf_t *
buf_private(const void *key, size_t size)
{
	buf_t *b;

	b = thread_private_get(key);

	if G_LIKELY(b != NULL) {
		g_assert(BUF_MAGIC_PRIVATE == b->b_magic);
		return b;
	}

	/*
	 * Allocate a new buffer and declare it as a thread-private variable
	 * with an associated free routine.
	 */

	b = NOT_LEAKING(buf_new_embedded(size));
	b->b_magic = BUF_MAGIC_PRIVATE;		/* Prevents accidental free */

	thread_private_add_extended(key, b, buf_private_reclaim, NULL);

	return b;
}

/**
 * Resize buffer to the specified size.
 *
 * When the new size is larger, the extra data in the buffer is zeroed.
 *
 * @param b		the buffer to resize
 * @param size	the new desired buffer size
 *
 * @return the new buffer, since the address can change due to reallocation
 * when the buffer is embedded.
 */
static buf_t *
buf_resize_internal(buf_t *b, size_t size)
{
	size_t old_size = b->b_size;
	char *p;

	g_assert(size_is_positive(size));	/* Implies `size' cannot be 0 */

	if (buf_is_embedded(b)) {
		b = xrealloc(b, BUF_DATA_OFFSET + size);
		p = (char *) b->b_u.bu_edata;
	} else {
		p = b->b_u.bu_data = xrealloc(b->b_u.bu_data, size);
	}

	b->b_size = size;
	if (old_size < size)
		memset(p + old_size, 0, size - old_size);

	return b;
}

/**
 * Resize buffer to the specified size.
 *
 * When the new size is larger, the extra data in the buffer is zeroed.
 *
 * @param b		the buffer to resize
 * @param size	the new desired buffer size
 *
 * @return the new buffer, since the address can change due to reallocation
 * when the buffer is embedded.
 */
buf_t *
buf_resize(buf_t *b, size_t size)
{
	buf_check(b);
	g_assert(BUF_MAGIC_PRIVATE != b->b_magic);
	g_assert(BUF_MAGIC_STATIC != b->b_magic);

	return buf_resize_internal(b, size);
}

/**
 * Grow buffer if needed to be able to hold the specified amout of data.
 *
 * @param b			the buffer to resize
 * @param total	the amount of bytes we would like to hold in buffer
 *
 * @return the new buffer, since the address can change due to reallocation
 * when the buffer is embedded.
 */
buf_t *
buf_grow(buf_t *b, size_t total)
{
	buf_check(b);
	g_assert(BUF_MAGIC_PRIVATE != b->b_magic);
	g_assert(BUF_MAGIC_STATIC != b->b_magic);

	if G_LIKELY(b->b_size >= total)
		return b;

	/*
	 * Provide some hysteresis when the block becomes larger than BUF_HYST_SIZE.
	 */

	if (total > BUF_HYST_SIZE)
		return buf_resize_internal(b, buf_hyst_round(total));

	return buf_resize_internal(b, total);
}

/**
 * Resize private buffer attached to given key to the specified size.
 *
 * When the new size is larger, the extra data in the buffer is zeroed.
 *
 * If the buffer was not already existing for that thread, it is allocated
 * transparently to the proper size.
 *
 * @param key	the key to access the thread-private buffer
 * @param size	the new desired buffer size
 *
 * @return the new buffer, since the address can change due to reallocation
 * when the buffer is embedded.
 */
buf_t *
buf_private_resize(const void *key, size_t size)
{
	buf_t *b, *nb;

	b = thread_private_get(key);

	if G_UNLIKELY(NULL == b)
		return buf_private(key, size);

	g_assert(BUF_MAGIC_PRIVATE == b->b_magic);

	nb = buf_resize_internal(b, size);
	if (nb != b) {
		bool found;

		/*
		 * Since the address of the thread-private value changes, we need
		 * to update the data structure.  We cannot simply remove the
		 * value because the free routine would be invoked, and the address
		 * just changed!
		 *
		 * We therefore remove the old free-routine we had installed, then
		 * remove the value from the table, then re-install the new value
		 * with the proper free routine.
		 */

		thread_private_set_extended(key, b, NULL, NULL);
		found = thread_private_remove(key);
		g_assert(found);

		thread_private_add_extended(key, nb, buf_private_reclaim, NULL);
	}

	return nb;
}

/**
 * Set character in buffer ``b'' at offset ``i'' to ``c''
 */
void
buf_setc(buf_t *b, size_t i, char c)
{
	char *data;

	buf_check(b);
	g_assert_log(i < buf_size(b),
		"%s(): i=%zu, buf_size(b)=%zu", G_STRFUNC, i, buf_size(b));

	data = buf_data(b);
	data[i] = c;
}

/**
 * Get character in buffer ``b'' at offset ``i''.
 */
char
buf_getc(const buf_t *b, size_t i)
{
	char *data;

	buf_check(b);
	g_assert_log(i < buf_size(b),
		"%s(): i=%zu, buf_size(b)=%zu", G_STRFUNC, i, buf_size(b));

	data = buf_data(b);
	return data[i];
}

/**
 * Copy data into buffer.
 *
 * @param b		the buffer to which data is copied
 * @param src	data source
 * @param len	length of data source, in bytes
 *
 * @return the amount of bytes copied.
 */
size_t
buf_copyin(buf_t *b, const void *src, size_t len)
{
	buf_check(b);

	return clamp_memcpy(buf_data(b), b->b_size, src, len);
}

/**
 * A regular sprintf() into the buffer, without fear of overflow.
 *
 * @return the amount of formatted chars.
 */
size_t
buf_printf(buf_t *b, const char *fmt, ...)
{
	va_list args;
	size_t n;

	va_start(args, fmt);
	n = str_vbprintf(buf_data(b), buf_size(b), fmt, args);
	va_end(args);

	return n;
}

/**
 * A regular sprintf() into the buffer, without fear of overflow.
 *
 * @return the amount of formatted chars.
 */
size_t
buf_vprintf(buf_t *b, const char *fmt, va_list args)
{
	return str_vbprintf(buf_data(b), buf_size(b), fmt, args);
}

/**
 * Append formatted string to previous string in fix-sized buffer.
 *
 * @return the amount of formatted chars.
 */
size_t
buf_catf(buf_t *b, const char *fmt, ...)
{
	va_list args;
	size_t n;

	va_start(args, fmt);
	n = str_vbcatf(buf_data(b), buf_size(b), fmt, args);
	va_end(args);

	return n;
}

/**
 * Append formatted string to previous string in fix-sized buffer.
 *
 * @return the amount of formatted chars.
 */
size_t
buf_vcatf(buf_t *b, const char *fmt, va_list args)
{
	return str_vbcatf(buf_data(b), buf_size(b), fmt, args);
}

/* vi: set ts=4 sw=4 cindent: */
