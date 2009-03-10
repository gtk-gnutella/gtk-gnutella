/*
 * $Id$
 *
 * Copyright (c) 2004, Christian Biere
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

#ifndef _lib_iovec_h_
#define _lib_iovec_h_

#include "common.h"

/**
 * Allocates an array of "struct iov" elements.
 * @param n The desired array length in elements.
 */
static inline struct iovec *
iov_alloc_n(size_t n)
{
	struct iovec *iov;

	if (n > (size_t) -1 / sizeof *iov) {
		g_assert_not_reached(); /* We don't want to handle failed allocations */
		return NULL;
	}
	iov = g_malloc(n * sizeof *iov);
	return iov;
}

static inline struct iovec
iov_get(gpointer base, size_t size)
{
	static const struct iovec zero_iov;
	struct iovec iov;

	iov = zero_iov;
	iov.iov_base = base;
	iov.iov_len = size;
	return iov;
}

/**
 * Resets an array of "struct iov" elements, so that iov_base is NULL
 * and iov_len is 0 for each element.
 *
 * @param iov The array base.
 * @param n The array length in elements.
 */
static inline void
iov_reset_n(struct iovec *iov, size_t n)
{
	size_t i;

	g_assert(iov);
	for (i = 0; i < n; i++) {
		static const struct iovec zero_iov;
		iov[i] = zero_iov;
	}
}

/**
 * Initializes the elements of an struct iovec array from an array of strings.
 * iov_len is set to string length plus one to include the trailing NUL.
 *
 * @param iov An array of writable initialized memory buffers.
 * @param iov_cnt The array length of iov.
 * @param src The source buffer to copy.
 * @param size The amount of bytes to copy from "src".
 * @return The amount of elements initialized. Thus, MIN(iov_cnt, argc).
 */
static inline size_t 
iov_init_from_string_vector(struct iovec *iov, size_t iov_cnt,
	char *argv[], size_t argc)
{
	size_t i, n;

	g_assert(iov);
	g_assert(iov_cnt >= argc);
	g_assert(argv);

	n = MIN(iov_cnt, argc);
	for (i = 0; i < n; i++) {
		iov[i].iov_base = argv[i];
		iov[i].iov_len = argv[i] ? (1 + strlen(argv[i])) : 0;
	}
	return n;
}

/**
 * Checks whether two given struct iovec point to contiguous memory.
 *
 * @return TRUE if b->iov_base directly follows after &a->iov_base[a->iov_len].
 */
static inline gboolean
iov_is_contiguous(const struct iovec * const a, const struct iovec * const b)
{
	g_assert(a);
	g_assert(b);

	return (size_t) a->iov_base + a->iov_len == (size_t) b->iov_base;
}

/**
 * Returns the size of contiguous memory buffers.
 *
 * @param iov An array of initialized memory buffers.
 * @param iov_cnt The array length of iov.
 * @return The amount contiguous bytes.
 */
static inline size_t 
iov_contiguous_size(const struct iovec *iov, size_t iov_cnt)
{
	struct iovec iov0;
	size_t i;

	g_assert(iov);

	iov0 = iov[0];

	for (i = 1; i < iov_cnt && iov_is_contiguous(&iov0, &iov[i]); i++) {
		size_t n = iov[i].iov_len;

		if (n >= (size_t) -1 - iov0.iov_len) {
			/* Abort if size would overflow */
			iov0.iov_len = (size_t) -1;
			break;
		}
		iov0.iov_len += n;
	}
	return iov0.iov_len;
}

/**
 * Clear all bytes in the buffer starting at the given offset. If the
 * offset is beyond iov->iov_len, nothing happens.
 *
 * @param iov An initialized struct iovec.
 * @param byte_offset The offset relative to iov->iov_base.
 */
static inline void
iov_clear(struct iovec *iov, size_t byte_offset)
{
	g_assert(iov);
	
	if (byte_offset < iov->iov_len) {
		char *p = iov->iov_base;
		memset(&p[byte_offset], 0, iov->iov_len - byte_offset);
	}
}

/**
 * Calculates the cumulative size of the memory buffers. This uses
 * saturation arithmetic, so the returned value can never overflow.
 *
 * @param iov An array of initialized memory buffers.
 * @param iov_cnt The array length of iov.
 * @return The sum of all buffer sizes.
 */
static inline size_t
iov_calculate_size(struct iovec *iov, size_t iov_cnt)
{
	size_t size = 0;
	size_t i;

	g_assert(iov);

	for (i = 0; i < iov_cnt; i++) {
		size_t n = iov[i].iov_len;

		if (n >= (size_t) -1 - size) {
			/* Abort if size would overflow */
			size = (size_t) -1;
			break;
		}
		size += n;
	}
	return size;
}

/**
 * Scatters a NUL-terminated string over an array of struct iovec buffers. The
 * trailing buffer space is zero-filled. If the string is too long, it is
 * truncated, so that there is a terminating NUL in any case, except if the
 * buffer space is zero.
 *
 * @param iov An array of initialized memory buffers.
 * @param iov_cnt The array length of iov.
 * @return The amount of bytes copied excluding the terminating NUL.
 */
static inline size_t
iov_scatter_string(struct iovec *iov, size_t iov_cnt, const char *s)
{
	size_t i, len, avail, size;

	g_assert(iov);
	g_assert(s);

	/* Reserve one byte for the trailing NUL */
	size = iov_calculate_size(iov, iov_cnt);
	len = strlen(s);
	if (len >= size) {
		len = size > 0 ? (size - 1) : 0;
	}
	avail = len;

	for (i = 0; i < iov_cnt; i++) {
		size_t n;

		n = MIN(iov[i].iov_len, avail);
		memmove(iov[i].iov_base, s, n);
		avail -= n;
		s += n;
		if (0 == avail) {
			iov_clear(&iov[i], n);
			i++;
			break;
		}
	}
	while (i < iov_cnt) {
		iov_clear(&iov[i], 0);
		i++;
	}
	return len;
}

#endif /* _lib_iovec_h_ */
/* vi: set ts=4 sw=4 cindent: */
