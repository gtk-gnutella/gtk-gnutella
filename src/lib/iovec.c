/*
 * Copyright (c) 2004, Christian Biere
 * Copyright (c) 2012-2018, Raphael Manfredi
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
 * I/O vector helping routines.
 *
 * It is necessary to have routines using XMALLOC allocation macros to
 * be in a C file and not defined as inlined routines in a header file.
 * Otherwise, it is not possible to trap the allocation through a CPP
 * remapping in "override.h".
 * 		--RAM, 2020-08-19
 *
 * @author Christian Biere
 * @date 2004
 * @author Raphael Manfredi
 * @date 2012-2018
 */

#include "common.h"

#include "iovec.h"

#include "xmalloc.h"

#include "override.h"			/* Must be the last header included */

/**
 * Allocates an array of "struct iov" elements.
 * @param n The desired array length in elements.
 */
iovec_t *
iov_alloc_n(size_t n)
{
	iovec_t *iov;

	if (n > (size_t) -1 / sizeof *iov) {
		g_assert_not_reached(); /* We don't want to handle failed allocations */
		return NULL;
	}
	XMALLOC0_ARRAY(iov, n);
	return iov;
}

/**
 * Free array of "struct iov" elements allocated via iov_alloc_n().
 */
void
iov_free(iovec_t *iov)
{
	xfree(iov);
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
size_t
iov_scatter_string(iovec_t *iov, size_t iov_cnt, const char *s)
{
	size_t i, len, avail, size;

	g_assert(iov);
	g_assert(s);

	/* Reserve one byte for the trailing NUL */
	size = iov_calculate_size(iov, iov_cnt);
	len = vstrlen(s);
	if (len >= size) {
		len = size > 0 ? (size - 1) : 0;
	}
	avail = len;

	for (i = 0; i < iov_cnt; i++) {
		size_t n;

		n = MIN(iovec_len(&iov[i]), avail);
		memmove(iovec_base(&iov[i]), s, n);
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

/* vi: set ts=4 sw=4 cindent: */
