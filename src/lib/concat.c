/*
 * Copyright (c) 2001-2009, Raphael Manfredi
 * Copyright (c) 2003-2008, Christian Biere
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
 * String concatenation functions.
 *
 * @author Raphael Manfredi
 * @date 2001-2009
 * @author Christian Biere
 * @date 2003-2008
 */

#include "common.h"

#include "concat.h"
#include "glib-missing.h"
#include "unsigned.h"
#include "walloc.h"
#include "override.h"			/* Must be the last header included */

size_t
concat_strings_v(char *dst, size_t size, const char *s, va_list ap)
{
	char *p = dst;
	size_t ret = 0;

	g_assert(0 == size || NULL != dst);

	if (size > 0) {
		if (!s)
			*p = '\0';

		while (NULL != s) {
			size_t len;

			len = g_strlcpy(p, s, size);
			ret = size_saturate_add(ret, len);
			s = va_arg(ap, const char *);
			size = size_saturate_sub(size, len);
			if (0 == size)
				break;

			p += len;
		}
	}

	while (NULL != s) {
		ret = size_saturate_add(ret, strlen(s));
		s = va_arg(ap, const char *);
	}

	g_assert(ret < SIZE_MAX);
	return ret;
}

/**
 * Concatenates a variable number of NUL-terminated strings into ``dst''.
 *
 * The resulting string will be NUL-terminated unless ``size'' is zero. The
 * returned value is the length of the resulting string if ``dst'' had been
 * large enough. If the returned value is equal to or greater than ``size''
 * the string is truncated. If ``size'' is zero, ``dst'' may be NULL to
 * calculate the resulting string length.
 *
 * The list of strings must be terminated by a (void *) 0. The first
 * list element may be NULL in which case zero is returned.
 *
 * @param dst the destination buffer.
 * @param size the number of bytes ``dst'' can hold.
 * @param s the first source string or NULL.
 *
 * @return the sum of the lengths of all passed strings.
 */
size_t
concat_strings(char *dst, size_t size, const char *s, ...)
{
	va_list ap;
	size_t ret;

	va_start(ap, s);
	ret = concat_strings_v(dst, size, s, ap);
	va_end(ap);
	return ret;
}

/**
 * Concatenates a variable number of NUL-terminated strings into buffer
 * which will be allocated using walloc().
 *
 * The list of strings must be terminated by a (void *) 0. The first
 * list element may be NULL in which case 1 is returned.
 *
 * @param dst_ptr if not NULL, it will point to the allocated buffer.
 * @param first the first source string or NULL.
 *
 * @return The sum of the lengths of all passed strings plus 1 for the
 *         the trailing NUL. Use this as size argument for wfree() to
 *		   release the allocated buffer.
 */
size_t
w_concat_strings(char **dst_ptr, const char *first, ...)
{
	va_list ap;
	va_list ap2;
	size_t len;

	va_start(ap, first);
	VA_COPY(ap2, ap);

	len = concat_strings_v(NULL, 0, first, ap);
	va_end(ap);

	if (dst_ptr) {
		size_t ret;

		*dst_ptr = walloc(len + 1);
		ret = concat_strings_v(*dst_ptr, len + 1, first, ap2);
		g_assert(ret == len);
	}

	va_end(ap2);

	return 1 + len;
}

/* vi: set ts=4 sw=4 cindent: */
