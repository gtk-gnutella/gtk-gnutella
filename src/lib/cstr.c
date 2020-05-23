/*
 * Copyright (c) 2018 Raphael Manfredi
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
 * C string miscellaneous utilities.
 *
 * A C string is a chain of bytes NUL-terminated.
 *
 * @author Raphael Manfredi
 * @date 2018
 */

#include "common.h"

#include "cstr.h"

#include "log.h"
#include "stringify.h"		/* For plural() */

#include "override.h"		/* Must be the last header included */

/*
 * Copy source string into destination without overflowing the destination buffer.
 *
 * @param dst		the destination buffer
 * @param len		length of the destination buffer in bytes
 * @param src		the source string (NUL-terminated) to copy into destination
 *
 * @return the length of the source string (if greater or equal to the buffer
 * length, it means output was truncated).
 */
static size_t
cstr_cpy(char *dst, size_t len, const char *src)
{
	char *d = dst;
	size_t n = len;
	const char *s = src;

	/*
	 * Copy source into destination as long as we have room for it.
	 */

	if (n != 0) {
		while (--n != 0) {
			if ('\0' == (*d++ = *s++))
				break;
		}
	}

	/*
	 * If we do not have enough room, truncate the string in the buffer
	 * since we stopped early and therefore did not copy the trailing NUL.
	 */

	if G_UNLIKELY(0 == n) {
		if (len != 0)
			*d = '\0';		/* NUL-terminate truncated string */

		/* Scan source to know its length */

		while (*s++)
			/* empty */;
	}

	/*
	 * Returns length of source string.
	 */

	return s - src - 1;		/* Does not count trailing NUL */
}

/*
 * A clone of strlcpy(), with different argument position.
 *
 * It truncates the output if the destination buffer is not large enough,
 * and emits a loud warning the first time it happens, to locate the place
 * in the code where this truncation was done.
 *
 * @param dst	the destination buffer
 * @param len	length of the destination buffer
 * @param src	the source string to copy into the buffer.
 *
 * @return the length of the source string (if greater or equal to the buffer
 * length, it means output was truncated).
 */
size_t
cstr_bcpy(char *dst, size_t len, const char *src)
{
	size_t slen;
	
	slen = cstr_cpy(dst, len, src);

	if G_UNLIKELY(slen >= len) {
		s_carp_once("%s(): truncated output after %zu byte%s, needed %zu",
			G_STRFUNC, len, plural(len), slen + 1);
	}

	return slen;
}

/*
 * A clone of strlcpy(), with different argument position.
 *
 * @param dst	the destination buffer
 * @param len	length of the destination buffer
 * @param src	the source string to copy into the buffer.
 *
 * @return TRUE if source fully fits in buffer.
 */
bool
cstr_fcpy(char *dst, size_t len, const char *src)
{
	return cstr_cpy(dst, len, src) < len;
}

/*
 * A clone of strlcpy(), with different argument position.
 *
 * @param dst	the destination buffer
 * @param len	length of the destination buffer
 * @param src	the source string to copy into the buffer.
 *
 * @return the length of the source string (if greater or equal to the buffer
 * length, it means output was truncated).
 */
size_t
cstr_lcpy(char *dst, size_t len, const char *src)
{
	return cstr_cpy(dst, len, src);
}

/* vi: set ts=4 sw=4 cindent: */
