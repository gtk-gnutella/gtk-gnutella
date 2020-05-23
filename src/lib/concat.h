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
 *      51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
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

#ifndef _concat_h_
#define _concat_h_

size_t concat_strings(char *dst, size_t size,
	const char *s, ...) G_NULL_TERMINATED;
size_t w_concat_strings(char **dst,
	const char *first, ...) G_NULL_TERMINATED;
size_t concat_strings_v(char *dst, size_t size, const char *s, va_list ap);

#endif /* _concat_h_ */

/* vi: set ts=4 sw=4 cindent: */
