/*
 * Copyright (c) 2015 Raphael Manfredi
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
 * String vector array utilities.
 *
 * @author Raphael Manfredi
 * @date 2015
 */

#ifndef _strvec_h_
#define _strvec_h_

/*
 * Public interface.
 */

size_t strvec_count(char * const *strv);
size_t strvec_size(char * const *strv);
size_t strvec_free_with(free_fn_t fn, char **strv);
char **strvec_append_with(realloc_fn_t fn,
	char **oldv, size_t *oldn,
	char * const *copyv, size_t copyn);
void *strvec_cpy(char **dstv, char * const *strv, size_t cnt,
		void *mem, size_t *len);

#endif	/* _strvec_h_ */

/* vi: set ts=4 sw=4 cindent: */
