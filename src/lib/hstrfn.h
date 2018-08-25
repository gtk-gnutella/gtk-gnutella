/*
 * Copyright (c) 2016 Raphael Manfredi
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
 * String functions where memory is dynamically allocated via halloc().
 *
 * @author Raphael Manfredi
 * @date 2015
 */

#ifndef _hstrfn_h_
#define _hstrfn_h_

/*
 * Public interface.
 */

void *h_private(const void *key, void *p);

/*
 * Under TRACK_MALLOC control, these routines are remapped to malloc()/free().
 */

#ifndef TRACK_MALLOC
char *h_strdup(const char *str) G_MALLOC;
char *h_strndup(const char *str, size_t n) G_MALLOC;
char *h_strjoinv(const char *separator, char * const *str_ary);
char *h_strnjoinv(const char *separator, size_t seplen, char * const *str_ary);
void h_strfreev(char **str_array);
char *h_strconcat(const char *str1, ...) G_MALLOC G_NULL_TERMINATED;
char *h_strconcat_v(const char *first, va_list ap) G_MALLOC;
char *h_strdup_printf(const char *format, ...) G_PRINTF(1, 2);
char *h_strdup_vprintf(const char *format, va_list ap) G_PRINTF(1, 0);
char *h_strdup_len_vprintf(const char *format, va_list ap, size_t *len)
	G_PRINTF(1, 0);
#endif	/* !TRACK_MALLOC */

char **h_strsplit(const char *str, const char *delim, size_t max_tokens);
char **h_strsplit_set(const char *str, const char *delim, size_t max_tokens);

#endif	/* _hstrfn_h_ */

/* vi: set ts=4 sw=4 cindent: */
