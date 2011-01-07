/*
 * $Id$
 *
 * Copyright (c) 1996-2000, 2007, 2010 Raphael Manfredi
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
 * Dynamic string handling.
 *
 * @author Raphael Manfredi
 * @date 1996-2000, 2007, 2010
 */

#ifndef _str_h_
#define _str_h_

#include "common.h"

struct str;
typedef struct str str_t;

/*
 * Public interface.
 */

size_t str_len(const str_t *s);
str_t *str_new(size_t szhint);
str_t *str_new_from(const char *string);
str_t *str_new_not_leaking(size_t szhint);
str_t *str_create(str_t *str, size_t szhint);
str_t *str_make(char *ptr, size_t len);
void str_foreign(str_t *str, char *buffer, size_t len, size_t size);
void str_from_foreign(str_t *str, char *ptr, size_t len, size_t size);
void str_free(str_t *str);
void str_destroy(str_t *str);
void str_destroy_null(str_t **s_ptr);
char *str_2c(str_t *str);
char *str_s2c_null(str_t **s_ptr);
char *str_dup(str_t *str);
str_t *str_clone(str_t *str);
void str_reset(str_t *str);
void str_grow(str_t *str, size_t size);
void str_setlen(str_t *str, size_t len);
void str_putc(str_t *str, char c);
void str_cpy(str_t *str, const char *string);
void str_cat(str_t *str, const char *string);
void str_cat_len(str_t *str, const char *string, size_t len);
void str_ncat(str_t *str, const char *string, size_t len);
void str_shift(str_t *str, size_t len);
gboolean str_ichar(str_t *str, ssize_t idx, char c);
gboolean str_istr(str_t *str, ssize_t idx, const char *string);
gboolean str_instr(str_t *str, ssize_t idx, const char *string, size_t n);
void str_remove(str_t *str, ssize_t idx, size_t n);
void str_chomp(str_t *s);
gboolean str_replace(str_t *str, ssize_t idx, size_t amt, const char *string);
void str_escape(str_t *str, char c, char e);

size_t str_vncatf(str_t *str, size_t maxlen, const char *fmt, va_list *args);
size_t str_vcatf(str_t *str, const char *fmt, va_list *args);
size_t str_vprintf(str_t *str, const char *fmt, va_list *args);
size_t str_catf(str_t *str, const char *fmt, ...) G_GNUC_PRINTF(2, 3);
size_t str_ncatf(str_t *str, size_t n, const char *fmt, ...)
	G_GNUC_PRINTF(3, 4);
size_t str_printf(str_t *str, const char *fmt, ...) G_GNUC_PRINTF(2, 3);
size_t str_nprintf(str_t *str, size_t n, const char *fmt, ...)
	G_GNUC_PRINTF(3, 4);
str_t *str_msg(const char *fmt, ...) G_GNUC_PRINTF(1, 2);
char *str_cmsg(const char *fmt, ...) G_GNUC_PRINTF(1, 2);

#endif /* _str_h_ */

