/*
 * Copyright (c) 1996-2000, 2007, 2010-2015 Raphael Manfredi
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
 * @date 1996-2000, 2007, 2010-2015
 */

#ifndef _str_h_
#define _str_h_

#include "common.h"

/*
 * The string structure is public to allow static string objects.
 */

enum str_magic { STR_MAGIC = 0x04ed2baa };

/**
 * A dynamic string. That string is not NUL-terminated and is expanded
 * as necessary. To get the final C version, a call to str_2c() is mandatory:
 * It ensures the string is NUL-terminated and returns a pointer to it.
 */
typedef struct str {
	enum str_magic s_magic;
	uint32 s_flags;			/**< General flags */
	char *s_data;			/**< Where string data is held */
	size_t s_len;			/**< String length (amount of chars held) */
	size_t s_size;			/**< Size of the data arena */
} str_t;

static inline void
str_check(const struct str * const s)
{
	g_assert(s != NULL);
	g_assert(STR_MAGIC == s->s_magic);
	g_assert(s->s_len <= s->s_size);
}

/**
 * @return available bytes in current string's buffer.
 */
static inline size_t
str_avail(const struct str * const s)
{
	str_check(s);
	return s->s_size - s->s_len;
}

struct ckhunk;		/* Avoids dependency on "ckalloc.h" here */

/*
 * Public interface.
 */

size_t str_len(const str_t *s) G_PURE;
str_t *str_new(size_t szhint);
str_t *str_new_from(const char *string);
str_t *str_new_not_leaking(size_t szhint);
str_t *str_new_in_chunk(struct ckhunk *ck, size_t size);
str_t *str_new_in_buffer(void *buf, size_t len);
str_t *str_private(const void *key, size_t szhint);
str_t *str_create(str_t *str, size_t szhint);
str_t *str_make(char *ptr, size_t len);
void str_foreign(str_t *str, char *buffer, size_t len, size_t size);
void str_new_buffer(str_t *str, char *ptr, size_t len, size_t size);
void str_free(str_t *str);
void str_discard(str_t *str);
void str_destroy(str_t *str);
void str_destroy_null(str_t **s_ptr);
char *str_2c(str_t *str);
char *str_s2c_null(str_t **s_ptr);
char *str_dup(str_t *str);
str_t *str_clone(str_t *str);
void str_reset(str_t *str);
void str_grow(str_t *str, size_t size);
void str_reserve(str_t *str, size_t len);
void str_setlen(str_t *str, size_t len);
void str_putc(str_t *str, char c);
void str_cpy(str_t *str, const char *string);
void str_cpy_len(str_t *str, const char *string, size_t len);
void str_cat(str_t *str, const char *string);
void str_cat_len(str_t *str, const char *string, size_t len);
void str_ncat(str_t *str, const char *string, size_t len);
bool str_ncat_safe(str_t *str, const char *string, size_t len);
void str_shift(str_t *str, size_t len);
bool str_ichar(str_t *str, ssize_t idx, char c);
bool str_istr(str_t *str, ssize_t idx, const char *string);
bool str_instr(str_t *str, ssize_t idx, const char *string, size_t n);
void str_remove(str_t *str, ssize_t idx, size_t n);
void str_chomp(str_t *s);
char str_chop(str_t *s);
bool str_replace(str_t *str, ssize_t idx, size_t amt, const char *string);
void str_reverse(str_t *s);
void str_escape(str_t *str, char c, char e);
size_t str_copyout(str_t *s, char *dest, size_t dest_size);
size_t str_copyout_offset(str_t *s, size_t off, char *dest, size_t dest_size);
size_t str_reverse_copyout(str_t *s, char *dest, size_t dest_size);
size_t str_memout(str_t *s, char *dest, size_t dest_size);
size_t str_memout_offset(str_t *s, size_t off, char *dest, size_t dest_size);
char str_at(const str_t *s, ssize_t offset);
ssize_t str_chr(const str_t *s, int c);
ssize_t str_chr_at(const str_t *s, int c, ssize_t offset);
ssize_t str_rchr(const str_t *s, int c);
ssize_t str_rchr_at(const str_t *s, int c, ssize_t offset);
str_t *str_slice(const str_t *s, ssize_t from, ssize_t to);
str_t *str_substr(const str_t *s, ssize_t from, size_t length);
bool str_has_suffix_len(const str_t *, const char *suf, size_t len, size_t *ix);
bool str_has_suffix(const str_t *, const char *suf, size_t *ix);

size_t str_vncatf(str_t *str, size_t maxlen, const char *fmt, va_list args);
size_t str_vcatf(str_t *str, const char *fmt, va_list args);
size_t str_vprintf(str_t *str, const char *fmt, va_list args);
size_t str_catf(str_t *str, const char *fmt, ...) G_PRINTF(2, 3);
size_t str_ncatf(str_t *str, size_t n, const char *fmt, ...)
	G_PRINTF(3, 4);
size_t str_printf(str_t *str, const char *fmt, ...) G_PRINTF(2, 3);
size_t str_nprintf(str_t *str, size_t n, const char *fmt, ...)
	G_PRINTF(3, 4);
str_t *str_msg(const char *fmt, ...) G_PRINTF(1, 2);
char *str_cmsg(const char *fmt, ...) G_PRINTF(1, 2);
char *str_vcmsg(const char *fmt, va_list args);
const char *str_smsg(const char *fmt, ...) G_PRINTF(1, 2);
const char *str_smsg2(const char *fmt, ...) G_PRINTF(1, 2);
size_t str_bprintf(char *dst, size_t size, const char *fmt, ...)
	G_PRINTF(3, 4);
size_t str_vbprintf(char *dst, size_t size, const char *fmt, va_list args);
size_t str_bcatf(char *dst, size_t size, const char *fmt, ...)
	G_PRINTF(3, 4);
size_t str_vbcatf(char *dst, size_t size, const char *fmt, va_list args);

size_t str_test(bool verbose);

/*
 * Macros to use with constant string arguments.
 *
 * STR_CONST_LEN() must be used with a manifest string (or there will be
 * a compile-time error) and it returns the length of the C string at
 * compile time.
 *
 * The appended "" in the macro is NOT an error and allows catching some
 * improper usage, relying on compile-time string concatenation when the
 * argument is a manifest string.  It will not catch improper usage like
 * STR_CONST_LEN(v ? "a" : "bc") though.
 *
 * STR_CPY() and STR_CAT() are also intended to be used with manifest strings
 * and issue the corresponding calls with the length of their string argument
 * pre-computed at compile time.
 */

#define STR_CONST_LEN(p)	(sizeof(p "") - 1)
#define STR_CPY(s, p)		str_cpy_len((s), (p), STR_CONST_LEN(p))
#define STR_CAT(s, p)		str_cat_len((s), (p), STR_CONST_LEN(p))

#define STR_HAS_SUFFIX(s, p, i)	\
	str_has_suffix_len((s), (p), STR_CONST_LEN(p), (i))

#endif /* _str_h_ */

/* vi: set ts=4 sw=4 cindent: */
