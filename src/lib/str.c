/*
 * Copyright (c) 1996-2000, 2007, 2010 Raphael Manfredi
 *
 * This code given by Raphael Manfredi, extracted from his fm2html package.
 * Also contains some code borrowed from Perl: routine str_vncatf().
 * Code was slightly adapted to use standard features available in the
 * gtk-gnutella library.
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
 * All memory allocation is done through walloc() and halloc().
 * Memory must be released with hfree().
 *
 * @author Raphael Manfredi
 * @date 1996-2000, 2007, 2010
 */

#include "common.h"

#include <math.h>		/* For frexp() and isfinite() */

#include "str.h"
#include "ascii.h"
#include "ckalloc.h"
#include "float.h"
#include "glib-missing.h"
#include "halloc.h"
#include "log.h"
#include "misc.h"			/* For clamp_strcpy() and symbolic_errno() */
#include "unsigned.h"
#include "walloc.h"

#include "override.h"		/* Must be the last header included */

#define STR_DEFSIZE		64		/* Default string size */
#define STR_GROW		2		/* Grow factor, if size less than STR_MAXGROW */
#define STR_MAXGROW		4096	/* Above this size, increase by STR_CHUNK */
#define STR_CHUNK		4096	/* Size increase if above STR_MAXGROW */

#define FPREC			17		/* IEEE 64-bit double maximum digit precision */

static gboolean tests_completed;	/* Controls truncation warnings */
static gboolean format_verbose;		/* Controls debugging of formatting */

static inline void
str_check(const struct str * const s)
{
	g_assert(s != NULL);
	g_assert(STR_MAGIC == s->s_magic);
	g_assert(s->s_len <= s->s_size);
}

/**
 * Flags for s_flags
 */
#define STR_FOREIGN_PTR		(1 << 0)	/**< We don't own the pointer */
#define STR_OBJECT			(1 << 1)	/**< Object created, not a structure */

/**
 * @return length of string.
 */
size_t
str_len(const str_t *s)
{
	str_check(s);

	/*
	 * Make a "foreign" string appear shorter because when we convert it
	 * to C we will need to append a trailing NUL, truncating the last
	 * character.
	 */

	if (G_UNLIKELY(s->s_flags & STR_FOREIGN_PTR)) {
		if (s->s_len == s->s_size)
			return s->s_len - 1;
		/* FALL THROUGH */
	}

	return s->s_len;
}

/**
 * Allocate a new non-leaking string structure.
 *
 * This should only be used with static string objects that are never freed.
 */
str_t *
str_new_not_leaking(size_t szhint)
{
	str_t *str;

	str = NOT_LEAKING_Z(str_new(szhint));
	(void) NOT_LEAKING(str->s_data);

	return str;
}

/**
 * Allocate a new string structure from a pre-allocated chunk.
 *
 * The string buffer is non-resizeable so the string must be carefully sized.
 *
 * This is meant to be used in signal handlers, in order to construct logging
 * messages or format strings.
 *
 * @param ck	the pre-allocated chunk from which allocation is done
 * @param size	size of the string buffer.
 *
 * @return the allocated string object, NULL if there is no more memory
 * available in the chunk.
 */
str_t *
str_new_in_chunk(ckhunk_t *ck, size_t size)
{
	str_t *str;
	char *arena;

	g_assert(size_is_positive(size));

	/*
	 * Start by allocating the arena, which is by far the largest amount
	 * to get from the chunk.
	 */

	arena = ck_alloc(ck, size);
	if G_UNLIKELY(NULL == arena)
		return NULL;

	/*
	 * Now that we allocated the arena, and since we cannot free individual
	 * objects in a chunk, use critical allocation to be able to allocate
	 * the str_t object, hopefully.
	 */

	str = ck_alloc_critical(ck, sizeof *str);
	if G_UNLIKELY(NULL == str)
		return NULL;

	/*
	 * Detect harmful asynchronous ck_restore() between two allocations.
	 */

	g_assert_log(ptr_diff(str, arena) >= size,
		"str=%p, arena=%p, size=%zu", (void *) str, arena, size);

	/*
	 * Don't set the STR_OBJECT because the object is non-freeable.
	 * Force STR_FOREIGN_PTR because the arena is non-freeable.
	 */

	str->s_magic = STR_MAGIC;
	str->s_flags = STR_FOREIGN_PTR;
	str->s_data = arena;
	str->s_len = 0;
	str->s_size = size;

	return str;
}

/**
 * Allocate a new string structure, of the specified hint size.
 *
 * @param szhint	initial length of the data buffer (0 for default)
 *
 * @return newly allocated string.
 */
str_t *
str_new(size_t szhint)
{
	str_t *str;

	WALLOC(str);
	str_create(str, szhint);
	str->s_flags |= STR_OBJECT;		/* Signals: we allocated the object */

	return str;
}

/**
 * Fill in an existing string structure, of the specified hint size.
 *
 * @return its "str" argument.
 */
str_t *
str_create(str_t *str, size_t szhint)
{
	g_assert(str != NULL);

	if (szhint == 0)
		szhint = STR_DEFSIZE;

	str->s_flags = 0;
	str->s_magic = STR_MAGIC;
	str->s_data = halloc(szhint);
	str->s_len = 0;
	str->s_size = szhint;

	return str;
}

/**
 * Create a new string from supplied C string (may be NULL).
 */
str_t *
str_new_from(const char *string)
{
	str_t *s;

	if (NULL == string) {
		s = str_new(STR_DEFSIZE);
	} else {
		size_t len;

		len = strlen(string);
		s = str_new(len + 1 + (len / 4));
		str_cat_len(s, string, len);
	}

	return s;
}

/**
 * Fill a string structure with supplied C pointer, pointing to an arena
 * of `len' bytes. The resulting string is made "foreign" since we don't
 * own the pointer.
 *
 * If `len' is (size_t) -1, an strlen() is ran on `ptr' to compute the length.
 * If `size' is 0, it is set to `len + 1' (after length computation, if any).
 */
void
str_foreign(str_t *str, char *ptr, size_t len, size_t size)
{
	str_check(str);

	g_assert(ptr != NULL);
	g_assert(size_is_non_negative(len + 1));
	g_assert(size_is_non_negative(size));

	if (str->s_data != NULL && !(str->s_flags & STR_FOREIGN_PTR))
		str_free(str);

	if ((size_t) -1 == len)
		len = strlen(ptr);

	if (0 == size)
		size = len + 1;			/* Must include hidden NUL in foreign string */

	str->s_flags |= STR_FOREIGN_PTR;
	str->s_len = len;
	str->s_size = size;
	str->s_data = ptr;
}

/**
 * Like str_foreign(), but string structure has not been initialized yet
 * and is a static buffer.
 *
 * To create a string on the stack with no memory allocation:
 *
 *    str_t str;
 *    char data[80];
 *
 *    str_from_foreign(&str, data, 0, sizeof data);
 */
void
str_from_foreign(str_t *str, char *ptr, size_t len, size_t size)
{
	g_assert(str != NULL);

	ZERO(str);
	str->s_magic = STR_MAGIC;
	str_foreign(str, ptr, len, size);
}

/**
 * Make an str_t object out of a specified C string, which is duplicated.
 * If specified length is (size_t) -1, it is computed using strlen().
 */
str_t *
str_make(char *ptr, size_t len)
{
	str_t *str;

	g_assert(ptr != NULL);
	g_assert(size_is_non_negative(len + 1));

	if ((size_t) -1 == len)
		len = strlen(ptr);					/* Can still be zero, but it's OK */

	WALLOC(str);
	(void) str_create(str, len + 1);		/* Allow for trailing NUL */
	str->s_len = len;						/* Final NUL not accounted for */
	memcpy(str->s_data, ptr, len);			/* Don't copy trailing NUL */

	return str;
}

/**
 * Creates a clone of the str_t object.
 */
str_t *
str_clone(str_t *str)
{
	size_t len;
	str_t *n;

	str_check(str);

	len = str->s_len;
	n = str_new(len + 1);	/* Allow for trailing NUL in str_2c() */
	n->s_len = len;
	memcpy(n->s_data, str->s_data, len);

	return n;
}

/**
 * Free string held within the str_t structure, but not the structure itself.
 */
void
str_free(str_t *str)
{
	str_check(str);

	/*
	 * If data arena is a foreign structure, don't free it: we are not the
	 * owner of the pointer to it.
	 */

	if (!(str->s_flags & STR_FOREIGN_PTR))
		hfree(str->s_data);
	else
		str->s_flags &= ~STR_FOREIGN_PTR;		/* Clear foreign indication */

	str->s_data = NULL;
	str->s_len = 0;
	str->s_size = 0;
}

/**
 * Destroy string held within the str_t structure, then the structure.
 */
void
str_destroy(str_t *str)
{
	str_check(str);

	if G_UNLIKELY(!(str->s_flags & STR_OBJECT))
		s_error("str_destroy() called on \"static\" string object");

	str_free(str);
	str->s_magic = 0;
	WFREE(str);
}

/**
 * Destroy string and nullify pointer.
 */
void
str_destroy_null(str_t **s_ptr)
{
	str_t *s = *s_ptr;

	if (s != NULL) {
		str_destroy(s);
		*s_ptr = NULL;
	}
}

/**
 * Expand/shrink data space, if possible.
 */
static void
str_resize(str_t *str, size_t newsize)
{
	str_check(str);
	g_assert(size_is_non_negative(newsize));

	/*
	 * When called on foreign strings, we don't have to shrink the data
	 * space since we don't own the pointer. However, it is a panic if we
	 * are called to expand that space.
	 */

	if G_UNLIKELY(str->s_flags & STR_FOREIGN_PTR) {
		if (str->s_size >= newsize)
			return;
		s_error("str_resize() would expand \"foreign\" string");
	}

	/*
	 * Already fits exactly, nothing to do.
	 */

	if (str->s_size == newsize)
		return;

	/*
	 * Make the data space "exactly" fit (modulo malloc alignment constraints)
	 * with the requested `newsize'.
	 */

	str->s_data = hrealloc(str->s_data, newsize);
	str->s_size = newsize;
	if (str->s_len > newsize)
		str->s_len = newsize;
}

/*
 * str_makeroom
 *
 * Ensure there is enough room for `len' more bytes worth of data in `s' by
 * calling str_resize if necessary.
 */
static inline void
str_makeroom(str_t *s, size_t len)
{
	size_t n = size_saturate_add(len, s->s_len);

	if G_UNLIKELY(s->s_size < n) {
		size_t newsize = s->s_size;

		while (newsize < n) {
			if (newsize <= STR_MAXGROW)
				newsize = size_saturate_mult(newsize, STR_GROW);
			else
				newsize = size_saturate_add(newsize, STR_CHUNK);
		}
		str_resize(s, newsize);
	}
}

/**
 * Expand data space if necessary, returning the (new) data location.
 */
void
str_grow(str_t *str, size_t size)
{
	str_check(str);
	g_assert(size_is_non_negative(size));

	if G_LIKELY(str->s_size >= size)
		return;					/* Nothing to do */

	if G_UNLIKELY(str->s_flags & STR_FOREIGN_PTR)
		s_error("str_grow() called on \"foreign\" string");

	str->s_data = hrealloc(str->s_data, size);
	str->s_size = size;
}

/**
 * Change logical length of the string in the arena.
 */
void
str_setlen(str_t *str, size_t len)
{
	size_t curlen;

	str_check(str);
	g_assert(size_is_non_negative(len));

	if G_UNLIKELY(0 == len) {
		str_reset(str);
		return;
	}

	curlen = str->s_len;

	if (len == curlen)
		return;

	if (curlen > len) {						/* Truncating */
		str->s_len = len;					/* Truncated string */
		return;
	}

	if (len >= str->s_size)
		str_makeroom(str, len - str->s_size + 1);	/* Allow hidden NUL */

	memset(str->s_data + curlen, 0, len - curlen);	/* Zero expanded area */
	str->s_len = len;
}

/**
 * @return a pointer to the data, as a `C' string (NUL-terminated).
 *
 * As a convenience, returns NULL if "str" is NULL.
 *
 * NB: The returned string is still held within the str_t object. Use str_s2c()
 * to get the C string and dispose of the str_t overhead.
 */
char *
str_2c(str_t *str)
{
	size_t len;

	if G_UNLIKELY(NULL == str)
		return NULL;

	str_check(str);

	len = str->s_len;

	if (len == str->s_size) {
		if G_UNLIKELY(str->s_flags & STR_FOREIGN_PTR) {
			len--;						/* Truncate the string */
			str->s_len = len;
		} else {
			str_grow(str, len + 1);		/* Allow room for trailing NUL */
		}
	}

	str->s_data[len] = '\0';		/* Don't increment str->s_len */

	return str->s_data;
}

/**
 * Destroy the str_t container and keep only its data arena, returning a
 * pointer to it as a `C' string (NUL-terminated).
 *
 * The returned string must be freed via hfree().
 *
 * As a convenience, returns NULL if "str" is NULL.
 *
 * NB: Upon return, the str_t object is gone. Use str_2c() to get a C string
 * still held within the object.
 */
static char *
str_s2c(str_t *str)
{
	char *cstr;
	size_t len;

	if (NULL == str)
		return NULL;

	str_check(str);

	if G_UNLIKELY(!(str->s_flags & STR_OBJECT))
		s_error("str_s2c() called on \"static\" string object");

	len = str->s_len;

	if G_UNLIKELY(str->s_flags & STR_FOREIGN_PTR) {
		if (len == str->s_size)
			len--;						/* Truncate the string */
	} else {
		str_resize(str, len + 1);		/* Ensure string fits neatly */
	}

	cstr = str->s_data;
	cstr[len] = '\0';				/* Ensure trailing NUL for C */

	str->s_magic = 0;
	WFREE(str);

	return cstr;
}

/**
 * Same as str_s2c() but also nullifies the string pointer, since it is
 * becoming invalid.
 *
 * If "s_ptr" was pointing to NULL, returns a NULL as well.
 */
char *
str_s2c_null(str_t **s_ptr)
{
	char *result;

	g_assert(s_ptr != NULL);

	result = str_s2c(*s_ptr);
	*s_ptr = NULL;

	return result;
}

/**
 * Create a pure C string copy of the string currently held in the arena.
 * @return pointer to the copied string location.
 *
 * NB: The str_t object is not disposed of. If the object is no longer needed,
 * use str_s2c() to dispose of it whilst retaining its arena.
 */
char *
str_dup(str_t *str)
{
	size_t len;
	char *sdup;

	str_check(str);

	len = str->s_len;
	sdup = halloc(len + 1);
	memcpy(sdup, str->s_data, len);
	sdup[len] = '\0';

	return sdup;
}

/**
 * Append a character to the string (NUL allowed).
 */
void
str_putc(str_t *str, char c)
{
	str_check(str);

 	str_makeroom(str, 1);
	str->s_data[str->s_len++] = c;
}

/**
 * Empty string.
 */
void
str_reset(str_t *str)
{
	str_check(str);

	str->s_len = 0;
}

/**
 * Copy string argument into the string structure, keeping trailing NUL as
 * a hidden char (thereby making the arena a C string).
 */
void
str_cpy(str_t *str, const char *string)
{
	str_check(str);

	str->s_len = 0;
	str_cat_len(str, string, strlen(string));
}

/**
 * Append C string argument (i.e. has a trailing NUL) into the string structure,
 * keeping this trailing NUL as a hidden char (not accounted for in s_len).
 */
void
str_cat(str_t *str, const char *string)
{
	str_check(str);
	g_assert(string != NULL);

	str_cat_len(str, string, strlen(string));
}

/**
 * Append "len" bytes of data to string.
 *
 * Since the len is provided, the data need not have a trailing NUL.
 * Although it may contain embedded NUL, it should not however because this
 * will disrupt the perception of the resulting string as C string.
 */
void
str_cat_len(str_t *str, const char *string, size_t len)
{
	str_check(str);
	g_assert(string != NULL);
	g_assert(size_is_non_negative(len));

	if G_UNLIKELY(0 == len)
		return;

	str_makeroom(str, len + 1);		/* Allow for trailing NUL */
	memcpy(str->s_data + str->s_len, string, len);
	str->s_len += len;				/* Trailing NUL remains hidden */
}

/**
 * Append specified amount of bytes into the string, or less if the
 * string is shorter than `len'.
 */
void
str_ncat(str_t *str, const char *string, size_t len)
{
	char *p;
	const char *q;
	char c;

	str_check(str);
	g_assert(string != NULL);
	g_assert(size_is_non_negative(len));

	if G_UNLIKELY(0 == len)
		return;

	str_makeroom(str, len + 1);			/* Allow for trailing NUL */
	p = str->s_data + str->s_len; 
	q = string;

	while (len > 0 && '\0' != (c = *q++)) {
		*p++ = c;
		len--;
	}

	str->s_len = p - str->s_data;
}

/**
 * Append specified amount of bytes into the string, or less if the
 * string is shorter than `len' or if the string arena is foreign and not
 * large enough to hold all the data.
 *
 * The routine is "safe" in that it will never trigger an error when the
 * foreign string is too small, silently truncating instead.
 *
 * When the string arena can be resized, this routine behaves as str_ncat().
 *
 * @return TRUE if written normally, FALSE when clamping was done.
 */
gboolean
str_ncat_safe(str_t *str, const char *string, size_t len)
{
	char *p;
	const char *q;
	char c;
	gboolean fits = TRUE;

	str_check(str);
	g_assert(string != NULL);
	g_assert(size_is_non_negative(len));

	if G_UNLIKELY(0 == len)
		return TRUE;

	if G_UNLIKELY(str->s_flags & STR_FOREIGN_PTR) {
		size_t n;

		if (str->s_len == str->s_size) {
			return FALSE;		/* Nothing can fit */
		} else {
			n = size_saturate_add(len, str->s_len);

			if (n >= str->s_size) {
				fits = FALSE;
				len = str->s_size - str->s_len - 1;	/* -1 for trailing NUL */
				if (0 == len)
					return FALSE;
			}
		}
	} else {
		str_makeroom(str, len + 1);			/* Allow for trailing NUL */
	}

	p = str->s_data + str->s_len; 
	q = string;

	while (len > 0 && '\0' != (c = *q++)) {
		*p++ = c;
		len--;
	}

	str->s_len = p - str->s_data;
	return fits;
}

/**
 * Discard first n bytes from string, shifting the remaining to the left and
 * adjusting the size.
 */
void
str_shift(str_t *str, size_t n)
{
	size_t len;

	str_check(str);
	g_assert(size_is_non_negative(n));

	if G_UNLIKELY(0 == n)
		return;

	if (n >= str->s_len) {
		str->s_len = 0;
		return;
	}

	len = str->s_len;
	memmove(str->s_data, str->s_data + n, len - n);			/* Overlap-safe */
	str->s_len -= n;
}

/**
 * Insert char before given position. If outside string bounds, do nothing.
 * If index is negative, insert from the end of the string, i.e. -1 means
 * before the last character, and so on.
 *
 * @return TRUE if insertion took place, FALSE if it was ignored.
 */
gboolean
str_ichar(str_t *str, ssize_t idx, char c)
{
	size_t len;

	str_check(str);

	len = str->s_len;

	if (idx < 0)						/* Stands for chars before end */
		idx += len;

	if G_UNLIKELY(idx < 0 || (size_t) idx >= len)		/* Off string */
		return FALSE;

	str_makeroom(str, 1);
	memmove(str->s_data + idx + 1, str->s_data + idx, len - idx);
	str->s_data[idx] = c;
	str->s_len++;

	return TRUE;
}

/**
 * Insert string before given position. If outside string bounds, do nothing.
 * If index is negative, insert from the end of the string, i.e. -1 means
 * before the last character, etc...
 *
 * @return TRUE if insertion took place, FALSE if it was ignored.
 */
gboolean
str_istr(str_t *str, ssize_t idx, const char *string)
{
	str_check(str);
	g_assert(string != NULL);

	return str_instr(str, idx, string, strlen(string));
}

/**
 * Same as str_istr, only the first `n' chars of string are inserted.
 *
 * @return TRUE if insertion took place, FALSE if it was ignored.
 */
gboolean
str_instr(str_t *str, ssize_t idx, const char *string, size_t n)
{
	size_t len;

	str_check(str);
	g_assert(string != NULL);
	g_assert(size_is_non_negative(n));

	len = str->s_len;

	if G_UNLIKELY(0 == n)				/* Empty string */
		return TRUE;					/* Did nothing but nothing to do */

	if (idx < 0)						/* Stands for chars before end */
		idx += len;

	if G_UNLIKELY(idx < 0 || (size_t) idx >= len)	/* Off string */
		return FALSE;

	str_makeroom(str, n);
	memmove(str->s_data + idx + n, str->s_data + idx, len - idx);
	memmove(str->s_data + idx, string, n);
	str->s_len += n;

	return TRUE;
}

/**
 * Remove n characters starting from index idx.
 * If idx is negative, start from end of string, i.e. -1 is last char.
 * If n is larger than what remains in string, remove until end of string.
 */
void
str_remove(str_t *str, ssize_t idx, size_t n)
{
	size_t len;

	str_check(str);
	g_assert(size_is_non_negative(n));

	len = str->s_len;

	if G_UNLIKELY(0 == n)				/* Nothing to remove */
		return;

	if (idx < 0)						/* Stands for chars before end */
		idx += len;

	if (idx < 0 || (size_t) idx >= len)			/* Off string */
		return;

	if (n >= (len - idx)) {				/* A mere truncation till end */
		str->s_len = idx;
		return;
	}

	memmove(str->s_data + idx, str->s_data + idx + n, len - idx - n);
	str->s_len -= n;
}

/**
 * Replace amount characters starting at position idx (included) with the
 * content of the specified string. If the starting position is negative,
 * it is interpreted as an offset relative to the end of the string, i.e. -1
 * is the last character.
 *
 * If the amount is greater than the characters held in the string after the
 * starting position, it is silently truncated down to the amount of bytes
 * held until the end of the string.
 *
 * @return TRUE if we replaced, FALSE if we ignored due to out-of-bound index.
 */
gboolean
str_replace(str_t *str, ssize_t idx, size_t amount, const char *string)
{
	size_t length;
	size_t len;

	str_check(str);
	g_assert(size_is_non_negative(amount));
	g_assert(string != NULL);

	length = strlen(string);
	len = str->s_len;

	if (idx < 0)						/* Stands for chars before end */
		idx += len;

	if G_UNLIKELY(idx < 0 || (size_t) idx >= len)	/* Off string */
		return FALSE;

	if (amount > (len - idx))			/* More than what remains afterwards */
		amount = len - idx;

	/*
	 * Start by copying those characters from replacing string that will
	 * physically replace existing characters.
	 */

	if (length) {
		size_t n = length > amount ? amount : length;
		memmove(str->s_data + idx, string, n);
		length -= n;
		string += n;
		idx += n;
		amount -= n;
	}

	/*
	 * We're done if both length and amount are zero: replacement string
	 * fully covered existing chars, the overall string length did not change.
	 *
	 * If only length reached zero, then the replacement string was shorter
	 * than the replaced spot. We need to remove extra characters from string,
	 * and we're done.
	 */

	if (length == 0) {
		if (amount)							/* Not fully covered spot */
			str_remove(str, idx, amount);	/* Remove extra characters */
		return TRUE;
	}

	/*
	 * Replacement string was larger than the replaced spot. Insert
	 * remaining characters after the spot we just superseded. If we're at
	 * the end of the string, i.e. if idx is str->s_len, call str_ncat()
	 * instead since str_instr() won't do anything when index is off bounds.
	 */

	if ((size_t) idx == str->s_len)
		str_ncat(str, string, length);
	else
		str_instr(str, idx, string, length);

	return TRUE;
}

/**
 * Remove antepenultimate char of string if it is a "\r" followed by "\n".
 * Remove final char of string if it is a plain "\n" or "\r".
 */
void
str_chomp(str_t *s)
{
	size_t len;

	str_check(s);

	len = s->s_len;

	if (len >= 2 && s->s_data[len - 2] == '\r' && s->s_data[len - 1] == '\n') {
		s->s_len -= 2;
	} else if (
		len >= 1 && (s->s_data[len - 1] == '\r' || s->s_data[len - 1] == '\n')
	) {
		s->s_len--;
	}
}

/**
 * Escape (in-place) all 'c' characters in string by prepending an escape 'e'
 * char in front of them.
 */
void
str_escape(str_t *str, char c, char e)
{
	size_t len;
	size_t idx;

	str_check(str);

	len = str->s_len;

	if G_UNLIKELY(0 == len)
		return;

	for (idx = 0; idx < len; idx++) {
		if (str->s_data[idx] != c)
			continue;
		str_ichar(str, idx, e);			/* Insert escape char in front */
		idx++;							/* Skip escaped char */
		len++;							/* One more char in string */
	}
}

/**
 * Round up floating-point mantissa, with leading extra carry digit.
 *
 * For instance, given "314159" with a rounding position of 2, the routine
 * returns "0314".  However, given "9995", it would return "1000".
 *
 * This routine is used internally by str_nvcatf() to format floats.
 *
 * @param mbuf		the mantissa
 * @param mlen		the length of the mantissa
 * @param pos		rounding position (index of first digit to exclude in mbuf)
 * @param rbuf		where rounded mantissa is writen
 * @param rlen		length of rounded mantissa (at least mlen + 1)
 *
 * @return number of characters written in the rounded mantissa buffer
 */
static size_t
str_fround(const char *mbuf, size_t mlen, size_t pos, char *rbuf, size_t rlen)
{
	g_assert(mbuf != NULL);
	g_assert(size_is_non_negative(mlen));
	g_assert(size_is_non_negative(pos));
	g_assert(pos <= mlen);
	g_assert(rbuf != NULL);
	g_assert(rlen >= mlen + 1);

	if (pos == mlen) {
		/* Nothing to round, copy whole mantissa, leading carry is '0' */
		rbuf[0] = '0';
		clamp_memcpy(&rbuf[1], rlen - 1, mbuf, mlen);
	} else if (0 == pos) {
		char c = mbuf[0];
		/* Look adhead next digit to round approximated mantissa */
		if (mlen > 1) {
			if (mbuf[1] >= '5' && '9' != c)
				c++;
		}
		rbuf[0] = c < '5' ? '0' : '1';
	} else if (mbuf[pos] < '5') {
		/* Nothing to round, copy truncated mantissa, leading carry is '0' */
		rbuf[0] = '0';
		clamp_memcpy(&rbuf[1], rlen - 1, mbuf, pos);
	} else {
		const char *p = &mbuf[pos - 1];
		char *q = &rbuf[pos];
		size_t n = pos - 1;

		do {
			char c = *p--;
			if ('9' == c) {
				*q-- = '0';
			} else {
				*q-- = c + 1;
				break;				/* No more carry over */
			}
		} while (n--);

		g_assert(ptr_cmp(p + 1, mbuf) >= 0);		/* No underflow */
		g_assert(ptr_cmp(q + 1, rbuf) >= 0);

		if (size_is_non_negative(n)) {
			/* Broken up from loop without carrying over till the end */
			rbuf[0] = '0';
			clamp_memcpy(&rbuf[1], rlen - 1, mbuf, n);	/* Leading mantissa */
		} else {
			g_assert(0 == ptr_cmp(q, rbuf));
			rbuf[0] = '1';
		}
	}

	if G_UNLIKELY(format_verbose) {
		s_debug("%s(): m=\"%.*s\" (len=%zu), pos=%zu, r=\"%.*s\" (len=%zu)",
			G_STRFUNC, (int) mlen, mbuf, mlen, pos,
			(int) pos + 1, rbuf, pos + 1);
	}

	return pos + 1;		/* Includes extra leading carry digit */
}

/*
 * The following are used to minimize the amount of code changes done to
 * str_vncatf(), which comes from Perl sources.
 */

#define bool			int
#define BIT_DIGITS(n)	(((n)*146)/485 + 1)			/* log2(10) =~ 146/485 */
#define TYPE_DIGITS(t)	BIT_DIGITS(sizeof(t) * 8)

/**
 * Append to string the variable formatted argument list, just like sprintf()
 * would, but avoiding the need of computing a suitable buffer size for the
 * output...
 *
 * Formatting is constrained by the specified amount of chars, and the routine
 * returns the amount of chars physically appended to the string.
 *
 * When formatting into a string with a foreign pointer (which cannot be
 * resized), the output is truncated if there is not enough space left in
 * the string buffer.
 *
 * This routine can be safely called from a signal handler provided the
 * string is a foreign buffer.
 *
 * Adpated from Perl 5.004_04 by Raphael Manfredi:
 *
 * - use str_t intead of SV, removing Perlism such as %_ and %V.
 * - added the `maxlen' constraint and handling of "foreign" strings.
 * - added the %' formatting directive to group integers by thousands.
 * - added native floating point formatting.
 *
 * Here are the supported universally-known conversions:
 *
 * %%   a percent sign
 * %c   a character with the given number
 * %s   a string
 * %d   a signed integer, in decimal
 * %u   an unsigned integer, in decimal
 * %o   an unsigned integer, in octal
 * %x   an unsigned integer, in hexadecimal
 * %e   a floating-point number, in scientific notation
 * %f   a floating-point number, in fixed decimal notation
 * %g   a floating-point number, in %e or %f notation
 *
 * The routine also allows the following widely-supported conversions:
 *
 * %X   like %x, but using upper-case letters
 * %E   like %e, but using an upper-case "E"
 * %G   like %g, but with an upper-case "E" (if applicable)
 * %p   a pointer (outputs the value's address in lower-cased hexadecimal)
 * %n   special: *stores* the number of characters output so far
 *      into the next variable in the parameter list
 *
 * The routine understands the following extensions, correctly parsed by gcc:
 *
 * %m   replaced by symbolic errno value + message: "EIO (I/O error)"
 *
 * Finally, for backward compatibility, the following unnecessary but
 * widely-supported conversions are allowed:
 *
 * %i   a synonym for %d
 * %D   a synonym for %ld
 * %U   a synonym for %lu
 * %O   a synonym for %lo
 * %F   a synonym for %f
 *
 * The routine permits the following universally-known flags between the
 * % and the conversion letter:
 *
 * space    prefix positive number with a space
 * +        prefix positive number with a plus sign
 * -        left-justify within the field
 * 0        use zeros, not spaces, to right-justify
 * #        prefix octal with "0", hex with "0x"
 * '        use thousands groupping in decimal integers with ","
 * number   minimum field width
 * .number  precision: digits after decimal point for floating-point,
 *          max length for string, minimum length for integer
 * l        interpret integer as C type "long" or "unsigned long"
 * h        interpret integer as C type "short" or "unsigned short"
 * z        interpret integer as C type "size_t" or "ssize_t"
 *
 * Where a number would appear in the flags, an asterisk ("*") may be
 * instead, in which case the routine uses the next item in the parameter
 * list as the given number (that is, as the field width or precision).
 * If a field width obtained through "*" is negative, it has the same effect
 * as the '-' flag: left-justification.
 */
size_t
str_vncatf(str_t *str, size_t maxlen, const char *fmt, va_list args)
{
	static const char nullstr[] = "(null)";
	const char *f;
	const char *q;
	char *p;
	const char *fmtend;
	size_t fmtlen;
	size_t origlen;
	size_t remain = maxlen;

	str_check(str);
	g_assert(size_is_non_negative(maxlen));
	g_assert(fmt != NULL);

	fmtlen = strlen(fmt);
	origlen = str->s_len;

	/*
	 * Special-case "" and "%s".
	 */

	if G_UNLIKELY(0 == fmtlen)
		return 0;

	if G_UNLIKELY(2 == fmtlen && fmt[0] == '%' && fmt[1] == 's') {
		const char *s = va_arg(args, char*);
		size_t len;
		s = s ? s : nullstr;
		len = strlen(s);
		if (!str_ncat_safe(str, s, len > maxlen ? maxlen : len) || len > maxlen)
			goto clamped;
		goto done;
	}

	/*
	 * Clamp available space for foreign strings, which cannot be resized.
	 *
	 * We still allow calls to str_makeroom() on such strings though, because
	 * it will be allowed to proceed if it does not try to exceed the size
	 * of the foreign buffer, so we use that as assertions that our logic
	 * is correct.
	 *
	 * However, this routine uses str_ncat_safe() instead of str_ncat()
	 * to be able to truncate the output if there is not enough space.
	 */

	if G_UNLIKELY(str->s_flags & STR_FOREIGN_PTR) {
		size_t avail = str->s_size - str->s_len;
		if G_UNLIKELY(0 == avail)
			goto clamped;
		avail--;					/* Leave room for trailing NUL */
		remain = MIN(maxlen, avail);
	}

#define STR_APPEND(x, l) \
G_STMT_START {									\
	if G_UNLIKELY((l) > remain) {				\
		str_ncat_safe(str, (x), remain);		\
		goto clamped;	/* Reached maxlen */	\
	} else {									\
		if (!str_ncat_safe(str, (x), (l))) 		\
			goto clamped;	/* Full! */			\
		remain -= (l);							\
	}											\
} G_STMT_END

	/*
	 * Here we go, process the whole format string.
	 */

	fmtend = fmt + fmtlen;

	for (f = fmt; f < fmtend; f = q) {
		bool alt = FALSE;
		bool left = FALSE;
		bool group = FALSE;
		char fill = ' ';
		char plus = 0;
		char intsize = 0;
		size_t width = 0;
		size_t zeros = 0;
		size_t ezeros = 0;		/* Trailing mantissa zero in %e form */
		size_t dzeros = 0;		/* Trailing zeros before dot */
		size_t azeros = 0;		/* After-dot zeros, before value */
		size_t fzeros = 0;		/* Trailing filling zeros */
		size_t dot = 0;
		bool has_precis = FALSE;
		size_t precis = 0;
		size_t digits = 0;

		char esignbuf[4];
		int esignlen = 0;

		char expbuf[6];
		int explen = 0;

		const char *eptr = NULL;
		const char *expptr = NULL;
		char *mptr;
		size_t elen = 0;
		char ebuf[TYPE_DIGITS(long) * 2 + 16]; /* large enough for "%#.#f" */

		char c;
		unsigned base;
		long iv;
		unsigned long uv;
		double nv;
		size_t have;
		size_t need;
		size_t gap;

		g_assert(size_is_non_negative(remain));

		for (q = f; q < fmtend && *q != '%'; q++) ;

		if (q > f) {
			size_t len = q - f;
			STR_APPEND(f, len);
			f = q;
		}
		if (q++ >= fmtend)
			break;

		/* FLAGS */

		while (*q) {
			switch (*q) {
			case ' ':
			case '+':
				plus = *q++;
				continue;

			case '-':
				left = TRUE;
				q++;
				continue;

			case '0':
				fill = *q++;
				continue;

			case '#':
				alt = TRUE;
				q++;
				continue;

			case '\'':
				group = TRUE;
				q++;
				continue;

			default:
				break;
			}
			break;
		}

		/* WIDTH */

		switch (*q) {
		case '1': case '2': case '3':
		case '4': case '5': case '6':
		case '7': case '8': case '9':
			width = 0;
			while (is_ascii_digit(*q)) {
				width = size_saturate_mult(width, 10);
				width = size_saturate_add(width, *q++ - '0');
			}
			break;

		case '*':
			{
				int i = va_arg(args, int);
				left |= (i < 0);
				width = (i < 0) ? -UNSIGNED(i) : UNSIGNED(i);
				q++;
			}
			break;
		}

		/* PRECISION */

		if (*q == '.') {
			q++;
			if (*q == '*') {
				int i = va_arg(args, int);
				precis = (i < 0) ? 0 : i;
				q++;
			} else {
				precis = 0;
				while (is_ascii_digit(*q)) {
					precis = size_saturate_mult(precis, 10);
					precis = size_saturate_add(precis, *q++ - '0');
				}
			}
			has_precis = TRUE;
		}

		/* SIZE */

		switch (*q) {
		case 'l':
			/* FALL THROUGH */
		case 'h':
			/* FALL THROUGH */
		case 'z':
			intsize = *q++;
			break;
		}

		/* CONVERSION */

		switch (c = *q++) {

			/* STRINGS */

		case '%':
			eptr = q - 1;
			elen = 1;
			goto string;

		case 'c':
			c = va_arg(args, int) & MAX_INT_VAL(unsigned char);
			eptr = &c;
			elen = 1;
			goto string;

		case 'm':
			{
				const char *e = symbolic_errno(errno);
				const char *s = g_strerror(errno);
				size_t len;

				len = strlen(e);
				STR_APPEND(e, len);
				STR_APPEND(" (", 2);
				len = strlen(s);
				STR_APPEND(s, len);
				STR_APPEND(")", 1);
			}
			continue;

		case 's':
			eptr = va_arg(args, char*);
			if (NULL == eptr)
				eptr = nullstr;
			if (has_precis) {
				/* String may not be NUL-terminated */
				elen = clamp_strlen(eptr, precis);
			} else {
				elen = strlen(eptr);
			}
			/* FALL THROUGH */

		string:
			if (has_precis && elen > precis)
				elen = precis;
			break;

			/* INTEGERS */

		case 'p':
			uv = (unsigned long) va_arg(args, void*);
			base = 16;
			c = 'x';		/* Request lower-cased pointer */
			alt = TRUE;		/* Request leading "0x" */
			goto integer;

		case 'D':
			intsize = 'l';
			/* FALL THROUGH */
		case 'd':
		case 'i':
			switch (intsize) {
			case 'h':		iv = (short) va_arg(args, int); break;
			case 'l':		iv = va_arg(args, long); break;
			case 'z':		iv = va_arg(args, ssize_t); break;
			default:		iv = va_arg(args, int); break;
			}
			if (iv >= 0) {
				uv = iv;
				if (plus)
					esignbuf[esignlen++] = plus;
			}
			else {
				uv = -iv;
				esignbuf[esignlen++] = '-';
			}
			base = 10;
			goto integer;

		case 'U':
			intsize = 'l';
			/* FALL THROUGH */
		case 'u':
			base = 10;
			goto uns_integer;

		case 'O':
			intsize = 'l';
			/* FALL THROUGH */
		case 'o':
			base = 8;
			goto uns_integer;

		case 'X':
		case 'x':
			base = 16;
			/* FALL THROUGH */

		uns_integer:
			switch (intsize) {
			case 'h':  uv = (unsigned short) va_arg(args, unsigned); break;
			case 'l':  uv = va_arg(args, unsigned long); break;
			case 'z':  uv = va_arg(args, size_t); break;
			default:   uv = va_arg(args, unsigned); break;
			}

		/* FALL THROUGH */

		integer:
			mptr = ebuf + sizeof ebuf;
			switch (base) {
				unsigned dig;
				const char *hex;
			case 16:
				hex = (c == 'X') ? "0123456789ABCDEF" : "0123456789abcdef";
				do {
					dig = uv & 15;
					*--mptr = hex[dig];
				} while (uv >>= 4);
				if (alt) {
					esignbuf[esignlen++] = '0';
					esignbuf[esignlen++] = c;  /* 'x' or 'X' */
				}
				break;
			case 8:
				do {
					dig = uv & 7;
					*--mptr = '0' + dig;
				} while (uv >>= 3);
				if (alt && *mptr != '0')
					*--mptr = '0';
				break;
			case 10:
				if G_UNLIKELY(group) {
					/* Highlight thousands groups with "," */
					unsigned d = 0;
					do {
						dig = uv % base;
						if (0 == d++ % 3 && d != 1)
							*--mptr = ',';
						*--mptr = '0' + dig;
					} while (uv /= base);
				} else {
					do {
						dig = uv % base;
						*--mptr = '0' + dig;
					} while (uv /= base);
				}
				break;
			default:
				g_assert_not_reached();
				break;
			}
			eptr = mptr;
			elen = (ebuf + sizeof ebuf) - eptr;
			if (has_precis && precis > elen)
				zeros = precis - elen;
			break;

			/* FLOATING POINT */

		case 'F':
			c = 'f';			/* maybe %F isn't supported here */
			/* FALL THROUGH */
		case 'e': case 'E':
		case 'f':
		case 'g': case 'G':

			nv = va_arg(args, double);

			/*
			 * Adjust precision: it's 6 by default.
			 *
			 * For %g, the precision is the number of digits displayed, whereas
			 * for %e it's the number of digits after the decimal point.
			 */

			if (!has_precis)
				precis = 6;

			if ('g' == c || 'G' == c) {
				digits = MAX(1, precis);	/* Non-zero, flags %g or %G */
				precis = (0 == precis) ? 0 : precis - 1;
			}

			/*
			 * Ensure nv is a valid number, and not NaN, +Inf or -Inf
			 * before calling the formatting routine.
			 */

			mptr = ebuf + sizeof ebuf;

			switch (fpclassify(nv)) {
			case FP_NAN:
				if (is_ascii_upper(c)) {
					elen = 4;
					eptr = "NAN*";
				} else {
					elen = 3;
					eptr = "nan";
				}
				break;
			case FP_INFINITE:
				mptr -= 3;
				clamp_memcpy(mptr, 3, is_ascii_upper(c) ? "INF" : "inf", 3);
				if (nv < 0)
					*--mptr = '-';
				else if (plus)
					*--mptr = plus;
				eptr = mptr;
				elen = (ebuf + sizeof ebuf) - eptr;
				break;
			default:
				{
					int e;
					char m[32], r[33];
					size_t mlen, rlen, asked;

					if (nv >= 0) {
						if (plus)
							esignbuf[esignlen++] = plus;
					} else {
						nv = -nv;
						esignbuf[esignlen++] = '-';
					}

					/*
					 * We cap the precision at FPREC since this is the maximum
					 * supported by 64-bit IEEE numbers with a 52-bit mantissa.
					 */

					asked = digits ? MIN(FPREC, digits) : MIN(FPREC, precis);
					if (!digits)
						asked++;
					if ('f' == c || 'F' == c)
						asked = FPREC;		/* Will do rounding ourselves */

					/*
					 * Format the floating point number, separating the
					 * mantissa and the exponent.
					 *
					 * The returned values are such that one presentation
					 * of the number would be the output of:
					 *
					 *		printf("0.%se%d", m, e + 1);
					 */

					mlen = float_fixed(m, sizeof m, nv, asked, &e);

					g_assert(size_is_positive(mlen));
					g_assert(mlen < sizeof m);

					if G_UNLIKELY(format_verbose) {
						char buf[150];
						gm_snprintf(buf, sizeof buf,
							"%g with \"%%%c\": m=\"%.*s\" "
							"(len=%zu, asked=%zu), e=%d "
							"[precis=%zu, digits=%zu]",
							nv, c, (int) mlen, m, mlen, asked,
							e, precis, digits);
						s_debug("%s", buf);
					}

					/*
					 * %g is turned into %e (and %G to %E) when the exponent
					 * is less than -4 or when it is greater than or equal
					 * to the precision.
					 */

					if ('g' == c || 'G' == c) {
						if (e < -4 || e >= (int) precis + 1)
							c = ('g' == c) ? 'e' : 'E';
					}

					if ('e' == c || 'E' == c) {
						size_t v;
						size_t start;
						bool non_zero;

						/* Exponent */

						mptr = expbuf + sizeof expbuf;

						v = (e >= 0) ? e : -e;
						do {
							unsigned dig = v % 10;
							*--mptr = '0' + dig;
						} while (v /= 10);
						v = (e >= 0) ? e : -e;
						if (v < 10)
							*--mptr = '0';
						*--mptr = (e >= 0) ? '+' : '-';
						*--mptr = is_ascii_upper(c) ? 'E' : 'e';

						g_assert(ptr_cmp(mptr, expbuf) >= 0);

						expptr = mptr;
						explen = (expbuf + sizeof expbuf) - expptr;

						/* Mantissa */

						mptr = ebuf + sizeof ebuf;

						v = precis + 1;
						v = MIN(mlen, v);
						start = v; 			/* Starting index */
						non_zero = 0 == digits;

						rlen = str_fround(m, mlen, v, r, sizeof r);

						do {
							if (1 == v && start != 1)
								*--mptr = '.';
							if (r[v] != '0')
								non_zero = TRUE;
							if (1 == v || non_zero)
								*--mptr = r[v];
						} while (--v);

						/* Trailing mantissa zeros if %e or %E */
						if (mlen < precis && !digits)
							ezeros = precis - mlen;

					} else {
						size_t i;
						char *t;
						size_t d;	/* Dot position */

						/* %f or %F -- THE FUN BEGINS! */

						if (e < 0) {
							size_t v = -e;
							size_t z = v - 1;	/* Amount of zeros after dot */

							/* Formatted as 0.xxxx */

							if (z >= precis) {
								i = 0;
							} else {
								/* How many trailing zeros? */
								if (precis > z + mlen)
									fzeros = precis - z - mlen;

								i = precis - z;
								i = MIN(i, mlen);
							}

							/* How many after-dot zeros? (0.000xxx) */
							if (z != 0) {
								azeros = z;
								dot = 1;
								dzeros = 1;		/* Will emit "0." later */
							}

							/* Rounding for the precision digit */
							rlen = str_fround(m, mlen, i, r, sizeof r);

							/* Remove one leading zero due to rounding carry */
							if (azeros != 0)
								azeros--;

							/* Don't emit if we're down to printing 0.0 */
							if (0 == azeros || azeros < precis) {
								/* Compute position of digital dot */
								d = azeros ? 0 : 1;
								for (i = rlen, t = r + rlen; i > 0;) {
									*--mptr = *--t;
									if (--i == d) {
										/* Leading "0.0" done later?*/
										if (0 != azeros)
											break;
										/* No, emit now */
										*--mptr = '.';
										*--mptr = *--t;
										i--;
									}
								}
							}
						} else {
							unsigned v = e;

							if (v < mlen) {
								size_t subdot;
								bool has_non_zero;

								/* Formatted as y.xxxx with y >= 0 */

								d = e + 1;	/* Dot position */

								if (digits) {
									/* Formatting from %g or %G */
									has_non_zero = FALSE;
									subdot = digits > d ? digits - d : 0;
								} else {
									subdot = precis;
									has_non_zero = TRUE;
								}

								/* Rounding for the precision digit */
								i = d + subdot;		/* First excluded */
								i = MIN(i, mlen);

								/* Trailing floating zeros to emit */
								if (i < precis)
									fzeros = precis - i;

								rlen = str_fround(m, mlen, i, r, sizeof r);

								i = rlen - 1;
								d++;		/* Extra carry digit in r[] */

								do {
									/* No leading zero carry? */
									if (0 == i && i < d - 1 && '0' == r[0])
										break;
									/* Skip trailing zeros if %g or %G */
									if (digits && i >= d) {
										if (r[i] != '0') {
											*--mptr = r[i];
											has_non_zero = TRUE;
										}
									} else {
										*--mptr = r[i];
									}
									if (i == d && has_non_zero)
										*--mptr = '.';
								} while (i--);
							} else {
								size_t x = e - mlen + 1;	/* Extra 10s */
								size_t subdot;

								if (digits) {
									/* Formatting from %g or %G */
									subdot = precis > v ? precis - v : 0;
								} else {
									subdot = precis;
								}

								dzeros = x; /* Zeros before the decimal point */
								dot = (0 == subdot) ? 0 : 1; /* Emit a dot? */
								fzeros = subdot;	/* Zeros after the dot */

								g_assert(mlen <= sizeof ebuf);

								mptr -= mlen;
								memcpy(mptr, m, mlen);
							}
						}
					}
				}
				g_assert(ptr_cmp(mptr, ebuf) >= 0);		/* No underflow */
				eptr = mptr;
				elen = (ebuf + sizeof ebuf) - eptr;

				if G_UNLIKELY(format_verbose) {
					char buf[150];
					gm_snprintf(buf, sizeof buf,
						"%g as \"%%%c\": elen=%zu, eptr=\"%.*s\", "
						"expptr=\"%.*s\", dot=%s, zeros<e=%zu, d=%zu, "
						"a=%zu, f=%zu>",
						nv, c, elen, (int) elen, eptr, explen, expptr,
						dot ? "y" : "n", ezeros, dzeros, azeros, fzeros);
					s_debug("%s", buf);
				}
				break;
			}
			break;

			/* SPECIAL */

		case 'n':
			{
				size_t n = str->s_len - origlen;
				switch (intsize) {
				case 'h': *(va_arg(args, short*)) = MIN(n, SHRT_MAX); break;
				case 'l': *(va_arg(args, long*)) = MIN(n, LONG_MAX); break;
				case 'z': *(va_arg(args, ssize_t*)) = MIN(n, SSIZE_MAX); break;
				default:  *(va_arg(args, int*)) = MIN(n, INT_MAX); break;
				}
			}
			continue;	/* not "break" */

			/* UNKNOWN */

		default:
			if (c) {
				s_minicarp("%s(): invalid conversion \"%%%c\"",
					G_STRFUNC, c & 0xff);
			} else {
				s_minicarp("%s(): invalid end of string", G_STRFUNC);
			}

			/* output mangled stuff ... */
			if (c == '\0')
				--q;
			eptr = f;
			elen = q - f;

			/* ... right here, because formatting flags should not apply */
			STR_APPEND(eptr, elen);
			continue;	/* not "break" */
		}

		have = esignlen + zeros + elen +
			/* Floating-point specific formatting */
			ezeros + explen + dzeros + dot + azeros + fzeros;

		need = (have > width ? have : width);
		gap = need - have;

		/*
		 * Now, append item inside string, mangling freely with str_t
		 * internals for efficient appending...
		 *
		 * It would be very inefficient to check for maxlen before appending
		 * each char, so that check is performed once and for all at the
		 * beginning, and only when we do need to be careful do we check
		 * more precisely.
		 */

		if (remain <= need)				/* Cannot fit entirely */
			goto careful;

		/*
		 * CAUTION: code duplication with "careful" below. Any change made
		 * here NEEDS TO BE REPORTED to the next section.
		 */

		str_makeroom(str, need);		/* we do not NUL terminate it */
		p = str->s_data + str->s_len;	/* next "free" char in arena */
		if (esignlen && fill == '0') {
			memcpy(p, esignbuf, esignlen);
			p += esignlen;
		}
		if (gap && !left) {
			memset(p, fill, gap);
			p += gap;
		}
		if (esignlen && fill != '0') {
			memcpy(p, esignbuf, esignlen);
			p += esignlen;
		}
		if (zeros) {
			memset(p, '0', zeros);
			p += zeros;
		}
		if (elen && 0 == azeros) {
			memcpy(p, eptr, elen);
			p += elen;
		}
		if (ezeros) {
			memset(p, '0', ezeros);
			p += ezeros;
		}
		if (explen) {
			memcpy(p, expptr, explen);
			p += explen;
		}
		if (dzeros) {
			memset(p, '0', dzeros);
			p += dzeros;
		}
		if (dot) {
			*p++ = '.';
		}
		if (azeros) {
			memset(p, '0', azeros);
			p += azeros;
		}
		if (elen && 0 != azeros) {
			memcpy(p, eptr, elen);
			p += elen;
		}
		if (fzeros) {
			memset(p, '0', fzeros);
			p += fzeros;
		}
		if (gap && left) {
			memset(p, ' ', gap);
			p += gap;
		}
		str->s_len = p - str->s_data;	/* trailing NUL does not count */
		remain -= need;
		continue;

	careful:
		/*
		 * Have to be careful, because current field will be only partially
		 * printed (remain is less or equal to the amount of chars we need).
		 * In particular, one cannot expect the trailing NUL char to be
		 * present in the string.
		 *
		 * CAUTION: code duplication with previous section. Any change made
		 * to code here MAY NEED TO BE REPORTED to the above section.
		 */

		str_makeroom(str, remain);			/* we do not NUL terminate it */
		p = str->s_data + str->s_len;		/* next "free" char in arena */
		str->s_len += remain;				/* know how much we'll append */
		q = p + remain;						/* first char past limit */
		if (esignlen && fill == '0') {
			p += clamp_memcpy(p, q - p, esignbuf, esignlen);
			if (p >= q)
				goto clamped;
			remain -= esignlen;
		}
		if (gap && !left) {
			p += clamp_memset(p, q - p, fill, gap);
			if (p >= q)
				goto clamped;
			remain -= gap;
		}
		if (esignlen && fill != '0') {
			p += clamp_memcpy(p, q - p, esignbuf, esignlen);
			if (p >= q)
				goto clamped;
			remain -= esignlen;
		}
		if (zeros) {
			p += clamp_memset(p, q - p, '0', zeros);
			if (p >= q)
				goto clamped;
			remain -= zeros;
		}
		if (elen && 0 == azeros) {
			p += clamp_memcpy(p, q - p, eptr, elen);
			if (p >= q)
				goto clamped;
			remain -= elen;
		}
		if (ezeros) {
			p += clamp_memset(p, q - p, '0', ezeros);
			if (p >= q)
				goto clamped;
			remain -= ezeros;
		}
		if (explen) {
			p += clamp_memcpy(p, q - p, expptr, explen);
			if (p >= q)
				goto clamped;
			remain -= explen;
		}
		if (dzeros) {
			p += clamp_memset(p, q - p, '0', dzeros);
			if (p >= q)
				goto clamped;
			remain -= dzeros;
		}
		if (dot) {
			if (0 == remain)
				goto clamped;
			*p++ = '.';
			remain--;
		}
		if (azeros) {
			p += clamp_memset(p, q - p, '0', azeros);
			if (p >= q)
				goto clamped;
			remain -= azeros;
		}
		if (elen && 0 != azeros) {
			p += clamp_memcpy(p, q - p, eptr, elen);
			if (p >= q)
				goto clamped;
			remain -= elen;
		}
		if (fzeros) {
			p += clamp_memset(p, q - p, '0', fzeros);
			if (p >= q)
				goto clamped;
			remain -= fzeros;
		}
		if (gap && left) {
			p += clamp_memset(p, q - p, ' ', gap);
			if (p >= q)
				goto clamped;
			remain -= gap;
		}

		/*
		 * At this point, `remain' can only be zero anyway.
		 */

		g_assert(0 == remain);

		break;
	}

done:
	return str->s_len - origlen;

clamped:
	{
		static gboolean recursion;

		/*
		 * This routine MUST be recursion-safe since it is used indirectly
		 * by s_minicarp() through the str_vprintf() call and we're about
		 * to call the former now!
		 */

		if (!recursion && tests_completed) {
			recursion = TRUE;
			s_minicarp("truncated output within %zu-byte buffer "
				"(%zu max, %zu written, %zu available) with \"%s\"",
				str->s_size, maxlen, str->s_len - origlen,
				str->s_size - str->s_len, fmt);
			recursion = FALSE;
		}
	}

	return str->s_len - origlen;

#undef STR_APPEND
}

/*
 * The following are convenience wrappers to str_vncatf(), by increasing
 * order of sophistication, more or less.
 */

/**
 * Append to string the variable formatted argument list, just like sprintf().
 * @return the amount of formatted chars.
 */
size_t
str_vcatf(str_t *str, const char *fmt, va_list args)
{
	return str_vncatf(str, INT_MAX, fmt, args);
}

/**
 * Like str_vcatf(), but resets the string first.
 * @return the amount of formatted chars.
 */
size_t
str_vprintf(str_t *str, const char *fmt, va_list args)
{
	str_check(str);

	str->s_len = 0;
	return str_vncatf(str, INT_MAX, fmt, args);
}

/**
 * Append result of "printf(fmt, ...)" to string.
 * @return the amount of formatted chars.
 */
size_t
str_catf(str_t *str, const char *fmt, ...)
{
	va_list args;
	size_t formatted;

	va_start(args, fmt);
	formatted = str_vncatf(str, INT_MAX, fmt, args);
	va_end(args);

	return formatted;
}

/**
 * Append result of "nprintf(fmt, ...)" to string.
 * @return the amount of formatted chars.
 */
size_t
str_ncatf(str_t *str, size_t n, const char *fmt, ...)
{
	va_list args;
	size_t formatted;

	va_start(args, fmt);
	formatted = str_vncatf(str, n, fmt, args);
	va_end(args);

	return formatted;
}

/**
 * A regular sprintf() without fear of buffer overflow...
 * @return the amount of formatted chars.
 */
size_t
str_printf(str_t *str, const char *fmt, ...)
{
	va_list args;
	size_t formatted;

	str_check(str);

	str->s_len = 0;

	va_start(args, fmt);
	formatted = str_vncatf(str, INT_MAX, fmt, args);
	va_end(args);

	return formatted;
}

/**
 * Like str_printf(), but formats at most `n' characters.
 * @return the amount of formatted chars.
 */
size_t
str_nprintf(str_t *str, size_t n, const char *fmt, ...)
{
	va_list args;
	size_t formatted;

	str_check(str);

	str->s_len = 0;

	va_start(args, fmt);
	formatted = str_vncatf(str, n, fmt, args);
	va_end(args);

	return formatted;
}

/**
 * Create a new string, and sprintf() the arguments inside.
 * @return the new string item, which may be disposed of with str_destroy().
 */
str_t *
str_msg(const char *fmt, ...)
{
	str_t *str;
	va_list args;

	str = str_new(0);

	va_start(args, fmt);
	str_vncatf(str, INT_MAX, fmt, args); /* We know length is 0 */
	va_end(args);

	str_resize(str, str->s_len + 1);	/* Allow for possible trailing NUL */

	return str;
}

/**
 * sprintf() the arguments inside a dynamic string and return the result in a
 * freshly allocated C string, which needs to be disposed of by hfree().
 */
char *
str_vcmsg(const char *fmt, va_list args)
{
	static str_t *str;
	
	if G_UNLIKELY(NULL == str)
		str = str_new_not_leaking(0);

	str->s_len = 0;
	str_vncatf(str, INT_MAX, fmt, args);

	return str_dup(str);
}

/**
 * sprintf() the arguments inside a dynamic string and return the result in a
 * freshly allocated C string, which needs to be disposed of by hfree().
 */
char *
str_cmsg(const char *fmt, ...)
{
	static str_t *str;
	va_list args;
	
	if G_UNLIKELY(NULL == str)
		str = str_new_not_leaking(0);

	str->s_len = 0;
	va_start(args, fmt);
	str_vncatf(str, INT_MAX, fmt, args);
	va_end(args);

	return str_dup(str);
}

/**
 * sprintf() the arguments inside a static string and return a C string.
 *
 * This string must not be disposed of, as it is held in a static buffer
 * which will be reset upon next call.  It needs to be duplicated if meant to
 * be perused later.
 */
const char *
str_smsg(const char *fmt, ...)
{
	static str_t *str;
	va_list args;
	
	if G_UNLIKELY(NULL == str)
		str = str_new_not_leaking(0);

	str->s_len = 0;
	va_start(args, fmt);
	str_vncatf(str, INT_MAX, fmt, args);
	va_end(args);

	return str_2c(str);
}

/**
 * Same as str_smsg(), but in a different string.
 */
const char *
str_smsg2(const char *fmt, ...)
{
	static str_t *str;
	va_list args;
	
	if G_UNLIKELY(NULL == str)
		str = str_new_not_leaking(0);

	str->s_len = 0;
	va_start(args, fmt);
	str_vncatf(str, INT_MAX, fmt, args);
	va_end(args);

	return str_2c(str);
}

/**
 * A regular sprintf() into a fix sized buffer without fear of overflow...
 * @return the amount of formatted chars.
 */
size_t
str_bprintf(char *dst, size_t size, const char *fmt, ...)
{
	str_t str;
	va_list args;
	size_t formatted;

	str_from_foreign(&str, dst, 0, size);

	va_start(args, fmt);
	formatted = str_vncatf(&str, size - 1, fmt, args);
	va_end(args);

	str_putc(&str, '\0');

	return formatted;
}

/**
 * A regular vsprintf() into a fix sized buffer without fear of overflow...
 * @return the amount of formatted chars.
 */
size_t
str_vbprintf(char *dst, size_t size, const char *fmt, va_list args)
{
	str_t str;
	size_t formatted;

	str_from_foreign(&str, dst, 0, size);

	formatted = str_vncatf(&str, size - 1, fmt, args);
	str_putc(&str, '\0');

	return formatted;
}

/***
 *** Non-regression tests for str_vncatf().
 ***/

/**
 * str_bprintf() without any format argument checking, for testing purposes.
 */
static void
str_tprintf(char *dst, size_t size, const char *fmt, ...)
{
	str_t str;
	va_list args;

	str_from_foreign(&str, dst, 0, size);

	va_start(args, fmt);
	str_vncatf(&str, size - 1, fmt, args);
	va_end(args);

	str_putc(&str, '\0');
}

/**
 * Non-regression tests for the str_vncatf() formatting routine.
 */
G_GNUC_COLD void
str_test(void)
{
#define MLEN		64
#define DEADBEEF	((void *) 0xdeadbeef)
#define INTEGER		345000
#define LONG		345000L
#define PI			3.141592654
#define DOUBLE		3.45e8
#define LN2			0.69314718056
#define INF			HUGE_VAL

	static const char ANYTHING[] = "anything";
	static const char INTSTR[] = "345000";
	static const char INThex[] = "543a8";
	static const char INTHEX[] = "543A8";
	static const struct tstring {
		const char *fmt;
		size_t buflen;
		const char *value;
		const char *result;
	} test_strings[] = {
		{ "",				10,		ANYTHING,		"" },
		{ "%%",				10,		ANYTHING,		"%" },
		{ "%s",				MLEN,	ANYTHING,		ANYTHING },
		{ "%s",				5,		ANYTHING,		"anyt" },
		{ "%.2s",			5,		ANYTHING,		"an" },
		{ "%.15s",			MLEN,	ANYTHING,		ANYTHING },
		{ "%15s",			MLEN,	ANYTHING,		"       anything" },
		{ "%15s",			9,		ANYTHING,		"       a" },
		{ "%-15s",			MLEN,	ANYTHING,		"anything       " },
		{ "%-15s.",			MLEN,	ANYTHING,		"anything       ." },
		{ "%015s.",			MLEN,	ANYTHING,		"0000000anything." },
		{ "%-5s",			MLEN,	ANYTHING,		ANYTHING },
		{ "%-5s.",			MLEN,	ANYTHING,		"anything." },
	};
	static const struct tpointer {
		const char *fmt;
		size_t buflen;
		void *value;
		const char *result;
	} test_pointers[] = {
		{ "%p",				MLEN,	DEADBEEF,		"0xdeadbeef" },
		{ "%p",				5,		DEADBEEF,		"0xde" },
	};
	static const struct tint {
		const char *fmt;
		size_t buflen;
		int value;
		const char *result;
	} test_ints[] = {
		{ "%d",				MLEN,	INTEGER,		INTSTR },
		{ "%x",				MLEN,	INTEGER,		INThex },
		{ "%X",				MLEN,	INTEGER,		INTHEX },
		{ "%x",				5,		INTEGER,		"543a" },
		{ "%#x",			5,		INTEGER,		"0x54" },
		{ "%#x",			MLEN,	INTEGER,		"0x543a8" },
		{ "%#X",			MLEN,	INTEGER,		"0X543A8" },
		{ "%.2d",			MLEN,	INTEGER,		INTSTR },
		{ "%2d",			MLEN,	INTEGER,		INTSTR },
		{ "%'d",			MLEN,	INTEGER,		"345,000" },
		{ "%-8d.",			MLEN,	INTEGER,		"345000  ." },
		{ "%-8d.",			MLEN,	INTEGER,		"345000  ." },
		{ "%8d",			MLEN,	INTEGER,		"  345000" },
		{ "%8d",			5,		INTEGER,		"  34" },
		{ "%d",				MLEN,	-INTEGER,		"-345000" },
		{ "%-8d.",			MLEN,	-INTEGER,		"-345000 ." },
		{ "%.08d",			MLEN,	INTEGER,		"00345000" },
	};
	static const struct tlong {
		const char *fmt;
		size_t buflen;
		long value;
		const char *result;
	} test_longs[] = {
		{ "%ld",			MLEN,	LONG,		INTSTR },
		{ "%lx",			MLEN,	LONG,		INThex },
		{ "%lX",			MLEN,	LONG,		INTHEX },
		{ "%lx",			5,		LONG,		"543a" },
		{ "%#lx",			5,		LONG,		"0x54" },
		{ "%#lx",			MLEN,	LONG,		"0x543a8" },
		{ "%#lX",			MLEN,	LONG,		"0X543A8" },
		{ "%.2ld",			MLEN,	LONG,		INTSTR },
		{ "%2ld",			MLEN,	LONG,		INTSTR },
		{ "%'d",			MLEN,	LONG,		"345,000" },
		{ "%-8ld.",			MLEN,	LONG,		"345000  ." },
		{ "%-8ld.",			MLEN,	LONG,		"345000  ." },
		{ "%8ld",			MLEN,	LONG,		"  345000" },
		{ "%8ld",			5,		LONG,		"  34" },
		{ "%ld",			MLEN,	-LONG,		"-345000" },
		{ "%-8ld.",			MLEN,	-LONG,		"-345000 ." },
		{ "%.08ld",			MLEN,	LONG,		"00345000" },
	};
	static const struct tdouble {
		const char *fmt;
		size_t buflen;
		double value;
		const char *result;
	} test_doubles[] = {
		/* #1 */
		{ "%g",				MLEN,	INF,		"inf" },
		{ "%G",				MLEN,	INF,		"INF" },
		{ "%g",				MLEN,	-INF,		"-inf" },
		{ "%G",				MLEN,	-INF,		"-INF" },
		{ "%f",				MLEN,	PI,			"3.141593" },
		{ "%g",				MLEN,	PI,			"3.14159" },
		{ "%.1g",			MLEN,	PI,			"3" },
		{ "%e",				MLEN,	PI,			"3.141593e+00" },
		{ "%e",				MLEN,	-PI,		"-3.141593e+00" },
		/* #10 */
		{ "%.2e",			MLEN,	-PI,		"-3.14e+00" },
		{ "%.2f",			MLEN,	-PI,		"-3.14" },
		{ "%8.2f",			MLEN,	-PI,		"   -3.14" },
		{ "%g",				MLEN,	DOUBLE,		"3.45e+08" },
		{ "%g",				MLEN,	-DOUBLE,	"-3.45e+08" },
		{ "%G",				MLEN,	DOUBLE,		"3.45E+08" },
		{ "%e",				MLEN,	DOUBLE,		"3.450000e+08" },
		{ "%E",				MLEN,	DOUBLE,		"3.450000E+08" },
		{ "%e",				MLEN,	LN2,		"6.931472e-01" },
		{ "%.0e",			MLEN,	LN2,		"7e-01" },
		/* #20 */
		{ "%.17f",			MLEN,	LN2,		"0.69314718056000002" },
		{ "%.0f",			MLEN,	LN2,		"1" },
		{ "%.1f",			MLEN,	LN2,		"0.7" },
		{ "%f",				MLEN,	LN2,		"0.693147" },
		{ "%.5f",			MLEN,	LN2,		"0.69315" },
		{ "%.5f",			5,		LN2,		"0.69" },
		{ "%f",				MLEN,	-LN2,		"-0.693147" },
		{ "%.5f",			MLEN,	-LN2,		"-0.69315" },
		{ "%.5f",			5,		-LN2,		"-0.6" },
		{ "%g",				MLEN,	5434e-9,	"5.434e-06" },
		/* #30 */
		{ "%g",				MLEN,	5434e-9,	"5.434e-06" },
		{ "%.2g",			MLEN,	5434e-9,	"5.4e-06" },
		{ "%.0g",			MLEN,	5434e-9,	"5e-06" },
		{ "%.14f",			MLEN,	5434e-9,	"0.00000543400000" },
		{ "%f",				MLEN,	1e-7,		"0.000000" },
		{ "%f",				MLEN,	9e-7,		"0.000001" },
		{ "%f",				MLEN,	5e-7,		"0.000001" },
		{ "%f",				MLEN,	4e-7,		"0.000000" },
		{ "%f",				MLEN,	4e-6,		"0.000004" },
		{ "%f",				MLEN,	9e-6,		"0.000009" },
		/* #40 */
		{ "%f",				MLEN,	94e-7,		"0.000009" },
		{ "%f",				MLEN,	95e-7,		"0.000010" },
		{ "%f",				MLEN,	150,		"150.000000" },
		{ "%.0f",			MLEN,	150,		"150" },
		{ "%.0f",			MLEN,	180,		"180" },
		{ "%g",				MLEN,	150,		"150" },
		{ "%e",				MLEN,	150,		"1.500000e+02" },
		{ "%.15e",			MLEN,	150,		"1.500000000000000e+02" },
		{ "%.0e",			MLEN,	150,		"2e+02" },
		{ "%.0e",			MLEN,	180,		"2e+02" },
		/* #50 */
		{ "%.0e",			MLEN,	140,		"1e+02" },
		{ "%.0e",			MLEN,	149,		"1e+02" },
		{ "%.0e",			MLEN,	151,		"2e+02" },
		{ "%g",				MLEN,	15000,		"15000" },
		{ "%g",				MLEN,	15000.4,	"15000.4" },
		{ "%.10e",			MLEN,	150000.04,	"1.5000004000e+05" },
		{ "%.0f",			MLEN,	15000.9,	"15001" },
		{ "%.0f",			MLEN,	0.899,		"1" },
		{ "%.1f",			MLEN,	0.899,		"0.9" },
		{ "%.3f",			MLEN,	0.899,		"0.899" },
		/* #60 */
		{ "%.2f",			MLEN,	0.899,		"0.90" },
		{ "%g",				MLEN,	150000,		"150000" },
		{ "%g",				MLEN,	1500000,	"1.5e+06" },
		{ "%g",				MLEN,	1.5e-200,	"1.5e-200" },
		{ "%+g",			MLEN,	1.5e200,	"+1.5e+200" },
		{ "%+g",			MLEN,	-1.5e200,	"-1.5e+200" },
		{ "%12g",			MLEN,	-1.5e200,	"   -1.5e+200" },
		{ "%-12g.",			MLEN,	-1.5e200,	"-1.5e+200   ." },
		{ "%-12g.",			MLEN,	-1.5e20,	"-1.5e+20    ." },
		{ "%-12g.",			MLEN,	-1.5e09,	"-1.5e+09    ." },
		/* #70 */
		{ "%-12g.",			MLEN,	-1.5e-09,	"-1.5e-09    ." },
		{ "%-12g.",			MLEN,	+1.5e-09,	"1.5e-09     ." },
		{ "%+12g",			MLEN,	+1.5e-09,	"    +1.5e-09" },
		{ "%.4g",			MLEN,	-1.5e200,	"-1.5e+200" },
		{ "%.5g",			MLEN,	15000,		"15000" },
		{ "%.4g",			MLEN,	15000,		"1.5e+04" },
		{ "%.0f",			MLEN,	2e+19,		"20000000000000000000" },
		{ "%.20g",			MLEN,	2e+19,		"20000000000000000000" },
		{ "%.51g",			MLEN,	2e+50,		"20000000000000002000000000"
												"0000000000000000000000000" },
		{ "%5.4f",			MLEN,	4561056.99,	"4561056.9900" },
		/* #80 */
		{ "%5.2f",			MLEN,	4561056.99,	"4561056.99" },
		{ "%5.1f",			MLEN,	4561056.99,	"4561057.0" },
		{ "%5.2f",			MLEN,	-61056.99,	"-61056.99" },
		{ "%5.1f",			MLEN,	-61056.99,	"-61057.0" },
	};

#define TEST(what) G_STMT_START {								\
	unsigned i;													\
																\
	for (i = 0; i < G_N_ELEMENTS(test_##what##s); i++) {		\
		char buf[MLEN];											\
		const struct t##what *t = &test_##what##s[i];			\
																\
		g_assert(sizeof buf >= t->buflen);						\
																\
		str_tprintf(buf, t->buflen, t->fmt, t->value);			\
																\
		if (0 != strcmp(buf, t->result) && !format_verbose) {	\
			/* Retry with debugging before crashing */			\
			format_verbose = TRUE;								\
			str_tprintf(buf, t->buflen, t->fmt, t->value);		\
		}														\
																\
		g_assert_log(0 == strcmp(buf, t->result),				\
			"%s test #%u/%zu fmt=\"%s\", len=%zu, "				\
			"returned=\"%s\", expected=\"%s\"",					\
			#what, i + 1, G_N_ELEMENTS(test_##what##s),			\
			t->fmt, t->buflen, buf, t->result);					\
	}															\
} G_STMT_END

	TEST(string);
	TEST(pointer);
	TEST(int);
	TEST(long);
	TEST(double);

	tests_completed = TRUE;		/* Allow warnings on truncations */

#undef MLEN
#undef TEST
#undef DEADBEEF
#undef INTEGER
#undef LONG
#undef PI
#undef DOUBLE
#undef LN2
}

/* vi: set ts=4 sw=4 cindent: */
