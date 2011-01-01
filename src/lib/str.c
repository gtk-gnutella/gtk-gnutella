/*
 * $Id$
 *
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

RCSID("$Id$")

#include <math.h>		/* For frexp() */

#include "ascii.h"
#include "str.h"
#include "glib-missing.h"
#include "misc.h"			/* For clamp_strcpy */
#include "halloc.h"
#include "unsigned.h"
#include "walloc.h"

#include "override.h"		/* Must be the last header included */

#define STR_DEFSIZE		64		/* Default string size */
#define STR_GROW		2		/* Grow factor, if size less than STR_MAXGROW */
#define STR_MAXGROW		4096	/* Above this size, increase by STR_CHUNK */
#define STR_CHUNK		4096	/* Size increase if above STR_MAXGROW */

enum str_magic { STR_MAGIC = 0x04ed2baa };

/**
 * A dynamic string. That string is not NUL-terminated and is expanded
 * as necessary. To get the final C version, a call to str_2c() is mandatory:
 * It ensures the string is NUL-terminated and returns a pointer to it.
 */
struct str {
	enum str_magic s_magic;
	guint32 s_flags;		/**< General flags */
	char *s_data;			/**< Where string data is held */
	size_t s_len;			/**< String length (amount of chars held) */
	size_t s_size;			/**< Size of the data arena */
};

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

	str = walloc(sizeof *str);
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

	if (str->s_data && !(str->s_flags & STR_FOREIGN_PTR))
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
 */
void
str_from_foreign(str_t *str, char *ptr, size_t len, size_t size)
{
	g_assert(str != NULL);

	str->s_magic = STR_MAGIC;
	str->s_flags = 0;
	str->s_data = NULL;
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

	str = walloc(sizeof *str);
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

	if (!(str->s_flags & STR_OBJECT))
		g_error("str_destroy() called on \"static\" string object");

	str_free(str);
	str->s_magic = 0;
	wfree(str, sizeof *str);
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

	if (str->s_flags & STR_FOREIGN_PTR) {
		if (str->s_size >= newsize)
			return;
		g_error("str_resize() would expand \"foreign\" string");
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

	return;
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

	if (s->s_size < n) {
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

	if (str->s_size >= size)
		return;					/* Nothing to do */

	if (str->s_flags & STR_FOREIGN_PTR)
		g_error("str_grow() called on \"foreign\" string");

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

	if (0 == len) {
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
 * Returns a pointer to the data, as a `C' string (NUL-terminated).
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

	if (NULL == str)
		return NULL;

	str_check(str);

	len = str->s_len;

	if (len == str->s_size)
		str_grow(str, len + 1);		/* Allow room for trailing NUL */

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

	if (!(str->s_flags & STR_OBJECT))
		g_error("str_s2c() called on \"static\" string object");

	if (str->s_flags & STR_FOREIGN_PTR)
		g_error("str_s2c() called on \"foreign\" string");

	len = str->s_len;

	str_resize(str, len + 1);		/* Ensure string fits neatly */
	cstr = str->s_data;
	cstr[len] = '\0';				/* Ensure trailing NUL for C */

	str->s_magic = 0;
	wfree(str, sizeof *str);

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
 * Returns pointer to the copied string location.
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

	if (0 == len)
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

	if (0 == len)
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
 * Discard first n bytes from string, shifting the remaining to the left and
 * adjusting the size.
 */
void
str_shift(str_t *str, size_t n)
{
	size_t len;

	str_check(str);
	g_assert(size_is_non_negative(n));

	if (0 == n)
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

	if (idx < 0 || (size_t) idx >= len)			/* Off string */
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

	if (0 == n)							/* Empty string */
		return TRUE;					/* Did nothing but nothing to do */

	if (idx < 0)						/* Stands for chars before end */
		idx += len;

	if (idx < 0 || (size_t) idx >= len)			/* Off string */
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

	if (!n)								/* Nothing to remove */
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

	if (idx < 0 || (size_t) idx >= len)			/* Off string */
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

	if (0 == len)
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
 * Wrapper over vsnprintf() to avoid GCC warning on the use of printf()
 * routines with a non-litteral string format buffer.
 *
 * Do NOT add a G_GNUC_PRINTF(3, 4) attribute for this routine.
 *
 * NOTE: this routine is only called to format floating point numbers from
 * within str_vncatf().
 */
static void
str_snprintf(char *dst, size_t size, const char *fmt, ...)
{
	va_list args;

	g_assert(dst != NULL);
	g_assert(fmt != NULL);

	va_start(args, fmt);

	/*
	 * Do not use gm_vsnprintf() here, because if vsnprintf() is missing,
	 * it could get back here as it relies on str_vncatf().
	 *
	 * Better avoid any overhead and directly call the routines we need.
	 */

#ifdef HAS_VSNPRINTF
	vsnprintf(dst, size, fmt, args);
#else
	{
		char *buf = g_strdup_vprintf(fmt, args);
		clamp_strcpy(dst, size, buf);
		G_FREE_NULL(buf);
	}
#endif	/* HAS_VSNPRINTF */

	va_end(args);
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
 * Adpated from Perl 5.004_04 by Raphael Manfredi to use str_t intead of SV,
 * removing Perlism such as %_ and %V. Also added the `maxlen' constraint.
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
 * The routine alos allows the following widely-supported conversions:
 *
 * %X   like %x, but using upper-case letters
 * %E   like %e, but using an upper-case "E"
 * %G   like %g, but with an upper-case "E" (if applicable)
 * %p   a pointer (outputs the value's address in hexadecimal)
 * %n   special: *stores* the number of characters output so far
 *      into the next variable in the parameter list
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
 * number   minimum field width
 * .number  precision: digits after decimal point for floating-point,
 *          max length for string, minimum length for integer
 * l        interpret integer as C type "long" or "unsigned long"
 * h        interpret integer as C type "short" or "unsigned short"
 *
 * Where a number would appear in the flags, an asterisk ("*") may be
 * instead, in which case the routine uses the next item in the parameter
 * list as the given number (that is, as the field width or precision).
 * If a field width obtained through "*" is negative, it has the same effect
 * as the '-' flag: left-justification.
 */
size_t
str_vncatf(str_t *str, size_t maxlen, const char *fmt, va_list *args)
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
	g_assert(args != NULL);

	fmtlen = strlen(fmt);
	origlen = str->s_len;

	/*
	 * Special-case "" and "%s".
	 */

	if (0 == fmtlen)
		return 0;

	if (2 == fmtlen && fmt[0] == '%' && fmt[1] == 's') {
		if (args) {
			const char *s = va_arg(*args, char*);
			size_t len;
			s = s ? s : nullstr;
			len = strlen(s);
			str_ncat(str, s, len > maxlen ? maxlen : len);
		}
		goto done;
	}

	fmtend = fmt + fmtlen;

	for (f = fmt; f < fmtend; f = q) {
		bool alt = FALSE;
		bool left = FALSE;
		char fill = ' ';
		char plus = 0;
		char intsize = 0;
		size_t width = 0;
		int zeros = 0;
		bool has_precis = FALSE;
		size_t precis = 0;

		char esignbuf[4];
		int esignlen = 0;

		const char *eptr = NULL;
		char *mptr;
		size_t elen = 0;
		char ebuf[TYPE_DIGITS(long) * 2 + 16]; /* large enough for "%#.#f" */

		static char *efloatbuf = NULL;
		static size_t efloatsize = 0;

		char c;
		int i;
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
			if (len > remain) {
				str_ncat(str, f, remain);
				goto done;						/* Reached maxlen */
			} else {
				str_ncat(str, f, len);
				remain -= len;
			}
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
			if (args)
				i = va_arg(*args, int);
			else
				i = 0;
			left |= (i < 0);
			width = (i < 0) ? -UNSIGNED(i) : UNSIGNED(i);
			q++;
			break;
		}

		/* PRECISION */

		if (*q == '.') {
			q++;
			if (*q == '*') {
				if (args)
					i = va_arg(*args, int);
				else
					i = 0;
				precis = (i < 0) ? 0 : i;
				q++;
			}
			else {
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
			if (args)
				c = va_arg(*args, int) & MAX_INT_VAL(unsigned char);
			else
				c = 0;
			eptr = &c;
			elen = 1;
			goto string;

		case 's':
			if (args) {
				eptr = va_arg(*args, char*);
				if (NULL == eptr)
					eptr = nullstr;
				elen = strlen(eptr);
			}

		string:
			if (has_precis && elen > precis)
				elen = precis;
			break;

			/* INTEGERS */

		case 'p':
			if (args)
				uv = (unsigned long) va_arg(*args, void*);
			else
				uv = 0;
			base = 16;
			goto integer;

		case 'D':
			intsize = 'l';
			/* FALL THROUGH */
		case 'd':
		case 'i':
			if (args) {
				switch (intsize) {
				case 'h':		iv = (short) va_arg(*args, int); break;
				default:		iv = va_arg(*args, int); break;
				case 'l':		iv = va_arg(*args, long); break;
				}
			}
			else {
				iv = 0;
				switch (intsize) {
				case 'h':		iv = (short) iv; break;
				default:		iv = (int) iv; break;
				case 'l':		iv = (long) iv; break;
				}
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

		uns_integer:
			if (args) {
				switch (intsize) {
				case 'h':  uv = (unsigned short) va_arg(*args, unsigned); break;
				case 'l':  uv = va_arg(*args, unsigned long); break;
				default:   uv = va_arg(*args, unsigned); break;
				}
			}
			else {
				uv = 0;
				switch (intsize) {
				case 'h':		uv = (unsigned short)uv; break;
				case 'l':		uv = (unsigned long)uv; break;
				default:		uv = (unsigned)uv; break;
				}
			}

		integer:
			mptr = ebuf + sizeof ebuf;
			switch (base) {
				unsigned dig;
			case 16:
				p = (c == 'X') ? "0123456789ABCDEF" : "0123456789abcdef";
				do {
					dig = uv & 15;
					*--mptr = p[dig];
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
				do {
					dig = uv % base;
					*--mptr = '0' + dig;
				} while (uv /= base);
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

			/*
			 * This is evil, but floating point is even more evil.
			 * Formatting of floats is delegated to system's snprintf().
			 */

			if (args)
				nv = va_arg(*args, double);
			else
				nv = 0.0;

			need = 0;
			if (c != 'e' && c != 'E') {
				i = INT_MIN;
				(void) frexp(nv, &i);
				if (i == INT_MIN)
					g_error("frexp");
				if (i > 0)
					need = BIT_DIGITS(i);
			}
			need += has_precis ? precis : 6;	/* known default */
			if (need < width)
				need = width;

			need += 20; /* fudge factor */
			if (efloatsize < need) {
				efloatsize = need + 20;			/* more fudge */
				efloatbuf = NOT_LEAKING(hrealloc(efloatbuf, efloatsize));
			}

			mptr = ebuf + sizeof ebuf;
			*--mptr = '\0';
			*--mptr = c;
			if (has_precis) {
				base = precis;
				do { *--mptr = '0' + (base % 10); } while (base /= 10);
				*--mptr = '.';
			}
			if (width) {
				base = width;
				do { *--mptr = '0' + (base % 10); } while (base /= 10);
			}
			if (fill == '0')
				*--mptr = fill;
			if (left)
				*--mptr = '-';
			if (plus)
				*--mptr = plus;
			if (alt)
				*--mptr = '#';
			*--mptr = '%';

			/* should be big enough */
			str_snprintf(efloatbuf, efloatsize, mptr, nv);

			eptr = efloatbuf;
			elen = strlen(efloatbuf);

			break;

			/* SPECIAL */

		case 'n':
			i = str->s_len - origlen;
			if (args) {
				switch (intsize) {
				case 'h':		*(va_arg(*args, short*)) = i; break;
				case 'l':		*(va_arg(*args, long*)) = i; break;
				default:		*(va_arg(*args, int*)) = i; break;
				}
			}
			continue;	/* not "break" */

			/* UNKNOWN */

		default:
			if (c)
				g_warning("str_vncatf(): invalid conversion \"%%%c\"", c & 0xff);
			else
				g_warning("str_vncatf(): invalid end of string");

			/* output mangled stuff ... */
			if (c == '\0')
				--q;
			eptr = p;
			elen = q - p;

			/* ... right here, because formatting flags should not apply */
			if (elen > remain) {
				str_ncat(str, eptr, remain);
				goto done;						/* Reached maxlen */
			} else {
				str_ncat(str, eptr, elen);
				remain -= elen;
			}
			continue;	/* not "break" */
		}

		have = esignlen + zeros + elen;
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

		str_makeroom(str, need + 1);	/* will NUL terminate it */
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
		if (elen) {
			memcpy(p, eptr, elen);
			p += elen;
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

		str_makeroom(str, remain);			/* no room for NUL terminate */
		p = str->s_data + str->s_len;		/* next "free" char in arena */
		str->s_len += remain;				/* know how much we'll append */
		q = p + remain;						/* first char past limit */
		if (esignlen && fill == '0') {
			for (i = 0; i < esignlen && p < q; i++)
				*p++ = esignbuf[i];
			if (p >= q)
				goto done;
			remain -= esignlen;
		}
		if (gap && !left) {
			if (gap >= remain) {
				memset(p, fill, remain);
				goto done;
			} else {
				memset(p, fill, gap);
				p += gap;
			}
			remain -= gap;
		}
		if (esignlen && fill != '0') {
			for (i = 0; i < esignlen && p < q; i++)
				*p++ = esignbuf[i];
			if (p >= q)
				goto done;
			remain -= esignlen;
		}
		if (zeros) {
			for (i = zeros; i && p < q; i--)
				*p++ = '0';
			if (p >= q)
				goto done;
			remain -= zeros;
		}
		if (elen) {
			if (elen >= remain) {
				memcpy(p, eptr, remain);
				goto done;
			} else {
				memcpy(p, eptr, elen);
				p += elen;
			}
			remain -= elen;
		}
		if (gap && left) {
			if (gap >= remain) {
				memset(p, ' ', remain);
				goto done;
			} else {
				memset(p, ' ', gap);
				p += gap;
			}
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
}

/*
 * The following are convenience wrappers to str_vncatf(), by increasing
 * order of sophistication, more or less.
 */

/**
 * Append to string the variable formatted argument list, just like sprintf().
 * Returns the amount of formatted chars.
 */
size_t
str_vcatf(str_t *str, const char *fmt, va_list *args)
{
	return str_vncatf(str, INT_MAX, fmt, args);
}

/**
 * Like str_vcatf(), but resets the string first.
 * Returns the amount of formatted chars.
 */
size_t
str_vprintf(str_t *str, const char *fmt, va_list *args)
{
	str_check(str);

	str->s_len = 0;
	return str_vncatf(str, INT_MAX, fmt, args);
}

/**
 * Append result of "printf(fmt, ...)" to string.
 * Returns the amount of formatted chars.
 */
size_t
str_catf(str_t *str, const char *fmt, ...)
{
	va_list args;
	size_t formatted;

	va_start(args, fmt);
	formatted = str_vncatf(str, INT_MAX, fmt, &args);
	va_end(args);

	return formatted;
}

/**
 * Append result of "nprintf(fmt, ...)" to string.
 * Returns the amount of formatted chars.
 */
size_t
str_ncatf(str_t *str, size_t n, const char *fmt, ...)
{
	va_list args;
	size_t formatted;

	va_start(args, fmt);
	formatted = str_vncatf(str, n, fmt, &args);
	va_end(args);

	return formatted;
}

/**
 * A regular sprintf() without fear of buffer overflow...
 * Returns the amount of formatted chars.
 */
size_t
str_printf(str_t *str, const char *fmt, ...)
{
	va_list args;
	size_t formatted;

	str_check(str);

	str->s_len = 0;

	va_start(args, fmt);
	formatted = str_vncatf(str, INT_MAX, fmt, &args);
	va_end(args);

	return formatted;
}

/**
 * Like str_printf(), but formats at most `n' characters.
 * Returns the amount of formatted chars.
 */
size_t
str_nprintf(str_t *str, size_t n, const char *fmt, ...)
{
	va_list args;
	size_t formatted;

	str_check(str);

	str->s_len = 0;

	va_start(args, fmt);
	formatted = str_vncatf(str, n, fmt, &args);
	va_end(args);

	return formatted;
}

/**
 * Create a new string, and sprintf() the arguments inside.
 * Returns the new string item, which may be disposed of with str_destroy().
 */
str_t *
str_msg(const char *fmt, ...)
{
	str_t *str;
	va_list args;

	str = str_new(0);

	va_start(args, fmt);
	str_vncatf(str, INT_MAX, fmt, &args); /* We know length is 0 */
	va_end(args);

	str_resize(str, str->s_len + 1);	/* Allow for possible trailing NUL */

	return str;
}

/**
 * Create a new string, sprintf() the arguments inside and return a C string,
 * which may be disposed of by a regular hfree(). There is no need to strdup()
 * the string, it is already done.
 */
char *
str_cmsg(const char *fmt, ...)
{
	static str_t *str;
	va_list args;
	
	if (NULL == str)
		str = str_new_not_leaking(0);

	str->s_len = 0;
	va_start(args, fmt);
	str_vncatf(str, INT_MAX, fmt, &args);
	va_end(args);

	return str_dup(str);
}

/* vi: set ts=4: */
