/*
 * Copyright (c) 1996-2000, 2007, 2010-2013 Raphael Manfredi
 *
 * This code given by Raphael Manfredi, extracted from his fm2html package.
 * Also contains some code borrowed from Perl: routine str_vncatf().
 * Code was slightly adapted to use standard features available in the
 * gtk-gnutella library.
 *
 * After 2007, the original code was enriched with new features such as
 * native floating point formatting or other string copyout operations.
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
 * @date 1996-2000, 2007, 2010-2013
 */

#include "common.h"

#include <math.h>		/* For frexp() and isfinite() */

#include "ascii.h"
#include "ckalloc.h"
#include "float.h"
#include "glib-missing.h"
#include "halloc.h"
#include "log.h"
#include "mempcpy.h"
#include "misc.h"			/* For clamp_strcpy() and symbolic_errno() */
#include "omalloc.h"
#include "str.h"
#include "stringify.h"		/* For logging */
#include "thread.h"
#include "unsigned.h"
#include "walloc.h"

#include "override.h"		/* Must be the last header included */

#define STR_DEFSIZE		64		/* Default string size */
#define STR_GROW		2		/* Grow factor, if size less than STR_MAXGROW */
#define STR_MAXGROW		4096	/* Above this size, increase by STR_CHUNK */
#define STR_CHUNK		4096	/* Size increase if above STR_MAXGROW */

#define FPREC			17		/* IEEE 64-bit double maximum digit precision */

static bool tests_completed;		/* Controls truncation warnings */
static bool format_verbose;			/* Controls debugging of formatting */
static unsigned format_recursion;	/* Prevents recursive verbose debugging */

/**
 * Flags for s_flags
 */
#define STR_FOREIGN_PTR		(1 << 0)	/**< We don't own the pointer */
#define STR_OBJECT			(1 << 1)	/**< Object created, not a structure */
#define STR_THREAD			(1 << 2)	/**< String is thread-private */

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

	/*
	 * We don't want something from a zone here to allow this object to be
	 * use throughout the lifetime of the process, including after a zclose().
	 * In other words, walloc() is forbidden!
	 *
	 * Because the memory will never be freed, it's best to use omalloc().
	 */

	OMALLOC(str);
	str_create(str, szhint);
	(void) NOT_LEAKING(str->s_data);

	/* Note: STR_OBJECT not set because structure cannot be freed. */

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
 * Cram a string at the start of the buffer, the remaining space being
 * used to hold the string arena.
 *
 * @param buf		buffer where we can allocate the string
 * @param len		length of buffer
 *
 * @return newly create string, NULL if buffer is too small
 */
str_t *
str_new_in_buffer(void *buf, size_t len)
{
	str_t *str;

	g_assert(buf != NULL);
	g_assert(size_is_positive(len));

	if (len <= sizeof *str)
		return NULL;

	/*
	 * Don't set the STR_OBJECT because the object is non-freeable.
	 * Force STR_FOREIGN_PTR because the arena is non-freeable.
	 */

	str = buf;
	str->s_magic = STR_MAGIC;
	str->s_flags = STR_FOREIGN_PTR;
	str->s_data = ptr_add_offset(buf, sizeof *str);
	str->s_len = 0;
	str->s_size = len - sizeof *str;

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
 * @param str		the string structure to fill with new data buffer
 * @param szhint	buffer hint size
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
 *
 * @param str	pointer to existing (and initialized) string object
 * @param ptr	start of fix-sized buffer where string data will be held
 * @param len	length of existing string, computed if (size_t) -1
 * @param size	size of buffer starting at ptr (0 sets it to `len + 1')
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
		len = (0 == size) ? strlen(ptr) : clamp_strlen(ptr, size);

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
 *    str_new_buffer(&str, data, 0, sizeof data);
 *
 * @param str	pointer to uninitialized existing string object
 * @param ptr	start of fix-sized buffer where string data will be held
 * @param len	length of existing string, computed if (size_t) -1
 * @param size	size (positive) of buffer starting at ptr
 */
void
str_new_buffer(str_t *str, char *ptr, size_t len, size_t size)
{
	g_assert(str != NULL);
	g_assert(ptr != NULL);
	g_assert(size_is_non_negative(len + 1));
	g_assert(size_is_positive(size));

	str->s_magic = STR_MAGIC;
	str->s_flags = STR_FOREIGN_PTR;
	str->s_data = ptr;
	str->s_len = ((size_t) -1 == len) ? clamp_strlen(ptr, size) : len;
	str->s_size = size;

	g_assert(str->s_len <= str->s_size);
}

/**
 * Reclaim a thread-private string when the thread is exiting.
 */
static void
str_private_reclaim(void *data, void *unused)
{
	str_t *s = data;

	(void) unused;

	str_check(s);
	g_assert_log(s->s_flags & STR_THREAD,
		"%s(): called on a regular string object", G_STRFUNC);

	s->s_flags &= ~STR_THREAD;
	str_destroy(s);
}

/**
 * Get a thread-private string attached to the specified key.
 *
 * If the string already existed in the thread for this key, it is returned,
 * and the szhint parameter is ignored.
 *
 * Otherwise, a new string is created and attached to the key.
 *
 * A typical usage of this routine is to make a routine returning static
 * data thread-safe:
 *
 *   const char *
 *   routine(int i)
 *   {
 *       str_t *s = str_private(G_STRFUNC, 10);
 *
 *       str_printf(s, "%dB", i);
 *       return str_2c(s);	       // the private copy for this thread
 *   }
 *
 * @param key		the key to use to identify this string
 * @param szhint	initial length of the data buffer (0 for default)
 *
 * @note
 * The string will be reclaimed automatically when the thread exits and its
 * pointer should not be given to foreign threads but used solely in the
 * context of the thread.  This applies to the string object and its buffer.
 *
 * @return a string object dedicated to the calling thread.
 */
str_t *
str_private(const void *key, size_t szhint)
{
	str_t *s;

	s = thread_private_get(key);

	if G_LIKELY(s != NULL) {
		str_check(s);
		return s;
	}

	/*
	 * Allocate a new string and declare it as a thread-private variable
	 * with an associated free routine.  The string cannot be destroyed but
	 * through that specialized free routine.
	 */

	s = str_new(szhint);
	s->s_flags |= STR_THREAD;	/* Prevents plain str_free() on that string */

	thread_private_add_extended(key, s, str_private_reclaim, NULL);

	return s;
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

	g_assert_log(!(str->s_flags & STR_THREAD),
		"%s(): called on thread-private string object", G_STRFUNC);

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
 * Discard the str_t structure, freeing string data and making object invalid.
 *
 * This is to be used on static str_t structures, when we want to free the
 * allocated memory and prevent any further usage of the structure.
 */
void
str_discard(str_t *str)
{
	str_free(str);
	str->s_magic = 0;
}

/**
 * Destroy string held within the str_t structure, then the structure.
 */
void
str_destroy(str_t *str)
{
	str_check(str);

	g_assert_log(str->s_flags & STR_OBJECT,
		"%s(): called on \"static\" string object", G_STRFUNC);

	str_discard(str);
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
		s_error("%s() would expand \"foreign\" string", G_STRFUNC);
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
 * Pre-expand string data space to be able to hold at least `len' more bytes.
 *
 * @param str		the string object
 * @param len		the extra room we want to have in the buffer
 */
void
str_reserve(str_t *str, size_t len)
{
	str_check(str);
	g_assert(size_is_non_negative(len));

	str_makeroom(str, size_saturate_add(len, 1));
}

/**
 * Expand data space, if necessary.
 *
 * @param str		the string object
 * @param size		the new buffer data size we want
 */
void
str_grow(str_t *str, size_t size)
{
	str_check(str);
	g_assert(size_is_non_negative(size));

	if G_LIKELY(str->s_size >= size)
		return;					/* Nothing to do */

	if G_UNLIKELY(str->s_flags & STR_FOREIGN_PTR)
		s_error("%s() would expand \"foreign\" string", G_STRFUNC);

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
		s_error("%s() called on \"static\" string object", G_STRFUNC);

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
	char *sdup, *p;

	str_check(str);

	len = str->s_len;
	sdup = halloc(len + 1);
	p = mempcpy(sdup, str->s_data, len);
	*p = '\0';

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
 * Copy string argument into the string structure, keeping trailing NUL as
 * a hidden char (thereby making the arena a C string).
 *
 * Since the len is provided, the data need not have a trailing NUL.
 * Although it may contain embedded NUL, it should not however because this
 * will disrupt the perception of the resulting string as C string.
 */
void
str_cpy_len(str_t *str, const char *string, size_t len)
{
	str_check(str);

	str->s_len = 0;
	str_cat_len(str, string, len);
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
bool
str_ncat_safe(str_t *str, const char *string, size_t len)
{
	char *p;
	const char *q;
	char c;
	bool fits = TRUE;

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
bool
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
bool
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
bool
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
bool
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
 * Remove penultimate character of string and return it.
 */
char
str_chop(str_t *s)
{
	size_t len;
	char c;

	str_check(s);

	len = s->s_len;

	if G_UNLIKELY(0 == len)
		return '\0';

	c = s->s_data[len - 1];
	s->s_len--;

	return c;
}

/**
 * Reverse string in-place: "noel" becomes "leon".
 */
void
str_reverse(str_t *s)
{
	char *p, *q;
	size_t len;

	str_check(s);

	len = s->s_len;

	if G_UNLIKELY(0 == len)
		return;

	p = &s->s_data[0];
	q = &s->s_data[len - 1];

	while (ptr_cmp(p, q) < 0) {
		char t = *q;
		*q-- = *p;
		*p++ = t;
	}
}

/**
 * Move string content starting at some offset to specified buffer, clamping
 * copy at the last character of the buffer and finishing with a NUL.
 *
 * @return amount of copied bytes (trailing NUL does not count).
 */
size_t
str_copyout_offset(str_t *s, size_t offset, char *dest, size_t dest_size)
{
	size_t n;
	size_t ds;
	size_t len;

	str_check(s);
	g_assert(size_is_positive(dest_size));

	ds = dest_size - 1;
	len = s->s_len;

	if (offset >= len)
		return 0;

	len -= offset;

	n = MIN(ds, len);
	memcpy(dest, &s->s_data[offset], n);
	dest[n] = '\0';

	return n;
}

/**
 * Move string content to specified buffer, clamping copy at the last character
 * of the buffer and finishing with a NUL.
 *
 * @return amount of copied bytes (trailing NUL does not count).
 */
size_t
str_copyout(str_t *s, char *dest, size_t dest_size)
{
	return str_copyout_offset(s, 0, dest, dest_size);
}

/**
 * Move string content starting at some offset to specified buffer, clamping
 * copy at the last character of the buffer, but without NUL-terminating the
 * copied data.
 *
 * To copy a "string" (NUL-terminated), use str_copyout_offset().
 *
 * @return amount of copied bytes.
 */
size_t
str_memout_offset(str_t *s, size_t offset, char *dest, size_t dest_size)
{
	size_t n;
	size_t len;

	str_check(s);
	g_assert(size_is_non_negative(dest_size));

	len = s->s_len;

	if (offset >= len)
		return 0;

	len -= offset;

	n = MIN(dest_size, len);
	memcpy(dest, &s->s_data[offset], n);

	return n;
}

/**
 * Move string content to specified buffer, clamping copy at the last
 * character of the buffer, but without NUL-terminating the copied data.
 *
 * To copy a "string" (NUL-terminated), use str_copyout().
 *
 * @return amount of copied bytes.
 */
size_t
str_memout(str_t *s, char *dest, size_t dest_size)
{
	return str_memout_offset(s, 0, dest, dest_size);
}

/**
 * Reverse copy string content to specified buffer, clamping copy at the last
 * character of the buffer and finishing with a NUL.
 *
 * @return amount of copied bytes (trailing NUL does not count).
 */
size_t
str_reverse_copyout(str_t *s, char *dest, size_t dest_size)
{
	size_t n;
	size_t ds;
	char *q;

	str_check(s);
	g_assert(size_is_positive(dest_size));

	ds = dest_size - 1;
	n = MIN(ds, s->s_len);
	q = dest;

	if (n != 0) {
		char *p = &s->s_data[s->s_len];

		while (n-- != 0)
			*q++ = *--p;
		*q = '\0';
	}

	return q - dest;
}

/**
 * Fetch character at given offset.  Read from the end of the string when
 * the offset is negative, -1 being the last character, 0 being the first.
 *
 * @return NUL if offset is not within the string range, but NUL may be a
 * valid string character when dealing with binary strings.
 */
char
str_at(str_t *s, ssize_t offset)
{
	size_t len;

	str_check(s);

	len = s->s_len;

	if (offset >= 0) {
		return UNSIGNED(offset) >= len ? '\0' : s->s_data[offset];
	} else {
		size_t pos = len + offset;
		return pos >= len ? '\0' : s->s_data[pos];
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
 * Look for character ``c'' in string, starting at position 0.
 *
 * @return the offset from the start of the string where character is found,
 * or -1 if not found.
 */
ssize_t
str_chr(const str_t *s, int c)
{
	size_t len, i;
	const char *p;

	str_check(s);

	len = s->s_len;

	for (i = 0, p = s->s_data; i < len; i++) {
		if G_UNLIKELY(*p++ == c)
			return i;
	}

	return -1;
}

/**
 * Backward look for character ``c'' in string, starting at end of string.
 *
 * @return the offset from the start of the string where character is found,
 * or -1 if not found.
 */
ssize_t
str_rchr(const str_t *s, int c)
{
	size_t i;
	const char *p;

	str_check(s);

	for (i = s->s_len, p = s->s_data + i - 1; i != 0; i--) {
		if G_UNLIKELY(*p-- == c)
			return i - 1;
	}

	return -1;
}

/**
 * Round up floating-point mantissa, with leading extra carry digit.
 *
 * For instance, given "314159" with a rounding position of 2, the routine
 * returns "0314".  However, given "9995", it would return "1000".
 *
 * This routine is used internally by str_fcat_safe() to format floats.
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

	if G_UNLIKELY(format_verbose && 1 == format_recursion) {
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

#define BIT_DIGITS(n)	(((n)*146)/485 + 1)			/* log2(10) =~ 146/485 */
#define TYPE_DIGITS(t)	BIT_DIGITS(sizeof(t) * 8)

/**
 * Append formatted floating point value.
 *
 * This routine does not come from Perl but was written by Raphael Manfredi.
 *
 * @param str			string to which fomatting occurs
 * @param maxlen		maximum amount of bytes to print
 * @param nv			floating point value
 * @param f				format letter: 'f', 'g', 'e' or upper-cased version
 * @param has_precis	whether precision was requested
 * @param precision		precision for formatting (0 if !has_precis)
 * @param width			field width (0 if none enforced)
 * @param plus			the leading '+' sign to use, or '\0' for none.
 * @param left			whether to left-justify the field
 * @param alt			whether to use "alternate" float formatting
 * @param written		set with amount of bytes appended to string
 *
 * @return TRUE if written normally, FALSE when clamping was done.
 */
static size_t
str_fcat_safe(str_t *str, size_t maxlen, double nv, const char f,
	bool has_precis, const size_t precision, const size_t width,
	const char plus, const bool left, const bool alt, size_t *written)
{
	size_t ezeros = 0;		/* Trailing mantissa zeros in %e form */
	size_t dzeros = 0;		/* Trailing zeros before dot */
	size_t azeros = 0;		/* After-dot zeros, before value */
	size_t fzeros = 0;		/* Trailing fixed zeros */
	size_t dot = 0;			/* Emit floating point "." if 1, "0." if 2 */
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
	char *p, *q;

	size_t have;
	size_t need;
	size_t gap;

	char c = f;
	size_t origlen = str->s_len;
	size_t precis = precision;
	size_t remain = maxlen;

	str_check(str);
	g_assert(size_is_non_negative(maxlen));

	/*
	 * Sanity check of the ``maxlen'' parameter.
	 */

	if G_UNLIKELY(str->s_flags & STR_FOREIGN_PTR) {
		size_t avail = str->s_size - str->s_len;
		if G_UNLIKELY(avail <= 1)
			goto clamped;
		avail--;					/* Leave room for trailing NUL */
		remain = MIN(maxlen, avail);
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
			bool dragon_fmt = FALSE;
			bool asked_dragon = FALSE;

			if ('F' == c) {
				asked_dragon = TRUE;
				if (has_precis)
					c = 'G';
				else
					dragon_fmt = TRUE;
			}

			/*
			 * For %g, the precision is the number of digits displayed,
			 * whereas for %e it's the number of digits after the
			 * decimal point.
			 */

			if ('g' == c || 'G' == c) {
				/* A non-zero digits value flags %g or %G */
				digits = MAX(1, precis);
				precis = (0 == precis) ? 0 : precis - 1;
			}

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

			if ('f' == c) {
				asked = FPREC;		/* Will do rounding ourselves */
			} else if (digits) {
				asked = MIN(FPREC, digits);
			} else {
				asked = 1 + MIN(FPREC, precis);
			}

			/*
			 * Format the floating point number, separating the
			 * mantissa and the exponent.
			 *
			 * The returned values are such that one presentation
			 * of the number would be the output of:
			 *
			 *		printf("0.%se%d", m, e + 1);
			 */

			if (asked_dragon) {
				mlen = float_dragon(m, sizeof m, nv, &e);
			} else {
				mlen = float_fixed(m, sizeof m, nv, asked, &e);
			}

			g_assert(size_is_positive(mlen));
			g_assert(mlen < sizeof m);

			if G_UNLIKELY(format_verbose && 1 == format_recursion) {
				char buf[32];
				gm_snprintf(buf, sizeof buf, "%g", nv);
				s_debug("%s with \"%%%c\": m=\"%.*s\" "
					"(len=%zu, asked=%s), e=%d "
					"[precis=%zu, digits=%zu, alt=%s]",
					buf, c, (int) mlen, m, mlen,
					asked_dragon ? "none" : size_t_to_string(asked),
					e, precis, digits, alt ? "y" : "n");
			}

			/*
			 * %g is turned into %e (and %G to %E) when the exponent
			 * is less than -4 or when it is greater than or equal
			 * to the precision.
			 *
			 * %F is our special "free format":
			 * - If e = 0, we show the mantissa as-is.
			 * - If e > 0, we switch to scientific notation as soon as
			 *   the exponent is greater than the available significant
			 *   digits and when e > 10.
			 * - If e < 0, we switch to scientific notation when
			 *   the number of leading zeros + the mantissa would be
			 *   larger than FPREC digits (deemed harder to read at
			 *   that time), or when e < -5.
			 */

			if ('g' == c || 'G' == c) {
				if (e < -4 || e >= (int) precis + 1)
					c = 'g' == c ? 'e' : 'E';
			} else if (dragon_fmt) {
				c = 'f';				/* For logging only */
				if (e > 0) {
					size_t v = e;
					if (v > mlen && e > 10)			c = 'E';
				} else if (e < 0) {
					if (e < -5 || mlen - e > FPREC)	c = 'E';
				}
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
				if (v < 10 && !asked_dragon)
					*--mptr = '0';
				*--mptr = (e >= 0) ? '+' : '-';
				*--mptr = is_ascii_upper(c) ? 'E' : 'e';

				g_assert(ptr_cmp(mptr, expbuf) >= 0);

				expptr = mptr;
				explen = (expbuf + sizeof expbuf) - expptr;

				/* Mantissa */

				mptr = ebuf + sizeof ebuf;

				if (dragon_fmt) {
					v = mlen - 1;
					do {
						if (0 == v && mlen > 1)
							*--mptr = '.';
						*--mptr = m[v];
					} while (v--);

					/* Trailing mantissa filler if has precision */
					if (has_precis && mlen < precis + 1)
						ezeros = precis + 1 - mlen;

				} else {
					v = precis + 1;
					v = MIN(mlen, v);
					start = v; 			/* Starting index */
					non_zero = alt || 0 == digits;

					rlen = str_fround(m, mlen, v, r, sizeof r);

					do {
						if (1 == v && (alt || start != 1))
							*--mptr = '.';
						if (r[v] != '0')
							non_zero = TRUE;
						if (1 == v || non_zero)
							*--mptr = r[v];
					} while (--v);

					/* Trailing mantissa zeros if %e or %E or %#[gG] */
					if (mlen < precis + 1 && (alt || 0 == digits))
						ezeros = precis + 1 - mlen;
				}
			} else {
				size_t i;
				char *t;
				size_t d;	/* Dot position */

				/* %f or %F -- THE FUN BEGINS! */

				if (dragon_fmt) {
					if (e < 0) {
						azeros = -e - 1;	/* Zeros after dot */
						g_assert(mlen <= sizeof ebuf);
						mptr -= mlen;
						memcpy(mptr, m, mlen);
						if (0 == azeros) {
							*--mptr = '.';
							*--mptr = '0';
						} else {
							dot = 2;		/* Will emit "0." later */
						}
					} else {
						size_t v = e;

						if (v < mlen) {
							d = e + 1;		/* Dot position */
							i = mlen - 1;
							do {
								*--mptr = m[i];
								if (i == d)
									*--mptr = '.';
							} while (i--);
							/* Ensure trailing dot present if %# */
							dot = (alt && d > mlen - 1) ? 1 : 0;
						} else {
							size_t x = e - mlen + 1;	/* Extra 10s */

							dzeros = x; /* Before the decimal point */
							g_assert(mlen <= sizeof ebuf);
							mptr -= mlen;
							memcpy(mptr, m, mlen);
							/* Ensure trailing dot present if %# */
							dot = alt ? 1 : 0;
						}
					}
				} else if (e < 0) {
					size_t v = -e;
					size_t z = v - 1;	/* Amount of zeros after dot */

					/* Formatted as 0.xxxx */

					if (z >= precis && 0 == digits) {
						i = 0;
					} else {
						/* How many trailing zeros? (none for %g) */
						if (precis > z + mlen && (0 == digits || alt))
							fzeros = precis - z - mlen;

						i = (0 == digits) ? precis - z : mlen;
						i = MIN(i, mlen);
					}

					/*
					 * How many after-dot zeros? (0.000xxx)
					 *
					 * We remove one after-dot zero due to the leading carry
					 * digit, which is known to be 0.  However, if we were
					 * about to emit just one zero, we need to emit the
					 * dot ourselves in the printing loop below.
					 */

					if (z != 0) {
						azeros = z - 1;
						dot = (z > 1) ? 2 : 0;	/* Will emit "0." later */
					}

					/* Rounding for the precision digit */
					rlen = str_fround(m, mlen, i, r, sizeof r);

					/* Don't emit if we're down to printing 0.0 */
					if (0 == azeros || azeros < precis) {
						bool has_non_zero = 0 == digits || alt;
						/* Compute position of digital dot */
						d = (z != 0) ? 0 : 1;
						for (i = rlen, t = r + rlen; i > 0;) {
							char dig = *--t;
							if (has_non_zero || dig != '0') {
								*--mptr = dig;
								has_non_zero = TRUE;
							}
							if (--i == d) {
								/* Leading "0.0" done later?*/
								if (0 == dot) {
									/* No, emit now */
									*--mptr = '.';
									*--mptr = '0';
								}
								break;
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

						if (0 != digits) {
							/* Formatting from %g or %G */
							has_non_zero = alt;	/* %#g wants dot */
							subdot = digits > d ? digits - d : 0;
						} else {
							subdot = precis;
							has_non_zero = TRUE;
						}

						/* Rounding for the precision digit */
						i = d + subdot;		/* First excluded */
						i = MIN(i, mlen);

						/* Trailing fixed zeros to emit */
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
							/* Trailing zeros kept with %#g (alt) */
							if (digits && !alt && i >= d) {
								if (r[i] != '0' || has_non_zero) {
									*--mptr = r[i];
									has_non_zero = TRUE;
								}
							} else {
								*--mptr = r[i];
							}
							if (i == d && has_non_zero)
								*--mptr = '.';
						} while (i--);

						/* Ensure trailing dot present if %# */
						dot = (alt && d > rlen - 1) ? 1 : 0;
					} else {
						size_t x = e - mlen + 1;	/* Extra 10s */
						size_t subdot;

						if (digits) {
							if (alt) {
								/* Formatting from %#g or %#G */
								subdot = precis;
							} else {
								/* Formatting from %g or %G */
								subdot = precis > v ? precis - v : 0;
							}
						} else {
							subdot = precis;
						}

						dzeros = x; /* Zeros before the decimal point */
						fzeros = subdot;	/* Zeros after the dot */

						/* Emit a dot? */
						dot = (0 == subdot && !alt) ? 0 : 1;

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

		if G_UNLIKELY(format_verbose && 1 == format_recursion) {
			char buf[32];
			gm_snprintf(buf, sizeof buf, "%g", nv);
			s_debug("%s as \"%%%c\": elen=%zu, eptr=\"%.*s\", "
				"expptr=\"%.*s\", dot=\"%s\", zeros<e=%zu, d=%zu, "
				"a=%zu, f=%zu>",
				buf, c, elen, (int) elen, eptr, explen, expptr,
				2 == dot ? "0." :
				1 == dot ? "." : "",
				ezeros, dzeros, azeros, fzeros);
		}
		break;
	}

	have = esignlen + elen + ezeros + explen + dzeros + dot + azeros + fzeros;
	need = MAX(have, width);
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

	if (remain < need)				/* Cannot fit entirely */
		goto careful;

	/*
	 * CAUTION: code duplication with "careful" below. Any change made
	 * here NEEDS TO BE REPORTED to the next section.
	 */

	str_makeroom(str, need);		/* we do not NUL terminate it */
	p = str->s_data + str->s_len;	/* next "free" char in arena */
	if (gap && !left) {
		memset(p, ' ', gap);
		p += gap;
	}
	if (esignlen) {
		p = mempcpy(p, esignbuf, esignlen);
	}
	if (elen && 0 == azeros) {
		p = mempcpy(p, eptr, elen);
	}
	if (ezeros) {
		memset(p, '0', ezeros);
		p += ezeros;
	}
	if (explen) {
		p = mempcpy(p, expptr, explen);
	}
	if (dzeros) {
		memset(p, '0', dzeros);
		p += dzeros;
	}
	if (dot) {
		if (2 == dot)
			*p++ = '0';
		*p++ = '.';
	}
	if (azeros) {
		memset(p, '0', azeros);
		p += azeros;
	}
	if (elen && 0 != azeros) {
		p = mempcpy(p, eptr, elen);
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
	g_assert(str->s_len <= str->s_size);
	goto done;

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
	if (gap && !left) {
		p += clamp_memset(p, q - p, ' ', gap);
		if (p >= q)
			goto clamped;
		remain -= gap;
	}
	if (esignlen) {
		p += clamp_memcpy(p, q - p, esignbuf, esignlen);
		if (p >= q)
			goto clamped;
		remain -= esignlen;
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
		if (2 == dot) {
			*p++ = '0';
			if (0 == --remain)
				goto clamped;
		}
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

done:
	*written = str->s_len - origlen;
	return TRUE;

clamped:
	*written = str->s_len - origlen;
	return FALSE;
}

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
 * %F   "free format" for floats, almost similar to %G if precision is given
 *
 * Finally, for backward compatibility, the following unnecessary but
 * widely-supported conversions are allowed:
 *
 * %i   a synonym for %d
 * %D   a synonym for %ld
 * %U   a synonym for %lu
 * %O   a synonym for %lo
 *
 * The routine permits the following universally-known flags between the
 * % and the conversion letter:
 *
 * space    prefix positive number with a space
 * +        prefix positive number with a plus sign
 * -        left-justify within the field
 * 0        use zeros, not spaces, to right-justify
 * #        prefix octal with "0", hex with "0x"
 *          force trailing dot for floats, don't strip trailing zeros for %[gG]
 * '        use thousands groupping in decimal integers with ","
 * number   minimum field width
 * .number  precision: digits after decimal point for floating-point,
 *          max length for string, minimum length for integer
 * l        interpret integer as C type "long" or "unsigned long"
 * h        interpret integer as C type "short" or "unsigned short"
 * z        interpret integer as C type "size_t" or "ssize_t"
 *
 * Where a number would appear in the flags, an asterisk ("*") may be given
 * instead, in which case the routine uses the next item (int) in the parameter
 * list as the given number (that is, as the field width or precision).
 * If a field width obtained through "*" is negative, it has the same effect
 * as the '-' flag: left-justification.
 *
 * @param str		string to which fomatting occurs
 * @param maxlen	maximum amount of bytes to print
 * @param fmt		format string
 * @param args		variable arguments
 *
 * @return amount of bytes appended to string.
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
	size_t processed = 0;

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

	format_recursion++;

	if G_UNLIKELY(2 == fmtlen && fmt[0] == '%' && fmt[1] == 's') {
		const char *s = va_arg(args, char*);
		size_t len;
		processed++;
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
		if G_UNLIKELY(avail <= 1)
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
		bool has_precis = FALSE;
		size_t precis = 0;

		char esignbuf[4];
		int esignlen = 0;

		const char *eptr = NULL;
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
				processed++;
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
				processed++;
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
			processed++;
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
			processed++;
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
			processed++;
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
			processed++;
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
			processed++;

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

		case 'e': case 'E':
		case 'f': case 'F':
		case 'g': case 'G':
			{
				size_t written;
				bool ok;

				nv = va_arg(args, double);
				processed++;
				if (!has_precis)
					precis = 6;					/* Default precision */

				/* Floating point formatting is complex, handle separately */

				ok = str_fcat_safe(str, remain, nv, c,
						has_precis, precis, width, plus, left, alt, &written);
				if (!ok)
					goto clamped;
				remain -= written;
			}
			continue;	/* not "break" */

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
				processed++;
			}
			continue;	/* not "break" */

			/* UNKNOWN */

		default:
			if (c) {
				s_minicarp("%s(): invalid conversion \"%%%c\"",
					G_STRFUNC, c & 0xff);
			} else {
				s_minicarp("%s(): invalid end of format string \"%s\"",
					G_STRFUNC, fmt);
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

		have = esignlen + zeros + elen;
		need = MAX(have, width);
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

		if (remain < need)				/* Cannot fit entirely */
			goto careful;

		/*
		 * CAUTION: code duplication with "careful" below. Any change made
		 * here NEEDS TO BE REPORTED to the next section.
		 */

		str_makeroom(str, need);		/* we do not NUL terminate it */
		p = str->s_data + str->s_len;	/* next "free" char in arena */
		if (esignlen && fill == '0') {
			p = mempcpy(p, esignbuf, esignlen);
		}
		if (gap && !left) {
			memset(p, fill, gap);
			p += gap;
		}
		if (esignlen && fill != '0') {
			p = mempcpy(p, esignbuf, esignlen);
		}
		if (zeros) {
			memset(p, '0', zeros);
			p += zeros;
		}
		if (elen) {
			p = mempcpy(p, eptr, elen);
		}
		if (gap && left) {
			memset(p, ' ', gap);
			p += gap;
		}
		str->s_len = p - str->s_data;	/* trailing NUL does not count */
		g_assert(str->s_len <= str->s_size);
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
		if (elen) {
			p += clamp_memcpy(p, q - p, eptr, elen);
			if (p >= q)
				goto clamped;
			remain -= elen;
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
	format_recursion--;
	return str->s_len - origlen;

clamped:
	{
#define TKEY	func_to_pointer(str_vncatf)

		bool recursion = thread_private_get(TKEY) != NULL;

		/*
		 * This routine MUST be recursion-safe since it is used indirectly
		 * by s_minicarp() through the str_vprintf() call and we're about
		 * to call the former now!
		 *
		 * Hence the use of a thread-private variable to record recursions
		 * before invoking s_minicarp().
		 */

		if (!recursion && tests_completed) {
			thread_private_add(TKEY, uint_to_pointer(1));
			s_minicarp("truncated output within %zu-byte buffer "
				"(%zu max, %zu written, %zu available) with \"%s\" "
				"(%zu arg%s processed)",
				str->s_size, maxlen, str->s_len - origlen,
				str->s_size - str->s_len,
				fmt, processed, plural(processed));
			thread_private_remove(TKEY);
		}
	}

#undef TKEY

	goto done;

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
	static str_t *str[THREAD_MAX];
	int stid = thread_small_id();

	if G_UNLIKELY(NULL == str[stid])
		str[stid] = str_new_not_leaking(0);

	str[stid]->s_len = 0;
	str_vncatf(str[stid], INT_MAX, fmt, args);

	return str_dup(str[stid]);
}

/**
 * sprintf() the arguments inside a dynamic string and return the result in a
 * freshly allocated C string, which needs to be disposed of by hfree().
 */
char *
str_cmsg(const char *fmt, ...)
{
	static str_t *str[THREAD_MAX];
	va_list args;
	int stid = thread_small_id();

	if G_UNLIKELY(NULL == str[stid])
		str[stid] = str_new_not_leaking(0);

	str[stid]->s_len = 0;
	va_start(args, fmt);
	str_vncatf(str[stid], INT_MAX, fmt, args);
	va_end(args);

	return str_dup(str[stid]);
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
	static str_t *str[THREAD_MAX];
	va_list args;
	int stid = thread_small_id();

	if G_UNLIKELY(NULL == str[stid])
		str[stid] = str_new_not_leaking(0);

	str[stid]->s_len = 0;
	va_start(args, fmt);
	str_vncatf(str[stid], INT_MAX, fmt, args);
	va_end(args);

	return str_2c(str[stid]);
}

/**
 * Same as str_smsg(), but in a different string.
 */
const char *
str_smsg2(const char *fmt, ...)
{
	static str_t *str[THREAD_MAX];
	va_list args;
	int stid = thread_small_id();

	if G_UNLIKELY(NULL == str[stid])
		str[stid] = str_new_not_leaking(0);

	str[stid]->s_len = 0;
	va_start(args, fmt);
	str_vncatf(str[stid], INT_MAX, fmt, args);
	va_end(args);

	return str_2c(str[stid]);
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

	str_new_buffer(&str, dst, 0, size);

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

	str_new_buffer(&str, dst, 0, size);

	formatted = str_vncatf(&str, size - 1, fmt, args);
	str_putc(&str, '\0');

	return formatted;
}

/**
 * Append formatted string to previous string in fix sized buffer.
 * @return the amount of formatted chars.
 */
size_t
str_bcatf(char *dst, size_t size, const char *fmt, ...)
{
	str_t str;
	va_list args;
	size_t len, formatted;

	len = clamp_strlen(dst, size);
	str_new_buffer(&str, dst, len, size);

	va_start(args, fmt);
	formatted = str_vncatf(&str, size - len - 1, fmt, args);
	va_end(args);

	str_putc(&str, '\0');

	return formatted;
}

/**
 * Append formatted string to previous string in fix sized buffer.
 * @return the amount of formatted chars.
 */
size_t
str_vbcatf(char *dst, size_t size, const char *fmt, va_list args)
{
	str_t str;
	size_t len, formatted;

	len = clamp_strlen(dst, size);
	str_new_buffer(&str, dst, len, size);

	formatted = str_vncatf(&str, size - len - 1, fmt, args);
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

	str_new_buffer(&str, dst, 0, size);

	va_start(args, fmt);
	str_vncatf(&str, size - 1, fmt, args);
	va_end(args);

	str_putc(&str, '\0');
}

/**
 * Fix the exponent part of a formatted double.
 *
 * On Windows, and maybe on other systems, snprintf() formats exponents with
 * 3 digits, whereas our str_vncatf() routine uses 2 digits.
 *
 * This routine normalizes exponents to 2 digits, for the purpose of
 * avoiding spurious discrepancies reports when issues a verbose str_test().
 */
static void G_GNUC_COLD
str_test_fix_exponent(char *std)
{
	char *p = std;
	int c;
	bool has_leading_space;

	has_leading_space = ' ' == *p;

	while ((c = *p++)) {
		int a;

		if ('e' == c || 'E' == c) {
			char *extra;

			c = *p++;
			if ('-' != c && '+' != c)
				goto error;	/* Not in an exponent */

			extra = p;		/* Extra '0' spot, if any present */
			c = *p++;
			if (c != '0')
				break;		/* Nothing to fix */

			c = *p++;
			if (!is_ascii_digit(c))
				goto error;	/* Only one digit after exponent, that's bad */

			c = *p++;
			if (!is_ascii_digit(c))
				break;		/* Out of number, in formatted space now */

			/*
			 * Ah, reached a third digit with an expoenent starting with '0'
			 * at ``extra'' in the string.  Move everything back by one char.
			 */

			a = *p;		/* Character after the number */

			g_assert(a == '\0' || is_ascii_space(a));

			p = extra;
			while (1) {
				*p = *(p + 1);
				if (a != '\0' && a == *p)
					break;			/* Leave trailing spaces intact */
				if ('\0' == *p++)
					break;
			}

			/*
			 * We removed one digit in the format, so we need to restore
			 * an additional leading space to compensate for the missing
			 * character, to not mess-up with the right-justification that
			 * necessarily occurred during the formatting.
			 */

			if (has_leading_space) {
				a = ' ';
				p = std;
				while (1) {
					int t = *p;
					*p++ = a;
					if ('\0' == a)
						break;
					a = t;
				}
			}

			break;			/* Done, string fixed */
		}
	}

	return;		/* OK, nothing to fix */

error:
	s_error("%s(): invalid exponent in \"%s\"", G_STRFUNC, std);
}

/**
 * Non-regression tests for the str_vncatf() formatting routine.
 *
 * Aborts execution on failure.
 *
 * @param verbose		whether to log differences with snprintf()
 *
 * @return amount of discrepancies found with the system's snprintf().
 */
size_t G_GNUC_COLD
str_test(bool verbose)
{
#define MLEN		64
#define DEADBEEF	((void *) 0xdeadbeef)
#define INTEGER		345000
#define LONG		345000L
#define PI			3.141592654
#define DOUBLE		3.45e8
#define LN2			0.69314718056
#define INF			HUGE_VAL
#define S			TRUE			/* Standard */
#define X			FALSE			/* Excluded from snprintf() consistency */

	size_t discrepancies = 0;
	static const char ANYTHING[] = "anything";
	static const char INTSTR[] = "345000";
	static const char INThex[] = "543a8";
	static const char INTHEX[] = "543A8";
	static const struct tstring {
		const char *fmt;
		bool std;
		size_t buflen;
		const char *value;
		const char *result;
	} test_strings[] = {
		{ "",			S, 10,		ANYTHING,	"" },
		{ "%%",			S, 10,		ANYTHING,	"%" },
		{ "s%st",		S, MLEN,	"tar",		"start" },
		{ "%s",			S, MLEN,	ANYTHING,	ANYTHING },
		{ "%s",			S, 5,		ANYTHING,	"anyt" },
		{ "%.2s",		S, 5,		ANYTHING,	"an" },
		{ "%.15s",		S, MLEN,	ANYTHING,	ANYTHING },
		{ "%15s",		S, MLEN,	ANYTHING,	"       anything" },
		{ "%15s",		S, 9,		ANYTHING,	"       a" },
		{ "%-15s",		S, MLEN,	ANYTHING,	"anything       " },
		{ "%-15s.",		S, MLEN,	ANYTHING,	"anything       ." },
		{ "%015s.",		X, MLEN,	ANYTHING,	"0000000anything." },
		{ "%-5s",		S, MLEN,	ANYTHING,	ANYTHING },
		{ "%-5s.",		S, MLEN,	ANYTHING,	"anything." },
	};
	static const struct tchar {
		const char *fmt;
		bool std;
		size_t buflen;
		const char value;
		const char *result;
	} test_chars[] = {
		{ "%c",			S, 10,		'\0',		"" },
		{ "%c",			S, 10,		'A',		"A" },
		{ "%c",			S, 1,		'A',		"" },
	};
	static const struct tpointer {
		const char *fmt;
		bool std;
		size_t buflen;
		void *value;
		const char *result;
	} test_pointers[] = {
		{ "%p",			S, MLEN,	DEADBEEF,	"0xdeadbeef" },
		{ "%p",			S, 5,		DEADBEEF,	"0xde" },
	};
	static const struct tint {
		const char *fmt;
		bool std;
		size_t buflen;
		int value;
		const char *result;
	} test_ints[] = {
		{ "%d",			S, MLEN,	INTEGER,	INTSTR },
		{ "%x",			S, MLEN,	INTEGER,	INThex },
		{ "%X",			S, MLEN,	INTEGER,	INTHEX },
		{ "%x",			S, 5,		INTEGER,	"543a" },
		{ "%#x",		S, 5,		INTEGER,	"0x54" },
		{ "%#x",		S, MLEN,	INTEGER,	"0x543a8" },
		{ "%#X",		S, MLEN,	INTEGER,	"0X543A8" },
		{ "%.2d",		S, MLEN,	INTEGER,	INTSTR },
		{ "%2d",		S, MLEN,	INTEGER,	INTSTR },
		{ "%'d",		X, MLEN,	INTEGER,	"345,000" },
		{ "%-8d.",		S, MLEN,	INTEGER,	"345000  ." },
		{ "%-8d.",		S, MLEN,	INTEGER,	"345000  ." },
		{ "%8d",		S, MLEN,	INTEGER,	"  345000" },
		{ "%8d",		S, 5,		INTEGER,	"  34" },
		{ "%d",			S, MLEN,	-INTEGER,	"-345000" },
		{ "%-8d.",		S, MLEN,	-INTEGER,	"-345000 ." },
		{ "%.08d",		S, MLEN,	INTEGER,	"00345000" },
		{ "%+d",		S, MLEN,	INTEGER,	"+345000" },
		{ "%+d",		S, MLEN,	-INTEGER,	"-345000" },
	};
	static const struct tlong {
		const char *fmt;
		bool std;
		size_t buflen;
		long value;
		const char *result;
	} test_longs[] = {
		{ "%ld",		S, MLEN,	LONG,		INTSTR },
		{ "%lx",		S, MLEN,	LONG,		INThex },
		{ "%lX",		S, MLEN,	LONG,		INTHEX },
		{ "%lx",		S, 5,		LONG,		"543a" },
		{ "%#lx",		S, 5,		LONG,		"0x54" },
		{ "%#lx",		S, MLEN,	LONG,		"0x543a8" },
		{ "%#lX",		S, MLEN,	LONG,		"0X543A8" },
		{ "%.2ld",		S, MLEN,	LONG,		INTSTR },
		{ "%2ld",		S, MLEN,	LONG,		INTSTR },
		{ "%'d",		X, MLEN,	LONG,		"345,000" },
		{ "%-8ld.",		S, MLEN,	LONG,		"345000  ." },
		{ "%-8ld.",		S, MLEN,	LONG,		"345000  ." },
		{ "%8ld",		S, MLEN,	LONG,		"  345000" },
		{ "%8ld",		S, 5,		LONG,		"  34" },
		{ "%ld",		S, MLEN,	-LONG,		"-345000" },
		{ "%-8ld.",		S, MLEN,	-LONG,		"-345000 ." },
		{ "%.08ld",		S, MLEN,	LONG,		"00345000" },
		{ "%+ld",		S, MLEN,	LONG,		"+345000" },
		{ "%+ld",		S, MLEN,	-LONG,		"-345000" },
	};
	static const struct tdouble {
		const char *fmt;
		bool std;
		size_t buflen;
		double value;
		const char *result;
	} test_doubles[] = {
		/* #1 */
		{ "%g",			S, MLEN,	INF,		"inf" },
		{ "%G",			S, MLEN,	INF,		"INF" },
		{ "%g",			S, MLEN,	-INF,		"-inf" },
		{ "%G",			S, MLEN,	-INF,		"-INF" },
		{ "%f",			S, MLEN,	PI,			"3.141593" },
		{ "%g",			S, MLEN,	PI,			"3.14159" },
		{ "%.1g",		S, MLEN,	PI,			"3" },
		{ "%e",			S, MLEN,	PI,			"3.141593e+00" },
		{ "%e",			S, MLEN,	-PI,		"-3.141593e+00" },
		/* #10 */
		{ "%.2e",		S, MLEN,	-PI,		"-3.14e+00" },
		{ "%.2f",		S, MLEN,	-PI,		"-3.14" },
		{ "%8.2f",		S, MLEN,	-PI,		"   -3.14" },
		{ "%g",			S, MLEN,	DOUBLE,		"3.45e+08" },
		{ "%g",			S, MLEN,	-DOUBLE,	"-3.45e+08" },
		{ "%G",			S, MLEN,	DOUBLE,		"3.45E+08" },
		{ "%e",			S, MLEN,	DOUBLE,		"3.450000e+08" },
		{ "%E",			S, MLEN,	DOUBLE,		"3.450000E+08" },
		{ "%e",			S, MLEN,	LN2,		"6.931472e-01" },
		{ "%.0e",		S, MLEN,	LN2,		"7e-01" },
		/* #20 */
		{ "%.17f",		S, MLEN,	LN2,		"0.69314718056000002" },
		{ "%.0f",		S, MLEN,	LN2,		"1" },
		{ "%.1f",		S, MLEN,	LN2,		"0.7" },
		{ "%f",			S, MLEN,	LN2,		"0.693147" },
		{ "%.5f",		S, MLEN,	LN2,		"0.69315" },
		{ "%.5f",		S, 5,		LN2,		"0.69" },
		{ "%f",			S, MLEN,	-LN2,		"-0.693147" },
		{ "%.5f",		S, MLEN,	-LN2,		"-0.69315" },
		{ "%.5f",		S, 5,		-LN2,		"-0.6" },
		{ "%g",			S, MLEN,	5434e-9,	"5.434e-06" },
		/* #30 */
		{ "%.3e",		S, MLEN,	-5434e-9,	"-5.434e-06" },
		{ "%.2g",		S, MLEN,	5434e-9,	"5.4e-06" },
		{ "%.0g",		S, MLEN,	5434e-9,	"5e-06" },
		{ "%.14f",		S, MLEN,	5434e-9,	"0.00000543400000" },
		{ "%f",			S, MLEN,	1e-7,		"0.000000" },
		{ "%f",			S, MLEN,	9e-7,		"0.000001" },
		{ "%f",			S, MLEN,	5.01e-7,	"0.000001" },
		{ "%f",			S, MLEN,	4e-7,		"0.000000" },
		{ "%f",			S, MLEN,	4e-6,		"0.000004" },
		{ "%f",			S, MLEN,	9e-6,		"0.000009" },
		/* #40 */
		{ "%f",			S, MLEN,	94e-7,		"0.000009" },
		{ "%f",			S, MLEN,	95e-7,		"0.000010" },
		{ "%f",			S, MLEN,	150,		"150.000000" },
		{ "%.0f",		S, MLEN,	150,		"150" },
		{ "%.0f",		S, MLEN,	180,		"180" },
		{ "%g",			S, MLEN,	150,		"150" },
		{ "%e",			S, MLEN,	150,		"1.500000e+02" },
		{ "%.15e",		S, MLEN,	150,		"1.500000000000000e+02" },
		{ "%.0e",		S, MLEN,	150,		"2e+02" },
		{ "%.0e",		S, MLEN,	180,		"2e+02" },
		/* #50 */
		{ "%.0e",		S, MLEN,	140,		"1e+02" },
		{ "%.0e",		S, MLEN,	149,		"1e+02" },
		{ "%.0e",		S, MLEN,	151,		"2e+02" },
		{ "%g",			S, MLEN,	15000,		"15000" },
		{ "%g",			S, MLEN,	15000.4,	"15000.4" },
		{ "%.10e",		S, MLEN,	150000.04,	"1.5000004000e+05" },
		{ "%.0f",		S, MLEN,	15000.9,	"15001" },
		{ "%.0f",		S, MLEN,	0.899,		"1" },
		{ "%.1f",		S, MLEN,	0.899,		"0.9" },
		{ "%.3f",		S, MLEN,	0.899,		"0.899" },
		/* #60 */
		{ "%.2f",		S, MLEN,	0.899,		"0.90" },
		{ "%g",			S, MLEN,	150000,		"150000" },
		{ "%g",			S, MLEN,	1500000,	"1.5e+06" },
		{ "%g",			S, MLEN,	1.5e-200,	"1.5e-200" },
		{ "%+g",		S, MLEN,	1.5e200,	"+1.5e+200" },
		{ "%+g",		S, MLEN,	-1.5e200,	"-1.5e+200" },
		{ "%12g",		S, MLEN,	-1.5e200,	"   -1.5e+200" },
		{ "%-12g.",		S, MLEN,	-1.5e200,	"-1.5e+200   ." },
		{ "%-12g.",		S, MLEN,	-1.5e20,	"-1.5e+20    ." },
		{ "%-12g.",		S, MLEN,	-1.5e09,	"-1.5e+09    ." },
		/* #70 */
		{ "%-12g.",		S, MLEN,	-1.5e-09,	"-1.5e-09    ." },
		{ "%-12g.",		S, MLEN,	+1.5e-09,	"1.5e-09     ." },
		{ "%+12g",		S, MLEN,	+1.5e-09,	"    +1.5e-09" },
		{ "%.4g",		S, MLEN,	-1.5e200,	"-1.5e+200" },
		{ "%.5g",		S, MLEN,	15000,		"15000" },
		{ "%.4g",		S, MLEN,	15000,		"1.5e+04" },
		{ "%.0f",		S, MLEN,	2e+19,		"20000000000000000000" },
		{ "%.20g",		S, MLEN,	2e+19,		"20000000000000000000" },
		{ "%.51g",		X, MLEN,	2e+50,		"20000000000000002000000000"
												"0000000000000000000000000" },
		{ "%5.4f",		S, MLEN,	4561056.99,	"4561056.9900" },
		/* #80 */
		{ "%5.2f",		S, MLEN,	4561056.99,	"4561056.99" },
		{ "%5.1f",		S, MLEN,	4561056.99,	"4561057.0" },
		{ "%5.2f",		S, MLEN,	-61056.99,	"-61056.99" },
		{ "%5.1f",		S, MLEN,	-61056.99,	"-61057.0" },
		{ "%#f",		S, MLEN,	-61056.99,	"-61056.990000" },
		{ "%#g",		S, MLEN,	5434e-9,	"5.43400e-06" },
		{ "%#e",		S, MLEN,	5434e-9,	"5.434000e-06" },
		{ "%#.0g",		S, MLEN,	5434e-9,	"5.e-06" },
		{ "%#.0e",		S, MLEN,	5434e-9,	"5.e-06" },
		{ "%#.3g",		S, MLEN,	100.0,		"100." },
		/* #90 */
		{ "%#.0e",		S, MLEN,	0.0,		"0.e+00" },
		{ "%#.0f",		S, MLEN,	0.0,		"0." },
		{ "%#.0g",		S, MLEN,	0.0,		"0." },
		{ "%g",			S, MLEN,	.00012435395457,	"0.000124354" },
		{ "%.11g",		S, MLEN,	.00012435395457,	"0.00012435395457" },
		{ "%.11g",		S, MLEN,	12435.3954575763,	"12435.395458" },
		{ "%g",			S, MLEN,	12435.3954575763,	"12435.4" },
		{ "%.17g",		S, MLEN,	12435.3954575763,	"12435.3954575763" },
		{ "%.17g",		S, MLEN,	124353954575.763,	"124353954575.763" },
		{ "%.10g",		S, MLEN,	124353954575.763,	"1.243539546e+11" },
		/* #100 */
		{ "%.11g",		S, MLEN,	124353954575.763,	"1.2435395458e+11" },
		{ "%.12g",		S, MLEN,	124353954575.763,	"124353954576" },
		{ "%.13g",		S, MLEN,	124353954575.763,	"124353954575.8" },
		{ "%.14g",		S, MLEN,	124353954575.763,	"124353954575.76" },
		{ "%F",			X, MLEN,	0,			"0" },
		{ "%F",			X, MLEN,	1,			"1" },
		{ "%F",			X, MLEN,	-1,			"-1" },
		{ "%F",			X, MLEN,	1.5,		"1.5" },
		{ "%F",			X, MLEN,	-1.5,		"-1.5" },
		{ "%F",			X, MLEN,	.5,			"0.5" },
		/* #110 */
		{ "%F",			X, MLEN,	.05,			"0.05" },
		{ "%F",			X, MLEN,	.005,			"0.005" },
		{ "%F",			X, MLEN,	.0005,			"0.0005" },
		{ "%F",			X, MLEN,	.00005,			"0.00005" },
		{ "%F",			X, MLEN,	.000005,		"5E-6" },
		{ "%F",			X, MLEN,	-.0000005,		"-5E-7" },
		{ "%F",			X, MLEN,	.0005342532345,	"0.0005342532345" },
		{ "%F",			X, MLEN,	.0005342532345536986,
													"5.342532345536986E-4" },
		{ "%F",			X, MLEN,	50,				"50" },
		{ "%F",			X, MLEN,	500,			"500" },
		/* #120 */
		{ "%F",			X, MLEN,	50000000000,	"50000000000" },
		{ "%F",			X, MLEN,	500000000000,	"5E+11" },
		{ "%F",			X, MLEN,	50000000000.25,	"50000000000.25" },
		{ "%F",			X, MLEN,	54321987654,	"54321987654" },
		{ "%F",			X, MLEN,	54321987654.999,"54321987654.999" },
		{ "%.1F",		X, MLEN,	4561056.99,		"5E+6" },
		{ "%.1F",		X, MLEN,	500000000000,	"5E+11" },
		{ "%.12F",		X, MLEN,	500000000000,	"500000000000" },
		{ "%.8F",		X, MLEN,	4561056.99,		"4561057" },
		{ "%.9F",		X, MLEN,	4561056.99,		"4561056.99" },
		/* #130 */
		{ "%F",			X, MLEN,	5.12345678901e4,"51234.5678901" },
		{ "%F",			X, MLEN,	1.2342543e200,	"1.2342543E+200" },
		{ "%#F",		X, MLEN,	0,				"0." },
		{ "%#F",		X, MLEN,	-1,				"-1." },
		{ "%#F",		X, MLEN,	.5,				"0.5" },
		{ "%#F",		X, MLEN,	500,			"500." },
		{ "%#F",		X, MLEN,	50000000000,	"50000000000." },
		{ "%#F",		X, MLEN,	500000000.1,	"500000000.1" },
		{ "%#.1F",		X, MLEN,	4561056.99,		"5.E+6" },
		{ "%g",			S, MLEN,	0.009999997868, "0.01" },
		/* #140 */
		{ "%g",			S, MLEN,	0.000999999868, "0.001" },
		{ "%g",			S, MLEN,	0.000099999998, "0.0001" },
		{ "%g",			S, MLEN,	0.1, 			"0.1" },
		{ "%g",			S, MLEN,	0.01, 			"0.01" },
		{ "%g",			S, MLEN,	0.001, 			"0.001" },
		{ "%g",			S, MLEN,	0.0001, 		"0.0001" },
		{ "%f",			S, MLEN,	0.1, 			"0.100000" },
		{ "%f",			S, MLEN,	0.01, 			"0.010000" },
		{ "%f",			S, MLEN,	0.001, 			"0.001000" },
		{ "%f",			S, MLEN,	0.0001, 		"0.000100" },
		/* #150 */
		{ "%f",			S, MLEN,	0.00001, 		"0.000010" },
		{ "%f",			S, MLEN,	0.000001, 		"0.000001" },
		{ "%f",			S, MLEN,	0.0000001, 		"0.000000" },
		{ "%#g",		S, MLEN,	0.1, 			"0.100000" },
		{ "%#g",		S, MLEN,	0.01, 			"0.0100000" },
		{ "%F",			X, MLEN,	13.005952380952381,	"13.005952380952381" },
		{ "%F",			X, MLEN,	130.05952380952381,	"130.0595238095238" },
		{ "%F",			X, MLEN,	1300.5952380952381,	"1300.595238095238" },
		{ "%F",			X, MLEN,	13005.952380952381,	"13005.952380952382" },
		{ "%F",			X, MLEN,	130059523.80952381,	"130059523.8095238" },
		/* #160 */
		{ "%F",			X, MLEN,	1300595238.0952381,	"1300595238.0952382" },
		{ "%F",			X, MLEN,	13005952380.952381,	"13005952380.952381" },
		{ "%.17F",		X, MLEN,	1300595238.0952381,	"1300595238.0952382" },
		{ "%.17F",		X, MLEN,	13005952380.952381,	"13005952380.952381" },
		{ "%.17g",		S, MLEN,	1300595238.0952381,	"1300595238.0952382" },
		{ "%.17g",		S, MLEN,	13005952380.952381,	"13005952380.952381" },
	};

#define TEST(what, vfmt) G_STMT_START {							\
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
																\
		if (t->std) {											\
			char std[MLEN];										\
			char value[MLEN];									\
			/* Avoid truncation warning in logs */				\
			gm_snprintf_unchecked(std, sizeof std,				\
				t->fmt, t->value);								\
			std[t->buflen - 1] = '\0';	/* Truncate here */		\
			if (0 == ptr_cmp(&test_##what##s, &test_doubles))	\
				str_test_fix_exponent(std);						\
			gm_snprintf(value, sizeof value, vfmt, t->value);	\
			if (0 != strcmp(std, buf)) {						\
				discrepancies++;								\
				if (verbose) g_message(							\
					"formatting %s \"%s\" in test #%u/%zu "		\
					"with \"%s\" yields "						\
					"\"%s\" with snprintf() but "				\
					"\"%s\" with str_vncatf()",					\
					#what, value,								\
					i + 1, G_N_ELEMENTS(test_##what##s),		\
					t->fmt, std, buf);							\
			}													\
		}														\
	}															\
} G_STMT_END

	tests_completed = FALSE;	/* Disables warnings on truncations */

	TEST(string,	"%s");
	TEST(char,		"%c");
	TEST(pointer,	"%p");
	TEST(int,		"%d");
	TEST(long,		"%ld");
	TEST(double,	"%.17g");

	tests_completed = TRUE;		/* Allow warnings on truncations */

	/*
	 * Make sure gm_snprintf() and str_bprintf() behave similarily.
	 *
	 * The gm_snprintf() call is a wrapper on top of libc's vsnprintf().
	 * The str_bprintf() call is a wrapper on top of our str_vncatf().
	 */

#define FORMAT	"\"%s\" on %u-byte buffer"
#define ARGS	"Testing", (unsigned) sizeof vsnp

	{
		char vsnp[28], ours[28];
		size_t vsn_count, our_count;

		STATIC_ASSERT(sizeof vsnp == sizeof ours);

		vsn_count = gm_snprintf(vsnp, sizeof vsnp, FORMAT, ARGS);
		our_count = str_bprintf(ours, sizeof ours, FORMAT, ARGS);

		g_assert_log(0 == strcmp(vsnp, ours),
			"vsnprintf() returned \"%s\", str_vncatf() returned \"%s\"",
			vsnp, ours);
		g_assert_log(vsn_count == our_count,
			"vsnprintf() returned %zu, str_vncatf() returned %zu",
			vsn_count, our_count);
		g_assert(strlen(vsnp) == vsn_count);	/* Consistency check */
		g_assert(sizeof vsnp - 1 == vsn_count);	/* Ensure we filled buffer */
	}

	return discrepancies;

#undef MLEN
#undef TEST
#undef DEADBEEF
#undef INTEGER
#undef LONG
#undef PI
#undef DOUBLE
#undef LN2
#undef FORMAT
#undef ARGS
}

/* vi: set ts=4 sw=4 cindent: */
