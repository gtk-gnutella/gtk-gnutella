/*
 * Copyright (c) 2006 Christian Biere
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
 * @file
 *
 * Functions for safer casting. 
 *
 * @author Christian Biere
 * @date 2006
 */

#ifndef _casts_h_
#define _casts_h_

/* @note This file is only for inclusion by common.h. */

/*
 * Cast a ``const type *'' to ``type *''. This allows the compiler to
 * print a diagnostic message if you accidently try to deconstify an
 * incompatible type. A direct typecast would hide such a mistake.
 */

static inline G_CONST WARN_UNUSED_RESULT ALWAYS_INLINE gboolean *
deconstify_gboolean(const gboolean *p)
{
	return (gboolean *) p;
}

static inline G_CONST WARN_UNUSED_RESULT ALWAYS_INLINE bool *
deconstify_bool(const bool *p)
{
	return (bool *) p;
}

static inline G_CONST WARN_UNUSED_RESULT ALWAYS_INLINE char *
deconstify_gchar(const char *p)
{
	return (char *) p;
}

static inline G_CONST WARN_UNUSED_RESULT ALWAYS_INLINE char *
deconstify_char(const char *p)
{
	return (char *) p;
}

static inline G_CONST WARN_UNUSED_RESULT ALWAYS_INLINE uint32 *
deconstify_uint32(const uint32 *p)
{
	return (uint32 *) p;
}

static inline G_CONST WARN_UNUSED_RESULT ALWAYS_INLINE void * 
deconstify_gpointer(const void *p)
{
	return (void *) p;
}

static inline G_CONST WARN_UNUSED_RESULT ALWAYS_INLINE void * 
deconstify_pointer(const void *p)
{
	return (void *) p;
}

static inline G_CONST WARN_UNUSED_RESULT ALWAYS_INLINE const void *
cast_to_gconstpointer(const void *p)
{
	return p; 
}

static inline G_CONST WARN_UNUSED_RESULT ALWAYS_INLINE const void *
cast_to_constpointer(const void *p)
{
	return p; 
}

static inline G_CONST WARN_UNUSED_RESULT ALWAYS_INLINE void *
cast_to_gpointer(void *p)
{
	return p;
}

static inline G_CONST WARN_UNUSED_RESULT ALWAYS_INLINE void *
cast_to_pointer(void *p)
{
	return p;
}

#ifndef  __cplusplus
static inline G_CONST WARN_UNUSED_RESULT ALWAYS_INLINE char *
cast_to_gchar_ptr(void *p)
{
	return p;
}
#endif	/* !C++ */

static inline G_CONST WARN_UNUSED_RESULT ALWAYS_INLINE void *
cast_to_void_ptr(void *p)
{
	return p;
}

#ifndef  __cplusplus
static inline G_CONST WARN_UNUSED_RESULT ALWAYS_INLINE char *
cast_to_char_ptr(void *p)
{
	return p;
}

static inline G_CONST WARN_UNUSED_RESULT ALWAYS_INLINE unsigned char *
cast_to_guchar_ptr(void *p)
{
	return p;
}
#endif	/* !C++ */

static inline G_CONST WARN_UNUSED_RESULT ALWAYS_INLINE void *
ulong_to_pointer(unsigned long value)
{
	return (void *) value;
}

static inline G_CONST WARN_UNUSED_RESULT ALWAYS_INLINE void *
long_to_pointer(long value)
{
	return (void *) value;
}

static inline G_CONST WARN_UNUSED_RESULT ALWAYS_INLINE void *
size_to_pointer(size_t value)
{
	return (void *) value;
}

static inline G_CONST WARN_UNUSED_RESULT ALWAYS_INLINE unsigned long
pointer_to_ulong(const void *p)
{
	return (unsigned long) p;
}

static inline G_CONST WARN_UNUSED_RESULT ALWAYS_INLINE long
pointer_to_long(const void *p)
{
	return (long) p;
}

static inline G_CONST WARN_UNUSED_RESULT ALWAYS_INLINE size_t
pointer_to_size(const void *p)
{
	return (size_t) p;
}

static inline G_CONST WARN_UNUSED_RESULT ALWAYS_INLINE void *
uint_to_pointer(unsigned value)
{
	return ulong_to_pointer(value);
}

static inline G_CONST WARN_UNUSED_RESULT ALWAYS_INLINE unsigned
pointer_to_uint(const void *p)
{
	return pointer_to_ulong(p);
}

static inline G_CONST WARN_UNUSED_RESULT ALWAYS_INLINE void *
int_to_pointer(int value)
{
	return uint_to_pointer(value);
}

static inline G_CONST WARN_UNUSED_RESULT ALWAYS_INLINE int
pointer_to_int(const void *p)
{
	return pointer_to_uint(p);
}

static inline G_CONST WARN_UNUSED_RESULT ALWAYS_INLINE void *
bool_to_pointer(bool value)
{
	return ulong_to_pointer(value);
}

static inline G_CONST WARN_UNUSED_RESULT ALWAYS_INLINE bool
pointer_to_bool(const void *p)
{
	return p != NULL;
}

typedef void (*func_ptr_t)();

static inline G_CONST WARN_UNUSED_RESULT ALWAYS_INLINE func_ptr_t
cast_pointer_to_func(const void *p)
{
	union {
		func_ptr_t func;
		const void *ptr;
	} tmp;
	tmp.ptr = p;
	return tmp.func;
}

static inline G_CONST WARN_UNUSED_RESULT ALWAYS_INLINE void *
cast_func_to_pointer(func_ptr_t func)
{
	union {
		func_ptr_t func;
		void *ptr;
	} tmp;
	tmp.func = func;
	return tmp.ptr;
}

static inline G_CONST WARN_UNUSED_RESULT ALWAYS_INLINE free_fn_t
cast_to_free_fn(const func_ptr_t fn)
{
	return (free_fn_t) fn;
}

/**
 * Casting of a random function pointer to "void *" is cumbersome if
 * you want to spell it out in a pedantic-safe way.  That's where the
 * func_to_pointer() macro is handy.
 */
#define func_to_pointer(x)	cast_func_to_pointer((func_ptr_t) (x))

static inline size_t G_CONST WARN_UNUSED_RESULT ALWAYS_INLINE
ptr_diff(const void *a, const void *b)
{
	return (const char *) a - (const char *) b;
}

static inline void * G_CONST WARN_UNUSED_RESULT ALWAYS_INLINE
ptr_add_offset(void *p, size_t offset)
{
	/* Using size_t instead of 'char *' because pointers don't wrap. */
	return (void *) ((size_t) p + offset);
}

static inline const void * G_CONST WARN_UNUSED_RESULT ALWAYS_INLINE
const_ptr_add_offset(const void *p, size_t offset)
{
	/* Using size_t instead of 'char *' because pointers don't wrap. */
	return (const void *) ((size_t) p + offset);
}

/*
 * Deconstify resulting pointer.
 */
static inline void * G_CONST WARN_UNUSED_RESULT ALWAYS_INLINE
ptr_add_offset_const(const void *p, size_t offset)
{
	/* Using size_t instead of 'char *' because pointers don't wrap. */
	return (void *) ((size_t) p + offset);
}


/**
 * Compare two generic pointers.
 */
static inline int G_CONST WARN_UNUSED_RESULT ALWAYS_INLINE
ptr_cmp(const void *a, const void *b)
{
	return CMP((const char *) a, (const char *) b);
}

/**
 * Converts a filesize_t to fileoffset_t.
 *
 * @return On failure (fileoffset_t) -1 is returned.
 */
static inline fileoffset_t G_CONST WARN_UNUSED_RESULT ALWAYS_INLINE
filesize_to_fileoffset_t(filesize_t pos)
{
	fileoffset_t offset = pos > OFF_T_MAX ?
		(fileoffset_t) -1 : (fileoffset_t) pos;

	/* Handle -1 explicitly just in case there might be platform with
	 * an non-standard unsigned fileoffset_t.
	 */
	if ((fileoffset_t) -1 == offset || offset < 0) {
		return (fileoffset_t) -1;
	}
	return offset;
}

/**
 * Implicit promotion to an unsigned integer. It allows one to avoid
 * comparision of signed values with unsigned values without resorting
 * to harmful explicit casts.
 */
#if defined(UINTMAX_C)
#define UNSIGNED(value) ((value) + (UINTMAX_C(0)))
#elif defined(UINTMAX_MAX)
#define UNSIGNED(value) ((value) + (UINTMAX_MAX - UINTMAX_MAX))
#else
#define UNSIGNED(value) ((value) + ((uint64)0U))
#endif	/* UINTMAX_C */

/* Normalize boolean-like values to TRUE(1) or FALSE(0) */
#define booleanize(x) (0 != (x))

/* Common logic operations missing an operator in C */
#define implies(p, q) (!(p) || (q))
#define equiv(p, q)   (!(p) == !(q))

#endif /* _casts_h_ */

/* vi: set ts=4 sw=4 cindent: */
