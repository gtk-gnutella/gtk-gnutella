/*
 * $Id$
 *
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

/**
 * Cast a ``const gchar *'' to ``gchar *''. This allows the compiler to
 * print a diagnostic message if you accidently try to deconstify an
 * incompatible type. A direct typecast would hide such a mistake.
 */
static inline G_GNUC_CONST WARN_UNUSED_RESULT ALWAYS_INLINE gboolean *
deconstify_gboolean(const gboolean *p)
{
	return (gboolean *) p;
}

static inline G_GNUC_CONST WARN_UNUSED_RESULT ALWAYS_INLINE char *
deconstify_gchar(const char *p)
{
	return (char *) p;
}

static inline G_GNUC_CONST WARN_UNUSED_RESULT ALWAYS_INLINE guint32 *
deconstify_guint32(const guint32 *p)
{
	return (guint32 *) p;
}

static inline G_GNUC_CONST WARN_UNUSED_RESULT ALWAYS_INLINE void * 
deconstify_gpointer(const void *p)
{
	return (void *) p;
}

static inline G_GNUC_CONST WARN_UNUSED_RESULT ALWAYS_INLINE const void *
cast_to_gconstpointer(const void *p)
{
	return p; 
}

static inline G_GNUC_CONST WARN_UNUSED_RESULT ALWAYS_INLINE void *
cast_to_gpointer(void *p)
{
	return p;
}

static inline G_GNUC_CONST WARN_UNUSED_RESULT ALWAYS_INLINE char *
cast_to_gchar_ptr(void *p)
{
	return p;
}

static inline G_GNUC_CONST WARN_UNUSED_RESULT ALWAYS_INLINE unsigned char *
cast_to_guchar_ptr(void *p)
{
	return p;
}

static inline G_GNUC_CONST WARN_UNUSED_RESULT ALWAYS_INLINE void *
ulong_to_pointer(unsigned long value)
{
	return (void *) value;
}

static inline G_GNUC_CONST WARN_UNUSED_RESULT ALWAYS_INLINE unsigned long
pointer_to_ulong(const void *p)
{
	return (unsigned long) p;
}

static inline G_GNUC_CONST WARN_UNUSED_RESULT ALWAYS_INLINE void *
uint_to_pointer(unsigned value)
{
	return ulong_to_pointer(value);
}

static inline G_GNUC_CONST WARN_UNUSED_RESULT ALWAYS_INLINE unsigned
pointer_to_uint(const void *p)
{
	return pointer_to_ulong(p);
}

static inline G_GNUC_CONST WARN_UNUSED_RESULT ALWAYS_INLINE void *
int_to_pointer(int value)
{
	return uint_to_pointer(value);
}

static inline G_GNUC_CONST WARN_UNUSED_RESULT ALWAYS_INLINE int
pointer_to_int(const void *p)
{
	return pointer_to_uint(p);
}

typedef void (*func_ptr_t)(void);

static inline G_GNUC_CONST WARN_UNUSED_RESULT ALWAYS_INLINE func_ptr_t
cast_pointer_to_func(const void *p)
{
	return (func_ptr_t) p;
}

static inline size_t G_GNUC_CONST WARN_UNUSED_RESULT ALWAYS_INLINE
ptr_diff(const void *a, const void *b)
{
	return (const char *) a - (const char *) b;
}

/**
 * Converts a filesize_t to off_t.
 *
 * @return On failure (off_t) -1 is returned.
 */
static inline off_t G_GNUC_CONST WARN_UNUSED_RESULT ALWAYS_INLINE
filesize_to_off_t(filesize_t pos)
{
	off_t offset = pos > OFF_T_MAX ? (off_t) -1 : (off_t) pos;

	/* Handle -1 explicitly just in case there might be platform with
	 * an non-standard unsigned off_t.
	 */
	if ((off_t) -1 == offset || offset < 0) {
		return (off_t) -1;
	}
	return offset;
}

/**
 * Implicit promotion to an unsigned integer. It allows to avoid comparision of
 * signed values with unsigned values without resorting to harmful explicit
 * casts.
 */
#if defined(UINTMAX_C)
#define UNSIGNED(value) ((value) + (UINTMAX_C(0)))
#elif defined(UINTMAX_MAX)
#define UNSIGNED(value) ((value) + (UINTMAX_MAX - UINTMAX_MAX))
#else
#define UNSIGNED(value) ((value) + ((guint64)0U))
#endif	/* UINTMAX_C */

#endif /* _casts_h_ */

/* vi: set ts=4 sw=4 cindent: */
