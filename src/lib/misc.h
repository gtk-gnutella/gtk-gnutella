/*
 * $Id$
 *
 * Copyright (c) 2001-2003, Raphael Manfredi
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
 *
 * This misc.[ch] provides several miscellaneous small routines & macros for:
 *
 * - Array size determination
 * - Flag handling
 * - Sorting constants
 * - Network related string routines
 * - Date string conversions
 * - Time string conversions
 * - Size string conversions
 * - SHA1<->base32 string conversion
 * - Tests
 * - Random numbers
 * - Stuff...
 */

#ifndef _misc_h_
#define _misc_h_

#include "config.h"				/* Needed for FreeBSD compiles */

#include <time.h>
#include <stdio.h>
#include <ctype.h>

#include <glib.h>

#define SIZE_FIELD_MAX 64		/* Max size of sprintf-ed size quantity */

/*
 * Needs to be defined if we are not using Glib 2
 */
#ifndef USE_GLIB2

#ifndef HAVE_STRLCPY
size_t strlcpy(gchar *dst, const gchar *src, size_t dst_size);
#endif

#define g_string_printf g_string_sprintf
#define g_strlcpy strlcpy
#endif

size_t concat_strings(gchar *dst, size_t size,
	const gchar *s, ...) WARN_NEED_SENTINEL;

/**
 * Cast a ``const gchar *'' to ``gchar *''. This allows the compiler to
 * print a diagnostic message if you accidently try to deconstify an
 * incompatible type. A direct typecast would hide such a mistake.
 */
static inline G_GNUC_CONST WARN_UNUSED_RESULT gchar *
deconstify_gchar(const gchar *p)
{
	return (gchar *) p;
}

static inline G_GNUC_CONST WARN_UNUSED_RESULT guint32 *
deconstify_guint32(const guint32 *p)
{
	return (guint32 *) p;
}

static inline G_GNUC_CONST WARN_UNUSED_RESULT gconstpointer
cast_to_gconstpointer(gconstpointer p)
{
	return p; 
}

static inline G_GNUC_CONST WARN_UNUSED_RESULT gpointer
cast_to_gpointer(gpointer p)
{
	return p; 
}

typedef void (*func_ptr_t)(void);
		
static inline G_GNUC_CONST WARN_UNUSED_RESULT gpointer
cast_func_to_gpointer(func_ptr_t f)
{
	union {
		func_ptr_t f;
		gpointer p;
	} u;

	u.f = f;
	return u.p;
}

static inline G_GNUC_CONST WARN_UNUSED_RESULT func_ptr_t
cast_gpointer_to_func(gconstpointer p)
{
	union {
		func_ptr_t f;
		gconstpointer p;
	} u;

	u.p = p;
	return u.f;
}

gint ascii_strcasecmp(const gchar *s1, const gchar *s2);
gint ascii_strncasecmp(const gchar *s1, const gchar *s2, size_t len);

/* ctype-like functions that allow only ASCII characters whereas the locale
 * would allow others. The parameter doesn't have to be casted to (unsigned
 * char) because these functions return false for everything out of [0..127].
 *
 * GLib 2.x has similar macros/functions but defines only a subset.
 */

static inline G_GNUC_CONST WARN_UNUSED_RESULT gboolean
is_ascii_blank(gint c)
{
	return c == 32 || c == 9;	/* space, tab */
}

static inline G_GNUC_CONST WARN_UNUSED_RESULT gboolean
is_ascii_cntrl(gint c)
{
	return (c >= 0 && c <= 31) || c == 127;
}

static inline G_GNUC_CONST WARN_UNUSED_RESULT gboolean
is_ascii_digit(gint c)
{
	return c >= 48 && c <= 57;	/* 0-9 */
}

static inline G_GNUC_CONST WARN_UNUSED_RESULT gboolean
is_ascii_xdigit(gint c)
{
	return is_ascii_digit(c) ||			/* 0-9 */
			(c >= 65 && c <= 70) ||		/* A-F */
			(c >= 97 && c <= 102);		/* a-f */
}

static inline G_GNUC_CONST WARN_UNUSED_RESULT gboolean
is_ascii_upper(gint c)
{
	return c >= 65 && c <= 90;		/* A-Z */
}

static inline G_GNUC_CONST WARN_UNUSED_RESULT gboolean
is_ascii_lower(gint c)
{
	return c >= 97 && c <= 122;		/* a-z */
}

static inline G_GNUC_CONST WARN_UNUSED_RESULT gboolean
is_ascii_alpha(gint c)
{
	return is_ascii_upper(c) || is_ascii_lower(c);	/* A-Z, a-z */
}

static inline G_GNUC_CONST WARN_UNUSED_RESULT gboolean
is_ascii_alnum(gint c)
{
	return is_ascii_alpha(c) || is_ascii_digit(c);	/* A-Z, a-z, 0-9 */
}

static inline G_GNUC_CONST WARN_UNUSED_RESULT gboolean
is_ascii_space(gint c)
{
	return c == 32 || (c >= 9 && c <= 13);
}

static inline G_GNUC_CONST WARN_UNUSED_RESULT gboolean
is_ascii_graph(gint c)
{
	return c >= 33 && c <= 126;
}

static inline G_GNUC_CONST WARN_UNUSED_RESULT gboolean
is_ascii_print(gint c)
{
	return is_ascii_graph(c) || c == 32;
}

static inline G_GNUC_CONST WARN_UNUSED_RESULT gboolean
is_ascii_punct(gint c)
{
	return c >= 33 && c <= 126 && !is_ascii_alnum(c);
}

static inline G_GNUC_CONST WARN_UNUSED_RESULT gint
ascii_toupper(gint c)
{
	return is_ascii_lower(c) ? c - 32 : c;
}

static inline G_GNUC_CONST WARN_UNUSED_RESULT gint
ascii_tolower(gint c)
{
	return is_ascii_upper(c) ? c + 32 : c;
}

#if !GLIB_CHECK_VERSION(2,4,0)
static inline WARN_UNUSED_RESULT const gchar *
g_strip_context(const gchar *id, const gchar *val)
{
	const gchar *s;

	s = id != val ? NULL : strchr(id, '|');
	return s ? ++s : val;
}
#endif /* GLib < 2.4.0 */

/**
 * Skips over all ASCII space characters starting at ``s''.
 *
 * @return a pointer to the first non-space character starting from s.
 */
static inline WARN_UNUSED_RESULT gchar *
skip_ascii_spaces(const gchar *s)
{
	while (is_ascii_space(*s))
		s++;

	return deconstify_gchar(s);
}

/**
 * Skips over all ASCII blank characters starting at ``s''.
 *
 * @return a pointer to the first non-blank character starting from s.
 */
static inline WARN_UNUSED_RESULT gchar *
skip_ascii_blanks(const gchar *s)
{
	while (is_ascii_blank(*s))
		s++;

	return deconstify_gchar(s);
}

/*
 * Determine the length of string literals
 */
#define CONST_STRLEN(x) (sizeof(x) - 1)

/*
 * Array size determination
 */
#ifndef G_N_ELEMENTS
#define G_N_ELEMENTS(arr) (sizeof (arr) / sizeof ((arr)[0]))
#endif

/*
 * Set/clear binary flags
 */
typedef guint16 flag_t;
#define set_flags(r,f) (r |= (f))
#define clear_flags(r,f) (r &= ~(f))

/*
 * Network related string routines
 */
guint32  gchar_to_ip(const gchar *);
gboolean gchar_to_ip_strict(const gchar *s, guint32 *addr, gchar const **ep);
gboolean gchar_to_ip_and_mask(const gchar *str, guint32 *ip, guint32 *netmask);
gboolean gchar_to_ip_port(const gchar *str, guint32 *ip, guint16 *port);
gboolean gchar_to_ip_and_mask(const gchar *str, guint32 *ip, guint32 *netmask);
gchar *  ip_to_gchar(guint32);
gchar *  ip2_to_gchar(guint32);
void ip_to_string(guint32 ip, gchar *buf, size_t size);
gchar *  ip_port_to_gchar(guint32, guint16);
gchar *hostname_port_to_gchar(const gchar *hostname, guint16 port);
guint32  host_to_ip(const gchar *);
const gchar *ip_to_host(guint32 addr);
gchar *  host_name(void);
#define port_is_valid(port) (port != 0)
gboolean ip_is_valid(guint32);

/*
 * Date string conversions
 */
gchar *date_to_iso_gchar(time_t date);
gchar *date_to_rfc822_gchar(time_t date);
gchar *date_to_rfc822_gchar2(time_t date);
gchar *date_to_rfc1123_gchar(time_t date);

/*
 * Time string conversions
 */
gchar *short_time(gint s);
gchar *short_uptime(gint s);

/* Use a macro so that's possible to not use difftime where it's not
 * necessary because time_t is flat encoded
 */
/* XXX: Hardcoded to difftime because there's no Configure check yet */
#if 1 || defined(USE_DIFFTIME)
#define delta_time(a, b) ((gint64) difftime((a), (b)))
#else
#define ((gint64) ((a) - (b)))
#endif

/*
 * Size string conversions
 */
const gchar *short_size(guint64 size);
const gchar *short_kb_size(guint64 size);
const gchar *short_rate(guint64 rate);
const gchar *compact_size(guint64 size);
const gchar *compact_rate(guint64 rate);
const gchar *compact_kb_size(guint32 size);
gchar *short_value(gchar *buf, size_t size, guint64 v);
gchar *compact_value(gchar *buf, size_t size, guint64 v);

/*
 * SHA1<->base32 string conversion
 */
gchar *sha1_base32(const gchar *sha1);
gchar *base32_sha1(const gchar *base32);

/*
 * GUID<->hex string conversion
 */
gchar *guid_hex_str(const gchar *guid);
gboolean hex_to_guid(const gchar *hexguid, gchar *guid);

/*
 * GUID<->base32 string conversion
 */
gchar *guid_base32_str(const gchar *guid);
gchar *base32_to_guid(const gchar *base32);

/*
 * Tests
 */
gboolean is_string_ip(const gchar *);
gboolean is_private_ip(guint32 ip);
gboolean is_absolute_path(const char *);
gboolean is_directory(const gchar *);
gboolean is_regular(const gchar *);
gboolean is_symlink(const gchar *);
gboolean file_exists(const gchar *);
guint32 next_pow2(guint32 n);

static inline G_GNUC_CONST gboolean
is_pow2(guint32 value)
{
	return value && !(value & (value - 1));
}

/*
 * Random numbers
 */
void random_init(void);
guint32 random_value(guint32 max) WARN_UNUSED_RESULT;
void guid_random_fill(gchar *xuid);

/*
 * Stuff
 */
gint str_chomp(gchar *str, gint len);
gint hex2dec(guchar c);
gboolean is_printable(const gchar *buf, gint len);
void dump_hex(FILE *, const gchar *, gconstpointer, gint);
void locale_strlower(gchar *, const gchar *);
void ascii_strlower(gchar *dst, const gchar *src);
gint strcmp_delimit(const gchar *a, const gchar *b, const gchar *delimit);
gint strcasecmp_delimit(const gchar *a, const gchar *b, const gchar *delimit);
char *unique_filename(const gchar *path, const gchar *file, const gchar *ext);
gchar *hex_escape(const gchar *name, gboolean strict);
gint highest_bit_set(guint32 n) G_GNUC_CONST;
gfloat force_range(gfloat value, gfloat min, gfloat max);
gchar *make_pathname(const gchar *dir, const gchar *file);
gchar *short_filename(gchar *fullname);
gchar *data_hex_str(const gchar *data, size_t len);
gint create_directory(const gchar *dir);
gboolean filepath_exists(const gchar *dir, const gchar *file);
guint32 parse_uint32(const gchar *, gchar const **, gint, gint *);
guint64 parse_uint64(const gchar *, gchar const **, gint, gint *);
gchar * uint64_to_string_buf(gchar *dst, size_t size, guint64 v);
const gchar * uint64_to_string(guint64 v);
const gchar * uint64_to_string2(guint64 v);
gint parse_major_minor(const gchar *src, gchar const **endptr,
	guint *major, guint *minor);
gchar *is_strprefix(const gchar *str, const gchar *prefix) WARN_UNUSED_RESULT;

typedef void (*signal_handler_t)(gint signo);
signal_handler_t set_signal(gint signo, signal_handler_t handler);

gchar *ascii_strcasestr(const gchar *haystack, const gchar *needle);

#define NULL_STRING(s) (s != NULL ? s : "(null)")

/**
 * Swap endianness of a guint32.
 *
 * @param i the guint32 to swap
 *
 * @returns the value of i after swapping its byte order.
 */
static inline G_GNUC_CONST guint32
swap_guint32(guint32 i)
{
	gint a = i & 0x000000ff;
	gint b = (i & 0x0000ff00) >> 8;
	gint c = (i & 0x00ff0000) >> 16;
	gint d = (i & 0xff000000) >> 24;

	return d + (c << 8) + (b << 16) + (a << 24);
}

/*
 * Syscall wrappers for errno == 0 bug. --RAM, 27/10/2003
 */

struct stat;

extern gint do_errno;

gint do_stat(const gchar *path, struct stat *buf);

/*
 * CIDR split of IP range.
 */

typedef void (*cidr_split_t)(guint32 ip, guint bits, gpointer udata);

void ip_range_split(
	guint32 lower_ip, guint32 upper_ip, cidr_split_t cb, gpointer udata);

/**
 * Perform a binary search over an array.
 *
 * bs_type is the type of bs_item
 * bs_key is the key to lookup
 * bs_size is the array length
 * bs_cmp(bs_item, bs_key) is used to compare the key with the current item
 * bs_get_key(bs_index) must return the key at bs_index
 * bs_found(bs_index) is executed if bs_key is found
 *
 * All local variables are prefixed with bs_ to prevent clashes with
 * other visible variables.
 */
#define BINARY_SEARCH(bs_type, bs_key, bs_size, bs_cmp, bs_get_key, bs_found) \
do { \
	size_t bs_index, bs_j = 0, bs_k; \
	for (bs_k = (bs_size); bs_k != 0; bs_k >>= 1) { \
		bs_type bs_item; \
		gint bs_cmp_result; \
\
		bs_index = bs_j + (bs_k >> 1); \
		bs_item = bs_get_key(bs_index); \
		bs_cmp_result = bs_cmp(bs_item, bs_key); \
		if (0 == bs_cmp_result) {	\
			bs_found(bs_index); \
			break; \
		} else if (bs_cmp_result < 0) { \
			bs_j = bs_index + 1; \
			bs_k--; \
		} \
	} \
} while (0)

#endif /* _misc_h_ */

/* vi: set ts=4 sw=4 cindent: */
