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

#include <time.h>
#include <stdio.h>

#include "config.h"				/* Needed for FreeBSD compiles */

/* The RCS IDs can be looked up from the compiled binary with e.g. `what'  */
#ifdef __GNUC__
#define RCSID(x) \
	static const char rcsid[] __attribute__((__unused__)) = "@(#) " x
#else
#define RCSID(x) static const char rcsid[] = "@(#) " x
#endif

#define SIZE_FIELD_MAX 64		/* Max size of sprintf-ed size quantity */


/*
 * Needs to be defined if we are not using Glib 2
 */
#ifndef USE_GTK2

#ifndef HAVE_STRLCPY
size_t strlcpy(gchar *dst, const gchar *src, size_t dst_size);
#endif

#define g_ascii_strcasecmp g_strcasecmp
#define g_ascii_strncasecmp g_strncasecmp
#define g_string_printf g_string_sprintf
#define g_strlcpy strlcpy
#endif

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
#define set_flags(r,f) (r = r | (f))
#define clear_flags(r,f) (r = r & ~(f))

/*
 * Sorting constants
 */
#define SORT_ASC  1
#define SORT_DESC (-1)
#define SORT_NONE 0
#define SORT_NO_COL 0		/* On search creation, no column chosen for sort */

/* SIGN() returns whether a is smaller (-1), equal (0) or greater (1) than b */
#define SIGN(a, b) ((a) == (b) ? 0 : (a) > (b) ? 1 : (-1))

/*
 * Network related string routines
 */
guint32  gchar_to_ip(const gchar *);
gboolean gchar_to_ip_port(const gchar *str, guint32 *ip, guint16 *port);
gboolean gchar_to_ip_and_mask(const gchar *str, guint32 *ip, guint32 *netmask);
gchar *  ip_to_gchar(guint32);
gchar *  ip2_to_gchar(guint32);
gchar *  ip_port_to_gchar(guint32, guint16);
gchar *hostname_port_to_gchar(const gchar *hostname, guint16 port);
guint32  host_to_ip(const gchar *);
gchar *  host_name(void);
gboolean host_is_valid(guint32, guint16);

/*
 * Date string conversions
 */
gchar *date_to_iso_gchar(time_t date);
gchar *date_to_rfc822_gchar(time_t date);
gchar *date_to_rfc822_gchar2(time_t date);

/*
 * Time string conversions
 */
gchar *short_time(time_t s);
gchar *short_uptime(time_t s);

/*
 * Size string conversions
 */
gchar *short_size(guint32);
gchar *short_size64(guint64 size);
gchar *short_kb_size(guint32);
gchar *compact_size(guint32 size);
gchar *compact_size64(guint64 size);
gchar *compact_kb_size(guint32 size);

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
gboolean is_directory(const gchar *);
gboolean is_regular(const gchar *);
gboolean is_symlink(const gchar *);
gboolean file_exists(const gchar *);
gboolean is_pow2(guint32 value);
guint32 next_pow2(guint32 n);

/*
 * Random numbers
 */
void random_init(void);
guint32 random_value(guint32 max);

/*
 * Stuff
 */
gint str_chomp(gchar *str, gint len);
gint hex2dec(guchar c);
void dump_hex(FILE *, const gchar *, gconstpointer, gint);
void strlower(gchar *, const gchar *);
gint strcmp_delimit(const gchar *a, const gchar *b, const gchar *delimit);
char *unique_filename(const gchar *path, const gchar *file, const gchar *ext);
gchar *hex_escape(const gchar *name, gboolean strict);
gint highest_bit_set(guint32 n);
gfloat force_range(gfloat value, gfloat min, gfloat max);

#ifdef HAVE_STRCASESTR
char *strcasestr(const char *haystack, const char *needle);
#else
gchar *strcasestr(const gchar *haystack, const gchar *needle);
#endif

/*
 * Syscall wrappers for errno == 0 bug. --RAM, 27/10/2003
 */

struct stat;

extern gint do_errno;

gint do_stat(const gchar *path, struct stat *buf);

#endif /* _misc_h_ */
