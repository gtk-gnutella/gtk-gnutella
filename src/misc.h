/*
 * $Id$
 *
 * Copyright (c) 2001-2002, Raphael Manfredi
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

#ifndef __misc_h__
#define __misc_h__

#include <time.h>
#include <stdio.h>

#include "config.h"				/* Needed for FreeBSD compiles */

/* The RCS IDs can be looked up from the compiled binary with e.g. `what'  */
#ifdef __GNUC__
#define RCSID(x) static const char rcsid[] __attribute__((__unused__)) = "@(#) " x
#else
#define RCSID(x) static const char rcsid[] = "@(#) " x
#endif

#define SIZE_FIELD_MAX 64		/* Max size of sprintf-ed size quantity */


/*
 * Needs to be defined if we are not using Glib 2
 */
#ifndef USE_GTK2
#define g_ascii_strcasecmp g_strcasecmp
#define g_ascii_strncasecmp g_strncasecmp
#define g_string_printf g_string_sprintf
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
#define SORT_DESC -1
#define SORT_NONE 0

/*
 * Network related string routines
 */
guint32  gchar_to_ip(const gchar *);
gboolean gchar_to_ip_port(gchar *str, guint32 *ip, guint16 *port);
gchar *  ip_to_gchar(guint32);
gchar *  ip_port_to_gchar(guint32, guint16);
guint32  host_to_ip(gchar *);
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
gchar *short_time(guint32 s);
gchar *short_uptime(guint32 s);

/*
 * Size string conversions
 */
gchar *short_size(guint32);
gchar *short_kb_size(guint32);
gchar *compact_size(guint32 size);

/*
 * SHA1<->base32 string conversion
 */
gchar *sha1_base32(const guchar *sha1);
guchar *base32_sha1(const gchar *base32);

/*
 * Tests
 */
gboolean is_string_ip(const gchar *);
gboolean is_private_ip(guint32 ip);
gboolean is_directory(const gchar *);
gboolean file_exists(gchar *);
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
gchar *guid_hex_str(guchar *guid);
gint hex2dec(gchar c);
void hex_to_guid(gchar *hexguid, guchar *guid);
void dump_hex(FILE *, gchar *, gchar *, gint);
void strlower(gchar *, gchar *);
gchar *unique_filename(gchar *path, gchar *file, gchar *ext);

#ifdef HAVE_STRCASESTR
char *strcasestr(const char *haystack, const char *needle);
#else
guchar *strcasestr(const guchar *haystack, const guchar *needle);
#endif

#endif /* __misc_h__ */
