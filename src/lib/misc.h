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
 */

/**
 * @ingroup lib
 * @file
 *
 * Misc functions.
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
 *
 * @author Raphael Manfredi
 * @date 2001-2003
 */

#ifndef _misc_h_
#define _misc_h_

#include "common.h"

#include "compat_sleep_ms.h"
#include "fs_free_space.h"
#include "tm.h"
#include "vmm.h"

#define SIZE_FIELD_MAX 64		/**< Max size of sprintf-ed size quantity */
#define GUID_RAW_SIZE		16	/**< Binary representation of 128 bits */
#define GUID_HEX_SIZE		32	/**< Hexadecimal GUID representation */
#define GUID_BASE32_SIZE	26	/**< base32 GUID representation */

typedef struct short_string {
	gchar str[SIZE_FIELD_MAX];
} short_string_t;

/**
 * Needs to be defined if we are not using Glib 2
 */
#ifndef USE_GLIB2

#ifndef HAS_STRLCPY
size_t strlcpy(gchar *dst, const gchar *src, size_t dst_size);
#endif /* HAS_STRLCPY */

#ifndef HAS_STRLCAT
size_t strlcat(gchar *dst, const gchar *src, size_t dst_size);
#endif /* HAS_STRLCAT */

#define g_string_printf g_string_sprintf
#define g_strlcpy strlcpy
#define g_strlcat strlcat
#endif

size_t concat_strings(gchar *dst, size_t size,
	const gchar *s, ...) G_GNUC_NULL_TERMINATED;
size_t w_concat_strings(gchar **dst,
	const gchar *first, ...) G_GNUC_NULL_TERMINATED;

gint ascii_strcasecmp(const gchar *s1, const gchar *s2);
gint ascii_strncasecmp(const gchar *s1, const gchar *s2, size_t len);

/**
 * Converts an integer to a single hexadecimal ASCII digit. The are no checks,
 * this is just a convenience function.
 *
 * @param x An integer between 0 and 15.
 * @return The ASCII character corresponding to the hex digit [0-9a-f].
 */
static inline guchar
hex_digit(guchar x)
{
	extern const char hex_alphabet_lower[];
	return hex_alphabet_lower[x & 0xf]; 
}

/**
 * Converts a hexadecimal char (0-9, A-F, a-f) to an integer.
 *
 * @param c the character to convert.
 * @return 0..15 for valid hexadecimal ASCII characters, -1 otherwise.
 */
static inline gint
hex2int_inline(guchar c)
{
	extern const gint8 *hex2int_tab;
	return hex2int_tab[c];
}

/**
 * Converts a decimal char (0-9) to an integer.
 *
 * @param c the character to convert.
 * @return 0..9 for valid decimal ASCII characters, -1 otherwise.
 */
static inline gint
dec2int_inline(guchar c)
{
	extern const gint8 *dec2int_tab;
	return dec2int_tab[c];
}

/**
 * Converts an alphanumeric char (0-9, A-Z, a-z) to an integer.
 *
 * @param c the character to convert.
 * @return 0..9 for valid alphanumeric ASCII characters, -1 otherwise.
 */
static inline gint
alnum2int_inline(guchar c)
{
	extern const gint8 *alnum2int_tab;
	return alnum2int_tab[c];
}

/**
 * ctype-like functions that allow only ASCII characters whereas the locale
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
	return -1 != hex2int_inline(c) && !(c & ~0x7f);
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
	return -1 != alnum2int_inline(c) && !(c & ~0x7f); /* A-Z, a-z, 0-9 */
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
 * Skips over all characters which are not ASCII spaces starting at ``s''.
 *
 * @return a pointer to the first space or NUL character starting from s.
 */
static inline WARN_UNUSED_RESULT gchar *
skip_ascii_non_spaces(const gchar *s)
{
	while ('\0' != *s && !is_ascii_space(*s))
		s++;

	return deconstify_gchar(s);
}

/**
 * Skips over all characters which are ASCII alphanumerical characters
 * starting at ``s''.
 *
 * @return a pointer to the first space or NUL character starting from s.
 */
static inline WARN_UNUSED_RESULT gchar *
skip_ascii_alnum(const gchar *s)
{
	while (is_ascii_alnum(*s))
		s++;

	return deconstify_gchar(s);
}

/**
 * Skips over all ASCII blank characters starting at ``s''.
 *
 * @return A pointer to the first non-blank character starting from s.
 */
static inline WARN_UNUSED_RESULT gchar *
skip_ascii_blanks(const gchar *s)
{
	while (is_ascii_blank(*s))
		s++;

	return deconstify_gchar(s);
}

static inline WARN_UNUSED_RESULT gchar *
skip_dir_separators(const gchar *s)
{
	while ('/' == s[0] || G_DIR_SEPARATOR == s[0])
		s++;

	return deconstify_gchar(s);
}

/*
 * Determine the length of string literals
 */
#define CONST_STRLEN(x) (sizeof(x) - 1)

/*
 * Set/clear binary flags
 */
typedef guint16 flag_t;
#define set_flags(r,f) (r |= (f))
#define clear_flags(r,f) (r &= ~(f))

/*
 * Macros to determine the maximum buffer size required to hold a
 * NUL-terminated string.
 */
#define UINT8_HEX_BUFLEN	(sizeof "FF")
#define UINT8_DEC_BUFLEN	(sizeof "255")
#define UINT16_HEX_BUFLEN	(sizeof "01234")
#define UINT16_DEC_BUFLEN	(sizeof "65535")
#define UINT32_HEX_BUFLEN	(sizeof "012345678")
#define UINT32_DEC_BUFLEN	(sizeof "4294967295")
#define UINT64_HEX_BUFLEN	(sizeof "0123456789ABCDEF")
#define UINT64_DEC_BUFLEN	(sizeof "18446744073709551615")
#define IPV4_ADDR_BUFLEN	(sizeof "255.255.255.255")
#define IPV6_ADDR_BUFLEN \
	  (sizeof "0001:0203:0405:0607:0809:1011:255.255.255.255")
#define TIMESTAMP_BUF_LEN	(sizeof "9999-12-31 23:59:61")
#define OFF_T_DEC_BUFLEN	(sizeof(off_t) * CHAR_BIT) /* very roughly */
#define TIME_T_DEC_BUFLEN	(sizeof(time_t) * CHAR_BIT) /* very roughly */

#define HOST_ADDR_BUFLEN	(MAX(IPV4_ADDR_BUFLEN, IPV6_ADDR_BUFLEN))
#define HOST_ADDR_PORT_BUFLEN	(HOST_ADDR_BUFLEN + sizeof ":[65535]")

gboolean parse_ipv6_addr(const gchar *s, uint8_t *dst, const gchar **endptr);
const gchar *ipv6_to_string(const guint8 *ipv6);
size_t ipv6_to_string_buf(const guint8 *ipv6, gchar *dst, size_t size);

/*
 * Network related string routines
 */
guint32  string_to_ip(const gchar *);
gboolean string_to_ip_strict(const gchar *s, guint32 *addr, const gchar **ep);
gboolean string_to_ip_and_mask(const gchar *str, guint32 *ip, guint32 *netmask);
gboolean string_to_ip_port(const gchar *str, guint32 *ip, guint16 *port);
const gchar *ip_to_string(guint32);
size_t ipv4_to_string_buf(guint32 ip, gchar *buf, size_t size);
const gchar *hostname_port_to_string(const gchar *hostname, guint16 port);
const gchar *local_hostname(void);
#define port_is_valid(port) (port != 0)

/*
 * Date string conversions
 */
const gchar *timestamp_to_string(time_t date);
const gchar *timestamp_utc_to_string(time_t date);
const gchar *timestamp_rfc822_to_string(time_t date);
const gchar *timestamp_rfc822_to_string2(time_t date);
const gchar *timestamp_rfc1123_to_string(time_t date);

size_t timestamp_to_string_buf(time_t date, gchar *dst, size_t size);
size_t timestamp_utc_to_string_buf(time_t date, gchar *dst, size_t size);
size_t time_locale_to_string_buf(time_t date, gchar *dst, size_t size);

short_string_t timestamp_get_string(time_t date);

/*
 * Time string conversions
 */
const gchar *short_time(time_delta_t s);
const gchar *short_time_ascii(time_delta_t t);
const gchar *short_uptime(time_delta_t s);
const gchar *compact_time(time_delta_t t);

/*
 * Size string conversions
 */
const gchar *short_size(guint64 size, gboolean metric);
const gchar *short_html_size(guint64 size, gboolean metric);
const gchar *short_kb_size(guint64 size, gboolean metric);
const gchar *short_rate(guint64 rate, gboolean metric);
const gchar *compact_size(guint64 size, gboolean metric);
const gchar *compact_rate(guint64 rate, gboolean metric);
const gchar *compact_kb_size(guint32 size, gboolean metric);
const gchar *nice_size(guint64 size, gboolean metric);
gchar *short_value(gchar *buf, size_t size, guint64 v, gboolean metric);
gchar *compact_value(gchar *buf, size_t size, guint64 v, gboolean metric);

short_string_t short_rate_get_string(guint64 rate, gboolean metric);

/*
 * SHA1<->base32 string conversion
 */
typedef struct sha1 {
	char data[SHA1_RAW_SIZE];
} sha1_t;

#define SHA1_URN_LENGTH	(CONST_STRLEN("urn:sha1:") + SHA1_BASE32_SIZE)

const char *sha1_to_string(const struct sha1 sha1);
const char *sha1_to_urn_string(const struct sha1 *);
size_t sha1_to_urn_string_buf(const struct sha1 *, char *dst, size_t size);
char *sha1_to_base32_buf(const struct sha1 *, char *dst, size_t size);
const char *sha1_base32(const struct sha1 *);
const struct sha1 *base32_sha1(const char *base32);

static inline int
sha1_cmp(const struct sha1 *a, const struct sha1 *b)
{
	return memcmp(a, b, SHA1_RAW_SIZE);
}

/*
 * TTH <-> base32 string conversion
 */
typedef struct tth {
	char data[TTH_RAW_SIZE];
} tth_t;

#define TTH_URN_LENGTH	(CONST_STRLEN("urn:ttroot:") + TTH_BASE32_SIZE)

const char *tth_base32(const struct tth *);
const struct tth *base32_tth(const char *base32);
const char *tth_to_urn_string(const struct tth *);
size_t tth_to_urn_string_buf(const struct tth *, char *dst, size_t size);
char *tth_to_base32_buf(const struct tth *, char *dst, size_t size);


const char *bitprint_to_urn_string(const struct sha1 *, const struct tth *);

/*
 * GUID<->hex string conversion
 */
const gchar *guid_hex_str(const gchar *guid);
gboolean hex_to_guid(const gchar *hexguid, gchar *guid);
size_t guid_to_string_buf(const gchar *guid, gchar *dst, size_t size);
const gchar *guid_to_string(const gchar *guid);

/*
 * GUID<->base32 string conversion
 */
gchar *guid_base32_str(const gchar *guid);
gchar *base32_to_guid(const gchar *base32);

/*
 * Generic binary to hexadecimal conversion.
 */
size_t bin_to_hex_buf(const gchar *data, size_t len, gchar *dst, size_t size);

/*
 * Tests
 */
gboolean is_absolute_path(const char *pathname);
gboolean is_directory(const gchar *pathname);
gboolean is_regular(const gchar *pathname);
gboolean is_symlink(const gchar *pathname);
int is_same_file(const char *, const char *);
gboolean file_exists(const gchar *pathname);
gboolean file_does_not_exist(const gchar *pathname);
guint32 next_pow2(guint32 n);

#define IS_POWER_OF_2(x) ((x) && 0 == ((x) & ((x) - 1)))
/**
 * Checks whether the given value is a power of 2.
 *
 * @param value a 32-bit integer
 * @return TRUE if ``value'' is a power of 2. Otherwise FALSE.
 */
static inline G_GNUC_CONST gboolean
is_pow2(guint32 value)
#ifdef HAS_BUILTIN_POPCOUNT
{
	return 1 == __builtin_popcount(value);
}
#else /* !HAS_BUILTIN_POPCOUNT */
{
	return IS_POWER_OF_2(value);
}
#endif /* HAS_BUILTIN_POPCOUNT */

/*
 * Random numbers
 */
void random_init(void);
guint32 random_value(guint32 max) WARN_UNUSED_RESULT;
guint32 random_u32(void) WARN_UNUSED_RESULT;
void random_bytes(void *dst, size_t size);
void guid_random_fill(gchar *xuid);

/*
 * Stuff
 */
void misc_init(void);
size_t str_chomp(gchar *str, size_t len);
gint hex2int(guchar c);
gboolean is_printable(const gchar *buf, gint len);
void dump_hex(FILE *, const gchar *, gconstpointer, gint);
void locale_strlower(gchar *, const gchar *);
void ascii_strlower(gchar *dst, const gchar *src);
gint strcmp_delimit(const gchar *a, const gchar *b, const gchar *delimit);
gint ascii_strcasecmp_delimit(const gchar *a, const gchar *b,
		const gchar *delimit);
size_t filename_shrink(const gchar *filename, gchar *buf, size_t size);
char *unique_filename(const gchar *path, const gchar *file, const gchar *ext,
		gboolean (*name_is_uniq)(const gchar *pathname));
gchar *hex_escape(const gchar *name, gboolean strict);
gchar *control_escape(const gchar *s);
const gchar *lazy_string_to_printf_escape(const gchar *src);
gint highest_bit_set(guint32 n) G_GNUC_CONST;
size_t common_leading_bits(
	gconstpointer k1, size_t k1bits, gconstpointer k2, size_t k2bits);
gfloat force_range(gfloat value, gfloat min, gfloat max);
gchar *absolute_pathname(const gchar *file);
gchar *make_pathname(const gchar *dir, const gchar *file);
gchar *short_filename(gchar *fullname);
gchar *data_hex_str(const gchar *data, size_t len);

#if defined(S_IROTH) && defined(S_IXOTH)
/* 0755 */
#define DEFAULT_DIRECTORY_MODE (S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH)
#else
/* 0750 */
#define DEFAULT_DIRECTORY_MODE (S_IRWXU | S_IRGRP | S_IXGRP)
#endif /* S_IROTH && S_IXOTH */

gint create_directory(const gchar *dir, mode_t mode);
gint compat_mkdir(const gchar *path, mode_t mode);
gboolean filepath_exists(const gchar *dir, const gchar *file);
const gchar * filepath_basename(const gchar *pathname);
gchar * filepath_directory(const gchar *pathname);
guint16 parse_uint16(const gchar *, gchar const **, guint, gint *)
	NON_NULL_PARAM((1, 4));
guint32 parse_uint32(const gchar *, gchar const **, guint, gint *)
	NON_NULL_PARAM((1, 4));
guint64 parse_uint64(const gchar *, gchar const **, guint, gint *)
	NON_NULL_PARAM((1, 4));
size_t int32_to_string_buf(gint32 v, gchar *dst, size_t size);
size_t uint32_to_string_buf(guint32 v, gchar *dst, size_t size);
size_t uint64_to_string_buf(guint64 v, gchar *dst, size_t size);
size_t off_t_to_string_buf(off_t v, gchar *dst, size_t size);
size_t time_t_to_string_buf(time_t v, gchar *dst, size_t size);
const gchar *uint32_to_string(guint32 v);
const gchar *uint64_to_string(guint64 v);
const gchar *uint64_to_string2(guint64 v);
const gchar *off_t_to_string(off_t v);
const gchar *time_t_to_string(time_t v);
const gchar *filesize_to_string(filesize_t v);
const gchar *filesize_to_string2(filesize_t v);
gint parse_major_minor(const gchar *src, gchar const **endptr,
	guint *major, guint *minor);
gchar *is_strprefix(const gchar *s, const gchar *prefix) WARN_UNUSED_RESULT;
gchar *is_strcaseprefix(const gchar *s, const gchar *prefix) WARN_UNUSED_RESULT;
size_t html_escape(const gchar *src, gchar *dst, size_t dst_size);
guint32 html_decode_entity(const gchar *src, const gchar **endptr);
gint canonize_path(gchar *dst, const gchar *path);
guint compat_max_fd(void);
void close_file_descriptors(const int first_fd);
int reserve_standard_file_descriptors(void);
gboolean compat_is_superuser(void);
int compat_daemonize(const char *directory);
void set_close_on_exec(gint fd);
void compat_fadvise_sequential(int fd, off_t offset, off_t size);
void *compat_memmem(const void *data, size_t data_size,
		const void *pattern, size_t pattern_size);

int get_non_stdio_fd(int fd);

typedef void (*signal_handler_t)(gint signo);
signal_handler_t set_signal(gint signo, signal_handler_t handler);

gchar *ascii_strcasestr(const gchar *haystack, const gchar *needle);
gchar *normalize_dir_separators(const gchar *s);
size_t memcmp_diff(const void *a, const void *b, size_t n);
guint32 cpu_noise(void);

static inline guint
pointer_hash_func(const void *p)
{
	size_t v = (size_t) p;
	return (((guint64) 0x4F1BBCDCUL * v) >> 32) ^ v;
}

static inline guint
str_case_hash_func(gconstpointer key)
{
	const guchar *s = key;
	gulong c, hash = 0;
	
	while ((c = ascii_tolower(*s++))) {
		hash ^= (hash << 8) | c;
	}
	return hash ^ (((guint64) 1048573 * hash) >> 32);
}

static inline gint
str_case_eq_func(gconstpointer a, gconstpointer b)
{
	return 0 == ascii_strcasecmp(a, b);
}

/**
 * Determines the length of a NUL-terminated string looking only at the first
 * "src_size" bytes. If src[0..size] contains no NUL byte, "src_size" is
 * returned. Otherwise, the returned value is identical to strlen(str). Thus,
 * it is safe to pass a possibly non-terminated buffer.
 * 
 * @return The number of bytes in "src" before the first found NUL or src_size
 *		   if there is no NUL.
 */
static inline size_t
clamp_strlen(const gchar *src, size_t src_size)
{
	const gchar *p;
	
	p = memchr(src, '\0', src_size);
	return (p ? p : &src[src_size]) - src;
}

static inline const gchar *
NULL_STRING(const gchar *s)
{
	return NULL != s ? s : "(null)";
}

static inline const gchar *
EMPTY_STRING(const gchar *s)
{
	return NULL != s ? s : "";
}

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
	guint32 a;
	guint32 b;
                                  /* i -> ABCD */
	a = (i & 0x00ff00ff) << 8;    /* a -> B0D0 */
	b = (i & 0xff00ff00) >> 8;    /* b -> 0A0C */
	i = a | b;                    /* i -> BADC */
	i = (i << 16) | (i >> 16);    /* i -> DCBA */
    
	return i;
}

/**
 * Converts the given IPv4 netmask in host byte order to a CIDR prefix length.
 * No checks are performed whether the netmask is proper and if it's not
 * the result is unspecified.
 *
 * @param netmask an IPv4 netmask in host byte order.
 * @return The CIDR prefix length (0..32).
 */
static inline G_GNUC_CONST WARN_UNUSED_RESULT guint8
netmask_to_cidr(guint32 netmask)
#ifdef HAVE_BUILTIN_POPCOUNT
{
	__builtin_popcount(netmask);
}
#else	/* HAVE_BUILTIN_POPCOUNT */
{
	guint8 bits = 32;

	while (0 == (netmask & 0x1)) {
		netmask >>= 1;
		bits--;
	}
	return bits;
}
#endif /* HAVE_BUILTIN_POPCOUNT */

/**
 * Converts the CIDR prefix length to a IPv4 netmask in host byte order.
 * No checks are performed.
 *
 * @param bits A value between 1..32.
 * @return The equivalent netmask in host byte order.
 */
static inline G_GNUC_CONST WARN_UNUSED_RESULT guint32
cidr_to_netmask(guint bits)
{
	return (guint32)-1 << (32 - bits);
}

/**
 * Rounds ``n'' up so that it matches the given alignment ``align''.
 */
static inline size_t
round_size(size_t align, size_t n)
{
	size_t m = n % align;
	return m ? n + (align - m) : MAX(n, align);
}

/*
 * Syscall wrappers for errno == 0 bug. --RAM, 27/10/2003
 */

struct stat;

static inline gboolean
is_temporary_error(gint error)
{
  switch (error) {
  case EAGAIN:
#if defined(EWOULDBLOCK) && EAGAIN != EWOULDBLOCK
  case EWOULDBLOCK:
#endif /* EWOULDBLOCK != EAGAIN */
  case EINTR:
    return TRUE;
  }
  return FALSE;
}

/* Wrapper around lseek() to handle filesize -> off_t conversion. */
gint seek_to_filepos(gint fd, filesize_t pos);

guint filesize_per_100(filesize_t size, filesize_t part);
guint filesize_per_1000(filesize_t size, filesize_t part);
guint filesize_per_10000(filesize_t size, filesize_t part);

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
G_STMT_START { \
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
} G_STMT_END

/**
 * Ensure a table used for binary search is sorted.
 *
 * bs_array is the (static) array to scan.
 * bs_type is the type of bs_item
 * bs_field is the field in the bs_item structure to compare.
 * bs_cmp() is the comparison function to use between items
 * bs_field2str is how one can stringify the bs_field.
 *
 * Skip the first to have a previous element, tables with a single
 * element are sorted anyway.
 */
#define BINARY_ARRAY_SORTED(bs_array, bs_type, bs_field, bs_cmp, bs_field2str) \
G_STMT_START { \
	size_t bs_index; \
	size_t bs_size = G_N_ELEMENTS(bs_array); \
\
	for (bs_index = 1; bs_index < bs_size; bs_index++) { \
		const bs_type *prev = &bs_array[bs_index - 1]; \
		const bs_type *e = &bs_array[bs_index]; \
\
		if (bs_cmp(prev->bs_field, e->bs_field) >= 0) \
			g_error(STRINGIFY(bs_array) "[] unsorted (near item \"%s\")", \
				bs_field2str(e->bs_field)); \
	} \
} G_STMT_END

static inline const char *
print_number(char *dst, size_t size, unsigned long value)
{
	char *p = &dst[size];

	if (size > 0) {
		*--p = '\0';
	}
	while (p != dst) {
		*--p = (value % 10) + '0';
		value /= 10;
		if (0 == value)
			break;
	}
	return p;
}

#endif /* _misc_h_ */

/* vi: set ts=4 sw=4 cindent: */
