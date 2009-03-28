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
	char str[SIZE_FIELD_MAX];
} short_string_t;

/**
 * Needs to be defined if we are not using Glib 2
 */
#ifndef USE_GLIB2

#ifndef HAS_STRLCPY
size_t strlcpy(char *dst, const char *src, size_t dst_size);
#endif /* HAS_STRLCPY */

#ifndef HAS_STRLCAT
size_t strlcat(char *dst, const char *src, size_t dst_size);
#endif /* HAS_STRLCAT */

#define g_string_printf g_string_sprintf
#define g_strlcpy strlcpy
#define g_strlcat strlcat
#endif

size_t concat_strings(char *dst, size_t size,
	const char *s, ...) G_GNUC_NULL_TERMINATED;
size_t w_concat_strings(char **dst,
	const char *first, ...) G_GNUC_NULL_TERMINATED;

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

#if !GLIB_CHECK_VERSION(2,4,0)
static inline WARN_UNUSED_RESULT const char *
g_strip_context(const char *id, const char *val)
{
	const char *s;

	s = id != val ? NULL : strchr(id, '|');
	return s ? ++s : val;
}
#endif /* GLib < 2.4.0 */

static inline WARN_UNUSED_RESULT char *
skip_dir_separators(const char *s)
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

gboolean parse_ipv6_addr(const char *s, uint8_t *dst, const char **endptr);
const char *ipv6_to_string(const guint8 *ipv6);
size_t ipv6_to_string_buf(const guint8 *ipv6, char *dst, size_t size);

/*
 * Network related string routines
 */
guint32  string_to_ip(const char *);
gboolean string_to_ip_strict(const char *s, guint32 *addr, const char **ep);
gboolean string_to_ip_and_mask(const char *str, guint32 *ip, guint32 *netmask);
gboolean string_to_ip_port(const char *str, guint32 *ip, guint16 *port);
const char *ip_to_string(guint32);
size_t ipv4_to_string_buf(guint32 ip, char *buf, size_t size);
const char *hostname_port_to_string(const char *hostname, guint16 port);
const char *local_hostname(void);
#define port_is_valid(port) (port != 0)

/*
 * Date string conversions
 */
const char *timestamp_to_string(time_t date);
const char *timestamp_utc_to_string(time_t date);
const char *timestamp_rfc822_to_string(time_t date);
const char *timestamp_rfc822_to_string2(time_t date);
const char *timestamp_rfc1123_to_string(time_t date);

size_t timestamp_to_string_buf(time_t date, char *dst, size_t size);
size_t timestamp_utc_to_string_buf(time_t date, char *dst, size_t size);
size_t time_locale_to_string_buf(time_t date, char *dst, size_t size);

short_string_t timestamp_get_string(time_t date);

/*
 * Time string conversions
 */
const char *short_time(time_delta_t s);
const char *short_time_ascii(time_delta_t t);
const char *short_uptime(time_delta_t s);
const char *compact_time(time_delta_t t);

/*
 * Size string conversions
 */
const char *short_size(guint64 size, gboolean metric);
const char *short_html_size(guint64 size, gboolean metric);
const char *short_kb_size(guint64 size, gboolean metric);
const char *short_rate(guint64 rate, gboolean metric);
const char *compact_size(guint64 size, gboolean metric);
const char *compact_rate(guint64 rate, gboolean metric);
const char *compact_kb_size(guint32 size, gboolean metric);
const char *nice_size(guint64 size, gboolean metric);
char *short_value(char *buf, size_t size, guint64 v, gboolean metric);
char *compact_value(char *buf, size_t size, guint64 v, gboolean metric);

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
struct guid;

const char *guid_hex_str(const struct guid *);
gboolean hex_to_guid(const char *, struct guid *);
size_t guid_to_string_buf(const struct guid *, char *, size_t);
const char *guid_to_string(const struct guid *);

/*
 * GUID<->base32 string conversion
 */
const char *guid_base32_str(const struct guid *);
const struct guid *base32_to_guid(const char *);

/*
 * Generic binary to hexadecimal conversion.
 */
size_t bin_to_hex_buf(const void *data, size_t len, char *dst, size_t size);

/*
 * Tests
 */
gboolean is_absolute_path(const char *pathname);
gboolean is_directory(const char *pathname);
gboolean is_regular(const char *pathname);
gboolean is_symlink(const char *pathname);
int is_same_file(const char *, const char *);
gboolean file_exists(const char *pathname);
gboolean file_does_not_exist(const char *pathname);
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
void guid_random_fill(struct guid *);

/*
 * Stuff
 */
void misc_init(void);
size_t str_chomp(char *str, size_t len);
int hex2int(guchar c);
gboolean is_printable(const char *buf, int len);
void dump_hex(FILE *, const char *, gconstpointer, int);
void dump_string(FILE *out, const char *str, size_t len, const char *trailer);
void locale_strlower(char *, const char *);
size_t filename_shrink(const char *filename, char *buf, size_t size);
char *unique_filename(const char *path, const char *file, const char *ext,
		gboolean (*name_is_uniq)(const char *pathname));
char *hex_escape(const char *name, gboolean strict);
char *control_escape(const char *s);
const char *lazy_string_to_printf_escape(const char *src);
int highest_bit_set(guint32 n) G_GNUC_CONST;
size_t common_leading_bits(
	gconstpointer k1, size_t k1bits, gconstpointer k2, size_t k2bits);
float force_range(float value, float min, float max);
char *absolute_pathname(const char *file);
char *make_pathname(const char *dir, const char *file);
char *short_filename(char *fullname);
char *data_hex_str(const char *data, size_t len);

#if defined(S_IROTH) && defined(S_IXOTH)
/* 0755 */
#define DEFAULT_DIRECTORY_MODE (S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH)
#else
/* 0750 */
#define DEFAULT_DIRECTORY_MODE (S_IRWXU | S_IRGRP | S_IXGRP)
#endif /* S_IROTH && S_IXOTH */

int create_directory(const char *dir, mode_t mode);
int compat_mkdir(const char *path, mode_t mode);
gboolean filepath_exists(const char *dir, const char *file);
const char * filepath_basename(const char *pathname);
char * filepath_directory(const char *pathname);
guint16 parse_uint16(const char *, char const **, guint, int *)
	NON_NULL_PARAM((1, 4));
guint32 parse_uint32(const char *, char const **, guint, int *)
	NON_NULL_PARAM((1, 4));
guint64 parse_uint64(const char *, char const **, guint, int *)
	NON_NULL_PARAM((1, 4));
size_t int32_to_string_buf(gint32 v, char *dst, size_t size);
size_t uint32_to_string_buf(guint32 v, char *dst, size_t size);
size_t uint64_to_string_buf(guint64 v, char *dst, size_t size);
size_t off_t_to_string_buf(off_t v, char *dst, size_t size);
size_t time_t_to_string_buf(time_t v, char *dst, size_t size);
const char *uint32_to_string(guint32 v);
const char *uint64_to_string(guint64 v);
const char *uint64_to_string2(guint64 v);
const char *off_t_to_string(off_t v);
const char *time_t_to_string(time_t v);
const char *filesize_to_string(filesize_t v);
const char *filesize_to_string2(filesize_t v);
int parse_major_minor(const char *src, char const **endptr,
	guint *major, guint *minor);
char *is_strprefix(const char *s, const char *prefix) WARN_UNUSED_RESULT;
char *is_strcaseprefix(const char *s, const char *prefix) WARN_UNUSED_RESULT;
size_t html_escape(const char *src, char *dst, size_t dst_size);
guint32 html_decode_entity(const char *src, const char **endptr);
int canonize_path(char *dst, const char *path);
guint compat_max_fd(void);
void close_file_descriptors(const int first_fd);
int reserve_standard_file_descriptors(void);
gboolean compat_is_superuser(void);
int compat_daemonize(const char *directory);
void set_close_on_exec(int fd);
void compat_fadvise_sequential(int fd, off_t offset, off_t size);
void *compat_memmem(const void *data, size_t data_size,
		const void *pattern, size_t pattern_size);

int get_non_stdio_fd(int fd);

typedef void (*signal_handler_t)(int signo);
signal_handler_t set_signal(int signo, signal_handler_t handler);

char *normalize_dir_separators(const char *s);
size_t memcmp_diff(const void *a, const void *b, size_t n);
guint32 cpu_noise(void);

static inline guint
pointer_hash_func(const void *p)
{
	size_t v = (size_t) p;
	return (((guint64) 0x4F1BBCDCUL * v) >> 32) ^ v;
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
clamp_strlen(const char *src, size_t src_size)
{
	const char *p;
	
	p = memchr(src, '\0', src_size);
	return (p ? p : &src[src_size]) - src;
}

static inline const char *
NULL_STRING(const char *s)
{
	return NULL != s ? s : "(null)";
}

static inline const char *
EMPTY_STRING(const char *s)
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
is_temporary_error(int error)
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
int seek_to_filepos(int fd, filesize_t pos);
filesize_t get_random_file_offset(const filesize_t size);

guint filesize_per_100(filesize_t size, filesize_t part);
guint filesize_per_1000(filesize_t size, filesize_t part);
guint filesize_per_10000(filesize_t size, filesize_t part);

/*
 * NOTE: ssize_t is NOT the signed variant of size_t and casting values blindly
 * to ssize_t may cause integer overflows.  Larger values, especially SIZE_MAX
 * (size_t)-1 may be the result of errors or wrap arounds during calculations.
 * Therefore in places where memory objects larger than half of the address
 * space are unreasonable, the following two functions are useful to check for
 * such conditions.
 */

/*
 * Check whether a signed representation of size would be non-negative.
 * @return TRUE if size is equal to zero or larger and smaller than
 *         SIZE_MAX / 2.
 */
static inline gboolean
size_is_non_negative(size_t size)
{
	return size <= SIZE_MAX / 2;
}

/**
 * Check whether a signed representation of size would be positive.
 * @return TRUE if size is larger than zero and smaller than SIZE_MAX / 2.
 */
static inline gboolean
size_is_positive(size_t size)
{
	return size_is_non_negative(size - 1);
}

/*
 * Calculate the sum of a and b but saturate towards SIZE_MAX.
 * @return SIZE_MAX if a + b > SIZE_MAX, otherwise a + b.
 */
static inline size_t
size_saturate_add(size_t a, size_t b)
{
	size_t ret = a + b;
	if (G_UNLIKELY(ret < a))
		return SIZE_MAX;
	return ret;
}

/*
 * Calculate the product of a and b but saturate towards SIZE_MAX.
 * @return SIZE_MAX if a * b > SIZE_MAX, otherwise a * b.
 */
static inline size_t
size_saturate_mult(size_t a, size_t b)
{
	if (G_UNLIKELY(0 != a && SIZE_MAX / a < b))
		return SIZE_MAX;
	return a * b;
}

/*
 * Calculate the difference between a and b but saturate towards zero.
 * @return zero if a < b, otherwise a - b.
 */
static inline size_t
size_saturate_sub(size_t a, size_t b)
{
	if (G_UNLIKELY(a < b))
		return 0;
	return a - b;
}

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
		int bs_cmp_result; \
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
