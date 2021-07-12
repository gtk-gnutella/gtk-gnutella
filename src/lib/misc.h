/*
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
 *      51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
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
 * - Stuff...
 *
 * @author Raphael Manfredi
 * @date 2001-2003
 */

#ifndef _misc_h_
#define _misc_h_

#include "common.h"

#include "fs_free_space.h"
#include "pslist.h"
#include "sha1.h"
#include "vmm.h"

#define SIZE_FIELD_MAX		64	/**< Max size of sprintf-ed size quantity */
#define GUID_RAW_SIZE		16	/**< Binary representation of 128 bits */
#define GUID_HEX_SIZE		32	/**< Hexadecimal GUID representation */
#define GUID_BASE32_SIZE	26	/**< base32 GUID representation */

typedef struct short_string {
	char str[SIZE_FIELD_MAX];
} short_string_t;

static inline G_CONST ALWAYS_INLINE int
is_dir_separator(int c)
{
	return '/' == c || G_DIR_SEPARATOR == c;
}

/**
 * Converts an integer to a single hexadecimal ASCII digit. The are no checks,
 * this is just a convenience function.
 *
 * @param x An integer between 0 and 15.
 * @return The ASCII character corresponding to the hex digit [0-9a-f].
 */
static inline G_PURE ALWAYS_INLINE uchar
hex_digit(uchar x)
{
	extern const char hex_alphabet_lower[];
	return hex_alphabet_lower[x & 0xf];
}

#if !GLIB_CHECK_VERSION(2,4,0)
static inline WARN_UNUSED_RESULT const char *
g_strip_context(const char *id, const char *val)
{
	const char *s;

	s = id != val ? NULL : vstrchr(id, '|');
	return s ? ++s : val;
}
#endif /* GLib < 2.4.0 */

static inline WARN_UNUSED_RESULT char *
skip_dir_separators(const char *s)
{
	while (is_dir_separator(s[0]))
		s++;

	return deconstify_gchar(s);
}

/*
 * Determine the length of string literals
 */
#define CONST_STRLEN(x) (sizeof(x) - 1)

/*
 * Network related string routines
 */
const char *local_hostname(void);
#define port_is_valid(port) (port != 0)

/*
 * Size string conversions
 */
const char *short_frequency(uint64 freq);
const char *short_size(uint64 size, bool metric);
const char *short_size2(uint64 size, bool metric);
const char *short_html_size(uint64 size, bool metric);
const char *short_kb_size(uint64 size, bool metric);
const char *short_kb_size2(uint64 size, bool metric);
const char *short_rate(uint64 rate, bool metric);
const char *short_byte_size(uint64 size, bool metric);
const char *short_byte_size2(uint64 size, bool metric);
const char *compact_size(uint64 size, bool metric);
const char *compact_size2(uint64 size, bool metric);
const char *compact_rate(uint64 rate, bool metric);
const char *compact_kb_size(uint32 size, bool metric);
const char *nice_size(uint64 size, bool metric);
char *long_value(char *buf, size_t size, uint64 v, bool metric);
char *short_value(char *buf, size_t size, uint64 v, bool metric);
char *compact_value(char *buf, size_t size, uint64 v, bool metric);

size_t short_byte_size_to_buf(uint64 size, bool metric, char *, size_t);
size_t short_kb_size_to_buf(uint64 size, bool metric, char *, size_t);
size_t short_size_to_string_buf(uint64 size, bool metric, char *, size_t);

short_string_t short_rate_get_string(uint64 rate, bool metric);
short_string_t long_value_get_string(uint64 value, bool metric);

/*
 * SHA1<->base32 string conversion
 */

#define SHA1_URN_LENGTH	(CONST_STRLEN("urn:sha1:") + SHA1_BASE32_SIZE)

const char *sha1_to_string(const struct sha1 *sha1);
const char *sha1_to_urn_string(const struct sha1 *);
size_t sha1_to_urn_string_buf(const struct sha1 *, char *dst, size_t size);
char *sha1_to_base32_buf(const struct sha1 *, char *dst, size_t size);
const char *sha1_base32(const struct sha1 *);
char *sha1_to_base16_buf(const struct sha1 *, char *dst, size_t size);
const char *sha1_base16(const struct sha1 *);
const struct sha1 *base32_sha1(const char *base32);

static inline G_PURE int
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
bool hex_to_guid(const char *, struct guid *);
size_t guid_to_string_buf(const struct guid *, char *, size_t);
const char *guid_to_string(const struct guid *);

/*
 * GUID<->base32 string conversion
 */
const char *guid_base32_str(const struct guid *);
const struct guid *base32_to_guid(const char *, struct guid *);

/*
 * Generic binary to hexadecimal conversion.
 */
size_t bin_to_hex_buf(const void *data, size_t len, char *dst, size_t size);

/*
 * Tests
 */
bool is_directory(const char *pathname);
bool is_regular(const char *pathname);
bool is_symlink(const char *pathname);
int is_same_file(const char *, const char *);

/**
 * Tries to extract the file mode from a struct dirent. Not all systems
 * support this, in which case zero is returned. Types other than regular
 * files, directories and symlinks are ignored and gain a value of zero
 * as well.
 */
static inline mode_t
dir_entry_mode(const struct dirent *dir_entry)
{
	g_assert(dir_entry);
#ifdef HAS_DIRENT_D_TYPE
	switch (dir_entry->d_type) {
	case DT_DIR:	return S_IFDIR;
	case DT_LNK:	return S_IFLNK;
	case DT_REG:	return S_IFREG;
	case DT_CHR:	return S_IFCHR;
	case DT_BLK:	return S_IFBLK;
	case DT_FIFO:	return S_IFIFO;
#if defined(DT_WHT) && defined(S_IFWHT)
	case DT_WHT:	return S_IFWHT;
#endif	/* DT_WHT */
#if defined(DT_SOCK) && defined(S_IFSOCK)
	case DT_SOCK:	return S_IFSOCK;
#endif	/* DT_SOCK */
	}
#endif	/* HAS_DIRENT_WITH_D_TYPE */
	return 0;
}

#ifndef MINGW32
/* There is a MINGW32 version defined for Windows in lib/mingw32.c */
static inline const char *
dir_entry_filename(const struct dirent *dir_entry)
{
	g_assert(dir_entry != NULL);

	return dir_entry->d_name;
}

/* There is a MINGW32 version defined for Windows in lib/mingw32.c */
static inline size_t
dir_entry_namelen(const struct dirent *dir_entry)
{
	g_assert(dir_entry != NULL);

#ifdef HAS_DIRENT_D_NAMLEN
	if G_LIKELY(dir_entry->d_namlen != 0)
		return dir_entry->d_namlen;
#endif	/* HAS_DIRENT_D_NAMLEN */

	return vstrlen(dir_entry->d_name);
}
#endif	/* MINGW32 */

/*
 * Stuff
 */

void misc_init(void);
void misc_close(void);

size_t strchomp(char *str, size_t len);
int hex2int(uchar c);
bool is_printable(const char *buf, int len);
void dump_hex(FILE *, const char *, const void *, int);
void dump_hex_vec(FILE *out, const char *title,
	const iovec_t *iov, size_t iovcnt);
void dump_string(FILE *out, const char *str, size_t len, const char *trailer);
bool is_printable_iso8859_string(const char *s);
void locale_strlower(char *, const char *);
size_t common_leading_bits(
	const void *k1, size_t k1bits, const void *k2, size_t k2bits)
	G_PURE;
float force_range(float value, float min, float max);
const char *short_filename(const char *fullname);
char *data_hex_str(const char *data, size_t len);
char *xml_indent(const char *text, size_t *lenp);
char *xml_indent_buf(const void *buf, size_t len, size_t *lenp);
pslist_t *dirlist_parse(const char *dirs);
char *dirlist_to_string(const pslist_t *pl_dirs);

#if defined(S_IROTH) && defined(S_IXOTH)
/* 0755 */
#define DEFAULT_DIRECTORY_MODE (S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH)
#else
/* 0750 */
#define DEFAULT_DIRECTORY_MODE (S_IRWXU | S_IRGRP | S_IXGRP)
#endif /* S_IROTH && S_IXOTH */

int create_directory(const char *dir, mode_t mode);

char *is_strprefix(const char *s, const char *prefix) WARN_UNUSED_RESULT;
char *is_strcaseprefix(const char *s, const char *prefix) WARN_UNUSED_RESULT;
char *is_strsuffix(const char *str, size_t len, const char *suffix);
char *is_strcasesuffix(const char *str, size_t len, const char *suffix);
char *is_bufprefix(const char *str, size_t len, const char *prefix);
char *is_bufcaseprefix(const char *str, size_t len, const char *prefix);
size_t html_escape(const char *src, char *dst, size_t dst_size);
uint32 html_decode_entity(const char *src, const char **endptr);
const char *symbolic_errno(int errnum);
const char * english_strerror(int errnum);
void normalize_dir_separators(char *);
size_t memcmp_diff(const void *a, const void *b, size_t n);
int bitcmp(const void *s1, const void *s2, size_t n);

size_t clamp_strlen(const char *src, size_t src_size);

/**
 * Returns the length of the string plus one, i.o.w.
 * the required buffer size in bytes.
 */
static inline size_t
strsize(const char *src)
{
	return vstrlen(src) + 1;
}

/**
 * Copies at most MIN(dst_size, src_len) bytes from "src" to "dst".
 *
 * @param dst the destination buffer.
 * @param dst_size the size of dst in number of bytes.
 * @param src the source buffer.
 * @param src_len the length of src in number of bytes.
 *
 * @return The number of copied bytes.
 */
static inline size_t
clamp_memcpy(void *dst, size_t dst_size, const void *src, size_t src_len)
{
	size_t n;

	n = MIN(dst_size, src_len);
	memcpy(dst, src, n);
	return n;
}

/**
 * Sets MIN(dst_size, src_len) bytes starting at dst to 'c'.
 *
 * @param dst the destination buffer.
 * @param dst_size the size of dst in number of bytes.
 * @param c the value to set each byte to.
 * @param n the number of bytes to set.
 *
 * @return The number of set bytes.
 */
static inline size_t
clamp_memset(void *dst, size_t dst_size, char c, size_t n)
{
	n = MIN(dst_size, n);
	memset(dst, c, n);
	return n;
}

/**
 * Compare at most MIN(a_len, b_len) bytes between "a" and "b".
 *
 * @param a		the first buffer.
 * @param a_len the length of the first buffer, in bytes
 * @param b		the second buffer.
 * @param b_len the length of the second buffer, in bytes
 *
 * @return the result of the memcmp() operation (-1, 0, +1).
 */
static inline int
clamp_memcmp(const void *a, size_t a_len, const void *b, size_t b_len)
{
	return memcmp(a, b, MIN(a_len, b_len));
}

/**
 * Copies at most MIN(dst_size - 1, src_len) characters from the buffer "src"
 * to the buffer "dst", ensuring the resulting string in "dst" is
 * NUL-terminated and truncating it if necessary. If "src_len" is (size_t)-1,
 * "src" must be NUL-terminated, otherwise the first "src_len" bytes of "src"
 * must be initialized but a terminating NUL is not necessary.
 *
 * @NOTE: The 'dst' buffer is NOT padded with NUL-bytes.
 *
 * @param dst the destination buffer.
 * @param dst_size the size of dst in number of bytes.
 * @param src a NUL-terminated string or at an initialized buffer of least
 *        "src_len" bytes.
 * @param src_len the length of src in number of bytes to copy at maximum. May
 *        be (size_t)-1 if "src" is NUL-terminated.
 *
 * @return The length of the resulting string in number of bytes.
 */
static inline size_t
clamp_strncpy(char *dst, size_t dst_size, const char *src, size_t src_len)
{
	if (dst_size-- > 0) {
		size_t n;

		if ((size_t) -1 == src_len) {
			src_len = clamp_strlen(src, dst_size);
		}
		n = clamp_memcpy(dst, dst_size, src, src_len);
		dst[n] = '\0';
		return n;
	} else {
		return 0;
	}
}

/**
 * Copies at most "dst_size - 1" characters from the NUL-terminated string
 * "src" to the buffer "dst", ensuring the resulting string in "dst" is
 * NUL-terminated and truncating it if necessary.
 *
 * @NOTE: The 'dst' buffer is NOT padded with NUL-bytes.
 *
 * @param dst the destination buffer.
 * @param dst_size the size of dst in number of bytes.
 * @param src a NUL-terminated string.
 *
 * @return The length of the resulting string in number of bytes.
 */
static inline size_t
clamp_strcpy(char *dst, size_t dst_size, const char *src)
{
	return clamp_strncpy(dst, dst_size, src, (size_t) -1);
}

/**
 * Appends at most "dst_size - 1" characters from the NUL-terminated string
 * "src" to the buffer "dst", ensuring the resulting string in "dst" is
 * NUL-terminated and truncating it if necessary.
 *
 * @NOTE: The 'dst' buffer is NOT padded with NUL-bytes.
 *
 * @param dst the destination buffer. Must be initialized.
 * @param dst_size the size of dst in number of bytes.
 * @param src a NUL-terminated string.
 *
 * @return The length of the resulting string in number of bytes.
 */
static inline size_t
clamp_strcat(char *dst, size_t dst_size, const char *src)
{
	size_t dst_len;

	dst_len = clamp_strlen(dst, dst_size);
	dst += dst_len;
	dst_size -= dst_len;
	return dst_len + clamp_strcpy(dst, dst_size, src);
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
 * Is string NULL or empty?
 */
static inline bool
is_null_or_empty(const char *s)
{
	return NULL == s || '\0' == *s;
}

/**
 * Swap endianness of a uint32.
 *
 * @param i the uint32 to swap
 *
 * @returns the value of i after swapping its byte order.
 */
static inline G_CONST uint32
swap_uint32(uint32 i)
{
	uint32 a;
	uint32 b;
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
static inline G_CONST WARN_UNUSED_RESULT uint8
netmask_to_cidr(uint32 netmask)
#ifdef HAS_BUILTIN_POPCOUNT
{
	return __builtin_popcount(netmask);
}
#else	/* !HAS_BUILTIN_POPCOUNT */
{
	uint8 bits = 32;

	while (0 == (netmask & 0x1)) {
		netmask >>= 1;
		bits--;
	}
	return bits;
}
#endif /* HAS_BUILTIN_POPCOUNT */

/**
 * Converts the CIDR prefix length to a IPv4 netmask in host byte order.
 * No checks are performed.
 *
 * @param bits A value between 1..32.
 * @return The equivalent netmask in host byte order.
 */
static inline ALWAYS_INLINE G_CONST WARN_UNUSED_RESULT uint32
cidr_to_netmask(uint bits)
{
	return (uint32)-1 << (32 - bits);
}

/**
 * Rounds ``n'' up so that it matches the given alignment ``align''.
 */
static inline size_t
round_size(size_t align, size_t n)
{
	size_t m = n % align;
	return m ? n + (align - m) : n;
}

/**
 * Rounds ``n'' up so that it matches the given alignment ``align''.
 * Fast version, when ``align'' is known to be a power of 2.
 */
static inline size_t
round_size_fast(size_t align, size_t n)
{
	size_t mask = align - 1;

	return (n + mask) & ~mask;
}

void guid_random_fill(struct guid *);

/*
 * Syscall wrappers for errno == 0 bug. --RAM, 27/10/2003
 */

static inline bool
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

/* Wrapper around lseek() to handle filesize -> fileoffset_t conversion. */
int seek_to_filepos(int fd, filesize_t pos);
filesize_t get_random_file_offset(const filesize_t size);

uint filesize_per_100(filesize_t size, filesize_t part);
uint filesize_per_1000(filesize_t size, filesize_t part);
uint filesize_per_10000(filesize_t size, filesize_t part);

/*
 * CIDR split of IP range.
 */

typedef void (*cidr_split_t)(uint32 ip, uint bits, void *udata);

void ip_range_split(
	uint32 lower_ip, uint32 upper_ip, cidr_split_t cb, void *udata);

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
	size_t bs_size = N_ITEMS(bs_array); \
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

/**
 * Converts an integer to a single decimal ASCII digit. The are no checks,
 * this is just a convenience function.
 *
 * @param x An integer between 0 and 9.
 * @return The ASCII character corresponding to the decimal digit [0-9].
 */
static inline uchar
dec_digit(uchar x)
{
	static const char dec_alphabet[] = "0123456789";
	return dec_alphabet[x % 10];
}

/**
 * Copies "src_len" chars from "src" to "dst" reversing their order.
 * The resulting string is always NUL-terminated unless "size" is zero.
 * If "size" is not larger than "src_len", the resulting string will
 * be truncated. NUL chars copied from "src" are not treated as string
 * terminations.
 *
 * @param dst The destination buffer.
 * @param size The size of the destination buffer.
 * @param src The source buffer.
 * @param src_len The size of the source buffer.
 *
 * @return The resulting length of string not counting the termating NUL.
 *         Note that NULs that might have been copied from "src" are
 *         included in this count. Thus strlen(dst) would return a lower
 *         value in this case.
 */
static inline size_t
reverse_strlcpy(char * const dst, size_t size,
	const char *src, size_t src_len)
{
	char *p = dst;

	if (size-- > 0) {
		const char *q = &src[src_len], *end = &dst[MIN(src_len, size)];

		while (p != end) {
			*p++ = *--q;
		}
		*p = '\0';
	}

	return p - dst;
}

/**
 * Encodes a variable-length integer. This encoding is equivalent to
 * little-endian encoding whereas trailing zeros are discarded.
 *
 * @param v		the value to encode.
 * @param data  must point to a sufficiently large buffer. At maximum
 *				8 bytes are required.
 *
 * @return the length in bytes of the encoded variable-length integer.
 */
static inline int
vlint_encode(uint64 v, char *data)
{
	char *p;

	for (p = data; v != 0; v >>= 8)	{
		*p++ = v & 0xff;
	}

	return p - data;
}

/**
 * Decodes a variable-length integer. This encoding is equivalent to
 * little-endian encoding whereas trailing zeros are discarded.
 *
 * @param data	the payload to decode.
 * @param len	the length of data in bytes.
 *
 * @return The decoded value.
 */
static inline uint64
vlint_decode(const char *data, size_t len)
{
	uint64 v;
	uint i;

	v = 0;
	if (len <= 8) {
		for (i = 0; i < len; i++) {
			v |= (((uint64) data[i]) & 0xff) << (i * 8);
		}
	}
	return v;
}

#endif /* _misc_h_ */

/* vi: set ts=4 sw=4 cindent: */
