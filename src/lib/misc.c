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
 * Miscellaneous functions.
 *
 * @author Raphael Manfredi
 * @date 2001-2003
 */

#include "common.h"

RCSID("$Id$")

#include "atoms.h"
#include "base16.h"
#include "base32.h"
#include "endian.h"
#include "eval.h"
#include "html_entities.h"
#include "misc.h"
#include "glib-missing.h"
#include "sha1.h"
#include "tm.h"
#include "walloc.h"
#include "utf8.h"

#include "lib/misc.h"
#include "lib/fs_free_space.h"

#include "override.h"			/* Must be the last header included */

#if !defined(HAS_ARC4RANDOM) && (!defined(HAS_SRANDOM) || !defined(HAS_RANDOM))
#error "No sufficient PRNG functions available."
/*
 * srandom() and random() are available as open-source implementations. Use
 * that or a stronger PRNG but do NOT use crappy toys like srand()/rand()!
 */
#endif	/* HAS_SRANDOM && HAS_RANDOM */

static const char hex_alphabet[] = "0123456789ABCDEF";
const char hex_alphabet_lower[] = "0123456789abcdef";

#if !defined(HAS_STRLCPY) && !defined(USE_GLIB2)
size_t
strlcpy(gchar *dst, const gchar *src, size_t dst_size)
{
	gchar *d = dst;
	const gchar *s = src;

	g_assert(NULL != dst);
	g_assert(NULL != src);

	if (dst_size--) {
		size_t i = 0;

		while (i < dst_size) {
			if (!(*d++ = *s++))
				return i;
			i++;
		}
		dst[dst_size] = '\0';
	}
 	while (*s)
		s++;
	return s - src;
}
#endif /* HAS_STRLCPY */

#if !defined(HAS_STRLCAT) && !defined(USE_GLIB2)
size_t
strlcat(gchar *dst, const gchar *src, size_t dst_size)
{
	size_t n;
	
	g_assert(NULL != dst);
	g_assert(NULL != src);

	n = strlen(dst);	
	if (n < dst_size) {
		dst_size -= n;
	} else if (dst_size > 0) {
		dst[dst_size - 1] = '\0';
		dst_size = 0;
	}
	return n += g_strlcpy(&dst[n], src, dst_size);
}
#endif /* HAS_STRLCAT */

/**
 * Concatenates a variable number of NUL-terminated strings into ``dst''.
 *
 * The resulting string will be NUL-terminated unless ``size'' is zero. The
 * returned value is the length of the resulting string if ``dst'' had been
 * large enough. If the returned value is equal to or greater than ``size''
 * the string is truncated. If ``size'' is zero, ``dst'' may be NULL to
 * calculate the resulting string length.
 *
 * The list of strings must be terminated by a NULL pointer. The first
 * list element may be NULL in which case zero is returned.
 *
 * @param dst the destination buffer.
 * @param size the number of bytes ``dst'' can hold.
 * @param s the first source string or NULL.
 *
 * @return the sum of the lengths of all passed strings.
 */
size_t
concat_strings(gchar *dst, size_t size, const gchar *s, ...)
{
	va_list ap;
	gchar *p = dst;

	g_assert(0 == size || NULL != dst);

	va_start(ap, s);

	if (size > 0) {
		if (!s)
			*p = '\0';

		while (NULL != s) {
			size_t len;

			len = g_strlcpy(p, s, size);
			s = va_arg(ap, const gchar *);
			p += len;
			if (len >= size) {
				size = 0;
				break;
			}
			size -= len;
		}
	}

	while (NULL != s) {
		p += strlen(s);
		s = va_arg(ap, const gchar *);
	}

	va_end(ap);

	return p - dst;
}

/**
 * Concatenates a variable number of NUL-terminated strings into buffer
 * which will be allocated using walloc().
 *
 * The list of strings must be terminated by a NULL pointer. The first
 * list element may be NULL in which case 1 is returned.
 *
 * @param dst_ptr if not NULL, it will point to the allocated buffer.
 * @param first the first source string or NULL.
 *
 * @return The sum of the lengths of all passed strings plus 1 for the
 *         the trailing NUL. Use this as size argument for wfree() to
 *		   release the allocated buffer.
 */
size_t
w_concat_strings(gchar **dst_ptr, const gchar *first, ...)
{
	va_list ap, ap2;
	const gchar *s;
	size_t size;

	va_start(ap, first);
	VA_COPY(ap2, ap);

	for (s = first, size = 1; NULL != s; /* NOTHING */) {
		size += strlen(s);
		s = va_arg(ap, const gchar *);
	}

	va_end(ap);

	if (dst_ptr) {
		gchar *p;
		size_t n, len = size - 1;

		*dst_ptr = p = walloc(size);
		for (s = first; NULL != s; p += n, len -= n) {
			n = g_strlcpy(p, s, len + 1);
			s = va_arg(ap2, const gchar *);
			g_assert(n <= len);
		}
		*p = '\0';
		g_assert(0 == len);
	}

	va_end(ap2);

	return size;
}

/**
 * Checks whether ``prefix'' is a prefix of ``str''.
 * Maybe skip_prefix() would be a better name.
 *
 * @param str a NUL-terminated string
 * @param prefix a NUL-terminated string
 *
 * @return	NULL, if ``prefix'' is not a prefix of ``str''. Otherwise, a
 *			pointer to the first character in ``str'' after the prefix.
 */
gchar *
is_strprefix(const gchar *str, const gchar *prefix)
{
	const gchar *s, *p;
	gint c;

	g_assert(NULL != str);
	g_assert(NULL != prefix);

	for (s = str, p = prefix; '\0' != (c = *p); p++) {
		if (c != *s++)
			return NULL;
	}

	return deconstify_gchar(s);
}

/**
 * Checks whether ``prefix'' is a prefix of ``str'' performing an
 * case-insensitive (ASCII only) check.
 * Maybe skip_caseprefix() would be a better name.
 *
 * @param str a NUL-terminated string
 * @param prefix a NUL-terminated string
 *
 * @return	NULL, if ``prefix'' is not a prefix of ``str''. Otherwise, a
 *			pointer to the first character in ``str'' after the prefix.
 */
gchar *
is_strcaseprefix(const gchar *str, const gchar *prefix)
{
	const gchar *s, *p;
	gint a;

	g_assert(NULL != str);
	g_assert(NULL != prefix);

	for (s = str, p = prefix; '\0' != (a = *p); p++) {
		gint b = *s++;
		if (a != b && ascii_tolower(a) != ascii_tolower(b))
			return NULL;
	}

	return deconstify_gchar(s);
}

/**
 * Check for file existence.
 */
gboolean
file_exists(const gchar *pathname)
{
  	struct stat st;

    g_assert(pathname);
    return 0 == stat(pathname, &st);
}

/**
 * Check for file non-existence.
 */
gboolean
file_does_not_exist(const gchar *pathname)
{
  	struct stat st;

    g_assert(pathname);
	return stat(pathname, &st) && ENOENT == errno;
}

/**
 * Prints the unsigned 16-bit value ``v'' in hexadecimal presentation as
 * NUL-terminated string to ``dst'' and returns the length of the resulting
 * string. ``dst'' must point to a buffer of 5 or more bytes.
 *
 * @param dst the destination buffer.
 * @param v the 16-bit value.
 * @return the length of resulting string.
 */
static inline size_t
print_uint16_hex(gchar *dst, guint16 v)
{
	gchar *p = dst;
	gint i;

	for (i = 0; i < 3; i++, v <<= 4) {
		guint8 d;

		d = v >> 12;
		if (0 != d || p != dst)
			*p++ = hex_alphabet_lower[d];
	}
	*p++ = hex_alphabet_lower[v >> 12];

	*p = '\0';
	return p - dst;
}

/**
 * Converts an integer to a single decimal ASCII digit. The are no checks,
 * this is just a convenience function.
 *
 * @param x An integer between 0 and 9.
 * @return The ASCII character corresponding to the decimal digit [0-9].
 */
static inline guchar
dec_digit(guchar x)
{
	static const gchar dec_alphabet[] = "0123456789";
	return dec_alphabet[x % 10];
}

/**
 * Converts an IPv4 address in host-endian order to a string.
 *
 * @param ipv4 An 32-bit integer holding an IPv4 address in host-endian order.
 * @param dst The destination buffer to hold the resulting string.
 * @param size The size of the `dst' buffer in bytes. This should be
 *             IPV4_ADDR_BUFLEN or larger, otherwise the string will be
               truncated.
 * @return The length of the resulting string assuming `size' was sufficiently
 *         large.
 */
size_t
ipv4_to_string_buf(guint32 ipv4, gchar *dst, size_t size)
{
	gchar buf[IPV4_ADDR_BUFLEN];
	gchar * const p0 = size < sizeof buf ? buf : dst;
	gchar *p = p0;
	guint i;

	for (i = 0; i < 4; i++) {
		guchar v;
	   
		v = (ipv4 >> 24) & 0xff;
		ipv4 <<= 8;

		if (v >= 10) {
			div_t r;

			if (v >= 100) {
				r = div(v, 100);
				*p++ = dec_digit(r.quot);
				v = r.rem;
			}

			r = div(v, 10);
			*p++ = dec_digit(r.quot);
			v = r.rem;
		}
		*p++ = dec_digit(v);
		if (i < 3)
			*p++ = '.';
	}
	*p = '\0';

	if (p0 != dst) {
		g_strlcpy(dst, p0, size);
	}
	return p - p0;
}

/**
 * Prints the IPv6 address ``ipv6'' to ``dst''. The string written to ``dst''
 * is always NUL-terminated unless ``size'' is zero. If ``size''
 * is too small, the string will be truncated.
 *
 * @param dst the destination buffer; may be NULL iff ``size'' is zero.
 * @param ipv6 the IPv6 address; must point to a buffer of 16 bytes.
 * @param size the size of ``dst'' in bytes.
 *
 * @return The length of the resulting string assuming ``size'' is sufficient.
 */
size_t
ipv6_to_string_buf(const uint8_t *ipv6, gchar *dst, size_t size)
{
	gchar *p, buf[IPV6_ADDR_BUFLEN];
	const gchar *q;
	gint zero_len = 2, zero_start = -1;
	gint cur_len = 0, cur_start = 0;
	gint i;

	g_assert(ipv6);
	g_assert(0 == size || NULL != dst);

	/*
	 * Use a temporary buffer if ``size'' is not "safe" so that we
	 * don't need any boundary checks.
	 */
	q = p = size < sizeof buf ? buf : dst;

	/*
	 * The zero compression "::" is allowed exactly once. Thus, determine
	 * the longest run of zeros first.
	 */

	for (i = 0; i < 16; /* NOTHING */) {
		guint16 v;

		v = peek_be16(&ipv6[i]);

		/* We want "::1" and "::" but "::192.0.20.3" */
		if (0 == v && (12 != i || 0 == cur_len || 0 == ipv6[12]))
			cur_len += 2;

		i += 2;
		if (0 != v || 16 == i) {
			if (cur_len > zero_len) {
				zero_start = cur_start;
				zero_len = cur_len;
			}
			cur_start = i;
			cur_len = 0;
		}
	}


	for (i = 0; i < 16; /* NOTHING */) {
		guint16 v = peek_be16(&ipv6[i]);

		if (i != zero_start) {
			p += print_uint16_hex(p, v);
			i += 2;

			if (i < 16 && i != zero_start)
				*p++ = ':';
		} else if (zero_len > 0) {
			/* Compress the longest string of contiguous zeros with "::" */
			i += zero_len;
			*p++ = ':';
			*p++ = ':';
		}

		/*
		 * Use IPv4 representation for the special addresses
		 */
		if (12 == i &&
			(
			 (0xffff == v && 10 == zero_len) ||
			 (0x0000 == v && 12 == zero_len)
			)
		) {
			size_t n;

			n = sizeof buf - (p - q);
			p += ipv4_to_string_buf(peek_be32(&ipv6[12]), p, n);
			break;
		}

	}

	/* Now copy the result to ``dst'' if we used the temporary buffer. */
	if (dst != q) {
		size_t n = size - 1;

		n = MIN(n, (size_t) (p - q));
		memcpy(dst, q, n);
		dst[n] = '\0';
	}

	*p = '\0';
	return p - q;
}

/**
 * Prints the IPv6 address ``ipv6'' to a static buffer.
 *
 * @param ipv6 the IPv6 address; must point to a buffer of 16 bytes.
 * @return a pointer to a static buffer holding a NUL-terminated string
 *         representing the given IPv6 address.
 */
const gchar *
ipv6_to_string(const guint8 *ipv6)
{
	static gchar buf[IPV6_ADDR_BUFLEN];
	size_t n;

	n = ipv6_to_string_buf(ipv6, buf, sizeof buf);
	g_assert(n < sizeof buf);
	return buf;
}

const gchar *
ip_to_string(guint32 ip)
{
	static gchar buf[IPV4_ADDR_BUFLEN];

	ipv4_to_string_buf(ip, buf, sizeof buf);
	return buf;
}

const gchar *
hostname_port_to_string(const gchar *hostname, guint16 port)
{
	static gchar a[300];

	gm_snprintf(a, sizeof(a), "%.255s:%u", hostname, port);
	return a;
}

/**
 * @returns 0 if ``s'' is not a valid IPv4 address. Otherwise, the parsed
 * 			IPv4 address in host byte order.
 */
guint32
string_to_ip(const gchar *s)
{
	guint32 ip;

	s = skip_ascii_spaces(s);
	return string_to_ip_strict(s, &ip, NULL) ? ip : 0;
}

/**
 * Parses an IPv6 address.
 *
 * @param s the string to parse.
 * @param dst will hold the IPv6 address on success; must
 *        point to 16 or more bytes .
 * @param endptr if not NULL, it will point to the next character after
 *        the parsed address on success. On failure it will point to the
 *        character which caused the failure.
 * @returns FALSE if ``s'' is not a valid IPv6 address; TRUE on success.
 */
gboolean
parse_ipv6_addr(const gchar *s, guint8 *dst, const gchar **endptr)
{
	guint8 buf[16];
	gint i;
	guchar c = 0, last;
	gint dc_start = -1;
	gint error;

	g_assert(s);

	for (i = 0; i < 16; /* NOTHING */) {
		const gchar *ep;
		guint32 v;

		last = c;
		c = *s;

		if (':' == c) {
			if (':' == last) {
				if (dc_start >= 0) {
					/* Second double colon */
					s--; /* Rewind to the really bad colon */
					break;
				}
				dc_start = i;
			}
			s++;
			continue;
		}

		if (!is_ascii_xdigit(c)) {
			/* "Expected hexdigit" */
			break;
		}

		v = parse_uint32(s, &ep, 16, &error);
		if (error || v > 0xffff) {
			/* parse_uint32() failed */
			break;
		}

		if (*ep == '.' && i <= 12) {
			guint32 ip;

			if (string_to_ip_strict(s, &ip, &ep)) {
				s = ep;
				poke_be32(&buf[i], ip);
				i += 4;
			}
			/* IPv4 found */
			break;
		}

		buf[i++] = v >> 8;
		buf[i++] = v & 0xff;

		s = ep;

		if ('\0' == *s) {
			/* NUL reached */
			break;
		}

		last = 0;
	}

	if (endptr)
		*endptr = s;

	if (dc_start >= 0) {
		gint z, n, j;

		z = 16 - i;
		n = i - dc_start;

		for (j = 1; j <= n; j++)
			buf[16 - j] = buf[dc_start + n - j];

		memset(&buf[dc_start], 0, z);
		i += z;
	}

	if (16 != i)
		return FALSE;

	if (dst)
		memcpy(dst, buf, sizeof buf);

	return TRUE;
}

/**
 * A strict string to IP address conversion; when other stuff from misc.[ch]
 * is not sufficient.
 *
 * @return TRUE if ``s'' pointed to a string representation of an IPv4
 * address, otherwise FALSE.
 *
 * If successful, ``*addr'' will be set to the IPv4 address in NATIVE
 * byte order and ``*endptr'' will point to the character after the
 * IPv4 address. ``addr'' and ``endptr'' may be NULL.
 */
gboolean
string_to_ip_strict(const gchar *s, guint32 *addr, const gchar **endptr)
{
	const gchar *p = s;
	guint32 a = 0; /* 'pid compiler */
	gboolean valid;
	gint i;

	g_assert(s);

	i = 0;
	for (;;) {
		gint d, v;
		
		v = dec2int_inline(*p);
		if (-1 == v)
			break;

		d = dec2int_inline(*++p);
		if (-1 != d) {
			v = v * 10 + d;
		
			d = dec2int_inline(*++p);
			if (-1 != d) {
				v = v * 10 + d;
				p++;
			}
		}

		a = (a << 8) | v;
		
		if (3 == i++ || '.' != *p)
			break;
		p++;
	}

	/*
	 * The check for a dot takes care of addresses like 192.0.2.17.example.com.
	 */
	valid = 4 == i && '.' != *p;
	
	if (endptr)
		*endptr = p;

	if (addr)
		*addr = valid ? a : 0;

	return valid; 
}

/**
 * Decompiles ip:port into ip and port.  Leading spaces are ignored.
 *
 * @return TRUE if it parsed correctly, FALSE otherwise.
 */
gboolean
string_to_ip_port(const gchar *s, guint32 *ip_ptr, guint16 *port_ptr)
{
	const gchar *ep;
	guint32 v;
	gint error;

	s = skip_ascii_spaces(s);
	if (!string_to_ip_strict(s, ip_ptr, &ep) || ':' != *ep)
		return FALSE;

	s = ++ep;
	v = parse_uint32(s, NULL, 10, &error);
	if (error || v > 65535)
		return FALSE;

	if (port_ptr)
		*port_ptr = v;

	return TRUE;
}

/**
 * @returns local host name, as pointer to static data.
 */
const gchar *
local_hostname(void)
{
	static gchar name[256 + 1];

	if (-1 == gethostname(name, sizeof name))
		g_warning("gethostname() failed: %s", g_strerror(errno));

	name[sizeof(name) - 1] = '\0';
	return name;
}

/**
 * Remove antepenultimate char of string if it is a "\r" followed by "\n".
 * Remove final char of string if it is a "\n" or "\r".
 * If len is 0, compute it.
 *
 * @returns new string length.
 */
size_t
str_chomp(gchar *str, size_t len)
{
	if (len == 0) {
		len = strlen(str);
		if (len == 0)
			return 0;
	}

	if (len >= 2 && str[len-2] == '\r' && str[len-1] == '\n') {
		str[len-2] = '\0';
		return len - 2;
	}

	if (str[len-1] == '\n' || str[len-1] == '\r') {
		str[len-1] = '\0';
		return len - 1;
	} else
		return len;
}

/**
 * Create an absolute path.
 */
gchar *
absolute_pathname(const char *file)
{
	g_assert(file);
	
	if (is_absolute_path(file)) {
		return g_strdup(file);
	} else if ('\0' == file[0]) {
		return NULL;
	} else {
		gchar buf[4096], *ret;

		ret = getcwd(buf, sizeof buf);
		return ret ? make_pathname(ret, file) : NULL;
	}
}

/**
 * Check whether path is an absolute path.
 */
gboolean
is_absolute_path(const char *pathname)
{
	g_assert(pathname);
	return '/' == pathname[0] || G_DIR_SEPARATOR == pathname[0];
}

/**
 * Check whether path is a directory.
 */
gboolean
is_directory(const gchar *pathname)
{
	struct stat st;

	g_assert(pathname);
	return 0 == stat(pathname, &st) && S_ISDIR(st.st_mode);
}

/**
 * Check whether path points to a regular file.
 */
gboolean
is_regular(const gchar *pathname)
{
	struct stat st;

	g_assert(pathname);
	return 0 == stat(pathname, &st) && S_ISREG(st.st_mode);
}

/**
 * Check whether path is a symbolic link.
 */
gboolean
is_symlink(const gchar *pathname)
#if defined(HAS_LSTAT)
{
	struct stat st;

	g_assert(pathname);
	if (0 != lstat(pathname, &st))
		return FALSE;
	return (st.st_mode & S_IFMT) == S_IFLNK;
}
#else /* !HAS_LSTAT */
{
	g_assert(pathname);
	return FALSE;
}
#endif /* HAS_LSTAT */

/**
 * Tests whether the two given pathnames point to same file using stat().
 * @param pathname_a A pathname.
 * @param pathname_b A pathname.
 * @return -1 on error, errno will be set by either stat() call.
 *          FALSE if the device number and file serial number are different.
 *          TRUE if the device number and file serial number are different.
 */
int
is_same_file(const char *pathname_a, const char *pathname_b)
{
	struct stat sb_a, sb_b;

	g_assert(pathname_a);
	g_assert(pathname_b);

	/* May no exist but points clearly to the same file */
	if (0 == strcmp(pathname_a, pathname_b))
		return TRUE;

	if (stat(pathname_a, &sb_a))
		return -1;

	if (stat(pathname_b, &sb_b))
		return -1;

	return sb_a.st_dev == sb_b.st_dev && sb_a.st_ino == sb_b.st_ino;
}

/**
 * A wrapper around lseek() for handling filesize_t to off_t conversion.
 *
 * @param fd A valid file descriptor.
 * @param pos The position to seek to.
 * @return 0 on success and -1 on failure.
 */
gint
seek_to_filepos(gint fd, filesize_t pos)
{
	off_t offset;

	offset = filesize_to_off_t(pos);
	if ((off_t) -1 == offset) {
		errno = ERANGE;
		return -1;
	} else {
		gint saved_errno = errno;
		off_t ret;

		/* Clear errno to be sure we get no bogus errno code, if
		 * the system does not agree with us that the lseek()
		 * failed. */
		errno = 0;
		ret = lseek(fd, offset, SEEK_SET);
		if ((off_t) -1 == ret || ret != offset) {
			return -1;
		}
		errno = saved_errno;
	}
	return 0;
}

static inline guint
filesize_fraction(filesize_t size, filesize_t part, guint base)
{
	filesize_t x;

	/**
	 * Use integer arithmetic because float or double might be too small
	 * for 64-bit values.
	 */
	if (size == part) {
		return base;
	}
	if (size > base) {
		x = size / base;
		x = part / MAX(1, x);
	} else {
		x = (part * base) / MAX(1, size);
	}
	base--;
	return MIN(x, base);
}

#define GENERATE_FILESIZE_PER_X(base) \
guint \
filesize_per_ ## base (filesize_t size, filesize_t part) \
{ \
	return filesize_fraction(size, part, base); \
}

GENERATE_FILESIZE_PER_X(100)
GENERATE_FILESIZE_PER_X(1000)
GENERATE_FILESIZE_PER_X(10000)
#undef GENERATE_FILESIZE_PER_X

static inline guint
kilo(gboolean metric)
{
	return metric ? 1000 : 1024;
}

static inline const gchar *
byte_suffix(gboolean metric)
{
	static const gchar suffix[] = "iB";
	return &suffix[metric ? 1 : 0];
}

static inline const gchar *
scale_prefixes(gboolean metric)
{
	return metric ? "\0kMGTPEZ" : "\0KMGTPEZ";
}

/**
 * Scales v so that quotient and reminder are both in the range "0..1023".
 *
 * @param v no document.
 * @param q pointer to a guint; will hold the quotient.
 * @param r pointer to a guint; will hold the reminder.
 * @param s a string holding the scale prefixes; must be sufficiently long.
 *
 * @return the appropriate prefix character from "s".
 */
static inline gchar
size_scale(guint64 v, guint *q, guint *r, const gchar *s, gboolean metric)
{
	const guint base = kilo(metric);

	if (v < base) {
		*q = v;
		*r = 0;
	} else {
		const guint thresh = base * base;

		for (s++; v >= thresh; v /= base)
			s++;
	
		*q = (guint) v / base;
		*r = (guint) v % base;
	}
	return *s;
}

static inline gchar
norm_size_scale(guint64 v, guint *q, guint *r, gboolean metric)
{
	return size_scale(v, q, r, scale_prefixes(metric), metric);
}

/**
 * Same as norm_size_scale_base2() but assumes v is already divided
 * by 1024 (binary).
 */
static inline gchar
kib_size_scale(guint64 v, guint *q, guint *r, gboolean metric)
{
	if (metric && v < ((guint64) -1) / 1024) {
		v = (v * 1024) / 1000;
	}
	return size_scale(v, q, r, scale_prefixes(metric) + 1, metric);
}

const gchar *
short_size(guint64 size, gboolean metric)
{
	static gchar b[SIZE_FIELD_MAX];

	if (size < kilo(metric)) {
		guint n = size;
		gm_snprintf(b, sizeof b, NG_("%u Byte", "%u Bytes", n), n);
	} else {
		guint q, r;
		gchar c;

		c = norm_size_scale(size, &q, &r, metric);
		r = (r * 100) / kilo(metric);
		gm_snprintf(b, sizeof b, "%u.%02u %c%s", q, r, c, byte_suffix(metric));
	}

	return b;
}

/**
 * Like short_size() but with unbreakable space between the digits and unit.
 */
const gchar *
short_html_size(guint64 size, gboolean metric)
{
	static gchar b[SIZE_FIELD_MAX];

	if (size < kilo(metric)) {
		guint n = size;
		gm_snprintf(b, sizeof b, NG_("%u&nbsp;Byte", "%u&nbsp;Bytes", n), n);
	} else {
		guint q, r;
		gchar c;

		c = norm_size_scale(size, &q, &r, metric);
		r = (r * 100) / kilo(metric);
		gm_snprintf(b, sizeof b, "%u.%02u&nbsp;%c%s", q, r, c,
			byte_suffix(metric));
	}

	return b;
}

const gchar *
short_kb_size(guint64 size, gboolean metric)
{
	static gchar b[SIZE_FIELD_MAX];
	
	if (size < kilo(metric)) {
		gm_snprintf(b, sizeof b, "%u %s", (guint) size, metric ? "kB" : "KiB");
	} else {
		guint q, r;
		gchar c;

		c = kib_size_scale(size, &q, &r, metric);
		r = (r * 100) / kilo(metric);
		gm_snprintf(b, sizeof b, "%u.%02u %c%s", q, r, c, byte_suffix(metric));
	}

	return b;
}

/**
 * @return a number of Kbytes in a compact readable form
 */
const gchar *
compact_kb_size(guint32 size, gboolean metric)
{
	static gchar b[SIZE_FIELD_MAX];

	if (size < kilo(metric)) {
		gm_snprintf(b, sizeof b, "%u%s", (guint) size, metric ? "kB" : "KiB");
	} else {
		guint q, r;
		gchar c;

		c = kib_size_scale(size, &q, &r, metric);
		r = (r * 10) / kilo(metric);
		gm_snprintf(b, sizeof b, "%u.%u%c%s", q, r, c, byte_suffix(metric));
	}

	return b;
}

const gchar *
nice_size(guint64 size, gboolean metric)
{
	static gchar buf[256];
	gchar bytes[UINT64_DEC_BUFLEN];

	uint64_to_string_buf(size, bytes, sizeof bytes);
	gm_snprintf(buf, sizeof buf,
		_("%s (%s bytes)"), short_size(size, metric), bytes);
	return buf;
}

gchar *
compact_value(gchar *buf, size_t size, guint64 v, gboolean metric)
{
	if (v < kilo(metric)) {
		gm_snprintf(buf, size, "%u", (guint) v);
	} else {
		guint q, r;
		gchar c;

		c = norm_size_scale(v, &q, &r, metric);
		r = (r * 10) / kilo(metric);
		gm_snprintf(buf, size, "%u.%u%c%s", q, r, c, metric ? "" : "i");
	}

	return buf;
}

gchar *
short_value(gchar *buf, size_t size, guint64 v, gboolean metric)
{
	if (v < kilo(metric)) {
		gm_snprintf(buf, size, "%u ", (guint) v);
	} else {
		guint q, r;
		gchar c;

		c = norm_size_scale(v, &q, &r, metric);
		r = (r * 100) / kilo(metric);
		gm_snprintf(buf, size, "%u.%02u %c%s", q, r, c, metric ? "" : "i");
	}
	
	return buf;
}

const gchar *
compact_size(guint64 size, gboolean metric)
{
	static gchar buf[SIZE_FIELD_MAX];

	compact_value(buf, sizeof buf, size, metric);
	g_strlcat(buf, "B", sizeof buf);
	return buf;
}

const gchar *
compact_rate(guint64 rate, gboolean metric)
{
	static gchar buf[SIZE_FIELD_MAX];

	compact_value(buf, sizeof buf, rate, metric);
	/* TRANSLATORS: Don't translate 'B', just 's' is allowed. */
	g_strlcat(buf, _("B/s"), sizeof buf);
	return buf;
}

static size_t
short_rate_to_string_buf(guint64 rate, gboolean metric, gchar *dst, size_t size)
{
	short_value(dst, size, rate, metric);
	/* TRANSLATORS: Don't translate 'B', just 's' is allowed. */
	return g_strlcat(dst, _("B/s"), size);
}

short_string_t
short_rate_get_string(guint64 rate, gboolean metric)
{
	short_string_t buf;
	short_rate_to_string_buf(rate, metric, buf.str, sizeof buf.str);
	return buf;
}

const gchar *
short_rate(guint64 rate, gboolean metric)
{
	static short_string_t buf;
	buf = short_rate_get_string(rate, metric);
	return buf.str;
}

/**
 * @return time spent in seconds in a consise short readable form.
 * @note The returned string may be translated and non-ASCII.
 */
const gchar *
short_time(time_delta_t t)
{
	static gchar buf[4 * SIZE_FIELD_MAX];
	guint s = MAX(t, 0);

	if (s > 86400)
		gm_snprintf(buf, sizeof buf, _("%ud %uh"),
			s / 86400, (s % 86400) / 3600);
	else if (s > 3600)
		gm_snprintf(buf, sizeof buf, _("%uh %um"), s / 3600, (s % 3600) / 60);
	else if (s > 60)
		gm_snprintf(buf, sizeof buf, _("%um %us"), s / 60, s % 60);
	else
		gm_snprintf(buf, sizeof buf, _("%us"), s);

	return buf;
}

/**
 * @return time spent in seconds in a consise short readable form.
 * @note The returned string is in English and ASCII encoded.
 */
const gchar *
short_time_ascii(time_delta_t t)
{
	static gchar buf[4 * SIZE_FIELD_MAX];
	guint s = MAX(t, 0);

	if (s > 86400)
		gm_snprintf(buf, sizeof buf, "%ud %uh",
			s / 86400, (s % 86400) / 3600);
	else if (s > 3600)
		gm_snprintf(buf, sizeof buf, "%uh %um", s / 3600, (s % 3600) / 60);
	else if (s > 60)
		gm_snprintf(buf, sizeof buf, "%um %us", s / 60, s % 60);
	else
		gm_snprintf(buf, sizeof buf, "%us", s);

	return buf;
}

/**
 * A variant of short_time_ascii() without whitespace.
 *
 * @return time spent in seconds in a consise short readable form.
 * @note The returned string is in English and ASCII encoded.
 */
const gchar *
compact_time(time_delta_t t)
{
	static gchar buf[4 * SIZE_FIELD_MAX];
	guint s = MAX(t, 0);

	if (s > 86400)
		gm_snprintf(buf, sizeof buf, "%ud%uh",
			s / 86400, (s % 86400) / 3600);
	else if (s > 3600)
		gm_snprintf(buf, sizeof buf, "%uh%um", s / 3600, (s % 3600) / 60);
	else if (s > 60)
		gm_snprintf(buf, sizeof buf, "%um%us", s / 60, s % 60);
	else
		gm_snprintf(buf, sizeof buf, "%us", s);

	return buf;
}

/**
 * Alternate time formatter for uptime.
 */
const gchar *
short_uptime(time_delta_t uptime)
{
	static gchar b[SIZE_FIELD_MAX];
	guint s = MAX(uptime, 0);

	if (s > 86400) {
		guint32 d = s % 86400;
		gm_snprintf(b, sizeof(b), "%ud %02d%c%02d",
			s / 86400, d / 3600, (s & 0x1) ? '.' : ':', (d % 3600) / 60);
	} else {
		guint32 h = s % 3600;
		gm_snprintf(b, sizeof(b), "%02d:%02d:%02d", s / 3600, h / 60, h % 60);
	}

	return b;
}

/**
 * Convert binary data into a hexadecimal string.
 *
 * @param data		the data to convert
 * @paran len		length of the binary data supplied
 * @param dst		destination buffer, where to put the result
 * @param size		size of the destination buffer
 *
 * @return the length of the hexadecimal string generated.
 */
size_t
bin_to_hex_buf(const gchar *data, size_t len, gchar *dst, size_t size)
{
	size_t retval;

	if (size > 0) {
		retval = base16_encode(dst, size, data, len);
		dst[retval] = '\0';
	} else {
		retval = 0;
	}
	return retval;
}

/**
 * Convert GUID to hexadecimal string in the supplied buffer.
 */
size_t
guid_to_string_buf(const gchar *guid, gchar *dst, size_t size)
{
	return bin_to_hex_buf(guid, GUID_RAW_SIZE, dst, size);
}

/**
 * @return hexadecimal string representing given GUID, in static buffer.
 */
const gchar *
guid_to_string(const gchar *guid)
{
	static gchar buf[GUID_HEX_SIZE + 1];
	size_t ret;

	ret = guid_to_string_buf(guid, buf, sizeof buf);
	g_assert(GUID_HEX_SIZE == ret);
	return buf;
}

/**
 * @return hexadecimal string representing given GUID, in static buffer.
 */
const gchar *
guid_hex_str(const gchar *guid)
{
	static gchar buf[GUID_HEX_SIZE + 1];
	size_t ret;

	ret = guid_to_string_buf(guid, buf, sizeof buf);
	g_assert(GUID_HEX_SIZE == ret);
	return buf;
}

/**
 * @return hexadecimal string representation of "small" binary buffer.
 *
 * @note
 * Buffer must be less than 40 chars, or only the first 40 chars are
 * represented with a trailing "..." added to show it is incomplete.
 */
gchar *
data_hex_str(const gchar *data, size_t len)
{
	static gchar buf[84];
	static const size_t maxlen = sizeof(buf) - 4; /* 3 chars for "more" + NUL */
	const guint8 *p = cast_to_gconstpointer(data);
	size_t hmax;
	size_t i;

	hmax = 2 * len;
	hmax = MIN(hmax, maxlen);

	for (i = 0; i < hmax; p++) {
		buf[i++] = hex_alphabet_lower[*p >> 4];
		buf[i++] = hex_alphabet_lower[*p & 0x0f];
	}

	if (2 * len > hmax) {
		buf[i++] = '.';
		buf[i++] = '.';
		buf[i++] = '.';
	}

	g_assert(i < sizeof(buf));

	buf[i] = '\0';
	return buf;
}

static gint8 char2int_tabs[3][(size_t) (guchar) -1 + 1];

const gint8 *hex2int_tab = char2int_tabs[0];
const gint8 *dec2int_tab = char2int_tabs[1];
const gint8 *alnum2int_tab = char2int_tabs[2];

/**
 * Converts a hexadecimal char (0-9, A-F, a-f) to an integer.
 *
 * Passing a character which is not a hexadecimal ASCII character
 * causes an assertion failure.
 *
 * @param c the hexadecimal ASCII character to convert.
 * @return "0..15" for valid hexadecimal ASCII characters.
 */
gint
hex2int(guchar c)
{
	gint ret;
	
	ret = hex2int_inline(c);
	g_assert(-1 != ret);
	return ret;
}

/**
 * Converts a decimal char (0-9) to an integer.
 *
 * Passing a character which is not a decimal ASCII character causes
 * an assertion failure.
 *
 * @param c the decimal ASCII character to convert.
 * @return "0..9" for valid decimal ASCII characters.
 */
static gint
dec2int(guchar c)
{
	gint ret;
	
	ret = dec2int_inline(c);
	g_assert(-1 != ret);
	return ret;
}

/**
 * Converts an alphanumeric char (0-9, A-Z, a-z) to an integer.
 *
 * Passing a character which is not an alphanumeric ASCII character
 * causes an assertion failure.
 *
 * @param c the decimal ASCII character to convert.
 * @return "0..36" for valid decimal ASCII characters.
 */
static gint
alnum2int(guchar c)
{
	gint ret;
	
	ret = alnum2int_inline(c);
	g_assert(-1 != ret);
	return ret;
}

/**
 * Initializes the lookup table for hex2int().
 */
static void
hex2int_init(void)
{
	size_t i;

	/* Initialize hex2int_tab */
	
	for (i = 0; i < G_N_ELEMENTS(char2int_tabs[0]); i++) {
		static const gchar hexa[] = "0123456789abcdef";
		const gchar *p = i ? strchr(hexa, ascii_tolower(i)): NULL;
		
		char2int_tabs[0][i] = p ? (p - hexa) : -1;
	}
	
	/* Check consistency of hex2int_tab */

	for (i = 0; i <= (guchar) -1; i++)
		switch (i) {
		case '0': g_assert(0 == hex2int(i)); break;
		case '1': g_assert(1 == hex2int(i)); break;
		case '2': g_assert(2 == hex2int(i)); break;
		case '3': g_assert(3 == hex2int(i)); break;
		case '4': g_assert(4 == hex2int(i)); break;
		case '5': g_assert(5 == hex2int(i)); break;
		case '6': g_assert(6 == hex2int(i)); break;
		case '7': g_assert(7 == hex2int(i)); break;
		case '8': g_assert(8 == hex2int(i)); break;
		case '9': g_assert(9 == hex2int(i)); break;
		case 'A':
		case 'a': g_assert(10 == hex2int(i)); break;
		case 'B':
		case 'b': g_assert(11 == hex2int(i)); break;
		case 'C':
		case 'c': g_assert(12 == hex2int(i)); break;
		case 'D':
		case 'd': g_assert(13 == hex2int(i)); break;
		case 'E':
		case 'e': g_assert(14 == hex2int(i)); break;
		case 'F':
		case 'f': g_assert(15 == hex2int(i)); break;
		default:
				  g_assert(-1 == hex2int_inline(i));
		}
}

/**
 * Initializes the lookup table for dec2int().
 */
static void
dec2int_init(void)
{
	size_t i;

	/* Initialize dec2int_tab */
	
	for (i = 0; i < G_N_ELEMENTS(char2int_tabs[1]); i++) {
		static const gchar deca[] = "0123456789";
		const gchar *p = i ? strchr(deca, i): NULL;
		
		char2int_tabs[1][i] = p ? (p - deca) : -1;
	}
	
	/* Check consistency of hex2int_tab */

	for (i = 0; i <= (guchar) -1; i++)
		switch (i) {
		case '0': g_assert(0 == dec2int(i)); break;
		case '1': g_assert(1 == dec2int(i)); break;
		case '2': g_assert(2 == dec2int(i)); break;
		case '3': g_assert(3 == dec2int(i)); break;
		case '4': g_assert(4 == dec2int(i)); break;
		case '5': g_assert(5 == dec2int(i)); break;
		case '6': g_assert(6 == dec2int(i)); break;
		case '7': g_assert(7 == dec2int(i)); break;
		case '8': g_assert(8 == dec2int(i)); break;
		case '9': g_assert(9 == dec2int(i)); break;
		default:
				  g_assert(-1 == dec2int_inline(i));
		}
}

/**
 * Initializes the lookup table for alnum2int().
 */
static void
alnum2int_init(void)
{
	static const gchar abc[] = "0123456789abcdefghijklmnopqrstuvwxyz";
	size_t i;

	/* Initialize alnum2int_tab */
	
	for (i = 0; i < G_N_ELEMENTS(char2int_tabs[2]); i++) {
		const gchar *p = i ? strchr(abc, ascii_tolower(i)): NULL;
		
		char2int_tabs[2][i] = p ? (p - abc) : -1;
	}
	
	/* Check consistency of hex2int_tab */

	for (i = 0; i <= (guchar) -1; i++) {
		const gchar *p = i ? strchr(abc, ascii_tolower(i)): NULL;
		gint v = p ? (p - abc) : -1;
	
		g_assert(alnum2int_inline(i) == v);
		g_assert(!p || alnum2int(i) >= 0);
	}
}


/**
 * Converts hexadecimal string into a GUID.
 *
 * @param hexguid	the hexadecimal representation to convert
 * @param guid		the 16-byte array into which the decoded GUID is written to
 *
 * @return TRUE if OK.
 */
gboolean
hex_to_guid(const gchar *hexguid, gchar *guid)
{
	guint i;

	for (i = 0; i < GUID_RAW_SIZE; i++) {
 		guchar a, b;

		a = *hexguid++;
		if (!is_ascii_xdigit(a))
			return FALSE;

		b = *hexguid++;
		if (!is_ascii_xdigit(b))
			return FALSE;

		guid[i] = (hex2int_inline(a) << 4) + hex2int_inline(b);
	}

	return TRUE;
}

/**
 * Converts GUID into its base32 representation, without the trailing padding.
 *
 * @return pointer to static data.
 */
gchar *
guid_base32_str(const gchar *guid)
{
	static gchar buf[GUID_BASE32_SIZE + 1];
	size_t len;

	len = base32_encode(buf, sizeof buf, guid, GUID_RAW_SIZE);
	g_assert(len == G_N_ELEMENTS(buf) - 1);
	buf[len] = '\0';
	return buf;
}

/**
 * Decode the base32 representation of a GUID.
 *
 * @return pointer to static data, or NULL if the input was not valid base32.
 */
gchar *
base32_to_guid(const gchar *base32)
{
	static gchar guid[GUID_RAW_SIZE];
	size_t ret;

	ret = base32_decode(guid, sizeof guid, base32, GUID_BASE32_SIZE);
	return (size_t) GUID_RAW_SIZE == ret ? guid : NULL;
}

/**
 * Convert binary SHA1 into a base32 string.
 *
 * @param dst The destination buffer for the string.
 * @param size The size of "dst" in bytes; should be larger than
 *             SHA1_BASE32_SIZE, otherwise the resulting string will be
 *             truncated.
 * @return dst.
 */
char *
sha1_to_base32_buf(const struct sha1 *sha1, char *dst, size_t size)
{
	g_assert(sha1);
	if (size > 0) {
		base32_encode(dst, size, sha1->data, sizeof sha1->data);
		dst[size - 1] = '\0';
	}
	return dst;
}

/**
 * Convert binary SHA1 into a base32 string.
 *
 * @return pointer to static data.
 */
const gchar *
sha1_base32(const struct sha1 *sha1)
{
	static gchar digest_b32[SHA1_BASE32_SIZE + 1];

	g_assert(sha1);
	return sha1_to_base32_buf(sha1, digest_b32, sizeof digest_b32);
}

const gchar *
sha1_to_string(const struct sha1 sha1)
{
	static gchar digest_b32[SHA1_BASE32_SIZE + 1];
	return sha1_to_base32_buf(&sha1, digest_b32, sizeof digest_b32);
}

/**
 * Convert binary SHA1 into a urn:sha1:<base32> string.
 *
 * @param sha1 A binary SHA-1.
 * @return The SHA-1 converted to an URN string.
 */
size_t
sha1_to_urn_string_buf(const struct sha1 *sha1, char *dst, size_t size)
{
	static const char prefix[] = "urn:sha1:";
	size_t n;

	g_assert(sha1);

	n = MIN(size, CONST_STRLEN(prefix));
	memcpy(dst, prefix, n);
	size -= n;
	if (size > 0) {
		n = MIN(size, (SHA1_BASE32_SIZE + 1));
		sha1_to_base32_buf(sha1, &dst[CONST_STRLEN(prefix)], n);
	}
	return CONST_STRLEN(prefix) + SHA1_BASE32_SIZE + 1;
}

const char *
sha1_to_urn_string(const struct sha1 *sha1)
{
	static char buf[CONST_STRLEN("urn:sha1:") + SHA1_BASE32_SIZE + 1];

	g_assert(sha1);
	sha1_to_urn_string_buf(sha1, buf, sizeof buf);
	return buf;
}

const char *
bitprint_to_urn_string(const struct sha1 *sha1, const struct tth *tth)
{
	g_assert(sha1);

	if (tth) {
		static const char prefix[] = "urn:bitprint:";
		static char buf[CONST_STRLEN(prefix) + BITPRINT_BASE32_SIZE + 1];
		const char * const end = &buf[sizeof buf];
		char *p = buf;

		memcpy(p, prefix, CONST_STRLEN(prefix));
		p += CONST_STRLEN(prefix);
		
		base32_encode(p, end - p, sha1->data, sizeof sha1->data);
		p += SHA1_BASE32_SIZE;

		*p++ = '.';
		
		base32_encode(p, end - p, tth->data, sizeof tth->data);
		p += TTH_BASE32_SIZE;
		*p = '\0';
		
		return buf;
	} else {
		static char buf[CONST_STRLEN("urn:sha1:") + SHA1_BASE32_SIZE + 1];

		sha1_to_urn_string_buf(sha1, buf, sizeof buf);
		return buf;
	}
}

/**
 * Convert base32 string into binary SHA1.
 *
 * @param base32 a buffer holding SHA1_BASE32_SIZE or more bytes.
 *
 * @return	Returns pointer to static data or NULL if the input wasn't a
 *			validly base32 encoded SHA1.
 */
const struct sha1 *
base32_sha1(const char *base32)
{
	static struct sha1 sha1;
	size_t len;

	g_assert(base32);
	len = base32_decode(sha1.data, sizeof sha1.data, base32, SHA1_BASE32_SIZE);
	return SHA1_RAW_SIZE == len ? &sha1 : NULL;
}

/**
 * Convert binary TTH into a base32 string.
 *
 * @return pointer to static data.
 */
const char *
tth_base32(const struct tth *tth)
{
	static char buf[TTH_BASE32_SIZE + 1];

	g_assert(tth);
	base32_encode(buf, sizeof buf, tth->data, sizeof tth->data);
	buf[sizeof buf - 1] = '\0';
	return buf;
}

/**
 * Convert base32 string into a binary TTH.
 *
 * @param base32 a buffer holding TTH_BASE32_SIZE or more bytes.
 *
 * @return	Returns pointer to static data or NULL if the input wasn't a
 *			validly base32 encoded TTH.
 */
const struct tth *
base32_tth(const char *base32)
{
	static struct tth tth;
	size_t len;

	g_assert(base32);
	len = base32_decode(tth.data, sizeof tth.data, base32, TTH_BASE32_SIZE);
	return TTH_RAW_SIZE == len ? &tth : NULL;
}

/**
 * Convert binary TTH into a base32 string.
 *
 * @param dst The destination buffer for the string.
 * @param size The size of "dst" in bytes; should be larger than
 *             TTH_BASE32_SIZE, otherwise the resulting string will be
 *             truncated.
 * @return dst.
 */
char *
tth_to_base32_buf(const struct tth *tth, char *dst, size_t size)
{
	g_assert(tth);
	if (size > 0) {
		base32_encode(dst, size, tth->data, sizeof tth->data);
		dst[size - 1] = '\0';
	}
	return dst;
}

/**
 * Convert binary TTH into a urn:ttroot:<base32> string.
 *
 * @param tth A binary TTH.
 * @return The TTH converted to an URN string.
 */
size_t
tth_to_urn_string_buf(const struct tth *tth, char *dst, size_t size)
{
	static const char prefix[] = "urn:ttroot:";
	size_t n;

	g_assert(tth);

	n = MIN(size, CONST_STRLEN(prefix));
	memcpy(dst, prefix, n);
	size -= n;
	if (size > 0) {
		n = MIN(size, (TTH_BASE32_SIZE + 1));
		tth_to_base32_buf(tth, &dst[CONST_STRLEN(prefix)], n);
	}
	return CONST_STRLEN(prefix) + TTH_BASE32_SIZE + 1;
}

const char *
tth_to_urn_string(const struct tth *tth)
{
	static char buf[CONST_STRLEN("urn:ttroot:") + TTH_BASE32_SIZE + 1];

	g_assert(tth);
	tth_to_urn_string_buf(tth, buf, sizeof buf);
	return buf;
}

/**
 * Convert time to ISO 8601 date plus time, e.g. "2002-06-09 14:54:42Z".
 *
 * @return The length of the created string.
 */
size_t
timestamp_utc_to_string_buf(time_t date, gchar *dst, size_t size)
{
	const struct tm *tm = localtime(&date);
	size_t len;

	g_assert(size > 0);
	tm = gmtime(&date);
	len = strftime(dst, size, "%Y-%m-%d %H:%M:%SZ", tm);
	dst[len] = '\0';		/* Be really sure */

	return len;
}

/**
 * Convert time to an ISO 8601 timestamp, e.g. "2002-06-09T14:54:42Z".
 *
 * @return pointer to static data.
 */
const gchar *
timestamp_utc_to_string(time_t date)
{
	static gchar buf[80];
	timestamp_utc_to_string_buf(date, buf, sizeof buf);
	return buf;
}

/**
 * Convert time to ISO 8601 date plus time, e.g. "2002-06-09 14:54:42".
 *
 * @return The length of the created string.
 */
size_t
timestamp_to_string_buf(time_t date, gchar *dst, size_t size)
{
	const struct tm *tm = localtime(&date);
	size_t len;

	g_assert(size > 0);
	tm = localtime(&date);
	len = strftime(dst, size, "%Y-%m-%d %H:%M:%S", tm);
	dst[len] = '\0';		/* Be really sure */

	return len;
}

short_string_t
timestamp_get_string(time_t date)
{
	short_string_t buf;
	timestamp_to_string_buf(date, buf.str, sizeof buf.str);
	return buf;
}

/**
 * Convert time to ISO 8601 date plus time, e.g. "2005-11-10 20:21:57".
 *
 * @return pointer to static data.
 */
const gchar *
timestamp_to_string(time_t date)
{
	static gchar buf[TIMESTAMP_BUF_LEN];

	timestamp_to_string_buf(date, buf, sizeof buf);
	return buf;
}

/**
 * Convert time (without the date) to a human-readable string using the
 * time representation of the current locale.
 *
 * @param t		time to convert.
 * @param dst	buffer to hold the resulting string.
 * @param size	the size of the dst buffer.
 *
 * @return		length of the created string.
 */
size_t
time_locale_to_string_buf(time_t t, gchar *dst, size_t size)
{
	const struct tm *tm = localtime(&t);
	size_t len;

	g_assert(size > 0);	

	len = strftime(dst, size, "%X", tm);
	dst[len] = '\0';

	return len;
}

/**
 * Compute the difference in seconds between two tm structs (a - b).
 * Comes from glibc-2.2.5.
 */
static gint
tm_diff(const struct tm *a, const struct tm * b)
{
	/*
	 * Compute intervening leap days correctly even if year is negative.
	 * Take care to avoid int overflow in leap day calculations,
	 * but it's OK to assume that A and B are close to each other.
	 */

#define TM_YEAR_BASE 1900

	gint a4 = (a->tm_year >> 2) + (TM_YEAR_BASE >> 2) - ! (a->tm_year & 3);
	gint b4 = (b->tm_year >> 2) + (TM_YEAR_BASE >> 2) - ! (b->tm_year & 3);
	gint a100 = a4 / 25 - (a4 % 25 < 0);
	gint b100 = b4 / 25 - (b4 % 25 < 0);
	gint a400 = a100 >> 2;
	gint b400 = b100 >> 2;
	gint intervening_leap_days = (a4 - b4) - (a100 - b100) + (a400 - b400);
	gint years = a->tm_year - b->tm_year;
	gint days = (365 * years + intervening_leap_days
		+ (a->tm_yday - b->tm_yday));

	return (60 * (60 * (24 * days + (a->tm_hour - b->tm_hour))
		+ (a->tm_min - b->tm_min))
		+ (a->tm_sec - b->tm_sec));
}

static const gchar days[7][4] =
	{ "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" };

static const gchar months[12][4] = {
	"Jan", "Feb", "Mar", "Apr", "May", "Jun",
	"Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
};

/**
 * Convert time to RFC-822 style date, into supplied string buffer.
 *
 * @param date The timestamp.
 * @param buf The destination buffer to hold the resulting string. Must be
 *            greater than zero.
 * @param size The size of of "buf".
 * @return The length of the created string.
 */
static size_t 
timestamp_rfc822_to_string_buf(time_t date, gchar *buf, size_t size)
{
	struct tm *tm;
	struct tm gmt_tm;
	gint gmt_off;
	gchar sign;

	g_assert(size > 0);
	tm = gmtime(&date);
	gmt_tm = *tm;					/* struct copy */
	tm = localtime(&date);

	/*
	 * We used to do:
	 *
	 *    strftime(buf, len, "%a, %d %b %Y %H:%M:%S %z", tm);
	 *
	 * but doing both:
	 *
	 *    putenv("LC_TIME=C");
	 *    setlocale(LC_TIME, "C");
	 *
	 * did not seem to force that routine to emit English.  Let's do it
	 * ourselves.
	 *
	 * We also used to reply on strftime()'s "%z" to compute the GMT offset,
	 * but this is GNU-specific.
	 */

	gmt_off = tm_diff(tm, &gmt_tm) / 60;	/* in minutes */

	if (gmt_off < 0) {
		sign = '-';
		gmt_off = -gmt_off;
	} else
		sign = '+';

	return gm_snprintf(buf, size, "%s, %02d %s %04d %02d:%02d:%02d %c%04d",
		days[tm->tm_wday], tm->tm_mday, months[tm->tm_mon], tm->tm_year + 1900,
		tm->tm_hour, tm->tm_min, tm->tm_sec,
		sign, gmt_off / 60 * 100 + gmt_off % 60);
}

/**
 * Convert time to RFC-822 style date.
 *
 * @return pointer to static data.
 */
const gchar *
timestamp_rfc822_to_string(time_t date)
{
	static gchar buf[80];

	timestamp_rfc822_to_string_buf(date, buf, sizeof buf);
	return buf;
}

/**
 * Same as date_to_rfc822_gchar(), to be able to use the two in the same
 * printf() line.
 */
const gchar *
timestamp_rfc822_to_string2(time_t date)
{
	static gchar buf[80];

	timestamp_rfc822_to_string_buf(date, buf, sizeof buf);
	return buf;
}

/**
 * Convert time to RFC-1123 style date, into supplied string buffer.
 *
 * @param date The timestamp.
 * @param buf The destination buffer to hold the resulting string. Must be
 *            greater than zero.
 * @param size The size of of "buf".
 * @return The length of the created string.
 */
static size_t 
timestamp_rfc1123_to_string_buf(time_t date, gchar *buf, size_t size)
{
	const struct tm *tm;

	g_assert(size > 0);
	tm = gmtime(&date);
	return gm_snprintf(buf, size, "%s, %02d %s %04d %02d:%02d:%02d GMT",
		days[tm->tm_wday], tm->tm_mday, months[tm->tm_mon], tm->tm_year + 1900,
		tm->tm_hour, tm->tm_min, tm->tm_sec);
}

/**
 * Convert time to RFC-1123 style date.
 *
 * @returns pointer to static data.
 */
const gchar *
timestamp_rfc1123_to_string(time_t date)
{
	static gchar buf[80];

	timestamp_rfc1123_to_string_buf(date, buf, sizeof buf);
	return buf;
}

/**
 * @returns the closest power of two greater or equal to `n'.
 * next_pow2(0) and next_pow2(0x8.......) return 0.
 */
guint32
next_pow2(guint32 n)
{
	n--;

	n |= n >> 16;
	n |= n >> 8;
	n |= n >> 4;
	n |= n >> 2;
	n |= n >> 1;

	return n + 1;
}

/**
 * Determine the highest bit set in `n', -1 if value was 0.
 */
gint
highest_bit_set(guint32 n)
{
	gint h = 0;
	guint32 r = n;

	if (r == 0)
		return -1;

	while (r >>= 1)			/* Will find largest bit set */
		h++;

	return h;
}

/**
 * Enforce range boundaries on a given floating point
 * number.
 *
 * @param val The value to force within the range.
 * @param min The minimum value which val can be.
 * @param max The maximum value with val can be.
 *
 * @return The new value of val which will be between
 *         min and max.
 */
gfloat
force_range(gfloat val, gfloat min, gfloat max)
{
	g_assert(min <= max);

	return
		val < min ? min :
		val > max ? max :
		val;
}

#ifdef HAS_ARC4RANDOM
/**
 * @return random value between 0 and (2**32)-1. All 32 bit are random.
 */
guint32
random_u32(void)
{
	return arc4random();
}
#else	/* !HAS_ARC4RANDOM */
/* rotates a 32-bit value by 16 bit */
static inline guint32
uint32_rot16(guint32 value)
{
	return (value << 16) | (value >> 16);
}

/**
 * @return random value between 0 and (2**32)-1. All 32 bit are random.
 */
guint32
random_u32(void)
{
	/*
	 * random() returns only values between 0 and (2**31)-1, so the
	 * MSB is always zero. Therefore mix two random values to get
	 * full 32 random bits.
	 */
	return uint32_rot16(random()) ^ random();
}
#endif	/* HAS_ARC4RANDOM */

/**
 * @return random value between (0..max).
 */
guint32
random_value(guint32 max)
{
	return (guint32) ((max + 1.0) * random_u32() / ((guint32) -1 + 1.0));
}

/**
 * Fills buffer 'dst' with 'size' bytes of random data.
 */
void
random_bytes(void *dst, size_t size)
{
	char *p = dst;

	while (size > 4) {
		const guint32 value = random_u32();
		memcpy(p, &value, 4);
		p += 4;
		size -= 4;
	}
	if (size > 0) {
		const guint32 value = random_u32();
		memcpy(p, &value, size);
	}
}

static void
sha1_feed_ulong(SHA1Context *ctx, gulong value)
{
	SHA1Input(ctx, &value, sizeof value);
}

static void
sha1_feed_double(SHA1Context *ctx, gdouble value)
{
	SHA1Input(ctx, &value, sizeof value);
}

static void
sha1_feed_pointer(SHA1Context *ctx, gconstpointer p)
{
	SHA1Input(ctx, &p, sizeof p);
}

static void
sha1_feed_string(SHA1Context *ctx, const gchar *s)
{
	if (s) {
		SHA1Input(ctx, s, strlen(s));
	}
}

/**
 * Initialize random number generator.
 */
void
random_init(void)
{
	struct stat buf;
	FILE *f = NULL;
	SHA1Context ctx;
	tm_t start, end;
	guint32 seed;
	struct sha1 digest;
	gboolean is_pipe = TRUE;

	/*
	 * Get random entropy from the system.
	 */

	tm_now_exact(&start);

	SHA1Reset(&ctx);
	SHA1Input(&ctx, &start, sizeof start);

	/*
	 * If we have a /dev/urandom character device, use it.
	 * Otherwise, launch ps and grab its output.
	 */

	if (-1 != stat("/dev/urandom", &buf) && S_ISCHR(buf.st_mode)) {
		f = fopen("/dev/urandom", "r");
		is_pipe = FALSE;
		SHA1Input(&ctx, &buf, sizeof buf);
	} else if (-1 != access("/bin/ps", X_OK)) {
		f = popen("/bin/ps -ef", "r");
	} else if (-1 != access("/usr/bin/ps", X_OK)) {
		f = popen("/usr/bin/ps -ef", "r");
	} else if (-1 != access("/usr/ucb/ps", X_OK)) {
		f = popen("/usr/ucb/ps aux", "r");
	}

	if (f == NULL)
		g_warning("was unable to %s on your system",
			is_pipe ? "find the ps command" : "open /dev/urandom");
	else {
		/*
		 * Compute the SHA1 of the output (either ps or /dev/urandom).
		 */

		SHA1Input(&ctx, f, sizeof *f);		/* Initial state */

		for (;;) {
			guint8 data[1024];
			gint r;
			gint len = is_pipe ? sizeof(data) : 128;

			r = fread(data, 1, len, f);
			SHA1Input(&ctx, f, sizeof *f);	/* Changes as we read */
			if (r)
				SHA1Input(&ctx, data, r);
			if (r < len || !is_pipe)		/* Read once from /dev/urandom */
				break;
		}

		if (is_pipe)
			pclose(f);
		else
			fclose(f);
	}

	/* Add some host/user dependent noise */
	sha1_feed_ulong(&ctx, getuid());
	sha1_feed_ulong(&ctx, getgid());
	sha1_feed_ulong(&ctx, getpid());
	sha1_feed_ulong(&ctx, getppid());
	sha1_feed_ulong(&ctx, compat_max_fd());

	sha1_feed_string(&ctx, __DATE__);
	sha1_feed_string(&ctx, __TIME__);
	sha1_feed_string(&ctx, "$Id$");

#if GLIB_CHECK_VERSION(2,6,0)
	/*
	 * These functions cannot be used with an unpatched GLib 1.2 on some
	 * systems as they trigger a bug in GLib causing a crash.  On Darwin
	 * there's still a problem before GLib 2.6 due to a bug in Darwin though.
	 */
	sha1_feed_string(&ctx, g_get_user_name());
	sha1_feed_string(&ctx, g_get_real_name());
#endif	/* GLib >= 2.0 */

	sha1_feed_string(&ctx, eval_subst("~"));
	if (-1 != stat(eval_subst("~"), &buf)) {
		SHA1Input(&ctx, &buf, sizeof buf);
	}
	if (-1 != stat(".", &buf)) {
		SHA1Input(&ctx, &buf, sizeof buf);
	}
	if (-1 != stat("..", &buf)) {
		SHA1Input(&ctx, &buf, sizeof buf);
	}
	if (-1 != stat("/", &buf)) {
		SHA1Input(&ctx, &buf, sizeof buf);
	}
	if (-1 != fstat(STDIN_FILENO, &buf)) {
		SHA1Input(&ctx, &buf, sizeof buf);
	}
	if (-1 != fstat(STDOUT_FILENO, &buf)) {
		SHA1Input(&ctx, &buf, sizeof buf);
	}

	sha1_feed_double(&ctx, fs_free_space_pct(eval_subst("~")));
	sha1_feed_double(&ctx, fs_free_space_pct("/"));

#ifdef HAS_UNAME
	{
		struct utsname un;
		
		if (-1 != uname(&un)) {
			SHA1Input(&ctx, &un, sizeof un);
		}
	}
#endif	/* HAS_UNAME */
	
	sha1_feed_pointer(&ctx, &ctx);
	sha1_feed_pointer(&ctx, &random_init);
	sha1_feed_pointer(&ctx, sbrk(0));

	{
		extern char **environ;
		size_t i;

		for (i = 0; NULL != environ[i]; i++) {
			sha1_feed_string(&ctx, environ[i]);
		}
	}

	sha1_feed_string(&ctx, ttyname(STDIN_FILENO));

#if defined(HAS_GETRUSAGE)
	{
		struct rusage usage;

		if (-1 != getrusage(RUSAGE_SELF, &usage)) {
			SHA1Input(&ctx, &usage, sizeof usage);
		}
	}
#endif	/* HAS_GETRUSAGE */

	/*
	 * Add timing entropy.
	 */

	{
		gdouble u, s;
		tm_t before, after, elapsed;
		gdouble starget;

		sha1_feed_double(&ctx, tm_cputime(&u, &s));
		sha1_feed_double(&ctx, u);
		sha1_feed_double(&ctx, s);

		tm_now_exact(&before);
#ifdef HAS_USLEEP
		usleep(250 * 1000);		/* 250 ms */
		starget = 0.25;
#else
		sleep(1);
		starget = 1.0;
#endif
		tm_now_exact(&after);
		tm_elapsed(&elapsed, &after, &before);
		starget -= tm2f(&elapsed);
		sha1_feed_double(&ctx, starget);
	}

	tm_now_exact(&end);
	SHA1Input(&ctx, &end, sizeof end);

	/*
	 * Reduce SHA1 to a single guint32.
	 */

	SHA1Result(&ctx, &digest);
	seed = sha1_hash(&digest);

	/*
	 * Finally, can initialize the random number generator.
	 */

	srandom(seed);	/* Just in case initstate() enables the alarm device */

#if defined(HAS_INITSTATE)
	{
		static gulong state[256 / sizeof(gulong)];
		
		initstate(seed, cast_to_gchar_ptr(state), sizeof state);
	}
#endif /* HAS_INITSTATE */

	/*
	 * Randomly ask for a few random bytes so that even if the same seed
	 * is selected by two peers, the first random values they generate
	 * will differ.  This matters when the first thing they will do is
	 * generate a GUID or a KUID...
	 *
	 * This adds roughly 8 bits of additional salt to the 32-bit seed since
	 * it can compute at most 22*20 = 440 random numbers, that amount being
	 * random (based on the SHA1 noise we have already computed).
	 */

	{
		int i;
		guint32 count = 0;

		for (i = 0; i < SHA1_RAW_SIZE; i++) {
			int j = (guchar) digest.data[i] % 23;

			while (j-- > 0)
				count += random_u32();		/* Avoid compiler warnings */
		}
	}
}

/**
 * Check whether buffer contains printable data, suitable for "%s" printing.
 * If not, consider dump_hex().
 */
gboolean
is_printable(const gchar *buf, gint len)
{
	const gchar *p = buf;
	gint l = len;

	while (l--) {
		gchar c = *p++;
		if (!is_ascii_print(c))
			return FALSE;
	}

	return TRUE;
}

/**
 * Prints a single "dump hex" line which consists of 16 byte from data.
 *
 * @param out The stream to print the string at.
 * @param data A pointer to the first byte of the data to dump.
 * @param length The length of data in bytes.
 * @param offset The offset in data to start dumping at.
 */
static void
dump_hex_line(FILE *out, const gchar *data, size_t length, size_t offset)
{
	gchar char_buf[32], hex_buf[64];
	gchar *p = hex_buf, *q = char_buf;
	size_t j, i = offset;

	for (j = 0; j < 16; j++) {
		*p++ = ' ';
		if (8 == j) {
			*p++ = ' ';
		}
		if (i < length) {	
			guchar c;

			c = data[i];
			i++;

			*p++ = hex_digit((c >> 4) & 0xf);
			*p++ = hex_digit(c & 0x0f);

			if (is_ascii_alnum(c) || is_ascii_punct(c)) {
				*q++ = c;
			} else {
				*q++ = '.';		/* no non-printables */
			}
		} else {
			*p++ = ' ';
			*p++ = ' ';

			*q++ = ' ';
		}
	}
	*p = '\0';
	*q = '\0';

	fprintf(out, "%5u %s  %s\n", (guint) (offset & 0xffff), hex_buf, char_buf);
}

/**
 * Displays hex & ascii lines to the terminal (for debug)
 * Displays the "title" then the characters in "s", # of bytes to print in "b"
 */
void
dump_hex(FILE *out, const gchar *title, gconstpointer data, gint length)
{
	gint i;

	if (length < 0 || data == NULL) {
		g_warning("dump_hex: value out of range [data=0x%lx, length=%d] for %s",
			(gulong) data, length, title);
		fflush(out);
		return;
	}

	fprintf(out, "----------------- %s:\n", title);

	for (i = 0; i < length; i += MIN(length - i, 16)) {
		if (i % 256 == 0) {
			if (i > 0) {
				fputc('\n', out);	/* break after 256 byte chunk */
			}
			fputs("Offset  0  1  2  3  4  5  6  7   8  9  a  b  c  d  e  f  "
				"0123456789abcdef\n", out);
		}
		dump_hex_line(out, data, length, i);
	}

	fprintf(out, "----------------- (%d bytes).\n", length);
	fflush(out);
}

/**
 * Copies ``src'' to ``dst'', converting all upper-case characters to
 * lower-case. ``dst'' and ``src'' may point to the same object. The
 * conversion depends on the current locale.
 */
void
locale_strlower(gchar *dst, const gchar *src)
{
	do {
		*dst++ = tolower((guchar) *src);
	} while (*src++);
}

/**
 * Copies ``src'' to ``dst'', converting all ASCII upper-case characters to
 * ASCII lower-case. ``dst'' and ``src'' may be identical but must not
 * overlap otherwise.
 */
void
ascii_strlower(gchar *dst, const gchar *src)
{
	gint c;

	if (dst != src)
		do {
			c = (guchar) *src++;
			*dst++ = ascii_tolower(c);
		} while (c != '\0');
	else
		do {
			c = (guchar) *src++;
			if (is_ascii_upper(c))
				*dst = ascii_tolower(c);
			dst++;
		} while (c != '\0');
}

/**
 * Same as strcasecmp() but only case-insensitive for ASCII characters.
 */
gint
ascii_strcasecmp(const gchar *s1, const gchar *s2)
{
	gint a, b;

	g_assert(s1 != NULL);
	g_assert(s2 != NULL);

	do {
		a = (guchar) *s1++;
		b = (guchar) *s2++;
		if (a != b) {
			a = ascii_tolower(a);
			b = ascii_tolower(b);
		}
	} while (a != '\0' && a == b);

	return a - b;
}

/**
 * Same as strncasecmp() but only case-insensitive for ASCII characters.
 */
gint
ascii_strncasecmp(const gchar *s1, const gchar *s2, size_t len)
{
	gint a, b;

	g_assert(s1 != NULL);
	g_assert(s2 != NULL);
	g_assert(len <= INT_MAX);

	if (len <= 0)
		return 0;

	do {
		a = (guchar) *s1++;
		b = (guchar) *s2++;
		if (a != b) {
			a = ascii_tolower(a);
			b = ascii_tolower(b);
		}
	} while (a != '\0' && a == b && --len > 0);

	return a - b;
}


/**
 * Same as strstr() but case-insensitive with respect to ASCII characters.
 */
gchar *
ascii_strcasestr(const gchar *haystack, const gchar *needle)
{
	guint32 delta[256];
	size_t nlen = strlen(needle);
	guint32 *pd = delta;
	size_t i;
	const gchar *n;
	guint32 haylen = strlen(haystack);
	const gchar *end = haystack + haylen;
	gchar *tp;

	/*
	 * Initialize Sunday's algorithm, lower-casing the needle.
	 */

	nlen++;		/* Avoid increasing within the loop */

	for (i = 0; i < 256; i++)
		*pd++ = nlen;

	nlen--;		/* Restore original pattern length */

	for (n = needle, i = 0; i < nlen; i++) {
		guchar c = *n++;
		delta[ascii_tolower(c)] = nlen - i;
	}

	/*
	 * Now run Sunday's algorithm.
	 */

	for (tp = *(gchar **) &haystack; tp + nlen <= end; /* empty */) {
		const gchar *t;
		guchar c;

		for (n = needle, t = tp, i = 0; i < nlen; n++, t++, i++)
			if (ascii_tolower((guchar) *n) != ascii_tolower((guchar) *t))
				break;

		if (i == nlen)						/* Got a match! */
			return tp;

		c = *(tp + nlen);
		tp += delta[ascii_tolower(c)];	/* Continue search there */
	}

	return NULL;		/* Not found */
}

/**
 * Compare two strings up to the specified delimiters.
 */
static gint
strcmp_delimit_full(const gchar *a, const gchar *b,
	const gchar *delimitors, gboolean case_sensitive)
{
	guchar is_delimit[(guchar)-1];

	/*
	 * Initialize delimitors.
	 */

	{
		size_t i;

		is_delimit[0] = TRUE;
		for (i = 1; i < G_N_ELEMENTS(is_delimit); i++) {
			is_delimit[i] = FALSE;
		}
	}

	while (*delimitors) {
		guchar c = *delimitors++;
		is_delimit[case_sensitive ? c : ascii_tolower(c)] = TRUE;
	}

	/*
	 * Compare strings up to the specified delimitors.
	 */

	for (;;) {
		guchar c, d;

		c = *a++;
		d = *b++;
		if (case_sensitive) {
			c = ascii_tolower(c);
			d = ascii_tolower(d);
		}
		if (is_delimit[c])
			return is_delimit[d] ? 0 : -1;
		if (is_delimit[d])
			return +1;
		if (c != d)
			return c < d ? -1 : +1;
	}
}

/**
 * Compare two strings case-senstive up to the specified delimiters.
 */
gint
strcmp_delimit(const gchar *a, const gchar *b, const gchar *delimit)
{
	return strcmp_delimit_full(a, b, delimit, TRUE);
}

/**
 * Compare two strings case-insensitive up to the specified delimiters.
 */
gint
ascii_strcasecmp_delimit(const gchar *a, const gchar *b, const gchar *delimit)
{
	return strcmp_delimit_full(a, b, delimit, FALSE);
}

/**
 * Generate a new random GUID within given `xuid'.
 */
void
guid_random_fill(gchar *xuid)
{
	random_bytes(xuid, GUID_RAW_SIZE);
}

/**
 * Shrinks a filename so that it fits into the given buffer. The function
 * tries to preserve the filename extension if there is any. The UTF-8
 * encoding is also preserved.
 *
 * @return The length of the resulting filename.
 */
size_t
filename_shrink(const gchar *filename, gchar *buf, size_t size)
{
	const gchar *ext;
	size_t ext_size = 0, ret;

	g_assert(filename);
	g_assert(buf);
	
	/* Try to preserve the filename extension */
	ext = strrchr(filename, '.');
	if (ext) {
		ext_size = strlen(ext) + 1;	/* Include NUL */
		if (ext_size >= size) {
			/*
			 * If it's too long, assume it's not extension at all.
			 * We must truncate the "extension" anyway and also
			 * preserve the UTF-8 encoding by all means.
			 */
			ext_size = 0;
			ext = NULL;
		}
	}

	g_assert(ext_size < size);
	utf8_strlcpy(buf, filename, size - ext_size);

	/* Append the filename extension */
	if (ext) {
		g_strlcat(buf, ext, size);
	}

	ret = strlen(buf);
	g_assert(ret < size);
	return ret;
}

static gchar *
unique_pathname(const gchar *path, const gchar *filename,
		gboolean (*name_is_uniq)(const gchar *pathname))
{
	gchar *pathname;
	
	if (!name_is_uniq) {
		name_is_uniq = file_does_not_exist;
	}
	pathname = make_pathname(path, filename);
	if (!(*name_is_uniq)(pathname)) {
		G_FREE_NULL(pathname);
	}
	return pathname;
}

/**
 * Copies a string into a buffer whereas the string is potentially
 * truncated but the UTF-8 encoding is preserved.
 *
 * @param src The string to copy.
 * @param dst The destination buffer.
 * @param size The size of "dst" in bytes.
 * @return The length of the truncated string in bytes.
 */
static size_t
utf8_truncate(const gchar *src, gchar *dst, size_t size)
{
	g_assert(src);
	g_assert(0 == size || NULL != dst);

	if (size > 0) {
		utf8_strlcpy(dst, src, size);
		return strlen(dst);
	} else {
		return 0;
	}
}

/**
 * Determine unique filename for `file' in `path', with optional trailing
 * extension `ext'.  If no `ext' is wanted, one must supply an empty string.
 *
 * @param path A directory path.
 * @param file The basename for the resulting pathname.
 * @param ext An optional filename extension to be appended to the basename.
 * @param name_is_uniq An optional callback to decide whether a created
 *        pathname is uniq. If omitted, the default is file_does_not_exist().
 *
 * @returns the chosen unique complete filename as a pointer which must be
 * freed.
 */
gchar *
unique_filename(const gchar *path, const gchar *name, const gchar *ext,
		gboolean (*name_is_uniq)(const gchar *pathname))
{
	gchar filename_buf[FILENAME_MAXBYTES];
	gchar name_buf[FILENAME_MAXBYTES];
	gchar mid_buf[32];
	gchar ext_buf[32];
	const gchar *mid;
	gchar *pathname;
	size_t name_len, mid_len, ext_len;
	gint i;

	g_assert(path);
	g_assert(name);
	g_assert(ext);
	g_assert(is_absolute_path(path));

	STATIC_ASSERT(sizeof filename_buf >
		sizeof mid_buf + sizeof ext_buf + GUID_HEX_SIZE);

	/**
	 * NOTE: The generated filename must not exceed FILENAME_MAXBYTES
	 *		 because such a file cannot be created. In reality, it depends
	 *		 on the filesystem as well and the limit might be even smaller.
	 *		 In any case, we don't want to cut-off arbitrary bytes but
	 *		 at least preserve the filename extension and the (potential)
	 *		 UTF-8 encoding.
	 */

	/* Because "ext" can be an additional extension like .BAD rather than
	 * one that indicates the filetype, try to preserve the next "extension"
	 * as well, if there's any. */
	mid = strrchr(name, '.');
	if (NULL == mid || mid == name || strlen(mid) >= sizeof mid_buf) {
		mid = strchr(name, '\0');
	}

	ext_len = strlen(ext);
	mid_len = strlen(mid);
	name_len = strlen(name) - mid_len;

	ext_len = MIN(ext_len, sizeof ext_buf - 1);
	mid_len = MIN(mid_len, sizeof mid_buf - 1);
	name_len = MIN(name_len, sizeof name_buf - 1);

	if (name_len + mid_len + ext_len >= sizeof filename_buf) {
		g_assert(name_len >= ext_len);
		name_len -= ext_len;
	}

	/* Truncate strings so that an UTF-8 encoding is preserved */
	ext_len = utf8_truncate(ext, ext_buf, ext_len + 1);
	mid_len = utf8_truncate(mid, mid_buf, mid_len + 1);
	name_len = utf8_truncate(name, name_buf, name_len + 1);

	gm_snprintf(filename_buf, sizeof filename_buf, "%s%s%s",
		name_buf, mid_buf, ext_buf);

	pathname = unique_pathname(path, filename_buf, name_is_uniq);
	if (pathname)
		goto finish;

	if (!is_directory(path))
		return NULL;

	/*
	 * Looks like we need to make the filename more unique.  Append .00, then
	 * .01, etc... until .99.
	 */

	while (name_len + mid_len + ext_len + 3 >= sizeof filename_buf) {
		g_assert(name_len > 0);
		name_len--;
	}
	name_len = utf8_truncate(name, name_buf, name_len + 1);

	for (i = 0; i < 100; i++) {
		gm_snprintf(filename_buf, sizeof filename_buf, "%s.%02u%s%s",
			name_buf, i, mid_buf, ext_buf);

		pathname = unique_pathname(path, filename_buf, name_is_uniq);
		if (pathname)
			goto finish;
	}

	/*
	 * OK, no luck.  Try with a few random numbers then.
	 */

	while (name_len + mid_len + ext_len + 9 >= sizeof filename_buf) {
		g_assert(name_len > 0);
		name_len--;
	}
	name_len = utf8_truncate(name, name_buf, name_len + 1);

	for (i = 0; i < 100; i++) {
		gm_snprintf(filename_buf, sizeof filename_buf, "%s.%x%s%s",
			name_buf, (unsigned) random_u32(), mid_buf, ext_buf);

		pathname = unique_pathname(path, filename_buf, name_is_uniq);
		if (pathname)
			goto finish;
	}

	/*
	 * Bad luck.  Allocate a random GUID then.
	 */

	while (
		name_len + mid_len + ext_len + GUID_HEX_SIZE + 1 >= sizeof filename_buf
	) {
		g_assert(name_len > 0);
		name_len--;
	}
	name_len = utf8_truncate(name, name_buf, name_len + 1);

	{
		gchar xuid[GUID_RAW_SIZE];

		guid_random_fill(xuid);
		gm_snprintf(filename_buf, sizeof filename_buf, "%s.%s%s%s",
			name_buf, guid_hex_str(xuid), mid_buf, ext_buf);
	}

	pathname = unique_pathname(path, filename_buf, name_is_uniq);
	if (pathname)
		goto finish;

	/*
	 * This may also be the result of permission problems or inode
	 * exhaustion.
	 */
	g_warning("no luck with random number generator");

finish:
	return pathname;
}

static const gchar escape_char = '\\';

/**
 * Allow spaces, tabs or new-lines as "spacing" chars.
 */
static inline gboolean
char_is_space(guchar c)
{
	return c == ' ' || c == '\t' || c == '\n';
}

/**
 * Nearly the same as isprint() but allows additional safe chars if !strict.
 */
static inline gboolean
char_is_safe(guchar c, gboolean strict)
{
	return isprint(c) || (!strict && char_is_space(c));
}

/**
 * Escape all non-printable chars into the hexadecimal "\xhh" form.
 *
 * @returns new escaped string, or the original string if no escaping occurred.
 */
gchar *
hex_escape(const gchar *name, gboolean strict)
{
	const gchar *p;
	gchar *q;
	guchar c;
	gint need_escape = 0;
	gchar *new;

	for (p = name, c = *p++; c; c = *p++)
		if (!char_is_safe(c, strict))
			need_escape++;

	if (need_escape == 0)
		return deconstify_gchar(name);

	new = g_malloc(p - name + 3 * need_escape);

	for (p = name, q = new, c = *p++; c; c = *p++) {
		if (char_is_safe(c, strict))
			*q++ = c;
		else {
			*q++ = escape_char;
			*q++ = 'x';
			*q++ = hex_alphabet[c >> 4];
			*q++ = hex_alphabet[c & 0xf];
		}
	}
	*q = '\0';

	return new;
}

/**
 * Checks whether the given character is a control character that should
 * be escaped.
 *
 * @return TRUE if "c" should be escaped, FALSE otherwise.
 */
static inline gboolean
escape_control_char(guchar c)
{
	return is_ascii_cntrl(c) && !char_is_space(c);
}

/**
 * Escape all ASCII control chars except LF into the hexadecimal "\xhh" form.
 * When a CR LF sequence is seen, the CR character is dropped.
 *
 * @returns new escaped string, or the original string if no escaping occurred.
 */
gchar *
control_escape(const gchar *s)
{
	size_t need_escape = 0;
	const gchar *p;
	guchar c;

	for (p = s; '\0' != (c = *p); p++)
		if (escape_control_char(c))
			need_escape++;

	if (need_escape > 0) {
		gchar *q, *escaped;

		q = escaped = g_malloc(p - s + 1 + 3 * need_escape);

		for (p = s; '\0' != (c = *p); p++) {
			if (escape_control_char(c)) {
				if ('\r' == c && '\n' == p[1]) {
					/* Skip CR in CR LF sequences */
				} else {
					*q++ = escape_char;
					*q++ = 'x';
					*q++ = hex_alphabet[c >> 4];
					*q++ = hex_alphabet[c & 0xf];
				}
			} else {
				*q++ = c;
			}
		}
		*q = '\0';

		return escaped;
	}
	
	return deconstify_gchar(s);
}

static guint
char_to_printf_escape(guchar c, gchar *esc, const char *safe_chars)
{
	if (!safe_chars) {
		safe_chars = "";
	}
	if (is_ascii_alnum(c) || (c < 0x80 && strchr(safe_chars, c))) {
		if (esc)
			*esc = c;
		
		return 1;
	} else {
		if (esc) {
			esc[0] = '\\';
			esc[1] = 'x';
			esc[2] = hex_digit((c >> 4) & 0xf);
			esc[3] = hex_digit(c & 0x0f);
		}
		return 4;
	}
}

/**
 * Escapes a string so that it can be used careless with the POSIX printf tool.
 * Therefore it's absolutely paranoid and escapes everything but ASCII
 * alphanumerics, dots, hyphen and underscores.
 *
 * @note Hex sequences are always two digits long, so "\xAAA" is the same as
 * "\xAA" "A". In C this not necessarily true and could be understood as a
 * wide-char sequence.
 *
 * @param src The string to escape.
 * @return The escaped string. MUST NOT be freed.
 */ 
const gchar *
lazy_string_to_printf_escape(const gchar *src)
{
	static const gchar safe_chars[] = ".-_";
	static gchar *prev;
	const gchar *s;
	gchar *p;
	guchar c;
	size_t n;

	g_assert(src);
	g_assert(src != prev);

	G_FREE_NULL(prev);
	
	for (s = src, n = 0; '\0' != (c = *s); s++)
		n += char_to_printf_escape(c, NULL, safe_chars);

	if (n == (size_t) (s - src))
		return src;
	
	prev = g_malloc(n + 1);
	for (s = src, p = prev; '\0' != (c = *s); s++) {
		guint len = char_to_printf_escape(c, p, safe_chars);
		p += len;
	}
	*p = '\0';
	
	return prev;	
}

/**
 * Extracts the IP address into `ip' and the netmask into `netmask'.
 *
 * @returns whether the supplied string represents a valid ip/mask combination.
 *
 * Accepted forms:
 * "a.b.c.d"			implies /32
 * "a.b.c.d/e"			whereas e [1..32]
 * "a.b.c.d/w.x.y.z"
 *
 * If the IP address or the netmask is zero, the function will return FALSE.
 */
gboolean
string_to_ip_and_mask(const gchar *str, guint32 *ip, guint32 *netmask)
{
	const gchar *ep, *s = str;

	if (!string_to_ip_strict(s, ip, &ep))
		return FALSE;

	s = ep;

	if (*s == '\0') {
		*netmask = ~0;
		return TRUE;
	}

	if (*s++ != '/')
		return FALSE;

	if (!is_ascii_digit(*s))
		return FALSE;

	if (string_to_ip_strict(s, netmask, &ep)) {
		return 0 != *netmask;
	} else {
		guint32 u;
		gint error;
		
		u = parse_uint32(s, &ep, 10, &error);
		if (error || u < 1 || u > 32 || *ep != '\0')
			return FALSE;

		*netmask = ~0U << (32 - u);
	}
	return TRUE;
}

/**
 * Create new pathname from the concatenation of the dirname and the basename
 * of the file. A directory separator is insert, unless "dir" already ends
 * with one or "filename" starts with one.
 *
 * @param dir The directory path.
 * @param file The filename.
 *
 * @return A newly allocated string.
 */
gchar *
make_pathname(const gchar *dir, const gchar *file)
{
	const gchar *sep;
	size_t n;

	g_assert(dir);
	g_assert(file);

	n = strlen(dir);
	if ((n > 0 && dir[n - 1] == G_DIR_SEPARATOR) || file[0] == G_DIR_SEPARATOR)
		 sep = "";
	else
		 sep = G_DIR_SEPARATOR_S;

	return g_strconcat(dir, sep, file, (void *) 0);
}

/**
 * Determine stripped down path, removing SRC_PREFIX if present.
 *
 * @returns pointer within supplied string.
 */
gchar *
short_filename(gchar *fullname)
{
	gchar *s;

	s = is_strprefix(fullname, SRC_PREFIX);
	return s ? s : fullname;
}

/**
 * Creates the given directory including sub-directories if necessary. The
 * path must be absolute.
 *
 * @param dir the pathname of the directory to create.
 *
 * @return On success, zero is returned. On failure, -1 is returned and
 *         errno indicates the reason.
 */
gint
create_directory(const gchar *dir, mode_t mode)
{
	gint error = 0;

	if (NULL == dir) {
		error = EINVAL;
		goto failure;
	}
	if (!is_absolute_path(dir)) {
		error = EPERM;
		goto failure;
	}

	if (compat_mkdir(dir, mode)) {
		error = errno;
		if (EEXIST == error) {
			goto finish;
		} else if (ENOENT == error) {
			gchar *upper = filepath_directory(dir);

			if (create_directory(upper, mode)) {
				error = errno;
		 	} else {
				if (compat_mkdir(dir, mode)) {
					error = errno;
				} else {
					error = 0;
				}
			}
			G_FREE_NULL(upper);
		} else {
			goto failure;
		}
	}
	if (error && EEXIST != error)
		goto failure;

finish:
	return is_directory(dir) ? 0 : -1;

failure:
	g_warning("mkdir(\"%s\") failed: %s", dir, g_strerror(error));
	errno = error;
	return -1;
}

/**
 * Returns a pointer to the basename of the given pathname. A slash is
 * always considered a  separator but G_DIR_SEPARATOR is considered as
 * well. Thus "/whatever/blah\\yadda" returns a pointer to yadda iff
 * G_DIR_SEPARATOR is a backslash and otherwise points to "blah[...]".
 *
 * @param pathname A pathname to extract basename from. This may be a relative
 *			path or just a basename.
 * @return	A pointer to the basename of "pathname". The pointer points into
 *			the buffer holding pathname.
 */
const gchar *
filepath_basename(const gchar *pathname)
{
	const gchar *p, *q;
	
	g_assert(pathname);
	
	p = strrchr(pathname, '/');
	if (p) {
		p++;
	} else {
		p = pathname;
	}
	q = strrchr(p, G_DIR_SEPARATOR);
	if (q) {
		p = &q[1];
	}
	return p;
}

static const gchar *
filepath_directory_end(const gchar *pathname, gchar separator)
{
	const gchar *p;
	
	p = strrchr(pathname, separator);
	if (p) {
		while (p != pathname && ('/' == p[-1] || G_DIR_SEPARATOR == p[-1])) {
			p--;
		}
	}
	return p;
}

/**
 * Creates a copy with the given pathname with the basename cut off. A slash
 * is always considered a separator but G_DIR_SEPARATOR is considered as
 * well. Thus "/whatever/blah\\yadda" returns "/whatever/blah" if G_DIR_SEPARATOR
 * is a backslash, otherwise "/whatever" is returned.
 *
 * @return	A newly allocated string holding the given pathname with the
 *			basename cut off. If the string contained no directory separator,
 *			NULL is returned.
 */
gchar *
filepath_directory(const gchar *pathname)
{
	const gchar *sep;
	gchar *dir;

	sep = filepath_directory_end(pathname, '/');
	if (G_DIR_SEPARATOR != '/') {
		const gchar *alt;

		alt = filepath_directory_end(pathname, G_DIR_SEPARATOR);
		if (sep && alt) {
			sep = (sep - pathname > alt - pathname) ? sep : alt;
		} else if (alt) {
			sep = alt;
		}
	}
	if (sep == pathname) {
		dir = g_strdup(G_DIR_SEPARATOR_S);
	} else if (sep) {
		dir = g_strndup(pathname, sep - pathname);
	} else {
		dir = NULL;
	}
	return dir;
}

/**
 * Check whether file given by its dirname and its basename exists.
 */
gboolean
filepath_exists(const gchar *dir, const gchar *file)
{
	struct stat buf;
	gboolean exists;
	gchar *path;

	path = make_pathname(dir, file);
	exists = 0 == stat(path, &buf);
	G_FREE_NULL(path);

	return exists;
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
reverse_strlcpy(gchar * const dst, size_t size,
	const gchar *src, size_t src_len)
{
	gchar *p = dst;
	
	if (size-- > 0) {
		const gchar *q = &src[src_len], *end = &dst[MIN(src_len, size)];

		while (p != end) {
			*p++ = *--q;
		}
		*p = '\0';
	}

	return p - dst;
}

size_t
int32_to_string_buf(gint32 v, char *dst, size_t size)
{
	char buf[UINT32_DEC_BUFLEN + 1];
	char *p;
	gboolean neg;

	g_assert(0 == size || NULL != dst);
	g_assert(size <= INT_MAX);

	p = buf;
	neg = v < 0;

	do {
		int d = v % 10;

		v /= 10;
		*p++ = dec_digit(neg ? -d : d);
	} while (0 != v);

	if (neg) {
		*p++ = '-';
	}
	return reverse_strlcpy(dst, size, buf, p - buf);
}

size_t
uint32_to_string_buf(guint32 v, gchar *dst, size_t size)
{
	gchar buf[UINT32_DEC_BUFLEN];
	gchar *p;

	g_assert(0 == size || NULL != dst);
	g_assert(size <= INT_MAX);

	for (p = buf; /* NOTHING */; v /= 10) {
		*p++ = dec_digit(v % 10);
		if (v < 10)
			break;
	}

	return reverse_strlcpy(dst, size, buf, p - buf);
}

size_t
uint64_to_string_buf(guint64 v, gchar *dst, size_t size)
{
	gchar buf[UINT64_DEC_BUFLEN];
	gchar *p;

	if ((guint32) -1 >= v) {
		/* 32-bit arithmetic is cheaper for most machines */
		return uint32_to_string_buf(v, dst, size);
	}

	g_assert(0 == size || NULL != dst);
	g_assert(size <= INT_MAX);

	for (p = buf; /* NOTHING */; v /= 10) {
		*p++ = dec_digit(v % 10);
		if (v < 10)
			break;
	}

	return reverse_strlcpy(dst, size, buf, p - buf);
}

size_t
off_t_to_string_buf(off_t v, gchar *dst, size_t size)
{
	gchar buf[OFF_T_DEC_BUFLEN];
	gchar *p;
	gboolean neg;

	g_assert(0 == size || NULL != dst);
	g_assert(size <= INT_MAX);

	p = buf;
	neg = v < 0;
	do {
		gint d = v % 10;

		v /= 10;
		*p++ = dec_digit(neg ? -d : d);
	} while (0 != v);
	if (neg) {
		*p++ = '-';
	}

	return reverse_strlcpy(dst, size, buf, p - buf);
}

size_t
time_t_to_string_buf(time_t v, gchar *dst, size_t size)
{
	gchar buf[TIME_T_DEC_BUFLEN];
	gchar *p;
	gboolean neg;

	g_assert(0 == size || NULL != dst);
	g_assert(size <= INT_MAX);

	p = buf;
	neg = v < 0;
	do {
		gint d = v % 10;

		v /= 10;
		*p++ = dec_digit(neg ? -d : d);
	} while (0 != v);
	if (neg) {
		*p++ = '-';
	}

	return reverse_strlcpy(dst, size, buf, p - buf);
}

const gchar *
uint32_to_string(guint32 v)
{
	static gchar buf[UINT32_DEC_BUFLEN];
	size_t n;

	n = uint32_to_string_buf(v, buf, sizeof buf);
	g_assert(n > 0);
	g_assert(n < sizeof buf);
	return buf;
}

const gchar *
uint64_to_string(guint64 v)
{
	static gchar buf[UINT64_DEC_BUFLEN];
	size_t n;

	n = uint64_to_string_buf(v, buf, sizeof buf);
	g_assert(n > 0);
	g_assert(n < sizeof buf);
	return buf;
}

const gchar *
uint64_to_string2(guint64 v)
{
	static gchar buf[UINT64_DEC_BUFLEN];
	size_t n;

	n = uint64_to_string_buf(v, buf, sizeof buf);
	g_assert(n > 0);
	g_assert(n < sizeof buf);
	return buf;
}

const gchar *
filesize_to_string(filesize_t v)
{
	static gchar buf[UINT64_DEC_BUFLEN];
	size_t n;

	STATIC_ASSERT((filesize_t)-1 <= (guint64)-1);
	n = uint64_to_string_buf(v, buf, sizeof buf);
	g_assert(n > 0);
	g_assert(n < sizeof buf);
	return buf;
}

const gchar *
filesize_to_string2(filesize_t v)
{
	static gchar buf[UINT64_DEC_BUFLEN];
	size_t n;

	STATIC_ASSERT((filesize_t)-1 <= (guint64)-1);
	n = uint64_to_string_buf(v, buf, sizeof buf);
	g_assert(n > 0);
	g_assert(n < sizeof buf);
	return buf;
}

const gchar *
off_t_to_string(off_t v)
{
	static gchar buf[OFF_T_DEC_BUFLEN];
	size_t n;

	n = off_t_to_string_buf(v, buf, sizeof buf);
	g_assert(n > 0);
	g_assert(n < sizeof buf);
	return buf;
}

const gchar *
time_t_to_string(time_t v)
{
	static gchar buf[TIME_T_DEC_BUFLEN];
	size_t n;

	n = time_t_to_string_buf(v, buf, sizeof buf);
	g_assert(n > 0);
	g_assert(n < sizeof buf);
	return buf;
}

/*
 * Parses an unsigned X-bit integer from an ASCII string.
 *
 * @param src
 *    The string to parse.
 * @param endptr
 *    May be NULL. Otherwise, it will be set to address of the first invalid
 *    character.
 * @param base
 *    The base system to be assumed e.g., 10 for decimal numbers 16 for
 *    hexadecimal numbers. The value MUST be 2..36.
 * @param errorptr
 *    Indicates a parse error if not zero. EINVAL means there was no
 *    number with respect to the used base at all. ERANGE means the
 *    number would exceed (2^X)-1.
 *
 * @return
 *    The parsed value or zero in case of an error. If zero is returned
 *    error must be checked to determine whether there was an error
 *    or whether the parsed value was zero.
 */

#define GENERATE_PARSE_UNSIGNED(NAME, TYPE) 								\
TYPE 																		\
NAME(const gchar *src, gchar const **endptr, guint base, gint *errorptr) 	\
{																			\
	const gchar *p;															\
	TYPE v = 0, mm;															\
	gint error = 0;															\
	guint d;																\
																			\
	STATIC_ASSERT((TYPE) -1 > 35); /* works for unsigned integers only */	\
																			\
	g_assert(src);															\
	g_assert(errorptr);														\
	g_assert(base >= 2 && base <= 36);										\
																			\
	p = src;																\
	if (base < 2 || base > 36) {											\
		error = EINVAL;														\
		goto finish;														\
	}																		\
	mm = ((TYPE) -1) / base;	/* determine maximum multiplicand */		\
																			\
	for (/* NOTHING */; (d = alnum2int_inline(*p)) < base; ++p) {			\
		TYPE w;																\
																			\
		w = v * base;														\
		if (v > mm || ((TYPE) -1) - w < (TYPE) d) {							\
			error = ERANGE;													\
			goto finish;													\
		}																	\
		v = w + d;															\
	}																		\
																			\
	if (p == src)															\
		error = EINVAL;														\
																			\
finish:																		\
	if (endptr)																\
		*endptr = p;														\
																			\
	*errorptr = error;														\
	return error ? 0 : v;													\
}

#define GENERATE_PARSE_UINTX(bits) \
	GENERATE_PARSE_UNSIGNED(CAT2(parse_uint,bits), CAT2(guint,bits))
GENERATE_PARSE_UINTX(64)
GENERATE_PARSE_UINTX(32)
GENERATE_PARSE_UINTX(16)

gint
parse_major_minor(const gchar *src, gchar const **endptr,
	guint *major, guint *minor)
{
	const gchar *ep;
	gint error;
	guint32 maj, min;

	g_assert(src);

	maj = parse_uint32(src, &ep, 10, &error);
	if (error) {
		min = 0;	/* dumb compiler */
	} else if (*ep != '.') {
		error = EINVAL;
		min = 0;	/* dumb compiler */
	} else {
		ep++; /* Skip the '.' */
		min = parse_uint32(ep, &ep, 10, &error);
	}

	if (endptr)
		*endptr = ep;
	if (major)
		*major = error ? 0 : maj;
	if (minor)
		*minor = error ? 0 : min;

	return error;
}

/**
 * Find amount of common leading bits between two IP addresses.
 */
static guint8
find_common_leading(guint32 ip1, guint32 ip2)
{
	guint8 n;
	guint32 mask;

	for (n = 0, mask = 0x80000000; n < 32; n++, mask |= (mask >> 1)) {
		if ((ip1 & mask) != (ip2 & mask))
			return n;
	}

	return n;
}

/**
 * Computes the set of CIDR ranges that make up the set of IPs between
 * two boundary IPs, included.
 *
 * For instance, for the range 2.0.0.0 - 2.138.24.150, we have:
 *
 * 2.0.0.0/9, 2.128.0.0/13, 2.136.0.0/15, 2.138.0.0/20, 2.138.16.0/21,
 * 2.138.24.0/25, 2.138.24.128/28, 2.138.24.144/30, 2.138.24.148,
 * 2.138.24.149 and 2.138.24.150.
 *
 * For each identified CIDR range, invoke the supplied callback, along
 * with the trailing user-supplied `udata' pointer.
 *
 * @param lower_ip	the lower-bound IP
 * @param upper_ip	the upper-bound IP
 * @param cb		the callback, invoked as callback(ip, bits, udata)
 * @param udata		the trailing parameter passed as-is to the callbacks
 */
void
ip_range_split(
	guint32 lower_ip, guint32 upper_ip, cidr_split_t cb, gpointer udata)
{
	guint8 bits;
	guint32 mask;
	guint32 trailing;

	g_assert(lower_ip <= upper_ip);

	bits = find_common_leading(lower_ip, upper_ip);
	mask = 1 << (32 - bits);
	trailing = mask - 1;

	if (bits == 32) {
		g_assert(lower_ip == upper_ip);
		(*cb)(lower_ip, bits, udata);
	} else if (trailing == (upper_ip & trailing)) {
		/*
		 * All the trailing bits of upper_ip are 1s.
		 */

		if (0 == (lower_ip & trailing)) {
			/*
			 * All the trailing bits of lower_ip are 0s -- we're done
			 */

			(*cb)(lower_ip, bits, udata);
		} else {
			guint32 cut;

			/*
			 * Start filling after the first 1 bit in lower_ip.
			 */

			mask = 1;
			while (0 == (lower_ip & mask))
				mask <<= 1;
			cut = (mask - 1) | lower_ip;

			/*
			 * Recurse on sub-ranges [lower_ip, cut] and ]cut, upper_ip].
			 */

			ip_range_split(lower_ip, cut, cb, udata);
			ip_range_split(cut + 1, upper_ip, cb, udata);
		}
	} else {
		guint32 cut;

		/*
		 * We can't cover the full range.
		 *
		 * We know that bits #(32-bits) in lower_ip and upper_ip differ.
		 * Since lower_ip <= upper_ip, the bit is necessary 0 in lower_ip.
		 */

		mask >>= 1;					/* First bit that differs */

		g_assert(0 == (lower_ip & mask));
		g_assert(0 != (upper_ip & mask));

		cut = upper_ip & ~mask;		/* Reset that bit in upper_ip */
		cut |= mask - 1;			/* And set the trailing bits to 1s */

		/*
		 * Recurse on sub-ranges [lower_ip, cut] and ]cut, upper_ip].
		 */

		ip_range_split(lower_ip, cut, cb, udata);
		ip_range_split(cut + 1, upper_ip, cb, udata);
	}
}

/**
 * Installs a signal handler. The signal handler is not reset to the default
 * handler after delivery. If the signal is SIGALRM, the handler is installed
 * so that interrupted system calls fail with EINTR. Handlers for other all
 * signals are installed so that interrupted system calls are restarted
 * instead.
 *
 * @param signo the signal number.
 * @param handler the signal handler to install.
 *
 * @return the previous signal handler or SIG_ERR on failure.
 */
signal_handler_t
set_signal(gint signo, signal_handler_t handler)
{
#ifdef HAS_SIGACTION
	static const struct sigaction zero_sa;
	struct sigaction sa, osa;
	
	g_assert(handler != SIG_ERR);

	sa = zero_sa;
	sa.sa_handler = handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = signo != SIGALRM ? SA_RESTART
#ifdef HAS_SA_INTERRUPT
		: SA_INTERRUPT;
#else
		: 0;
#endif

	return sigaction(signo, &sa, &osa) ? SIG_ERR : osa.sa_handler;
#else
	/* FIXME WIN32, probably: We can't just ignore all signal logic */
	return NULL;
#endif
}

static inline const gchar *
html_escape_replacement(gchar c, size_t *len)
{
	static gchar r;

#define REPLACE(x) { *len = CONST_STRLEN(x); return (x); }

	switch (c) {
	case '&':
		REPLACE("&amp;");
	case '<':
		REPLACE("&lt;");
	case '>':
		REPLACE("&gt;");
	case '"':
		REPLACE("&quot;");
	case '\'':
		REPLACE("&#39;");
	}
#undef REPLACE

	r = c;
	*len = 1;
	return &r;
}

/**
 * Copies the NUL-terminated string ``src'' to ``dst'' replacing all
 * characters which are reserved in HTML with a replacement string.
 *
 * @param src a NUL-terminated string.
 * @param dst the destination buffer, may be NULL if ``size'' is zero.
 * @param dst_size the size in bytes of the destination buffer.
 * @return the length in bytes of resulting string assuming size was
 *         sufficiently large.
 */
size_t
html_escape(const gchar *src, gchar *dst, size_t dst_size)
{
	gchar *d = dst;
	const gchar *s = src;
	guchar c;

	g_assert(0 == dst_size || NULL != dst);
	g_assert(NULL != src);

	if (dst_size-- > 0) {
		for (/* NOTHING*/; '\0' != (c = *s); s++) {
			const gchar *r;
			size_t len;

			r = html_escape_replacement(c, &len);
			if (len > dst_size)
				break;

			dst_size -= len;
			while (len-- > 0)
				*d++ = *r++;
		}
		*d = '\0';
	}
	while ('\0' != (c = *s++)) {
		size_t len;

		html_escape_replacement(c, &len);
		d += len;
	}

	return d - dst;
}

guint32
html_decode_entity(const gchar *src, const gchar **endptr)
{
	guint i;
	guint32 uc = -1;

	if ('&' == src[0]) {
		for (i = 0; i < G_N_ELEMENTS(html_entities); i++) {
			const gchar *end;

			end = is_strprefix(&src[1], html_entities[i].name);
			if (end && *end == ';') {
				uc = html_entities[i].uc;
				src = end;
				break;
			}
		}
	}
	if (endptr) {
		*endptr = src;
	}
	return uc;
}

/**
 * Creates the canonical representation of a path.
 *
 * ``dst'' and ``src'' may be identical but must not overlap otherwise.
 *
 * @param dst the destination, must be sufficiently long.
 * @param path a NUL-terminated string representing the input path.
 * @return zero on sucess, non-zero on failure.
 */
gint
canonize_path(gchar *dst, const gchar *path)
{
  const gchar *p;
  gchar c, *q, *ep;

  g_assert(dst);
  g_assert(path);
  /** TODO: Add overlap check. */

  /* Scan path */
  for (p = path, q = dst; '\0' != (c = *p); q++, p++) {

    /* Handle relative paths i.e., /. and /.. */
    if ('/' != c) {
      *q = c;
      continue;
    }

    /* Special handling for '/' follows */

    do {

      *q = '/';

      while ('/' == p[1]) {
        p++;
      }

      if (0 == strcmp(p, "/.")) {
        p++;
        /* Ignoring trailing "/." in URI */
      } else if (0 == strcmp(p, "/..")) {
        return -1;
      } else if (NULL != (ep = is_strprefix(p, "/./"))) {
        p = ep - 1;
        /* Ignoring unnecessary "/./" in URI */
      } else if (NULL != (ep = is_strprefix(p, "/../"))) {
        p = ep - 1;

        /* Ascending one component in URI */
        do {
          if (q == dst)
            return -1; /* beyond root */
        } while ('/' != *--q);

      } else {
        break;
      }

    } while ('/' == p[0] && ('/' == p[1] || '.' == p[1]));

  }

  *q = '\0';

  return 0;
}

guint
compat_max_fd(void)
{
#ifdef MINGW32
	/* FIXME WIN32 */
	return 1024;
#else
	return getdtablesize();
#endif
}

gint
compat_mkdir(const gchar *path, mode_t mode)
{
#ifdef MINGW32
	/* FIXME WIN32 */
	return mkdir(path);
#else
	return mkdir(path, mode);
#endif
}

gboolean
compat_is_superuser(void)
{
	gboolean ret = FALSE;	/* Assume luser by default */
	
#ifdef HAS_GETUID
	ret |= 0 == getuid();
#endif /* HAS_GETUID */

#ifdef HAS_GETEUID
	ret |= 0 == geteuid();
#endif /* HAS_GETEUID */

	return ret;
}

/**
 * Daemonizes the current process.
 *
 * @param directory We will chdir() to this directory. A value of NULL
 *                  implies the root directory.
 */
int
compat_daemonize(const char *directory)
{
	pid_t pid;
	int i;

	if (!directory) {
		directory = "/";
	}

	for (i = 0; i < 2; i++) {
		/* A handler for SIGCHLD should already be installed. */

		fflush(NULL);
		pid = fork();
		if ((pid_t) -1 == pid) {
			g_warning("fork() failed: %s", g_strerror(errno));
			return -1;
		}

		if (pid) {
			_exit(0);
			/* NOTREACHED */
			return -1;
		}

		/* Create a new session after the first fork() */
		if (0 == i && (pid_t) -1 == setsid()) {
			g_warning("setsid() failed: %s", g_strerror(errno));
			return -1;
		}
	}

	pid = getpid();
	if (setpgid(0, pid)) {
		g_warning("setpgid(0, %lu) failed: %s",
				(unsigned long) pid, g_strerror(errno));
		return -1;
	}

	if (chdir(directory)) {
		g_warning("chdir(\"%s\") failed: %s", directory, g_strerror(errno));
		return -1;
	}

	/*
	 * Make sure we don't create any files with an s-bit set or
	 * a world-writeable file.
	 */
	umask(umask(0) | S_IWOTH | S_ISUID | S_ISGID);

	/*
	 * Close all standard streams.
	 */

	if (!freopen("/dev/null", "r", stdin)) {
		g_warning("freopen() failed for stdin");
		return -1;
	}
	if (!freopen("/dev/null", "w", stdout)) {
		g_warning("freopen() failed for stdout");
		return -1;
	}
	if (!freopen("/dev/null", "w", stderr)) {
		g_warning("freopen() failed for stderr");
		return -1;
	}

	return 0;
}

void
compat_fadvise_sequential(int fd, off_t offset, off_t size)
{
	g_return_if_fail(fd >= 0);
	g_return_if_fail(offset >= 0);
	g_return_if_fail(size >= 0);

#ifdef HAS_POSIX_FADVISE
	posix_fadvise(fd, offset, size, POSIX_FADV_SEQUENTIAL);
#endif	/* HAS_POSIX_FADVISE */
}

/**
 * Counts the number of bytes that differ between two chunks of memory.
 */
size_t
memcmp_diff(const void *a, const void *b, size_t size)
{
	const gchar *p = a, *q = b;
	size_t n = 0;

	while (size-- > 0) {
		if (*p++ != *q++)
			n++;
	}

	return n;
}

guint32
cpu_noise(void)
{
	static guchar data[512];
	struct sha1 digest;
	SHA1Context ctx;
	guint32 r, i;
	
	r = random_u32();
	i = r % G_N_ELEMENTS(data);
	data[i] = r;

	SHA1Reset(&ctx);
	SHA1Input(&ctx, data, i);
	SHA1Result(&ctx, &digest);

	return peek_le32(digest.data);
}

/**
 * Creates a string copy with all directory separators replaced with the
 * canonic path component separator '/' (a slash).
 *
 * @param s a pathname. 
 * @return  a newly allocated string.
 */
gchar *
normalize_dir_separators(const gchar *s)
{
	gchar *ret;
  
   	g_assert(s);	

	ret = g_strdup(s);

	if (G_DIR_SEPARATOR != '/') {
		gchar *p = ret;

		while (p) {
			p = strchr(p, G_DIR_SEPARATOR);
			if (p) {
				*p++ = '/';
			}
		}
	}
	return ret;
}

void
set_close_on_exec(gint fd)
{
	gint flags;

	flags = fcntl(fd, F_GETFD);
	if (0 == (flags & FD_CLOEXEC)) {
		flags |= FD_CLOEXEC;
		fcntl(fd, F_SETFD, flags);
	}
}

static inline gboolean
try_close_from(const int first_fd)
{
#if defined(F_CLOSEM)
	return -1 != fcntl(first_fd, F_CLOSEM);
#elif defined(HAS_CLOSEFROM)
	/* Returns nothing on Solaris; NetBSD has F_CLOSEM and closefrom()
	 * equivalent to the above. Thus prefer F_CLOSEM due to potential
	 * error. */
	closefrom(first_fd);
	return TRUE;
#else
	(void) first_fd;
	return FALSE;
#endif	/* HAS_CLOSEFROM */
}

/**
 * Closes all file descriptors greater or equal to ``first_fd''.
 */
void
close_file_descriptors(const int first_fd)
{
	int fd;

	g_return_if_fail(first_fd >= 0);

	if (try_close_from(first_fd))
		return;

	fd = compat_max_fd() - 1;
	while (fd >= first_fd) {
		if (close(fd)) {
#if defined(F_MAXFD)
			fd = fcntl(0, F_MAXFD);
			continue;
#endif	/* F_MAXFD */
		}
		fd--;
	}
}

/*
 * Ensures that fd 0, 1 and 2 are opened.
 *
 * @return 0 on success, -1 on failure.
 */
int
reserve_standard_file_descriptors(void)
{
	int fd;

	/*
	 * POSIX guarantees that open() and dup() return the lowest unassigned file
	 * descriptor. Check this but don't rely on it.
	 */
	for (fd = 0; fd < 3; fd++) {
		if (-1 != fcntl(fd, F_GETFL))
			continue;
		if (open("/dev/null", O_RDWR, 0) != fd)
			return -1;
	}
	return 0; 
}

/**
 * Equivalent to strstr() for raw memory without NUL-termination.
 *
 * @param data The memory to scan.
 * @param data_size The length of data.
 * @param pattern The byte pattern to look for.
 * @param pattern_size The length of the pattern.
 * @return NULL if not found. Otherwise, the start address of the first match
 *         is returned.
 */
void *
compat_memmem(const void *data, size_t data_size,
	const void *pattern, size_t pattern_size)
{
	const gchar *next, *p, *pat;
	
	pat = pattern;
	for (p = data; NULL != p; p = next) {
		if (data_size < pattern_size) {
			p = NULL;
			break;
		}
		if (0 == memcmp(p, pattern, pattern_size)) {
			break;
		}
		next = memchr(&p[1], pat[0], data_size - 1);
		data_size -= next - p;
	}
	return deconstify_gchar(p);
}

static gboolean
need_get_non_stdio_fd(void)
{
	int fd;

	/* Assume that STDIN_FILENO is open. */
	fd = fcntl(STDIN_FILENO, F_DUPFD, 256);
	if (fd >= 0) {
		FILE *f;

		f = fdopen(fd, "r");
		if (f) {
			fclose(f);
		} else {
			close(fd);
			return TRUE;
		}
	}
	return FALSE;
}

/**
 * If we detect that stdio cannot handle file descriptors above 255, this
 * functions tries to reassign 'fd' to a file descriptor above 255 in order to
 * reserve lower file descriptors for stdio. File descriptors below 3 or above
 * 255 are returned as-is. The original file descriptor is closed if it was
 * reassigned. On systems which do not need this workaround, the original
 * file descriptor is returned.
 *
 * @note The FD_CLOEXEC flag set will be cleared on the new file descriptor if
 *		 the file descriptor is successfully reassigned.
 *
 * @return	On success a new file descriptor above 255 is returned.
 *         	On failure or if reassigning was not necessary the original file
 *			descriptor is returned.
 */
int
get_non_stdio_fd(int fd)
{
	static gboolean initialized, needed;

	if (!initialized) {
		initialized = TRUE;
		needed = need_get_non_stdio_fd();
	}
	if (needed && fd > 2 && fd < 256) {
		int nfd, saved_errno;

		saved_errno = errno;
		nfd = fcntl(fd, F_DUPFD, 256);
		if (nfd > 0) {
			close(fd);
			fd = nfd;
		}
		errno = saved_errno;
	}
	return fd;
}

void
misc_init(void)
{
	hex2int_init();
	dec2int_init();
	alnum2int_init();

	{
		static const struct {
			const gchar *s;
			const guint64 v;
			const guint base;
			const gint error;
		} tests[] = {
			{ "", 					0,				10, EINVAL },
			{ "1111",				1111,			10, 0 },
			{ "z",					35, 			36, 0 },
			{ "Z",					35,				36, 0 },
			{ "0ff",				0xff,			16, 0 },
			{ "-1",					0,				10, EINVAL },
			{ "aBcDE",				0xabcde,		16, 0 },
			{ "ffff",				0xffff,			16, 0 },
			{ "fffff",				0xfffff,		16, 0 },
			{ "ffffffff",			0xffffffffU,	16, 0 },
			{ "ffffffffffffffff",	(guint64) -1,	16, 0 },
			{ "1111111111111111",	0xffff,			2,  0 },
			{ "11111111111111111",	0x1ffff,		2,  0 },
			{ "111111111111111111",	0x3ffff,		2,  0 },
			{ "ZZZ0",				1679580,		36, 0 },
			{ "2",					0,				2, EINVAL },
			{ "3",					0,				3, EINVAL },
			{ "4",					0,				4, EINVAL },
			{ "5",					0,				5, EINVAL },
			{ "6",					0,				6, EINVAL },
			{ "7",					0,				7, EINVAL },
			{ "8",					0,				8, EINVAL },
			{ "9",					0,				9, EINVAL },
		};
		guint i;

		for (i = 0; i < G_N_ELEMENTS(tests); i++) {
			const gchar *endptr;
			gint error;
			guint64 v;

			g_assert((0 == tests[i].v) ^ (0 == tests[i].error));
			
			error = EAGAIN;
			endptr = GINT_TO_POINTER(-1);
			v = parse_uint64(tests[i].s, &endptr, tests[i].base, &error);
			g_assert(tests[i].v == v);
			g_assert(tests[i].error == error);
			
			error = EAGAIN;
			endptr = GINT_TO_POINTER(-1);
			v = parse_uint32(tests[i].s, &endptr, tests[i].base, &error);
			if (tests[i].v > (guint32) -1) {
				g_assert(0 == v);
				g_assert(ERANGE == error);
			} else {
				g_assert(tests[i].v == v);
				g_assert(tests[i].error == error);
			}

			error = EAGAIN;
			endptr = GINT_TO_POINTER(-1);
			v = parse_uint16(tests[i].s, &endptr, tests[i].base, &error);
			if (tests[i].v > (guint16) -1) {
				g_assert(0 == v);
				g_assert(ERANGE == error);
			} else {
				g_assert(tests[i].v == v);
				g_assert(tests[i].error == error);
			}
		}
	}

}

/* vi: set ts=4 sw=4 cindent: */
