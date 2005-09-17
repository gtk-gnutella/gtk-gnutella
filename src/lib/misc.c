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

RCSID("$Id$");

#include <sys/times.h>			/* For times() */

#include "base32.h"
#include "endian.h"
#include "misc.h"
#include "glib-missing.h"
#include "sha1.h"
#include "tm.h"
#include "walloc.h"

#include "override.h"			/* Must be the last header included */

#if !defined(HAS_SRANDOM) || !defined(HAS_RANDOM)
#define srandom(x)	srand(x)
#define random()	rand()
#define RANDOM_MASK				0xffffffff
#define RANDOM_MAXV				RAND_MAX
#else
#define RANDOM_MASK				0x7fffffff
#define RANDOM_MAXV				RANDOM_MASK
#endif

static const char hex_alphabet[] = "0123456789ABCDEF";
static const char hex_alphabet_lower[] = "0123456789abcdef";



#ifndef HAS_STRLCPY
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

/**
 * Concatenates a variable number of NUL-terminated strings into ``dst''.
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
 * The returned value is the length of the resulting string. The buffer
 * is exactly one byte larger than this to hold the terminating NUL.
 *
 * The list of strings must be terminated by a NULL pointer. The first
 * list element may be NULL in which case zero is returned.
 *
 * @param dst_ptr if not NULL, it will point to the allocated buffer.
 * @param first the first source string or NULL.
 *
 * @return the sum of the lengths of all passed strings.
 */
size_t
w_concat_strings(gchar **dst_ptr, const gchar *first, ...)
{
	va_list ap, ap2;
	const gchar *s;
	size_t len;

	va_start(ap, first);
	VA_COPY(ap2, ap);

	for (s = first, len = 0; NULL != s; /* NOTHING */) {
		len += strlen(s);
		s = va_arg(ap, const gchar *);
	}

	va_end(ap);

	if (dst_ptr) {
		gchar *p;
		size_t n, size = 1 + len;

		*dst_ptr = p = walloc(size);
		for (s = first; NULL != s; p += n, size -= n) {
			n = g_strlcpy(p, s, size);
			s = va_arg(ap2, const gchar *);
			g_assert(n < size);
		}
		g_assert(1 == size);
	}

	va_end(ap2);

	return len;
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
file_exists(const gchar *f)
{
  	struct stat st;

    g_assert(f != NULL);
    return stat(f, &st) != -1;
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
			p += ip_to_string_buf(peek_be32(&ipv6[12]), p, n);
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

size_t
ip_to_string_buf(guint32 ip, gchar *buf, size_t size)
{
	struct in_addr ia;

	g_assert(buf != NULL);
	g_assert(size <= INT_MAX);

	ia.s_addr = htonl(ip);
	return g_strlcpy(buf, inet_ntoa(ia), size);
}

const gchar *
ip_to_string(guint32 ip)
{
	static gchar buf[32];

	ip_to_string_buf(ip, buf, sizeof buf);
	return buf;
}

const gchar *
ip_to_string2(guint32 ip)
{
	static gchar buf[32];

	ip_to_string_buf(ip, buf, sizeof buf);
	return buf;
}

const gchar *
ip_port_to_string(guint32 ip, guint16 port)
{
	static gchar a[32];
	size_t len;
	struct in_addr ia;

	ia.s_addr = htonl(ip);
	len = g_strlcpy(a, inet_ntoa(ia), sizeof(a));
	if (len < sizeof(a) - 1)
		gm_snprintf(a + len, sizeof(a) - len, ":%u", port);
	return a;
}

const gchar *
hostname_port_to_gchar(const gchar *hostname, guint16 port)
{
	static gchar a[300];

	gm_snprintf(a, sizeof(a), "%.255s:%u", hostname, port);
	return a;
}

/*
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
	gboolean is_valid = TRUE;
	gint i, j, v;
	guint32 a = 0; /* 'pid compiler */

	g_assert(s);

	for (i = 0; i < 4; i++) {
		v = 0;
		for (j = 0; j < 3; j++) {
			if (*p < '0' || *p > '9') {
				is_valid = j > 0;
				break;
			}
			v *= 10;
			v += *p++ - '0';
		}
		if (!is_valid)
			break;
		if (i < 3) {
			if (*p != '.') {
				is_valid = FALSE;
				break; /* failure */
			}
			p++;
		}
		a = (a << 8) | v;
	}

	if (endptr)
		*endptr = p;

	if (addr)
		*addr = is_valid ? a : 0;

	return is_valid;
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
gint
str_chomp(gchar *str, gint len)
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
 * Check whether path is an absolute path.
 */
gboolean
is_absolute_path(const char *path)
{
	g_assert(path != NULL);
	return '/' == path[0];
}

/**
 * Check whether path is a directory.
 */
gboolean
is_directory(const gchar *path)
{
	struct stat st;
	if (stat(path, &st) == -1)
		return FALSE;
	return S_ISDIR(st.st_mode);
}

/**
 * Check whether path points to a regular file.
 */
gboolean
is_regular(const gchar *path)
{
	struct stat st;
	if (stat(path, &st) == -1)
		return FALSE;
	return S_ISREG(st.st_mode);
}

/**
 * Check whether path is a symbolic link.
 */
gboolean
is_symlink(const gchar *path)
{
	struct stat st;
	if (-1 == lstat(path, &st))
		return FALSE;
	return (st.st_mode & S_IFMT) == S_IFLNK;
}

const gchar *
short_size(guint64 size)
{
	static gchar b[SIZE_FIELD_MAX];

	if (size < 1024) {
		if (size == 1)
			gm_snprintf(b, sizeof(b), _("1 Byte"));
		else
			gm_snprintf(b, sizeof(b), _("%u Bytes"), (guint) size);
	} else if (size < 1048576)
		gm_snprintf(b, sizeof(b), "%.2f KiB", (gfloat) size / 1024.0);
	else if (size < 1073741824)
		gm_snprintf(b, sizeof(b), "%.2f MiB", (gfloat) size / 1048576.0);
	else if ((size >> 10) < 1073741824)
		gm_snprintf(b, sizeof(b), "%.2f GiB", (gfloat) size / 1073741824.0);
	else if ((size >> 20) < 1073741824)
		gm_snprintf(b, sizeof(b), "%.2f TiB",
			(gfloat) (size >> 10) / 1073741824.0);
	else if ((size >> 30) < 1073741824)
		gm_snprintf(b, sizeof(b), "%.2f PiB",
			(gfloat) (size >> 20) / 1073741824.0);
	else
		gm_snprintf(b, sizeof(b), "%.2f EiB",
			(gfloat) (size >> 30) / 1073741824.0);

	return b;
}

/**
 * Like short_size() but with unbreakable space between the digits and unit.
 */
const gchar *
short_html_size(guint64 size)
{
	static gchar b[SIZE_FIELD_MAX];

	if (size < 1024) {
		if (size == 1)
			gm_snprintf(b, sizeof(b), _("1&nbsp;Byte"));
		else
			gm_snprintf(b, sizeof(b), _("%u&nbsp;Bytes"), (guint) size);
	} else if (size < 1048576)
		gm_snprintf(b, sizeof(b), "%.2f&nbsp;KiB", (gfloat) size / 1024.0);
	else if (size < 1073741824)
		gm_snprintf(b, sizeof(b), "%.2f&nbsp;MiB", (gfloat) size / 1048576.0);
	else if ((size >> 10) < 1073741824)
		gm_snprintf(b, sizeof(b), "%.2f&nbsp;GiB", (gfloat) size / 1073741824.0);
	else if ((size >> 20) < 1073741824)
		gm_snprintf(b, sizeof(b), "%.2f&nbsp;TiB",
			(gfloat) (size >> 10) / 1073741824.0);
	else if ((size >> 30) < 1073741824)
		gm_snprintf(b, sizeof(b), "%.2f&nbsp;PiB",
			(gfloat) (size >> 20) / 1073741824.0);
	else
		gm_snprintf(b, sizeof(b), "%.2f&nbsp;EiB",
			(gfloat) (size >> 30) / 1073741824.0);

	return b;
}

const gchar *
short_kb_size(guint64 size)
{
	static gchar b[SIZE_FIELD_MAX];

	if (size < 1024)
		gm_snprintf(b, sizeof(b), "%u KiB", (guint) size);
	else if (size < 1048576)
		gm_snprintf(b, sizeof(b), "%.2f MiB", (gfloat) size / 1024.0);
	else if (size < 1073741824)
		gm_snprintf(b, sizeof(b), "%.2f GiB", (gfloat) size / 1048576.0);
	else if ((size >> 10) < 1073741824)
		gm_snprintf(b, sizeof(b), "%.2f TiB", (gfloat) size / 1073741824.0);
	else if ((size >> 20) < 1073741824)
		gm_snprintf(b, sizeof(b), "%.2f PiB",
			(gfloat) (size >> 10) / 1073741824.0);
	else if ((size >> 30) < 1073741824)
		gm_snprintf(b, sizeof(b), "%.2f EiB",
			(gfloat) (size >> 20) / 1073741824.0);
	else
		gm_snprintf(b, sizeof(b), "%.2f ZiB",
			(gfloat) (size >> 30) / 1073741824.0);

	return b;
}

gchar *
compact_value(gchar *buf, size_t size, guint64 v)
{
	if (v < 1024) {
		gm_snprintf(buf, size, "%u", (guint) v);
	} else if (v < 1048576) {
		if (v & 0x3ff)
			gm_snprintf(buf, size, "%.1fKi",
				(gfloat) (guint32) v / 1024.0);
		else
			gm_snprintf(buf, size, "%uKi", (guint32) v >> 10);
	} else if (v < 1073741824) {
		if (v & 0xfffff)
			gm_snprintf(buf, size, "%.1fMi",
				(gfloat) (guint32) v / 1048576.0);
		else
			gm_snprintf(buf, size, "%uMi", (guint32) v >> 20);
	} else if ((v >> 10) < 1073741824) {
		if (v & 0x3fffffff)
			gm_snprintf(buf, size, "%.1fGi", (gfloat) v / 1073741824.0);
		else
			gm_snprintf(buf, size, "%uGi", (guint32) (v >> 30));
	} else {
		gm_snprintf(buf, size, "%.1fTi", (gfloat) (v >> 10) / 1073741824.0);
	}

	return buf;
}

gchar *
short_value(gchar *buf, size_t size, guint64 v)
{
	if (v < 1024) {
		gm_snprintf(buf, size, "%u ", (guint) v);
	} else if (v < 1048576) {
		if (v & 0x3ff)
			gm_snprintf(buf, size, "%.2f Ki",
				(gfloat) (guint32) v / 1024.0);
		else
			gm_snprintf(buf, size, "%u Ki", (guint32) v >> 10);
	} else if (v < 1073741824) {
		if (v & 0xfffff)
			gm_snprintf(buf, size, "%.2f Mi",
				(gfloat) (guint32) v / 1048576.0);
		else
			gm_snprintf(buf, size, "%u Mi", (guint32) v >> 20);
	} else if ((v >> 10) < 1073741824) {
		if (v & 0x3fffffff)
			gm_snprintf(buf, size, "%.2f Gi", (gfloat) v / 1073741824.0);
		else
			gm_snprintf(buf, size, "%u Gi", (guint32) (v >> 30));
	} else {
		gm_snprintf(buf, size, "%.2f Ti", (gfloat) (v >> 10) / 1073741824.0);
	}

	return buf;
}

const gchar *
compact_size(guint64 size)
{
	static gchar buf[64];
	gchar sizebuf[48];

	gm_snprintf(buf, sizeof buf, "%sB",
		compact_value(sizebuf, sizeof sizebuf, size));
	return buf;
}

const gchar *
compact_rate(guint64 rate)
{
	static gchar buf[64];
	gchar ratebuf[48];

	/* TRANSLATORS: Don't translate 'B', just 's' is allowed. */
	gm_snprintf(buf, sizeof buf, _("%sB/s"),
		compact_value(ratebuf, sizeof ratebuf, rate));
	return buf;
}

const gchar *
short_rate(guint64 rate)
{
	static gchar buf[64];
	gchar ratebuf[48];

	/* TRANSLATORS: Don't translate 'B', just 's' is allowed. */
	gm_snprintf(buf, sizeof buf, _("%sB/s"),
		short_value(ratebuf, sizeof ratebuf, rate));
	return buf;
}

/**
 * @return a number of Kbytes in a compact readable form
 */
const gchar *
compact_kb_size(guint32 size)
{
	static gchar b[64];

	if (size < 1024)
		gm_snprintf(b, sizeof(b), "%uKi", size);
	else if (size < 1048576) {
		if (size & 0x3ff)
			gm_snprintf(b, sizeof(b), "%.1fMi", (gfloat) size / 1024.0);
		else
			gm_snprintf(b, sizeof(b), "%dMi", size >> 10);
	} else if (size < 1073741824)
		if (size & 0xfffff)
			gm_snprintf(b, sizeof(b), "%.1fGi", (gfloat) size / 1048576.0);
		else
			gm_snprintf(b, sizeof(b), "%dGi", size >> 20);
	else {
		if (size & 0x3fffffff)
			gm_snprintf(b, sizeof(b), "%.1fTi", (gfloat) size / 1073741824.0);
		else
			gm_snprintf(b, sizeof(b), "%dTi", size >> 30);
	}

	return b;
}

/**
 * @return time spent in seconds in a consise short readable form
 */
gchar *
short_time(gint t)
{
	static gchar b[SIZE_FIELD_MAX];
	gint s = MAX(t, 0);

	if (s > 86400)
		gm_snprintf(b, sizeof(b), "%dd %dh", s / 86400, (s % 86400) / 3600);
	else if (s > 3600)
		gm_snprintf(b, sizeof(b), "%dh %dm", s / 3600, (s % 3600) / 60);
	else if (s > 60)
		gm_snprintf(b, sizeof(b), "%dm %ds", s / 60, s % 60);
	else
		gm_snprintf(b, sizeof(b), "%ds", s);

	return b;
}

/**
 * Alternate time formatter for uptime.
 */
gchar *
short_uptime(gint uptime)
{
	static gchar b[SIZE_FIELD_MAX];
	gint s = MAX(uptime, 0);

	if (s > 86400) {
		guint32 d = s % 86400;
		gm_snprintf(b, sizeof(b), "%dd %02d%c%02d",
			s / 86400, d / 3600, (s & 0x1) ? '.' : ':', (d % 3600) / 60);
	} else {
		guint32 h = s % 3600;
		gm_snprintf(b, sizeof(b), "%02d:%02d:%02d", s / 3600, h / 60, h % 60);
	}

	return b;
}

/**
 * @return hexadecimal string representing given GUID.
 */
gchar *
guid_hex_str(const gchar *guid)
{
	static gchar buf[33];
	const guint8 *g = cast_to_gconstpointer(guid);
	gulong i;

	for (i = 0; i < 32; g++) {
		buf[i++] = hex_alphabet_lower[*g >> 4];
		buf[i++] = hex_alphabet_lower[*g & 0x0f];
	}

	buf[32] = '\0';
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

static inline gint
hex2dec_invalid(void)
{
	g_assert_not_reached();
	return -1;
}

/**
 * Convert an hexadecimal char (0-9, A-F, a-f) into decimal.
 */
static inline gint
hex2dec_inline(guchar c)
{
	return c >= '0' && c <= '9' ? c - '0'
		 : c >= 'a' && c <= 'f' ? c - 'a' + 10
		 : c >= 'A' && c <= 'F' ? c - 'A' + 10
		 : hex2dec_invalid();
}

gint
hex2dec(guchar c)
{
	return hex2dec_inline(c);
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
	gulong i;

	for (i = 0; i < GUID_RAW_SIZE; i++) {
 		gint a;
 		gint b;

		a = (guchar) hexguid[i << 1];
		if (!is_ascii_xdigit(a))
			return FALSE;

		b = (guchar) hexguid[(i << 1) + 1];
		if (!is_ascii_xdigit(b))
			return FALSE;

		guid[i] = (hex2dec_inline(a) << 4) + hex2dec_inline(b);
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
	static gchar guid_b32[26 + 1];		/* 26 chars needed for a GUID */

	base32_encode_str_into(guid, 16, guid_b32, sizeof(guid_b32), FALSE);

	return guid_b32;
}

/**
 * Decode the base32 representation of a GUID.
 *
 * @return pointer to static data, or NULL if the input was not valid base32.
 */
gchar *
base32_to_guid(const gchar *base32)
{
	static gchar guid[20];	/* Needs 20 chars to decode, last 4 will be 0 */

	if (0 == base32_decode_into(base32, 26, guid, sizeof(guid)))
		return NULL;

	g_assert(guid[16] == '\0' && guid[17] == '\0' &&
		guid[18] == '\0' && guid[19] == '\0');

	return guid;
}

/**
 * Convert binary SHA1 into a base32 string.
 *
 * @return pointer to static data.
 */
gchar *
sha1_base32(const gchar *sha1)
{
	static gchar digest_b32[SHA1_BASE32_SIZE + 1];

	base32_encode_into(sha1, SHA1_RAW_SIZE, digest_b32, sizeof(digest_b32));
	digest_b32[SHA1_BASE32_SIZE] = '\0';

	return digest_b32;
}

/**
 * Convert base32 string into binary SHA1.
 *
 * @param base32 a buffer holding SHA1_BASE32_SIZE or more bytes.
 *
 * @return	Returns pointer to static data or NULL if the input wasn't a
 *			validly base32 encoded SHA1.
 */
gchar *
base32_sha1(const gchar *base32)
{
	static gchar digest_sha1[SHA1_RAW_SIZE];
	gint len;

	len = base32_decode_into(base32, SHA1_BASE32_SIZE,
		digest_sha1, sizeof(digest_sha1));

	return SHA1_RAW_SIZE == len ? digest_sha1 : NULL;
}

/**
 * Convert time to ISO style date, e.g. "2002-06-09T14:54:42Z".
 *
 * @return pointer to static data.
 */
gchar *
date_to_iso_gchar(time_t date)
{
	static gchar buf[80];
	struct tm *tm;

	tm = gmtime(&date);
	strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", tm);
	buf[sizeof(buf)-1] = '\0';		/* Be really sure */

	return buf;
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
 */
static void
date_to_rfc822(time_t date, gchar *buf, gint len)
{
	struct tm *tm;
	struct tm gmt_tm;
	gint gmt_off;
	gchar sign;

	g_assert(len > 0);
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

	gm_snprintf(buf, len, "%s, %02d %s %04d %02d:%02d:%02d %c%04d",
		days[tm->tm_wday], tm->tm_mday, months[tm->tm_mon], tm->tm_year + 1900,
		tm->tm_hour, tm->tm_min, tm->tm_sec,
		sign, gmt_off / 60 * 100 + gmt_off % 60);

	buf[len - 1] = '\0';		/* Be really sure */
}

/**
 * Convert time to RFC-822 style date.
 *
 * @return pointer to static data.
 */
gchar *
date_to_rfc822_gchar(time_t date)
{
	static gchar buf[80];

	date_to_rfc822(date, buf, sizeof(buf));
	return buf;
}

/**
 * Same as date_to_rfc822_gchar(), to be able to use the two in the same
 * printf() line.
 */
gchar *
date_to_rfc822_gchar2(time_t date)
{
	static gchar buf[80];

	date_to_rfc822(date, buf, sizeof(buf));
	return buf;
}

/**
 * Convert time to RFC-1123 style date, into supplied string buffer.
 */
static void
date_to_rfc1123(time_t date, gchar *buf, gint len)
{
	const struct tm *tm;

	g_assert(len > 0);
	tm = gmtime(&date);
	gm_snprintf(buf, len, "%s, %02d %s %04d %02d:%02d:%02d GMT",
		days[tm->tm_wday], tm->tm_mday, months[tm->tm_mon], tm->tm_year + 1900,
		tm->tm_hour, tm->tm_min, tm->tm_sec);
}

/**
 * Convert time to RFC-1123 style date.
 *
 * @returns pointer to static data.
 */
gchar *
date_to_rfc1123_gchar(time_t date)
{
	static gchar buf[80];

	date_to_rfc1123(date, buf, sizeof(buf));
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

/**
 * @return random value between (0..max).
 */
guint32
random_value(guint32 max)
{
	return (guint32)
		((max + 1.0) * (random() & RANDOM_MASK) / (RANDOM_MAXV + 1.0));
}

/**
 * Initialize random number generator.
 */
void
random_init(void)
{
	FILE *f = NULL;
	SHA1Context ctx;
	struct stat buf;
	tm_t start, end;
	struct tms ticks;
	guint32 seed;
	guint8 digest[SHA1HashSize];
	guint32 sys[17];
	gint i;
	gint j;
	gboolean is_pipe = TRUE;

	/*
	 * Get random entropy from the system.
	 */

	tm_now_exact(&start);

	SHA1Reset(&ctx);

	/*
	 * If we have a /dev/urandom character device, use it.
	 * Otherwise, launch ps and grab its output.
	 */

	if (-1 != stat("/dev/urandom", &buf) && S_ISCHR(buf.st_mode)) {
		f = fopen("/dev/urandom", "r");
		is_pipe = FALSE;
	}
	else if (-1 != stat("/bin/ps", &buf))
		f = popen("/bin/ps -ef", "r");
	else if (-1 != stat("/usr/bin/ps", &buf))
		f = popen("/usr/bin/ps -ef", "r");
	else if (-1 != stat("/usr/ucb/ps", &buf))
		f = popen("/usr/ucb/ps aux", "r");

	if (f == NULL)
		g_warning("was unable to %s on your system",
			is_pipe ? "find the ps command" : "open /dev/urandom");
	else {
		/*
		 * Compute the SHA1 of the output (either ps or /dev/urandom).
		 */

		for (;;) {
			guint8 data[1024];
			gint r;
			gint len = is_pipe ? sizeof(data) : 128;

			r = fread(data, 1, len, f);
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

	/*
	 * Add timing entropy.
	 */

	i = 0;
	sys[i++] = start.tv_sec;
	sys[i++] = start.tv_usec;

	sys[i++] = times(&ticks);
	sys[i++] = ticks.tms_utime;
	sys[i++] = ticks.tms_stime;

	tm_now_exact(&end);

	sys[i++] = end.tv_sec - start.tv_sec;
	sys[i++] = end.tv_usec - start.tv_usec;

	/* Add some host/user dependent noise */	
	sys[i++] = getuid();
	sys[i++] = getgid();
	sys[i++] = getpid();
	sys[i++] = getppid();

	sys[i++] = g_str_hash(__DATE__);
	sys[i++] = g_str_hash(__TIME__);
	sys[i++] = g_str_hash(g_get_user_name());
	sys[i++] = g_str_hash(g_get_real_name());
	sys[i++] = g_str_hash(g_get_home_dir());

	sys[i++] = GPOINTER_TO_UINT(&sys);

	g_assert(i == G_N_ELEMENTS(sys));	
	SHA1Input(&ctx, (guint8 *) sys, sizeof(sys));

	/*
	 * Reduce SHA1 to a single guint32.
	 */

	SHA1Result(&ctx, digest);

	for (seed = 0, i = j = 0; i < SHA1HashSize; i++) {
		guint32 b = digest[i];
		seed ^= b << (j << 3);
		j = (j + 1) & 0x3;
	}

	/*
	 * Finally, can initialize the random number generator.
	 */

	srandom(seed);
}

/**
 * Check whether buffer contains printable data, suitable for "%s" printing.
 * If not, consider dump_hex().
 */
gboolean is_printable(const gchar *buf, gint len)
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
 * Display header line for hex dumps
 */
static inline void
dump_hex_header(FILE *out)
{
	fprintf(out, "%s%s\n",
		"Offset  0  1  2  3  4  5  6  7   8  9  a  b  c  d  e  f  ",
		"0123456789abcdef");
}

/**
 * Displays hex & ascii lines to the terminal (for debug)
 * Displays the "title" then the characters in "s", # of bytes to print in "b"
 */
void
dump_hex(FILE *out, const gchar *title, gconstpointer data, gint b)
{
	int i, x, y, z, end;
	const gchar *s = data;
	gchar temp[18];

	if ((b < 0) || (s == NULL)) {
		g_warning("dump_hex: value out of range [s=0x%lx, b=%d] for %s",
			(gulong) s, b, title);
		fflush(out);
		return;
	}

	fprintf(out, "----------------- %s:\n", title);

	if (b == 0)
		goto done;

	i = x = end = 0;
	for (;;) {
		if ((x & 0xff) == 0) {					/* x%256 == 0 */
			if (x > 0)
				fputc('\n', out);				/* break after 256 byte chunk */
			dump_hex_header(out);
		}
		if (i == 0)
			fprintf(out, "%5d  ", x & 0xffff);	/* offset, lowest 16 bits */
		if ((x & 0x07) == 0 && (x & 0x08))		/* x == 8 modulo 16 */
			fputc(' ', out);
		if (end) {
			fputs("   ", out);
			temp[i] = ' ';
		} else {
			z = s[x] & 0xff;
			fprintf(out, "%.2X ", z);
			if (!(isalnum(z) || ispunct(z)))
				z = '.';		/* no non printables */
			temp[i] = z;		/* save it for later ASCII print */
		}
		if (++i >= 16) {
			fputc(' ', out);
			for (y = 0; y < 16; y++) {	/* do 16 bytes ASCII */
				fputc(temp[y], out);
			}
			fputc('\n', out);
			if (end || ((x + 1) >= b))
				break;
			i = 0;
		}
		if (++x >= b)
			end = 1;
	}

done:
	fprintf(out, "----------------- (%d bytes).\n", b);
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
	const gchar *delimit, gboolean case_sensitive)
{
	gboolean is_delimit[256];
	gint i;
	guchar *p;
	guchar *q;
	guchar c;
	guchar d;

	/*
	 * Initialize delimitors.
	 */

	is_delimit[0] = TRUE;
	for (i = 1; i < 256; i++)
		is_delimit[i] = FALSE;

	p = (guchar *) delimit;
	while ((c = *p++))
		is_delimit[case_sensitive ? c : tolower(c)] = TRUE;

	/*
	 * Compare strings up to the specified delimitors.
	 */

	p = (guchar *) a;
	q = (guchar *) b;

	for (;;) {
		c = *p++;
		d = *q++;
		if (case_sensitive) {
			c = tolower(c);
			d = tolower(d);
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
strcasecmp_delimit(const gchar *a, const gchar *b, const gchar *delimit)
{
	return strcmp_delimit_full(a, b, delimit, FALSE);
}

/**
 * Generate a new random GUID within given `xuid'.
 */
void
guid_random_fill(gchar *xuid)
{
	gint i;
	guint32 v;

	for (i = 0; i < 16; i++) {
		v =  random_value(~((guint32) 0U));
		xuid[i] = v ^ (v >> 8) ^ (v >> 16) ^ (v >> 24);
	}
}


/**
 * Determine unique filename for `file' in `path', with optional trailing
 * extension `ext'.  If no `ext' is wanted, one must supply an empty string.
 *
 * @returns the chosen unique complete filename as a pointer which must be
 * freed.
 */
gchar *
unique_filename(const gchar *path, const gchar *file, const gchar *ext)
{
	static const gchar extra_bytes[] = "0123456789abcdefghijklmnopqrstuvwxyz";
	const gchar *sep;
	gchar *filename;
	size_t size;
	size_t len;
	struct stat buf;
	gint i;
	gchar xuid[GUID_RAW_SIZE];

	g_assert(path);
	g_assert(file);
	g_assert(ext);

	sep = strrchr(path, G_DIR_SEPARATOR);
	g_assert(sep);	/* This is supposed to an absolute path */
	/* Insert G_DIR_SEPARATOR_S only if necessary */
	sep = sep[1] != '\0' ? G_DIR_SEPARATOR_S : "";

	/* Use extra_bytes so we can easily append a few chars later */
	filename = g_strconcat(path, sep, file, ext, extra_bytes, (void *) 0);
	size = strlen(filename);
	g_assert(size > sizeof extra_bytes);
	len = size - (sizeof extra_bytes - 1);
	g_assert(filename[len] == extra_bytes[0]);
	filename[len] = '\0';

	/*
	 * Append file and extension, then try to see whether this file exists.
	 */

	if (-1 == do_stat(filename, &buf) && ENOENT == do_errno)
		return filename;

	/*
	 * Looks like we need to make the filename more unique.  Append .00, then
	 * .01, etc... until .99.
	 */

	for (i = 0; i < 100; i++) {
		gm_snprintf(&filename[len], size - len, ".%02d%s", i, ext);
		if (-1 == do_stat(filename, &buf) && ENOENT == do_errno)
			return filename;
	}

	/*
	 * OK, no luck.  Try with a few random numbers then.
	 */

	for (i = 0; i < 100; i++) {
		guint32 rnum = random_value(~((guint32) 0));
		gm_snprintf(&filename[len], size - len, ".%x%s", rnum, ext);
		if (-1 == do_stat(filename, &buf) && ENOENT == do_errno)
			return filename;
	}

	/*
	 * Bad luck.  Allocate a random GUID then.
	 */

	guid_random_fill(xuid);
	gm_snprintf(&filename[len], size - len, ".%s%s", guid_hex_str(xuid), ext);

	if (-1 == do_stat(filename, &buf))
		return filename;

	g_error("no luck with random number generator");	/* Should NOT happen */
	return NULL;
}

#define ESCAPE_CHAR		'\\'

/*
 * CHAR_IS_SAFE
 *
 * Nearly the same as isprint() but allows additional safe chars if !strict.
 */
#define CHAR_IS_SAFE(c, strict) \
	(isprint((c)) || (!(strict) && ((c) == ' ' || (c) == '\t' || (c) == '\n')))


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
		if (!CHAR_IS_SAFE(c, strict))
			need_escape++;

	if (need_escape == 0)
		return deconstify_gchar(name);

	new = g_malloc(p - name + 3 * need_escape);

	for (p = name, q = new, c = *p++; c; c = *p++) {
		if (CHAR_IS_SAFE(c, strict))
			*q++ = c;
		else {
			*q++ = ESCAPE_CHAR;
			*q++ = 'x';
			*q++ = hex_alphabet[c >> 4];
			*q++ = hex_alphabet[c & 0xf];
		}
	}
	*q = '\0';

	return new;
}

/**
 * Escape all control chars into the hexadecimal "\xhh" form.
 *
 * @returns new escaped string, or the original string if no escaping occurred.
 */
gchar *
control_escape(const gchar *s)
{
	const gchar *p;
	gchar *q;
	guchar c;
	gint need_escape = 0;
	gchar *new;

	for (p = s; '\0' != (c = *p); p++)
		if (is_ascii_cntrl(c) || iscntrl(c))
			need_escape++;

	if (0 == need_escape)
		return deconstify_gchar(s);

	new = g_malloc(p - s + 3 * need_escape);

	for (p = s, q = new; '\0' != (c = *p); p++) {
		if (!is_ascii_cntrl(c) && !iscntrl(c))
			*q++ = c;
		else {
			*q++ = ESCAPE_CHAR;
			*q++ = 'x';
			*q++ = hex_alphabet[c >> 4];
			*q++ = hex_alphabet[c & 0xf];
		}
	}
	*q = '\0';

	return new;
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
	gint error;
	glong v;

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

	if (string_to_ip_strict(s, netmask, &ep))
		return 0 != *netmask;

	v = gm_atoul(s, (gchar **) &ep, &error);
	if (error || v < 1 || v > 32 || *ep != '\0')
		return FALSE;

	*netmask = ~0U << (32 - v);
	return TRUE;
}

/***
 *** System call wrapping with errno remapping.
 ***/

gint do_errno;

/**
 * Wrapper for the stat() system call.
 */
gint
do_stat(const gchar *path, struct stat *buf)
{
	gint ret;

	/*
	 * On my system, since I upgraded to libc6 2.3.2, I have system calls
	 * that fail with errno = 0.  I assume this is a multi-threading issue,
	 * since my kernel is SMP and gcc 3.3 requires a libpthread.  Or whatever,
	 * but it did not occur before with the same kernel and a previous libc6
	 * along with gcc 2.95.
	 *
	 * So... Assume that if stat() returns -1 and errno is 0, then it
	 * really means ENOENT.
	 *
	 *		--RAM, 27/10/2003
	 */

	ret = stat(path, buf);
	do_errno = errno;

	if (-1 == ret && 0 == do_errno) {
		g_warning("stat(\"%s\") returned -1 with errno = 0, assuming ENOENT",
			path);
		do_errno = errno = ENOENT;
	}

	/*
	 * Perform some remapping.  Stats through NFS may return EXDEV?
	 */

	switch (do_errno) {
	case EXDEV:
		g_warning("stat(\"%s\") failed with weird errno = %d (%s), "
			"assuming ENOENT", path, do_errno, g_strerror(do_errno));
		do_errno = errno = ENOENT;
		break;
	default:
		break;
	}

	if (-1 == ret && ENOENT != do_errno)
		g_warning("stat(\"%s\") returned -1 with errno = %d (%s)",
			path, do_errno, g_strerror(do_errno));

	return ret;
}

/**
 * Create new pathname from the concatenation of the dirname and the basename
 * of the file.  The resulting string can be freed when it is no longer needed.
 */
gchar *
make_pathname(const gchar *dir, const gchar *file)
{
	const gchar *sep;
	size_t l;

	g_assert(dir);
	g_assert(file);

	l = strlen(dir);
	if ((l > 0 && dir[l - 1] == G_DIR_SEPARATOR) || file[0] == G_DIR_SEPARATOR)
		 sep = "";
	else
		 sep = G_DIR_SEPARATOR_S;

	return g_strconcat(dir, sep, file, NULL);
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
 * FIXME: This might fail with ``fancy'' file permissions. The directories
 *        should be created from leaf to root instead of vice-versa.
 *
 * @param dir the pathname of the directory to create.
 *
 * @return On success, zero is returned. On failure, -1 is returned and
 *         errno indicates the reason.
 */
gint
create_directory(const gchar *dir)
{
	static const mode_t mode =
		S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH; /* 0755 */
	gchar *path = NULL;
	size_t len, i;

	g_assert(dir != NULL);

	if (*dir != '/') {
		errno = EPERM;
		goto failure;
	}

	len = strlen(dir);
	path = g_malloc0(len + 1);
	memcpy(path, dir, len);
	path[len] = '\0';
	i = 0;

	do {
		const gchar *p;

		path[i++] = '/';
		p = strchr(&path[i], '/');
		if (p != NULL) {
			i = p - path;
			g_assert(i > 0 && i < len);
			g_assert(path[i] == '/');
			path[i] = '\0';
		} else {
			i = len;
			g_assert(path[i] == '\0');
		}

		g_message("stat(\"%s\")", path);
		if (!is_directory(path)) {
			g_message("stat() failed: %s", g_strerror(errno));
			if (errno != ENOENT)
				goto failure;

			g_message("mkdir(\"%s\")", path);
			if (mkdir(path, mode)) {
				g_message("mkdir() failed: %s", g_strerror(errno));
				goto failure;
			}
		}

	} while (i < len);

	G_FREE_NULL(path);
	return is_directory(dir) ? 0 : -1;

failure:

	G_FREE_NULL(path);
	return -1;
}

/**
 * Check whether file given by its dirname and its basename exists.
 */
gboolean
filepath_exists(const gchar *dir, const gchar *file)
{
	gchar *path;
	struct stat buf;
	gboolean exists = TRUE;

	path = make_pathname(dir, file);

	if (-1 == do_stat(path, &buf))
		exists = FALSE;

	G_FREE_NULL(path);

	return exists;
}

size_t
uint32_to_string_buf(guint64 v, gchar *dst, size_t size)
{
	static const gchar dec_alphabet[] = "0123456789";
	gchar buf[UINT32_DEC_BUFLEN];
	gchar *p;
	size_t len;

	g_assert(0 == size || NULL != dst);
	g_assert(size <= INT_MAX);

	for (p = buf; /* NOTHING */; v /= 10) {
		*p++ = dec_alphabet[v % 10];
		if (v < 10)
			break;
	}
	len = p - buf;

	if (size > 0) {
		const gchar *end = &dst[size - 1];
		gchar *q;

		for (q = dst; q != end && p != buf; q++)
			*q = *--p;

		*q = '\0';
	}

	return len;
}

size_t
uint64_to_string_buf(guint64 v, gchar *dst, size_t size)
{
	static const gchar dec_alphabet[] = "0123456789";
	gchar buf[UINT64_DEC_BUFLEN];
	gchar *p;
	size_t len;

	g_assert(0 == size || NULL != dst);
	g_assert(size <= INT_MAX);

	for (p = buf; /* NOTHING */; v /= 10) {
		*p++ = dec_alphabet[v % 10];
		if (v < 10)
			break;
	}
	len = p - buf;

	if (size > 0) {
		const gchar *end = &dst[size - 1];
		gchar *q;

		for (q = dst; q != end && p != buf; q++)
			*q = *--p;

		*q = '\0';
	}

	return len;
}

const gchar *
uint32_to_string(guint32 v)
{
	static gchar buf[UINT32_DEC_BUFLEN];
	size_t n;

	n = uint32_to_string_buf(v, buf, sizeof buf);
	g_assert(n < sizeof buf);
	return buf;
}

const gchar *
uint64_to_string(guint64 v)
{
	static gchar buf[UINT64_DEC_BUFLEN];
	size_t n;

	n = uint64_to_string_buf(v, buf, sizeof buf);
	g_assert(n < sizeof buf);
	return buf;
}

const gchar *
uint64_to_string2(guint64 v)
{
	static gchar buf[UINT64_DEC_BUFLEN];
	size_t n;

	n = uint64_to_string_buf(v, buf, sizeof buf);
	g_assert(n < sizeof buf);
	return buf;
}

/**
 * Parses an unsigned 64-bit integer from an ASCII string.
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
 *    number would exceed (2^64)-1.
 *
 * @return
 *    The parsed value or zero in case of an error. If zero is returned
 *    error must be checked to determine whether there was an error
 *    or whether the parsed value was zero.
 */
guint64
parse_uint64(const gchar *src, gchar const **endptr, gint base, gint *errorptr)
{
	const gchar *p;
	guint64 v = 0;
	gint error = 0, c;

	g_assert(src != NULL);
	g_assert(errorptr != NULL);
	g_assert(base >= 2 && base <= 36);

	if (base < 2 || base > 36) {
		*errorptr = EINVAL;
		return 0;
	}

	for (p = src; (c = (guchar) *p) != '\0'; ++p) {
		guint64 d, w;

		if (!isascii(c))
			break;

		if (isdigit(c))
			d = c - '0';
		else if (isalpha(c)) {
			c = ascii_tolower(c);
			d = c - 'a' + 10;
		} else
			break;

		if (d >= (guint) base)
			break;

		w = v * base;
		if (w / base != v) {
			error = ERANGE;
			break;
		}
		v = w + d;
		if (v < w) {
			error = ERANGE;
			break;
		}
	}

	if (NULL != endptr)
		*endptr = p;

	if (!error && p == src)
		error = EINVAL;

	*errorptr = error;
	return error ? 0 : v;
}

/**
 * Parses an unsigned 32-bit integer from an ASCII string.
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
 *    number would exceed (2^32)-1.
 *
 * @return
 *    The parsed value or zero in case of an error. If zero is returned
 *    error must be checked to determine whether there was an error
 *    or whether the parsed value was zero.
 */
guint32
parse_uint32(const gchar *src, gchar const **endptr, gint base, gint *errorptr)
{
	const gchar *p;
	guint32 v = 0;
	gint error = 0, c;

	g_assert(src != NULL);
	g_assert(errorptr != NULL);
	g_assert(base >= 2 && base <= 36);

	if (base < 2 || base > 36) {
		*errorptr = EINVAL;
		return 0;
	}

	for (p = src; (c = (guchar) *p) != '\0'; ++p) {
		guint32 d, w;

		if (!isascii(c))
			break;

		if (isdigit(c))
			d = c - '0';
		else if (isalpha(c)) {
			c = ascii_tolower(c);
			d = c - 'a' + 10;
		} else
			break;

		if (d >= (guint) base)
			break;

		w = v * base;
		if (w / base != v) {
			error = ERANGE;
			break;
		}
		v = w + d;
		if (v < w) {
			error = ERANGE;
			break;
		}
	}

	if (NULL != endptr)
		*endptr = p;

	if (!error && p == src)
		error = EINVAL;

	*errorptr = error;
	return error ? 0 : v;
}

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
 *
 * @todo
 * TODO: Add Configure check for SA_INTERRUPT.
 *
 */
signal_handler_t
set_signal(gint signo, signal_handler_t handler)
{
	static const struct sigaction zero_sa;
	struct sigaction sa, osa;

	g_assert(handler != SIG_ERR);

	sa = zero_sa;
	sa.sa_handler = handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = signo != SIGALRM ? SA_RESTART
#if defined(HAVE_SA_INTERRUPT) || defined(SA_INTERRUPT)
		: SA_INTERRUPT;
#else
		: 0;
#endif

	return sigaction(signo, &sa, &osa) ? SIG_ERR : osa.sa_handler;
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


/* vi: set ts=4 sw=4 cindent: */
