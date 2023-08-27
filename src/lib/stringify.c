/*
 * Copyright (c) 2008-2009, Raphael Manfredi
 * Copyright (c) 2003-2008, Christian Biere
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
 * Stringification routines.
 *
 * @author Raphael Manfredi
 * @date 2008-2009
 * @author Christian Biere
 * @date 2003-2008
 */

#include "common.h"

#include "stringify.h"

#include "ascii.h"
#include "buf.h"
#include "cstr.h"
#include "endian.h"
#include "halloc.h"
#include "mempcpy.h"
#include "misc.h"
#include "str.h"

#include "override.h"			/* Must be the last header included */

static const char hex_alphabet[] = "0123456789ABCDEF";
const char hex_alphabet_lower[] = "0123456789abcdef";

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
print_uint16_hex(char *dst, uint16 v)
{
	char *p = dst;
	int i;

	for (i = 0; i < 3; i++, v <<= 4) {
		uint8 d;

		d = v >> 12;
		if (0 != d || p != dst)
			*p++ = hex_alphabet_lower[d];
	}
	*p++ = hex_alphabet_lower[v >> 12];

	*p = '\0';
	return p - dst;
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
ipv4_to_string_buf(uint32 ipv4, char *dst, size_t size)
{
	char buf[IPV4_ADDR_BUFLEN];
	char * const p0 = size < sizeof buf ? buf : dst;
	char *p = p0;
	uint i;

	for (i = 0; i < 4; i++) {
		uchar v;

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
		cstr_bcpy(dst, size, p0);
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
ipv6_to_string_buf(const uint8_t *ipv6, char *dst, size_t size)
{
	char *p, buf[IPV6_ADDR_BUFLEN];
	const char *q;
	int zero_len = 2, zero_start = -1;
	int cur_len = 0, cur_start = 0;
	int i;

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
		uint16 v;

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
		uint16 v = peek_be16(&ipv6[i]);

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
		char *end;

		n = MIN(n, (size_t) (p - q));
		end = mempcpy(dst, q, n);
		*end = '\0';
	}

	*p = '\0';
	return p - q;
}

static const char *
ipv6_to_string_b(const uint8 *ipv6, buf_t *b)
{
	char *p = buf_data(b);
	size_t n, sz = buf_size(b);

	n = ipv6_to_string_buf(ipv6, p, sz);
	g_assert(n < sz);
	return p;
}

/**
 * Prints the IPv6 address ``ipv6'' to a static buffer.
 *
 * @param ipv6 the IPv6 address; must point to a buffer of 16 bytes.
 * @return a pointer to a static buffer holding a NUL-terminated string
 *         representing the given IPv6 address.
 */
const char *
ipv6_to_string(const uint8 *ipv6)
{
	buf_t *b = buf_private(G_STRFUNC, IPV6_ADDR_BUFLEN);
	return ipv6_to_string_b(ipv6, b);
}

const char *
ipv6_to_string2(const uint8 *ipv6)
{
	buf_t *b = buf_private(G_STRFUNC, IPV6_ADDR_BUFLEN);
	return ipv6_to_string_b(ipv6, b);
}

const char *
ip_to_string(uint32 ip)
{
	buf_t *b = buf_private(G_STRFUNC, IPV4_ADDR_BUFLEN);
	char *p = buf_data(b);
	size_t n, sz = buf_size(b);

	n = ipv4_to_string_buf(ip, p, sz);
	g_assert(n < sz);
	return p;
}

const char *
hostname_port_to_string(const char *hostname, uint16 port)
{
	str_t *s = str_private(G_STRFUNC, 255 + UINT16_DEC_BUFLEN + 2);

	str_printf(s, "%.255s:%u", hostname, port);
	return str_2c(s);
}

size_t
int32_to_string_buf(int32 v, char *dst, size_t size)
{
	char buf[UINT32_DEC_BUFLEN + 1];
	char *p;
	bool neg;

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
int64_to_string_buf(int64 v, char *dst, size_t size)
{
	char buf[UINT64_DEC_BUFLEN + 1];
	char *p;
	bool neg;

	g_assert(0 == size || NULL != dst);
	g_assert(size <= INT_MAX);

	if ((v >= 0 && v <= INT_MAX) || (v < 0 && v >= INT_MIN)) {
		/* 32-bit arithmetic is cheaper for most machines */
		return int32_to_string_buf(v, dst, size);
	}

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
uint32_to_string_buf(uint32 v, char *dst, size_t size)
{
	char buf[UINT32_DEC_BUFLEN];
	char *p;

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
uint64_to_string_buf(uint64 v, char *dst, size_t size)
{
	char buf[UINT64_DEC_BUFLEN];
	char *p;

	if ((uint32) -1 >= v) {
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
uint_to_string_buf(unsigned v, char *dst, size_t size)
{
	char buf[UINT_DEC_BUFLEN];
	char *p;

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
ulong_to_string_buf(unsigned long v, char *dst, size_t size)
{
	char buf[ULONG_DEC_BUFLEN];
	char *p;

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
size_t_to_string_buf(size_t v, char *dst, size_t size)
{
	char buf[SIZE_T_DEC_BUFLEN];
	char *p;

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
pointer_to_string_buf(const void *ptr, char *dst, size_t size)
{
	char buf[POINTER_BUFLEN];
	unsigned long v = pointer_to_ulong(ptr);
	char *p;

	g_assert(0 == size || NULL != dst);
	g_assert(size <= INT_MAX);

	for (p = buf; /* NOTHING */; v /= 16) {
		*p++ = hex_digit(v % 16);
		if (v < 16)
			break;
	}

	/* Add the leading "0x" prefix, accounted for in POINTER_BUFLEN */

	*p++ = 'x';		/* String will be reversed */
	*p++ = '0';

	return reverse_strlcpy(dst, size, buf, p - buf);
}

size_t
fileoffset_t_to_string_buf(fileoffset_t v, char *dst, size_t size)
{
	char buf[OFF_T_DEC_BUFLEN];
	char *p;
	bool neg;

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

const char *
int32_to_string(int32 v)
{
	buf_t *b = buf_private(G_STRFUNC, UINT32_DEC_BUFLEN + 1);
	char *p = buf_data(b);
	size_t n, sz = buf_size(b);

	n = int32_to_string_buf(v, p, sz);
	g_assert(n > 0);
	g_assert(n < sz);
	return p;
}

const char *
uint32_to_string(uint32 v)
{
	buf_t *b = buf_private(G_STRFUNC, UINT32_DEC_BUFLEN);
	char *p = buf_data(b);
	size_t n, sz = buf_size(b);

	n = uint32_to_string_buf(v, p, sz);
	g_assert(n > 0);
	g_assert(n < sz);
	return p;
}

static const char *
int64_to_string_b(int64 v, buf_t *b)
{
	char *p = buf_data(b);
	size_t n, sz = buf_size(b);

	n = int64_to_string_buf(v, p, sz);
	g_assert(n > 0);
	g_assert(n < sz);
	return p;
}

const char *
int64_to_string(int64 v)
{
	buf_t *b = buf_private(G_STRFUNC, UINT64_DEC_BUFLEN + 1);
	return int64_to_string_b(v, b);
}

const char *
int64_to_string2(int64 v)
{
	buf_t *b = buf_private(G_STRFUNC, UINT64_DEC_BUFLEN + 1);
	return int64_to_string_b(v, b);
}

const char *
int64_to_string3(int64 v)
{
	buf_t *b = buf_private(G_STRFUNC, UINT64_DEC_BUFLEN + 1);
	return int64_to_string_b(v, b);
}

const char *
int64_to_string4(int64 v)
{
	buf_t *b = buf_private(G_STRFUNC, UINT64_DEC_BUFLEN + 1);
	return int64_to_string_b(v, b);
}

const char *
int64_to_string5(int64 v)
{
	buf_t *b = buf_private(G_STRFUNC, UINT64_DEC_BUFLEN + 1);
	return int64_to_string_b(v, b);
}

const char *
int64_to_string6(int64 v)
{
	buf_t *b = buf_private(G_STRFUNC, UINT64_DEC_BUFLEN + 1);
	return int64_to_string_b(v, b);
}

const char *
int64_to_string7(int64 v)
{
	buf_t *b = buf_private(G_STRFUNC, UINT64_DEC_BUFLEN + 1);
	return int64_to_string_b(v, b);
}

const char *
int64_to_string8(int64 v)
{
	buf_t *b = buf_private(G_STRFUNC, UINT64_DEC_BUFLEN + 1);
	return int64_to_string_b(v, b);
}

const char *
int64_to_string9(int64 v)
{
	buf_t *b = buf_private(G_STRFUNC, UINT64_DEC_BUFLEN + 1);
	return int64_to_string_b(v, b);
}

const char *
int64_to_string10(int64 v)
{
	buf_t *b = buf_private(G_STRFUNC, UINT64_DEC_BUFLEN + 1);
	return int64_to_string_b(v, b);
}

static const char *
uint64_to_string_b(uint64 v, buf_t *b)
{
	char *p = buf_data(b);
	size_t n, sz = buf_size(b);

	n = uint64_to_string_buf(v, p, sz);
	g_assert(n > 0);
	g_assert(n < sz);
	return p;
}

const char *
uint64_to_string(uint64 v)
{
	buf_t *b = buf_private(G_STRFUNC, UINT64_DEC_BUFLEN);
	return uint64_to_string_b(v, b);
}

const char *
uint64_to_string2(uint64 v)
{
	buf_t *b = buf_private(G_STRFUNC, UINT64_DEC_BUFLEN);
	return uint64_to_string_b(v, b);
}

const char *
uint64_to_string3(uint64 v)
{
	buf_t *b = buf_private(G_STRFUNC, UINT64_DEC_BUFLEN);
	return uint64_to_string_b(v, b);
}

const char *
ulong_to_string(ulong v)
{
	buf_t *b = buf_private(G_STRFUNC, ULONG_DEC_BUFLEN);
	char *p = buf_data(b);
	size_t n, sz = buf_size(b);

	n = ulong_to_string_buf(v, p, sz);
	g_assert(n > 0);
	g_assert(n < sz);
	return p;
}

const char *
uint_to_string(unsigned v)
{
	buf_t *b = buf_private(G_STRFUNC, UINT_DEC_BUFLEN);
	char *p = buf_data(b);
	size_t n, sz = buf_size(b);

	n = uint_to_string_buf(v, p, sz);
	g_assert(n > 0);
	g_assert(n < sz);
	return p;
}

const char *
size_t_to_string(size_t v)
{
	buf_t *b = buf_private(G_STRFUNC, SIZE_T_DEC_BUFLEN);
	char *p = buf_data(b);
	size_t n, sz = buf_size(b);

	n = size_t_to_string_buf(v, p, sz);
	g_assert(n > 0);
	g_assert(n < sz);
	return p;
}

const char *
pointer_to_string(const void *q)
{
	buf_t *b = buf_private(G_STRFUNC, POINTER_BUFLEN);
	char *p = buf_data(b);
	size_t n, sz = buf_size(b);

	n = pointer_to_string_buf(q, p, sz);
	g_assert(n > 0);
	g_assert(n < sz);
	return p;
}

static const char *
filesize_to_string_b(filesize_t v, buf_t *b)
{
	char *p = buf_data(b);
	size_t n, sz = buf_size(b);

	STATIC_ASSERT((filesize_t)-1 <= (uint64)-1);

	n = uint64_to_string_buf(v, p, sz);
	g_assert(n > 0);
	g_assert(n < sz);
	return p;
}

const char *
filesize_to_string(filesize_t v)
{
	buf_t *b = buf_private(G_STRFUNC, FILESIZE_DEC_BUFLEN);
	return filesize_to_string_b(v, b);
}

const char *
filesize_to_string2(filesize_t v)
{
	buf_t *b = buf_private(G_STRFUNC, FILESIZE_DEC_BUFLEN);
	return filesize_to_string_b(v, b);
}

const char *
filesize_to_string3(filesize_t v)
{
	buf_t *b = buf_private(G_STRFUNC, FILESIZE_DEC_BUFLEN);
	return filesize_to_string_b(v, b);
}

const char *
fileoffset_t_to_string(fileoffset_t v)
{
	buf_t *b = buf_private(G_STRFUNC, OFF_T_DEC_BUFLEN);
	char *p = buf_data(b);
	size_t n, sz = buf_size(b);

	n = fileoffset_t_to_string_buf(v, p, sz);
	g_assert(n > 0);
	g_assert(n < sz);
	return p;
}

size_t
int32_to_gstring_buf(int32 v, char *dst, size_t size)
{
	char buf[UINT32_DEC_GRP_BUFLEN + 1];
	char *p;
	bool neg;
	unsigned n;

	g_assert(0 == size || NULL != dst);
	g_assert(size <= INT_MAX);

	p = buf;
	neg = v < 0;
	n = 0;

	do {
		int d = v % 10;

		v /= 10;
		if (0 == n++ % 3 && n != 1)
			*p++ = ',';
		*p++ = dec_digit(neg ? -d : d);
	} while (0 != v);

	if (neg) {
		*p++ = '-';
	}
	return reverse_strlcpy(dst, size, buf, p - buf);
}

size_t
uint32_to_gstring_buf(uint32 v, char *dst, size_t size)
{
	char buf[UINT32_DEC_GRP_BUFLEN];
	char *p;
	unsigned n;

	g_assert(0 == size || NULL != dst);
	g_assert(size <= INT_MAX);

	for (p = buf, n = 0; /* NOTHING */; v /= 10, n++) {
		if (n != 0 && 0 == n % 3)
			*p++ = ',';
		*p++ = dec_digit(v % 10);
		if (v < 10)
			break;
	}

	return reverse_strlcpy(dst, size, buf, p - buf);
}

size_t
int64_to_gstring_buf(int64 v, char *dst, size_t size)
{
	char buf[UINT64_DEC_GRP_BUFLEN + 1];
	char *p;
	bool neg;
	unsigned n;

	g_assert(0 == size || NULL != dst);
	g_assert(size <= INT_MAX);

	if ((v >= 0 && v <= INT_MAX) || (v < 0 && v >= INT_MIN)) {
		/* 32-bit arithmetic is cheaper for most machines */
		return int32_to_gstring_buf(v, dst, size);
	}

	p = buf;
	neg = v < 0;
	n = 0;

	do {
		int64 d = v % 10;

		v /= 10;
		if (0 == n++ % 3 && n != 1)
			*p++ = ',';
		*p++ = dec_digit(neg ? -d : d);
	} while (0 != v);

	if (neg) {
		*p++ = '-';
	}
	return reverse_strlcpy(dst, size, buf, p - buf);
}

size_t
uint64_to_gstring_buf(uint64 v, char *dst, size_t size)
{
	char buf[UINT64_DEC_GRP_BUFLEN];
	char *p;
	unsigned n;

	if ((uint32) -1 >= v) {
		/* 32-bit arithmetic is cheaper for most machines */
		return uint32_to_gstring_buf(v, dst, size);
	}

	g_assert(0 == size || NULL != dst);
	g_assert(size <= INT_MAX);

	for (p = buf, n = 0; /* NOTHING */; v /= 10, n++) {
		if (n != 0 && 0 == n % 3)
			*p++ = ',';
		*p++ = dec_digit(v % 10);
		if (v < 10)
			break;
	}

	return reverse_strlcpy(dst, size, buf, p - buf);
}

size_t
uint_to_gstring_buf(unsigned v, char *dst, size_t size)
{
	char buf[UINT_DEC_GRP_BUFLEN];
	char *p;
	unsigned n;

	g_assert(0 == size || NULL != dst);
	g_assert(size <= INT_MAX);

	for (p = buf, n = 0; /* NOTHING */; v /= 10, n++) {
		if (n != 0 && 0 == n % 3)
			*p++ = ',';
		*p++ = dec_digit(v % 10);
		if (v < 10)
			break;
	}

	return reverse_strlcpy(dst, size, buf, p - buf);
}

size_t
ulong_to_gstring_buf(unsigned long v, char *dst, size_t size)
{
	char buf[ULONG_DEC_GRP_BUFLEN];
	char *p;
	unsigned n;

	g_assert(0 == size || NULL != dst);
	g_assert(size <= INT_MAX);

	for (p = buf, n = 0; /* NOTHING */; v /= 10, n++) {
		if (n != 0 && 0 == n % 3)
			*p++ = ',';
		*p++ = dec_digit(v % 10);
		if (v < 10)
			break;
	}

	return reverse_strlcpy(dst, size, buf, p - buf);
}

size_t
size_t_to_gstring_buf(size_t v, char *dst, size_t size)
{
	char buf[SIZE_T_DEC_GRP_BUFLEN];
	char *p;
	unsigned n;

	g_assert(0 == size || NULL != dst);
	g_assert(size <= INT_MAX);

	for (p = buf, n = 0; /* NOTHING */; v /= 10, n++) {
		if (n != 0 && 0 == n % 3)
			*p++ = ',';
		*p++ = dec_digit(v % 10);
		if (v < 10)
			break;
	}

	return reverse_strlcpy(dst, size, buf, p - buf);
}

const char *
uint32_to_gstring(uint32 v)
{
	buf_t *b = buf_private(G_STRFUNC, UINT32_DEC_GRP_BUFLEN);
	char *p = buf_data(b);
	size_t n, sz = buf_size(b);

	n = uint32_to_gstring_buf(v, p, sz);
	g_assert(n > 0);
	g_assert(n < sz);
	return p;
}

const char *
uint64_to_gstring(uint64 v)
{
	buf_t *b = buf_private(G_STRFUNC, UINT64_DEC_GRP_BUFLEN);
	char *p = buf_data(b);
	size_t n, sz = buf_size(b);

	n = uint64_to_gstring_buf(v, p, sz);
	g_assert(n > 0);
	g_assert(n < sz);
	return p;
}

const char *
uint_to_gstring(unsigned v)
{
	buf_t *b = buf_private(G_STRFUNC, UINT_DEC_GRP_BUFLEN);
	char *p = buf_data(b);
	size_t n, sz = buf_size(b);

	n = uint_to_gstring_buf(v, p, sz);
	g_assert(n > 0);
	g_assert(n < sz);
	return p;
}

const char *
size_t_to_gstring(size_t v)
{
	buf_t *b = buf_private(G_STRFUNC, SIZE_T_DEC_GRP_BUFLEN);
	char *p = buf_data(b);
	size_t n, sz = buf_size(b);

	n = size_t_to_gstring_buf(v, p, sz);
	g_assert(n > 0);
	g_assert(n < sz);
	return p;
}

const char *
filesize_to_gstring(filesize_t v)
{
	buf_t *b = buf_private(G_STRFUNC, FILESIZE_DEC_GRP_BUFLEN);
	char *p = buf_data(b);
	size_t n, sz = buf_size(b);

	STATIC_ASSERT((filesize_t)-1 <= (uint64)-1);

	n = uint64_to_gstring_buf(v, p, sz);
	g_assert(n > 0);
	g_assert(n < sz);
	return p;
}

const char *
uint32_to_string_grp(uint32 v, bool groupped)
{
	buf_t *b = buf_private(G_STRFUNC, UINT32_DEC_GRP_BUFLEN);
	char *p = buf_data(b);
	size_t n, sz = buf_size(b);

	n = groupped ?
		uint32_to_gstring_buf(v, p, sz) : uint32_to_string_buf(v, p, sz);

	g_assert(n > 0);
	g_assert(n < sz);
	return p;
}

const char *
uint64_to_string_grp(uint64 v, bool groupped)
{
	buf_t *b = buf_private(G_STRFUNC, UINT64_DEC_GRP_BUFLEN);
	char *p = buf_data(b);
	size_t n, sz = buf_size(b);

	n = groupped ?
		uint64_to_gstring_buf(v, p, sz) : uint64_to_string_buf(v, p, sz);

	g_assert(n > 0);
	g_assert(n < sz);
	return p;
}

const char *
uint_to_string_grp(uint v, bool groupped)
{
	buf_t *b = buf_private(G_STRFUNC, UINT_DEC_GRP_BUFLEN);
	char *p = buf_data(b);
	size_t n, sz = buf_size(b);

	n = groupped ?
		uint_to_gstring_buf(v, p, sz) : uint_to_string_buf(v, p, sz);

	g_assert(n > 0);
	g_assert(n < sz);
	return p;
}

const char *
size_t_to_string_grp(size_t v, bool groupped)
{
	buf_t *b = buf_private(G_STRFUNC, SIZE_T_DEC_GRP_BUFLEN);
	char *p = buf_data(b);
	size_t n, sz = buf_size(b);

	n = groupped ?
		size_t_to_gstring_buf(v, p, sz) : size_t_to_string_buf(v, p, sz);

	g_assert(n > 0);
	g_assert(n < sz);
	return p;
}

const char *
filesize_to_string_grp(filesize_t v, bool groupped)
{
	buf_t *b = buf_private(G_STRFUNC, FILESIZE_DEC_GRP_BUFLEN);
	char *p = buf_data(b);
	size_t n, sz = buf_size(b);

	STATIC_ASSERT((filesize_t)-1 <= (uint64)-1);

	n = groupped ?
		uint64_to_gstring_buf(v, p, sz) : uint64_to_string_buf(v, p, sz);

	g_assert(n > 0);
	g_assert(n < sz);
	return p;
}

/**
 * @return hexadecimal string representation of "small" binary buffer.
 *
 * @note
 * Buffer must be less than 40 chars, or only the first 40 chars are
 * represented with a trailing "..." added to show it is incomplete.
 */
char *
data_hex_str(const char *data, size_t len)
{
	static const size_t maxlen = 84 - 4; /* 3 chars for "more" + NUL */
	buf_t *b = buf_private(G_STRFUNC, maxlen);
	char *buf = buf_data(b);
	const uint8 *p = cast_to_constpointer(data);
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

	g_assert(i < buf_size(b));

	buf[i] = '\0';
	return buf;
}

static const char escape_char = '\\';

/**
 * Allow spaces, tabs or new-lines as "spacing" chars.
 */
static inline bool
char_is_space(uchar c)
{
	return c == ' ' || c == '\t' || c == '\n';
}

/**
 * Nearly the same as isprint() but allows additional safe chars if !strict.
 */
static inline bool
char_is_safe(uchar c, bool strict)
{
	return isprint(c) || (!strict && char_is_space(c));
}

/**
 * Escape all non-printable chars into the hexadecimal "\xhh" form.
 *
 * @returns new escaped string, or the original string if no escaping occurred.
 * The new string must be freed through hfree().
 */
char *
hex_escape(const char *name, bool strict)
{
	const char *p;
	char *q;
	uchar c;
	int need_escape = 0;
	char *new;

	for (p = name, c = *p++; c; c = *p++)
		if (!char_is_safe(c, strict))
			need_escape++;

	if (need_escape == 0)
		return deconstify_gchar(name);

	new = halloc(p - name + 3 * need_escape);

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
static inline bool
escape_control_char(uchar c)
{
	return is_ascii_cntrl(c) && !char_is_space(c);
}

/**
 * Escape all ASCII control chars except LF into the hexadecimal "\xhh" form.
 * When a CR LF sequence is seen, the CR character is dropped.
 *
 * @returns new escaped string, or the original string if no escaping occurred
 * The new string must be freed through hfree().
 */
char *
control_escape(const char *s)
{
	size_t need_escape = 0;
	const char *p;
	uchar c;

	for (p = s; '\0' != (c = *p); p++)
		if (escape_control_char(c))
			need_escape++;

	if (need_escape > 0) {
		char *q, *escaped;

		q = escaped = halloc(p - s + 1 + 3 * need_escape);

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

static uint
char_to_printf_escape(uchar c, char *esc, const char *safe_chars)
{
	if (!safe_chars) {
		safe_chars = "";
	}
	if (is_ascii_alnum(c) || (c < 0x80 && vstrchr(safe_chars, c))) {
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
const char *
lazy_string_to_printf_escape(const char *src)
{
	char *prev;
	buf_t *b = buf_private(G_STRFUNC, sizeof prev);
	void *bd = buf_data(b);
	static const char safe_chars[] = ".-_";
	const char *s;
	char *p;
	uchar c;
	size_t n;

	/*
	 * The "prev" variable holds the address of the previous allocated string.
	 * Its value is stored in a thread-private buffer, so the lazy pointer is
	 * managed on a pre-thread basis.
	 */

	memcpy(&prev, bd, sizeof prev);		/* Previous value, NULL initially */

	g_assert(src);
	g_assert(src != prev);

	HFREE_NULL(prev);

	for (s = src, n = 0; '\0' != (c = *s); s++)
		n += char_to_printf_escape(c, NULL, safe_chars);

	if (n == (size_t) (s - src))
		return src;

	prev = halloc(n + 1);
	for (s = src, p = prev; '\0' != (c = *s); s++) {
		uint len = char_to_printf_escape(c, p, safe_chars);
		p += len;
	}
	*p = '\0';

	memcpy(bd, &prev, sizeof prev);		/* No VARLEN(): memcpy() may be a macro */
	return NOT_LEAKING(prev);
}

/**
 * @return time spent in seconds in a consise short readable form.
 * @note The returned string may be translated and non-ASCII.
 *
 * @param t		the time to format
 * @param p		the string into which we can format the time
 *
 * @return a pointer to the formatted string.
 */
static const char *
short_time_to_str(time_delta_t t, str_t *p)
{
	uint s = MAX(t, 0);

	if (s > 86400)
		str_printf(p, _("%ud %uh"), s / 86400, (s % 86400) / 3600);
	else if (s > 3600)
		str_printf(p, _("%uh %um"), s / 3600, (s % 3600) / 60);
	else if (s > 60)
		str_printf(p, _("%um %us"), s / 60, s % 60);
	else
		str_printf(p, _("%us"), s);

	return str_2c(p);
}

/**
 * @return time spent in seconds in a consise short readable form.
 * @note The returned string may be translated and non-ASCII.
 */
const char *
short_time(time_delta_t t)
{
	str_t *p = str_private(G_STRFUNC, 4 * SIZE_FIELD_MAX);

	return short_time_to_str(t, p);
}

/**
 * @return time spent in seconds in a consise short readable form.
 * @note The returned string may be translated and non-ASCII.
 */
const char *
short_time2(time_delta_t t)
{
	str_t *p = str_private(G_STRFUNC, 4 * SIZE_FIELD_MAX);

	return short_time_to_str(t, p);
}

/**
 * @return time spent in seconds in a concise short readable form.
 * @note The returned string is in English and ASCII encoded.
 */
const char *
short_time_ascii(time_delta_t t)
{
	str_t *p = str_private(G_STRFUNC, 4 * SIZE_FIELD_MAX);
	uint s;
	const char *m;

	if (t >= 0) {
		s = t;  m = "";
	} else {
		s = -t; m = "-";
	}

	if (s > 86400)
		str_printf(p, "%s%ud %uh", m, s / 86400, (s % 86400) / 3600);
	else if (s > 3600)
		str_printf(p, "%s%uh %um", m, s / 3600, (s % 3600) / 60);
	else if (s > 60)
		str_printf(p, "%s%um %us", m, s / 60, s % 60);
	else
		str_printf(p, "%s%us", m, s);

	return str_2c(p);
}

/**
 * A variant of compact_time(), formatting being done in the supplied buffer.
 *
 * @param t			the elapsed time to format.
 * @param dst		the destination buffer; may be NULL iff ``size'' is zero
 * @param size		the size of ``dst'', in bytes
 *
 * @return The length of the resulting string assuming ``size'' is sufficient.
 */
size_t
compact_time_to_buf(time_delta_t t, char *dst, size_t size)
{
	unsigned s = t < 0 ? -t : t;
	char *m = t < 0 ? "-" : "";
	size_t r;

	if (s > 86400)
		r = str_bprintf(dst, size, "%s%ud%uh",
				m, s / 86400, (s % 86400) / 3600);
	else if (s > 3600)
		r = str_bprintf(dst, size, "%s%uh%um", m, s / 3600, (s % 3600) / 60);
	else if (s > 60)
		r = str_bprintf(dst, size, "%s%um%us", m, s / 60, s % 60);
	else
		r = str_bprintf(dst, size, "%s%us", m, s);

	return r;
}

/**
 * A variant of short_time_ascii() without whitespace.
 *
 * @return time spent in seconds in a concise short readable form.
 * @note The returned string is in English and ASCII encoded, and held in
 * a static buffer.
 */
const char *
compact_time(time_delta_t t)
{
	/*
	 * Because this routine can be called during logging at thread-exit time,
	 * we do not want to create a thread-private value, since it would leak.
	 * Therefore we manage a set of fix-sized strings indexed by thread ID.
	 * The maximum string we can print is "-49710d24h60m60s" or 17 chars.
	 */

#define COMPACT_TIME_MAX_LEN	17

	static char buf[THREAD_MAX][COMPACT_TIME_MAX_LEN];
	int stid = thread_small_id();
	char *p = &buf[stid][0];
	size_t n;

	n = compact_time_to_buf(t, p, COMPACT_TIME_MAX_LEN);
	g_assert(n < COMPACT_TIME_MAX_LEN);
	return p;
}

/**
 * A variant of short_time_ascii() without whitespace.
 *
 * @return time spent in seconds in a concise short readable form.
 * @note The returned string is in English and ASCII encoded, and held in
 * a static buffer.
 */
const char *
compact_time2(time_delta_t t)
{
	buf_t *b = buf_private(G_STRFUNC, COMPACT_TIME_MAX_LEN);
	char *p = buf_data(b);
	size_t n, sz = buf_size(b);

	n = compact_time_to_buf(t, p, sz);
	g_assert(n < sz);
	return p;
}

/**
 * A variant of compact_time(), formatting being done in the supplied buffer.
 *
 * The last figure is displayed in decimal (e.g "4d14.53h".
 *
 * @param t			the elapsed time to format, in ms
 * @param dst		the destination buffer; may be NULL iff ``size'' is zero
 * @param size		the size of ``dst'', in bytes
 *
 * @return The length of the resulting string assuming ``size'' is sufficient.
 */
size_t
compact_time_ms_to_buf(long t, char *dst, size_t size)
{
	long ms = t < 0 ? -t : t;
	long s = ms / 1000;
	char *m = t < 0 ? "-" : "";
	size_t r;

	if (s > 86400)
		r = str_bprintf(dst, size, "%s%lud%.2fh",
				m, s / 86400, (s % 86400) / 3600.0);
	else if (s > 3600)
		r = str_bprintf(dst, size, "%s%luh%.2fm",
				m, s / 3600, (s % 3600) / 60.0);
	else if (s > 60)
		r = str_bprintf(dst, size, "%s%lum%.2fs",
			m, s / 60, (ms - 60000 * (s / 60)) / 1000.0);
	else
		r = str_bprintf(dst, size, "%s%.3fs", m, ms / 1000.0);

	return r;
}

/**
 * A variant of compact_time() with last figure being decimal, and up to
 * the millisecond.
 *
 * @param t		time, in ms
 *
 * @return time spent in seconds in a concise short readable form.
 * @note The returned string is in English and ASCII encoded, and held in
 * a static buffer.
 */
const char *
compact_time_ms(long t)
{
	buf_t *b = buf_private(G_STRFUNC, SIZE_FIELD_MAX);
	char *p = buf_data(b);
	size_t n, sz = buf_size(b);

	n = compact_time_ms_to_buf(t, p, sz);
	g_assert(n < sz);
	return p;
}

/**
 * Alternate time formatter for uptime.
 */
const char *
short_uptime(time_delta_t uptime)
{
	str_t *p = str_private(G_STRFUNC, SIZE_FIELD_MAX);
	uint s = MAX(uptime, 0);

	if (s > 86400) {
		uint32 d = s % 86400;
		str_printf(p, "%ud %02d%c%02d",
			s / 86400, d / 3600, (s & 0x1) ? '.' : ':', (d % 3600) / 60);
	} else {
		uint32 h = s % 3600;
		str_printf(p, "%02d:%02d:%02d", s / 3600, h / 60, h % 60);
	}

	return str_2c(p);
}

size_t
time_t_to_string_buf(time_t v, char *dst, size_t size)
{
	char buf[TIME_T_DEC_BUFLEN];
	char *p;
	bool neg;

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

const char *
time_t_to_string(time_t v)
{
	buf_t *b = buf_private(G_STRFUNC, TIME_T_DEC_BUFLEN);
	char *p = buf_data(b);
	size_t n, sz = buf_size(b);

	n = time_t_to_string_buf(v, p, sz);
	g_assert(n > 0);
	g_assert(n < sz);
	return p;
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
time_locale_to_string_buf(time_t t, char *dst, size_t size)
{
	const struct tm *tm = localtime(&t);
	size_t len;

	g_assert(size > 0);

	len = strftime(dst, size, "%X", tm);
	dst[len] = '\0';

	return len;
}

/**
 * Convert boolean to string.
 *
 * When the value given is not simply TRUE or FALSE, show the actual value,
 * which is of course TRUE.
 *
 * @param b		the boolean value
 */
const char *
bool_to_string(bool v)
{
	if (0 == v)
		return "FALSE";
	else if (1 == v)
		return "TRUE";
	else {
		/* Catch any boolean which is not simply 0 or 1 */
		buf_t *b = buf_private(G_STRFUNC, INT_DEC_BUFLEN + sizeof("TRUE="));
		char *p = buf_data(b);
		size_t sz = buf_size(b);

		/*
		 * We carp to help find the source of the culprit, knowing that
		 * if several booleans are logged in a single formatting call,
		 * only the last value will actually be printed if several have
		 * non TRUE or FALSE values (they all use the same private buffer
		 * to hold the value).
		 */

		s_carp_once("%s(): actual boolean value is %d", G_STRFUNC, v);

		str_bprintf(p, sz, "TRUE=%d", v);	/* Visual indication of weirdness */
		return p;
	}
}

/* vi: set ts=4 sw=4 cindent: */
