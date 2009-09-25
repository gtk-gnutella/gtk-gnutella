/*
 * $Id$
 *
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
 *      59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *----------------------------------------------------------------------
 */

/**
 * @ingroup lib
 * @file
 *
 * Basic parsing functions.
 *
 * @author Raphael Manfredi
 * @date 2008-2009
 * @author Christian Biere
 * @date 2003-2008
 */

#include "common.h"

RCSID("$Id$")

#include "parse.h"
#include "ascii.h"
#include "endian.h"
#include "override.h"			/* Must be the last header included */

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
NAME(const char *src, char const **endptr, unsigned base, int *errorptr) 	\
{																			\
	const char *p;															\
	TYPE v = 0, mm;															\
	int error = 0;															\
	unsigned d;																\
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

GENERATE_PARSE_UNSIGNED(parse_uint, unsigned int)
GENERATE_PARSE_UNSIGNED(parse_ulong, unsigned long)
GENERATE_PARSE_UNSIGNED(parse_size, size_t)

/**
 * Parse a pointer in hexadecimal notation, with optional leading "Ox" or "0X".
 */
const void *
parse_pointer(const char *src, char const **endptr, int *errorptr)
{
	size_t value;

	if ('0' == src[0] && 'x' == ascii_tolower(src[1])) {
		src += 2;
	}
	value = parse_size(src, endptr, 16, errorptr);
	return (const void *) value;
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
parse_ipv6_addr(const char *s, guint8 *dst, const char **endptr)
{
	guint8 buf[16];
	int i;
	guchar c = 0, last;
	int dc_start = -1;
	int error;

	g_assert(s);

	for (i = 0; i < 16; /* NOTHING */) {
		const char *ep;
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
		int z, n, j;

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
 * @returns 0 if ``s'' is not a valid IPv4 address. Otherwise, the parsed
 * 			IPv4 address in host byte order.
 */
guint32
string_to_ip(const char *s)
{
	guint32 ip;

	s = skip_ascii_spaces(s);
	return string_to_ip_strict(s, &ip, NULL) ? ip : 0;
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
string_to_ip_strict(const char *s, guint32 *addr, const char **endptr)
{
	const char *p = s;
	guint32 a = 0; /* 'pid compiler */
	gboolean valid;
	int i;

	g_assert(s);

	i = 0;
	for (;;) {
		int d, v;
		
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
string_to_ip_port(const char *s, guint32 *ip_ptr, guint16 *port_ptr)
{
	const char *ep;
	guint32 v;
	int error;

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
string_to_ip_and_mask(const char *str, guint32 *ip, guint32 *netmask)
{
	const char *ep, *s = str;

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
		int error;
		
		u = parse_uint32(s, &ep, 10, &error);
		if (error || u < 1 || u > 32 || *ep != '\0')
			return FALSE;

		*netmask = ~0U << (32 - u);
	}
	return TRUE;
}

/* vi: set ts=4 sw=4 cindent: */
