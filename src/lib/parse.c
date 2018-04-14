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

#include "parse.h"
#include "ascii.h"
#include "misc.h"
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
	g_assert(src != NULL);													\
	g_assert(errorptr != NULL);												\
	g_assert(base >= 2 && base <= 36);										\
																			\
	if G_UNLIKELY(0 == alnum2int_inline('a'))								\
		misc_init();		/* Auto-initialization of alnum2int_inline() */	\
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
	if (endptr != NULL)														\
		*endptr = p;														\
																			\
	*errorptr = error;														\
	return error ? 0 : v;													\
}

#define GENERATE_PARSE_UINTX(bits) \
	GENERATE_PARSE_UNSIGNED(CAT2(parse_uint,bits), CAT2(uint,bits))
GENERATE_PARSE_UINTX(64)
GENERATE_PARSE_UINTX(32)
GENERATE_PARSE_UINTX(16)
GENERATE_PARSE_UINTX(8)

GENERATE_PARSE_UNSIGNED(parse_uint, unsigned int)
GENERATE_PARSE_UNSIGNED(parse_ulong, unsigned long)
GENERATE_PARSE_UNSIGNED(parse_size, size_t)

/**
 * Determine which base the number held in `src' is expressed in.
 *
 * If the number starts with "0x" or "0X", hexadecimal is assumed.
 * If the number starts with "0b" or "0B", binary is assumed.
 * If the number starts with "0", octal is assumed.
 * Otherwise, decimal is assumed if it starts with 1-9.
 *
 * @param src		the number to parse, with leading base indication
 * @param endptr	if non-NULL, set with the start of the number, past base
 *
 * @return the intuited number base, 0 if first character is not a number.
 */
uint
parse_base(const char *src, char const **endptr)
{
	uint base;
	const char *p = src;

	g_assert(src != NULL);

	if ('0' == src[0]) {
		if ('x' == ascii_tolower(src[1])) {
			base = 16;
			p = &src[2];
		} else if ('b' == ascii_tolower(src[1])) {
			base = 2;
			p = &src[2];
		} else if ('\0' == src[1]) {
			base = 10;		/* This is a plain "0" */
		} else {
			base = 8;
			p = &src[1];
		}
	} else if (is_ascii_digit(src[0])) {
		base = 10;
	} else {
		base = 0;
	}


	if (endptr != NULL)
		*endptr = p;

	return base;
}

/**
 * Parse 32-bit value which can be given as decimal, octal (prefix "0"),
 * hexadecimal (prefix "0x" or "OX"), binary (prefix "0b" or "OB").
 *
 * If an error occurs, *errorptr is set with EINVAL or ERANGE, otherwise
 * *errorptr is written with 0.
 *
 * @return the parsed value, 0 meaning possible error (check *errorptr).
 */
uint32
parse_v32(const char *src, char const **endptr, int *errorptr)
{
	uint base;
	const char *start;

	base = parse_base(src, &start);

	if G_UNLIKELY(0 == base) {
		if (endptr != NULL)
			*endptr = src;
		*errorptr = EINVAL;
		return 0;
	}

	return parse_uint32(start, endptr, base, errorptr);
}

/**
 * Parse 64-bit value which can be given as decimal, octal (prefix "0"),
 * hexadecimal (prefix "0x" or "OX"), binary (prefix "0b" or "OB").
 *
 * If an error occurs, *errorptr is set with EINVAL or ERANGE, otherwise
 * *errorptr is written with 0.
 *
 * @return the parsed value, 0 meaning possible error (check *errorptr).
 */
uint64
parse_v64(const char *src, char const **endptr, int *errorptr)
{
	uint base;
	const char *start;

	base = parse_base(src, &start);

	if G_UNLIKELY(0 == base) {
		if (endptr != NULL)
			*endptr = src;
		*errorptr = EINVAL;
		return 0;
	}

	return parse_uint64(start, endptr, base, errorptr);
}

/**
 * Parse a pointer in hexadecimal notation, with optional leading "0x" or "0X".
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
bool
parse_ipv6_addr(const char *s, uint8 *dst, const char **endptr)
{
	const char *p = s;
	uint8 buf[16];
	int i;
	uchar c = 0, last;
	int dc_start = -1;
	int error;
	bool leading_bracket = FALSE;
	bool ok = TRUE;

	g_assert(s != NULL);

	/*
	 * IPv6 address may also be formed like [2001::1].
	 *	-- JA 24/7/2011
	 */

	if ('[' == *s) {
		leading_bracket = TRUE;
		p++;
	}

	for (i = 0; i < 16; /* NOTHING */) {
		const char *ep;
		uint32 v;

		last = c;
		c = *p;

		if (':' == c) {
			if (':' == last) {
				if (dc_start >= 0) {
					/* Second double colon */
					p--; /* Rewind to the really bad colon */
					break;
				}
				dc_start = i;
			}
			p++;
			continue;
		}

		if (!is_ascii_xdigit(c))
			break;		/* "Expected hexdigit" */

		v = parse_uint32(p, &ep, 16, &error);
		if (error || v > 0xffff)
			break;		/* parse_uint32() failed */

		if (*ep == '.' && i <= 12) {
			uint32 ip;

			if (string_to_ip_strict(p, &ip, &ep)) {
				p = ep;
				poke_be32(&buf[i], ip);
				i += 4;
			}
			break;		/* IPv4 found */
		}

		buf[i++] = v >> 8;
		buf[i++] = v & 0xff;

		p = ep;

		if ('\0' == *p)
			break;			/* NUL reached */

		last = 0;
	}

	if (leading_bracket) {
		if (']' == *p) {
			p++;
		} else {
			ok = FALSE;		/* Missing closing ']' */
		}
	}

	if (endptr)
		*endptr = p;

	if (!ok)
		return FALSE;

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
		memcpy(dst, ARYLEN(buf));

	return TRUE;
}

/**
 * Parses a "major.minor" string.
 *
 * @param src		the string to parse.
 * @param endptr	if not NULL, it will point to the next character after
 * 					the parsed address on success. On failure it will point
 *					to the character which caused the failure.
 * @param major		if non-NULL, where the major value is writtten
 * @param minor		if non-NULL, where the minor value is writtten
 *
 * @return 0 if OK, an errno code otherwise.
 */
int
parse_major_minor(const char *src, char const **endptr,
	unsigned *major, unsigned *minor)
{
	const char *ep;
	int error;
	uint32 maj, min;

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
 * @returns 0 if ``s'' is not a valid IPv4 address. Otherwise, the parsed
 * 			IPv4 address in host byte order.
 */
uint32
string_to_ip(const char *s)
{
	uint32 ip;

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
bool
string_to_ip_strict(const char *s, uint32 *addr, const char **endptr)
{
	const char *p = s;
	uint32 a = 0; /* 'pid compiler */
	bool valid;
	int i;

	g_assert(s != NULL);

	if G_UNLIKELY(0 == dec2int_inline('1'))
		misc_init();	/* Auto-initialization of dec2int_inline() */

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
bool
string_to_ip_port(const char *s, uint32 *ip_ptr, uint16 *port_ptr)
{
	const char *ep;
	uint32 v;
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
bool
string_to_ip_and_mask(const char *str, uint32 *ip, uint32 *netmask)
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
		uint32 u;
		int error;

		u = parse_uint32(s, &ep, 10, &error);
		if (error || u < 1 || u > 32 || *ep != '\0')
			return FALSE;

		*netmask = ~0U << (32 - u);
	}
	return TRUE;
}

/* vi: set ts=4 sw=4 cindent: */
