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
 * Stringification routines.
 *
 * @author Raphael Manfredi
 * @date 2008-2009
 * @author Christian Biere
 * @date 2003-2008
 */

#ifndef _stringify_h_
#define _stringify_h_

#include "tm.h"

/*
 * Macros to determine the maximum buffer size required to hold a
 * NUL-terminated string.
 */
#define IPV4_ADDR_BUFLEN	(sizeof "255.255.255.255")
#define IPV6_ADDR_BUFLEN \
	  (sizeof "0001:0203:0405:0607:0809:1011:255.255.255.255")
#define TIMESTAMP_BUFLEN	(sizeof "9999-12-31 23:59:61")

/*
 * How many bytes do we need to stringify an unsigned quantity in decimal
 * form, including the trailing NUL?
 *
 * To represent a decimal number x, one needs 1 + E(log(x)) digits, E(x)
 * being the integer part of x, and log(x) = ln(x) / ln(10)
 *
 * For a power of 2, this becomes:
 *
 * log(2^n) = log(2) * n.
 * log(2) = 0.301029995, which can be approximated by 146/485 (larger value).
 */
#define SIGNED_TYPE(t)	   ((t) -1 < 1)
#define BIT_DEC_BUFLEN(n)  (2 + ((n) * 146) / 485)		/* 2 = 1 + NUL */
#define TYPE_DEC_BUFLEN(t) BIT_DEC_BUFLEN(sizeof(t) * CHAR_BIT + SIGNED_TYPE(t))
#define TYPE_HEX_BUFLEN(t) (1 + sizeof(t) * (CHAR_BIT / 4))

#define GROUPPED_DEC_BUFLEN(t) \
	(TYPE_DEC_BUFLEN(t) + (BIT_DEC_BUFLEN(sizeof(t) * CHAR_BIT)) / 3)

/*
 * The following include space for NUL, too.
 */
#define UINT8_DEC_BUFLEN	TYPE_DEC_BUFLEN(uint8)
#define UINT16_DEC_BUFLEN	TYPE_DEC_BUFLEN(uint16)
#define UINT32_DEC_BUFLEN	TYPE_DEC_BUFLEN(uint32)
#define UINT64_DEC_BUFLEN	TYPE_DEC_BUFLEN(uint64)
#define OFF_T_DEC_BUFLEN	TYPE_DEC_BUFLEN(fileoffset_t)
#define TIME_T_DEC_BUFLEN	TYPE_DEC_BUFLEN(time_t)
#define SIZE_T_DEC_BUFLEN	TYPE_DEC_BUFLEN(size_t)
#define USHRT_DEC_BUFLEN	TYPE_DEC_BUFLEN(unsigned short)
#define UINT_DEC_BUFLEN		TYPE_DEC_BUFLEN(unsigned int)
#define ULONG_DEC_BUFLEN	TYPE_DEC_BUFLEN(unsigned long)
#define FILESIZE_DEC_BUFLEN	TYPE_DEC_BUFLEN(filesize_t)

#define INT_DEC_BUFLEN		TYPE_DEC_BUFLEN(int)
#define LONG_DEC_BUFLEN		TYPE_DEC_BUFLEN(long)

#define UINT8_HEX_BUFLEN	TYPE_HEX_BUFLEN(uint8)
#define UINT16_HEX_BUFLEN	TYPE_HEX_BUFLEN(uint16)
#define UINT32_HEX_BUFLEN	TYPE_HEX_BUFLEN(uint32)
#define UINT64_HEX_BUFLEN	TYPE_HEX_BUFLEN(uint64)
#define ULONG_HEX_BUFLEN	TYPE_HEX_BUFLEN(unsigned long)

#define POINTER_BUFLEN			(TYPE_HEX_BUFLEN(ulong) + sizeof "0x" - 1)
#define HOST_ADDR_BUFLEN		(MAX(IPV4_ADDR_BUFLEN, IPV6_ADDR_BUFLEN))
#define HOST_ADDR_PORT_BUFLEN	(HOST_ADDR_BUFLEN + sizeof ":[65535]")

#define UINT16_DEC_GRP_BUFLEN	GROUPPED_DEC_BUFLEN(uint16)
#define UINT32_DEC_GRP_BUFLEN	GROUPPED_DEC_BUFLEN(uint32)
#define UINT64_DEC_GRP_BUFLEN	GROUPPED_DEC_BUFLEN(uint64)
#define OFF_T_DEC_GRP_BUFLEN	GROUPPED_DEC_BUFLEN(fileoffset_t)
#define TIME_T_DEC_GRP_BUFLEN	GROUPPED_DEC_BUFLEN(time_t)
#define SIZE_T_DEC_GRP_BUFLEN	GROUPPED_DEC_BUFLEN(size_t)
#define USHRT_DEC_GRP_BUFLEN	GROUPPED_DEC_BUFLEN(unsigned short)
#define UINT_DEC_GRP_BUFLEN		GROUPPED_DEC_BUFLEN(unsigned int)
#define ULONG_DEC_GRP_BUFLEN	GROUPPED_DEC_BUFLEN(unsigned long)
#define FILESIZE_DEC_GRP_BUFLEN	GROUPPED_DEC_BUFLEN(filesize_t)

size_t int32_to_string_buf(int32 v, char *dst, size_t size);
size_t uint32_to_string_buf(uint32 v, char *dst, size_t size);
size_t uint64_to_string_buf(uint64 v, char *dst, size_t size);
size_t uint_to_string_buf(unsigned v, char *dst, size_t size);
size_t ulong_to_string_buf(unsigned long v, char *dst, size_t size);
size_t fileoffset_t_to_string_buf(fileoffset_t v, char *dst, size_t size);
size_t size_t_to_string_buf(size_t v, char *dst, size_t size);
size_t pointer_to_string_buf(const void *ptr, char *dst, size_t size);
const char *uint32_to_string(uint32);
const char *uint64_to_string(uint64);
const char *uint64_to_string2(uint64);
const char *uint64_to_string3(uint64);
const char *ulong_to_string(ulong v);
const char *uint_to_string(unsigned v);
const char *fileoffset_t_to_string(fileoffset_t);
const char *size_t_to_string(size_t);
const char *pointer_to_string(const void *);
const char *filesize_to_string(filesize_t);
const char *filesize_to_string2(filesize_t);
const char *filesize_to_string3(filesize_t);
const char *ipv6_to_string(const uint8 *ipv6);
const char *ipv6_to_string2(const uint8 *ipv6);
size_t ipv6_to_string_buf(const uint8 *ipv6, char *dst, size_t size);

char *hex_escape(const char *name, bool strict);
char *control_escape(const char *s);
const char *lazy_string_to_printf_escape(const char *src);

/*
 * Groupped by thousands integer values.
 */

size_t int32_to_gstring_buf(int32 v, char *dst, size_t size);
size_t uint32_to_gstring_buf(uint32 v, char *dst, size_t size);
size_t uint64_to_gstring_buf(uint64 v, char *dst, size_t size);
size_t uint_to_gstring_buf(unsigned v, char *dst, size_t size);
size_t ulong_to_gstring_buf(unsigned long v, char *dst, size_t size);
size_t size_t_to_gstring_buf(size_t v, char *dst, size_t size);
const char *uint32_to_gstring(uint32);
const char *uint64_to_gstring(uint64);
const char *uint_to_gstring(unsigned v);
const char *size_t_to_gstring(size_t v);
const char *filesize_to_gstring(filesize_t v);

/*
 * Optionally groupped by thousands.
 */

const char *uint32_to_string_grp(uint32, bool);
const char *uint64_to_string_grp(uint64, bool);
const char *uint_to_string_grp(unsigned, bool);
const char *size_t_to_string_grp(size_t, bool);
const char *filesize_to_string_grp(filesize_t, bool);

/*
 * Time string conversions
 */
const char *short_time(time_delta_t s);
const char *short_time_ascii(time_delta_t t);
size_t compact_time_to_buf(time_delta_t t, char *dst, size_t size);
const char *compact_time(time_delta_t t);
const char *compact_time2(time_delta_t t);
size_t compact_time_ms_to_buf(long t, char *dst, size_t size);
const char *compact_time_ms(long t);
const char *short_uptime(time_delta_t s);
size_t time_locale_to_string_buf(time_t date, char *dst, size_t size);
size_t time_t_to_string_buf(time_t v, char *dst, size_t size);
const char *time_t_to_string(time_t);

/*
 * Miscellaneous stringifications.
 */

static inline const char *
bool_to_string(const bool v)
{
	return v ? "TRUE" : "FALSE";
}

/* Plural of most words */
static inline const char *
plural(const unsigned long v)
{
	return 1 == v ? "" : "s";
}

/* Plural of words finishing in "y" like "entry" */
static inline const char *
plural_y(const unsigned long v)
{
	return 1 == v ? "y" : "ies";
}

/* Plural of words finishing in "ch" like "match" */
static inline const char *
plural_es(const unsigned long v)
{
	return 1 == v ? "" : "es";
}

/* Plural of words finishing in "f" like "leaf" */
static inline const char *
plural_f(const unsigned long v)
{
	return 1 == v ? "f" : "ves";
}

#endif /* _stringify_h_ */

/* vi: set ts=4 sw=4 cindent: */
