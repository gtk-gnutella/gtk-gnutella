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
#define SIZE_T_DEC_BUFLEN	(sizeof(size_t) * CHAR_BIT) /* very roughly */
#define POINTER_BUFLEN		(sizeof(unsigned long) * CHAR_BIT) /* very roughly */

#define HOST_ADDR_BUFLEN	(MAX(IPV4_ADDR_BUFLEN, IPV6_ADDR_BUFLEN))
#define HOST_ADDR_PORT_BUFLEN	(HOST_ADDR_BUFLEN + sizeof ":[65535]")

size_t int32_to_string_buf(gint32 v, char *dst, size_t size);
size_t uint32_to_string_buf(guint32 v, char *dst, size_t size);
size_t uint64_to_string_buf(guint64 v, char *dst, size_t size);
size_t off_t_to_string_buf(off_t v, char *dst, size_t size);
size_t size_t_to_string_buf(size_t v, char *dst, size_t size);
size_t pointer_to_string_buf(const void *ptr, char *dst, size_t size);
const char *uint32_to_string(guint32);
const char *uint64_to_string(guint64);
const char *uint64_to_string2(guint64);
const char *off_t_to_string(off_t);
const char *size_t_to_string(size_t);
const char *pointer_to_string(const void *);
const char *filesize_to_string(filesize_t);
const char *filesize_to_string2(filesize_t);
const char *ipv6_to_string(const guint8 *ipv6);
size_t ipv6_to_string_buf(const guint8 *ipv6, char *dst, size_t size);

char *hex_escape(const char *name, gboolean strict);
char *control_escape(const char *s);
const char *lazy_string_to_printf_escape(const char *src);

/*
 * Time string conversions
 */
const char *short_time(time_delta_t s);
const char *short_time_ascii(time_delta_t t);
const char *compact_time(time_delta_t t);
const char *short_uptime(time_delta_t s);
size_t time_locale_to_string_buf(time_t date, char *dst, size_t size);
size_t time_t_to_string_buf(time_t v, char *dst, size_t size);
const char *time_t_to_string(time_t);


#endif /* _stringify_h_ */

/* vi: set ts=4 sw=4 cindent: */
