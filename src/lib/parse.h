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

#ifndef _parse_h_
#define _parse_h_

guint16 parse_uint16(const char *, char const **, unsigned, int *)
	NON_NULL_PARAM((1, 4));
guint32 parse_uint32(const char *, char const **, unsigned, int *)
	NON_NULL_PARAM((1, 4));
guint64 parse_uint64(const char *, char const **, unsigned, int *)
	NON_NULL_PARAM((1, 4));
unsigned parse_uint(const char *, char const **, unsigned, int *)
	NON_NULL_PARAM((1, 4));
unsigned long parse_ulong(const char *, char const **, unsigned, int *)
	NON_NULL_PARAM((1, 4));
size_t parse_size(const char *, char const **, unsigned, int *)
	NON_NULL_PARAM((1, 4));
const void *parse_pointer(const char *, char const **, int *)
	NON_NULL_PARAM((1, 3));
gboolean parse_ipv6_addr(const char *s, uint8_t *dst, const char **endptr)
	NON_NULL_PARAM((1, 3));

guint32  string_to_ip(const char *);
gboolean string_to_ip_strict(const char *s, guint32 *addr, const char **ep);
gboolean string_to_ip_and_mask(const char *str, guint32 *ip, guint32 *netmask);
gboolean string_to_ip_port(const char *str, guint32 *ip, guint16 *port);
const char *ip_to_string(guint32);
size_t ipv4_to_string_buf(guint32 ip, char *buf, size_t size);
const char *hostname_port_to_string(const char *hostname, guint16 port);

#endif /* _parse_h_ */

/* vi: set ts=4 sw=4 cindent: */
