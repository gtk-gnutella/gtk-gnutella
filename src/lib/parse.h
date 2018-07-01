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

#ifndef _parse_h_
#define _parse_h_

uint8 parse_uint8(const char *, char const **, unsigned, int *);
uint16 parse_uint16(const char *, char const **, unsigned, int *);
uint32 parse_uint32(const char *, char const **, unsigned, int *);
uint64 parse_uint64(const char *, char const **, unsigned, int *);
unsigned parse_uint(const char *, char const **, unsigned, int *);
unsigned long parse_ulong(const char *, char const **, unsigned, int *);
size_t parse_size(const char *, char const **, unsigned, int *);
const void *parse_pointer(const char *, char const **, int *)
	NON_NULL_PARAM((1));
bool parse_ipv6_addr(const char *s, uint8_t *dst, const char **endptr);
int parse_major_minor(const char *src, char const **endptr,
	unsigned *major, unsigned *minor);

uint parse_base(const char *src, char const **);
uint32 parse_v32(const char *, char const **, int *) NON_NULL_PARAM((1));
uint64 parse_v64(const char *, char const **, int *) NON_NULL_PARAM((1));

uint32 string_to_ip(const char *);
bool string_to_ip_strict(const char *s, uint32 *addr, const char **ep);
bool string_to_ip_and_mask(const char *str, uint32 *ip, uint32 *netmask);
bool string_to_ip_port(const char *str, uint32 *ip, uint16 *port);
const char *ip_to_string(uint32);
size_t ipv4_to_string_buf(uint32 ip, char *buf, size_t size);
const char *hostname_port_to_string(const char *hostname, uint16 port);

#endif /* _parse_h_ */

/* vi: set ts=4 sw=4 cindent: */
