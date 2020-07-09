/*
 * Copyright (c) 2011, Raphael Manfredi
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
 * @ingroup core
 * @file
 *
 * Support for IPv6-Ready.
 *
 * @author Raphael Manfredi
 * @date 2011
 */

#ifndef _core_ipv6_ready_h_
#define _core_ipv6_ready_h_

#include "lib/host_addr.h"

/**
 * This address is used by the IPv6-Ready code to signal that the host
 * has no IPv4 address.
 */
#define IPV4_NONE 	0x7f000000U			/* 127.0.0.0/32 */

uint32 ipv6_ready_advertised_ipv4(const host_addr_t addr) G_PURE;
bool ipv6_ready_no_ipv4_addr(const host_addr_t ha) G_CONST;

/**
 * @return whether advertised IPv4 address indicates no IPv4 support.
 */
static inline G_CONST bool
ipv6_ready_has_no_ipv4(const uint32 advertised)
{
	return advertised == IPV4_NONE;
}

#endif /* _core_ipv6_ready_h_ */

/* vi: set ts=4 sw=4 cindent: */
