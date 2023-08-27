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
 * Because Gnutella was originally architected with a 4-byte slot in messages
 * to carry an IPv4 address, servents willing to carry only an IPv6 must flag
 * that IPv4 address with 127.0.0.0, the actual IPv6 address being carried
 * in a GGEP "6" extension.
 *
 * When the IPv4 address is not 127.0.0.0, any GGEP "6" extension simply
 * indicates that the servent sending the message also listens on IPv6.
 *
 * @author Raphael Manfredi
 * @date 2011
 */

#include "common.h"

#include "ipv6-ready.h"

#include "lib/host_addr.h"
#include "lib/override.h"				/* Must be the last header included */

/**
 * Given an IP address to transmit in a legacy IPv4-only field, compute
 * the address to advertise.
 *
 * @return the IPv4 address to advertise.
 */
uint32
ipv6_ready_advertised_ipv4(const host_addr_t ha)
{
	if (NET_TYPE_IPV4 == host_addr_net(ha)) {
		uint32 ipv4 = host_addr_ipv4(ha);
		return IPV4_NONE == ipv4 ? 0 : ipv4;
	} else {
		return IPV4_NONE;
	}
}

/**
 * @return whether advertised IPv4 address indicates no IPv4 support.
 */
bool
ipv6_ready_no_ipv4_addr(const host_addr_t ha)
{
	return host_addr_is_ipv4(ha) && host_addr_ipv4(ha) == IPV4_NONE;
}

/* vi: set ts=4 sw=4 cindent: */

