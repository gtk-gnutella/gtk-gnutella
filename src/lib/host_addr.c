/*
 * Copyright (c) 2001-2003, Raphael Manfredi
 * Copyright (c) 2005, Christian Biere
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
 * Host address functions.
 *
 * @author Christian Biere
 * @date 2005
 */

#include "common.h"

#ifdef I_NET_IF
#include <net/if.h>		/* For IFF_* flags */
#endif /* I_NET_IF */

#ifdef I_IFADDRS
#include <ifaddrs.h>	/* For getifaddrs() */
#endif /* I_IFADDRS */

#ifdef I_NETDB
#include <netdb.h>				/* For gethostbyname() */
#endif /* I_NETDB */

#include "host_addr.h"

#include "ascii.h"
#include "concat.h"
#include "endian.h"
#include "glib-missing.h"		/* For g_strlcpy() */
#include "hashing.h"			/* For binary_hash() */
#include "hset.h"
#include "parse.h"
#include "pslist.h"
#include "random.h"
#include "stringify.h"
#include "walloc.h"

#include "override.h"		/* Must be the last header included */

/**
 * Hashing of host_addr_t.
 */
unsigned
host_addr_hash(host_addr_t ha)
{
	switch (ha.net) {
	case NET_TYPE_IPV6:
		{
			host_addr_t ha_ipv4;

			if (!host_addr_convert(ha, &ha_ipv4, NET_TYPE_IPV4))
				return binary_hash(&ha.addr.ipv6[0], sizeof ha.addr.ipv6);
			ha = ha_ipv4;
		}
		/* FALL THROUGH */
	case NET_TYPE_IPV4:
		return ha.net ^ integer_hash_fast(host_addr_ipv4(ha));
	case NET_TYPE_LOCAL:
	case NET_TYPE_NONE:
		return ha.net;
	}
	g_assert_not_reached();
	return (unsigned) -1;
}

/**
 * Alternate hashing of host_addr_t.
 */
unsigned
host_addr_hash2(host_addr_t ha)
{
	switch (ha.net) {
	case NET_TYPE_IPV6:
		{
			host_addr_t ha_ipv4;

			if (!host_addr_convert(ha, &ha_ipv4, NET_TYPE_IPV4))
				return binary_hash2(&ha.addr.ipv6[0], sizeof ha.addr.ipv6);
			ha = ha_ipv4;
		}
		/* FALL THROUGH */
	case NET_TYPE_IPV4:
		return ha.net ^ integer_hash2(host_addr_ipv4(ha));
	case NET_TYPE_LOCAL:
	case NET_TYPE_NONE:
		return ha.net;
	}
	g_assert_not_reached();
	return (unsigned) -1;
}

/**
 * Hashing of host_addr_t + port.
 */
unsigned
host_addr_port_hash(host_addr_t ha, uint16 port)
{
	switch (ha.net) {
	case NET_TYPE_IPV6:
		{
			host_addr_t ha_ipv4;

			if (!host_addr_convert(ha, &ha_ipv4, NET_TYPE_IPV4))
				return binary_hash(&ha.addr.ipv6[0], sizeof ha.addr.ipv6);
			ha = ha_ipv4;
		}
		/* FALL THROUGH */
	case NET_TYPE_IPV4:
		return ha.net + integer_hash_fast(host_addr_ipv4(ha)) + u16_hash(port);
	case NET_TYPE_LOCAL:
	case NET_TYPE_NONE:
		return ha.net + u16_hash(port);
	}
	g_assert_not_reached();
	return (unsigned) -1;
}

/**
 * Alternate hashing of host_addr_t + port.
 */
unsigned
host_addr_port_hash2(host_addr_t ha, uint16 port)
{
	switch (ha.net) {
	case NET_TYPE_IPV6:
		{
			host_addr_t ha_ipv4;

			if (!host_addr_convert(ha, &ha_ipv4, NET_TYPE_IPV4))
				return binary_hash2(&ha.addr.ipv6[0], sizeof ha.addr.ipv6);
			ha = ha_ipv4;
		}
		/* FALL THROUGH */
	case NET_TYPE_IPV4:
		return ha.net + integer_hash2(host_addr_ipv4(ha)) + u16_hash2(port);
	case NET_TYPE_LOCAL:
	case NET_TYPE_NONE:
		return ha.net + u16_hash2(port);
	}
	g_assert_not_reached();
	return (unsigned) -1;
}

/**
 * Check whether hosts are equal.
 */
bool
host_addr_equal(const host_addr_t a, const host_addr_t b)
{
	if (a.net == b.net) {
		switch (a.net) {
		case NET_TYPE_IPV4:
			return host_addr_ipv4(a) == host_addr_ipv4(b);
		case NET_TYPE_IPV6:
			return 0 == memcmp(a.addr.ipv6, b.addr.ipv6, sizeof a.addr.ipv6);
		case NET_TYPE_LOCAL:
		case NET_TYPE_NONE:
			return TRUE;
		}
		g_assert_not_reached();
	}
	return FALSE;
}

/**
 * Check whether hosts are "equivalent", modulo conversion to IPv4 for IPv6.
 *
 * @attention
 * This routine CANNOT be used directly or indirectly as a comparison function
 * for hash tables because it's not possible to have two items being "equal"
 * that do not hash to the same value!  For hash tables, use host_addr_equal()
 * which tests true equality.
 */
bool
host_addr_equiv(const host_addr_t a, const host_addr_t b)
{
	if (a.net == b.net) {
		switch (a.net) {
		case NET_TYPE_IPV4:
			return host_addr_ipv4(a) == host_addr_ipv4(b);
		case NET_TYPE_IPV6:
			if (0 != memcmp(a.addr.ipv6, b.addr.ipv6, sizeof a.addr.ipv6)) {
				host_addr_t a_ipv4, b_ipv4;

				return host_addr_convert(a, &a_ipv4, NET_TYPE_IPV4) &&
					host_addr_convert(b, &b_ipv4, NET_TYPE_IPV4) &&
					host_addr_ipv4(a_ipv4) == host_addr_ipv4(b_ipv4);
			}
			return TRUE;

		case NET_TYPE_LOCAL:
		case NET_TYPE_NONE:
			return TRUE;
		}
		g_assert_not_reached();
	} else {
		host_addr_t to;

		return host_addr_convert(a, &to, b.net) && host_addr_equiv(to, b);
	}
	return FALSE;
}

/**
 * @param ha An initialized host address.
 * @return The proper AF_* value or -1 if not available.
 */
int
host_addr_family(const host_addr_t ha)
{
	if (!host_addr_initialized(ha)) {
		g_error("host_addr_family(): ha.net=%u", (uint8) ha.net);
    }	
	switch (ha.net) {
	case NET_TYPE_IPV4:
		return AF_INET;
	case NET_TYPE_IPV6:
#ifdef HAS_IPV6
		return AF_INET6;
#else
		return -1;
#endif
	case NET_TYPE_LOCAL:
		return AF_LOCAL;
	case NET_TYPE_NONE:
		break;
	}
	return -1;
}

/**
 * Checks for RFC1918 private addresses but also IPv6 link-local and site-local
 * addresses.
 *
 * @return TRUE if is a private address.
 */
bool
is_private_addr(const host_addr_t addr)
{
	host_addr_t addr_ipv4;

	if (host_addr_convert(addr, &addr_ipv4, NET_TYPE_IPV4)) {
		uint32 ip = host_addr_ipv4(addr_ipv4);

		/* 10.0.0.0 -- (10/8 prefix) */
		if ((ip & 0xff000000) == 0xa000000)
			return TRUE;

		/* 172.16.0.0 -- (172.16/12 prefix) */
		if ((ip & 0xfff00000) == 0xac100000)
			return TRUE;

		/* 169.254.0.0 -- (169.254/16 prefix) -- since Jan 2001 */
		if ((ip & 0xffff0000) == 0xa9fe0000)
			return TRUE;

		/* 192.168.0.0 -- (192.168/16 prefix) */
		if ((ip & 0xffff0000) == 0xc0a80000)
			return TRUE;
	} else {

		switch (host_addr_net(addr)) {
		case NET_TYPE_IPV4:
			g_assert_not_reached();
		case NET_TYPE_IPV6:
			return	host_addr_equiv(addr, ipv6_loopback) ||
					host_addr_matches(addr, ipv6_link_local, 10) ||
					host_addr_matches(addr, ipv6_site_local, 10);
		case NET_TYPE_LOCAL:
			return TRUE;
		case NET_TYPE_NONE:
			break;
		}
	}
	return FALSE;
}

static inline bool
ipv4_addr_is_routable(uint32 ip)
{
	static const struct {
		const uint32 addr, mask;
	} net[] = {
		{ 0x00000000UL, 0xff000000UL },	/* 0.0.0.0/8	"This" Network */
		{ 0xe0000000UL, 0xe0000000UL },	/* 224.0.0.0/4	Multicast + Reserved */
		{ 0x7f000000UL,	0xff000000UL },	/* 127.0.0.0/8	Loopback */
		{ 0xc0000200UL, 0xffffff00UL },	/* 192.0.2.0/24	Test-Net [RFC 3330] */
		{ 0xc0586300UL, 0xffffff00UL },	/* 192.88.99.0/24	6to4 [RFC 3068] */
		{ 0xc6120000UL, 0xfffe0000UL },	/* 198.18.0.0/15	[RFC 2544] */
	};
	uint i;

	for (i = 0; i < G_N_ELEMENTS(net); i++) {
		if ((ip & net[i].mask) == net[i].addr)
			return FALSE;
	}

	return TRUE;
}

static inline bool
host_addr_is_6to4(const host_addr_t ha)
{
	return host_addr_is_ipv6(ha) && 0x2002 == peek_be16(&ha.addr.ipv6[0]);
}

static inline bool
host_addr_is_teredo(const host_addr_t ha)
{
	return host_addr_is_ipv6(ha) && 0x20010000UL == peek_be32(&ha.addr.ipv6[0]);
}

static inline uint32
host_addr_6to4_client_ipv4(const host_addr_t ha)
{
	return peek_be32(&ha.addr.ipv6[2]);	/* 2002:AABBCCDD::/48 */
}

static inline uint32
host_addr_teredo_client_ipv4(const host_addr_t ha)
{
	return ~peek_be32(&ha.addr.ipv6[12]);	/* 2001::~A~B~C~D */
}

bool
host_addr_6to4_client(const host_addr_t from, host_addr_t *to)
{
	if (host_addr_is_6to4(from)) {
		if (to) {
			*to = host_addr_get_ipv4(host_addr_6to4_client_ipv4(from));
		}
		return TRUE;
	} else {
		if (to) {
			*to = zero_host_addr;
		}
		return FALSE;
	}
}

bool
host_addr_teredo_client(const host_addr_t from, host_addr_t *to)
{
	if (host_addr_is_teredo(from)) {
		if (to) {
			*to = host_addr_get_ipv4(host_addr_teredo_client_ipv4(from));
		}
		return TRUE;
	} else {
		if (to) {
			*to = zero_host_addr;
		}
		return FALSE;
	}
}

static bool
host_addr_is_tunneled(const host_addr_t ha)
{
	return host_addr_is_teredo(ha) || host_addr_is_6to4(ha);
}

bool
host_addr_tunnel_client(const host_addr_t from, host_addr_t *to)
{
	return host_addr_teredo_client(from, to) || host_addr_6to4_client(from, to);
}

uint32
host_addr_tunnel_client_ipv4(const host_addr_t from)
{
	host_addr_t to;
	(void) host_addr_tunnel_client(from, &to);
	return host_addr_ipv4(to);
}

/**
 * Checks whether the given address is 127.0.0.1 or ::1.
 */
bool
host_addr_is_loopback(const host_addr_t addr)
{
	host_addr_t ha;
	
	if (!host_addr_convert(addr, &ha, NET_TYPE_IPV4))
		ha = addr;
	
	switch (host_addr_net(ha)) {
	case NET_TYPE_IPV4:
		return host_addr_ipv4(ha) == 0x7f000001; /* 127.0.0.1 in host endian */

	case NET_TYPE_IPV6:
		return host_addr_equiv(ha, ipv6_loopback);

	case NET_TYPE_LOCAL:
	case NET_TYPE_NONE:
		break;
	}

	g_assert_not_reached();
	return FALSE;
}

/**
 * Checks whether the given address is unspecified (all zeroes).
 */
bool
host_addr_is_unspecified(const host_addr_t addr)
{
	switch (host_addr_net(addr)) {
	case NET_TYPE_IPV4:
		return host_addr_ipv4(addr) == 0;

	case NET_TYPE_IPV6:
		return host_addr_equiv(addr, ipv6_unspecified);

	case NET_TYPE_LOCAL:
	case NET_TYPE_NONE:
		break;
	}

	g_assert_not_reached();
	return FALSE;
}

/**
 * Check whether host can be reached from the Internet.
 * We rule out IPs of private networks, plus some other invalid combinations.
 */
bool
host_addr_is_routable(const host_addr_t addr)
{
	host_addr_t ha;

	if (!is_host_addr(addr) || is_private_addr(addr))
		return FALSE;

	if (!host_addr_convert(addr, &ha, NET_TYPE_IPV4))
		ha = addr;

	switch (host_addr_net(ha)) {
	case NET_TYPE_IPV4:
		return ipv4_addr_is_routable(host_addr_ipv4(ha));

	case NET_TYPE_IPV6:
		return 	!host_addr_matches(ha, ipv6_unspecified, 8) &&
				!host_addr_matches(ha, ipv6_multicast, 8) &&
				!host_addr_matches(ha, ipv6_site_local, 10) &&
				!host_addr_matches(ha, ipv6_link_local, 10) &&
				!(
						host_addr_is_tunneled(ha) &&
						!ipv4_addr_is_routable(host_addr_tunnel_client_ipv4(ha))
				);

	case NET_TYPE_LOCAL:
	case NET_TYPE_NONE:
		return FALSE;
	}

	g_assert_not_reached();
	return FALSE;
}

bool
host_addr_can_convert(const host_addr_t from, enum net_type to_net)
{
	if (from.net == to_net)
		return TRUE;

	switch (to_net) {
	case NET_TYPE_IPV4:
		switch (from.net) {
		case NET_TYPE_IPV6:
			return host_addr_matches(from, ipv6_ipv4_mapped, 96) ||
					(
					 	0 != from.addr.ipv6[12] &&
					 	host_addr_matches(from, ipv6_unspecified, 96)
					);
		case NET_TYPE_NONE:
			break;
		}
		break;

	case NET_TYPE_IPV6:
		switch (from.net) {
		case NET_TYPE_IPV4:
			return TRUE;
		case NET_TYPE_NONE:
			break;
		}
		break;

	case NET_TYPE_LOCAL:
	case NET_TYPE_NONE:
		break;
	}

	return FALSE;
}

/**
 * Tries to convert the host address "from" to the network type "to_net"
 * and stores the converted address in "*to". If conversion is not possible,
 * FALSE is returned and "*to" is set to zero_host_addr.
 *
 * @param from The address to convert.
 * @param to Will hold the converted address.
 * @param to_net The network type to convert the address to.
 * 
 * @return TRUE if the address could be converted, FALSE otherwise.
 */
bool
host_addr_convert(const host_addr_t from, host_addr_t *to,
	enum net_type to_net)
{
	if (from.net == to_net) {
		*to = from;
		return TRUE;
	}

	switch (to_net) {
	case NET_TYPE_IPV4:
		switch (from.net) {
		case NET_TYPE_IPV6:
			if (host_addr_can_convert(from, NET_TYPE_IPV4)) {
				*to = host_addr_peek_ipv4(&from.addr.ipv6[12]);
				return TRUE;
			}
			break;
		case NET_TYPE_LOCAL:
		case NET_TYPE_NONE:
			break;
		}
		break;

	case NET_TYPE_IPV6:
		switch (from.net) {
		case NET_TYPE_IPV4:
			to->net = to_net;
			memset(to->addr.ipv6, 0, 10);
			to->addr.ipv6[10] = 0xff;
			to->addr.ipv6[11] = 0xff;
			poke_be32(&to->addr.ipv6[12], host_addr_ipv4(from));
			return TRUE;
		case NET_TYPE_NONE:
			break;
		}
		break;

	case NET_TYPE_LOCAL:
	case NET_TYPE_NONE:
		break;
	}

	*to = zero_host_addr;
	return FALSE;
}

/**
 * Prints the host address ``ha'' to ``dst''. The string written to ``dst''
 * is always NUL-terminated unless ``size'' is zero. If ``size'' is too small,
 * the string will be truncated.
 *
 * @param dst the destination buffer; may be NULL iff ``size'' is zero.
 * @param ha the host address.
 * @param size the size of ``dst'' in bytes.
 *
 * @return The length of the resulting string assuming ``size'' is sufficient.
 */
size_t
host_addr_to_string_buf(const host_addr_t ha, char *dst, size_t size)
{
	switch (host_addr_net(ha)) {
	case NET_TYPE_IPV4:
		return ipv4_to_string_buf(host_addr_ipv4(ha), dst, size);
	case NET_TYPE_IPV6:
		return ipv6_to_string_buf(host_addr_ipv6(&ha), dst, size);
	case NET_TYPE_LOCAL:
		return g_strlcpy(dst, "<local>", size);
	case NET_TYPE_NONE:
		return g_strlcpy(dst, "<none>", size);
	}

	g_assert_not_reached();
	return 0;
}

/**
 * Prints the host address ``ha'' to a static buffer.
 *
 * @param ha the host address.
 * @return a pointer to a static buffer holding a NUL-terminated string
 *         representing the given host address.
 */
const char *
host_addr_to_string(const host_addr_t ha)
{
	static char buf[HOST_ADDR_BUFLEN];
	size_t n;

	n = host_addr_to_string_buf(ha, buf, sizeof buf);
	g_assert(n < sizeof buf);
	return buf;
}

/**
 * Same as host_addr_to_string(), but in another static buffer.
 */
const char *
host_addr_to_string2(const host_addr_t ha)
{
	static char buf[HOST_ADDR_BUFLEN];
	size_t n;

	n = host_addr_to_string_buf(ha, buf, sizeof buf);
	g_assert(n < sizeof buf);
	return buf;
}

/**
 * Prints the host address ``ha'' followed by ``port'' to ``dst''. The string
 * written to ``dst'' is always NUL-terminated unless ``size'' is zero. If
 * ``size'' is too small, the string will be truncated.
 *
 * @param dst the destination buffer; may be NULL iff ``size'' is zero.
 * @param ha the host address.
 * @param port the port number.
 * @param size the size of ``dst'' in bytes.
 *
 * @return The length of the resulting string assuming ``size'' is sufficient.
 */
size_t
host_addr_port_to_string_buf(const host_addr_t ha, uint16 port,
		char *dst, size_t size)
{
	char host_buf[HOST_ADDR_BUFLEN];
	char port_buf[UINT32_DEC_BUFLEN];
	size_t n;

	host_addr_to_string_buf(ha, host_buf, sizeof host_buf);
	uint32_to_string_buf(port, port_buf, sizeof port_buf);

	switch (host_addr_net(ha)) {
	case NET_TYPE_IPV6:
		n = concat_strings(dst, size, "[", host_buf, "]:",
				port_buf, (void *) 0);
		break;
	case NET_TYPE_IPV4:
		n = concat_strings(dst, size, host_buf, ":", port_buf, (void *) 0);
		break;
	default:
		n = g_strlcpy(dst, host_buf, size);
	}

	return n;
}

/**
 * Prints the host address ``ha'' followed by ``port'' to a static buffer. 
 *
 * @param ha the host address.
 * @param port the port number.
 *
 * @return a pointer to a static buffer holding a NUL-terminated string
 *         representing the given host address and port.
 */
const char *
host_addr_port_to_string(const host_addr_t ha, uint16 port)
{
	static char buf[HOST_ADDR_PORT_BUFLEN];
	size_t n;

	n = host_addr_port_to_string_buf(ha, port, buf, sizeof buf);
	g_assert(n < sizeof buf);
	return buf;
}

const char *
host_addr_port_to_string2(const host_addr_t ha, uint16 port)
{
	static char buf[HOST_ADDR_PORT_BUFLEN];
	size_t n;

	n = host_addr_port_to_string_buf(ha, port, buf, sizeof buf);
	g_assert(n < sizeof buf);
	return buf;
}

/**
 * Prints the ``port'' followed by host address ``ha'' to ``dst''. The string
 * written to ``dst'' is always NUL-terminated unless ``size'' is zero. If
 * ``size'' is too small, the string will be truncated.
 *
 * @param dst the destination buffer; may be NULL iff ``size'' is zero.
 * @param port the port number.
 * @param ha the host address.
 * @param size the size of ``dst'' in bytes.
 *
 * @return The length of the resulting string assuming ``size'' is sufficient.
 */
size_t
host_port_addr_to_string_buf(uint16 port, const host_addr_t ha,
	char *dst, size_t size)
{
	char port_buf[UINT32_DEC_BUFLEN];
	char host_buf[HOST_ADDR_BUFLEN];
	size_t n;

	uint32_to_string_buf(port, port_buf, sizeof port_buf);
	host_addr_to_string_buf(ha, host_buf, sizeof host_buf);

	switch (host_addr_net(ha)) {
	case NET_TYPE_IPV6:
		n = concat_strings(dst, size, port_buf, ":[", host_buf, "]",
			(void *) 0);
		break;
	case NET_TYPE_IPV4:
		n = concat_strings(dst, size, port_buf, ":", host_buf, (void *) 0);
		break;
	default:
		n = g_strlcpy(dst, host_buf, size);
	}

	return n;
}

/**
 * Prints the host address ``ha'' followed by ``port'' to a static buffer. 
 *
 * @param ha the host address.
 * @param port the port number.
 *
 * @return a pointer to a static buffer holding a NUL-terminated string
 *         representing the given host address and port.
 */
const char *
port_host_addr_to_string(uint16 port, const host_addr_t ha)
{
	static char buf[HOST_ADDR_PORT_BUFLEN];
	size_t n;

	n = host_port_addr_to_string_buf(port, ha, buf, sizeof buf);
	g_assert(n < sizeof buf);
	return buf;
}

const char *
host_port_to_string(const char *hostname, host_addr_t addr, uint16 port)
{
	static char buf[MAX_HOSTLEN + 32];

	if (hostname) {
		char port_buf[UINT32_DEC_BUFLEN];

		uint32_to_string_buf(port, port_buf, sizeof port_buf);
		concat_strings(buf, sizeof buf, hostname, ":", port_buf, (void *) 0);
	} else {
		host_addr_port_to_string_buf(addr, port, buf, sizeof buf);
	}
	return buf;
}

/**
 * Parses IPv4 and IPv6 addresses. The latter requires IPv6 support to be
 * enabled.
 *
 * For convenience, if the first character is '[' then the address is parsed
 * as an IPv6 one and the trailing ']' is both expected and swallowed.  This
 * allows the routine to be used when parsing "ipv4:port" or "[ipv6]:port"
 * strings.
 *
 * @param s The string to parse.
 * @param endptr This will point to the first character after the parsed
 *        address.
 * @param addr_ptr If not NULL, it is set to the parsed host address or
 *        ``zero_host_addr'' on failure.
 * @return Returns TRUE on success; otherwise FALSE.
 */
bool
string_to_host_addr(const char *s, const char **endptr, host_addr_t *addr_ptr)
{
	uint32 ip;
	bool brackets = FALSE;

	g_assert(s);

	if ('[' == *s) {
		brackets = TRUE;
		s++;
	}

	if (!brackets && string_to_ip_strict(s, &ip, endptr)) {
		if (addr_ptr) {
			*addr_ptr = host_addr_get_ipv4(ip);
		}
		return TRUE;
	} else {
		uint8 ipv6[16];
		const char *end;
		bool ok;

		ok = parse_ipv6_addr(s, ipv6, &end);
		if (ok) {
			if (addr_ptr) {
				*addr_ptr = host_addr_peek_ipv6(ipv6);
			}
			if (brackets) {
				if (']' == *end) {
					end++;
				} else {
					ok = FALSE;		/* Trailing ']' required if we had '[' */
				}
			}
		}

		if (endptr != NULL)
			*endptr = end;
		if (ok)
			return TRUE;

		/* FALL THROUGH */
	}

	if (addr_ptr)
		*addr_ptr = zero_host_addr;
	return FALSE;
}

/**
 * Parses the NUL-terminated string ``s'' for a host address or a hostname.
 * If ``s'' points to a parsable address, ``*ha'' will be set to it. Otherwise,
 * ``*ha'' is set to ``zero_host_addr''. If the string is a possible hostname
 * the function returns TRUE nonetheless and ``*endptr'' will point to the
 * first character after hostname.
 *
 * @param s the string to parse.
 * @param endptr if not NULL, it will point the first character after
 *        the parsed host address or hostname.
 * @param ha if not NULL, it is set to the parsed host address or
 *        ``zero_host_addr'' on failure.
 * @return TRUE if the string points to host address or is a possible
 *         hostname.
 */
bool
string_to_host_or_addr(const char *s, const char **endptr, host_addr_t *ha)
{
	const char *ep;
	size_t len;
	host_addr_t addr;

	if (string_to_host_addr(s, endptr, &addr)) {
		if (ha)
			*ha = addr;

		return TRUE;
	}

	for (ep = s; '\0' != *ep; ep++) {
		if (!is_ascii_alnum(*ep) && '.' != *ep && '-' != *ep)
			break;
	}

	if (ha)
		*ha = zero_host_addr;
	if (endptr)
		*endptr = ep;

	len = ep - s;
	return len > 0 && len <= MAX_HOSTLEN;
}

/**
 * Parse "IP:port" string to retrieve the host address and port.
 *
 * @param str		the string to parse
 * @param endptr	if not NULL, it will point the first character after
 * 					the parsed elements.
 * @param addr_ptr	where the parsed address is written
 * @param port_ptr	where the parsed port is written
 *
 * @return TRUE if we parsed the string correctly, FALSE if it did not
 * look like a valid "IP:port" string.
 */
bool
string_to_host_addr_port(const char *str, const char **endptr,
	host_addr_t *addr_ptr, uint16 *port_ptr)
{
	const char *ep;
	host_addr_t addr;
	bool ret;
	uint16 port;

	ret = string_to_host_or_addr(str, &ep, &addr);
	if (ret && ':' == *ep && is_host_addr(addr)) {
		int error;

		ep++;
		port = parse_uint16(ep, &ep, 10, &error);
		ret = 0 == error && 0 != port;
	} else {
		ret = FALSE;
		port = 0;
	}

	if (addr_ptr)
		*addr_ptr = addr;
	if (port_ptr)
		*port_ptr = port;
	if (endptr)
		*endptr = ep;

	return ret;
}

/**
 * Parse "port:IP" string to retrieve the host address and port.
 *
 * @param str		the string to parse
 * @param endptr	if not NULL, it will point the first character after
 * 					the parsed elements.
 * @param port_ptr	where the parsed port is written
 * @param addr_ptr	where the parsed address is written
 *
 * @return TRUE if we parsed the string correctly, FALSE if it did not
 * look like a valid "port:IP" string.
 */
bool
string_to_port_host_addr(const char *str, const char **endptr,
	uint16 *port_ptr, host_addr_t *addr_ptr)
{
	const char *ep;
	host_addr_t addr;
	bool ret;
	uint16 port;
	int error;

	port = parse_uint16(str, &ep, 10, &error);
	if (!error && ':' == *ep) {
		ret = string_to_host_or_addr(ep, &ep, &addr);
		ret = ret && is_host_addr(addr);
	} else {
		addr = zero_host_addr;
		ret = FALSE;
	}

	if (addr_ptr)
		*addr_ptr = addr;
	if (port_ptr)
		*port_ptr = port;
	if (endptr)
		*endptr = ep;

	return ret;
}

#ifndef HAS_GETNAMEINFO
static void
gethostbyname_error(const char *host)
{
#if defined(HAS_HSTRERROR)
		g_warning("cannot resolve \"%s\": %s", host, hstrerror(h_errno));
#elif defined(HAS_HERROR)
		g_warning("cannot resolve \"%s\":", host);
		herror("gethostbyname()");
#else
		g_warning("cannot resolve \"%s\": gethostbyname() failed!", host);
#endif /* defined(HAS_HSTRERROR) */
}
#endif	/* !HAS_GETNAMEINFO */

/**
 * Initializes sa_ptr from a host address and a port number.
 *
 * @param addr The host address.
 * @param port The port number.
 * @param sa_ptr a pointer to a socket_addr_t
 *
 * @return The length of the initialized structure.
 */
socklen_t
socket_addr_set(socket_addr_t *sa_ptr, const host_addr_t addr, uint16 port)
{
	switch (host_addr_net(addr)) {
	case NET_TYPE_IPV4:
		if (sa_ptr) {
			static const struct sockaddr_in zero_sin;

			sa_ptr->inet4 = zero_sin;
#ifdef HAS_SOCKADDR_IN_SIN_LEN
			sa_ptr->inet4.sin_len = sizeof sa_ptr->inet4;
#endif /* HAS_SOCKADDR_IN_SIN_LEN */
			sa_ptr->inet4.sin_family = AF_INET;
			sa_ptr->inet4.sin_port = htons(port);
			sa_ptr->inet4.sin_addr.s_addr = htonl(host_addr_ipv4(addr));
		}
		return sizeof sa_ptr->inet4;
	case NET_TYPE_IPV6:
#ifdef HAS_IPV6
		if (sa_ptr) {
			static const struct sockaddr_in6 zero_sin6;

			sa_ptr->inet6 = zero_sin6;
#ifdef SIN6_LEN
			sa_ptr->inet6.sin6_len = sizeof sa_ptr->inet6;
#endif /* SIN6_LEN */
			sa_ptr->inet6.sin6_family = AF_INET6;
			sa_ptr->inet6.sin6_port = htons(port);
			memcpy(sa_ptr->inet6.sin6_addr.s6_addr, addr.addr.ipv6, 16);
		}
		return sizeof sa_ptr->inet6;
#endif	/* HAS_IPV6 */
	case NET_TYPE_LOCAL:
	case NET_TYPE_NONE:
		if (sa_ptr) {
			static const socket_addr_t zero_sa;
			*sa_ptr = zero_sa;
		}
		return 0;
	}
	g_assert_not_reached();
	return 0;
}

socklen_t
socket_addr_init(socket_addr_t *sa_ptr, enum net_type net)
{
	switch (net) {
	case NET_TYPE_IPV4:
		return socket_addr_set(sa_ptr, ipv4_unspecified, 0);
	case NET_TYPE_IPV6:
#ifdef HAS_IPV6
		return socket_addr_set(sa_ptr, ipv6_unspecified, 0);
#endif
	case NET_TYPE_LOCAL:
	case NET_TYPE_NONE:
		break;
	}
	return 0;
}

/**
 * Fill `p_addr' with the socket's local address/port information.
 */
int
socket_addr_getsockname(socket_addr_t *p_addr, int fd)
{
	struct sockaddr_in sin4;
	socklen_t len;
	host_addr_t addr = zero_host_addr;
	uint16 port = 0;
	bool success = FALSE;

	len = sizeof sin4;
	if (-1 != getsockname(fd, cast_to_pointer(&sin4), &len)) {
		addr = host_addr_peek_ipv4(&sin4.sin_addr.s_addr);
		port = ntohs(sin4.sin_port);
		success = TRUE;
	}

#ifdef HAS_IPV6
	if (!success) {
		struct sockaddr_in6 sin6;

		len = sizeof sin6;
		if (-1 != getsockname(fd, cast_to_pointer(&sin6), &len)) {
			addr = host_addr_peek_ipv6(sin6.sin6_addr.s6_addr);
			port = ntohs(sin6.sin6_port);
			success = TRUE;
		}
	}
#endif	/* HAS_IPV6 */

	if (success) {
		socket_addr_set(p_addr, addr, port);
	}
	return success ? 0 : -1;
}

/**
 * Fill `p_addr' with socket's remote address/port information.
 */
int
socket_addr_getpeername(socket_addr_t *p_addr, int fd)
{
	socklen_t addr_len;

	g_return_val_if_fail(p_addr, -1);
	g_return_val_if_fail(fd >= 0, -1);

	errno = 0;
	addr_len = socket_addr_init(p_addr, NET_TYPE_IPV4);
	if (
		-1 != getpeername(fd, socket_addr_get_sockaddr(p_addr), &addr_len) &&
		AF_INET == socket_addr_get_family(p_addr)
	) {
		return 0;
	}

#ifdef HAS_IPV6
	errno = 0;
	addr_len = socket_addr_init(p_addr, NET_TYPE_IPV6);
	if (
		-1 != getpeername(fd, socket_addr_get_sockaddr(p_addr), &addr_len) &&
		AF_INET6 == socket_addr_get_family(p_addr)
	) {
		return 0;
	}
#endif	/* HAS_IPV6 */

	return -1;
}

/**
 * Mask out given address, clearing the trailing v4 or v6 bits, depending
 * on the address type.
 *
 * @param addr		the address to mask out
 * @param v4		amount of trailing bits to mask out for IPv4 address
 * @param v6		amount of trailing bits to mask out for IPv6 address
 *
 * @return masked out address, possibly converted from IPv6 to IPv4.
 */
host_addr_t
host_addr_mask_net(host_addr_t addr, int v4, int v6)
{
	host_addr_t masked = addr;

	g_assert(v4 >= 0 && v4 <= 32);
	g_assert(v6 >= 0 && v6 <= 128);

	if (host_addr_can_convert(addr, NET_TYPE_IPV4))
		(void) host_addr_convert(addr, &masked, NET_TYPE_IPV4);

	switch (host_addr_net(addr)) {
	case NET_TYPE_IPV4:
		if (32 == v4)
			masked.addr.ipv4 = 0;
		else
			masked.addr.ipv4 &= ~((1U << v4) - 1);
		break;
	case NET_TYPE_IPV6:
		{
			int bytes = v6 / 8;			/* Amount of trailing bytes to clear */
			int bits = v6 % 8;			/* Trailing bits in upper byte */
			int i;

			for (i = 0; i < bytes; i++) {
				masked.addr.ipv6[15 - i] = 0;
			}
			masked.addr.ipv6[15 - bytes] &= ~((1U << bits) - 1);
		}
		break;
	case NET_TYPE_LOCAL:
	case NET_TYPE_NONE:
		break;
	}

	return masked;
}

/**
 * Resolves an IP address to a hostname per DNS.
 *
 * @param ha	The host address to resolve.
 * @return		On success, the hostname is returned. Otherwise, NULL is
 *				returned. The resulting string points to a static buffer.
 */
const char *
host_addr_to_name(host_addr_t addr)
{
	socket_addr_t sa;

	if (host_addr_can_convert(addr, NET_TYPE_IPV4)) {
		(void) host_addr_convert(addr, &addr, NET_TYPE_IPV4);
	}
	if (0 == socket_addr_set(&sa, addr, 0)) {
		return NULL;
	}

#ifdef HAS_GETNAMEINFO
	{
		static char host[1025];
		int error;

		error = getnameinfo(socket_addr_get_const_sockaddr(&sa),
					socket_addr_get_len(&sa), host, sizeof host, NULL, 0, 0);
		if (error) {
			char buf[HOST_ADDR_BUFLEN];

			host_addr_to_string_buf(addr, buf, sizeof buf);
			g_message("getnameinfo() failed for \"%s\": %s",
				buf, gai_strerror(error));
			return NULL;
		}
		return host;
	}
#else	/* !HAS_GETNAMEINFO */
	{
		const struct hostent *he;
		socklen_t len = 0;
		const char *ptr = NULL;

		switch (host_addr_net(addr)) {
		case NET_TYPE_IPV4:
			ptr = cast_to_gchar_ptr(&sa.inet4.sin_addr);
			len = sizeof sa.inet4.sin_addr;
			break;
		case NET_TYPE_IPV6:
#ifdef HAS_IPV6
			ptr = cast_to_gchar_ptr(&sa.inet6.sin6_addr);
			len = sizeof sa.inet6.sin6_addr;
			break;
#endif /* HAS_IPV6 */
		case NET_TYPE_LOCAL:
		case NET_TYPE_NONE:
			return NULL;
		}
		g_return_val_if_fail(ptr, NULL);
		g_return_val_if_fail(0 != len, NULL);

		he = gethostbyaddr(ptr, len, socket_addr_get_family(&sa));
		if (!he) {
			char buf[HOST_ADDR_BUFLEN];

			host_addr_to_string_buf(addr, buf, sizeof buf);
			gethostbyname_error(buf);
			return NULL;
		}
		return he->h_name;
	}
#endif	/* HAS_GETNAMEINFO */
}

#ifdef HAS_GETADDRINFO
host_addr_t
addrinfo_to_addr(const struct addrinfo *ai)
{
	host_addr_t addr = zero_host_addr;

	switch (ai->ai_family) {
	case PF_INET:
		if (ai->ai_addrlen >= 4) {
			const struct sockaddr_in *sin4;

			sin4 = cast_to_constpointer(ai->ai_addr);
			addr = host_addr_peek_ipv4(&sin4->sin_addr.s_addr);
		}
		break;

#ifdef HAS_IPV6
	case PF_INET6:
		if (ai->ai_addrlen >= 16) {
			const struct sockaddr_in6 *sin6;

			sin6 = cast_to_constpointer(ai->ai_addr);
			addr = host_addr_peek_ipv6(cast_to_constpointer(
						sin6->sin6_addr.s6_addr));
		}
		break;
#endif /* HAS_IPV6 */
	}

	return addr;
}
#endif	/* HAS_GETADDRINFO */

static pslist_t *
resolve_hostname(const char *host, enum net_type net)
#ifdef HAS_GETADDRINFO
{
	static const struct addrinfo zero_hints;
	struct addrinfo hints, *ai, *ai0 = NULL;
	hset_t *hs;
	pslist_t *sl_addr;
	int error;

	g_assert(host);
	
	hints = zero_hints;
	hints.ai_family = net_type_to_pf(net);

	error = getaddrinfo(host, NULL, &hints, &ai0);
	if (error) {
		g_message("getaddrinfo() failed for \"%s\": %s",
				host, gai_strerror(error));
		return NULL;
	}

	sl_addr = NULL;
	hs = hset_create_any(host_addr_hash_func, NULL, host_addr_eq_func);
	for (ai = ai0; ai; ai = ai->ai_next) {
		host_addr_t addr;

		if (!ai->ai_addr)
			continue;

		addr = addrinfo_to_addr(ai);

		if (is_host_addr(addr) && !hset_contains(hs, &addr)) {
			host_addr_t *addr_copy;

			addr_copy = wcopy(&addr, sizeof addr);
			sl_addr = pslist_prepend(sl_addr, addr_copy);
			hset_insert(hs, addr_copy);
		}
	}
	hset_free_null(&hs);

	if (ai0)
		freeaddrinfo(ai0);

	return pslist_reverse(sl_addr);
}
#else /* !HAS_GETADDRINFO */
{
	const struct hostent *he;
	hset_t *hs;
	pslist_t *sl_addr;
	int af;
	size_t i;

	g_assert(host);
   	he = gethostbyname(host);
	if (!he) {
		gethostbyname_error(host);
		return NULL;
	}
	if (!he->h_addr_list)
		return NULL;

	af = net_type_to_af(net);
	if (af != he->h_addrtype && af != AF_UNSPEC)
		return NULL;

	switch (he->h_addrtype) {
	case AF_INET:
		if (4 != he->h_length) {
			g_warning("%s(): wrong length %d for IPv4 address \"%s\"",
				G_STRFUNC, he->h_length, host);
			return NULL;
		}
		break;
		
#ifdef HAS_IPV6
	case AF_INET6:
		if (16 != he->h_length) {
			g_warning("%s(): wrong length %d for IPv6 address \"%s\"",
				G_STRFUNC, he->h_length, host);
			return NULL;
		}
		break;
#endif /* HAS_IPV6 */
		
	default:
		return NULL;
	}
	
	sl_addr = NULL;
	hs = hset_create_any(host_addr_hash_func, NULL, host_addr_eq_func);
	for (i = 0; NULL != he->h_addr_list[i]; i++) {
		host_addr_t addr;

		switch (he->h_addrtype) {
		case AF_INET:
			addr = host_addr_peek_ipv4(&he->h_addr_list[i]);
			break;

#ifdef HAS_IPV6
		case AF_INET6:
			addr = host_addr_peek_ipv6(
						cast_to_constpointer(he->h_addr_list[i]));
			break;
#endif /* !HAS_IPV6 */
		default:
			g_assert_not_reached();
		}

		if (is_host_addr(addr) && !hset_contains(hs, &addr)) {
			host_addr_t *addr_copy;

			addr_copy = wcopy(&addr, sizeof addr);
			sl_addr = pslist_prepend(sl_addr, addr_copy);
			hset_insert(hs, addr_copy);
		}
	}
	hset_free_null(&hs);

	return pslist_reverse(sl_addr);
}
#endif /* HAS_GETADDRINFO */

/**
 * Resolves a hostname to IP addresses per DNS.
 *
 * This returns a list of IP addresses (containing "host_addr_t *" values)
 * that must be freed by the caller using host_addr_free_list().
 *
 * @param host	A NUL-terminated string holding the hostname to resolve.
 * @param net	Use NET_TYPE_IPV4 if you want only IPv4 addresses or like-wise
 *				NET_TYPE_IPV6. If you don't care, use NET_TYPE_NONE.
 *
 * @return a single-linked list of walloc()ated host_addr_t on success or
 * NULL on failure.
 */
pslist_t *
name_to_host_addr(const char *host, enum net_type net)
{
	const char *endptr;
	host_addr_t addr;
	
	g_assert(host);

	/* As far as I know, some broken implementations won't resolve numeric
	 * addresses although getaddrinfo() must support exactly this for protocol
	 * independence. gethostbyname() implementations won't do this especially
	 * not for IPv6 although some support IPv6.
	 */

	if (string_to_host_addr(host, &endptr, &addr) && '\0' == *endptr) {
		return pslist_append(NULL, wcopy(&addr, sizeof addr));
	}

	return resolve_hostname(host, net);
}

/**
 * Frees a singly-linked list of host_addr_t elements.
 */
void
host_addr_free_list(pslist_t **sl_ptr)
{
	g_assert(sl_ptr);

	if (*sl_ptr) {
		pslist_t *sl;

		PSLIST_FOREACH(*sl_ptr, sl) {
			host_addr_t *addr_ptr = sl->data;
			WFREE(addr_ptr);
		}
		pslist_free_null(sl_ptr);
	}
}

/**
 * Resolves a hostname to an IP address per DNS. This is the same as
 * name_to_host_addr() but we pick a random item from the result list
 * and return it.
 */
host_addr_t
name_to_single_host_addr(const char *host, enum net_type net)
{
	pslist_t *sl_addr;
	host_addr_t addr;
	
	addr = zero_host_addr;
	sl_addr = name_to_host_addr(host, net);
	if (sl_addr) {
		size_t i, len;
		const host_addr_t *addr_ptr;

		len = pslist_length(sl_addr);
		i = len > 1 ? random_value(len - 1) : 0;
		addr_ptr = pslist_nth_data(sl_addr, i);
		g_assert(addr_ptr != NULL);
		addr = *addr_ptr;

		host_addr_free_list(&sl_addr);
	}

	return addr;
}

uint
host_addr_hash_func(const void *key)
{
	const host_addr_t *addr = key;
	return host_addr_hash(*addr);
}

uint
host_addr_hash_func2(const void *key)
{
	const host_addr_t *addr = key;
	return host_addr_hash2(*addr);
}

bool
host_addr_eq_func(const void *p, const void *q)
{
	const host_addr_t *a = p, *b = q;
	return host_addr_equiv(*a, *b);
}

/**
 * List free callback.
 */
void
wfree_host_addr1(void *key)
{
	wfree(key, sizeof(host_addr_t));
}

/**
 * Aging table callback.
 */
void
wfree_host_addr(void *key, void *unused_data)
{
	(void) unused_data;
	wfree(key, sizeof(host_addr_t));
}

/**
 * @return	A list of all IPv4 and IPv6 addresses assigned to interfaces
 *			of the machine.
 */
pslist_t *
host_addr_get_interface_addrs(const enum net_type net)
#if defined(HAS_GETIFADDRS)
{
	struct ifaddrs *ifa0, *ifa;
	pslist_t *sl_addrs = NULL;

	if (0 != getifaddrs(&ifa0)) {
		return NULL;
	}

	for (ifa = ifa0; ifa != NULL; ifa = ifa->ifa_next) {
		host_addr_t addr;

		if (NULL == ifa->ifa_addr)
			continue;
		if ((IFF_LOOPBACK & ifa->ifa_flags)) /* skip loopback interfaces */
			continue;
		if (0 == (IFF_UP & ifa->ifa_flags)) /* interface down */
			continue;
		if (0 == (IFF_RUNNING & ifa->ifa_flags)) /* interface not running */
			continue;
		if (NULL == ifa->ifa_netmask) /* no netmask */
			continue;

		if (AF_INET == ifa->ifa_addr->sa_family) {
            const struct sockaddr_in *sin4;
			
			sin4 = cast_to_constpointer(ifa->ifa_addr);
			addr = host_addr_peek_ipv4(&sin4->sin_addr.s_addr);
#ifdef HAS_IPV6
		} else if (AF_INET6 == ifa->ifa_addr->sa_family) {
            const struct sockaddr_in6 *sin6;

			sin6 = cast_to_constpointer(ifa->ifa_addr);
			addr = host_addr_peek_ipv6(sin6->sin6_addr.s6_addr);
#endif /* HAS_IPV6 */
		} else {
			addr = zero_host_addr;
		}

		if (
			(NET_TYPE_NONE == net || host_addr_net(addr) == net) &&
			is_host_addr(addr)
		) {
			sl_addrs = pslist_prepend(sl_addrs, wcopy(&addr, sizeof addr));
		}
	}

	freeifaddrs(ifa0);
	return pslist_reverse(sl_addrs);
}
#else	/* !HAS_GETIFADDRS */
{
	(void) net;
	return NULL;
}
#endif	/* HAS_GETIFADDRS */

/**
 * Frees a list along with its item returned by
 * host_addr_get_interface_addrs() and nullifies the given pointer.
 */
void
host_addr_free_interface_addrs(pslist_t **sl_ptr)
{
	g_assert(sl_ptr);
	if (*sl_ptr) {
		pslist_t *sl;

		PSLIST_FOREACH(*sl_ptr, sl) {
            host_addr_t *addr = sl->data;
			g_assert(host_addr_initialized(*addr));
			WFREE(addr);
		}
		pslist_free_null(sl_ptr);
	}
}

struct packed_host_addr
host_addr_pack(const host_addr_t addr)
{
	static struct packed_host_addr zero_paddr;
	struct packed_host_addr paddr;
	enum net_type net;

	paddr = zero_paddr;			/* Shut compiler warning up */
	net = host_addr_net(addr);
	switch (net) {
	case NET_TYPE_IPV4:
		poke_be32(paddr.addr, host_addr_ipv4(addr));
		break;
	case NET_TYPE_IPV6:
		memcpy(paddr.addr, host_addr_ipv6(&addr), sizeof addr.addr.ipv6);
		break;
	case NET_TYPE_LOCAL:
	case NET_TYPE_NONE:
		break;
	default:
		net = NET_TYPE_NONE;
		g_assert_not_reached();
	}
	paddr.net = net;
	return paddr;
}

host_addr_t
packed_host_addr_unpack(const struct packed_host_addr paddr)
{
	switch (paddr.net) {
	case NET_TYPE_IPV4:
		return host_addr_peek_ipv4(paddr.addr);
	case NET_TYPE_IPV6:
		return host_addr_peek_ipv6(paddr.addr);
	case NET_TYPE_LOCAL:
		return local_host_addr;
	case NET_TYPE_NONE:
		return zero_host_addr;
	}
	g_assert_not_reached();
	return zero_host_addr;
}

host_addr_t
packed_host_addr_unpack_ptr(const struct packed_host_addr *paddr)
{
	g_assert(paddr != NULL);

	switch (paddr->net) {
	case NET_TYPE_IPV4:
		return host_addr_peek_ipv4(&paddr->addr[0]);
	case NET_TYPE_IPV6:
		return host_addr_peek_ipv6(paddr->addr);
	case NET_TYPE_LOCAL:
		return local_host_addr;
	case NET_TYPE_NONE:
		return zero_host_addr;
	}
	g_assert_not_reached();
	return zero_host_addr;
}

/**
 * Significant size of a packed host_addr (serialization size).
 */
uint
packed_host_addr_size_ptr(const struct packed_host_addr *paddr)
{
	switch (paddr->net) {
	case NET_TYPE_IPV4:	 return 1 + 4;
	case NET_TYPE_IPV6:  return 1 + 16;
	case NET_TYPE_LOCAL: return 1;
	case NET_TYPE_NONE:	 return 1;
	}
	g_assert_not_reached();
	return 0;
}

uint
packed_host_addr_size(const struct packed_host_addr paddr)
{
	return packed_host_addr_size_ptr(&paddr);
}

struct packed_host
host_pack(const host_addr_t addr, uint16 port)
{
	struct packed_host phost;

	phost.ha = host_addr_pack(addr);
	poke_be16(&phost.port, port);
	return phost;
}

G_GNUC_HOT void
packed_host_unpack_addr(
	const struct packed_host *phost,	/* MUST be a pointer */
	host_addr_t *addr_ptr)
{
	g_assert(phost != NULL);

	switch (phost->ha.net) {
	case NET_TYPE_IPV4:
		if (addr_ptr) {
			/*
			 * Compiler hack alert!
			 * 
			 * Ensure generated code will NEVER try to access the whole array
			 * since only the necessary bytes may have been allocated to hold
			 * the packed representation! When "phost->ha.addr" causes a
			 * memory fault if the structure is tighly allocated, taking the
			 * address of the first byte alleviates all problems since we
			 * know host_addr_peek_ipv4() will behave sanely with the pointer
			 * it is passed and will not try to access beyond the size of
			 * the expected IPv4 address.
			 *
			 *		--RAM, 2011-05-03
			 */
			*addr_ptr = host_addr_peek_ipv4(&phost->ha.addr[0]);
		}
		return;
	case NET_TYPE_IPV6:
		if (addr_ptr) {
			*addr_ptr = host_addr_peek_ipv6(phost->ha.addr);
		}
		return;
	case NET_TYPE_LOCAL:
		if (addr_ptr) {
			*addr_ptr = local_host_addr;
		}
		return;
	case NET_TYPE_NONE:
		if (addr_ptr) {
			*addr_ptr = zero_host_addr;
		}
		return;
	}
	/*
	 * Because this routine can be used through gnet_host_get_addr() to grab
	 * the address from a packed structure coming from a DBMW file, we cannot
	 * abort the execution when faced with an invalid structure (coming from
	 * the disk).
	 */
	g_carp("corrupted packed host: unknown net address type %d", phost->ha.net);
	*addr_ptr = zero_host_addr;
}

/**
 * Significant size of a packed host (serialization size), given by address.
 */
static inline uint
packed_host_size_ptr(const struct packed_host *phost)
{
	switch (phost->ha.net) {
	case NET_TYPE_IPV4:	 return 1 + 4 + 2;
	case NET_TYPE_IPV6:  return 1 + 16 + 2;
	case NET_TYPE_LOCAL: return 1 + 2;
	case NET_TYPE_NONE:	 return 1 + 2;
	}
	g_assert_not_reached();
	return 0;
}

/**
 * Significant size of a packed host (serialization size).
 */
uint
packed_host_size(const struct packed_host phost)
{
	return packed_host_size_ptr(&phost);
}

/***
 *** The following routines are meant to be used for hash tables indexed
 *** by packed_host structures, which are variable-sized entities.
 ***/

/**
 * Hash a packed host buffer (variable-sized).
 */
uint
packed_host_hash_func(const void *key)
{
	const struct packed_host *p = key;
	return binary_hash(key, packed_host_size_ptr(p));
}

/**
 * Alternate hash for a packed host buffer (variable-sized).
 */
uint
packed_host_hash_func2(const void *key)
{
	const struct packed_host *p = key;
	return binary_hash2(key, packed_host_size_ptr(p));
}

/**
 * Compare two packed host buffers (variable-sized).
 */
bool
packed_host_eq_func(const void *p, const void *q)
{
	const struct packed_host *a = p, *b = q;
	uint asize = packed_host_size_ptr(a);
	uint bsize = packed_host_size_ptr(b);

	if (asize != bsize)
		return FALSE;

	return 0 == memcmp(a, b, asize);
}

/**
 * Allocate a packed_host key.
 */
void *
walloc_packed_host(const host_addr_t addr, uint16 port)
{
	struct packed_host packed = host_pack(addr, port);

	return wcopy(&packed, packed_host_size_ptr(&packed));
}

/**
 * Release packed_host key.
 */
void
wfree_packed_host(void *key, void *unused_data)
{
	const struct packed_host *p = key;

	(void) unused_data;

	wfree(key, packed_host_size_ptr(p));
}

/***
 *** The following routines are meant to be used for hash tables indexed
 *** by packed_host_addr structures, which are variable-sized entities.
 ***/

/**
 * Hash a packed host_addr buffer (variable-sized).
 */
uint
packed_host_addr_hash(const void *key)
{
	const struct packed_host_addr *p = key;
	return binary_hash(key, packed_host_addr_size_ptr(p));
}

/**
 * Alternate hash for a packed host_addr buffer (variable-sized).
 */
uint
packed_host_addr_hash2(const void *key)
{
	const struct packed_host_addr *p = key;
	return binary_hash2(key, packed_host_addr_size_ptr(p));
}

/**
 * Compare two packed host_addr buffers (variable-sized).
 */
bool
packed_host_addr_equal(const void *p, const void *q)
{
	const struct packed_host_addr *a = p, *b = q;
	uint asize = packed_host_addr_size_ptr(a);
	uint bsize = packed_host_addr_size_ptr(b);

	if (asize != bsize)
		return FALSE;

	return 0 == memcmp(a, b, asize);
}

/**
 * Allocate a packed_host_addr object from a host address.
 */
void *
walloc_packed_host_addr(const host_addr_t addr)
{
	struct packed_host_addr packed = host_addr_pack(addr);

	return wcopy(&packed, packed_host_addr_size_ptr(&packed));
}

/**
 * Allocate a packed_host_addr object from a host address pointer.
 */
void *
walloc_packed_host_addr_ptr(const void *paddr)
{
	const host_addr_t *addr = paddr;
	struct packed_host_addr packed = host_addr_pack(*addr);

	return wcopy(&packed, packed_host_addr_size_ptr(&packed));
}

/**
 * Release packed_host_addr allocated via walloc_packed_host_addr().
 */
void
wfree_packed_host_addr(void *pha)
{
	const struct packed_host_addr *p = pha;

	wfree(pha, packed_host_addr_size_ptr(p));
}

/* vi: set ts=4 sw=4 cindent: */
