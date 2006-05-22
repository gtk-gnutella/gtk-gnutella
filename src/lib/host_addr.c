/*
 * $Id$
 *
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

RCSID("$Id$");

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
#include "misc.h"
#include "endian.h"
#include "walloc.h"

#include "override.h"		/* Must be the last header included */

/**
 * Checks for RFC1918 private addresses.
 *
 * @return TRUE if is a private address.
 */
gboolean
is_private_addr(const host_addr_t ha)
{
	if (NET_TYPE_IPV4 == host_addr_net(ha)) {
		guint32 ip = host_addr_ipv4(ha);

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
		
	} else if (NET_TYPE_IPV6 == host_addr_net(ha)) {
		return host_addr_equal(ha, ipv6_loopback);
	}

	return FALSE;
}

static inline gboolean
ipv4_addr_is_routable(guint32 ip)
{
	static const struct {
		const guint32 addr, mask;
	} net[] = {
		{ 0x00000000UL, 0xff000000UL },	/* 0.0.0.0/8	"This" Network */
		{ 0xe0000000UL, 0xe0000000UL },	/* 224.0.0.0/4	Multicast + Reserved */
		{ 0x7f000000UL,	0xff000000UL },	/* 127.0.0.0/8	Loopback */
		{ 0xc0000200UL, 0xffffff00UL },	/* 192.0.2.0/24	Test-Net [RFC 3330] */
		{ 0xc0586300UL, 0xffffff00UL },	/* 192.88.99.0/24	6to4 [RFC 3068] */
		{ 0xc6120000UL, 0xfffe0000UL },	/* 198.18.0.0/15	[RFC 2544] */
	};
	guint i;

	for (i = 0; i < G_N_ELEMENTS(net); i++) {
		if ((ip & net[i].mask) == net[i].addr)
			return FALSE;
	}

	return TRUE;
}

static inline guint32
host_addr_is_6to4(const host_addr_t ha)
{
	return NET_TYPE_IPV6 == host_addr_net(ha) &&
		htons(0x2002) == ha.addr.u16[0];
}

static inline guint32
host_addr_6to4_ipv4(const host_addr_t ha)
{
	return peek_be32(&ha.addr.u16[1]);	/* 2002:AABBCCDD::/48 */
}

gboolean
host_addr_6to4_to_ipv4(const host_addr_t from, host_addr_t *to)
{
	if (host_addr_is_6to4(from)) {
		if (to)
			to->addr.ipv4 = peek_be32(&from.addr.u16[1]);
		return TRUE;
	} else {
		if (to)
			*to = zero_host_addr;
		return FALSE;
	}
}

/**
 * Checks whether the given address is 127.0.0.1 or ::1.
 */
gboolean
host_addr_is_loopback(const host_addr_t addr)
{
	host_addr_t ha;
	
	if (!host_addr_convert(addr, &ha, NET_TYPE_IPV4))
		ha = addr;
	
	switch (host_addr_net(ha)) {
	case NET_TYPE_IPV4:
		return host_addr_ipv4(ha) == 0x7f000001; /* 127.0.0.1 in host endian */

	case NET_TYPE_IPV6:
		return host_addr_equal(ha, ipv6_loopback);

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
gboolean
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
						host_addr_is_6to4(ha) &&
						!ipv4_addr_is_routable(host_addr_6to4_ipv4(ha))
				);

	case NET_TYPE_NONE:
		break;
	}

	g_assert_not_reached();
	return FALSE;
}

gboolean
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
gboolean
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
				to->net = NET_TYPE_IPV4;
				to->addr.ipv4 = peek_be32(&from.addr.ipv6[12]);
				return TRUE;
			}
			break;
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
			poke_be32(&to->addr.ipv6[12], from.addr.ipv4);
			return TRUE;
		case NET_TYPE_NONE:
			break;
		}
		break;

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
host_addr_to_string_buf(const host_addr_t ha, gchar *dst, size_t size)
{
	switch (host_addr_net(ha)) {
	case NET_TYPE_IPV4:
		{
			struct in_addr ia;

			ia.s_addr = htonl(host_addr_ipv4(ha));
			return g_strlcpy(dst, inet_ntoa(ia), size);
		}

	case NET_TYPE_IPV6:
		return ipv6_to_string_buf(host_addr_ipv6(&ha), dst, size);

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
const gchar *
host_addr_to_string(const host_addr_t ha)
{
	static gchar buf[128];
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
host_addr_port_to_string_buf(const host_addr_t ha, guint16 port,
		gchar *dst, size_t size)
{
	size_t n;
	gchar host_buf[64];
	gchar port_buf[UINT32_DEC_BUFLEN];

	host_addr_to_string_buf(ha, host_buf, sizeof host_buf);
	uint32_to_string_buf(port, port_buf, sizeof port_buf);

	if (NET_TYPE_IPV6 == host_addr_net(ha)) {
		n = concat_strings(dst, size, "[", host_buf, "]:",
				port_buf, (void *) 0);
	} else {
		n = concat_strings(dst, size, host_buf, ":", port_buf, (void *) 0);
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
const gchar *
host_addr_port_to_string(const host_addr_t ha, guint16 port)
{
	static gchar buf[IPV6_ADDR_BUFLEN + sizeof "[]:65535"];
	size_t n;

	n = host_addr_port_to_string_buf(ha, port, buf, sizeof buf);
	g_assert(n < sizeof buf);
	return buf;
}

const gchar *
host_addr_port_to_string2(const host_addr_t ha, guint16 port)
{
	static gchar buf[IPV6_ADDR_BUFLEN + sizeof "[]:65535"];
	size_t n;

	n = host_addr_port_to_string_buf(ha, port, buf, sizeof buf);
	g_assert(n < sizeof buf);
	return buf;
}

/**
 * Parses IPv4 and IPv6 addresses. The latter requires IPv6 support to be
 * enabled.
 *
 * @param s The string to parse.
 * @param endptr This will point to the first character after the parsed
 *        address.
 * @param addr_ptr If not NULL, it is set to the parsed host address or
 *        ``zero_host_addr'' on failure.
 * @return Returns TRUE on success; otherwise FALSE.
 */
gboolean
string_to_host_addr(const char *s, const gchar **endptr, host_addr_t *addr_ptr)
{
	guint32 ip;

	g_assert(s);

	if (string_to_ip_strict(s, &ip, endptr)) {
		if (addr_ptr)
			*addr_ptr = host_addr_set_ipv4(ip);
		return TRUE;
	} else {
		guint8 ipv6[16];
		if (parse_ipv6_addr(s, ipv6, endptr)) {
			if (addr_ptr)
				host_addr_set_ipv6(addr_ptr, ipv6);
			return TRUE;
		}
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
 * first character after hostname. If IPv6 support is disabled, "[::]" will
 * be considered a hostname rather than a host address.
 *
 * @param s the string to parse.
 * @param endptr if not NULL, it will point the first character after
 *        the parsed host address or hostname.
 * @param ha if not NULL, it is set to the parsed host address or
 *        ``zero_host_addr'' on failure.
 * @return TRUE if the string points to host address or is a possible
 *         hostname.
 */
gboolean
string_to_host_or_addr(const char *s, const gchar **endptr, host_addr_t *ha)
{
	const gchar *ep;
	host_addr_t addr;

	if ('[' == s[0]) {
		guint8 ipv6[16];

		if (parse_ipv6_addr(&s[1], ipv6, &ep) && ']' == *ep) {

			if (ha) {
				host_addr_set_ipv6(ha, ipv6);
			}
			if (endptr)
				*endptr = ++ep;

			return TRUE;
		}
	}

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

	return s != ep ? TRUE : FALSE;
}

gboolean
string_to_host_addr_port(const gchar *str, const gchar **endptr,
	host_addr_t *addr_ptr, guint16 *port_ptr)
{
	const gchar *ep;
	host_addr_t addr;
	gboolean ret;
	guint16 port;

	ret = string_to_host_or_addr(str, &ep, &addr);
	if (ret && ':' == *ep && is_host_addr(addr)) {
		guint32 u;
		gint error;

		ep++;
		u = parse_uint32(ep, &ep, 10, &error);
		port = error || u > 65535 ? 0 : u;
		ret = 0 != port;
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

void
gethostbyname_error(const gchar *host)
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
socket_addr_set(socket_addr_t *sa_ptr, const host_addr_t addr, guint16 port)
{
	switch (host_addr_net(addr)) {
	case NET_TYPE_IPV4:
		if (sa_ptr) {
			static const struct sockaddr_in zero_sin;

			sa_ptr->inet4 = zero_sin;
			/* Note: The next line is a cheap(?) hack to be used until
			 *       HAS_SIN_LEN is initialized by Configure. sin_len if
			 *       available.
			 */
			sa_ptr->len = sizeof sa_ptr->inet4;
#ifdef HAS_SIN_LEN
			sa_ptr->inet4.sin_len = sizeof sa_ptr->inet4;
#endif /* HAS_SIN_LEN */
			sa_ptr->inet4.sin_family = AF_INET;
			sa_ptr->inet4.sin_port = htons(port);
			sa_ptr->inet4.sin_addr.s_addr = htonl(host_addr_ipv4(addr));
		}
		return sizeof sa_ptr->inet4;
	case NET_TYPE_IPV6:
#ifdef USE_IPV6
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
#endif	/* USE_IPV6 */
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

/**
 * Resolves an IP address to a hostname per DNS.
 *
 * @param ha	The host address to resolve.
 * @return		On success, the hostname is returned. Otherwise, NULL is
 *				returned. The resulting string points to a static buffer.
 */
const gchar *
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
		static gchar host[1025];
		gint error;

		error = getnameinfo(socket_addr_get_sockaddr(&sa),
					socket_addr_get_len(&sa), host, sizeof host, NULL, 0, 0);
		if (error) {
			gchar buf[HOST_ADDR_BUFLEN];

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
		const gchar *ptr = NULL;

		switch (host_addr_net(addr)) {
		case NET_TYPE_IPV4:
			ptr = cast_to_gchar_ptr(&sa.inet4.sin_addr);
			len = sizeof sa.inet4.sin_addr;
			break;
		case NET_TYPE_IPV6:
#ifdef USE_IPV6
			ptr = cast_to_gchar_ptr(&sa.inet6.sin6_addr);
			len = sizeof sa.inet6.sin6_addr;
			break;
#endif /* USE_IPV6 */
		case NET_TYPE_NONE:
			return NULL;
		}
		g_return_val_if_fail(ptr, NULL);
		g_return_val_if_fail(0 != len, NULL);

		he = gethostbyaddr(ptr, len, socket_addr_get_family(&sa));
		if (!he) {
			gchar buf[128];

			host_addr_to_string_buf(addr, buf, sizeof buf);
			gethostbyname_error(buf);
			return NULL;
		}
		return he->h_name;
	}
#endif	/* HAS_GETNAMEINFO */
}

static GSList *
resolve_hostname(const gchar *host, enum net_type net)
#if defined(HAS_GETADDRINFO)
{
	static const struct addrinfo zero_hints;
	struct addrinfo hints, *ai, *ai0 = NULL;
	GHashTable *ht;
	GSList *sl_addr;
	gint error;

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
	ht = g_hash_table_new(host_addr_hash_func, host_addr_eq_func);
	for (ai = ai0; ai; ai = ai->ai_next) {
		host_addr_t addr;

		if (!ai->ai_addr)
			continue;

		addr = zero_host_addr;
		switch (ai->ai_family) {
		case PF_INET:
			if (ai->ai_addrlen >= 4) {
				const struct sockaddr_in *sin;

				sin = cast_to_gconstpointer(ai->ai_addr);
				addr = host_addr_set_ipv4(ntohl(sin->sin_addr.s_addr));
			}
			break;

#ifdef USE_IPV6
		case PF_INET6:
			if (ai->ai_addrlen >= 16) {
				const struct sockaddr_in6 *sin6;

				sin6 = cast_to_gconstpointer(ai->ai_addr);
				host_addr_set_ipv6(&addr,
					cast_to_gconstpointer(sin6->sin6_addr.s6_addr));
			}
			break;
#endif /* USE_IPV6 */
		}

		if (is_host_addr(addr) && !g_hash_table_lookup(ht, &addr)) {
			host_addr_t *addr_copy;

			addr_copy = wcopy(&addr, sizeof addr);
			sl_addr = g_slist_prepend(sl_addr, addr_copy);
			g_hash_table_insert(ht, addr_copy, GINT_TO_POINTER(1));
		}
	}
	g_hash_table_destroy(ht);

	if (ai0)
		freeaddrinfo(ai0);

	return g_slist_reverse(sl_addr);
}
#else /* !HAS_GETADDRINFO */
{
	const struct hostent *he;
	GHashTable *ht;
	GSList *sl_addr;
	gint af;
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
			g_warning("host_to_addr: Wrong length of IPv4 address (\"%s\")",
				host);
			return NULL;
		}
		break;
		
#ifdef USE_IPV6
	case AF_INET6:
		if (16 != he->h_length) {
			g_warning("host_to_addr: Wrong length of IPv6 address (\"%s\")",
				host);
			return NULL;
		}
		break;
#endif /* USE_IPV6 */
		
	default:
		return NULL;
	}
	
	sl_addr = NULL;
	ht = g_hash_table_new(host_addr_hash_func, host_addr_eq_func);
	for (i = 0; NULL != he->h_addr_list[i]; i++) {
		host_addr_t addr;

		switch (he->h_addrtype) {
		case AF_INET:
			addr = host_addr_set_ipv4(peek_be32(he->h_addr_list[i]));
			break;

#ifdef USE_IPV6
		case AF_INET6:
			host_addr_set_ipv6(&addr,
				cast_to_gconstpointer(he->h_addr_list[i]));
			break;
#endif /* !USE_IPV6 */
		default:
			g_assert_not_reached();
		}

		if (is_host_addr(addr) && !g_hash_table_lookup(ht, &addr)) {
			host_addr_t *addr_copy;

			addr_copy = wcopy(&addr, sizeof addr);
			sl_addr = g_slist_prepend(sl_addr, addr_copy);
			g_hash_table_insert(ht, addr_copy, GINT_TO_POINTER(1));
		}
	}
	g_hash_table_destroy(ht);

	return g_slist_reverse(sl_addr);
}
#endif /* HAS_GETADDRINFO */

/**
 * Resolves a hostname to IP addresses per DNS.
 *
 * @todo TODO: This should return all resolved address not just the first
 *             and it should be possible to request only IPv4 or IPv6
 *             addresses.
 *
 * @param host A NUL-terminated string holding the hostname to resolve.
 * @param net Use NET_TYPE_IPV4 if you want only IPv4 addresses or like-wise
              NET_TYPE_IPV6. If you don't care, use NET_TYPE_NONE.
 * @return On success, a single-linked list of walloc()ated host_addr_t
 *         items is returned.
 *         On failure, NULL is returned.
 */
GSList *
name_to_host_addr(const gchar *host, enum net_type net)
{
	const gchar *endptr;
	host_addr_t addr;
	
	g_assert(host);

	/* As far as I know, some broken implementations won't resolve numeric
	 * addresses although getaddrinfo() must support exactly this for protocol
	 * independence. gethostbyname() implementations won't do this especially
	 * not for IPv6 although some support IPv6.
	 */

	if (string_to_host_addr(host, &endptr, &addr) && '\0' == *endptr) {
		return g_slist_append(NULL, wcopy(&addr, sizeof addr));
	}

	return resolve_hostname(host, net);
}

/**
 * Resolves a hostname to an IP address per DNS. This is the same as
 * name_to_host_addr() but we pick a random item from the result list
 * and return it.
 */
host_addr_t
name_to_single_host_addr(const gchar *host, enum net_type net)
{
	GSList *sl_addr;
	host_addr_t addr;
	
	addr = zero_host_addr;
	sl_addr = name_to_host_addr(host, net);
	if (sl_addr) {
		GSList *sl;
		size_t i, len;

		len = g_slist_length(sl_addr);
		i = len > 1 ? (random_raw() % len) : 0;

		for (sl = sl_addr; NULL != sl; sl = g_slist_next(sl)) {
			const host_addr_t *addr_ptr = sl->data;

			g_assert(addr_ptr);
			if (0 == i--) {
				addr = *addr_ptr;
				break;
			}
		}

		for (sl = sl_addr; NULL != sl; sl = g_slist_next(sl)) {
			host_addr_t *addr_ptr = sl->data;
			wfree(addr_ptr, sizeof *addr_ptr);
		}
		g_slist_free(sl_addr);
	}

	return addr;
}

guint
host_addr_hash_func(gconstpointer key)
{
	const host_addr_t *addr = key;
	return host_addr_hash(*addr);
}

gboolean
host_addr_eq_func(gconstpointer p, gconstpointer q)
{
	const host_addr_t *a = p, *b = q;
	return host_addr_equal(*a, *b);
}

void
wfree_host_addr(gpointer key, gpointer unused_data)
{
	(void) unused_data;
	wfree(key, sizeof (host_addr_t));
}

/**
 * @return	A list of all IPv4 and IPv6 addresses assigned to interfaces
 *			of the machine.
 */
GSList *
host_addr_get_interface_addrs(void)
#if defined(HAS_GETIFADDRS)
{
	struct ifaddrs *ifa0, *ifa;
	GSList *sl_addrs = NULL;

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
            const struct sockaddr_in *sin;
			
			sin = cast_to_gconstpointer(ifa->ifa_addr);
			addr = host_addr_set_ipv4(ntohl(sin->sin_addr.s_addr));
#ifdef USE_IPV6
		} else if (AF_INET6 == ifa->ifa_addr->sa_family) {
            const struct sockaddr_in6 *sin6;

			sin6 = cast_to_gconstpointer(ifa->ifa_addr);
			host_addr_set_ipv6(&addr, sin6->sin6_addr.s6_addr);
#endif /* USE_IPV6 */
		} else {
			addr = zero_host_addr;
		}

		if (is_host_addr(addr)) {
			sl_addrs = g_slist_prepend(sl_addrs, wcopy(&addr, sizeof addr));
		}
	}

	freeifaddrs(ifa0);
	return g_slist_reverse(sl_addrs);
}
#else	/* !HAS_GETIFADDRS */
{
	return NULL;
}
#endif	/* HAS_GETIFADDRS */

/**
 * Frees a list along with its item returned by
 * host_addr_get_interface_addrs() and nullifies the given pointer.
 */
void
host_addr_free_interface_addrs(GSList **sl_ptr)
{
	g_assert(sl_ptr);
	if (*sl_ptr) {
		GSList *sl;

		for (sl = *sl_ptr; NULL != sl; sl = g_slist_next(sl)) {
            host_addr_t *addr = sl->data;
			g_assert(host_addr_initialized(*addr));
			wfree(addr, sizeof *addr);
		}
		g_slist_free(*sl_ptr);
		*sl_ptr = NULL;
	}
}

/* vi: set ts=4 sw=4 cindent: */
