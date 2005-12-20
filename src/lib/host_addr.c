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

#ifdef I_NETDB
#include <netdb.h>				/* For gethostbyname() */
#endif

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
		
#ifdef USE_IPV6
	} else if (NET_TYPE_IPV6 == host_addr_net(ha)) {
		return host_addr_equal(ha, ipv6_loopback);
#endif /* USE_IPV6 */
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

#ifdef USE_IPV6
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
#endif /* USE_IPV6 */

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
#ifdef USE_IPV6
		return host_addr_equal(ha, ipv6_loopback);
#endif /* USE_IPV6 */

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
#ifdef USE_IPV6
		return 	!host_addr_matches(ha, ipv6_unspecified, 8) &&
				!host_addr_matches(ha, ipv6_multicast, 8) &&
				!(
						host_addr_is_6to4(ha) &&
						!ipv4_addr_is_routable(host_addr_6to4_ipv4(ha))
				);
#endif /* USE_IPV6 */

	case NET_TYPE_NONE:
		break;
	}

	g_assert_not_reached();
	return FALSE;
}

#ifdef USE_IPV6
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
#endif /* USE_IPV6 */

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

#if defined(USE_IPV6)
	case NET_TYPE_IPV6:
		return ipv6_to_string_buf(host_addr_ipv6(&ha), dst, size);
#endif /* USE_IPV6*/

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
	gchar port_buf[UINT64_DEC_BUFLEN];

	host_addr_to_string_buf(ha, host_buf, sizeof host_buf);
	uint64_to_string_buf(port, port_buf, sizeof port_buf);

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

/**
 * Parses IPv4 and IPv6 addresses. The latter requires IPv6 support to be
 * enabled.
 *
 * "0.0.0.0" and "::" cannot be distinguished from unparsable addresses.
 *
 * @param s The string to parse.
 * @param endptr This will point to the first character after the parsed
 *        address.
 * @return Returns the host address or ``zero_host_addr'' on failure.
 */
host_addr_t
string_to_host_addr(const char *s, const gchar **endptr)
{
	host_addr_t ha;
	guint32 ip;

	g_assert(s);

	if (string_to_ip_strict(s, &ip, endptr)) {
		ha = host_addr_set_ipv4(ip);
		return ha;
#ifdef USE_IPV6
	} else {
		guint8 ipv6[16];
		if (parse_ipv6_addr(s, ipv6, endptr)) {
			host_addr_set_ipv6(&ha, ipv6);
			return ha;
		}
#endif
	}
	return zero_host_addr;
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
#ifdef USE_IPV6
				host_addr_set_ipv6(ha, ipv6);
#else
				/* If IPv6 is disabled, consider [::] a hostname */
				*ha = zero_host_addr;
#endif /* USE_IPV6 */
			}
			if (endptr)
				*endptr = ++ep;

			return TRUE;
		}
	}

	addr = string_to_host_addr(s, endptr);
	if (is_host_addr(addr)) {
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

static void
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
 * Resolves an IP address to a hostname per DNS.
 *
 * @todo TODO: Use getnameinfo() if available.
 *
 * @param ha	The host address to resolve.
 * @return		On success, the hostname is returned. Otherwise, NULL is
 *				returned. The resulting string points to a static buffer.
 */
const gchar *
host_addr_to_name(const host_addr_t addr)
{
	const struct hostent *he;
	union {
		struct in_addr in;
#ifdef USE_IPV6	
		struct in6_addr in6;
#endif /* USE_IPV6 */
	} a;
	host_addr_t ha;
	gconstpointer sockaddr;
	int type;
	socklen_t len;

	if (!host_addr_convert(addr, &ha, NET_TYPE_IPV4))
		ha = addr;
	
	switch (host_addr_net(ha)) {
	case NET_TYPE_IPV4:
		{
			static const struct in_addr zero_addr;

			type = AF_INET;
			a.in = zero_addr;
			a.in.s_addr = htonl(host_addr_ipv4(ha));

			sockaddr = cast_to_gpointer(&a.in);
			len = sizeof a.in;
		}
		break;

#ifdef USE_IPV6
	case NET_TYPE_IPV6:
		{
			static const struct in6_addr zero_addr;

			type = AF_INET6;
			a.in6 = zero_addr;
			memcpy(&a.in6, host_addr_ipv6(&ha), 16);

			sockaddr = cast_to_gpointer(&a.in6);
			len = sizeof a.in6;
		}
		break;
#endif /* USE_IPV6 */

	default:
		sockaddr = NULL;
		type = 0;
		len = 0;
		g_assert_not_reached();
	}

	he = gethostbyaddr(sockaddr, sizeof sockaddr, type);
	if (!he) {
		gchar buf[128];

		host_addr_to_string_buf(ha, buf, sizeof buf);
		gethostbyname_error(buf);
		return NULL;
	}

#if 0
	g_message("h_name=\"%s\"", NULL_STRING(he->h_name));
	if (he->h_aliases) {
		size_t i;

		for (i = 0; he->h_aliases[i]; i++)
			g_message("h_aliases[%u]=\"%s\"", (unsigned) i, he->h_aliases[i]);
	}
#endif

	return he->h_name;
}

/**
 * Resolves a hostname to an IP address per DNS.
 *
 * @todo TODO: This should return all resolved address not just the first
 *             and it should be possible to request only IPv4 or IPv6
 *             addresses.
 *
 * @param host A NUL-terminated string holding the hostname to resolve.
 * @return On success, the first address IPv4 or IPv6 address is returned.
 *         On failure, zero_host_addr is returned.
 */
host_addr_t
name_to_host_addr(const gchar *host)
#if defined(HAS_GETADDRINFO)
{
	static const struct addrinfo zero_hints;
	struct addrinfo hints, *ai, *ai0 = NULL;
	gboolean finished = FALSE;
	host_addr_t addr;
	const gchar *endptr;
	gint error;

	g_assert(host);

	/* As far as I know, some broken implementations won't resolve numeric
	 * addresses although getaddrinfo() must support exactly this for protocol
	 * independence.
	 */

	addr = string_to_host_addr(host, &endptr);
	if (is_host_addr(addr) && '\0' == *endptr)
		return addr;
	
	hints = zero_hints;
	hints.ai_family =
#ifdef USE_IPV6
		PF_UNSPEC;
#else	/* !USE_IPV6 */
		PF_INET;
#endif	/* USE_IPV6 */

	error = getaddrinfo(host, NULL, &hints, &ai0);
	if (error) {
		g_message("getaddrinfo() failed for \"%s\": %s",
				host, gai_strerror(error));
		return zero_host_addr;
	}

	addr = zero_host_addr;
	for (ai = ai0; ai && !finished; ai = ai->ai_next) {
		if (!ai->ai_addr)
			continue;

		switch (ai->ai_family) {
		case PF_INET:
			if (ai->ai_addrlen >= 4) {
				const struct sockaddr_in *sin;

				sin = cast_to_gconstpointer(ai->ai_addr);
				addr = host_addr_set_ipv4(ntohl(sin->sin_addr.s_addr));
				finished = TRUE;
			}
			break;

#ifdef USE_IPV6
		case PF_INET6:
			if (ai->ai_addrlen >= 16) {
				const struct sockaddr_in6 *sin6;

				sin6 = cast_to_gconstpointer(ai->ai_addr);
				host_addr_set_ipv6(&addr,
					cast_to_gconstpointer(sin6->sin6_addr.s6_addr));
				finished = TRUE;
			}
			break;
#endif /* USE_IPV6 */

		default:;
		}
	}

	if (ai0)
		freeaddrinfo(ai0);

	return addr;
}
#else /* !HAS_GETADDRINFO */
{
	const struct hostent *he;
	const gchar *endptr;
	host_addr_t addr;

	/*
	 * Make sure we can "resolve" stringyfied addresses because some
	 * gethostbyname() implementations won't do this especially not for IPv6
	 * although some support IPv6.
	 */

	addr = string_to_host_addr(host, &endptr);
	if (is_host_addr(addr) && '\0' == *endptr)
		return addr;
	
   	he = gethostbyname(host);
	if (!he) {
		gethostbyname_error(host);
		return zero_host_addr;
	}

#if 0
	g_message("h_name=\"%s\"", NULL_STRING(he->h_name));
	if (he->h_aliases) {
		size_t i;

		for (i = 0; he->h_aliases[i]; i++)
			g_message("h_aliases[%u]=\"%s\"", (unsigned) i, he->h_aliases[i]);
	}
#endif

	switch (he->h_addrtype) {
	case AF_INET:
		if (4 != he->h_length) {
			g_warning("host_to_addr: Wrong length of IPv4 address "
				"(host=\"%s\")", host);
			return zero_host_addr;
		}

		addr = host_addr_set_ipv4(peek_be32(he->h_addr_list[0]));
		return addr;

#ifdef USE_IPV6
	case AF_INET6:
		if (16 != he->h_length) {
			g_warning("host_to_addr: Wrong length of IPv6 address "
				"(host=\"%s\")", host);
			return zero_host_addr;
		}
		host_addr_set_ipv6(&addr, cast_to_gconstpointer(he->h_addr_list[0]));
		return addr;
#endif /* !USE_IPV6 */
	}

	return zero_host_addr;
}
#endif /* HAS_GETADDRINFO */

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

/* vi: set ts=4 sw=4 cindent: */
