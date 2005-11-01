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

#ifndef _host_addr_h_
#define _host_addr_h_

#include "common.h"
#include "misc.h"

enum net_type {
	NET_TYPE_NONE	= 0,
	NET_TYPE_IPV4	= 4,
	NET_TYPE_IPV6	= 6,
};

#ifdef USE_IPV6
typedef struct host_addr {
	guint32 net;	/**< The address network type */
	union {
		guint8	ipv6[16];	/**< This is valid if "net == NET_TYPE_IPV6" */
		guint32 ipv4;		/**< @attention: Always in host byte order! */

		guint8	u8[16];
		guint16 u16[8];
		guint32 u32[4];
	} addr;
} host_addr_t;

#else /* !USE_IPV6 */

/* For an IPv4-only configuration */
typedef guint32 host_addr_t; /**< @attention: Always in host byte order! */

#endif /* USE_IPV6*/

#if defined(USE_IPV6)
static const host_addr_t ipv6_unspecified = {	/* :: */
	NET_TYPE_IPV6,
	{ { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 } },
};

static const host_addr_t ipv6_loopback = {	/* ::1 */
	NET_TYPE_IPV6,
	{ { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 } },
};

static const host_addr_t ipv6_ipv4_mapped = {	/* ::ffff:0:0 */
	NET_TYPE_IPV6,
	{ { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 0, 0 } },
};

static const host_addr_t ipv6_multicast = {		/* ff00:: */
	NET_TYPE_IPV6,
	{ { 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 } },
};

static const host_addr_t ipv6_link_local = {	/* fe80:: */
	NET_TYPE_IPV6,
	{ { 0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 } },
};

static const host_addr_t ipv6_site_local = {	/* fec0:: */
	NET_TYPE_IPV6,
	{ { 0xfe, 0xc0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 } },
};

static const host_addr_t ipv6_6to4 = {			/* 2002:: */
	NET_TYPE_IPV6,
	{ { 0x20, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 } },
};


static const host_addr_t zero_host_addr;

gboolean host_addr_convert(const host_addr_t from, host_addr_t *to,
	enum net_type to_net);
gboolean host_addr_can_convert(const host_addr_t from, enum net_type to_net);

static inline gboolean
host_addr_initialized(const host_addr_t ha)
{
	switch (ha.net) {
	case NET_TYPE_IPV4:
	case NET_TYPE_IPV6:
		return TRUE;
	case NET_TYPE_NONE:
		return FALSE;
	}
	g_assert_not_reached();
	return FALSE;
}

static inline enum net_type 
host_addr_net(const host_addr_t ha)
{
	return ha.net;
}

static inline guint32
host_addr_ipv4(const host_addr_t ha)
{
	return NET_TYPE_IPV4 == ha.net ? ha.addr.ipv4 : 0;
}

static inline const guint8 *
host_addr_ipv6(const host_addr_t *ha)
{
	return NET_TYPE_IPV6 == ha->net ? ha->addr.ipv6 : NULL;
}

static inline host_addr_t
host_addr_set_ipv4(guint32 ip)
{
	host_addr_t ha;

	ha.net = NET_TYPE_IPV4;
	ha.addr.ipv4 = ip;
	return ha;
}

static inline void
host_addr_set_ipv6(host_addr_t *ha, const guint8 *ipv6)
{
	ha->net = NET_TYPE_IPV6;
	memcpy(ha->addr.ipv6, ipv6, 16);
}

static inline gboolean
host_addr_equal(const host_addr_t a, const host_addr_t b)
{
	if (a.net == b.net) {
		switch (a.net) {
		case NET_TYPE_IPV4:
			return a.addr.ipv4 == b.addr.ipv4;
		case NET_TYPE_IPV6:
			if (0 != memcmp(a.addr.ipv6, b.addr.ipv6, sizeof a.addr.ipv6)) {
				host_addr_t a_ipv4, b_ipv4;

				return host_addr_convert(a, &a_ipv4, NET_TYPE_IPV4) &&
					host_addr_convert(b, &b_ipv4, NET_TYPE_IPV4) &&
					a_ipv4.addr.ipv4 == b_ipv4.addr.ipv4;
			}
			return TRUE;

		case NET_TYPE_NONE:
			return TRUE;
		}
		g_assert_not_reached();
	} else {
		host_addr_t to;

		return host_addr_convert(a, &to, b.net) && host_addr_equal(to, b);
	}
	return FALSE;
}

static inline gint
host_addr_cmp(host_addr_t a, host_addr_t b)
{
	gint r;

	r = CMP(a.net, b.net);
	if (0 != r) {
		host_addr_t to;

		if (!host_addr_convert(b, &to, a.net))
			return r;
		b = to;
	}

	switch (a.net) {
	case NET_TYPE_IPV4:
		return CMP(a.addr.ipv4, b.addr.ipv4);
	case NET_TYPE_IPV6:
		{
			guint i;

			for (i = 0; i < G_N_ELEMENTS(a.addr.ipv6); i++) {
				r = CMP(a.addr.ipv6[i], b.addr.ipv6[i]);
				if (0 != r)
					break;
			}
		}
		return r;
	case NET_TYPE_NONE:
		return 0;
	}
	g_assert_not_reached();
	return 0;
}

static inline gboolean
host_addr_matches(const host_addr_t a, const host_addr_t b, guint8 bits)
{
	host_addr_t to;
	guint8 shift;

	if (!host_addr_convert(b, &to, a.net))
		return FALSE;

	switch (a.net) {
	case NET_TYPE_IPV4:
		shift = bits < 32 ? 32 - bits : 0;
		return (a.addr.ipv4 >> shift) == (to.addr.ipv4 >> shift);

	case NET_TYPE_IPV6:
		{
			gint i;

			bits = MIN(128, bits);
			for (i = 0; bits >= 8; i++, bits -= 8) {
				if (a.addr.ipv6[i] != to.addr.ipv6[i])
					return FALSE;
			}

			if (bits > 0) {
				guint8 shift = 8 - bits;
				return (a.addr.ipv6[i] >> shift) == (to.addr.ipv6[i] >> shift);
			}

		}
		return TRUE;

	case NET_TYPE_NONE:
		return TRUE;
	}

	g_assert_not_reached();
	return FALSE;
}


static inline gboolean
is_host_addr(const host_addr_t ha)
{
	switch (host_addr_net(ha)) {
	case NET_TYPE_IPV4:
		return 0 != ha.addr.ipv4;
	case NET_TYPE_IPV6:
		return 0 != memcmp(ha.addr.ipv6, zero_host_addr.addr.ipv6,
						sizeof ha.addr.ipv6);
	case NET_TYPE_NONE:
		return FALSE;
	}
	g_assert_not_reached();
	return FALSE;
}

static inline int
host_addr_family(const host_addr_t ha)
{
	switch (ha.net) {
	case NET_TYPE_IPV4:
		return AF_INET;
	case NET_TYPE_IPV6:
		return AF_INET6;
	case NET_TYPE_NONE:
		break;
	}
	g_message("%u:%u", (guint8) ha.net, ha.addr.ipv4);
	g_assert_not_reached();
	return -1;
}

static inline guint32
host_addr_hash(host_addr_t ha)
{
	switch (ha.net) {
	case NET_TYPE_IPV6:
		{
			host_addr_t ha_ipv4;

			if (!host_addr_convert(ha, &ha_ipv4, NET_TYPE_IPV4)) {
				guint32 h = ha.net ^ ha.addr.ipv6[15];
				guint i;

				for (i = 0; i < sizeof ha.addr.ipv6; i++)
					h ^= (guint32) ha.addr.ipv6[i] << (i * 2);

				return h;
			}
			ha = ha_ipv4;
		}
		/* FALL THROUGH */
	case NET_TYPE_IPV4:
		return ha.net ^ ha.addr.ipv4;
	case NET_TYPE_NONE:
		return 0;
	}
	g_assert_not_reached();
	return -1;
}

#else

/* IPv4 only */

#define host_addr_initialized(x)	TRUE
#define host_addr_net(x) (((void) (x)), NET_TYPE_IPV4)
#define host_addr_family(x) (((void) (x)), AF_INET)
#define host_addr_ipv4(x) (x)
#define host_addr_set_ipv4(x) (x)
#define host_addr_set_net(x, y) G_STMT_START { (void) ((x), (y)) } G_STMT_END
#define is_host_addr(x) (0 != (x))
#define host_addr_equal(a, b) ((a) == (b))
#define host_addr_cmp(a, b) (CMP((a), (b)))
#define host_addr_hash(x) (x)
#define zero_host_addr 0

static inline gboolean
host_addr_convert(const host_addr_t from, host_addr_t *to,
	enum net_type to_net)
{
	if (NET_TYPE_IPV4 == to_net) {
		*to = from;
		return TRUE;
	}
	*to = zero_host_addr;
	return FALSE;
}

static inline G_GNUC_CONST WARN_UNUSED_RESULT gboolean
host_addr_matches(guint32 a, guint32 b, guint8 bits)
{
	guint8 shift;

	shift = bits < 32 ? 32 - bits : 0;
	return (a >> shift) == (b >> shift);
}

#endif /* USE_IPV6 */

guint host_addr_hash_func(gconstpointer key);
gboolean host_addr_eq_func(gconstpointer p, gconstpointer q);
void wfree_host_addr(gpointer key, gpointer unused_data);

gboolean is_private_addr(const host_addr_t addr);
gboolean host_addr_is_routable(const host_addr_t addr);
gboolean host_addr_is_loopback(const host_addr_t addr);
const gchar *host_addr_to_string(const host_addr_t addr);
size_t host_addr_to_string_buf(const host_addr_t addr, gchar *, size_t);
host_addr_t string_to_host_addr(const gchar *s, const gchar **endptr);
const gchar *host_addr_port_to_string(const host_addr_t addr, guint16 port);
size_t host_addr_port_to_string_buf(const host_addr_t addr,
				guint16 port, gchar *, size_t);
gboolean string_to_host_addr_port(const gchar *str, const gchar **endptr,
	host_addr_t *addr_ptr, guint16 *port_ptr);
host_addr_t name_to_host_addr(const gchar *host);
const gchar *host_addr_to_name(const host_addr_t addr);
gboolean string_to_host_or_addr(const char *s, const gchar **endptr,
		host_addr_t *ha);

#endif /* _host_addr_h_ */
/* vi: set ts=4 sw=4 cindent: */
