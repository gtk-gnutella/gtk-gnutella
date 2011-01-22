/*
 * $Id$
 *
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
 *      59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *----------------------------------------------------------------------
 */

/**
 * @ingroup lib
 * @file
 *
 * Get default gateway address.
 *
 * @author Raphael Manfredi
 * @date 2011
 */

#include "common.h"

RCSID("$Id$")

#ifdef I_NET_ROUTE
#include <net/route.h>
#endif

#if defined(I_LINUX_NETLINK) && defined(I_LINUX_RTNETLINK)
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#define USE_NETLINK
#endif

#include "getgateway.h"
#include "host_addr.h"
#include "ascii.h"
#include "misc.h"
#include "parse.h"

#include "override.h"			/* Must be the last header included */

/**
 * Compute default gateway address.
 *
 * If there are two default gateways (e.g. one for IPv4 and one for IPv6),
 * either one can be returned.
 *
 * @param addrp		where gateway address is to be written
 *
 * @return 0 on success, -1 on failure with errno set.
 */
int
getgateway(host_addr_t *addrp)
#if defined(MINGW32)
{
	guint32 ip;

	if (-1 == mingw_getgateway(&ip))
		return -1;

	*addrp = host_addr_get_ipv4(ip);
	return 0;
}
#elif defined(USE_NETLINK)
{
	int fd;
	char buf[1024];
	struct nlmsghdr *nl;
	struct rtmsg *rt;
	ssize_t rw;
	unsigned seq = 1;
	unsigned pid = getpid();
	host_addr_t gateway;
	gboolean done;

	/*
	 * This implementation uses the linux netlink interface.
	 */

	fd = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
	if (-1 == fd)
		return -1;

	memset(buf, 0, sizeof buf);
	nl = (struct nlmsghdr *) buf;
	nl->nlmsg_len = NLMSG_LENGTH(sizeof *rt);
	nl->nlmsg_type = RTM_GETROUTE;
	nl->nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST;
	nl->nlmsg_seq = seq;
	nl->nlmsg_pid = pid;

	rt = (struct rtmsg *) NLMSG_DATA(nl);
	rt->rtm_family = AF_UNSPEC;
	rt->rtm_table = RT_TABLE_MAIN;

	rw = send(fd, nl, sizeof *rt + sizeof *nl, 0);
	if (UNSIGNED(rw) != sizeof *rt + sizeof *nl)
		goto error;

	for (done = FALSE; !done; /* empty */) {
		unsigned nlen;

		rw = recv(fd, buf, sizeof buf, 0);
		if ((ssize_t) -1 == rw) {
			g_warning("getgateway(): recv() failed: %s", g_strerror(errno));
			goto error;
		}

		nl = (struct nlmsghdr *) buf;

		if (0 == NLMSG_OK(nl, UNSIGNED(rw)) || NLMSG_ERROR == nl->nlmsg_type)
			goto error;

		if (nl->nlmsg_seq != seq || nl->nlmsg_pid != pid)
			continue;

		if (!(nl->nlmsg_flags & NLM_F_MULTI) || NLMSG_DONE == nl->nlmsg_type)
			done = TRUE;

		/*
		 * Parse each message in the reply.
		 */

		for (
			nlen = UNSIGNED(rw);
			NLMSG_OK(nl, nlen);
			nl = NLMSG_NEXT(nl, nlen)
		) {
			struct rtattr *attr;
			unsigned rlen;

			rt = (struct rtmsg *) NLMSG_DATA(nl);

			if (rt->rtm_table != RT_TABLE_MAIN)
				continue;

			if (rt->rtm_family != AF_INET && rt->rtm_family != AF_INET6)
				continue;

			/* 
			 * Look for an attribute of type RTA_GATEWAY.
			 */

			for (
				rlen = RTM_PAYLOAD(nl), attr = (struct rtattr *) RTM_RTA(rt);
				RTA_OK(attr, rlen);
				attr = RTA_NEXT(attr, rlen)
			) {
				if (RTA_GATEWAY == attr->rta_type) {
					if (AF_INET == rt->rtm_family) {
						struct in_addr *in = (struct in_addr *) RTA_DATA(attr);
						gateway = host_addr_peek_ipv4(&in->s_addr);
						goto found;
					} else if (AF_INET6 == rt->rtm_family) {
						struct in6_addr *in =
							(struct in6_addr *) RTA_DATA(attr);
						gateway = host_addr_peek_ipv6(in->s6_addr);
						goto found;
					}
				}
			}
		}
	}

	/* FALL THROUGH */

error:
	close(fd);
	errno = ENETUNREACH;
	return -1;

found:
	close(fd);
	*addrp = gateway;
	return 0;
}
#else
{
	FILE *f = NULL;
	char tmp[80];
	guint32 gate = 0;

	/*
	 * This implementation should be a safe default on UNIX platforms, but
	 * it is inefficient and as such can only constitute a fallback.
	 */

	if (-1 != access("/bin/netstat", X_OK)) {
		f = popen("/bin/netstat -rn", "r");
	} else if (-1 != access("/usr/bin/netstat", X_OK)) {
		f = popen("/usr/bin/netstat -rn", "r");
	}

	if (NULL == f) {
		errno = ENOENT;		/* netstat not found */
		return -1;
	}

	/*
	 * Typical netstat -rn output:
	 *
	 * Destination        Gateway            Flags .....
	 * 0.0.0.0            192.168.0.200      UG
	 * default            192.168.0.200      UG
	 *
	 * Some systems like linux display "0.0.0.0", but traditional UNIX
	 * output is "default" for the default route.
	 */

	while (fgets(tmp, sizeof tmp, f)) {
		char *p;
		guint32 ip;

		p = is_strprefix(tmp, "default");
		if (NULL == p)
			p = is_strprefix(tmp, "0.0.0.0");

		if (NULL == p || !is_ascii_space(*p))
			continue;

		ip = string_to_ip(p);
		if (ip != 0) {
			gate = ip;
			break;
		}
	}

	pclose(f);

	if (0 == gate) {
		errno = ENETUNREACH;
		return -1;
	}

	*addrp = host_addr_get_ipv4(gate);
	return 0;
}
#endif

/* vi: set ts=4 sw=4 cindent: */
