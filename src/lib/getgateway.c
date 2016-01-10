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

#ifdef I_NET_ROUTE
#include <net/route.h>
#endif

#if defined(I_LINUX_NETLINK) && defined(I_LINUX_RTNETLINK)
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#define USE_NETLINK
#endif

#include "getgateway.h"

#include "ascii.h"
#include "compat_usleep.h"
#include "fd.h"
#include "host_addr.h"
#include "mempcpy.h"
#include "misc.h"
#include "parse.h"
#include "spinlock.h"
#include "timestamp.h"
#include "tm.h"

#include "override.h"			/* Must be the last header included */

/**
 * Default implementation to get the default gateway by parsing the
 * output of the "netstat -rn" command.
 *
 * @param addrp		where gateway address is to be written
 *
 * @return 0 on success, -1 on failure with errno set.
 */
static int G_COLD
parse_netstat(host_addr_t *addrp)
#ifdef HAS_POPEN
{
	FILE *f = NULL;
	char tmp[80];
	uint32 gate = 0;

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
		uint32 ip;

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
#else
{
	static bool warned;

	(void) addrp;

	if (!warned) {
		g_warning("%s(): no popen() on this platform", G_STRFUNC);
		warned = TRUE;
	}

	errno = ENOTSUP;
	return -1;
}
#endif	/* HAS_POPEN */

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
int G_COLD
getgateway(host_addr_t *addrp)
#if defined(MINGW32)
{
	uint32 ip;

	if (-1 == mingw_getgateway(&ip)) {
		g_warning("%s(): GetBestRoute() failed: %m", G_STRFUNC);
		return parse_netstat(addrp);	/* Avoids "unused function" warning */
	}

	*addrp = host_addr_get_ipv4(ip);
	return 0;
}
#elif defined(USE_NETLINK)
{
	int fd;
	ssize_t rw;
	unsigned seq = 1;
	__u32 pid = getpid(); /* not pid_t because nlmsg_pid is of type __u32 */
	host_addr_t gateway;
	bool done;
	struct {
		struct nlmsghdr hdr;
		struct rtmsg rtm;
		unsigned char space[1024];	/* Unexplained magic buffer size */
	} nlm;
	static host_addr_t gw;			/* Previously computed gateway */
	static time_t gw_time;			/* When it was computed */
	static spinlock_t gw_slk = SPINLOCK_INIT;

	/*
	 * This implementation uses the linux netlink interface.
	 */

	fd = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
	if (-1 == fd)
		goto error;

	ZERO(&nlm);
	nlm.hdr.nlmsg_len = NLMSG_LENGTH(sizeof nlm.rtm);
	nlm.hdr.nlmsg_type = RTM_GETROUTE;
	nlm.hdr.nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST;
	nlm.hdr.nlmsg_seq = seq;
	nlm.hdr.nlmsg_pid = pid;

	nlm.rtm.rtm_family = AF_UNSPEC;
	nlm.rtm.rtm_table = RT_TABLE_MAIN;

	rw = send(fd, &nlm, sizeof nlm.hdr + sizeof nlm.rtm, 0);
	if (UNSIGNED(rw) != sizeof nlm.hdr + sizeof nlm.rtm)
		goto error;

	for (done = FALSE; !done; /* empty */) {
		unsigned nlen;
		struct nlmsghdr *nl;
		int i;

		/*
		 * Unfortunately, the recv() call is non-blocking and can sometimes
		 * return EAGAIN, multiple times.  Hence the loop and the usleep().
		 */

		for (i = 0; i < 1000; i++) {
			rw = recv(fd, &nlm, sizeof nlm, MSG_DONTWAIT);
			if ((ssize_t) -1 == rw) {
				if (EAGAIN == errno || EWOULDBLOCK == errno) {
					compat_usleep(1000);	/* 1 ms */
					continue;
				}
				break;
			} else {
				goto answered;
			}
		}

		if (EAGAIN == errno || EWOULDBLOCK == errno)
			goto try_cached;

		g_warning("%s(): recv() failed: %m", G_STRFUNC);
		goto error;

	answered:
		nl = &nlm.hdr;

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
			const struct rtmsg *rt;
			unsigned rlen;

			rt = (const struct rtmsg *) NLMSG_DATA(nl);

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
	fd_close(&fd);
	g_warning("%s(): netlink failed, using the netstat command", G_STRFUNC);
	return parse_netstat(addrp);

found:
	fd_close(&fd);
	*addrp = gateway;

	/*
	 * Save compute gateway in case we cannot compute it next time we are
	 * called due to the kernel being busy.
	 */

	spinlock(&gw_slk);
	gw = gateway;
	gw_time = tm_time();
	spinunlock(&gw_slk);

	return 0;

try_cached:
	/*
	 * Could not get a reply, see if we can return previously computed
	 * information if it is not too ancient (less than 60 secs ago).
	 */

	spinlock(&gw_slk);
	if (is_host_addr(gw) && delta_time(tm_time(), gw_time) < 60) {
		gateway = gw;
		spinunlock(&gw_slk);
		goto found;
	}

	spinunlock(&gw_slk);
	goto error;
}
#elif defined(I_NET_ROUTE) && defined(PF_ROUTE) && defined(RTM_GET)
{
	int fd;
	struct sockaddr dest, mask;
	struct sockaddr *gate;
	char *p;
	ssize_t rw;
	int seq = 1;
	pid_t pid = getpid();
	host_addr_t gateway;
	struct {
		struct rt_msghdr head;
		char data[512];
	} rtm;
	struct rt_msghdr * const rt = &rtm.head;
	char * const payload = rtm.data;

	/*
	 * This implementation uses the BSD route socket interface.
	 */

	fd = socket(PF_ROUTE, SOCK_RAW, 0);
	if (-1 == fd)
		goto error;

	ZERO(rt);
	ZERO(&dest);
	ZERO(&mask);

	rt->rtm_type = RTM_GET;
	rt->rtm_flags = RTF_UP | RTF_GATEWAY;
	rt->rtm_version = RTM_VERSION;
	rt->rtm_seq = seq;
	rt->rtm_addrs = RTA_DST | RTA_NETMASK;

	dest.sa_family = AF_UNSPEC;
	mask.sa_family = AF_UNSPEC;

	STATIC_ASSERT(2 * sizeof dest <= sizeof rtm.data);

	p = payload;
	p = mempcpy(p, &dest, sizeof dest);
	p = mempcpy(p, &mask, sizeof mask);

	rt->rtm_msglen = (p - payload) + sizeof *rt;

	g_assert(rt->rtm_msglen <= sizeof rtm);

	rw = write(fd, rt, rt->rtm_msglen);
	if (UNSIGNED(rw) != rt->rtm_msglen)
		goto error;

	for (;;) {
		rw = read(fd, &rtm, sizeof rtm);

		if ((ssize_t) -1 == rw)
			goto error;

		if (rt->rtm_seq == seq && rt->rtm_pid == pid)
			break;
	}

	fd_close(&fd);

	if (rt->rtm_addrs != 0) {
		unsigned bitmask;

		p = payload;
		for (bitmask = 1; 0 != bitmask; bitmask <<= 1) {
			g_assert(ptr_diff(p, payload) < sizeof rtm.data);

			if (rt->rtm_addrs & bitmask) {
				if (RTA_GATEWAY & bitmask) {
					gate = (struct sockaddr *) p;
					g_assert(ptr_diff(gate + 1, payload) <= sizeof rtm.data);
					goto got_gateway;
				}
				p += sizeof *gate;
			}
		}
	}

	goto error;

got_gateway:
	{
		struct sockaddr sa;

		/*
		 * The "gate" address may not be aligned.
		 *
		 * Note that on FreeBSD, the AF_INET6 gateway seems to never be
		 * returned.  Moreover the size of "struct sockaddr" is lower than
		 * that of "struct sockaddr_in6" so the code above that skips
		 * addresses in the reply until it finds an RTA_GATEWAY one may
		 * be incorrect the day BSD starts to return AF_INET6.
		 *		--RAM, 2011-01-27
		 */

		memcpy(&sa, gate, sizeof sa);

		if (AF_INET == sa.sa_family) {
			struct sockaddr_in sin;
			memcpy(&sin, gate, sizeof sin);
			gateway = host_addr_peek_ipv4(&sin.sin_addr.s_addr);
			goto found;
		} else if (AF_INET6 == sa.sa_family) {
			struct sockaddr_in6 sin6;
			memcpy(&sin6, gate, sizeof sin6);
			gateway = host_addr_peek_ipv6(sin6.sin6_addr.s6_addr);
			goto found;
		}
	}

	/* FALL THROUGH */

error:
	fd_close(&fd);
	g_warning("%s(): route socket failed, using the netstat command",
		G_STRFUNC);
	return parse_netstat(addrp);

found:
	fd_close(&fd);
	*addrp = gateway;
	return 0;
}
#else
{
	static bool warned;

	/*
	 * Let's get information about which systems cannot benefit from a
	 * native faster interface to get the default gateway.
	 */

	if (!warned) {
		g_warning("%s(): using the slow netstat command", G_STRFUNC);
		warned = TRUE;
	}

	return parse_netstat(addrp);
}
#endif

/* vi: set ts=4 sw=4 cindent: */
