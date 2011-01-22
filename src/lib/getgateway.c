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

#include "getgateway.h"
#include "host_addr.h"

#include "override.h"			/* Must be the last header included */
#include "ascii.h"
#include "misc.h"
#include "parse.h"

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
