/*
 * Copyright (c) 2003, Christian Biere
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
 * Asynchronous DNS lookup message definitions.
 *
 * @author Christian Biere
 * @date 2003
 */

#ifndef _adns_msg_h_
#define _adns_msg_h_

#include "common.h"
#include "host_addr.h"	/* For ``struct host_addr'' */

enum adns_magic { ADNS_COMMON_MAGIC = 0x05dc21cb };

struct adns_common {
	enum adns_magic magic;
	void (*user_callback)(void);
	void *user_data;
	bool reverse;
};

struct adns_reverse_query {
	host_addr_t addr;
};

struct adns_query {
	enum net_type net;
	char hostname[MAX_HOSTLEN + 1];
};

struct adns_reply {
	char hostname[MAX_HOSTLEN + 1];
	host_addr_t addrs[10];
};

struct adns_reverse_reply {
	char hostname[MAX_HOSTLEN + 1];
	host_addr_t addr;
};

struct adns_request {
	struct adns_common common;
	union {
		struct adns_query by_addr;
		struct adns_reverse_query reverse;
	} query;
};

struct adns_response {
	struct adns_common common;
	union {
		struct adns_reply by_addr;
		struct adns_reverse_reply reverse;
	} reply;
};

#endif /* _adns_msg_h_ */
