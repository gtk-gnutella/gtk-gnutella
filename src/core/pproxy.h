/*
 * Copyright (c) 2002-2003, Raphael Manfredi
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
 * @ingroup core
 * @file
 *
 * Push proxy HTTP management.
 *
 * @author Raphael Manfredi
 * @date 2002-2003
 */

#ifndef _core_pproxy_h_
#define _core_pproxy_h_

#include "common.h"

#include "if/core/pproxy.h"
#include "lib/array.h"
#include "lib/gnet_host.h"
#include "lib/sequence.h"

struct guid;

/***
 *** Server side
 ***/

enum pproxy_magic { PPROXY_MAGIC = 0x037fa833 };

/**
 * A push proxy request we received.
 */
struct pproxy {
	enum pproxy_magic magic;
	struct gnutella_socket *socket;
	int error_sent;		/**< HTTP error code sent back */
	time_t last_update;

	host_addr_t addr_v4;	/**< IPv4 of the requesting servent */
	host_addr_t addr_v6;	/**< IPv6 of the requesting servent */
	uint16 port;			/**< Port where GIV should be sent back */
	const char *user_agent;	/**< User-Agent string */
	const struct guid *guid;/**< GUID (atom) to which push should be sent */
	uint32 file_idx;		/**< File index to request (0 if none supplied) */
	uint32 flags;
	void *io_opaque;		/**< Opaque I/O callback information */
};

static inline void
pproxy_check(const struct pproxy * const p)
{
	g_assert(p != NULL);
	g_assert(PPROXY_MAGIC == p->magic);
}

#define pproxy_vendor_str(p)	((p)->user_agent ? (p)->user_agent : "")

void pproxy_add(struct gnutella_socket *s);
void pproxy_timer(time_t now);
void pproxy_close(void);

/***
 *** Client side
 ***/

struct cproxy *cproxy_create(struct download *d,
	const host_addr_t addr, uint16 port, const struct guid *guid,
	uint32 file_idx);
void cproxy_free(struct cproxy *cp);
void cproxy_reparent(struct download *d, struct download *cd);

struct array build_push(uint8 ttl, uint8 hops,
	const struct guid *guid, host_addr_t addr_v4, host_addr_t addr_v6,
	uint16 port, uint32 file_idx, bool supports_tls);

/***
 *** Push proxy set
 ***/

typedef struct pproxy_set pproxy_set_t;

pproxy_set_t *pproxy_set_allocate(size_t max_proxies);
void pproxy_set_free_null(pproxy_set_t **ps_ptr);
bool pproxy_set_add(pproxy_set_t *ps, const host_addr_t addr, uint16 port);
void pproxy_set_add_vec(pproxy_set_t *ps, const gnet_host_vec_t *vec);
void pproxy_set_add_array(pproxy_set_t *ps,
	gnet_host_t *proxies, int proxy_count);
bool pproxy_set_remove(pproxy_set_t *ps,
	const host_addr_t addr, uint16 port);
size_t pproxy_set_count(const pproxy_set_t *ps);
bool pproxy_set_older_than(const pproxy_set_t *ps, time_t t);
void pproxy_set_foreach(const pproxy_set_t *ps, GFunc func, void *user_data);
gnet_host_t *pproxy_set_head(const pproxy_set_t *ps);
sequence_t *pproxy_set_sequence(const pproxy_set_t *ps);
gnet_host_vec_t *pproxy_set_host_vec(const pproxy_set_t *ps);
const gnet_host_t *pproxy_set_oldest(const pproxy_set_t *ps);

#endif	/* _core_pproxy_h_ */

/* vi: set ts=4 sw=4 cindent: */
