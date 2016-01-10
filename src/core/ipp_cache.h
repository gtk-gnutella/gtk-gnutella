/*
 * Copyright (c) 2009, Raphael Manfredi
 * Copyright (c) 2006, Christian Biere
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
 * Caching of hosts by IP:port.
 *
 * @author Raphael Manfredi
 * @date 2009
 * @author Christian Biere
 * @date 2006
 */

#ifndef _core_ipp_cache_h_
#define _core_ipp_cache_h_

#include "common.h"

#include "lib/host_addr.h"

typedef struct ipp_cache ipp_cache_t;

enum ipp_cache_id {
	IPP_CACHE_TLS = 0,		/**< Cache for TLS hosts */
	IPP_CACHE_G2,			/**< Cache for "G2" hosts */
	IPP_CACHE_LOCAL_ADDR,	/**< Cache for hosts's past IP:port combinations */

	IPP_CACHE_COUNT
};

void ipp_cache_insert(enum ipp_cache_id cid,
	const host_addr_t addr, uint16 port);
bool ipp_cache_lookup(enum ipp_cache_id cid,
	const host_addr_t addr, uint16 port);
time_t ipp_cache_get_timestamp(enum ipp_cache_id cid,
	const host_addr_t addr, uint16 port);
bool ipp_cache_remove(enum ipp_cache_id cid,
	const host_addr_t addr, uint16 port);

void ipp_cache_init(void);
void ipp_cache_load_all(void);
void ipp_cache_save_all(void);
void ipp_cache_close(void);

/*
 * TLS cache convenience routines.
 */

static inline void
tls_cache_insert(const host_addr_t addr, uint16 port)
{
	ipp_cache_insert(IPP_CACHE_TLS, addr, port);
}

static inline void
tls_cache_remove(const host_addr_t addr, uint16 port)
{
	ipp_cache_remove(IPP_CACHE_TLS, addr, port);
}

static inline bool
tls_cache_lookup(const host_addr_t addr, uint16 port)
{
	return ipp_cache_lookup(IPP_CACHE_TLS, addr, port);
}

static inline time_t
tls_cache_get_timestamp(const host_addr_t addr, uint16 port)
{
	return ipp_cache_get_timestamp(IPP_CACHE_TLS, addr, port);
}

/*
 * G2 cache convenience routines.
 */

static inline void
g2_cache_insert(const host_addr_t addr, uint16 port)
{
	ipp_cache_insert(IPP_CACHE_G2, addr, port);
}

static inline bool
g2_cache_lookup(const host_addr_t addr, uint16 port)
{
	return ipp_cache_lookup(IPP_CACHE_G2, addr, port);
}

/*
 * Local IP:port cache convenience routines.
 */

static inline void
local_addr_cache_insert(const host_addr_t addr, uint16 port)
{
	ipp_cache_insert(IPP_CACHE_LOCAL_ADDR, addr, port);
}

static inline bool
local_addr_cache_lookup(const host_addr_t addr, uint16 port)
{
	return ipp_cache_lookup(IPP_CACHE_LOCAL_ADDR, addr, port);
}

#endif /* _core_ipp_cache_h_ */

/* vi: set ts=4 sw=4 cindent: */
