/*
 * Copyright (c) 2006-2008, Raphael Manfredi
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
 * @ingroup dht
 * @file
 *
 * Kademlia nodes.
 *
 * @author Raphael Manfredi
 * @date 2006-2008
 */

#ifndef _dht_knode_h_
#define _dht_knode_h_

#include "common.h"

#include "if/dht/knode.h"

#define KNODE_MAX_TIMEOUTS	5			/**< Max is 5 timeouts in a row */

/*
 * Public interface.
 */

knode_t *knode_new(
	const kuid_t *id, uint8 flags,
	host_addr_t addr, uint16 port, vendor_code_t vcode,
	uint8 major, uint8 minor);
knode_t *knode_clone(const knode_t *kn);
void knode_change_vendor(knode_t *kn, vendor_code_t vcode);
void knode_change_version(knode_t *kn, uint8 major, uint8 minor);
bool knode_can_recontact(const knode_t *kn);
bool knode_is_usable(const knode_t *kn);
bool knode_addr_is_usable(const knode_t *kn);
double knode_still_alive_probability(const knode_t *kn);

#endif /* _dht_knode_h_ */

/* vi: set ts=4 sw=4 cindent: */
