/*
 * $Id$
 *
 * Copyright (c) 2008, Raphael Manfredi
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
 * Accounting.
 *
 * @author Raphael Manfredi
 * @date 2008
 */

#ifndef _dht_acct_h_
#define _dht_acct_h_

#include "lib/host_addr.h"

#define NET_CLASS_C_MASK	0xffffff00U		/**< Class C network mask */
#define NET_IPv4_MASK		0xffffffffU		/**< IPv4 address mask */


/*
 * Public interface.
 */

GHashTable *acct_net_create(void);
int acct_net_get(GHashTable *ht, host_addr_t addr, guint32 mask);
void acct_net_update(GHashTable *ht, host_addr_t addr, guint32 mask, int pmone);
void acct_net_free(GHashTable **hptr);

#endif /* _dht_acct_h_ */

/* vi: set ts=4 sw=4 cindent: */
