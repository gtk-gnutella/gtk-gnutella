/*
 * $Id: guid.h 9304 2005-08-27 14:54:28Z rmanfredi $
 *
 * Copyright (c) 2006, Raphael Manfredi
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
 * Kademlia Unique ID (KUID) manager.
 *
 * @author Raphael Manfredi
 * @date 2006
 */

#ifndef _dht_kuid_h_
#define _dht_kuid_h_

#include <glib.h>

#define KUID_RAW_SIZE	20

/*
 * Public interface.
 */

void kuid_init(void);
void kuid_random_fill(gchar *kuid);
gint kuid_cmp(const gchar *target, const gchar *kuid1, const gchar *kuid2);

#endif /* _dht_kuid_h_ */

