/*
 * $Id$
 *
 * Copyright (c) 2002, Raphael Manfredi
 *
 * Host cache management.
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

#ifndef _hcache_h_
#define _hcache_h_

#include <glib.h>

struct gnutella_host;

typedef enum {
	HCACHE_ANY = 0,				/* Any node */
	HCACHE_ULTRA,				/* Ultra nodes */
	HCACHE_MAX,
} hcache_type_t;

/*
 * Global Functions
 */

void hcache_init(void);
void hcache_close(void);

gchar *hcache_type_to_gchar(hcache_type_t type);

void hcache_save_valid(hcache_type_t type, guint32 ip, guint16 port);

gboolean hcache_add(hcache_type_t type, guint32 ip, guint16 port, gchar *what);
void hcache_clear(hcache_type_t type);
void hcache_prune(hcache_type_t type) ;

gint hcache_size(hcache_type_t type);
gboolean hcache_is_low(hcache_type_t type);

gint hcache_fill_caught_array(
	hcache_type_t type, struct gnutella_host *hosts, gint hcount);

void hcache_get_caught(hcache_type_t type, guint32 *ip, guint16 *port);
gboolean hcache_find_nearby(hcache_type_t type, guint32 *ip, guint16 *port);

void hcache_retrieve(hcache_type_t type);
void hcache_store(hcache_type_t type);

#endif /* _hcache_h_ */

