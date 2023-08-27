/*
 * Copyright (c) 2004, Raphael Manfredi
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
 *      51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *----------------------------------------------------------------------
 */

#ifndef _if_core_settings_h_
#define _if_core_settings_h_

/*
 * Public interface, visible from the bridge.
 */

#ifdef CORE_SOURCES

#include "lib/host_addr.h"

host_addr_t listen_addr(void);
host_addr_t listen_addr6(void);
host_addr_t listen_addr_by_net(enum net_type net);
const char *settings_config_dir(void);
const char *settings_home_dir(void);
const char *settings_crash_dir(void);
const char *settings_local_socket_path(void);
const char *settings_gnet_db_dir(void);
const char *settings_dht_db_dir(void);
enum net_type settings_dns_net(void);

#endif /* CORE_SOURCES */
#endif /* _if_core_settings_h */

/* vi: set ts=4 sw=4 cindent: */
