/*
 * Copyright (c) 2001-2003, Raphael Manfredi, Richard Eckart
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

/**
 * @ingroup core
 * @file
 *
 * gtk-gnutella configuration.
 *
 * @author Raphael Manfredi
 * @author Richard Eckart
 * @date 2001-2003
 */

#ifndef _core_settings_h_
#define _core_settings_h_

#include "common.h"
#include "hcache.h"		/* For host_net_t */

#include "if/core/settings.h"
#include "lib/host_addr.h"
#include "lib/file.h"	/* For file_path_t */

/**
 * Global Data.
 */

extern struct in_addr *local_netmasks;

/*
 * Global Functions
 */

bool is_my_address(const host_addr_t addr);
bool is_my_address_and_port(const host_addr_t addr, uint16 port);

void settings_early_init(void);
void settings_unique_instance(bool is_supervisor);
bool settings_is_unique_instance(void);
void settings_init(bool resume);
void settings_save_if_dirty(void);
void settings_random_save(bool verbose);
void settings_shutdown(void);
void settings_addr_changed(const host_addr_t new_addr, const host_addr_t peer);
uint32 settings_max_msg_size(void);
void settings_add_randomness();
void settings_close(void);
void settings_terminate(void);
void settings_create_listening_sockets(void);

uint32 get_average_servent_uptime(time_t now);
uint32 get_average_ip_lifetime(time_t now, enum net_type net);

bool settings_is_leaf(void);
bool settings_is_ultra(void);
bool settings_use_ipv4(void);
bool settings_use_ipv6(void);
bool settings_running_ipv4(void);
bool settings_running_ipv6(void);
bool settings_running_ipv4_and_ipv6(void);
bool settings_running_ipv6_only(void);
bool settings_running_same_net(const host_addr_t addr);
bool settings_can_connect(const host_addr_t addr);

host_addr_t listen_addr_primary(void);
host_addr_t listen_addr_primary_net(host_net_t net);

/**
 * Flags for settings_file_path_load().
 */
#define SFP_DFLT		0			/**< Defaults */
#define SFP_NO_CONFIG	(1U << 0)	/**< Don't include the config directory */
#define SFP_ALL			(1U << 1)	/**< Include all fallbacks */

uint settings_file_path_load(file_path_t fp[], const char *file, uint flags);

#endif /* _core_settings_h_ */

/* vi: set ts=4 sw=4 cindent: */
