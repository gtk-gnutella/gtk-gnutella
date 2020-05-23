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

/**
 * @ingroup core
 * @file
 *
 * Support for geographic IP mapping.
 *
 * @author Raphael Manfredi
 * @date 2004
 */

#ifndef _core_geo_ip_h_
#define _core_geo_ip_h_

#include "common.h"
#include "lib/host_addr.h"

void gip_init(void);
void gip_close(void);

uint16 gip_country(const host_addr_t addr);
uint16 gip_country_safe(const host_addr_t ha);

const char *gip_country_cc(const host_addr_t ha);
const char *gip_country_name(const host_addr_t ha);

#endif /* _core_geo_ip_h_ */

/* vi: set ts=4 sw=4 cindent: */
