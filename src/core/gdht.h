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
 * @ingroup core
 * @file
 *
 * Gnutella DHT interface.
 *
 * @author Raphael Manfredi
 * @date 2008
 */

#ifndef _core_gdht_h_
#define _core_gdht_h_

#include "if/core/fileinfo.h"

/*
 * Public interface.
 */

void gdht_init(void);
void gdht_close(void);

void gdht_find_sha1(const fileinfo_t *fi);
void gdht_find_guid(const char *guid, const host_addr_t addr, guint16 port);

#endif	/* _core_gdht_h_ */

/* vi: set ts=4 sw=4 cindent: */
