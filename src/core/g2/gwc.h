/*
 * Copyright (c) 2001-2003, 2014 Raphael Manfredi
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
 * Gnutella Web Cache.
 *
 * @author Raphael Manfredi
 * @date 2001-2003, 2014
 */

#ifndef _core_g2_gwc_h_
#define _core_g2_gwc_h_

#include "common.h"

/*
 * Public interface.
 */

void gwc_init(void);
void gwc_close(void);

void gwc_store_if_dirty(void);
void gwc_get_hosts(void);
gboolean gwc_is_waiting(void);

#endif /* _core_g2_gwc_h_ */

