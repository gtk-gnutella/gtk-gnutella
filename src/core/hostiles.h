/*
 * $Id$
 *
 * Copyright (c) 2003, Markus Goetz & Raphael Manfredi
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
 * Support for the hostiles.txt of BearShare.
 *
 * @author Markus Goetz
 * @author Raphael Manfredi
 * @date 2003
 */

#ifndef _core_hostiles_h_
#define _core_hostiles_h_

#include "common.h"
#include "lib/host_addr.h"

void hostiles_init(void);
void hostiles_close(void);

gboolean hostiles_check(const host_addr_t addr);
gboolean hostiles_spam_check(const host_addr_t addr, guint16 port);

void hostiles_dynamic_add(const host_addr_t addr, const char *reason);
void hostiles_spam_add(const host_addr_t addr, guint16 port);

#endif /* _core_hostiles_h_ */

/* vi: set ts=4 sw=4 cindent: */
