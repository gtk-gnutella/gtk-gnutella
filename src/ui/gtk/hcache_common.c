/*
 * $Id$
 *
 * Copyright (c) 2001-2003, Richard Eckart
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

#include "gui.h"

RCSID("$Id$")

#include "hcache_common.h"
#include "lib/override.h"		/* Must be the last header included */

/**
 * Gets the host cache names.
 */
const gchar *
get_hcache_name(hcache_type_t type)
{
	switch (type) {
	case HCACHE_FRESH_ANY:   return _("Fresh regular");
	case HCACHE_VALID_ANY:   return _("Valid regular");
	case HCACHE_FRESH_ULTRA: return _("Fresh ultra");
	case HCACHE_VALID_ULTRA: return _("Valid ultra");
	case HCACHE_TIMEOUT:     return _("Timeout");
	case HCACHE_BUSY:        return _("Busy");
	case HCACHE_UNSTABLE:    return _("Unstable");
	case HCACHE_NONE:
	case HCACHE_MAX:
		break;
	}
	g_warning("get_hcache_name: unknown hcache %d", type);
	return "";
}
