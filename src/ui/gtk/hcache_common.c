/*
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

#include "hcache_common.h"
#include "gtk/notebooks.h"

#include "lib/override.h"		/* Must be the last header included */

/**
 * Gets the host cache names.
 */
const gchar *
get_hcache_name(hcache_type_t type)
{
	switch (type) {
	case HCACHE_FRESH_ANY:    return _("Fresh regular");
	case HCACHE_VALID_ANY:    return _("Valid regular");
	case HCACHE_FRESH_ULTRA:  return _("Fresh IPv4 ultra");
	case HCACHE_VALID_ULTRA:  return _("Valid IPv4 ultra");
	case HCACHE_FRESH_ULTRA6: return _("Fresh IPv6 ultra");
	case HCACHE_VALID_ULTRA6: return _("Valid IPv6 ultra");
	case HCACHE_FRESH_G2HUB:  return _("Fresh G2 hub");
	case HCACHE_VALID_G2HUB:  return _("Valid G2 hub");
	case HCACHE_TIMEOUT:      return _("Timeout");
	case HCACHE_BUSY:         return _("Busy");
	case HCACHE_UNSTABLE:     return _("Unstable");
	case HCACHE_ALIEN:        return _("Alien");
	case HCACHE_GUESS:        return _("GUESS (IPv4 running)");
	case HCACHE_GUESS_INTRO:  return _("GUESS (IPv4 introductions)");
	case HCACHE_GUESS6:       return _("GUESS (IPv6 running)");
	case HCACHE_GUESS6_INTRO: return _("GUESS (IPv6 introductions)");
	case HCACHE_NONE:
	case HCACHE_MAX:
		break;
	}
	g_carp("%s(): unknown hcache %d", G_STRFUNC, type);
	return "";
}

static gboolean
hcache_gui_is_visible(void)
{
	return main_gui_window_visible() &&
		nb_main_page_hostcache == main_gui_notebook_get_page();
}

void
hcache_gui_timer(time_t now)
{
	static time_t last_update;

	if (last_update != now && hcache_gui_is_visible()) {
		last_update = now;
		hcache_gui_update_display();
	}
}

/* vi: set ts=4 sw=4 cindent: */

