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
 *      59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *----------------------------------------------------------------------
 */

#ifndef _gnet_search_h_
#define _gnet_search_h_

#include "common.h"
#include "ui_core_interface_gnet_search_defs.h"


/*
 * Search public interface
 */
gnet_search_t search_new
    (const gchar *, guint16 min_speed, guint32 timeout, flag_t flags);
void search_close(gnet_search_t sh);

void search_start(gnet_search_t sh);
void search_stop(gnet_search_t sh);

/*  search_is_stopped doesn't exist yet! 
gboolean search_is_stopped(gnet_search_t sh);
*/

void search_reissue(gnet_search_t sh);

gboolean search_is_passive(gnet_search_t sh);
gboolean search_is_frozen(gnet_search_t sh);

void search_set_reissue_timeout(gnet_search_t sh, guint32 timeout);
guint32 search_get_reissue_timeout(gnet_search_t sh);

void search_free_alt_locs(gnet_record_t *rc);
void search_free_proxies(gnet_results_set_t *rs);

#endif /* _gnet_search_h_ */
