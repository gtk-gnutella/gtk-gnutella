/*
 * $Id$
 *
 * Copyright (c) 2001-2003, Raphael Manfredi
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
 * Search handling (core side).
 *
 * @author Raphael Manfredi
 * @date 2001-2003
 */

#ifndef _core_search_h_
#define _core_search_h_

#include "nodes.h"

/*
 * Special marking of the "connection speed" field in queries.
 */

#define QUERY_SPEED_MARK		0x0080	/**< Field is special: not a speed */
#define QUERY_SPEED_FIREWALLED	0x0040	/**< Issuing servent is firewalled */
#define QUERY_SPEED_NO_XML		0x0020	/**< No XML in result set, please */
#define QUERY_SPEED_LEAF_GUIDED	0x0010	/**< Leaf-guided query */
#define QUERY_SPEED_GGEP_H		0x0008	/**< Recipient understands GGEP "H" */
#define QUERY_SPEED_OOB_REPLY	0x0004	/**< Out-of-band reply possible */
#define QUERY_SPEED_FW_TO_FW	0x0002	/**< Can do fw to fw transfers */

#define QUERY_FW2FW_FILE_INDEX	0x7FFFFFFD	/**< Magic index for fw-fw reqs */

/*
 * Global Functions
 */

void search_init(void);
void search_shutdown(void);

gboolean search_results(gnutella_node_t *n, gint *results);
gboolean search_query_allowed(gnet_search_t sh);
guint32 search_get_id(gnet_search_t sh, gpointer *search);
void search_notify_sent(gpointer search, guint32 id, guint32 node_id);
void search_add_kept(gnet_search_t sh, guint32 kept);
gboolean search_get_kept_results(gchar *muid, guint32 *kept);
guint32 search_get_kept_results_by_handle(gnet_search_t sh);
void search_oob_pending_results(
	gnutella_node_t *n, gchar *muid, gint hits, gboolean udp_firewalled);

void search_dissociate_browse(gnet_search_t sh, gpointer download);
void search_browse_results(gnutella_node_t *n, gnet_search_t sh);

#endif /* _core_search_h_ */

/* vi: set ts=4 sw=4 cindent: */
