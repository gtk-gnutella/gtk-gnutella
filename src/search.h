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

#ifndef _search_h_
#define _search_h_

#include "nodes.h"

/*
 * Special marking of the "connection speed" field in queries.
 */

#define QUERY_SPEED_MARK		0x0080		/* Field is special: not a speed */
#define QUERY_SPEED_FIREWALLED	0x0040		/* Issuing servent is firewalled */
#define QUERY_SPEED_NO_XML		0x0020		/* No XML in result set, please */
#define QUERY_SPEED_LEAF_GUIDED	0x0010		/* Leaf-guided query */
#define QUERY_SPEED_GGEP_H		0x0008		/* Recipient understands GGEP "H" */
#define QUERY_SPEED_OOB_REPLY	0x0004		/* Out-of-band reply possible */

/*
 * Global Functions
 */

void search_init(void);
void search_shutdown(void);

gboolean search_results(gnutella_node_t *n);
gboolean search_query_allowed(gnet_search_t sh);
void search_update_items(gnet_search_t sh, guint items);

#endif /* _search_h_ */

