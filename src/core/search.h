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

#include "common.h"

#include "nodes.h"

/*
 * Special marking of the "connection speed" field in queries.
 */

#define QUERY_SPEED_MARK		0x0080	/**< Field is special: not a speed */
#define QUERY_SPEED_FIREWALLED	0x0040	/**< Issuing servent is firewalled */
#define QUERY_SPEED_XML			0x0020	/**< Supports XML in result set */
#define QUERY_SPEED_LEAF_GUIDED	0x0010	/**< Leaf-guided query */
#define QUERY_SPEED_GGEP_H		0x0008	/**< Recipient understands GGEP "H" */
#define QUERY_SPEED_OOB_REPLY	0x0004	/**< Out-of-band reply possible */
#define QUERY_SPEED_FW_TO_FW	0x0002	/**< Can do fw to fw transfers */
/**
 * NOTE: At this point all of the bits are exhausted. 0x0001 is not available
 * 		 because the next 9 bits are not available for flags.
 */

#define QUERY_FW2FW_FILE_INDEX	0x7FFFFFFD	/**< Magic index for fw-fw reqs */

struct download;

/*
 * Global Functions
 */

void search_init(void);
void search_shutdown(void);

gboolean search_results(gnutella_node_t *n, gint *results);
gboolean search_query_allowed(gnet_search_t sh);
guint32 search_get_id(gnet_search_t sh, gpointer *search);
void search_notify_sent(gpointer search, guint32 id, const node_id_t node_id);
void search_add_kept(gnet_search_t sh, guint32 kept);
gboolean search_get_kept_results(const gchar *muid, guint32 *kept);
guint32 search_get_kept_results_by_handle(gnet_search_t sh);
void search_oob_pending_results(gnutella_node_t *n, const gchar *muid,
	gint hits, gboolean udp_firewalled, gboolean secure);

void search_dissociate_browse(gnet_search_t sh, struct download *d);
void search_browse_results(gnutella_node_t *n, gnet_search_t sh);

gboolean search_request_preprocess(struct gnutella_node *n);
gboolean search_request(struct gnutella_node *n, struct query_hashvec *qhv);
size_t compact_query(gchar *search);
void query_strip_oob_flag(const struct gnutella_node *n, gchar *data);
void query_set_oob_flag(const struct gnutella_node *n, gchar *data);

void record_query_string(const gchar muid[GUID_RAW_SIZE], const gchar *query);
const gchar *map_muid_to_query_string(const gchar muid[GUID_RAW_SIZE]);

#endif /* _core_search_h_ */

/* vi: set ts=4 sw=4 cindent: */
