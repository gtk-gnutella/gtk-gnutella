/*
 * $Id$
 *
 * Copyright (c) 2002-2003, Raphael Manfredi
 *
 * Query Routing Protocol (LimeWire's scheme).
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

#ifndef _qrp_h_
#define _qrp_h_

#include "gnutella.h"

#include <glib.h>
#include "ui_core_interface_qrp_defs.h"
#include "ui_core_interface_nodes_defs.h"


/*
 * Public interface.
 */


guint32 qrp_hashcode(gchar *x);

void qrp_init(char_map_t map);
void qrp_close(void);

void qrp_leaf_changed(void);
void qrp_peermode_changed(void);

void qrp_prepare_computation(void);
void qrp_add_file(struct shared_file *sf);
void qrp_finalize_computation(void);

gpointer qrt_update_create(struct gnutella_node *n, gpointer query_table);
void qrt_update_free(gpointer handle);
gboolean qrt_update_send_next(gpointer handle);
gboolean qrt_update_was_ok(gpointer handle);

gpointer qrt_receive_create(struct gnutella_node *n, gpointer query_table);
void qrt_receive_free(gpointer handle);
gboolean qrt_receive_next(gpointer handle, gboolean *done);

gpointer qrt_get_table(void);
gpointer qrt_ref(gpointer obj);
void qrt_unref(gpointer obj);
void qrt_get_info(gpointer obj, qrt_info_t *qi);

struct query_hashvec *qhvec_alloc(gint size);
void qhvec_free(struct query_hashvec *qhvec);
void qhvec_reset(struct query_hashvec *qhvec);
query_hashvec_t * qhvec_clone(query_hashvec_t *qsrc);
gboolean qhvec_has_source(query_hashvec_t *qhvec, enum query_hsrc src);
void qhvec_add(struct query_hashvec *qhvec, gchar *word, enum query_hsrc src);

GSList *qrt_build_query_target(
	query_hashvec_t *qhvec, gint hops, gint ttl, struct gnutella_node *source);
void qrt_route_query(struct gnutella_node *n, query_hashvec_t *qhvec);
gboolean qrp_node_can_route(struct gnutella_node *n, query_hashvec_t *qhv);

#endif	/* _qrp_h_ */

/* vi: set ts=4: */
