/*
 * $Id$
 *
 * Copyright (c) 2002, Raphael Manfredi
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

#define QRP_MIN_WORD_LENGTH		3		/* Minimal word length */

/*
 * Query routing: structures to keep track of all the query hashes,
 * and where they come from..
 */

enum query_hsrc {
	QUERY_H_WORD = 0,				/* Query word (AND-ed) */
	QUERY_H_URN,					/* URN (OR-ed) */
};

struct query_hash {
	guint32 hashcode;
	enum query_hsrc source;
};

typedef struct query_hashvec {
	gint count;				/* Amount of slots actually taken */
	gint size;				/* Amount of slots in vector */
	struct query_hash *vec;	/* Vector of at most `size' entries */
} query_hashvec_t;

/*
 * Public interface.
 */

typedef void (*qrp_callback_t)(gpointer arg, gboolean cancelled);

guint32 qrp_hashcode(gchar *x);

void qrp_init(char_map_t map);
void qrp_close(void);

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

struct query_hashvec *qhvec_alloc(gint size);
void qhvec_free(struct query_hashvec *qhvec);
void qhvec_reset(struct query_hashvec *qhvec);
void qhvec_add(struct query_hashvec *qhvec, gchar *word, enum query_hsrc src);

GSList *qrt_build_query_target(
	query_hashvec_t *qhvec, gint hops, struct gnutella_node *source);
void qrt_route_query(struct gnutella_node *n, query_hashvec_t *qhvec);

#endif	/* _qrp_h_ */

/* vi: set ts=4: */

