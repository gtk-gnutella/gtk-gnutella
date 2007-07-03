/*
 * $Id$
 *
 * Copyright (c) 2002-2003, Raphael Manfredi
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
 * Query Routing Protocol (LimeWire's scheme).
 *
 * @author Raphael Manfredi
 * @date 2002-2003
 */

#ifndef _core_qrp_h_
#define _core_qrp_h_

#include "common.h"

#define QRP_MIN_WORD_LENGTH		3	/**< Minimal word length */

/*
 * Query routing: structures to keep track of all the query hashes,
 * and where they come from..
 */

enum query_hsrc {
	QUERY_H_WORD,		/**< Query word (AND-ed) */
	QUERY_H_URN			/**< URN (OR-ed) */
};

typedef struct qrt_info {
	gint slots;				/**< Amount of slots */
	gint generation;		/**< Generation number */
	gint fill_ratio;		/**< Percentage of slots used */
	gint pass_throw;		/**< Passing throw, on a d100 */
} qrt_info_t;


/*
 * Public interface.
 */

struct gnutella_node;
struct routing_table;
struct shared_file;
struct query_hashvec;

typedef struct query_hashvec query_hashvec_t;

void qrp_init(void);
void qrp_close(void);

void qrp_leaf_changed(void);
void qrp_peermode_changed(void);

void qrp_prepare_computation(void);
void qrp_add_file(struct shared_file *sf);
void qrp_finalize_computation(void);

struct qrt_update *qrt_update_create(struct gnutella_node *n,
						struct routing_table *);
void qrt_update_free(struct qrt_update *);
gboolean qrt_update_send_next(struct qrt_update *);
gboolean qrt_update_was_ok(struct qrt_update *);

struct qrt_receive *qrt_receive_create(struct gnutella_node *n,
						struct routing_table *);
void qrt_receive_free(struct qrt_receive *);
gboolean qrt_receive_next(struct qrt_receive *, gboolean *done);

struct routing_table *qrt_get_table(void);
struct routing_table *qrt_ref(struct routing_table *);
void qrt_unref(struct routing_table *);
void qrt_get_info(const struct routing_table *, qrt_info_t *qi);

struct query_hashvec *qhvec_alloc(gint size);
void qhvec_free(struct query_hashvec *qhvec);
void qhvec_reset(struct query_hashvec *qhvec);
query_hashvec_t * qhvec_clone(const query_hashvec_t *qsrc);
void qhvec_add(struct query_hashvec *qhvec, const gchar *word,
	enum query_hsrc src);
gboolean qhvec_has_urn(const struct query_hashvec *qhv);
guint qhvec_count(const struct query_hashvec *qhv);

GSList *qrt_build_query_target(
	query_hashvec_t *qhvec, gint hops, gint ttl, struct gnutella_node *source);
void qrt_route_query(struct gnutella_node *n, query_hashvec_t *qhvec);
gboolean qrp_node_can_route(const struct gnutella_node *n,
			const query_hashvec_t *qhv);

#endif	/* _core_qrp_h_ */

/* vi: set ts=4 sw=4 cindent: */
