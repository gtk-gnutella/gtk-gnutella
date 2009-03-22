/*
 * $Id$
 *
 * Copyright (c) 2009, Raphael Manfredi
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
 * @ingroup lib
 * @file
 *
 * Interface definition for a sequence (traversable ordered structure).
 *
 * @author Raphael Manfredi
 * @date 2009
 */

#ifndef _sequence_h_
#define _sequence_h_

#include "common.h"

#include "list.h"
#include "slist.h"
#include "hashlist.h"

/**
 * Allowed sequence types.
 */
enum sequence_type {
	SEQUENCE_GSLIST = 0x1,		/**< GSList */
	SEQUENCE_GLIST,				/**< GList */
	SEQUENCE_LIST,				/**< list_t */
	SEQUENCE_SLIST,				/**< slist_t */
	SEQUENCE_HLIST,				/**< hash_list_t */

	SEQUENCE_MAXTYPE
};

/**
 * The sequence structure holding the necessary information to delegate all
 * the operations to different implementations.
 */
struct sequence {
	union {
		GSList *gsl;
		GList *gl;
		list_t *l;
		slist_t *sl;
		hash_list_t *hl;
	} u;
	enum sequence_type type;
};

typedef struct sequence sequence_t;
typedef struct sequence_iterator sequence_iter_t;

/**
 * Creation interface.
 */

sequence_t *sequence_create_from_gslist(GSList *gsl);
sequence_t *sequence_create_from_glist(GList *gl);
sequence_t *sequence_create_from_list(list_t *l);
sequence_t *sequence_create_from_slist(slist_t *sl);
sequence_t *sequence_create_from_hash_list(hash_list_t *hl);

sequence_t *sequence_fill_from_gslist(sequence_t *s, GSList *gsl);
sequence_t *sequence_fill_from_glist(sequence_t *s, GList *gl);
sequence_t *sequence_fill_from_list(sequence_t *s, list_t *l);
sequence_t *sequence_fill_from_slist(sequence_t *s, slist_t *sl);
sequence_t *sequence_fill_from_hash_list(sequence_t *s, hash_list_t *hl);

/**
 * Public sequence interface.
 */

gpointer sequence_implementation(const sequence_t *s);
gpointer sequence_release(sequence_t *s);
void sequence_destroy(sequence_t *s);

gboolean sequence_is_empty(const sequence_t *s);

sequence_iter_t *sequence_forward_iterator(const sequence_t *s);
gboolean sequence_iter_has_next(const sequence_iter_t *si);
gpointer sequence_iter_next(sequence_iter_t *si);
void sequence_iterator_release(sequence_iter_t **iter_ptr);

#endif	/* _sequence_h_ */

/* vi: set ts=4 sw=4 cindent: */
