/*
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

#include "hashlist.h"
#include "list.h"
#include "plist.h"
#include "pslist.h"
#include "slist.h"
#include "vector.h"

/**
 * Allowed sequence types.
 */
enum sequence_type {
	SEQUENCE_GSLIST = 0x1,		/**< GSList */
	SEQUENCE_GLIST,				/**< GList */
	SEQUENCE_LIST,				/**< list_t */
	SEQUENCE_SLIST,				/**< slist_t */
	SEQUENCE_HLIST,				/**< hash_list_t */
	SEQUENCE_VECTOR,			/**< vector_t */
	SEQUENCE_PLIST,				/**< plist_t */
	SEQUENCE_PSLIST,			/**< pslist_t */

	SEQUENCE_MAXTYPE
};

enum sequence_magic { SEQUENCE_MAGIC = 0x062be573U };

/**
 * The sequence structure holding the necessary information to delegate all
 * the operations to different implementations.
 */
struct sequence {
	enum sequence_magic magic;
	enum sequence_type type;
	union {
		GSList *gsl;
		GList *gl;
		list_t *l;
		slist_t *sl;
		hash_list_t *hl;
		vector_t *vec;
		plist_t *pl;
		pslist_t *psl;
	} u;
};

typedef struct sequence sequence_t;
typedef struct sequence_iterator sequence_iter_t;

/**
 * Creation interface.
 */

sequence_t *sequence_create_from_glist(GList *);
sequence_t *sequence_create_from_gslist(GSList *);
sequence_t *sequence_create_from_hash_list(hash_list_t *);
sequence_t *sequence_create_from_list(list_t *);
sequence_t *sequence_create_from_plist(plist_t *);
sequence_t *sequence_create_from_pslist(pslist_t *);
sequence_t *sequence_create_from_slist(slist_t *);
sequence_t *sequence_create_from_vector(vector_t *);

sequence_t *sequence_fill_from_glist(sequence_t *, GList *);
sequence_t *sequence_fill_from_gslist(sequence_t *, GSList *);
sequence_t *sequence_fill_from_hash_list(sequence_t *, hash_list_t *);
sequence_t *sequence_fill_from_list(sequence_t *, list_t *);
sequence_t *sequence_fill_from_plist(sequence_t *, plist_t *);
sequence_t *sequence_fill_from_pslist(sequence_t *, pslist_t *);
sequence_t *sequence_fill_from_slist(sequence_t *, slist_t *);
sequence_t *sequence_fill_from_vector(sequence_t *, vector_t *);

/**
 * Public sequence interface.
 */

void *sequence_implementation(const sequence_t *);
void *sequence_release(sequence_t **);
const char *sequence_type_to_string(const sequence_t *);
void sequence_destroy(sequence_t *);

bool sequence_is_empty(const sequence_t *);
size_t sequence_count(const sequence_t *s);
void sequence_foreach(const sequence_t *s, GFunc func, void *data);

sequence_iter_t *sequence_forward_iterator(const sequence_t *);
bool sequence_iter_has_next(const sequence_iter_t *);
void *sequence_iter_next(sequence_iter_t *);
sequence_iter_t *sequence_backward_iterator(const sequence_t *, bool);
bool sequence_iter_has_previous(const sequence_iter_t *);
void *sequence_iter_previous(sequence_iter_t *);
void sequence_iterator_release(sequence_iter_t **);

#endif	/* _sequence_h_ */

/* vi: set ts=4 sw=4 cindent: */
