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
 *      51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
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

#include "common.h"

#include "sequence.h"
#include "glib-missing.h"
#include "walloc.h"
#include "override.h"			/* Must be the last header included */

/**
 * Iterator directions.
 */
enum sequence_direction {
	SEQ_ITER_FORWARD = 0,		/**< Forward iteration */
	SEQ_ITER_BACKWARD			/**< Backward iteration */
};

enum sequence_iter_magic { SEQUENCE_ITER_MAGIC = 0x169103ceU };

/**
 * A sequence iterator.
 */
struct sequence_iterator {
	enum sequence_iter_magic magic;
	enum sequence_type type;
	union {
		GSList *gsl;
		GList *gl;
		plist_t *pl;
		pslist_t *psl;
		list_iter_t *li;
		slist_iter_t *sli;
		hash_list_iter_t *hli;
		vector_iter_t *veci;
	} u;
	enum sequence_direction direction;
};

static inline void
sequence_iter_check(const sequence_iter_t *si)
{
	g_assert(si != NULL);
	g_assert(SEQUENCE_ITER_MAGIC == si->magic);
}

static inline void
sequence_check(const sequence_t *s)
{
	g_assert(s != NULL);
	g_assert(SEQUENCE_MAGIC == s->magic);
}

/**
 * Create a sequence out of an existing GSList.
 * Use sequence_release() to discard the sequence encapsulation.
 */
sequence_t *
sequence_create_from_gslist(GSList *gsl)
{
	sequence_t *s;

	WALLOC(s);
	return sequence_fill_from_gslist(s, gsl);
}

/**
 * Create a sequence out of an existing GList.
 * Use sequence_release() to discard the sequence encapsulation.
 */
sequence_t *
sequence_create_from_glist(GList *gl)
{
	sequence_t *s;

	WALLOC(s);
	return sequence_fill_from_glist(s, gl);
}

/**
 * Create a sequence out of an existing pslist_t.
 * Use sequence_release() to discard the sequence encapsulation.
 */
sequence_t *
sequence_create_from_pslist(pslist_t *pl)
{
	sequence_t *s;

	WALLOC(s);
	return sequence_fill_from_pslist(s, pl);
}

/**
 * Create a sequence out of an existing plist_t.
 * Use sequence_release() to discard the sequence encapsulation.
 */
sequence_t *
sequence_create_from_plist(plist_t *pl)
{
	sequence_t *s;

	WALLOC(s);
	return sequence_fill_from_plist(s, pl);
}

/**
 * Create a sequence out of an existing list_t.
 * Use sequence_release() to discard the sequence encapsulation.
 */
sequence_t *
sequence_create_from_list(list_t *l)
{
	sequence_t *s;

	g_assert(l != NULL);

	WALLOC(s);
	return sequence_fill_from_list(s, l);
}

/**
 * Create a sequence out of an existing slist_t.
 * Use sequence_release() to discard the sequence encapsulation.
 */
sequence_t *
sequence_create_from_slist(slist_t *sl)
{
	sequence_t *s;

	g_assert(sl != NULL);

	WALLOC(s);
	return sequence_fill_from_slist(s, sl);
}

/**
 * Create a sequence out of an existing hash_list_t.
 * Use sequence_release() to discard the sequence encapsulation.
 */
sequence_t *
sequence_create_from_hash_list(hash_list_t *hl)
{
	sequence_t *s;

	g_assert(hl != NULL);

	WALLOC(s);
	return sequence_fill_from_hash_list(s, hl);
}

/**
 * Create a sequence out of an existing vector_t.
 * Use sequence_release() to discard the sequence encapsulation.
 */
sequence_t *
sequence_create_from_vector(vector_t *vec)
{
	sequence_t *s;

	g_assert(vec != NULL);

	WALLOC(s);
	return sequence_fill_from_vector(s, vec);
}

/**
 * Fill sequence object with GSList.
 */
sequence_t *
sequence_fill_from_gslist(sequence_t *s, GSList *gsl)
{
	s->magic = SEQUENCE_MAGIC;
	s->type = SEQUENCE_GSLIST;
	s->u.gsl = gsl;
	return s;
}

/**
 * Fill sequence object with GList.
 */
sequence_t *
sequence_fill_from_glist(sequence_t *s, GList *gl)
{
	s->magic = SEQUENCE_MAGIC;
	s->type = SEQUENCE_GLIST;
	s->u.gl = gl;
	return s;
}

/**
 * Fill sequence object with plist_t.
 */
sequence_t *
sequence_fill_from_plist(sequence_t *s, plist_t *pl)
{
	s->magic = SEQUENCE_MAGIC;
	s->type = SEQUENCE_PLIST;
	s->u.pl = pl;
	return s;
}

/**
 * Fill sequence object with pslist_t.
 */
sequence_t *
sequence_fill_from_pslist(sequence_t *s, pslist_t *pl)
{
	s->magic = SEQUENCE_MAGIC;
	s->type = SEQUENCE_PSLIST;
	s->u.psl = pl;
	return s;
}

/**
 * Fill sequence object with list_.
 */
sequence_t *
sequence_fill_from_list(sequence_t *s, list_t *l)
{
	g_assert(l != NULL);

	s->magic = SEQUENCE_MAGIC;
	s->type = SEQUENCE_LIST;
	s->u.l = l;
	return s;
}

/**
 * Fill sequence object with slist_t.
 */
sequence_t *
sequence_fill_from_slist(sequence_t *s, slist_t *sl)
{
	g_assert(sl != NULL);

	s->magic = SEQUENCE_MAGIC;
	s->type = SEQUENCE_SLIST;
	s->u.sl = sl;
	return s;
}

/**
 * Fill sequence object with hash_list_t.
 */
sequence_t *
sequence_fill_from_hash_list(sequence_t *s, hash_list_t *hl)
{
	g_assert(hl != NULL);

	s->magic = SEQUENCE_MAGIC;
	s->type = SEQUENCE_HLIST;
	s->u.hl = hl;
	return s;
}

/**
 * Fill sequence object with vector_t.
 */
sequence_t *
sequence_fill_from_vector(sequence_t *s, vector_t *vec)
{
	g_assert(vec != NULL);

	s->magic = SEQUENCE_MAGIC;
	s->type = SEQUENCE_VECTOR;
	s->u.vec = vec;
	return s;
}

/**
 * Return sequence type string, for logging.
 */
const char *
sequence_type_to_string(const sequence_t *s)
{
	sequence_check(s);

	switch (s->type) {
	case SEQUENCE_GSLIST:		return "GSList";
	case SEQUENCE_GLIST:		return "GList";
	case SEQUENCE_LIST:			return "list_t";
	case SEQUENCE_PSLIST:		return "pslist_t";
	case SEQUENCE_PLIST:		return "plist_t";
	case SEQUENCE_SLIST:		return "slist_t";
	case SEQUENCE_HLIST:		return "hash_list_t";
	case SEQUENCE_VECTOR:		return "vector_t";
	case SEQUENCE_MAXTYPE:		break;
	}

	g_assert_not_reached();
	return NULL;
}

/**
 * Apply ``func'' to all the items in the sequence.
 */
void
sequence_foreach(const sequence_t *s, GFunc func, void *data)
{
	sequence_check(s);

	switch (s->type) {
	case SEQUENCE_GSLIST:
		g_slist_foreach(s->u.gsl, func, data);
		break;
	case SEQUENCE_GLIST:
		g_list_foreach(s->u.gl, func, data);
		break;
	case SEQUENCE_LIST:
		list_foreach(s->u.l, func, data);
		break;
	case SEQUENCE_PSLIST:
		pslist_foreach(s->u.psl, func, data);
		break;
	case SEQUENCE_PLIST:
		plist_foreach(s->u.pl, func, data);
		break;
	case SEQUENCE_SLIST:
		slist_foreach(s->u.sl, func, data);
		break;
	case SEQUENCE_HLIST:
		hash_list_foreach(s->u.hl, func, data);
		break;
	case SEQUENCE_VECTOR:
		vector_foreach(s->u.vec, func, data);
		break;
	case SEQUENCE_MAXTYPE:
		g_assert_not_reached();
	}
}

/**
 * Is the sequence empty?
 */
bool
sequence_is_empty(const sequence_t *s)
{
	sequence_check(s);

	switch (s->type) {
	case SEQUENCE_GSLIST:
		return NULL == s->u.gsl;
	case SEQUENCE_GLIST:
		return NULL == s->u.gl;
	case SEQUENCE_LIST:
		return 0 == list_length(s->u.l);
	case SEQUENCE_PSLIST:
		return NULL == s->u.psl;
	case SEQUENCE_PLIST:
		return NULL == s->u.pl;
	case SEQUENCE_SLIST:
		return 0 == slist_length(s->u.sl);
	case SEQUENCE_HLIST:
		return 0 == hash_list_length(s->u.hl);
	case SEQUENCE_VECTOR:
		return 0 == vector_length(s->u.vec);
	case SEQUENCE_MAXTYPE:
		g_assert_not_reached();
	}

	return FALSE;
}

/**
 * @return how many items are held in the sequence.
 */
size_t
sequence_count(const sequence_t *s)
{
	sequence_check(s);

	switch (s->type) {
	case SEQUENCE_GSLIST:
		return g_slist_length(s->u.gsl);
	case SEQUENCE_GLIST:
		return g_list_length(s->u.gl);
	case SEQUENCE_LIST:
		return list_length(s->u.l);
	case SEQUENCE_PSLIST:
		return pslist_length(s->u.psl);
	case SEQUENCE_PLIST:
		return plist_length(s->u.pl);
	case SEQUENCE_SLIST:
		return slist_length(s->u.sl);
	case SEQUENCE_HLIST:
		return hash_list_length(s->u.hl);
	case SEQUENCE_VECTOR:
		return vector_length(s->u.vec);
	case SEQUENCE_MAXTYPE:
		g_assert_not_reached();
	}

	return 0;
}

/**
 * Returns the underlying sequence implementation.
 */
void *
sequence_implementation(const sequence_t *s)
{
	sequence_check(s);

	switch (s->type) {
	case SEQUENCE_GSLIST:
		return s->u.gsl;
	case SEQUENCE_GLIST:
		return s->u.gl;
	case SEQUENCE_LIST:
		return s->u.l;
	case SEQUENCE_PSLIST:
		return s->u.psl;
	case SEQUENCE_PLIST:
		return s->u.pl;
	case SEQUENCE_SLIST:
		return s->u.sl;
	case SEQUENCE_HLIST:
		return s->u.hl;
	case SEQUENCE_VECTOR:
		return s->u.vec;
	case SEQUENCE_MAXTYPE:
		g_assert_not_reached();
	}

	return NULL;
}

/**
 * Release sequence encapsulation, returning the underlying implementation
 * object (will need to be cast back to the proper type for perusal).
 *
 * The supplied pointer to the sequence is nullified upon return.
 */
void *
sequence_release(sequence_t **s_ptr)
{
	sequence_t *s = *s_ptr;

	if (s != NULL) {
		void *implementation;

		sequence_check(s);

		implementation = sequence_implementation(s);

		s->type = SEQUENCE_MAXTYPE;
		s->magic = 0;
		WFREE(s);

		*s_ptr = NULL;
		return implementation;
	}

	return NULL;
}

/**
 * Destroy a sequence and the underlying implementation.
 */
void
sequence_destroy(sequence_t *s)
{
	sequence_check(s);

	switch (s->type) {
	case SEQUENCE_GSLIST:
		gm_slist_free_null(&s->u.gsl);
		break;
	case SEQUENCE_GLIST:
		gm_list_free_null(&s->u.gl);
		break;
	case SEQUENCE_LIST:
		list_free(&s->u.l);
		break;
	case SEQUENCE_PSLIST:
		pslist_free_null(&s->u.psl);
		break;
	case SEQUENCE_PLIST:
		plist_free_null(&s->u.pl);
		break;
	case SEQUENCE_SLIST:
		slist_free(&s->u.sl);
		break;
	case SEQUENCE_HLIST:
		hash_list_free(&s->u.hl);
		break;
	case SEQUENCE_VECTOR:
		vector_free(&s->u.vec);
		break;
	case SEQUENCE_MAXTYPE:
		g_assert_not_reached();
	}

	s->type = SEQUENCE_MAXTYPE;
	s->magic = 0;
	WFREE(s);
}

/**
 * Create a forward iterator.
 */
sequence_iter_t *
sequence_forward_iterator(const sequence_t *s)
{
	sequence_iter_t *si;

	g_assert(s != NULL);

	WALLOC(si);
	si->magic = SEQUENCE_ITER_MAGIC;
	si->direction = SEQ_ITER_FORWARD;
	si->type = s->type;

	switch (s->type) {
	case SEQUENCE_GSLIST:
		si->u.gsl = s->u.gsl;
		break;
	case SEQUENCE_GLIST:
		si->u.gl = s->u.gl;
		break;
	case SEQUENCE_LIST:
		si->u.li = list_iter_before_head(s->u.l);
		break;
	case SEQUENCE_PSLIST:
		si->u.psl = s->u.psl;
		break;
	case SEQUENCE_PLIST:
		si->u.pl = s->u.pl;
		break;
	case SEQUENCE_SLIST:
		si->u.sli = slist_iter_before_head(s->u.sl);
		break;
	case SEQUENCE_HLIST:
		si->u.hli = hash_list_iterator(s->u.hl);
		break;
	case SEQUENCE_VECTOR:
		si->u.veci = vector_iterator(s->u.vec);
		break;
	case SEQUENCE_MAXTYPE:
		g_assert_not_reached();
	}

	return si;
}

/**
 * Check whether we have a next item to be iterated over.
 */
bool
sequence_iter_has_next(const sequence_iter_t *si)
{
	if (!si)
		return FALSE;

	sequence_iter_check(si);
	g_assert(SEQ_ITER_FORWARD == si->direction);

	switch (si->type) {
	case SEQUENCE_GSLIST:
		return si->u.gsl != NULL;
	case SEQUENCE_GLIST:
		return si->u.gl != NULL;
	case SEQUENCE_LIST:
		return list_iter_has_next(si->u.li);
	case SEQUENCE_PSLIST:
		return si->u.psl != NULL;
	case SEQUENCE_PLIST:
		return si->u.pl != NULL;
	case SEQUENCE_SLIST:
		return slist_iter_has_next(si->u.sli);
	case SEQUENCE_HLIST:
		return hash_list_iter_has_next(si->u.hli);
	case SEQUENCE_VECTOR:
		return vector_iter_has_next(si->u.veci);
	case SEQUENCE_MAXTYPE:
		g_assert_not_reached();
	}

	return FALSE;
}

/**
 * Get next item, moving iterator cursor by one position.
 */
void *
sequence_iter_next(sequence_iter_t *si)
{
	void *next = NULL;

	sequence_iter_check(si);
	g_assert(SEQ_ITER_FORWARD == si->direction);

	switch (si->type) {
	case SEQUENCE_GSLIST:
		next = si->u.gsl ? si->u.gsl->data : NULL;
		si->u.gsl = g_slist_next(si->u.gsl);
		break;
	case SEQUENCE_GLIST:
		next = si->u.gl ? si->u.gl->data : NULL;
		si->u.gl = g_list_next(si->u.gl);
		break;
	case SEQUENCE_LIST:
		return list_iter_next(si->u.li);
	case SEQUENCE_PSLIST:
		next = si->u.psl ? si->u.psl->data : NULL;
		si->u.psl = pslist_next(si->u.psl);
		break;
	case SEQUENCE_PLIST:
		next = si->u.pl ? si->u.pl->data : NULL;
		si->u.pl = plist_next(si->u.pl);
		break;
	case SEQUENCE_SLIST:
		return slist_iter_next(si->u.sli);
	case SEQUENCE_HLIST:
		return hash_list_iter_next(si->u.hli);
	case SEQUENCE_VECTOR:
		return vector_iter_next(si->u.veci);
	case SEQUENCE_MAXTYPE:
		g_assert_not_reached();
	}

	return next;
}

/**
 * Creates a backward iterator, for the sequences that support it.
 * If the structure does not support it, set it up as a forward iterator
 * instead unless ``check'' is TRUE in which case we panic.
 */
sequence_iter_t *
sequence_backward_iterator(const sequence_t *s, bool check)
{
	sequence_iter_t *si;

	g_assert(s != NULL);

	WALLOC(si);
	si->magic = SEQUENCE_ITER_MAGIC;
	si->direction = SEQ_ITER_BACKWARD;
	si->type = s->type;

	switch (s->type) {
	case SEQUENCE_GSLIST:
		if (check)
			goto panic;
		si->u.gsl = s->u.gsl;
		break;
	case SEQUENCE_GLIST:
		si->u.gl = g_list_last(s->u.gl);
		break;
	case SEQUENCE_LIST:
		si->u.li = list_iter_after_tail(s->u.l);
		break;
	case SEQUENCE_PSLIST:
		if (check)
			goto panic;
		si->u.psl = s->u.psl;	/* Forward iteration from head */
		break;
	case SEQUENCE_PLIST:
		si->u.pl = plist_last(s->u.pl);
		break;
	case SEQUENCE_SLIST:
		if (check)
			goto panic;
		si->u.sli = slist_iter_before_head(s->u.sl);
		break;
	case SEQUENCE_HLIST:
		si->u.hli = hash_list_iterator_tail(s->u.hl);
		break;
	case SEQUENCE_VECTOR:
		si->u.veci = vector_iterator_tail(s->u.vec);
		break;
	case SEQUENCE_MAXTYPE:
		g_assert_not_reached();
	}

	return si;

panic:
	g_error("sequence_backward_iterator() impossible on type %s",
		sequence_type_to_string(s));
	return NULL;
}

/**
 * Get previous item, moving iterator cursor by one position backwards.
 */
void *
sequence_iter_previous(sequence_iter_t *si)
{
	void *prev = NULL;

	sequence_iter_check(si);
	g_assert(SEQ_ITER_BACKWARD == si->direction);

	switch (si->type) {
	case SEQUENCE_GSLIST:
		/* Forward iteration only */
		prev = si->u.gsl ? si->u.gsl->data : NULL;
		si->u.gsl = g_slist_next(si->u.gsl);
		break;
	case SEQUENCE_GLIST:
		prev = si->u.gl ? si->u.gl->data : NULL;
		si->u.gl = g_list_previous(si->u.gl);
		break;
	case SEQUENCE_LIST:
		return list_iter_previous(si->u.li);
	case SEQUENCE_PSLIST:
		/* Forward iteration only */
		prev = si->u.psl ? si->u.psl->data : NULL;
		si->u.psl = pslist_next(si->u.psl);
		break;
	case SEQUENCE_PLIST:
		prev = si->u.pl ? si->u.pl->data : NULL;
		si->u.pl = plist_prev(si->u.pl);
		break;
	case SEQUENCE_SLIST:
		/* Forward iteration only */
		return slist_iter_next(si->u.sli);
	case SEQUENCE_HLIST:
		return hash_list_iter_previous(si->u.hli);
	case SEQUENCE_VECTOR:
		return vector_iter_previous(si->u.veci);
	case SEQUENCE_MAXTYPE:
		g_assert_not_reached();
	}

	return prev;
}

/**
 * Check whether we have a previous item to be iterated over.
 */
bool
sequence_iter_has_previous(const sequence_iter_t *si)
{
	if (!si)
		return FALSE;

	sequence_iter_check(si);
	g_assert(SEQ_ITER_BACKWARD == si->direction);

	switch (si->type) {
	case SEQUENCE_GSLIST:
		/* Forward iteration only */
		return si->u.gsl != NULL;
	case SEQUENCE_GLIST:
		return si->u.gl != NULL;
	case SEQUENCE_LIST:
		return list_iter_has_previous(si->u.li);
	case SEQUENCE_PSLIST:
		return si->u.psl != NULL;
	case SEQUENCE_PLIST:
		return si->u.pl != NULL;
	case SEQUENCE_SLIST:
		/* Forward iteration only */
		return slist_iter_has_next(si->u.sli);
	case SEQUENCE_HLIST:
		return hash_list_iter_has_previous(si->u.hli);
	case SEQUENCE_VECTOR:
		return vector_iter_has_previous(si->u.veci);
	case SEQUENCE_MAXTYPE:
		g_assert_not_reached();
	}

	return FALSE;
}

/**
 * Release the iterator.
 */
void
sequence_iterator_release(sequence_iter_t **iter_ptr)
{
	if (*iter_ptr) {
		sequence_iter_t *si = *iter_ptr;

		sequence_iter_check(si);

		switch (si->type) {
		case SEQUENCE_GSLIST:
		case SEQUENCE_GLIST:
		case SEQUENCE_PSLIST:
		case SEQUENCE_PLIST:
			break;
		case SEQUENCE_LIST:
			list_iter_free(&si->u.li);
			break;
		case SEQUENCE_SLIST:
			slist_iter_free(&si->u.sli);
			break;
		case SEQUENCE_HLIST:
			hash_list_iter_release(&si->u.hli);
			break;
		case SEQUENCE_VECTOR:
			vector_iter_release(&si->u.veci);
			break;
		case SEQUENCE_MAXTYPE:
			g_assert_not_reached();
		}

		si->magic = 0;
		WFREE(si);
		*iter_ptr = NULL;
	}
}

/* vi: set ts=4 sw=4 cindent: */
