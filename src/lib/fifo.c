/*
 * $Id$
 *
 * Copyright (c) 2004, Raphael Manfredi
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
 * A FIFO.
 *
 * Items are put on one end and retrieved on the other, in the order
 * they were put.
 *
 * @author Raphael Manfredi
 * @date 2004
 */

#include "common.h"

#include "fifo.h"
#include "glib-missing.h"
#include "walloc.h"
#include "override.h"		/* Must be the last header included */

/**
 * The real FIFO structure (the advertised fifo_t is just a facade).
 */
struct fifo {
	GList *head;			/**< Head of FIFO, where data is prepended */
	GList *tail;			/**< Tail of FIFO, where data is removed from */
	int count;				/**< Amount of entries in FIFO */
};

/**
 * Create new FIFO.
 */
fifo_t *
fifo_make(void)
{
	fifo_t *f;

	WALLOC0(f);
	return f;
}

/**
 * Destroy FIFO.
 */
void
fifo_free(fifo_t *f)
{
	gm_list_free_null(&f->head);
	WFREE(f);
}

/**
 * Destroy FIFO, invoking freeing callback on all items still held.
 *
 * @param f the FIFO to free
 * @param cb the freeing callback to invoke on all items.
 * @param udata the extra user data passed as-is to the freeing callback.
 */
void
fifo_free_all(fifo_t *f, fifo_free_t cb, gpointer udata)
{
	GList *l;

	for (l = f->head; l; l = g_list_next(l))
		(*cb)(l->data, udata);

	fifo_free(f);
}

/**
 * Returns amount of items queued in FIFO.
 */
int
fifo_count(fifo_t *f)
{
	return f->count;
}

/**
 * Add entry to FIFO.
 */
void
fifo_put(fifo_t *f, gconstpointer data)
{
	g_assert(f->count == 0 || f->head != NULL);
	g_assert(f->count == 0 || f->tail != NULL);
	g_assert(f->head == NULL || f->count != 0);
	g_assert(f->tail == NULL || f->count != 0);

	f->head = g_list_prepend(f->head, (gpointer) data);
	if (f->tail == NULL)
		f->tail = f->head;
	f->count++;
}

/**
 * Remove entry from FIFO.
 *
 * @return the oldest item still held in FIFO, NULL if no item remains.
 */
gpointer
fifo_remove(fifo_t *f)
{
	GList *prev;
	gpointer data;

	if (f->count == 0)
		return NULL;

	g_assert(f->tail != NULL);

	data = f->tail->data;
	prev = g_list_previous(f->tail);

	if (prev == NULL) {
		g_assert(f->tail == f->head);
		g_assert(f->count == 1);
		f->head = f->tail = g_list_remove(f->head, data);
	} else {
		IGNORE_RESULT(g_list_remove_link(prev, f->tail));
		g_list_free_1(f->tail);
		f->tail = prev;
	}

	f->count--;

	g_assert(f->count == 0 || f->head != NULL);
	g_assert(f->count == 0 || f->tail != NULL);
	g_assert(f->head == NULL || f->count != 0);
	g_assert(f->tail == NULL || f->count != 0);

	return data;
}

