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

RCSID("$Id$")

#include "fifo.h"
#include "walloc.h"
#include "override.h"		/* Must be the last header included */

/**
 * The real FIFO structure (the advertised fifo_t is just a facade).
 */
typedef struct fifo_real {
	GList *head;			/**< Head of FIFO, where data is prepended */
	GList *tail;			/**< Tail of FIFO, where data is removed from */
	gint count;				/**< Amount of entries in FIFO */
} fifo_real_t;

/**
 * Create new FIFO.
 */
fifo_t *
fifo_make(void)
{
	fifo_real_t *fr;

	fr = walloc0(sizeof(*fr));

	return (fifo_t *) fr;
}

/**
 * Destroy FIFO.
 */
void
fifo_free(fifo_t *f)
{
	fifo_real_t *fr = (fifo_real_t *) f;

	g_list_free(fr->head);
	wfree(fr, sizeof(*fr));
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
	fifo_real_t *fr = (fifo_real_t *) f;
	GList *l;

	for (l = fr->head; l; l = g_list_next(l))
		(*cb)(l->data, udata);

	fifo_free(f);
}

/**
 * Returns amount of items queued in FIFO.
 */
gint
fifo_count(fifo_t *f)
{
	fifo_real_t *fr = (fifo_real_t *) f;

	return fr->count;
}

/**
 * Add entry to FIFO.
 */
void
fifo_put(fifo_t *f, gconstpointer data)
{
	fifo_real_t *fr = (fifo_real_t *) f;

	g_assert(fr->count == 0 || fr->head != NULL);
	g_assert(fr->count == 0 || fr->tail != NULL);
	g_assert(fr->head == NULL || fr->count != 0);
	g_assert(fr->tail == NULL || fr->count != 0);

	fr->head = g_list_prepend(fr->head, (gpointer) data);
	if (fr->tail == NULL)
		fr->tail = fr->head;
	fr->count++;
}

/**
 * Remove entry from FIFO.
 *
 * @return the oldest item still held in FIFO, NULL if no item remains.
 */
gpointer
fifo_remove(fifo_t *f)
{
	fifo_real_t *fr = (fifo_real_t *) f;
	GList *prev;
	gpointer data;

	if (fr->count == 0)
		return NULL;

	g_assert(fr->tail != NULL);

	data = fr->tail->data;
	prev = g_list_previous(fr->tail);

	if (prev == NULL) {
		g_assert(fr->tail == fr->head);
		g_assert(fr->count == 1);
		fr->head = fr->tail = g_list_remove(fr->head, data);
	} else {
		fr->head = g_list_remove_link(fr->head, fr->tail);
		g_list_free_1(fr->tail);
		fr->tail = prev;
	}

	fr->count--;

	g_assert(fr->count == 0 || fr->head != NULL);
	g_assert(fr->count == 0 || fr->tail != NULL);
	g_assert(fr->head == NULL || fr->count != 0);
	g_assert(fr->tail == NULL || fr->count != 0);

	return data;
}

