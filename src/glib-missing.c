/*
 * $Id$
 *
 * Copyright (c) 2003, Raphael Manfredi
 *
 * Functions that should be in glib-1.2 but are not.
 * They are all prefixed with "gm_" as in "Glib Missing".
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

#include "common.h"
#include "glib-missing.h"

RCSID("$Id$");

/*
 * gm_slist_insert_after
 *
 * Insert `item' after `link' in list `list'.
 * If `link' is NULL, insertion happens at the head.
 *
 * Returns new list head.
 */
GSList *gm_slist_insert_after(GSList *list, GSList *link, gpointer data)
{
	GSList *new;

	g_assert(list != NULL || link == NULL);	/* (list = NULL) => (link = NULL) */

	if (link == NULL)
		return g_slist_prepend(list, data);

	new = g_slist_alloc();
	new->data = data;

	new->next = link->next;
	link->next = new;

	return list;
}

/*
 * gm_list_insert_after
 *
 * Insert `item' after `link' in list `list'.
 * If `link' is NULL, insertion happens at the head.
 *
 * Returns new list head.
 */
GList *gm_list_insert_after(GList *list, GList *link, gpointer data)
{
	GList *new;

	g_assert(list != NULL || link == NULL);	/* (list = NULL) => (link = NULL) */

	if (link == NULL)
		return g_list_prepend(list, data);

	new = g_list_alloc();
	new->data = data;

	new->prev = link;
	new->next = link->next;

	if (link->next)
		link->next->prev = new;

	link->next = new;

	return list;
}

