/*
 * $Id$
 *
 * Copyright (c) 2003, Christian Biere
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
#include "hashlist.h"

#include "override.h"		/* Must be the last header included */

RCSID("$Id$");

typedef enum {
	HASH_LIST_MAGIC = 0x338954fdU
} hash_list_magic_t;

struct hash_list {
	GList *l;
	GHashTable *ht; 
	GList *last;
	gulong len;
	gulong refcount;
	gulong stamp;
	hash_list_magic_t magic;
};

struct hash_list_iter {
	hash_list_t *hl; 
	GList *l;
	gulong stamp;
};

#if 0
#define USE_HASH_LIST_REGRESSION 1
#endif

#ifdef USE_HASH_LIST_REGRESSION
static void inline hash_list_regression(const hash_list_t *hl)
{
	g_assert(HASH_LIST_MAGIC == hl->magic);
	g_assert(NULL != hl->ht);
	g_assert(g_list_first(hl->l) == hl->l);
	g_assert(g_list_first(hl->last) == hl->l);
	g_assert(g_list_last(hl->l) == hl->last);
	g_assert(g_list_length(hl->l) == hl->len);
	g_assert(g_hash_table_size(hl->ht) == hl->len);
}
#else
#define hash_list_regression(hl)
#endif

#ifdef TRACK_MALLOC
#undef hash_list_new
#undef hash_list_free
#endif

hash_list_t *hash_list_new(void)
{
	hash_list_t *hl = walloc(sizeof(*hl));
	hl->l = NULL;
	hl->ht = g_hash_table_new(NULL, NULL);
	hl->last = NULL;
	hl->refcount = 1;
	hl->len = 0;
	hl->stamp = HASH_LIST_MAGIC + 1;
	hl->magic = HASH_LIST_MAGIC;
	hash_list_regression(hl);

	return hl;
}

void hash_list_free(hash_list_t *hl)
{
	g_assert(NULL != hl);
	hash_list_regression(hl);

	if (--hl->refcount != 0) {
		g_warning("hash_list_free: hash list is still referenced! "
			"(hl=%p, hl->refcount=%lu)", hl, hl->refcount);
	}
	g_hash_table_destroy(hl->ht);
	g_list_free(hl->l);
	hl->ht = NULL; 
	hl->l = NULL;
	hl->len = 0;

	wfree(hl, sizeof(*hl));
}

void hash_list_append(hash_list_t *hl, gpointer data)
{
	g_assert(NULL != data);
	g_assert(NULL != hl);
	g_assert(1 == hl->refcount);
	hash_list_regression(hl);

	hl->last = g_list_last(g_list_append(hl->last, data));
	if (NULL == hl->l)
		hl->l = hl->last;
	g_assert(NULL == g_hash_table_lookup(hl->ht, data));
	g_hash_table_insert(hl->ht, data, hl->last);
	hl->len++;
	hl->stamp++;

	hash_list_regression(hl);
}

void hash_list_prepend(hash_list_t *hl, gpointer data)
{
	g_assert(NULL != data);
	g_assert(NULL != hl);
	g_assert(1 == hl->refcount);
	hash_list_regression(hl);

	hl->l = g_list_prepend(hl->l, data);
	if (NULL == hl->last)
		hl->last = hl->l;
	g_assert(NULL == g_hash_table_lookup(hl->ht, data));
	g_hash_table_insert(hl->ht, data, hl->l);
	hl->len++;
	hl->stamp++;

	hash_list_regression(hl);
}

void hash_list_remove(hash_list_t *hl, gpointer data)
{
	GList *l;

	g_assert(NULL != data);
	g_assert(1 == hl->refcount);
	hash_list_regression(hl);

	l = (GList *) g_hash_table_lookup(hl->ht, data);
	g_assert(NULL != l);
	if (NULL != hl->last && hl->last->data == data)
		hl->last = g_list_previous(hl->last);
	hl->l = g_list_delete_link(hl->l, l);
	g_hash_table_remove(hl->ht, data);
	hl->len--;
	hl->stamp++;

	hash_list_regression(hl);
}

gpointer hash_list_last(const hash_list_t *hl)
{
	g_assert(NULL != hl);
	g_assert(hl->refcount > 0);
	hash_list_regression(hl);

	return NULL != hl ? hl->last : NULL;
} 

gpointer hash_list_first(const hash_list_t *hl)
{
	g_assert(NULL != hl);
	g_assert(hl->refcount > 0);
	hash_list_regression(hl);

	return NULL != hl->l ? hl->l->data : NULL;
} 

gulong hash_list_length(const hash_list_t *hl)
{
	g_assert(NULL != hl);
	g_assert(hl->refcount > 0);
	hash_list_regression(hl);

	return hl->len;
}

gpointer hash_list_get_iter(hash_list_t *hl, hash_list_iter_t **i)
{
	g_assert(NULL != hl);
	g_assert(NULL != i);
	g_assert(NULL != *i);
	g_assert(hl->refcount > 0);
	(*i)->hl = hl;
	(*i)->l = hl->l;
	(*i)->stamp = hl->stamp;
	hl->refcount++;
	return hash_list_first((*i)->hl);
}

gpointer hash_list_next(hash_list_iter_t *i)
{
	g_assert(NULL != i);
	g_assert(NULL != i->hl);
	g_assert(i->hl->refcount > 0);
	g_assert(i->hl->stamp == i->stamp);
	i->l = g_list_next(i->l);
	return NULL != i->l ? i->l->data : NULL;
}

gboolean hash_list_has_next(const hash_list_iter_t *i)
{
	g_assert(NULL != i);
	g_assert(NULL != i->hl);
	g_assert(i->hl->refcount > 0);
	g_assert(i->hl->stamp == i->stamp);

	return NULL != g_list_next(i->l);
}

gboolean hash_list_has_previous(const hash_list_iter_t *i)
{
	g_assert(NULL != i);
	g_assert(NULL != i->hl);
	g_assert(i->hl->refcount > 0);
	g_assert(i->hl->stamp == i->stamp);

	return NULL != g_list_previous(i->l);
}

void hash_list_release(hash_list_iter_t *i)
{
	g_assert(NULL != i);
	g_assert(i->hl->refcount > 0);
	g_assert(i->hl->stamp == i->stamp);
	i->hl->refcount--;
}

gboolean hash_list_contains(hash_list_t *hl, gpointer data)
{
	GList *l;
	g_assert(NULL != hl);
	g_assert(NULL != hl->ht);
	g_assert(NULL != data);
	g_assert(hl->refcount > 0);
	hash_list_regression(hl);

	l = g_hash_table_lookup(hl->ht, data);
	return NULL != l && l->data == data;
}

void hash_list_foreach(const hash_list_t *hl, GFunc func, gpointer user_data)
{
	g_assert(NULL != hl);
	g_assert(NULL != func);
	g_assert(hl->refcount > 0);
	hash_list_regression(hl);

	G_LIST_FOREACH(hl->l, func, user_data);

	hash_list_regression(hl);
}
