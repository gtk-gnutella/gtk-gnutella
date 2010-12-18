/*
 * $Id$
 *
 * Copyright (c) 2010, Raphael Manfredi
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
 * Name / Value pairs and tables.
 *
 * The name is necessary a string.
 * The value is an arbitrary data buffer.
 *
 * @author Raphael Manfredi
 * @date 2010
 */

#include "common.h"

RCSID("$Id$")

#include "nv.h"
#include "atoms.h"
#include "glib-missing.h"
#include "halloc.h"
#include "unsigned.h"
#include "walloc.h"
#include "override.h"		/* Must be the last header included */

enum nv_pair_magic { NV_PAIR_MAGIC = 0x60f7c898U };

/**
 * The name/value pair.
 *
 * This is the actual value we store in the hash table.
 */
struct nv_pair {
	enum nv_pair_magic magic;
	const char *name;		/**< The name (atom) */
	void *value;			/**< The value (halloc()'ed); can be NULL */
	size_t length;			/**< Length of value (0 if value is NULL) */
	int refcnt;				/**< Reference count */
	unsigned allocated:1;	/**< Whether data was allocated */
};

static inline void
nv_pair_check(const nv_pair_t * const nvp)
{
	g_assert(nvp != NULL);
	g_assert(NV_PAIR_MAGIC == nvp->magic);
	g_assert(nvp->name != NULL);
	g_assert(0 == nvp->length || nvp->value != NULL);
	g_assert(nvp->refcnt > 0);
}

enum nv_table_magic { NV_TABLE_MAGIC = 0xa557a3b2U };

/*
 * A name/value pair table.
 */
struct nv_table {
	enum nv_table_magic magic;
	GHashTable *ht;				/**< Hash table name -> nv_pair */
};

static inline void
nv_table_check(const nv_table_t * const nvt)
{
	g_assert(nvt != NULL);
	g_assert(NV_TABLE_MAGIC == nvt->magic);
	g_assert(nvt->ht != NULL);
}

/**
 * Create a new name/value pair.
 *
 * The name string is always copied, but the value is not, unless "copy" is
 * requested.  If the value is not duplicated, it will not be freed either
 * when the name/value pair is discarded, so the data has better be statically
 * allocated or it will leak, since there is no free callback.
 *
 * @param name		the name
 * @param value		the value buffer (can be NULL)
 * @param length	length of value (must be zero if value is NULL)
 * @param copy		whether we should duplicate the value
 *
 * @return the allocated name/value pair.
 */
static nv_pair_t *
nv_pair_make_full(const char *name, const void *value, size_t length,
	gboolean copy)
{
	nv_pair_t *nvp;

	g_assert(name != NULL);
	g_assert(0 == length || value != NULL);
	g_assert(NULL == value || size_is_positive(length));

	nvp = walloc(sizeof *nvp);
	nvp->magic = NV_PAIR_MAGIC;
	nvp->refcnt = 1;
	nvp->name = atom_str_get(name);
	if (value != NULL) {
		nvp->value = deconstify_gpointer(copy ? hcopy(value, length) : value);
	} else {
		nvp->value = NULL;
	}
	nvp->length = length;
	nvp->allocated = copy && value != NULL;

	return nvp;
}

/**
 * Create a new name/value pair.
 *
 * The name string is always copied, but the value is not: it has to be
 * statically allocated data.
 *
 * If the length is 0, the value must be NULL.
 *
 * @param name		the name
 * @param value		the value buffer (can be NULL)
 * @param length	length of value (must be zero if value is NULL)
 *
 * @return the allocated name/value pair.
 */
nv_pair_t *
nv_pair_make_nocopy(char *name, const void *value, size_t length)
{
	return nv_pair_make_full(name, value, length, FALSE);
}

/**
 * Create a new name/value pair.
 *
 * A copy of both name and value data (if not NULL) is made.
 * If the length is 0, the value must be NULL.
 *
 * @param name		the name
 * @param value		the value buffer (can be NULL)
 * @param length	length of value (must be zero if value is NULL)
 *
 * @return the allocated name/value pair.
 */
nv_pair_t *
nv_pair_make(char *name, const void *value, size_t length)
{
	return nv_pair_make_full(name, value, length, TRUE);
}

/**
 * Get the pair name.
 */
const char *
nv_pair_name(const nv_pair_t *nvp)
{
	nv_pair_check(nvp);
	return nvp->name;
}

/**
 * Get the pair value and its length.
 *
 * A NULL means a zero-length quantity.
 * If "retlen" is not NULL, the value length is returned there.
 */
void *
nv_pair_value_len(const nv_pair_t *nvp, size_t *retlen)
{
	nv_pair_check(nvp);

	if (retlen != NULL)
		*retlen = nvp->length;
	return nvp->value;
}

/**
 * Get the pair value, without length information.
 *
 * A NULL means a zero-length quantity.
 *
 * This should only be used for string values, whose end is known, or
 * for fixed-sized objects.  Otherwise, use nv_pair_value_len().
 */
void *
nv_pair_value(const nv_pair_t *nvp)
{
	nv_pair_check(nvp);

	return nvp->value;
}

/**
 * Get the pair value, known to be a string, without length information.
 *
 * This should only be used for string values, whose end is known.
 * Otherwise, use nv_pair_value_len().
 */
const char *
nv_pair_value_str(const nv_pair_t *nvp)
{
	static const char empty[] = "";

	nv_pair_check(nvp);

	return NULL == nvp->value ? empty : nvp->value;
}

/**
 * Get a new reference on an existing name/value pair.
 * @return the nv_pair_t object.
 */
nv_pair_t *
nv_pair_refcnt_inc(nv_pair_t *nvp)
{
	nv_pair_check(nvp);

	nvp->refcnt++;
	return nvp;
}

/**
 * Destroy a name/value pair.
 */
void
nv_pair_free(nv_pair_t *nvp)
{
	nv_pair_check(nvp);

	if (--(nvp->refcnt) != 0)
		return;

	atom_str_free_null(&nvp->name);
	if (nvp->allocated)
		HFREE_NULL(nvp->value);
	nvp->magic = 0;
	wfree(nvp, sizeof *nvp);
}

/**
 * Destroy a name/value pair and nullify its pointer.
 */
void
nv_pair_free_null(nv_pair_t **nvp_ptr)
{
	nv_pair_t *nvp = *nvp_ptr;

	if (nvp != NULL) {
		nv_pair_free(nvp);
		*nvp_ptr = NULL;
	}
}

/**
 * Create a new name/value table.
 */
nv_table_t *
nv_table_make(void)
{
	nv_table_t *nvt;

	nvt = walloc(sizeof *nvt);
	nvt->magic = NV_TABLE_MAGIC;
	nvt->ht = g_hash_table_new(g_str_hash, g_str_equal);

	return nvt;
}

/**
 * g_hash_table_foreach() iterator to free up values in the nv_table_t.
 */
static void
nv_table_free_value(gpointer u_key, gpointer value, gpointer u_data)
{
	(void) u_key;
	(void) u_data;
	nv_pair_free(value);
}

/**
 * Free a name/value table.
 */
void
nv_table_free(nv_table_t *nvt)
{
	nv_table_check(nvt);

	g_hash_table_foreach(nvt->ht, nv_table_free_value, NULL);
	gm_hash_table_destroy_null(&nvt->ht);
	nvt->magic = 0;
	wfree(nvt, sizeof *nvt);
}

/**
 * Free a name/value table and nullify its pointer.
 */
void
nv_table_free_null(nv_table_t **nvt_ptr)
{
	nv_table_t *nvt = *nvt_ptr;

	if (nvt != NULL) {
		nv_table_free(nvt);
		*nvt_ptr = NULL;
	}
}

/**
 * Insert a name value pair into the table.
 *
 * If an entry already existed for that name, it is superseding the old value
 * which is freed.
 */
void
nv_table_insert_pair(const nv_table_t *nvt, nv_pair_t *nvp)
{
	nv_pair_t *old;

	nv_table_check(nvt);
	nv_pair_check(nvp);

	old = g_hash_table_lookup(nvt->ht, nvp->name);
	if (old != NULL) {
		g_hash_table_remove(nvt->ht, nvp->name);
		nv_pair_free(old);
	}
	gm_hash_table_insert_const(nvt->ht, nvp->name, nvp);
}

/**
 * Record a name/value pair.
 *
 * The name and value are copied.
 *
 * @param nvt		the name/value table
 * @param name		the name of the pair
 * @param value		the value to insert (may be NULL)
 * @param length	the length of the value (0 if value is NULL)
 */
void
nv_table_insert(const nv_table_t *nvt,
	const char *name, const void *value, size_t length)
{
	nv_pair_t *nvp;

	nv_table_check(nvt);

	nvp = nv_pair_make_full(name, 0 == length ? NULL : value, length, TRUE);
	nv_table_insert_pair(nvt, nvp);
}

/**
 * Record a name/value pair.
 *
 * The name is atomized (copied) but the value is NOT copied.
 *
 * @param nvt		the name/value table
 * @param name		the name of the pair
 * @param value		the value to insert (may be NULL)
 * @param length	the length of the value (0 if value is NULL)
 */
void
nv_table_insert_nocopy(const nv_table_t *nvt,
	const char *name, const void *value, size_t length)
{
	nv_pair_t *nvp;

	nv_table_check(nvt);

	nvp = nv_pair_make_full(name, 0 == length ? NULL : value, length, FALSE);
	nv_table_insert_pair(nvt, nvp);
}

/**
 * Remove name/value pair.
 *
 * @return TRUE if name/value pair existed.
 */
gboolean
nv_table_remove(const nv_table_t *nvt, const char *name)
{
	nv_pair_t *nvp;

	nv_table_check(nvt);
	g_assert(name != NULL);

	nvp = g_hash_table_lookup(nvt->ht, name);
	if (NULL == nvp)
		return FALSE;

	g_hash_table_remove(nvt->ht, name);
	nv_pair_free(nvp);
	return TRUE;
}

/**
 * Get name/value pair from table.
 *
 * @return NULL if name/value pair does not exist, otherwise the nv_pair_t.
 */
nv_pair_t *
nv_table_lookup(const nv_table_t *nvt, const char *name)
{
	nv_table_check(nvt);
	g_assert(name != NULL);

	return g_hash_table_lookup(nvt->ht, name);
}

/**
 * Get value string associated with a name/value pair in the table.
 *
 * @return NULL if name/value pair does not exist, otherwise the string value.
 */
const char *
nv_table_lookup_str(const nv_table_t *nvt, const char *name)
{
	nv_pair_t *nvp;

	nv_table_check(nvt);
	g_assert(name != NULL);

	nvp = g_hash_table_lookup(nvt->ht, name);
	if (NULL == nvp)
		return NULL;

	return nv_pair_value_str(nvp);	/* Guaranteed to not be NULL */
}

/**
 * Return amount of entries in the table.
 */
size_t
nv_table_count(const nv_table_t *nvt)
{
	nv_table_check(nvt);

	return g_hash_table_size(nvt->ht);
}

/* vi: set ts=4 sw=4 cindent: */
