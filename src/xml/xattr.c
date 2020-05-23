/*
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
 *      51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *----------------------------------------------------------------------
 */

/**
 * @ingroup xml
 * @file
 *
 * XML attributes.
 *
 * Manages XML attributes (optionally prefixed with a URI string) in an
 * ordered table.  All names and values are strings.
 *
 * @author Raphael Manfredi
 * @date 2010
 */

#include "common.h"

#include "xattr.h"

#include "lib/atoms.h"
#include "lib/halloc.h"
#include "lib/hashing.h"
#include "lib/hashlist.h"
#include "lib/hstrfn.h"
#include "lib/walloc.h"

#include "lib/override.h"	/* Must be the last header included */

enum xattr_table_magic { XATTR_TABLE_MAGIC = 0x44d9a5d8 };

/**
 * An XML attribute table.
 *
 * For attributes, we normalize the name using { "URI", "name" } where URI is
 * the actual namespace, not the local prefix referring to it.  Therefore,
 * to access the { "xml", "lang" } attribute, one must really look for the
 * { "http://www.w3.org/XML/1998/namespace", "lang" } attribute.  The key
 * within the attribute table is therefore a structure, not a plain string.
 *
 * We hide the structure behind the XML attribute table interface to be
 * able to easily access un-prefixed attributes as well.
 */
struct xattr_table {
	enum xattr_table_magic magic;
	hash_list_t *hl;
};

static inline void
xattr_table_check(const struct xattr_table * const xat)
{
	g_assert(xat != NULL);
	g_assert(XATTR_TABLE_MAGIC == xat->magic);
}

/**
 * Attributes (key / value).
 */
struct xattr {
	const char *uri;			/**< URI (atom), NULL if no namespace */
	const char *local;			/**< Local name (atom) */
	char *value;				/**< Attribute value */
};

/**
 * Attribute key hashing.
 */
static unsigned
xattr_hash(const void *key)
{
	const struct xattr *xa = key;
	unsigned hash;

	/* xa->uri can be NULL, xa->local cannot */

	hash = (NULL == xa->uri) ? 0 : string_mix_hash(xa->uri);

	return hash ^ string_mix_hash(xa->local);
}

/**
 * Test two attribute keys for equality.
 */
static bool
xattr_eq(const void *k1, const void *k2)
{
	const struct xattr *x1 = k1;
	const struct xattr *x2 = k2;

	if (NULL == x1->uri) {
		return (NULL == x2->uri) ? 0 == strcmp(x1->local, x2->local) : FALSE;
	} else {
		return (NULL == x2->uri) ? FALSE : 0 == strcmp(x1->local, x2->local);
	}
}

/**
 * Allocate a new attribute key/value.
 *
 * @param uri		the namespace URI (may be NULL)
 * @param local		the local name
 * @param value		the attribute value (copied)
 *
 * @return a new attribute key/value.
 */
static struct xattr *
xattr_alloc(const char *uri, const char *local, const char *value)
{
	struct xattr *xa;

	WALLOC(xa);
	xa->uri = (NULL == uri) ? NULL : atom_str_get(uri);
	xa->local = atom_str_get(local);
	xa->value = h_strdup(value);

	return xa;
}

/**
 * Free an attribute key/value.
 */
static void
xattr_free(struct xattr *xa)
{
	g_assert(xa != NULL);

	atom_str_free_null(&xa->uri);
	atom_str_free_null(&xa->local);
	HFREE_NULL(xa->value);
	WFREE(xa);
}

/**
 * Create a new attribute table.
 */
xattr_table_t *
xattr_table_make(void)
{
	xattr_table_t *xat;

	WALLOC(xat);
	xat->magic = XATTR_TABLE_MAGIC;
	xat->hl = hash_list_new(xattr_hash, xattr_eq);

	return xat;
}

/**
 * Free an attribute table.
 */
static void
xattr_table_free(xattr_table_t *xat)
{
	xattr_table_check(xat);

	hash_list_free_all(&xat->hl, cast_to_hashlist_destroy(xattr_free));
	xat->magic = 0;
	WFREE(xat);
}

/**
 * Free an attribute table and nullify its pointer.
 */
void
xattr_table_free_null(xattr_table_t **xat_ptr)
{
	xattr_table_t *xat = *xat_ptr;

	if (xat != NULL) {
		xattr_table_free(xat);
		*xat_ptr = NULL;
	}
}

/**
 * Lookup an attribute in the table.
 *
 * The key is only used for lookups, only the hashed elements need to be
 * filled in.
 */
static struct xattr *
xattr_table_lookup_key(const xattr_table_t *xat, const struct xattr *key)
{
	const void *it;

	xattr_table_check(xat);

	return hash_list_find(xat->hl, key, &it) ? deconstify_pointer(it) : NULL;
}

/**
 * Insert an attribute to the table.
 *
 * If the attribute already existed, the value is replaced so that the
 * older position is kept.  Otherwsie, the new attribute is appended to the
 * list of existing attributes.
 *
 * @return TRUE when we create a new attribute, FALSE if we replaced the
 * value of an existing one.
 */
static bool
xattr_table_insert(xattr_table_t *xat, struct xattr *xa)
{
	struct xattr *old;

	xattr_table_check(xat);
	g_assert(xa != NULL);

	old = xattr_table_lookup_key(xat, xa);

	if (old != NULL) {
		HFREE_NULL(old->value);
		old->value = xa->value;
		xa->value = NULL;
		xattr_free(xa);
		return FALSE;
	} else {
		hash_list_append(xat->hl, xa);
		return TRUE;
	}
}

/**
 * Remove an attribute from the table.
 *
 * The key is only used for lookups, only the hashed elements need to be
 * filled in.
 *
 * @return TRUE if we found the attribute and removed it.
 */
static bool
xattr_table_remove_key(xattr_table_t *xat, const struct xattr *key)
{
	struct xattr *old;

	xattr_table_check(xat);
	g_assert(key != NULL);

	old = xattr_table_lookup_key(xat, key);

	if (old != NULL) {
		hash_list_remove(xat->hl, old);
		xattr_free(old);
		return TRUE;
	} else {
		return FALSE;
	}
}

/**
 * Add an XML attribute value to the table.
 *
 * If the value exisited in the table, the new value replaces the older one
 * which is then freed.
 *
 * Attributes are kept in the order in which they are inserted.
 *
 * For convenience, the URI may be NULL, in which case the routine behaves
 * as if xattr_table_add_local() had been called.
 *
 * @param xat		the XML attribute table
 * @param uri		the URI namespace of the attribute (copied if non-NULL)
 * @param local		the local name (copied)
 * @param value		the attribute value (copied)
 */
bool
xattr_table_add(xattr_table_t *xat,
	const char *uri, const char *local, const char *value)
{
	struct xattr *xa;

	xattr_table_check(xat);
	g_assert(local != NULL);
	g_assert(value != NULL);

	xa = xattr_alloc(uri, local, value);
	return xattr_table_insert(xat, xa);
}

/**
 * Remove an XML attribute from the table.
 *
 * @param xat		the XML attribute table
 * @param uri		the URI namespace of the attribute (may be NULL)
 * @param local		the local name
 *
 * @return TRUE if attribute existed and was removed.
 */
bool
xattr_table_remove(xattr_table_t *xat, const char *uri, const char *local)
{
	struct xattr key;

	xattr_table_check(xat);
	g_assert(local != NULL);

	key.uri = uri;
	key.local = local;

	return xattr_table_remove_key(xat, &key);
}

/**
 * Get the attribute value.
 *
 * @param xat		the XML attribute table
 * @param uri		the URI namespace of the attribute (may be NULL)
 * @param local		the local name
 *
 * @return the attribute value, or NULL if the attribute was not found.
 */
const char *
xattr_table_lookup(const xattr_table_t *xat, const char *uri, const char *local)
{
	struct xattr key;
	struct xattr *xa;

	xattr_table_check(xat);
	g_assert(local != NULL);

	key.uri = uri;
	key.local = local;

	xa = xattr_table_lookup_key(xat, &key);
	return (xa != NULL) ? xa->value : NULL;
}

/**
 * @return the number of attributes held.
 */
size_t
xattr_table_count(const xattr_table_t *xat)
{
	xattr_table_check(xat);

	return hash_list_length(xat->hl);
}

struct xattr_table_foreach_ctx {
	xattr_table_cb_t func;
	void *data;
};

static void
xattr_table_foreach_wrap(void *key, void *data)
{
	struct xattr *xa = key;
	struct xattr_table_foreach_ctx *ctx = data;

	(*ctx->func)(xa->uri, xa->local, xa->value, ctx->data);
}

/**
 * Apply function to each attribute, in the order they were defined.
 */
void
xattr_table_foreach(const xattr_table_t *xat, xattr_table_cb_t func, void *data)
{
	struct xattr_table_foreach_ctx ctx;

	xattr_table_check(xat);

	ctx.func = func;
	ctx.data = data;

	hash_list_foreach(xat->hl, xattr_table_foreach_wrap, &ctx);
}

/* vi: set ts=4 sw=4 cindent: */
