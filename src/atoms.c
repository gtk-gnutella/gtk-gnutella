/*
 * Copyright (c) 2002, Raphael Manfredi
 *
 * Atom management.
 *
 * An atom is a single piece of information that is likely to be shared
 * and which is therefore only allocated once: all other instances point
 * to the common object.
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

#include <string.h>

#include "atoms.h"

/*
 * Atoms are ref-counted.
 *
 * The reference count is held at the beginning of the data arena.
 * What we return to the outside is a pointer to arena[], not to
 * the atom structure.
 */
struct atom {
	gint refcnt;				/* Amount of references */
	guchar arena[1];			/* Start of user arena */
};

#define ARENA_OFFSET	G_STRUCT_OFFSET(struct atom, arena)

typedef gint (*len_func_t)(gconstpointer v);

/*
 * Description of atom types.
 */
struct table_desc {
	gchar *type;				/* Type of atoms */
	GHashTable *table;			/* Table of atoms: "atom value" => 1 */
	GHashFunc hash_func;		/* Hashing function for atoms */
	GCompareFunc eq_func;		/* Atom equality function */
	len_func_t len_func;		/* Atom length function */
};

static gint str_len(gconstpointer v);
static guint guid_hash(gconstpointer key);
static gint guid_eq(gconstpointer a, gconstpointer b);
static gint guid_len(gconstpointer v);
static guint sha1_hash(gconstpointer key);
static gint sha1_eq(gconstpointer a, gconstpointer b);
static gint sha1_len(gconstpointer v);

/*
 * The set of all atom types we know about.
 */
struct table_desc atoms[] = {
	{ "String",	NULL,	g_str_hash,	g_str_equal, str_len	},	/* 0 */
	{ "GUID",	NULL,	guid_hash,	guid_eq,	 guid_len	},	/* 1 */
	{ "SHA1",	NULL,	sha1_hash,	sha1_eq,	 sha1_len	},	/* 2 */
};

#define COUNT(x)	(sizeof(x) / sizeof(x[0]))

/*
 * str_len
 *
 * Returns length of string + trailing NUL.
 */
static gint str_len(gconstpointer v)
{
	gchar *p = (gchar *) v;

	while (*p++)
		/* empty */;

	return p - (gchar *) v;
}

/*
 * binary_hash
 *
 * Hash `len' bytes (multiple of 4) starting from `key'.
 */
static guint binary_hash(gconstpointer key, gint len)
{
	guchar *buf = (guchar *) key;
	gint i;
	guint hash = 0;

	g_assert(0 == (len & 0x3));		/* Multiple of 4 */

	for (i = 0; i < len; i += 4) {
		guint v =
			(buf[i])            |
			(buf[i + 1] << 8)   |
			(buf[i + 2] << 16)  |
			(buf[i + 3] << 24);

		hash ^= v;
	}

	return hash;
}

/*
 * guid_hash
 *
 * Hash a GUID (16 bytes).
 */
static guint guid_hash(gconstpointer key)
{
	return binary_hash(key, 16);
}

/*
 * guid_eq
 *
 * Test two GUIDs for equality.
 */
static gint guid_eq(gconstpointer a, gconstpointer b)
{
	return 0 == memcmp(a, b, 16);
}

/*
 * guid_len
 *
 * Returns length of GUID.
 */
static gint guid_len(gconstpointer v)
{
	return 16;
}

/*
 * sha1_hash
 *
 * Hash a SHA1 (20 bytes).
 */
static guint sha1_hash(gconstpointer key)
{
	return binary_hash(key, 20);
}

/*
 * sha1_eq
 *
 * Test two SHA1s for equality.
 */
static gint sha1_eq(gconstpointer a, gconstpointer b)
{
	return 0 == memcmp(a, b, 20);
}

/*
 * sha1_len
 *
 * Returns length of SHA1.
 */
static gint sha1_len(gconstpointer v)
{
	return 20;
}


/*
 * atoms_init
 *
 * Initialize atom structures.
 */
void atoms_init(void)
{
	gint i;

	for (i = 0; i < COUNT(atoms); i++) {
		struct table_desc *td = &atoms[i];

		td->table = g_hash_table_new(td->hash_func, td->eq_func);
	}
}

/*
 * atom_get
 *
 * Get atom of given `type', whose value is `key'.
 * If the atom does not exist yet, `key' is cloned and makes up the new atom.
 *
 * Returns the atom's value.
 */
gpointer atom_get(gint type, gconstpointer key)
{
	struct table_desc *td;
	gboolean found;
	gpointer value;
	gpointer x;
	struct atom *a;
	gint len;

	g_assert(type >= 0 && type < COUNT(atoms));

	td = &atoms[type];		/* Where atoms of this type are held */

	/* 
	 * If atom exists, increment ref count and return it.
	 */

	found = g_hash_table_lookup_extended(td->table, key, &value, &x);

	if (found) {
		a = (struct atom *) (value - ARENA_OFFSET);

		g_assert(a->refcnt > 0);

		a->refcnt++;
		return value;
	}

	/*
	 * Create new atom.
	 */

	len = (*td->len_func)(key);

	a = g_malloc(ARENA_OFFSET + len);
	a->refcnt = 1;
	memcpy(a->arena, key, len);

	/*
	 * Insert atom in table.
	 */

	g_hash_table_insert(td->table, a->arena, (gpointer) 1);

	return a->arena;
}

/*
 * atom_free
 *
 * Remove one reference from atom. 
 * Dispose of atom if nobody references it anymore.
 */
void atom_free(gint type, gconstpointer key)
{
	struct table_desc *td;
	gboolean found;
	gpointer value;
	gpointer x;
	struct atom *a;

	g_assert(type >= 0 && type < COUNT(atoms));

	td = &atoms[type];		/* Where atoms of this type are held */

	found = g_hash_table_lookup_extended(td->table, key, &value, &x);

	g_assert(found);
	g_assert(value == key);

	a = (struct atom *) (key - ARENA_OFFSET);

	g_assert(a->refcnt > 0);

	/*
	 * Dispose of atom when its reference count reaches 0.
	 */

	if (--a->refcnt == 0) {
		g_hash_table_remove(td->table, key);
		g_free(a);
	}
}

/*
 * atom_warn_free
 *
 * Free atom entry, warning about it.
 */
static gboolean atom_warn_free(gpointer key, gpointer value, gpointer udata)
{
	struct atom *a = (struct atom *) (key - ARENA_OFFSET);

	g_warning("freeing remaining %s atom 0x%lx, refcnt=%d",
		(gchar *) udata, (glong) key, a->refcnt);

	g_free(a);

	return TRUE;
}

/*
 * atoms_free_all
 *
 * Remove all atoms from table, warning about problems.
 */
static void atoms_free_all(GHashTable *ht, gchar *type)
{
	g_hash_table_foreach_remove(ht, atom_warn_free, type);
}

/*
 * atoms_close
 *
 * Shutdown atom structures, freeing all remaining atoms.
 */
void atoms_close(void)
{
	gint i;

	for (i = 0; i < COUNT(atoms); i++) {
		struct table_desc *td = &atoms[i];

		atoms_free_all(td->table, td->type);
		g_hash_table_destroy(td->table);
	}
}

