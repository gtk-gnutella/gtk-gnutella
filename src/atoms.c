/*
 * $Id$
 *
 * Copyright (c) 2002-2003, Raphael Manfredi
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

#define ATOMS_SOURCE
#include "common.h"

RCSID("$Id$");

#ifdef PROTECT_ATOMS
/*
 * With PROTECT_ATOMS the arena of atoms will be mapped read-only. This
 * might not be fully portable and should be used for debugging only.
 * The atoms must be page-aligned for this feature. So you'll need
 * much more memory.
 */

#include <sys/mman.h>

#ifndef PAGESIZE
#define PAGESIZE 4096
#endif

#define PADDING(x) (PAGESIZE - ((x) % PAGESIZE))

typedef enum {
	ATOM_PROT_MAGIC = 0x3eeb9a27U
} atom_prot_magic_t;

#else

#define PADDING(x) 0

#endif /* PROTECT_ATOMS */

#include "override.h"		/* Must be the last header included */

/*
 * Atoms are ref-counted.
 *
 * The reference count is held at the beginning of the data arena.
 * What we return to the outside is a pointer to arena[], not to
 * the atom structure.
 */
typedef struct atom {
		gint refcnt;			/* Amount of references */
#ifdef TRACK_ATOMS
		GHashTable *get;		/* Allocation spots */
		GHashTable *free;		/* Free spots */
#endif
#ifdef PROTECT_ATOMS
		union {
			struct {
				guint len;				/* Length of user arena */
				atom_prot_magic_t magic;
			} attr;
			gchar padding[PAGESIZE - sizeof(guint)];
		};
		/* PADDING */
#endif /* PROTECT_ATOMS */
		gchar arena[1];			/* Start of user arena */
} atom_t;


#define ARENA_OFFSET	G_STRUCT_OFFSET(struct atom, arena)

#ifdef PROTECT_ATOMS
static inline void atom_unprotect(atom_t *a)
{
	int ret;

	g_assert(ATOM_PROT_MAGIC == a->attr.magic);
	g_assert(a->attr.len > 0 && 0 == (a->attr.len % PAGESIZE));
	ret = mprotect(a->arena, a->attr.len, PROT_READ | PROT_WRITE);
	if (-1 == ret)
		g_warning("atom_unprotect: mprotect(%p, %u, ...) failed: %s",
			a->arena, a->attr.len, g_strerror(errno));
}

static inline void atom_protect(atom_t *a, guint len)
{
	int ret;

	g_assert(len > 0 && 0 == (len % PAGESIZE));
	a->attr.len = len;
	a->attr.magic = ATOM_PROT_MAGIC;
	ret = mprotect(a->arena, a->attr.len, PROT_READ);
	if (-1 == ret)
		g_warning("atom_protect: mprotect(%p, %u, ...) failed: %s",
			a->arena, a->attr.len, g_strerror(errno));
}
#else

#define atom_protect(a, l)
#define atom_unprotect(a)

#endif /* PROTECT_ATOMS */

typedef gint (*len_func_t)(gconstpointer v);
typedef const gchar *(*str_func_t)(gconstpointer v);

/*
 * Description of atom types.
 */
typedef struct table_desc {
	const gchar *type;			/* Type of atoms */
	GHashTable *table;			/* Table of atoms: "atom value" => 1 */
	GHashFunc hash_func;		/* Hashing function for atoms */
	GCompareFunc eq_func;		/* Atom equality function */
	len_func_t len_func;		/* Atom length function */
	str_func_t str_func;		/* Atom to human-readable string */
} table_desc_t;

#define public

static gint str_len(gconstpointer v);
static const gchar *str_str(gconstpointer v);
public guint guid_hash(gconstpointer key);
public gint guid_eq(gconstpointer a, gconstpointer b);
static gint guid_len(gconstpointer v);
static const gchar *guid_str(gconstpointer v);
public guint sha1_hash(gconstpointer key);
public gint sha1_eq(gconstpointer a, gconstpointer b);
static gint sha1_len(gconstpointer v);
static const gchar *sha1_str(gconstpointer v);
static gint int_len(gconstpointer v);
static const gchar *int_str(gconstpointer v);

#undef public

/*
 * The set of all atom types we know about.
 */
table_desc_t atoms[] = {
	{ "String",	NULL,	g_str_hash,	g_str_equal, str_len,	str_str	},	/* 0 */
	{ "GUID",	NULL,	guid_hash,	guid_eq,	 guid_len,	guid_str},	/* 1 */
	{ "SHA1",	NULL,	sha1_hash,	sha1_eq,	 sha1_len,	sha1_str},	/* 2 */
	{ "int",	NULL,	g_int_hash,	g_int_equal, int_len,	int_str},	/* 3 */
};

#define COUNT(x)	G_N_ELEMENTS(x)

/*
 * str_len
 *
 * Returns length of string + trailing NUL.
 */
static gint str_len(gconstpointer v)
{
	const gchar *p = (const gchar *) v;

	while (*p++)
		/* empty */;

	return p - (const gchar *) v;
}

/*
 * str_str
 *
 * Returns printable form of a string, i.e. self.
 */
static const gchar *str_str(gconstpointer v)
{
	return (const gchar *) v;
}

/*
 * binary_hash
 *
 * Hash `len' bytes (multiple of 4) starting from `key'.
 */
static guint binary_hash(const guchar *key, gint len)
{
	const gchar *buf = (const gchar *) key;
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
guint guid_hash(gconstpointer key)
{
	return binary_hash(key, 16);
}

/*
 * guid_eq
 *
 * Test two GUIDs for equality.
 */
gint guid_eq(gconstpointer a, gconstpointer b)
{
/* FIXME:	Disabled because of alignment problems
 *			This should work if guid was declared as guint32[4].
 */
#if 0
	const guint32 *ax = (const guint32 *) a;
	const guint32 *bx = (const guint32 *) b;

	return
		ax[0] == bx[0] &&
		ax[1] == bx[1] &&
		ax[2] == bx[2] &&
		ax[3] == bx[3];
#else
	return a == b || 0 == memcmp(a, b, 16);
#endif
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
 * guid_str
 *
 * Returns printable form of a GUID, as pointer to static data.
 */
static const gchar *guid_str(gconstpointer v)
{
	return guid_hex_str((const gchar *) v);
}

/*
 * sha1_hash
 *
 * Hash a SHA1 (20 bytes).
 *
 * NB: This routine is visible for the download mesh.
 */
guint sha1_hash(gconstpointer key)
{
	return binary_hash(key, 20);
}

/*
 * sha1_eq
 *
 * Test two SHA1s for equality.
 *
 * NB: This routine is visible for the download mesh.
 */
gint sha1_eq(gconstpointer a, gconstpointer b)
{
/* FIXME:	Disabled because of alignment problems
 *			This should work if sha1_t (?) was declared as guint32[5].
 */
#if 0
	const guint32 *ax = (const guint32 *) a;
	const guint32 *bx = (const guint32 *) b;

	return
		ax[0] == bx[0] &&
		ax[1] == bx[1] &&
		ax[2] == bx[2] &&
		ax[3] == bx[3] &&
		ax[4] == bx[4];
#else
	return a == b || 0 == memcmp(a, b, 20);
#endif
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
 * sha1_str
 *
 * Returns printable form of a SHA1, as pointer to static data.
 */
static const gchar *sha1_str(gconstpointer v)
{
	return sha1_base32((const gchar *) v);
}

/*
 * int_len
 *
 * Returns length of an int.
 */
static gint int_len(gconstpointer v)
{
	return sizeof(gint);
}

/*
 * int_str
 *
 * Returns printable form of an int, as pointer to static data.
 */
static const gchar *int_str(gconstpointer v)
{
	static gchar fmt[32];

	gm_snprintf(fmt, sizeof(fmt), "%d/%u",
		*(const gint *) v, *(const guint *) v);

	return fmt;
}

/*
 * atoms_init
 *
 * Initialize atom structures.
 */
void atoms_init(void)
{
	gint i;

#ifdef PROTECT_ATOMS
	g_assert(ARENA_OFFSET == PAGESIZE);
#endif /* PROTECT_ATOMS */

	for (i = 0; i < COUNT(atoms); i++) {
		table_desc_t *td = &atoms[i];

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
	table_desc_t *td;
	gboolean found;
	gpointer value;
	gpointer x;
	atom_t *a;
	gint len;

    g_assert(key != NULL);
	g_assert(type >= 0 && type < COUNT(atoms));

	td = &atoms[type];		/* Where atoms of this type are held */

	/* 
	 * If atom exists, increment ref count and return it.
	 */

	found = g_hash_table_lookup_extended(td->table, key, &value, &x);

	if (found) {
		a = (atom_t *) ((gchar *) value - ARENA_OFFSET);

		g_assert(a->refcnt > 0);

		a->refcnt++;
		return value;
	}

	/*
	 * Create new atom.
	 */

	len = (*td->len_func)(key);

	a = g_malloc(ARENA_OFFSET + len + PADDING(len));
	a->refcnt = 1;
	memcpy(a->arena, key, len);
	atom_protect(a, len + PADDING(len));

	/*
	 * Insert atom in table.
	 */

	g_hash_table_insert(td->table, a->arena, GINT_TO_POINTER(1));

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
	table_desc_t *td;
	gboolean found;
	gpointer value;
	gpointer x;
	atom_t *a;

    g_assert(key != NULL);
	g_assert(type >= 0 && type < COUNT(atoms));

	td = &atoms[type];		/* Where atoms of this type are held */

	found = g_hash_table_lookup_extended(td->table, key, &value, &x);

	g_assert(found);
	g_assert(value == key);

	a = (atom_t *) ((gchar *) key - ARENA_OFFSET);

	g_assert(a->refcnt > 0);

	/*
	 * Dispose of atom when its reference count reaches 0.
	 */

	if (--a->refcnt == 0) {
		g_hash_table_remove(td->table, key);
		atom_unprotect(a);
		g_free(a);
	}
}

#ifdef TRACK_ATOMS

struct spot {			/* Information about given spot */
	gint count;			/* Amount of allocation/free performed at spot */
};

/*
 * atom_get_track
 *
 * The tracking version of atom_get().
 * Returns the atom's value.
 */
gpointer atom_get_track(gint type, gconstpointer key, gchar *file, gint line)
{
	gpointer atom;
	atom_t *a;
	gchar buf[512];
	gpointer k;
	gpointer v;
	struct spot *sp;

	atom = atom_get(type, key);
	a = (atom_t *) ((gchar *) atom - ARENA_OFFSET);

	/*
	 * Initialize tracking tables on first allocation.
	 */

	if (a->refcnt == 1) {
		a->get = g_hash_table_new(g_str_hash, g_str_equal);
		a->free = g_hash_table_new(g_str_hash, g_str_equal);
	}

	gm_snprintf(buf, sizeof(buf), "%s:%d", file, line);

	if (g_hash_table_lookup_extended(a->get, buf, &k, &v)) {
		sp = (struct spot *) v;
		sp->count++;
	} else {
		sp = walloc(sizeof(*sp));
		sp->count = 1;
		g_hash_table_insert(a->get, g_strdup(buf), sp);
	}

	return atom;
}

/*
 * tracking_free_kv
 *
 * Free key/value pair of the tracking table.
 */
static gboolean tracking_free_kv(gpointer key, gpointer value, gpointer user)
{
	g_free(key);
	wfree(value, sizeof(struct spot));
	return TRUE;
}

/*
 * destroy_tracking_table
 *
 * Get rid of the tracking hash table.
 */
static void destroy_tracking_table(GHashTable *h)
{
	g_hash_table_foreach_remove(h, tracking_free_kv, NULL);
	g_hash_table_destroy(h);
}

/*
 * atom_free_track
 *
 * The tracking version of atom_free().
 * Remove one reference from atom. 
 * Dispose of atom if nobody references it anymore.
 */
void atom_free_track(gint type, gconstpointer key, gchar *file, gint line)
{
	atom_t *a;
	gchar buf[512];
	gpointer k;
	gpointer v;
	struct spot *sp;

	a = (atom_t *) ((gchar *) key - ARENA_OFFSET);

	/*
	 * If we're going to free the atom, dispose the tracking tables.
	 */

	if (a->refcnt == 1) {
		destroy_tracking_table(a->get);
		destroy_tracking_table(a->free);
	} else {
		gm_snprintf(buf, sizeof(buf), "%s:%d", file, line);

		if (g_hash_table_lookup_extended(a->free, buf, &k, &v)) {
			sp = (struct spot *) v;
			sp->count++;
		} else {
			sp = walloc(sizeof(*sp));
			sp->count = 1;
			g_hash_table_insert(a->free, g_strdup(buf), sp);
		}
	}

	atom_free(type, key);
}

/*
 * dump_tracking_entry
 *
 * Dump all the spots where some tracked operation occurred, along with the
 * amount of such operations.
 */
static void dump_tracking_entry(gpointer key, gpointer value, gpointer user)
{
	struct spot *sp = (struct spot *) value;
	gchar *what = (gchar *) user;

	g_warning("%10d %s at \"%s\"", sp->count, what, (gchar *) key);
}

/*
 * dump_tracking_table
 *
 * Dump the values held in the tracking table `h'.
 */
static void dump_tracking_table(gpointer atom, GHashTable *h, gchar *what)
{
	gint count = g_hash_table_size(h);

	g_warning("all %d %s spot%s for 0x%lx:",
		count, what, count == 1 ? "" : "s", (gulong) atom);

	g_hash_table_foreach(h, dump_tracking_entry, what);
}

#endif	/* TRACK_ATOMS */

/*
 * atom_warn_free
 *
 * Warning about existing atom that should have been freed.
 */
static gboolean atom_warn_free(gpointer key, gpointer value, gpointer udata)
{
	atom_t *a = (atom_t *) ((gchar *) key - ARENA_OFFSET);
	table_desc_t *td = (table_desc_t *) udata;

	g_warning("found remaining %s atom 0x%lx, refcnt=%d: \"%s\"",
		td->type, (glong) key, a->refcnt, (*td->str_func)(key));

#ifdef TRACK_ATOMS
	dump_tracking_table(key, a->get, "get");
	dump_tracking_table(key, a->free, "free");
	destroy_tracking_table(a->get);
	destroy_tracking_table(a->free);
#endif

	/*
	 * Don't free the entry, so that we know where the leak originates from
	 * when running under -DUSE_DMALLOC or via valgrind.
	 *		--RAM, 02/02/2003
	 */

	return TRUE;
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
		table_desc_t *td = &atoms[i];

		g_hash_table_foreach_remove(td->table, atom_warn_free, td);
		g_hash_table_destroy(td->table);
	}
}

