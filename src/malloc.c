/*
 * $Id$
 *
 * Copyright (c) 2004, Raphael Manfredi
 *
 * Debugging malloc, to supplant dmalloc which is not satisfactory.
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


#include "common.h"		/* For RCSID */

#include <stdlib.h>		/* For malloc() and qsort() */
#include <string.h>		/* For memset() */
#include <glib.h>

#ifdef TRACK_MALLOC

#define MALLOC_SOURCE	/* Avoid nasty remappings, but include signatures */
#include "override.h"

RCSID("$Id$");

//#define TRANSPARENT	/* To make sure our macros have no side effect */

/*
 * Structure keeping track of allocated blocks.
 *
 * Each block is inserted into a hash table, the key being the block's
 * address and the value being a structure keeping track of the initial
 * allocation, and possibly of all the reallocations performed.
 */
struct block {
	gchar *file;
	gint line;
	guint32 size;
	GSList *realloc;
};

GHashTable *blocks = NULL;

/*
 * malloc_init
 *
 * Called at first allocation to initialize tracking structures.
 */
static void malloc_init(void)
{
	blocks = g_hash_table_new(g_direct_hash, g_direct_equal);
}

/*
 * malloc_log_block		-- hash table iterator callback
 *
 * Log used block, and record it among the `leaksort' set for future summary.
 */
static void malloc_log_block(gpointer k, gpointer v, gpointer leaksort)
{
	struct block *b = (struct block *) v;

	g_warning("leaked block 0x%lx (%u bytes) from \"%s:%d\"",
		(gulong) k, b->size, b->file, b->line);

	leak_add(leaksort, b->size, b->file, b->line);

	if (b->realloc) {
		struct block *r = (struct block *) b->realloc->data;
		gint cnt = g_slist_length(b->realloc);

		g_warning("   (realloc'ed %d time%s, final: %u bytes from \"%s:%d\")",
			cnt, cnt == 1 ? "" : "s", r->size, r->file, r->line);
	}
}

/*
 * malloc_close
 *
 * Dump all the blocks that are still used.
 */
void malloc_close(void)
{
	gpointer leaksort;

	if (blocks == NULL)
		return;

	leaksort = leak_init();

	g_hash_table_foreach(blocks, malloc_log_block, leaksort);

	leak_dump(leaksort);
	leak_close(leaksort);
}

/*
 * malloc_record
 *
 * Record object `o' allocated at `file' and `line' of size `s'.
 * Returns argument `o'.
 */
gpointer malloc_record(gpointer o, guint32 s, gchar *file, gint line)
{
	struct block *b;

#ifdef TRANSPARENT
	return o;
#endif

	if (o == NULL)				/* In case it's called externally */
		return o;

	if (blocks == NULL)
		malloc_init();

	b = calloc(sizeof(*b), 1);
	if (b == NULL)
		g_error("unable to allocate %u bytes", sizeof(*b));

	b->file = file;
	b->line = line;
	b->size = s;
	b->realloc = NULL;

	g_hash_table_insert(blocks, o, b);

	return o;
}

/*
 * malloc_track
 *
 * Allocate `s' bytes.
 */
gpointer malloc_track(guint32 s, gchar *file, gint line)
{
	gpointer o;

	o = malloc(s);
	if (o == NULL)
		g_error("unable to allocate %u bytes", s);

	return malloc_record(o, s, file, line);
}

/*
 * malloc0_track
 *
 * Allocate `s' bytes, zero the allocated zone.
 */
gpointer malloc0_track(guint32 s, gchar *file, gint line)
{
	gpointer o;

	o = malloc_track(s, file, line);
	memset(o, 0, s);
	
	return o;
}

/*
 * free_track
 *
 * Free allocated block.
 */
void free_track(gpointer o, gchar *file, gint line)
{
	struct block *b;
	gpointer k;
	gpointer v;
	GSList *l;

#ifdef TRANSPARENT
	free(o);
	return;
#endif

	if (blocks == NULL || !(g_hash_table_lookup_extended(blocks, o, &k, &v))) {
		g_warning("(%s:%d) attempt to free block at 0x%lx twice?",
			file, line, (gulong) o);
		return;
	}

	free(o);

	b = (struct block *) v;
	g_assert(o == k);

	g_hash_table_remove(blocks, o);
	for (l = b->realloc; l; l = g_slist_next(l)) {
		struct block *r = l->data;
		g_assert(r->realloc == NULL);
		free(r);
	}
	g_slist_free(b->realloc);
	free(b);
}

/*
 * strfreev_track
 *
 * Free NULL-terminated vector of strings, and the vector.
 */
void strfreev_track(gchar **v, gchar *file, gint line)
{
	gchar *x;
	gchar **iv = v;

	while ((x = *iv++))
		free_track(x, file, line);

	free_track(v, file, line);
}

/*
 * realloc_track
 *
 * Realloc object `o' to `s' bytes.
 */
gpointer realloc_track(gpointer o, guint32 s, gchar *file, gint line)
{
	struct block *b;
	struct block *r;
	gpointer n;

	if (o == NULL)
		return malloc_track(s, file, line);

#ifdef TRANSPARENT
	return realloc(o, s);
#endif

	if (blocks == NULL || !(b = g_hash_table_lookup(blocks, o))) {
		g_warning("(%s:%d) attempt to realloc freed block at 0x%lx?",
			file, line, (gulong) o);
		return malloc_track(s, file, line);
	}

	n = realloc(o, s);

	if (n == NULL)
		g_error("cannot realloc %u-byte block into %u-byte one", b->size, s);

	r = calloc(sizeof(*r), 1);
	if (r == NULL)
		g_error("unable to allocate %u bytes", sizeof(*r));

	r->file = file;
	r->line = line;
	r->size = s;
	r->realloc = NULL;

	b->realloc = g_slist_prepend(b->realloc, r);	/* Last realloc at head */

	if (n != o) {
		g_hash_table_remove(blocks, o);
		g_hash_table_insert(blocks, n, b);
	}

	return n;
}

/*
 * memdup_track
 *
 * Duplicate buffer `p' of length `size'.
 */
gpointer memdup_track(gconstpointer p, guint size, gchar *file, gint line)
{
	gpointer o;

	if (p == NULL)
		return NULL;

	o = malloc_track(size, file, line);
	memcpy(o, p, size);

	return o;
}

/*
 * strdup_track
 *
 * Duplicate string `s'.
 */
gchar *strdup_track(const gchar *s, gchar *file, gint line)
{
	gpointer o;
	guint32 len;

	if (s == NULL)
		return NULL;

	len = strlen(s);
	o = malloc_track(len + 1, file, line);
	memcpy(o, s, len + 1);		/* Also copy trailing NUL */

	return o;
}

/*
 * strndup_track
 *
 * Duplicate string `s', on at most `n' chars.
 */
gchar *strndup_track(const gchar *s, gint n, gchar *file, gint line)
{
	gpointer o;
	gchar *p;
	gchar *q;
	gchar c;

	if (s == NULL)
		return NULL;

	o = malloc_track(n + 1, file, line);
	p = (gchar *) s;
	q = o;
	while ((c = *p++) && n-- > 0)
		*q++ = c;
	*q++ = '\0';

	return o;
}

/*
 * strjoinv_track
 *
 * Join items in `vec' with `s' in-between.
 */
gchar *strjoinv_track(const gchar *s, gchar **vec, gchar *file, gint line)
{
	gchar *o;
	
	o = g_strjoinv(s, vec);

	return malloc_record(o, strlen(o) + 1, file, line);
}

/*
 * strconcat_track
 *
 * Perform string concatenation, returning newly allocated string.
 */
gchar *strconcat_track(gchar *file, gint line, const gchar *s, ...)
{
	va_list args;
	gchar *o;

	va_start(args, s);
	o = gm_strconcatv(s, args);
	va_end(args);

	return malloc_record(o, strlen(o) + 1, file, line);
}

/*
 * strdup_printf_track
 *
 * Perform printf into newly allocated string.
 */
gchar *strdup_printf_track(gchar *file, gint line, const gchar *fmt, ...)
{
	va_list args;
	gchar *o;

	va_start(args, fmt);
	o = g_strdup_vprintf(fmt, args);
	va_end(args);

	return malloc_record(o, strlen(o) + 1, file, line);
}

/*
 * strsplit_track
 *
 * Perform a g_strplit() operation, tracking all returned strings.
 */
gchar **strsplit_track(
	const gchar *s, const gchar *d, gint m, gchar *file, gint line)
{
	gchar **v;
	gchar **iv;
	gchar *x;

	v = g_strsplit(s, d, m);
	malloc_record(v, (m + 1) * sizeof(gchar *), file, line);

	iv = v;
	while ((x = *iv++))
		malloc_record(x, strlen(x) + 1, file, line);

	return v;
}

/*
 * string_record
 *
 * Record string `s' allocated at `file' and `line'.
 * Returns argument `s'.
 */
gpointer string_record(const gchar *s, gchar *file, gint line)
{
	if (s == NULL)
		return NULL;

	return malloc_record((gpointer) s, strlen(s) + 1, file, line);
}

#endif /* TRACK_MALLOC */

/***
 *** This section contains general-purpose leak summarizing routines that
 *** can be used by both malloc() and zalloc().
 ***/

#if defined(TRACK_MALLOC) || defined(TRACK_ZALLOC)

struct leak_set {
	GHashTable *places;		/* Maps "file:4" -> total bytes */
	GHashTable *counts;		/* Maps "file:4" -> # of times seen */
};

/*
 * leak_init
 *
 * Initialize the leak accumulator by "file:line"
 */
gpointer leak_init(void)
{
	struct leak_set *ls;

	ls = malloc(sizeof(struct leak_set));
	ls->places = g_hash_table_new(g_str_hash, g_str_equal);
	ls->counts = g_hash_table_new(g_str_hash, g_str_equal);

	return ls;
}

/*
 * leak_free_kv
 *
 * Get rid of the key/value tupple in the leak table.
 */
static gboolean leak_free_kv(gpointer key, gpointer value, gpointer user)
{
	free(key);
	return TRUE;
}

/*
 * leak_close
 *
 * Dispose of the leaks accumulated.
 */
void leak_close(gpointer o)
{
	struct leak_set *ls = (struct leak_set *) o;

	/*
	 * Key strings are shared between the `places' and `counts' hash tables.
	 */

	g_hash_table_foreach_remove(ls->places, leak_free_kv, NULL);
	g_hash_table_destroy(ls->places);
	g_hash_table_destroy(ls->counts);

	free(ls);
}

/*
 * leak_add
 *
 * Record a new leak of `size' bytes allocated at `file', line `line'.
 */
void leak_add(gpointer o, guint32 size, gchar *file, gint line)
{
	struct leak_set *ls = (struct leak_set *) o;
	gchar *key = g_strdup_printf("%s:%d", file, line);
	gboolean found;
	gpointer k;
	gpointer v;

	found = g_hash_table_lookup_extended(ls->places, key, &k, &v);

	/*
	 * NB: keys are shared between the two hash tables.
	 */

	if (found) {
		guint32 leaked = size + GPOINTER_TO_UINT(v);
		guint32 count = GPOINTER_TO_UINT(g_hash_table_lookup(ls->counts, key));
		g_hash_table_insert(ls->places, k, GUINT_TO_POINTER(leaked));
		count++;
		g_hash_table_insert(ls->counts, k, GUINT_TO_POINTER(count));
		g_free(key);
	} else {
		g_hash_table_insert(ls->places, key, GUINT_TO_POINTER(size));
		g_hash_table_insert(ls->counts, key, GUINT_TO_POINTER(1));
	}
}

struct leak {			/* A memory leak, for sorting purposes */
	gchar *place;
	guint32 size;
	guint count;
};

/*
 * leak_size_cmp		-- qsort() callback
 *
 * Compare two pointers to "struct leak" based on their size value,
 * in reverse order.
 */
static gint leak_size_cmp(const void *p1, const void *p2)
{
	guint32 i1 = ((struct leak *) p1)->size;
	guint32 i2 = ((struct leak *) p2)->size;

	return
		i1 == i2 ?  0 :
		i1 < i2  ? +1 : -1;		/* Reverse order: largest first */
}

struct filler {			/* Used by hash table iterator to fill leak array */
	struct leak *leaks;
	gint count;			/* Size of `leaks' array */
	gint idx;			/* Next index to be filled */
	GHashTable *counts;	/* Hash table yielding amount of blocks leaked */
};

/*
 * fill_array			-- hash table iterator
 *
 * Append current hash table entry at the end of the "leaks" array.
 */
static void fill_array(gpointer key, gpointer value, gpointer user)
{
	struct filler *filler = (struct filler *) user;
	struct leak *l;

	g_assert(filler->idx < filler->count);

	l = &filler->leaks[filler->idx++];
	l->place = (gchar *) key;
	l->size = GPOINTER_TO_UINT(value);
	l->count = GPOINTER_TO_UINT(g_hash_table_lookup(filler->counts, key));
}

/*
 * leak_dump
 *
 * Dump the links sorted by decreasing leak size.
 */
void leak_dump(gpointer o)
{
	struct leak_set *ls = (struct leak_set *) o;
	gint count;
	struct filler filler;
	gint i;

	count = g_hash_table_size(ls->places);

	if (count == 0)
		return;

	filler.leaks = (struct leak *) malloc(sizeof(struct leak) * count);
	filler.count = count;
	filler.idx = 0;
	filler.counts = ls->counts;

	/*
	 * Linearize hash table into an array before sorting it by
	 * decreasing leak size.
	 */

	g_hash_table_foreach(ls->places, fill_array, &filler);
	qsort(filler.leaks, count, sizeof(struct leak), leak_size_cmp);

	/*
	 * Dump the leaks.
	 */

	g_warning("leak summary by total decreasing size:");

	for (i = 0; i < count; i++) {
		struct leak *l = &filler.leaks[i];
		g_warning("%u bytes (%u block%s) from \"%s\"", l->size,
			l->count, l->count == 1 ? "" : "s", l->place);
	}

	free(filler.leaks);
}

#endif /* TRACK_MALLOC || TRACK_ZALLOC */

