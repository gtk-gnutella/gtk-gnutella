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
 * Debugging malloc, to supplant dmalloc which is not satisfactory.
 *
 * @author Raphael Manfredi
 * @date 2004
 */

#include "common.h"		/* For RCSID */

#include "atoms.h"		/* For binary_hash() */
#include "misc.h"		/* For concat_strings() */
#include "tm.h"			/* For tm_time() */

/**
 * Routines in this file are defined either for TRACK_MALLOC or TRACK_ZALLOC
 */

#if defined(TRACK_MALLOC) || defined(TRACK_ZALLOC)
RCSID("$Id$");

/*
 * When MALLOC_FRAMES is supplied, we keep information about the allocation
 * stack frame and free stack frames.
 *
 * This turns on MALLOC_STATS automatically if not set.
 *
 * XXX need metaconfig checks for execinfo.h, backtrace() and
 * backtrace_symbols().  Also, when GNU ld is used, -rdynamic must be
 * added to the ld flags to get routine name information.
 */

#ifdef MALLOC_FRAMES
#include <execinfo.h>

#ifndef MALLOC_STATS
#define MALLOC_STATS
#endif

#define FRAME_DEPTH		8	/**< Size of allocation frame we keep around */

#endif /* MALLOC_FRAMES */
#endif /* TRACK_MALLOC || TRACK_ZALLOC */

#ifdef TRACK_MALLOC

#include "hashlist.h"
#include "misc.h"
#include "glib-missing.h"
#define MALLOC_SOURCE	/**< Avoid nasty remappings, but include signatures */
#include "override.h"

#if 0
#define TRANSPARENT		/**< To make sure our macros have no side effect */
#endif

static time_t init_time = 0;
static time_t reset_time = 0;

/**
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

static GHashTable *blocks = NULL;

static void free_record(gpointer o, gchar *file, gint line);

#ifdef MALLOC_FRAMES

/**
 * Structure keeping track of the allocation/free stack frames.
 *
 * Counts are signed because for realloc() frames, we count algebric
 * quantities (in case the blocks are shrunk).
 */
struct frame {
	void *stack[FRAME_DEPTH];	/**< PC of callers */
	gint len;					/**< Number of valid entries in stack */
	gint32 count;				/**< Bytes allocated/freed since reset */
	gint32 total_count;			/**< Grand total for this stack frame */
};

/**
 * Hashing routine for a "struct frame".
 */
static guint
frame_hash(gconstpointer key)
{
	struct frame *f = (struct frame *) key;

	return binary_hash((gconstpointer) f->stack, f->len * sizeof(void *));
}

/**
 * Comparison of two "struct frame" structures.
 */
static gint
frame_eq(gconstpointer a, gconstpointer b)
{
	struct frame *fa = (struct frame *) a;
	struct frame *fb = (struct frame *) b;

	return fa->len == fb->len &&
		0 == memcmp(fa->stack, fb->stack, fa->len * sizeof(void *));
}

#endif /* MALLOC_FRAMES */

/**
 * @struct stats
 *
 * When MALLOC_STATS is supplied, we keep information about the amount
 * of bytes allocated from a single point in the code, and the amount
 * of it that has been freed.
 *
 * When compiling with MALLOC_STATS, it's best to use REMAP_ZALLOC
 * as well since normally zalloc has its own block tracking features
 * that will not be accounted for in the malloc stats.
 */
#ifdef MALLOC_STATS

struct stats {
	gchar *file;				/**< Place where allocation took place */
	gint line;					/**< Line number */
	gint blocks;				/**< Live blocks since last "reset" */
	gint total_blocks;			/**< Total live blocks */
	guint32 allocated;			/**< Total allocated since last "reset" */
	guint32 freed;				/**< Total freed since last "reset" */
	guint32 total_allocated;	/**< Total allocated overall */
	guint32 total_freed;		/**< Total freed overall */
	gint32 reallocated;			/**< Total reallocated since last "reset" */
	gint32 total_reallocated;	/**< Total reallocated overall (algebric!) */
#ifdef MALLOC_FRAMES
	GHashTable *alloc_frames;	/**< The frames where allocation took place */
	GHashTable *free_frames;	/**< The frames where free took place */
	GHashTable *realloc_frames;	/**< The frames where realloc took place */
#endif /* MALLOC_FRAMES */
};

static GHashTable *stats = NULL; /**< maps stats(file, line) -> stats */

/**
 * Hashing routine for "struct stats".
 * Only the "file" and "line" fields are considered.
 */
static guint
stats_hash(gconstpointer key)
{
	struct stats *s = (struct stats *) key;

	return g_str_hash(s->file) ^ s->line;
}

/**
 * Comparison of two "struct stats" structures.
 * Only the "file" and "line" fields are considered.
 */
static gint
stats_eq(gconstpointer a, gconstpointer b)
{
	struct stats *sa = (struct stats *) a;
	struct stats *sb = (struct stats *) b;

	return  sa->line == sb->line && 0 == strcmp(sa->file, sb->file);
}
#endif /* MALLOC_STATS */

/**
 * malloc_init
 *
 * Called at first allocation to initialize tracking structures.
 */
static void
malloc_init(void)
{
	blocks = g_hash_table_new(g_direct_hash, g_direct_equal);

#ifdef MALLOC_STATS
	stats = g_hash_table_new(stats_hash, stats_eq);
#endif

	init_time = reset_time = tm_time();
}

/**
 * malloc_log_block		-- hash table iterator callback
 *
 * Log used block, and record it among the `leaksort' set for future summary.
 */
static void
malloc_log_block(gpointer k, gpointer v, gpointer leaksort)
{
	struct block *b = (struct block *) v;

	g_warning("leaked block 0x%lx (%u bytes) from \"%s:%d\"",
		(gulong) k, b->size, b->file, b->line);

	leak_add(leaksort, b->size, b->file, b->line);

	if (b->realloc) {
		struct block *r = (struct block *) b->realloc->data;
		gint cnt = g_slist_length(b->realloc);

		g_warning("   (realloc'ed %d time%s, lastly from \"%s:%d\")",
			cnt, cnt == 1 ? "" : "s", r->file, r->line);
	}
}

/**
 * Dump all the blocks that are still used.
 */
void
malloc_close(void)
{
	gpointer leaksort;

	if (blocks == NULL)
		return;

#ifdef MALLOC_STATS
	g_warning("aggregated memory usage statistics:");
	alloc_dump(stderr, TRUE);
#endif

	leaksort = leak_init();

	g_hash_table_foreach(blocks, malloc_log_block, leaksort);

	leak_dump(leaksort);
	leak_close(leaksort);
}

/**
 * Record object `o' allocated at `file' and `line' of size `s'.
 * @return argument `o'.
 */
gpointer
malloc_record(gpointer o, guint32 sz, gchar *file, gint line)
{
	struct block *b;
	struct block *ob;
#ifdef MALLOC_STATS
	struct stats *st;		/* Needed in case MALLOC_FRAMES is also set */
#endif

#ifdef TRANSPARENT
	return o;
#endif

	if (o == NULL)			/* In case it's called externally */
		return o;

	if (blocks == NULL)
		malloc_init();

	b = calloc(1, sizeof(*b));
	if (b == NULL)
		g_error("unable to allocate %u bytes", sizeof(*b));

	b->file = short_filename(file);
	b->line = line;
	b->size = sz;
	b->realloc = NULL;

	/**
	 * It can happen that we track the allocation of a block somewhere
	 * but the freeing happens somewhere we either we forgot to include
	 * "override.h", or happens in some library (e.g. in GTK+) where we
	 * can't record it.
	 *
	 * If we're "lucky" enough to see the address of such a block being
	 * reused again, then it has necessarily been freed, or malloc() would
	 * not reuse it again!  Fake a free from "FAKED:0".
	 */

	if ((ob = (struct block *) g_hash_table_lookup(blocks, o))) {
		g_warning("(%s:%d) reusing block 0x%lx from %s:%d, missed its freeing",
			file, line, (glong) o, ob->file, ob->line);
		free_record(o, "FAKED", 0);
	}

	g_hash_table_insert(blocks, o, b);

#ifdef MALLOC_STATS
	{
		struct stats s;

		s.file = b->file;
		s.line = line;

		st = g_hash_table_lookup(stats, &s);

		if (st == NULL) {
			st = calloc(1, sizeof(*st));
			st->file = b->file;
			st->line = line;
			g_hash_table_insert(stats, st, st);
		}

		st->total_blocks++;
		st->blocks++;
		st->allocated += sz;
		st->total_allocated += sz;
	}
#endif /* MALLOC_STATS */
#ifdef MALLOC_FRAMES
	{
		struct frame f;
		struct frame *fr = NULL;

		f.len = backtrace(f.stack, G_N_ELEMENTS(f.stack));

		if (st->alloc_frames == NULL)
			st->alloc_frames = g_hash_table_new(frame_hash, frame_eq);
		else
			fr = g_hash_table_lookup(st->alloc_frames, &f);

		if (fr == NULL) {
			fr = calloc(1, sizeof(*fr));
			memcpy(fr->stack, f.stack, f.len * sizeof(void *));
			fr->len = f.len;
			g_hash_table_insert(st->alloc_frames, fr, fr);
		}

		fr->count += sz;
		fr->total_count += sz;
	}
#endif /* MALLOC_FRAMES */

	return o;
}

/**
 * Allocate `s' bytes.
 */
gpointer
malloc_track(guint32 s, gchar *file, gint line)
{
	gpointer o;

	o = malloc(s);
	if (o == NULL)
		g_error("unable to allocate %u bytes", s);

	return malloc_record(o, s, file, line);
}

/**
 * Allocate `s' bytes, zero the allocated zone.
 */
gpointer
malloc0_track(guint32 s, gchar *file, gint line)
{
	gpointer o;

	o = malloc_track(s, file, line);
	memset(o, 0, s);

	return o;
}

/**
 * Record freeing of allocated block.
 */
static void
free_record(gpointer o, gchar *file, gint line)
{
	struct block *b;
	gpointer k;
	gpointer v;
	GSList *l;
#ifdef MALLOC_STATS
	struct stats *st;		/* Needed in case MALLOC_FRAMES is also set */
#endif

	if (blocks == NULL || !(g_hash_table_lookup_extended(blocks, o, &k, &v))) {
		g_warning("(%s:%d) attempt to free block at 0x%lx twice?",
			file, line, (gulong) o);
		return;
	}

	b = (struct block *) v;
	g_assert(o == k);

#ifdef MALLOC_STATS
	{
		struct stats s;

		s.file = b->file;
		s.line = b->line;

		st = g_hash_table_lookup(stats, &s);

		if (st == NULL)
			g_warning("(%s:%d) no allocation record of block 0x%lx from %s:%d?",
				file, line, (gulong) o, b->file, b->line);
		else {
			/* Count present block size, after possible realloc() */
			st->freed += b->size;
			st->total_freed += b->size;
			if (st->total_blocks > 0)
				st->total_blocks--;
			else
				g_warning("(%s:%d) live # of blocks was zero at free time?",
					file, line);

			/* We could free blocks allocated before "reset", don't warn */
			if (st->blocks > 0)
				st->blocks--;
		}
	}
#endif /* MALLOC_STATS */
#ifdef MALLOC_FRAMES
	if (st != NULL) {
		struct frame f;
		struct frame *fr = NULL;

		f.len = backtrace(f.stack, G_N_ELEMENTS(f.stack));

		if (st->free_frames == NULL)
			st->free_frames = g_hash_table_new(frame_hash, frame_eq);
		else
			fr = g_hash_table_lookup(st->free_frames, &f);

		if (fr == NULL) {
			fr = calloc(1, sizeof(*fr));
			memcpy(fr->stack, f.stack, f.len * sizeof(void *));
			fr->len = f.len;
			g_hash_table_insert(st->free_frames, fr, fr);
		}

		fr->count += b->size;			/* Counts actual size, not original */
		fr->total_count += b->size;
	}
#endif /* MALLOC_FRAMES */

	g_hash_table_remove(blocks, o);

	for (l = b->realloc; l; l = g_slist_next(l)) {
		struct block *r = l->data;
		g_assert(r->realloc == NULL);
		free(r);
	}
	g_slist_free(b->realloc);

	free(b);
}

/**
 * Free allocated block.
 */
void
free_track(gpointer o, gchar *file, gint line)
{
#ifndef TRANSPARENT
	free_record(o, file, line);
#endif
	free(o);
}

/**
 * Free NULL-terminated vector of strings, and the vector.
 */
void
strfreev_track(gchar **v, gchar *file, gint line)
{
	gchar *x;
	gchar **iv = v;

	while ((x = *iv++))
		free_track(x, file, line);

	free_track(v, file, line);
}

/**
 * Update data structures to record that block `o' was re-alloced into
 * a block of `s' bytes at `n'.
 */
static gpointer
realloc_record(gpointer o, gpointer n, guint32 s, gchar *file, gint line)
{
	struct block *b;
	struct block *r;
#ifdef MALLOC_STATS
	struct stats *st;		/* Needed in case MALLOC_FRAMES is also set */
#endif

	if (blocks == NULL || !(b = g_hash_table_lookup(blocks, o))) {
		g_warning("(%s:%d) attempt to realloc freed block at 0x%lx?",
			file, line, (gulong) o);
		return malloc_record(n, s, file, line);
	}

	r = calloc(sizeof(*r), 1);
	if (r == NULL)
		g_error("unable to allocate %u bytes", sizeof(*r));

	r->file = short_filename(file);
	r->line = line;
	r->size = b->size;			/* Previous size before realloc */
	r->realloc = NULL;

	b->realloc = g_slist_prepend(b->realloc, r);	/* Last realloc at head */
	b->size = s;

	if (n != o) {
		g_hash_table_remove(blocks, o);
		g_hash_table_insert(blocks, n, b);
	}

#ifdef MALLOC_STATS
	{
		struct stats s;

		s.file = b->file;
		s.line = b->line;

		st = g_hash_table_lookup(stats, &s);

		if (st == NULL)
			g_warning("(%s:%d) no allocation record of block 0x%lx from %s:%d?",
				file, line, (gulong) o, b->file, b->line);
		else {
			/* We store variations in size, as algebric quantities */
			st->reallocated += b->size - r->size;
			st->total_reallocated += b->size - r->size;
		}
	}
#endif /* MALLOC_STATS */
#ifdef MALLOC_FRAMES
	if (st != NULL) {
		struct frame f;
		struct frame *fr = NULL;

		f.len = backtrace(f.stack, G_N_ELEMENTS(f.stack));

		if (st->realloc_frames == NULL)
			st->realloc_frames = g_hash_table_new(frame_hash, frame_eq);
		else
			fr = g_hash_table_lookup(st->realloc_frames, &f);

		if (fr == NULL) {
			fr = calloc(1, sizeof(*fr));
			memcpy(fr->stack, f.stack, f.len * sizeof(void *));
			fr->len = f.len;
			g_hash_table_insert(st->realloc_frames, fr, fr);
		}

		fr->count += b->size - r->size;
		fr->total_count += b->size - r->size;
	}
#endif /* MALLOC_FRAMES */

	return n;
}

/**
 * Realloc object `o' to `s' bytes.
 */
gpointer
realloc_track(gpointer o, guint32 s, gchar *file, gint line)
{
	gpointer n;

	if (o == NULL)
		return malloc_track(s, file, line);

#ifdef TRANSPARENT
	return realloc(o, s);
#endif

	n = realloc(o, s);

	if (n == NULL)
		g_error("cannot realloc block into a %u-byte one", s);

	return realloc_record(o, n, s, file, line);
}

/**
 * Duplicate buffer `p' of length `size'.
 */
gpointer
memdup_track(gconstpointer p, guint size, gchar *file, gint line)
{
	gpointer o;

	if (p == NULL)
		return NULL;

	o = malloc_track(size, file, line);
	memcpy(o, p, size);

	return o;
}

/**
 * Duplicate string `s'.
 */
gchar *
strdup_track(const gchar *s, gchar *file, gint line)
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

/**
 * Duplicate string `s', on at most `n' chars.
 */
gchar *
strndup_track(const gchar *s, gint n, gchar *file, gint line)
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

/**
 * Join items in `vec' with `s' in-between.
 */
gchar *
strjoinv_track(const gchar *s, gchar **vec, gchar *file, gint line)
{
	gchar *o;

	o = g_strjoinv(s, vec);

	return malloc_record(o, strlen(o) + 1, file, line);
}

/**
 * The internal implementation of a vectorized g_strconcat().
 */
static gchar *
m_strconcatv(const gchar *s, va_list args)
{
	gchar *res;
	gchar *add;
	gint size;

	size = strlen(s) + 1;
	res = g_malloc(size);
	memcpy(res, s, size);

	while ((add = va_arg(args, gchar *))) {
		gint len = strlen(add);
		res = g_realloc(res, size + len);
		memcpy(res + size - 1, add, len + 1);	/* Includes trailing NULL */
		size += len;
	}

	return res;
}

/**
 * Perform string concatenation, returning newly allocated string.
 */
gchar *
strconcat_track(gchar *file, gint line, const gchar *s, ...)
{
	va_list args;
	gchar *o;

	va_start(args, s);
	o = m_strconcatv(s, args);
	va_end(args);

	return malloc_record(o, strlen(o) + 1, file, line);
}

/**
 * Perform printf into newly allocated string.
 */
gchar *
strdup_printf_track(gchar *file, gint line, const gchar *fmt, ...)
{
	va_list args;
	gchar *o;

	va_start(args, fmt);
	o = g_strdup_vprintf(fmt, args);
	va_end(args);

	return malloc_record(o, strlen(o) + 1, file, line);
}

/**
 * Perform a g_strplit() operation, tracking all returned strings.
 */
gchar **
strsplit_track(const gchar *s, const gchar *d, gint m, gchar *file, gint line)
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

/**
 * Record string `s' allocated at `file' and `line'.
 * @return argument `s'.
 */
gpointer
string_record(const gchar *s, gchar *file, gint line)
{
	if (s == NULL)
		return NULL;

	return malloc_record((gpointer) s, strlen(s) + 1, file, line);
}

/**
 * Wrapper over g_hash_table_new() to track allocation of hash tables.
 */
GHashTable *
hashtable_new_track(GHashFunc h, GCompareFunc y, gchar *file, gint line)
{
	GHashTable *o;

	o = g_hash_table_new(h, y);
	return malloc_record(o, 24, file, line);	/* Size not right, don't care */
}

/**
 * Wrapper over g_hash_Table_destroy() to track destruction of hash tables.
 */
void
hashtable_destroy_track(GHashTable *h, gchar *file, gint line)
{
	free_record(h, file, line);
	g_hash_table_destroy(h);
}

/**
 * Wrapper over hash_list_new().
 */
hash_list_t *
hash_list_new_track(
	GHashFunc hash_func, GEqualFunc eq_func, gchar *file, gint line)
{
	return malloc_record(
		hash_list_new(hash_func, eq_func),
		28,				/* Approx. size */
		file, line);
}

/**
 * Wrapper over hash_list_free().
 */
void
hash_list_free_track(hash_list_t *h, gchar *file, gint line)
{
	free_record(h, file, line);
	hash_list_free(h);
}

/***
 *** List trackers, to unveil hidden linkable allocation.
 ***/

#define GSLIST_LINK_SIZE	8		/* Random size */
#define GLIST_LINK_SIZE		12		/* Random size */

GSList *
slist_alloc_track(gchar *file, gint line)
{
	return malloc_record(g_slist_alloc(), GSLIST_LINK_SIZE, file, line);
}

GSList *
slist_append_track(GSList *l, gpointer data, gchar *file, gint line)
{
	GSList *new;

	new = slist_alloc_track(file, line);
	new->data = data;

	if (l) {
		GSList *last = g_slist_last(l);
		last->next = new;
		return l;
	} else
		return new;
}

GSList *
slist_prepend_track(GSList *l, gpointer data, gchar *file, gint line)
{
	GSList *new;

	new = slist_alloc_track(file, line);
	new->data = data;
	new->next = l;

	return new;
}

GSList *
slist_copy_track(GSList *list, gchar *file, gint line)
{
	GSList *new;
	GSList *l;

	new = g_slist_copy(list);

	for (l = new; l; l = g_slist_next(l))
		malloc_record(l, GSLIST_LINK_SIZE, file, line);

	return new;
}

void
slist_free_track(GSList *l, gchar *file, gint line)
{
	GSList *lk;

	for (lk = l; lk; lk = g_slist_next(lk))
		free_record(lk, file, line);

	g_slist_free(l);
}

void
slist_free1_track(GSList *l, gchar *file, gint line)
{
	if (l == NULL)
		return;

	free_record(l, file, line);
	g_slist_free_1(l);
}

GSList *
slist_remove_track(GSList *l, gpointer data, gchar *file, gint line)
{
	GSList *lk;

	lk = g_slist_find(l, data);
	if (lk == NULL)
		return l;

	return slist_delete_link_track(l, lk, file, line);
}

GSList *
slist_delete_link_track(GSList *l, GSList *lk, gchar *file, gint line)
{
	GSList *new;

	new = g_slist_remove_link(l, lk);
	slist_free1_track(lk, file, line);

	return new;
}

GSList *
slist_insert_track(GSList *l, gpointer data, gint pos, gchar *file, gint line)
{
	GSList *lk;

	if (pos < 0)
		return slist_append_track(l, data, file, line);
	else if (pos == 0)
		return slist_prepend_track(l, data, file, line);

	lk = g_slist_nth(l, pos - 1);
	if (lk == NULL)
		return slist_append_track(l, data, file, line);
	else
		return slist_insert_after_track(l, lk, data, file, line);
}

GSList *
slist_insert_sorted_track(GSList *l, gpointer d, GCompareFunc c,
	gchar *file, gint line)
{
	gint cmp;
	GSList *tmp = l;
	GSList *prev = NULL;
	GSList *new;

	if (l == NULL)
		return slist_prepend_track(l, d, file, line);

	cmp = (*c)(d, tmp->data);
	while (tmp->next != NULL && cmp > 0) {
		prev = tmp;
		tmp = tmp->next;
		cmp = (*c)(d, tmp->data);
	}

	new = slist_alloc_track(file, line);
	new->data = d;

	if (tmp->next == NULL && cmp > 0) {
		tmp->next = new;
		return l;
	}

	if (prev != NULL) {
		prev->next = new;
		new->next = tmp;
		return l;
	}

	new->next = l;
	return new;
}

GSList *
slist_insert_after_track(GSList *l, GSList *lk, gpointer data,
	gchar *file, gint line)
{
	GSList *new;

	if (lk == NULL)
		return slist_prepend_track(l, data, file, line);

	new = slist_alloc_track(file, line);
	new->data = data;

	new->next = lk->next;
	lk->next = new;

	return l;
}

GList *
list_alloc_track(gchar *file, gint line)
{
	return malloc_record(g_list_alloc(), GLIST_LINK_SIZE, file, line);
}

GList *
list_append_track(GList *l, gpointer data, gchar *file, gint line)
{
	GList *new;

	new = list_alloc_track(file, line);
	new->data = data;

	if (l) {
		GList *last = g_list_last(l);
		last->next = new;
		new->prev = last;
		return l;
	} else
		return new;
}

GList *
list_prepend_track(GList *l, gpointer data, gchar *file, gint line)
{
	GList *new;

	new = list_alloc_track(file, line);
	new->data = data;

	if (l) {
		if (l->prev) {
			l->prev->next = new;
			new->prev = l->prev;
		}
		l->prev = new;
		new->next = l;
	}

	return new;
}

GList *
list_copy_track(GList *list, gchar *file, gint line)
{
	GList *new;
	GList *l;

	new = g_list_copy(list);

	for (l = new; l; l = g_list_next(l))
		malloc_record(l, GLIST_LINK_SIZE, file, line);

	return new;
}

void
list_free_track(GList *l, gchar *file, gint line)
{
	GList *lk;

	for (lk = l; lk; lk = g_list_next(lk))
		free_record(lk, file, line);

	g_list_free(l);
}

void
list_free1_track(GList *l, gchar *file, gint line)
{
	if (l == NULL)
		return;

	free_record(l, file, line);
	g_list_free_1(l);
}

GList *
list_remove_track(GList *l, gpointer data, gchar *file, gint line)
{
	GList *lk;

	lk = g_list_find(l, data);
	if (lk == NULL)
		return l;

	return list_delete_link_track(l, lk, file, line);
}

GList *
list_insert_track(GList *l, gpointer data, gint pos, gchar *file, gint line)
{
	GList *lk;

	if (pos < 0)
		return list_append_track(l, data, file, line);
	else if (pos == 0)
		return list_prepend_track(l, data, file, line);

	lk = g_list_nth(l, pos - 1);
	if (lk == NULL)
		return list_append_track(l, data, file, line);
	else
		return list_insert_after_track(l, lk, data, file, line);
}

GList *
list_insert_sorted_track(GList *l, gpointer d, GCompareFunc c,
	gchar *file, gint line)
{
	gint cmp;
	GList *tmp = l;
	GList *new;

	if (l == NULL)
		return list_prepend_track(l, d, file, line);

	cmp = (*c)(d, tmp->data);
	while (tmp->next != NULL && cmp > 0) {
		tmp = tmp->next;
		cmp = (*c)(d, tmp->data);
	}

	new = list_alloc_track(file, line);
	new->data = d;

	if (tmp->next == NULL && cmp > 0) {
		tmp->next = new;
		new->prev = tmp;
		return l;
	}

	/* Insert `new' before `tmp' */

	if (tmp->prev != NULL) {
		tmp->prev->next = new;
		new->prev = tmp->prev;
	}

	new->next = tmp;
	tmp->prev = new;

	return (tmp == l) ? new : l;
}

GList *
list_insert_after_track(GList *l, GList *lk, gpointer data,
	gchar *file, gint line)
{
	GList *new;

	if (lk == NULL)
		return list_prepend_track(l, data, file, line);

	new = list_alloc_track(file, line);
	new->data = data;

	new->prev = lk;
	new->next = lk->next;

	if (lk->next)
		lk->next->prev = new;

	lk->next = new;

	return l;
}

GList *
list_delete_link_track(GList *l, GList *lk, gchar *file, gint line)
{
	GList *new;

	new = g_list_remove_link(l, lk);
	list_free1_track(lk, file, line);

	return new;
}

/***
 *** String trackers, to unveil hidden string buffer allocation.
 ***/

#define GSTRING_OBJ_SIZE	8		/* Random size */

/**
 * string_str_track
 *
 * Track changes to the internal string object.
 * @return GString object.
 */
static GString *
string_str_track(GString *s, gchar *old, gchar *file, gint line)
{
	if (s->str != old) {
		free_record(old, file, line);
		string_record(s->str, file, line);
	} else
		realloc_record(s->str, s->str, s->len + 1, file, line);

	return s;
}

GString *
string_new_track(const gchar *p, gchar *file, gint line)
{
	GString *result = g_string_new(p);

	malloc_record(result, GSTRING_OBJ_SIZE, file, line);
	string_record(result->str, file, line);

	return result;
}

GString *
string_sized_new_track(guint size, gchar *file, gint line)
{
	GString *result = g_string_sized_new(size);

	malloc_record(result, GSTRING_OBJ_SIZE, file, line);
	string_record(result->str, file, line);

	return result;
}

GString *
string_append_track(GString *s, const gchar *p, gchar *file, gint line)
{
	gchar *old = s->str;

	s = g_string_append(s, p);
	return string_str_track(s, old, file, line);
}

GString *
string_append_c_track(GString *s, gchar c, gchar *file, gint line)
{
	gchar *old = s->str;

	s = g_string_append_c(s, c);
	return string_str_track(s, old, file, line);
}

GString *
string_append_len_track(GString *s, const gchar *val, gssize len,
	gchar *file, gint line)
{
	gchar *old = s->str;

	s = g_string_append_len(s, val, len);
	return string_str_track(s, old, file, line);
}

GString *
string_assign_track(GString *s, const gchar *p, gchar *file, gint line)
{
	gchar *old = s->str;

	s = g_string_assign(s, p);
	return string_str_track(s, old, file, line);
}

void
string_free_track(GString *s, gint freestr, gchar *file, gint line)
{
	free_record(s, file, line);
	if (freestr)
		free_record(s->str, file, line);

	g_string_free(s, freestr);
}

GString *
string_prepend_track(GString *s, const gchar *p, gchar *file, gint line)
{
	gchar *old = s->str;

	s = g_string_prepend(s, p);
	return string_str_track(s, old, file, line);
}

GString *
string_prepend_c_track(GString *s, gchar c, gchar *file, gint line)
{
	gchar *old = s->str;

	s = g_string_prepend_c(s, c);
	return string_str_track(s, old, file, line);
}

GString *
string_insert_track(GString *s, gint pos, const gchar *p,
	gchar *file, gint line)
{
	gchar *old = s->str;

	s = g_string_insert(s, pos, p);
	return string_str_track(s, old, file, line);
}

GString *
string_insert_c_track(GString *s, gint pos, gchar c, gchar *file, gint line)
{
	gchar *old = s->str;

	s = g_string_insert_c(s, pos, c);
	return string_str_track(s, old, file, line);
}

GString *
string_sprintf_track(GString *s, gchar *file, gint line, const gchar *fmt, ...)
{
	va_list args;
	gchar *o;
	gchar *old = s->str;

	va_start(args, fmt);
	o = g_strdup_vprintf(fmt, args);
	va_end(args);

	g_string_assign(s, o);
	g_free(o);
	return string_str_track(s, old, file, line);
}

GString *
string_sprintfa_track(GString *s, gchar *file, gint line, const gchar *fmt, ...)
{
	va_list args;
	gchar *o;
	gchar *old = s->str;

	va_start(args, fmt);
	o = g_strdup_vprintf(fmt, args);
	va_end(args);

	g_string_append(s, o);
	g_free(o);
	return string_str_track(s, old, file, line);
}

#endif /* TRACK_MALLOC */

/***
 *** This section contains general-purpose leak summarizing routines that
 *** can be used by both malloc() and zalloc().
 ***/

#if defined(TRACK_MALLOC) || defined(TRACK_ZALLOC)

struct leak_record {		/* Informations about leak at some place */
	guint32 size;			/* Total size allocated there */
	guint32 count;			/* Amount of allocations */
};

struct leak_set {
	GHashTable *places;		/* Maps "file:4" -> leak_record */
};

/**
 * Initialize the leak accumulator by "file:line"
 */
gpointer leak_init(void)
{
	struct leak_set *ls;

	ls = malloc(sizeof *ls);
	ls->places = g_hash_table_new(g_str_hash, g_str_equal);

	return ls;
}

/**
 * Get rid of the key/value tupple in the leak table.
 */
static gboolean
leak_free_kv(gpointer key, gpointer value, gpointer unused_user)
{
	(void) unused_user;
	free(key);
	free(value);
	return TRUE;
}

/**
 * Dispose of the leaks accumulated.
 */
void
leak_close(gpointer o)
{
	struct leak_set *ls = (struct leak_set *) o;

	g_hash_table_foreach_remove(ls->places, leak_free_kv, NULL);
	g_hash_table_destroy(ls->places);

	free(ls);
}

/**
 * Record a new leak of `size' bytes allocated at `file', line `line'.
 */
void
leak_add(gpointer o, guint32 size, gchar *file, gint line)
{
	struct leak_set *ls = o;
	gchar key[1024];
	struct leak_record *lr;
	gboolean found;
	gpointer k;
	gpointer v;

	g_assert(file);
	g_assert(line >= 0);

	concat_strings(key, sizeof key,
		file, ":", uint64_to_string(line), (void *) 0);
	found = g_hash_table_lookup_extended(ls->places, key, &k, &v);

	if (found) {
		lr = (struct leak_record *) v;
		lr->size += size;
		lr->count++;
	} else {
		lr = malloc(sizeof(*lr));
		lr->size = size;
		lr->count = 1;
		g_hash_table_insert(ls->places, g_strdup(key), lr);
	}
}

struct leak {			/* A memory leak, for sorting purposes */
	gchar *place;
	struct leak_record *lr;
};

/**
 * leak_size_cmp		-- qsort() callback
 *
 * Compare two pointers to "struct leak" based on their size value,
 * in reverse order.
 */
static gint
leak_size_cmp(const void *p1, const void *p2)
{
	guint32 i1 = ((struct leak *) p1)->lr->size;
	guint32 i2 = ((struct leak *) p2)->lr->size;

	return
		i1 == i2 ?  0 :
		i1 < i2  ? +1 : -1;		/* Reverse order: largest first */
}

struct filler {			/* Used by hash table iterator to fill leak array */
	struct leak *leaks;
	gint count;			/* Size of `leaks' array */
	gint idx;			/* Next index to be filled */
};

/**
 * fill_array			-- hash table iterator
 *
 * Append current hash table entry at the end of the "leaks" array.
 */
static void
fill_array(gpointer key, gpointer value, gpointer user)
{
	struct filler *filler = user;
	struct leak *l;
	struct leak_record *lr = value;

	g_assert(filler->idx < filler->count);

	l = &filler->leaks[filler->idx++];
	l->place = (gchar *) key;
	l->lr = lr;
}

/**
 * Dump the links sorted by decreasing leak size.
 */
void
leak_dump(gpointer o)
{
	struct leak_set *ls = (struct leak_set *) o;
	gint count;
	struct filler filler;
	gint i;

	count = g_hash_table_size(ls->places);

	if (count == 0)
		return;

	filler.leaks = malloc(sizeof(struct leak) * count);
	filler.count = count;
	filler.idx = 0;

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
	g_warning("leaks found: %d", count);

	for (i = 0; i < count; i++) {
		struct leak *l = &filler.leaks[i];
		g_warning("%u bytes (%u block%s) from \"%s\"", l->lr->size,
			l->lr->count, l->lr->count == 1 ? "" : "s", l->place);
	}

	free(filler.leaks);
}

#endif /* TRACK_MALLOC || TRACK_ZALLOC */

/***
 *** This section contains general-purpose allocation summarizing routines that
 *** are used when MALLOC_STATS is on.
 ***
 *** This is used to spot the places where allocation takes place, sorted
 *** by decreasing allocation size.
 ***/

#ifdef MALLOC_STATS

struct afiller {		/* Used by hash table iterator to fill alloc array */
	struct stats **stats;
	gint count;			/* Size of `stats' array */
	gint idx;			/* Next index to be filled */
};

/**
 * Compare two pointers to "struct stat" based on their allocation value,
 * in reverse order. -- qsort() callback
 */
static gint
stats_allocated_cmp(const void *p1, const void *p2)
{
	guint32 i1 = (*(struct stats **) p1)->allocated;
	guint32 i2 = (*(struct stats **) p2)->allocated;

	return
		i1 == i2 ?  0 :
		i1 < i2  ? +1 : -1;		/* Reverse order: largest first */
}

/**
 * Compare two pointers to "struct stat" based on their total allocation value,
 * in reverse order. -- qsort() callback
 */
static gint
stats_total_allocated_cmp(const void *p1, const void *p2)
{
	guint32 i1 = (*(struct stats **) p1)->total_allocated;
	guint32 i2 = (*(struct stats **) p2)->total_allocated;

	return
		i1 == i2 ?  0 :
		i1 < i2  ? +1 : -1;		/* Reverse order: largest first */
}

/**
 * Compare two pointers to "struct stat" based on their residual value,
 * in reverse order. -- qsort() callback
 */
static gint
stats_residual_cmp(const void *p1, const void *p2)
{
	struct stats *s1 = *(struct stats **) p1;
	struct stats *s2 = *(struct stats **) p2;
	gint32 i1 = s1->allocated + s1->reallocated - s1->freed;
	gint32 i2 = s2->allocated + s2->reallocated - s2->freed;

	return
		i1 == i2 ?  stats_allocated_cmp(p1, p2) :
		i1 < i2  ? +1 : -1;		/* Reverse order: largest first */
}

/**
 * Compare two pointers to "struct stat" based on their total residual value,
 * in reverse order. -- qsort() callback
 */
static gint
stats_total_residual_cmp(const void *p1, const void *p2)
{
	struct stats *s1 = *(struct stats **) p1;
	struct stats *s2 = *(struct stats **) p2;
	gint32 i1 = s1->total_allocated + s1->total_reallocated - s1->total_freed;
	gint32 i2 = s2->total_allocated + s2->total_reallocated - s2->total_freed;

	return
		i1 == i2 ?  stats_total_allocated_cmp(p1, p2) :
		i1 < i2  ? +1 : -1;		/* Reverse order: largest first */
}

/**
 * Append current hash table entry at the end of the "stats" array
 * in the supplied filler structure.  -- hash table iterator
 */
static void
stats_fill_array(gpointer unused_key, gpointer value, gpointer user)
{
	struct afiller *filler = (struct afiller *) user;
	struct stats *st = (struct stats *) value;
	struct stats **e;

	(void) unused_key;

	g_assert(filler->idx < filler->count);

	e = &filler->stats[filler->idx++];
	*e = st;
}

/**
 * Dump the stats held in the specified array.
 */
static void
stats_array_dump(FILE *f, struct afiller *filler)
{
	gint i;

	fprintf(f, "%7s %7s %8s %8s %4s [%7s %7s %8s %8s %6s] #a #f #r %s:\n",
		"alloc", "freed", "realloc", "remains", "live",
		"alloc", "freed", "realloc", "remains", "live", "from");

	for (i = 0; i < filler->count; i++) {
		struct stats *st = filler->stats[i];
		gint alloc_stacks;
		gint free_stacks;
		gint realloc_stacks;
		gint remains = st->allocated + st->reallocated - st->freed;
		gint total_remains =
			st->total_allocated + st->total_reallocated - st->total_freed;
		gchar *c_allocated = strdup(compact_size(st->allocated, FALSE));
		gchar *c_freed = strdup(compact_size(st->freed, FALSE));
		gchar *c_reallocated = strdup(compact_size(ABS(st->reallocated), FALSE));
		gchar *c_remains = strdup(compact_size(ABS(remains), FALSE));
		gchar *c_tallocated = strdup(compact_size(st->total_allocated, FALSE));
		gchar *c_tfreed = strdup(compact_size(st->total_freed, FALSE));
		gchar *c_treallocated =
			strdup(compact_size(ABS(st->total_reallocated), FALSE));
		gchar *c_tremains = strdup(compact_size(ABS(total_remains), FALSE));

#ifdef MALLOC_FRAMES
		alloc_stacks = st->alloc_frames == NULL ?
			0 : g_hash_table_size(st->alloc_frames);
		free_stacks = st->free_frames == NULL ?
			0 : g_hash_table_size(st->free_frames);
		realloc_stacks = st->realloc_frames == NULL ?
			0 : g_hash_table_size(st->realloc_frames);
#else
		alloc_stacks = free_stacks = realloc_stacks = 0;
#endif

		fprintf(f, "%7s %7s %c%7s %c%7s %4d [%7s %7s %c%7s %c%7s %6d] "
			"%2d %2d %2d \"%s:%d\"\n",
			c_allocated, c_freed,
			st->reallocated < 0 ? '-' : ' ', c_reallocated,
			remains < 0 ? '-' : ' ', c_remains,
			MIN(st->blocks, 9999),
			c_tallocated, c_tfreed,
			st->total_reallocated < 0 ? '-' : ' ', c_treallocated,
			total_remains < 0 ? '-' : ' ', c_tremains,
			MIN(st->total_blocks, 999999),
			MIN(alloc_stacks, 99),
			MIN(free_stacks, 99),
			MIN(realloc_stacks, 99),
			st->file, st->line);

		free(c_allocated);
		free(c_freed);
		free(c_reallocated);
		free(c_remains);
		free(c_tallocated);
		free(c_tfreed);
		free(c_treallocated);
		free(c_tremains);
	}
}

/**
 * Dump the allocation sorted by decreasing amount size on specified file.
 * When `total' is TRUE, sorting is made on the total stats instead of
 * the incremental ones.
 */
void
alloc_dump(FILE *f, gboolean total)
{
	gint count;
	struct afiller filler;
	time_t now;

	count = g_hash_table_size(stats);

	if (count == 0)
		return;

	now = tm_time();
	fprintf(f, "--- distinct allocation spots found: %d at %s\n",
		count, short_time(now - init_time));

	filler.stats = malloc(sizeof(struct stats *) * count);
	filler.count = count;
	filler.idx = 0;

	/*
	 * Linearize hash table into an array before sorting it by
	 * decreasing allocation size.
	 */

	g_hash_table_foreach(stats, stats_fill_array, &filler);
	qsort(filler.stats, count, sizeof(struct stats *),
		total ? stats_total_allocated_cmp : stats_allocated_cmp);

	/*
	 * Dump the allocation based on allocation sizes.
	 */

	fprintf(f, "--- summary by decreasing %s allocation size %s %s:\n",
		total ? "total" : "incremental", total ? "at" : "after",
		short_time(now - (total ? init_time : reset_time)));
	stats_array_dump(f, &filler);

	/*
	 * Now linearize hash table by decreasing residual allocation size.
	 */

	filler.idx = 0;

	g_hash_table_foreach(stats, stats_fill_array, &filler);
	qsort(filler.stats, count, sizeof(struct stats *),
		total ? stats_total_residual_cmp : stats_residual_cmp);

	fprintf(f, "--- summary by decreasing %s residual memory size %s %s:\n",
		total ? "total" : "incremental", total ? "at" : "after",
		short_time(now - (total ? init_time : reset_time)));
	stats_array_dump(f, &filler);

	fprintf(f, "--- end summary at %s\n", short_time(now - init_time));

	free(filler.stats);
}

/**
 * Reset incremental allocation and free counters. -- hash table iterator
 */
static void
stats_reset(gpointer uu_key, gpointer value, gpointer uu_user)
{
	struct stats *st = (struct stats *) value;

	(void) uu_key;
	(void) uu_user;

	st->blocks = st->allocated = st->freed = st->reallocated = 0;
}

/**
 * Atomically dump the allocation stats and reset the incremental allocation
 * statistics.
 */
void
alloc_reset(FILE *f, gboolean total)
{
	time_t now = tm_time();

	alloc_dump(f, total);
	g_hash_table_foreach(stats, stats_reset, NULL);

	fprintf(f, "--- incremental allocation stats reset after %s.\n",
		short_time(now - reset_time));

	reset_time = now;
}

#endif /* MALLOC_STATS */

/* vi: set ts=4 sw=4 cindent:  */
