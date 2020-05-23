/*
 * Copyright (c) 2004, 2012 Raphael Manfredi
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
 * @ingroup lib
 * @file
 *
 * Leak summarizing routines.
 *
 * These general-purpose leak summarizing routines can be used by both
 * malloc() and zalloc() when tracking allocations, to be able to report
 * on leaks at exit time.
 *
 * Because the code here can be executed during final shutdown of the memory
 * allocators, we cannot use walloc() for the data structures and need to
 * rely on the VMM and xmalloc() layers only.  Hence the hash table is
 * create in "real" mode to prevent any usage of walloc().
 *
 * @author Raphael Manfredi
 * @date 2004, 2012
 */

#include "common.h"

#include "concat.h"
#include "leak.h"
#include "htable.h"
#include "log.h"
#include "stacktrace.h"		/* For struct stackatom, stack_hash(), stack_eq() */
#include "stringify.h"
#include "xmalloc.h"
#include "xsort.h"

#include "override.h"		/* Must be the last header included */

enum leak_set_magic { LEAK_SET_MAGIC = 0x15ba83bf };

struct leak_set {
	enum leak_set_magic magic;
	htable_t *places;		/* Maps "file:4" -> leak_record */
	htable_t *stacks;		/* Maps stackatom -> leak_record */
};

static inline void
leak_set_check(const struct leak_set * const ls)
{
	g_assert(ls != NULL);
	g_assert(LEAK_SET_MAGIC == ls->magic);
}

struct leak_record {		/* Informations about leak at some place */
	size_t size;			/* Total size allocated there */
	size_t count;			/* Amount of allocations */
};

/**
 * Initialize the leak accumulator by "file:line"
 */
leak_set_t *
leak_init(void)
{
	struct leak_set *ls;

	XMALLOC0(ls);
	ls->magic = LEAK_SET_MAGIC;
	ls->places = htable_create_real(HASH_KEY_STRING, 0);	/* No walloc() */
	ls->stacks = htable_create_any_real(stack_hash, NULL, stack_eq);

	return ls;
}

/**
 * Get rid of the key/value tupple in the leak table.
 */
static void
leak_free_kv(const void *key, void *value, void *unused)
{
	(void) unused;
	xfree(deconstify_pointer(key));
	xfree(value);
}

/**
 * Get rid of the value in the leak table.
 */
static void
leak_free_v(const void *key, void *value, void *unused)
{
	(void) key;
	(void) unused;
	xfree(value);
}

/**
 * Dispose of the leaks accumulated.
 */
static void
leak_close(leak_set_t *ls)
{
	leak_set_check(ls);

	htable_foreach(ls->places, leak_free_kv, NULL);
	htable_foreach(ls->stacks, leak_free_v, NULL);
	htable_free_null(&ls->places);
	htable_free_null(&ls->stacks);
	ls->magic = 0;
	xfree(ls);
}

/*
 * Free leak set and nullify its pointer.
 */
void
leak_close_null(leak_set_t **ls_ptr)
{
	leak_set_t *ls = *ls_ptr;

	if (ls != NULL) {
		leak_close(ls);
		*ls_ptr = NULL;
	}
}

/**
 * Record a new leak of `size' bytes allocated at `file', line `line'.
 */
void
leak_add(leak_set_t *ls, size_t size, const char *file, int line)
{
	char key[1024];
	struct leak_record *lr;
	bool found;
	void *v;

	leak_set_check(ls);
	g_assert(file);
	g_assert(line >= 0);

	concat_strings(ARYLEN(key), file, ":", uint64_to_string(line), NULL_PTR);
	found = htable_lookup_extended(ls->places, key, NULL, &v);

	if (found) {
		lr = v;
		lr->size += size;
		lr->count++;
	} else {
		XMALLOC(lr);
		lr->size = size;
		lr->count = 1;
		htable_insert(ls->places, xstrdup(key), lr);
	}
}

/**
 * Record a new leak of `size' bytes allocated from stack trace.
 */
void
leak_stack_add(leak_set_t *ls, size_t size, const struct stackatom *sa)
{
	struct leak_record *lr;
	bool found;
	void *v;

	leak_set_check(ls);

	found = htable_lookup_extended(ls->stacks, sa, NULL, &v);

	if (found) {
		lr = v;
		lr->size += size;
		lr->count++;
	} else {
		XMALLOC(lr);
		lr->size = size;
		lr->count = 1;
		htable_insert(ls->stacks, sa, lr);
	}
}

enum leak_keytype {
	LEAK_KEY_PLACE,
	LEAK_KEY_STACK
};

struct leak {			/* A memory leak, for sorting purposes */
	/*
	 * The union discriminant is implicit: it is derived from the hash table
	 * were the leak structure is held.
	 */
	union {
		const char *place;
		const struct stackatom *sa;
	} u;
	struct leak_record *lr;
};

/**
 * leak_size_cmp		-- qsort() callback
 *
 * Compare two pointers to "struct leak" based on their size value,
 * in reverse order.
 */
static int
leak_size_cmp(const void *p1, const void *p2)
{
	const struct leak *leak1 = p1, *leak2 = p2;

	/* Reverse order: largest first */
	return CMP(leak2->lr->size, leak1->lr->size);
}

struct filler {			/* Used by hash table iterator to fill leak array */
	struct leak *leaks;
	int count;				/* Size of `leaks' array */
	int idx;				/* Next index to be filled */
	enum leak_keytype kt;	/* The union discriminant */
};

/**
 * fill_array			-- hash table iterator
 *
 * Append current hash table entry at the end of the "leaks" array.
 */
static void
fill_array(const void *key, void *value, void *user)
{
	struct filler *filler = user;
	struct leak *l;
	struct leak_record *lr = value;

	g_assert(filler->idx < filler->count);

	l = &filler->leaks[filler->idx++];
	switch (filler->kt) {
	case LEAK_KEY_PLACE:
		l->u.place = key;
		break;
	case LEAK_KEY_STACK:
		l->u.sa = key;
		break;
	}
	l->lr = lr;
}

/**
 * Dump the links sorted by decreasing leak size.
 */
void G_COLD
leak_dump(const leak_set_t *ls)
{
	int count;
	struct filler filler;
	int i;

	leak_set_check(ls);

	count = htable_count(ls->stacks);

	if (count == 0)
		goto leaks_by_place;

	/*
	 * Linearize hash table into an array before sorting it by
	 * decreasing leak size.
	 */

	XMALLOC_ARRAY(filler.leaks, count);
	filler.count = count;
	filler.idx = 0;
	filler.kt = LEAK_KEY_STACK;

	htable_foreach(ls->stacks, fill_array, &filler);
	xqsort(filler.leaks, count, sizeof(struct leak), leak_size_cmp);

	/*
	 * Dump the leaks by allocation place.
	 */

	s_warning("leak summary by stackframe and total decreasing size:");
	s_warning("distinct calling stacks found: %d", count);

	for (i = 0; i < count; i++) {
		struct leak *l = &filler.leaks[i];
		size_t avg = l->lr->size / (0 == l->lr->count ? 1 : l->lr->count);
		s_warning("%zu bytes (%zu block%s, average %zu byte%s) from:",
			l->lr->size, l->lr->count, plural(l->lr->count), avg, plural(avg));
		stacktrace_atom_decorate(stderr, l->u.sa,
			STACKTRACE_F_ORIGIN | STACKTRACE_F_SOURCE);
	}

	xfree(filler.leaks);

leaks_by_place:

	count = htable_count(ls->places);

	if (count == 0)
		return;

	/*
	 * Linearize hash table into an array before sorting it by
	 * decreasing leak size.
	 */

	XMALLOC_ARRAY(filler.leaks, count);
	filler.count = count;
	filler.idx = 0;
	filler.kt = LEAK_KEY_PLACE;

	htable_foreach(ls->places, fill_array, &filler);
	xqsort(filler.leaks, count, sizeof(struct leak), leak_size_cmp);

	/*
	 * Dump the leaks by allocation place.
	 */

	s_warning("leak summary by origin and total decreasing size:");
	s_warning("distinct allocation points found: %d", count);

	for (i = 0; i < count; i++) {
		struct leak *l = &filler.leaks[i];
		size_t avg = l->lr->size / (0 == l->lr->count ? 1 : l->lr->count);
		s_warning("%zu bytes (%zu block%s, average %zu byte%s) from \"%s\"",
			l->lr->size, l->lr->count, plural(l->lr->count),
			avg, plural(avg), l->u.place);
	}

	xfree(filler.leaks);
}

/* vi: set ts=4 sw=4 cindent: */
