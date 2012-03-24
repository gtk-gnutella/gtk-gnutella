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
 *      59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
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

#include "leak.h"
#include "concat.h"
#include "htable.h"
#include "stringify.h"
#include "xmalloc.h"
#include "xsort.h"

#include "override.h"		/* Must be the last header included */

enum leak_set_magic { LEAK_SET_MAGIC = 0x15ba83bf };

struct leak_set {
	enum leak_set_magic magic;
	htable_t *places;		/* Maps "file:4" -> leak_record */
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

	XPMALLOC0(ls);
	ls->magic = LEAK_SET_MAGIC;
	ls->places = htable_create_real(HASH_KEY_STRING, 0);	/* No walloc() */

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
 * Dispose of the leaks accumulated.
 */
static void
leak_close(leak_set_t *ls)
{
	leak_set_check(ls);

	htable_foreach(ls->places, leak_free_kv, NULL);
	htable_free_null(&ls->places);
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

	concat_strings(key, sizeof key,
		file, ":", uint64_to_string(line), (void *) 0);
	found = htable_lookup_extended(ls->places, key, NULL, &v);

	if (found) {
		lr = v;
		lr->size += size;
		lr->count++;
	} else {
		XPMALLOC(lr);
		lr->size = size;
		lr->count = 1;
		htable_insert(ls->places, xstrdup(key), lr);
	}
}

struct leak {			/* A memory leak, for sorting purposes */
	char *place;
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
	int count;			/* Size of `leaks' array */
	int idx;			/* Next index to be filled */
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
	l->place = (char *) key;
	l->lr = lr;
}

/**
 * Dump the links sorted by decreasing leak size.
 */
G_GNUC_COLD void
leak_dump(const leak_set_t *ls)
{
	int count;
	struct filler filler;
	int i;

	leak_set_check(ls);

	count = htable_count(ls->places);

	if (count == 0)
		return;

	filler.leaks = xpmalloc(sizeof(struct leak) * count);
	filler.count = count;
	filler.idx = 0;

	/*
	 * Linearize hash table into an array before sorting it by
	 * decreasing leak size.
	 */

	htable_foreach(ls->places, fill_array, &filler);
	xqsort(filler.leaks, count, sizeof(struct leak), leak_size_cmp);

	/*
	 * Dump the leaks.
	 */

	g_warning("leak summary by total decreasing size:");
	g_warning("leaks found: %d", count);

	for (i = 0; i < count; i++) {
		struct leak *l = &filler.leaks[i];
		g_warning("%zu bytes (%zu block%s) from \"%s\"",
			l->lr->size, l->lr->count, l->lr->count == 1 ? "" : "s", l->place);
	}

	xfree(filler.leaks);
}

/* vi: set ts=4 sw=4 cindent: */
