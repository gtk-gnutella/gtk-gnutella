/*
 * $Id$
 *
 * Copyright (c) 2006 Christian Biere
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
 * Memory fragmentation.
 *
 * @author Christian Biere
 * @date 2006
 */

#include "lib/fragcheck.h"

#ifdef FRAGCHECK

#include "lib/glib-missing.h"
#include "lib/bit_array.h"
#include "lib/misc.h"

/* Not g_assert() because it seems to call g_malloc() sometimes. */
#include <assert.h>

#include "lib/override.h"		/* Must be the last header included */

RCSID("$Id$")

#if HAVE_GCC(3, 0)
#define FRAGCHECK_TRACK_CALLERS
#endif	/* GCC >= 3.0 */

#if 0
#define FRAGCHECK_VERBOSE
#endif

union alloc {
	void *p;
	long l;
	int i;
	short s;
	char c;
	double d;
	float f;
};

#ifdef FRAGCHECK_TRACK_CALLERS
enum fragcheck_ret {
	FC_RET_0,
	FC_RET_1,
	FC_RET_2,
	FC_RET_3,

	NUM_FC_RET
};
#endif

struct fragcheck_meta {
	const void *base;
	size_t size;
#ifdef FRAGCHECK_TRACK_CALLERS
	size_t ret[NUM_FC_RET];
#endif	/* FRAGCHECK_TRACK_CALLERS */
};

/* Configured for a maximum address space of 512 MiB */
#define BIT_COUNT (512 * 1024 * 1024 / sizeof (union alloc))
#define MAX_ALLOC_NUM (1024 * 1024)

static struct {
	/* The index uses two bits per slot. If the first is set,
	 * the item is or was in use, if the second bit is set the item
	 * has been deleted, otherwise it is in use.
	 *
	 * 00: free
	 * 01: deleted
	 * 10: in-use
	 * 11: re-used
	 */
	struct fragcheck_meta meta_tab[MAX_ALLOC_NUM];
	bit_array_t meta_index[BIT_ARRAY_SIZE(MAX_ALLOC_NUM * 2)];

	size_t alloc_base;
	bit_array_t allocated[BIT_ARRAY_SIZE(BIT_COUNT)];
	bit_array_t touched[BIT_ARRAY_SIZE(BIT_COUNT)];
} vars;

static inline guint32
fragcheck_meta_hash(const void *p)
{
	size_t x = (size_t) p;

	x ^= x >> 31;
	return x % MAX_ALLOC_NUM;
}

static struct fragcheck_meta *
fragcheck_meta_new(const void *p)
{
	size_t i, slot = fragcheck_meta_hash(p);

	for (i = 0; i < MAX_ALLOC_NUM; i++) {
		size_t x = slot * 2;

		if (!bit_array_get(vars.meta_index, x)) {
			bit_array_set(vars.meta_index, x);
			return &vars.meta_tab[slot];
		}
		slot += 37;
		slot %= MAX_ALLOC_NUM;
	}
	return NULL;
}

static struct fragcheck_meta *
fragcheck_meta_lookup(const void *p)
{
	guint32 i, slot = fragcheck_meta_hash(p);

	for (i = 0; i < MAX_ALLOC_NUM; i++) {
		size_t x = slot * 2;

		if (bit_array_get(vars.meta_index, x)) {
			if (p == vars.meta_tab[slot].base) {
				return &vars.meta_tab[slot];
			}
		} else if (!bit_array_get(vars.meta_index, x + 1)) {
			break;
		}
		slot += 37;
		slot %= MAX_ALLOC_NUM;
	}
	return NULL;
}

static void
fragcheck_meta_delete(struct fragcheck_meta *meta)
{
	assert(meta);
	{
		size_t x, slot;
		
		slot = meta - &vars.meta_tab[0];
		x = slot * 2;
		bit_array_clear(vars.meta_index, x);		/* free slot */
		bit_array_set(vars.meta_index, x + 1);	/* deleted */
		meta->base = NULL;
		meta->size = 0;
	}
}

static gpointer
my_malloc(gsize n)
{
	struct fragcheck_meta *meta;
	void *p;

	n = round_size(sizeof (union alloc), n);
	p = malloc(n);

#ifdef FRAGCHECK_VERBOSE 
	printf("%s(%lu)=0x%08lx\n", __func__, (unsigned long) n, (unsigned long) p);
#endif	/* FRAGCHECK_VERBOSE */

	assert(p);
	assert(0 == (size_t) p % sizeof (union alloc));
	assert((size_t) p >= (size_t) vars.alloc_base);
	assert(!fragcheck_meta_lookup(p));

	if (!vars.alloc_base) {
		/* The divisor is a good guess and depends on the malloc
		 * implementation. The first call doesn't necessarily
		 * return the lowest available address. */
		vars.alloc_base = (size_t) p / 2;
	} else {
		assert(vars.alloc_base <= (size_t) p);
	}

	meta = fragcheck_meta_new(p);
	assert(meta);
	meta->base = p;
	meta->size = n;

#ifdef FRAGCHECK_TRACK_CALLERS
	{
		enum fragcheck_ret i;
		for (i = FC_RET_0; i < NUM_FC_RET; i++) {
			switch (i) {
#define CASE(x) \
	case x: meta->ret[x] = (size_t) __builtin_return_address(x + 1); break;
			CASE(FC_RET_0)
			CASE(FC_RET_1)
			CASE(FC_RET_2)
			CASE(FC_RET_3)
			case NUM_FC_RET: assert(0);
#undef CASE
			}
		}
	}
#endif	/* FRAGCHECK_TRACK_CALLERS */
	
	{
		size_t from, to, i;

		from = ((size_t) p - vars.alloc_base) / sizeof (union alloc);
		to = from + (meta->size / sizeof (union alloc));

		assert(from < BIT_COUNT);
		assert(to < BIT_COUNT);
		assert(to > from);
		
		for (i = from; i < to; i++) {
			assert(!bit_array_get(vars.allocated, i));
			bit_array_set(vars.allocated, i);
			bit_array_set(vars.touched, i);
			assert(bit_array_get(vars.allocated, i));
			assert(bit_array_get(vars.touched, i));
		}
	}
	assert(fragcheck_meta_lookup(p));
	return p;
}

static void
my_free(gpointer p)
{
#ifdef FRAGCHECK_VERBOSE 
	printf("%s(%p)\n", __func__, p);
#endif	/* FRAGCHECK_VERBOSE */

	if (p) {
		struct fragcheck_meta *meta;

		meta = fragcheck_meta_lookup(p);
		assert(meta);
		assert(meta->size >= sizeof (union alloc));
		assert(0 == meta->size % sizeof (union alloc));
		assert(0 == (size_t) p % sizeof (union alloc));
		assert((size_t) p >= (size_t) vars.alloc_base);
		{
			size_t from, to, i;

			from = ((size_t) p - vars.alloc_base) / sizeof (union alloc);
			to = from + (meta->size / sizeof (union alloc));

			assert(from < BIT_COUNT);
			assert(to < BIT_COUNT);
			assert(to > from);

			for (i = from; i < to; i++) {
				assert(bit_array_get(vars.touched, i));
				assert(bit_array_get(vars.allocated, i));
				bit_array_clear(vars.allocated, i);
				assert(!bit_array_get(vars.allocated, i));
			}
		}
		memset(p, 0, meta->size);
		fragcheck_meta_delete(meta);
		assert(!fragcheck_meta_lookup(p));
		free(p);
	}
}

static gpointer
my_realloc(gpointer p, gsize n)
{
	static volatile gboolean lock;
	gpointer x;

	g_assert(!lock);
	lock = TRUE;

#ifdef FRAGCHECK_VERBOSE 
	printf("%s(%p, %lu)\n", __func__, p, (unsigned long) n);
#endif	/* FRAGCHECK_VERBOSE */

	assert(n > 0);
	x = my_malloc(n);
	if (p) {
		const struct fragcheck_meta *meta;

		meta = fragcheck_meta_lookup(p);
		assert(meta);
		assert(meta->size >= sizeof (union alloc));
		assert(0 == meta->size % sizeof (union alloc));
		assert(0 == (size_t) p % sizeof (union alloc));
		assert((size_t) p >= (size_t) vars.alloc_base);

		memcpy(x, p, MIN(meta->size, n));
		my_free(p);
	}
	lock = FALSE;
	return x;
}

void
alloc_dump(FILE *f, gboolean unused_flag)
{
	size_t i, base_i = 0;
	int cur = -1;

	(void) unused_flag;

	for (i = 0; /* NOTHING */; i++) {
		int v;

		if (i < BIT_COUNT) {
			if (bit_array_get(vars.touched, i)) {
				v = bit_array_get(vars.allocated, i) ? 'a' : 'f';
			} else {
				v = 'u';
			}
		} else {
			v = -2;
		}

		if (v != cur) {
			size_t n = i - base_i;
			if (n > 0) {
				size_t base = vars.alloc_base + base_i * sizeof (union alloc);
				size_t len = n * sizeof (union alloc);

				fprintf(f, "%c base: 0x%08lx length: %8.1lu",
					cur, (unsigned long) base, (unsigned long) len);
				fputs("\n", f);
			}
			if (i == BIT_COUNT) {
				fflush(f);
				break;
			}
			base_i = i;
			cur = v;
		}
	}
}

void
alloc_dump2(FILE *f, gboolean unused_flag)
{
	size_t i;

	(void) unused_flag;

	for (i = 0; i < MAX_ALLOC_NUM; i++) {
		const struct fragcheck_meta *meta;

		meta = &vars.meta_tab[i];
		if (meta->base) {
			fprintf(f, "base: 0x%08lx length: %8.1lu",
				(unsigned long) meta->base,
				(unsigned long) meta->size);

#ifdef FRAGCHECK_TRACK_CALLERS
			{
				unsigned j;
				
				fputs(" callers:", f);
				for (j = FC_RET_0; j < NUM_FC_RET; j++) {
					fprintf(f, " 0x%08lx", (unsigned long) meta->ret[j]);
				}
			}
#endif	/* FRAGCHECK_TRACK_CALLERS */

			fputs("\n", f);
		}
	}
}

void
fragcheck_init(void)
{
	static GMemVTable vtable;

	vtable.malloc = my_malloc;
	vtable.realloc = my_realloc;
	vtable.free = my_free;

	g_mem_set_vtable(&vtable);

	{
		extern const int end;

		/*
		 * The address of "end" points to end of the BSS and should
		 * be equivalent to the lowest heap address
		 */

		vars.alloc_base = round_size(sizeof (union alloc),
						(size_t) &end - sizeof (union alloc));
	}
}

#endif	/* FRAGCHECK */

/* vi: set ts=4 sw=4 cindent: */
