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

#include "lib/bit_array.h"
#include "lib/misc.h"

/* Not g_assert() because it seems to call g_malloc() sometimes. */
#include <assert.h>

#include "lib/override.h"		/* Must be the last header included */

RCSID("$Id$")

#if GLIB_CHECK_VERSION(2,0,0)

union alloc {
	size_t size;
	void *p;
	long l;
	int i;
	short s;
	char c;
	double d;
	float f;
};

/* Configured for a maximum address space of 512 MiB */
#define BIT_COUNT (512 * 1024 * 1024 / sizeof (union alloc))

static bit_array_t allocated[BIT_ARRAY_SIZE(BIT_COUNT)];
static size_t alloc_base;

static gpointer
my_malloc(gsize n)
{
	union alloc *ap;

#if 0
	printf("%s(%lu)\n", __func__, (unsigned long) n);
#endif
	n = round_size(sizeof *ap, n);
	ap = malloc(n + sizeof *ap);
	assert(0 == (size_t) ap % sizeof *ap);
	ap->size = n;
	{
		size_t from, to;

		if (!alloc_base) {
			/* The divisor is a good guess and depends on the malloc
			 * implementation. The first call doesn't necessarily
			 * return the lowest available address. */
			alloc_base = (size_t) ap / 2;
		} else {
			assert(alloc_base <= (size_t) ap);
		}
		from = ((size_t) ap - alloc_base) / sizeof *ap;
		to = from + (n / sizeof *ap);
		assert(from < BIT_COUNT);
		assert(to < BIT_COUNT);
		assert(!bit_array_get(allocated, from));
		assert(!bit_array_get(allocated, to));
		bit_array_set_range(allocated, from, to);
	}
	return &ap[1];
}

static void
my_free(gpointer p)
{
#if 0
	printf("%s(%p)\n", __func__, p);
#endif
	if (p) {
		union alloc *ap;

		ap = p;
		ap--;
		assert(ap->size >= sizeof *ap);
		assert(0 == ap->size % sizeof *ap);
		assert(0 == (size_t) ap % sizeof *ap);
		assert((size_t) ap >= (size_t) alloc_base);
		{
			size_t from, to;

			from = ((size_t) ap - alloc_base) / sizeof *ap;
			to = from + (ap->size / sizeof *ap);
			assert(from < BIT_COUNT);
			assert(to < BIT_COUNT);
			assert(bit_array_get(allocated, from));
			assert(bit_array_get(allocated, to));
			bit_array_clear_range(allocated, from, to);
		}
		ap->size = 0;
		free(ap);
	}
}

static gpointer
my_realloc(gpointer p, gsize n)
{
	union alloc *ap;
	gpointer x;

#if 0
	printf("%s(%p, %lu)\n", __func__, p, (unsigned long) n);
#endif

	assert(n > 0);
	x = my_malloc(n);
	if (p) {
		ap = p;
		ap--;
		assert(ap->size >= sizeof *ap);
		assert(0 == ap->size % sizeof *ap);
		assert(0 == (size_t) ap % sizeof *ap);
		memcpy(x, p, MIN(ap->size, n));
		my_free(p);
	}
	return x;
}

static gpointer
my_calloc(gsize n, gsize m)
{
	size_t size;
	char *p;

#if 0
	printf("%s(%lu, %lu)\n", __func__, (unsigned long) n, (unsigned long) m);
#endif
	assert(n > 0);
	assert(m > 0);
	assert(n < ((size_t) -1) / m);

	size = n * m;
	p = my_malloc(size);
	memset(p, 0, size);
	return p;
}

static gpointer
my_try_malloc(gsize n)
{
#if 0
	printf("%s(%lu)\n", __func__, (unsigned long) n);
#endif
	return my_malloc(n);
}

static gpointer
my_try_realloc(gpointer p, gsize n)
{
#if 0
	printf("%s(%p, %lu)\n", __func__, p, (unsigned long) n);
#endif
	return my_realloc(p, n);
}

void
alloc_reset(FILE *unused_f, gboolean unused_flag)
{
	(void) unused_f;
	(void) unused_flag;
}

void
alloc_dump(FILE *f, gboolean unused_flag)
{
	size_t i, base_i = 0;
	int cur = -1;

	(void) unused_flag;

	for (i = 0; /* NOTHING */; i++) {
		gboolean v;
	
		v = i < BIT_COUNT ? bit_array_get(allocated, i) : !cur;
		if ((int) v != cur) {
			size_t n = i - base_i;
			if (n > 0) {
				size_t base = alloc_base + base_i * sizeof (union alloc);
				size_t len = n * sizeof (union alloc);
				fprintf(f, "%c base: 0x%08lx length: %lu\n",
					cur ? 'a' : 'f', (unsigned long) base, (unsigned long) len);
			}
			if (i == BIT_COUNT)
				break;
			base_i = i;
			cur = v;
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
	vtable.calloc = my_calloc;
	vtable.try_malloc = my_try_malloc;
	vtable.try_realloc = my_try_realloc;

	g_mem_set_vtable(&vtable);
}

#endif	/* GLib >= 2.0 */
#endif	/* FRAGCHECK */

/* vi: set ts=4 sw=4 cindent: */
