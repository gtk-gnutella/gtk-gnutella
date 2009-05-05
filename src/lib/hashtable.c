/*
 * Copyright (c) 2009 Raphael Manfredi <Raphael_Manfredi@pobox.com>
 * All rights reserved.
 *
 * Copyright (c) 2006 Christian Biere <christianbiere@gmx.de>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the authors nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/**
 * @ingroup lib
 * @file
 *
 * A simple hashtable implementation.
 *
 * @author Raphael Manfredi
 * @date 2009
 * @author Christian Biere
 * @date 2006
 */

#include "common.h"

RCSID("$Id$")

#include "lib/hashtable.h"
#include "lib/vmm.h"

#include "lib/override.h"		/* Must be the last header included */

#define HASH_ITEMS_PER_BIN	4
#define HASH_ITEMS_GROW		56

#if 0
#define HASH_TABLE_CHECKS
#endif

/*
 * More costsly run-time assertions are only enabled if HASH_TABLE_CHECKS
 * is defined.
 */
#ifdef HASH_TABLE_CHECKS
#define RUNTIME_CHECK(x)		RUNTIME_ASSERT(x)
#else
#define RUNTIME_CHECK(x)
#endif

typedef struct hash_item {
  const void *key;
  const void *value;
  struct hash_item *next;
} hash_item_t;

struct hash_table {
  size_t      num_items; /* Array length of "items" */
  size_t      num_bins; /* Number of bins */
  size_t      num_held; /* Number of items actually in the table */
  size_t      bin_fill; /* Number of bins in use */
  hash_table_hash_func hash;	/* Key hash functions, or NULL */
  hash_table_eq_func eq;		/* Key equality function, or NULL */
  hash_item_t **bins;   /* Array of bins of size ``num_bins'' */
  hash_item_t *free_list;   /* List of free hash items */
  hash_item_t *items;       /* Array of items */
};

#define hash_table_check(ht) \
G_STMT_START { \
  const hash_table_t *ht_ = (ht); \
 \
  RUNTIME_ASSERT(ht_ != NULL); \
  RUNTIME_ASSERT(ht_->num_bins > 0); \
} G_STMT_END

/**
 * NOTE: A naive direct use of the pointer has a much worse distribution e.g.,
 *       only a quarter of the bins are used.
 */
static inline size_t
hash_id_key(const void *key)
{
  size_t n = (size_t) key;
  return ((0x4F1BBCDCUL * (guint64) n) >> 32) ^ n;
}

static inline gboolean
hash_id_eq(const void *a, const void *b)
{
  return a == b;
}

static hash_item_t * 
hash_item_alloc(hash_table_t *ht, const void *key, const void *value)
{
  hash_item_t *item;

  item = ht->free_list;
  RUNTIME_ASSERT(item);
  ht->free_list = item->next;

  item->key = key;
  item->value = value;
  item->next = NULL;

  return item;
}

static void 
hash_item_free(hash_table_t *ht, hash_item_t *item)
{
  RUNTIME_ASSERT(ht != NULL);
  RUNTIME_ASSERT(item != NULL);

  item->key = NULL;
  item->value = NULL;
  item->next = ht->free_list;
  ht->free_list = item;
}

/**
 * Compute how much memory we need to allocate to store the bins and the
 * zone for the items. Bins come first, then optional padding, then items.
 *
 * @return the total size needed and the offset within the big chunk where
 * items will start, taking into account memory alignment constraints.
 */
static size_t
hash_bins_items_arena_size(const hash_table_t *ht, size_t *items_offset)
{
  size_t bins = ht->num_bins * sizeof ht->bins[0];
  size_t items = ht->num_items * sizeof ht->items[0];
  size_t align = bins % MEM_ALIGNBYTES;

  if (align != 0)
	  align = MEM_ALIGNBYTES - align;		/* Padding to align items */


  if (items_offset)	
	*items_offset = bins + align;

  return bins + align + items;
}

static void
hash_table_new_intern(hash_table_t *ht, size_t num_bins,
	hash_table_hash_func hash, hash_table_eq_func eq)
{
  size_t i;
  size_t arena;
  size_t items_off;
   
  RUNTIME_ASSERT(ht);
  RUNTIME_ASSERT(num_bins > 1);
  
  ht->num_held = 0;
  ht->bin_fill = 0;
  ht->hash = hash ? hash : hash_id_key;
  ht->eq = eq ? eq : hash_id_eq;

  ht->num_bins = num_bins;
  ht->num_items = ht->num_bins * HASH_ITEMS_PER_BIN;

  arena = hash_bins_items_arena_size(ht, &items_off);

  ht->bins = alloc_pages(arena);
  RUNTIME_ASSERT(ht->bins);
  RUNTIME_ASSERT(items_off != 0);
  
  ht->items = ptr_add_offset(ht->bins, items_off);

  /* Build free list */

  ht->free_list = &ht->items[0];
  for (i = 0; i < ht->num_items - 1; i++) {
    ht->items[i].next = &ht->items[i + 1];
  }
  ht->items[i].next = NULL;

  /* Initialize bins -- all empty */

  for (i = 0; i < ht->num_bins; i++) {
    ht->bins[i] = NULL;
  }

  hash_table_check(ht);
}

hash_table_t *
hash_table_new(void)
{
  hash_table_t *ht = malloc(sizeof *ht);
  hash_table_new_intern(ht, 2, NULL, NULL);
  return ht;
}

hash_table_t *
hash_table_new_full(hash_table_hash_func hash, hash_table_eq_func eq)
{
  hash_table_t *ht = malloc(sizeof *ht);
  hash_table_new_intern(ht, 2, hash, eq);
  return ht;
}

/**
 * Checks how many items are currently in stored in the hash_table.
 *
 * @param ht the hash_table to check.
 * @return the number of items in the hash_table.
 */
size_t
hash_table_size(const hash_table_t *ht)
{
  hash_table_check(ht);
  return ht->num_held;
}

/**
 * NOTE: A naive direct use of the pointer has a much worse distribution e.g.,
 *       only a quarter of the bins are used.
 */
static inline size_t
hash_key(const hash_table_t *ht, const void *key)
{
  return (*ht->hash)(key);
}

static inline gboolean
hash_eq(const hash_table_t *ht, const void *a, const void *b)
{
  return (*ht->eq)(a, b);
}

/**
 * @param ht a hash_table.
 * @param key the key to look for.
 * @param bin if not NULL, it will be set to the bin number that is or would
 *        be used for the key. It is set regardless whether the key is in
 *        the hash_table.
 * @return NULL if the key is not in the hash_table. Otherwise, the item
 *         associated with the key is returned.
 */
static hash_item_t *
hash_table_find(const hash_table_t *ht, const void *key, size_t *bin)
{
  hash_item_t *item;
  size_t hash;

  hash_table_check(ht);

  hash = hash_key(ht, key) & (ht->num_bins - 1);
  item = ht->bins[hash];
  if (bin) {
    *bin = hash;
  }

  for (/* NOTHING */; item != NULL; item = item->next) {
    if (hash_eq(ht, key, item->key))
        return item;
  }

  return NULL;
}

void
hash_table_foreach(hash_table_t *ht, hash_table_foreach_func func, void *data)
{
  size_t i, n;

  hash_table_check(ht);
  RUNTIME_ASSERT(func != NULL);

  n = ht->num_held;
  i = ht->num_bins;
  while (i-- > 0) {
    hash_item_t *item;

    for (item = ht->bins[i]; NULL != item; item = item->next) {
      (*func)(item->key, deconstify_gpointer(item->value), data);
      n--;
    }
  }
  RUNTIME_ASSERT(0 == n);
}

static void
hash_table_clear(hash_table_t *ht)
{
  size_t i;
  size_t arena;

  hash_table_check(ht);

  i = ht->num_bins;
  while (i-- > 0) {
    hash_item_t *item = ht->bins[i];

    while (item) {
      hash_item_t *next;

      next = item->next;
      hash_item_free(ht, item);
      item = next;
    }
    ht->bins[i] = NULL;
  }

  arena = hash_bins_items_arena_size(ht, NULL);

  free_pages(ht->bins, arena);
  ht->bins = NULL;
  ht->num_bins = 0;
  ht->items = NULL;
  ht->num_held = 0;
  ht->num_items = 0;
  ht->free_list = NULL;
}

/**
 * Adds a new item to the hash_table. If the hash_table already contains an
 * item with the same key, the old value is kept and FALSE is returned.
 *
 * @return FALSE if the item could not be added, TRUE on success.
 */
static gboolean
hash_table_insert_no_resize(hash_table_t *ht,
	const void *key, const void *value)
{
  hash_item_t *item;
  size_t bin;

  hash_table_check(ht);

  RUNTIME_ASSERT(key);
  RUNTIME_ASSERT(value);

  if (hash_table_find(ht, key, &bin)) {
    return FALSE;
  }
  RUNTIME_CHECK(NULL == hash_table_lookup(ht, key));

  item = hash_item_alloc(ht, key, value);
  RUNTIME_ASSERT(item != NULL);

  if (NULL == ht->bins[bin]) {
    RUNTIME_ASSERT(ht->bin_fill < ht->num_bins);
    ht->bin_fill++;
  }
  item->next = ht->bins[bin];
  ht->bins[bin] = item;
  ht->num_held++;

  RUNTIME_CHECK(value == hash_table_lookup(ht, key));
  return TRUE;
}

static void
hash_table_resize_helper(const void *key, void *value, void *data)
{
  gboolean ok;
  ok = hash_table_insert_no_resize(data, key, value);
  RUNTIME_ASSERT(ok);
}

static void
hash_table_resize(hash_table_t *ht, size_t n)
{
  hash_table_t tmp;

  hash_table_new_intern(&tmp, n, ht->hash, ht->eq);
  hash_table_foreach(ht, hash_table_resize_helper, &tmp);
  RUNTIME_ASSERT(ht->num_held == tmp.num_held);
  hash_table_clear(ht);
  *ht = tmp;
}

static inline void
hash_table_resize_on_remove(hash_table_t *ht)
{
  size_t n;
  size_t needed_bins = ht->num_held / HASH_ITEMS_PER_BIN;

  if (needed_bins + (HASH_ITEMS_GROW / HASH_ITEMS_PER_BIN) >= ht->num_bins / 2)
	return;

  n = ht->num_bins / 2;
  n = MAX(2, n);
  if (n < needed_bins)
	return;

  hash_table_resize(ht, n);
}

static inline void
hash_table_resize_on_insert(hash_table_t *ht)
{
  if (ht->num_held / HASH_ITEMS_PER_BIN < ht->num_bins)
	return;

  hash_table_resize(ht, ht->num_bins * 2);
}

/**
 * Adds a new item to the hash_table. If the hash_table already contains an
 * item with the same key, the old value is kept and FALSE is returned.
 *
 * @return FALSE if the item could not be added, TRUE on success.
 */
gboolean
hash_table_insert(hash_table_t *ht, const void *key, const void *value)
{
  hash_table_check(ht);

  hash_table_resize_on_insert(ht);
  return hash_table_insert_no_resize(ht, key, value);
}

#if 0 /* UNUSED */
void
hash_table_status(const hash_table_t *ht)
{
  fprintf(stderr,
      "hash_table_status:\n"
      "ht=%p\n"
      "num_held=%lu\n"
      "num_bins=%lu\n"
      "bin_fill=%lu\n",
      ht,
      (unsigned long) ht->num_held,
      (unsigned long) ht->num_bins,
      (unsigned long) ht->bin_fill);
}
#endif /* UNUSED */

gboolean
hash_table_remove(hash_table_t *ht, const void *key)
{
  hash_item_t *item;
  size_t bin;

  item = hash_table_find(ht, key, &bin);
  if (item) {
    hash_item_t *i;

    i = ht->bins[bin];
    RUNTIME_ASSERT(i != NULL);
    if (i == item) {
      if (!i->next) {
        RUNTIME_ASSERT(ht->bin_fill > 0);
        ht->bin_fill--;
      }
      ht->bins[bin] = i->next;
    } else {
      
      RUNTIME_ASSERT(i->next != NULL);
      while (item != i->next) { 
        RUNTIME_ASSERT(i->next != NULL);
        i = i->next;
      }
      RUNTIME_ASSERT(i->next == item);

      i->next = item->next;
    }

    hash_item_free(ht, item);
    ht->num_held--;

    RUNTIME_CHECK(!hash_table_lookup(ht, key));

	hash_table_resize_on_remove(ht);

    return TRUE;
  }
  RUNTIME_CHECK(!hash_table_lookup(ht, key));
  return FALSE;
}

void
hash_table_replace(hash_table_t *ht, const void *key, const void *value)
{
  hash_item_t *item;

  hash_table_check(ht);
	
  item = hash_table_find(ht, key, NULL);
  if (item == NULL) {
	hash_table_insert(ht, key, value);
  } else {
	item->key = key;
	item->value = value;
  }
}

void *
hash_table_lookup(const hash_table_t *ht, const void *key)
{
  hash_item_t *item;

  hash_table_check(ht);
  item = hash_table_find(ht, key, NULL);

  return item ? deconstify_gpointer(item->value) : NULL;
}

gboolean
hash_table_lookup_extended(const hash_table_t *ht,
	const void *key, const void **kp, void **vp)
{
  hash_item_t *item;

  hash_table_check(ht);
  item = hash_table_find(ht, key, NULL);

  if (item == NULL)
	return FALSE;

  if (kp)	*kp = item->key;
  if (vp)	*vp = deconstify_gpointer(item->value);

  return TRUE;
}

void
hash_table_destroy(hash_table_t *ht)
{
  hash_table_clear(ht);
  free(ht);
}

#ifdef TRACK_MALLOC
/*
 * The hash table is used to keep track of the malloc() and free() operations,
 * so we need special routines to ensure allocation and freeing of memory
 * uses the real routines, not the remapped ones.
 *
 * These *_real() routines must only be called by the malloc tracking code.
 * Other clients of this hash table should use the regular routines, so that
 * their usage is properly tracked.
 */

#undef malloc
#undef free

hash_table_t *
hash_table_new_real(void)
{
  hash_table_t *ht = malloc(sizeof *ht);
  hash_table_new_intern(ht, 2, NULL, NULL);
  return ht;
}

hash_table_t *
hash_table_new_full_real(hash_table_hash_func hash, hash_table_eq_func eq)
{
  hash_table_t *ht = malloc(sizeof *ht);
  hash_table_new_intern(ht, 2, hash, eq);
  return ht;
}

void
hash_table_destroy_real(hash_table_t *ht)
{
  hash_table_clear(ht);
  free(ht);
}
#endif /* TRACK_MALLOC */

/* vi: set ai et sts=2 sw=2 cindent: */
