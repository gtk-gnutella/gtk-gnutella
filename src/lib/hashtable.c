/*
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
 * @author Christian Biere
 * @date 2006
 */

#include "common.h"

RCSID("$Id$")

#include "lib/hashtable.h"
#include "lib/vmm.h"

#include "lib/override.h"		/* Must be the last header included */

#define HASH_ITEMS_PER_BIN 4

typedef struct hash_item {
  void *key;
  void *value;
  struct hash_item *next;
} hash_item_t;

struct hash_table {
  size_t      num_items; /* Array length of "items" */
  size_t      num_bins; /* Number of bins */
  size_t      num_held; /* Number of items actually in the table */
  size_t      bin_fill; /* Number of bins in use */
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

static hash_item_t * 
hash_item_alloc(hash_table_t *ht, void *key, void *value)
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

void
hash_table_new_intern(hash_table_t *ht, size_t num_bins)
{
  size_t i;
   
  RUNTIME_ASSERT(ht);
  RUNTIME_ASSERT(num_bins > 1);
  
  ht->num_held = 0;
  ht->bin_fill = 0;

  ht->num_bins = num_bins;
  ht->bins = alloc_pages(ht->num_bins * sizeof ht->bins[0]);
  RUNTIME_ASSERT(ht->bins);
  
  ht->num_items = ht->num_bins * HASH_ITEMS_PER_BIN;
  ht->items = alloc_pages(ht->num_items * sizeof ht->items[0]);
  RUNTIME_ASSERT(ht->items);

  ht->free_list = &ht->items[0];
  for (i = 0; i < ht->num_items - 1; i++) {
    ht->items[i].next = &ht->items[i + 1];
  }
  ht->items[i].next = NULL;

  for (i = 0; i < ht->num_bins; i++) {
    ht->bins[i] = NULL;
  }

  hash_table_check(ht);
}

hash_table_t *
hash_table_new(void)
{
  hash_table_t *ht = malloc(sizeof *ht);
  hash_table_new_intern(ht, 2);
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
hash_key(const void *key)
{
  size_t n = (size_t) key;
  return ((0x4F1BBCDCUL * (guint64) n) >> 32) ^ n;
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
hash_table_find(hash_table_t *ht, const void *key, size_t *bin)
{
  hash_item_t *item;
  size_t hash;

  hash_table_check(ht);

  hash = hash_key(key) & (ht->num_bins - 1);
  item = ht->bins[hash];
  if (bin) {
    *bin = hash;
  }

  for (/* NOTHING */; item != NULL; item = item->next) {
    if (key == item->key)
        return item;
  }

  return NULL;
}

void
hash_table_foreach(hash_table_t *ht, hash_table_foreach_func func, void *data)
{
  size_t i;

  hash_table_check(ht);
  RUNTIME_ASSERT(func != NULL);

  for (i = 0; i < ht->num_bins; i++) {
    hash_item_t *item;

    for (item = ht->bins[i]; NULL != item; item = item->next) {
      (*func)(item->key, item->value, data);
    }
  }
}

static void
hash_table_clear(hash_table_t *ht)
{
  size_t i;

  hash_table_check(ht);
  for (i = 0; i < ht->num_bins; i++) {
    hash_item_t *item = ht->bins[i];

    while (item) {
      hash_item_t *next;

      next = item->next;
      hash_item_free(ht, item);
      item = next;
    }
    ht->bins[i] = NULL;
  }

  free_pages(ht->bins, ht->num_bins * sizeof ht->bins[0]);
  ht->bins = NULL;
  ht->num_bins = 0;
  free_pages(ht->items, ht->num_items * sizeof ht->items[0]);
  ht->items = NULL;
  ht->num_items = 0;
  ht->free_list = NULL;
}

void
hash_table_resize_helper(void *key, void *value, void *data)
{
  gboolean ok;
  ok = hash_table_insert(data, key, value);
  RUNTIME_ASSERT(ok);
}

static inline void
hash_table_resize(hash_table_t *ht)
{
  size_t n;

  /* TODO: Also shrink the table */
  if ((ht->num_held / HASH_ITEMS_PER_BIN) >= ht->num_bins) {
    n = ht->num_bins * 2;
  } else {
    n = ht->num_bins;
  }

  if (n != ht->num_bins) {
    hash_table_t tmp;

    hash_table_new_intern(&tmp, n);
    hash_table_foreach(ht, hash_table_resize_helper, &tmp);
    hash_table_clear(ht);

    RUNTIME_ASSERT(ht->num_held == tmp.num_held);

    *ht = tmp;
  }
}

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

/**
 * Adds a new item to the hash_table. If the hash_table already contains an
 * item with the same key, the old value is kept and FALSE is returned.
 *
 * @return FALSE if the item could not be added, TRUE on success.
 */
gboolean
hash_table_insert(hash_table_t *ht, void *key, void *value)
{
  hash_item_t *item;
  size_t bin;

  hash_table_check(ht);

  RUNTIME_ASSERT(key);
  RUNTIME_ASSERT(value);

  hash_table_resize(ht);

  if (hash_table_find(ht, key, &bin)) {
    return FALSE;
  }
  RUNTIME_ASSERT(NULL == hash_table_lookup(ht, key));

  item = hash_item_alloc(ht, key, value);
  RUNTIME_ASSERT(item != NULL);

  if (NULL == ht->bins[bin]) {
    RUNTIME_ASSERT(ht->bin_fill < ht->num_bins);
    ht->bin_fill++;
  }
  item->next = ht->bins[bin];
  ht->bins[bin] = item;
  ht->num_held++;

  RUNTIME_ASSERT(value == hash_table_lookup(ht, key));
  return TRUE;
}

gboolean
hash_table_remove(hash_table_t *ht, void *key)
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

    RUNTIME_ASSERT(!hash_table_lookup(ht, key));
    return TRUE;
  }
  RUNTIME_ASSERT(!hash_table_lookup(ht, key));
  return FALSE;
}

void *
hash_table_lookup(hash_table_t *ht, void *key)
{
  hash_item_t *item;

  hash_table_check(ht);
  item = hash_table_find(ht, key, NULL);

  return item ? item->value : NULL;
}

void
hash_table_destroy(hash_table_t *ht)
{
  hash_table_clear(ht);
  free(ht);
}

/* vi: set ai et sts=2 sw=2 cindent: */
