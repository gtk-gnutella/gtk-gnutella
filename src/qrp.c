/*
 * Copyright (c) 2002, Raphael Manfredi
 *
 * Query Routing Protocol (LimeWire's scheme).
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

#include <ctype.h>

#include "gnutella.h"
#include "qrp.h"
#include "matching.h"

#define MIN_SPARSE_RATIO	20		/* At most 20% of slots used */
#define MAX_CONFLICT_RATIO	10		/* At most 10% of insertion conflicts */
#define MIN_WORD_LENGTH		3		/* Minimal word length */
#define LOCAL_INFINITY		2		/* We're one hop away, so 2 is infinity */
#define MIN_TABLE_SIZE		16384	/* 16 KB */
#define MAX_TABLE_SIZE		524288	/* 512 KB */

/*
 * A routing table.
 *
 * If we are a leaf node, we send our routing table to neighbours.  We keep
 * a pointer to the previous table sent, so that we can determine the "patch"
 * with the current table in case our library is regenerated.
 */
struct routing_table {
	gint refcnt;			/* Amount of references */
	gint generation;		/* Generation number */
	guchar *arena;			/* Where table starts */
	gint slots;				/* Amount of slots in table */
};

static char_map_t qrp_map;
static struct routing_table *routing_table = NULL;	/* Our table */
static gint generation = 0;

extern void node_qrt_changed(void);		/* Notify that QRT changed */

/*
 * qrp_hashcode
 *
 * Compute standard QRP hash code on 32 bits.
 */
__inline__ guint32 qrp_hashcode(guchar *x)
{
	guint32 xor = 0;		/* The running total */
	gint j = 0;  			/* The byte position in xor */
	gint c;

#define A_INT 0x4F1BBCDC

	/*
	 * First turn x[0...end-1] into a number by treating all 4-byte
	 * chunks as a little-endian quadword, and XOR'ing the result together.
	 * We pad x with zeroes as needed. 
	 *
	 * To avoid having do deal with special cases, we do this by XOR'ing
	 * a rolling value one byte at a time, taking advantage of the fact that
	 * x XOR 0==x.
	 */


	while ((c = *x++)) {
		guint32 b = tolower(c) & 0xFF; 
		xor ^= b << (j << 3);
		j = (j + 1) & 0x3;
	}

	/*
	 * Multiplication-based hash function.  See Chapter 12.3.2. of CLR.
	 */

	return xor * A_INT;
}

/*
 * qrp_hash_restrict
 *
 * Restrict given hashcode to be a suitable index on `bits' bits.
 */
guint32 qrp_hash_restrict(guint32 hashcode, gint bits)
{
	return hashcode >> (32 - bits);
}

/*
 * qrp_hash
 *
 * The hashing function, defined by the QRP specifications.
 * Naturally, everyone must use the SAME hashing function!
 */
guint32 qrp_hash(guchar *x, gint bits)
{
	return qrp_hashcode(x) >> (32 - bits);
}

/*
 * qrp_init
 *
 * Initialize QRP.
 */
void qrp_init(char_map_t map)
{
	gint c;

	g_assert(map);

	for (c = 0; c < 256; c++)
		qrp_map[c] = map[c];

	/*
	 * Having a working hash function is critical.
	 * Check that the implementation is not broken by accident.
	 */

	g_assert(qrp_hash("ebcklmenq", 13) == 3527);
	g_assert(qrp_hash("ndflalem", 16) == 37658);
	g_assert(qrp_hash("7777a88a8a8a8", 10) == 342);
}

/*
 * qrp_close
 *
 * Called at servent shutdown to reclaim all the memory.
 */
void qrp_close(void)
{
}

/***
 *** Routing table management.
 ***/

/*
 * qrt_create
 *
 * Create a new query routing table, with supplied `arena' and `slots'.
 */
static struct routing_table *qrt_create(guchar *arena, gint slots)
{
	struct routing_table *qrt;

	qrt = g_malloc(sizeof(*qrt));

	qrt->arena = arena;
	qrt->slots = slots;
	qrt->generation = generation++;
	qrt->refcnt = 1;

	return qrt;
}

/*
 * qrt_free
 *
 * Free query routing table.
 */
static void qrt_free(struct routing_table *qrt)
{
	g_assert(qrt->refcnt == 0);

	g_free(qrt->arena);
	g_free(qrt);
}

/*
 * qrt_unref
 *
 * Remove one reference to query routing table.
 * When the last reference is removed, the table is freed.
 */
static void qrt_unref(struct routing_table *qrt)
{
	g_assert(qrt->refcnt > 0);

	if (--qrt->refcnt == 0)
		qrt_free(qrt);
}

/***
 *** Construction of our own routing table.
 ***/

/*
 * Since the routing table is only used between a leaf and an ultranode,
 * the hop counts should be either 1 or INFINITY.
 */

#define DEFAULT_BUF_SIZE	512
#define MIN_BUF_GROW		256

static GHashTable *ht_seen_words = NULL;
static struct {
	guchar *arena;
	gint len;
} buffer = { NULL, 0 };

/*
 * qrp_prepare_computation
 *
 * This routine must be called to initialize the computation of the new QRP.
 */
void qrp_prepare_computation(void)
{
	g_assert(ht_seen_words == NULL);	/* Not already in computation */
	g_assert(qrp_map != NULL);			/* qrp_init() called */

	ht_seen_words = g_hash_table_new(g_str_hash, g_str_equal);

	if (buffer.arena == NULL) {
		buffer.arena = g_malloc(DEFAULT_BUF_SIZE);
		buffer.len = DEFAULT_BUF_SIZE;
	}
}

/*
 * qrp_add_file
 *
 * Add shared file to our QRP.
 */
void qrp_add_file(struct shared_file *sf)
{
	word_vec_t *wovec;
	guint wocnt;
	gint i;

	g_assert(ht_seen_words != NULL);	/* Already in computation */
	g_assert(sf);

	/*
	 * Copy filename to buffer, since we're going to map it inplace.
	 */

	if (sf->file_name_len >= buffer.len) {
		gint grow = MAX(MIN_BUF_GROW, sf->file_name_len - buffer.len + 1);

		buffer.arena = g_realloc(buffer.arena, buffer.len + grow);
		buffer.len += grow;
	}

	g_assert(sf->file_name_len <= (buffer.len + 1));

	strncpy(buffer.arena, sf->file_name, buffer.len);

	/*
	 * Apply our mapping filter, which will keep only words and lowercase
	 * everything.  All other letters are replaced by spaces, so that
	 * we may use query_make_word_vec() to break them up.
	 */

	(void) match_map_string(qrp_map, buffer.arena);
	wocnt = query_make_word_vec(buffer.arena, &wovec);

	if (wocnt == 0)
		return;

	/*
	 * Identify unique words we have not already seen in `ht_seen_words'.
	 */

	for (i = 0; i < wocnt; i++) {
		gchar *word = wovec[i].word;

		g_assert(word[0] != '\0');

		/*
		 * It is unreasonable to put words of 1 and 2 letters in the QR table.
		 * Also, all words smaller than MIN_WORD_LENGTH are skipped.
		 */

		if (word[1] == '\0' || word[2] == '\0')
			continue;

		if (MIN_WORD_LENGTH > 3 && strlen(word) < MIN_WORD_LENGTH)
			continue;

		/*
		 * Record word if we haven't seen it yet.
		 */

		if (g_hash_table_lookup(ht_seen_words, (gconstpointer) word))
			continue;

		g_hash_table_insert(ht_seen_words, g_strdup(word), (gpointer) 1);

		if (dbg > 8)
			printf("new QRP word \"%s\" [from %s]\n", word, sf->file_name);
	}

	query_word_vec_free(wovec, wocnt);
}

/*
 * Hash table iterator callbacks
 */

static void free_word(gpointer key, gpointer value, gpointer udata)
{
	g_free(key);
}

struct unique_substrings {		/* User data for unique_subtr() callback */
	GHashTable *unique;
	GSList *head;
	gint count;
};

static void unique_substr(gpointer key, gpointer value, gpointer udata)
{
	struct unique_substrings *u = (struct unique_substrings *) udata;
	guchar *word = (guchar *) key;
	gint len;

	/*
	 * Add all unique (i.e. not already seen) substrings from word, all
	 * anchored at the start, whose length range from 3 to the word length.
	 */

	for (len = strlen(word); len >= 3; len--) {
		guchar c = word[len];
		word[len] = '\0';				/* Truncate word */

		if (!g_hash_table_lookup(u->unique, (gconstpointer) word)) {
			guchar *newword = g_strdup(word);
			g_hash_table_insert(u->unique, newword, (gpointer) 1);
			u->head = g_slist_prepend(u->head, newword);
			u->count++;
		}

		word[len] = c;
	}
}

/*
 * unique_substrings
 *
 * Create a list of all unique substrings at least MIN_WORD_LENGTH long,
 * from words held in `ht'.
 *
 * Returns created list, and count in `retcount'.
 */
static GSList *unique_substrings(GHashTable *ht, gint *retcount)
{
	struct unique_substrings u = { NULL, NULL, 0 };		/* Callback args */

	u.unique = g_hash_table_new(g_str_hash, g_str_equal);

	g_hash_table_foreach(ht, unique_substr, &u);

	g_hash_table_destroy(u.unique);		/* Created words ref'ed by u.head */
	*retcount = u.count;

	return u.head;
}

/*
 * qrp_finalize_computation
 *
 * This routine must be called once all the files have been added to finalize
 * the computation of the new QRP.
 */
void qrp_finalize_computation(void)
{
	guchar *table = NULL;
	gint slots;
	GSList *sl_substrings;
	gint substrings;
	GSList *l;

	g_assert(ht_seen_words != NULL);	/* Already in computation */

	/*
	 * Compute list of all the unique substrings we need to insert.
	 */

	sl_substrings = unique_substrings(ht_seen_words, &substrings);

	if (dbg > 1)
		printf("QRP unique subwords: %d\n", substrings);

	/*
	 * Build QR table: we try to achieve a minimum sparse ratio (empty
	 * slots filled with INFINITY) whilst limiting the size of the table,
	 * so we incrementally try and double the size until we reach the maximum.
	 */

	for (slots = MIN_TABLE_SIZE; slots <= MAX_TABLE_SIZE; slots *= 2) {
		gint bits = ffs(slots) - 1;
		gint upper_thresh = MIN_SPARSE_RATIO * slots;
		gboolean full = FALSE;
		gint hashed = 0;
		gint filled = 0;
		gint conflict_ratio;

		g_assert(1 << bits == slots);

		if (table)
			g_free(table);

		table = g_malloc(slots);
		memset(table, LOCAL_INFINITY, slots);

		for (l = sl_substrings; l; l = l->next) {
			guchar *word = (guchar *) l->data;
			guint idx = qrp_hash(word, bits);

			hashed++;

			if (table[idx] == LOCAL_INFINITY) {
				table[idx] = 1;
				filled++;
				if (dbg > 7)
					printf("QRP added subword: \"%s\"\n", word);
			}

			if (slots != MAX_TABLE_SIZE && 100*filled > upper_thresh) {
				full = TRUE;
				break;
			}
		}

		conflict_ratio = (gint) (100.0 * (substrings - filled) / substrings);

		if (dbg > 1)
			printf("QRP size=%d, filled=%d, hashed=%d, "
				"ratio=%d%%, conflicts=%d%%%s\n",
				slots, filled, hashed,
				(gint) (100.0 * filled / slots),
				conflict_ratio, full ? " FULL" : "");

		if (!full && conflict_ratio < MAX_CONFLICT_RATIO)
			break;
	}

	if (dbg)
		printf("QRP table size: %d bytes\n", slots);

	/*
	 * If we had already a table, compare it to the one we just built.
	 * If they are identical, discard the new one.
	 */

	if (routing_table) {
		if (
			routing_table->slots == slots &&
			0 == memcmp(routing_table->arena, table, slots)
		) {
			if (dbg)
				printf("no change in QRP table\n");
			goto cleanup;
		}
		qrt_unref(routing_table);
	}

	/*
	 * Install new routing table and notify the nodes that it has changed.
	 */

	routing_table = qrt_create(table, slots);
	node_qrt_changed();

	/*
	 * Final cleanup.
	 */
cleanup:

	g_hash_table_foreach(ht_seen_words, free_word, NULL);
	g_hash_table_destroy(ht_seen_words);
	ht_seen_words = NULL;

	for (l = sl_substrings; l; l = l->next)
		g_free(l->data);
	g_slist_free(sl_substrings);
}

/***
 *** Testing section.
 ***/

#ifdef TEST

#define CHECK(x) do { \
	if (!(x)) printf("FAILED: %s\n", #x); \
	else printf("OK: %s\n", #x); \
} while (0)

void test_hash(void)
{
#define hash qrp_hash

	CHECK(hash("", 13)==0);
	CHECK(hash("eb", 13)==6791);
	CHECK(hash("ebc", 13)==7082);
	CHECK(hash("ebck", 13)==6698);
	CHECK(hash("ebckl", 13)==3179);
	CHECK(hash("ebcklm", 13)==3235);
	CHECK(hash("ebcklme", 13)==6438);
	CHECK(hash("ebcklmen", 13)==1062);
	CHECK(hash("ebcklmenq", 13)==3527);
	CHECK(hash("", 16)==0);
	CHECK(hash("n", 16)==65003);
	CHECK(hash("nd", 16)==54193);
	CHECK(hash("ndf", 16)==4953);
	CHECK(hash("ndfl", 16)==58201);
	CHECK(hash("ndfla", 16)==34830);
	CHECK(hash("ndflal", 16)==36910);
	CHECK(hash("ndflale", 16)==34586);
	CHECK(hash("ndflalem", 16)==37658);
	CHECK(hash("FAIL", 16)==37458);	// WILL FAIL
	CHECK(hash("ndflaleme", 16)==45559);
	CHECK(hash("ol2j34lj", 10)==318);
	CHECK(hash("asdfas23", 10)==503);
	CHECK(hash("9um3o34fd", 10)==758);
	CHECK(hash("a234d", 10)==281);
	CHECK(hash("a3f", 10)==767);
	CHECK(hash("3nja9", 10)==581);
	CHECK(hash("2459345938032343", 10)==146);
	CHECK(hash("7777a88a8a8a8", 10)==342);
	CHECK(hash("asdfjklkj3k", 10)==861);
	CHECK(hash("adfk32l", 10)==1011);
	CHECK(hash("zzzzzzzzzzz", 10)==944);

	CHECK(hash("3nja9", 10)==581);
	CHECK(hash("3NJA9", 10)==581);
	CHECK(hash("3nJa9", 10)==581);
}

#endif /* TEST */

