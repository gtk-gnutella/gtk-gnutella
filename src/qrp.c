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
#include "zlib_util.h"

#define MIN_SPARSE_RATIO	20		/* At most 20% of slots used */
#define MAX_CONFLICT_RATIO	10		/* At most 10% of insertion conflicts */
#define MIN_WORD_LENGTH		3		/* Minimal word length */
#define LOCAL_INFINITY		2		/* We're one hop away, so 2 is infinity */
#define MIN_TABLE_BITS		14		/* 16 KB */
#define MAX_TABLE_BITS		21		/* 2 MB */

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
	gint infinity;			/* Value for "infinity" */
	gboolean compacted;
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

/***
 *** Routing table management.
 ***/

/*
 * qrt_compact
 *
 * Compact routing table in place so that only one bit of information is used
 * per entry, reducing memory requirements by a factor of 8.
 */
static void qrt_compact(struct routing_table *rt)
{
	gint nsize;				/* New table size */
	guchar *narena;			/* New arena */
	gint i;
	guint mask;
	guchar *p;
	guchar *q;

	g_assert(rt);
	g_assert(rt->slots >= 8);
	g_assert(0 == (rt->slots & 0x7));	/* Multiple of 8 */
	g_assert(!rt->compacted);

	nsize = rt->slots / 8;
	narena = g_malloc0(nsize);
	q = narena + (nsize - 1);

	/*
	 * Because we're compacting an ultranode -> leafnode routing table,
	 * items in the original table that are not "infinity" are replaced
	 * by 1 bits (i.e. present).  A keyword is either present or not.
	 */

	for (mask = 0, i = rt->slots - 1, p = &rt->arena[i]; i >= 0; i--, p--) {
		if (*p != rt->infinity)
			mask |= 0x1;
		if (0 == (i & 0x7)) {			/* Reached "bit 0" */
			*q-- = mask;
			mask = 0;
		} else
			mask <<= 1;
	}

	g_assert((q + 1) == narena);		/* Filled 1st byte at last iteration */

	/*
	 * Install new compacted arena in place of the non-compacted one.
	 */

	g_free(rt->arena);
	rt->arena = narena;
	rt->compacted = TRUE;
}

/*
 * qrt_apply_patch_8
 *
 * Given a non-compacted patch array, apply it to the specified routing table.
 * The patch is given with entries being 8-bit wide.
 */
static void qrt_apply_patch_8(struct routing_table *rt, guchar *patch, gint len)
{
	guchar *p;
	guchar *q;
	gint i;
	gint bytes = rt->slots / 8;

	g_assert(rt->compacted);
	g_assert(len == rt->slots);

	/*
	 * The only possibilities for the patch are negative values, to
	 * bring the slot value from infinity to 1, or positive values to put
	 * the slot back to infinity, 0 for no change.
	 *
	 * Therefore, a positive patch value means that we no longer have
	 * anything for the slot, a negative one that we do have something, 0
	 * meaning no change.
	 */

	for (i = 0, p = rt->arena, q = patch; i < bytes; i++) {
		guint set = 0;				/* Bits to set */
		guint clear = 0;			/* Bits to clear */
		guchar r;
		gint j;

		for (j = 7; j >= 0; j--) {
			guchar v = *q++;
			if (v & 0x80)			/* Negative value, sign bit is 1 */
				set |= 1 << j;		/* We have something for this slot */
			else if (v != 0)		/* Positive value */
				clear |= 1 << j;	/* We no longer have something there */
		}

		g_assert(0 == (set & clear));	/* Each bit is set or cleared */

		/*
		 * Apply patch.
		 */

		r = *p;
		r &= ~clear;
		r |= set;
		*p++ = r;
	}

	g_assert(q == (patch + len));	/* Went through all the patch */
}

/*
 * qrt_apply_patch_4
 *
 * Given a non-compacted patch array, apply it to the specified routing table.
 * The patch is given with entries being 4-bit wide.
 */
static void qrt_apply_patch_4(struct routing_table *rt, guchar *patch, gint len)
{
	guchar *p;
	guchar *q;
	gint i;
	gint bytes = rt->slots / 8;

	g_assert(rt->compacted);
	g_assert(len == rt->slots);

	/*
	 * The only possibilities for the patch are negative values, to
	 * bring the slot value from infinity to 1, or positive values to put
	 * the slot back to infinity, 0 for no change.
	 *
	 * Therefore, a positive patch value means that we no longer have
	 * anything for the slot, a negative one that we do have something, 0
	 * meaning no change.
	 */

	for (i = 0, p = rt->arena, q = patch; i < bytes; i++) {
		guint set = 0;				/* Bits to set */
		guint clear = 0;			/* Bits to clear */
		guchar r;
		gint j;

		for (j = 7; j >= 0; j--) {
			guchar v;

			if (j & 0x1)
				v = (*q & 0xf0) >> 4;		/* First quartet, highest part */
			else
				v = (*q++ & 0x0f);			/* Second quartet, lowest part */

			if (v & 0x08)			/* Negative value, sign bit is 1 */
				set |= 1 << j;		/* We have something for this slot */
			else if (v != 0)		/* Positive value */
				clear |= 1 << j;	/* We no longer have something there */
		}

		g_assert(0 == (set & clear));	/* Each bit is set or cleared */

		/*
		 * Apply patch.
		 */

		r = *p;
		r &= ~clear;
		r |= set;
		*p++ = r;
	}

	g_assert(q == (patch + len));	/* Went through all the patch */
}

/*
 * A routing table patch.
 */
struct routing_patch {
	guchar *arena;
	gint size;						/* Number of quartets */
	gint len;						/* Length of arena in bytes */
	gint entry_bits;
	gboolean compressed;
};

/*
 * qrt_diff_4
 *
 * Compute patch between two (compacted) routing tables.
 * When `old' is NULL, then we compare against a table filled with "infinity".
 * If `old' isn't NULL, then it must have the same size as `new'.
 *
 * Returns a patch buffer (uncompressed), made of signed quartets.
 */
static struct routing_patch *qrt_diff_4(
	struct routing_table *old,
	struct routing_table *new)
{
	gint bytes;
	struct routing_patch *rp;
	guchar *op;
	guchar *np;
	guchar *pp;
	gint i;

	g_assert(old == NULL || old->compacted);
	g_assert(new->compacted);
	g_assert(old == NULL || new->slots == old->slots);

	rp = g_malloc(sizeof(*rp));
	rp->size = new->slots;
	rp->len = rp->size / 2;			/* Each entry stored on 4 bits */
	rp->entry_bits = 4;
	rp->compressed = FALSE;
	pp = rp->arena = g_malloc(rp->len);

	op = old ? old->arena : NULL;
	np = new->arena;

	for (i = 0, bytes = new->slots / 8; i < bytes; i++) {
		guint8 obyte = op ? *op++ : 0x0;	/* Nothing */
		guint8 nbyte = *np++;
		gint j;
		guint8 v;

		/*
		 * In an uncompressed table, cleared bits would be infinity.
		 * Thus, we need to build the patch quartets as:
         *
         *     old bit      new bit      patch
         *        0            0          0x0     (no change)
         *        0            1          0xf     (-1, from INFINITY=2 to 1)
         *        1            0          0x1     (+1, from 1 to INFINITY)
         *        1            1          0x0     (no change)
         */

		for (v = 0, j = 7; j >= 0; j--) {
			guint8 mask = 1 << j;

			if ((obyte & mask) ^ (nbyte & mask))	/* Bit `j' changed */
				v |= (obyte & mask) ? 0x1 : 0xf;

			if (j & 0x1)
				v <<= 4;			/* We have upper half of octet (byte) */
			else
				*pp++ = v;
		}
	}

	g_assert(np == (new->arena + new->slots / 8));
	g_assert(op == NULL || op == (old->arena + old->slots / 8));
	g_assert(pp == (rp->arena + rp->len));

	return rp;
}

/*
 * Co-routine compression context.
 */

#define QRT_COMPRESS_MAGIC	0x45afbb01
#define QRT_INITIAL_CHUNK	256			/* Initial compressing chunk size */
#define QRT_HALF_LIFE		50000		/* In useconds, MUST be << 1000 usec */

struct qrt_compress_context {
	gint magic;						/* Magic number */
	struct routing_patch *rp;		/* Routing table being compressed */
	zlib_deflater_t *zd;			/* Incremental deflater */
	gint chunklen;					/* Amount to compress */
	qrp_callback_t done_callback;	/* Notification callback when done */
	gpointer arg;					/* Callback argument */
	gint timer_id;					/* Computation hearbeat */
};

static gboolean qrt_compress_timer(gpointer arg);
static GSList *sl_compress_coroutines = NULL;

/*
 * qrt_patch_compress
 *
 * Compress routing patch inplace (asynchronously).
 * When it's done, invoke callback with specified argument.
 */
static void qrt_patch_compress(
	struct routing_patch *rp,
	qrp_callback_t done_callback, gpointer arg)
{
	struct qrt_compress_context *ctx;
	zlib_deflater_t *zd;

	zd = zlib_deflater_make(rp->arena, rp->len, 9);

	if (zd == NULL) {
		(*done_callback)(arg, FALSE);
		return;
	}

	/*
	 * Because compression is possibly a CPU-intensive operation, it
	 * is dealt with as a coroutine that will be scheduled at regular
	 * intervals.
	 */

	ctx = g_malloc0(sizeof(*ctx));
	ctx->magic = QRT_COMPRESS_MAGIC;
	ctx->rp = rp;
	ctx->zd = zd;
	ctx->chunklen = QRT_INITIAL_CHUNK;
	ctx->done_callback = done_callback;
	ctx->arg = arg;
	ctx->timer_id = g_timeout_add(1000, qrt_compress_timer, ctx);

	sl_compress_coroutines = g_slist_prepend(sl_compress_coroutines, ctx);
}

/*
 * qrt_compress_timer
 *
 * Perform incremental compression.
 */
static gboolean qrt_compress_timer(gpointer arg)
{
	struct qrt_compress_context *ctx = (struct qrt_compress_context *) arg;
	struct timeval start, end;
	gint ret;
	glong delay;

	g_assert(ctx->magic == QRT_COMPRESS_MAGIC);

	if (dbg > 4)
		printf("compress_timer: chunk = %d bytes\n", ctx->chunklen);

	gettimeofday(&start, NULL);
	ret = zlib_deflate(ctx->zd, ctx->chunklen);
	gettimeofday(&end, NULL);

	switch (ret) {
	case -1:					/* Error occurred */
		zlib_deflater_free(ctx->zd, TRUE);
		goto done;
		/* NOTREACHED */
	case 0:						/* Finished */
		/*
		 * Install compressed routing patch if it's smaller than the original.
		 */

		if (dbg > 2) {
			printf("QRP patch: len=%d, compressed=%d (ratio %.2f%%)\n",
				ctx->rp->len, zlib_deflater_outlen(ctx->zd),
				100.0 * (ctx->rp->len - zlib_deflater_outlen(ctx->zd)) /
					ctx->rp->len);
			fflush(stdout);
		}

		if (zlib_deflater_outlen(ctx->zd) < ctx->rp->len) {
			struct routing_patch *rp = ctx->rp;

			g_free(rp->arena);
			rp->arena = zlib_deflater_out(ctx->zd);
			rp->len = zlib_deflater_outlen(ctx->zd);
			rp->compressed = TRUE;

			zlib_deflater_free(ctx->zd, FALSE);
		} else
			zlib_deflater_free(ctx->zd, TRUE);

		goto done;
		/* NOTREACHED */
	case 1:						/* More work required */
		break;
	default:
		g_assert(0);			/* Bug in zlib_deflate() */
	}

	/*
	 * Compute size of compressing chunk for next iteration.
	 *
	 * Double credit for next iteration if we are under the half life,
	 * but remove one fourth of the credit if we are above twice that
	 * elapsed time.  That's coarse grain adjustments.
	 *
	 * Within the [half-life, 2* half-life] interval, we shoot for
	 * the middle of the interval, by making linear adjustments.
	 */

	delay = end.tv_usec - start.tv_usec +
		(end.tv_sec - start.tv_sec) * 1000 * 1000;

	if (delay == 0)
		delay++;

	if (delay < QRT_HALF_LIFE)
		ctx->chunklen *= 2;
	else if (delay > QRT_HALF_LIFE * 2)
		ctx->chunklen -= ctx->chunklen >> 2;
	else
		ctx->chunklen = (gint) (ctx->chunklen *
			(gfloat) (QRT_HALF_LIFE + QRT_HALF_LIFE/2) / delay);

	if (ctx->chunklen < QRT_INITIAL_CHUNK)
		ctx->chunklen = QRT_INITIAL_CHUNK;

	if (dbg > 4) {
		printf("compress_credit: elapsed: %ld usec, new chunk = %d bytes\n",
			delay, ctx->chunklen);
		fflush(stdout);
	}

	return TRUE;

done:
	sl_compress_coroutines = g_slist_remove(sl_compress_coroutines, ctx);
	(*ctx->done_callback)(ctx->arg, FALSE);
	g_free(ctx);

	return FALSE;
}

/*
 * qrt_compress_cancel_one
 *
 * Cancel a compression coroutine identified by its context.
 * The entry is NOT removed from the list.
 */
static void qrt_compress_cancel_one(struct qrt_compress_context *ctx)
{
	g_assert(ctx->magic == QRT_COMPRESS_MAGIC);
	g_assert(ctx->timer_id);
	g_assert(ctx->zd);

	zlib_deflater_free(ctx->zd, TRUE);
	g_source_remove(ctx->timer_id);

	ctx->zd = NULL;
	ctx->timer_id = 0;

	(*ctx->done_callback)(ctx->arg, TRUE);

	g_free(ctx);
}

/*
 * qrt_compress_cancel_all
 *
 * Cancel all running compression coroutines.
 */
static void qrt_compress_cancel_all(void)
{
	GSList *l;

	for (l = sl_compress_coroutines; l; l = l->next)
		qrt_compress_cancel_one((struct qrt_compress_context *) l->data);

	g_slist_free(sl_compress_coroutines);
	sl_compress_coroutines = NULL;
}

/*
 * qrt_create
 *
 * Create a new query routing table, with supplied `arena' and `slots'.
 * The value used for infinity is given as `max'.
 */
static struct routing_table *qrt_create(guchar *arena, gint slots, gint max)
{
	struct routing_table *rt;

	rt = g_malloc(sizeof(*rt));

	rt->arena = arena;
	rt->slots = slots;
	rt->generation = generation++;
	rt->refcnt = 1;
	rt->infinity = max;
	rt->compacted = FALSE;

	qrt_compact(rt);

	return rt;
}

/*
 * qrt_free
 *
 * Free query routing table.
 */
static void qrt_free(struct routing_table *rt)
{
	g_assert(rt->refcnt == 0);

	g_free(rt->arena);
	g_free(rt);
}

/*
 * qrt_unref
 *
 * Remove one reference to query routing table.
 * When the last reference is removed, the table is freed.
 */
static void qrt_unref(struct routing_table *rt)
{
	g_assert(rt->refcnt > 0);

	if (--rt->refcnt == 0)
		qrt_free(rt);
}

/***
 *** Management of per-connection routing table.
 ***/

/*
 * This structure is opaque for nodes, and is installed as `query_routing'
 * information in the node structure.
 */
struct query_routing {
	struct routing_table *qrt;		/* Current routing table */
	gchar *patch;					/* Patching arena */
	gchar *patch_end;				/* One byte of end of patching arena */
	gint state;						/* State of the QRT propagation */
	gint bits_per_entry;			/* Amount of bits per entry in patch */
	gint payload_size;				/* Size of the PATCH message payload */
	gint seqno;						/* Sequence number of next packet */
	gint max_seqno;					/* Last sequence number to send */
};

/*
 * States.
 */

#define QRT_NONE			0		/* No QRT sent yet */
#define QRT_SENDING			1		/* Sending patches */
#define QRT_IDLE			2		/* Finished send patches */

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

static void qrp_cancel_computation(void);

/*
 * qrp_prepare_computation
 *
 * This routine must be called to initialize the computation of the new QRP.
 */
void qrp_prepare_computation(void)
{
	g_assert(qrp_map != NULL);			/* qrp_init() called */

	qrp_cancel_computation();			/* Cancel any running computation */
	g_assert(ht_seen_words == NULL);	/* Not already in computation */

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
 * Co-routine context.
 */

#define QRP_STEP_SUBSTRING	1		/* Substring computation */
#define QRP_STEP_COMPUTE	2		/* Compute QRT */
#define QRP_STEP_INSTALL	3		/* Install new QRT */
#define QRP_STEP_LAST		3		/* Last step */

#define QRP_MAGIC	0x45afcc05

struct qrp_context {
	gint magic;
	gint step;					/* Current processing step */
	gint seqno;					/* Number of calls at same step */
	GSList *sl_substrings;		/* List of all substrings */
	gint substrings;			/* Amount of substrings */
	guchar *table;				/* Computed routing table */
	gint slots;					/* Amount of slots in table */
	gint timer_id;
};

static struct qrp_context *qrp_ctx = NULL;
static gboolean qrp_compute_timer(gpointer arg);

/*
 * qrp_finalize_computation
 *
 * This routine must be called once all the files have been added to finalize
 * the computation of the new QRP.
 *
 * If the routing table has changed, the node_qrt_changed() routine will
 * be called once we have finished its computation.
 */
void qrp_finalize_computation(void)
{
	/*
	 * Because QRP computation is possibly a CPU-intensive operation, it
	 * is dealt with as a coroutine that will be scheduled at regular
	 * intervals.
	 */

	qrp_ctx = g_malloc0(sizeof(*qrp_ctx));
	qrp_ctx->magic = QRP_MAGIC;
	qrp_ctx->step = QRP_STEP_SUBSTRING;
	qrp_ctx->timer_id = g_timeout_add(500, qrp_compute_timer, qrp_ctx);
}

/*
 * qrp_context_free
 *
 * Free query routing table computation context.
 */
static void qrp_context_free(struct qrp_context *ctx)
{
	GSList *l;

	for (l = ctx->sl_substrings; l; l = l->next)
		g_free(l->data);
	g_slist_free(ctx->sl_substrings);

	g_free(ctx);
}

/*
 * dispose_ht_seen_words
 *
 * Free the `ht_seen_words' table.
 */
static void dispose_ht_seen_words(void)
{
	g_assert(ht_seen_words);

	g_hash_table_foreach(ht_seen_words, free_word, NULL);
	g_hash_table_destroy(ht_seen_words);
	ht_seen_words = NULL;
}

/*
 * qrp_cancel_computation
 *
 * Cancel current computation, if any.
 */
static void qrp_cancel_computation(void)
{
	qrt_compress_cancel_all();

	if (qrp_ctx == NULL)
		return;

	if (ht_seen_words)
		dispose_ht_seen_words();

	g_source_remove(qrp_ctx->timer_id);
	qrp_context_free(qrp_ctx);
	qrp_ctx = NULL;
}

/*
 * qrp_step_substring
 *
 * Compute all the substrings we need to insert.
 */
static gint qrp_step_substring(struct qrp_context *ctx)
{
	g_assert(ht_seen_words != NULL);	/* Already in computation */

	ctx->sl_substrings = unique_substrings(ht_seen_words, &ctx->substrings);

	dispose_ht_seen_words();

	if (dbg > 1)
		printf("QRP unique subwords: %d\n", ctx->substrings);

	return 0;		/* All done for this step */
}

/*
 * qrp_step_compute
 *
 * Compute table.
 */
static gint qrp_step_compute(struct qrp_context *ctx)
{
	guchar *table = NULL;
	gint slots;
	gint bits;
	GSList *l;
	gint upper_thresh;
	gint hashed = 0;
	gint filled = 0;
	gint conflict_ratio;
	gboolean full = FALSE;

	/*
	 * Build QR table: we try to achieve a minimum sparse ratio (empty
	 * slots filled with INFINITY) whilst limiting the size of the table,
	 * so we incrementally try and double the size until we reach the maximum.
	 */

	bits = MIN_TABLE_BITS + ctx->seqno;
	slots = 1 << bits;

	upper_thresh = MIN_SPARSE_RATIO * slots;

	table = g_malloc(slots);
	memset(table, LOCAL_INFINITY, slots);

	for (l = ctx->sl_substrings; l; l = l->next) {
		guchar *word = (guchar *) l->data;
		guint idx = qrp_hash(word, bits);

		hashed++;

		if (table[idx] == LOCAL_INFINITY) {
			table[idx] = 1;
			filled++;
			if (dbg > 7)
				printf("QRP added subword: \"%s\"\n", word);
		}

		if (bits < MAX_TABLE_BITS && 100*filled > upper_thresh) {
			full = TRUE;
			break;
		}
	}

	conflict_ratio =
		(gint) (100.0 * (ctx->substrings - filled) / ctx->substrings);

	if (dbg > 1)
		printf("QRP [seqno=%d] size=%d, filled=%d, hashed=%d, "
			"ratio=%d%%, conflicts=%d%%%s\n",
			ctx->seqno, slots, filled, hashed,
			(gint) (100.0 * filled / slots),
			conflict_ratio, full ? " FULL" : "");

	/*
	 * Decide whether we can keep the table we've just built.
	 */

	if (
		bits >= MAX_TABLE_BITS ||
		(!full && conflict_ratio < MAX_CONFLICT_RATIO)
	) {
		if (dbg)
			printf("QRP final table size: %d bytes\n", slots);

		/*
		 * If we had already a table, compare it to the one we just built.
		 * If they are identical, discard the new one.
		 */

		if (
			routing_table &&
			routing_table->slots == slots &&
			0 == memcmp(routing_table->arena, table, slots)
		) {
			if (dbg)
				printf("no change in QRP table\n");
			g_free(table);
			return -1;			/* Abort processing */
		}

		/* 
		 * OK, we keep the table.
		 */

		ctx->table = table;
		ctx->slots = slots;

		return 0;		/* Done! */
	}

	g_free(table);

	return 1;			/* More work required */
}

// XXX
static void compressed(gpointer arg, gboolean cancelled)
{
	printf("GOT QRP COMPRESSED CALLBACK (%s)!\n",
		cancelled ? "cancelled" : "OK");
}

/*
 * qrp_step_install
 *
 * Install the routing table we've built.
 */
static gint qrp_step_install(struct qrp_context *ctx)
{
	if (routing_table)
		qrt_unref(routing_table);

	/*
	 * Install new routing table and notify the nodes that it has changed.
	 */

	routing_table = qrt_create(ctx->table, ctx->slots, LOCAL_INFINITY);
	node_qrt_changed();

// XXX
	{
		struct routing_patch *rp = qrt_diff_4(NULL, routing_table);
		qrt_patch_compress(rp, compressed, 0);
	}

	return 0;			/* Done! */
}

/*
 * qrp_compute_timer
 */
static gboolean qrp_compute_timer(gpointer arg)
{
	struct qrp_context *ctx = (struct qrp_context *) arg;
	gint ret;
	struct timeval start, end;

	g_assert(ctx->magic == QRP_MAGIC);

	if (dbg)
		gettimeofday(&start, NULL);

	switch (ctx->step) {
	case QRP_STEP_SUBSTRING:
		ret = qrp_step_substring(ctx);
		break;
	case QRP_STEP_COMPUTE:
		ret = qrp_step_compute(ctx);
		break;
	case QRP_STEP_INSTALL:
		ret = qrp_step_install(ctx);
		break;
	default:
		ret = -1;
		g_assert(0);
	}

	if (dbg) {
		gettimeofday(&end, NULL);

		printf("QRP computation step #%d.%d took %d msec\n",
			ctx->step, ctx->seqno,
			(gint) ((end.tv_sec - start.tv_sec) * 1000 +
				(end.tv_usec - start.tv_usec) / 1000));
	}

	/*
	 * Analyze returned value:
	 */

	switch (ret) {
	case -1:						/* Error, abort processing */
		break;
	case 0:							/* Completed, move to next step */
		if (ctx->step == QRP_STEP_LAST)
			break;
		ctx->seqno = 0;
		ctx->step++;
		return TRUE;
		/* NOTREACHED */
	case 1:							/* More work needed for this step */
		ctx->seqno++;
		return TRUE;
	default:
		g_assert(0);				/* Bug in processing routine */
	}
		
	qrp_context_free(ctx);
	qrp_ctx = NULL;

	return FALSE;
}

/*
 * qrp_close
 *
 * Called at servent shutdown to reclaim all the memory.
 */
void qrp_close(void)
{
	if (routing_table)
		qrt_unref(routing_table);
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

