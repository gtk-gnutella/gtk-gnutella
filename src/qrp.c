/*
 * $Id$
 *
 * Copyright (c) 2002-2003, Raphael Manfredi
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

#include "gnutella.h"

#include <stdio.h>					/* For qrt_dump() */
#include <ctype.h>
#include <math.h>
#include <zlib.h>

#include "qrp.h"
#include "routing.h"				/* For message_set_muid() */
#include "gmsg.h"
#include "nodes.h"					/* For NODE_IS_WRITABLE() */
#include "gnet_stats.h"

RCSID("$Id$");

#define MIN_SPARSE_RATIO	1		/* At most 1% of slots used */
#define MAX_CONFLICT_RATIO	20		/* At most 20% of insertion conflicts */
#define LOCAL_INFINITY		2		/* We're one hop away, so 2 is infinity */
#define MIN_TABLE_BITS		16		/* 64 KB */
#define MAX_TABLE_BITS		21		/* 2 MB */

#define MAX_TABLE_SIZE		(1 << MAX_TABLE_BITS)

#define QRP_ROUTE_MAGIC		0x30011ab1

/*
 * A routing table.
 *
 * If we are a leaf node, we send our routing table to neighbours.  We keep
 * a pointer to the previous table sent, so that we can determine the "patch"
 * with the current table in case our library is regenerated.
 */
struct routing_table {
	guint32 magic;
	gint refcnt;			/* Amount of references */
	gint generation;		/* Generation number */
	guint8 *arena;			/* Where table starts */
	gint slots;				/* Amount of slots in table */
	gint infinity;			/* Value for "infinity" */
	guint32 client_slots;	/* Only for received tables, for shrinking ctrl */
	gint bits;				/* Amount of bits used in table size (received) */
	gint set_count;			/* Amount of slots set in table (received) */
	gint fill_ratio;		/* 100 * fill ratio for table (received) */
	gint pass_throw;		/* Query must pass a d100 throw to be forwarded */
	gchar *digest;			/* SHA1 digest of the whole table (atom) */
	gboolean compacted;
};

/*
 * A routing table patch.
 */
struct routing_patch {
	gint refcnt;					/* Amount of references */
	guint8 *arena;
	gint size;						/* Number of entries in table */
	gint len;						/* Length of arena in bytes */
	gint entry_bits;
	gboolean compressed;
};

static char_map_t qrp_map;
static struct routing_table *routing_table = NULL;	/* Our table */
static struct routing_patch *routing_patch = NULL;	/* Against empty table */
static gint generation = 0;

static gchar qrp_tmp[4096];

static void qrt_compress_cancel_all(void);
static void qrt_patch_compute(void);
static guint32 qrt_dump(FILE *f, struct routing_table *rt, gboolean full);

/*
 * qrp_hashcode
 *
 * Compute standard QRP hash code on 32 bits.
 */
inline guint32 qrp_hashcode(gchar *x)
{
	guint32 xor = 0;		/* The running total */
	gint j = 0;  			/* The byte position in xor */
	guchar c;

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
		guint32 b = (c >= 'A' && c <= 'Z') ? (c + 'a' - 'A') : c; 
		xor ^= b << (j << 3);
		j = (j + 1) & 0x3;
	}

	/*
	 * Multiplication-based hash function.  See Chapter 12.3.2. of CLR.
	 */

	return xor * A_INT;
}

/*
 * QRP_HASH_RESTRICT
 *
 * Restrict given hashcode to be a suitable index on `bits' bits.
 */
#define QRP_HASH_RESTRICT(hashcode, bits) \
	((guint32) (hashcode) >> (32 - (gint) (bits)))

/*
 * qrp_hash		-- for tests only
 *
 * The hashing function, defined by the QRP specifications.
 * Naturally, everyone must use the SAME hashing function!
 */
static guint32 qrp_hash(gchar *x, gint bits)
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
	g_assert(qrp_hash("NDFLalem", 16) == 37658);
	g_assert(qrp_hash("7777a88a8a8a8", 10) == 342);
}

/***
 *** Routing table management.
 ***/

/*
 * RT_SLOT_READ
 *
 * Access slot #`s' in arena `a'.
 * Table is compacted so that slot #6 is bit 1 of byte 0.
 *
 * In general:
 *
 *	byte = slot >> 3;
 *	bit = 7 - (slot & 0x7);
 *  value = arena[byte] & (1 << bit)
 *
 * Returns the TRUE if there is something present, FALSE otherwise.
 */
#define RT_SLOT_READ(a,s) ((a)[(s) >> 3] & (1 << (7 - ((s) & 0x7))))

/*
 * RT_SLOT_SET
 *
 * Set slot #`s' in arena `a'.
 */
#define RT_SLOT_SET(a,s) \
	do { (a)[(s) >> 3] |= (1 << (7 - ((s) & 0x7))); } while (0)

/*
 * RT_SLOT_CLEAR
 *
 * Clear slot #`s' in arena `a'.
 */
#define RT_SLOT_CLEAR(a,s) \
	do { (a)[(s) >> 3] &= ~(1 << (7 - ((s) & 0x7))); } while (0)

/*
 * qrt_compact
 *
 * Compact routing table in place so that only one bit of information is used
 * per entry, reducing memory requirements by a factor of 8.
 */
static void qrt_compact(struct routing_table *rt)
{
	gint nsize;				/* New table size */
	gchar *narena;			/* New arena */
	gint i;
	guint mask;
	guchar *p;
	guchar *q;
	guint32 token = 0;

	g_assert(rt);
	g_assert(rt->slots >= 8);
	g_assert(0 == (rt->slots & 0x7));	/* Multiple of 8 */
	g_assert(!rt->compacted);

	if (dbg > 4) {
		printf("Dumping QRT before compaction...\n");
		token = qrt_dump(stdout, rt, dbg > 20);
	}

	nsize = rt->slots / 8;
	narena = g_malloc0(nsize);
	q = (guchar *) narena + (nsize - 1);

	/*
	 * Because we're compacting an ultranode -> leafnode routing table,
	 * items in the original table that are not "infinity" are replaced
	 * by 1 bits (i.e. present).  A keyword is either present or not.
	 *
	 * Compaction of byte 0 (the first byte) is done in bit 7.
	 * Compaction of byte 7 (the 8th byte) is done in bit 0.
	 *
	 * Therefore, the sequence of bits mimics the slots in the original table.
	 */

	for (mask = 0, i = rt->slots - 1, p = &rt->arena[i]; i >= 0; i--, p--) {
		if (*p != rt->infinity)
			mask |= 0x80;				/* Bit set to indicates presence */
		if (0 == (i & 0x7)) {			/* Reached "bit 0" */
			*q-- = mask;
			mask = 0;
		} else
			mask >>= 1;					/* Starting from end of table */
	}

	g_assert((gchar *) (q+1) == narena);/* Filled 1st byte at last iteration */

	/*
	 * Install new compacted arena in place of the non-compacted one.
	 */

	g_free(rt->arena);
	rt->arena = (guchar *) narena;
	rt->compacted = TRUE;

	if (dbg > 4) {
		guint32 token2;
		printf("Dumping QRT after compaction...\n");
		token2 = qrt_dump(stdout, rt, dbg > 20);

		if (token2 != token)
			g_warning("BUG in QRT compaction!");
	}
}

/*
 * qrt_sha1
 *
 * Computes the SHA1 of a compacted routing table.
 * Returns a pointer to static data.
 */
static gchar *qrt_sha1(struct routing_table *rt)
{
	gint i;
	gint bytes;
	guint8 vector[8];
	SHA1Context ctx;
	static gchar digest[SHA1HashSize];
	guint8 *p;

	g_assert(rt->compacted);

	bytes = rt->slots / 8;
	SHA1Reset(&ctx);

	for (i = 0, p = rt->arena; i < bytes; i++) {
		gint j;
		guint8 mask;
		guint8 value = *p++;

		for (j = 0, mask = 0x80; j < 8; j++, mask >>= 1)
			vector[j] = (value & mask) ? 1 : 0;		/* 1 for presence */

		SHA1Input(&ctx, vector, sizeof(vector));
	}

	SHA1Result(&ctx, (guint8 *) digest);

	return digest;
}

/*
 * qrt_patch_ref
 *
 * Get a new reference on a routing patch.
 */
static struct routing_patch *qrt_patch_ref(struct routing_patch *rp)
{
	rp->refcnt++;
	return rp;
}

/*
 * qrt_patch_free
 *
 * Free routing table patch.
 */
static void qrt_patch_free(struct routing_patch *rp)
{
	g_free(rp->arena);
	wfree(rp, sizeof(*rp));
}

/*
 * qrt_patch_unref
 *
 * Remove a reference on a routing patch, freeing it when no more ref remains.
 */
static void qrt_patch_unref(struct routing_patch *rp)
{
	g_assert(rp->refcnt > 0);

	if (--rp->refcnt == 0)
		qrt_patch_free(rp);
}

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

	g_assert(old == NULL || old->magic == QRP_ROUTE_MAGIC);
	g_assert(old == NULL || old->compacted);
	g_assert(new->magic == QRP_ROUTE_MAGIC);
	g_assert(new->compacted);
	g_assert(old == NULL || new->slots == old->slots);

	rp = walloc(sizeof(*rp));
	rp->refcnt = 1;
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
		 * In our compacted table, set bits indicate presence.
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
			else {
				*pp++ = v;
				v = 0;
			}
		}
	}

	g_assert(np == (new->arena + new->slots / 8));
	g_assert(op == NULL || op == (old->arena + old->slots / 8));
	g_assert(pp == (rp->arena + rp->len));

	return rp;
}

/*
 * Compression task context.
 */

#define QRT_COMPRESS_MAGIC	0x45afbb01
#define QRT_TICK_CHUNK		256			/* Chunk size per tick */

struct qrt_compress_context {
	gint magic;						/* Magic number */
	struct routing_patch *rp;		/* Routing table being compressed */
	zlib_deflater_t *zd;			/* Incremental deflater */
	bgdone_cb_t usr_done;			/* User-defined callback */
	gpointer usr_arg;				/* Arg for user-defined callback */
};

static GSList *sl_compress_tasks = NULL;

/*
 * qrt_compress_free
 *
 * Free compression context.
 */
static void qrt_compress_free(gpointer u)
{
	struct qrt_compress_context *ctx = (struct qrt_compress_context *) u;

	g_assert(ctx->magic == QRT_COMPRESS_MAGIC);

	if (ctx->zd)
		zlib_deflater_free(ctx->zd, TRUE);

	wfree(ctx, sizeof(*ctx));
}

/*
 * qrt_step_compress
 *
 * Perform incremental compression.
 */
static bgret_t qrt_step_compress(gpointer h, gpointer u, gint ticks)
{
	struct qrt_compress_context *ctx = (struct qrt_compress_context *) u;
	gint ret;
	gint chunklen;
	gint status = 0;

	g_assert(ctx->magic == QRT_COMPRESS_MAGIC);

	chunklen = ticks * QRT_TICK_CHUNK;

	if (dbg > 4)
		printf("QRP qrt_step_compress: ticks = %d => chunk = %d bytes\n",
			ticks, chunklen);

	ret = zlib_deflate(ctx->zd, chunklen);

	switch (ret) {
	case -1:					/* Error occurred */
		status = -1;
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
		ctx->zd = NULL;
		goto done;
		/* NOTREACHED */
	case 1:						/* More work required */
		break;
	default:
		g_assert(0);			/* Bug in zlib_deflate() */
	}

	return BGR_MORE;		/* More work required */

done:
	bg_task_exit(h, status);

	return BGR_ERROR;		/* Not reached */
}

/*
 * qrt_patch_compress_done
 *
 * Called when the compress task is finished.
 *
 * This is really a wrapper on top of the user-supplied "done" callback
 * which lets us remove the task from the list.
 */
static void qrt_patch_compress_done(
	gpointer h, gpointer u, bgstatus_t status, gpointer arg)
{
	struct qrt_compress_context *ctx = (struct qrt_compress_context *) u;

	g_assert(ctx->magic == QRT_COMPRESS_MAGIC);

	/*
	 * When status is BGS_KILLED, the task is being cancelled.
	 * This means we're iterating on the `sl_compress_tasks' list
	 * so don't alter it.
	 *		--RAM, 29/01/2003
	 */

	if (status != BGS_KILLED)
		sl_compress_tasks = g_slist_remove(sl_compress_tasks, h);

	(*ctx->usr_done)(h, u, status, ctx->usr_arg);
}

/*
 * qrt_patch_compress
 *
 * Compress routing patch inplace (asynchronously).
 * When it's done, invoke callback with specified argument.
 *
 * Returns handle of the compressing task.
 */
static gpointer qrt_patch_compress(
	struct routing_patch *rp,
	bgdone_cb_t done_callback, gpointer arg)
{
	struct qrt_compress_context *ctx;
	zlib_deflater_t *zd;
	gpointer task;
	bgstep_cb_t step = qrt_step_compress;

	zd = zlib_deflater_make(rp->arena, rp->len, 9);

	if (zd == NULL) {
		(*done_callback)(NULL, NULL, BGS_ERROR, arg);
		return NULL;
	}

	/*
	 * Because compression is possibly a CPU-intensive operation, it
	 * is dealt with a background task that will be scheduled at regular
	 * intervals.
	 */

	ctx = walloc0(sizeof(*ctx));
	ctx->magic = QRT_COMPRESS_MAGIC;
	ctx->rp = rp;
	ctx->zd = zd;
	ctx->usr_done = done_callback;
	ctx->usr_arg = arg;

	gnet_prop_set_guint32_val(PROP_QRP_PATCH_RAW_LENGTH, (guint32) rp->len);

	task = bg_task_create("QRP patch compression",
		&step, 1, ctx, qrt_compress_free, qrt_patch_compress_done, NULL);

	if (task != NULL)
		sl_compress_tasks = g_slist_prepend(sl_compress_tasks, task);

	return task;
}

/*
 * qrt_create
 *
 * Create a new query routing table, with supplied `arena' and `slots'.
 * The value used for infinity is given as `max'.
 */
static struct routing_table *qrt_create(gchar *arena, gint slots, gint max)
{
	struct routing_table *rt;

	rt = walloc(sizeof(*rt));

	rt->magic = QRP_ROUTE_MAGIC;
	rt->arena = (guchar *) arena;
	rt->slots = slots;
	rt->generation = generation++;
	rt->refcnt = 1;
	rt->infinity = max;
	rt->compacted = FALSE;
	rt->digest = NULL;

	gnet_prop_set_guint32_val(PROP_QRP_GENERATION, (guint32) rt->generation);

	qrt_compact(rt);

	rt->digest = atom_sha1_get(qrt_sha1(rt));

	if (dbg > 1)
		printf("QRP ready: gen=%d, slots=%d, SHA1=%s\n",
			rt->generation, rt->slots, sha1_base32(rt->digest));

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

	rt->magic = 0;				/* Prevent accidental reuse */

	if (rt->digest)
		atom_sha1_free(rt->digest);
	g_free(rt->arena);

	wfree(rt, sizeof(*rt));
}

/*
 * qrt_get_table
 *
 * Returns the query routing table, NULL if not computed yet.
 */
gpointer qrt_get_table(void)
{
	return routing_table;
}

/*
 * qrt_ref
 *
 * Get a new reference on the query routing table.
 * Returns its argument.
 */
gpointer qrt_ref(gpointer obj)
{
	struct routing_table *rt = (struct routing_table *) obj;

	g_assert(obj);
	g_assert(rt->magic == QRP_ROUTE_MAGIC);

	rt->refcnt++;
	return obj;
}

/*
 * qrt_unref
 *
 * Remove one reference to query routing table.
 * When the last reference is removed, the table is freed.
 */
void qrt_unref(gpointer obj)
{
	struct routing_table *rt = (struct routing_table *) obj;

	g_assert(obj);
	g_assert(rt->magic == QRP_ROUTE_MAGIC);
	g_assert(rt->refcnt > 0);

	if (--rt->refcnt == 0)
		qrt_free(rt);
}

/*
 * qrt_get_info
 *
 * Returns information about query routing table.
 */
void qrt_get_info(gpointer obj, qrt_info_t *qi)
{
	struct routing_table *rt = (struct routing_table *) obj;

	g_assert(obj);
	g_assert(rt->magic == QRP_ROUTE_MAGIC);
	g_assert(rt->refcnt > 0);

	qi->slots = rt->slots;
	qi->generation = rt->generation;
	qi->fill_ratio = rt->fill_ratio;
	qi->pass_throw = rt->pass_throw;
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
	gchar *arena;
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
		 * Also, all words strictly smaller than QRP_MIN_WORD_LENGTH are
		 * skipped.
		 */

		if (word[1] == '\0' || word[2] == '\0')		/* Handles lengths 1 & 2 */
			continue;

		if (QRP_MIN_WORD_LENGTH > 3 && strlen(word) < QRP_MIN_WORD_LENGTH)
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

	/*
	 * If we have a SHA1 for this file, add it to the table as well.
	 */

	if (sha1_hash_available(sf)) {
		gchar *key = g_strdup_printf("urn:sha1:%s",
			sha1_base32(sf->sha1_digest));

		if (NULL == g_hash_table_lookup(ht_seen_words, key))
			g_hash_table_insert(ht_seen_words, key, GINT_TO_POINTER(1));
		else
			g_free(key);
	}
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
	gchar *word = key;
	gint len;

#define INSERT do { \
	if (!g_hash_table_lookup(u->unique, (gconstpointer) word)) {	\
		gchar *newword = g_strdup(word);							\
		g_hash_table_insert(u->unique, newword, (gpointer) 1);		\
		u->head = g_slist_prepend(u->head, newword);				\
		u->count++;													\
	}																\
} while (0)

	/*
	 * Special-case urn:sha1 entries: we insert them as a whole!
	 */

	if (word[0] == 'u' && 0 == strncasecmp(word, "urn:sha1:", 9)) {
		INSERT;
		return;
	}

	/*
	 * Add all unique (i.e. not already seen) substrings from word, all
	 * anchored at the start, whose length range from 3 to the word length.
	 */

	for (len = strlen(word); len >= 3; len--) {
		guchar c = word[len];
		word[len] = '\0';				/* Truncate word */
		INSERT;
		word[len] = c;
	}

#undef INSERT
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
	GSList *sl_substrings;		/* List of all substrings */
	gint substrings;			/* Amount of substrings */
	gchar *table;				/* Computed routing table */
	gint slots;					/* Amount of slots in table */
};

static gpointer qrp_comp = NULL;		/* Background computation handle */

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
 * qrp_context_free
 *
 * Free query routing table computation context.
 */
static void qrp_context_free(gpointer p)
{
	struct qrp_context *ctx = (struct qrp_context *) p;
	GSList *l;

	g_assert(ctx->magic == QRP_MAGIC);

	qrp_comp = NULL;		/* If we're called, the task is being terminated */

	/*
	 * The `ht_seen_words' table is not really part of our task context,
	 * but was filled only so that the task could perform its work.
	 * XXX put it in context, and clear global once inserted.
	 */

	if (ht_seen_words)
		dispose_ht_seen_words();

	for (l = ctx->sl_substrings; l; l = l->next)
		g_free(l->data);
	g_slist_free(ctx->sl_substrings);

	if (ctx->table)
		g_free(ctx->table);

	wfree(ctx, sizeof(*ctx));
}

/*
 * qrp_cancel_computation
 *
 * Cancel current computation, if any.
 */
static void qrp_cancel_computation(void)
{
	qrt_compress_cancel_all();

	if (qrp_comp) {
		bg_task_cancel(qrp_comp);
		qrp_comp = NULL;
	}
}

/*
 * qrp_step_substring
 *
 * Compute all the substrings we need to insert.
 */
static bgret_t qrp_step_substring(gpointer h, gpointer u, gint ticks)
{
	struct qrp_context *ctx = (struct qrp_context *) u;

	g_assert(ctx->magic == QRP_MAGIC);
	g_assert(ht_seen_words != NULL);	/* XXX Already in computation */

	ctx->sl_substrings = unique_substrings(ht_seen_words, &ctx->substrings);

	dispose_ht_seen_words();

	if (dbg > 1)
		printf("QRP unique subwords: %d\n", ctx->substrings);

	return BGR_NEXT;		/* All done for this step */
}

/*
 * qrt_eq
 *
 * Compare possibly compacted table `rt' with expanded table arena `arena'
 * having `slots' slots.
 *
 * Returns whether tables are identical.
 */
static gboolean qrt_eq(struct routing_table *rt, gchar *arena, gint slots)
{
	gint i;

	g_assert(rt != NULL);
	g_assert(arena != NULL);
	g_assert(slots > 0);

	if (rt->slots != slots)
		return FALSE;

	if (!rt->compacted)
		return 0 == memcmp(rt->arena, arena, slots);

	for (i = 0; i < slots; i++) {
		gboolean s1 = RT_SLOT_READ(rt->arena, i);
		gboolean s2 = arena[i] != LOCAL_INFINITY;
		if (!s1 != !s2)
			return FALSE;
	}

	return TRUE;
}

/*
 * qrp_step_compute
 *
 * Compute table.
 */
static bgret_t qrp_step_compute(gpointer h, gpointer u, gint ticks)
{
	struct qrp_context *ctx = (struct qrp_context *) u;
	gchar *table = NULL;
	gint slots;
	gint bits;
	GSList *l;
	gint upper_thresh;
	gint hashed = 0;
	gint filled = 0;
	gint conflict_ratio;
	gboolean full = FALSE;

	g_assert(ctx->magic == QRP_MAGIC);

	/*
	 * Build QR table: we try to achieve a minimum sparse ratio (empty
	 * slots filled with INFINITY) whilst limiting the size of the table,
	 * so we incrementally try and double the size until we reach the maximum.
	 */

	bits = MIN_TABLE_BITS + bg_task_seqno(h);
	slots = 1 << bits;

	upper_thresh = MIN_SPARSE_RATIO * slots;

	table = g_malloc(slots);
	memset(table, LOCAL_INFINITY, slots);

	for (l = ctx->sl_substrings; l; l = l->next) {
		gchar *word = (gchar *) l->data;
		guint idx = qrp_hash(word, bits);

		hashed++;

		if (table[idx] == LOCAL_INFINITY) {
			table[idx] = 1;
			filled++;
			if (dbg > 7)
				printf("QRP added subword: \"%s\"\n", word);
		}

		/*
		 * We won't be removing the slot we already filled, so if we
		 * already filled more than our threshold ratio, there's no
		 * need to continue: the table is full and we must double the
		 * size -- unless we've reached our maximum size.
		 */

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
			bg_task_seqno(h), slots, filled, hashed,
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

		gnet_prop_set_guint32_val(PROP_QRP_SLOTS, (guint32) slots);
		gnet_prop_set_guint32_val(PROP_QRP_SLOTS_FILLED, (guint32) filled);
		gnet_prop_set_guint32_val(PROP_QRP_HASHED_KEYWORDS, (guint32) hashed);
		gnet_prop_set_guint32_val(PROP_QRP_FILL_RATIO,
			(guint32) (100.0 * filled / slots));
		gnet_prop_set_guint32_val(PROP_QRP_CONFLICT_RATIO,
			(guint32) conflict_ratio);

		/*
		 * If we had already a table, compare it to the one we just built.
		 * If they are identical, discard the new one.
		 *
		 * Can't do a direct memcmp() on the tables though, as the routing
		 * table arena may be compressed and our table is not.
		 */

		if (routing_table && qrt_eq(routing_table, table, slots)) {
			if (dbg)
				printf("no change in QRP table\n");
			g_free(table);
			bg_task_exit(h, 0);	/* Abort processing */
		}

		/* 
		 * OK, we keep the table.
		 */

		ctx->table = table;
		ctx->slots = slots;

		return BGR_NEXT;		/* Done! */
	}

	g_free(table);

	return BGR_MORE;			/* More work required */
}

/*
 * qrp_step_install
 *
 * Install the routing table we've built.
 */
static bgret_t qrp_step_install(gpointer h, gpointer u, gint ticks)
{
	struct qrp_context *ctx = (struct qrp_context *) u;
	guint32 elapsed;

	g_assert(ctx->magic == QRP_MAGIC);


	/*
	 * Install new routing table and notify the nodes that it has changed.
	 */

	if (routing_table != NULL)
		qrt_unref(routing_table);

	routing_table = qrt_create(ctx->table, ctx->slots, LOCAL_INFINITY);
	ctx->table = NULL;		/* Don't free table when freeing context */

	/*
	 * Now that a new routing table is available, we'll need a new routing
	 * patch against an empty table, to send to new connections.
	 */

	if (routing_patch != NULL) {
		qrt_patch_unref(routing_patch);
		routing_patch = NULL;
	}

	elapsed = (guint32) time(NULL) - qrp_timestamp;
	gnet_prop_set_guint32_val(PROP_QRP_COMPUTATION_TIME, elapsed);

	qrt_patch_compute();				/* Default patch, done asynchronously */
	node_qrt_changed(routing_table);

	return BGR_DONE;		/* Done! */
}

static bgstep_cb_t qrp_compute_steps[] = {
	qrp_step_substring,
	qrp_step_compute,
	qrp_step_install,
};

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
	struct qrp_context *ctx;

	/*
	 * Because QRP computation is possibly a CPU-intensive operation, it
	 * is dealt with as a coroutine that will be scheduled at regular
	 * intervals.
	 */

	ctx = walloc0(sizeof(*ctx));
	ctx->magic = QRP_MAGIC;

	gnet_prop_set_guint32_val(PROP_QRP_TIMESTAMP, (guint32) time(NULL));

	qrp_comp = bg_task_create("QRP computation",
		qrp_compute_steps,
		sizeof(qrp_compute_steps) / sizeof(qrp_compute_steps[0]),
		ctx,
		qrp_context_free,
		NULL, NULL);
}

/***
 *** Computation of the routing patch against an empty table.
 ***/

#define QRT_PATCH_MAGIC	0x9a1c4939

struct qrt_patch_context {
	guint32 magic;
	struct routing_patch *rp;	/* Routing patch being compressed */
	gpointer compress;			/* The compression task */
};

typedef void (*qrt_patch_computed_cb_t)(gpointer arg, struct routing_patch *rp);

struct patch_listener_info {
	qrt_patch_computed_cb_t callback;
	gpointer arg;
};

static struct qrt_patch_context *qrt_patch_ctx = NULL;
static GSList *qrt_patch_computed_listeners = NULL;


/*
 * qrt_patch_computed
 *
 * Callback invoked when the routing patch is computed.
 */
static void qrt_patch_computed(
	gpointer h, gpointer u, bgstatus_t status, gpointer arg)
{
	struct qrt_patch_context *ctx = (struct qrt_patch_context *) arg;
	GSList *l;

	g_assert(ctx->magic == QRT_PATCH_MAGIC);
	g_assert(ctx == qrt_patch_ctx);
	g_assert(routing_patch == NULL);

	if (dbg > 2)
		printf("QRP global default patch computed (status = %d)\n", status);

	qrt_patch_ctx = NULL;			/* Indicates that we're done */

	if (status == BGS_OK) {
		time_t now = time(NULL);
		guint32 elapsed;

		routing_patch = ctx->rp;

		elapsed = (guint32) now - qrp_patch_timestamp;
		gnet_prop_set_guint32_val(PROP_QRP_PATCH_COMPUTATION_TIME, elapsed);
		gnet_prop_set_guint32_val(PROP_QRP_PATCH_LENGTH,
			(guint32) ctx->rp->len);
		gnet_prop_set_guint32_val(PROP_QRP_PATCH_COMP_RATIO,
			(guint32) (100.0 * (qrp_patch_raw_length - qrp_patch_length) /
				MAX(qrp_patch_raw_length, 1)));
	}

	ctx->magic = 0;					/* Prevent accidental reuse */

	wfree(ctx, sizeof(*ctx));

	/*
	 * Tell all our listeners that the routing patch is now available, or
	 * that an error occurred.
	 */

	for (l = qrt_patch_computed_listeners; l; l = l->next) {
		struct patch_listener_info *pi = l->data;
		(*pi->callback)(pi->arg, routing_patch);	/* NULL indicates failure */
		wfree(pi, sizeof(*pi));
	}

	g_slist_free(qrt_patch_computed_listeners);
	qrt_patch_computed_listeners = NULL;
}

/*
 * qrt_patch_computed_add_listener
 *
 * Record listener to callback with given argument when the default routing
 * patch will be ready.
 */
static gpointer qrt_patch_computed_add_listener(
	qrt_patch_computed_cb_t cb, gpointer arg)
{
	struct patch_listener_info *pi;

	/*
	 * `qrt_patch_ctx' may be NULL: we may have finished a rescan, and
	 * be in the process of updating the routing table, but not yet in
	 * the process of computing the patch.
	 *
	 * That's alright, just register the listener.
	 */

	pi = walloc(sizeof(*pi));

	pi->callback = cb;
	pi->arg = arg;

	qrt_patch_computed_listeners =
		g_slist_prepend(qrt_patch_computed_listeners, pi);

	return pi;
}

/*
 * qrt_patch_computed_remove_listener
 *
 * Remove recorded listener.
 */
static void qrt_patch_computed_remove_listener(gpointer handle)
{
	g_assert(qrt_patch_computed_listeners != NULL);

	qrt_patch_computed_listeners =
		g_slist_remove(qrt_patch_computed_listeners, handle);
}

/*
 * qrt_patch_cancel_compute
 *
 * Cancel computation.
 */
static void qrt_patch_cancel_compute(void)
{
	gpointer comptask;

	g_assert(qrt_patch_ctx != NULL);

	comptask = qrt_patch_ctx->compress;

	bg_task_cancel(comptask);
	sl_compress_tasks = g_slist_remove(sl_compress_tasks, comptask);

	g_assert(qrt_patch_ctx == NULL);	/* qrt_patch_computed() called! */
	g_assert(qrt_patch_computed_listeners == NULL);
}

/*
 * qrt_patch_compute
 *
 * Launch asynchronous computation of the default routing patch.
 */
static void qrt_patch_compute(void)
{
	struct qrt_patch_context *ctx;

	g_assert(qrt_patch_ctx == NULL);	/* No computation active */

	gnet_prop_set_guint32_val(PROP_QRP_PATCH_TIMESTAMP, (guint32) time(NULL));

	qrt_patch_ctx = ctx = walloc(sizeof(*ctx));

	ctx->magic = QRT_PATCH_MAGIC;
	ctx->rp = qrt_diff_4(NULL, routing_table);
	ctx->compress = qrt_patch_compress(ctx->rp, qrt_patch_computed, ctx);
}

/*
 * qrt_compress_cancel_all
 *
 * Cancel all running compression coroutines.
 */
static void qrt_compress_cancel_all(void)
{
	GSList *l;

	if (qrt_patch_ctx != NULL)
		qrt_patch_cancel_compute();

	for (l = sl_compress_tasks; l; l = l->next)
		bg_task_cancel(l->data);

	g_slist_free(sl_compress_tasks);
	sl_compress_tasks = NULL;
}

/***
 *** Sending of the QRP messages.
 ***/

/*
 * qrp_send_reset
 *
 * Send the RESET message, which must be sent before the PATCH sequence
 * to size the table.
 */
static void qrp_send_reset(struct gnutella_node *n, gint slots, gint infinity)
{
	struct gnutella_msg_qrp_reset m;

	g_assert(is_pow2(slots));
	g_assert(infinity > 0 && infinity < 256);

	message_set_muid(&m.header, GTA_MSG_QRP);

	m.header.function = GTA_MSG_QRP;
	m.header.ttl = 1;
	m.header.hops = 0;
	WRITE_GUINT32_LE(sizeof(m.data), m.header.size);

	m.data.variant = GTA_MSGV_QRP_RESET;
	WRITE_GUINT32_LE(slots, m.data.table_length);
	m.data.infinity = (guchar) infinity;

	gmsg_sendto_one(n, (gchar *) &m, sizeof(m));

	if (dbg > 4)
		printf("QRP sent RESET slots=%d, infinity=%d to %s\n",
			slots, infinity, node_ip(n));
}

/*
 * qrp_send_patch
 *
 * Send the PATCH message.  The patch payload data is made of the `len' bytes
 * starting at `buf'.
 */
static void qrp_send_patch(struct gnutella_node *n,
	gint seqno, gint seqsize, gboolean compressed, gint bits,
	gchar *buf, gint len)
{
	struct gnutella_msg_qrp_patch *m;
	gint msglen;
	gint paylen;

	g_assert(seqsize >= 1 && seqsize <= 255);
	g_assert(seqno >= 1 && seqno <= seqsize);

	/*
	 * Compute the overall message length.
	 *
	 * If the size is small enough, we'll be able to use a static buffer
	 * to create the message.
	 */

	msglen = sizeof(*m) + len;
	paylen = sizeof(m->data) + len;

	if (msglen <= sizeof(qrp_tmp))
		m = (struct gnutella_msg_qrp_patch *) qrp_tmp;
	else
		m = g_malloc(msglen);

	message_set_muid(&m->header, GTA_MSG_QRP);

	m->header.function = GTA_MSG_QRP;
	m->header.ttl = 1;
	m->header.hops = 0;
	WRITE_GUINT32_LE(paylen, m->header.size);

	m->data.variant = GTA_MSGV_QRP_PATCH;
	m->data.seq_no = seqno;
	m->data.seq_size = seqsize;
	m->data.compressor = compressed ? 0x1 : 0x0;
	m->data.entry_bits = bits;

	memcpy((gchar *) m + sizeof(*m), buf, len);

	gmsg_sendto_one(n, (gchar *) m, msglen);

	if ((gchar *) m != qrp_tmp)
		g_free(qrp_tmp);

	if (dbg > 4)
		printf("QRP sent PATCH #%d/%d (%d bytes) to %s\n",
			seqno, seqsize, len, node_ip(n));
}

/***
 *** Reception of the QRP messages.
 ***/

struct qrp_reset {
	guint32 table_length;
	guint8 infinity;
};

struct qrp_patch {
	guint8 seq_no;
	guint8 seq_size;
	guint8 compressor;
	guint8 entry_bits;
	guchar *data;			/* Points into node's message buffer */
	gint len;				/* Length of data pointed at by `data' */
};

/*
 * qrp_recv_reset
 *
 * Receive a RESET message and fill the `reset' structure with its payload.
 * Returns TRUE if we read the message OK.
 */
static gboolean qrp_recv_reset(struct gnutella_node *n, struct qrp_reset *reset)
{
	struct gnutella_qrp_reset *msg = (struct gnutella_qrp_reset *) n->data;

	g_assert(msg->variant == GTA_MSGV_QRP_RESET);

	if (n->size != sizeof(struct gnutella_qrp_reset)) {
		gnet_stats_count_dropped(n, MSG_DROP_BAD_SIZE);
		return FALSE;
	}

	READ_GUINT32_LE(msg->table_length, reset->table_length);
	reset->infinity = msg->infinity;

	return TRUE;
}

/*
 * qrp_recv_patch
 *
 * Receive a PATCH message and fill the `patch' structure with its payload.
 * Returns TRUE if we read the message OK.
 */
static gboolean qrp_recv_patch(struct gnutella_node *n, struct qrp_patch *patch)
{
	struct gnutella_qrp_patch *msg = (struct gnutella_qrp_patch *) n->data;

	g_assert(msg->variant == GTA_MSGV_QRP_PATCH);

	if (n->size <= sizeof(struct gnutella_qrp_patch)) {
		gnet_stats_count_dropped(n, MSG_DROP_BAD_SIZE);
		return FALSE;
	}

	patch->seq_no = msg->seq_no;
	patch->seq_size = msg->seq_size;
	patch->compressor = msg->compressor;
	patch->entry_bits = msg->entry_bits;

	patch->data = (guchar *) (msg + 1);		/* Data start after header info */
	patch->len = n->size - sizeof(struct gnutella_qrp_patch);

	g_assert(patch->len > 0);

	return TRUE;
}

/***
 *** Management of the updating sequence -- sending side.
 ***/

#define QRT_UPDATE_MAGIC	0x15afcc05
#define QRT_PATCH_LEN		512		/* Send 512 bytes at a time, if we can */
#define QRT_MAX_SEQSIZE		255		/* Maximum: 255 messages */
#define QRT_MAX_BANDWIDTH	1024	/* Max bandwidth if clogging occurs */

struct qrt_update {
	guint32 magic;
	struct gnutella_node *node;		/* Node for which we're sending */
	struct routing_patch *patch;	/* The patch to send */
	gint seqno;						/* Sequence number of next message (1..n) */
	gint seqsize;					/* Total amount of messages to send */
	gint offset;					/* Offset within patch */
	gpointer compress;				/* Compressing task (NULL = done) */
	gpointer listener;				/* Listener for default patch being ready */
	gint chunksize;					/* Amount to send within each PATCH */
	time_t last;					/* Time at which we sent the last batch */
	gint last_sent;					/* Amount sent during last batch */
	gboolean ready;					/* Ready for sending? */
	gboolean reset_needed;			/* Is the initial RESET needed? */
};

/*
 * qrt_compressed
 *
 * Callback invoked when the computed patch for a connection
 * has been compressed.
 */
static void qrt_compressed(
	gpointer h, gpointer u, bgstatus_t status, gpointer arg)
{
	struct qrt_update *qup = (struct qrt_update *) arg;
	struct routing_patch *rp;
	gint msgcount;

	g_assert(qup->magic == QRT_UPDATE_MAGIC);

	qup->compress = NULL;
	qup->ready = TRUE;

	if (status == BGS_ERROR) {		/* Error during processing */
		g_warning("could not compress query routing patch to send to %s",
			node_ip(qup->node));
		goto error;
	}

	if (!NODE_IS_WRITABLE(qup->node))
		goto error;

	/*
	 * If the computed patch for this connection is larger than the
	 * size of the default patch (against an empty table), send that
	 * one instead.  We'll need an extra RESET though.
	 */

	if (routing_patch != NULL && qup->patch->len > routing_patch->len) {
		if (dbg)
			g_warning("incremental query routing patch for node %s is %d "
				"bytes, bigger than the default patch (%d bytes) -- "
				"using latter",
				node_ip(qup->node), qup->patch->len, routing_patch->len);

		qrt_patch_unref(qup->patch);
		qup->patch = qrt_patch_ref(routing_patch);
		qup->reset_needed = TRUE;
	}

	/*
	 * Now that we know the final length of the (hopefully) compressed patch,
	 * determine how many messages we'll have to send.
	 *
	 * We have only 8 bits to store the sequence number, so we can't send more
	 * than 255 messages (numbering starts at 1).
	 */

	rp = qup->patch;
	qup->chunksize = 1 + rp->len / QRT_MAX_SEQSIZE;

	if (qup->chunksize < QRT_PATCH_LEN)
		qup->chunksize = QRT_PATCH_LEN;

	msgcount = rp->len / qup->chunksize;

	if (msgcount * qup->chunksize != rp->len)
		msgcount++;

	g_assert(msgcount <= QRT_MAX_SEQSIZE);

	/*
	 * Initialize sequence, then send a RESET message if needed.
	 */

	qup->seqno = 1;					/* Numbering starts at 1 */
	qup->seqsize = msgcount;

	if (qup->reset_needed)
		qrp_send_reset(qup->node,
			routing_table->slots, routing_table->infinity);

	return;

error:
	if (qup->patch != NULL)
		qrt_patch_unref(qup->patch);
	qup->patch = NULL;			/* Signal error to qrt_update_send_next() */
	return;
}

/*
 * qrt_patch_available
 *
 * Default global routing patch (the one against a NULL table) is now
 * available for consumption.
 *
 * If we get a NULL pointer, it means the computation was interrupted or
 * that an error occurred.
 */
static void qrt_patch_available(gpointer arg, struct routing_patch *rp)
{
	struct qrt_update *qup = (struct qrt_update *) arg;

	g_assert(qup->magic == QRT_UPDATE_MAGIC);

	if (dbg > 2)
		printf("QRP global routing patch %s (node %s)\n",
			rp == NULL ? "computation was cancelled" : "is now available",
			node_ip(qup->node));

	qup->listener = NULL;
	qup->patch = (rp == NULL) ? NULL : qrt_patch_ref(rp);

	qrt_compressed(NULL, NULL, rp == NULL ? BGS_ERROR : BGS_OK, qup);
}

/*
 * qrt_update_create
 *
 * Create structure keeping track of the table update.
 * Call qrt_update_send_next() to send the next patching message.
 *
 * `query_table' is the table that was fully propagated to that node already.
 * It can be NULL if no table was fully propagated yet.
 *
 * NB: we become owner of the routing_patch, and it will be freed when the
 * created handle is destroyed.
 *
 * Return opaque handle.
 */
gpointer qrt_update_create(struct gnutella_node *n, gpointer query_table)
{
	struct qrt_update *qup;
	gpointer old_table = query_table;

	g_assert(routing_table != NULL);

	/*
	 * If the old routing table and the new one do not have the same amount
	 * of slots, then we need to send the whole table again, meaning we'll
	 * need a RESET message to send the new table size.
	 */

	if (old_table != NULL) {
		struct routing_table *old = (struct routing_table *) old_table;

		g_assert(old->magic == QRP_ROUTE_MAGIC);

		if (old->slots != routing_table->slots) {
			if (dbg)
				g_warning("old QRT for %s had %d slots, new one has %d",
					node_ip(n), old->slots, routing_table->slots);
			old_table = NULL;
		}
	}

	qup = walloc0(sizeof(*qup));

	qup->magic = QRT_UPDATE_MAGIC;
	qup->node = n;
	qup->ready = FALSE;
	qup->reset_needed = (old_table == NULL);	/* RESET only the first time */

	if (old_table == NULL) {
		/*
		 * If routing_patch is not NULL, it is ready, no need to compute it.
		 * Otherwise, it means it is being computed, so enqueue a
		 * notification callback to know when it is ready.
		 */

		if (routing_patch != NULL) {
			if (dbg > 2)
				printf("QRP default routing patch is already there (node %s)\n",
					node_ip(n));

			qup->patch = qrt_patch_ref(routing_patch);
			qrt_compressed(NULL, NULL, BGS_OK, qup);
		} else {
			if (dbg > 2)
				printf("QRP must wait for routing patch (node %s)\n",
					node_ip(n));

			qup->listener =
				qrt_patch_computed_add_listener(qrt_patch_available, qup);
		}
	} else {
		/*
		 * The compression call may take a while, in the background.
		 * When compression is done, `qup->compress' will be set to NULL.
		 */

		qup->patch = qrt_diff_4(old_table, routing_table);
		qup->compress = qrt_patch_compress(qup->patch, qrt_compressed, qup);
	}

	return qup;
}

/*
 * qrt_update_free
 *
 * Free query routing update tracker.
 */
void qrt_update_free(gpointer handle)
{
	struct qrt_update *qup = (struct qrt_update *) handle;

	g_assert(qup->magic == QRT_UPDATE_MAGIC);

	if (qup->compress != NULL)
		bg_task_cancel(qup->compress);

	g_assert(qup->compress == NULL);	/* Reset by qrt_compressed() */

	if (qup->listener)
		qrt_patch_computed_remove_listener(qup->listener);

	qup->magic = 0;						/* Prevent accidental reuse */
	if (qup->patch)
		qrt_patch_unref(qup->patch);

	wfree(qup, sizeof(*qup));
}

/*
 * qrt_update_send_next
 *
 * Send the next batch of data.
 * Returns whether the routing should still be called.
 */
gboolean qrt_update_send_next(gpointer handle)
{
	struct qrt_update *qup = (struct qrt_update *) handle;
	time_t now;
	time_t elapsed;
	gint len;
	gint i;

	g_assert(qup->magic == QRT_UPDATE_MAGIC);

	if (!qup->ready)				/* Still compressing or waiting */
		return TRUE;

	if (qup->patch == NULL)			/* An error occurred */
		return FALSE;

	/*
	 * Make sure we don't exceed the maximum bandwidth allocated for
	 * the QRP messages if the connection start clogging, i.e. if some
	 * bytes accumulate in the TX queue.
	 */

	now = time(NULL);
	elapsed = now - qup->last;

	if (elapsed == 0)				/* We're called once every second */
		elapsed = 1;				/* So adjust */

	if (
		qup->last_sent / elapsed > QRT_MAX_BANDWIDTH &&
		NODE_MQUEUE_PENDING(qup->node)
	)
		return TRUE;

	/*
	 * We have to send another message(s).
	 *
	 * To flush the QRT patch as quickly as possible, we can send up to
	 * 5 messages in a row here.  We'll stop if the queue starts to fill up.
	 */

	for (qup->last_sent = 0, i = 0; i < 5 && qup->seqno <= qup->seqsize; i++) {
		len = qup->chunksize;

		if (qup->offset + len >= qup->patch->len) {
			len = qup->patch->len - qup->offset;
			g_assert(qup->seqno == qup->seqsize);	/* Last message */
			g_assert(len > 0);
			g_assert(len <= qup->chunksize);
		}

		qrp_send_patch(qup->node, qup->seqno++, qup->seqsize,
			qup->patch->compressed, qup->patch->entry_bits,
			(gchar *) qup->patch->arena + qup->offset, len);

		qup->offset += len;
		qup->last_sent += len;

		g_assert(qup->seqno <= qup->seqsize || qup->offset == qup->patch->len);

		/*
		 * Break the loop if we did not fully sent the last message, meaning
		 * the TCP connection has its buffer full.
		 */

		if (NODE_MQUEUE_COUNT(qup->node))
			break;
	}

	qup->last = now;

	return qup->seqno <= qup->seqsize;
}

/*
 * qrt_update_was_ok
 *
 * Check whether sending was successful.
 * Should be called when qrt_update_send_next() returned FALSE.
 */
gboolean qrt_update_was_ok(gpointer handle)
{
	struct qrt_update *qup = (struct qrt_update *) handle;

	g_assert(qup->magic == QRT_UPDATE_MAGIC);

	return qup->patch != NULL && qup->seqno > qup->seqsize;
}

/***
 *** Management of the updating sequence -- receiving side.
 ***/

/*
 * A routing table being received.
 *
 * The table is compacted on the fly, and possibly shrunk down if its
 * slot size exceeds our maximum size.
 */

#define QRT_RECEIVE_MAGIC	0x15efbb04
#define QRT_RECEIVE_BUFSIZE	4096		/* Size of decompressing buffer */

struct qrt_receive {
	guint32 magic;
	struct gnutella_node *node;		/* Node for which we're receiving */
	struct routing_table *table;	/* Table being built / updated */
	gint shrink_factor;		/* 1 means none, `n' means coalesce `n' entries */
	gint seqsize;			/* Amount of patch messages to expect */
	gint seqno;				/* Sequence number of next message we expect */
	gint entry_bits;		/* Amount of bits used by PATCH */
	z_streamp inz;			/* Data inflater */
	gchar *data;			/* Where inflated data is written */
	gint len;				/* Length of the `data' buffer */
	gint current_slot;		/* Current slot processed in patch */
	gint current_index;		/* Current index (after shrinking) in QR table */
	gchar *expansion;		/* Temporary expansion arena before shrinking */
	gboolean deflated;		/* Is data deflated? */
};

/*
 * qrt_receive_create
 *
 * Create a new QRT receiving handler, to process all incoming QRP messages
 * from the leaf node.
 *
 * `query_table' is the existing query table we have for the node.  If it
 * is NULL, it means we have no query table yet, and the first QRP message
 * will have to be a RESET.
 *
 * Returns pointer to handler.
 */
gpointer qrt_receive_create(struct gnutella_node *n, gpointer query_table)
{
	struct routing_table *table = (struct routing_table *) query_table;
	struct qrt_receive *qrcv;
	z_streamp inz;
	gint ret;

	g_assert(query_table == NULL || table->magic == QRP_ROUTE_MAGIC);
	g_assert(query_table == NULL || table->client_slots > 0);

	inz = walloc(sizeof(*inz));

	inz->zalloc = NULL;
	inz->zfree = NULL;
	inz->opaque = NULL;

	ret = inflateInit(inz);

	if (ret != Z_OK) {
		wfree(inz, sizeof(*inz));
		g_warning("unable to initialize QRP decompressor for node %s: %s",
			node_ip(n), zlib_strerror(ret));
		return NULL;
	}

	qrcv = walloc(sizeof(*qrcv));
	
	qrcv->magic = QRT_RECEIVE_MAGIC;
	qrcv->node = n;
	qrcv->table = table ? qrt_ref(table) : NULL;
	qrcv->shrink_factor = 1;		/* Assume none for now */
	qrcv->seqsize = 0;				/* Unknown yet */
	qrcv->seqno = 1;				/* Expecting message #1 */
	qrcv->entry_bits = 0;
	qrcv->deflated = FALSE;
	qrcv->inz = inz;
	qrcv->len = QRT_RECEIVE_BUFSIZE;
	qrcv->data = g_malloc(qrcv->len);
	qrcv->expansion = NULL;

	/*
	 * We don't know yet whether we'll receive a RESET, but if we already
	 * have a table, increase its generation number.  If a RESET comes,
	 * we'll create a new table anyway.
	 *
	 * Also compute proper shrink factor and allocate `expansion'.
	 */

	if (table != NULL) {
		gint length = table->client_slots;

		table->generation++;

		/*
		 * Since we know the table_length is a power of two, to
		 * know the shrinking factor, we need only count the amount
		 * of right shifts required to make it be MAX_TABLE_SIZE.
		 */

		while (length > MAX_TABLE_SIZE) {
			length >>= 1;
			qrcv->shrink_factor <<= 1;
		}

		qrcv->expansion = walloc(qrcv->shrink_factor);
	}

	return qrcv;
}

/*
 * qrt_receive_free
 *
 * Dispose of the QRP receiving state.
 */
void qrt_receive_free(gpointer handle)
{
	struct qrt_receive *qrcv = (struct qrt_receive *) handle;

	g_assert(qrcv->magic == QRT_RECEIVE_MAGIC);

	(void) inflateEnd(qrcv->inz);
	wfree(qrcv->inz, sizeof(*qrcv->inz));
	if (qrcv->table)
		qrt_unref(qrcv->table);
	if (qrcv->expansion)
		wfree(qrcv->expansion, qrcv->shrink_factor);
	g_free(qrcv->data);

	qrcv->magic = 0;			/* Prevent accidental reuse */

	wfree(qrcv, sizeof(*qrcv));
}

/*
 * qrt_apply_patch
 *
 * Apply raw patch data (uncompressed) to the current routing table.
 * Returns TRUE on sucess, FALSE on error with the node being BYE-ed.
 */
static gboolean qrt_apply_patch(
	struct qrt_receive *qrcv, guchar *data, gint len)
{
	gint bpe = qrcv->entry_bits;		/* bits per entry */
	gint epb;							/* entries per byte */
	guint8 rmask;						/* reading mask */
	gint expansion_slot;
	struct routing_table *rt = qrcv->table;
	gint i;

	g_assert(qrcv->table != NULL);
	g_assert(qrcv->expansion != NULL);

	/*
	 * NOTA BENE:
	 *
	 * When we're shrinking the table, every entry needs to be expanded
	 * first by the shrinking factor into the `expansion' array, then
	 * the patch is applied on that array, and afterwards the array is
	 * shrunk back to one single value in the table.
	 *
	 * If at least one entry in the `expansion' array is set (i.e. is
	 * marked "present"), the corresponding slot in the routing table will
	 * end-up being set.
	 *
	 * Assume a shrink factor of 2: A "1" in the table will be expaned
	 * as being { "1", "1" }.  If the patch clears the first entry only,
	 * the shrunk table will keep its "1" value.  Only if both entries were
	 * cleared would the table entry become "0".
	 *
	 * This means a succession of patches that flips { "1", "0" } in the
	 * original servent table to { "0", "1" }, and then clears the second
	 * entry to { "0", "0" } will be INCORRECTLY summarized with a "1" value
	 * in the table, since { "0", "1" } will expand back to { "1", "1" }.
	 *
	 *		--RAM, 13/01/2003
	 */

	/*
	 * Compute the expansion slot.  The shrink_factor is always a
	 * power of two, so it's easy to know where to begin!  Computation
	 * is done using the remote servent slot numbers (i.e. before shrinking).
	 *
	 * If we are already past the expansion slot, it means we already expanded
	 * the necessary information in `expansion', but did not have enough data
	 * to shrink it back yet.
	 */

	expansion_slot = qrcv->current_slot & ~(qrcv->shrink_factor - 1);

	if (qrcv->current_slot > expansion_slot)
		expansion_slot += qrcv->shrink_factor;

	/*
	 * Compute the amount of entries per byte, and the initial reading mask.
	 */

	switch (bpe) {
	case 8: epb = 1; rmask = 0xff; break;
	case 4: epb = 2; rmask = 0xf0; break;
	case 2: epb = 4; rmask = 0xc0; break;
	case 1: epb = 8; rmask = 0x80; break;
	default:
		g_error("unsupported bits per entry: %d", bpe);
		return FALSE;
	}

	g_assert(qrcv->expansion != NULL);

	for (i = 0; i < len; i++) {
		gint j;
		guint8 value = data[i];		/* Patch byte contains `epb' slots */
		guint8 smask;				/* Sign bit mask */
		guint8 mask;

		for (
			j = 0, mask = rmask, smask = 0x80;
			j < epb;
			j++, mask >>= bpe, smask >>= bpe
		) {
			guint8 v = value & mask;
			gint o;

			/*
			 * If we are at an expansion slot, expand.
			 *
			 * We don't special-case the non-shrinking cases, even though
			 * those will be the most common, because peformance is not what
			 * matters here.
			 */

			if (qrcv->current_slot == expansion_slot) {
				gint k;
				gboolean v;

				g_assert(qrcv->current_index < rt->slots);

				v = RT_SLOT_READ(rt->arena, qrcv->current_index) ? TRUE : FALSE;

				for (k = 0; k < qrcv->shrink_factor; k++)
					qrcv->expansion[k] = v;

				expansion_slot += qrcv->shrink_factor;	/* For next expansion */
			}

			/*
			 * At this point, `expansion_slot' points to the next expansion
			 * point.  Our offset `o' within the array (whose size is the
			 * shrink_factor) is where the next patch must be applied.
			 */

			g_assert(expansion_slot > qrcv->current_slot);

			o = qrcv->shrink_factor - (expansion_slot - qrcv->current_slot);

			g_assert(o >= 0);

			/*
			 * The only possibilities for the patch are:
			 *
			 * . A negative value, to bring the slot value from infinity to 1.
			 * . A null value for no change.
			 * . A positive value to bring the slot back to infinity.
			 *
			 * The "bpe=1" patch is special.  The value is XOR-ed, thus
			 * a 0 means no change, and a 1 inverts the value.
			 *
			 * In reality, for leaf<->ultrapeer QRT, what matters is presence.
			 * We consider everything that is less to infinity as being
			 * present, and therefore forget about the "hops-away" semantics
			 * of the QRT slot value.
			 */

			if (bpe == 1) {				/* Special, use XOR */
				if (v)
					qrcv->expansion[o] = !qrcv->expansion[o];
			} else if (v & smask)		/* Negative value, sign bit is 1 */
				qrcv->expansion[o] = 1;	/* We have something */
			else if (v != 0)			/* Positive value */
				qrcv->expansion[o] = 0;	/* We no longer have something */

			/*
			 * Advance to next slot, and if we reach the next expansion
			 * slot, it's time to compact the data back into the current index
			 * and move to the next index.
			 */

			if (++qrcv->current_slot == expansion_slot) {
				gint k;
				gboolean v = FALSE;

				for (k = 0; k < qrcv->shrink_factor; k++) {
					if (qrcv->expansion[k]) {
						v = TRUE;
						break;
					}
				}

				g_assert(qrcv->current_index < rt->slots);

				if (v) {
					RT_SLOT_SET(rt->arena, qrcv->current_index);
					rt->set_count++;
				} else
					RT_SLOT_CLEAR(rt->arena, qrcv->current_index);

				qrcv->current_index++;
			}

			/*
			 * Make sure they are not providing us with more data than
			 * the table can hold.
			 */

			if (qrcv->current_slot >= rt->client_slots) {
				if (j != (epb - 1) || i != (len - 1)) {
					struct gnutella_node *n = qrcv->node;
					g_warning("node %s <%s> overflowed its QRP patch",
						node_ip(n), node_vendor(n));
					node_bye_if_writable(n, 413, "QRP patch overflowed table");
					return FALSE;
				}
			}
		}
	}

	return TRUE;
}

/*
 * qrt_handle_reset
 *
 * Handle reception of QRP RESET.
 * Returns TRUE if we handled the message correctly, FALSE if an error
 * was found and the node BYE-ed.
 */
static gboolean qrt_handle_reset(
	struct gnutella_node *n, struct qrt_receive *qrcv, struct qrp_reset *reset)
{
	struct routing_table *rt;
	gint ret;
	gint slots;

	ret = inflateReset(qrcv->inz);
	if (ret != Z_OK) {
		g_warning("unable to reset QRP decompressor for node %s: %s",
			node_ip(n), zlib_strerror(ret));
		node_bye_if_writable(n, 500, "Error resetting QRP inflater: %s",
			zlib_strerror(ret));
		return FALSE;
	}

	/*
	 * If the advertized table size is not a power of two, good bye.
	 */

	if (!is_pow2(reset->table_length)) {
		g_warning("node %s <%s> sent us non power-of-two QRP length: %u",
			node_ip(n), node_vendor(n), reset->table_length);
		node_bye_if_writable(n, 413, "Invalid QRP table length %u",
			reset->table_length);
		return FALSE;
	}

	/*
	 * If infinity is not at least 1, there is a problem.
	 *
	 * We allow 1 because for leaf<->ultrapeer QRTs, what matters is
	 * presence, and we don't really care about the hop distance: normally,
	 * presence would be 1 and absence 2, without any 0 in the table.  When
	 * infinity is 1, presence will be indicated by a 0.
	 */

	if (reset->infinity < 1) {
		g_warning("node %s <%s> sent us invalid QRP infinity: %u",
			node_ip(n), node_vendor(n), (guint) reset->infinity);
		node_bye_if_writable(n, 413, "Invalid QRP infinity %u",
			(guint) reset->infinity);
		return FALSE;
	}

	/*
	 * Create new empty table, and set shrink_factor correctly in case
	 * the table's size exceeds our maximum size.
	 */

	node_qrt_discard(n);

	if (qrcv->table)
		qrt_unref(qrcv->table);

	if (qrcv->expansion)
		wfree(qrcv->expansion, qrcv->shrink_factor);

	rt = qrcv->table = walloc(sizeof(*rt));

	rt->magic = QRP_ROUTE_MAGIC;
	rt->refcnt = 1;
	rt->generation = 0;
	rt->infinity = reset->infinity;
	rt->client_slots = reset->table_length;
	rt->compacted = TRUE;		/* We'll compact it on the fly */
	rt->digest = NULL;

	qrcv->shrink_factor = 1;		/* Assume none for now */
	qrcv->seqsize = 0;				/* Unknown yet */
	qrcv->seqno = 1;				/* Expecting message #1 */

	/*
	 * Since we know the table_length is a power of two, to
	 * know the shrinking factor, we need only count the amount
	 * of right shifts required to make it be MAX_TABLE_SIZE.
	 */

	while (reset->table_length > MAX_TABLE_SIZE) {
		reset->table_length >>= 1;
		qrcv->shrink_factor <<= 1;
	}

	if (dbg && qrcv->shrink_factor > 1)
		g_warning("QRT from %s <%s> will be shrank by a factor of %d",
			node_ip(n), node_vendor(n), qrcv->shrink_factor);

	qrcv->expansion = walloc(qrcv->shrink_factor);

	rt->slots = rt->client_slots / qrcv->shrink_factor;
	rt->bits = highest_bit_set(rt->slots);

	g_assert(is_pow2(rt->slots));
	g_assert(rt->slots <= MAX_TABLE_SIZE);
	g_assert((1 << rt->bits) == rt->slots);

	/*
	 * Allocate the compacted area.
	 * Since the table is empty, it is zero-ed.
	 */

	slots = rt->slots / 8;			/* 8 bits per byte, table is compacted */
	rt->arena = g_malloc0(slots);

	/*
	 * We're now ready to handle PATCH messages.
	 */

	return TRUE;
}

/*
 * qrt_handle_patch
 *
 * Handle reception of QRP PATCH.
 *
 * Returns TRUE if we handled the message correctly, FALSE if an error
 * was found and the node BYE-ed.  Sets `done' to TRUE on the last message
 * from the sequence.
 */
static gboolean qrt_handle_patch(
	struct gnutella_node *n, struct qrt_receive *qrcv, struct qrp_patch *patch,
	gboolean *done)
{
	/*
	 * If we don't have a routing table allocated, it means they never sent
	 * the RESET message, and no prior table was recorded.
	 */

	if (qrcv->table == NULL) {
		g_warning("node %s <%s> did not sent any QRP RESET before PATCH",
			node_ip(n), node_vendor(n));
		node_bye_if_writable(n, 413, "No QRP RESET received before PATCH");
		return FALSE;
	}

	/*
	 * Check that we're receiving the proper sequence.
	 */

	if (patch->seq_no != qrcv->seqno) {
		g_warning("node %s <%s> sent us invalid QRP seqno %u (expected %u)",
			node_ip(n), node_vendor(n), (guint) patch->seq_no, qrcv->seqno);
		node_bye_if_writable(n, 413, "Invalid QRP seq number %u (expected %u)",
			(guint) patch->seq_no, qrcv->seqno);
		return FALSE;
	}

	/*
	 * Check that the maxmimum amount of messages for the patch sequence
	 * is remaining stable accross all the PATCH messages.
	 */

	if (qrcv->seqno == 1) {
		qrcv->seqsize = patch->seq_size;
		qrcv->deflated = patch->compressor == 0x1;
		qrcv->entry_bits = patch->entry_bits;
		qrcv->current_index = qrcv->current_slot = 0;
		qrcv->table->set_count = 0;

		switch (qrcv->entry_bits) {
		case 8:
		case 4:
		case 2:
		case 1:
			break;
		default:
			g_warning("node %s <%s> sent invalid QRP entry bits %u for PATCH",
				node_ip(n), node_vendor(n), qrcv->entry_bits);
			node_bye_if_writable(n, 413, "Invalid QRP entry bits %u for PATCH",
				qrcv->entry_bits);
			return FALSE;
		}
	} else if (patch->seq_size != qrcv->seqsize) {
		g_warning("node %s <%s> changed QRP seqsize to %u at message #%d "
			"(started with %u)",
			node_ip(n), node_vendor(n),
			(guint) patch->seq_size, qrcv->seqno, qrcv->seqsize);
		node_bye_if_writable(n, 413,
			"Changed QRP seq size to %u at message #%d (began with %u)",
			(guint) patch->seq_size, qrcv->seqno, qrcv->seqsize);
		return FALSE;
	}

	/*
	 * Check that the compression bits and entry_bits values are staying
	 * the same.
	 */

	if (qrcv->entry_bits != patch->entry_bits) {
		g_warning("node %s <%s> changed QRP patch entry bits to %u "
			"at message #%d (started with %u)",
			node_ip(n), node_vendor(n),
			(guint) patch->entry_bits, qrcv->seqno, qrcv->entry_bits);
		node_bye_if_writable(n, 413,
			"Changed QRP patch entry bits to %u at message #%d (began with %u)",
			(guint) patch->entry_bits, qrcv->seqno, qrcv->entry_bits);
		return FALSE;
	}

	qrcv->seqno++;

	/*
	 * Process the patch data.
	 */

	if (qrcv->deflated) {
		z_streamp inz = qrcv->inz;
		gint ret;
		gboolean seen_end = FALSE;

		inz->next_in = patch->data;
		inz->avail_in = patch->len;

		while (!seen_end && inz->avail_in > 0) {
			inz->next_out = (gpointer) qrcv->data;
			inz->avail_out = qrcv->len;

			ret = inflate(inz, Z_SYNC_FLUSH);

			if (ret == Z_STREAM_END && qrcv->seqno > qrcv->seqsize) {
				seen_end = TRUE;
				ret = Z_OK;
			}

			if (ret != Z_OK) {
				g_warning("decompression of QRP patch #%u/%u failed for "
					"node %s <%s>: %s",
					(guint) patch->seq_no, (guint) patch->seq_size,
					node_ip(n), node_vendor(n), zlib_strerror(ret));
				node_bye_if_writable(n, 413,
					"QRP patch #%u/%u decompression failed: %s",
					(guint) patch->seq_no, (guint) patch->seq_size,
					zlib_strerror(ret));
				return FALSE;
			}

			if (
				!qrt_apply_patch(qrcv, (gpointer) qrcv->data,
					qrcv->len - inz->avail_out)
			)
				return FALSE;
		}
			
		/*
		 * If we reached the end of the stream, make sure we were at
		 * the last patch of the sequence.
		 */

		if (seen_end && qrcv->seqno <= qrcv->seqsize) {
			g_warning("saw end of compressed QRP patch at #%u/%u for "
				"node %s <%s>",
				(guint) patch->seq_no, (guint) patch->seq_size,
				node_ip(n), node_vendor(n));
			node_bye_if_writable(n, 413,
				"Early end of compressed QRP patch at #%u/%u",
				(guint) patch->seq_no, (guint) patch->seq_size);
			return FALSE;
		}
	} else if (!qrt_apply_patch(qrcv, patch->data, patch->len))
		return FALSE;

	/*
	 * Was the PATCH sequence fully processed?
	 */

	if (qrcv->seqno > qrcv->seqsize) {
		struct routing_table *rt = qrcv->table;

		*done = TRUE;

		/*
		 * Make sure the servent sent us a patch that covers the whole table.
		 * We've reached the end of the patch sequence, but that does not
		 * necessarily means it applied to all the slots.
		 */

		if (qrcv->current_index < rt->slots) {
			g_warning("QRP %d-bit patch from node %s <%s> covered only "
				"%d/%d slots",
				qrcv->entry_bits, node_ip(n), node_vendor(n),
				qrcv->current_index, rt->slots);
			node_bye_if_writable(n, 413,
				"Incomplete %d-bit QRP patch covered %d/%d slots",
				qrcv->entry_bits, qrcv->current_index, rt->slots);
			return FALSE;
		}

		g_assert(qrcv->current_index == rt->slots);

		if (rt->digest)
			atom_sha1_free(rt->digest);

		rt->digest = atom_sha1_get(qrt_sha1(rt));
		rt->fill_ratio = (gint) (100.0 * rt->set_count / rt->slots);

		/*
		 * If table is more than 1% full, each query will go through a
		 * random d100 throw, and will pass only if the score is below
		 * the value of the pass throw threshold.
		 *
		 * The function below quickly drops and then flattens:
		 *
		 *   x =  2%  -> throw = 61
		 *   x =  3%  -> throw = 55
		 *   x =  5%  -> throw = 48
		 *   x = 10%  -> throw = 39
		 *   x = 20%  -> throw = 29
		 *   x = 50%  -> throw = 14
		 *   x = 90%  -> throw = 3
		 *   x = 99%  -> throw = 1
		 *
		 * throw = 100 * (1 - (x - 0.01)^1/5 + 0.01) 
		 */

		if (rt->fill_ratio > 1)
			rt->pass_throw = (gint)
				(100.0 * (1 - pow((rt->fill_ratio - 1) / 100.0, 1/5.0) + 0.01));
		else
			rt->pass_throw = 100;		/* Always forward if QRT says so */

		if (dbg > 2)
			printf("QRP got whole %d-bit patch "
				"(gen=%d, slots=%d (*%d), fill=%d%%, throw=%d) "
				"from %s <%s>: SHA1=%s\n",
				qrcv->entry_bits, rt->generation, rt->slots,
				qrcv->shrink_factor, rt->fill_ratio, rt->pass_throw,
				node_ip(n), node_vendor(n), sha1_base32(rt->digest));

		/*
		 * Install the table in the node, if it was a generation 0 table.
		 * Otherwise, we only finished patching it.
		 */

		if (rt->generation == 0)
			node_qrt_install(n, rt);
		else
			node_qrt_patched(n, rt);

		(void) qrt_dump(stdout, rt, dbg > 20);
	}

	return TRUE;
}

/*
 * qrt_receive_next
 *
 * Handle reception of the next QRP message in the stream for a given update.
 *
 * Returns whether we successfully handled the message.  If not, the node
 * has been signalled if needed, and may have been BYE-ed.
 *
 * When the last message from the sequence has been processed, set `done'
 * to TRUE.
 */
gboolean qrt_receive_next(gpointer handle, gboolean *done)
{
	struct qrt_receive *qrcv = (struct qrt_receive *) handle;
	struct gnutella_node *n = qrcv->node;
	guint8 type;

	g_assert(qrcv->magic == QRT_RECEIVE_MAGIC);
	g_assert(n->header.function == GTA_MSG_QRP);

	type = *n->data;

	*done = FALSE;

	switch (type) {
	case GTA_MSGV_QRP_RESET:
		{
			struct qrp_reset reset;

			if (!qrp_recv_reset(n, &reset))
				goto dropped;

			return qrt_handle_reset(n, qrcv, &reset);
		}
		break;
	case GTA_MSGV_QRP_PATCH:
		{
			struct qrp_patch patch;

			if (!qrp_recv_patch(n, &patch))
				goto dropped;

			return qrt_handle_patch(n, qrcv, &patch, done);
		}
		break;
	default:
		gnet_stats_count_dropped(n, MSG_DROP_UNKNOWN_TYPE);
		goto dropped;
	}

	return TRUE;

dropped:
	if (dbg > 3)
		gmsg_log_dropped(&n->header, "from %s", node_ip(n));

	n->rx_dropped++;
	return TRUE;		/* Everything is fine, even if we dropped message */
}

/*
 * qrp_close
 *
 * Called at servent shutdown to reclaim all the memory.
 */
void qrp_close(void)
{
	qrp_cancel_computation();

	if (routing_table)
		qrt_unref(routing_table);

	if (routing_patch)
		qrt_patch_unref(routing_patch);

	if (buffer.arena)
		g_free(buffer.arena);
}

/*
 * qrt_dump_is_slot_present
 *
 * Used by qrt_dump().
 * Returns whether a slot in the table is present or not.
 */
static gboolean qrt_dump_is_slot_present(struct routing_table *rt, gint slot)
{
	g_assert(slot < rt->slots);

	if (!rt->compacted)
		return rt->arena[slot] < rt->infinity;

	return RT_SLOT_READ(rt->arena, slot);
}

/*
 * qrt_dump
 *
 * Dump QRT to specified file.
 * If `full' is true, we dump the whole table.
 *
 * Returns a unique 32-bit checksum.
 */
static guint32 qrt_dump(FILE *f, struct routing_table *rt, gboolean full)
{
	gint i;
	gint j;
	gboolean last_status = FALSE;
	gint last_slot = 0;
	SHA1Context ctx;
	guint8 digest[SHA1HashSize];
	guint32 result;

	fprintf(f, "------ Query Routing Table (gen=%d, slots=%d, %scompacted)\n",
		rt->generation, rt->slots, rt->compacted ? "" : "not ");

	SHA1Reset(&ctx);

	for (i = 0; i <= rt->slots; i++) {
		gboolean status = FALSE;
		guint8 value;

		if (i == rt->slots)
			goto final;

		status = qrt_dump_is_slot_present(rt, i);
		value = status ? 1 : 0;			/* 1 for presence */

		SHA1Input(&ctx, &value, sizeof(value));

		if (i == 0) {
			last_slot = i;
			last_status = status;
			continue;
		}

		if (!last_status == !status)
			continue;

	final:
		if (full) {
			if (i - 1 != last_slot)
				fprintf(f, "%d .. %d: %s\n", last_slot, i - 1,
					last_status ? "PRESENT" : "nothing");
			else
				fprintf(f, "%d: %s\n", last_slot,
					last_status ? "PRESENT" : "nothing");

			last_slot = i;
			last_status = status;
		}
	}

	SHA1Result(&ctx, digest);

	/*
	 * Reduce SHA1 to a single guint32.
	 */

	for (result = 0, i = j = 0; i < SHA1HashSize; i++) {
		guint32 b = digest[i];
		result ^= b << (j << 3);
		j = (j + 1) & 0x3;
	}


	fprintf(f, "------ End Routing Table (gen=%d, SHA1=%s, token=0x%x)\n",
		rt->generation, sha1_base32((gchar *) digest), result);

	return result;
}

/***
 *** Query routing management.
 ***/

/*
 * qhvec_alloc
 *
 * Allocate a query hash container for at most `size' entries.
 */
query_hashvec_t *qhvec_alloc(gint size)
{
	query_hashvec_t *qhvec;

	qhvec = walloc(sizeof(*qhvec));

	qhvec->count = 0;
	qhvec->size = size;
	qhvec->vec = walloc(size * sizeof(struct query_hash));

	return qhvec;
}

/*
 * qhvec_free
 *
 * Dispose of the query hash container.
 */
void qhvec_free(query_hashvec_t *qhvec)
{
	wfree(qhvec->vec, qhvec->size * sizeof(struct query_hash));
	wfree(qhvec, sizeof(*qhvec));
}

/*
 * qhvec_reset
 *
 * Empty query hash container.
 */
void qhvec_reset(query_hashvec_t *qhvec)
{
	qhvec->count = 0;
}

/*
 * qhvec_add
 *
 * Add the `word' coming from `src' into the query hash vector.
 * If the vector is already full, do nothing.
 */
void qhvec_add(query_hashvec_t *qhvec, gchar *word, enum query_hsrc src)
{
	struct query_hash *qh;

	if (qhvec->count >= qhvec->size)
		return;

	qh = &qhvec->vec[qhvec->count++];
	qh->hashcode = qrp_hashcode(word);
	qh->source = src;
}

/*
 * qrt_build_query_target
 *
 * Compute list of nodes to send the query to, based on node's QRT.
 * The query is identified by its list of QRP hashes, by its hop count
 * and by its source node (so we don't send back the query where it
 * came from).
 *
 * Returns list of nodes, a subset of the currently connected nodes.
 * Once used, the list of nodes can be freed with g_slist_free().
 */
GSList *qrt_build_query_target(
	query_hashvec_t *qhvec, gint hops, struct gnutella_node *source)
{
	GSList *nodes = NULL;		/* Targets for the query */
	gint count = 0;				/* Amount of selected nodes so far */
	const GSList *sl;

	g_assert(qhvec != NULL);
	g_assert(hops >= 0);

	if (qhvec->count == 0) {
		if (dbg) {
			if (source != NULL)
				g_warning("QRP %s had empty hash vector",
					gmsg_infostr(&source->header));
			else
				g_warning("QRP query [hops=%d] had empty hash vector", hops);
		}
		return NULL;
	}

	for (sl = node_all_nodes(); sl; sl = g_slist_next(sl)) {
		struct gnutella_node *dn = (struct gnutella_node *) sl->data;
		struct routing_table *rt = (struct routing_table *) dn->query_table;
		struct query_hash *qh;
		gboolean can_route;
		gboolean sha1_query;
		gboolean sha1_in_qrt;
		gint i;

		if (rt == NULL)			/* Node has not sent its query routing table */
			continue;

		if (dn == source)		/* This is the node that sent us the query */
			continue;

		if (!NODE_IS_LEAF(dn) || !NODE_IS_WRITABLE(dn))
			continue;

		if (hops >= dn->hops_flow)		/* Hops-flow prevents sending */
			continue;

		/*
		 * Look whether we can route the query to the leaf node.
		 */

		node_inc_qrp_query(dn);

		can_route = TRUE;
		sha1_query = FALSE;
		sha1_in_qrt = FALSE;

		for (i = qhvec->count, qh = qhvec->vec; i > 0; i--, qh++) {
			guint32 idx = QRP_HASH_RESTRICT(qh->hashcode, rt->bits);

			/* 
			 * If there is an entry in the table and the source is an URN,
			 * we have to forward the query, as those are OR-ed.
			 * Otherwise, ALL the keywords must be present.
			 */

			g_assert(idx < rt->slots);

			if (qh->source == QUERY_H_URN)
				sha1_query = TRUE;

			if (RT_SLOT_READ(rt->arena, idx)) {
				if (qh->source == QUERY_H_URN) {	/* URN present */
					sha1_in_qrt = TRUE;
					can_route = TRUE;				/* Force routing */
					break;							/* Will forward */
				}
			} else {
				if (qh->source == QUERY_H_WORD)		/* Word NOT present */
					can_route = FALSE;				/* A priori, don't route */
			}
		}

		if (!can_route)
			continue;

		/*
		 * When facing a SHA1 query, if not at least one of the possibly
		 * multiple SHA1 URN present did not match the QRT, don't forward.
		 */

		if (sha1_query && !sha1_in_qrt)
			continue;

		/*
		 * If table for the node is so full that we can't let all the queries
		 * pass through, further restrict sending even though QRT says we
		 * can let it go.
		 *
		 * We only do that when there are pending messages in the node's queue,
		 * meaning we can't transmit all our packets fast enough.
		 */

		if (rt->pass_throw < 100 && NODE_MQUEUE_COUNT(dn) != 0) {
			if (random_value(99) >= rt->pass_throw)
				continue;
		}

		/*
		 * If leaf is flow-controlled, it has trouble reading or we don't
		 * have enough bandwidth to send everything.  If we were not skipping
		 * it, the flow-control would cause the message queue to prioritize
		 * the query in the queue, removing queries coming far away in favor
		 * of closer ones (hops-wise).  But if we skip it alltogether, we loose
		 * some potential for a match.
		 *
		 * Therefore, let only 50% of the queries pass to flow-controlled nodes.
		 *
		 * We don't less SHA1 queries through, as the chances they will match
		 * are very slim: not all servents include the SHA1 in their QRP, and
		 * there can be many hashing conflicts, so the fact that it matched
		 * an entry in the QRP table does not imply there will be a match
		 * in the leaf node.
		 *		--RAM, 31/12/2003
		 */

		if (NODE_IN_TX_FLOW_CONTROL(dn)) {
			if (sha1_query)
				continue;
			if (random_value(99) >= 50)
				continue;
		}

		/*
		 * OK, can send the query to that node.
		 */

		nodes = g_slist_prepend(nodes, dn);
		count++;
		node_inc_qrp_match(dn);
	}

	return nodes;
}

/*
 * qrt_route_query
 *
 * Route query message to leaf nodes, based on their QRT.
 */
void qrt_route_query(struct gnutella_node *n, query_hashvec_t *qhvec)
{
	GSList *nodes;				/* Targets for the query */

	g_assert(qhvec != NULL);
	g_assert(n->header.function == GTA_MSG_SEARCH);

	nodes = qrt_build_query_target(qhvec, n->header.hops, n);

	if (dbg > 4)
		printf("QRP %s (%d word/hash) forwarded to %d/%d leaves\n",
			gmsg_infostr(&n->header), qhvec->count, g_slist_length(nodes),
			node_leaf_count);

	gmsg_split_sendto_leaves(nodes, (guchar *) &n->header, n->data,
		n->size + sizeof(struct gnutella_header));

	g_slist_free(nodes);
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
	CHECK(hash("FAIL", 16)==37458);	/* WILL FAIL */
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

