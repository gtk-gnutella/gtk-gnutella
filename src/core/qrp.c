/*
 * $Id$
 *
 * Copyright (c) 2002-2003, Raphael Manfredi
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
 * @ingroup core
 * @file
 *
 * Query Routing Protocol (LimeWire's scheme).
 *
 * @author Raphael Manfredi
 * @date 2002-2003
 */

#include "common.h"

RCSID("$Id$")

#ifdef I_MATH
#include <math.h>
#endif	/* I_MATH */

#include <zlib.h>

#include "qrp.h"
#include "routing.h"				/* For message_set_muid() */
#include "gmsg.h"
#include "nodes.h"					/* For NODE_IS_WRITABLE() */
#include "gnet_stats.h"
#include "share.h"

#include "lib/atoms.h"
#include "lib/bg.h"
#include "lib/cq.h"
#include "lib/glib-missing.h"
#include "lib/endian.h"
#include "lib/sha1.h"
#include "lib/tm.h"
#include "lib/utf8.h"
#include "lib/wordvec.h"
#include "lib/walloc.h"
#include "lib/zlib_util.h"

#include "if/gnet_property.h"
#include "if/gnet_property_priv.h"

#include "lib/override.h"			/* Must be the last header included */

#define MIN_SPARSE_RATIO	1		/**< At most 1% of slots used */
#define MAX_CONFLICT_RATIO	20		/**< At most 20% of insertion conflicts */
#define LOCAL_INFINITY		2		/**< We're one hop away, so 2 is infinity */
#define MIN_TABLE_BITS		14		/**< 16 KB */
#define MAX_TABLE_BITS		21		/**< 2 MB */

#define MAX_TABLE_SIZE		(1 << MAX_TABLE_BITS)
#define MAX_UP_TABLE_SIZE	131072 /**< Max size for inter-UP QRP: 128 Kslots */
#define EMPTY_TABLE_SIZE	8

struct query_hash {
	guint32 hashcode;
	enum query_hsrc source;
};

struct query_hashvec {
	struct query_hash *vec;	/**< Vector of at most `size' entries */
	guint8 count;			/**< Amount of slots actually taken */
	guint8 size;			/**< Amount of slots in vector */
	guint8 has_urn;			/**< Whether an URN is present in the query */
};

gboolean
qhvec_has_urn(const struct query_hashvec *qhv)
{
	return 0 != qhv->has_urn;
}

guint
qhvec_count(const struct query_hashvec *qhv)
{
	return qhv->count;
}

/*
 * Period between inter-UP QRP exchanges where we propagate a new QRP to our
 * peers if the leaves changed their QRP, either through updating or through
 * connection/disconnection.
 *
 * Used to do that every 90 secs, but raised the period to 5 minutes because
 * inter-UP QRP exchanges consumed about 44% of the outgoing traffic, and it
 * is not ultra critical if neighbours don't have the latest set of keywords,
 * given that there will be important conflicts in the small 128K tables!
 *		--RAM, 2004-09-09
 */
#define LEAF_MONITOR_PERIOD	(300 * 1000)	/**< 5 minutes, in ms */

enum qrp_route_magic {
	QRP_ROUTE_MAGIC	= 0xf2aa4886
};

/**
 * A routing table.
 *
 * If we are a leaf node, we send our routing table to neighbours.  We keep
 * a pointer to the previous table sent, so that we can determine the "patch"
 * with the current table in case our library is regenerated.
 */
struct routing_table {
	enum qrp_route_magic magic;
	gint refcnt;			/**< Amount of references */
	gint generation;		/**< Generation number */
	guint8 *arena;			/**< Where table starts */
	gint slots;				/**< Amount of slots in table */
	gint infinity;			/**< Value for "infinity" */
	guint32 client_slots;	/**< Only for received tables, for shrinking ctrl */
	gint bits;				/**< Amount of bits used in table size (received) */
	gint set_count;			/**< Amount of slots set in table */
	gint fill_ratio;		/**< 100 * fill ratio for table (received) */
	gint pass_throw;		/**< Query must pass a d100 throw to be forwarded */
	const struct sha1 *digest;	/**< SHA1 digest of the whole table (atom) */
	gchar *name;			/**< Name for dumping purposes */
	gboolean reset;			/**< This is a new table, after a RESET */
	gboolean compacted;
};

enum routing_patch_magic {
	ROUTING_PATCH_MAGIC = 0x811906cf
};

/**
 * A routing table patch.
 */
struct routing_patch {
	enum routing_patch_magic magic;
	gint refcnt;			/**< Amount of references */
	guint8 *arena;
	gint size;				/**< Number of entries in table */
	gint infinity;			/**< Value of infinity for the table patched */
	gint len;				/**< Length of arena in bytes */
	gint entry_bits;
	gboolean compressed;
};

static struct routing_table *routing_table; /**< Our table */
static struct routing_patch *routing_patch; /**< Against empty table */
static struct routing_table *local_table;   /**< Table for local files */
static struct routing_table *merged_table;  /**< From all our leaves */
static gint generation;

static void qrt_compress_cancel_all(void);
static void qrt_patch_compute(
	struct routing_table *rt, struct routing_patch **rpp);
static guint32 qrt_dump(FILE *f, struct routing_table *rt, gboolean full);
void test_hash(void);

static void qrp_monitor(cqueue_t *cq, gpointer obj);

static cevent_t *monitor_ev;

/**
 * Install supplied routing_table as the global `routing_table'.
 */
static void
install_routing_table(struct routing_table *rt)
{
	g_assert(rt != NULL);

	if (routing_table != NULL)
		qrt_unref(routing_table);
	routing_table = qrt_ref(rt);

	/*
	 * Update some properties with might have changed compared to the local
	 * table when running in UP mode, since we're merging our table with
	 * the ones from the leaves.  Alas, we can't really update the conflict
	 * ratio nor the amount of keywords present.
	 */

	gnet_prop_set_guint32_val(PROP_QRP_SLOTS, (guint32) rt->slots);
	gnet_prop_set_guint32_val(PROP_QRP_SLOTS_FILLED, (guint32) rt->set_count);
	gnet_prop_set_guint32_val(PROP_QRP_FILL_RATIO,
		(guint32) (100.0 * rt->set_count / rt->slots));
}

/**
 * Install supplied routing_table as the global `merged_table'.
 * If the supplied table is NULL, we simply forget about the old table.
 */
static void
install_merged_table(struct routing_table *rt)
{
	if (merged_table != NULL)
		qrt_unref(merged_table);
	merged_table = (rt == NULL) ? rt : qrt_ref(rt);
}

/**
 * Compute standard QRP hash code on 32 bits.
 *
 * @param s A keyword in canonic form (UTF-8, NFC, lowercased, etc.).
 */
static inline guint32
qrp_hashcode(const gchar *s)
{
	guint32 x = 0;		/* The running total */
	guint32 uc;
	guint j;			/* The bit position in xor */

	/*
	 * First turn x[0...end-1] into a number by treating all 4-byte
	 * chunks as a little-endian quadword, and XOR'ing the result together.
	 * We pad x with zeroes as needed.
	 *
	 * To avoid having do deal with special cases, we do this by XOR'ing
	 * a rolling value one byte at a time, taking advantage of the fact that
	 * x XOR 0==x.
	 */

	for (j = 0; '\0' != (uc = (guchar) *s); j = (j + 8) & 24) {
		guint retlen;

		uc = utf8_decode_char_fast(s, &retlen);
		if (!uc)
			break;	/* Invalid encoding */

		if (uc > 0xffffU) {
			/* ``uc'' will hold two surrogates */
			uc = utf16_encode_char_compact(uc);

			x ^= (uc & 0xff) << j;
			j = (j + 8) & 24;
			uc >>= 16;	/* move to the second surrogate */
		}
		x ^= (uc & 0xff) << j;
		s += retlen;
	}

	/*
	 * Multiplication-based hash function.
	 *
	 * See Chapter 12.3.2. of "Introduction to Algorithms" by
	 * (Cormen, Leiserson, and Rivest) [CLR]
	 */

	return x * 0x4F1BBCDCUL;
}

/**
 * For tests only
 *
 * The hashing function, defined by the QRP specifications.
 * Naturally, everyone must use the SAME hashing function!
 */
static inline guint32
qrp_hash(const gchar *s, gint bits)
{
	return qrp_hashcode(s) >> (32 - bits);
}

/***
 *** Routing table management.
 ***/

/**
 * Access slot #`s' in arena `a'.
 * Table is compacted so that slot #6 is bit 1 of byte 0.
 *
 * In general:
 *
 *	byte = slot >> 3;
 *	bit = 7 - (slot & 0x7);
 *  value = arena[byte] & (1 << bit)
 *
 * @returns the TRUE if there is something present, FALSE otherwise.
 */

static inline gboolean
RT_SLOT_READ(const guint8 *arena, guint i)
{
	return 0 != (arena[i >> 3] & (0x80U >> (i & 0x7)));
}

static inline void
qrt_patch_slot(struct routing_table *rt, guint i, guint8 v)
{
	if (v) {
		guint b = 0x80U >> (i & 0x7);

		if (v & 0x80) {		/* Negative value */
			rt->arena[i >> 3] |= b;
			rt->set_count++;
		} else { 			/* Positive value */
			rt->arena[i >> 3] &= ~b;
		}
	}
	/* else... unchanged. */
}

/**
 * Compact routing table in place so that only one bit of information is used
 * per entry, reducing memory requirements by a factor of 8.
 */
static void
qrt_compact(struct routing_table *rt)
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

	if (GNET_PROPERTY(qrp_debug) > 4) {
		g_message("dumping QRT before compaction...");
		token = qrt_dump(stderr, rt, GNET_PROPERTY(qrp_debug) > 19);
	}

	nsize = rt->slots / 8;
	narena = g_malloc0(nsize);
	rt->set_count = 0;
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
		if (*p != rt->infinity) {
			mask |= 0x80;				/* Bit set to indicates presence */
			rt->set_count++;
		}
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

	G_FREE_NULL(rt->arena);
	rt->arena = (guchar *) narena;
	rt->compacted = TRUE;

	if (GNET_PROPERTY(qrp_debug) > 4) {
		guint32 token2;
		g_message("dumping QRT after compaction...");
		token2 = qrt_dump(stderr, rt, GNET_PROPERTY(qrp_debug) > 19);

		if (token2 != token)
			g_warning("BUG in QRT compaction!");
	}
}

/**
 * Computes the SHA1 of a compacted routing table.
 * @returns a pointer to static data.
 */
static struct sha1 *
qrt_sha1(struct routing_table *rt)
{
	static struct sha1 sha1;
	SHA1Context ctx;
	gint i;
	gint bytes;
	guint8 vector[8];
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

		SHA1Input(&ctx, vector, sizeof vector);
	}

	SHA1Result(&ctx, &sha1);
	return &sha1;
}

/**
 * Get a new reference on a routing patch.
 */
static struct routing_patch *
qrt_patch_ref(struct routing_patch *rp)
{
	g_assert(ROUTING_PATCH_MAGIC == rp->magic);
	rp->refcnt++;
	return rp;
}

/**
 * Free routing table patch.
 */
static void
qrt_patch_free(struct routing_patch *rp)
{
	g_assert(ROUTING_PATCH_MAGIC == rp->magic);
	G_FREE_NULL(rp->arena);
	rp->magic = 0;
	wfree(rp, sizeof *rp);
}

/**
 * Remove a reference on a routing patch, freeing it when no more ref remains.
 */
static void
qrt_patch_unref(struct routing_patch *rp)
{
	g_assert(ROUTING_PATCH_MAGIC == rp->magic);
	g_assert(rp->refcnt > 0);

	if (--rp->refcnt == 0)
		qrt_patch_free(rp);
}

/**
 * Compute patch between two (compacted) routing tables.
 * When `old' is NULL, then we compare against a table filled with "infinity".
 * If `old' isn't NULL, then it must have the same size as `new'.
 *
 * @returns a patch buffer (uncompressed), made of signed quartets, or NULL
 * if there were no differences between the two tables.  If the `old' table
 * was NULL, we guarantee we'll provide a non-null result.
 */
static struct routing_patch *
qrt_diff_4(struct routing_table *old, struct routing_table *new)
{
	gint bytes;
	struct routing_patch *rp;
	guchar *op;
	guchar *np;
	guchar *pp;
	gint i;
	gboolean changed = FALSE;

	g_assert(old == NULL || old->magic == QRP_ROUTE_MAGIC);
	g_assert(old == NULL || old->compacted);
	g_assert(new->magic == QRP_ROUTE_MAGIC);
	g_assert(new->compacted);
	g_assert(old == NULL || new->slots == old->slots);

	rp = walloc(sizeof *rp);
	rp->magic = ROUTING_PATCH_MAGIC;
	rp->refcnt = 1;
	rp->size = new->slots;
	rp->infinity = new->infinity;
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

			if ((obyte & mask) ^ (nbyte & mask)) {	/* Bit `j' changed */
				v |= (obyte & mask) ? 0x1 : 0xf;
				changed = TRUE;
			}

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

	if (!changed && old != NULL) {
		qrt_patch_free(rp);
		return NULL;
	}

	return rp;
}

/*
 * Compression task context.
 */

enum qrt_compress_magic {
	QRT_COMPRESS_MAGIC = 0xcbb0a7ac
};
#define QRT_TICK_CHUNK		256			/**< Chunk size per tick */

struct qrt_compress_context {
	enum qrt_compress_magic magic;	/**< Magic number */
	struct routing_patch *rp;		/**< Routing table being compressed */
	zlib_deflater_t *zd;			/**< Incremental deflater */
	bgdone_cb_t usr_done;			/**< User-defined callback */
	gpointer usr_arg;				/**< Arg for user-defined callback */
};

static GSList *sl_compress_tasks;

/**
 * Free compression context.
 */
static void
qrt_compress_free(gpointer u)
{
	struct qrt_compress_context *ctx = u;

	g_assert(ctx->magic == QRT_COMPRESS_MAGIC);

	if (ctx->zd) {
		zlib_deflater_free(ctx->zd, TRUE);
		ctx->zd = NULL;
	}
	ctx->magic = 0;
	wfree(ctx, sizeof *ctx);
}

/**
 * Perform incremental compression.
 */
static bgret_t
qrt_step_compress(struct bgtask *h, gpointer u, gint ticks)
{
	struct qrt_compress_context *ctx = u;
	gint ret;
	gint chunklen;
	gint status = 0;

	g_assert(ctx->magic == QRT_COMPRESS_MAGIC);

	chunklen = ticks * QRT_TICK_CHUNK;

	if (GNET_PROPERTY(qrp_debug) > 4)
		g_message("QRP qrt_step_compress: ticks = %d => chunk = %d bytes",
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

		if (GNET_PROPERTY(qrp_debug) > 2) {
			g_message("QRP patch: len=%d, compressed=%d (ratio %.2f%%)",
				ctx->rp->len, zlib_deflater_outlen(ctx->zd),
				100.0 * (ctx->rp->len - zlib_deflater_outlen(ctx->zd)) /
					ctx->rp->len);
			fflush(stdout);
		}

		if (zlib_deflater_outlen(ctx->zd) < ctx->rp->len) {
			struct routing_patch *rp = ctx->rp;

			g_assert(ROUTING_PATCH_MAGIC == rp->magic);
			G_FREE_NULL(rp->arena);
			rp->len = zlib_deflater_outlen(ctx->zd);
			rp->arena = g_memdup(zlib_deflater_out(ctx->zd), rp->len);
			rp->compressed = TRUE;
		}
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

/**
 * Called when the compress task is finished.
 *
 * This is really a wrapper on top of the user-supplied "done" callback
 * which lets us remove the task from the list.
 */
static void
qrt_patch_compress_done(struct bgtask *h, gpointer u, bgstatus_t status,
	gpointer unused_arg)
{
	struct qrt_compress_context *ctx = u;

	(void) unused_arg;
	g_assert(ctx->magic == QRT_COMPRESS_MAGIC);

	/*
	 * When status is BGS_KILLED, the task is being cancelled.
	 * This means we're iterating on the `sl_compress_tasks' list
	 * so don't alter it.
	 *		--RAM, 29/01/2003
	 */

	if (status != BGS_KILLED) {
		g_assert(g_slist_find(sl_compress_tasks, h));
		sl_compress_tasks = g_slist_remove(sl_compress_tasks, h);
	}

	(*ctx->usr_done)(h, u, status, ctx->usr_arg);
}

/**
 * Compress routing patch inplace (asynchronously).
 * When it's done, invoke callback with specified argument.
 *
 * @returns handle of the compressing task.
 */
static gpointer
qrt_patch_compress(
	struct routing_patch *rp,
	bgdone_cb_t done_callback, gpointer arg)
{
	struct qrt_compress_context *ctx;
	zlib_deflater_t *zd;
	struct bgtask *task;
	bgstep_cb_t step = qrt_step_compress;

	g_assert(ROUTING_PATCH_MAGIC == rp->magic);
	zd = zlib_deflater_make(rp->arena, rp->len, Z_DEFAULT_COMPRESSION);

	if (zd == NULL) {
		(*done_callback)(NULL, NULL, BGS_ERROR, arg);
		return NULL;
	}

	/*
	 * Because compression is possibly a CPU-intensive operation, it
	 * is dealt with a background task that will be scheduled at regular
	 * intervals.
	 */

	ctx = walloc0(sizeof *ctx);
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

/**
 * Create a new query routing table, with supplied `arena' and `slots'.
 * The value used for infinity is given as `max'.
 */
static struct routing_table *
qrt_create(const gchar *name, gchar *arena, gint slots, gint max)
{
	struct routing_table *rt;

	g_assert(slots > 0);
	g_assert(max > 0);
	g_assert(arena != NULL);

	rt = walloc(sizeof *rt);

	rt->magic = QRP_ROUTE_MAGIC;
	rt->name = g_strdup(name);
	rt->arena = (guchar *) arena;
	rt->slots = slots;
	rt->generation = generation++;
	rt->refcnt = 0;
	rt->infinity = max;
	rt->compacted = FALSE;
	rt->digest = NULL;
	rt->reset = FALSE;

	qrt_compact(rt);

	gnet_prop_set_guint32_val(PROP_QRP_GENERATION, (guint32) rt->generation);
	gnet_prop_set_guint32_val(PROP_QRP_MEMORY,
		GNET_PROPERTY(qrp_memory) + slots / 8);

	if (GNET_PROPERTY(qrp_debug) > 2)
		rt->digest = atom_sha1_get(qrt_sha1(rt));

	if (GNET_PROPERTY(qrp_debug) > 1)
		g_message("QRP \"%s\" ready: gen=%d, slots=%d, SHA1=%s",
			rt->name, rt->generation, rt->slots,
			rt->digest ? sha1_base32(rt->digest) : "<not computed>");

	return rt;
}

/**
 * Create small empty table.
 */
static struct routing_table *
qrt_empty_table(const gchar *name)
{
	gchar *arena;

	arena = g_malloc(EMPTY_TABLE_SIZE);
	memset(arena, LOCAL_INFINITY, EMPTY_TABLE_SIZE);

	return qrt_create(name, arena, EMPTY_TABLE_SIZE, LOCAL_INFINITY);
}

/**
 * Free query routing table.
 */
static void
qrt_free(struct routing_table *rt)
{
	g_assert(rt->refcnt == 0);

	atom_sha1_free_null(&rt->digest);
	G_FREE_NULL(rt->arena);
	G_FREE_NULL(rt->name);

	gnet_prop_set_guint32_val(PROP_QRP_MEMORY,
	  GNET_PROPERTY(qrp_memory) - (rt->compacted ? rt->slots / 8 : rt->slots));

	rt->magic = 0;				/* Prevent accidental reuse */
	wfree(rt, sizeof *rt);
}

/**
 * Shrink arena inplace to use only `new_slots' instead of `old_slots'.
 * The memory area is also shrunk and the new location of the arena is
 * returned.
 */
static gpointer
qrt_shrink_arena(gchar *arena, gint old_slots, gint new_slots, gint infinity)
{
	gint factor;		/* Shrink factor */
	gint ratio;
	gint i, j;

	g_assert(old_slots > new_slots);
	g_assert(is_pow2(old_slots));
	g_assert(is_pow2(new_slots));

	ratio = highest_bit_set(old_slots) - highest_bit_set(new_slots);

	g_assert(ratio >= 0);

	factor = 1 << ratio;

	/*
	 * The shrinking algorithm: an entry is "set" to contain something if
	 * any of the "factor" entries in the larger table contain something.
	 */

	for (i = 0, j = 0; i < new_slots && j < old_slots; i++, j += factor) {
		gint k;
		gint set = FALSE;

		for (k = 0; k < factor && !set; k++) {
			if ((guchar) arena[j + k] != infinity)
				set = TRUE;
		}

		arena[i] = set ? 0 : infinity;
	}

	return g_realloc(arena, new_slots);
}

/**
 * @returns the query routing table, NULL if not computed yet.
 */
struct routing_table *
qrt_get_table(void)
{
	return routing_table;
}

/**
 * Get a new reference on the query routing table.
 * @returns its argument.
 */
struct routing_table *
qrt_ref(struct routing_table *rt)
{
	g_assert(rt);
	g_assert(rt->magic == QRP_ROUTE_MAGIC);

	rt->refcnt++;
	return rt;
}

/**
 * Remove one reference to query routing table.
 * When the last reference is removed, the table is freed.
 */
void
qrt_unref(struct routing_table *rt)
{
	g_assert(rt);
	g_assert(rt->magic == QRP_ROUTE_MAGIC);
	g_assert(rt->refcnt > 0);

	if (--rt->refcnt == 0)
		qrt_free(rt);
}

/**
 * @returns information about query routing table.
 */
void
qrt_get_info(const struct routing_table *rt, qrt_info_t *qi)
{
	g_assert(rt);
	g_assert(rt->magic == QRP_ROUTE_MAGIC);
	g_assert(rt->refcnt > 0);

	qi->slots = rt->slots;
	qi->generation = rt->generation;
	qi->fill_ratio = rt->fill_ratio;
	qi->pass_throw = rt->pass_throw;
}

/***
 *** Merging of the leaf node QRP tables into `merged_table'.
 ***/

static struct bgtask *merge_comp;		/* Background table merging handle */

enum merge_magic {
	MERGE_MAGIC	= 0xe39ee39e
};

struct merge_context {
	enum merge_magic magic;
	GSList *tables;				/* Leaf routing tables */
	guchar *arena;				/* Working arena (not compacted) */
	gint slots;					/* Amount of slots used for merged table */
};

static struct merge_context *merge_ctx;

/**
 * Free merge context.
 */
static void
merge_context_free(gpointer p)
{
	struct merge_context *ctx = p;
	GSList *sl;

	g_assert(ctx->magic == MERGE_MAGIC);

	merge_comp = NULL;		/* Task is being terminated */
	merge_ctx = NULL;

	for (sl = ctx->tables; sl; sl = g_slist_next(sl)) {
		struct routing_table *rt = sl->data;

		qrt_unref(rt);
	}
	g_slist_free(ctx->tables);

	G_FREE_NULL(ctx->arena);
	ctx->magic = 0;
	wfree(ctx, sizeof *ctx);
}

/**
 * Fetch the list of all the QRT from our leaves.
 */
static bgret_t
mrg_step_get_list(struct bgtask *unused_h, gpointer u, gint unused_ticks)
{
	struct merge_context *ctx = u;
	const GSList *sl;
	gint max_size = 0;			/* Max # of slots seen in all QRT */

	(void) unused_h;
	(void) unused_ticks;
	g_assert(MERGE_MAGIC == ctx->magic);

	for (sl = node_all_nodes(); sl; sl = g_slist_next(sl)) {
		struct gnutella_node *dn = sl->data;
		struct routing_table *rt = dn->recv_query_table;

		if (rt == NULL || !NODE_IS_LEAF(dn))
			continue;

		/*
		 * Do not include leaves whose hops-flow is set to a value less
		 * than NODE_LEAF_MIN_FLOW because they are not fully searcheable
		 * by remote ultrapeers.
		 *		--RAM, 2007-05-23
		 */

		if (dn->hops_flow < NODE_LEAF_MIN_FLOW)
			continue;

		/*
		 * At this point we're snapshoting the list of tables and we take
		 * a reference on the table of the node.  Later on, the node can be
		 * removed, but then we'll know because we'll be the only one
		 * referencing the table!
		 */

		ctx->tables = g_slist_prepend(ctx->tables, qrt_ref(rt));

		if (max_size < rt->slots)
			max_size = rt->slots;
	}

	/* No valid table can have 0 slots! */
	g_assert(max_size > 0 || ctx->tables == NULL);

	ctx->slots = max_size;
	if (max_size > 0) {
		ctx->arena = g_malloc(max_size);
		memset(ctx->arena, LOCAL_INFINITY, max_size);
	}

	return BGR_NEXT;
}

/**
 * Merge routing table into specified arena.
 *
 * @param rt is the routing table to merge
 * @param arena is a non-compacted arena
 * @param slots is the number of slots in the arena
 */
static void
merge_table_into_arena(struct routing_table *rt, guchar *arena, gint slots)
{
	gint ratio;
	gint expand;
	gint i;

	/*
	 * By construction, the size of the arena is the max of all the sizes
	 * of the QRT tables, so the size of the routing table to merge can only
	 * be smaller than the arena size.
	 */

	g_assert(rt->slots <= slots);
	g_assert(rt->compacted);
	g_assert(is_pow2(slots));
	g_assert(is_pow2(rt->slots));

	ratio = highest_bit_set(slots) - highest_bit_set(rt->slots);

	g_assert(ratio >= 0);

	expand = 1 << ratio;

	g_assert(rt->slots * expand <= slots);	/* Won't overflow */

	/*
	 * Loop over the supplied QRT, and expand each slot `expand' times into
	 * the arena, doing an "OR" merging.
	 */

	for (i = 0; i < rt->slots; i++) {
		gboolean value = RT_SLOT_READ(rt->arena, i);

		if (value != 0) {				/* "0 OR x = x" -- no change */
			memset(&arena[i * expand], 0, expand);	/* Less than "infinity" */
		}
	}
}

/**
 * Merge next leaf QRT table if node is still there.
 */
static bgret_t
mrg_step_merge_one(struct bgtask *unused_h, gpointer u, gint ticks)
{
	struct merge_context *ctx = u;
	gint ticks_used = 0;

	(void) unused_h;
	g_assert(MERGE_MAGIC == ctx->magic);

	/*
	 * If we're no longer running in UP mode, we can end this task
	 * immediately.
	 */

	if (GNET_PROPERTY(current_peermode) != NODE_P_ULTRA)
		return BGR_DONE;

	while (ctx->tables != NULL && ticks_used < ticks) {
		struct routing_table *rt = ctx->tables->data;

		ctx->tables = g_slist_remove(ctx->tables, rt);

		/*
		 * If we're the only referer to this table, it means the node is
		 * dead and therefore this table should be skipped.
		 */

		if (rt->refcnt > 1) {
			merge_table_into_arena(rt, ctx->arena, ctx->slots);
			ticks_used++;
		}

		qrt_unref(rt);
	}

	return (ctx->tables == NULL) ? BGR_NEXT : BGR_MORE;
}

/**
 * Create and install the table.
 */
static bgret_t
mrg_step_install_table(struct bgtask *unused_h, gpointer u, gint unused_ticks)
{
	struct merge_context *ctx = u;

	(void) unused_h;
	(void) unused_ticks;
	g_assert(MERGE_MAGIC == ctx->magic);

	/*
	 * Make sure we're still running in UP mode... otherwise, it does
	 * not make sense.
	 */

	if (GNET_PROPERTY(current_peermode) == NODE_P_ULTRA) {
		struct routing_table *mt;
		if (ctx->slots != 0)
			mt = qrt_create("Merged table",
				cast_to_gpointer(ctx->arena), ctx->slots, LOCAL_INFINITY);
		else {
			g_assert(ctx->arena == NULL);
			mt = qrt_empty_table("Empty merged table");
		}
		ctx->arena = NULL;			/* Don't free arena when freeing context */
		install_merged_table(mt);
	}

	return BGR_DONE;
}

static bgstep_cb_t merge_steps[] = {
	mrg_step_get_list,
	mrg_step_merge_one,
	mrg_step_install_table,
};

/**
 * Launch asynchronous merging of the leaf node QRT tables.
 *
 * @param done_cb is the routine to invoke when merging is done.  If NULL, then
 * no routine is called.
 */
static void
mrg_compute(bgdone_cb_t done_cb)
{
	struct merge_context *ctx;

	g_assert(merge_ctx == NULL);	/* No computation active */

	ctx = walloc0(sizeof *ctx);
	ctx->magic = MERGE_MAGIC;
	merge_ctx = ctx;

	merge_comp = bg_task_create("Leaf QRT merging",
		merge_steps, G_N_ELEMENTS(merge_steps),
		ctx, merge_context_free,
		done_cb, NULL);
}

/***
 *** Management of per-connection routing table.
 ***/

/**
 * This structure is opaque for nodes, and is installed as `query_routing'
 * information in the node structure.
 */
struct query_routing {
	struct routing_table *qrt;		/**< Current routing table */
	gchar *patch;					/**< Patching arena */
	gchar *patch_end;				/**< One byte of end of patching arena */
	gint state;						/**< State of the QRT propagation */
	gint bits_per_entry;			/**< Amount of bits per entry in patch */
	gint payload_size;				/**< Size of the PATCH message payload */
	gint seqno;						/**< Sequence number of next packet */
	gint max_seqno;					/**< Last sequence number to send */
};

/*
 * States.
 */

#define QRT_NONE			0		/**< No QRT sent yet */
#define QRT_SENDING			1		/**< Sending patches */
#define QRT_IDLE			2		/**< Finished send patches */

/***
 *** Construction of our own routing table.
 ***/

/*
 * Since the routing table is only used between a leaf and an ultranode,
 * the hop counts should be either 1 or INFINITY.
 */

#define DEFAULT_BUF_SIZE	512
#define MIN_BUF_GROW		256

static GHashTable *ht_seen_words;
static struct {
	gchar *arena;	/* g_malloc()ed */
	gint len;
} buffer;

static void qrp_cancel_computation(void);

/**
 * This routine must be called to initialize the computation of the new QRP
 * based on our local files.
 */
void
qrp_prepare_computation(void)
{
	qrp_cancel_computation();			/* Cancel any running computation */
	g_assert(ht_seen_words == NULL);	/* Not already in computation */

	ht_seen_words = g_hash_table_new(g_str_hash, g_str_equal);

	if (buffer.arena == NULL) {
		buffer.arena = g_malloc(DEFAULT_BUF_SIZE);
		buffer.len = DEFAULT_BUF_SIZE;
	}
}

/**
 * Add shared file to our QRP.
 */
void
qrp_add_file(struct shared_file *sf)
{
	word_vec_t *wovec;
	guint wocnt;
	guint i;

	g_assert(ht_seen_words != NULL);	/* Already in computation */
	g_assert(sf);

	/*
	 * Copy filename to buffer, since we're going to map it inplace.
	 */

	g_assert(utf8_is_valid_data(shared_file_name_nfc(sf),
				shared_file_name_nfc_len(sf)));
	g_assert(utf8_is_valid_data(shared_file_name_canonic(sf),
				shared_file_name_canonic_len(sf)));

	/*
	 * The words in the QRP must be lowercased, but the pre-computed canonic
	 * representation of the filename is already in lowercase form.
	 */

	wocnt = word_vec_make(shared_file_name_canonic(sf), &wovec);

	if (0 == wocnt)
		return;

	/*
	 * Identify unique words we have not already seen in `ht_seen_words'.
	 */

	for (i = 0; i < wocnt; i++) {
		const gchar *word = wovec[i].word;
		size_t word_len;

		g_assert(word[0] != '\0');
		word_len = strlen(word);

		/*
		 * Record word if we haven't seen it yet.
		 */

		if (g_hash_table_lookup(ht_seen_words, word)) {
			continue;
		} else {
			gpointer p;
			size_t n = 1 + word_len;

			p = wcopy(word, n);
			g_hash_table_insert(ht_seen_words, p, (gpointer) n);
		}

		if (GNET_PROPERTY(qrp_debug) > 8)
			g_message("new QRP word \"%s\" [from %s]",
				word, shared_file_name_nfc(sf));
	}

	word_vec_free(wovec, wocnt);

	/*
	 * If we have a SHA1 for this file, add it to the table as well.
	 */

	if (sha1_hash_available(sf)) {
		gchar key[256];

		sha1_to_urn_string_buf(shared_file_sha1(sf), key, sizeof key);
		if (NULL == g_hash_table_lookup(ht_seen_words, key)) {
			gpointer p;
			size_t n;

			n = 1 + strlen(key);
			p = wcopy(key, n);
			g_hash_table_insert(ht_seen_words, p, (gpointer) n);
		}
	}
}

/*
 * Hash table iterator callbacks
 */

static void
free_word(gpointer key, gpointer value, gpointer unused_udata)
{
	(void) unused_udata;
	g_assert(value);
	wfree(key, (size_t) value);
}

struct unique_substrings {		/* User data for unique_subtr() callback */
	GHashTable *unique;
	GSList *head;
};

static inline void
insert_substr(struct unique_substrings *u, const gchar *word)
{
	if (!g_hash_table_lookup(u->unique, word)) {
		gchar *s;
		size_t n;

		n = 1 + strlen(word);
		s = wcopy(word, n);
		g_hash_table_insert(u->unique, s, (gpointer) n);
		u->head = g_slist_prepend(u->head, s);
	}
}

/**
 * Iteration callback on the hashtable containing keywords.
 */
static void
unique_substr(gpointer key, gpointer unused_value, gpointer udata)
{
	struct unique_substrings *u = udata;
	const gchar *word = key;
	(void) unused_value;

	/*
	 * Special-case urn:sha1 entries: we insert them as a whole!
	 */

	if (is_strcaseprefix(word, "urn:sha1:")) {
		insert_substr(u, word);
	}  else {
		gchar *s;
		size_t len, size;


		/*
		 * Add all unique (i.e. not already seen) substrings from word, all
		 * anchored at the start, whose length range from 3 to the word length.
		 */

		len = strlen(word);
		size = len + 1;
		s = wcopy(word, size);

		for (;;) {
			insert_substr(u, s);
			
			while (len > QRP_MIN_WORD_LENGTH) {
				guint retlen;

				len--;
				if (utf8_decode_char_fast(&s[len], &retlen)) {
					s[len] = '\0';				/* Truncate word */
					break;
				}
			}
			if (len <= QRP_MIN_WORD_LENGTH)
				break;
		}
		WFREE_NULL(s, size);
	}
}

/**
 * Create a list of all unique substrings at least QRP_MIN_WORD_LENGTH long,
 * from words held in `ht'.
 *
 * @returns created list, and count in `retcount'.
 */
static GSList *
unique_substrings(GHashTable *ht, gint *retcount)
{
	struct unique_substrings u = { NULL, NULL };		/* Callback args */

	u.unique = g_hash_table_new(g_str_hash, g_str_equal);
	g_hash_table_foreach(ht, unique_substr, &u);
	*retcount = g_hash_table_size(u.unique);
	g_hash_table_destroy(u.unique);		/* Created words ref'ed by u.head */

	return u.head;
}

/*
 * Co-routine context.
 */

#define QRP_STEP_SUBSTRING	1	/**< Substring computation */
#define QRP_STEP_COMPUTE	2	/**< Compute QRT */
#define QRP_STEP_INSTALL	3	/**< Install new QRT */
#define QRP_STEP_LAST		3	/**< Last step */

enum qrp_magic {
	QRP_MAGIC = 0xc4b5975aU
};

struct qrp_context {
	enum qrp_magic magic;
	struct routing_table **rtp;	/**< Points to routing table variable to fill */
	struct routing_patch **rpp;	/**< Points to routing patch variable to fill */
	GSList *sl_substrings;		/**< List of all substrings */
	gint substrings;			/**< Amount of substrings */
	gchar *table;				/**< Computed routing table */
	gint slots;					/**< Amount of slots in table */
	struct routing_table *st;	/**< Smaller table */
	struct routing_table *lt;	/**< Larger table for merging (destination) */
	gint sidx;					/**< Source index in `st' */
	gint lidx;					/**< Merging index in `lt' */
	gint expand;				/**< Expansion ratio from `st' to `lt' */
};

static struct bgtask *qrp_comp;	/**< Background computation handle */
static struct bgtask *qrp_merge;/**< Background merging handle */

/**
 * Free the `ht_seen_words' table.
 */
static void
dispose_ht_seen_words(void)
{
	g_assert(ht_seen_words);

	g_hash_table_foreach(ht_seen_words, free_word, NULL);
	g_hash_table_destroy(ht_seen_words);
	ht_seen_words = NULL;
}

/**
 * Free query routing table computation context.
 */
static void
qrp_context_free(gpointer p)
{
	struct qrp_context *ctx = p;
	GSList *sl;

	g_assert(ctx->magic == QRP_MAGIC);

	/*
	 * The `ht_seen_words' table is not really part of our task context,
	 * but was filled only so that the task could perform its work.
	 * XXX put it in context, and clear global once inserted.
	 */

	if (ht_seen_words)
		dispose_ht_seen_words();

	for (sl = ctx->sl_substrings; sl; sl = g_slist_next(sl)) {
		gchar *word = sl->data;
		size_t size;

		size = 1 + strlen(word);
		g_assert(size > 0);
		wfree(word, size);
	}
	g_slist_free(ctx->sl_substrings);

	G_FREE_NULL(ctx->table);

	if (ctx->st)
		qrt_unref(ctx->st);
	if (ctx->lt)
		qrt_unref(ctx->lt);

	ctx->magic = 0;
	wfree(ctx, sizeof *ctx);
}

/**
 * Called when the QRP recomputation is done to free the context.
 */
static void
qrp_comp_context_free(gpointer p)
{
	qrp_comp = NULL;		/* If we're called, the task is being terminated */
	qrp_context_free(p);
}

/**
 * Called when the QRP merging is done to free the context.
 */
static void
qrp_merge_context_free(gpointer p)
{
	qrp_merge = NULL;		/* If we're called, the task is being terminated */
	qrp_context_free(p);
}

/**
 * Cancel current computation, if any.
 */
static void
qrp_cancel_computation(void)
{
	qrt_compress_cancel_all();

	if (qrp_comp) {
		bg_task_cancel(qrp_comp);
		qrp_comp = NULL;
	}

	if (qrp_merge) {
		bg_task_cancel(qrp_merge);
		qrp_merge = NULL;
	}
}

/**
 * Compute all the substrings we need to insert.
 */
static bgret_t
qrp_step_substring(struct bgtask *unused_h, gpointer u, gint unused_ticks)
{
	struct qrp_context *ctx = u;

	(void) unused_h;
	(void) unused_ticks;
	g_assert(ctx->magic == QRP_MAGIC);
	g_assert(ht_seen_words != NULL);	/* XXX Already in computation */

	ctx->sl_substrings = unique_substrings(ht_seen_words, &ctx->substrings);

	dispose_ht_seen_words();

	if (GNET_PROPERTY(qrp_debug) > 1)
		g_message("QRP unique subwords: %d", ctx->substrings);

	return BGR_NEXT;		/* All done for this step */
}

/**
 * Compare possibly compacted table `rt' with expanded table arena `arena'
 * having `slots' slots.
 *
 * @returns whether tables are identical.
 */
static gboolean
qrt_eq(const struct routing_table *rt, const gchar *arena, gint slots)
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

/**
 * Compute QRP table, iteration step.
 */
static bgret_t
qrp_step_compute(struct bgtask *h, gpointer u, gint unused_ticks)
{
	struct qrp_context *ctx = u;
	gchar *table = NULL;
	gint slots;
	gint bits;
	const GSList *sl;
	gint upper_thresh;
	gint hashed = 0;
	gint filled = 0;
	gint conflict_ratio;
	gboolean full = FALSE;

	(void) unused_ticks;
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

	for (sl = ctx->sl_substrings; sl; sl = g_slist_next(sl)) {
		const gchar *word = sl->data;
		guint idx = qrp_hash(word, bits);

		hashed++;

		if (table[idx] == LOCAL_INFINITY) {
			table[idx] = 1;
			filled++;
			if (GNET_PROPERTY(qrp_debug) > 7)
				g_message("QRP added subword: \"%s\"", word);
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

	conflict_ratio = ctx->substrings == 0 ? 0 :
		(gint) (100.0 * (ctx->substrings - filled) / ctx->substrings);

	if (GNET_PROPERTY(qrp_debug) > 1)
		g_message("QRP [seqno=%d] size=%d, filled=%d, hashed=%d, "
			"ratio=%d%%, conflicts=%d%%%s",
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
		if (GNET_PROPERTY(qrp_debug))
			g_message("QRP final table size: %d bytes", slots);

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
			if (GNET_PROPERTY(qrp_debug))
				g_message("no change in QRP table");
			G_FREE_NULL(table);
			bg_task_exit(h, 0);	/* Abort processing */
		}

		/*
		 * OK, we keep the table.
		 */

		ctx->table = table;
		ctx->slots = slots;

		return BGR_NEXT;		/* Done! */
	}

	G_FREE_NULL(table);

	return BGR_MORE;			/* More work required */
}

/**
 * Create the compacted routing table object.
 */
static bgret_t
qrp_step_create_table(struct bgtask *unused_h, gpointer u, gint unused_ticks)
{
	struct qrp_context *ctx = u;
	glong elapsed;

	(void) unused_h;
	(void) unused_ticks;
	g_assert(ctx->magic == QRP_MAGIC);
	g_assert(ctx->rtp != NULL);
	g_assert(ctx->rpp != NULL);

	/*
	 * Install new routing table and notify the nodes that it has changed.
	 */

	if (*ctx->rtp != NULL)
		qrt_unref(*ctx->rtp);

	*ctx->rtp = qrt_ref(qrt_create("Local table",
		ctx->table, ctx->slots, LOCAL_INFINITY));
	ctx->table = NULL;		/* Don't free table when freeing context */

	/*
	 * Now that a new routing table is available, we'll need a new routing
	 * patch against an empty table, to send to new connections.
	 */

	if (*ctx->rpp != NULL) {
		qrt_patch_unref(*ctx->rpp);
		*ctx->rpp = NULL;
	}

	elapsed = delta_time(tm_time(), (time_t) GNET_PROPERTY(qrp_timestamp));
	elapsed = MAX(0, elapsed);
	gnet_prop_set_guint32_val(PROP_QRP_COMPUTATION_TIME, elapsed);

	return BGR_NEXT;		/* Proceed to next step */
}

/**
 * Install the routing table we've built, if running as leaf.
 */
static bgret_t
qrp_step_install_leaf(struct bgtask *unused_h, gpointer u, gint unused_ticks)
{
	struct qrp_context *ctx = u;

	(void) unused_h;
	(void) unused_ticks;
	g_assert(ctx->magic == QRP_MAGIC);
	g_assert(ctx->rtp != NULL);
	g_assert(ctx->rpp != NULL);

	/*
	 * Default patch (stored in *ctx->rpp), is computed asynchronously.
	 *
	 * If we're a leaf node, we're done.  We have computed the local_table
	 * and can now start computing the default patch.
	 *
	 * If we're an ultra node, we need to first merge all the routing tables
	 * from our leaves with ours, before proceeding with the patch computation.
	 */

	if (GNET_PROPERTY(current_peermode) != NODE_P_ULTRA) {
		install_routing_table(*ctx->rtp);
		install_merged_table(NULL);			/* We're not an ultra node */
		qrt_patch_compute(routing_table, ctx->rpp);
		node_qrt_changed(routing_table);
		return BGR_DONE;		/* Done! */
	}

	return BGR_NEXT;		/* Proceed to next step */
}

/**
 * Wait for the `merged_table' to be ready.
 */
static bgret_t
qrp_step_wait_for_merged_table(struct bgtask *h, gpointer u, gint unused_ticks)
{
	struct qrp_context *ctx = u;
	gint ratio;

	(void) unused_ticks;
	g_assert(ctx->magic == QRP_MAGIC);

	/*
	 * If we switched to leaf mode, go on...  The next step will explicitly
	 * catch this.
	 */

	if (GNET_PROPERTY(current_peermode) != NODE_P_ULTRA)
		return BGR_NEXT;

	/*
	 * If the `merged_table' is not ready yet, we can't proceed with this
	 * task.  We need to wait for the thread computing the table, or start
	 * it if it's not running yet.
	 */

	if (merged_table == NULL) {
		if (merge_comp == NULL)		/* Task not started yet */
			mrg_compute(NULL);		/* Launch it */

		bg_task_ticks_used(h, 0);
		return BGR_MORE;			/* Switch to next task to run */
	}

	/*
	 * Prepare the iteration for the next step.
	 *
	 * Identify the smallest of the two tables, and put the smallest in `st'
	 * and the largest in `lt'.  Then compute the expansion factor between
	 * the two and allocate the arena for the merging.
	 */

	g_assert(local_table != NULL);
	g_assert(merged_table != NULL);

	if (local_table->slots < merged_table->slots) {
		ctx->slots = merged_table->slots;
		ctx->st = qrt_ref(local_table);
		ctx->lt = qrt_ref(merged_table);
	} else {
		ctx->slots = local_table->slots;
		ctx->st = qrt_ref(merged_table);
		ctx->lt = qrt_ref(local_table);
	}

	ratio = highest_bit_set(ctx->lt->slots) - highest_bit_set(ctx->st->slots);

	g_assert(ratio >= 0);		/* By construction, lt is larger than st */

	ctx->expand = 1 << ratio;
	ctx->sidx = ctx->lidx = 0;

	g_assert(ctx->table == NULL);

	ctx->table = g_malloc(ctx->slots);
	memset(ctx->table, LOCAL_INFINITY, ctx->slots);

	/* Ready for iterating */

	return BGR_NEXT;
}

/**
 * Merge `local_table' with `merged_table'.
 */
static bgret_t
qrp_step_merge_with_leaves(struct bgtask *unused_h, gpointer u, gint ticks)
{
	struct qrp_context *ctx = u;
	gint used;
	struct routing_table *st = ctx->st;
	struct routing_table *lt = ctx->lt;
	gint max;
	gint i = ctx->sidx;
	gint expand = ctx->expand;
	gint j;

	(void) unused_h;
	g_assert(ctx->magic == QRP_MAGIC);

	/*
	 * If we switched to leaf mode, go on...  The next step will explicitly
	 * catch this.
	 */

	if (GNET_PROPERTY(current_peermode) != NODE_P_ULTRA)
		return BGR_NEXT;

	g_assert(st != NULL && lt != NULL);
	g_assert(st->compacted);
	g_assert(lt->compacted);

	max = st->slots;

	for (used = 0; used < ticks && i < max; i++, used++, ctx->sidx++) {
		gboolean vs = RT_SLOT_READ(st->arena, i);

		/*
		 * Since `lt', the larger table, has the same size as the merged
		 * table, the `ctx->lidx' also points to the next area to be merged
		 * in the result.
		 */

		g_assert(ctx->lidx + expand <= lt->slots);	/* Won't overflow */

		for (j = 0; j < expand; j++) {
			gboolean vl = RT_SLOT_READ(lt->arena, ctx->lidx);
			if (vl || vs)
				ctx->table[ctx->lidx++] = 0;	/* Present, less than oo */
			else
				ctx->table[ctx->lidx++] = LOCAL_INFINITY;	/* Absent => oo */
		}
	}

	return (ctx->sidx < max) ? BGR_MORE : BGR_NEXT;
}

/**
 * Install the final routing table, and begin computation of the default
 * QRT patch for new connections.
 */
static bgret_t
qrp_step_install_ultra(struct bgtask *h, gpointer u, gint ticks)
{
	struct qrp_context *ctx = u;
	struct routing_table *rt;

	g_assert(ctx->magic == QRP_MAGIC);

	/*
	 * If we switched to leaf mode whilst processing, go on with the
	 * "leaf install" mode.
	 */

	if (GNET_PROPERTY(current_peermode) != NODE_P_ULTRA)
		return qrp_step_install_leaf(h, u, ticks);

	/*
	 * Since we exchange lots of inter-UP QRP tables, make sure they're not
	 * too big so that their patches remain small enough.  It does not matter
	 * much if they are more filled than leaf QRP tables!
	 *
	 * We only shrink before installing, since shrinking looses information
	 * and may make the resulting table more full than the original was.
	 * All our computations are therefore done internally using the highest
	 * table size.
	 */

	if (ctx->slots > MAX_UP_TABLE_SIZE) {
		ctx->table = qrt_shrink_arena(
			ctx->table, ctx->slots, MAX_UP_TABLE_SIZE, LOCAL_INFINITY);
		ctx->slots = MAX_UP_TABLE_SIZE;
	}

	/*
	 * Install merged table as `routing_table'.
	 */

	rt = qrt_create("Routing table", ctx->table, ctx->slots, LOCAL_INFINITY);
	ctx->table = NULL;			/* Don't free arena when freeing context */

	install_routing_table(rt);

	/*
	 * Activate default patch computation and tell them we got a new table...
	 */

	qrt_patch_compute(routing_table, ctx->rpp);
	node_qrt_changed(routing_table);

	return BGR_DONE;
}

static bgstep_cb_t qrp_compute_steps[] = {
	qrp_step_substring,
	qrp_step_compute,
	qrp_step_create_table,
	qrp_step_install_leaf,
	qrp_step_wait_for_merged_table,
	qrp_step_merge_with_leaves,
	qrp_step_install_ultra,
};

static bgstep_cb_t qrp_merge_steps[] = {
	qrp_step_wait_for_merged_table,
	qrp_step_merge_with_leaves,
	qrp_step_install_ultra,
};

/**
 * This routine must be called once all the files have been added to finalize
 * the computation of the new QRP.
 *
 * If the routing table has changed, the node_qrt_changed() routine will
 * be called once we have finished its computation.
 */
void
qrp_finalize_computation(void)
{
	struct qrp_context *ctx;

	/*
	 * Because QRP computation is possibly a CPU-intensive operation, it
	 * is dealt with as a coroutine that will be scheduled at regular
	 * intervals.
	 */

	ctx = walloc0(sizeof *ctx);
	ctx->magic = QRP_MAGIC;
	ctx->rtp = &local_table;	/* NOT routing_table, this is for local files */
	ctx->rpp = &routing_patch;

	gnet_prop_set_timestamp_val(PROP_QRP_TIMESTAMP, tm_time());

	qrp_comp = bg_task_create("QRP computation",
		qrp_compute_steps, G_N_ELEMENTS(qrp_compute_steps),
		ctx, qrp_comp_context_free,
		NULL, NULL);
}

/**
 * Proceed with table merging between `merge_table' and `local_table' into
 * `routing_table' if we're running as an ultra node, or install the
 * `local_table' as the `routing_table' if we're running as leaf.
 */
static void
qrp_update_routing_table(void)
{
	struct qrp_context *ctx;

	if (qrp_merge != NULL)
		bg_task_cancel(qrp_merge);

	g_assert(qrp_merge == NULL);
	g_assert(local_table != NULL);

	ctx = walloc0(sizeof *ctx);
	ctx->magic = QRP_MAGIC;
	ctx->rtp = &local_table;		/* In case we call qrp_step_install_leaf */
	ctx->rpp = &routing_patch;

	qrp_merge = bg_task_create("QRP merging",
		qrp_merge_steps, G_N_ELEMENTS(qrp_merge_steps),
		ctx, qrp_merge_context_free,
		NULL, NULL);
}

/**
 * Called as a task completion callback when the `merge_table' has been
 * recomputed, to relaunch the merging with `local_table' to get the final
 * routing table.
 */
static void
qrp_merge_routing_table(struct bgtask *unused_h, gpointer unused_c,
	bgstatus_t status, gpointer unused_arg)
{
	(void) unused_h;
	(void) unused_c;
	(void) unused_arg;

	if (status == BGS_KILLED)
		return;

	qrp_update_routing_table();
}

/**
 * Called when the current peermode has changed.
 */
void
qrp_peermode_changed(void)
{
	/*
	 * Make sure we won't send an invalid patch to new connections.
	 */

	if (routing_patch != NULL) {
		g_assert(ROUTING_PATCH_MAGIC == routing_patch->magic);
		qrt_patch_unref(routing_patch);
		routing_patch = NULL;
	}

	qrp_update_routing_table();
}

/***
 *** Computation of the routing patch against an empty table.
 ***/

enum qrt_patch_magic {
	QRT_PATCH_MAGIC	= 0xf347c237
};

struct qrt_patch_context {
	enum qrt_patch_magic magic;
	struct routing_patch **rpp;	/**< Pointer where final patch is stored */
	struct routing_patch *rp;	/**< Routing patch being compressed */
	struct routing_table *rt;	/**< Table against which patch is computed */
	struct bgtask *compress;	/**< The compression task */
};

typedef void (*qrt_patch_computed_cb_t)(gpointer arg, struct routing_patch *rp);

struct patch_listener_info {
	qrt_patch_computed_cb_t callback;
	gpointer arg;
};

static struct qrt_patch_context *qrt_patch_ctx;
static GSList *qrt_patch_computed_listeners;


/**
 * Callback invoked when the routing patch is computed.
 */
static void
qrt_patch_computed(struct bgtask *unused_h, gpointer unused_u,
	bgstatus_t status, gpointer arg)
{
	struct qrt_patch_context *ctx = arg;
	GSList *sl;

	(void) unused_h;
	(void) unused_u;
	g_assert(ctx->magic == QRT_PATCH_MAGIC);
	g_assert(ctx == qrt_patch_ctx);
	g_assert(ctx->rpp != NULL);

	if (GNET_PROPERTY(qrp_debug) > 2)
		g_message("QRP global default patch computed (status = %d)", status);

	qrt_patch_ctx = NULL;			/* Indicates that we're done */

	if (status == BGS_OK) {
		time_t now = tm_time();
		glong elapsed;

		if (*ctx->rpp != NULL)
			qrt_patch_unref(*ctx->rpp);

		*ctx->rpp = ctx->rp;

		elapsed = delta_time(now, (time_t) GNET_PROPERTY(qrp_patch_timestamp));
		elapsed = MAX(0, elapsed);
		gnet_prop_set_guint32_val(PROP_QRP_PATCH_COMPUTATION_TIME, elapsed);
		gnet_prop_set_guint32_val(PROP_QRP_PATCH_LENGTH,
			(guint32) ctx->rp->len);
		gnet_prop_set_guint32_val(PROP_QRP_PATCH_COMP_RATIO,
			(guint32) (100.0 *
			(GNET_PROPERTY(qrp_patch_raw_length)
				   - GNET_PROPERTY(qrp_patch_length))) /
						MAX(GNET_PROPERTY(qrp_patch_raw_length), 1));
	}

	ctx->magic = 0;					/* Prevent accidental reuse */

	/*
	 * Tell all our listeners that the routing patch is now available, or
	 * that an error occurred.
	 */

	for (sl = qrt_patch_computed_listeners; sl; sl = g_slist_next(sl)) {
		struct patch_listener_info *pi = sl->data;
		(*pi->callback)(pi->arg, *ctx->rpp);	/* NULL indicates failure */
		wfree(pi, sizeof *pi);
	}

	ctx->magic = 0;
	wfree(ctx, sizeof *ctx);

	g_slist_free(qrt_patch_computed_listeners);
	qrt_patch_computed_listeners = NULL;
}

/**
 * Record listener to callback with given argument when the default routing
 * patch will be ready.
 */
static gpointer
qrt_patch_computed_add_listener(qrt_patch_computed_cb_t cb, gpointer arg)
{
	struct patch_listener_info *pi;

	/*
	 * `qrt_patch_ctx' may be NULL: we may have finished a rescan, and
	 * be in the process of updating the routing table, but not yet in
	 * the process of computing the patch.
	 *
	 * That's alright, just register the listener.
	 */

	pi = walloc(sizeof *pi);

	pi->callback = cb;
	pi->arg = arg;

	qrt_patch_computed_listeners =
		g_slist_prepend(qrt_patch_computed_listeners, pi);

	return pi;
}

/**
 * Remove recorded listener.
 */
static void
qrt_patch_computed_remove_listener(gpointer handle)
{
	g_assert(qrt_patch_computed_listeners != NULL);

	qrt_patch_computed_listeners =
		g_slist_remove(qrt_patch_computed_listeners, handle);
}

/**
 * Cancel computation.
 */
static void
qrt_patch_cancel_compute(void)
{
	struct bgtask *comptask;

	g_assert(qrt_patch_ctx != NULL);

	comptask = qrt_patch_ctx->compress;
	bg_task_cancel(comptask);
	sl_compress_tasks = g_slist_remove(sl_compress_tasks, comptask);

	g_assert(qrt_patch_ctx == NULL);	/* qrt_patch_computed() called! */
	g_assert(qrt_patch_computed_listeners == NULL);
}

/**
 * Launch asynchronous computation of the default routing patch.
 *
 * @param rt is the table for which the default patch is computed.
 * @param rpp is a pointer to a variable where the final routing patch
 * is to be stored.
 */
static void
qrt_patch_compute(struct routing_table *rt, struct routing_patch **rpp)
{
	struct qrt_patch_context *ctx;

	/*
	 * Cancel computation if already active.
	 */

	if (qrt_patch_ctx != NULL)
		qrt_patch_cancel_compute();

	g_assert(qrt_patch_ctx == NULL);	/* No computation active */

	gnet_prop_set_timestamp_val(PROP_QRP_PATCH_TIMESTAMP, tm_time());

	qrt_patch_ctx = ctx = walloc(sizeof *ctx);

	ctx->magic = QRT_PATCH_MAGIC;
	ctx->rpp = rpp;
	ctx->rt = rt;
	ctx->rp = qrt_diff_4(NULL, rt);
	ctx->compress = qrt_patch_compress(ctx->rp, qrt_patch_computed, ctx);
}

/**
 * Cancel all running compression coroutines.
 */
static void
qrt_compress_cancel_all(void)
{
	GSList *sl;

	if (qrt_patch_ctx != NULL)
		qrt_patch_cancel_compute();

	for (sl = sl_compress_tasks; sl; sl = g_slist_next(sl))
		bg_task_cancel(sl->data);

	g_slist_free(sl_compress_tasks);
	sl_compress_tasks = NULL;
}

/***
 *** Sending of the QRP messages.
 ***/

/**
 * Send the RESET message, which must be sent before the PATCH sequence
 * to size the table.
 */
static void
qrp_send_reset(struct gnutella_node *n, gint slots, gint infinity)
{
	gnutella_msg_qrp_reset_t msg;
	gnutella_header_t *header = gnutella_msg_qrp_reset_header(&msg);

	g_assert(is_pow2(slots));
	g_assert(infinity > 0 && infinity < 256);

	message_set_muid(header, GTA_MSG_QRP);

	gnutella_header_set_function(header, GTA_MSG_QRP);
	gnutella_header_set_ttl(header, 1);
	gnutella_header_set_hops(header, 0);
	gnutella_header_set_size(header, sizeof msg - GTA_HEADER_SIZE);

	gnutella_msg_qrp_reset_set_variant(&msg, GTA_MSGV_QRP_RESET);
	gnutella_msg_qrp_reset_set_table_length(&msg, slots);
	gnutella_msg_qrp_reset_set_infinity(&msg, infinity);

	gmsg_sendto_one(n, &msg, sizeof msg);

	if (GNET_PROPERTY(qrp_debug) > 4)
		g_message("QRP sent RESET slots=%d, infinity=%d to %s",
			slots, infinity, node_addr(n));
}

/**
 * Send the PATCH message.
 *
 * The patch payload data is made of the `len' bytes starting at `buf'.
 */
static void
qrp_send_patch(struct gnutella_node *n,
	gint seqno, gint seqsize, gboolean compressed, gint bits,
	gchar *buf, gint len)
{
	gnutella_msg_qrp_patch_t *msg;
	guint msglen;

	g_assert(seqsize >= 1 && seqsize <= 255);
	g_assert(seqno >= 1 && seqno <= seqsize);
	g_assert(len >= 0 && len <= INT_MAX);

	/*
	 * Compute the overall message length.
	 */

	g_assert((size_t) len <= INT_MAX - sizeof *msg);
	msglen = len + sizeof *msg;
	msg = g_malloc(msglen);

	{
		gnutella_header_t *header = gnutella_msg_qrp_patch_header(msg);
		
		message_set_muid(header, GTA_MSG_QRP);
		gnutella_header_set_function(header, GTA_MSG_QRP);
		gnutella_header_set_ttl(header, 1);
		gnutella_header_set_hops(header, 0);
		gnutella_header_set_size(header, msglen - GTA_HEADER_SIZE);
	}

	gnutella_msg_qrp_patch_set_variant(msg, GTA_MSGV_QRP_PATCH);
	gnutella_msg_qrp_patch_set_seq_no(msg, seqno);
	gnutella_msg_qrp_patch_set_seq_size(msg, seqsize);
	gnutella_msg_qrp_patch_set_compressor(msg, compressed ? 0x1 : 0x0);
	gnutella_msg_qrp_patch_set_entry_bits(msg, bits);

	memcpy(cast_to_gchar_ptr(msg) + sizeof *msg, buf, len);

	gmsg_sendto_one(n, msg, msglen);

	G_FREE_NULL(msg);

	if (GNET_PROPERTY(qrp_debug) > 4)
		g_message("QRP sent PATCH #%d/%d (%d bytes) to %s",
			seqno, seqsize, len, node_addr(n));
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
	guchar *data;			/**< Points into node's message buffer */
	gint len;				/**< Length of data pointed at by `data' */
};

/**
 * Receive a RESET message and fill the `reset' structure with its payload.
 *
 * @returns TRUE if we read the message OK.
 */
static gboolean
qrp_recv_reset(struct gnutella_node *n, struct qrp_reset *reset)
{
	gconstpointer msg = n->data;

	g_assert(gnutella_qrp_reset_get_variant(msg) == GTA_MSGV_QRP_RESET);

	if (n->size != sizeof(gnutella_qrp_reset_t)) {
		gnet_stats_count_dropped(n, MSG_DROP_BAD_SIZE);
		return FALSE;
	}

	reset->table_length = gnutella_qrp_reset_get_table_length(msg);
	reset->infinity = gnutella_qrp_reset_get_infinity(msg);

	return TRUE;
}

/**
 * Receive a PATCH message and fill the `patch' structure with its payload.
 * @returns TRUE if we read the message OK.
 */
static gboolean
qrp_recv_patch(struct gnutella_node *n, struct qrp_patch *patch)
{
	gconstpointer msg = n->data;

	g_assert(gnutella_qrp_patch_get_variant(msg) == GTA_MSGV_QRP_PATCH);

	if (n->size <= sizeof(gnutella_qrp_patch_t)) {
		gnet_stats_count_dropped(n, MSG_DROP_BAD_SIZE);
		return FALSE;
	}

	patch->seq_no = gnutella_qrp_patch_get_seq_no(msg);
	patch->seq_size = gnutella_qrp_patch_get_seq_size(msg);
	patch->compressor = gnutella_qrp_patch_get_compressor(msg);
	patch->entry_bits = gnutella_qrp_patch_get_entry_bits(msg);

	/* Data start after header info */
	patch->data = (guchar *) msg + sizeof(gnutella_qrp_patch_t);
	patch->len = n->size - sizeof(gnutella_qrp_patch_t);

	g_assert(patch->len > 0);

	return TRUE;
}

/***
 *** Management of the updating sequence -- sending side.
 ***/

enum qrt_update_magic {
	QRT_UPDATE_MAGIC = 0x31912e13
};

#define QRT_PATCH_LEN		512		/**< Send 512 bytes at a time, if we can */
#define QRT_MAX_SEQSIZE		255		/**< Maximum: 255 messages */
#define QRT_MAX_BANDWIDTH	1024	/**< Max bandwidth if clogging occurs */
#define QRT_MIN_QUEUE_FILL  40		/**< Hold PATCH message if queue 40% full */

struct qrt_update {
	enum qrt_update_magic magic;
	struct gnutella_node *node;	 /**< Node for which we're sending */
	struct routing_patch *patch; /**< The patch to send */
	gint seqno;					 /**< Sequence number of next message (1..n) */
	gint seqsize;				 /**< Total amount of messages to send */
	gint offset;				 /**< Offset within patch */
	gpointer compress;			 /**< Compressing task (NULL = done) */
	gpointer listener;			 /**< Listener for default patch being ready */
	gint chunksize;				 /**< Amount to send within each PATCH */
	time_t last;				 /**< Time at which we sent the last batch */
	gint last_sent;				 /**< Amount sent during last batch */
	gboolean ready;				 /**< Ready for sending? */
	gboolean reset_needed;		 /**< Is the initial RESET needed? */
	gboolean empty_patch;		 /**< Was patch empty? */
};

/**
 * Callback invoked when the computed patch for a connection
 * has been compressed.
 */
static void
qrt_compressed(struct bgtask *unused_h, gpointer unused_u,
	bgstatus_t status, gpointer arg)
{
	struct qrt_update *qup = arg;
	struct routing_patch *rp;
	gint msgcount;

	(void) unused_h;
	(void) unused_u;
	g_assert(qup->magic == QRT_UPDATE_MAGIC);

	qup->compress = NULL;
	qup->ready = TRUE;

	if (status == BGS_KILLED)
		goto error;
	else if (status == BGS_ERROR) {		/* Error during processing */
		g_warning("could not compress query routing patch to send to %s",
			node_addr(qup->node));
		goto error;
	}

	if (!NODE_IS_WRITABLE(qup->node))
		goto error;

	/*
	 * In this routine, we reference the `routing_patch' global variable
	 * directly, because there can be only one default routing patch,
	 * whether we are an UP or a leaf, and it is the default patch that
	 * can be sent against a NULL table to bring them up-to-date wrt
	 * the `routing_table' table, our QRT (computed against local files
	 * only when we're a leaf, or the result of the merging of our local
	 * table for the local files and all the QRT of our leaves when we're
	 * running as an UP).
	 */

	/*
	 * If the computed patch for this connection is larger than the
	 * size of the default patch (against an empty table), send that
	 * one instead.  We'll need an extra RESET though.
	 */

	if (routing_patch != NULL && qup->patch->len > routing_patch->len) {
		if (GNET_PROPERTY(qrp_debug))
			g_warning("incremental query routing patch for node %s is %d "
				"bytes, bigger than the default patch (%d bytes) -- "
				"using latter",
				node_addr(qup->node), qup->patch->len, routing_patch->len);

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

	/*
	 * Although we referenced `routing_patch' freely above, we cannot
	 * reference `routing_table' here to get its size and infinity values.
	 * We MUST use the values from the computed routing patch, since the
	 * global routing table might have already been changed whilst we were
	 * compressing the patch: we'll send a stale patch, but that's OK.
	 *
	 * If the table size has grown since the time we started the patch
	 * computation, we'd send a bad size for the RESET and that could explain
	 * the bugs we've seen whereby UP <-> UP routing table updates fail with
	 * a message like "Incomplete 4-bit QRP patch covered 16384/65536 slots".
	 *
	 * This is more likely to happen for UP <-> UP updates because in an UP
	 * the recomputation of the routing table happens each time there is a
	 * change detected, but the bug was also latent for Leaf -> UP updates,
	 * although of course less frequent.
	 *
	 *		--RAM, 2006-07-28, hoping to have nailed down that bug
	 */

	if (qup->reset_needed)
		qrp_send_reset(qup->node, rp->size, rp->infinity);

	return;

error:
	if (qup->patch != NULL)
		qrt_patch_unref(qup->patch);
	qup->patch = NULL;			/* Signal error to qrt_update_send_next() */
	return;
}

/**
 * Default global routing patch (the one against a NULL table) is now
 * available for consumption.
 *
 * If we get a NULL pointer, it means the computation was interrupted or
 * that an error occurred.
 */
static void
qrt_patch_available(gpointer arg, struct routing_patch *rp)
{
	struct qrt_update *qup = arg;

	g_assert(qup->magic == QRT_UPDATE_MAGIC);

	if (GNET_PROPERTY(qrp_debug) > 2)
		g_message("QRP global routing patch %s (node %s)",
			rp == NULL ? "computation was cancelled" : "is now available",
			node_addr(qup->node));

	qup->listener = NULL;
	qup->patch = (rp == NULL) ? NULL : qrt_patch_ref(rp);

	qrt_compressed(NULL, NULL, rp == NULL ? BGS_ERROR : BGS_OK, qup);
}

/**
 * Create structure keeping track of the table update.
 * Call qrt_update_send_next() to send the next patching message.
 *
 * `query_table' is the table that was fully propagated to that node already.
 * It can be NULL if no table was fully propagated yet.
 *
 * NB: we become owner of the routing_patch, and it will be freed when the
 * created handle is destroyed.
 *
 * @return opaque handle.
 */
struct qrt_update *
qrt_update_create(struct gnutella_node *n, struct routing_table *query_table)
{
	struct qrt_update *qup;
	struct routing_table *old_table = query_table;

	g_assert(routing_table != NULL);

	/*
	 * If the old routing table and the new one do not have the same amount
	 * of slots, then we need to send the whole table again, meaning we'll
	 * need a RESET message to send the new table size.
	 */

	if (old_table != NULL) {
		struct routing_table *old = old_table;

		g_assert(old->magic == QRP_ROUTE_MAGIC);

		if (old->slots != routing_table->slots) {
			if (GNET_PROPERTY(qrp_debug))
				g_warning("old QRT for %s had %d slots, new one has %d",
					node_addr(n), old->slots, routing_table->slots);
			old_table = NULL;
		}
	}

	qup = walloc0(sizeof *qup);

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
			if (GNET_PROPERTY(qrp_debug) > 2)
				g_message(
					"QRP default routing patch is already there (node %s)",
					node_addr(n));

			qup->patch = qrt_patch_ref(routing_patch);
			qrt_compressed(NULL, NULL, BGS_OK, qup);
		} else {
			if (GNET_PROPERTY(qrp_debug) > 2)
				g_message("QRP must wait for routing patch (node %s)",
					node_addr(n));

			qup->listener =
				qrt_patch_computed_add_listener(qrt_patch_available, qup);
		}
	} else {
		/*
		 * The compression call may take a while, in the background.
		 * When compression is done, `qup->compress' will be set to NULL.
		 * If there are no differences, the patch will be NULL.
		 */

		qup->patch = qrt_diff_4(old_table, routing_table);
		if (qup->patch != NULL)
			qup->compress = qrt_patch_compress(qup->patch, qrt_compressed, qup);
		else {
			qup->empty_patch = TRUE;
			qup->ready = TRUE;
		}
	}

	return qup;
}

/**
 * Free query routing update tracker.
 */
void
qrt_update_free(struct qrt_update *qup)
{
	g_assert(qup->magic == QRT_UPDATE_MAGIC);

	if (qup->compress != NULL) {
		struct bgtask *task = qup->compress;
		bg_task_cancel(task);
		sl_compress_tasks = g_slist_remove(sl_compress_tasks, task);
	}

	g_assert(qup->compress == NULL);	/* Reset by qrt_compressed() */

	if (qup->listener)
		qrt_patch_computed_remove_listener(qup->listener);

	if (qup->patch)
		qrt_patch_unref(qup->patch);

	qup->magic = 0;						/* Prevent accidental reuse */
	wfree(qup, sizeof *qup);
}

/**
 * Send the next batch of data.
 * @returns whether the routing should still be called.
 */
gboolean
qrt_update_send_next(struct qrt_update *qup)
{
	time_t now;
	time_t elapsed;
	gint len;
	gint i;
	struct gnutella_node *n;

	g_assert(QRT_UPDATE_MAGIC == qup->magic);

	if (!qup->ready)				/* Still compressing or waiting */
		return TRUE;

	if (qup->patch == NULL)			/* An error occurred, or patch was empty */
		return FALSE;

	/*
	 * If queue is more than QRT_MIN_QUEUE_FILL percent full, then
	 * don't send a new patch message now, wait for it to flush a little.
	 */

	n = qup->node;

	g_assert(NODE_IS_CONNECTED(n));

	if (NODE_MQUEUE_PERCENT_USED(n) > QRT_MIN_QUEUE_FILL)
		return TRUE;

	/*
	 * Make sure we don't exceed the maximum bandwidth allocated for
	 * the QRP messages if the connection start clogging, i.e. if some
	 * bytes accumulate in the TX queue.
	 */

	now = tm_time();
	elapsed = delta_time(now, qup->last);

	if (elapsed <= 0)				/* We're called once every second */
		elapsed = 1;				/* So adjust */

	if (
		qup->last_sent / elapsed > QRT_MAX_BANDWIDTH &&
		NODE_MQUEUE_PENDING(n)
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

		g_assert(QRT_UPDATE_MAGIC == qup->magic);

		if (qup->offset + len >= qup->patch->len) {
			len = qup->patch->len - qup->offset;
			g_assert(qup->seqno == qup->seqsize);	/* Last message */
			g_assert(len > 0);
			g_assert(len <= qup->chunksize);
		}

		qrp_send_patch(n, qup->seqno++, qup->seqsize,
			qup->patch->compressed, qup->patch->entry_bits,
			(gchar *) qup->patch->arena + qup->offset, len);

		/*
		 * Break immediately if node is no longer connected, since then
		 * the QRT structure has been freed.  We MUST return TRUE as if
		 * the routine should be called again, but it won't since the
		 * node's QRT sending structure is gone.
		 *
		 * The reason for returning TRUE is that we don't want the caller
		 * to start performing any cleanup required when the sending of
		 * the QRT patches is complete.
		 *		--RAM, 2005-10-31
		 */

		if (!NODE_IS_CONNECTED(n))
			return TRUE;

		qup->offset += len;
		qup->last_sent += len;

		g_assert(qup->seqno <= qup->seqsize || qup->offset == qup->patch->len);

		/*
		 * Break the loop if we did not fully sent the last message, meaning
		 * the TCP connection has its buffer full.
		 */

		if (NODE_MQUEUE_COUNT(n))
			break;
	}

	qup->last = now;

	return qup->seqno <= qup->seqsize;
}

/**
 * Check whether sending was successful.
 * Should be called when qrt_update_send_next() returned FALSE.
 */
gboolean
qrt_update_was_ok(struct qrt_update *qup)
{
	g_assert(qup->magic == QRT_UPDATE_MAGIC);

	return qup->empty_patch ||
		(qup->patch != NULL && qup->seqno > qup->seqsize);
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

enum qrt_receive_magic {
	QRT_RECEIVE_MAGIC = 0x15efbb04
};
#define QRT_RECEIVE_BUFSIZE	4096		/**< Size of decompressing buffer */

struct qrt_receive {
	enum qrt_receive_magic magic;
	struct gnutella_node *node;		/**< Node for which we're receiving */
	struct routing_table *table;	/**< Table being built / updated */
	gint shrink_factor;		/**< 1 means none, `n' means coalesce `n' entries */
	gint seqsize;			/**< Amount of patch messages to expect */
	gint seqno;				/**< Sequence number of next message we expect */
	gint entry_bits;		/**< Amount of bits used by PATCH */
	z_streamp inz;			/**< Data inflater */
	gchar *data;			/**< Where inflated data is written */
	gint len;				/**< Length of the `data' buffer */
	gint current_slot;		/**< Current slot processed in patch */
	gint current_index;		/**< Current index (after shrinking) in QR table */
	gchar *expansion;		/**< Temporary expansion arena before shrinking */
	gboolean deflated;		/**< Is data deflated? */
	gboolean (*patch)(struct qrt_receive *qrcv, const guchar *data, gint len);
};

/**
 * A default handler that should never be called.
 *
 * @returns FALSE always.
 */
static gboolean
qrt_unknown_patch(struct qrt_receive *unused_qrcv,
	const guchar *unused_data, gint unused_len)
{
	(void) unused_qrcv;
	(void) unused_data;
	(void) unused_len;

	g_error("Patch application pointer uninitialized.");

	return FALSE;
}

/**
 * Create a new QRT receiving handler, to process all incoming QRP messages
 * from the leaf node.
 *
 * @param `n'			no brief description.
 * @param `query_table' The existing query table we have for the node.
 *
 * If `query_table' is NULL, it means we have no query table yet, and the
 * first QRP message will have to be a RESET.
 *
 * @returns pointer to handler.
 */
struct qrt_receive *
qrt_receive_create(struct gnutella_node *n, struct routing_table *query_table)
{
	struct routing_table *table = query_table;
	struct qrt_receive *qrcv;
	z_streamp inz;
	gint ret;

	g_assert(query_table == NULL || table->magic == QRP_ROUTE_MAGIC);
	g_assert(query_table == NULL || table->client_slots > 0);

	inz = walloc(sizeof *inz);

	inz->zalloc = zlib_alloc_func;
	inz->zfree = zlib_free_func;
	inz->opaque = NULL;

	ret = inflateInit(inz);

	if (ret != Z_OK) {
		wfree(inz, sizeof *inz);
		g_warning("unable to initialize QRP decompressor for node %s: %s",
			node_addr(n), zlib_strerror(ret));
		return NULL;
	}

	qrcv = walloc(sizeof *qrcv);

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
	qrcv->patch = qrt_unknown_patch;

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
		table->reset = FALSE;

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

/**
 * Dispose of the QRP receiving state.
 */
void
qrt_receive_free(struct qrt_receive *qrcv)
{
	g_assert(qrcv->magic == QRT_RECEIVE_MAGIC);

	(void) inflateEnd(qrcv->inz);
	wfree(qrcv->inz, sizeof *qrcv->inz);
	if (qrcv->table)
		qrt_unref(qrcv->table);
	if (qrcv->expansion)
		wfree(qrcv->expansion, qrcv->shrink_factor);
	G_FREE_NULL(qrcv->data);

	qrcv->magic = 0;			/* Prevent accidental reuse */
	wfree(qrcv, sizeof *qrcv);
}

/**
 * Apply raw patch data (uncompressed) to the current routing table.
 *
 * @returns TRUE on sucess, FALSE on error with the node being BYE-ed.
 */
static gboolean
qrt_apply_patch(struct qrt_receive *qrcv, const guchar *data, gint len)
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
	 * Make sure the received table is not full yet.  If that
	 * test fails, they have already sent more data than the
	 * advertised table size.
	 */

	if (len == 0)						/* No data, only zlib trailer */
		return TRUE;

	if (qrcv->current_index >= rt->slots) {
		struct gnutella_node *n = qrcv->node;
		g_warning("%s node %s <%s> overflowed its QRP patch of %s slots"
			" (spurious message?)", node_type(n), node_addr(n), node_vendor(n),
			compact_size(rt->client_slots,
				GNET_PROPERTY(display_metric_units)));
		node_bye_if_writable(n, 413, "QRP patch overflowed table (%s slots)",
			compact_size(rt->client_slots,
				GNET_PROPERTY(display_metric_units)));
		return FALSE;
	}

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
				gboolean val;

				g_assert(qrcv->current_index < rt->slots);

				val = RT_SLOT_READ(rt->arena, qrcv->current_index);

				for (k = 0; k < qrcv->shrink_factor; k++)
					qrcv->expansion[k] = val;

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
				guint8 val = 0x01;

				for (k = 0; k < qrcv->shrink_factor; k++) {
					if (qrcv->expansion[k]) {
						val = 0x80;
						break;
					}
				}

				g_assert(qrcv->current_index < rt->slots);

				qrt_patch_slot(rt, qrcv->current_index, val);

				qrcv->current_index++;
			}

			/*
			 * Make sure they are not providing us with more data than
			 * the table can hold.
			 */

			if ((guint) qrcv->current_slot >= rt->client_slots) {
				if (j != (epb - 1) || i != (len - 1)) {
					struct gnutella_node *n = qrcv->node;
					g_warning(
						"%s node %s <%s> overflowed its QRP patch of %s slots",
						node_type(n), node_addr(n), node_vendor(n),
						compact_size(rt->client_slots,
							GNET_PROPERTY(display_metric_units)));
					node_bye_if_writable(n, 413,
						"QRP patch overflowed table (%s slots)",
						compact_size(rt->client_slots,
							GNET_PROPERTY(display_metric_units)));
					return FALSE;
				}
			}
		}
	}

	return TRUE;
}

/**
 * Sanity checks at each patch reception.
 *
 * @return FALSE if there was an error reported and the patch message
 * must be ignored.
 */
static gboolean
qrt_patch_is_valid(struct qrt_receive *qrcv, gint len, gint slots_per_byte)
{
	struct routing_table *rt = qrcv->table;

	/*
	 * Make sure the received table is not full yet.  If that
	 * test fails, they have already sent more data than the
	 * advertised table size.
	 */

	if (qrcv->current_index >= rt->slots) {
		struct gnutella_node *n = qrcv->node;
		g_warning("%s node %s <%s> overflowed its QRP patch of %s slots"
			" (spurious message?)", node_type(n), node_addr(n), node_vendor(n),
			compact_size(rt->client_slots,
				GNET_PROPERTY(display_metric_units)));
		node_bye_if_writable(n, 413, "QRP patch overflowed table (%s slots)",
			compact_size(rt->client_slots,
				GNET_PROPERTY(display_metric_units)));
		return FALSE;
	}

	/*
	 * Make sure they are not providing us with more data than
	 * the table can hold.
	 */
	if ((guint) qrcv->current_slot + len * slots_per_byte > rt->client_slots) {
		struct gnutella_node *n = qrcv->node;
		g_warning(
			"%s node %s <%s> overflowed its QRP patch of %s slots",
			node_type(n), node_addr(n), node_vendor(n),
			compact_size(rt->client_slots,
				GNET_PROPERTY(display_metric_units)));
		node_bye_if_writable(n, 413, "QRP patch overflowed table (%s slots)",
			compact_size(rt->client_slots,
				GNET_PROPERTY(display_metric_units)));
		return FALSE;
	}
	
	return TRUE;
}

/**
 * Apply raw 8-bit patch data (uncompressed) to the current routing table.
 *
 * @returns TRUE on sucess, FALSE on error with the node being BYE-ed.
 */
static gboolean
qrt_apply_patch8(struct qrt_receive *qrcv, const guchar *data, gint len)
{
	struct routing_table *rt = qrcv->table;
	gint i;

	g_assert(qrcv->table != NULL);

	/* True for this variant of patch function. 8-bit, no expansion. */
	g_assert((gint)rt->client_slots == rt->slots);
	g_assert(qrcv->entry_bits == 8);
	g_assert(qrcv->shrink_factor == 1);

	if (len == 0)						/* No data, only zlib trailer */
		return TRUE;

	if (!qrt_patch_is_valid(qrcv, len, 1))
		return FALSE;

	g_assert(qrcv->current_index + len <= rt->slots);
	
	/*
	 * Compute the amount of entries per byte, and the initial reading mask.
	 */

	for (i = 0; i < len; i++) {
		/*
		 * The only possibilities for the patch are:
		 *
		 * . A negative value, to bring the slot value from infinity to 1.
		 * . A null value for no change.
		 * . A positive value to bring the slot back to infinity.
		 *
		 * In reality, for leaf<->ultrapeer QRT, what matters is presence.
		 * We consider everything that is less to infinity as being
		 * present, and therefore forget about the "hops-away" semantics
		 * of the QRT slot value.
		 */
		
		qrt_patch_slot(rt, qrcv->current_index++, data[i]);
	}
	qrcv->current_slot = qrcv->current_index - 1;

	return TRUE;
}


/**
 * Apply raw 4-bit patch data (uncompressed) to the current routing table.
 *
 * @returns TRUE on sucess, FALSE on error with the node being BYE-ed.
 */
static gboolean
qrt_apply_patch4(struct qrt_receive *qrcv, const guchar *data, gint len)
{
	struct routing_table *rt = qrcv->table;
	gint i;

	g_assert(qrcv->table != NULL);

	/* True for this variant of patch function. 8-bit, no expansion. */
	g_assert((gint)rt->client_slots == rt->slots);
	g_assert(qrcv->entry_bits == 4);
	g_assert(qrcv->shrink_factor == 1);

	if (len == 0)						/* No data, only zlib trailer */
		return TRUE;

	if (!qrt_patch_is_valid(qrcv, len, 2))
		return FALSE;

	g_assert(qrcv->current_index + len * 2 <= rt->slots);
	
	/*
	 * Compute the amount of entries per byte, and the initial reading mask.
	 */

	for (i = 0; i < len; i++) {
		guint8 v = data[i];	/* Patch byte contains `epb' slots */

		/*
		 * The only possibilities for the patch are:
		 *
		 * . A negative value, to bring the slot value from infinity to 1.
		 * . A null value for no change.
		 * . A positive value to bring the slot back to infinity.
		 *
		 * In reality, for leaf<->ultrapeer QRT, what matters is presence.
		 * We consider everything that is less to infinity as being
		 * present, and therefore forget about the "hops-away" semantics
		 * of the QRT slot value.
		 */
	
		qrt_patch_slot(rt, qrcv->current_index++, v & 0xf0);
		qrt_patch_slot(rt, qrcv->current_index++, (v << 4) & 0xf0);

	}
	qrcv->current_slot = qrcv->current_index - 1;

	return TRUE;
}

/**
 * Handle reception of QRP RESET.
 *
 * @returns TRUE if we handled the message correctly, FALSE if an error
 * was found and the node BYE-ed.
 */
static gboolean
qrt_handle_reset(
	struct gnutella_node *n, struct qrt_receive *qrcv, struct qrp_reset *reset)
{
	struct routing_table *rt;
	gint ret;
	gint slots;
	gint old_generation = -1;

	ret = inflateReset(qrcv->inz);
	if (ret != Z_OK) {
		g_warning("unable to reset QRP decompressor for node %s: %s",
			node_addr(n), zlib_strerror(ret));
		node_bye_if_writable(n, 500, "Error resetting QRP inflater: %s",
			zlib_strerror(ret));
		return FALSE;
	}

	/*
	 * If the advertized table size is not a power of two, good bye.
	 */

	if (!is_pow2(reset->table_length)) {
		g_warning("node %s <%s> sent us non power-of-two QRP length: %u",
			node_addr(n), node_vendor(n), reset->table_length);
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
			node_addr(n), node_vendor(n), (guint) reset->infinity);
		node_bye_if_writable(n, 413, "Invalid QRP infinity %u",
			(guint) reset->infinity);
		return FALSE;
	}

	/*
	 * Create new empty table, and set shrink_factor correctly in case
	 * the table's size exceeds our maximum size.
	 */

	node_qrt_discard(n);

	if (qrcv->table) {
		old_generation = qrcv->table->generation;
		qrt_unref(qrcv->table);
	}

	if (qrcv->expansion)
		wfree(qrcv->expansion, qrcv->shrink_factor);

	rt = qrcv->table = walloc(sizeof *rt);

	rt->magic = QRP_ROUTE_MAGIC;
	rt->name = g_strdup_printf("QRT node %s", node_addr(n));
	rt->refcnt = 1;
	rt->generation = old_generation + 1;
	rt->infinity = reset->infinity;
	rt->client_slots = reset->table_length;
	rt->compacted = TRUE;		/* We'll compact it on the fly */
	rt->digest = NULL;
	rt->reset = TRUE;

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

	if (GNET_PROPERTY(qrp_debug) && qrcv->shrink_factor > 1)
		g_warning("QRT from %s <%s> will be shrunk by a factor of %d",
			node_addr(n), node_vendor(n), qrcv->shrink_factor);

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

	gnet_prop_set_guint32_val(PROP_QRP_MEMORY,
		GNET_PROPERTY(qrp_memory) + slots);

	/*
	 * We're now ready to handle PATCH messages.
	 */

	return TRUE;
}

/**
 * Handle reception of QRP PATCH.
 *
 * @returns TRUE if we handled the message correctly, FALSE if an error
 * was found and the node BYE-ed.  Sets `done' to TRUE on the last message
 * from the sequence.
 */
static gboolean
qrt_handle_patch(
	struct gnutella_node *n, struct qrt_receive *qrcv, struct qrp_patch *patch,
	gboolean *done)
{
	/*
	 * If we don't have a routing table allocated, it means they never sent
	 * the RESET message, and no prior table was recorded.
	 */

	if (qrcv->table == NULL) {
		g_warning("node %s <%s> did not sent any QRP RESET before PATCH",
			node_addr(n), node_vendor(n));
		node_bye_if_writable(n, 413, "No QRP RESET received before PATCH");
		return FALSE;
	}

	/*
	 * Check that we're receiving the proper sequence.
	 */

	if (patch->seq_no != qrcv->seqno) {
		g_warning("%s node %s <%s> sent us invalid QRP seqno %u (expected %u)",
			node_type(n), node_addr(n), node_vendor(n),
			(guint) patch->seq_no, qrcv->seqno);
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
		qrcv->patch = qrt_apply_patch; /* Default handler. */

		switch (qrcv->entry_bits) {
		case 8:
			if (qrcv->shrink_factor == 1)
				qrcv->patch = qrt_apply_patch8;
			break;
		case 4:
			if (qrcv->shrink_factor == 1)
				qrcv->patch = qrt_apply_patch4;
			break;
		case 2:
			/* Use default handler. */
			break;
		case 1:	
			/* Use default handler. */
			break;
		default:
			g_warning("node %s <%s> sent invalid QRP entry bits %u for PATCH",
				node_addr(n), node_vendor(n), qrcv->entry_bits);
			node_bye_if_writable(n, 413, "Invalid QRP entry bits %u for PATCH",
				qrcv->entry_bits);
			return FALSE;
		}
	} else if (patch->seq_size != qrcv->seqsize) {
		g_warning("node %s <%s> changed QRP seqsize to %u at message #%d "
			"(started with %u)",
			node_addr(n), node_vendor(n),
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
		g_warning("%s node %s <%s> changed QRP patch entry bits to %u "
			"at message #%d (started with %u)",
			node_type(n), node_addr(n), node_vendor(n),
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
					"%s node %s <%s>: %s",
					(guint) patch->seq_no, (guint) patch->seq_size,
					node_type(n), node_addr(n), node_vendor(n),
					zlib_strerror(ret));
				node_bye_if_writable(n, 413,
					"QRP patch #%u/%u decompression failed: %s",
					(guint) patch->seq_no, (guint) patch->seq_size,
					zlib_strerror(ret));
				return FALSE;
			}

			if (
				!qrcv->patch(qrcv, (guchar *) qrcv->data,
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
				"%s node %s <%s>",
				(guint) patch->seq_no, (guint) patch->seq_size,
				node_type(n), node_addr(n), node_vendor(n));
			node_bye_if_writable(n, 413,
				"Early end of compressed QRP patch at #%u/%u",
				(guint) patch->seq_no, (guint) patch->seq_size);
			return FALSE;
		}
	} else if (!qrcv->patch(qrcv, patch->data, patch->len))
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
			g_warning("QRP %d-bit patch from %s node %s <%s> covered only "
				"%d/%d slots",
				qrcv->entry_bits, node_type(n),
				node_addr(n), node_vendor(n), qrcv->current_index, rt->slots);
			node_bye_if_writable(n, 413,
				"Incomplete %d-bit QRP patch covered %d/%d slots",
				qrcv->entry_bits, qrcv->current_index, rt->slots);
			return FALSE;
		}

		g_assert(qrcv->current_index == rt->slots);
		atom_sha1_free_null(&rt->digest);

		if (GNET_PROPERTY(qrp_debug) > 2)
			rt->digest = atom_sha1_get(qrt_sha1(rt));

		rt->fill_ratio = (gint) (100.0 * rt->set_count / rt->slots);

		/*
		 * If table is more than 5% full, each query will go through a
		 * random d100 throw, and will pass only if the score is below
		 * the value of the pass throw threshold.
		 *
		 * The function below quickly drops and then flattens:
		 *
		 *   x =  6%  -> throw = 84
		 *   x =  7%  -> throw = 79
		 *   x =  8%  -> throw = 75
		 *   x = 10%  -> throw = 69
		 *   x = 20%  -> throw = 53
		 *   x = 50%  -> throw = 27
		 *   x = 90%  -> throw = 6
		 *   x = 99%  -> throw = 2
		 *
		 * throw = 100 * (1 - (x - 0.05)^1/2.5)
		 *
		 * Function was adjusted to cut at 5% now instead of 1% since we
		 * now filter SHA1 queries via the QRP, so leaf traffic is far
		 * diminished.
		 *		--RAM, 03/01/2004
		 */

		if (rt->fill_ratio > 5)
			rt->pass_throw = (gint)
				(100.0 * (1 - pow((rt->fill_ratio - 5) / 100.0, 1/2.5)));
		else
			rt->pass_throw = 100;		/* Always forward if QRT says so */

		if (GNET_PROPERTY(qrp_debug) > 2)
			g_message("QRP got whole %d-bit patch "
				"(gen=%d, slots=%d (*%d), fill=%d%%, throw=%d) "
				"from %s %s <%s>: SHA1=%s",
				qrcv->entry_bits, rt->generation, rt->slots,
				qrcv->shrink_factor, rt->fill_ratio, rt->pass_throw,
				node_type(n), node_addr(n), node_vendor(n),
				rt->digest ? sha1_base32(rt->digest) : "<not computed>");

		/*
		 * Install the table in the node, if it was a new table.
		 * Otherwise, we only finished patching it.
		 */

		if (rt->reset)
			node_qrt_install(n, rt);
		else
			node_qrt_patched(n, rt);

		if (NODE_IS_LEAF(n))
			qrp_leaf_changed();

		if (GNET_PROPERTY(qrp_debug) > 1)
			(void) qrt_dump(stdout, rt, GNET_PROPERTY(qrp_debug) > 19);
	}

	return TRUE;
}

/**
 * Handle reception of the next QRP message in the stream for a given update.
 *
 * @returns whether we successfully handled the message.  If not, the node
 * has been signalled if needed, and may have been BYE-ed.
 *
 * When the last message from the sequence has been processed, set `done'
 * to TRUE.
 */
gboolean
qrt_receive_next(struct qrt_receive *qrcv, gboolean *done)
{
	struct gnutella_node *n = qrcv->node;
	guint8 type;

	g_assert(qrcv->magic == QRT_RECEIVE_MAGIC);
	g_assert(gnutella_header_get_function(&n->header) == GTA_MSG_QRP);

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
		/* FALL THROUGH */
	}

dropped:
	return TRUE;		/* Everything is fine, even if we dropped message */
}

static gboolean qrt_leaf_change_notified = FALSE;

/**
 * Called when we get a new QRT from a leaf node, or when we loose a leaf
 * that sent us its QRT.
 */
void
qrp_leaf_changed(void)
{
	qrt_leaf_change_notified = TRUE;
}

/**
 * Periodic monitor, to trigger recomputation of the merged table if we got
 * a new leaf with a QRT or lost a leaf which sent us its QRT.
 */
static void
qrp_monitor(cqueue_t *unused_cq, gpointer unused_obj)
{
	(void) unused_cq;
	(void) unused_obj;

	/*
	 * Re-install monitor for next time.
	 */

	monitor_ev = cq_insert(callout_queue,
		LEAF_MONITOR_PERIOD, qrp_monitor, NULL);

	/*
	 * If we're not running as an ultra node, or if the reconstruction thread
	 * is already running, don't bother...
	 */

	if (GNET_PROPERTY(current_peermode) != NODE_P_ULTRA || merge_comp != NULL)
		return;

	/*
	 * If we got notified of changes, relaunch the computation of the
	 * merge_table.
	 */

	if (qrt_leaf_change_notified) {
		qrt_leaf_change_notified = FALSE;
		mrg_compute(qrp_merge_routing_table);
	}
}

/**
 * Initialize QRP.
 */
void
qrp_init(void)
{
	/*
	 * Having a working hash function is critical.
	 * Check that the implementation is not broken by accident.
	 */

	g_assert(qrp_hash("ebcklmenq", 13) == 3527);
	g_assert(qrp_hash("ndflalem", 16) == 37658);
	g_assert(qrp_hash("7777a88a8a8a8", 10) == 342);

	test_hash();

	/*
	 * Install the periodic monitoring callback.
	 */

	monitor_ev = cq_insert(callout_queue,
		LEAF_MONITOR_PERIOD, qrp_monitor, NULL);

	/*
	 * Install an empty local table untill we compute our shared library.
	 */

	local_table = qrt_ref(qrt_empty_table("Empty local table"));
}

/**
 * Called at servent shutdown to reclaim all the memory.
 */
void
qrp_close(void)
{
	cq_cancel(callout_queue, &monitor_ev);
	qrp_cancel_computation();

	if (routing_table)
		qrt_unref(routing_table);

	if (routing_patch)
		qrt_patch_unref(routing_patch);

	if (local_table)
		qrt_unref(local_table);

	if (merged_table)
		qrt_unref(merged_table);

	G_FREE_NULL(buffer.arena);
}

/**
 * Used by qrt_dump().
 *
 * @returns whether a slot in the table is present or not.
 */
static gboolean
qrt_dump_is_slot_present(struct routing_table *rt, gint slot)
{
	g_assert(slot < rt->slots);

	if (!rt->compacted)
		return rt->arena[slot] < rt->infinity;

	return RT_SLOT_READ(rt->arena, slot);
}

/**
 * Dump QRT to specified file.
 * If `full' is true, we dump the whole table.
 *
 * @returns a unique 32-bit checksum.
 */
static guint32
qrt_dump(FILE *f, struct routing_table *rt, gboolean full)
{
	struct sha1 digest;
	SHA1Context ctx;
	gboolean last_status = FALSE;
	gint last_slot = 0;
	guint32 result;
	gint i;

	if (GNET_PROPERTY(qrp_debug) > 0) {
		fprintf(f, "------ Query Routing Table \"%s\" "
			"(gen=%d, slots=%d, %scompacted)\n",
			rt->name, rt->generation, rt->slots, rt->compacted ? "" : "not ");
	}

	SHA1Reset(&ctx);

	for (i = 0; i <= rt->slots; i++) {
		gboolean status = FALSE;
		guint8 value;

		if (i == rt->slots)
			goto final;

		status = qrt_dump_is_slot_present(rt, i);
		value = status ? 1 : 0;			/* 1 for presence */

		SHA1Input(&ctx, &value, sizeof value);

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

	SHA1Result(&ctx, cast_to_gpointer(&digest));

	/*
	 * Reduce SHA1 to a single guint32.
	 */

	result = sha1_hash(&digest);

	if (GNET_PROPERTY(qrp_debug) > 0) {
		fprintf(f, "------ End Routing Table \"%s\" "
			"(gen=%d, SHA1=%s, token=0x%x)\n",
			rt->name, rt->generation, sha1_base32(&digest), result);
	}

	return result;
}

/***
 *** Query routing management.
 ***/

/**
 * Allocate a query hash container for at most `size' entries.
 */
query_hashvec_t *
qhvec_alloc(guint size)
{
	query_hashvec_t *qhvec;

	size = MIN(QRP_HVEC_MAX, size);
	qhvec = walloc(sizeof *qhvec);

	qhvec->count = 0;
	qhvec->size = size;
	qhvec->has_urn = FALSE;
	qhvec->vec = walloc(size * sizeof qhvec->vec[0]);

	return qhvec;
}

/**
 * Dispose of the query hash container.
 */
void
qhvec_free(query_hashvec_t *qhvec)
{
	wfree(qhvec->vec, qhvec->size * sizeof qhvec->vec[0]);
	wfree(qhvec, sizeof *qhvec);
}

/**
 * Empty query hash container.
 */
void
qhvec_reset(query_hashvec_t *qhvec)
{
	qhvec->count = 0;
	qhvec->has_urn = FALSE;
}

/**
 * Clone query hash vector.
 */
query_hashvec_t *
qhvec_clone(const query_hashvec_t *qsrc)
{
	query_hashvec_t *qhvec;
	gint vecsize;

	g_assert(qsrc != NULL);

	qhvec = walloc(sizeof *qhvec);

	qhvec->count = qsrc->count;
	qhvec->size = qsrc->size;
	qhvec->has_urn = qsrc->has_urn;
	vecsize = qsrc->size * sizeof qhvec->vec[0];
	qhvec->vec = walloc(vecsize);

	memcpy(qhvec->vec, qsrc->vec, vecsize);

	return qhvec;
}

/**
 * Add the `word' coming from `src' into the query hash vector.
 * If the vector is already full, do nothing.
 */
void
qhvec_add(query_hashvec_t *qhvec, const gchar *word, enum query_hsrc src)
{
	struct query_hash *qh = NULL;

	if (qhvec->count >= qhvec->size)
		return;

	/*
	 * To make qrp_can_route() efficient, we put first the items that are
	 * optional (URNs) and last items that are mandatory (a word not matching
	 * means we don't have to continue since we AND words).  If we did not put
	 * optional items first, we'd still have to loop through all the words
	 * until we find an URN.  Also, a matching URN means we can route the
	 * the query immediately.
	 */

	switch (src) {
	case QUERY_H_URN:			/* Prepend */
		qhvec->has_urn = TRUE;
		if (qhvec->count)
			memmove(&qhvec->vec[1], &qhvec->vec[0],
				qhvec->count * sizeof(qhvec->vec[0]));
		qh = &qhvec->vec[0];
		break;
	case QUERY_H_WORD:			/* Append */
		qh = &qhvec->vec[qhvec->count];
		break;
	}

	g_assert(qh != NULL);

	qhvec->count++;
	qh->hashcode = qrp_hashcode(word);
	qh->source = src;
}

/**
 * Check whether we can route a query identified by its hash vector
 * to a node given its routing table.
 *
 * @param qhv			the query hit vector containing QRP hashes and types
 * @param rt			the routing table of the target node
 *
 * @note thie routine expects the query hash vector to be sorted with URNs
 * coming first and words later.
 */
static gboolean
qrp_can_route(const query_hashvec_t *qhv, const struct routing_table *rt)
{
	const struct query_hash *qh;
	const guint8 *arena;
	guint i, shift;
	gboolean has_urn;

	/*
	 * This routine is a hot spot when running as an ultra node.
	 * Prefetch constant items in local variables.
	 */

	arena = rt->arena;
	has_urn = qhv->has_urn;
	shift = 32 - rt->bits;
	qh = qhv->vec;

	for (i = 0; i < qhv->count; i++) {
		guint32 idx = qh[i].hashcode >> shift;

		/* Tight loop -- g_assert(idx < (guint32) rt->slots); */

		/*
		 * If there is an entry in the table and the source is an URN,
		 * we have to forward the query, as those are OR-ed.
		 * Otherwise, ALL the keywords must be present.
		 *
		 * When facing a SHA1 query, we require that at least one of the
		 * URN matches or we don't forward the query.
		 */

		if (RT_SLOT_READ(arena, idx)) {
			if (qh[i].source == QUERY_H_URN)	/* URN present */
				return TRUE;					/* Will forward */
			if (has_urn)						/* We passed all the URNs */
				return FALSE;					/* And none matched */
		} else {
			if (qh[i].source == QUERY_H_WORD) {	/* Word NOT present */
				/* We know no URN matched already because qhv is sorted */
				return FALSE;					/* All words did not match */
			}
		}
	}

	/*
	 * If we had no URN, all the words matched, so route query!
	 * If we had some URNs, none matched so don't forward.
	 */

	return !has_urn;
}

/**
 * Check whether we can route a query identified by its hash vector
 * to a node.
 */
gboolean
qrp_node_can_route(const gnutella_node_t *n, const query_hashvec_t *qhv)
{
	const struct routing_table *rt = n->recv_query_table;

	if (!NODE_IS_WRITABLE(n))
		return FALSE;

	/*
	 * If we did not get any table for an UP, act as if it did not
	 * support QRP-routing and send it everything.
	 */

	if (rt == NULL)
		return NODE_IS_LEAF(n) ? FALSE : TRUE;

	return qrp_can_route(qhv, rt);
}

/**
 * Compute list of nodes to send the query to, based on node's QRT.
 * The query is identified by its list of QRP hashes, by its hop count, TTL
 * and by its source node (so we don't send back the query where it
 * came from).
 *
 * @attention
 * NB: it is allowed to call this with TTL=0, in which case we won't
 * consider UPs for forwarding.  If TTL=1, we forward to all normal nodes
 * or UPs that don't support last-hop QRP, plus those whose QRP table says
 * they could bring a match.
 *
 * @returns list of nodes, a subset of the currently connected nodes.
 * Once used, the list of nodes can be freed with g_slist_free().
 */
GSList *
qrt_build_query_target(
	query_hashvec_t *qhvec, gint hops, gint ttl, struct gnutella_node *source)
{
	GSList *nodes = NULL;		/* Targets for the query */
	const GSList *sl;
	gboolean sha1_query;

	g_assert(qhvec != NULL);
	g_assert(hops >= 0);

	if (qhvec->count == 0) {
		if (GNET_PROPERTY(qrp_debug)) {
			if (source != NULL)
				g_warning("QRP %s had empty hash vector",
					gmsg_infostr(&source->header));
			else
				g_warning("QRP query [hops=%d] had empty hash vector", hops);
		}
		return NULL;
	}

	sha1_query = qhvec_has_urn(qhvec);

	/*
	 * We need to special case processing of queries with TTL=1 so that they
	 * get set to ultra peers that support last-hop QRP only if they can
	 * provide a reply.  Ultrapeers that don't support last-hop QRP will
	 * always get the query.
	 */

	for (sl = node_all_nodes(); sl; sl = g_slist_next(sl)) {
		struct gnutella_node *dn = sl->data;
		struct routing_table *rt = dn->recv_query_table;
		gboolean is_leaf;

		if (!NODE_IS_WRITABLE(dn))
			continue;

		if (hops >= dn->hops_flow)		/* Hops-flow prevents sending */
			continue;

		if (dn == source)		/* This is the node that sent us the query */
			continue;

		/*
		 * Look whether we can route the query to the peer (a leaf node or
		 * a last-hop QRP capable ultra node).
		 */

		is_leaf = NODE_IS_LEAF(dn);

		if (is_leaf) {
			/* Leaf node */
			if (rt == NULL)				/* No QRT yet */
				continue;				/* Don't send anything */
		} else {
			/* Ultra node */
			if (ttl != 1)				/* Only deal with last-hop UP */
				continue;
			if (rt == NULL)				/* UP has not sent us its table */
				goto can_send;			/* Forward everything then */
			if (!NODE_UP_QRP(dn))		/* QRP-unaware host? */
				goto can_send;			/* Broadcast to that node */
		}

		node_inc_qrp_query(dn);			/* We have a QRT, mark we try routing */

		if (!qrp_can_route(qhvec, rt))
			continue;

		if (!is_leaf)
			goto can_send;			/* Avoid indentation of remaining code */

		/*
		 * If table for the leaf node is so full that we can't let all the
		 * queries pass through, further restrict sending even though QRT says
		 * we can let it go.
		 *
		 * We only do that when there are pending messages in the node's queue,
		 * meaning we can't transmit all our packets fast enough.
		 */

		if (rt->pass_throw < 100 && NODE_MQUEUE_COUNT(dn) != 0) {
			if ((gint) (random_u32() % 100) >= rt->pass_throw)
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
			if (random_u32() % 256 >= 128)
				continue;
		}

		/*
		 * OK, can send the query to that node.
		 */

	can_send:
		nodes = g_slist_prepend(nodes, dn);
		if (rt != NULL)
			node_inc_qrp_match(dn);
	}

	return nodes;
}

/**
 * Route query message to leaf nodes, based on their QRT, or to ultrapeers
 * that support last-hop QRP if TTL=1.
 */
void
qrt_route_query(struct gnutella_node *n, query_hashvec_t *qhvec)
{
	GSList *nodes;				/* Targets for the query */

	g_assert(qhvec != NULL);
	g_assert(gnutella_header_get_function(&n->header) == GTA_MSG_SEARCH);

	nodes = qrt_build_query_target(qhvec,
				gnutella_header_get_hops(&n->header),
				gnutella_header_get_ttl(&n->header),
				n);

	if (nodes == NULL)
		return;

	if (GNET_PROPERTY(qrp_debug) > 4) {
		GSList *sl;
		gint leaves = 0;
		gint ultras = 0;

		for (sl = nodes; sl; sl = g_slist_next(sl)) {
			struct gnutella_node *dn = sl->data;

			if (NODE_IS_LEAF(dn))
				leaves++;
			else
				ultras++;
		}

		g_message(
			"QRP %s (%d word%s%s) forwarded to %d/%d leaves, %d ultra%s",
			gmsg_infostr(&n->header),
			qhvec->count, qhvec->count == 1 ? "" : "s",
			qhvec->has_urn ? " + URN" : "", leaves,
			GNET_PROPERTY(node_leaf_count),
			ultras, ultras == 1 ? "" : "s");
	}

	/*
	 * Now that the original TTL was used to build the node list, don't
	 * forget that we choose to forward queries that reach us with TTL=0
	 * to our leaves.  But we can never send out a TTL=0 message, so
	 * increase the TTL before sending.
	 */

	if (gnutella_header_get_ttl(&n->header) == 0)
		gnutella_header_set_ttl(&n->header, 1);

	gmsg_split_sendto_all(nodes, &n->header, n->data,
		n->size + GTA_HEADER_SIZE);

	g_slist_free(nodes);
}

/***
 *** Testing section.
 ***/

#ifdef TEST

#define CHECK(x)							\
G_STMT_START {								\
	if (!(x)) printf("FAILED: %s\n", #x);	\
	else printf("OK: %s\n", #x);			\
} G_STMT_END
#else /* !TEST */

#define CHECK(x) g_assert((x))
#endif /* TEST */

void
test_hash(void)
{
	static const struct {
		const guint32 s[16];
		const guint32 hash;
	} tests[] = {
		{ { 0x30a2, 0x30cb, 0x30e1, 0 }, 46 }, /* a-ni-me */
		{ { 0x30e9, 0 }, 0 }, /* ra */
		{ { 0x58f0, 0x512a, 0 }, 731 }, /* voice actor */
		{ { 0x10400, 0 }, 316 }, /* DESERET CAPITAL LETTER LONG I */
		{ { 0x10428, 0 }, 658 }, /* DESERET SMALL LETTER LONG I */
		{ { 0x0001, 0x0028, 0 }, 658 }, /* Same as above because "& 0xff" */
		{ { 0xff01, 0x9428, 0 }, 658 }, /* Same as above because "& 0xff" */
		{ { 0x1001, 0x2000, 0 }, 316 },
	};
	guint i;

	CHECK(qrp_hash("", 13)==0);
	CHECK(qrp_hash("eb", 13)==6791);
	CHECK(qrp_hash("ebc", 13)==7082);
	CHECK(qrp_hash("ebck", 13)==6698);
	CHECK(qrp_hash("ebckl", 13)==3179);
	CHECK(qrp_hash("ebcklm", 13)==3235);
	CHECK(qrp_hash("ebcklme", 13)==6438);
	CHECK(qrp_hash("ebcklmen", 13)==1062);
	CHECK(qrp_hash("ebcklmenq", 13)==3527);
	CHECK(qrp_hash("", 16)==0);
	CHECK(qrp_hash("n", 16)==65003);
	CHECK(qrp_hash("nd", 16)==54193);
	CHECK(qrp_hash("ndf", 16)==4953);
	CHECK(qrp_hash("ndfl", 16)==58201);
	CHECK(qrp_hash("ndfla", 16)==34830);
	CHECK(qrp_hash("ndflal", 16)==36910);
	CHECK(qrp_hash("ndflale", 16)==34586);
	CHECK(qrp_hash("ndflalem", 16)==37658);
	CHECK(qrp_hash("FAIL", 16)!=37458);	/* Note the != */
	CHECK(qrp_hash("ndflaleme", 16)==45559);
	CHECK(qrp_hash("ol2j34lj", 10)==318);
	CHECK(qrp_hash("asdfas23", 10)==503);
	CHECK(qrp_hash("9um3o34fd", 10)==758);
	CHECK(qrp_hash("a234d", 10)==281);
	CHECK(qrp_hash("a3f", 10)==767);
	CHECK(qrp_hash("3nja9", 10)==581);
	CHECK(qrp_hash("2459345938032343", 10)==146);
	CHECK(qrp_hash("7777a88a8a8a8", 10)==342);
	CHECK(qrp_hash("asdfjklkj3k", 10)==861);
	CHECK(qrp_hash("adfk32l", 10)==1011);
	CHECK(qrp_hash("zzzzzzzzzzz", 10)==944);

	CHECK(qrp_hash("3nja9", 10)==581);

	/* Non-ASCII test cases */
	for (i = 0; i < G_N_ELEMENTS(tests); i++) {
		gchar buf[1024];
		size_t n;
		guint32 h;

		n = utf32_to_utf8(tests[i].s, buf, G_N_ELEMENTS(buf));
		g_assert(n < G_N_ELEMENTS(buf));

		h = qrp_hash(buf, 10);
		if (h != tests[i].hash) {
			g_warning("qrp_hash() failed: i=%d, h=%u, buf=\"%s\"", i, h, buf);
			g_assert_not_reached();
		}
	}

}

/* vi: set ts=4 sw=4 cindent: */
