/*
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

#ifdef I_MATH
#include <math.h>
#endif	/* I_MATH */

#include <zlib.h>

#include "qrp.h"
#include "gmsg.h"
#include "gnet_stats.h"
#include "nodes.h"					/* For NODE_IS_WRITABLE() */
#include "routing.h"				/* For message_set_muid() */
#include "search.h"					/* For search_compact() */
#include "settings.h"
#include "share.h"

#include "lib/atoms.h"
#include "lib/bg.h"
#include "lib/cq.h"
#include "lib/glib-missing.h"
#include "lib/endian.h"
#include "lib/halloc.h"
#include "lib/hashing.h"
#include "lib/hset.h"
#include "lib/htable.h"
#include "lib/pow2.h"
#include "lib/random.h"
#include "lib/sha1.h"
#include "lib/str.h"
#include "lib/stringify.h"
#include "lib/tm.h"
#include "lib/unsigned.h"
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

#define qrp_debugging(lvl)	G_UNLIKELY(GNET_PROPERTY(qrp_debug) > (lvl))

struct query_hash {
	uint32 hashcode;
	enum query_hsrc source;
};

struct query_hashvec {
	struct query_hash *vec;	/**< Vector of at most `size' entries */
	uint8 count;			/**< Amount of slots actually taken */
	uint8 size;				/**< Amount of slots in vector */
	uint8 has_urn;			/**< Whether an URN is present in the query */
	uint8 whats_new;		/**< Query is "What's New?", must be forwarded */
};

bool
qhvec_has_urn(const struct query_hashvec *qhv)
{
	return 0 != qhv->has_urn;
}

bool
qhvec_whats_new(const struct query_hashvec *qhv)
{
	return 0 != qhv->whats_new;
}

void
qhvec_set_whats_new(struct query_hashvec *qhv, bool val)
{
	qhv->whats_new = booleanize(val);
}

uint
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
	QRP_ROUTE_MAGIC	= 0x72aa4886
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
	int refcnt;				/**< Amount of references */
	int generation;			/**< Generation number */
	uint8 *arena;			/**< Where table starts */
	int slots;				/**< Amount of slots in table */
	int infinity;			/**< Value for "infinity" */
	uint32 client_slots;	/**< Only for received tables, for shrinking ctrl */
	int bits;				/**< Amount of bits used in table size (received) */
	int set_count;			/**< Amount of slots set in table */
	int fill_ratio;			/**< 100 * fill ratio for table (received) */
	int pass_throw;			/**< Query must pass a d100 throw to be forwarded */
	const struct sha1 *digest;	/**< SHA1 digest of the whole table (atom) */
	char *name;				/**< Name for dumping purposes */
	unsigned reset:1;		/**< This is a new table, after a RESET */
	unsigned compacted:1;	/**< Table was compacted */
	unsigned cancelled:1;	/**< Must supersede with next version */
	/**
	 * Whether this routing table can route the given URN query.
	 */
	bool (*can_route_urn)(const query_hashvec_t *,
							  const struct routing_table *rt);
	/**
	 * Whether this routing table can route the keyword query.
	 */
	bool (*can_route)(const query_hashvec_t *,
						  const struct routing_table *rt);
};

enum routing_patch_magic {
	ROUTING_PATCH_MAGIC = 0x011906cf
};

/**
 * A routing table patch.
 */
struct routing_patch {
	enum routing_patch_magic magic;
	int refcnt;				/**< Amount of references */
	uint8 *arena;
	int size;				/**< Number of entries in table */
	int infinity;			/**< Value of infinity for the table patched */
	int len;				/**< Length of arena in bytes */
	int entry_bits;
	bool compressed;
};

static struct routing_table *routing_table; /**< Our table */
static struct routing_patch *routing_patch; /**< Against empty table */
static struct routing_table *local_table;   /**< Table for local files */
static struct routing_table *merged_table;  /**< From all our leaves */
static int generation;

static void qrt_compress_cancel_all(void);
static void qrt_patch_compute(
	struct routing_table *rt, struct routing_patch **rpp);
static uint32 qrt_dump(struct routing_table *rt, bool full);
void test_hash(void);

static bool
qrp_can_route_default(const query_hashvec_t *qhv,
					  const struct routing_table *rt);

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

	gnet_prop_set_guint32_val(PROP_QRP_SLOTS, (uint32) rt->slots);
	gnet_prop_set_guint32_val(PROP_QRP_SLOTS_FILLED, (uint32) rt->set_count);
	gnet_prop_set_guint32_val(PROP_QRP_FILL_RATIO,
		(uint32) (100.0 * rt->set_count / rt->slots));
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
static inline uint32
qrp_hashcode(const char *s)
{
	uint32 x = 0;		/* The running total */
	uint32 uc;
	uint j;				/* The bit position in xor */

	/*
	 * First turn x[0...end-1] into a number by treating all 4-byte
	 * chunks as a little-endian quadword, and XOR'ing the result together.
	 * We pad x with zeroes as needed.
	 *
	 * To avoid having do deal with special cases, we do this by XOR'ing
	 * a rolling value one byte at a time, taking advantage of the fact that
	 * x XOR 0==x.
	 */

	for (j = 0; '\0' != (uc = (uchar) *s); j = (j + 8) & 24) {
		uint retlen;

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

	return x * GOLDEN_RATIO_31;		/* Must keep only lowest 31 bits */
}

/**
 * For tests only
 *
 * The hashing function, defined by the QRP specifications.
 * Naturally, everyone must use the SAME hashing function!
 */
static inline uint32
qrp_hash(const char *s, int bits)
{
	return qrp_hashcode(s) >> (32 - bits);
}

/***
 *** Routing table management.
 ***/

/*
 * Following inline versions for benchmarking purposes.
 *
 * Code should use RT_SLOT_READ() only.
 */

static inline unsigned
RT_SLOT_READ_div(const uint8 *arena, uint i)
{
	static const uint8 mask[] = {
		0x80, 0x40, 0x20, 0x10, 0x8, 0x4, 0x2, 0x1 };
	div_t r = div(i, 8);
	return 0 != (arena[r.quot] & mask[r.rem]);
}

static inline unsigned
RT_SLOT_READ_div2(const uint8 *arena, uint i)
{
	static const uint8 mask[] = {
		0x80, 0x40, 0x20, 0x10, 0x8, 0x4, 0x2, 0x1 };
	unsigned q, r;
	q = i / 8;
	r = i % 8;
	return 0 != (arena[q] & mask[r]);
}

static inline unsigned
RT_SLOT_READ_lut(const uint8 *arena, uint i)
{
	static const uint8 mask[] = {
		0x80, 0x40, 0x20, 0x10, 0x8, 0x4, 0x2, 0x1 };
	return 0 != (arena[i >> 3] & mask[i & 0x7]);
}

static inline unsigned
RT_SLOT_READ_shift_right(const uint8 *arena, uint i)
{
	return 0 != (arena[i >> 3] & (0x80U >> (i & 0x7)));
}

static inline unsigned
RT_SLOT_READ_shift_left(const uint8 *arena, uint i)
{
	return 0 != (arena[i >> 3] & (1U << (~i & 0x7)));
}

static inline unsigned
RT_SLOT_READ_and1(const uint8 *arena, uint i)
{
	return 1U & (arena[i >> 3] >> (~i & 0x7));
}

static inline unsigned
RT_SLOT_READ_and128(const uint8 *arena, uint i)
{
	return 0 != (0x80U & (arena[i >> 3] << (i & 0x7)));
}

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
static inline bool
RT_SLOT_READ(const uint8 *arena, uint i)
{
	/* Hopefully the fastest version: 1 memory access, 5 shift/mask/cmp ops */

	return RT_SLOT_READ_and128(arena, i);
}

/**
 * In a compressed routing table, patch entry ``i'' with ``v'', the value
 * we got from the routing patch.
 *
 * As a side effect, increment rt->set_count if the position ``i'' ends-up
 * being set after patching.
 */
static inline G_GNUC_HOT ALWAYS_INLINE void
qrt_patch_slot(struct routing_table *rt, uint i, uint8 v)
{
	uint b = 0x80U >> (i & 0x7);

	if (v) {
		if (v & 0x80) {				/* Negative value -> set bit */
			rt->arena[i >> 3] |= b;
			rt->set_count++;
		} else { 					/* Positive value -> clear bit */
			rt->arena[i >> 3] &= ~b;
		}
	} else {
		/* else... unchanged. */
		if (rt->arena[i >> 3] & b) {
			rt->set_count++;		/* Bit was already set, kept that way */
		}
	}
}

/**
 * Compact routing table in place so that only one bit of information is used
 * per entry, reducing memory requirements by a factor of 8.
 */
static void
qrt_compact(struct routing_table *rt)
{
	int nsize;				/* New table size */
	char *narena;			/* New arena */
	int i;
	uint mask;
	uchar *p;
	uchar *q;
	uint32 token = 0;

	g_assert(rt);
	g_assert(rt->slots >= 8);
	g_assert(0 == (rt->slots & 0x7));	/* Multiple of 8 */
	g_assert(!rt->compacted);

	if (qrp_debugging(4)) {
		g_debug("QRP dumping QRT before compaction...");
		token = qrt_dump(rt, GNET_PROPERTY(qrp_debug) > 19);
	}

	nsize = rt->slots / 8;
	narena = halloc0(nsize);
	rt->set_count = 0;
	q = ptr_add_offset(narena, nsize - 1);

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

	g_assert((char *) (q+1) == narena);/* Filled 1st byte at last iteration */

	/*
	 * Install new compacted arena in place of the non-compacted one.
	 */

	HFREE_NULL(rt->arena);
	rt->arena = (uchar *) narena;
	rt->compacted = TRUE;

	if (qrp_debugging(4)) {
		uint32 token2;
		g_debug("QRP dumping QRT after compaction...");
		token2 = qrt_dump(rt, GNET_PROPERTY(qrp_debug) > 19);

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
	int i;
	int bytes;
	uint8 vector[8];
	uint8 *p;

	g_assert(rt->compacted);

	bytes = rt->slots / 8;
	SHA1Reset(&ctx);

	for (i = 0, p = rt->arena; i < bytes; i++) {
		int j;
		uint8 mask;
		uint8 value = *p++;

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
	HFREE_NULL(rp->arena);
	rp->magic = 0;
	WFREE(rp);
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
	int bytes;
	struct routing_patch *rp;
	uchar *op;
	uchar *np;
	uchar *pp;
	int i;
	bool changed = FALSE;

	g_assert(old == NULL || old->magic == QRP_ROUTE_MAGIC);
	g_assert(old == NULL || old->compacted);
	g_assert(new->magic == QRP_ROUTE_MAGIC);
	g_assert(new->compacted);
	g_assert(old == NULL || new->slots == old->slots);

	WALLOC(rp);
	rp->magic = ROUTING_PATCH_MAGIC;
	rp->refcnt = 1;
	rp->size = new->slots;
	rp->infinity = new->infinity;
	rp->len = rp->size / 2;			/* Each entry stored on 4 bits */
	rp->entry_bits = 4;
	rp->compressed = FALSE;
	pp = rp->arena = halloc(rp->len);

	op = old ? old->arena : NULL;
	np = new->arena;

	for (i = 0, bytes = new->slots / 8; i < bytes; i++) {
		uint8 obyte = op ? *op++ : 0x0;	/* Nothing */
		uint8 nbyte = *np++;
		int j;
		uint8 v;

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
			uint8 mask = 1 << j;

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
	QRT_COMPRESS_MAGIC = 0x4bb0a7ac
};
#define QRT_TICK_CHUNK		256			/**< Chunk size per tick */

struct qrt_compress_context {
	enum qrt_compress_magic magic;	/**< Magic number */
	struct routing_patch *rp;		/**< Routing table being compressed */
	zlib_deflater_t *zd;			/**< Incremental deflater */
	bgdone_cb_t usr_done;			/**< User-defined callback */
	void *usr_arg;					/**< Arg for user-defined callback */
};

static GSList *sl_compress_tasks;

/**
 * Free compression context.
 */
static void
qrt_compress_free(void *u)
{
	struct qrt_compress_context *ctx = u;

	g_assert(ctx->magic == QRT_COMPRESS_MAGIC);

	if (ctx->zd) {
		zlib_deflater_free(ctx->zd, TRUE);
		ctx->zd = NULL;
	}
	ctx->magic = 0;
	WFREE(ctx);
}

/**
 * Perform incremental compression.
 */
static bgret_t
qrt_step_compress(struct bgtask *h, void *u, int ticks)
{
	struct qrt_compress_context *ctx = u;
	int ret;
	int chunklen;
	int status = 0;

	g_assert(ctx->magic == QRT_COMPRESS_MAGIC);

	chunklen = ticks * QRT_TICK_CHUNK;

	if (qrp_debugging(4)) {
		g_debug("QRP qrt_step_compress: ticks = %d => chunk = %d bytes",
			ticks, chunklen);
	}

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

		if (qrp_debugging(1)) {
			g_debug("QRP patch: len=%d, compressed=%d (ratio %.2f%%)",
				ctx->rp->len, zlib_deflater_outlen(ctx->zd),
				100.0 * (ctx->rp->len - zlib_deflater_outlen(ctx->zd)) /
					ctx->rp->len);
		}

		if (zlib_deflater_outlen(ctx->zd) < ctx->rp->len) {
			struct routing_patch *rp = ctx->rp;

			g_assert(ROUTING_PATCH_MAGIC == rp->magic);
			HFREE_NULL(rp->arena);
			rp->len = zlib_deflater_outlen(ctx->zd);
			rp->arena = hcopy(zlib_deflater_out(ctx->zd), rp->len);
			rp->compressed = TRUE;
		}
		zlib_deflater_free(ctx->zd, TRUE);
		ctx->zd = NULL;
		goto done;
		/* NOTREACHED */
	case 1:						/* More work required */
		break;
	default:
		g_assert_not_reached();	/* Bug in zlib_deflate() */
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
qrt_patch_compress_done(struct bgtask *h, void *u, bgstatus_t status,
	void *unused_arg)
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
static void *
qrt_patch_compress(
	struct routing_patch *rp,
	bgdone_cb_t done_callback, void *arg)
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

	WALLOC0(ctx);
	ctx->magic = QRT_COMPRESS_MAGIC;
	ctx->rp = rp;
	ctx->zd = zd;
	ctx->usr_done = done_callback;
	ctx->usr_arg = arg;

	gnet_prop_set_guint32_val(PROP_QRP_PATCH_RAW_LENGTH, (uint32) rp->len);

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
qrt_create(const char *name, char *arena, int slots, int max)
{
	struct routing_table *rt;

	g_assert(slots > 0);
	g_assert(max > 0);
	g_assert(arena != NULL);

	WALLOC0(rt);

	rt->magic         = QRP_ROUTE_MAGIC;
	rt->name          = h_strdup(name);
	rt->arena         = (uchar *) arena;
	rt->slots         = slots;
	rt->generation    = generation++;
	rt->refcnt        = 0;
	rt->infinity      = max;
	rt->compacted     = FALSE;
	rt->digest        = NULL;
	rt->reset         = FALSE;
	rt->can_route_urn = qrp_can_route_default;
	rt->can_route     = qrp_can_route_default;

	qrt_compact(rt);

	gnet_prop_set_guint32_val(PROP_QRP_GENERATION, (uint32) rt->generation);
	gnet_prop_set_guint32_val(PROP_QRP_MEMORY,
		GNET_PROPERTY(qrp_memory) + slots / 8);

	if (qrp_debugging(2))
		rt->digest = atom_sha1_get(qrt_sha1(rt));

	if (qrp_debugging(1)) {
		g_debug("QRP \"%s\" ready: gen=%d, slots=%d, SHA1=%s",
			rt->name, rt->generation, rt->slots,
			rt->digest ? sha1_base32(rt->digest) : "<not computed>");
	}

	return rt;
}

/**
 * Create small empty table.
 */
static struct routing_table *
qrt_empty_table(const char *name)
{
	char *arena;

	arena = halloc(EMPTY_TABLE_SIZE);
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
	HFREE_NULL(rt->arena);
	HFREE_NULL(rt->name);

	gnet_prop_set_guint32_val(PROP_QRP_MEMORY,
	  GNET_PROPERTY(qrp_memory) - (rt->compacted ? rt->slots / 8 : rt->slots));

	rt->magic = 0;				/* Prevent accidental reuse */
	WFREE(rt);
}

/**
 * Shrink arena inplace to use only `new_slots' instead of `old_slots'.
 * The memory area is also shrunk and the new location of the arena is
 * returned.
 */
static void *
qrt_shrink_arena(char *arena, int old_slots, int new_slots, int inf_val)
{
	int factor;		/* Shrink factor */
	int ratio;
	int i, j;

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
		int k;
		int set = FALSE;

		for (k = 0; k < factor && !set; k++) {
			if ((uchar) arena[j + k] != inf_val)
				set = TRUE;
		}

		arena[i] = set ? 0 : inf_val;
	}

	return hrealloc(arena, new_slots);
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
	MERGE_MAGIC	= 0x639ee39eU
};

struct merge_context {
	enum merge_magic magic;
	GSList *tables;				/* Leaf routing tables */
	uchar *arena;				/* Working arena (not compacted) */
	int slots;					/* Amount of slots used for merged table */
};

static struct merge_context *merge_ctx;

/**
 * Free merge context.
 */
static void
merge_context_free(void *p)
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
	gm_slist_free_null(&ctx->tables);

	HFREE_NULL(ctx->arena);
	ctx->magic = 0;
	WFREE(ctx);
}

/**
 * Fetch the list of all the QRT from our leaves.
 */
static bgret_t
mrg_step_get_list(struct bgtask *unused_h, void *u, int unused_ticks)
{
	struct merge_context *ctx = u;
	const GSList *sl;
	int max_size = 0;			/* Max # of slots seen in all QRT */

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
		 * If table is so small to be useless, don't merge it.
		 */

		if (rt->slots <= 8)
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
		ctx->arena = halloc(max_size);
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
merge_table_into_arena(struct routing_table *rt, uchar *arena, int slots)
{
	int ratio;
	int expand;
	int i;
	int b;
	int bytes;

	/*
	 * By construction, the size of the arena is the max of all the sizes
	 * of the QRT tables, so the size of the routing table to merge can only
	 * be smaller than the arena size.
	 */

	g_assert(rt->slots <= slots);
	g_assert(rt->compacted);
	g_assert(is_pow2(slots));
	g_assert(is_pow2(rt->slots));
	g_assert(rt->slots >= 8);

	ratio = highest_bit_set(slots) - highest_bit_set(rt->slots);

	g_assert(ratio >= 0);

	expand = 1 << ratio;
	bytes = rt->slots / 8;

	g_assert(rt->slots * expand <= slots);	/* Won't overflow */

	/*
	 * Loop over the supplied QRT, and expand each slot `expand' times into
	 * the arena, doing an "OR" merging.
	 *
	 * Since this is going to be a tight loop, try to optimize the smallest
	 * expansion factors by avoiding memset() calls.
	 *
	 * Furthermore, we avoid repeated RT_SLOT_READ() calls by accessing the
	 * compacted table one byte at a time and then looping on each of its bits.
	 */

#define RT_FOR_EACH_BIT_SET(ON_CHANGE)				\
for (b = 0, i = 0; b < bytes; b++) {				\
	uint8 entry = rt->arena[b];						\
	unsigned mask = 0x80;							\
													\
	do {											\
		/* "0 OR x = x", hence skip unset bits */	\
		if (entry & mask) {							\
			ON_CHANGE								\
		}											\
		i++;										\
		mask >>= 1;									\
	} while (mask);									\
}

	switch (expand) {
	case 1:
		RT_FOR_EACH_BIT_SET(
			arena[i] = 0;		/* less than "inf" => indicates presence */
		);
		break;
	case 2:
		RT_FOR_EACH_BIT_SET(
			size_t j = i * 2;
			arena[j++] = 0;		/* less than "inf" => indicates presence */
			arena[j] = 0;
		);
		break;
	case 4:
		RT_FOR_EACH_BIT_SET(
			size_t j = i * 4;
			arena[j++] = 0;		/* less than "inf" => indicates presence */
			arena[j++] = 0;
			arena[j++] = 0;
			arena[j] = 0;
		);
		break;
	case 8:
		RT_FOR_EACH_BIT_SET(
			size_t j = i * 8;
			arena[j++] = 0;		/* less than "inf" => indicates presence */
			arena[j++] = 0;
			arena[j++] = 0;
			arena[j++] = 0;
			arena[j++] = 0;
			arena[j++] = 0;
			arena[j++] = 0;
			arena[j] = 0;
		);
		break;
	case 16:
		RT_FOR_EACH_BIT_SET(
			/* 0 is less than "infinity" => indicates presence */
			memset(&arena[i * 16], 0, 16);
		);
		break;
	case 32:
		RT_FOR_EACH_BIT_SET(
			/* 0 is less than "infinity" => indicates presence */
			memset(&arena[i * 32], 0, 32);
		);
		break;
	default:
		RT_FOR_EACH_BIT_SET(
			/* 0 is less than "infinity" => indicates presence */
			memset(&arena[i * expand], 0, expand);
		);
		break;
	}

#undef RT_FOR_EACH_BIT_SET
}

/**
 * Merge next leaf QRT table if node is still there.
 */
static bgret_t
mrg_step_merge_one(struct bgtask *unused_h, void *u, int ticks)
{
	struct merge_context *ctx = u;
	int ticks_used = 0;

	(void) unused_h;
	g_assert(MERGE_MAGIC == ctx->magic);

	/*
	 * If we're no longer running in UP mode, we can end this task
	 * immediately.
	 */

	if (!settings_is_ultra())
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
mrg_step_install_table(struct bgtask *unused_h, void *u, int unused_ticks)
{
	struct merge_context *ctx = u;

	(void) unused_h;
	(void) unused_ticks;
	g_assert(MERGE_MAGIC == ctx->magic);

	/*
	 * Make sure we're still running in UP mode... otherwise, it does
	 * not make sense.
	 */

	if (settings_is_ultra()) {
		struct routing_table *mt;
		if (ctx->slots != 0)
			mt = qrt_create("Merged table",
				cast_to_pointer(ctx->arena), ctx->slots, LOCAL_INFINITY);
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

	WALLOC0(ctx);
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
	char *patch;					/**< Patching arena */
	char *patch_end;				/**< One byte of end of patching arena */
	int state;						/**< State of the QRT propagation */
	int bits_per_entry;			/**< Amount of bits per entry in patch */
	int payload_size;				/**< Size of the PATCH message payload */
	int seqno;						/**< Sequence number of next packet */
	int max_seqno;					/**< Last sequence number to send */
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

static struct {
	char *arena;	/* halloc()ed */
	int len;
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

	if (buffer.arena == NULL) {
		buffer.arena = halloc(DEFAULT_BUF_SIZE);
		buffer.len = DEFAULT_BUF_SIZE;
	}
}

/**
 * Add shared file to our QRP.
 */
void
qrp_add_file(const shared_file_t *sf, htable_t *words)
{
	word_vec_t *wovec;
	uint wocnt;
	uint i;

	g_assert(sf != NULL);
	g_assert(words != NULL);

	/*
	 * Copy filename to buffer, since we're going to map it inplace.
	 */

	g_assert(utf8_is_valid_data(shared_file_name_nfc(sf),
				shared_file_name_nfc_len(sf)));
	g_assert(utf8_is_valid_data(shared_file_name_canonic(sf),
				shared_file_name_canonic_len(sf)));

	if (qrp_debugging(1)) {
		g_debug("QRP adding file \"%s\"", shared_file_name_canonic(sf));
	}

	/*
	 * The words in the QRP must be lowercased, but the pre-computed canonic
	 * representation of the filename is already in lowercase form.
	 */

	wocnt = word_vec_make(shared_file_name_canonic(sf), &wovec);

	if (0 == wocnt)
		return;

	/*
	 * Identify unique words we have not already seen in `words'.
	 */

	for (i = 0; i < wocnt; i++) {
		const char *word = wovec[i].word;
		size_t word_len;

		g_assert(word[0] != '\0');
		word_len = strlen(word);

		/*
		 * Record word if we haven't seen it yet.
		 */

		if (htable_contains(words, word)) {
			continue;
		} else {
			void *p;
			size_t n = 1 + word_len;

			p = wcopy(word, n);
			htable_insert(words, p, size_to_pointer(n));
		}

		if (qrp_debugging(8)) {
			g_debug("new QRP word \"%s\" [from %s]",
				word, shared_file_name_nfc(sf));
		}
	}

	word_vec_free(wovec, wocnt);
}

/*
 * Hash table iterator callbacks
 */

static void
free_word(const void *key, void *value, void *unused_udata)
{
	g_assert(size_is_positive(pointer_to_size(value)));

	(void) unused_udata;
	wfree(deconstify_pointer(key), pointer_to_size(value));
}

struct unique_substrings {		/* User data for unique_subtr() callback */
	hset_t *unique;
	GSList *head;
};

static inline void
insert_substr(struct unique_substrings *u, const char *word, size_t size)
{
	if (!hset_contains(u->unique, word)) {
		void *s;

		s = wcopy(word, size);
		hset_insert(u->unique, s);
		u->head = g_slist_prepend(u->head, s);
	}
}

/**
 * Iteration callback on the hashtable containing keywords.
 */
static void
unique_substr(const void *key, void *value, void *udata)
{
	struct unique_substrings *u = udata;
	const char *word = key;
	char *s;
	size_t len, size, i;

	g_assert(size_is_positive(pointer_to_size(value)));

	/*
	 * Add all unique (i.e. not already seen) substrings from word, all
	 * anchored at the start, whose length range from 3 to the word length.
	 */

	size = pointer_to_size(value);
	s = wcopy(word, size);
	len = size - 1;				/* Trailing NUL included in size */

	for (i = 0; i <= QRP_MAX_CUT_CHARS; i++) {

		insert_substr(u, s, len + 1);

		while (len > QRP_MIN_WORD_LENGTH) {
			uint retlen;

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

/**
 * Create a list of all unique substrings at least QRP_MIN_WORD_LENGTH long,
 * from words held in `ht' (keys are words, values are the word's length plus
 * the trailing NUL).
 *
 * @returns created list, and count in `retcount'.
 */
static GSList *
unique_substrings(htable_t *ht, int *retcount)
{
	struct unique_substrings u = { NULL, NULL };		/* Callback args */

	u.unique = hset_create(HASH_KEY_STRING, 0);
	htable_foreach(ht, unique_substr, &u);
	*retcount = hset_count(u.unique);
	hset_free_null(&u.unique);		/* Created words ref'ed by u.head */

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
	QRP_MAGIC = 0x44b5975aU
};

struct qrp_context {
	enum qrp_magic magic;
	struct routing_table **rtp;	/**< Points to routing table variable to fill */
	struct routing_patch **rpp;	/**< Points to routing patch variable to fill */
	GSList *sl_substrings;		/**< List of all substrings */
	htable_t *words;			/**< Words making up the files */
	int substrings;				/**< Amount of substrings */
	char *table;				/**< Computed routing table */
	int slots;					/**< Amount of slots in table */
	struct routing_table *st;	/**< Smaller table */
	struct routing_table *lt;	/**< Larger table for merging (destination) */
	int sidx;					/**< Source index in `st' */
	int lidx;					/**< Merging index in `lt' */
	int expand;					/**< Expansion ratio from `st' to `lt' */
};

static struct bgtask *qrp_comp;	/**< Background computation handle */
static struct bgtask *qrp_merge;/**< Background merging handle */

/**
 * Free the "seen words" hash table we're filling up in qrp_add_file()
 * and perusing in qrp_finalize_computation(), then nullify pointer.
 */
void
qrp_dispose_words(htable_t **h_ptr)
{
	htable_t *h = *h_ptr;

	if (h != NULL) {
		htable_foreach(h, free_word, NULL);
		htable_free_null(h_ptr);
	}
}

/**
 * Free query routing table computation context.
 */
static void
qrp_context_free(void *p)
{
	struct qrp_context *ctx = p;
	GSList *sl;

	g_assert(ctx->magic == QRP_MAGIC);

	qrp_dispose_words(&ctx->words);

	for (sl = ctx->sl_substrings; sl; sl = g_slist_next(sl)) {
		char *word = sl->data;
		size_t size;

		size = 1 + strlen(word);
		g_assert(size_is_positive(size));
		wfree(word, size);
	}
	gm_slist_free_null(&ctx->sl_substrings);

	HFREE_NULL(ctx->table);

	if (ctx->st)
		qrt_unref(ctx->st);
	if (ctx->lt)
		qrt_unref(ctx->lt);

	ctx->magic = 0;
	WFREE(ctx);
}

/**
 * Called when the QRP recomputation is done to free the context.
 */
static void
qrp_comp_context_free(void *p)
{
	qrp_comp = NULL;		/* If we're called, the task is being terminated */
	qrp_context_free(p);
}

/**
 * Called when the QRP merging is done to free the context.
 */
static void
qrp_merge_context_free(void *p)
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
qrp_step_substring(struct bgtask *unused_h, void *u, int unused_ticks)
{
	struct qrp_context *ctx = u;

	(void) unused_h;
	(void) unused_ticks;
	g_assert(ctx->magic == QRP_MAGIC);
	g_assert(ctx->words != NULL);

	ctx->sl_substrings = unique_substrings(ctx->words, &ctx->substrings);
	qrp_dispose_words(&ctx->words);

	if (qrp_debugging(1))
		g_debug("QRP unique subwords: %d", ctx->substrings);

	return BGR_NEXT;		/* All done for this step */
}

/**
 * Compare possibly compacted table `rt' with expanded table arena `arena'
 * having `slots' slots.
 *
 * @returns whether tables are identical.
 */
static bool
qrt_eq(const struct routing_table *rt, const char *arena, int slots)
{
	int i;

	g_assert(rt != NULL);
	g_assert(arena != NULL);
	g_assert(slots > 0);

	if (rt->slots != slots)
		return FALSE;

	if (!rt->compacted)
		return 0 == memcmp(rt->arena, arena, slots);

	for (i = 0; i < slots; i++) {
		bool s1 = RT_SLOT_READ(rt->arena, i);
		bool s2 = arena[i] != LOCAL_INFINITY;
		if (!s1 != !s2)
			return FALSE;
	}

	return TRUE;
}

/**
 * Compute QRP table, iteration step.
 */
static bgret_t
qrp_step_compute(struct bgtask *h, void *u, int unused_ticks)
{
	struct qrp_context *ctx = u;
	char *table = NULL;
	int slots;
	int bits;
	const GSList *sl;
	int upper_thresh;
	int hashed = 0;
	int filled = 0;
	int conflict_ratio;
	bool full = FALSE;

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

	table = halloc(slots);
	memset(table, LOCAL_INFINITY, slots);

	for (sl = ctx->sl_substrings; sl; sl = g_slist_next(sl)) {
		const char *word = sl->data;
		uint idx = qrp_hash(word, bits);

		hashed++;

		if (table[idx] == LOCAL_INFINITY) {
			table[idx] = 1;
			filled++;
			if (qrp_debugging(7))
				g_debug("QRP added subword: \"%s\"", word);
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
		(int) (100.0 * (ctx->substrings - filled) / ctx->substrings);

	if (qrp_debugging(1))
		g_debug("QRP [seqno=%d] size=%d, filled=%d, hashed=%d, "
			"ratio=%d%%, conflicts=%d%%%s",
			bg_task_seqno(h), slots, filled, hashed,
			(int) (100.0 * filled / slots),
			conflict_ratio, full ? " FULL" : "");

	/*
	 * Decide whether we can keep the table we've just built.
	 */

	if (
		bits >= MAX_TABLE_BITS ||
		(!full && conflict_ratio < MAX_CONFLICT_RATIO)
	) {
		if (qrp_debugging(1))
			g_debug("QRP final table size: %d slots", slots);

		gnet_prop_set_guint32_val(PROP_QRP_SLOTS, (uint32) slots);
		gnet_prop_set_guint32_val(PROP_QRP_SLOTS_FILLED, (uint32) filled);
		gnet_prop_set_guint32_val(PROP_QRP_HASHED_KEYWORDS, (uint32) hashed);
		gnet_prop_set_guint32_val(PROP_QRP_FILL_RATIO,
			(uint32) (100.0 * filled / slots));
		gnet_prop_set_guint32_val(PROP_QRP_CONFLICT_RATIO,
			(uint32) conflict_ratio);

		/*
		 * If we had already a table, compare it to the one we just built.
		 * If they are identical, discard the new one.
		 *
		 * Can't do a direct memcmp() on the tables though, as the routing
		 * table arena may be compressed and our table is not.
		 */

		if (routing_table != NULL) {
			if (routing_table->cancelled) {
				/*
				 * Routing table was canceleld because the computation of the
				 * global routing patch was cancelled when we began a new
				 * computation.  Therefore, even if the new table is the same
				 * as the old one, we need to keep the new one and continue
				 * the process to propagate the table to our Gnutella peers
				 * and recompute the default patch.
				 *		--RAM, 2011-05-16
				 */
				if (qrp_debugging(1)) {
					g_debug("QRP table at generation #%d was cancelled",
						routing_table->generation);
				}
			} else if (qrt_eq(routing_table, table, slots)) {
				if (qrp_debugging(1)) {
					g_debug("QRP no change in table, keeping generation #%d",
						routing_table->generation);
				}
				HFREE_NULL(table);
				bg_task_exit(h, 0);	/* Abort processing */
			}
		}

		/*
		 * OK, we keep the table.
		 */

		ctx->table = table;
		ctx->slots = slots;

		return BGR_NEXT;		/* Done! */
	}

	HFREE_NULL(table);

	return BGR_MORE;			/* More work required */
}

/**
 * Create the compacted routing table object.
 */
static bgret_t
qrp_step_create_table(struct bgtask *unused_h, void *u, int unused_ticks)
{
	struct qrp_context *ctx = u;
	long elapsed;

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
qrp_step_install_leaf(struct bgtask *unused_h, void *u, int unused_ticks)
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

	if (!settings_is_ultra()) {
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
qrp_step_wait_for_merged_table(struct bgtask *h, void *u, int unused_ticks)
{
	struct qrp_context *ctx = u;
	int ratio;

	(void) unused_ticks;
	g_assert(ctx->magic == QRP_MAGIC);

	/*
	 * If we switched to leaf mode, go on...  The next step will explicitly
	 * catch this.
	 */

	if (settings_is_leaf())
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

	ctx->table = halloc(ctx->slots);
	memset(ctx->table, LOCAL_INFINITY, ctx->slots);

	/* Ready for iterating */

	return BGR_NEXT;
}

/**
 * Merge `local_table' with `merged_table'.
 */
static bgret_t
qrp_step_merge_with_leaves(struct bgtask *unused_h, void *u, int ticks)
{
	struct qrp_context *ctx = u;
	int used;
	struct routing_table *st = ctx->st;
	struct routing_table *lt = ctx->lt;
	int max;
	int i = ctx->sidx;
	int expand = ctx->expand;
	int j;

	(void) unused_h;
	g_assert(ctx->magic == QRP_MAGIC);

	/*
	 * If we switched to leaf mode, go on...  The next step will explicitly
	 * catch this.
	 */

	if (settings_is_leaf())
		return BGR_NEXT;

	g_assert(st != NULL && lt != NULL);
	g_assert(st->compacted);
	g_assert(lt->compacted);

	max = st->slots;

	for (used = 0; used < ticks && i < max; i++, used++, ctx->sidx++) {
		bool vs = RT_SLOT_READ(st->arena, i);

		/*
		 * Since `lt', the larger table, has the same size as the merged
		 * table, the `ctx->lidx' also points to the next area to be merged
		 * in the result.
		 */

		g_assert(ctx->lidx + expand <= lt->slots);	/* Won't overflow */

		for (j = 0; j < expand; j++) {
			bool vl = RT_SLOT_READ(lt->arena, ctx->lidx);
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
qrp_step_install_ultra(struct bgtask *h, void *u, int ticks)
{
	struct qrp_context *ctx = u;
	struct routing_table *rt;

	g_assert(ctx->magic == QRP_MAGIC);

	/*
	 * If we switched to leaf mode whilst processing, go on with the
	 * "leaf install" mode.
	 */

	if (settings_is_leaf())
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
 *
 * @param words		the words making up the filenames (takes ownership of it)
 */
void
qrp_finalize_computation(htable_t *words)
{
	struct qrp_context *ctx;

	g_assert(words != NULL);

	/*
	 * Because QRP computation is possibly a CPU-intensive operation, it
	 * is dealt with as a coroutine that will be scheduled at regular
	 * intervals.
	 */

	WALLOC0(ctx);
	ctx->magic = QRP_MAGIC;
	ctx->rtp = &local_table;	/* NOT routing_table, this is for local files */
	ctx->rpp = &routing_patch;
	ctx->words = words;			/* Will free it, caller must forget about it */

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

	WALLOC0(ctx);
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
qrp_merge_routing_table(struct bgtask *unused_h, void *unused_c,
	bgstatus_t status, void *unused_arg)
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
	QRT_PATCH_MAGIC	= 0x7347c237U
};

struct qrt_patch_context {
	enum qrt_patch_magic magic;
	struct routing_patch **rpp;	/**< Pointer where final patch is stored */
	struct routing_patch *rp;	/**< Routing patch being compressed */
	struct routing_table *rt;	/**< Table against which patch is computed */
	struct bgtask *compress;	/**< The compression task */
};

typedef void (*qrt_patch_computed_cb_t)(void *arg, struct routing_patch *rp);

struct patch_listener_info {
	qrt_patch_computed_cb_t callback;
	void *arg;
};

static struct qrt_patch_context *qrt_patch_ctx;
static GSList *qrt_patch_computed_listeners;


/**
 * Callback invoked when the routing patch is computed.
 */
static void
qrt_patch_computed(struct bgtask *unused_h, void *unused_u,
	bgstatus_t status, void *arg)
{
	struct qrt_patch_context *ctx = arg;
	GSList *sl;

	(void) unused_h;
	(void) unused_u;
	g_assert(ctx->magic == QRT_PATCH_MAGIC);
	g_assert(ctx == qrt_patch_ctx);
	g_assert(ctx->rpp != NULL);

	if (qrp_debugging(1))
		g_debug("QRP global default patch computed (status = %d)", status);

	qrt_patch_ctx = NULL;			/* Indicates that we're done */

	if (status == BGS_OK) {
		time_t now = tm_time();
		long elapsed;

		if (*ctx->rpp != NULL)
			qrt_patch_unref(*ctx->rpp);

		*ctx->rpp = ctx->rp;

		elapsed = delta_time(now, (time_t) GNET_PROPERTY(qrp_patch_timestamp));
		elapsed = MAX(0, elapsed);
		gnet_prop_set_guint32_val(PROP_QRP_PATCH_COMPUTATION_TIME, elapsed);
		gnet_prop_set_guint32_val(PROP_QRP_PATCH_LENGTH,
			(uint32) ctx->rp->len);
		gnet_prop_set_guint32_val(PROP_QRP_PATCH_COMP_RATIO,
			(uint32) (100.0 *
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
		WFREE(pi);
	}

	ctx->magic = 0;
	WFREE(ctx);

	gm_slist_free_null(&qrt_patch_computed_listeners);
}

/**
 * Record listener to callback with given argument when the default routing
 * patch will be ready.
 */
static void *
qrt_patch_computed_add_listener(qrt_patch_computed_cb_t cb, void *arg)
{
	struct patch_listener_info *pi;

	/*
	 * `qrt_patch_ctx' may be NULL: we may have finished a rescan, and
	 * be in the process of updating the routing table, but not yet in
	 * the process of computing the patch.
	 *
	 * That's alright, just register the listener.
	 */

	WALLOC(pi);
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
qrt_patch_computed_remove_listener(void *handle)
{
	struct patch_listener_info *pi = handle;

	g_assert(qrt_patch_computed_listeners != NULL);

	qrt_patch_computed_listeners =
		g_slist_remove(qrt_patch_computed_listeners, handle);
	WFREE(pi);
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

	WALLOC(ctx);
	qrt_patch_ctx = ctx;
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

	gm_slist_free_null(&sl_compress_tasks);
}

/***
 *** Sending of the QRP messages.
 ***/

/**
 * Send the RESET message, which must be sent before the PATCH sequence
 * to size the table.
 */
static void
qrp_send_reset(struct gnutella_node *n, int slots, int inf_val)
{
	gnutella_msg_qrp_reset_t msg;
	gnutella_header_t *header = gnutella_msg_qrp_reset_header(&msg);

	g_assert(is_pow2(slots));
	g_assert(inf_val > 0 && inf_val < 256);

	message_set_muid(header, GTA_MSG_QRP);

	gnutella_header_set_function(header, GTA_MSG_QRP);
	gnutella_header_set_ttl(header, 1);
	gnutella_header_set_hops(header, 0);
	gnutella_header_set_size(header, sizeof msg - GTA_HEADER_SIZE);

	gnutella_msg_qrp_reset_set_variant(&msg, GTA_MSGV_QRP_RESET);
	gnutella_msg_qrp_reset_set_table_length(&msg, slots);
	gnutella_msg_qrp_reset_set_infinity(&msg, inf_val);

	gmsg_sendto_one(n, &msg, sizeof msg);

	if (qrp_debugging(2)) {
		g_debug("QRP sent RESET slots=%d, infinity=%d to %s",
			slots, inf_val, node_infostr(n));
	}
}

/**
 * Send the PATCH message.
 *
 * The patch payload data is made of the `len' bytes starting at `buf'.
 */
static void
qrp_send_patch(struct gnutella_node *n,
	int seqno, int seqsize, bool compressed, int bits,
	char *buf, int len)
{
	gnutella_msg_qrp_patch_t *msg;
	uint msglen;

	g_assert(seqsize >= 1 && seqsize <= 255);
	g_assert(seqno >= 1 && seqno <= seqsize);
	g_assert(len >= 0 && len < INT_MAX);

	/*
	 * Compute the overall message length.
	 */

	g_assert((size_t) len <= INT_MAX - sizeof *msg);
	msglen = len + sizeof *msg;
	msg = halloc(msglen);

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

	memcpy(cast_to_char_ptr(msg) + sizeof *msg, buf, len);

	gmsg_sendto_one(n, msg, msglen);

	HFREE_NULL(msg);

	if (qrp_debugging(2)) {
		g_debug("QRP sent PATCH #%d/%d (%d bytes) to %s",
			seqno, seqsize, len, node_infostr(n));
	}
}

/***
 *** Reception of the QRP messages.
 ***/

struct qrp_reset {
	uint32 table_length;
	uint8 infinity;
};

struct qrp_patch {
	uint8 seq_no;
	uint8 seq_size;
	uint8 compressor;
	uint8 entry_bits;
	uchar *data;			/**< Points into node's message buffer */
	int len;				/**< Length of data pointed at by `data' */
};

/**
 * Receive a RESET message and fill the `reset' structure with its payload.
 *
 * @returns TRUE if we read the message OK.
 */
static bool
qrp_recv_reset(struct gnutella_node *n, struct qrp_reset *reset)
{
	const void *msg = n->data;

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
static bool
qrp_recv_patch(struct gnutella_node *n, struct qrp_patch *patch)
{
	const void *msg = n->data;

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
	patch->data = (uchar *) msg + sizeof(gnutella_qrp_patch_t);
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
	int seqno;					 /**< Sequence number of next message (1..n) */
	int seqsize;				 /**< Total amount of messages to send */
	int offset;					 /**< Offset within patch */
	int chunksize;				 /**< Amount to send within each PATCH */
	int last_sent;				 /**< Amount sent during last batch */
	void *compress;				 /**< Compressing task (NULL = done) */
	void *listener;				 /**< Listener for default patch being ready */
	time_t last;				 /**< Time at which we sent the last batch */
	unsigned ready:1;			 /**< Ready for sending? */
	unsigned reset_needed:1;	 /**< Is the initial RESET needed? */
	unsigned empty_patch:1;		 /**< Was patch empty? */
};

/**
 * Callback invoked when the computed patch for a connection
 * has been compressed.
 */
static void
qrt_compressed(struct bgtask *unused_h, void *unused_u,
	bgstatus_t status, void *arg)
{
	struct qrt_update *qup = arg;
	struct routing_patch *rp;
	int msgcount;

	(void) unused_h;
	(void) unused_u;
	g_assert(qup->magic == QRT_UPDATE_MAGIC);

	qup->compress = NULL;
	qup->ready = TRUE;

	if G_UNLIKELY(status == BGS_KILLED)
		goto error;
	else if G_UNLIKELY(status == BGS_ERROR) {	/* Error during processing */
		g_warning("could not compress query routing patch to send to %s",
			node_infostr(qup->node));
		goto error;
	}

	if G_UNLIKELY(!NODE_IS_WRITABLE(qup->node))
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

	if G_UNLIKELY(
		routing_patch != NULL &&
		qup->patch->len > routing_patch->len
	) {
		if (qrp_debugging(0))
			g_warning("QRP incremental query routing patch for node %s is %d "
				"bytes for %s slots, bigger than the default "
				"patch (%d bytes for %s slots) -- using latter",
				node_gnet_addr(qup->node),
				qup->patch->len, compact_size(qup->patch->size, FALSE),
				routing_patch->len, compact_size2(routing_patch->size, FALSE));

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
qrt_patch_available(void *arg, struct routing_patch *rp)
{
	struct qrt_update *qup = arg;

	g_assert(qup->magic == QRT_UPDATE_MAGIC);

	if (qrp_debugging(1)) {
		g_debug("QRP global routing patch %s (%s)",
			rp == NULL ? "computation was cancelled" : "is now available",
			node_infostr(qup->node));
	}

	/*
	 * If the global routing patch computation was cancelled, we must mark
	 * the routing table so that we do not keep it even if the next one
	 * we compute is identical.
	 */

	if (NULL == rp) {
		g_assert(routing_table != NULL);
		routing_table->cancelled = TRUE;
	}

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
			if (qrp_debugging(0))
				g_warning("QRP old QRT for %s had %d slots, new one has %d",
					node_infostr(n), old->slots, routing_table->slots);
			old_table = NULL;	/* Will trigger a RESET, as if the first time */
		}
	}

	WALLOC0(qup);

	qup->magic = QRT_UPDATE_MAGIC;
	qup->node = n;
	qup->ready = FALSE;
	qup->reset_needed = booleanize(old_table == NULL);

	if (old_table == NULL) {
		/*
		 * If routing_patch is not NULL and has the right size, it is ready,
		 * no need to compute it.
		 * Otherwise, it means it is being computed, so enqueue a
		 * notification callback to know when it is ready.
		 */

		if (
			routing_patch != NULL &&
			routing_patch->size == routing_table->slots
		) {
			if (qrp_debugging(2)) {
				g_debug(
					"QRP default routing patch is already there (%s)",
					node_infostr(n));
			}

			qup->patch = qrt_patch_ref(routing_patch);
			qrt_compressed(NULL, NULL, BGS_OK, qup);
		} else {
			if (qrp_debugging(1)) {
				g_debug("QRP must wait for default routing patch "
					"(%s): %s",
					node_infostr(n),
					NULL == routing_patch ? "none present" : "has wrong size");
			}

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
	WFREE(qup);
}

/**
 * Send the next batch of data.
 * @returns whether the routing should still be called.
 */
bool
qrt_update_send_next(struct qrt_update *qup)
{
	time_t now;
	time_t elapsed;
	int len;
	int i;
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
			(char *) qup->patch->arena + qup->offset, len);

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
bool
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
	int shrink_factor;		/**< 1 means none, `n' means coalesce `n' entries */
	int seqsize;			/**< Amount of patch messages to expect */
	int seqno;				/**< Sequence number of next message we expect */
	int entry_bits;			/**< Amount of bits used by PATCH */
	z_streamp inz;			/**< Data inflater */
	char *data;				/**< Where inflated data is written */
	int len;				/**< Length of the `data' buffer */
	int current_slot;		/**< Current slot processed in patch */
	int current_index;		/**< Current index (after shrinking) in QR table */
	char *expansion;		/**< Temporary expansion arena before shrinking */
	bool deflated;			/**< Is data deflated? */
	bool (*patch)(struct qrt_receive *qrcv, const uchar *data, int len,
						const struct qrp_patch *patch);
};

/**
 * A default handler that should never be called.
 *
 * @returns FALSE always.
 */
static bool
qrt_unknown_patch(struct qrt_receive *unused_qrcv,
	const uchar *unused_data, int unused_len,
	const struct qrp_patch *unused_patch)
{
	(void) unused_qrcv;
	(void) unused_data;
	(void) unused_len;
	(void) unused_patch;

	g_error("QRP patch application pointer uninitialized.");

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
	int ret;

	g_assert(query_table == NULL || table->magic == QRP_ROUTE_MAGIC);
	g_assert(query_table == NULL || table->client_slots > 0);

	WALLOC(inz);
	inz->zalloc = zlib_alloc_func;
	inz->zfree = zlib_free_func;
	inz->opaque = NULL;

	ret = inflateInit(inz);

	if G_UNLIKELY(ret != Z_OK) {
		WFREE(inz);
		g_warning("unable to initialize QRP decompressor for %s: %s",
			node_infostr(n), zlib_strerror(ret));
		return NULL;
	}

	WALLOC(qrcv);
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
	qrcv->data = halloc(qrcv->len);
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
		int length = table->client_slots;

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
	WFREE(qrcv->inz);
	if (qrcv->table)
		qrt_unref(qrcv->table);
	if (qrcv->expansion)
		wfree(qrcv->expansion, qrcv->shrink_factor);
	HFREE_NULL(qrcv->data);

	qrcv->magic = 0;			/* Prevent accidental reuse */
	WFREE(qrcv);
}

/**
 * Apply raw patch data (uncompressed) to the current routing table.
 *
 * @param qrcv			query routing table being received
 * @param data			patch data to apply
 * @param len			length of patch data (amount of data bytes)
 * @param patch			the PATCH message, for logging purposes
 *
 * @returns TRUE on sucess, FALSE on error with the node being BYE-ed.
 */
static bool
qrt_apply_patch(struct qrt_receive *qrcv, const uchar *data, int len,
	const struct qrp_patch *patch)
{
	int bpe = qrcv->entry_bits;			/* bits per entry */
	int epb;							/* entries per byte */
	uint8 rmask;						/* reading mask */
	int expansion_slot;
	struct routing_table *rt = qrcv->table;
	int i;

	g_assert(qrcv->table != NULL);
	g_assert(qrcv->expansion != NULL);

	/*
	 * Make sure the received table is not full yet.  If that
	 * test fails, they have already sent more data than the
	 * advertised table size.
	 */

	if G_UNLIKELY(len == 0)				/* No data, only zlib trailer */
		return TRUE;

	if G_UNLIKELY(qrcv->current_index >= rt->slots) {
		struct gnutella_node *n = qrcv->node;
		g_warning("%s overflowed its QRP %d-bit patch of %s slots"
			" (%s message #%d/%d)",
			node_infostr(n), qrcv->entry_bits,
			compact_size(rt->client_slots, FALSE),
			patch->compressor ? "compressed" : "plain",
			patch->seq_no, patch->seq_size);
		node_bye_if_writable(n, 413, "QRP patch overflowed table (%s slots)",
			compact_size(rt->client_slots, FALSE));
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
		int j;
		uint8 value = data[i];		/* Patch byte contains `epb' slots */
		uint8 smask;				/* Sign bit mask */
		uint8 mask;

		for (
			j = 0, mask = rmask, smask = 0x80;
			j < epb;
			j++, mask >>= bpe, smask >>= bpe
		) {
			uint8 v = value & mask;
			int o;

			/*
			 * If we are at an expansion slot, expand.
			 *
			 * We don't special-case the non-shrinking cases, even though
			 * those will be the most common, because peformance is not what
			 * matters here.
			 */

			if (qrcv->current_slot == expansion_slot) {
				int k;
				bool val;

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
				int k;
				uint8 val = 0x01;

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

			if ((uint) qrcv->current_slot >= rt->client_slots) {
				if (j != (epb - 1) || i != (len - 1)) {
					struct gnutella_node *n = qrcv->node;
					g_warning("%s overflowed its QRP "
						"%d-bit patch of %s slots",
						node_infostr(n),
						qrcv->entry_bits,
						compact_size(rt->client_slots, FALSE));
					node_bye_if_writable(n, 413,
						"QRP patch overflowed table (%s slots)",
						compact_size(rt->client_slots, FALSE));
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
static bool
qrt_patch_is_valid(struct qrt_receive *qrcv, int len, int slots_per_byte,
	const struct qrp_patch *patch)
{
	struct routing_table *rt = qrcv->table;
	unsigned last_patch_slot;

	/*
	 * Make sure the received table is not full yet.  If that
	 * test fails, they have already sent more data than the
	 * advertised table size.
	 */

	if G_UNLIKELY(qrcv->current_index >= rt->slots) {
		struct gnutella_node *n = qrcv->node;
		g_warning("%s overflowed its QRP %d-bit patch of %s slots"
			" (current_index=%d, slots=%d at %s message #%u/%u)",
			node_infostr(n), qrcv->entry_bits,
			compact_size(rt->client_slots, FALSE),
			qrcv->current_index, rt->slots,
			patch->compressor ? "compressed" : "plain",
			patch->seq_no, patch->seq_size);
		node_bye_if_writable(n, 413, "QRP patch overflowed table (%s slots)",
			compact_size(rt->client_slots, FALSE));
		return FALSE;
	}

	/*
	 * Make sure they are not providing us with more data than
	 * the table can hold.
	 */

	last_patch_slot = (uint) qrcv->current_slot + len * slots_per_byte;

	if G_UNLIKELY(last_patch_slot > rt->client_slots) {
		struct gnutella_node *n = qrcv->node;
		g_warning("%s overflowed its QRP %d-bit patch of "
			"%s slots by extra %s at %s message #%u/%u",
			node_infostr(n), qrcv->entry_bits,
			compact_size(rt->client_slots, FALSE),
			uint32_to_string(last_patch_slot - rt->client_slots),
			patch->compressor ? "compressed" : "plain",
			patch->seq_no, patch->seq_size);
		node_bye_if_writable(n, 413, "QRP patch overflowed table (%s slots)",
			compact_size(rt->client_slots, FALSE));
		return FALSE;
	}
	
	return TRUE;
}

/**
 * Apply raw 8-bit patch data (uncompressed) to the current routing table.
 *
 * @param qrcv			query routing table being received
 * @param data			patch data to apply
 * @param len			length of patch data (amount of data bytes)
 * @param patch			the PATCH message, for logging purposes
 *
 * @returns TRUE on sucess, FALSE on error with the node being BYE-ed.
 */
static bool
qrt_apply_patch8(struct qrt_receive *qrcv, const uchar *data, int len,
	const struct qrp_patch *patch)
{
	struct routing_table *rt = qrcv->table;
	int i;

	g_assert(qrcv->table != NULL);

	/* True for this variant of patch function. 8-bit, no expansion. */
	g_assert((int)rt->client_slots == rt->slots);
	g_assert(qrcv->entry_bits == 8);
	g_assert(qrcv->shrink_factor == 1);

	if (len == 0)						/* No data, only zlib trailer */
		return TRUE;

	if (!qrt_patch_is_valid(qrcv, len, 1, patch))
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
 * @param qrcv			query routing table being received
 * @param data			patch data to apply
 * @param len			length of patch data (amount of data bytes)
 * @param patch			the PATCH message, for logging purposes
 *
 * @returns TRUE on sucess, FALSE on error with the node being BYE-ed.
 */
static G_GNUC_HOT bool
qrt_apply_patch4(struct qrt_receive *qrcv, const uchar *data, int len,
	const struct qrp_patch *patch)
{
	struct routing_table *rt = qrcv->table;
	int i;

	g_assert(qrcv->table != NULL);

	/* True for this variant of patch function. 8-bit, no expansion. */
	g_assert((int)rt->client_slots == rt->slots);
	g_assert(qrcv->entry_bits == 4);
	g_assert(qrcv->shrink_factor == 1);

	if G_UNLIKELY(len == 0)				/* No data, only zlib trailer */
		return TRUE;

	if (!qrt_patch_is_valid(qrcv, len, 2, patch))
		return FALSE;

	g_assert(qrcv->current_index + len * 2 <= rt->slots);
	
	/*
	 * Compute the amount of entries per byte, and the initial reading mask.
	 */

	for (i = 0; i < len; i++) {
		uint8 v = data[i];	/* Patch byte contains `epb' slots */

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
 * A macro that creates functions with fixed slot sizes to determine
 * if the table contains all key words.  With a parameter of 21, the
 * name will be qrp_can_route_21.
 */
#define CAN_ROUTE(bits) \
static G_GNUC_HOT bool \
qrp_can_route_##bits(const query_hashvec_t *qhv, \
					 const struct routing_table *rt) \
 \
{ \
	const struct query_hash * const vec = qhv->vec; \
	const uint8 * const arena = rt->arena; \
	uint8 i = qhv->count; \
 \
	while (i-- > 0) { \
		uint32 idx = vec[i].hashcode >> (32 - bits); \
		/* ALL the keywords must be present -- hardwire RT_SLOT_READ. */ \
		if (0 == (0x80U & (arena[idx >> 3] << (idx & 0x7)))) \
			return FALSE; \
	} \
	return TRUE; \
}

/* Create eight QRT lookup routines with fixed shift factors. */
CAN_ROUTE(14)
CAN_ROUTE(15)
CAN_ROUTE(16)
CAN_ROUTE(17)
CAN_ROUTE(18)
CAN_ROUTE(19)
CAN_ROUTE(20)
CAN_ROUTE(21)

#undef CAN_ROUTE

/**
 * A macro that creates functions with fixed slot sizes to determine
 * if the table contains an URN.  With a parameter of 14, the name
 * will be qrp_can_route_urn_14.
 *
 * @todo: Is URN searched deprecated, with DHT queries?
 */
#define CAN_ROUTE_URN(bits)                                           \
static bool                                                           \
qrp_can_route_urn_##bits(const query_hashvec_t *qhv,                  \
					                const struct routing_table *rt)   \
{                                                                     \
	const struct query_hash *qh = qhv->vec;                           \
	const uint8 *arena          = rt->arena;                          \
	uint i;                                                           \
					                                                  \
	for (i = 0; i < qhv->count; i++) {                                \
		uint32 idx = qh[i].hashcode >> (32 - bits);                   \
					                                                  \
		/*                                                            \
		 * If there is an entry in the table and the source is an URN,\
		 * we have to forward the query, as those are OR-ed.          \
		 * Otherwise, ALL the keywords must be present.               \
		 *                                                            \
		 * When facing a SHA1 query, we require that at least one of  \
		 * the URN matches or we don't forward the query.             \
		 */                                                           \
		if (RT_SLOT_READ(arena, idx)) {                               \
			if (qh[i].source == QUERY_H_URN)	/* URN present */     \
				return TRUE;					/* Will forward */    \
			return FALSE;					/* And none matched */    \
		} else {                                                      \
			if (qh[i].source == QUERY_H_WORD) {                       \
				/* We know no URN matched already                     \
				   because qhv is sorted */                           \
				return FALSE;	/* All words did not match */         \
			}                                                         \
		}                                                             \
	}                                                                 \
	/*                                                                \
	 * We had some URNs and none matched so don't forward.            \
	 */                                                               \
	return FALSE;                                                     \
}

/* Create eight QRT lookup routines (with a URN) with fixed shift
 * factors. */
CAN_ROUTE_URN(14)
CAN_ROUTE_URN(15)
CAN_ROUTE_URN(16)
CAN_ROUTE_URN(17)
CAN_ROUTE_URN(18)
CAN_ROUTE_URN(19)
CAN_ROUTE_URN(20)
CAN_ROUTE_URN(21)
#undef CAN_ROUTE_URN

/**
 * Handle reception of QRP RESET.
 *
 * @returns TRUE if we handled the message correctly, FALSE if an error
 * was found and the node BYE-ed.
 */
static bool
qrt_handle_reset(
	struct gnutella_node *n, struct qrt_receive *qrcv, struct qrp_reset *reset)
{
	struct routing_table *rt;
	int ret;
	int slots;
	int old_generation = -1;

	ret = inflateReset(qrcv->inz);
	if G_UNLIKELY(ret != Z_OK) {
		g_warning("unable to reset QRP decompressor for %s: %s",
			node_infostr(n), zlib_strerror(ret));
		node_bye_if_writable(n, 500, "Error resetting QRP inflater: %s",
			zlib_strerror(ret));
		return FALSE;
	}

	/*
	 * If the advertized table size is not a power of two, good bye.
	 */

	if G_UNLIKELY(!is_pow2(reset->table_length)) {
		g_warning("%s sent us non power-of-two QRP length: %u",
			node_infostr(n), reset->table_length);
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

	if G_UNLIKELY(reset->infinity < 1) {
		g_warning("%s sent us invalid QRP infinity: %u",
			node_infostr(n), (uint) reset->infinity);
		node_bye_if_writable(n, 413, "Invalid QRP infinity %u",
			(uint) reset->infinity);
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

	WALLOC(rt);
	rt->magic = QRP_ROUTE_MAGIC;
	rt->name = str_cmsg("QRT %s", node_infostr(n));
	rt->refcnt = 1;
	rt->generation = old_generation + 1;
	rt->infinity = reset->infinity;
	rt->client_slots = reset->table_length;
	rt->compacted = TRUE;		/* We'll compact it on the fly */
	rt->digest = NULL;
	rt->reset = TRUE;

	qrcv->table = rt;
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

	if (qrp_debugging(0) && qrcv->shrink_factor > 1)
		g_warning("QRP QRT from %s will be shrunk by a factor of %d",
			node_infostr(n), qrcv->shrink_factor);

	qrcv->expansion = walloc(qrcv->shrink_factor);

	rt->slots = rt->client_slots / qrcv->shrink_factor;
	rt->bits = highest_bit_set(rt->slots);

	/* Populate 'can_route' routines based on constant slot sizes.
	 * This allows pre-computed shift to be optimized for each table size.
	 */
	switch(rt->bits)
	{
		case 14:
			rt->can_route_urn = qrp_can_route_urn_14;
			rt->can_route     = qrp_can_route_14;
			break;
		case 15:
			rt->can_route_urn = qrp_can_route_urn_15;
			rt->can_route     = qrp_can_route_15;
			break;
		case 16:
			rt->can_route_urn = qrp_can_route_urn_16;
			rt->can_route     = qrp_can_route_16;
			break;
		case 17:
			rt->can_route_urn = qrp_can_route_urn_17;
			rt->can_route     = qrp_can_route_17;
			break;
		case 18:
			rt->can_route_urn = qrp_can_route_urn_18;
			rt->can_route     = qrp_can_route_18;
			break;
		case 19:
			rt->can_route_urn = qrp_can_route_urn_19;
			rt->can_route     = qrp_can_route_19;
			break;
		case 20:
			rt->can_route_urn = qrp_can_route_urn_20;
			rt->can_route     = qrp_can_route_20;
			break;
		case 21:
			rt->can_route_urn = qrp_can_route_urn_21;
			rt->can_route     = qrp_can_route_21;
			break;
		default:
			rt->can_route_urn = qrp_can_route_default;
			rt->can_route     = qrp_can_route_default;
			
	}

	g_assert(is_pow2(rt->slots));
	g_assert(rt->slots <= MAX_TABLE_SIZE);
	g_assert((1 << rt->bits) == rt->slots);

	/*
	 * Allocate the compacted area.
	 * Since the table is empty, it is zero-ed.
	 */

	slots = rt->slots / 8;			/* 8 bits per byte, table is compacted */
	rt->arena = halloc0(slots);

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
 * @param n			the node sending the patch
 * @param qrcv		the querty routing table being received
 * @param patch		the PATCH message
 * @param done		written with TRUE when last message was processed
 *
 * @returns TRUE if we handled the message correctly, FALSE if an error
 * was found and the node BYE-ed.  Sets `done' to TRUE on the last message
 * from the sequence.
 */
static bool
qrt_handle_patch(
	struct gnutella_node *n, struct qrt_receive *qrcv, struct qrp_patch *patch,
	bool *done)
{
	/*
	 * If we don't have a routing table allocated, it means they never sent
	 * the RESET message, and no prior table was recorded.
	 */

	if G_UNLIKELY(qrcv->table == NULL) {
		g_warning("%s did not sent any QRP RESET before PATCH",
			node_infostr(n));
		node_bye_if_writable(n, 413, "No QRP RESET received before PATCH");
		return FALSE;
	}

	/*
	 * Check that we're receiving the proper sequence.
	 */

	if G_UNLIKELY(patch->seq_no != qrcv->seqno) {
		g_warning("%s sent us invalid QRP seqno %u (expected %u)",
			node_infostr(n), (uint) patch->seq_no, qrcv->seqno);
		node_bye_if_writable(n, 413, "Invalid QRP seq number %u (expected %u)",
			(uint) patch->seq_no, qrcv->seqno);
		return FALSE;
	}

	/*
	 * Check that the maxmimum amount of messages for the patch sequence
	 * is remaining stable accross all the PATCH messages.
	 */

	if G_UNLIKELY(qrcv->seqno == 1) {
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
			g_warning("%s sent invalid QRP entry bits %u for PATCH",
				node_infostr(n), qrcv->entry_bits);
			node_bye_if_writable(n, 413, "Invalid QRP entry bits %u for PATCH",
				qrcv->entry_bits);
			return FALSE;
		}
	} else if G_UNLIKELY(patch->seq_size != qrcv->seqsize) {
		g_warning("%s changed QRP seqsize to %u at message #%d "
			"(started with %u)",
			node_infostr(n),
			(uint) patch->seq_size, qrcv->seqno, qrcv->seqsize);
		node_bye_if_writable(n, 413,
			"Changed QRP seq size to %u at message #%d (began with %u)",
			(uint) patch->seq_size, qrcv->seqno, qrcv->seqsize);
		return FALSE;
	}

	/*
	 * Check that the compression bits and entry_bits values are staying
	 * the same.
	 */

	if G_UNLIKELY(qrcv->entry_bits != patch->entry_bits) {
		g_warning("%s changed QRP patch entry bits to %u "
			"at message #%d (started with %u)",
			node_infostr(n),
			(uint) patch->entry_bits, qrcv->seqno, qrcv->entry_bits);
		node_bye_if_writable(n, 413,
			"Changed QRP patch entry bits to %u at message #%d (began with %u)",
			(uint) patch->entry_bits, qrcv->seqno, qrcv->entry_bits);
		return FALSE;
	}

	qrcv->seqno++;

	/*
	 * Attempt to relocate the table if it is a standalone memory fragment.
	 */

	{
		struct routing_table *rt = qrcv->table;

		g_assert(rt != NULL);
		g_assert(rt->compacted);	/* 8 bits per byte, table is compacted */

		rt->arena = hrealloc(rt->arena, rt->slots / 8);
	}

	/*
	 * Process the patch data.
	 */

	if (qrcv->deflated) {
		z_streamp inz = qrcv->inz;
		int ret;
		bool seen_end = FALSE;

		inz->next_in = patch->data;
		inz->avail_in = patch->len;

		while (!seen_end && inz->avail_in > 0) {
			inz->next_out = cast_to_pointer(qrcv->data);
			inz->avail_out = qrcv->len;

			ret = inflate(inz, Z_SYNC_FLUSH);

			if (ret == Z_STREAM_END && qrcv->seqno > qrcv->seqsize) {
				seen_end = TRUE;
				ret = Z_OK;
			}

			if G_UNLIKELY(ret != Z_OK) {
				g_warning("decompression of QRP patch #%u/%u failed for %s: %s",
					(uint) patch->seq_no, (uint) patch->seq_size,
					node_infostr(n), zlib_strerror(ret));
				node_bye_if_writable(n, 413,
					"QRP patch #%u/%u decompression failed: %s",
					(uint) patch->seq_no, (uint) patch->seq_size,
					zlib_strerror(ret));
				return FALSE;
			}

			if (
				!qrcv->patch(qrcv, (uchar *) qrcv->data,
					qrcv->len - inz->avail_out, patch)
			)
				return FALSE;
		}

		/*
		 * If we reached the end of the stream, make sure we were at
		 * the last patch of the sequence.
		 */

		if G_UNLIKELY(seen_end && qrcv->seqno <= qrcv->seqsize) {
			g_warning("saw end of compressed QRP patch at #%u/%u for %s",
				(uint) patch->seq_no, (uint) patch->seq_size,
				node_infostr(n));
			node_bye_if_writable(n, 413,
				"Early end of compressed QRP patch at #%u/%u",
				(uint) patch->seq_no, (uint) patch->seq_size);
			return FALSE;
		}
	} else if (!qrcv->patch(qrcv, patch->data, patch->len, patch))
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

		if G_UNLIKELY(qrcv->current_index < rt->slots) {
			g_warning("QRP %d-bit patch from %s covered only %d/%d slots",
				qrcv->entry_bits, node_infostr(n),
				qrcv->current_index, rt->slots);
			node_bye_if_writable(n, 413,
				"Incomplete %d-bit QRP patch covered %d/%d slots",
				qrcv->entry_bits, qrcv->current_index, rt->slots);
			return FALSE;
		}

		g_assert(qrcv->current_index == rt->slots);
		atom_sha1_free_null(&rt->digest);

		if (qrp_debugging(2))
			rt->digest = atom_sha1_get(qrt_sha1(rt));

		rt->fill_ratio = (int) (100.0 * rt->set_count / rt->slots);

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
			rt->pass_throw = (int)
				(100.0 * (1 - pow((rt->fill_ratio - 5) / 100.0, 1/2.5)));
		else
			rt->pass_throw = 100;		/* Always forward if QRT says so */

		if (qrp_debugging(2)) {
			g_debug("QRP got whole %d-bit patch "
				"(gen=%d, slots=%d (*%d), fill=%d%%, throw=%d) "
				"from %s: SHA1=%s",
				qrcv->entry_bits, rt->generation, rt->slots,
				qrcv->shrink_factor, rt->fill_ratio, rt->pass_throw,
				node_infostr(n),
				rt->digest ? sha1_base32(rt->digest) : "<not computed>");
		}

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

		if (qrp_debugging(4))
			(void) qrt_dump(rt, GNET_PROPERTY(qrp_debug) > 19);
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
bool
qrt_receive_next(struct qrt_receive *qrcv, bool *done)
{
	struct gnutella_node *n = qrcv->node;
	uint8 type;

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

static bool qrt_leaf_change_notified = FALSE;

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
static bool
qrp_monitor(void *unused_obj)
{
	(void) unused_obj;

	/*
	 * If we're not running as an ultra node, or if the reconstruction thread
	 * is already running, don't bother...
	 */

	if (!settings_is_ultra() || merge_comp != NULL)
		return TRUE;

	/*
	 * If we got notified of changes, relaunch the computation of the
	 * merge_table.
	 */

	if (qrt_leaf_change_notified) {
		qrt_leaf_change_notified = FALSE;
		mrg_compute(qrp_merge_routing_table);
	}

	return TRUE;		/* Keep calling */
}

/**
 * Initialize QRP.
 */
G_GNUC_COLD void
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

	cq_periodic_main_add(LEAF_MONITOR_PERIOD, qrp_monitor, NULL);

	/*
	 * Install an empty local table untill we compute our shared library.
	 */

	local_table = qrt_ref(qrt_empty_table("Empty local table"));
}

/**
 * Called at servent shutdown to reclaim all the memory.
 */
G_GNUC_COLD void
qrp_close(void)
{
	qrp_cancel_computation();

	if (routing_table)
		qrt_unref(routing_table);

	if (routing_patch)
		qrt_patch_unref(routing_patch);

	if (local_table)
		qrt_unref(local_table);

	if (merged_table)
		qrt_unref(merged_table);

	HFREE_NULL(buffer.arena);
}

/**
 * Used by qrt_dump().
 *
 * @returns whether a slot in the table is present or not.
 */
static bool
qrt_dump_is_slot_present(struct routing_table *rt, int slot)
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
static uint32
qrt_dump(struct routing_table *rt, bool full)
{
	struct sha1 digest;
	SHA1Context ctx;
	bool last_status = FALSE;
	int last_slot = 0;
	uint32 result;
	int i;

	g_debug("------ Query Routing Table \"%s\" "
		"(gen=%d, slots=%d, %scompacted)",
		rt->name, rt->generation, rt->slots, rt->compacted ? "" : "not ");

	SHA1Reset(&ctx);

	for (i = 0; i <= rt->slots; i++) {
		bool status = FALSE;
		uint8 value;

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
				g_debug("%d .. %d: %s", last_slot, i - 1,
					last_status ? "PRESENT" : "nothing");
			else
				g_debug("%d: %s", last_slot,
					last_status ? "PRESENT" : "nothing");

			last_slot = i;
			last_status = status;
		}
	}

	SHA1Result(&ctx, cast_to_pointer(&digest));

	/*
	 * Reduce SHA1 to a single uint32.
	 */

	result = sha1_hash(&digest);

	g_debug("------ End Routing Table \"%s\" "
		"(gen=%d, SHA1=%s, token=0x%x)",
		rt->name, rt->generation, sha1_base32(&digest), result);

	return result;
}

/***
 *** Query routing management.
 ***/

/**
 * Allocate a query hash container for at most `size' entries.
 */
query_hashvec_t *
qhvec_alloc(uint size)
{
	query_hashvec_t *qhvec;

	size = MIN(QRP_HVEC_MAX, size);

	WALLOC(qhvec);
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
	WFREE(qhvec);
}

/**
 * Empty query hash container.
 */
void
qhvec_reset(query_hashvec_t *qhvec)
{
	qhvec->count = 0;
	qhvec->has_urn = FALSE;
	qhvec->whats_new = FALSE;
}

/**
 * Clone query hash vector.
 */
query_hashvec_t *
qhvec_clone(const query_hashvec_t *qsrc)
{
	query_hashvec_t *qhvec;
	int vecsize;

	g_assert(qsrc != NULL);

	WALLOC(qhvec);
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
qhvec_add(query_hashvec_t *qhvec, const char *word, enum query_hsrc src)
{
	struct query_hash *qh = NULL;

	if G_UNLIKELY(qhvec->count >= qhvec->size)
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
 * @note thie routine expects the query hash vector to be sorted with
 * URNs coming first and words later.  This is a default
 * implementation.  The macros CAN_ROUTE and CAN_ROUTE_URN expand into
 * routines that perform the same tests with pre-computed shifts.
 */
static bool
qrp_can_route_default(const query_hashvec_t *qhv, const struct routing_table *rt)
{
	const struct query_hash *qh;
	const uint8 *arena;
	uint i, shift;
	bool has_urn;

	/*
	 * This routine is a hot spot when running as an ultra node.
	 * Prefetch constant items in local variables.
	 */

	arena = rt->arena;
	has_urn = qhv->has_urn;
	shift = 32 - rt->bits;
	qh = qhv->vec;

	for (i = 0; i < qhv->count; i++) {
		uint32 idx = qh[i].hashcode >> shift;

		/* Tight loop -- g_assert(idx < (uint32) rt->slots); */

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
bool
qrp_node_can_route(const gnutella_node_t *n, const query_hashvec_t *qhv)
{
	const struct routing_table *rt = n->recv_query_table;

	if G_UNLIKELY(!NODE_IS_WRITABLE(n))
		return FALSE;

	/*
	 * If we did not get any table for an UP, act as if it did not
	 * support QRP-routing and send it everything.
	 */

	if G_UNLIKELY(rt == NULL)
		return NODE_IS_LEAF(n) ? FALSE : TRUE;

	return qhv->has_urn ?
	   rt->can_route_urn(qhv, rt) :
	   rt->can_route(qhv, rt);
}

/**
 * Compute list of nodes to send the query to, based on node's QRT.
 * The query is identified by its list of QRP hashes, by its hop count, TTL
 * and by its source node (so we don't send back the query where it
 * came from).
 *
 * When ``leaves'' is FALSE, we do not include leaves in the resulting list.
 * This is used when dealing with a duplicate (but with higher TTL) query
 * that needs to be forwarded to neighbouring ultra-nodes, but which leaves
 * already received.
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
G_GNUC_HOT GSList *
qrt_build_query_target(
	query_hashvec_t *qhvec, int hops, int ttl, bool leaves,
	struct gnutella_node *source)
{
	GSList *nodes = NULL;		/* Targets for the query */
	const GSList *sl;
	bool sha1_query;
	bool whats_new;

	g_assert(qhvec != NULL);
	g_assert(hops >= 0);

	whats_new = qhvec_whats_new(qhvec);

	if G_UNLIKELY(0 == qhvec->count && !whats_new) {
		if (qrp_debugging(2)) {
			if (source != NULL)
				g_warning("QRP %s had empty hash vector",
					gmsg_node_infostr(source));
			else
				g_warning("QRP query [hops=%d] had empty hash vector", hops);
		}
		if (qrp_debugging(4) && source != NULL) {
			/* Skip search flags (2 first bytes) */
			dump_hex(stderr, "Query Payload",
				source->data + 2, source->size - 2);
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
		bool is_leaf;

		/*
		 * Avoid G_UNLIKELY() hints in the loop.  Either they are wrong hints
		 * or they increase the code size and result in I-cache misses, but
		 * profiling showed that these hints actually slow down this routine.
		 *		--RAM, 2011-10-18
		 */

		if (!NODE_IS_WRITABLE(dn))
			continue;

		if (hops >= dn->hops_flow)	/* Hops-flow prevents sending */
			continue;

		if (dn == source)			/* Skip node that sent us the query */
			continue;

		/*
		 * Look whether we can route the query to the peer (a leaf node or
		 * a last-hop QRP capable ultra node).
		 */

		is_leaf = NODE_IS_LEAF(dn);

		if (is_leaf) {
			/* Leaf node */
			if (!leaves) {
				continue;				/* Routing duplicate query, skip! */
			} else if (whats_new) {
				if (NODE_CAN_WHAT(dn)) {
					goto can_send;		/* What's New? queries broadcasted */
				} else {
					continue;			/* Leaf won't understand it, skip! */
				}
			}
			if (rt == NULL)				/* No QRT yet */
				continue;				/* Don't send anything */
			if (NODE_HAS_BAD_GUID(dn)) {
				if (!NODE_USES_DUP_GUID(dn))
					continue;			/* Rogue node, probably */
				if (NODE_IS_FIREWALLED(dn))
					continue;			/* Will not be able to PUSH to it */
			}
		} else {
			/* Ultra node */
			if (0 == ttl)				/* Exclude routing to other UPs */
				continue;
			if (ttl > 1)				/* Only deal with last-hop UP */
				goto can_send;			/* Send to other UP if ttl > 1 */
			if (whats_new) {
				if (NODE_CAN_WHAT(dn)) {
					goto can_send;		/* Broadcast to that node */
				} else {
					continue;			/* Skip node, would not be efficient */
				}
			}
			if (rt == NULL)				/* UP has not sent us its table */
				goto can_send;			/* Forward everything then */
		}

		node_inc_qrp_query(dn);			/* We have a QRT, mark we try routing */

		if (!(qhvec->has_urn ?
			  rt->can_route_urn(qhvec, rt) :
			  rt->can_route(qhvec, rt)))
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
			if ((int) random_value(99) >= rt->pass_throw)
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
		 * We don't let SHA1 queries through, as the chances they will match
		 * are very slim: not all servents include the SHA1 in their QRP, and
		 * there can be many hashing conflicts, so the fact that it matched
		 * an entry in the QRP table does not imply there will be a match
		 * in the leaf node.
		 *		--RAM, 31/12/2003
		 */

		if (NODE_IN_TX_FLOW_CONTROL(dn)) {
			if (sha1_query)
				continue;
			if (random_value(255) >= 128)
				continue;
		}

		/*
		 * OK, can send the query to that node.
		 */

	can_send:

		/*
		 * Severely limit traffic to transient nodes since we're going
		 * to shut them down soon anyway.  Send them something randomly
		 * to limit easy spotting and account for the fact that the query
		 * could be usefully relayed still (albeit it better have OOB
		 * delivery).  The more spam they return, the less we send them.
		 *		--RAM, 2011-11-24.
		 */

		if (NODE_IS_TRANSIENT(dn)) {
			unsigned ratio;
			ratio = uint_saturate_mult(dn->n_spam, 100) / (dn->received + 1);
			if (random_value(99) < ratio)
				continue;
		}

		nodes = g_slist_prepend(nodes, dn);
		if (rt != NULL && !whats_new)
			node_inc_qrp_match(dn);
	}

	return nodes;
}

/**
 * Route query message to leaf nodes, based on their QRT, or to ultrapeers
 * that support last-hop QRP if TTL=1.
 *
 * When ``leaves'' is FALSE, we don't route to leaf nodes because we're
 * routing a duplicate query (with higher TTL) which leaves already got.
 */
void
qrt_route_query(struct gnutella_node *n, query_hashvec_t *qhvec, bool leaves)
{
	GSList *nodes;				/* Targets for the query */

	g_assert(qhvec != NULL);
	g_assert(gnutella_header_get_function(&n->header) == GTA_MSG_SEARCH);

	nodes = qrt_build_query_target(qhvec,
				gnutella_header_get_hops(&n->header),
				gnutella_header_get_ttl(&n->header),
				leaves, n);

	if G_UNLIKELY(
		GNET_PROPERTY(qrp_debug) > 4 ||
		GNET_PROPERTY(query_debug) > 10 ||
		GNET_PROPERTY(log_gnutella_routing) ||
		(GNET_PROPERTY(guess_server_debug) > 4 && NODE_IS_UDP(n))
	) {
		GSList *sl;
		int leaves = 0;
		int ultras = 0;
		int words = 0;
		int urns = 0;
		size_t i;

		for (sl = nodes; sl; sl = g_slist_next(sl)) {
			struct gnutella_node *dn = sl->data;

			if (NODE_IS_LEAF(dn))
				leaves++;
			else
				ultras++;
		}

		for (i = 0; i < qhvec->count; i++) {
			if (QUERY_H_WORD == qhvec->vec[i].source)
				words++;
			else
				urns++;
		}

		g_debug(
			"QRP %s%s %s(%d word%s + %d URN%s) "
			"forwarded to %d/%d leaves, %d ultra%s",
			NODE_IS_UDP(n) ? "(GUESS) " : "",
			gmsg_node_infostr(n),
			qhvec_whats_new(qhvec) ? "\"What's New?\" " : "",
			words, 1 == words ? "" : "s", urns, 1 == urns ? "" : "s",
			leaves, GNET_PROPERTY(node_leaf_count),
			ultras, ultras == 1 ? "" : "s");
	}

	if (nodes == NULL)
		return;

	/*
	 * Since this query is going to be sent on the network, compact it
	 * if requested.
	 */

	if (
		GNET_PROPERTY(gnet_compact_query) || (n->msg_flags & NODE_M_EXT_CLEANUP)
	)
		search_compact(n);

	/*
	 * Now that the original TTL was used to build the node list, don't
	 * forget that we choose to forward queries that reach us with TTL=0
	 * to our leaves.  But we can never send out a TTL=0 message, so
	 * increase the TTL before sending.
	 */

	if G_UNLIKELY(gnutella_header_get_ttl(&n->header) == 0)
		gnutella_header_set_ttl(&n->header, 1);

	gmsg_split_routeto_all(nodes, n, &n->header, n->data,
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

G_GNUC_COLD void
test_hash(void)
{
	static const struct {
		const uint32 s[16];
		const uint32 hash;
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
	uint i;

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
		char buf[1024];
		size_t n;
		uint32 h;

		n = utf32_to_utf8(tests[i].s, buf, G_N_ELEMENTS(buf));
		g_assert(n < G_N_ELEMENTS(buf));

		h = qrp_hash(buf, 10);
		if (h != tests[i].hash) {
			g_error("qrp_hash() failed: i=%d, h=%u, buf=\"%s\"", i, h, buf);
			g_assert_not_reached();
		}
	}

}

/* vi: set ts=4 sw=4 cindent: */
