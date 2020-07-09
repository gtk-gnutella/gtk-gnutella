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
 *      51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *----------------------------------------------------------------------
 */

/**
 * @ingroup core
 * @file
 *
 * Bandwidth scheduling.
 *
 * @author Raphael Manfredi
 * @date 2002-2003
 */

#include "common.h"

#include "bsched.h"
#include "inet.h"
#include "sockets.h"
#include "uploads.h"

#include "if/core/wrap.h"		/* For wrapped_io_t */
#include "if/gnet_property_priv.h"

#include "lib/compat_sendfile.h"
#include "lib/entropy.h"
#include "lib/halloc.h"
#include "lib/hstrfn.h"
#include "lib/inputevt.h"
#include "lib/parse.h"
#include "lib/plist.h"
#include "lib/pslist.h"
#include "lib/stringify.h"
#include "lib/vmm.h"
#include "lib/walloc.h"

#include "lib/override.h"		/* Must be the last header included */

/*
 * Scheduling flags.
 */
enum {
	BS_F_ENABLED		= (1 << 0),		/**< Scheduler enabled */
	BS_F_READ			= (1 << 1),		/**< Reading sources */
	BS_F_WRITE			= (1 << 2),		/**< Writing sources */
	BS_F_NOBW			= (1 << 3),		/**< No more bandwidth */
	BS_F_FROZEN_SLOT	= (1 << 4),		/**< Value of `bw_slot' is frozen */
	BS_F_CHANGED_BW		= (1 << 5),		/**< Bandwidth limit changed */
	BS_F_CLEARED		= (1 << 6),		/**< Ran clear_active once on sched. */
	BS_F_DATA_READ		= (1 << 7),		/**< Data read from one source */
	BS_F_NO_STEALING	= (1 << 8),		/**< Prevent b/w stealing from us */
	BS_F_STOLEN_IGN		= (1 << 9),		/**< Ignore stolen bandwidth */
	BS_F_UNIFORM_BW		= (1 << 10),	/**< Uniform b/w allocation */

	BS_F_RW				= (BS_F_READ|BS_F_WRITE)
};

/*
 * Scheduling types.
 */

enum {
	BS_T_STREAM	= 1,	/**< Streaming */
	BS_T_RANDOM	= 2		/**< Random (unsupported) */
};

enum bsched_magic {
	BSCHED_MAGIC = 0x6e24261eU
};

/**
 * Bandwidth scheduler.
 *
 * A bandwidth scheduler (`B-sched' for short) is made of:
 *
 * - A set of I/O sources.
 * - A set of I/O callbacks to trigger when I/O sources are ready.
 * - A bandwidth limit per scheduling perdiod.
 * - A scheduling period.
 *
 * It operates in cooperation with the I/O sources:
 *
 * -# Each I/O source registers its I/O callback through the B-sched, so
 *    that it is possible to temporarily disable them should we run out of
 *    bandwidth for the period.
 * -# Each I/O source requests an amount of bandwidth to use.
 * -# After use, each I/O source tells the B-sched how much of the allocated
 *    bandwidth it really used.
 *
 * Periodically, the scheduler runs to compute the amount available for the
 * next period.
 *
 * A list of stealing schedulers can be added to each scheduler.  At the end
 * of the period, any amount of bandwidth that has been unused will be
 * given as "stolen" bandwidth to some of the schedulers stealing from us.
 * Priority is given to schedulers that used up all their bandwidth.
 */

struct bsched {
	enum bsched_magic magic;
	tm_t last_period;			/**< Last time we ran our period */
	plist_t *sources;			/**< List of bio_source_t */
	pslist_t *stealers;			/**< List of bsched_t stealing bw */
	char *name;					/**< Name, for tracing purposes */
	int count;					/**< Amount of sources */
	uint type;					/**< Scheduling type */
	uint flags;					/**< Processing flags */
	int period;					/**< Fixed scheduling period, in ms */
	int min_period;				/**< Minimal period without correction */
	int max_period;				/**< Maximal period without correction */
	int period_ema;				/**< EMA of period, in ms */
	int64 bw_per_second;		/**< Configured bandwidth in bytes/sec */
	int64 bw_max;				/**< Max bandwidth per period */
	int64 bw_actual;			/**< Bandwidth used so far in period */
	int64 bw_last_period;		/**< Bandwidth used last period */
	int64 bw_last_capped;		/**< Bandwidth capped last period */
	int64 bw_slot;				/**< Basic per-source bandwidth lot */
	int64 bw_ema;				/**< EMA of bandwidth really used */
	int64 bw_stolen;			/**< Amount we stole this period */
	int64 bw_stolen_ema;		/**< EMA of stolen bandwidth */
	int64 bw_delta;				/**< Running diff of actual vs. theoric */
	int64 bw_unwritten;			/**< Data that we could not write */
	int64 bw_capped;			/**< Bandwidth we refused to sources */
	int64 bw_urgent;			/**< Urgent b/w required in stealing */
	int last_used;				/**< Nb of active sources last period */
	int current_used;			/**< Nb of active sources this period */
	uint io_favours;			/**< Amount of sources wanting favours */
	unsigned looped:1;			/**< True when looped once over sources */
};

/*
 * Global bandwidth schedulers.
 */

static bsched_t *bws_set[NUM_BSCHED_BWS];

static pslist_t *bws_list = NULL;
static pslist_t *bws_out_list = NULL;
static pslist_t *bws_in_list = NULL;
static int64 bws_out_ema = 0;
static int64 bws_in_ema = 0;

#define BW_SLOT_MIN		256	 /**< Minimum bandwidth/slot for realloc */

#define BW_OUT_UP_MIN	8192 /**< Minimum out bandwidth for becoming ultra */
#define BW_OUT_GNET_MIN	128	 /**< Minimum out bandwidth per Gnet connection */
#define BW_OUT_LEAF_MIN	32	 /**< Minimum out bandwidth per leaf connection */
#define BW_UL_STALL_TIM	21600	/**< Hysteresis for upload stalling condition */
#define BW_UL_RUN_TIME	3600 /**< Check period for running uploads */

#define BW_TCP_MSG		40	 /**< Smallest size of a TCP message */
#define BW_UDP_MSG		28	 /**< Minimal IP+UDP overhead for a UDP message */

#define BW_UDP_OVERSIZE	1024 /**< Allow that many bytes over available b/w */

static inline void
bsched_check(const bsched_t * const bs)
{
	g_assert(bs);
	g_assert(BSCHED_MAGIC == bs->magic);
}

static inline void
bio_check(const bio_source_t * const bio)
{
	g_assert(bio);
	g_assert(BIO_SOURCE_MAGIC == bio->magic);
}

/**
 * Create a new bandwidth scheduler.
 *
 * @param `name' no brief description.
 * @param `type' refers to the scheduling model.  Only BS_T_STREAM for now.
 * @param `mode' refers to the nature of the sources: either reading or writing.
 * @param `bandwidth' is the expected bandwidth in bytes per second.
 * @param `period' is the scheduling period in ms.
 */
static bsched_t *
bsched_make(const char *name, uint type, uint32 mode,
	int64 bandwidth, uint period)
{
	bsched_t *bs;

	/* Must contain either reading or writing sources */
	g_assert(mode & BS_F_RW);
	g_assert((mode & BS_F_RW) != BS_F_RW);
	g_assert(!(mode & ~BS_F_RW));

	g_assert(bandwidth >= 0);
	g_assert(period > 0);
	g_assert(type == BS_T_STREAM);		/* XXX only mode supported for now */
	g_assert(bandwidth <= BS_BW_MAX);	/* Signed, and multiplied by 1000 */

	WALLOC0(bs);
	bs->magic = BSCHED_MAGIC;
	bs->name = h_strdup(name);
	bs->flags = mode;
	bs->type = type;
	bs->period = period;
	bs->min_period = period >> 1;		/* 50% of nominal period */
	bs->max_period = period << 1;		/* 200% of nominal period */
	bs->period_ema = period;
	bs->bw_per_second = bandwidth;
	bs->bw_max = (int64) (bandwidth / 1000.0 * period);

	return bs;
}

static bsched_t *
bsched_get(bsched_bws_t bws)
{
	uint i = (uint) bws;

	g_assert(i < NUM_BSCHED_BWS);
	bsched_check(bws_set[i]);
	return bws_set[i];
}


/**
 * Free bandwidth scheduler.
 *
 * All sources have their bsched pointer reset to NULL but are not disposed of.
 * Naturally, they cannot be used for I/O any more.
 */
static void
bsched_free(bsched_t *bs)
{
	plist_t *iter;

	bsched_check(bs);

	PLIST_FOREACH(bs->sources, iter) {
		bio_source_t *bio = iter->data;

		bio_check(bio);
		g_assert(bsched_get(bio->bws) == bs);
		bio->bws = BSCHED_BWS_INVALID;	/* Mark orphan source */
	}

	plist_free_null(&bs->sources);
	pslist_free_null(&bs->stealers);
	HFREE_NULL(bs->name);
	bs->magic = 0;
	WFREE(bs);
}

/**
 * Is bandwidth scheduler saturated currently?
 */
bool
bsched_saturated(bsched_bws_t bws)
{
	const bsched_t *bs = bsched_get(bws);
	if (!(bs->flags & BS_F_ENABLED))		/* Scheduler disabled */
		return FALSE;
	return bs->bw_actual > bs->bw_max;
}

/**
 * @return amount of unused bandwidth in this scheduler during the
 * last period, in bytes.
 */
uint64
bsched_unused(bsched_bws_t bws)
{
	const bsched_t *bs = bsched_get(bws);
	uint64 unused;

	if (!(bs->flags & BS_F_ENABLED))		/* Scheduler disabled */
		return BS_BW_MAX;

	unused = uint64_saturate_sub(bs->bw_max, bs->bw_last_period);
	return uint64_saturate_sub(unused, bs->bw_urgent);
}

uint64
bsched_bps(bsched_bws_t bws)
{
	const bsched_t *bs = bsched_get(bws);
	return bs->bw_last_period * 1000 / bs->period;
}

uint64
bsched_avg_bps(bsched_bws_t bws)
{
	const bsched_t *bs = bsched_get(bws);
	return bs->bw_ema * 1000 / bs->period;
}

uint64
bsched_bw_per_second(bsched_bws_t bws)
{
	const bsched_t *bs = bsched_get(bws);
	return bs->bw_per_second;
}

ulong
bsched_pct(bsched_bws_t bws)
{
	return bsched_bps(bws) * 100 / (1 + bsched_bw_per_second(bws));
}

ulong
bsched_avg_pct(bsched_bws_t bws)
{
	return bsched_avg_bps(bws) * 100 / (1 + bsched_bw_per_second(bws));
}

int64
bsched_urgent(bsched_bws_t bws)
{
	const bsched_t *bs = bsched_get(bws);
	return bs->bw_urgent;
}

/**
 * Record urgent bandwidth stealing needs that should be fulfilled to
 * prevent any TX flow control situation.
 */
void
bsched_set_urgent(bsched_bws_t bws, int64 amount)
{
	bsched_t *bs;

	g_soft_assert_log(amount > 0,
		"%s: amount=%s", G_STRFUNC, int64_to_string(amount));

	bs = bsched_get(bws);
	bs->bw_urgent = MAX(amount, 0);
}

/**
 * Add `stealer' as a bandwidth stealer for underused bandwidth in `bws'.
 * Both must be either reading or writing schedulers.
 */
static void
bsched_add_stealer(bsched_bws_t bws, bsched_bws_t bws_stealer)
{
	bsched_t *bs, *stealer;

	g_assert(bws != bws_stealer);

	bs = bsched_get(bws);
	stealer = bsched_get(bws_stealer);
	g_assert((bs->flags & BS_F_RW) == (stealer->flags & BS_F_RW));

	bs->stealers = pslist_prepend(bs->stealers, stealer);
}

/**
 * Reset `stealer' list for scheduler.
 */
static void
bsched_reset_stealers(bsched_t *bs)
{
	bsched_check(bs);

	pslist_free_null(&bs->stealers);
}

/**
 * Configure outband DHT traffic cross-stealing with Gnutella UDP
 */
static void G_COLD
bsched_dht_cross_stealing(void)
{
	bsched_add_stealer(BSCHED_BWS_GOUT_UDP, BSCHED_BWS_DHT_OUT);
	bsched_add_stealer(BSCHED_BWS_DHT_OUT, BSCHED_BWS_GOUT_UDP);
}

/**
 * Allow cross-stealing of unused bandwidth between HTTP/gnet.
 */
void G_COLD
bsched_config_steal_http_gnet(void)
{
	pslist_t *iter;

	PSLIST_FOREACH(bws_list, iter) {
		bsched_bws_t bws = pointer_to_uint(iter->data);
		bsched_reset_stealers(bsched_get(bws));
	}

	bsched_add_stealer(BSCHED_BWS_OUT, BSCHED_BWS_GOUT);
	bsched_add_stealer(BSCHED_BWS_OUT, BSCHED_BWS_GOUT_UDP);
	bsched_add_stealer(BSCHED_BWS_OUT, BSCHED_BWS_GLOUT);
	bsched_add_stealer(BSCHED_BWS_OUT, BSCHED_BWS_DHT_OUT);

	bsched_add_stealer(BSCHED_BWS_GOUT, BSCHED_BWS_OUT);
	bsched_add_stealer(BSCHED_BWS_GOUT, BSCHED_BWS_GOUT_UDP);
	bsched_add_stealer(BSCHED_BWS_GOUT, BSCHED_BWS_GLOUT);

	bsched_add_stealer(BSCHED_BWS_IN, BSCHED_BWS_GIN);
	bsched_add_stealer(BSCHED_BWS_IN, BSCHED_BWS_GIN_UDP);
	bsched_add_stealer(BSCHED_BWS_IN, BSCHED_BWS_GLIN);

	bsched_add_stealer(BSCHED_BWS_GIN, BSCHED_BWS_IN);
	bsched_add_stealer(BSCHED_BWS_GIN, BSCHED_BWS_GIN_UDP);
	bsched_add_stealer(BSCHED_BWS_GIN, BSCHED_BWS_GLIN);

	bsched_add_stealer(BSCHED_BWS_GLOUT, BSCHED_BWS_GOUT);
	bsched_add_stealer(BSCHED_BWS_GLOUT, BSCHED_BWS_GOUT_UDP);
	bsched_add_stealer(BSCHED_BWS_GLOUT, BSCHED_BWS_OUT);
	bsched_add_stealer(BSCHED_BWS_GLOUT, BSCHED_BWS_DHT_OUT);

	bsched_add_stealer(BSCHED_BWS_GLIN, BSCHED_BWS_GIN);
	bsched_add_stealer(BSCHED_BWS_GLIN, BSCHED_BWS_GIN_UDP);
	bsched_add_stealer(BSCHED_BWS_GLIN, BSCHED_BWS_IN);

	bsched_add_stealer(BSCHED_BWS_GOUT_UDP, BSCHED_BWS_GOUT);
	bsched_add_stealer(BSCHED_BWS_GOUT_UDP, BSCHED_BWS_GLOUT);
	bsched_add_stealer(BSCHED_BWS_GOUT_UDP, BSCHED_BWS_OUT);

	bsched_add_stealer(BSCHED_BWS_DHT_OUT, BSCHED_BWS_GOUT);
	bsched_add_stealer(BSCHED_BWS_DHT_OUT, BSCHED_BWS_GLOUT);
	bsched_add_stealer(BSCHED_BWS_DHT_OUT, BSCHED_BWS_OUT);

	bsched_dht_cross_stealing();
}

/**
 * Allow cross-stealing of unused bandwidth between TCP and UDP gnet only.
 */
void G_COLD
bsched_config_steal_gnet(void)
{
	pslist_t *iter;

	PSLIST_FOREACH(bws_list, iter) {
		bsched_bws_t bws = GPOINTER_TO_UINT(iter->data);
		bsched_reset_stealers(bsched_get(bws));
	}

	bsched_add_stealer(BSCHED_BWS_GIN, BSCHED_BWS_GIN_UDP);
	bsched_add_stealer(BSCHED_BWS_GOUT, BSCHED_BWS_GOUT_UDP);
	bsched_add_stealer(BSCHED_BWS_GOUT_UDP, BSCHED_BWS_GOUT);

	bsched_dht_cross_stealing();
}

/*
 * This is called BEFORE settings_init(), bandwidth values are the default
 * values, not the configured ones.
 */
void G_COLD
bsched_early_init(void)
{
	bws_set[BSCHED_BWS_OUT] = bsched_make("out",
		BS_T_STREAM, BS_F_WRITE, GNET_PROPERTY(bw_http_out), 1000);

	bws_set[BSCHED_BWS_GOUT] = bsched_make("G TCP out",
		BS_T_STREAM, BS_F_WRITE, GNET_PROPERTY(bw_gnet_out) / 2, 1000);

	bws_set[BSCHED_BWS_GOUT_UDP] = bsched_make("G UDP out",
		BS_T_STREAM, BS_F_WRITE, GNET_PROPERTY(bw_gnet_out) / 2, 1000);

	bws_set[BSCHED_BWS_GLOUT] = bsched_make("GL out",
		BS_T_STREAM, BS_F_WRITE, GNET_PROPERTY(bw_gnet_lout), 1000);

	bws_set[BSCHED_BWS_IN] = bsched_make("in",
		BS_T_STREAM, BS_F_READ, GNET_PROPERTY(bw_http_in), 1000);

	bws_set[BSCHED_BWS_GIN] = bsched_make("G TCP in",
		BS_T_STREAM, BS_F_READ, GNET_PROPERTY(bw_gnet_in) / 2, 1000);

	bws_set[BSCHED_BWS_GIN_UDP] = bsched_make("G UDP in",
		BS_T_STREAM, BS_F_READ, 0, 1000);

	bws_set[BSCHED_BWS_GLIN] = bsched_make("GL in",
		BS_T_STREAM, BS_F_READ, GNET_PROPERTY(bw_gnet_lin), 1000);

	bws_set[BSCHED_BWS_LOOPBACK_OUT] = bsched_make("loopback out",
		BS_T_STREAM, BS_F_WRITE, 0, 1000);

	bws_set[BSCHED_BWS_LOOPBACK_IN] = bsched_make("loopback in",
		BS_T_STREAM, BS_F_READ, 0, 1000);

	bws_set[BSCHED_BWS_PRIVATE_OUT] = bsched_make("private out",
		BS_T_STREAM, BS_F_WRITE, 0, 1000);

	bws_set[BSCHED_BWS_PRIVATE_IN] = bsched_make("private in",
		BS_T_STREAM, BS_F_READ, 0, 1000);

	bws_set[BSCHED_BWS_DHT_OUT] = bsched_make("DHT out",
		BS_T_STREAM, BS_F_WRITE, GNET_PROPERTY(bw_dht_out), 1000);

	bws_set[BSCHED_BWS_DHT_IN] = bsched_make("DHT in",
		BS_T_STREAM, BS_F_READ, 0, 1000);

	bws_list = pslist_prepend(bws_list,
						uint_to_pointer(BSCHED_BWS_LOOPBACK_IN));
	bws_list = pslist_prepend(bws_list,
						uint_to_pointer(BSCHED_BWS_PRIVATE_IN));
	bws_list = pslist_prepend(bws_list,
						uint_to_pointer(BSCHED_BWS_GLIN));
	bws_list = pslist_prepend(bws_list,
						uint_to_pointer(BSCHED_BWS_GIN));
	bws_list = pslist_prepend(bws_list,
						uint_to_pointer(BSCHED_BWS_GIN_UDP));
	bws_list = pslist_prepend(bws_list,
						uint_to_pointer(BSCHED_BWS_IN));
	bws_list = pslist_prepend(bws_list,
						uint_to_pointer(BSCHED_BWS_DHT_IN));
	bws_list = pslist_prepend(bws_list,
						uint_to_pointer(BSCHED_BWS_LOOPBACK_OUT));
	bws_list = pslist_prepend(bws_list,
						uint_to_pointer(BSCHED_BWS_PRIVATE_OUT));
	bws_list = pslist_prepend(bws_list,
						uint_to_pointer(BSCHED_BWS_GLOUT));
	bws_list = pslist_prepend(bws_list,
						uint_to_pointer(BSCHED_BWS_GOUT));
	bws_list = pslist_prepend(bws_list,
						uint_to_pointer(BSCHED_BWS_GOUT_UDP));
	bws_list = pslist_prepend(bws_list,
						uint_to_pointer(BSCHED_BWS_OUT));
	bws_list = pslist_prepend(bws_list,
						uint_to_pointer(BSCHED_BWS_DHT_OUT));

	bws_in_list = pslist_prepend(bws_in_list,
						uint_to_pointer(BSCHED_BWS_LOOPBACK_IN));
	bws_in_list = pslist_prepend(bws_in_list,
						uint_to_pointer(BSCHED_BWS_PRIVATE_IN));
	bws_in_list = pslist_prepend(bws_in_list,
						uint_to_pointer(BSCHED_BWS_GLIN));
	bws_in_list = pslist_prepend(bws_in_list,
						uint_to_pointer(BSCHED_BWS_GIN));
	bws_in_list = pslist_prepend(bws_in_list,
						uint_to_pointer(BSCHED_BWS_GIN_UDP));
	bws_in_list = pslist_prepend(bws_in_list,
						uint_to_pointer(BSCHED_BWS_IN));
	bws_in_list = pslist_prepend(bws_in_list,
						uint_to_pointer(BSCHED_BWS_DHT_IN));

	bws_out_list = pslist_prepend(bws_out_list,
						uint_to_pointer(BSCHED_BWS_LOOPBACK_OUT));
	bws_out_list = pslist_prepend(bws_out_list,
						uint_to_pointer(BSCHED_BWS_PRIVATE_OUT));
	bws_out_list = pslist_prepend(bws_out_list,
						uint_to_pointer(BSCHED_BWS_GLOUT));
	bws_out_list = pslist_prepend(bws_out_list,
						uint_to_pointer(BSCHED_BWS_GOUT));
	bws_out_list = pslist_prepend(bws_out_list,
						uint_to_pointer(BSCHED_BWS_GOUT_UDP));
	bws_out_list = pslist_prepend(bws_out_list,
						uint_to_pointer(BSCHED_BWS_OUT));
	bws_out_list = pslist_prepend(bws_out_list,
						uint_to_pointer(BSCHED_BWS_DHT_OUT));
}

/**
 * Configure schedules with actual limits set by the user.
 */
static void G_COLD
bsched_correct_init(void)
{
	bsched_set_bandwidth(BSCHED_BWS_OUT, GNET_PROPERTY(bw_http_out));
	bsched_set_bandwidth(BSCHED_BWS_GOUT, GNET_PROPERTY(bw_gnet_out) / 2);
	bsched_set_bandwidth(BSCHED_BWS_GOUT_UDP, GNET_PROPERTY(bw_gnet_out) / 2);
	bsched_set_bandwidth(BSCHED_BWS_GLOUT, GNET_PROPERTY(bw_gnet_lout));
	bsched_set_bandwidth(BSCHED_BWS_IN, GNET_PROPERTY(bw_http_in));
	bsched_set_bandwidth(BSCHED_BWS_GIN, GNET_PROPERTY(bw_gnet_in));
	bsched_set_bandwidth(BSCHED_BWS_GIN_UDP, 0);
	bsched_set_bandwidth(BSCHED_BWS_GLIN, GNET_PROPERTY(bw_gnet_lin));
	bsched_set_bandwidth(BSCHED_BWS_DHT_OUT, GNET_PROPERTY(bw_dht_out));
	bsched_set_bandwidth(BSCHED_BWS_DHT_IN, 0);
}

/**
 * Initialize global bandwidth schedulers.
 */
void G_COLD
bsched_init(void)
{
	bsched_correct_init();	/* Fix badnwidth using user-configured values */

	/*
	 * We always steal bandwidth between TCP and UDP gnet, since we
	 * forcefully split the allocated bandwidth evenly between the
	 * two traffic types.
	 */

	if (GNET_PROPERTY(bw_allow_stealing))
		bsched_config_steal_http_gnet();
	else
		bsched_config_steal_gnet();

	bsched_set_peermode(GNET_PROPERTY(current_peermode));
}

/**
 * Discard global bandwidth schedulers.
 */
void G_COLD
bsched_close(void)
{
	pslist_t *iter;
	uint i;

	PSLIST_FOREACH(bws_list, iter) {
		bsched_bws_t bws = pointer_to_uint(iter->data);
		bsched_free(bsched_get(bws));
	}

	pslist_free_null(&bws_list);
	pslist_free_null(&bws_out_list);
	pslist_free_null(&bws_in_list);

	for (i = 0; i < NUM_BSCHED_BWS; i++) {
		bws_set[i] = NULL;
	}
}

/**
 * Adapt the overall Gnet/HTTP bandwidth repartition depending on the current
 * peermode.
 *
 * This routine is called each time the peermode changes or each time the
 * settings for the traffic shapers changes.
 */
void
bsched_set_peermode(node_peer_t mode)
{
	uint64 steal;

	switch (mode) {
	case NODE_P_NORMAL:
	case NODE_P_LEAF:
		bsched_set_bandwidth(BSCHED_BWS_GLIN, 1);		/* 0 would disable it */
		bsched_set_bandwidth(BSCHED_BWS_GLOUT, 1);
		bsched_set_bandwidth(BSCHED_BWS_IN, GNET_PROPERTY(bw_http_in));
		bsched_set_bandwidth(BSCHED_BWS_OUT, GNET_PROPERTY(bw_http_out));
		break;
	case NODE_P_ULTRA:
		/*
		 * If leaf traffic shaper is enabled, steal bandwidth from HTTP.
		 * Otherwise, bandwidth is unlimited.
		 */

		steal = MIN(GNET_PROPERTY(bw_http_in), GNET_PROPERTY(bw_gnet_lin));
		if (GNET_PROPERTY(bws_glin_enabled) && steal) {
			bsched_set_bandwidth(BSCHED_BWS_GLIN, steal);
			bsched_set_bandwidth(BSCHED_BWS_IN,
				MAX(1, GNET_PROPERTY(bw_http_in) - steal));
		} else {
			bsched_set_bandwidth(BSCHED_BWS_GLIN, 0);			/* Disables */
			bsched_set_bandwidth(BSCHED_BWS_IN, GNET_PROPERTY(bw_http_in));
		}

		steal = MIN(GNET_PROPERTY(bw_http_out), GNET_PROPERTY(bw_gnet_lout));
		if (GNET_PROPERTY(bws_glout_enabled) && steal) {
			bsched_set_bandwidth(BSCHED_BWS_GLOUT, steal);
			bsched_set_bandwidth(BSCHED_BWS_OUT,
				MAX(1, GNET_PROPERTY(bw_http_out) - steal));
		} else {
			bsched_set_bandwidth(BSCHED_BWS_GLOUT, 0);			/* Disables */
			bsched_set_bandwidth(BSCHED_BWS_OUT, GNET_PROPERTY(bw_http_out));
		}

		if (
			bsched_bw_per_second(BSCHED_BWS_GLIN) &&
			GNET_PROPERTY(bws_glin_enabled)
		) {
			bsched_enable(BSCHED_BWS_GLIN);
		}
		if (
			bsched_bw_per_second(BSCHED_BWS_GLOUT) &&
			GNET_PROPERTY(bws_glout_enabled)
		) {
			bsched_enable(BSCHED_BWS_GLOUT);
		}
		break;
	default:
		g_error("unhandled peer mode %d", mode);
	}
}

/**
 * Enable scheduling, marks the start of the period.
 */
void
bsched_enable(bsched_bws_t bws)
{
	bsched_t *bs = bsched_get(bws);
	bs->flags |= BS_F_ENABLED;
	tm_now(&bs->last_period);

	if (GNET_PROPERTY(bsched_debug))
		g_debug("BSCHED enabling \"%s\"", bs->name);
}

/**
 * Disable scheduling.
 */
void
bsched_disable(bsched_bws_t bws)
{
	bsched_t *bs = bsched_get(bws);
	bs->flags &= ~BS_F_ENABLED;

	if (GNET_PROPERTY(bsched_debug))
		g_debug("BSCHED disabling \"%s\"", bs->name);
}

/**
 * Enable all known bandwidth schedulers.
 */
void
bsched_enable_all(void)
{
	if (
		bsched_bw_per_second(BSCHED_BWS_OUT) &&
		GNET_PROPERTY(bws_out_enabled)
	) {
		bsched_enable(BSCHED_BWS_OUT);
	}
	if (
		bsched_bw_per_second(BSCHED_BWS_GOUT) &&
		GNET_PROPERTY(bws_gout_enabled)
	) {
		bsched_enable(BSCHED_BWS_GOUT);
		bsched_enable(BSCHED_BWS_GOUT_UDP);
	}

	if (
		bsched_bw_per_second(BSCHED_BWS_GLOUT) &&
		GNET_PROPERTY(bws_glout_enabled)
	) {
		bsched_enable(BSCHED_BWS_GLOUT);
	}
	if (
		bsched_bw_per_second(BSCHED_BWS_IN) &&
		GNET_PROPERTY(bws_in_enabled)
	) {
		bsched_enable(BSCHED_BWS_IN);
	}
	if (
		bsched_bw_per_second(BSCHED_BWS_GIN) &&
		GNET_PROPERTY(bws_gin_enabled)
	) {
		bsched_enable(BSCHED_BWS_GIN);
		bsched_enable(BSCHED_BWS_GIN_UDP);
	}

	if (
		bsched_bw_per_second(BSCHED_BWS_GLIN) &&
		GNET_PROPERTY(bws_glin_enabled)
	) {
		bsched_enable(BSCHED_BWS_GLIN);
	}
}

/**
 * Shutdowning program.
 * Disable all known bandwidth schedulers, so that any pending I/O can
 * go through as quickly as possible.
 */
void G_COLD
bsched_shutdown(void)
{
	pslist_t *sl;

	PSLIST_FOREACH(bws_list, sl) {
		bsched_bws_t bws = pointer_to_uint(sl->data);
		bsched_disable(bws);
	}
}

/**
 * @return b/w per second configured for the scheduler to which this I/O
 * source belongs.
 */
uint64
bio_bw_per_second(const bio_source_t *bio)
{
	const bsched_t *bs;

	bio_check(bio);

	bs = bsched_get(bio->bws);
	return bs->bw_per_second;
}

/**
 * Trigger the "passive" callback to signify that a new timeslice has begun
 * and that I/Os can resume on the source.
 */
static void
bio_trigger(const bio_source_t *bio)
{
	bio_check(bio);
	g_assert(0 == bio->io_tag);
	g_assert(bio->io_callback != NULL);
	g_assert(bio->flags & BIO_F_PASSIVE);
	wrap_io_check(bio->wio);

	(*bio->io_callback)(bio->io_arg, bio->wio->fd(bio->wio),
		(bio->flags & BIO_F_READ) ? INPUT_EVENT_R : INPUT_EVENT_W);
}

/**
 * Enable an I/O source.
 */
static void
bio_enable(bio_source_t *bio)
{
	bio_check(bio);
	g_assert(0 == bio->io_tag);
	g_assert(bio->io_callback);		/* "passive" sources not concerned */
	g_assert(0 == (bio->flags & BIO_F_PASSIVE));
	wrap_io_check(bio->wio);

	bio->io_tag = inputevt_add(bio->wio->fd(bio->wio),
			(bio->flags & BIO_F_READ) ? INPUT_EVENT_RX : INPUT_EVENT_WX,
			bio->io_callback, bio->io_arg);

	g_assert(bio->io_tag);
}

/**
 * Get I/O source configured buffer size.
 *
 * @return the underlying socket buffer size, 0 if unknown.
 */
unsigned
bio_get_bufsize(const bio_source_t *bio, enum socket_buftype type)
{
	bio_check(bio);
	wrap_io_check(bio->wio);
	return bio->wio->bufsize(bio->wio, type);
}

/**
 * Disable I/O source.
 *
 * The value of `bw_available' is ignored, as this is a fairly low-level call.
 * If it is called, then the caller has already taken care of redispatching
 * any remaining bandwidth.
 */
static void
bio_disable(bio_source_t *bio)
{
	bio_check(bio);
	g_assert(bio->io_tag);
	g_assert(bio->io_callback);		/* "passive" sources not concerned */
	g_assert(0 == (bio->flags & BIO_F_PASSIVE));

	inputevt_remove(&bio->io_tag);
}

/**
 * Add I/O callback to a "passive" I/O source, making it active.
 *
 * The source will be added to the input event dispatcher and the callback
 * will be invoked as soon as something happens on that source (for instance
 * it becomes readable, writable, or an exception occurs).
 */
void
bio_add_callback(bio_source_t *bio, inputevt_handler_t callback, void *arg)
{
	bio_check(bio);
	g_assert(bio->io_callback == NULL);	/* "passive" source */
	g_assert(callback);

	bio->io_callback = callback;
	bio->io_arg = arg;
	bio->flags &= ~BIO_F_PASSIVE;

	if (!(bsched_get(bio->bws)->flags & BS_F_NOBW))
		bio_enable(bio);
}

/**
 * Adds I/O callback to a "passive" I/O source, without making it active.
 *
 * The callback will be invoked with read/write events each time a new
 * scheduling time slice begins (which should indicate that bandwidth is
 * available for I/Os) but the source will not be added to the input event
 * dispatcher.
 *
 * Typically that would be useful on never-blocking sources (like files, on
 * which we would like to limit read/writes) or on UDP sockets where the
 * kernel will not buffer data, hence making them always writable.
 */
void
bio_add_passive_callback(bio_source_t *bio, inputevt_handler_t cb, void *arg)
{
	bio_check(bio);
	g_assert(bio->io_callback == NULL);	/* "passive" source */
	g_assert(cb != NULL);

	bio->io_callback = cb;
	bio->io_arg = arg;
	bio->flags |= BIO_F_PASSIVE;		/* Don't call bio_enable() */
}

/**
 * Remove I/O callback from I/O source.
 */
void
bio_remove_callback(bio_source_t *bio)
{
	bio_check(bio);
	g_assert(bio->io_callback);		/* Not a "passive" source */

	if (bio->io_tag)
		bio_disable(bio);

	bio->flags &= ~BIO_F_PASSIVE;
	bio->io_callback = NULL;
	bio->io_arg = NULL;
}


/**
 * Disable all sources and flag that we have no more bandwidth.
 */
static void
bsched_no_more_bandwidth(bsched_t *bs)
{
	plist_t *iter;

	bsched_check(bs);
	PLIST_FOREACH(bs->sources, iter) {
		bio_source_t *bio = iter->data;

		bio_check(bio);

		if (bio->io_tag)
			bio_disable(bio);
	}

	bs->flags |= BS_F_NOBW;
}

/**
 * Remove activation indication on all the sources.
 */
static void
bsched_clear_active(bsched_t *bs)
{
	plist_t *iter;

	bsched_check(bs);
	PLIST_FOREACH(bs->sources, iter) {
		bio_source_t *bio = iter->data;

		bio_check(bio);
		bio->flags &= ~BIO_F_ACTIVE;
	}
}

/**
 * Called whenever a new scheduling timeslice begins.
 *
 * Re-enable all sources and flag that we have bandwidth.
 * Update the per-source bandwidth statistics.
 * Clears all activation indication on all sources.
 */
static void
bsched_begin_timeslice(bsched_t *bs)
{
	plist_t *iter, *last = NULL;
	pslist_t *trigger = NULL;
	double norm_factor;
	int count;
	int64 bw_max;

	bsched_check(bs);

	/*
	 * When the BS_F_STOLEN_IGN flag is set, stolen bandwidth can be given
	 * to this scheduler but we ignore it.  The reason is that application
	 * code which turned on this behaviour suspects that TCP may be doing
	 * some retransmission in the background, which of course we can't see
	 * and gives a false impression of bandwidth availability: some sources
	 * never actually request bandwidth when they should (kernel buffers are
	 * full).
	 *
	 * Allowing the scheduler to steal bandwidth as usual does not perturb
	 * the other I/Os.  However we're not going to use this stolen bandwidth,
	 * thereby giving a chance to TCP to flush buffered data.
	 *
	 * Note that "capped" bandwidth is also stolen bandwidth in a way: it is
	 * an amount we did not distribute during the previous timeslice, so we're
	 * stealing it from the past.  Hence we reset it as well.
	 */

	if (bs->flags & BS_F_STOLEN_IGN) {
		if (bs->bw_stolen != 0) {
			if (GNET_PROPERTY(bsched_debug)) {
				g_debug("BSCHED %s: \"%s\" ignoring stolen %s byte%s",
					G_STRFUNC, bs->name,
					int64_to_string(bs->bw_stolen), plural(bs->bw_stolen));
			}
			bs->bw_stolen = 0;
		}
		if (bs->bw_last_capped != 0) {
			if (GNET_PROPERTY(bsched_debug)) {
				g_debug("BSCHED %s: \"%s\" ignoring %s byte%s of capped b/w",
					G_STRFUNC, bs->name, int64_to_string(bs->bw_last_capped),
					plural(bs->bw_last_capped));
			}
			bs->bw_last_capped = 0;
		}
	}

	norm_factor = 1000.0 / bs->period;
	bs->io_favours = 0;
	bw_max = bs->bw_max;
	count = 0;

	PLIST_FOREACH(bs->sources, iter) {
		bio_source_t *bio = iter->data;
		uint64 actual;

		bio_check(bio);

		last = iter;		/* Remember last seen source for rotation */
		count++;			/* Count them for assertion */

		bio->flags &= ~(BIO_F_ACTIVE | BIO_F_USED);

		if (bio->io_tag == 0 && bio->io_callback) {
			if (bio->flags & BIO_F_PASSIVE)
				trigger = pslist_prepend(trigger, bio);
			else
				bio_enable(bio);
		}

		if (bio->flags & BIO_F_FAVOUR)
			bs->io_favours++;

		/*
		 * Pre-allocated banwdwidth is substracted from the available maximum
		 * to not fully starve other sources and not cause over-spending.
		 */

		bw_max -= MIN(bw_max, bio->bw_allocated);

		/*
		 * Fast EMA of bandwidth is computed on the last n=3 terms.
		 * The smoothing factor, sm=2/(n+1), is therefore 0.5, which is easy
		 * to compute.  The short period gives us a good estimation of the
		 * "instantaneous bandwidth" used.
		 *
		 * Slow EMA of bandwidth is computed on the last n=127 terms, which at
		 * one computation per second, means an average of the last two minutes.
		 * This value is smoother and therefore more suited to use for the
		 * remaining time estimates.
		 *
		 * Because we use integer arithmetic (and therefore loose important
		 * decimals), the actual values are shifted by BIO_EMA_SHIFT.
		 * The fields storing the EMAs should therefore only be accessed via
		 * the macros, which perform the shift in the other way to
		 * re-establish proper scaling.
		 */

		actual = bio->bw_actual << BIO_EMA_SHIFT;
		bio->bw_fast_ema += (actual >> 1) - (bio->bw_fast_ema >> 1);
		bio->bw_slow_ema += (actual >> 6) - (bio->bw_slow_ema >> 6);
		bio->bw_last_bps = (int64) (bio->bw_actual * norm_factor);
		bio->bw_actual = 0;
	}

	g_assert(bs->count == count);	/* All sources are there */

	/*
	 * Rotate sources, since we don't know how glib handles callbacks on
	 * the registered sources.  We don't want to always have the same
	 * sources get most of the bandwidth because they simply get added
	 * first as I/O sources.
	 */

	if (last != NULL && last != bs->sources) {
		bio_source_t *bio;

		g_assert(bs->sources != NULL);
		bio = bs->sources->data;
		bio_check(bio);
		bs->sources = plist_remove(bs->sources, bio);
		bs->sources = plist_insert_after(bs->sources, last, bio);
	}

	bs->flags &= ~(BS_F_NOBW|BS_F_FROZEN_SLOT|BS_F_CHANGED_BW|BS_F_CLEARED);

	/*
	 * On the first round of source dispatching, don't use the stolen b/w.
	 * Only introduce it when we come back to a source we already
	 * scheduled, to avoid spending bandwidth too early when we have
	 * many sources in various schedulers stealing each other some
	 * bandwidth that could starve others.
	 *
	 * In other words, don't distribute (bs->bw_max + bs->bw_stolen)
	 * among all the slots, but only bs->bw_max.  The remaining
	 * will be distributed by bw_available().
	 *
	 * We artificially raise the bandwidth per slot if we have some capped
	 * bandwidth recorded for the previous timeslice, meaning we did not used
	 * all our (writing) bandwidth and yet refused some bandwidth to active
	 * sources.
	 *
	 * Finally, if we did not use all our sources last time, we give more
	 * bandwidth to active sources.  We add 1 to the amount of sources used
	 * to avoid the same sources using all the bandwidth each time before
	 * it runs out for the time slice.  This adjustment is turned off when
	 * the BS_F_UNIFORM_BW flag is set: all sources get the same initial
	 * allocation.
	 */

	if (bs->count) {
		int dividor = bs->count;
		if (!(bs->flags & BS_F_UNIFORM_BW)) {
			if (bs->last_used > 0 && bs->last_used < bs->count)
				dividor = bs->last_used + 1;
		}
		bs->bw_slot = (bw_max + bs->bw_last_capped) / dividor;
	} else
		bs->bw_slot = 0;

	/*
	 * If the slot is less than the minimum we can reach by dynamically
	 * adjusting the bandwidth, then don't bother trying and freeze it.
	 */

	if (bs->bw_slot < BW_SLOT_MIN && bs->bw_stolen == 0)
		bs->flags |= BS_F_FROZEN_SLOT;

	/*
	 * If uniform bandwidth allocation is requested, the slot allocation is
	 * also frozen, regardless of how many sources become active.
	 */

	if (bs->flags & BS_F_UNIFORM_BW)
		bs->flags |= BS_F_FROZEN_SLOT;

	/*
	 * Reset the amount of data we could not write due to kernel flow-control,
	 * and the amount of capped bandwidth for the period.
	 */

	bs->bw_unwritten = 0;			/* Even if `bs' is for read sources... */
	bs->bw_capped = 0;

	bs->current_used = 0;
	bs->looped = FALSE;

	/*
	 * If there are passive callbacks installed, trigger them now.
	 */

	while (trigger != NULL) {
		bio_source_t *bio = trigger->data;

		trigger = pslist_remove(trigger, bio);
		bio_trigger(bio);
	}
}

/**
 * Add new source to the source list of scheduler.
 */
static void
bsched_bio_add(bsched_t *bs, bio_source_t *bio)
{
	bsched_check(bs);
	bio_check(bio);

	bs->sources = plist_append(bs->sources, bio);
	bs->count++;

	bs->bw_slot = (bs->bw_max + bs->bw_stolen) / bs->count;

	/*
	 * If the slot is less than the minimum we can reach by dynamically
	 * adjusting the bandwidth, then don't bother trying and freeze it.
	 */

	if (bs->bw_slot < BW_SLOT_MIN)
		bs->flags |= BS_F_FROZEN_SLOT;
}

/**
 * Remove source from the source list of scheduler.
 */
static void
bsched_bio_remove(bsched_bws_t bws, bio_source_t *bio)
{
	bsched_t *bs;

	bs = bsched_get(bws);
	bio_check(bio);

	bs->sources = plist_remove(bs->sources, bio);
	bs->count--;

	if (bs->count)
		bs->bw_slot = (bs->bw_max + bs->bw_stolen) / bs->count;

	g_assert(bs->count >= 0);
}

/**
 * Declare fd as a new source for the scheduler.
 *
 * When `callback' is NULL, the source will be "passive", i.e. its bandwidth
 * will be limited when calls to bio_write() or bio_read() are made, but
 * whether the source can accept those calls without blocking will have to
 * be determined explicitly.
 *
 * @returns new bio_source object.
 */
bio_source_t *
bsched_source_add(
	bsched_bws_t bws, wrap_io_t *wio, uint32 flags,
	inputevt_handler_t callback, void *arg)
{
	bio_source_t *bio;
	bsched_t *bs;

	wrap_io_check(wio);

	/*
	 * Must insert reading sources in reading scheduler and writing ones
	 * in a writing scheduler.
	 */

	bs = bsched_get(bws);

	g_assert(!(bs->flags & BS_F_READ) == !(flags & BIO_F_READ));
	g_assert(flags & BIO_F_RW);
	g_assert((flags & BIO_F_RW) != BIO_F_RW);	/* Either reading or writing */
	g_assert(!(flags & ~BIO_F_RW));				/* Can only specify r/w flags */

	WALLOC0(bio);
	bio->magic = BIO_SOURCE_MAGIC;
	bio->bws = bws;
	bio->wio = wio;
	bio->flags = flags;
	bio->io_callback = callback;
	bio->io_arg = arg;

	/*
	 * If there is no callback, the I/O source is "passive".  The supplier
	 * has means to know whether it can read/write from the source, and only
	 * uses the scheduler to limit the amount of data read/written from/to
	 * that source.
	 */

	bsched_bio_add(bs, bio);

	if (!(bs->flags & BS_F_NOBW) && bio->io_callback)
		bio_enable(bio);

	return bio;
}

/**
 * Remove bio_source object from the scheduler.
 * The bio_source object is freed and must not be re-used.
 */
void
bsched_source_remove(bio_source_t *bio)
{
	bio_check(bio);

	if (BSCHED_BWS_INVALID != bio->bws) {
		bsched_bio_remove(bio->bws, bio);
		bio->bws = BSCHED_BWS_INVALID;
	}
	inputevt_remove(&bio->io_tag);
	bio->magic = 0;
	WFREE(bio);
}

/**
 * On-the-fly changing of the allowed bandwidth.
 */
void
bsched_set_bandwidth(bsched_bws_t bws, int64 bandwidth)
{
	bsched_t *bs;

	bs = bsched_get(bws);

	g_assert(bandwidth >= 0);
	g_assert(bandwidth <= BS_BW_MAX);	/* Signed, and multiplied by 1000 */

	if (GNET_PROPERTY(bsched_debug))
		g_debug("BSCHED %s: using %.2f KiB/s for %s",
			G_STRFUNC, (double) bandwidth / bs->period, bs->name);

	bs->bw_per_second = bandwidth;
	bs->bw_max = (int64) (bandwidth / 1000.0 * bs->period);

	/*
	 * If `bandwidth' is 0, then we're disabling bandwidth scheduling and
	 * allow all traffic to go through, unlimited.
	 *
	 * NB: at the next heartbeat, bsched_begin_timeslice() will be called
	 * to re-enable all the sources if any were disabled.
	 */

	if (bandwidth == 0) {
		bsched_disable(bws);
		return;
	}

	/*
	 * When all bandwidth has been used, disable all sources.
	 */

	if (bs->bw_actual >= (bs->bw_max + bs->bw_stolen))
		bsched_no_more_bandwidth(bs);

	bs->flags |= BS_F_CHANGED_BW;
}


/**
 * @param `bio' no brief description.
 * @param `len' is the amount of bytes requested by the application.
 *
 * @returns the bandwidth available for a given source.
 */
static size_t
bw_available(bio_source_t *bio, int len)
{
	bsched_t *bs;
	int64 available;
	int64 result;
	bool capped = FALSE;
	bool used;
	bool active;
	bool favoured;

	bio_check(bio);
	wrap_io_check(bio->wio);	/* Make sure socket still allocated */

	bs = bsched_get(bio->bws);

	if (!(bs->flags & BS_F_ENABLED))		/* Scheduler disabled */
		return len;							/* Use amount requested */

	if (bs->flags & BS_F_NOBW)				/* No more bandwidth */
		return 0;							/* Grant nothing */

	/*
	 * Source is already disabled if there is a callback and no tag on a
	 * non-passive source.
	 */

	if (bio->io_callback && !bio->io_tag && !(bio->flags & BIO_F_PASSIVE))
		return 0;							/* No bandwidth available */

	/*
	 * If capping is in effect and we have already used our allowed share,
	 * disable source to avoid it triggering again.
	 */

	if (0 != bio->bw_cap && bio->bw_actual >= (int64) bio->bw_cap) {
		bio_disable(bio);
		return 0;
	}

	/*
	 * If uniform scheduling is on, disable source so that it does not
	 * trigger again for this timeslice.
	 */

	if ((bs->flags & BS_F_UNIFORM_BW) && bio->io_tag)
		bio_disable(bio);

	/*
	 * The BIO_F_USED flag is set only once during a period, and is used
	 * to identify sources that already triggered.
	 *
	 * The BIO_F_ACTIVE flag is used to mark a source as being used as well,
	 * but can be cleared during a period, when we redistribute bandwidth
	 * among the slots.  So the flag is set when the source was already
	 * used since we recomputed the bandwidth per slot.
	 *
	 * The BIO_F_FAVOUR flag marks sources we want to favour during b/w
	 * distribution: they are allowed to use all the available bandwidth
	 * immediately.
	 */

	used = bio->flags & BIO_F_USED;
	active = bio->flags & BIO_F_ACTIVE;
	favoured = bio->flags & BIO_F_FAVOUR;

	if (!used) {
		bs->current_used++;
		bio->flags |= BIO_F_USED;
	}

	bio->flags |= BIO_F_ACTIVE;

	/*
	 * Set the `looped' flag the first time when we encounter a source that
	 * was already marked used.  It means it is the second time we see
	 * that source trigger during the period and it means we already gave
	 * a chance to all the other sources to trigger.
	 */

	if (!bs->looped && used)
		bs->looped = TRUE;

	/*
	 * If source was already active, recompute the per-slot value since
	 * we already looped once through all the sources.  This prevents the
	 * first scheduled sources from eating all the bandwidth.
	 *
	 * At this point, we'll distribute the stolen bandwidth, which was
	 * not initially distributed.  If the stolen bandwidth is an order of
	 * magnitude larger than the regular bandwidth (bs->bw_max), distribute
	 * only the regular bandwidth for now.  Hence the test below.
	 */

	available = bs->bw_max + bs->bw_stolen - bs->bw_actual;

	if (GNET_PROPERTY(bsched_debug) > 8)
		g_debug("BSCHED %s: "
			"[fd #%d] max=%s, stolen=%s, actual=%s => avail=%s",
			G_STRFUNC, bio->wio->fd(bio->wio),
			int64_to_string(bs->bw_max),
			int64_to_string2(bs->bw_stolen),
			int64_to_string3(bs->bw_actual),
			int64_to_string4(available));

	/*
	 * If we haven't looped yet and we have favoured I/O sources, don't give
	 * anything to non-favoured ones or ones with no pre-allocated bandwidth.
	 */

	if (favoured || 0 != bio->bw_allocated) {
		/* Special-cased later */
	} else if (!bs->looped && bs->io_favours > 0) {
		if (GNET_PROPERTY(bsched_debug) > 8)
			g_debug("BSCHED \t(non-favoured denied) favour=%d", bs->io_favours);
		return 0;
	} else if (available > bs->bw_max) {
		available = bs->bw_max;
		capped = TRUE;
	}

	if (GNET_PROPERTY(bsched_debug) > 8) {
		g_debug("BSCHED \tcapped=%c, used=%c, active=%c, favour=%c, alloc=%c"
			" => avail=%s",
			capped ? 'y' : 'n', used ? 'y' : 'n', active ? 'y' : 'n',
			favoured ? 'y' : 'n', 0 != bio->bw_allocated ? 'y' : 'n',
			int64_to_string(available));
	}

	if (
		!(bs->flags & BS_F_FROZEN_SLOT) &&
		available > BW_SLOT_MIN &&
		active
	) {
		int64 slot = available / bs->count;

		/*
		 * It's not worth redistributing less than BW_SLOT_MIN bytes per slot.
		 * If we ever drop below that value, freeze the slot value to prevent
		 * further redistribution.
		 *
		 * We don't freeze when the amount available which was redistributed
		 * is equal to the regular bandwidth for the scheduler.  This usually
		 * happens when there is some stolen bandwidth that is not used yet.
		 *
		 * NB: we don't freeze the slots if we capped the redistribution above,
		 * because we have more stolen bandwidth to possibly use.
		 *
		 * NB: we run bsched_clear_active() only ONCE per period, because if
		 * we have to run it more, it means that a few set of sources are
		 * very active: just give them bandwidth now, other sources had their
		 * fair chance to trigger and things may change at the next period.
		 */

		if (capped || slot > BW_SLOT_MIN) {
			if (!(bs->flags & BS_F_CLEARED)) {	/* Only once per period */
				bsched_clear_active(bs);
				bs->flags |= BS_F_CLEARED;
			}
			bs->bw_slot = slot;
		} else {
			bs->flags |= BS_F_FROZEN_SLOT;
			bs->bw_slot = BW_SLOT_MIN;
		}

		if (GNET_PROPERTY(bsched_debug) > 7)
			g_debug("BSCHED %s: new slot=%s for \"%s\" (%scapped)",
				G_STRFUNC, int64_to_string(bs->bw_slot),
				bs->name, capped ? "" : "un");
	}

	/*
	 * If nothing is available, disable all sources.
	 */

	if (available <= 0) {
		bsched_no_more_bandwidth(bs);
		available = 0;
	}

	/*
	 * Enforce 0 bytes if source was used with uniform scheduling.
	 * Active sources are disabled, but we could face a passive one.
	 */

	{
		int64 bwslot = bs->bw_slot;

		/*
		 * The penalty factor exponentially decreases the amount of slot
		 * bandwidth we allocate for the I/O source.  It enables us to
		 * progressively adjust up or down the amount of allocated write
		 * bandwidth we can give to "stalling" sources (those incapable
		 * of withstanding the amount of writing we're using).
		 * 		--RAM, 2020-05-26
		 */

		if (0 != bio->bw_penalty_factor) {
			bwslot >>= bio->bw_penalty_factor;
			if G_UNLIKELY(bwslot < BW_SLOT_MIN)
				bwslot = BW_SLOT_MIN;
		}

		if (used && (bs->flags & BS_F_UNIFORM_BW))
			result = 0;
		else if (bio->flags & BIO_F_FAVOUR)
			result = available;
		else if (0 != bio->bw_allocated) {
			result = MAX(bio->bw_allocated, bwslot);
			result = MIN(result, available);
		} else
			result = MIN(bwslot, available);
	}

	available -= result;

	/*
	 * If `bw_last_capped' is not zero, we had to cap the traffic last period,
	 * even though we did not use the whole allocated bandwidth.
	 *
	 * If the source is not flagged as `used', then we already looped through
	 * the other active sources and consumed some bandwidth.
	 *
	 * So if we already looped through the sources, try to consume more data
	 * this time.  The rationale is that we might not write enough data
	 * for each active source, and we don't loop enough time over the sources
	 * to be able to fill our bandwidth allocation.
	 *
	 * Do not perform any adjustment when BS_F_UNIFORM_BW was set because we
	 * want to keep the allocated bandwidth the same for all the sources.
	 * If a source "stalls" and does not consume its bandwidth slot, that
	 * amount will be lost this period.
	 */

	if (
		result < len && available > 0 && bs->looped &&
		(!used || bs->bw_last_capped > 0) &&
		!(bs->flags & BS_F_UNIFORM_BW) &&
		0 == bio->bw_penalty_factor
	) {
		int64 adj = len - result;
		int64 nominal;

		if (bs->bw_last_capped > 0 && bs->bw_last_period < bs->bw_max) {
			int64 distribute = MAX(bs->bw_last_capped, available);

			/*
			 * We have capped bandwidth last period, yet we consumed less
			 * than what we were allowed to.
			 *
			 * When source was not used yet, we rely on the previously used
			 * source count, since we don't know how many more sources will
			 * trigger this period.
			 */

			if (used) {
				g_assert(bs->current_used != 0);	/* This source is used! */
				nominal = distribute / bs->current_used;
			} else
				nominal = distribute / MAX(bs->last_used, bs->current_used);
		} else {
			/*
			 * Try to stuff 2 slots worth of data
			 *
			 * If we never used that source, we use the nominal bandwidth for
			 * each slot.  Otherwise we use the current per-slot bandwidth.
			 */

			if (used)
				nominal = 2 * bs->bw_slot;
			else
				nominal = 2 * bs->bw_max / bs->count;
		}

		if (adj > nominal)
			adj = nominal;

		if (adj > available)
			adj = available;

		if (GNET_PROPERTY(bsched_debug) > 4)
			g_debug("BSCHED %s: \"%s\" adding %s to %s"
				" (len=%d, capped=%s [%d-%d/%d], available=%s, used=%c)",
				G_STRFUNC, bs->name,
				int64_to_string(adj), int64_to_string2(result),
				len, int64_to_string3(bs->bw_last_capped),
				bs->last_used, bs->current_used, bs->count,
				int64_to_string4(available),
				(bio->flags & BIO_F_USED) ? 'y' : 'n');

		result += adj;
	}

	/*
	 * Now apply capping to avoid sending more than what we promised for
	 * this I/O source.  Naturally, if we do cap at this stage, we'll
	 * skip the cap-bandwidth tracking logic below.
	 */

	if (0 != bio->bw_cap) {
		int64 remain = (int64) bio->bw_cap - bio->bw_actual;

		if (remain <= 0)
			result = 0;
		else
			result = remain;

		if (0 == result)
			bio_disable(bio);		/* Avoid further triggering this timeslice */
	}

	/*
	 * If we return less than the amount requested, we capped the bandwidth.
	 *
	 * Keep track of that bandwidth, because if we end-up having consumed
	 * less that what we should and we have some capped bandwidth, it means
	 * we're not distributing it correctly: the sources don't trigger "fast
	 * enough" during the period.
	 */

	if (result < len && 0 == bio->bw_penalty_factor && 0 == bio->bw_cap)
		bs->bw_capped += len - result;

	/*
	 * Since bandwidth computations are now done in 64-bit values but we can
	 * run on a 32-bit machine where size_t will be capped to 32 bit, we
	 * must cap the result to the maximum that can fit in a size_t variable.
	 * 		--RAM, 2017-08-15
	 */

	if (MAX_INT_VAL(size_t) != MAX_INT_VAL(uint64)) {
		return MIN(UNSIGNED(result), MAX_INT_VAL(size_t));	/* 32-bit system */
	} else {
		return UNSIGNED(result);							/* 64-bit system */
	}
}

/**
 * Update bandwidth used, and scheduler statistics.
 * If no more bandwidth is available, disable all sources.
 *
 * @param `bs' no brief description.
 * @param `used' is the amount of bytes used by the I/O.
 * @param `requested' is the amount of bytes requested for the I/O.
 */
static void
bsched_bw_update(bsched_t *bs, ssize_t used, size_t requested)
{
	bsched_check(bs);		/* Ensure I/O source was in alive scheduler */

	g_assert(size_is_non_negative(used));
	g_assert(UNSIGNED(used) <= requested);

	/*
	 * Even when the scheduler is disabled, update the actual bandwidth used
	 * for the statistics and the GUI display.
	 */

	bs->bw_actual += used;

	if (!(bs->flags & BS_F_ENABLED))		/* Scheduler disabled */
		return;								/* Nothing to update */

	/*
	 * For writing schedulers, sum-up the difference between the amount of
	 * data that we originally wished to write and the amount that got
	 * actually written.  If it is positive, it means the kernel
	 * flow-controlled the connection.
	 *
	 * For reading shedulers, we don't care about that difference.
	 */

	if (bs->flags & BS_F_WRITE)
		bs->bw_unwritten += requested - used;

	/*
	 * When all bandwidth has been used, disable all sources.
	 */

	if (bs->bw_actual >= (bs->bw_max + bs->bw_stolen))
		bsched_no_more_bandwidth(bs);
}

static inline ALWAYS_INLINE void
bio_bw_update(bio_source_t *bio, ssize_t used)
{
	bio->bw_actual += used;

	if G_UNLIKELY(0 != bio->bw_allocated)
		bio->bw_allocated -= MIN(bio->bw_allocated, used);
}

/**
 * Set I/O favouring for source.
 *
 * @return previous status: TRUE if it was favoured, FALSE otheriwse.
 */
bool
bio_set_favour(bio_source_t *bio, bool on)
{
	bool old;

	bio_check(bio);

	old = booleanize(bio->flags & BIO_F_FAVOUR);

	if (on) {
		bio->flags |= BIO_F_FAVOUR;
		bio->bw_allocated = 0;
	} else {
		bio->flags &= ~BIO_F_FAVOUR;
	}

	return old;
}

/**
 * Allocate bandwidth amount for I/O source to use prioritarily.
 *
 * @return total amount of allocated banwdidth.
 */
unsigned
bio_add_allocated(bio_source_t *bio, unsigned bw)
{
	bio_check(bio);

	bio->bw_allocated = uint_saturate_add(bio->bw_allocated, bw);

	return bio->bw_allocated;
}

/**
 * Add penalty (power of 2) `n' to the I/O source.
 *
 * @param bio	the I/O source
 * @param n		how many additional power-of-2 shifts should we perform?
 *
 * @return new amount of penalty.
 */
uint8
bio_add_penalty(bio_source_t *bio, uint8 n)
{
	uint np;

	bio_check(bio);

	np = bio->bw_penalty_factor + n;
	np = MIN(np, 62);		/* At most 62 shifts on a 64-bit system */

	return bio->bw_penalty_factor = np;
}

/**
 * Remove penalty (power of 2) `n' to the I/O source.
 *
 * If `n' is MAX_INT_VAL(uint8) or larger than the existing amount of penalty
 * present, the penalty is reset to 0 (i.e. it can never become negative).
 *
 * @param bio	the I/O source
 * @param n		how many power-of-2 shifts should we deduce from existing ones?
 *
 * @return new amount of penalty.
 */
uint8
bio_remove_penalty(bio_source_t *bio, uint8 n)
{
	int np;

	bio_check(bio);

	np = bio->bw_penalty_factor - n;
	np = MAX(np, 0);

	return bio->bw_penalty_factor = np;
}

/**
 * Get current amount of I/O penalty we have on the given source.
 *
 * This amount corresponds to the decimation factor we apply to the scheduler
 * slot bandwidth, in powers of 2.  Hence a value of 0 tells us there is no
 * penalty, 3 that the slot bandwidth is divided by 2^3 = 8, with a minimum
 * bandwidth allowed to go through.
 *
 * Penalty is used to slow down our transmission rate on a given I/O source
 * in the hope it will avoid congestion on the other side, if it cannot cope
 * correctly with all the incoming traffic we're sending.
 *
 * Application code uses bio_add_penalty() and bio_remove_penalty() to control
 * the amount of penalty being used.
 */
uint8
bio_penalty(const bio_source_t *bio)
{
	bio_check(bio);

	return bio->bw_penalty_factor;
}

/**
 * Set b/w cap for I/O source: the max amount of data we can write per second.
 *
 * @param bio	the I/O source
 * @param cap	the b/w cap, 0 meaning none
 *
 * @return the actual cap registered
 */
uint32
bio_set_cap(bio_source_t *bio, uint32 cap)
{
	bio_check(bio);

	if (cap != 0 && cap < BW_SLOT_MIN)
		cap = BW_SLOT_MIN;

	return bio->bw_cap = cap;
}

/**
 * Write at most `len' bytes from `buf' to source's fd, as bandwidth permits.
 * If we cannot write anything due to bandwidth constraints, return -1 with
 * errno set to EAGAIN.
 */
ssize_t
bio_write(bio_source_t *bio, const void *data, size_t len)
{
	size_t available;
	size_t amount;
	ssize_t r;

	bio_check(bio);
	g_assert(bio->flags & BIO_F_WRITE);

	/*
	 * If we don't have any bandwidth, return -1 with errno set to EAGAIN
	 * to signal that we cannot perform any I/O right now.
	 */

	available = bw_available(bio, len);

	if (available == 0) {
		errno = VAL_EAGAIN;
		return -1;
	}

	amount = len > available ? available : len;

	if (GNET_PROPERTY(bsched_debug) > 7)
		g_debug("BSCHED %s(wio=%d, len=%zu) available=%zu",
			G_STRFUNC, bio->wio->fd(bio->wio), len, available);

	r = bio->wio->write(bio->wio, data, amount);

	/*
	 * XXX hack for broken libc, which can return -1 with errno = 0!
	 *
	 * Apparently, when compiling with gcc-3.3.x, one can have a system
	 * call return -1 with errno set to EOK.
	 *		--RAM, 05/10/2003
	 */

	if ((ssize_t) -1 == r && 0 == errno) {
		g_warning("wio->write(fd=%d, len=%zu) returned -1 with errno = 0, "
			"assuming EAGAIN", bio->wio->fd(bio->wio), len);
		errno = VAL_EAGAIN;
	}

	if (r > 0) {
		bsched_bw_update(bsched_get(bio->bws), r, amount);
		bio_bw_update(bio, r);
	}

	return r;
}

/**
 * Write at most `len' bytes from `iov' to source's fd, as bandwidth permits,
 * `len' being determined by the size of the supplied I/O vector.
 * If we cannot write anything due to bandwidth constraints, return -1 with
 * errno set to EAGAIN.
 */
ssize_t
bio_writev(bio_source_t *bio, iovec_t *iov, int iovcnt)
{
	size_t available;
	ssize_t r;
	size_t len;
	iovec_t *siov;
	int slen = -1;			/* Avoid "may be used uninitialized" warning */

	bio_check(bio);
	g_assert(bio->flags & BIO_F_WRITE);

	/*
	 * Compute I/O vector's length.
	 */

	for (r = 0, siov = iov, len = 0; r < iovcnt; r++, siov++)
		len += iovec_len(siov);

	/*
	 * If we don't have any bandwidth, return -1 with errno set to EAGAIN
	 * to signal that we cannot perform any I/O right now.
	 */

	available = bw_available(bio, len);

	if (available == 0) {
		errno = VAL_EAGAIN;
		return -1;
	}

	/*
	 * If we cannot write the whole vector, we need to trim it.
	 * Because we promise to not corrupt the original I/O vector, we
	 * save the original length of the last I/O entry, should we modify it.
	 */

	if (len > available) {
		size_t curlen;

		for (r = 0, siov = iov, curlen = 0; r < iovcnt; r++, siov++) {
			curlen += iovec_len(siov);

			/*
			 * Exact size reached, we just need to adjust down the iov count.
			 * Force siov to NULL before leaving the loop to indicate we did
			 * not have to alter it.
			 */

			if (curlen == available) {
				siov = NULL;
				iovcnt = r + 1;
				break;
			}

			/*
			 * Maximum size reached...  Need to adjust both the iov count
			 * and the length of the current siov entry.
			 */

			if (curlen > available) {
				slen = iovec_len(siov);		/* Save for later restore */
				iovec_set_len(siov, iovec_len(siov) - (curlen - available));
				iovcnt = r + 1;
				g_assert(iovec_len(siov) > 0);
				break;
			}
		}
	}

	/*
	 * Write I/O vector, updating used bandwidth.
	 *
	 * When `iovcnt' is greater than MAX_IOV_COUNT, use our custom writev()
	 * wrapper to avoid failure with EINVAL.
	 *		--RAM, 17/03/2002
	 */

	if (GNET_PROPERTY(bsched_debug) > 7)
		g_debug("BSCHED %s(fd=%d, len=%zu) available=%zu",
			G_STRFUNC, bio->wio->fd(bio->wio), len, available);

	if (iovcnt > MAX_IOV_COUNT)
		r = safe_writev(bio->wio, iov, iovcnt);
	else
		r = bio->wio->writev(bio->wio, iov, iovcnt);

	/*
	 * XXX hack for broken libc, which can return -1 with errno = 0!
	 *
	 * Apparently, when compiling with gcc-3.3.x, one can have a system
	 * call return -1 with errno set to EOK.
	 *		--RAM, 05/10/2003
	 */

	if ((ssize_t) -1 == r && 0 == errno) {
		g_warning("writev(fd=%d, len=%zu) returned -1 with errno = 0, "
			"assuming EAGAIN", bio->wio->fd(bio->wio), len);
		errno = VAL_EAGAIN;
	}

	if (r > 0) {
		g_assert((size_t) r <= available);
		bsched_bw_update(bsched_get(bio->bws), r, MIN(len, available));
		bio_bw_update(bio, r);
	}

	/*
	 * Restore original I/O vector if we trimmed it.
	 */

	if (len > available && siov) {
		g_assert(slen >= 0);			/* Ensure it was initialized */
		iovec_set_len(siov, slen);
	}

	return r;
}

/**
 * Send UDP datagram to specified destination `to'.
 *
 * @return -1 with errno set to EAGAIN, if we cannot write anything due
 * to bandwidth constraints.
 */
ssize_t
bio_sendto(bio_source_t *bio, const gnet_host_t *to,
	const void *data, size_t len)
{
	size_t available;
	ssize_t r;

	bio_check(bio);
	g_assert(bio->flags & BIO_F_WRITE);

	/*
	 * If we don't have any bandwidth, return -1 with errno set to EAGAIN
	 * to signal that we cannot perform any I/O right now.
	 *
	 * Note that datagrams are necessarily atomic operations, therefore
	 * they must be completely possible or not performed at all, but we
	 * can't really be too strict or large datagrams will never be sent
	 * at all.  Hence we act as if we had BW_UDP_OVERSIZE extra bandwidth
	 * available if we don't have enough bandwidth initially, but have
	 * some available still.
	 */

	available = bw_available(bio, len);

	if (available == 0 || available + BW_UDP_OVERSIZE < len) {
		errno = VAL_EAGAIN;
		return -1;
	}

	if (GNET_PROPERTY(bsched_debug) > 7)
		g_debug("BSCHED %s(wio=%d, len=%zu) available=%zu",
			G_STRFUNC, bio->wio->fd(bio->wio), len, available);

	g_assert(bio->wio != NULL);
	g_assert(bio->wio->sendto != NULL);
	r = (*bio->wio->sendto)(bio->wio, to, data, len);

	/*
	 * XXX hack for broken libc, which can return -1 with errno = 0!
	 *
	 * Apparently, when compiling with gcc-3.3.x, one can have a system
	 * call return -1 with errno set to EOK.
	 *		--RAM, 05/10/2003
	 */

	if ((ssize_t) -1 == r && 0 == errno) {
		g_warning("wio->sendto(fd=%d, len=%zu) returned -1 with errno = 0, "
			"assuming EAGAIN", bio->wio->fd(bio->wio), len);
		errno = VAL_EAGAIN;
	}

	if (r > 0) {
		bsched_bw_update(bsched_get(bio->bws),
			r + BW_UDP_MSG, len + BW_UDP_MSG);
		bio_bw_update(bio, r + BW_UDP_MSG);
	}

	return r;
}

/**
 * Write at most `len' bytes to source's fd, as bandwidth permits.
 *
 * Bytes are read from `offset' in the in_fd file descriptor, and the value
 * is updated in place by the kernel.
 *
 * @return -1 with errno set to EAGAIN, if we cannot write anything due to
 * bandwidth constraints.
 */
ssize_t
bio_sendfile(sendfile_ctx_t *ctx, bio_source_t *bio,
	int in_fd, fileoffset_t *offset, size_t len)
{
#if !defined(HAS_MMAP) && !defined(HAS_SENDFILE)

	(void) ctx;
	(void) bio;
	(void) in_fd;
	(void) offset;
	(void) len;

	g_assert_not_reached();
	/* NOTREACHED */

	errno = ENOSYS;

	return (ssize_t) -1;

#else /* USE_MMAP || HAS_SENDFILE */

	/*
	 * amount is only declared volatile to shut up the bogus warning by GCC
	 * 2.95.x that ``amount'' *might* be clobbered by sigsetjmp - which is
	 * actually not the case.
	 */
	size_t amount;
	size_t available;
	ssize_t r;
	int out_fd;
	fileoffset_t start;

	g_assert(ctx);
	bio_check(bio);
	wrap_io_check(bio->wio);
	g_assert(bio->flags & BIO_F_WRITE);
	g_assert(offset);
	g_assert(len > 0);

	start = *offset;
	g_assert(start >= 0);
	g_assert(start + (fileoffset_t) len > start);

	out_fd = bio->wio->fd(bio->wio);

	/*
	 * If we don't have any bandwidth, return -1 with errno set to EAGAIN
	 * to signal that we cannot perform any I/O right now.
	 */

	available = bw_available(bio, len);

	if (available == 0) {
		errno = VAL_EAGAIN;
		return -1;
	}

	amount = len > available ? available : len;

	if (GNET_PROPERTY(bsched_debug) > 7)
		g_debug("BSCHED %s(fd=%d, len=%zu) available=%zu",
			G_STRFUNC, bio->wio->fd(bio->wio), len, available);

#if defined(HAS_MMAP) && !defined(HAS_SENDFILE)
	{
		const char *data;

		if (
			ctx->map == NULL ||
			start < ctx->map_start ||
			(fileoffset_t) (start + amount) > ctx->map_end
		) {
			static const size_t min_map_size = 64 * 1024;
			size_t map_len, old_len;
			fileoffset_t map_start;
			int flags = MAP_PRIVATE;
			void *addr;

			/*
			 * Make sure ``off'' is page-aligned for mmap(); some
			 * implementations require this.
			 */

			map_start = start - (start % compat_pagesize());
			map_len = amount + (start - map_start);

			/*
			 * Map at least 64 KiB so that mmap() isn't called too frequently.
			 */

			if (
				map_len < min_map_size &&
				(size_t) (MAX_INT_VAL(fileoffset_t) - map_start) >= min_map_size
			) {
				map_len = min_map_size;
			}

			old_len = ctx->map_end - ctx->map_start;
			if (ctx->map) {
			   	if (old_len != map_len) {
					vmm_munmap(ctx->map, old_len);
					ctx->map = NULL;
				} else {
					flags |= MAP_FIXED;
				}
			}

			ctx->map_start = map_start;
			ctx->map_end = ctx->map_start + map_len;
			g_assert(ctx->map_start < ctx->map_end);

			addr = vmm_mmap(ctx->map, map_len, PROT_READ, flags, in_fd,
						ctx->map_start);

			if (addr == MAP_FAILED) {
				int saved_errno = errno;
				if (ctx->map) {
					vmm_munmap(ctx->map, old_len);
					old_len = 0;
					flags &= ~MAP_FIXED;
				}
				ctx->map = NULL;
				ctx->map_start = 0;
				ctx->map_end = 0;
				errno = saved_errno;
				return (ssize_t) -1;
			}

			ctx->map = addr;
			vmm_madvise_sequential(ctx->map, map_len);
		}

		g_assert(ctx->map != NULL);
		data = ctx->map;

		g_assert(start >= ctx->map_start);
		data = &data[start - ctx->map_start];

		g_assert(ctx->map_end > start);
		amount = MIN((size_t) (ctx->map_end - start), amount);

		r = s_write(out_fd, data, amount);
		switch (r) {
		case (ssize_t) -1:
			break;
		case 0:
			vmm_munmap(ctx->map, ctx->map_end - ctx->map_start);
			ctx->map = NULL;
			break;
		default:
			*offset = start + r;
		}
	}
#else /* !USE_MMAP */
	r = compat_sendfile(out_fd, in_fd, offset, amount);
#endif	/* USE_MMAP */

	if (r > 0) {
		bsched_bw_update(bsched_get(bio->bws), r, amount);
		bio_bw_update(bio, r);
	}

	return r;
#endif /* !USE_MMAP && !HAS_SENDFILE */
}

/**
 * Read at most `len' bytes from `buf' from source's fd, as bandwidth
 * permits.
 *
 * @return -1 with errno set to EAGAIN, if we cannot read anything due to
 * bandwidth constraints.
 */
ssize_t
bio_read(bio_source_t *bio, void *data, size_t len)
{
	size_t available;
	size_t amount;
	ssize_t r;

	bio_check(bio);
	g_assert(bio->flags & BIO_F_READ);

	/*
	 * If we don't have any bandwidth, return -1 with errno set to EAGAIN
	 * to signal that we cannot perform any I/O right now.
	 */

	available = bw_available(bio, len);
	if (available == 0) {
		errno = VAL_EAGAIN;
		return -1;
	}

	amount = len > available ? available : len;
	if (GNET_PROPERTY(bsched_debug) > 7)
		g_debug("BSCHED %s(fd=%d, len=%zu) available=%zu",
			G_STRFUNC, bio->wio->fd(bio->wio), len, available);

	r = bio->wio->read(bio->wio, data, amount);
	if (r > 0) {
		bsched_bw_update(bsched_get(bio->bws), r, amount);
		bio_bw_update(bio, r);
		bsched_get(bio->bws)->flags |= BS_F_DATA_READ;
	}

	return r;
}

/**
 * Read at most `len' bytes from `iov' to source's fd, as bandwidth permits,
 * `len' being determined by the size of the supplied I/O vector.
 * If we cannot read anything due to bandwidth constraints, return -1 with
 * errno set to EAGAIN.
 */
ssize_t
bio_readv(bio_source_t *bio, iovec_t *iov, int iovcnt)
{
	size_t available;
	ssize_t r;
	size_t len;
	iovec_t *siov;
	int slen = -1;			/* Avoid "may be used uninitialized" warning */

	bio_check(bio);
	g_assert(bio->flags & BIO_F_READ);

	/*
	 * Compute I/O vector's length.
	 */

	for (r = 0, siov = iov, len = 0; r < iovcnt; r++, siov++)
		len += iovec_len(siov);

	/*
	 * If we don't have any bandwidth, return -1 with errno set to EAGAIN
	 * to signal that we cannot perform any I/O right now.
	 */

	available = bw_available(bio, len);

	if (available == 0) {
		errno = VAL_EAGAIN;
		return -1;
	}

	/*
	 * If we cannot read the whole vector, we need to trim it.
	 * Because we promise to not corrupt the original I/O vector, we
	 * save the original length of the last I/O entry, should we modify it.
	 */

	if (len > available) {
		size_t curlen;

		for (r = 0, siov = iov, curlen = 0; r < iovcnt; r++, siov++) {
			curlen += iovec_len(siov);

			/*
			 * Exact size reached, we just need to adjust down the iov count.
			 * Force siov to NULL before leaving the loop to indicate we did
			 * not have to alter it.
			 */

			if (curlen == available) {
				siov = NULL;
				iovcnt = r + 1;
				break;
			}

			/*
			 * Maximum size reached...  Need to adjust both the iov count
			 * and the length of the current siov entry.
			 */

			if (curlen > available) {
				slen = iovec_len(siov);	/* Save for later restore */
				iovec_set_len(siov,
					iovec_len(siov) - (curlen - available)
				);
				iovcnt = r + 1;
				g_assert(iovec_len(siov) > 0);
				break;
			}
		}
	}

	/*
	 * Read into I/O vector, updating used bandwidth.
	 *
	 * When `iovcnt' is greater than MAX_IOV_COUNT, use our custom readv()
	 * wrapper to avoid failure with EINVAL.
	 *		--RAM, 17/03/2002
	 */

	if (GNET_PROPERTY(bsched_debug) > 7)
		g_debug("BSCHED %s(fd=%d, len=%zu) available=%zu",
			G_STRFUNC, bio->wio->fd(bio->wio), len, available);

	if (iovcnt > MAX_IOV_COUNT)
		r = safe_readv(bio->wio, iov, iovcnt);
	else
		r = bio->wio->readv(bio->wio, iov, iovcnt);

	/*
	 * XXX hack for broken libc, which can return -1 with errno = 0!
	 *
	 * Apparently, when compiling with gcc-3.3.x, one can have a system
	 * call return -1 with errno set to EOK.
	 *		--RAM, 05/10/2003
	 */

	if ((ssize_t) -1 == r && 0 == errno) {
		g_warning("readv(fd=%d, len=%zu) returned -1 with errno = 0, "
			"assuming EAGAIN", bio->wio->fd(bio->wio), len);
		errno = VAL_EAGAIN;
	}

	if (r > 0) {
		g_assert((size_t) r <= available);
		bsched_bw_update(bsched_get(bio->bws), r, MIN(len, available));
		bio_bw_update(bio, r);
		bsched_get(bio->bws)->flags |= BS_F_DATA_READ;
	}

	/*
	 * Restore original I/O vector if we trimmed it.
	 */

	if (len > available && siov) {
		g_assert(slen >= 0);			/* Ensure it was initialized */
		iovec_set_len(siov, slen);
	}

	return r;
}

/**
 * Write at most `len' bytes from `buf' to specified fd, and account the
 * bandwidth used.  Any overused bandwidth will be tracked, so that on
 * average, we stick to the requested bandwidth rate.
 *
 * @return The amount of bytes written or (-1) if an error occurred.
 */
ssize_t
bws_write(bsched_bws_t bws, wrap_io_t *wio, const void *data, size_t len)
{
	bsched_t *bs;
	ssize_t r;

	bs = bsched_get(bws);

	g_assert(bs->flags & BS_F_WRITE);
	wrap_io_check(wio);
	g_assert(wio->write);
	g_assert(len <= INT_MAX);

	r = wio->write(wio, data, len);
	if (r > 0)
		bsched_bw_update(bs, r, len);

	return r;
}

/**
 * Read at most `len' bytes from `buf' from specified fd, and account the
 * bandwidth used.  Any overused bandwidth will be tracked, so that on
 * average, we stick to the requested bandwidth rate.
 */
ssize_t
bws_read(bsched_bws_t bws, wrap_io_t *wio, void *data, size_t len)
{
	bsched_t *bs;
	ssize_t r;

	bs = bsched_get(bws);

	g_assert(bs->flags & BS_F_READ);
	wrap_io_check(wio);
	g_assert(wio->read);
	g_assert(len <= INT_MAX);

	r = wio->read(wio, data, len);
	if (r > 0) {
		bsched_bw_update(bs, r, len);
		bs->flags |= BS_F_DATA_READ;
	}

	return r;
}

/**
 * Account for read data from UDP.
 */
void
bws_udp_count_read(int len, bool dht)
{
	int count = BW_UDP_MSG + len;
	bsched_t *bs;

	bs = bsched_get(dht ? BSCHED_BWS_DHT_IN : BSCHED_BWS_GIN_UDP);
	bsched_bw_update(bs, count, count);
	bs->flags |= BS_F_DATA_READ;
}

/**
 * Enable / disable bandwidth stealing from scheduler.
 *
 * @return whether bandwidth stealing was enabled.
 */
bool
bws_allow_stealing(bsched_bws_t bws, bool allow)
{
	bsched_t *bs;
	bool was_disabled;

	bs = bsched_get(bws);
	was_disabled = booleanize(bs->flags & BS_F_NO_STEALING);

	if (allow)
		bs->flags &= ~BS_F_NO_STEALING;
	else
		bs->flags |= BS_F_NO_STEALING;

	return !was_disabled;
}

/**
 * Enable / disable usage of stolen bandwidth by scheduler.
 *
 * @return whether bandwidth stealing was ignored.
 */
bool
bws_ignore_stolen(bsched_bws_t bws, bool ignore)
{
	bsched_t *bs;
	bool was_ignoring;

	bs = bsched_get(bws);
	was_ignoring = booleanize(bs->flags & BS_F_STOLEN_IGN);

	if (ignore)
		bs->flags |= BS_F_STOLEN_IGN;
	else
		bs->flags &= ~BS_F_STOLEN_IGN;

	return was_ignoring;
}

/**
 * Set / clear scheduler for uniform allocation (all sources getting the same
 * amount of bandwidth, "inactive" ones included).
 *
 * @return whether uniform allocation was already enabled.
 */
bool
bws_uniform_allocation(bsched_bws_t bws, bool uniform)
{
	bsched_t *bs;
	bool was_uniform;

	bs = bsched_get(bws);
	was_uniform = booleanize(bs->flags & BS_F_UNIFORM_BW);

	if (uniform)
		bs->flags |= BS_F_UNIFORM_BW;
	else
		bs->flags &= ~BS_F_UNIFORM_BW;

	return was_uniform;
}

/**
 * Returns adequate b/w shaper depending on the socket type.
 *
 * @returns NULL if there is no b/w shaper to consider.
 */
static bsched_t *
bs_socket(enum socket_direction dir, enum socket_type type)
{
	bsched_bws_t bws = BSCHED_BWS_INVALID;

	switch (type) {
	case SOCK_TYPE_DOWNLOAD:
	case SOCK_TYPE_HTTP:
	case SOCK_TYPE_UPLOAD:
	case SOCK_TYPE_PPROXY:
		bws = SOCK_CONN_OUTGOING == dir ? BSCHED_BWS_OUT : BSCHED_BWS_IN;
		break;
	case SOCK_TYPE_CONTROL:
	case SOCK_TYPE_CONNBACK:
		bws = SOCK_CONN_OUTGOING == dir ? BSCHED_BWS_GOUT : BSCHED_BWS_GIN;
		break;
	case SOCK_TYPE_SHELL:
		return NULL;
	case SOCK_TYPE_UDP:
		bws = SOCK_CONN_OUTGOING == dir
			? BSCHED_BWS_GOUT_UDP : BSCHED_BWS_GIN_UDP;
		break;
	case SOCK_TYPE_UNKNOWN:
	case SOCK_TYPE_DESTROYING:
		break;
	}
	if (BSCHED_BWS_INVALID == bws) {
		g_warning("%s(): unhandled socket type %d", G_STRFUNC, type);
		bws = SOCK_CONN_OUTGOING == dir ? BSCHED_BWS_OUT : BSCHED_BWS_IN;
	}
	return bsched_get(bws);
}

/**
 * Record that we're issuing a TCP/IP connection of a particular type.
 */
void
bws_sock_connect(enum socket_type type)
{
	bsched_t *bs = bs_socket(SOCK_CONN_OUTGOING, type);

	/*
	 * At worst, a TCP/IP connect sequence can send 3 SYN packets,
	 * of 40 bytes each.  But the connection can be denied immediately
	 * with a RST after the first SYN.
	 *
	 * What we do here is account for 60 bytes only (half the maximum).
	 * If the connection attempt times out, we'll account for 40 more
	 * bytes, as a conservative measure.
	 */

	if (bs) {
		bsched_check(bs);
		bsched_bw_update(bs, (3 * BW_TCP_MSG) / 2, (3 * BW_TCP_MSG) / 2);
	}
}

/**
 * Record that the connection attempt failed.
 */
void
bws_sock_connect_failed(enum socket_type type)
{
	bsched_t *bs = bs_socket(SOCK_CONN_INCOMING, type);

	/*
	 * We got an RST message.
	 */

	if (bs) {
		bsched_check(bs);
		bsched_bw_update(bs, BW_TCP_MSG, BW_TCP_MSG);
	}
}

/**
 * A connection attempt of `type' timed out.
 */
void
bws_sock_connect_timeout(enum socket_type type)
{
	bsched_t *bs = bs_socket(SOCK_CONN_OUTGOING, type);

	/*
	 * Assume we sent an extra SYN.
	 */

	if (bs) {
		bsched_check(bs);
		bsched_bw_update(bs, BW_TCP_MSG, BW_TCP_MSG);
	}
}

/**
 * Record that the connection attempt succeeded.
 */
void
bws_sock_connected(enum socket_type type)
{
	bsched_t *bs = bs_socket(SOCK_CONN_INCOMING, type);

	/*
	 * We got an ACK message.
	 */

	if (bs != NULL)
		bsched_bw_update(bs, BW_TCP_MSG, BW_TCP_MSG);
}

/**
 * We accepted an incoming connection of `type'.
 */
void
bws_sock_accepted(enum socket_type type)
{
	bsched_t *bsout = bs_socket(SOCK_CONN_OUTGOING, type);
	bsched_t *bsin = bs_socket(SOCK_CONN_INCOMING, type);

	/*
	 * We received a SYN message.
	 * We sent back an ACK+SYN message to acknowledge the connection.
	 */

	if (bsout != NULL)
		bsched_bw_update(bsout, BW_TCP_MSG, BW_TCP_MSG);
	if (bsin != NULL)
		bsched_bw_update(bsin, BW_TCP_MSG, BW_TCP_MSG);
}

/**
 * The connection was closed, remotely if `remote' is true.
 */
void
bws_sock_closed(enum socket_type type, bool remote)
{
	bsched_t *bsout = bs_socket(SOCK_CONN_OUTGOING, type);
	bsched_t *bsin = bs_socket(SOCK_CONN_INCOMING, type);

	/*
	 * Assume we sent a FIN and an ACK if we closed locally,
	 * or that we got a single FIN if it was closed remotely.
	 */

	if (remote) {
		if (bsout != NULL)
			bsched_bw_update(bsout, BW_TCP_MSG, BW_TCP_MSG); /* Sent an ACK */
		if (bsin != NULL)
			bsched_bw_update(bsin, BW_TCP_MSG, BW_TCP_MSG);	 /* Got a FIN */
	} else {
		/* Sent a FIN and an ACK */
		if (bsout != NULL)
			bsched_bw_update(bsout, 2 * BW_TCP_MSG, 2 * BW_TCP_MSG);
		if (bsin != NULL)
			bsched_bw_update(bsin, BW_TCP_MSG, BW_TCP_MSG);	 /* Got an ACK */
	}
}

/**
 * Do we have the bandwidth to issue a new TCP/IP connection of `type'?
 */
bool
bws_can_connect(enum socket_type type)
{
	bsched_t *bsout = bs_socket(SOCK_CONN_OUTGOING, type);
	bsched_t *bsin = bs_socket(SOCK_CONN_INCOMING, type);
	int64 available;

	if (bsout != NULL && (bsout->flags & BS_F_ENABLED)) {
		if (bsout->flags & BS_F_NOBW)				/* No more bandwidth */
			return FALSE;

		/*
		 * We need 1.5 TCP messages at least to allow the connection.
		 */

		available = bsout->bw_max + bsout->bw_stolen - bsout->bw_actual;

		if (available < 1.5 * BW_TCP_MSG)
			return FALSE;
	}

	if (bsin != NULL && (bsin->flags & BS_F_ENABLED)) {
		if (bsin->flags & BS_F_NOBW)				/* No more bandwidth */
			return FALSE;

		/*
		 * We need 1 TCP message at least to allow the connection.
		 */

		available = bsin->bw_max + bsin->bw_stolen - bsin->bw_actual;

		if (available < BW_TCP_MSG)
			return FALSE;
	}

	return TRUE;
}

/**
 * Periodic heartbeat.
 */
static void
bsched_heartbeat(bsched_t *bs, tm_t *tv)
{
	plist_t *iter;
	int delay;
	int64 overused;
	int64 theoric;
	int64 correction;
	int64 last_bw_max;
	int64 last_capped;
	int64 last_used;
	time_delta_t elapsed;

	bsched_check(bs);

	/*
	 * How much time elapsed since last call?
	 */

	delay = elapsed = tm_elapsed_ms(tv, &bs->last_period);

	/*
	 * It is possible to get a negative delay (i.e. have the current time
	 * be less than the previous time) when the machine runs a time
	 * synchronization daemon.
	 *
	 * In general, this is deemed to happen when the actual delay is less
	 * than min_period (75% of nominal).  We then force the fixed scheduling
	 * period delay and proceed as usual.
	 *
	 * Likewise, it is possible for the time to go forward.  This is a little
	 * more difficult to detect, because we can be delayed due to a high CPU
	 * load.  That's why the max_period is at 150% of the nominal period, and
	 * not at 125%.
	 */

	if (delay < bs->min_period) {
		if (GNET_PROPERTY(bsched_debug) && bs->last_period.tv_sec) {
			g_warning("%s(): \"%s\" noticed time jumped backwards (~%d ms)",
				G_STRFUNC, bs->name, bs->period - delay);
		}
		delay = bs->period;
	} else if (delay > bs->max_period) {
		if (GNET_PROPERTY(bsched_debug) && bs->last_period.tv_sec) {
			g_warning("%s(): \"%s\" noticed time jumped forwards (~%d ms)",
				G_STRFUNC, bs->name, delay - bs->period);
		}
		delay = bs->period;
	}

	bs->last_period = *tv;		/* struct copy */

	g_assert(delay > 0);

	/*
	 * Exponential Moving Average (EMA) with smoothing factor sm=1/4.
	 * Since usually one uses sm=2/(n+1), it's a moving average with n=7.
	 *
	 *      EMA(n+1) = sm*x(n) + (1-sm)*EMA(n)
	 */

	bs->period_ema += (delay >> 2) - (bs->period_ema >> 2);
	bs->bw_ema += (bs->bw_actual >> 2) - (bs->bw_ema >> 2);
	bs->bw_stolen_ema += (bs->bw_stolen >> 2) - (bs->bw_stolen_ema >> 2);

	g_assert(bs->period_ema >= 0);
	g_assert(bs->bw_ema >= 0);
	g_assert(bs->bw_stolen_ema >= 0);

	/*
	 * If scheduler is disabled, we don't need to recompute bandwidth.
	 *
	 * Jump to the end, where the new timeslice begins, so that per-source
	 * bandwidth transfer rates are updated nonetheless.  Use "goto" to avoid
	 * indenting the whole routine.
	 */

	if (!(bs->flags & BS_F_ENABLED))
		goto new_timeslice;

	/*
	 * Recompute bandwidth for the next period.
	 */

	last_bw_max = bs->bw_max;
	last_capped = bs->bw_capped;

	theoric = (int) (bs->bw_per_second / 1000.0 * delay);
	overused = bs->bw_actual - theoric;
	bs->bw_delta += overused;

	overused -= bs->bw_stolen;		/* Correct for computations below */

	entropy_harvest_single(VARLEN(overused));

	bs->bw_max = (int) (bs->bw_per_second / 1000.0 * bs->period_ema);

	/*
	 * We correct the bandwidth for the next slot.
	 *
	 * However, we don't use the current overuse indication in that case,
	 * but the maximum between the EMA of the bandwidth overused and the
	 * current overuse, to absorb random burst effects and yet account
	 * for constant average overuse.
	 *
	 * If a correction is due but the bandwidth settings changed in the
	 * period, forget it: allow a full period at the nominal new settings.
	 */

	/* Following is the overused "EMA" */
	correction = bs->bw_ema - bs->bw_stolen_ema - theoric;
	correction = MAX(correction, overused);

	if (correction > 0 && !(bs->flags & BS_F_CHANGED_BW)) {
		bs->bw_max -= correction;
		if (bs->bw_max < 0)
			bs->bw_max = 0;
	}

	/*
	 * Disregard amount of capped bandwidth if we used all our
	 * configured maximum, so that it is used more evenly during next slice.
	 * This information is also only perused for writing sources.
	 */

	if (bs->bw_actual >= last_bw_max || !(bs->flags & BS_F_WRITE))
		bs->bw_capped = 0;

	/*
	 * Any unwritten data must be removed from the amount of capped bandwidth.
	 * If we start to be flow-controlled by the kernel, we have to be careful
	 * not to write too much anyway.
	 */

	bs->bw_capped -= bs->bw_unwritten;
	bs->bw_capped = MAX(0, bs->bw_capped);

	/*
	 * Compute the amount of sources used this period.
	 *
	 * This information is used to initially compute the bandwidth per slot.
	 * Indeed, when only a few sources are active, we need to distribute more
	 * bandwidth per slot that triggers in case we don't have the opportunity
	 * to loop through all the sources more than once before the end of
	 * the slot.
	 */

	last_used = 0;

	PLIST_FOREACH(bs->sources, iter) {
		bio_source_t *bio = iter->data;

		bio_check(bio);

		if (bio->flags & BIO_F_USED)
			last_used++;
	}

	g_assert(last_used <= bs->current_used);	/* May have removed a source */

	bs->last_used = last_used;

	if (GNET_PROPERTY(bsched_debug) > 4) {
		g_debug("BSCHED %s(%s): delay=%d (EMA=%s), b/w=%s (EMA=%s), "
			"overused=%s (EMA=%s) stolen=%s (EMA=%s) unwritten=%s "
			"capped=%s (%s) used %d/%d",
			G_STRFUNC, bs->name, delay, int64_to_string(bs->period_ema),
			int64_to_string2(bs->bw_actual), int64_to_string3(bs->bw_ema),
			int64_to_string4(overused),
			int64_to_string5(bs->bw_ema - bs->bw_stolen_ema - theoric),
			int64_to_string6(bs->bw_stolen),
			int64_to_string7(bs->bw_stolen_ema),
			int64_to_string8(bs->bw_unwritten),
			int64_to_string9(last_capped), int64_to_string10(bs->bw_capped),
			bs->last_used, bs->count);
		g_debug("BSCHED    -> b/w delta=%s, max=%s, slot=%s, first=%s "
			"(target %s B/s, %d slot%s, real %.02f B/s)",
			int64_to_string(bs->bw_delta), int64_to_string2(bs->bw_max),
			int64_to_string3(bs->count ? bs->bw_max / bs->count : 0),
			int64_to_string4(
				bs->count ? (bs->bw_max + bs->bw_capped) / bs->count : 0),
			int64_to_string5(bs->bw_per_second), PLURAL(bs->count),
			bs->bw_actual * 1000.0 / delay);
	}

	/*
	 * Reset running counters.
	 */

new_timeslice:

	bs->bw_last_period = bs->bw_actual;
	bs->bw_last_capped = bs->bw_capped;
	bs->bw_actual = bs->bw_stolen = 0;
}

/**
 * Periodic stealing beat, occurs after the heartbeat.
 */
static void
bsched_stealbeat(bsched_t *bs)
{
	pslist_t *l;
	pslist_t *all_used = NULL;		/* List of bsched_t that used all b/w */
	int all_used_count = 0;			/* Amount of bsched_t that used all b/w */
	int all_favour_count = 0;		/* I/O sources wanting favours */
	uint64 all_bw_count = 0;		/* Sum of configured bandwidth */
	int steal_count = 0;
	int64 underused;

	bsched_check(bs);
	g_assert(bs->bw_actual == 0);	/* Heartbeat step must have been done */

	if (bs->stealers == NULL)		/* No stealers */
		return;

	if (!(bs->flags & BS_F_ENABLED))	/* Scheduler disabled */
		return;

	if (bs->flags & BS_F_NO_STEALING)	/* Stealing from scheduler disabled */
		return;

	/**
	 * Note that we do not use the theoric bandwidth, but bs->bw_max to
	 * estimate the amount of underused bandwidth.  The reason is that
	 * bs->bw_max can be corrected due to traffic spikes.
	 */

	underused = bs->bw_max - bs->bw_last_period;

	/*
	 * If `bs' holds reading sources, there is no further correction needed.
	 *
	 * Howewever, for writing sources, we need to pay attention to possible
	 * outgoing flow-control exercised by the kernel.  We simply correct
	 * the amount of underused bandwidth by the amount of unwritten data.
	 */

	underused -= bs->bw_unwritten;

	/* XXX: Remove that for now -- we don't know if the untriggered sources
	 *		had anything to write or not. -- RAM, 11/05/2003 */

#if 0
	/*
	 * That's not enough for writing schedulers: some sources have no
	 * triggering callback (i.e. we write to them when we have more data),
	 * but others have triggering callbacks invoked only when there is room
	 * for more data.
	 *
	 * If there are such sources that have callbacks and did not trigger,
	 * it means there is already some flow control going on.  Maybe the
	 * remote end is not reading, or we have problem sending.  It's hard to
	 * tell.  In any case, remove half the contribution of each untriggered
	 * source.
	 */

	if (bs->flags & BS_F_WRITE) {
		int half_contribution = bs->count ? bs->bw_max / (2 * bs->count) : 0;
		plist_t *bl;

		for (bl = bs->sources; bl && underused > 0; bl = plist_next(bl)) {
			bio_source_t *bio = (bio_source_t *) bl->data;

			if (bio->io_callback != NULL && !(bio->flags & BIO_F_USED))
				underused -= half_contribution;
		}
	}
#endif

	entropy_harvest_single(VARLEN(underused));

	if (underused <= 0)				/* Nothing to redistribute */
		return;

	/*
	 * Determine who used up all its bandwidth among our stealers.
	 */

	PSLIST_FOREACH(bs->stealers, l) {
		bsched_t *xbs = l->data;

		steal_count++;
		all_favour_count += xbs->io_favours;

		if (xbs->bw_last_period >= xbs->bw_max) {
			all_used = pslist_prepend(all_used, xbs);
			all_used_count++;
			all_bw_count += xbs->bw_max;
		}

		/*
		 * If a stealer has an urgent need for bandwidth, distribute as
		 * much as we can to it before considering others.  If more than
		 * one stealer has urgent need, the order in which it is distributed
		 * is the reverse order in which stealers were added (i.e. the last
		 * addition is viewed as more prioritary).
		 */

		if (xbs->bw_urgent > 0) {
			int64 amount = MIN(underused, xbs->bw_urgent);
			xbs->bw_stolen += amount;
			xbs->bw_urgent -= amount;
			underused -= amount;

			if (GNET_PROPERTY(bsched_debug) > 4) {
				g_debug("BSCHED %s: \"%s\" urgently giving %s bytes "
					"to \"%s\" (still wants %s bytes urgently)",
					G_STRFUNC, bs->name, int64_to_string(amount),
					xbs->name, int64_to_string2(xbs->bw_urgent));
			}

			if (underused <= 0)			/* Nothing left to redistribute */
				goto done;
		}
	}

	g_assert(steal_count > 0);

	/*
	 * If some stealers have I/O sources wanting favours (extra bandwidth),
	 * distribute our surplus proportionally to the amount of sources.
	 *
	 * Distribute our available bandwidth proportionally to all the
	 * schedulers that saturated their bandwidth, or evenly to all the
	 * stealers if noone saturated.
	 */

	if (all_favour_count != 0) {
		PSLIST_FOREACH(bs->stealers, l) {
			bsched_t *xbs = l->data;
			double amount;

			if (xbs->bw_max == 0)
				continue;

			amount = (double) underused *
				(double) xbs->io_favours / all_favour_count;

			if ((double) xbs->bw_stolen + amount > (double) BS_BW_MAX)
				xbs->bw_stolen = BS_BW_MAX;
			else
				xbs->bw_stolen += (int64) amount;

			if (GNET_PROPERTY(bsched_debug) > 4)
				g_debug("BSCHED %s: \"%s\" giving %s bytes to \"%s\" "
					"(%d favour%s)",
					G_STRFUNC, bs->name, int64_to_string((int64) amount),
					xbs->name, PLURAL(xbs->io_favours));
		}
	} else if (all_used_count == 0) {
		PSLIST_FOREACH(bs->stealers, l) {
			bsched_t *xbs = l->data;
			xbs->bw_stolen += underused / steal_count;

			if (GNET_PROPERTY(bsched_debug) > 4)
				g_debug("BSCHED %s: \"%s\" evenly giving %s bytes to \"%s\"",
					G_STRFUNC, bs->name,
					int64_to_string(underused / steal_count), xbs->name);
		}
	} else {
		PSLIST_FOREACH(all_used, l) {
			bsched_t *xbs = l->data;
			double amount;

			if (xbs->bw_max == 0)
				continue;

			amount = (double) underused * (double) xbs->bw_max / all_bw_count;

			if ((double) xbs->bw_stolen + amount > (double) BS_BW_MAX)
				xbs->bw_stolen = BS_BW_MAX;
			else
				xbs->bw_stolen += (int64) amount;

			if (GNET_PROPERTY(bsched_debug) > 4)
				g_debug("BSCHED %s: \"%s\" giving %s bytes to \"%s\"",
					G_STRFUNC, bs->name, int64_to_string((int64) amount),
					xbs->name);
		}
	}

done:
	pslist_free(all_used);
}

/**
 * Periodic timer.
 */
void
bsched_timer(void)
{
	tm_t tv;
	pslist_t *l;
	int64 out_used = 0;
	int64 in_used = 0;
	bool read_data = FALSE;

	tm_now(&tv);

	/*
	 * First pass: compute bandwidth used.
	 */

	PSLIST_FOREACH(bws_list, l) {
		bsched_bws_t bws = pointer_to_uint(l->data);
		bsched_heartbeat(bsched_get(bws), &tv);
	}

	/*
	 * Second pass: possibly steal bandwidth from schedulers that
	 * have not used up all their quota.
	 */

	PSLIST_FOREACH(bws_list, l) {
		bsched_bws_t bws = pointer_to_uint(l->data);
		bsched_stealbeat(bsched_get(bws));
	}

	/*
	 * Third pass: begin new timeslice.
	 */

	PSLIST_FOREACH(bws_list, l) {
		bsched_bws_t bws = pointer_to_uint(l->data);
		bsched_begin_timeslice(bsched_get(bws));
	}

	/*
	 * Fourth pass: update the average bandwidth used.
	 */

	PSLIST_FOREACH(bws_out_list, l) {
		bsched_bws_t bws = pointer_to_uint(l->data);
		bsched_t *bs = bsched_get(bws);
		out_used += (int64) (bs->bw_last_period * 1000.0 / bs->period_ema);
	}

	bws_out_ema += (out_used >> 6) - (bws_out_ema >> 6);	/* Slow EMA */

	if (GNET_PROPERTY(bsched_debug) > 3) {
		g_debug("BSCHED outgoing b/w EMA = %s bytes/s",
			int64_to_string(bws_out_ema));
	}

	PSLIST_FOREACH(bws_in_list, l) {
		bsched_bws_t bws = pointer_to_uint(l->data);
		bsched_t *bs = bsched_get(bws);

		in_used += (int64) (bs->bw_last_period * 1000.0 / bs->period_ema);

		if (bs->flags & BS_F_DATA_READ) {
			read_data = TRUE;
			bs->flags &= ~BS_F_DATA_READ;
			entropy_harvest_single(VARLEN(in_used));
		}
	}

	bws_in_ema += (in_used >> 6) - (bws_in_ema >> 6);		/* Slow EMA */

	if (GNET_PROPERTY(bsched_debug) > 3) {
		g_debug("BSCHED incoming b/w EMA = %s bytes/s",
			int64_to_string(bws_in_ema));
	}

	/*
	 * Don't simply rely on in_used > 0 since we fake input data when
	 * sockets are closed or timeout on connection.  We really want to know
	 * whether there has been actual data read.
	 *		--RAM, 2005-06-29
	 */

	if (read_data)
		inet_read_activity();
}

static bool
true_expr(const char *expr)
{
	if (GNET_PROPERTY(bsched_debug)) {
		g_debug("BSCHED %s", expr);
	}
	return TRUE;
}

#define noisy_check(expr) ((expr) ? true_expr(G_STRLOC ": " #expr) : 0)

/**
 * Determine whether we have enough bandwidth to possibly become an ultra node:
 *
 *  -# Uploads must not be frequently stalling.
 *  -# If the servent is not sharing anything, use its bandwidth for ultra mode.
 *  -# If bandwidth schedulers are enabled, leaf nodes must not be configured
 *     to steal all the HTTP outgoing bandwidth, unless they disabled uploads.
 *  -# If Gnet out scheduler is enabled, there must be at least BW_OUT_GNET_MIN
 *     bytes per gnet connection.
 *  -# Overall, there must be BW_OUT_LEAF_MIN bytes per configured leaf plus
 *     BW_OUT_GNET_MIN bytes per gnet connection available.
 *
 * @return TRUE if we have enough bandwidth to become an ultra node.
 */
bool
bsched_enough_up_bandwidth(void)
{
	static time_t last_stall, last_uploads;
	uint64 total = 0;

	/*
	 * Stalling uploads are an indication that the output bandwidth is
	 * saturated.  This condition is not triggered lightly, and adjustments
	 * to the bandwidth distribution are made before declaring that uploads
	 * are really stalling (see upload_stall() and related routines).
	 */

	if (noisy_check(GNET_PROPERTY(uploads_stalling))) {
		last_stall = tm_time();
		return FALSE;		/* 1. */
	}

	/*
	 * To avoid frequent UP -> leaf demotions due to upload stalling, we
	 * impose a minimum amount of time since the last stalling condition.
	 */

	if (noisy_check(delta_time(tm_time(), last_stall) < BW_UL_STALL_TIM))
		return FALSE;		/* 1. */

	/*
	 * Servents not sharing anything should be able to devote their outgoing
	 * bandwidth to serve as ultra nodes.
	 */

	if (noisy_check(!upload_is_enabled()))
		goto upload_bw_irrelevant;	/* 2. */

	if (noisy_check(delta_time(tm_time(), last_uploads) >= BW_UL_RUN_TIME)) {
		if (0 != GNET_PROPERTY(ul_registered))
			last_uploads = tm_time();
		else
			goto upload_bw_irrelevant;	/* 2. */
	}

	/*
	 * Servent is uploading, make sure configured schedulers would not steal
	 * out all the HTTP bandwidth if promoted to ultra mode (since leaves
	 * take their bandwidth out of the configured HTTP limit).
	 */

	if (
		noisy_check(
			GNET_PROPERTY(bws_glout_enabled) &&
			GNET_PROPERTY(bws_out_enabled) &&
			GNET_PROPERTY(bw_gnet_lout) >= GNET_PROPERTY(bw_http_out)
		)
	)
		return FALSE;		/* 3. */

upload_bw_irrelevant:

	/*
	 * If they configured outgoing limits for the Gnutella traffic, make
	 * sure we have a reasonable setup, compatible with the predicted ultra
	 * node usage.
	 */

	if (
		noisy_check(
			GNET_PROPERTY(bws_gout_enabled) &&
			GNET_PROPERTY(bw_gnet_out) < BW_OUT_GNET_MIN *
		(GNET_PROPERTY(up_connections) + GNET_PROPERTY(max_connections)) / 2)
	)
		return FALSE;		/* 4. */

	if (GNET_PROPERTY(bws_gout_enabled))
		total += GNET_PROPERTY(bw_gnet_out);

	if (GNET_PROPERTY(bws_out_enabled)) /* Leaf b/w stolen from HTTP traffic */
		total += GNET_PROPERTY(bw_http_out);
	else if (GNET_PROPERTY(bws_glout_enabled))
		total += GNET_PROPERTY(bw_gnet_lout);

	if (noisy_check(0 == total))
		return TRUE;		/* No bandwidth limits configured */

	if (
		noisy_check(total <
			(BW_OUT_GNET_MIN * GNET_PROPERTY(max_connections) +
			 BW_OUT_LEAF_MIN * GNET_PROPERTY(max_leaves)))
	) {
		return FALSE;		/* 5. */
	}

	return TRUE;
}

/**
 * Return appropriate bandwidth secheduler for outgoing traffic based on the
 * destination address.
 */
bsched_bws_t
bsched_out_select_by_addr(const host_addr_t addr)
{
	return host_addr_is_loopback(addr) ? BSCHED_BWS_LOOPBACK_OUT :
			is_private_addr(addr) ? BSCHED_BWS_PRIVATE_OUT : BSCHED_BWS_OUT;
}

/**
 * Return appropriate bandwidth secheduler for incoming traffic based on the
 * source address.
 */
bsched_bws_t
bsched_in_select_by_addr(const host_addr_t addr)
{
	return host_addr_is_loopback(addr) ? BSCHED_BWS_LOOPBACK_IN :
		is_private_addr(addr) ? BSCHED_BWS_PRIVATE_IN : BSCHED_BWS_IN;
}

/* vi: set ts=4 sw=4 cindent: */
