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
 * Bandwidth scheduling.
 *
 * @author Raphael Manfredi
 * @date 2002-2003
 */

#ifndef _core_bsched_h_
#define _core_bsched_h_

#include "sockets.h"		/* For enum socket_type */

#include "lib/inputevt.h"
#include "lib/tm.h"
#include "if/core/hosts.h"	/* For gnet_host_t */
#include "if/core/nodes.h"	/* For node_peer_t */
#include "if/core/bsched.h"

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
 * given as "stolem" bandwidth to some of the schedulers stealing from us.
 * Priority is given to schedulers that used up all their bandwidth.
 */

struct bsched {
	tm_t last_period;				/**< Last time we ran our period */
	GList *sources;					/**< List of bio_source_t */
	GSList *stealers;				/**< List of bsched_t stealing bw */
	gchar *name;					/**< Name, for tracing purposes */
	gint count;						/**< Amount of sources */
	gint type;						/**< Scheduling type */
	gint flags;						/**< Processing flags */
	gint period;					/**< Fixed scheduling period, in ms */
	gint min_period;				/**< Minimal period without correction */
	gint max_period;				/**< Maximal period without correction */
	gint period_ema;				/**< EMA of period, in ms */
	gint bw_per_second;				/**< Configure bandwidth in bytes/sec */
	gint bw_max;					/**< Max bandwidth per period */
	gint bw_actual;					/**< Bandwidth used so far in period */
	gint bw_last_period;			/**< Bandwidth used last period */
	gint bw_last_capped;			/**< Bandwidth capped last period */
	gint bw_slot;					/**< Basic per-source bandwidth lot */
	gint bw_ema;					/**< EMA of bandwidth really used */
	gint bw_stolen;					/**< Amount we stole this period */
	gint bw_stolen_ema;				/**< EMA of stolen bandwidth */
	gint bw_delta;					/**< Running diff of actual vs. theoric */
	gint bw_unwritten;				/**< Data that we could not write */
	gint bw_capped;					/**< Bandwidth we refused to sources */
	gint last_used;					/**< Nb of active sources last period */
	gint current_used;				/**< Nb of active sources this period */
	gboolean looped;				/**< True when looped once over sources */
};

/*
 * Scheduling types.
 */

#define BS_T_STREAM		1				/**< Streaming */
#define BS_T_RANDOM		2				/**< Random (unsupported) */

/*
 * Scheduling flags.
 */

#define BS_F_ENABLED		0x00000001	/**< Scheduler enabled */
#define BS_F_READ			0x00000002	/**< Reading sources */
#define BS_F_WRITE			0x00000004	/**< Writing sources */
#define BS_F_NOBW			0x00000008	/**< No more bandwidth */
#define BS_F_FROZEN_SLOT	0x00000010	/**< Value of `bw_slot' is frozen */
#define BS_F_CHANGED_BW		0x00000020	/**< Bandwidth limit changed */
#define BS_F_CLEARED		0x00000040	/**< Ran clear_active once on sched. */
#define BS_F_DATA_READ		0x00000080	/**< Data read from one source */

#define BS_F_RW				(BS_F_READ|BS_F_WRITE)

#define bsched_bps(b)		((b)->bw_last_period * 1000 / (b)->period)
#define bsched_pct(b)		(bsched_bps(b) * 100 / (1+(b)->bw_per_second))
#define bsched_avg_bps(b)	((b)->bw_ema * 1000 / (b)->period)
#define bsched_avg_pct(b)	(bsched_avg_bps(b) * 100 / (1+(b)->bw_per_second))

#define bsched_bwps(b)		((b)->bw_per_second)
#define bsched_saturated(b)	((b)->bw_actual > (b)->bw_max)

#define bsched_enabled(b)	((b)->flags & BS_F_ENABLED)

/**
 * Global bandwidth schedulers.
 */

struct bws_set {
	bsched_t *out;			/**< Output (uploads) */
	bsched_t *in;			/**< Input (downloads) */
	bsched_t *gout;			/**< Gnet TCP output */
	bsched_t *gin;			/**< Gnet TCP input */
	bsched_t *gout_udp;		/**< Gnet UDP output */
	bsched_t *gin_udp;		/**< Gnet UDP input */
	bsched_t *glout;		/**< Gnet leaf output */
	bsched_t *glin;			/**< Gnet leaf input */
};

typedef struct sendfile_ctx {
	void *map;
	off_t map_start, map_end;
} sendfile_ctx_t;


struct iovec;
extern struct bws_set bws;

/*
 * Public interface.
 */

bsched_t *bsched_make(const gchar *name,
	gint type, guint32 mode, gint bandwidth, gint period);
void bsched_init(void);
void bsched_shutdown(void);
void bsched_close(void);
void bsched_set_peermode(node_peer_t mode);
void bsched_enable(bsched_t *bs);
void bsched_disable(bsched_t *bs);
void bsched_enable_all(void);
bio_source_t *bsched_source_add(bsched_t *bs, wrap_io_t *wio, guint32 flags,
	inputevt_handler_t callback, gpointer arg);
void bsched_source_remove(bio_source_t *bio);
void bsched_set_bandwidth(bsched_t *bs, gint bandwidth);
bio_source_t *bsched_source_add(bsched_t *bs, wrap_io_t *wio, guint32 flags,
	inputevt_handler_t callback, gpointer arg);
void bio_add_callback(bio_source_t *bio,
	inputevt_handler_t callback, gpointer arg);
void bio_remove_callback(bio_source_t *bio);
ssize_t bio_write(bio_source_t *bio, gconstpointer data, size_t len);
ssize_t bio_writev(bio_source_t *bio, struct iovec *iov, gint iovcnt);
ssize_t bio_sendto(bio_source_t *bio, const gnet_host_t *to,
	gconstpointer data, size_t len);
ssize_t bio_sendfile(sendfile_ctx_t *ctx, bio_source_t *bio, gint in_fd,
	off_t *offset, size_t len);
ssize_t bio_read(bio_source_t *bio, gpointer data, size_t len);
ssize_t bio_readv(bio_source_t *bio, struct iovec *iov, gint iovcnt);
ssize_t bws_write(bsched_t *bs, wrap_io_t *wio, gconstpointer data, size_t len);
ssize_t bws_read(bsched_t *bs, wrap_io_t *wio, gpointer data, size_t len);
void bsched_timer(void);

void bws_sock_connect(enum socket_type type);
void bws_sock_connected(enum socket_type type);
void bws_sock_accepted(enum socket_type type);
void bws_sock_connect_timeout(enum socket_type type);
void bws_sock_connect_failed(enum socket_type type);
void bws_sock_closed(enum socket_type type, gboolean remote);
gboolean bws_can_connect(enum socket_type type);

void bws_udp_count_written(gint len);
void bws_udp_count_read(gint len);

gboolean bsched_enough_up_bandwidth(void);

void bsched_config_steal_http_gnet(void);
void bsched_config_steal_gnet(void);

#endif	/* _core_bsched_h_ */

/* vi: set ts=4 sw=4 cindent: */
