/*
 * $Id$
 *
 * Copyright (c) 2002-2003, Raphael Manfredi
 *
 * Bandwidth scheduling.
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

#ifndef _bsched_h_
#define _bsched_h_

#include "gnet.h"			/* For node_peer_t */
#include "sockets.h"		/* For enum socket_type */

struct iovec;

#include <sys/types.h>		/* For off_t */

/*
 * Bandwidth scheduler.
 *
 * A bandwidth scheduler (`B-sched' for short) is made of:
 *
 * . A set of I/O sources.
 * . A set of I/O callbacks to trigger when I/O sources are ready.
 * . A bandwidth limit per scheduling perdiod.
 * . A scheduling period.
 *
 * It operates in cooperation with the I/O sources:
 *
 * 1. Each I/O source registers its I/O callback through the B-sched, so
 *    that it is possible to temporarily disable them should we run out of
 *    bandwidth for the period.
 * 2. Each I/O source requests an amount of bandwidth to use.
 * 3. After use, each I/O source tells the B-sched how much of the allocated
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
typedef struct bsched {
	GTimeVal last_period;				/* Last time we ran our period */
	GList *sources;						/* List of bio_source_t */
	GSList *stealers;					/* List of bsched_t stealing bw */
	gchar *name;						/* Name, for tracing purposes */
	gint count;							/* Amount of sources */
	gint type;							/* Scheduling type */
	gint flags;							/* Processing flags */
	gint period;						/* Fixed scheduling period, in ms */
	gint min_period;					/* Minimal period without correction */
	gint max_period;					/* Maximal period without correction */
	gint period_ema;					/* EMA of period, in ms */
	gint bw_per_second;					/* Configure bandwidth in bytes/sec */
	gint bw_max;						/* Max bandwidth per period */
	gint bw_actual;						/* Bandwidth used so far in period */
	gint bw_last_period;				/* Bandwidth used last period */
	gint bw_last_capped;				/* Bandwidth capped last period */
	gint bw_slot;						/* Basic per-source bandwidth lot */
	gint bw_ema;						/* EMA of bandwidth really used */
	gint bw_stolen;						/* Amount we stole this period */
	gint bw_stolen_ema;					/* EMA of stolen bandwidth */
	gint bw_delta;						/* Running diff of actual vs. theoric */
	gint bw_unwritten;					/* Data that we could not write */
	gint bw_capped;						/* Bandwidth we refused to sources */
	gint last_used;						/* Nb of active sources last period */
	gint current_used;					/* Nb of active sources this period */
	gboolean looped;					/* True when looped once over sources */
} bsched_t;

/*
 * Scheduling types.
 */

#define BS_T_STREAM		1				/* Streaming */
#define BS_T_RANDOM		2				/* Random (unsupported) */

/*
 * Scheduling flags.
 */

#define BS_F_ENABLED		0x00000001	/* Scheduler enabled */
#define BS_F_READ			0x00000002	/* Reading sources */
#define BS_F_WRITE			0x00000004	/* Writing sources */
#define BS_F_NOBW			0x00000008	/* No more bandwidth */
#define BS_F_FROZEN_SLOT	0x00000010	/* Value of `bw_slot' is frozen */
#define BS_F_CHANGED_BW		0x00000020	/* Bandwidth limit changed */

#define BS_F_RW				(BS_F_READ|BS_F_WRITE)

#define BS_BW_MAX			(2*1024*1024)

#define bsched_bps(b)		((b)->bw_last_period * 1000 / (b)->period)
#define bsched_pct(b)		(bsched_bps(b) * 100 / (1+(b)->bw_per_second))
#define bsched_avg_bps(b)	((b)->bw_ema * 1000 / (b)->period)
#define bsched_avg_pct(b)	(bsched_avg_bps(b) * 100 / (1+(b)->bw_per_second))

#define bsched_bwps(b)		((b)->bw_per_second)
#define bsched_saturated(b)	((b)->bw_actual > (b)->bw_max)

#define bsched_enabled(b)	((b)->flags & BS_F_ENABLED)

/*
 * Source under bandwidth control.
 */
typedef struct bio_source {
	bsched_t *bs;						/* B/w scheduler for this source */
	gint fd;							/* File descriptor */
	gint io_tag;						/* Recorded I/O callback tag */
	guint io_flags;						/* Flags for I/O callback */
	inputevt_handler_t io_callback;		/* I/O callback routine */
	gpointer io_arg;					/* I/O callback argument */
	guint32 flags;						/* Source flags */
	guint bw_actual;					/* Actual bandwidth used in period */
	guint bw_last_bps;					/* B/w used last period (bps) */
	guint bw_fast_ema;					/* Fast EMA of actual bandwidth used */
	guint bw_slow_ema;					/* Slow EMA of actual bandwidth used */
} bio_source_t;

/*
 * Source flags.
 */

#define BIO_F_READ			0x00000001	/* Reading source */
#define BIO_F_WRITE			0x00000002	/* Writing source */
#define BIO_F_ACTIVE		0x00000004	/* Source active since b/w scheduled */
#define BIO_F_USED			0x00000008	/* Source used this period */

#define BIO_F_RW			(BIO_F_READ|BIO_F_WRITE)

#define BIO_EMA_SHIFT	7

#define bio_bps(b)		((b)->bw_last_bps)
#define bio_avg_bps(b)	((b)->bw_slow_ema >> BIO_EMA_SHIFT)

/*
 * Global bandwidth schedulers.
 */

struct bws_set {
	bsched_t *out;			/* Output (uploads) */
	bsched_t *in;			/* Input (downloads) */
	bsched_t *gout;			/* Gnet output */
	bsched_t *gin;			/* Gnet input */
	bsched_t *glout;		/* Gnet leaf output */
	bsched_t *glin;			/* Gnet leaf input */
};

extern struct bws_set bws;

/*
 * Public interface.
 */

bsched_t *bsched_make(gchar *name,
	gint type, guint32 mode, gint bandwidth, gint period);
void bsched_init(void);
void bsched_shutdown(void);
void bsched_close(void);
void bsched_set_peermode(node_peer_t mode);
void bsched_enable(bsched_t *bs);
void bsched_disable(bsched_t *bs);
void bsched_enable_all(void);
bio_source_t *bsched_source_add(bsched_t *bs, int fd, guint32 flags,
	inputevt_handler_t callback, gpointer arg);
void bsched_source_remove(bio_source_t *bio);
void bsched_set_bandwidth(bsched_t *bs, gint bandwidth);
void bio_add_callback(bio_source_t *bio,
	inputevt_handler_t callback, gpointer arg);
void bio_remove_callback(bio_source_t *bio);
gint bio_write(bio_source_t *bio, gconstpointer data, gint len);
gint bio_writev(bio_source_t *bio, struct iovec *iov, gint iovcnt);
gint bio_sendfile(bio_source_t *bio, gint in_fd, off_t *offset, gint len);
gint bio_read(bio_source_t *bio, gpointer data, gint len);
gint bws_write(bsched_t *bs, gint fd, gconstpointer data, gint len);
gint bws_read(bsched_t *bs, gint fd, gpointer data, gint len);
void bsched_timer(void);

void bws_sock_connect(enum socket_type type);
void bws_sock_connected(enum socket_type type);
void bws_sock_accepted(enum socket_type type);
void bws_sock_connect_timeout(enum socket_type type);
void bws_sock_connect_failed(enum socket_type type);
void bws_sock_closed(enum socket_type type, gboolean remote);
gboolean bws_can_connect(enum socket_type type);

gboolean bsched_enough_up_bandwidth(void);

#endif	/* _bsched_h_ */

/* vi: set ts=4: */

