/*
 * Copyright (c) 2002, Raphael Manfredi
 *
 * Bandwidth scheduling.
 */

#ifndef __bsched_h__
#define __bsched_h__

#include <sys/time.h>		/* For struct timeval */
#include <gdk/gdk.h>

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
 */
typedef struct bsched {
	struct timeval last_period;			/* Last time we ran our period */
	GList *sources;						/* List of bio_source_t */
	gchar *name;						/* Name, for tracing purposes */
	gint count;							/* Amount of sources */
	gint type;							/* Scheduling type */
	gint flags;							/* Processing flags */
	gint period;						/* Fixed scheduling period, in ms */
	gint period_ema;					/* EMA of period, in ms */
	gint bw_per_second;					/* Configure bandwidth in bytes/sec */
	gint bw_max;						/* Max bandwidth per period */
	gint bw_actual;						/* Bandwidth used so far in period */
	gint bw_slot;						/* Basic per-source bandwidth lot */
	gint bw_ema;						/* EMA of bandwidth really used */
	gint bw_delta;						/* Running diff of actual vs. theoric */
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

/*
 * Source under bandwidth control.
 */
typedef struct bio_source {
	bsched_t *bs;						/* B/w scheduler for this source */
	gint fd;							/* File descriptor */
	gint io_tag;						/* Recorded I/O callback tag */
	guint io_flags;						/* Flags for I/O callback */
	GdkInputFunction io_callback;		/* I/O callback routine */
	gpointer io_arg;					/* I/O callback argument */
	guint32 flags;						/* Source flags */
} bio_source_t;

/*
 * Source flags.
 */

#define BIO_F_READ			0x00000001	/* Reading source */
#define BIO_F_WRITE			0x00000002	/* Writing source */
#define BIO_F_ACTIVE		0x00000004	/* Source active this period */

/*
 * Global bandwidth schedulers.
 */

extern bsched_t *bws_out;
extern bsched_t *bws_in;

/*
 * Public interaface.
 */

bsched_t *bsched_make(gchar *name,
	gint type, guint32 mode, gint bandwidth, gint period);
void bsched_init(void);
void bsched_close(void);
void bsched_enable(bsched_t *bs);
void bsched_enable_all(void);
bio_source_t *bsched_source_add(bsched_t *bs, int fd, guint32 flags,
	GdkInputFunction callback, gpointer arg);
void bsched_source_remove(bio_source_t *bio);
gint bio_write(bio_source_t *bio, gpointer data, gint len);
gint bio_read(bio_source_t *bio, gpointer data, gint len);
gint bws_write(bsched_t *bs, gint fd, gpointer data, gint len);
gint bws_read(bsched_t *bs, gint fd, gpointer data, gint len);
void bsched_timer(void);

#endif	/* __bsched_h__ */

/* vi: set ts=4: */

