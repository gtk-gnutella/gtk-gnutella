/*
 * Copyright (c) 2002, Raphael Manfredi
 *
 * Bandwidth scheduling.
 */

#include <stdio.h>
#include <errno.h>
#include <unistd.h>

#include "config.h"

#ifdef HAVE_SENDFILE_H
#include <sys/sendfile.h>
#endif

#include "bsched.h"
#include "appconfig.h"

/*
 * Global bandwidth schedulers.
 */

bsched_t *bws_out = NULL;
bsched_t *bws_in = NULL;

#define BW_SLOT_MIN		256		/* Minimum bandwidth/slot for realloc */

/*
 * bsched_make
 *
 * Create a new bandwidth scheduler.
 *
 * `type' refers to the scheduling model.  Only BS_T_STREAM for now.
 * `mode' refers to the nature of the sources: either reading or writing.
 * `bandwidth' is the expected bandwidth in bytes per second.
 * `period' is the scheduling period in ms.
 */
bsched_t *bsched_make(gchar *name,
	gint type, guint32 mode, gint bandwidth, gint period)
{
	bsched_t *bs;

	/* Must contain either reading or writing sources */
	g_assert(mode & (BS_F_READ|BS_F_WRITE));
	g_assert((mode & (BS_F_READ|BS_F_WRITE)) != (BS_F_READ|BS_F_WRITE));
	g_assert(!(mode & ~(BS_F_READ|BS_F_WRITE)));

	g_assert(bandwidth >= 0);
	g_assert(period > 0);
	g_assert(type == BS_T_STREAM);		/* XXX only mode supported for now */
	g_assert(bandwidth < BS_BW_MAX);	/* Signed, and multiplied by 1000 */

	bs = (bsched_t *) g_malloc0(sizeof(*bs));

	bs->name = g_strdup(name);
	bs->flags = mode;
	bs->type = type;
	bs->period = period;
	bs->min_period = period - (period >> 2);	/* 75% of nominal period */
	bs->max_period = period + (period >> 1);	/* 150% of nominal period */
	bs->period_ema = period;
	bs->bw_per_second = bandwidth;
	bs->bw_max = bandwidth * period / 1000;

	return bs;
}

/*
 * bsched_free
 *
 * Free bandwidth scheduler.
 *
 * All sources have their bsched pointer reset to NULL but are not disposed of.
 * Naturally, they cannot be used for I/O any more.
 */
static void bsched_free(bsched_t *bs)
{
	GList *l;

	for (l = bs->sources; l; l = g_list_next(l)) {
		bio_source_t *bio = (bio_source_t *) l->data;
		
		g_assert(bio->bs == bs);
		bio->bs = NULL;				/* Mark orphan source */
	}

	g_list_free(bs->sources);
	g_free(bs->name);
	g_free(bs);
}

/*
 * bsched_init
 *
 * Initialize global bandwidth schedulers.
 */
void bsched_init(void)
{
	bws_out = bsched_make("out",
		BS_T_STREAM, BS_F_WRITE, output_bandwidth, 1000);

	bws_in = bsched_make("in",
		BS_T_STREAM, BS_F_READ, input_bandwidth, 1000);
}

/*
 * bsched_close
 *
 * Discard global bandwidth schedulers.
 */
void bsched_close(void)
{
	bsched_free(bws_out);
	bsched_free(bws_in);

	bws_out = bws_in = NULL;
}

/*
 * bsched_enable
 *
 * Enable scheduling, marks the start of the period.
 */
void bsched_enable(bsched_t *bs)
{
	struct timezone tz;

	g_assert(bs);

	bs->flags |= BS_F_ENABLED;
	(void) gettimeofday(&bs->last_period, &tz);
}

/*
 * bsched_disable
 *
 * Disable scheduling.
 */
static void bsched_disable(bsched_t *bs)
{
	g_assert(bs);

	bs->flags &= ~BS_F_ENABLED;
}

/*
 * bsched_enable_all
 *
 * Enable all known bandwidth schedulers.
 */
void bsched_enable_all(void)
{
	if (bws_out->bw_per_second)
		bsched_enable(bws_out);

	if (bws_in->bw_per_second)
		bsched_enable(bws_in);
}

/*
 * bio_enable
 *
 * Enable an I/O source.
 */
static void bio_enable(bio_source_t *bio)
{
	g_assert(bio->io_tag == 0);

	bio->io_tag = gdk_input_add(bio->fd,
		(GdkInputCondition) GDK_INPUT_EXCEPTION |
			((bio->flags & BIO_F_READ) ? GDK_INPUT_READ : GDK_INPUT_WRITE),
		bio->io_callback, bio->io_arg);

	g_assert(bio->io_tag);
}

/*
 * bio_disable
 *
 * Disable I/O source.
 *
 * The value of `bw_available' is ignored, as this is a fairly low-level call.
 * If it is called, then the caller has already taken care of redispatching
 * any remaining bandwidth.
 */
static void bio_disable(bio_source_t *bio)
{
	g_assert(bio->io_tag);

	gdk_input_remove(bio->io_tag);
	bio->io_tag = 0;
}

/*
 * bsched_no_more_bandwidth
 *
 * Disable all sources and flag that we have no more bandwidth.
 */
static void bsched_no_more_bandwidth(bsched_t *bs)
{
	GList *l;

	for (l = bs->sources; l; l = g_list_next(l)) {
		bio_source_t *bio = (bio_source_t *) l->data;

		if (bio->io_tag)
			bio_disable(bio);
	}

	bs->flags |= BS_F_NOBW;
}

/*
 * bsched_clear_active
 *
 * Remove activation indication on all the sources.
 */
static void bsched_clear_active(bsched_t *bs)
{
	GList *l;

	for (l = bs->sources; l; l = g_list_next(l)) {
		bio_source_t *bio = (bio_source_t *) l->data;

		bio->flags &= ~BIO_F_ACTIVE;
	}
}

/*
 * bsched_begin_timeslice
 *
 * Called whenever a new scheduling timeslice begins.
 *
 * Re-enable all sources and flag that we have bandwidth.
 * Update the per-source bandwidth statistics.
 * Clears all activation indication on all sources.
 */
static void bsched_begin_timeslice(bsched_t *bs)
{
	GList *l;

	for (l = bs->sources; l; l = g_list_next(l)) {
		bio_source_t *bio = (bio_source_t *) l->data;
		guint32 actual;

		bio->flags &= ~BIO_F_ACTIVE;
		if (bio->io_tag == 0)
			bio_enable(bio);

		/*
		 * Fast EMA of bandwidth is computed on the last n=3 terms.
		 * The smoothing factor, sm=2/(n+1), is therefore 0.5, which is easy
		 * to compute.  The short period gives us a good estimation of the
		 * "instantaneous bandwidth" used.
		 *
		 * Slow EMA of bandwidth is computed on the last n=127 terms, which at
		 * one computation per second, means an average of the two minutes.
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
		bio->bw_actual = 0;
	}

	bs->flags &= ~(BS_F_NOBW|BS_F_FROZEN_SLOT|BS_F_CHANGED_BW);

	/*
	 * If the slot is less than the minimum we can reach by dynamically
	 * adjusting the bandwidth, then don't bother trying and freeze it.
	 */

	if (bs->bw_slot < BW_SLOT_MIN)
		bs->flags |= BS_F_FROZEN_SLOT;
}

/*
 * bsched_bio_add
 *
 * Add new source to the source list of scheduler.
 */
static void bsched_bio_add(bsched_t *bs, bio_source_t *bio)
{
	bs->sources = g_list_append(bs->sources, bio);
	bs->count++;

	bs->bw_slot = bs->bw_max / bs->count;

	/*
	 * If the slot is less than the minimum we can reach by dynamically
	 * adjusting the bandwidth, then don't bother trying and freeze it.
	 */

	if (bs->bw_slot < BW_SLOT_MIN)
		bs->flags |= BS_F_FROZEN_SLOT;
}

/*
 * bsched_bio_remove
 *
 * Remove source from the source list of scheduler.
 */
static void bsched_bio_remove(bsched_t *bs, bio_source_t *bio)
{
	bs->sources = g_list_remove(bs->sources, bio);
	bs->count--;

	if (bs->count)
		bs->bw_slot = bs->bw_max / bs->count;

	g_assert(bs->count >= 0);
}

/*
 * bsched_source_add
 *
 * Declare fd as a new source for the scheduler.
 * Returns new bio_source object.
 */
bio_source_t *bsched_source_add(bsched_t *bs, int fd, guint32 flags,
	GdkInputFunction callback, gpointer arg)
{
	bio_source_t *bio;

	/*
	 * Must insert reading sources in reading scheduler and writing ones
	 * in a writing scheduler.
	 */

	g_assert(!(bs->flags & BS_F_READ) == !(flags & BIO_F_READ));
	g_assert(flags & (BIO_F_READ|BIO_F_WRITE));
	g_assert((flags & (BIO_F_READ|BIO_F_WRITE)) != (BIO_F_READ|BIO_F_WRITE));
	g_assert(!(flags & ~(BIO_F_READ|BIO_F_WRITE)));

	bio = (bio_source_t *) g_malloc0(sizeof(*bio));

	bio->bs = bs;
	bio->fd = fd;
	bio->flags = flags;
	bio->io_callback = callback;
	bio->io_arg = arg;

	bsched_bio_add(bs, bio);
	if (!(bs->flags & BS_F_NOBW))
		bio_enable(bio);

	return bio;
}

/*
 * bsched_source_remove
 *
 * Remove bio_source object from the scheduler.
 * The bio_source object is freed and must not be re-used.
 */
void bsched_source_remove(bio_source_t *bio)
{
	bsched_t *bs = bio->bs;

	if (bs)
		bsched_bio_remove(bs, bio);
	if (bio->io_tag)
		gdk_input_remove(bio->io_tag);

	g_free(bio);
}

/*
 * bsched_set_bandwidth
 *
 * On-the-fly changing of the allowed bandwidth.
 */
void bsched_set_bandwidth(bsched_t *bs, gint bandwidth)
{
	g_assert(bs);
	g_assert(bandwidth >= 0);
	g_assert(bandwidth < BS_BW_MAX);	/* Signed, and multiplied by 1000 */

	bs->bw_per_second = bandwidth;
	bs->bw_max = bandwidth * bs->period / 1000;

	/*
	 * If `bandwidth' is 0, then we're disabling bandwidth scheduling and
	 * allow all traffic to go through, unlimited.
	 *
	 * NB: at the next heartbeat, bsched_begin_timeslice() will be called
	 * to re-enable all the sources if any were disabled.
	 */

	if (bandwidth == 0) {
		bsched_disable(bs);
		return;
	}

	/*
	 * When all bandwidth has been used, disable all sources.
	 */

	if (bs->bw_actual >= bs->bw_max)
		bsched_no_more_bandwidth(bs);

	bs->flags |= BS_F_CHANGED_BW;
}


/*
 * bw_available
 *
 * Returns the bandwidth available for a given source.
 * `len' is the amount of bytes requested by the application.
 */
static gint bw_available(bio_source_t *bio, gint len)
{
	bsched_t *bs = bio->bs;
	gint available;

	if (!(bs->flags & BS_F_ENABLED))		/* Scheduler disabled */
		return len;							/* Use amount requested */

	if (bs->flags & BS_F_NOBW)				/* No more bandwidth */
		return 0;							/* Grant nothing */

	if (!bio->io_tag)						/* Source already disabled */
		return 0;							/* No bandwidth available */

	/*
	 * If source was already active, recompute the per-slot value since
	 * we already looped once through all the sources.  This prevents the
	 * first scheduled sources to eat all the bandwidth.
	 */

	available = bs->bw_max - bs->bw_actual;

	if (
		!(bs->flags & BS_F_FROZEN_SLOT) &&
		available > BW_SLOT_MIN &&
		(bio->flags & BIO_F_ACTIVE)
	) {
		gint slot = available / bs->count;

		/*
		 * It's not worth redistributing less than BW_SLOT_MIN bytes per slot.
		 * If we ever drop below that value, freeze the slot value to prevent
		 * further redistribution.
		 */

		if (slot > BW_SLOT_MIN) {
			bsched_clear_active(bs);
			bs->bw_slot = slot;
		} else {
			bs->flags |= BS_F_FROZEN_SLOT;
			bs->bw_slot = BW_SLOT_MIN;
		}
	}

	/*
	 * If nothing is available, disable all sources.
	 */

	if (available <= 0) {
		bsched_no_more_bandwidth(bs);
		available = 0;
	}

	return MIN(bs->bw_slot, available);
}

/*
 * bsched_bw_update
 *
 * Update bandwidth used, and scheduler statistics.
 * If no more bandwidth is available, disable all sources.
 *
 * `used' is the amount of bytes used by the I/O.
 */
static void bsched_bw_update(bsched_t *bs, gint used)
{
	g_assert(bs);		/* Ensure I/O source was in alive scheduler */

	/*
	 * Even when the scheduler is disabled, update the actual bandwidth used
	 * for the statistics and the GUI display.
	 */

	bs->bw_actual += used;

	if (!(bs->flags & BS_F_ENABLED))		/* Scheduler disabled */
		return;								/* Nothing to update */

	/*
	 * When all bandwidth has been used, disable all sources.
	 */

	if (bs->bw_actual >= bs->bw_max)
		bsched_no_more_bandwidth(bs);
}

/*
 * bio_write
 *
 * Write at most `len' bytes from `buf' to source's fd, as bandwidth permits.
 * If we cannot write anything due to bandwidth constraints, return -1 with
 * errno set to EAGAIN.
 */
gint bio_write(bio_source_t *bio, gpointer data, gint len)
{
	gint available;
	gint amount;
	gint r;

	g_assert(bio);
	g_assert(bio->flags & BIO_F_WRITE);

	/* 
	 * If we don't have any bandwidth, return -1 with errno set to EAGAIN 
	 * to signal that we cannot perform any I/O right now.
	 */

	available = bw_available(bio, len);

	if (available == 0) {
		errno = EAGAIN;
		return -1;
	}

	amount = len > available ? available : len;

	if (dbg > 7)
		printf("bsched_write(fd=%d, len=%d) available=%d\n",
			bio->fd, len, available);

	bio->flags |= BIO_F_ACTIVE;
	r = write(bio->fd, data, amount);

	if (r > 0) {
		bsched_bw_update(bio->bs, r);
		bio->bw_actual += r;
	}

	return r;
}

/*
 * bio_sendfile
 *
 * Write at most `len' bytes to source's fd, as bandwidth permits.
 * Bytes are read from `offset' in the in_fd file descriptor, and the value
 * is updated in place by the kernel.
 *
 * If we cannot write anything due to bandwidth constraints, return -1 with
 * errno set to EAGAIN.
 */
gint bio_sendfile(bio_source_t *bio, gint in_fd, off_t *offset, gint len)
{
#ifndef HAVE_SENDFILE_H
	g_error("missing sendfile(2), should not have been called");
	return EOPNOTSUPP;		/* g_error() is fatal, just shut warnings */
#else
	gint available;
	gint amount;
	gint r;

	g_assert(bio);
	g_assert(bio->flags & BIO_F_WRITE);

	/* 
	 * If we don't have any bandwidth, return -1 with errno set to EAGAIN 
	 * to signal that we cannot perform any I/O right now.
	 */

	available = bw_available(bio, len);

	if (available == 0) {
		errno = EAGAIN;
		return -1;
	}

	amount = len > available ? available : len;

	if (dbg > 7)
		printf("bsched_write(fd=%d, len=%d) available=%d\n",
			bio->fd, len, available);

	bio->flags |= BIO_F_ACTIVE;
	r = sendfile(bio->fd, in_fd, offset, amount);

	if (r > 0) {
		bsched_bw_update(bio->bs, r);
		bio->bw_actual += r;
	}

	return r;
#endif	/* HAVE_SENDFILE_H */
}

/*
 * bio_read
 *
 * Read at most `len' bytes from `buf' from source's fd, as bandwidth permits.
 * If we cannot read anything due to bandwidth constraints, return -1 with
 * errno set to EAGAIN.
 */
gint bio_read(bio_source_t *bio, gpointer data, gint len)
{
	gint available;
	gint amount;
	gint r;

	g_assert(bio);
	g_assert(bio->flags & BIO_F_READ);

	/* 
	 * If we don't have any bandwidth, return -1 with errno set to EAGAIN 
	 * to signal that we cannot perform any I/O right now.
	 */

	available = bw_available(bio, len);

	if (available == 0) {
		errno = EAGAIN;
		return -1;
	}

	amount = len > available ? available : len;

	if (dbg > 7)
		printf("bsched_read(fd=%d, len=%d) available=%d\n",
			bio->fd, len, available);

	bio->flags |= BIO_F_ACTIVE;
	r = read(bio->fd, data, amount);

	if (r > 0) {
		bsched_bw_update(bio->bs, r);
		bio->bw_actual += r;
	}

	return r;
}

/*
 * bws_write
 *
 * Write at most `len' bytes from `buf' to specified fd, and account the
 * bandwidth used.  Any overused bandwidth will be tracked, so that on
 * average, we stick to the requested bandwidth rate.
 */
gint bws_write(bsched_t *bs, gint fd, gpointer data, gint len)
{
	gint r;

	g_assert(bs);
	g_assert(bs->flags & BS_F_WRITE);

	r = write(fd, data, len);

	if (r > 0)
		bsched_bw_update(bs, r);

	return r;
}

/*
 * bws_read
 *
 * Read at most `len' bytes from `buf' from specified fd, and account the
 * bandwidth used.  Any overused bandwidth will be tracked, so that on
 * average, we stick to the requested bandwidth rate.
 */
gint bws_read(bsched_t *bs, gint fd, gpointer data, gint len)
{
	gint r;

	g_assert(bs);
	g_assert(bs->flags & BS_F_READ);

	r = read(fd, data, len);

	if (r > 0)
		bsched_bw_update(bs, r);

	return r;
}

/*
 * bsched_heartbeat
 *
 * Periodic heartbeat.
 */
static void bsched_heartbeat(bsched_t *bs, struct timeval *tv)
{
	gint delay;
	gint overused;
	gint theoric;
	gint correction;

	/*
	 * How much time elapsed since last call?
	 */

	delay = (gint) ((tv->tv_sec - bs->last_period.tv_sec) * 1000 +
		(tv->tv_usec - bs->last_period.tv_usec) / 1000);

	bs->last_period = *tv;		/* struct copy */

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
		g_warning("periodic timer (%s) noticed time jumped backwards (~%d ms)",
			bs->name, bs->period - delay);
		delay = bs->period;
	} else if (delay > bs->max_period) {
		g_warning("periodic timer (%s) noticed time jumped forwards (~%d ms)",
			bs->name, delay - bs->period);
		delay = bs->period;
	}

	g_assert(delay > 0);

	/*
	 * Exponential Moving Average (EMA) with smoothing factor sm=1/4.
	 * Since usually one uses sm=2/(n+1), it's a moving average with n=7.
	 *
	 *      EMA(n+1) = sm*x(n) + (1-sm)*EMA(n)
	 */

	bs->period_ema += (delay >> 2) - (bs->period_ema >> 2);
	bs->bw_ema += (bs->bw_actual >> 2) - (bs->bw_ema >> 2);

	g_assert(bs->period_ema >= 0);
	g_assert(bs->bw_ema >= 0);

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

	theoric = bs->bw_per_second * delay / 1000;
	overused = bs->bw_actual - theoric;
	bs->bw_delta += overused;

	bs->bw_max = bs->bw_per_second * bs->period_ema / 1000;

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

	correction = bs->bw_ema - theoric;		/* This is the overused "EMA" */
	correction = MAX(correction, overused);

	if (correction > 0 && !(bs->flags & BS_F_CHANGED_BW)) {
		bs->bw_max -= correction;
		if (bs->bw_max < 0)
			bs->bw_max = 0;
	}

	if (bs->count)
		bs->bw_slot = bs->bw_max / bs->count;
	else
		bs->bw_slot = 0;

	if (dbg > 4) {
		printf("bsched_timer(%s): delay=%d (EMA=%d), b/w=%d (EMA=%d), "
			"overused=%d (EMA = %d)\n",
			bs->name, delay, bs->period_ema, bs->bw_actual, bs->bw_ema,
			overused, bs->bw_ema - theoric);
		printf("    -> b/w delta=%d, max=%d, slot=%d "
			"(target %d B/s, %d slot%s, real %.02f B/s)\n",
			bs->bw_delta, bs->bw_max, bs->bw_slot, bs->bw_per_second, bs->count,
			bs->count == 1 ? "" : "s", bs->bw_actual * 1000.0 / delay);
	}

	/*
	 * Reset running counters, and re-enable all sources.
	 */

new_timeslice:

	bs->bw_last_period = bs->bw_actual;
	bs->bw_actual = 0;
	bsched_begin_timeslice(bs);
}

/*
 * bsched_timer
 *
 * Periodic timer.
 */
void bsched_timer(void)
{
	struct timezone tz;
	struct timeval tv;

	(void) gettimeofday(&tv, &tz);

	bsched_heartbeat(bws_out, &tv);
	bsched_heartbeat(bws_in, &tv);
}

