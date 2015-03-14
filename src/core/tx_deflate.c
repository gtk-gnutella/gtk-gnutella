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
 * Network driver -- compressing level.
 *
 * This driver compresses its data stream before sending it to the link layer.
 *
 * @author Raphael Manfredi
 * @date 2002-2003
 */

#include "common.h"

#include <zlib.h>

#include "tx.h"
#include "tx_deflate.h"
#include "hosts.h"
#include "sockets.h"

#include "if/gnet_property_priv.h"

#include "lib/cq.h"
#include "lib/endian.h"
#include "lib/mempcpy.h"
#include "lib/tm.h"
#include "lib/walloc.h"
#include "lib/zlib_util.h"

#include "lib/override.h"		/* Must be the last header included */

/*
 * The driver manages two fixed-size buffers: one is being filled by the
 * compressing algorithm whilst the second is being sent on the network.
 * When there is no more room in either buffer, we flow control the upper
 * layer.  We leave the flow-control state when the buffer being sent has
 * been completely flushed.
 *
 * The write pointer is used when writing into the buffer.  The read pointer
 * is used when the data written into the buffer are read to be sent to the
 * lower layer.
 */

#define BUFFER_COUNT	2
#define BUFFER_NAGLE	500		/**< 500 ms */
#define BUFFER_DELAY	2		/**< 2 secs -- max Nagle delay */

struct buffer {
	char *arena;				/**< Buffer arena */
	char *end;					/**< First byte outside buffer */
	char *wptr;				/**< Write pointer (first byte to write) */
	char *rptr;				/**< Read pointer (first byte to read) */
};

/*
 * Private attributes for the link.
 */
struct attr {
	struct buffer buf[BUFFER_COUNT];
	size_t buffer_size;			/**< Buffer size used */
	size_t buffer_flush;		/**< Flush after that many bytes */
	double ratio;				/**< Overall compression ratio */
	double ratio_ema;			/**< EMA of compression ratio */
	int fill_idx;				/**< Filled buffer index */
	int send_idx;				/**< Buffer to be sent */
	z_streamp outz;				/**< Compressing stream */
	txdrv_t *nd;				/**< Network driver, underneath us */
	size_t unflushed;			/**< Amount of input bytes since last flush */
	size_t flushed;				/**< Amount of output bytes since last flush */
	size_t total_input;			/**< Total amount of input bytes flushed */
	size_t total_output;		/**< Total amount of output bytes flushed */
	int flags;					/**< Operating flags */
	cqueue_t *cq;				/**< The callout queue to use for Nagle */
	cevent_t *tm_ev;			/**< The timer event */
	const struct tx_deflate_cb *cb;	/**< Layer-specific callbacks */
	tx_closed_t closed;			/**< Callback to invoke when layer closed */
	void *closed_arg;			/**< Argument for closing routine */
	time_t nagle_start;			/**< When we started the Nagle timer */
	struct {
		bool		enabled;	/**< Whether to use gzip encapsulation */
		uint32		size;		/**< Payload size counter for gzip */
		uLong		crc;		/**< CRC-32 accumlator for gzip */
	} gzip;
	unsigned nagle:1;			/**< Whether to use Nagle or not */
};

/*
 * Operating flags.
 */

#define DF_FLOWC		0x00000001	/**< We flow-controlled the upper layer */
#define DF_NAGLE		0x00000002	/**< Nagle timer started */
#define DF_FLUSH		0x00000004	/**< Flushing started */
#define DF_SHUTDOWN		0x00000008	/**< Stack has shut down */

static void deflate_nagle_timeout(cqueue_t *cq, void *arg);
static size_t tx_deflate_pending(txdrv_t *tx);

#define tx_deflate_debugging(lvl) \
	G_UNLIKELY(GNET_PROPERTY(tx_deflate_debug) > (lvl) && \
		tx_debug_host(&tx->host))

/**
 * Write ready-to-be-sent buffer to the lower layer.
 */
static void
deflate_send(txdrv_t *tx)
{
	struct attr *attr = tx->opaque;
	struct buffer *b;
	size_t len;					/**< Amount of bytes to send */
	ssize_t r;

	g_assert(attr->send_idx >= 0);	/* We have something to send */
	g_assert(attr->send_idx < BUFFER_COUNT);

	/*
	 * Compute data to be sent.
	 */

	b = &attr->buf[attr->send_idx];		/* Buffer to send */
	len = b->wptr - b->rptr;

	g_assert(len > 0 && len <= INT_MAX);

	/*
	 * Write as much as possible.
	 */

	r = tx_write(tx->lower, b->rptr, len);

	if (tx_deflate_debugging(9)) {
		g_debug("TX %s: (%s) wrote %zu/%zu bytes (buffer #%d) [%c%c]",
			G_STRFUNC, gnet_host_to_string(&tx->host), r, len, attr->send_idx,
			(attr->flags & DF_FLOWC) ? 'C' : '-',
			(attr->flags & DF_FLUSH) ? 'f' : '-');
	}
	if ((ssize_t) -1 == r) {
		tx_error(tx);
		return;
	}

	/*
	 * If we wrote everything, we're done.
	 */

	if ((size_t) r == len) {
		if (tx_deflate_debugging(9)) {
			g_debug("TX %s: (%s) buffer #%d is empty",
				G_STRFUNC, gnet_host_to_string(&tx->host), attr->send_idx);
		}
		attr->send_idx = -1;			/* Signals: is now free */
		b->wptr = b->rptr = b->arena;	/* Buffer is now empty */
		return;
	}

	/*
	 * We were unable to send the whole buffer.  Enable servicing when
	 * the lower layer will be ready for more input.
	 */

	b->rptr += r;

	g_assert(b->rptr < b->wptr);		/* We haven't written everything */

	tx_srv_enable(tx->lower);
}

/**
 * Start the nagle timer.
 */
static void
deflate_nagle_start(txdrv_t *tx)
{
	struct attr *attr = tx->opaque;

	g_assert(!(attr->flags & DF_NAGLE));
	g_assert(NULL == attr->tm_ev);

	if (!attr->nagle)					/* Nagle not allowed */
		return;

	attr->tm_ev = cq_insert(attr->cq, BUFFER_NAGLE, deflate_nagle_timeout, tx);
	attr->flags |= DF_NAGLE;
	attr->nagle_start = tm_time();
}

/**
 * Delay the nagle timer when more data is coming.
 */
static void
deflate_nagle_delay(txdrv_t *tx)
{
	struct attr *attr = tx->opaque;

	g_assert(attr->flags & DF_NAGLE);
	g_assert(NULL != attr->tm_ev);
	g_assert(attr->nagle);				/* Nagle is allowed */

	/*
	 * We push back the initial delay a little while when more data comes,
	 * hoping that enough will be output so that we end up sending the TX
	 * buffer without having to trigger a flush too soon, since that would
	 * degrade compression performance.
	 *
	 * If too much time elapsed since the Nagle timer started, do not
	 * postpone the flush otherwise we might delay time-sensitive messages.
	 */

	if (delta_time(tm_time(), attr->nagle_start) < BUFFER_DELAY) {
		int delay = cq_remaining(attr->tm_ev);
		cq_resched(attr->tm_ev, MAX(delay, BUFFER_NAGLE / 2));
	}
}

/**
 * Stop the nagle timer.
 */
static void
deflate_nagle_stop(txdrv_t *tx)
{
	struct attr *attr = tx->opaque;

	g_assert(attr->flags & DF_NAGLE);
	g_assert(NULL != attr->tm_ev);

	cq_cancel(&attr->tm_ev);
	attr->flags &= ~DF_NAGLE;
}

/**
 * Make the "filling buffer" the buffer to send, and rotate filling buffers.
 * Attempt to write the new send buffer immediately.
 */
static void
deflate_rotate_and_send(txdrv_t *tx)
{
	struct attr *attr = tx->opaque;

	g_assert(-1 == attr->send_idx);		/* No pending send */

	/*
	 * Cancel any pending Nagle timer.
	 */

	if (attr->flags & DF_NAGLE)
		deflate_nagle_stop(tx);

	/*
	 * The buffer to send is the one we filled.
	 */

	attr->send_idx = attr->fill_idx;
	attr->fill_idx++;
	if (attr->fill_idx >= BUFFER_COUNT)
		attr->fill_idx = 0;

	if (tx_deflate_debugging(9)) {
		g_debug("TX %s: (%s) fill buffer now #%d [%c%c]",
			G_STRFUNC, gnet_host_to_string(&tx->host), attr->fill_idx,
			(attr->flags & DF_FLOWC) ? 'C' : '-',
			(attr->flags & DF_FLUSH) ? 'f' : '-');
	}
	deflate_send(tx);
}

/**
 * Compute amount of buffered output data awaiting to be sent.
 */
static size_t
deflate_buffered(const txdrv_t *tx)
{
	const struct attr *attr = tx->opaque;
	const struct buffer *b;
	size_t buffered;

	b = &attr->buf[attr->fill_idx];	/* Buffer we fill */
	buffered = b->wptr - b->rptr;

	if (-1 != attr->send_idx) {
		b = &attr->buf[attr->send_idx];	/* Buffer we send */
		buffered += b->wptr - b->rptr;
	}

	return buffered;
}

/**
 * Enter or leave flow-control.
 */
static void
deflate_set_flowc(txdrv_t *tx, bool on)
{
	struct attr *attr = tx->opaque;

	if (on) {
		attr->flags |= DF_FLOWC;		/* Enter flow control */
	} else {
		attr->flags &= ~DF_FLOWC;		/* Leave flow control state */
	}

	if (tx_deflate_debugging(4)) {
		g_debug("TX %s: (%s) %s flow-control [%c%c]",
			G_STRFUNC, gnet_host_to_string(&tx->host),
			on ? "entering" : "leaving",
			(attr->flags & DF_FLOWC) ? 'C' : '-',
			(attr->flags & DF_FLUSH) ? 'f' : '-');
	}

	if (NULL != attr->cb->flow_control)
		attr->cb->flow_control(tx->owner, on ? deflate_buffered(tx) : 0);
}

/**
 * Pending data were all flushed.
 */
static void
deflate_flushed(txdrv_t *tx)
{
	struct attr *attr = tx->opaque;
	double flush = 0.0;

	g_assert(size_is_non_negative(attr->unflushed));

	attr->total_input += attr->unflushed;
	attr->total_output += attr->flushed;

	g_return_unless(attr->total_input != 0);

	attr->ratio = 1.0 - ((double) attr->total_output / attr->total_input);

	if (0 != attr->unflushed) {
		/*
		 * Fast EMA for compression ratio is computed for the last n=3 flushes,
		 * so the smoothing factor sm=2/(n+1) is 1/2.
		 */

		flush = 1.0 - ((double) attr->flushed / attr->unflushed);
		attr->ratio_ema += (flush / 2.0) - (attr->ratio_ema / 2.0);
	}

	if (tx_deflate_debugging(4)) {
		g_debug("TX %s: (%s) deflated %zu bytes into %zu "
			"(%.2f%%, EMA=%.2f%%, overall %.2f%%)",
			G_STRFUNC, gnet_host_to_string(&tx->host),
			attr->unflushed, attr->flushed,
			100 * flush, 100 * attr->ratio_ema, 100 * attr->ratio);
	}

	attr->unflushed = attr->flushed = 0;
	attr->flags &= ~DF_FLUSH;
}

/**
 * Flush compression within filling buffer.
 *
 * @return success status, failure meaning we shutdown.
 */
static bool
deflate_flush(txdrv_t *tx)
{
	struct attr *attr = tx->opaque;
	z_streamp outz = attr->outz;
	struct buffer *b;
	int ret;
	int old_avail;

retry:
	b = &attr->buf[attr->fill_idx];	/* Buffer we fill */

	if (tx_deflate_debugging(9)) {
		g_debug("TX %s: (%s) flushing %zu bytes "
			"(buffer #%d, flushed %zu, unflushed %zu) [%c%c]",
			G_STRFUNC, gnet_host_to_string(&tx->host),
			b->wptr - b->rptr, attr->fill_idx,
			attr->flushed, attr->unflushed,
			(attr->flags & DF_FLOWC) ? 'C' : '-',
			(attr->flags & DF_FLUSH) ? 'f' : '-');
	}

	/*
	 * Prepare call to deflate().
	 *
	 * We force avail_in to 0, and don't touch next_in: no input should
	 * be consumed.
	 */

	outz->next_out = cast_to_pointer(b->wptr);
	outz->avail_out = old_avail = b->end - b->wptr;

	outz->avail_in = 0;

	g_assert(outz->avail_out > 0);

	ret = deflate(outz, (tx->flags & TX_CLOSING) ? Z_FINISH : Z_SYNC_FLUSH);

	switch (ret) {
	case Z_BUF_ERROR:				/* Nothing to flush */
		goto done;
	case Z_OK:
	case Z_STREAM_END:
		break;
	default:
		attr->flags |= DF_SHUTDOWN;
		tx_error(tx);

		/* XXX: The callback must not destroy the tx! */
		(*attr->cb->shutdown)(tx->owner, "Compression flush failed: %s",
				zlib_strerror(ret));
		return FALSE;
	}

	{
		size_t written;

		written = old_avail - outz->avail_out;
		b->wptr += written;
		attr->flushed += written;

		if (NULL != attr->cb->add_tx_deflated)
			attr->cb->add_tx_deflated(tx->owner, written);
	}

	/*
	 * Check whether avail_out is 0.
	 *
	 * If it is, then we lacked room to complete the flush.  Try to send the
	 * buffer and continue.
	 */

	if (0 == outz->avail_out) {
		if (attr->send_idx >= 0) {			/* Send buffer not sent yet */
			attr->flags |= DF_FLUSH;		/* In flush mode */
			deflate_set_flowc(tx, TRUE);	/* Starting flow-control */
			return TRUE;
		}

		deflate_rotate_and_send(tx);		/* Can set TX_ERROR */

		if (tx->flags & TX_ERROR)
			return FALSE;

		goto retry;
	}

done:
	deflate_flushed(tx);

	return TRUE;		/* Fully flushed */
}

/**
 * Flush compression and send whatever we got so far.
 */
static void
deflate_flush_send(txdrv_t *tx)
{
	struct attr *attr = tx->opaque;

	/*
	 * During deflate_flush(), we can fill the current buffer, then call
	 * deflate_rotate_and_send() and finish the flush.  But it is possible
	 * that the whole send buffer does not get sent immediately.  Therefore,
	 * we need to recheck for attr->send_idx.
	 */

	if (deflate_flush(tx)) {
		if (-1 == attr->send_idx) {			/* No write pending */
			struct buffer *b = &attr->buf[attr->fill_idx];

			if (b->rptr != b->wptr)			/* Something to send */
				deflate_rotate_and_send(tx);
		}
	}
}

/**
 * Called from the callout queue when the Nagle timer expires.
 *
 * If we can send the buffer, flush it and send it.  Otherwise, reschedule.
 */
static void
deflate_nagle_timeout(cqueue_t *cq, void *arg)
{
	txdrv_t *tx = arg;
	struct attr *attr = tx->opaque;

	cq_zero(cq, &attr->tm_ev);

	if (-1 != attr->send_idx) {		/* Send buffer still incompletely sent */

		if (tx_deflate_debugging(9)) {
			g_debug("TX %s: (%s) buffer #%d unsent, exiting [%c%c]",
				G_STRFUNC, gnet_host_to_string(&tx->host), attr->send_idx,
				(attr->flags & DF_FLOWC) ? 'C' : '-',
				(attr->flags & DF_FLUSH) ? 'f' : '-');
		}

		attr->tm_ev =
			cq_insert(attr->cq, BUFFER_NAGLE, deflate_nagle_timeout, tx);
		return;
	}

	attr->flags &= ~DF_NAGLE;

	if (tx_deflate_debugging(9)) {
		struct buffer *b = &attr->buf[attr->fill_idx];	/* Buffer to send */
		g_debug("TX %s: (%s) flushing %zu bytes (buffer #%d) [%c%c]",
			G_STRFUNC, gnet_host_to_string(&tx->host),
			b->wptr - b->rptr, attr->fill_idx,
			(attr->flags & DF_FLOWC) ? 'C' : '-',
			(attr->flags & DF_FLUSH) ? 'f' : '-');
	}

	deflate_flush_send(tx);
}

/**
 * Compress as much data as possible to the output buffer, sending data
 * as we go along.
 *
 * @return the amount of input bytes that were consumed ("added"), -1 on error.
 */
static int
deflate_add(txdrv_t *tx, const void *data, int len)
{
	struct attr *attr = tx->opaque;
	z_streamp outz = attr->outz;
	int added = 0;

	if (tx_deflate_debugging(9)) {
		g_debug("TX %s: (%s) given %u bytes (buffer #%d, nagle %s, "
			"unflushed %zu) [%c%c]%s", G_STRFUNC,
			gnet_host_to_string(&tx->host), len, attr->fill_idx,
			(attr->flags & DF_NAGLE) ? "on" : "off", attr->unflushed,
			(attr->flags & DF_FLOWC) ? 'C' : '-',
			(attr->flags & DF_FLUSH) ? 'f' : '-',
			(tx->flags & TX_ERROR) ? " ERROR" : "");
	}

	/*
	 * If an error was already reported, the whole deflate stream is dead
	 * and we cannot accept any more data.
	 */

	if G_UNLIKELY(tx->flags & TX_ERROR)
		return -1;

	while (added < len) {
		struct buffer *b = &attr->buf[attr->fill_idx];	/* Buffer we fill */
		int ret;
		int old_added = added;
		bool flush_started = (attr->flags & DF_FLUSH) ? TRUE : FALSE;
		int old_avail;
		const char *in, *old_in;

		/*
		 * Prepare call to deflate().
		 */

		outz->next_out = cast_to_pointer(b->wptr);
		outz->avail_out = old_avail = b->end - b->wptr;

		in = data;
		old_in = &in[added];
		outz->next_in = deconstify_pointer(old_in);
		outz->avail_in = len - added;

		g_assert(outz->avail_out > 0);
		g_assert(outz->avail_in > 0);

		/*
		 * Compress data.
		 *
		 * If we previously started to flush, continue the operation, now
		 * that we have more room available for the output.
		 */

		ret = deflate(outz, flush_started ? Z_SYNC_FLUSH : 0);

		if (Z_OK != ret) {
			attr->flags |= DF_SHUTDOWN;
			(*attr->cb->shutdown)(tx->owner, "Compression failed: %s",
				zlib_strerror(ret));
			return -1;
		}

		/*
		 * Update the parameters.
		 */

		b->wptr = cast_to_pointer(outz->next_out);
		added = ptr_diff(outz->next_in, in);

		g_assert(added >= old_added);

		attr->unflushed += added - old_added;
		attr->flushed += old_avail - outz->avail_out;

		if (NULL != attr->cb->add_tx_deflated)
			attr->cb->add_tx_deflated(tx->owner, old_avail - outz->avail_out);

		if (attr->gzip.enabled) {
			size_t r;

			r = ptr_diff(outz->next_in, old_in);
			attr->gzip.size += r;
			attr->gzip.crc = crc32(attr->gzip.crc,
								cast_to_constpointer(old_in), r);
		}

		if (tx_deflate_debugging(9)) {
			g_debug("TX %s: (%s) deflated %d bytes into %d "
				"(buffer #%d, nagle %s, flushed %zu, unflushed %zu) [%c%c]",
				G_STRFUNC, gnet_host_to_string(&tx->host),
				added, old_avail - outz->avail_out, attr->fill_idx,
				(attr->flags & DF_NAGLE) ? "on" : "off",
				attr->flushed, attr->unflushed,
				(attr->flags & DF_FLOWC) ? 'C' : '-',
				(attr->flags & DF_FLUSH) ? 'f' : '-');
		}

		/*
		 * If we filled the output buffer, check whether we have a pending
		 * send buffer.  If we do, we cannot process more data.  Otherwise
		 * send it now and continue.
		 */

		if (0 == outz->avail_out) {
			if (attr->send_idx >= 0) {
				deflate_set_flowc(tx, TRUE);	/* Enter flow control */
				return added;
			}

			deflate_rotate_and_send(tx);		/* Can set TX_ERROR */

			if (tx->flags & TX_ERROR)
				return -1;
		}

		/*
		 * If we were flushing and we consumed all the input, then
		 * the flush is done and we're starting normal compression again.
		 *
		 * This must be done after we made sure that we had enough output
		 * space avaialable.
		 */

		if (flush_started && 0 == outz->avail_in)
			deflate_flushed(tx);
	}

	g_assert(0 == outz->avail_in);

	/*
	 * Start Nagle if not already on.
	 */

	if (attr->flags & DF_NAGLE)
		deflate_nagle_delay(tx);
	else
		deflate_nagle_start(tx);

	/*
	 * We're going to ask for a flush if not already started yet and the
	 * amount of bytes we have written since the last flush is greater
	 * than attr->buffer_flush.
	 */

	if (attr->unflushed > attr->buffer_flush) {
		if (!deflate_flush(tx))
			return -1;
	}

	return added;
}

/**
 * Service routine for the compressing stage.
 *
 * Called by lower layer when it is ready to process more data.
 */
static void
deflate_service(void *data)
{
	txdrv_t *tx = data;
	struct attr *attr = tx->opaque;
	struct buffer *b;

	g_assert(attr->send_idx < BUFFER_COUNT);

	if (tx_deflate_debugging(9)) {
		g_debug("TX %s: (%s) %s(buffer #%d, %zu bytes held) [%c%c]",
			G_STRFUNC, gnet_host_to_string(&tx->host),
			(tx->flags & TX_ERROR) ? "ERROR " : "",
			attr->send_idx,
			attr->send_idx >= 0 ?
				(attr->buf[attr->send_idx].wptr -
					attr->buf[attr->send_idx].rptr) : 0,
			(attr->flags & DF_FLOWC) ? 'C' : '-',
			(attr->flags & DF_FLUSH) ? 'f' : '-');
	}
	/*
	 * First, attempt to transmit the whole send buffer, if any pending.
	 */

	if (attr->send_idx >= 0)
		deflate_send(tx);			/* Send buffer `send_idx' */

	if (attr->send_idx >= 0)		/* Could not send it entirely */
		return;						/* Done, servicing still enabled */

	/*
	 * NB: In the following operations, order matters.  In particular, we
	 * must disable the servicing before attempting to service the upper
	 * layer, since the data it will send us can cause us to flow control
	 * and re-enable the servicing.
	 *
	 * If the `fill' buffer is full, try to send it now.
	 */

	b = &attr->buf[attr->fill_idx];	/* Buffer we fill */

	if (b->wptr >= b->end) {
		if (tx_deflate_debugging(9)) {
			g_debug("TX %s: (%s) sending fill buffer #%d, %zu bytes",
				G_STRFUNC, gnet_host_to_string(&tx->host), attr->fill_idx,
				b->wptr - b->rptr);
		}
		deflate_rotate_and_send(tx);	/* Can set TX_ERROR */

		if (tx->flags & TX_ERROR)
			return;
	}

	/*
	 * If we were able to send the whole send buffer, disable servicing.
	 */

	if (-1 == attr->send_idx)
		tx_srv_disable(tx->lower);

	/*
	 * If we entered flow control, we can now safely leave it, since we
	 * have at least a free `fill' buffer.
	 */

	if (attr->flags & DF_FLOWC)
		deflate_set_flowc(tx, FALSE);	/* Leave flow control state */

	/*
	 * If closing, we're done once we have flushed everything we could.
	 * There's no need to even bother with the upper layer: if we're
	 * closing, we won't accept any further data to write anyway.
	 */

	if (tx->flags & TX_CLOSING) {
		deflate_flush_send(tx);

		if (tx->flags & TX_ERROR)
			return;

		if (0 == tx_deflate_pending(tx)) {
			(*attr->closed)(tx, attr->closed_arg);
			return;
		}
	}

	if (tx_deflate_debugging(9)) {
		g_debug("TX %s: (%s) %sdone locally [%c%c]",
			G_STRFUNC, gnet_host_to_string(&tx->host),
			(tx->flags & TX_ERROR) ? "ERROR " : "",
			(attr->flags & DF_FLOWC) ? 'C' : '-',
			(attr->flags & DF_FLUSH) ? 'f' : '-');
	}

	/*
	 * If upper layer wants servicing, do it now.
	 * Note that this can put us back into flow control.
	 */

	if (tx->flags & TX_SERVICE) {
		g_assert(tx->srv_routine);
		tx->srv_routine(tx->srv_arg);
	}
}

/***
 *** Polymorphic routines.
 ***/

/**
 * Initialize the driver.
 *
 * @return NULL if there is an initialization problem.
 */
static void *
tx_deflate_init(txdrv_t *tx, void *args)
{
	struct attr *attr;
	struct tx_deflate_args *targs = args;
	z_streamp outz;
	int ret;
	int i;

	g_assert(tx);
	g_assert(NULL != targs->cb);

	WALLOC(outz);
	outz->zalloc = zlib_alloc_func;
	outz->zfree = zlib_free_func;
	outz->opaque = NULL;

	/*
	 * Reduce memory requirements for deflation when running as an ultrapeer.
	 *
	 * Memory used for deflation is:
	 *
	 *	(1 << (window_bits +2)) +  (1 << (mem_level + 9))
	 *
	 * For leaves, we use window_bits = 15 and mem_level = 9, which makes
	 * for 128 KiB + 256 KiB = 384 KiB per connection (TX side).
	 *
	 * For ultra peers, we use window_bits = 14 and mem_level = 6, so this
	 * uses 64 KiB + 32 KiB = 96 KiB only.
	 *
	 * Since ultra peers have many more connections than leaves, the memory
	 * savings are drastic, yet compression levels remain around 50% (varies
	 * depending on the nature of the traffic, of course).
	 *
	 *		--RAM, 2009-04-09
	 *
	 * For Ultra <-> Ultra connections we use window_bits = 15 and mem_level = 9
	 * and request a best compression because the amount of ultra connections
	 * is far less than the number of leaf connections and modern machines
	 * can cope with a "best" compression overhead.
	 *
	 * This is now controlled with the "reduced" argument, so this layer does
	 * not need to know whether we're an ultra node or even what an ultra
	 * node is... It just knows whether we have to setup a fully compressed
	 * connection or a reduced one (both in terms of memory usage and level
	 * of compression).
	 *
	 *		--RAM, 2011-11-29
	 */

	{
		int window_bits = MAX_WBITS;		/* Must be 8 .. MAX_WBITS */
		int mem_level = MAX_MEM_LEVEL;		/* Must be 1 .. MAX_MEM_LEVEL */
		int level = Z_BEST_COMPRESSION;

		if (targs->reduced) {
			/* Ultra -> Leaf connection */
			window_bits = 14;
			mem_level = 6;
			level = Z_DEFAULT_COMPRESSION;
		}

		g_assert(window_bits >= 8 && window_bits <= MAX_WBITS);
		g_assert(mem_level >= 1 && mem_level <= MAX_MEM_LEVEL);
		g_assert(level == Z_DEFAULT_COMPRESSION ||
			(level >= Z_BEST_SPEED && level <= Z_BEST_COMPRESSION));

		ret = deflateInit2(outz, level, Z_DEFLATED,
				targs->gzip ? (-window_bits) : window_bits, mem_level,
				Z_DEFAULT_STRATEGY);
	}

	if (Z_OK != ret) {
		g_warning("unable to initialize compressor for peer %s: %s",
			gnet_host_to_string(&tx->host), zlib_strerror(ret));
		WFREE(outz);
		return NULL;
	}

	WALLOC0(attr);
	attr->cq = targs->cq;
	attr->cb = targs->cb;
	attr->buffer_size = targs->buffer_size;
	attr->buffer_flush = targs->buffer_flush;
	attr->nagle = booleanize(targs->nagle);
	attr->gzip.enabled = targs->gzip;

	attr->outz = outz;
	attr->tm_ev = NULL;

	for (i = 0; i < BUFFER_COUNT; i++) {
		struct buffer *b = &attr->buf[i];

		b->arena = b->wptr = b->rptr = walloc(attr->buffer_size);
		b->end = &b->arena[attr->buffer_size];
	}

	attr->fill_idx = 0;
	attr->send_idx = -1;		/* Signals: none ready */

	if (attr->gzip.enabled) {
		/* See RFC 1952 - GZIP file format specification version 4.3 */
		static const unsigned char header[] = {
			0x1f, 0x8b, /* gzip magic */
			0x08,		/* compression method: deflate */
			0,			/* flags: none */
			0, 0, 0, 0, /* modification time: unavailable */
			0,			/* extra flags: none */
			0xff,		/* filesystem: unknown */
		};
		struct buffer *b;

		b = &attr->buf[attr->fill_idx];	/* Buffer we fill */
		g_assert(sizeof header <= (size_t) (b->end - b->wptr));
		b->wptr = mempcpy(b->wptr, header, sizeof header);

		attr->gzip.crc = crc32(0, NULL, 0);
		attr->gzip.size = 0;
	}

	tx->opaque = attr;

	/*
	 * Register our service routine to the lower layer.
	 */

	tx_srv_register(tx->lower, deflate_service, tx);

	return tx;		/* OK */
}

/**
 * Get rid of the driver's private data.
 */
static void
tx_deflate_destroy(txdrv_t *tx)
{
	struct attr *attr = tx->opaque;
	int i;
	int ret;

	g_assert(attr->outz);

	for (i = 0; i < BUFFER_COUNT; i++) {
		struct buffer *b = &attr->buf[i];
		wfree(b->arena, attr->buffer_size);
	}

	/*
	 * We ignore Z_DATA_ERROR errors (discarded data, probably).
	 */

	ret = deflateEnd(attr->outz);

	if (Z_OK != ret && Z_DATA_ERROR != ret)
		g_warning("while freeing compressor for peer %s: %s",
			gnet_host_to_string(&tx->host), zlib_strerror(ret));

	WFREE(attr->outz);
	cq_cancel(&attr->tm_ev);
	WFREE(attr);
}

/**
 * Write data buffer.
 *
 * @return amount of bytes written, or -1 on error.
 */
static ssize_t
tx_deflate_write(txdrv_t *tx, const void *data, size_t len)
{
	struct attr *attr = tx->opaque;

	if (tx_deflate_debugging(9)) {
		g_debug("TX %s: (%s) (buffer #%d, nagle %s, unflushed %zu) [%c%c]",
			G_STRFUNC, gnet_host_to_string(&tx->host), attr->fill_idx,
			(attr->flags & DF_NAGLE) ? "on" : "off", attr->unflushed,
			(attr->flags & DF_FLOWC) ? 'C' : '-',
			(attr->flags & DF_FLUSH) ? 'f' : '-');
	}
	/*
	 * If we're flow controlled or shut down, don't accept anything.
	 */

	if (attr->flags & (DF_FLOWC|DF_SHUTDOWN))
		return 0;

	return deflate_add(tx, data, len);
}

/**
 * Write I/O vector.
 *
 * @return amount of bytes written, or -1 on error.
 */
static ssize_t
tx_deflate_writev(txdrv_t *tx, iovec_t *iov, int iovcnt)
{
	struct attr *attr = tx->opaque;
	int sent = 0;

	if (tx_deflate_debugging(9)) {
		g_debug("TX %s: (%s) (buffer #%d, nagle %s, unflushed %zu) [%c%c]",
			G_STRFUNC, gnet_host_to_string(&tx->host), attr->fill_idx,
			(attr->flags & DF_NAGLE) ? "on" : "off", attr->unflushed,
			(attr->flags & DF_FLOWC) ? 'C' : '-',
			(attr->flags & DF_FLUSH) ? 'f' : '-');
	}

	while (iovcnt-- > 0) {
		int ret;

		/*
		 * If we're flow controlled or shut down, stop sending.
		 */

		if (attr->flags & (DF_FLOWC|DF_SHUTDOWN))
			break;

		ret = deflate_add(tx, iovec_base(iov), iovec_len(iov));

		if (-1 == ret)
			return -1;

		sent += ret;
		if (UNSIGNED(ret) < iovec_len(iov)) {
			/* Could not write all, flow-controlled */
			break;
		}
		iov++;
	}

	if (tx_deflate_debugging(9)) {
		g_debug("TX %s: (%s) sent %lu bytes (buffer #%d, nagle %s, "
			"unflushed %zu) [%c%c]", G_STRFUNC,
			gnet_host_to_string(&tx->host), (ulong) sent, attr->fill_idx,
			(attr->flags & DF_NAGLE) ? "on" : "off", attr->unflushed,
			(attr->flags & DF_FLOWC) ? 'C' : '-',
			(attr->flags & DF_FLUSH) ? 'f' : '-');
	}
	return sent;
}

/**
 * Allow servicing of upper TX queue.
 */
static void
tx_deflate_enable(txdrv_t *unused_tx)
{
	/* Nothing specific */
	(void) unused_tx;
}

/**
 * Disable servicing of upper TX queue.
 */
static void
tx_deflate_disable(txdrv_t *unused_tx)
{
	/* Nothing specific */
	(void) unused_tx;
}

/**
 * @return the amount of data buffered locally.
 */
static size_t
tx_deflate_pending(txdrv_t *tx)
{
	const struct attr *attr = tx->opaque;
	size_t pending;

	pending = deflate_buffered(tx);

	/*
	 * Account for deflation of pending bytes, using the current compression
	 * ratio (EMA) to estimate how much we're going to emit.
	 */

	if (attr->unflushed != 0) {
		size_t projected = attr->unflushed * (1.0 - attr->ratio_ema);
		pending += attr->flushed >= projected ? 1 : projected - attr->flushed;
	}

	return pending;
}

/**
 * Trigger the Nagle timeout immediately, if registered.
 */
static void
tx_deflate_flush(txdrv_t *tx)
{
	struct attr *attr = tx->opaque;

	if (attr->flags & DF_NAGLE) {
		g_assert(NULL != attr->tm_ev);
		cq_expire(attr->tm_ev);
	} else if (!(attr->flags & DF_FLOWC))
		deflate_flush_send(tx);
}

/**
 * Disable all transmission.
 */
static void
tx_deflate_shutdown(txdrv_t *tx)
{
	struct attr *attr = tx->opaque;

	/*
	 * Disable firing of the Nagle callback, if registered.
	 */

	if (attr->flags & DF_NAGLE)
		deflate_nagle_stop(tx);
}

/**
 * Close the layer, flushing all the data there is.
 * Once this is done, invoke the supplied callback.
 */
static void
tx_deflate_close(txdrv_t *tx, tx_closed_t cb, void *arg)
{
	struct attr *attr = tx->opaque;

	g_assert(tx->flags & TX_CLOSING);

	if (tx_deflate_debugging(9)) {
		g_debug("TX %s: (%s) send=%d buffer #%d, nagle %s, "
			"unflushed %zu) [%c%c]", G_STRFUNC,
			gnet_host_to_string(&tx->host), attr->send_idx, attr->fill_idx,
			(attr->flags & DF_NAGLE) ? "on" : "off", attr->unflushed,
			(attr->flags & DF_FLOWC) ? 'C' : '-',
			(attr->flags & DF_FLUSH) ? 'f' : '-');
	}

	/*
	 * Flush whatever we can.
	 */

	tx_deflate_flush(tx);

	if (attr->gzip.enabled && 0 == tx_deflate_pending(tx)) {
		/* See RFC 1952 - GZIP file format specification version 4.3 */
		struct buffer *b;
		uint32 trailer[2]; /* 0: CRC32, 1: SIZE % (1 << 32) */

		/* We don't want to send the trailer more than once */
		attr->gzip.enabled = FALSE;

		attr->send_idx = 0;
		b = &attr->buf[attr->send_idx];
		poke_le32(&trailer[0], (uint32) attr->gzip.crc);
		poke_le32(&trailer[1], attr->gzip.size);

		g_assert(sizeof trailer <= (size_t) (b->end - b->wptr));
		b->wptr = mempcpy(b->wptr, trailer, sizeof trailer);

		deflate_send(tx);
	}

	if (0 == tx_deflate_pending(tx)) {
		if (tx_deflate_debugging(9)) {
			g_debug("TX %s: flushed everything immediately", G_STRFUNC);
		}
		(*cb)(tx, arg);
		return;
	}

	/*
	 * We were unable to flush everything.
	 */

	attr->closed = cb;
	attr->closed_arg = arg;

	if (tx_deflate_debugging(9)) {
		g_debug("TX %s: (%s) delayed! send=%d buffer #%d, nagle %s, "
			"flushed %zu, unflushed %zu) [%c%c]",
			G_STRFUNC, gnet_host_to_string(&tx->host),
			attr->send_idx, attr->fill_idx,
			(attr->flags & DF_NAGLE) ? "on" : "off",
			attr->flushed, attr->unflushed,
			(attr->flags & DF_FLOWC) ? 'C' : '-',
			(attr->flags & DF_FLUSH) ? 'f' : '-');
	}
}

static const struct txdrv_ops tx_deflate_ops = {
	"deflate",				/**< name */
	tx_deflate_init,		/**< init */
	tx_deflate_destroy,		/**< destroy */
	tx_deflate_write,		/**< write */
	tx_deflate_writev,		/**< writev */
	tx_no_sendto,			/**< sendto */
	tx_deflate_enable,		/**< enable */
	tx_deflate_disable,		/**< disable */
	tx_deflate_pending,		/**< pending */
	tx_deflate_flush,		/**< flush */
	tx_deflate_shutdown,	/**< shutdown */
	tx_deflate_close,		/**< close */
	tx_no_source,			/**< bio_source */
};

const struct txdrv_ops *
tx_deflate_get_ops(void)
{
	return &tx_deflate_ops;
}

/* vi: set ts=4 sw=4 cindent: */
