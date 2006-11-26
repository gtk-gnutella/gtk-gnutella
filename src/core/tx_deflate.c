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
 * Network driver -- compressing level.
 *
 * This driver compresses its data stream before sending it to the link layer.
 *
 * @author Raphael Manfredi
 * @date 2002-2003
 */

#include "common.h"

RCSID("$Id$")

#include <zlib.h>

#include "sockets.h"
#include "hosts.h"
#include "tx.h"
#include "tx_deflate.h"

#include "if/gnet_property_priv.h"

#include "lib/endian.h"
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
#define BUFFER_NAGLE	200		/**< 200 ms */

struct buffer {
	gchar *arena;				/**< Buffer arena */
	gchar *end;					/**< First byte outside buffer */
	gchar *wptr;				/**< Write pointer (first byte to write) */
	gchar *rptr;				/**< Read pointer (first byte to read) */
};

/*
 * Private attributes for the link.
 */
struct attr {
	struct buffer buf[BUFFER_COUNT];
	size_t buffer_size;			/**< Buffer size used */
	size_t buffer_flush;		/**< Flush after that many bytes */
	gint fill_idx;				/**< Filled buffer index */
	gint send_idx;				/**< Buffer to be sent */
	z_streamp outz;				/**< Compressing stream */
	txdrv_t *nd;				/**< Network driver, underneath us */
	size_t unflushed;			/**< Amount of bytes written since last flush */
	gint flags;					/**< Operating flags */
	cqueue_t *cq;				/**< The callout queue to use for Nagle */
	gpointer tm_ev;				/**< The timer event */
	const struct tx_deflate_cb *cb;	/**< Layer-specific callbacks */
	tx_closed_t closed;			/**< Callback to invoke when layer closed */
	gpointer closed_arg;		/**< Argument for closing routine */
	gboolean nagle;				/**< Whether to use Nagle or not */
	struct {
		gboolean	enabled;	/**< Whether to use gzip encapsulation */
		guint32		size;		/**< Payload size counter for gzip */
		uLong		crc;		/**< CRC-32 accumlator for gzip */
	} gzip;
};

/*
 * Operating flags.
 */

#define DF_FLOWC		0x00000001	/**< We flow-controlled the upper layer */
#define DF_NAGLE		0x00000002	/**< Nagle timer started */
#define DF_FLUSH		0x00000004	/**< Flushing started */
#define DF_SHUTDOWN		0x00000008	/**< Stack has shut down */

static void deflate_nagle_timeout(cqueue_t *cq, gpointer arg);
static size_t tx_deflate_pending(txdrv_t *tx);

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

	if (dbg > 9)
		printf("deflate_send: (%s) wrote %d bytes (buffer #%d) [%c%c]\n",
			host_to_string(&tx->host), (gint) r, attr->send_idx,
			(attr->flags & DF_FLOWC) ? 'C' : '-',
			(attr->flags & DF_FLUSH) ? 'f' : '-');

	if ((ssize_t) -1 == r) {
		tx->flags |= TX_ERROR;
		return;
	}

	/*
	 * If we wrote everything, we're done.
	 */

	if ((size_t) r == len) {
		if (dbg > 9)
			printf("deflate_send: (%s) buffer #%d is empty\n",
				host_to_string(&tx->host), attr->send_idx);

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

	cq_cancel(attr->cq, attr->tm_ev);

	attr->tm_ev = NULL;
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

	if (dbg > 9)
		printf("deflate_rotate_and_send: (%s) fill buffer now #%d [%c%c]\n",
			host_to_string(&tx->host), attr->fill_idx,
			(attr->flags & DF_FLOWC) ? 'C' : '-',
			(attr->flags & DF_FLUSH) ? 'f' : '-');

	deflate_send(tx);
}

/**
 * Flush compression within filling buffer.
 *
 * @return success status, failure meaning we shutdown.
 */
static gboolean
deflate_flush(txdrv_t *tx)
{
	struct attr *attr = tx->opaque;
	z_streamp outz = attr->outz;
	struct buffer *b;
	gint ret;
	gint old_avail;

retry:
	b = &attr->buf[attr->fill_idx];	/* Buffer we fill */

	if (dbg > 9)
		printf("deflate_flush: (%s) flushing (buffer #%d) [%c%c]\n",
			host_to_string(&tx->host), attr->fill_idx,
			(attr->flags & DF_FLOWC) ? 'C' : '-',
			(attr->flags & DF_FLUSH) ? 'f' : '-');

	/*
	 * Prepare call to deflate().
	 *
	 * We force avail_in to 0, and don't touch next_in: no input should
	 * be consumed.
	 */

	outz->next_out = cast_to_gpointer(b->wptr);
	outz->avail_out = old_avail = b->end - b->wptr;

	outz->avail_in = 0;

	g_assert(outz->avail_out > 0);
	g_assert(outz->next_in);		/* We previously wrote something */

	ret = deflate(outz, (tx->flags & TX_CLOSING) ? Z_FINISH : Z_SYNC_FLUSH);

	switch (ret) {
	case Z_BUF_ERROR:				/* Nothing to flush */
		return TRUE;
	case Z_OK:
	case Z_STREAM_END:
		break;
	default:
		attr->flags |= DF_SHUTDOWN;
		tx->flags |= TX_ERROR;

		/* XXX: The callback must not destroy the tx! */
		attr->cb->shutdown(tx->owner, "Compression flush failed: %s",
				zlib_strerror(ret));
		return FALSE;
	}

	{
		size_t written;

		written = old_avail - outz->avail_out;
		b->wptr += written;

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
		if (attr->send_idx >= 0) {				/* Send buffer not sent yet */
			attr->flags |= DF_FLOWC|DF_FLUSH;	/* Enter flow control */

			if (dbg > 4)
				printf("Compressing TX stack for peer %s enters FLOWC/FLUSH\n",
					host_to_string(&tx->host));

			return TRUE;
		}

		deflate_rotate_and_send(tx);			/* Can set TX_ERROR */

		if (tx->flags & TX_ERROR)
			return FALSE;

		goto retry;
	}

	attr->unflushed = 0;
	attr->flags &= ~DF_FLUSH;

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
deflate_nagle_timeout(cqueue_t *unused_cq, gpointer arg)
{
	txdrv_t *tx = arg;
	struct attr *attr = tx->opaque;

	(void) unused_cq;
	if (-1 != attr->send_idx) {		/* Send buffer still incompletely sent */

		if (dbg > 9)
			printf("deflate_nagle_timeout: (%s) buffer #%d unsent,"
				" exiting [%c%c]\n",
				host_to_string(&tx->host), attr->send_idx,
				(attr->flags & DF_FLOWC) ? 'C' : '-',
				(attr->flags & DF_FLUSH) ? 'f' : '-');


		attr->tm_ev =
			cq_insert(attr->cq, BUFFER_NAGLE, deflate_nagle_timeout, tx);
		return;
	}

	attr->flags &= ~DF_NAGLE;
	attr->tm_ev = NULL;

	if (dbg > 9) {
		printf("deflate_nagle_timeout: (%s) flushing (buffer #%d) [%c%c]\n",
			host_to_string(&tx->host), attr->fill_idx,
			(attr->flags & DF_FLOWC) ? 'C' : '-',
			(attr->flags & DF_FLUSH) ? 'f' : '-');
		fflush(stdout);
	}

	deflate_flush_send(tx);
}

/**
 * Compress as much data as possible to the output buffer, sending data
 * as we go along.
 *
 * @return the amount of input bytes that were consumed ("added"), -1 on error.
 */
static gint
deflate_add(txdrv_t *tx, gconstpointer data, gint len)
{
	struct attr *attr = tx->opaque;
	z_streamp outz = attr->outz;
	gint added = 0;

	if (dbg > 9) {
		printf("deflate_add: (%s) given %lu bytes (buffer #%d, nagle %s, "
			"unflushed %lu) [%c%c]\n",
			host_to_string(&tx->host), (gulong) len, attr->fill_idx,
			(attr->flags & DF_NAGLE) ? "on" : "off", (gulong) attr->unflushed,
			(attr->flags & DF_FLOWC) ? 'C' : '-',
			(attr->flags & DF_FLUSH) ? 'f' : '-');
		fflush(stdout);
	}

	while (added < len) {
		struct buffer *b = &attr->buf[attr->fill_idx];	/* Buffer we fill */
		gint ret;
		gint old_added = added;
		gboolean flush_started = (attr->flags & DF_FLUSH) ? TRUE : FALSE;
		gint old_avail;
		const gchar *in, *old_in;

		/*
		 * Prepare call to deflate().
		 */

		outz->next_out = cast_to_gpointer(b->wptr);
		outz->avail_out = old_avail = b->end - b->wptr;

		in = data;
		old_in = &in[added];
		outz->next_in = deconstify_gpointer(old_in);
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
			attr->cb->shutdown(tx->owner, "Compression failed: %s",
				zlib_strerror(ret));
			return -1;
		}

		/*
		 * Update the parameters.
		 */

		b->wptr = cast_to_gpointer(outz->next_out);
		added = cast_to_gchar_ptr(outz->next_in) - in;

		g_assert(added >= old_added);

		attr->unflushed += added - old_added;

		if (NULL != attr->cb->add_tx_deflated)
			attr->cb->add_tx_deflated(tx->owner, old_avail - outz->avail_out);

		if (attr->gzip.enabled) {
			size_t r;

			r = cast_to_gchar_ptr(outz->next_in) - old_in;
			attr->gzip.size += r;
			attr->gzip.crc = crc32(attr->gzip.crc,
								cast_to_gconstpointer(old_in), r);
		}

		/*
		 * If we filled the output buffer, check whether we have a pending
		 * send buffer.  If we do, we cannot process more data.  Otherwise
		 * send it now and continue.
		 */

		if (0 == outz->avail_out) {
			if (attr->send_idx >= 0) {
				attr->flags |= DF_FLOWC;	/* Enter flow control */

				if (dbg > 4)
					printf("Compressing TX stack for peer %s enters FLOWC\n",
						host_to_string(&tx->host));

				return added;
			}

			deflate_rotate_and_send(tx);	/* Can set TX_ERROR */

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

		if (flush_started && 0 == outz->avail_in) {
			attr->unflushed = 0;
			attr->flags &= ~DF_FLUSH;
		}
	}

	g_assert(0 == outz->avail_in);

	/*
	 * Start Nagle if not already on.
	 */

	if (!(attr->flags & DF_NAGLE))
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
deflate_service(gpointer data)
{
	txdrv_t *tx = data;
	struct attr *attr = tx->opaque;
	struct buffer *b;

	g_assert(attr->send_idx < BUFFER_COUNT);

	if (dbg > 9)
		printf("deflate_service: (%s) %s(buffer #%d, %d bytes held) [%c%c]\n",
			host_to_string(&tx->host), (tx->flags & TX_ERROR) ? "ERROR " : "",
			attr->send_idx,
			attr->send_idx >= 0 ?
				(gint) (attr->buf[attr->send_idx].wptr -
						attr->buf[attr->send_idx].rptr) : 0,
			(attr->flags & DF_FLOWC) ? 'C' : '-',
			(attr->flags & DF_FLUSH) ? 'f' : '-');

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
		if (dbg > 9)
			printf("deflate_service: (%s) sending fill buffer #%d, %d bytes\n",
				host_to_string(&tx->host), attr->fill_idx,
				(gint) (b->wptr - b->rptr));

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

	if (attr->flags & DF_FLOWC) {
		attr->flags &= ~DF_FLOWC;	/* Leave flow control state */

		if (dbg > 4)
			printf("Compressing TX stack for peer %s leaves FLOWC\n",
				host_to_string(&tx->host));
	}

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


	if (dbg > 9)
		printf("deflate_service: (%s) %sdone locally [%c%c]\n",
			host_to_string(&tx->host), (tx->flags & TX_ERROR) ? "ERROR " : "",
			(attr->flags & DF_FLOWC) ? 'C' : '-',
			(attr->flags & DF_FLUSH) ? 'f' : '-');

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
static gpointer
tx_deflate_init(txdrv_t *tx, gpointer args)
{
	struct attr *attr;
	struct tx_deflate_args *targs = args;
	z_streamp outz;
	gint ret;
	gint i;

	g_assert(tx);
	g_assert(NULL != targs->cb);

	outz = walloc(sizeof *outz);

	outz->zalloc = zlib_alloc_func;
	outz->zfree = zlib_free_func;
	outz->opaque = NULL;

	ret = targs->gzip
		? deflateInit2(outz, Z_DEFAULT_COMPRESSION, Z_DEFLATED, (-MAX_WBITS),
				MAX_MEM_LEVEL, Z_DEFAULT_STRATEGY)
		: deflateInit(outz, Z_DEFAULT_COMPRESSION);

	if (Z_OK != ret) {
		wfree(outz, sizeof *outz);
		g_warning("unable to initialize compressor for peer %s: %s",
			host_to_string(&tx->host), zlib_strerror(ret));
		return NULL;
	}

	attr = walloc(sizeof *attr);

	attr->cq = targs->cq;
	attr->cb = targs->cb;
	attr->buffer_size = targs->buffer_size;
	attr->buffer_flush = targs->buffer_flush;
	attr->nagle = targs->nagle;
	attr->gzip.enabled = targs->gzip;

	attr->outz = outz;
	attr->flags = 0;
	attr->tm_ev = NULL;
	attr->unflushed = 0;

	for (i = 0; i < BUFFER_COUNT; i++) {
		struct buffer *b = &attr->buf[i];

		b->arena = b->wptr = b->rptr = walloc(attr->buffer_size);
		b->end = &b->arena[attr->buffer_size];
	}

	attr->fill_idx = 0;
	attr->send_idx = -1;		/* Signals: none ready */

	if (attr->gzip.enabled) {
		/* See RFC 1952 - GZIP file format specification version 4.3 */
		static const gchar header[] = {
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
		memcpy(b->wptr, header, sizeof header);
		b->wptr += sizeof header;

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
	gint i;
	gint ret;

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
			host_to_string(&tx->host), zlib_strerror(ret));

	wfree(attr->outz, sizeof *attr->outz);

	if (attr->tm_ev)
		cq_cancel(attr->cq, attr->tm_ev);

	wfree(attr, sizeof *attr);
}

/**
 * Write data buffer.
 *
 * @return amount of bytes written, or -1 on error.
 */
static ssize_t
tx_deflate_write(txdrv_t *tx, gconstpointer data, size_t len)
{
	struct attr *attr = tx->opaque;

	if (dbg > 9)
		printf("tx_deflate_write: (%s) (buffer #%d, nagle %s, "
			"unflushed %lu) [%c%c]\n",
			host_to_string(&tx->host), attr->fill_idx,
			(attr->flags & DF_NAGLE) ? "on" : "off", (gulong) attr->unflushed,
			(attr->flags & DF_FLOWC) ? 'C' : '-',
			(attr->flags & DF_FLUSH) ? 'f' : '-');

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
tx_deflate_writev(txdrv_t *tx, struct iovec *iov, gint iovcnt)
{
	struct attr *attr = tx->opaque;
	gint sent = 0;

	if (dbg > 9)
		printf("tx_deflate_writev: (%s) (buffer #%d, nagle %s, "
			"unflushed %lu) [%c%c]\n",
			host_to_string(&tx->host), attr->fill_idx,
			(attr->flags & DF_NAGLE) ? "on" : "off", (gulong) attr->unflushed,
			(attr->flags & DF_FLOWC) ? 'C' : '-',
			(attr->flags & DF_FLUSH) ? 'f' : '-');

	while (iovcnt--) {
		gint ret;

		/*
		 * If we're flow controlled or shut down, stop sending.
		 */

		if (attr->flags & (DF_FLOWC|DF_SHUTDOWN))
			return sent;

		ret = deflate_add(tx, iov->iov_base, iov->iov_len);

		if (-1 == ret)
			return -1;

		sent += ret;
		if ((guint) ret < iov->iov_len) {
			/* Could not write all, flow-controlled */
			break;
		}
		iov++;
	}

	if (dbg > 9)
		printf("tx_deflate_writev: (%s) sent %lu bytes (buffer #%d, nagle %s, "
			"unflushed %lu) [%c%c]\n",
			host_to_string(&tx->host), (gulong) sent, attr->fill_idx,
			(attr->flags & DF_NAGLE) ? "on" : "off", (gulong) attr->unflushed,
			(attr->flags & DF_FLOWC) ? 'C' : '-',
			(attr->flags & DF_FLUSH) ? 'f' : '-');

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
	const struct buffer *b;
	size_t pending;

	b = &attr->buf[attr->fill_idx];	/* Buffer we fill */
	pending = b->wptr - b->rptr;
	pending += attr->unflushed;		/* Some of those made it to buffer */

	if (-1 != attr->send_idx) {
		b = &attr->buf[attr->send_idx];	/* Buffer we send */
		pending += b->wptr - b->rptr;
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
		cq_expire(attr->cq, attr->tm_ev);
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
tx_deflate_close(txdrv_t *tx, tx_closed_t cb, gpointer arg)
{
	struct attr *attr = tx->opaque;

	g_assert(tx->flags & TX_CLOSING);

	if (dbg > 9)
		printf("tx_deflate_close: (%s) send=%d buffer #%d, nagle %s, "
			"unflushed %lu) [%c%c]\n",
			host_to_string(&tx->host), attr->send_idx, attr->fill_idx,
			(attr->flags & DF_NAGLE) ? "on" : "off", (gulong) attr->unflushed,
			(attr->flags & DF_FLOWC) ? 'C' : '-',
			(attr->flags & DF_FLUSH) ? 'f' : '-');

	/*
	 * Flush whatever we can.
	 */

	tx_deflate_flush(tx);

	if (attr->gzip.enabled && 0 == tx_deflate_pending(tx)) {
		/* See RFC 1952 - GZIP file format specification version 4.3 */
		struct buffer *b;
		guint32 trailer[2]; /* 0: CRC32, 1: SIZE % (1 << 32) */

		/* We don't want to send the trailer more than once */
		attr->gzip.enabled = FALSE;

		attr->send_idx = 0;
		b = &attr->buf[attr->send_idx];
		poke_le32(&trailer[0], (guint32) attr->gzip.crc);
		poke_le32(&trailer[1], attr->gzip.size);

		g_assert(sizeof trailer <= (size_t) (b->end - b->wptr));
		memcpy(b->wptr, trailer, sizeof trailer);
		b->wptr += sizeof trailer;

		deflate_send(tx);
	}

	if (0 == tx_deflate_pending(tx)) {
		if (dbg > 9)
			printf("tx_deflate_close: flushed everything immediately\n");

		(*cb)(tx, arg);
		return;
	}

	/*
	 * We were unable to flush everything.
	 */

	attr->closed = cb;
	attr->closed_arg = arg;

	if (dbg > 9)
		printf("tx_deflate_close: (%s) delayed! send=%d buffer #%d, nagle %s, "
			"unflushed %lu) [%c%c]\n",
			host_to_string(&tx->host),
			attr->send_idx, attr->fill_idx,
			(attr->flags & DF_NAGLE) ? "on" : "off", (gulong) attr->unflushed,
			(attr->flags & DF_FLOWC) ? 'C' : '-',
			(attr->flags & DF_FLUSH) ? 'f' : '-');
}

static const struct txdrv_ops tx_deflate_ops = {
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
