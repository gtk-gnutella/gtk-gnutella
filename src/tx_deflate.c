/*
 * Copyright (c) 2002, Raphael Manfredi
 *
 * Network driver -- compressing level.
 *
 * This driver compresses its data stream before sending it to the link layer.
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

#include <sys/types.h>
#include <sys/uio.h>	/* struct iovec */
#include <zlib.h>

#include "sockets.h"
#include "nodes.h"
#include "tx.h"
#include "tx_deflate.h"
#include "misc.h"
#include "zlib_util.h"
#include "cq.h"

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
#define BUFFER_SIZE		2048
#define BUFFER_FLUSH	4096	/* Try to flush every 4K */
#define BUFFER_NAGLE	200		/* 200 ms */

struct buffer {
	gchar *arena;				/* Buffer arena */
	gchar *end;					/* First byte outside buffer */
	gchar *wptr;				/* Write pointer (first byte to write) */
	gchar *rptr;				/* Read pointer (first byte to read) */
};

/*
 * Private attributes for the link.
 */
struct attr {
	struct buffer buf[BUFFER_COUNT];
	gint fill_idx;				/* Filled buffer index */
	gint send_idx;				/* Buffer to be sent */
	z_streamp outz;				/* Compressing stream */
	txdrv_t *nd;				/* Network driver, underneath us */
	gint unflushed;				/* Amount of bytes written since last flush */
	gint flags;					/* Operating flags */
	cqueue_t *cq;				/* The callout queue to use for Nagle */
	gpointer tm_ev;				/* The timer event */
};

/*
 * Operating flags.
 */

#define DF_FLOWC		0x00000001	/* We flow-controlled the upper layer */
#define DF_NAGLE		0x00000002	/* Nagle timer started */
#define DF_FLUSH		0x00000004	/* Flushing started */
#define DF_SHUTDOWN		0x00000008	/* Stack has shut down */

static void deflate_nagle_timeout(cqueue_t *cq, gpointer arg);

/*
 * deflate_send
 *
 * Write ready-to-be-sent buffer to the lower layer.
 */
static void deflate_send(txdrv_t *tx)
{
	struct attr *attr = (struct attr *) tx->opaque;
	struct buffer *b;
	gint len;					/* Amount of bytes to send */
	gint r;

	g_assert(attr->send_idx >= 0);	/* We have something to send */
	g_assert(attr->send_idx < BUFFER_COUNT);

	/*
	 * Compute data to be sent.
	 */

	b = &attr->buf[attr->send_idx];		/* Buffer to send */
	len = b->wptr - b->rptr;

	g_assert(len > 0);

	/*
	 * Write as much as possible.
	 */

	r = tx_write(attr->nd, b->rptr, len);

	if (dbg > 9)
		printf("deflate_send: (%s) wrote %d bytes (buffer #%d)\n",
			node_ip(tx->node), r, attr->send_idx);

	if (r < 0)
		return;

	/*
	 * If we wrote everything, we're done.
	 */

	if (r == len) {
		if (dbg > 9)
			printf("deflate_send: (%s) buffer #%d is empty\n",
				node_ip(tx->node), attr->send_idx);

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

	tx_srv_enable(attr->nd);
}

/*
 * deflate_nagle_start
 *
 * Start the nagle timer.
 */
static void deflate_nagle_start(txdrv_t *tx)
{
	struct attr *attr = (struct attr *) tx->opaque;

	g_assert(!(attr->flags & DF_NAGLE));
	g_assert(attr->tm_ev == NULL);

	attr->tm_ev = cq_insert(attr->cq, BUFFER_NAGLE, deflate_nagle_timeout, tx);
	attr->flags |= DF_NAGLE;
}

/*
 * deflate_nagle_stop
 *
 * Stop the nagle timer.
 */
static void deflate_nagle_stop(txdrv_t *tx)
{
	struct attr *attr = (struct attr *) tx->opaque;

	g_assert(attr->flags & DF_NAGLE);
	g_assert(attr->tm_ev != NULL);

	cq_cancel(attr->cq, attr->tm_ev);

	attr->tm_ev = NULL;
	attr->flags &= ~DF_NAGLE;
}

/*
 * deflate_rotate_and_send
 *
 * Make the "filling buffer" the buffer to send, and rotate filling buffers.
 * Attempt to write the new send buffer immediately.
 */
static void deflate_rotate_and_send(txdrv_t *tx)
{
	struct attr *attr = (struct attr *) tx->opaque;

	g_assert(attr->send_idx == -1);		/* No pending send */

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
		printf("deflate_rotate_and_send: (%s) fill buffer now #%d\n",
			node_ip(tx->node), attr->fill_idx);

	deflate_send(tx);
}

/*
 * deflate_service
 *
 * Service routine for the compressing stage.
 * Called by lower layer when it is ready to process more data.
 */
static void deflate_service(gpointer data)
{
	txdrv_t *tx = (txdrv_t *) data;
	struct attr *attr = (struct attr *) tx->opaque;
	struct buffer *b;

	g_assert(attr->send_idx >= 0);	/* We have something to send */
	g_assert(attr->send_idx < BUFFER_COUNT);

	if (dbg > 9)
		printf("deflate_service: (%s) (buffer #%d, %d bytes held)\n",
			node_ip(tx->node), attr->send_idx,
			attr->buf[attr->send_idx].wptr - attr->buf[attr->send_idx].rptr);

	/*
	 * First, attempt to transmit the whole send buffer.
	 */

	deflate_send(tx);				/* Send buffer `send_idx' */

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
				node_ip(tx->node), attr->fill_idx, b->wptr - b->rptr);

		deflate_rotate_and_send(tx);
	}

	/*
	 * If we were able to send the whole send buffer, disable servicing.
	 */

	if (attr->send_idx == -1)
		tx_srv_disable(attr->nd);

	/*
	 * If we entered flow control, we can now safely leave it, since we
	 * have at least a free `fill' buffer.
	 */

	if (attr->flags & DF_FLOWC) {
		attr->flags &= ~DF_FLOWC;	/* Leave flow control state */

		if (dbg > 4)
			printf("Compressing TX stack for node %s leaves FLOWC\n",
				node_ip(tx->node));

		/*
		 * If upper layer wants servicing, do it now.
		 * Note that this can put us back into flow control.
		 */

		if (tx->flags & TX_SERVICE) {
			g_assert(tx->srv_routine);
			tx->srv_routine(tx->srv_arg);
		}
	}
}

/*
 * deflate_flush
 *
 * Flush compression within filling buffer.
 * Return success status, failure meaning we shutdown.
 */
static gboolean deflate_flush(txdrv_t *tx)
{
	struct attr *attr = (struct attr *) tx->opaque;
	z_streamp outz = attr->outz;
	struct buffer *b;
	gint ret;
	gint old_avail;

retry:
	b = &attr->buf[attr->fill_idx];	/* Buffer we fill */

	if (dbg > 9)
		printf("deflate_flush: (%s) flushing (buffer #%d)\n",
			node_ip(tx->node), attr->fill_idx);

	/*
	 * Prepare call to deflate().
	 *
	 * We force avail_in to 0, and don't touch next_in: no input should
	 * be consumed.
	 */

	outz->next_out = b->wptr;
	outz->avail_out = old_avail = b->end - b->wptr;

	outz->avail_in = 0;

	g_assert(outz->avail_out > 0);
	g_assert(outz->next_in);		/* We previously wrote something */

	ret = deflate(outz, Z_SYNC_FLUSH);

	switch (ret) {
	case Z_BUF_ERROR:				/* Nothing to flush */
		return TRUE;
	case Z_OK:
		break;
	default:
		attr->flags |= DF_SHUTDOWN;
		node_shutdown(tx->node, "Compression flush failed: %s",
			zlib_strerror(ret));
		return FALSE;
	}

	b->wptr += old_avail - outz->avail_out;

	node_add_tx_deflated(tx->node, old_avail - outz->avail_out);

	/*
	 * Check whether avail_out is 0.
	 *
	 * If it is, then we lacked room to complete the flush.  Try to send the
	 * buffer and continue.
	 */

	if (outz->avail_out == 0) {
		if (attr->send_idx >= 0) {				/* Send buffer not sent yet */
			attr->flags |= DF_FLOWC|DF_FLUSH;	/* Enter flow control */

			if (dbg > 4)
				printf("Compressing TX stack for node %s enters FLOWC/FLUSH\n",
					node_ip(tx->node));

			return TRUE;
		}

		deflate_rotate_and_send(tx);
		goto retry;
	}

	attr->unflushed = 0;
	attr->flags &= ~DF_FLUSH;

	return TRUE;		/* Fully flushed */
}

/*
 * deflate_nagle_timeout
 *
 * Called from the callout queue when the Nagle timer expires.
 * If we can send the buffer, flush it and send it.  Otherwise, reschedule.
 */
static void deflate_nagle_timeout(cqueue_t *cq, gpointer arg)
{
	txdrv_t *tx = (txdrv_t *) arg;
	struct attr *attr = (struct attr *) tx->opaque;

	if (attr->send_idx != -1) {		/* Send buffer still incompletely sent */

		if (dbg > 9)
			printf("deflate_nagle_timeout: (%s) buffer #%d unsent, exiting\n",
				node_ip(tx->node), attr->send_idx);

		attr->tm_ev =
			cq_insert(attr->cq, BUFFER_NAGLE, deflate_nagle_timeout, tx);
		return;
	}

	attr->flags &= ~DF_NAGLE;
	attr->tm_ev = NULL;

	if (dbg > 9) {
		printf("deflate_nagle_timeout: (%s) flushing (buffer #%d)\n",
			node_ip(tx->node), attr->fill_idx);
		fflush(stdout);
	}

	/*
	 * During deflate_flush(), we can fill the current buffer, then call
	 * deflate_rotate_and_send() and finish the flush.  But it is possible
	 * that the whole send buffer does not get sent immediately.  Therefore,
	 * we need to recheck for attr->send_idx.
	 */

	if (deflate_flush(tx)) {
		if (attr->send_idx == -1)
			deflate_rotate_and_send(tx);
	}
}

/*
 * deflate_add
 *
 * Compress as much data as possible to the output buffer, sending data
 * as we go along.
 *
 * Returns the amount of input bytes that were consumed ("added"), -1 on error.
 */
static gint deflate_add(txdrv_t *tx, gpointer data, gint len)
{
	struct attr *attr = (struct attr *) tx->opaque;
	z_streamp outz = attr->outz;
	gint added = 0;

	if (dbg > 9) {
		printf("deflate_add: (%s) given %d bytes (buffer #%d, nagle %s, "
			"unflushed %d)\n",
			node_ip(tx->node), len, attr->fill_idx,
			(attr->flags & DF_NAGLE) ? "on" : "off", attr->unflushed);
		fflush(stdout);
	}

	while (added < len) {
		struct buffer *b = &attr->buf[attr->fill_idx];	/* Buffer we fill */
		gint ret;
		gint old_added = added;
		gboolean flush_started = (attr->flags & DF_FLUSH) ? TRUE : FALSE;
		gint old_avail;

		/*
		 * Prepare call to deflate().
		 */

		outz->next_out = b->wptr;
		outz->avail_out = old_avail = b->end - b->wptr;

		outz->next_in = data + added;
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

		if (ret != Z_OK) {
			attr->flags |= DF_SHUTDOWN;
			node_shutdown(tx->node, "Compression failed: %s",
				zlib_strerror(ret));
			return -1;
		}

		/*
		 * Update the parameters.
		 */

		b->wptr = outz->next_out;
		added = (gpointer) outz->next_in - data;

		g_assert(added >= old_added);

		attr->unflushed += added - old_added;
		node_add_tx_deflated(tx->node, old_avail - outz->avail_out);

		/*
		 * If we filled the output buffer, check whether we have a pending
		 * send buffer.  If we do, we cannot process more data.  Otherwise
		 * send it now and continue.
		 */

		if (outz->avail_out == 0) {
			if (attr->send_idx >= 0) {
				attr->flags |= DF_FLOWC;	/* Enter flow control */

				if (dbg > 4)
					printf("Compressing TX stack for node %s enters FLOWC\n",
						node_ip(tx->node));

				return added;
			}

			deflate_rotate_and_send(tx);
		}

		/*
		 * If we were flushing and we consumed all the input, then
		 * the flush is done and we're starting normal compression again.
		 *
		 * This must be done after we made sure that we had enough output
		 * space avaialable.
		 */

		if (flush_started && outz->avail_in == 0) {
			attr->unflushed = 0;
			attr->flags &= ~DF_FLUSH;
		}
	}

	g_assert(outz->avail_in == 0);

	/*
	 * Start Nagle if not already on.
	 */

	if (!(attr->flags & DF_NAGLE))
		deflate_nagle_start(tx);

	/*
	 * We're going to ask for a flush if not already started yet and the
	 * amount of bytes we have written since the last flush is greater
	 * than BUFFER_FLUSH.
	 */

	if (attr->unflushed > BUFFER_FLUSH) {
		if (!deflate_flush(tx))
			return -1;
	}

	return added;
}

/***
 *** Polymorphic routines.
 ***/

/*
 * tx_deflate_init
 *
 * Initialize the driver.
 * Returns NULL if there is an initialization problem.
 */
static gpointer tx_deflate_init(txdrv_t *tx, gpointer args)
{
	struct attr *attr;
	struct tx_deflate_args *targs = (struct tx_deflate_args *) args;
	z_streamp outz;
	gint ret;
	gint i;

	g_assert(tx);

	outz = g_malloc(sizeof(*outz));

	outz->zalloc = NULL;
	outz->zfree = NULL;
	outz->opaque = NULL;

	ret = deflateInit(outz, Z_DEFAULT_COMPRESSION);

	if (ret != Z_OK) {
		g_free(outz);
		g_warning("unable to initialize compressor for node %s: %s",
			node_ip(tx->node), zlib_strerror(ret));
		return NULL;
	}

	attr = g_malloc(sizeof(*attr));

	attr->nd = targs->nd;
	attr->cq = targs->cq;
	attr->outz = outz;
	attr->flags = 0;
	attr->tm_ev = NULL;
	attr->unflushed = 0;

	for (i = 0; i < BUFFER_COUNT; i++) {
		struct buffer *b = &attr->buf[i];

		b->arena = b->wptr = b->rptr = (gchar *) g_malloc(BUFFER_SIZE);
		b->end = b->arena + BUFFER_SIZE;
	}

	attr->fill_idx = 0;
	attr->send_idx = -1;		/* Signals: none ready */

	tx->opaque = attr;

	/*
	 * Register our service routine to the lower layer.
	 */

	tx_srv_register(attr->nd, deflate_service, tx);

	return tx;		/* OK */
}

/*
 * tx_deflate_destroy
 *
 * Get rid of the driver's private data.
 */
static void tx_deflate_destroy(txdrv_t *tx)
{
	struct attr *attr = (struct attr *) tx->opaque;
	gint i;
	gint ret;

	/*
	 * XXX At some point, this will need to be refactored to do like it's
	 * XXX done for the RX stack: the TX structure keeps track of the
	 * XXX layers and this recursion is done from the upper level.
	 *		-- RAM, 11/05/2002
	 */

	tx_free(attr->nd);			/* Free lower layer */

	g_assert(attr->outz);

	for (i = 0; i < BUFFER_COUNT; i++) {
		struct buffer *b = &attr->buf[i];
		g_free(b->arena);
	}

	/*
	 * We ignore Z_DATA_ERROR errors (discarded data, probably).
	 */

	ret = deflateEnd(attr->outz);

	if (ret != Z_OK && ret != Z_DATA_ERROR)
		g_warning("while freeing compressor for node %s: %s",
			node_ip(tx->node), zlib_strerror(ret));

	g_free(attr->outz);

	if (attr->tm_ev)
		cq_cancel(attr->cq, attr->tm_ev);

	g_free(tx->opaque);
}

/*
 * tx_deflate_write
 *
 * Write data buffer.
 * Returns amount of bytes written, or -1 on error.
 */
static gint tx_deflate_write(txdrv_t *tx, gpointer data, gint len)
{
	struct attr *attr = (struct attr *) tx->opaque;

	/*
	 * If we're flow controlled or shut down, don't accept anything.
	 */

	if (attr->flags & (DF_FLOWC|DF_SHUTDOWN))
		return 0;

	return deflate_add(tx, data, len);
}

/*
 * tx_deflate_writev
 *
 * Write I/O vector.
 * Returns amount of bytes written, or -1 on error.
 */
static gint tx_deflate_writev(txdrv_t *tx, struct iovec *iov, gint iovcnt)
{
	struct attr *attr = (struct attr *) tx->opaque;
	gint sent = 0;

	while (iovcnt--) {
		gint ret;

		/*
		 * If we're flow controlled or shut down, stop sending.
		 */

		if (attr->flags & (DF_FLOWC|DF_SHUTDOWN))
			return sent;

		ret = deflate_add(tx, iov->iov_base, iov->iov_len);

		if (ret == -1)
			return -1;

		sent += ret;
		if (ret < iov->iov_len)		/* Could not write all, flow-controlled */
			break;
		iov++;
	}

	return sent;
}

/*
 * tx_deflate_enable
 *
 * Allow servicing of upper TX queue.
 */
static void tx_deflate_enable(txdrv_t *tx)
{
	/* Nothing specific */
}

/*
 * tx_deflate_disable
 *
 * Disable servicing of upper TX queue.
 */
static void tx_deflate_disable(txdrv_t *tx)
{
	/* Nothing specific */
}

/*
 * tx_deflate_pending
 *
 * Returns the amount of data buffered locally and in the stack below.
 */
static gint tx_deflate_pending(txdrv_t *tx)
{
	struct attr *attr = (struct attr *) tx->opaque;
	struct buffer *b;
	gint pending;

	b = &attr->buf[attr->fill_idx];	/* Buffer we fill */
	pending = b->wptr - b->rptr;
	pending += attr->unflushed;		/* Some of those made it to buffer */

	if (attr->send_idx != -1) {
		b = &attr->buf[attr->send_idx];	/* Buffer we send */
		pending += b->wptr - b->rptr;
	}

	return pending + tx_pending(attr->nd);
}

struct txdrv_ops tx_deflate_ops = {
	tx_deflate_init,		/* init */
	tx_deflate_destroy,		/* destroy */
	tx_deflate_write,		/* write */
	tx_deflate_writev,		/* writev */
	tx_deflate_enable,		/* enable */
	tx_deflate_disable,		/* disable */
	tx_deflate_pending,		/* pending */
};

