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
 * Network driver -- link level.
 *
 * This driver reads data from the network and builds messages that are
 * given to the upper layer on the "interrupt stack".
 *
 * @author Raphael Manfredi
 * @date 2002-2003
 */

#include "common.h"

#include "sockets.h"
#include "rx.h"
#include "rx_link.h"
#include "rxbuf.h"
#include "bsched.h"

#include "lib/pmsg.h"
#include "lib/walloc.h"
#include "lib/override.h"		/* Must be the last header included */

/**
 * Private attributes for the link.
 */
struct attr {
	wrap_io_t *wio;				/**< Cached wrapped IO object */
	bio_source_t *bio;			/**< Bandwidth-limited I/O source */
	bsched_bws_t bws;			/**< Scheduler to attach I/O source to */
	const struct rx_link_cb *cb;/**< Layer-specific callbacks */
	unsigned delivering:1;		/**< Currently delivery payloads */
};

/**
 * Invoked when the input file descriptor has more data available.
 */
static void
is_readable(void *data, int unused_source, inputevt_cond_t cond)
{
	rxdrv_t *rx = data;
	struct attr *attr = rx->opaque;
	pdata_t *db[32];
	iovec_t iov[N_ITEMS(db)];
	pmsg_t *mb;
	ssize_t r;
	uint i, iov_cnt;
	size_t avail;

	(void) unused_source;
	g_assert(attr->bio);			/* Input enabled */

	if (cond & INPUT_EVENT_EXCEPTION) {
		errno = EIO;
		attr->cb->read_error(rx->owner, _("Read failed (Input Exception)"));
		return;
	}

	avail = inputevt_data_available();
	if (0 == avail) {
		/*
		 * If we don't know how much can be read immediately, we make a
		 * guess. This prevents multiple readv() syscalls when reading from
		 * a fast source which would occur otherwise.
		 *
		 * The socket's RX buffer size represents the maximum amount of data
		 * that the kernel can hold for the connection.
		 */

		avail = bio_get_bufsize(attr->bio, SOCK_BUF_RX);
		if (0 == avail)
			avail = 32 * 1024;	/* Guess if nothing was configured */
	}

	/*
	 * Grab RX buffers, and try to fill as much as we can.
	 */

	i = 0;
	for (i = 0; i < N_ITEMS(db); /* NOTHING */) {
		size_t len;

		db[i] = rxbuf_new();
		len = pdata_len(db[i]);
		iovec_set(&iov[i], pdata_start(db[i]), len);
		i++;

		if (len >= avail)
			break;
		avail -= len;
	}
	iov_cnt = i;

	i = 0;	/* To free all buffers on error */
	r = bio_readv(attr->bio, iov, iov_cnt);
	if (r == 0) {
		attr->cb->got_eof(rx->owner);
	} else if ((ssize_t) -1 == r) {
		if (!is_temporary_error(errno))
			attr->cb->read_error(rx->owner, _("Read error: %s"),
				g_strerror(errno));
	} else {
		/*
		 * Got something, build a message and send it to the upper layer.
		 * NB: `mb' is expected to be freed by the last layer using it.
		 */

		g_assert(!attr->delivering);	/* No recursion: would mess up order */

		attr->delivering = TRUE;

		if (attr->cb->add_rx_given != NULL)
			attr->cb->add_rx_given(rx->owner, r);

		while (r > 0 && i < iov_cnt) {
			size_t n = pdata_len(db[i]);

			if (n > (size_t) r) {
				n = (size_t) r;
				r = 0;
			} else {
				r -= n;
			}
			mb = pmsg_alloc(PMSG_P_DATA, db[i], 0, n);
			i++;
			if (!(*rx->data.ind)(rx, mb))
				break;
		}

		attr->delivering = FALSE;
	}

	/*
	 * Discard unused RX buffers.
	 */

	for (/* CONTINUE*/; i < iov_cnt; i++) {
		rxbuf_free(db[i]);
	}
}

/***
 *** Polymorphic routines.
 ***/

/**
 * Initialize the driver.
 *
 * Always succeeds, so never returns NULL.
 */
static void *
rx_link_init(rxdrv_t *rx, const void *args)
{
	const struct rx_link_args *rargs = args;
	struct attr *attr;

	rx_check(rx);
	g_assert(rargs);
	g_assert(rargs->cb);

	WALLOC0(attr);
	attr->cb = rargs->cb;
	attr->wio = rargs->wio;
	attr->bws = rargs->bws;
	attr->bio = NULL;

	rx->opaque = attr;

	return rx;		/* OK */
}

/**
 * Get rid of the driver's private data.
 */
static void
rx_link_destroy(rxdrv_t *rx)
{
	struct attr *attr = rx->opaque;

	if (attr->bio) {
		bsched_source_remove(attr->bio);
		attr->bio = NULL;					/* Paranoid */
	}

	WFREE(attr);
	rx->opaque = NULL;
}

/**
 * Inject data into driver.
 *
 * Since we normally read from the network, we don't have to process those
 * data and can forward them directly to the upper layer.
 *
 * @return FALSE if there was an error or the receiver wants no more data.
 */
static bool
rx_link_recv(rxdrv_t *rx, pmsg_t *mb)
{
	struct attr *attr = rx->opaque;

	rx_check(rx);
	g_assert(mb);

	if (attr->cb->add_rx_given != NULL)
		attr->cb->add_rx_given(rx->owner, pmsg_size(mb));

	/*
	 * Call the registered data_ind callback to feed the upper layer.
	 * NB: `mb' is expected to be freed by the last layer using it.
	 */

	return (*rx->data.ind)(rx, mb);
}

/**
 * Enable reception of data.
 */
static void
rx_link_enable(rxdrv_t *rx)
{
	struct attr *attr = rx->opaque;

	g_assert(attr->bio == NULL);

	/*
	 * Install reading callback.
	 */

	attr->bio = bsched_source_add(attr->bws, attr->wio, BIO_F_READ,
					is_readable, rx);

	g_assert(attr->bio);
}

/**
 * Disable reception of data.
 */
static void
rx_link_disable(rxdrv_t *rx)
{
	struct attr *attr = rx->opaque;

	/*
	 * Disabling is blindly called when the RX stack is freed, regardless
	 * of whether the stack is enabled or not.  Therefore we cannot
	 * assert that attr->bio is not NULL.
	 *
	 * XXX Have the RX stack "rxdrv_t" record whether we're enabled or not
	 * XXX to have conditional disabling from the upper layers, as it is
	 * XXX done for TX?		--RAM, 2005-11-30
	 */

	if (attr->bio == NULL)
		return;

	bsched_source_remove(attr->bio);
	attr->bio = NULL;
}

/**
 * @return I/O source of the lower level.
 */
static struct
bio_source *rx_link_bio_source(rxdrv_t *rx)
{
	struct attr *attr = rx->opaque;

	return attr->bio;
}

static const struct rxdrv_ops rx_link_ops = {
	rx_link_init,		/**< init */
	rx_link_destroy,	/**< destroy */
	rx_link_recv,		/**< recv */
	NULL,				/**< recvfrom */
	rx_link_enable,		/**< enable */
	rx_link_disable,	/**< disable */
	rx_link_bio_source,	/**< bio_source */
};

const struct rxdrv_ops *
rx_link_get_ops(void)
{
	return &rx_link_ops;
}

/* vi: set ts=4 sw=4 cindent: */
