/*
 * Copyright (c) 2005, Christian Biere
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
 * Network RX -- chunked-encoding.
 *
 * @author Christian Biere
 * @date 2005
 */

#include "common.h"

#include "hosts.h"				/* For host_ip() */
#include "rx.h"
#include "rx_chunk.h"
#include "rxbuf.h"

#include "if/gnet_property_priv.h"

#include "lib/ascii.h"
#include "lib/pmsg.h"
#include "lib/stringify.h"
#include "lib/walloc.h"
#include "lib/override.h"		/* Must be the last header included */

enum chunk_state {
	CHUNK_STATE_ERROR = 0,
	CHUNK_STATE_SIZE,
	CHUNK_STATE_EXT,
	CHUNK_STATE_DATA,
	CHUNK_STATE_DATA_CRLF,
	CHUNK_STATE_TRAILER_START,
	CHUNK_STATE_TRAILER,
	CHUNK_STATE_END,

	NUM_CHUNK_STATES
};

/*
 * Private attributes for the dechunking layer.
 */
struct attr {
	const struct rx_chunk_cb *cb;	/**< Layer-specific callbacks */
	uint64 data_remain;			/**< Amount of remaining chunk payload data */
	char hex_buf[16];			/**< Holds the hex digits of chunk-size */
	size_t hex_pos;				/**< Current position in hex_buf */
	enum chunk_state state;		/**< Current decoding state */
	int flags;
};

#define IF_ENABLED	0x00000001		/**< Reception enabled */
#define IF_NO_CRLF	0x00000002		/**< Set when missing CRLF after data */

/**
 * Decodes "chunked" data.
 *
 * The function returns as soon as it needs more data to proceed, on
 * error, if the state CHUNK_STATE_END was reached, or if the state
 * CHUNK_STATE_DATA was reached. In the latter case the chunk payload
 * itself must be consumed and this function must not be called again
 * until the state CHUNK_STATE_DATA_CRLF is reached.
 *
 * @param rx			the current RX driver.
 * @param src			the chunk data.
 * @param size			no document.
 * @param p_error_str	if not NULL and parse_chunk() fails, it will point
 *						to an informational error message.
 *
 * @return 0 on failure; non-zero amount of consumed bytes on success.
 */
static size_t
parse_chunk(rxdrv_t *rx, const char *src, size_t size,
	const char **p_error_str)
{
	struct attr *attr = rx->opaque;
	const char *error_str;
	size_t len;

	g_assert(attr);
	g_assert(src);
	g_assert(size > 0);
	g_assert(attr->state < NUM_CHUNK_STATES);
	g_assert(0 == attr->data_remain);

	len = size;

	do {
		switch (attr->state) {
		case CHUNK_STATE_DATA_CRLF:
			/* The chunk-data must be followed by a CRLF */
			while (len > 0) {
				uchar c;

				len--;
				c = *src++;
				if ('\r' == c) {
				   /*
					* This allows more than one CR but we must consume
				 	* some data or keep state over this otherwise.
					*/
					continue;
				} else if ('\n' == c) {
					attr->state = CHUNK_STATE_SIZE;
					break;
				} else {
					/*
					 * Normally it is an error, there should be CRLF after
					 * the chunk data.  However, they might have forgotten
					 * to send the '\n' or the whole sequence.
					 *
					 * If what follows looks like a valid chunk size, then
					 * we should be able to resync properly: Unread the
					 * character and move on to the chunk size decoding.
					 */

					if (!(attr->flags & IF_NO_CRLF)) {
						attr->flags |= IF_NO_CRLF;
						g_warning("host %s forgot CRLF after data",
							gnet_host_to_string(&rx->host));
					}

					len++;
					src--;
					attr->state = CHUNK_STATE_SIZE;
					break;
				}
			}
			break;

		case CHUNK_STATE_SIZE:
			g_assert(attr->hex_pos < sizeof attr->hex_buf);
			while (len > 0) {
				uchar c;

				len--;
				c = *src++;
				if (is_ascii_xdigit(c)) {
					if (attr->hex_pos >= sizeof attr->hex_buf) {
						error_str = "Overflow in chunk-size";
						goto error;
					}
					/* Collect up to 16 hex characters */
					attr->hex_buf[attr->hex_pos++] = c;
				} else {
					/*
					 * There might be a chunk-extension after the
					 * hexadecimal chunk-size but there shouldn't
					 * anything else.
					 */

					if (
						0 == attr->hex_pos ||
						(!is_ascii_space(c) && ';' != c)
					) {
						error_str = "Bad chunk-size";
						goto error;
					}
					attr->state = CHUNK_STATE_EXT;
					break;
				}
			}
			break;

		case CHUNK_STATE_EXT:
			/* Just skip over the chunk-extension */

			if G_UNLIKELY(0 == hex2int_inline('a'))
				misc_init();	/* Auto-initialization of hex2int_inline() */

			while (len > 0) {
				len--;
				if ('\n' == *src++) {

					/*
					 * Pick up the collected hex digits and
					 * calculate the chunk-size.
					 */

					g_assert(attr->hex_pos > 0);
					g_assert(attr->hex_pos <= sizeof attr->hex_buf);

					{
						uint64 v = 0;
						uint i;

						for (i = 0; i < attr->hex_pos; i++)
							v = (v << 4) | hex2int_inline(attr->hex_buf[i]);

						attr->data_remain = v;
						attr->hex_pos = 0;
					}

					attr->state = 0 != attr->data_remain
						? CHUNK_STATE_DATA
						: CHUNK_STATE_TRAILER_START;
					break;
				}
			}
			break;

		case CHUNK_STATE_TRAILER_START:
			/* We've reached another trailer line */
			if (len < 1)
				break;
			if ('\r' == src[0]) {
				/*
				 * This allows more than one CR but we must consume
				 * some data or keep state over this otherwise.
				 */
				src++;
				len--;
			}
			if (len < 1)
				break;
			if ('\n' == src[0]) {
				/* An empty line means the end of all trailers was reached */
				src++;
				len--;
				attr->state = CHUNK_STATE_END;
				break;
			}
			attr->state = CHUNK_STATE_TRAILER;
			/* FALL THROUGH */

		case CHUNK_STATE_TRAILER:
			/* Just skip over the trailer line */
			while (len > 0) {
				len--;
				if ('\n' == *src++) {
					/*
					 * Now check whether there's another trailer
					 * line or whether we've reached the end
					 */

					attr->state = CHUNK_STATE_TRAILER_START;
					break;
				}
			}
			break;

		case CHUNK_STATE_END:
			/*
			 * We're not supposed to receive data after the chunk stream
			 * has been ended.  But if we do, it means either we
			 * misinterpreted the chunk end stream or the other end is just
			 * going berserk.
			 */

			error_str = "Remaining data after chunk end";
			goto error;

		case CHUNK_STATE_DATA:
		case CHUNK_STATE_ERROR:
		case NUM_CHUNK_STATES:
			g_assert_not_reached();
			break;
		}

		/* NB: Some data from ``src'' must have been consumed or an
		 *     infinite loop may occur.
		 */

		if (CHUNK_STATE_DATA == attr->state) {
			if (GNET_PROPERTY(rx_debug) > 9)
				g_debug("parse_chunk: chunk size %s bytes",
					uint64_to_string(attr->data_remain));
			break;
		}

	} while (len > 0 && CHUNK_STATE_END != attr->state);

	if (p_error_str)
		*p_error_str = NULL;

	return size - len;

error:

	if (p_error_str)
		*p_error_str = error_str;

	attr->state = CHUNK_STATE_ERROR;
	return 0;
}

/**
 * Dechunk more data from the input buffer `mb'.
 * @returns dechunked data in a new buffer, or NULL if no more data.
 */
static pmsg_t *
dechunk_data(rxdrv_t *rx, pmsg_t *mb)
{
	struct attr *attr = rx->opaque;
	const char *error_str, *src;
	size_t size;

	/*
	 * Prepare call to parse_chunk().
	 */

	size = pmsg_size(mb);
	src = pmsg_read_base(mb);

	while (size > 0) {
		size_t ret;

		g_assert(CHUNK_STATE_ERROR != attr->state);

		/*
		 * Copy avoidance: if the data we got fits into the current chunk size,
		 * then we don't have to parse anything: all the data belong to the
		 * current chunk, so we can simply pass them to the upper layer.
		 */

		if (CHUNK_STATE_DATA == attr->state) {
			pmsg_t *nmb;

			nmb = pmsg_clone(mb);
			if (size < attr->data_remain) {
				/* The complete chunk data is forwarded to the upper layer */
				mb->m_rptr += size;
				attr->data_remain -= size;
			} else {
				/* Only the first ``data_remain'' bytes are forwarded */
				mb->m_rptr += attr->data_remain;
				nmb->m_wptr =
					deconstify_pointer(&nmb->m_rptr[attr->data_remain]);
				attr->data_remain = 0;
				attr->state = CHUNK_STATE_DATA_CRLF;
			}
			if (GNET_PROPERTY(rx_debug) > 9)
				g_debug("dechunk_data: returning chunk of %u bytes",
					pmsg_size(nmb));
			return nmb;
		}

		g_assert(size > 0);
		g_assert(CHUNK_STATE_DATA != attr->state);

		/*
		 * Parse chunk headers
		 */

		ret = parse_chunk(rx, src, size, &error_str);
		if (0 == ret) {
			/*
			 * We can't continue if we meet a dechunking error.  Signal
			 * our user so that the connection is terminated.
			 */

			errno = EIO;
			attr->cb->chunk_error(rx->owner,
					"dechunk() failed: %s", error_str);
			g_warning("dechunk_data(): %s", error_str);
			break;
		}
		g_assert(ret <= size);
		size -= ret;
		mb->m_rptr += ret;		/* Read that far */
	}

	return NULL;				/* No more data */
}

/***
 *** Polymorphic routines.
 ***/

/**
 * Initialize the driver.
 */
static void *
rx_chunk_init(rxdrv_t *rx, const void *args)
{
	const struct rx_chunk_args *rargs = args;
	struct attr *attr;

	rx_check(rx);
	g_assert(rargs->cb != NULL);

	WALLOC(attr);
	attr->cb = rargs->cb;
	attr->flags = 0;
	attr->data_remain = 0;
	attr->hex_pos = 0;
	attr->state = CHUNK_STATE_SIZE;

	rx->opaque = attr;

	return rx;		/* OK */
}

/**
 * Get rid of the driver's private data.
 */
static void
rx_chunk_destroy(rxdrv_t *rx)
{
	struct attr *attr = rx->opaque;

	WFREE(attr);
	rx->opaque = NULL;
}

/**
 * Got data from lower layer.
 */
static bool
rx_chunk_recv(rxdrv_t *rx, pmsg_t *mb)
{
	struct attr *attr = rx->opaque;
	bool error = FALSE;
	pmsg_t *imb;		/* Dechunked message */

	rx_check(rx);
	g_assert(mb);

	/*
	 * Dechunk the stream, forwarding dechunked data to the upper layer.
	 * At any time, a packet we forward can cause the reception to be
	 * disabled, in which case we must stop.
	 */

	while ((attr->flags & IF_ENABLED) && (imb = dechunk_data(rx, mb))) {
		error = !(*rx->data.ind)(rx, imb);
		if (error)
			break;
	}

	pmsg_free(mb);

	/*
	 * When we encountered the end of the stream, let them know.
	 */

	if ((attr->flags & IF_ENABLED) && attr->state == CHUNK_STATE_END)
		attr->cb->chunk_end(rx->owner);

	return !error;
}

/**
 * Enable reception of data.
 */
static void
rx_chunk_enable(rxdrv_t *rx)
{
	struct attr *attr = (struct attr *) rx->opaque;

	attr->flags |= IF_ENABLED;
}

/**
 * Disable reception of data.
 */
static void
rx_chunk_disable(rxdrv_t *rx)
{
	struct attr *attr = rx->opaque;

	attr->flags &= ~IF_ENABLED;
}

static const struct rxdrv_ops rx_chunk_ops = {
	rx_chunk_init,		/**< init */
	rx_chunk_destroy,	/**< destroy */
	rx_chunk_recv,		/**< recv */
	NULL,				/**< recvfrom */
	rx_chunk_enable,	/**< enable */
	rx_chunk_disable,	/**< disable */
	rx_no_source,		/**< bio_source */
};

const struct rxdrv_ops *
rx_chunk_get_ops(void)
{
	return &rx_chunk_ops;
}

/* vi: set ts=4 sw=4 cindent: */
