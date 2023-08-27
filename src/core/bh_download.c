/*
 * Copyright (c) 2005, Raphael Manfredi
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
 * Handles the client-side of the Browse Host function.
 *
 * @author Raphael Manfredi
 * @date 2005
 */

#include "common.h"

#include "bh_download.h"
#include "downloads.h"
#include "bsched.h"
#include "dump.h"
#include "gnet_stats.h"
#include "rx_inflate.h"

#include "g2/frame.h"
#include "g2/msg.h"
#include "g2/tfmt.h"
#include "g2/tree.h"

#include "lib/atoms.h"
#include "lib/endian.h"
#include "lib/halloc.h"
#include "lib/pmsg.h"
#include "lib/stringify.h"	/* For plural */
#include "lib/walloc.h"

#include "lib/override.h"	/* Must be the last header included */

#define BH_DL_DEFAULT_SIZE	4096	/* Default data buffer size */
#define BH_DL_MAX_SIZE		65536	/* Maximum payload size we allow */

struct browse_ctx {
	void *owner;				/**< Download owning us */
	rxdrv_t *rx;				/**< RX stack top */
	gnet_host_t host;			/**< Host we're browsing, for logging */
	gnet_search_t sh;			/**< Search ID to which hits are given */
	const char *vendor;			/**< Vendor version string (atom) */
	gnutella_header_t header;	/**< Received header */
	char *data;					/**< Where payload data is stored */
	uint data_size;				/**< Size of data buffer */
	uint pos;					/**< Reading position */
	uint32 size;				/**< Payload size */
	unsigned has_header:1;		/**< True when header has been read */
	unsigned closed:1;			/**< Set when search is closed */
	unsigned g2:1;				/**< Expecting G2 hits */
};

/**
 * Initialize the browse host context.
 */
struct browse_ctx *
browse_host_dl_create(void *owner, gnet_host_t *host, gnet_search_t sh)
{
	struct browse_ctx *bc;

	WALLOC0(bc);
	bc->owner = owner;
	gnet_host_copy(&bc->host, host);
	bc->sh = sh;

	return bc;
}

/**
 * Check sure the browse-host context is for the proper search ID.
 */
bool
browse_host_dl_for_search(struct browse_ctx *bc, gnet_search_t sh)
{
	g_assert(bc != NULL);

	return bc->sh == sh;
}

/**
 * Read data from the message buffer we just received.
 *
 * @return TRUE whilst we think there is more data to read in the buffer.
 */
static bool
browse_data_read(struct browse_ctx *bc, pmsg_t *mb)
{
	/*
	 * Read header if it has not been fully fetched yet.
	 */

	if (!bc->has_header) {
		char *w = cast_to_pointer(&bc->header);

		g_assert(sizeof bc->header >= bc->pos);
		bc->pos += pmsg_read(mb, &w[bc->pos], sizeof bc->header - bc->pos);
		if (bc->pos < sizeof bc->header)
			return FALSE;

		bc->has_header = TRUE;		/* We have read the full header */

		bc->size = gnutella_header_get_size(&bc->header);

		/*
		 * Protect against too large data.
		 */

		if (bc->size > BH_DL_MAX_SIZE) {
			download_stop(bc->owner, GTA_DL_ERROR, "Gnutella payload too big");
			return FALSE;
		}

		/*
		 * Resize payload buffer if needed
		 */

		if (bc->size > bc->data_size) {
			bc->data_size = MAX(BH_DL_DEFAULT_SIZE, bc->size);
			bc->data = hrealloc(bc->data, bc->data_size);
		}

		bc->pos = 0;

		/* FALL THROUGH */
	}

	/*
	 * Read message data, if any.
	 */

	if (bc->size) {
		g_assert(bc->size >= bc->pos);
		bc->pos += pmsg_read(mb, &bc->data[bc->pos], bc->size - bc->pos);
	}

	if (bc->pos >= bc->size) {
		bc->has_header = FALSE;		/* For next message */
		bc->pos = 0;
		return TRUE; /* Must process message and continue */
	} else {
		return FALSE;
	}
}

/**
 * Process the whole message we read.
 *
 * @return FALSE if an error was reported (processing aborted).
 */
static bool
browse_data_process(struct browse_ctx *bc)
{
	gnutella_node_t *n;

	/*
	 * We accept only query hits.
	 */

	if (gnutella_header_get_function(&bc->header) != GTA_MSG_SEARCH_RESULTS) {
		download_stop(bc->owner, GTA_DL_ERROR, "Non query-hit received");
		return FALSE;
	}

	n = node_browse_prepare(
		&bc->host, bc->vendor, &bc->header, bc->data, bc->size);

	dump_rx_packet(n);
	gnet_stats_count_received_header(n);
	gnet_stats_count_received_payload(n, bc->data);

	search_browse_results(n, bc->sh, NULL);
	node_browse_cleanup(n);

	return TRUE;
}

/**
 * Read data from the message buffer we just received.
 *
 * @return TRUE whilst we think there is more data to read in the buffer.
 */
static bool
browse_data_g2_read(struct browse_ctx *bc, pmsg_t *mb)
{
	int r;

	/*
	 * Grabbing of the G2 frame works thusly:
	 *
	 * As long as bc->has_header is FALSE, we read bytes until we have enough
	 * to figure out the length of the whole frame.
	 */

	if (!bc->has_header) {
		char *w;
		size_t len;

		if G_UNLIKELY(NULL == bc->data) {
			g_assert(0 == bc->data_size);
			bc->data_size = BH_DL_DEFAULT_SIZE;
			bc->data = halloc(bc->data_size);
		}

		w = bc->data;

		/*
		 * We need 4 bytes at most to completely determine the size of the
		 * whole G2 frame.
		 */

		if (0 == bc->pos) {
			r = pmsg_read(mb, w, 4);
			if G_UNLIKELY(0 == r)
				return FALSE;		/* Reached end of buffer */
			bc->pos += r;
			len = g2_frame_whole_length(w, bc->pos);
			if (0 == len)
				return FALSE;		/* Not read enough to compute length */
		} else {
			for (;;) {
				g_assert(bc->pos < sizeof bc->header);

				r = pmsg_read(mb, &w[bc->pos], 1);
				bc->pos += r;
				len = g2_frame_whole_length(w, bc->pos);
				if (len != 0)
					break;
				if (0 == r)
					return FALSE;	/* Reached end of buffer */
				if (bc->pos >= sizeof bc->header) {
					download_stop(bc->owner, GTA_DL_ERROR, "Garbled input");
					return FALSE;
				}
			}
		}

		/*
		 * If the length is 1, we reached the "end of stream" byte.
		 */

		if G_UNLIKELY(1 == len) {
			download_stop(bc->owner, GTA_DL_ERROR, "Got End-of-Stream byte");
			return FALSE;
		}

		/*
		 * Protect against too large data.
		 */

		if (len > BH_DL_MAX_SIZE) {
			download_stop(bc->owner, GTA_DL_ERROR, "G2 payload too big");
			return FALSE;
		}

		bc->has_header = TRUE;		/* We have read the full header */
		bc->size = len;

		/*
		 * Resize payload buffer if needed
		 */

		if (bc->size > bc->data_size) {
			bc->data_size = MAX(BH_DL_DEFAULT_SIZE, bc->size);
			bc->data = hrealloc(bc->data, bc->data_size);
		}

		/* FALL THROUGH */
	}

	/*
	 * Read the whole frame data.
	 */

	r = pmsg_read(mb, bc->data + bc->pos, bc->size - bc->pos);

	bc->pos += r;

	if (bc->pos >= bc->size) {
		bc->has_header = FALSE;		/* For next message */
		bc->pos = 0;
		return TRUE;				 /* Must process message and continue */
	} else {
		return FALSE;
	}
}

/**
 * Process the whole message we read.
 *
 * @return FALSE if an error was reported (processing aborted).
 */
static bool
browse_data_g2_process(struct browse_ctx *bc)
{
	gnutella_node_t *n;
	g2_tree_t *t;
	size_t plen;

	/*
	 * Deserialize the message.
	 */

	t = g2_frame_deserialize(bc->data, bc->size, &plen, FALSE);

	if (NULL == t) {
		download_stop(bc->owner, GTA_DL_ERROR, "Cannot deserialize message");
		return FALSE;
	} else if (plen != bc->size) {
		download_stop(bc->owner, GTA_DL_ERROR, "Incomplete deserialization");
		g2_tree_free_null(&t);
		return FALSE;
	}

	/*
	 * We accept only query hits (/QH2), ignore the rest.
	 *
	 * Contratry to Gnutella host browsing, G2 hosts can send other messages
	 * when being browsed, such as /UPROD, or other /VF (undocumented anyway),
	 * which we need to ignore.
	 */

	if (G2_MSG_QH2 != g2_msg_name_type(g2_tree_name(t))) {
		if (GNET_PROPERTY(download_debug) || GNET_PROPERTY(log_dropped_g2)) {
			g_debug("BROWSE %s(): ignoring unexpected /%s (%u byte%s) from %s",
				G_STRFUNC, g2_tree_name(t), PLURAL(bc->size),
				gnet_host_to_string(&bc->host));
			if (GNET_PROPERTY(log_bad_g2))
				g2_tfmt_tree_dump(t, stderr, G2FMT_O_PAYLEN | G2FMT_O_PAYLOAD);
		}
		goto done;
	}

	n = node_browse_prepare(&bc->host, bc->vendor, NULL, bc->data, bc->size);

	dump_rx_packet(n);
	gnet_stats_count_received_payload(n, bc->data);

	search_browse_results(n, bc->sh, t);
	node_browse_cleanup(n);

done:
	g2_tree_free_null(&t);
	return TRUE;
}

/**
 * RX data indication callback used to give us some new Gnet traffic in a
 * low-level message structure (which can contain several Gnet messages).
 *
 * @return FALSE if an error occurred.
 */
static bool
browse_data_ind(rxdrv_t *rx, pmsg_t *mb)
{
	struct browse_ctx *bc = rx_owner(rx);
	struct download *d;
	bool error = FALSE;

	if (bc->g2) {
		while (browse_data_g2_read(bc, mb)) {
			if (!browse_data_g2_process(bc)) {
				error = TRUE;
				break;
			}
		}
	} else {
		while (browse_data_read(bc, mb)) {
			if (!browse_data_process(bc)) {
				error = TRUE;
				break;
			}
		}
	}

	/*
	 * When we receive browse-host data with an advertised size, the remote
	 * end will simply stop emitting data when we're done and could maintain
	 * the HTTP connection alive.  Therefore, since we don't intend to
	 * issue any more request on that connection, we must check for completion.
	 *
	 * When chunked data is received (unknown size), the last chunk will
	 * trigger completion via an RX-callback invoked from the dechunking
	 * layer, but in that case it is harmless to make the call anyway.
	 */

	d = bc->owner;
	download_check(d);

	if (!error) {
		download_maybe_finished(d);
		download_check(d);
	}

	pmsg_free(mb);
	return !error && DOWNLOAD_IS_RUNNING(d);
}

/***
 *** RX link callbacks
 ***/

static void
browse_rx_given(void *o, ssize_t r)
{
	struct browse_ctx *bc = o;

	download_data_received(bc->owner, r);
}

static G_PRINTF(2, 3) void
browse_rx_error(void *o, const char *reason, ...)
{
	struct browse_ctx *bc = o;
	va_list args;

	va_start(args, reason);
	download_stop_v(bc->owner, GTA_DL_ERROR, reason, args);
	va_end(args);
}

static void
browse_rx_got_eof(void *o)
{
	struct browse_ctx *bc = o;

	download_got_eof(bc->owner);
}

static void
browse_rx_done(void *o)
{
	struct browse_ctx *bc = o;

	download_rx_done(bc->owner);
}

static const struct rx_link_cb browse_rx_link_cb = {
	browse_rx_given,		/* add_rx_given */
	browse_rx_error,		/* read_error */
	browse_rx_got_eof,		/* got_eof */
};

static const struct rx_chunk_cb browse_rx_chunk_cb = {
	browse_rx_error,		/* chunk_error */
	browse_rx_done,			/* chunk_end */
};

static const struct rx_inflate_cb browse_rx_inflate_cb = {
	NULL,					/* add_rx_inflated */
	browse_rx_error,		/* inflate_error */
};

/**
 * Prepare reception of query hit data by building an appropriate RX stack.
 *
 * @return TRUE if we may continue with the download, FALSE if the search
 * was already closed in the GUI.
 */
bool
browse_host_dl_receive(
	struct browse_ctx *bc, gnet_host_t *host, wrap_io_t *wio,
	const char *vendor, uint32 flags)
{
	g_assert(bc != NULL);

	if (bc->closed)
		return FALSE;

	gnet_host_copy(&bc->host, host);
	bc->vendor = atom_str_get(vendor);

	/*
	 * Freeing of the RX stack must be asynchronous: each time we establish
	 * a new connection, dismantle the previous stack.  Otherwise the RX
	 * stack will be freed when the corresponding download structure is
	 * reclaimed.
	 */

	if (bc->rx != NULL) {
		rx_free(bc->rx);
		bc->rx = NULL;
	}

	{
		struct rx_link_args args;

		args.cb = &browse_rx_link_cb;
		args.bws = bsched_in_select_by_addr(gnet_host_get_addr(&bc->host));
		args.wio = wio;

		bc->rx = rx_make(bc, &bc->host, rx_link_get_ops(), &args);
	}

	if (flags & BH_DL_CHUNKED) {
		struct rx_chunk_args args;

		args.cb = &browse_rx_chunk_cb;

		bc->rx = rx_make_above(bc->rx, rx_chunk_get_ops(), &args);
	}

	if (flags & BH_DL_INFLATE) {
		struct rx_inflate_args args;

		args.cb = &browse_rx_inflate_cb;

		bc->rx = rx_make_above(bc->rx, rx_inflate_get_ops(), &args);
	}

	bc->g2 = booleanize(flags & BH_DL_G2);

	rx_set_data_ind(bc->rx, browse_data_ind);
	rx_enable(bc->rx);

	if (GNET_PROPERTY(download_debug)) {
		g_debug("BROWSE %s(): setup %s%s%slink with %s",
			G_STRFUNC, bc->g2 ? "G2 " : "",
			(flags & BH_DL_INFLATE) ? "deflated " : "",
			(flags & BH_DL_CHUNKED) ? "chunked " : "",
			gnet_host_to_string(&bc->host));
	}

	return TRUE;
}

/**
 * Fetch the I/O source of the RX stack.
 */
struct bio_source *
browse_host_io_source(struct browse_ctx *bc)
{
	g_assert(bc != NULL);
	g_assert(bc->rx != NULL);

	return rx_bio_source(bc->rx);
}

/**
 * Received data from outside the RX stack.
 */
void
browse_host_dl_write(struct browse_ctx *bc, char *data, size_t len)
{
	pdata_t *db;
	pmsg_t *mb;

	g_assert(bc->rx != NULL);

	/*
	 * Prepare data buffer to feed the RX stack.
	 */

	db = pdata_allocb_ext(data, len, pdata_free_nop, NULL);
	mb = pmsg_alloc(PMSG_P_DATA, db, 0, len);

	/*
	 * The message is given to the RX stack, and it will be freed by
	 * the last function consuming it.
	 */

	rx_recv(rx_bottom(bc->rx), mb);
}

/**
 * Disable the RX stack.
 */
void
browse_host_dl_close(struct browse_ctx *bc)
{
	g_assert(bc != NULL);

	if (bc->rx) {
		rx_disable(bc->rx);
	}
}

/**
 * Terminate host browsing.
 */
void
browse_host_dl_free(struct browse_ctx **ptr)
{
	struct browse_ctx *bc = *ptr;

	if (bc) {
		atom_str_free_null(&bc->vendor);
		if (bc->rx) {
			rx_free(bc->rx);
			bc->rx = NULL;
		}
		if (!bc->closed) {
			search_dissociate_browse(bc->sh, bc->owner);
		}
		HFREE_NULL(bc->data);
		WFREE(bc);
		*ptr = NULL;
	}
}

/**
 * Signal that the corresponding search was closed.
 */
void
browse_host_dl_search_closed(struct browse_ctx *bc, gnet_search_t sh)
{
	g_assert(bc != NULL);
	g_assert(bc->sh == sh);

	bc->closed = TRUE;
}

/* vi: set ts=4 sw=4 cindent: */
