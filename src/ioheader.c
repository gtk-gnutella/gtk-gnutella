/*
 * $Id$
 *
 * Copyright (c) 2002, Raphael Manfredi
 *
 * Asynchronous I/O header parsing.
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

#include <string.h>
#include <errno.h>
#include <gdk/gdk.h>

#include "ioheader.h"
#include "walloc.h"
#include "header.h"
#include "getline.h"
#include "sockets.h"
#include "misc.h"
#include "bsched.h"

#include "gnet_property.h"
#include "gnet_property_priv.h"

/*
 * This structure is used to encapsulate the various arguments required
 * by the header parsing I/O callbacks.
 */
struct io_header {
	gpointer resource;					/* Resource for which we're parsing */
	gpointer *io_opaque;				/* Where we're referenced in resource */
	struct gnutella_socket *socket;		/* Socket on which we're reading */
	bsched_t *bs;						/* Bandwidth scheduler to use */
	header_t *header;
	getline_t *getline;
	struct io_error *error;				/* Error callbacks */
	io_done_cb_t process_header;		/* Called when all headers are read */
	io_start_cb_t header_read_start;	/* Called when reading first byte */
	gint flags;
};

/*
 * io_free
 *
 * Free the opaque I/O data.
 */
void io_free(gpointer opaque)
{
	struct io_header *ih = (struct io_header *) opaque;

	g_assert(ih);
	g_assert(ih->io_opaque);
	g_assert((gchar *) ih->io_opaque > (gchar *) ih->resource);
	g_assert(((gchar *) ih->io_opaque - (gchar *) ih->resource) < 1024);
	g_assert(*ih->io_opaque == opaque);

	*ih->io_opaque = NULL;

	if (ih->header)
		header_free(ih->header);
	if (ih->getline)
		getline_free(ih->getline);
	
	wfree(ih, sizeof(*ih));
}

/*
 * io_header
 *
 * Fetch header structure from opaque I/O data.
 */
struct header *io_header(gpointer opaque)
{
	struct io_header *ih = (struct io_header *) opaque;

	g_assert(ih);
	g_assert(ih->io_opaque);
	g_assert((gchar *) ih->io_opaque > (gchar *) ih->resource);
	g_assert(((gchar *) ih->io_opaque - (gchar *) ih->resource) < 1024);
	g_assert(*ih->io_opaque == opaque);

	return ih->header;
}

/*
 * io_getline
 *
 * Fetch getline structure from opaque I/O data.
 */
struct getline *io_getline(gpointer opaque)
{
	struct io_header *ih = (struct io_header *) opaque;

	g_assert(ih);
	g_assert(ih->io_opaque);
	g_assert((gchar *) ih->io_opaque > (gchar *) ih->resource);
	g_assert(((gchar *) ih->io_opaque - (gchar *) ih->resource) < 1024);
	g_assert(*ih->io_opaque == opaque);

	return ih->getline;
}

/*
 * io_header_parse
 *
 * This routine is called to parse the input buffer (the socket's buffer),
 * a line at a time, until EOH is reached.
 */
static void io_header_parse(struct io_header *ih)
{
	struct gnutella_socket *s = ih->socket;
	getline_t *getline = ih->getline;
	header_t *header = ih->header;
	guint parsed;
	gint error;

	/*
	 * Read header a line at a time.  We have exacly s->pos chars to handle.
	 * NB: we're using a goto label to loop over.
	 */

nextline:
	switch (getline_read(getline, s->buffer, s->pos, &parsed)) {
	case READ_OVERFLOW:
		g_warning("io_header_parse: line too long, disconnecting from %s",
			ip_to_gchar(s->ip));
		dump_hex(stderr, "Leading Data", s->buffer, MIN(s->pos, 256));
		fprintf(stderr, "------ Header Dump:\n");
		header_dump(header, stderr);
		fprintf(stderr, "------\n");
		(*ih->error->line_too_long)(ih->resource);
		return;
		/* NOTREACHED */
	case READ_DONE:
		if (s->pos != parsed)
			memmove(s->buffer, s->buffer + parsed, s->pos - parsed);
		s->pos -= parsed;
		break;
	case READ_MORE:		/* ok, but needs more data */
	default:
		g_assert(parsed == s->pos);
		s->pos = 0;
		return;
	}

	/*
	 * We come here everytime we get a full header line.
	 */

	if (ih->flags & IO_SAVE_FIRST) {
		/*
		 * Save status line away in socket's "getline" object, then clear
		 * the fact that we're expecting a status line and continue to get
		 * the following header lines.
		 */

		g_assert(s->getline == 0);
		s->getline = getline_make();

		getline_copy(getline, s->getline);
		getline_reset(getline);
		ih->flags &= ~IO_SAVE_FIRST;
		goto nextline;
	}

	if (ih->flags & IO_SINGLE_LINE) {
		/*
		 * Call processing routine immediately, then terminate processing.
		 * It is up to the callback to cleanup the I/O structure.
		 */

		g_assert(s->gdk_tag);

		gdk_input_remove(s->gdk_tag);
		s->gdk_tag = 0;

		ih->process_header(ih->resource, ih->header);
		return;
	}

	error = header_append(header,
		getline_str(getline), getline_length(getline));

	switch (error) {
	case HEAD_OK:
		getline_reset(getline);
		goto nextline;			/* Go process other lines we may have read */
		/* NOTREACHED */
	case HEAD_EOH:				/* We reached the end of the header */
		break;
	case HEAD_TOO_LARGE:
	case HEAD_MANY_LINES:
		if (ih->error->header_error_tell)
			(*ih->error->header_error_tell)(ih->resource, error);
		/* FALL THROUGH */
	case HEAD_EOH_REACHED:
		g_warning("io_header_parse: %s, disconnecting from %s",
			header_strerror(error),	ip_to_gchar(s->ip));
		fprintf(stderr, "------ Header Dump:\n");
		header_dump(header, stderr);
		fprintf(stderr, "------\n");
		dump_hex(stderr, "Header Line", getline_str(getline),
			MIN(getline_length(getline), 128));
		(*ih->error->header_error)(ih->resource, error);
		return;
		/* NOTREACHED */
	default:					/* Error, but try to continue */
		if (dbg) {
			g_warning("io_header_parse: %s, from %s",
				header_strerror(error), ip_to_gchar(s->ip));
			dump_hex(stderr, "Header Line",
				getline_str(getline), getline_length(getline));
			fprintf(stderr, "------ Header Dump (so far):\n");
			header_dump(header, stderr);
			fprintf(stderr, "------\n");
		}
		getline_reset(getline);
		goto nextline;			/* Go process other lines we may have read */
	}

	/*
	 * We reached the end of headers.
	 */

	if ((ih->flags & IO_HEAD_ONLY) && s->pos) {
		g_warning("remote %s sent extra bytes after headers",
			ip_to_gchar(s->ip));
		dump_hex(stderr, "Extra Data", s->buffer, MIN(s->pos, 512));
		(*ih->error->header_extra_data)(ih->resource);
		return;
	}

	/*
	 * If IO_3_WAY is set, then we're dealing with a 3-way handshaking.
	 *
	 * For incoming connections:
	 * . We need to welcome the peer, and it will reply after our welcome,
	 *   so we don't free the io_header structure and the getline/header
	 *   objects yet.  The io_continue_header() will be called to change
	 *   the necessary flags/callbacks.
	 *
	 * . If this is our second call, we'll go to a finalizing callback.
	 *   This will terminate the handshaking process, and cleanup the header
	 *   parsing structure, then install the data handling callback.
	 *
	 * For outgoing connections:
	 * . We simply need to parse our peer's reply and accept/deny the
	 *   connection, so we do through here only once.
	 */

	if (ih->flags & IO_3_WAY)
		getline_reset(ih->getline);	/* Ensure it's empty, ready for reuse */
	else {
		/*
		 * Remove the I/O callback input before invoking the processing
		 * callback: no io_continue_header() is possible, and we're done
		 * with reading header data.
		 */

		g_assert(s->gdk_tag);

		gdk_input_remove(s->gdk_tag);
		s->gdk_tag = 0;
	}

	ih->process_header(ih->resource, ih->header);
}

/*
 * io_read_data
 *
 * This routine is installed as an input callback to read the headers
 * into the socket's buffer.
 *
 * Read data is then handed out to io_header_parse() for analysis.
 */
static void io_read_data(
	gpointer data, gint source, GdkInputCondition cond)
{
	struct io_header *ih = (struct io_header *) data;
	struct gnutella_socket *s = ih->socket;
	guint count;
	gint r;

	if (cond & GDK_INPUT_EXCEPTION) {
		(*ih->error->input_exception)(ih->resource);
		return;
	}

	/*
	 * First time we read data, notify them once if needed.
	 */

	if (ih->header_read_start) {
		(*ih->header_read_start)(ih->resource);
		ih->header_read_start = NULL;
	}

	/*
	 * Read within socket buffer.  Since we feed data to the parsing routine
	 * as we read them, the "input buffer full" condition below should
	 * never happen.
	 */

	count = sizeof(s->buffer) - s->pos - 1;		/* -1 to allow trailing NUL */
	if (count <= 0) {
		g_warning("ih_header_read: incoming buffer full, "
			"disconnecting from %s", ip_to_gchar(s->ip));
		dump_hex(stderr, "Leading Data", s->buffer, MIN(s->pos, 256));
		(*ih->error->input_buffer_full)(ih->resource);
		return;
	}

	/*
	 * Ignore interrupted read syscall (EAGAIN), but signal EOF and other
	 * errors to our client.
	 */

	r = bws_read(ih->bs, s->file_desc, s->buffer + s->pos, count);
	if (r == 0) {
		(*ih->error->header_read_eof)(ih->resource);
		return;
	} else if (r < 0 && errno == EAGAIN)
		return;
	else if (r < 0) {
		(*ih->error->header_read_error)(ih->resource, errno);
		return;
	}

	/*
	 * During the header reading phase, we don't update any "last_update" 
	 * kind of field, on purpose.  The timeouts are defined for the whole
	 * connection phase, i.e. until we read the end of the headers.
	 */

	s->pos += r;

	io_header_parse(ih);
}

/*
 * io_get_header
 *
 * Setup input callback and context for reading/parsing the header.
 * The I/O parsing context is directly written into the structure.
 *
 * Data is read into the supplied socket's buffer, and then stuffed into
 * the headers, unless the IO_SAVE_FIRST flag is set, in which case the very
 * first line will be copied into the (dynamically allocated) socket's
 * getline buffer.
 */
void io_get_header(
	gpointer resource,			/* Resource for which we're reading headers */
	gpointer *io_opaque,		/* Field address in resource's structure */
	bsched_t *bs,				/* B/w scheduler from which we read */
	struct gnutella_socket *s,	/* Socket from which we're reading */
	gint flags,					/* I/O parsing flags */
	io_done_cb_t done,			/* Mandatory: final callback when all done */
	io_start_cb_t start,		/* Optional: called when reading 1st byte */
	struct io_error *error)		/* Mandatory: error callbacks for resource */
{
	struct io_header *ih;

	g_assert(resource);
	g_assert(io_opaque);
	g_assert((gchar *) io_opaque > (gchar *) resource);
	g_assert(((gchar *) io_opaque - (gchar *) resource) < 1024);
	g_assert(bs);
	g_assert(s);
	g_assert(done);
	g_assert(error);

	g_assert(!(flags & IO_HEAD_ONLY) || error->header_extra_data);

	/*
	 * Create and initialize the callback argument used during header reading.
	 */

	ih = walloc(sizeof(*ih));
	ih->resource = resource;
	ih->io_opaque = io_opaque;
	ih->getline = getline_make();
	ih->socket = s;
	ih->flags = flags;
	ih->bs = bs;
	ih->error = error;
	ih->process_header = done;
	ih->header_read_start = start;
	ih->header = (flags & IO_SINGLE_LINE) ? NULL : header_make();

	/*
	 * Associate the structure with the resource.
	 */

	g_assert(*io_opaque == NULL);

	*io_opaque = ih;

	/*
	 * Install the reading callback.
	 */

	g_assert(s->gdk_tag == 0);

	s->gdk_tag = gdk_input_add(s->file_desc,
		(GdkInputCondition) GDK_INPUT_READ | GDK_INPUT_EXCEPTION,
		io_read_data, (gpointer) ih);

	/*
	 * There may be pending input in the socket buffer, so go handle
	 * it immediately.
	 */

	io_header_parse(ih);
}

/*
 * io_continue_header
 *
 * Called during a 3-way handshaking process.
 *
 * This is used when we're receiving an incoming connection.  Once we have
 * parsed the initial handshaking headers, we're replying and then we have
 * to parse the final handshaking headers from our peer.  That's when
 * this routine is called.
 */
void io_continue_header(
	gpointer opaque,			/* Existing header parsing context */
	gint flags,					/* New I/O parsing flags */
	io_done_cb_t done,			/* Mandatory: final callback when all done */
	io_start_cb_t start)		/* Optional: called when reading 1st byte */
{
	struct io_header *ih = (struct io_header *) opaque;

	g_assert(ih);
	g_assert(ih->flags & IO_3_WAY);
	g_assert(!(flags & IO_3_WAY));

	g_assert(!(flags & IO_HEAD_ONLY) || ih->error->header_extra_data);

	header_reset(ih->header);
	ih->flags = flags;
	ih->process_header = done;
	ih->header_read_start = start;
}

