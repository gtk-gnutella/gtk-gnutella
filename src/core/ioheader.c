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
 * Asynchronous I/O header parsing.
 *
 * @author Raphael Manfredi
 * @date 2002-2003
 */

#include "common.h"

#include "ioheader.h"
#include "sockets.h"
#include "bsched.h"

#include "lib/getline.h"
#include "lib/header.h"
#include "lib/inputevt.h"
#include "lib/log.h"		/* For log_printable() */
#include "lib/misc.h"
#include "lib/str.h"
#include "lib/walloc.h"

#include "if/gnet_property_priv.h"

#include "lib/override.h"	/* Must be the last header included */

#define DFLT_SIZE	2048	/**< Expected headers should not be larger */

enum io_opaque_magic { IO_OPAQUE_MAGIC = 0x578da161U };

/**
 * This structure is used to encapsulate the various arguments required
 * by the header parsing I/O callbacks.
 */
struct io_header {
	enum io_opaque_magic magic;
	void *resource;					/**< Resource for which we're parsing */
	void **io_opaque;				/**< Where we're referenced in resource */
	struct gnutella_socket *socket;	/**< Socket on which we're reading */
	bsched_bws_t bws;				/**< Bandwidth scheduler to use */
	header_t *header;
	getline_t *getline;
	const struct io_error *error;	/**< Error callbacks */
	io_done_cb_t process_header;	/**< Called when all headers are read */
	io_start_cb_t header_read_start;/**< Called when reading first byte */
	str_t *text;					/**< Full header text */
	uint read_bytes;				/**< Amount of bytes read */
	int flags;
};

/**
 * Internal consistency checks.
 */
static void
io_check(const void *opaque)
{
	const struct io_header *ih = opaque;

	g_assert(ih);
	g_assert(IO_OPAQUE_MAGIC == ih->magic);
	g_assert(ih->io_opaque);
	g_assert((char *) ih->io_opaque > (char *) ih->resource);
	g_assert(((char *) ih->io_opaque - (char *) ih->resource) < 1024);
	g_assert(*ih->io_opaque == opaque);
}

/**
 * Free the opaque I/O data.
 */
void
io_free(void *opaque)
{
	struct io_header *ih = opaque;

	io_check(opaque);
	*ih->io_opaque = NULL;

	if (ih->header)
		header_free(ih->header);
	getline_free_null(&ih->getline);
	str_destroy_null(&ih->text);

	ih->magic = 0;
	WFREE(ih);
}

/**
 * Fetch header structure from opaque I/O data.
 */
struct header *
io_header(const void *opaque)
{
	const struct io_header *ih = opaque;

	io_check(opaque);

	return ih->header;
}

/**
 * Fetch getline structure from opaque I/O data.
 */
struct getline *
io_getline(const void *opaque)
{
	const struct io_header *ih = opaque;

	io_check(opaque);

	return ih->getline;
}

/**
 * Fetch header text as C string from opaque I/O data.
 *
 * It is up to the caller to strdup the data if needed.
 * The returned data will be freed when io_free() is called.
 */
char *
io_gettext(const void *opaque)
{
	const struct io_header *ih = opaque;

	io_check(opaque);
	g_assert(ih->flags & IO_SAVE_HEADER);	/* They must have requested this */
	g_assert(ih->text);

	return str_2c(ih->text);
}

/**
 * How many bytes we received so far during header parsing.
 */
uint
io_get_read_bytes(const void *opaque)
{
	const struct io_header *ih = opaque;

	io_check(opaque);

	return ih->read_bytes;
}

/**
 * This routine is called to parse the input buffer (the socket's buffer),
 * a line at a time, until EOH is reached.
 */
static void
io_header_parse(struct io_header *ih)
{
	struct gnutella_socket *s = ih->socket;
	header_t *header = ih->header;
	size_t parsed;
	int error;

	/*
	 * Read header a line at a time.  We have exacly s->pos chars to handle.
	 * NB: we're using a goto label to loop over.
	 */

nextline:
	switch (getline_read(ih->getline, s->buf, s->pos, &parsed)) {
	case READ_OVERFLOW:
		g_warning("%s(): line too long, disconnecting from %s",
			G_STRFUNC, host_addr_to_string(s->addr));
		if (log_printable(LOG_STDERR)) {
			dump_hex(stderr, "Leading Data", s->buf, MIN(s->pos, 256));
			fprintf(stderr, "------ Header Dump:\n");
			header_dump(stderr, header, "-----");
		}
		(*ih->error->line_too_long)(ih->resource, header);
		return;
		/* NOTREACHED */
	case READ_DONE:
		if (s->pos != parsed)
			memmove(s->buf, &s->buf[parsed], s->pos - parsed);
		s->pos -= parsed;
		break;
	case READ_MORE:		/* ok, but needs more data */
		g_assert(parsed == s->pos);
		s->pos = 0;
		return;
	}

	/*
	 * We come here everytime we get a full header line.
	 */

	if (ih->flags & IO_SAVE_HEADER) {
		/*
		 * Make sure we get an exact copy of the header data, in the way
		 * we read them.  However, we insert a "\n" at the end of the
		 * line instead of the "\r\n" because the data is only meant for
		 * tracing / debugging, and we don't really care about the "\r".
		 *		--RAM, 2004-08-02
		 */

		g_assert(ih->text != NULL);
		str_cat_len(ih->text,
			getline_str(ih->getline), getline_length(ih->getline));
		str_putc(ih->text, '\n');
	}

	if (ih->flags & IO_SAVE_FIRST) {
		/*
		 * Save status line away in socket's "getline" object, then clear
		 * the fact that we're expecting a status line and continue to get
		 * the following header lines.
		 */

		g_assert(NULL == s->getline);
		s->getline = getline_make(getline_length(ih->getline) + 1);
		getline_copy(ih->getline, s->getline);
		getline_reset(ih->getline);
		ih->flags &= ~IO_SAVE_FIRST;
		goto nextline;
	}

	if (ih->flags & IO_SINGLE_LINE) {
		/*
		 * Call processing routine immediately, then terminate processing.
		 * It is up to the callback to cleanup the I/O structure.
		 */

		g_assert(s->gdk_tag);

		socket_evt_clear(s);

		ih->process_header(ih->resource, ih->header);
		return;
	}

	error = header_append(header,
		getline_str(ih->getline), getline_length(ih->getline));
	
	switch (error) {
	case HEAD_OK:
		getline_reset(ih->getline);
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
		g_warning("%s(): %s, disconnecting from %s",
			G_STRFUNC, header_strerror(error), host_addr_to_string(s->addr));
		if (log_printable(LOG_STDERR)) {
			fprintf(stderr, "------ Header Dump:\n");
			header_dump(stderr, header, "-----");
			dump_hex(stderr, "Header Line", getline_str(ih->getline),
				MIN(getline_length(ih->getline), 128));
		}
		(*ih->error->header_error)(ih->resource, error);
		return;
		/* NOTREACHED */
	default:					/* Error, but try to continue */
		if (GNET_PROPERTY(dbg)) {
			g_warning("%s(): %s, from %s",
				G_STRFUNC, header_strerror(error),
				host_addr_to_string(s->addr));
			if (log_printable(LOG_STDERR)) {
				dump_hex(stderr, "Header Line",
					getline_str(ih->getline), getline_length(ih->getline));
				fprintf(stderr, "------ Header Dump (so far):\n");
				header_dump(stderr, header, "-----");
			}
		}
		getline_reset(ih->getline);
		goto nextline;			/* Go process other lines we may have read */
	}

	/*
	 * We reached the end of headers.
	 */

	if ((ih->flags & IO_HEAD_ONLY) && s->pos) {
        if (GNET_PROPERTY(dbg)) {
            g_debug("remote %s sent extra bytes after headers",
                host_addr_to_string(s->addr));
            dump_hex(stderr, "Extra Data", s->buf, MIN(s->pos, 512));
        }
		(*ih->error->header_extra_data)(ih->resource, ih->header);
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

		socket_evt_clear(s);
	}

	ih->process_header(ih->resource, ih->header);
}

/**
 * This routine is installed as an input callback to read the headers
 * into the socket's buffer.
 *
 * Read data is then handed out to io_header_parse() for analysis.
 */
static void
io_read_data(void *data, int unused_source, inputevt_cond_t cond)
{
	struct io_header *ih = data;
	struct gnutella_socket *s = ih->socket;
	size_t count;
	ssize_t r;

	(void) unused_source;
	g_assert(s != NULL);
	g_assert(s->gdk_tag);			/* I/O callback still registered */

	if (cond & INPUT_EVENT_EXCEPTION) {
		socket_eof(s);
		(*ih->error->input_exception)(ih->resource, ih->header);
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

	g_assert(s->buf_size >= s->pos);
	count = s->buf_size - s->pos;
	if (count < 1) {
		g_warning("%s(): incoming buffer full, disconnecting from %s",
			G_STRFUNC, host_addr_to_string(s->addr));
		dump_hex(stderr, "Leading Data", s->buf, MIN(s->pos, 256));
		(*ih->error->input_buffer_full)(ih->resource);
		return;
	}
	count--; /* -1 to allow trailing NUL */

	/*
	 * Ignore interrupted read syscall (EAGAIN), but signal EOF and other
	 * errors to our client.
	 */

	r = bws_read(ih->bws, &s->wio, &s->buf[s->pos], count);
	if (r == 0) {
		socket_eof(s);
		(*ih->error->header_read_eof)(ih->resource, ih->header);
		return;
	} else if ((ssize_t) -1 == r) {
	  	if (!is_temporary_error(errno)) {
			socket_eof(s);
			(*ih->error->header_read_error)(ih->resource, errno);
		}
		return;
	}

	/*
	 * During the header reading phase, we don't update any "last_update"
	 * kind of field, on purpose.  The timeouts are defined for the whole
	 * connection phase, i.e. until we read the end of the headers.
	 */

	s->pos += r;
	ih->read_bytes += r;

	io_header_parse(ih);
}

/**
 * This routine is only used when doing HTTP pipelining, to be able to
 * process already received network traffic from a connection, which is
 * expected to be found in the socket's buffer.
 *
 * Read data is then handed out to io_header_parse() for analysis.
 */
void
io_add_header(void *opaque)
{
	struct io_header *ih = opaque;
	struct gnutella_socket *s;

	io_check(opaque);

	s = ih->socket;
	g_assert(s != NULL);

	/*
	 * First time we read data, notify them once if needed.
	 */

	if (ih->header_read_start) {
		(*ih->header_read_start)(ih->resource);
		ih->header_read_start = NULL;
	}

	ih->read_bytes += s->pos;
	io_header_parse(ih);
}

/**
 * Setup input callback and context for reading/parsing the header.
 * The I/O parsing context is directly written into the structure.
 *
 * Data is read into the supplied socket's buffer, and then stuffed into
 * the headers, unless the IO_SAVE_FIRST flag is set, in which case the very
 * first line will be copied into the (dynamically allocated) socket's
 * getline buffer.
 */
void
io_get_header(
	void *resource,				/**< Resource for which we're reading headers */
	void **io_opaque,			/**< Field address in resource's structure */
	bsched_bws_t bws,			/**< B/w scheduler from which we read */
	struct gnutella_socket *s,	/**< Socket from which we're reading */
	int flags,					/**< I/O parsing flags */
	io_done_cb_t done,			/**< Mandatory: final callback when all done */
	io_start_cb_t start,		/**< Optional: called when reading 1st byte */
	const struct io_error *error) /**< Mandatory: error callbacks for resource */
{
	struct io_header *ih;

	g_assert(resource);
	g_assert(io_opaque);
	g_assert((char *) io_opaque > (char *) resource);
	g_assert(((char *) io_opaque - (char *) resource) < 1024);
	g_assert(bws < NUM_BSCHED_BWS);
	g_assert(s);
	g_assert(done);
	g_assert(error);

	g_assert(!(flags & IO_HEAD_ONLY) || error->header_extra_data);

	/*
	 * Create and initialize the callback argument used during header reading.
	 */

	WALLOC(ih);
	ih->magic = IO_OPAQUE_MAGIC;
	ih->resource = resource;
	ih->io_opaque = io_opaque;
	ih->getline = getline_make(HEAD_MAX_SIZE);
	ih->socket = s;
	ih->flags = flags;
	ih->bws = bws;
	ih->error = error;
	ih->process_header = done;
	ih->header_read_start = start;
	ih->header = (flags & IO_SINGLE_LINE) ? NULL : header_make();
	ih->text = (flags & IO_SAVE_HEADER) ? str_new(DFLT_SIZE) : NULL;
	ih->read_bytes = 0;

	/*
	 * Associate the structure with the resource.
	 */

	g_assert(*io_opaque == NULL);

	*io_opaque = ih;

	/*
	 * Install the reading callback.
	 */

	g_assert(s->gdk_tag == 0);

	socket_evt_set(s, INPUT_EVENT_RX, io_read_data, ih);

	/*
	 * There may be pending input in the socket buffer, so go handle
	 * it immediately.
	 */

	io_header_parse(ih);
}

/**
 * Called during a 3-way handshaking process.
 *
 * This is used when we're receiving an incoming connection.  Once we have
 * parsed the initial handshaking headers, we're replying and then we have
 * to parse the final handshaking headers from our peer.  That's when
 * this routine is called.
 */
void
io_continue_header(
	void *opaque,				/**< Existing header parsing context */
	int flags,					/**< New I/O parsing flags */
	io_done_cb_t done,			/**< Mandatory: final callback when all done */
	io_start_cb_t start)		/**< Optional: called when reading 1st byte */
{
	struct io_header *ih = opaque;

	io_check(opaque);
	g_assert(ih->flags & IO_3_WAY);
	g_assert(!(flags & IO_3_WAY));

	g_assert(!(flags & IO_HEAD_ONLY) || ih->error->header_extra_data);

	/*
	 * If they no longer wish to save the header, discard any existing
	 * entry.  Otherwise, reset it.
	 *
	 * If they begin to set IO_SAVE_HEADER here, create the data structure
	 * necessary to save the header text.
	 */

	if (ih->text) {
		g_assert(ih->flags & IO_SAVE_HEADER);

		if (flags & IO_SAVE_HEADER)
			str_setlen(ih->text, 0);
		else {
			str_destroy_null(&ih->text);
		}
	} else if (flags & IO_SAVE_HEADER)
		ih->text = str_new(DFLT_SIZE);

	header_reset(ih->header);
	ih->flags = flags;
	ih->process_header = done;
	ih->header_read_start = start;
	ih->read_bytes = 0;
}

/* vi: set ts=4 sw=4 cindent: */
