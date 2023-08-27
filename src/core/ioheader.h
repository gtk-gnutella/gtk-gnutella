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
 * Asynchronous I/O header parsing routines.
 *
 * @author Raphael Manfredi
 * @date 2002-2003
 */

#ifndef _core_ioheader_h_
#define _core_ioheader_h_

#include "common.h"
#include "bsched.h"

struct io_header;
struct header;
struct getline;
struct gnutella_socket;

/**
 * This structure holds all the per-resource callbacks that can be used
 * during header processing in case something goes wrong.
 */
struct io_error {
	void (*line_too_long)(void *resource, struct header *header);
	void (*header_error_tell)(void *resource, int error);	/**< Optional */
	void (*header_error)(void *resource, int error);
	void (*input_exception)(void *resource, struct header *header);
	void (*input_buffer_full)(void *resource);
	void (*header_read_error)(void *resource, int error);
	void (*header_read_eof)(void *resource, struct header *header);
	void (*header_extra_data)(void *resource, struct header *header);
};

typedef void (*io_done_cb_t)(void *resource, struct header *header);
typedef void (*io_start_cb_t)(void *resource);

/*
 * Parsing flags.
 */

#define IO_HEAD_ONLY	0x00000001	/**< No data expected after EOH */
#define IO_SAVE_FIRST	0x00000002	/**< Save 1st line in socket's getline */
#define IO_SINGLE_LINE	0x00000004	/**< Get one line only, then process */
#define IO_3_WAY		0x00000008	/**< In 3-way handshaking */
#define IO_SAVE_HEADER	0x00000010	/**< Save header text for later perusal */

/*
 * Public interface
 */

void io_free(void *opaque);
struct header *io_header(const void *opaque);
struct getline *io_getline(const void *opaque);
char *io_gettext(const void *opaque);
uint io_get_read_bytes(const void *opaque);
void io_add_header(void *opaque);

void io_get_header(
	void *resource,				/**< Resource for which we're reading headers */
	void **io_opaque,			/**< Field address in resource's structure */
	bsched_bws_t bws,			/**< B/w scheduler from which we read */
	struct gnutella_socket *s,	/**< Socket from which we're reading */
	int flags,					/**< I/O parsing flags */
	io_done_cb_t done,			/**< Mandatory: final callback when all done */
	io_start_cb_t start,		/**< Optional: called when reading 1st byte */
	const struct io_error *error);	/**< Mandatory: error callbacks */

void io_continue_header(
	void *opaque,				/**< Existing header parsing context */
	int flags,					/**< New I/O parsing flags */
	io_done_cb_t done,			/**< Mandatory: final callback when all done */
	io_start_cb_t start);		/**< Optional: called when reading 1st byte */

#endif	/* _core_ioheader_h_ */

/* vi: set ts=4 sw=4 cindent: */

