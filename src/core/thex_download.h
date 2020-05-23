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
 * Handles downloads of THEX data.
 *
 * @author Raphael Manfredi
 * @date 2005
 */

#ifndef _core_thex_download_h_
#define _core_thex_download_h_

#include "common.h"

/**
 * Flags for thex_download_open().
 */
#define THEX_DOWNLOAD_F_INFLATE	(1 << 0)	/**< Inflate input */
#define THEX_DOWNLOAD_F_GUNZIP	(1 << 1)	/**< gunzip input */
#define THEX_DOWNLOAD_F_CHUNKED	(1 << 2)	/**< Getting chunked data */

/*
 * Public interface.
 */

struct bio_source;
struct gnutella_host;
struct sha1;
struct tth;
struct thex_download;
struct wrap_io;

struct thex_download *thex_download_create(void *owner,
							struct gnutella_host *host,
							const struct sha1 *,
							const struct tth *,
							filesize_t filesize);

void thex_download_free(struct thex_download **ptr);
void thex_download_write(struct thex_download *, char *data, size_t len);
bool thex_download_receive(struct thex_download *,
			filesize_t content_length,
			struct gnutella_host *host, struct wrap_io *wio, uint32 flags);
struct bio_source *thex_download_io_source(struct thex_download *);
void thex_download_close(struct thex_download *);
bool thex_download_finished(struct thex_download *ctx);

const struct sha1 *thex_download_get_sha1(const struct thex_download *);
const struct tth *thex_download_get_tth(const struct thex_download *ctx);
size_t thex_download_get_leaves(const struct thex_download *ctx,
	const struct tth **leaves_ptr);

#endif /* _core_thex_download_h_ */

/* vi: set ts=4 sw=4 cindent: */
