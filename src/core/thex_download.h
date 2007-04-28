/*
 * $Id$
 *
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
 *      59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
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

typedef void (*thex_download_success_cb)(
				const struct sha1 *, const struct tth *,
				const struct tth *leaves, size_t num_leaves);

struct thex_download *thex_download_create(gpointer owner,
							struct gnutella_host *host,
							const struct sha1 *,
							const struct tth *,
							filesize_t filesize,
							thex_download_success_cb callback);

void thex_download_free(struct thex_download **ptr);
void thex_download_write(struct thex_download *, gchar *data, size_t len);
gboolean thex_download_receive(struct thex_download *,
			struct gnutella_host *host, struct wrap_io *wio,
			guint32 flags);
struct bio_source *thex_download_io_source(struct thex_download *);
void thex_download_close(struct thex_download *);
void thex_download_finished(struct thex_download *);
const struct sha1 *thex_download_get_sha1(const struct thex_download *);

#endif /* _core_thex_download_h_ */

/* vi: set ts=4 sw=4 cindent: */
