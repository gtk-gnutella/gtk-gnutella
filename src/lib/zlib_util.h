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
 * @ingroup lib
 * @file
 *
 * Zlib wrapper functions.
 *
 * @author Raphael Manfredi
 * @date 2002-2003
 */

#ifndef _zlib_util_h_
#define _zlib_util_h_

#include "common.h"

/**
 * Incremental deflater stream.
 */
typedef struct  {
	gconstpointer in;	/**< Buffer being compressed */
	gint inlen;			/**< Length of input buffer */
	gpointer out;		/**< Compressed data */
	gint outlen;		/**< Length of ouput buffer */
	gint inlen_total;	/**< Total input length seen */
	gpointer opaque;	/**< Internal data structures */
	gboolean allocated;	/**< Whether output buffer was allocated or static */
	gboolean closed;	/**< Whether the stream was closed */
} zlib_deflater_t;

#define zlib_deflater_out(z)	((z)->out)
#define zlib_deflater_outlen(z)	((z)->outlen)
#define zlib_deflater_inlen(z)	((z)->inlen_total)
#define zlib_deflater_closed(z)	((z)->closed)

/*
 * Public interface.
 */

const gchar *zlib_strerror(gint errnum);

zlib_deflater_t *zlib_deflater_make(gconstpointer data, gint len, gint level);
zlib_deflater_t *zlib_deflater_make_into(
	gconstpointer data, gint len, gpointer dest, gint destlen, gint level);
gint zlib_deflate(zlib_deflater_t *zd, gint amount);
gboolean zlib_deflate_data(zlib_deflater_t *zd, gconstpointer data, gint len);
gboolean zlib_deflate_close(zlib_deflater_t *zd);
void zlib_deflater_free(zlib_deflater_t *zd, gboolean output);

gpointer zlib_uncompress(gconstpointer data, gint len, gulong uncompressed_len);
gint zlib_inflate_into(gconstpointer data, gint len, gpointer out, gint *outlen);
gboolean zlib_is_valid_header(gconstpointer data, gint len);

void zlib_free_func(gpointer unused_opaque, gpointer p);
gpointer zlib_alloc_func(gpointer unused_opaque, guint n, guint m);

#endif	/* _zlib_util_h_ */

/* vi: set ts=4 sw=4 cindent: */

