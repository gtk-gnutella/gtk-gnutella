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

#ifndef _zlib_util_h_
#define _zlib_util_h_

#include <glib.h>

/*
 * Incremental deflater stream.
 */
typedef struct  {
	gpointer in;			/* Buffer being compressed */
	gint inlen;				/* Length of input buffer */
	gpointer out;			/* Compressed data */
	gint outlen;			/* Length of ouput buffer */
	gpointer opaque;		/* Internal data structures */
} zlib_deflater_t;

#define zlib_deflater_out(z)	((z)->out)
#define zlib_deflater_outlen(z)	((z)->outlen)

/*
 * Public interface.
 */

gchar *zlib_strerror(gint errnum);

zlib_deflater_t *zlib_deflater_make(gpointer data, gint len, gint level);
gint zlib_deflate(zlib_deflater_t *zd, gint amount);
void zlib_deflater_free(zlib_deflater_t *zd, gboolean output);

gpointer zlib_uncompress(gpointer data, gint len, gint uncompressed_len);

#endif	/* _zlib_util_h_ */

/* vi: set ts=4: */

