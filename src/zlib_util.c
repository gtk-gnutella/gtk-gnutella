/*
 * $Id$
 *
 * Copyright (c) 2002, Raphael Manfredi
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

#include <zlib.h>
#include <glib.h>

#include "zlib_util.h"

#define OUT_GROW	1024		/* To grow output buffer if it's to short */

/*
 * zlib_strerror
 *
 * Return human-readable error string corresponding to error code `errnum'.
 */
gchar *zlib_strerror(gint errnum)
{
	switch (errnum) {
	case Z_OK:				return "OK";
	case Z_STREAM_END:		return "End of stream";
	case Z_NEED_DICT:		return "Decompressing dictionary needed";
	case Z_ERRNO:			return "Generic zlib error";
	case Z_STREAM_ERROR:	return "Stream error";
	case Z_DATA_ERROR:		return "Data error";
	case Z_MEM_ERROR:		return "Memory error";
	case Z_BUF_ERROR:		return "Buffer error";
	case Z_VERSION_ERROR:	return "Incompatible runtime zlib library";
	default:				break;
	}

	return "Invalid error code";
}

/*
 * zlib_deflater_make
 *
 * Creates an incremental zlib deflater for `len' bytes starting at `data',
 * with specified compression `level'.  If `level' is 0, the default is used.
 *
 * Returns new deflater, or NULL if error.
 */
zlib_deflater_t *zlib_deflater_make(gpointer data, gint len, gint level)
{
	zlib_deflater_t *zd;
	z_streamp outz;
	gint ret;

	outz = g_malloc(sizeof(*outz));
	outz->zalloc = NULL;
	outz->zfree = NULL;
	outz->opaque = NULL;

	ret = deflateInit(outz, level ? level : Z_DEFAULT_COMPRESSION);

	if (ret != Z_OK) {
		g_free(outz);
		g_warning("unable to initialize compressor: %s", zlib_strerror(ret));
		return NULL;
	}

	zd = g_malloc(sizeof(*zd));

	zd->opaque = outz;

	zd->in = data;
	zd->inlen = len;

	/*
	 * zlib requires normally 0.1% more + 12 bytes, we use 0.5% to be safe.
	 *
	 * NB: strictly speaking, we shouldn't need to store this information
	 * here, we could rely on the information in the Z stream.  However, to
	 * be able to inspect what's going on and add assertion,s, let's be
	 * redundant.
	 */

	zd->outlen = (gint) (len * 1.005 + 12.0);
	zd->out = g_malloc(zd->outlen);

	/*
	 * Initialize Z stream.
	 */

	outz->next_out = zd->out;
	outz->avail_out = zd->outlen;
	outz->next_in = zd->in;
	outz->avail_in = 0;			/* Will be set each time zlib_deflate called */

	return zd;
}

/*
 * zlib_deflate
 *
 * Incrementally deflate more data.
 *
 * Returns -1 on error, 1 if work remains, 0 when done.
 */
gint zlib_deflate(zlib_deflater_t *zd, gint amount)
{
	z_streamp outz = (z_streamp) zd->opaque;
	gint remaining;
	gint process;
	gboolean finishing;
	gint ret;

	g_assert(amount > 0);

	/*
	 * Compute amount of input data to process.
	 */

	remaining = zd->inlen - ((guchar *) outz->next_in - (guchar *) zd->in);
	g_assert(remaining >= 0);

	process = MIN(remaining, amount);
	finishing = process < amount;

	/*
	 * Process data.
	 */

	outz->avail_in = process;

	ret = deflate(outz, finishing ? Z_FINISH : 0);

	switch (ret) {
	case Z_OK:
		if (outz->avail_out == 0) {
			g_warning("under-estimated output buffer size: input=%d, output=%d",
				zd->inlen, zd->outlen);

			zd->outlen += OUT_GROW;
			zd->out = g_realloc(zd->out, zd->outlen);
			outz->next_out = (guchar *) zd->out + (zd->outlen - OUT_GROW);
			outz->avail_out = OUT_GROW;
		}

		return 1;				/* Need to call us again */
		/* NOTREACHED */

	case Z_STREAM_END:
		g_assert(finishing);

		zd->outlen = (guchar *) outz->next_out - (guchar *) zd->out;
		g_assert(zd->outlen > 0);

		ret = deflateEnd(outz);
		if (ret != Z_OK)
			g_warning("while freeing compressor: %s", zlib_strerror(ret));

		g_free(outz);
		zd->opaque = NULL;

		return 0;				/* Done */
		/* NOTREACHED */

	default:
		g_warning("error during compression: %s", zlib_strerror(ret));
		ret = deflateEnd(outz);
		if (ret != Z_OK && ret != Z_DATA_ERROR)
			g_warning("while freeing compressor: %s", zlib_strerror(ret));
		g_free(outz);
		zd->opaque = NULL;

		return -1;				/* Error! */
	}

	g_assert(0);		/* Not reached */
	return -1;
}

/*
 * zlib_deflater_free
 *
 * Dispose of the incremental deflater.
 * If `output' is true, also free the output buffer.
 */
void zlib_deflater_free(zlib_deflater_t *zd, gboolean output)
{
	z_streamp outz = (z_streamp) zd->opaque;

	if (outz) {
		gint ret = deflateEnd(outz);

		if (ret != Z_OK && ret != Z_DATA_ERROR)
			g_warning("while freeing compressor: %s", zlib_strerror(ret));

		g_free(outz);
	}

	if (output)
		g_free(zd->out);

	g_free(zd);
}

/*
 * zlib_uncompress
 *
 * Inflate data, whose final uncompressed size is known.
 * Return allocated uncompressed data if OK, NULL on error.
 */
guchar *zlib_uncompress(guchar *data, gint len, gint uncompressed_len)
{
	gint ret;
	guchar *out = g_malloc(uncompressed_len);
	glong retlen = uncompressed_len;

	ret = uncompress(out, &retlen, data, len);

	if (ret == Z_OK) {
		if (retlen != uncompressed_len)
			g_warning("expected %d bytes of decompressed data, got %ld",
				uncompressed_len, retlen);
		return out;
	}

	g_warning("while decompressing data: %s", zlib_strerror(ret));
	g_free(out);

	return NULL;
}

