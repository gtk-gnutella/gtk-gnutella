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

#include "common.h"

RCSID("$Id$")

#include <zlib.h>

#include "zlib_util.h"
#include "misc.h"
#include "walloc.h"
#include "override.h"		/* Must be the last header included */

#define OUT_GROW	1024		/**< To grow output buffer if it's to short */

/**
 * Maps the given error code to an error message.
 *
 * @return human-readable error string corresponding to error code `errnum'.
 */
const char *
zlib_strerror(gint errnum)
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

gpointer
zlib_alloc_func(gpointer unused_opaque, guint n, guint m)
{
	(void) unused_opaque;

	g_return_val_if_fail(n > 0, NULL);
	g_return_val_if_fail(m > 0, NULL);
	g_return_val_if_fail(m < ((size_t) -1) / n, NULL);

	return g_malloc((size_t) n * m);
}

void
zlib_free_func(gpointer unused_opaque, gpointer p)
{
	(void) unused_opaque;
	g_free(p);
}

/**
 * Creates an incremental zlib deflater for `len' bytes starting at `data',
 * with specified compression `level'.
 *
 * @param data		data to compress; if NULL, will be incrementally given
 * @param len		length of data to compress (if data not NULL) or estimation
 * @param dest		where compressed data should go, or NULL if allocated
 * @param destlen	length of supplied output buffer, if dest != NULL
 * @param level		compression level, between 0 and 9.
 *
 * @return new deflater, or NULL if error.
 */
static zlib_deflater_t *
zlib_deflater_alloc(
	gconstpointer data, gint len, gpointer dest, gint destlen, gint level)
{
	zlib_deflater_t *zd;
	z_streamp outz;
	gint ret;

	g_assert(level == Z_DEFAULT_COMPRESSION || (level >= 0 && level <= 9));

	outz = walloc(sizeof(*outz));
	outz->zalloc = zlib_alloc_func;
	outz->zfree = zlib_free_func;
	outz->opaque = NULL;

	ret = deflateInit(outz, level);

	if (ret != Z_OK) {
		wfree(outz, sizeof(*outz));
		g_warning("unable to initialize compressor: %s", zlib_strerror(ret));
		return NULL;
	}

	zd = walloc(sizeof(*zd));

	zd->opaque = outz;
	zd->closed = FALSE;

	zd->in = data;
	zd->inlen = data ? len : 0;
	zd->inlen_total = zd->inlen;

	/*
	 * zlib requires normally 0.1% more + 12 bytes, we use 0.5% to be safe.
	 *
	 * NB: strictly speaking, we shouldn't need to store this information
	 * here, we could rely on the information in the Z stream.  However, to
	 * be able to inspect what's going on and add assertion,s, let's be
	 * redundant.
	 */

	if (dest == NULL) {
		/* Compressed data go to a dynamically allocated buffer */
		if (data == NULL && len == 0)
			len = 512;

		zd->outlen = (gint) (len * 1.005 + 12.0);
		zd->out = g_malloc(zd->outlen);
		zd->allocated = TRUE;
	} else {
		/* Compressed data go to a supplied buffer, not-resizable */
		zd->out = dest;
		zd->outlen = destlen;
		zd->allocated = FALSE;
	}

	/*
	 * Initialize Z stream.
	 */

	outz->next_out = zd->out;
	outz->avail_out = zd->outlen;
	outz->next_in = deconstify_gpointer(zd->in);
	outz->avail_in = 0;			/* Will be set by zlib_deflate_step() */

	return zd;
}

/**
 * Creates an incremental zlib deflater for `len' bytes starting at `data',
 * with specified compression `level'.  Data will be compressed into a
 * dynamically allocated buffer, resized as needed.
 *
 * If `data' is NULL, data to compress will have to be fed to the deflater
 * via zlib_deflate_data() calls.  Otherwise, calls to zlib_deflate() will
 * incrementally compress the initial buffer.
 *
 * @return new deflater, or NULL if error.
 */
zlib_deflater_t *
zlib_deflater_make(gconstpointer data, gint len, gint level)
{
	return zlib_deflater_alloc(data, len, NULL, 0, level);
}

/**
 * Creates an incremental zlib deflater for `len' bytes starting at `data',
 * with specified compression `level'.  Data will be compressed into the
 * supplied buffer starting at `dest'.
 *
 * If `data' is NULL, data to compress will have to be fed to the deflater
 * via zlib_deflate_data() calls.  Otherwise, calls to zlib_deflate() will
 * incrementally compress the initial buffer.
 *
 * @return new deflater, or NULL if error.
 */
zlib_deflater_t *
zlib_deflater_make_into(
	gconstpointer data, gint len, gpointer dest, gint destlen, gint level)
{
	return zlib_deflater_alloc(data, len, dest, destlen, level);
}

/**
 * Incrementally deflate more data.
 *
 * @param zd		the deflator object
 * @param amount	amount of data to deflate
 * @param may_close	whether to allow closing when all data was consumed
 *
 * @return -1 on error, 1 if work remains, 0 when done.
 */
static gint
zlib_deflate_step(zlib_deflater_t *zd, gint amount, gboolean may_close)
{
	z_streamp outz = zd->opaque;
	gint remaining;
	gint process;
	gboolean finishing;
	gint ret;

	g_assert(amount > 0);
	g_assert(!zd->closed);
	g_assert(outz != NULL);			/* Stream not closed yet */

	/*
	 * Compute amount of input data to process.
	 */

	remaining = zd->inlen - ((char *) outz->next_in - (char *) zd->in);
	g_assert(remaining >= 0);

	process = MIN(remaining, amount);
	finishing = process == remaining && may_close;

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

			if (zd->allocated) {
				zd->outlen += OUT_GROW;
				zd->out = g_realloc(zd->out, zd->outlen);
				outz->next_out = (guchar *) zd->out + (zd->outlen - OUT_GROW);
				outz->avail_out = OUT_GROW;
			} else
				goto error;		/* Cannot continue */
		}

		return 1;				/* Need to call us again */
		/* NOTREACHED */

	case Z_STREAM_END:
		g_assert(finishing);

		zd->outlen = (char *) outz->next_out - (char *) zd->out;
		g_assert(zd->outlen > 0);

		ret = deflateEnd(outz);
		if (ret != Z_OK)
			g_warning("while freeing compressor: %s", zlib_strerror(ret));

		wfree(outz, sizeof(*outz));
		zd->opaque = NULL;
		zd->closed = TRUE;

		return 0;				/* Done */
		/* NOTREACHED */

	default:
		g_warning("error during compression: %s", zlib_strerror(ret));
	}

	/* FALL THROUGH */

error:
	ret = deflateEnd(outz);
	if (ret != Z_OK && ret != Z_DATA_ERROR)
		g_warning("while freeing compressor: %s", zlib_strerror(ret));
	wfree(outz, sizeof(*outz));
	zd->opaque = NULL;

	return -1;				/* Error! */
}

/**
 * Incrementally deflate more data, the `amount' specified.
 * When all the data have been compressed, the stream is closed.
 *
 * @return -1 on error, 1 if work remains, 0 when done.
 */
gint
zlib_deflate(zlib_deflater_t *zd, gint amount)
{
	return zlib_deflate_step(zd, amount, TRUE);
}

/**
 * Deflate the data supplied, but do not close the stream when all the
 * data have been compressed.  Needs to call zlib_deflate_close() for that.
 *
 * @returns TRUE if OK, FALSE on error.
 */
gboolean
zlib_deflate_data(zlib_deflater_t *zd, gconstpointer data, gint len)
{
	z_streamp outz = zd->opaque;

	g_assert(outz != NULL);			/* Stream not closed yet */

	zd->in = data;
	zd->inlen = len;
	zd->inlen_total += len;

	outz->next_in = deconstify_gpointer(zd->in);
	outz->avail_in = 0;			/* Will be set by zlib_deflate_step() */

	return zlib_deflate_step(zd, len, FALSE) > 0 ? TRUE : FALSE;
}

/**
 * Marks the end of the data: flush the stream and close.
 *
 * @returns TRUE if OK, FALSE on error.
 */
gboolean
zlib_deflate_close(zlib_deflater_t *zd)
{
	z_streamp outz = zd->opaque;
	gint ret;

	g_assert(!zd->closed);
	g_assert(outz != NULL);			/* Stream not closed yet */

	zd->in = NULL;
	zd->inlen = 0;

	outz->next_in = deconstify_gpointer(zd->in);
	outz->avail_in = 0;

	ret = zlib_deflate_step(zd, 1, TRUE) == 0 ? TRUE : FALSE;

	zd->closed = TRUE;				/* Even if there was an error */

	return ret;
}

/**
 * Dispose of the incremental deflater.
 * If `output' is true, also free the output buffer.
 */
void
zlib_deflater_free(zlib_deflater_t *zd, gboolean output)
{
	z_streamp outz = zd->opaque;

	if (outz) {
		gint ret = deflateEnd(outz);

		if (ret != Z_OK && ret != Z_DATA_ERROR)
			g_warning("while freeing compressor: %s", zlib_strerror(ret));

		wfree(outz, sizeof(*outz));
	}

	if (output && zd->allocated) {
		G_FREE_NULL(zd->out);
	}
	wfree(zd, sizeof(*zd));
}

/**
 * Inflate data, whose final uncompressed size is known.
 *
 * @return allocated uncompressed data if OK, NULL on error.
 */
gpointer
zlib_uncompress(gconstpointer data, gint len, gulong uncompressed_len)
{
	gint ret;
	guchar *out = g_malloc(uncompressed_len);
	gulong retlen = uncompressed_len;

	ret = uncompress(out, &retlen, data, len);

	if (ret == Z_OK) {
		if (retlen != uncompressed_len)
			g_warning("expected %lu bytes of decompressed data, got %ld",
				uncompressed_len, retlen);
		return out;
	}

	g_warning("while decompressing data: %s", zlib_strerror(ret));
	G_FREE_NULL(out);

	return NULL;
}

/**
 * Inflate data into supplied buffer.
 *
 * @param data		the data to inflate
 * @param len		length of data
 * @param out		buffer where inflate data should be put
 * @param outlen	on input the length of out buffer, on output the length of
 *					the deflated data.
 *
 * @return zlib's status: Z_OK on OK, error code otherwise.
 */
gint
zlib_inflate_into(gconstpointer data, gint len, gpointer out, gint *outlen)
{
	z_streamp inz;
	gint ret;
	gint inflated = 0;

	g_assert(data != NULL);
	g_assert(len > 0);
	g_assert(out != NULL);
	g_assert(outlen != NULL);
	g_assert(*outlen > 0);

	/*
	 * Allocate decompressor.
	 */

	inz = walloc(sizeof(*inz));

	inz->zalloc = zlib_alloc_func;
	inz->zfree = zlib_free_func;
	inz->opaque = NULL;

	ret = inflateInit(inz);

	if (ret != Z_OK) {
		g_warning("unable to setup decompressor: %s", zlib_strerror(ret));
		goto done;
	}

	/*
	 * Prepare call to inflate().
	 */

	inz->next_in = deconstify_gpointer(data);
	inz->avail_in = len;

	inz->next_out = out;
	inz->avail_out = *outlen;

	/*
	 * Decompress data.
	 */

	ret = inflate(inz, Z_SYNC_FLUSH);

	inflated = *outlen - inz->avail_out;

	if (ret == Z_STREAM_END) {
		ret = Z_OK;
		*outlen = inflated;
		goto done;
	}

	if (ret == Z_OK)		/* Expected Z_STREAM_END! */
		ret = Z_DATA_ERROR;

	/* FALL THROUGH */

done:
	wfree(inz, sizeof(*inz));
	return ret;
}

/**
 * Check whether first bytes of data make up a valid zlib marker.
 */
gboolean
zlib_is_valid_header(gconstpointer data, gint len)
{
	const guchar *p = data;
	guint16 check;

	if (len < 2)
		return FALSE;

	/*
	 * A deflated buffer starts with:
	 *
	 *      0   1
	 *    +---+---+
	 *    |CMF|FLG|   (more-->)
	 *    +---+---+
	 *
	 * With:
	 *
	 * CMF: bit 0-3 = CM (compression method)
	 * CMF: bit 4-7 = CINFO (compression info)
	 *
	 * FLG: bit 0-4 = FCHECK (check bits for CMF and FLG)
	 * FLG: bit 5   = FDICT (preset dictionary)
	 * FLG: bit 6-7 = FLEVEL (compression level)
	 *
	 * The FCHECK value must be such that CMF and FLG, when viewed as a
	 * 16-bit unsigned integer, stored in MSB order (CMF*256 + FLG), is
	 * a multiple of 31.
	 *
	 * Valid values for CM are 8 (deflate) and 15 (reserved).
	 */

	switch (p[0] & 0xf) {
	case 8:
	case 15:
		break;
	default:
		return FALSE;
	}

	check = (p[0] << 8) | p[1];

	return (0 == check % 31) ? TRUE : FALSE;
}

/* vi: set ts=4 sw=4 cindent: */
