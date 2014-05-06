/*
 * Copyright (c) 2002-2003, 2012 Raphael Manfredi
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
 * Zlib wrapper functions and utilities.
 *
 * @author Raphael Manfredi
 * @date 2002-2003, 2012
 */

#include "common.h"

#include <zlib.h>

#include "zlib_util.h"
#include "glib-missing.h"
#include "misc.h"
#include "halloc.h"
#include "unsigned.h"
#include "walloc.h"
#include "override.h"		/* Must be the last header included */

#define OUT_GROW	1024		/**< To grow output buffer if it's to short */

enum zlib_stream_magic {
	ZLIB_DEFLATER_MAGIC = 0x22a22f45,
	ZLIB_INFLATER_MAGIC = 0x49ad00b4
};

/**
 * The zlib stream wrapper.
 */
typedef struct zlib_stream {
	enum zlib_stream_magic magic;
	const void *in;		/**< Buffer being compressed */
	size_t inlen;		/**< Length of input buffer */
	void *out;			/**< Compressed data */
	size_t outlen;		/**< Length of ouput buffer */
	size_t inlen_total;	/**< Total input length seen */
	z_streamp z;		/**< The underlying zlib stream */
	uint allocated:1;	/**< Was output buffer allocated or static? */
	uint closed:1;		/**< Whether the stream was closed */
} zlib_stream_t;

/**
 * Incremental deflater stream.
 */
struct zlib_deflater {
	struct zlib_stream zs;
};

static inline void
zlib_deflater_check(const struct zlib_deflater * const zd)
{
	g_assert(zd != NULL);
	g_assert(ZLIB_DEFLATER_MAGIC == zd->zs.magic);
}

/**
 * Re-usable inflater stream (across messages).
 */
struct zlib_inflater {
	struct zlib_stream zs;
	size_t maxoutlen;	/**< Upper limit for inflation (0 = unlimited) */
};

static inline void
zlib_inflater_check(const struct zlib_inflater * const zi)
{
	g_assert(zi != NULL);
	g_assert(ZLIB_INFLATER_MAGIC == zi->zs.magic);
}

void *
zlib_deflater_out(const struct zlib_deflater *zd)
{
	zlib_deflater_check(zd);
	return zd->zs.out;
}

int
zlib_deflater_outlen(const struct zlib_deflater *zd)
{
	zlib_deflater_check(zd);
	g_assert(zd->zs.closed);
	return zd->zs.outlen;
}

int
zlib_deflater_inlen(const struct zlib_deflater *zd)
{
	zlib_deflater_check(zd);
	return zd->zs.inlen_total;
}

bool
zlib_deflater_closed(const struct zlib_deflater *zd)
{
	zlib_deflater_check(zd);
	return zd->zs.closed;
}

void *
zlib_inflater_out(const struct zlib_inflater *zi)
{
	zlib_inflater_check(zi);
	return zi->zs.out;
}

int
zlib_inflater_outlen(const struct zlib_inflater *zi)
{
	zlib_inflater_check(zi);
	g_assert(zi->zs.closed);
	return zi->zs.outlen;
}

int
zlib_inflater_inlen(const struct zlib_inflater *zi)
{
	zlib_inflater_check(zi);
	return zi->zs.inlen_total;
}

size_t
zlib_inflater_maxoutlen(const struct zlib_inflater *zi)
{
	zlib_inflater_check(zi);
	return zi->maxoutlen;
}

void
zlib_inflater_set_maxoutlen(struct zlib_inflater *zi, size_t len)
{
	zlib_inflater_check(zi);
	zi->maxoutlen = len;
}

bool
zlib_inflater_closed(const struct zlib_inflater *zi)
{
	zlib_inflater_check(zi);
	return zi->zs.closed;
}

/**
 * Maps the given error code to an error message.
 *
 * @return human-readable error string corresponding to error code `errnum'.
 */
const char *
zlib_strerror(int errnum)
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

void *
zlib_alloc_func(void *unused_opaque, uint n, uint m)
{
	(void) unused_opaque;

	g_return_val_if_fail(n > 0, NULL);
	g_return_val_if_fail(m > 0, NULL);
	g_return_val_if_fail(m < ((size_t) -1) / n, NULL);

	return halloc((size_t) n * m);
}

void
zlib_free_func(void *unused_opaque, void *p)
{
	(void) unused_opaque;
	hfree(p);
}

/**
 * Initialize internal state for our incremental zlib stream.
 *
 * @param zs		the zlib stream structure to initialize
 * @param data		input data to process; if NULL, will be incrementally given
 * @param len		length of data to process (if data not NULL) or estimation
 * @param dest		where processed data should go, or NULL if allocated
 * @param destlen	length of supplied output buffer, if dest != NULL
 */
static void
zlib_stream_init(zlib_stream_t *zs,
	const void *data, size_t len, void *dest, size_t destlen)
{
	z_streamp z;

	g_assert(size_is_non_negative(len));
	g_assert(size_is_non_negative(destlen));

	zs->in = data;
	zs->inlen = data ? len : 0;
	zs->inlen_total = zs->inlen;

	/*
	 * When deflating zlib requires normally 0.1% more + 12 bytes, we use
	 * 0.5% to be safe.
	 *
	 * When inflating, assume we'll double the input at least.
	 */

	if (NULL == dest) {
		/* Processed data go to a dynamically allocated buffer */
		if (!zs->allocated) {
			if (data == NULL && len == 0)
				len = 512;

			if (ZLIB_DEFLATER_MAGIC == zs->magic) {
				zs->outlen = (len * 1.005 + 12.0);
				g_assert(zs->outlen > len);
				g_assert(zs->outlen - len >= 12);
			} else {
				zs->outlen = UNSIGNED(len) * 2;
			}

			zs->out = halloc(zs->outlen);
			zs->allocated = TRUE;
		}
	} else {
		/* Processed data go to a supplied buffer, not-resizable */
		if (zs->allocated)
			hfree(zs->out);
		zs->out = dest;
		zs->outlen = destlen;
		zs->allocated = FALSE;
	}

	/*
	 * Initialize Z stream.
	 */

	z = zs->z;
	g_assert(z != NULL);			/* Stream not closed yet */

	z->next_out = zs->out;
	z->avail_out = zs->outlen;
	z->next_in = deconstify_pointer(zs->in);
	z->avail_in = 0;			/* Will be set by zlib_xxx_step() */
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
	const void *data, size_t len, void *dest, size_t destlen, int level)
{
	zlib_deflater_t *zd;
	z_streamp outz;
	int ret;

	g_assert(size_is_non_negative(len));
	g_assert(size_is_non_negative(destlen));
	g_assert(level == Z_DEFAULT_COMPRESSION || (level >= 0 && level <= 9));

	WALLOC(outz);
	outz->zalloc = zlib_alloc_func;
	outz->zfree = zlib_free_func;
	outz->opaque = NULL;

	ret = deflateInit(outz, level);

	if (ret != Z_OK) {
		WFREE(outz);
		g_carp("%s(): unable to initialize compressor: %s",
			G_STRFUNC, zlib_strerror(ret));
		return NULL;
	}

	WALLOC0(zd);
	zd->zs.magic = ZLIB_DEFLATER_MAGIC;
	zd->zs.z = outz;
	zd->zs.closed = FALSE;

	zlib_stream_init(&zd->zs, data, len, dest, destlen);

	return zd;
}

/**
 * Reset an incremental zlib stream.
 *
 * The compression parameters remain the same as the ones used when the
 * deflater was initially created.  Only the input/output settings change.
 *
 * @param zd		the zlib deflater to reset
 * @param data		data to compress; if NULL, will be incrementally given
 * @param len		length of data to compress (if data not NULL) or estimation
 * @param dest		where compressed data should go, or NULL if allocated
 * @param destlen	length of supplied output buffer, if dest != NULL
 */
static void
zlib_stream_reset_into(zlib_stream_t *zs,
	const void *data, size_t len, void *dest, size_t destlen)
{
	g_assert(zs->z != NULL);		/* Stream not closed yet */

	zs->closed = FALSE;
	switch (zs->magic) {
	case ZLIB_INFLATER_MAGIC:
		inflateReset(zs->z);
		break;
	case ZLIB_DEFLATER_MAGIC:
		deflateReset(zs->z);
		break;
	}
	zlib_stream_init(zs, data, len, dest, destlen);
}

/**
 * Attempt to grow the output buffer.
 *
 * @param zs		the zlib stream object
 * @param maxout	maximum length of dynamically-allocated buffer (0 = none)
 *
 * @return TRUE if we can resume processing after the output buffer was
 * expanded, FALSE if the buffer cannot be expanded (not dynamically allocated
 * or reached the maximum size).
 */
static bool
zlib_stream_grow_output(zlib_stream_t *zs, size_t maxout)
{
	if (zs->allocated) {
		z_streamp z = zs->z;

		/*
		 * Limit growth if asked to do so.
		 *
		 * This is used when inflating, usually, to avoid being given a small
		 * amount of data that will expand into megabytes...
		 */

		if (maxout != 0 && zs->outlen >= maxout) {
			g_warning("%s(): reached maximum buffer size (%zu bytes): "
				"input=%zu, output=%zu",
				G_STRFUNC, maxout, zs->inlen, zs->outlen);
			return FALSE;	/* Cannot continue */
		}

		zs->outlen += OUT_GROW;
		zs->out = hrealloc(zs->out, zs->outlen);
		z->next_out = ptr_add_offset(zs->out, zs->outlen - OUT_GROW);
		z->avail_out = OUT_GROW;
		return TRUE;	/* Can process remaining input */
	}

	g_warning("%s(): under-estimated output buffer size: "
		"input=%zu, output=%zu", G_STRFUNC, zs->inlen, zs->outlen);

	return FALSE;		/* Cannot continue */
}

/**
 * Incrementally process more data.
 *
 * @param zs		the zlib stream object
 * @param amount	amount of data to process
 * @param maxout	maximum length of dynamically-allocated buffer (0 = none)
 * @param may_close	whether to allow closing when all data was consumed
 * @param finish	whether this is the last data to process
 *
 * @return -1 on error, 1 if work remains, 0 when done.
 */
static int
zlib_stream_process_step(zlib_stream_t *zs, int amount, size_t maxout,
	bool may_close, bool finish)
{
	z_streamp z;
	int remaining;
	int process;
	bool finishing;
	int ret = 0;

	g_assert(amount > 0);
	g_assert(!zs->closed);

	z = zs->z;
	g_assert(z != NULL);			/* Stream not closed yet */

	/*
	 * Compute amount of input data to process.
	 */

	remaining = zs->inlen - ptr_diff(z->next_in, zs->in);
	g_assert(remaining >= 0);

	process = MIN(remaining, amount);
	finishing = process == remaining;

	/*
	 * Process data.
	 */

	z->avail_in = process;

resume:
	switch (zs->magic) {
	case ZLIB_DEFLATER_MAGIC:
		ret = deflate(z, finishing && finish ? Z_FINISH : 0);
		break;
	case ZLIB_INFLATER_MAGIC:
		ret = inflate(z, Z_SYNC_FLUSH);
		break;
	}

	switch (ret) {
	case Z_OK:
		if (0 == z->avail_out) {
			if (zlib_stream_grow_output(zs, maxout))
				goto resume;	/* Process remaining input */
			goto error;			/* Cannot continue */
		}
		return 1;				/* Need to call us again */
		/* NOTREACHED */

	case Z_BUF_ERROR:			/* Output full or need more input to continue */
		if (0 == z->avail_out) {
			if (zlib_stream_grow_output(zs, maxout))
				goto resume;	/* Process remaining input */
			goto error;			/* Cannot continue */
		}
		if (0 == z->avail_in)
			return 1;			/* Need to call us again */
		goto error;				/* Cannot continue */
		/* NOTREACHED */

	case Z_STREAM_END:			/* Reached end of input stream */
		g_assert(finishing);

		/*
		 * Supersede the output length to let them probe how much data
		 * was processed once the stream is closed, through calls to
		 * zlib_deflater_outlen() or zlib_inflater_outlen().
		 */

		zs->outlen = ptr_diff(z->next_out, zs->out);
		g_assert(zs->outlen > 0);

		if (may_close) {
			switch (zs->magic) {
			case ZLIB_DEFLATER_MAGIC:
				ret = deflateEnd(z);
				break;
			case ZLIB_INFLATER_MAGIC:
				ret = inflateEnd(z);
				break;
			}

			if (ret != Z_OK) {
				g_carp("%s(): while freeing zstream: %s",
					G_STRFUNC, zlib_strerror(ret));
			}
			WFREE(z);
			zs->z = NULL;
		}

		zs->closed = TRUE;		/* Signals processing stream done */
		return 0;				/* Done */
		/* NOTREACHED */

	default:
		break;
	}

	/* FALL THROUGH */

error:
	g_carp("%s(): error during %scompression: %s "
		"(avail_in=%u, avail_out=%u, total_in=%lu, total_out=%lu)",
		G_STRFUNC, ZLIB_DEFLATER_MAGIC == zs->magic ? "" : "de",
		zlib_strerror(ret),
		z->avail_in, z->avail_out, z->total_in, z->total_out);

	if (may_close) {
		switch (zs->magic) {
		case ZLIB_DEFLATER_MAGIC:
			ret = deflateEnd(z);
			break;
		case ZLIB_INFLATER_MAGIC:
			ret = inflateEnd(z);
			break;
		}
		if (ret != Z_OK && ret != Z_DATA_ERROR) {
			g_carp("%s(): while freeing stream: %s",
				G_STRFUNC, zlib_strerror(ret));
		}
		WFREE(z);
		zs->z = NULL;
	}

	return -1;				/* Error! */
}

/**
 * Process the data supplied, but do not close the stream when all the
 * data have been handled.  Needs to call zlib_deflate_close() for that
 * when deflating.
 *
 * @return -1 on error, 1 if work remains, 0 when done.
 */
static int
zlib_stream_process_data(zlib_stream_t *zs, const void *data, int len,
	size_t maxout, bool final)
{
	z_streamp z;

	g_assert(len >= 0);

	z = zs->z;
	g_assert(z != NULL);			/* Stream not closed yet */

	if G_UNLIKELY(0 == len)
		return zs->closed ? 0 : 1;

	zs->in = data;
	zs->inlen = len;
	zs->inlen_total += len;

	z->next_in = deconstify_pointer(zs->in);
	z->avail_in = 0;			/* Will be set by zlib_stream_process_step() */

	return zlib_stream_process_step(zs, len, maxout, FALSE, final);
}

/**
 * Dispose of the incremental stream processor.
 * If `output' is true, also free the output buffer.
 */
static void
zlib_stream_free(zlib_stream_t *zs, bool output)
{
	z_streamp z;

	z = zs->z;

	if (z != NULL) {
		int ret = 0;

		switch (zs->magic) {
		case ZLIB_DEFLATER_MAGIC:
			ret = deflateEnd(z);
			break;
		case ZLIB_INFLATER_MAGIC:
			ret = inflateEnd(z);
			break;
		}

		if (ret != Z_OK && ret != Z_DATA_ERROR) {
			g_carp("%s(): while freeing stream: %s",
				G_STRFUNC, zlib_strerror(ret));
		}
		WFREE(z);
	}

	if (output && zs->allocated)
		HFREE_NULL(zs->out);
}

/**
 * Reset an incremental zlib deflater.
 *
 * The compression parameters remain the same as the ones used when the
 * deflater was initially created.  Only the input/output settings change.
 *
 * @param zd		the zlib deflater to reset
 * @param data		data to compress; if NULL, will be incrementally given
 * @param len		length of data to compress (if data not NULL) or estimation
 * @param dest		where compressed data should go, or NULL if allocated
 * @param destlen	length of supplied output buffer, if dest != NULL
 */
void
zlib_deflater_reset_into(zlib_deflater_t *zd,
	const void *data, int len, void *dest, int destlen)
{
	zlib_deflater_check(zd);
	zlib_stream_reset_into(&zd->zs, data, len, dest, destlen);
}

/**
 * Reset an incremental zlib deflater whose output goes to a dynamically
 * allocated message.
 *
 * The compression parameters remain the same as the ones used when the
 * deflater was initially created.  Only the input/output settings change.
 *
 * @param zd		the zlib deflater to reset
 * @param data		data to compress; if NULL, will be incrementally given
 * @param len		length of data to compress (if data not NULL) or estimation
 */
void
zlib_deflater_reset(zlib_deflater_t *zd, const void *data, int len)
{
	zlib_deflater_check(zd);
	zlib_stream_reset_into(&zd->zs, data, len, NULL, 0);
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
zlib_deflater_make(const void *data, int len, int level)
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
	const void *data, int len, void *dest, int destlen, int level)
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
int
zlib_deflate_step(zlib_deflater_t *zd, int amount, bool may_close)
{
	zlib_deflater_check(zd);
	return zlib_stream_process_step(&zd->zs, amount, 0, may_close, TRUE);
}

/**
 * Incrementally deflate more data, the `amount' specified.
 * When all the data have been compressed, the stream is closed.
 *
 * @return -1 on error, 1 if work remains, 0 when done.
 */
int
zlib_deflate(zlib_deflater_t *zd, int amount)
{
	return zlib_deflate_step(zd, amount, TRUE);
}

/**
 * Deflate all the data supplied during zlib_deflater_reset().
 *
 * @return -1 on error, 0 when done.
 */
int
zlib_deflate_all(zlib_deflater_t *zd)
{
	int ret;

	zlib_deflater_check(zd);
	g_assert(zd->zs.in != NULL);		/* Data to deflate supplied */

	ret = zlib_stream_process_step(&zd->zs, zd->zs.inlen, 0, FALSE, TRUE);

	g_assert(ret != 1);		/* Must have processed the whole input */

	return ret;
}

/**
 * Deflate the data supplied, but do not close the stream when all the
 * data have been compressed.  Needs to call zlib_deflate_close() for that.
 *
 * When ``final'' is set, this is going to be the last data in the stream,
 * so we must flush the whole compression state.
 *
 * @returns TRUE if OK, FALSE on error.
 */
bool
zlib_deflate_data(zlib_deflater_t *zd, const void *data, int len, bool final)
{
	zlib_deflater_check(zd);
	return booleanize(
		zlib_stream_process_data(&zd->zs, data, len, 0, final) > 0);
}

/**
 * Marks the end of the data: flush the stream and close (no further data can
 * be given until a reset).
 *
 * This does NOT free the underlying zstream, which can be reset to restart
 * another deflation.  To free everything, call zlib_deflater_free().
 *
 * @returns TRUE if OK, FALSE on error.
 */
bool
zlib_deflate_close(zlib_deflater_t *zd)
{
	z_streamp outz;
	zlib_stream_t *zs;

	int ret;

	zlib_deflater_check(zd);

	zs = &zd->zs;
	g_assert(!zs->closed);

	outz = zs->z;
	g_assert(outz != NULL);			/* Stream not closed yet */

	zs->in = NULL;
	zs->inlen = 0;

	outz->next_in = deconstify_pointer(zs->in);
	outz->avail_in = 0;

	ret = booleanize(0 == zlib_stream_process_step(zs, 1, 0, FALSE, TRUE));
	zs->closed = TRUE;				/* Even if there was an error */

	return ret;
}

/**
 * Dispose of the incremental deflater.
 * If `output' is true, also free the output buffer.
 */
void
zlib_deflater_free(zlib_deflater_t *zd, bool output)
{
	zlib_deflater_check(zd);

	zlib_stream_free(&zd->zs, output);
	zd->zs.magic = 0;
	WFREE(zd);
}

/**
 * Inflate data, whose final uncompressed size is known.
 *
 * @return allocated uncompressed data via halloc() if OK, NULL on error.
 * Use hfree() to free the data.
 */
void *
zlib_uncompress(const void *data, int len, ulong uncompressed_len)
{
	int ret;
	uchar *out = halloc(uncompressed_len);
	ulong retlen = uncompressed_len;

	g_return_val_if_fail(uncompressed_len != 0, NULL);

	ret = uncompress(out, &retlen, data, len);

	if (ret == Z_OK) {
		if (retlen != uncompressed_len)
			g_carp("%s(): expected %lu bytes of decompressed data, got %ld",
				G_STRFUNC, uncompressed_len, retlen);
		return out;
	}

	g_carp("%s(): while decompressing data: %s", G_STRFUNC, zlib_strerror(ret));
	HFREE_NULL(out);

	return NULL;
}

/**
 * Inflate data into supplied buffer.
 *
 * @param data		the data to inflate
 * @param len		length of data
 * @param out		buffer where inflated data should be put
 * @param outlen	on input the length of out buffer, on output the length of
 *					the deflated data.
 *
 * @return zlib's status: Z_OK on OK, error code otherwise.
 */
int
zlib_inflate_into(const void *data, int len, void *out, int *outlen)
{
	z_streamp inz;
	int ret;
	int inflated = 0;

	g_assert(data != NULL);
	g_assert(len > 0);
	g_assert(out != NULL);
	g_assert(outlen != NULL);
	g_assert(*outlen > 0);

	/*
	 * Allocate decompressor.
	 */

	WALLOC(inz);
	inz->zalloc = zlib_alloc_func;
	inz->zfree = zlib_free_func;
	inz->opaque = NULL;

	ret = inflateInit(inz);

	if (ret != Z_OK) {
		g_carp("%s(): unable to setup decompressor: %s",
			G_STRFUNC, zlib_strerror(ret));
		goto done;
	}

	/*
	 * Prepare call to inflate().
	 */

	inz->next_in = deconstify_pointer(data);
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
	(void) inflateEnd(inz);
	WFREE(inz);
	return ret;
}

/**
 * Reset an incremental zlib inflater.
 *
 * @param zi		the zlib inflater to reset
 * @param data		data to inflate; if NULL, will be incrementally given
 * @param len		length of data to inflate (if data not NULL) or estimation
 * @param dest		where inflated data should go, or NULL if allocated
 * @param destlen	length of supplied output buffer, if dest != NULL
 */
void
zlib_inflater_reset_into(zlib_inflater_t *zi,
	const void *data, int len, void *dest, int destlen)
{
	zlib_inflater_check(zi);
	zlib_stream_reset_into(&zi->zs, data, len, dest, destlen);
}

/**
 * Reset an incremental zlib inflater whose output goes to a dynamically
 * allocated message.
 *
 * @param zi		the zlib inflater to reset
 * @param data		data to inflate; if NULL, will be incrementally given
 * @param len		length of data to inflate (if data not NULL) or estimation
 */
void
zlib_inflater_reset(zlib_inflater_t *zi, const void *data, int len)
{
	zlib_inflater_check(zi);
	zlib_stream_reset_into(&zi->zs, data, len, NULL, 0);
}

/**
 * Creates an incremental zlib inflater for `len' bytes starting at `data'.
 *
 * @param data		data to inflate; if NULL, will be incrementally given
 * @param len		length of data to infalte (if data not NULL) or estimation
 * @param dest		where inflated data should go, or NULL if allocated
 * @param destlen	length of supplied output buffer, if dest != NULL
 *
 * @return new infalter, or NULL if error.
 */
static zlib_inflater_t *
zlib_inflater_alloc(
	const void *data, int len, void *dest, int destlen)
{
	zlib_inflater_t *zi;
	z_streamp inz;
	int ret;

	g_assert(len >= 0);
	g_assert(destlen >= 0);

	WALLOC(inz);
	inz->zalloc = zlib_alloc_func;
	inz->zfree = zlib_free_func;
	inz->opaque = NULL;

	ret = inflateInit(inz);

	if (ret != Z_OK) {
		WFREE(inz);
		g_carp("%s(): unable to initialize decompressor: %s",
			G_STRFUNC, zlib_strerror(ret));
		return NULL;
	}

	WALLOC0(zi);
	zi->zs.magic = ZLIB_INFLATER_MAGIC;
	zi->zs.z = inz;
	zi->zs.closed = FALSE;

	zlib_stream_init(&zi->zs, data, len, dest, destlen);

	return zi;
}

/**
 * Creates an incremental zlib inflater for `len' bytes starting at `data'.
 * Data will be inflated into a dynamically allocated buffer, resized as needed.
 *
 * If `data' is NULL, data to inflate will have to be fed to the inflater
 * via zlib_inflate_data() calls.  Otherwise, calls to zlib_inflate() will
 * incrementally inflate the initial buffer.
 *
 * @return new inflater, or NULL if error.
 */
zlib_inflater_t *
zlib_inflater_make(const void *data, int len)
{
	return zlib_inflater_alloc(data, len, NULL, 0);
}

/**
 * Creates an incremental zlib inflater for `len' bytes starting at `data',
 * Data will be inflated into the supplied buffer starting at `dest'.
 *
 * If `data' is NULL, data to inflate will have to be fed to the inflater
 * via zlib_inflate_data() calls.  Otherwise, calls to zlib_inflate() will
 * incrementally inflate the initial buffer.
 *
 * @return new inflater, or NULL if error.
 */
zlib_inflater_t *
zlib_inflater_make_into(
	const void *data, int len, void *dest, int destlen)
{
	return zlib_inflater_alloc(data, len, dest, destlen);
}

/**
 * Incrementally inflate more data.
 *
 * @param zi		the inflator object
 * @param amount	amount of data to inflate
 * @param may_close	whether to allow closing when all data was consumed
 *
 * @return -1 on error, 1 if work remains, 0 when done.
 */
int
zlib_inflate_step(zlib_inflater_t *zi, int amount, bool may_close)
{
	zlib_inflater_check(zi);
	return zlib_stream_process_step(&zi->zs, amount, zi->maxoutlen,
		may_close, FALSE /* Does not matter when inflating */);
}

/**
 * Inflate the data supplied, but do not close the stream when all the
 * data have been inflated.
 *
 * @return -1 on error, 1 if work remains, 0 when done.
 */
int
zlib_inflate_data(zlib_inflater_t *zi, const void *data, int len)
{
	zlib_inflater_check(zi);
	return zlib_stream_process_data(&zi->zs, data, len, zi->maxoutlen,
		FALSE /* Does not matter when inflating*/);
}

/**
 * Dispose of the incremental inflater.
 * If `output' is true, also free the output buffer.
 */
void
zlib_inflater_free(zlib_inflater_t *zi, bool output)
{
	zlib_inflater_check(zi);

	zlib_stream_free(&zi->zs, output);
	zi->zs.magic = 0;
	WFREE(zi);
}

/**
 * Check whether first bytes of data make up a valid zlib marker.
 */
bool
zlib_is_valid_header(const void *data, int len)
{
	const uchar *p = data;
	uint16 check;

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

	return booleanize(0 == check % 31);
}

/* vi: set ts=4 sw=4 cindent: */
