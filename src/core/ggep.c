/*
 * $Id$
 *
 * Copyright (c) 2002-2004, Raphael Manfredi
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
 * @file
 *
 * Gnutella Generic Extension Protocol (GGEP).
 */

#include "common.h"

RCSID("$Id$");

#include "ggep.h"
#include "extensions.h"
#include "lib/cobs.h"
#include "lib/walloc.h"
#include "lib/zlib_util.h"

#include "if/gnet_property_priv.h"

#include "lib/override.h"			/* Must be the last header included */

#define MAX_PAYLOAD_LEN		65536	/* Max length for deflated payload */
#define MIN_GROW			256		/* Minimum grow size for inflated buffer */

#if 0	/* UNUSED for now */
/**
 * Inflate `len' bytes starting at `buf', up to MAX_PAYLOAD_LEN bytes.
 * The payload `token' is given only in case there is an error to report.
 *
 * Returns the allocated inflated buffer, and its inflated length in `retlen'.
 * Returns NULL on error.
 */
static gchar *
ggep_inflate(gchar *buf, gint len, gint *retlen, gint token)
{
	gchar *result;					/* Inflated buffer */
	gint rsize;						/* Result's buffer size */
	z_streamp inz;
	gint ret;
	gint inflated;					/* Amount of inflated data so far */
	gboolean failed = FALSE;

	g_assert(buf);
	g_assert(len > 0);
	g_assert(retlen);

	inz = walloc(sizeof(*inz));

	inz->zalloc = NULL;
	inz->zfree = NULL;
	inz->opaque = NULL;

	ret = inflateInit(inz);

	if (ret != Z_OK) {
		wfree(inz, sizeof(*inz));
		g_warning("unable to initialize decompressor for GGEP payload %d: %s",
			token, zlib_strerror(ret));
		return NULL;
	}

	rsize = len * 2;				/* Assume a 50% compression ratio */
	rsize = MIN(rsize, MAX_PAYLOAD_LEN);
	result = g_malloc(rsize);

	/*
	 * Prepare call to inflate().
	 */

	inz->next_in = (gpointer) buf;
	inz->avail_in = len;

	inflated = 0;

	for (;;) {
		/*
		 * Resize output buffer if needed.
		 * Never grow the result buffer to more than MAX_PAYLOAD_LEN bytes.
		 */

		if (rsize == inflated) {
			rsize += MAX(len, MIN_GROW);
			rsize = MIN(rsize, MAX_PAYLOAD_LEN);

			if (rsize == inflated) {		/* Reached maximum size! */
				g_warning("GGEP payload %d would be larger than %d bytes",
					token, MAX_PAYLOAD_LEN);
				failed = TRUE;
				break;
			}

			g_assert(rsize > inflated);

			result = g_realloc(result, rsize);
		}

		inz->next_out = (guchar *) result + inflated;
		inz->avail_out = rsize - inflated;

		/*
		 * Decompress data.
		 */

		ret = inflate(inz, Z_SYNC_FLUSH);
		inflated += rsize - inflated - inz->avail_out;

		g_assert(inflated <= rsize);

		if (ret == Z_STREAM_END)				/* All done! */
			break;

		if (ret != Z_OK) {
			if (dbg) g_warning("decompression of GGEP payload %d failed: %s",
				token, zlib_strerror(ret));
			failed = TRUE;
			break;
		}
	}

	/*
	 * Dispose of decompressor.
	 */

	ret = inflateEnd(inz);
	if (ret != Z_OK)
		g_warning("while freeing decompressor for GGEP payload %d: %s",
			token, zlib_strerror(ret));

	wfree(inz, sizeof(*inz));

	/*
	 * Return NULL on error, fill `retlen' if OK.
	 */

	if (failed) {
		G_FREE_NULL(result);
		return NULL;
	}

	*retlen = inflated;

	return result;				/* OK, successfully inflated */
}
#endif

/**
 * Inflate `len' bytes starting at `buf' into the supplied output buffer
 * of `outlen' bytes starting at `out'.
 *
 * The payload `token' is given only in case there is an error to report.
 *
 * @return inflated length if OK, -1 on error.
 */
static gint
ggep_inflate_into(gchar *buf, gint len, gchar *out, gint outlen, gint token)
{
	z_streamp inz;
	gint ret;
	gint result;

	g_assert(buf);
	g_assert(len > 0);
	g_assert(out);
	g_assert(outlen > 0);

	/*
	 * Allocate decompressor.
	 */

	inz = walloc(sizeof(*inz));

	inz->zalloc = NULL;
	inz->zfree = NULL;
	inz->opaque = NULL;

	ret = inflateInit(inz);

	if (ret != Z_OK) {
		wfree(inz, sizeof(*inz));
		g_warning("unable to initialize decompressor for GGEP payload %d: %s",
			token, zlib_strerror(ret));
		return -1;
	}

	/*
	 * Preapre call to a single inflate().
	 */

	inz->next_in = (gpointer) buf;
	inz->avail_in = len;

	inz->next_out = (gpointer) out;
	inz->avail_out = outlen;
	
	ret = inflate(inz, Z_FINISH);

	if (ret == Z_STREAM_END)
		result = outlen - inz->avail_out;
	else {
		if (dbg) g_warning("decompression of GGEP payload %d failed: %s",
			token, zlib_strerror(ret));
		result = -1;
	}

	/*
	 * Dispose of decompressor.
	 */

	ret = inflateEnd(inz);
	if (ret != Z_OK)
		g_warning("while freeing decompressor for GGEP payload %d: %s",
			token, zlib_strerror(ret));

	wfree(inz, sizeof(*inz));

	return result;
}

/**
 * Decode the GGEP payload pointed at by `exv' into `buf' of `len' bytes.
 * If the GGEP payload is neither COBS-encoded nor deflated, the operation
 * is a mere copy.
 *
 * It is an error if `len' bytes are not enough to hold the whole payload.
 *
 * Returns the amount of bytes copied into `buf', -1 on error.
 */
gint
ggep_decode_into(extvec_t *exv, gchar *buf, gint len)
{
	gchar *pbase;					/* Current payload base */
	gint plen;						/* Curernt payload length */
	gchar *uncobs = NULL;			/* COBS-decoded buffer */
	gint result;					/* Decoded length */

	g_assert(exv);
	g_assert(exv->ext_type == EXT_GGEP);
	g_assert(buf);
	g_assert(len > 0);

	pbase = exv->ext_payload;
	plen = exv->ext_paylen;

	/*
	 * If there is no COBS decoding nor deflation needed, simply copy.
	 */

	if (!exv->ext_ggep_cobs && !exv->ext_ggep_deflate) {
		if (len < plen)
			return -1;
		memcpy(buf, pbase, plen);
		return plen;
	}

	/*
	 * COBS decoding must be performed before inflation, if any.
	 * However, if no inflation will be required, we can decode directly
	 * in the supplied output buffer.
	 */

	if (exv->ext_ggep_cobs) {
		if (!exv->ext_ggep_deflate) {
			if (!cobs_decode_into(pbase, plen, buf, len, &result))
				return -1;

			g_assert(result <= plen);
			g_assert(result <= len);

			return result;
		} else {
			uncobs = walloc(plen);		/* At worse slightly oversized */

			if (!cobs_decode_into(pbase, plen, uncobs, plen, &result)) {
				result = -1;
				goto out;
			}

			g_assert(result <= plen);

			/*
			 * Replace current payload base/length with the COBS buffer.
			 */

			pbase = uncobs;
			plen = result;
		}

		/* FALL THROUGH */
	}

	g_assert(exv->ext_ggep_deflate);

	/*
	 * Payload is deflated, inflate it into the output buffer.
	 */

	result = ggep_inflate_into(pbase, plen, buf, len, exv->ext_token);

out:
	if (uncobs != NULL)
		wfree(uncobs, exv->ext_paylen);

	return result;
}

/**
 * Initialize a GGEP stream object, capable of receiving multiple GGEP
 * extensions, written into the supplied buffer.
 *
 * @param data		start of buffer where data will be written
 * @param len		length of supplied buffer
 */
void
ggep_stream_init(ggep_stream_t *gs, gpointer data, gint len)
{
	gs->outbuf = data;
	gs->end = gs->outbuf + len;
	gs->o = data;
	gs->last_fp = gs->fp = gs->lp = NULL;
	gs->magic_emitted = FALSE;
	gs->begun = FALSE;
	gs->zd = NULL;
}

/**
 * Called when there is an error during the writing of the payload.
 * Restore the stream to the state it had before we began.
 */
static void
ggep_stream_cleanup(ggep_stream_t *gs)
{
	g_assert(gs->begun);

	gs->begun = FALSE;
	gs->o = gs->fp;		/* Back to the beginning of the failed extension */

	if (gs->zd) {
		zlib_deflater_free(gs->zd, TRUE);
		gs->zd = NULL;
	}
}

/**
 * Append char to the GGEP stream.
 *
 * @return FALSE if there's not enough room in the output.
 */
static gboolean
ggep_stream_appendc(ggep_stream_t *gs, gchar c)
{
	if (gs->o >= gs->end)
		return FALSE;

	*(gs->o++) = c;

	return TRUE;
}

/**
 * Append data to the GGEP stream.
 *
 * @return FALSE if there's not enough room in the output.
 */
static gboolean
ggep_stream_append(ggep_stream_t *gs, gpointer data, gint len)
{
	if (gs->o + len > gs->end)
		return FALSE;

	memcpy(gs->o, data, len);
	gs->o += len;

	return TRUE;
}

/**
 * Begin emission of GGEP extension.
 *
 * @param id		the ID of the GGEP extension
 * @param wflags	whether COBS / deflate should be used.
 *
 * @return TRUE if OK, FALSE if there's not enough room in the output.
 * On error, the stream is left in a clean state.
 */
gboolean
ggep_stream_begin(ggep_stream_t *gs, gchar *id, guint32 wflags)
{
	gint idlen;
	guint8 flags = 0;

	g_assert(gs->outbuf != NULL);		/* Stream not closed */

	/*
	 * Emit leading magic byte if not done already.
	 */

	if (!gs->magic_emitted) {
		if (!ggep_stream_appendc(gs, GGEP_MAGIC))
			return FALSE;
		gs->magic_emitted = TRUE;
	}

	idlen = strlen(id);

	g_assert(idlen > 0);
	g_assert(idlen < 16);

	/*
	 * Compute leading flags.
	 */

	if (wflags & GGEP_W_COBS)
		flags |= GGEP_F_COBS;
	if (wflags & GGEP_W_DEFLATE)
		flags |= GGEP_F_DEFLATE;
	flags |= idlen & GGEP_F_IDLEN;

	gs->flags = flags;

	/*
	 * Emit the flags, keeping track of the position where they were
	 * written.
	 *
	 * When the extension ends, we'll perhaps need to come back there and
	 * update some of the flags, depending on whether we really deflated
	 * or performed COBS, for instance.  Or to mark the extension as being
	 * the last one of the GGEP block.
	 */

	gs->fp = gs->o;			/* Also marks the first byte of the extension */

	if (!ggep_stream_append(gs, &flags, 1))
		return FALSE;

	/*
	 * Emit the extension ID.
	 */

	if (!ggep_stream_append(gs, id, idlen))
		goto cleanup;

	/*
	 * We don't know what the size of the extension will end-up being.
	 * And the size of the extension can be encoded with a variable amount
	 * of bytes.
	 *
	 * We reserve a single byte for the extension length, and save the place
	 * where it is stored.  Later on, as we write extension data, we'll
	 * move data around in the buffer should we need more than one byte to
	 * store the extension length.
	 */

	gs->lp = gs->o;
	if (!ggep_stream_appendc(gs, '\0'))
		goto cleanup;

	/*
	 * If deflation is needed, but not COBS, then we can allocate a deflation
	 * stream to write directly into the buffer.  Otherwise, we'll need to
	 * deflate to a temporary (dynamically allocated) buffer and COBS the
	 * data later.
	 */

	g_assert(gs->zd == NULL);

	if (wflags & GGEP_W_DEFLATE) {
		if (wflags & GGEP_W_COBS)
			gs->zd = zlib_deflater_make(NULL, 0, Z_DEFAULT_COMPRESSION);
		else
			gs->zd = zlib_deflater_make_into(NULL, 0,
				gs->o, gs->end - gs->o, Z_DEFAULT_COMPRESSION);
	}

	/*
	 * If we need to COBS data, initialize the COBS stream to perform
	 * transformation as we write data to the stream.
	 */

	if (wflags & GGEP_W_COBS)
		cobs_stream_init(&gs->cs, gs->o, gs->end - gs->o);

	/*
	 * We successfully begun the extension.
	 * All the data we'll now be appending count as payload data.
	 */

	gs->begun = TRUE;

	return TRUE;

cleanup:
	gs->o = gs->fp;
	return FALSE;
}

/**
 * The vectorized version of ggep_stream_write().
 *
 * @return TRUE if OK.  On error, the stream is brought back to a clean state.
 */
gboolean
ggep_stream_writev(ggep_stream_t *gs, struct iovec *iov, gint iovcnt)
{
	gint i;
	struct iovec *xiov;

	g_assert(gs->begun);

	/*
	 * If deflation is configured, pass all the data to the deflater.
	 */

	if (gs->flags & GGEP_F_DEFLATE) {
		g_assert(gs->zd != NULL);

		for (i = iovcnt, xiov = iov; i--; xiov++) {
			if (!zlib_deflate_data(gs->zd, xiov->iov_base, xiov->iov_len))
				goto cleanup;
		}

		return TRUE;
	}

	/*
	 * If COBS is required, filter data through the COBS stream.
	 */

	if (gs->flags & GGEP_F_COBS) {
		for (i = iovcnt, xiov = iov; i--; xiov++) {
			if (!cobs_stream_write(&gs->cs, xiov->iov_base, xiov->iov_len))
				goto cleanup;
		}

		return TRUE;
	}

	/*
	 * Write data directly into the payload.
	 */

	for (i = iovcnt, xiov = iov; i--; xiov++) {
		if (!ggep_stream_append(gs, xiov->iov_base, xiov->iov_len))
			goto cleanup;
	}

	return TRUE;

cleanup:
	ggep_stream_cleanup(gs);
	return FALSE;
}

/**
 * Write data into the payload of the extension begun with ggep_stream_begin().
 *
 * @return TRUE if OK.  On error, the stream is brought back to a clean state.
 */
gboolean
ggep_stream_write(ggep_stream_t *gs, gpointer data, gint len)
{
	struct iovec iov;

	iov.iov_base = data;
	iov.iov_len = len;

	return ggep_stream_writev(gs, &iov, 1);
}

/**
 * End the extension begun with ggep_stream_begin().
 *
 * @return TRUE if OK.  On error, the stream is brought back to a clean state.
 */
gboolean
ggep_stream_end(ggep_stream_t *gs)
{
	gint plen = 0;
	gint8 hlen[3];
	gint slen;

	g_assert(gs->begun);

	/*
	 * If we initiated compression, flush the stream.
	 */

	if (gs->flags & GGEP_F_DEFLATE) {
		gint ilen;

		g_assert(gs->zd);

		if (!zlib_deflate_close(gs->zd))
			goto cleanup;

		plen = zlib_deflater_outlen(gs->zd);

		/*
		 * If data compress to a larger size than the original input,
		 * then we don't need compression.  CPU is cheaper than bandwidth,
		 * so uncompress the data and put them back in.
		 */

		ilen = zlib_deflater_inlen(gs->zd);

		if (plen > ilen) {
			gpointer data;
			gboolean ok;

			if (ggep_debug)
				g_warning("GGEP \"%.*s\" not compressing %d bytes into %d",
					*gs->fp & GGEP_F_IDLEN, gs->fp + 1, ilen, plen);

			data = zlib_uncompress(zlib_deflater_out(gs->zd), plen, ilen);
			if (data == NULL)
				goto cleanup;

			/*
			 * Remove any deflate indication.
			 */

			gs->flags &= ~GGEP_F_DEFLATE;
			*gs->fp &= ~GGEP_F_DEFLATE;

			zlib_deflater_free(gs->zd, TRUE);
			gs->zd = NULL;

			/*
			 * Rewind stream right after the begin call, and write the
			 * original data, possibly COBS-ing it on the fly if that
			 * was requested.
			 */

			gs->o = gs->lp + 1;		/* Rewind after NUL "length" byte */
			ok = ggep_stream_write(gs, data, ilen);
			g_free(data);

			if (!ok)
				goto cleanup;
		}
	}

	/*
	 * If data was deflated and also requires COBS encoding, then it was
	 * deflated into a temporary buffer.  We now need to pass it through
	 * the COBS stream.
	 */

	if ((gs->flags & GGEP_F_DEFLATE) && (gs->flags & GGEP_F_COBS)) {
		gchar *deflated = zlib_deflater_out(gs->zd);

		if (!cobs_stream_write(&gs->cs, deflated, plen))
			goto cleanup;
	}

	/*
	 * Get rid of the deflating stream.
	 */

	if (gs->zd) {
		zlib_deflater_free(gs->zd, TRUE);
		gs->zd = NULL;
	}

	/*
	 * If data went through COBS, close the COBS stream.
	 */

	if (gs->flags & GGEP_F_COBS) {
		gboolean saw_nul;

		plen = cobs_stream_close(&gs->cs, &saw_nul);
		if (plen == -1)
			goto cleanup;

		/*
		 * If it was not necessary to COBS the data, un-COBS them in place.
		 */

		if (!saw_nul) {
			gint ilen;

			if (NULL == cobs_decode(gs->lp + 1, plen, &ilen, TRUE))
				goto cleanup;

			if (ggep_debug)
				g_warning("GGEP \"%.*s\" no need to COBS %d bytes into %d",
					*gs->fp & GGEP_F_IDLEN, gs->fp + 1, ilen, plen);

			/*
			 * Remove any COBS indication.
			 */

			gs->flags &= ~GGEP_F_COBS;
			*gs->fp &= ~GGEP_F_COBS;

			plen = ilen;

			/*
			 * Adjust stream pointer to point right after the data.
			 */

			gs->o = gs->lp + (1 + plen);	/* +1 to skip NUL "length" byte */
		}
	}

	/*
	 * If there was neither COBS nor deflate, compute the payload length
	 * by looking at the current output pointer.
	 */

	if (!(gs->flags & (GGEP_F_COBS|GGEP_F_DEFLATE)))
		plen = (gs->o - gs->lp) - 1;		/* -1 to skip NUL "length" byte */

	/*
	 * Now that we have the final payload data in the buffer, we may have
	 * to shift it to the right to make room for the length bytes, which are
	 * stored at the beginning.  We only reserved 1 byte for the length.
	 */

	if (ggep_debug > 2)
		printf("GGEP \"%.*s\" payload holds %d byte%s\n",
			*gs->fp & GGEP_F_IDLEN, gs->fp + 1, plen, plen == 1 ? "" : "s");

	if (plen <= 63) {
		slen = 1;
		hlen[0] = GGEP_L_LAST | (plen & GGEP_L_VALUE);
	} else if (plen <= 4095) {
		slen = 2;
		hlen[0] = GGEP_L_CONT | ((plen >> GGEP_L_VSHIFT) & GGEP_L_VALUE);
		hlen[1] = GGEP_L_LAST | (plen & GGEP_L_VALUE);
	} else if (plen <= 262143) {
		slen = 3;
		hlen[0] = GGEP_L_CONT | ((plen >> (2*GGEP_L_VSHIFT)) & GGEP_L_VALUE);
		hlen[1] = GGEP_L_CONT | ((plen >> GGEP_L_VSHIFT) & GGEP_L_VALUE);
		hlen[2] = GGEP_L_LAST | (plen & GGEP_L_VALUE);
	} else {
		g_warning("too large GGEP payload length (%d bytes) for \"%.*s\"",
			plen, *gs->fp & GGEP_F_IDLEN, gs->fp + 1);
		goto cleanup;
	}

	/*
	 * Shift payload if length is greater than 64, i.e. if we need more than
	 * the single byte we reserved to write the length.
	 */

	gs->o = gs->lp + (plen + 1);		/* Ensure it is correct before move */

	if (slen > 1) {
		gchar *start = gs->lp + 1;

		if (gs->o + (slen - 1) >= gs->end)
			goto cleanup;

		memmove(start + (slen - 1), start, plen);
		gs->o += (slen - 1);
	}

	/*
	 * Copy the length and terminate extension.
	 */

	memcpy(gs->lp, hlen, slen);			/* Size of extension */
	gs->last_fp = gs->fp;				/* Last successfully written ext. */

	gs->fp = gs->lp = NULL;
	gs->begun = FALSE;

	g_assert(gs->o <= gs->end);			/* No overwriting */

	return TRUE;

cleanup:
	ggep_stream_cleanup(gs);
	return FALSE;
}

/**
 * We're done with the stream, close it.
 *
 * @return the length of the writen data in the whole stream.
 */
gint
ggep_stream_close(ggep_stream_t *gs)
{
	gint len;

	g_assert(!gs->begun);			/* Not in the middle of an extension! */
	g_assert(gs->outbuf != NULL);	/* Not closed already */

	/*
	 * If we ever wrote anything, `gs->last_fp' will point to the last
	 * extension in the block.
	 */

	if (gs->last_fp == NULL)
		len = 0;
	else {
		*gs->last_fp |= GGEP_F_LAST;
		len = gs->o - gs->outbuf;
	}

	gs->outbuf = NULL;				/* Mark stream as closed */

	return len;
}

/**
 * The vectorized version of ggep_stream_pack().
 *
 * @return TRUE if written successfully.
 */
gboolean
ggep_stream_packv(ggep_stream_t *gs,
	gchar *id, struct iovec *iov, gint iovcnt, guint32 wflags)
{
	if (!ggep_stream_begin(gs, id, wflags))
		return FALSE;

	if (!ggep_stream_writev(gs, iov, iovcnt))
		return FALSE;

	if (!ggep_stream_end(gs))
		return FALSE;

	return TRUE;
}

/**
 * Pack extension data in initialized stream.
 * The extension's name is `id' and its payload is represented by `plen'
 * bytes starting at `payload'.
 *
 * If `GGEP_W_COBS' is set, COBS encoding is attempted if there is a
 * NUL byte within the payload.
 *
 * If `GGEP_W_DEFLATE' is set, we attempt to deflate the payload.  If the
 * output is larger than the initial size, we emit the original payload
 * instead.
 *
 * @return TRUE if written successfully.  On error, the stream is reset as
 * if the write attempt had not taken place, so one may continue writing
 * shorter extension, if the error is due to a lack of space in the stream.
 */
gboolean
ggep_stream_pack(ggep_stream_t *gs,
	gchar *id, gchar *payload, gint plen, guint32 wflags)
{
	struct iovec iov;

	iov.iov_base = payload;
	iov.iov_len = plen;

	return ggep_stream_packv(gs, id, &iov, 1, wflags);
}

/* vi: set ts=4 sw=4 cindent: */
