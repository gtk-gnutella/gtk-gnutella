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
 * @ingroup core
 * @file
 *
 * Gnutella Generic Extension Protocol (GGEP).
 *
 * @author Raphael Manfredi
 * @date 2002-2004
 */

#include "common.h"

RCSID("$Id$")

#include <zlib.h>	/* Z_DEFAULT_COMPRESSION */

#include "ggep.h"
#include "extensions.h"
#include "lib/cobs.h"
#include "lib/misc.h"
#include "lib/walloc.h"
#include "lib/zlib_util.h"

#include "if/gnet_property_priv.h"

#include "lib/override.h"			/* Must be the last header included */

/**
 * Check whether a GGEP stream descriptor is valid.
 */
gboolean
ggep_stream_is_valid(ggep_stream_t *gs)
{
	if (NULL == gs)
		return FALSE;

	if (gs->magic != GGEP_MAGIC_ID)
		return FALSE;

	if (NULL == gs->outbuf)
		return FALSE;

	if (NULL == gs->end || gs->end <= gs->outbuf)
		return FALSE;

	if (NULL == gs->o || gs->o < gs->outbuf || gs->o > gs->end)
		return FALSE;

	if (gs->magic_emitted != TRUE && gs->magic_emitted != FALSE)
		return FALSE;

	if (gs->begun != TRUE && gs->begun != FALSE)
		return FALSE;

	if (gs->begun) {
		if ((gs->flags & GGEP_F_COBS) && !cobs_stream_is_valid(&gs->cs))
			return FALSE;

		if ((gs->flags & GGEP_F_DEFLATE) && NULL == gs->zd)
			return FALSE;

		if (!(gs->flags & GGEP_F_DEFLATE) && NULL != gs->zd)
			return FALSE;
	}

	return TRUE;
}

/**
 * Initialize a GGEP stream object, capable of receiving multiple GGEP
 * extensions, written into the supplied buffer.
 *
 * @param gs		a GGEP stream
 * @param data		start of buffer where data will be written
 * @param len		length of supplied buffer
 */
void
ggep_stream_init(ggep_stream_t *gs, gpointer data, size_t len)
{
	g_assert(len <= INT_MAX);
	g_assert(len != 0);

	gs->magic = GGEP_MAGIC_ID;
	gs->outbuf = data;
	gs->size = len;
	gs->end = &gs->outbuf[len];
	gs->o = data;
	gs->last_fp = gs->fp = gs->lp = NULL;
	gs->magic_emitted = FALSE;
	gs->begun = FALSE;
	gs->zd = NULL;

	g_assert(ggep_stream_is_valid(gs));
}

/**
 * @return	the number of bytes that can still be written to the stream
 *			at maximum.
 */
static inline size_t
ggep_stream_avail(ggep_stream_t *gs)
{
	size_t avail = gs->end - gs->o;
	g_assert(avail <= gs->size);
	return avail;
}

/**
 * Called when there is an error during the writing of the payload.
 * Restore the stream to the state it had before we began.
 */
static void
ggep_stream_cleanup(ggep_stream_t *gs)
{
	g_assert(ggep_stream_is_valid(gs));
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
static inline gboolean
ggep_stream_appendc(ggep_stream_t *gs, char c)
{
	g_assert(ggep_stream_is_valid(gs));

	if (0 == ggep_stream_avail(gs))
		return FALSE;

	*(gs->o++) = c;

	return TRUE;
}

/**
 * Append data to the GGEP stream.
 *
 * @return FALSE if there's not enough room in the output.
 */
static inline gboolean
ggep_stream_append(ggep_stream_t *gs, gconstpointer data, size_t len)
{
	g_assert(ggep_stream_is_valid(gs));

	if (len > ggep_stream_avail(gs))
		return FALSE;

	memcpy(gs->o, data, len);
	gs->o += len;

	return TRUE;
}

/**
 * Begin emission of GGEP extension.
 *
 * @param gs		a GGEP stream
 * @param id		the ID of the GGEP extension
 * @param wflags	whether COBS / deflate should be used.
 *
 * @return TRUE if OK, FALSE if there's not enough room in the output.
 * On error, the stream is left in a clean state.
 */
gboolean
ggep_stream_begin(ggep_stream_t *gs, const char *id, guint32 wflags)
{
	int idlen;
	guint8 flags = 0;

	g_assert(ggep_stream_is_valid(gs));
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
				gs->o, ggep_stream_avail(gs), Z_DEFAULT_COMPRESSION);
	}

	/*
	 * If we need to COBS data, initialize the COBS stream to perform
	 * transformation as we write data to the stream.
	 */

	if (wflags & GGEP_W_COBS)
		cobs_stream_init(&gs->cs, gs->o, ggep_stream_avail(gs));

	/*
	 * We successfully begun the extension.
	 * All the data we'll now be appending count as payload data.
	 */

	g_assert(ggep_stream_is_valid(gs));

	gs->begun = TRUE;

	g_assert(!(gs->flags & GGEP_F_COBS) || cobs_stream_is_valid(&gs->cs));
	g_assert(!(gs->flags & GGEP_F_DEFLATE) || gs->zd != NULL);
	g_assert((gs->flags & GGEP_F_DEFLATE) || gs->zd == NULL);

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
ggep_stream_writev(ggep_stream_t *gs, const struct iovec *iov, int iovcnt)
{
	const struct iovec *xiov;
	int i;

	g_assert(ggep_stream_is_valid(gs));
	g_assert(gs->begun);
	g_assert(iovcnt >= 0);

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
ggep_stream_write(ggep_stream_t *gs, gconstpointer data, size_t len)
{
	struct iovec iov;
	const struct iovec *p_iov = &iov;

	g_assert(len <= INT_MAX);
	iov.iov_base = deconstify_gpointer(data);
	iov.iov_len = len;

	return ggep_stream_writev(gs, p_iov, 1);
}

/**
 * End the extension begun with ggep_stream_begin().
 *
 * @return TRUE if OK.  On error, the stream is brought back to a clean state.
 */
gboolean
ggep_stream_end(ggep_stream_t *gs)
{
	size_t plen = 0;
	gint8 hlen[3];
	size_t slen;

	g_assert(ggep_stream_is_valid(gs));
	g_assert(gs->begun);

	/*
	 * If we initiated compression, flush the stream.
	 */

	if (gs->flags & GGEP_F_DEFLATE) {
		size_t ilen;

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

			if (GNET_PROPERTY(ggep_debug) > 2)
				g_warning("GGEP \"%.*s\" not compressing %d bytes into %d",
					(int) (*gs->fp & GGEP_F_IDLEN), gs->fp + 1,
					(int) ilen, (int) plen);

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
			/* No overwriting */
			g_assert((size_t) (gs->end - gs->o) <= gs->size);
			ok = ggep_stream_write(gs, data, ilen);
			G_FREE_NULL(data);

			if (!ok)
				goto cleanup;
		} else if (GNET_PROPERTY(ggep_debug) > 2)
			g_warning("GGEP \"%.*s\" compressed %d bytes into %d",
				(int) (*gs->fp & GGEP_F_IDLEN),
				gs->fp + 1, (int) ilen, (int) plen);
	}

	/*
	 * If data was deflated and also requires COBS encoding, then it was
	 * deflated into a temporary buffer.  We now need to pass it through
	 * the COBS stream.
	 */

	if ((gs->flags & GGEP_F_DEFLATE) && (gs->flags & GGEP_F_COBS)) {
		char *deflated = zlib_deflater_out(gs->zd);

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
		if (0 == plen)
			goto cleanup;

		/*
		 * If it was not necessary to COBS the data, un-COBS them in place.
		 */

		if (!saw_nul) {
			size_t ilen;

			if (NULL == cobs_decode(gs->lp + 1, plen, &ilen, TRUE))
				goto cleanup;

			if (GNET_PROPERTY(ggep_debug) > 2)
				g_warning("GGEP \"%.*s\" no need to COBS %d bytes into %d",
					(int) (*gs->fp & GGEP_F_IDLEN), gs->fp + 1,
					(int) ilen, (int) plen);

			/*
			 * Remove any COBS indication.
			 */

			gs->flags &= ~GGEP_F_COBS;
			*gs->fp &= ~GGEP_F_COBS;

			plen = ilen;

			/*
			 * Adjust stream pointer to point right after the data.
			 */

			gs->o = &gs->lp[1 + plen];	/* +1 to skip NUL "length" byte */
			/* No overwriting */
			g_assert((size_t) (gs->end - gs->o) <= gs->size);
		} else if (GNET_PROPERTY(ggep_debug) > 2)
			g_message("GGEP \"%.*s\" COBS-ed into %d bytes",
				(int) (*gs->fp & GGEP_F_IDLEN), gs->fp + 1, (int) plen);
	}

	/*
	 * If there was neither COBS nor deflate, compute the payload length
	 * by looking at the current output pointer.
	 */

	if (!(gs->flags & (GGEP_F_COBS|GGEP_F_DEFLATE)))
		plen = (gs->o - gs->lp) - 1;		/* -1 to skip NUL "length" byte */
		g_assert((size_t) plen <= gs->size);

	/*
	 * Now that we have the final payload data in the buffer, we may have
	 * to shift it to the right to make room for the length bytes, which are
	 * stored at the beginning.  We only reserved 1 byte for the length.
	 */

	if (GNET_PROPERTY(ggep_debug) > 3)
		g_message("GGEP \"%.*s\" payload holds %d byte%s",
			(int) (*gs->fp & GGEP_F_IDLEN), gs->fp + 1,
			(int) plen, plen == 1 ? "" : "s");

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
			(int) plen, (int) (*gs->fp & GGEP_F_IDLEN), gs->fp + 1);
		goto cleanup;
	}

	/*
	 * Shift payload if length is greater than 64, i.e. if we need more than
	 * the single byte we reserved to write the length.
	 */

	gs->o = gs->lp + (plen + 1);		/* Ensure it is correct before move */
	g_assert((size_t) (gs->end - gs->o) <= gs->size);	/* No overwriting */

	if (slen > 1) {
		char *start = gs->lp + 1;

		if ((size_t) (gs->end - gs->o) < (slen - 1))
			goto cleanup;

		memmove(start + (slen - 1), start, plen);
		gs->o += (slen - 1);
	}

	/*
	 * Copy the length and terminate extension.
	 */

	memcpy(gs->lp, hlen, slen);		/* Size of extension */
	gs->last_fp = gs->fp;			/* Last successfully written ext. */

	gs->fp = gs->lp = NULL;
	gs->begun = FALSE;

	g_assert((size_t) (gs->end - gs->o) <= gs->size);	/* No overwriting */

	return TRUE;

cleanup:
	g_assert((size_t) (gs->end - gs->o) <= gs->size);	/* No overwriting */
	ggep_stream_cleanup(gs);
	return FALSE;
}

/**
 * We're done with the stream, close it.
 *
 * @return the length of the writen data in the whole stream.
 */
size_t
ggep_stream_close(ggep_stream_t *gs)
{
	size_t len;

	g_assert(!gs->begun);			/* Not in the middle of an extension! */
	g_assert(gs->outbuf != NULL);	/* Not closed already */

	/*
	 * If we ever wrote anything, `gs->last_fp' will point to the last
	 * extension in the block.
	 */

	if (gs->last_fp == NULL) {
		len = 0;
	} else {
		*gs->last_fp |= GGEP_F_LAST;
		len = gs->o - gs->outbuf;
	}

	gs->outbuf = NULL;				/* Mark stream as closed */

	g_assert(len <= gs->size);
	return len;
}

/**
 * The vectorized version of ggep_stream_pack().
 *
 * @return TRUE if written successfully.
 */
gboolean
ggep_stream_packv(ggep_stream_t *gs,
	const char *id, const struct iovec *iov, int iovcnt, guint32 wflags)
{
	g_assert(iovcnt >= 0);

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
 *
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
	const char *id, gconstpointer payload, size_t plen, guint32 wflags)
{
	struct iovec iov;
	const struct iovec *p_iov = &iov;

	g_assert(id);
	g_assert(0 == plen || NULL != payload);
	g_assert(plen <= INT_MAX);

	iov.iov_base = deconstify_gpointer(payload);
	iov.iov_len = plen;

	return ggep_stream_packv(gs, id, p_iov, 1, wflags);
}

/* vi: set ts=4 sw=4 cindent: */
