/*
 * $Id$
 *
 * Copyright (c) 2002-2003, Raphael Manfredi
 *
 * Gnutella Generic Extension Protocol (GGEP).
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

#include "gnutella.h"		/* For <string.h> + dbg */

#include <sys/types.h>		/* FreeBSD requires this before <sys/uio.h> */
#include <sys/uio.h>		/* For struct iovec */

#include <zlib.h>

#include "ggep.h"
#include "extensions.h"
#include "huge.h"			/* For SHA1_RAW_SIZE */
#include "override.h"			/* Must be the last header included */

RCSID("$Id$");

#define MAX_PAYLOAD_LEN		65536	/* Max length for deflated payload */
#define MIN_GROW			256		/* Minimum grow size for inflated buffer */

/*
 * ggep_inflate
 *
 * Inflate `len' bytes starting at `buf', up to MAX_PAYLOAD_LEN bytes.
 * The payload `token' is given only in case there is an error to report.
 *
 * Returns the allocated inflated buffer, and its inflated length in `retlen'.
 * Returns NULL on error.
 */
static gchar *ggep_inflate(gchar *buf, gint len, gint *retlen, gint token)
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

/*
 * ggep_inflate_into
 *
 * Inflate `len' bytes starting at `buf' into the supplied output buffer
 * of `outlen' bytes starting at `out'.
 *
 * The payload `token' is given only in case there is an error to report.
 *
 * Returns inflated length if OK, -1 on error.
 */
static gint ggep_inflate_into(
	gchar *buf, gint len, gchar *out, gint outlen, gint token)
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

/*
 * ggep_decode_into
 *
 * Decode the GGEP payload pointed at by `exv' into `buf' of `len' bytes.
 * If the GGEP payload is neither COBS-encoded nor deflated, the operation
 * is a mere copy.
 *
 * It is an error if `len' bytes are not enough to hold the whole payload.
 *
 * Returns the amount of bytes copied into `buf', -1 on error.
 */
gint ggep_decode_into(extvec_t *exv, gchar *buf, gint len)
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
	 * COBS decoding must be performed before deflation, if any.
	 * However, if no deflation will be required, we can decode directly
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

/*
 * ggep_ext_writev
 *
 * Vectorized version of ggep_ext_write().
 */
gint ggep_ext_writev(
	gchar *buf, gint len,
	gchar *id, struct iovec *iov, gint iovcnt,
	guint32 wflags)
{
	gint idlen;
	gboolean needs_cobs = FALSE;
	gchar *p;
	gint i;
	gint8 hlen[3];
	gint slen;
	gint needed;
	guint8 flags = 0;
	struct iovec *xiov;
	gint plen = 0;
	gchar *payload = NULL;
	gint initial_plen;

	g_assert(buf);
	g_assert(len > 0);
	g_assert(id);
	g_assert(iov);
	g_assert(iovcnt > 0);

	idlen = strlen(id);

	g_assert(idlen > 0);
	g_assert(idlen < 16);
	g_assert(!(wflags & GGEP_W_DEFLATE));	/* XXX deflate not supported yet */

	/*
	 * If NUL is not allowed, check the payload to see whether we need
	 * to activate COBS encoding.
	 */

	if (wflags & GGEP_W_COBS) {
		for (i = iovcnt, xiov = iov; i-- && !needs_cobs; xiov++) {
			gint j;

			for (j = xiov->iov_len, p = xiov->iov_base; j--; /**/) {
				if (*p++ == '\0') {
					needs_cobs = TRUE;		/* Will break us from outer loop */
					break;
				}
			}
		}
	}

	/*
	 * Compute initial payload length.
	 */

	i = iovcnt;
	xiov = iov;

	while (i--)
		plen += (xiov++)->iov_len;

	initial_plen = plen;

	/*
	 * If COBS is needed, encode into a new buffer.
	 *
	 * We don't do this in `buf' directly since we need to encode the
	 * length of the raw extension data in the header.  And we'll know
	 * the final length only after COBS is done.
	 */

	if (needs_cobs)
		payload = cobs_encodev(iov, iovcnt, &plen);

	/*
	 * Encode length.
	 */

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
		g_warning("too large GGEP payload length (%d bytes) for \"%s\"",
			plen, id);
		goto bad;
	}

	/*
	 * Compute leading flags.
	 */

	if (wflags & GGEP_W_LAST)
		flags |= GGEP_F_LAST;
	if (needs_cobs)
		flags |= GGEP_F_COBS;
	flags |= idlen & GGEP_F_IDLEN;

	/*
	 * Now we know how many bytes we need to write.
	 */

	needed = ((wflags & GGEP_W_FIRST) ? 1 : 0)		/* Leading magic */
		+ 1					/* Leading flags */
		+ idlen				/* ID name */
		+ slen				/* Payload size indication in the header */
		+ plen;				/* Raw data size to write */

	/*
	 * If there's not enough room in the buffer, bail out.
	 */

	if (dbg > 4)
		printf("GGEP \"%s\" flags=0x%x payload=%d raw=%d needed=%d avail=%d\n",
			id, flags, initial_plen, plen, needed, len);

	if (len < needed)
		goto bad;

	/*
	 * Copy data into provided buffer.
	 */

	p = buf;

	if (wflags & GGEP_W_FIRST)
		*p++ = GGEP_MAGIC;				/* Leading magic byte */

	*p++ = flags;						/* Flags */
	memcpy(p, id, idlen);				/* ID */
	p += idlen;
	memcpy(p, hlen, slen);				/* Size */
	p += slen;

	if (payload != NULL) {				/* Vector was linearized */
		memcpy(p, payload, plen);		/* Raw payload */
		p += plen;
		G_FREE_NULL(payload);
	} else {
		for (i = iovcnt, xiov = iov; i--; xiov++) {
			gint xlen = xiov->iov_len;

			memcpy(p, xiov->iov_base, xlen);
			p += xlen;
		}
	}

	g_assert(p - buf == needed);		/* We have not forgotten anything */

	return needed;

bad:
	if (needs_cobs)
		G_FREE_NULL(payload);
	return -1;
}

/*
 * ggep_ext_write
 *
 * Write extension data in memory, within buffer `buf' of `len' bytes.
 * The extension's name is `id' and its payload is represented by `plen'
 * bytes starting at `payload'.
 *
 * If `GGEP_W_LAST' is set, marks the extension as being the last one.
 * Otherwise, you can always mark it as being the last afterwards
 * by calling "ggep_ext_mark_last(buf)" upon successful return.
 *
 * If `GGEP_W_COBS' is set, COBS encoding is attempted if there is a
 * NUL byte within the payload.
 *
 * If `GGEP_W_DEFLATE' is set, we attempt to deflate the payload.  If the
 * output is larger than the initial size, we emit the original payload
 * instead.
 *
 * If `GGEP_W_FIRST' is set, we emit the leading GGEP_MAGIC byte before
 * the extension.
 *
 * Returns the amount of bytes written, or -1 if the buffer is too short
 * to hold the whole extension.
 */
gint ggep_ext_write(
	gchar *buf, gint len,
	gchar *id, gchar *payload, gint plen,
	guint32 wflags)
{
	struct iovec iov;

	iov.iov_base = payload;
	iov.iov_len = plen;

	return ggep_ext_writev(buf, len, id, &iov, 1, wflags);
}

/*
 * ggep_ext_mark_last
 *
 * Mark extension starting at `start' as being the last one.
 */
void ggep_ext_mark_last(guchar *start)
{
	g_assert(start);
	g_assert(0 == (*start & GGEP_F_MBZ));		/* Sanity checks */
	g_assert(0 != (*start & GGEP_F_IDLEN));
	g_assert(!(*start & GGEP_F_LAST));

	*start |= GGEP_F_LAST;
}

