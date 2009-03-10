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
 * @ingroup core
 * @file
 *
 * Gnutella Generic Extension Protocol (GGEP).
 *
 * @author Raphael Manfredi
 * @date 2002-2003
 */

#ifndef _core_ggep_h_
#define _core_ggep_h_

#include "common.h"

#include "extensions.h"
#include "lib/cobs.h"
#include "lib/zlib_util.h"

#define GGEP_MAGIC		0xC3U		/**< GGEP extension prefix */

/*
 * GGEP Extension Header Flags.
 */

#define GGEP_F_LAST		0x80U		/**< Last extension in GGEP block */
#define GGEP_F_COBS		0x40U		/**< Whether COBS was used on payload */
#define GGEP_F_DEFLATE	0x20U		/**< Whether payload was deflated */
#define GGEP_F_MBZ		0x10U		/**< Bits that Must Be Zero */
#define GGEP_F_IDLEN	0x0fU		/**< Where ID length is stored */

/*
 * GGEP Length Encoding.
 */

#define GGEP_L_CONT		'\x80'		/**< Continuation present */
#define GGEP_L_LAST		'\x40'		/**< Last byte */
#define GGEP_L_VALUE	'\x3f'		/**< Value */
#define GGEP_L_VSHIFT	6

#define GGEP_L_XFLAGS	(GGEP_L_CONT | GGEP_L_LAST)

/*
 * The "H" extension
 */

#define GGEP_H_SHA1		0x01		/**< Binary SHA1 */
#define GGEP_H_BITPRINT	0x02		/**< Bitprint (SHA1 + Tiger tree root) */
#define GGEP_H_MD5		0x03		/**< Binary MD5 */
#define GGEP_H_UUID		0x04		/**< Binary UUID (GUID-like) */
#define GGEP_H_MD4		0x05		/**< Binary MD4 */

/*
 * Flags for ggep_ext_write() and friends.
 */

#define GGEP_W_LAST		0x00000001	/**< This is the last extension */
#define GGEP_W_COBS		0x00000002	/**< Attempt COBS encoding, if needed */
#define GGEP_W_DEFLATE	0x00000004	/**< Attempt payload compression */
#define GGEP_W_FIRST	0x00000008	/**< First extension, write GGEP_MAGIC */

enum ggep_magic { GGEP_MAGIC_ID = 0x62961da4U };

/**
 * Structure keeping track of incremental GGEP writes.
 */
typedef struct ggep_stream {
	enum ggep_magic magic;/**< Magic number */
	char *outbuf;			/**< Base address of output buffer */
	char *end;				/**< First address beyond output buffer */
	char *o;				/**< Where next output should go */
	char *fp;				/**< Where flags for current extension are */
	char *lp;				/**< Where length should be written when known */
	char *last_fp;			/**< Flags of last successfully written ext. */
	size_t size;			/**< Size of the outbuf buffer */
	guint8 flags;			/**< Extension flags (COBS / DEFLATE) */
	gboolean magic_emitted;	/**< Whether leading magic was emitted */
	gboolean begun;			/**< Whether extension was correctly begun */
	cobs_stream_t cs;		/**< Used if COBS needed */
	zlib_deflater_t *zd;	/**< Allocated and used if deflation needed */
} ggep_stream_t;

/*
 * Public interface.
 */

struct iovec;

gint ggep_decode_into(extvec_t *exv, char *buf, size_t len);

void ggep_stream_init(ggep_stream_t *gs, gpointer data, size_t len);
gboolean ggep_stream_begin(ggep_stream_t *gs, const char *id, guint32 wflags);
gboolean ggep_stream_writev(ggep_stream_t *gs,
	const struct iovec *iov, gint iovcnt);
gboolean ggep_stream_write(ggep_stream_t *gs, gconstpointer data, size_t len);
gboolean ggep_stream_end(ggep_stream_t *gs);
size_t ggep_stream_close(ggep_stream_t *gs);
gboolean ggep_stream_packv(ggep_stream_t *gs,
	const char *id, const struct iovec *iov, gint iovcnt, guint32 wflags);
gboolean ggep_stream_pack(ggep_stream_t *gs,
	const char *id, gconstpointer payload, size_t plen, guint32 wflags);

gboolean ggep_stream_is_valid(ggep_stream_t *gs);

#endif	/* _core_ggep_h_ */

/* vi: set ts=4 sw=4 cindent: */

