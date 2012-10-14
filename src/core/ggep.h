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
 * @ingroup core
 * @file
 *
 * Gnutella Generic Extension Protocol (GGEP).
 *
 * @author Raphael Manfredi
 * @date 2002-2003, 2012
 */

#ifndef _core_ggep_h_
#define _core_ggep_h_

#include "common.h"

#include "extensions.h"
#include "lib/cobs.h"
#include "lib/zlib_util.h"

#define GGEP_MAGIC		((unsigned char) 0xC3U)	/**< GGEP extension prefix */

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

#define GGEP_W_STRIP	(1U << 0)	/**< Strip if payload is empty */
#define GGEP_W_COBS		(1U << 1)	/**< Attempt COBS encoding, if needed */
#define GGEP_W_DEFLATE	(1U << 2)	/**< Attempt payload compression */

/*
 * Error codes.
 */

#define GGEP_E_OK		0			/**< OK */
#define GGEP_E_SPACE	1			/**< No more space in output buffer */
#define GGEP_E_DEFLATE	2			/**< Error during zlib deflation */
#define GGEP_E_COBS		3			/**< Error during COBS encoding */
#define GGEP_E_ZCLOSE	4			/**< Error during zlib stream close */
#define GGEP_E_INFLATE	5			/**< Error during zlib inflation */
#define GGEP_E_CCLOSE	6			/**< Error during COBS stream close */
#define GGEP_E_UNCOBS	7			/**< Unable to un-COBS data */
#define GGEP_E_LARGE	8			/**< GGEP payload too large */
#define GGEP_E_INTERNAL	9			/**< Internal error */

enum ggep_magic { GGEP_MAGIC_ID = 0x62961da4U };

/**
 * Structure keeping track of incremental GGEP writes.
 *
 * It is made visible to allow allocation on the stack.
 */
typedef struct ggep_stream {
	enum ggep_magic magic;	/**< Magic number */
	char *outbuf;			/**< Base address of output buffer */
	char *end;				/**< First address beyond output buffer */
	char *o;				/**< Where next output should go */
	char *fp;				/**< Where flags for current extension are */
	char *lp;				/**< Where length should be written when known */
	char *last_fp;			/**< Flags of last successfully written ext. */
	size_t size;			/**< Size of the outbuf buffer */
	uint8 flags;			/**< Extension flags (COBS / DEFLATE) */
	cobs_stream_t cs;		/**< Used if COBS needed */
	zlib_deflater_t *zd;	/**< Allocated and used if deflation needed */
	unsigned magic_sent:1;	/**< Whether leading magic was emitted */
	unsigned begun:1;		/**< Whether extension was correctly begun */
	unsigned strip_empty:1;	/**< Whether empty extension should be stripped */
} ggep_stream_t;

/*
 * Public interface.
 */

const char *ggep_strerror(unsigned errnum);
extern unsigned ggep_errno;

int ggep_decode_into(extvec_t *exv, char *buf, size_t len);

void ggep_stream_init(ggep_stream_t *gs, void *data, size_t len);
bool ggep_stream_begin(ggep_stream_t *gs, const char *id, uint32 wflags);
bool ggep_stream_writev(ggep_stream_t *gs,
	const iovec_t *iov, int iovcnt);
bool ggep_stream_write(ggep_stream_t *gs, const void *data, size_t len);
bool ggep_stream_end(ggep_stream_t *gs);
size_t ggep_stream_close(ggep_stream_t *gs);
bool ggep_stream_packv(ggep_stream_t *gs,
	const char *id, const iovec_t *iov, int iovcnt, uint32 wflags);
bool ggep_stream_pack(ggep_stream_t *gs,
	const char *id, const void *payload, size_t plen, uint32 wflags);

bool ggep_stream_is_valid(ggep_stream_t *gs);

/**
 * @return human-readable error string for last error (current ggep_errno).
 */
static inline const char *
ggep_errstr(void)
{
	return ggep_strerror(ggep_errno);
}

#endif	/* _core_ggep_h_ */

/* vi: set ts=4 sw=4 cindent: */

