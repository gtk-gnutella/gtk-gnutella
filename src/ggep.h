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

#ifndef _ggep_h_
#define _ggep_h_

#include "extensions.h"

#include <glib.h>

#define GGEP_MAGIC		'\xc3'		/* GGEP extension prefix */

/*
 * GGEP Extension Header Flags.
 */

#define GGEP_F_LAST		'\x80'		/* Last extension in GGEP block */
#define GGEP_F_COBS		'\x40'		/* Whether COBS was used on payload */
#define GGEP_F_DEFLATE	'\x20'		/* Whether payload was deflated */
#define GGEP_F_MBZ		'\x10'		/* Bits that Must Be Zero */
#define GGEP_F_IDLEN	'\x0f'		/* Where ID length is stored */

/*
 * GGEP Length Encoding.
 */

#define GGEP_L_CONT		'\x80'		/* Continuation present */
#define GGEP_L_LAST		'\x40'		/* Last byte */
#define GGEP_L_VALUE	'\x3f'		/* Value */
#define GGEP_L_VSHIFT	6

#define GGEP_L_XFLAGS	(GGEP_L_CONT | GGEP_L_LAST)

/*
 * The "H" extension
 */

#define GGEP_H_SHA1		0x01		/* Binary SHA1 */
#define GGEP_H_BITPRINT	0x02		/* Bitprint (SHA1 + Tiger tree root) */
#define GGEP_H_MD5		0x03		/* Binary MD5 */
#define GGEP_H_UUID		0x04		/* Binary UUID (GUID-like) */
#define GGEP_H_MD4		0x05		/* Binary MD4 */

/*
 * Flags for ggep_ext_write() and friends.
 */

#define GGEP_W_LAST		0x00000001	/* This is the last extension */
#define GGEP_W_COBS		0x00000002	/* Attempt COBS encoding, if needed */
#define GGEP_W_DEFLATE	0x00000004	/* Attempt payload compression */
#define GGEP_W_FIRST	0x00000008	/* First extension, write GGEP_MAGIC */

/*
 * Public interface.
 */

struct iovec;

gint ggep_decode_into(extvec_t *exv, gchar *buf, gint len);

gint ggep_ext_write(
	gchar *buf, gint len,
	gchar *id, gchar *payload, gint plen,
	guint32 wflags);

gint ggep_ext_writev(
	gchar *buf, gint len,
	gchar *id, struct iovec *iov, gint iovcnt,
	guint32 wflags);

void ggep_ext_mark_last(guchar *start);

#endif	/* _ggep_h_ */

/* vi: set ts=4: */

