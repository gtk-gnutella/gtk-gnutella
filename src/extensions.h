/*
 * $Id$
 *
 * Copyright (c) 2002, Raphael Manfredi
 *
 * Gnutella message extension handling.
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

#ifndef __extensions_h__
#define __extensions_h__

#include <glib.h>

/*
 * An extension descriptor.
 *
 * The extension block is structured thustly:
 *
 *    <.................len.......................>
 *    <..headlen.><..........paylen...............>
 *    +-----------+-------------------------------+
 *    |   header  |      extension payload        |
 *    +-----------+-------------------------------+
 *    ^           ^
 *    base        payload
 *
 * The <headlen> part is simply <len> - <paylen> so it is not stored.
 * Likewise, we store only the beginning of the payload, the base can be
 * computed if needed.
 */
typedef struct extvec {
	guchar *ext_payload;	/* Start of payload buffer */
	gchar *ext_name;		/* Extension name (may be NULL) */
	gint ext_token;			/* Extension token */
	guint16 ext_len;		/* Extension length (header + payload) */
	guint16 ext_paylen;		/* Extension payload length */
	guint8 ext_type;		/* Extension type */

	union {
		struct {
			gboolean extu_cobs;			/* Payload is COBS-encoded */
			gboolean extu_deflate;		/* Payload is deflated */
		} extu_ggep;
	} ext_u;

} extvec_t;

#define ext_headlen(e)	((e)->ext_len - (e)->ext_paylen)
#define ext_base(e)		((e)->ext_payload - ext_headlen(e))

/* 
 * Union access shortcuts.
 */

#define ext_ggep_cobs		ext_u.extu_ggep.extu_cobs
#define ext_ggep_deflate	ext_u.extu_ggep.extu_deflate

#define MAX_EXTVEC		32	/* Maximum amount of extensions in vector */

/*
 * Known extension types.
 */

#define EXT_UNKNOWN		0	/* Unknown extension */
#define EXT_XML			1	/* XML extension */
#define EXT_HUGE		2	/* Hash/URN Gnutella Extensions */
#define EXT_GGEP		3	/* Gnutella Generic Extension Protocol */
#define EXT_MAXTYPE		3

/*
 * Extension tokens.
 */

#define EXT_T_UNKNOWN			0	/* Unknown */
#define EXT_T_URN_SHA1			1	/* urn:sha1: */
#define EXT_T_URN_BITPRINT		2	/* urn:bitprint: */
#define EXT_T_URN_EMPTY			3	/* urn: */
#define EXT_T_XML				4	/* XML payload */
#define EXT_T_GGEP_H			5	/* GGEP binary hash value */

/*
 * Public interaface.
 */

gint ext_parse(guchar *buf, gint len, extvec_t *exv, gint extcnt);

gboolean ext_is_printable(extvec_t *e);
gboolean ext_is_ascii(extvec_t *e);
gboolean ext_has_ascii_word(extvec_t *e);

void ext_dump(FILE *fd, extvec_t *extvec, gint extcnt,
	gchar *prefix, gchar *postfix, gboolean payload);

#endif	/* __extensions_h__ */

/* vi: set ts=4: */

