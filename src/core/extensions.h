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
 * Gnutella message extension handling.
 *
 * @author Raphael Manfredi
 * @date 2002-2003
 */

#ifndef _core_extensions_h_
#define _core_extensions_h_

#include <glib.h>

/**
 * Known extension types.
 */

typedef enum ext_type {
	EXT_UNKNOWN = 0,	/**< Unknown extension */
	EXT_XML,			/**< XML extension */
	EXT_HUGE,			/**< Hash/URN Gnutella Extensions */
	EXT_GGEP,			/**< Gnutella Generic Extension Protocol */
	EXT_NONE,			/**< Not really an extension, only overhead */

	EXT_TYPE_COUNT
} ext_type_t;

/**
 * Extension tokens.
 */

typedef enum ext_token {
	EXT_T_UNKNOWN = 0,		/**< Unknown */
	EXT_T_URN_BITPRINT,		/**< urn:bitprint: */
	EXT_T_URN_SHA1,			/**< urn:sha1: */
	EXT_T_URN_EMPTY,		/**< urn: */
	EXT_T_XML,				/**< XML payload */
	EXT_T_UNKNOWN_GGEP,		/**< Unknown GGEP extension */
	EXT_T_OVERHEAD,			/**< Pure overhead */
	EXT_T_GGEP_LIME_XML,	/**< LimeWire XML metadata, in query hits */
	/* sort below */
	EXT_T_GGEP_ALT,			/**< Alternate locations in query hits */
	EXT_T_GGEP_BH,			/**< Browseable host indication */
	EXT_T_GGEP_CT,			/**< Resource creation time */
	EXT_T_GGEP_DU,			/**< Daily Uptime */
	EXT_T_GGEP_FW,			/**< Firewalled-to-Firewalled protocol version */
	EXT_T_GGEP_GGEP,		/**< Name of known GGEP extensions, NUL-separated */
	EXT_T_GGEP_GTKG_IPV6,	/**< GTKG IPv6 address */
	EXT_T_GGEP_GTKG_TLS,	/**< GTKG TLS support indication */
	/* watch out, below is off-order */
	EXT_T_GGEP_GTKGV1,		/**< GTKG version indication #1 */
	EXT_T_GGEP_GUE,			/**< GUESS support */
	EXT_T_GGEP_H,			/**< GGEP binary hash value */
	EXT_T_GGEP_HNAME,		/**< Hostname info, in query hits */
	EXT_T_GGEP_IP,			/**< IP:Port, in ping and pongs (F2F) */
	EXT_T_GGEP_IPP,			/**< IP:Port, in pongs (UHC) */
	EXT_T_GGEP_LF,			/**< Large File, in query hits */
	EXT_T_GGEP_LOC,			/**< Locale preferences */
	EXT_T_GGEP_PATH,		/**< Shared file path, in query hits */
	EXT_T_GGEP_PHC,			/**< Packed HostCaches, in pongs (UHC) */
	EXT_T_GGEP_PUSH,		/**< Push proxy info, in query hits */
	EXT_T_GGEP_SCP,			/**< Support Cached Pongs, in pings (UHC) */
	EXT_T_GGEP_T,			/**< Textual information in query hits */
	EXT_T_GGEP_UA,			/**< User-Agent string */
	EXT_T_GGEP_UDPHC,		/**< UDP HostCache, in pongs (UHC) */
	EXT_T_GGEP_UP,			/**< UltraPeer information */
	EXT_T_GGEP_VC,			/**< Vendor Code */
	EXT_T_GGEP_VMSG,		/**< Array of vendor message codes supported */
	EXT_T_GGEP_u,			/**< HUGE URN in ASCII */

	EXT_T_TOKEN_COUNT
} ext_token_t;

#define GGEP_NAME(x) ext_ggep_name(CAT2(EXT_T_GGEP_,x))
#define GGEP_GTKG_NAME(x) ext_ggep_name(CAT2(EXT_T_GGEP_GTKG_,x))

/**
 * A public extension descriptor.
 *
 * An extension block is structured thustly:
 *
 *    - <.................len.......................>
 *    - <..headlen.><..........paylen...............>
 *    - +-----------+-------------------------------+
 *    - |   header  |      extension payload        |
 *    - +-----------+-------------------------------+
 *    - ^           ^
 *    - base        payload
 *
 * To be able to transparently handle decompression and COBS decoding of GGEP
 * extensions, the public structure exposes no data fields.  Everything must
 * be fetched through accessors, which will make COBS and decompression
 * invisible.
 *
 * Each of the fields shown above can be accessed via ext_xxx().
 * For instance, access to the payload must be made through ext_payload(),
 * and access to the whole length via ext_len().
 */
typedef struct extvec {
	const gchar *ext_name;	/**< Extension name (may be NULL) */
	ext_token_t ext_token;	/**< Extension token */
	ext_type_t ext_type;	/**< Extension type */
	gpointer opaque;		/**< Internal information */
} extvec_t;

#define MAX_EXTVEC		32	/**< Maximum amount of extensions in vector */

/*
 * Public interface.
 */

void ext_init(void);
void ext_close(void);

void ext_prepare(extvec_t *exv, gint exvcnt);
gint ext_parse(gchar *buf, gint len, extvec_t *exv, gint exvcnt);
void ext_reset(extvec_t *exv, gint exvcnt);

gboolean ext_is_printable(const extvec_t *e);
gboolean ext_is_ascii(const extvec_t *e);
gboolean ext_has_ascii_word(const extvec_t *e);

void ext_dump(FILE *fd, const extvec_t *extvec, gint extcnt,
	const gchar *prefix, const gchar *postfix, gboolean payload);

const gchar *ext_payload(const extvec_t *e);
guint16 ext_paylen(const extvec_t *e);
const gchar *ext_base(const extvec_t *e);
guint16 ext_headlen(const extvec_t *e);
guint16 ext_len(const extvec_t *e);
const gchar *ext_ggep_id_str(const extvec_t *e);
const gchar *ext_ggep_name(ext_token_t id);

void ext_prepare(extvec_t *exv, gint exvcnt);
void ext_reset(extvec_t *exv, gint exvcnt);

#endif	/* _core_extensions_h_ */

/* vi: set ts=4 sw=4 cindent: */

