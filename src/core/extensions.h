/*
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

#include "common.h"

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
 *
 * WARNING: the actual values of the enums below matter, because of the way
 * ext_ggep_name() is built.  If the order is not right, gtk-gnutella will
 * not startup and will complain that the ggeptable[] is not sorted properly.
 *
 * The order of the enum values must match that of the stringified extensions
 * listed in the ggeptable[] array (which must be sorted lexically because
 * binary searches are used to locate extensions by name)..
 */

typedef enum ext_token {
	EXT_T_UNKNOWN = 0,		/**< Unknown */
	EXT_T_URN_BITPRINT,		/**< urn:bitprint: */
	EXT_T_URN_BTIH,			/**< urn:btih: */
	EXT_T_URN_ED2KHASH,		/**< urn:ed2khash: */
	EXT_T_URN_MD5,			/**< urn:md5: */
	EXT_T_URN_SHA1,			/**< urn:sha1: */
	EXT_T_URN_TTH,			/**< urn:ttroot: */
	EXT_T_URN_UNKNOWN,		/**< Unknown (but syntactically correct) URN */
	EXT_T_URN_EMPTY,		/**< urn: */
	EXT_T_URN_BAD,			/**< urn */
	EXT_T_XML,				/**< XML payload */
	EXT_T_UNKNOWN_GGEP,		/**< Unknown GGEP extension */
	EXT_T_OVERHEAD,			/**< Pure overhead */
	/* sort below according to ggeptable[] in core/extension.c */
	EXT_T_GGEP_6,			/**< IPv6 address */
	EXT_T_GGEP_LIME_XML,	/**< LimeWire XML metadata, in query hits */
	EXT_T_GGEP_A,			/**< Same as GGEP ALT but used in HEAD Pongs */
	EXT_T_GGEP_A6,			/**< Same as GGEP ALT6 but used in HEAD Pongs */
	EXT_T_GGEP_ALT,			/**< IPv4:port alternate locations in query hits */
	EXT_T_GGEP_ALT6,		/**< IPv6:port alternate locations in query hits */
	EXT_T_GGEP_ALT6_TLS,	/**< TLS-capability bitmap for GGEP ALT6 */
	EXT_T_GGEP_ALT_TLS,		/**< TLS-capability bitmap for GGEP ALT */
	EXT_T_GGEP_BH,			/**< Browseable host indication */
	EXT_T_GGEP_C,			/**< Result Code in HEAD Pongs */
	EXT_T_GGEP_CHAT,		/**< Chat support info in qhit trailers */
	EXT_T_GGEP_CT,			/**< Resource creation time */
	EXT_T_GGEP_DHT,			/**< DHT version and flags, in pongs */
	EXT_T_GGEP_DHTIPP,		/**< DHT nodes in packed IPv4:Port format (pongs) */
	EXT_T_GGEP_DHTIPP6,		/**< DHT nodes in packed IPv6:Port format (pongs) */
	EXT_T_GGEP_DU,			/**< Daily Uptime */
	EXT_T_GGEP_F,			/**< Flags in HEAD Pongs */
	EXT_T_GGEP_FW,			/**< Firewalled-to-Firewalled protocol version */
	EXT_T_GGEP_GGEP,		/**< Name of known GGEP extensions, NUL-separated */
	EXT_T_GGEP_GTKG_IPV6,	/**< GTKG IPv6 address (deprecated @0.97) */
	EXT_T_GGEP_GTKG_TLS,	/**< GTKG TLS support ind. (deprecated @0.97) */
	/* watch out, below is off-order */
	EXT_T_GGEP_GTKGV,		/**< GTKG version indication */
	EXT_T_GGEP_GTKGV1,		/**< GTKG version ind. #1 (deprecated @0.97) */
	/* keep remaining sorted */
	EXT_T_GGEP_GUE,			/**< GUESS support */
	EXT_T_GGEP_H,			/**< GGEP binary hash value */
	EXT_T_GGEP_HNAME,		/**< Hostname info, in query hits and ALOC */
	EXT_T_GGEP_I6,			/**< IPv6 support indication (can flag no IPv4) */
	EXT_T_GGEP_IP,			/**< IP:Port, in ping and pongs (F2F) */
	EXT_T_GGEP_IPP,			/**< IPv4:port, in pongs (UHC) */
	EXT_T_GGEP_IPP6,		/**< IPv6:port, in pongs (UHC) */
	EXT_T_GGEP_IPP6_TLS,	/**< TLS-capability bitmap for GGEP IPP6 */
	EXT_T_GGEP_IPP_TLS,		/**< TLS-capability bitmap for GGEP IPP */
	EXT_T_GGEP_LF,			/**< Large File, in query hits */
	EXT_T_GGEP_LOC,			/**< Locale preferences */
	EXT_T_GGEP_M,			/**< MIME type for queries (byte code) */
	EXT_T_GGEP_NP,			/**< do Not Proxy the query (OOB) */
	EXT_T_GGEP_P,			/**< Push alt-locs in HEAD Pongs */
	EXT_T_GGEP_PATH,		/**< Shared file path, in query hits */
	EXT_T_GGEP_PHC,			/**< Packed HostCaches, in pongs (UHC) */
	EXT_T_GGEP_PR,			/**< Partial Result, in queries and hits */
	EXT_T_GGEP_PR0,			/**< Empty partial set (query hits) */
	EXT_T_GGEP_PR1,			/**< Partial intervals coded on 1 byte */
	EXT_T_GGEP_PR2,			/**< Partial intervals coded on 2 bytes */
	EXT_T_GGEP_PR3,			/**< Partial intervals coded on 3 bytes */
	EXT_T_GGEP_PR4,			/**< Partial intervals coded on 4 bytes */
	EXT_T_GGEP_PRU,			/**< Partial Result Unverified (query hits) */
	EXT_T_GGEP_PUSH,		/**< IPv4:port push proxy info, in query hits */
	EXT_T_GGEP_PUSH6,		/**< IPv6:port push proxy info, in query hits */
	EXT_T_GGEP_PUSH6_TLS,	/**< TLS-capability bitmap for GGEP PUSH6 */
	EXT_T_GGEP_PUSH_TLS,	/**< TLS-capability bitmap for GGEP PUSH */
	EXT_T_GGEP_Q,			/**< Queue status in HEAD Pongs */
	EXT_T_GGEP_QK,			/**< GUESS Query Key */
	EXT_T_GGEP_SCP,			/**< Support Cached Pongs, in pings (UHC) */
	EXT_T_GGEP_SO,			/**< Secure OOB */
	EXT_T_GGEP_T,			/**< Same as ALT_TLS but for HEAD Pongs */
	EXT_T_GGEP_T6,			/**< Same as ALT6_TLS but for HEAD Pongs */
	EXT_T_GGEP_TLS,			/**< Supports TLS */
	EXT_T_GGEP_TT,			/**< Tigertree root hash (TTH); binary */
	EXT_T_GGEP_UA,			/**< User-Agent string */
	EXT_T_GGEP_UDPHC,		/**< UDP HostCache, in pongs (UHC) */
	EXT_T_GGEP_UP,			/**< UltraPeer information */
	EXT_T_GGEP_V,			/**< Vendor Code in HEAD Pongs */
	EXT_T_GGEP_VC,			/**< Vendor Code */
	EXT_T_GGEP_VMSG,		/**< Array of vendor message codes supported */
	EXT_T_GGEP_WH,			/**< Feature query */
	EXT_T_GGEP_XQ,			/**< eXtended Query; for longer query strings */
	EXT_T_GGEP_Z,			/**< Signals UDP compression support (for GUESS) */
	EXT_T_GGEP_avail,		/**< "avail" in ALOC v0.1 (PFS: available bytes) */
	EXT_T_GGEP_client_id,	/**< "client-id" in ALOC & PROX v0.0 (i.e. GUID) */
	EXT_T_GGEP_features,	/**< Unknown value, PROX v0.0 */
	EXT_T_GGEP_firewalled,	/**< Firewalled status in ALOC v0.0 */
	EXT_T_GGEP_fwt_version,	/**< Fw-to-fw transfer version, PROX v0.0 */
	EXT_T_GGEP_guid,		/**< Servent's GUID in NOPE v0.0 */
	EXT_T_GGEP_length,		/**< File length in ALOC v0.1 */
	EXT_T_GGEP_port,		/**< Servent's Port in ALOC v0.0 */
	EXT_T_GGEP_proxies,		/**< Push proxies in PROX v0.0 */
	EXT_T_GGEP_tls,			/**< Servent TLS support indication in ALOC v0.1 */
	EXT_T_GGEP_ttroot,		/**< TTH root in ALOC v0.1 */
	EXT_T_GGEP_u,			/**< HUGE URN in ASCII */

	EXT_T_TOKEN_COUNT
} ext_token_t;

#define GGEP_NAME(x) ext_ggep_name(EXT_T_GGEP_ ## x)
#define GGEP_GTKG_NAME(x) ext_ggep_name(EXT_T_GGEP_GTKG_ ## x)

/**
 * A public extension descriptor.
 *
 * An extension block is structured thusly:
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
	const char *ext_name;	/**< Extension name (may be NULL) */
	ext_token_t ext_token;	/**< Extension token */
	ext_type_t ext_type;	/**< Extension type */
	void *opaque;			/**< Internal information */
} extvec_t;

#define MAX_EXTVEC		32	/**< Maximum amount of extensions in vector */

/*
 * Public interface.
 */

void ext_init(void);
void ext_close(void);

void ext_prepare(extvec_t *exv, int exvcnt);
int ext_parse(const char *buf, int len, extvec_t *exv, int exvcnt);
int ext_parse_nul(const char *buf, int len, char **endptr, extvec_t *, int);
void ext_reset(extvec_t *exv, int exvcnt);

bool ext_is_printable(const extvec_t *e);
bool ext_is_ascii(const extvec_t *e);
bool ext_has_ascii_word(const extvec_t *e);

void ext_dump(FILE *fd, const extvec_t *extvec, int extcnt,
	const char *prefix, const char *postfix, bool payload);

const void *ext_payload(const extvec_t *e);
uint16 ext_paylen(const extvec_t *e);
const char *ext_base(const extvec_t *e);
uint16 ext_headlen(const extvec_t *e);
uint16 ext_len(const extvec_t *e);
const char *ext_ggep_id_str(const extvec_t *e);
bool ext_ggep_is_deflated(const extvec_t *e);
const char *ext_huge_urn_name(const extvec_t *e);
const char *ext_ggep_name(ext_token_t id);

size_t ext_to_string_buf(const extvec_t *e, char *buf, size_t len);
const char *ext_to_string(const extvec_t *e);

int ext_ggep_strip(char *buf, int len, const char *key);

#endif	/* _core_extensions_h_ */

/* vi: set ts=4 sw=4 cindent: */

