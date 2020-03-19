/*
 * Copyright (c) 2002-2003, 2009, Raphael Manfredi
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
 * @date 2009
 */

#include "common.h"

#include <zlib.h>

#include "extensions.h"
#include "ggep.h"

#include "lib/ascii.h"
#include "lib/atoms.h"
#include "lib/halloc.h"
#include "lib/htable.h"
#include "lib/log.h"
#include "lib/mempcpy.h"
#include "lib/str.h"
#include "lib/stringify.h"
#include "lib/walloc.h"

#include "lib/override.h"		/* Must be the last header included */

#include "if/gnet_property_priv.h"

#define HUGE_FS		0x1CU		/**< Field separator (HUGE) */

#define GGEP_MAXLEN	65535		/**< Maximum decompressed length */
#define GGEP_GROW	512			/**< Minimum chunk growth when resizing */

/**
 * An extension descriptor.
 *
 * The extension block is structured thusly:
 *
 *    - <.................len.......................>
 *    - <..headlen.><..........paylen...............>
 *    - +-----------+-------------------------------+
 *    - |   header  |      extension payload        |
 *    - +-----------+-------------------------------+
 *    - ^           ^
 *    - base        payload
 *
 * The "<headlen>" part is simply "<len>" - "<paylen>" so it is not stored.
 * Likewise, we store only the beginning of the payload, the base can be
 * computed if needed.
 *
 * All those pointers refer DIRECTLY to the message we received, so naturally
 * one MUST NOT alter the data we can read or we would corrupt the messages
 * before forwarding them.
 *
 * There is a slight complication introduced with GGEP extensions, since the
 * data there can be COBS encoded, and even deflated.  Therefore, reading
 * directly data from ext_phys_payload could yield compressed data, not
 * something really usable.
 *
 * Therefore, the extension structure is mostly private, and routines are
 * provided to access the data.  Decompression and decoding of COBS is lazily
 * performed when they wish to access the extension data.
 *
 * The ext_phys_xxx fields refer to the physical information about the
 * extension.  The ext_xxx() routines allow access to the virtual information
 * after decompression and COBS decoding.  Naturally, if the extension is
 * not compressed nor COBS-encoded, the ext_xxx() routine will return the
 * physical data.
 *
 * The structure here refers to the opaque data that is dynamically allocated
 * each time a new extension is found.
 */
typedef struct extdesc {
	const char *ext_phys_payload;	/**< Start of payload buffer */
	const char *ext_payload;		/**< "virtual" payload */
	uint16 ext_phys_len;		/**< Extension length (header + payload) */
	uint16 ext_phys_paylen;		/**< Extension payload length */
	uint16 ext_paylen;			/**< "virtual" payload length */
	uint16 ext_rpaylen;			/**< Length of buffer for "virtual" payload */

	union {
		struct {
			bool extu_cobs;			/**< Payload is COBS-encoded */
			bool extu_deflate;		/**< Payload is deflated */
			const char *extu_id;	/**< Extension ID */
		} extu_ggep;
	} ext_u;

} extdesc_t;

#define ext_phys_headlen(d)	((d)->ext_phys_len - (d)->ext_phys_paylen)
#define ext_phys_base(d)	((d)->ext_phys_payload - ext_phys_headlen(d))

/*
 * Union access shortcuts.
 */

#define ext_ggep_cobs		ext_u.extu_ggep.extu_cobs
#define ext_ggep_deflate	ext_u.extu_ggep.extu_deflate
#define ext_ggep_id			ext_u.extu_ggep.extu_id

/**
 * Flags for ext_parse_buffer.
 */

#define EXT_F_NUL_END		(1 << 0)	/**< Stop at first NUL byte */

static const char * const extype[] = {
	"UNKNOWN",					/**< EXT_UNKNOWN */
	"XML",						/**< EXT_XML */
	"HUGE",						/**< EXT_HUGE */
	"GGEP",						/**< EXT_GGEP */
	"NONE",						/**< EXT_NONE */
};

/***
 *** Extension name screener.
 ***/

/**
 * Reserved word description.
 */
struct rwtable {
	const char *rw_name;	/**< Representation */
	ext_token_t rw_token;	/**< Token value */
};

/** URN name table (sorted) */
static const struct rwtable urntable[] =
{
	{ "bitprint",		EXT_T_URN_BITPRINT },
	{ "btih",			EXT_T_URN_BTIH },
	{ "ed2khash",		EXT_T_URN_ED2KHASH },
	{ "md5",			EXT_T_URN_MD5 },
	{ "sha1",			EXT_T_URN_SHA1 },
	{ "ttroot",			EXT_T_URN_TTH },
};

/** GGEP extension table (sorted) */
static const struct rwtable ggeptable[] =
{
#define GGEP_ID(x) { #x, EXT_T_GGEP_ ## x }
#define GGEP_GTKG_ID(x) { "GTKG." #x, EXT_T_GGEP_GTKG_ ## x }

	GGEP_ID(6),			/**< IPv6 address */
	{ "<", EXT_T_GGEP_LIME_XML }, /**< '<' is less that 'A' but more than '6' */
	GGEP_ID(A),			/**< Same as GGEP ALT but used in HEAD Pongs */
	GGEP_ID(A6),		/**< Same as GGEP ALT6 but used in HEAD Pongs */
	GGEP_ID(ALT),		/**< IPv4:port alt-locs in qhits */
	GGEP_ID(ALT6),		/**< IPv6:port alt-locs in qhits */
	GGEP_ID(ALT6_TLS),	/**< TLS-capability bitmap for GGEP ALT6 */
	GGEP_ID(ALT_TLS),	/**< TLS-capability bitmap for GGEP ALT */
	GGEP_ID(BH),		/**< Browseable host indication */
	GGEP_ID(C),			/**< Result Code in HEAD Pongs */
	GGEP_ID(CHAT),		/**< CHAT indication in query hit trailer */
	GGEP_ID(CT),		/**< Resource creation time */
	GGEP_ID(DHT),		/**< DHT version and flags, in pongs */
	GGEP_ID(DHTIPP),	/**< DHT nodes in packed IPv4:Port format (pongs) */
	GGEP_ID(DHTIPP6),	/**< DHT nodes in packed IPv6:Port format (pongs) */
	GGEP_ID(DU),		/**< Average servent uptime */
	GGEP_ID(F),			/**< Flags in HEAD Pongs */
	GGEP_ID(FW),		/**< Firewalled-to-Firewalled protocol version */
	GGEP_ID(GGEP),		/**< GGEP extension names known, NUL-separated */
	GGEP_GTKG_ID(IPV6),	/**< GTKG IPv6 address (deprecated @0.97) */
	GGEP_GTKG_ID(TLS),	/**< GTKG TLS support indication (deprecated @0.97) */
	GGEP_ID(GTKGV),		/**< GTKG complete version number (binary) */
	GGEP_ID(GTKGV1),	/**< GTKG complete version (bin, deprecated @0.97) */
	GGEP_ID(GUE),		/**< GUESS support */
	GGEP_ID(H),			/**< Hashes in binary form */
	GGEP_ID(HNAME),		/**< Hostname */
	GGEP_ID(I6),		/**< IPv6 support indication (can flag no IPv4) */
	GGEP_ID(IP),		/**< IP:Port in ping and pongs (F2F) */
	GGEP_ID(IPP),		/**< IPv4:Port in pongs (UHC) */
	GGEP_ID(IPP6),		/**< IPv6:Port in pongs (UHC) */
	GGEP_ID(IPP6_TLS),	/**< TLS-capability bitmap for GGEP IPP6 */
	GGEP_ID(IPP_TLS),	/**< TLS-capability bitmap for GGEP IPP */
	GGEP_ID(LF),		/**< Large file size in qhits */
	GGEP_ID(LOC),		/**< Locale preferences, for clustering  */
	GGEP_ID(M),			/**< MIME type for queries (byte code) */
	GGEP_ID(NP),		/**< do Not Proxy (queries; OOB) */
	GGEP_ID(P),			/**< Push alt-locs in HEAD Pongs */
	GGEP_ID(PATH),		/**< Shared file path, in query hits */
	GGEP_ID(PHC),		/**< Packed host caches (UHC) in pongs */
	GGEP_ID(PR),		/**< Partial Result, in queries and hits */
	GGEP_ID(PR0),		/**< Empty partial set (query hits) */
	GGEP_ID(PR1),		/**< Partial intervals coded on 1 byte */
	GGEP_ID(PR2),		/**< Partial intervals coded on 2 bytes */
	GGEP_ID(PR3),		/**< Partial intervals coded on 3 bytes */
	GGEP_ID(PR4),		/**< Partial intervals coded on 4 bytes */
	GGEP_ID(PRU),		/**< Partial Result Unverified (query hits) */
	GGEP_ID(PUSH),		/**< IPv4:port push proxy info array, in qhits */
	GGEP_ID(PUSH6),		/**< IPv6:port push proxy info array, in qhits */
	GGEP_ID(PUSH6_TLS),	/**< TLS-capability bitmap for GGEP PUSH */
	GGEP_ID(PUSH_TLS),	/**< TLS-capability bitmap for GGEP PUSH */
	GGEP_ID(Q),			/**< Queue status in HEAD Pongs */
	GGEP_ID(QK),		/**< GUESS Query Key */
	GGEP_ID(SCP),		/**< Supports cached pongs, in pings (UHC) */
	GGEP_ID(SO),		/**< Secure OOB */
	GGEP_ID(T),			/**< Same as ALT_TLS but for HEAD Pongs */
	GGEP_ID(T6),		/**< Same as ALT6_TLS but for HEAD Pongs */
	GGEP_ID(TLS),		/**< TLS support indication */
	GGEP_ID(TT),		/**< Tigertree root hash (TTH); binary */
	GGEP_ID(UA),		/**< User-Agent string */
	GGEP_ID(UDPHC),		/**< Is an UDP hostcache (UHC) , in pongs */
	GGEP_ID(UP),		/**< Ultrapeer information about free slots */
	GGEP_ID(V),			/**< Vendor code, in HEAD Pongs */
	GGEP_ID(VC),		/**< Vendor code, in pongs */
	GGEP_ID(VMSG),		/**< Array of supported vendor message codes */
	GGEP_ID(WH),		/**< Feature query */
	GGEP_ID(XQ),		/**< eXtended Query; for longer query strings */
	GGEP_ID(Z),			/**< Signals UDP compression support (GUESS queries) */
	GGEP_ID(avail),		/**< Partial file, available length in ALOC v0.1 */
	{ "client-id", EXT_T_GGEP_client_id }, /**< GUID in ALOC v0.0 */
	GGEP_ID(features),	/**< Unknown value, PROX v0.0 */
	GGEP_ID(firewalled),/**< Firewalled status in ALOC v0.0 */
	{ "fwt-version", EXT_T_GGEP_fwt_version }, /**< FW2FW version, PROX v0.0 */
	GGEP_ID(guid),		/**< Servent's GUID in NOPE v0.0 */
	GGEP_ID(length),	/**< File length in ALOC v0.1 */
	GGEP_ID(port),		/**< Servent's Port in ALOC v0.0 */
	GGEP_ID(proxies),	/**< Push proxies in PROX v0.0 */
	GGEP_ID(tls),		/**< TLS support in ALOC v0.1 */
	GGEP_ID(ttroot),	/**< TTH root in ALOC v0.1 */
	GGEP_ID(u),			/**< HUGE URN in ASCII */

#undef GGEP_ID
};

/**
 * Perform a dichotomic search for keywords in the reserved-word table.
 * The `case_sensitive' parameter governs whether lookup is done with or
 * without paying attention to case.
 *
 * @return the keyword token value upon success, EXT_T_UNKNOWN if not found.
 * If keyword was found, its static shared string is returned in `retkw'.
 */
static ext_token_t G_HOT
rw_screen(bool case_sensitive,
	const struct rwtable *table, size_t size,
	const char *word, const char **retkw)
{
	g_assert(retkw);

#define GET_KEY(i) (table[(i)].rw_name)
#define FOUND(i) \
	G_STMT_START { \
		*retkw = table[(i)].rw_name; \
	   	return table[(i)].rw_token; \
		/* NOTREACHED */ \
	} G_STMT_END

	if (case_sensitive)
		BINARY_SEARCH(const char *, word, size,
				strcmp, GET_KEY, FOUND);
	else
		BINARY_SEARCH(const char *, word, size,
				ascii_strcasecmp, GET_KEY, FOUND);

#undef FOUND
#undef GET_KEY

	*retkw = NULL;
	return EXT_T_UNKNOWN;
}

/**
 * Ensure the reserved-word table is lexically sorted.
 */
static void G_COLD
rw_is_sorted(const char *name,
	const struct rwtable *table, size_t size)
{
	size_t i;

	/* Skip the first to have a previous element, tables with a single
	 * element are sorted anyway. */
	for (i = 1; i < size; i++) {
		const struct rwtable *prev = &table[i - 1], *e = &table[i];

		if (
			prev->rw_token >= e->rw_token ||
			strcmp(prev->rw_name, e->rw_name) >= 0
		)
			g_error("reserved word table \"%s\" unsorted "
				"(item #%zu \"%s\" = %d follows \"%s\" = %d)",
				name, i + 1, e->rw_name, e->rw_token,
				prev->rw_name, prev->rw_token);

		if (ggeptable == table) {
			const char *s;

		   	s = ext_ggep_name(e->rw_token);
			if (0 != strcmp(s, e->rw_name)) {
				g_error("table \"%s\" has wrong GGEP ID \"%s\" (item \"%s\")",
					name, s, e->rw_name);
			}
		}
	}
}

/**
 * @return the GGEP token value upon success, EXT_T_UNKNOWN_GGEP if not found.
 * If keyword was found, its static shared string is returned in `retkw'.
 */
static ext_token_t
rw_ggep_screen(char *word, const char **retkw)
{
	ext_token_t t;

	t = rw_screen(TRUE, ggeptable, N_ITEMS(ggeptable), word, retkw);

	return (t == EXT_T_UNKNOWN) ? EXT_T_UNKNOWN_GGEP : t;
}

/**
 * @return the URN token value upon success, EXT_T_UNKNOWN if not found.
 * If keyword was found, its static shared string is returned in `retkw'.
 */
static ext_token_t
rw_urn_screen(const char *word, const char **retkw)
{
	ext_token_t t;

	t = rw_screen(FALSE, urntable, N_ITEMS(urntable), word, retkw);

	return EXT_T_UNKNOWN == t ? EXT_T_URN_UNKNOWN : t;
}

/***
 *** Extension name atoms.
 ***/

static htable_t *ext_names = NULL;

/**
 * Transform the name into a printable form.
 *
 * @return an atom string of that printable form.
 */
static char *
ext_name_atom(const char *name)
{
	char *key;
	char *atom;

	/*
	 * Look whether we already known about this name.
	 */

	atom = htable_lookup(ext_names, name);

	if (atom != NULL)
		return atom;

	/*
	 * The key is always the raw name we're given.
	 *
	 * The value is always a printable form of the name, where non-printable
	 * chars are shown as hexadecimal escapes: \xhh.  However, if there is
	 * no escaping, then the name is also the key (same object).
	 */

	key = wcopy(name, 1 + vstrlen(name));
	atom = hex_escape(key, TRUE); /* strict escaping */

	htable_insert(ext_names, key, atom);

	return atom;
}

/**
 * Callback for freeing entries in the `ext_names' hash table.
 */
static void
ext_names_kv_free(const void *key, void *value, void *unused_udata)
{
	(void) unused_udata;

	if (key != value)
		HFREE_NULL(value);

	wfree(deconstify_pointer(key), 1 + vstrlen(key));
}

/***
 *** Extension parsing.
 ***
 *** All the ext_xxx_parse routines share the same signature and behaviour:
 ***
 *** They extract one extension, as guessed by the leading byte introducing
 *** those extensions and return the amount of entries they added to the
 *** supplied extension vector (this will be typically 1 but for GGEP which
 *** is structured and can therefore grab more than one extension in one call).
 ***
 *** Upon entry, `*retp' points to the start of the extension, and there are
 *** `len' bytes to parse.  There are `exvcnt' slots available in the extension
 *** vector, starting at `exv'.
 ***
 *** On exit, `p' is updated to the first byte following the last successfully
 *** parsed byte.  If the returned value is 0, then `p' is not updated.
 ***/

/**
 * Parses a GGEP block (can hold several extensions).
 */
static int G_HOT
ext_ggep_parse(const char **retp, int len, extvec_t *exv, int exvcnt)
{
	const char *p = *retp;
	const char *end = &p[len];
	const char *lastp = p;				/* Last parsed point */
	int count;

	for (count = 0; count < exvcnt && p < end; /* empty */) {
		uchar flags;
		char id[GGEP_F_IDLEN + 1];
		uint id_len, data_length, i;
		bool length_ended = FALSE;
		const char *name;
		extdesc_t *d;

		g_assert(exv->opaque == NULL);

		/*
		 * First byte is GGEP flags.
		 */

		flags = (uchar) *p++;

		if (flags & GGEP_F_MBZ)		/* A byte that Must Be Zero is set */
			goto abort;

		id_len = flags & GGEP_F_IDLEN;
		g_assert(id_len < sizeof id);

		if (id_len == 0)
			goto abort;

		if ((size_t) (end - p) < id_len) /* Not enough bytes to store the ID! */
			goto abort;

		/*
		 * Read ID, and NUL-terminate it.
		 *
		 * As a safety precaution, only allow ASCII IDs, and nothing in
		 * the control space.  It's not really in the GGEP specs, but it's
		 * safer that way, and should protect us if we parse garbage starting
		 * with 0xC3....
		 *		--RAM, 2004-11-12
		 */

		for (i = 0; i < id_len; i++) {
			int c = *p++;
			if (c == '\0' || !isascii(c) || is_ascii_cntrl(c))
				goto abort;
			id[i] = c;
		}
		id[i] = '\0';

		/*
		 * Read the payload length (maximum of 3 bytes).
		 */

		data_length = 0;
		for (i = 0; i < 3 && p < end; i++) {
			uchar b = *p++;

			/*
			 * Either GGEP_L_CONT or GGEP_L_LAST must be set, thereby
			 * ensuring that the byte cannot be NUL.
			 */

			if (((b & GGEP_L_XFLAGS) == GGEP_L_XFLAGS) || !(b & GGEP_L_XFLAGS))
				goto abort;

			data_length = (data_length << GGEP_L_VSHIFT) | (b & GGEP_L_VALUE);

			if (b & GGEP_L_LAST) {
				length_ended = TRUE;
				break;
			}
		}

		if (!length_ended)
			goto abort;

		/*
		 * Ensure we have enough bytes left for the payload.  If not, it
		 * means the length is garbage.
		 */

		/* Check whether there are enough bytes for the payload */
		if ((size_t) (end - p) < data_length)
			goto abort;

		/*
		 * Some sanity checks:
		 *
		 * A COBS-encoded buffer can be trivially validated.
		 * A deflated payload must be at least 6 bytes with a valid header.
		 */

		if (flags & (GGEP_F_COBS|GGEP_F_DEFLATE)) {
			uint d_len = data_length;

			if (flags & GGEP_F_COBS) {
				if (d_len == 0 || !cobs_is_valid(p, d_len))
					goto abort;
				d_len--;					/* One byte of overhead */
			}

			if (flags & GGEP_F_DEFLATE) {
				uint offset = 0;

				if (d_len < 6)
					goto abort;

				/*
				 * If COBS-ed, since neither the first byte nor the
				 * second byte of the raw deflated payload can be NUL,
				 * the leading COBS code will be at least 3.  Then
				 * the next 2 bytes are the raw deflated header.
				 *
				 * If not COBS-ed, check whether payload holds a valid
				 * deflated header.
				 */

				if (flags & GGEP_F_COBS) {
					if ((uchar) *p < 3)
						goto abort;
					offset = 1;			/* Skip leading byte */
				}

				if (!zlib_is_valid_header(p + offset, d_len))
					goto abort;
			}
		}

		/*
		 * OK, at this point we have validated the GGEP header.
		 */

		WALLOC(d);

		d->ext_phys_payload = p;
		d->ext_phys_paylen = data_length;
		d->ext_phys_len = (p - lastp) + data_length;
		d->ext_ggep_cobs = flags & GGEP_F_COBS;
		d->ext_ggep_deflate = flags & GGEP_F_DEFLATE;

		if (0 == (flags & (GGEP_F_COBS|GGEP_F_DEFLATE))) {
			d->ext_payload = d->ext_phys_payload;
			d->ext_paylen = d->ext_phys_paylen;
		} else
			d->ext_payload = NULL;		/* Will lazily compute, if accessed */

		exv->opaque = d;

		g_assert(ext_phys_headlen(d) >= 0);

		/*
		 * Look whether we know about this extension.
		 *
		 * If we do, the name is the ID as well.  Otherwise, for tracing
		 * and debugging purposes, save the name away, once.
		 */

		exv->ext_type = EXT_GGEP;
		exv->ext_token = rw_ggep_screen(id, &name);
		exv->ext_name = name;

		if (name != NULL)
			d->ext_ggep_id = name;
		else
			d->ext_ggep_id = ext_name_atom(id);

		/*
		 * One more entry, prepare next iteration.
		 */

		exv++;
		count++;
		lastp = p + data_length;
		p = lastp;

		/*
		 * Was this the last extension?
		 */

		if (flags & GGEP_F_LAST)
			break;
	}

	*retp = lastp;	/* Points to first byte after what we parsed */

	return count;

abort:
	/*
	 * Cleanup any extension we already parsed.
	 */

	while (count--) {
		exv--;
		wfree(exv->opaque, sizeof(extdesc_t));
		exv->opaque = NULL;
	}

	return 0;		/* Cannot be a GGEP block: leave parsing pointer intact */
}

static int
ext_urn_bad_parse(const char **retp, int len, extvec_t *exv, int exvcnt)
{
	const char *p = *retp;
	const char *lastp = p;				/* Last parsed point */
	extdesc_t *d;

	g_assert(exvcnt > 0);
	g_assert(exv->opaque == NULL);

	if (len != 3)
		return 0;
	p = is_strcaseprefix(p, "urn");
	if (!p)
		return 0;

	/*
	 * Encapsulate as one big opaque chunk.
	 */

	WALLOC(d);

	d->ext_phys_payload = lastp;
	d->ext_phys_len = d->ext_phys_paylen = p - lastp;
	d->ext_payload = d->ext_phys_payload;
	d->ext_paylen = d->ext_phys_paylen;

	exv->opaque = d;
	exv->ext_type = EXT_NONE;
	exv->ext_name = NULL;
	exv->ext_token = EXT_T_URN_BAD;

	g_assert(p - lastp == d->ext_phys_len);

	*retp = p;			/* Points to first byte after what we parsed */

	return 1;
}


/**
 * Parses a URN block (one URN only).
 */
static int
ext_huge_parse(const char **retp, int len, extvec_t *exv, int exvcnt)
{
	const char *p = *retp;
	const char *end = &p[len];
	const char *lastp = p;				/* Last parsed point */
	ext_token_t token;
	const char *payload_start = NULL;
	int data_length;
	const char *name = NULL;
	extdesc_t *d;

	g_assert(exvcnt > 0);
	g_assert(exv->opaque == NULL);

	/*
	 * Make sure we can at least read "urn:", i.e. that we have 4 chars.
	 */

	if (len < 4)
		return ext_urn_bad_parse(retp, len, exv, exvcnt);

	/*
	 * Recognize "urn:".
	 */

	p = is_strcaseprefix(p, "urn:");
	if (!p)
		return 0;

	/*
	 * Maybe it's simply a "urn:" empty specification?
	 */

	if (p == end || *p == '\0' || *p == HUGE_FS) {
		token = EXT_T_URN_EMPTY;
		payload_start = p;
		data_length = 0;
		goto found;
	}

	/*
	 * Look for the end of the name, identified by ':'.
	 */

	{
		const char *name_start, *name_end;
		size_t name_len;
		char name_buf[9];	/* Longest name we parse is "bitprint" */

		name_start = p;
		name_end = vmemchr(p, ':', end - name_start);

		/*
		 * Some broken servents don't include the trailing ':', which is a
		 * mistake.  Try to accomodate them by looking up the next HUGE
		 * or GGEP field separator.
		 */

		if G_UNLIKELY(NULL == name_end) {
			name_end = vmemchr(p, HUGE_FS, end - name_start);
			if (NULL == name_end)
				name_end = vmemchr(p, GGEP_MAGIC, end - name_start);
		}

		name_len = (name_end != NULL) ? name_end - name_start : 0;

		if G_UNLIKELY(0 == name_len) {
			return 0;			/* No sperator found, extension is weird */
		} else if (name_len >= sizeof name_buf) {
			/* We shall treat this URN extension as being unknown */
			token = EXT_T_URN_UNKNOWN;
		} else {
			char *nend;
			/* Lookup the name token to determine the URN type */
			nend = mempcpy(name_buf, name_start, name_len);
			*nend = '\0';
			token = rw_urn_screen(name_buf, &name);

			if (EXT_T_URN_UNKNOWN == token && GNET_PROPERTY(ggep_debug)) {
				g_info("unknown URN name \"%s\" in HUGE extension", name_buf);
			}
		}
		p = &name_end[1];	/* Skip the ':' following the URN name */
	}

	/*
	 * Now extract the payload (must be made of alphanum chars or '.'),
	 * until we reach a delimiter (NUL byte, GGEP header, GEM separator).
	 * NB: of those, only GGEP_MAGIC could be "alnum" under some locales.
	 */

	payload_start = p;
	for (/* NOTHING*/; p < end; p++) {
		uchar c = *p;
		if (!(is_ascii_alnum(c) || '.' == c) || c == GGEP_MAGIC) {
			break;
		}
	}
	data_length = p - payload_start;

found:
	g_assert(payload_start);

	WALLOC(d);

	d->ext_phys_payload = payload_start;
	d->ext_phys_paylen = data_length;
	d->ext_phys_len = (payload_start - lastp) + data_length;
	d->ext_payload = d->ext_phys_payload;
	d->ext_paylen = d->ext_phys_paylen;

	exv->opaque = d;
	exv->ext_type = EXT_HUGE;
	exv->ext_name = name;
	exv->ext_token = token;

	g_assert(ext_phys_headlen(d) >= 0);
	g_assert(p - lastp == d->ext_phys_len);

	if (p < end && ('\0' == *p || HUGE_FS == *p))
		p++;	/* Swallow separator */

	*retp = p;	/* Points to first byte after what we parsed */

	return 1;
}

/**
 * Parses a XML block (grabs the whole xml up to the first NUL or separator).
 */
static int
ext_xml_parse(const char **retp, int len, extvec_t *exv, int exvcnt)
{
	const char *p = *retp;
	const char *end = &p[len];
	const char *lastp = p;				/* Last parsed point */
	extdesc_t *d;

	g_assert(exvcnt > 0);
	g_assert(exv->opaque == NULL);

	for (/* NOTHING */; p != end; p++) {
		uchar c = *p;
		if (c == '\0' || c == HUGE_FS) {
			break;
		}
	}

	/*
	 * We don't analyze the XML, encapsulate as one big opaque chunk.
	 */

	WALLOC(d);

	d->ext_phys_payload = lastp;
	d->ext_phys_len = d->ext_phys_paylen = p - lastp;
	d->ext_payload = d->ext_phys_payload;
	d->ext_paylen = d->ext_phys_paylen;

	exv->opaque = d;
	exv->ext_type = EXT_XML;
	exv->ext_name = NULL;
	exv->ext_token = EXT_T_XML;

	g_assert(p - lastp == d->ext_phys_len);

	if (p != end)
		p++;			/* Swallow separator as well */

	*retp = p;			/* Points to first byte after what we parsed */

	return 1;
}

/**
 * Parses an unknown block, attempting to resynchronize on a known separator.
 * Everything up to the resync point is wrapped as an "unknown" extension.
 *
 * If `skip' is TRUE, we don't resync on the first resync point.
 */
static int
ext_unknown_parse(const char **retp, int len, extvec_t *exv,
	int exvcnt, bool skip)
{
	const char *p = *retp;
	const char *lastp = p;				/* Last parsed point */
	extdesc_t *d;
	bool separator = FALSE;

	g_assert(exvcnt > 0);
	g_assert(exv->opaque == NULL);

	/*
	 * Try to resync on a NUL byte, the HUGE_FS separator, "urn:" or what
	 * could appear to be the start of a GGEP block or XML.
	 */

	for (/* NOTHING*/; len > 0; p++, len--) {
		bool found;

		switch ((uchar) *p) {
		case '\0':
		case HUGE_FS:
			separator = TRUE;
			/* FALL THROUGH */
		case GGEP_MAGIC:
			found = TRUE;
			break;
		case 'u':
		case 'U':
			found = len >= 4 && is_strcaseprefix(p, "urn:");
			break;
		case '<':
			found = len >= 2 && is_ascii_alpha((uchar) p[1]);
			break;
		default:
			found = FALSE;
		}

		if (found) {
			if (skip) {
				skip = FALSE;
			} else {
				break;
			}
		}
	}

	/*
	 * Encapsulate as one big opaque chunk.
	 */

	WALLOC(d);

	d->ext_phys_payload = lastp;
	d->ext_phys_len = d->ext_phys_paylen = p - lastp;
	d->ext_payload = d->ext_phys_payload;
	d->ext_paylen = d->ext_phys_paylen;

	exv->opaque = d;
	exv->ext_type = EXT_UNKNOWN;
	exv->ext_name = NULL;
	exv->ext_token = EXT_T_UNKNOWN;

	g_assert(p - lastp == d->ext_phys_len);

	if (separator)
		p++;			/* Swallow HUGE separator as well */

	*retp = p;			/* Points to first byte after what we parsed */

	return 1;
}

/**
 * Parses a "no extension" block, made of NUL bytes or HUGE field separators
 * exclusively.  Obviously, this is unneeded stuff that simply accounts
 * for overhead!
 *
 * If more that one separator in a row is found, they are all wrapped as a
 * "none" extension.
 */
static int
ext_none_parse(const char **retp, int len, extvec_t *exv, int exvcnt)
{
	const char *p = *retp;
	const char *end = &p[len];
	const char *lastp = p;				/* Last parsed point */
	extdesc_t *d;

	g_assert(exvcnt > 0);
	g_assert(exv->opaque == NULL);

	for (/* NOTHING */; p != end; p++) {
		uchar c = *p;
		if (c != '\0' && c != HUGE_FS)
			break;
	}

	/*
	 * If we're still at the beginning, it means there was no separator
	 * at all, so we did not find any "null" extension.
	 */

	if (p == lastp)
		return 0;

	/*
	 * Encapsulate as one big opaque chunk.
	 */

	WALLOC(d);

	d->ext_phys_payload = lastp;
	d->ext_phys_len = d->ext_phys_paylen = p - lastp;
	d->ext_payload = d->ext_phys_payload;
	d->ext_paylen = d->ext_phys_paylen;

	exv->opaque = d;
	exv->ext_type = EXT_NONE;
	exv->ext_name = NULL;
	exv->ext_token = EXT_T_OVERHEAD;

	g_assert(p - lastp == d->ext_phys_len);

	*retp = p;			/* Points to first byte after what we parsed */

	return 1;
}

/**
 * Merge two consecutive extensions `exv' and `next' into one big happy
 * extension, in `exv'.   The resulting extension type is that of `exv'.
 */
static void
ext_merge_adjacent(extvec_t *exv, extvec_t *next)
{
	const char *end;
	const char *nend;
	const char *nbase;
	uint16 added;
	extdesc_t *d = exv->opaque;
	extdesc_t *nd = next->opaque;

	g_assert(exv->opaque != NULL);
	g_assert(next->opaque != NULL);

	end = d->ext_phys_payload + d->ext_phys_paylen;
	nbase = ext_phys_base(nd);
	nend = nd->ext_phys_payload + nd->ext_phys_paylen;

	g_assert(nbase + nd->ext_phys_len == nend);
	g_assert(nend > end);
	g_assert(nbase >= end);

	/*
	 * Merged extensions must be adjacent, but can be separated by a set
	 * of separators (or what we thought were separators but which are
	 * going to become part of the payload for the new merged extension).
	 */

	added = nend - end;			/* Includes any separator between the two */

	/*
	 * By incrementing the total length and the payload length of `exv',
	 * we catenate `next' at the tail of `exv'.
	 */

	d->ext_phys_len += added;
	d->ext_phys_paylen += added;

	if (d->ext_payload != NULL) {
		g_assert(d->ext_payload == d->ext_phys_payload);

		d->ext_paylen += added;
	}

	/*
	 * Get rid of the `next' opaque descriptor.
	 * We should not have computed any "virtual" payload at this point.
	 */

	g_assert(
		nd->ext_payload == NULL || nd->ext_payload == nd->ext_phys_payload);

	WFREE(nd);
	next->opaque = NULL;
}

/**
 * Parse buffer for extensions, filling supplied extension vector with
 * the extensions which were successfully parsed.
 *
 * @param buf		start of data to parse
 * @param len		length of data available (may stop parsing earlier)
 * @param flags		flags controlling how parsing is done
 * @param exv		extension vector to fill-in
 * @param exvcnt	length of extension vector
 * @param endptr	if non-NULL, filled	with pointer to next byte
 *
 * @return the number of filled entries.
 */
static int G_HOT
ext_parse_buffer(const char *buf, size_t len, int flags,
	extvec_t *exv, int exvcnt, char **endptr)
{
	const char *p = buf, *end = &buf[len];
	int cnt = 0;

	g_assert(buf);
	g_assert(len > 0);
	g_assert(exv);
	g_assert(exvcnt > 0);
	g_assert(exv->opaque == NULL);

	while (p < end && exvcnt > 0) {
		const char *old_p = p;
		int found = 0;

		g_assert(len > 0);

		/*
		 * From now on, all new Gnutella extensions will be done via GGEP.
		 * However, we have to be backward compatible with legacy extensions
		 * that predate GGEP (HUGE and XML) and were not properly encapsulated.
		 */

		switch ((uchar) *p) {
		case GGEP_MAGIC:
			p++;
			if (p == end)
				goto out;
			found = ext_ggep_parse(&p, len-1, exv, exvcnt);
			break;
		case 'u':
		case 'U':
			found = ext_huge_parse(&p, len, exv, exvcnt);
			break;
		case '<':
			found = ext_xml_parse(&p, len, exv, exvcnt);
			break;
		case HUGE_FS:
		case '\0':
			p++;
			if (p == end)
				goto out;
			if ((flags & EXT_F_NUL_END) && '\0' == *(p - 1))
				goto out;
			found = ext_none_parse(&p, len-1, exv, exvcnt);
			if (!found) {
				len--;
				continue;			/* Single separator, no bloat then */
			}
			break;
		default:
			found = ext_unknown_parse(&p, len, exv, exvcnt, FALSE);
			break;
		}

		/*
		 * If parsing did not advance one bit, grab as much as we can as
		 * an "unknown" extension.
		 */

		g_assert(found == 0 || p != old_p);

		if (found == 0) {
			g_assert((uchar) *old_p == GGEP_MAGIC || p == old_p);

			/*
			 * If we were initially on a GGEP magic byte, and since we did
			 * not find any valid GGEP extension, go back one byte.  We're
			 * about to skip the first synchronization point...
			 */

			if ((uchar) *old_p == GGEP_MAGIC) {
				p--;
				g_assert(p == old_p);
			}

			found = ext_unknown_parse(&p, len, exv, exvcnt, TRUE);
		} else {
			/*
			 * The possible trailing NUL at the end of the extension we
			 * just parsed was swallowed by the parser.  If we have to
			 * end parsing at the first NUL encountered, we need to exit.
			 */

			if ((flags & EXT_F_NUL_END) && '\0' == *(p - 1)) {
				cnt += found;
				goto out;
			}
		}

		g_assert(found > 0);
		g_assert(found <= exvcnt);
		g_assert(p != old_p);

		len -= p - old_p;

		/*
		 * If we found an "unknown" or "none" extension, and the previous
		 * extension was "unknown", merge them.  The result will be "unknown".
		 */

		if (
			found == 1 && cnt > 0 &&
			(exv->ext_type == EXT_UNKNOWN || exv->ext_type == EXT_NONE)
		) {
			extvec_t *prev = exv - 1;
			if (prev->ext_type == EXT_UNKNOWN) {
				ext_merge_adjacent(prev, exv);
				continue;					/* Don't move `exv' */
			}
		}

		exv += found;
		exvcnt -= found;
		cnt += found;
	}

out:
	if (endptr != NULL)
		*endptr = deconstify_pointer(p);	/* Beyond what we parsed */

	return cnt;
}

/**
 * Parse extension block of `len' bytes starting at `buf' and fill the
 * supplied extension vector `exv', whose size is `exvcnt' entries.
 *
 * @return the number of filled entries.
 */
int
ext_parse(const char *buf, int len, extvec_t *exv, int exvcnt)
{
	return ext_parse_buffer(buf, len, 0, exv, exvcnt, NULL);
}

/**
 * Parse extension block of `len' bytes starting at `buf' and fill the
 * supplied extension vector `exv', whose size is `exvcnt' entries.
 * Stop parsing at the first NUL byte.
 *
 * @return the number of filled entries, and fills `end' with the address
 * of the first byte beyond the parsed area, which may be beyond the initial
 * buffer if there was no NUL byte to stop the parsing.
 */
int
ext_parse_nul(const char *buf, int len, char **end, extvec_t *exv, int exvcnt)
{
	return ext_parse_buffer(buf, len, EXT_F_NUL_END, exv, exvcnt, end);
}

/**
 * Locate the start of the next GGEP extension block.
 *
 * @param buf		buffer to parse
 * @param len		size of buffer in bytes
 *
 * @return the start of the next GGEP extension block AFTER the leading mark,
 * or NULL if none could be found.
 */
static char *
ext_ggep_nextblock(const char *buf, int len)
{
	const char *p = buf, *end = &buf[len];
	extvec_t exv[1];

	g_assert(buf != NULL);
	g_assert(len >= 0);

	if (len <= 2)
		return NULL;	/* Cannot hold a valid GGEP block in so few bytes */

	ext_prepare(exv, N_ITEMS(exv));

	while (p < end) {
		const char *old_p = p;
		int found = 0;

		g_assert(len > 0);

		switch ((uchar) *p) {
		case GGEP_MAGIC:
			p++;
			if (p == end)
				return NULL;	/* Cannot possibly be a GGEP block */
			return deconstify_pointer(p);	/* Start of GGEP data */
		case 'u':
		case 'U':
			found = ext_huge_parse(&p, len, exv, N_ITEMS(exv));
			break;
		case '<':
			found = ext_xml_parse(&p, len, exv, N_ITEMS(exv));
			break;
		case HUGE_FS:
		case '\0':
			p++;
			if (p == end)
				return NULL;
			found = ext_none_parse(&p, len-1, exv, N_ITEMS(exv));
			if (!found) {
				len--;
				continue;			/* Single separator, no bloat then */
			}
			break;
		default:
			found = ext_unknown_parse(&p, len, exv, N_ITEMS(exv), FALSE);
			break;
		}

		/*
		 * If parsing did not advance one bit, grab as much as we can as
		 * an "unknown" extension.
		 */

		g_assert(found == 0 || p != old_p);

		if (found == 0) {
			g_assert(p == old_p);
			found = ext_unknown_parse(&p, len, exv, N_ITEMS(exv), TRUE);
		}

		g_assert(found > 0);
		g_assert(UNSIGNED(found) <= N_ITEMS(exv));
		g_assert(p != old_p);

		len -= p - old_p;

		ext_reset(exv, N_ITEMS(exv));
	}

	return NULL;	/* Did not find any GGEP start */
}

/**
 * Strip instances of a particular GGEP key from the current GGEP block, moving
 * data around to fill the gaps.
 *
 * @param buf		buffer to parse (byte following leading GGEP block mark)
 * @param len		size of buffer in bytes
 * @param key		the key to strip
 * @param endptr	where we return the first unparsed byte after the block
 * @param emptied	set to TRUE if stripping removes all keys from the block
 *
 * @return the new length of the extension arena.
 */
static int
ext_ggep_stripkey(char *buf, int len, const char *key,
	const char **endptr, bool *emptied)
{
	char *p = buf;
	const char *end = &buf[len];
	int newlen = len;
	char *prev_flags = NULL;

	g_assert(buf != NULL);
	g_assert(len > 0);
	g_assert(key != NULL);
	g_assert(clamp_strlen(key, GGEP_F_IDLEN + 1) <= GGEP_F_IDLEN);
	g_assert(emptied != NULL);

	*emptied = FALSE;

	while (p < end) {
		uchar flags;
		char id[GGEP_F_IDLEN + 1];
		uint id_len, data_length, i;
		bool length_ended = FALSE;
		char *cur_flags = p;	/* This is the start of the key/value pair */

		/*
		 * First byte is GGEP flags.
		 */

		flags = (uchar) *p++;

		if (flags & GGEP_F_MBZ)		/* A byte that Must Be Zero is set */
			goto abort;

		id_len = flags & GGEP_F_IDLEN;
		g_assert(id_len < sizeof id);

		if (id_len == 0)
			goto abort;

		if ((size_t) (end - p) < id_len) /* Not enough bytes to store the ID! */
			goto abort;

		/*
		 * Read ID, and NUL-terminate it.
		 *
		 * As a safety precaution, only allow ASCII IDs, and nothing in
		 * the control space.  It's not really in the GGEP specs, but it's
		 * safer that way, and should protect us if we parse garbage starting
		 * with 0xC3....
		 *		--RAM, 2004-11-12
		 */

		for (i = 0; i < id_len; i++) {
			int c = *p++;
			if (c == '\0' || !isascii(c) || is_ascii_cntrl(c))
				goto abort;
			id[i] = c;
		}
		id[i] = '\0';

		/*
		 * Read the payload length (maximum of 3 bytes).
		 */

		data_length = 0;
		for (i = 0; i < 3 && p < end; i++) {
			uchar b = *p++;

			/*
			 * Either GGEP_L_CONT or GGEP_L_LAST must be set, thereby
			 * ensuring that the byte cannot be NUL.
			 */

			if (((b & GGEP_L_XFLAGS) == GGEP_L_XFLAGS) || !(b & GGEP_L_XFLAGS))
				goto abort;

			data_length = (data_length << GGEP_L_VSHIFT) | (b & GGEP_L_VALUE);

			if (b & GGEP_L_LAST) {
				length_ended = TRUE;
				break;
			}
		}

		if (!length_ended)
			goto abort;

		/*
		 * Ensure we have enough bytes left for the payload.  If not, it
		 * means the length is garbage.
		 */

		if ((size_t) (end - p) < data_length)
			goto abort;

		/*
		 * OK, at this point we have validated the GGEP header.
		 */

		p += data_length;		/* Move past the value data */

		/*
		 * Strip key/value pair if the ID matches.
		 */

		if (0 == strcmp(id, key)) {
			size_t elen = p - cur_flags;	/* Amount of bytes to remove */

			/*
			 * If removing the last key of the GGEP block, propagate
			 * the "last key" bit to the previous one, if there was any,
			 *
			 * If we remove the last key of the block and we have no previous
			 * key, then we emptied the block: we signal that to the caller
			 * so that the now useless GGEP block marker must be stripped.
			 */

			if (GNET_PROPERTY(ggep_debug) > 5) {
				g_debug("GGEP stripping \"%s\" %skey (%zu bytes)",
					key, (flags & GGEP_F_LAST) ? "last " : "", elen);
			}

			if (flags & GGEP_F_LAST) {
				if (prev_flags != NULL) {
					g_assert(!(*prev_flags & GGEP_F_LAST));
					*prev_flags |= GGEP_F_LAST;
				} else {
					if (GNET_PROPERTY(ggep_debug) > 4) {
						g_debug("GGEP stripped \"%s\" was sole GGEP key", key);
					}
					*emptied = TRUE;
				}
			}

			g_assert(UNSIGNED(newlen) >= elen);

			memmove(cur_flags, p, end - p);
			newlen -= elen;
			end -= elen;
			p = cur_flags;

			g_assert(newlen >= 0);
			g_assert(p <= end);
		} else {
			prev_flags = cur_flags;
		}

		if (flags & GGEP_F_LAST)
			break;					/* Reached the last key/value */
	}

	*endptr = p;
	return newlen;

abort:
	if (GNET_PROPERTY(ggep_debug)) {
		g_carp("GGEP block is not valid");
	}

	*endptr = end;		/* Could not parse block, assume no more GGEP blocks */
	return newlen;		/* Some keys could have been stripped already */
}

/**
 * Strip instances of a particular GGEP key all the GGEP blocks, moving
 * data around to fill the gaps.
 *
 * @param buf		buffer to parse
 * @param len		size of buffer in bytes
 * @param key		the key to strip
 *
 * @return the new length of the extension arena.
 */
int
ext_ggep_strip(char *buf, int len, const char *key)
{
	char *start = buf;
	const char *end = &buf[len];
	char *p;
	unsigned blocks = 0;
	unsigned removed = 0;

	g_assert(buf != NULL);
	g_assert(len > 0);
	g_assert(key != NULL);
	g_assert(clamp_strlen(key, GGEP_F_IDLEN + 1) <= GGEP_F_IDLEN);

	while (NULL != (p = ext_ggep_nextblock(start, end - start))) {
		const char *endp;
		bool emptied;
		int newlen;
		int stripped;

		g_assert(p > start);	/* Skipped at least the leading GGEP marker */

		blocks++;
		newlen = ext_ggep_stripkey(p, end - p, key, &endp, &emptied);
		stripped = (end - p) - newlen;

		g_assert(stripped >= 0);
		g_assert(endp - p <= newlen);

		end -= stripped;
		g_assert(endp <= end);

		start = deconstify_pointer(endp);

		/*
		 * If GGEP block was completely emptied, remove the GGEP marker.
		 */

		if (emptied) {
			char *q = p - 1;			/* GGEP Magic */

			g_assert(q >= buf);
			g_assert(GGEP_MAGIC == *(uchar *) q);

			memmove(q, p, end - p);
			end--;
			start--;
			removed++;

			if (GNET_PROPERTY(ggep_debug) > 5) {
				g_debug("GGEP stripped leading magic byte");
			}

			/*
			 * If the GGEP block was the last extension block, we need to
			 * remove any previous HUGE_FS character which is now pure
			 * overhead as well.
			 */

			if (
				q != buf &&
				(start == end || HUGE_FS == *start || '\0' == *start)
			) {
				char *r = q - 1;		/* Char before GGEP magic */

				g_assert(r >= buf);

				if (HUGE_FS == *r) {
					memmove(r, q, end - q);
					end--;
					start--;

					if (GNET_PROPERTY(ggep_debug) > 5) {
						g_debug("GGEP stripped now useless HUGE separator");
					}
				}
			}
		}
	}

	g_assert(end >= buf);

	if (GNET_PROPERTY(ggep_debug) > 4) {
		int newlen = end - buf;
		g_debug("GGEP stripping of \"%s\" in %u block%s removed %d bytes "
			"(emptied %u block%s)",
			key, blocks, plural(blocks), len - newlen,
			removed, plural(removed));
	}

	return end - buf;
}

/**
 * Inflate `len' bytes starting at `buf', up to GGEP_MAXLEN bytes.
 * The payload `name' is given only in case there is an error to report.
 *
 * @return the allocated inflated buffer, and its inflated length in `retlen'
 * or NULL on error.
 */
static char *
ext_ggep_inflate(const char *buf, int len, uint16 *retlen, const char *name)
{
	char *result;					/* Inflated buffer */
	int rsize;						/* Result's buffer size */
	z_streamp inz;
	int ret;
	int inflated;					/* Amount of inflated data so far */
	bool failed = FALSE;

	g_assert(buf);
	g_assert(len > 0);
	g_assert(retlen);

	/*
	 * Allocate decompressor.
	 */

	WALLOC(inz);

	inz->zalloc = zlib_alloc_func;
	inz->zfree = zlib_free_func;
	inz->opaque = NULL;

	ret = inflateInit(inz);

	if (ret != Z_OK) {
		WFREE(inz);
		g_warning("unable to setup decompressor for GGEP payload \"%s\": %s",
			name, zlib_strerror(ret));
		return NULL;
	}

	rsize = len * 2;				/* Assume a 50% compression ratio */
	rsize = MIN(rsize, GGEP_MAXLEN);
	result = halloc(rsize);

	/*
	 * Prepare call to inflate().
	 */

	inz->next_in = (void *) buf;
	inz->avail_in = len;

	inflated = 0;

	for (;;) {
		/*
		 * Resize output buffer if needed.
		 * Never grow the result buffer to more than GGEP_MAXLEN bytes.
		 */

		if (rsize == inflated) {
			if (rsize >= GGEP_MAXLEN) {		/* Reached maximum size! */
				if (GNET_PROPERTY(ggep_debug)) {
					g_warning("GGEP payload \"%s\" (%d byte%s) would "
						"decompress to more than %d bytes",
						name, len, plural(len), GGEP_MAXLEN);
				}
				failed = TRUE;
				break;
			}

			rsize += MAX(len, GGEP_GROW);
			rsize = MIN(rsize, GGEP_MAXLEN);

			result = hrealloc(result, rsize);
		}

		g_assert(rsize > inflated);

		inz->next_out = (uchar *) result + inflated;
		inz->avail_out = rsize - inflated;

		/*
		 * Decompress data.
		 */

		ret = inflate(inz, Z_SYNC_FLUSH);
		inflated = rsize - inz->avail_out;

		g_assert(inflated <= rsize);

		if (ret == Z_STREAM_END) {			/* All done! */
			if (GNET_PROPERTY(ggep_debug) > 3) {
				g_info("GGEP payload \"%s\" inflated %d byte%s into %d",
					name, len, plural(len), inflated);
			}
			break;
		}

		if (ret == Z_BUF_ERROR) {			/* Needs more output space */
			if (rsize == inflated)
				continue;

			if (GNET_PROPERTY(ggep_debug)) {
				g_warning("GGEP payload \"%s\" does not decompress properly "
					"(consumed %d/%d byte%s inflated into %d)",
					name, len - inz->avail_in, len, plural(len), inflated);
			}
			failed = TRUE;
			break;
		}

		if (ret != Z_OK) {
			if (GNET_PROPERTY(ggep_debug)) {
				g_warning("decompression of GGEP payload \"%s\""
					" (%d byte%s) failed: %s [consumed %d, inflated into %d]",
					name, len, plural(len), zlib_strerror(ret),
					len - inz->avail_in, inflated);
			}
			failed = TRUE;
			break;
		}
	}

	/*
	 * Dispose of decompressor.
	 */

	ret = inflateEnd(inz);
	if (ret != Z_OK) {
		if (GNET_PROPERTY(ggep_debug)) {
			g_warning("while freeing decompressor for GGEP payload \"%s\": %s",
				name, zlib_strerror(ret));
		}
	}

	WFREE(inz);

	/*
	 * return NULL on error.
	 */

	if (failed) {
		HFREE_NULL(result);
		return NULL;
	}

	*retlen = inflated;

	g_assert(*retlen == inflated);	/* Make sure it was not truncated */

	if (GNET_PROPERTY(ggep_debug) > 5) {
		g_debug("decompressed GGEP payload \"%s\" (%d byte%s) into %d",
			name, len, plural(len), inflated);
	}

	return result;					/* OK, successfully inflated */
}

/**
 * Decode the GGEP payload pointed at by `e', allocating a new buffer capable
 * of holding the decoded data.
 *
 * This is performed only when the GGEP payload is either COBS-encoded or
 * deflated.
 */
static void
ext_ggep_decode(const extvec_t *e)
{
	const char *pbase;				/* Current payload base */
	size_t plen;					/* Curernt payload length */
	char *uncobs = NULL;			/* COBS-decoded buffer */
	size_t uncobs_len = 0;			/* Length of walloc()'ed buffer */
	size_t result;					/* Decoded length */
	extdesc_t *d;

	g_assert(e);
	g_assert(e->ext_type == EXT_GGEP);
	g_assert(e->opaque != NULL);

	d = e->opaque;

	g_assert(d->ext_ggep_cobs || d->ext_ggep_deflate);
	g_assert(d->ext_payload == NULL);

	pbase = d->ext_phys_payload;
	plen = d->ext_phys_paylen;

	if (plen == 0)
		goto out;

	/*
	 * COBS decoding must be performed before inflation, if any.
	 */

	if (d->ext_ggep_cobs) {
		uncobs = walloc(plen);		/* At worse slightly oversized */
		uncobs_len = plen;

		if (!cobs_decode_into(pbase, plen, uncobs, plen, &result)) {
			if (GNET_PROPERTY(ggep_debug))
				g_warning("unable to decode COBS buffer for GGEP \"%s\"",
					d->ext_ggep_id);
			goto out;
		}

		if (!d->ext_ggep_deflate) {
			g_assert(result <= plen);

			d->ext_payload = uncobs;
			d->ext_paylen = result;
			d->ext_rpaylen = plen;		/* Signals it was walloc()'ed */

			return;
		} else {
			g_assert(result <= plen);

			/*
			 * Replace current payload base/length with the COBS buffer.
			 */

			pbase = uncobs;
			plen = result;
		}

		if (plen == 0)		/* 0 bytes cannot be a valid deflated payload */
			goto out;

		/* FALL THROUGH */
	}

	/*
	 * Payload is deflated, inflate it.
	 */

	g_assert(d->ext_ggep_deflate);

	d->ext_rpaylen = 0;			/* Signals it was halloc()'ed */
	d->ext_payload =
		ext_ggep_inflate(pbase, plen, &d->ext_paylen, d->ext_ggep_id);

	/* FALL THROUGH */
out:
	if (uncobs != NULL)
		wfree(uncobs, uncobs_len);

	/*
	 * If something went wrong, setup a zero-length payload so that we
	 * don't go through this whole decoding again.
	 */

	if (d->ext_payload == NULL) {
		if (GNET_PROPERTY(ggep_debug)) {
			g_warning("unable to get GGEP \"%s\" %d-byte payload (%s)",
				d->ext_ggep_id, d->ext_phys_paylen,
				(d->ext_ggep_deflate && d->ext_ggep_cobs) ? "COBS + deflated" :
				d->ext_ggep_cobs ? "COBS" : "deflated");
		}
		d->ext_paylen = 0;
		d->ext_payload = d->ext_phys_payload;
	}
}

/**
 * @returns a pointer to the extension's payload.
 */
const void *
ext_payload(const extvec_t *e)
{
	extdesc_t *d = e->opaque;

	g_assert(e->opaque != NULL);

	if (NULL == d->ext_payload) {
		/*
		 * GGEP payload is COBS-ed and/or deflated.
		 */
		ext_ggep_decode(e);
	}
	return d->ext_payload;
}

/**
 * @returns the extension's payload length (after possible decompression).
 */
uint16
ext_paylen(const extvec_t *e)
{
	extdesc_t *d = e->opaque;

	g_assert(e->opaque != NULL);

	if (NULL == d->ext_payload) {
		/*
		 * GGEP payload is COBS-ed and/or deflated.
		 */
		ext_ggep_decode(e);
	}
	return d->ext_paylen;
}

/**
 * @returns the extension's payload physical length (as transmitted).
 */
static uint16
ext_phys_paylen(const extvec_t *e)
{
	extdesc_t *d = e->opaque;

	g_assert(e->opaque != NULL);

	return d->ext_phys_paylen;
}

/**
 * @returns a pointer to the extension's header.
 *
 * @warning the actual "virtual" payload may not be contiguous to the end
 * of the header: don't read past the ext_headlen() first bytes of the
 * header.
 */
const char *
ext_base(const extvec_t *e)
{
	extdesc_t *d = e->opaque;

	g_assert(e->opaque != NULL);

	return ext_phys_base(d);
}

/**
 * @returns the length of the extensions's header.
 */
uint16
ext_headlen(const extvec_t *e)
{
	extdesc_t *d = e->opaque;

	g_assert(e->opaque != NULL);

	return ext_phys_headlen(d);
}

/**
 * @returns the total length of the extension (payload + extension header).
 */
uint16
ext_len(const extvec_t *e)
{
	extdesc_t *d = e->opaque;
	int headlen;

	g_assert(e->opaque != NULL);

	headlen = ext_phys_headlen(d);

	if (d->ext_payload != NULL)
		return headlen + d->ext_paylen;

	return headlen + ext_paylen(e);		/* Will decompress / COBS decode */
}

/**
 * @return string representation for the URN token, the empty string
 * if unknown.  Note that there is no trailing ':' in the string.
 */
const char *
ext_huge_urn_name(const extvec_t *e)
{
	switch (e->ext_token) {
	case EXT_T_URN_BITPRINT:	return "urn:bitprint";
	case EXT_T_URN_BTIH:		return "urn:btih";
	case EXT_T_URN_SHA1:		return "urn:sha1";
	case EXT_T_URN_TTH:			return "urn:ttroot";
	case EXT_T_URN_ED2KHASH:	return "urn:ed2khash";
	case EXT_T_URN_MD5:			return "urn:md5";
	case EXT_T_URN_EMPTY:		return "urn";
	case EXT_T_URN_UNKNOWN:		return "urn:*";		/* Parsed but unknown */
	default:					return "";
	}
}

/**
 * @return extension's GGEP ID, or "" if not a GGEP one.
 */
const char *
ext_ggep_id_str(const extvec_t *e)
{
	extdesc_t *d = e->opaque;

	g_assert(e->opaque != NULL);

	if (e->ext_type != EXT_GGEP)
		return "";

	return d->ext_ggep_id;
}

/**
 * @return whether GGEP extension is deflated.
 */
bool
ext_ggep_is_deflated(const extvec_t *e)
{
	extdesc_t *d = e->opaque;

	g_assert(e->opaque != NULL);

	if (e->ext_type != EXT_GGEP)
		return FALSE;

	return booleanize(d->ext_ggep_deflate);
}

/**
 * @return TRUE if extension is printable.
 */
bool
ext_is_printable(const extvec_t *e)
{
	const uchar *p = ext_payload(e);
	size_t len;

	for (len = ext_paylen(e); len > 0; len--, p++) {
		if (!isprint(*p))
			return FALSE;
	}
	return TRUE;
}

/**
 * @return TRUE if extension is ASCII.
 */
bool
ext_is_ascii(const extvec_t *e)
{
	const uchar *p = ext_payload(e);
	size_t len;

	for (len = ext_paylen(e); len > 0; len--, p++) {
		if (!isascii(*p))
			return FALSE;
	}
	return TRUE;
}

/**
 * @return TRUE if extension is ASCII and contains at least a character.
 */
bool
ext_has_ascii_word(const extvec_t *e)
{
	const uchar *p = ext_payload(e);
	size_t len;
	bool has_alnum = FALSE;

	for (len = ext_paylen(e); len > 0; len--, p++) {
		if (!isascii(*p))
			return FALSE;
		has_alnum |= is_ascii_alnum(*p);
	}
	return has_alnum;
}

/**
 * Summarize extension (type, name) into supplied string buffer.
 */
size_t
ext_to_string_buf(const extvec_t *e, char *buf, size_t len)
{
	size_t rw = 0;

	g_assert(e->ext_type < EXT_TYPE_COUNT);
	g_assert(e->opaque != NULL);
	g_assert(buf != NULL);
	g_assert(size_is_non_negative(len));

	rw = str_bprintf(buf, len, "%s ", extype[e->ext_type]);

	switch (e->ext_type) {
	case EXT_UNKNOWN:
	case EXT_XML:
	case EXT_NONE:
		break;
	case EXT_HUGE:
		{
			const char *what;
			switch (e->ext_token) {
			case EXT_T_URN_BITPRINT:
			case EXT_T_URN_SHA1:
			case EXT_T_URN_TTH:
			case EXT_T_URN_ED2KHASH:
			case EXT_T_URN_UNKNOWN:
			case EXT_T_URN_EMPTY:		what = ext_huge_urn_name(e); break;
			case EXT_T_URN_BAD:			what = "bad URN"; break;
			default:					what = "<unknown>"; break;
			}
			rw += str_bprintf(&buf[rw], len - rw, "%s ", what);
		}
		break;
	case EXT_GGEP:
		{
			extdesc_t *d = e->opaque;
			rw += str_bprintf(&buf[rw], len - rw, "\"%s\" ", d->ext_ggep_id);
			if (d->ext_ggep_cobs)
				rw += str_bprintf(&buf[rw], len - rw, "COBS ");
			if (d->ext_ggep_deflate)
				rw += str_bprintf(&buf[rw], len - rw, "deflated ");
		}
		break;
	case EXT_TYPE_COUNT:
		g_assert_not_reached();
	}

	rw += str_bprintf(&buf[rw], len - rw, "(%u byte%s)",
		ext_paylen(e), plural(ext_paylen(e)));

	return rw;
}

/**
 * Return small extension description in static buffer.
 */
const char *
ext_to_string(const extvec_t *e)
{
	static char buf[80];

	ext_to_string_buf(e, ARYLEN(buf));
	return buf;
}

/**
 * Dump an extension to specified stdio stream.
 */
static void
ext_dump_one(FILE *f, const extvec_t *e, const char *prefix,
	const char *postfix, bool payload)
{
	uint16 paylen, phys_paylen;

	g_assert(e->ext_type < EXT_TYPE_COUNT);
	g_assert(e->opaque != NULL);

	if (prefix)
		fputs(prefix, f);

	fputs(extype[e->ext_type], f);
	fprintf(f, " (token=%d) ", e->ext_token);

	if (e->ext_name)
		fprintf(f, "\"%s\" ", e->ext_name);

	paylen = ext_paylen(e);
	phys_paylen = ext_phys_paylen(e);

	if (paylen == phys_paylen) {
		fprintf(f, "%u byte%s", paylen, plural(paylen));
	} else {
		fprintf(f, "%u byte%s <%u byte%s>",
			paylen, plural(paylen), phys_paylen, plural(phys_paylen));
	}

	if (e->ext_type == EXT_GGEP) {
		extdesc_t *d = e->opaque;
		fprintf(f, " (ID=\"%s\", COBS: %s, deflate: %s)",
			d->ext_ggep_id,
			bool_to_string(d->ext_ggep_cobs),
			bool_to_string(d->ext_ggep_deflate));
	}

	if (postfix)
		fputs(postfix, f);

	if (payload && paylen > 0) {
		if (ext_is_printable(e)) {
			if (prefix)
				fputs(prefix, f);

			fputs("Payload: ", f);
			fwrite(ext_payload(e), paylen, 1, f);

			if (postfix)
				fputs(postfix, f);
		} else
			dump_hex(f, "Payload", ext_payload(e), paylen);
	}

	fflush(f);
}

/**
 * Dump all extensions in vector to specified stdio stream.
 *
 * The `prefix' and `postfix' strings, if non-NULL, are emitted before and
 * after the extension summary.
 *
 * If `payload' is true, the payload is dumped in hexadecimal if it contains
 * non-printable characters, as text otherwise.
 */
void
ext_dump(FILE *fd, const extvec_t *exv, int exvcnt,
	const char *prefix, const char *postfix, bool payload)
{
	int i;

	if (!log_file_printable(fd))
		return;

	for (i = 0; i < exvcnt; i++)
		ext_dump_one(fd, &exv[i], prefix, postfix, payload);
}

/**
 * Prepare the vector for parsing, by ensuring the `opaque' pointers are
 * all set to NULL.
 */
void
ext_prepare(extvec_t *exv, int exvcnt)
{
	int i;

	for (i = 0; i < exvcnt; i++)
		exv[i].opaque = NULL;
}

/**
 * Reset an extension vector by disposing of the opaque structures
 * and of any allocated "virtual" payload.
 */
void
ext_reset(extvec_t *exv, int exvcnt)
{
	int i;

	for (i = 0; i < exvcnt; i++) {
		extvec_t *e = &exv[i];
		extdesc_t *d;

		if (e->opaque == NULL)		/* No more allocated extensions */
			break;

		d = e->opaque;

		if (d->ext_payload != NULL && d->ext_payload != d->ext_phys_payload) {
			void *p = deconstify_pointer(d->ext_payload);
			if (d->ext_rpaylen == 0) {
				HFREE_NULL(p);
			} else {
				wfree(p, d->ext_rpaylen);
				p = NULL;
			}
			d->ext_payload = NULL;
		}

		WFREE(d);
		e->opaque = NULL;
	}
}

const char *
ext_ggep_name(ext_token_t id)
{
	size_t i;

	g_assert(id < EXT_T_TOKEN_COUNT);
	g_assert(id >= ggeptable[0].rw_token);

	i = id - ggeptable[0].rw_token;
	g_assert(i < N_ITEMS(ggeptable));
	g_assert(id == ggeptable[i].rw_token);

	return ggeptable[i].rw_name;
}

/***
 *** Init & Shutdown
 ***/

/**
 * Initialize the extension subsystem.
 */
void
ext_init(void)
{
	ext_names = htable_create(HASH_KEY_STRING, 0);

	rw_is_sorted("ggeptable", ggeptable, N_ITEMS(ggeptable));
	rw_is_sorted("urntable", urntable, N_ITEMS(urntable));
}

/**
 * Free resources used by the extension subsystem.
 */
void
ext_close(void)
{
	htable_foreach(ext_names, ext_names_kv_free, NULL);
	htable_free_null(&ext_names);
}

/* vi: set ts=4 sw=4 cindent: */
