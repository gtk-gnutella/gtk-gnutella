/*
 * $Id$
 *
 * Copyright (c) 2002-2003, Raphael Manfredi
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

#include "common.h"

RCSID("$Id$");

#include "extensions.h"
#include "ggep.h"

#include "lib/atoms.h"
#include "lib/misc.h"
#include "lib/override.h"		/* Must be the last header included */

#define HUGE_FS		'\x1c'		/* Field separator (HUGE) */

static const gchar * const extype[] = {
	"UNKNOWN",					/* EXT_UNKNOWN */
	"XML",						/* EXT_XML */
	"HUGE",						/* EXT_HUGE */
	"GGEP",						/* EXT_GGEP */
	"NONE",						/* EXT_NONE */
};

/***
 *** Extension name screener.
 ***/

struct rwtable {			/* Reserved word description */
	const gchar *rw_name;	/* Representation */
	gint rw_token;			/* Token value */
};

static const struct rwtable urntable[] =	/* URN name table (sorted) */
{
	{ "bitprint",		EXT_T_URN_BITPRINT },
	{ "sha1",			EXT_T_URN_SHA1 },
};

static const struct rwtable ggeptable[] =	/* GGEP extension table (sorted) */
{
#define GGEP_ID(x) { #x, EXT_T_GGEP_ ## x }
   	
	{ "<", EXT_T_GGEP_LIME_XML },
	GGEP_ID(ALT),
	GGEP_ID(DU),
	GGEP_ID(GTKGV1),
	GGEP_ID(H),
	GGEP_ID(HNAME),
	GGEP_ID(IPP),
	GGEP_ID(LF),
	GGEP_ID(LOC),
	GGEP_ID(PHC),
	GGEP_ID(PUSH),
	GGEP_ID(SCP),
	GGEP_ID(T),
	GGEP_ID(UDPHC),
	GGEP_ID(UP),
	GGEP_ID(VC),
	GGEP_ID(u),
	
#undef GGEP_ID
};

#define END(v)		(v - 1 + G_N_ELEMENTS(v))

/**
 * Perform a dichotomic search for keywords in the reserved-word table.
 * The `case_sensitive' parameter governs whether lookup is done with or
 * without paying attention to case.
 *
 * @return the keyword token value upon success, EXT_T_UNKNOWN if not found.
 * If keyword was found, its static shared string is returned in `retkw'.
 */
static gint
rw_screen(gboolean case_sensitive,
	const struct rwtable *low, const struct rwtable *high,
	const gchar *word, const gchar **retkw)
{
	const struct rwtable *mid;
	gint c;

	g_assert(retkw);

	while (low <= high) {
		mid = low + (high-low)/2;
		c = case_sensitive ?
			strcmp(mid->rw_name, word) : strcasecmp(mid->rw_name, word);
		if (c == 0) {
			*retkw = mid->rw_name;
			return mid->rw_token;
		} else if (c < 0)
			low = mid + 1;
		else
			high = mid - 1;
	}

	*retkw = NULL;

	return EXT_T_UNKNOWN;
}

/**
 * @return the GGEP token value upon success, EXT_T_UNKNOWN if not found.
 * If keyword was found, its static shared string is returned in `retkw'.
 */
static gint
rw_ggep_screen(gchar *word, const gchar **retkw)
{
	return rw_screen(TRUE, ggeptable, END(ggeptable), word, retkw);
}

/**
 * @return the URN token value upon success, EXT_T_UNKNOWN if not found.
 * If keyword was found, its static shared string is returned in `retkw'.
 */
static gint
rw_urn_screen(gchar *word, const gchar **retkw)
{
	return rw_screen(FALSE, urntable, END(urntable), word, retkw);
}

/***
 *** Extension name atoms.
 ***/

static GHashTable *ext_names = NULL;

/**
 * Transform the name into a printable form, and return an atom string
 * of that printable form.
 */
static gchar *
ext_name_atom(const gchar *name)
{
	gchar *key;
	gchar *atom;

	/*
	 * Look whether we already known about this name.
	 */

	atom = g_hash_table_lookup(ext_names, name);

	if (atom != NULL)
		return atom;

	/*
	 * The key is always the raw name we're given.
	 *
	 * The value is always a printable form of the name, where non-printable
	 * chars are shown as hexadecimal escapes: \xhh.  However, if there is
	 * no escaping, then the name is also the key (same object).
	 */

	key = g_strdup(name);
	atom = hex_escape(key, TRUE); /* strict escaping */

	g_hash_table_insert(ext_names, key, atom);

	return atom;
}

/**
 * Callback for freeing entries in the `ext_names' hash table.
 */
static gboolean
ext_names_kv_free(gpointer key, gpointer value, gpointer unused_udata)
{
	(void) unused_udata;

	if (0 != strcmp((gchar *) key, (gchar *) value))
		G_FREE_NULL(value);

	G_FREE_NULL(key);

	return TRUE;
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
 ** `len' bytes to parse.  There are `exvcnt' slots available in the extension
 *** vector, starting at `exv'.
 ***
 *** On exit, `p' is updated to the first byte following the last successfully
 *** parsed byte.  If the returned value is 0, then `p' is not updated.
 ***/

/*
 * ext_ggep_parse
 *
 * Parses a GGEP block (can hold several extensions).
 */
static gint
ext_ggep_parse(gchar **retp, gint len, extvec_t *exv, gint exvcnt)
{
	gchar *p = *retp;
	gchar *end = p + len;
	gchar *lastp = p;				/* Last parsed point */
	gint count;

	for (count = 0; count < exvcnt && p < end; /* empty */) {
		guchar flags;
		gchar id[16];
		gint id_len;
		gint data_length;
		gint i;
		gchar *ip = id;
		gboolean length_ended = FALSE;
		const gchar *name;

		/*
		 * First byte is GGEP flags.
		 */

		flags = (guchar) *p++;

		if (flags & GGEP_F_MBZ)		/* A byte that Must Be Zero is set */
			goto out;

		id_len = flags & GGEP_F_IDLEN;

		if (id_len == 0)
			goto out;

		if (end - p < id_len)		/* Not enough bytes to store the ID! */
			goto out;

		/*
		 * Read ID, and NUL-terminate it.
		 */

		for (i = 0; i < id_len; i++) {
			guchar c = *p++;
			if (c == '\0')
				goto out;
			*ip++ = c;
		}

		*ip++ = '\0';

		/*
		 * Read the payload length (maximum of 3 bytes).
		 */

		data_length = 0;
		for (i = 0; i < 3 && p < end; i++) {
			guchar b = *p++;

			/*
			 * Either GGEP_L_CONT or GGEP_L_LAST must be set, thereby
			 * ensuring that the byte cannot be NUL.
			 */

			if (((b & GGEP_L_XFLAGS) == GGEP_L_XFLAGS) || !(b & GGEP_L_XFLAGS))
				goto out;

			data_length = (data_length << GGEP_L_VSHIFT) | (b & GGEP_L_VALUE);

			if (b & GGEP_L_LAST) {
				length_ended = TRUE;
				break;
			}
		}

		if (!length_ended)
			goto out;

		/* 
		 * Ensure we have enough bytes left for the payload.  If not, it
		 * means the length is garbage.
		 */

		if (end - p < data_length)		/* Not enough bytes for the payload */
			goto out;

		/*
		 * OK, at this point we have validated the GGEP header.
		 */

		exv->ext_payload = p;
		exv->ext_paylen = data_length;
		exv->ext_len = (p - lastp) + data_length;
		exv->ext_type = EXT_GGEP;
		exv->ext_ggep_cobs = flags & GGEP_F_COBS;
		exv->ext_ggep_deflate = flags & GGEP_F_DEFLATE;

		g_assert(ext_headlen(exv) >= 0);

		/*
		 * Look whether we know about this extension.
		 *
		 * If we do, the name is the ID as well.  Otherwise, for tracing
		 * and debugging purposes, save the name away, once.
		 */

		exv->ext_token = rw_ggep_screen(id, &name);
		exv->ext_name = name;

		if (name != NULL)
			exv->ext_ggep_id = name;
		else
			exv->ext_ggep_id = ext_name_atom(id);

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

out:
	*retp = lastp;	/* Points to first byte after what we parsed */

	return count;
}

/**
 * Parses a URN block (one URN only).
 */
static gint
ext_huge_parse(gchar **retp, gint len, extvec_t *exv, gint exvcnt)
{
	gchar *p = *retp;
	gchar *end = p + len;
	gchar *lastp = p;				/* Last parsed point */
	gchar *name_start;
	gint token;
	gchar *payload_start = NULL;
	gint data_length = 0;
	const gchar *name = NULL;

	g_assert(exvcnt > 0);

	/*
	 * Make sure we can at least read "urn:", i.e. that we have 4 chars.
	 */

	if (len < 4)
		return 0;

	/*
	 * Recognize "urn:".
	 */

	if (0 != strncasecmp(p, "urn:", 4))
		return 0;

	p += 4;

	/*
	 * Maybe it's simply a "urn:" empty specification?
	 */

	if (p == end || *p == '\0' || *p == HUGE_FS) {
		token = EXT_T_URN_EMPTY;
		payload_start = p;
		g_assert(data_length == 0);
		goto found;
	}

	/*
	 * Look for the end of the name, identified by ':'.
	 */

	name_start = p;

	while (p < end) {
		if (*p == ':')
			break;
		p++;
	}

	if (p == end || p == name_start)	/* Not found, or empty name */
		return 0;

	g_assert(*p == ':');

	/*
	 * Lookup the token.
	 */

	*p = '\0';
	token = rw_urn_screen(name_start, &name);
	*p++ = ':';

	/*
	 * Now extract the payload (must be made of alphanum chars),
	 * until we reach a delimiter (NUL byte, GGEP header, GEM separator).
	 * NB: of those, only GGEP_MAGIC could be "alnum" under some locales.
	 */

	payload_start = p;

	while (p < end) {
		guchar c = *p++;
		if (!isalnum(c) || c == (guchar) GGEP_MAGIC) {
			p--;
			break;
		}
		data_length++;
	}

	g_assert(data_length == p - payload_start);

found:
	g_assert(payload_start);

	exv->ext_payload = payload_start;
	exv->ext_paylen = data_length;
	exv->ext_len = (payload_start - lastp) + data_length;
	exv->ext_type = EXT_HUGE;
	exv->ext_name = name;
	exv->ext_token = token;

	g_assert(ext_headlen(exv) >= 0);
	g_assert(p - lastp == exv->ext_len);

	*retp = p;	/* Points to first byte after what we parsed */

	return 1;
}

/**
 * Parses a XML block (grabs the whole xml up to the first NUL or separator).
 */
static gint
ext_xml_parse(gchar **retp, gint len, extvec_t *exv, gint exvcnt)
{
	gchar *p = *retp;
	gchar *end = p + len;
	gchar *lastp = p;				/* Last parsed point */

	g_assert(exvcnt > 0);

	while (p < end) {
		guchar c = *p++;
		if (c == '\0' || c == (guchar) HUGE_FS) {
			p--;
			break;
		}
	}

	/*
	 * We don't analyze the XML, encapsulate as one big opaque chunk.
	 */

	exv->ext_payload = lastp;
	exv->ext_len = exv->ext_paylen = p - lastp;
	exv->ext_type = EXT_XML;
	exv->ext_name = NULL;
	exv->ext_token = EXT_T_XML;

	g_assert(p - lastp == exv->ext_len);

	*retp = p;			/* Points to first byte after what we parsed */

	return 1;
}

/**
 * Parses an unknown block, attempting to resynchronize on a known separator.
 * Everything up to the resync point is wrapped as an "unknown" extension.
 *
 * If `skip' is TRUE, we don't resync on the first resync point.
 */
static gint
ext_unknown_parse(gchar **retp, gint len, extvec_t *exv,
	gint exvcnt, gboolean skip)
{
	gchar *p = *retp;
	gchar *end = p + len;
	gchar *lastp = p;				/* Last parsed point */

	g_assert(exvcnt > 0);

	/*
	 * Try to resync on a NUL byte, the HUGE_FS separator, "urn:" or what
	 * could appear to be the start of a GGEP block or XML.
	 */

	while (p < end) {
		guchar c = *p++;
		if (
			(c == '\0' || c == (guchar) HUGE_FS || c == (guchar) GGEP_MAGIC) ||
			(
				(c == 'u' || c == 'U') &&
				(end - p) >= 3 &&
				0 == strncasecmp(p, "rn:", 3)
			) ||
			(c == '<' && (p < end) && isalpha((guchar) *p))
		) {
			if (skip) {
				skip = FALSE;
				continue;
			}
			p--;
			break;
		}
	}

	/*
	 * Encapsulate as one big opaque chunk.
	 */

	exv->ext_payload = lastp;
	exv->ext_len = exv->ext_paylen = p - lastp;
	exv->ext_type = EXT_UNKNOWN;
	exv->ext_name = NULL;
	exv->ext_token = EXT_T_UNKNOWN;

	g_assert(p - lastp == exv->ext_len);

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
static gint
ext_none_parse(gchar **retp, gint len, extvec_t *exv, gint exvcnt)
{
	gchar *p = *retp;
	gchar *end = p + len;
	gchar *lastp = p;				/* Last parsed point */

	g_assert(exvcnt > 0);

	while (p < end) {
		guchar c = *p++;
		if (c == '\0' || c == (guchar) HUGE_FS)
			continue;
		p--;						/* Point back to the non-NULL char */
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

	exv->ext_payload = lastp;
	exv->ext_len = exv->ext_paylen = p - lastp;
	exv->ext_type = EXT_NONE;
	exv->ext_name = NULL;
	exv->ext_token = EXT_T_OVERHEAD;

	g_assert(p - lastp == exv->ext_len);

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
	gchar *end;
	gchar *nend;
	gchar *nbase;
	guint16 added;

	end = exv->ext_payload + exv->ext_paylen;
	nbase = ext_base(next);
	nend = next->ext_payload + next->ext_paylen;

	g_assert(nbase + next->ext_len == nend);
	g_assert(nend > end);

	/*
	 * Extensions are adjacent, but can be separated by a single NUL or other
	 * one byte separator.
	 */

	g_assert(nbase == end || nbase == (end + 1));

	added = nend - end;			/* Includes any separator between the two */

	/*
	 * By incrementing the total length and the payload length of `exv',
	 * we catenate `next' at the tail of `exv'.
	 */

	exv->ext_len += added;
	exv->ext_paylen += added;
}

/**
 * Parse extension block of `len' bytes starting at `buf' and fill the
 * supplied extension vector `exv', whose size is `exvcnt' entries.
 *
 * @return the number of filled entries.
 */
gint
ext_parse(gchar *buf, gint len, extvec_t *exv, gint exvcnt)
{
	gchar *p = buf;
	gchar *end = buf + len;
	gint cnt = 0;

	g_assert(buf);
	g_assert(len > 0);
	g_assert(exv);
	g_assert(exvcnt > 0);

	while (p < end && exvcnt > 0) {
		gint found = 0;
		gchar *old_p = p;

		g_assert(len > 0);

		/* 
		 * From now on, all new Gnutella extensions will be done via GGEP.
		 * However, we have to be backward compatible with legacy extensions
		 * that predate GGEP (HUGE and XML) and were not properly encapsulated.
		 */

		switch (*p) {
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
			g_assert(*old_p == GGEP_MAGIC || p == old_p);

			/*
			 * If we were initially on a GGEP magic byte, and since we did
			 * not find any valid GGEP extension, go back one byte.  We're
			 * about to skip the first synchronization point...
			 */

			if (*old_p == GGEP_MAGIC) {
				p--;
				g_assert(p == old_p);
			}

			found = ext_unknown_parse(&p, len, exv, exvcnt, TRUE);
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
	return cnt;
}

/**
 * @return TRUE if extension is printable.
 */
gboolean
ext_is_printable(const extvec_t *e)
{
	const gchar *p = e->ext_payload;
	gint len = e->ext_paylen;

	g_assert(len >= 0);
	while (len--) {
		guchar c = *p++;
		if (!isprint(c))
			return FALSE;
	}

	return TRUE;
}

/**
 * @return TRUE if extension is ASCII.
 */
gboolean
ext_is_ascii(const extvec_t *e)
{
	const gchar *p = e->ext_payload;
	gint len = e->ext_paylen;

	g_assert(len >= 0);
	while (len--) {
		guchar c = *p++;
		if (!isascii(c))
			return FALSE;
	}

	return TRUE;
}

/**
 * @return TRUE if extension is ASCII and contains at least a character.
 */
gboolean
ext_has_ascii_word(const extvec_t *e)
{
	const gchar *p = e->ext_payload;
	gint len = e->ext_paylen;
	gboolean has_alnum = FALSE;

	g_assert(len >= 0);
	while (len--) {
		guchar c = *p++;
		if (!isascii(c))
			return FALSE;
		if (!has_alnum && isalnum(c))
			has_alnum = TRUE;
	}

	return has_alnum;
}

/**
 * Dump an extension to specified stdio stream.
 */
static void
ext_dump_one(FILE *f, const extvec_t *e, const gchar *prefix,
	const gchar *postfix, gboolean payload)
{
	g_assert(e->ext_type <= EXT_MAXTYPE);

	if (prefix)
		fputs(prefix, f);

	fputs(extype[e->ext_type], f);
	fprintf(f, " (token=%d) ", e->ext_token);
	
	if (e->ext_name)
		fprintf(f, "\"%s\" ", e->ext_name);

	fprintf(f, "%d byte%s", e->ext_paylen, e->ext_paylen == 1 ? "" : "s");

	if (e->ext_type == EXT_GGEP)
		fprintf(f, " (ID=\"%s\", COBS: %s, deflate: %s)",
			e->ext_ggep_id,
			e->ext_ggep_cobs ? "yes" : "no",
			e->ext_ggep_deflate ? "yes" : "no");

	if (postfix)
		fputs(postfix, f);

	if (payload && e->ext_paylen > 0) {
		if (ext_is_printable(e)) {
			if (prefix)
				fputs(prefix, f);

			fputs("Payload: ", f);
			fwrite(e->ext_payload, e->ext_paylen, 1, f);

			if (postfix)
				fputs(postfix, f);
		} else
			dump_hex(f, "Payload", e->ext_payload, e->ext_paylen);
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
ext_dump(FILE *fd, const extvec_t *exv, gint exvcnt,
	const gchar *prefix, const gchar *postfix, gboolean payload)
{
	while (exvcnt--)
		ext_dump_one(fd, exv++, prefix, postfix, payload);
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
	ext_names = g_hash_table_new(g_str_hash, g_str_equal);
}

/**
 * Free resources used by the extension subsystem.
 */
void
ext_close(void)
{
	g_hash_table_foreach_remove(ext_names, ext_names_kv_free, NULL);
	g_hash_table_destroy(ext_names);
}

/* vi: set ts=4 sw=4 cindent: */
