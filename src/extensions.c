/*
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

#include <glib.h>
#include <string.h>
#include <ctype.h>
#include <stdio.h>

#include "misc.h"
#include "extensions.h"
#include "ggep.h"

#define HUGE_FS		0x1c		/* Field separator (HUGE) */
#define GGEP_MAGIC	0xc3		/* GGEP extension prefix */

static gchar *extype[] = {
	"UNKNOWN",					/* EXT_UNKNOWN */
	"XML",						/* EXT_XML */
	"HUGE",						/* EXT_HUGE */
	"GGEP",						/* EXT_GGEP */
};

/***
 *** Extension name screener.
 ***/

struct rwtable {			/* Reserved word description */
	gchar *rw_name;			/* Representation */
	gint rw_token;			/* Token value */
};

static struct rwtable urntable[] =	/* URN name table (sorted) */
{
	{ "bitprint",		EXT_T_URN_BITPRINT },
	{ "sha1",			EXT_T_URN_SHA1 },
};

static struct rwtable ggeptable[] =	/* GGEP extension table (sorted) */
{
	{ "H",				EXT_T_GGEP_H },
};

#define END(v)		(v - 1 + sizeof(v) / sizeof(v[0]))

/*
 * rw_screen
 *
 * Perform a dichotomic search for keywords in the reserved-word table.
 * The `case_sensitive' parameter governs whether lookup is done with or
 * without paying attention to case.
 *
 * Returns the keyword token value upon success, EXT_T_UNKNOWN if not found.
 * If keyword was found, its static shared string is returned in `retkw'.
 */
static gint rw_screen(
	gboolean case_sensitive,
	struct rwtable *low, struct rwtable *high, gchar *word, gchar **retkw)
{
	struct rwtable *mid;
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

/*
 * rw_ggep_screen
 *
 * Returns the GGEP token value upon success, EXT_T_UNKNOWN if not found.
 * If keyword was found, its static shared string is returned in `retkw'.
 */
static gint rw_ggep_screen(gchar *word, gchar **retkw)
{
	return rw_screen(TRUE, ggeptable, END(ggeptable), word, retkw);
}

/*
 * rw_urn_screen
 *
 * Returns the URN token value upon success, EXT_T_UNKNOWN if not found.
 * If keyword was found, its static shared string is returned in `retkw'.
 */
static gint rw_urn_screen(gchar *word, gchar **retkw)
{
	return rw_screen(FALSE, urntable, END(urntable), word, retkw);
}

/***
 *** Extension parsing.
 ***
 *** All the ext_xxx_parse routines share the same signature and behaviour:
 ***
 *** They extract one extension, as guessed by the leading byte introducing
 *** those extensions and return the amount of entries they added to the
 *** supplied extension vector (this will be typically 1, but for GGEP which
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
static gint ext_ggep_parse(
	guchar **retp, gint len, extvec_t *exv, gint exvcnt)
{
	guchar *p = *retp;
	guchar *end = p + len;
	guchar *lastp = p;				/* Last parsed point */
	gint count;

	for (count = 0; count < exvcnt && p < end; /* empty */) {
		guchar flags;
		guchar id[16];
		gint id_len;
		gint data_length = 0;
		gint i;
		guchar *ip = id;
		gboolean length_ended = FALSE;
		gchar *name;

		/*
		 * First byte is GGEP flags.
		 */

		flags = *p++;

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

		for (i = 0; i < 3 && p < end; i++) {
			guchar b = *p++;

			/*
			 * Either GGEP_L_CONT or GGEP_L_LAST must be set, thereby
			 * ensuring that the byte cannot be NUL.
			 */

			if (((b & GGEP_L_XFLAGS) == GGEP_L_XFLAGS) || !(b & GGEP_L_XFLAGS))
				goto out;

			data_length = (data_length << 6) | (b & GGEP_L_VALUE);

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
		 */

		exv->ext_token = rw_ggep_screen(id, &name);
		exv->ext_name = name;

		/*
		 * One more entry, prepare next iteration.
		 */

		exv++;
		count++;
		lastp = p + data_length;

		/*
		 * Was this the last extension?
		 */

		if (flags & GGEP_F_LAST)
			break;
	}

out:
	*retp = lastp;		/* Points to first byte after what we parsed */

	return count;
}

/*
 * ext_huge_parse
 *
 * Parses a URN block (one URN only).
 */
static gint ext_huge_parse(guchar **retp, gint len, extvec_t *exv, gint exvcnt)
{
	guchar *p = *retp;
	guchar *end = p + len;
	guchar *lastp = p;				/* Last parsed point */
	guchar *name_start;
	gint token;
	guchar *payload_start = NULL;
	gint data_length = 0;
	gchar *name = NULL;

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
	 * Now extract the payload.
	 */

	payload_start = p;

	while (p < end) {
		guchar c = *p++;
		if (c == '\0' || c == HUGE_FS) {
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

	*retp = p;			/* Points to first byte after what we parsed */

	return 1;
}

/*
 * ext_xml_parse
 *
 * Parses a XML block (grabs the whole xml up to the first NUL or separator).
 */
static gint ext_xml_parse(guchar **retp, gint len, extvec_t *exv, gint exvcnt)
{
	guchar *p = *retp;
	guchar *end = p + len;
	guchar *lastp = p;				/* Last parsed point */

	while (p < end) {
		guchar c = *p++;
		if (c == '\0' || c == HUGE_FS || c == GGEP_MAGIC) {
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

/*
 * ext_unknown_parse
 *
 * Parses an unknown block, attempting to resynchronize on a known separator.
 * Everything up to the resync point is wrapped as an "unknown" extension.
 *
 * If `skip' is TRUE, we don't resync on the first resync point.
 */
static gint ext_unknown_parse(
	guchar **retp, gint len, extvec_t *exv, gint exvcnt, gboolean skip)
{
	guchar *p = *retp;
	guchar *end = p + len;
	guchar *lastp = p;				/* Last parsed point */

	/*
	 * Try to resync on a NUL byte, the HUGE_FS separator, "urn:" or what
	 * could appear to be the start of a GGEP block or XML.
	 */

	while (p < end) {
		guchar c = *p++;
		if (
			(c == '\0' || c == HUGE_FS || c == GGEP_MAGIC) ||
			(
				(c == 'u' || c == 'U') &&
				(end - p) >= 3 &&
				0 == strncasecmp(p, "rn:", 3)
			) ||
			(c == '<' && (p < end) && isalpha(*p))
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

/*
 * ext_parse
 *
 * Parse extension block of `len' bytes starting at `buf' and fill the
 * supplied extension vector `exv', whose size is `exvcnt' entries.
 *
 * Returns the number of filled entries.
 */
gint ext_parse(guchar *buf, gint len, extvec_t *exv, gint exvcnt)
{
	guchar *p = buf;
	guchar *end = buf + len;
	gint cnt = 0;

	g_assert(buf);
	g_assert(len > 0);
	g_assert(exv);
	g_assert(exvcnt > 0);

	while (p < end && exvcnt > 0) {
		gint found = 0;
		guchar *old_p = p;

		g_assert(len > 0);

		/* 
		 * From now on, all new Gnutella extensions will be done via GGEP.
		 * However, we have to be backward compatible with historic extensions
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
			len--;
			continue;
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

		exv += found;
		exvcnt -= found;
		cnt += found;

		len -= p - old_p;
	}

out:
	return cnt;
}

/*
 * ext_is_printable
 *
 * Returns TRUE if extension is printable.
 */
gboolean ext_is_printable(extvec_t *e)
{
	guchar *p = e->ext_payload;
	gint len = e->ext_paylen;

	while (len--) {
		guchar c = *p++;
		if (!isprint(c))
			return FALSE;
	}

	return TRUE;
}

/*
 * ext_dump_one
 *
 * Dump an extension to specified stdio stream.
 */
static void ext_dump_one(FILE *fd,
	extvec_t *e, gchar *prefix, gchar *postfix, gboolean payload)
{
	g_assert(e->ext_type <= EXT_MAXTYPE);

	if (prefix)
		fputs(prefix, fd);

	fputs(extype[e->ext_type], fd);
	fputc(' ', fd);
	
	if (e->ext_name)
		fprintf(fd, "\"%s\" ", e->ext_name);

	fprintf(fd, "%d byte%s", e->ext_paylen, e->ext_paylen == 1 ? "" : "s");

	if (e->ext_type == EXT_GGEP)
		fprintf(fd, " (COBS: %s, deflate: %s)",
			e->ext_ggep_cobs ? "yes" : "no",
			e->ext_ggep_deflate ? "yes" : "no");

	if (postfix)
		fputs(postfix, fd);

	if (payload && e->ext_paylen > 0) {
		if (ext_is_printable(e)) {
			if (prefix)
				fputs(prefix, fd);

			fputs("Payload: ", fd);
			fwrite(e->ext_payload, e->ext_paylen, 1, fd);

			if (postfix)
				fputs(postfix, fd);
		} else
			dump_hex(fd, "Payload", e->ext_payload, e->ext_paylen);
	}

	fflush(fd);
}

/*
 * ext_dump
 *
 * Dump all extensions in vector to specified stdio stream.
 *
 * The `prefix' and `postfix' strings, if non-NULL, are emitted before and
 * after the extension summary.
 *
 * If `payload' is true, the payload is dumped in hexadecimal if it contains
 * non-printable characters, as text otherwise.
 */
void ext_dump(FILE *fd, extvec_t *exv, gint exvcnt,
	gchar *prefix, gchar *postfix, gboolean payload)
{
	while (exvcnt--)
		ext_dump_one(fd, exv++, prefix, postfix, payload);
}

