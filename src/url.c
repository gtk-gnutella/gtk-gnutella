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

#include <ctype.h>

#include "common.h"
#include "url.h"
#include "override.h"		/* Must be the last header included */

RCSID("$Id$");

#define ESCAPE_CHAR		'%'
#define TRANSPARENT_CHAR(x,m) \
	((x) >= 32 && (x) < 128 && (is_transparent[(x)-32] & (m)))

/*
 * Reserved chars: ";", "/", "?", ":", "@", "=" and "&"
 * Unsafe chars  : " ", '"', "<", ">", "#", and "%"
 * Misc chars    : "{", "}", "|", "\", "^", "~", "[", "]" and "`"
 *
 * Bit 0 encodes regular transparent set (pathnames, '/' is transparent).
 * Bit 1 encodes regular transparent set minus '+' (query string).
 */
static const guint8 is_transparent[96] = {
/*  0 1 2 3 4 5 6 7 8 9 a b c d e f */	/* 0123456789abcdef -            */
    0,3,0,0,3,0,0,3,3,3,3,1,3,3,3,3,	/*  !"#$%&'()*+,-./ -  32 -> 47  */
    3,3,3,3,3,3,3,3,3,3,0,0,0,0,0,0,	/* 0123456789:;<=>? -  48 -> 63  */
    0,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,	/* @ABCDEFGHIJKLMNO -  64 -> 79  */
    3,3,3,3,3,3,3,3,3,3,3,0,0,0,0,3,	/* PQRSTUVWXYZ[\]^_ -  80 -> 95  */
    0,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,	/* `abcdefghijklmno -  96 -> 111 */
    3,3,3,3,3,3,3,3,3,3,3,0,0,0,0,0,	/* pqrstuvwxyz{|}~  - 112 -> 127 */
};

#define PATH_MASK		0x1
#define QUERY_MASK		0x2

static const char hex_alphabet[] = "0123456789ABCDEF";

/*
 * url_escape_mask
 *
 * Escape undesirable characters using %xx, where xx is an hex code.
 * `mask' tells us whether we're escaping an URL path or a query string.
 *
 * Returns argument if no escaping is necessary, or a new string otherwise.
 */
static gchar *url_escape_mask(gchar *url, guint8 mask)
{
	gchar *p;
	gchar *q;
	int need_escape = 0;
	guchar c;
	gchar *new;

	for (p = url, c = *p++; c; c = *p++)
		if (!TRANSPARENT_CHAR(c, mask))
			need_escape++;

	if (need_escape == 0)
		return url;

	new = g_malloc(p - url + (need_escape << 1));

	for (p = url, q = new, c = *p++; c; c = *p++) {
		if (TRANSPARENT_CHAR(c, mask))
			*q++ = c;
		else {
			*q++ = ESCAPE_CHAR;
			*q++ = hex_alphabet[c >> 4];
			*q++ = hex_alphabet[c & 0xf];
		}
	}
	*q = '\0';

	return new;
}

/*
 * url_escape_mask_into
 *
 * Escape undesirable characters using %xx, where xx is an hex code.
 * This is done in the `target' buffer, whose size is `len'.
 * `mask' tells us whether we're escaping an URL path or a query string.
 *
 * Returns amount of characters written into buffer (not counting trailing
 * NUL), or -1 if the buffer was too small.
 */
static gint url_escape_mask_into(
	const gchar *url, gchar *target, gint len, guint8 mask)
{
	const gchar *p = url;
	gchar *q;
	guchar c;
	gchar *end = target + len;

	for (q = target, c = *p++; c && q < end; c = *p++) {
		if (TRANSPARENT_CHAR(c, mask))
			*q++ = c;
		else if (end - q >= 3) {
			*q++ = ESCAPE_CHAR;
			*q++ = hex_alphabet[c >> 4];
			*q++ = hex_alphabet[c & 0xf];
		} else
			break;
	}

	g_assert(q <= end);

	if (q == end)
		return -1;

	*q = '\0';

	return q - target;
}

/*
 * url_escape
 *
 * Escape undesirable characters using %xx, where xx is an hex code.
 * Returns argument if no escaping is necessary, or a new string otherwise.
 */
gchar *url_escape(gchar *url)
{
	return url_escape_mask(url, PATH_MASK);
}

/*
 * url_escape_query
 *
 * Same as url_escape(), but '+' are also escaped for the query string.
 * Returns argument if no escaping is necessary, or a new string otherwise.
 */
gchar *url_escape_query(gchar *url)
{
	return url_escape_mask(url, QUERY_MASK);
}

/*
 * url_escape_into
 *
 * Escape undesirable characters using %xx, where xx is an hex code.
 * This is done in the `target' buffer, whose size is `len'.
 *
 * Returns amount of characters written into buffer (not counting trailing
 * NUL), or -1 if the buffer was too small.
 */
gint url_escape_into(const gchar *url, gchar *target, gint len)
{
	return url_escape_mask_into(url, target, len, PATH_MASK);
}

/*
 * url_escape_cntrl
 *
 * Escape control characters using %xx, where xx is an hex code.
 *
 * Returns argument if no escaping is necessary, or a new string otherwise.
 */
gchar *url_escape_cntrl(gchar *url)
{
	gchar *p;
	gchar *q;
	int need_escape = 0;
	guchar c;
	gchar *new;

	for (p = url, c = *p++; c; c = *p++)
		if (iscntrl(c) || c == ESCAPE_CHAR)
			need_escape++;

	if (need_escape == 0)
		return url;

	new = g_malloc(p - url + (need_escape << 1));

	for (p = url, q = new, c = *p++; c; c = *p++) {
		if (!iscntrl(c) && c != ESCAPE_CHAR)
			*q++ = c;
		else {
			*q++ = ESCAPE_CHAR;
			*q++ = hex_alphabet[c >> 4];
			*q++ = hex_alphabet[c & 0xf];
		}
	}
	*q = '\0';

	return new;
}

/*
 * url_unescape
 *
 * Unescape string, in-place if `inplace' is TRUE.
 *
 * Returns the argument if un-escaping is NOT necessary, a new string
 * otherwise unless in-place decoding was requested.
 */
gchar *url_unescape(gchar *url, gboolean inplace)
{
	gchar *p;
	gchar *q;
	gint need_unescape = 0;
	guint unescaped_memory = 0;
	guchar c;
	gchar *new;

	for (p = url, c = *p++; c; c = *p++)
		if (c == ESCAPE_CHAR)
			need_unescape++;

	if (need_unescape == 0)
		return url;

	/*
	 * The "+ 1" in the g_malloc() call below is for the rare cases where
	 * the string would finish on a truncated escape sequence.  In that
	 * case, we would not have enough room for the final trailing NUL.
	 */

	if (inplace)
		new = url;
	else {
		unescaped_memory = p - url - (need_unescape << 1) + 1;
		new = g_malloc(unescaped_memory);
	}
	
	for (p = url, q = new, c = *p++; c; c = *p++) {
		if (c != ESCAPE_CHAR)
			*q++ = c;
		else {
			if ((c = *p++)) {
				gint v = (hex2dec(c) << 4) & 0xf0;
				if ((c = *p++))
					v += hex2dec(c) & 0x0f;
				else
					break;		/* String ending in the middle of escape */

				g_assert(inplace || new + unescaped_memory >= q);
				*q++ = v;
			} else
				break;
		}
	}

	g_assert(inplace || new + unescaped_memory >= q);

	*q = '\0';

	g_assert(!inplace || new == url);

	return new;
}

/*
 * url_params_parse
 *
 * Parse all the parameters in the URL query string.  All parameter values are
 * stored in their URL-unescaped form, but parameter names are NOT un-escaped.
 *
 * Returns an url_params_t object that can be queried for later...
 */
url_params_t *url_params_parse(gchar *query)
{
	url_params_t *up;
	gchar *q;
	gchar *start;
	gchar *name = NULL;
	gchar *value = NULL;
	gboolean in_value = FALSE;

	up = walloc(sizeof(*up));
	up->params = g_hash_table_new(g_str_hash, g_str_equal);
	up->count = 0;

	for (q = start = query; /* empty */; q++) {
		gchar c = *q;

		if (in_value) {
			if (c == '&' || c == '\0') {		/* End of value */
				*q = '\0';
				value = url_unescape(start, FALSE);
				if (value == start)				/* No unescaping took place */
					value = g_strdup(start);
				*q = c;
				g_hash_table_insert(up->params, name, value);
				up->count++;
				in_value = FALSE;
				name = NULL;
				value = NULL;
				start = q + 1;					/* Name will start there */
			}
		} else {
			if (c == '=') {						/* End of parameter name */
				*q = '\0';
				name = g_strdup(start);
				*q = c;
				in_value = TRUE;
				start = q + 1;					/* Value will start there */
			}
		}

		if (c == '\0')
			break;
	}

	g_assert(name == NULL);
	g_assert(value == NULL);

	return up;
}

/*
 * url_params_get
 *
 * Get the value of a parameter, or NULL if the parameter is not present.
 * The value returned has already been URL-unescaped.
 */
gchar *url_params_get(url_params_t *up, gchar *name)
{
	g_assert(up != NULL);
	g_assert(up->params != NULL);

	return g_hash_table_lookup(up->params, name);
}

static void free_params_kv(gpointer key, gpointer value, gpointer udata)
{
	g_free(key);
	g_free(value);
}

/*
 * url_params_free
 *
 * Dispose of the url_params_t structure.
 */
void url_params_free(url_params_t *up)
{
	g_assert(up != NULL);

	g_hash_table_foreach(up->params, free_params_kv, NULL);
	g_hash_table_destroy(up->params);

	wfree(up, sizeof(*up));
}

static gboolean url_safe_char(gint c, url_policy_t p)
{
	static gboolean url_dbg = TRUE;

	if (p & URL_POLICY_GWC_RULES) {
		/* Reject allow anything unreasonable */
		if (!isascii(c)) {
			if (url_dbg)
				g_warning("Non-ASCII character in GWC URL; rejected");
			return FALSE;
		}

    	if (!isalnum(c)
        	&& c != '/' && c != '.' && c != '_' && c != '-' && c != '~'
      	) {
			if (url_dbg)
      			g_warning("Unsafe character in GWC URL; rejected");
      		return FALSE;
    	}
	} else {
		/* XXX: Figure out what's the correct set for this */
		if (!isascii(c) || iscntrl(c)) {
			return FALSE;
		}
	}
	return TRUE;
}

/*
 * url_strtoaddr_strict
 *
 * A strict string to IP address conversion; the other stuff from misc.[ch]
 * is not sufficient.
 *
 * Returns TRUE if ``s'' pointed to a string representation of an IPv4
 * address, otherwise FALSE.
 * If successful, ``*addr'' will be set to the IPv4 address in network
 * byte order and ``*endptr'' will point to the character after the
 * IPv4 address. ``addr'' and ``endptr'' may be NULL.
 */
static gboolean url_strtoaddr_strict(const gchar *s, guint32 *addr,
	gchar const **endptr)
{
	const gchar *p = s;
	guchar buf[sizeof *addr];
	guchar *a = addr ? (guchar *) addr : buf;
	gboolean is_valid = TRUE;
	gint i, j, v;

	g_assert(s);

	for (i = 0; i < 4; i++) {
		v = 0;
		for (j = 0; j < 3; j++) {
			if (*p < '0' || *p > '9') {
				is_valid = j > 0;
				break;
			}
			v *= 10;
			v += *p++ - '0';
		}
		if (!is_valid)
			break;
		if (i < 3) {
			if (*p != '.') {
				is_valid = FALSE;
				break; /* failure */
			}
			p++;
		}
		*a++ = (gchar) v;
	}

	if (endptr)
		*endptr = p;

	if (!is_valid) {
		if (addr)
			*addr = 0;
		return FALSE;
	}
	return TRUE;
}

/*
 * url_normalize
 *
 * NB: May modify ``url'' in all cased; pass a copy if necessary!
 *
 * Returns NULL if ``url'' isn't a valid resp. allowed URL. Otherwise,
 * it returns either a pointer to the original URL or a g_malloc()ed
 * modified copy which has to be g_free()ed.
 * The URL is validated according to the specified policy. Unnecessary
 * parts such as ":80" (for the port) and "/./" are removed: the hostname
 * is forced to lowercase; a base URI "/" is appended if missing.
 * This allows comparing different variants of the same URL to detect
 * duplicates.
 */
gchar *url_normalize(gchar *url, url_policy_t pol)
{
	gint c, dots = 0;
	gchar *endptr;
	const gchar *tld = NULL;
	guint16 port = 0;
	guint32 addr = 0;
	gchar *p, *q = url;
	const gchar *uri;
	static const char http_prefix[] = "http://";
	static gboolean url_dbg = TRUE;

	g_assert(url);

	if (0 != strncmp(q, http_prefix, sizeof http_prefix - 1)) {
		if (url_dbg)
			g_warning("URL isn't preceded by \"http://\"");
		return NULL;
	}
	q += sizeof http_prefix - 1;

	if (!isalnum((guchar) *q)) {
		if (url_dbg)
			g_warning("HTTP prefix MUST be followed by an alphanum");
		return NULL;
	}

	if (url_strtoaddr_strict(q, &addr, (const gchar **) &endptr)) {
		if (!(pol & URL_POLICY_ALLOW_IP_AS_HOST)) {
			if (url_dbg)
				g_warning("URLs without hostnames have been disabled");
			return NULL;
		}
		q = endptr;

	} else {
		/* The ``host'' part is not an IP address */  

		for (/* NOTHING */; *q != '\0'; q++) {
			gint c;

		    for (/* NOTHING */; (c = (guchar) *q) != '\0'; q++) {
        		if (isalnum(c)) {
          			*q = tolower(c);
        		} else if (c != '-') {
          			break;
        		}
      		}   

			if (c == '\0') {
				if (dots < 1 && !(pol & URL_POLICY_ALLOW_LOCAL_HOSTS)) {
					g_warning("Current URL policy forbids local hosts");
					return NULL;
				}
				break;
			} else if (c == '.') {

				if (!(isalnum((guchar) *(q - 1)) && isalnum((guchar) q[1]))) {
					if (url_dbg)
						g_warning("a dot must be preceded and followed by"
						 	"an alphanum");
					return NULL;
				}
				dots++;
				if (q[1] == '\0' || q[1] == ':' || q[1] == '/')
					break;

				tld = &q[1];
			} else if (c == '\0' || c == '/' || c == ':') {
				break;
			} else {
				if (url_dbg)
					g_warning("invalid character in ``host:port'' part: "
						"%s", q);
				return NULL;
			}
		}

		if (!tld || !(isalpha((guchar) tld[0]) && isalpha((guchar) tld[1]))) {
			if (url_dbg)
				g_warning("no or invalid top-level domain");
			return NULL;
		}

	}

	p = q;
	if (*q == ':' ) {
		gulong v;

		q++;
		errno = 0;
		v = strtoul(q, &endptr, 10);
		if (errno || v < 1 || v > 65535) {
			if (url_dbg)
				g_warning("':' MUST be followed a by port value (1-65535)");
			return NULL;
		}
		port = (guint16) v;
		p = endptr;
		if (port == /* HTTP_PORT */ 80) {
			/* We don't want the default port in a URL;
			 * this does also prevents duplicates. */
			q--;
		} else {
			q = endptr;
		}
	}

	if (*p != '/' && *p != '\0') {
		if (url_dbg)
			g_warning("host must be followed by ':', '/' or NUL");
		return NULL;
	}

	uri = q;

	/* Scan path */
	for (/* NOTHING */; (c = *(guchar *) p) != '\0'; q++, p++) {
		if (!url_safe_char(c, pol)) {
			if (url_dbg)
				g_warning("URL contains characters prohibited by policy");
			return NULL;
		}
      
		/* Handle relative paths i.e., /. and /.. */
		if (c != '/') {
				*q = c;
			continue;
		}

		/* Special handling for '/' follows */
		do {

			*q = '/';

			while (p[1] == '/')
				p++;

			if (0 == strcmp(p, "/.")) {
				p++;
				if (url_dbg)
					g_message("Ignoring trailing \"/.\" in URI");
			} else if (0 == strcmp(p, "/..")) {
				if (url_dbg)
					g_message("Trailing \"/..\" in URI; rejected");
				return NULL;
			} else if (0 == strncmp(p, "/./", sizeof "/./" - 1)) {
				p += 2;
				if (url_dbg)
					g_message("Ignoring unnecessary \"/./\" in URI");
			} else if (0 == strncmp(p, "/../", sizeof "/../" - 1)) {
				p += 3;
				if (url_dbg)
					g_message("Ascending one component in URI");
				while (*--q != '/')
					if (q <= uri) {
						if (url_dbg)
							g_message("URI ascents beyond root per \"/../\"");
						return NULL;
					}
			} else {
				break;
			}

		} while (*p == '/' && (p[1] == '/' || p[1] == '.'));

	}
	*q = '\0';

	if (pol & URL_POLICY_GWC_RULES) {
		static const struct {
			ssize_t len;
			const gchar *ext;
		} static_types[] = {
			{ 5, ".html" },
			{ 4, ".htm" },
			{ 4, ".txt" }
		};
		guint i;

		for (i = 0; i < G_N_ELEMENTS(static_types); i++)
    		if (!strcasecmp(q - static_types[i].len, static_types[i].ext)) {
				if (url_dbg)
					g_message("URL points probably to static data; rejected");
      			return NULL;
    		}
	}

	/* Add a trailing slash; if the URI is empty (to prevent dupes) */
	if (*uri == '\0') {
		ssize_t len = q - url;
 
		g_assert(len > 0); 
		p = g_malloc(len + sizeof "/");
		if (p) {
			memcpy(p, url, len);
			p[len] = '/';
			p[len + 1] = '\0';
		}
		url = p;
	}

	if (url_dbg)
		g_message("url=\"%s\"", url);

	return url;
}

/* vi: set ts=4: */
