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
 * @ingroup lib
 * @file
 *
 * URL handling of specific formats.
 *
 * @author Raphael Manfredi
 * @date 2002-2003
 */

#include "common.h"

RCSID("$Id$")

#include "ascii.h"
#include "glib-missing.h"
#include "host_addr.h"
#include "url.h"
#include "misc.h"
#include "walloc.h"
#include "override.h"		/* Must be the last header included */

#define ESCAPE_CHAR		'%'

/**
 * - Reserved chars: ";", "/", "?", ":", "@", "=" and "&"
 * - Unsafe chars  : " ", '"', "<", ">", "#", and "%"
 * - Misc chars    : "{", "}", "|", "\", "^", "~", "[", "]" and "`"
 *
 * - Bit 0 encodes regular transparent set (pathnames, '/' is transparent).
 * - Bit 1 encodes regular transparent set minus '+' (query string).
 * - Bit 2 encodes the set for fixing an incomplete escaping.
 * - Bit 3 encodes the set for use in a shell.
 */
static const guint8 is_transparent[96] = {
/*  0   1   2   3   4   5   6   7 */	/* 01234567 -            */
    0x0,0x0,0x0,0x0,0x7,0x0,0x4,0x0,	/*  !"#$%&' -	 32..39  */
	0x7,0x7,0x7,0x0,0xf,0xf,0xf,0xf,	/* ()*+,-./ -	 40..47	 */
    0xf,0xf,0xf,0xf,0xf,0xf,0xf,0xf,	/* 01234567 -	 48..55  */
	0xf,0xf,0x6,0x0,0x0,0x4,0x0,0x4,	/* 89:;<=>? -    56..63  */
    0x0,0xf,0xf,0xf,0xf,0xf,0xf,0xf,	/* @ABCDEFG -	 64..71	 */
	0xf,0xf,0xf,0xf,0xf,0xf,0xf,0xf,	/* HIJKLMNO - 	 72..79  */
    0xf,0xf,0xf,0xf,0xf,0xf,0xf,0xf,	/* PQRSTUVW -    80..87	 */
	0xf,0xf,0xf,0x4,0x0,0x4,0x0,0xf,	/* XYZ[\]^_ -	 88..95  */
    0x0,0xf,0xf,0xf,0xf,0xf,0xf,0xf,	/* `abcdefg	-	 96..103 */
	0xf,0xf,0xf,0xf,0xf,0xf,0xf,0xf,	/* hijklmno -	104..111 */
    0xf,0xf,0xf,0xf,0xf,0xf,0xf,0xf,	/* pqrstuvw -   112..119 */
	0xf,0xf,0xf,0x0,0x0,0x0,0x0,0x0,	/* xyz{|}~  -	120..127 */
};

enum escape_mask {
	PATH_MASK	= (1 << 0),
	QUERY_MASK	= (1 << 1),
	FIX_MASK	= (1 << 2),
	SHELL_MASK	= (1 << 3)
};

static inline gboolean
is_transparent_char(const gint c, const enum escape_mask m)
{
	return c >= 32 && c < 128 && (is_transparent[c - 32] & (guint8) m);
}

static const char hex_alphabet[] = "0123456789ABCDEF";

/**
 * Escape undesirable characters using %xx, where xx is an hex code.
 *
 * @param `url' no brief description.
 * @param `mask' tells us whether we're escaping an URL path or a query string.
 *
 * @return argument if no escaping is necessary, or a new string otherwise.
 */
static char *
url_escape_mask(const char *url, guint8 mask)
{
	const char *p;
	char *q;
	int need_escape = 0;
	guchar c;
	char *new;

	for (p = url, c = *p++; c; c = *p++)
		if (!is_transparent_char(c, mask))
			need_escape++;

	if (need_escape == 0)
		return deconstify_gchar(url);

	new = g_malloc(p - url + (need_escape << 1));

	for (p = url, q = new, c = *p++; c; c = *p++) {
		if (is_transparent_char(c, mask))
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

/**
 * Escape undesirable characters using %xx, where xx is an hex code.
 * This is done in the `target' buffer, whose size is `len'.
 * `mask' tells us whether we're escaping an URL path or a query string.
 *
 * @return amount of characters written into buffer (not counting trailing
 * NUL), or -1 if the buffer was too small.
 */
static gint
url_escape_mask_into(const char *url, char *target, gint len, guint8 mask)
{
	const char *p = url;
	char *q;
	guchar c;
	char *end = target + len;

	for (q = target, c = *p++; c && q < end; c = *p++) {
		if (is_transparent_char(c, mask))
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

/**
 * Escape undesirable characters using %xx, where xx is an hex code.
 *
 * @return argument if no escaping is necessary, or a new string otherwise.
 */
char *
url_escape(const char *url)
{
	return url_escape_mask(url, PATH_MASK);
}

/**
 * Same as url_escape() except for:
 *
 * '+' is also escaped for the query string.
 * ':' is not escaped.
 *
 * @return argument if no escaping is necessary, or a new string otherwise.
 */
char *
url_escape_query(const char *url)
{
	return url_escape_mask(url, QUERY_MASK);
}

/**
 * Escapes the given string for safe use in a shell or file: URL.
 * @return argument if no escaping is necessary, or a new string otherwise.
 */
char *
url_escape_shell(const char *url)
{
	return url_escape_mask(url, SHELL_MASK);
}

/**
 * Creates a file: URL from the given absolute path and escapes it properly
 * for safe use in a shell too.
 * @return A new string or NULL on failure.
 */
char *
url_from_absolute_path(const char *path)
{
	char *escaped, *url;
	
	g_return_val_if_fail(is_absolute_path(path), NULL);
	escaped = url_escape_mask(path, SHELL_MASK);
	url = g_strconcat("file://", escaped, (void *) 0);
	if (escaped != path) {
		G_FREE_NULL(escaped);
	}
	return url;
}

/**
 * Escape undesirable characters using %xx, where xx is an hex code.
 * This is done in the `target' buffer, whose size is `len'.
 *
 * @return amount of characters written into buffer (not counting trailing
 * NUL), or -1 if the buffer was too small.
 */
gint
url_escape_into(const char *url, char *target, gint len)
{
	return url_escape_mask_into(url, target, len, PATH_MASK);
}

/**
 * Don't touch '?', '&', '=', ':', '[', ']', %HH.
 */
char *
url_fix_escape(const char *url)
{
	const char *p;
	GString *gs;
	guchar c;

	gs = g_string_new(NULL);

	for (p = url; '\0' != (c = *p); p++) {
		if (
			is_transparent_char(c, FIX_MASK) ||
			('%' == c && is_ascii_xdigit(p[1]) && is_ascii_xdigit(p[2]))
		) {
			gs = g_string_append_c(gs, c);
		} else {
			char buf[3];

			buf[0] = ESCAPE_CHAR;
			buf[1] = hex_alphabet[c >> 4];
			buf[2] = hex_alphabet[c & 0xf];
			gs = g_string_append_len(gs, buf, sizeof buf);
		}
	}

	return gm_string_finalize(gs);
}

/**
 * Escape control characters using %xx, where xx is an hex code.
 *
 * @return argument if no escaping is necessary, or a new string otherwise.
 */
char *
url_escape_cntrl(const char *url)
{
	size_t need_escape = 0;
	const char *p;

	for (p = url; '\0' != *p; p++) {
		if (is_ascii_cntrl(*p) || ESCAPE_CHAR == *p)
			need_escape++;
	}

	if (need_escape > 0) {
		char *escaped, *q;
		size_t size;
		guchar c;

		size = p - url + 1 + need_escape * 2;
		escaped = g_malloc(size);
		q = escaped;

		for (p = url; '\0' != (c = *p); p++) {
			if (!is_ascii_cntrl(c) && ESCAPE_CHAR != c)
				*q++ = c;
			else {
				*q++ = ESCAPE_CHAR;
				*q++ = hex_alphabet[c >> 4];
				*q++ = hex_alphabet[c & 0xf];
			}
		}
		*q = '\0';
		return escaped;
	} else {
		return deconstify_gchar(url);
	}
}

/**
 * Unescape string, in-place if `inplace' is TRUE.
 *
 * Returns the argument if un-escaping is NOT necessary, a new string
 * otherwise unless in-place decoding was requested.
 *
 * @return NULL if the argument isn't valid encoded.
 */
char *
url_unescape(char *url, gboolean inplace)
{
	char *p;
	char *q;
	gint need_unescape = 0;
	guint unescaped_memory = 0;
	guchar c;
	char *new;

	for (p = url; (c = *p) != '\0'; c = *p++)
		if (c == ESCAPE_CHAR) {
			guchar h = *(++p);
			guchar l = *(++p);

			if (
				(h == '0' && l == '0') ||	/* Forbid %00 */
				!(is_ascii_xdigit(h) && is_ascii_xdigit(l))
			) {
				return NULL;
			}
			need_unescape++;
		}

	if (need_unescape == 0)
		return url;

	/*
	 * The "+ 1" in the g_malloc() call below is for the impossible case where
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
				gint v = hex2int_inline(c) << 4;
				if ((c = *p++))
					v += hex2int_inline(c);
				else
					g_assert_not_reached();	/* Handled in pre-scan above */

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

/**
 * Parse all the parameters in the URL query string.  All parameter values are
 * stored in their URL-unescaped form, but parameter names are NOT un-escaped.
 *
 * @return an url_params_t object that can be queried for later...
 *         or NULL if the argument isn't valid encoded.
 */
url_params_t *
url_params_parse(char *query)
{
	url_params_t *up;
	char *q;
	char *start;
	char *name = NULL;
	char *value = NULL;
	gboolean in_value = FALSE;

	up = walloc(sizeof *up);
	up->params = g_hash_table_new(g_str_hash, g_str_equal);
	up->count = 0;

	for (q = start = query; /* empty */; q++) {
		char c = *q;

		if (in_value) {
			if (c == '&' || c == '\0') {		/* End of value */
				*q = '\0';
				value = url_unescape(start, FALSE);
				if (!value) {
					G_FREE_NULL(name);
					url_params_free(up);
					return NULL;
				}
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

/**
 * Get the value of a parameter, or NULL if the parameter is not present.
 * The value returned has already been URL-unescaped.
 */
const char *
url_params_get(url_params_t *up, const char *name)
{
	g_assert(up != NULL);
	g_assert(up->params != NULL);

	return g_hash_table_lookup(up->params, name);
}

static void
free_params_kv(gpointer key, gpointer value, gpointer unused_udata)
{
	(void) unused_udata;
	g_free(key);
	g_free(value);
}

/**
 * Dispose of the url_params_t structure.
 */
void
url_params_free(url_params_t *up)
{
	g_assert(up != NULL);

	g_hash_table_foreach(up->params, free_params_kv, NULL);
	g_hash_table_destroy(up->params);

	wfree(up, sizeof *up);
}

static gboolean
url_safe_char(char c, url_policy_t p)
{
	if (!isascii(c) || is_ascii_cntrl(c))
		return FALSE;

	if (!(p & URL_POLICY_ALLOW_ANY_CHAR)) {
    	if (
			!is_ascii_lower(c) &&
			!is_ascii_digit(c) &&
			NULL == strchr("/._-~", c)
		) {
      		/* Unsafe character in GWC URL; rejected */
      		return FALSE;
    	}
	}

	return TRUE;
}

/**
 * @attention
 * NB: May modify ``url'' in all cased; pass a copy if necessary!
 *
 * @returns NULL if ``url'' isn't a valid resp. allowed URL. Otherwise,
 * it returns either a pointer to the original URL or a g_malloc()ed
 * modified copy which has to be g_free()ed.
 *
 * The URL is validated according to the specified policy. Unnecessary
 * parts such as ":80" (for the port) and "/./" are removed: the hostname
 * is forced to lowercase; a base URI "/" is appended if missing.
 * This allows comparing different variants of the same URL to detect
 * duplicates.
 */
char *
url_normalize(char *url, url_policy_t pol)
{
	static const char http_prefix[] = "http://";
	const char *p, *uri, *endptr, *tld = NULL, *warn = NULL;
	char c, *q;
	host_addr_t addr;

	g_assert(url);

	if (NULL == (q = is_strcaseprefix(url, http_prefix)))
		return NULL;

	/* Make sure the prefix is all-lowercase */
	memcpy(url, http_prefix, CONST_STRLEN(http_prefix));

	if (!is_ascii_alnum(*q)) {
		warn = "HTTP prefix MUST be followed by an alphanum";
		goto bad;
	}

	if (
		string_to_host_or_addr(q, &endptr, &addr) &&
		is_host_addr(addr) &&
		('/' == *endptr || ':' == *endptr || '\0' == *endptr)
	) {
		if (!(pol & URL_POLICY_ALLOW_IP_AS_HOST)) {
			warn = "URLs without hostnames have been disabled";
			goto bad;
		}
		q = deconstify_gchar(endptr);

	} else {
		size_t dots = 0;

		/* The ``host'' part is not an IP address */

		for (/* NOTHING */; *q != '\0'; q++) {

		    for (/* NOTHING */; '\0' != (c = *q); q++) {
        		if (is_ascii_alnum(c)) {
          			*q = ascii_tolower(c);
        		} else if ('-' != c) {
          			break;
        		}
      		}

			if ('\0' == c) {
				if (dots < 1 && !(pol & URL_POLICY_ALLOW_LOCAL_HOSTS)) {
					warn = "current URL policy forbids local hosts";
					goto bad;
				}
				break;
			} else if ('.' == c) {

				if ( !(is_ascii_alnum(*(q - 1)) && is_ascii_alnum(q[1]))) {
					warn = "a dot must be preceded and followed by an alphanum";
					goto bad;
				}
				dots++;
				if ('\0' == q[1] || ':' == q[1] || '/' == q[1])
					break;

				tld = &q[1];
			} else if ('\0' == c || '/' == c || ':' == c) {
				break;
			} else {
				return NULL;
			}
		}

		if (!tld || !(is_ascii_alpha(tld[0]) && is_ascii_alpha(tld[1]))) {
			warn = "no or invalid top-level domain";
			goto bad;
		}

	}

	p = q;
	if (':' == *q) {
		guint32 port;
		gint error;

		q++; /* Skip ':' */

		/* Reject port numbers with leading zeros */
		if (!is_ascii_digit(*q) || '0' == *q) {
			error = EINVAL;
			port = 0;
		} else {
			port = parse_uint32(q, &endptr, 10, &error);
		}

		if (error || port < 1 || port > 65535) {
			warn = "':' MUST be followed a by port value (1-65535)";
			goto bad;
		}

		if (
			!(URL_POLICY_ALLOW_ANY_PORT & pol) &&
			port < 1024 &&
			80 != port &&
			443 != port
		) {
			warn = "Ports below 1024 other than 80 and 443 are disallowed";
			goto bad;
		}

		p = endptr;
		if (port == /* HTTP_PORT */ 80) {
			/* We don't want the default port in a URL;
			 * this does also prevents duplicates. */
			q--;
		} else {
			q = deconstify_gchar(endptr);
		}
	}

	if ('/' != *p && '\0' != *p) {
		warn = "host must be followed by ':', '/' or NUL";
		goto bad;
	}

	uri = p;

	/* Scan path */
	for (/* NOTHING */; '\0' != (c = *p); p++) {
		if (!url_safe_char(c, pol)) {
			warn = "URL contains characters prohibited by policy";
			goto bad;
		}
	}

	if (q != uri) {
		size_t len;

		len = strlen(uri);
		memmove(q, uri, len);
		q[len] = '\0';
	}
	uri = q;

	if (0 != canonize_path(q, q)) {
		warn = "Could not canonize URI";
		goto bad;
	}

	if (!(URL_POLICY_ALLOW_STATIC_FILES & pol)) {
		static const struct {
			const char *ext;
			size_t len;
		} static_types[] = {
#define D(x) { (x), CONST_STRLEN(x) }
			D(".html"),
			D(".htm"),
			D(".txt"),
#undef D
		};
		guint i;

		for (i = 0; i < G_N_ELEMENTS(static_types); i++)
    		if (
				0 == ascii_strcasecmp(q - static_types[i].len,
						static_types[i].ext)
			) {
				warn = "URL points probably to static data; rejected";
      			goto bad;
    		}
	}

	/* Add a trailing slash; if the URI is empty (to prevent dupes) */
	if ('\0' == uri[0]) {
		ssize_t len = q - url;
		char *s;

		g_assert(len > 0);
		s = g_malloc(len + sizeof "/");
		memcpy(s, url, len);
		s[len] = '/';
		s[len + 1] = '\0';
		url = s;
	}

	return url;

bad:
	return NULL;
}

/* vi: set ts=4 sw=4 cindent: */
