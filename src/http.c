/*
 * $Id$
 *
 * Copyright (c) 2002, Raphael Manfredi
 *
 * HTTP routines.
 *
 * The whole HTTP logic is not contained here.  Only generic supporting
 * routines are here.
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

#include "gnutella.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>

#include "http.h"
#include "sockets.h"
#include "bsched.h"
#include "header.h"
#include "ioheader.h"
#include "version.h"
#include "glib-missing.h"
#include "token.h"

RCSID("$Id$");

http_url_error_t http_url_errno;		/* Error from http_url_parse() */

static GSList *sl_outgoing = NULL;		/* To spot reply timeouts */

/*
 * http_send_status
 *
 * Send HTTP status on socket, with code and reason.
 *
 * If `hev' is non-null, it points to a vector of http_extra_desc_t items,
 * containing `hevcnt' entries.  Each entry describes something to be
 * inserted in the header.
 *
 * The connection is NOT closed physically.
 *
 * At the HTTP level, the connection is closed if an error is returned
 * (either 4xx or 5xx) or a redirection occurs (3xx).
 *
 * Returns TRUE if we were able to send everything, FALSE otherwise.
 */
gboolean http_send_status(
	struct gnutella_socket *s, gint code,
	http_extra_desc_t *hev, gint hevcnt,
	gchar *reason, ...)
{
	gchar header[1536];			/* 1.5 K max */
	gchar status_msg[512];
	gint rw;
	gint mrw;
	gint sent;
	gint i;
	va_list args;
	gchar *conn_close = "Connection: close\r\n";

	va_start(args, reason);
	gm_vsnprintf(status_msg, sizeof(status_msg)-1,  reason, args);
	va_end(args);

	if (code < 300)
		conn_close = "";		/* Keep HTTP connection */

	rw = gm_snprintf(header, sizeof(header),
		"HTTP/1.1 %d %s\r\n"
		"Server: %s\r\n"
		"%s"			// Connection
		"X-Token: %s\r\n"
		"X-Live-Since: %s\r\n",
		code, status_msg, version_string, conn_close,
		tok_version(), start_rfc822_date);

	mrw = rw;		/* Minimal header length */

	/*
	 * Append extra information to the minimal header created above.
	 */

	for (i = 0; i < hevcnt && rw < sizeof(header); i++) {
		http_extra_desc_t *he = &hev[i];
		http_extra_type_t type = he->he_type;

		switch (type) {
		case HTTP_EXTRA_LINE:
			rw += gm_snprintf(&header[rw], sizeof(header) - rw,
				"%s", he->he_msg);
			break;
		case HTTP_EXTRA_CALLBACK:
			{
				/* The -3 is there to leave room for "\r\n" + NUL */
				gint len = sizeof(header) - rw - 3;
				
				(*he->he_cb)(&header[rw], &len, he->he_arg);

				g_assert(len + rw <= sizeof(header));

				rw += len;
			}
			break;
		}
	}

	if (rw < sizeof(header))
		rw += gm_snprintf(&header[rw], sizeof(header) - rw, "\r\n");

	if (rw >= sizeof(header) && hev) {
		g_warning("HTTP status %d (%s) too big, ignoring extra information",
			code, reason);

		rw = mrw + gm_snprintf(&header[mrw], sizeof(header) - mrw, "\r\n");
		g_assert(rw < sizeof(header));
	}

	if (-1 == (sent = bws_write(bws.out, s->file_desc, header, rw))) {
		g_warning("Unable to send back HTTP status %d (%s) to %s: %s",
			code, reason, ip_to_gchar(s->ip), g_strerror(errno));
		return FALSE;
	} else if (sent < rw) {
		g_warning("Only sent %d out of %d bytes of status %d (%s) to %s: %s",
			sent, rw, code, reason, ip_to_gchar(s->ip), g_strerror(errno));
		return FALSE;
	} else if (dbg > 2) {
		printf("----Sent HTTP Status to %s:\n%.*s----\n",
			ip_to_gchar(s->ip), rw, header);
		fflush(stdout);
	}

	return TRUE;
}

/***
 *** HTTP parsing.
 ***/

/*
 * code_message_parse
 *
 * Parse status messages formed of leading digit numbers, then an optional
 * message.  The pointer to the start of the message is returned in `msg'
 * if it is non-null.
 *
 * Returns status code, -1 on error.
 */
static gint code_message_parse(gchar *line, gchar **msg)
{
	guchar *p;
	guchar code[4];
	gint c;
	gint i;
	gint status;

	/*
	 * We expect exactly 3 status digits.
	 */

	for (i = 0, p = line; i < 3; i++, p++) {
		c = *p;
		if (!isdigit(c))
			return -1;
		code[i] = c;
	}
	code[3] = '\0';

	status = atoi(code);

	/*
	 * Make sure we have at least a space after the code, or that we
	 * reached the end of the string.
	 */

	c = *p;

	if (c == '\0') {			/* 3 digits followed by a space */
		if (msg)
			*msg = p;			/* Points to the trailing NUL */
		return status;
	}

	if (!isspace(c))			/* 3 digits NOT followed by a space */
		return -1;

	if (!msg)
		return status;			/* No need to point to start of message */

	/*
	 * Now skip any further space.
	 */

	for (c = *(++p); c; c = *(++p)) {
		if (!isspace(c))
			break;
	}

	*msg = p;					/* This is the beginning of the message */

	return status;
}

/*
 * http_status_parse
 *
 * Parse protocol status line, and return the status code, and optionally a
 * pointer within the string where the status message starts (if `msg' is
 * a non-null pointer), and the protocol major/minor (if `major' and `minor'
 * are non-null).
 *
 * If `proto' is non-null, then when there is a leading protocol string in
 * the reply, it must be equal to `proto'.
 *
 * Returns -1 if it fails to parse the status line correctly, the status code
 * otherwise.
 *
 * We recognize the following status lines:
 *
 *     ZZZ 403 message                        (major=-1, minor=-1)
 *     ZZZ/2.3 403 message                    (major=2, minor=3)
 *     403 message                            (major=-1, minor=-1)
 *
 * We don't yet handle "SMTP-like continuations":
 *
 *     403-message line #1
 *     403-message line #2
 *     403 last message line
 *
 * There is no way to return the value of "ZZZ" via this routine.
 *
 * NB: this routine is also used to parse GNUTELLA status codes, since
 * they follow the same pattern as HTTP status codes.
 */
gint http_status_parse(gchar *line,
	gchar *proto, gchar **msg, gint *major, gint *minor)
{
	gint c;
	guchar *p;

	/*
	 * Skip leading spaces.
	 */

	for (p = line, c = *p; c; c = *(++p)) {
		if (!isspace(c))
			break;
	}

	/*
	 * If first character is a digit, then we have simply:
	 *
	 *   403 message
	 *
	 * There's no known protocol information.
	 */

	if (c == '\0')
		return -1;					/* Empty line */

	if (isdigit(c)) {
		if (major)
			*major = -1;
		if (minor)
			*minor = -1;
		return code_message_parse(p, msg);
	}

	/*
	 * Check protocol.
	 */

	if (proto) {
		gint plen = strlen(proto);
		if (0 == strncmp(proto, line, plen)) {
			/*
			 * Protocol string matches, make sure it ends with a space or
			 * a "/" delimiter.
			 */

			p = &line[plen];
			c = *p;					/* Can dereference, at worst it's a NUL */
			if (c == '\0')			/* Only "protocol" name in status */
				return -1;
			if (!isspace(c) && c != '/')
				return -1;
		} else
			return -1;
	} else {
		/*
		 * Move along the string until we find a space or a "/".
		 */

		for (/* empty */; c; c = *(++p)) {
			if (c == '/' || isspace(c))
				break;
		}
	}

	if (c == '\0')
		return -1;

	/*
	 * We've got a "/", parse protocol version number, then move past
	 * to the first space.
	 */

	if (c == '/') {
		gint maj, min;
		if (major || minor) {
			if (sscanf(p+1, "%d.%d", &maj, &min)) {
				if (major)
					*major = maj;
				if (minor)
					*minor = min;
			} else
				return -1;
		}

		for (c = *(++p); c; c = *(++p)) {
			if (isspace(c))
				break;
		}

		if (c == '\0')
			return -1;
	}

	g_assert(isspace(c));

	/*
	 * Now strip leading spaces.
	 */

	for (c = *(++p); c; c = *(++p)) {
		if (!isspace(c))
			break;
	}

	if (c == '\0')
		return -1;

	if (!isdigit(c))
		return -1;

	return code_message_parse(p, msg);
}


/*
 * http_extract_version
 *
 * Extract HTTP version major/minor out of the given request, whose string
 * length is `len' bytes.
 *
 * Returns TRUE when we identified the "HTTP/x.x" trailing string, filling
 * major and minor accordingly.
 */
gboolean http_extract_version(
	gchar *request, gint len, gint *major, gint *minor)
{
	gint limit;
	gchar *p;
	gint i;

	/*
	 * The smallest request would be "GET / HTTP/1.0".
	 */

	limit = sizeof("GET / HTTP/1.0") - 1;

	if (dbg > 4)
		printf("HTTP req (%d bytes): %s\n", len, request);

	if (len < limit)
		return FALSE;

	/*
	 * Scan backwards, until we find the first space with the last trailing
	 * chars.  If we don't, it can't be an HTTP request.
	 */

	for (p = request + len - 1, i = 0; i < limit; p--, i++) {
		gint c = *p;

		if (c == ' ')		/* Not isspace(), looking for space only */
			break;
	}

	if (dbg > 4)
		printf("HTTP i = %d, limit = %d\n", i, limit);

	if (i == limit)
		return FALSE;		/* Reached our limit without finding a space */

	/*
	 * Here, `p' point to the space character.
	 */

	g_assert(*p == ' ');

	if (2 != sscanf(p+1, "HTTP/%d.%d", major, minor)) {
		if (dbg > 1)
			printf("HTTP req (%d bytes): no protocol tag: %s\n", len, request);
		return FALSE;
	}

	if (dbg > 4)
		printf("HTTP req OK (%d.%d)\n", *major, *minor);

	/*
	 * We don't check trailing chars after the HTTP/x.x indication.
	 * There should not be any, but even if there are, we'll just ignore them.
	 */

	return TRUE;			/* Parsed HTTP/x.x OK */
}

/***
 *** HTTP URL parsing.
 ***/

static gchar *parse_errstr[] = {
	"OK",									/* HTTP_URL_OK */
	"Not an http URI",						/* HTTP_URL_NOT_HTTP */
	"More than one <user>:<password>",		/* HTTP_URL_MULTIPLE_CREDENTIALS */
	"Truncated <user>:<password>",			/* HTTP_URL_BAD_CREDENTIALS */
	"Could not parse port",					/* HTTP_URL_BAD_PORT_PARSING */
	"Port value is out of range",			/* HTTP_URL_BAD_PORT_RANGE */
	"Could not resolve host into IP",		/* HTTP_URL_HOSTNAME_UNKNOWN */
};

#define MAX_PARSE_ERRNUM (sizeof(parse_errstr) / sizeof(parse_errstr[0]) - 1)

/*
 * http_url_strerror
 *
 * Return human-readable error string corresponding to error code `errnum'.
 */
gchar *http_url_strerror(http_url_error_t errnum)
{
	if (errnum < 0 || errnum > MAX_PARSE_ERRNUM)
		return "Invalid error code";

	return parse_errstr[errnum];
}

/*
 * http_url_parse
 *
 * Parse HTTP url and extract the IP/port we need to connect to.
 * Also identifies the start of the path to request on the server.
 *
 * Returns TRUE if the URL was correctly parsed, with `port', 'host'
 * and `path' filled if they are non-NULL, FALSE otherwise.
 * The variable `http_url_errno' is set accordingly.
 *
 */
gboolean http_url_parse(
	gchar *url, guint16 *port, gchar **host, gchar **path)
{
	gchar *host_start;
	gchar *port_start;
	gchar *p;
	gchar c;
	gboolean seen_upw = FALSE;
	gchar s;
	guint32 portnum;
	static gchar hostname[MAX_HOSTLEN + 1];

	g_assert(url != NULL);

	if (0 != strncasecmp(url, "http://", 7)) {
		http_url_errno = HTTP_URL_NOT_HTTP;
		return FALSE;
	}

	url += 7;

	/*
	 * The general URL syntax is (RFC-1738):
	 *
	 *	//<user>:<password>@<host>:<port>/<url-path>
	 *
	 * Any special character in <user> or <password> (i.e. '/', ':' or '@')
	 * must be URL-encoded, naturally.
	 *
	 * In the code below, we don't care about the user/password and simply
	 * skip them if they are present.
	 */

	host_start = url;		/* Assume there's no <user>:<password> */
	port_start = NULL;		/* Port not seen yet */
	p = url + 1;

	while ((c = *p++)) {
		if (c == '@') {
			if (seen_upw) {			/* There can be only ONE user/password */
				http_url_errno = HTTP_URL_MULTIPLE_CREDENTIALS;
				return FALSE;
			}
			seen_upw = TRUE;
			host_start = p;			/* Right after the '@' */
			port_start = NULL;
		} else if (c == ':')
			port_start = p;			/* Right after the ':' */
		else if (c == '/')
			break;
	}

	p--;							/* Go back to trailing "/" */
	if (*p != '/') {
		http_url_errno = HTTP_URL_BAD_CREDENTIALS;
		return FALSE;
	}

	if (path != NULL)
		*path = p;					/* Start of path, at the "/" */

	/*
	 * Validate the port.
	 */

	if (port_start == NULL)
		portnum = HTTP_PORT;
	else if (2 != sscanf(port_start, "%u%c", &portnum, &s) || s != '/') {
		http_url_errno = HTTP_URL_BAD_PORT_PARSING;
		return FALSE;
	}

	if ((guint32) (guint16) portnum != portnum) {
		http_url_errno = HTTP_URL_BAD_PORT_RANGE;
		return FALSE;
	}

	if (port != NULL)
		*port = (guint16) portnum;

	hostname[0] = '\0';

	{
		gchar *q = hostname;
		gchar *end = hostname + sizeof(hostname);

		/*
		 * Extract hostname into hostname[].
		 */

		p = host_start;
		while ((c = *p++) && q < end) {
			if (c == '/' || c == ':') {
				*q++ = '\0';
				break;
			}
			*q++ = c;
		}
		hostname[MAX_HOSTLEN] = '\0';
		if (host != NULL)
			*host = hostname;				/* Static data! */
	}

	if (dbg > 5)
		printf("URL \"%s\" -> host=%s, path=%s\n",
			url,
			(host != NULL) ? (*host ? *host : "<none>") : "<not remembered>",
			(path != NULL) ? *path : "<not remembered>");

	http_url_errno = HTTP_URL_OK;

	return TRUE;
}

/***
 *** HTTP range parsing.
 ***/

/*
 * http_range_add
 *
 * Add a new http_range_t object within the sorted list.
 * Refuse to add the range if it is overlapping existing ranges.
 *
 * The `field' and `vendor' arguments are only there to log errors, if any.
 *
 * Returns the new head of the list.
 * `ignored' is set to TRUE if range was ignored.
 */
static GSList *http_range_add(
	GSList *list, guint32 start, guint32 end,
	gchar *field, gchar *vendor, gboolean *ignored)
{
	GSList *l;
	GSList *prev;
	http_range_t *item;

	g_assert(start <= end);		/* 0-0 is a 1-byte range containing byte 0 */

	item = walloc(sizeof(*item));
	item->start = start;
	item->end = end;

	*ignored = FALSE;

	for (l = list, prev = NULL; l; prev = l, l = g_slist_next(l)) {
		http_range_t *r = (http_range_t *) l->data;

		/*
		 * The list is sorted and there should be no overlapping between
		 * the items, so as soon as we find a range that starts after "end",
		 * we know we have to insert before.
		 */

		if (r->start > end) {
			GSList *next;

			/* Ensure range is not overlapping with previous */
			if (prev != NULL) {
				http_range_t *pr = (http_range_t *) prev->data;
				if (pr->end >= start) {
					g_warning("vendor <%s> sent us overlapping range %u-%u"
						" (with previous %u-%u) in the %s header -- ignoring",
						vendor, start, end, pr->start, pr->end, field);
					goto ignored;
				}
			}

			/* Ensure range is not overlapping with next, if any */
			next = g_slist_next(l);
			if (next != NULL) {
				http_range_t *nr = (http_range_t *) next->data;
				if (nr->start <= end) {
					g_warning("vendor <%s> sent us overlapping range %u-%u"
						" (with next %u-%u) in the %s header -- ignoring",
						vendor, start, end, nr->start, nr->end, field);
					goto ignored;
				}
			}

			/* Insert after `prev' (which may be NULL) */
			return gm_slist_insert_after(list, prev, item);
		}

		if (r->end >= start) {
			g_warning("vendor <%s> sent us overlapping range %u-%u"
				" (with %u-%u) in the %s header -- ignoring",
				vendor, start, end, r->start, r->end, field);
			goto ignored;
		}
	}

	/*
	 * Insert at the tail of the list.
	 *
	 * NB: the following call works as expected is list == NULL, because
	 * then prev == NULL and we insert `item' as the first and only entry.
	 */

	return gm_slist_insert_after(list, prev, item);

ignored:
	*ignored = TRUE;
	wfree(item, sizeof(*item));		/* Item was not inserted */
	return list;					/* No change in list */
}

/*
 * http_range_parse
 *
 * Parse a Range: header in the request, returning the list of ranges
 * that are enumerated.  Invalid ranges are ignored.
 *
 * Only "bytes" ranges are supported.
 *
 * When parsing a "bytes=" style, it means it's a request, so we allow
 * negative ranges.  Otherwise, for "bytes " specifications, it's a reply
 * and we ignore negative ranges.
 *
 * `size' gives the length of the resource, to resolve negative ranges and
 * make sure we don't have ranges that extend past that size.
 *
 * The `field' and `vendor' arguments are only there to log errors, if any.
 *
 * Returns a sorted list of http_range_t objects.
 */
GSList *http_range_parse(
	gchar *field, gchar *value, guint32 size, gchar *vendor)
{
	GSList *ranges = NULL;
	guchar *str = value;
	guchar c;
	guint32 start;
	guint32 end;
	gboolean request = FALSE;		/* True if 'bytes=' is seen */
	gboolean has_start;
	gboolean has_end;
	gboolean skipping;
	gboolean minus_seen;
	gboolean ignored;
	gint count = 0;

	g_assert(size > 0);

	if (0 == strncmp(str, "bytes", 5)) {
		c = str[5];
		if (!isspace(c) && c != '=') {
			g_warning("improper %s header from <%s>: %s", field, vendor, value);
			return NULL;
		}
	} else {
		g_warning("improper %s header from <%s> (not bytes?): %s",
			field, vendor, value);
		return NULL;
	}

	str += 5;

	/*
	 * Move to the first non-space char.
	 * Meanwhile, if we see a '=', we know it's a request-type range header.
	 */

	while ((c = *str)) {
		if (c == '=') {
			if (request) {
				g_warning("improper %s header from <%s> (multiple '='): %s",
					field, vendor, value);
				return NULL;
			}
			request = TRUE;
			str++;
			continue;
		}
		if (isspace(c)) {
			str++;
			continue;
		}
		break;
	}

	start = 0;
	has_start = FALSE;
	has_end = FALSE;
	end = size - 1;
	skipping = FALSE;
	minus_seen = FALSE;

	while ((c = *str++)) {
		if (isspace(c))
			continue;

		if (c == ',') {
			if (skipping) {
				skipping = FALSE;		/* ',' is a resynch point */
				continue;
			}

			if (!minus_seen) {
				g_warning("weird %s header from <%s>, offset %d (no range?): "
					"%s", field, vendor, (gint) ((gchar *) str - value) - 1, value);
				goto reset;
			}

			if (start == HTTP_OFFSET_MAX && !has_end) {	/* Bad negative range */
				g_warning("weird %s header from <%s>, offset %d "
					"(incomplete negative range): %s",
					field, vendor, (gint) ((gchar *) str - value) - 1, value);
				goto reset;
			}

			if (start > end) {
				g_warning("weird %s header from <%s>, offset %d "
					"(swapped range?): %s", field, vendor,
					(gint) ((gchar *) str - value) - 1, value);
				goto reset;
			}

			ranges = http_range_add(ranges,
				start, end, field, vendor, &ignored);
			count++;

			if (ignored)
				g_warning("weird %s header from <%s>, offset %d "
					"(ignored range #%d): %s",
					field, vendor, (gint) ((gchar *) str - value) - 1, count,
					value);

			goto reset;
		}

		if (skipping)				/* Waiting for a ',' */
			continue;

		if (c == '-') {
			if (minus_seen) {
				g_warning("weird %s header from <%s>, offset %d "
					"(spurious '-'): %s",
					field, vendor, (gint) ((gchar *) str - value) - 1, value);
				goto resync;
			}
			minus_seen = TRUE;
			if (!has_start) {		/* Negative range */
				if (!request) {
					g_warning("weird %s header from <%s>, offset %d "
						"(negative range in reply): %s",
						field, vendor, (gint) ((gchar *) str - value) - 1,
						value);
					goto resync;
				}
				start = HTTP_OFFSET_MAX;	/* Indicates negative range */
				has_start = TRUE;
			}
			continue;
		}

		if (isdigit(c)) {
			gchar *dend;
			guint32 val = strtoul(str - 1, &dend, 10);

			g_assert((guchar *) dend != (str - 1));	/* Started with digit! */

			str = (guchar *) dend;		/* Skip number */

			if (has_end) {
				g_warning("weird %s header from <%s>, offset %d "
					"(spurious boundary %u): %s",
					field, vendor, (gint) ((gchar *) str - value) - 1, val,
					value);
				goto resync;
			}

			if (val >= size) {
				g_warning("weird %s header from <%s>, offset %d "
					"(%s boundary %u outside resource range 0-%u): %s",
					field, vendor, (gint) ((gchar *) str - value) - 1,
					has_start ? "end" : "start", val, size - 1, value);
				goto resync;
			}

			if (has_start) {
				if (!minus_seen) {
					g_warning("weird %s header from <%s>, offset %d "
						"(no '-' before boundary %u): %s",
						field, vendor, (gint) ((gchar *) str - value) - 1, val,
						value);
					goto resync;
				}
				if (start == HTTP_OFFSET_MAX) {			/* Negative range */
					start = (val > size) ? 0 : size - val;	/* Last bytes */
					end = size - 1;
				} else
					end = val;
				has_end = TRUE;
			} else {
				start = val;
				has_start = TRUE;
			}
			continue;
		}

		g_warning("weird %s header from <%s>, offset %d "
			"(unexpected char '%c'): %s",
			field, vendor, (gint) ((gchar *) str - value) - 1, c, value);

		/* FALL THROUGH */

	resync:
		skipping = TRUE;
	reset:
		start = 0;
		has_start = FALSE;
		has_end = FALSE;
		minus_seen = FALSE;
		end = size - 1;
	}

	/*
	 * Handle trailing range, if needed.
	 */

	if (minus_seen) {
		if (start == HTTP_OFFSET_MAX && !has_end) {	/* Bad negative range */
			g_warning("weird %s header from <%s>, offset %d "
				"(incomplete trailing negative range): %s",
				field, vendor, (gint) ((gchar *) str - value) - 1, value);
			goto final;
		}

		if (start > end) {
			g_warning("weird %s header from <%s>, offset %d "
				"(swapped trailing range?): %s", field, vendor,
				(gint) ((gchar *) str - value) - 1, value);
			goto final;
		}

		ranges = http_range_add(ranges, start, end, field, vendor, &ignored);
		count++;

		if (ignored)
			g_warning("weird %s header from <%s>, offset %d "
				"(ignored final range #%d): %s",
				field, vendor, (gint) ((gchar *) str - value) - 1, count,
				value);
	}

final:

	if (dbg > 4) {
		GSList *l;
		printf("Saw %d ranges in %s %s: %s\n",
			count, request ? "request" : "reply", field, value);
		if (ranges)
			printf("...retained:\n");
		for (l = ranges; l; l = g_slist_next(l)) {
			http_range_t *r = (http_range_t *) l->data;
			printf("...  %u-%u\n", r->start, r->end);
		}
	}

	if (ranges == NULL)
		g_warning("retained no ranges in %s header from <%s>: %s",
			field, vendor, value);

	return ranges;
}

/*
 * http_range_free
 *
 * Free list of http_range_t objects.
 */
void http_range_free(GSList *list)
{
	GSList *l;

	for (l = list; l; l = g_slist_next(l))
		wfree(l->data, sizeof(http_range_t));

	g_slist_free(list);
}

/*
 * http_range_size
 *
 * Returns total size of all the ranges.
 */
guint32 http_range_size(GSList *list)
{
	GSList *l;
	guint32 size = 0;

	for (l = list; l; l = g_slist_next(l)) {
		http_range_t *r = (http_range_t *) l->data;
		size += r->end - r->start + 1;
	}

	return size;
}

/*
 * http_range_to_gchar
 *
 * Returns a pointer to static data, containing the available ranges.
 */
gchar *http_range_to_gchar(GSList *list)
{
	static gchar str[2048];
	GSList *l;
	gint rw;

	for (l = list, rw = 0; l && rw < sizeof(str); l = g_slist_next(l)) {
		http_range_t *r = (http_range_t *) l->data;

		rw += gm_snprintf(&str[rw], sizeof(str)-rw, "%u-%u", r->start, r->end);

		if (g_slist_next(l) != NULL)
			rw += gm_snprintf(&str[rw], sizeof(str)-rw, ", ");
	}

	return str;
}

/*
 * http_range_contains
 *
 * Checks whether range contains the contiguous [from, to] interval.
 */
gboolean http_range_contains(GSList *ranges, guint32 from, guint32 to)
{
	GSList *l;

	/*
	 * The following relies on the fact that the `ranges' list is sorted
	 * and that it contains disjoint intervals.
	 */

	for (l = ranges; l; l = g_slist_next(l)) {
		http_range_t *r = (http_range_t *) l->data;

		if (from > r->end)
			continue;

		if (from < r->start)
			break;			/* `from' outside of any following interval */

		/* `from' is within `r' */

		if (to <= r->end)
			return TRUE;

		break;				/* No other interval can contain `from' */
	}

	return FALSE;
}

/***
 *** Asynchronous HTTP error code management.
 ***/

static gchar *error_str[] = {
	"OK",									/* HTTP_ASYNC_OK */
	"Invalid HTTP URL",						/* HTTP_ASYNC_BAD_URL */
	"Connection failed",					/* HTTP_ASYNC_CONN_FAILED */
	"I/O error",							/* HTTP_ASYNC_IO_ERROR */
	"Request too large",					/* HTTP_ASYNC_REQ2BIG */
	"Header too large",						/* HTTP_ASYNC_HEAD2BIG */
	"User cancel",							/* HTTP_ASYNC_CANCELLED */
	"Got EOF",								/* HTTP_ASYNC_EOF */
	"Unparseable HTTP status",				/* HTTP_ASYNC_BAD_STATUS */
	"Got moved status, but no location",	/* HTTP_ASYNC_NO_LOCATION */
	"Data timeout",							/* HTTP_ASYNC_TIMEOUT */
	"Nested redirection",					/* HTTP_ASYNC_NESTED */
	"Invalid URI in Location header",		/* HTTP_ASYNC_BAD_LOCATION_URI */
};

gint http_async_errno;		/* Used to return error codes during setup */

#define MAX_ERRNUM (sizeof(error_str) / sizeof(error_str[0]) - 1)

/*
 * http_async_strerror
 *
 * Return human-readable error string corresponding to error code `errnum'.
 */
gchar *http_async_strerror(gint errnum)
{
	if (errnum < 0 || errnum > MAX_ERRNUM)
		return "Invalid error code";

	return error_str[errnum];
}

/***
 *** Asynchronous HTTP transactions.
 ***/

enum http_reqtype {
	HTTP_HEAD = 0,
	HTTP_GET,
	HTTP_POST,
	HTTP_MAX_REQTYPE,
};

static gchar *http_verb[HTTP_MAX_REQTYPE] = {
	"HEAD",
	"GET",
	"POST",
};

#define HTTP_ASYNC_MAGIC 0xa91cf3ee

struct http_async {					/* An asynchronous HTTP request */
	gint magic;						/* Magic number */
	enum http_reqtype type;			/* Type of request */
	guint32 flags;					/* Operational flags */
	gchar *url;						/* Initial URL request (atom) */
	gchar *path;					/* Path to request (atom) */
	gchar *host;					/* Hostname, if not a numeric IP (atom) */
	struct gnutella_socket *socket;	/* Attached socket */
	http_header_cb_t header_ind;	/* Callback for headers */
	http_data_cb_t data_ind;		/* Callback for data */
	http_error_cb_t error_ind;		/* Callback for errors */
	time_t last_update;				/* Time of last activity */
	gpointer io_opaque;				/* Opaque I/O callback information */
	bio_source_t *bio;				/* Bandwidth-limited source */
	gpointer user_opaque;			/* User opaque data */
	http_user_free_t user_free;		/* Free routine for opaque data */
	struct http_async *parent;		/* Parent request, for redirections */
	GSList *children;				/* Child requests */
};

/*
 * Operational flags.
 */

#define HA_F_FREED		0x00000001	/* Structure has been logically freed */
#define HA_F_SUBREQ		0x00000002	/* Children request now has control */

/*
 * In order to allow detection of logically freed structures when we return
 * from user callbacks, we delay the physical removal of the http_async
 * structure to the clock timer.  A freed structure is marked HA_F_FREED
 * and its magic number is zeroed to prevent accidental reuse.
 *
 * All freed structures are enqueued in the sl_ha_freed list.
 */

static GSList *sl_ha_freed = NULL;		/* Pending physical removal */

/*
 * http_async_info
 *
 * Get URL and request information, given opaque handle.
 * This can be used by client code to log request parameters.
 *
 * Returns URL and fills `req' with the request type string (GET, POST, ...)
 * if it is a non-NULL pointer, `path' with the request path, `ip' and `port'
 * with the server address/port.
 */
gchar *http_async_info(
	gpointer handle, gchar **req, gchar **path, guint32 *ip, guint16 *port)
{
	struct http_async *ha = (struct http_async *) handle;

	g_assert(ha->magic == HTTP_ASYNC_MAGIC);

	if (req)  *req  = http_verb[ha->type];
	if (path) *path = ha->path;
	if (ip)   *ip   = ha->socket->ip;
	if (port) *port = ha->socket->port;

	return ha->url;
}

/*
 * http_async_set_opaque
 *
 * Set user-defined opaque data, which can be freed via `fn'.
 */
void http_async_set_opaque(gpointer handle, gpointer data, http_user_free_t fn)
{
	struct http_async *ha = (struct http_async *) handle;

	g_assert(ha->magic == HTTP_ASYNC_MAGIC);
	g_assert(fn != NULL);
	g_assert(data != NULL);

	ha->user_opaque = data;
	ha->user_free = fn;
}

/*
 * http_async_get_opaque
 *
 * Retrieve user-defined opaque data.
 */
gpointer http_async_get_opaque(gpointer handle)
{
	struct http_async *ha = (struct http_async *) handle;

	g_assert(ha->magic == HTTP_ASYNC_MAGIC);

	return ha->user_opaque;
}

/*
 * http_async_free_recursive
 *
 * Free this HTTP asynchronous request handler, disposing of all its
 * attached resources, recursively.
 */
static void http_async_free_recursive(struct http_async *ha)
{
	GSList *l;

	g_assert(ha->magic == HTTP_ASYNC_MAGIC);

	g_assert(sl_outgoing);

	if (ha->socket)
		socket_free(ha->socket);

	atom_str_free(ha->url);
	atom_str_free(ha->path);

	if (ha->host)
		atom_str_free(ha->host);
	if (ha->io_opaque)
		io_free(ha->io_opaque);
	if (ha->bio)
		bsched_source_remove(ha->bio);
	if (ha->user_free)
		(*ha->user_free)(ha->user_opaque);

	sl_outgoing = g_slist_remove(sl_outgoing, ha);

	/*
	 * Recursively free the children requests.
	 */

	for (l = ha->children; l; l = l->next) {
		struct http_async *cha = (struct http_async *) l->data;
		http_async_free_recursive(cha);
	}

	ha->magic = 0;				/* Prevent accidental reuse */
	ha->flags |= HA_F_FREED;	/* Will be freed later */

	sl_ha_freed = g_slist_prepend(sl_ha_freed, ha);
}

/*
 * http_async_free
 *
 * Free the root of the HTTP asynchronous request handler, disposing
 * of all its attached resources.
 */
static void http_async_free(struct http_async *ha)
{
	struct http_async *hax;

	g_assert(sl_outgoing);

	/*
	 * Find the root of the hierearchy into `hax'.
	 */

	for (hax = ha;; hax = hax->parent) {
		if (!hax->parent)
			break;
	}

	g_assert(hax != NULL);
	g_assert(hax->parent == NULL);

	http_async_free_recursive(hax);
}

/*
 * http_async_free_pending
 *
 * Free all structures that have already been logically freed.
 */
static void http_async_free_pending(void)
{
	GSList *l;

	for (l = sl_ha_freed; l; l = l->next) {
		struct http_async *ha = (struct http_async *) l->data;

		g_assert(ha->flags & HA_F_FREED);
		wfree(ha, sizeof(*ha));
	}

	g_slist_free(sl_ha_freed);
	sl_ha_freed = NULL;
}

/*
 * http_async_close
 *
 * Close request.
 */
void http_async_close(gpointer handle)
{
	struct http_async *ha = (struct http_async *) handle;

	g_assert(ha->magic == HTTP_ASYNC_MAGIC);

	http_async_free(ha);
}

/*
 * http_async_remove
 *
 * Cancel request (internal call).
 */
static void http_async_remove(
	gpointer handle, http_errtype_t type, gpointer code)
{
	struct http_async *ha = (struct http_async *) handle;

	g_assert(ha->magic == HTTP_ASYNC_MAGIC);

	(*ha->error_ind)(handle, type, code);
	http_async_free(ha);
}

/*
 * http_async_cancel
 *
 * Cancel request (user request).
 */
void http_async_cancel(gpointer handle)
{
	http_async_remove(handle, HTTP_ASYNC_ERROR, (gpointer) HTTP_ASYNC_CANCELLED);
}

/*
 * http_async_error
 *
 * Cancel request (internal error).
 */
void http_async_error(gpointer handle, gint code)
{
	http_async_remove(handle, HTTP_ASYNC_ERROR, GINT_TO_POINTER(code));
}

/*
 * http_async_syserr
 *
 * Cancel request (system call error).
 */
static void http_async_syserr(gpointer handle, gint code)
{
	http_async_remove(handle, HTTP_ASYNC_SYSERR, GINT_TO_POINTER(code));
}

/*
 * http_async_headerr
 *
 * Cancel request (header parsing error).
 */
static void http_async_headerr(gpointer handle, gint code)
{
	http_async_remove(handle, HTTP_ASYNC_HEADER, GINT_TO_POINTER(code));
}

/*
 * http_async_http_error
 *
 * Cancel request (HTTP error).
 */
static void http_async_http_error(
	gpointer handle, struct header *header, gint code, gchar *message)
{
	http_error_t he;

	he.header = header;
	he.code = code;
	he.message = message;

	http_async_remove(handle, HTTP_ASYNC_HTTP, &he);
}


/*
 * http_async_create
 *
 * Internal creation routine for HTTP asynchronous requests.
 *
 * The URL to request is given by `url'.
 * The type of HTTP request (GET, POST, ...) is given by `type'.
 *
 * When all headers are read, optionally call `header_ind' if not-NULL.
 * When data is present, call `data_ind'.
 * On error condition during the asynchronous processing, call `error_ind',
 * including when the request is explicitly cancelled (but NOT when it is
 * excplicitly closed).
 *
 * If `parent' is not NULL, then this request is a child request.
 *
 * Returns the newly created request, or NULL with `http_async_errno' set.
 */
static struct http_async *http_async_create(
	gchar *url,
	enum http_reqtype type,
	http_header_cb_t header_ind,
	http_data_cb_t data_ind,
	http_error_cb_t error_ind,
	struct http_async *parent)
{
	guint16 port;
	gchar *path;
	struct gnutella_socket *s;
	struct http_async *ha;
	gchar *host;

	g_assert(url);
	g_assert(data_ind);
	g_assert(error_ind);

	/*
	 * Extract the necessary parameters for the connection.
	 */

	if (!http_url_parse(url, &port, &host, &path)) {
		http_async_errno = HTTP_ASYNC_BAD_URL;
		return NULL;
	}

	/*
	 * Attempt asynchronous connection.
	 *
	 * When connection is established, http_async_connected() will be called
	 * from the socket layer.
	 */

	s = socket_connect_by_name(host, port, SOCK_TYPE_HTTP);

	if (s == NULL) {
		http_async_errno = HTTP_ASYNC_CONN_FAILED;
		return NULL;
	}

	/*
	 * Connection started, build handle and return.
	 */

	ha = walloc(sizeof(*ha));

	s->resource.handle = ha;

	ha->magic = HTTP_ASYNC_MAGIC;
	ha->type = type;
	ha->flags = 0;
	ha->url = atom_str_get(url);
	ha->path = atom_str_get(path);
	ha->host = host ? atom_str_get(host) : NULL;
	ha->socket = s;
	ha->header_ind = header_ind;
	ha->data_ind = data_ind;
	ha->error_ind = error_ind;
	ha->io_opaque = NULL;
	ha->bio = NULL;
	ha->last_update = time(NULL);
	ha->user_opaque = NULL;
	ha->user_free = NULL;
	ha->parent = parent;
	ha->children = NULL;

	sl_outgoing = g_slist_prepend(sl_outgoing, ha);

	/*
	 * If request has a parent, insert in parent's children list.
	 */

	if (parent)
		parent->children = g_slist_prepend(parent->children, ha);

	return ha;
}

/*
 * http_async_get
 *
 * Starts an asynchronous HTTP GET request on the specified path.
 * Returns a handle on the request if OK, NULL on error with the
 * http_async_errno variable set before returning.
 *
 * When data is available, `data_ind' will be called.  When all data have been
 * read, a final call to `data_ind' is made with no data.
 *
 * On error, `error_ind' will be called, and upon return, the request will
 * be automatically cancelled.
 */
gpointer http_async_get(
	gchar *url,
	http_header_cb_t header_ind,
	http_data_cb_t data_ind,
	http_error_cb_t error_ind)
{
	return (gpointer) http_async_create(url, HTTP_GET,
		header_ind, data_ind, error_ind,
		NULL);
}

/*
 * http_subreq_header_ind
 *
 * Interceptor callback for `header_ind' in child requests.
 * Reroute to parent request.
 */
static gboolean http_subreq_header_ind(
	gpointer handle, struct header *header, gint code)
{
	struct http_async *ha = (struct http_async *) handle;

	g_assert(ha->magic == HTTP_ASYNC_MAGIC);
	g_assert(ha->parent != NULL);
	g_assert(ha->parent->header_ind);

	return (*ha->parent->header_ind)(ha->parent, header, code);
}

/*
 * http_subreq_data_ind
 *
 * Interceptor callback for `data_ind' in child requests.
 * Reroute to parent request.
 */
static void http_subreq_data_ind(
	gpointer handle, gchar *data, gint len)
{
	struct http_async *ha = (struct http_async *) handle;

	g_assert(ha->magic == HTTP_ASYNC_MAGIC);
	g_assert(ha->parent != NULL);
	g_assert(ha->parent->data_ind);

	(*ha->parent->data_ind)(ha->parent, data, len);
}

/*
 * http_subreq_error_ind
 *
 * Interceptor callback for `error_ind' in child requests.
 * Reroute to parent request.
 */
static void http_subreq_error_ind(
	gpointer handle, http_errtype_t error, gpointer val)
{
	struct http_async *ha = (struct http_async *) handle;

	g_assert(ha->magic == HTTP_ASYNC_MAGIC);
	g_assert(ha->parent != NULL);
	g_assert(ha->parent->error_ind);

	(*ha->parent->error_ind)(ha->parent, error, val);
}

/*
 * http_async_subrequest
 *
 * Create a child request, to follow redirection transparently.
 * All callbacks will be rerouted to the parent request, as if they came
 * from the original parent.
 *
 * Returns whether we succeeded in creating the subrequest.
 */
static gboolean http_async_subrequest(
	struct http_async *parent, gchar *url, enum http_reqtype type)
{
	struct http_async *child;

	/*
	 * We're installing our own callbacks to transparently reroute them
	 * to the user-supplied callbacks for the parent request, hence making
	 * the sub-request invisible from the outside.
	 */

	child = http_async_create(url, type,
		parent->header_ind ? http_subreq_header_ind : NULL,	/* Optional */
		http_subreq_data_ind, http_subreq_error_ind,
		parent);

	/*
	 * Indicate that the child request now has control, the parent request
	 * being only there to record the user's callbacks (and because it's the
	 * only one known from the outside).
	 */

	if (child)
		parent->flags |= HA_F_SUBREQ;

	return child != NULL;
}

/*
 * http_redirect
 *
 * Redirect current HTTP request to some other URL.
 */
static void http_redirect(struct http_async *ha, gchar *url)
{
	/*
	 * If this request already has a parent, then we're already
	 * a redirection.  We're currently not allowing it.  When we do, it
	 * will have to be limited anyway to avoid endless redirections.
	 */

	if (ha->parent) {
		http_async_error(ha, HTTP_ASYNC_NESTED);
		return;
	}

	/*
	 * Close connection of parent request.
	 *
	 */

	g_assert(ha->socket);

	socket_free(ha->socket);
	ha->socket = NULL;

	/*
	 * Create sub-request to handle the redirection.
	 */

	if (!http_async_subrequest(ha, url, ha->type)) {
		http_async_error(ha, http_async_errno);
		return;
	}

	/*
	 * Free useless I/O opaque structure (a new one will be created when the
	 * subrequest has its socket connected).
	 *
	 * NB: We have to do this after http_async_subrequest(), since `url' is
	 * actually pointing inside the header data in the io_opaque structure: it
	 * is extracted from the Location: header.
	 */

	g_assert(ha->io_opaque);
	g_assert(ha->bio == NULL);		/* Have not started to read data */

	io_free(ha->io_opaque);
	ha->io_opaque = NULL;
}

/*
 * http_got_data
 *
 * Tell the user that we got new data for his request.
 * If `eof' is TRUE, this is the last data we'll get.
 */
static void http_got_data(struct http_async *ha, gboolean eof)
{
	struct gnutella_socket *s = ha->socket;

	g_assert(s);
	g_assert(eof || s->pos > 0);		/* If not EOF, there must be data */

	if (s->pos > 0) {
		ha->last_update = time(NULL);
		(*ha->data_ind)(ha, s->buffer, s->pos);
		if (ha->flags & HA_F_FREED)		/* Callback decided to cancel/close */
			return;
		s->pos = 0;
	}

	if (eof) {
		(*ha->data_ind)(ha, NULL, 0);	/* Indicates EOF */
		if (ha->flags & HA_F_FREED)		/* Callback decided to cancel/close */
			return;
		http_async_free(ha);
	}
}

/*
 * http_data_read
 *
 * Called when data are available on the socket.
 * Read them and pass them to http_got_data().
 */
static void http_data_read(gpointer data, gint source, inputevt_cond_t cond)
{
	struct http_async *ha = (struct http_async *) data;
	struct gnutella_socket *s = ha->socket;
	gint r;

	g_assert(ha->magic == HTTP_ASYNC_MAGIC);

	if (cond & GDK_INPUT_EXCEPTION) {
		http_async_error(ha, HTTP_ASYNC_IO_ERROR);
		return;
	}

	g_assert(s->pos >= 0 && s->pos <= sizeof(s->buffer));

	if (s->pos == sizeof(s->buffer)) {
		http_async_error(ha, HTTP_ASYNC_IO_ERROR);
		return;
	}

	r = bio_read(ha->bio, s->buffer + s->pos, sizeof(s->buffer) - s->pos);
	if (r == 0) {
		http_got_data(ha, TRUE);			/* Signals EOF */
		return;
	} else if (r < 0 && errno == EAGAIN)
		return;
	else if (r < 0) {
		http_async_syserr(ha, errno);
		return;
	}

	s->pos += r;

	http_got_data(ha, FALSE);				/* EOF not reached yet */
}

/*
 * http_got_header
 *
 * Called when the whole server's reply header was parsed.
 */
static void http_got_header(struct http_async *ha, header_t *header)
{
	struct gnutella_socket *s = ha->socket;
	gchar *status = getline_str(s->getline);
	gint ack_code;
	gchar *ack_message = "";
	gchar *buf;
	gint http_major = 0, http_minor = 0;

	ha->last_update = time(NULL);		/* Done reading headers */

	if (dbg > 2) {
		printf("----Got HTTP reply from %s:\n", ip_to_gchar(s->ip));
		printf("%s\n", status);
		header_dump(header, stdout);
		printf("----\n");
		fflush(stdout);
	}

	/*
	 * Check status.
	 */

	ack_code = http_status_parse(status, "HTTP",
		&ack_message, &http_major, &http_minor);

	if (ack_code == -1) {
		http_async_error(ha, HTTP_ASYNC_BAD_STATUS);
		return;
	}

	/*
	 * Notify them that we got the headers.
	 * Don't continue if the callback returns FALSE.
	 */

	if (ha->header_ind && !(*ha->header_ind)(ha, header, ack_code))
		return;

	/*
	 * Deal with return code.
	 */

	switch (ack_code) {
	case 200:					/* OK */
		break;
	case 301:					/* Moved permanently */
	case 302:					/* Found */
	case 303:					/* See other */
	case 307:					/* Moved temporarily */
		buf = header_get(header, "Location");
		if (buf == NULL) {
			http_async_error(ha, HTTP_ASYNC_NO_LOCATION);
			return;
		}

		/*
		 * On 302, we can only blindly follow the redirection if the original
		 * request was a GET or a HEAD.
		 */

		if (
			ack_code != 302 ||
			(ack_code == 302 && (ha->type == HTTP_GET || ha->type == HTTP_HEAD))
		) {
			if (dbg > 2)
				printf("HTTP %s redirect %d (%s): \"%s\" -> \"%s\"\n",
					http_verb[ha->type], ack_code, ack_message, ha->url, buf);

			/*
			 * The Location: header MUST be an absolute URI, according to
			 * RFC-2616 (HTTP/1.1 specs).
			 */

			if (!http_url_parse(buf, NULL, NULL, NULL)) {
				http_async_error(ha, HTTP_ASYNC_BAD_LOCATION_URI);
				return;
			}

			http_redirect(ha, buf);
			return;
		}
		/* FALL THROUGH */
	default:					/* Error */
		http_async_http_error(ha, header, ack_code, ack_message);
		return;
	}

	/*
	 * Prepare reception of data.
	 */

	g_assert(s->gdk_tag == 0);
	g_assert(ha->bio == NULL);

	ha->bio = bsched_source_add(bws.in, s->file_desc,
		BIO_F_READ, http_data_read, (gpointer) ha);

	/*
	 * We may have something left in the input buffer.
	 * Give them the data immediately.
	 */

	if (s->pos > 0)
		http_got_data(ha, FALSE);
}

/**
 ** HTTP header parsing dispatching callbacks.
 **/

static void call_http_got_header(gpointer obj, header_t *header)
{
	struct http_async *ha = (struct http_async *) obj;

	g_assert(ha->magic == HTTP_ASYNC_MAGIC);

	http_got_header(ha, header);
}

static struct io_error http_io_error;

/*
 * http_async_connected
 *
 * Callback from the socket layer when the connection to the remote
 * server is made.
 */
void http_async_connected(gpointer handle)
{
	struct http_async *ha = (struct http_async *) handle;
	struct gnutella_socket *s = ha->socket;
	gchar req[2048];
	gint rw;
	gint sent;

	g_assert(ha->magic == HTTP_ASYNC_MAGIC);
	g_assert(s);
	g_assert(s->resource.handle == handle);

	/*
	 * Create the HTTP request.
	 */

	rw = gm_snprintf(req, sizeof(req),
		"%s %s HTTP/1.1\r\n"
		"Host: %s\r\n"
		"User-Agent: %s\r\n"
		"Connection: close\r\n"
		"\r\n",
		http_verb[ha->type], ha->path,
		ha->host ? ha->host : ip_to_gchar(s->ip),
		version_string);

	if (rw >= sizeof(req)) {
		http_async_error(ha, HTTP_ASYNC_REQ2BIG);
		return;
	}

	/*
	 * Send the HTTP request.
	 */

	if (-1 == (sent = bws_write(bws.out, s->file_desc, req, rw))) {
		g_warning("HTTP request sending to %s failed: %s",
			ip_port_to_gchar(s->ip, s->port), g_strerror(errno));
		http_async_syserr(ha, errno);
		return;
	} else if (sent < rw) {
		g_warning("HTTP request sending to %s: only %d of %d bytes sent",
			ip_port_to_gchar(s->ip, s->port), sent, rw);
		http_async_error(ha, HTTP_ASYNC_IO_ERROR);
		return;
	} else if (dbg > 2) {
		printf("----Sent HTTP request to %s:\n%.*s----\n",
			ip_port_to_gchar(s->ip, s->port), (int) rw, req);
		fflush(stdout);
	}

	ha->last_update = time(NULL);
	
	/*
	 * Prepare to read back the status line and the headers.
	 */

	io_get_header(ha, &ha->io_opaque, bws.in, s, IO_SAVE_FIRST,
		call_http_got_header, NULL, &http_io_error);
}

/*
 * http_async_log_error
 *
 * Default error indication callback which logs the error by listing the
 * initial HTTP request and the reported error cause.
 */
void http_async_log_error(gpointer handle, http_errtype_t type, gpointer v)
{
	gchar *url;
	gchar *req;
	gint error = GPOINTER_TO_INT(v);
	http_error_t *herror = (http_error_t *) v;

	url = http_async_info(handle, &req, NULL, NULL, NULL);

	switch (type) {
	case HTTP_ASYNC_SYSERR:
		g_warning("aborting \"%s %s\" on system error: %s",
			req, url, g_strerror(error));
		break;
	case HTTP_ASYNC_ERROR:
		if (error == HTTP_ASYNC_CANCELLED) {
			if (dbg > 3)
				printf("explicitly cancelled \"%s %s\"\n", req, url);
		} else
			g_warning("aborting \"%s %s\" on error: %s",
				req, url, http_async_strerror(error));
		break;
	case HTTP_ASYNC_HEADER:
		g_warning("aborting \"%s %s\" on header parsing error: %s",
				req, url, header_strerror(error));
		break;
	case HTTP_ASYNC_HTTP:
		g_warning("stopping \"%s %s\": HTTP %d %s",
				req, url, herror->code, herror->message);
		break;
	default:
		g_error("unhandled HTTP request error type %d", type);
		/* NOTREACHED */
	}
}

/***
 *** I/O header parsing callbacks.
 ***/

static void err_line_too_long(gpointer obj)
{
	http_async_error(obj, HTTP_ASYNC_HEAD2BIG);
}

static void err_header_error(gpointer obj, gint error)
{
	http_async_headerr(obj, error);
}

static void err_input_exception(gpointer obj)
{
	http_async_error(obj, HTTP_ASYNC_IO_ERROR);
}

static void err_input_buffer_full(gpointer obj)
{
	http_async_error(obj, HTTP_ASYNC_IO_ERROR);
}

static void err_header_read_error(gpointer obj, gint error)
{
	http_async_syserr(obj, error);
}

static void err_header_read_eof(gpointer obj)
{
	http_async_error(obj, HTTP_ASYNC_EOF);
}

static struct io_error http_io_error = {
	err_line_too_long,
	NULL,
	err_header_error,
	err_input_exception,
	err_input_buffer_full,
	err_header_read_error,
	err_header_read_eof,
	NULL,
};

/*
 * http_timer
 *
 * Called from main timer to expire HTTP requests that take too long.
 */
void http_timer(time_t now)
{
	GSList *l;

retry:
	for (l = sl_outgoing; l; l = l->next) {
		struct http_async *ha = (struct http_async *) l->data;
		time_t elapsed = now - ha->last_update;
		time_t timeout = (time_t) (ha->bio ?
			download_connected_timeout :
			download_connecting_timeout);

		if (ha->flags & HA_F_SUBREQ)
			continue;

		if (elapsed > timeout) {
			http_async_error(ha, HTTP_ASYNC_TIMEOUT);
			goto retry;
		}
	}

	/*
	 * Dispose of the logically freed structures, asynchronously.
	 */

	if (sl_ha_freed)
		http_async_free_pending();
}

/*
 * http_close
 *
 * Shutdown the HTTP module.
 */
void http_close(void)
{
	while (sl_outgoing)
		http_async_error(
			(struct http_async *) sl_outgoing->data, HTTP_ASYNC_CANCELLED);
}

