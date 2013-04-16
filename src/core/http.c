/*
 * Copyright (c) 2002-2003, 2010, Raphael Manfredi
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
 * HTTP routines.
 *
 * The whole HTTP logic is not contained here.  Only generic supporting
 * routines are defined, as well as the asynchronous HTTP logic.
 *
 * @author Raphael Manfredi
 * @date 2002-2003, 2010
 */

#include "common.h"

#include "nodes.h"
#include "http.h"
#include "sockets.h"
#include "bsched.h"
#include "ioheader.h"
#include "version.h"
#include "token.h"
#include "clock.h"
#include "rx.h"
#include "rx_link.h"
#include "rx_inflate.h"
#include "rx_chunk.h"

#include "lib/ascii.h"
#include "lib/atoms.h"
#include "lib/concat.h"
#include "lib/getline.h"
#include "lib/glib-missing.h"
#include "lib/gnet_host.h"
#include "lib/halloc.h"
#include "lib/header.h"
#include "lib/http_range.h"			/* For http_range_test() */
#include "lib/log.h"				/* For log_printable() */
#include "lib/mempcpy.h"
#include "lib/parse.h"
#include "lib/pmsg.h"
#include "lib/str.h"
#include "lib/stringify.h"
#include "lib/timestamp.h"
#include "lib/tm.h"
#include "lib/unsigned.h"
#include "lib/walloc.h"

#include "if/gnet_property_priv.h"

#include "lib/override.h"			/* Must be the last header included */

/*
 * Define to have asynchronous HTTP layer testing at startup.
 */
#if 0
#define HTTP_TESTING
#endif

http_url_error_t http_url_errno;	/**< Error from http_url_parse() */

static GSList *sl_outgoing = NULL;	/**< To spot reply timeouts */

/**
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
 * Unless keep_alive = true.
 *
 * When the outgoing bandwidth is saturated, we start to limit the size of
 * the generated headers.  We reduce the size of the generated header
 * to about 512 bytes, and remove non-essential things.
 *
 * @returns TRUE if we were able to send everything, FALSE otherwise.
 */
bool
http_send_status(
	http_layer_t layer,
	struct gnutella_socket *s, int code, bool keep_alive,
	http_extra_desc_t *hev, int hevcnt,
	const char *reason, ...)
{
	char header[2560];			/* 2.5 K max */
	char status_msg[512];
	size_t rw, minimal_rw;
	size_t header_size = sizeof(header);
	ssize_t sent;
	int i;
	va_list args;
	const char *conn_close = keep_alive ? "" : "Connection: close\r\n";
	const char *no_content = "Content-Length: 0\r\n";
	const char *version;
	const char *date;
	const char *token;
	const char *body = NULL;
	bool saturated = bsched_saturated(BSCHED_BWS_OUT);
	int cb_flags = 0;

	va_start(args, reason);
	str_vbprintf(status_msg, sizeof status_msg - 1, reason, args);
	va_end(args);

	/*
	 * Prepare flags for callbacks.
	 */

	if (saturated)		cb_flags |= HTTP_CBF_BW_SATURATED;
	if (code == 503)	cb_flags |= HTTP_CBF_BUSY_SIGNAL;

	/*
	 * On 5xx errors, limit the header to 1K max, a priori.  This will be
	 * further reduced below if we have saturated the bandwidth.
	 * Likewise, on 4xx errors, we don't need to send much, excepted on 416:
	 * we need a longer reply when the connection is kept alive because of
	 * the available ranges to propagate.
	 */

	if		(code >= 500 && code <= 599)	header_size = 1024;
	else if	(code >= 400 && code <= 499)	header_size = 512;

	/*
	 * Activate X-Available-Ranges: emission on 416 and 2xx provided the
	 * connection will be kept alive.
	 */

	if (keep_alive) {
		if (code == 416) {
			header_size = sizeof(header);		/* Was reduced above for 4xx */
			cb_flags |= HTTP_CBF_SHOW_RANGES;
		} else if (code >= 200 && code <= 299)
			cb_flags |= HTTP_CBF_SHOW_RANGES;
	}

	/*
	 * If bandwidth is short, reduce the header size noticeably, so that only
	 * the most important stuff gets out.
	 *		--RAM, 12/10/2003
	 */

	if (saturated && code >= 300) {
		version = version_short_string;
		token = socket_omit_token(s) ? NULL : tok_short_version();
		header_size = 512;
		cb_flags |= HTTP_CBF_SMALL_REPLY;
	} else {
		version = version_string;
		token = socket_omit_token(s) ? NULL : tok_version();
	}

	for (i = 0; i < hevcnt; i++) {
		http_extra_desc_t *he = &hev[i];

		if (HTTP_EXTRA_BODY == he->he_type) {
			if ('\0' != he->he_msg[0])
				body = he->he_msg;
			break;
		}
	}

	if (code < 300 || !keep_alive || body)
		no_content = "";

	/*
	 * Construct a minimal header: what we shall always send.
	 */

	g_assert(header_size <= sizeof header);

	date = timestamp_rfc1123_to_string(clock_loc2gmt(tm_time()));
	rw = str_bprintf(header, header_size,
		"HTTP/1.1 %d %s\r\n"
		"Server: %s\r\n"
		"Date: %s\r\n"
		"%s"			/* Connection */
		"%s%s%s"		/* X-Token (optional) */
		"%s",			/* Content length */
		code, status_msg, version, date, conn_close,
		token ? "X-Token: " : "",
		token ? token : "",
		token ? "\r\n" : "",
		no_content);

	minimal_rw = rw;		/* Minimal header length */

	/*
	 * Append extra information to the minimal header created above.
	 */

	for (i = 0; i < hevcnt && rw + 3 < header_size; i++) {
		http_extra_desc_t *he = &hev[i];
		http_extra_type_t type = he->he_type;
		size_t size;

		g_assert(header_size >= rw);
	   	size = header_size - rw;

		if (size <= sizeof("\r\n"))
			break;
		size -= sizeof("\r\n");

		switch (type) {
		case HTTP_EXTRA_BODY:
			/* Already handled above */
			break;
		case HTTP_EXTRA_LINE:
			if (size > strlen(he->he_msg)) {
				/* Don't emit truncated lines */
				rw += str_bprintf(&header[rw], size, "%s", he->he_msg);
			}
			break;
		case HTTP_EXTRA_CALLBACK:
			{
				size_t len;

				len = (*he->he_cb)(&header[rw], size, he->he_arg, cb_flags);
				g_assert(len < size);
				rw += len;
			}
			break;
		}
	}

	if (body) {
		rw += str_bprintf(&header[rw], header_size - rw,
						"Content-Length: %zu\r\n", strlen(body));
	}
	if (rw < header_size) {
		rw += str_bprintf(&header[rw], header_size - rw, "\r\n");
	}
	if (body) {
		rw += str_bprintf(&header[rw], header_size - rw, "%s", body);
	}
	if (rw >= header_size - 1 && (hev || body)) {
		g_warning("HTTP status %d (%s) too big, ignoring extra information",
			code, status_msg);

		rw = minimal_rw;
		rw += str_bprintf(&header[rw], header_size - rw, "\r\n");
		g_assert(rw < header_size);
		if (body) {
			rw += str_bprintf(&header[rw], header_size - rw, "%s", body);
		}
	}

	sent = bws_write(BSCHED_BWS_OUT, &s->wio, header, rw);
	if ((ssize_t) -1 == sent) {
		socket_eof(s);
		if (GNET_PROPERTY(http_debug) > 1)
			g_warning("unable to send back HTTP status %d (%s) to %s: %m",
			code, status_msg, host_addr_to_string(s->addr));
		return FALSE;
	} else if ((size_t) sent < rw) {
		if (GNET_PROPERTY(http_debug)) g_warning(
			"only sent %lu out of %lu bytes of status %d (%s) to %s",
			(ulong) sent, (ulong) rw, code, status_msg,
			host_addr_to_string(s->addr));
		return FALSE;
	} else {
		uint32 trace = 0;

		switch (layer) {
		case HTTP_PUSH_PROXY:
			trace = GNET_PROPERTY(push_proxy_trace) & SOCK_TRACE_OUT;
			break;
		case HTTP_UPLOAD:
			trace = GNET_PROPERTY(upload_trace) & SOCK_TRACE_OUT;
			break;
		case HTTP_OTHER:
			trace = GNET_PROPERTY(http_trace) & SOCK_TRACE_OUT;
			break;
		}

		if (trace) {
			g_debug("----Sent HTTP status to %s (%lu bytes):",
				host_addr_to_string(s->addr), (ulong) rw);
			dump_string(stderr, header, rw, "----");
		}
	}

	return TRUE;
}

/**
 * HTTP status callback.
 *
 * Add an X-Hostname line bearing the fully qualified hostname.
 *
 * The ``arg'' parameter is interpreted as a flag: if TRUE, it forces the
 * emission of the header even if bandwidth is tight (HTTP_CBF_SMALL_REPLY).
 */
size_t
http_hostname_add(char *buf, size_t size, void *arg, uint32 flags)
{
	size_t len;

	if (arg == NULL && (flags & HTTP_CBF_SMALL_REPLY))
		return 0;
	if (is_null_or_empty(GNET_PROPERTY(server_hostname)))
		return 0;

	len = concat_strings(buf, size,
			"X-Hostname: ", GNET_PROPERTY(server_hostname), "\r\n",
			(void *) 0);
	return len < size ? len : 0;
}

/**
 * HTTP status callback.
 *
 * Add a Retry-After header.
 */
size_t
http_retry_after_add(char *buf, size_t size,
	void *arg, uint32 unused_flags)
{
	size_t len;

	(void) unused_flags;
	len = concat_strings(buf, size,
			"Retry-After: ", uint32_to_string(GPOINTER_TO_UINT(arg)), "\r\n",
			(void *) 0);
	return len < size ? len : 0;
}

/***
 *** HTTP parsing.
 ***/

/**
 * Parse status messages formed of leading digit numbers, then an optional
 * message.  The pointer to the start of the message is returned in `msg'
 * if it is non-null.
 *
 * @return status code, -1 on error.
 */
static int
code_message_parse(const char *line, const char **msg)
{
	const char *endptr;
	uint32 v;
	int error;

	/*
	 * We expect exactly 3 status digits.
	 */

	v = parse_uint32(line, &endptr, 10, &error);
	if (error || v > 999 || (*endptr != '\0' && !is_ascii_space(*endptr)))
		return -1;

	if (msg)
		*msg = skip_ascii_spaces(endptr);

	return v;
}

/**
 * Parse protocol status line, and return the status code, and optionally a
 * pointer within the string where the status message starts (if `msg' is
 * a non-null pointer), and the protocol major/minor (if `major' and `minor'
 * are non-null).
 *
 * If `proto' is non-null, then when there is a leading protocol string in
 * the reply, it must be equal to `proto'.
 *
 * @returns -1 if it fails to parse the status line correctly, the status code
 * otherwise.
 *
 * We recognize the following status lines:
 *
 *     - ZZZ 403 message                        (major=0, minor=0)
 *     - ZZZ/2.3 403 message                    (major=2, minor=3)
 *     - 403 message                            (major=0, minor=0)
 *
 * We don't yet handle "SMTP-like continuations":
 *
 *     - 403-message line #1
 *     - 403-message line #2
 *     - 403 last message line
 *
 * There is no way to return the value of "ZZZ" via this routine.
 *
 * @attention
 * NB: this routine is also used to parse GNUTELLA status codes, since
 * they follow the same pattern as HTTP status codes.
 */
int
http_status_parse(const char *line,
	const char *proto, const char **msg, uint *major, uint *minor)
{
	uchar c;
	const char *p;

	/*
	 * Skip leading spaces.
	 */

	p = skip_ascii_spaces(line);
	c = *p;

	/*
	 * If first character is a digit, then we have simply:
	 *
	 *   403 message
	 *
	 * There's no known protocol information.
	 */

	if (c == '\0')
		return -1;					/* Empty line */

	if (is_ascii_digit(c)) {
		if (major)
			*major = 0;
		if (minor)
			*minor = 0;
		return code_message_parse(p, msg);
	}

	/*
	 * Check protocol.
	 */

	if (proto) {
		if (NULL != (p = is_strprefix(line, proto))) {
			/*
			 * Protocol string matches, make sure it ends with a space or
			 * a "/" delimiter.
			 */

			c = *p;					/* Can dereference, at worst it's a NUL */
			if (c == '\0')			/* Only "protocol" name in status */
				return -1;
			if (!is_ascii_space(c) && c != '/')
				return -1;
		} else
			return -1;
	} else {
		/*
		 * Move along the string until we find a space or a "/".
		 */

		for (/* empty */; c; c = *(++p)) {
			if (c == '/' || is_ascii_space(c))
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
		if (major || minor) {
			if (0 != parse_major_minor(&p[1], NULL, major, minor))
				return -1;
		}

		for (c = *(++p); c; c = *(++p)) {
			if (is_ascii_space(c))
				break;
		}

		if (c == '\0')
			return -1;
	}

	g_assert(is_ascii_space(c));

	/*
	 * Now strip leading spaces.
	 */

	p = skip_ascii_spaces(++p);
	c = *p;

	if (c == '\0' || !is_ascii_digit(c))
		return -1;

	return code_message_parse(p, msg);
}


/**
 * Extract HTTP version major/minor out of the given request, whose string
 * length is `len' bytes.
 *
 * @returns TRUE when we identified the "HTTP/x.x" trailing string, filling
 * major and minor accordingly.
 */
bool
http_extract_version(
	const char *request, size_t len, uint *major, uint *minor)
{
	const char *p;
	size_t limit, i;

	/*
	 * The smallest request would be "X / HTTP/1.0".
	 */

	limit = sizeof("X / HTTP/1.0") - 1;

	if (GNET_PROPERTY(http_debug) > 4)
		g_debug("HTTP req (%lu bytes): %s", (ulong) len, request);

	if (len < limit)
		return FALSE;

	/*
	 * Scan backwards, until we find the first space with the last trailing
	 * chars.  If we don't, it can't be an HTTP request.
	 */

	for (p = &request[len - 1], i = 0; i < limit; p--, i++) {
		if (' ' == *p)		/* Not isspace(), looking for space only */
			break;
	}

	if (GNET_PROPERTY(http_debug) > 4)
		g_debug("HTTP i = %lu, limit = %lu", (ulong) i, (ulong) limit);

	if (i == limit)
		return FALSE;		/* Reached our limit without finding a space */

	/*
	 * Here, `p' point to the space character.
	 */

	g_assert(*p == ' ');
	p++;

	if (
		NULL == (p = is_strprefix(p, "HTTP/")) ||
		0 != parse_major_minor(p, NULL, major, minor)
	) {
		if (GNET_PROPERTY(http_debug) > 1)
			g_debug("HTTP req (%lu bytes): no protocol tag: %s",
				(ulong) len, request);
		return FALSE;
	}

	if (GNET_PROPERTY(http_debug) > 4)
		g_debug("HTTP req OK (%u.%u)", *major, *minor);

	/*
	 * We don't check trailing chars after the HTTP/x.x indication.
	 * There should not be any, but even if there are, we'll just ignore them.
	 */

	return TRUE;			/* Parsed HTTP/x.x OK */
}

/***
 *** HTTP token and parameter parsing within field value.
 ***/

/**
 * Checks whether header field value starts with specified token, in a case
 * sensitive or insensitive way.
 *
 * The value of header fields like Content-Type: can be split between a leading
 * token and optional parameters, introduced by ';'.  This routine only focuses
 * on the starting token.  For instance, it will match the following two
 * lines:
 *
 *     Field-Name: token
 *     Field-Name: token; param1=value1 param2="value2"
 *
 * However, HTTP allows multiple occurrences of header fields to be collapsed
 * into one single field, with header values separated by ','.  Therefore,
 * the token must either end with '\0' (no parameter) or ';', but a ',' would
 * indicate a multiple-valued field, which is not the scope of this routine.
 *
 * Note that trailing white space after the token are ignored, so we allow
 * blanks between the end of the token and ';' or '\0'.
 *
 * @param buf		the field value we're matching against
 * @param token		the token to look for
 * @param sensitive	if TRUE, match token case-sensitively
 *
 * @return NULL if no match, a pointer to the first character past the token
 * and any whitespace otherwise (either pointing to NUL or ';').
 */
char *
http_field_starts_with(const char *buf, const char *token, bool sensitive)
{
	const char *p;

	p = sensitive ? is_strprefix(buf, token) : is_strcaseprefix(buf, token);

	if (NULL == p)
		return NULL;

	p = skip_ascii_spaces(p);

	if (';' == *p || '\0' == *p)
		return deconstify_char(p);

	return NULL;
}

/**
 * Skip to first unquoted character matching the one specified, or to the end
 * of the string, whichever comes first.
 *
 * Strings within double quotes are handled properly, with '\' being the
 * authorized escaping character.
 *
 * @param p		start of string
 * @param mc	matching character we're looking for
 *
 * @return a pointer in the string to the first occurrence of mc, or a pointer
 * to the end of the string.
 */
static const char *
skip_to_unquoted(const char *p, int mc)
{
	int c;
	bool in_quote = FALSE;

	while ('\0' != (c = *p)) {
		if (in_quote) {
			if ('\\' == c) {
				p++;				/* Ignore escaped character */
				if ('\0' == *p)		/* Unless it's NUL */
					break;
			} else if ('"' == c)
				in_quote = FALSE;
		} else {
			if (c == mc)
				break;
			else if ('"' == c)
				in_quote = TRUE;
		}
		p++;
	}

	return p;
}

/**
 * Collect a parameter value in specified buffer, stripping optional
 * enclosing quotes and un-escaping any escaped character.
 *
 * @param start		first character for value
 * @param value		where value must be stored
 * @param len		length of the value buffer
 *
 * @return TRUE if we managed to fill the value, FALSE on error (value too
 * large to fit in the buffer, or badly delimited end).
 */
static bool
http_value_collect(const char *start, char *value, size_t len)
{
	size_t pos = 0;
	const char *p = start;
	bool has_quote = FALSE;
	int c;

	g_assert(value != NULL);
	g_assert(size_is_non_negative(len));

	c = *p;
	if ('"' == c) {			/* Leading quote is stripped */
		has_quote = TRUE;
		p++;
	}

	while ('\0' != (c = *p++) && pos < len) {
		if ('"' == c) {
			if (has_quote)
				goto ok;
			return FALSE;		/* No quote in the middle of a value */
		} else if ('\\' == c) {
			c = *p++;
			if ('\0' == c)
				return FALSE;	/* No NUL after an escape */
		}
		value[pos++] = c;
	}

	if (has_quote)
		return FALSE;

	if (pos == len)
		return FALSE;			/* Value too large */

ok:
	g_assert(pos < len);

	value[pos] = '\0';
	return TRUE;
}

/**
 * Look for an optional parmeter in the header line and return its value.
 *
 * HTTP parameters are optional elements separated from the header value
 * by a ';' character.  For instance, in a Content-Type header may look
 * like this:
 *
 *		Content-Type: text/html; charset=utf-8
 *
 * The only parameter here is "charset" and its value is "utf-8".
 *
 * Parameter names are case-insensitive, but values may or may not be,
 * depending on the parameter semantics.
 *
 * If the same parameter occurs more than once, only the first value is
 * returned.
 *
 * The value length for a parameter is limited to 255 bytes.  Longer values
 * are simply ignored, i.e. the parameter will appear to be not present.
 * This low size limit protects against malformed headers, since all common
 * parameters are supposed to be much shorter than that.
 *
 * The function skips to the first ';' unquoted character and then starts
 * to look for parameters.
 *
 * @param field			the header field string
 * @param name			the parameter name being looked for
 *
 * @return NULL if the parameter is not found, its value otherwise.   The value
 * is held in a static buffer, so it needs to be duplicated if it needs to be
 * used after another invocation of this routine.
 */
const char *
http_parameter_get(const char *field, const char *name)
{
	static char value[256];
	const char *p;

	/*
	 * The grammar for parameters, from RFC 2616:
	 *
	 *    parameter      ::= attribute '=' value
	 *    attribute      ::= token
	 *    value          ::= token | quoted-string
	 *    quoted-string  ::= '"' (qdtext | quoted-pair)* '"'
	 *    qdtext         ::= <any TEXT except '"'>
	 *    quoted-pair    ::= '\' CHAR
	 *
	 * Parameters are introduced by a ';' character.
	 */

	p = field;

	for (;;) {
		int c;
		const char *eq;

		p = skip_to_unquoted(p, ';');

		c = *p++;			/* Go past the separator */
		if ('\0' == c)		/* Reached end of string */
			break;

		p = skip_ascii_spaces(p);
		if ('\0' == *p)
			break;

		/* At the possible start of a parameter name (attribute) */

		eq = is_strcaseprefix(p, name);
		if (NULL == eq)
			continue;

		if (*eq != '=')
			continue;

		/* Found parameter, collect value in static buffer */

		if (!http_value_collect(eq + 1, value, sizeof value))
			break;

		return value;
	}

	return NULL;
}

/***
 *** HTTP URL parsing.
 ***/

static const char * const parse_errstr[] = {
	"OK",								/**< HTTP_URL_OK */
	"Not an http URI",					/**< HTTP_URL_NOT_HTTP */
	"More than one <user>:<password>",	/**< HTTP_URL_MULTIPLE_CREDENTIALS */
	"Truncated <user>:<password>",		/**< HTTP_URL_BAD_CREDENTIALS */
	"Could not parse port",				/**< HTTP_URL_BAD_PORT_PARSING */
	"Port value is out of range",		/**< HTTP_URL_BAD_PORT_RANGE */
	"Could not parse host",				/**< HTTP_URL_BAD_HOST_PART */
	"Could not resolve host into IP",	/**< HTTP_URL_HOSTNAME_UNKNOWN */
	"URL has no URI part",				/**< HTTP_URL_MISSING_URI */
};

/**
 * @return human-readable error string corresponding to error code `errnum'.
 */
const char *
http_url_strerror(http_url_error_t errnum)
{
	if (UNSIGNED(errnum) >= G_N_ELEMENTS(parse_errstr)) {
		static char buf[40];
		str_bprintf(buf, sizeof buf, "Invalid URL error code: %u", errnum);
		return buf;
	}

	return parse_errstr[errnum];
}

/**
 * Parse HTTP url and extract the IP/port we need to connect to.
 * Also identifies the start of the path to request on the server.
 *
 * @returns TRUE if the URL was correctly parsed, with `port', 'host'
 * and `path' filled if they are non-NULL, FALSE otherwise.
 * The variable `http_url_errno' is set accordingly.
 *
 */
bool
http_url_parse(const char *url, uint16 *port, const char **host,
	const char **path)
{
	static char hostname[MAX_HOSTLEN + 1];
	struct {
		const char *host, *path;
		uint16 port;
	} tmp;
	const char *endptr, *p;
	host_addr_t addr;

	g_assert(url);

	if (!host) host = &tmp.host;
	if (!path) path = &tmp.path;
	if (!port) port = &tmp.port;

	/*
	 * The general URL syntax is (RFC 1738):
	 *
	 *	//[<user>[:<pass>]@]<host>[:<port>]/[<url-path>]
	 *
	 */

	/* Assume there's no <user>:<password> */
	p = is_strcaseprefix(url, "http://");
	if (!p) {
		http_url_errno = HTTP_URL_NOT_HTTP;
		return FALSE;
	}

	/*
	 * Extract hostname into hostname[].
	 */

	if (!string_to_host_or_addr(p, &endptr, &addr)) {
		http_url_errno = HTTP_URL_BAD_HOST_PART;
		return FALSE;
	}

	if (is_host_addr(addr)) {
		host_addr_to_string_buf(addr, hostname, sizeof hostname);
	} else {
		size_t len;
		char *end;

		len = endptr - p;
		if (len >= sizeof hostname) {
			http_url_errno = HTTP_URL_BAD_HOST_PART;
			return FALSE;
		}
		end = mempcpy(hostname, p, len);
		*end = '\0';
	}
	p = endptr;
	*host = hostname;				/* Static data! */

	if (':' != *p) {
		*port = HTTP_PORT;
	} else {
		int error;
		uint32 u;

		g_assert(':'== *p);
		p++;

		u = parse_uint32(p, &endptr, 10, &error);
		if (error) {
			http_url_errno = HTTP_URL_BAD_PORT_PARSING;
			return FALSE;
		} else if (u > 65535) {
			http_url_errno = HTTP_URL_BAD_PORT_RANGE;
			return FALSE;
		}
		p = endptr;
		*port = u;
	}

	*path = p;
	if ('/' != *p) {
		http_url_errno = HTTP_URL_MISSING_URI;
		return FALSE;
	}

	if (GNET_PROPERTY(http_debug) > 4) {
		g_debug("URL \"%s\" -> host=\"%s\", port=%u, path=\"%s\"",
			url, *host, (unsigned) *port, *path);
	}

	http_url_errno = HTTP_URL_OK;

	return TRUE;
}

/***
 *** HTTP buffer management.
 ***/

/**
 * Allocate HTTP buffer, capable of holding data at `buf', of `len' bytes,
 * and whose `written' bytes have already been sent out.
 */
http_buffer_t *
http_buffer_alloc(char *buf, size_t len, size_t written)
{
	http_buffer_t *b;

	g_assert(buf);
	g_assert(size_is_positive(len));
	g_assert(written < len);

	WALLOC(b);
	b->magic = HTTP_BUFFER_MAGIC;
	b->hb_arena = walloc(len);		/* Should be small enough for walloc */
	b->hb_len = len;
	b->hb_end = b->hb_arena + len;
	b->hb_rptr = b->hb_arena + written;

	memcpy(b->hb_arena, buf, len);

	return b;
}

/**
 * Dispose of HTTP buffer.
 */
void
http_buffer_free(http_buffer_t *b)
{
	http_buffer_check(b);

	wfree(b->hb_arena, b->hb_len);
	b->magic = 0;
	WFREE(b);
}

/**
 * Parses the content of a Content-Range header.
 *
 * @param buf should point the payload of a Content-Range header
 * @param start will be set to the ``start'' offset
 * @param end will be set to the ``end'' offset
 * @param total will be set to the ``total'' size of the requested object.
 *
 * @return -1 on error, zero on success.
 */
int
http_content_range_parse(const char *buf,
		filesize_t *start, filesize_t *end, filesize_t *total)
{
	const char *s = buf, *endptr;
	int error;

	/*
	 * HTTP/1.1 -- RFC 2616 -- 3.12 Range Units
	 *
	 *		bytes SP start '-' end '/' total
	 *
	 * HTTP/1.1 -- RFC 2616 -- 14.35.1 Byte Ranges
	 *
	 * This is wrong but used by some (legacy?) servers:
	 *
	 *		bytes '=' start '-' end '/' total
	 */

	s = is_strcaseprefix(s, "bytes");
	if (!s)
		return -1;

	if (*s != ' ' && *s != '=')
		return -1;

	s++;
	s = skip_ascii_spaces(s);
	*start = parse_uint64(s, &endptr, 10, &error);
	if (error || *endptr++ != '-')
		return -1;

	s = skip_ascii_spaces(endptr);
	*end = parse_uint64(s, &endptr, 10, &error);
	if (error || *endptr++ != '/')
		return -1;

	s = skip_ascii_spaces(endptr);
	*total = parse_uint64(s, &endptr, 10, &error);

	/*
	 * According to the HTTP/1.1 specs, start <= end < total
	 * must be true, otherwise the range is invalid.
	 */

	if (error || *start > *end || *end >= *total)
		return -1;

	return 0;
}

/***
 *** Asynchronous HTTP error code management.
 ***/

static const char * const error_str[] = {
	"OK",									/**< HTTP_ASYNC_OK */
	"Invalid HTTP URL",						/**< HTTP_ASYNC_BAD_URL */
	"Connection failed",					/**< HTTP_ASYNC_CONN_FAILED */
	"I/O error",							/**< HTTP_ASYNC_IO_ERROR */
	"Request too large",					/**< HTTP_ASYNC_REQ2BIG */
	"Header too large",						/**< HTTP_ASYNC_HEAD2BIG */
	"User cancel",							/**< HTTP_ASYNC_CANCELLED */
	"Got EOF",								/**< HTTP_ASYNC_EOF */
	"Unparseable HTTP status",				/**< HTTP_ASYNC_BAD_STATUS */
	"Got moved status, but no location",	/**< HTTP_ASYNC_NO_LOCATION */
	"Connection timeout",					/**< HTTP_ASYNC_CONN_TIMEOUT */
	"Data timeout",							/**< HTTP_ASYNC_TIMEOUT */
	"Nested redirection",					/**< HTTP_ASYNC_NESTED */
	"Invalid URI in Location header",		/**< HTTP_ASYNC_BAD_LOCATION_URI */
	"Connection was closed, all OK",		/**< HTTP_ASYNC_CLOSED */
	"Redirected, following disabled",		/**< HTTP_ASYNC_REDIRECTED */
	"Unparseable header value",				/**< HTTP_ASYNC_BAD_HEADER */
	"Data too large",						/**< HTTP_ASYNC_DATA2BIG */
	"Mandatory request not understood",		/**< HTTP_ASYNC_MAN_FAILURE */
};

uint http_async_errno;		/**< Used to return error codes during setup */

/**
 * @return human-readable error string corresponding to error code `errnum'.
 */
const char *
http_async_strerror(uint errnum)
{
	if (errnum >= G_N_ELEMENTS(error_str)) {
		static char buf[50];
		str_bprintf(buf, sizeof buf,
			"Invalid HTTP async error code: %u", errnum);
		return buf;
	}

	return error_str[errnum];
}

/***
 *** Asynchronous HTTP transactions.
 ***/

enum http_reqtype {
	HTTP_HEAD = 0,
	HTTP_GET,
	HTTP_POST,

	NUM_HTTP_REQTYPES
};

static const char * const http_verb[NUM_HTTP_REQTYPES] = {
	"HEAD",
	"GET",
	"POST",
};

enum http_async_magic { HTTP_ASYNC_MAGIC = 0x291cf3eeU };

/**
 * An asynchronous HTTP request.
 */
struct http_async {
	enum http_async_magic magic;	/**< Magic number */
	enum http_reqtype type;			/**< Type of request */
	http_state_t state;				/**< Current request state */
	uint32 flags;					/**< Operational flags */
	uint32 options;					/**< User options */
	const char *url;				/**< Initial URL request (atom) */
	const char *path;				/**< Path to request (atom) */
	const char *host;				/**< Hostname, if not a numeric IP (atom) */
	struct gnutella_socket *socket;	/**< Attached socket */
	http_header_cb_t header_ind;	/**< Callback for headers */
	http_data_cb_t data_ind;		/**< Callback for data */
	http_error_cb_t error_ind;		/**< Callback for errors */
	http_state_change_t state_chg;	/**< Optional: callback for state changes */
	time_t last_update;				/**< Time of last activity */
	void *io_opaque;				/**< Opaque I/O callback information */
	rxdrv_t *rx;					/**< RX stack for downloading data */
	void *user_opaque;				/**< User opaque data */
	http_user_free_t user_free;		/**< Free routine for opaque data */
	struct http_async *parent;		/**< Parent request, for redirections */
	GSList *delayed;				/**< Delayed data (list of http_buffer_t) */
	GSList *children;				/**< Child requests */
	unsigned header_sent:1;			/**< Whether HTTP request header was sent */

	/*
	 * Only defined for POST operations.
	 */

	const char *content_type;		/**< For POST: data Content-Type */
	char *data;						/**< For POST: data to send */
	size_t datalen;					/**< For POST: length of data */
	http_data_free_t data_free;		/**< Optional free routine for data */
	void *data_free_arg;			/**< Additional argument for data_free */

	http_op_post_request_t op_post_request;	/**< Creates HTTP request */

	/*
	 * Operations that may be redefined by user.
	 */


	http_op_get_request_t op_get_request;	/**< Creates HTTP request */
	http_op_reqsent_t op_headsent;		/**< Called on HTTP header sent */
	http_op_reqsent_t op_datasent;		/**< Called on HTTP data sent */
	http_op_gotreply_t op_gotreply;		/**< Called when HTTP reply received */
};

/*
 * Operational flags.
 */

#define HA_F_FREED		0x00000001	/**< Structure has been logically freed */
#define HA_F_SUBREQ		0x00000002	/**< Children request now has control */

/**
 * In order to allow detection of logically freed structures when we return
 * from user callbacks, we delay the physical removal of the http_async
 * structure to the clock timer.  A freed structure is marked HA_F_FREED
 * and its magic number is zeroed to prevent accidental reuse.
 *
 * All freed structures are enqueued in the sl_ha_freed list.
 */

static GSList *sl_ha_freed = NULL;		/* Pending physical removal */

static void http_async_connected(http_async_t *handle);

static inline void
http_async_check(const http_async_t *ha)
{
	g_assert(ha != NULL);
	g_assert(HTTP_ASYNC_MAGIC == ha->magic);
}

/**
 * Callback invoked when socket is destroyed.
 */
static void
http_async_socket_destroy(gnutella_socket_t *s, void *owner, const char *reason)
{
	http_async_t *ha = owner;

	http_async_check(ha);
	g_assert(s == ha->socket);

	(void) reason;
	http_async_error(ha, HTTP_ASYNC_IO_ERROR);
}

/**
 * Callback invoked when socket is connected.
 */
static void
http_async_socket_connected(gnutella_socket_t *s, void *owner)
{
	http_async_t *ha = owner;

	http_async_check(ha);
	g_assert(s == ha->socket);

	http_async_connected(ha);
}

/**
 * Socket-layer callbacks for asynchronous HTTP requests.
 */
static struct socket_ops http_async_socket_ops = {
	NULL,							/* connect_failed */
	http_async_socket_connected,	/* connected */
	http_async_socket_destroy,		/* destroy */
};

/**
 * Get URL and request information, given opaque handle.
 * This can be used by client code to log request parameters.
 *
 * @returns URL and fills `req' with the request type string (GET, POST, ...)
 * if it is a non-NULL pointer, `path' with the request path, `addr' and `port'
 * with the server address/port.
 */
const char *
http_async_info(
	http_async_t *handle, const char **req, const char **path,
	host_addr_t *addr, uint16 *port)
{
	http_async_t *ha = handle;

	http_async_check(ha);

	if (req)  *req  = http_verb[ha->type];
	if (path) *path = ha->path;
	if (addr) *addr   = ha->socket->addr;
	if (port) *port = ha->socket->port;

	return ha->url;
}

/**
 * Set user-defined opaque data, which can optionally be freed via `fn' if a
 * non-NULL function pointer is given.
 */
void
http_async_set_opaque(http_async_t *ha, void *data, http_user_free_t fn)
{
	http_async_check(ha);
	g_assert(data != NULL);

	ha->user_opaque = data;
	ha->user_free = fn;
}

/**
 * Retrieve user-defined opaque data.
 */
void *
http_async_get_opaque(const http_async_t *ha)
{
	http_async_check(ha);

	return ha->user_opaque;
}

/**
 * Retrieve local IP address, if available, filling ``addrp''.
 *
 * @return TRUE if the IP address is available with the address being filled
 * in ``addrp'', FALSE otherwise.
 */
bool
http_async_get_local_addr(const http_async_t *ha, host_addr_t *addrp)
{
	http_async_check(ha);

	return socket_local_addr(ha->socket, addrp);
}

/**
 * Provide additional options to adjust the behaviour.
 *
 * Options are given by a mask.  One can either add new options, remove
 * specified options or set options.
 *
 */
void
http_async_option_ctl(http_async_t *ha, uint32 mask, http_ctl_op_t what)
{
	http_async_check(ha);

	switch (what) {
	case HTTP_CTL_ADD:
		ha->options |= mask;
		return;
	case HTTP_CTL_REMOVE:
		ha->options &= ~mask;
		return;
	case HTTP_CTL_SET:
		ha->options = mask;
		return;
	}

	g_assert_not_reached();
}

/**
 * Free this HTTP asynchronous request handler, disposing of all its
 * attached resources, recursively.
 */
static void
http_async_free_recursive(http_async_t *ha)
{
	GSList *l;

	http_async_check(ha);
	g_assert(sl_outgoing);

	atom_str_free_null(&ha->url);
	atom_str_free_null(&ha->path);
	atom_str_free_null(&ha->host);

	if (ha->io_opaque) {
		io_free(ha->io_opaque);
		ha->io_opaque = NULL;
	}
	if (ha->rx)
		rx_disable(ha->rx);			/* No further reads */
	socket_free_null(&ha->socket);
	if (ha->user_free) {
		(*ha->user_free)(ha->user_opaque);
		ha->user_free = NULL;
		ha->user_opaque = NULL;
	}
	if (ha->data_free) {
		(*ha->data_free)(ha->data, ha->data_free_arg);
		ha->data_free = NULL;
		ha->data = NULL;
	}
	if (ha->delayed != NULL) {
		GSList *sl;

		GM_SLIST_FOREACH(ha->delayed, sl) {
			http_buffer_free(sl->data);
		}
		gm_slist_free_null(&ha->delayed);
	}
	sl_outgoing = g_slist_remove(sl_outgoing, ha);

	/*
	 * Recursively free the children requests.
	 */

	for (l = ha->children; l; l = l->next) {
		http_async_t *cha = l->data;
		http_async_free_recursive(cha);
	}

	ha->magic = 0;					/* Prevent accidental reuse */
	ha->flags |= HA_F_FREED;		/* Will be freed later */
	ha->state = HTTP_AS_REMOVED;	/* Don't notify about state change! */

	sl_ha_freed = g_slist_prepend(sl_ha_freed, ha);
}

/**
 * Free the root of the HTTP asynchronous request handler, disposing
 * of all its attached resources.
 */
static void
http_async_free(http_async_t *ha)
{
	http_async_t *hax;

	http_async_check(ha);
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

/**
 * Free all structures that have already been logically freed.
 *
 * This is done asynchronously with respect to any data reception, which
 * guarantees that nobody can reference the structure any more.
 */
static void
http_async_free_pending(void)
{
	GSList *l;

	for (l = sl_ha_freed; l; l = l->next) {
		http_async_t *ha = l->data;

		g_assert(ha->flags & HA_F_FREED);

		if (ha->rx != NULL)
			rx_free(ha->rx);		/* RX must be dismantled asynchronously */

		WFREE(ha);
	}

	gm_slist_free_null(&sl_ha_freed);
}

/**
 * Close request.
 */
void
http_async_close(http_async_t *ha)
{
	http_async_check(ha);
	http_async_free(ha);
}

/**
 * Cancel request (internal call).
 */
static void
http_async_remove(http_async_t *ha, http_errtype_t type, void *code)
{
	http_async_check(ha);

	(*ha->error_ind)(ha, type, code);

	/*
	 * Callback may decide to cancel/close the request on errors, which
	 * will mark the request with the HA_F_FREED flag (the object being
	 * collected asynchronously so still being accessible upon callback
	 * return).
	 */

	if (!(ha->flags & HA_F_FREED))
		http_async_free(ha);
}

/**
 * Cancel request (user request).
 */
void
http_async_cancel(http_async_t *handle)
{
	http_async_check(handle);
	http_async_remove(handle, HTTP_ASYNC_ERROR,
		GINT_TO_POINTER(HTTP_ASYNC_CANCELLED));
}

/**
 * Cancel request (user request) and nullify pointer.
 */
void
http_async_cancel_null(http_async_t **handle_ptr)
{
	http_async_t *ha = *handle_ptr;

	if (ha != NULL) {
		http_async_cancel(ha);
		*handle_ptr = NULL;
	}
}

/**
 * Cancel request (internal error).
 */
void
http_async_error(http_async_t *handle, int code)
{
	http_async_check(handle);
	http_async_remove(handle, HTTP_ASYNC_ERROR, GINT_TO_POINTER(code));
}

/**
 * Cancel request (system call error).
 */
static void
http_async_syserr(http_async_t *handle, int code)
{
	http_async_check(handle);
	http_async_remove(handle, HTTP_ASYNC_SYSERR, GINT_TO_POINTER(code));
}

/**
 * Cancel request (header parsing error).
 */
static void
http_async_headerr(http_async_t *handle, int code)
{
	http_async_check(handle);
	http_async_remove(handle, HTTP_ASYNC_HEADER, GINT_TO_POINTER(code));
}

/**
 * Cancel request (HTTP error).
 */
static void
http_async_http_error(http_async_t *handle, struct header *header,
	int code, const char *message)
{
	http_error_t he;

	http_async_check(handle);

	he.header = header;
	he.code = code;
	he.message = message;

	http_async_remove(handle, HTTP_ASYNC_HTTP, &he);
}

/**
 * Build HTTP "host:port" string for the remote host, suitable for inclusion
 * in the Host header of the HTTP request.
 *
 * @return pointer to static data
 */
const char *
http_async_remote_host_port(const http_async_t *ha)
{
	static char buf[MAX_HOSTLEN + UINT32_DEC_BUFLEN + 1];
	struct gnutella_socket *s;

	STATIC_ASSERT(HOST_ADDR_BUFLEN <= MAX_HOSTLEN);
	http_async_check(ha);

	s = ha->socket;

	if (ha->host) {
		if (s->port != HTTP_PORT)
			str_bprintf(buf, sizeof buf, "%s:%u", ha->host, (uint) s->port);
		else
			g_strlcpy(buf, ha->host, sizeof buf);
	} else {
		if (s->port != HTTP_PORT)
			host_addr_port_to_string_buf(s->addr, s->port, buf, sizeof buf);
		else
			host_addr_to_string_buf(s->addr, buf, sizeof buf);
	}

	return buf;
}

/**
 * Default callback invoked to build the HTTP GET request.
 *
 * The request is to be built in `buf', which is `len' bytes long.
 * The HTTP request is defined by the `verb' ("GET", "HEAD", ...), the
 * `path' to ask for and the `host' to which we are making the request, for
 * suitable "Host:" header emission.
 *
 * @return the length of the generated request, which must be terminated
 * properly by a trailing "\r\n" on a line by itself to mark the end of the
 * header.
 */
static size_t
http_async_build_get_request(const http_async_t *ha,
	char *buf, size_t len, const char *verb, const char *path)
{
	size_t rw;

	http_async_check(ha);
	g_assert(len <= INT_MAX);

	rw = str_bprintf(buf, len,
		"%s %s HTTP/1.1\r\n"
		"Host: %s\r\n"
		"User-Agent: %s\r\n"
		"Accept-Encoding: deflate\r\n"
		"Connection: close\r\n"
		"\r\n",
		verb, path,
		http_async_remote_host_port(ha),
		version_string);

	return rw;
}

/**
 * Default callback invoked to build the HTTP POST request.
 *
 * The request is to be built in `buf', which is `len' bytes long.
 * The HTTP request is defined by the `verb' ("POST"), the `path' to ask for,
 * the `host' to which we are making the request, and the content that will
 * be included with the request.
 *
 * @return the length of the generated request, which must be terminated
 * properly by a trailing "\r\n" on a line by itself to mark the end of the
 * header.
 */
static size_t
http_async_build_post_request(const http_async_t *ha,
	char *buf, size_t len, const char *verb, const char *path,
	const char *content_type, size_t content_len)
{
	size_t rw;

	http_async_check(ha);
	g_assert(len <= INT_MAX);

	rw = str_bprintf(buf, len,
		"%s %s HTTP/1.1\r\n"
		"Host: %s\r\n"
		"User-Agent: %s\r\n"
		"Accept-Encoding: deflate\r\n"
		"Content-Type: %s\r\n"
		"Content-Length: %s\r\n"
		"Connection: close\r\n"
		"\r\n",
		verb, path,
		http_async_remote_host_port(ha),
		version_string, content_type, size_t_to_string(content_len));

	return rw;
}

/**
 * Default callback invoked when the HTTP request header has been sent.
 *
 * @param unused_ha		the (unused) HTTP async request descriptor
 * @param s				the socket on which we wrote the request
 * @param req			the actual request string
 * @param len			the length of the request string
 * @param deferred		if TRUE, full request sending was deferred earlier
 */
static void
http_async_sent_head(const http_async_t *unused_ha,
	const struct gnutella_socket *s, const char *req, size_t len,
	bool deferred)
{
	(void) unused_ha;

	if (GNET_PROPERTY(http_trace) & SOCK_TRACE_OUT) {
		g_debug("----Sent HTTP request%s to %s (%u bytes):",
			deferred ? " completely" : "",
			host_addr_port_to_string(s->addr, s->port), (unsigned) len);
		dump_string(stderr, req, len, "----");
	}
}

/**
 * Default callback invoked when the HTTP request data has been sent.
 *
 * @param unused_ha		the (unused) HTTP async request descriptor
 * @param s				the socket on which we wrote the data
 * @param data			the actual data string
 * @param len			the length of the data string
 * @param deferred		if TRUE, full data sending was deferred earlier
 */
static void
http_async_sent_data(const http_async_t *unused_ha,
	const struct gnutella_socket *s, const char *data, size_t len,
	bool deferred)
{
	(void) unused_ha;

	if (GNET_PROPERTY(http_trace) & SOCK_TRACE_OUT) {
		g_debug("----Sent HTTP data%s to %s (%u bytes):",
			deferred ? " completely" : "",
			host_addr_port_to_string(s->addr, s->port), (unsigned) len);
		dump_string(stderr, data, len, "----");
	}
}

/**
 * Default callback invoked when we got the whole HTTP reply.
 *
 * @param unused_ha		the (unused) HTTP async request descriptor
 * @param s				the socket on which we got the reply
 * @param status		the first HTTP status line
 * @param header		the parsed header structure
 */
static void
http_async_got_reply(const http_async_t *unused_ha,
	const struct gnutella_socket *s, const char *status, const header_t *header)
{
	(void) unused_ha;

	if (GNET_PROPERTY(http_trace) & SOCK_TRACE_IN) {
		if (log_printable(LOG_STDERR)) {
			g_debug("----Got HTTP reply from %s:",
				host_addr_to_string(s->addr));
			fprintf(stderr, "%s\n", status);
			header_dump(stderr, header, "----");
		}
	}
}

/**
 * Internal creation routine for HTTP asynchronous requests.
 *
 * The URL to request is given by `url'.
 * The type of HTTP request (GET, POST, ...) is given by `type'.
 *
 * If `addr' is non-zero, then `url' is supposed to hold a path, and `port'
 * must also be non-zero.  Otherwise, the IP and port are gathered from
 * `url', which must start be something like "http://server:port/path".
 *
 * When all headers are read, optionally call `header_ind' if not-NULL.
 * When data is present, optionally call `data_ind' or close the connection.
 * On error condition during the asynchronous processing, call `error_ind',
 * including when the request is explicitly cancelled (but NOT when it is
 * excplicitly closed).
 *
 * If `parent' is not NULL, then this request is a child request.
 *
 * @param url			the full URL or path requested
 * @param addr			host to contact, 0 means: grab from URL
 * @param port			port to contact, grabbed from URL if addr is 0
 * @param type			HTTP_GET or HTTP_POST
 * @param post_data		for HTTP_POST: description data to post in request
 * @param header_ind	header reception indication callback
 * @param data_ind		data reception indication callback
 * @param error_ind		error indication callback
 * @param parent		parent HTTP request, if nested request after redirect
 *
 * @return the newly created request, or NULL with `http_async_errno' set.
 */
static http_async_t *
http_async_create(
	const char *url,				/* Either full URL or path */
	const host_addr_t addr,			/* Optional: 0 means grab from url */
	uint16 port,					/* Optional, must be given when IP given */
	enum http_reqtype type,			/* HTTP_GET or HTTP_POST */
	http_post_data_t *post_data,	/* For HTTP_POST only */
	http_header_cb_t header_ind,
	http_data_cb_t data_ind,
	http_error_cb_t error_ind,
	http_async_t *parent)
{
	struct gnutella_socket *s;
	http_async_t *ha;
	const char *path, *host = NULL;

	g_assert(url);
	g_assert(error_ind);
	g_assert(!is_host_addr(addr) || port != 0);
	g_assert(HTTP_POST == type || NULL == post_data);
	g_assert(HTTP_POST != type || NULL != post_data);

	/*
	 * Extract the necessary parameters for the connection.
	 *
	 * When connection is established, http_async_connected() will be called
	 * from the socket layer.
	 */

	if (!is_host_addr(addr)) {
		host_addr_t ip;
		uint16 uport;

		if (!http_url_parse(url, &uport, &host, &path)) {
			http_async_errno = HTTP_ASYNC_BAD_URL;
			return NULL;
		}

		g_assert(host != NULL);

		/*
		 * Host can be an IP address or a hostname.  If it is a hostname,
		 * we want to keep it as such in ha->host, otherwise we keep only
		 * the IP address as part of the socket structure.
		 */

		if (string_to_host_addr(host, NULL, &ip)) {
			host = NULL;
			s = socket_connect(ip, uport, SOCK_TYPE_HTTP, SOCK_F_FORCE);
		} else {
			s = socket_connect_by_name(host, uport,
					SOCK_TYPE_HTTP, SOCK_F_FORCE);
		}
	} else {
		host = NULL;
		path = url;
		s = socket_connect(addr, port, SOCK_TYPE_HTTP, SOCK_F_FORCE);
	}

	if (s == NULL) {
		http_async_errno = HTTP_ASYNC_CONN_FAILED;
		return NULL;
	}

	/*
	 * Connection started, build handle and return.
	 */

	WALLOC0(ha);

	ha->magic = HTTP_ASYNC_MAGIC;
	ha->type = type;
	ha->state = HTTP_AS_CONNECTING;
	ha->flags = 0;
	ha->url = atom_str_get(url);
	ha->path = atom_str_get(path);
	ha->host = host ? atom_str_get(host) : NULL;
	ha->socket = s;
	ha->header_ind = header_ind;
	ha->data_ind = data_ind;
	ha->error_ind = error_ind;
	ha->state_chg = NULL;
	ha->io_opaque = NULL;
	ha->rx = NULL;
	ha->last_update = tm_time();
	ha->user_opaque = NULL;
	ha->user_free = NULL;
	ha->parent = parent;
	ha->children = NULL;
	ha->delayed = NULL;

	socket_attach_ops(s, SOCK_TYPE_HTTP, &http_async_socket_ops, ha);

	if (post_data != NULL) {
		ha->data = post_data->data;
		ha->datalen = post_data->datalen;
		ha->content_type = post_data->content_type;
		ha->data_free = post_data->data_free;
		ha->data_free_arg = post_data->data_free_arg;
	}

	if (HTTP_POST == ha->type) {
		ha->op_get_request = NULL;;
		ha->op_post_request = http_async_build_post_request;
		ha->op_datasent = http_async_sent_data;
	} else {
		ha->op_get_request = http_async_build_get_request;
		ha->op_post_request = NULL;
		ha->op_datasent = NULL;;
	}

	ha->op_headsent = http_async_sent_head;
	ha->op_gotreply = http_async_got_reply;

	sl_outgoing = g_slist_prepend(sl_outgoing, ha);

	/*
	 * If request has a parent, insert in parent's children list.
	 */

	if (parent)
		parent->children = g_slist_prepend(parent->children, ha);

	return ha;
}

/**
 * @return the server hostname, if known, otherwise the IP address.
 */
static const char *
http_async_host(const http_async_t *ha)
{
	static char buf[HOST_ADDR_BUFLEN];

	if (ha->host != NULL)
		return ha->host;

	host_addr_to_string_buf(ha->socket->addr, buf, sizeof buf);
	return buf;
}

/**
 * Change the request state, and notify listener if any.
 */
static void
http_async_newstate(http_async_t *ha, http_state_t state)
{
	http_async_check(ha);

	ha->state = state;
	ha->last_update = tm_time();

	if (ha->state_chg != NULL)
		(*ha->state_chg)(ha, state);
}

/**
 * Starts an asynchronous HTTP GET request on the specified path.
 *
 * @returns a handle on the request if OK, NULL on error with the
 * http_async_errno variable set before returning.
 *
 * When data is available, `data_ind' will be called.  When all data have been
 * read, a final call to `data_ind' is made with no data.  If there is no
 * `data_ind' routine, the connection will be closed after reading the
 * whole header.
 *
 * On error, `error_ind' will be called, and upon return, the request will
 * be automatically cancelled.
 */
http_async_t *
http_async_get(
	const char *url,
	http_header_cb_t header_ind,
	http_data_cb_t data_ind,
	http_error_cb_t error_ind)
{
	return http_async_create(url, zero_host_addr, 0, HTTP_GET, NULL,
		header_ind, data_ind, error_ind, NULL);
}

/**
 * Same as http_async_get(), but a path on the server is given and the
 * IP and port to contact are given explicitly.
 */
http_async_t *
http_async_get_addr(
	const char *path,
	const host_addr_t addr,
	uint16 port,
	http_header_cb_t header_ind,
	http_data_cb_t data_ind,
	http_error_cb_t error_ind)
{
	return http_async_create(path, addr, port, HTTP_GET, NULL,
		header_ind, data_ind, error_ind,
		NULL);
}

/**
 * Starts an asynchronous HTTP POST request to the specified path.
 *
 * When reply data is available, `data_ind' will be called.  When all data have
 * been read, a final call to `data_ind' is made with no data.  If there is no
 * `data_ind' routine, the connection will be closed after reading the
 * whole header.
 *
 * On error, `error_ind' will be called, and upon return, the request will
 * be automatically cancelled.
 *
 * @returns a handle on the request if OK, NULL on error with the
 * http_async_errno variable set before returning.
 */
http_async_t *
http_async_post(
	const char *url,
	http_post_data_t *post_data,
	http_header_cb_t header_ind,
	http_data_cb_t data_ind,
	http_error_cb_t error_ind)
{
	return http_async_create(url, zero_host_addr, 0, HTTP_POST, post_data,
		header_ind, data_ind, error_ind, NULL);
}

/**
 * Same as http_async_post(), but a path on the server is given and the
 * IP and port to contact are given explicitly.
 */
http_async_t *
http_async_post_addr(
	const char *path,
	const host_addr_t addr,
	uint16 port,
	http_post_data_t *post_data,
	http_header_cb_t header_ind,
	http_data_cb_t data_ind,
	http_error_cb_t error_ind)
{
	return http_async_create(path, addr, port, HTTP_POST, post_data,
		header_ind, data_ind, error_ind, NULL);
}

/**
 * Redefines the building of the HTTP GET request.
 */
void
http_async_set_op_get_request(http_async_t *ha, http_op_get_request_t op)
{
	http_async_check(ha);
	g_assert(op != NULL);
	g_assert(HTTP_POST != ha->type);

	ha->op_get_request = op;
}

/**
 * Redefines the building of the HTTP POST request.
 */
void
http_async_set_op_post_request(http_async_t *ha, http_op_post_request_t op)
{
	http_async_check(ha);
	g_assert(op != NULL);
	g_assert(HTTP_POST == ha->type);

	ha->op_post_request = op;
}

/**
 * Set callback to invoke when the HTTP request header is sent.
 */
void http_async_set_op_headsent(http_async_t *ha, http_op_reqsent_t op)
{
	http_async_check(ha);
	g_assert(op != NULL);

	ha->op_headsent = op;
}

/**
 * Set callback to invoke when the HTTP request data is sent (for POST).
 */
void http_async_set_op_datasent(http_async_t *ha, http_op_reqsent_t op)
{
	http_async_check(ha);
	g_assert(op != NULL);
	g_assert(HTTP_POST == ha->type);

	ha->op_datasent = op;
}

/**
 * Set callback to invoke when HTTP reply has been fully received.
 */
void http_async_set_op_gotreply(http_async_t *ha, http_op_gotreply_t op)
{
	http_async_check(ha);
	g_assert(op != NULL);

	ha->op_gotreply = op;
}

/**
 * Defines callback to invoke when the request changes states.
 */
void
http_async_on_state_change(http_async_t *ha, http_state_change_t fn)
{
	http_async_check(ha);
	g_assert(fn != NULL);

	ha->state_chg = fn;
}

/**
 * Interceptor callback for `header_ind' in child requests.
 * Reroute to parent request.
 */
static bool
http_subreq_header_ind(http_async_t *ha, struct header *header,
	int code, const char *message)
{
	http_async_check(ha);
	g_assert(ha->parent != NULL);
	g_assert(ha->parent->header_ind);

	return (*ha->parent->header_ind)(ha->parent, header, code, message);
}

/**
 * Interceptor callback for `data_ind' in child requests.
 * Reroute to parent request.
 */
static void
http_subreq_data_ind(http_async_t *ha, char *data, int len)
{
	http_async_check(ha);
	g_assert(ha->parent != NULL);
	g_assert(ha->parent->data_ind);

	(*ha->parent->data_ind)(ha->parent, data, len);
}

/**
 * Interceptor callback for `error_ind' in child requests.
 * Reroute to parent request.
 */
static void
http_subreq_error_ind(http_async_t *ha, http_errtype_t error, void *val)
{
	http_async_check(ha);
	g_assert(ha->parent != NULL);
	g_assert(ha->parent->error_ind);

	(*ha->parent->error_ind)(ha->parent, error, val);
}

/**
 * Create a child request, to follow redirection transparently.
 *
 * All callbacks will be rerouted to the parent request, as if they came
 * from the original parent.
 *
 * @returns whether we succeeded in creating the subrequest.
 */
static bool
http_async_subrequest(
	http_async_t *parent, char *url, enum http_reqtype type)
{
	http_async_t *child;
	http_post_data_t post_data;
	http_post_data_t *post;;

	http_async_check(parent);

	/*
	 * We're installing our own callbacks to transparently reroute them
	 * to the user-supplied callbacks for the parent request, hence making
	 * the sub-request invisible from the outside.
	 */

	if (HTTP_POST == type) {
		post_data.content_type = parent->content_type;
		post_data.data = parent->data;
		post_data.datalen = parent->datalen;
		post_data.data_free = parent->data_free;
		post_data.data_free_arg = parent->data_free_arg;
		post = &post_data;
	} else {
		post = NULL;
	}

	child = http_async_create(url, zero_host_addr, 0, type, post,
		parent->header_ind ? http_subreq_header_ind : NULL,	/* Optional */
		parent->data_ind ? http_subreq_data_ind : NULL,		/* Optional */
		http_subreq_error_ind,
		parent);

	/*
	 * Propagate any redefined operation.
	 */

	child->op_get_request = parent->op_get_request;
	child->op_post_request = parent->op_post_request;
	child->op_headsent = parent->op_headsent;
	child->op_datasent = parent->op_datasent;
	child->op_gotreply = parent->op_gotreply;

	/*
	 * Indicate that the child request now has control, the parent request
	 * being only there to record the user's callbacks (and because it's the
	 * only one known from the outside).
	 */

	if (child)
		parent->flags |= HA_F_SUBREQ;

	return child != NULL;
}

/**
 * Redirect current HTTP request to some other URL.
 */
static void
http_redirect(http_async_t *ha, char *url)
{
	http_async_check(ha);

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

	socket_free_null(&ha->socket);
	http_async_newstate(ha, HTTP_AS_REDIRECTED);

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
	g_assert(ha->rx == NULL);		/* Have not started to read data */

	io_free(ha->io_opaque);
	ha->io_opaque = NULL;
}

/***
 *** RX link callbacks.
 ***/

static bool http_data_ind(rxdrv_t *rx, pmsg_t *mb);

static G_GNUC_PRINTF(2, 3) void
http_async_rx_error(void *o, const char *reason, ...)
{
	http_async_t *ha = o;
	va_list args;
	int saved_errno;

	http_async_check(ha);

	saved_errno = errno;

	if (GNET_PROPERTY(http_debug)) {
		char buf[128];

		va_start(args, reason);
		str_vbprintf(buf, sizeof buf, reason, args);
		va_end(args);
		g_warning("HTTP RX error from %s for \"%s\": %s",
			http_async_host(ha), ha->url, buf);
	}

	http_async_syserr(ha, saved_errno);
}

static void
http_async_rx_done(void *o)
{
	http_async_t *ha = o;

	http_async_check(ha);
	http_data_ind(ha->rx, NULL);	/* Signals EOF */
}

static const struct rx_link_cb http_async_rx_link_cb = {
	NULL,					/* add_rx_given */
	http_async_rx_error,	/* read_error */
	http_async_rx_done,		/* got_eof */
};

static const struct rx_chunk_cb http_async_rx_chunk_cb = {
	http_async_rx_error,	/* chunk_error */
	http_async_rx_done,		/* chunk_end */
};

static const struct rx_inflate_cb http_async_rx_inflate_cb = {
	NULL,					/* add_rx_inflated */
	http_async_rx_error,	/* read_error */
};

/***
 *** HTTP RX handling.
 ***/

/**
 * Tell the user that we got new data for his request.
 * If ``data'' is NULL, this is the last data we'll get (EOF reached).
 *
 * @return TRUE if we can continue reading data.
 */
static bool
http_got_data(http_async_t *ha, char *data, size_t len)
{
	http_async_check(ha);
	/* If not EOF, there must be data */
	g_assert(NULL == data || size_is_positive(len));

	ha->last_update = tm_time();
	(*ha->data_ind)(ha, data, len);

	if (ha->flags & HA_F_FREED)		/* Callback decided to cancel/close */
		return FALSE;

	if (NULL == data) {				/* EOF reached */
		http_async_free(ha);
		return FALSE;
	}

	return TRUE;
}

/**
 * Called when data are available on the RX stack.
 *
 * @return FALSE if an error occurred.
 */
static bool
http_data_ind(rxdrv_t *rx, pmsg_t *mb)
{
	http_async_t *ha = rx_owner(rx);
	bool ok;

	http_async_check(ha);

	if (NULL == mb)
		return http_got_data(ha, NULL, 0);

	ok = http_got_data(ha, pmsg_start(mb), pmsg_size(mb));
	pmsg_free(mb);

	return ok;
}

/**
 * Called when the whole server's reply header was parsed.
 */
static void
http_got_header(http_async_t *ha, header_t *header)
{
	struct gnutella_socket *s;
	const char *status;
	int ack_code;
	const char *ack_message = "";
	char *buf;
	uint http_major = 0, http_minor = 0;

	http_async_check(ha);

	s = ha->socket;
	status = getline_str(s->getline);

	/* Log HTTP headers */
	(*ha->op_gotreply)(ha, s, status, header);

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

	if (
		ha->header_ind &&
		!(*ha->header_ind)(ha, header, ack_code, ack_message)
	)
		return;

	/*
	 * Deal with return code.
	 */

	switch (ack_code) {
	case 200:					/* OK */
	case 202:					/* Accepted (for POST) */
		break;
	case 301:					/* Moved permanently */
	case 302:					/* Found */
	case 303:					/* See other */
	case 307:					/* Moved temporarily */
		if (!(ha->options & HTTP_O_REDIRECT)) {
			http_async_error(ha, HTTP_ASYNC_REDIRECTED);
			return;
		}

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
			if (GNET_PROPERTY(http_debug) > 2)
				g_debug("HTTP %s redirect %d (%s): \"%s\" -> \"%s\"",
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
		/*
		 * If they want to read the HTTP reply regardless of the error,
		 * then they must install an header_ind callback to grab the HTTP
		 * status code to be able to distinguish between genuine data and
		 * an error message.
		 */

		if (ha->options & HTTP_O_READ_REPLY)
			break;

		/*
		 * Otherwise (default behaviour, no reading on error), signal the
		 * unsucessful request and terminate operations.
		 */

		http_async_http_error(ha, header, ack_code, ack_message);
		return;
	}

	/*
	 * If there is no callback for data reception, we're done.
	 */

	if (ha->data_ind == NULL) {
		http_async_error(ha, HTTP_ASYNC_CLOSED);
		return;
	}

	/*
	 * Prepare reception of data.
	 */

	g_assert(s->gdk_tag == 0);
	g_assert(ha->rx == NULL);

	/*
	 * Lowest RX layer: the link level, doing network I/O.
	 */

	{
		struct rx_link_args args;
		gnet_host_t host;

		args.cb = &http_async_rx_link_cb;
		args.bws = bsched_in_select_by_addr(s->addr);
		args.wio = &s->wio;
		gnet_host_set(&host, s->addr, s->port);

		ha->rx = rx_make(ha, &host, rx_link_get_ops(), &args);
	}

	/*
	 * Transport encoding: the dechunking layer is right above the
	 * link level and removes chunk marks, providing a stream of bytes
	 * to upper level.
	 */

	buf = header_get(header, "Transfer-Encoding");
	if (buf != NULL && 0 == strcmp(buf, "chunked")) {
		struct rx_chunk_args args;

		args.cb = &http_async_rx_chunk_cb;

		ha->rx = rx_make_above(ha->rx, rx_chunk_get_ops(), &args);
	}

	/*
	 * Decompressing layer: if server is sending compressed data, the
	 * inflating layer provides a stream of decompressed bytes to upper
	 * level.
	 */

	buf = header_get(header, "Content-Encoding");
	if (buf != NULL && 0 == strcmp(buf, "deflate")) {
		struct rx_inflate_args args;

		args.cb = &http_async_rx_inflate_cb;

		ha->rx = rx_make_above(ha->rx, rx_inflate_get_ops(), &args);
	}

	/*
	 * Ready to receive using the RX stack.
	 */

	rx_set_data_ind(ha->rx, http_data_ind);
	rx_enable(ha->rx);

	http_async_newstate(ha, HTTP_AS_RECEIVING);

	/*
	 * We may have something left in the input buffer.
	 * Give them the data immediately.
	 */

	if (s->pos > 0) {
		pdata_t *db;
		pmsg_t *mb;

		/*
		 * Prepare data buffer out of the socket's buffer.
		 */

		db = pdata_allocb_ext(s->buf, s->pos, pdata_free_nop, NULL);
		mb = pmsg_alloc(PMSG_P_DATA, db, 0, s->pos);
		s->pos = 0;

		/*
		 * The message is given to the RX stack, and it will be freed by
		 * the last function consuming it.
		 */

		rx_recv(rx_bottom(ha->rx), mb);
	}
}

/**
 * Get the state of the HTTP request.
 */
http_state_t
http_async_state(http_async_t *ha)
{
	http_async_check(ha);

	/*
	 * Special-case redirected request: they have at least one child.
	 * @return the state of the first active child we get.
	 */

	if (ha->state == HTTP_AS_REDIRECTED) {
		GSList *l;

		g_assert(ha->children);

		for (l = ha->children; l; l = g_slist_next(l)) {
			http_async_t *cha = l->data;

			switch (cha->state) {
			case HTTP_AS_REDIRECTED:
			case HTTP_AS_REMOVED:
				break;
			default:
				return cha->state;
			}
		}

		return HTTP_AS_UNKNOWN;		/* Weird */
	}

	return ha->state;
}

/***
 *** HTTP header parsing dispatching callbacks.
 ***/

/**
 * Called when full header was collected.
 */
static void
call_http_got_header(void *obj, header_t *header)
{
	http_async_t *ha = obj;

	http_async_check(ha);
	http_got_header(ha, header);
}

static struct io_error http_io_error;

/**
 * Called when we start receiving the HTTP headers.
 */
static void
http_header_start(void *obj)
{
	http_async_t *ha = obj;

	http_async_check(ha);
	http_async_newstate(ha, HTTP_AS_HEADERS);
}

/**
 * Called when the whole HTTP request has been sent out.
 */
static void
http_async_request_sent(http_async_t *ha)
{
	http_async_check(ha);

	http_async_newstate(ha, HTTP_AS_REQ_SENT);

	/*
	 * Prepare to read back the status line and the headers.
	 */

	g_assert(ha->io_opaque == NULL);

	io_get_header(ha, &ha->io_opaque, BSCHED_BWS_IN, ha->socket,
		IO_SAVE_FIRST, call_http_got_header, http_header_start, &http_io_error);
}

/**
 * I/O callback invoked when we can write more data to the server to finish
 * sending the HTTP request.
 */
static void
http_async_write_request(void *data, int unused_source,
	inputevt_cond_t cond)
{
	http_async_t *ha = data;
	struct gnutella_socket *s;
	http_buffer_t *r;
	ssize_t sent;
	size_t rw;
	char *base;

	(void) unused_source;

	http_async_check(ha);
	g_assert(ha->delayed != NULL);
	g_assert(ha->state == HTTP_AS_REQ_SENDING);

	s = ha->socket;

next_buffer:

	r = ha->delayed->data;

	http_buffer_check(r);

	if (cond & INPUT_EVENT_EXCEPTION) {
		socket_eof(s);
		http_async_error(ha, HTTP_ASYNC_IO_ERROR);
		return;
	}

	rw = http_buffer_unread(r);			/* Data we still have to send */
	base = http_buffer_read_base(r);	/* And where unsent data start */

	sent = bws_write(BSCHED_BWS_OUT, &s->wio, base, rw);
	if ((ssize_t) -1 == sent) {
		g_warning("HTTP request sending to %s failed: %m",
			host_addr_port_to_string(s->addr, s->port));
		http_async_syserr(ha, errno);
		return;
	} else if ((size_t) sent < rw) {
		http_buffer_add_read(r, sent);
		return;
	} else {
		if (!ha->header_sent) {
			ha->header_sent = TRUE;

			/* Log HTTP request header sent so far */
			(*ha->op_headsent)(ha, s,
				http_buffer_base(r), http_buffer_length(r), TRUE);
		} else {
			/* Log HTTP data sent so far */
			(*ha->op_datasent)(ha, s,
				http_buffer_base(r), http_buffer_length(r), TRUE);
		}

		g_assert(ha->header_sent);

		/*
		 * Current buffer was completely sent out, move to the next buffer
		 * to complete the request if there are more buffers available,
		 * which is the case for POST requests where the second buffer
		 * holds the data.
		 */

		ha->delayed = g_slist_next(ha->delayed);
		if (ha->delayed != NULL) {
			http_buffer_free(r);
			goto next_buffer;
		}
	}

	/*
	 * HTTP request was completely sent (header + data for POST).
	 */

	if (GNET_PROPERTY(http_debug))
		g_warning("flushed partially written HTTP request to %s (%d bytes)",
			host_addr_port_to_string(s->addr, s->port),
			http_buffer_length(r));

	socket_evt_clear(s);

	http_buffer_free(r);
	ha->delayed = NULL;

	http_async_request_sent(ha);
}

/**
 * Callback from the socket layer when the connection to the remote
 * server is made.
 */
static void
http_async_connected(http_async_t *ha)
{
	struct gnutella_socket *s;
	size_t rw;
	ssize_t sent;
	char req[2048];

	http_async_check(ha);

	s = ha->socket;
	socket_check(s);

	/*
	 * Build the HTTP request.
	 */

	if (HTTP_POST == ha->type) {
		rw = (*ha->op_post_request)(ha, req, sizeof(req),
			(char *) http_verb[ha->type], ha->path,
			ha->content_type, ha->datalen);
	} else {
		rw = (*ha->op_get_request)(ha, req, sizeof(req),
			(char *) http_verb[ha->type], ha->path);
	}

	if (rw >= sizeof(req)) {
		http_async_error(ha, HTTP_ASYNC_REQ2BIG);
		return;
	}

	/*
	 * Send the HTTP request header.
	 */

	http_async_newstate(ha, HTTP_AS_REQ_SENDING);

	sent = bws_write(BSCHED_BWS_OUT, &s->wio, req, rw);

	if ((ssize_t) -1 == sent) {
		g_warning("HTTP request sending to %s failed: %m",
			host_addr_port_to_string(s->addr, s->port));
		http_async_syserr(ha, errno);
		return;
	} else if ((size_t) sent < rw) {
		http_buffer_t *r;

		g_warning("partial HTTP request write to %s: only %d of %d bytes sent",
			host_addr_port_to_string(s->addr, s->port), (int) sent, (int) rw);

		g_assert(ha->delayed == NULL);

		r = http_buffer_alloc(req, rw, sent);
		ha->delayed = g_slist_append(ha->delayed, r);

		/*
		 * For a POST we also have to send the data following the header.
		 */

		if (HTTP_POST == ha->type && ha->datalen != 0) {
			r = http_buffer_alloc(ha->data, ha->datalen, 0);
			ha->delayed = g_slist_append(ha->delayed, r);
		}

		/*
		 * Install the writing callback.
		 */

		socket_evt_set(s, INPUT_EVENT_WX, http_async_write_request, ha);
		return;
	} else {
		ha->header_sent = TRUE;

		/* Log HTTP request header */
		(*ha->op_headsent)(ha, s, req, rw, FALSE);
	}

	/*
	 * For a POST we also have to send the data following the header.
	 */

	if (HTTP_POST == ha->type && ha->datalen != 0) {
		sent = bws_write(BSCHED_BWS_OUT, &s->wio, ha->data, ha->datalen);

		if ((ssize_t) -1 == sent) {
			g_warning("HTTP data sending to %s failed: %m",
				host_addr_port_to_string(s->addr, s->port));
			http_async_syserr(ha, errno);
			return;
		} else if ((size_t) sent < ha->datalen) {
			http_buffer_t *r;

			g_warning("partial HTTP data write to %s: "
				"only %zu of %zu bytes sent",
				host_addr_port_to_string(s->addr, s->port),
				sent, ha->datalen);

			g_assert(ha->delayed == NULL);

			r = http_buffer_alloc(ha->data, ha->datalen, sent);
			ha->delayed = g_slist_append(ha->delayed, r);

			/*
			 * Install the writing callback.
			 */

			socket_evt_set(s, INPUT_EVENT_WX, http_async_write_request, ha);
			return;
		} else {
			/* Log HTTP request data */
			(*ha->op_datasent)(ha, s, ha->data, ha->datalen, FALSE);
		}
	}

	/*
	 * Both HTTP request header and possible data have been sent.
	 */

	http_async_request_sent(ha);
}

/**
 * Error indication callback which logs the error by listing the
 * initial HTTP request and the reported error cause.  The specified
 * debugging level is explicitly given.
 *
 * @param handle		the asynchronous HTTP request
 * @param type			the error type, as reported to the error callback
 * @param v				the opaque error description from error callback
 * @param prefix		logging prefix to be inserted in logging messages
 * @param all			if TRUE, also log explicit user cancels
 *
 * If no prefix is supplied, "HTTP" is used.
 *
 * @return TRUE if anything was logged.
 */
bool
http_async_log_error_dbg(http_async_t *handle,
	http_errtype_t type, void *v, const char *prefix, bool all)
{
	const char *url;
	const char *req;
	int error = GPOINTER_TO_INT(v);
	http_error_t *herror = v;
	host_addr_t addr;
	uint16 port;
	const char *what = prefix != NULL ? prefix : "HTTP";

	http_async_check(handle);

	url = http_async_info(handle, &req, NULL, &addr, &port);

	switch (type) {
	case HTTP_ASYNC_SYSERR:
		errno = error;
		g_message("%s: aborting \"%s %s\" at %s on system error: %m",
			what, req, url, host_addr_port_to_string(addr, port));
		return TRUE;
	case HTTP_ASYNC_ERROR:
		if (error == HTTP_ASYNC_CANCELLED) {
			if (all) {
				g_message("%s: explicitly cancelled \"%s %s\" at %s",
					what, req, url, host_addr_port_to_string(addr, port));
				return TRUE;
			}
		} else if (error == HTTP_ASYNC_CLOSED) {
			if (all) {
				g_message("%s: connection closed for \"%s %s\" at %s",
					what, req, url, host_addr_port_to_string(addr, port));
				return TRUE;
			}
		} else {
			g_message("%s: aborting \"%s %s\" at %s on error: %s",
				what, req, url,
				host_addr_port_to_string(addr, port),
				http_async_strerror(error));
			return TRUE;
		}
		return FALSE;
	case HTTP_ASYNC_HEADER:
		g_message("%s: aborting \"%s %s\" at %s on header parsing error: %s",
			what, req, url, host_addr_port_to_string(addr, port),
			header_strerror(error));
		return TRUE;
	case HTTP_ASYNC_HTTP:
		g_message("%s: stopping \"%s %s\" at %s: HTTP %d %s",
			what, req, url,
			host_addr_port_to_string(addr, port),
			herror->code, herror->message);
		return TRUE;
	/* No default clause, let the compiler warn us about missing cases. */
	}

	/* In case the error was not trapped at compile time... */
	g_error("unhandled HTTP request error type %d", type);
	/* NOTREACHED */
	return FALSE;	/* Avoid compiler warnings about missing returned value */
}

/**
 * Default error indication callback which logs the error by listing the
 * initial HTTP request and the reported error cause.
 *
 * @return whether anything was logged.
 */
bool
http_async_log_error(http_async_t *handle,
	http_errtype_t type, void *v, const char *prefix)
{
	if (GNET_PROPERTY(http_debug)) {
		return http_async_log_error_dbg(handle, type, v, prefix,
			GNET_PROPERTY(http_debug) >= 4);
	}

	return FALSE;
}

/***
 *** Higher-level API to get whole content.
 ***/

enum http_wget_magic { HTTP_WGET_MAGIC = 0x22e19f43U };

/**
 * Additional context for wget requests.
 */
typedef struct http_wget {
	enum http_wget_magic magic;		/**< magic */
	http_async_t *ha;			/**< HTTP asynchronous request */
	http_wget_cb_t cb;				/**< User callback to invoke when done */
	header_t *header;				/**< HTTP reply header */
	void *arg;						/**< User argument for callback */
	char *data;						/**< Collected data */
	size_t maxlen;					/**< Maximum allowed data length */
	size_t len;						/**< Length of collected data */
	size_t content_len;				/**< Promised length, maxlen if none */
	size_t datasize;				/**< Size of allocated buffer for data */
	int code;						/**< HTTP status code */
} http_wget_t;

static inline void
http_wget_check(const http_wget_t * const wg)
{
	g_assert(NULL != wg);
	g_assert(HTTP_WGET_MAGIC == wg->magic);
}

/**
 * Free http_wget_t object.
 */
static void
http_wget_free(void *data)
{
	http_wget_t *wg = data;

	http_wget_check(wg);

	HFREE_NULL(wg->data);
	header_free_null(&wg->header);
	WFREE(wg);
}

/**
 * Callback for http_async_wget(), invoked when all headers have been read.
 * @return TRUE if we can continue with the request.
 */
static bool
wget_header_ind(http_async_t *ha, struct header *header,
	int code, const char *unused_message)
{
	http_wget_t *wg = http_async_get_opaque(ha);
	const char *buf;

	http_wget_check(wg);
	(void) unused_message;

	/*
	 * Save HTTP status code and headers so that they can be given to
	 * the completion callback.
	 */

	wg->code = code;
	wg->header = header_refcnt_inc(header);

	/*
	 * Make sure they're not returning content that is larger than the
	 * maximum size we're willing to handle.
	 *
	 * Note that the Content-Length header may be missing if the server
	 * is returning chunked output, in which case we will have to dynamically
	 * adjust the reception buffer size.
	 */

	buf = header_get(header, "Content-Length");
	if (buf != NULL) {
		uint64 len;
		int error;

		len = parse_uint64(buf, NULL, 10, &error);
		if (error) {
			if (GNET_PROPERTY(http_debug)) {
				g_warning("HTTP cannot parse Content-Length header "
					"from %s for \"%s\": value is \"%s\"",
					http_async_host(ha), ha->url, buf);
			}
			http_async_error(ha, HTTP_ASYNC_BAD_HEADER);
			return FALSE;
		}

		if (len > wg->maxlen) {
			http_async_error(ha, HTTP_ASYNC_DATA2BIG);
			return FALSE;
		}

		wg->content_len = len;
	}

	/*
	 * If they advertised a content length, allocate the appropriate buffer
	 * to hold it.  Otherwise, allocate 1/16th of the maximum size: each
	 * time we resize we'll double the size of the buffer, so there will
	 * be at most 4 resize operations.
	 */

	wg->datasize = (buf != NULL) ? wg->content_len : (wg->maxlen >> 4);
	wg->data = halloc(wg->datasize);

	return TRUE;
}

/**
 * Callback for http_async_wget(), invoked when new HTTP payload data is read.
 * When data is NULL, it indicates an EOF condition.
 */
static void
wget_data_ind(http_async_t *ha, char *data, int len)
{
	http_wget_t *wg = http_async_get_opaque(ha);
	size_t new_length;

	http_wget_check(wg);

	if (NULL == data) {
		char *result;

		/*
		 * Reached EOF, we're done.  User becomes the owner of the data now.
		 */

		result = wg->data;
		wg->data = NULL;			/* So we don't free it ourselves */
		(*wg->cb)(result, wg->len, wg->code, wg->header, wg->arg);
		return;
	}

	/*
	 * Ensure there is enough room in the buffer to grab the new data.
	 */

	new_length = size_saturate_add(wg->len, len);

	if (new_length > wg->content_len) {
		http_async_error(ha, HTTP_ASYNC_DATA2BIG);
		return;
	}

	if (new_length > wg->datasize) {
		size_t new_size = size_saturate_mult(wg->datasize, 2);

		wg->data = hrealloc(wg->data, new_size);
		wg->datasize = new_size;
	}

	/*
	 * Append new data to the one we already got.
	 */

	memcpy(&wg->data[wg->len], data, len);
	wg->len = new_length;
}

/**
 * Callback for http_async_wget(), invoked on errors.
 */
static void
wget_error_ind(http_async_t *ha, http_errtype_t type, void *val)
{
	http_wget_t *wg = http_async_get_opaque(ha);

	http_wget_check(wg);

	http_async_log_error(ha, type, val, "HTTP wget");

	if (
		type == HTTP_ASYNC_ERROR &&
		GPOINTER_TO_INT(val) == HTTP_ASYNC_CANCELLED
	)
		return;		/* Don't invoke any callback on explicit user cancel */

	(*wg->cb)(NULL, 0, wg->code, wg->header, wg->arg);	/* Signal error */
}

/**
 * Asynchronously fetch the given URL, grabbing all the data into a memory
 * buffer and invoking the supplied callback when done.
 *
 * @param url		the URL to retrieve
 * @param maxlen	maximum data length we accept to allocate and grab
 * @param cb		callback to invoked on completion / error
 * @param arg		user-defined value, passed as-is to callback
 *
 * @return an asynchronous HTTP handle on success, NULL if we were not able
 * to launch the request (in which case the callback is not invoked and
 * http_async_errno is set to indicate the error).
 */
http_async_t *
http_async_wget(const char *url, size_t maxlen, http_wget_cb_t cb, void *arg)
{
	http_async_t *ha;

	ha = http_async_get(url, wget_header_ind, wget_data_ind, wget_error_ind);

	if (ha != NULL) {
		http_wget_t *wg;

		WALLOC0(wg);
		wg->magic = HTTP_WGET_MAGIC;
		wg->ha = ha;
		wg->maxlen = maxlen;
		wg->content_len = maxlen;	/* Until we see a Content-Length header */
		wg->cb = cb;
		wg->arg = arg;
		http_async_set_opaque(ha, wg, http_wget_free);
	}

	return ha;
}

/**
 * Parse buffer for HTTP status line and headers.
 *
 * This is meant to be used by HTTP over UDP, to parse the HTTP reply
 * held in the datagram.
 *
 * @param data		the data to parse
 * @param len		length of data
 * @param code		if non-NULL, filled with HTTP status code
 * @param msg		if non-NULL, filled with halloc()'ed status message
 * @param major		if non-NULL, filled with HTTP major version
 * @param minor		if non-NULL, filled with HTTP minor version
 * @param endptr	if non-NULL, filled with first unparsed character in data
 *
 * @return NULL on error, the parsed header object that must be reclaimed
 * with header_free() when done.
 */
header_t *
http_header_parse(const char *data, size_t len, int *code, char **msg,
	unsigned *major, unsigned *minor, const char **endptr)
{
	getline_t *gl;
	const char *p = data;
	size_t remain = len;
	size_t parsed;
	header_t *h = NULL;
	int ack_code;
	const char *ack_msg = NULL;
	int error;

	gl = getline_make(MAX_LINE_SIZE);

	/*
	 * First line is the HTTP status line, e.g. "HTTP/1.1 200 OK"
	 */

	switch (getline_read(gl, p, remain, &parsed)) {
	case READ_OVERFLOW:
	case READ_MORE:
		goto failed;
	case READ_DONE:
		g_assert(parsed <= remain);
		p += parsed;
		remain -= parsed;
		break;
	}

	/*
	 * Analyze status message.
	 */

	ack_code = http_status_parse(getline_str(gl), "HTTP",
		&ack_msg, major, minor);

	if (-1 == ack_code)
		goto failed;

	if (code != NULL)
		*code = ack_code;
	if (msg != NULL)
		*msg = h_strdup(ack_msg);

	/*
	 * We parsed the status line, now grab the header.
	 */

	h = header_make();
	getline_reset(gl);

nextline:
	switch (getline_read(gl, p, remain, &parsed)) {
	case READ_OVERFLOW:
	case READ_MORE:
		goto failed;
	case READ_DONE:
		g_assert(parsed <= remain);
		p += parsed;
		remain -= parsed;
		break;
	}

	error = header_append(h, getline_str(gl), getline_length(gl));

	switch (error) {
	case HEAD_OK:
		getline_reset(gl);
		goto nextline;
	case HEAD_EOH:				/* Reached the end of the header */
		break;
	default:
		goto failed;
	}

	/*
	 * All done, successfully parsed.
	 */

	if (endptr != NULL)
		*endptr = p;

	getline_free(gl);

	return h;		/* Caller will have to invoke header_free() */

	/*
	 * Parsing failed, somehow.
	 */

failed:
	if (h != NULL)
		header_free(h);
	if (gl != NULL)
		getline_free(gl);
	if (msg != NULL && ack_msg != NULL) {
		hfree(*msg);
		*msg = NULL;
	}

	return NULL;
}

/***
 *** I/O header parsing callbacks.
 ***/

static void
err_line_too_long(void *obj, header_t *unused_head)
{
	http_async_t *ha = obj;
	(void) unused_head;
	http_async_check(ha);
	http_async_error(ha, HTTP_ASYNC_HEAD2BIG);
}

static void
err_header_error(void *obj, int error)
{
	http_async_t *ha = obj;
	http_async_check(ha);
	http_async_headerr(ha, error);
}

static void
err_input_exception(void *obj, header_t *unused_head)
{
	http_async_t *ha = obj;
	(void) unused_head;
	http_async_check(ha);
	http_async_error(ha, HTTP_ASYNC_IO_ERROR);
}

static void
err_input_buffer_full(void *obj)
{
	http_async_t *ha = obj;
	http_async_check(ha);
	http_async_error(ha, HTTP_ASYNC_IO_ERROR);
}

static void
err_header_read_error(void *obj, int error)
{
	http_async_t *ha = obj;
	http_async_check(ha);
	http_async_syserr(ha, error);
}

static void
err_header_read_eof(void *obj, header_t *unused_head)
{
	http_async_t *ha = obj;
	(void) unused_head;
	http_async_check(ha);
	http_async_error(ha, HTTP_ASYNC_EOF);
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

/**
 * Called from main timer to expire HTTP requests that take too long.
 */
void
http_timer(time_t now)
{
	GSList *l;

retry:
	for (l = sl_outgoing; l; l = l->next) {
		http_async_t *ha = l->data;
		int elapsed = delta_time(now, ha->last_update);
		int timeout = ha->rx
			? GNET_PROPERTY(download_connected_timeout)
			: GNET_PROPERTY(download_connecting_timeout);

		if (ha->flags & HA_F_SUBREQ)
			continue;

		if (elapsed > timeout) {
			switch (ha->state) {
			case HTTP_AS_UNKNOWN:
			case HTTP_AS_CONNECTING:
				http_async_error(ha, HTTP_ASYNC_CONN_TIMEOUT);
				goto retry;
			case HTTP_AS_REMOVED:
				g_error("removed async request should not be listed");
				break;
			default:
				http_async_error(ha, HTTP_ASYNC_TIMEOUT);
				goto retry;
			}
		}
	}

	/*
	 * Dispose of the logically freed structures, asynchronously.
	 */

	if (sl_ha_freed)
		http_async_free_pending();
}

/**
 * Shutdown the HTTP module.
 */
void
http_close(void)
{
	while (sl_outgoing)
		http_async_error(sl_outgoing->data, HTTP_ASYNC_CANCELLED);
}

/***
 *** HTTP asynchronous fetching logic test.
 ***/

#ifdef HTTP_TESTING
static G_GNUC_COLD void
http_transaction_failed(char *data, size_t len, int code, header_t *h, void *a)
{
	const char *url = a;

	(void) h;

	if (NULL == data) {
		g_message("HTTP expected-to-fail wget of \"%s\" OK (HTTP %d)",
			url, code);
	} else {
		g_warning("HTTP expected-to-fail wget of \"%s\" FAILED: got %zu bytes",
			url, len);
	}
}

static G_GNUC_COLD void
http_transaction_done(char *data, size_t len, int code, header_t *h, void *arg)
{
	char *url = arg;

	if (NULL == data) {
		g_warning("HTTP async wget of \"%s\" FAILED (HTTP %d)", url, code);
	} else {
		void *ha;

		g_message("HTTP async wget of \"%s\" SUCCEEDED (%zu byte%s)",
			url, len, 1 == len ? "" : "s");
		g_debug("---- Begin HTTP Header ----");
		header_dump(stderr, h, NULL);
		g_debug("---- End HTTP Header ----");
		g_debug("---- Begin HTTP Payload ----");
		write(STDERR_FILENO, data, len);
		g_debug("---- End HTTP Payload ----");
		hfree(data);

		ha = http_async_wget(url, len / 2, http_transaction_failed, url);
		if (NULL == ha) {
			g_warning("HTTP cannot start second wget of \"%s\": %s",
				url, http_async_strerror(http_async_errno));
		} else {
			g_info("HTTP expected-to-fail wget \"%s\" started", url);
		}
	}
}

static G_GNUC_COLD void
http_async_test(void)
{
	void *ha;
	char *url = "http://www.perl.com/index.html";

	g_message("HTTP starting async wget of \"%s\"", url);

	ha = http_async_wget(url, 500000, http_transaction_done, url);
	if (NULL == ha) {
		g_warning("HTTP cannot start wget of \"%s\": %s",
			url, http_async_strerror(http_async_errno));
	} else {
		g_info("HTTP wget \"%s\" started", url);
	}
}
#else	/* !HTTP_TESTING */
static G_GNUC_COLD void
http_async_test(void)
{
	/* Nothing */
}
#endif	/* HTTP_TESTING */

G_GNUC_COLD void
http_test(void)
{
	http_async_test();
	http_range_test();
}

/* vi: set ts=4 sw=4 cindent: */
