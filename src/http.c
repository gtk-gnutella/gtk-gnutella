/*
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>

#include "http.h"
#include "appconfig.h"
#include "sockets.h"
#include "bsched.h"
#include "misc.h"

/*
 * http_send_status
 *
 * Send HTTP status on socket, with code and reason.
 *
 * If `hev' is non-null, it points to a vector of http_extra_desc_t items,
 * containing `hevcnt' entries.  Each entry describes something to be
 * inserted in the header.
 *
 * The connection is NOT closed.
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

	va_start(args, reason);
	g_vsnprintf(status_msg, sizeof(status_msg)-1,  reason, args);
	va_end(args);

	rw = g_snprintf(header, sizeof(header),
		"HTTP/1.0 %d %s\r\n"
		"Server: %s\r\n"
		"Connection: close\r\n"
		"X-Live-Since: %s\r\n",
		code, status_msg, version_string, start_rfc822_date);

	mrw = rw;		/* Minimal header length */

	/*
	 * Append extra information to the minimal header created above.
	 */

	for (i = 0; i < hevcnt && rw < sizeof(header); i++) {
		http_extra_desc_t *he = &hev[i];
		http_extra_type_t type = he->he_type;

		switch (type) {
		case HTTP_EXTRA_LINE:
			rw += g_snprintf(&header[rw], sizeof(header) - rw,
				"%s", he->he_msg);
			break;
		case HTTP_EXTRA_CALLBACK:
			{
				gint len = sizeof(header) - rw;
				
				(*he->he_cb)(&header[rw], &len, he->he_arg);

				g_assert(len + rw <= sizeof(header));

				rw += len;
			}
			break;
		}
	}

	if (rw < sizeof(header))
		rw += g_snprintf(&header[rw], sizeof(header) - rw, "\r\n");

	if (rw >= sizeof(header) && hev) {
		g_warning("HTTP status %d (%s) too big, ignoring extra information",
			code, reason);

		rw = mrw + g_snprintf(&header[mrw], sizeof(header) - mrw, "\r\n");
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
	} else if (dbg > 4) {
		printf("----Sent HTTP Status to %s:\n%.*s----\n",
			ip_to_gchar(s->ip), rw, header);
		fflush(stdout);
	}

	return TRUE;
}

/***
 *** HTTP status parsing.
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
	gchar *p;
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
	gchar *p;

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

