/*
 * Copyright (c) 2003, Jeroen Asselman & Raphael Manfredi
 *
 * Passive/Active Remote Queuing.
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

#include "common.h"		/* For -DUSE_DMALLOC */

#include "parq.h"
#include "ioheader.h"
#include "sockets.h"
#include "gnutella.h"

RCSID("$Id$");

#define PARQ_RETRY_SAFETY	40		/* 40 seconds before lifetime */
#define PARQ_TIMER_BY_POS	30		/* 30 seconds for each queue position */

/*
 * get_header_version
 * 
 * Extract the version from a given header. EG:
 * X-Queue: 1.0
 * major=1 minor=0
 */
static gboolean get_header_version(gchar const *const header, 
								gint *major, gint *minor)
{
	return sscanf(header, ": %d.%d", major, minor) != 0;
}

/* 
 * get_header_value
 *
 * Retreives a value from a header line. If possible the length (in gchars)
 * is returned for that value.
 */
static gchar *get_header_value(
	gchar *const s, gchar const *const attribute, gint *length)
{
	gchar *lowercase_header = s;
	gchar *end;
	gboolean found_right_attribute = FALSE;
	gboolean found_equal_sign = FALSE;
	size_t attrlen;
	gchar e;
	gchar b;
	gchar es;
	
	
	g_assert(s != NULL);
	g_assert(attribute != NULL);

	attrlen = strlen(attribute);

	/*
	 * When we are looking for "foo", make sure we aren't actually
	 * parsing "barfoobar". There should be at least a space, or a
	 * delimiter at the end and at the beginning.
	 */

	do {
		lowercase_header = strcasestr(lowercase_header, attribute);
		
		if (lowercase_header == NULL)
			return NULL;

		e = lowercase_header[attrlen];		/* End char after attribute */
		
		if (lowercase_header == s) {
			/*
			 * This is actually the first value of the header. And it
			 * started at position '0'. Which is the same as were
			 * s pointed too. Only check to see if the end is correct
			 */

			found_right_attribute = e == ' ' || e == '=' || e == '\0';
		} else {
			b = *(lowercase_header - 1);	/* Character before attribute */
			found_right_attribute = (
					b == ';' || b == ',' || b == ':' || b == ' '
				) && (
					e == ' ' || e == '=' || e == '\0'
				);
		}

		/* 
		 * If we weren't looking at the right value. Move on to the next.
		 * If there are no valid values, the while loop will abort with 
		 * lowercase_header == NULL
		 * If we did find a valid position we want to make sure the next
		 * char is an '='. So we need to move ahead anyway.
		 */
		
		lowercase_header += attrlen;
		
		if (found_right_attribute) {
			
			/*
			 * OK, so we found a possible valid attribute. Now make sure the
			 * first character is an '=', ignoring white spaces.
			 * If we don't, we didn't find a valid attribute.
			 */
			
			es = *lowercase_header;
			
			do {
				found_right_attribute = es == '=' || es == ' ' || es == '\0';
				found_equal_sign = es == '=';
								
				if (!found_equal_sign)
					es = *(++lowercase_header);		/* Skip spaces */
				
			} while (!found_equal_sign && found_right_attribute && es != '\0');

			/*
			 * If we did not find the right attribute, it means we did not
			 * encounter an '=' sign before the start of the next attribute
			 * or the end of the string.
			 *
			 * For instance, we stumbled on `var2' in:
			 *
			 *   var1 = foo; var2 ; var3=bar
			 *
			 * Clearly, this is incorrect for our purposes, as all attributes
			 * are expected to have a value.
			 */

			g_assert(!found_equal_sign || found_right_attribute);

			if (!found_right_attribute) {
				g_assert(!found_equal_sign);
				g_warning("attribute '%s' has no value in string: %s",
					attribute, s);
			}
		}		
	} while (!found_right_attribute);	
	
	g_assert(lowercase_header != NULL);
	g_assert(found_equal_sign);
	g_assert(*lowercase_header == '=');
	
	lowercase_header++;			/* Skip the '=' sign */

	/*
	 * If we need to compute the length of the attribute's value, look for
	 * the next trailing delimiter (';' or ',').
	 */
	
	if (length != NULL) {
		*length = 0;

		end = strchr(lowercase_header, ';');		/* PARQ style */
		if (end == NULL)
			end = strchr(lowercase_header, ',');	/* Active queuing style */

		/* 
		 * If we couldn't find a delimiter, then this value is the last one.
		 */

		*length = (end == NULL) ?
			strlen(lowercase_header) : end - lowercase_header;
	}

	return lowercase_header;
}

/*
 * parq_download_retry_active_queued
 *
 * Active queued means we didn't close the http connection on a HTTP 503 busy
 * when the server supports queueing. So prepare the download structure
 * for a 'valid' segment. And re-request the segment.
 */
void parq_download_retry_active_queued(struct download *d)
{
	g_assert(d != NULL);
	g_assert(d->socket != NULL);
	g_assert(d->status == GTA_DL_ACTIVE_QUEUED);
	g_assert(parq_download_is_active_queued(d));
	
	if (download_start_prepare_running(d)) {
		struct gnutella_socket *s = d->socket;
		d->keep_alive = TRUE;			/* was reset in start_prepare_running */
		
 		/* Will be re initialised in download_send_request */
		io_free(d->io_opaque);
		d->io_opaque = NULL;
		getline_free(s->getline);		/* No longer need this */
		s->getline = NULL;

		/* Resend request for download */
		download_send_request(d);
	}
}
	
/*
 * get_integer
 *
 * Convenience wrapper on top of strtoul().
 * Returns parsed integer (base 10), or 0 if none could be found.
 */
static gint get_integer(gchar *buf)
{
	glong val;
	gchar *end;

	/* XXX This needs to get more parameters, so that we can log the
	 * XXX problem if we cannot parse, or if the value does not fit.
	 * XXX We probably need the download structure, and the name of
	 * XXX the field being parsed, with the header line as well.
	 * XXX	--RAM, 02/02/2003.
	 */

	val = strtoul(buf, &end, 10);
	if (end == buf)
		return 0;

	if (val > INT_MAX)
		val = INT_MAX;

	return (gint) val;
}

/*
 * parq_download_parse_queue_status
 *
 * Retrieve and parse queueing information.
 * Returns TRUE if we parsed it OK, FALSE on error.
 */
gboolean parq_download_parse_queue_status(struct download *d, header_t *header)
{	
	gchar *buf;
	gchar *value;
	gint major, minor;
	gint header_value_length;
	gint retry;

	g_assert(d != NULL);
	g_assert(header != NULL);

	buf = header_get(header, "X-Queue");
	
	if (buf == NULL)			/* Remote server does not support queues */
		return FALSE;

	if (!get_header_version(buf, &major, &minor)) {
		/*
		 * Could not retreive queueing version. It could be 0.1 but there is no
		 * way to tell for certain
		 */
		major = 0;
		minor = 1;
	}
	
	d->server->parq_version.major = major;
	d->server->parq_version.minor = minor;
	
	switch (major) {
	case 0:				/* Active queueing */		
		d->queue_status.ID[0] = '\0';

		value = get_header_value(buf, "pollMin", NULL);
		d->queue_status.retry_delay  = value == NULL ? 0 : get_integer(value);
		
		value = get_header_value(buf, "pollMax", NULL);
		d->queue_status.lifetime  = value == NULL ? 0 : get_integer(value);
		break;
	case 1:				/* PARQ */
		buf = header_get(header, "X-Queued");

		if (buf == NULL) {
			g_warning("host %s advertised PARQ %d.%d but did not send X-Queued",
				ip_port_to_gchar(download_ip(d), download_port(d)),
				major, minor);
			if (dbg) {
				g_warning("header dump:");
				header_dump(header, stderr);
			}
			return FALSE;
		}

		value = get_header_value(buf, "lifetime", NULL);
		d->queue_status.lifetime = value == NULL ? 0 : get_integer(value);

		d->queue_status.retry_delay = extract_retry_after(header);

		value = get_header_value(buf, "ID", &header_value_length);
		header_value_length = MIN(header_value_length, PARQ_MAX_ID_LENGTH);
		strncpy(d->queue_status.ID, value, header_value_length);
		break;
	default:
		g_warning("unhandled queuing version %d.%d from %s <%s>",
			major, minor, ip_port_to_gchar(download_ip(d), download_port(d)),
			download_vendor_str(d));
		return FALSE;
	}

	value = get_header_value(buf, "position", NULL);
	d->queue_status.position = value == NULL ? 0 : get_integer(value);
	
	value = get_header_value(buf, "length", NULL);
	d->queue_status.length   = value == NULL ? 0 : get_integer(value);
				
	value = get_header_value(buf, "ETA", NULL);
	d->queue_status.ETA  = value == NULL ? 0 : get_integer(value);

	/*
	 * If we're not in the first position, lower our retry rate.
	 * We try to retry every 60 seconds when in position 2, every 90 in
	 * position 3, and so on.  If we fall out of range, adjust: we must not
	 * poll before the minimum specified by `retry_delay', and we try to
	 * poll again at least 40 seconds before `lifetime' to avoid being
	 * kicked out.
	 *		--RAM, 22/02/2003
	 */

	retry = d->queue_status.position * PARQ_TIMER_BY_POS;

	if (retry > (d->queue_status.lifetime - PARQ_RETRY_SAFETY))
		retry = d->queue_status.lifetime - PARQ_RETRY_SAFETY;
	if (retry < d->queue_status.retry_delay)
		retry = d->queue_status.retry_delay;

	if (dbg)
		printf("Queue version: %d.%d, position %d out of %d,"
			" retry in %ds within [%d, %d]\n",
			major, minor, d->queue_status.position, d->queue_status.length,
			retry, d->queue_status.retry_delay, d->queue_status.lifetime);
	
	if (parq_download_is_active_queued(d)) {
		/*
		 * Don't keep a chunk busy if we are queued, perhaps another servent
		 * can complete it for us.
		 */

		file_info_clear_download(d, TRUE);
		d->status = GTA_DL_ACTIVE_QUEUED;
	}
	
	d->timeout_delay = retry;

	return TRUE;		/* OK */
}

/*
 * parq_download_is_active_queued
 *
 * Wether the download is queued remotely or not.
 */
gboolean parq_download_is_active_queued(struct download *d)
{
	g_assert(d != NULL);

	return d->queue_status.position > 0 && d->keep_alive;
}

/*
 * parq_download_add_header
 *
 * Adds an:
 *
 *    X-Queue: 1.0
 *    X-Queued: position=x; ID=xxxxx
 *
 * to the HTTP GET request
 */
void parq_download_add_header(
	gchar *buf, gint len, gint *rw, struct download *d)
{
	*rw += gm_snprintf(&buf[*rw], len - *rw,
		"X-Queue: %d.%d\r\n", PARQ_VERSION_MAJOR, PARQ_VERSION_MINOR);

	/*
	 * Only add X-Queued header if server really supports X-Queue: 1.x. Don't
	 * add X-Queued if there is no ID available. This could be because it is
	 * a first request.
	 */

	if (d->server->parq_version.major == 1 && d->queue_status.ID[0] != '\0')
		*rw += gm_snprintf(&buf[*rw], len - *rw,
			"X-Queued: position=%d; ID=%s\r\n",
			d->queue_status.position, d->queue_status.ID);
}

