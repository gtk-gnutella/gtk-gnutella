/*
 * $Id$
 *
 * Copyright (c) 2003, Raphael Manfredi
 *
 * Push proxy HTTP management.
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

#include "gnutella.h"		/* For <string.h> + dbg */

#include "pproxy.h"
#include "header.h"
#include "http.h"
#include "atoms.h"
#include "version.h"
#include "misc.h"

/* Following extra needed for the server-side */

#include "sockets.h"
#include "ioheader.h"
#include "bsched.h"
#include "routing.h"
#include "gmsg.h"
#include "uploads.h"

/* Following extra needed for the client-side */

#include "settings.h"		/* For listen_ip() */
#include "token.h"
#include "downloads.h"

RCSID("$Id$");

/***
 *** Server-side of push-proxy
 ***/

static GSList *pproxies = NULL;	/* Currently active push-proxy requests */

extern gint guid_eq(gconstpointer a, gconstpointer b);

/*
 * pproxy_free_resources
 *
 * Get rid of all the resources attached to the push-proxy struct.
 * But not the structure itself.
 */
static void pproxy_free_resources(struct pproxy *pp)
{
	if (pp->guid != NULL) {
		atom_guid_free(pp->guid);
		pp->guid = NULL;
	}
	if (pp->io_opaque != NULL) {
		io_free(pp->io_opaque);
		g_assert(pp->io_opaque == NULL);
	}
	if (pp->user_agent != NULL) {
		atom_str_free(pp->user_agent);
		pp->user_agent = NULL;
	}
	if (pp->socket != NULL) {
		g_assert(pp->socket->resource.pproxy == pp);
		socket_free(pp->socket);
		pp->socket = NULL;
	}
}

/*
 * send_pproxy_error_v
 *
 * The vectorized (message-wise) version of send_pproxy_error().
 */
static void send_pproxy_error_v(
	struct pproxy *pp,
	const gchar *ext,
	int code,
	const gchar *msg, va_list ap)
{
	gchar reason[1024];
	gchar extra[1024];
	gint slen = 0;
	http_extra_desc_t hev[1];
	gint hevcnt = 0;

	if (msg) {
		gm_vsnprintf(reason, sizeof(reason), msg, ap);
		reason[sizeof(reason) - 1] = '\0';		/* May be truncated */
	} else
		reason[0] = '\0';

	if (pp->error_sent) {
		g_warning("push-proxy: already sent an error %d to %s, "
			"not sending %d (%s)",
			pp->error_sent, ip_to_gchar(pp->socket->ip), code, reason);
		return;
	}

	extra[0] = '\0';

	/*
	 * If `ext' is not null, we have extra header information to propagate.
	 */

	if (ext) {
		slen = gm_snprintf(extra, sizeof(extra), "%s", ext);
		
		if (slen < sizeof(extra)) {
			hev[hevcnt].he_type = HTTP_EXTRA_LINE;
			hev[hevcnt++].he_msg = extra;
		} else
			g_warning("send_pproxy_error_v: "
				"ignoring too large extra header (%d bytes)", slen);
	}

	http_send_status(pp->socket, code, FALSE,
			hevcnt ? hev : NULL, hevcnt, reason);

	pp->error_sent = code;
}

/*
 * send_pproxy_error
 *
 * Send error message to requestor.
 * This can only be done once per connection.
 */
static void send_pproxy_error(
	struct pproxy *pp, int code, const gchar *msg, ...)
{
	va_list args;

	va_start(args, msg);
	send_pproxy_error_v(pp, NULL, code, msg, args);
	va_end(args);
}

/*
 * pproxy_remove_v
 *
 * The vectorized (message-wise) version of pproxy_remove().
 */
static void pproxy_remove_v(
	struct pproxy *pp, const gchar *reason, va_list ap)
{
	const gchar *logreason;
	gchar errbuf[1024];

	g_assert(pp != NULL);

	if (reason) {
		gm_vsnprintf(errbuf, sizeof(errbuf), reason, ap);
		errbuf[sizeof(errbuf) - 1] = '\0';		/* May be truncated */
		logreason = errbuf;
	} else {
		if (pp->error_sent) {
			gm_snprintf(errbuf, sizeof(errbuf), "HTTP %d", pp->error_sent);
			logreason = errbuf;
		} else {
			errbuf[0] = '\0';
			logreason = "No reason given";
		}
	}

	if (dbg > 1) {
		printf("push-proxy: ending request from %s (%s): %s\n",
			pp->socket ? ip_to_gchar(pp->socket->ip) : "<no socket>",
			pproxy_vendor_str(pp),
			logreason);
	}

	if (!pp->error_sent) {
		if (reason == NULL)
			logreason = "Bad Request";
		send_pproxy_error(pp, 400, logreason);
	}

	pproxy_free_resources(pp);
	wfree(pp, sizeof(*pp));

	pproxies = g_slist_remove(pproxies, (gpointer) pp);
}

/*
 * pproxy_remove
 *
 * Remove push proxy entry, log reason.
 *
 * If no status has been sent back on the HTTP stream yet, give
 * them a 400 error with the reason.
 */
void pproxy_remove(struct pproxy *pp, const gchar *reason, ...)
{
	va_list args;
	
	g_assert(pp != NULL);
	
	va_start(args, reason);
	pproxy_remove_v(pp, reason, args);
	va_end(args);
}

/*
 * pproxy_error_remove
 *
 * Utility routine.  Cancel the request, sending back the HTTP error message.
 */
static void pproxy_error_remove(
	struct pproxy *pp, int code, const gchar *msg, ...)
{
	va_list args, errargs;

	g_assert(pp != NULL);

	va_start(args, msg);

	VA_COPY(errargs, args);
	send_pproxy_error_v(pp, NULL, code, msg, errargs);
	va_end(errargs);

	pproxy_remove_v(pp, msg, args);
	va_end(args);
}

/*
 * pproxy_timer
 *
 * Push proxy timer.
 */
void pproxy_timer(time_t now)
{
	GSList *l;
	GSList *to_remove = NULL;

	for (l = pproxies; l; l = g_slist_next(l)) {
		struct pproxy *pp = (struct pproxy *) l->data;
		
		/*
		 * We can't call pproxy_remove() since it will remove the structure
		 * from the list we are traversing.
		 */

		if (now - pp->last_update > upload_connecting_timeout) {
			to_remove = g_slist_prepend(to_remove, pp);
		}
	}

	for (l = to_remove; l; l = g_slist_next(l)) {
		struct pproxy *pp = (struct pproxy *) l->data;
		pproxy_error_remove(pp, 408, "Request timeout");
	}

	g_slist_free(to_remove);
}

/*
 * pproxy_create
 */
static struct pproxy *pproxy_create(struct gnutella_socket *s)
{
	struct pproxy *pp;

	pp = walloc0(sizeof(*pp));

	pp->socket = s;
	pp->last_update = time(NULL);
	s->resource.pproxy = pp;

	return pp;
}

/*
 * get_guid
 *
 * Extract GUID for push-proxyfication from the HTTP requestl line.
 *
 * Returns GUID atom, or NULL if we could not figure it out, in which case
 * we also return an error to the calling party.
 */
static gchar *get_guid(struct pproxy *pp, gchar *request)
{
	gchar *uri;
	gchar *attr;
	gchar *next;
	gchar *p;
	gint attrlen;
	gint datalen;
	gboolean maybe = FALSE;

	/*
	 * Move to the start of the requested path.  Note that sizeof("GET")
	 * accounts for the trailing NUL in the string.
	 */

	uri = request + ((request[0] == 'G') ? sizeof("GET") : sizeof("HEAD"));
	while (*uri == ' ' || *uri == '\t')
		uri++;

	/*
	 * Go patch the first space we encounter before HTTP to be a NUL.
	 * Indeed, the requesst shoud be "GET /get/12/foo.txt HTTP/1.0".
	 *
	 * Note that if we don't find HTTP/ after the space, it's not an
	 * error: they're just sending an HTTP/0.9 request, which is awkward
	 * but we accept it.
	 */

	p = strrchr(uri, ' ');
	if (p && p[1]=='H' && p[2]=='T' && p[3]=='T' && p[4]=='P' && p[5]=='/')
		*p = '\0';

	/*
	 * Determine proper parameter to extract based on the URL.
	 *
	 * The first two are legacy only, and the third one is the new form.
	 * However, we need some transition period before emitting the new form...
	 *		--RAM, 18/07/2003
	 */

	if (0 == strncmp(uri, "/gnutella/pushproxy?", 20)) {
		uri += 20;
		attr = "ServerId";
	} else if (0 == strncmp(uri, "/gnutella/push-proxy?", 21)) {
		uri += 21;
		attr = "ServerId";
	} else if (0 == strncmp(uri, "/gnet/push-proxy?", 17)) {
		uri += 17;
		attr = "guid";
	} else {
		pproxy_error_remove(pp, 400, "Request not understood");
		return NULL;
	}

	/*
	 * Look for the proper "ServerId=" or "guid=" parameter.
	 */

	attrlen = strlen(attr);

	if (0 == strncmp(uri, attr, attrlen)) {
		uri += attrlen;
		maybe = TRUE;
	} else
		maybe = FALSE;

	while (*uri && (!maybe || *uri != '=')) {
		uri = strchr(uri, '&');				/* Move to next parameter */
		if (uri == NULL)
			break;
		uri++;
		if (0 == strncmp(uri, attr, attrlen)) {
			uri += attrlen;
			maybe = TRUE;
		} else
			maybe = FALSE;
	}

	if (uri == NULL || *uri != '=' || !maybe) {
		pproxy_error_remove(pp, 400,
			"Malformed push-proxy request: no %s found", attr);
		return NULL;
	}

	g_assert(*uri == '=');
	g_assert(maybe);

	uri++;						/* Skip the "=" */

	/*
	 * Determine how much data we have for the parameter.
	 */

	next = strchr(uri, '&');
	if (next != NULL)
		*next = '\0';

	datalen = strlen(uri);

	if (0 == strcmp(attr, "ServerId")) {
		gchar *guid;

		/*
		 * GUID is base32-encoded: valid lengths are 26 (no padding) or 32.
		 */

		if (datalen != 26 && datalen != 32) {
			pproxy_error_remove(pp, 400, "Malformed push-proxy request: "
				"wrong length for parameter \"%s\": %d byte%s", attr, datalen,
				datalen == 1 ? "" : "s");
			return NULL;
		}

		if (dbg > 4)
			printf("PUSH-PROXY: decoding %s=%s as base32\n", attr, uri);
		
		guid = base32_to_guid(uri);
		if (guid == NULL) {
			pproxy_error_remove(pp, 400, "Malformed push-proxy request: "
				"parameter \"%s\" is not valid base32", attr);
			return NULL;
		}

		return atom_guid_get(guid);
	} else if (0 == strcmp(attr, "guid")) {
		gchar guid[16];

		/*
		 * GUID in hexadecimal: valid length is 32.
		 */

		if (datalen != 32) {
			pproxy_error_remove(pp, 400, "Malformed push-proxy request: "
				"wrong length for parameter \"%s\": %d byte%s", attr, datalen,
				datalen == 1 ? "" : "s");
			return NULL;
		}

		if (dbg > 4)
			printf("PUSH-PROXY: decoding %s=%s as hexadecimal\n", attr, uri);

		if (!hex_to_guid(uri, guid)) {
			pproxy_error_remove(pp, 400, "Malformed push-proxy request: "
				"parameter \"%s\" is not valid hexadecimal", attr);
			return NULL;
		}

		return atom_guid_get(guid);
	}

	g_error("unhandled parameter \"%s\"", attr);
	return NULL;
}

/*
 * build_push
 *
 * Build a push request to send.  We set TTL=max_ttl-1 and hops=1 since
 * it does not come from our node really.  The file ID is set to 0, but
 * it should be ignored when the GIV is received anyway.
 */
static void build_push(struct gnutella_msg_push_request *m,
	gchar *guid, guint32 ip, guint16 port)
{
	static const guint32 one = 1;

	message_set_muid(&m->header, GTA_MSG_PUSH_REQUEST);

	m->header.function = GTA_MSG_PUSH_REQUEST;
	m->header.ttl = max_ttl - 1;
	m->header.hops = 1;

	WRITE_GUINT32_LE(sizeof(struct gnutella_push_request), m->header.size);

	memcpy(m->request.guid, guid, 16);

	WRITE_GUINT32_LE(one, m->request.file_id);
	WRITE_GUINT32_BE(ip, m->request.host_ip);
	WRITE_GUINT16_LE(port, m->request.host_port);
}

/*
 * validate_vendor
 *
 * Validate vendor.
 * Returns atom, or NULL.
 */
static gchar *validate_vendor(gchar *vendor, gchar *token, guint32 ip)
{
	gchar *result = NULL;

	if (vendor) {
		gboolean faked = !version_check(vendor, token, ip);

		if (faked) {
			gchar *name = g_strdup_printf("!%s", vendor);
			result = atom_str_get(name);
			g_free(name);
		} else
			result = atom_str_get(vendor);
	}

	return result;
}

/*
 * pproxy_request
 *
 * Called once all the HTTP headers have been read to proceed with
 * the push proxyfication.
 */
static void pproxy_request(struct pproxy *pp, header_t *header) 
{
	struct gnutella_socket *s = pp->socket;
	gchar *request = getline_str(s->getline);
	struct gnutella_node *n;
	gchar *buf;
	gchar *token;
	gchar *user_agent;
	struct gnutella_msg_push_request m;
	GSList *nodes;

	if (dbg > 2) {
		printf("----Push-proxy request from %s:\n", ip_to_gchar(s->ip));
		printf("%s\n", request);
		header_dump(header, stdout);
		printf("----\n");
		fflush(stdout);
	}

	/*
	 * Extract User-Agent and X-Token if needed.
	 */

	token = header_get(header, "X-Token");
	user_agent = header_get(header, "User-Agent");

	pp->user_agent = validate_vendor(user_agent, token, s->ip);

	/*
	 * Determine the servent ID.
	 */

	pp->guid = get_guid(pp, request);

	if (pp->guid == NULL)
		return;				/* Already reported the error in get_guid() */

	if (dbg > 2)
		printf("PUSH-PROXY: %s requesting a push to %s",
			ip_to_gchar(s->ip), guid_hex_str(pp->guid));

	/*
	 * Make sure they provide an X-Node header so we know whom to set up
	 * as the originator of the push.  Then validate the address.
	 */

	buf = header_get(header, "X-Node");

	if (buf == NULL) {
		pproxy_error_remove(pp, 400,
			"Malformed push-proxy request: missing X-Node header");
		return;
	}

	if (!gchar_to_ip_port(buf, &pp->ip, &pp->port)) {
		pproxy_error_remove(pp, 400,
			"Malformed push-proxy request: cannot parse X-Node");
		return;
	}

	if (!host_is_valid(pp->ip, pp->port)) {
		pproxy_error_remove(pp, 400,
			"Malformed push-proxy request: supplied address %s unreachable",
			ip_port_to_gchar(pp->ip, pp->port));
		return;
	}

	if (pp->ip != s->ip)
		g_warning("push-proxy request from %s (%s) said node was at %s",
			ip_to_gchar(s->ip), pproxy_vendor_str(pp),
			ip_port_to_gchar(pp->ip, pp->port));

	/*
	 * Locate a route to that servent.
	 */

	n = route_proxy_find(pp->guid);

	if (n != NULL) {
		build_push(&m, pp->guid, pp->ip, pp->port);
		message_add(m.header.muid, GTA_MSG_PUSH_REQUEST, NULL);

		gmsg_sendto_one(n, (gchar *) &m, sizeof(m));

		http_send_status(pp->socket, 202, FALSE, NULL, 0,
			"Push-proxy: message sent to node");

		pproxy_remove(pp, "Push sent directly to node GUID %s",
			guid_hex_str(pp->guid));

		return;
	}

	/*
	 * Bad luck, no direct connection.  Look for a Gnutella route.
	 */

	nodes = route_towards_guid(pp->guid);

	if (nodes != NULL) {
		gint cnt;

		build_push(&m, pp->guid, pp->ip, pp->port);
		message_add(m.header.muid, GTA_MSG_PUSH_REQUEST, NULL);

		gmsg_sendto_all(nodes, (gchar *) &m, sizeof(m));

		cnt = g_slist_length(nodes);
		g_slist_free(nodes);

		http_send_status(pp->socket, 203, FALSE, NULL, 0,
			"Push-proxy: message sent through Gnutella (via %d node%s)",
			cnt, cnt == 1 ? "" : "s");

		pproxy_remove(pp, "Push sent via Gnutella (%d node%s) for GUID %s",
			cnt, cnt == 1 ? "" : "s", guid_hex_str(pp->guid));

		return;
	}

	/*
	 * If by extraordinary the GUID is ours, honour it immediately by
	 * sending a GIV back.
	 */

	if (guid_eq(pp->guid, guid)) {
		upload_send_giv(pp->ip, pp->port, 0, 1, 0, "<from push-proxy>", FALSE);

		http_send_status(pp->socket, 202, FALSE, NULL, 0,
			"Push-proxy: you found the target GUID %s",
			guid_hex_str(pp->guid));

		pproxy_remove(pp, "Push was for our GUID %s", guid_hex_str(pp->guid));

		return;
	}

	/*
	 * Sorry.
	 */

	pproxy_error_remove(pp, 410, "Push proxy: no route to servent GUID %s",
		guid_hex_str(pp->guid));
}

/***
 *** I/O header parsing callbacks.
 ***/

#define PPROXY(x)	((struct pproxy *) (x))

static void err_line_too_long(gpointer obj)
{
	pproxy_error_remove(PPROXY(obj), 413, "Header too large");
}

static void err_header_error_tell(gpointer obj, gint error)
{
	send_pproxy_error(PPROXY(obj), 413, header_strerror(error));
}

static void err_header_error(gpointer obj, gint error)
{
	pproxy_remove(PPROXY(obj), "Failed (%s)", header_strerror(error));
}

static void err_input_exception(gpointer obj)
{
	pproxy_remove(PPROXY(obj), "Failed (Input Exception)");
}

static void err_input_buffer_full(gpointer obj)
{
	pproxy_error_remove(PPROXY(obj), 500, "Input buffer full");
}

static void err_header_read_error(gpointer obj, gint error)
{
	pproxy_remove(PPROXY(obj), "Failed (Input error: %s)", g_strerror(error));
}

static void err_header_read_eof(gpointer obj)
{
	pproxy_remove(PPROXY(obj), "Failed (EOF)");
}

static void err_header_extra_data(gpointer obj)
{
	pproxy_error_remove(PPROXY(obj), 400, "Extra data after HTTP header");
}

static struct io_error pproxy_io_error = {
	err_line_too_long,
	err_header_error_tell,
	err_header_error,
	err_input_exception,
	err_input_buffer_full,
	err_header_read_error,
	err_header_read_eof,
	err_header_extra_data,
};

static void call_pproxy_request(gpointer obj, header_t *header)
{
	pproxy_request(PPROXY(obj), header);
}

#undef PPROXY

/*
 * pproxy_add
 *
 * Create new push-proxy request and begin reading HTTP headers.
 */
void pproxy_add(struct gnutella_socket *s)
{
	struct pproxy *pp;

	s->type = SOCK_TYPE_PPROXY;
	socket_tos_default(s);

	pp = pproxy_create(s);

	/*
	 * Read HTTP headers, then call pproxy_request() when done.
	 */

	io_get_header(pp, &pp->io_opaque, bws.in, s, IO_HEAD_ONLY,
		call_pproxy_request, NULL, &pproxy_io_error);
}

/*
 * pproxy_close
 *
 * Called a shutdown time.
 */
void pproxy_close(void)
{
	GSList *l;

	for (l = pproxies; l; l = g_slist_next(l)) {
		struct pproxy *pp = (struct pproxy *) l->data;

		pproxy_free_resources(pp);
		wfree(pp, sizeof(*pp));
	}

	g_slist_free(pproxies);
}

/***
 *** Client-side of push-proxy
 ***/

#define CPROXY_MAGIC	0xc8301

/*
 * cproxy_free
 *
 * Free the structure and all its dependencies.
 */
void cproxy_free(struct cproxy *cp)
{
	g_assert(cp->magic == CPROXY_MAGIC);

	if (cp->guid != NULL) {
		atom_guid_free(cp->guid);
		cp->guid = NULL;
	}
	if (cp->http_handle != NULL) {
		http_async_cancel(cp->http_handle);
		cp->http_handle = NULL;
	}
	if (cp->server != NULL) {
		atom_str_free(cp->server);
		cp->server = NULL;
	}

	cp->magic = 0;
	wfree(cp, sizeof(*cp));
}

/*
 * cproxy_http_error_ind
 *
 * HTTP async callback for error notifications.
 */
static void cproxy_http_error_ind(
	gpointer handle, http_errtype_t type, gpointer v)
{
	struct cproxy *cp = (struct cproxy *) http_async_get_opaque(handle);

	g_assert(cp != NULL);
	g_assert(cp->magic == CPROXY_MAGIC);

	http_async_log_error(handle, type, v);

	cp->http_handle = NULL;
	cp->done = TRUE;

	if (
		type == HTTP_ASYNC_ERROR &&
		GPOINTER_TO_INT(v) == HTTP_ASYNC_CANCELLED
	)
		return;		/* Was an explicit cancel */

	download_proxy_failed(cp->d);
}

/*
 * cproxy_http_header_ind
 *
 * HTTP async callback for header reception notification.
 * Returns whether processing can continue.
 */
static gboolean cproxy_http_header_ind(
	gpointer handle, header_t *header, gint code, const gchar *message)
{
	struct cproxy *cp = (struct cproxy *) http_async_get_opaque(handle);
	gchar *token;
	gchar *server;

	g_assert(cp != NULL);
	g_assert(cp->d != NULL);
	g_assert(cp->magic == CPROXY_MAGIC);

	/*
	 * Extract vendor information.
	 */

	token = header_get(header, "X-Token");
	server = header_get(header, "Server");
	if (server == NULL)
		server = header_get(header, "User-Agent");

	cp->server = validate_vendor(server, token, cp->ip);

	/*
	 * Don't continue past headers, we don't expect data, and besides the
	 * error codes are non-standard.
	 */

	g_assert(handle == cp->http_handle);

	http_async_cancel(cp->http_handle);
	cp->http_handle = NULL;

	g_assert(cp->done);		/* Set by the error_ind callback during cancel */

	/*
	 * Analyze status.
	 */

	switch (code) {
	case 202:
		download_proxy_sent(cp->d);
		cp->sent = TRUE;
		cp->directly = TRUE;
		break;
	case 203:
		download_proxy_sent(cp->d);
		cp->sent = TRUE;
		cp->directly = FALSE;
		break;
	case 400:
		g_warning("push-proxy at %s (%s) for %s reported HTTP %d: %s",
			ip_port_to_gchar(cp->ip, cp->port), cproxy_vendor_str(cp),
			guid_hex_str(cp->guid), code, message);
		/* FALL THROUGH */
	case 410:
		download_proxy_failed(cp->d);
		break;
	default:
		g_warning("push-proxy at %s (%s) for %s sent unexpected HTTP %d: %s",
			ip_port_to_gchar(cp->ip, cp->port), cproxy_vendor_str(cp),
			guid_hex_str(cp->guid), code, message);
		download_proxy_failed(cp->d);
		break;
	}

	return FALSE;		/* Don't continue -- handle invalid now anyway */
}

/*
 * cproxy_build_request
 *
 * Redefines the HTTP request building.
 *
 * See http_async_build_request() for the model and details about
 * the various parameters.
 *
 * Returns length of generated request.
 */
static gint cproxy_build_request(gpointer handle, gchar *buf, gint len,
	gchar *verb, gchar *path, gchar *host)
{
	/*
	 * Note that we send an HTTP/1.0 request here, hence we need neither
	 * the Host: nor the Connection: header.
	 */

	return gm_snprintf(buf, len,
		"%s %s HTTP/1.0\r\n"
		"User-Agent: %s\r\n"
		"X-Token: %s\r\n"
		"X-Node: %s\r\n"
		"\r\n",
		verb, path, version_string,
		tok_version(),
		ip_port_to_gchar(listen_ip(), listen_port));
}

/*
 * cproxy_http_newstate
 *
 * Invoked when the state of the HTTP async request changes.
 */
static void cproxy_http_newstate(gpointer handle, http_state_t newstate)
{
	struct cproxy *cp = (struct cproxy *) http_async_get_opaque(handle);

	g_assert(cp != NULL);
	g_assert(cp->d != NULL);
	g_assert(cp->magic == CPROXY_MAGIC);

	cp->state = newstate;
	download_proxy_newstate(cp->d);
}

/*
 * cproxy_create
 *
 * Create client proxy.
 * Returns NULL if problem during connection.
 */
struct cproxy *cproxy_create(struct download *d,
	guint32 ip, guint16 port, gchar *guid)
{
	struct cproxy *cp;
	gpointer handle;
	static gchar path[128];

	(void) gm_snprintf(path, sizeof(path),
		"/gnutella/push-proxy?ServerId=%s",
		guid_base32_str(guid));

	/*
	 * Try to connect immediately: if we can't connect, no need to continue.
	 */

	handle = http_async_get_ip(path, ip, port,
		cproxy_http_header_ind, NULL, cproxy_http_error_ind);

	if (handle == NULL) {
		g_warning("can't connect to push-proxy %s for GUID %s: %s",
			ip_port_to_gchar(ip, port), guid_hex_str(guid),
			http_async_strerror(http_async_errno));
		return NULL;
	}

	cp = walloc0(sizeof(*cp));

	cp->magic = CPROXY_MAGIC;
	cp->d = d;
	cp->ip = ip;
	cp->port = port;
	cp->guid = atom_guid_get(guid);
	cp->http_handle = handle;

	/*
	 * Customize async HTTP layer.
	 */

	http_async_set_opaque(handle, cp, NULL);
	http_async_set_op_request(handle, cproxy_build_request);
	http_async_on_state_change(handle, cproxy_http_newstate);

	return cp;
}

/*
 * cproxy_reparent
 *
 * Updates the proxy structures to point to the right download when a download
 * was cloned.
 */
void cproxy_reparent(struct download *d, struct download *cd)
{
	g_assert(d != cd);
	g_assert(d->cproxy != NULL);
	g_assert(cd->cproxy != NULL);
	
	cd->cproxy->d = cd;
	
	d->cproxy = NULL;
	
	g_assert(d->cproxy == NULL);
	g_assert(cd->cproxy != NULL);
	g_assert(cd == cd->cproxy->d);
}
