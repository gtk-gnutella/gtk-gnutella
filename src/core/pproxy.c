/*
 * $Id$
 *
 * Copyright (c) 2003, Raphael Manfredi
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
 * Push proxy HTTP management.
 *
 * @author Raphael Manfredi
 * @date 2003
 */

#include "common.h"

RCSID("$Id$")

#include "pproxy.h"
#include "http.h"
#include "hosts.h"
#include "version.h"

/* Following extra needed for the server-side */

#include "sockets.h"
#include "ioheader.h"
#include "bsched.h"
#include "routing.h"
#include "gmsg.h"
#include "uploads.h"
#include "ggep.h"
#include "ggep_type.h"
#include "gnet_stats.h"
#include "lib/url.h"

/* Following extra needed for the client-side */

#include "settings.h"			/* For listen_addr() */
#include "token.h"
#include "downloads.h"
#include "features.h"

#include "lib/ascii.h"
#include "lib/atoms.h"
#include "lib/getline.h"
#include "lib/header.h"
#include "lib/glib-missing.h"
#include "lib/endian.h"
#include "lib/tm.h"
#include "lib/walloc.h"

#include "if/gnet_property_priv.h"

#include "lib/override.h"		/* Must be the last header included */

/***
 *** Server-side of push-proxy
 ***/

static GSList *pproxies = NULL;	/**< Currently active push-proxy requests */

static void send_pproxy_error(struct pproxy *pp, int code,
	const gchar *msg, ...) G_GNUC_PRINTF(3, 4);
static void pproxy_error_remove(struct pproxy *pp, int code,
	const gchar *msg, ...) G_GNUC_PRINTF(3, 4);

/**
 * Get rid of all the resources attached to the push-proxy struct.
 * But not the structure itself.
 */
static void
pproxy_free_resources(struct pproxy *pp)
{
	atom_guid_free_null(&pp->guid);
	if (pp->io_opaque != NULL) {
		io_free(pp->io_opaque);
		g_assert(pp->io_opaque == NULL);
	}
	atom_str_free_null(&pp->user_agent);
	if (pp->socket != NULL) {
		g_assert(pp->socket->resource.pproxy == pp);
		socket_free_null(&pp->socket);
	}
}

/**
 * The vectorized (message-wise) version of send_pproxy_error().
 */
static void
send_pproxy_error_v(
	struct pproxy *pp,
	const gchar *ext,
	int code,
	const gchar *msg, va_list ap)
{
	gchar reason[1024];
	gchar extra[1024];
	http_extra_desc_t hev[1];
	gint hevcnt = 0;

	if (msg) {
		gm_vsnprintf(reason, sizeof reason, msg, ap);
	} else
		reason[0] = '\0';

	if (pp->error_sent) {
		g_warning("push-proxy: already sent an error %d to %s, "
			"not sending %d (%s)",
			pp->error_sent,host_addr_to_string(pp->socket->addr),
			code, reason);
		return;
	}

	extra[0] = '\0';

	/*
	 * If `ext' is not null, we have extra header information to propagate.
	 */

	if (ext) {
		size_t slen = g_strlcpy(extra, ext, sizeof extra);

		if (slen < sizeof extra) {
			hev[hevcnt].he_type = HTTP_EXTRA_LINE;
			hev[hevcnt++].he_msg = extra;
		} else
			g_warning("send_pproxy_error_v: "
				"ignoring too large extra header (%d bytes)", (int) slen);
	}

	http_send_status(pp->socket, code, FALSE,
			hevcnt ? hev : NULL, hevcnt, "%s", reason);

	pp->error_sent = code;
}

/**
 * Send error message to requestor.
 * This can only be done once per connection.
 */
static void
send_pproxy_error(struct pproxy *pp, int code, const gchar *msg, ...)
{
	va_list args;

	va_start(args, msg);
	send_pproxy_error_v(pp, NULL, code, msg, args);
	va_end(args);
}

/**
 * The vectorized (message-wise) version of pproxy_remove().
 */
static void
pproxy_remove_v(struct pproxy *pp, const gchar *reason, va_list ap)
{
	const gchar *logreason;
	gchar errbuf[1024];

	g_assert(pp != NULL);

	if (reason) {
		gm_vsnprintf(errbuf, sizeof errbuf , reason, ap);
		logreason = errbuf;
	} else {
		if (pp->error_sent) {
			gm_snprintf(errbuf, sizeof errbuf, "HTTP %d", pp->error_sent);
			logreason = errbuf;
		} else {
			errbuf[0] = '\0';
			logreason = "No reason given";
		}
	}

	if (GNET_PROPERTY(push_proxy_debug) > 0) {
		g_message("push-proxy: ending request from %s (%s): %s",
			pp->socket ? host_addr_to_string(pp->socket->addr) : "<no socket>",
			pproxy_vendor_str(pp),
			logreason);
	}

	if (!pp->error_sent) {
		if (reason == NULL)
			logreason = "Bad Request";
		send_pproxy_error(pp, 400, "%s", logreason);
	}

	pproxy_free_resources(pp);
	wfree(pp, sizeof *pp);

	pproxies = g_slist_remove(pproxies, pp);
}

/**
 * Remove push proxy entry, log reason.
 *
 * If no status has been sent back on the HTTP stream yet, give
 * them a 400 error with the reason.
 */
void
pproxy_remove(struct pproxy *pp, const gchar *reason, ...)
{
	va_list args;

	g_assert(pp != NULL);

	va_start(args, reason);
	pproxy_remove_v(pp, reason, args);
	va_end(args);
}

/**
 * Utility routine.  Cancel the request, sending back the HTTP error message.
 */
static void
pproxy_error_remove(struct pproxy *pp, int code, const gchar *msg, ...)
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

/**
 * Push proxy timer.
 */
void
pproxy_timer(time_t now)
{
	GSList *sl;
	GSList *to_remove = NULL;

	for (sl = pproxies; sl; sl = g_slist_next(sl)) {
		struct pproxy *pp = sl->data;

		/*
		 * We can't call pproxy_remove() since it will remove the structure
		 * from the list we are traversing.
		 */

		if (
			delta_time(now, pp->last_update) >
				(time_delta_t) GNET_PROPERTY(upload_connecting_timeout)
		) {
			to_remove = g_slist_prepend(to_remove, pp);
		}
	}

	for (sl = to_remove; sl; sl = g_slist_next(sl)) {
		struct pproxy *pp = sl->data;
		pproxy_error_remove(pp, 408, "Request timeout");
	}

	g_slist_free(to_remove);
}

/**
 * pproxy_create
 */
static struct pproxy *
pproxy_create(struct gnutella_socket *s)
{
	struct pproxy *pp;

	pp = walloc0(sizeof *pp);

	pp->socket = s;
	pp->flags = 0; /* XXX: TLS? */
	pp->last_update = tm_time();
	s->resource.pproxy = pp;

	return pp;
}

/**
 * Extract GUID for push-proxyfication from the HTTP request line.
 * Extract file index if present (otherwise 0 will be used).
 *
 * Fills the GUID atom into `guid_atom' and the file index into `file_idx'.
 *
 * @returns TRUE if OK, FALSE if we could not figure it out, in which case
 * we also return an error to the calling party.
 */
static gboolean
get_params(struct pproxy *pp, const gchar *request,
	const struct guid **guid_atom, guint32 *file_idx, gboolean *supports_tls)
{
	static const struct {
		const gchar *req;
		const gchar *attr;
	} req_types[] = {
		{ "/gnutella/pushproxy?",	"ServerId" },
		{ "/gnutella/push-proxy?",	"ServerId" },
		{ "/gnet/push-proxy?",		"guid" },
	};
	gchar *uri;
	const gchar *attr;
	gchar *p;
	const gchar *value;
	gint datalen;
	url_params_t *up;
	guint i;

	g_assert(pp);
	g_assert(request);
	g_assert(guid_atom);
	g_assert(file_idx);
	g_assert(supports_tls);
	
	/*
	 * Move to the start of the requested path.  Note that sizeof("GET")
	 * accounts for the trailing NUL in the string.
	 */

	uri = is_strprefix(request, "GET");
	if (!uri)
		uri = is_strprefix(request, "HEAD");
	if (!uri) {
		pproxy_error_remove(pp, 501, "Not Implemented");
		return FALSE;
	}
	uri = skip_ascii_blanks(uri);

	/*
	 * Go patch the first space we encounter before HTTP to be a NUL.
	 * Indeed, the request should be "GET /get/12/foo.txt HTTP/1.0".
	 *
	 * Note that if we don't find HTTP/ after the space, it's not an
	 * error: they're just sending an HTTP/0.9 request, which is awkward
	 * but we accept it.
	 */

	p = strrchr(uri, ' ');
	if (p && is_strprefix(&p[1], "HTTP/"))
		*p = '\0';

	/*
	 * Determine proper parameter to extract based on the URL.
	 *
	 * The first two are legacy only, and the third one is the new form.
	 * However, we need some transition period before emitting the new form...
	 *		--RAM, 18/07/2003
	 */

	attr = NULL;
	for (i = 0; i < G_N_ELEMENTS(req_types); i++) {
		gchar *q;

		if (NULL != (q = is_strprefix(uri, req_types[i].req))) {
			attr = req_types[i].attr;
			uri = q;
			break;
		}
	}

	if (!attr) {
		pproxy_error_remove(pp, 400, "Request not understood");
		return FALSE;
	}

	/*
	 * Look for the proper "ServerId=" or "guid=" parameter.
	 */

	up = url_params_parse(uri);
	if (!up) {
		pproxy_error_remove(pp, 400,
			"Malformed push-proxy request: Bad URL encoding");
		goto error;
	}
	value = url_params_get(up, attr);

	if (value == NULL) {
		pproxy_error_remove(pp, 400,
			"Malformed push-proxy request: no %s found", attr);
		goto error;
	}

	/*
	 * Determine how much data we have for the parameter.
	 */

	datalen = strlen(value);

	if (0 == strcmp(attr, "ServerId")) {
		const struct guid *guid;

		/*
		 * GUID is base32-encoded: valid lengths are 26 (no padding) or 32.
		 */

		if (datalen != 26 && datalen != 32) {
			pproxy_error_remove(pp, 400, "Malformed push-proxy request: "
				"wrong length for parameter \"%s\": %d byte%s", attr, datalen,
				datalen == 1 ? "" : "s");
			goto error;
		}

		if (GNET_PROPERTY(push_proxy_debug) > 0)
			g_message("PUSH-PROXY: decoding %s=%s as base32", attr, value);

		guid = base32_to_guid(value);
		if (guid == NULL) {
			pproxy_error_remove(pp, 400, "Malformed push-proxy request: "
				"parameter \"%s\" is not valid base32", attr);
			goto error;
		}

		*guid_atom = atom_guid_get(guid);
	} else if (0 == strcmp(attr, "guid")) {
		struct guid guid;

		/*
		 * GUID in hexadecimal: valid length is 32.
		 */

		if (datalen != 32) {
			pproxy_error_remove(pp, 400, "Malformed push-proxy request: "
				"wrong length for parameter \"%s\": %d byte%s", attr, datalen,
				datalen == 1 ? "" : "s");
			goto error;
		}

		if (GNET_PROPERTY(push_proxy_debug) > 0)
			g_message("PUSH-PROXY: decoding %s=%s as hexadecimal", attr, value);

		if (!hex_to_guid(value, &guid)) {
			pproxy_error_remove(pp, 400, "Malformed push-proxy request: "
				"parameter \"%s\" is not valid hexadecimal", attr);
			goto error;
		}

		*guid_atom = atom_guid_get(&guid);
	} else {
		g_error("unhandled parameter \"%s\"", attr);
	}

	/*
	 * Extract the optional "file=" parameter.
	 */

	value = url_params_get(up, "file");
	if (value) {
		gint error;

		/* Ignore errors; parse_uint32() returns 0 on error. */
		*file_idx = parse_uint32(value, NULL, 10, &error);
	} else {
		*file_idx = 0;
	}

	value = url_params_get(up, "tls");
	if (value) {
		*supports_tls = 0 == ascii_strcasecmp(value, "true");
	} else {
		*supports_tls = FALSE;
	}

	url_params_free(up);
	return TRUE;

error:
	url_params_free(up);
	return FALSE;
}

/**
 * Builds a push request to send.  We set TTL=max_ttl-1 and hops=1 since
 * it does not come from our node really.  The file ID may be set to 0, but
 * it should be ignored when the GIV is received anyway.
 *
 * @param size_ptr no document
 * @param ttl the TTL to use for the packet header.
 * @param hops the hops value to use for the packet header.
 * @param guid the hops value to use for the packet header.
 * @param addr the host address the receiving peer should connect to.
 * @param port the port number the receiving peer should connect to.
 * @param file_idx the file index this push is for.
 * @return	A pointer to a static buffer holding the created Gnutella PUSH
 *			packet on success, an empty array on failure.
 */
struct array
build_push(guint8 ttl, guint8 hops, const struct guid *guid,
	host_addr_t addr_v4, host_addr_t addr_v6, guint16 port,
	guint32 file_idx, gboolean supports_tls)
{
	static union {
		gnutella_msg_push_request_t m;
		gchar data[1024];
	} packet;
	gchar *p = packet.data;
	size_t len = 0, size = sizeof packet;
	ggep_stream_t gs;

	g_assert(guid);
	g_assert(0 != port);

	{
		gnutella_header_t *header = gnutella_msg_push_request_header(&packet.m);

		message_set_muid(header, GTA_MSG_PUSH_REQUEST);
		gnutella_header_set_function(header, GTA_MSG_PUSH_REQUEST);
		gnutella_header_set_ttl(header, ttl);
		gnutella_header_set_hops(header, hops);
	}
	
	gnutella_msg_push_request_set_guid(&packet.m, guid);

	STATIC_ASSERT(49 == sizeof packet.m);
	p += sizeof packet.m;
	size -= sizeof packet.m;
	len += sizeof packet.m - GTA_HEADER_SIZE;	/* Exclude the header size */

	ggep_stream_init(&gs, p, size);

	if (!supports_tls && tls_enabled()) {
		supports_tls = is_my_address_and_port(addr_v4, port)
			|| is_my_address_and_port(addr_v6, port);
	}
	
	if (supports_tls) {
		if (!ggep_stream_pack(&gs, GGEP_NAME(TLS), NULL, 0, 0)) {
			g_warning("could not write GGEP \"TLS\" extension into PUSH");
			ggep_stream_close(&gs);
			return zero_array;
		}
		if (!ggep_stream_pack(&gs, GGEP_GTKG_NAME(TLS), NULL, 0, 0)) {
			g_warning("could not write GGEP \"GTKG.TLS\" extension into PUSH");
			ggep_stream_close(&gs);
			return zero_array;
		}
	}

	if (is_host_addr(addr_v6) && NET_TYPE_IPV6 == host_addr_net(addr_v6)) {
		const guint8 *ipv6 = host_addr_ipv6(&addr_v6);

		if (!ggep_stream_pack(&gs, GGEP_GTKG_NAME(IPV6), ipv6, 16, 0)) {
			g_warning("could not write GGEP \"GTKG.IPV6\" extension into PUSH");
			ggep_stream_close(&gs);
			return zero_array;
		}
	}

	{
		size_t glen;

		glen = ggep_stream_close(&gs);
		g_assert(size >= glen);

		size -= glen;
		len += glen;
		p += glen;
	}
	g_assert(len < size);
	g_assert(len < sizeof packet);

	gnutella_msg_push_request_set_file_id(&packet.m,
		file_idx == URN_INDEX ? 0 : file_idx);
	gnutella_msg_push_request_set_host_ip(&packet.m, host_addr_ipv4(addr_v4));
	gnutella_msg_push_request_set_host_port(&packet.m, port);
	gnutella_header_set_size(gnutella_msg_push_request_header(&packet.m), len);

	message_add(
		gnutella_header_get_muid(gnutella_msg_push_request_header(&packet.m)),
		GTA_MSG_PUSH_REQUEST, NULL);

	return array_init(packet.data, p - packet.data);
}

/**
 * Validate vendor.
 *
 * @return atom, or NULL.
 */
static const gchar *
validate_vendor(gchar *vendor, gchar *token, const host_addr_t addr)
{
	const gchar *result;

	if (vendor) {
		gboolean faked = !version_check(vendor, token, addr);

		if (faked) {
			gchar name[1024];

			name[0] = '!';
			g_strlcpy(&name[1], vendor, sizeof name - 1);
			result = atom_str_get(name);
		} else
			result = atom_str_get(vendor);
	} else {
		result = NULL;
	}

	return result;
}

static void
pproxy_fetch_addresses(struct pproxy *pp, const char *buf)
{
	const gchar *endptr;
	host_addr_t addr;
	guint16 port;

	if (NULL == buf)
		return;

	if (!string_to_host_addr_port(buf, &endptr, &addr, &port))
		return;

	pp->addr_v4 = zero_host_addr;
	pp->addr_v6 = zero_host_addr;
	pp->port = port;

	switch (host_addr_net(addr)) {
	case NET_TYPE_IPV4:
		pp->addr_v4 = addr;
		break;
	case NET_TYPE_IPV6:
		pp->addr_v6 = addr;
		break;
	case NET_TYPE_LOCAL:
	case NET_TYPE_NONE:
		break;
	}

	/* Allow a second address */
	endptr = skip_ascii_spaces(endptr);
	if (',' == *endptr) {
		endptr = skip_ascii_spaces(&endptr[1]);
		if (
			string_to_host_addr_port(endptr, NULL, &addr, &port) &&
			port == pp->port
		) {
			switch (host_addr_net(addr)) {
			case NET_TYPE_IPV4:
				pp->addr_v4 = addr;
				break;
			case NET_TYPE_IPV6:
				pp->addr_v6 = addr;
				break;
			case NET_TYPE_LOCAL:
			case NET_TYPE_NONE:
				break;
			}
		}
	}
}

/**
 * Called once all the HTTP headers have been read to proceed with
 * the push proxyfication.
 */
static void
pproxy_request(struct pproxy *pp, header_t *header)
{
	struct gnutella_socket *s = pp->socket;
	const gchar *request = getline_str(s->getline);
	struct gnutella_node *n;
	const gchar *buf;
	gchar *token;
	gchar *user_agent;
	GSList *nodes;
	gboolean supports_tls = FALSE;

	if (GNET_PROPERTY(push_proxy_debug) > 0) {
		g_message("----Push-proxy request from %s:\n%s",
			host_addr_to_string(s->addr), request);
		header_dump(header, stderr);
		g_message("----");
	}

	/*
	 * Extract User-Agent and X-Token if needed.
	 */

	token = header_get(header, "X-Token");
	user_agent = header_get(header, "User-Agent");

	pp->user_agent = validate_vendor(user_agent, token, s->addr);

	/*
	 * Determine the servent ID.
	 */

	if (!get_params(pp, request, &pp->guid, &pp->file_idx, &supports_tls))
		return;				/* Already reported the error in get_params() */

	supports_tls |= header_get_feature("tls", header, NULL, NULL);

	if (GNET_PROPERTY(push_proxy_debug) > 0)
		g_message("PUSH-PROXY: %s requesting a push to %s for file #%d",
			host_addr_to_string(s->addr), guid_hex_str(pp->guid),
			pp->file_idx);

	/*
	 * Make sure they provide an X-Node header so we know whom to set up
	 * as the originator of the push.  Then validate the address.
	 */

	buf = header_get(header, "X-Node");
	if (buf) {
		pproxy_fetch_addresses(pp, buf);
	}
	buf = header_get(header, "X-Node-IPv6");
	if (buf) {
		pproxy_fetch_addresses(pp, buf);
	}

	if (!host_is_valid(pp->addr_v4, pp->port)) {
		pp->addr_v4 = zero_host_addr;
	}
	if (!host_is_valid(pp->addr_v6, pp->port)) {
		pp->addr_v6 = zero_host_addr;
	}
	
	if (!is_host_addr(pp->addr_v4) && !is_host_addr(pp->addr_v6)) {
		pproxy_error_remove(pp, 400,
			"Malformed push-proxy request: supplied no valid address");
		return;
	}

	if (
		!host_addr_equal(pp->addr_v4, s->addr) &&
		!host_addr_equal(pp->addr_v6, s->addr)
	) {
		g_warning("push-proxy request from %s (%s) said node was at %s/%s",
			host_addr_to_string(s->addr), pproxy_vendor_str(pp),
			host_addr_port_to_string(pp->addr_v4, pp->port),
			host_addr_port_to_string2(pp->addr_v6, pp->port));
	}

	/*
	 * Locate a route to that servent.
	 */

	n = route_proxy_find(pp->guid);

	if (n != NULL) {
		struct array packet;

		/*
 		 * We set TTL=max_ttl-1 and hops=1 since
		 * it does not come from our node really.
		 */

		packet = build_push(GNET_PROPERTY(max_ttl) - 1, 1, pp->guid,
					pp->addr_v4, pp->addr_v6, pp->port,
					pp->file_idx, supports_tls);

		if (NULL == packet.data) {
			g_warning("Failed to send push for %s/%s (index=%lu)",
				host_addr_port_to_string(pp->addr_v4, pp->port),
				host_addr_port_to_string2(pp->addr_v6, pp->port),
				(gulong) pp->file_idx);
		} else {
			gmsg_sendto_one(n, packet.data, packet.size);
			gnet_stats_count_general(GNR_PUSH_PROXY_RELAYED, 1);

			http_send_status(pp->socket, 202, FALSE, NULL, 0,
					"Push-proxy: message sent to node");

			pp->error_sent = 202;
			pproxy_remove(pp, "Push sent directly to node GUID %s",
					guid_hex_str(pp->guid));
		}

		return;
	}

	/*
	 * Bad luck, no direct connection.  Look for a Gnutella route.
	 */

	if (NULL != (nodes = route_towards_guid(pp->guid))) {
		struct array packet;

		/*
 		 * We set TTL=max_ttl-1 and hops=1 since
		 * it does not come from our node really.
		 */

		packet = build_push(GNET_PROPERTY(max_ttl) - 1, 1, pp->guid,
					pp->addr_v4, pp->addr_v6, pp->port,
					pp->file_idx, supports_tls);

		if (NULL == packet.data) {
			g_warning("Failed to send push to %s/%s (index=%lu)",
				host_addr_port_to_string(pp->addr_v4, pp->port),
				host_addr_port_to_string2(pp->addr_v6, pp->port),
				(gulong) pp->file_idx);
		} else {
			gint cnt;

			gmsg_sendto_all(nodes, packet.data, packet.size);
			gnet_stats_count_general(GNR_PUSH_PROXY_BROADCASTED, 1);

			cnt = g_slist_length(nodes);

			http_send_status(pp->socket, 203, FALSE, NULL, 0,
					"Push-proxy: message sent through Gnutella (via %d node%s)",
					cnt, cnt == 1 ? "" : "s");

			pp->error_sent = 203;
			pproxy_remove(pp, "Push sent via Gnutella (%d node%s) for GUID %s",
					cnt, cnt == 1 ? "" : "s", guid_hex_str(pp->guid));
		}

		g_slist_free(nodes);
		nodes = NULL;
		return;
	}

	/*
	 * If by extraordinary the GUID is ours, honour it immediately by
	 * sending a GIV back.
	 */

	if (guid_eq(pp->guid, GNET_PROPERTY(servent_guid))) {
		upload_send_giv(pp->addr_v4, pp->port, 0, 1, 0,
			"<from push-proxy>", FALSE, pp->flags);

		http_send_status(pp->socket, 202, FALSE, NULL, 0,
			"Push-proxy: you found the target GUID %s",
			guid_hex_str(pp->guid));

		pp->error_sent = 202;
		pproxy_remove(pp, "Push was for our GUID %s", guid_hex_str(pp->guid));

		return;
	}

	/*
	 * Sorry.
	 */

	gnet_stats_count_general(GNR_PUSH_PROXY_FAILED, 1);

	pproxy_error_remove(pp, 410, "Push proxy: no route to servent GUID %s",
		guid_hex_str(pp->guid));
}

/***
 *** I/O header parsing callbacks.
 ***/

static inline struct pproxy *
PPROXY(gpointer obj)
{
	return obj;
}

static void
err_line_too_long(gpointer obj, header_t *unused_head)
{
	(void) unused_head;
	pproxy_error_remove(PPROXY(obj), 413, "Header too large");
}

static void
err_header_error_tell(gpointer obj, gint error)
{
	send_pproxy_error(PPROXY(obj), 413, "%s", header_strerror(error));
}

static void
err_header_error(gpointer obj, gint error)
{
	pproxy_remove(PPROXY(obj), "Failed (%s)", header_strerror(error));
}

static void
err_input_exception(gpointer obj, header_t *unused_head)
{
	(void) unused_head;
	pproxy_remove(PPROXY(obj), "Failed (Input Exception)");
}

static void
err_input_buffer_full(gpointer obj)
{
	pproxy_error_remove(PPROXY(obj), 500, "Input buffer full");
}

static void
err_header_read_error(gpointer obj, gint error)
{
	pproxy_remove(PPROXY(obj), "Failed (Input error: %s)", g_strerror(error));
}

static void
err_header_read_eof(gpointer obj, header_t *unused_head)
{
	(void) unused_head;
	pproxy_remove(PPROXY(obj), "Failed (EOF)");
}

static void
err_header_extra_data(gpointer obj, header_t *unused_head)
{
	(void) unused_head;
	pproxy_error_remove(PPROXY(obj), 400, "Extra data after HTTP header");
}

static const struct io_error pproxy_io_error = {
	err_line_too_long,
	err_header_error_tell,
	err_header_error,
	err_input_exception,
	err_input_buffer_full,
	err_header_read_error,
	err_header_read_eof,
	err_header_extra_data,
};

static void
call_pproxy_request(gpointer obj, header_t *header)
{
	pproxy_request(PPROXY(obj), header);
}

/**
 * Create new push-proxy request and begin reading HTTP headers.
 */
void
pproxy_add(struct gnutella_socket *s)
{
	struct pproxy *pp;

	s->type = SOCK_TYPE_PPROXY;
	socket_tos_default(s);

	pp = pproxy_create(s);

	/*
	 * Read HTTP headers, then call pproxy_request() when done.
	 */

	io_get_header(pp, &pp->io_opaque, BSCHED_BWS_IN, s, IO_HEAD_ONLY,
		call_pproxy_request, NULL, &pproxy_io_error);
}

/**
 * Called a shutdown time.
 */
void
pproxy_close(void)
{
	GSList *l;

	for (l = pproxies; l; l = g_slist_next(l)) {
		struct pproxy *pp = l->data;

		pproxy_free_resources(pp);
		wfree(pp, sizeof *pp);
	}

	g_slist_free(pproxies);
}

/***
 *** Client-side of push-proxy
 ***/

#define CPROXY_MAGIC	0xc8301U

/**
 * Free the structure and all its dependencies.
 */
void
cproxy_free(struct cproxy *cp)
{
	g_assert(cp->magic == CPROXY_MAGIC);

	atom_guid_free_null(&cp->guid);
	if (cp->http_handle != NULL) {
		http_async_cancel(cp->http_handle);
		cp->http_handle = NULL;
	}
	atom_str_free_null(&cp->server);

	cp->magic = 0;
	wfree(cp, sizeof *cp);
}

/**
 * HTTP async callback for error notifications.
 */
static void
cproxy_http_error_ind(struct http_async *handle,
	http_errtype_t type, gpointer v)
{
	struct cproxy *cp = http_async_get_opaque(handle);

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

/**
 * HTTP async callback for header reception notification.
 * @returns whether processing can continue.
 */
static gboolean
cproxy_http_header_ind(struct http_async *handle, header_t *header,
	gint code, const gchar *message)
{
	struct cproxy *cp = http_async_get_opaque(handle);
	gchar *token;
	gchar *server;
	gchar *to_free;

	g_assert(cp != NULL);
	g_assert(cp->d != NULL);
	g_assert(cp->magic == CPROXY_MAGIC);

	/* message is not valid anymore after http_async_cancel() */
	to_free = g_strdup(message);
	message = to_free;

	/*
	 * Extract vendor information.
	 */

	token = header_get(header, "X-Token");
	server = header_get(header, "Server");
	if (server == NULL)
		server = header_get(header, "User-Agent");

	cp->server = validate_vendor(server, token, cp->addr);

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
		g_warning("push-proxy at %s (%s) for %s file #%u reported HTTP %d: %s",
			host_addr_port_to_string(cp->addr, cp->port), cproxy_vendor_str(cp),
			guid_hex_str(cp->guid), cp->file_idx, code, message);
		/* FALL THROUGH */
	case 410:
		download_proxy_failed(cp->d);
		break;
	default:
		g_warning("push-proxy at %s (%s) for %s file #%u "
			"sent unexpected HTTP %d: %s",
			host_addr_port_to_string(cp->addr, cp->port), cproxy_vendor_str(cp),
			guid_hex_str(cp->guid), cp->file_idx, code, message);
		download_proxy_failed(cp->d);
		break;
	}

	if (GNET_PROPERTY(push_proxy_debug) > 0 && cp->sent)
		g_message("PUSH-PROXY at %s (%s) sent PUSH for %s file #%u %s",
			host_addr_port_to_string(cp->addr, cp->port), cproxy_vendor_str(cp),
			guid_hex_str(cp->guid), cp->file_idx,
			cp->directly ? "directly" : "via Gnet");

	G_FREE_NULL(to_free);

	return FALSE;		/* Don't continue -- handle invalid now anyway */
}

/**
 * Redefines the HTTP request building.
 *
 * See http_async_build_request() for the model and details about
 * the various parameters.
 *
 * @return length of generated request.
 */
static size_t
cproxy_build_request(struct http_async *unused_handle, gchar *buf, size_t len,
	const gchar *verb, const gchar *path, const gchar *unused_host,
	guint16 unused_port)
{
	gchar addr_v4_buf[128];
	gchar addr_v6_buf[128];
	host_addr_t addr;
	gboolean has_ipv4 = FALSE;

	(void) unused_handle;
	(void) unused_host;
	(void) unused_port;
	g_assert(len <= INT_MAX);

	addr = listen_addr();
	addr_v4_buf[0] = '\0';
	if (is_host_addr(addr)) {
		has_ipv4 = TRUE;
		concat_strings(addr_v4_buf, sizeof addr_v4_buf,
			"X-Node: ",
			host_addr_port_to_string(addr, GNET_PROPERTY(listen_port)),
			"\r\n",
			(void *) 0);
	}

	addr = listen_addr6();
	addr_v6_buf[0] = '\0';
	if (is_host_addr(addr)) {
		/* Older clients only know X-Node, so if we don't have an IPv4
		 * address, use the X-Node header instead. If they don't support
		 * IPv6 we lose anyway.
		 */
		concat_strings(addr_v6_buf, sizeof addr_v6_buf,
			has_ipv4 ? "X-Node-IPv6: " : "X-Node: ",
			host_addr_port_to_string(addr, GNET_PROPERTY(listen_port)),
			"\r\n",
			(void *) 0);
	}
	
	return gm_snprintf(buf, len,
		"%s %s HTTP/1.1\r\n"
		"User-Agent: %s\r\n"
		"Connection: close\r\n"
		"Host:\r\n"
		"X-Token: %s\r\n"
		"%s"
		"%s"
		"\r\n",
		verb, path, version_string,
		tok_version(),
		addr_v4_buf,
		addr_v6_buf);
}

/**
 * Invoked when the state of the HTTP async request changes.
 */
static void
cproxy_http_newstate(struct http_async *handle, http_state_t newstate)
{
	struct cproxy *cp = http_async_get_opaque(handle);

	g_assert(cp != NULL);
	g_assert(cp->d != NULL);
	g_assert(cp->magic == CPROXY_MAGIC);

	cp->state = newstate;
	download_proxy_newstate(cp->d);
}

/**
 * Create client proxy.
 *
 * @returns NULL if problem during connection.
 */
struct cproxy *
cproxy_create(struct download *d, const host_addr_t addr, guint16 port,
	const struct guid *guid, guint32 file_idx)
{
	struct http_async *handle;
	struct cproxy *cp;
	char path[128];

	concat_strings(path, sizeof path,
		"/gnutella/push-proxy?ServerId=", guid_base32_str(guid),
		tls_enabled() ? "&tls=true" : "",
		(void *) 0);

	/*
	 * Try to connect immediately: if we can't connect, no need to continue.
	 */

	handle = http_async_get_addr(path, addr, port,
		cproxy_http_header_ind, NULL, cproxy_http_error_ind);

	if (handle == NULL) {
		g_warning("can't connect to push-proxy %s for GUID %s: %s",
			host_addr_port_to_string(addr, port), guid_hex_str(guid),
			http_async_strerror(http_async_errno));
		return NULL;
	}

	cp = walloc0(sizeof *cp);

	cp->magic = CPROXY_MAGIC;
	cp->d = d;
	cp->addr = addr;
	cp->port = port;
	cp->guid = atom_guid_get(guid);
	cp->file_idx = file_idx == URN_INDEX ? 0 : file_idx;
	cp->http_handle = handle;
	cp->flags = 0;

	/*
	 * Customize async HTTP layer.
	 */

	http_async_set_opaque(handle, cp, NULL);
	http_async_set_op_request(handle, cproxy_build_request);
	http_async_on_state_change(handle, cproxy_http_newstate);

	return cp;
}

/**
 * Updates the proxy structures to point to the right download when a download
 * was cloned.
 */
void
cproxy_reparent(struct download *d, struct download *cd)
{
	g_assert(d != cd);
	g_assert(d->cproxy != NULL);
	g_assert(cd->cproxy != NULL);
	g_assert(d->cproxy == cd->cproxy);
	g_assert(d->cproxy->magic == CPROXY_MAGIC);

	cd->cproxy->d = cd;
	d->cproxy = NULL;

	g_assert(d->cproxy == NULL);
	g_assert(cd->cproxy != NULL);
	g_assert(cd == cd->cproxy->d);
}

/* vi: set ts=4 sw=4 cindent: */
