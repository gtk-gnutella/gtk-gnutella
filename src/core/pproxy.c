/*
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
 * Push proxy HTTP and set management.
 *
 * @author Raphael Manfredi
 * @date 2003
 */

#include "common.h"

#include "pproxy.h"
#include "http.h"
#include "hosts.h"
#include "version.h"

/* Following extra needed for the server-side */

#include "bsched.h"
#include "ggep.h"
#include "ggep_type.h"
#include "gmsg.h"
#include "gnet_stats.h"
#include "ioheader.h"
#include "ipv6-ready.h"
#include "routing.h"
#include "search.h"				/* For QUERY_FW2FW_FILE_INDEX */
#include "sockets.h"
#include "uploads.h"

#include "lib/url.h"

/* Following extra needed for the client-side */

#include "downloads.h"
#include "features.h"
#include "settings.h"			/* For listen_addr() */
#include "token.h"

#include "lib/ascii.h"
#include "lib/atoms.h"
#include "lib/concat.h"
#include "lib/endian.h"
#include "lib/getline.h"
#include "lib/glib-missing.h"
#include "lib/halloc.h"
#include "lib/hashlist.h"
#include "lib/header.h"
#include "lib/log.h"
#include "lib/parse.h"
#include "lib/sequence.h"
#include "lib/str.h"
#include "lib/tm.h"
#include "lib/unsigned.h"
#include "lib/walloc.h"

#include "if/gnet_property_priv.h"

#include "lib/override.h"		/* Must be the last header included */

/***
 *** Server-side of push-proxy
 ***/

static GSList *pproxies = NULL;	/**< Currently active push-proxy requests */

static void send_pproxy_error(struct pproxy *pp, int code,
	const char *msg, ...) G_GNUC_PRINTF(3, 4);
static void pproxy_error_remove(struct pproxy *pp, int code,
	const char *msg, ...) G_GNUC_PRINTF(3, 4);

static struct socket_ops pproxy_socket_ops;

/**
 * Get rid of all the resources attached to the push-proxy struct.
 * But not the structure itself.
 */
static void
pproxy_free_resources(struct pproxy *pp)
{
	pproxy_check(pp);

	atom_guid_free_null(&pp->guid);
	if (pp->io_opaque != NULL) {
		io_free(pp->io_opaque);
		g_assert(pp->io_opaque == NULL);
	}
	atom_str_free_null(&pp->user_agent);
	socket_free_null(&pp->socket);
}

/**
 * The vectorized (message-wise) version of send_pproxy_error().
 */
static void
send_pproxy_error_v(
	struct pproxy *pp,
	const char *ext,
	int code,
	const char *msg, va_list ap)
{
	char reason[1024];
	char extra[1024];
	http_extra_desc_t hev[1];
	int hevcnt = 0;

	if (msg) {
		str_vbprintf(reason, sizeof reason, msg, ap);
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
	 * If `ext' is not NULL, we have extra header information to propagate.
	 */

	if (ext) {
		size_t extlen = clamp_strcpy(extra, sizeof extra, ext);

		if ('\0' != ext[extlen]) {
			g_warning("%s: ignoring too large extra header (%zu bytes)",
				G_STRFUNC, strlen(ext));
		} else {
			hev[hevcnt].he_type = HTTP_EXTRA_LINE;
			hev[hevcnt++].he_msg = extra;
		}
	}

	http_send_status(HTTP_PUSH_PROXY, pp->socket, code, FALSE,
			hevcnt ? hev : NULL, hevcnt, "%s", reason);

	pp->error_sent = code;
}

/**
 * Send error message to requestor.
 * This can only be done once per connection.
 */
static void
send_pproxy_error(struct pproxy *pp, int code, const char *msg, ...)
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
pproxy_remove_v(struct pproxy *pp, const char *reason, va_list ap)
{
	const char *logreason;
	char errbuf[1024];

	pproxy_check(pp);

	if (reason) {
		str_vbprintf(errbuf, sizeof errbuf , reason, ap);
		logreason = errbuf;
	} else {
		if (pp->error_sent) {
			str_bprintf(errbuf, sizeof errbuf, "HTTP %d", pp->error_sent);
			logreason = errbuf;
		} else {
			errbuf[0] = '\0';
			logreason = "No reason given";
		}
	}

	if (GNET_PROPERTY(push_proxy_debug) > 0) {
		g_debug("push-proxy: ending request from %s (%s): %s",
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
	pp->magic = 0;
	WFREE(pp);

	pproxies = g_slist_remove(pproxies, pp);
}

/**
 * Remove push proxy entry, log reason.
 *
 * If no status has been sent back on the HTTP stream yet, give
 * them a 400 error with the reason.
 */
void G_GNUC_PRINTF(2, 3)
pproxy_remove(struct pproxy *pp, const char *reason, ...)
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
pproxy_error_remove(struct pproxy *pp, int code, const char *msg, ...)
{
	va_list args, errargs;

	pproxy_check(pp);

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

		pproxy_check(pp);

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

	WALLOC0(pp);
	pp->magic = PPROXY_MAGIC;
	pp->socket = s;
	pp->flags = 0; /* XXX: TLS? */
	pp->last_update = tm_time();

	socket_attach_ops(s, SOCK_TYPE_PPROXY, &pproxy_socket_ops, pp);

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
static bool
get_params(struct pproxy *pp, const char *request,
	const struct guid **guid_atom, uint32 *file_idx, bool *supports_tls)
{
	static const struct {
		const char *req;
		const char *attr;
	} req_types[] = {
		{ "/gnutella/pushproxy?",	"ServerId" },
		{ "/gnutella/push-proxy?",	"ServerId" },
		{ "/gnet/push-proxy?",		"guid" },
	};
	char *uri;
	const char *attr;
	char *p;
	const char *value;
	int datalen;
	url_params_t *up;
	uint i;

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
	if (!uri || !is_ascii_blank(uri[0])) {
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
		char *q;

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
		struct guid buf;
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
			g_debug("PUSH-PROXY: decoding %s=%s as base32", attr, value);

		guid = base32_to_guid(value, &buf);
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
			g_debug("PUSH-PROXY: decoding %s=%s as hexadecimal", attr, value);

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
		int error;

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
 * @param ttl		the TTL to use for the packet header.
 * @param hops		the hops value to use for the packet header.
 * @param guid		the hops value to use for the packet header.
 * @param addr_v4	the IPv4 address the receiving peer should connect to.
 * @param addr_v6	the IPv6 address the receiving peer should connect to.
 * @param port		the port number the receiving peer should connect to.
 * @param file_idx	the file index this push is for.
 *
 * @return	A pointer to a static buffer holding the created Gnutella PUSH
 *			packet on success, an empty array on failure.
 */
struct array
build_push(uint8 ttl, uint8 hops, const struct guid *guid,
	host_addr_t addr_v4, host_addr_t addr_v6, uint16 port,
	uint32 file_idx, bool supports_tls)
{
	static union {
		gnutella_msg_push_request_t m;
		char data[1024];
	} packet;
	char *p = packet.data;
	size_t len = 0, size = sizeof packet;
	ggep_stream_t gs;
	host_addr_t primary;
	uint32 ipv4;

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

	/*
	 * IPv6-Ready: our primary address is the IPv4 one, IPv6 being a fallback.
	 */

	primary = is_host_addr(addr_v4) ? addr_v4 : addr_v6;

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
	}

	/*
	 * IPv6-Ready support: the PUSH message is architected with an IPv4 address.
	 * When the address we want to send is an IPv6 one, it needs to be sent
	 * in a GGEP "6" field, the IPv4 field being set to 127.0.0.0.
	 */

	ipv4 = ipv6_ready_advertised_ipv4(primary);

	if (
		ipv6_ready_has_no_ipv4(ipv4) ||
		(is_host_addr(addr_v6) && host_addr_is_ipv6(addr_v6))
	) {
		const uint8 *ipv6 = host_addr_ipv6(&addr_v6);

		g_assert(ipv6 != NULL);

		if (!ggep_stream_pack(&gs, GGEP_NAME(6), ipv6, 16, 0)) {
			g_warning("could not write GGEP \"6\" extension into PUSH");
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
	gnutella_msg_push_request_set_host_ip(&packet.m, ipv4);
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
static const char *
validate_vendor(char *vendor, char *token, const host_addr_t addr)
{
	const char *result;

	if (vendor) {
		bool faked = !version_check(vendor, token, addr);

		if (faked) {
			char name[1024];

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
	const char *endptr;
	host_addr_t addr;
	uint16 port;

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
	const char *request = getline_str(s->getline);
	struct gnutella_node *n;
	const char *buf;
	char *token;
	char *user_agent;
	GSList *nodes;
	bool supports_tls = FALSE;

	if (GNET_PROPERTY(push_proxy_trace) & SOCK_TRACE_IN) {
		g_debug("----Push-proxy request from %s:\n%s",
			host_addr_to_string(s->addr), request);
		header_dump(stderr, header, "----");
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

	if (QUERY_FW2FW_FILE_INDEX == pp->file_idx)
		gnet_stats_inc_general(GNR_PUSH_PROXY_TCP_FW2FW);

	if (GNET_PROPERTY(push_proxy_debug) > 0) {
		if (QUERY_FW2FW_FILE_INDEX == pp->file_idx) {
			g_debug("PUSH-PROXY: %s requesting FW-FW connection with %s",
				host_addr_to_string(s->addr), guid_hex_str(pp->guid));
		} else {
			g_debug("PUSH-PROXY: %s requesting a push to %s for file #%d",
				host_addr_to_string(s->addr), guid_hex_str(pp->guid),
				pp->file_idx);
		}
	}

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

	if (!route_guid_pushable(pp->guid))
		goto sorry;

	n = route_proxy_find(pp->guid);

	/*
	 * Even if they did no ask for us to be their proxy, locate nodes to
	 * which we are connected to see if haven't learned of their GUID
	 * by looking at the query hits they sent out: see update_neighbour_info().
	 *		--RAM, 2009-03-14
	 */

	if (NULL == n) {
		n = node_by_guid(pp->guid);
		if (n != NULL)
			gnet_stats_inc_general(GNR_PUSH_PROXY_ROUTE_NOT_PROXIED);
	}

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
			g_warning("failed to send push for %s/%s (index=%lu)",
				host_addr_port_to_string(pp->addr_v4, pp->port),
				host_addr_port_to_string2(pp->addr_v6, pp->port),
				(ulong) pp->file_idx);
		} else {
			gmsg_sendto_one(n, packet.data, packet.size);
			gnet_stats_inc_general(GNR_PUSH_PROXY_TCP_RELAYED);

			http_send_status(HTTP_PUSH_PROXY, pp->socket, 202, FALSE, NULL, 0,
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
				(ulong) pp->file_idx);
		} else {
			int cnt;

			gmsg_sendto_all(nodes, packet.data, packet.size);
			gnet_stats_inc_general(GNR_PUSH_PROXY_BROADCASTED);

			cnt = g_slist_length(nodes);

			http_send_status(HTTP_PUSH_PROXY, pp->socket, 203, FALSE, NULL, 0,
					"Push-proxy: message sent through Gnutella (via %d node%s)",
					cnt, cnt == 1 ? "" : "s");

			pp->error_sent = 203;
			pproxy_remove(pp, "Push sent via Gnutella (%d node%s) for GUID %s",
					cnt, cnt == 1 ? "" : "s", guid_hex_str(pp->guid));
		}

		gm_slist_free_null(&nodes);
		return;
	}

	/*
	 * If by extraordinary the GUID is ours, honour it immediately by
	 * sending a GIV back.
	 */

	if (guid_eq(pp->guid, GNET_PROPERTY(servent_guid))) {
		upload_send_giv(pp->addr_v4, pp->port, 0, 1, 0,
			"<from push-proxy>", pp->flags);

		http_send_status(HTTP_PUSH_PROXY, pp->socket, 202, FALSE, NULL, 0,
			"Push-proxy: you found the target GUID %s",
			guid_hex_str(pp->guid));

		pp->error_sent = 202;
		pproxy_remove(pp, "Push was for our GUID %s", guid_hex_str(pp->guid));

		return;
	}

	/*
	 * Sorry.
	 */

sorry:
	gnet_stats_inc_general(GNR_PUSH_PROXY_FAILED);

	pproxy_error_remove(pp, 410, "Push proxy: no route to servent GUID %s",
		guid_hex_str(pp->guid));
}

/***
 *** I/O header parsing callbacks.
 ***/

static inline struct pproxy *
PPROXY(void *obj)
{
	return obj;
}

static void
err_line_too_long(void *obj, header_t *unused_head)
{
	(void) unused_head;
	pproxy_error_remove(PPROXY(obj), 413, "Header too large");
}

static void
err_header_error_tell(void *obj, int error)
{
	send_pproxy_error(PPROXY(obj), 413, "%s", header_strerror(error));
}

static void
err_header_error(void *obj, int error)
{
	pproxy_remove(PPROXY(obj), "Failed (%s)", header_strerror(error));
}

static void
err_input_exception(void *obj, header_t *unused_head)
{
	(void) unused_head;
	pproxy_remove(PPROXY(obj), "Failed (Input Exception)");
}

static void
err_input_buffer_full(void *obj)
{
	pproxy_error_remove(PPROXY(obj), 500, "Input buffer full");
}

static void
err_header_read_error(void *obj, int error)
{
	pproxy_remove(PPROXY(obj), "Failed (Input error: %s)", g_strerror(error));
}

static void
err_header_read_eof(void *obj, header_t *unused_head)
{
	(void) unused_head;
	pproxy_remove(PPROXY(obj), "Failed (EOF)");
}

static void
err_header_extra_data(void *obj, header_t *unused_head)
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
call_pproxy_request(void *obj, header_t *header)
{
	pproxy_request(PPROXY(obj), header);
}

/**
 * Callback invoked when the push-proxy socket is destroyed.
 */
static void
pproxy_socket_destroy(gnutella_socket_t *s, void *owner, const char *reason)
{
	struct pproxy *pp = owner;

	pproxy_check(pp);
	g_assert(s == pp->socket);

	pproxy_remove(pp, "%s", reason);
}

/**
 * Server-side push-proxy socket callbacks.
 */
static struct socket_ops pproxy_socket_ops = {
	NULL,						/* connect_failed */
	NULL,						/* connected */
	pproxy_socket_destroy,		/* destroy */
};

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
		pp->magic = 0;
		WFREE(pp);
	}

	gm_slist_free_null(&pproxies);
}

/***
 *** Client-side of push-proxy
 ***/

#define CPROXY_UDP_MS	5000		/**< in milliseconds */

static void cproxy_http_request(struct cproxy *cp);

static inline void
cproxy_check(const struct cproxy *cp)
{
	g_assert(cp != NULL);
	g_assert(CPROXY_MAGIC == cp->magic);
	g_assert(cp->d != NULL);
	g_assert(cp->d->cproxy == cp);
}

/**
 * Free the structure and all its dependencies.
 */
void
cproxy_free(struct cproxy *cp)
{
	cproxy_check(cp);

	atom_guid_free_null(&cp->guid);
	if (cp->http_handle != NULL) {
		http_async_cancel(cp->http_handle);
		cp->http_handle = NULL;
	}
	atom_str_free_null(&cp->server);
	cq_cancel(&cp->udp_ev);

	cp->magic = 0;
	WFREE(cp);
}

/**
 * HTTP async callback for error notifications.
 */
static void
cproxy_http_error_ind(struct http_async *handle, http_errtype_t type, void *v)
{
	struct cproxy *cp = http_async_get_opaque(handle);

	cproxy_check(cp);

	http_async_log_error(handle, type, v, "HTTP push-proxy request");

	cp->http_handle = NULL;
	cp->done = TRUE;

	if (
		type == HTTP_ASYNC_ERROR &&
		(
			GPOINTER_TO_INT(v) == HTTP_ASYNC_CANCELLED ||
			GPOINTER_TO_INT(v) == HTTP_ASYNC_CLOSED
		)
	)
		return;

	download_proxy_failed(cp->d);
}

/**
 * HTTP async callback for header reception notification.
 * @returns whether processing can continue.
 */
static bool
cproxy_http_header_ind(struct http_async *handle, header_t *header,
	int code, const char *message)
{
	struct cproxy *cp = http_async_get_opaque(handle);
	char *token;
	char *server;
	char *to_free;

	cproxy_check(cp);

	/* message is not valid anymore after http_async_cancel() */
	to_free = h_strdup(message);
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
		g_debug("PUSH-PROXY at %s (%s) sent PUSH for %s file #%u %s",
			host_addr_port_to_string(cp->addr, cp->port), cproxy_vendor_str(cp),
			guid_hex_str(cp->guid), cp->file_idx,
			cp->directly ? "directly" : "via Gnet");

	HFREE_NULL(to_free);

	return FALSE;		/* Don't continue -- handle invalid now anyway */
}

/**
 * Redefines the HTTP request building.
 *
 * See http_async_build_get_request() for the model and details about
 * the various parameters.
 *
 * @return length of generated request.
 */
static size_t
cproxy_build_request(const struct http_async *ha,
	char *buf, size_t len, const char *verb, const char *path)
{
	char addr_v4_buf[128];
	char addr_v6_buf[128];
	host_addr_t addr;
	bool has_ipv4 = FALSE;

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
	
	return str_bprintf(buf, len,
		"%s %s HTTP/1.1\r\n"
		"User-Agent: %s\r\n"
		"Connection: close\r\n"
		"Host: %s\r\n"
		"X-Token: %s\r\n"
		"%s"
		"%s"
		"\r\n",
		verb, path, version_string,
		http_async_remote_host_port(ha),
		tok_version(),
		addr_v4_buf,
		addr_v6_buf);
}

/**
 * Redefine callback invoked when the HTTP request has been sent.
 *
 * @param unused_ha		the (unused) HTTP async request descriptor
 * @param s				the socket on which we wrote the request
 * @param req			the actual request string
 * @param len			the length of the request string
 * @param deferred		if TRUE, full request sending was deferred earlier
 */
static void
cproxy_sent_request(const struct http_async *unused_ha,
	const struct gnutella_socket *s, const char *req, size_t len,
	bool deferred)
{
	(void) unused_ha;

	if (GNET_PROPERTY(push_proxy_trace) & SOCK_TRACE_OUT) {
		g_debug("----Sent push-proxy request%s to %s (%zu bytes):",
			deferred ? " completely" : "",
			host_addr_port_to_string(s->addr, s->port), len);
		dump_string(stderr, req, len, "----");
	}
}

/**
 * Redefine callback invoked when we got the whole HTTP reply.
 *
 * @param unused_ha		the (unused) HTTP async request descriptor
 * @param s				the socket on which we got the reply
 * @param status		the first HTTP status line
 * @param header		the parsed header structure
 */
static void
cproxy_got_reply(const struct http_async *unused_ha,
	const struct gnutella_socket *s, const char *status, const header_t *header)
{
	(void) unused_ha;

	if (GNET_PROPERTY(push_proxy_trace) & SOCK_TRACE_IN) {
		g_debug("----Got push-proxy reply from %s:",
			host_addr_to_string(s->addr));
		if (log_printable(LOG_STDERR)) {
			fprintf(stderr, "%s\n", status);
			header_dump(stderr, header, "----");
		}
	}
}

/**
 * Invoked when the state of the HTTP async request changes.
 */
static void
cproxy_http_newstate(struct http_async *handle, http_state_t newstate)
{
	struct cproxy *cp = http_async_get_opaque(handle);

	cproxy_check(cp);

	cp->state = newstate;
	download_proxy_newstate(cp->d);
}

static void
cproxy_http_start(cqueue_t *cq, void *obj)
{
	struct cproxy *cp = obj;

	cproxy_check(cp);

	cq_zero(cq, &cp->udp_ev);
	cproxy_http_request(cp);
}

/**
 * Asynchronous calling of cproxy_http_request(), so that the call happens
 * on another call stack, after cproxy_create() has returned.
 */
static void
cproxy_async_http_request(struct cproxy *cp)
{
	g_assert(cp != NULL);
	g_assert(CPROXY_MAGIC == cp->magic);

	cp->udp_ev = cq_main_insert(1, cproxy_http_start, cp);
}

/**
 * Create client proxy.
 *
 * @returns created client proxy.
 */
struct cproxy *
cproxy_create(struct download *d, const host_addr_t addr, uint16 port,
	const struct guid *guid, uint32 file_idx)
{
	struct cproxy *cp;
	struct array packet;

	WALLOC0(cp);
	cp->magic = CPROXY_MAGIC;
	cp->d = d;
	cp->addr = addr;
	cp->port = port;
	cp->guid = atom_guid_get(guid);
	cp->file_idx = file_idx == URN_INDEX ? 0 : file_idx;
	cp->flags = 0;

	/*
	 * Most push-proxies nowadays support routing PUSH messages received
	 * through UDP, and UDP is faster than establishing a TCP connection
	 * and issuing an HTTP request.
	 *
	 * Hence our strategy is to send an UDP packet to the proxy and wait for
	 * a while by arming a timer firing in CPROXY_UDP_MS.
	 *
	 * If the PUSH reaches its destination and the recipient comes back to us
	 * via a GIV callback and the proper download is selected, this push-proxy
	 * request will be cancelled, along with the timer.
	 *
	 * If no reply is received, the timer will fire and then we will switch
	 * back to establishing a TCP connection to the push-proxy.
	 *		--RAM, 2010-10-17
	 */

	packet = build_push(GNET_PROPERTY(max_ttl), 0 /* Hops */,
		cp->guid, listen_addr(), listen_addr6(), cp->port,
		cp->file_idx, tls_enabled());

	if (packet.data) {
		if (download_send_udp_push(packet, cp->addr, cp->port)) {
			cp->udp_ev = cq_main_insert(CPROXY_UDP_MS, cproxy_http_start, cp);
		} else {
			cproxy_async_http_request(cp);	/* Must be asynchronous */
		}
	} else {
		cproxy_async_http_request(cp);		/* Must be asynchronous */
	}

	return cp;
}

/**
 * Issue client proxy HTTP request.
 */
static void
cproxy_http_request(struct cproxy *cp)
{
	struct http_async *handle;
	char path[128];

	cproxy_check(cp);
	g_assert(NULL == cp->udp_ev);

	concat_strings(path, sizeof path,
		"/gnutella/push-proxy?ServerId=", guid_base32_str(cp->guid),
		tls_enabled() ? "&tls=true" : "",
		(void *) 0);

	/*
	 * Try to connect immediately: if we can't connect, no need to continue.
	 */

	handle = http_async_get_addr(path, cp->addr, cp->port,
		cproxy_http_header_ind, NULL, cproxy_http_error_ind);

	if (handle == NULL) {
		if (GNET_PROPERTY(download_debug)) {
			g_warning("can't connect to push-proxy %s for GUID %s: %s",
				host_addr_port_to_string(cp->addr, cp->port),
				guid_hex_str(cp->guid),
				http_async_strerror(http_async_errno));
		}
		download_proxy_failed(cp->d);
		return;
	}

	cp->http_handle = handle;
	cp->state = http_async_state(handle);

	/*
	 * Customize async HTTP layer.
	 */

	http_async_set_opaque(handle, cp, NULL);
	http_async_set_op_get_request(handle, cproxy_build_request);
	http_async_set_op_headsent(handle, cproxy_sent_request);
	http_async_set_op_gotreply(handle, cproxy_got_reply);
	http_async_on_state_change(handle, cproxy_http_newstate);
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

/***
 *** Set of push-proxies.
 ***/

enum pproxy_set_magic { PPROXY_SET_MAGIC = 0x4349802fU };

/**
 * A collection of push-proxies, used to hold all the known push-proxies for
 * a given servent (including ourselves).
 *
 * Newer entries are added at the head of the list.
 *
 * When dealing with push-proxies for download purposes, we should attempt to
 * use proxies in the order they are given, i.e. the freshest ones first.
 *
 * When dealing with our push-proxies, we must hand out the most stable entries
 * first, since they are the ones which are the most likely to be around for
 * a little while.  This means we must get entries in reverse order from the
 * tail of the list.
 */
struct pproxy_set {
	enum pproxy_set_magic magic;	/**< Magic number */
	time_t last_update;				/**< Last time we updated the list */
	hash_list_t *proxies;			/**< Known push proxies (gnet_host_t) */
	size_t max_proxies;				/**< Max amount we want (0 for unlimited) */
};

static inline void
pproxy_set_check(const pproxy_set_t *ps)
{
	g_assert(ps != NULL);
	g_assert(PPROXY_SET_MAGIC == ps->magic);
}

/**
 * @return amount of push-proxies held in the set.
 */
size_t
pproxy_set_count(const pproxy_set_t *ps)
{
	pproxy_set_check(ps);

	return hash_list_length(ps->proxies);
}

/**
 * @return whether timestamp is more recent than last addition made to
 * the push-proxy set.
 */
bool
pproxy_set_older_than(const pproxy_set_t *ps, time_t t)
{
	if (NULL == ps)
		return TRUE;

	pproxy_set_check(ps);
	return delta_time(t, ps->last_update) >= 0;
}

/**
 * Create a new set of push-proxies.
 *
 * @param max_proxies		maximum amount we want to keep (0 for unlimited)
 *
 * @return the newly created set of push-proxies.
 */
pproxy_set_t *
pproxy_set_allocate(size_t max_proxies)
{
	pproxy_set_t *ps;

	g_assert(size_is_non_negative(max_proxies));

	WALLOC0(ps);
	ps->magic = PPROXY_SET_MAGIC;
	ps->proxies = hash_list_new(gnet_host_hash, gnet_host_eq);
	ps->max_proxies = max_proxies;

	return ps;
}

/**
 * Dispose of the push-proxy set and nullify the pointer.
 */
void
pproxy_set_free_null(pproxy_set_t **ps_ptr)
{
	pproxy_set_t *ps = *ps_ptr;

	if (ps != NULL) {
		pproxy_set_check(ps);
		hash_list_free_all(&ps->proxies, gnet_host_free);
		ps->magic = 0;
		WFREE(ps);

		*ps_ptr = NULL;
	}
}

/**
 * Trim set so that we do not keep too many entries.
 */
static void
pproxy_set_trim(const pproxy_set_t *ps)
{
	pproxy_set_check(ps);

	if (0 == ps->max_proxies)
		return;					/* Unlimited length */

	while (hash_list_length(ps->proxies) > ps->max_proxies) {
		gnet_host_t *host = hash_list_remove_tail(ps->proxies);
		gnet_host_free(host);
	}
}

/**
 * Add a push-proxy to the set.
 *
 * @return TRUE if host was added, FALSE if we already knew it.
 */
bool
pproxy_set_add(pproxy_set_t *ps, const host_addr_t addr, uint16 port)
{
	gnet_host_t host;
	bool added = FALSE;

	pproxy_set_check(ps);

	gnet_host_set(&host, addr, port);
	if (hash_list_contains(ps->proxies, &host)) {
		hash_list_moveto_head(ps->proxies, &host);
	} else {
		hash_list_prepend(ps->proxies, gnet_host_dup(&host));
		pproxy_set_trim(ps);
		added = TRUE;
	}

	ps->last_update = tm_time();

	return added;
}

/**
 * Add hosts in the vector to the push-proxy set.
 */
void
pproxy_set_add_vec(pproxy_set_t *ps, const gnet_host_vec_t *vec)
{
	int i;

	pproxy_set_check(ps);

	for (i = gnet_host_vec_count(vec) - 1; i >= 0; i--) {
		gnet_host_t host = gnet_host_vec_get(vec, i);
		if (hash_list_contains(ps->proxies, &host)) {
			hash_list_moveto_head(ps->proxies, &host);
		} else {
			hash_list_prepend(ps->proxies, gnet_host_dup(&host));
		}
	}

	pproxy_set_trim(ps);
	ps->last_update = tm_time();
}

/**
 * Add hosts in the `proxies' array to the push-proxy set.
 */
void
pproxy_set_add_array(pproxy_set_t *ps, gnet_host_t *proxies, int proxy_count)
{
	int i;

	pproxy_set_check(ps);

	for (i = 0; i < proxy_count; i++) {
		if (hash_list_contains(ps->proxies, &proxies[i])) {
			hash_list_moveto_head(ps->proxies, &proxies[i]);
		} else {
			hash_list_prepend(ps->proxies, gnet_host_dup(&proxies[i]));
		}
	}

	pproxy_set_trim(ps);
	ps->last_update = tm_time();
}

/**
 * Remove a push-proxy from the set.
 *
 * @return TRUE if push-proxy was found and removed, FALSE if it was missing.
 */
bool
pproxy_set_remove(pproxy_set_t *ps, const host_addr_t addr, uint16 port)
{
	gnet_host_t key;
	gnet_host_t *item;

	pproxy_set_check(ps);

	gnet_host_set(&key, addr, port);
	item = hash_list_remove(ps->proxies, &key);

	if (item != NULL) {
		gnet_host_free(item);
		return TRUE;
	}

	return FALSE;
}

/**
 * Apply function to each of the push-proxies in the set.
 */
void
pproxy_set_foreach(const pproxy_set_t *ps, GFunc func, void *user_data)
{
	pproxy_set_check(ps);

	hash_list_foreach(ps->proxies, func, user_data);
}

/**
 * Create a sequence to iterate on the push-proxy set.
 * Items in the sequence are of type gnet_host_t *.
 *
 * @return sequence encapsulation which can be freed by sequence_release().
 */
sequence_t *
pproxy_set_sequence(const pproxy_set_t *ps)
{
	if (NULL == ps)
		return sequence_create_from_glist(NULL);	/* Empty sequence */

	pproxy_set_check(ps);
	return sequence_create_from_hash_list(ps->proxies);
}

/**
 * Get first item from push-proxy set.
 *
 * @return host or NULL if set is empty.
 */
gnet_host_t *
pproxy_set_head(const pproxy_set_t *ps)
{
	return ps ? hash_list_head(ps->proxies) : NULL;
}

/**
 * Get a host vector out of the push-proxy set.
 *
 * @return a host vector that must be freed with gnet_host_vec_free().
 */
gnet_host_vec_t *
pproxy_set_host_vec(const pproxy_set_t *ps)
{
	if (NULL == ps)
		return NULL;

	pproxy_set_check(ps);
	return gnet_host_vec_from_hash_list(ps->proxies);
}

/**
 * @return most ancient push proxy, NULL if none are recorded.
 */
const gnet_host_t *
pproxy_set_oldest(const pproxy_set_t *ps)
{
	pproxy_set_check(ps);

	return hash_list_tail(ps->proxies);
}

/* vi: set ts=4 sw=4 cindent: */
