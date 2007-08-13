/*
 * $Id$
 *
 * Copyright (c) 2001-2003, Raphael Manfredi
 * Copyright (c) 2000 Daniel Walker (dwalker@cats.ucsc.edu)
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
 * Socket management.
 *
 * @author Daniel Walker (dwalker@cats.ucsc.edu)
 * @date 2000
 * @author Raphael Manfredi
 * @date 2001-2003
 */

#include "common.h"

RCSID("$Id$")

#ifdef I_NETDB
#include <netdb.h>
#endif
#ifdef I_PWD
#include <pwd.h>
#endif

#include "sockets.h"
#include "downloads.h"
#include "features.h"
#include "uploads.h"
#include "parq.h"
#include "nodes.h"
#include "bsched.h"
#include "ban.h"
#include "http.h"
#include "inet.h"
#include "hostiles.h"
#include "pproxy.h"
#include "udp.h"
#include "settings.h"
#include "tls_cache.h"

#include "shell/shell.h"

#include "if/gnet_property.h"
#include "if/gnet_property_priv.h"

#include "lib/socket.h"
#include "lib/adns.h"
#include "lib/getline.h"
#include "lib/glib-missing.h"
#include "lib/endian.h"
#include "lib/header.h"
#include "lib/tm.h"
#include "lib/walloc.h"

#ifdef HAS_SOCKER_GET
#include <socker.h>
#endif /* HAS_SOCKER_GET */

#include "lib/override.h"		/* Must be the last header included */

#ifndef SHUT_WR
/* XXX: This should be handled by Configure because SHUT_* are sometimes
 *		enums instead of macro definitions.
 */
#define SHUT_WR 1					/**< Shutdown TX side */
#endif

#define RQST_LINE_LENGTH	256	/**< Reasonable estimate for request line */
#define SOCK_UDP_RECV_BUF	131072	/**< 128K - Large to avoid loosing dgrams */

#define SOCK_ADNS_PENDING	0x01	/**< Don't free() the socket too early */
#define SOCK_ADNS_FAILED	0x02	/**< Signals error in the ADNS callback */
#define SOCK_ADNS_BADNAME	0x04	/**< Signals bad host name */

struct gnutella_socket *s_tcp_listen = NULL;
struct gnutella_socket *s_tcp_listen6 = NULL;
struct gnutella_socket *s_udp_listen = NULL;
struct gnutella_socket *s_udp_listen6 = NULL;
struct gnutella_socket *s_local_listen = NULL;

static void socket_accept(gpointer data, gint, inputevt_cond_t cond);

static struct gnutella_socket *
socket_alloc(void)
{
	static const struct gnutella_socket zero_socket;
	struct gnutella_socket *s;

	s = walloc(sizeof *s);
	*s = zero_socket;
	s->magic = SOCKET_MAGIC;
	return s;
}

static void
socket_alloc_buffer(struct gnutella_socket *s)
{
	socket_check(s);
	g_assert((0 == s->buf_size) ^ (NULL != s->buf));

	if (!s->buf) {
		s->buf_size = SOCK_BUFSZ;
		s->buf = g_malloc(s->buf_size);
	}
}

static void
socket_free_buffer(struct gnutella_socket *s)
{
	socket_check(s);
	g_assert((0 == s->buf_size) ^ (NULL != s->buf));

	if (s->buf) {
		s->buf_size = 0;
		G_FREE_NULL(s->buf);
	}
}

void
socket_dealloc(struct gnutella_socket **s_ptr)
{
	struct gnutella_socket *s;

	g_assert(s_ptr);
	s = *s_ptr;
	if (s) {
		socket_check(s);
		s->magic = 0;
		wfree(s, sizeof *s);
		*s_ptr = NULL;
	}
}

host_addr_t
socket_ipv6_trt_map(const host_addr_t addr)
{
	if (
		GNET_PROPERTY(use_ipv6_trt) &&
		NET_TYPE_IPV4 == host_addr_net(addr) &&
		NET_TYPE_IPV6 == host_addr_net(GNET_PROPERTY(ipv6_trt_prefix))
	) {
		host_addr_t ret;

		ret = GNET_PROPERTY(ipv6_trt_prefix);
		poke_be32(&ret.addr.ipv6[12], host_addr_ipv4(addr));
		return ret;
	}
	return addr;
}

/**
 * Return the file descriptor to use for I/O monitoring callbacks on
 * the socket.
 */
gint
socket_evt_fd(struct gnutella_socket *s)
{
	gint fd = -1;

	socket_check(s);
	switch (s->direction) {
	case SOCK_CONN_LISTENING:
		g_assert(s->file_desc >= 0);
		fd = s->file_desc;
		break;

	case SOCK_CONN_INCOMING:
	case SOCK_CONN_OUTGOING:
	case SOCK_CONN_PROXY_OUTGOING:
		g_assert(s->wio.fd);
		fd = s->wio.fd(&s->wio);
		g_assert(fd >= 0);
		break;
	}
	g_assert(-1 != fd);

	return fd;
}

/**
 * Install handler callback when an input condition is satisfied on the socket.
 *
 * @param s			the socket
 * @param cond		Any INPUT_EVENT_* except INPUT_EVENT_EXCEPTION.
 * @param handler	the handler callback to invoke when condition is satisfied
 * @param data		opaque data to supply to the callback
 *
 * @note
 * When monitoring for INPUT_EVENT_RW(X), both INPUT_EVENT_R and
 * INPUT_EVENT_W flags can be set at the same time when the callback is
 * invoked.
 */
void
socket_evt_set(struct gnutella_socket *s,
	inputevt_cond_t cond, inputevt_handler_t handler, gpointer data)
{
	gint fd;

	socket_check(s);
	g_assert(handler);
	g_assert(INPUT_EVENT_EXCEPTION != cond);
	g_assert((0 != (INPUT_EVENT_R & cond)) ^ (0 != (INPUT_EVENT_W & cond)));
	g_assert(0 == s->gdk_tag);

	fd = socket_evt_fd(s);

#ifdef HAS_GNUTLS
	s->tls.cb_cond = cond;
	s->tls.cb_handler = handler;
	s->tls.cb_data = data;

	if (GNET_PROPERTY(tls_debug) > 1)
		g_message("socket_evt_set: fd=%d, cond=%s, handler=%p",
			fd, inputevt_cond_to_string(cond), handler);
#endif /* HAS_GNUTLS */

	s->gdk_tag = inputevt_add(fd, cond, handler, data);
	g_assert(0 != s->gdk_tag);
	
	if (!(INPUT_EVENT_W & cond) && s->wio.flush(&s->wio) < 0) {
		if (!is_temporary_error(errno)) {
			g_warning("socket_evt_set: flush error: %s", g_strerror(errno));
		}
	}
}

/**
 * Remove I/O readiness monitoring on the socket.
 */
void
socket_evt_clear(struct gnutella_socket *s)
{
	socket_check(s);

	if (s->gdk_tag) {
#ifdef HAS_GNUTLS
		if (GNET_PROPERTY(tls_debug) > 1) {
			gint fd = socket_evt_fd(s);
			g_message("socket_evt_clear: fd=%d, cond=%s, handler=%p",
				fd, inputevt_cond_to_string(s->tls.cb_cond), s->tls.cb_handler);
		}

		s->tls.cb_cond = 0;
		s->tls.cb_handler = NULL;
		s->tls.cb_data = NULL;
#endif /* HAS_GNUTLS */
		inputevt_remove(s->gdk_tag);
		s->gdk_tag = 0;
	}
}

/*
 * In order to avoid having a dependency between sockets.c and ban.c,
 * we have ban.c register a callback to reclaim file descriptors
 * at init time.
 *		--RAM, 2004-08-18
 */
static reclaim_fd_t reclaim_fd = NULL;

/**
 * Register fd reclaiming callback.
 * Use NULL to unregister it.
 */
void
socket_register_fd_reclaimer(reclaim_fd_t callback)
{
	reclaim_fd = callback;
}

static GSList *sl_incoming = NULL;	/**< To spot inactive sockets */

static void guess_local_addr(struct gnutella_socket *s);
static void socket_destroy(struct gnutella_socket *s, const gchar *reason);
static void socket_connected(gpointer data, gint source, inputevt_cond_t cond);
static void socket_wio_link(struct gnutella_socket *s);

/*
 * SOL_TCP and SOL_IP aren't standards. Some platforms define them, on
 * some it's safe to assume they're the same as IPPROTO_*, but the
 * only way to be portably safe is to use protoent functions.
 *
 * If the user changes /etc/protocols while running gtkg, things may
 * go badly.
 */
static gboolean sol_got = FALSE;
static gint sol_tcp_cached = -1;
static gint sol_ip_cached = -1;
static gint sol_ipv6_cached = -1;

/**
 * Compute and cache values for SOL_TCP and SOL_IP.
 */
static void
get_sol(void)
{
	struct protoent *pent;

#ifdef IPPROTO_IP
	sol_ip_cached = IPPROTO_IP;
#endif /* IPPROTO_IP */
#ifdef IPPROTO_IPV6
	sol_ipv6_cached = IPPROTO_IPV6;
#endif /* IPPROTO_IPV6 */
#ifdef IPPROTO_TCP
	sol_tcp_cached = IPPROTO_TCP;
#endif /* IPPROTO_TCP */

	pent = getprotobyname("ip");
	if (NULL != pent)
		sol_ip_cached = pent->p_proto;
	pent = getprotobyname("ipv6");
	if (NULL != pent)
		sol_ipv6_cached = pent->p_proto;
	pent = getprotobyname("tcp");
	if (NULL != pent)
		sol_tcp_cached = pent->p_proto;

	sol_got = TRUE;
}

/**
 * @returns SOL_TCP.
 */
static gint
sol_tcp(void)
{
	g_assert(sol_got);
	return sol_tcp_cached;
}

/**
 * @returns SOL_IP.
 */
static gint
sol_ip(void)
{
	g_assert(sol_got);
	return sol_ip_cached;
}

/**
 * @returns SOL_IPV6.
 */
static gint
sol_ipv6(void)
{
	g_assert(sol_got);
	return sol_ipv6_cached;
}

#ifdef USE_IP_TOS

/**
 * Set the TOS on the socket.  Routers can use this information to
 * better route the IP datagrams.
 */
static gint
socket_tos(const struct gnutella_socket *s, gint tos)
{
	socket_check(s);
	g_return_val_if_fail(NET_TYPE_NONE != s->net, 0);

	if (
		GNET_PROPERTY(use_ip_tos) &&
		NET_TYPE_IPV4 == s->net &&
		-1 == setsockopt(s->file_desc, sol_ip(), IP_TOS, &tos, sizeof tos)
	) {
		if (ECONNRESET != errno) {
			const gchar *tosname;

			switch (tos) {
			case 0: tosname = "default"; break;
			case IPTOS_LOWDELAY: tosname = "low delay"; break;
			case IPTOS_THROUGHPUT: tosname = "throughput"; break;
			default:
				tosname = NULL;
				g_assert_not_reached();
			}
			g_warning("unable to set IP_TOS to %s (%d) on fd#%d: %s",
				tosname, tos, s->file_desc, g_strerror(errno));
		}
		return -1;
	}

	return 0;
}

/**
 * Pick an appropriate default TOS for packets on the socket, based
 * on the socket's type.
 */
void
socket_tos_default(const struct gnutella_socket *s)
{
	socket_check(s);
	switch (s->type) {
	case SOCK_TYPE_DOWNLOAD: /* ACKs w/ low latency => higher transfer rates */
		socket_tos_lowdelay(s);
		break;
	case SOCK_TYPE_UPLOAD:
		socket_tos_throughput(s);
		break;
	case SOCK_TYPE_CONTROL:
	case SOCK_TYPE_HTTP:
	case SOCK_TYPE_PPROXY:
	default:
		socket_tos_normal(s);
	}
}
#else
static gint
socket_tos(const struct gnutella_socket *unused_s, gint unused_tos)
{
	(void) unused_s;
	(void) unused_tos;
	return 0;
}

void
socket_tos_default(const struct gnutella_socket *unused_s)
{
	(void) unused_s;
	/* Empty */
}
#endif /* USE_IP_TOS */

/**
 * Set the Type of Service (TOS) field to "normal."
 */
void
socket_tos_normal(const struct gnutella_socket *s)
{
	socket_tos(s, 0);
}

/**
 * Set the Type of Service (TOS) field to "lowdelay." This may cause
 * your host and/or any routers along the path to put its packets in
 * a higher-priority queue, and/or to route them along the lowest-
 * latency path without regard for bandwidth.
 */
void
socket_tos_lowdelay(const struct gnutella_socket *s)
{
	static gboolean failed;

	if (!failed)
		failed = 0 != socket_tos(s, IPTOS_LOWDELAY);
}

/**
 * Set the Type of Service (TOS) field to "throughput." This may cause
 * your host and/or any routers along the path to put its packets in
 * a lower-priority queue, and/or to route them along the highest-
 * bandwidth path without regard for latency.
 */
void
socket_tos_throughput(const struct gnutella_socket *s)
{
	static gboolean failed;

	if (!failed)
		failed = 0 != socket_tos(s, IPTOS_THROUGHPUT);
}

/**
 * Got an EOF condition on the socket.
 */
void
socket_eof(struct gnutella_socket *s)
{
	socket_check(s);

	s->flags |= SOCK_F_EOF;
}

static void
proxy_connect_helper(const host_addr_t *addr, size_t n, gpointer udata)
{
	gboolean *in_progress = udata;

	g_assert(addr);
	g_assert(in_progress);
	*in_progress = FALSE;

	if (n > 0) {
		/* Just pick the first address */
		gnet_prop_set_ip_val(PROP_PROXY_ADDR, addr[0]);
		g_message("Resolved proxy name \"%s\" to %s",
			GNET_PROPERTY(proxy_hostname), host_addr_to_string(addr[0]));
	} else {
		g_message("Could not resolve proxy name \"%s\"",
			GNET_PROPERTY(proxy_hostname));
	}
}

/**
 * Verifies the proxy settings.
 *
 * @return TRUE if a proxy is configured.
 */
static gboolean
proxy_is_enabled(void)
{
	switch ((enum proxy_protocol) GNET_PROPERTY(proxy_protocol)) {
	case PROXY_NONE:
		return FALSE;
	case PROXY_HTTP:
	case PROXY_SOCKSV4:
	case PROXY_SOCKSV5:
		return 0 != GNET_PROPERTY(proxy_port) &&
				'\0' != GNET_PROPERTY(proxy_hostname)[0];
	}
	g_assert_not_reached();
}

/*
 * The socks 4/5 code was taken from tsocks 1.16 Copyright (C) 2000 Shaun
 * Clowes It was modified to work with gtk_gnutella and non-blocking sockets.
 * --DW
 */
static int
proxy_connect(int fd)
{
	static gboolean in_progress = FALSE;
	socket_addr_t server;
	socklen_t len;

	if (!is_host_addr(GNET_PROPERTY(proxy_addr)) && proxy_is_enabled()) {
		if (!in_progress) {
			in_progress = TRUE;
			g_warning("Resolving proxy name \"%s\"",
				GNET_PROPERTY(proxy_hostname));
			adns_resolve(GNET_PROPERTY(proxy_hostname), settings_dns_net(),
				proxy_connect_helper, &in_progress);
		}

		if (in_progress) {
			errno = VAL_EAGAIN;
			return -1;
		}
	}

	if (
		!is_host_addr(GNET_PROPERTY(proxy_addr)) ||
		!GNET_PROPERTY(proxy_port)
	) {
		errno = EINVAL;
		return -1;
	}

	len = socket_addr_set(&server,
			GNET_PROPERTY(proxy_addr), GNET_PROPERTY(proxy_port));
	return connect(fd, socket_addr_get_const_sockaddr(&server), len);
}

static gint
send_socks4(struct gnutella_socket *s)
{
	size_t length;
	ssize_t ret;
	host_addr_t addr;

	socket_check(s);

	/* SOCKS4 is IPv4 only */
	if (!host_addr_convert(s->addr, &addr, NET_TYPE_IPV4))
		return -1;

	/* Create the request */
	{
		struct {
			guint8 version;
			guint8 command;
			guint8 dstport[2];
			guint8 dstip[4];
			/* A null terminated username goes here */
		} *req;

		STATIC_ASSERT(8 == sizeof *req);

		req = cast_to_gpointer(s->buf);
		req->version = 4;	/* SOCKS 4 */
		req->command = 1;	/* Connect */
		poke_be16(req->dstport, s->port);
		poke_be32(req->dstip, host_addr_ipv4(addr));
		length = sizeof *req;
	}

	/* XXX: Shouldn't this use the configured username instead? */
	/* Determine the current username */
	{
		const struct passwd *user;
		const gchar *name;
		size_t name_size;

		user = getpwuid(getuid());
		name = user != NULL ? user->pw_name : "";
		name_size = 1 + strlen(name);

		/* Make sure the request fits into the socket buffer */
		if (
			name_size >= s->buf_size ||
			length + name_size > s->buf_size
		) {
			/* Such a long username would be insane, no need to malloc(). */
			g_warning("send_socks4(): Username is too long");
			return -1;
		}

		/* Copy the username */
		memcpy(&s->buf[length], name, name_size);
		length += name_size;
	}

	/* Send the socks header info */
	ret = write(s->file_desc, s->buf, length);

	if ((size_t) ret != length) {
		g_warning("Error attempting to send SOCKS request (%s)",
			ret == (ssize_t) -1 ? strerror(errno) : "Partial write");
		return -1;
	}

	return 0;
}

static gint
recv_socks4(struct gnutella_socket *s)
{
	struct {
		guint8 version;
		guint8 result;
		guint8 ignore1[2];
		guint8 ignore2[4];
	} reply;
	static const size_t size = sizeof reply;
	ssize_t ret;

	STATIC_ASSERT(8 == sizeof reply);
	socket_check(s);

	ret = read(s->file_desc, cast_to_gpointer(&reply), size);
	if ((ssize_t) -1 == ret) {
		g_warning("Error attempting to receive SOCKS reply (%s)",
			g_strerror(errno));
		return ECONNREFUSED;
	}
	if ((size_t) ret != size) {
		g_warning("Short reply from SOCKS server");
		/* Let the application try and see how they go */
		return ECONNREFUSED;
	}

	ret = (ssize_t) -1;
	switch (reply.result) {
	case 91:
		g_warning("SOCKS server refused connection");
		break;

	case 92:
		g_warning("SOCKS server refused connection "
				   "because of failed connect to identd "
				   "on this machine");
		break;

	case 93:
		g_warning("SOCKS server refused connection "
				   "because identd and this library "
				   "reported different user-ids");
		break;

	default:
		ret = 0;
	}

	if (0 != ret) {
		errno = ECONNREFUSED;
		return -1;
	}

	return 0;
}

static gint
connect_http(struct gnutella_socket *s)
{
	ssize_t ret;
	size_t parsed;
	gint status;
	const gchar *str;

	socket_check(s);

	switch (s->pos) {
	case 0:
		{
			static const struct {
				const gchar *s;
			} parts[] = {
				{ "CONNECT " }, { NULL }, { " HTTP/1.0\r\nHost: " }, { NULL },
				{ "\r\n\r\n" },
			};
			struct iovec iov[G_N_ELEMENTS(parts)];
			const gchar *host_port = host_addr_port_to_string(s->addr, s->port);
			size_t size = 0;
			guint i;

			for (i = 0; i < G_N_ELEMENTS(iov); i++) {
				iov[i].iov_base = deconstify_gchar(
									parts[i].s ? parts[i].s : host_port);
				size += iov[i].iov_len = strlen(iov[i].iov_base);
			}

			ret = writev(s->file_desc, iov, G_N_ELEMENTS(iov));
			if ((size_t) ret != size) {
				g_warning("Sending info to HTTP proxy failed: %s",
					ret == (ssize_t) -1 ? g_strerror(errno) : "Partial write");
				return -1;
			}
		}
		s->pos++;
		break;

	case 1:
		ret = read(s->file_desc, s->buf, s->buf_size - 1);
		if (ret == (ssize_t) -1) {
			g_warning("Receiving answer from HTTP proxy failed: %s",
				g_strerror(errno));
			return -1;
		}
		if (!s->getline)
			s->getline = getline_make(HEAD_MAX_SIZE);

		switch (getline_read(s->getline, s->buf, ret, &parsed)) {
		case READ_OVERFLOW:
			g_warning("HTTP proxy returned a too long line");
			return -1;
		case READ_DONE:
			if ((size_t) ret != parsed)
				memmove(s->buf, &s->buf[parsed], ret - parsed);
			ret -= parsed;
			break;
		case READ_MORE:
			g_assert(parsed == (size_t) ret);
			return 0;
		}
		str = getline_str(s->getline);
		if ((status = http_status_parse(str, NULL, NULL, NULL, NULL)) < 0) {
			g_warning("Bad status line");
			return -1;
		}
		if ((status / 100) != 2) {
			g_warning("Cannot use HTTP proxy: \"%s\"", str);
			return -1;
		}
		s->pos++;

		while (ret != 0) {
			getline_reset(s->getline);
			switch (getline_read(s->getline, s->buf, ret, &parsed)) {
			case READ_OVERFLOW:
				g_warning("HTTP proxy returned a too long line");
				return -1;
			case READ_DONE:
				if ((size_t) ret != parsed)
					memmove(s->buf, &s->buf[parsed], ret - parsed);
				ret -= parsed;
				if (getline_length(s->getline) == 0) {
					s->pos++;
					getline_free(s->getline);
					s->getline = NULL;
					return 0;
				}
				break;
			case READ_MORE:
				g_assert(parsed == (size_t) ret);
				return 0;
			}
		}
		break;
	case 2:
		ret = read(s->file_desc, s->buf, s->buf_size - 1);
		if (ret == (ssize_t) -1) {
			g_warning("Receiving answer from HTTP proxy failed: %s",
				g_strerror(errno));
			return -1;
		}
		while (ret != 0) {
			getline_reset(s->getline);
			switch (getline_read(s->getline, s->buf, ret, &parsed)) {
			case READ_OVERFLOW:
				g_warning("HTTP proxy returned a too long line");
				return -1;
			case READ_DONE:
				if ((size_t) ret != parsed)
					memmove(s->buf, &s->buf[parsed], ret - parsed);
				ret -= parsed;
				if (getline_length(s->getline) == 0) {
					s->pos++;
					getline_free(s->getline);
					s->getline = NULL;
					return 0;
				}
				break;
			case READ_MORE:
				g_assert(parsed == (size_t) ret);
				return 0;
			}
		}
		break;
	}

	return 0;
}

/*
0: Send
1: Recv
..
4: Send
5: Recv

6: Done
*/

static gint
connect_socksv5(struct gnutella_socket *s)
{
	static const gchar verstring[] = "\x05\x02\x02";
	ssize_t ret = 0;
	size_t size;
	const gchar *name;
	gint sockid;
	host_addr_t addr;

	socket_check(s);

	sockid = s->file_desc;

	if (!host_addr_convert(s->addr, &addr, NET_TYPE_IPV4))
		addr = s->addr;

	{
		gboolean ok = FALSE;

		switch (host_addr_net(addr)) {
		case NET_TYPE_IPV4:
			ok = TRUE;
			break;
		case NET_TYPE_IPV6:
#ifdef HAS_IPV6
			ok = TRUE;
			break;
#endif /* HAS_IPV6 */
		case NET_TYPE_LOCAL:
		case NET_TYPE_NONE:
			break;
		}
		if (!ok)
			return ECONNREFUSED;
	}

	switch (s->pos) {
	case 0:
		/* Now send the method negotiation */
		size = sizeof verstring;
		ret = write(sockid, verstring, size);
		if ((size_t) ret != size) {
			g_warning("Sending SOCKS method negotiation failed: %s",
				ret == (ssize_t) -1 ? g_strerror(errno) : "Partial write");
			return -1;
		}
		s->pos++;
		break;

	case 1:
		/* Now receive the reply as to which method we're using */
		size = 2;
		ret = read(sockid, s->buf, size);
		if (ret == (ssize_t) -1) {
			g_warning("Receiving SOCKS method negotiation reply failed: %s",
				g_strerror(errno));
			return ECONNREFUSED;
		}

		if ((size_t) ret != size) {
			g_warning("Short reply from SOCKS server");
			return ECONNREFUSED;
		}

		/* See if we offered an acceptable method */
		if (s->buf[1] == '\xff') {
			g_warning("SOCKS server refused authentication methods");
			return ECONNREFUSED;
		}

		if (
			s->buf[1] == 2 &&
			GNET_PROPERTY(socks_user) != NULL &&
			GNET_PROPERTY(socks_user)[0] != '\0'
		) {
		   	/* has provided user info */
			s->pos++;
		} else {
			s->pos += 3;
		}
		break;
	case 2:
		/* If the socks server chose username/password authentication */
		/* (method 2) then do that */

		if (GNET_PROPERTY(socks_user) != NULL) {
			name = GNET_PROPERTY(socks_user);
		} else {
			const struct passwd *pw;

			/* Determine the current *nix username */
			pw = getpwuid(getuid());
			name = pw != NULL ? pw->pw_name : NULL;
		}

		if (name == NULL) {
			g_warning("No Username to authenticate with.");
			return ECONNREFUSED;
		}

		if (GNET_PROPERTY(socks_pass) == NULL) {
			g_warning("No Password to authenticate with.");
			return ECONNREFUSED;
		}

		if (strlen(name) > 255 || strlen(GNET_PROPERTY(socks_pass)) > 255) {
			g_warning("Username or password exceeds 255 characters.");
			return ECONNREFUSED;
		}

		size = gm_snprintf(s->buf, s->buf_size, "\x01%c%s%c%s",
					(guchar) strlen(name),
					name,
					(guchar) strlen(GNET_PROPERTY(socks_pass)),
					GNET_PROPERTY(socks_pass));

		/* Send out the authentication */
		ret = write(sockid, s->buf, size);
		if ((size_t) ret != size) {
			g_warning("Sending SOCKS authentication failed: %s",
				ret == (ssize_t) -1 ? g_strerror(errno) : "Partial write");
			return -1;
		}

		s->pos++;

		break;
	case 3:
		/* Receive the authentication response */
		size = 2;
		ret = read(sockid, s->buf, size);
		if (ret == (ssize_t) -1) {
			g_warning("Receiving SOCKS authentication reply failed: %s",
				g_strerror(errno));
			return ECONNREFUSED;
		}

		if ((size_t) ret != size) {
			g_warning("Short reply from SOCKS server");
			return ECONNREFUSED;
		}

		if (s->buf[1] != '\0') {
			g_warning("SOCKS authentication failed, "
					   "check username and password");
			return ECONNREFUSED;
		}
		s->pos++;
		break;
	case 4:
		/* Now send the connect */
		s->buf[0] = 0x05;		/* Version 5 SOCKS */
		s->buf[1] = 0x01;		/* Connect request */
		s->buf[2] = 0x00;		/* Reserved		*/

		size = 0;
		switch (host_addr_net(addr)) {
		case NET_TYPE_IPV4:
			s->buf[3] = 0x01;		/* IP version 4	*/
			poke_be32(&s->buf[4], host_addr_ipv4(addr));
			poke_be16(&s->buf[8], s->port);
			size = 10;
			break;

		case NET_TYPE_IPV6:
#ifdef HAS_IPV6
			s->buf[3] = 0x04;		/* IP version 6	*/
			memcpy(&s->buf[4], host_addr_ipv6(&addr), 16);
			poke_be16(&s->buf[20], s->port);
			size = 22;
			break;
#endif /* HAS_IPV6 */
		case NET_TYPE_LOCAL:
		case NET_TYPE_NONE:
			g_assert_not_reached();
		}

		g_assert(0 != size);

		/* Now send the connection */

		ret = write(sockid, s->buf, size);
		if ((size_t) ret != size) {
			g_warning("Send SOCKS connect command failed: %s",
				ret == (ssize_t) -1 ? g_strerror(errno) : "Partial write");
			return (-1);
		}

		s->pos++;
		break;
	case 5:
		/* Now receive the reply to see if we connected */

		size = 10;
		ret = read(sockid, s->buf, size);
		if ((ssize_t) -1 == ret) {
			g_warning("Receiving SOCKS connection reply failed: %s",
				g_strerror(errno));
			return ECONNREFUSED;
		}
		if (GNET_PROPERTY(socket_debug))
			g_message("connect_socksv5: Step 5, bytes recv'd %d\n", (int) ret);
		if ((size_t) ret != size) {
			g_warning("Short reply from SOCKS server");
			return ECONNREFUSED;
		}

		/* See the connection succeeded */
		if (s->buf[1] != '\0') {
			g_warning("SOCKS connect failed: ");
			switch (s->buf[1]) {
			case 1:
				g_warning("General SOCKS server failure");
				return ECONNABORTED;
			case 2:
				g_warning("Connection denied by rule");
				return ECONNABORTED;
			case 3:
				g_warning("Network unreachable");
				return ENETUNREACH;
			case 4:
				g_warning("Host unreachable");
				return EHOSTUNREACH;
			case 5:
				g_warning("Connection refused");
				return ECONNREFUSED;
			case 6:
				g_warning("TTL Expired");
				return ETIMEDOUT;
			case 7:
				g_warning("Command not supported");
				return ECONNABORTED;
			case 8:
				g_warning("Address type not supported");
				return ECONNABORTED;
			default:
				g_warning("Unknown error");
				return ECONNABORTED;
			}
		}

		s->pos++;
		break;
	}

	return 0;
}

/**
 * Checks whether our current IPv6 address has changed and updates it
 * if a change is detected.
 */
static void
socket_check_ipv6_address(void)
{
	switch (GNET_PROPERTY(network_protocol)) {
	case NET_USE_IPV4:
		return;
	case NET_USE_BOTH:
	case NET_USE_IPV6:
		break;
	}
	if (!GNET_PROPERTY(force_local_ip6)) {
		GSList *sl_addrs, *sl;
		host_addr_t addr, old_addr, first_addr;

		addr = zero_host_addr;
		first_addr = zero_host_addr;
		old_addr = listen_addr6();
		
		sl_addrs = host_addr_get_interface_addrs(NET_TYPE_IPV6);
		for (sl = sl_addrs; NULL != sl; sl = g_slist_next(sl)) {
			host_addr_t *addr_ptr;

			addr_ptr = sl->data;
			addr = *addr_ptr;
			if (!host_addr_is_routable(addr)) {
				continue;
			}
			if (host_addr_equal(old_addr, addr)) {
				break;
			}
			if (!is_host_addr(first_addr)) {
				first_addr = addr;
			}
		}
		host_addr_free_interface_addrs(&sl_addrs);
		if (!is_host_addr(addr)) {
			addr = first_addr;
		}
		if (!host_addr_equal(old_addr, addr)) {
			gnet_prop_set_ip_val(PROP_LOCAL_IP6, addr);
		}
	}
}

static void
socket_enable_accept(struct gnutella_socket *s)
{
	/* For convience allow passing NULL here */
	if (s) {
		socket_check(s);
		if (0 == s->gdk_tag) {
			socket_evt_set(s, INPUT_EVENT_RX, socket_accept, s);
		}
	}
}

/**
 * Called by main timer.
 * Expires inactive sockets.
 */
void
socket_timer(time_t now)
{
	GSList *l;
	GSList *to_remove = NULL;

	for (l = sl_incoming; l; l = g_slist_next(l)) {
		struct gnutella_socket *s = l->data;
		time_delta_t delta;

		socket_check(s);
		g_assert(s->last_update);
		/*
		 * Last_update can be in the feature due to parq. This is needed
		 * to avoid dropping the connection
		 */
		delta = delta_time(now, s->last_update);
		if (delta > (time_delta_t) GNET_PROPERTY(incoming_connecting_timeout)) {
			if (GNET_PROPERTY(socket_debug)) {
				g_warning("connection from %s timed out (%d bytes read)",
					  host_addr_to_string(s->addr), (int) s->pos);
				if (s->pos > 0)
					dump_hex(stderr, "Connection Header",
						s->buf, MIN(s->pos, 80));
			}
			to_remove = g_slist_prepend(to_remove, s);
		}
	}

	for (l = to_remove; l; l = g_slist_next(l)) {
		struct gnutella_socket *s = l->data;
		socket_destroy(s, "Connection timeout");
	}
	g_slist_free(to_remove);

	{
		static time_t last_check;

		if (!last_check || delta_time(now, last_check) > 30) {
			last_check = now;
			socket_check_ipv6_address();
		}
	}

	socket_enable_accept(s_tcp_listen);
	socket_enable_accept(s_tcp_listen6);
	socket_enable_accept(s_local_listen);
}

/**
 * Cleanup data structures on shutdown.
 */
void
socket_shutdown(void)
{
	while (sl_incoming) {
		struct gnutella_socket *s = sl_incoming->data;

		socket_check(s);
		socket_destroy(s, NULL);
	}

	/* No longer accept connections or UDP packets */
	socket_free_null(&s_local_listen);
	socket_free_null(&s_tcp_listen);
	socket_free_null(&s_tcp_listen6);
	socket_free_null(&s_udp_listen);
	socket_free_null(&s_udp_listen6);
}

/* ----------------------------------------- */

/**
 * Destroy a socket.
 *
 * If there is an attached resource, call the resource's termination routine
 * with the supplied reason.
 */
static void
socket_destroy(struct gnutella_socket *s, const gchar *reason)
{
	socket_check(s);

	/*
	 * If there is an attached resource, its removal routine is responsible
	 * for calling back socket_free().
	 */

	switch (s->type) {
	case SOCK_TYPE_CONTROL:
		if (s->resource.node) {
			node_remove(s->resource.node, "%s", reason);
			return;
		}
		break;
	case SOCK_TYPE_DOWNLOAD:
		if (s->resource.download) {
			download_stop(s->resource.download, GTA_DL_ERROR, "%s", reason);
			return;
		}
		break;
	case SOCK_TYPE_UPLOAD:
		if (s->resource.upload) {
			upload_remove(s->resource.upload, "%s", reason);
			return;
		}
		break;
	case SOCK_TYPE_PPROXY:
		if (s->resource.pproxy) {
			pproxy_remove(s->resource.pproxy, "%s", reason);
			return;
		}
		break;
	case SOCK_TYPE_HTTP:
		if (s->resource.handle) {
			http_async_error(s->resource.handle, HTTP_ASYNC_IO_ERROR);
			return;
		}
		break;
	default:
		break;
	}

	/*
	 * No attached resource, we can simply free this socket then.
	 */

	socket_free_null(&s);
}

struct socket_linger {
	guint tag;	/* Holds the result of inputevt_add() */
};

static void
socket_linger_cb(gpointer data, gint fd, inputevt_cond_t unused_cond)
{
	struct socket_linger *ctx = data;

	(void) unused_cond;
	g_assert(fd >= 0);
	g_assert(NULL != data);
	g_assert(0 != ctx->tag);

	if (close(fd)) {
		gint e = errno;

		if (!is_temporary_error(e))
			g_warning("close(%d) failed: %s", fd, g_strerror(e));

		/* remove the handler in case of EBADF because it would
		 * cause looping otherwise */
		if (EBADF != e)
			return;
	} else {
		g_message("socket_linger_cb: close() succeeded");
	}

	inputevt_remove(ctx->tag);
	wfree(ctx, sizeof *ctx);
}

static void
socket_linger_close(gint fd)
{
	struct socket_linger *ctx;

	g_assert(fd >= 0);

	ctx = walloc(sizeof *ctx);
	ctx->tag = inputevt_add(fd, INPUT_EVENT_RX, socket_linger_cb, ctx);
	g_assert(0 != ctx->tag);
}

/**
 * Dispose of socket, closing connection, removing input callback, and
 * reclaiming attached getline buffer.
 */
static void
socket_free(struct gnutella_socket *s)
{
	socket_check(s);

	if (s->flags & SOCK_F_EOF)
		bws_sock_closed(s->type, TRUE);
	else if (s->flags & SOCK_F_ESTABLISHED)
		bws_sock_closed(s->type, FALSE);
	else
		bws_sock_connect_timeout(s->type);

	if (s->flags & SOCK_F_UDP) {
		if (s->resource.handle)
			wfree(s->resource.handle, sizeof(socket_addr_t));
	}
	if (s->last_update) {
		g_assert(sl_incoming);
		sl_incoming = g_slist_remove(sl_incoming, s);
		s->last_update = 0;
	}
	socket_evt_clear(s);
	if (s->adns & SOCK_ADNS_PENDING) {
		s->type = SOCK_TYPE_DESTROYING;
		return;
	}
	if (s->getline) {
		getline_free(s->getline);
		s->getline = NULL;
	}

#ifdef HAS_GNUTLS
	if (s->tls.ctx) {
		if (s->file_desc != -1 && SOCK_TLS_ESTABLISHED == s->tls.stage) {
			gboolean is_incoming = SOCK_CONN_INCOMING == s->direction;

			if (!is_incoming) {
				tls_cache_insert(s->addr, s->port);
			}
			tls_bye(s->tls.ctx, is_incoming);
		}
		tls_free(&s->tls.ctx);
	}
#endif	/* HAS_GNUTLS */

	if (s->file_desc != -1) {
		if (s->corked)
			sock_cork(s, FALSE);
		sock_tx_shutdown(s);
		if (close(s->file_desc)) {
			gint e = errno;

			if (!is_temporary_error(e))
				g_warning("close(%d) failed: %s", s->file_desc, g_strerror(e));

			if (EBADF != e) /* just in case, as it would cause looping */
				socket_linger_close(s->file_desc);
		}
		s->file_desc = -1;
	}
	socket_free_buffer(s);
	socket_dealloc(&s);
}

void
socket_free_null(struct gnutella_socket **s_ptr)
{
	g_assert(s_ptr);

	if (*s_ptr) {
		socket_free(*s_ptr);
		*s_ptr = NULL;
	}
}

/**
 * @return	0 on success. On failure -1 is returned and errno is set.
 *			If the error is temporary, the handshake was incomplete
 *			and the same I/O handler will be called again which must call
 *			socket_tls_setup() once more.
 */
static gboolean
socket_tls_setup(struct gnutella_socket *s)
#ifdef HAS_GNUTLS
{
	if (!s->tls.enabled) {
		return 0;
	}

	if (s->tls.stage < SOCK_TLS_INITIALIZED) {
		s->tls.ctx = tls_init(s);
		if (!s->tls.ctx) {
			goto destroy;
		}
		s->tls.stage = SOCK_TLS_INITIALIZED;
	}

	if (s->tls.stage < SOCK_TLS_ESTABLISHED) {
		switch (tls_handshake(s)) {
		case TLS_HANDSHAKE_ERROR:
			goto destroy;
		case TLS_HANDSHAKE_RETRY:
			errno = VAL_EAGAIN;
			return -1;
		case TLS_HANDSHAKE_FINISHED:
			s->tls.stage = SOCK_TLS_ESTABLISHED;
			if (SOCK_CONN_INCOMING != s->direction) {
				tls_cache_insert(s->addr, s->port);
			}
			socket_wio_link(s);				/* Link to the I/O functions */
			return 0;
		}
		g_assert_not_reached();
		goto destroy;
	}
	return 0;

destroy:
	errno = EIO;
	return -1;
}
#else	/* HAVE_GNUTLS */
{
	(void) s;
	return 0;
}
#endif	/* HAVE_GNUTLS */

/**
 * Used for incoming connections, for outgoing too??
 * Read bytes on an unknown incoming socket. When the first line
 * has been read it's decided on what type cof connection this is.
 * If the first line is not complete on the first call, this function
 * will be called as often as necessary to fetch a full line.
 */
static void
socket_read(gpointer data, gint source, inputevt_cond_t cond)
{
	struct gnutella_socket *s = data;
	size_t count;
	ssize_t r;
	size_t parsed;
	const gchar *first, *endptr;
	time_t banlimit;

	(void) source;

	if (cond & INPUT_EVENT_EXCEPTION) {
		socket_destroy(s, "Input exception");
		return;
	}

	g_assert(0 == s->pos);		/* We read a line, then leave this callback */

#ifdef HAS_GNUTLS
	if (s->direction == SOCK_CONN_INCOMING) {
		if (s->tls.enabled && s->tls.stage < SOCK_TLS_INITIALIZED) {
			ssize_t ret;
			guchar c;

			/* Peek at the socket buffer to check whether the incoming
			 * connection uses TLS or not. */
			ret = recv(s->file_desc, &c, sizeof c, MSG_PEEK);
			if ((ssize_t) -1 == ret) {
				if (!is_temporary_error(errno)) {
					socket_destroy(s, _("Read error"));
				}
				/* If recv() failed only temporarily, wait for further data. */
				return;
			} else if (0 == ret) {
				socket_destroy(s, _("Got EOF"));
				return;
			} else {
				g_assert(1 == ret);

				if (GNET_PROPERTY(tls_debug) > 2)
					g_message("socket_read(): c=0x%02x", c);

				if (is_ascii_alnum(c) || '\n' == c || '\r' == c) {
					s->tls.enabled = FALSE;
				}
			}
		}

		if (0 != socket_tls_setup(s)) {
			if (!is_temporary_error(errno)) {
				socket_destroy(s, "TLS handshake failed");
			}
			return;
		}
	}
#endif /* HAS_GNUTLS */

	socket_alloc_buffer(s);

	g_assert(s->buf_size >= s->pos);
	count = s->buf_size - s->pos;

	/* 1 to allow trailing NUL */
	if (count < 1) {
		g_warning("socket_read(): incoming buffer full, disconnecting from %s",
			 host_addr_to_string(s->addr));
		dump_hex(stderr, "Leading Data", s->buf, MIN(s->pos, 256));
		socket_destroy(s, "Incoming buffer full");
		return;
	}
	count--; /* Account for trailing NUL */

	/*
	 * Don't read too much data.  We're solely interested in getting
	 * the leading line.  If we don't read the whole line, we'll come
	 * back later on to read the remaining data.
	 *		--RAM, 23/05/2002
	 */

	count = MIN(count, RQST_LINE_LENGTH);

	r = bws_read(BSCHED_BWS_IN, &s->wio, &s->buf[s->pos], count);
	switch (r) {
	case 0:
		socket_destroy(s, "Got EOF");
		return;
	case (ssize_t) -1:
		if (!is_temporary_error(errno))
			socket_destroy(s, _("Read error"));
		return;
	default:
		s->last_update = tm_time();
		s->pos += r;
	}

	if (!s->getline) {
		s->getline = getline_make(MAX_LINE_SIZE);
	}

	/*
	 * Get first line.
	 */

	switch (getline_read(s->getline, s->buf, s->pos, &parsed)) {
	case READ_OVERFLOW:
		g_warning("socket_read(): first line too long, disconnecting from %s",
			 host_addr_to_string(s->addr));
		dump_hex(stderr, "Leading Data",
			getline_str(s->getline), MIN(getline_length(s->getline), 256));
		if (
			is_strprefix(s->buf, "GET ") ||
			is_strprefix(s->buf, "HEAD ")
		)
			http_send_status(s, 414, FALSE, NULL, 0, "Requested URL Too Large");
		socket_destroy(s, "Requested URL too large");
		return;
	case READ_DONE:
		if (s->pos != parsed)
			memmove(s->buf, &s->buf[parsed], s->pos - parsed);
		s->pos -= parsed;
		break;
	case READ_MORE:		/* ok, but needs more data */
	default:
		g_assert(parsed == s->pos);
		s->pos = 0;
		return;
	}

	/*
	 * We come here only when we got the first line of data.
	 *
	 * Whatever happens now, we're not going to use the existing read
	 * callback, and we'll no longer monitor the socket via the `sl_incoming'
	 * list: if it's a node connection, we'll monitor the node, if it's
	 * an upload, we'll monitor the upload.
	 */

	socket_evt_clear(s);
	sl_incoming = g_slist_remove(sl_incoming, s);
	s->last_update = 0;

	first = getline_str(s->getline);

	/*
	 * Always authorize replies for our PUSH requests.
	 * Likewise for PARQ download resuming.
	 */

	if (is_strprefix(first, "GIV ")) {
		download_push_ack(s);
		return;
	}

	if (is_strprefix(first, "QUEUE ")) {
		parq_download_queue_ack(s);
		return;
	}

	/*
	 * Check for banning.
	 */

	switch (ban_allow(s->addr)) {
	case BAN_OK:				/* Connection authorized */
		break;
	case BAN_FORCE:				/* Connection refused, no ack */
		ban_force(s);
		goto cleanup;
	case BAN_MSG:				/* Send specific 403 error message */
		{
			const gchar *msg = ban_message(s->addr);

            if (GNET_PROPERTY(socket_debug)) {
                g_message("rejecting connection from banned %s (%s still): %s",
                    host_addr_to_string(s->addr),
					short_time(ban_delay(s->addr)), msg);
            }

			if (is_strprefix(first, GNUTELLA_HELLO)) {
				send_node_error(s, 503, "%s", msg);
			} else {
				http_extra_desc_t hev;

				http_extra_callback_set(&hev, http_retry_after_add,
					GUINT_TO_POINTER(ban_delay(s->addr)));
				http_send_status(s, 503, FALSE, &hev, 1, "%s", msg);
			}
		}
		goto cleanup;
	case BAN_FIRST:				/* Connection refused, negative ack */
		if (is_strprefix(first, GNUTELLA_HELLO))
			send_node_error(s, 550, "Banned for %s",
				short_time_ascii(ban_delay(s->addr)));
		else {
			gint delay = ban_delay(s->addr);
			http_extra_desc_t hev;

			http_extra_callback_set(&hev, http_retry_after_add,
				GUINT_TO_POINTER(delay));
			http_send_status(s, 550, FALSE, &hev, 1,
				"Banned for %s", short_time_ascii(delay));
		}
		goto cleanup;
	default:
		g_assert_not_reached();
	}

	/*
	 * Check for PARQ banning.
	 * 		-- JA, 29/07/2003
	 */

	banlimit = parq_banned_source_expire(s->addr);
	if (banlimit) {
		if (GNET_PROPERTY(socket_debug))
			g_warning("[sockets] PARQ has banned host %s until %s",
				host_addr_to_string(s->addr), timestamp_to_string(banlimit));
		ban_force(s);
		goto cleanup;
	}

	/*
	 * Deny connections from hostile IP addresses.
	 *
	 * We do this after banning checks so that if they hammer us, they
	 * get banned silently.
	 */

	if (hostiles_check(s->addr)) {
		static const gchar msg[] = "Hostile IP address banned";

		socket_disable_token(s);

		if (GNET_PROPERTY(socket_debug))
			g_warning("denying connection from hostile %s: \"%s\"",
				host_addr_to_string(s->addr), first);
		if (is_strprefix(first, GNUTELLA_HELLO))
			send_node_error(s, 550, msg);
		else
			http_send_status(s, 550, FALSE, NULL, 0, msg);
		goto cleanup;
	}

	/*
	 * Dispatch request. Here we decide what kind of connection this is.
	 */

	if (is_strprefix(first, GNUTELLA_HELLO)) {
		/* Incoming control connection */
		node_add_socket(s, s->addr, s->port, 0);
	} else if (
		NULL != (endptr = is_strprefix(first, "GET ")) ||
		NULL != (endptr = is_strprefix(first, "HEAD "))
	) {
		const gchar *uri;

		/*
		 * We have to decide whether this is an upload request or a
		 * push-proxyfication request.
		 */

		uri = skip_ascii_blanks(endptr);

		if (is_strprefix(uri, "/gnutella/") || is_strprefix(uri, "/gnet/"))
			pproxy_add(s);
		else
			upload_add(s);
	} else if (
		NULL != (endptr = is_strprefix(first, "HELO")) &&
		(is_ascii_space(endptr[0]) || '\0' == endptr[0])
	) {
		getline_set_maxlen(s->getline, SHELL_MAX_LINE_SIZE);
        shell_add(s);
	} else
		goto unknown;

	/* Socket might be free'ed now */

	return;

unknown:
	if (GNET_PROPERTY(socket_debug)) {
		size_t len = getline_length(s->getline);
		g_warning("socket_read(): got unknown incoming connection from %s, "
			"dropping!", host_addr_to_string(s->addr));
		if (len > 0)
			dump_hex(stderr, "First Line", first, MIN(len, 160));
	}
	if (strstr(first, "HTTP"))
		http_send_status(s, 501, FALSE, NULL, 0, "Method Not Implemented");
	/* FALL THROUGH */

cleanup:
	socket_destroy(s, NULL);
}

/**
 * Callback for outgoing connections!
 *
 * Called when a socket is connected. Checks type of connection and hands
 * control over the connetion over to more specialized handlers. If no
 * handler was found the connection is terminated.
 * This is the place to hook up handlers for new communication types.
 * So far there are CONTROL, UPLOAD, DOWNLOAD and HTTP handlers.
 */
static void
socket_connected(gpointer data, gint source, inputevt_cond_t cond)
{
	/* We are connected to somebody */

	struct gnutella_socket *s = data;

	socket_check(s);
	g_assert(source == s->file_desc);

	if (cond & INPUT_EVENT_EXCEPTION) {	/* Error while connecting */
		bws_sock_connect_failed(s->type);
		if (s->type == SOCK_TYPE_DOWNLOAD && s->resource.download)
			download_fallback_to_push(s->resource.download, FALSE, FALSE);
		else
			socket_destroy(s, _("Connection failed"));
		return;
	}

	s->flags |= SOCK_F_ESTABLISHED;
	bws_sock_connected(s->type);

	if (0 != socket_tls_setup(s)) {
		if (!is_temporary_error(errno)) {
			socket_destroy(s, "TLS handshake failed");
		}
		return;
	}

	socket_alloc_buffer(s);

	if (cond & INPUT_EVENT_R) {
		if (
			proxy_is_enabled() &&
			s->direction == SOCK_CONN_PROXY_OUTGOING
		) {
			socket_evt_clear(s);

			switch ((enum proxy_protocol) GNET_PROPERTY(proxy_protocol)) {
			case PROXY_SOCKSV4:
				if (recv_socks4(s) != 0) {
					socket_destroy(s, "Error receiving from SOCKS 4 proxy");
					return;
				}
				s->direction = SOCK_CONN_OUTGOING;
				socket_evt_set(s, INPUT_EVENT_WX, socket_connected, s);
				return;

			case PROXY_SOCKSV5:
				if (connect_socksv5(s) != 0) {
					socket_destroy(s, "Error conneting to SOCKS 5 proxy");
					return;
				}
				if (s->pos > 5) {
					s->direction = SOCK_CONN_OUTGOING;
					socket_evt_set(s, INPUT_EVENT_WX, socket_connected, s);
				} else {
					socket_evt_set(s, INPUT_EVENT_WX, socket_connected, s);
				}
				return;

			case PROXY_HTTP:
				if (connect_http(s) != 0) {
					socket_destroy(s, "Unable to connect to HTTP proxy");
					return;
				}

				if (s->pos > 2) {
					s->direction = SOCK_CONN_OUTGOING;
					socket_evt_set(s, INPUT_EVENT_WX, socket_connected, s);
				} else {
					socket_evt_set(s, INPUT_EVENT_RX, socket_connected, s);
				}
				return;

			case PROXY_NONE:
				g_assert_not_reached();
			}
		}
	}

	if (0 != (cond & INPUT_EVENT_W)) {
		/* We are just connected to our partner */
		gint res, option;
		socklen_t size = sizeof option;

		socket_evt_clear(s);

		/* Check whether the socket is really connected */

		res = getsockopt(s->file_desc, SOL_SOCKET, SO_ERROR,
					   (void *) &option, &size);

		if (res == -1 || option) {
			if (
				s->type == SOCK_TYPE_DOWNLOAD &&
				s->resource.download &&
				!(GNET_PROPERTY(is_firewalled) || !GNET_PROPERTY(send_pushes))
			)
				download_fallback_to_push(s->resource.download, FALSE, FALSE);
			else
				socket_destroy(s, _("Connection failed"));
			return;
		}

		if (
			proxy_is_enabled() &&
			s->direction == SOCK_CONN_PROXY_OUTGOING
		) {
			switch ((enum proxy_protocol) GNET_PROPERTY(proxy_protocol)) {
			case PROXY_SOCKSV4:
				if (send_socks4(s) != 0) {
					socket_destroy(s, "Error sending to SOCKS 4 proxy");
					return;
				}
				break;

			case PROXY_SOCKSV5:
				if (connect_socksv5(s) != 0) {
					socket_destroy(s, "Error connecting to SOCKS 5 proxy");
					return;
				}
				break;

			case PROXY_HTTP:
				if (connect_http(s) != 0) {
					socket_destroy(s, "Error connecting to HTTP proxy");
					return;
				}
				break;

			case PROXY_NONE:
				g_assert_not_reached();
			}

			socket_evt_set(s, INPUT_EVENT_RX, socket_connected, s);
			return;
		}

		inet_connection_succeeded(s->addr);

		s->pos = 0;
		memset(s->buf, 0, s->buf_size);

		g_assert(0 == s->gdk_tag);

		/*
		 * Even though local_addr is persistent, we refresh it after startup,
		 * in case the IP changed since last time.
		 *		--RAM, 07/05/2002
		 */

		guess_local_addr(s);

		switch (s->type) {
		case SOCK_TYPE_CONTROL:
			{
				struct gnutella_node *n = s->resource.node;

				g_assert(n->socket == s);
				node_init_outgoing(n);
			}
			break;

		case SOCK_TYPE_DOWNLOAD:
			{
				struct download *d = s->resource.download;

				g_assert(d->socket == s);
				download_connected(d);
			}
			break;

		case SOCK_TYPE_UPLOAD:
			{
				struct upload *u = s->resource.upload;

				g_assert(u->socket == s);
				upload_connect_conf(u);
			}
			break;

		case SOCK_TYPE_HTTP:
			http_async_connected(s->resource.handle);
			break;

		case SOCK_TYPE_CONNBACK:
			node_connected_back(s);
			break;

        case SOCK_TYPE_SHELL:
            g_assert_not_reached(); /* FIXME: add code here? */
            break;

		default:
			g_warning("socket_connected(): Unknown socket type %d !", s->type);
			socket_destroy(s, NULL);		/* ? */
			break;
		}
	}

}

static int
socket_addr_getsockname(socket_addr_t *p_addr, int fd)
{
	struct sockaddr_in sin4;
	socklen_t len;
	host_addr_t addr = zero_host_addr;
	guint16 port = 0;

	len = sizeof sin4;
	if (-1 != getsockname(fd, cast_to_gpointer(&sin4), &len)) {
		addr = host_addr_peek_ipv4(&sin4.sin_addr.s_addr);
		port = sin4.sin_port;
	}

#ifdef HAS_IPV6
	if (!is_host_addr(addr)) {
		struct sockaddr_in6 sin6;

		len = sizeof sin6;
		if (-1 != getsockname(fd, cast_to_gpointer(&sin6), &len)) {
			addr = host_addr_peek_ipv6(sin6.sin6_addr.s6_addr);
			port = sin6.sin6_port;
		}
	}
#endif	/* HAS_IPV6 */

	if (!is_host_addr(addr))
		return -1;

	socket_addr_set(p_addr, addr, port);
	return 0;
}

/**
 * Tries to guess the local IP address.
 */
static void
guess_local_addr(struct gnutella_socket *s)
{
	socket_addr_t saddr;
	int fd;

	g_return_if_fail(s);

	fd = s->file_desc;
	g_return_if_fail(fd >= 0);

	if (!socket_is_local(s) && 0 == socket_addr_getsockname(&saddr, fd)) {
		host_addr_t addr;

		addr = socket_addr_get_addr(&saddr);
		switch (host_addr_net(addr)) {
		case NET_TYPE_IPV4:
		case NET_TYPE_IPV6:
			settings_addr_changed(addr, s->addr);
			break;
		case NET_TYPE_LOCAL:
		case NET_TYPE_NONE:
			break;
		}
	}
}

/**
 * @return socket's local port, or -1 on error.
 */
static int
socket_local_port(struct gnutella_socket *s)
{
	socket_addr_t addr;

	if (0 != socket_addr_getsockname(&addr, s->file_desc))
		return -1;

	return socket_addr_get_port(&addr);
}

/**
 * Someone is connecting to us.
 */
static void
socket_accept(gpointer data, gint unused_source, inputevt_cond_t cond)
{
	socket_addr_t addr;
	socklen_t len = sizeof addr;
	struct gnutella_socket *s = data;
	struct gnutella_socket *t = NULL;
	gint fd;

	(void) unused_source;
	socket_check(s);
	g_assert(s->flags & (SOCK_F_TCP | SOCK_F_LOCAL));

	if (cond & INPUT_EVENT_EXCEPTION) {
		g_warning("Input exception on TCP listening socket #%d!", s->file_desc);
		return;		/* Ignore it, what else can we do? */
	}

	switch (s->type) {
	case SOCK_TYPE_CONTROL:
		break;
	default:
		g_warning("socket_accept(): Unknown listening socket type %d !",
				  s->type);
		socket_destroy(s, NULL);
		return;
	}

	fd = accept(s->file_desc, (struct sockaddr *) &addr, &len);
	if (fd < 0) {
		/*
		 * If we ran out of file descriptors, try to reclaim one from the
		 * banning pool and retry.
		 */

		if (
			(errno == EMFILE || errno == ENFILE) &&
			reclaim_fd != NULL && (*reclaim_fd)()
		) {
			fd = accept(s->file_desc, (struct sockaddr *) &addr, &len);
		}

		if (fd < 0) {
			if (errno != ECONNABORTED && !is_temporary_error(errno)) {
				g_warning("accept() failed (%s)", g_strerror(errno));
				if (errno == EMFILE || errno == ENFILE) {
					/*
					 * Disable accept() temporarily to prevent spinning
					 * on socket_accept(). It's re-enabled from socket_timer()
					 */
					socket_evt_clear(s);
				}
			}
			return;
		}

		g_warning("had to close a banned fd to accept new connection");
	}
	fd = get_non_stdio_fd(fd);

	bws_sock_accepted(SOCK_TYPE_HTTP);	/* Do not charge Gnet b/w for that */

	/*
	 * Create a new struct socket for this incoming connection
	 */

	set_close_on_exec(fd);
	socket_set_nonblocking(fd);

	t = socket_alloc();

	t->file_desc = fd;
	t->direction = SOCK_CONN_INCOMING;
	t->type = s->type;

	if (SOCK_F_TCP & s->flags) {
		t->addr = socket_addr_get_addr(&addr);
		t->port = socket_addr_get_port(&addr);
		t->local_port = s->local_port;
		t->flags |= SOCK_F_TCP;
	} else {
		g_assert(SOCK_F_LOCAL & s->flags);
		t->flags |= SOCK_F_LOCAL;
		t->addr.net = NET_TYPE_LOCAL;
	}
	t->net = host_addr_net(t->addr);

#ifdef HAS_GNUTLS
	t->tls.enabled = s->tls.enabled; /* Inherit from listening socket */
	t->tls.stage = SOCK_TLS_NONE;
	t->tls.ctx = NULL;
	t->tls.snarf = 0;

	if (GNET_PROPERTY(tls_debug) > 2)
		g_message("Incoming connection");
#endif	/* HAS_GNUTLS */
        
	socket_wio_link(t);

	t->flags |= SOCK_F_ESTABLISHED;

	switch (s->type) {
	case SOCK_TYPE_CONTROL:
		socket_evt_set(t, INPUT_EVENT_RX, socket_read, t);
		/*
		 * Whilst the socket is attached to that callback, it has been
		 * freshly accepted and we don't know what we're going to do with
		 * it.	Is it an incoming node connection or an upload request?
		 * Can't tell until we have read enough bytes.
		 *
		 * However, we must guard against a subtle DOS attack whereby
		 * someone would connect to us and then send only one byte (say),
		 * then nothing.  The socket would remain connected, without
		 * being monitored for timeout by the node/upload code.
		 *
		 * Insert the socket to the `sl_incoming' list, and have it
		 * monitored periodically.	We know the socket is on the list
		 * as soon as it has a non-zero last_update field.
		 *				--RAM, 07/09/2001
		 */

		sl_incoming = g_slist_prepend(sl_incoming, t);
		t->last_update = tm_time();
		break;

	default:
		g_assert_not_reached();			/* Can't happen */
		break;
	}

	inet_got_incoming(t->addr);	/* Signal we got an incoming connection */
	if (!GNET_PROPERTY(force_local_ip))
		guess_local_addr(t);
}

#if defined(CMSG_FIRSTHDR) && defined(CMSG_NXTHDR)
static inline const struct cmsghdr *
cmsg_nxthdr(const struct msghdr *msg, const struct cmsghdr *cmsg)
{
	return CMSG_NXTHDR((struct msghdr *) msg, (struct cmsghdr *) cmsg);
}
#endif	/* CMSG_FIRSTHDR && CMSG_NXTHDR */

static gboolean
socket_udp_extract_dst_addr(const struct msghdr *msg, host_addr_t *dst_addr)
#if defined(CMSG_FIRSTHDR) && defined(CMSG_NXTHDR)
{
	const struct cmsghdr *p;

	g_assert(msg);
	g_assert(dst_addr);

	for (p = CMSG_FIRSTHDR(msg); NULL != p; p = cmsg_nxthdr(msg, p)) {
		if (0) {
			/* NOTHING */
#if defined(IP_RECVDSTADDR)
		} else if (
			IP_RECVDSTADDR == p->cmsg_type &&
			sol_ip() == p->cmsg_level
		) {
			struct in_addr addr;
			const void *data;

			data = CMSG_DATA(p);
			if (sizeof addr == p->cmsg_len - ptr_diff(data, p)) {
				memcpy(&addr, data, sizeof addr);
				*dst_addr = host_addr_peek_ipv4(&addr.s_addr);
				return TRUE;
			}
#endif /* IP_RECVDSTADDR */
#if defined(HAS_IPV6) && defined(IPV6_RECVPKTINFO)
		} else if (
			IPV6_PKTINFO == p->cmsg_type &&
			sol_ipv6() == p->cmsg_level
		) {
			struct in6_pktinfo info;
			const void *data;

			data = CMSG_DATA(p);
			if (sizeof info == p->cmsg_len - ptr_diff(data, p)) {
				memcpy(&info, data, sizeof info);
				*dst_addr = host_addr_peek_ipv6(info.ipi6_addr.s6_addr);
				return TRUE;
			}
#endif /* HAS_IPV6 && IPV6_RECVPKTINFO */
		} else {
			if (GNET_PROPERTY(socket_debug))
				g_message("socket_udp_extract_dst_addr(): "
					"CMSG type=%u, level=%u, len=%u",
					(unsigned) p->cmsg_type,
					(unsigned) p->cmsg_level,
					(unsigned) p->cmsg_len);
		}
	}

	return FALSE;
}
#else	/* !(CMSG_FIRSTHDR && CMSG_NXTHDR) */
{
	(void) msg;
	(void) dst_addr;
	return FALSE;
}
#endif	/* CMSG_FIRSTHDR && CMSG_NXTHDR */

/**
 * Someone is sending us a datagram.
 */
static ssize_t
socket_udp_accept(struct gnutella_socket *s)
{
	socket_addr_t *from_addr;
	struct sockaddr *from;
	socklen_t from_len;
	ssize_t r;
	gboolean truncated, has_dst_addr = FALSE;
	host_addr_t dst_addr;

	socket_check(s);
	g_assert(s->flags & SOCK_F_UDP);
	g_assert(s->type == SOCK_TYPE_UDP);

	/*
	 * Receive the datagram in the socket's buffer.
	 */

	from_addr = s->resource.handle;

	/* Initialize from_addr so that it matches the socket's network type. */
	from_len = socket_addr_init(from_addr, s->net);
	g_assert(from_len > 0);

	from = socket_addr_get_sockaddr(from_addr);
	g_assert(from);

	/*
	 * Detect truncation of the UDP message via MSG_TRUNC.
	 *
	 * We won't be rejecting truncated messages yet because we want to
	 * log them as being "too large", so we'll check msg_flag to see
	 * whether the message is truncated.
	 */
	{
		static const struct msghdr zero_msg;
		struct msghdr msg;
		struct iovec iov;

		iov.iov_base = s->buf;
		iov.iov_len = s->buf_size;

		msg = zero_msg;
		msg.msg_name = cast_to_gpointer(from);
		msg.msg_namelen = from_len;
		msg.msg_iov = &iov;
		msg.msg_iovlen = 1;

		/* Some implementations have msg_accrights and msg_accrightslen
		 * instead of msg_control and msg_controllen.
		 */
#if defined(CMSG_LEN) && defined(CMSG_SPACE)
		{
			static const size_t cmsg_size = 512;
			static gchar *cmsg_buf;
			static size_t cmsg_len;

			if (!cmsg_buf) {
				cmsg_len = CMSG_LEN(cmsg_size);
				cmsg_buf = walloc0(CMSG_SPACE(cmsg_size));
			}

			msg.msg_control = cmsg_buf;
			msg.msg_controllen = cmsg_len;
		}
#endif /* CMSG_LEN && CMSG_SPACE */

		r = recvmsg(s->file_desc, &msg, 0);

		/* msg_flags is missing at least in some versions of IRIX. */
#ifdef HAS_MSGHDR_MSG_FLAGS
		truncated = 0 != (MSG_TRUNC & msg.msg_flags);
#else	/* HAS_MSGHDR_MSG_FLAGS */
		truncated = FALSE;	/* We can't detect truncation with recvfrom() */
#endif /* HAS_MSGHDR_MSG_FLAGS */

		if ((ssize_t) -1 != r && !GNET_PROPERTY(force_local_ip)) {
			has_dst_addr = socket_udp_extract_dst_addr(&msg, &dst_addr);
		}
	}

	if ((ssize_t) -1 == r)
		return (ssize_t) -1;

	g_assert((size_t) r <= s->buf_size);

	bws_udp_count_read(r);
	s->pos = r;

	/*
	 * Record remote address.
	 */

	s->addr = socket_addr_get_addr(from_addr);
	s->port = socket_addr_get_port(from_addr);

	if (has_dst_addr) {
		static host_addr_t last_addr;

		settings_addr_changed(dst_addr, s->addr);

		/* Show the destination address only when it differs from
		 * the last seen or if the debug level is higher than 1.
		 */
		if (
			GNET_PROPERTY(socket_debug) > 1 ||
			!host_addr_equal(last_addr, dst_addr)
		) {
			last_addr = dst_addr;
			if (GNET_PROPERTY(socket_debug))
				g_message("socket_udp_accept(): dst_addr=%s",
					host_addr_to_string(dst_addr));
		}
	}

	/*
	 * Signal reception of a datagram to the UDP layer.
	 */

	udp_received(s, truncated);
	return r;
}

/**
 * Someone is sending us a datagram.
 */
static void
socket_udp_event(gpointer data, gint unused_source, inputevt_cond_t cond)
{
	struct gnutella_socket *s = data;
	size_t i, avail;

	(void) unused_source;

	if (cond & INPUT_EVENT_EXCEPTION) {
		gint error;
		socklen_t error_len = sizeof error;

		getsockopt(s->file_desc, SOL_SOCKET, SO_ERROR, &error, &error_len);
		g_warning("Input Exception for UDP listening socket #%d: %s",
				  s->file_desc, g_strerror(error));
		return;
	}

	/*
	 * It might be useful to call socket_udp_accept() several times
	 * as there are often several packets queued.
	 */

	avail = inputevt_data_available();
	for (i = 0; i < 16; i++) {
		ssize_t r;

		r = socket_udp_accept(s);
		if ((ssize_t) -1 == r) {
			if (!is_temporary_error(errno))
				g_warning("ignoring datagram reception error: %s",
					g_strerror(errno));
			break;
		}
		if ((size_t) r >= avail)
			break;
		avail -= r;

		/* kevent() reports 32 more bytes than there are, maybe
		 * it refers to header or control msg data. */
		if (avail <= 32)
			break;
	}
}

static inline void
socket_set_linger(gint fd)
{
	g_assert(fd >= 0);

	if (!GNET_PROPERTY(use_so_linger))
		return;

#ifdef TCP_LINGER2
	{
		gint timeout = 20;	/* timeout in seconds for FIN_WAIT_2 */

		if (setsockopt(fd, sol_tcp(), TCP_LINGER2, &timeout, sizeof timeout))
			g_warning("setsockopt() for TCP_LINGER2 failed: %s",
				g_strerror(errno));
	}
#else
	{
		static const struct linger zero_linger;
		struct linger lb;

		lb = zero_linger;
		lb.l_onoff = 1;
		lb.l_linger = 0;	/* closes connections with RST */
		if (setsockopt(fd, SOL_SOCKET, SO_LINGER, &lb, sizeof lb))
			g_warning("setsockopt() for SO_LINGER failed: %s",
				g_strerror(errno));
	}
#endif /* TCP_LINGER */
}

static void
socket_set_accept_filters(struct gnutella_socket *s)
{
	socket_check(s);
	g_assert(s->file_desc >= 0);

#if defined(TCP_DEFER_ACCEPT)
	if (GNET_PROPERTY(tcp_defer_accept_timeout) > 0) {
		gint timeout;

		timeout = MIN(GNET_PROPERTY(tcp_defer_accept_timeout), (guint) INT_MAX);
		if (
			setsockopt(s->file_desc, sol_tcp(), TCP_DEFER_ACCEPT,
				&timeout, sizeof timeout)
		) {
			g_warning("setsockopt() for TCP_DEFER_ACCEPT(%d) failed: %s",
				timeout, g_strerror(errno));
		}
	}
#endif /* TCP_DEFER_ACCEPT */
#if defined(SO_ACCEPTFILTER)
	{
		static const struct accept_filter_arg zero_arg;
		struct accept_filter_arg arg;
		static const gchar name[] = "dataready";

		arg = zero_arg;
		STATIC_ASSERT(sizeof arg.af_name >= CONST_STRLEN(name));
		strncpy(arg.af_name, name, sizeof arg.af_name);

		if (setsockopt(s->file_desc, SOL_SOCKET, SO_ACCEPTFILTER,
				&arg, sizeof arg)
		) {
			/* This is usually not supported for IPv6. Thus suppress
			 * the warning by default. */
			if (NET_TYPE_IPV6 != s->net || GNET_PROPERTY(socket_debug) > 0) {
				g_warning("Cannot set SO_ACCEPTFILTER (%s): %s",
					name, g_strerror(errno));
			}
		}
	}
#endif /* SO_ACCEPTFILTER */
}


/*
 * Sockets creation
 */

/**
 * Called to prepare the creation of the socket connection.
 *
 * @returns non-zero in case of failure, zero on success.
 */
static gint
socket_connect_prepare(struct gnutella_socket *s,
	host_addr_t addr, guint16 port, enum socket_type type, guint32 flags)
{
	static const int enable = 1;
	gint fd, family;

	socket_check(s);

	if (!(s->flags & SOCK_F_FORCE) && hostiles_check(addr)) {
		g_warning("Not connecting to hostile host %s",
			host_addr_to_string(addr));
		errno = EPERM;
		return -1;
	}

	if (0 == (SOCK_F_TLS & flags) && tls_cache_lookup(addr, port)) {
		flags |= SOCK_F_TLS;
	}

	addr = socket_ipv6_trt_map(addr);
	family = host_addr_family(addr);
	if (-1 == family) {
		errno = EINVAL;
		return -1;
	}

	fd = socket(family, SOCK_STREAM, 0);
	if (fd < 0) {
		/*
		 * If we ran out of file descriptors, try to reclaim one from the
		 * banning pool and retry.
		 */

		if (
			(errno == EMFILE || errno == ENFILE) &&
			reclaim_fd != NULL && (*reclaim_fd)()
		) {
			fd = socket(family, SOCK_STREAM, 0);
		}

		if (fd < 0) {
			gint saved_errno = errno;
			g_warning("unable to create a socket (%s)",
				g_strerror(saved_errno));
			errno = saved_errno;
			return -1;
		}

		g_warning("had to close a banned fd to prepare new connection");
	}
	fd = get_non_stdio_fd(fd);

	s->type = type;
	s->direction = SOCK_CONN_OUTGOING;
	s->net = host_addr_net(addr);
	s->file_desc = fd;
	s->port = port;
	s->flags |= SOCK_F_TCP | flags;

#ifdef HAS_GNUTLS
	s->tls.enabled = GNET_PROPERTY(tls_enforce) || (SOCK_F_TLS & flags);
	s->tls.stage = SOCK_TLS_NONE;
	s->tls.ctx = NULL;
	s->tls.snarf = 0;
#endif	/* HAS_GNUTLS */
        
	socket_wio_link(s);

	setsockopt(s->file_desc, SOL_SOCKET, SO_KEEPALIVE, &enable, sizeof enable);
	setsockopt(s->file_desc, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof enable);

	socket_set_nonblocking(s->file_desc);
	set_close_on_exec(fd);
	socket_set_linger(s->file_desc);
	socket_tos_normal(s);

	return 0;
}

/**
 * Called to finalize the creation of the socket connection, which is done
 * in two steps since DNS resolving is asynchronous.
 *
 * @returns non-zero in case of failure, zero on success.
 */
static gint
socket_connect_finalize(struct gnutella_socket *s, const host_addr_t ha)
{
	socket_addr_t addr;
	socklen_t addr_len;
	gint res;

	socket_check(s);

	/*
	 * Allow forced connections to an hostile host.
	 */

	if (!(s->flags & SOCK_F_FORCE) && hostiles_check(ha)) {
		g_warning("Not connecting to hostile host %s", host_addr_to_string(ha));
		socket_destroy(s, "Not connecting to hostile host");
		return -1;
	}

	s->addr = ha;
	addr_len = socket_addr_set(&addr, s->addr, s->port);

	inet_connection_attempted(s->addr);

	/*
	 * Now we check if we're forcing a local IP, and make it happen if so.
	 *   --JSL
	 */
	if (GNET_PROPERTY(force_local_ip) || GNET_PROPERTY(force_local_ip6)) {
		host_addr_t bind_addr = zero_host_addr;

		switch (s->net) {
		case NET_TYPE_IPV4:
			if (GNET_PROPERTY(force_local_ip)) {
				bind_addr = listen_addr();
			}
			break;
		case NET_TYPE_IPV6:
			if (GNET_PROPERTY(force_local_ip6)) {
				bind_addr = listen_addr6();
			}
			break;
		case NET_TYPE_LOCAL:
		case NET_TYPE_NONE:
			break;
		}

		if (host_addr_initialized(bind_addr)) {
			socket_addr_t local;
			socklen_t len;

			len = socket_addr_set(&local, bind_addr, 0);

			/*
			 * Note: we ignore failures: it will be automatic at connect()
			 * It's useful only for people forcing the IP without being
			 * behind a masquerading firewall --RAM.
			 */
			(void) bind(s->file_desc,
					socket_addr_get_const_sockaddr(&local), len);
		}
	}

	if (proxy_is_enabled()) {
		s->direction = SOCK_CONN_PROXY_OUTGOING;
		res = proxy_connect(s->file_desc);
	} else {
		res = connect(s->file_desc,
				socket_addr_get_const_sockaddr(&addr), addr_len);
	}

	if (-1 == res && EINPROGRESS != errno) {
		if (proxy_is_enabled() && !is_host_addr(GNET_PROPERTY(proxy_addr))) {
			if (!is_temporary_error(errno)) {
				g_warning("Proxy isn't properly configured (%s:%u)",
					GNET_PROPERTY(proxy_hostname), GNET_PROPERTY(proxy_port));
			}
			socket_destroy(s, "Check the proxy configuration");
			return -1;
		}

		g_warning("Unable to connect to %s: (%s)",
			host_addr_port_to_string(s->addr, s->port), g_strerror(errno));

		if (s->adns & SOCK_ADNS_PENDING)
			s->adns_msg = "Connection failed";
		else
			socket_destroy(s, _("Connection failed"));
		return -1;
	}

	s->local_port = socket_local_port(s);
	bws_sock_connect(s->type);

	/* Set the file descriptor non blocking */
	socket_set_nonblocking(s->file_desc);

	g_assert(0 == s->gdk_tag);

	socket_evt_set(s, INPUT_EVENT_WX, socket_connected, s);
	return 0;
}

/**
 * Creates a connected socket with an attached resource of `type'.
 *
 * Connection happens in the background, the connection callback being
 * determined by the resource type.
 */
struct gnutella_socket *
socket_connect(const host_addr_t ha, guint16 port,
	enum socket_type type, guint32 flags)
{
	struct gnutella_socket *s;

	s = socket_alloc();

	if (0 != socket_connect_prepare(s, ha, port, type, flags)) {
		socket_dealloc(&s);
		return NULL;
	}

	return 0 != socket_connect_finalize(s, ha) ? NULL : s;
}

/**
 * @returns whether bad hostname was reported after a DNS lookup.
 */
gboolean
socket_bad_hostname(struct gnutella_socket *s)
{
	socket_check(s);

	return (s->adns & SOCK_ADNS_BADNAME) ? TRUE : FALSE;
}

/**
 * Called when we got a reply from the ADNS process.
 *
 * @todo TODO: All resolved addresses should be attempted.
 */
static void
socket_connect_by_name_helper(const host_addr_t *addrs, size_t n,
	gpointer user_data)
{
	struct gnutella_socket *s = user_data;
	host_addr_t addr;
	gboolean can_tls;

	socket_check(s);
	g_assert(addrs);

	s->adns &= ~SOCK_ADNS_PENDING;

	if (n < 1 || s->type == SOCK_TYPE_DESTROYING) {
		s->adns |= SOCK_ADNS_FAILED | SOCK_ADNS_BADNAME;
		s->adns_msg = "Could not resolve address";
		return;
	}

	addr = addrs[random_raw() % n];
	can_tls = tls_cache_lookup(addr, s->port);

	if (
		s->net != host_addr_net(addr) ||
		(can_tls && 0 == (SOCK_F_TLS & s->flags))
	) {
		s->net = host_addr_net(addr);

		if (-1 != s->file_desc) {
			close(s->file_desc);
			s->file_desc = -1;
		}
		if (can_tls) {
			s->flags |= SOCK_F_TLS;
		}
		if (socket_connect_prepare(s, addr, s->port, s->type, s->flags)) {
			s->adns |= SOCK_ADNS_FAILED;
			return;
		}
	}

	if (socket_connect_finalize(s, addr)) {
		s->adns |= SOCK_ADNS_FAILED;
		return;
	}
}

/**
 * Like socket_connect() but the remote address is not known and must be
 * resolved through async DNS calls.
 */
struct gnutella_socket *
socket_connect_by_name(const gchar *host, guint16 port,
	enum socket_type type, guint32 flags)
{
	struct gnutella_socket *s;
	host_addr_t ha;

	g_assert(host);

	/* The socket is closed and re-created if the hostname resolves
	 * to an IPv6 address. */
	ha = ipv4_unspecified;

	s = socket_alloc();

	if (0 != socket_connect_prepare(s, ha, port, type, flags)) {
		socket_dealloc(&s);
		return NULL;
	}

	s->adns |= SOCK_ADNS_PENDING;
	if (
		!adns_resolve(host, settings_dns_net(),
			&socket_connect_by_name_helper, s)
		&& (s->adns & SOCK_ADNS_FAILED)
	) {
		/*	socket_connect_by_name_helper() was already invoked! */
		if (GNET_PROPERTY(socket_debug) > 0)
			g_warning("socket_connect_by_name: "
				"adns_resolve() failed in synchronous mode");
		socket_destroy(s, s->adns_msg);
		return NULL;
	}

	return s;
}

/**
 * Creates a listening socket and binds it to `bind_addr' unless it is
 * of type NET_TYPE_NONE. The socket is also set to non-blocking mode
 * and the FD_CLOEXEC flag is set as well.
 *
 * @param bind_addr The address to bind the socket to.
 * @param port The UDP or TCP port to use.
 * @param type Either SOCK_DGRAM or SOCK_STREAM.
 *
 * @return The new file descriptor of socket or -1 on failure.
 */
gint
socket_create_and_bind(const host_addr_t bind_addr,
	const guint16 port, const int type)
{
	gboolean socket_failed;
	gint fd, saved_errno, family;

	g_assert(SOCK_DGRAM == type || SOCK_STREAM == type);

	if (port < 2) {
		errno = EINVAL;
		return -1;
	}
	if (NET_TYPE_NONE == host_addr_net(bind_addr)) {
		errno = EINVAL;
		return -1;
	}
	family = host_addr_family(bind_addr);
	if (-1 == family) {
		errno = EINVAL;
		return -1;
	}
	fd = socket(family, type, 0);
	if (fd < 0) {
		socket_failed = TRUE;
		saved_errno = errno;
	} else {
		static const int enable = 1;
		socket_addr_t addr;
		socklen_t len;

		/* Linux absolutely wants this before bind() unlike BSD */
		setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof enable);

#if defined(HAS_IPV6) && defined(IPV6_V6ONLY)
		if (
			NET_TYPE_IPV6 == host_addr_net(bind_addr) &&
			setsockopt(fd, sol_ipv6(), IPV6_V6ONLY, &enable, sizeof enable)
		) {
			g_warning("setsockopt() failed for IPV6_V6ONLY (%s)",
				g_strerror(errno));
		}
#endif /* HAS_IPV6 && IPV6_V6ONLY */

		/* bind() the socket */
		socket_failed = FALSE;
		len = socket_addr_set(&addr, bind_addr, port);
		if (-1 == bind(fd, socket_addr_get_const_sockaddr(&addr), len)) {
			saved_errno = errno;
			close(fd);
			fd = -1;
		} else {
			saved_errno = 0;
		}
	}

#if defined(HAS_SOCKER_GET)
	if (fd < 0 && (EACCES == saved_errno || EPERM == saved_errno)) {
		gchar addr_str[128];

		host_addr_to_string_buf(bind_addr, addr_str, sizeof addr_str);
		fd = socker_get(family, type, 0, addr_str, port);
		if (fd < 0) {
			g_warning("socker_get() failed (%s)", g_strerror(errno));
		}
	}
#endif /* HAS_SOCKER_GET */

	if (fd < 0) {
		const gchar *type_str = SOCK_DGRAM == type ? "datagram" : "stream";
		const gchar *net_str = net_type_to_string(host_addr_net(bind_addr));

		if (socket_failed) {
			g_warning("Unable to create the %s (%s) socket (%s)",
				type_str, net_str, g_strerror(errno));
		} else {
			gchar bind_addr_str[HOST_ADDR_PORT_BUFLEN];

			host_addr_port_to_string_buf(bind_addr, port,
				bind_addr_str, sizeof bind_addr_str);
			g_warning("Unable to bind() the %s (%s) socket to %s (%s)",
				type_str, net_str, bind_addr_str, g_strerror(errno));
		}
	} else {
		fd = get_non_stdio_fd(fd);
		set_close_on_exec(fd);
		socket_set_nonblocking(fd);
	}

	return fd;
}

/**
 * @return TRUE if the socket is a local unix domain socket.
 */
gboolean
socket_is_local(const struct gnutella_socket *s)
{
	gboolean is_local, is_tcp, is_udp;

	socket_check(s);

	is_local = 0 != (s->flags & SOCK_F_LOCAL);
	is_tcp = 0 != (s->flags & SOCK_F_TCP);
	is_udp = 0 != (s->flags & SOCK_F_UDP);

	g_assert(is_local ^ (is_tcp | is_udp));
	g_assert(is_local || is_tcp || is_udp);

	if (is_local) {
		static const struct sockaddr_un zero_addr;
		struct sockaddr_un addr = zero_addr;
		socklen_t len = sizeof addr;

		if (getsockname(s->file_desc, cast_to_gpointer(&addr), &len)) {
			is_local = FALSE;
			g_warning("socket_is_local(): getsockname() failed: %s",
				g_strerror(errno));
		} else if (AF_LOCAL != addr.sun_family) {
			is_local = FALSE;
			g_warning("socket_is_local(): "
				"address family mismatch! (expected %u, got %u)",
				(guint) AF_LOCAL, (guint) addr.sun_family);
		}
	}

	return is_local;
}

/**
 * Creates a non-blocking listening unix domain socket with an attached
 * resource of `type'.
 */
struct gnutella_socket *
socket_local_listen(const gchar *pathname)
{
	struct sockaddr_un addr;
	struct gnutella_socket *s;
	int fd;

	g_return_val_if_fail(pathname, NULL);
	g_return_val_if_fail(is_absolute_path(pathname), NULL);

	{
		static const struct sockaddr_un zero_un;
		size_t size = sizeof addr.sun_path;

		addr = zero_un;
		addr.sun_family = AF_LOCAL;
		if (g_strlcpy(addr.sun_path, pathname, size) >= size) {
			g_warning("socket_local_listen(): pathname is too long");
			return NULL; 
		}
	}

	fd = socket(PF_LOCAL, SOCK_STREAM, 0);
	if (fd < 0) {
		g_warning("socket(PF_LOCAL, SOCK_STREAM, 0) failed: %s",
			g_strerror(errno));
		return NULL;
	}
	fd = get_non_stdio_fd(fd);

	(void) unlink(pathname);

	{
		int ret, saved_errno;
		mode_t mask;
	
		/* umask 177 -> mode 200; write-only for user */
		mask = umask(S_IRUSR | S_IXUSR | S_IRWXG | S_IRWXO);
    	ret = bind(fd, cast_to_gconstpointer(&addr), sizeof addr);
		saved_errno = errno;
		(void) umask(mask);

		if (0 != ret) {
			g_warning("socket_local_listen(): bind() failed: %s",
				g_strerror(saved_errno));
			close(fd);
			return NULL;
		}
	}

	s = socket_alloc();

	s->type = SOCK_TYPE_CONTROL;
	s->direction = SOCK_CONN_LISTENING;
	s->file_desc = fd;
	s->pos = 0;
	s->flags |= SOCK_F_LOCAL;

	socket_wio_link(s);				/* Link to the I/O functions */

	set_close_on_exec(fd);
	socket_set_nonblocking(fd);

	s->net = NET_TYPE_NONE;
	s->local_port = 0;

	/* listen() the socket */

	if (listen(fd, 5) == -1) {
		g_warning("Unable to listen() the socket (%s)", g_strerror(errno));
		socket_destroy(s, "Unable to listen on socket");
		return NULL;
	}

#ifdef HAS_GNUTLS
	s->tls.enabled = TRUE;
#endif /* HAS_GNUTLS */

	socket_enable_accept(s);
	return s;
}

/**
 * Creates a non-blocking TCP listening socket with an attached
 * resource of `type'.
 */
struct gnutella_socket *
socket_tcp_listen(host_addr_t bind_addr, guint16 port)
{
	static const int enable = 1;
	struct gnutella_socket *s;
	int fd;

	/* Create a socket, then bind() and listen() it */
	fd = socket_create_and_bind(bind_addr, port, SOCK_STREAM);
	if (fd < 0)
		return NULL;

	s = socket_alloc();

	s->type = SOCK_TYPE_CONTROL;
	s->direction = SOCK_CONN_LISTENING;
	s->file_desc = fd;
	s->pos = 0;
	s->flags |= SOCK_F_TCP;
	s->net = host_addr_net(bind_addr);

	socket_wio_link(s);				/* Link to the I/O functions */

	setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &enable, sizeof enable);

	socket_set_linger(s->file_desc);

	/* listen() the socket */

	if (listen(fd, 5) == -1) {
		g_warning("Unable to listen() the socket (%s)", g_strerror(errno));
		socket_destroy(s, "Unable to listen on socket");
		return NULL;
	}

	socket_set_accept_filters(s);

	/* Get the port of the socket, if needed */

	if (port) {
		s->local_port = port;
	} else {
		socket_addr_t addr;

		if (0 != socket_addr_getsockname(&addr, fd)) {
			g_warning("Unable to get the port of the socket: "
				"getsockname() failed (%s)", g_strerror(errno));
			socket_destroy(s, "Can't probe socket for port");
			return NULL;
		}

		s->local_port = socket_addr_get_port(&addr);
	}

#ifdef HAS_GNUTLS
	s->tls.enabled = TRUE;
#endif /* HAS_GNUTLS */

	socket_enable_accept(s);
	return s;
}

static void
socket_enable_recvdstaddr(const struct gnutella_socket *s)
{
	static const int on = 1;
	int fd;

	socket_check(s);
	fd = s->file_desc;
	g_assert(fd >= 0);

	(void) on;
	switch (s->net) {
	case NET_TYPE_IPV4:
#if defined(IP_RECVDSTADDR) && IP_RECVDSTADDR
		if (setsockopt(fd, sol_ip(), IP_RECVDSTADDR, &on, sizeof on)) {
			g_warning("socket_enable_recvdstaddr(): "
				"setsockopt() for IP_RECVDSTADDR failed: %s",
				g_strerror(errno));
		}
#endif /* IP_RECVDSTADDR && IP_RECVDSTADDR */
		break;

	case NET_TYPE_IPV6:
#if defined(HAS_IPV6) && defined(IPV6_RECVPKTINFO)
		if (setsockopt(fd, sol_ipv6(), IPV6_RECVPKTINFO, &on, sizeof on)) {
			g_warning("socket_enable_recvdstaddr(): "
				"setsockopt() for IPV6_RECVPKTINFO failed: %s",
				g_strerror(errno));
		}
#endif /* HAS_IPV6 && IPV6_RECVPKTINFO */
		break;

	case NET_TYPE_LOCAL:
	case NET_TYPE_NONE:
		break;
	}
}

/**
 * Creates a non-blocking listening UDP socket.
 */
struct gnutella_socket *
socket_udp_listen(host_addr_t bind_addr, guint16 port)
{
	struct gnutella_socket *s;
	int fd;

	/* Create a socket, then bind() */
	fd = socket_create_and_bind(bind_addr, port, SOCK_DGRAM);
	if (fd < 0)
		return NULL;

	s = socket_alloc();

	socket_alloc_buffer(s);
	s->type = SOCK_TYPE_UDP;
	s->direction = SOCK_CONN_LISTENING;
	s->file_desc = fd;
	s->pos = 0;
	s->flags |= SOCK_F_UDP;
	s->net = host_addr_net(bind_addr);

	socket_wio_link(s);				/* Link to the I/O functions */

	socket_enable_recvdstaddr(s);

	/*
	 * Attach the socket information so that we may record the origin
	 * of the datagrams we receive.
	 */

	s->resource.handle = walloc(sizeof(socket_addr_t));

	/* Get the port of the socket, if needed */

	if (port) {
		s->local_port = port;
	} else {
		socket_addr_t addr;

		if (0 != socket_addr_getsockname(&addr, fd)) {
			g_warning("Unable to get the port of the socket: "
				"getsockname() failed (%s)", g_strerror(errno));
			socket_destroy(s, "Can't probe socket for port");
			return NULL;
		}

		s->local_port = socket_addr_get_port(&addr);
	}

	/* Ignore exceptions */
	socket_evt_set(s, INPUT_EVENT_R, socket_udp_event, s);

	/*
	 * Enlarge the RX buffer on the UDP socket to avoid loosing incoming
	 * datagrams if we are not able to read them during some time.
	 */

	sock_recv_buf(s, SOCK_UDP_RECV_BUF, FALSE);

	return s;
}

void
socket_disable_token(struct gnutella_socket *s)
{
	socket_check(s);
	s->omit_token = TRUE;
}

gboolean
socket_omit_token(struct gnutella_socket *s)
{
	socket_check(s);
	return s->omit_token;
}

/**
 * Set/clear TCP_CORK on the socket.
 *
 * When set, TCP will only send out full TCP/IP frames.
 * The exact size depends on your LAN interface, but on Ethernet,
 * it's about 1500 bytes.
 */
void
sock_cork(struct gnutella_socket *s, gboolean on)
#if defined(TCP_CORK) || defined(TCP_NOPUSH)
{
	static const gint option =
#if defined(TCP_CORK)
		TCP_CORK;
#else	/* !TCP_CORK*/
		TCP_NOPUSH;
#endif /* TCP_CORK */
	gint arg = on ? 1 : 0;

	socket_check(s);
	if (!(SOCK_F_TCP & s->flags)) {
		return;
	}

	if (-1 == setsockopt(s->file_desc, sol_tcp(), option, &arg, sizeof arg)) {
		if (ECONNRESET != errno) {
			g_warning("unable to %s TCP_CORK on fd#%d: %s",
				on ? "set" : "clear", s->file_desc, g_strerror(errno));
		}
	} else {
		s->corked = on;
	}
}
#else
{
	static gboolean warned = FALSE;

	socket_check(s);
	(void) on;

	if (!warned && GNET_PROPERTY(socket_debug)) {
		warned = TRUE;
		g_warning("TCP_CORK is not implemented on this system");
	}
}
#endif /* TCP_CORK || TCP_NOPUSH */

/*
 * Internal routine for sock_send_buf() and sock_recv_buf().
 * Set send/receive buffer to specified size, and warn if it cannot be done.
 * If `shrink' is false, refuse to shrink the buffer if its size is larger.
 */
static void
sock_set_intern(gint fd, gint option, gint size,
	const gchar *type, gboolean shrink)
{
	gint old_len = 0;
	gint new_len = 0;
	socklen_t len;

	size = (size + 1) & ~0x1;	/* Must be even, round to upper boundary */

	len = sizeof(old_len);
	if (-1 == getsockopt(fd, SOL_SOCKET, option, &old_len, &len))
		g_warning("cannot read old %s buffer length on fd #%d: %s",
			type, fd, g_strerror(errno));

/* XXX needs to add metaconfig test */
#ifdef LINUX_SYSTEM
	old_len >>= 1;		/* Linux returns twice the real amount */
#endif

	if (!shrink && old_len >= size) {
		if (GNET_PROPERTY(socket_debug) > 5)
			g_message(
				"socket %s buffer on fd #%d NOT shrank to %d bytes (is %d)",
				type, fd, size, old_len);
		return;
	}

	if (-1 == setsockopt(fd, SOL_SOCKET, option, &size, sizeof(size)))
		g_warning("cannot set new %s buffer length to %d on fd #%d: %s",
			type, size, fd, g_strerror(errno));

	len = sizeof(new_len);
	if (-1 == getsockopt(fd, SOL_SOCKET, option, &new_len, &len))
		g_warning("cannot read new %s buffer length on fd #%d: %s",
			type, fd, g_strerror(errno));

#ifdef LINUX_SYSTEM
	new_len >>= 1;		/* Linux returns twice the real amount */
#endif

	if (GNET_PROPERTY(socket_debug) > 5)
		g_message("socket %s buffer on fd #%d: %d -> %d bytes (now %d) %s",
			type, fd, old_len, size, new_len,
			(new_len == size) ? "OK" : "FAILED");
}

/**
 * Set socket's send buffer to specified size.
 * If `shrink' is false, refuse to shrink the buffer if its size is larger.
 */
void
sock_send_buf(struct gnutella_socket *s, gint size, gboolean shrink)
{
	socket_check(s);
	g_return_if_fail(!s->was_shutdown);
	sock_set_intern(s->file_desc, SO_SNDBUF, size, "send", shrink);
}

/**
 * Set socket's receive buffer to specified size.
 * If `shrink' is false, refuse to shrink the buffer if its size is larger.
 */
void
sock_recv_buf(struct gnutella_socket *s, gint size, gboolean shrink)
{
	socket_check(s);
	g_return_if_fail(!s->was_shutdown);
	sock_set_intern(s->file_desc, SO_RCVBUF, size, "receive", shrink);
}

/**
 * Turn TCP_NODELAY on or off on the socket.
 */
void
sock_nodelay(struct gnutella_socket *s, gboolean on)
{
	gint arg = on ? 1 : 0;

	socket_check(s);
	if (!(SOCK_F_TCP & s->flags)) {
		return;
	}
	if (
		-1 == setsockopt(s->file_desc, sol_tcp(), TCP_NODELAY, &arg, sizeof arg)
	) {
		if (errno != ECONNRESET)
			g_warning("unable to %s TCP_NODELAY on fd#%d: %s",
				on ? "set" : "clear", s->file_desc, g_strerror(errno));
	}
}

/**
 * Shutdown the TX side of the socket.
 */
void
sock_tx_shutdown(struct gnutella_socket *s)
{
	socket_check(s);
	g_assert(s->file_desc >= 0);

	if (s->was_shutdown)
		return;

	/* EINVAL and ENOTCONN may occur if connect() didn't succeed */
	if (
		-1 == shutdown(s->file_desc, SHUT_WR) &&
		EINVAL != errno &&
		ENOTCONN != errno
	) {
		g_warning("unable to shutdown TX on fd#%d: %s",
			s->file_desc, g_strerror(errno));
	}
	s->was_shutdown = TRUE;
}

static int
socket_get_fd(struct wrap_io *wio)
{
	struct gnutella_socket *s = wio->ctx;
	socket_check(s);
	return s->file_desc;
}

static ssize_t
socket_plain_write(struct wrap_io *wio, gconstpointer buf, size_t size)
{
	struct gnutella_socket *s = wio->ctx;

	socket_check(s);
	g_assert(!socket_uses_tls(s));

	return write(s->file_desc, buf, size);
}

static ssize_t
socket_plain_read(struct wrap_io *wio, gpointer buf, size_t size)
{
	struct gnutella_socket *s = wio->ctx;

	socket_check(s);
	g_assert(!socket_uses_tls(s));

	return read(s->file_desc, buf, size);
}

static ssize_t
socket_plain_writev(struct wrap_io *wio, const struct iovec *iov, int iovcnt)
{
	struct gnutella_socket *s = wio->ctx;

	socket_check(s);
	g_assert(!socket_uses_tls(s));

	return writev(s->file_desc, iov, iovcnt);
}

static ssize_t
socket_plain_readv(struct wrap_io *wio, struct iovec *iov, int iovcnt)
{
	struct gnutella_socket *s = wio->ctx;

	socket_check(s);
	g_assert(!socket_uses_tls(s));

	return readv(s->file_desc, iov, iovcnt);
}

static ssize_t
socket_plain_sendto(
	struct wrap_io *wio, const gnet_host_t *to, gconstpointer buf, size_t size)
{
	struct gnutella_socket *s = wio->ctx;
	socklen_t len;
	socket_addr_t addr;
	host_addr_t ha;
	ssize_t ret;

	socket_check(s);
	g_assert(!socket_uses_tls(s));

	if (!host_addr_convert(gnet_host_get_addr(to), &ha, s->net)) {
		errno = EINVAL;
		return -1;
	}

	len = socket_addr_set(&addr, ha, gnet_host_get_port(to));
	ret = sendto(s->file_desc, buf, size, 0,
			socket_addr_get_const_sockaddr(&addr), len);

	if ((ssize_t) -1 == ret && GNET_PROPERTY(udp_debug)) {
		gint e = errno;

		g_warning("sendto() failed: %s", g_strerror(e));
		errno = e;
	}
	return ret;
}

static ssize_t
socket_no_sendto(struct wrap_io *unused_wio, const gnet_host_t *unused_to,
	gconstpointer unused_buf, size_t unused_size)
{
	(void) unused_wio;
	(void) unused_to;
	(void) unused_buf;
	(void) unused_size;
	g_error("no sendto() routine allowed");
	return -1;
}

static ssize_t
socket_no_write(struct wrap_io *unused_wio,
		gconstpointer unused_buf, size_t unused_size)
{
	(void) unused_wio;
	(void) unused_buf;
	(void) unused_size;
	g_error("no write() routine allowed");
	return -1;
}

static ssize_t
socket_no_writev(struct wrap_io *unused_wio,
		const struct iovec *unused_iov, int unused_iovcnt)
{
	(void) unused_wio;
	(void) unused_iov;
	(void) unused_iovcnt;
	g_error("no writev() routine allowed");
	return -1;
}

static ssize_t
socket_no_read(struct wrap_io *unused_wio,
		gpointer unused_buf, size_t unused_size)
{
	(void) unused_wio;
	(void) unused_buf;
	(void) unused_size;
	g_error("no read() routine allowed");
	return -1;
}

static ssize_t
socket_no_readv(struct wrap_io *unused_wio,
		struct iovec *unused_iov, int unused_iovcnt)
{
	(void) unused_wio;
	(void) unused_iov;
	(void) unused_iovcnt;
	g_error("no readv() routine allowed");
	return -1;
}

static int
socket_no_flush(struct wrap_io *unused_wio)
{
	(void) unused_wio;
	return 0;
}

static void
socket_wio_link(struct gnutella_socket *s)
{
	socket_check(s);
	g_assert(s->flags & (SOCK_F_LOCAL | SOCK_F_TCP | SOCK_F_UDP));

	s->wio.ctx = s;
	s->wio.fd = socket_get_fd;
	s->wio.flush = socket_no_flush;

	if (s->flags & SOCK_F_UDP) {
		s->wio.write = socket_no_write;
		s->wio.read = socket_plain_read;
		s->wio.writev = socket_no_writev;
		s->wio.readv = socket_plain_readv;
		s->wio.sendto = socket_plain_sendto;
	} else if (SOCK_CONN_LISTENING == s->direction) {
		s->wio.write = socket_no_write;
		s->wio.read = socket_no_read;
		s->wio.writev = socket_no_writev;
		s->wio.readv = socket_no_readv;
		s->wio.sendto = socket_no_sendto;
	} else if (socket_uses_tls(s)) {
		tls_wio_link(&s->wio);
	} else {
		g_assert(s->flags & (SOCK_F_TCP | SOCK_F_LOCAL));
		s->wio.write = socket_plain_write;
		s->wio.read = socket_plain_read;
		s->wio.writev = socket_plain_writev;
		s->wio.readv = socket_plain_readv;
		s->wio.sendto = socket_no_sendto;
	}
}

/***
 *** Utility routines that do not really fit elsewhere.
 ***/

/**
 * Wrapper over readv() ensuring that we don't request more than
 * MAX_IOV_COUNT entries at a time.
 */
ssize_t
safe_readv(wrap_io_t *wio, struct iovec *iov, gint iovcnt)
{
	size_t got = 0;
	struct iovec *end = iov + iovcnt;
	struct iovec *siov;
	gint siovcnt = MAX_IOV_COUNT;
	gint iovgot = 0;

	for (siov = iov; siov < end; siov += siovcnt) {
		ssize_t r;
		size_t size;
		struct iovec *xiv;
		struct iovec *xend;

		siovcnt = iovcnt - iovgot;
		if (siovcnt > MAX_IOV_COUNT)
			siovcnt = MAX_IOV_COUNT;
		g_assert(siovcnt > 0);

		r = wio->readv(wio, siov, siovcnt);

		if ((ssize_t) -1 == r || 0 == r) {
			if (r == 0 || got)
				break;				/* Don't flag error if we read bytes */
			return -1;				/* Propagate error */
		}

		got += r;
		iovgot += siovcnt;		/* We'll break out if we did not get it all */

		/*
		 * How much did we get?  If not the whole vector, we're blocking,
		 * so stop reading and return amount we got.
		 */

		for (size = 0, xiv = siov, xend = siov + siovcnt; xiv < xend; xiv++)
			size += xiv->iov_len;

		if ((size_t) r < size)
			break;
	}

	return got;
}

/**
 * Wrapper over readv() ensuring that we don't request more than
 * MAX_IOV_COUNT entries at a time.
 */
ssize_t
safe_readv_fd(gint fd, struct iovec *iov, gint iovcnt)
{
	size_t got = 0;
	struct iovec *end = iov + iovcnt;
	struct iovec *siov;
	gint siovcnt = MAX_IOV_COUNT;
	gint iovgot = 0;

	for (siov = iov; siov < end; siov += siovcnt) {
		ssize_t r;
		size_t size;
		struct iovec *xiv;
		struct iovec *xend;

		siovcnt = iovcnt - iovgot;
		if (siovcnt > MAX_IOV_COUNT)
			siovcnt = MAX_IOV_COUNT;
		g_assert(siovcnt > 0);

		r = readv(fd, siov, siovcnt);

		if ((ssize_t) -1 == r || 0 == r) {
			if (r == 0 || got)
				break;				/* Don't flag error if we read bytes */
			return -1;				/* Propagate error */
		}

		got += r;
		iovgot += siovcnt;		/* We'll break out if we did not get it all */

		/*
		 * How much did we get?  If not the whole vector, we're blocking,
		 * so stop reading and return amount we got.
		 */

		for (size = 0, xiv = siov, xend = siov + siovcnt; xiv < xend; xiv++)
			size += xiv->iov_len;

		if ((size_t) r < size)
			break;
	}

	return got;
}

/**
 * Wrapper over writev() ensuring that we don't request more than
 * MAX_IOV_COUNT entries at a time.
 */
ssize_t
safe_writev(wrap_io_t *wio, const struct iovec *iov, gint iovcnt)
{
	const struct iovec *siov, *end = &iov[iovcnt];
	gint siovcnt = MAX_IOV_COUNT;
	gint iovsent = 0;
	size_t sent = 0;

	for (siov = iov; siov < end; siov += siovcnt) {
		const struct iovec *xiv, *xend;
		size_t size;
		ssize_t r;

		siovcnt = iovcnt - iovsent;
		if (siovcnt > MAX_IOV_COUNT)
			siovcnt = MAX_IOV_COUNT;
		g_assert(siovcnt > 0);

		r = wio->writev(wio, siov, siovcnt);

		if ((ssize_t) -1 == r || 0 == r) {
			if (r == 0 || sent)
				break;				/* Don't flag error if bytes sent */
			return -1;				/* Propagate error */
		}

		sent += r;
		iovsent += siovcnt;		/* We'll break out if we did not send it all */

		/*
		 * How much did we send?  If not the whole vector, we're blocking,
		 * so stop writing and return amount we sent.
		 */

		for (size = 0, xiv = siov, xend = siov + siovcnt; xiv < xend; xiv++)
			size += xiv->iov_len;

		if ((size_t) r < size)
			break;
	}

	return sent;
}

/**
 * Wrapper over writev() ensuring that we don't request more than
 * MAX_IOV_COUNT entries at a time.
 */
ssize_t
safe_writev_fd(gint fd, const struct iovec *iov, gint iovcnt)
{
	const struct iovec *siov, *end = &iov[iovcnt];
	gint siovcnt = MAX_IOV_COUNT;
	gint iovsent = 0;
	size_t sent = 0;

	for (siov = iov; siov < end; siov += siovcnt) {
		const struct iovec *xiv, *xend;
		size_t size;
		ssize_t r;

		siovcnt = iovcnt - iovsent;
		if (siovcnt > MAX_IOV_COUNT)
			siovcnt = MAX_IOV_COUNT;
		g_assert(siovcnt > 0);

		r = writev(fd, siov, siovcnt);

		if ((ssize_t) -1 == r || 0 == r) {
			if (r == 0 || sent)
				break;				/* Don't flag error if bytes sent */
			return -1;				/* Propagate error */
		}

		sent += r;
		iovsent += siovcnt;		/* We'll break out if we did not send it all */

		/*
		 * How much did we send?  If not the whole vector, we're blocking,
		 * so stop writing and return amount we sent.
		 */

		for (size = 0, xiv = siov, xend = siov + siovcnt; xiv < xend; xiv++)
			size += xiv->iov_len;

		if ((size_t) r < size)
			break;
	}

	return sent;
}

void
socket_init(void)
{
	get_sol();
	(void) sol_ipv6(); /* Get rid of warning "defined but unused" */
}

/* vi: set ts=4 sw=4 cindent: */
