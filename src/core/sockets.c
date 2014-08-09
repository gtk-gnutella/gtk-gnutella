/*
 * Copyright (c) 2001-2003, 2012-2013 Raphael Manfredi
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
 * @date 2001-2003, 2012-2013
 */

#include "common.h"

#ifdef I_NETDB
#include <netdb.h>
#endif
#ifdef I_PWD
#include <pwd.h>
#endif

#include "sockets.h"

#include "ban.h"
#include "bsched.h"
#include "ctl.h"
#include "downloads.h"
#include "features.h"
#include "geo_ip.h"
#include "gnet_stats.h"
#include "hostiles.h"
#include "http.h"
#include "inet.h"
#include "ipp_cache.h"
#include "nodes.h"
#include "parq.h"
#include "pproxy.h"
#include "settings.h"
#include "udp.h"
#include "uploads.h"

#include "shell/shell.h"

#include "upnp/upnp.h"

#include "if/gnet_property.h"
#include "if/gnet_property_priv.h"

#include "lib/adns.h"
#include "lib/aging.h"
#include "lib/ascii.h"
#include "lib/atoms.h"
#include "lib/compat_un.h"
#include "lib/cq.h"
#include "lib/endian.h"
#include "lib/entropy.h"
#include "lib/fd.h"
#include "lib/getline.h"
#include "lib/gnet_host.h"
#include "lib/halloc.h"
#include "lib/header.h"
#include "lib/once.h"
#include "lib/pslist.h"
#include "lib/random.h"
#include "lib/str.h"
#include "lib/stringify.h"
#include "lib/timestamp.h"
#include "lib/tm.h"
#include "lib/unsigned.h"
#include "lib/walloc.h"

#ifdef HAS_SOCKER_GET
#include <socker.h>
#endif /* HAS_SOCKER_GET */

#include "lib/override.h"		/* Must be the last header included */

#ifndef SHUT_WR
/* FIXME: This should be handled by Configure because SHUT_* are sometimes
 *		  enums instead of macro definitions.
 */
#define SHUT_WR 1					/**< Shutdown TX side */
#endif

#define RQST_LINE_LENGTH	256		/**< Reasonable estimate for request line */
#define SOCK_UDP_RECV_BUF	131072	/**< 128K - Large to avoid loosing dgrams */
#define MAX_UDP_AGE			5		/**< Max UDP age before RX dropping */
#define MAX_UDP_LOOP_MS		37		/**< Amount of CPU time we can spend */
#define UDP_QUEUED_GUESS	65536	/**< Guess amount of pending RX input */
#define UDP_QUEUE_DELAY_MS	250		/**< RX queue processing delay */
#define TLS_BAN_FREQ		300		/**< Avoid TLS for 5 minutes */

enum {
	SOCK_ADNS_PENDING	= 1 << 0,	/**< Don't free() the socket too early */
	SOCK_ADNS_FAILED	= 1 << 1,	/**< Signals error in the ADNS callback */
	SOCK_ADNS_BADNAME	= 1 << 2,	/**< Signals bad host name */
	SOCK_ADNS_ASYNC		= 1 << 3	/**< Signals async resolution */
};

struct gnutella_socket *s_tcp_listen = NULL;
struct gnutella_socket *s_tcp_listen6 = NULL;
struct gnutella_socket *s_udp_listen = NULL;
struct gnutella_socket *s_udp_listen6 = NULL;
struct gnutella_socket *s_local_listen = NULL;

static aging_table_t *tls_ban;
static once_flag_t tls_ban_inited;

static bool socket_shutdowned;		/**< Set when layer has been shutdowned */

static void socket_accept(void *data, int, inputevt_cond_t cond);
static bool socket_reconnect(struct gnutella_socket *s);

static void
tls_ban_init(void)
{
	tls_ban = aging_make(TLS_BAN_FREQ,
		gnet_host_hash, gnet_host_equal, gnet_host_free_atom2);
}

static bool
socket_tls_banned(const host_addr_t addr, const uint16 port)
{
	gnet_host_t to;

	if (NULL == tls_ban)
		return FALSE;

	gnet_host_set(&to, addr, port);
	return NULL != aging_lookup(tls_ban, &to);
}

static struct gnutella_socket *
socket_alloc(void)
{
	static const struct gnutella_socket zero_socket;
	struct gnutella_socket *s;

	WALLOC(s);
	*s = zero_socket;
	s->magic = SOCKET_MAGIC;
	return s;
}

static void
socket_alloc_buffer(struct gnutella_socket *s)
{
	socket_buffer_check(s);

	if (NULL == s->buf) {
		g_assert(0 == s->pos);
		s->buf_size = SOCK_BUFSZ;
		s->buf = halloc(s->buf_size);
	}
}

static void
socket_free_buffer(struct gnutella_socket *s)
{
	socket_buffer_check(s);

	if (NULL != s->buf) {
		s->buf_size = 0;
		HFREE_NULL(s->buf);
		s->pos = 0;
	}
}

static void
socket_dealloc(struct gnutella_socket **s_ptr)
{
	struct gnutella_socket *s;

	g_assert(s_ptr);
	s = *s_ptr;
	if (s) {
		socket_check(s);
		s->magic = 0;
		s->wio.magic = 0;
		WFREE(s);
		*s_ptr = NULL;
	}
}

static host_addr_t
socket_ipv6_trt_map(const host_addr_t addr)
{
	if (
		GNET_PROPERTY(use_ipv6_trt) &&
		host_addr_is_ipv4(addr) &&
		host_addr_is_ipv6(GNET_PROPERTY(ipv6_trt_prefix))
	) {
		host_addr_t ret;

		ret = GNET_PROPERTY(ipv6_trt_prefix);
		poke_be32(&ret.addr.ipv6[12], host_addr_ipv4(addr));
		return ret;
	}
	return addr;
}

/**
 * Stringify a socket connection type.
 */
static const char *
socket_type_to_string(enum socket_type type)
{
	switch (type) {
	case SOCK_TYPE_UNKNOWN:		return "unknown";
	case SOCK_TYPE_CONTROL:		return "Gnet";
	case SOCK_TYPE_DOWNLOAD:	return "HTTP-download";
	case SOCK_TYPE_UPLOAD:		return "HTTP-upload";
	case SOCK_TYPE_HTTP:		return "HTTP";
	case SOCK_TYPE_SHELL:		return "shell";
	case SOCK_TYPE_CONNBACK:	return "Gnet-connect-back";
	case SOCK_TYPE_PPROXY:		return "HTTP-push-proxy";
	case SOCK_TYPE_DESTROYING:	return "(destroying)";
	case SOCK_TYPE_UDP:			return "UDP";
	}

	return "?";
}

/**
 * Return the file descriptor to use for I/O monitoring callbacks on
 * the socket.
 */
int
socket_evt_fd(struct gnutella_socket *s)
{
	socket_fd_t fd = INVALID_SOCKET;

	socket_check(s);
	switch (s->direction) {
	case SOCK_CONN_LISTENING:
		g_assert(is_valid_fd(s->file_desc));
		fd = s->file_desc;
		break;

	case SOCK_CONN_INCOMING:
	case SOCK_CONN_OUTGOING:
	case SOCK_CONN_PROXY_OUTGOING:
		g_assert(s->wio.fd != NULL);
		fd = s->wio.fd(&s->wio);
		break;
	}
	g_assert(is_valid_fd(fd));

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
	inputevt_cond_t cond, inputevt_handler_t handler, void *data)
{
	int fd;

	socket_check(s);
	g_assert(handler);
	g_assert(INPUT_EVENT_EXCEPTION != cond);
	g_assert(0 != (INPUT_EVENT_RW & cond));
	g_assert(0 == s->gdk_tag);

	fd = socket_evt_fd(s);

	s->tls.cb_cond = cond;
	s->tls.cb_handler = handler;
	s->tls.cb_data = data;

	if (GNET_PROPERTY(tls_debug) > 4) {
		g_debug("socket_evt_set: fd=%d, cond=%s",
			fd, inputevt_cond_to_string(cond));
	}
	s->gdk_tag = inputevt_add(fd, cond, handler, data);
	g_assert(0 != s->gdk_tag);

	if (!(INPUT_EVENT_W & cond) && s->wio.flush(&s->wio) < 0) {
		if (!is_temporary_error(errno)) {
			g_warning("%s: flush error: %m", G_STRFUNC);
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
		if (GNET_PROPERTY(tls_debug) > 4) {
			int fd = socket_evt_fd(s);
			g_debug("socket_evt_clear: fd=%d, cond=%s",
				fd, inputevt_cond_to_string(s->tls.cb_cond));
		}

		s->tls.cb_cond = 0;
		s->tls.cb_handler = NULL;
		s->tls.cb_data = NULL;

		inputevt_remove(&s->gdk_tag);
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

static pslist_t *sl_incoming = NULL;	/**< To spot inactive sockets */

static void guess_local_addr(const struct gnutella_socket *s);
static void socket_destroy(struct gnutella_socket *s, const char *reason);
static void socket_connected(void *data, int source, inputevt_cond_t cond);
static void socket_wio_link(struct gnutella_socket *s);

/*
 * SOL_TCP and SOL_IP aren't standards. Some platforms define them, on
 * some it's safe to assume they're the same as IPPROTO_*, but the
 * only way to be portably safe is to use protoent functions.
 *
 * If the user changes /etc/protocols while running gtkg, things may
 * go badly.
 */
static bool sol_got = FALSE;
static int sol_tcp_cached = -1;
static int sol_ip_cached = -1;
static int sol_ipv6_cached = -1;

#ifdef IPTOS_LOWDELAY
#define iptos_lowdelay IPTOS_LOWDELAY
#else
#define iptos_lowdelay 0
#endif

#ifdef IPTOS_THROUGHPUT
#define iptos_throughput IPTOS_THROUGHPUT
#else
#define iptos_throughput 0
#endif

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
static inline int
sol_tcp(void)
{
	g_assert(sol_got);
	return sol_tcp_cached;
}

/**
 * @returns SOL_IP.
 */
static inline int
sol_ip(void)
{
	g_assert(sol_got);
	return sol_ip_cached;
}

/**
 * @returns SOL_IPV6.
 */
static inline int
sol_ipv6(void)
{
	g_assert(sol_got);
	return sol_ipv6_cached;
}

/**
 * Set the TOS on the socket.  Routers can use this information to
 * better route the IP datagrams.
 */
static int
socket_tos(const struct gnutella_socket *s, int tos)
{
#ifdef USE_IP_TOS
	socket_check(s);
	g_return_val_if_fail(NET_TYPE_NONE != s->net, 0);

	if (
		GNET_PROPERTY(use_ip_tos) &&
		NET_TYPE_IPV4 == s->net &&
		-1 == setsockopt(s->file_desc, sol_ip(), IP_TOS, &tos, sizeof tos)
	) {
		if (ECONNRESET != errno) {
			const char *name;

			/* Intentionally not switch() in case some values are identical */
			if (0 == tos) {
				name = "default";
			} else if (iptos_lowdelay == tos) {
				name = "low delay";
			} else if (iptos_throughput == tos) {
				name = "throughput";
			} else {
				g_assert_not_reached();
			}
			g_warning("unable to set IP_TOS to %s (%d) on fd#%d: %m",
				name, tos, s->file_desc);
		}
		return -1;
	}

	return 0;
#else
	(void) s;
	(void) tos;
	return -1;
#endif /* USE_IP_TOS */
}

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
	static bool failed;

	failed = failed || socket_tos(s, iptos_lowdelay);
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
	static bool failed;

	failed = failed || socket_tos(s, iptos_throughput);
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

/**
 * Got an EOF condition on the socket.
 */
void
socket_eof(struct gnutella_socket *s)
{
	socket_check(s);

	s->flags |= SOCK_F_EOF;
}

/**
 * Got a "connection reset" condition on the socket.
 */
void
socket_connection_reset(struct gnutella_socket *s)
{
	socket_check(s);

	s->flags |= SOCK_F_CONNRESET;
}

static void
proxy_connect_helper(const host_addr_t *addr, size_t n, void *udata)
{
	bool *in_progress = udata;

	g_assert(addr);
	g_assert(in_progress);
	*in_progress = FALSE;

	if (n > 0) {
		/* Just pick the first address */
		gnet_prop_set_ip_val(PROP_PROXY_ADDR, addr[0]);
		g_message("resolved proxy name \"%s\" to %s",
			GNET_PROPERTY(proxy_hostname), host_addr_to_string(addr[0]));
	} else {
		g_message("could not resolve proxy name \"%s\"",
			GNET_PROPERTY(proxy_hostname));
	}
}

/**
 * Verifies the proxy settings.
 *
 * @return TRUE if a proxy is configured.
 */
static bool
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
 * Clowes. It was modified to work with gtk_gnutella and non-blocking sockets.
 * --DW
 */
static socket_fd_t
proxy_connect(socket_fd_t fd)
{
	static bool in_progress = FALSE;
	socket_addr_t server;
	socklen_t len;

	if (!is_host_addr(GNET_PROPERTY(proxy_addr)) && proxy_is_enabled()) {
		if (!in_progress) {
			in_progress = TRUE;
			g_warning("resolving proxy name \"%s\"",
				GNET_PROPERTY(proxy_hostname));
			adns_resolve(GNET_PROPERTY(proxy_hostname), settings_dns_net(),
				proxy_connect_helper, &in_progress);
		}

		if (in_progress) {
			errno = VAL_EAGAIN;
			return INVALID_SOCKET;
		}
	}

	if (
		!is_host_addr(GNET_PROPERTY(proxy_addr)) ||
		!GNET_PROPERTY(proxy_port)
	) {
		errno = EINVAL;
		return INVALID_SOCKET;
	}

	len = socket_addr_set(&server,
			GNET_PROPERTY(proxy_addr), GNET_PROPERTY(proxy_port));
	return connect(fd, socket_addr_get_const_sockaddr(&server), len);
}

static int
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
			uint8 version;
			uint8 command;
			uint8 dstport[2];
			uint8 dstip[4];
			/* A null terminated username goes here */
		} *req;

		STATIC_ASSERT(8 == sizeof *req);

		req = cast_to_pointer(s->buf);
		req->version = 4;	/* SOCKS 4 */
		req->command = 1;	/* Connect */
		poke_be16(req->dstport, s->port);
		poke_be32(req->dstip, host_addr_ipv4(addr));
		length = sizeof *req;
	}

	{
		const char *name;
		size_t name_size;

		name = EMPTY_STRING(GNET_PROPERTY(socks_user));
		name_size = 1 + strlen(name);

		/* Make sure the request fits into the socket buffer */
		if (
			name_size >= s->buf_size ||
			length + name_size > s->buf_size
		) {
			/* Such a long username would be insane, no need to malloc(). */
			g_warning("%s(): username is too long", G_STRFUNC);
			return -1;
		}

		/* Copy the username */
		memcpy(&s->buf[length], name, name_size);
		length += name_size;
	}

	/* Send the socks header info */
	ret = s_write(s->file_desc, s->buf, length);

	if ((size_t) ret != length) {
		g_warning("error attempting to send SOCKS request (%s)",
			ret == (ssize_t) -1 ? strerror(errno) : "Partial write");
		return -1;
	}

	return 0;
}

static int
recv_socks4(struct gnutella_socket *s)
{
	struct {
		uint8 version;
		uint8 result;
		uint8 ignore1[2];
		uint8 ignore2[4];
	} reply;
	static const size_t size = sizeof reply;
	ssize_t ret;

	STATIC_ASSERT(8 == sizeof reply);
	socket_check(s);

	ret = s_read(s->file_desc, cast_to_pointer(&reply), size);
	if ((ssize_t) -1 == ret) {
		g_warning("error attempting to receive SOCKS reply: %m");
		return ECONNREFUSED;
	}
	if ((size_t) ret != size) {
		g_warning("short reply from SOCKS server");
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

static int
connect_http(struct gnutella_socket *s)
{
	ssize_t ret;
	size_t parsed;
	int status;
	const char *str;

	socket_check(s);

	switch (s->pos) {
	case 0:
		{
			static const struct {
				const char *s;
			} parts[] = {
				{ "CONNECT " }, { NULL }, { " HTTP/1.0\r\nHost: " }, { NULL },
				{ "\r\n\r\n" },
			};
			iovec_t iov[G_N_ELEMENTS(parts)];
			const char *host_port = host_addr_port_to_string(s->addr, s->port);
			size_t size = 0;
			uint i;

			for (i = 0; i < G_N_ELEMENTS(iov); i++) {
				size_t n;

				iovec_set_base(&iov[i], deconstify_char(
									parts[i].s ? parts[i].s : host_port));
				n = strlen(iovec_base(&iov[i]));
				iovec_set_len(&iov[i], n);
				size += n;
			}

			ret = s_writev(s->file_desc, iov, G_N_ELEMENTS(iov));
			if ((size_t) ret != size) {
				g_warning("sending info to HTTP proxy failed: %s",
					ret == (ssize_t) -1 ? g_strerror(errno) : "Partial write");
				return -1;
			}
		}
		s->pos++;
		break;

	case 1:
		ret = s_read(s->file_desc, s->buf, s->buf_size - 1);
		if (ret == (ssize_t) -1) {
			g_warning("receiving answer from HTTP proxy failed: %m");
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
			g_warning("bad HTTP proxy status line");
			return -1;
		}
		if ((status / 100) != 2) {
			g_warning("cannot use HTTP proxy: \"%s\"", str);
			return -1;
		}
		s->pos++;

		while (ret != 0) {
			getline_reset(s->getline);
			switch (getline_read(s->getline, s->buf, ret, &parsed)) {
			case READ_OVERFLOW:
				g_warning("HTTP proxy returned too long a line");
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
		ret = s_read(s->file_desc, s->buf, s->buf_size - 1);
		if (ret == (ssize_t) -1) {
			g_warning("receiving answer from HTTP proxy failed: %m");
			return -1;
		}
		while (ret != 0) {
			getline_reset(s->getline);
			switch (getline_read(s->getline, s->buf, ret, &parsed)) {
			case READ_OVERFLOW:
				g_warning("HTTP proxy returned too long a line");
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

static int
connect_socksv5(struct gnutella_socket *s)
{
	static const char verstring[] = "\x05\x02\x02";
	ssize_t ret = 0;
	size_t size;
	const char *name;
	int sockid;
	host_addr_t addr;

	socket_check(s);

	sockid = s->file_desc;

	if (!host_addr_convert(s->addr, &addr, NET_TYPE_IPV4))
		addr = s->addr;

	{
		bool ok = FALSE;

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
		ret = s_write(sockid, verstring, size);
		if ((size_t) ret != size) {
			g_warning("sending SOCKS method negotiation failed: %s",
				ret == (ssize_t) -1 ? g_strerror(errno) : "Partial write");
			return -1;
		}
		s->pos++;
		break;

	case 1:
		/* Now receive the reply as to which method we're using */
		size = 2;
		ret = s_read(sockid, s->buf, size);
		if (ret == (ssize_t) -1) {
			g_warning("receiving SOCKS method negotiation reply failed: %m");
			return ECONNREFUSED;
		}

		if ((size_t) ret != size) {
			g_warning("short reply from SOCKS server");
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

		name = GNET_PROPERTY(socks_user);
		if (name == NULL) {
			g_warning("SOCKS no username to authenticate with");
			return ECONNREFUSED;
		}

		if (GNET_PROPERTY(socks_pass) == NULL) {
			g_warning("SOCKS no password to authenticate with");
			return ECONNREFUSED;
		}

		if (strlen(name) > 255 || strlen(GNET_PROPERTY(socks_pass)) > 255) {
			g_warning("SOCKS username or password exceeds 255 characters");
			return ECONNREFUSED;
		}

		size = str_bprintf(s->buf, s->buf_size, "\x01%c%s%c%s",
					(uchar) strlen(name),
					name,
					(uchar) strlen(GNET_PROPERTY(socks_pass)),
					GNET_PROPERTY(socks_pass));

		/* Send out the authentication */
		ret = s_write(sockid, s->buf, size);
		if ((size_t) ret != size) {
			g_warning("sending SOCKS authentication failed: %s",
				ret == (ssize_t) -1 ? g_strerror(errno) : "Partial write");
			return -1;
		}

		s->pos++;

		break;
	case 3:
		/* Receive the authentication response */
		size = 2;
		ret = s_read(sockid, s->buf, size);
		if (ret == (ssize_t) -1) {
			g_warning("receiving SOCKS authentication reply failed: %m");
			return ECONNREFUSED;
		}

		if ((size_t) ret != size) {
			g_warning("short reply from SOCKS server");
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

		ret = s_write(sockid, s->buf, size);
		if ((size_t) ret != size) {
			g_warning("send SOCKS connect command failed: %s",
				ret == (ssize_t) -1 ? g_strerror(errno) : "Partial write");
			return (-1);
		}

		s->pos++;
		break;
	case 5:
		/* Now receive the reply to see if we connected */

		size = 10;
		ret = s_read(sockid, s->buf, size);
		if ((ssize_t) -1 == ret) {
			g_warning("receiving SOCKS connection reply failed: %m");
			return ECONNREFUSED;
		}
		if (GNET_PROPERTY(socket_debug)) {
			g_debug("%s: step 5, bytes recv'd %zu", G_STRFUNC, ret);
		}
		if ((size_t) ret != size) {
			g_warning("short reply from SOCKS server");
			return ECONNREFUSED;
		}

		/* See the connection succeeded */
		if (s->buf[1] != '\0') {
			const char *msg;
			int error;

			switch (s->buf[1]) {
			case 1:
				msg = "General SOCKS server failure";
				error = ECONNABORTED;
				break;
			case 2:
				msg = "Connection denied by rule";
				error = ECONNABORTED;
				break;
			case 3:
				msg = "Network unreachable";
				error = ENETUNREACH;
				break;
			case 4:
				msg = "Host unreachable";
				error = EHOSTUNREACH;
				break;
			case 5:
				msg = "Connection refused";
				error = ECONNREFUSED;
				break;
			case 6:
				msg = "TTL Expired";
				error = ETIMEDOUT;
				break;
			case 7:
				msg = "Command not supported";
				error = ECONNABORTED;
				break;
			case 8:
				msg = "Address type not supported";
				error = ECONNABORTED;
				break;
			default:
				msg = "Unknown error";
				error = ECONNABORTED;
				break;
			}
			g_warning("SOCKS connect failed: %s", msg);
			return error;
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
		pslist_t *sl_addrs, *sl;
		host_addr_t addr, old_addr, first_addr;

		addr = zero_host_addr;
		first_addr = zero_host_addr;
		old_addr = listen_addr6();

		sl_addrs = host_addr_get_interface_addrs(NET_TYPE_IPV6);
		PSLIST_FOREACH(sl_addrs, sl) {
			host_addr_t *addr_ptr;

			addr_ptr = sl->data;
			addr = *addr_ptr;
			if (!host_addr_is_routable(addr)) {
				continue;
			}
			if (host_addr_equiv(old_addr, addr)) {
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
		if (!host_addr_equiv(old_addr, addr)) {
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
	pslist_t *l;
	pslist_t *to_remove = NULL;

	PSLIST_FOREACH(sl_incoming, l) {
		struct gnutella_socket *s = l->data;
		time_delta_t delta;

		socket_check(s);
		g_assert(s->last_update);

		/*
		 * Last_update can be in the future due to PARQ. This is needed
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

			to_remove = pslist_prepend(to_remove, s);
		}
	}

	PSLIST_FOREACH(to_remove, l) {
		struct gnutella_socket *s = l->data;
		socket_destroy(s, "Connection timeout");
	}
	pslist_free(to_remove);

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

static inline void
socket_disable(struct gnutella_socket *s)
{
	if (s != NULL)
		socket_evt_clear(s);
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

	if (s_tcp_listen != NULL)
		upnp_unmap_tcp(s_tcp_listen->local_port);
	if (s_udp_listen != NULL)
		upnp_unmap_udp(s_udp_listen->local_port);
	
	/* No longer accept connections or UDP packets */
	socket_disable(s_local_listen);
	socket_disable(s_tcp_listen);
	socket_disable(s_tcp_listen6);
	socket_disable(s_udp_listen);
	socket_disable(s_udp_listen6);

	socket_shutdowned = TRUE;
}

/**
 * Cleanup remaining data structures on final close down.
 */
void
socket_closedown(void)
{
	socket_free_null(&s_local_listen);
	socket_free_null(&s_tcp_listen);
	socket_free_null(&s_tcp_listen6);
	socket_free_null(&s_udp_listen);
	socket_free_null(&s_udp_listen6);

	aging_destroy(&tls_ban);
}

/* ----------------------------------------- */

/**
 * Attach operation callbacks to non-UDP socket, superseding its type.
 *
 * @param s		the socket (TCP or LOCAL, not UDP)
 * @param type	new socket type (for logging mostly)
 * @param ops	operation callbacks to install
 * @param owner	socket owner, passed to callback in addition to socket
 */
void
socket_attach_ops(gnutella_socket_t *s,
	enum socket_type type, struct socket_ops *ops, void *owner)
{
	socket_check(s);
	g_assert(!(s->flags & SOCK_F_UDP));
	g_assert(ops != NULL);
	
	if (NULL == s->resource.tcp)
		WALLOC(s->resource.tcp);

	s->resource.tcp->owner = owner;
	s->resource.tcp->ops = ops;
	s->type = type;
}

/**
 * Detach operation callbacks from non-UDP socket.
 */
void
socket_detach_ops(gnutella_socket_t *s)
{
	socket_check(s);
	g_assert(!(s->flags & SOCK_F_UDP));

	WFREE_TYPE_NULL(s->resource.tcp);
}

/**
 * Change owner of non-UDP socket.
 */
void
socket_change_owner(gnutella_socket_t *s, void *owner)
{
	socket_check(s);
	g_assert(s->resource.tcp != NULL);

	s->resource.tcp->owner = owner;
}

/**
 * Destroy a socket.
 *
 * If there is an attached resource, call the resource's termination routine
 * with the supplied reason.
 */
static void
socket_destroy(struct gnutella_socket *s, const char *reason)
{
	socket_check(s);

	/*
	 * If there is an attached resource, its removal routine is responsible
	 * for calling back socket_free().
	 */

	switch (s->type) {
	case SOCK_TYPE_UDP:
		break;
	default:
		/*
		 * Invoke optional destruction callback installed by the owner of
		 * the socket, which must then invoke socket_free_null() itself.
		 */

		if (s->resource.tcp != NULL && s->resource.tcp->ops->destroy != NULL) {
			(*s->resource.tcp->ops->destroy)(s, s->resource.tcp->owner, reason);
			return;
		}
		break;
	}

	/*
	 * No attached resource, we can simply free this socket then.
	 */

	socket_free_null(&s);
}

/**
 * Free UDP queued datagram.
 */
static void
socket_udpq_free(struct udpq *uq)
{
	g_assert(uq != NULL);

	WFREE_NULL(uq->buf, uq->len);
	WFREE(uq);
}

/**
 * Embedded list callback to free a 'struct udpq' item.
 */
static void
socket_udp_qfree(void *item, void *unused_data)
{
	(void) unused_data;

	socket_udpq_free(item);
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
		struct udpctx *uctx = s->resource.udp;
		if (uctx != NULL) {
			WFREE_NULL(uctx->socket_addr, sizeof(socket_addr_t));
			eslist_foreach(&uctx->queue, socket_udp_qfree, NULL);
			cq_cancel(&uctx->queue_ev);
			WFREE(s->resource.udp);
		}
	} else {
		WFREE_TYPE_NULL(s->resource.tcp);
	}

	if (s->last_update) {
		g_assert(sl_incoming);
		sl_incoming = pslist_remove(sl_incoming, s);
		s->last_update = 0;
	}
	if (s->adns & SOCK_ADNS_PENDING) {
		s->type = SOCK_TYPE_DESTROYING;
		return;
	}
	if (s->getline) {
		getline_free(s->getline);
		s->getline = NULL;
	}

	if (socket_with_tls(s)) {
		if (is_valid_fd(s->file_desc) && socket_uses_tls(s)) {
			if (SOCK_CONN_INCOMING != s->direction) {
				tls_cache_insert(s->addr, s->port);
			}
			if (!(SOCK_F_CONNRESET & s->flags)) {
				tls_bye(s);
			}
		}
		tls_free(s);
	}
	socket_evt_clear(s);

	if (is_valid_fd(s->file_desc)) {
		socket_cork(s, FALSE);
		socket_tx_shutdown(s);

		/*
		 * Socket closing is a source of randomness since the actual file
		 * descriptor being closed and the closing order between different
		 * sockets is hard to predict.
		 */

		entropy_harvest_single(VARLEN(s->file_desc));

		if (compat_socket_close(s->file_desc)) {
			g_warning("%s: close(%d) failed: %m", G_STRFUNC, s->file_desc);
		}
		s->file_desc = INVALID_SOCKET;
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
static bool
socket_tls_setup(struct gnutella_socket *s)
{
	if (!s->tls.enabled)
		return 0;

	if (s->tls.stage < SOCK_TLS_INITIALIZED) {
		if (tls_init(s))
			goto destroy;
		s->tls.stage = SOCK_TLS_INITIALIZED;
		socket_nodelay(s, TRUE);
	}

	if (s->tls.stage < SOCK_TLS_ESTABLISHED) {
		switch (tls_handshake(s)) {
		case TLS_HANDSHAKE_ERROR:
			if (SOCK_CONN_INCOMING != s->direction) {
				tls_cache_remove(s->addr, s->port);
			}
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

/**
 * Used for incoming connections.
 *
 * Read intial bytes on an unknown incoming socket.
 * When the first line has been read, we parse it to decide what type of
 * connection we're facing.
 *
 * If the first line is not complete on the first call, this function
 * will be called as often as necessary to fetch a full line.
 *
 * This routine is no longer called once the type of connection has been
 * determined.
 */
static void
socket_read(void *data, int source, inputevt_cond_t cond)
{
	struct gnutella_socket *s = data;
	size_t count;
	ssize_t r;
	size_t parsed;
	const char *first, *endptr;
	hostiles_flags_t hostile;

	(void) source;

	if G_UNLIKELY(socket_shutdowned) {
		socket_destroy(s, "Servent shutdown");
		return;
	}

	if G_UNLIKELY(cond & INPUT_EVENT_EXCEPTION) {
		socket_destroy(s, "Input exception");
		return;
	}

	g_assert(0 == s->pos);		/* We read a line, then leave this callback */

	/*
	 * Application-level hook for the UNIX socket emulation layer.
	 */

	if (s->direction == SOCK_CONN_INCOMING && (s->flags & SOCK_F_LOCAL)) {
		bool error;

		if (compat_accept_check(s->file_desc, &error)) {
			if (error)
				socket_destroy(s, "UNIX emulation input error");
			return;
		}
		/* FALL THROUGH */
	}

	if (s->direction == SOCK_CONN_INCOMING && s->tls.enabled) {
		if (s->tls.enabled && s->tls.stage < SOCK_TLS_INITIALIZED) {
			ssize_t ret;
			char c;

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

				if (is_ascii_alnum(c) || '\n' == c || '\r' == c) {
					s->tls.enabled = FALSE;
				}

				if (GNET_PROPERTY(tls_debug) > 2) {
					g_debug("socket_read(): c=0x%02x%s",
						(unsigned char) c, s->tls.enabled ? " [TLS]" : "");
				}
			}
		}

		if (0 != socket_tls_setup(s)) {
			if (!is_temporary_error(errno)) {
				socket_destroy(s, _("TLS handshake failed"));
			}
			return;
		}
	}

	socket_alloc_buffer(s);

	g_assert(s->buf_size >= s->pos);
	count = s->buf_size - s->pos;

	/* 1 to allow trailing NUL */
	if (count < 1) {
		g_warning("%s(): incoming buffer full, disconnecting from %s",
			 G_STRFUNC, host_addr_to_string(s->addr));
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
		g_warning("%s(): first line too long, disconnecting from %s",
			 G_STRFUNC, host_addr_to_string(s->addr));
		dump_hex(stderr, "Leading Data",
			getline_str(s->getline), MIN(getline_length(s->getline), 256));
		if (
			is_strprefix(s->buf, "GET ") ||
			is_strprefix(s->buf, "HEAD ")
		) {
			http_send_status(HTTP_UPLOAD, s, 414, FALSE, NULL, 0,
				"Requested URL Too Large");
		}
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
	sl_incoming = pslist_remove(sl_incoming, s);
	s->last_update = 0;

	first = getline_str(s->getline);

	/*
	 * Always authorize replies for our PUSH requests.
	 * Likewise for PARQ download resuming.
	 */

	if (is_strprefix(first, "GIV ") || is_strprefix(first, "PUSH ")) {
		/* GIV is Gnutella's answer, "PUSH" is G2's answer */
		download_push_ack(s);
		return;
	}

	if (parq_is_enabled() && is_strprefix(first, "QUEUE ")) {
		parq_download_queue_ack(s);
		return;
	}

	/*
	 * Check for banning.
	 */

	switch (ban_allow(BAN_CAT_SOCKET, s->addr)) {
	case BAN_OK:				/* Connection authorized */
		break;
	case BAN_FORCE:				/* Connection refused, no ack */
		ban_force(s);
		goto cleanup;
	case BAN_MSG:				/* Send specific 403 error message */
		{
			const char *msg = ban_message(s->addr);

            if (GNET_PROPERTY(socket_debug)) {
                g_debug("rejecting connection from banned %s (%s still): %s",
                    host_addr_to_string(s->addr),
					short_time(ban_delay(BAN_CAT_SOCKET, s->addr)), msg);
            }

			if (is_strprefix(first, GNUTELLA_HELLO)) {
				send_node_error(s, 503, "%s", msg);
			} else {
				http_extra_desc_t hev;

				http_extra_callback_set(&hev, http_retry_after_add,
					GUINT_TO_POINTER(ban_delay(BAN_CAT_SOCKET, s->addr)));
				http_send_status(HTTP_UPLOAD, s, 503, FALSE, &hev, 1,
					"%s", msg);
			}
		}
		goto cleanup;
	case BAN_FIRST:				/* Connection refused, negative ack */
		entropy_harvest_single(VARLEN(s->addr));
		if (is_strprefix(first, GNUTELLA_HELLO))
			send_node_error(s, 550, "Banned for %s",
				short_time_ascii(ban_delay(BAN_CAT_SOCKET, s->addr)));
		else {
			int delay = ban_delay(BAN_CAT_SOCKET, s->addr);
			http_extra_desc_t hev;

			http_extra_callback_set(&hev, http_retry_after_add,
				GUINT_TO_POINTER(delay));
			http_send_status(HTTP_UPLOAD, s, 550, FALSE, &hev, 1,
				"Banned for %s", short_time_ascii(delay));
		}
		goto cleanup;
	default:
		g_assert_not_reached();
	}

	if (parq_is_enabled()) {
		time_t banlimit;
		/*
		 * Check for PARQ banning.
		 * 		-- JA, 29/07/2003
		 */

		banlimit = parq_banned_source_expire(s->addr);
		if (banlimit) {
			if (GNET_PROPERTY(socket_debug)) {
				g_warning("[sockets] PARQ has banned host %s until %s",
					host_addr_to_string(s->addr),
					timestamp_to_string(banlimit));
			}
			ban_force(s);
			goto cleanup;
		}
	}

	/*
	 * Deny connections from hostile IP addresses.
	 *
	 * We do this after banning checks so that if they hammer us, they
	 * get banned silently.
	 */

	hostile = hostiles_check(s->addr);

	if (
		hostiles_flags_are_bad(hostile) ||
		hostiles_flags_warrant_shunning(hostile)
	) {
		static const char banned[]  = "Hostile IP address banned";
		static const char shunned[] = "Shunned IP address";
		bool bad = hostiles_flags_are_bad(hostile);

		socket_disable_token(s);

		if (GNET_PROPERTY(socket_debug)) {
			const char *string = first;

			if (!is_printable_iso8859_string(first))
				string = "<non-printable request>";
			g_warning("denying connection from hostile %s (%s): \"%s\"",
				host_addr_to_string(s->addr),
				hostiles_flags_to_string(hostile), string);
		}

		if (is_strprefix(first, GNUTELLA_HELLO)) {
			send_node_error(s, 550, bad ? banned : shunned);
		} else {
			http_send_status(HTTP_UPLOAD, s, 550, FALSE, NULL, 0,
				bad ? banned : shunned);
		}
		goto cleanup;
	}

	/*
	 * Dispatch request. Here we decide what kind of connection this is.
	 */

	if (is_strprefix(first, GNUTELLA_HELLO)) {
		/* Incoming control connection */
		node_add_socket(s);
	} else if (
		NULL != (endptr = is_strprefix(first, "GET ")) ||
		NULL != (endptr = is_strprefix(first, "HEAD "))
	) {
		const char *uri;

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
		g_warning("%s(): got unknown incoming connection from %s, dropping!",
			G_STRFUNC, host_addr_to_string(s->addr));
		if (len > 0)
			dump_hex(stderr, "First Line", first, MIN(len, 160));
	}
	if (strstr(first, "HTTP")) {
		http_send_status(HTTP_UPLOAD, s, 501, FALSE, NULL, 0,
			"Method Not Implemented");
	}
	/* FALL THROUGH */

cleanup:
	socket_destroy(s, NULL);
}

/**
 * Socket connection failed, destroy the socket.
 *
 * If we're establishing a download, try to fallback to sending push since
 * a direct connection seems impossible.
 */
static void
socket_connection_failed(struct gnutella_socket *s, const char *errmsg)
{
	if (
		s->resource.tcp != NULL &&
		s->resource.tcp->ops->connect_failed != NULL
	) {
		(*s->resource.tcp->ops->connect_failed)(s,
			s->resource.tcp->owner, errmsg);
		return;		/* Socket destroyed by callback */
	}

	socket_destroy(s, errmsg);
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
socket_connected(void *data, int source, inputevt_cond_t cond)
{
	/* We are connected to somebody */

	struct gnutella_socket *s = data;

	socket_check(s);
	g_assert((socket_fd_t) source == s->file_desc);

	if G_UNLIKELY(socket_shutdowned) {
		socket_destroy(s, "Servent shutdown");
		return;
	}

	if G_UNLIKELY(cond & INPUT_EVENT_EXCEPTION) {	/* Error while connecting */
		bws_sock_connect_failed(s->type);
		socket_connection_failed(s, _("Connection failed"));
		return;
	}

	s->flags |= SOCK_F_ESTABLISHED;
	bws_sock_connected(s->type);

	if (0 != socket_tls_setup(s)) {
		if (!is_temporary_error(errno)) {
			if (GNET_PROPERTY(tls_debug)) {
				g_debug("TLS handshake failed when connecting to %s, %s",
					host_addr_port_to_string(s->addr, s->port),
					GNET_PROPERTY(tls_enforce) ? "aborting" : "retrying");
			}

			/*
			 * When TLS is not enforced, attempt to reconnect to the same
			 * server without any TLS support, in case we had incorrectly
			 * flagged the host as supporting TLS.
			 *		--RAM, 2012-02-20
			 */

			if (GNET_PROPERTY(tls_enforce) || !socket_reconnect(s)) {
				socket_connection_failed(s, _("TLS handshake failed"));
			}
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
		int res, option;
		socklen_t size = sizeof option;

		socket_evt_clear(s);

		/* Check whether the socket is really connected */

		res = getsockopt(s->file_desc, SOL_SOCKET, SO_ERROR,
					   (void *) &option, &size);

		if (res == -1 || option) {
			socket_connection_failed(s, _("Connection failed"));
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

		/*
		 * Notify owner about connection success.
		 */

		if (
			s->resource.tcp != NULL &&
			s->resource.tcp->ops->connected != NULL
		) {
			(*s->resource.tcp->ops->connected)(s, s->resource.tcp->owner);
		}
	}
}

/**
 * Extract the local address from the socket, filling ``addrptr'' with the
 * extracted IP address.
 *
 * @return TRUE on success, FALSE on error with errno set.
 */
bool
socket_local_addr(const struct gnutella_socket *s, host_addr_t *addrptr)
{
	socket_addr_t saddr;
	int fd;

	g_return_val_if_fail(s, FALSE);

	fd = s->file_desc;
	g_return_val_if_fail(is_valid_fd(s->file_desc), FALSE);

	if (!socket_is_local(s) && 0 == socket_addr_getsockname(&saddr, fd)) {
		host_addr_t addr;

		addr = socket_addr_get_addr(&saddr);
		*addrptr = addr;		/* Struct copy */
		return host_addr_net(addr) != NET_TYPE_NONE;
	} else {
		return FALSE;
	}
}

/**
 * Tries to guess the local IP address.
 */
static void
guess_local_addr(const struct gnutella_socket *s)
{
	host_addr_t addr;

	if (socket_local_addr(s, &addr)) {
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
socket_local_port(const struct gnutella_socket *s)
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
socket_accept(void *data, int unused_source, inputevt_cond_t cond)
{
	socket_addr_t addr;
	socklen_t addr_len;
	struct gnutella_socket *s = data;
	struct gnutella_socket *t = NULL;
	int fd;

	(void) unused_source;
	socket_check(s);
	g_assert(s->flags & (SOCK_F_TCP | SOCK_F_LOCAL));

	if G_UNLIKELY(cond & INPUT_EVENT_EXCEPTION) {
		g_warning("%s(): input exception on TCP listening socket #%d!",
			G_STRFUNC, s->file_desc);
		return;		/* Ignore it, what else can we do? */
	}

	switch (s->type) {
	case SOCK_TYPE_CONTROL:
		break;
	default:
		g_warning("%s(): unknown listening socket type %d !",
			G_STRFUNC, s->type);
		socket_destroy(s, NULL);
		return;
	}

	addr_len = socket_addr_init(&addr, s->net);
	fd = compat_accept(s->file_desc,
			socket_addr_get_sockaddr(&addr), &addr_len);

	if (fd < 0) {
		/*
		 * If we ran out of file descriptors, try to reclaim one from the
		 * banning pool and retry.
		 */

		if (
			(errno == EMFILE || errno == ENFILE) &&
			reclaim_fd != NULL && (*reclaim_fd)()
		) {
			addr_len = socket_addr_init(&addr, s->net);
			fd = compat_accept(s->file_desc, socket_addr_get_sockaddr(&addr),
					&addr_len);
		}

		if (fd < 0) {
			if (errno != ECONNABORTED && !is_temporary_error(errno)) {
				g_warning("accept() failed: %m");
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

	if (s->flags & SOCK_F_TCP)
		bws_sock_accepted(SOCK_TYPE_HTTP);	/* Do not charge Gnet for that */

	/*
	 * Create a new struct socket for this incoming connection
	 */

	set_close_on_exec(fd);
	fd_set_nonblocking(fd);

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

	if ((SOCK_F_TCP & t->flags) && !is_host_addr(t->addr)) {
		if (socket_addr_getpeername(&addr, t->file_desc)) {
			g_warning("getpeername() failed: %m");
			socket_free_null(&t);
			return;
		}
		t->addr = socket_addr_get_addr(&addr);
		t->port = socket_addr_get_port(&addr);
		if (!is_host_addr(t->addr)) {
			g_warning("incoming TCP connection from unidentifiable source");
			socket_free_null(&t);
			return;
		}
		g_warning("had to use getpeername() after accept(): peer=%s",
			host_addr_port_to_string(t->addr, t->port));
	}

	if (
		(t->flags & SOCK_F_TCP) &&
		ctl_limit(t->addr, CTL_S_ANY_TCP | CTL_D_STEALTH)
	) {
		if (GNET_PROPERTY(ctl_debug) > 2) {
			g_debug("CTL closing incoming TCP connection from %s [%s]",
				host_addr_port_to_string(t->addr, t->port),
				gip_country_cc(t->addr));
		}
		socket_free_null(&t);
		return;
	}

	t->tls.enabled = s->tls.enabled; /* Inherit from listening socket */
	t->tls.stage = SOCK_TLS_NONE;
	t->tls.ctx = NULL;
	t->tls.snarf = 0;

	if (GNET_PROPERTY(tls_debug) > 2) {
		g_debug("incoming connection from %s",
			host_addr_port_to_string(t->addr, t->port));
	}

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

		sl_incoming = pslist_prepend(sl_incoming, t);
		t->last_update = tm_time();
		break;

	default:
		g_assert_not_reached();			/* Can't happen */
		break;
	}

	/* Harvest entropy */
	entropy_harvest_many(
		VARLEN(t), VARLEN(t->file_desc), VARLEN(t->addr),
		VARLEN(t->port), VARLEN(t->local_port), NULL);

	inet_got_incoming(t->addr);	/* Signal we got an incoming connection */
	if (!GNET_PROPERTY(force_local_ip))
		guess_local_addr(t);
}

#if defined(CMSG_FIRSTHDR) && defined(CMSG_NXTHDR)
static inline const struct cmsghdr *
cmsg_nxthdr(const struct msghdr *msg_, const struct cmsghdr *cmsg_)
{
	struct msghdr *msg = (struct msghdr *) msg_;
	struct cmsghdr *cmsg = (struct cmsghdr *) cmsg_;

	return CMSG_NXTHDR(msg, cmsg);
}
#endif	/* CMSG_FIRSTHDR && CMSG_NXTHDR */

static inline bool
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
				g_debug("socket_udp_extract_dst_addr(): "
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
 * Signal reception of a datagram to the UDP layer.
 * Note: for the Gnutella datagram socket this is udp_received().
 */
static inline void
socket_udp_process(gnutella_socket_t *s, bool truncated)
{
	(*s->resource.udp->data_ind)(s, s->buf, s->pos, truncated);
}

/**
 * Let the application process the queued datagram, then free it.
 */
static inline void
socket_udp_process_queued(gnutella_socket_t *s, struct udpq *uq)
{
	time_delta_t age;

	/*
	 * The application can query these fields directly to know the origin
	 * of the UDP datagram.
	 */

	s->addr = uq->addr;
	s->port = uq->port;

	/*
	 * The application layer can determine that it is processing an "old"
	 * UDP datagram by checking for socket_udp_is_old().
	 *
	 * Note: it is critical that upper layers never access s->buf or s->pos
	 * when receiving a message from a UDP socket but use instead the
	 * provided data and length values.  Indeed, when delivering queued
	 * data, the s->buf and s->pos fields are meaningless!
	 */

	age = delta_time(tm_time(), uq->queued);
	gnet_stats_max_general(GNR_UDP_READ_AHEAD_DELAY_MAX, age);

	if (age >= MAX_UDP_AGE) {
		gnet_stats_inc_general(GNR_UDP_READ_AHEAD_OLD_SUM);
		s->flags |= SOCK_F_OLD;
		(*s->resource.udp->data_ind)(s, uq->buf, uq->len, uq->truncated);
		s->flags &= ~SOCK_F_OLD;
	} else {
		(*s->resource.udp->data_ind)(s, uq->buf, uq->len, uq->truncated);
	}

	s->resource.udp->queued =
		size_saturate_sub(s->resource.udp->queued, uq->len);

	socket_udpq_free(uq);
}

/**
 * Is processed datagram "old" (enqueued more than MAX_UDP_AGE secs ago)?
 *
 * This call can safely be called on any socket, but of course it will
 * always return FALSE when the socket is not UDP.
 *
 * @return whether the datagram was received more than MAX_UDP_AGE secs ago.
 */
bool
socket_udp_is_old(const gnutella_socket_t *s)
{
	socket_check(s);

	if (!(s->flags & SOCK_F_UDP))
		return FALSE;		/* Not an UDP socket */

	return booleanize(s->flags & SOCK_F_OLD);
}

/**
 * Someone is sending us a datagram.  Read it into the socket's buffer.
 *
 * @param s				the socket which receives a datagram
 * @param truncation	written with whether datagram was truncated
 *
 * @return -1 on error, the size of the datagram otherwise.
 */
static ssize_t
socket_udp_accept(struct gnutella_socket *s, bool *truncation)
{
	socket_addr_t *from_addr;
	struct sockaddr *from;
	socklen_t from_len;
	ssize_t r;
	bool truncated = FALSE, has_dst_addr = FALSE;
	host_addr_t dst_addr;

	socket_check(s);
	g_assert(s->flags & SOCK_F_UDP);
	g_assert(s->type == SOCK_TYPE_UDP);

	/*
	 * Receive the datagram in the socket's buffer.
	 */

	from_addr = s->resource.udp->socket_addr;

	/* Initialize from_addr so that it matches the socket's network type. */
	from_len = socket_addr_init(from_addr, s->net);
	g_assert(from_len > 0);
	g_assert(from_len == socket_addr_get_len(from_addr));

	from = socket_addr_get_sockaddr(from_addr);
	g_assert(from);

#ifdef HAS_RECVMSG
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
		iovec_t iov;

		iovec_set(&iov, s->buf, s->buf_size);

		msg = zero_msg;
		msg.msg_name = cast_to_pointer(from);
		msg.msg_namelen = from_len;
		msg.msg_iov = &iov;
		msg.msg_iovlen = 1;

		/* Some implementations have msg_accrights and msg_accrightslen
		 * instead of msg_control and msg_controllen.
		 */
#if defined(CMSG_LEN) && defined(CMSG_SPACE)
		{
			union {
				struct cmsghdr hdr;
				size_t align;
				char bytes[CMSG_SPACE(512)];
			} cmsg_buf;

			ZERO(&cmsg_buf.hdr);
			msg.msg_control = cmsg_buf.bytes;
			msg.msg_controllen = sizeof cmsg_buf.bytes;
		}
#endif /* CMSG_LEN && CMSG_SPACE */

		r = recvmsg(s->file_desc, &msg, 0);

		/* msg_flags is missing at least in some versions of IRIX. */
#if defined(HAS_MSGHDR_MSG_FLAGS)
		truncated = 0 != (MSG_TRUNC & msg.msg_flags);
#endif

		if ((ssize_t) -1 != r && !GNET_PROPERTY(force_local_ip)) {
			has_dst_addr = socket_udp_extract_dst_addr(&msg, &dst_addr);
		}
	}
#else	/* !HAS_RECVMSG */
	r = recvfrom(s->file_desc, s->buf, s->buf_size, 0,
			cast_to_pointer(from), &from_len);
#endif	/* HAS_RECVMSG */

	if ((ssize_t) -1 == r)
		return (ssize_t) -1;

	g_assert((size_t) r <= s->buf_size);

	/*
	 * We're too low level to account for the proper bandwidth here as we
	 * want to distinguish between UDP Gnutella traffic and DHT traffic.
	 *
	 * This will be done in udp_receieved() which we're about to call.
	 */

	s->pos = r;

	/*
	 * Record remote address.
	 */

	s->addr = socket_addr_get_addr(from_addr);
	s->port = socket_addr_get_port(from_addr);

	if (!is_host_addr(s->addr)) {
		gnet_stats_inc_general(GNR_UDP_BOGUS_SOURCE_IP);
		bws_udp_count_read(r, FALSE);	/* Assume not from DHT */
		errno = EINVAL;
		return (ssize_t) -1;
	}

	if (has_dst_addr) {
		static host_addr_t last_addr;

		settings_addr_changed(dst_addr, s->addr);

		/*
		 * Show the destination address only when it differs from
		 * the last seen or if the debug level is higher than 1.
		 */

		if (
			GNET_PROPERTY(socket_debug) > 1 ||
			!host_addr_equiv(last_addr, dst_addr)
		) {
			last_addr = dst_addr;
			if (GNET_PROPERTY(socket_debug)) {
				g_debug("%s(): dst_addr=%s",
					G_STRFUNC, host_addr_to_string(dst_addr));
			}
		}
	}

	if (truncated)
		gnet_stats_inc_general(GNR_UDP_RX_TRUNCATED);

	*truncation = truncated;
	return r;
}

/**
 * Enqueue UDP datagram for deferred processing.
 */
static void
socket_udp_queue(gnutella_socket_t *s, bool truncated)
{
	struct udpctx *uctx;
	struct udpq *uq;

	g_assert(s->flags & SOCK_F_UDP);

	uctx = s->resource.udp;
	
	WALLOC(uq);
	uq->buf = wcopy(s->buf, s->pos);
	uq->len = s->pos;
	uq->queued = tm_time();
	uq->truncated = booleanize(truncated);
	uq->addr = s->addr;
	uq->port = s->port;

	eslist_append(&uctx->queue, uq);
	s->resource.udp->queued =
		size_saturate_add(s->resource.udp->queued, uq->len);
}

static void socket_udp_flush_queue(gnutella_socket_t *s, time_delta_t maxtime);

/**
 * Timer installed to flush the enqueued read-ahead UDP datagrams.
 */
static void
socket_udp_flush_timer(cqueue_t *cq, void *obj)
{
	gnutella_socket_t *s = obj;
	struct udpctx *uctx;

	socket_check(s);
	g_assert(s->flags & SOCK_F_UDP);

	uctx = s->resource.udp;
	cq_zero(cq, &uctx->queue_ev);		/* Timer expired */

	/*
	 * If the socket layer has already began shutdown, do not process
	 * read-ahead datagrams.
	 */

	if (GNET_PROPERTY(socket_debug)) {
		g_debug("%s(): %s %'zu queued datagrams on UDP socket port %u",
			G_STRFUNC, socket_shutdowned ? "dropping" : "flushing",
			eslist_count(&uctx->queue), s->local_port);
	}

	if G_UNLIKELY(socket_shutdowned) {
		eslist_foreach(&uctx->queue, socket_udp_qfree, NULL);
		eslist_clear(&uctx->queue);
	} else {
		socket_udp_flush_queue(s, 2 * MAX_UDP_LOOP_MS);
	}
}

/**
 * Flush the read-ahead UDP datagrams.
 *
 * @param s			the gnutella socket
 * @param maxtime	maximum processing time allowed (in ms)
 */
static void
socket_udp_flush_queue(gnutella_socket_t *s, time_delta_t maxtime)
{
	struct udpctx *uctx = s->resource.udp;
	struct udpq *uq;
	unsigned i;
	tm_t start, end;

	tm_now_exact(&start);
	i = 0;

	while (NULL != (uq = eslist_shift(&uctx->queue))) {
		i++;
		socket_udp_process_queued(s, uq);			/* Process it */

		tm_now_exact(&end);
		if (tm_elapsed_ms(&end, &start) > maxtime)
			break;
	}

	if (GNET_PROPERTY(socket_debug)) {
		tm_now_exact(&end);
		g_debug("%s() processed %'u queued datagrams "
			"(%'zu remain) in %'u usecs",
			G_STRFUNC, i, eslist_count(&uctx->queue),
			(unsigned) tm_elapsed_us(&end, &start));
	}

	/*
	 * Install processing timer if items remain to be processed since
	 * we cannot wait for more incoming datagrams to trigger further
	 * flushing.
	 */

	if (0 == eslist_count(&uctx->queue)) {
		cq_cancel(&uctx->queue_ev);
	} else if (NULL == uctx->queue_ev) {
		uctx->queue_ev = cq_main_insert(UDP_QUEUE_DELAY_MS,
			socket_udp_flush_timer, s);
	} else {
		cq_resched(uctx->queue_ev, UDP_QUEUE_DELAY_MS);
	}
}

/**
 * Someone is sending us a datagram.
 */
static void
socket_udp_event(void *data, int unused_source, inputevt_cond_t cond)
{
	struct gnutella_socket *s = data;
	size_t avail, rd, qd, qn;
	bool guessed, truncated, enqueue;
	unsigned i;
	time_delta_t processing = 0;
	tm_t start, end;
	struct udpctx *uctx;

	(void) unused_source;
	g_assert(s->flags & SOCK_F_UDP);

	if G_UNLIKELY(cond & INPUT_EVENT_EXCEPTION) {
		int error;

		socklen_t error_len = sizeof error;

		getsockopt(s->file_desc, SOL_SOCKET, SO_ERROR, &error, &error_len);
		errno = error;
		g_warning("input exception for UDP listening socket #%d: %m",
			s->file_desc);
		return;
	}

	/*
	 * It might be useful to call socket_udp_accept() several times
	 * as there are often several packets queued.
	 *
	 * When the RX queue is full, the kernel will start dropping new
	 * incoming UDP datagrams, and we want to avoid that because this may
	 * cause us to lose an important UDP reply, for instance.
	 *
	 * Therefore, we allow read-ahead of messages from the UDP queue without
	 * processing them in an attempt to leave enough room in the RX queue.
	 * These queued messages are then processed at a later time.
	 *		--RAM, 2012-11-13
	 */

	tm_now_exact(&start);

	avail = inputevt_data_available();
	guessed = 0 == avail;
	avail = guessed ? UDP_QUEUED_GUESS : avail;
	uctx = s->resource.udp;
	enqueue = 0 != eslist_count(&uctx->queue);

	i = 0;
	rd = qd = qn = 0;

	for(;;) {
		ssize_t r;

		i++;
		r = socket_udp_accept(s, &truncated);		/* Read datagram */

		if ((ssize_t) -1 == r) {
			/* ECONNRESET is meaningless with UDP but happens on Windows */
			if (!is_temporary_error(errno) && errno != ECONNRESET) {
				g_warning("%s(): ignoring datagram reception error: %m",
					G_STRFUNC);
			}
			break;
		}

		if G_UNLIKELY(0 == r) {
			g_warning("%s(): ignoring empty datagram from %s",
				G_STRFUNC, host_addr_port_to_string(s->addr, s->port));
			gnet_stats_inc_general(GNR_UDP_UNPROCESSED_MESSAGE);
			goto next;
		}

		rd += r;

		/*
		 * If there are pending datagrams in the queue, do not process the
		 * new datagram but rather enqueue it: we need to process the messages
		 * in the order they were received.
		 */

		if (enqueue) {
			socket_udp_queue(s, truncated);				/* Enqueue it */
			qd += r;
			qn++;
		} else {
			socket_udp_process(s, truncated);			/* Process it */
		}

		avail = size_saturate_sub(avail, r);

		/* kevent() reports 32 more bytes than there are, maybe
		 * it refers to header or control msg data. */
		if (avail <= 32)
			break;

	next:

		/* Process one event at a time if configured as such */
		if (s->flags & SOCK_F_SINGLE)
			break;

		if (!enqueue) {
			time_delta_t spent;

			/*
			 * Do not monopolize CPU for too long whilst processing.
			 *
			 * However, once our processing quota is expired, start to enqueue
			 * messages in order to flush the kernel RX queue.
			 */

			tm_now_exact(&end);
			spent = tm_elapsed_ms(&end, &start);

			if (spent > MAX_UDP_LOOP_MS) {
				processing = spent;			/* Time already spent processing */
				enqueue = TRUE;				/* Continue reading only */
			}
		}
	}

	if ((i > 16 || enqueue) && GNET_PROPERTY(socket_debug)) {
		tm_now_exact(&end);
		g_debug("%s() iterated %'u times, read %'zu bytes "
			"(%s%'zu more pending), enqueued %'zu bytes (%'zu datagram%s) "
			"in %'u usecs",
			G_STRFUNC, i, rd, guessed ? "~" : "", avail, qd,
			qn, plural(qn), (unsigned) tm_elapsed_us(&end, &start));
	}

	/*
	 * Update statistics.
	 */

	gnet_stats_count_general(GNR_UDP_READ_AHEAD_COUNT_SUM, qn);
	gnet_stats_count_general(GNR_UDP_READ_AHEAD_BYTES_SUM, qd);
	gnet_stats_max_general(GNR_UDP_READ_AHEAD_BYTES_MAX, uctx->queued);
	gnet_stats_max_general(GNR_UDP_READ_AHEAD_COUNT_MAX,
		eslist_count(&uctx->queue));

	/*
	 * Harvest entropy.
	 */

	if (enqueue)
		entropy_harvest_many(VARLEN(rd), VARLEN(qd), VARLEN(processing), NULL);
	else if (i > 4)
		entropy_harvest_small(VARLEN(rd), VARLEN(qd), VARLEN(i), NULL);
	else
		entropy_harvest_time();

	/*
	 * Dequeue some of the queued datagrams, processing them.
	 */

	if (0 != eslist_count(&uctx->queue)) {
		time_delta_t processtime;

		/*
		 * Do not monopolize CPU for too long, but we still need to flush
		 * our backlog, so devote more CPU time to handling the queued
		 * items than we do when reading with no backlog.
		 */

		processtime = (processing >= 2 * MAX_UDP_LOOP_MS) ? 0 :
			2 * MAX_UDP_LOOP_MS - processing;

		socket_udp_flush_queue(s, processtime);
	}
}

static inline void
socket_set_linger(int fd)
{
	g_assert(fd >= 0);

	if (!GNET_PROPERTY(use_so_linger))
		return;

#ifdef TCP_LINGER2
	{
		int timeout = 20;	/* timeout in seconds for FIN_WAIT_2 */

		if (setsockopt(fd, sol_tcp(), TCP_LINGER2, &timeout, sizeof timeout))
			g_warning("setsockopt() for TCP_LINGER2 failed: %m");
	}
#else
	{
		static const struct linger zero_linger;
		struct linger lb;

		lb = zero_linger;
		lb.l_onoff = 1;
		lb.l_linger = 0;	/* closes connections with RST */
		if (setsockopt(fd, SOL_SOCKET, SO_LINGER, &lb, sizeof lb))
			g_warning("setsockopt() for SO_LINGER failed: %m");
	}
#endif /* TCP_LINGER */
}

static void
socket_set_accept_filters(struct gnutella_socket *s)
{
	socket_check(s);
	g_assert(is_valid_fd(s->file_desc));

	if (GNET_PROPERTY(tcp_defer_accept_timeout) <= 0)
		return;

#if defined(TCP_DEFER_ACCEPT)
	{
		int timeout;

		timeout = MIN(GNET_PROPERTY(tcp_defer_accept_timeout), (uint) INT_MAX);
		if (
			setsockopt(s->file_desc, sol_tcp(), TCP_DEFER_ACCEPT,
				&timeout, sizeof timeout)
		) {
			g_warning("setsockopt() for TCP_DEFER_ACCEPT(%d) failed: %m",
				timeout);
		}
	}
#endif /* TCP_DEFER_ACCEPT */
#if defined(SO_ACCEPTFILTER)
	{
		static const struct accept_filter_arg zero_arg;
		struct accept_filter_arg arg;
		static const char name[] = "dataready";

		arg = zero_arg;
		STATIC_ASSERT(sizeof arg.af_name >= CONST_STRLEN(name));
		strncpy(arg.af_name, name, sizeof arg.af_name);

		if (setsockopt(s->file_desc, SOL_SOCKET, SO_ACCEPTFILTER,
				&arg, sizeof arg)
		) {
			/* This is usually not supported for IPv6. Thus suppress
			 * the warning by default. */
			if (NET_TYPE_IPV6 != s->net || GNET_PROPERTY(socket_debug) > 0) {
				g_warning("cannot set SO_ACCEPTFILTER (%s): %m", name);
			}
		}
	}
#endif /* SO_ACCEPTFILTER */
}

static void
socket_set_fastack(struct gnutella_socket *s)
{
	static const int on = 1;

	socket_check(s);
	g_return_if_fail(is_valid_fd(s->file_desc));

	if (!(SOCK_F_TCP & s->flags))
		return;

	(void) on;
#if defined(TCP_FASTACK)
	if (setsockopt(s->file_desc, sol_tcp(), TCP_FASTACK, &on, sizeof on)) {
		g_warning("could not set TCP_FASTACK (fd=%d): %m", s->file_desc);
	}
#endif /* TCP_FASTACK */
}

/**
 * Enable quick ACK sending at the TCP level, if supported on this platform.
 * This can really increase the reception of data as data packets are
 * immediately acknowledged to the sender.
 */
void
socket_set_quickack(struct gnutella_socket *s, int on)
{
	socket_check(s);
	g_return_if_fail(is_valid_fd(s->file_desc));

	if (!(SOCK_F_TCP & s->flags))
		return;

	(void) on;
#if defined(TCP_QUICKACK)
	if (setsockopt(s->file_desc, sol_tcp(), TCP_QUICKACK, &on, sizeof on)) {
		g_warning("could not set TCP_QUICKACK (fd=%d): %m", s->file_desc);
	}
#endif	/* TCP_QUICKACK*/
}

/*
 * Sockets creation
 */

/**
 * Verify that connection can be made to an addr.
 * @return 0 if OK.
 */
static int
socket_connection_allowed(const host_addr_t addr, enum socket_type type)
{
	unsigned flag = 0;

	if (hostiles_is_bad(addr)) {
		if (GNET_PROPERTY(socket_debug)) {
			hostiles_flags_t flags = hostiles_check(addr);
			g_warning("not connecting [%s] to hostile host %s (%s)",
				socket_type_to_string(type), host_addr_to_string(addr),
				hostiles_flags_to_string(flags));
		}
		errno = EPERM;
		return -1;
	}

	switch (type) {
	case SOCK_TYPE_DOWNLOAD:	flag = CTL_D_OUTGOING; break;
	case SOCK_TYPE_HTTP:		flag = CTL_D_OUTGOING; break;
	case SOCK_TYPE_CONTROL:		flag = CTL_D_GNUTELLA; break;
	case SOCK_TYPE_UPLOAD:		flag = CTL_D_INCOMING; break;
	case SOCK_TYPE_CONNBACK:
		flag = ctl_limit(addr, CTL_D_STEALTH) ? CTL_D_GNUTELLA : 0;
		break;
	default:
		g_warning("socket_connect_prepare(): unexpected type \"%s\"",
			socket_type_to_string(type));
		flag = CTL_D_OUTGOING;
		break;
	}

	if (ctl_limit(addr, flag)) {
		if (GNET_PROPERTY(socket_debug) || GNET_PROPERTY(ctl_debug)) {
			g_warning("CTL not connecting [%s] to host %s [%s]",
				socket_type_to_string(type), host_addr_to_string(addr),
				gip_country_cc(addr));
		}
		errno = EPERM;
		return -1;
	}

	return 0;
}

/**
 * Called to prepare the creation of the socket connection.
 *
 * @returns non-zero in case of failure, zero on success.
 */
static int
socket_connect_prepare(struct gnutella_socket *s,
	host_addr_t addr, uint16 port, enum socket_type type, uint32 flags)
{
	static const int on = 1;
	int fd, family;

	socket_check(s);

	/* Harvest entropy */
	entropy_harvest_many(
		VARLEN(s), VARLEN(addr), VARLEN(port), VARLEN(type), VARLEN(flags),
		NULL);

	/* Filter out flags which we cannot accept */
	flags &= (SOCK_F_TLS | SOCK_F_FORCE);

	/*
	 * If they want a TLS connection but we're banning this address for TLS,
	 * abort the connection immediately.
	 */

	if ((flags & SOCK_F_TLS) && socket_tls_banned(addr, port)) {
		errno = ECONNABORTED;
		return -1;
	}

	if (!(s->flags & SOCK_F_FORCE) && is_host_addr(addr)) {
		if (0 != socket_connection_allowed(addr, type))
			return -1;
		flags |= SOCK_F_PREPARED;
	}

	if (
		0 == (SOCK_F_TLS & flags) &&
		tls_cache_lookup(addr, port) &&
		!socket_tls_banned(addr, port)
	) {
		flags |= SOCK_F_TLS;
	}

	addr = socket_ipv6_trt_map(addr);
	if (NET_TYPE_NONE == host_addr_net(addr)) {
		errno = EINVAL;
		return -1;
	}
	family = host_addr_family(addr);
	if (-1 == family) {
		errno = EINVAL;
		return -1;
	}

	/*
	 * If they configured IPv4 or IPv6 only, make sure we're not attempting
	 * a connection to a forbidden network (even though the network protocol
	 * is understood by the kernel).
	 */

	if (!settings_can_connect(addr)) {
		host_addr_t to;
		enum net_type target;

		target = settings_use_ipv6() ? NET_TYPE_IPV6 : NET_TYPE_IPV4;

		if (host_addr_convert(addr, &to, target)) {
			addr = to;
		} else {
			errno = EPERM;
			return -1;
		}
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
			g_warning("unable to create %s socket: %m",
				socket_type_to_string(type));
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

	s->tls.enabled = tls_enabled() && (SOCK_F_TLS & flags);
	s->tls.stage = SOCK_TLS_NONE;
	s->tls.ctx = NULL;
	s->tls.snarf = 0;

	socket_wio_link(s);

	if (
		-1 == setsockopt(s->file_desc, SOL_SOCKET, SO_KEEPALIVE, &on, sizeof on)
	) {
		s_warning("%s(): setsockopt(%d, SOL_SOCKET, SO_KEEPALIVE) failed: %m",
			G_STRFUNC, s->file_desc);
	}
	if (
		-1 == setsockopt(s->file_desc, SOL_SOCKET, SO_REUSEADDR, &on, sizeof on)
	) {
		s_warning("%s(): setsockopt(%d, SOL_SOCKET, SO_REUSEADDR) failed: %m",
			G_STRFUNC, s->file_desc);
	}

	fd_set_nonblocking(s->file_desc);
	set_close_on_exec(s->file_desc);
	socket_set_linger(s->file_desc);
	socket_tos_normal(s);

	/*
	 * Fast ACKs is mainly useful for downloads.
	 */

	switch (s->type) {
	case SOCK_TYPE_DOWNLOAD:
	case SOCK_TYPE_HTTP:
		socket_set_fastack(s);
		socket_set_quickack(s, TRUE);
		break;
	default:
		socket_set_quickack(s, FALSE);
		break;
	}

	return 0;
}

/**
 * Called to finalize the creation of the socket connection, which is done
 * in two steps since DNS resolving is asynchronous.
 *
 * @returns non-zero in case of failure, zero on success.
 */
static int
socket_connect_finalize(struct gnutella_socket *s,
	const host_addr_t ha, bool destroy_on_error)
{
	socket_addr_t addr;
	socklen_t addr_len;
	int res;

	socket_check(s);
	g_assert(is_valid_fd(s->file_desc));

	/*
	 * Allow forced connections to an hostile host.
	 *
	 * If SOCK_F_PREPARED is set, then we've already checked for hostiles
	 * in socket_connect_prepare(), where we already knew the address, and
	 * there's no need to redo it now.
	 */

	if (!(s->flags & (SOCK_F_FORCE | SOCK_F_PREPARED))) {
		if (0 != socket_connection_allowed(ha, s->type))
			goto failure;	/* Not connecting to hostile host */
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

	if (-1 == res && EINPROGRESS != errno && !is_temporary_error(errno)) {
		if (proxy_is_enabled() && !is_host_addr(GNET_PROPERTY(proxy_addr))) {
			if (!is_temporary_error(errno)) {
				g_warning("SOCKS proxy isn't properly configured (%s:%u)",
					GNET_PROPERTY(proxy_hostname), GNET_PROPERTY(proxy_port));
			}
			goto failure;	/* Check the proxy configuration */
		}

		g_warning("unable to connect to %s: %m",
			host_addr_port_to_string(s->addr, s->port));
		goto failure;
	}

	s->local_port = socket_local_port(s);
	bws_sock_connect(s->type);

	/* Set the socket descriptor non blocking */
	fd_set_nonblocking(s->file_desc);

	g_assert(0 == s->gdk_tag);

	socket_evt_set(s, INPUT_EVENT_WX, socket_connected, s);
	return 0;

failure:

	if (destroy_on_error) {
		socket_destroy(s, _("Connection failed"));
	}
	return -1;
}

/**
 * Creates a connected socket with an attached resource of `type'.
 *
 * Connection happens in the background, the connection callback being
 * determined by the resource type.
 */
struct gnutella_socket *
socket_connect(const host_addr_t ha, uint16 port,
	enum socket_type type, uint32 flags)
{
	struct gnutella_socket *s;

	s = socket_alloc();

	if (0 != socket_connect_prepare(s, ha, port, type, flags)) {
		socket_dealloc(&s);
		return NULL;
	}

	return 0 != socket_connect_finalize(s, ha, TRUE) ? NULL : s;
}

/**
 * Attempt to reconnect to socket, without TLS.
 *
 * @return TRUE if OK, FALSE on error (with socket not destroyed).
 */
static bool
socket_reconnect(struct gnutella_socket *s)
{
	gnet_host_t to;

	socket_check(s);
	g_assert(s->flags & SOCK_F_TCP);

	socket_evt_clear(s);
	s_close(s->file_desc);
	s->file_desc = INVALID_SOCKET;
	s->flags = 0;
	if (socket_with_tls(s)) {
		tls_free(s);
	}

	/*
	 * Remove host from the TLS cache because if it is present there, then
	 * socket_connect_prepare() will re-enable SOCK_F_TLS automatically and
	 * we want to avoid TLS on a reconnection.
	 *		--RAM, 2013-12-04
	 */

	tls_cache_remove(s->addr, s->port);

	/*
	 * Also ban TLS connections within the next TLS_BAN_FREQ seconds to avoid
	 * the same host re-advertising TLS support, with the connection failing
	 * over and over.
	 *		--RAM, 2013-12-08
	 */

	once_flag_run(&tls_ban_inited, tls_ban_init);

	gnet_host_set(&to, s->addr, s->port);
	aging_insert(tls_ban, atom_host_get(&to), int_to_pointer(1));

	if (0 != socket_connect_prepare(s, s->addr, s->port, s->type, SOCK_F_FORCE))
		return FALSE;

	g_soft_assert(!s->tls.enabled);

	return 0 == socket_connect_finalize(s, s->addr, FALSE);
}

/**
 * @returns whether bad hostname was reported after a DNS lookup.
 */
bool
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
	void *user_data)
{
	struct gnutella_socket *s = user_data;
	host_addr_t addr;
	bool can_tls;

	socket_check(s);
	g_assert(addrs);

	if (n < 1 || s->type == SOCK_TYPE_DESTROYING) {
		s->adns |= SOCK_ADNS_FAILED | SOCK_ADNS_BADNAME;
		s->adns_msg = "Could not resolve address";
		goto finish;
	}

	addr = addrs[random_value(n - 1)];
	can_tls = 0 != (SOCK_F_TLS & s->flags) || tls_cache_lookup(addr, s->port);

	if (can_tls && socket_tls_banned(addr, s->port))
		can_tls = FALSE;

	if (
		s->net != host_addr_net(addr) ||
		(can_tls && 0 == (SOCK_F_TLS & s->flags))
	) {
		s->net = host_addr_net(addr);

		if (is_valid_fd(s->file_desc)) {
			s_close(s->file_desc);
			s->file_desc = INVALID_SOCKET;
		}
		if (can_tls) {
			s->flags |= SOCK_F_TLS;
		}
		if (socket_connect_prepare(s, addr, s->port, s->type, s->flags)) {
			s->adns |= SOCK_ADNS_FAILED;
			s->adns_msg = "Could not resolve address";
			goto finish;
		}
	}

	/* SOCK_ADNS_PENDING is still set here, will be cleared below */

	if (socket_connect_finalize(s, addr, FALSE)) {
		s->adns |= SOCK_ADNS_FAILED;
		s->adns_msg = "Connection failed";
		goto finish;
	}

finish:
	s->adns &= ~SOCK_ADNS_PENDING;
	if ((s->adns & SOCK_ADNS_ASYNC) && (s->adns & SOCK_ADNS_FAILED)) {
		socket_destroy(s, s->adns_msg);
	}
}

/**
 * Like socket_connect() but the remote address is not known and must be
 * resolved through async DNS calls.
 */
struct gnutella_socket *
socket_connect_by_name(const char *host, uint16 port,
	enum socket_type type, uint32 flags)
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

	s->adns = SOCK_ADNS_PENDING;
	if (
		adns_resolve(host, settings_dns_net(), socket_connect_by_name_helper, s)
	) {
		s->adns |= SOCK_ADNS_ASYNC;
	} else if (s->adns & SOCK_ADNS_FAILED) {
		/*	socket_connect_by_name_helper() was already invoked! */
		if (GNET_PROPERTY(socket_debug) > 0)
			g_warning("%s: adns_resolve() failed in synchronous mode",
				G_STRFUNC);
		socket_destroy(s, s->adns_msg);
		return NULL;
	}

	return s;
}

/**
 * Creates a listening socket and binds it to `bind_addr' unless it is
 * an unspecified address in which case the kernel will pick an address.
 * If the port is 0, then the socket will be "anonymous": it will be bound
 * to a port chosen by the kernel, which is inappropriate for listening
 * sockets of course.
 *
 * The socket is also set to non-blocking mode and the FD_CLOEXEC flag is
 * set as well.
 *
 * @param bind_addr	The address to bind the socket to (may be unspecified).
 * @param port		The UDP or TCP port to use (0 means: let kernel pick)
 * @param type		Either SOCK_DGRAM or SOCK_STREAM.
 *
 * @return The new file descriptor of socket or -1 on failure.
 */
static socket_fd_t
socket_create_and_bind(const host_addr_t bind_addr,
	const uint16 port, const int type)
{
	bool socket_failed;
	socket_fd_t fd;
	int saved_errno, family;
	int protocol;

	g_assert(SOCK_DGRAM == type || SOCK_STREAM == type);

	if (1 == port) {
		errno = EINVAL;
		return INVALID_SOCKET;
	}
	if (NET_TYPE_NONE == host_addr_net(bind_addr)) {
		errno = EINVAL;
		return INVALID_SOCKET;
	}
	family = host_addr_family(bind_addr);
	if (-1 == family) {
		errno = EINVAL;
		return INVALID_SOCKET;
	}

	protocol = (SOCK_DGRAM == type) ? IPPROTO_UDP : IPPROTO_TCP;
	fd = socket(family, type, protocol);

	if (!is_valid_fd(fd)) {
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
			host_addr_is_ipv6(bind_addr) &&
			setsockopt(fd, sol_ipv6(), IPV6_V6ONLY, &enable, sizeof enable)
		) {
			g_warning("setsockopt() failed for IPV6_V6ONLY: %m");
		}
#endif /* HAS_IPV6 && IPV6_V6ONLY */

		/* bind() the socket */
		socket_failed = FALSE;
		len = socket_addr_set(&addr, bind_addr, port);
		if (-1 == bind(fd, socket_addr_get_const_sockaddr(&addr), len)) {
			saved_errno = errno;
			s_close(fd);
			fd = INVALID_SOCKET;
		} else {
			saved_errno = 0;
		}
	}

#if defined(HAS_SOCKER_GET)
	if (!is_valid_fd(fd) && (EACCES == saved_errno || EPERM == saved_errno)) {
		char addr_str[128];

		host_addr_to_string_buf(bind_addr, addr_str, sizeof addr_str);
		fd = socker_get(family, type, 0, addr_str, port);
		if (!is_valid_fd(fd)) {
			g_warning("socker_get() failed: %m");
		}
	}
#else
	(void) saved_errno;
#endif /* HAS_SOCKER_GET */

	if (!is_valid_fd(fd)) {
		const char *type_str = SOCK_DGRAM == type ? "datagram" : "stream";
		const char *net_str = net_type_to_string(host_addr_net(bind_addr));

		if (socket_failed) {
			g_warning("unable to create the %s (%s) socket: %m",
				type_str, net_str);
		} else {
			char bind_addr_str[HOST_ADDR_PORT_BUFLEN];

			host_addr_port_to_string_buf(bind_addr, port,
				bind_addr_str, sizeof bind_addr_str);
			g_warning("unable to bind() the %s (%s) socket to %s: %m",
				type_str, net_str, bind_addr_str);
		}
	} else {
		fd = get_non_stdio_fd(fd);
		set_close_on_exec(fd);
		fd_set_nonblocking(fd);
	}

	return fd;
}

/**
 * @return TRUE if the socket is a local unix domain socket.
 */
bool
socket_is_local(const struct gnutella_socket *s)
{
	bool is_local, is_tcp, is_udp;

	socket_check(s);

	is_local = 0 != (s->flags & SOCK_F_LOCAL);
	is_tcp = 0 != (s->flags & SOCK_F_TCP);
	is_udp = 0 != (s->flags & SOCK_F_UDP);

	g_assert(is_local ^ (is_tcp | is_udp));
	g_assert(is_local || is_tcp || is_udp);

	if (is_local) {
		static const sockaddr_unix_t zero_addr;
		sockaddr_unix_t addr = zero_addr;
		socklen_t len = sizeof addr;

		if (compat_getsockname(s->file_desc, cast_to_pointer(&addr), &len)) {
			is_local = FALSE;
			g_warning("%s(): getsockname() failed: %m", G_STRFUNC);
		} else if (AF_LOCAL != addr.sun_family) {
			is_local = FALSE;
			g_warning("%s(): address family mismatch! (expected %u, got %u)",
				G_STRFUNC, (uint) AF_LOCAL, (uint) addr.sun_family);
		}
	}

	return is_local;
}

/**
 * Creates a non-blocking listening unix domain socket with an attached
 * resource of `type'.
 */
struct gnutella_socket *
socket_local_listen(const char *pathname)
{
	sockaddr_unix_t addr;
	struct gnutella_socket *s;
	int fd;

	g_return_val_if_fail(pathname, NULL);
	g_return_val_if_fail(is_absolute_path(pathname), NULL);

	{
		static const sockaddr_unix_t zero_un;
		size_t size = sizeof addr.sun_path;

		addr = zero_un;
		addr.sun_family = AF_LOCAL;
		if (g_strlcpy(addr.sun_path, pathname, size) >= size) {
			g_warning("%s(): pathname is too long", G_STRFUNC);
			return NULL;
		}
	}

	fd = compat_socket(PF_LOCAL, SOCK_STREAM, 0);
	if (fd < 0) {
		g_warning("socket(PF_LOCAL, SOCK_STREAM, 0) failed: %m");
		return NULL;
	}
	fd = get_non_stdio_fd(fd);

	(void) unlink(pathname);

	{
		int ret, saved_errno;
		mode_t mask;

		/* umask 177 -> mode 200; write-only for user */
		mask = umask(S_IRUSR | S_IXUSR | S_IRWXG | S_IRWXO);
    	ret = compat_bind(fd, cast_to_constpointer(&addr), sizeof addr);
		saved_errno = errno;
		(void) umask(mask);

		if (0 != ret) {
			errno = saved_errno;
			g_warning("%s(): bind() failed: %m", G_STRFUNC);
			compat_socket_close(fd);
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
	fd_set_nonblocking(fd);

	s->net = NET_TYPE_NONE;
	s->local_port = 0;

	/* listen() the socket */

	if (compat_listen(fd, 5) == -1) {
		g_warning("unable to listen() on the socket: %m");
		socket_destroy(s, "Unable to listen on socket");
		return NULL;
	}

	s->tls.enabled = tls_enabled();

	socket_enable_accept(s);
	return s;
}

/**
 * Creates a non-blocking TCP listening socket with an attached
 * resource of `type'.
 */
struct gnutella_socket *
socket_tcp_listen(host_addr_t bind_addr, uint16 port)
{
	static const int on = 1;
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

	if (-1 == setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &on, sizeof on)) {
		g_warning("%s(): setsockopt(%d, SOL_SOCKET, SO_KEEPALIVE) failed: %m",
			G_STRFUNC, fd);
	}

	socket_set_linger(s->file_desc);

	/* listen() the socket */

	if (listen(fd, 5) == -1) {
		g_warning("unable to listen() on the socket: %m");
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
			g_warning("unable to get the port of the socket: "
				"getsockname() failed: %m");
			socket_destroy(s, "Can't probe socket for port");
			return NULL;
		}

		s->local_port = socket_addr_get_port(&addr);
	}

	s->tls.enabled = tls_enabled();

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
			g_warning("%s(): setsockopt() for IP_RECVDSTADDR failed: %m",
				G_STRFUNC);
		}
#endif /* IP_RECVDSTADDR && IP_RECVDSTADDR */
		break;

	case NET_TYPE_IPV6:
#if defined(HAS_IPV6) && defined(IPV6_RECVPKTINFO)
		if (setsockopt(fd, sol_ipv6(), IPV6_RECVPKTINFO, &on, sizeof on)) {
			g_warning("%s(): setsockopt() for IPV6_RECVPKTINFO failed: %m",
				G_STRFUNC);
		}
#endif /* HAS_IPV6 && IPV6_RECVPKTINFO */
		break;

	case NET_TYPE_LOCAL:
	case NET_TYPE_NONE:
		break;
	}
}

/**
 * Mark socket a "single" to make sure we only read one single message at
 * a time.
 */
void
socket_set_single(struct gnutella_socket *s, bool on)
{
	if (on) {
		s->flags |= SOCK_F_SINGLE;
	} else {
		s->flags &= ~SOCK_F_SINGLE;
	}
}
 
/**
 * Creates a non-blocking listening UDP socket.
 *
 * Upon datagram reception, the ``data_ind'' callback is invoked. The received
 * data will be held in s->buf, being s->pos byte-long.
 */
struct gnutella_socket *
socket_udp_listen(host_addr_t bind_addr, uint16 port,
	socket_udp_data_ind_t data_ind)
{
	struct gnutella_socket *s;
	int fd;

	/* Create a socket, then bind() */
	fd = socket_create_and_bind(bind_addr, port, SOCK_DGRAM);
	if (fd < 0)
		return NULL;

	s = socket_alloc();

	s->buf_size = SOCK_LBUFSZ;		/* Larger buffer to allow big payloads */
	s->buf = halloc(s->buf_size);
	s->type = SOCK_TYPE_UDP;
	s->direction = SOCK_CONN_LISTENING;
	s->file_desc = fd;
	s->pos = 0;
	s->flags |= SOCK_F_UDP;
	s->net = host_addr_net(bind_addr);

	socket_wio_link(s);				/* Link to the I/O functions */

	socket_enable_recvdstaddr(s);

	/*
	 * Allocate the UDP context and register the datagram reception callback.
	 */
	
	WALLOC0(s->resource.udp);
	s->resource.udp->data_ind = data_ind;

	/*
	 * The queue is there to read-ahead datagrams in socket_udp_event() when
	 * we have to stop processing them: emptying the kernel RX queue is needed
	 * if we want to avoid losing incoming datagrams.
	 */

	eslist_init(&s->resource.udp->queue, offsetof(struct udpq, lnk));

	/*
	 * Attach the socket information so that we may record the origin
	 * of the datagrams we receive.
	 */

	s->resource.udp->socket_addr = walloc(sizeof(socket_addr_t));

	/* Get the port of the socket, if needed */

	if (port) {
		s->local_port = port;
	} else {
		socket_addr_t addr;

		if (0 != socket_addr_getsockname(&addr, fd)) {
			g_warning("unable to get the port of the socket: "
				"getsockname() failed: %m");
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

	socket_recv_buf(s, SOCK_UDP_RECV_BUF, FALSE);

	return s;
}

void
socket_disable_token(struct gnutella_socket *s)
{
	socket_check(s);
	s->flags |= SOCK_F_OMIT_TOKEN;
}

bool
socket_omit_token(struct gnutella_socket *s)
{
	socket_check(s);
	return 0 != (s->flags & SOCK_F_OMIT_TOKEN);
}

/**
 * Set/clear TCP_CORK on the socket.
 *
 * When set, TCP will only send out full TCP/IP frames.
 * The exact size depends on your LAN interface, but on Ethernet,
 * it's about 1500 bytes.
 */
void
socket_cork(struct gnutella_socket *s, bool on)
#if defined(TCP_CORK) || defined(TCP_NOPUSH)
{
	static const int option =
#if defined(TCP_CORK)
		TCP_CORK;
#else	/* !TCP_CORK*/
		TCP_NOPUSH;
#endif /* TCP_CORK */
	int arg = on ? 1 : 0;

	socket_check(s);

	if (!(SOCK_F_TCP & s->flags))
		return;

	if (!(s->flags & SOCK_F_CORKED) == !on)
		return;

	if (setsockopt(s->file_desc, sol_tcp(), option, &arg, sizeof arg)) {
		if (ECONNRESET != errno) {
			g_warning("unable to %s TCP_CORK on fd#%d: %m",
				on ? "set" : "clear", s->file_desc);
		}
	} else {
		s->flags &= ~SOCK_F_CORKED;
		s->flags |= on ? SOCK_F_CORKED : 0;
	}
}
#else
{
	static bool warned = FALSE;

	socket_check(s);
	(void) on;

	if (!warned && GNET_PROPERTY(socket_debug)) {
		warned = TRUE;
		g_warning("TCP_CORK is not implemented on this system");
	}
}
#endif /* TCP_CORK || TCP_NOPUSH */

/*
 * Internal routine for socket_send_buf() and socket_recv_buf().
 * Set send/receive buffer to specified size, and warn if it cannot be done.
 * If `shrink' is false, refuse to shrink the buffer if its size is larger.
 * If `size' is zero, the request is ignored. This is useful to stick to the
 * system's default buffer sizes.
 *
 * @return the new size of the socket buffer.
 */
static unsigned
socket_set_intern(int fd, int option, unsigned size,
	const char *type, bool shrink)
{
	unsigned old_len = 0;
	unsigned new_len = 0;
	socklen_t len;

	if (0 == size)
		return 0;

	size = (size + 1) & ~0x1U;	/* Must be even, round to upper boundary */

	len = sizeof(old_len);
	if (-1 == getsockopt(fd, SOL_SOCKET, option, &old_len, &len))
		g_warning("cannot read old %s buffer length on fd #%d: %m", type, fd);

/* FIXME: needs to add metaconfig test */
#ifdef LINUX_SYSTEM
	old_len >>= 1;		/* Linux returns twice the real amount */
#endif

	if (!shrink && old_len >= size) {
		if (GNET_PROPERTY(socket_debug) > 5)
			g_debug(
				"socket %s buffer on fd #%d NOT shrank to %u bytes (is %u)",
				type, fd, size, old_len);
		return old_len;
	}

	if (-1 == setsockopt(fd, SOL_SOCKET, option, &size, sizeof(size)))
		g_warning("cannot set new %s buffer length to %u on fd #%d: %m",
			type, size, fd);

	len = sizeof(new_len);
	if (-1 == getsockopt(fd, SOL_SOCKET, option, &new_len, &len))
		g_warning("cannot read new %s buffer length on fd #%d: %m", type, fd);

#ifdef LINUX_SYSTEM
	new_len >>= 1;		/* Linux returns twice the real amount */
#endif

	if (GNET_PROPERTY(socket_debug) > 5)
		g_debug("socket %s buffer on fd #%d: %u -> %u bytes (now %u) %s",
			type, fd, old_len, size, new_len,
			(new_len == size) ? "OK" : "FAILED");

	return (new_len == size) ? new_len : old_len;
}

/**
 * Set socket's send buffer to specified size.
 * If `shrink' is false, refuse to shrink the buffer if its size is larger.
 */
void
socket_send_buf(struct gnutella_socket *s, int size, bool shrink)
{
	socket_check(s);
	g_return_if_fail(!(s->flags & SOCK_F_SHUTDOWN));
	s->so_sndbuf =
		socket_set_intern(s->file_desc, SO_SNDBUF, size, "send", shrink);
}

/**
 * Set socket's receive buffer to specified size.
 * If `shrink' is false, refuse to shrink the buffer if its size is larger.
 */
void
socket_recv_buf(struct gnutella_socket *s, int size, bool shrink)
{
	socket_check(s);
	g_return_if_fail(!(s->flags & SOCK_F_SHUTDOWN));
	s->so_rcvbuf =
		socket_set_intern(s->file_desc, SO_RCVBUF, size, "receive", shrink);
}

/**
 * Turn TCP_NODELAY on or off on the socket.
 */
void
socket_nodelay(struct gnutella_socket *s, bool on)
{
	int arg = on ? 1 : 0;

	socket_check(s);

	if (!(SOCK_F_TCP & s->flags))
		return;

	/*
	 * Some systems don't like enabling TCP_NODELAY if it's already enabled and
	 * checking may also save a system call.
	 */
	if (!(SOCK_F_NODELAY & s->flags) == !on)
		return;

	if (setsockopt(s->file_desc, sol_tcp(), TCP_NODELAY, &arg, sizeof arg)) {
		if (
			errno != ECONNRESET &&
			errno != EINVAL /* Socket has been shutdown on DARWIN */
		) {
			g_warning("unable to %s TCP_NODELAY on fd#%d: %m",
				on ? "set" : "clear", s->file_desc);
		}
	} else {
		s->flags &= ~SOCK_F_NODELAY;
		s->flags |= on ? SOCK_F_NODELAY : 0;
	}
}

/**
 * Shutdown the TX side of the socket.
 */
void
socket_tx_shutdown(struct gnutella_socket *s)
{
	socket_check(s);
	g_assert(is_valid_fd(s->file_desc));

	if (s->flags & SOCK_F_SHUTDOWN)
		return;

	/*
	 * EINVAL and ENOTCONN may occur if connect() didn't succeed.
	 * ECONNRESET may occur when TX shutdown happens late and the other
	 * side of the connection already closed its socket.
	 */
	if (
		-1 == shutdown(s->file_desc, SHUT_WR) &&
		EINVAL != errno &&
		ENOTCONN != errno &&
		ECONNRESET != errno
	) {
		g_warning("unable to shutdown TX on fd#%d: %m", s->file_desc);
	}
	s->flags |= SOCK_F_SHUTDOWN;
}

static int
socket_get_fd(struct wrap_io *wio)
{
	struct gnutella_socket *s = wio->ctx;
	socket_check(s);		/* Ensures socket not freed */
	return s->file_desc;
}

static unsigned
socket_get_bufsize(struct wrap_io *wio, enum socket_buftype type)
{
	struct gnutella_socket *s = wio->ctx;

	socket_check(s);

	switch (type) {
	case SOCK_BUF_RX:	return s->so_rcvbuf;
	case SOCK_BUF_TX:	return s->so_sndbuf;
	}

	g_assert_not_reached();
}

static ssize_t
socket_plain_write(struct wrap_io *wio, const void *buf, size_t size)
{
	struct gnutella_socket *s = wio->ctx;

	socket_check(s);
	g_assert(!socket_uses_tls(s));

	return s_write(s->file_desc, buf, size);
}

static ssize_t
socket_plain_read(struct wrap_io *wio, void *buf, size_t size)
{
	struct gnutella_socket *s = wio->ctx;

	socket_check(s);
	g_assert(!socket_uses_tls(s));

	return s_read(s->file_desc, buf, size);
}

static ssize_t
socket_plain_writev(struct wrap_io *wio, const iovec_t *iov, int iovcnt)
{
	struct gnutella_socket *s = wio->ctx;

	socket_check(s);
	g_assert(!socket_uses_tls(s));

	return s_writev(s->file_desc, iov, iovcnt);
}

static ssize_t
socket_plain_readv(struct wrap_io *wio, iovec_t *iov, int iovcnt)
{
	struct gnutella_socket *s = wio->ctx;

	socket_check(s);
	g_assert(!socket_uses_tls(s));

	return s_readv(s->file_desc, iov, iovcnt);
}

static ssize_t
socket_plain_sendto(
	struct wrap_io *wio, const gnet_host_t *to, const void *buf, size_t size)
{
	struct gnutella_socket *s = wio->ctx;
	socklen_t len;
	socket_addr_t addr;
	host_addr_t ha;
	ssize_t ret;

	socket_check(s);
	g_assert(!socket_uses_tls(s));

	if (!host_addr_convert(gnet_host_get_addr(to), &ha, s->net)) {
		if (GNET_PROPERTY(udp_debug)) {
			g_carp("%s(): cannot convert %s to %s",
				G_STRFUNC, host_addr_to_string(gnet_host_get_addr(to)),
				net_type_to_string(s->net));
		}
		errno = EINVAL;
		return -1;
	}

	len = socket_addr_set(&addr, ha, gnet_host_get_port(to));
	ret = sendto(s->file_desc, buf, size, 0,
			socket_addr_get_const_sockaddr(&addr), len);

	if ((ssize_t) -1 == ret && GNET_PROPERTY(udp_debug)) {
		int e = errno;
		g_warning("sendto() failed: %m");
		errno = e;
	}
	return ret;
}

static ssize_t
socket_no_sendto(struct wrap_io *unused_wio, const gnet_host_t *unused_to,
	const void *unused_buf, size_t unused_size)
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
		const void *unused_buf, size_t unused_size)
{
	(void) unused_wio;
	(void) unused_buf;
	(void) unused_size;
	g_error("no write() routine allowed");
	return -1;
}

static ssize_t
socket_no_writev(struct wrap_io *unused_wio,
		const iovec_t *unused_iov, int unused_iovcnt)
{
	(void) unused_wio;
	(void) unused_iov;
	(void) unused_iovcnt;
	g_error("no writev() routine allowed");
	return -1;
}

static ssize_t
socket_no_read(struct wrap_io *unused_wio, void *unused_buf, size_t unused_size)
{
	(void) unused_wio;
	(void) unused_buf;
	(void) unused_size;
	g_error("no read() routine allowed");
	return -1;
}

static ssize_t
socket_no_readv(struct wrap_io *unused_wio,
		iovec_t *unused_iov, int unused_iovcnt)
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

	s->wio.magic = WRAP_IO_MAGIC;
	s->wio.ctx = s;
	s->wio.fd = socket_get_fd;
	s->wio.flush = socket_no_flush;
	s->wio.bufsize = socket_get_bufsize;

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
		tls_wio_link(s);
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
safe_readv(wrap_io_t *wio, iovec_t *iov, int iovcnt)
{
	size_t got = 0;
	iovec_t *end = iov + iovcnt;
	iovec_t *siov;
	int siovcnt = MAX_IOV_COUNT;
	int iovgot = 0;

	wrap_io_check(wio);

	for (siov = iov; siov < end; siov += siovcnt) {
		ssize_t r;
		size_t size;
		iovec_t *xiv;
		iovec_t *xend;

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
			size += iovec_len(xiv);

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
safe_readv_fd(int fd, iovec_t *iov, int iovcnt)
{
	size_t got = 0;
	iovec_t *end = iov + iovcnt;
	iovec_t *siov;
	int siovcnt = MAX_IOV_COUNT;
	int iovgot = 0;

	for (siov = iov; siov < end; siov += siovcnt) {
		ssize_t r;
		size_t size;
		iovec_t *xiv;
		iovec_t *xend;

		siovcnt = iovcnt - iovgot;
		if (siovcnt > MAX_IOV_COUNT)
			siovcnt = MAX_IOV_COUNT;
		g_assert(siovcnt > 0);

		r = s_readv(fd, siov, siovcnt);

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
			size += iovec_len(xiv);

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
safe_writev(wrap_io_t *wio, const iovec_t *iov, int iovcnt)
{
	const iovec_t *siov, *end = &iov[iovcnt];
	int siovcnt = MAX_IOV_COUNT;
	int iovsent = 0;
	size_t sent = 0;

	wrap_io_check(wio);

	for (siov = iov; siov < end; siov += siovcnt) {
		const iovec_t *xiv, *xend;
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
			size += iovec_len(xiv);

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
safe_writev_fd(int fd, const iovec_t *iov, int iovcnt)
{
	const iovec_t *siov, *end = &iov[iovcnt];
	int siovcnt = MAX_IOV_COUNT;
	int iovsent = 0;
	size_t sent = 0;

	for (siov = iov; siov < end; siov += siovcnt) {
		const iovec_t *xiv, *xend;
		size_t size;
		ssize_t r;

		siovcnt = iovcnt - iovsent;
		if (siovcnt > MAX_IOV_COUNT)
			siovcnt = MAX_IOV_COUNT;
		g_assert(siovcnt > 0);

		r = s_writev(fd, siov, siovcnt);

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
			size += iovec_len(xiv);

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
