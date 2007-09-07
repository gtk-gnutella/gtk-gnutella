/*
 * $Id$
 *
 * Copyright (c) 2006, Christian Biere
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
 * Common TLS functions.
 */

#include "common.h"

RCSID("$Id$")

#ifdef HAS_GNUTLS
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#endif /* HAS_GNUTLS */

#include "tls_common.h"
#include "features.h"
#include "sockets.h"

#include "if/gnet_property_priv.h"
#include "if/core/settings.h"

#include "lib/array.h"
#include "lib/header.h"
#include "lib/misc.h"
#include "lib/walloc.h"

#include "lib/override.h"		/* Must be the last header included */

#ifdef HAS_GNUTLS

struct tls_context {
	gnutls_session session;
	gnutls_anon_server_credentials server_cred;
	gnutls_anon_client_credentials client_cred;
	const struct gnutella_socket *s;
};

static gnutls_certificate_credentials server_cert_cred;

static inline gnutls_session
tls_socket_get_session(struct gnutella_socket *s)
{
	g_return_val_if_fail(s, NULL);
	g_return_val_if_fail(s->tls.ctx, NULL);
	return s->tls.ctx->session;
}

static inline size_t
tls_adjust_send_size(struct gnutella_socket *s, size_t size)
{
	size_t max_size = gnutls_record_get_max_size(tls_socket_get_session(s));
	return MIN(size, max_size);
}

#ifdef XXX_CUSTOM_PUSH_PULL
static inline void
tls_transport_debug(const char *op, int fd, size_t size, ssize_t ret)
{
	if (GNET_PROPERTY(tls_debug) > 1) {
		int saved_errno = errno;
		gboolean error = (ssize_t) -1 == ret;

		g_message("%s(): fd=%d size=%lu ret=%ld%s%s%s",
			op, fd, (gulong) size, (glong) ret,
			error ? " errno=\"" : "",
			error ? g_strerror(saved_errno) : "",
			error ? "\"" : "");

		errno = saved_errno;
	}
}

static ssize_t
tls_push(gnutls_transport_ptr ptr, const void *buf, size_t size) 
{
	struct gnutella_socket *s = ptr;
	ssize_t ret;

	g_assert(s);
	g_assert(s->file_desc >= 0);

	ret = write(s->file_desc, buf, size);
	tls_transport_debug("tls_push", s->file_desc, size, ret);
	return ret;
}

static ssize_t
tls_pull(gnutls_transport_ptr ptr, void *buf, size_t size) 
{
	struct gnutella_socket *s = ptr;
	ssize_t ret;

	g_assert(s);
	g_assert(s->file_desc >= 0);

	ret = read(s->file_desc, buf, size);
	tls_transport_debug("tls_pull", s->file_desc, size, ret);
	return ret;
}
#endif /* XXX_CUSTOM_PUSH_PULL */

/**
 * Change the monitoring condition on the socket.
 */
static void
tls_socket_evt_change(struct gnutella_socket *s, inputevt_cond_t cond)
{
	g_assert(s);
	g_assert(socket_with_tls(s));	/* No USES yet, may not have handshaked */
	g_assert(INPUT_EVENT_EXCEPTION != cond);
	g_assert(0 != s->gdk_tag);

	if (cond != s->tls.cb_cond) {
		int saved_errno = errno;

		if (GNET_PROPERTY(tls_debug) > 1) {
			int fd = socket_evt_fd(s);
			g_message("tls_socket_evt_change: fd=%d, cond=%s -> %s, handler=%p",
				fd, inputevt_cond_to_string(s->tls.cb_cond),
				inputevt_cond_to_string(cond), s->tls.cb_handler);
		}
		if (s->gdk_tag) {
			inputevt_remove(s->gdk_tag);
			s->gdk_tag = 0;
		}
		socket_evt_set(s, cond, s->tls.cb_handler, s->tls.cb_data);
		errno = saved_errno;
	}
}

static gnutls_dh_params
get_dh_params(void)
{
	static gnutls_dh_params dh_params;
	static gboolean initialized = FALSE;

	if (!initialized) {
 		if (gnutls_dh_params_init(&dh_params)) {
			g_warning("get_dh_params(): gnutls_dh_params_init() failed");
			return NULL;
		}
    	if (gnutls_dh_params_generate2(dh_params, TLS_DH_BITS)) {
			g_warning("get_dh_params(): gnutls_dh_params_generate2() failed");
			return NULL;
		}
		initialized = TRUE;
	}
	return dh_params;
}

static void
tls_print_session_info(const host_addr_t addr, guint16 port,
	gnutls_session session)
{
	const char *proto, *cert, *kx, *ciph, *mac, *comp;

	g_return_if_fail(session);

	proto = gnutls_protocol_get_name(gnutls_protocol_get_version(session));
	cert = gnutls_certificate_type_get_name(
				gnutls_certificate_type_get(session));
	kx = gnutls_kx_get_name(gnutls_kx_get(session));
	comp = gnutls_compression_get_name(gnutls_compression_get(session));
	ciph = gnutls_cipher_get_name(gnutls_cipher_get(session));
	mac = gnutls_mac_get_name(gnutls_mac_get (session));

	g_message(
		"TLS session info:\n"
		"Host:         %s\n"
		"Protocol:     %s\n"
		"Certificate:  %s\n"
		"Key Exchange: %s\n"
		"Cipher:       %s\n"
		"MAC:          %s\n"
		"Compression:  %s\n",
		host_addr_port_to_string(addr, port),
		NULL_STRING(proto),
		NULL_STRING(cert),
		NULL_STRING(kx),
		NULL_STRING(ciph),
		NULL_STRING(mac),
		NULL_STRING(comp)
	);
}

/**
 * @return	TLS_HANDSHAKE_ERROR if the TLS handshake failed.
 *			TLS_HANDSHAKE_RETRY if the handshake is incomplete; thus
 *				tls_handshake() should called again on the next I/O event.
 *			TLS_HANDSHAKE_FINISHED if the TLS handshake succeeded. Note
 *				that this is also returned if TLS is disabled. Therefore
 *				this does not imply an encrypted connection.
 */
enum tls_handshake_result
tls_handshake(struct gnutella_socket *s)
{
	gnutls_session session;
	gboolean do_warn;
	int ret;

	g_assert(s);

	/*
	 * For connect-back probes, the handshake will probably fail. We use
	 * TLS anyway to avoid getting blocked which the remote peer would
	 * not notice. Thus suppress warnings for failed handshakes in this
	 * case.
	 */
	do_warn = SOCK_TYPE_CONNBACK != s->type;

	session = tls_socket_get_session(s);
	g_return_val_if_fail(session, TLS_HANDSHAKE_ERROR);
	g_return_val_if_fail(SOCK_TLS_INITIALIZED == s->tls.stage,
		TLS_HANDSHAKE_ERROR);

#ifdef XXX_CUSTOM_PUSH_PULL
	{
		const void *ptr = gnutls_transport_get_ptr(session);
		if (!ptr) {
			gnutls_transport_set_ptr(session, s);
		}
	}
#else
	{
		int fd = GPOINTER_TO_INT(gnutls_transport_get_ptr(session));
		if (fd < 0) {
			fd = s->file_desc;
			g_assert(fd >= 0);
			gnutls_transport_set_ptr(session, GINT_TO_POINTER(fd));
		}
	}
#endif	/* XXX_CUSTOM_PUSH_PULL */


	ret = gnutls_handshake(session);
	switch (ret) {
	case 0:
		if (GNET_PROPERTY(tls_debug)) {
			g_message("TLS handshake succeeded");
		}
		tls_socket_evt_change(s, INPUT_EVENT_W);
		if (GNET_PROPERTY(tls_debug)) {
			tls_print_session_info(s->addr, s->port, session);
		}
		return TLS_HANDSHAKE_FINISHED;
	case GNUTLS_E_AGAIN:
	case GNUTLS_E_INTERRUPTED:
		tls_socket_evt_change(s, gnutls_record_get_direction(session)
				? INPUT_EVENT_WX : INPUT_EVENT_RX);
		return TLS_HANDSHAKE_RETRY;
	case GNUTLS_E_PULL_ERROR:
	case GNUTLS_E_PUSH_ERROR:
		if (GNET_PROPERTY(tls_debug)) {
			switch (errno) {
			case EPIPE:
			case ECONNRESET:
				if (GNET_PROPERTY(tls_debug) < 2)
					break;
			default:
				g_message("gnutls_handshake() failed: host=%s errno=\"%s\"",
					host_addr_port_to_string(s->addr, s->port),
					g_strerror(errno));
			}
		}
		break;
	default:
		if (do_warn && GNET_PROPERTY(tls_debug)) {
			g_warning("gnutls_handshake() failed: host=%s (%s) error=\"%s\"",
				host_addr_port_to_string(s->addr, s->port),
				SOCK_CONN_INCOMING == s->direction ? "incoming" : "outgoing",
				gnutls_strerror(ret));
		}
	}
	return TLS_HANDSHAKE_ERROR;
}

/**
 * Initiates a new TLS session.
 *
 * @param is_incoming Whether this is an incoming connection.
 * @return The session pointer on success; NULL on failure.
 */
tls_context_t
tls_init(const struct gnutella_socket *s)
{
	static const int cipher_list[] = {
		GNUTLS_CIPHER_AES_256_CBC,
		GNUTLS_CIPHER_AES_128_CBC,
		0
	};
	static const int kx_list[] = {
		GNUTLS_KX_ANON_DH,
		GNUTLS_KX_RSA,
		GNUTLS_KX_DHE_DSS,
		GNUTLS_KX_DHE_RSA,
		0
	};
	static const int mac_list[] = {
		GNUTLS_MAC_MD5,
		GNUTLS_MAC_SHA,
		GNUTLS_MAC_RMD160,
		0
	};
	static const int comp_list[] = {
#if 0
		/* XXX: This causes internal errors from gnutls_record_recv()
		 * at least when browsing hosts which send deflated data.
		 */
		GNUTLS_COMP_DEFLATE,
#endif
		GNUTLS_COMP_NULL,
		0
	};
	static const int cert_list[] = {
		GNUTLS_CRT_X509,
		GNUTLS_CRT_OPENPGP,
		0
	};
	struct tls_context *ctx;

	socket_check(s);

	ctx = walloc0(sizeof *ctx);
	ctx->s = s;

	if (SOCK_CONN_INCOMING == s->direction) {

		if (gnutls_anon_allocate_server_credentials(&ctx->server_cred)) {
			g_warning("gnutls_anon_allocate_server_credentials() failed");
			goto failure;
		}
		gnutls_anon_set_server_dh_params(ctx->server_cred, get_dh_params());

		if (gnutls_init(&ctx->session, GNUTLS_SERVER)) {
			g_warning("gnutls_init() failed");
			goto failure;
		}
		gnutls_dh_set_prime_bits(ctx->session, TLS_DH_BITS);

		if (gnutls_credentials_set(ctx->session,
				GNUTLS_CRD_ANON, ctx->server_cred)) {
			g_warning("gnutls_credentials_set() failed");
			goto failure;
		}

		if (server_cert_cred) {
			if (gnutls_credentials_set(ctx->session,
					GNUTLS_CRD_CERTIFICATE, server_cert_cred)) {
				g_warning("gnutls_credentials_set() failed");
				goto failure;
			}
		}
	} else {
		if (gnutls_anon_allocate_client_credentials(&ctx->client_cred)) {
			g_warning("gnutls_anon_allocate_client_credentials() failed");
			goto failure;
		}
		if (gnutls_init(&ctx->session, GNUTLS_CLIENT)) {
			g_warning("gnutls_init() failed");
			goto failure;
		}
		if (gnutls_credentials_set(ctx->session,
				GNUTLS_CRD_ANON, ctx->client_cred)) {
			g_warning("gnutls_credentials_set() failed");
			goto failure;
		}
	}

	gnutls_set_default_priority(ctx->session);
	if (gnutls_cipher_set_priority(ctx->session, cipher_list)) {
		g_warning("gnutls_cipher_set_priority() failed");
		goto failure;
	}
	if (gnutls_kx_set_priority(ctx->session, kx_list)) {
		g_warning("gnutls_kx_set_priority() failed");
		goto failure;
	}
	if (gnutls_mac_set_priority(ctx->session, mac_list)) {
		g_warning("gnutls_mac_set_priority() failed");
		goto failure;
	}
	if (gnutls_certificate_type_set_priority(ctx->session, cert_list)) {
		g_warning("gnutls_certificate_type_set_priority() failed");
		goto failure;
	}
	if (gnutls_compression_set_priority(ctx->session, comp_list)) {
		g_warning("gnutls_compression_set_priority() failed");
		goto failure;
	}
#ifdef XXX_CUSTOM_PUSH_PULL
	gnutls_transport_set_ptr(ctx->session, NULL);
	gnutls_transport_set_push_function(ctx->session, tls_push);
	gnutls_transport_set_pull_function(ctx->session, tls_pull);
#endif /* XXX_CUSTOM_PUSH_PULL */
	return ctx;

failure:
	tls_free(&ctx);
	return NULL;
}

void
tls_bye(tls_context_t ctx, gboolean is_incoming)
{
	int ret;
	
	g_return_if_fail(ctx);
	g_return_if_fail(ctx->session);

	ret = gnutls_bye(ctx->session,
			is_incoming ? GNUTLS_SHUT_WR : GNUTLS_SHUT_RDWR);
	if (ret < 0) {
		switch (ret) {
		case GNUTLS_E_INTERRUPTED:
		case GNUTLS_E_AGAIN:
			break;
		case GNUTLS_E_PULL_ERROR:
		case GNUTLS_E_PUSH_ERROR:
			if (GNET_PROPERTY(tls_debug)) {
				switch (errno) {
				case EPIPE:
				case ECONNRESET:
					if (GNET_PROPERTY(tls_debug) < 2)
						break;
				default:
					g_message("gnutls_bye() failed: host=%s errno=\"%s\"",
						host_addr_port_to_string(ctx->s->addr, ctx->s->port),
						g_strerror(errno));
				}
			}
			break;
		default:
			g_warning("gnutls_bye() failed: host=%s error=\"%s\"",
				host_addr_port_to_string(ctx->s->addr, ctx->s->port),
				gnutls_strerror(ret));
		}
	}
}

void
tls_free(tls_context_t *ctx_ptr)
{
	tls_context_t ctx;

	g_assert(ctx_ptr);
	ctx = *ctx_ptr;
	if (ctx) {
		if (ctx->session) {
			gnutls_deinit(ctx->session);
		}
		if (ctx->server_cred) {
			gnutls_anon_free_server_credentials(ctx->server_cred);
			ctx->server_cred = NULL;
		}
		if (ctx->client_cred) {
			gnutls_anon_free_client_credentials(ctx->client_cred);
			ctx->client_cred = NULL;
		}
		wfree(ctx, sizeof *ctx);
		*ctx_ptr = NULL;
	}
}

void
tls_global_init(void)
{
	static const struct {
		const char * const name;
		const int major;
		const int minor;
	} f = {
		"tls", 1, 0
	};
	char *cert_file, *key_file;

	if (gnutls_global_init()) {
		g_error("gnutls_global_init() failed");
	}
	get_dh_params();

	key_file = make_pathname(settings_config_dir(), "key.pem");
	cert_file = make_pathname(settings_config_dir(), "cert.pem");

	if (file_exists(key_file) && file_exists(cert_file)) {
		int ret;

		gnutls_certificate_allocate_credentials(&server_cert_cred);
		ret = gnutls_certificate_set_x509_key_file(server_cert_cred,
				cert_file, key_file, GNUTLS_X509_FMT_PEM);
		if (ret < 0) {
			g_warning("gnutls_certificate_set_x509_key_file() failed: %s",
					gnutls_strerror(ret));
			gnutls_certificate_free_credentials(server_cert_cred);
			server_cert_cred = NULL;
		} else {
			gnutls_certificate_set_dh_params(server_cert_cred, get_dh_params());
		}
	}
	G_FREE_NULL(key_file);
	G_FREE_NULL(cert_file);

	header_features_add(FEATURES_CONNECTIONS, f.name, f.major, f.minor);
	header_features_add(FEATURES_DOWNLOADS, f.name, f.major, f.minor);
	header_features_add(FEATURES_UPLOADS, f.name, f.major, f.minor);
}

static ssize_t
tls_write(struct wrap_io *wio, gconstpointer buf, size_t size)
{
	inputevt_cond_t cond = 0;
	struct gnutella_socket *s = wio->ctx;
	const char *p;
	size_t len;
	ssize_t ret;

	g_assert(size <= INT_MAX);
	g_assert(s != NULL);
	g_assert(buf != NULL);

	g_assert(socket_uses_tls(s));

	if (0 != s->tls.snarf) {
		p = NULL;
		len = 0;
	} else {
		p = buf;
		len = tls_adjust_send_size(s, size);
		g_assert(NULL != p && len > 0);
	}

	ret = gnutls_record_send(tls_socket_get_session(s), p, len);
	if (ret < 0) {
		switch (ret) {
		case GNUTLS_E_INTERRUPTED:
		case GNUTLS_E_AGAIN:
			cond = gnutls_record_get_direction(tls_socket_get_session(s))
					? INPUT_EVENT_WX : INPUT_EVENT_RX;

			if (0 == s->tls.snarf) {
				s->tls.snarf = len;
				ret = len;
			} else {
				errno = VAL_EAGAIN;
				ret = -1;
			}
			break;
		case GNUTLS_E_PULL_ERROR:
		case GNUTLS_E_PUSH_ERROR:
			if (GNET_PROPERTY(tls_debug)) {
				g_message("tls_write(): socket_tls_write() failed: "
					"host=%s errno=\"%s\"",
					host_addr_port_to_string(s->addr, s->port),
					g_strerror(errno));
			}
			errno = EIO;
			ret = -1;
			break;
		default:
			if (GNET_PROPERTY(tls_debug)) {
				g_warning("tls_write(): gnutls_record_send() failed: "
					"host=%s snarf=%lu error=\"%s\"",
					host_addr_port_to_string(s->addr, s->port),
					(unsigned long) s->tls.snarf,
					gnutls_strerror(ret));
			}
			errno = EIO;
			ret = -1;
		}
	} else {
		if (0 != s->tls.snarf) {
			g_assert(s->tls.snarf >= (size_t) ret);
			s->tls.snarf -= ret;
			errno = VAL_EAGAIN;
			ret = -1;
		}
	}

	if (s->gdk_tag && cond)
		tls_socket_evt_change(s, cond);

	g_assert(ret == (ssize_t) -1 || (size_t) ret <= size);
	return ret;
}

static ssize_t
tls_read(struct wrap_io *wio, gpointer buf, size_t size)
{
	inputevt_cond_t cond = 0;
	struct gnutella_socket *s = wio->ctx;
	ssize_t ret;

	g_assert(size <= INT_MAX);
	g_assert(s != NULL);
	g_assert(buf != NULL);

	g_assert(socket_uses_tls(s));

	if (s->wio.flush(&s->wio) < 0) {
		if (!is_temporary_error(errno)) {
			g_warning("tls_read: flush error: %s", g_strerror(errno));
			return -1;
		}
	}

	ret = gnutls_record_recv(tls_socket_get_session(s), buf, size);
	if (ret < 0) {
		switch (ret) {
		case GNUTLS_E_INTERRUPTED:
		case GNUTLS_E_AGAIN:
			cond = gnutls_record_get_direction(tls_socket_get_session(s))
					? INPUT_EVENT_WX : INPUT_EVENT_RX;
			errno = VAL_EAGAIN;
			break;
		case GNUTLS_E_PULL_ERROR:
		case GNUTLS_E_PUSH_ERROR:
			if (GNET_PROPERTY(tls_debug)) {
				g_message("tls_read(): socket_tls_read() failed: "
					"host=%s errno=\"%s\"",
					host_addr_port_to_string(s->addr, s->port),
					g_strerror(errno));
			}
			errno = EIO;
			break;
		default:
			if (GNET_PROPERTY(tls_debug)) {
				g_warning("tls_read(): gnutls_record_recv() failed: "
					"host=%s error=\"%s\"",
					host_addr_port_to_string(s->addr, s->port),
					gnutls_strerror(ret));
			}
			errno = EIO;
		}
		ret = -1;
	}

	if (s->gdk_tag && cond)
		tls_socket_evt_change(s, cond);

	g_assert(ret == (ssize_t) -1 || (size_t) ret <= size);
	return ret;
}

static int
tls_flush(struct wrap_io *wio)
{
	struct gnutella_socket *s = wio->ctx;
	ssize_t ret;

	socket_check(s);

	if (0 == s->tls.snarf)
		return 0;

	if (GNET_PROPERTY(tls_debug)) {
		g_message("tls_flush: snarf=%lu", (gulong) s->tls.snarf);
	}
	ret = tls_write(wio, "", 0);
	g_assert((ssize_t)-1 == ret);
	return (s->tls.snarf > 0 || VAL_EAGAIN != errno) ? -1 : 0;
}

static ssize_t
tls_writev(struct wrap_io *wio, const struct iovec *iov, int iovcnt)
{
	inputevt_cond_t cond = 0;
	struct gnutella_socket *s = wio->ctx;
	ssize_t ret, written;
	int i;

	g_assert(socket_uses_tls(s));
	g_assert(iovcnt > 0);

	if (0 != s->tls.snarf) {
		ret = gnutls_record_send(tls_socket_get_session(s), NULL, 0);
		if (ret > 0) {
			g_assert((ssize_t) s->tls.snarf >= ret);
			s->tls.snarf -= ret;
			if (0 != s->tls.snarf) {
				errno = VAL_EAGAIN;
				ret = -1;
				goto done;
			}
		} else {
			switch (ret) {
			case 0:
				ret = 0;
				goto done;
			case GNUTLS_E_INTERRUPTED:
			case GNUTLS_E_AGAIN:
				cond = gnutls_record_get_direction(tls_socket_get_session(s))
						? INPUT_EVENT_WX : INPUT_EVENT_RX;
				errno = VAL_EAGAIN;
				break;
			case GNUTLS_E_PULL_ERROR:
			case GNUTLS_E_PUSH_ERROR:
				if (GNET_PROPERTY(tls_debug)) {
					g_message("tls_writev() failed: "
						"host=%s errno=\"%s\"",
						host_addr_port_to_string(s->addr, s->port),
						g_strerror(errno));
				}
				errno = EIO;
				break;
			default:
				if (GNET_PROPERTY(tls_debug)) {
					g_warning("tls_writev(): gnutls_record_send() failed: "
						"host=%s error=\"%s\"",
						host_addr_port_to_string(s->addr, s->port),
						gnutls_strerror(ret));
				}
				errno = EIO;
			}
			ret = -1;
			goto done;
		}
	}

	ret = -2;	/* Shut the compiler: iovcnt could still be 0 */
	written = 0;
	for (i = 0; i < iovcnt; ++i) {
		char *p;
		size_t len;

		p = iov[i].iov_base;
		len = tls_adjust_send_size(s, iov[i].iov_len);
		g_assert(NULL != p && len > 0);

		ret = gnutls_record_send(tls_socket_get_session(s), p, len);
		if (ret < 0) {
			switch (ret) {
			case GNUTLS_E_INTERRUPTED:
			case GNUTLS_E_AGAIN:
				cond = gnutls_record_get_direction(tls_socket_get_session(s))
						? INPUT_EVENT_WX : INPUT_EVENT_RX;
				s->tls.snarf = len;
				ret = written + len;
				break;
			case GNUTLS_E_PULL_ERROR:
			case GNUTLS_E_PUSH_ERROR:
				if (GNET_PROPERTY(tls_debug)) {
					g_message("tls_writev() failed: "
						"host=%s errno=\"%s\"",
						host_addr_port_to_string(s->addr, s->port),
						g_strerror(errno));
				}
				ret = -1;
				break;
			default:
				if (GNET_PROPERTY(tls_debug)) {
					g_warning("gnutls_record_send() failed: "
						"host=%s error=\"%s\"",
						host_addr_port_to_string(s->addr, s->port),
						gnutls_strerror(ret));
				}
				errno = EIO;
				ret = -1;
			}
			break;
		} else if (0 == ret) {
			ret = written;
			break;
		} else {
			written += ret;
			ret = written;
		}
	}

done:
	if (s->gdk_tag && cond)
		tls_socket_evt_change(s, cond);

	g_assert((ssize_t) -1 == ret || ret >= 0);
	return ret;
}

static ssize_t
tls_readv(struct wrap_io *wio, struct iovec *iov, int iovcnt)
{
	inputevt_cond_t cond = 0;
	struct gnutella_socket *s = wio->ctx;
	size_t rcvd = 0;
	ssize_t ret;
	int i;

	g_assert(socket_uses_tls(s));
	g_assert(iovcnt > 0);

	if (s->wio.flush(&s->wio) < 0) {
		if (!is_temporary_error(errno)) {
			g_warning("tls_read: flush error: %s", g_strerror(errno));
			return -1;
		}
	}

	ret = 0;	/* Shut the compiler: iovcnt could still be 0 */
	for (i = 0; i < iovcnt; ++i) {
		size_t len;
		char *p;

		p = iov[i].iov_base;
		len = tls_adjust_send_size(s, iov[i].iov_len);
		g_assert(NULL != p && len > 0);

		ret = gnutls_record_recv(tls_socket_get_session(s), p, len);
		if (ret <= 0) {
			break;
		}
		rcvd += ret;
		if ((size_t) ret != len) {
			break;
		}
	}

	if (ret < 0) {
		switch (ret) {
		case GNUTLS_E_INTERRUPTED:
		case GNUTLS_E_AGAIN:
			cond = gnutls_record_get_direction(tls_socket_get_session(s))
					? INPUT_EVENT_WX : INPUT_EVENT_RX;
			if (rcvd > 0) {
				ret = rcvd;
			} else {
				errno = VAL_EAGAIN;
				ret = -1;
			}
			break;
		case GNUTLS_E_PULL_ERROR:
		case GNUTLS_E_PUSH_ERROR:
			if (GNET_PROPERTY(tls_debug)) {
				g_message("tls_readv(): socket_tls_readv() failed: "
					"host=%s errno=\"%s\"",
					host_addr_port_to_string(s->addr, s->port),
					g_strerror(errno));
			}
			errno = EIO;
			ret = -1;
			break;
		default:
			if (GNET_PROPERTY(tls_debug)) {
				g_warning("tls_readv(): gnutls_record_recv() failed: "
					"host=%s error=\"%s\"",
					host_addr_port_to_string(s->addr, s->port),
					gnutls_strerror(ret));
			}
			errno = EIO;
			ret = -1;
		}
	} else {
		ret = rcvd;
	}

	if (s->gdk_tag && cond)
		tls_socket_evt_change(s, cond);

	g_assert((ssize_t) -1 == ret || ret >= 0);
	return ret;
}

static ssize_t
tls_no_sendto(struct wrap_io *unused_wio, const gnet_host_t *unused_to,
	gconstpointer unused_buf, size_t unused_size)
{
	(void) unused_wio;
	(void) unused_to;
	(void) unused_buf;
	(void) unused_size;
	g_error("no sendto() routine allowed");
	return -1;
}

void
tls_wio_link(struct wrap_io *wio)
{
	g_assert(wio);	
	wio->write = tls_write;
	wio->read = tls_read;
	wio->writev = tls_writev;
	wio->readv = tls_readv;
	wio->sendto = tls_no_sendto;
	wio->flush = tls_flush;
}

const char *
tls_version_string(void)
{
	static char buf[128];

	if ('\0' == buf[0]) {
		const char *current = gnutls_check_version(NULL);
		int differ = strcmp(current, LIBGNUTLS_VERSION);

		concat_strings(buf, sizeof buf, "GNU TLS ", current,
			differ ? " (compiled against " : "",
			differ ? LIBGNUTLS_VERSION : "",
			differ ? ")" : "",
			(void *) 0);
	}
	return buf;
}

static gnutls_x509_crt
svn_release_notify_certificate(void)
{
	static const char certificate[] =
"-----BEGIN CERTIFICATE-----\n"
"MIIBKTCB1qADAgECAgEAMAsGCSqGSIb3DQEBBTAAMB4XDTA3MDgyNTA0MjIxMVoX\n"
"DTA4MDgyNDA0MjIxNVowADBZMAsGCSqGSIb3DQEBAQNKADBHAkCpadMxWZWWzcV7\n"
"Mu66wzBuQ8AkanGspm7ImdRKOlo55V3uBlSob9N/GFlzZ9kG6kS169wgdK2vNQwR\n"
"5jOMeIMbAgMBAAGjQDA+MAwGA1UdEwEB/wQCMAAwDwYDVR0PAQH/BAUDAweAADAd\n"
"BgNVHQ4EFgQU8pP/Zgh/K6N0zVHMEs2VIWZNjUIwCwYJKoZIhvcNAQEFA0EAO6ld\n"
"1NFx0QRBCHE+BUaCX3tuRC0a7HRq8UEqhcKgW7Xk3nkGUNXTcSSo7wu+jpePUsw8\n"
"njFhJCXeDIcR7jzNCA==\n"
"-----END CERTIFICATE-----\n";
	static gboolean initialized;
	static gnutls_x509_crt cert;

	if (!initialized) {
		gnutls_datum cert_data;
		int error;

		initialized = TRUE;
		error = gnutls_x509_crt_init(&cert);
		if (error) {
			g_warning("gnutls_x509_crt_init() failed: %s",
					gnutls_strerror(error));
			cert = NULL;
			return NULL;
		}

		cert_data.data = (void *) certificate;
		cert_data.size = CONST_STRLEN(certificate);
		error = gnutls_x509_crt_import(cert, &cert_data, GNUTLS_X509_FMT_PEM);
		if (error) {
			g_warning("gnutls_x509_crt_import() failed: %s",
					gnutls_strerror(error));
			gnutls_x509_crt_deinit(cert);
			cert = NULL;
			return NULL;
		}
	}
	return cert; 
}

gboolean
svn_release_notification_can_verify(void)
{
	return NULL != svn_release_notify_certificate();
}

static gboolean
verify_signature(gnutls_x509_crt cert,
	const struct array *input, const struct array *signature)
{
	gnutls_datum data, sig;

	g_return_val_if_fail(cert, FALSE);
	g_return_val_if_fail(input, FALSE);
	g_return_val_if_fail(signature, FALSE);

	data.data = (void *) input->data;
	data.size = input->size;

	sig.data = (void *) signature->data;
	sig.size = signature->size;

	return 1 == gnutls_x509_crt_verify_data(cert, 0, &data, &sig);
}

/**
 * Verifies "data" against "signature".
 *
 * @return TRUE if the signature matches.
 */
gboolean
svn_release_notification_verify(guint32 revision, time_t date,
	const struct array *signature)
{
	char rev[12], data[64];
	struct array input;

	uint32_to_string_buf(revision, rev, sizeof rev);
	input.data = (void *) data;
	input.size = concat_strings(data, sizeof data,
					"r", rev,
					"@", uint32_to_string(date),
					(void *) 0);

	return verify_signature(svn_release_notify_certificate(),
				&input, signature);
}

#else	/* !HAS_GNUTLS*/

enum tls_handshake_result
tls_handshake(struct gnutella_socket *s)
{
	(void) s;
	return TLS_HANDSHAKE_FINISHED;
}

tls_context_t 
tls_init(const struct gnutella_socket *s)
{
	(void) s;
	return NULL;
}

void
tls_wio_link(struct wrap_io *wio)
{
	(void) wio;
	g_assert_not_reached();
}

void
tls_global_init(void)
{
	/* Nothing to do */
}

const char *
tls_version_string(void)
{
	return NULL;
}

gboolean
svn_release_notification_can_verify(void)
{
	return FALSE;
}

gboolean
svn_release_notification_verify(guint32 revision, time_t date,
	const struct array *signature)
{
	g_return_val_if_fail(signature, FALSE);
	(void) revision;
	(void) date;
	return FALSE;
}

#endif	/* HAS_GNUTLS */

/* vi: set ts=4 sw=4 cindent: */
