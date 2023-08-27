/*
 * Copyright (c) 2015 Raphael Manfredi
 * Copyright (c) 2006 Christian Biere
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
 *      51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *----------------------------------------------------------------------
 */

/**
 * @ingroup core
 * @file
 *
 * Common TLS functions.
 */

#include "common.h"

#ifdef HAS_GNUTLS
#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>
#include <gnutls/x509.h>

#ifdef GNUTLS_VERSION_MAJOR
#define HAS_TLS(major, minor) \
	((GNUTLS_VERSION_MAJOR > (major) || \
	 (GNUTLS_VERSION_MAJOR == (major) && GNUTLS_VERSION_MINOR >= (minor))))
#else
#define HAS_TLS(major, minor) 0
#endif

#else
#define HAS_TLS(major, minor) 0
#endif /* HAS_GNUTLS */

#if HAS_TLS(2, 12)
#include <gnutls/abstract.h>
#endif

#if HAS_TLS(2, 12) && !defined(MINGW32)
/* Unfortunately, there is no support on Windows at the gnutls level */
#define USE_TLS_PUSHV
#elif HAS_TLS(3, 3)
/* Works fine in Windows starting with 3.3 (and maybe earlier?) */
#define USE_TLS_PUSHV
#endif

#include "tls_common.h"

#include "features.h"
#include "sockets.h"

#include "if/gnet_property_priv.h"
#include "if/core/settings.h"

#include "lib/aje.h"
#include "lib/array.h"
#include "lib/concat.h"
#include "lib/endian.h"
#include "lib/fd.h"
#include "lib/file.h"
#include "lib/glog.h"
#include "lib/halloc.h"
#include "lib/header.h"
#include "lib/hstrfn.h"
#include "lib/htable.h"
#include "lib/iovec.h"
#include "lib/misc.h"			/* For strchomp() */
#include "lib/path.h"
#include "lib/product.h"
#include "lib/random.h"
#include "lib/str.h"
#include "lib/stringify.h"
#include "lib/walloc.h"

#include "lib/override.h"		/* Must be the last header included */

#ifdef HAS_GNUTLS

static const char tls_keyfile[]  = "key.pem";
static const char tls_certfile[] = "cert.pem";

#define TLS_DH_BITS			768
#define TLS_FILE_MAXSIZE	(64 * 1024)

struct tls_context {
	gnutls_session_t session;
	union {
		gnutls_anon_server_credentials_t server;
		gnutls_anon_client_credentials_t client;
	} cred;
	const struct gnutella_socket *s;
};

static gnutls_certificate_credentials_t cert_cred;
static bool cert_cred_loaded;

/**
 * Table mapping a gnutls_session_t (a pointer to a data structure) into
 * the corresponding gnutella_socket_t structure.  This is required for
 * gnutls callbacks that provide only a session.
 */
static htable_t *tls_sessions;

/**
 * Fill ``len'' random byte starting at ``data''.
 *
 * @attention
 * This supersedes the version from the gnutls library!
 *
 * @param level		the random level GNUTLS_RND_NONCE, etc...
 * @param data		where to write the random data
 * @param len		amount of random data to generate
 *
 * @return 0 if OK
 */
int
gnutls_rnd(gnutls_rnd_level_t level, void *data, size_t len)
{
	/*
	 * The GNUTLS_RND_KEY is the strongest level for TLS: if the random
	 * generator is broken, many TLS sessions become insecure.
	 *
	 * The GNUTLS_RND_RANDOM is a medium level, which compromises
	 * the current session if broken.
	 *
	 * The GNUTLS_RND_NONCE is for non-predictable random numbers, which
	 * must resist statistical analysis.  If broken, parts of the TLS
	 * session are compromised.
	 */

	if (GNUTLS_RND_KEY == level)
		random_key_bytes(data, len);
	else if (GNUTLS_RND_NONCE == level)
		random_bytes_with(aje_rand, data, len);
	else
		random_strong_bytes(data, len);

	if (GNET_PROPERTY(tls_debug) > 9) {
		g_debug("%s(): generated %zu %s byte%s",
			G_STRFUNC, len,
			GNUTLS_RND_KEY == level ? "key" :
			GNUTLS_RND_NONCE == level ? "nonce" :
			GNUTLS_RND_RANDOM == level ? "random" : "unknown",
			plural(len));
	}

	return 0;
}

/**
 * Generate an X.509 private key in PEM format.
 *
 * @param file		the path to the file where key needs to be stored.
 */
static void
tls_generate_private_key(const char *file)
{
	gnutls_x509_privkey_t key = NULL;
	size_t len;
	uint bits;
	void *data = NULL;
	int e, fd = -1;
	const char *fn;
	const int key_type = GNUTLS_PK_RSA;
	const int mode = S_IRUSR;	/* 0400 */

#define TRY(function) (fn = (#function)), e = function

	if (TRY(gnutls_x509_privkey_init)(&key))
		goto failed;

#if HAS_TLS(2, 12)
	bits = gnutls_sec_param_to_pk_bits(key_type, GNUTLS_SEC_PARAM_HIGH);
#else
	bits = 3248;	/* output with 2.12 for the above call */
#endif

	g_info("TLS generating %d-bit %s private key...",
		bits, gnutls_pk_algorithm_get_name(key_type));

	if (TRY(gnutls_x509_privkey_generate)(key, key_type, bits, 0))
		goto failed;

	g_info("TLS saving %d-bit key into %s", bits, file);

	fd = file_create(file, O_WRONLY, mode);
	if (-1 == fd)
		goto done;

	len = bits;			/* Result should be shorter than that */
	data = halloc(len);
	if (TRY(gnutls_x509_privkey_export)(key, GNUTLS_X509_FMT_PEM, data, &len))
		goto failed;

	if (-1 == write(fd, data, len)) {
		g_warning("%s(): write() failed: %m", G_STRFUNC);
		goto error;
	}

	fd_close(&fd);
	goto done;

failed:
	g_warning("%s(): %s() failed: %s", G_STRFUNC, fn, gnutls_strerror(e));
	/* FALL THROUGH */
error:
	fd_close(&fd);			/* On Windows, needs to close before unlink() */
	(void) unlink(file);
	/* FALL THROUGH */
done:
	gnutls_x509_privkey_deinit(key);
	HFREE_NULL(data);

#undef TRY
}

/**
 * Log message.
 */
static void G_PRINTF(2, 0)
tls_logfmt(GLogLevelFlags level, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	gl_logv(G_LOG_DOMAIN, level, fmt, args);
	va_end(args);
}

/**
 * Log TLS certificate.
 */
static void G_PRINTF(1, 0)
tls_cert_log(const char *fmt,
	gnutls_x509_crt_t cert, gnutls_certificate_print_formats_t format)
{
	gnutls_datum_t out;
	int e;

	e = gnutls_x509_crt_print(cert, format, &out);
	if (e) {
		str_t *s = str_new(80);

		str_printf(s, "error printing X.509 certificate: %s",
			gnutls_strerror(e));
		tls_logfmt(G_LOG_LEVEL_WARNING, fmt, str_2c(s));
		str_destroy_null(&s);
	} else {
		tls_logfmt(G_LOG_LEVEL_INFO, fmt, out.data);
		gnutls_free(out.data);
	}
}

/**
 * Get file data into a halloc()'ed buffer.
 */
static gnutls_datum_t
tls_read_filedata(const char *file)
{
	int fd = -1;
	filestat_t buf;
	ssize_t r;
	gnutls_datum_t d = { NULL, 0 };

	if (-1 == stat(file, &buf)) {
		g_warning("%s(): can't stat() %s: %m", G_STRFUNC, file);
		return d;
	}

	if (buf.st_size > TLS_FILE_MAXSIZE) {
		g_warning("%s(): file %s is too large (%'zu bytes, max set to %'d)",
			G_STRFUNC, file, (size_t) buf.st_size, TLS_FILE_MAXSIZE);
		return d;
	}

	d.data = halloc(buf.st_size);
	fd = file_open(file, O_RDONLY, 0);
	if (-1 == fd)
		goto error;

	r = read(fd, d.data, buf.st_size);
	if (r < 0) {
		g_warning("%s(): read() failed: %m", G_STRFUNC);
		goto error;
	}
	if (r != buf.st_size) {
		g_warning("%s(): partial read() of %'zd out of %'zu bytes from %s",
			G_STRFUNC, r, (size_t) buf.st_size, file);
		goto error;
	}

	fd_close(&fd);
	d.size = r;

	return d;

error:
	HFREE_NULL(d.data);
	fd_close(&fd);

	return d;
}

#if HAS_TLS(2, 12)
/**
 * Generate an X.509 self-signed certificate in PEM format.
 *
 * @param file		the path to the file where certificate needs to be stored.
 * @param keyfile	the path to the private key file
 */
static void
tls_generate_self_signed_cert(const char *file, const char *keyfile)
{
	gnutls_x509_crt_t crt = NULL;
	gnutls_x509_privkey_t key = NULL;
	gnutls_privkey_t privkey = NULL;
	gnutls_pubkey_t pubkey = NULL;
	void *data = NULL;
	size_t len;
	int e, fd = -1;
	const char *fn;
	const int key_type = GNUTLS_PK_RSA;
	const int mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;		/* 0644 */
	const gnutls_digest_algorithm_t digest = GNUTLS_DIG_SHA256;
	gnutls_datum_t dkey;
	time_t expire = 2145913200;		/* Fri Jan  1 00:00:00 2038 */
	str_t *cn = NULL;

	cn = str_new(80);
	str_printf(cn, "%s/%s", product_name(), product_version());

#define TRY(function) (fn = (#function)), e = function

	if (TRY(gnutls_x509_privkey_init)(&key))
		goto failed;

	if (TRY(gnutls_x509_crt_init)(&crt))
		goto failed;

	if (TRY(gnutls_pubkey_init)(&pubkey))
		goto failed;

	if (TRY(gnutls_privkey_init)(&privkey))
		goto failed;

	dkey = tls_read_filedata(keyfile);

	if (NULL == dkey.data)
		goto error;

	g_info("TLS generating self-signed certificate...");

	if (TRY(gnutls_x509_privkey_import)(key, &dkey, key_type))
		goto failed;

	HFREE_NULL(data);

	if (TRY(gnutls_privkey_import_x509)(privkey, key, 0))
		goto failed;

	if (TRY(gnutls_pubkey_import_privkey)(pubkey, privkey, 0, 0))
		goto failed;

	if (TRY(gnutls_x509_crt_set_pubkey)(crt, pubkey))
		goto failed;

	/* OID "2.5.4.3" is the "CN" -- Common Name */

	if (
		TRY(gnutls_x509_crt_set_dn_by_oid)
			(crt, "2.5.4.3", 0, str_2c(cn), str_len(cn))
	)
		goto failed;

	/*
	 * No two certificates generated by the same CA can bear the same serial,
	 * and we are our own CA (Certification Authority) here since we will
	 * be self-signing.  Use the current time to make the serial unique.
	 */

	{
		char serial[2 * sizeof(uint32)];
		tm_t now;
		char *p;

		ZERO(&serial);
		tm_now_exact(&now);

		p = poke_le32(serial, now.tv_sec);
		p = poke_be32(p, now.tv_usec);

		if (TRY(gnutls_x509_crt_set_serial)(crt, serial, N_ITEMS(serial)))
			goto failed;
	}

	/*
	 * The subject and authority IDs are this servent's GUID.
	 */

	{
		guid_t *guid = (guid_t *) GNET_PROPERTY_PTR(servent_guid);

		if (TRY(gnutls_x509_crt_set_subject_key_id)(crt, PTRLEN(guid)))
			goto failed;

		if (TRY(gnutls_x509_crt_set_authority_key_id)(crt, PTRLEN(guid)))
			goto failed;
	}

	if (TRY(gnutls_x509_crt_set_activation_time)(crt, time(NULL)))
		goto failed;

	if (TRY(gnutls_x509_crt_set_expiration_time)(crt, expire))
		goto failed;

	if (TRY(gnutls_x509_crt_set_version (crt, 3)))
		goto failed;

	if (TRY(gnutls_x509_crt_privkey_sign)(crt, crt, privkey, digest, 0))
		goto failed;

	tls_cert_log("TLS generated certificate:\n%s", crt, GNUTLS_CRT_PRINT_FULL);
	g_info("TLS saving certificate into %s", file);

	fd = file_create(file, O_WRONLY, mode);
	if (-1 == fd)
		goto done;

	len = 64 * 1024;
	data = halloc(len);

	if (TRY(gnutls_x509_crt_export)(crt, GNUTLS_X509_FMT_PEM, data, &len))
		goto failed;

	if (-1 == write(fd, data, len)) {
		g_warning("%s(): write() failed: %m", G_STRFUNC);
		goto error;
	}

	fd_close(&fd);
	goto done;

failed:
	g_warning("%s(): %s() failed: %s", G_STRFUNC, fn, gnutls_strerror(e));
	/* FALL THROUGH */
error:
	fd_close(&fd);			/* On Windows, needs to close before unlink() */
	(void) unlink(file);
	/* FALL THROUGH */
done:
	gnutls_x509_privkey_deinit(key);
	gnutls_x509_crt_deinit(crt);
	gnutls_pubkey_deinit(pubkey);
	gnutls_privkey_deinit(privkey);
	HFREE_NULL(data);
	str_destroy_null(&cn);
#undef TRY
}
#endif	/* TLS >= 2.12 */

static inline gnutls_session_t
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
	g_assert(max_size > 0);
	return MIN(size, max_size);
}

static inline void
tls_transport_debug(const char *op, const struct gnutella_socket *s,
	size_t size, ssize_t ret)
{
	if ((ssize_t) -1 == ret) {
		unsigned level = is_temporary_error(errno) ? 2 : 0;

		if (GNET_PROPERTY(tls_debug) > level) {
			g_debug("%s(): fd=%d size=%zu host=%s ret=-1 errno=%m",
				op, s->file_desc, size,
				host_addr_port_to_string(s->addr, s->port));
		}
	} else {
		if (GNET_PROPERTY(tls_debug) > 2) {
			g_debug("%s(): fd=%d size=%zu host=%s ret=%zu",
				op, s->file_desc, size,
				host_addr_port_to_string(s->addr, s->port), ret);
		}
	}
}

/**
 * Change the monitoring condition on the socket.
 */
static void
tls_socket_evt_change(struct gnutella_socket *s, inputevt_cond_t cond)
{
	socket_check(s);
	g_assert(socket_with_tls(s));	/* No USES yet, may not have handshaked */
	g_assert(INPUT_EVENT_EXCEPTION != cond);

	if (0 == s->gdk_tag)
		return;

	if (cond != s->tls.cb_cond) {
		int saved_errno = errno;

		if (GNET_PROPERTY(tls_debug) > 1) {
			int fd = socket_evt_fd(s);
			g_debug("%s(): fd=%d, cond=%s -> %s",
				G_STRFUNC, fd, inputevt_cond_to_string(s->tls.cb_cond),
				inputevt_cond_to_string(cond));
		}
		inputevt_remove(&s->gdk_tag);
		socket_evt_set(s, cond, s->tls.cb_handler, s->tls.cb_data);
		errno = saved_errno;
	}
}

static inline void
tls_signal_pending(struct gnutella_socket *s)
{
	size_t n = gnutls_record_check_pending(tls_socket_get_session(s));

	/*
	 * There can be data in the GnuTLS layer, or in the socket input buffer.
	 */

	if (n > 0 || 0 != (n = s->pos)) {
		int saved_errno = errno;

		if (GNET_PROPERTY(tls_debug) > 1) {
			g_debug("%s(): pending=%zu%s",
				G_STRFUNC, n, s->pos != 0 ? " (socket)" : "");
		}
		inputevt_set_readable(s->file_desc);
		errno = saved_errno;
	}
}

static inline void
tls_set_errno(struct gnutella_socket *s, int errnum)
{
	gnutls_transport_set_errno(tls_socket_get_session(s), errnum);
}

#ifdef USE_TLS_PUSHV
static inline ssize_t
tls_pushv(gnutls_transport_ptr_t ptr, const giovec_t *iov, int iovcnt)
{
	struct gnutella_socket *s = ptr;
	ssize_t ret;
	int saved_errno;
	iovec_t *niov;

	socket_check(s);
	g_assert(is_valid_fd(s->file_desc));

	/*
	 * On Windows, we need to convert the giovec_t structure into our
	 * emulated iovec_t, which are actually WSABUF structures, so that
	 * we can pass them to s_writev().
	 */

	if (is_running_on_mingw()) {
		int i;

		HALLOC_ARRAY(niov, iovcnt);
		for (i = 0; i < iovcnt; i++) {
			iovec_set(&niov[i], iov[i].iov_base, iov[i].iov_len);
		}
	} else {
		niov = (iovec_t *) iov;		/* Isomorphic structures */
	}

	ret = s_writev(s->file_desc, niov, iovcnt);
	saved_errno = errno;
	tls_signal_pending(s);
	if ((ssize_t) -1 == ret) {
		tls_set_errno(s, saved_errno);
		if (ECONNRESET == saved_errno || EPIPE == saved_errno) {
			socket_connection_reset(s);
		}
	}
	tls_transport_debug(G_STRFUNC, s, iov_calculate_size(niov, iovcnt), ret);
	if (is_running_on_mingw())
		hfree(niov);
	errno = saved_errno;
	return ret;
}
#else	/* !USE_TLS_PUSHV */
static inline ssize_t
tls_push(gnutls_transport_ptr_t ptr, const void *buf, size_t size)
{
	struct gnutella_socket *s = ptr;
	ssize_t ret;
	int saved_errno;

	socket_check(s);
	g_assert(is_valid_fd(s->file_desc));

	ret = s_write(s->file_desc, buf, size);
	saved_errno = errno;
	tls_signal_pending(s);
	if ((ssize_t) -1 == ret) {
		tls_set_errno(s, saved_errno);
		if (ECONNRESET == saved_errno || EPIPE == saved_errno) {
			socket_connection_reset(s);
		}
	}
	tls_transport_debug(G_STRFUNC, s, size, ret);
	errno = saved_errno;
	return ret;
}
#endif	/* USE_TLS_PUSHV */

static inline ssize_t
tls_pull(gnutls_transport_ptr_t ptr, void *buf, size_t size)
{
	struct gnutella_socket *s = ptr;
	ssize_t ret;
	int saved_errno;

	socket_check(s);
	g_assert(is_valid_fd(s->file_desc));

	/*
	 * If there are still pending data in the socket buffer, consume them.
	 *
	 * This can happen after we upgrade a normal connection into a TLS one,
	 * and the TLS handshake data was already read as part of the normal
	 * connection into the socket buffer.
	 *		--RAM, 2015-11-22
	 */

	if G_UNLIKELY(s->pos != 0) {
		size_t avail = s->pos;

		if (GNET_PROPERTY(tls_debug) > 1) {
			g_debug("%s(): host=%s still has %zu buffered byte%s",
				G_STRFUNC, host_addr_port_to_string(s->addr, s->port),
				PLURAL(s->pos));
		}

		avail = MIN(avail, size);	/* Can't read more than they request */
		memcpy(buf, s->buf, avail);
		if (avail != s->pos)
			memmove(s->buf, &s->buf[avail], s->pos - avail);
		s->pos -= avail;
		tls_transport_debug(G_STRFUNC, s, size, avail);

		/*
		 * If there is more buffered data to read, mark the source as
		 * readable because poll() or select() do not know about these
		 * extra bytes that are available.
		 */

		if (s->pos != 0)
			inputevt_set_readable(s->file_desc);

		return avail;
	}

	ret = s_read(s->file_desc, buf, size);
	saved_errno = errno;
	tls_signal_pending(s);
	if ((ssize_t) -1 == ret) {
		tls_set_errno(s, saved_errno);
		if (!is_temporary_error(saved_errno)) {
			socket_connection_reset(s);
		}
	} else if (0 == ret) {
		socket_eof(s);
	}
	tls_transport_debug(G_STRFUNC, s, size, ret);
	errno = saved_errno;
	return ret;
}

static gnutls_dh_params_t
tls_dh_params(void)
{
	static gnutls_dh_params_t dh_params;
	static bool initialized = FALSE;
	int e;
	const char *fn;

#define TRY(function) (fn = (#function)), e = function

	if (!initialized) {
		uint bits = TLS_DH_BITS;

		if (GNET_PROPERTY(tls_debug) > 0)
			g_info("TLS initializing Diffie-Hellman parameters...");

#if HAS_TLS(2, 12)
		/*
		 * GNUTLS_SEC_PARAM_NORMAL became GNUTLS_SEC_PARAM_MEDIUM later but
		 * there is a compatibility remapping.  For the sake of portability,
		 * we stick to GNUTLS_SEC_PARAM_NORMAL.
		 */
		bits = gnutls_sec_param_to_pk_bits(GNUTLS_PK_DH,
			GNUTLS_SEC_PARAM_NORMAL);
#endif

		if (TRY(gnutls_dh_params_init)(&dh_params))
			goto failed;

		if (TRY(gnutls_dh_params_generate2)(dh_params, bits))
			goto failed;

		initialized = TRUE;

		if (GNET_PROPERTY(tls_debug) > 0)
			g_info("TLS computed %u-bit Diffie-Hellman parameters", bits);
	}
	return dh_params;

failed:
	g_warning("%s(): %s() failed: %s", G_STRFUNC, fn, gnutls_strerror(e));
	return NULL;

#undef TRY
}

static void
tls_print_session_info(const host_addr_t addr, uint16 port,
	gnutls_session_t session, bool incoming)
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

	g_debug(
		"TLS session info (%s):\n"
		"    Session:      %p\n"
		"    Host:         %s\n"
		"    Protocol:     %s\n"
		"    Certificate:  %s\n"
		"    Key Exchange: %s\n"
		"    Cipher:       %s\n"
		"    MAC:          %s\n"
		"    Compression:  %s",
		incoming ? "incoming" : "outgoing",
		session, host_addr_port_to_string(addr, port),
		NULL_STRING(proto),
		NULL_STRING(cert),
		NULL_STRING(kx),
		NULL_STRING(ciph),
		NULL_STRING(mac),
		NULL_STRING(comp)
	);
}

#if HAS_TLS(3, 0)
static void
tls_log_audit(gnutls_session_t session, const char *message)
{
	char *dupmsg;

	if (GNET_PROPERTY(tls_debug) < 2)
		return;

	/* Remove trailing "\n" before logging */
	dupmsg = h_strdup(message);
	strchomp(dupmsg, 0);
	g_warning("TLS ALERT for session=%p: %s", session, dupmsg);
	HFREE_NULL(dupmsg);

	if (session != NULL) {
		gnutella_socket_t *s = htable_lookup(tls_sessions, session);
		if (s != NULL) {
			tls_print_session_info(s->addr, s->port, session,
				SOCK_CONN_INCOMING == s->direction);
		} else {
			g_warning("TLS no socket attached to session=%p", session);
		}
	}
}
#endif	/* TLS >= 3.0 */

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
	gnutls_session_t session;
	bool do_warn;
	int ret;

	socket_check(s);

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

	ret = gnutls_handshake(session);
	switch (ret) {
	case 0:
		if (GNET_PROPERTY(tls_debug) > 3) {
			g_debug("%s(): TLS handshake succeeded with %s %s on fd=%d",
				G_STRFUNC,
				SOCK_CONN_INCOMING == s->direction ? "client" : "server",
				host_addr_port_to_string(s->addr, s->port), s->file_desc);
		}
		tls_socket_evt_change(s, SOCK_CONN_INCOMING == s->direction
									? INPUT_EVENT_R : INPUT_EVENT_W);
		if (GNET_PROPERTY(tls_debug > 3)) {
			tls_print_session_info(s->addr, s->port, session,
				SOCK_CONN_INCOMING == s->direction);
		}
		tls_signal_pending(s);
		return TLS_HANDSHAKE_FINISHED;
	case GNUTLS_E_AGAIN:
	case GNUTLS_E_INTERRUPTED:
		tls_socket_evt_change(s, gnutls_record_get_direction(session)
				? INPUT_EVENT_WX : INPUT_EVENT_RX);
		if (GNET_PROPERTY(tls_debug) > 3) {
			g_debug("%s(): TLS handshake still ongoing with %s %s on fd=%d",
				G_STRFUNC,
				SOCK_CONN_INCOMING == s->direction ? "client" : "server",
				host_addr_port_to_string(s->addr, s->port), s->file_desc);
		}
		tls_signal_pending(s);
		return TLS_HANDSHAKE_RETRY;
	case GNUTLS_E_PULL_ERROR:
	case GNUTLS_E_PUSH_ERROR:
		/* Logging already done by tls_transport_debug() */
		break;
	case GNUTLS_E_UNEXPECTED_PACKET_LENGTH:
		if ((SOCK_F_EOF | SOCK_F_CONNRESET) & s->flags) {
		   	/* Remote peer has hung up */
			break;
		}
		/* FALLTHROUGH */
	default:
		if (do_warn && GNET_PROPERTY(tls_debug)) {
			g_carp("%s(): handshake failed: host=%s (%s) error=\"%s\"",
				G_STRFUNC, host_addr_port_to_string(s->addr, s->port),
				SOCK_CONN_INCOMING == s->direction ? "incoming" : "outgoing",
				gnutls_strerror(ret));
		}
	}
	return TLS_HANDSHAKE_ERROR;
}

/**
 * Initiates a new TLS session.
 *
 * @return 0 on success, -1 on error.
 */
int
tls_init(struct gnutella_socket *s)
{
	/**
	 * ANON-DH is enabled because we don't use PKI.
	 * DEFLATE is disabled because it seems to cause crashes.
	 * ARCFOUR-40 is disabled because it is deprecated.
	 */

	static const char prio_want[] = "NORMAL"
#if HAS_TLS(3, 2)
		":+ANON-ECDH"
#endif
		":+ANON-DH"
#if !HAS_TLS(3, 0)
		":-ARCFOUR-40:-COMP-DEFLATE"
#endif
		;

	/* "-COMP-DEFLATE" is causing an error on MinGW with GnuTLS 2.10.2 */
	/* "-ARCFOUR-40"   is causing an error on MinGW with GnuTLS 3.4.5 */
	static const char prio_must[] = "NORMAL"
#if HAS_TLS(3, 2)
		":+ANON-ECDH"
#endif
		":+ANON-DH"
		;

	const bool server = SOCK_CONN_INCOMING == s->direction;
	struct tls_context *ctx;
	const char *fn;
	int e;

#define TRY(function) (fn = (#function)), e = function

	socket_check(s);
	g_assert(NULL == s->tls.ctx);

	WALLOC0(ctx);
	ctx->s = s;
	s->tls.ctx = ctx;

	if (
		TRY(gnutls_init)(&ctx->session, server ? GNUTLS_SERVER : GNUTLS_CLIENT)
	) {
		ctx->session = NULL;
		goto failure;
	}

	if (TRY(gnutls_priority_set_direct)(ctx->session, prio_want, NULL)) {
		const char *error;
		if (TRY(gnutls_priority_set_direct)(ctx->session, prio_must, &error)) {
			g_warning("%s() failed at \"%s\"", fn, error);
			goto failure;
		}
	}

	if (cert_cred_loaded) {
		if (TRY(gnutls_credentials_set)(ctx->session,
				GNUTLS_CRD_CERTIFICATE, cert_cred))
			goto failure;
	}

	/*
	 * This is for the client to inform the handshaking logic about the
	 * minimum amount of bits we expect for the prime number: if the server
	 * sends a prime smaller than this, the TLS handshake will fail.
	 *
	 * This function was deprecated since 3.1.7, so we don't use it starting
	 * with 3.2: the minimum number of bits is automatically derived by the
	 * library using the priority string.
	 */

#if !HAS_TLS(3, 2)
	if (!server)
		gnutls_dh_set_prime_bits(ctx->session, TLS_DH_BITS);
#endif

	gnutls_transport_set_ptr(ctx->session, s);
	gnutls_transport_set_pull_function(ctx->session, tls_pull);

#ifdef USE_TLS_PUSHV
	gnutls_transport_set_vec_push_function(ctx->session, tls_pushv);
#else
	gnutls_transport_set_push_function(ctx->session, tls_push);
#endif	/* USE_TLS_PUSHV */

#if !HAS_TLS(2, 12)
	/*
	 * This routine has been removed starting TLS 3.0.  It was used to disable
	 * the lowat feature, and apparently this is now always the case in recent
	 * TLS versions.	--RAM, 2011-09-28
	 *
	 * It's also flagged as deprecated in 2.12.x, so don't use it there.
	 *		--RAM, 2011-12-15
	 */
	gnutls_transport_set_lowat(ctx->session, 0);
#endif	/* TLS < 2.12 */

	if (server) {
		/*
		 * There's no need to allocate an anonymous server credential
		 * if we already laoded the certificate.
		 */

		if (cert_cred_loaded)
			goto done;

		if (TRY(gnutls_anon_allocate_server_credentials)(&ctx->cred.server))
			goto failure;

		gnutls_anon_set_server_dh_params(ctx->cred.server, tls_dh_params());

		if (TRY(gnutls_credentials_set)(ctx->session,
				GNUTLS_CRD_ANON, ctx->cred.server))
			goto failure;

	} else {
		if (TRY(gnutls_anon_allocate_client_credentials)(&ctx->cred.client))
			goto failure;

		if (TRY(gnutls_credentials_set)(ctx->session,
				GNUTLS_CRD_ANON, ctx->cred.client))
			goto failure;
	}

	/* FALL THROUGH */

done:
	htable_insert(tls_sessions, ctx->session, s);
	return 0;

failure:
	g_warning("%s() failed: %s", EMPTY_STRING(fn), gnutls_strerror(e));
	tls_free(s);
	return -1;
#undef TRY
}

void
tls_free(struct gnutella_socket *s)
{
	tls_context_t ctx;
	const bool server = SOCK_CONN_INCOMING == s->direction;

	socket_check(s);
	ctx = s->tls.ctx;
	if (ctx) {
		if (ctx->session) {
			htable_remove(tls_sessions, ctx->session);
			gnutls_deinit(ctx->session);
		}
		if (server && ctx->cred.server != NULL) {
			gnutls_anon_free_server_credentials(ctx->cred.server);
			ctx->cred.server = NULL;
		}
		if (!server && ctx->cred.client != NULL) {
			gnutls_anon_free_client_credentials(ctx->cred.client);
			ctx->cred.client = NULL;
		}
		WFREE(ctx);
		s->tls.ctx = NULL;
	}
}

static inline void
tls_log_function(int level, const char *text)
{
	if (GNET_PROPERTY(tls_debug) > UNSIGNED(level)) {
		char *str = h_strdup(text);
		strchomp(str, 0);
		g_debug("TLS(%d): %s", level, str);
		hfree(str);
	}
}

void G_COLD
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
	int e;

	if ((e = gnutls_global_init())) {
		g_error("%s(): gnutls_global_init() failed: %s",
			G_STRFUNC, gnutls_strerror(e));
	}

	gnutls_global_set_log_level(9);
	gnutls_global_set_log_function(tls_log_function);

#if HAS_TLS(3, 0)
	gnutls_global_set_audit_log_function(tls_log_audit);
#endif	/* TLS >= 3.0 */

	(void) tls_dh_params();
	gnutls_certificate_allocate_credentials(&cert_cred);

	key_file = make_pathname(settings_config_dir(), tls_keyfile);
	cert_file = make_pathname(settings_config_dir(), tls_certfile);

	if (!file_exists(key_file))
		tls_generate_private_key(key_file);

#if HAS_TLS(2, 12)
	if (!file_exists(cert_file) && file_exists(key_file))
		tls_generate_self_signed_cert(cert_file, key_file);
#endif

	if (file_exists(key_file) && file_exists(cert_file)) {
		e = gnutls_certificate_set_x509_key_file(cert_cred,
				cert_file, key_file, GNUTLS_X509_FMT_PEM);
		if (e) {
			g_warning("%s(): gnutls_certificate_set_x509_key_file() failed: %s",
				G_STRFUNC, gnutls_strerror(e));
			gnutls_certificate_set_dh_params(cert_cred, tls_dh_params());
		} else {
			gnutls_datum_t data = tls_read_filedata(cert_file);
			gnutls_x509_crt_t crt;

			if (
				0 == gnutls_x509_crt_init(&crt) &&
				0 == gnutls_x509_crt_import(crt, &data, GNUTLS_X509_FMT_PEM)
			) {
				tls_cert_log("TLS loaded X.509 certificate: %s",
					crt, GNUTLS_CRT_PRINT_ONELINE);
			}
			gnutls_x509_crt_deinit(crt);
			cert_cred_loaded = TRUE;
		}
	} else {
		gnutls_certificate_set_dh_params(cert_cred, tls_dh_params());
	}

	HFREE_NULL(key_file);
	HFREE_NULL(cert_file);

	header_features_add(FEATURES_CONNECTIONS, f.name, f.major, f.minor);
	header_features_add(FEATURES_G2_CONNECTIONS, f.name, f.major, f.minor);
	header_features_add(FEATURES_DOWNLOADS, f.name, f.major, f.minor);
	header_features_add(FEATURES_UPLOADS, f.name, f.major, f.minor);

	tls_sessions = htable_create(HASH_KEY_SELF, 0);
}

void
tls_global_close(void)
{
	if (cert_cred) {
		gnutls_certificate_free_credentials(cert_cred);
		cert_cred = NULL;
	}
	htable_free_null(&tls_sessions);
	gnutls_global_deinit();
}

static ssize_t
tls_write_intern(struct wrap_io *wio, const void *buf, size_t size)
{
	struct gnutella_socket *s = wio->ctx;
	ssize_t ret;

	g_assert((0 == s->tls.snarf) ^ (NULL == buf));
	g_assert((0 == s->tls.snarf) ^ (0 == size));

	size = tls_adjust_send_size(s, size);
	ret = gnutls_record_send(tls_socket_get_session(s), buf, size);
	if (ret < 0) {
		switch (ret) {
		case GNUTLS_E_INTERRUPTED:
		case GNUTLS_E_AGAIN:
			if (0 == s->tls.snarf) {
				s->tls.snarf = size;
				ret = size;
			} else {
				errno = VAL_EAGAIN;
				ret = -1;
			}
			break;
		case GNUTLS_E_PULL_ERROR:
		case GNUTLS_E_PUSH_ERROR:
			/* Logging already done by tls_transport_debug() */
			errno = (SOCK_F_CONNRESET & s->flags) ? ECONNRESET : EIO;
			ret = -1;
			goto finish;

		default:
			if (GNET_PROPERTY(tls_debug)) {
				g_carp("%s(): gnutls_record_send(fd=%d) failed: "
					"host=%s snarf=%zu error=\"%s\"",
					G_STRFUNC,
					s->file_desc, host_addr_port_to_string(s->addr, s->port),
					s->tls.snarf, gnutls_strerror(ret));
			}
			errno = EIO;
			ret = -1;
			goto finish;
		}
	} else {

		if (s->tls.snarf) {
			g_assert(s->tls.snarf >= (size_t) ret);
			s->tls.snarf -= ret;
			errno = VAL_EAGAIN;
			ret = -1;
			goto finish;
		}
	}

	if (s->tls.snarf) {
		tls_socket_evt_change(s, INPUT_EVENT_WX);
	}

finish:
	g_assert(ret == (ssize_t) -1 || (size_t) ret <= size);
	return ret;
}

static int
tls_flush(struct wrap_io *wio)
{
	struct gnutella_socket *s = wio->ctx;

	socket_check(s);

	if (s->tls.snarf) {
		if (GNET_PROPERTY(tls_debug > 1)) {
			g_debug("%s(): snarf=%zu host=%s fd=%d",
					G_STRFUNC, s->tls.snarf,
					host_addr_port_to_string(s->addr, s->port), s->file_desc);
		}
		(void ) tls_write_intern(wio, NULL, 0);
		if (s->tls.snarf)
			return -1;
	}
	return 0;
}


static ssize_t
tls_write(struct wrap_io *wio, const void *buf, size_t size)
{
	struct gnutella_socket *s = wio->ctx;
	ssize_t ret;

	socket_check(s);
	g_assert(socket_uses_tls(s));
	g_assert(NULL != buf);
	g_assert(size_is_positive(size));

	ret = tls_flush(wio);
	if (0 == ret) {
		ret = tls_write_intern(wio, buf, size);
		if (s->gdk_tag) {
			tls_socket_evt_change(s, INPUT_EVENT_WX);
		}
	}
	g_assert(ret == (ssize_t) -1 || (size_t) ret <= size);
	tls_signal_pending(s);
	return ret;
}

static ssize_t
tls_read(struct wrap_io *wio, void *buf, size_t size)
{
	struct gnutella_socket *s = wio->ctx;
	ssize_t ret;

	socket_check(s);
	g_assert(socket_uses_tls(s));
	g_assert(NULL != buf);
	g_assert(size_is_positive(size));

	if (tls_flush(wio) && !is_temporary_error(errno)) {
		if (GNET_PROPERTY(tls_debug)) {
			g_warning("%s(): tls_flush(fd=%d) error: %m",
				G_STRFUNC, s->file_desc);
		}
		return -1;
	}

	ret = gnutls_record_recv(tls_socket_get_session(s), buf, size);
	if (ret < 0) {
		switch (ret) {
		case GNUTLS_E_INTERRUPTED:
		case GNUTLS_E_AGAIN:
			errno = VAL_EAGAIN;
			break;
		case GNUTLS_E_PULL_ERROR:
		case GNUTLS_E_PUSH_ERROR:
			/* Logging already done by tls_transport_debug() */
			errno = (SOCK_F_CONNRESET & s->flags) ? ECONNRESET : EIO;
			break;
		case GNUTLS_E_UNEXPECTED_PACKET_LENGTH:
			if (SOCK_F_EOF & s->flags) {
			   	/*
				 * Remote peer has hung up.
				 *
				 * This is not exceptional, so we make it appear to upper
				 * layers (who do not necessarily know they're dealing with
				 * a TLS socket) as a regular EOF condition: the read()
				 * operation return 0.
				 */
				ret = 0;
				goto no_error;
			} else if (SOCK_F_CONNRESET & s->flags) {
				errno = ECONNRESET;
				break;
			}
			/* FALLTHROUGH */
		default:
			if (GNET_PROPERTY(tls_debug)) {
				g_carp("%s(): gnutls_record_recv(fd=%d) failed: "
					"host=%s error=\"%s\"",
					G_STRFUNC,
					s->file_desc, host_addr_port_to_string(s->addr, s->port),
					gnutls_strerror(ret));
			}
			errno = EIO;
		}
		ret = -1;
	}

no_error:
	if (s->gdk_tag && 0 == s->tls.snarf) {
		tls_socket_evt_change(s, INPUT_EVENT_RX);
	}
	g_assert(ret == (ssize_t) -1 || (size_t) ret <= size);
	tls_signal_pending(s);
	return ret;
}

static ssize_t
tls_writev(struct wrap_io *wio, const iovec_t *iov, int iovcnt)
{
	struct gnutella_socket *s = wio->ctx;
	ssize_t ret, done;
	int i;

	g_assert(socket_uses_tls(s));
	g_assert(iovcnt > 0);

	done = 0;
	ret = 0;
	for (i = 0; i < iovcnt; i++) {
		const size_t size = iovec_len(&iov[i]);

		ret = tls_write(wio, iovec_base(&iov[i]), size);
		if ((ssize_t) -1 == ret)
			break;
		done += (size_t) ret;
		if (size != (size_t) ret)
			break;
	}
	return done > 0 ? done : ret;
}

static ssize_t
tls_readv(struct wrap_io *wio, iovec_t *iov, int iovcnt)
{
	struct gnutella_socket *s = wio->ctx;
	ssize_t ret, done;
	int i;

	g_assert(socket_uses_tls(s));
	g_assert(iovcnt > 0);

	done = 0;
	ret = 0;
	for (i = 0; i < iovcnt; i++) {
		const size_t size = iovec_len(&iov[i]);

		ret = tls_read(wio, iovec_base(&iov[i]), size);
		if ((ssize_t) -1 == ret)
			break;
		done += (size_t) ret;
		if (size != (size_t) ret)
			break;
	}

	return done > 0 ? done : ret;
}

static ssize_t
tls_no_sendto(struct wrap_io *unused_wio, const gnet_host_t *unused_to,
	const void *unused_buf, size_t unused_size)
{
	(void) unused_wio;
	(void) unused_to;
	(void) unused_buf;
	(void) unused_size;
	g_error("no sendto() routine allowed");
	return -1;
}

void
tls_wio_link(struct gnutella_socket *s)
{
	socket_check(s);

	s->wio.write = tls_write;
	s->wio.read = tls_read;
	s->wio.writev = tls_writev;
	s->wio.readv = tls_readv;
	s->wio.sendto = tls_no_sendto;
	s->wio.flush = tls_flush;
}

void
tls_bye(struct gnutella_socket *s)
{
	int ret;

	socket_check(s);
	g_return_if_fail(s->tls.ctx);
	g_return_if_fail(s->tls.ctx->session);

	if ((SOCK_F_EOF | SOCK_F_SHUTDOWN) & s->flags)
		return;

	if (tls_flush(&s->wio) && GNET_PROPERTY(tls_debug)) {
		g_warning("%s(): tls_flush(fd=%d) failed", G_STRFUNC, s->file_desc);
	}

	ret = gnutls_bye(s->tls.ctx->session,
			SOCK_CONN_INCOMING != s->direction
				? GNUTLS_SHUT_WR : GNUTLS_SHUT_RDWR);

	if (ret < 0) {
		switch (ret) {
		case GNUTLS_E_INTERRUPTED:
		case GNUTLS_E_AGAIN:
			break;
		case GNUTLS_E_PULL_ERROR:
		case GNUTLS_E_PUSH_ERROR:
			/* Logging already done by tls_transport_debug() */
			break;
		default:
			if (GNET_PROPERTY(tls_debug)) {
				g_carp("%s(): gnutls_bye() failed: host=%s error=%m",
					G_STRFUNC,
					host_addr_port_to_string(s->addr, s->port));
			}
		}
	}
}

const char *
tls_version_string(void)
{
	static char buf[128];

	if ('\0' == buf[0]) {
		const char *current = gnutls_check_version(NULL);
		int differ = strcmp(current, LIBGNUTLS_VERSION);

		concat_strings(ARYLEN(buf), "GnuTLS ", current,
			differ ? " (compiled against " : "",
			differ ? LIBGNUTLS_VERSION : "",
			differ ? ")" : "",
			NULL_PTR);
	}
	return buf;
}

bool
tls_enabled(void)
{
	return TRUE;
}

#if 0		/* DISABLED -- no longer using SVN -- RAM, 2013-12-30 */

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
	static bool initialized;
	static gnutls_x509_crt cert;

	if (!initialized) {
		gnutls_datum_t cert_data;
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

bool
svn_release_notification_can_verify(void)
{
	return NULL != svn_release_notify_certificate();
}

static bool
verify_signature(gnutls_x509_crt cert,
	const struct array *input, const struct array *signature)
{
	gnutls_datum_t data, sig;

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
bool
svn_release_notification_verify(uint32 revision, time_t date,
	const struct array *signature)
{
	char rev[12], data[64];
	struct array input;

	uint32_to_string_buf(revision, rev, sizeof rev);
	input.data = (void *) data;
	input.size = concat_strings(data, sizeof data,
					"r", rev,
					"@", uint32_to_string(date),
					NULL_PTR);

	return verify_signature(svn_release_notify_certificate(),
				&input, signature);
}
#endif	/* Disabled SVN signature verification */

#else	/* !HAS_GNUTLS*/

enum tls_handshake_result
tls_handshake(struct gnutella_socket *s)
{
	(void) s;
	return TLS_HANDSHAKE_FINISHED;
}

int
tls_init(struct gnutella_socket *s)
{
	socket_check(s);
	g_assert_not_reached();
	return -1;
}

void
tls_free(struct gnutella_socket *s)
{
	socket_check(s);
	g_assert_not_reached();
}

void
tls_bye(struct gnutella_socket *s)
{
	socket_check(s);
	g_assert_not_reached();
}

void
tls_wio_link(struct gnutella_socket *s)
{
	socket_check(s);
	g_assert_not_reached();
}

void
tls_global_init(void)
{
	/* Nothing to do */
}

void
tls_global_close(void)
{
	/* Nothing to do */
}

const char *
tls_version_string(void)
{
	return NULL;
}

bool
tls_enabled(void)
{
	return FALSE;
}

#endif	/* HAS_GNUTLS */

bool
svn_release_notification_can_verify(void)
{
	return FALSE;
}

bool
svn_release_notification_verify(uint32 revision, time_t date,
	const struct array *signature)
{
	g_return_val_if_fail(signature, FALSE);
	(void) revision;
	(void) date;
	return FALSE;
}

/* vi: set ts=4 sw=4 cindent: */
