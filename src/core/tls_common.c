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

RCSID("$Id$");

#include "tls_common.h"
#include "features.h"

#include "if/gnet_property_priv.h"

#include "lib/header.h"

#include "lib/override.h"		/* Must be the last header included */

/**
 * Performs a TLS handshake.
 *
 * @param session A TLS session pointer returned from tls_init().
 * @return -1 on failure;
 *			0 if the handshake is still incomplete;
 *			1 if the handshake succeeded.
 */
int 
tls_handshake(tls_session_t session)
{
	static char success[] = "success";
	int ret;

	g_assert(session);
	
	if (gnutls_session_get_ptr(session) == &success)
		return 1;

	ret = gnutls_handshake(session);
	switch (ret) {
	case 0:
		if (tls_debug) {
			g_message("TLS handshake succeeded");
		}
		gnutls_session_set_ptr(session, &success);
		return 1;
	case GNUTLS_E_AGAIN:
	case GNUTLS_E_INTERRUPTED:
		return 0;
	}
	if (tls_debug) {
		g_warning("gnutls_handshake() failed: %s",
				gnutls_strerror(ret));
	}
	return -1;
}

/**
 * Initiates a new TLS session.
 *
 * @param is_incoming Whether this is an incoming connection.
 * @return The session pointer on success; NULL on failure.
 */
tls_session_t
tls_init(gboolean is_incoming)
{
	static const int cipher_list[] = {
		GNUTLS_CIPHER_AES_256_CBC, GNUTLS_CIPHER_AES_128_CBC,
		0
	};
	static const int kx_list[] = {
		GNUTLS_KX_ANON_DH,
		0
	};
	static const int mac_list[] = {
		GNUTLS_MAC_MD5, GNUTLS_MAC_SHA, GNUTLS_MAC_RMD160,
		0
	};
	static const int comp_list[] = {
		GNUTLS_COMP_DEFLATE, GNUTLS_COMP_NULL,
		0
	};
	gnutls_anon_server_credentials server_cred;
	gnutls_anon_client_credentials client_cred;
	gnutls_session_t session;
	void *cred;

	if (is_incoming) {

		if (gnutls_anon_allocate_server_credentials(&server_cred)) {
			g_warning("gnutls_anon_allocate_server_credentials() failed");
			return NULL;
		}

		gnutls_anon_set_server_dh_params(server_cred, get_dh_params());
		cred = server_cred;

		if (gnutls_init(&session, GNUTLS_SERVER)) {
			g_warning("gnutls_init() failed");
			return NULL;
		}
		gnutls_dh_set_prime_bits(session, TLS_DH_BITS);

	} else {
		if (gnutls_anon_allocate_client_credentials(&client_cred)) {
			g_warning("gnutls_anon_allocate_client_credentials() failed");
			return NULL;
		}
		cred = client_cred;

		if (gnutls_init(&session, GNUTLS_CLIENT)) {
			g_warning("gnutls_init() failed");
			return NULL;
		}
	}

	if (gnutls_credentials_set(session, GNUTLS_CRD_ANON, cred)) {
		g_warning("gnutls_credentials_set() failed");
		return NULL;
	}

	gnutls_set_default_priority(session);
	if (gnutls_cipher_set_priority(session, cipher_list)) {
		g_warning("gnutls_cipher_set_priority() failed");
		return NULL;
	}
	if (gnutls_kx_set_priority(session, kx_list)) {
		g_warning("gnutls_kx_set_priority() failed");
		return NULL;
	}
	if (gnutls_mac_set_priority(session, mac_list)) {
		g_warning("gnutls_mac_set_priority() failed");
		return NULL;
	}
	if (gnutls_compression_set_priority(session, comp_list)) {
		g_warning("gnutls_mac_set_priority() failed");
		return NULL;
	}

	return session;
}

gnutls_dh_params_t
get_dh_params(void)
{
	static gnutls_dh_params_t dh_params;
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

void
tls_global_init(void)
{
#ifdef HAS_GNUTLS
	static const struct {
		const gchar * const name;
		const gint major;
		const gint minor;
	} f = {
		"tls", 1, 0
	};

	if (gnutls_global_init()) {
		g_error("socket_init(): gnutls_global_init() failed");
	}
	get_dh_params();
	header_features_add(&xfeatures.connections, f.name, f.major, f.minor);
	header_features_add(&xfeatures.downloads, f.name, f.major, f.minor);
	header_features_add(&xfeatures.uploads, f.name, f.major, f.minor);
#endif /* HAS_GNUTLS */
}

/* vi: set ts=4 sw=4 cindent: */
