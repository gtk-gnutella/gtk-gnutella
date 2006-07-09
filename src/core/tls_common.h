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
 * TLS common functions.
 */

#ifndef _core_tls_common_h_
#define _core_tls_common_h_

#include <gnutls/gnutls.h>

#define TLS_DH_BITS 768

typedef void *tls_session_t;

tls_session_t tls_init(gboolean is_incoming);
int tls_handshake(tls_session_t session);

void tls_global_init(void);
gnutls_dh_params_t get_dh_params(void);

#endif /* _core_tls_common_h_ */
