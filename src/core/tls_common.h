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

#include "common.h"

#define TLS_DH_BITS 768

#include "if/core/wrap.h"			/* For wrap_io_t */

enum tls_handshake_result {
	TLS_HANDSHAKE_FINISHED,
	TLS_HANDSHAKE_RETRY,
	TLS_HANDSHAKE_ERROR
};

struct gnutella_socket;
struct tls_context;

typedef struct tls_context *tls_context_t;

int tls_init(struct gnutella_socket *);
enum tls_handshake_result tls_handshake(struct gnutella_socket *);
void tls_bye(struct gnutella_socket *);
void tls_free(struct gnutella_socket *);
void tls_wio_link(struct gnutella_socket *);

gboolean tls_enabled(void);
void tls_global_init(void);
const gchar *tls_version_string(void);

struct array;

gboolean svn_release_notification_can_verify(void);
gboolean svn_release_notification_verify(guint32 revision, time_t date,
	const struct array *signature);

#endif /* _core_tls_common_h_ */
/* vi: set ts=4 sw=4 cindent: */
