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

#ifndef _core_sockets_h_
#define _core_sockets_h_

#include "common.h"

#include "if/core/wrap.h"			/* wrap_io_t */
#include "if/core/sockets.h"

#ifdef USE_TLS
#include <gnutls/gnutls.h>

enum socket_tls_stage {
	SOCK_TLS_NONE			= 0,
	SOCK_TLS_INITIALIZED	= 1,
	SOCK_TLS_ESTABLISHED	= 2
};

struct socket_tls_ctx {
	gnutls_session		 	session;
	gboolean			 	enabled;
	enum socket_tls_stage	stage;
	size_t snarf;			/**< Pending bytes if write failed temporarily. */
};

#define SOCKET_USES_TLS(s) \
	((s)->tls.enabled && (s)->tls.stage >= SOCK_TLS_ESTABLISHED)
#else /* !USE_TLS */
#define SOCKET_USES_TLS(s) 0
#endif /* USE_TLS */

struct sockaddr;

/*
 * Connection directions.
 */

enum socket_direction {
	SOCK_CONN_INCOMING,
	SOCK_CONN_OUTGOING,
	SOCK_CONN_LISTENING,
	SOCK_CONN_PROXY_OUTGOING,
};

/*
 * Connection types.
 */

enum socket_type {
	SOCK_TYPE_UNKNOWN = 0,
	SOCK_TYPE_CONTROL,
	SOCK_TYPE_DOWNLOAD,
	SOCK_TYPE_UPLOAD,
	SOCK_TYPE_HTTP,
    SOCK_TYPE_SHELL,
    SOCK_TYPE_CONNBACK,
    SOCK_TYPE_PPROXY,
    SOCK_TYPE_DESTROYING,
	SOCK_TYPE_UDP,
};

struct gnutella_socket {
	gint file_desc;			/* file descriptor */
	guint32 flags;			/* operating flags */
	guint gdk_tag;			/* gdk tag */

	enum socket_direction direction;
	enum socket_type type;
	gboolean corked;
	gint adns;				/* status of ADNS resolution */
	gchar *adns_msg;		/* ADNS error message */

	guint32 ip;				/* IP	of our partner */
	guint16 port;			/* Port of our partner */

	guint16 local_port;		/* Port on our side */

	time_t last_update;		/* Timestamp of last activity on socket */
	
	struct wrap_io wio;		/**< Wrapped IO object */
	
#ifdef USE_TLS
	struct socket_tls_ctx tls;
#endif

	union {
		struct gnutella_node *node;
		struct download *download;
		struct upload *upload;
		struct pproxy *pproxy;
		struct cproxy *cproxy;
		gpointer handle;
	} resource;

	struct getline *getline;	/* Line reader object */

	gchar buffer[SOCK_BUFSZ];	/* buffer to put in the data read */
	size_t pos;			/* write position in the buffer */
};

/*
 * Operating flags
 */

#define SOCK_F_ESTABLISHED		0x00000001 /* Connection was established */
#define SOCK_F_EOF				0x00000002 /* Got an EOF condition */
#define SOCK_F_UDP				0x40000000 /* Is a UDP socket */
#define SOCK_F_TCP				0x80000000 /* Is a TCP socket */

/*
 * Access macros
 */

#define sock_is_corked(x)		((x)->corked)

/*
 * Global Data
 */

extern struct gnutella_socket *s_tcp_listen;
extern struct gnutella_socket *s_udp_listen;

/*
 * Global Functions
 */

void socket_init(void);
void socket_register_fd_reclaimer(reclaim_fd_t callback);
void socket_eof(struct gnutella_socket *s);
void socket_free(struct gnutella_socket *);
struct gnutella_socket *socket_connect(guint32, guint16, enum socket_type);
struct gnutella_socket *socket_connect_by_name(
	const gchar *host, guint16, enum socket_type);
struct gnutella_socket *socket_tcp_listen(guint32, guint16, enum socket_type);
struct gnutella_socket *socket_udp_listen(guint32, guint16);

void sock_cork(struct gnutella_socket *s, gboolean on);
void sock_send_buf(struct gnutella_socket *s, gint size, gboolean shrink);
void sock_recv_buf(struct gnutella_socket *s, gint size, gboolean shrink);
void sock_nodelay(struct gnutella_socket *s, gboolean on);
void sock_tx_shutdown(struct gnutella_socket *s);
void socket_tos_default(struct gnutella_socket *s);
void socket_tos_throughput(struct gnutella_socket *s);
void socket_tos_lowdelay(struct gnutella_socket *s);
void socket_tos_normal(struct gnutella_socket *s);
gboolean socket_bad_hostname(struct gnutella_socket *s);

int connect_http(struct gnutella_socket *);
int connect_socksv5(struct gnutella_socket *);
int proxy_connect(int, const struct sockaddr *, guint);
int recv_socks(struct gnutella_socket *);
int send_socks(struct gnutella_socket *);

void socket_timer(time_t now);
void socket_shutdown(void);

#endif /* _core_sockets_h_ */

/* vi: set ts=4 sw=4 cindent: */
