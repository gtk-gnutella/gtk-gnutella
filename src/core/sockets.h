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
 * @author Raphael Manfredi
 * @date 2001-2003
 * @author Daniel Walker (dwalker@cats.ucsc.edu)
 * @date 2000
 */

#ifndef _core_sockets_h_
#define _core_sockets_h_

#include "common.h"

#include "tls_common.h"

#include "if/core/wrap.h"			/* For wrap_io_t */
#include "if/core/sockets.h"

#include "lib/inputevt.h"

enum socket_tls_stage {
	SOCK_TLS_NONE			= 0,
	SOCK_TLS_INITIALIZED	= 1,
	SOCK_TLS_ESTABLISHED	= 2
};

struct socket_tls_ctx {
	tls_context_t		 	ctx;
	gboolean			 	enabled;
	enum socket_tls_stage	stage;
	size_t snarf;			/**< Pending bytes if write failed temporarily. */
	
	inputevt_cond_t			cb_cond;
	inputevt_handler_t		cb_handler;
	gpointer				cb_data;
};

struct sockaddr;

/*
 * Connection directions.
 */

enum socket_direction {
	SOCK_CONN_INCOMING,
	SOCK_CONN_OUTGOING,
	SOCK_CONN_LISTENING,
	SOCK_CONN_PROXY_OUTGOING
};

/**
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
	SOCK_TYPE_UDP
};

typedef enum {
	SOCKET_MAGIC = 0x1fb7ddeb
} socket_magic_t;

struct gnutella_socket {
	socket_magic_t magic;	/**< magic for consistency checks */
	gint file_desc;			/**< file descriptor */
	guint32 flags;			/**< operating flags */
	guint gdk_tag;			/**< gdk tag */

	enum socket_direction direction;
	enum socket_type type;
	enum net_type net;
	gboolean omit_token;	/**< TRUE if the connection needs no token */
	gboolean corked;
	gboolean was_shutdown;	/**< Set if shutdown() was used */
	gint adns;				/**< status of ADNS resolution */
	gchar *adns_msg;		/**< ADNS error message */

	host_addr_t addr;		/**< IP   of our partner */
	guint16 port;			/**< Port of our partner */

	guint16 local_port;		/**< Port on our side */

	time_t last_update;		/**< Timestamp of last activity on socket */

	struct wrap_io wio;		/**< Wrapped IO object */

#ifdef HAS_GNUTLS
	struct socket_tls_ctx tls;
#endif /* HAS_GNUTLS */

	union {
		struct gnutella_node *node;
		struct download *download;
		struct upload *upload;
		struct pproxy *pproxy;
		struct cproxy *cproxy;
		gpointer handle;
	} resource;

	struct getline *getline;	/**< Line reader object */

	size_t pos;			/**< write position in the buffer */
	size_t buf_size;	/**< write position in the buffer */
	gchar *buf;			/**< buffer to put in the data read */
};

static inline void
socket_check(const struct gnutella_socket * const s)
{
	g_assert(s);
	g_assert(SOCKET_MAGIC == s->magic);
}

/*
 * Global Data
 */

extern struct gnutella_socket *s_tcp_listen;
extern struct gnutella_socket *s_tcp_listen6;
extern struct gnutella_socket *s_udp_listen;
extern struct gnutella_socket *s_udp_listen6;
extern struct gnutella_socket *s_local_listen;


/**
 * Accessors.
 */

#ifdef HAS_GNUTLS
static inline gboolean
SOCKET_WITH_TLS(struct gnutella_socket *s)
{
	return s->tls.enabled && s->tls.stage >= SOCK_TLS_INITIALIZED;
}

static inline gboolean
SOCKET_USES_TLS(struct gnutella_socket *s)
{
	return s->tls.enabled && s->tls.stage >= SOCK_TLS_ESTABLISHED;
}
#else
#define SOCKET_WITH_TLS(s) FALSE
#define SOCKET_USES_TLS(s) FALSE
#endif	/* HAS_GNUTLS */


static inline gboolean
sock_is_corked(const struct gnutella_socket *s)
{
	return s->corked;
}

/**
 * This verifies whether UDP support is enabled and if the UDP socket
 * has been initialized.
 */
static inline gboolean
udp_active(void)
{
	return NULL != s_udp_listen || NULL != s_udp_listen6;
}

static inline guint16
socket_listen_port(void)
{
	if (s_tcp_listen)
		return s_tcp_listen->local_port;
	if (s_tcp_listen6)
		return s_tcp_listen6->local_port;
	return 0;
}

/*
 * Global Functions
 */

void socket_init(void);
void socket_register_fd_reclaimer(reclaim_fd_t callback);
void socket_eof(struct gnutella_socket *s);
void socket_free_null(struct gnutella_socket **s_ptr);
struct gnutella_socket *socket_connect(const host_addr_t, guint16,
		enum socket_type, guint32 flags);
struct gnutella_socket *socket_connect_by_name(
	const gchar *host, guint16, enum socket_type, guint32 flags);
struct gnutella_socket *socket_tcp_listen(const host_addr_t, guint16);
struct gnutella_socket *socket_udp_listen(const host_addr_t, guint16);
struct gnutella_socket *socket_local_listen(const gchar *pathname);

void socket_evt_set(struct gnutella_socket *s,
	inputevt_cond_t cond, inputevt_handler_t handler, gpointer data);
void socket_evt_clear(struct gnutella_socket *s);

void sock_cork(struct gnutella_socket *s, gboolean on);
void sock_send_buf(struct gnutella_socket *s, gint size, gboolean shrink);
void sock_recv_buf(struct gnutella_socket *s, gint size, gboolean shrink);
void sock_nodelay(struct gnutella_socket *s, gboolean on);
void sock_tx_shutdown(struct gnutella_socket *s);
void socket_tos_default(const struct gnutella_socket *s);
void socket_tos_throughput(const struct gnutella_socket *s);
void socket_tos_lowdelay(const struct gnutella_socket *s);
void socket_tos_normal(const struct gnutella_socket *s);
gboolean socket_bad_hostname(struct gnutella_socket *s);
void socket_disable_token(struct gnutella_socket *s);
gboolean socket_omit_token(struct gnutella_socket *s);
void socket_set_bind_address(const host_addr_t addr);
gint socket_evt_fd(struct gnutella_socket *s);
gboolean socket_is_local(const struct gnutella_socket *s);

void socket_timer(time_t now);
void socket_shutdown(void);

ssize_t safe_readv(wrap_io_t *wio, struct iovec *iov, gint iovcnt);
ssize_t safe_readv_fd(gint fd, struct iovec *iov, gint iovcnt);
ssize_t safe_writev(wrap_io_t *wio, const struct iovec *iov, gint iovcnt);
ssize_t safe_writev_fd(gint fd, const struct iovec *iov, gint iovcnt);

#endif /* _core_sockets_h_ */

/* vi: set ts=4 sw=4 cindent: */
