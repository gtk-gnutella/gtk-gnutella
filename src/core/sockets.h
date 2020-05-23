/*
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
 *      51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
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
#include "lib/eslist.h"

enum socket_tls_stage {
	SOCK_TLS_NONE			= 0,
	SOCK_TLS_INITIALIZED	= 1,
	SOCK_TLS_ESTABLISHED	= 2
};

struct socket_tls_ctx {
	tls_context_t		 	ctx;
	bool				 	enabled;
	enum socket_tls_stage	stage;
	size_t snarf;			/**< Pending bytes if write failed temporarily. */

	inputevt_cond_t			cb_cond;
	inputevt_handler_t		cb_handler;
	void *					cb_data;
};

struct sockaddr;
struct udpctx;
struct tcpctx;

/*
 * Connection directions.
 */

enum socket_direction {
	SOCK_CONN_INCOMING,
	SOCK_CONN_OUTGOING,
	SOCK_CONN_LISTENING,
	SOCK_CONN_PROXY_OUTGOING
};

typedef enum {
	SOCKET_MAGIC = 0x1fb7ddeb
} socket_magic_t;


typedef struct gnutella_socket {
	socket_magic_t magic;	/**< magic for consistency checks */
	socket_fd_t file_desc;	/**< file descriptor */
	uint32 flags;			/**< operating flags */
	uint gdk_tag;			/**< gdk tag */

	enum socket_direction direction;
	enum socket_type type;
	enum net_type net;

	int adns;				/**< status of ADNS resolution */
	const char *adns_msg;	/**< ADNS error message */

	host_addr_t addr;		/**< IP   of our partner */
	uint16 port;			/**< Port of our partner */

	uint16 local_port;		/**< Port on our side */

	time_t last_update;		/**< Timestamp of last activity on socket */

	struct wrap_io wio;		/**< Wrapped IO object */

	struct socket_tls_ctx tls;

	union {
		struct tcpctx *tcp; 	/**< TCP-specific additional context */
		struct udpctx *udp;		/**< UDP-specific additional context */
	} resource;

	struct getline *getline;	/**< Line reader object */

	size_t pos;			/**< write position in the buffer */
	size_t buf_size;	/**< allocated buffer size */
	char *buf;			/**< buffer to put in the data read */

	unsigned so_rcvbuf;	/**< Configured RX buffer size, 0 if unknown */
	unsigned so_sndbuf;	/**< Configured TX buffer size, 0 if unknown */
} gnutella_socket_t;

/**
 * The UDP data indication callback.
 *
 * @param s				the receiving socket
 * @param data			start of received data (not necessarily s->buf)
 * @param len			length of received data (not necessarily s->pos)
 * @param truncated		whether received datagram was truncated
 *
 * Data is held in s->buf and is s->pos byte-long.
 */
typedef void (*socket_udp_data_ind_t)(const gnutella_socket_t *s,
	const void *data, size_t len, bool truncated);

/**
 * TCP socket callback operations.
 */
struct socket_ops {
	void (*connect_failed)(gnutella_socket_t *s, void *owner, const char *err);
	void (*connected)(gnutella_socket_t *s, void *owner);
	void (*destroy)(gnutella_socket_t *s, void *owner, const char *reason);
};

/**
 * TCP socket context.
 */
struct tcpctx {
	void *owner;				/**< Owner of the socket */
	struct socket_ops *ops;		/**< Operational callbacks */
};

/**
 * UDP socket queued datagrams.
 */
struct udpq {
	host_addr_t addr;			/**< Host sending us the datagram */
	slink_t lnk;				/**< Embedded list link */
	void *buf;					/**< Buffer holding data */
	size_t len;					/**< Length of data */
	time_t queued;				/**< Time at which we read the datagram */
	uint16 port;				/**< Remote UDP sender port */
	uint8 truncated;			/**< Whether data was truncated */
};

/**
 * UDP socket context.
 */
struct udpctx {
	void *socket_addr;					/**< To get reception address */
	socket_udp_data_ind_t data_ind;		/**< Callback on datagram reception */
	struct cevent *queue_ev;			/**< Queue processing event */
	eslist_t queue;						/**< Queued items (read-ahead) */
	size_t queued;						/**< Amount of bytes queued */
};

static inline void
socket_check(const struct gnutella_socket * const s)
{
	g_assert(s != NULL);
	g_assert(SOCKET_MAGIC == s->magic);
}

static inline void
socket_buffer_check(const struct gnutella_socket * const s)
{
	g_assert(s != NULL);
	g_assert(SOCKET_MAGIC == s->magic);
	g_assert((0 == s->buf_size) ^ (NULL != s->buf));
	g_assert(0 == s->pos || s->buf != NULL);
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

static inline bool
socket_with_tls(const struct gnutella_socket *s)
{
	return s->tls.enabled && s->tls.stage >= SOCK_TLS_INITIALIZED;
}

static inline bool
socket_uses_tls(const struct gnutella_socket *s)
{
	return s->tls.enabled && s->tls.stage == SOCK_TLS_ESTABLISHED;
}

static inline bool
socket_is_corked(const struct gnutella_socket *s)
{
	return 0 != (SOCK_F_CORKED & s->flags);
}

/**
 * This verifies whether UDP support is enabled and if the UDP socket
 * has been initialized.
 */
static inline bool
udp_active(void)
{
	return NULL != s_udp_listen || NULL != s_udp_listen6;
}

static inline uint16
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
void socket_connection_reset(struct gnutella_socket *s);
void socket_free_buffer(struct gnutella_socket *s);
void socket_free_null(struct gnutella_socket **s_ptr);
struct gnutella_socket *socket_connect(const host_addr_t, uint16,
		enum socket_type, uint32 flags);
struct gnutella_socket *socket_connect_by_name(
	const char *host, uint16, enum socket_type, uint32 flags);
struct gnutella_socket *socket_tcp_listen(const host_addr_t, uint16);
struct gnutella_socket *socket_udp_listen(const host_addr_t, uint16,
	socket_udp_data_ind_t data_ind);
struct gnutella_socket *socket_local_listen(const char *pathname);
void socket_set_single(struct gnutella_socket *s, bool on);

void socket_attach_ops(gnutella_socket_t *s,
	enum socket_type, struct socket_ops *ops, void *owner);
void socket_detach_ops(gnutella_socket_t *s);
void socket_change_owner(gnutella_socket_t *s, void *owner);
void socket_destroy(struct gnutella_socket *s, const char *reason);

void socket_evt_set(struct gnutella_socket *s,
	inputevt_cond_t cond, inputevt_handler_t handler, void *data);
void socket_evt_clear(struct gnutella_socket *s);

void socket_cork(struct gnutella_socket *s, bool on);
void socket_send_buf(struct gnutella_socket *s, int size, bool shrink);
void socket_recv_buf(struct gnutella_socket *s, int size, bool shrink);
void socket_nodelay(struct gnutella_socket *s, bool on);
void socket_tx_shutdown(struct gnutella_socket *s);
void socket_tos_default(const struct gnutella_socket *s);
void socket_tos_throughput(const struct gnutella_socket *s);
void socket_tos_lowdelay(const struct gnutella_socket *s);
void socket_tos_normal(const struct gnutella_socket *s);
void socket_set_quickack(struct gnutella_socket *s, int val);
bool socket_bad_hostname(struct gnutella_socket *s);
void socket_disable_token(struct gnutella_socket *s);
bool socket_omit_token(struct gnutella_socket *s);
void socket_set_bind_address(const host_addr_t addr);
int socket_evt_fd(struct gnutella_socket *s);
bool socket_is_local(const struct gnutella_socket *s);
bool socket_local_addr(const struct gnutella_socket *s, host_addr_t *ap);
bool socket_udp_is_old(const struct gnutella_socket *s);

void socket_tls_upgrade(struct gnutella_socket *s, notify_fn_t cb, void *arg);

void socket_timer(time_t now);
void socket_shutdowning(void);
void socket_shutdown(void);
void socket_closedown(void);

ssize_t safe_readv(wrap_io_t *wio, iovec_t *iov, int iovcnt);
ssize_t safe_readv_fd(int fd, iovec_t *iov, int iovcnt);
ssize_t safe_writev(wrap_io_t *wio, const iovec_t *iov, int iovcnt);
ssize_t safe_writev_fd(int fd, const iovec_t *iov, int iovcnt);

#endif /* _core_sockets_h_ */

/* vi: set ts=4 sw=4 cindent: */
