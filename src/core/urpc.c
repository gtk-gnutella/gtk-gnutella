/*
 * Copyright (c) 2010, Raphael Manfredi
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
 * UDP Remote Procedure Call support.
 *
 * @author Raphael Manfredi
 * @date 2010
 */

#include "common.h"

#include "urpc.h"
#include "sockets.h"
#include "inet.h"

#include "if/gnet_property_priv.h"

#include "lib/cq.h"
#include "lib/gnet_host.h"
#include "lib/host_addr.h"
#include "lib/walloc.h"
#include "lib/override.h"		/* Must be the last header included */

enum urpc_cb_magic { URPC_CB_MAGIC = 0x790f55e5U };

/**
 * An UDP RPC callback descriptor.
 */
struct urpc_cb {
	enum urpc_cb_magic magic;	/**< magic */
	host_addr_t addr;			/**< The host to which we sent the request */
	const char *what;			/**< Type of RPC (static string) */
	urpc_cb_t cb;				/**< The callback */
	void *arg;					/**< The user-defined callback parameter */
	struct gnutella_socket *s;	/**< The socket used to send/receive */
	cevent_t *timeout_ev;		/**< Callout queue timeout event */
	guint16 port;				/**< The port to which we sent the request */
};

static inline void
urpc_cb_check(const struct urpc_cb * const ucb)
{
	g_assert(ucb != NULL);
	g_assert(URPC_CB_MAGIC == ucb->magic);
	g_assert(ucb->cb != NULL);
	g_assert(ucb->s != NULL);
}

static GHashTable *pending;		/**< Pending RPCs (socket -> urcp_cb) */

/**
 * Free the callback waiting indication.
 */
static void
urpc_cb_free(struct urpc_cb *ucb, gboolean in_shutdown)
{
	urpc_cb_check(ucb);

	if (in_shutdown) {
		(*ucb->cb)(URPC_TIMEOUT, ucb->addr, ucb->port, NULL, 0, ucb->arg);
	} else {
		g_hash_table_remove(pending, ucb->s);
	}

	cq_cancel(&ucb->timeout_ev);
	socket_free_null(&ucb->s);
	ucb->magic = 0;
	WFREE(ucb);
}

/**
 * Notification from the socket layer that we got a new datagram.
 * If `truncated' is true, then the message was too large for the
 * socket buffer.
 */
static void
urpc_received(struct gnutella_socket *s, gboolean truncated)
{
	struct urpc_cb *ucb;

	inet_udp_got_incoming(s->addr);

	ucb = g_hash_table_lookup(pending, s);

	if (NULL == ucb) {
		g_warning("UDP got unexpected %s%lu-byte RPC reply from %s",
			truncated ? "truncated " : "", (unsigned long) s->pos,
			host_addr_port_to_string(s->addr, s->port));
		return;
	}

	if (GNET_PROPERTY(udp_debug) > 1) {
		g_debug("UDP [%s] got %s%lu-byte RPC reply from %s",
			ucb->what, truncated ? "truncated " : "", (unsigned long) s->pos,
			host_addr_port_to_string(s->addr, s->port));
	}

	/*
	 * Invoke user callback so that reply can be processed.
	 * Then discard the socket.
	 */

	(*ucb->cb)(URPC_REPLY, s->addr, s->port, s->buf, s->pos, ucb->arg);
	urpc_cb_free(ucb, FALSE);
}

/**
 * RPC timed out.
 */
static void
urpc_timed_out(cqueue_t *unused_cq, gpointer obj)
{
	struct urpc_cb *ucb = obj;

	urpc_cb_check(ucb);
	(void) unused_cq;

	ucb->timeout_ev = NULL;

	if (GNET_PROPERTY(udp_debug)) {
		g_message("UDP [%s] RPC to %s timed out",
			ucb->what, host_addr_port_to_string(ucb->addr, ucb->port));
	}

	(*ucb->cb)(URPC_TIMEOUT, ucb->addr, ucb->port, NULL, 0, ucb->arg);
	urpc_cb_free(ucb, FALSE);
}

/**
 * Initiate an UDP RPC transaction.
 *
 * The message held in ``data'' is sent to the specified address and port.
 * Upon reception of a reply from that host, the callback is invoked.
 * If no reply is received after some time, the callaback is also invoked.
 *
 * @param what		type of RPC, for logging (static string)
 * @param addr		address where RPC should be sent to
 * @param port		port where RPC should be sent to
 * @param data		message data to send
 * @param len		length of data to send
 * @param timeout	timeout in milliseconds to get a reply
 * @param cb		callback to invoke on reply or timeout
 * @param arg		additionnal callback argument
 *
 * @return 0 if OK, -1 if we could not initiate the RPC, with errno set.
 */
int
urpc_send(const char *what,
	host_addr_t addr, guint16 port, const void *data, size_t len,
	unsigned long timeout, urpc_cb_t cb, void *arg)
{
	struct urpc_cb *ucb;
	struct gnutella_socket *s;
	host_addr_t bind_addr = zero_host_addr;
	gnet_host_t to;
	ssize_t r;

	/*
	 * Create anonymous socket to send/receive the RPC.
	 */

	switch (host_addr_net(addr)) {
	case NET_TYPE_IPV4:
		bind_addr = ipv4_unspecified;
		break;
	case NET_TYPE_IPV6:
		bind_addr = ipv6_unspecified;
		break;
	case NET_TYPE_LOCAL:
	case NET_TYPE_NONE:
		g_assert_not_reached();
	}

	s = socket_udp_listen(bind_addr, 0, urpc_received);
	if (NULL == s) {
		if (GNET_PROPERTY(udp_debug)) {
			g_warning("unable to create anonymous UDP %s socket for %s RPC: %s",
				net_type_to_string(host_addr_net(bind_addr)),
				what, g_strerror(errno));
		}
		return -1;
	}

	/*
	 * Send the message.
	 */

	gnet_host_set(&to, addr, port);
	r = (s->wio.sendto)(&s->wio, &to, data, len);

	/*
	 * Reset errno if there was no "real" error to prevent getting a
	 * bogus and possibly misleading error message later.
	 */

	if ((ssize_t) -1 == r) {
		if (GNET_PROPERTY(udp_debug)) {
			g_warning("unable to send UDP %s RPC to %s: %s",
				what, host_addr_port_to_string(addr, port), g_strerror(errno));
		}
	} else {
		errno = 0;
	}

	if (len != UNSIGNED(r)) {
		if ((ssize_t) -1 != r) {
			if (GNET_PROPERTY(udp_debug)) {
				g_warning("unable to send whole %lu-byte UDP %s RPC to %s: "
					"only sent %lu byte%s",
					(unsigned long) len, what,
					host_addr_port_to_string(addr, port),
					(unsigned long) r, 1 == r ? "" : "s");
			}
		}
		socket_free_null(&s);
		return -1;
	}

	/*
	 * Make sure socket_udp_event() will only process replies one at a time
	 * since we're going to close the anonymous UDP socket as soon as we
	 * get a reply.
	 */

	socket_set_single(s, TRUE);

	/*
	 * Message was sent, wait for the answer.
	 */

	WALLOC(ucb);
	ucb->magic = URPC_CB_MAGIC;
	ucb->addr = addr;
	ucb->port = port;
	ucb->s = s;
	ucb->cb = cb;
	ucb->arg = arg;
	ucb->timeout_ev = cq_main_insert(timeout, urpc_timed_out, ucb);
	ucb->what = what;

	g_hash_table_insert(pending, s, ucb);

	return 0;
}

/**
 * Do we have pending UDP RPCs?
 */
gboolean
urpc_pending(void)
{
	return 0 != g_hash_table_size(pending);
}

/**
 * Initialize the UDP RPC layer.
 */
void
urpc_init(void)
{
	pending = g_hash_table_new(pointer_hash_func, NULL);
}

static void
urpc_free_kv(gpointer unused_key, gpointer val, gpointer unused_x)
{
	(void) unused_key;
	(void) unused_x;

	urpc_cb_free(val, TRUE);
}

/*
 * Shutdown the UDP RPC layer.
 */
void
urpc_close(void)
{
	g_hash_table_foreach(pending, urpc_free_kv, NULL);
	gm_hash_table_destroy_null(&pending);
}

/* vi: set ts=4 sw=4 cindent: */
