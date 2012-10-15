/*
 * Copyright (c) 2004, Raphael Manfredi
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
 * Handling of UDP datagrams.
 *
 * @author Raphael Manfredi
 * @date 2004
 */

#ifndef _core_udp_h_
#define _core_udp_h_

#include "common.h"
#include "gnutella.h"

#include "lib/host_addr.h"

/**
 * UDP Ping replies.
 */
enum udp_ping_ret {
	UDP_PING_TIMEDOUT = 0,		/**< timed out */
	UDP_PING_EXPIRED,			/**< expired, but got replies previously */
	UDP_PING_REPLY				/**< got a reply from host */
};

enum udp_pong_status {
	UDP_PONG_UNSOLICITED,		/**< no registered ping */
	UDP_PONG_SOLICITED,			/**< solicited pong, no callback attached */
	UDP_PONG_HANDLED			/**< solicited pong, handled through callback */
};

struct gnutella_node;

/**
 * UDP Pong reception callback (installed for registered ping).
 *
 * @param type		type of reply, if any
 * @param n			gnutella node replying (NULL if no reply)
 * @param data		user-supplied callback data
 */
typedef void (*udp_ping_cb_t)(enum udp_ping_ret type,
	const struct gnutella_node *n, void *data);

/**
 * Known semi-reliable UDP protocol types.
 */
enum udp_sr_tag {
	UDP_SR_GTA,
	UDP_SR_GND
};

/*
 * Public interface.
 */

struct gnutella_socket;
struct gnutella_node;
struct guid;
struct pmsg;
struct rxdriver;

void udp_received(struct gnutella_socket *s, bool truncated);
void udp_connect_back(const host_addr_t addr, uint16 port,
	const struct guid *muid);
void udp_send_msg(const struct gnutella_node *n, const void *buf, int len);
void udp_ctrl_send_msg(const struct gnutella_node *n, const void *buf, int len);
bool udp_send_ping(const struct guid *muid,
	const host_addr_t addr, uint16 port, bool uhc_ping);
bool udp_send_ping_callback(gnutella_msg_init_t *m, uint32 size,
	const host_addr_t addr, uint16 port,
	udp_ping_cb_t cb, void *arg, bool multiple);
void udp_send_mb(const struct gnutella_node *n, struct pmsg *mb);
void udp_dht_send_mb(const struct gnutella_node *n, struct pmsg *mb);
enum udp_pong_status udp_ping_is_registered(const struct gnutella_node *n);

bool udp_is_valid_gnet_split(struct gnutella_node *n,
	const struct gnutella_socket *s,
	bool truncated, const void *header, const void *payload, size_t len);

void udp_set_rx_semi_reliable(enum udp_sr_tag tag,
	struct rxdriver *rx, enum net_type net);

void udp_init(void);
void udp_close(void);

#endif /* _core_udp_h_ */

