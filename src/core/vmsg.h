/*
 * Copyright (c) 2003, Raphael Manfredi
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
 * Vendor-specific messages.
 *
 * @author Raphael Manfredi
 * @date 2003
 */

#ifndef _core_vmsg_h_
#define _core_vmsg_h_

#include "common.h"

#include "lib/tm.h"

struct array;
struct gnutella_node;
struct guid;
struct pmsg;
struct rnode_info;

/**
 * Send completion callback for a vendor message.
 *
 * @param n		the target to which message was directed to (NULL if node gone)
 * @param sent	whether message was sent or dropped
 * @param arg	user-supplied argument
 */
typedef void (*vmsg_sent_t)(struct gnutella_node *n, bool sent, void *arg);

/*
 * Public interface
 */

void vmsg_handle(struct gnutella_node *n);
const char *vmsg_infostr(const void *data, size_t size);

void vmsg_send_messages_supported(struct gnutella_node *n);
void vmsg_send_features_supported(struct gnutella_node *n);
void vmsg_send_hops_flow(struct gnutella_node *n, uint8 hops,
	vmsg_sent_t sent, void *arg);
void vmsg_send_tcp_connect_back(struct gnutella_node *n, uint16 port);
void vmsg_send_udp_connect_back(struct gnutella_node *n, uint16 port);
void vmsg_send_proxy_req(struct gnutella_node *n, const struct guid *muid);
void vmsg_send_qstat_req(struct gnutella_node *n, const struct guid *muid);
void vmsg_send_qstat_answer(struct gnutella_node *n,
		const struct guid *muid, uint16 hits);
void vmsg_send_proxy_cancel(struct gnutella_node *n);
void vmsg_send_oob_reply_ack(struct gnutella_node *n,
		const struct guid *muid, uint8 want, const struct array *token);
void vmsg_send_time_sync_req(struct gnutella_node *n, bool ntp, tm_t *);
void vmsg_send_time_sync_reply(struct gnutella_node *n, bool ntp, tm_t *);
void vmsg_send_udp_crawler_pong(struct gnutella_node *n, struct pmsg *mb);
void vmsg_send_node_info_ans(struct gnutella_node *n,
	const struct rnode_info *ri);
void vmsg_send_head_ping(const struct sha1 *sha1,
		host_addr_t addr, uint16 port, const struct guid *guid);

struct pmsg *vmsg_build_oob_reply_ind(const struct guid *muid,
				uint8 hits, bool secure);

uint8 vmsg_weight(const void *data);

void vmsg_init(void);
void vmsg_close(void);

#endif	/* _core_vmsg_h_ */

/* vi: set ts=4 sw=4 cindent: */
