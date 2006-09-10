/*
 * $Id$
 *
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
 *      59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
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

#include <glib.h>

#include "lib/tm.h"

struct gnutella_node;
struct pmsg;
struct rnode_info;

/*
 * Public interface
 */

void vmsg_handle(struct gnutella_node *n);
const gchar *vmsg_infostr(gconstpointer data, gint size);

void vmsg_send_messages_supported(struct gnutella_node *n);
void vmsg_send_hops_flow(struct gnutella_node *n, guint8 hops);
void vmsg_send_tcp_connect_back(struct gnutella_node *n, guint16 port);
void vmsg_send_udp_connect_back(struct gnutella_node *n, guint16 port);
void vmsg_send_proxy_req(struct gnutella_node *n, const gchar *muid);
void vmsg_send_qstat_req(struct gnutella_node *n, const gchar *muid);
void vmsg_send_qstat_answer(struct gnutella_node *n, gchar *muid, guint16 hits);
void vmsg_send_proxy_cancel(struct gnutella_node *n);
void vmsg_send_oob_reply_ack(struct gnutella_node *n, gchar *muid, guint8 want);
void vmsg_send_time_sync_req(struct gnutella_node *n, gboolean ntp, tm_t *);
void vmsg_send_time_sync_reply(struct gnutella_node *n, gboolean ntp, tm_t *);
void vmsg_send_udp_crawler_pong(struct gnutella_node *n, struct pmsg *mb);
void vmsg_send_node_info_ans(struct gnutella_node *n,
	const struct rnode_info *ri);

struct pmsg *vmsg_build_oob_reply_ind(gchar *muid, guint8 hits);

void vmsg_init(void);

#endif	/* _core_vmsg_h_ */

/* vi: set ts=4 sw=4 cindent: */
