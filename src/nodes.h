/*
 * $Id$
 *
 * Copyright (c) 2001-2003, Raphael Manfredi
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

#ifndef _nodes_h_
#define _nodes_h_

#include "gnutella.h"
#include "mq.h"
#include "sq.h"
#include "rx.h"
#include "qrp.h"
#include "hsep.h"

#include "ui_core_interface_nodes_defs.h"

extern GHookList node_added_hook_list;
extern struct gnutella_node *node_added;

/*
 * Global Functions
 */

void node_init(void);
void node_slow_timer(time_t now);
void node_timer(time_t now);
guint connected_nodes(void);
guint node_count(void);
gint node_keep_missing(void);
gint node_missing(void);
guint node_outdegree(void);
gboolean node_is_connected(guint32 ip, guint16 port, gboolean incoming);
gboolean node_host_is_connected(guint32 ip, guint16 port);
void node_add_socket(struct gnutella_socket *s, guint32 ip, guint16 port);
void node_remove(struct gnutella_node *,
	const gchar * reason, ...) G_GNUC_PRINTF(2, 3);
void node_bye(gnutella_node_t *, gint code,
	const gchar * reason, ...) G_GNUC_PRINTF(3, 4);
void node_real_remove(gnutella_node_t *);
void node_eof(struct gnutella_node *n,
	const gchar * reason, ...) G_GNUC_PRINTF(2, 3);
void node_shutdown(struct gnutella_node *n,
	const gchar * reason, ...) G_GNUC_PRINTF(2, 3);
void node_bye_if_writable(struct gnutella_node *n, gint code,
	const gchar * reason, ...) G_GNUC_PRINTF(3, 4);
void node_init_outgoing(struct gnutella_node *);
void node_sent_ttl0(struct gnutella_node *n);
void node_disableq(struct gnutella_node *n);
void node_enableq(struct gnutella_node *n);
void node_flushq(struct gnutella_node *n);
void node_tx_service(struct gnutella_node *n, gboolean on);
void node_tx_enter_flowc(struct gnutella_node *n);
void node_tx_leave_flowc(struct gnutella_node *n);
void node_tx_swift_changed(struct gnutella_node *n);
void node_bye_all(void);
gboolean node_bye_pending(void);
void node_close(void);
gboolean node_remove_worst(gboolean non_local);

void node_qrt_changed(gpointer query_table);
void node_qrt_discard(struct gnutella_node *n);
void node_qrt_install(struct gnutella_node *n, gpointer query_table);
void node_qrt_patched(struct gnutella_node *n, gpointer query_table);

void send_node_error(struct gnutella_socket *s, int code,
	const gchar *msg, ...) G_GNUC_PRINTF(3, 4);

void node_add_sent(gnutella_node_t *n, gint x);
void node_add_txdrop(gnutella_node_t *n, gint x);
void node_add_rxdrop(gnutella_node_t *n, gint x);

void node_set_vendor(gnutella_node_t *n, const gchar *vendor);

void node_set_hops_flow(gnutella_node_t *n, guint8 hops);
void node_set_online_mode(gboolean on);
void node_current_peermode_changed(node_peer_t mode);
gchar *node_ip(const gnutella_node_t *n);

void node_connect_back(const gnutella_node_t *n, guint16 port);
void node_connected_back(struct gnutella_socket *s);

void node_mark_bad_vendor(struct gnutella_node *n);
	
gboolean node_proxying_add(gnutella_node_t *n, gchar *guid);
void node_proxy_add(gnutella_node_t *n, guint32 ip, guint16 port);
void node_http_proxies_add(
	gchar *buf, gint *retval, gpointer arg, guint32 flags);
GSList *node_push_proxies(void);
const GSList *node_all_nodes(void);
gnutella_node_t *node_active_by_id(guint32 id);

void node_became_firewalled(void);
void node_set_socket_rx_size(gint rx_size);

void node_udp_process(struct gnutella_socket *s);

#endif /* _nodes_h_ */

/* vi: set ts=4 sw=4 cindent: */
