/*
 * $Id$
 *
 * Copyright (c) 2001-2002, Raphael Manfredi
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

#ifndef __nodes_h__
#define __nodes_h__

#include "gnutella.h"
#include "mq.h"
#include "sq.h"
#include "rx.h"

/*
 * MAX_CACHE_HOPS defines the maximum hop count we handle for the ping/pong
 * caching scheme.  Any hop count greater than that is thresholded to that
 * value.
 *
 * CACHE_HOP_IDX is the macro returning the array index in the
 * (0 .. MAX_CACHE_HOPS) range, based on the hop count.
 */
#define MAX_CACHE_HOPS	9		/* We won't handle anything larger */

#define CACHE_HOP_IDX(h)	(((h) > MAX_CACHE_HOPS) ? MAX_CACHE_HOPS : (h))

typedef struct gnutella_node {
    gnet_node_t node_handle;    /* Handle of this node */
	node_peer_t peermode;		/* Operating mode (leaf, ultra, normal) */

	gchar error_str[256];		/* To sprintf() error strings with vars */
	struct gnutella_socket *socket;		/* Socket of the node */
	gint proto_major;			/* Protocol major number */
	gint proto_minor;			/* Protocol minor number */
	gchar *vendor;				/* Vendor information */
	guchar vcode[4];			/* Vendor code (vcode[0] == NUL when unknown) */
	gpointer io_opaque;			/* Opaque I/O callback information */

	struct gnutella_header header;		/* Header of the current message */

	guint32 size;	/* How many bytes we need to read for the current message */

	gchar *data;			/* data of the current message */

	guint32 pos;			/* write position in data */

	guchar status;			/* See possible values below */
	guint32 flags;			/* See possible values below */
	guint32 attrs;			/* See possible values below */

	guint32 sent;				/* Number of sent packets */
	guint32 received;			/* Number of received packets */
	guint32 tx_dropped;			/* Number of packets dropped at TX time */
	guint32 rx_dropped;			/* Number of packets dropped at RX time */
	guint32 n_bad;				/* Number of bad packets received */
	guint16 n_dups;				/* Number of dup messages received (bad) */
	guint16 n_hard_ttl;			/* Number of hard_ttl exceeded (bad) */
	guint32 n_weird;			/* Number of weird messages from that node */

	guint32 allocated;			/* Size of allocated buffer data, 0 for none */
	gboolean have_header;		/* TRUE if we have got a full message header */

	time_t last_update;			/* Last update of the node */
	time_t connect_date;		/* When we got connected (after handshake) */
	time_t tx_flowc_date;		/* When we entered in TX flow control */
	time_t shutdown_date;		/* When we entered in shutdown mode */
	time_t up_date;				/* When remote server started (0 if unknown) */
	guint32 shutdown_delay;		/* How long we can stay in shutdown mode */

	const gchar *remove_msg;	/* Reason of removing */

	guint32 ip;					/* ip of the node */
	guint16 port;				/* port of the node */

	mqueue_t *outq;				/* TX Output queue */
	squeue_t *searchq;			/* TX Search queue */
	rxdrv_t *rx;				/* RX stack top */

	gpointer routing_data;		/* Opaque info, for gnet message routing */
	gpointer query_routing;		/* Opaque info, for query routing, if UP */
	gpointer query_table;		/* Opaque info, last query table sent to UP */
	gpointer qrt_update;		/* Opaque info, query routing update handle */

	gpointer alive_pings;		/* Opaque info, for alive ping checks */
	time_t last_alive_ping;		/* Last time we sent an alive ping */
	guint alive_period;			/* Period for sending alive pings (secs) */

	/*
	 * Data structures used by the ping/pong reduction scheme.
	 *		--RAM, 02/02/2002
	 */

	gint32 id;					/* Unique internal ID */
	time_t ping_accept;			/* Time after which we accept new pings */
	time_t next_ping;			/* When to send a ping, for "OLD" clients */
	guchar ping_guid[16];		/* The GUID of the last accepted ping */
	guchar pong_needed[MAX_CACHE_HOPS+1];	/* Pongs needed, by hop value */
	guchar pong_missing;		/* Sum(pong_needed[i]), i = 0..MAX_CACHE_HOPS */

	guint32 gnet_ip;			/* When != 0, we know the remote IP/port */
	guint16 gnet_port;			/* (listening port, that is ) */
	guint32 gnet_files_count;	/* Used to answer "Crawling" pings */
	guint32 gnet_kbytes_count;	/* Used to answer "Crawling" pings */
	guint32 gnet_pong_ip;		/* When != 0, last IP we got in pong */
	guint32 gnet_qhit_ip;		/* When != 0, last IP we got in query hit */
	guchar *gnet_guid;			/* GUID of node (atom) seen on the network */

	guint32 n_ping_throttle;	/* Number of pings we throttled */
	guint32 n_ping_accepted;	/* Number of pings we accepted */
	guint32 n_ping_special;		/* Number of special pings we received */
	guint32 n_ping_sent;		/* Number of pings we sent to this node */
	guint32 n_pong_received;	/* Number of pongs we received from this node */
	guint32 n_pong_sent;		/* Number of pongs we sent to this node */

	/*
	 * Traffic statistics -- RAM, 13/05/2002.
	 */

	gint32 tx_given;			/* Bytes fed to the TX stack (from top) */
	gint32 tx_deflated;			/* Bytes deflated by the TX stack */
	gint32 tx_written;			/* Bytes written by the TX stack */
	
	gint32 rx_given;			/* Bytes fed to the RX stack (from bottom) */
	gint32 rx_inflated;			/* Bytes inflated by the RX stack */
	gint32 rx_read;				/* Bytes read from the RX stack */
} gnutella_node_t;

/*
 * Node flags.
 */

#define NODE_F_HDSK_PING	0x00000001	/* Expecting handshake ping */
#define NODE_F_TMP			0x00000002	/* Temporary, until we send pongs */
#define NODE_F_INCOMING		0x00000004	/* Incoming (permanent) connection */
#define NODE_F_RETRY_04		0x00000008	/* Retry handshake at 0.4 on failure */
#define NODE_F_VALID		0x00000010	/* We handshaked with a Gnutella node */
#define NODE_F_ALIEN_IP		0x00000020	/* Pong-IP does not match TCP/IP addr */
#define NODE_F_WRITABLE		0x00000040	/* Node is writable */
#define NODE_F_READABLE		0x00000080	/* Node is readable, process queries */
#define NODE_F_BYE_SENT		0x00000100	/* Bye message was queued */
#define NODE_F_NODELAY		0x00000200	/* TCP_NODELAY was activated */
#define NODE_F_NOREAD		0x00000400	/* Prevent further reading from node */
#define NODE_F_EOF_WAIT		0x00000800	/* During final shutdown, waiting EOF */
#define NODE_F_CLOSING		0x00001000	/* Initiated bye or shutdown */
#define NODE_F_ULTRA		0x00002000	/* Is one of our ultra nodes */
#define NODE_F_LEAF			0x00004000	/* Is one of our leaves */

/*
 * Node attributes.
 */

#define NODE_A_BYE_PACKET	0x00000001	/* Supports Bye-Packet */
#define NODE_A_PONG_CACHING	0x00000002	/* Supports Pong-Caching */
#define NODE_A_PONG_ALIEN	0x00000004	/* Alien Pong-Caching scheme */
#define NODE_A_QHD_NO_VTAG	0x00000008	/* Servent has no vendor tag in QHD */
#define NODE_A_RX_INFLATE	0x00000010	/* Reading compressed data */
#define NODE_A_TX_DEFLATE	0x00000020	/* Sending compressed data */
#define NODE_A_CAN_ULTRA	0x00000040	/* Node is ultra capable */
#define NODE_A_ULTRA		0x00000100	/* Node wants to be an Ultrapeer */
#define NODE_A_NO_ULTRA		0x00000200	/* Node is NOT ultra capable */

#define NODE_A_CAN_INFLATE	0x80000000	/* Node capable of inflating */

/*
 * State inspection macros.
 */

#define NODE_IS_CONNECTING(n)						\
	(	(n)->status == GTA_NODE_CONNECTING			\
	||	(n)->status == GTA_NODE_HELLO_SENT			\
	||	(n)->status == GTA_NODE_WELCOME_SENT		\
	||	(n)->status == GTA_NODE_RECEIVING_HELLO	)

#define NODE_IS_CONNECTED(n)						\
	(	(n)->status == GTA_NODE_CONNECTED			\
	||	(n)->status == GTA_NODE_SHUTDOWN )

#define NODE_IS_PONGING_ONLY(n) \
	((n)->flags & NODE_F_TMP)

#define NODE_IS_INCOMING(n)	\
	((n)->flags & (NODE_F_TMP|NODE_F_INCOMING))

#define NODE_IS_REMOVING(n) \
	((n)->status == GTA_NODE_REMOVING)

#define NODE_IN_TX_FLOW_CONTROL(n) \
	((n)->outq && mq_is_flow_controlled((n)->outq))

#define NODE_IS_WRITABLE(n) \
	(((n)->flags & (NODE_F_TMP|NODE_F_WRITABLE)) == NODE_F_WRITABLE)

#define NODE_IS_READABLE(n) \
	(((n)->flags & (NODE_F_READABLE|NODE_F_NOREAD)) == NODE_F_READABLE)

#define NODE_MQUEUE_PERCENT_USED(n) \
	((n)->outq ? mq_size((n)->outq) * 100 / mq_maxsize((n)->outq) : 0)

#define NODE_SQUEUE(n) ((n)->searchq)

#define NODE_MQUEUE_COUNT(n) \
	((n)->outq ? mq_count((n)->outq) : 0)

#define NODE_SQUEUE_COUNT(n) \
	((n)->searchq ? sq_count((n)->searchq) : 0)

#define NODE_SQUEUE_SENT(n) \
	((n)->searchq ? sq_sent((n)->searchq) : 0)

#define NODE_RX_COMPRESSED(n) \
	((n)->attrs & NODE_A_RX_INFLATE)

#define NODE_TX_COMPRESSED(n) \
	((n)->attrs & NODE_A_TX_DEFLATE)

#define NODE_TX_COMPRESSION_RATIO(n)	\
	((n)->tx_given ?					\
		(double) ((n)->tx_given - (n)->tx_deflated) / (n)->tx_given : 0.0)

#define NODE_RX_COMPRESSION_RATIO(n)	\
	((n)->rx_inflated ?					\
		(double) ((n)->rx_inflated - (n)->rx_given) / (n)->rx_inflated : 0.0)

/*
 * Peer inspection macros
 */

#define NODE_IS_LEAF(n)			((n)->peermode == NODE_P_LEAF)
#define NODE_IS_NORMAL(n)		((n)->peermode == NODE_P_NORMAL)
#define NODE_IS_ULTRA(n)		((n)->peermode == NODE_P_ULTRA)

/*
 * Macros.
 */

#define node_vendor(n)              ((n)->vendor)

#define node_inc_sent(n)            node_add_sent(n, 1)
#define node_inc_txdrop(n)          node_add_txdrop(n, 1)
#define node_inc_rxdrop(n)          node_add_rxdrop(n, 1)

#define node_add_tx_given(n,x)		do { (n)->tx_given += (x); } while (0)
#define node_add_tx_written(n,x)	do { (n)->tx_written += (x); } while (0)
#define node_add_tx_deflated(n,x)	do { (n)->tx_deflated += (x); } while (0)

#define node_add_rx_given(n,x)		do { (n)->rx_given += (x); } while (0)
#define node_add_rx_inflated(n,x)	do { (n)->rx_inflated += (x); } while (0)
#define node_add_rx_read(n,x)		do { (n)->rx_read += (x); } while (0)

/*
 * Global Data
 */

extern const gchar *gnutella_hello;
extern guint32 gnutella_hello_length;

extern GSList *sl_nodes;

extern GHookList node_added_hook_list;
extern struct gnutella_node *node_added;

/*
 * Global Functions
 */

void node_init(void);
void node_timer(time_t now);
gboolean on_the_net(void);
gint32 connected_nodes(void);
gint32 node_count(void);
gboolean node_is_connected(guint32 ip, guint16 port, gboolean incoming);
void node_add_socket(struct gnutella_socket *s, guint32 ip, guint16 port);
void node_remove(struct gnutella_node *, const gchar * reason, ...);
void node_bye(gnutella_node_t *, gint code, const gchar * reason, ...);
void node_real_remove(gnutella_node_t *);
void node_eof(struct gnutella_node *n, const gchar * reason, ...);
void node_shutdown(struct gnutella_node *n, const gchar * reason, ...);
void node_bye_if_writable(
	struct gnutella_node *n, gint code, const gchar * reason, ...);
void node_init_outgoing(struct gnutella_node *);
gboolean node_sent_ttl0(struct gnutella_node *n);
void node_disableq(struct gnutella_node *n);
void node_enableq(struct gnutella_node *n);
void node_flushq(struct gnutella_node *n);
void node_tx_enter_flowc(struct gnutella_node *n);
void node_tx_leave_flowc(struct gnutella_node *n);
void node_bye_all(void);
gboolean node_bye_pending(void);
void node_close(void);
gboolean node_remove_worst(gboolean non_local);

void node_qrt_changed(gpointer query_table);

void send_node_error(struct gnutella_socket *s, int code, guchar *msg, ...);

__inline__ void node_add_sent(gnutella_node_t *n, gint x);
__inline__ void node_add_txdrop(gnutella_node_t *n, gint x);
__inline__ void node_add_rxdrop(gnutella_node_t *n, gint x);

inline void node_set_vendor(gnutella_node_t *n, const gchar *vendor);

void node_set_online_mode(gboolean on);
void node_set_current_peermode(guint32 mode);
gchar *node_ip(gnutella_node_t *n);

#endif /* __nodes_h__ */

