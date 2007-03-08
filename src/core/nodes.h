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

#ifndef _core_nodes_h_
#define _core_nodes_h_

#include "common.h"

#include "mq.h"
#include "sq.h"
#include "rx.h"
#include "qrp.h"
#include "hsep.h"
#include "gnutella.h"
#include "extensions.h"

#include "if/core/wrap.h"			/* For wrap_io_t */
#include "if/core/hsep.h"
#include "if/core/guid.h"
#include "if/core/hcache.h"
#include "if/core/nodes.h"

#include "lib/header.h"

typedef enum {
	NODE_MAGIC = 0x67f8e02f
} node_magic_t;

/**
 * @struct node_rxfc_mon
 *
 * This structure keeps tracks of remote flow-control indications and
 * measures the time spent in flow-control over a period of time.  Every
 * half period we monitor the time we spend against a ratio.
 *
 * When no flow control occurs at all during two half periods, the structure
 * is disposed of.
 */

#define NODE_RX_FC_HALF_PERIOD	300		/**< 5 minutes */

struct node_rxfc_mon {
	time_t start_half_period;	/**< When half period started */
	time_t fc_last_half;		/**< Time spent in FC last half period */
	time_t fc_accumulator;		/**< Time spent in FC this period */
	time_t fc_start;			/**< Time when FC started, 0 if not in FC */
};

/**
 * @def MAX_CACHE_HOPS
 * defines the maximum hop count we handle for the ping/pong caching
 * scheme.  Any hop count greater than that is thresholded to that
 * value.
 */
/**
 * @def CACHE_HOP_IDX
 * The macro returning the array index in the (0 .. MAX_CACHE_HOPS)
 * range, based on the hop count.
 */

#define MAX_CACHE_HOPS	6		/* We won't handle anything larger */

#define CACHE_HOP_IDX(h)	(((h) > MAX_CACHE_HOPS) ? MAX_CACHE_HOPS : (h))

/*
 * Throttle periods for ping reception, depending on the peer mode.
 * This is applicable for regular pings, not alive pings.
 */
#define PING_REG_THROTTLE		3		/**< seconds, regular peer */
#define PING_LEAF_THROTTLE		60		/**< seconds, peer is leaf node */

typedef guint64 node_id_t;

typedef struct gnutella_node {
	node_magic_t magic;			/**< Magic value for consistency checks */
    gnet_node_t node_handle;    /**< Handle of this node */
	node_peer_t peermode;		/**< Operating mode (leaf, ultra, normal) */
	node_peer_t start_peermode;	/**< Operating mode when handshaking begun */

	gchar error_str[256];		/**< To sprintf() error strings with vars */
	struct gnutella_socket *socket;		/**< Socket of the node */
	guint8 proto_major;			/**< Handshaking protocol major number */
	guint8 proto_minor;			/**< Handshaking protocol minor number */

	guint8 qrp_major;			/**< Query routing protocol major number */
	guint8 qrp_minor;			/**< Query routing protocol minor number */
	guint8 uqrp_major;			/**< UP Query routing protocol major number */
	guint8 uqrp_minor;			/**< UP Query routing protocol minor number */
	const gchar *vendor;		/**< Vendor information (always UTF-8) */
	gint country;				/**< Country of origin -- encoded ISO3166 */
	vendor_code_t vcode;		/**< Vendor code (vcode.u32 == 0 if unknown) */
	gpointer io_opaque;			/**< Opaque I/O callback information */

	gnutella_header_t header;		/**< Header of the current message */
	extvec_t extvec[MAX_EXTVEC];	/**< GGEP extensions in "fat" messages */
	gint extcount;					/**< Amount of extensions held */

	guint16 size; /**< How many bytes we need to read for the current message */
	guint16 header_flags;		/**< Header flags (new message architecture) */

	gchar *data;				/**< data of the current message */
	guint32 pos;				/**< write position in data */

	gnet_node_state_t status;	/**< See possible values below */
	guint32 flags;				/**< See possible values below */
	guint32 attrs;				/**< See possible values below */

	guint8 hops_flow;			/**< Don't send queries with a >= hop count */
	guint8 max_ttl;				/**< Value of their advertised X-Max-TTL */
	guint16 degree;				/**< Value of their advertised X-Degree */

	GHashTable *qseen;			/**< Queries seen from this leaf node */
	GHashTable *qrelayed;		/**< Queries relayed from this node */
	GHashTable *qrelayed_old;	/**< Older version of the `qrelayed' table */
	time_t qrelayed_created;	/**< When `qrelayed' was created */

	guint32 sent;				/**< Number of sent packets */
	guint32 received;			/**< Number of received packets */
	guint32 tx_dropped;			/**< Number of packets dropped at TX time */
	guint32 rx_dropped;			/**< Number of packets dropped at RX time */
	guint32 n_bad;				/**< Number of bad packets received */
	guint16 n_dups;				/**< Number of dup messages received (bad) */
	guint16 n_hard_ttl;			/**< Number of hard_ttl exceeded (bad) */
	guint32 n_weird;			/**< Number of weird messages from that node */
	guint32 n_hostile;			/**< Number of messages from hostile IP */
	guint32 n_spam;				/**< Number of messages rated as spam */
	guint32 n_evil;				/**< Number of messages with evil filenames */

	guint32 allocated;			/**< Size of allocated buffer data, 0 for none */
	gboolean have_header;		/**< TRUE if we have got a full message header */

	time_t last_update;			/**< Last update of the node */
	time_t last_tx;				/**< Last time we transmitted to the node */
	time_t last_rx;				/**< Last time we received from the node */
	time_t connect_date;		/**< When we got connected (after handshake) */
	time_t tx_flowc_date;		/**< When we entered in TX flow control */
	struct node_rxfc_mon *rxfc;	/**< Optional, time spent in RX flow control */
	time_t shutdown_date;		/**< When we entered in shutdown mode */
	time_t up_date;				/**< When remote server started (0 if unknown) */
	time_t leaf_flowc_start;	/**< Time when leaf flow-controlled queries */
	time_delta_t shutdown_delay; /**< How long we can stay in shutdown mode */

	const gchar *remove_msg;	/**< Reason of removing */

	host_addr_t addr;			/**< ip of the node */
	guint16 port;				/**< port of the node */

	host_addr_t proxy_addr;		/**< ip of the node for push proxyfication */
	guint16 proxy_port;			/**< port of the node for push proxyfication */

	mqueue_t *outq;				/**< TX Output queue */
	squeue_t *searchq;			/**< TX Search queue */
	rxdrv_t *rx;				/**< RX stack top */

	gpointer routing_data;		/**< Opaque info, for gnet message routing */
	gpointer sent_query_table;	/**< Opaque info, query table sent to node */
	gpointer recv_query_table;	/**< Opaque info, query table recved from node */
	gpointer qrt_update;		/**< Opaque info, query routing update handle */
	gpointer qrt_receive;		/**< Opaque info, query routing reception */
	qrt_info_t *qrt_info;		/**< Info about received query table */

	gpointer alive_pings;		/**< Opaque info, for alive ping checks */
	time_t last_alive_ping;		/**< Last time we sent an alive ping */
	time_delta_t alive_period;	/**< Period for sending alive pings (secs) */

	wrap_buf_t hello;			/**< Spill buffer for GNUTELLA HELLO */

	/*
	 * Round-trip time (RTT) measurements operated via Time Sync
	 * (more accuracy than with traditional ping / pong exchanges).
	 * Figures are in ms.
	 */

	guint32 tcp_rtt;			/**< RTT when exchange takes place over TCP */
	guint32 udp_rtt;			/**< RTT when exchange takes place over UDP  */
	cevent_t *tsync_ev;			/**< Time sync event */

	/*
	 * Data structures used by the ping/pong reduction scheme.
	 *		--RAM, 02/02/2002
	 */

	node_id_t id;				/**< Unique internal ID */
	guint ping_throttle;		/**< Period for accepting new pings (secs) */
	time_t ping_accept;			/**< Time after which we accept new pings */
	time_t next_ping;			/**< When to send a ping, for "OLD" clients */
	gchar ping_guid[GUID_RAW_SIZE];	/**< The GUID of the last accepted ping */
	guchar pong_needed[MAX_CACHE_HOPS+1];	/**< Pongs needed, by hop value */
	guchar pong_missing;	/**< Sum(pong_needed[i]), i = 0..MAX_CACHE_HOPS */

	host_addr_t gnet_addr;		/**< When != 0, we know the remote IP/port */
	guint16 gnet_port;			/**< (listening port, that is ) */
	guint32 gnet_files_count;	/**< Used to answer "Crawling" pings */
	guint32 gnet_kbytes_count;	/**< Used to answer "Crawling" pings */
	host_addr_t gnet_pong_addr;	/**< When != 0, last IP we got in pong */
	host_addr_t gnet_qhit_addr;	/**< When != 0, last IP we got in query hit */
	const gchar *guid;			/**< GUID of node (atom) seen on the network */

	guint32 n_ping_throttle;  /**< Number of pings we throttled */
	guint32 n_ping_accepted;  /**< Number of pings we accepted */
	guint32 n_ping_special;	  /**< Number of special pings we received */
	guint32 n_ping_sent;	  /**< Number of pings we sent to this node */
	guint32 n_pong_received;  /**< Number of pongs we received from this node */
	guint32 n_pong_sent;	  /**< Number of pongs we sent to this node */

	/*
	 * Traffic statistics -- RAM, 13/05/2002.
	 */

	gint32 tx_given;			/**< Bytes fed to the TX stack (from top) */
	gint32 tx_deflated;			/**< Bytes deflated by the TX stack */
	gint32 tx_written;			/**< Bytes written by the TX stack */

	gint32 rx_given;			/**< Bytes fed to the RX stack (from bottom) */
	gint32 rx_inflated;			/**< Bytes inflated by the RX stack */
	gint32 rx_read;				/**< Bytes read from the RX stack */

	/*
	 * Various Gnutella statistics -- RAM, 10/12/2003.
	 *
	 * qrp_queries/qrp_matches is used by both leaf and ultra nodes:
	 * . Leaf structures use it to count the amount of queries received versus
	 *   queries sent after QRP filtering by the ultra node (us).
	 * . Ultra structures use it to count the amount of queries received from
	 *   the ultra node by the leaf node (us) versus the amount of queries
	 *   that really caused a match to one of our files.
	 */

	guint32 qrp_queries;		/**< Queries received under QRP control */
	guint32 qrp_matches;		/**< Queries received that incurred a match */
	guint32 rx_queries;			/**< Total amount of queries received */
	guint32 tx_queries;			/**< Total amount of queries sent */
	guint32 rx_qhits;			/**< Total amount of hits received */
	guint32 tx_qhits;			/**< Total amount of hits sent */

	hsep_ctx_t *hsep;	/**< Horizon size estimation (HSEP) -- TSC, 11/02/2004 */

} gnutella_node_t;

/*
 * Node flags.
 */

enum {
	NODE_F_HDSK_PING	= 1 << 0,	/**< Expecting handshake ping */
	NODE_F_STALE_QRP	= 1 << 1,	/**< Is sending a stale QRP patch */
	NODE_F_INCOMING		= 1 << 2,	/**< Incoming (permanent) connection */
	NODE_F_ESTABLISHED	= 1 << 3,	/**< Gnutella connection established */
	NODE_F_VALID		= 1 << 4,	/**< Handshaked with a Gnutella node */
	NODE_F_ALIEN_IP		= 1 << 5,	/**< Pong-IP did not match TCP/IP addr */
	NODE_F_WRITABLE		= 1 << 6,	/**< Node is writable */
	NODE_F_READABLE		= 1 << 7,	/**< Node is readable, process queries */
	NODE_F_BYE_SENT		= 1 << 8,	/**< Bye message was queued */
	NODE_F_NODELAY		= 1 << 9,	/**< TCP_NODELAY was activated */
	NODE_F_NOREAD		= 1 << 10,	/**< Prevent further reading from node */
	NODE_F_EOF_WAIT		= 1 << 11,	/**< At final shutdown, waiting EOF */
	NODE_F_CLOSING		= 1 << 12,	/**< Initiated bye or shutdown */
	NODE_F_ULTRA		= 1 << 13,	/**< Is one of our ultra nodes */
	NODE_F_LEAF			= 1 << 14,	/**< Is one of our leaves */
	NODE_F_CRAWLER		= 1 << 15,	/**< Is a Gnutella Crawler */
	NODE_F_FAKE_NAME	= 1 << 16,	/**< Was unable to validate GTKG name */
	NODE_F_PROXY		= 1 << 17,	/**< Sent a push-proxy request to it */
	NODE_F_PROXIED		= 1 << 18,	/**< We are push-proxy for that node */
	NODE_F_QRP_SENT		= 1 << 19,	/**< Undergone 1 complete QRP sending */
	NODE_F_TSYNC_WAIT	= 1 << 20,	/**< Time sync pending via TCP */
	NODE_F_TSYNC_TCP	= 1 << 21,	/**< No replies via UDP, use TCP */
	NODE_F_GTKG			= 1 << 22,	/**< Node is another gtk-gnutella */
	NODE_F_FORCE		= 1 << 23,	/**< Connection is forced */
	NODE_F_NO_OOB_PROXY	= 1 << 24,	/**< Do not OOB proxy the leaf */
	NODE_F_TLS			= 1 << 25,	/**< TLS-tunneled */
	NODE_F_CAN_TLS		= 1 << 26	/**< Indicated support for TLS */
};

/*
 * Node attributes.
 */

enum {
	NODE_A_BYE_PACKET	= 1 << 0,	/**< Supports Bye-Packet */
	NODE_A_PONG_CACHING	= 1 << 1,	/**< Supports Pong-Caching */
	NODE_A_PONG_ALIEN	= 1 << 2,	/**< Alien Pong-Caching scheme */
	NODE_A_QHD_NO_VTAG	= 1 << 3,	/**< Servent has no vendor tag in QHD */
	NODE_A_RX_INFLATE	= 1 << 4,	/**< Reading compressed data */
	NODE_A_TX_DEFLATE	= 1 << 5,	/**< Sending compressed data */
	NODE_A_ULTRA		= 1 << 6,	/**< Node wants to be an Ultrapeer */
	NODE_A_NO_ULTRA		= 1 << 7,	/**< Node is NOT ultra capable */
	NODE_A_UP_QRP		= 1 << 8,	/**< Supports intra-UP QRP */
	NODE_A_GUIDANCE		= 1 << 9,	/**< Can leaf-guide dyn queries */
	NODE_A_TIME_SYNC	= 1 << 10,	/**< Supports time sync */
	NODE_A_CRAWLABLE	= 1 << 11,	/**< Node can be UDP-crawled */
	NODE_A_DYN_QUERY	= 1 << 12,	/**< Node can perform dynamic queries */
	NODE_A_CAN_SFLAG	= 1 << 13,	/**< Node supports flags in headers */
 
	NODE_A_NO_KEPT_ZERO	= 1 << 14,	/**< For GTKG < 2006-08-15: no kept=0! */
	NODE_A_NO_DUPS		= 1 << 15,	/**< For broken old GTKG: no dups! */
	NODE_A_CAN_HSEP		= 1 << 16,	/**< Node supports HSEP */
	NODE_A_CAN_QRP		= 1 << 17,	/**< Node supports query routing */
	NODE_A_CAN_VENDOR	= 1 << 18,	/**< Node supports vendor messages */
	NODE_A_CAN_ULTRA	= 1 << 19,	/**< Node is ultra capable */
	NODE_A_CAN_INFLATE	= 1 << 20,	/**< Node capable of inflating */
	NODE_A_CAN_HEAD		= 1 << 21	/**< Supports HEAD ping (vendor message) */
};
 
/*
 * UDP crawling "feature" flags.
 */

#define NODE_CR_CONNECTION	0x01		/**< Include connection times */
#define NODE_CR_LOCALE		0x02		/**< Include locale information */
#define NODE_CR_CRAWLABLE	0x04		/**< Include crawlable peers only */
#define NODE_CR_USER_AGENT	0x08		/**< Include user-agent strings */
#define NODE_CR_MASK		0x0f		/**< Mask for supported features */

#define NODE_CR_SEPARATOR	';'
#define NODE_CR_ESCAPE_CHAR	'\\'

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

#define NODE_IS_INCOMING(n)	\
	((n)->flags & NODE_F_INCOMING)

#define NODE_IS_REMOVING(n) \
	((n)->status == GTA_NODE_REMOVING)

#define NODE_IN_TX_FLOW_CONTROL(n) \
	((n)->outq && mq_is_flow_controlled((n)->outq))

#define NODE_IN_TX_SWIFT_CONTROL(n) \
	((n)->outq && mq_is_swift_controlled((n)->outq))

#define NODE_IS_WRITABLE(n) \
	((n)->flags & NODE_F_WRITABLE)

#define NODE_IS_READABLE(n) \
	(((n)->flags & (NODE_F_READABLE|NODE_F_NOREAD)) == NODE_F_READABLE)

#define NODE_IS_ESTABLISHED(n) \
	(((n)->flags & (NODE_F_WRITABLE|NODE_F_ESTABLISHED)) == \
		(NODE_F_WRITABLE|NODE_F_ESTABLISHED))

#define NODE_MQUEUE_PERCENT_USED(n) \
	((n)->outq ? mq_size((n)->outq) * 100 / mq_maxsize((n)->outq) : 0)

#define NODE_SQUEUE(n) ((n)->searchq)

#define NODE_MQUEUE_COUNT(n) \
	((n)->outq ? mq_count((n)->outq) : 0)

#define NODE_MQUEUE_PENDING(n) \
	((n)->outq ? mq_pending((n)->outq) : 0)

#define NODE_MQUEUE_ABOVE_LOWAT(n) \
	((n)->outq ? mq_size((n)->outq) > mq_lowat((n)->outq) : FALSE)

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

#define NODE_ID(n)				((n)->id)

#define NODE_CAN_SFLAG(n)		((n)->attrs & NODE_A_CAN_SFLAG)
#define NODE_UP_QRP(n)			((n)->attrs & NODE_A_UP_QRP)
#define NODE_LEAF_GUIDE(n)		((n)->attrs & NODE_A_GUIDANCE)
#define NODE_CAN_INFLATE(n)		((n)->attrs & NODE_A_CAN_INFLATE)

/*
 * Peer inspection macros
 */

#define NODE_IS_LEAF(n)			((n)->peermode == NODE_P_LEAF)
#define NODE_IS_NORMAL(n)		((n)->peermode == NODE_P_NORMAL)
#define NODE_IS_ULTRA(n)		((n)->peermode == NODE_P_ULTRA)
#define NODE_IS_UDP(n)			((n)->peermode == NODE_P_UDP)

/*
 * Macros.
 */

#define node_vendor(n)		((n)->vendor != NULL ? (n)->vendor : "????")
#define node_type(n)		\
	(NODE_IS_LEAF(n) ? "leaf" : NODE_IS_ULTRA(n) ? "ultra" : "legacy")

#define node_inc_sent(n)            node_add_sent(n, 1)
#define node_inc_txdrop(n)          node_add_txdrop(n, 1)
#define node_inc_rxdrop(n)          node_add_rxdrop(n, 1)

#define node_add_tx_given(n,x)		do { (n)->tx_given += (x); } while (0)
#define node_add_rx_read(n,x)		do { (n)->rx_read += (x); } while (0)

#define node_inc_tx_query(n)		do { (n)->tx_queries++; } while (0)
#define node_inc_rx_query(n)		do { (n)->rx_queries++; } while (0)
#define node_inc_tx_qhit(n)			do { (n)->tx_qhits++; } while (0)
#define node_inc_rx_qhit(n)			do { (n)->rx_qhits++; } while (0)

#define node_inc_qrp_query(n)		do { (n)->qrp_queries++; } while (0)
#define node_inc_qrp_match(n)		do { (n)->qrp_matches++; } while (0)

/*
 * Check whether Ultra node has received our QRP table, or whether
 * we fully got the QRP table from the leaf.
 */
#define node_ultra_received_qrp(n) \
	(NODE_IS_ULTRA(n) && \
	(n)->qrt_update == NULL && (n)->sent_query_table != NULL)
#define node_leaf_sent_qrp(n) \
	(NODE_IS_LEAF(n) && \
	(n)->qrt_receive == NULL && (n)->recv_query_table != NULL)

/**
 * Can we send query with hop count `h' according to node's hops-flow value?
 */
#define node_query_hops_ok(n, h)	((h) < (n)->hops_flow)

/**
 * @def node_flowc_swift_grace
 *
 * The grace period between the time the node enters flow-control and the
 * time we want to speed up things and drop traffic, entering "swift" mode.
 * For a leaf node, we allow more time before we start to aggressively drop
 * traffic, but for a peer, we need to respond quickly, to avoid long clogging.
 */
/**
 * @def node_flowc_swift_period
 *
 * In "swift" mode, a callback is periodically invoked to drop more traffic
 * if we don't see much progress in the queue backlog.  For a leaf node, it
 * is invoked less often than for a peer.
 *
 */
#define node_flowc_swift_grace(n)	(NODE_IS_LEAF(n) ? 210 : 30)
#define node_flowc_swift_period(n)	(NODE_IS_LEAF(n) ? 140 : 20)

/*
 * Global Data
 */

#define GNUTELLA_HELLO "GNUTELLA CONNECT/"
#define GNUTELLA_HELLO_LENGTH	(sizeof(GNUTELLA_HELLO) - 1)

#define NODE_ID_SELF	((node_id_t) 0)	/**< ID for "our node" (ourselves) */

extern const gchar *start_rfc822_date;

extern GHookList node_added_hook_list;
extern struct gnutella_node *node_added;

/*
 * Global Functions
 */

void node_init(void);
void node_post_init(void);
void node_slow_timer(time_t now);
void node_timer(time_t now);
guint connected_nodes(void);
guint node_count(void);
guint node_keep_missing(void);
guint node_missing(void);
guint node_leaves_missing(void);
guint node_outdegree(void);
gboolean node_is_connected(const host_addr_t addr, guint16 port,
		gboolean incoming);
gboolean node_host_is_connected(const host_addr_t addr, guint16 port);
void node_add_socket(struct gnutella_socket *s, const host_addr_t addr,
		guint16 port, guint32 flags);
void node_remove(struct gnutella_node *,
	const gchar * reason, ...) G_GNUC_PRINTF(2, 3);
guint node_remove_by_addr(const host_addr_t addr, guint16 port);
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
void node_unflushq(struct gnutella_node *n);
void node_tx_service(struct gnutella_node *n, gboolean on);
void node_tx_enter_flowc(struct gnutella_node *n);
void node_tx_leave_flowc(struct gnutella_node *n);
void node_tx_enter_warnzone(struct gnutella_node *n);
void node_tx_leave_warnzone(struct gnutella_node *n);
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
const gchar *node_addr(const gnutella_node_t *n);
const gchar *node_addr2(const gnutella_node_t *n);
const gchar *node_gnet_addr(const gnutella_node_t *n);

void node_connect_back(const gnutella_node_t *n, guint16 port);
void node_connected_back(struct gnutella_socket *s);

void node_mark_bad_vendor(struct gnutella_node *n);

void node_proxying_remove(gnutella_node_t *n);
gboolean node_proxying_add(gnutella_node_t *n, const gchar *guid);
void node_proxy_add(gnutella_node_t *n, const host_addr_t addr, guint16 port);
void node_proxy_cancel_all(void);
void node_http_proxies_add(
	gchar *buf, gint *retval, gpointer arg, guint32 flags);
GSList *node_push_proxies(void);
const GSList *node_all_nodes(void);
const GSList *node_all_but_broken_gtkg(void);

guint node_id_hash(gconstpointer key);
gboolean node_id_eq(gconstpointer a, gconstpointer b);
const gchar *node_id_to_string(node_id_t node_id);
gnutella_node_t *node_active_by_id(node_id_t id);
void node_set_leaf_guidance(node_id_t id, gboolean supported);

void node_became_firewalled(void);
void node_became_udp_firewalled(void);
void node_set_socket_rx_size(gint rx_size);

mqueue_t *node_udp_get_outq(enum net_type net);
void node_udp_enable(void);
void node_udp_disable(void);
void node_udp_process(struct gnutella_socket *s);
gnutella_node_t *node_udp_get_addr_port(const host_addr_t addr, guint16 port);

void node_can_tsync(gnutella_node_t *n);
void node_crawl(gnutella_node_t *n, gint ucnt, gint lcnt, guint8 features);

void node_update_udp_socket(void);
void node_check_remote_ip_header(const host_addr_t peer, header_t *head);

guint feed_host_cache_from_headers(header_t *headers,
	host_type_t sender, gboolean gnet, const host_addr_t peer);

gnutella_node_t *node_browse_prepare(
	gnet_host_t *host, const gchar *vendor, gnutella_header_t *header,
	gchar *data, guint32 size);
void node_browse_cleanup(gnutella_node_t *n);
void node_kill_hostiles(void);

static inline void
node_check(const struct gnutella_node * const n)
{
	g_assert(n);
	g_assert(NODE_MAGIC == n->magic);
	g_assert(NODE_ID_SELF != n->id);
}

static inline const gchar *
node_guid(const struct gnutella_node * const n)
{
	return n->guid;
}

gboolean node_set_guid(struct gnutella_node *n, const gchar *guid);
struct gnutella_node *node_by_guid(const gchar *guid);

#endif /* _core_nodes_h_ */

/* vi: set ts=4 sw=4 cindent: */
