/*
 * $Id$
 *
 * Copyright (c) 2001-2003, Raphael Manfredi, Richard Eckart
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

#ifndef _if_core_nodes_h_
#define _if_core_nodes_h_

#include "common.h"

#include "if/core/hosts.h"
#include "lib/vendors.h"

/**
 * Gnet node specific types.
 */
typedef guint32 gnet_node_t;

/*
 * XXX this structure should really be inlined in a node,
 * XXX to avoid definition duplication --RAM, 2004-08-21
 */

typedef struct gnet_node_status {
	guchar status;			    /**< See possible values below */

	/* FIXME: the variables below should go to gnet_node_info since they
	 *        only change very seldom
     */
	time_t connect_date;	/**< When we got connected (after handshake) */
	time_t up_date;			/**< When remote server started (0 if unknown) */
	guint32 gnet_files_count;	/**< Amount of files shared */
	guint32 gnet_kbytes_count;	/**< Size of the library, in Kbytes */
	gboolean gnet_info_known;	/**< Whether previous two values are known */

	guint32  sent;				/**< Number of sent packets */
	guint32  received;			/**< Number of received packets */
	guint32  tx_dropped;		/**< Number of packets dropped at TX time */
	guint32  rx_dropped;		/**< Number of packets dropped at RX time */
	guint32  n_bad;				/**< Number of bad packets received */
	guint16  n_dups;			/**< Number of dup messages received (bad) */
	guint16  n_hard_ttl;		/**< Number of hard_ttl exceeded (bad) */
	guint32  n_weird;			/**< Number of weird messages from that node */
	guint32  n_hostile;			/**< Number of messages from hostile IP */
	guint32  n_spam;			/**< Number of messages rated as spam */
	guint32  n_evil;			/**< Number of messages with evil filenames */

    gint     squeue_sent;
    gint     squeue_count;
    gint     mqueue_count;
    gint     mqueue_percent_used;
    gboolean in_tx_flow_control;
    gboolean in_tx_swift_control;

	/*
	 * Traffic statistics -- RAM, 13/05/2002.
	 */

	gint32   tx_given;			/**< Bytes fed to the TX stack (from top) */
	gint32   tx_deflated;		/**< Bytes deflated by the TX stack */
	gint32   tx_written;		/**< Bytes written by the TX stack */
    gboolean tx_compressed;     /**< Is TX traffic compressed */
    gfloat   tx_compression_ratio; /**< TX compression ratio */
    guint32  tx_bps;			/**< TX traffic rate */

	gint32   rx_given;			/**< Bytes fed to the RX stack (from bottom) */
	gint32   rx_inflated;		/**< Bytes inflated by the RX stack */
	gint32   rx_read;			/**< Bytes read from the RX stack */
    gboolean rx_compressed;     /**< Is RX traffic compressed */
    gfloat   rx_compression_ratio;/**< RX compression ratio */
    gfloat   rx_bps;			/**< RX traffic rate */

	/*
	 * Gnutella statistics -- RAM, 10/12/2003.
	 */

	gboolean has_qrp;		/**< Whether node is under QRP control */
	gfloat qrp_efficiency;	/**< Queries matched / received on QRP control */
	guint32 rx_queries;		/**< Total amount of queries received */
	guint32 tx_queries;		/**< Total amount of queries sent */
	guint32 rx_qhits;		/**< Total amount of hits received */
	guint32 tx_qhits;		/**< Total amount of hits sent */

	gint qrt_slots;			/**< Amount of slots in leaf's QRT */
	gint qrt_generation;	/**< Generation number */
	gint qrt_fill_ratio;	/**< % of filling */
	gint qrt_pass_throw;	/**< Query limiter pass throw when table filled */

	guint32  rt_avg;			/**< Average ping/pong roundtrip time */
	guint32  rt_last;			/**< Last ping/pong roundtrip time */

	guint32 tcp_rtt;			/**< RTT in ms over TCP */
	guint32 udp_rtt;			/**< RTT in ms over UDP */

    gint     shutdown_remain;   /**< Number of seconds before shutdown */
    gchar    message[128];		/**< Additional information */
} gnet_node_status_t;

typedef struct gnet_node_info {
    gnet_node_t node_handle;    /**< Internal node handle */

    gchar *error_str;       /**< To sprintf() error strings with vars */
	gint proto_major;		/**< Protocol major number */
	gint proto_minor;		/**< Protocol minor number */
	gchar *vendor;			/**< Vendor information (always UTF-8) */
	gint country;			/**< Country information */
	union vendor_code vcode;/**< Vendor code (vcode.u32 == 0 when unknown) */

	host_addr_t addr;		/**< ip of the node (connected) */
	guint16 port;			/**< port of the node (connected) */

	gboolean is_pseudo;		/**< TRUE if it's the pseudo UDP node */

	host_addr_t gnet_addr;	/**< Advertised Gnutella address for connecting */
	guint16 gnet_port;		/**< Advertised Gnutella listening port */
	gchar gnet_guid[GUID_RAW_SIZE];		/**< Seen on network (can be blank) */
} gnet_node_info_t;

/*
 * Peer modes.
 */

typedef enum {
	NODE_P_LEAF = 0,			/**< Leaf node */
	NODE_P_AUTO,				/**< Automatic mode */
	NODE_P_ULTRA,				/**< Ultra node */
	NODE_P_NORMAL,				/**< Normal legacy node */
	NODE_P_CRAWLER,				/**< Crawler node */
	NODE_P_UDP,					/**< UDP "fake" node */
	NODE_P_UNKNOWN				/**< Unknown mode yet */
} node_peer_t;

/*
 * QRT state.
 */

typedef enum {
	QRT_S_NONE = 0,				/**< Nothing */
	QRT_S_SENDING,				/**< Sending QRT to ultrapeer */
	QRT_S_SENT,					/**< Sent QRT to ultrapeer */
	QRT_S_RECEIVING,			/**< Receiving initial QRT from leaf */
	QRT_S_PATCHING,				/**< Receiving QRT patch from leaf */
	QRT_S_RECEIVED				/**< Received QRT from leaf */
} qrt_state_t;

typedef struct gnet_node_flags {
	node_peer_t peermode;
	qrt_state_t qrt_state;
	qrt_state_t uqrt_state;
	guint8 hops_flow;
	gboolean incoming;
	gboolean writable;
	gboolean readable;
	gboolean tx_compressed;
	gboolean rx_compressed;
	gboolean mqueue_empty;
	gboolean mqueue_above_lowat;
	gboolean in_tx_flow_control;
	gboolean in_tx_swift_control;
	gboolean is_push_proxied;
	gboolean is_proxying;
	gboolean tls;
} gnet_node_flags_t;

/*
 * Node states.
 */
typedef enum {
	GTA_NODE_CONNECTING			= 1,	/**< Making outgoing connection */
	GTA_NODE_HELLO_SENT			= 2,	/**< Sent 0.4 hello */
	GTA_NODE_WELCOME_SENT		= 3,	/**< Hello accepted, remote welcomed */
	GTA_NODE_CONNECTED			= 4,	/**< Connected at the Gnet level */
	GTA_NODE_REMOVING			= 5,	/**< Removing node */
	GTA_NODE_RECEIVING_HELLO	= 6,	/**< Receiving 0.6 headers */
	GTA_NODE_SHUTDOWN			= 7		/**< Connection being shutdown */
	
} gnet_node_state_t;

#define GTA_NORMAL_TTL				4	/**< Regular TTL, for hops-flow */

/*
 * Nodes callback definitions
 */
typedef void (*node_added_listener_t) (gnet_node_t);
typedef void (*node_removed_listener_t) (gnet_node_t);
typedef void (*node_info_changed_listener_t) (gnet_node_t);
typedef void (*node_flags_changed_listener_t) (gnet_node_t);

#define node_add_listener(signal, callback) \
    CAT3(node_add_,signal,_listener)(callback);

#define node_remove_listener(signal, callback) \
    CAT3(node_remove_,signal,_listener)(callback);

#ifdef CORE_SOURCES

/***
 *** Gnet nodes
 ***/

void node_add_node_added_listener(node_added_listener_t);
void node_remove_node_added_listener(node_added_listener_t);
void node_add_node_removed_listener(node_removed_listener_t);
void node_remove_node_removed_listener(node_removed_listener_t);
void node_add_node_info_changed_listener(node_info_changed_listener_t);
void node_remove_node_info_changed_listener(node_info_changed_listener_t);
void node_add_node_flags_changed_listener(node_flags_changed_listener_t);
void node_remove_node_flags_changed_listener(node_flags_changed_listener_t);

/*
 * Nodes public interface
 */
void node_add(const host_addr_t addr, guint16, guint32 flags);
void node_add_by_name(const gchar *host, guint16, guint32 flags);
void node_remove_by_handle(gnet_node_t n);
void node_remove_nodes_by_handle(GSList *node_list);
void node_get_status(const gnet_node_t n, gnet_node_status_t *s);
gnet_node_info_t *node_get_info(const gnet_node_t n);
void node_clear_info(gnet_node_info_t *info);
void node_free_info(gnet_node_info_t *info);
void node_fill_flags(gnet_node_t n, gnet_node_flags_t *flags);
void node_fill_info(const gnet_node_t n, gnet_node_info_t *info);
const gchar *node_flags_to_string(const gnet_node_flags_t *flags);

#endif /* CORE_SOURCES */

#endif /* _if_core_nodes_h */
/* vi: set ts=4 sw=4 cindent: */
