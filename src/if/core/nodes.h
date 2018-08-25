/*
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

#include "if/core/guid.h"
#include "if/core/mq.h"

#include "lib/host_addr.h"
#include "lib/gnet_host.h"
#include "lib/vendors.h"

struct nid;

/**
 * Remote node mode, as specified for GTKG/23v1.
 */
enum rnode_mode {
	RNODE_M_AUTO = 0,
	RNODE_M_LEAF = 1,
	RNODE_M_ULTRA = 2
};

/**
 * Remote node information structure, as gathered through GTKG/23v1.
 */
typedef struct rnode_info {
	/* General information always returned */
	char vendor[4];			/**< Vendor code */
	enum rnode_mode mode;		/**< Running configuration */
	uint32 answer_flags;		/**< Flags for the "Node Info Reply" message */
	uint32 op_flags;			/**< Operating flags */
	uint32 features[2];			/**< Optional features */
	uint8 features_count;		/**< # of valid entries in features[] */
	uint8 max_ultra_up;			/**< Max # of ultrapeers in ultra mode */
	uint8 max_ultra_lf;			/**< Max # of ultrapeers in leaf mode */
	uint8 ultra_count;			/**< Current amount of ultra nodes */
	uint8 ttl;					/**< TTL limit for messages sent */
	uint8 hard_ttl;				/**< Hard TTL limit for messages relayed */
	uint16 max_leaves;			/**< Max # of leaf nodes */
	uint16 leaf_count;			/**< Current amount of leaf nodes */
	uint32 startup_time;		/**< Startup time */
	uint32 ip_change_time;		/**< Last IP change time */
	/* Bandwidth information, optional */
	uint16 bw_flags;			/**< Bandwidth setting flags */
	uint32 gnet_bw_in;			/**< Incoming Gnet b/w in KiB/s (0=no limit) */
	uint32 gnet_bw_out;			/**< Outgoing Gnet b/w in KiB/s (0=no limit) */
	uint32 gnet_bwl_in;			/**< Incoming leaf b/w in KiB/s (0=no limit) */
	uint32 gnet_bwl_out;		/**< Outgoing leaf b/w in KiB/s (0=no limit) */
	/* Packets remote node dropped on this TCP connection */
	uint32 tx_dropped;			/**< Amount of dropped packets on TX */
	uint32 rx_dropped;			/**< Amount of dropped packets on RX */
	/* Query hit statistics */
	uint16 results_max;			/**< Max # of results per query hit */
	uint32 file_hits;			/**< Hits on shared files */
	uint32 qhits_tcp;			/**< Query hits returned via TCP */
	uint32 qhits_udp;			/**< Claimed query hits returned via UDP */
	uint64 qhits_tcp_bytes;		/**< Total size of TCP qhits (with header) */
	uint64 qhits_udp_bytes;		/**< Total size of UDP qhits (with header) */
	/* CPU statistics */
	uint64 cpu_usr;				/**< Total user CPU time used, in ms */
	uint64 cpu_sys;				/**< Total kernel CPU time used, in ms */
	/* Information sent via optional GGEP blocks */
	uint32 ggep_du;				/**< Daily average uptime, from "DU" */
	const char *ggep_ua;		/**< User-Agent string (atom), from "UA" */
	host_addr_t ggep_ipv6;		/**< IPv6 address */
} rnode_info_t;

/**
 * Request flags to customize the reply we want.
 */

#define RNODE_RQ_GGEP_DU	0x00000001	/**< Include GGEP "DU" */
#define RNODE_RQ_GGEP_LOC	0x00000002	/**< Include GGEP "LOC" */
#define RNODE_RQ_GGEP_IPV6	0x00000004	/**< Include GGEP "6" */
#define RNODE_RQ_GGEP_UA	0x00000008	/**< Include GGEP "UA" */
#define RNODE_RQ_BW_INFO	0x00000010	/**< Include bandwidth information */
#define RNODE_RQ_DROP_INFO	0x00000020	/**< Include TX/RX dropped packets */
#define RNODE_RQ_QHIT_INFO	0x00000040	/**< Include query hit statistics */
#define RNODE_RQ_CPU_INFO	0x00000080	/**< Include CPU statistics */
#define RNODE_RQ_GGEP_GGEP	0x00000100	/**< Include "GGEP" known extensions */
#define RNODE_RQ_GGEP_VMSG	0x00000200	/**< Include "VMSG" known vendor msgs */

/**
 * Remote node operating flags.
 */
#define RNODE_OF_TCP_FW		0x00000001	/**< Is TCP-firewalled */
#define RNODE_OF_UDP_FW		0x00000002	/**< Is UDP-firewalled */
#define RNODE_OF_DHT_ACTIVE	0x00000004	/**< Is an active member of the DHT */
#define RNODE_OF_ANCIENT	0x00000008	/**< Running an ancient version */
#define RNODE_OF_NTP		0x00000010	/**< Time synchronized via NTP */
#define RNODE_OF_HEADLESS	0x00000020	/**< Running headless */
#define RNODE_OF_DHT_PASIVE	0x00000040	/**< Is a passive member of the DHT */
#define RNODE_OF_UDP		0x00000080	/**< Allows UDP traffic */
#define RNODE_OF_DNS_NAME	0x00000100	/**< Advertises public hostname */
#define RNODE_OF_OOB		0x00000200	/**< Requests OOB in its queries */
#define RNODE_OF_OOB_PROXY	0x00000400	/**< Can act as OOB proxy for leaves */
#define RNODE_OF_OOB_REPLY	0x00000800	/**< Can deliver OOB replies */
#define RNODE_OF_UDP_HOLE	0x00001000	/**< Can punch UDP holes though f/w */
#define RNODE_OF_OFFICIAL	0x00002000	/**< Is an official build */

/**
 * Remote bandwidth setting flags.
 */
#define RNODE_BW_STRICT		0x0001		/**< No sharing of b/w between pools */
#define RNODE_BW_IP4_TOS	0x0002		/**< Uses IPv4 TOS */
#define RNODE_BW_UP2UP_BW	0x0004		/**< High UP to UP bandwidth usage */
#define RNODE_BW_UP2LF_BW	0x0008		/**< High UP to leaf bandwidth usage */
#define RNODE_BW_OUT_BW		0x0010		/**< Outgoing b/w saturated */

/**
 * Optional features #1.
 */

#define RNODE_O1_BROWSE		(1 << 0)	/**< Browse host */
#define RNODE_O1_PFSP		(1 << 1)	/**< Partial File Sharing protocol */
#define RNODE_O1_CHAT		(1 << 2)	/**< Chat */
#define RNODE_O1_FW2FW		(1 << 3)	/**< Firewall-to-Firewall transfers */
#define RNODE_O1_PPROXY		(1 << 4)	/**< Push Proxy */
#define RNODE_O1_WHATSNEW	(1 << 5)	/**< "What's New?" queries */
#define RNODE_O1_THEX		(1 << 6)	/**< TTH and THEX */
#define RNODE_O1_MAGNET		(1 << 7)	/**< Magnet URIs */
#define RNODE_O1_UHC		(1 << 8)	/**< Can act as UHC server */
#define RNODE_O1_TCP_DEFL	(1 << 9)	/**< TCP stream compression */
#define RNODE_O1_UDP_DEFL	(1 << 10)	/**< UDP payload compression */
#define RNODE_O1_DYN_QUERY	(1 << 11)	/**< Dynamic querying */
#define RNODE_O1_ACTV_QUEUE	(1 << 12)	/**< Active download queuing */
#define RNODE_O1_PASV_QUEUE	(1 << 13)	/**< Passive download queuing */
#define RNODE_O1_GWC_BOOT	(1 << 14)	/**< GWC-based bootstrapping */
#define RNODE_O1_UHC_BOOT	(1 << 15)	/**< UHC-based bootstrapping */
#define RNODE_O1_QHIT_XML	(1 << 16)	/**< Emits XML meta data in hits */
#define RNODE_O1_TCP_CRAWL	(1 << 17)	/**< Answers to TCP-based crawling */
#define RNODE_O1_UDP_CRAWL	(1 << 18)	/**< Answers to UDP-based crawling */
#define RNODE_O1_UP_QRP		(1 << 19)	/**< Inter-UP QRP tables */
#define RNODE_O1_LARGE_QRT	(1 << 20)	/**< Large QRT (up to 2 MiSlots */
#define RNODE_O1_CHUNKED	(1 << 21)	/**< HTTP/1.1 "chunked" transfers */
#define RNODE_O1_RETRY_AFTER (1 << 22)	/**< HTTP/1.1 "Retry-After" honoured */
#define RNODE_O1_QUERY_SPEED (1 << 23)	/**< Modern "query speed" flags */
#define RNODE_O1_TLS 		(1 << 24)	/**< TLS connections */
#define RNODE_O1_OOB_HITS 	(1 << 25)	/**< OOB hit delivery */
#define RNODE_O1_OOB_PROXY 	(1 << 26)	/**< OOB proxying for leaves */
#define RNODE_O1_BYE 		(1 << 27)	/**< BYE with meaningful messages */
#define RNODE_O1_SWARMING 	(1 << 28)	/**< Download from multiple hosts */
#define RNODE_O1_GGEP 		(1 << 29)	/**< GGEP extensions */
#define RNODE_O1_DL_CE 		(1 << 30)	/**< Content-Encoding nego. for d/l */
#define RNODE_O1_UL_CE 		(1 << 31)	/**< Content-Encoding nego. for u/l */

/**
 * Optional features #2.
 */

#define RNODE_O2_GUESS		(1 << 0)	/**< GUESS queries */
#define RNODE_O2_DHT		(1 << 1)	/**< Gnutella DHT */
#define RNODE_O2_IPv6		(1 << 2)	/**< IPv6 */
#define RNODE_O2_BW_LIMIT	(1 << 3)	/**< Bandwidth limiting */
#define RNODE_O2_GNET_FC	(1 << 4)	/**< Gnutella traffic flow-control */
#define RNODE_O2_HOPS_FC	(1 << 5)	/**< Uses Hops-Flow for flow-control */
#define RNODE_O2_HTTP_HEAD	(1 << 6)	/**< HTTP "HEAD" requests */
#define RNODE_O2_ALIVE		(1 << 7)	/**< Alive ping/pongs */
#define RNODE_O2_PONG_CACHE	(1 << 8)	/**< Pong caching (no ping broadcast) */
#define RNODE_O2_DUP_TTL	(1 << 9)	/**< Forwards dups with higher TTL */
#define RNODE_O2_DYN_HITS	(1 << 10)	/**< Dynamic query hit throttling */
#define RNODE_O2_LEAF_GUIDE	(1 << 11)	/**< Leaf-guided querying */
#define RNODE_O2_OOQ_CHUNK	(1 << 12)	/**< Out-of-Queue small chunk service */

/*
 * XXX this structure should really be inlined in a node,
 * XXX to avoid definition duplication --RAM, 2004-08-21
 */

typedef struct gnet_node_status {
	uchar status;			    /**< See possible values below */

	/* FIXME: the variables below should go to gnet_node_info since they
	 *        only change very seldom
     */
	time_t connect_date;	/**< When we got connected (after handshake) */
	time_t up_date;			/**< When remote server started (0 if unknown) */
	uint32 gnet_files_count;	/**< Amount of files shared */
	uint32 gnet_kbytes_count;	/**< Size of the library, in Kbytes */
	bool gnet_info_known;		/**< Whether previous two values are known */
	bool is_pseudo;				/**< TRUE if it's the pseudo UDP node */

	uint32  sent;				/**< Number of sent packets */
	uint32  received;			/**< Number of received packets */
	uint32  tx_dropped;			/**< Number of packets dropped at TX time */
	uint32  rx_dropped;			/**< Number of packets dropped at RX time */
	uint32  n_bad;				/**< Number of bad packets received */
	uint16  n_dups;				/**< Number of dup messages received (bad) */
	uint16  n_hard_ttl;			/**< Number of hard_ttl exceeded (bad) */
	uint32  n_weird;			/**< Number of weird messages from that node */
	uint32  n_hostile;			/**< Number of messages from hostile IP */
	uint32  n_spam;				/**< Number of messages rated as spam */
	uint32  n_evil;				/**< Number of messages with evil filenames */

    uint squeue_sent;
    uint squeue_count;
    uint mqueue_count;
    uint mqueue_percent_used;
    bool in_tx_flow_control;
    bool in_tx_swift_control;

	/*
	 * Traffic statistics -- RAM, 13/05/2002.
	 */

	uint64 tx_given;			/**< Bytes fed to the TX stack (from top) */
	uint64 tx_deflated;			/**< Bytes deflated by the TX stack */
	uint64 tx_written;			/**< Bytes written by the TX stack */
    uint64 tx_bps;				/**< TX traffic rate */
    bool   tx_compressed;		/**< Is TX traffic compressed */
    float  tx_compression_ratio; /**< TX compression ratio */

	uint64 rx_given;			/**< Bytes fed to the RX stack (from bottom) */
	uint64 rx_inflated;			/**< Bytes inflated by the RX stack */
	uint64 rx_read;				/**< Bytes read from the RX stack */
    uint64  rx_bps;				/**< RX traffic rate */
    bool   rx_compressed;		/**< Is RX traffic compressed */
    float  rx_compression_ratio;/**< RX compression ratio */

	/*
	 * Gnutella statistics -- RAM, 10/12/2003.
	 */

	bool has_qrp;			/**< Whether node is under QRP control */
	float qrp_efficiency;	/**< Queries matched / received on QRP control */
	uint32 rx_queries;		/**< Total amount of queries received */
	uint32 tx_queries;		/**< Total amount of queries sent */
	uint32 rx_qhits;		/**< Total amount of hits received */
	uint32 tx_qhits;		/**< Total amount of hits sent */

	uint qrt_slots;			/**< Amount of slots in leaf's QRT */
	uint qrt_generation;	/**< Generation number */
	uint qrt_fill_ratio;	/**< % of filling */
	uint qrt_pass_throw;	/**< Query limiter pass throw when table filled */

	uint32  rt_avg;			/**< Average ping/pong roundtrip time */
	uint32  rt_last;		/**< Last ping/pong roundtrip time */

	uint32 tcp_rtt;			/**< RTT in ms over TCP */
	uint32 udp_rtt;			/**< RTT in ms over UDP */

    uint    shutdown_remain;	/**< Number of seconds before shutdown */
    char    message[128];		/**< Additional information */
} gnet_node_status_t;

typedef struct gnet_node_info {
    struct nid *node_id;   	/**< Internal node ID */

	struct guid gnet_guid;	/**< Seen on network (can be blank) */

    char *error_str;		/**< To sprintf() error strings with vars */
	const char *vendor;		/**< Vendor information (always UTF-8) */

	int proto_major;		/**< Protocol major number */
	int proto_minor;		/**< Protocol minor number */
	vendor_code_t vcode;	/**< Vendor code (vcode.u32 == 0 when unknown) */
	uint is_pseudo:1;		/**< TRUE if it's the pseudo UDP node */
	uint is_g2:1;			/**< TRUE if this is a G2 node */

	host_addr_t addr;		/**< ip of the node (connected) */
	host_addr_t gnet_addr;	/**< Advertised Gnutella address for connecting */

	uint16 port;			/**< port of the node (connected) */
	uint16 gnet_port;		/**< Advertised Gnutella listening port */
	uint16 country;			/**< Country information */

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
	NODE_P_DHT,					/**< DHT "fake" node (UDP-only traffic) */
	NODE_P_G2HUB,				/**< G2 Hub */
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
	mq_status_t mq_status;
	uint8 hops_flow;
	unsigned incoming:1;
	unsigned writable:1;
	unsigned readable:1;
	unsigned tx_compressed:1;
	unsigned rx_compressed:1;
	unsigned is_push_proxied:1;
	unsigned is_proxying:1;
	unsigned tls:1;
	unsigned tls_upgraded:1;
	unsigned empty_qrt:1;
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

#define GTA_NORMAL_TTL			4		/**< Regular TTL, for hops-flow */

/*
 * Nodes callback definitions
 */
typedef void (*node_added_listener_t) (const struct nid *);
typedef void (*node_removed_listener_t) (const struct nid *);
typedef void (*node_info_changed_listener_t) (const struct nid *);
typedef void (*node_flags_changed_listener_t) (const struct nid *);

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

struct pslist;

void node_add(const host_addr_t addr, uint16, uint32 flags);
void node_g2_add(const host_addr_t addr, uint16, uint32 flags);
void node_add_by_name(const char *host, uint16, uint32 flags);
void node_remove_by_id(const struct nid *node_id);
void node_remove_nodes_by_id(const struct pslist *node_list);
bool node_get_status(const struct nid *node_id, gnet_node_status_t *s);
gnet_node_info_t *node_get_info(const struct nid *node_id);
void node_clear_info(gnet_node_info_t *info);
void node_free_info(gnet_node_info_t *info);
bool node_fill_flags(const struct nid *node_id, gnet_node_flags_t *flags);
bool node_fill_info(const struct nid *node_id, gnet_node_info_t *info);
const char *node_flags_to_string(const gnet_node_flags_t *flags);
const char *node_peermode_to_string(node_peer_t m);


#endif /* CORE_SOURCES */

#endif /* _if_core_nodes_h */
/* vi: set ts=4 sw=4 cindent: */
