#ifndef __nodes_h__
#define __nodes_h__

#include "gnutella.h"

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

struct membuf {
	gchar *data;			/* Where data is held */
	gchar *end;				/* First location beyond buffer */
	gchar *rptr;			/* Read pointer within data */
};

struct gnutella_node {
	gchar error_str[256];		/* To sprintf() error strings with vars */
	struct gnutella_socket *socket;		/* Socket of the node */
	gint proto_major;			/* Protocol major number */
	gint proto_minor;			/* Protocol minor number */

	struct gnutella_header header;		/* Header of the current message */

	guint32 size;	/* How many bytes we need to read for the current message */

	gchar *data;			/* data of the current message */

	guint32 pos;			/* write position in data */

	guchar status;			/* See possible values below */
	gint flags;				/* See possible values below */

	guint32 sent;				/* Number of sent packets */
	guint32 received;			/* Number of received packets */
	guint32 dropped;			/* Number of packets dropped */
	guint32 n_bad;				/* Number of bad packets received */
	guint16 n_dups;				/* Number of dup messages received (bad) */
	guint16 n_hard_ttl;			/* Number of hard_ttl exceeded (bad) */

	guint32 allocated;			/* Size of allocated buffer data, 0 for none */
	gboolean have_header;		/* TRUE if we have got a full message header */

	time_t last_update;			/* Last update of the node in the GUI */
	time_t connect_date;		/* When we got connected (after handshake) */

	const gchar *remove_msg;	/* Reason of removing */

	guint32 ip;					/* ip of the node */
	guint16 port;				/* port of the node */

	gint gdk_tag;				/* gdk tag for write status */
	gchar *sendq;				/* Output buffer */
	guint32 sq_pos;				/* write position in the sendq */
	/* list of ends of packets, so that sent may be kept up to date. */
	GSList *end_of_packets;
	/* The data "pointer" is actually a guint32. */
	/* how many bytes need to be written to reach the end of the last
	 * enqueued end of packet */
	guint32 end_of_last_packet;
	/* any information necessary to route packets associated with this
	   host goes here */
	gpointer routing_data;

	/*
	 * The following are used after a 0.6 handshake.  See comment in
	 * node_process_handshake_ack() to understand how it is used and why.
	 *		--RAM, 23/12/2001
	 */

	gint (*read)(gint, gpointer, gint);	/* Data reading routine */
	struct membuf *membuf;				/* Buffer, which we can read from */

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

	guint32 n_ping_throttle;	/* Number of pings we throttled */
	guint32 n_ping_accepted;	/* Number of pings we accepted */
	guint32 n_ping_special;		/* Number of special pings we received */
	guint32 n_ping_sent;		/* Number of pings we sent to this node */
	guint32 n_pong_received;	/* Number of pongs we received from this node */
	guint32 n_pong_sent;		/* Number of pongs we sent to this node */
};

/*
 * Node flags.
 */

#define NODE_F_HDSK_PING	0x00000001	/* Expecting handshake ping */
#define NODE_F_PING_LIMIT	0x00000002	/* Flags a "NEW" ping limiting node */
#define NODE_F_TMP			0x00000004	/* Temporary, until we send pongs */
#define NODE_F_INCOMING		0x00000008	/* Incoming (permanent) connection */
#define NODE_F_PING_ALIEN	0x00000010	/* We don't know the limiting algo */
#define NODE_F_RETRY_04		0x00000020	/* Retry handshake at 0.4 on failure */
#define NODE_F_VALID		0x00000040	/* We handshaked with a Gnutella node */

/*
 * Node states.
 */

#define GTA_NODE_CONNECTING			1	/* Making outgoing connection */
#define GTA_NODE_HELLO_SENT			2	/* Sent 0.4 hello */
#define GTA_NODE_WELCOME_SENT		3	/* Hello accepted, remote welcomed */
#define GTA_NODE_CONNECTED			4	/* Connected at the Gnet level */
#define GTA_NODE_REMOVING			5	/* Removing node */
#define GTA_NODE_RECEIVING_HELLO	6	/* Receiving 0.6 headers */

/*
 * State inspection macros.
 */

#define NODE_IS_CONNECTING(n)						\
	(	(n)->status == GTA_NODE_CONNECTING			\
	||	(n)->status == GTA_NODE_HELLO_SENT			\
	||	(n)->status == GTA_NODE_WELCOME_SENT		\
	||	(n)->status == GTA_NODE_RECEIVING_HELLO	)

#define NODE_IS_CONNECTED(n) \
	((n)->status == GTA_NODE_CONNECTED)

#define NODE_IS_PONGING_ONLY(n) \
	((n)->flags & NODE_F_TMP)

#define NODE_IS_INCOMING(n)	\
	((n)->flags & (NODE_F_TMP|NODE_F_INCOMING))

/*
 * Global Data
 */

extern const gchar *gnutella_hello;
extern guint32 gnutella_hello_length;

extern GSList *sl_nodes;
extern guint32 global_messages, global_searches, routing_errors,
	dropped_messages;

extern GHookList node_added_hook_list;
extern struct gnutella_node *node_added;

/*
 * Global Functions
 */

void network_init(void);
gboolean on_the_net(void);
gint32 connected_nodes(void);
gint32 node_count(void);
void node_add(struct gnutella_socket *, guint32, guint16);
void node_real_remove(struct gnutella_node *);
void node_remove(struct gnutella_node *, const gchar * reason, ...);
void node_init_outgoing(struct gnutella_node *);
void node_read_connecting(gpointer, gint, GdkInputCondition);
void node_read(gpointer, gint, GdkInputCondition);
void node_write(gpointer, gint, GdkInputCondition);
gboolean node_enqueue(struct gnutella_node *, gchar *, guint32);
void node_enqueue_end_of_packet(struct gnutella_node *);
gboolean node_sent_ttl0(struct gnutella_node *n);
void node_close(void);

#endif /* __nodes_h__ */
