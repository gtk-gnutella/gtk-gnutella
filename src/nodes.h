#ifndef __nodes_h__
#define __nodes_h__

#include "gnutella.h"

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

	guint32 sent;				/* Number of sent packets */
	guint32 received;			/* Number of received packets */
	guint32 dropped;			/* Number of packets dropped */
	guint32 n_bad;				/* Number of bad packets received */
	guint16 n_dups;				/* Number of dup messages received (bad) */
	guint16 n_hard_ttl;			/* Number of hard_ttl exceeded (bad) */

	guint32 allocated;			/* Size of allocated buffer data, 0 for none */
	gboolean have_header;		/* TRUE if we have got a full message header */

	time_t last_update;	/* Timestamp of last update of the node in the GUI */

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
	 * The following is used after a 0.6 handshake.  See comment in
	 * node_process_handshake_ack() to understand how it is used and why.
	 *		--RAM, 23/12/2001
	 */
	gint (*read)(gint, gpointer, gint);	/* Data reading routine */
	struct membuf *membuf;				/* Buffer, which we can read from */
};

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
	||	(n)->status == GTA_NODE_RECEIVING_HELLO	)

/*
 * Global Data
 */

extern const gchar *gnutella_hello;
extern guint32 gnutella_hello_length;

extern GSList *sl_nodes;
extern guint32 nodes_in_list;
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
void node_add(struct gnutella_socket *, guint32, guint16);
void node_real_remove(struct gnutella_node *);
void node_remove(struct gnutella_node *, const gchar * reason, ...);
void node_init_outgoing(struct gnutella_node *);
void node_read_connecting(gpointer, gint, GdkInputCondition);
void node_read(gpointer, gint, GdkInputCondition);
void node_write(gpointer, gint, GdkInputCondition);
gboolean node_enqueue(struct gnutella_node *, gchar *, guint32);
void node_enqueue_end_of_packet(struct gnutella_node *);
void node_close(void);

#endif /* __nodes_h__ */
