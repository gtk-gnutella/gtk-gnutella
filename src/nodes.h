#ifndef __nodes_h__
#define __nodes_h__

#include "gnutella.h"

struct gnutella_node {
	gchar error_str[256];		/* To sprintf() error strings with vars */
	struct gnutella_socket *socket;		/* Socket of the node */

	struct gnutella_header header;		/* Header of the current message */

	guint32 size;	/* How many bytes we need to read for the current message */

	gchar *data;			/* data of the current message */

	guint32 pos;			/* write position in data */

	/* GNUTELLA_HELLO_SENT | GNUTELLA_HELLO_RECEIVED |
	   GNUTELLA_CONNECTED | GNUTELLA_ */
	guchar status;

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
};

/*
 * Global Data
 */

extern const gchar *gnutella_hello;

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
struct gnutella_node *node_add(struct gnutella_socket *, guint32, guint16);
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
