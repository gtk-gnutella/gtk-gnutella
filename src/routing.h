#ifndef __routing_h__
#define __routing_h__

/*
 * Global Functions
 */

void routing_init(void);
void routing_close(void);
void generate_new_muid(guchar *muid, gboolean modern);
void message_set_muid(struct gnutella_header *header, gboolean modern);
gboolean route_message(struct gnutella_node **);
void routing_node_remove(struct gnutella_node *);
void sendto_one(struct gnutella_node *, guchar *, guchar *, guint32);
void sendto_all_but_one(struct gnutella_node *, guchar *, guchar *,
						guint32);
void sendto_all(guchar *, guchar *, guint32);
void message_add(guchar *, guint8, struct gnutella_node *);
struct gnutella_node *route_towards_guid(guchar *guid);

#endif /* __routing_h__ */
