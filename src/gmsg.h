/*
 * Copyright (c) 2002, Raphael Manfredi
 *
 * Gnutella Messages.
 */

#ifndef __gmsg_h__
#define __gmsg_h__

struct gnutella_node;
struct route_dest;

/*
 * Public interface
 */

void gmsg_init(void);
gchar *gmsg_name(gint function);

void gmsg_sendto_one(struct gnutella_node *n, guchar *msg, guint32 size);
void gmsg_ctrl_sendto_one(struct gnutella_node *n, guchar *msg, guint32 size);
void gmsg_split_sendto_one(struct gnutella_node *n,
	guchar *head, guchar *data, guint32 size);
void gmsg_sendto_all(GSList *l, guchar *msg, guint32 size);
void gmsg_split_sendto_all_but_one(GSList *l, struct gnutella_node *n,
	guchar *head, guchar *data, guint32 size);
void gmsg_sendto_route(struct gnutella_node *n, struct route_dest *rt);

gboolean gmsg_can_drop(gpointer pdu, gint size);
gint gmsg_cmp(gpointer pdu1, gpointer pdu2);
gchar *gmsg_infostr(gpointer head);
void gmsg_log_dropped(gpointer head, gchar *reason, ...);

#endif	/* __gmsg_h__ */

/* vi: set ts=4: */
