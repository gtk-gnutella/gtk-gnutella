#ifndef __misc_h__
#define __misc_h__

#include "nodes.h"

/*
 * Global Functions
 */

gchar *ip_to_gchar(guint32);
gchar *ip_port_to_gchar(guint32, guint16);
guint32 gchar_to_ip(gchar *);
guint32 host_to_ip(gchar *);
gboolean is_private_ip(guint32 ip);
gchar *node_ip(struct gnutella_node *);
void message_dump(struct gnutella_node *);
gboolean is_directory(gchar *);
gchar *guid_hex_str(guchar *guid);
void dump_hex(FILE *, gchar *, gchar *, gint);
gchar *short_size(guint32);
void strlower(gchar *, gchar *);

#endif /* __misc_h__ */
