/*
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

#ifndef __misc_h__
#define __misc_h__

#include <time.h>
#include "nodes.h"
#include "downloads.h"

#define SIZE_FIELD_MAX 64		/* Max size of sprintf-ed size quantity */


/*
 * Some useful macros.
 */

/* Set/clear binary flags */
#define set_flags(r,f) (r = r | (f))
#define clear_flags(r,f) (r = r & ~(f))

#define SORT_ASC  1
#define SORT_DESC -1
#define SORT_NONE 0

/*
 * Some common types
 */
typedef guint16 flag_t;

/*
 * Global Functions
 */
gboolean file_exists(gchar *);
gchar *ip_to_gchar(guint32);
gchar *ip_port_to_gchar(guint32, guint16);
guint32 gchar_to_ip(gchar *);
gboolean gchar_to_ip_port(gchar *str, guint32 *ip, guint16 *port);
guint32 host_to_ip(gchar *);
gint str_chomp(gchar *str, gint len);
gboolean is_private_ip(guint32 ip);
gchar *node_ip(struct gnutella_node *);
void message_dump(struct gnutella_node *);
gboolean is_directory(gchar *);
gchar *guid_hex_str(guchar *guid);
gint hex2dec(gchar c);
void hex_to_guid(gchar *hexguid, guchar *guid);
gchar *date_to_iso_gchar(time_t date);
gchar *date_to_rfc822_gchar(time_t date);
gchar *date_to_rfc822_gchar2(time_t date);
gchar *sha1_base32(const guchar *sha1);
guchar *base32_sha1(const gchar *base32);
void dump_hex(FILE *, gchar *, gchar *, gint);
gchar *short_size(guint32);
gchar *short_kb_size(guint32);
gchar *compact_size(guint32 size);
gchar *short_time(guint32 s);
gchar *short_uptime(guint32 s);
guint32 random_value(guint32 max);
void strlower(gchar *, gchar *);
guchar *strcasestr(const guchar *haystack, const guchar *needle);
gchar *build_url_from_download(struct download *d);

#endif /* __misc_h__ */
