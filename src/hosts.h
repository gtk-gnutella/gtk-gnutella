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

#ifndef __hosts_h__
#define __hosts_h__

struct gnutella_host {
	guint32 ip;
	guint16 port;
};

/*
 * Global Data
 */

extern GList *sl_caught_hosts;
extern gint hosts_idle_func;
extern guint32 hosts_in_catcher;
extern gboolean host_low_on_pongs;

/*
 * Global Functions
 */

void host_init(void);
void host_timer(void);
gboolean find_host(guint32, guint16);
void host_remove(struct gnutella_host *);
void host_save_valid(guint32 ip, guint16 port);
void host_add(guint32, guint16, gboolean);
void host_prune_cache();
gboolean host_cache_is_empty(void);
gint host_cache_size(void);
void host_add_semi_pong(guint32 ip, guint16 port);
gint host_fill_caught_array(struct gnutella_host *hosts, gint hcount);
void host_get_caught(guint32 *ip, guint16 *port);
gboolean check_valid_host(guint32, guint16);
void hosts_read_from_file(gchar *, gboolean);
void hosts_write_to_file(gchar *);
void host_clear_cache(void);
void host_shutdown(void);
void host_close(void);

void parse_netmasks(gchar *value);
gboolean find_nearby_host(guint32 *ip, guint16 *port);
gboolean host_is_nearby(guint32 ip);

#endif /* __hosts_h__ */
