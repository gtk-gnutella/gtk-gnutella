/*
 * Copyright (c) 2002, Vidar Madsen
 *
 * Functions for keeping a whitelist of nodes we always allow in,
 * and whom we try to keep a connection to.
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

#ifndef _whitelist_h_
#define _whitelist_h_

/* Number of seconds between each connection attempt to a whitelisted node. */
#define WHITELIST_RETRY_DELAY 30

/* Number of seconds between checking the whitelist file for updates. */
#define WHITELIST_CHECK_INTERVAL 60

struct whitelist {
    guint32 ip;
    guint16 port;
    guint32 netmask;
    time_t last_try;
};

gboolean whitelist_check(guint32 ip);
void whitelist_init(void);
void whitelist_close(void);
int whitelist_connect(void);
void whitelist_reload(void);

#endif /* _whitelist_h_ */
