/*
 * $Id$
 *
 * Copyright (c) 2001-2003, Raphael Manfredi, Richard Eckart
 *
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
 */

#ifndef _settings_h_
#define _settings_h_

#include <glib.h>
#include <sys/time.h>		/* for time_t */

/*
 * Global Data
 */

extern struct in_addr *local_netmasks;

/*
 * Global macros.
 */

#define listen_ip()		(force_local_ip ? forced_local_ip : local_ip)


/*
 * Global Functions
 */

void settings_init(void);
void settings_shutdown(void);
void settings_ip_changed(guint32 new_ip);
guint32 settings_max_msg_size(void);
const gchar *settings_config_dir(void);
void settings_close(void);

#endif /* _settings_h_ */
