/*
 * $Id$
 *
 * Copyright (c) 2001-2003, Raphael Manfredi
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

#ifndef _gnutella_h_
#define _gnutella_h_

#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>	/* For ntohl(), htonl() */

#include "gnet.h"
#include "gnet_property_priv.h"
#include "ui_core_interface_gnutella_defs.h"


/* main.c */

extern struct gnutella_socket *s_tcp_listen;
extern struct gnutella_socket *s_udp_listen;
extern gchar *start_rfc822_date;

#endif							/* _gnutella_h_ */

/* vi: set ts=4: */
