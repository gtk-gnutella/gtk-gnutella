/*
 * $Id$
 *
 * Copyright (c) 2001-2003, Raphael Manfredi, Richard Eckart
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

#ifndef _gnet_stats_gui_common_h_
#define _gnet_stats_gui_common_h_

#include "config.h"
#include "gnet.h"		/* XXX -- for the sizes of the arrays below */

#include <glib.h> 

extern const gchar *msg_type_str[MSG_TYPE_COUNT];
extern const gchar *msg_drop_str[MSG_DROP_REASON_COUNT];
extern const gchar *general_type_str[GNR_TYPE_COUNT];

#endif /* _gnet_stats_gui_common_h_ */
