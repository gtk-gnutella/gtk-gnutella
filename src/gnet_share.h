/*
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

#ifndef _gnet_share_h_
#define _gnet_share_h_

#include "common.h"

/***
 *** Sharing
 ***/

/*
 * Search query types
 */
typedef enum {
    QUERY_STRING,
    QUERY_SHA1
} query_type_t;

/*
 * Sharing callbacks
 */
typedef void (*search_request_listener_t) (
    query_type_t, const gchar *query, guint32, guint16);

void share_add_search_request_listener(search_request_listener_t l);
void share_remove_search_request_listener(search_request_listener_t l);

#endif /* _gnet_share_h_ */
