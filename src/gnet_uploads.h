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

#ifndef _gnet_uploads_h_
#define _gnet_uploads_h_

#include "common.h"
#include "ui_core_interface_gnet_upload_defs.h"


void upload_add_upload_added_listener(upload_added_listener_t);
void upload_remove_upload_added_listener(upload_added_listener_t);
void upload_add_upload_removed_listener(upload_removed_listener_t);
void upload_remove_upload_removed_listener(upload_removed_listener_t);
void upload_add_upload_info_changed_listener
    (upload_info_changed_listener_t);
void upload_remove_upload_info_changed_listener
    (upload_info_changed_listener_t);

/*
 * Uploads public interface
 */
gnet_upload_info_t *upload_get_info(gnet_upload_t);
void upload_free_info(gnet_upload_info_t *);
void upload_get_status(gnet_upload_t u, gnet_upload_status_t *s);
void upload_kill(gnet_upload_t);




#endif /* _gnet_uploads_h_ */
