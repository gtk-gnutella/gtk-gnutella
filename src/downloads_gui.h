/*
 * $Id$
 *
 * Copyright (c) 2001-2003, Richard Eckart
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

#ifndef _downloads_gui_h_
#define _downloads_gui_h_

#include "gui.h"
#include "downloads_gui_common.h"

/* Indicates that a dl node is a header node */
#define DL_GUI_IS_HEADER -1		 

/*
 * Global Functions
 */

void downloads_gui_init(void);
void downloads_gui_shutdown(void);


void download_gui_add(struct download *d);
void download_gui_remove(struct download *d);
	
void gui_update_download(struct download *, gboolean);
void gui_update_download_server(struct download *);
void gui_update_download_range(struct download *d);
void gui_update_download_host(struct download *d);

void gui_update_download_abort_resume(void);


#endif /* _downloads_gui_h_ */
