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

#ifndef _gnet_downloads_h_
#define _gnet_downloads_h_

#include "ui_core_interface_fileinfo_defs.h"
#include "ui_core_interface_gnet_download_defs.h"

/***
 *** Sources (downloads)
 ***/

/* FIXME: download_index_changed
 *        actually needs to be in downloads.h and should be called from
 *        search.h and not from search_gui.h.
 */
void download_index_changed(guint32, guint16, gchar *, guint32, guint32);
  
gboolean download_new(gchar *,
	guint32, guint32, guint32, guint16, gchar *, gchar *, gchar *, time_t,
    gboolean, struct dl_file_info *, gnet_host_vec_t *);
void download_auto_new(gchar *,
 	guint32, guint32, guint32, guint16, gchar *, gchar *, gchar *, time_t,
    gboolean, gboolean, struct dl_file_info *, gnet_host_vec_t *);
void download_index_changed(guint32, guint16, gchar *, guint32, guint32);

void src_add_listener(src_listener_t, gnet_src_ev_t, frequency_t, guint32);
void src_remove_listener(src_listener_t, gnet_src_ev_t);
struct download *src_get_download(gnet_src_t src_handle);


/***
 *** Fileinfo
 ***/
void fi_add_listener(fi_listener_t, gnet_fi_ev_t, frequency_t, guint32);
void fi_remove_listener(fi_listener_t, gnet_fi_ev_t);

gnet_fi_info_t *fi_get_info(gnet_fi_t);
void fi_free_info(gnet_fi_info_t *);
void fi_get_status(gnet_fi_t, gnet_fi_status_t *);
GSList *fi_get_chunks(gnet_fi_t);
void fi_free_chunks(GSList *chunks);
gchar **fi_get_aliases(gnet_fi_t fih);

void fi_purge_by_handle_list(GSList *list);
gboolean fi_purge(gnet_fi_t fih);



#endif /* _gnet_downloads_h_ */
