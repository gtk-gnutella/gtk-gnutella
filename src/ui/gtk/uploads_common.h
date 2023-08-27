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
 *      51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *----------------------------------------------------------------------
 */

#ifndef _gtk_uploads_common_h_
#define _gtk_uploads_common_h_

#include "common.h"
#include "uploads.h"    /* For upload_row_data_t */

#include "lib/host_addr.h"

#include "if/ui/gtk/uploads.h"

gdouble uploads_gui_progress(const gnet_upload_status_t *u,
		const upload_row_data_t *data);
const gchar *uploads_gui_status_str(const gnet_upload_status_t *u,
		const upload_row_data_t *data);
gboolean upload_should_remove(time_t now, const upload_row_data_t *ul);
const gchar *uploads_gui_host_string(const gnet_upload_info_t *u);
void uploads_gui_browse_host(host_addr_t addr, guint16 port);
upload_row_data_t *uploads_gui_get_row_data(gnet_upload_t uhandle);

gboolean uploads_gui_update_required(time_t now);

#endif /* _gtk_uploads_common_h_ */

/* vi: set ts=4 sw=4 cindent: */
