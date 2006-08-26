/*
 * $Id$
 *
 * Copyright (c) 2004, Emile Roberts
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

/**
 * @ingroup ui
 * @file
 *
 * Interface core -> UI.
 *
 * @author Emile Roberts
 * @date 2004
 */

#ifndef _if_bridge_c2ui_h_
#define _if_bridge_c2ui_h_

/*
 *	SECTION 1 - Interface includes
 */

#include "if/core/downloads.h"
#include "if/core/uploads.h"
#include "if/core/bitzi.h"

#include "lib/host_addr.h"
#include "lib/misc.h"

/* Property table includes */
#include "if/gui_property.h"

/* Other includes */
#include <glib.h>

/* download interface functions */
void gcu_download_enable_start_now(guint32 running_downloads,
	guint32 max_downloads);
void gcu_gui_update_download(struct download *d, gboolean force);
void gcu_gui_update_download_server(struct download *d);
void gcu_gui_update_download_range(struct download *d);
void gcu_gui_update_download_size(struct download *d);
void gcu_gui_update_download_host(struct download *d);
void gcu_gui_update_download_abort_resume(void);
void gcu_gui_update_download_clear(void);
void gcu_gui_update_download_clear_now(void);
void gcu_gui_update_queue_frozen(void);
void gcu_download_gui_add(struct download *d);
void gcu_download_gui_remove(struct download *d);

/* misc interface functions */
void guc_allow_rescan_dir(gboolean flag);
void gcu_gui_update_files_scanned(void);
gint gcu_gtk_main_flush(void);

/** search interface functions */
gboolean gcu_search_gui_new_search(const gchar *query, flag_t flags);

/* statusbar interface functions */
void gcu_statusbar_warning(const gchar *message);
void gcu_statusbar_message(const gchar *message);

/* upload interface functions */
void gcu_upload_stats_gui_add(struct ul_stats *);
void gcu_upload_stats_gui_update(const gchar *name, guint64 size);
void gcu_upload_stats_gui_clear_all(void);

/** bitzi results */
void gcu_bitzi_result(bitzi_data_t *bitzi_data);

#endif /* _if_bridge_c2ui_h_ */

