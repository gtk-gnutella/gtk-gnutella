/*
 * $Id$
 *
 * Copyright (c) 2004, Emile Roberts
 *	
 * Interface core -> UI
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


/*
 *	At this point the interface basically redirects function calls from the ui 
 *	to the core and vice-versa.
 */

#include "c2ui.h"

/* includes core needs to access ui */

#define GUI_SOURCES

#include "if/ui/gtk/downloads.h"
#include "if/ui/gtk/misc.h"
#include "if/ui/gtk/search.h"
#include "if/ui/gtk/statusbar.h"
#include "if/ui/gtk/upload_stats.h"

/*
 * Functions the CORE uses to access the UI
 */

/*	download interface functions (CORE -> UI)*/
void gcu_download_enable_start_now(guint32 running_downloads, 
	guint32 max_downloads)
{
	gui_download_enable_start_now(running_downloads, max_downloads);
}

void gcu_gui_update_download(download_t *d, gboolean force)
{
	gui_update_download(d, force);
}
	
void gcu_gui_update_download_server(struct download *d)
{
	gui_update_download_server(d);
}

void gcu_gui_update_download_range(struct download *d)
{
	gui_update_download_range(d);
}

void gcu_gui_update_download_host(struct download *d)
{
	gui_update_download_host(d);	
}

void gcu_gui_update_download_abort_resume(void)
{
	gui_update_download_abort_resume();
}

void gcu_gui_update_download_clear(void)
{
	gui_update_download_clear();
}

void gcu_gui_update_download_clear_now(void)
{
	gui_update_download_clear_now();
}

void gcu_gui_update_queue_frozen(void)
{
	gui_update_queue_frozen();
}

void gcu_download_gui_add(struct download *d)
{
	download_gui_add(d);
}

void gcu_download_gui_remove(struct download *d)
{
	download_gui_remove(d);
}


/*	misc. interface functions (CORE -> UI)*/
void gcu_gui_update_files_scanned(void)
{
	gui_update_files_scanned();
}

void guc_allow_rescan_dir(gboolean flag)
{
	gui_allow_rescan_dir(flag);
}

gint gcu_gtk_main_flush(void)
{
	extern gint gtk_main_flush();	/* Don't include any GTK-related header */
	return gtk_main_flush();
}


/*	dearch interface functions (CORE -> UI)*/
gboolean gcu_search_gui_new_search(const gchar *query, flag_t flags)
{
	return search_gui_new_search(query, flags, NULL);
}


/*	upload interface functions (CORE -> UI)*/
void gcu_upload_stats_gui_add(struct ul_stats *stat)
{
	upload_stats_gui_add(stat);
}

void gcu_upload_stats_gui_update(const gchar *name, guint64 size)
{
	upload_stats_gui_update(name, size);
}

void gcu_upload_stats_gui_clear_all(void)
{
	upload_stats_gui_clear_all();	
}

/*	statusbar interface functions (CORE -> UI)*/
void gcu_statusbar_warning(const gchar *message)
{
	statusbar_gui_warning(15, message);
}

