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
 * At this point the interface basically redirects function calls from
 * the ui to the core and vice-versa.
 *
 * @author Emile Roberts
 * @date 2004
 */

#include "c2ui.h"

/* includes core needs to access ui */

#define GUI_SOURCES

#if defined(USE_TOPLESS)
#define gui_update_download(d, force) ((void) d, (void) force)
#define gui_update_download_server(d) ((void) d)
#define gui_update_download_range(d) ((void) d)
#define gui_update_download_size(d) ((void) d)
#define gui_update_download_host(d) ((void) d)
#define gui_update_download_abort_resume()
#define gui_update_download_clear()
#define	gui_update_download_clear_now()

#define	gui_download_updates_freeze()
#define	gui_download_updates_thaw()

#define	download_gui_add(d) ((void) d)
#define	download_gui_remove(d) ((void) d)

#define	gui_update_files_scanned()
#define	gui_allow_rescan_dir(flag) ((void) flag)
#define search_gui_new_search(query, flags, x) (((query) && (flags)) ? 0 : 0)

#define upload_stats_gui_add(s) ((void) s)
#define upload_stats_gui_update(s) ((void) s)
#define	upload_stats_gui_clear_all()
#define upload_stats_gui_thaw()
#define upload_stats_gui_freeze()

#define statusbar_gui_warning(sec, fmt, message) g_message((fmt), (message))
#define statusbar_gui_message(sec, fmt, message) g_message((fmt), (message))

#define bitzi_gui_update(bitzi_data) ((void) bitzi_data)

#endif /* USE_TOPLESS */

#if defined(USE_GTK1) || defined(USE_GTK2)
#include "if/ui/gtk/bitzi.h"
#include "if/ui/gtk/downloads.h"
#include "if/ui/gtk/misc.h"
#include "if/ui/gtk/search.h"
#include "if/ui/gtk/statusbar.h"
#include "if/ui/gtk/uploads.h"
#include "if/ui/gtk/upload_stats.h"
#endif /* GTK */

/*
 * Functions the CORE uses to access the UI
 */

void
gcu_gui_update_download(struct download *d, gboolean force)
{
	gui_update_download(d, force);
}

void
gcu_gui_update_download_server(struct download *d)
{
	gui_update_download_server(d);
}

void
gcu_gui_update_download_range(struct download *d)
{
	gui_update_download_range(d);
}

void
gcu_gui_update_download_size(struct download *d)
{
	gui_update_download_size(d);
}

void
gcu_gui_update_download_host(struct download *d)
{
	gui_update_download_host(d);
}

void
gcu_gui_update_download_abort_resume(void)
{
	gui_update_download_abort_resume();
}

void
gcu_gui_update_download_clear(void)
{
	gui_update_download_clear();
}

void
gcu_gui_update_download_clear_now(void)
{
	gui_update_download_clear_now();
}

void
gcu_download_gui_add(struct download *d)
{
	download_gui_add(d);
}

void
gcu_download_gui_remove(struct download *d)
{
	download_gui_remove(d);
}

void
gcu_download_gui_updates_freeze(void)
{
	gui_download_updates_freeze();
}

void
gcu_download_gui_updates_thaw(void)
{
	gui_download_updates_thaw();
}

/** misc. interface functions (CORE -> UI) */
void
gcu_gui_update_files_scanned(void)
{
	gui_update_files_scanned();
}

void
guc_allow_rescan_dir(gboolean flag)
{
	gui_allow_rescan_dir(flag);
}

gint
gcu_gtk_main_flush(void)
{
#if defined(USE_GTK1) || defined(USE_GTK2)
	extern gint gtk_main_flush();	/* Don't include any GTK-related header */
	return gtk_main_flush();
#else
	return 0;
#endif /* GTK */
}

/**	search interface functions (CORE -> UI) */
gboolean
gcu_search_gui_new_search(const gchar *query, flag_t flags)
{
	return search_gui_new_search(query, flags, NULL);
}


/*	upload interface functions (CORE -> UI)*/
void
gcu_upload_stats_gui_add(const struct ul_stats *s)
{
	upload_stats_gui_add(s);
}

void
gcu_upload_stats_gui_update(const struct ul_stats *s)
{
	upload_stats_gui_update(s);
}

void
gcu_upload_stats_gui_clear_all(void)
{
	upload_stats_gui_clear_all();
}

void
gcu_upload_stats_gui_freeze(void)
{
	upload_stats_gui_freeze();
}

void
gcu_upload_stats_gui_thaw(void)
{
	upload_stats_gui_thaw();
}

/**
 * Bitzi result notification (Core->UI)
 *
 * If the IPC split goes ahead then the data will need to be copied
 * across. For the time being we just pass the pointer.
 */

void
gcu_bitzi_result(bitzi_data_t *bitzi_data)
{
    bitzi_gui_update(bitzi_data);
}

/*	statusbar interface functions (CORE -> UI) */
void
gcu_statusbar_warning(const gchar *message)
{
	statusbar_gui_warning(15, "%s", message);
}

void
gcu_statusbar_message(const gchar *message)
{
	statusbar_gui_message(10, "%s", message);
}

/* vi: set ts=4 sw=4 cindent: */
