/*
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
#define running_topless 1

#define	gui_download_updates_freeze()
#define	gui_download_updates_thaw()

#define	gui_update_files_scanned()
#define	gui_allow_rescan_dir(flag) ((void) flag)
#define search_gui_new_search(query, flags, x) (((query) && (flags)) ? 0 : 0)
#define search_gui_store_searches()

#define upload_stats_gui_add(s) ((void) s)
#define upload_stats_gui_update(s) ((void) s)
#define upload_stats_gui_update_name(s) ((void) s)
#define	upload_stats_gui_clear_all()
#define upload_stats_gui_thaw()
#define upload_stats_gui_freeze()

#define statusbar_gui_warning(sec, fmt, message) g_message((fmt), (message))
#define statusbar_gui_message(sec, fmt, message) g_message((fmt), (message))

#endif /* USE_TOPLESS */

#if defined(USE_GTK1) || defined(USE_GTK2)
extern bool running_topless;
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
gcu_download_gui_updates_freeze(void)
{
	if (!running_topless) {
		gui_download_updates_freeze();
	}
}

void
gcu_download_gui_updates_thaw(void)
{
	if (!running_topless) {
		gui_download_updates_thaw();
	}
}

/** misc. interface functions (CORE -> UI) */
void
gcu_gui_update_files_scanned(void)
{
	if (!running_topless) {
		gui_update_files_scanned();
	}
}

void
guc_allow_rescan_dir(bool flag)
{
	if (!running_topless) {
		gui_allow_rescan_dir(flag);
	}
}

int
gcu_gtk_main_flush(void)
{
#if defined(USE_GTK1) || defined(USE_GTK2)
	if (!running_topless) {
		extern int gtk_main_flush();
		/* Don't include any GTK-related header */
		return gtk_main_flush();
	}
#endif /* GTK */
	return 0;
}

/**	search interface functions (CORE -> UI) */
bool
gcu_search_gui_new_search(const gchar *query, uint32 flags)
{
	if (!running_topless) {
		return search_gui_new_search(query, flags, NULL);
	} else {
		return FALSE;
	}
}

void
gcu_search_gui_store_searches(void)
{
	search_gui_store_searches();
}

/*	upload interface functions (CORE -> UI)*/
void
gcu_upload_stats_gui_add(struct ul_stats *s)
{
	if (!running_topless) {
		upload_stats_gui_add(s);
	}
}

void
gcu_upload_stats_gui_update_name(struct ul_stats *s)
{
	if (!running_topless) {
		upload_stats_gui_update_name(s);
	}
}

void
gcu_upload_stats_gui_update(struct ul_stats *s)
{
	if (!running_topless) {
		upload_stats_gui_update(s);
	}
}

void
gcu_upload_stats_gui_clear_all(void)
{
	if (!running_topless) {
		upload_stats_gui_clear_all();
	}
}

void
gcu_upload_stats_gui_freeze(void)
{
	if (!running_topless) {
		upload_stats_gui_freeze();
	}
}

void
gcu_upload_stats_gui_thaw(void)
{
	if (!running_topless) {
		upload_stats_gui_thaw();
	}
}

/*	statusbar interface functions (CORE -> UI) */
void
gcu_statusbar_warning(const gchar *message)
{
	if (!running_topless) {
		statusbar_gui_warning(15, "%s", message);
	}
}

void
gcu_statusbar_message(const gchar *message)
{
	if (!running_topless) {
		statusbar_gui_message(10, "%s", message);
	}
}

/* vi: set ts=4 sw=4 cindent: */
