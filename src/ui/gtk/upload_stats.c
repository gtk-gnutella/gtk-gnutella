/*
 * Copyright (c) 2009, Raphael Manfredi
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
 * @ingroup gtk
 * @file
 *
 * Common routines for upload statistics display.
 *
 * @author Raphael Manfredi
 * @date 2009
 */

#include "gui.h"

#include "upload_stats.h"
#include "notebooks.h"

#include "lib/glib-missing.h"
#include "lib/override.h"		/* Must be the last header included */

#define UPDATE_MIN		60		/**< Update screen every minute at least */
#define UPDATE_LOOKING	5		/**< Every 5 seconds when they're looking */

/**
 * This table holds all the pending updates, which are buffered and
 * displayed only periodically, to avoid too frequent updates of the GUI
 * structures, and costly operations when the columns are sorted.
 */
static GHashTable *pending;

static gboolean
upload_stats_gui_is_visible(void)
{
	return main_gui_window_visible() &&
		nb_main_page_uploads_stats == main_gui_notebook_get_page();
}

/**
 * Buffer the update of statistics for a given file.
 */
void
upload_stats_gui_update(struct ul_stats *us)
{
	/*
	 * This works because the "us" structure is allocated by the core and is
	 * associated to one single upload.  It is always the same structure that
	 * is being passed for a given upload.
	 */

	if (!g_hash_table_lookup(pending, us))
		g_hash_table_insert(pending, us, GINT_TO_POINTER(1));
}

static gboolean
upload_stats_update_model(gpointer key, gpointer uvalue, gpointer udata)
{
	(void) uvalue;
	(void) udata;

	upload_stats_gui_update_model(key);
	return TRUE;
}

static void
upload_stats_gui_update_if_required(time_t now)
{
	static time_t last_update;
	time_delta_t delta;
	time_delta_t threshold;

	/*
	 * If nobody is watching, don't update unless UPDATE_MIN has passed.
	 * If they are watching, only update every UPDATE_LOOKING seconds.
	 */

	delta = last_update ? delta_time(now, last_update) : UPDATE_MIN;
	threshold = upload_stats_gui_is_visible() ? UPDATE_LOOKING : UPDATE_MIN;

	if (delta >= threshold) {
		last_update = now;
		upload_stats_gui_freeze();
		g_hash_table_foreach_remove(pending, upload_stats_update_model, NULL);
		upload_stats_gui_thaw();
	}
}

static void
upload_stats_common_gui_timer(time_t now)
{
	upload_stats_gui_update_if_required(now);
}

void
upload_stats_common_gui_init(void)
{
	pending = g_hash_table_new(NULL, NULL);
	main_gui_add_timer(upload_stats_common_gui_timer);
}

void
upload_stats_common_gui_shutdown(void)
{
	gm_hash_table_destroy_null(&pending);
}

/* vi: set ts=4 sw=4 cindent: */
