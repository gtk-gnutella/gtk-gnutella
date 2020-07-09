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
 *      51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
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

#include "lib/hset.h"
#include "lib/override.h"		/* Must be the last header included */

#define UPDATE_MIN		60		/**< Update screen every minute at least */
#define UPDATE_LOOKING	5		/**< Every 5 seconds when they're looking */

/**
 * This set holds all the pending updates, which are buffered and
 * displayed only periodically, to avoid too frequent updates of the GUI
 * structures, and costly operations when the columns are sorted.
 */
static hset_t *pending;

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

	hset_insert(pending, us);
}

/**
 * Clear statistics.
 */
void
upload_stats_gui_clear_all(void)
{
	/*
	 * After clearing the model we also forget about all pending updates since
	 * the core will free up all the "ul_stats" structures.
	 */

	upload_stats_gui_clear_model();
	hset_clear(pending);
}

static bool
upload_stats_update_model(const void *key, void *udata)
{
	(void) udata;

	upload_stats_gui_update_model(deconstify_pointer(key));
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
		hset_foreach_remove(pending, upload_stats_update_model, NULL);
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
	pending = hset_create(HASH_KEY_SELF, 0);
	main_gui_add_timer(upload_stats_common_gui_timer);
}

void
upload_stats_common_gui_shutdown(void)
{
	hset_free_null(&pending);
}

/* vi: set ts=4 sw=4 cindent: */
