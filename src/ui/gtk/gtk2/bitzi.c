/*
 * $Id$
 *
 * Copyright (c) 2004, Alex Bennee <alex@bennee.com>
 *
 * Bitzi search code
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

#include "gtk/gui.h"

RCSID("$Id$");

#include "gtk/search.h"		/* search_t */
#include "gtk/misc.h"		/* gui_record_sha1_eq() */
#include "gtk/gtk-missing.h"

#include "if/bridge/ui2c.h"
#include "lib/override.h"	/* Must be the last header included */

/*
 ** GUI Actions
 */

void
on_search_meta_data_activate(GtkMenuItem *menuitem, gpointer user_data)
{
#ifdef HAS_LIBXML2
	search_t *search;
	GtkTreeSelection *selection;
	GSList *sl;

	g_message("on_search_meta_data_active: called");

	/* collect the list of files selected */

	search = search_gui_get_current_search();
	g_assert(search != NULL);

	selection = gtk_tree_view_get_selection(GTK_TREE_VIEW(search->tree_view));

	sl = tree_selection_collect_data(selection, gui_record_sha1_eq);

	/* Queue up our requests */
	g_message("on_search_meta_data: %d items",
		g_slist_position(sl, g_slist_last(sl)) + 1);

	g_slist_foreach(sl, (GFunc) guc_bitzi_queue_metadata_search, NULL);
	g_slist_free(sl);

	/* Kick off requests if nothing happening */
	if (!guc_bitzi_has_pending())
		guc_bitzi_metadata_query(NULL);
#endif	/* HAS_LIBXML2 */
}

/* vi: set ts=4 sw=4 cindent: */
