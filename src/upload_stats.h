/*
 * $Id$
 *
 * Copyright (c) 2001-2002, Raphael Manfredi
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

#ifndef __upload_stats_h__
#define __upload_stats_h__

#include <glib.h>
#include <gtk/gtk.h>

#include "uploads.h"

gint compare_ul_size(GtkCList *, gconstpointer, gconstpointer);
gint compare_ul_attempts(GtkCList *, gconstpointer, gconstpointer);
gint compare_ul_complete(GtkCList *, gconstpointer, gconstpointer);
gint compare_ul_norm(GtkCList *, gconstpointer, gconstpointer);
void ul_stats_load_history(const gchar *);
void ul_stats_dump_history(const gchar *filename, gboolean cleanup);
void ul_flush_stats_if_dirty(void);
void ul_stats_file_begin(const struct upload *u);
void ul_stats_file_aborted(const struct upload *u);
void ul_stats_file_complete(const struct upload *u);
void ul_stats_prune_nonexistant();
void ul_stats_clear_all();

/*
 * GUI column indices.
 */

#define UL_STATS_FILE_IDX		0
#define UL_STATS_SIZE_IDX		1
#define UL_STATS_ATTEMPTS_IDX	2
#define UL_STATS_COMPLETE_IDX	3
#define UL_STATS_NORM_IDX		4

#endif
