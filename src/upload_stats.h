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
#include "uploads.h"

void upload_stats_load_history(const gchar *);
void upload_stats_dump_history(const gchar *filename, gboolean cleanup);
void upload_stats_flush_if_dirty(void);
void upload_stats_file_begin(const struct upload *u);
void upload_stats_file_aborted(const struct upload *u);
void upload_stats_file_complete(const struct upload *u);
void upload_stats_prune_nonexistent(void);
void upload_stats_clear_all(void);

#endif
