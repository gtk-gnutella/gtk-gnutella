/*
 * Copyright (c) 2001-2003, Raphael Manfredi
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
 * @ingroup core
 * @file
 *
 * Keep track of which files we send away, and how often.
 *
 * @author Raphael Manfredi
 * @date 2001-2003
 */

#ifndef _core_upload_stats_h_
#define _core_upload_stats_h_

#include "common.h"

struct shared_file;

void upload_stats_clear_all(void);
void upload_stats_close(void);
void upload_stats_file_aborted(const struct shared_file *sf, filesize_t done);
void upload_stats_file_begin(const struct shared_file *sf);
void upload_stats_file_complete(const struct shared_file *sf, filesize_t done);
void upload_stats_file_requested(const struct shared_file *sf);
void upload_stats_flush_if_dirty(void);
void upload_stats_load_history(void);
void upload_stats_enforce_local_filename(const struct shared_file *sf);

#endif /* _core_upload_stats_h_ */
/* vi: set ts=4 sw=4 cindent: */
