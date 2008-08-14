/*
 * $Id$
 *
 * Copyright (c) 2002-2003, Raphael Manfredi
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
 * @ingroup lib
 * @file
 *
 * Miscellaneous common file routines.
 *
 * @author Raphael Manfredi
 * @date 2002-2003
 */

#ifndef _file_h_
#define _file_h_

#include "common.h"

/**
 * This structure is used to identify a file to be saved/restored.
 */
typedef struct {
	const gchar *dir;				/**< File's directory */
	const gchar *name;				/**< File's basename */
} file_path_t;

/*
 * Public interface.
 */

void file_register_fd_reclaimer(reclaim_fd_t callback);

FILE *file_config_open_read(
	const gchar *what, const file_path_t *fv, gint fvcnt);
FILE *file_config_open_read_norename(
	const gchar *what, const file_path_t *fv, gint fvcnt);
FILE *file_config_open_read_norename_chosen(
	const gchar *what, const file_path_t *fv, gint fvcnt, gint *chosen);
FILE *file_config_open_write(const gchar *what, const file_path_t *fv);
gboolean file_config_close(FILE *out, const file_path_t *fv);

void file_config_preamble(FILE *out, const gchar *what);
void file_path_set(file_path_t *fp, const char *dir, const char *name);

gint file_open(const gchar *path, gint flags, gint mode);
gint file_open_missing(const gchar *path, gint flags);
gint file_create(const gchar *path, gint flags, gint mode);
gint file_create_missing(const gchar *path, gint flags, gint mode);
FILE *file_fopen(const gchar *path, const gchar *mode);
FILE *file_fopen_missing(const gchar *path, const gchar *mode);

void file_set_nonblocking(gint fd);
void file_close(int *);

#endif /* _file_ */
/* vi: set ts=4 sw=4 cindent: */
