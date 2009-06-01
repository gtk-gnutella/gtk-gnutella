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
	const char *dir;				/**< File's directory */
	const char *name;				/**< File's basename */
} file_path_t;

/*
 * Public interface.
 */

void file_register_fd_reclaimer(reclaim_fd_t callback);

FILE *file_config_open_read(
	const char *what, const file_path_t *fv, int fvcnt);
FILE *file_config_open_read_norename(
	const char *what, const file_path_t *fv, int fvcnt);
FILE *file_config_open_read_norename_chosen(
	const char *what, const file_path_t *fv, int fvcnt, int *chosen);
FILE *file_config_open_write(const char *what, const file_path_t *fv);
gboolean file_config_close(FILE *out, const file_path_t *fv);

void file_config_preamble(FILE *out, const char *what);
void file_path_set(file_path_t *fp, const char *dir, const char *name);

int file_open(const char *path, int flags, int mode);
int file_open_missing(const char *path, int flags);
int file_create(const char *path, int flags, int mode);
int file_create_missing(const char *path, int flags, int mode);
FILE *file_fopen(const char *path, const char *mode);
FILE *file_fopen_missing(const char *path, const char *mode);

#endif /* _file_ */
/* vi: set ts=4 sw=4 cindent: */
