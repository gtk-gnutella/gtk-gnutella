/*
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
bool file_exists(const char *pathname);

char *file_locate_from_path(const char *argv0);
char *file_program_path(const char *argv0);

FILE *file_config_open_read(
	const char *what, const file_path_t *fv, int fvcnt);
FILE *file_config_open_read_chosen(
	const char *what, const file_path_t *fv, int fvcnt, int *chosen);
FILE *file_config_open_read_norename(
	const char *what, const file_path_t *fv, int fvcnt);
FILE *file_config_open_read_norename_chosen(
	const char *what, const file_path_t *fv, int fvcnt, int *chosen);
FILE *file_config_open_write(const char *what, const file_path_t *fv);
bool file_config_close(FILE *out, const file_path_t *fv);
int file_sync_fclose(FILE *f);

void file_config_preamble(FILE *out, const char *what);
void file_path_set(file_path_t *fp, const char *dir, const char *name);
const char *file_oflags_to_string(int flags);
const char *file_accmode_to_string(const int accmode) G_CONST;

int file_open(const char *path, int flags, int mode);
int file_open_silent(const char *path, int flags, int mode);
int file_absolute_open(const char *path, int flags, int mode);
int file_absolute_open_silent(const char *path, int flags, int mode);
int file_open_missing(const char *path, int flags);
int file_open_missing_silent(const char *path, int flags);
int file_create(const char *path, int flags, int mode);
int file_create_missing(const char *path, int flags, int mode);
FILE *file_fopen(const char *path, const char *mode);
FILE *file_fopen_missing(const char *path, const char *mode);

/*
 * File line predicates.
 */

bool file_line_chomp_tail(char *line, size_t size, size_t *lenptr);

/**
 * Is line a comment?
 */
static inline ALWAYS_INLINE bool G_PURE
file_line_is_comment(const char * const line)
{
	return '#' == line[0];
}

/**
 * Is line empty?
 */
static inline ALWAYS_INLINE bool G_PURE
file_line_is_empty(const char * const line)
{
	return '\0' == line[0];
}

static inline ALWAYS_INLINE bool G_PURE
file_line_is_skipable(const char * const line)
{
	return file_line_is_comment(line) || file_line_is_empty(line);
}

#endif /* _file_ */

/* vi: set ts=4 sw=4 cindent: */
