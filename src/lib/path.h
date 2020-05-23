/*
 * Copyright (c) 2009, Raphael Manfredi
 * Copyright (c) 2006-2008, Christian Biere
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
 * @ingroup lib
 * @file
 *
 * Path manipulation.
 *
 * @author Raphael Manfredi
 * @date 2009
 * @author Christian Biere
 * @date 2006-2008
 */

#ifndef _path_h_
#define _path_h_

char *make_pathname(const char *dir, const char *file);
char *absolute_pathname(const char *file);
bool path_does_not_exist(const char *pathname);
bool is_absolute_path(const char *pathname);
bool filepath_exists(const char *dir, const char *file);
const char *filepath_basename(const char *pathname);
char *filepath_directory(const char *pathname);

enum special_folder {
	PRIVLIB_PATH = 0,
	NLS_PATH,

	SPECIAL_FOLDER_COUNT
};

typedef const char *(*get_folder_basepath_func_t)(
	enum special_folder which_folder);
void set_folder_basepath_func(get_folder_basepath_func_t func);
const char *get_folder_path(enum special_folder folder);

#endif /* _path_h_ */

/* vi: set ts=4 sw=4 cindent: */
