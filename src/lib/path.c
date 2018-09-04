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
 *      59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
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

#include "common.h"

#include "ascii.h"
#include "concat.h"
#include "halloc.h"
#include "hstrfn.h"
#include "log.h"				/* For s_error() */
#include "misc.h"
#include "omalloc.h"
#include "path.h"
#include "spinlock.h"

#include "override.h"			/* Must be the last header included */

static const char *get_folder_basepath(enum special_folder folder);

static get_folder_basepath_func_t get_folder_basepath_func =
	get_folder_basepath;

/**
 * Create new pathname from the concatenation of the dirname and the basename
 * of the file. A directory separator is inserted, unless "dir" already ends
 * with one or "file" starts with one.
 *
 * @param dir	the directory path
 * @param file	the filename
 *
 * @return a newly allocated string that must be freed with hfree().
 */
char *
make_pathname(const char *dir, const char *file)
{
	const char *sep;
	size_t n;

	g_assert(dir);
	g_assert(file);

	n = vstrlen(dir);

	if (G_DIR_SEPARATOR == file[0] || '/' == file[0])
		sep = "";
	else if (n > 0 && G_DIR_SEPARATOR == dir[n - 1])
		sep = "";
	else if (G_DIR_SEPARATOR != '/' && n > 0 && '/' == dir[n - 1])
		sep = "";
	else if (G_DIR_SEPARATOR != '/' && vstrchr(dir, G_DIR_SEPARATOR))
		sep = G_DIR_SEPARATOR_S;
	else
		sep = "/";

	return h_strconcat(dir, sep, file, NULL_PTR);
}

/**
 * Create an absolute path.
 * The resulting string must be freed with hfree().
 */
char *
absolute_pathname(const char *file)
{
	g_assert(file != NULL);

	if (is_absolute_path(file)) {
		return h_strdup(file);
	} else if ('\0' == file[0]) {
		return NULL;
	} else {
		char buf[4096], *ret;

		ret = getcwd(ARYLEN(buf));
		return ret ? make_pathname(ret, file) : NULL;
	}
}

/**
 * Check that given path does not exist.
 */
bool
path_does_not_exist(const char *pathname)
{
	filestat_t st;

	g_assert(pathname != NULL);
	return stat(pathname, &st) && ENOENT == errno;
}

/**
 * Check whether path is an absolute path.
 */
bool
is_absolute_path(const char *path)
{
	g_assert(path != NULL);

	if (is_dir_separator(path[0]))
		return TRUE;

	/* On Windows also check for something like C:\ and x:/ */
	return is_running_on_mingw() &&
			is_ascii_alpha(path[0]) &&
			':' == path[1] &&
			is_dir_separator(path[2]);
}

/**
 * Check whether file given by its dirname and its basename exists.
 */
bool
filepath_exists(const char *dir, const char *file)
{
	filestat_t buf;
	bool exists;
	char *path;

	path = make_pathname(dir, file);
	exists = 0 == stat(path, &buf);
	HFREE_NULL(path);

	return exists;
}

/**
 * Returns a pointer to the basename of the given pathname. A slash is
 * always considered a valid separator but G_DIR_SEPARATOR is considered as
 * well. Thus "/whatever/blah\\yadda" returns a pointer to yadda iff
 * G_DIR_SEPARATOR is a backslash and otherwise points to "blah[...]".
 *
 * @param pathname A pathname to extract basename from. This may be a relative
 *			path or just a basename.
 * @return	A pointer to the basename of "pathname". The pointer points into
 *			the buffer holding pathname.
 */
const char *
filepath_basename(const char *pathname)
{
	const char *p;

	g_assert(pathname);

	p = strrchr(pathname, '/');
	if (p) {
		p++;
	} else {
		p = pathname;
	}
	if (G_DIR_SEPARATOR != '/') {
		const char *q = strrchr(p, G_DIR_SEPARATOR);
		if (q)
			p = &q[1];
	}
	return p;
}

static const char *
filepath_directory_end(const char *pathname, char separator)
{
	const char *p;

	p = strrchr(pathname, separator);
	if (p) {
		while (p != pathname && is_dir_separator(p[-1])) {
			p--;
		}
	}
	return p;
}

/**
 * Creates a copy with the given pathname with the basename cut off. A slash
 * is always considered a separator but G_DIR_SEPARATOR is considered as
 * well. Thus "/whatever/blah\\yadda" returns "/whatever/blah" if G_DIR_SEPARATOR
 * is a backslash, otherwise "/whatever" is returned.
 *
 * @return	A newly allocated string holding the given pathname with the
 *			basename cut off. If the string contained no directory separator,
 *			NULL is returned.  The string must be freed via hfree().
 */
char *
filepath_directory(const char *pathname)
{
	const char *sep;
	char *dir;

	sep = filepath_directory_end(pathname, '/');
	if (G_DIR_SEPARATOR != '/') {
		const char *alt;

		alt = filepath_directory_end(pathname, G_DIR_SEPARATOR);
		if (sep && alt) {
			sep = (sep - pathname > alt - pathname) ? sep : alt;
		} else if (alt) {
			sep = alt;
		}
	}
	if (sep == pathname) {
		dir = h_strdup(G_DIR_SEPARATOR_S);
	} else if (sep) {
		dir = h_strndup(pathname, sep - pathname);
	} else {
		dir = NULL;
	}
	return dir;
}

/**
 * Get special folder path.
 *
 * @note
 * Our caller handles the caching so that it is guaranteed that we will be
 * called just once per folder type.
 *
 * @return pointer to static string, NULL if folder does not exist.
 */
static const char *
get_folder_basepath(enum special_folder folder)
{
	char *special_path = NULL;
	char *pathname = NULL;

	switch (folder) {
	case PRIVLIB_PATH:
		special_path = getenv("XDG_DATA_DIRS");

		if (special_path != NULL) {
			if (is_absolute_path(special_path)) {
				pathname = omalloc(MAX_PATH_LEN);
				concat_strings(pathname, MAX_PATH_LEN,
					special_path, G_DIR_SEPARATOR_S, PACKAGE,
					NULL_PTR);
			} else {
				s_warning("ignoring environment variable XDG_DATA_DIRS: "
					"holds non-absolute path \"%s\"", special_path);
			}
		}
		special_path = pathname;
		break;
	case NLS_PATH:
		pathname = getenv("NLSPATH");

		if (pathname != NULL && !is_absolute_path(pathname)) {
			s_warning("ignoring environment variable NLSPATH: "
				"holds non-absolute path \"%s\"", pathname);
			pathname = NULL;
		}

		if (NULL == pathname)
			pathname = LOCALE_EXP;

		special_path = pathname;
		break;
	case SPECIAL_FOLDER_COUNT:
		g_assert_not_reached();
	}

	return special_path;
}

void
set_folder_basepath_func(get_folder_basepath_func_t func)
{
	get_folder_basepath_func = func;
}

/**
 * @return name of special folder.
 */
static char *
special_folder_name(enum special_folder folder)
{
	switch (folder) {
	case PRIVLIB_PATH:	return "PRIVLIB_PATH";
	case NLS_PATH:		return "NLS_PATH";
	case SPECIAL_FOLDER_COUNT:	break;
	}

	g_assert_not_reached();
	return NULL;
}

/**
 * Compute special folder path.
 *
 * @param folder	the special folder token
 *
 * @return constant string path, NULL if special folder is unknown.
 */
const char *
get_folder_path(enum special_folder folder)
{
	const char *pathname;
	const char *special_path = NULL;
	static struct {
		const char *path;
		bool computed;
	} cached[SPECIAL_FOLDER_COUNT];
	static spinlock_t cached_slk = SPINLOCK_INIT;

	g_assert(UNSIGNED(folder) < SPECIAL_FOLDER_COUNT);

	/*
	 * Lookup in the cache first, so that we do not re-attempt to dynamically
	 * compute something that failed earlier (i.e. a NULL pointer is not
	 * sufficient to trigger computation).
	 */

	if (cached[folder].computed)
		return cached[folder].path;		/* Can be NULL */

	spinlock(&cached_slk);

	if G_UNLIKELY(cached[folder].computed) {
		spinunlock(&cached_slk);
		return cached[folder].path;		/* Can be NULL */
	}

	special_path = (*get_folder_basepath_func)(folder);

	if (NULL == special_path) {
		pathname = NULL;
	} else {
		pathname = ostrdup_readonly(special_path);

		/*
		 * A special folder MUST be an absolute path.
		 */

		if (!is_absolute_path(pathname)) {
			s_error("special folder %s is not an absolute path: %s",
				special_folder_name(folder), pathname);
		}
	}

	cached[folder].path = pathname;
	cached[folder].computed = TRUE;

	spinunlock(&cached_slk);

	return pathname;
}

/* vi: set ts=4 sw=4 cindent: */
