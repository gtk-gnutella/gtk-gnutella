/*
 * $Id$
 *
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

RCSID("$Id$")

#include "path.h"
#include "halloc.h"
#include "override.h"			/* Must be the last header included */

/**
 * Create new pathname from the concatenation of the dirname and the basename
 * of the file. A directory separator is insert, unless "dir" already ends
 * with one or "filename" starts with one.
 *
 * @param dir The directory path.
 * @param file The filename.
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

	n = strlen(dir);
	if ((n > 0 && dir[n - 1] == G_DIR_SEPARATOR) || file[0] == G_DIR_SEPARATOR)
		 sep = "";
	else
		 sep = G_DIR_SEPARATOR_S;

	return h_strconcat(dir, sep, file, (void *) 0);
}

/**
 * Create an absolute path.
 * The resulting string must be freed with hfree().
 */
char *
absolute_pathname(const char *file)
{
	g_assert(file);
	
	if (is_absolute_path(file)) {
		return h_strdup(file);
	} else if ('\0' == file[0]) {
		return NULL;
	} else {
		char buf[4096], *ret;

		ret = getcwd(buf, sizeof buf);
		return ret ? make_pathname(ret, file) : NULL;
	}
}

/**
 * Check whether path is an absolute path.
 */
gboolean
is_absolute_path(const char *pathname)
{
	g_assert(pathname);
	return '/' == pathname[0] || G_DIR_SEPARATOR == pathname[0];
}

/**
 * Check whether file given by its dirname and its basename exists.
 */
gboolean
filepath_exists(const char *dir, const char *file)
{
	struct stat buf;
	gboolean exists;
	char *path;

	path = make_pathname(dir, file);
	exists = 0 == stat(path, &buf);
	HFREE_NULL(path);

	return exists;
}

/**
 * Returns a pointer to the basename of the given pathname. A slash is
 * always considered a  separator but G_DIR_SEPARATOR is considered as
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
	const char *p, *q;
	
	g_assert(pathname);
	
	p = strrchr(pathname, '/');
	if (p) {
		p++;
	} else {
		p = pathname;
	}
	q = strrchr(p, G_DIR_SEPARATOR);
	if (q) {
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
		while (p != pathname && ('/' == p[-1] || G_DIR_SEPARATOR == p[-1])) {
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

/* vi: set ts=4 sw=4 cindent: */
