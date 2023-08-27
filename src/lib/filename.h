/*
 * Copyright (c) 2001-2009, Raphael Manfredi
 * Copyright (c) 2003-2008, Christian Biere
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
 * Filename manipulation functions.
 *
 * @author Raphael Manfredi
 * @date 2001-2009
 * @author Christian Biere
 * @date 2003-2008
 */

#ifndef _filename_h_
#define _filename_h_

char *filename_sanitize(const char *filename,
	bool no_spaces, bool no_evil);
char *filename_beautify(const char *filename);

size_t filename_shrink(const char *filename, char *buf, size_t size);
char *filename_unique(const char *path, const char *file, const char *ext,
		bool (*name_is_uniq)(const char *pathname));

#endif /* _filename_h_ */

/* vi: set ts=4 sw=4 cindent: */
