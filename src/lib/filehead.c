/*
 * Copyright (c) 2010, Raphael Manfredi
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
 * Parsing of file head lines.
 *
 * @author Raphael Manfredi
 * @date 2010
 */

#include "common.h"

#include "filehead.h"
#include "fd.h"
#include "file.h"
#include "parse.h"

#include "override.h"			/* Must be the last header included */

#define FILEHEAD_LINE_MAXLEN	1024	/**< Maximum expected line length */

/**
 * Open and parse the first line of a given file as the ASCII representation
 * of an unsigned 64-bit integer.
 *
 * @param path			file path
 * @param missing		whether file may be missing (to shut up warnings)
 * @param errptr		if non-NULL, filled with error number (0 means OK)
 *
 * @return the value we parsed on the first line, 0 otherwise.
 *
 * @note
 * The ``errptr'' parameter needs to be used to distinguish between
 * a file containing "0" and a file which could not be parsed correctly.
 */
uint64
filehead_uint64(const char *path, bool missing, int *errptr)
{
	int fd;
	uint64 value;
	char data[FILEHEAD_LINE_MAXLEN + 1];
	ssize_t r;
	int error;

	fd = missing ?  file_open_missing(path, O_RDONLY) :
		file_open(path, O_RDONLY, 0);

	if (-1 == fd)
		goto error;

	r = read(fd, ARYLEN(data) - 1); /* reserve one byte for NUL */

	if ((ssize_t) -1 == r)
		goto error_close;

	g_assert(r >= 0 && UNSIGNED(r) < sizeof data);

	fd_close(&fd);
	data[r] = '\0';
	value = parse_uint64(data, NULL, 10, &error);

	if (error) {
		errno = error;
		goto error;
	}

	if (errptr != NULL)
		*errptr = 0;

	return value;

error_close:
	fd_close(&fd);
error:
	if (errptr != NULL)
		*errptr = errno;

	return 0;
}

/* vi: set ts=4 sw=4 cindent: */
