/*
 * Copyright (c) 2008, Raphael Manfredi
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
 * Determine free diskspace.
 *
 * @author Raphael Manfredi
 * @date 2008
 */

#include "common.h"

#include "fs_free_space.h"

#include "compat_statvfs.h"
#include "log.h"

#include "override.h"			/* Must be the last header included */

struct fs_info {
	filesize_t free_space;
	filesize_t total_space;
};

/**
 * Get information about the filesystem mounted under the given directory
 * by filling the fs_info structure.
 */
static int
get_fs_info(const char *path, struct fs_info *fsi)
{
	struct statvfs buf;

	g_assert(path != NULL);
	g_assert(fsi != NULL);

	if (-1 == compat_statvfs(path, &buf))
		return -1;

	fsi->free_space = ((filesize_t) 0 + buf.f_bavail) * buf.f_bsize;
	fsi->total_space = ((filesize_t) 0 + buf.f_blocks) * buf.f_frsize;

	return 0;
}

/**
 * Return the free space in bytes available currently in the filesystem
 * mounted under the given directory.
 */
filesize_t
fs_free_space(const char *path)
{
	struct fs_info buf;

	if (-1 == get_fs_info(path, &buf)) {
		s_warning("%s(): cannot statvfs(\"%s\"): %m", G_STRFUNC, path);
		return 0;
	}

	return buf.free_space;
}

/**
 * Return the free space available currently in the filesystem mounted
 * under the given directory in percentage of the total space.
 *
 * This routine is used for entropy collection, therefore we are totally
 * silent on failures.
 */
double
fs_free_space_pct(const char *path)
{
	struct fs_info buf;

	if (-1 == get_fs_info(path, &buf))
		return 0.0;

	if (buf.total_space == 0 || buf.total_space < buf.free_space)
		return 100.0;		/* Something is wrong */

	return buf.free_space * 100.0 / buf.total_space;
}

/* vi: set ts=4 sw=4 cindent: */
