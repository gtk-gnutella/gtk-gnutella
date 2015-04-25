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

/*
 * NOTE: The following header files pull in definition of ST_* macros
 * 	 which are conflicting with identifiers in the GUI code. Therefore,
 *	 these are only included here.
 */
#if defined(HAS_STATVFS)

#if defined(I_SYS_STATVFS)
#include <sys/statvfs.h>
#endif

#elif defined(HAS_STATFS)

#ifdef I_SYS_VFS
#include <sys/vfs.h>
#endif
#ifdef I_SYS_MOUNT
#include <sys/mount.h>
#endif

#endif	/* HAS_STATFS */

#include "fs_free_space.h"

#include "override.h"			/* Must be the last header included */

struct fs_info {
	filesize_t free_space;
	filesize_t total_space;
};

/**
 * Get information about the filesystem mounted under the given directory
 * by filling the fs_info structure.
 */
static void
get_fs_info(const char *path, struct fs_info *fsi)
{
	filesize_t free_space = MAX_INT_VAL(filesize_t);
	filesize_t total_space = MAX_INT_VAL(filesize_t);

	g_assert(path);
	g_assert(fsi);

	(void) path;

#if defined(HAS_STATVFS)
	{
		/* statvfs() is a POSIX.1-2001 system call */
		struct statvfs buf;

		if (-1 == statvfs(path, &buf)) {
			g_warning("statvfs(\"%s\") failed: %m", path);
		} else {
			free_space = ((filesize_t) 0 + buf.f_bavail) * buf.f_bsize;
			total_space = ((filesize_t) 0 + buf.f_blocks) * buf.f_frsize;
		}
	}
#elif defined(HAS_STATFS)
	{
		/* statfs() is deprecated but older systems may not have statvfs() */
		struct statfs buf;

		if (-1 == statfs(path, &buf)) {
			g_warning("statfs(\"%s\") failed: %m", path);
		} else {
			free_space = ((filesize_t) 0 + buf.f_bavail) * buf.f_bsize;
			total_space = ((filesize_t) 0 + buf.f_blocks) * buf.f_bsize;
		}
	}
#endif	/* HAS_STATVFS || HAS_STATFS */

	fsi->free_space = free_space;
	fsi->total_space = total_space;
}

/**
 * Return the free space in bytes available currently in the filesystem
 * mounted under the given directory.
 */
filesize_t
fs_free_space(const char *path)
{
	struct fs_info buf;

	get_fs_info(path, &buf);

	return buf.free_space;
}

/**
 * Return the free space available currently in the filesystem mounted
 * under the given directory in percentage of the total space.
 */
double
fs_free_space_pct(const char *path)
{
	struct fs_info buf;

	get_fs_info(path, &buf);

	if (buf.total_space == 0 || buf.total_space < buf.free_space)
		return 100.0;		/* Something is wrong */

	return buf.free_space * 100.0 / buf.total_space;
}

/* vi: set ts=4 sw=4 cindent: */
