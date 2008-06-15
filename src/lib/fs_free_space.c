/*
 * $Id$
 *
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

RCSID("$Id$")

/*
 * NOTE: The following header files pull in definition of ST_* macros
 * 	 which are conflicting with identifiers in the GUI code. Therefore,
 *	 these are only included here.
 */
#ifdef I_SYS_STATVFS
#include <sys/statvfs.h>
#endif
#ifdef I_SYS_VFS
#include <sys/vfs.h>
#endif

#include "lib/fs_free_space.h"

#include "override.h"			/* Must be the last header included */

/**
 * Return the free space in bytes available currently in the filesystem
 * mounted under the given directory.
 */
filesize_t
fs_free_space(const char *path)
{
	filesize_t free_space = MAX_INT_VAL(filesize_t);
#if defined(HAS_STATVFS)
	/* statvfs() is a POSIX.1-2001 system call */
	struct statvfs buf;

	if (-1 == statvfs(path, &buf)) {
		g_warning("statvfs(\"%s\") failed: %s", path, g_strerror(errno));
	} else {
		free_space = buf.f_bavail * buf.f_bsize;
	}
#elif defined(HAS_STATFS)
	/* statfs() is deprecated but older Linux systems may not have statvfs() */
	struct statfs buf;

	if (-1 == statfs(path, &buf)) {
		g_warning("statfs(\"%s\") failed: %s", path, g_strerror(errno));
	} else {
		free_space = buf.f_bavail * buf.f_bsize;
#endif	/* HAS_STATVFS || HAS_STATFS */

	return free_space;
}

/* vi: set ts=4 sw=4 cindent: */
