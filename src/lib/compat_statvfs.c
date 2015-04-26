/*
 * Copyright (c) 2015 Raphael Manfredi
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
 * Get file system statistics.
 *
 * @author Raphael Manfredi
 * @date 2015
 */

#include "common.h"

#if defined(HAS_STATVFS)

#ifdef I_SYS_STATVFS
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

#include "compat_statvfs.h"

#include "hashing.h"

#include "override.h"		/* Must be the last header included */

/**
 * Get file system statistics.
 */
int
compat_statvfs(const char *path, struct statvfs *buf)
#if defined(HAS_STATVFS)
{
	return statvfs(path, buf);
}
#elif defined(HAS_STATFS)
{
	struct statfs sfs;

	if (-1 == statfs(path, &sfs))
		return -1;

	buf->f_bsize   = sfs.f_bsize;
	buf->f_frsize  = sfs.f_bsize;	/* f_frsize only introduced in Linux 2.6) */
	buf->f_blocks  = sfs.f_blocks;
	buf->f_bfree   = sfs.f_bfree;
	buf->f_bavail  = sfs.f_bavail;
	buf->f_files   = sfs.f_files;
	buf->f_ffree   = sfs.f_ffree;
	buf->f_favail  = sfs.f_ffree;
	buf->f_fsid    = binary_hash(&sfs.f_fsid, sizeof sfs.f_fsid);
	buf->f_flag    = 0;
	buf->f_namemax = sfs.f_namelen;

	return 0;
}
#else
{
	(void) path;
	(void) buf;

	errno = ENOSYS;
	return -1;
}
#endif

/* vi: set ts=4 sw=4 cindent: */
