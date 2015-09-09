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

#ifdef I_SYS_STATVFS
#include <sys/statvfs.h>
#endif

#ifndef HAS_STATVFS
struct statvfs {
	ulong  f_bsize;		/* file system block size */
	ulong  f_frsize;	/* fragment size */
	uint64 f_blocks;	/* size of fs in f_frsize units */
	uint64 f_bfree;		/* # free blocks */
	uint64 f_bavail;	/* # free blocks for unprivileged users */
	uint64 f_files;		/* # inodes */
	uint64 f_ffree;		/* # free inodes */
	uint64 f_favail;	/* # free inodes for unprivileged users */
	ulong  f_fsid;		/* file system ID */
	ulong  f_flag;		/* mount flags */
	ulong  f_namemax;	/* maximum filename length */
};

#define ST_RDONLY	(1U << 0)	/* Read-only file system */
#define ST_NOSUID	(1U << 1)	/* Setuid/setgid bits are ignored by exec() */

#endif	/* !HAS_STATVFS */

int compat_statvfs(const char *path, struct statvfs *buf);

/* vi: set ts=4 sw=4 cindent: */
