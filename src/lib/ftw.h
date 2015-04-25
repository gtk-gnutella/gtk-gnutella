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
 * File tree walk.
 *
 * ftw_foreach() was modelled after the standard C library ftw() call, albeit
 * with a slightly different interface which also combines nftw() features
 * plus the ability to provide an additional callback argument.
 *
 * @author Raphael Manfredi
 * @date 2015
 */

#ifndef _ftw_h_
#define _ftw_h_

#include "common.h"

/**
 * Status that ftw_foreach() callbacks can return.
 */
typedef enum ftw_status {
	FTW_STATUS_ERROR = -1,			/**< Stop processing on error condition */
	FTW_STATUS_OK = 0,				/**< OK, continue processing */
	FTW_STATUS_SKIP_SIBLINGS,		/**< Skip siblings of current entry */
	FTW_STATUS_SKIP_SUBTREE,		/**< Do not process this directory */
	FTW_STATUS_CANCELLED,			/**< Stop processing on external cancel */
	FTW_STATUS_ABORT				/**< Stop processing, normal decision */
} ftw_status_t;

/**
 * Descriptive argument passed to callbacks.
 */
typedef struct ftw_info {
	const char *fpath;				/**< File path */
	const char *fbase;				/**< Pointer to file basename */
	const char *rpath;				/**< File path underneath traversal root */
	uint32 flags;					/**< Descriptive flags */
	uint32 ftw_flags;				/**< Flags used on ftw_foreach() */
	int root;						/**< Offset of rootdir in ``fpath'' */
	int base;						/**< Offset of file basename in ``fpath'' */
	int level;						/**< Depth of ``fpath'' in root tree */
	int fbase_len;					/**< Length of file basename */
} ftw_info_t;

/**
 * ftw_foreach() callback signature.
 *
 * @param info		the ftw_info_t structure
 * @param sb		the result of the [l]stat() call on the entry
 * @param data		opaque user-supplied argument
 */
typedef ftw_status_t (*ftw_fn_t)(
	const ftw_info_t *info, const filestat_t *sb, void *data);

/**
 * Callback flags.
 */
#define FTW_F_FILE			(1U << 0)	/**< is a regular file */
#define FTW_F_DIR			(1U << 1)	/**< is a directory */
#define FTW_F_OTHER			(1U << 2)	/**< is neither a file nor a dir */
#define FTW_F_NOREAD		(1U << 3)	/**< is an unreadable directory */
#define FTW_F_NOSTAT		(1U << 4)	/**< stat() failed */
#define FTW_F_DONE			(1U << 5)	/**< directory fully processed */
#define FTW_F_SYMLINK		(1U << 6)	/**< is a symbolic link */
#define FTW_F_DANGLING		(1U << 7)	/**< symbolic link points to nothing */

/**
 * Operating flags for ftw_foreach().
 */
#define FTW_O_CHDIR			(1U << 0)	/**< chdir() to dirs before handling */
#define FTW_O_DEPTH			(1U << 1)	/**< recurse to children first */
#define FTW_O_ENTRY			(1U << 2)	/**< On DEPTH, also call on dir entry */
#define FTW_O_MOUNT			(1U << 3)	/**< Do NOT cross mount points */
#define FTW_O_PHYS			(1U << 4)	/**< Do NOT follow symbolic links */
#define FTW_O_ALL			(1U << 5)	/**< Report all filesystem entries */
#define FTW_O_SILENT		(1U << 6)	/**< No loud warnings on minor errors */

/*
 * Public interface.
 */

ftw_status_t ftw_foreach(const char *dirpath, uint32 flags, int nfd,
	ftw_fn_t cb, void *data);

#endif /* _ftw_h_ */

/* vi: set ts=4 sw=4 cindent: */
