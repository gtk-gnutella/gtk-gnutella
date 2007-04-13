/*
 * $Id$
 *
 * Copyright (c) 2006, Christian Biere
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
 * @ingroup core
 * @file
 *
 * Caching of tigertree data.
 *
 * The TTH data for each file is stored in
 * $GTK_GNUTELLA_DIR/tth_cache/<base-32 TTH> in raw binary form. Only the
 * leaves are depth 9 or higher are stored. The root hash and the nodes at
 * each level between above these leaves can be calculated from the leaves.
 *
 * @author Christian Biere
 * @date 2007
 */

#include "common.h"

RCSID("$Id$")

#include "settings.h"
#include "tth_cache.h"

#include "lib/file.h"
#include "lib/misc.h"
#include "lib/walloc.h"

#include "lib/override.h"       /* Must be the last header included */

static const char *
tth_cache_directory(void)
{
	static char *directory;

	if (!directory) {
		directory = make_pathname(settings_config_dir(), "tth_cache");
	}
	return directory;
}

static char *
tth_cache_pathname(const struct tth *tth)
{
	g_assert(tth);
	return make_pathname(tth_cache_directory(), tth_base32(tth));
}

static int
tth_cache_file_open(const struct tth *tth, int accmode)
{
	char *pathname;
	int fd;

	g_return_val_if_fail(tth, -1);

	pathname = tth_cache_pathname(tth);
	fd = file_open(pathname, accmode);
	G_FREE_NULL(pathname);
	return fd;
}

void
tth_cache_insert(const struct tth *tth, const struct tth *leaves, int n)
{
	int fd;
	
	g_return_if_fail(tth);
	g_return_if_fail(leaves);
	g_return_if_fail(n >= 1);

	fd = tth_cache_file_open(tth, O_WRONLY);
	if (fd >= 0) {
		struct iovec *iov;
		ssize_t ret;
		size_t iov_size, size = 0;
		int i;

		iov_size = n * sizeof iov[0];
		iov = walloc(iov_size);

		for (i = 0; i < n; i++) {
			iov[i].iov_base = leaves[i].data;
			iov[i].iov_len = sizeof leaves[i].data;
			size += sizeof leaves[i].data;
		}
		ret = writev(fd, iov, n);
		if ((ssize_t) -1 == ret) {
			g_warning("tth_cache_insert(): writev() failed: %s",
				g_strerror(errno));
		} else if ((size_t) ret != size) {
			g_warning("tth_cache_insert(): incomplete writev()");
		}
		close(fd);
		wfree(iov, iov_size);
	}
}

/**
 * @return The depth of the cached tigertree or a non-positive value
 *		   if there's none.
 */
int
tth_cache_lookup(const struct tth *tth)
{
	int fd, depth, result = 0;
	struct stat sb;
	
	g_return_val_if_fail(tth, 0);

	fd = tth_cache_file_open(tth, O_RDONLY);
	if (fd < 0) {
		goto finish;
	}
	if (fstat(fd, &sb)) {
		g_warning("tth_cache_lookup(): fstat() failed for \"%s\": %s",
			tth_base32(tth), g_strerror(errno));
		goto finish;
	}
	if (!S_ISREG(sb.st_mode)) {
		g_warning("tth_cache_lookup(): Not a regular file \"%s\"",
			tth_base32(tth));
		goto finish;
	}
	if (sb.st_size < TTH_RAW_SIZE || sb.st_size % TTH_RAW_SIZE) {
		g_warning("tth_cache_lookup(): Bad filesize \"%s\"",
			tth_base32(tth));
		goto finish;
	}

	depth = 1;
	sb.st_size /= TTH_RAW_SIZE;
	while (sb.st_size > 1) {
		sb.st_size = (sb.st_size + 1) / 2;
		depth++;
	}
	
	result = depth;
	
finish:

	if (fd >= 0) {
		close(fd);
		fd = -1;
	}
	return result;
}

void
tth_cache_remove(const struct tth *tth)
{
	char *pathname;

	g_return_if_fail(tth);

	pathname = tth_cache_pathname(tth);
	remove(pathname);
	G_FREE_NULL(pathname);
}

void
tth_cache_init(void)
{
	/* NOTHING */
}

void
tth_cache_close(void)
{
	/* NOTHING */
}

/* vi: set ts=4 sw=4 cindent: */
