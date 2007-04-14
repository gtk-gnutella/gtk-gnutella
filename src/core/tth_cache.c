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

#include "lib/atoms.h"
#include "lib/file.h"
#include "lib/misc.h"
#include "lib/tigertree.h"
#include "lib/walloc.h"

#include "lib/override.h"       /* Must be the last header included */

#if defined(S_IROTH)
#define TTH_FILE_MODE (S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH) /* 0644 */
#else
#define TTH_FILE_MODE (S_IRUSR | S_IWUSR | S_IRGRP) /* 0640 */
#endif

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
tth_cache_file_create(const struct tth *tth)
{
	char *pathname;
	int accmode;
	int fd;

	g_return_val_if_fail(tth, -1);

	accmode = O_WRONLY | O_TRUNC;
	pathname = tth_cache_pathname(tth);
	fd = file_create(pathname, accmode, TTH_FILE_MODE);
	if (fd < 0 && ENOENT == errno) {
		if (0 == create_directory(tth_cache_directory())) {
			fd = file_create(pathname, accmode, TTH_FILE_MODE);
		}
	}
	G_FREE_NULL(pathname);
	return fd;
}

static int
tth_cache_file_open(const struct tth *tth)
{
	char *pathname;
	int fd;

	g_return_val_if_fail(tth, -1);

	pathname = tth_cache_pathname(tth);
	fd = file_open(pathname, O_RDONLY);
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

	{
		struct tth root;

		root = tt_root_hash(leaves, n);
		g_return_if_fail(tth_eq(tth, &root));
	}

	fd = tth_cache_file_create(tth);
	if (fd >= 0) {
		struct iovec *iov;
		ssize_t ret;
		size_t iov_size, size = 0;
		int i;

		iov_size = n * sizeof iov[0];
		iov = walloc(iov_size);

		for (i = 0; i < n; i++) {
			iov[i].iov_base = deconstify_gpointer(leaves[i].data);
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

static gboolean
tth_cache_check(const struct tth *tth, int fd, filesize_t filesize)
{
	struct tth root, nodes[1 << (TTH_MAX_DEPTH - 1)];
	char buf[G_N_ELEMENTS(nodes) * TTH_RAW_SIZE];
	size_t n_nodes, i, size;
	ssize_t r;

	g_return_val_if_fail(tth, FALSE);
	g_return_val_if_fail(fd >= 0, FALSE);
	g_return_val_if_fail(filesize >= TTH_RAW_SIZE, FALSE);
	g_return_val_if_fail(0 == (filesize % TTH_RAW_SIZE), FALSE);

	n_nodes = filesize / TTH_RAW_SIZE;
	g_return_val_if_fail(n_nodes <= G_N_ELEMENTS(nodes), FALSE);

	size = n_nodes * TTH_RAW_SIZE;
	r = read(fd, buf, size);
	g_return_val_if_fail((size_t) r == size, FALSE);

	for (i = 0; i < n_nodes; i++) {
		memmove(nodes[i].data, &buf[i * TTH_RAW_SIZE], TTH_RAW_SIZE);
	}

	root = tt_root_hash(nodes, n_nodes);
	g_return_val_if_fail(tth_eq(tth, &root), FALSE);

	return TRUE;
}

/**
 * @return The number of leaves or zero if unknown.
 */
size_t
tth_cache_lookup(const struct tth *tth)
{
	size_t result = 0;
	int fd, depth;
	filesize_t size;
	struct stat sb;
	
	g_return_val_if_fail(tth, 0);

	fd = tth_cache_file_open(tth);
	if (fd < 0) {
		goto finish;
	}
	if (fstat(fd, &sb)) {
		g_warning("tth_cache_lookup(%s): fstat() failed: %s", tth_base32(tth),
			g_strerror(errno));
		goto finish;
	}
	if (!S_ISREG(sb.st_mode)) {
		g_warning("tth_cache_lookup(%s): Not a regular file", tth_base32(tth));
		goto finish;
	}
	if (sb.st_size < TTH_RAW_SIZE || sb.st_size % TTH_RAW_SIZE) {
		g_warning("tth_cache_lookup(%s): Bad filesize %s",
			tth_base32(tth), off_t_to_string(sb.st_size));
		goto finish;
	}

	size = sb.st_size / TTH_RAW_SIZE;
	depth = 1;
	while (size > 1) {
		size = (size + 1) / 2;
		depth++;
	}
	if (depth > TTH_MAX_DEPTH) {
		g_warning("tth_cache_lookup(%s): Bad depth %u", tth_base32(tth), depth);
		goto finish;
	}
	if (!tth_cache_check(tth, fd, sb.st_size)) {
		g_warning("tth_cache_lookup(%s): Damaged file", tth_base32(tth));
		goto finish;
	}
	result = sb.st_size / TTH_RAW_SIZE;
	
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
