/*
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
 * The tigertree data for each shared file is stored in a file in the directory
 * GTK_GNUTELLA_DIR/tth_cache/ in raw binary form. For example, if the root
 * hash is 5EDB4PUVFGY2UKVISQ2DMACSPNRODTTODBS52RQ, the tigertree data is
 * stored in
 * $GTK_GNUTELLA_DIR/tth_cache/5E/DB4PUVFGY2UKVISQ2DMACSPNRODTTODBS52RQ.
 * This avoids storing too many files per directory.
 * 
 * Only the leaves at TTH_MAX_DEPTH or above are stored. The root hash and the
 * nodes at each level between above these leaves can be calculated from the
 * leaves.
 *
 * If the depth is 1 (root only), nothing is stored.
 *
 * @author Christian Biere
 * @date 2007
 */

#include "common.h"

#include "settings.h"
#include "tth_cache.h"

#include "lib/atoms.h"
#include "lib/fd.h"
#include "lib/file.h"
#include "lib/halloc.h"
#include "lib/path.h"
#include "lib/stringify.h"
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
	return NOT_LEAKING(directory);
}

static char *
tth_cache_pathname(const struct tth *tth)
{
	const char *hash;
	
	g_assert(tth);
	
	hash = tth_base32(tth);
	return h_strdup_printf("%s%c%2.2s%c%s",
			tth_cache_directory(), G_DIR_SEPARATOR,
			&hash[0], G_DIR_SEPARATOR, &hash[2]);
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
	fd = file_create_missing(pathname, accmode, TTH_FILE_MODE);
	if (fd < 0 && ENOENT == errno) {
		char *dir = filepath_directory(pathname);
		if (0 == create_directory(dir, DEFAULT_DIRECTORY_MODE)) {
			fd = file_create(pathname, accmode, TTH_FILE_MODE);
		}
		HFREE_NULL(dir);
	}
	HFREE_NULL(pathname);
	return fd;
}

static int
tth_cache_file_open(const struct tth *tth)
{
	char *pathname;
	int fd;

	g_return_val_if_fail(tth, -1);

	pathname = tth_cache_pathname(tth);
	fd = file_open_missing(pathname, O_RDONLY);
	HFREE_NULL(pathname);
	return fd;
}

static bool
tth_cache_file_exists(const struct tth *tth)
{
	bool ret;
	char *pathname;

	g_return_val_if_fail(tth, FALSE);

	pathname = tth_cache_pathname(tth);
	ret = file_exists(pathname);
	HFREE_NULL(pathname);
	return ret;
}

void
tth_cache_insert(const struct tth *tth, const struct tth *leaves, int n_leaves)
{
	int fd;
	
	g_return_if_fail(tth);
	g_return_if_fail(leaves);
	g_return_if_fail(n_leaves >= 1);

	{
		struct tth root;

		root = tt_root_hash(leaves, n_leaves);
		g_return_if_fail(tth_eq(tth, &root));
	}

	if (1 == n_leaves)
		return;

	fd = tth_cache_file_create(tth);
	if (fd >= 0) {
		size_t size;
		ssize_t ret;

		STATIC_ASSERT(TTH_RAW_SIZE == sizeof(leaves[0]));
			
		size = TTH_RAW_SIZE * n_leaves;
		ret = write(fd, leaves, size);
		if ((ssize_t) -1 == ret) {
			g_warning("%s(%s): write() failed: %m", G_STRFUNC, tth_base32(tth));
		} else if ((size_t) ret != size) {
			g_warning("%s(%s): incomplete write()", G_STRFUNC, tth_base32(tth));
		}
		fd_forget_and_close(&fd);
	}
}

static size_t
tth_cache_leave_count(const struct tth *tth, const filestat_t *sb)
{
	g_return_val_if_fail(tth, 0);
	g_return_val_if_fail(sb, 0);

	if (!S_ISREG(sb->st_mode)) {
		g_warning("tth_cache_leave_count(%s): Not a regular file",
			tth_base32(tth));
		return 0;
	}
	if (
		sb->st_size % TTH_RAW_SIZE ||
		sb->st_size < TTH_RAW_SIZE ||
		sb->st_size > TTH_MAX_LEAVES * TTH_RAW_SIZE
	) {
		g_warning("tth_cache_leave_count(%s): Bad filesize %s",
			tth_base32(tth), fileoffset_t_to_string(sb->st_size));
		return 0;
	}

	return sb->st_size / TTH_RAW_SIZE;
}

/**
 * @return The number of leaves or zero if unknown.
 */
size_t
tth_cache_lookup(const struct tth *tth, filesize_t filesize)
{
	size_t expected, leave_count = 0;
	
	g_return_val_if_fail(tth, 0);

	expected = tt_good_node_count(filesize);
	if (expected > 1) {
		filestat_t sb;
		char *pathname;

		pathname = tth_cache_pathname(tth);
		if (stat(pathname, &sb)) {
			leave_count = 0;
			if (ENOENT != errno) {
				g_warning("%s(%s): stat(\"%s\") failed: %m",
					G_STRFUNC, tth_base32(tth), pathname);
			}
		} else {
			leave_count = tth_cache_leave_count(tth, &sb);
		}
		HFREE_NULL(pathname);
	} else {
		leave_count = 1;
	}
	return expected != leave_count ? 0 : leave_count;
}

void
tth_cache_remove(const struct tth *tth)
{
	char *pathname;

	g_return_if_fail(tth);

	pathname = tth_cache_pathname(tth);
	unlink(pathname);
	HFREE_NULL(pathname);
}

static size_t
tth_cache_get_leaves(const struct tth *tth,
	struct tth leaves[TTH_MAX_LEAVES], size_t n)
{
	int fd, num_leaves = 0;

	g_return_val_if_fail(tth, 0);
	g_return_val_if_fail(leaves, 0);

	fd = tth_cache_file_open(tth);
	if (fd >= 0) {
		filestat_t sb;

		if (fstat(fd, &sb)) {
			g_warning("%s(%s): fstat() failed: %m", G_STRFUNC, tth_base32(tth));
		} else {
			size_t n_leaves;
		
			n_leaves = tth_cache_leave_count(tth, &sb);
			n_leaves = MIN(n, n_leaves);
			if (n_leaves > 0) {
				size_t size;
				ssize_t ret;

				STATIC_ASSERT(TTH_RAW_SIZE == sizeof(leaves[0]));

				size = TTH_RAW_SIZE * n_leaves;
				ret = read(fd, &leaves[0].data, size);
				if ((size_t) ret == size) {
					num_leaves = n_leaves;
				}
			}
		}
		fd_forget_and_close(&fd);
	}
	return num_leaves;
}

size_t
tth_cache_get_tree(const struct tth *tth, filesize_t filesize,
	const struct tth **tree)
{
	static struct tth nodes[TTH_MAX_LEAVES * 2];
	size_t n_leaves, expected;

	g_return_val_if_fail(tth, 0);
	g_return_val_if_fail(tree, 0);

	expected = tt_good_node_count(filesize);
	if (1 == expected) {
		nodes[0] = *tth;
		*tree = &nodes[0];
		return 1;
	}

	*tree = NULL;
	
	n_leaves = tth_cache_get_leaves(tth,
					&nodes[TTH_MAX_LEAVES], TTH_MAX_LEAVES);
	g_assert(n_leaves <= TTH_MAX_LEAVES);

	if (expected == n_leaves) {
		size_t n_nodes, dst, src;

		n_nodes = n_leaves;
		dst = TTH_MAX_LEAVES;

		while (n_leaves > 1) {
			src = dst;
			dst = src - (n_leaves + 1) / 2;

			n_leaves = tt_compute_parents(&nodes[dst], &nodes[src], n_leaves);
			n_nodes += n_leaves;
		}

		if (tth_eq(tth, &nodes[dst])) {
			*tree = &nodes[dst];
			return n_nodes;
		}
	}

	if (tth_cache_file_exists(tth)) {
		g_warning("tth_cache_get_tree(): Removing corrupted tigertree for %s",
			tth_base32(tth));
		tth_cache_remove(tth);
	}
	return 0;
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
