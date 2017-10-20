/*
 * Copyright (c) 2007 Christian Biere
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
 * @author Raphael Manfredi
 * @date 2015
 */

#include "common.h"

#include "tth_cache.h"

#include "settings.h"
#include "share.h"

#include "lib/atoms.h"
#include "lib/base32.h"
#include "lib/fd.h"
#include "lib/file.h"
#include "lib/ftw.h"
#include "lib/halloc.h"
#include "lib/hset.h"
#include "lib/hstrfn.h"
#include "lib/path.h"
#include "lib/pslist.h"
#include "lib/spinlock.h"
#include "lib/str.h"
#include "lib/stringify.h"
#include "lib/thread.h"
#include "lib/tigertree.h"
#include "lib/timestamp.h"
#include "lib/walloc.h"

#include "if/gnet_property_priv.h"
#include "if/core/main.h"		/* For debugging() */

#include "lib/override.h"       /* Must be the last header included */

#if defined(S_IROTH)
#define TTH_FILE_MODE (S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH) /* 0644 */
#else
#define TTH_FILE_MODE (S_IRUSR | S_IWUSR | S_IRGRP) /* 0640 */
#endif

/**
 * This lock is used to protect the creation / removal of directories
 * under the TTH cache.
 */
static spinlock_t tth_path_lk = SPINLOCK_INIT;

#define TTH_PATH_LOCK		spinlock(&tth_path_lk)
#define TTH_PATH_UNLOCK		spinunlock(&tth_path_lk)

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

	/*
	 * Critical section required since we could have a concurrent thread
	 * deciding to remove empty directories whilst we are attempting
	 * to create a new directory to store the new cached entry!
	 */

	TTH_PATH_LOCK;

	fd = file_create_missing(pathname, accmode, TTH_FILE_MODE);
	if (fd < 0 && ENOENT == errno) {
		char *dir = filepath_directory(pathname);
		if (0 == create_directory(dir, DEFAULT_DIRECTORY_MODE)) {
			fd = file_create(pathname, accmode, TTH_FILE_MODE);
		}
		HFREE_NULL(dir);
	}

	TTH_PATH_UNLOCK;

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
		g_warning("%s(%s): not a regular file", G_STRFUNC, tth_base32(tth));
		return 0;
	}
	if (
		sb->st_size % TTH_RAW_SIZE ||
		sb->st_size < TTH_RAW_SIZE ||
		sb->st_size > TTH_MAX_LEAVES * TTH_RAW_SIZE
	) {
		g_warning("%s(%s): bad filesize %s", G_STRFUNC,
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
		g_warning("%s(): removing corrupted tigertree for %s",
			G_STRFUNC, tth_base32(tth));
		tth_cache_remove(tth);
	}
	return 0;
}

/**
 * Get amount of leaves stored in the cached TTH entry.
 *
 * @param tth		the TTH for which we want the information
 *
 * @return 0 if the entry could not be located, the amount of leaves otherwise.
 */
size_t
tth_cache_get_nleaves(const struct tth *tth)
{
	int fd;
	filesize_t nleaves = 0;

	g_return_val_if_fail(tth != NULL, 0);

	fd = tth_cache_file_open(tth);

	if (fd >= 0) {
		filestat_t sb;

		if (fstat(fd, &sb)) {
			g_warning("%s(%s): fstat() failed: %m", G_STRFUNC, tth_base32(tth));
		} else {
			nleaves = tth_cache_leave_count(tth, &sb);
		}

		fd_forget_and_close(&fd);
	}

	return nleaves;
}

/**
 * Remove directory, warning only when it cannot be done for a reason other
 * than it not being empty.
 */
static void
tth_cache_dir_rmdir(const char *path)
{
	if (debugging(0))
		g_message("%s(): removing TTH cache directory %s", G_STRFUNC, path);

	/*
	 * To avoid any conflicts with another thread attempting to create a
	 * file under that directory, take a lock.
	 *
	 * Note that there is a race condition between the traversal that detects
	 * the directory is empty and the time we actually attempt to remove it.
	 * Hence, we silence any error having to deal with the directory being
	 * non-empty and therefore non-removable.
	 */

	TTH_PATH_LOCK;

	if (-1 == rmdir(path) && ENOTEMPTY != errno) {
		g_warning("%s(): cannot remove TTH cache directory %s: %m",
			G_STRFUNC, path);
	}

	TTH_PATH_UNLOCK;
}


/**
 * ftw_foreach() callback to remove empty directories.
 */
static ftw_status_t
tth_cache_cleanup_rmdir(
	const ftw_info_t *info, const filestat_t *unused_sb, void *data)
{
	pslist_t **dirsp = data;

	(void) unused_sb;

	if (FTW_F_DIR & info->flags) {
		if (FTW_F_NOREAD & info->flags) {
			tth_cache_dir_rmdir(info->fpath);	/* Try, we can't read it */
		} else if (FTW_F_DONE & info->flags) {
			void *cnt = (*dirsp)->data;
			if (NULL == cnt && 0 != info->level)
				tth_cache_dir_rmdir(info->fpath);
			*dirsp = pslist_delete_link(*dirsp, *dirsp);	/* Strip head */
		} else {
			*dirsp = pslist_prepend(*dirsp, NULL);
		}
		return FTW_STATUS_OK;
	}

	(*dirsp)->data = int_to_pointer(1);	/* There is something in directory */
	return FTW_STATUS_OK;
}

/**
 * Unlink cached file entry, warning if it cannot be done but otherwise not
 * logging anything on success.
 *
 * @return TRUE on success
 */
static bool
tth_cache_file_unlink(const char *path, const char *reason)
{
	if (-1 == unlink(path)) {
		g_warning("%s(): cannot remove %s TTH cache entry %s: %m",
			G_STRFUNC, reason, path);
		return FALSE;
	}

	return TRUE;
}

/**
 * Remove cached file entry, logging success.
 */
static void
tth_cache_file_remove(const char *path, const char *reason)
{
	if (tth_cache_file_unlink(path, reason))
		g_message("removed %s TTH cache entry: %s", reason, path);
}

/**
 * ftw_foreach() callback to remove obsolete / spurious files.
 */
static ftw_status_t
tth_cache_cleanup_unlink(
	const ftw_info_t *info, const filestat_t *sb, void *data)
{
	const hset_t *shared = data;

	if (FTW_F_DIR & info->flags)
		return FTW_STATUS_OK;

	if ((FTW_F_OTHER | FTW_F_SYMLINK) & info->flags) {
		tth_cache_file_remove(info->fpath, "alien");
		return FTW_STATUS_OK;
	}

	if (FTW_F_FILE & info->flags) {
		char **path;
		struct tth tth;
		char b32[TTH_BASE32_SIZE + 2];
		size_t len;

		if (FTW_F_NOSTAT & info->flags) {
			g_warning("%s(): ignoring unaccessible cached TTH %s",
				G_STRFUNC, info->fpath);
			return FTW_STATUS_OK;
		}

		if (info->level != 2) {
			tth_cache_file_remove(info->fpath, "spurious");
			return FTW_STATUS_OK;
		}

		path = g_strsplit(info->rpath, "/", 2);

		if (NULL == path)
			return FTW_STATUS_ABORT;	/* Weird, empty relative path? */

		len = str_bprintf(b32, sizeof b32, "%s", path[0]);
		if (len != 2)		/* Expected first path component is 2-char long */
			len = 0;
		len += str_bprintf(&b32[len], sizeof b32 - len, "%s", path[1]);

		if (
			TTH_BASE32_SIZE != len ||
			TTH_RAW_SIZE !=
				base32_decode(&tth, sizeof tth, b32, TTH_BASE32_SIZE)
		) {
			tth_cache_file_remove(info->fpath, "invalid");
			goto done;
		}

		/*
		 * At this point, we have a valid TTH cache filename.
		 *
		 * We want to only process files created before the session started.
		 *
		 * The rationale is that users could start unsharing directories,
		 * moving files around, add new files, etc..  Each time a new library
		 * rescan occurs, we're going to create new TTH cache files, or some
		 * cached files could become unused for a while and then files will
		 * reappear in the library.
		 *
		 * By only ever cleaning up files created before the current session,
		 * we have a higher likelyhood of processing an obsolete cache entry.
		 */

		if (delta_time(sb->st_mtime, GNET_PROPERTY(session_start_stamp)) >= 0)
			goto done;		/* Created after session started, skip */

		if (!hset_contains(shared, &tth)) {
			if (debugging(0))
				g_debug("%s(): unshared TTH (%s)", G_STRFUNC, info->rpath);
			(void) tth_cache_file_unlink(info->fpath, "unshared");
		}

		/* FALL THROUGH */

	done:
		g_strfreev(path);
		return FTW_STATUS_OK;
	}

	g_assert_not_reached();
	return FTW_STATUS_ERROR;
}

static int tth_cache_cleanups;

/**
 * Main entry point for the thread that cleans up the TTH cache.
 */
static void *
tth_cache_cleanup_thread(void *unused_arg)
{
	hset_t *shared;
	const char *rootdir = tth_cache_directory();
	pslist_t *dirstack;
	uint32 flags;
	ftw_status_t res;

	(void) unused_arg;

	if (!is_directory(rootdir))
		goto done;			/* No TTH cache */

	/*
	 * First pass: spot all file entries that are older than our start
	 * time (i.e. were created in another session) and which cannot be
	 * associated with a shared file.
	 */

	shared = share_tthset_get();
	flags = FTW_O_PHYS | FTW_O_MOUNT | FTW_O_ALL;
	res = ftw_foreach(rootdir, flags, 0, tth_cache_cleanup_unlink, shared);
	share_tthset_free(shared);

	if (res != FTW_STATUS_OK) {
		g_warning("%s(): initial traversal failed with %d, aborting",
			G_STRFUNC, res);
		goto done;
	}

	/*
	 * Second pass: spot empty directories and remove them.
	 */

	flags |= FTW_O_ENTRY | FTW_O_DEPTH;
	dirstack = NULL;
	(void) ftw_foreach(rootdir, flags, 0, tth_cache_cleanup_rmdir, &dirstack);
	pslist_free(dirstack);

	/* FALL THROUGH */

done:
	atomic_int_dec(&tth_cache_cleanups);
	return NULL;
}

/**
 * Cleanup the TTH cache by removing needless entries.
 */
void
tth_cache_cleanup(void)
{
	if (0 == atomic_int_inc(&tth_cache_cleanups)) {
		int id = thread_create(tth_cache_cleanup_thread,
					NULL, THREAD_F_DETACH | THREAD_F_WARN, THREAD_STACK_MIN);
		if (-1 == id)
			atomic_int_dec(&tth_cache_cleanups);
	} else if (debugging(0)) {
		g_warning("%s(): concurrent cleanup in progress", G_STRFUNC);
		atomic_int_dec(&tth_cache_cleanups);
	}
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
