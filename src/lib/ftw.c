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
 * The interface was inspired by the specifications of the standard nftw()
 * C library interface, with a few adjustments to allow the callback to
 * get an externally-supplied opaque data argument and get more readable
 * callback flags, whilst keeping the amount of callback arguments reasonable.
 *
 * The initial aim was to implement the functionality to get it under Windows,
 * since the nftw() routine is not available within the MinGW environment.
 * It was never a goal to be a drop-in replacement for nftw(), rather an
 * alternative, on which the application can be based regardless of the
 * actual platform.
 *
 * The nice thing about engineering your own wheel is that you can then
 * customize it and go beyond its original specifications...
 *
 * @author Raphael Manfredi
 * @date 2015
 */

#include "common.h"

#include "ftw.h"

#include "erbtree.h"
#include "eslist.h"
#include "fd.h"
#include "halloc.h"
#include "log.h"
#include "misc.h"			/* For dir_entry_mode() */
#include "path.h"
#include "stacktrace.h"
#include "str.h"
#include "walloc.h"

#include "override.h"		/* Must be the last header included */

enum ftw_ctx_magic { FTW_CTX_MAGIC = 0x39cba316 };

/**
 * Context used when recursing.
 */
struct ftw_ctx {
	enum ftw_ctx_magic magic;		/* Magic number */
	int nfd;						/* Maximum file descriptors we can use */
	int odirs;						/* Opened dirs */
	int callfd;						/* Descriptor of caller's current dir */
	uint32 flags;					/* Flags for ftw_foreach() */
	int rootlen;					/* Length of spath for root directory */
	int base;						/* Offset of file basename in spath */
	int level;						/* Filesystem depth (0 for root dir) */
	dev_t rootdev;					/* Device of root dir, for FTW_O_MOUNT */
	char *calldir;					/* In case we need to chdir back there */
	char *rootdir;					/* To safely escape from symlinked dirs */
	ftw_fn_t cb;					/* Callback to invoke */
	void *udata;					/* Opaque user-supplied argument */
	str_t spath;					/* Dynamic string to build path info */
	ftw_info_t info;				/* Informational context passed to user */
	erbtree_t entries;				/* Seen entries, if no FTW_O_PHYS */
};

static inline void
ftw_ctx_check(const struct ftw_ctx * const fx)
{
	g_assert(fx != NULL);
	g_assert(FTW_CTX_MAGIC == fx->magic);
}

/**
 * An entry in the filesystem.
 *
 * It is necessary to keep track of the visited entries when traversing
 * without FTW_O_PHYS since symbolic links could create loops and we need
 * to ensure we're only visiting each entry once.
 */
struct ftw_entry {
	dev_t dev;						/* Device */
	ino_t ino;						/* Inode number */
	rbnode_t node;					/* Embedded red-black node */
};

enum ftw_dir_magic { FTW_DIR_MAGIC = 0x0d63ab62 };

/**
 * A directory descriptor.
 *
 * These structures live on the stack and represent a directory we are
 * processing as part of the recursive traversal.
 *
 * When we have enough file descriptors, the ``dp'' descriptor points to
 * an opened directory.  If NULL, then the descriptor had to be closed,
 * in which case ``listing'' contains a list of all the directory entries
 * we have yet to process.
 *
 * The ftw_readdir() routine uses these descriptors to fill in ftw_dirent
 * structures much like readdir() fills in dirent ones.  This completely
 * hides whether the physical directory is still opened or whether its content
 * was already read and is being processed instead.
 *
 * The ftw_opendir() routine creates the descriptor and ftw_closedir() will
 * perform the necessary cleanup.
 */
struct ftw_dir {
	enum ftw_dir_magic magic;		/* Magic number */
	int fd;							/* dirfd(dp), or -1 if no dirfd() */
	DIR *dp;						/* If non-NULL, opened directory */
	struct ftw_dir *parent;			/* Parent directory, NULL if at root */
	eslist_t listing;				/* Content */
	size_t count;					/* Amount of listing entries to process */
};

static inline void
ftw_dir_check(const struct ftw_dir * const dp)
{
	g_assert(dp != NULL);
	g_assert(FTW_DIR_MAGIC == dp->magic);
}

/**
 * A directory listing entry that we saved.
 */
struct ftw_dirent {
	char *d_name;		/* Filename -- walloc()'ed */
	ino_t d_ino;		/* Inode number */
	uint16 d_namelen;	/* Filename length -- strlen(d_name) */
	mode_t d_mode;		/* File type, 0 means unknown */
	slink_t lnk;		/* Embedded list */
};

static ftw_status_t ftw_process_dir(
	struct ftw_ctx *fx, filestat_t *sb, struct ftw_dir *pdir, bool is_link);

/**
 * Comparison routine for the filesystem entries we insert in the tree.
 */
static int
ftw_entry_cmp(const void *a, const void *b)
{
	const struct ftw_entry *fa = a, *fb = b;
	int c;

	c = CMP(fa->ino, fb->ino);

	if G_UNLIKELY(0 == c)
		c = CMP(fa->dev, fb->dev);

	return c;
}

/**
 * Allocate a filesystem entry.
 */
static struct ftw_entry *
ftw_entry_alloc(dev_t dev, ino_t ino)
{
	struct ftw_entry *fe;

	WALLOC0(fe);
	fe->dev = dev;
	fe->ino = ino;

	return fe;
}

/**
 * Free filesystem entry.
 */
static void
ftw_entry_free(void *p)
{
	struct ftw_entry *fe = p;

	WFREE(fe);
}

/**
 * Get the current working directory.
 *
 * @return the directory in a newly halloc()'ed string, NULL on error.
 */
static char *
ftw_getcwd(void)
{
	char *dir;

	dir = halloc(MAX_PATH_LEN);

	if (NULL == getcwd(dir, MAX_PATH_LEN)) {
		HFREE_NULL(dir);
	} else {
		dir = hrealloc(dir, 1 + strlen(dir));
	}

	return dir;
}

/**
 * Read all the content of the directory stream that we have still not yet
 * processed and close its stream.
 *
 * @param fx		the tree walker context
 * @param dir		directory descriptor we need to close
 *
 * @return 0 if OK, -1 on error with errno set.
 */
static int
ftw_readdir_all(struct ftw_ctx *fx, struct ftw_dir *dir)
{
	struct dirent *entry;

	ftw_ctx_check(fx);
	ftw_dir_check(dir);
	g_assert(dir->dp != NULL);
	g_assert(!eslist_is_initialized(&dir->listing));
	g_assert(fx->odirs > 0);

	eslist_init(&dir->listing, offsetof(struct ftw_dirent, lnk));

	errno = 0;	/* Must disambiguate NULL on end-of-dir and NULL on error */

	while (NULL != (entry = readdir(dir->dp))) {
		uint16 namelen = dir_entry_namelen(entry);
		const char *name = dir_entry_filename(entry);
		struct ftw_dirent *fde;

		WALLOC0(fde);
		fde->d_name = wcopy(name, namelen + 1);	/* Include trailing NUL */
		fde->d_namelen = namelen;
		fde->d_mode = dir_entry_mode(entry);
		fde->d_ino = entry->d_ino;

		eslist_append(&dir->listing, fde);
	}

	dir->count = eslist_count(&dir->listing);

	closedir(dir->dp);
	dir->dp = NULL;
	dir->fd = -1;
	fx->odirs--;

	return 0 == errno ? 0 : -1;
}

/**
 * Find a directory among our parents that we could close.
 *
 * @param fx		the tree walker context
 * @param dir		first directory which we can consider for closing
 *
 * @return 0 if OK, -1 on error with errno set.
 */
static int
ftw_parent_close(struct ftw_ctx *fx, struct ftw_dir *dir)
{
	struct ftw_dir *d;
	int n;

	for (d = dir, n = 1; d != NULL; d = d->parent, n++) {
		if (d->dp != NULL) {
			if (0 == ftw_readdir_all(fx, d))
				return 0;

			if (0 == (fx->flags & FTW_O_SILENT)) {
				ssize_t pos = 0;	/* End of path string, due to "--" below */
				int i;

				for (i = n; i != 0; i--) {
					pos = str_rchr_at(&fx->spath, '/', --pos);
					if (pos <= 0)
						break;		/* No more '/' found, or reached start */
				}

				if (pos > 0) {
					str_t *sub = str_slice(&fx->spath, 0, pos - 1);
					s_carp("%s(): cannot fully read \"%s\": %m",
						G_STRFUNC, str_2c(sub));
					str_destroy(sub);
				} else {
					s_carp("%s(): cannot grab %dth parent dir of \"%s\": %m",
						G_STRFUNC, n, str_2c(&fx->spath));
				}
			}
			return -1;
		}
	}

	return 0;
}

/**
 * Open new directory.
 *
 * @param fx		the tree walker context
 * @param dir		descriptor to initialize
 * @param pdir		parent descriptor, NULL if at the top of the tree
 *
 * @return 0 if OK, -1 on error with errno set.
 */
static int
ftw_opendir(struct ftw_ctx *fx, struct ftw_dir *dir, struct ftw_dir *pdir)
{
	bool retried;

	ftw_ctx_check(fx);
	g_assert(fx->odirs <= fx->nfd);

	ZERO(dir);
	dir->magic = FTW_DIR_MAGIC;
	dir->fd = -1;
	dir->parent = pdir;

	/*
	 * If we have used up all the descriptors we could, we have to close
	 * the parent directory's stream.
	 */

	if G_UNLIKELY(fx->odirs == fx->nfd) {
		if (0 != ftw_parent_close(fx, pdir))
			return -1;
	}

	g_assert(fx->odirs < fx->nfd);

	/*
	 * If they have openat() and fdopendir(), we can accelerate things a bit
	 * by not having the kernel process and validate the full path, as long as
	 * the parent directory is still opened.
	 */

#if defined(HAS_FDOPENDIR) && defined(HAS_OPENAT)
	if (pdir != NULL && is_valid_fd(pdir->fd)) {
		int nfd;
		int flags = O_RDONLY;
		const char *dname = str_2c(&fx->spath) + fx->base;

#ifdef O_DIRECTORY
		flags |= O_DIRECTORY;	/* Fail if entry is no longer a directory! */
#endif

		g_assert('\0' != *dname);

		nfd = openat(pdir->fd, dname, flags);

		/*
		 * Even though we are below the amount of configured file descriptors
		 * for our tree walking, the system or the process could hit a limit
		 * on the amount of files that can be opened.
		 *
		 * When that happens, we attempt to close file descriptors still opened
		 * among our parent directories.
		 */

		if G_UNLIKELY(-1 == nfd) {
			if (EMFILE == errno || ENFILE == errno) {
				if (0 != ftw_parent_close(fx, pdir))
					return -1;
				goto use_opendir;	/* Parent directory closed */
			}
			goto error;
		}

		dir->dp = fdopendir(nfd);
		if G_UNLIKELY(NULL == dir->dp) {
			close(nfd);		/* Guess, fdopendir() could leave it dangling */
			goto error;
		}

		dir->fd = nfd;		/* Necessarily! */
	}
#endif	/* HAS_FDOPENDIR && HAS_OPENAT */

	/*
	 * If they lack one of fdopendir(), openat(), we'll fall through
	 * here.  Otherwise, we have already opened the directory if they had
	 * an opened parent directory.
	 */

use_opendir:
	retried = FALSE;

	/* FALL THROUGH */

retry:
	if (NULL == dir->dp) {
		if (fx->flags & FTW_O_CHDIR) {
			dir->dp = opendir(str_2c(&fx->spath) + fx->base);
		} else {
			dir->dp = opendir(str_2c(&fx->spath));
		}

		/*
		 * Same logic as above: retry once after closing one of the
		 * descriptors still kept opened in our parent directories should
		 * we hit an "out of descriptors" error condition.
		 */

		if G_UNLIKELY(NULL == dir->dp) {
			if (EMFILE == errno || ENFILE == errno) {
				if (!retried) {
					if (0 != ftw_parent_close(fx, pdir))
						return -1;
					retried = TRUE;
					goto retry;
				}
			}
			goto error;
		}

#ifdef HAS_DIRFD
		dir->fd = dirfd(dir->dp);
#endif	/* HAS_DIRFD */
	}

	fx->odirs++;
	return 0;

error:
	/*
	 * The only error our caller expects and can recover from is EACCES,
	 * therefore do not emit any error message when it happens.
	 */

	if (0 == (fx->flags & FTW_O_SILENT) && errno != EACCES) {
		s_carp("%s(): cannot opendir(\"%s\"): %m",
			G_STRFUNC, str_2c(&fx->spath));
	}
	return -1;
}

/**
 * Close directory stream.
 */
static void
ftw_closedir(struct ftw_ctx *fx, struct ftw_dir *dir)
{
	ftw_ctx_check(fx);
	ftw_dir_check(dir);
	g_assert(fx->odirs <= fx->nfd);

	if (NULL == dir->dp) {
		struct ftw_dirent *fde;

		/* Free allocated names */
		ESLIST_FOREACH_DATA(&dir->listing, fde) {
			WFREE_NULL(fde->d_name, fde->d_namelen + 1);
		}

		/* Discard all the list items in one single call */
		eslist_wfree(&dir->listing, sizeof *fde);
	} else {
		g_assert(fx->odirs > 0);
		closedir(dir->dp);
		fx->odirs--;
	}

	ZERO(dir);		/* Makes whole descriptor invalid */
	dir->fd = -1;
}

/**
 * Change to processed directory.
 *
 * @param fx		the tree walker context
 * @param dir		the local directory handle
 *
 * @return 0 if OK, -1 on error with errno set.
 */
static int
ftw_chdir(struct ftw_ctx *fx, struct ftw_dir *dir)
{
	ftw_ctx_check(fx);
	ftw_dir_check(dir);
	g_assert(dir->dp != NULL);

#ifdef HAS_FCHDIR
	if (is_valid_fd(dir->fd))
		return fchdir(dir->fd);
#endif	/* HAS_FCHDIR */

	return chdir(str_2c(&fx->spath) + fx->base);
}

/**
 * Change to parent directory.
 *
 * @param fx		the tree walker context
 * @param pdir		the parent directory handle
 * @param via_link	whether we crossed a symbolic link
 *
 * @return 0 if OK, -1 on error with errno set, -2 on error with warning.
 */
static int
ftw_chdir_parent(struct ftw_ctx *fx, struct ftw_dir *pdir, bool via_link)
{
	int ret;

	ftw_ctx_check(fx);
	ftw_dir_check(pdir);

#ifdef HAS_FCHDIR
	if (is_valid_fd(pdir->fd))
		return fchdir(pdir->fd);
#endif	/* HAS_FCHDIR */

	/*
	 * If they can follow symbolic links, we must not blindly chdir to ".."
	 * since it will point to the parent directory of the link and not to the
	 * parent directory where we want to go, which is the directory where we
	 * traversed the symbolic link!
	 */

	if G_UNLIKELY(via_link) {
		char *relpath;

		g_assert(fx->rootdir != NULL);		/* Created by ftw_process_dir() */

		/*
		 * Reconstruct the relative path to the root directory, where we
		 * started our tree walk.
		 */

		relpath = str_2c(&fx->spath) + fx->rootlen;

		if ('\0' == *relpath) {
			ret = chdir(fx->rootdir);
			if (0 != ret) {
				ret = -2;
				s_carp("%s(): unable to chdir() back to %s: %m",
					G_STRFUNC, fx->rootdir);
			}
		} else {
			str_t *s = str_new(MAX_PATH_LEN / 2);

			str_printf(s, "%s/%s", fx->rootdir, relpath);
			ret = chdir(str_2c(s));
			if (0 != ret) {
				ret = -2;
				s_carp("%s(): unable to chdir() back to %s: %m",
					G_STRFUNC, str_2c(s));
			}
			str_destroy_null(&s);
		}
	} else {
		ret = chdir("..");
	}

	return ret;
}

/**
 * Read next directory entry, copying data into the supplied structure.
 *
 * @param dir		the directory handle
 * @param entry		the entry to fill-in
 *
 * @return 0 if OK, -1 on error, +1 when we reached the end of the directory.
 */
static int
ftw_readdir(struct ftw_dir *dir, struct ftw_dirent *entry)
{
	ftw_dir_check(dir);
	g_assert(entry != NULL);

	if (dir->dp != NULL) {
		struct dirent *de;

		errno = 0;				/* Disambiguates NULL returns from readdir() */
		de = readdir(dir->dp);

		if (NULL == de)
			return 0 == errno ? +1 : -1;

		ZERO(entry);
		entry->d_name = deconstify_char(dir_entry_filename(de));
		entry->d_namelen = dir_entry_namelen(de);
		entry->d_ino = de->d_ino;
		entry->d_mode = dir_entry_mode(de);
	} else {
		struct ftw_dirent *fde;

		if (0 == dir->count)
			return +1;

		/*
		 * We do not remove processed items from the list for two reasons:
		 *
		 * 1. we need to keep around the allocated name since we're copying
		 *    the pointer.
		 * 2. freeing the list as a whole will be more efficient overall than
		 *    doing it one cell at a time.
		 *
		 * Therefore, we have a separate count of unprocessed items.  The next
		 * record is at the head of the list, and it is being moved at the tail
		 * of the list after processing.
		 */

		fde = eslist_head(&dir->listing);
		g_assert(fde != NULL);				/* Since dir->count was not 0 */
		eslist_rotate_left(&dir->listing);	/* Keep record around */
		dir->count--;

		*entry = *fde;	/* struct copy */
	}

	return 0;
}

/**
 * Invoke the callback for current entry.
 *
 * @param fx		the tree walker context
 * @param sb		the stat buffer for the current entry
 * @param flags		additional flags in addition to the file mode
 *
 * @return the callback status.
 */
static ftw_status_t
ftw_callback(struct ftw_ctx *fx, filestat_t *sb, uint32 flags)
{
	ftw_ctx_check(fx);
	g_assert(sb != NULL);
	g_assert(flags != 0);

	/*
	 * Address of string buffer can change when re-allocated, hence always
	 * update pointers. Since these are given to "userland", the content of
	 * the structure could be altered so it's good to always reset it.
	 */

	fx->info.fpath = str_2c(&fx->spath);
	fx->info.fpath_len = str_len(&fx->spath);
	fx->info.fbase = fx->info.fpath + fx->base;
	fx->info.fbase_len = fx->info.fpath_len - fx->base;
	fx->info.base = fx->base;
	fx->info.level = fx->level;

	/*
	 * Make sure the relative path (empty when we are processing the root
	 * directory of the tree) does not start with a '/'.
	 */

	fx->info.rpath = fx->info.fpath + fx->rootlen;
	if ('/' == *fx->info.rpath)
		fx->info.rpath++;
	fx->info.root = fx->info.rpath - fx->info.fpath;
	fx->info.rpath_len = fx->info.fpath_len - fx->info.root;

	fx->info.flags = flags;
	fx->info.ftw_flags = fx->flags;

	return (*fx->cb)(&fx->info, sb, fx->udata);
}
/*
 * Perform stat() on the entry and compute the callback flags.
 *
 * @param fx		the tree walker context
 * @param sb		the stat buffer we can use
 * @param dir		the directory handle
 * @param entry		the directory entry to process
 * @param flags		the flags to be filled
 *
 * @return 0 if we computed suitable flags, -1 on non-recoverable error.
 */
static int
ftw_stat(
	struct ftw_ctx *fx, filestat_t *sb,
	struct ftw_dir *dir, struct ftw_dirent *entry, uint32 *flags)
{
	int ret;

	ftw_ctx_check(fx);
	ftw_dir_check(dir);
	g_assert(sb != NULL);
	g_assert(entry != NULL);
	g_assert(flags != NULL);

#ifdef HAS_FSTATAT
	if (is_valid_fd(dir->fd)) {
		ret = fstatat(dir->fd, entry->d_name, sb,
				(fx->flags & FTW_O_PHYS) ? AT_SYMLINK_NOFOLLOW : 0);
	} else
#endif	/* HAS_FSTATAT */
	{
		const char *name;

		name = (fx->flags & FTW_O_CHDIR) ? entry->d_name : str_2c(&fx->spath);
		ret = (fx->flags & FTW_O_PHYS) ? lstat(name, sb) : stat(name, sb);
	}

	if (0 != ret) {
		if (errno != EACCES && errno != ENOENT) {
			if (0 == (fx->flags & FTW_O_SILENT)) {
				s_carp("%s(): cannot stat(\"%s\"): %m",
					G_STRFUNC, str_2c(&fx->spath));
			}
			return -1;		/* Non-recoverable error */
		}

		if (fx->flags & FTW_O_PHYS)
			*flags = FTW_F_NOSTAT;
		else if (S_ISLNK(entry->d_mode))
			*flags = FTW_F_SYMLINK | FTW_F_DANGLING | FTW_F_NOSTAT;
		else {
			/*
			 * FTW_O_PHYS was not given, i.e. we can follow symlinks, but
			 * entry->d_mode was not set accordingly (probably because the
			 * filesystem does not report d_type).
			 *
			 * Therefore we need to do an lstat() to get proper flags.
			 */

#ifdef HAS_FSTATAT
			if (is_valid_fd(dir->fd)) {
				ret = fstatat(dir->fd, entry->d_name, sb, AT_SYMLINK_NOFOLLOW);
			} else
#endif	/* HAS_FSTATAT */
			{
				const char *name = (fx->flags & FTW_O_CHDIR) ?
					entry->d_name : str_2c(&fx->spath);
				ret = lstat(name, sb);
			}

			if (0 == ret && S_ISLNK(sb->st_mode))
				*flags = FTW_F_SYMLINK | FTW_F_DANGLING;
			else
				*flags = FTW_F_NOSTAT;
		}

		/*
		 * When FTW_F_NOSTAT is on, we have no valid stat() information in
		 * the structure, so zero it to avoid confusion.
		 *
		 * Also, if we have d_type fields in the dirent structure and we can
		 * identify that the entry was of a certain type, flag it as such so
		 * that we can nonetheless invoke the callback with as much information
		 * as we could gather.
		 */

		if (*flags & FTW_F_NOSTAT) {
			ZERO(sb);

			if (S_ISDIR(entry->d_mode))
				*flags |= FTW_F_DIR;
			else if (S_ISLNK(entry->d_mode))
				*flags |= FTW_F_SYMLINK;
			else if (S_ISREG(entry->d_mode))
				*flags |= FTW_F_FILE;
			else if (0 != entry->d_mode)
				*flags |= FTW_F_OTHER;
		}
	} else {
		if (S_ISREG(sb->st_mode))
			*flags = FTW_F_FILE;
		else if (S_ISDIR(sb->st_mode))
			*flags = FTW_F_DIR;
		else if (S_ISLNK(sb->st_mode))
			*flags = FTW_F_SYMLINK;
		else
			*flags = FTW_F_OTHER;
	}

	/*
	 * If we're dealing with a directory, we need to know whether it was
	 * a symbolic link we crossed, in case we also chdir() to it, to be
	 * able to properly restore the current working directory later on.
	 */

	if G_UNLIKELY(
		FTW_O_CHDIR == (fx->flags & (FTW_O_PHYS | FTW_O_CHDIR)) &&
		(*flags & FTW_F_DIR)
	) {
		/*
		 * If the filesystem sets d_type, we'll know without issuing another
		 * lstat() call.  We don't need fstatat() here since we know we're
		 * doing chdir() to process directories.
		 */

		if (S_ISLNK(entry->d_mode)) {
			*flags |= FTW_F_SYMLINK;
		} else {
			filestat_t buf;
			ret = lstat(entry->d_name, &buf);
			if (0 == ret && S_ISLNK(buf.st_mode))
				*flags |= FTW_F_SYMLINK;
		}
	}

	return 0;
}

/**
 * Process a directory entry.
 *
 * @param fx		the tree walker context
 * @param sb		the stat buffer we can use (filled with directory info)
 * @param dir		the directory handle
 * @param entry		the directory entry to process
 */
static ftw_status_t
ftw_process_entry(
	struct ftw_ctx *fx,
	filestat_t *sb, struct ftw_dir *dir, struct ftw_dirent *entry)
{
	uint32 flags;
	ftw_status_t result;

	ftw_ctx_check(fx);
	ftw_dir_check(dir);
	g_assert(entry != NULL);

	/*
	 * We always skip "." and ".." entries.
	 */

	if G_UNLIKELY('.' == entry->d_name[0]) {
		if (
			'\0' == entry->d_name[1] ||
			('.' == entry->d_name[1] && '\0' == entry->d_name[2])
		)
			return FTW_STATUS_OK;
	}

	str_cat_len(&fx->spath, entry->d_name, entry->d_namelen);

	if (-1 == ftw_stat(fx, sb, dir, entry, &flags))
		return FTW_STATUS_ERROR;

	/*
	 * If it's not a file, directory or symlink, only process when FTW_O_ALL.
	 */

	if ((flags & FTW_F_OTHER) && 0 == (fx->flags & FTW_O_ALL))
		return FTW_STATUS_OK;

	/*
	 * If we could not stat the entry, we obviously cannot recurse even
	 * if it is a directory.  We cannot detect duplicate entries either
	 * since we have no information at all.  Still, we have a name that
	 * was present in the directory at the time we read it, so let them
	 * know about the entry and decide.
	 */

	if G_UNLIKELY(flags & FTW_F_NOSTAT)
		return ftw_callback(fx, sb, flags);

	/*
	 * If we're crossing mount points, skip the entry.
	 */

	if ((fx->flags & FTW_O_MOUNT) && sb->st_dev != fx->rootdev)
		return FTW_STATUS_OK;

	/*
	 * When we can follow symbolic links, ensure this is not an entry
	 * we have already processed.
	 */

	if (0 == (fx->flags & FTW_O_PHYS)) {
		struct ftw_entry fe;
		struct ftw_entry *nfe;
		void *old;

		fe.dev = sb->st_dev;
		fe.ino = sb->st_ino;

		if (erbtree_contains(&fx->entries, &fe))
			return FTW_STATUS_OK;

		nfe = ftw_entry_alloc(fe.dev, fe.ino);
		old = erbtree_insert(&fx->entries, &nfe->node);

		g_assert(NULL == old);		/* Node was not present in tree */
	}

	/*
	 * If we're dealing with a directory, we need to recurse down.
	 * Otherwise, just invoke the callback on the entry.
	 */

	if (flags & FTW_F_DIR) {
		result = ftw_process_dir(fx, sb, dir, 0 != (flags & FTW_F_SYMLINK));
	} else {
		result = ftw_callback(fx, sb, flags);

		if G_UNLIKELY(FTW_STATUS_SKIP_SUBTREE == result) {
			s_carp_once("%s(): ignoring FTW_STATUS_SKIP_SUBTREE from %s(): "
				"called on entry without FTW_F_DIR",
				G_STRFUNC, stacktrace_function_name(fx->cb));
			result = FTW_STATUS_OK;
		}
	}

	return result;
}

/**
 * Recursively process the directory whose path is held in ``fx->spath''.
 *
 * @param fx		the tree walker context
 * @param sb		the stat buffer we can use (filled with directory info)
 * @param pdir		the parent directory (NULL if at the top of tree)
 * @param is_link	whether we're traversing a symbolic link
 *
 * @return processing status, one of FTW_STATUS_*.
 */
static ftw_status_t
ftw_process_dir(
	struct ftw_ctx *fx, filestat_t *sb, struct ftw_dir *pdir, bool is_link)
{
	struct ftw_dir dir;
	struct ftw_dirent entry;
	ftw_status_t result = FTW_STATUS_OK;
	int saved_base;
	size_t saved_len;
	int r;

	ftw_ctx_check(fx);
	g_assert(NULL == pdir || fx->base >= fx->rootlen);
	g_assert(NULL != pdir || 0 == fx->base);

	if G_UNLIKELY(0 != ftw_opendir(fx, &dir, pdir)) {
		if (EACCES == errno) {
			/*
			 * Directory exists, was stat()-ed but cannot be opened for reading.
			 * This is not an error condition a priori, but we let the callback
			 * decide how to handle this.
			 *
			 * Note that we do not attempt to chdir() to it, even if they gave
			 * the FTW_O_CHDIR flag.
			 *
			 * And this will be a one-time call: no pre-order / post-order
			 * since the directory cannot be read.
			 */

			return ftw_callback(fx, sb, FTW_F_DIR | FTW_F_NOREAD);
		}
		return FTW_STATUS_ERROR;
	}

	/*
	 * If we're notifying directories in pre-order, now is the time.
	 */

	if (fx->flags & FTW_O_ENTRY) {
		result = ftw_callback(fx, sb, FTW_F_DIR);

		if G_UNLIKELY(result != FTW_STATUS_OK) {
			ftw_closedir(fx, &dir);

			if G_UNLIKELY(FTW_STATUS_SKIP_SUBTREE == result)
				result = FTW_STATUS_OK;

			return result;
		}
	}

	/*
	 * Move to that directory if requested.
	 */

	if (fx->flags & FTW_O_CHDIR) {
		if G_UNLIKELY(0 != ftw_chdir(fx, &dir)) {
			ftw_closedir(fx, &dir);
			return FTW_STATUS_ERROR;
		}

		/*
		 * Since we have to chdir() to each directory we traverse, we need to
		 * save the absolute path of the intial directory we're traversing so
		 * that we can always reconstruct the absolute path to the parent
		 * directory when we chdir() through a symlink!
		 *
		 * See ftw_chdir_parent() to see how this value will be used.
		 */

		if G_UNLIKELY(0 == (fx->flags & FTW_O_PHYS) && NULL == pdir) {
			g_assert(NULL == fx->rootdir);

			fx->rootdir = ftw_getcwd();

			if (NULL == fx->rootdir) {
				s_carp("%s(): cannot get current working directory in %s: %m",
					G_STRFUNC, str_2c(&fx->spath));
				ftw_closedir(fx, &dir);
				return FTW_STATUS_ERROR;
			}
		}
	}

	/*
	 * Process that directory.
	 *
	 * Note that we always use '/' as the path separator since that works
	 * on all UNIX and Windows platforms.
	 */

	saved_base = fx->base;
	saved_len = str_len(&fx->spath);

	/*
	 * Traps traversals from "/", to avoid two successive '/' in path.
	 * Otherwise, we know that there cannot be any trailing '/' in the path.
	 */

	if (fx->level != 0 || '/' != str_at(&fx->spath, -1))
		str_putc(&fx->spath, '/');

	fx->base = str_len(&fx->spath);
	fx->level++;

	g_assert(UNSIGNED(fx->base) >= saved_len);		/* No int overflow */

	while (0 == (r = ftw_readdir(&dir, &entry))) {
		str_setlen(&fx->spath, fx->base);	/* Useless for first entry */
		result = ftw_process_entry(fx, sb, &dir, &entry);

		if G_UNLIKELY(FTW_STATUS_SKIP_SUBTREE == result)
			result = FTW_STATUS_OK;

		if G_UNLIKELY(result != FTW_STATUS_OK)
			break;
	}

	ftw_closedir(fx, &dir);

	if (r < 0)
		return FTW_STATUS_ERROR;

	if G_UNLIKELY(FTW_STATUS_SKIP_SIBLINGS == result)
		result = FTW_STATUS_OK;		/* OK, exited directory processing loop */

	/*
	 * Done with directory, retore previous context.
	 */

	g_assert(fx->level > 0);
	g_assert(fx->base >= 1);

	fx->level--;
	str_setlen(&fx->spath, saved_len);	/* Also strips any '/' added above */
	fx->base = saved_base;

	/*
	 * If we're notifying directories in post-order, now is the time.
	 *
	 * Note that we do not invoke the post-order callback if we have an
	 * error / abort condition so far.
	 */

	if (FTW_STATUS_OK == result && (fx->flags & FTW_O_DEPTH)) {
		result = ftw_callback(fx, sb, FTW_F_DIR | FTW_F_DONE);

		if G_UNLIKELY(FTW_STATUS_SKIP_SUBTREE == result) {
			/* They are confused, it's too late! */
			s_carp_once("%s(): ignoring FTW_STATUS_SKIP_SUBTREE from %s(): "
				"called with FTW_F_DONE (post-order visit)",
				G_STRFUNC, stacktrace_function_name(fx->cb));
			result = FTW_STATUS_OK;
		}
	}

	/*
	 * If we're changing directories, we need to move out of the processed
	 * directory, back to the parent directory.
	 *
	 * However, don't bother if we're going to abort processing or if we would
	 * go back to the root directory, since the ftw_foreach() routine will
	 * handle the restoration of the original working directory.
	 */

	if (
		pdir != NULL && (fx->flags & FTW_O_CHDIR) &&
		!(FTW_STATUS_CANCELLED == result || FTW_STATUS_ABORT == result)
	) {
		int ret = ftw_chdir_parent(fx, pdir, is_link);

		if (0 != ret) {
			/* If ret is -2, then ftw_chdir_parent() already emitted warning */
			if (-1 == ret && 0 == (fx->flags & FTW_O_SILENT)) {
				s_carp("%s(): cannot chdir() back to parent of \"%s\"%s: %m",
					G_STRFUNC, str_2c(&fx->spath),
					is_link ? " (traversed via symlink)" : "");
			}
			result = FTW_STATUS_ERROR;
		}
	}

	return result;
}

/**
 * Cleanup resources used to track the original current working directory.
 */
static void
ftw_cleanup_cwd(struct ftw_ctx *fx)
{
	ftw_ctx_check(fx);

	if (-1 != fx->callfd)
		close(fx->callfd);

	HFREE_NULL(fx->calldir);
}

/**
 * Restore previous current working directory and cleanup resources.
 */
static void
ftw_restore_cwd(struct ftw_ctx *fx)
{
	ftw_ctx_check(fx);

#ifdef HAS_FCHDIR
	if (-1 != fx->callfd) {
		if (-1 == fchdir(fx->callfd)) {
			s_carp("%s(): cannot restore original working directory: %m",
				G_STRFUNC);
		}
	} else
#endif	/* HAS_FCHDIR */
	{
		if (-1 == chdir(fx->calldir)) {
			s_carp("%s(): cannot go back to directory \"%s\": %m",
				G_STRFUNC, fx->calldir);
		}
	}

	ftw_cleanup_cwd(fx);
}

/**
 * Starting from ``dirpath'', recursively traverse the filesystem, invoking
 * the supplied ``cb'' on each entry.
 *
 * The callback function will get paths under the initial ``dirpath'': if that
 * directory was relative from the current working directory, they will be
 * relative; otherwise they will be absolute paths.  However, when FTW_O_CHDIR
 * is given, callbacks are executed within the currently visited directory,
 * so if the file has to be opened, it must be through its basename.
 *
 * The callback status is monitored to determine whether traversal can continue.
 *
 * By default, symbolic links are traversed and mount points are no obstacles.
 * However, each file will only be reported once, no matter how many loops
 * the symbolic links create.
 *
 * Most of the time, one would specify FTW_O_PHYS to prevent symbolic links
 * from being followed and FTW_O_MOUNT to stay on the original file system and
 * prevent crossing mount points.
 *
 * To allow the callback to be executed in the context of the processed
 * directory, use FTW_O_CHDIR.  The initial working directory will be restored
 * before returning.
 *
 * Unless FTW_O_ALL is given, the callback is only invoked for files,
 * directories and symlinks (when FTW_O_PHYS is given).  This means entries
 * like devices, fifos, sockets will be skipped.
 *
 * The normal tree traversal is pre-order: the directory is handled and then
 * its entries are processed.  To request post-order traversal, whereby the
 * directory is processed only after all its entries where, use FTW_O_DEPTH.
 * In that case, the callback will get the FTW_F_DONE flag set to let the
 * processing callback know that the directory was fully processed.
 *
 * It is also possible to request directory notifications in both pre- and post-
 * oder by specifying FTW_O_ENTRY | FTW_O_DEPTH.
 *
 * To avoid reading the directory content into memory, we keep the parent
 * directories opened whilst recursing.  The maximum amount amout of file
 * descriptors to use can however be specified through ``nfd'', with 0 meaning
 * that we let the routine guess a suitable amount.
 *
 * @param dirpath		the root directory to start traversal from
 * @param flags			operating flags (combination of FTW_O_*)
 * @param nfd			max opened directories we can keep simultaneously
 * @param cb			the callback to invoke on each entry
 * @param data			opaque argument to pass to the callback
 *
 * @return FTW_STATUS_OK if OK, FTW_STATUS_ERROR if an error occurred,
 * FTW_STATUS_CANCELLED if the callback was externally told to cancel the
 * traversal (through a global variable being set, for instance), and
 * FTW_STATUS_ABORT if the callback decided to abort the traversal.
 */
ftw_status_t
ftw_foreach(const char *dirpath, uint32 flags, int nfd, ftw_fn_t cb, void *data)
{
	struct ftw_ctx fx;
	filestat_t buf;
	ftw_status_t result = FTW_STATUS_OK;
	bool is_link = FALSE;

	g_assert(dirpath != NULL);
	g_assert(nfd >= 0);
	g_assert(cb != NULL);

	if ('\0' == *dirpath) {
		errno = ENOENT;
		if (0 == (flags & FTW_O_SILENT))
			s_carp("%s(): given an empty path to process", G_STRFUNC);
		return FTW_STATUS_ERROR;
	}

	if (0 == nfd)
		nfd = getdtablesize() / 25;		/* 4% of available descriptors */

	nfd = MAX(nfd, 1);

	ZERO(&fx);
	fx.nfd = nfd;
	fx.udata = data;
	fx.info.ftw_flags = fx.flags = flags;
	fx.callfd = -1;
	fx.cb = cb;

#ifndef HAS_LSTAT
	fx.flags |= FTW_O_PHYS;			/* No symbolic links on that platform */
#endif

	if (0 == (flags & FTW_O_DEPTH))
		fx.flags |= FTW_O_ENTRY;	/* Default is pre-order directory visits */

	if (-1 == lstat(dirpath, &buf)) {
		if (0 == (flags & FTW_O_SILENT))
			s_carp("%s(): cannot stat(\"%s\"): %m", G_STRFUNC, dirpath);
		return FTW_STATUS_ERROR;
	}

	/*
	 * If we'll have to get back here, we have these options:
	 *
	 * 1. when fchdir() is available, we open the current directory.
	 * 2. we request the current working directory to chdir() to later.
	 */

	if (0 == (flags & FTW_O_CHDIR))
		goto got_cwd;

#ifdef HAS_FCHDIR

	if (nfd > 1) {
		fx.callfd = open(".", O_RDONLY);
		if (-1 != fx.callfd) {
			fx.nfd--;			/* We're using one fd now to track the cwd */
			goto got_cwd;
		}
		if (0 == (flags & FTW_O_SILENT)) {
			s_carp("%s(): unable to open \".\" to keep current directory: %m",
				G_STRFUNC);
		}
	}
	/* FALL THROUGH */

#endif	/* HAS_FCHDIR */

	fx.calldir = ftw_getcwd();
	if (NULL == fx.calldir) {
		if (0 == (flags & FTW_O_SILENT)) {
			s_carp("%s(): unable to get initial current directory: %m",
				G_STRFUNC);
		}
		return FTW_STATUS_ERROR;
	}

got_cwd:
	/*
	 * Check the ``dirpath'' argument: if it's not a directory, it can
	 * probably be processed immediately and we will be done!
	 */

	fx.magic = FTW_CTX_MAGIC;		/* About to use the context */

	g_assert(0 == fx.info.flags);

	if (!(FTW_O_PHYS & flags) && S_ISLNK(buf.st_mode)) {
		is_link = TRUE;
		if (-1 == stat(dirpath, &buf))
			fx.info.flags |= FTW_F_DANGLING;
	}

	if (!S_ISDIR(buf.st_mode)) {
		if (
			S_ISREG(buf.st_mode) ||		/* Regular file */
			S_ISLNK(buf.st_mode) ||		/* Symlink, no FTW_O_PHYS */
			(FTW_O_ALL & flags)			/* Any entry */
		) {
			fx.info.fpath = dirpath;
			fx.info.fbase = filepath_basename(dirpath);
			fx.info.rpath = fx.info.fbase;
			fx.info.base = ptr_diff(fx.info.fbase, fx.info.fpath);
			fx.info.root = fx.info.base;

			if (S_ISREG(buf.st_mode)) {
				fx.info.flags |= FTW_F_FILE;
			} else if (S_ISLNK(buf.st_mode)) {
				fx.info.flags |= FTW_F_SYMLINK;
			} else {
				fx.info.flags |= FTW_F_OTHER;
			}

			if (flags & FTW_O_CHDIR) {
				char *dir = filepath_directory(dirpath);
				if (dir != NULL) {
					if (-1 == chdir(dir)) {
						if (0 == (flags & FTW_O_SILENT)) {
							s_carp("%s(): cannot chdir() to \"%s\": %m",
								G_STRFUNC, dir);
						}
						HFREE_NULL(fx.calldir);		/* Have not changed cwd! */
						result = FTW_STATUS_ERROR;
						goto done;
					}
					HFREE_NULL(dir);
				}
			}

			result = (*cb)(&fx.info, &buf, fx.udata);
			goto restore_cwd;
		}

		/*
		 * We're not processing the entry, we did not change the workding dir.
		 */

		if (flags & FTW_O_CHDIR)
			ftw_cleanup_cwd(&fx);			/* Cleanup memory used */

		goto done;
	}

	/*
	 * At this stage, we have validated that ``dirpath'' is a directory.
	 * It has been successfully stat()'ed and is described in ``buf''.
	 */

	if (flags & FTW_O_MOUNT) {
		/*
		 * We need to avoid crossing filesystems, so remember the device on
		 * which the root directory lies.  If ``dirpath'' was a symbolic link
		 * and they have ommitted FTW_O_PHYS, we may already be on another
		 * device at this stage, but that is OK -- the crossing of mountpoints
		 * is only relative to the actual physical root directory...
		 */

		fx.rootdev = buf.st_dev;
	}

	if (0 == (flags & FTW_O_PHYS)) {
		struct ftw_entry *nfe;
		void *old;

		/*
		 * Since we're following symbolic links (logical traversal of the
		 * tree, not a physical one), we may go through loops.  In order to
		 * not visit the same entry twice, we remember all the (dev, ino)
		 * tuples we encounter by storing them in a red-black tree.
		 */

		erbtree_init(&fx.entries,
			ftw_entry_cmp, offsetof(struct ftw_entry, node));

		/*
		 * Insert the root directory, which we are about to enter.
		 */

		nfe = ftw_entry_alloc(buf.st_dev, buf.st_ino);
		old = erbtree_insert(&fx.entries, &nfe->node);

		g_assert(NULL == old);		/* Node was not present in tree */
	}

	/*
	 * This string will be used to construct the path of each entry,
	 * as we move down the file tree.  It is a path derived from ``dirpath''.
	 * As such, it cannot be used to access the files directly when traversing
	 * with FTW_O_CHDIR: the callback must use the ``fbase'' field from the
	 * ftw_info_t structure to access the processed items.
	 */

	{
		size_t dirlen = strlen(dirpath);

		str_create(&fx.spath, MAX_PATH_LEN / 4 + 1 + dirlen);
		str_cpy_len(&fx.spath, dirpath, dirlen);

		/* Remove trailing '/' in path, unless it ends-up being standalone */

		while ('/' == str_at(&fx.spath, -1) && str_len(&fx.spath) > 1)
			str_chop(&fx.spath);

		/* Remove trailing G_DIR_SEPARATOR in path */

		if (G_DIR_SEPARATOR != '/') {
			while (
				G_DIR_SEPARATOR == str_at(&fx.spath, -1) &&
				str_len(&fx.spath) > 1
			)
				str_chop(&fx.spath);
		}
	}

	/*
	 * Handle the directory, recursively.
	 */

	fx.base = 0;
	fx.rootlen = str_len(&fx.spath);

	result = ftw_process_dir(&fx, &buf, NULL, is_link);

	/*
	 * Cleanup data structures.
	 */

	str_discard(&fx.spath);

	if (0 == (flags & FTW_O_PHYS)) {
		erbtree_discard(&fx.entries, ftw_entry_free);
		HFREE_NULL(fx.rootdir);		/* Allocated in ftw_process_dir() */
	}

	/* FALL THROUGH */

restore_cwd:
	if (flags & FTW_O_CHDIR)
		ftw_restore_cwd(&fx);		/* Will cleanup memory */

	/* FALL THROUGH */

done:
	fx.magic = 0;

	g_assert(0 == fx.odirs);

	/*
	 * Never let one of the internal statuses (either governing the pruning of
	 * whole directories like FTW_STATUS_SKIP_SUBTREE, or allowing to skip
	 * the remaining entries from a directory like FTW_STATUS_SKIP_SIBLINGS)
	 * be visible from the outside of the tree walking process.
	 */

	if (FTW_STATUS_SKIP_SIBLINGS == result || FTW_STATUS_SKIP_SUBTREE == result)
		result = FTW_STATUS_OK;

	return result;
}

/* vi: set ts=4 sw=4 cindent: */
