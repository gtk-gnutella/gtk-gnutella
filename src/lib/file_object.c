/*
 * Copyright (c) 2006 Christian Biere
 * Copyright (c) 2013 Raphael Manfredi
 *
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
 * Sharing of file descriptors through file objects.
 *
 * @author Christian Biere
 * @date 2006
 * @author Raphael Manfredi
 * @date 2013
 */

/**
 * @note NOTE:
 * It is the callers responsibility to ensure consistency between the file
 * descriptor and the pathname. Thus, this must not be used with arbitrary
 * paths but only for directories under our control.  For example, the file
 * could be removed by another process and file_object_open() would return the
 * file descriptor of the already removed file. When the last file object for
 * this pathname is released, the file contents would be lost.
 *
 * Likewise, you can open a file that has already been deleted or moved when
 * using file_object_open(). Whether the file still exists can be checked with
 * fstat(). However this is not necessarily the same file referenced by the
 * file object.
 *
 * The current offset is shared that means, you should always use pread()
 * instead of read(), pwrite() instead of write() etc. The replacement
 * functions -- compat_pread() and compat_pwrite() -- do not restore the
 * original file offset.
 *
 * The file objects created with O_RDWR are returned for all
 * file_object_open() requests. That means the caller must take care to not
 * accidently write to a file object acquired with O_RDONLY.
 *
 * Normally, file objects should be acquired as follows:
 *
 *  // Try to reuse an existing file object
 *  file = file_object_open(pathname, mode);
 *  if (!file) {
 *      int fd;
 * 
 *      // If none exists, create a new file object
 *      fd = open_the_file(pathname, mode);
 *      if (fd >= 0) {
 *      	file = file_object_new(fd, pathname, mode);
 *      }
 *      // Do not use fd directly, could have been closed/reused already
 *  }
 *  if (!file) {
 *     // Error handling
 *  }
 *
 * In order to make the user code easier to read, use the file_object_get()
 * convenience routine whenever possible, since it factorizes most of the
 * common logic.
 *
 * If a file object is created and released in the same function i.e., reuse
 * unlikely, the strictest access mode should be used (O_RDONLY or O_WRONLY).
 * Otherwise, it is best to use O_RDWR so that the same object can be reused
 * by further calls to file_object_open() whilst the object exists.
 *
 * This API does not allow opening the same file twice for compatible access
 * modes. You can create one file object for O_RDONLY and another with
 * O_WRONLY for the same path though, if none with O_RDWR exists.
 */

#include "common.h"

#include "file_object.h"

#include "atoms.h"
#include "compat_pio.h"
#include "fd.h"
#include "file.h"
#include "glib-missing.h"
#include "hikset.h"
#include "iovec.h"
#include "mutex.h"
#include "once.h"
#include "path.h"
#include "str.h"			/* For str_private() */
#include "walloc.h"

#include "override.h"       /* Must be the last header included */

static hikset_t *ht_file_objects_rdonly;	/* read-only file objects */
static hikset_t *ht_file_objects_wronly;	/* write-only file objects */
static hikset_t *ht_file_objects_rdwr;		/* read+write-able file objects */

static mutex_t ht_file_objects_mtx = MUTEX_INIT;

#define FILE_OBJECTS_LOCK	mutex_lock(&ht_file_objects_mtx)
#define FILE_OBJECTS_UNLOCK	mutex_unlock(&ht_file_objects_mtx)

#define assert_file_objects_locked() \
	assert_mutex_is_owned(&ht_file_objects_mtx)

enum file_object_magic { FILE_OBJECT_MAGIC = 0x6b084325 };	/**< Magic number */

struct file_object {
	enum file_object_magic magic;
	const char *pathname;	/* atom */
	int ref_count;
	int fd;
	int accmode;	/* O_RDONLY, O_WRONLY, O_RDWR */
	int revoked;
};

/**
 * Applies some basic and fast consistency checks to a file object and
 * causes an assertion failure if a check fails.
 */
static inline void
file_object_check_minimal(const struct file_object * const fo)
{
	g_assert(fo);
	g_assert(FILE_OBJECT_MAGIC == fo->magic);
	g_assert(fo->pathname != NULL);
}

/**
 * Applies some basic and fast consistency checks to a file object and
 * causes an assertion failure if a check fails.
 */
static inline void
file_object_check(const struct file_object * const fo)
{
	file_object_check_minimal(fo);
	g_assert(fo->ref_count > 0);
	g_assert(fo->ref_count < INT_MAX);
}

/**
 * Get the hash table for a given access mode.
 *
 * @return The hash table holding file object for the access mode.
 */
static inline hikset_t *
file_object_mode_get_table(const int accmode)
{
	switch (accmode) {
	case O_RDONLY:	return ht_file_objects_rdonly;
	case O_WRONLY:	return ht_file_objects_wronly;
	case O_RDWR:	return ht_file_objects_rdwr;
	}
	return NULL;
}

/**
 * Lookup file object in the table handling specified access mode.
 *
 * @param pathname		path to file for which we want a file object
 * @param accmode		access mode to the file
 *
 * @return found file object, NULL if not found
 */
static inline struct file_object *
file_object_lookup(const char * const pathname, const int accmode)
{
	struct file_object *fo;

	assert_file_objects_locked();

	fo = hikset_lookup(file_object_mode_get_table(accmode), pathname);

	return fo;
}

/**
 * Insert file object in the table handling specified access mode.
 *
 * @param fo		the file object to insert
 * @param accmode		access mode to the file
 */
static inline void
file_object_insert(const struct file_object *fo, const int accmode)
{
	assert_file_objects_locked();

	hikset_insert(file_object_mode_get_table(accmode), fo);
}

/**
 * Remove file object from the table handling specified access mode.
 *
 * @param fo		the file object to insert
 * @param accmode		access mode to the file
 */
static inline void
file_object_remove(const struct file_object *fo, const int accmode)
{
	assert_file_objects_locked();

	hikset_remove(file_object_mode_get_table(accmode), fo->pathname);
}

/**
 * Find an existing file object associated with the given pathname
 * for the given access mode.
 *
 * @return If no file object with the given pathname is found NULL
 *		   is returned.
 */
static struct file_object *
file_object_find(const char * const pathname, int accmode)
{
	struct file_object *fo;

	assert_file_objects_locked();

	g_return_val_if_fail(ht_file_objects_rdonly, NULL);
	g_return_val_if_fail(ht_file_objects_wronly, NULL);
	g_return_val_if_fail(ht_file_objects_rdwr, NULL);
	g_return_val_if_fail(pathname, NULL);
	g_return_val_if_fail(is_absolute_path(pathname), NULL);

	fo = file_object_lookup(pathname, O_RDWR);

	/*
	 * We need to find a more specific file object if looking for O_WRONLY
	 * or O_RDONLY ones.
	 */

	if (O_RDWR != accmode) {
		struct file_object *xfo;
		xfo = file_object_lookup(pathname, accmode);
		if (xfo != NULL) {
			g_assert(xfo->accmode == accmode);
			fo = xfo;
		}
	}

	if (fo) {
		file_object_check_minimal(fo);
		g_assert(is_valid_fd(fo->fd));
		g_assert(0 == strcmp(pathname, fo->pathname));
		g_assert(fd_accmode_is_valid(fo->fd, accmode));
		g_assert(!fo->revoked);
	}

	return fo;
}

static struct file_object *
file_object_alloc(const int fd, const char * const pathname, int accmode)
{
	static const struct file_object zero_fo;
	struct file_object *fo;

	assert_file_objects_locked();

	g_return_val_if_fail(fd >= 0, NULL);
	g_return_val_if_fail(pathname, NULL);
	g_return_val_if_fail(is_absolute_path(pathname), NULL);
	g_return_val_if_fail(!file_object_find(pathname, accmode), NULL);

	WALLOC(fo);
	*fo = zero_fo;
	fo->magic = FILE_OBJECT_MAGIC;
	fo->ref_count = 1;
	fo->fd = fd;
	fo->accmode = accmode;
	fo->pathname = atom_str_get(pathname);

	file_object_check(fo);
	g_assert(is_valid_fd(fo->fd));
	file_object_insert(fo, accmode);

	return fo;
}

static void
file_object_revoke(struct file_object * const fo)
{
	const struct file_object *xfo;
	
	file_object_check_minimal(fo);
	assert_file_objects_locked();

	g_return_if_fail(!fo->revoked);

	xfo = file_object_find(fo->pathname, fo->accmode);
	g_assert(xfo == fo);

	file_object_remove(fo, fo->accmode);
	fo->revoked = TRUE;
}

static void
file_object_free(struct file_object * const fo)
{
	file_object_check_minimal(fo);
	g_assert(fo->revoked);

	fd_close(&fo->fd);
	atom_str_free_null(&fo->pathname);
	fo->magic = 0;
	WFREE(fo);
}

/**
 * Acquires a file object for a given pathname and access mode. If
 * no matching file object exists, NULL is returned.
 *
 * @param pathname An absolute pathname.
 * @return	On failure NULL is returned. On success a file object is
 *			returned.
 */
struct file_object *
file_object_open(const char * const pathname, int accmode)
{
	struct file_object *fo;

	g_return_val_if_fail(pathname, NULL);
	g_return_val_if_fail(is_absolute_path(pathname), NULL);

	file_object_init();

	FILE_OBJECTS_LOCK;

	fo = file_object_find(pathname, accmode);
	if (fo) {
		fo->ref_count++;
		g_assert(is_valid_fd(fo->fd));
	}

	FILE_OBJECTS_UNLOCK;

	return fo;
}

/**
 * Acquires a new file object for a given pathname.
 *
 * If there is a file object registered for this pathname already, the supplied
 * file descriptor is closed.
 *
 * @param fd		an existing descriptor to pathname, with right access mode
 * @param pathname	absolute pathname to file
 * @param accmode	access mode wanted for the file
 * 
 * @return a file object enabling I/O operations on success, NULL on error.
 */
struct file_object *
file_object_new(const int fd, const char * const pathname, int accmode)
{
	struct file_object *fo;

	file_object_init();

	g_return_val_if_fail(fd >= 0, NULL);
	g_return_val_if_fail(fd_accmode_is_valid(fd, accmode), NULL);
	g_return_val_if_fail(pathname, NULL);
	g_return_val_if_fail(is_absolute_path(pathname), NULL);

	/*
	 * Handle concurrent calls to file_object_new().
	 */

	FILE_OBJECTS_LOCK;

	fo = file_object_find(pathname, accmode);
	if G_LIKELY(NULL == fo) {
		fo = file_object_alloc(fd, pathname, accmode);
	} else {
		if (-1 == close(fd))
			g_warning("%s: cannot close(%d): %m", G_STRFUNC, fd);
	}

	FILE_OBJECTS_UNLOCK;

	return fo;
}

/**
 * Acquires a file object for a given pathname and access mode. If
 * no matching file object exists and the file cannot be open with the
 * specified access mode, NULL is returned.
 *
 * When opening a file read-only, the file_absolute_open() routine is called
 * to open the file, which will trigger a warning if the file is not found and
 * fail if the pathname is not absolute.
 *
 * When opening a file with write access, the file_open_missing() routine is
 * called to open the file, meaning that a missing file will not be reported
 * as an error, but the file object will not be created either.
 *
 * @param pathname An absolute pathname.
 * @return	On failure NULL is returned and errno is set.
 *          On success a file object is returned.
 */
struct file_object *
file_object_get(const char *pathname, int accmode)
{
	struct file_object *fo;

	/*
	 * Try to reusing existing file descriptor attached to the path for
	 * this access mode.
	 *
	 * There is no need to take a lock here: if the file object does not exist,
	 * we'll open the file and file_object_new() will grab the lock and check
	 * for an existing file object again before creating the file object itself.
	 */

	fo = file_object_open(pathname, accmode);

	if G_UNLIKELY(NULL == fo) {
		int fd;

		/*
		 * No known file object for this access mode, open the file then and
		 * if we can, wrap the file descriptor in a suitable file object.
		 */

		if (O_RDONLY == accmode) {
			 fd = file_absolute_open(pathname, accmode, 0);
		} else {
			 fd = file_open_missing(pathname, accmode);
		}

		if G_LIKELY(fd >= 0) {
			fo = file_object_new(fd, pathname, accmode);
		}
	}

	return fo;
}

/**
 * Releases a file object and frees its memory. The underlying file
 * descriptor however is not closed unless no other file object references
 * it. The pointer is nullified.
 *
 * @param fo_ptr If pointing to NULL, nothing happens. Otherwise, it must
 *               point to an initialized file_object.
 */
void
file_object_release(struct file_object **fo_ptr)
{
	g_assert(fo_ptr);

	if (*fo_ptr) {
		struct file_object *fo = *fo_ptr;
		bool revoked = FALSE;

		file_object_check(fo);

		FILE_OBJECTS_LOCK;

		if (1 == fo->ref_count--) {
			file_object_revoke(fo);
			revoked = TRUE;
		}

		FILE_OBJECTS_UNLOCK;

		if (revoked)
			file_object_free(fo);

		*fo_ptr = NULL;
	}
}

/**
 * Special operations that we can perform on file objects.
 *
 * These require special treatment because Windows frowns upon renaming
 * and unlinking of opened files and will not, unlike UNIX, keep an already
 * opened file accessible after it has been removed from the filesystem.
 *
 * Special operations provide uniform semantics on every platform:
 *
 * - FO_OP_UNLINK unlinks the file, denying further access to the file
 *   even if it was already opened.
 *
 * - FO_OP_RENAME renames the file, making it transparent for users with
 *   current accesses on the file being renamed.
 *
 * - FO_OP_MOVED notifies that the file was moved around (accross file
 *   systems possibly) and that current users of the old path should be
 *   transparently remapped to the new file with the same access levels,
 *   the old location being unlinked afterwards.
 */
enum file_object_op {
	FO_OP_UNLINK = 0,		/**< Unlink file, further access denied */
	FO_OP_RENAME,			/**< Rename file (on same filesystem) */
	FO_OP_MOVED				/**< Moving notification */
};

/**
 * Convert special operation to string.
 */
static const char *
file_object_op_to_string(enum file_object_op op)
{
	switch (op) {
	case FO_OP_UNLINK:	return "unlink()";
	case FO_OP_RENAME:	return "rename()";
	case FO_OP_MOVED:	return "unlink()";	/* "unlink()" is NOT a typo */
	}

	g_assert_not_reached();
	return NULL;
}

/**
 * Execute special operation.
 *
 * @param old_name	An absolute pathname, the old file name.
 * @param new_name	An absolute pathname, the new file name.
 *
 * @return TRUE if operation was successful, FALSE otherwise, with errno set.
 */
static bool
file_object_special_op(enum file_object_op op,
	const char * const old_name, const char * const new_name)
{
	const int accmodes[] = { O_RDONLY, O_WRONLY, O_RDWR };
	unsigned i;
	GSList *objects = NULL;
	bool ok = TRUE;
	int saved_errno = 0;

	errno = EINVAL;		/* In case one of the soft assertions fails */

	g_return_val_if_fail(old_name, FALSE);
	g_return_val_if_fail(is_absolute_path(old_name), FALSE);
	if (op != FO_OP_UNLINK) {
		g_return_val_if_fail(new_name, FALSE);
		g_return_val_if_fail(is_absolute_path(new_name), FALSE);
	}

	/*
	 * By taking this global lock, we ensure we can safely access all the
	 * file objects stored in any of the tables and manipulate them directly.
	 *
	 * This is a recursive lock, because we'll call file_object_find() which
	 * also needs to take the same lock to access the tables.
	 */

	FILE_OBJECTS_LOCK;

	/*
	 * Identify all the file objects currently active for the old name.
	 */

	for (i = 0; i < G_N_ELEMENTS(accmodes); i++) {
		struct file_object *fo;

		fo = file_object_find(old_name, accmodes[i]);
		if (fo != NULL) {
			if (NULL == g_slist_find(objects, fo)) {
				objects = g_slist_prepend(objects, fo);
			}
		}
	}

	/*
	 * On Windows, close all the files prior renaming / unlinking.
	 *
	 * On UNIX, only close all the files on unlink and moving.  There is
	 * no need to do anything for a rename() operation.
	 */

	if (op != FO_OP_RENAME || is_running_on_mingw()) {
		GSList *sl;

		GM_SLIST_FOREACH(objects, sl) {
			struct file_object *fo = sl->data;

			fd_forget_and_close(&fo->fd);
		}
	}

	/*
	 * Perform the rename() operation now since we can't update the file
	 * names if that operation fails.
	 *
	 * We can defer the unlink() operation after we have updated the file
	 * names for two reasons:
	 *
	 * - if we can't unlink the file, we can still revoke the file objects
	 *   as if we did unlink it...  and if the unlink is the result of a
	 *   successful "move" operation, we want the application to open the
	 *   new file anyway.
	 *
	 * - an unlink() operation for large files can take a long time on some
	 *   filesystems and we are still holding the lock, preventing concurrent
	 *   file opening to take place in other threads.
	 */

	if (FO_OP_RENAME == op && -1 == rename(old_name, new_name)) {
		saved_errno = errno;
		ok = FALSE;
		goto reopen;
	}

	ok = TRUE;

	if (op != FO_OP_UNLINK) {
		GSList *sl;

		/*
		 * Re-index the file objects with their new name.
		 *
		 * Because we hold the global lock, we can safely update the pathname
		 * of the file object: nobody can access that value from the outside
		 * without first taking the lock.
		 */

		GM_SLIST_FOREACH(objects, sl) {
			struct file_object *fo = sl->data;

			hikset_remove(file_object_mode_get_table(fo->accmode),
				fo->pathname);
			atom_str_change(&fo->pathname, new_name);
			hikset_insert(file_object_mode_get_table(fo->accmode), fo);
		}
	} else {
		GSList *sl;

		/*
		 * Revoke the file objects on unlinking.
		 *
		 * This will prevent further file_object_open() pointing to the (now
		 * removed) path from returning an existing file object.
		 * It will also invalidate all current file objects: further read/write
		 * attempts on these will return EBADF.
		 */

		GM_SLIST_FOREACH(objects, sl) {
			struct file_object *fo = sl->data;

			file_object_revoke(fo);
		}

		goto done;		/* No re-opening required with unlink */
	}

	/* FALL THROUGH */

reopen:

	/*
	 * On Windows, reopen all the files.
	 *
	 * On UNIX, reopen the files after a move operation.  There is nothing
	 * to be done on a rename() since we did not close the files before the
	 * operation and the kernel will do the right thing.
	 */

	if (FO_OP_MOVED == op || is_running_on_mingw()) {
		GSList *sl;

		GM_SLIST_FOREACH(objects, sl) {
			struct file_object *fo = sl->data;

			fo->fd = file_absolute_open(fo->pathname, fo->accmode, 0);

			if (!is_valid_fd(fo->fd)) {
				g_warning("cannot reopen \"%s\" mode 0%o "
					"after %s %s of \"%s\": %m",
					fo->pathname, fo->accmode,
					ok ? "successful" : "failed", file_object_op_to_string(op),
					old_name);
			}
		}
	}

	/* FALL THROUGH */

done:
	FILE_OBJECTS_UNLOCK;

	gm_slist_free_null(&objects);

	if (!ok)
		errno = saved_errno;

	/*
	 * Now that we released the lock we can perform the unlink() if needed.
	 * If we can't unlink the file we report a success for a move notification
	 * and we warn.  For a plain unlink(), we do not log anything but return
	 * a failure status.
	 */

	switch (op) {
	case FO_OP_UNLINK:
		ok = unlink(old_name) != -1;
		break;
	case FO_OP_MOVED:
		if (-1 == unlink(old_name)) {
			g_warning("%s(): cannot unlink \"%s\" after a copy to \"%s\": %m",
				G_STRFUNC, old_name, new_name);
		}
		ok = TRUE;
		break;
	case FO_OP_RENAME:
		break;				/* Already handled above */
	}

	return ok;
}

/**
 * Renames a file and transparently re-opens all the file objets pointing to
 * the old name, re-inserting the file objects with the new names, assuming
 * renaming was successful.
 *
 * @param old_name	An absolute pathname, the old file name.
 * @param new_name	An absolute pathname, the new file name.
 *
 * @return TRUE if renaming was successful, FALSE otherwise, with errno set.
 */
bool
file_object_rename(const char * const old_name, const char * const new_name)
{
	return file_object_special_op(FO_OP_RENAME, old_name, new_name);
}

/**
 * Notification that a file was successfully copied.  Access by file objects
 * to the old path are transferred to the new one and the old file is unlinked.
 *
 * @param old_name	An absolute pathname, the old file name.
 * @param new_name	An absolute pathname, the new file name.
 */
void
file_object_moved(const char * const old_name, const char * const new_name)
{
	file_object_special_op(FO_OP_MOVED, old_name, new_name);
}

/**
 * Deletes a file.
 *
 * @param path		An absolute pathname, the file to unkink()
 *
 * @return TRUE if unlinking was successful, FALSE otherwise, with errno set.
 */
bool
file_object_unlink(const char * const path)
{
	return file_object_special_op(FO_OP_UNLINK, path, NULL);
}

static ssize_t
file_object_ebadf(void)
{
	errno = EBADF;
	return (ssize_t) -1;
}

/**
 * Write the given data to a file object at the given offset.
 *
 * @param fo An initialized file object.
 * @param data An initialized buffer holding the data to write.
 * @param size The amount of bytes to write (i.e., the size of data).
 * @param offset The file offset at which to start writing the data.
 *
 * @return On failure -1 is returned and errno is set. On success the
 *		   amount of bytes written is returned.
 */
ssize_t
file_object_pwrite(const struct file_object * const fo,
	const void * const data, const size_t size, const filesize_t offset)
{
	file_object_check(fo);

	if (!is_valid_fd(fo->fd))
		return file_object_ebadf();

	return compat_pwrite(fo->fd, data, size, offset);
}

/**
 * Write the given data to a file object at the given offset.
 *
 * @param fo An initialized file object.
 * @param iov An initialized I/O vector buffer.
 * @param iov_cnt The number of initialized buffer in iov (i.e., its size).
 * @param offset The file offset at which to start writing the data.
 *
 * @return On failure -1 is returned and errno is set. On success the amount
 *         of data bytes written is returned.
 */
ssize_t
file_object_pwritev(const struct file_object * const fo,
	const iovec_t * iov, const int iov_cnt, const filesize_t offset)
{
	file_object_check(fo);
	g_assert(iov);
	g_assert(iov_cnt > 0);
	
	if (!is_valid_fd(fo->fd))
		return file_object_ebadf();

	return compat_pwritev(fo->fd, iov, iov_cnt, offset);
}

/**
 * Read data from the file object from the given offset.
 *
 * @param fo An initialized file object.
 * @param data A buffer for holding the data to be read.
 * @param size The amount of bytes to read (i.e., the size of data).
 * @param offset The file offset from which to start reading data.
 *
 * @return On failure -1 is returned and errno is set. On success the
 *		   amount of bytes read is returned.
 */
ssize_t
file_object_pread(const struct file_object * const fo,
	void * const data, const size_t size, const filesize_t offset)
{
	file_object_check(fo);

	if (!is_valid_fd(fo->fd))
		return file_object_ebadf();

	return compat_pread(fo->fd, data, size, offset);
}

/**
 * Read data from a file object from the given offset.
 *
 * @param fo An initialized file object.
 * @param iov An initialized I/O vector buffer.
 * @param iov_cnt The number of initialized buffer in iov (i.e., its size).
 * @param offset The file offset at which to start reading data.
 *
 * @return On failure -1 is returned and errno is set. On success the amount
 *         of data bytes read is returned.
 */
ssize_t
file_object_preadv(const struct file_object * const fo,
	iovec_t * const iov, const int iov_cnt, const filesize_t offset)
{
	file_object_check(fo);
	g_assert(iov);
	g_assert(iov_cnt > 0);

	if (!is_valid_fd(fo->fd))
		return file_object_ebadf();

	return compat_preadv(fo->fd, iov, MIN(iov_cnt, MAX_IOV_COUNT), offset);
}

/**
 * Get opened file status.
 *
 * @return 0 if OK, -1 on failure with errno set.
 */
int
file_object_fstat(const struct file_object * const fo, filestat_t *buf)
{
	file_object_check(fo);
	g_assert(is_valid_fd(fo->fd));

	return fstat(fo->fd, buf);
}

/**
 * Get the file descriptor associated with a file object. This should
 * not be used lightly and the returned file descriptor should not be
 * cached. Future versions might open/close the file descriptor on
 * demand or dynamically.
 *
 * @param An initialized file object.
 * @return The file descriptor of the file object.
 */
int
file_object_get_fd(const struct file_object * const fo)
{
	file_object_check(fo);
	return fo->fd;
}

/**
 * Get the pathname associated with a file object.
 *
 * @param An initialized file object.
 *
 * @return The pathname of the file object, held in a thread-private buffer.
 */
const char *
file_object_get_pathname(const struct file_object * const fo)
{
	str_t *s = str_private(G_STRFUNC, 256);
	const char *pathname;

	file_object_check(fo);

	/*
	 * Is is necessary to take the lock to access the value because it can
	 * be changed from file_object_special_op().
	 *
	 * There is a possible race because the pathname atom could be freed from
	 * within file_object_special_op() if the file is concurrently renamed
	 * or moved whilst this routine is called.  The lock only guarantees that
	 * we'll read a consistent value, but does not protect from concurrent
	 * freeing that could happen once the lock was released.
	 *
	 * Unfortunately, fixing this transparently for the caller is non-trivial.
	 *		--RAM, 2013-03-16
	 *
	 * To fix the race, we make a copy of the read pathname into a private
	 * buffer.  The caller must make sure to duplicate the returned value
	 * if it wants to peruse it.
	 *		--RAM, 2013-11-09
	 */

	FILE_OBJECTS_LOCK;
	pathname = fo->pathname;
	str_cpy(s, pathname);
	FILE_OBJECTS_UNLOCK;

	return str_2c(s);
}

/**
 * Initialize module, once.
 */
static void
file_object_init_once(void)
{
	size_t offset = offsetof(struct file_object, pathname);

	g_return_if_fail(!ht_file_objects_rdonly);
	g_return_if_fail(!ht_file_objects_wronly);
	g_return_if_fail(!ht_file_objects_rdwr);

	/*
	 * Each of these sets is indexed by the "pathname" field of the file object,
	 * as indicated by the "offset" variable (Hashed Internal Key SET).
	 */

	ht_file_objects_rdonly = hikset_create(offset, HASH_KEY_STRING, 0);
	ht_file_objects_wronly = hikset_create(offset, HASH_KEY_STRING, 0);
	ht_file_objects_rdwr   = hikset_create(offset, HASH_KEY_STRING, 0);
}

/**
 * Initializes this module and must be called before using any other function
 * of this module. 
 */
void
file_object_init(void)
{
	static once_flag_t inited;

	ONCE_FLAG_RUN(inited, file_object_init_once);
}

static void
file_object_show_item(void *value, void *unused_udata)
{
	const struct file_object * const fo = value;

	(void) unused_udata;

	file_object_check(fo);

	g_warning("leaked file object: ref.count=%d fd=%d pathname=\"%s\"",
		fo->ref_count, fo->fd, fo->pathname);
}

static inline void
file_object_destroy_table(hikset_t **ht_ptr, const char * const name)
{
	hikset_t *ht;
	uint n;

	g_assert(ht_ptr);
	ht = *ht_ptr;
	g_return_if_fail(ht);

	n = hikset_count(ht);
	if (n > 0) {
		g_warning("%s(): %s still contains %u items", G_STRFUNC, name, n);
		hikset_foreach(ht, file_object_show_item, NULL);
	}
	g_return_if_fail(0 == n);
	hikset_free_null(ht_ptr);
	*ht_ptr = NULL;
}

/**
 * Releases all used resources and should be called on shutdown.
 * @note Still existing file objects are not destroyed.
 */
void
file_object_close(void)
{
#define D(x) &x, #x

	file_object_destroy_table(D(ht_file_objects_rdonly));
	file_object_destroy_table(D(ht_file_objects_wronly));
	file_object_destroy_table(D(ht_file_objects_rdwr));

#undef D
}

/* vi: set ts=4 sw=4 cindent: */
