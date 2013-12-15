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
 * Normally, file objects should be acquired as follows:
 *
 *	// Open file, do not create it if missing
 *	file = file_object_open(pathname, mode);
 *  if (NULL == file) {
 *     // Error handling
 *  }
 *
 *  // Open file, creating it if missing
 *  file = file_object_create(pathname, mode, permissions);
 *  if (NULL == file) {
 *     // Error handling
 *  }
 *
 * Internally, all files are opened O_RDWR to be able to share the file
 * descriptors, but the API checks the access mode and will loudly complain
 * if the user is trying to read from a write-only file for instance, since
 * that indicates a programming error.
 */

#include "common.h"

#include "file_object.h"

#include "atomic.h"
#include "atoms.h"
#include "compat_misc.h"
#include "compat_pio.h"
#include "fd.h"
#include "file.h"
#include "hikset.h"
#include "hset.h"
#include "iovec.h"
#include "mutex.h"
#include "once.h"
#include "path.h"
#include "pslist.h"
#include "str.h"			/* For str_private() */
#include "walloc.h"

#include "override.h"       /* Must be the last header included */

/**
 * Table contains all the file descriptors, indexed by absolute pathname
 *
 */
static hikset_t *file_descriptors;
static mutex_t file_descriptors_mtx = MUTEX_INIT;

#define FILE_OBJECTS_LOCK	mutex_lock(&file_descriptors_mtx)
#define FILE_OBJECTS_UNLOCK	mutex_unlock(&file_descriptors_mtx)

#define assert_file_objects_locked() \
	assert_mutex_is_owned(&file_descriptors_mtx)

/*
 * Set containing all the opened files, to be able to warn at close time if
 * the application forgot to close some (file descriptor leak).
 */
static hset_t *file_objects;

enum file_object_magic { FILE_OBJECT_MAGIC = 0x6b084325 };

/**
 * Structure returned to users which describe the file being opened, the
 * mode of access, and which references the internal file descriptor.
 */
struct file_object {
	enum file_object_magic magic;
	struct file_descriptor *fd;	/* Internal file descriptor */
	const char *file;			/* Place where file was opened */
	int accmode;				/* O_RDONLY, O_WRONLY, O_RDWR */
	int line;					/* Line number where file was opened */
};

static inline void
file_object_check_minimal(const file_object_t * const fo)
{
	g_assert(fo != NULL);
	g_assert(FILE_OBJECT_MAGIC == fo->magic);
}

enum file_descriptor_magic { FILE_DESCRIPTOR_MAGIC   = 0x69ba3bc8 };

/**
 * Internal attributes for a file descriptor.
 */
struct file_descriptor {
	enum file_descriptor_magic magic;
	const char *pathname;		/* Atom, internal indexing key */
	int refcnt;					/* Reference count */
	int fd;						/* The file descriptor, opened O_RDWR */
	bool revoked;				/* Whether descriptor was revoked */
};

static inline void
file_descriptor_check_minimal(const struct file_descriptor * const fd)
{
	g_assert(fd != NULL);
	g_assert(FILE_DESCRIPTOR_MAGIC == fd->magic);
}

static inline void
file_descriptor_check(const struct file_descriptor * const fd)
{
	file_descriptor_check_minimal(fd);
	g_assert(fd->pathname != NULL);
	g_assert(fd->refcnt > 0);
	g_assert(fd->refcnt < INT_MAX);
}

static inline void
file_object_check(const file_object_t * const fo)
{
	file_object_check_minimal(fo);
	file_descriptor_check_minimal(fo->fd);
}

/**
 * @return English description of file opening mode.
 */
static const char *
file_object_mode_to_string(const file_object_t * const fo)
{
	switch (fo->accmode) {
	case O_RDONLY:	return "read-only";
	case O_WRONLY:	return "write-only";
	case O_RDWR:	return "read-write";
	}

	return str_smsg("mode 0%o", fo->accmode);
}

/**
 * Lookup file decriptor in the table.
 *
 * @param pathname		path to file for which we want a file descriptor
 *
 * @return found file descriptor, NULL if not found
 */
static inline struct file_descriptor *
file_object_lookup(const char * const pathname)
{
	assert_file_objects_locked();
	return hikset_lookup(file_descriptors, pathname);
}

/**
 * Insert file descriptor in the table.
 *
 * @param fd		the file descriptor to insert
 */
static inline void
file_object_insert(const struct file_descriptor *fd)
{
	assert_file_objects_locked();
	hikset_insert(file_descriptors, fd);
}

/**
 * Remove file object from the table.
 *
 * @param fd		the file descriptor to insert
 */
static inline void
file_object_remove(const struct file_descriptor *fd)
{
	assert_file_objects_locked();
	hikset_remove(file_descriptors, fd->pathname);
}

/**
 * Find an existing file descriptor associated with the given pathname.
 *
 * @return the file descriptor if found, NULL otherwise.
 */
static struct file_descriptor *
file_object_find(const char * const pathname)
{
	struct file_descriptor *fd;

	assert_file_objects_locked();

	g_return_val_if_fail(pathname != NULL, NULL);
	g_return_val_if_fail(is_absolute_path(pathname), NULL);

	fd = file_object_lookup(pathname);

	if (fd != NULL) {
		file_descriptor_check_minimal(fd);
		g_assert(is_valid_fd(fd->fd));
		g_assert(fd_accmode_is_valid(fd->fd, O_RDWR));
		g_assert(!fd->revoked);
	}

	return fd;
}

/**
 * Free file descriptor.
 */
static void
file_object_free_descriptor(struct file_descriptor * const fd)
{
	file_descriptor_check_minimal(fd);
	g_assert(0 == fd->refcnt);

	fd_close(&fd->fd);
	atom_str_free_null(&fd->pathname);
	fd->magic = 0;
	WFREE(fd);
}

/**
 * Allocate a new file descriptor and register it in the table.
 *
 * When there is already an entry for the path in the table (race condition)
 * the old entry is returned and the kernel descriptor is closed.
 *
 * @param d				kernel descriptor for opened file
 * @param pathname		absolute pathname
 */
static struct file_descriptor *
file_object_new_descriptor(const int d, const char * const pathname)
{
	struct file_descriptor *fd, *fdn;

	g_return_val_if_fail(d >= 0, NULL);
	g_return_val_if_fail(is_absolute_path(pathname), NULL);

	/*
	 * Assume there will be no race condition and create the new descriptor
	 * prior to taking the global lock.
	 */

	WALLOC0(fdn);
	fdn->magic = FILE_DESCRIPTOR_MAGIC;
	fdn->pathname = atom_str_get(pathname);
	fdn->fd = d;

	FILE_OBJECTS_LOCK;
	fd = file_object_find(pathname);

	if G_UNLIKELY(fd != NULL) {
		/*
		 * Race condition detected, we're returning the existing fd.
		 */

		atomic_int_inc(&fd->refcnt);
		FILE_OBJECTS_UNLOCK;

		/*
		 * Free the object we had created, which will close ``d''.
		 */

		g_assert(fd->fd != d);

		file_object_free_descriptor(fdn);
		return fd;
	}

	/*
	 * Nominal case, we're using the new object
	 */

	fdn->refcnt = 1;
	file_object_insert(fdn);
	FILE_OBJECTS_UNLOCK;

	return fdn;
}

/**
 * Allocate a new file object referencing a file descriptor (which has
 * already been ref-counted).
 *
 * @param fd		the file descriptor
 * @param accmode	user access mode on the file
 * @param file		location where file was opened
 * @param line		line number where file was opened
 */
static file_object_t *
file_object_alloc(struct file_descriptor *fd, int accmode,
	const char *file, int line)
{
	file_object_t *fo;

	WALLOC0(fo);
	fo->magic = FILE_OBJECT_MAGIC;
	fo->fd = fd;
	fo->accmode = accmode;
	fo->file = file;
	fo->line = line;

	/*
	 * Track all the files being opened so that we can warn them at exit
	 * time if there are some files which were opened and never closed,
	 * a source for file descriptor leaking!
	 */

	hset_insert(file_objects, fo);

	file_object_check(fo);

	return fo;
}

/**
 * Revoke a file descriptor.
 */
static void
file_object_revoke(struct file_descriptor * const fd)
{
	file_descriptor_check_minimal(fd);

	assert_file_objects_locked();
	g_return_if_fail(!fd->revoked);

	file_object_remove(fd);
	fd->revoked = TRUE;
	atomic_mb();			/* Since update was made without locking */
}

/**
 * Free file object.
 */
static void
file_object_free(file_object_t *fo)
{
	struct file_descriptor *fd;

	file_object_check(fo);

	fd = fo->fd;

	/*
	 * If d->refcnt is not zero, we don't need to take the global lock.
	 * Otherwise, we need to take the lock and recheck, since file descriptor
	 * could have been concurrently re-used.
	 */

	if (atomic_int_dec_is_zero(&fd->refcnt)) {
		bool need_free = FALSE;
		FILE_OBJECTS_LOCK;
		if (0 == atomic_int_get(&fd->refcnt)) {
			file_object_remove(fd);
			need_free = TRUE;
		}
		FILE_OBJECTS_UNLOCK;
		if (need_free)
			file_object_free_descriptor(fd);
	}

	hset_remove(file_objects, fo);

	fo->magic = 0;
	WFREE(fo);
}

/**
 * Acquires a file object for a given pathname and access mode.
 * When no matching file object exists and the file cannot be opened, NULL
 * is returned.
 *
 * @param pathname	absolute pathname
 * @param accmode	the access mode they want for this file
 * @param file		file location where file is opened
 * @param line		line number whenre file is opened
 *
 * @return file object if opened, NULL on error.
 */
file_object_t *
file_object_open_from(const char * const pathname, int accmode,
	const char *file, int line)
{
	struct file_descriptor *fd;

	g_assert(pathname != NULL);
	g_return_val_if_fail(is_absolute_path(pathname), NULL);

	file_object_init();

	FILE_OBJECTS_LOCK;
	fd = file_object_find(pathname);
	FILE_OBJECTS_UNLOCK;

	if (fd != NULL) {
		atomic_int_inc(&fd->refcnt);
	} else {
		int d;

		/*
		 * No known file descriptor for this path. Open the file then and
		 * if we can, wrap the file descriptor and record it.
		 *
		 * NOTE: we do not have the lock during file opening.
		 * We have to recheck for the file descriptor presence in
		 * file_object_new_descriptor().
		 */

		if (O_RDONLY == accmode) {
			 d = file_absolute_open(pathname, O_RDWR, 0);
		} else {
			 d = file_open_missing(pathname, O_RDWR);
		}

		if G_LIKELY(d >= 0) {
			fd = file_object_new_descriptor(d, pathname);
		}
	}

	g_assert(NULL == fd || is_valid_fd(fd->fd));

	if G_UNLIKELY(NULL == fd)
		return NULL;

	return file_object_alloc(fd, accmode, file, line);
}

/**
 * Acquires a file object for a given pathname (created if missing) and
 * access mode.  When no matching file object exists and the file cannot
 * be created, NULL is returned.
 *
 * @param pathname	absolute pathname to file
 * @param accmode	access mode for the file (O_RDONLY, O_WRONLY, O_RDWR)
 * @param mode		permission mode, if creating
 * @param file		file location where file is opened
 * @param line		line number whenre file is opened
 * 
 * @return a file object enabling I/O operations on success, NULL on error.
 */
file_object_t *
file_object_create_from(const char * const pathname, int accmode, mode_t mode,
	const char *file, int line)
{
	struct file_descriptor *fd;

	file_object_init();

	g_assert(pathname != NULL);
	g_return_val_if_fail(is_absolute_path(pathname), NULL);

	FILE_OBJECTS_LOCK;
	fd = file_object_find(pathname);
	FILE_OBJECTS_UNLOCK;

	if (fd != NULL) {
		atomic_int_inc(&fd->refcnt);
	} else {
		int d;

		/*
		 * No known file descriptor for this path. Open the file then and
		 * if we can, wrap the file descriptor and record it.
		 *
		 * NOTE: we do not have the lock during file opening.
		 * We have to recheck for the file descriptor presence in
		 * file_object_new_descriptor().
		 */

		 d = file_create(pathname, O_RDWR, mode);

		if G_LIKELY(d >= 0) {
			fd = file_object_new_descriptor(d, pathname);
		}
	}

	g_assert(NULL == fd || is_valid_fd(fd->fd));

	if G_UNLIKELY(NULL == fd)
		return NULL;

	return file_object_alloc(fd, accmode, file, line);
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
file_object_release(file_object_t **fo_ptr)
{
	g_assert(fo_ptr != NULL);

	if (*fo_ptr) {
		file_object_t *fo = *fo_ptr;

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
	struct file_descriptor *fd;
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
	fd = file_object_find(old_name);

	/*
	 * On Windows, close all the files prior renaming / unlinking.
	 *
	 * On UNIX, only close all the files on unlink and moving.  There is
	 * no need to do anything for a rename() operation.
	 */

	if (fd != NULL && (op != FO_OP_RENAME || is_running_on_mingw())) {
		fd_forget_and_close(&fd->fd);
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
		if (NULL == fd)
			goto done;
		goto reopen;
	}

	ok = TRUE;

	if (NULL == fd)
		goto done;

	if (op != FO_OP_UNLINK) {
		/*
		 * Re-index the file descriptor with its new name.
		 *
		 * Because we hold the global lock, we can safely update the pathname
		 * of the file descriptor: nobody can access that value from the outside
		 * without first taking the lock.
		 */

		hikset_remove(file_descriptors, fd->pathname);
		atom_str_change(&fd->pathname, new_name);
		hikset_insert(file_descriptors, fd);
	} else {
		/*
		 * Revoke the file descriptor on unlinking.
		 *
		 * This will prevent further file_object_open() pointing to the (now
		 * removed) path from returning an existing file object.
		 * It will also invalidate all current file objects: further read/write
		 * attempts on these will return EBADF.
		 */

		file_object_revoke(fd);
		goto done;		/* No re-opening required with unlink */
	}

	/* FALL THROUGH */

reopen:

	/*
	 * On Windows, reopen the file.
	 *
	 * On UNIX, reopen the file after a move operation.  There is nothing
	 * to be done on a rename() since we did not close the files before the
	 * operation and the kernel will do the right thing.
	 */

	if (FO_OP_MOVED == op || is_running_on_mingw()) {
		fd->fd = file_absolute_open(fd->pathname, O_RDWR, 0);

		if (!is_valid_fd(fd->fd)) {
			s_warning("%s(): cannot reopen \"%s\" "
				"after %s %s of \"%s\": %m",
				G_STRFUNC, fd->pathname,
				ok ? "successful" : "failed", file_object_op_to_string(op),
				old_name);
		}
	}

	/* FALL THROUGH */

done:
	FILE_OBJECTS_UNLOCK;

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
			s_warning("%s(): cannot unlink \"%s\" after a copy to \"%s\": %m",
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
 * Renames a file and transparently re-opens the file descriptor pointing to
 * the old name, re-inserting the file descriptor with the new names, assuming
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

static ssize_t
file_object_eperm(const file_object_t * const fo, const char *what,
	const char *where)
{
	s_carp("%s(): cannot %s to file opened %s at %s:%d",
		where, what, file_object_mode_to_string(fo), fo->file, fo->line);

	errno = EPERM;
	return (ssize_t) -1;
}

/**
 * Is file object readable?
 */
static inline bool
file_object_readable(const file_object_t * const fo)
{
	return O_RDONLY == fo->accmode || O_RDWR == fo->accmode;
}

/**
 * Is file object writable?
 */
static inline bool
file_object_writable(const file_object_t * const fo)
{
	return O_WRONLY == fo->accmode || O_RDWR == fo->accmode;
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
file_object_pwrite(const file_object_t * const fo,
	const void * const data, const size_t size, const filesize_t offset)
{
	const struct file_descriptor *fd;

	file_object_check(fo);

	fd = fo->fd;

	if G_UNLIKELY(!is_valid_fd(fd->fd))
		return file_object_ebadf();

	if G_UNLIKELY(!file_object_writable(fo))
		return file_object_eperm(fo, "write", G_STRFUNC);

	return compat_pwrite(fd->fd, data, size, offset);
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
file_object_pwritev(const file_object_t * const fo,
	const iovec_t * iov, const int iov_cnt, const filesize_t offset)
{
	const struct file_descriptor *fd;

	file_object_check(fo);
	g_assert(iov != NULL);
	g_assert(iov_cnt > 0);

	fd = fo->fd;

	if G_UNLIKELY(!is_valid_fd(fd->fd))
		return file_object_ebadf();

	if G_UNLIKELY(!file_object_writable(fo))
		return file_object_eperm(fo, "write", G_STRFUNC);

	return compat_pwritev(fd->fd, iov, iov_cnt, offset);
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
file_object_pread(const file_object_t * const fo,
	void * const data, const size_t size, const filesize_t offset)
{
	const struct file_descriptor *fd;

	file_object_check(fo);

	fd = fo->fd;

	if G_UNLIKELY(!is_valid_fd(fd->fd))
		return file_object_ebadf();

	if G_UNLIKELY(!file_object_readable(fo))
		return file_object_eperm(fo, "read", G_STRFUNC);

	return compat_pread(fd->fd, data, size, offset);
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
file_object_preadv(const file_object_t * const fo,
	iovec_t * const iov, const int iov_cnt, const filesize_t offset)
{
	const struct file_descriptor *fd;

	file_object_check(fo);
	g_assert(iov);
	g_assert(iov_cnt > 0);

	fd = fo->fd;

	if G_UNLIKELY(!is_valid_fd(fd->fd))
		return file_object_ebadf();

	if G_UNLIKELY(!file_object_readable(fo))
		return file_object_eperm(fo, "read", G_STRFUNC);

	return compat_preadv(fd->fd, iov, MIN(iov_cnt, MAX_IOV_COUNT), offset);
}

/**
 * @return internal open file descriptor.
 */
static int
file_object_open_fd(const file_object_t * const fo)
{
	const struct file_descriptor *fd;

	file_object_check(fo);
	fd = fo->fd;
	g_assert(is_valid_fd(fd->fd));

	return fd->fd;
}

/**
 * Get opened file status.
 *
 * @return 0 if OK, -1 on failure with errno set.
 */
int
file_object_fstat(const file_object_t * const fo, filestat_t *buf)
{
	int fd = file_object_open_fd(fo);

	return fstat(fd, buf);
}

/**
 * Truncate file.
 *
 * @return 0 if OK, -1 on failure with errno set.
 */
int
file_object_ftruncate(const file_object_t * const fo, filesize_t off)
{
	int fd = file_object_open_fd(fo);

	return ftruncate(fd, off);
}

/**
 * Predeclare a sequential access pattern for file data.
 */
void
file_object_fadvise_sequential(const file_object_t * const fo)
{
	int fd = file_object_open_fd(fo);

	compat_fadvise_sequential(fd, 0, 0);
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
file_object_fd(const file_object_t * const fo)
{
	return file_object_open_fd(fo);
}

/**
 * Get the pathname associated with a file object.
 *
 * @param An initialized file object.
 *
 * @return The pathname of the file object, held in a thread-private buffer.
 */
const char *
file_object_pathname(const file_object_t * const fo)
{
	str_t *s = str_private(G_STRFUNC, 256);
	const char *pathname;
	const struct file_descriptor *fd;

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

	fd = fo->fd;

	FILE_OBJECTS_LOCK;
	pathname = fd->pathname;
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
	size_t offset = offsetof(struct file_descriptor, pathname);

	g_return_if_fail(NULL == file_descriptors);
	g_return_if_fail(NULL == file_objects);

	/*
	 * This set is indexed by the "pathname" field of the file object,
	 * as indicated by the "offset" variable (Hashed Internal Key SET).
	 */

	file_descriptors = hikset_create(offset, HASH_KEY_STRING, 0);

	file_objects = hset_create(HASH_KEY_SELF, 0);
	hset_thread_safe(file_objects);
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
file_object_show_item(const void *value, void *unused_udata)
{
	const file_object_t * const fo = value;

	(void) unused_udata;

	file_object_check(fo);

	s_warning("leaked file object: pathname=\"%s\", opened %s at %s:%d",
		file_object_pathname(fo), file_object_mode_to_string(fo),
		fo->file, fo->line);
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
		s_warning("%s(): %s still contains %u items", G_STRFUNC, name, n);
	} else {
		hikset_free_null(ht_ptr);
		*ht_ptr = NULL;
	}
}

/**
 * Releases all used resources and should be called on shutdown.
 * @note Still existing file objects are not destroyed.
 */
void
file_object_close(void)
{
#define D(x) &x, #x

	file_object_destroy_table(D(file_descriptors));

#undef D

	hset_foreach(file_objects, file_object_show_item, NULL);
	if (0 == hset_count(file_objects))
		hset_free_null(&file_objects);
}

/**
 * Set iterator to get information about specific file object and add
 * it to the returned list of structures.
 */
static void
file_object_info_get(const void *data, void *udata)
{
	const file_object_t *fo = data;
	const struct file_descriptor *fd;
	pslist_t **list = udata;				/* List being built for user */
	pslist_t *sl = *list;					/* Current list head pointer */
	file_object_info_t *foi;

	file_object_check(fo);

	WALLOC0(foi);
	foi->magic = FILE_OBJECT_INFO_MAGIC;

	fd = fo->fd;
	foi->path = atom_str_get(fd->pathname);
	foi->refcnt = fd->refcnt;
	foi->mode = fo->accmode;
	foi->file = fo->file;
	foi->line = fo->line;

	sl = pslist_prepend(sl, foi);
	*list = sl;							/* Update list head pointer */
}

/**
 * Retrieve file_object information.
 *
 * @return list of file_object_info_t that must be freed by calling the
 * file_object_info_list_free_null() routine.
 */
pslist_t *
file_object_info_list(void)
{
	pslist_t *sl = NULL;

	hset_foreach(file_objects, file_object_info_get, &sl);
	return sl;
}

static void
file_object_info_free(void *data, void *udata)
{
	file_object_info_t *foi = data;

	file_object_info_check(foi);
	(void) udata;

	atom_str_free_null(&foi->path);
	foi->magic = 0;
	WFREE(foi);
}

/**
 * Free list returned by file_object_info_list() and nullify pointer.
 */
void
file_object_info_list_free_nulll(pslist_t **sl_ptr)
{
	pslist_t *sl = *sl_ptr;

	pslist_foreach(sl, file_object_info_free, NULL);
	pslist_free_null(sl_ptr);
}

/* vi: set ts=4 sw=4 cindent: */
