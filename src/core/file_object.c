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
 * Sharing of file descriptors through file objects.
 *
 * @author Christian Biere
 * @date 2006
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
 * functions do not restore the original file offset and they are NOT
 * thread-safe. As gtk-gnutella is mono-threaded this should never be a
 * problem.
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
 *  }
 *  if (!file) {
 *     // Error handling
 *  }
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

RCSID("$Id$")

#include "file_object.h"

#include "lib/atoms.h"
#include "lib/file.h"
#include "lib/iovec.h"
#include "lib/misc.h"
#include "lib/walloc.h"

#include "lib/override.h"       /* Must be the last header included */

static GHashTable *ht_file_objects_rdonly;	/* read-only file objects */
static GHashTable *ht_file_objects_wronly;	/* write-only file objects */
static GHashTable *ht_file_objects_rdwr;	/* read+write-able file objects */

enum file_object_magic { FILE_OBJECT_MAGIC = 0xeb084325 };	/**< Magic number */

struct file_object {
	const char *pathname;	/* atom */
	int ref_count;
	int fd;
	int accmode;	/* O_RDONLY, O_WRONLY, O_RDWR */
	enum file_object_magic magic;
};

/**
 * @todo
 * TODO: fd_is_*() and accmode_is_valid() are generic functions which should
 * 		 be moved elsewhere.
 */

/**
 * Checks whether the given file descriptor is opened for write operations.
 *
 * @param fd A valid file descriptor.
 * @return TRUE if the file descriptor is opened with O_WRONLY or O_RDWR.
 */
static inline gboolean
fd_is_writable(const int fd)
{
	int flags;

	g_return_val_if_fail(fd >= 0, FALSE);

	flags = fcntl(fd, F_GETFL);
	g_return_val_if_fail(-1 != flags, FALSE);

	flags &= O_ACCMODE;
	return O_WRONLY == flags || O_RDWR == flags;
}

/**
 * Checks whether the given file descriptor is opened for read operations.
 *
 * @param fd A valid file descriptor.
 * @return TRUE if the file descriptor is opened with O_RDONLY or O_RDWR.
 */
static inline gboolean
fd_is_readable(const int fd)
{
	int flags;

	g_return_val_if_fail(fd >= 0, FALSE);

	flags = fcntl(fd, F_GETFL);
	g_return_val_if_fail(-1 != flags, FALSE);

	flags &= O_ACCMODE;
	return O_RDONLY == flags || O_RDWR == flags;
}

/**
 * Checks whether the given file descriptor is opened for read and write
 * operations.
 *
 * @param fd A valid file descriptor.
 * @return TRUE if the file descriptor is opened with O_RDWR.
 */
static inline gboolean
fd_is_readable_and_writable(const int fd)
{
	int flags;

	g_return_val_if_fail(fd >= 0, FALSE);

	flags = fcntl(fd, F_GETFL);
	g_return_val_if_fail(-1 != flags, FALSE);

	flags &= O_ACCMODE;
	return O_RDWR == flags;
}

/**
 * Checks whether the given file descriptor is compatible with given
 * access mode. For example, if fd has access mode O_RDONLY but
 * accmode is O_WRONLY or O_RDWR FALSE is returned, because the
 * file descriptor is not writable.
 *
 * @param fd A valid file descriptor.
 * @return TRUE if the file descriptor is compatible with the access mode.
 */
static inline gboolean
accmode_is_valid(const int fd, const int accmode)
{
	g_return_val_if_fail(fd >= 0, FALSE);

	switch (accmode) {
	case O_RDONLY: return fd_is_readable(fd);
	case O_WRONLY: return fd_is_writable(fd);
	case O_RDWR:   return fd_is_readable_and_writable(fd);
	}
	return FALSE;
}

/**
 * Applies some basic and fast consistency checks to a file object and
 * causes an assertion failure if a check fails.
 */
static inline void
file_object_check(const struct file_object * const fo)
{
	g_assert(fo);
	g_assert(FILE_OBJECT_MAGIC == fo->magic);
	g_assert(fo->ref_count > 0);
	g_assert(fo->ref_count < INT_MAX);
	g_assert(fo->fd >= 0);
	g_assert(fo->pathname);
}

/**
 * Get the hash table for a given access mode.
 *
 * @return The hash table holding file object for the access mode.
 */
static inline GHashTable *
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
	
	g_return_val_if_fail(ht_file_objects_rdonly, NULL);
	g_return_val_if_fail(ht_file_objects_wronly, NULL);
	g_return_val_if_fail(ht_file_objects_rdwr, NULL);
	g_return_val_if_fail(pathname, NULL);
	g_return_val_if_fail(is_absolute_path(pathname), NULL);

	fo = g_hash_table_lookup(file_object_mode_get_table(O_RDWR), pathname);
	if (!fo && O_RDWR != accmode) {
		fo = g_hash_table_lookup(file_object_mode_get_table(accmode), pathname);
	}

	if (fo) {
		file_object_check(fo);
		g_assert(0 == strcmp(pathname, fo->pathname));
		g_assert(accmode_is_valid(fo->fd, accmode));
	}

	return fo;
}

static struct file_object *
file_object_alloc(const int fd, const char * const pathname, int accmode)
{
	static const struct file_object zero_fo;
	struct file_object *fo;
	GHashTable *ht;

	g_return_val_if_fail(fd >= 0, NULL);
	g_return_val_if_fail(pathname, NULL);
	g_return_val_if_fail(is_absolute_path(pathname), NULL);
	g_return_val_if_fail(!file_object_find(pathname, accmode), NULL);

	ht = file_object_mode_get_table(accmode);
	g_return_val_if_fail(ht, NULL);

	fo = walloc(sizeof *fo);
	*fo = zero_fo;
	fo->magic = FILE_OBJECT_MAGIC;
	fo->ref_count = 1;
	fo->fd = fd;
	fo->accmode = accmode;
	fo->pathname = atom_str_get(pathname);

	file_object_check(fo);
	g_hash_table_insert(file_object_mode_get_table(fo->accmode),
		deconstify_gchar(fo->pathname), fo);

	return fo;
}

static void
file_object_free(struct file_object * const fo)
{
	g_return_if_fail(fo);
	g_return_if_fail(1 == fo->ref_count);
	g_return_if_fail(fo->fd >= 0);
	g_return_if_fail(file_object_find(fo->pathname, fo->accmode));

	file_object_check(fo);
	g_hash_table_remove(file_object_mode_get_table(fo->accmode), fo->pathname);
	g_assert(!g_hash_table_lookup(file_object_mode_get_table(fo->accmode),
				fo->pathname));

	close(fo->fd);
	fo->fd = -1;
	atom_str_free_null(&fo->pathname);
	fo->magic = 0;
	wfree(fo, sizeof *fo);
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

	fo = file_object_find(pathname, accmode);
	if (fo) {
		fo->ref_count++;
	}
	return fo;
}

/**
 * Acquires a new file object for a given pathname. There must not be any
 * file object registered for this pathname already.
 *
 * @param pathname An absolute pathname.
 * @return	On failure NULL is returned. On success a file object is
 *			returned.
 */
struct file_object *
file_object_new(const int fd, const char * const pathname, int accmode)
{
	g_return_val_if_fail(fd >= 0, NULL);
	g_return_val_if_fail(accmode_is_valid(fd, accmode), NULL);
	g_return_val_if_fail(pathname, NULL);
	g_return_val_if_fail(is_absolute_path(pathname), NULL);
	g_return_val_if_fail(!file_object_find(pathname, accmode), NULL);

	return file_object_alloc(fd, pathname, accmode);
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

		file_object_check(fo);

		if (1 == fo->ref_count) {
			file_object_free(fo);
		} else {
			fo->ref_count--;
		}

		*fo_ptr = NULL;
	}
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
	const void * const data, const size_t size, const filesize_t pos)
#ifdef HAS_PWRITE
{
	off_t offset;

	file_object_check(fo);
	offset = filesize_to_off_t(pos);
	if ((off_t) -1 == offset) {
		errno = EINVAL;
		return -1;
	} else {
		return pwrite(fo->fd, data, size, offset);
	}
}
#else	/* !HAS_PWRITE */
{
	struct iovec iov;

	file_object_check(fo);
	iov = iov_get(deconstify_gpointer(data), size);
	return file_object_pwritev(fo, &iov, 1, pos);
}
#endif	/* HAS_PWRITE */


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
	const struct iovec * const iov, const int iov_cnt, const filesize_t pos)
#ifdef HAS_PWRITEV
{
	off_t offset;

	file_object_check(fo);
	g_assert(iov);
	g_assert(iov_cnt > 0);

	offset = filesize_to_off_t(pos);
	if ((off_t) -1 == offset) {
		errno = EINVAL;
		return -1;
	} else {
		return pwritev(fo->fd, iov, MIN(iov_cnt, MAX_IOV_COUNT), offset);
	}
}
#else	/* !HAS_PWRITEV */
{
	ssize_t ret;

	file_object_check(fo);
	g_assert(iov);
	g_assert(iov_cnt > 0);

#ifdef HAS_PWRITE
	if (1 == iov_cnt) {
		return file_object_pwrite(fo, iov->iov_base, iov->iov_len, pos);
	}
#endif /* HAS_PWRITE */
	
	if (0 != seek_to_filepos(fo->fd, pos)) {
		int saved_errno = errno;

		g_warning("failed to seek at offset %s (%s) for \"%s\" ",
			uint64_to_string(pos), g_strerror(errno), fo->pathname);

		errno = saved_errno;
		ret = -1;
	} else {
		ret = writev(fo->fd, iov, MIN(iov_cnt, MAX_IOV_COUNT));
	}
	return ret;
}
#endif	/* HAS_PWRITEV */

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
	void * const data, const size_t size, const filesize_t pos)
#ifdef HAS_PREAD
{
	off_t offset;

	file_object_check(fo);
	offset = filesize_to_off_t(pos);
	if ((off_t) -1 == offset) {
		errno = EINVAL;
		return -1;
	} else {
		return pread(fo->fd, data, size, offset);
	}
}
#else	/* !HAS_PREAD */
{
	struct iovec iov;

	file_object_check(fo);
	iov = iov_get(data, size);
	return file_object_preadv(fo, &iov, 1, pos);
}
#endif	/* HAS_PREAD */


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
	struct iovec * const iov, const int iov_cnt, const filesize_t pos)
#ifdef HAS_PREADV
{
	off_t offset;

	file_object_check(fo);
	g_assert(iov);
	g_assert(iov_cnt > 0);

	offset = filesize_to_off_t(pos);
	if ((off_t) -1 == offset) {
		errno = EINVAL;
		return -1;
	} else {
		return preadv(fo->fd, iov, MIN(iov_cnt, MAX_IOV_COUNT), offset);
	}
}
#else	/* !HAS_PREADV */
{
	ssize_t ret;

	file_object_check(fo);
	g_assert(iov);
	g_assert(iov_cnt > 0);

#ifdef HAS_PREAD
	if (1 == iov_cnt) {
		return file_object_pread(fo, iov->iov_base, iov->iov_len, pos);
	}
#endif /* HAS_PREAD */

	if (0 != seek_to_filepos(fo->fd, pos)) {
		int saved_errno = errno;

		g_warning("failed to seek at offset %s (%s) for \"%s\" ",
			uint64_to_string(pos), g_strerror(errno), fo->pathname);

		errno = saved_errno;
		ret = -1;
	} else {
		ret = readv(fo->fd, iov, MIN(iov_cnt, MAX_IOV_COUNT));
	}
	return ret;
}
#endif	/* HAS_PREADV */


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
 * @return The pathname of the file object.  
 */
const char *
file_object_get_pathname(const struct file_object * const fo)
{
	file_object_check(fo);
	return fo->pathname;
}

/**
 * Initializes this module and must be called before using any other function
 * of this module. 
 */
void
file_object_init(void)
{
	g_return_if_fail(!ht_file_objects_rdonly);
	g_return_if_fail(!ht_file_objects_wronly);
	g_return_if_fail(!ht_file_objects_rdwr);

	ht_file_objects_rdonly = g_hash_table_new(g_str_hash, g_str_equal);
	ht_file_objects_wronly = g_hash_table_new(g_str_hash, g_str_equal);
	ht_file_objects_rdwr = g_hash_table_new(g_str_hash, g_str_equal);
}

static void
file_object_show_item(gpointer key, gpointer value, gpointer unused_udata)
{
	const struct file_object * const fo = value;

	g_assert(key);
	g_assert(value);
	(void) unused_udata;

	file_object_check(fo);
	g_assert(fo->pathname == key);

	g_message("leaked file object: ref.count=%d fd=%d pathname=\"%s\"",
		fo->ref_count, fo->fd, fo->pathname);
}

static inline void
file_object_destroy_table(GHashTable **ht_ptr, const char * const name)
{
	GHashTable *ht;
	guint n;

	g_assert(ht_ptr);
	ht = *ht_ptr;
	g_return_if_fail(ht);

	n = g_hash_table_size(ht);
	if (n > 0) {
		g_warning("file_object_destroy_table(): %s still contains %u items",
			name, n);
		g_hash_table_foreach(ht, file_object_show_item, NULL);
	}
	g_return_if_fail(0 == n);
	g_hash_table_destroy(ht);
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
