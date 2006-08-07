/*
 * $Id$
 *
 * Copyright (c) 2004, Christian Biere
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
 * File object sharing by pathname for reduced file descriptor wastage. 
 *
 * @author Christian Biere
 * @date 2006
 */

/**
 * @todo TODO: At the moment, this is only used to reduce the amount of file
 * descriptors used for downloading a file from multiple sources. Of
 * course, this should be used for uploading as well. It could also be
 * used for partial file-sharing. In that case, the file descriptor
 * would need to be opened for reading and writing.
 */

/**
 * @note NOTE: It is the users responsibility to ensure consistency
 * between the file descriptor and the pathname. Thus, this must not be
 * used with arbitrary paths but only for directories under our control.
 * For example, the file could be removed by another process in any case
 * and file_object_open() would return the file descriptor of the already
 * removed file. When the last file object for this pathname is released,
 * the file contents would be lost.
 */

#include "common.h"

RCSID("$Id$")

#include "file_object.h"
#include "sockets.h"	/* For safe_writev_fd() */

#include "lib/atoms.h"
#include "lib/file.h"
#include "lib/iovec.h"
#include "lib/misc.h"
#include "lib/walloc.h"

#include "lib/override.h"       /* Must be the last header included */

static GHashTable *ht_file_objects;

enum file_object_magic { FILE_OBJECT_MAGIC = 0xeb084325 };	/**< Magic number */

struct file_object {
	enum file_object_magic magic;
	char *pathname;	/* atom */
	int ref_count;
	int fd;
};

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
 * Find an existing file object associated with the given pathname.
 *
 * @return If no file object with the given pathname is found NULL
 *		   is returned.
 */
static struct file_object *
file_object_find(const char * const pathname)
{
	struct file_object *fo;
	
	g_return_val_if_fail(ht_file_objects, NULL);
	g_return_val_if_fail(pathname, NULL);
	g_return_val_if_fail(is_absolute_path(pathname), NULL);

	fo = g_hash_table_lookup(ht_file_objects, pathname);
	if (fo) {
		file_object_check(fo);
	}
	return fo;
}

static struct file_object *
file_object_alloc(const int fd, const char * const pathname)
{
	static const struct file_object zero_fo;
	struct file_object *fo;

	g_return_val_if_fail(ht_file_objects, NULL);
	g_return_val_if_fail(fd >= 0, NULL);
	g_return_val_if_fail(pathname, NULL);
	g_return_val_if_fail(is_absolute_path(pathname), NULL);
	g_return_val_if_fail(!file_object_find(pathname), NULL);

	fo = walloc(sizeof *fo);
	*fo = zero_fo;
	fo->magic = FILE_OBJECT_MAGIC;
	fo->ref_count = 1;
	fo->fd = fd;
	fo->pathname = atom_str_get(pathname);

	g_hash_table_insert(ht_file_objects, fo->pathname, fo);
	
	return fo;
}

static void
file_object_free(struct file_object * const fo)
{
	g_return_if_fail(fo);
	g_return_if_fail(1 == fo->ref_count);
	g_return_if_fail(file_object_find(fo->pathname));

	g_hash_table_remove(ht_file_objects, fo->pathname);
	atom_str_free_null(&fo->pathname);
	fo->magic = 0;
	wfree(fo, sizeof *fo);
}

/**
 * Acquires a file object for a given pathname. If the file does not
 * exist, NULL is returned.
 *
 * @param pathname An absolute pathname.
 * @param mode The filemode to use when creating a new file.
 * @return	On failure NULL is returned. On success a file object is
 *			returned.
 */
struct file_object *
file_object_open_writable(const char * const pathname)
{
	struct file_object *fo;

	g_return_val_if_fail(ht_file_objects, NULL);
	g_return_val_if_fail(pathname, NULL);
	g_return_val_if_fail(is_absolute_path(pathname), NULL);

	fo = file_object_find(pathname);
	if (fo) {
		fo->ref_count++;
	} else {
		int fd;

		fd = file_open(pathname, O_WRONLY);
		if (fd >= 0) {
			fo = file_object_alloc(fd, pathname);
		}
	}
	return fo;
}

/**
 * Acquires a file object for a given pathname, creating it if it does
 * not already exist.
 *
 * @param pathname An absolute pathname.
 * @param mode The filemode to use when creating a new file.
 * @return	On failure NULL is returned. On success a file object is
 *			returned.
 */
struct file_object *
file_object_create_writable(const char * const pathname, mode_t mode)
{
	struct file_object *fo;

	g_return_val_if_fail(ht_file_objects, NULL);
	g_return_val_if_fail(pathname, NULL);
	g_return_val_if_fail(is_absolute_path(pathname), NULL);

	fo = file_object_find(pathname);
	if (fo) {
		fo->ref_count++;
	} else {
		int fd;

		fd = file_create(pathname, O_WRONLY, mode);
		if (fd >= 0) {
			fo = file_object_alloc(fd, pathname);
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

		file_object_check(fo);

		if (1 == fo->ref_count) {
			close(fo->fd);
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
 * @param iov An initialized I/O vector buffer.
 * @param iov_cnt The number of initialized buffer in iov (i.e., its size).
 * @param offset The file offset at which to start writing the data.
 *
 * @return On failure -1 is returned and errno is set. On success the amount
 *         of data written is returned.
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

	if (0 != seek_to_filepos(fo->fd, pos)) {
		int saved_errno = errno;

		g_warning("failed to seek at offset %s (%s) for \"%s\" ",
			uint64_to_string(pos), g_strerror(errno), fo->pathname);

		errno = saved_errno;
		ret = -1;
	} else {
		if (iov_cnt > MAX_IOV_COUNT) {
			ret = safe_writev_fd(fo->fd, iov, iov_cnt);
		} else {
			ret = writev(fo->fd, iov, iov_cnt);
		}
	}
	return ret;
}
#endif	/* HAS_PWRITEV */

/**
 * Write the given data to a file object at the given offset.
 *
 * @param fo An initialized file object.
 * @param data An initialized buffer holding the data to write.
 * @param size The amount of bytes to write (i.e., the size of data).
 * @param offset The file offset at which to start writing the data.
 *
 * @return On failure -1 is returned and errno is set. On success the
 *		   amount of data written is returned.
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
 * Get the file descriptor associated with a file object. This should
 * not be used lightly.
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
	g_return_if_fail(!ht_file_objects);

	ht_file_objects = g_hash_table_new(g_str_hash, g_str_equal);
}

/**
 * Releases all used resources and should be called on shutdown.
 */
void
file_object_close(void)
{
	g_return_if_fail(ht_file_objects);

	g_hash_table_destroy(ht_file_objects);
	ht_file_objects = NULL;
}

 /* vi: set ts=4 sw=4 cindent: */
