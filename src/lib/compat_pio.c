/*
 * $Id$
 *
 * Copyright (c) 2008, Christian Biere
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
 * Positioned I/O (seeking and write/read in one step).
 *
 * @author Christian Biere
 * @date 2008
 */

/**
 * @note NOTE:
 * The replacement functions do NOT restore the original file offset and they
 * are NOT thread-safe. As gtk-gnutella is mono-threaded this should never be a
 * problem.
 */

#include "common.h"

RCSID("$Id$")

#include "lib/compat_pio.h"
#include "lib/iovec.h"
#include "lib/misc.h"

#include "lib/override.h"       /* Must be the last header included */

/**
 * Write the given data to a file descriptor at the given offset.
 *
 * @param fd A valid file descriptor.
 * @param data An initialized buffer holding the data to write.
 * @param size The amount of bytes to write (i.e., the size of data).
 * @param pos The file offset at which to start writing the data.
 *
 * @return On failure -1 is returned and errno is set. On success the
 *		   amount of bytes written is returned.
 */
ssize_t
compat_pwrite(const int fd,
	const void * const data, const size_t size, const filesize_t pos)
#ifdef HAS_PWRITE
{
	off_t offset = filesize_to_off_t(pos);

	if ((off_t) -1 == offset) {
		errno = EINVAL;
		return -1;
	}
	return pwrite(fd, data, size, offset);
}
#else	/* !HAS_PWRITE */
{
	if (0 != seek_to_filepos(fd, pos)) {
		return -1;
	}
	return write(fd, data, size);
}
#endif	/* HAS_PWRITE */

/**
 * Write the given data to a file descriptor at the given offset.
 *
 * @param fd A valid file descriptor.
 * @param iov An initialized I/O vector buffer.
 * @param iov_cnt The number of initialized buffer in iov (i.e., its size).
 * @param pos The file offset at which to start writing the data.
 *
 * @return On failure -1 is returned and errno is set. On success the amount
 *         of data bytes written is returned.
 */
ssize_t
compat_pwritev(const int fd,
	const struct iovec * const iov, const int iov_cnt, const filesize_t pos)
#ifdef HAS_PWRITEV
{
	off_t offset = filesize_to_off_t(pos);

	if (NULL == iov || iov_cnt < 1 || (off_t) -1 == offset) {
		errno = EINVAL;
		return -1;
	}
	return pwritev(fd, iov, MIN(iov_cnt, MAX_IOV_COUNT), offset);
}
#else	/* !HAS_PWRITEV */
{
	if (NULL == iov || iov_cnt < 1) {
		errno = EINVAL;
		return -1;
	} else if (1 == iov_cnt) {
		return compat_pwrite(fd, iov->iov_base, iov->iov_len, pos);
	} else if (0 != seek_to_filepos(fd, pos)) {
		return -1;
	} else {
		return writev(fd, iov, MIN(iov_cnt, MAX_IOV_COUNT));
	}
}
#endif	/* HAS_PWRITEV */

/**
 * Read data from the file object from the given offset.
 *
 * @param fd A valid file descriptor.
 * @param data A buffer for holding the data to be read.
 * @param size The amount of bytes to read (i.e., the size of data).
 * @param pos The file offset from which to start reading data.
 *
 * @return On failure -1 is returned and errno is set. On success the
 *		   amount of bytes read is returned.
 */
ssize_t
compat_pread(const int fd,
	void * const data, const size_t size, const filesize_t pos)
#ifdef HAS_PREAD
{
	off_t offset = filesize_to_off_t(pos);

	if ((off_t) -1 == offset) {
		errno = EINVAL;
		return -1;
	}
	return pread(fd, data, size, offset);
}
#else	/* !HAS_PREAD */
{
	if (0 != seek_to_filepos(fd, pos)) {
		return -1;
	}
	return read(fd, data, size);
}
#endif	/* HAS_PREAD */


/**
 * Read data from a file object from the given offset.
 *
 * @param fd A valid file descriptor.
 * @param iov An initialized I/O vector buffer.
 * @param iov_cnt The number of initialized buffer in iov (i.e., its size).
 * @param pos The file offset at which to start reading data.
 *
 * @return On failure -1 is returned and errno is set. On success the amount
 *         of data bytes read is returned.
 */
ssize_t
compat_preadv(const int fd,
	struct iovec * const iov, const int iov_cnt, const filesize_t pos)
#ifdef HAS_PREADV
{
	off_t offset = filesize_to_off_t(pos);

	if (NULL == iov || iov_cnt < 1 || (off_t) -1 == offset) {
		errno = EINVAL;
		return -1;
	} else {
		return preadv(fd, iov, MIN(iov_cnt, MAX_IOV_COUNT), offset);
	}
}
#else	/* !HAS_PREADV */
{
	if (NULL == iov || iov_cnt < 1) {
		errno = EINVAL;
		return -1;
	} else if (1 == iov_cnt) {
		return compat_pread(fd, iov->iov_base, iov->iov_len, pos);
	} else if (0 != seek_to_filepos(fd, pos)) {
		return -1;
	} else {
		return readv(fd, iov, MIN(iov_cnt, MAX_IOV_COUNT));
	}
}
#endif	/* HAS_PREADV */

/* vi: set ts=4 sw=4 cindent: */
