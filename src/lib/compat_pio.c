/*
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
 * The replacement functions do NOT restore the original file offset.
 * However, the routines are thread-safe.
 */

#include "common.h"

#include "compat_pio.h"
#include "iovec.h"
#include "misc.h"
#include "once.h"
#include "spinlock.h"
#include "xmalloc.h"

#include "override.h"       /* Must be the last header included */

/*
 * Determine if we need emulation of pread(), pwrite(), and friends.
 */
#if !defined(HAS_PWRITE) || !defined(HAS_PREAD) || \
	!defined(HAS_PWRITEV) || !defined(HAS_PREADV)
#define PIO_EMULATION
#endif

/*
 * If we need to emulate positionned I/Os, we need to make sure the seek()
 * and the I/O operation that follows are thread-safe.  To that end, we
 * allocate a per-fd spinlock that will be used to ensure atomicity at the
 * application level.
 */
#ifdef PIO_EMULATION
static spinlock_t *pio_locks;		/* Array of spinlocks */
static unsigned pio_capacity;		/* Capacity of the spinlock array */
static once_flag_t pio_inited;		/* Whether array of spinlocks was inited */

/**
 * Initialize the spinlock array, once.
 */
static void
pio_init_once(void)
{
	unsigned i;

	g_assert(NULL == pio_locks);

	pio_capacity = getdtablesize();
	XMALLOC_ARRAY(pio_locks, pio_capacity);
	(void) NOT_LEAKING(pio_locks);

	for (i = 0; i < pio_capacity; i++) {
		spinlock_init(&pio_locks[i]);
	}
}

static inline ALWAYS_INLINE void
PIO_LOCK(int fd)
{
	ONCE_FLAG_RUN(pio_inited, pio_init_once);

	g_assert(fd >= 0);
	g_assert(UNSIGNED(fd) < pio_capacity);

	spinlock_hidden(&pio_locks[fd]);
}

static inline ALWAYS_INLINE void
PIO_UNLOCK(int fd)
{
	spinunlock_hidden(&pio_locks[fd]);
}
#endif	/* PIO_EMULATION */

/**
 * Write the given data to a file descriptor at the given offset.
 *
 * @attention This is not exactly always emulating a pwrite() call because
 * the system call will not change the current file offset whilst this
 * emulation may change it when the real pwrite() call is missing.
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
	fileoffset_t offset = filesize_to_fileoffset_t(pos);

	if ((fileoffset_t) -1 == offset) {
		errno = EINVAL;
		return -1;
	}
	return pwrite(fd, data, size, offset);
}
#else	/* !HAS_PWRITE */
{
	ssize_t r;

	PIO_LOCK(fd);
	r = seek_to_filepos(fd, pos);
	if (0 == r)
		r = write(fd, data, size);
	PIO_UNLOCK(fd);

	return r;
}
#endif	/* HAS_PWRITE */

/**
 * Write the given data to a file descriptor at the given offset.
 *
 * @attention This is not exactly always emulating a pwritev() call because
 * the system call will not change the current file offset whilst this
 * emulation may change it when the real pwritev() call is missing.
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
	const iovec_t * const iov, const int iov_cnt, const filesize_t pos)
#ifdef HAS_PWRITEV
{
	fileoffset_t offset = filesize_to_fileoffset_t(pos);

	if (NULL == iov || iov_cnt < 1 || (fileoffset_t) -1 == offset) {
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
		return compat_pwrite(fd,
			iovec_base(iov), iovec_len(iov),
			pos);
	} else {
		ssize_t r;

		PIO_LOCK(fd);
		r = seek_to_filepos(fd, pos);
		if (0 == r)
			r = writev(fd, iov, MIN(iov_cnt, MAX_IOV_COUNT));
		PIO_UNLOCK(fd);

		return r;
	}
}
#endif	/* HAS_PWRITEV */

/**
 * Read data from the file object from the given offset.
 *
 * @attention This is not exactly always emulating a pread() call because
 * the system call will not change the current file offset whilst this
 * emulation may change it when the real pread() call is missing.
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
	fileoffset_t offset = filesize_to_fileoffset_t(pos);

	if ((fileoffset_t) -1 == offset) {
		errno = EINVAL;
		return -1;
	}
	return pread(fd, data, size, offset);
}
#else	/* !HAS_PREAD */
{
	ssize_t r;

	PIO_LOCK(fd);
	r = seek_to_filepos(fd, pos);
	if (0 == r)
		r = read(fd, data, size);
	PIO_UNLOCK(fd);

	return r;
}
#endif	/* HAS_PREAD */

/**
 * Read data from a file object from the given offset.
 *
 * @attention This is not exactly always emulating a preadv() call because
 * the system call will not change the current file offset whilst this
 * emulation may change it when the real preadv() call is missing.
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
	iovec_t * const iov, const int iov_cnt, const filesize_t pos)
#ifdef HAS_PREADV
{
	fileoffset_t offset = filesize_to_fileoffset_t(pos);

	if (NULL == iov || iov_cnt < 1 || (fileoffset_t) -1 == offset) {
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
		return compat_pread(fd,
			iovec_base(iov), iovec_len(iov),
			pos);
	} else {
		ssize_t r;

		PIO_LOCK(fd);
		r = seek_to_filepos(fd, pos);
		if (0 == r)
			r = readv(fd, iov, MIN(iov_cnt, MAX_IOV_COUNT));
		PIO_UNLOCK(fd);

		return r;
	}
}
#endif	/* HAS_PREADV */

/* vi: set ts=4 sw=4 cindent: */
