/*
 * Copyright (c) 2013 Raphael Manfredi
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
 *      51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *----------------------------------------------------------------------
 */

/**
 * @ingroup lib
 * @file
 *
 * Atomic (respective to other threads) I/O operations.
 *
 * On linux (and maybe other flavours of UNIX), the write() and writev()
 * operations are not atomic in a multi-threaded environment, which is a
 * problem when emitting logs to stdout/stderr or other files that we have
 * not opened or for which we cannot know whether O_APPEND was specified.
 *
 * The application-level option to guarantee no log mixing is therefore to
 * use locks to protect the I/O operations.
 *
 * @author Raphael Manfredi
 * @date 2013
 */

#include "common.h"

#include "atio.h"
#include "pow2.h"
#include "spinlock.h"

#include "override.h"			/* Must be the last header included */

/*
 * To avoid too much lock contention between separate file descriptors,
 * we use an array of spinlocks to create the critical sections.  The actual
 * spinlock to use is obtained by hashing the file descriptor and then indexing
 * within that array.
 */
static spinlock_t atio_access[] = {
	SPINLOCK_INIT, SPINLOCK_INIT, SPINLOCK_INIT, SPINLOCK_INIT,	/* 4 */
	SPINLOCK_INIT, SPINLOCK_INIT, SPINLOCK_INIT, SPINLOCK_INIT,	/* 8 */
	SPINLOCK_INIT, SPINLOCK_INIT, SPINLOCK_INIT, SPINLOCK_INIT,	/* 12 */
	SPINLOCK_INIT, SPINLOCK_INIT, SPINLOCK_INIT, SPINLOCK_INIT,	/* 16 */
	SPINLOCK_INIT, SPINLOCK_INIT, SPINLOCK_INIT, SPINLOCK_INIT,	/* 20 */
	SPINLOCK_INIT, SPINLOCK_INIT, SPINLOCK_INIT, SPINLOCK_INIT,	/* 24 */
	SPINLOCK_INIT, SPINLOCK_INIT, SPINLOCK_INIT, SPINLOCK_INIT,	/* 28 */
	SPINLOCK_INIT, SPINLOCK_INIT, SPINLOCK_INIT, SPINLOCK_INIT,	/* 32 */
};

#define ATIO_HASH_MASK	(N_ITEMS(atio_access) - 1)

/*
 * Get spinlock to use based on file descriptor.
 */
static inline spinlock_t *
atio_get_lock(int fd)
{
	STATIC_ASSERT(IS_POWER_OF_2(ATIO_HASH_MASK + 1));

	return &atio_access[fd & ATIO_HASH_MASK];
}

/**
 * Perform an atomic write().
 */
ssize_t
atio_write(int fd, const void *buf, size_t count)
{
	ssize_t w;
	spinlock_t *l = atio_get_lock(fd);

	/*
	 * We use raw spinlocks here to avoid any complication with spinlock_loop().
	 * Indeed, atomic write operations are conducted from the logging layer
	 * during critical messages, and we know by design that no deadlock can
	 * occur on these locks.  Therefore, even if the lock operation was
	 * delayed for some reason, we don't want to pollute the output with more
	 * messages about a possible deadlock that we know cannot be.
	 */

	spinlock_raw(l);
	w = write(fd, buf, count);
	spinunlock_raw(l);

	return w;
}

/**
 * Perform an atomic writev().
 */
ssize_t
atio_writev(int fd, const iovec_t *iov, int iovcnt)
{
	ssize_t w;
	spinlock_t *l = atio_get_lock(fd);

	spinlock_raw(l);
	w = writev(fd, iov, iovcnt);
	spinunlock_raw(l);

	return w;
}

/**
 * Perform an atomic fwrite().
 */
size_t
atio_fwrite(const void *ptr, size_t size, size_t nmemb, FILE *f)
{
	size_t w;
	spinlock_t *l = atio_get_lock(fileno(f));

	spinlock_raw(l);
	w = fwrite(ptr, size, nmemb, f);
	spinunlock_raw(l);

	return w;
}

/* vi: set ts=4 sw=4 cindent: */
