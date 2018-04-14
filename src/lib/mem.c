/*
 * Copyright (c) 2012, Raphael Manfredi
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
 * Memory checking routines.
 *
 * The purpose is to verify whether a memory location / range is valid, i.e.
 * that is can safely be read by the process.  It does not check that the
 * memory pointed at is properly allocated for usage: a pointer to a freed
 * block might appear as valid because the page where it lies is still mapped
 * in the process.
 *
 * @author Raphael Manfredi
 * @date 2012
 */

#include "common.h"

#include "mem.h"

#include "fd.h"					/* For is_a_fifo() */
#include "file.h"
#include "log.h"
#include "spinlock.h"
#include "unsigned.h"
#include "vmm.h"

#include "override.h"			/* Must be the last header included */

typedef struct mem_pipe {
	int fd[2];
	uint8 flags[2];
	const char *name;
	spinlock_t lock;
} mem_pipe_t;

/*
 * Flag position within flags[].
 */

#define MEM_PIPE_WARNED		0
#define MEM_PIPE_ENOMEM		1

mem_pipe_t mem_fp = { { -1, -1 }, { FALSE }, "protection", SPINLOCK_INIT };
mem_pipe_t mem_fr = { { -1, -1 }, { FALSE }, "reading",    SPINLOCK_INIT };

#define MEM_PIPE_LOCK(mp)		spinlock_hidden(&(mp)->lock)
#define MEM_PIPE_UNLOCK(mp)		spinunlock_hidden(&(mp)->lock)

#define mem_pipe_is_locked(mp)	spinlock_is_held(&(mp)->lock)

/**
 * Check whether pipe flag was set, and set it.
 *
 * @param mp		the mem pipe
 * @param idx		flag index to test within the flags[] array
 *
 * @return whether flag was already set.
 */
static inline bool
mem_pipe_test_and_set(mem_pipe_t *mp, int idx)
{
	return atomic_test_and_set(&mp->flags[idx]);
}

/**
 * Set pipe flag.
 *
 * @param mp		the mem pipe
 * @param idx		flag index to test within the flags[] array
 */
static inline void
mem_pipe_set(mem_pipe_t *mp, int idx)
{
	mp->flags[idx] = TRUE;
}

/**
 * Close pipe on error.
 */
static void
mem_close_pipe(mem_pipe_t *mp)
{
	g_assert(mem_pipe_is_locked(mp));

	fd_close(&mp->fd[0]);
	fd_close(&mp->fd[1]);
}

/**
 * @return whether pipe file descriptors are valid.
 */
static bool
mem_initialized_pipe(const mem_pipe_t *mp)
{
	return is_valid_fd(mp->fd[0]) && is_valid_fd(mp->fd[1]);
}

/**
 * Assert that pipe holds invalid fds.
 */
static inline void
assert_mem_pipe_is_invalid(const mem_pipe_t *mp)
{
	g_assert(!mem_initialized_pipe(mp));
}

/**
 * Opens the pipe.
 *
 * @return TRUE if pipe was correctly opened.
 */
static bool
mem_open_pipe(mem_pipe_t *mp)
{
	g_assert(mem_pipe_is_locked(mp));
	assert_mem_pipe_is_invalid(mp);

	if (-1 == pipe(mp->fd) && !mem_pipe_test_and_set(mp, MEM_PIPE_WARNED)) {
		s_miniwarn("%s: pipe() failed for \"%s\": %m", G_STRFUNC, mp->name);
		assert_mem_pipe_is_invalid(mp);
		return FALSE;
	}

	/* Sanity check */

	if (!is_a_fifo(mp->fd[1])) {
		s_miniwarn("%s: pipe() \"%s\" opened but writing fd #%d not a FIFO?",
			G_STRFUNC, mp->name, mp->fd[1]);
		mem_pipe_set(mp, MEM_PIPE_WARNED);
		mem_close_pipe(mp);
		return FALSE;
	}

	/*
	 * Mark the pipe file descriptors as "preserved" so that they survive
	 * a call to fd_close_unpreserved_from() during crashes when we attempt
	 * to close all the unnecessary descriptors.
	 */

	fd_preserve(mp->fd[0]);
	fd_preserve(mp->fd[1]);

	return TRUE;		/* We'll never close these file descriptors */
}

/**
 * @return whether the two file descriptors in the pipe are indeed FIFO fds.
 */
static bool
mem_valid_pipe(const mem_pipe_t *mp)
{
	/*
	 * The check for is_a_fifo() is necessary because these routines may be
	 * called during crashes, after all file descriptors have been closed, and
	 * we are not notified.
	 *
	 * Any former use of these routines would therefore leave us with a stale
	 * file descriptor.
	 *
	 * NOTE: starting from 2015-12-30, the pipe fds are fd_preserve()'ed,
	 * which means they will not be closed by fd_close_unpreserved_from().
	 * As such, this routine is no longer called from mem_is_valid_ptr().
	 */

	return is_a_fifo(mp->fd[0]) && is_a_fifo(mp->fd[1]);
}

/**
 * Report write error on the pipe.
 *
 * @param mp		the pipe on which the write() failed
 * @param p			the address we were trying to test
 * @param caller	the calling routine
 */
static void
mem_pipe_write_error(mem_pipe_t *mp, const void *p, const char *caller)
{
	if (ENOMEM == errno && mem_pipe_test_and_set(mp, MEM_PIPE_ENOMEM))
		return;

	s_miniwarn("%s(): write(%u, %p, 1) to pipe failed: %m",
		caller, mp->fd[1], p);
}

/**
 * Is pointer valid?
 *
 * This routine does not take locks during normal operations.
 *
 * This is a costly check involving kernel operations to verify whether
 * the pointer lies in the virtual address space of the process.  It should
 * only be used in exceptional situations, not as part of routinely executed
 * assertions for instance.
 *
 * @return whether we can read a byte at the supplied memory location.
 */
bool
mem_is_valid_ptr(const void *p)
{
	mem_pipe_t *mp = &mem_fr;
	char c;

	/*
	 * We do not use mem_valid_pipe() but mem_initialized_pipe() here because
	 * we expect the write() below to return EBADF if the file descriptor is
	 * invalid and also because we now fd_preserve() the file descriptors,
	 * meaning they will not be closed by the crash handler until we're ready
	 * to perform an exec().
	 *		--RAM, 2015-12-30
	 */

	if G_UNLIKELY(!mem_initialized_pipe(mp)) {
		bool ok = TRUE;
		MEM_PIPE_LOCK(mp);
		if (!mem_initialized_pipe(mp))
			ok = mem_open_pipe(mp);
		MEM_PIPE_UNLOCK(mp);
		if (!ok)
			return TRUE;		/* Assume memory pointer is valid */
	}

	/*
	 * The write() system call will fail with EFAULT if the pointer is not
	 * within a valid memory region.
	 */

retry:
	if (-1 == write(mp->fd[1], p, 1)) {
		if (EFAULT == errno)
			return FALSE;
		if (EPIPE == errno || EBADF == errno) {
			bool ok;
			/*
			 * We get EPIPE when fd[0], the original reading end, was closed.
			 * We get EBADF when fd[1] is invalid, probably closed.
			 */
			MEM_PIPE_LOCK(mp);
			mem_close_pipe(mp);
			ok = mem_open_pipe(mp);
			MEM_PIPE_UNLOCK(mp);
			if (!ok)
				return TRUE;
			goto retry;
		}
		mem_pipe_write_error(mp, p, G_STRFUNC);
		return TRUE;	/* Assume memory pointer is valid */
	}

	if (-1 == read(mp->fd[0], &c, 1)) {
		s_miniwarn("%s(): read(%u, %p, 1) from pipe failed: %m",
			G_STRFUNC, mp->fd[0], &c);
		MEM_PIPE_LOCK(mp);
		mem_close_pipe(mp);
		MEM_PIPE_UNLOCK(mp);
	}

	return TRUE;
}

/**
 * Probe address to determine wheher the memory is readable or writable.
 *
 * If a page is not readable, it is assumed to not be writable.  We do not
 * probe for executable pages.
 *
 * This is a costly check involving kernel operations to verify whether
 * the pointer lies in the virtual address space of the process.  It should
 * only be used in exceptional situations, not as part of routinely executed
 * assertions for instance.
 *
 * @return memory protection flags: either MEM_PROT_NONE, MEM_PROT_READ
 * or MEM_PROT_READ | MEM_PROT_WRITE.
 */
int
mem_protection(const void *p)
{
	mem_pipe_t *mp = &mem_fp;
	char c, o;

	MEM_PIPE_LOCK(mp);

	if G_UNLIKELY(!mem_valid_pipe(mp)) {
		mem_close_pipe(mp);
		if (!mem_open_pipe(mp)) {
			MEM_PIPE_UNLOCK(mp);
			return MEM_PROT_NONE;	/* Assume memory pointer is not writable */
		}
	}

	/*
	 * The write() system call will fail with EFAULT if the pointer is not
	 * within a valid memory region.
	 */

retry:

	if (-1 == write(mp->fd[1], p, 1)) {
		if (EFAULT == errno) {
			MEM_PIPE_UNLOCK(mp);;
			return MEM_PROT_NONE;	/* Not readable, assume not writable */
		}
		if (EPIPE == errno) {
			/* fd[0], the original reading end, was closed */
			mem_close_pipe(mp);
			if (!mem_open_pipe(mp)) {
				MEM_PIPE_UNLOCK(mp);;
				return MEM_PROT_NONE;	/* Assume not accessible */
			}
			goto retry;
		}
		MEM_PIPE_UNLOCK(mp);;
		mem_pipe_write_error(mp, p, G_STRFUNC);
		return MEM_PROT_READ;	/* Assume memory pointer is not writable */
	}

	/*
	 * Read back the byte we just sent to the pipe, knowing that the read()
	 * system call will fail with EFAULT if the pointer is not writable.
	 */

	o = *(char *) p;		/* For assertions, we know pointer is readable */

	if (-1 == read(mp->fd[0], deconstify_pointer(p), 1)) {
		if (EFAULT == errno) {
			if (-1 == read(mp->fd[0], &c, 1)) {
				s_miniwarn("%s: sink read(%u, %p, 1) from pipe failed: %m",
					G_STRFUNC, mp->fd[0], &c);
				mem_close_pipe(mp);
			}
		} else {
			s_miniwarn("%s: initial read(%u, %p, 1) from pipe failed: %m",
				G_STRFUNC, mp->fd[0], p);
			mem_close_pipe(mp);
		}
		MEM_PIPE_UNLOCK(mp);
		g_assert(o == *(char *) p);
		return MEM_PROT_READ;		/* Not writable */
	}

	MEM_PIPE_UNLOCK(mp);
	g_assert(o == *(char *) p);

	return MEM_PROT_READ | MEM_PROT_WRITE;
}

/**
 * Is memory writable at the specified location?
 *
 * This is a costly check involving kernel operations to verify whether
 * the pointer lies in the virtual address space of the process.  It should
 * only be used in exceptional situations, not as part of routinely executed
 * assertions for instance.
 *
 * @return whether we can write a byte at the supplied memory location.
 */
bool
mem_is_writable(const void *p)
{
	return booleanize(mem_protection(p) & MEM_PROT_WRITE);
}

/**
 * Is memory range accessible, as determined by the predicate?
 *
 * @return whether all the encompassed memory pages are accessible.
 */
static bool
mem_is_accessible(const void *p, size_t len, bool (*predicate)(const void *))
{
	const void *end = const_ptr_add_offset(p, len);
	const void *page;

	g_assert(size_is_positive(len));

	/*
	 * The kernel handles permissions at the page-level granularity, so if
	 * we can access one byte in the page, we can access the whole page.
	 */

	page = vmm_page_start(p);

	do {
		if (!(*predicate)(page))
			return FALSE;
		page = vmm_page_next(page);
	} while (ptr_cmp(page, end) < 0);

	return TRUE;
}

/**
 * Is memory range readable?
 *
 * This does not mean the range is allocated or is usable by the process,
 * just that the memory region can be read.  It can be instructions, read-only
 * data, shared library data segment, etc...
 *
 * The check is costly as it involves system calls for each page within the
 * specified memory range.  It should only be used in exceptional circumstances
 * and not as part of routine checks.
 *
 * @return whether all the encompassed memory pages are readable.
 */
bool
mem_is_valid_range(const void *p, size_t len)
{
	return mem_is_accessible(p, len, mem_is_valid_ptr);
}

/**
 * Is memory range writable?
 *
 * The check is costly as it involves system calls for each page within the
 * specified memory range.  It should only be used in exceptional circumstances
 * and not as part of routine checks.
 *
 * @return whether all the encompassed memory pages are writable.
 */
bool
mem_is_writable_range(const void *p, size_t len)
{
	return mem_is_accessible(p, len, mem_is_writable);
}

/**
 * Ensure memory checking primitives are working properly.
 */
void
mem_test(void)
{
	static const char str[] = "x";

	if (!mem_is_valid_ptr(str) || mem_is_valid_ptr(NULL))
		s_warning("%s(): cannot check whether a pointer is valid", G_STRFUNC);

	if (mem_is_writable(str) || mem_is_writable(mem_test))
		s_warning("%s(): writable memory checks may not be working", G_STRFUNC);

	if (MEM_PROT_NONE == mem_protection(str))
		s_warning("%s(): memory protection checks are not working", G_STRFUNC);

	g_assert('x' == str[0]);	/* mem_protection() leaves memory intact */

	if (!mem_is_valid_range(ARYLEN(str)))
		s_warning("%s(): memory range checks are not working", G_STRFUNC);
}

/* vi: set ts=4 sw=4 cindent: */
