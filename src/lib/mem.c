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
#include "spinlock.h"
#include "unsigned.h"
#include "vmm.h"

#include "override.h"			/* Must be the last header included */

static int fd[2] = {-1, -1};	/* For the pipe() */

/**
 * This lock funnels all the memory checking operation which rely on the
 * same pipe() resources.
 */
static spinlock_t mem_slk = SPINLOCK_INIT;

#define MEM_FUNNEL		spinlock_hidden(&mem_slk)
#define MEM_UNFUNNEL	spinunlock_hidden(&mem_slk)

/**
 * Close pipe on error.
 */
static void
mem_close_pipe(void)
{
	g_assert(spinlock_is_held(&mem_slk));

	fd_close(&fd[0]);
	fd_close(&fd[1]);
}

/**
 * Assert that pipe holds invalid fds.
 */
static inline void
assert_mem_pipe_is_invalid(void)
{
	g_assert(!is_valid_fd(fd[0]));
	g_assert(!is_valid_fd(fd[1]));
}

/**
 * Opens the pipe used to check whether memory is readable.
 *
 * @return TRUE if pipe was correctly opened.
 */
static bool
mem_open_pipe(void)
{
	static bool warned;

	g_assert(spinlock_is_held(&mem_slk));
	assert_mem_pipe_is_invalid();
 
	if (-1 == pipe(fd) && !warned) {
		s_miniwarn("%s: pipe() failed: %m", G_STRFUNC);
		assert_mem_pipe_is_invalid();
		warned = TRUE;
		return FALSE;
	}

	/* Sanity check */

	if (!is_a_fifo(fd[1])) {
		s_miniwarn("%s: pipe() opened but writing fd #%d not a FIFO?",
			G_STRFUNC, fd[1]);
		warned = TRUE;
		mem_close_pipe();
		return FALSE;
	}

	return TRUE;		/* We'll never close these file descriptors */
}

static bool
mem_valid_pipe(void)
{
	return is_a_fifo(fd[0]) && is_a_fifo(fd[1]);
}

/**
 * Is pointer valid?
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
	char c;

	MEM_FUNNEL;

	/*
	 * The check for is_a_fifo() is necessary because these routines may be
	 * called during crashes, after all file descriptors have been closed, and
	 * we are not notified.
	 *
	 * Any former use of these routines would therefore leave us with a stale
	 * file descriptor.
	 */

	if G_UNLIKELY(!is_valid_fd(fd[0]) || !mem_valid_pipe()) {
		mem_close_pipe();
		if (!mem_open_pipe()) {
			MEM_UNFUNNEL;
			return TRUE;		/* Assume memory pointer is valid */
		}
	}

	/*
	 * The write() system call will fail with EFAULT if the pointer is not
	 * within a valid memory region.
	 */

retry:

	if (-1 == write(fd[1], p, 1)) {
		if (EFAULT == errno) {
			MEM_UNFUNNEL;
			return FALSE;
		}
		if (EPIPE == errno) {
			/* fd[0], the original reading end, was closed */
			mem_close_pipe();
			if (!mem_open_pipe()) {
				MEM_UNFUNNEL;
				return TRUE;
			}
			goto retry;
		}
		MEM_UNFUNNEL;
		s_miniwarn("%s: write(%u, %p, 1) to pipe failed: %m",
			G_STRFUNC, fd[1], p);
		return TRUE;	/* Assume memory pointer is valid */
	}

	if (-1 == read(fd[0], &c, 1)) {
		s_miniwarn("%s: read(%u, %p, 1) from pipe failed: %m",
			G_STRFUNC, fd[0], &c);
		mem_close_pipe();
	}

	MEM_UNFUNNEL;
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
	char c, o;

	MEM_FUNNEL;

	/*
	 * The check for is_open_fd() is necessary because these routines may be
	 * called during crashes, after all file descriptors have been closed, and
	 * we are not notified.
	 *
	 * Any former use of these routines would therefore leave us with a stale
	 * file descriptor.
	 */

	if G_UNLIKELY(!is_valid_fd(fd[0]) || !mem_valid_pipe()) {
		mem_close_pipe();
		if (!mem_open_pipe()) {
			MEM_UNFUNNEL;
			return MEM_PROT_NONE;	/* Assume memory pointer is not writable */
		}
	}

	/*
	 * The write() system call will fail with EFAULT if the pointer is not
	 * within a valid memory region.
	 */

retry:

	if (-1 == write(fd[1], p, 1)) {
		if (EFAULT == errno) {
			MEM_UNFUNNEL;
			return MEM_PROT_NONE;	/* Not readable, assume not writable */
		}
		if (EPIPE == errno) {
			/* fd[0], the original reading end, was closed */
			mem_close_pipe();
			if (!mem_open_pipe()) {
				MEM_UNFUNNEL;
				return MEM_PROT_NONE;	/* Assume not accessible */
			}
			goto retry;
		}
		MEM_UNFUNNEL;
		s_miniwarn("%s: write(%u, %p, 1) to pipe failed: %m",
			G_STRFUNC, fd[1], p);
		return MEM_PROT_READ;	/* Assume memory pointer is not writable */
	}

	/*
	 * Read back the byte we just sent to the pipe, knowing that the read()
	 * system call will fail with EFAULT if the pointer is not writable.
	 */

	o = *(char *) p;		/* For assertions */

	if (-1 == read(fd[0], deconstify_pointer(p), 1)) {
		if (EFAULT == errno) {
			if (-1 == read(fd[0], &c, 1)) {
				s_miniwarn("%s: sink read(%u, %p, 1) from pipe failed: %m",
					G_STRFUNC, fd[0], &c);
				mem_close_pipe();
			}
		} else {
			s_miniwarn("%s: initial read(%u, %p, 1) from pipe failed: %m",
				G_STRFUNC, fd[0], p);
			mem_close_pipe();
		}
		g_assert(o == *(char *) p);
		MEM_UNFUNNEL;
		return MEM_PROT_READ;		/* Not writable */
	}

	g_assert(o == *(char *) p);
	MEM_UNFUNNEL;

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

/* vi: set ts=4 sw=4 cindent: */
