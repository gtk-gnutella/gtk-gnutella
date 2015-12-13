/*
 * Copyright (c) 2009, Raphael Manfredi
 * Copyright (c) 2006-2008, Christian Biere
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
 * Miscellaneous compatibility routines.
 *
 * @author Raphael Manfredi
 * @date 2009
 * @author Christian Biere
 * @date 2006-2008
 */

#include "common.h"

#include "compat_misc.h"
#include "log.h"

#include "override.h"			/* Must be the last header included */

bool
compat_is_superuser(void)
{
	bool ret = FALSE;	/* Assume luser by default */
	
#ifdef HAS_GETUID
	ret |= 0 == getuid();
#endif /* HAS_GETUID */

#ifdef HAS_GETEUID
	ret |= 0 == geteuid();
#endif /* HAS_GETEUID */

	return ret;
}

/**
 * Performs a kill(pid, 0), portably between UNIX and Windows.
 */
int
compat_kill_zero(pid_t pid)
{
#ifdef MINGW32
	return mingw_process_access_check(pid);
#else
	return kill(pid, 0);
#endif
}

/**
 * Check whether process exists.
 */
bool
compat_process_exists(pid_t pid)
{
	return -1 != compat_kill_zero(pid) || EPERM == errno;
}

/**
 * Daemonizes the current process.
 *
 * @param directory We will chdir() to this directory. A value of NULL
 *                  implies the root directory.
 */
int
compat_daemonize(const char *directory)
{
#ifdef MINGW32
	/* FIXME MINGW32 */
	(void) directory;
#else
	pid_t pid;
	int i;

	if (!directory) {
		directory = "/";
	}

	for (i = 0; i < 2; i++) {
		/* A handler for SIGCHLD should already be installed. */

		fflush(NULL);
		pid = fork();
		if ((pid_t) -1 == pid) {
			s_warning("%s(): fork() failed: %m", G_STRFUNC);
			return -1;
		}

		if (pid) {
			_exit(0);
			/* NOTREACHED */
			return -1;
		}

		/* Create a new session after the first fork() */
		if (0 == i && (pid_t) -1 == setsid()) {
			s_warning("%s(): setsid() failed: %m", G_STRFUNC);
			return -1;
		}
	}

	pid = getpid();
	if (setpgid(0, pid)) {
		s_warning("%s(): setpgid(0, %lu) failed: %m", G_STRFUNC, (ulong) pid);
		return -1;
	}

	if (chdir(directory)) {
		s_warning("%s(): chdir(\"%s\") failed: %m", G_STRFUNC, directory);
		return -1;
	}

	/*
	 * Make sure we don't create any files with an s-bit set or
	 * a world-writeable file.
	 */
	umask(umask(0) | S_IWOTH | S_ISUID | S_ISGID);

	/*
	 * Close all standard streams.
	 */

	if (!freopen("/dev/null", "r", stdin)) {
		g_warning("freopen() failed for stdin");
		return -1;
	}
	if (!freopen("/dev/null", "w", stdout)) {
		g_warning("freopen() failed for stdout");
		return -1;
	}
	if (!freopen("/dev/null", "w", stderr)) {
		g_warning("freopen() failed for stderr");
		return -1;
	}
#endif	/* MINGW32 */
	return 0;
}

/**
 * Equivalent to strstr() for raw memory without NUL-termination.
 *
 * @param data The memory to scan.
 * @param data_size The length of data.
 * @param pattern The byte pattern to look for.
 * @param pattern_size The length of the pattern.
 * @return NULL if not found. Otherwise, the start address of the first match
 *         is returned.
 */
void *
compat_memmem(const void *data, size_t data_size,
	const void *pattern, size_t pattern_size)
{
	const char *next, *p, *pat;
	
	pat = pattern;
	for (p = data; NULL != p; p = next) {
		if (data_size < pattern_size) {
			p = NULL;
			break;
		}
		if (0 == memcmp(p, pattern, pattern_size)) {
			break;
		}
		next = memchr(&p[1], pat[0], data_size - 1);
		data_size -= next - p;
	}
	return deconstify_gchar(p);
}

/**
 * See posix_fadvise(2).
 *
 * @param fd A valid file descriptor of a regular file. 
 * @param offset Start of range.
 * @param size Size of range. Zero means up to end of file but see note below.
 * @param hint One of the POSIX_FADVISE_* values. These CANNOT be combined.
 */
static void
compat_fadvise(int fd, fileoffset_t offset, fileoffset_t size, int hint)
{
	g_return_if_fail(fd >= 0);
	g_return_if_fail(offset >= 0);
	g_return_if_fail(size >= 0);
	(void) hint;

	if (0 == size) {
		/**
 		 * NOTE: Buggy Linux kernels don't handle zero correctly.
		 */
		size = OFF_T_MAX;
	}
#ifdef HAS_POSIX_FADVISE
	posix_fadvise(fd, offset, size, hint);
#endif
}

#ifndef HAS_POSIX_FADVISE
#ifndef POSIX_FADV_SEQUENTIAL
#define POSIX_FADV_SEQUENTIAL 0
#endif
#ifndef POSIX_FADV_RANDOM
#define POSIX_FADV_RANDOM 0
#endif
#ifndef POSIX_FADV_NOREUSE
#define POSIX_FADV_NOREUSE 0
#endif
#ifndef POSIX_FADV_DONTNEED
#define POSIX_FADV_DONTNEED 0
#endif
#endif	/* HAS_POSIX_FADVISE */

void
compat_fadvise_sequential(int fd, fileoffset_t offset, fileoffset_t size)
{
	compat_fadvise(fd, offset, size, POSIX_FADV_SEQUENTIAL);
}

void
compat_fadvise_random(int fd, fileoffset_t offset, fileoffset_t size)
{
	compat_fadvise(fd, offset, size, POSIX_FADV_RANDOM);
}

void
compat_fadvise_noreuse(int fd, fileoffset_t offset, fileoffset_t size)
{
	compat_fadvise(fd, offset, size, POSIX_FADV_NOREUSE);
}

void
compat_fadvise_dontneed(int fd, fileoffset_t offset, fileoffset_t size)
{
	compat_fadvise(fd, offset, size, POSIX_FADV_DONTNEED);
}

/* vi: set ts=4 sw=4 cindent: */
