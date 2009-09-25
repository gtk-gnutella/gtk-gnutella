/*
 * $Id$
 *
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

RCSID("$Id$")

#include "compat_misc.h"
#include "override.h"			/* Must be the last header included */

guint
compat_max_fd(void)
{
#ifdef MINGW32
	/* FIXME WIN32 */
	return 1024;
#else
	return getdtablesize();
#endif
}

int
compat_mkdir(const char *path, mode_t mode)
{
#ifdef MINGW32
	/* FIXME WIN32 */
	return mkdir(path);
#else
	return mkdir(path, mode);
#endif
}

gboolean
compat_is_superuser(void)
{
	gboolean ret = FALSE;	/* Assume luser by default */
	
#ifdef HAS_GETUID
	ret |= 0 == getuid();
#endif /* HAS_GETUID */

#ifdef HAS_GETEUID
	ret |= 0 == geteuid();
#endif /* HAS_GETEUID */

	return ret;
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
			g_warning("fork() failed: %s", g_strerror(errno));
			return -1;
		}

		if (pid) {
			_exit(0);
			/* NOTREACHED */
			return -1;
		}

		/* Create a new session after the first fork() */
		if (0 == i && (pid_t) -1 == setsid()) {
			g_warning("setsid() failed: %s", g_strerror(errno));
			return -1;
		}
	}

	pid = getpid();
	if (setpgid(0, pid)) {
		g_warning("setpgid(0, %lu) failed: %s",
				(unsigned long) pid, g_strerror(errno));
		return -1;
	}

	if (chdir(directory)) {
		g_warning("chdir(\"%s\") failed: %s", directory, g_strerror(errno));
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
compat_fadvise(int fd, off_t offset, off_t size, int hint)
{
	g_return_if_fail(fd >= 0);
	g_return_if_fail(offset >= 0);
	g_return_if_fail(size >= 0);
	(void) hint;

#ifdef HAS_POSIX_FADVISE
	if (0 == size) {
		/**
 		 * NOTE: Buggy Linux kernels don't handle zero correctly.
		 */
		size = OFF_T_MAX;
	}
	posix_fadvise(fd, offset, size, hint);
#endif	/* HAS_POSIX_FADVISE */
}

void
compat_fadvise_sequential(int fd, off_t offset, off_t size)
{
#ifdef HAS_POSIX_FADVISE
	compat_fadvise(fd, offset, size, POSIX_FADV_SEQUENTIAL);
#endif	/* HAS_POSIX_FADVISE */
}

void
compat_fadvise_noreuse(int fd, off_t offset, off_t size)
{
#ifdef HAS_POSIX_FADVISE
	compat_fadvise(fd, offset, size, POSIX_FADV_NOREUSE);
#endif	/* HAS_POSIX_FADVISE */
}

void
compat_fadvise_dontneed(int fd, off_t offset, off_t size)
{
#ifdef HAS_POSIX_FADVISE
	compat_fadvise(fd, offset, size, POSIX_FADV_DONTNEED);
#endif	/* HAS_POSIX_FADVISE */
}

/* vi: set ts=4 sw=4 cindent: */
