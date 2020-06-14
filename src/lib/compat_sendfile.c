/*
 * Copyright (c) 2015 Raphael Manfredi
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
 * Data transfer between file descriptors without user/kernel memory copies.
 *
 * @author Raphael Manfredi
 * @date 2015
 */

#include "common.h"

#include "compat_sendfile.h"

#include "compat_pio.h"
#include "fd.h"
#include "halloc.h"
#include "misc.h"
#include "stringify.h"
#include "unsigned.h"

#include "override.h"		/* Must be the last header included */

#define SENDFILE_BUFSIZ_MAX	65536	/* Reading buffer size */

/**
 * Emulates sendfile() using read() and write() operations.
 *
 * @param out_fd	the file descriptor opened for writing
 * @param in_fd		the file descriptor opened for reading
 * @param offset	input = offset where to read, output = next unread offset
 * @param count		amount of bytes to transfer
 *
 * @return the amount of bytes written to out_fd, -1 on errors with ernno set.
 */
static ssize_t
compat_sendfile_emulated(int out_fd, int in_fd, off_t *offset, size_t count)
{
	off_t start = *offset;
	ssize_t r;
	void *buf;
	size_t bufsize, remain = count;

	bufsize = MIN(count, SENDFILE_BUFSIZ_MAX);
	buf = halloc(bufsize);

	while (remain != 0) {
		size_t nread = MIN(remain, bufsize);
		r = compat_pread(in_fd, buf, nread, start);
		if G_UNLIKELY(-1 == r)
			goto failed;
		if (-1 == write(out_fd, buf, r))
			goto failed;
		remain -= r;
		start += r;
		if G_UNLIKELY(UNSIGNED(r) < nread)
			break;		/* Short read, probably indicates EOF */
	}

	*offset = start;
	hfree(buf);

	return count - remain;

failed:
	hfree(buf);
	return -1;
}

#if defined(HAS_SENDFILE) && !defined(USE_BSD_SENDFILE)
/**
 * Wrapper over Linux-compatible sendfile().
 *
 * @param out_fd	the file descriptor opened for writing
 * @param in_fd		the file descriptor opened for reading
 * @param offset	input = offset where to read, output = next unread offset
 * @param count		amount of bytes to transfer
 *
 * @return the amount of bytes written to out_fd, -1 on errors with ernno set.
 */
static ssize_t
compat_sendfile_linux(int out_fd, int in_fd, off_t *offset, size_t count)
{
	off_t start = *offset;
	ssize_t r;

	r = sendfile(out_fd, in_fd, offset, count);

	/*
	 * Paranoid checks, verifying semantics are in line with what we expect.
	 */

	if G_UNLIKELY(r >= 0 && *offset != start + r) {
		g_assert(UNSIGNED(r) <= count);
		s_carp("%s(): fixed sendfile() returned offset: "
			"was set to %s instead of %s (%zu byte%s written)",
			G_STRFUNC, uint64_to_string(*offset), uint64_to_string2(start + r),
			PLURAL(r));
		*offset = start + r;
	} else if G_UNLIKELY((ssize_t) -1 == r) {
		*offset = start;		/* In case sendfile() touched it */

		/*
		 * Before linux 2.6.33, the ``out_fd'' parameter must be a socket.
		 * Otherwise, sendfile() sets errno to EINVAL.
		 */

		if (EINVAL == errno && !is_a_socket(out_fd))
			r = compat_sendfile_emulated(out_fd, in_fd, offset, count);
	}

	return r;
}
#endif	/* HAS_SENDFILE && !USE_BSD_SENDFILE */

#if defined(HAS_SENDFILE) && defined(USE_BSD_SENDFILE)
/**
 * Wrapper over BSD-compatible sendfile().
 *
 * The FreeBSD semantics for sendfile() differ from the Linux one:
 *
 * . FreeBSD sendfile() returns 0 on success, -1 on failure.
 * . FreeBSD sendfile() returns the amount of written bytes via a parameter
 *   when EAGAIN.
 * . FreeBSD sendfile() does not update the offset inplace.
 * . FreeBSD sendfile() does not accept regular files for out_fd, only sockets.
 *
 * @param out_fd	the file descriptor opened for writing
 * @param in_fd		the file descriptor opened for reading
 * @param offset	input = offset where to read, output = next unread offset
 * @param count		amount of bytes to transfer
 *
 * @return the amount of bytes written to out_fd, -1 on errors with ernno set.
 */
static ssize_t
compat_sendfile_bsd(int out_fd, int in_fd, off_t *offset, size_t count)
{
	fileoffset_t written = 0;
	off_t start = *offset;
	ssize_t r;

	r = sendfile(in_fd, out_fd, start, count, NULL, &written, 0);

	if G_UNLIKELY((ssize_t) -1 == r) {
		if (is_temporary_error(errno))
			r = written > 0 ? (ssize_t) written : (ssize_t) -1;
	} else {
		r = count;		/* Everything written, but returns 0 if OK */
	}

	if G_LIKELY(r > 0) {
		*offset = start + r;
	} else if (r < 0) {
		switch (errno) {
		case ENOBUFS:		/* kernel cannot allocate an internal buffer */
		case ENOTSOCK:		/* out_fd is not a socket */
		case EOPNOTSUPP:	/* in_fd does not support sendfile() */
			r = compat_sendfile_emulated(out_fd, in_fd, offset, count);
			break;
		}
	}

	return r;
}
#endif	/* HAS_SENDFILE && USE_BSD_SENDFILE */

/**
 * Transfer data between file descriptors.
 *
 * The signature of this routine is the one found on Linux.
 *
 * On FreeBSD, the sendfile() routine has a different signature and semantics
 * of its parameters and returned values.  They are all mapped back to Linux
 * semantics.
 *
 * When sendfile() is not available, this routine emulates the behaviour at
 * the expense of user/kernel memory copies.
 *
 * When sendfile() returns errors because out_fd is not a socket or in_fd
 * is not a suitable file descriptor (probably because mmap() will not work
 * over it -- a pipe or another non-plain file), we also emulate the behaviour
 * using plain read() and write() calls.
 *
 * @param out_fd	the file descriptor opened for writing
 * @param in_fd		the file descriptor opened for reading
 * @param offset	input = offset where to read, output = next unread offset
 * @param count		amount of bytes to transfer
 *
 * @return the amount of bytes written to out_fd, -1 on errors with ernno set.
 */
ssize_t
compat_sendfile(int out_fd, int in_fd, off_t *offset, size_t count)
{
	g_assert(is_valid_fd(out_fd));
	g_assert(is_valid_fd(in_fd));
	g_assert(offset != NULL);
	g_assert(size_is_non_negative(count));

#ifdef HAS_SENDFILE
#ifdef USE_BSD_SENDFILE
	return compat_sendfile_bsd(out_fd, in_fd, offset, count);
#else	/* !USE_BSD_SENDFILE */
	return compat_sendfile_linux(out_fd, in_fd, offset, count);
#endif	/* USE_BSD_SENDFILE */
#else	/* !HAS_SENDFILE */
	return compat_sendfile_emulated(out_fd, in_fd, offset, count);
#endif	/* HAS_SENDFILE */
}

/* vi: set ts=4 sw=4 cindent: */
