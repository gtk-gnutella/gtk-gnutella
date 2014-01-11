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
 *      59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *----------------------------------------------------------------------
 */

/**
 * @ingroup lib
 * @file
 *
 * Random value file persistency.
 *
 * This layer provides utilities to read / write random seeds.
 *
 * @author Raphael Manfredi
 * @date 2013
 */

#include "common.h"

#include "frand.h"

#include "file.h"

#include "override.h"			/* Must be the last header included */

/**
 * Use specified random filler to create a file full of random bytes.
 *
 * @param path		pathname where random data should be generated
 * @param rfn		random number buffer-filling routine to use
 * @param len		amount of random bytes to generate
 *
 * @return the amount of bytes generated if OK, a short count or -1 on error,
 * with errno set.
 */
ssize_t
frand_save(const char *path, randfill_fn_t rfn, size_t len)
{
	char buf[256];
	int fd;
	ssize_t written = 0;

	fd = file_create(path, O_WRONLY, S_IRUSR | S_IWUSR);

	if (-1 == fd)
		return -1;

	while (len != 0) {
		size_t n = MIN(len, sizeof buf);
		ssize_t w;

		(*rfn)(buf, n);
		w = write(fd, buf, n);
		if (-1 == w)
			goto done;
		written += w;
		if (UNSIGNED(w) != n)
			goto done;
		len -= n;
	}

done:
	ZERO(buf);		/* Leave no memory trail */
	close(fd);
	return written;
}

/**
 * Grab random data from file and feed them to the specified routine.
 *
 * @param path		pathname where random data are expected
 * @param rfd		random filling routine to feed data
 * @param len		amount of random bytes to read
 *
 * @return the amount of bytes fed if OK, a short count or -1 on error,
 * with errno set.
 */
ssize_t
frand_restore(const char *path, feed_fn_t rfd, size_t len)
{
	char buf[256];
	int fd;
	ssize_t bytes_read = 0;

	fd = file_open_missing(path, O_RDONLY);

	if (-1 == fd)
		return -1;

	while (len != 0) {
		size_t n = MIN(len, sizeof buf);
		ssize_t r;

		r = read(fd, buf, n);
		if (-1 == r)
			goto done;
		bytes_read += r;
		(*rfd)(buf, r);
		if (UNSIGNED(r) != n)
			goto done;
		len -= n;
	}

done:
	ZERO(buf);		/* Leave no memory trail */
	close(fd);
	return bytes_read;
}

/**
 * Zeroes specified buffer.
 */
static void
frand_zeroes(void *p, size_t len)
{
	memset(p, 0, len);
}

/**
 * Clear the leading bytes of specified file.
 *
 * @param path		pathname where random data are stored
 * @param len		amount of leading bytes to clear
 *
 * @return the amount of bytes cleared if OK, a short count or -1 on error,
 * with errno set.
 */
ssize_t
frand_clear(const char *path, size_t len)
{
	return frand_save(path, frand_zeroes, len);
}

/* vi: set ts=4 sw=4 cindent: */
