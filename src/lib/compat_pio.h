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
 */

ssize_t compat_pwrite(int, const void *, size_t, filesize_t);
ssize_t compat_pread(int, void *, size_t, const filesize_t);
ssize_t compat_pwritev(int, const iovec_t *, int, filesize_t);
ssize_t compat_preadv(int, iovec_t *, int, filesize_t);

void compat_pio_lock(int fd);
void compat_pio_unlock(int fd);


/* vi: set ts=4 sw=4 cindent: */
